//! Shared plumbing for the payment-channels recovery tools
//! ([`crate::session_recovery`], [`crate::batch_reclaim`]): both submit a
//! batch of independently-signed transactions with bounded concurrency and
//! report a confirmed/failed tally, so that one implementation is tested and
//! trusted instead of two near-identical copies.

use anyhow::{Context, Result, bail};
use futures::{StreamExt, stream};
use pay_kit::mpp::solana_keychain::SolanaSigner;
use pay_kit::mpp::solana_keychain::memory::MemorySigner;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;

use crate::fixture_rpc::FixtureRpc;
use crate::wallet::Wallet;

/// Fixed layout the shared payment-channels program account uses regardless
/// of which x402/MPP scheme opened the channel — same program, same account
/// shape. `getProgramAccounts` filters on these to find channels by status
/// without fetching every account's full data first.
pub(crate) const CHANNEL_ACCOUNT_SIZE: usize = 256;
pub(crate) const CHANNEL_STATUS_OFFSET: usize = 3;

/// Build and sign a transaction with `fee_payer` as the paying/first account
/// plus any `extra_signers` the instructions require (e.g. a channel's own
/// payer authorizing `request_close`). Each signer's signature is placed at
/// its own position in `account_keys`, so order in `extra_signers` doesn't
/// matter.
pub(crate) async fn signed_transaction(
    fee_payer: &Wallet,
    extra_signers: &[&Wallet],
    instructions: Vec<Instruction>,
    blockhash: Hash,
) -> Result<Transaction> {
    let message = Message::new_with_blockhash(&instructions, Some(&fee_payer.pubkey), &blockhash);
    let mut transaction = Transaction::new_unsigned(message);
    for wallet in std::iter::once(fee_payer).chain(extra_signers.iter().copied()) {
        let signer =
            MemorySigner::from_bytes(&wallet.keypair).context("loading recovery signer")?;
        let signature = signer
            .sign_message(&transaction.message_data())
            .await
            .context("signing recovery transaction")?;
        let index = transaction
            .message
            .account_keys
            .iter()
            .position(|key| *key == wallet.pubkey)
            .context("recovery signer is absent from transaction")?;
        transaction.signatures[index] = Signature::from(<[u8; 64]>::from(signature));
    }
    Ok(transaction)
}

/// Submit `transactions` with `concurrency` in flight, confirming each via
/// `rpc`'s shared batched tracker. `label` is a caller-supplied per-item
/// identifier (a user index, a channel address, ...) used only for the
/// failure report.
pub(crate) async fn submit_transactions<L: std::fmt::Display>(
    rpc: &FixtureRpc,
    transactions: Vec<(L, Transaction)>,
    concurrency: usize,
    operation: &str,
) -> Result<()> {
    let mut submitting = stream::iter(
        transactions
            .into_iter()
            .map(|(label, tx)| async move { (label, rpc.submit_and_confirm(&tx).await) }),
    )
    .buffer_unordered(concurrency);
    let mut confirmed = 0usize;
    let mut failures = Vec::new();
    while let Some((label, result)) = submitting.next().await {
        match result {
            Ok(_) => confirmed += 1,
            Err(error) => failures.push(format!("{label}: {error:#}")),
        }
    }
    println!(
        "{operation}: {confirmed} confirmed, {} failed",
        failures.len()
    );
    if !failures.is_empty() {
        let shown = failures.iter().take(20).cloned().collect::<Vec<_>>();
        bail!(
            "{operation} failed for {} channels (first {}):\n{}",
            failures.len(),
            shown.len(),
            shown.join("\n")
        );
    }
    Ok(())
}

/// Decode a channel account's `payer` from raw Borsh bytes without pulling in
/// a scheme-specific generated `Channel` type — the field layout (offset 88,
/// 32 bytes) is fixed by the shared on-chain program, independent of which
/// scheme's client library a caller has on hand.
pub(crate) fn decode_payer(data: &[u8]) -> Option<Pubkey> {
    const PAYER_OFFSET: usize = 88;
    let bytes: [u8; 32] = data.get(PAYER_OFFSET..PAYER_OFFSET + 32)?.try_into().ok()?;
    Some(Pubkey::new_from_array(bytes))
}
