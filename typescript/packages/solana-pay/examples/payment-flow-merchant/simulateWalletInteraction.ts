import { lamports } from '@solana/kit';
import type { TransferRequestURL } from '@solana/pay';
import { createWalletClient } from '@solana/pay';
import { rpcAirdrop } from '@solana/kit-plugin-rpc';
import { airdropPayer } from '@solana/kit-plugin-signer';
import { CUSTOMER_WALLET } from './constants.js';

export async function simulateWalletInteraction(url: URL) {
    /**
     * Create a wallet client with the customer's signer.
     * Includes transaction planner/executor so we can just call sendTransaction().
     * Airdrops some SOL to the customer wallet for a successful transaction.
     */
    const wallet = await createWalletClient({
        rpcUrl: 'http://127.0.0.1:8899',
        rpcSubscriptionsConfig: { url: 'ws://127.0.0.1:8900' },
        payer: CUSTOMER_WALLET,
    })
        .use(rpcAirdrop())
        .use(airdropPayer(lamports(2_000_000_000n)));

    /**
     * The URL that triggers the wallet interaction; follows the Solana Pay URL scheme.
     * The parameters needed to create the correct transaction are encoded within the URL.
     */
    const { recipient, amount, reference, label, message, memo } = wallet.pay.parseURL(url) as TransferRequestURL;
    console.log('label: ', label);
    console.log('message: ', message);

    /**
     * Create the transfer instructions from the parsed URL parameters
     */
    const instructions = await wallet.pay.createTransfer({
        recipient,
        amount: amount!,
        reference,
        memo,
    });

    /**
     * Send the transaction — planner/executor handles blockhash, signing, and submission
     */
    await wallet.sendTransaction(instructions);
}
