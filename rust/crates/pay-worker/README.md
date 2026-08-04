# pay-worker

Operator maintenance jobs for pay-kit payment-channel deployments.

The crate ships two binaries:

- **`close-channels`** handles explicit maintenance and scheduled rent reclaim.
- **`settle-sessions`** scans durable Redis session vouchers, compares them to
  on-chain state, and batches both newer watermarks and due idle closes.

`close-channels` closes a list of on-chain payment channels (the MPP payment-channels program,
`CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX`) by driving each through the
program's adaptive state machine, signing with a GCP-KMS-backed fee payer.

It reuses `pay-api-core` (RPC client, on-chain `Channel` decode, ATA
derivation) and pay-kit's generated instruction builders, so there is no
hand-copied program logic or account layout.

## Safety

- **`DRY_RUN` defaults to `true`.** With dry-run on (the default), the job does
  everything EXCEPT sign and broadcast: it fetches + decodes each channel,
  plans the instruction(s), derives all accounts, and logs the expected effect.
- A transaction is only signed and sent when **`DRY_RUN=false`** is explicitly
  set. Any other value (unset, `true`, `1`, garbage) keeps dry-run on.
- Always run a dry-run first and read the plan before setting `DRY_RUN=false`.

## Environment variables

| Var | Required | Default | Purpose |
| --- | --- | --- | --- |
| `CHANNEL_ADDRESSES` | no | empty | Comma-separated base58 channel pubkeys. Empty scans all on-chain `Distributed` channels for rent reclaim. |
| `NETWORK` | no | `mainnet` | `mainnet` or `sandbox`; selects the RPC + treasury. |
| `RPC_URL` | no | per-network YAML | Overrides the RPC URL for the active network (Helius, etc.). |
| `DRY_RUN` | no | `true` | `false` to actually sign + broadcast. Anything else = dry-run. |
| `PAY_API_SEND__FEE_PAYER__KEY_NAME` | prod | — | GCP KMS key resource name of the fee payer. |
| `PAY_API_SEND__FEE_PAYER__PUBKEY` | prod | — | Base58 pubkey of that KMS key. |
| `LOCAL_FEE_PAYER_PRIVATE_KEY` | local | — | Escape hatch: base58 secret key or `[1,2,…]` keypair JSON. Signs in-process, bypassing KMS. |
| `RUST_LOG` | no | `info` | `tracing` env-filter (e.g. `pay_worker=debug`). |
| `PAY_SESSION_REDIS_URL` | settle only | — | Redis URL shared with the proxy services. |
| `PAY_SESSION_REDIS_PREFIX` | no | `pay:session:v1:` | Session channel key namespace. |
| `PAY_SESSION_FINALIZED_RETENTION_SECONDS` | no | `604800` (7 days) | Retain a fully finalized session record for reconciliation/debugging before Redis expires it. |
| `SETTLEMENT_LOCK_TTL_SECONDS` | no | `300` | TTL for the singleton reconciliation lease. |
| `RUN_ONCE` | no | `true` | Keep one-shot behavior for manual Cloud Run Job executions. Set to `false` for the continuous worker. |
| `SETTLEMENT_INTERVAL_SECONDS` | no | `10` | Delay between continuous reconciliation iterations when `RUN_ONCE=false`. |

The fee-payer keys intentionally share pay-api's `send.fee_payer.*` env names so
a single Doppler config drives both. Job-specific overrides use the `JOBS_`
prefix (e.g. `JOBS_TREASURY_OWNER`, `JOBS_NETWORKS__SANDBOX__RPC_URL`), applied
on top of `config/default.yaml`.

`me` below = the fee-payer / KMS signer pubkey.

## Adaptive close logic

For each channel address the job fetches + borsh-decodes the on-chain `Channel`.
If the account isn't a live channel (wrong owner, not a decodable `Channel`,
e.g. a tombstone / `ClosedChannel`), it logs and skips. Otherwise:

- **OPEN**
  - `me == payee` → `settle_and_seal` (`has_voucher = 0`, no voucher), then
    treat as sealed and `distribute` (separate tx).
  - `me == payer` → `request_close` (starts the grace window only; a later run
    seals after the grace period elapses).
  - otherwise → log "cannot advance (not payer/payee)" and skip.
- **CLOSING**
  - deadline = `closure_started_at + grace_period`. If `now >= deadline` →
    `seal` (permissionless), then `distribute`.
  - else → log "grace not elapsed, retry after `<deadline>`" and skip.
- **SEALED** → `distribute` (permissionless; refunds payer, pays recipients,
  and either deallocates the channel or leaves it `Distributed` until its slot
  reclaim gate).
- **DISTRIBUTED** → once `current_slot > open_slot + 1500`, permissionlessly
  `reclaim` the PDA rent to its channel-bound rent payer.

With `CHANNEL_ADDRESSES` empty, the job uses a filtered `getProgramAccounts`
scan to discover only `Distributed` channels. It plans every unlocked reclaim
before broadcasting, then packs them using reclaim's operation-specific cap
and the serialized 1,232-byte transaction limit. Channels sharing the KMS rent
payer can fit up to 28 reclaim instructions in one legacy transaction; batches
with different rent payers are automatically smaller when their additional
account keys consume the available bytes. The deployer schedules the active
sweep on a cadence longer than the expected job runtime to avoid overlapping
executions. The Redis lease also rejects an overlapping run, so reclaim work
survives proxy restarts and does not depend on an in-process timer.

Non-reclaim state-machine steps remain separate transactions because later
steps depend on state produced by earlier ones. Each transaction uses the KMS
pubkey as fee payer, a freshly fetched blockhash, and the async KMS
`SolanaSigner`, then is sent and polled to `confirmed`. Planning errors remain
isolated per channel; a failed atomic reclaim transaction marks every channel
in that batch as failed and the job continues with later batches. When not in
dry-run, any hard failure makes the process exit non-zero.

## Durable session settlement

`settle-sessions` takes a Redis lease so a rolling deployment or manual
execution cannot duplicate work. It cursor-scans the configured channel
namespace, skips sealed and pull-mode records, and fetches every candidate
channel from Solana. If a push-channel account is already absent at confirmed
commitment, the worker deletes its terminal Redis record immediately.
For active channels it submits a voucher only when the stored cumulative
amount is strictly greater than the on-chain watermark. For idle channels it
atomically claims the still-due Redis deadline, settles the latest voucher,
seals, and distributes the channel. pay-kit's settlement worker packs as many
channel instruction groups as fit in each transaction.

Deployed as one continuously-running instance reconciling on an interval (see
`RUN_ONCE` / `SETTLEMENT_INTERVAL_SECONDS`); a one-shot invocation is also
available for manual diagnostics. Proxy instances persist request-start
activity and vouchers; they do not own a lifecycle clock when configured with
the durable Redis store.

### Distribution preimage recovery

`distribute` needs the full distribution plan (`count || entries`), but only its
`sha256` hash is stored on-chain. The job recovers the preimage from the
channel's **open** (creation) transaction:

1. `getSignaturesForAddress(channel)`, paginated to the OLDEST signature — that
   is the `open`.
2. `getTransaction(sig, base64)`, bincode-decoded; find the instruction whose
   program id is the payment-channels program and whose `data[0] == 1` (the
   `open` discriminator).
3. The `open` ix data is `[disc(1)][salt(8)][deposit(8)][grace(4)][open_slot(8)][count(4)][entries(count×34)]`.
   The preimage = `ix_data[29..]` = `count || entries` (each entry =
   `recipient(32) || bps(2 LE)`), which is exactly the borsh encoding of the
   `DistributeArgs.recipients` vector.
4. The recipient-ATA remaining-accounts tail = `ATA(recipient, mint, token_program)`
   per entry, in order.
5. Sanity check: `sha256(preimage) == channel.distribution_hash` before sending.
   On mismatch (or if the open tx can't be found/decoded) the `distribute` step
   is skipped with a clear error rather than broadcasting a doomed tx.

The empty-plan case works naturally: `count = 0` → preimage = the 4 bytes
`00 00 00 00`, no recipient ATAs, hash = `sha256([0,0,0,0])`.

### Derived accounts

- escrow ATA = `ATA(channel, mint, token_program)`
- payer ATA = `ATA(payer, mint, token_program)`
- payee ATA = `ATA(payee, mint, token_program)`
- treasury ATA = `ATA(treasury_owner, mint, token_program)` — `treasury_owner`
  defaults to `Cs2zdfUNonRdRGsiZUQQLdTxzxVvJZmgiX2mpLYKuEqP` (mainnet), config
  overridable via `JOBS_TREASURY_OWNER`.
- token program resolved from the mint account's owner (SPL Token vs Token-2022).
- `event_authority` = PDA(`["event_authority"]`, program); `self_program` = the
  payment-channels program id.

## Example invocations

Dry-run first (SAFE — nothing is signed or sent):

```bash
cd rust/crates/pay-worker
CHANNEL_ADDRESSES="Chan1...,Chan2..." \
NETWORK=mainnet \
  cargo run --release --bin close-channels
# or, from rust/: just close-channels
```

With a specific RPC and verbose logs (still dry-run):

```bash
RPC_URL="https://mainnet.helius-rpc.com/?api-key=..." \
RUST_LOG="pay_worker=debug,info" \
CHANNEL_ADDRESSES="Chan1..." \
  cargo run --release --bin close-channels
```

Real run (BROADCASTS — only after reviewing the dry-run plan). Prefer Doppler so
the KMS fee-payer config is injected:

```bash
DRY_RUN=false \
CHANNEL_ADDRESSES="Chan1...,Chan2..." \
  doppler run -- cargo run --release --bin close-channels
```

Local signing (sandbox / surfnet, no GCP):

```bash
NETWORK=sandbox \
DRY_RUN=false \
LOCAL_FEE_PAYER_PRIVATE_KEY="[12,34,...]" \
CHANNEL_ADDRESSES="Chan1..." \
  cargo run --release --bin close-channels
```

## Deploy

This crate produces the `close-channels` and `settle-sessions` binaries; its
`Dockerfile` here builds the image (context is `rust/`, since pay-worker is a
workspace member):

```bash
cd rust
just docker-build-pay-worker
```

Actual deployment (Cloud Run Job/service, scheduling, Redis, runtime service
account) is managed by the operator's Terraform stack, which pulls this image
from Artifact Registry. Refer to the deployment repository's runbook for the
deploy flow, including how to trigger `close-channels` via `gcloud run jobs
execute`.

## Limitations / TODOs

- Every action's transaction must be signable by the fee payer alone: the job
  builds the tx with the KMS pubkey in signature slot 0 and refuses to broadcast
  any tx that requires more than one signature. `distribute`, `seal`, and
  `settle_and_seal` (with the operator as payee) fit this; `request_close`
  and `withdraw_payer` require the *payer's* signature, so those paths only
  advance when the operator KMS key IS the payer. A future improvement could
  add partial-signing / multi-signer support.
- `distribute` is skipped (never sent) if the open tx can't be located/decoded
  or the recovered preimage's hash doesn't match `distribution_hash`.
- No compute-budget / priority-fee instructions are added; add them if channels
  need higher landing priority under congestion.
