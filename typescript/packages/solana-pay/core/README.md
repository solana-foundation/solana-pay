# Solana Pay

`@solana/pay` is a JavaScript library for facilitating commerce on Solana by using a token transfer URL scheme. The URL scheme ensures that no matter the wallet or service used, the payment request must be created and interpreted in one standard way.

> **v1.1** — This version is built on [`@solana/kit`](https://github.com/anza-xyz/kit) v8 and supports legacy, v0, and v1 transactions (see [Transaction versions](#transaction-versions)). If you're migrating from v0.2 (which used `@solana/web3.js`), see the [Migration Guide](#migration-guide) below.

## Requirements

- Node.js >= 20 (required for Ed25519 crypto.subtle support)

## Installation

```bash
npm install @solana/pay @solana/kit
```

### Peer dependencies

| Package | Version |
|---------|---------|
| `@solana/kit` | `^8.1.0` |

### Optional dependencies (for `createTransfer` / `validateTransfer`)

| Package | Version |
|---------|---------|
| `@solana-program/system` | `^0.14.0` |
| `@solana-program/token` | `^0.16.0` |
| `@solana-program/token-2022` | `^0.16.0` |
| `@solana-program/memo` | `^0.13.0` |

## Quick Start

### Merchant client

For the receiving side — encode payment URLs, generate QR codes, find and validate payments. No signer needed.

```ts
import { address } from '@solana/kit';
import { createMerchantClient } from '@solana/pay';

const merchant = createMerchantClient({
  rpcUrl: 'https://api.devnet.solana.com',
});

const recipient = address('MERCHANT_WALLET_ADDRESS');
const reference = address('UNIQUE_REFERENCE_ADDRESS');

// Encode a payment URL and show as QR code
const url = merchant.pay.encodeURL({ recipient, amount: 1, reference });
const qr = merchant.pay.createQR(url);

// After customer pays, find and validate the transaction
const found = await merchant.pay.findReference(reference);
await merchant.pay.validateTransfer(found.signature, { recipient, amount: 1, reference });
```

### Wallet client

For the paying side — parse payment URLs, create transfers, and send transactions. Includes a transaction planner/executor so you don't need to manually compose transactions.

```ts
import { createWalletClient } from '@solana/pay';

const wallet = createWalletClient({
  rpcUrl: 'https://api.devnet.solana.com',
  payer: myWalletSigner,
});

// Parse a Solana Pay URL and send the payment
const parsed = wallet.pay.parseURL(url);
const instructions = await wallet.pay.createTransfer({
  recipient: parsed.recipient,
  amount: parsed.amount,
});
await wallet.sendTransaction(instructions);
```

### Combined client

Use `createSolanaPayClient` when you need both merchant and wallet methods on one client:

```ts
import { createSolanaPayClient } from '@solana/pay';

const client = createSolanaPayClient({
  rpcUrl: 'https://api.devnet.solana.com',
  payer: myWalletSigner,
});

const url = client.pay.encodeURL({ recipient, amount: 1 });
const instructions = await client.pay.createTransfer({ recipient, amount: 1 });
await client.sendTransaction(instructions);
```

### Standalone usage

Use the functions directly without a client:

```ts
import { address, createSolanaRpc } from '@solana/kit';
import { encodeURL, createTransfer, findReference, validateTransfer, createQR } from '@solana/pay';

const rpc = createSolanaRpc('https://api.devnet.solana.com');
const recipient = address('MERCHANT_WALLET_ADDRESS');

const url = encodeURL({ recipient, amount: 1 });
const qr = createQR(url);
const instructions = await createTransfer(rpc, sender, { recipient, amount: 1 });

const signatureInfo = await findReference(rpc, reference);
await validateTransfer(rpc, signatureInfo.signature, { recipient, amount: 1 });
```

### Kit Plugin usage

Compose with other kit plugins for full control:

```ts
import { createClient } from '@solana/kit';
import { solanaRpcConnection } from '@solana/kit-plugin-rpc';
import { payerFromFile } from '@solana/kit-plugin-signer';
import { solanaPayMerchant, solanaPayWallet } from '@solana/pay';

const client = await createClient()
  .use(solanaRpcConnection({ rpcUrl: 'https://api.devnet.solana.com' }))
  .use(payerFromFile('~/.config/solana/id.json'))
  .use(solanaPayMerchant())
  .use(solanaPayWallet());

const url = client.pay.encodeURL({ recipient, amount: 1 });
const instructions = await client.pay.createTransfer({ recipient, amount: 1 });
```

## API

### URL Encoding & Parsing

- **`encodeURL(fields)`** — Encode a transfer or transaction request into a `solana:` URL.
- **`parseURL(url)`** — Parse a `solana:` URL into its fields.

### QR Codes

- **`createQR(url, size?, background?, color?)`** — Create a QR code from a Solana Pay URL.

### Transfers

- **`createTransfer(rpc, sender, fields)`** — Create transfer `Instruction[]` for a payment.
- **`findReference(rpc, reference, options?)`** — Find a transaction signature by reference address. Throws `FindReferenceError` with machine-readable `code` (`'not found'` when no transaction was seen — the RPC returned no signatures, or a `watchReference` subscription ended before any notification arrived; an inconclusive read that can't tell "never paid" from "not indexed yet" or "aged out of a non-archival node" — or `'aborted'` when a `watchReference` subscription is cancelled) so callers never have to string-match the message.
- **`validateTransfer(rpc, signature, fields, options?)`** — Validate that a confirmed transaction matches the expected payment.

### Transaction Requests

- **`fetchTransaction(rpc, account, link, options?)`** — Fetch a transaction from a transaction request endpoint.

### Clients

- **`createMerchantClient({ rpcUrl })`** — Merchant client with RPC and merchant plugin. No signer needed.
- **`createWalletClient({ rpcUrl, payer })`** — Wallet client with RPC, payer, transaction planner/executor, and wallet plugin.
- **`createSolanaPayClient({ rpcUrl, payer })`** — Combined client with all merchant + wallet methods.

### Plugins

- **`solanaPayMerchant()`** — Merchant plugin: `encodeURL`, `createQR`, `createQROptions`, `findReference`, `validateTransfer`.
- **`solanaPayWallet()`** — Wallet plugin: `parseURL`, `createTransfer`, `fetchTransaction`.

## How it works

### Web app to mobile wallet

Payment requests can be encoded as a URL according to the scheme, scanned using a QR code, sent and confirmed by the wallet, and discovered by the app.

### Web app to browser wallet

With a Solana Pay button, you could integrate an embeddable payment button that can be added to your existing app.

### Mobile app to mobile wallet

Payment requests could be encoded as a deep link. The app prepares a payment request, and passes control to the wallet. The wallet signs, sends, and confirms it, or cancels the request and passes control back to the app.

## Transaction Requests

A Solana Pay transaction request URL describes an interactive request for any Solana transaction. The parameters in the URL are used by a wallet to make an HTTP request to compose any transaction.

## Transfer Requests

A Solana Pay transfer request URL describes a non-interactive request for a SOL or SPL Token transfer. The parameters in the URL are used by a wallet to directly compose the transaction.

## Transaction versions

The library supports legacy, v0, and v1 transactions:

- `validateTransfer` validates transfers landed in any of the three formats.
- `fetchTransaction` decodes merchant-supplied transactions in any of the three formats, and preserves a v1 transaction's message-level config (compute unit limit, priority fee, loaded accounts data size limit, heap size) through the fee payer swap.
- The merchant plugin's `buildTransaction` builds v0 by default; pass `{ version: 1, config: { ... } }` to build a v1 transaction.

The v1 format ([SIMD-0385](https://solana.com/upgrades/larger-transaction-sizes)) raises the transaction size cap from 1232 to 4096 bytes and moves compute unit and data size limits from ComputeBudget instructions into a message-level config. Note that a v1 transaction with no `computeUnitLimit` in its config is budgeted **zero** compute units, so always set one when building v1 transactions. v1 requires the `txv1aq4pp281K9um3tnPgkfX8UqtFT6wcVW3hNezGLL` feature gate to be active on the target cluster (Agave v4.2+); legacy and v0 remain fully supported.

## Migration Guide

### v0.2 → v1.0

**Breaking changes:**

| v0.2 (`@solana/web3.js`) | v1.0 (`@solana/kit`) |
|--------------------------|----------------------|
| `PublicKey` | `Address` (branded string — use `address()` to create, `===` to compare) |
| `Connection` | `Rpc` from `@solana/kit` |
| `BigNumber` (from `bignumber.js`) | `number` — plain JS number for human-readable amounts |
| `createTransfer()` returns `Transaction` | Returns `Instruction[]` — compose with kit's `pipe()` + `createTransactionMessage()` |
| `sender: PublicKey` | `sender: TransactionSigner` |
| `@solana/spl-token` | `@solana-program/token` |
| `Buffer` | `Uint8Array` / `TextEncoder` |

**Typical migration:**

```diff
- import { Connection, PublicKey, Transaction } from '@solana/web3.js';
+ import { address, createSolanaRpc, pipe, createTransactionMessage,
+          setTransactionMessageFeePayer, appendTransactionMessageInstructions,
+          setTransactionMessageLifetimeUsingBlockhash, compileTransaction,
+          signTransaction, getBase64EncodedWireTransaction } from '@solana/kit';

- const connection = new Connection('https://api.devnet.solana.com');
+ const rpc = createSolanaRpc('https://api.devnet.solana.com');

- const recipient = new PublicKey('...');
+ const recipient = address('...');

- const transaction = await createTransfer(connection, sender.publicKey, { recipient, amount });
- transaction.feePayer = sender.publicKey;
- transaction.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
+ const instructions = await createTransfer(rpc, sender, { recipient, amount });
+ // Compose transaction using kit pipe() pattern
```

## License

The Solana Pay JavaScript SDK is open source and available under the MIT License. See the [LICENSE](./LICENSE) file for more info.

Subject to the foregoing, the Terms of Service available at solana.com/tos
