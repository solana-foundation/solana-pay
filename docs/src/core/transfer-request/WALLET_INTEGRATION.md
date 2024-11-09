---
title: Handle a transfer request
slug: /core/transfer-request/wallet-integration
---

This section describes how a wallet provider can support payment links in their wallet. It shows how to parse the payment URL and create a transaction from it.

This guide walks through an **example** implementation for wallet providers. The purpose of this is to make it easy for wallets to implement the protocol correctly.

---

## 1. Set up Solana Pay

Install the packages and import them in your code.

**npm**

```shell=
npm install @solana/pay @solana/web3.js@1 --save
```

**yarn**

```shell=
yarn add @solana/pay @solana/web3.js@1
```

## 2. Parse payment request link

As a wallet provider, you will have to parse the received URL to extract the parameters. For more information on the URL format, please see the [specification](../../SPEC.md).

<details>
    <summary>Parse the URL to retrieve all possible fields:</summary>

<br/>

```ts
import { parseURL } from '@solana/pay';

/**
 * For example only
 *
 * The URL that triggers the wallet interaction; follows the Solana Pay URL scheme
 * The parameters needed to create the correct transaction is encoded within the URL
 */
const url =
    'solana:mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN?amount=0.01&reference=82ZJ7nbGpixjeDCmEhUcmwXYfvurzAgGdtSMuHnUgyny&label=Michael&message=Thanks%20for%20all%20the%20fish&memo=OrderId5678';
const { recipient, amount, splToken, reference, label, message, memo } = parseURL(url);
```

See [full code snippet][9]

</details>

## 3. Create transaction

Use the `createTransaction` function to create a transaction with the parameters from the `parseURL` function with an additional `payer`.

The `payer` **should** be the public key of the current users' wallet.

<details>
    <summary>Create transaction reference implementation</summary>

<br/>

```typescript
import { parseURL, createTransaction } from '@solana/pay';

const url =
    'solana:mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN?amount=0.01&reference=82ZJ7nbGpixjeDCmEhUcmwXYfvurzAgGdtSMuHnUgyny&label=Michael&message=Thanks%20for%20all%20the%20fish&memo=OrderId5678';
const { recipient, amount, splToken, reference, label, message, memo } = parseURL(url);

/**
 * Create the transaction with the parameters decoded from the URL
 */
const payer = CUSTOMER_WALLET.publicKey;
const tx = await createTransfer(connection, payer, { recipient, amount, reference, memo });
```

See [full code snippet][10]

</details>

This transaction **should** represent the original intent of the payment request link. The example implementation walks through the steps on how to construct the transaction:

**Native SOL transfer**

1. Check that the payer and recipient accounts exist
2. Check the payer and recipient are valid native accounts
3. Check the payer has enough lamports for the transfer
4. Create an instruction to transfer native SOL
5. If references were included, add them to the instruction
6. If a memo was included, create an instruction for the memo program

**SPL token transfer**

1. Check that the payer and recipient accounts exist
2. Check the token provided is an initialized mint
3. Check the payer and recipient's Associated Token Account (ATA) exists
4. Check the payer has enough lamports for the transfer
5. Create an instruction to transfer SPL tokens
6. If references were included, add them to the instruction
7. If a memo was included, create an instruction for the memo program

## 4. Complete transaction

With the transaction formed. The user must be prompted to approve the transaction.

The `label` and `message` **should** be shown to the user, as it gives added context to the user on the transaction.

<details>
    <summary>
        Finally, use <code>sendAndConfirmTransaction</code> to complete the transaction.
    </summary>

```typescript
const { recipient, message, memo, amount, reference, label } = parseURL(url);
console.log('label: ', label);
console.log('message: ', message);

/**
 * Create the transfer with the parameters decoded from the URL
 */
const tx = await createTransfer(connection, payer, { recipient, amount, reference, memo });

/**
 * Send the transaction to the network
 */
sendAndConfirmTransaction(connection, tx, [CUSTOMER_WALLET]);
```

See [full code snippet][11]

</details>

## Deep linking

Wallet providers building for mobile or wearable devices are encouraged to register their app as a handler for the Solana Pay URL scheme `solana:`.

For example, when a payment request is presented as a QR code, the payer should ideally be able to read the code using the native scanning capability of their device and have the appropriate wallet open with the transaction prefilled.

URLs can be embedded in the environment in web pages, QR codes, NFC tags and potential new formats. To avoid inadvertent transfer of tokens, care must be taken when designing wallets to ensure that transactions cannot accidentally be triggered and sent.

<!-- References -->

[9]: https://github.com/solana-labs/solana-pay/blob/master/core/example/payment-flow-merchant/simulateWalletInteraction.ts#L13
[10]: https://github.com/solana-labs/solana-pay/blob/master/core/example/payment-flow-merchant/simulateWalletInteraction.ts#L27
[11]: https://github.com/solana-labs/solana-pay/blob/master/core/example/payment-flow-merchant/simulateWalletInteraction.ts#L35
