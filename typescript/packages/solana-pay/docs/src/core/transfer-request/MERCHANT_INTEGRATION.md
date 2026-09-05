---
title: Create a transfer request
slug: /core/transfer-request/merchant-integration
---

This section describes how a merchant can integrate Solana Pay transfer requests into their payments flow. It shows how to create a payment request link, encode it into a QR code, find the transaction, and validate it.

This guide walks through an example of a QR code-based Point of Sale system that accepts payments via Solana Pay.

The complete example code can be found [here][5].

## Requirements

Before you can receive payments, you'll need to obtain a native SOL address. This doesn't cost anything, and you can use any wallet to get started.

If you want to receive USDC or another SPL token on Solana, you'll need to create a token account, which may require a small amount of SOL.

One way to do both is to use Coinbase, which will provide a native SOL deposit address and an associated USDC token account to receive payments.

---

## 1. Set up Solana Pay

Install the packages and import them in your code.

```shell
pnpm add @solana/pay
```

### 1.1 Import necessary modules

Import the modules used to work with Solana Pay.

```typescript
import { address, generateKeyPairSigner } from '@solana/kit';
import { createMerchantClient } from '@solana/pay';
```

### 1.2 Create a merchant client

The merchant client provides all the methods you need to encode payment URLs, generate QR codes, and find/validate payments. No signer is required.

<details open>
    <summary>
        Create a merchant client connected to <code>devnet</code>
    </summary>

<br/>

```typescript
async function main() {
    // Variable to keep state of the payment status
    let paymentStatus: string;

    // Create a merchant client connected to devnet
    console.log('1. Establish connection to the network');
    const merchant = createMerchantClient({
        rpcUrl: 'https://api.devnet.solana.com',
    });
}
```

</details>

## 2. Create a payment request link

Solana Pay uses a [standard URL scheme](../../SPEC.md) across wallets for native SOL and SPL Token payments. Several parameters are encoded within the link representing an intent to collect payment from a customer.

<details>
    <summary>
        Create a payment request link with a <code>recipient</code>, <code>amount</code>, <code>label</code>, <code>message</code> ,  <code>memo</code> and <code>reference</code>.
    </summary>

<br/>

```typescript
// -- snippet -- //

/**
 * Simulate a checkout experience
 *
 * Recommendation:
 * `amount` and `reference` should be created in a trusted environment (server).
 * The `reference` should be unique to a single customer session,
 * and will be used to find and validate the payment in the future.
 *
 */
console.log('2. Simulate a customer checkout \n');
const recipient = address('MERCHANT_WALLET');
const amount = 20;
const referenceSigner = await generateKeyPairSigner();
const reference = referenceSigner.address;
const label = 'Jungle Cats store';
const message = 'Jungle Cats store - your order - #001234';
const memo = 'JC#4098';

/**
 * Create a payment request link
 *
 * Solana Pay uses a standard URL scheme across wallets for native SOL and SPL Token payments.
 * Several parameters are encoded within the link representing an intent to collect payment from a customer.
 */
console.log('3. Create a payment request link \n');
const url = merchant.pay.encodeURL({ recipient, amount, reference, label, message, memo });
```

See [full code snippet][6]

</details>

### Optional. SPL token transfer

For SPL Token transfers, use the `splToken` parameter. The `splToken` is the mint address of the SPL token.

<details>
    <summary>See code snippet</summary>

```typescript
/**
 * Simulate a checkout experience with an SPL token
 */
console.log('2. Simulate a customer checkout \n');
const splToken = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');

/**
 * Create a payment request link
 *
 * Solana Pay uses a standard URL scheme across wallets for native SOL and SPL Token payments.
 * Several parameters are encoded within the link representing an intent to collect payment from a customer.
 */
console.log('3. Create a payment request link \n');
const url = merchant.pay.encodeURL({
    recipient,
    amount,
    splToken,
    reference,
    label,
    message,
    memo,
});
```

</details>

## 3. Encode link into a QR code

Now that you've created a payment link, you need a way to show it to your customers.

<details>
    <summary>
        Encode the link into a QR code.
    </summary>

```typescript
// -- snippet -- //

console.log('3. Create a payment request link \n');
const url = merchant.pay.encodeURL({ recipient, amount, reference, label, message, memo });

// encode URL in QR code
const qrCode = merchant.pay.createQR(url);
```

</details>

<br/>

![qr code](../../images/solana-pay.png)

### 3.1 Add the QR code to your payment page

The QR code needs to be visible on your payment page.

<details>
    <summary>
        Add the QR code to an element on the payment page
    </summary>

```typescript
// -- snippet -- //

console.log('3. Create a payment request link \n');
const url = merchant.pay.encodeURL({ recipient, amount, reference, label, message, memo });

// encode URL in QR code
const qrCode = merchant.pay.createQR(url);

// get a handle of the element
const element = document.getElementById('qr-code');

// append QR code to the element
qrCode.append(element);
```

</details>

Instructions on integrating with your framework of choice can be found [here][1].

## 4. Show a payment status page

With the payment link set up and shown to the customer, you will need to ensure that the customer has paid for the item before shipping their order.

When a customer approves the payment request in their wallet, this transaction exists on-chain. You can use any references encoded into the payment link to find the exact transaction on-chain.

<details>
    <summary>
        Use <code>findReference</code> to find the on-chain transaction. Provide a <code>reference</code> to this function that identifies the transaction associated with the order.
    </summary>

<br/>

```typescript
// -- snippet -- //

/**
 * Wait for payment to be confirmed
 *
 * When a customer approves the payment request in their wallet, this transaction exists on-chain.
 * You can use any references encoded into the payment link to find the exact transaction on-chain.
 * Important to note that we can only find the transaction when it's **confirmed**
 */
console.log('\n5. Find the transaction');
const signatureInfo = await merchant.pay.findReference(reference, { commitment: 'confirmed' });

// Update payment status
paymentStatus = 'confirmed';
```

**Note**: The `findReference` function uses `confirmed` as the default commitment value. This can, on rare occasions, result in a transaction that is not fully complete. For full finality, use `finalized`. This can result in slower transaction completion.

See [full code snippet][7]

</details>

### 4.1 Retries

If a transaction with the given reference can't be found, the `findReference` function will throw an error. There are a few reasons why this could be:

-   Transaction is not yet confirmed
-   Customer is yet to approve/complete the transaction
-   The transaction has aged out of a non-archival RPC node's history

An empty result is inconclusive: it can't distinguish a customer who never paid from a payment this node hasn't indexed yet, or no longer serves. Treat the error as "not found yet" and decide on your own timeout, not on the error itself. To branch on the reason programmatically, read the machine-readable `code` property of `FindReferenceError`: it is `'not found'` here and from a `watchReference` subscription that ends before a transaction is seen, and `'aborted'` when a `watchReference` subscription is cancelled.

<details>
    <summary>
        You can implement a polling strategy to query for the transaction periodically.
    </summary>

```typescript
// -- snippet -- //

import { FindReferenceError } from '@solana/pay';

let signatureInfo;

return new Promise((resolve, reject) => {
    /**
     * Retry until we find the transaction
     *
     * If a transaction with the given reference can't be found, the `findReference`
     * function will throw an error. There are a few reasons why this could be a false negative:
     *
     * - Transaction is not yet confirmed
     * - Customer is yet to approve/complete the transaction
     *
     * You can implement a polling strategy to query for the transaction periodically.
     */
    const interval = setInterval(async () => {
        console.log('Checking for transaction...', count);
        try {
            signatureInfo = await merchant.pay.findReference(reference, { commitment: 'confirmed' });
            console.log('\n Signature found: ', signatureInfo.signature);
            clearInterval(interval);
            resolve(signatureInfo);
        } catch (error: any) {
            if (!(error instanceof FindReferenceError)) {
                console.error(error);
                clearInterval(interval);
                reject(error);
            }
        }
    }, 250);
});
```

See [full code snippet][7]

</details>

**Alternative: WebSocket subscription**

Instead of polling, you can use `watchReference` to subscribe to transaction notifications via WebSocket:

```typescript
const result = await merchant.pay.watchReference(reference, { commitment: 'confirmed' });
console.log('Payment received:', result.signature);
```

### 4.2 Validating the transaction

Once the `findReference` function returns a signature, it confirms that a transaction that references the order has been recorded on-chain. But it doesn't guarantee that a valid transfer with the expected amount and recipient happened.

<details>
    <summary>
        <code>validateTransfer</code> allows you to validate that the transaction signature found matches the transaction that you expected.
    </summary>

```typescript
// -- snippet -- //

/**
 * Validate transaction
 *
 * Once the `findReference` function returns a signature,
 * it confirms that a transaction with reference to this order has been recorded on-chain.
 *
 * `validateTransfer` allows you to validate that the transaction signature
 * found matches the transaction that you expected.
 */
console.log('\n6. Validate transaction \n');

try {
    await merchant.pay.validateTransfer(signatureInfo.signature, { recipient, amount });

    // Update payment status
    paymentStatus = 'validated';
    console.log('Payment validated');
    console.log('Ship order to customer');
} catch (error) {
    console.error('Payment failed', error);
}
```

See [full code snippet][8]

</details>

## Best practices

We recommend handling a customer session in a secure environment. Building a secure integration with Solana Pay requires a payment flow as follows:

![best practices diagram](../../images/transfer-request-best-practice-dark.png)

1. Customer goes to the payment page
2. Merchant frontend (client) sends order information to the backend
3. Merchant backend (server) generates a reference public key and stores it in a database with the expected amount for the shopping cart / pending purchase (unique to each customer's checkout session).
4. Merchant backend redirects the user to the confirmation page with the generated reference public key.
5. The confirmation page redirects to the merchant with the transaction signature.
6. Merchant backend checks that the transaction is valid for the checkout session by validating the transaction with the reference and amount stored in step 3.

The steps outlined above prevents:

-   A different transaction from being used to trick the merchant
-   The frontend from being manipulated to show a confirmed transaction

<!-- References -->

[1]: https://github.com/nickvdyck/qr-code-styling
[2]: https://spl.solana.com/memo
[3]: https://github.com/solana-labs/solana/issues/19535
[4]: https://github.com/solana-foundation/pay/tree/main/typescript/packages/solana-pay/examples/point-of-sale
[5]: https://github.com/solana-foundation/pay/tree/main/typescript/packages/solana-pay/core/example
[6]: https://github.com/solana-foundation/pay/blob/main/typescript/packages/solana-pay/core/example/index.ts
[7]: https://github.com/solana-foundation/pay/blob/main/typescript/packages/solana-pay/core/example/index.ts
[8]: https://github.com/solana-foundation/pay/blob/main/typescript/packages/solana-pay/core/example/index.ts
