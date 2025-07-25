# Solana Pay Specification

This spec is currently alpha and subject to change

## Summary
A standard protocol to encode Solana transaction requests within URLs to enable payments and other use cases.

This standard draws inspiration from [BIP 21](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki) and [EIP 681](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-681.md).

## Motivation
A standard URL protocol for requesting native SOL transfers, SPL Token transfers, and Solana transactions allows for a better user experience across apps and wallets in the Solana ecosystem.

These URLs may be encoded in QR codes or NFC tags, or sent between users and applications to request payment and compose transactions.

Applications should ensure that a transaction has been confirmed and is valid before they release goods or services being sold, or grant access to objects or events.

Mobile wallets should register to handle the URL scheme to provide a seamless yet secure experience when Solana Pay URLs are encountered in the environment.

By standardizing a simple approach to solving these problems, we ensure basic compatibility of applications and wallets so developers can focus on higher level abstractions.

## Specification: Transfer Request

A Solana Pay transfer request URL describes a non-interactive request for a SOL or SPL Token transfer.
```html
solana:<recipient>
      ?amount=<amount>
      &spl-token=<spl-token>
      &reference=<reference>
      &label=<label>
      &message=<message>
      &memo=<memo>
      &redirect=<redirect>
```

The request is non-interactive because the parameters in the URL are used by a wallet to directly compose a transaction.

### Recipient
A single `recipient` field is required as the pathname. The value must be the base58-encoded public key of a native SOL account. Associated token accounts must not be used.

Instead, to request an SPL Token transfer, the `spl-token` field must be used to specify an SPL Token mint, from which the associated token address of the recipient must be derived.

### Amount
A single `amount` field is allowed as an optional query parameter. The value must be a non-negative integer or decimal number of "user" units. For SOL, that's SOL and not lamports. For tokens, use [`uiAmountString` and not `amount`](https://docs.solana.com/developing/clients/jsonrpc-api#token-balances-structure).

`0` is a valid value. If the value is a decimal number less than `1`, it must have a leading `0` before the `.`. Scientific notation is prohibited.

If a value is not provided, the wallet must prompt the user for the amount. If the number of decimal places exceed what's supported for SOL (9) or the SPL Token (mint specific), the wallet must reject the URL as **malformed**.

### SPL Token
A single `spl-token` field is allowed as an optional query parameter. The value must be the base58-encoded public key of an SPL Token mint account.

If the field is provided, the [Associated Token Account](https://spl.solana.com/associated-token-account) convention must be used, and the wallet must include a `TokenProgram.Transfer` or `TokenProgram.TransferChecked` instruction as the last instruction of the transaction.

If the field is not provided, the URL describes a native SOL transfer, and the wallet must include a `SystemProgram.Transfer` instruction as the last instruction of the transaction instead.

The wallet must derive the ATA address from the `recipient` and `spl-token` fields. Transfers to auxiliary token accounts are not supported.

### Reference
Multiple `reference` fields are allowed as optional query parameters. The values must be base58-encoded 32 byte arrays. These may or may not be public keys, on or off the curve, and may or may not correspond with accounts on Solana.

If the values are provided, the wallet must include them in the order provided as read-only, non-signer keys to the `SystemProgram.Transfer` or `TokenProgram.Transfer`/`TokenProgram.TransferChecked` instruction in the payment transaction. The values may or may not be unique to the payment request, and may or may not correspond to an account on Solana.

Because Solana validators index transactions by these account keys, `reference` values can be used as client IDs (IDs usable before knowing the eventual payment transaction). The [`getSignaturesForAddress`](https://docs.solana.com/developing/clients/jsonrpc-api#getsignaturesforaddress) RPC method can be used locate transactions this way.

### Label
A single `label` field is allowed as an optional query parameter. The value must be a [URL-encoded](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent) UTF-8 string that describes the source of the transfer request.

For example, this might be the name of a brand, store, application, or person making the request. The wallet should [URL-decode](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/decodeURIComponent) the value and display the decoded value to the user.

### Message
A single `message` field is allowed as an optional query parameter. The value must be a [URL-encoded](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent) UTF-8 string that describes the nature of the transfer request.

For example, this might be the name of an item being purchased, an order ID, or a thank you note. The wallet should [URL-decode](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/decodeURIComponent) the value and display the decoded value to the user.

### Memo
A single `memo` field is allowed as an optional query parameter. The value must be a [URL-encoded](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent) UTF-8 string that must be included in an [SPL Memo](https://spl.solana.com/memo) instruction in the payment transaction.

The wallet must [URL-decode](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/decodeURIComponent) the value and should display the decoded value to the user. The memo will be recorded by validators and should not include private or sensitive information.

If the field is provided, the wallet must include a `MemoProgram` instruction as the second to last instruction of the transaction, immediately before the SOL or SPL Token transfer instruction, to avoid ambiguity with other instructions in the transaction.

### Redirect
A single `redirect` field is allowed as an optional query parameter. The value must be a [URL-encoded](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent) absolute HTTPS or `solana:` URL.

The wallet must [URL-decode](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/decodeURIComponent) the value. If it is a HTTPS URL then the wallet should display the decoded value to the user. 

Redirect URLs should only be followed if the transaction is successful. A transaction should be considered successful if the user approves it and the broadcast transaction has a Confirmed or Finalized status. If the redirect is a HTTPS URL then the wallet should open the URL using any browser. This may be a browser included in the wallet. If it is a `solana:` URL then the wallet should treat it as a new Solana Pay request.

### Examples

##### URL describing a transfer request for 1 SOL.
```
solana:mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN?amount=1&label=Michael&message=Thanks%20for%20all%20the%20fish&memo=OrderId12345
```

##### URL describing a transfer request for 0.01 USDC.
```
solana:mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN?amount=0.01&spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
```

##### URL describing a transfer request for SOL. The user must be prompted for the amount.
```
solana:mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN?label=Michael
```

##### URL describing a transfer request for 1 SOL with a redirect
```
solana:mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN?amount=1&label=Michael&message=Thanks%20for%20all%20the%20fish&memo=OrderId12345&redirect=https%3A%2F%2Fexample.com
```

## Specification: Transaction Request

A Solana Pay transaction request URL describes an interactive request for any Solana transaction.
```html
solana:<link>
```

The request is interactive because the parameters in the URL are used by a wallet to make an HTTP request to compose a transaction.

### Link
A single `link` field is required as the pathname. The value must be a conditionally [URL-encoded](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent) absolute HTTPS URL.

If the URL contains query parameters, it must be URL-encoded. Protocol query parameters may be added to this specification. URL-encoding the value prevents conflicting with protocol parameters.

If the URL does not contain query parameters, it should not be URL-encoded. This produces a shorter URL and a less dense QR code.

In either case, the wallet must [URL-decode](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/decodeURIComponent) the value. This has no effect if the value isn't URL-encoded. If the decoded value is not an absolute HTTPS URL, the wallet must reject it as **malformed**.

#### GET Request

The wallet should make an HTTP `GET` JSON request to the URL. The request should not identify the wallet or the user.

The wallet should make the request with an [Accept-Encoding header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Encoding), and 
should respond with a [Content-Encoding header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding) for HTTP compression.

The wallet should display the domain of the URL as the request is being made.

#### GET Response

The wallet must handle HTTP [client error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#client_error_responses), [server error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#server_error_responses), and [redirect responses](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#redirection_messages). The application must respond with these, or with an HTTP `OK` JSON response with a body of
```json
{"label":"<label>","icon":"<icon>"}
```

The `<label>` value must be a UTF-8 string that describes the source of the transaction request. For example, this might be the name of a brand, store, application, or person making the request.

The `<icon>` value must be an absolute HTTP or HTTPS URL of an icon image. The file must be an SVG, PNG, or WebP image, or the wallet must reject it as **malformed**.

The wallet should not cache the response except as instructed by [HTTP caching](https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching#controlling_caching) response headers.

The wallet should display the label and render the icon image to user.

#### POST Request

The wallet must make an HTTP `POST` JSON request to the URL with a body of
```json
{"account":"<account>"}
```

The `<account>` value must be the base58-encoded public key of an account that may sign the transaction.

The wallet should make the request with an [Accept-Encoding header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Encoding), and the application should respond with a [Content-Encoding header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding) for HTTP compression.

The wallet should display the domain of the URL as the request is being made. If a `GET` request was made, the wallet should also display the label and render the icon image from the response.

#### POST Response

The wallet must handle HTTP [client](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#client_error_responses) and [server](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#server_error_responses) errors in accordance with the [error handling](#error-handling) specification. [Redirect responses](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#redirection_messages) must be handled appropriately. The application must respond with these, or with an HTTP `OK` JSON response with a body of
```json
{"transaction":"<transaction>"}
```

The `<transaction>` value must be a base64-encoded [serialized transaction](https://solana-foundation.github.io/solana-web3.js/v1.x/classes/Transaction.html#serialize). The wallet must base64-decode the transaction and [deserialize it](https://solana-foundation.github.io/solana-web3.js/v1.x/classes/Transaction.html#from).

The application may respond with a partially or fully signed transaction. The wallet must validate the transaction as **untrusted**.

If the transaction [`signatures`](https://solana-foundation.github.io/solana-web3.js/v1.x/classes/Transaction.html#signatures) are empty:
  - The application should set the [`feePayer`](https://solana-foundation.github.io/solana-web3.js/v1.x/classes/Transaction.html#feePayer) to the `account` in the request, or the zero value (`new PublicKey(0)` or `new PublicKey("11111111111111111111111111111111")`).
  - The application should set the [`recentBlockhash`](https://solana-foundation.github.io/solana-web3.js/v1.x/classes/Transaction.html#recentBlockhash) to the [latest blockhash](https://solana-foundation.github.io/solana-web3.js/v1.x/classes/Connection.html#getLatestBlockhash), or the zero value (`new PublicKey(0).toBase58()` or `"11111111111111111111111111111111"`).
  - The wallet must ignore the [`feePayer`](https://solana-foundation.github.io/solana-web3.js/v1.x/classes/Transaction.html#feePayer) in the transaction and set the `feePayer` to the `account` in the request.
  - The wallet must ignore the [`recentBlockhash`](https://solana-foundation.github.io/solana-web3.js/v1.x/classes/Transaction.html#recentBlockhash) in the transaction and set the `recentBlockhash` to the [latest blockhash](https://solana-foundation.github.io/solana-web3.js/v1.x/classes/Connection.html#getLatestBlockhash).

If the transaction [`signatures`](https://solana-foundation.github.io/solana-web3.js/v1.x/classes/Transaction.html#signatures) are nonempty:
  - The application must set the [`feePayer`](https://solana-foundation.github.io/solana-web3.js/v1.x/classes/Transaction.html#feePayer) to the [public key of the first signature](https://solana-foundation.github.io/solana-web3.js/v1.x/modules.html#SignaturePubkeyPair).
  - The application must set the [`recentBlockhash`](https://solana-foundation.github.io/solana-web3.js/v1.x/classes/Transaction.html#recentBlockhash) to the [latest blockhash](https://solana-foundation.github.io/solana-web3.js/v1.x/classes/Connection.html#getLatestBlockhash).
  - The application must serialize and deserialize the transaction before signing it. This ensures consistent ordering of the account keys, as a workaround for [this issue](https://github.com/solana-labs/solana/issues/21722).
  - The wallet must not set the  [`feePayer`](https://solana-foundation.github.io/solana-web3.js/v1.x/classes/Transaction.html#feePayer) and [`recentBlockhash`](https://solana-foundation.github.io/solana-web3.js/v1.x/classes/Transaction.html#recentBlockhash).
  - The wallet must verify the signatures, and if any are invalid, the wallet must reject the transaction as **malformed**.

The wallet must only sign the transaction with the `account` in the request, and must do so only if a signature for the `account` in the request is expected.

If any signature except a signature for the `account` in the request is expected, the wallet must reject the transaction as **malicious**.

The application may also include an optional `message` field in the response body:
```json
{"message":"<message>","transaction":"<transaction>"}
```

The `<message>` value must be a UTF-8 string that describes the nature of the transaction response. The wallet must display at least the first 80 characters of the `message` field to the user if it is included in the response.

For example, this might be the name of an item being purchased, a discount applied to the purchase, or a thank you note. The wallet should display the value to the user.

The application may also include an optional `redirect` field in the response body:

```json
{"redirect":"<redirect>","transaction":"<transaction>"}
```

The `redirect` field must be an absolute HTTPS or `solana:` URL.

If it is a HTTPS URL then the wallet should display the decoded value to the user. 

Redirect URLs should only be followed if the transaction is successful. A transaction should be considered successful if the user approves it and the broadcast transaction has a Confirmed or Finalized [Commitment Status](https://docs.solana.com/cluster/commitments). If the redirect is a HTTPS URL then the wallet should open the URL using any browser. This may be a browser included in the wallet. If it is a `solana:` URL then the wallet should treat it as a new Solana Pay request.

The wallet and application should allow additional fields in the request body and response body, which may be added by future specification.

#### Error Handling
If the application responds with an HTTP [client](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#client_error_responses) or [server](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#server_error_responses) error in response to the POST or PUT operations, the wallet must consider the entire transaction request as failed.

Client and server errors may optionally be accompanied by a JSON body containing a UTF-8 string `message` field describing the nature of the error:
```json
{"message":"<message>"}
```

The wallet must display at least the first 80 characters of the `message` field to the user if it is included in the response.

### Example

##### URL describing a transaction request.
```
solana:https://example.com/solana-pay
```

##### URL describing a transaction request with query parameters.
```
solana:https%3A%2F%2Fexample.com%2Fsolana-pay%3Forder%3D12345
```

##### GET Request
```
GET /solana-pay?order=12345 HTTP/1.1
Host: example.com
Connection: close
Accept: application/json
Accept-Encoding: br, gzip, deflate
```

##### GET Response
```
HTTP/1.1 200 OK
Connection: close
Content-Type: application/json
Content-Length: 62
Content-Encoding: gzip

{"label":"Michael Vines","icon":"https://example.com/icon.svg"}
```

##### POST Request
```
POST /solana-pay?order=12345 HTTP/1.1
Host: example.com
Connection: close
Accept: application/json
Accept-Encoding: br, gzip, deflate
Content-Type: application/json
Content-Length: 57

{"account":"mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN"}
```

##### POST Response
```
HTTP/1.1 200 OK
Connection: close
Content-Type: application/json
Content-Length: 298
Content-Encoding: gzip

{"message":"Thanks for all the fish","transaction":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAECC4JMKqNplIXybGb/GhK1ofdVWeuEjXnQor7gi0Y2hMcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQECAAAMAgAAAAAAAAAAAAAA",
"redirect": "https://example.com"}
```

## Extensions

Additional formats and fields may be incorporated into this specification to enable new use cases while ensuring compatibility with apps and wallets.

Please open a Github issue to propose changes to the specification in order to solicit feedback from application and wallet developers.

[An actual example of such a proposal.](https://github.com/solana-labs/solana-pay/issues/26)
