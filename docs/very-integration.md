# Very integration

Pay can use Very Palm verification as an optional authorization gate for MPP
subscription activation. The feature is opt-in at build time and at runtime;
the existing platform gate remains the default.

This integration gates the operation that grants recurring pull authority. It
does not replace the wallet or export its private key. Pay still constructs and
signs the activation transaction locally after Very returns a valid,
action-bound human authorization attestation.

## Security contract

Before opening Very, Pay validates that the subscription request and the
transaction builder agree on the currency, amount, recipient, cadence, Plan,
and on-chain Plan terms. It then hashes a canonical, one-time authorization
envelope containing:

- the server challenge identity and expiry;
- network, program, Plan, mint, token program, merchant, puller, and recipient;
- amount in base units, decimals, cadence, and subscription expiry;
- request/operator context, fee-payer terms, Pay account name, and subscriber wallet;
- a fresh authorization nonce and short authorization expiry.

Pay sends Very the registered device id and public key, audience, action hash,
and a human-readable description; it does not send the wallet private key or
transaction payload. After Palm approval, Pay fetches Very's JWKS and verifies
the Ed25519 JWT locally. The gate fails closed unless the signature, issuer,
subject, audience, registered device, action hash, Palm verification method,
expiry, and freshness all match. Pay checks the server challenge expiry again
after approval and fetches a fresh Solana blockhash immediately before signing.

Very is currently restricted to typed subscription-activation intents. Ordinary
MPP charges, sessions, x402 payments, and subscription renewals retain their
existing behavior.

## Configuration

Build the CLI with the optional backend:

```sh
cd rust
cargo build -p pay --features very
```

Set `PAY_AUTH_BACKEND=very` to select it. A registered Very device identity is
also required:

```sh
export PAY_AUTH_BACKEND=very
export VERY_DEVICE_ID="your-registered-device-id"
export VERY_PUBLIC_KEY="your-registered-base64-DER-SPKI-public-key"
```

Optional overrides are:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PAY_VERY_API_BASE_URL` | `https://api.ag9.ai` | Current Very attestation origin (legacy hostname) |
| `PAY_VERY_JWKS_URL` | `<api-base>/.well-known/jwks.json` | Trusted Ed25519 key set |
| `PAY_VERY_ISSUER` | `api.ag9.ai` | Required JWT issuer (legacy hostname) |
| `PAY_VERY_AUDIENCE` | `pay.sh` | Attestation audience and action audience |
| `PAY_VERY_TIMEOUT_SECONDS` | `240` | Overall approval wait |
| `PAY_VERY_REQUEST_TIMEOUT_SECONDS` | `15` | Individual Very HTTP request timeout |
| `PAY_VERY_POLL_INTERVAL_MS` | `2500` | Status poll interval |
| `PAY_VERY_MAX_AGE_SECONDS` | `300` | Maximum attestation age |

Very's current attestation endpoint and JWT issuer use the existing
`api.ag9.ai` wire hostname. These values must match the service exactly until
the service migrates its hostname and issued claims.

If the binary was built without `--features very`, selecting the backend returns
a configuration error. Leaving `PAY_AUTH_BACKEND` unset preserves the platform
default. The override applies to sandbox ephemeral wallets and to auth-enabled
Apple Keychain, GNOME Keyring, Windows Hello, file, and 1Password accounts.
For 1Password, Very authorizes the subscription action first and the existing
`op` CLI flow then unlocks the stored key, so expect both approvals.

## No-mainnet demo

The bundled spec uses Pay's hosted Surfpool sandbox. It creates throwaway,
auto-funded wallets and does not spend mainnet funds.

In the first terminal, copy the spec because the server writes the newly
published sandbox Plan fields back into it:

```sh
cd rust
cp very-integration-demo.yaml /tmp/pay-very-integration-demo.yaml
export MPP_SECRET_KEY="replace-with-a-stable-64-character-hex-value"
cargo run -p pay --features very -- --sandbox server start /tmp/pay-very-integration-demo.yaml
```

On first launch, confirm the prompt to publish the Plan to Surfpool. Then, in a
second terminal with the Very variables above:

```sh
cd rust
export PAY_AUTH_BACKEND=very
export VERY_DEVICE_ID="your-registered-device-id"
export VERY_PUBLIC_KEY="your-registered-base64-DER-SPKI-public-key"
cargo run -p pay --features very -- --sandbox curl http://127.0.0.1:1402/api/v1/very-feed
```

Pay prints the exact recurring terms and a Very verification URL. Open it,
complete the Very Palm check, and keep the CLI running while it polls. A
matching attestation unlocks the local sandbox signer, activates the
subscription, and retries the request. Rejection, timeout, expiry, a changed
action, a different device, or a forged JWT stops before signing.

For a production deployment, keep the challenge-binding secret stable in a
secret manager, use an auth-enabled mainnet account, pin the expected Very
issuer/audience, and review the recurring terms shown in the approval prompt.
