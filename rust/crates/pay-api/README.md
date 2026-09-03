# pay-api

A small, stateless Rust HTTP service that returns Solana stablecoin balances for
any address, and issues confidential-transfer charge challenges and settlement.
Designed to be deployed on Google Cloud Run and called from `pay` in place of
direct RPC calls.

## Endpoints

### `GET /health`

```json
{ "status": "ok" }
```

### `GET /v1/balance/stablecoins`

| Query param | Type   | Notes                                              |
|-------------|--------|----------------------------------------------------|
| `address`   | base58 | Solana wallet pubkey                               |
| `network`   | enum   | `mainnet` or `sandbox` (`surfpool` / `localnet` aliases) |

Response:

```json
{
  "address": "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS",
  "network": "mainnet",
  "balances": [
    { "symbol": "USDC",  "mint": "EPjF...", "decimals": 6, "raw_amount": "1000000", "ui_amount": 1.0 },
    { "symbol": "PYUSD", "mint": "2b1k...", "decimals": 6, "raw_amount": "0",       "ui_amount": 0.0 },
    { "symbol": "CASH",  "mint": "CASH...", "decimals": 6, "raw_amount": "0",       "ui_amount": 0.0 },
    { "symbol": "USDT",  "mint": "Es9v...", "decimals": 6, "raw_amount": "0",       "ui_amount": 0.0 }
  ]
}
```

A non-existent ATA reports `0` rather than an error.

## How it's fast

- **One RPC round trip per request.** ATAs for the four stablecoins are
  derived locally; `getMultipleAccounts` fetches them in a single call.
- **Shared connection pool.** A single `reqwest::Client` (HTTP/2 + keep-alive)
  is reused across requests for the lifetime of the instance.
- **No database, no locks.** State is read-only after startup; an
  `Arc<AppState>` (no `RwLock`) is passed to every handler.
- **Distroless release image.** Slim binary + nonroot user → fast cold starts
  on Cloud Run.

## Configuration

Configuration is YAML-first (`config/default.yaml`); every field can be
overridden by an env var. Adding a new network is a YAML edit, not a code
change — populate the `networks` map and it's available immediately.

```yaml
port: 8080
rpc_timeout_ms: 3000

networks:
  mainnet:
    rpc_url: https://api.mainnet-beta.solana.com
  sandbox:
    rpc_url: http://127.0.0.1:8899

# Stablecoin registry. Order is preserved in the response.
# token_program: spl_token | token_2022.
stablecoins:
  - { symbol: USDC,  mint: EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v, token_program: spl_token,  decimals: 6 }
  - { symbol: PYUSD, mint: 2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo, token_program: token_2022, decimals: 6 }
  - { symbol: CASH,  mint: CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH, token_program: token_2022, decimals: 6 }
  - { symbol: USDT,  mint: Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB, token_program: spl_token,  decimals: 6 }
```

Specs are resolved (mints parsed, programs mapped) once at startup, so per-request work is just ATA derivation + one RPC call. Adding/removing a stablecoin is a YAML edit — no code change.

Env overrides use the `PAY_API_` prefix and `__` for nesting:

| Env var                                   | Overrides                       |
|-------------------------------------------|---------------------------------|
| `PORT`                                    | `port` (Cloud Run sets it)      |
| `PAY_API_PORT`                            | `port`                          |
| `PAY_API_RPC_TIMEOUT_MS`                  | `rpc_timeout_ms`                |
| `PAY_API_NETWORKS__MAINNET__RPC_URL`      | `networks.mainnet.rpc_url`      |
| `PAY_API_NETWORKS__SANDBOX__RPC_URL`      | `networks.sandbox.rpc_url`      |
| `PAY_API_SEND__FEE_PAYER__KEY_NAME`       | GCP KMS fee-payer key resource name |
| `PAY_API_SEND__FEE_PAYER__PUBKEY`         | base58 pubkey of that KMS key   |
| `MOONPAY_PUBLISHABLE_API_KEY`             | `/v1/onramp/start` MoonPay API key |
| `MOONPAY_ONRAMP_CURRENCY_CODE`            | `/v1/onramp/start` currency code   |
| `MOONPAY_ONRAMP_BASE_CURRENCY_AMOUNT`     | `/v1/onramp/start` base amount     |
| `LOG_FORMAT=json`                         | structured logs (prod)          |
| `RUST_LOG=info`                           | log level                       |
| `PAY_API_OTLP_SIDECAR=127.0.0.1:4318`     | OTLP sidecar export             |

## Onramp Redirect

`GET /v1/onramp/start` redirects to MoonPay checkout with server-side defaults:

- `currencyCode=usdc_sol`
- `baseCurrencyAmount=20`
- `externalTransactionId=pay-<uuid>`
- `apiKey` from `MOONPAY_PUBLISHABLE_API_KEY`

Caller-supplied `apiKey`, `api_key`, `currencyCode`, `baseCurrencyAmount`, and
`externalTransactionId` query params are replaced server-side. Other query params
such as `walletAddress`, `redirectURL`, and `paymentMethod` are preserved.

Use `GET /v1/onramp/complete` as the browser return page. It displays a small
static completion page for users returning from MoonPay.

The endpoint emits structured logs and OTLP metrics:

- `pay_api_onramp_requests_total` (`payment_method`)
- `pay_api_onramp_redirects_total`
- `pay_api_onramp_errors_total`
- `pay_api_balance_requests_total`
- `pay_api_balance_errors_total`

## Local dev

```bash
cd rust
just run pay-api
curl 'http://localhost:8080/health'
curl 'http://localhost:8080/v1/balance/stablecoins?address=Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS&network=mainnet'
```

## Deploy

This crate produces the `pay-api` binary and its `Dockerfile` here builds the
image (context is `rust/`, since pay-api is a workspace member):

```bash
cd rust
just docker-build-pay-api
```

Actual deployment (Cloud Run service, runtime service account, RPC URL
secrets) is managed by the operator's Terraform stack, which pulls this image
from Artifact Registry. Refer to the deployment repository's runbook for the
deploy flow.

## Layout

```
rust/crates/
├── pay-api-types/  # API-contract types (Network, StablecoinBalance(s)) — wire format
├── pay-api-core/    # ATA derivation, RPC client, stablecoin registry, balance fetch
└── pay-api/         # Axum bin: routing, YAML config (Figment), handlers, error mapping
```
