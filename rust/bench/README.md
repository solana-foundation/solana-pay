# pay-bench

A production-grade load/scaling harness for the Pay proxy. Goal: prove a
single proxy can hold large numbers of concurrent MPP sessions and measure how
each payment scheme / intent scales.

The bench is a **pure client**: it provisions funded wallets, pre-builds a
request buffer, unleashes load at a target rate against a proxy URL, then
settles and sweeps every wallet back to the funder. Every run is **journalled
and resumable** so an interrupted mainnet run never strands funds.

## Quick start (rehearsal — no real funds)

```sh
export BENCH_FORK_RPC_URL='https://your-read-only-solana-rpc.example'
cargo run -p pay-bench --release -- rehearse bench/configs/session-fork.yml
```

Rehearsal boots an embedded **surfpool** validator and a local pay proxy, then
runs the full pipeline against them. With a `rpc_url` in the config, surfpool
runs as a **JIT mainnet-fork** (fetching the payment-channel program and USDC
mint from that datasource). Current PayKit verifies genuine payment-channel
opens, so the MPP-session benchmark cannot use an offline synthetic open.

## Devnet Pingora smoke gate

`configs/devnet-pingora.yml` is a deployable Pingora configuration for a
headless, self-contained `GET /api/v1/compute` endpoint. It emits an MPP
session challenge and returns `200` only after voucher verification; its
`respond` route deliberately excludes an upstream application from this
gateway measurement.

Supply `PAY_PAYMENT_RECIPIENT`, `PAY_RPC_URL`, and a persistent random
`PAY_SESSION_SECRET` through the service environment. The gateway uses
client-funded channels (`operator.fee_payer: false`), so it does not need an
operator key for this smoke test. A real devnet load run still requires the
bench funder to hold devnet SOL and USDC; `pay-bench run` currently stops
before funding rather than pretending it completed that transfer.

For the Ubuntu benchmark host, install
`deploy/pay-bench-devnet.service` as `/etc/systemd/system/pay-bench-devnet.service`
and place the three environment values in `/etc/pay-bench/devnet.env` with
mode `0600`. The unit raises `LimitNOFILE` to `262144`, which is a prerequisite
for any high-concurrency generator or proxy run.

## Commands

| Command | Purpose |
|---|---|
| `rehearse <cfg>` | Full pipeline on a local fork — no real money. |
| `run <cfg> [--yes]` | Real run; `--yes` required on real-money networks. |
| `setup <cfg> --id <ID> --yes` | Create/resume a deterministic public-cluster wallet fixture. |
| `teardown <ID> --config <cfg> --yes` | Return fixture tokens, close ATAs, and reclaim rent. |
| `list-runs` | Recorded runs + outstanding-fund status. |
| `recover <id> \| --all` | Resume settle+sweep for an interrupted run. |
| `estimate <cfg>` | Validate a config and print parsed settings. |

## Seeded session verifier fixture

`configs/session-offline-seeded.yml` is a benchmark-only, local fixture for
the voucher data plane. It seeds deterministic confirmed channel state inside
the `pay-bench` process, then runs ordinary client-signed voucher headers
through `SessionMpp::process`. It has no production state-import route and must
not be used as evidence of open-channel, Redis, TLS, or network capacity.

## Config

```yaml
run:
  name: charge-fork
  scheme: mpp_charge          # mpp_charge | mpp_session | x402_exact
  network: fork               # fork | mainnet | devnet
  rpc_url: "https://…"        # fork datasource, or mainnet RPC (prefer rpc_url_env)
  tls_ca_cert_env: BENCH_TLS_CA_CERT # optional env var containing private CA path
  funder: { keypair_env: BENCH_FUNDER_KEYPAIR }
  safety:
    max_total_usdc: 100.0     # hard caps, enforced pre-flight
    max_total_sol: 200.0
    require_confirmation: true
load:
  users: 30000                # = concurrent channels for sessions
  requests_per_sec_per_user: 1
  prepare_secs: 30            # window to pre-build the request buffer
  unleash_secs: 60            # measured window
  max_concurrency: 2048
endpoints:
  - { url: "https://<proxy>/v1/charge", method: POST, body: "{}" }
session: { deposit_usdc: 0.10, voucher_usdc: 0.0001, close_after_run: true } # mpp_session only
```

> **Secrets:** prefer `rpc_url_env` / `funder.keypair_env` over inlining an
> API key or keypair in a committed config.

## Reusable devnet fixture

Use one of the versioned 100,000-wallet allocation plans:
`configs/devnet-fixture-100k.yml` for devnet USDC or
`configs/devnet-fixture-100k-usdtest.yml` for devnet-only USDtest (Token-2022).
A stable
`--id` is part of the wallet derivation namespace, so the same funder and ID
always recover the same 100,000 addresses. `setup` is resumable: it reconciles
each target ATA to its configured balance before transferring only the missing
amount. The journal stores no private keys or RPC URL.

```sh
export BENCH_DEVNET_RPC_URL='https://…'
export BENCH_FUNDER_KEYPAIR='[solana keypair bytes]'

# Review the caps in the YAML, then provision once.
cargo run -p pay-bench --release -- setup \
  bench/configs/devnet-fixture-100k.yml --id devnet-100k --yes

# A real load run reuses the funded, deterministic wallet set and leaves
# cleanup to the explicit teardown command.
cargo run -p pay-bench --release -- run bench/configs/session-devnet.yml \
  --fixture-id devnet-100k-usdtest --yes

# After all load runs are finished, return every token balance and close each
# ATA to reclaim its rent to the funder.
cargo run -p pay-bench --release -- teardown devnet-100k \
  --config bench/configs/devnet-fixture-100k.yml --yes
```

The USDtest fixture has its own setup journal but deliberately derives the
already-provisioned `devnet-100k-usdg` wallet cohort. This adds the new token
accounts without creating another 100,000 wallet addresses:

```sh
cargo run -p pay-bench --release -- setup \
  bench/configs/devnet-fixture-100k-usdtest.yml --id devnet-100k-usdtest --yes
```

Before provisioning all 100,000 token accounts, validate the real devnet path
with the bounded 100-wallet plan. It derives the same first 100 wallets and
uses an independent journal:

```sh
cargo run -p pay-bench --release -- setup \
  bench/configs/devnet-fixture-100-usdtest.yml --id devnet-100-usdtest --yes
cargo run -p pay-bench --release -- run bench/configs/session-devnet-smoke-10.yml \
  --fixture-id devnet-100-usdtest --yes
cargo run -p pay-bench --release -- run bench/configs/session-devnet.yml \
  --fixture-id devnet-100-usdtest --yes
```

The plan performs one idempotently reconciled transaction per derived wallet;
it is intentionally restart-safe rather than relying on a one-off bulk-
transfer script. Add USDT only with the actual devnet mint you fund: PayKit
intentionally never maps a devnet symbol to the mainnet USDT mint.

## Pipeline

`resolve → fund + provision → prepare → unleash → settle + sweep`, journalled at
every transition (`~/.config/pay/bench/<run-id>.json`, 0600, atomic writes).

- **Deterministic keys** — each user wallet is `HKDF(funder_secret, run_id,
  index)`, so no secret is ever stored and any run is recoverable from the
  funder + run id.
- **Money safety** — pre-flight spend caps, `--yes` gate on real money, and
  `recover` to sweep an interrupted run to zero stranded funds.

## Observability

Console logs are always on. Each phase logs its duration
(`phase: provisioned elapsed_ms=…`), and per-user `provision`/`prepare` work
runs inside spans (`provision{index=N}`). Worker threads are named
`bench-worker-N` and shown in logs, so you can see what each thread is doing.

Export spans + metrics to an OTLP collector to view full traces:

```sh
cargo run -p pay-bench -- --otlp 127.0.0.1:4318 rehearse bench/configs/charge-fork.yml
# or: OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318 cargo run -p pay-bench -- rehearse …
```

The pay server uses the same OTLP stack (`pay server start --otlp-sidecar …`)
and now names its runtime threads (`pay-server-worker-N`, `pay-mcp-worker-N`)
with spans on the payment middleware, session, and charge paths — so a bench
run and the proxy show up in one correlated trace view.

Tune verbosity with `RUST_LOG` (default
`info,pay_core=error,hyper=warn,reqwest=warn,tower=warn`).

## Schemes

| Scheme | Status | Notes |
|---|---|---|
| `mpp_charge` | ✅ M1 | One on-chain-settled credential per request. **Pipeline-correctness** scheme — Solana-bound, not the 30k path. |
| `mpp_session` | ✅ | Open a genuine channel once → off-chain vouchers (in-order, monotonic) → settle on close. Session runs require a JIT fork or a funded real network. |
| `self_test` | ✅ | No on-chain work — fires plain GETs at a free path. Generator/proxy ceiling check (`configs/selftest-10k.yml`). |
| `x402_exact` | ⏳ M5 | Per-request signed payment; deferred settlement. `up_to` is server-side volume-tier pricing, not a separate scheme. |

## Known characteristics

- **Charge on a fork** collides under replay protection: surfpool's fixed
  blockhash makes a user's repeated charges *identical* (same signature), so
  only the first settles and the rest 402 with "already processed". This is a
  fork artifact, not a harness bug — and exactly why sessions (distinct
  monotonic vouchers, no blockhash) are the throughput path.
- **`session-offline.yml` is historical only.** Current PayKit rejects it
  deliberately, because it cannot validate real payment-channel opens.
- **One box may not source 30k req/s.** Use a self-test ceiling check and
  distributed generators before attributing a limit to the proxy.

Not a workspace default-member: a plain `cargo build` skips it. Build/run with
`-p pay-bench`.
