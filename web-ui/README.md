# Payment Debugger

A real-time debugger for Solana payment flows. Groups HTTP 402 challenge-response cycles into single payment flows and visualizes them with a sequence diagram, so developers can see exactly what happened (and what went wrong) at each step.

Supports two payment protocols:

- **MPP** (Monetized Payment Protocol) — `www-authenticate` / `payment-receipt` headers
- **x402** — `X-PAYMENT` header, with facilitator verify/settle

Runs against the [Solana Payment Sandbox](https://402.surfnet.dev) — no real funds needed.

## Architecture

- **Backend** — Express API (`api/index.ts`) with payment-gated demo endpoints, an embedded x402 facilitator, and a correlation engine that groups raw HTTP requests into payment flows streamed over SSE.
- **Frontend** — React SPA (`src/`) with Vite. Compact flow list with protocol badge, resource path, status, and latency. Expanded view shows a step-by-step sequence diagram alongside a timestamped event log.
- **Embedded mode** — The frontend and backend are also compiled into the `pay` Rust binary (`crates/pdb`). Run `pay --sandbox gate api paywall.yml --debugger` to get the debugger alongside any gateway proxy.

For source packaging, build or unpack the frontend before compiling Rust:

```bash
cd web-ui && pnpm install --frozen-lockfile && pnpm build
cd ../rust && cargo build --release
```

Release builds also publish `pay-pdb-dist-<version>.tar.gz`. Packagers such as
Homebrew can unpack that artifact and set `PAY_PDB_DIST=/path/to/dist` before
running Cargo. `build.rs` intentionally does not fetch the latest GitHub release
so builds stay pinned, reproducible, and compatible with offline build systems.

## Quick start

```bash
pnpm install
pnpm dev        # starts Express (port 3000) + Vite (port 5173)
```

Open `http://localhost:5173`, then in another terminal:

```bash
# Trigger a 402 challenge
curl -i http://localhost:3000/mpp/quote/GOOG

# Or let the CLI handle the full payment flow
pay --sandbox curl http://localhost:3000/mpp/quote/GOOG
```

## Deploy

```bash
vercel          # preview
vercel --prod   # production
```

On cold start the serverless function bootstraps the fee payer with 100 SOL + 1000 USDC via Surfnet cheatcodes.

## Environment variables

Set these in your Vercel project settings (all optional):

| Variable | Description |
|----------|-------------|
| `RECIPIENT` | Solana address to receive payments (defaults to fee payer) |
| `FEE_PAYER_KEY` | Base58-encoded keypair (generates ephemeral if unset) |
| `RPC_URL` | Surfnet RPC (defaults to `https://402.surfnet.dev:8899`) |
| `SECRET_KEY` | MPP secret key (defaults to `demo-secret-key`) |
| `NETWORK` | Solana network (defaults to `localnet`) |

## Endpoints

| Endpoint | Protocol | Price |
|----------|----------|-------|
| `GET /mpp/quote/:symbol` | MPP | 0.01 USDC |
| `GET /mpp/weather/:city` | MPP | 0.005 USDC |
| `GET /x402/joke` | x402 | $0.001 |
| `GET /x402/fact` | x402 | $0.001 |
| `GET /health` | — | free |
| `GET /__debugger/logs/stream` | — | SSE stream of payment flows |

The embedded x402 facilitator is mounted at `/facilitator/*`.
