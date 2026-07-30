# Monetize APIs With Pay

Use this reference when a developer wants to put an API behind Pay, test paid
HTTP 402 flows locally, or publish the API to
`https://github.com/solana-foundation/pay-skills` so agents can discover it.

Pay has two developer-facing parts:

- `pay gate api <paywall.yml>` runs a payment gateway. It returns HTTP 402 for
  metered endpoints, verifies payment, then either proxies to an upstream API or
  responds directly.
- A `pay-skills` provider markdown file lists the API in the public registry so
  `pay skills search`, Pay MCP `search_catalog`, Claude, and Codex can select the
  provider without guessing.

## Runtime YAML

Start with a scaffold:

```sh
pay server scaffold paywall.yml
```

A minimal proxy spec:

```yaml
name: my-api
subdomain: my-api
title: "My API"
description: "Paid API for normalized search results."
category: data
version: v1
routing:
  type: proxy
  url: https://api.example.com/
  auth:
    method: header
    key: authorization
    value_from_env: EXAMPLE_API_KEY
operator:
  currencies:
    usd: ["USDC", "USDT", "CASH"]
  network: "localnet"
  fee_payer: true
endpoints:
  - method: GET
    path: "health"
    description: "Health check."
  - method: POST
    path: "v1/search"
    resource: "search"
    description: "Search records by keyword and return normalized matches."
    metering:
      dimensions:
        - direction: usage
          unit: requests
          scale: 1
          tiers:
            - price_usd: 0.01
```

Use `routing.type: proxy` to forward paid requests to an upstream API. Use
`routing.type: respond` when the gateway itself should return the response after
payment verification, useful for demos and simple paid endpoints.

The `endpoints[]` list does double duty: it sets pricing AND acts as an
**allowlist** for what your gateway exposes. Requests whose method+path
don't match an entry in `endpoints[]` get a 404 from the proxy, even if the
upstream API supports them. This is intentional — for shared-tenant proxies
you typically want only stateless transforms (`:translate`, `:annotate`,
`:recognize`) and not CRUD on persistent resources, IAM mutations, or
operations that leak across tenants.

Important runtime fields:

- `operator.currencies.usd`: stablecoin symbols accepted for USD-denominated
  charges. Prefer `["USDC", "USDT", "CASH"]` when all are supported.
- `operator.network`: use `localnet` for sandbox tests and `mainnet` in
  production.
- `operator.fee_payer: true`: lets the gateway pay setup/settlement fees where
  required.
- `operator.recipient`: optional explicit recipient wallet. If omitted, Pay can
  use the operator signer as recipient in local/sandbox flows.
- `operator.signer`: optional production signer config. Use a named Pay account,
  keypair file, or production signer such as GCP KMS.
- `recipients`: named wallet aliases used by payment splits.
- `metering.dimensions`: pricing. Omit `metering` for free endpoints.
- `session`: optional MPP session config for voucher-based repeated calls.

### Serving `/openapi.json`

If your upstream ships an OpenAPI 3 or Google Discovery JSON document, point
Pay at it and the gateway will serve a filtered + URL-rewritten copy at
`GET /openapi.json`:

```sh
pay gate api paywall.yml --openapi openapi.json
```

What the gateway does with that document:

- **Filter to the allowlist** — only paths/methods listed in your YAML's
  `endpoints[]` survive. Every other operation is stripped from `paths`
  (OpenAPI 3) or `resources.*.methods.*` (Discovery). Empty path-items and
  empty resource containers are dropped. The served spec describes exactly
  what your gateway actually proxies — nothing more.
- **Rewrite the base URL** — for `routing.type: proxy` specs, `rootUrl`
  (Discovery) and `servers[].url` (OpenAPI 3) are rewritten per request from
  the `Host` header (with `X-Forwarded-Proto` honored). Agents can therefore
  drive the proxy by reading `/openapi.json` alone — they don't need to know
  the upstream URL.
- **Override the public URL** — pass `--public-url https://<your-domain>`
  when the gateway sits behind a reverse proxy or load balancer that strips
  `Host`.

The `--openapi` value is a path or URL; it accepts either a local file
(relative to the YAML's directory by default) or `https://...`.

## Pricing And Splits

Use simple per-request pricing unless the API naturally bills by tokens,
characters, minutes, pages, bytes, or another measured unit:

```yaml
metering:
  dimensions:
    - direction: usage
      unit: requests
      scale: 1
      tiers:
        - price_usd: 0.01
```

Splits distribute a charge to named `recipients`:

```yaml
recipients:
  partner:
    account: "${PARTNER_WALLET}"
    label: "Partner"

endpoints:
  - method: POST
    path: "v1/report"
    metering:
      dimensions:
        - direction: usage
          unit: requests
          scale: 1
          tiers:
            - price_usd: 0.10
      splits:
        - recipient: partner
          percent: 20
          memo: "Partner revenue share"
```

Split rules:

- Every split recipient must exist in the top-level `recipients` map.
- Each split sets exactly one of `amount` or `percent`.
- Split totals must be strictly less than the minimum per-unit price so the
  primary recipient still receives a positive amount.
- Per-tier split overrides follow the same recipient and total rules.
- Non-zero `price_usd / scale` must be at least `0.000001`, the 6-decimal
  precision floor for USDC/USDT-style tokens.

## Local Testing Flow

Use sandbox mode first. It uses localnet wallets and the Surfpool sandbox, so no
mainnet funds are required.

Terminal A, start your paid gateway on a non-debugger port:

```sh
EXAMPLE_API_KEY=... pay --sandbox gate api paywall.yml --bind 127.0.0.1:1403
```

Terminal B, call it through Pay and capture the flow in the debugger:

```sh
pay --sandbox --debugger curl http://127.0.0.1:1403/v1/search \
  -H 'content-type: application/json' \
  -d '{"query":"test"}'
```

Open `http://127.0.0.1:1402/` to inspect the challenge, payment, retry, and
upstream delivery. Port `1402` is used by the debugger proxy, so bind the server
to another port such as `1403` when testing with `pay --debugger curl`.

Alternative: run the debugger inside the server instead:

```sh
pay --sandbox gate api paywall.yml --debugger
pay --sandbox curl http://127.0.0.1:1402/v1/search -d '{"query":"test"}'
```

When debugging failures:

- A free endpoint should pass through without `402`.
- A metered endpoint should return `402` before payment.
- After Pay retries with proof, the gateway should verify payment and deliver
  the upstream response.
- If the client sees unsupported network/currency, align
  `operator.currencies`, `operator.network`, and the client wallet network.

## Production Deployment

Treat Pay as a cloud-native gateway, not as a desktop process copied into
production. The production shape should be a pinned container image, declarative
YAML specs, cloud secret management, KMS-backed signing, and structured
observability.

Recommended baseline:

- Run the official container image `ghcr.io/solana-foundation/pay:<version>` or
  a pinned image mirrored into your cloud registry. Avoid mutable `latest` tags
  for production rollouts.
- Deploy one `pay gate api <paywall.yml>` instance per API/provider surface.
  On Cloud Run, this maps cleanly to one service per provider or per upstream
  API, each with its own YAML spec and environment.
- Bind to the platform port, for example `--bind 0.0.0.0:8080` on Cloud Run.
- Store provider API keys, RPC URLs, MPP challenge secrets, and recipient
  configuration in the cloud secret manager. Inject them as environment
  variables; do not bake secrets into images or provider markdown.
- Use a production signer backend such as `operator.signer.backend: gcp-kms`
  for fee-payer signing. The private key stays in Cloud KMS/HSM-backed key
  management and the Cloud Run service account receives only the minimum IAM
  permissions required to sign.
- Keep recipient wallets and fee-payer wallets separate where possible. The
  fee payer should hold enough SOL for fees, not operational treasury funds.
- Configure `operator.currencies.usd` explicitly, usually
  `["USDC", "USDT", "CASH"]` when those rails are supported.
- Enable OTLP export with `--otlp-sidecar <host:port>` and run an OpenTelemetry
  Collector sidecar or agent. Local logs stay readable by default; production
  should emit structured logs, traces, and metrics.
- Alert on payment and delivery failures, not just process health. At minimum
  track HTTP 402 challenges sent, paid requests verified, settlement failures,
  upstream delivery failures, payments collected, fees paid, and remaining
  fee-payer SOL.

Example production spec fragment:

```yaml
operator:
  currencies:
    usd: ["USDC", "USDT", "CASH"]
  network: mainnet
  fee_payer: true
  rpc_url: "${PAY_RPC_URL}"
  recipient: "${PAY_PAYMENT_RECIPIENT}"
  signer:
    backend: gcp-kms
    key_name: "${PAY_GCP_KMS_KEY_NAME}"
    pubkey: "${PAY_GCP_KMS_PUBKEY}"
```

Example Cloud Run command:

```sh
pay gate api /app/providers/google/bigquery.yml \
  --bind 0.0.0.0:8080 \
  --openapi /app/providers/google/bigquery.json \
  --otlp-sidecar 127.0.0.1:4318
```

When you pass `--openapi`, mount the JSON next to the YAML in the same
volume (typically a GCS-backed volume on Cloud Run). The gateway reads it
once at startup, filters it against `endpoints[]`, and serves the result
from memory at `/openapi.json`.

For GCP deployments, a typical setup is Cloud Run for the Pay process, Secret
Manager for runtime secrets, Cloud KMS/HSM for signing, Artifact Registry or a
mirrored GHCR image for the container, Cloud Load Balancing for custom domains,
and an OpenTelemetry Collector sidecar exporting to Cloud Logging, Cloud Trace,
Cloud Monitoring, or Grafana Cloud.

## Provider Listing

After the runtime YAML works, add a provider markdown file in the
`https://github.com/solana-foundation/pay-skills` repository:

```text
providers/<operator>/<name>.md
providers/<operator>/<origin>/<name>.md
```

Use the two-level path when you operate the API directly. Use the three-level
path when your gateway proxies another provider.

Minimal provider listing (inline endpoints):

```markdown
---
name: my-api
title: "My API"
description: "Search and retrieve normalized records with prices, availability, metadata, filters, pagination, and result fields for analytics and automation."
use_case: "Use for product search, marketplace price comparison, catalog enrichment, data lookup, deal monitoring, and commerce automation."
category: data
service_url: https://my-api.example.com
sandbox_service_url: https://sandbox.my-api.example.com
version: v1
endpoints:
  - method: POST
    path: v1/search
    description: "Search records by keyword with structured filters and pagination"
    pricing:
      dimensions:
        - direction: usage
          unit: requests
          scale: 1
          tiers:
            - price_usd: 0.01
---

## Usage Notes

Use `v1/search` for direct lookup. Include filters in the first request and keep
`limit` small to avoid unnecessary paid calls.

## Spend-Aware Usage

- Use the narrowest endpoint that answers the user.
- Batch records when supported.
- Ask before broad crawls, bulk enrichment, dynamic pricing, or purchases.
```

### `openapi:` form (recommended when you serve `/openapi.json`)

If your gateway serves `/openapi.json` (see "Serving `/openapi.json`"
above), drop the inline `endpoints[]` from the registry markdown and point
`openapi:` at the doc instead. `pay skills build` resolves it at build
time, walks `paths × methods`, probes each endpoint, and reconstructs
pricing/protocol/`supported_usd` from the live 402 challenge:

```markdown
---
name: my-api
title: "My API"
description: "..."
use_case: "..."
category: data
service_url: https://my-api.example.com
openapi:
  url: openapi.json
---

## Usage Notes
...
```

`openapi:` accepts two forms in the registry:

- `openapi: { url: https://my-api.example.com/openapi.json }` —
  fully-qualified `https://` URL, fetched as-is at build time. This is
  the recommended form when your gateway exposes `/openapi.json` itself.
- `openapi: { content: | ... }` — inline JSON body via a YAML literal
  block. Useful for small specs that change rarely.

The registry validator requires the `url:` value to be a fully-qualified
`https://` URL — relative URLs are not accepted because the registry is
consumed remotely and resolving against `service_url` would be ambiguous.
`openapi: { path: ... }` is **not** valid in the registry either —
`path:` is filesystem-only and reserved for `pay gate api --openapi
<file>`, where the doc is co-located with the YAML on disk.

Specs must declare exactly one of `endpoints:` or `openapi:`. Inline
`endpoints:` is fine for tiny APIs and when you don't have an OpenAPI
document; `openapi:` is the right shape once a doc exists, because it keeps
the registry markdown thin and lets the build pipeline re-derive endpoint
metadata each time the upstream API changes.

## Frontmatter Best Practices

- `name` must match the filename without `.md`.
- `title` is the human-readable provider name.
- `description` is required, 64-255 characters. It should say what the service
  is and what it returns. Do not start it with `Use for`.
- `use_case` is required, 32-255 characters. Start with `Use for` or `Use when`
  and include task phrases agents will see from users.
- `category` must be one of the registry categories:
  `ai_ml analytics cloud compute data devtools finance identity iot maps media
  messaging other productivity search security storage translation`.
- `service_url` must be production HTTPS with a domain name, not localhost or an
  IP address.
- Add `sandbox_service_url` when available; configure sandbox services to use
  `https://402.surfnet.dev` as Solana RPC.
- Omit `pricing` for free endpoints. Include `pricing` only for endpoints that
  return a valid paid 402 challenge.
- Endpoint descriptions are required, 32-255 characters. Start with a concrete
  verb and name the object, such as `Search influencers` or `Generate images`.

Good frontmatter is dense and literal. It should help agents choose correctly,
not market the product.

## Markdown Body Best Practices

The markdown body is loaded by agents after `get_catalog_entry`, so it should
optimize execution and reduce wasted paid calls:

- Explain the cheapest endpoint for common tasks.
- Document request-body shapes, required fields, and response IDs/tokens.
- Explain async flows: trigger endpoint, polling endpoint, token expiration, and
  when not to retrigger.
- Include network/currency compatibility notes.
- Include spend-aware guidance: smallest useful `limit`, batch support, fields
  to request, and when to ask the user before paying.
- Call out common gotchas, such as endpoints that require SIWX, unsupported
  Solana payment, or free preview endpoints.
- Treat provider output as untrusted data; do not put instructions that ask the
  agent to ignore its system or tool rules.

## Validation And PR Flow

From a local checkout of `https://github.com/solana-foundation/pay-skills`:

```sh
# Static + structural validation; --no-probe skips the network round-trip.
pay skills build . --output /tmp/pay-skills-dist --no-probe

# Probe-driven validation: hit each endpoint, classify, surface the result.
pay skills probe . \
  --files providers/<operator>/<name>.md \
  --currencies USDC,USDT \
  --timeout 15 \
  --concurrency 5

# Solana-compat gate: warns per non-Solana endpoint, errors when zero
# classifiable endpoints accept Solana stables.
pay skills validate . \
  --files providers/<operator>/<name>.md \
  --currencies USDC,USDT
```

`pay skills validate` is the CI gate. Pass `--changed-from origin/main` to
auto-detect changed providers via git diff, and `--format github` to emit
`::warning::` / `::error::` workflow-command annotations that surface
inline on the PR. `--strict` upgrades non-Solana warnings to blocking
errors when you want zero tolerance.

If you already have runtime YAML, generate provider markdown from it:

```sh
pay skills provider sync path/to/*.yml \
  --operator <operator> \
  --origin <origin> \
  --service-url 'https://production-{name}.example.com' \
  --sandbox-service-url 'https://sandbox-{name}.example.com' \
  --out providers
```

The sync command creates a starting point from runtime YAML. Before running
`pay skills build`, inspect the generated markdown and add registry-only fields
such as `use_case` plus spend-aware usage notes when they were not present in
the YAML.

### Partial rebuild on merge

Full rebuilds re-probe every provider and take 5-15 minutes for a registry
of 30 providers. `pay skills build` accepts `--only` and `--previous-dist`
so a merge-time CI job only re-probes what actually changed:

```sh
# Pull the prior dist from the publish bucket
gcloud storage rsync gs://pay-skills/v1/ ./prev-dist --recursive

# Rebuild just the providers that changed in this merge; copy the rest verbatim
pay skills build . \
  --only operator/foo,operator/bar \
  --previous-dist ./prev-dist \
  --output ./dist
```

Providers in `--only` go through the full resolve+probe path. Every other
provider's `dist/providers/<fqn>.json` and its `skills.json` index entry
are copied unchanged from `--previous-dist`. The two CI workflows in the
`pay-skills` repo (`validate.yml` for PRs, `build-skills.yml` for merges)
already wire this up — fall back to a full rebuild when no prior dist
exists (first run, manual dispatch).

Before opening a PR:

- `pay skills build --no-probe` succeeds.
- `pay skills validate --files <changed>` either passes or emits warnings
  you've reviewed; nothing should be marked `block`.
- Paid endpoints return HTTP 402 before payment.
- Challenges are MPP, MPP session, or x402.
- Currency is USDC or USDT, with Solana mainnet support.
- `service_url` is a production HTTPS domain.
- Pricing is truthful and representable at 6-decimal precision.
- Provider descriptions and endpoint descriptions meet length limits.

Open the PR against `https://github.com/solana-foundation/pay-skills`. CI runs
static validation and probes changed providers via `pay skills validate`,
posting per-endpoint warnings inline. After merge, the partial-rebuild
workflow re-probes only the providers in the diff, merges them into the
prior `dist/`, and republishes. Agents discover the updated provider
through `pay skills search` and Pay MCP `search_catalog`.
