<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/solana-foundation/pay/raw/main/docs/assets/banner-main-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/solana-foundation/pay/raw/main/docs/assets/banner-main-light.png">
    <img alt="pay.sh" width="100%" src="https://github.com/solana-foundation/pay/raw/main/docs/assets/banner-main-light.png">
  </picture>
</div>

<p align="center">
  <a href="https://skills.sh/solana-foundation/pay"><img alt="skills.sh" src="https://skills.sh/b/solana-foundation/pay"></a>
  <a href="https://x402.org"><img alt="x402" src="https://img.shields.io/badge/protocol-x402-black"></a>
  <a href="https://paymentauth.org"><img alt="MPP" src="https://img.shields.io/badge/protocol-MPP-black"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green"></a>
</p>

<p align="center">
  <b>The missing payment layer for HTTP — x402 &amp; MPP payment challenges with user-authorized stablecoin signing.</b>
</p>

<p align="center">
  <a href="#installation">Install</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="https://docs.solanapay.com">Docs</a>
</p>

---

```sh
# Without pay — you get a 402
curl https://debugger.pay.sh/mpp/quote/AAPL

# With pay -- it handles the 402 challenge and returns the response
pay curl https://debugger.pay.sh/mpp/quote/AAPL
```

## Key Features

### 💵 Transparent 402 Handling

Wrap your CLI (`curl`, `claude`, `codex`, etc.) -- when an API returns 402, `pay` detects the payment protocol, prepares the stablecoin transaction, asks the local wallet to authorize and sign it, then retries with the payment proof.

Supports both live payment standards on Solana:
- **[MPP](https://mpp.dev/)** — Machine Payments Protocol
- **[x402](https://x402.org/)** — x402 Payment Protocol

Stablecoins deployed to Solana are supported out of the box.

### 🤖 AI-Native with MCP

`pay` ships with a built-in [MCP](https://modelcontextprotocol.io/) server, letting AI assistants request paid API calls through the same local wallet-approval flow.

```sh
# Run Claude Code or Codex with pay injected into the agent session
pay claude
pay codex
```

ACP clients such as Buzz can launch the same paid inference route without
sharing their protocol stream with Pay:

```sh
# Interactive provider/model selection when run from a terminal
pay acp goose

# Deterministic configuration for a headless ACP client
pay acp goose --provider alibaba --model qwen3.7-plus
```

`pay acp` supports `goose`, `claude`, and `codex`. It starts the payer proxy,
configures the selected ACP adapter to use it, and passes ACP JSON-RPC through
stdin/stdout unchanged. Headless clients may set `PAY_ACP_PROVIDER` and
`PAY_ACP_MODEL` instead of passing flags.

When Buzz Desktop is installed, `pay setup` and `pay setup --update` offer to
register a **Pay + Goose/Claude Code/Codex** custom harness. Setup discovers
compatible providers and models, then writes an idempotent `pay-acp` definition
to Buzz's custom harness settings.

### 🛠️ Payment debugging and simulations

`pay` ships with an embedded Payment Debugger — a local web UI that visualizes every 402 challenge-response cycle as a sequence diagram. See exactly which headers were sent, which protocol was used (MPP or x402), and where things went wrong.

Everything runs locally — no data leaves your machine.

```sh
# Start a gateway with the debugger on any paywall
pay gate api paywall.yml --debugger

# Discover and gate local inference with optional per-model rates
pay --sandbox gate inference rates.yml

# Or run the bundled demo (sandbox + debugger + sample endpoints)
pay server demo
```

A [public debugger](https://debugger.pay.sh) is also available.

### 🔐 Gated Payments via Biometrics

`pay` lets AI agents use paid APIs without giving them your private key or an API-wide spending credential.

When a command, Claude Code, Codex, or another MCP client hits a paid endpoint, `pay` prepares the payment locally and asks your wallet backend to authorize the signature. On macOS, that means Touch ID via Keychain. On Windows, Windows Hello. On Linux, GNOME Keyring / polkit. If you reject the prompt, the payment is not signed and the request does not go through.

  
```sh
pay setup    # Touch ID on macOS, Windows Hello on Windows, GNOME Keyring on Linux, or choose 1Password
```

### 📚 Open Source Catalog

The paid API catalog is open source in the [`pay-skills`](https://github.com/solana-foundation/pay-skills) repo.

Anyone can contribute a provider listing, improve endpoint metadata, or add usage guidance for agents. Catalog entries follow the [`pay-skills` contributing guide](https://github.com/solana-foundation/pay-skills/blob/main/CONTRIBUTING.md), which defines the metadata, pricing, endpoint, and usage-note standards that keep **Agent experience** consistent.
  
```sh
  pay skills search "maps"
```

Good catalog entries make paid APIs easier for both humans and agents to discover, compare, and use safely.

## Installation

### Prebuilt Binaries

```sh
# macOS
brew install pay

# via NPM
npm install -g @solana/pay
```

### From Source

```sh
git clone https://github.com/solana-foundation/pay.git
cd pay
just install pay
```

### Verify

```sh
pay --version
```

## Quick Start

```sh
# 1. Setup your account
pay setup
pay whoami

# 2. Make a paid gated API call to https://debugger.pay.sh sandbox endpoints
pay --sandbox curl https://debugger.pay.sh/mpp/quote/AAPL

# 3. Or let your AI agent handle it
pay claude
```

## Contributing

```sh
cd rust
just build   # release binary
just test    # all tests
just lint    # clippy (warnings = errors)
```

We welcome contributions — check [open issues](https://github.com/solana-foundation/pay/issues) to get started.

## Troubleshooting

### Linux: `pay topup` or `pay curl` errors with "auth failed"

GNOME Keyring auth uses polkit, which requires a one-time setup step:

```sh
sudo cp rust/config/polkit/sh.pay.unlock-keypair.policy /usr/share/polkit-1/actions/
```

This grants `pay` the right to prompt for your password or fingerprint before accessing the keypair.

## License

MIT — see [LICENSE](./LICENSE).

Subject to the foregoing, the Terms of Service available at [solana.com/tos](https://solana.com/tos)
