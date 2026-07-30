# Setup, CLI, And Provider Authoring

## MCP Setup

Add Pay to your MCP config to give AI agents direct access to paid APIs:

```json
{
  "mcpServers": {
    "pay": {
      "command": "pay",
      "args": ["mcp"]
    }
  }
}
```

Or launch Claude Code / Codex with Pay injected into the agent session:

```sh
pay claude
pay codex
```

If `pay` is not installed, use `npx @solana/pay`.

## CLI Usage

```sh
pay setup                         # create a wallet
pay claude                        # launch Claude Code with pay
pay codex                         # launch Codex with pay
pay curl <url>                    # HTTP request with user-authorized 402 handling
pay --sandbox curl <url>          # use an ephemeral devnet wallet
pay skills list                   # browse the API registry
pay skills show <provider>        # show a provider's endpoints
pay account list                  # list accounts
pay topup                         # fund account
pay gate api <paywall.yml>        # run a payment gateway for your API
```

## Notes

- URLs from results are complete gateway URLs; use them as-is.
- Metered endpoints return 402 first; `curl` prepares the payment, gets local
  signing approval, then retries with the payment proof.
- Free endpoints pass through without payment.
- Use `create_skill` only when creating or reviewing a pay-skills provider file.
- For developer/operator workflows that monetize an API, write `pay gate api`
  YAML, publish a provider listing, or submit to
  `https://github.com/solana-foundation/pay-skills`, read
  `references/monetize-api.md`.
