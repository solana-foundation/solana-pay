# Bug Bounty Intelligence MCP Server

This is a minimal MCP server implementation that integrates with the x402 payment protocol to provide a smart contract security scanner service.

## Features

- Demonstrates a full end-to-end x402 payment flow:
  - GET `/api/bug-intel` returns HTTP 402 Payment Required.
  - Agent pays using x402 protocol.
  - POST `/api/bug-intel` processes the payment and returns a ranked vulnerability report.

- Compatible with `pay.sh` CLI tool for triggering scans without any SDK.

## Usage

### Run the server

```bash
cargo run --bin bug-bounty-intel-mcp
```

The server listens on `127.0.0.1:8080` by default.

### Trigger a scan with pay.sh

```bash
pay.sh post http://127.0.0.1:8080/api/bug-intel -d '{"repo":"your-org/your-repo"}'
```

Replace `your-org/your-repo` with the GitHub repository you want to scan.

## Implementation details

- The server responds to GET `/api/bug-intel` with a 402 Payment Required response including an x402 payment challenge.
- The client pays the challenge and retries with a POST `/api/bug-intel` including the payment proof.
- The server verifies the payment proof and returns a dummy ranked vulnerability report.

## License

MIT
