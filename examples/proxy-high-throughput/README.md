# High-throughput Pay proxy on Ubuntu

This example provisions one x86_64 Ubuntu host as a headless Pay proxy with a
single `GET /api/v1/compute` endpoint gated by MPP sessions. It builds Pay with
the exact nightly/toolchain shape used by the Sunburst experiment, applies
conservative socket tuning, installs a hardened systemd unit, and verifies that
the endpoint returns an HTTP 402 payment challenge.

The hot request path is off-chain. The existing session `ChannelStore`
atomically replaces each channel's cumulative watermark with the newest valid
voucher; it does not submit a transaction for each request. Every five minutes,
the embedded lifecycle worker scans active channels, skips watermarks already
recorded on-chain, and sends the remaining latest watermarks through PayKit's
size- and packet-bounded settlement worker. This is the production flow being
benchmarked, not a stream of per-request devnet transactions.

The default sample inventory pins Pay `84146398de61f2f49c521c1b3d404e0fb8972541`
and Rust `nightly-2026-08-14`, the exact source/toolchain pair used for the
retained AVX-512 IFMA server measurements. Do not replace the commit with a
moving branch when collecting benchmark evidence.

## What this does not claim

Provisioning the host does not prove one million accepted vouchers per second.
That claim requires independent off-host generators, a real NIC, a sustained
60-second window, zero failed vouchers, and server-side CPU/softirq/RSS
evidence. The retained experiment measured a repeatable 97.614 core-us per
accepted voucher, which predicts sufficient CPU budget; it did not complete
that final network proof.

The paywall uses `routing: respond`, so it measures the payment gate without an
upstream application. Replace it with a proxied upstream only after establishing
the gate baseline.

## Prerequisites

- Ansible Core 2.14 or newer on the controller.
- An x86_64 Ubuntu host reachable over SSH with passwordless sudo.
- At least 128 logical CPUs for the recorded one-million-per-second CPU budget.
- An AVX-512 IFMA-capable CPU to reproduce the fast crypto backend.
- TCP port 1402 allowed by the host firewall/security group.
- A Solana RPC URL, recipient address, and funded operator keypair. The sample
  paywall says `devnet`; change `operator.network` and the RPC together when
  targeting another deployment of the payment-channel program.

TLS and firewall policy are deliberately outside this playbook. For anything
beyond an isolated benchmark network, terminate TLS at a load balancer and
restrict port 1402 to the intended clients.

## Deploy

```sh
cd examples/proxy-high-throughput
cp inventory.example.yml inventory.yml
cp proxy.env.example proxy.env
chmod 600 proxy.env
```

Edit `inventory.yml` with the target host. Fill all four values in
`proxy.env`; the file is ignored by git and is copied with mode 0640. Then run:

```sh
ansible-playbook --syntax-check playbook.yml
ansible-playbook playbook.yml
```

The playbook refuses a moving `pay_git_ref`, a non-Ubuntu target, and—by
default—a host below 128 logical CPUs or without `avx512ifma`. Lower
`pay_min_logical_cpus` or set `pay_require_avx512_ifma=false` only for a
functional deployment that will not be compared with the retained result.

## Verify

The playbook's final task requires the local endpoint to return HTTP 402. From
the controller, confirm the public route and its payment challenge:

```sh
curl -sS -D - -o /dev/null http://HOST:1402/api/v1/compute
ansible pay_proxies -b -m command -a 'systemctl status pay-proxy --no-pager'
ansible pay_proxies -b -m command -a 'journalctl -u pay-proxy -n 100 --no-pager'
```

Confirm the deployed source, compiler, and IFMA instructions before attaching
results to a commit:

```sh
ansible pay_proxies -b -m shell -a 'git -C /opt/pay/src rev-parse HEAD'
ansible pay_proxies -b -m shell -a '/opt/pay/cargo/bin/rustc +nightly-2026-08-14 -Vv'
ansible pay_proxies -b -m shell -a "objdump -d /opt/pay/bin/pay | awk '/vpmadd52/{n++} END{print n+0}'"
```

`rust/bench/README.md` documents fixture creation, safety caps, recovery, and
the `pay-bench` workload. The playbook installs `pay-bench` beside `pay` so the
same immutable build can be used on separately authorized generator hosts.
Never place generators on the proxy host for a capacity claim: their CPU and
loopback traffic contaminate the server measurement.

## Settlement and state

The sample keeps the newest voucher per channel in PayKit's in-process
`MemoryChannelStore`, matching the measured server path. Voucher acceptance is
an atomic cumulative compare-and-swap, so an older voucher cannot move the
watermark backwards. `settlement_interval_ms: 300000` triggers a five-minute
scan; Pay skips already-settled watermarks and packs the remaining channel
instructions into Solana transactions within count and packet-size limits.

The RPC therefore sees channel-open/top-up traffic and periodic settlement
batches—not request-rate traffic. A graceful idle close is scheduled after ten
minutes and grouped on one-minute boundaries; it also settles the final latest
voucher before sealing the channel.

The in-memory store is intentionally the benchmark default. Restarting the
process can forfeit vouchers that were accepted but not yet settled. For a
restart-safe deployment, build Pay with `redis-session-store` and set
`PAY_SESSION_REDIS_URL` plus a unique `PAY_SESSION_REDIS_PREFIX`; benchmark that
shape separately because a durable store operation is then part of the request
path.

## Important variables

| Variable | Default | Purpose |
|---|---|---|
| `pay_git_ref` | `84146398…` | Immutable Pay commit used by the retained experiment. |
| `pay_rust_toolchain` | `nightly-2026-08-14` | Compiler that enabled curve25519-dalek's AVX-512 IFMA backend. |
| `pay_rustup_init_sha256` | `4acc9acc…` | Pins the x86_64 rustup bootstrap binary downloaded from `static.rust-lang.org`. |
| `pay_rustflags` | `-C target-cpu=native` | Selects the native Zen 5 instruction set. The binary is not portable to older CPUs. |
| `pay_require_avx512_ifma` | `true` | Fails before build if the target CPU lacks IFMA and after build if the binary lacks `vpmadd52`. |
| `pay_min_logical_cpus` | `128` | Rejects undersized hosts for the recorded one-million-per-second target. |
| `pay_proxy_port` | `1402` | Port used by the listener and local health check. |
| `pay_proxy_bind` | `0.0.0.0:1402` | Public listener address. |
| `pay_proxy_env_file` | empty | Controller-local secret file; must be supplied or set in inventory. |

The sample paywall's session lifecycle values are deliberately explicit:

| Setting | Value | Purpose |
|---|---:|---|
| `settlement_interval_ms` | `300000` | Push only the latest active-channel watermarks every five minutes. |
| `close_delay_ms` | `600000` | Close channels after ten minutes without activity. |
| `close_batch_interval_ms` | `60000` | Group idle-close deadlines on one-minute boundaries. |

## Update and rollback

To update, set `pay_git_ref` to a reviewed 40-character commit and rerun the
playbook. The binary is replaced only after a successful locked release build.

To roll back, restore the previous commit SHA and rerun the playbook. To remove
the service and tuning entirely:

```sh
ansible pay_proxies -b -m systemd_service -a 'name=pay-proxy state=stopped enabled=false'
ansible pay_proxies -b -m file -a 'path=/etc/sysctl.d/99-pay-proxy.conf state=absent'
ansible pay_proxies -b -m command -a 'sysctl --system'
```
