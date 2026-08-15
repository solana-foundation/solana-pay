# High-throughput Pay proxy on Ubuntu

This example provisions one x86_64 Ubuntu host as a headless Pay proxy with a
single `GET /api/v1/compute` endpoint gated by MPP sessions. It builds Pay with
the exact nightly/toolchain shape used by the Sunburst experiment, applies
conservative socket tuning, installs a hardened systemd unit, and verifies that
the endpoint returns an HTTP 402 payment challenge.

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
- A devnet RPC URL and a Solana recipient address.

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

Edit `inventory.yml` with the target host. Fill all three values in
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
