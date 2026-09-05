# Architecture-optimized gateway build

Build the benchmark gateway for the AMD EPYC 9555P host with Rust's Zen 5
target, whole-program optimization, and an architecture-specific standard
library. This build raised x402 batch-settlement throughput from roughly
731,000 requests/s to 939,000 requests/s outside a settlement sweep.

## Prerequisites

Install the pinned nightly toolchain and its standard-library sources:

```sh
rustup toolchain install nightly-2026-08-14
rustup component add rust-src --toolchain nightly-2026-08-14
```

The pinned compiler is Rust 1.99.0-nightly with LLVM 23.1.0. Pinning the date
keeps benchmark comparisons independent of nightly compiler updates.

## Build

Run the build from `rust/`:

```sh
CARGO_TARGET_DIR=target/znver5-fat \
CARGO_PROFILE_RELEASE_LTO=fat \
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
CARGO_PROFILE_RELEASE_PANIC=abort \
RUSTFLAGS="-C target-cpu=znver5" \
PAY_PDB_ALLOW_PLACEHOLDER=1 \
cargo +nightly-2026-08-14 build \
  -Z build-std=std,panic_abort \
  --release \
  -p pay
```

The gateway binary is written to `target/znver5-fat/release/pay`.

## Optimization settings

| Setting | Effect |
| --- | --- |
| `target-cpu=znver5` | Enables the EPYC 9555P instruction set, including its AVX2 and AVX-512 paths. |
| `lto=fat` | Optimizes across crate boundaries. |
| `codegen-units=1` | Gives LLVM the largest optimization scope at the cost of slower compilation. |
| `panic=abort` | Removes stack-unwinding machinery from the production binary. |
| `-Z build-std=std,panic_abort` | Rebuilds the standard library for Zen 5 instead of linking the generic prebuilt `std`. |
| `PAY_PDB_ALLOW_PLACEHOLDER=1` | Allows a gateway-only build when the optional web UI assets are absent. |

Do not deploy this binary to older or heterogeneous x86 hosts. Use
`-C target-cpu=x86-64-v4` for an AVX-512 fleet baseline, or a generic release
build when the destination CPU is unknown.

## Verify the artifact

Check the version, compiler metadata, and checksum before deployment:

```sh
target/znver5-fat/release/pay --version
readelf -p .comment target/znver5-fat/release/pay
sha256sum target/znver5-fat/release/pay
```

The benchmarked artifact reported:

```text
pay 0.29.0
rustc version 1.99.0-nightly (ba28ff76f 2026-08-13)
LLVM 23.1.0
```

## Observed benchmark effect

The controlled 100,000-channel x402 batch-settlement run produced:

| Measurement | Generic release build | Zen 5 optimized build |
| --- | ---: | ---: |
| Request throughput outside a full sweep | 731k-754k/s | approximately 939k/s |
| Request throughput during a full sweep | 700k-710k/s | approximately 911k-921k/s |
| Full 100,000-channel settlement sweep | 191-193 seconds | 154 seconds on the first sweep |

These numbers measure the combined build configuration. They do not attribute
the improvement to an individual flag. Compare `target-cpu`, LTO, rebuilt
`std`, and profile-guided optimization separately before changing the default
release profile for portable binaries.
