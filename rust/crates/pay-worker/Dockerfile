# syntax=docker/dockerfile:1.7
#
# Build context is `rust/` (the whole Cargo workspace) — pay-worker is a
# workspace member and needs the other crates' manifests to resolve. CI sets
# `context: rust`, `file: crates/pay-worker/Dockerfile`.

# ---- builder ----------------------------------------------------------------
FROM rust:1.89-slim-bookworm AS builder
WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config ca-certificates git cmake libssl-dev libclang-dev \
 && rm -rf /var/lib/apt/lists/*

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release -p pay-worker --bin close-channels --bin settle-sessions && \
    cp /app/target/release/close-channels /close-channels && \
    cp /app/target/release/settle-sessions /settle-sessions

# ---- runtime ----------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=builder /close-channels /usr/local/bin/close-channels
COPY --from=builder /settle-sessions /usr/local/bin/settle-sessions
COPY crates/pay-worker/config/ ./config/

ENV RUST_LOG=info
# DRY_RUN defaults to true inside the binary; the image does not override it,
# so a fresh `gcloud run jobs execute` is safe unless DRY_RUN=false is passed.
USER nonroot
ENTRYPOINT ["/usr/local/bin/close-channels"]
