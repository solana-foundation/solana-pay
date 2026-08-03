# syntax=docker/dockerfile:1.7
#
# Build context is `rust/` (the whole Cargo workspace), not this directory —
# pay-api is a workspace member and needs the other crates' manifests to
# resolve. CI sets `context: rust`, `file: crates/pay-api/Dockerfile`.

# ---- builder ----------------------------------------------------------------
FROM rust:1.89-slim-bookworm AS builder
WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config ca-certificates git cmake libssl-dev libclang-dev \
 && rm -rf /var/lib/apt/lists/*

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release -p pay-api --bin pay-api && \
    cp /app/target/release/pay-api /pay-api

# ---- runtime ----------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=builder /pay-api /usr/local/bin/pay-api
COPY crates/pay-api/config/ ./config/

ENV PORT=8080
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/usr/local/bin/pay-api"]
