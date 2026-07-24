FROM rust:bookworm AS build

ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

RUN apt-get update && apt-get install -y \
    ca-certificates \
    pkg-config \
    libssl-dev \
    libclang-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Use HTTPS for public git deps instead of SSH
RUN git config --global url."https://github.com/".insteadOf "git@github.com:" && \
    git config --global url."https://github.com/".insteadOf "ssh://git@github.com/"

COPY . .

ARG PAY_PDB_ALLOW_PLACEHOLDER
ENV PAY_PDB_ALLOW_PLACEHOLDER=${PAY_PDB_ALLOW_PLACEHOLDER}

RUN cargo build --release --features gcp_kms,redis-session-store

RUN cp target/release/pay /usr/local/bin/pay

# ── Runtime ──
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r pay && useradd -r -g pay -s /sbin/nologin pay

COPY --from=build /usr/local/bin/pay /usr/local/bin/pay

# Let the non-root `pay` user bind Vercel's default PORT=80 without requiring
# downstream Dockerfiles to switch back to root.
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/pay

WORKDIR /app

USER pay

ENTRYPOINT ["pay"]
