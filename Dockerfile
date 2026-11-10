# syntax=docker/dockerfile:1
# Optimized deploy image for the maskura gateway.
# Pre-built Wasm components committed to components/. Each invocation builds
# one native target; the release workflow assembles its multi-arch manifest.

FROM rust:1.99.1-trixie@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07 AS build
WORKDIR /src
ARG CARGO_BUILD_JOBS=2

COPY . .

RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo fetch --locked \
    && python3 scripts/sqlite-guard.py \
    && cargo build --locked --release --jobs "$CARGO_BUILD_JOBS" -p maskura-gateway \
    && python3 scripts/sqlite-guard.py \
    && cp /src/target/release/maskura-gateway /src/gateway-bin

# This step must execute anew for each supported host-wrapper invocation. The
# expensive compilation above remains cacheable; its actual source graph is
# inspected again with the wrapper's fresh nonce before an image is assembled.
ARG MASKURA_GUARD_NONCE
RUN python3 scripts/sqlite-guard.py --nonce "$MASKURA_GUARD_NONCE"

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/gateway-bin /usr/local/bin/maskura-gateway
COPY components /app/components
ENV MASKURA_DEFAULT_PLUGIN=/app/components/pii-default.component.wasm
ENV MASKURA_PLUGINS_DIR=/app/components
ENV LISTEN_ADDR=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["maskura-gateway"]
