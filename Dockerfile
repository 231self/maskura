# syntax=docker/dockerfile:1
# Optimized deploy image for the maskura gateway.
# Pre-built Wasm components committed to components/. Each invocation builds
# one native target; the release workflow assembles its multi-arch manifest.

FROM rust:1.99.1-trixie@sha256:931c2c0531a8b143e044f0f3914dfe802f15bb3d1955f0b657e9359327ac2ffc AS build
WORKDIR /src
ARG CARGO_BUILD_JOBS=2

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo fetch --locked \
    && cargo build --locked --release --jobs "$CARGO_BUILD_JOBS" -p maskura-gateway \
    && cp /src/target/release/maskura-gateway /src/gateway-bin

FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
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
