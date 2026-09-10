# syntax=docker/dockerfile:1
# Optimized deploy image for the maskura gateway.
# Pre-built Wasm components committed to components/. Each invocation builds
# one native target; the release workflow assembles its multi-arch manifest.

FROM rust:1.98.0-trixie@sha256:620dbcd124499c59e2406d3741574b5c5838cf9eb9656f0c3a03948f79b02959 AS build
WORKDIR /src
ARG CARGO_BUILD_JOBS=2

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo fetch --locked \
    && cargo build --locked --release --jobs "$CARGO_BUILD_JOBS" -p maskura-gateway \
    && cp /src/target/release/maskura-gateway /src/gateway-bin

FROM debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132
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
