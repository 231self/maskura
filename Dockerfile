# syntax=docker/dockerfile:1
# Optimized deploy image for the maskura gateway.
# Pre-built Wasm components committed to components/. Each invocation builds
# one native target; the release workflow assembles its multi-arch manifest.

FROM rust:1.98.1-trixie@sha256:a8a5f0a1e5fe7dfe1d352591e4a1c7dd2c08fd70475cae872cf3458ba0df0546 AS build
WORKDIR /src
ARG CARGO_BUILD_JOBS=2

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo fetch --locked \
    && cargo build --locked --release --jobs "$CARGO_BUILD_JOBS" -p maskura-gateway \
    && cp /src/target/release/maskura-gateway /src/gateway-bin

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
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
