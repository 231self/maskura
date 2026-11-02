# syntax=docker/dockerfile:1
# Optimized deploy image for the maskura gateway.
# Pre-built Wasm components committed to components/. Each invocation builds
# one native target; the release workflow assembles its multi-arch manifest.

FROM rust:1.99.1-trixie@sha256:09027f873d45b8ecd1dc86f1fa13b7a62b875c961f017a0e331267b350430137 AS build
WORKDIR /src
ARG CARGO_BUILD_JOBS=2

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo fetch --locked \
    && cargo build --locked --release --jobs "$CARGO_BUILD_JOBS" -p maskura-gateway \
    && cp /src/target/release/maskura-gateway /src/gateway-bin

FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
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
