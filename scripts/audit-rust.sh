#!/usr/bin/env bash
set -euo pipefail

# sqlx-macros-core records every database driver's dependencies in Cargo.lock,
# including the unfixed RSA advisory through its unused MySQL driver. Maskura is
# Postgres-only. Keep the exception valid only while RSA is absent from every
# resolved workspace target; if it becomes reachable, fail before cargo-audit.
if cargo tree --workspace --target all -i rsa@0.9.10 2>/dev/null | grep -q '^rsa v0\.9\.10'; then
  echo "ERROR: rsa 0.9.10 is now reachable; RUSTSEC-2023-0071 cannot be ignored" >&2
  exit 1
fi

# RUSTSEC-2026-0381/0382 (webpki-roots / rustls-webpki bundled roots trust
# distrusted emSign intermediates): rustls-webpki is fixed at 0.103.16 and the
# webpki-roots 1.x line at 1.0.10 (both applied in the lock). The 0.26
# webpki-roots line has NO fix (advisory fixes >=1.0.10) and is held by
# sqlx-core's TLS root bundle (no newer sqlx 0.8.x; checked 2026-10-21).
# Exposure: Postgres TLS validation against a bundle containing distrusted
# emSign intermediates. Keep the exception only while sqlx-core is the sole
# holder of the 0.26 line; re-review on any sqlx/sea-orm bump.
holders="$(cargo tree --workspace --target all --color never -i webpki-roots@0.26.11 --depth 1 \
  2>/dev/null | tail -n +2 | sed 's/^[^A-Za-z0-9_-]*//' | awk '{print $1}' | sort -u)"
if [ -n "$holders" ] && [ "$holders" != "sqlx-core" ]; then
  echo "ERROR: webpki-roots 0.26.11 holders changed ($holders); re-review RUSTSEC-2026-0381" >&2
  exit 1
fi

# RUSTSEC-2026-0387 (crypto-bigint 0.5.5 timing variability in operations
# intended to be constant-time; fixes >=0.7.6): held by aws-sigv4 1.6.0 (AWS
# SigV4 signing path — no newer release exists, checked 2026-10-24) and
# elliptic-curve 0.13.8 via p256 0.13.2 in maskura-pipeline-config (the ES256
# verification ADR 0023 pins; a fixed crypto-bigint needs an
# elliptic-curve/p256 0.14 major crypto-stack upgrade = architectural change,
# not a patch). Exposure: timing side channels in bigint operations used by
# SigV4 signing and P-256 verification. Keep the exception only while these
# two are the sole holders; re-review on any aws-sigv4/elliptic-curve/p256 bump.
holders="$(cargo tree --workspace --target all --color never -i crypto-bigint@0.5.5 --depth 1 \
  2>/dev/null | tail -n +2 | sed 's/^[^A-Za-z0-9_-]*//' | awk '{print $1}' | sort -u)"
expected_holders="$(printf 'aws-sigv4\nelliptic-curve')"
if [ -n "$holders" ] && [ "$holders" != "$expected_holders" ]; then
  echo "ERROR: crypto-bigint 0.5.5 holders changed ($holders); re-review RUSTSEC-2026-0387" >&2
  exit 1
fi

# RUSTSEC-2026-0391/0395-0406/0410 (the zstd family: abandoned-stream data
# leaks into the next stream on a reused context, uninitialized memory on
# legacy-frame decode failures, and the zstd-sys companion; fixes at
# zstd >=0.14.3 / zstd-safe >=8.2.0): held by apache-avro 0.22 (its
# zstandard feature pins zstd ^0.13; 0.22.0 is the latest release,
# checked 2026-10-26) and wasmtime-internal-cache 48 (needs the wasmtime
# 50 runtime major). Exposure: zstd decompression of untrusted Avro
# blocks and plugin cache reads. Keep the exception only while these two
# are the sole holders. Named follow-ups: evaluate wasmtime 50 (drops
# one holder) and evaluate dropping apache-avro's zstandard feature
# (fail-closed on zstd-compressed Avro, drops the untrusted-input path);
# re-review on any apache-avro/wasmtime bump.
holders="$(cargo tree --workspace --target all --color never -i zstd@0.13.3 --depth 1 \
  2>/dev/null | tail -n +2 | sed 's/^[^A-Za-z0-9_-]*//' | awk '{print $1}' | sort -u)"
expected_holders="$(printf 'apache-avro\nwasmtime-internal-cache')"
if [ -n "$holders" ] && [ "$holders" != "$expected_holders" ]; then
  echo "ERROR: zstd 0.13.3 holders changed ($holders); re-review the zstd family exceptions" >&2
  exit 1
fi

cargo audit --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2026-0381 --ignore RUSTSEC-2026-0387 \
  --ignore RUSTSEC-2026-0391 --ignore RUSTSEC-2026-0395 --ignore RUSTSEC-2026-0396 \
  --ignore RUSTSEC-2026-0397 --ignore RUSTSEC-2026-0398 --ignore RUSTSEC-2026-0399 \
  --ignore RUSTSEC-2026-0400 --ignore RUSTSEC-2026-0401 --ignore RUSTSEC-2026-0402 \
  --ignore RUSTSEC-2026-0403 --ignore RUSTSEC-2026-0404 --ignore RUSTSEC-2026-0405 \
  --ignore RUSTSEC-2026-0406 --ignore RUSTSEC-2026-0410
