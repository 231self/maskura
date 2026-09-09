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

cargo audit --ignore RUSTSEC-2023-0071
