#!/usr/bin/env bash
# Run the filter micro-benchmark and leave enough provenance to reproduce it.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/target/benchmarks.metadata"

cd "$ROOT"
cargo run --locked --release -p maskura-wasm-runtime --example bench_plugins

revision="unknown"
change="unknown"
dirty="unknown"
if command -v jj >/dev/null 2>&1; then
  revision="$(jj log --no-graph -r @ -T 'commit_id' 2>/dev/null || printf unknown)"
  change="$(jj log --no-graph -r @ -T 'change_id' 2>/dev/null || printf unknown)"
  if [ -z "$(jj diff --summary 2>/dev/null)" ]; then dirty=false; else dirty=true; fi
fi

processor="unknown"
if command -v sysctl >/dev/null 2>&1; then
  processor="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || printf unknown)"
elif [ -r /proc/cpuinfo ]; then
  processor="$(awk -F ': ' '/^model name/{print $2; exit}' /proc/cpuinfo)"
fi

{
  printf 'recorded_at_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'revision=%s\n' "$revision"
  printf 'change=%s\n' "$change"
  printf 'working_copy_dirty=%s\n' "$dirty"
  printf 'os=%s\n' "$(uname -sr)"
  printf 'architecture=%s\n' "$(uname -m)"
  printf 'processor=%s\n' "$processor"
  printf 'rustc=%s\n' "$(rustc --version)"
  printf 'cargo=%s\n' "$(cargo --version)"
  printf 'command=just bench-plugins\n'
} > "$OUT"

printf 'wrote %s\n' "$OUT"
