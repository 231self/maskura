#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: $1 is required for the dependency audit" >&2
    exit 1
  fi
}

require_command cargo
require_command grep
require_command npm

echo "==> Rust advisories"
bash scripts/audit-rust.sh

echo "==> Rust dependency policy"
cargo deny check --hide-inclusion-graph

echo "==> Python advisories"
if command -v uvx >/dev/null 2>&1; then
  uvx --from pip-audit==2.9.0 pip-audit \
    --strict \
    --progress-spinner off \
    --requirement sdks/python/requirements.txt
elif python3 -c 'import pip_audit' >/dev/null 2>&1; then
  python3 -m pip_audit \
    --strict \
    --progress-spinner off \
    --requirement sdks/python/requirements.txt
else
  echo "error: install uv or pip-audit 2.9.0 for the Python dependency audit" >&2
  exit 1
fi

echo "==> TypeScript advisories"
npm_audit_dir="$(mktemp -d)"
trap 'rm -rf -- "$npm_audit_dir"' EXIT
cp sdks/typescript/package.json "$npm_audit_dir/package.json"
(
  cd "$npm_audit_dir"
  npm install --package-lock-only --ignore-scripts --no-audit --no-fund >/dev/null
  npm audit
)

echo "==> Immutable CI and container references"
if grep -REn \
  'uses:[[:space:]]+[^./[:space:]][^[:space:]]*@' \
  .github/workflows \
  | grep -Ev '@[0-9a-f]{40}([[:space:]]|$)'; then
  echo "error: external GitHub Actions must use a full 40-character commit SHA" >&2
  exit 1
fi

if grep -nE '^FROM[[:space:]]+' Dockerfile Dockerfile.release \
  | grep -Ev '@sha256:[0-9a-f]{64}([[:space:]]|$)'; then
  echo "error: Docker base images must use an immutable sha256 digest" >&2
  exit 1
fi

echo "Dependency and supply-chain audits passed"
