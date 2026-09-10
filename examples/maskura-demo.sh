#!/usr/bin/env bash
# The old recorded demo depended on credentials appearing in gateway logs.
# Secrets are no longer logged; keep this entry point as a runnable replacement.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$ROOT/examples/prove-maskura.sh" all
