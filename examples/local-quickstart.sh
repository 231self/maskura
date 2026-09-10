#!/usr/bin/env bash
# Backward-compatible entry point for the canonical local S3 proof.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$ROOT/examples/prove-maskura.sh" redaction
