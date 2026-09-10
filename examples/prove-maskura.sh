#!/usr/bin/env bash
# Three executable claims: S3 interoperability + redaction, runtime Wasm
# import, and a Python hybrid-encryption round trip.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-all}"
IMAGE="${MASKURA_PROOF_IMAGE:-ghcr.io/231self/maskura/maskura:latest}"
PORT="${MASKURA_PROOF_PORT:-8793}"
ENDPOINT="http://127.0.0.1:${PORT}"
CONTAINER="maskura-proof-${PPID}-$$"
VOLUME="maskura-proof-data-${PPID}-$$"
TMP_CREATED="$(mktemp -d "${TMPDIR:-/tmp}/maskura-proof.XXXXXX")"
TMP="$(cd "$TMP_CREATED" && pwd -P)"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker volume rm "$VOLUME" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

require() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

plugin_ids() {
  curl -fsS "$ENDPOINT/dashboard/api/plugins" > "$TMP/plugins.json"
  python3 - "$TMP/plugins.json" "${1:-}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    plugins = json.load(handle)
name = sys.argv[2]
for plugin in plugins:
    if not name or plugin["name"] == name:
        print(plugin["id"])
PY
}

disable_plugins() {
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    curl -fsS -X PUT -H 'Content-Type: application/json' \
      -d '{"enabled":false}' "$ENDPOINT/dashboard/api/plugins/$id" >/dev/null
  done < <(plugin_ids)
}

enable_plugin() {
  local name="$1"
  local id
  id="$(plugin_ids "$name")"
  [ -n "$id" ] || fail "plugin not found: $name"
  curl -fsS -X PUT -H 'Content-Type: application/json' \
    -d '{"enabled":true}' "$ENDPOINT/dashboard/api/plugins/$id" >/dev/null
}

put_with_aws() {
  local source="$1"
  local key="$2"
  AWS_ACCESS_KEY_ID=proof AWS_SECRET_ACCESS_KEY=proof AWS_DEFAULT_REGION=us-east-1 \
    AWS_EC2_METADATA_DISABLED=true aws s3 --endpoint-url "$ENDPOINT" \
    cp "$source" "s3://maskura-local/$key" --content-type text/plain >/dev/null
}

get_with_aws() {
  local key="$1"
  AWS_ACCESS_KEY_ID=proof AWS_SECRET_ACCESS_KEY=proof AWS_DEFAULT_REGION=us-east-1 \
    AWS_EC2_METADATA_DISABLED=true aws s3 --endpoint-url "$ENDPOINT" \
    cp "s3://maskura-local/$key" -
}

prove_redaction() {
  require aws
  disable_plugins
  enable_plugin pii-default
  printf 'jane@example.com 4111111111111111\n' > "$TMP/redaction.txt"
  put_with_aws "$TMP/redaction.txt" proof/redaction.txt
  get_with_aws proof/redaction.txt > "$TMP/redacted.txt"
  grep -qF '[REDACTED_EMAIL]' "$TMP/redacted.txt" || fail "email was not redacted"
  grep -qF '[REDACTED_CARD]' "$TMP/redacted.txt" || fail "card was not redacted"
  ! grep -qF 'jane@example.com' "$TMP/redacted.txt" || fail "plaintext email reached raw read-back"
  printf 'PASS  unmodified AWS CLI -> Maskura S3 endpoint -> redacted object\n'
}

prove_plugin_import() {
  require aws
  local component="$TMP/email-detect.component.wasm"
  docker cp "$CONTAINER:/app/components/email-detect.component.wasm" "$component" >/dev/null
  [ -s "$component" ] || fail "versioned image does not contain email-detect.component.wasm"
  disable_plugins
  curl -fsS -X POST -H 'x-maskura-plugin-name: proof-email-only' \
    --data-binary "@$component" "$ENDPOINT/dashboard/api/plugins" > "$TMP/imported.json"
  python3 - "$TMP/imported.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    plugin = json.load(handle)
assert plugin["name"] == "proof-email-only"
assert plugin["enabled"] is True
PY
  printf 'jane@example.com 4111111111111111\n' > "$TMP/plugin.txt"
  put_with_aws "$TMP/plugin.txt" proof/plugin.txt
  get_with_aws proof/plugin.txt > "$TMP/plugin-output.txt"
  grep -qF '[REDACTED_EMAIL]' "$TMP/plugin-output.txt" || fail "imported component did not run"
  grep -qF '4111111111111111' "$TMP/plugin-output.txt" || fail "unexpected filter changed card"
  printf 'PASS  Wasm component imported at runtime and changed the live pipeline\n'
}

prove_python_hybrid() {
  disable_plugins
  enable_plugin envelope-encrypt.component
  if command -v uv >/dev/null 2>&1; then
    MASKURA_PROOF_ENDPOINT="$ENDPOINT" \
      uv run --with "$ROOT/sdks/python" \
      python "$ROOT/examples/python-hybrid-roundtrip.py"
  else
    PYTHONPATH="$ROOT/sdks/python${PYTHONPATH:+:$PYTHONPATH}" \
      MASKURA_PROOF_ENDPOINT="$ENDPOINT" python3 "$ROOT/examples/python-hybrid-roundtrip.py"
  fi
}

case "$MODE" in
  all|redaction|plugin|python) ;;
  *) fail "usage: $0 [all|redaction|plugin|python]" ;;
esac

require docker
require curl
require python3

printf 'Pulling %s\n' "$IMAGE"
docker pull "$IMAGE" >/dev/null
docker run --rm -d --name "$CONTAINER" \
  -p "127.0.0.1:${PORT}:8080" \
  --volume "$VOLUME:/data" \
  -e AUTH_DISABLED=true \
  -e MASKURA_KEYS_FILE=/data/keys.json \
  -e MASKURA_STORAGE_MODE=local \
  -e MASKURA_LOCAL_STORAGE_DIR=/data \
  -e MASKURA_STREAMING_READ_MODE=passthrough \
  "$IMAGE" >/dev/null

healthy=0
for _ in $(seq 1 30); do
  if curl -fsS "$ENDPOINT/health" >/dev/null 2>&1; then
    healthy=1
    break
  fi
  sleep 1
done
if [ "$healthy" -ne 1 ]; then
  docker logs "$CONTAINER" >&2 || true
  fail "gateway did not become healthy at $ENDPOINT"
fi

digest="$(docker image inspect --format '{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || true)"
printf 'Gateway healthy: %s\n' "${digest:-$IMAGE}"

case "$MODE" in
  all)
    prove_redaction
    prove_plugin_import
    prove_python_hybrid
    ;;
  redaction) prove_redaction ;;
  plugin) prove_plugin_import ;;
  python) prove_python_hybrid ;;
esac

printf 'All requested proofs passed.\n'
