#!/usr/bin/env bash
# Reproducible Polaris 1.8.0 + Trino 484 probe for byte-preserving storage
# scopes (ADR 0036). Manual/acceptance probe, not part of CI.
#
# Starts the gateway with a local FileStore and a byte-preserving scope, points
# Apache Polaris at it as the catalog's object store, connects Trino through
# the Iceberg REST catalog, and runs CREATE SCHEMA/CREATE TABLE/INSERT/SELECT.
# It then verifies the snapshot, restarts the gateway over the same storage,
# and re-runs the query.
#
# Requires: docker, curl, jq, aws (CLI), a built maskura-gateway binary.
#   MASKURA_GATEWAY_BIN=/path/to/maskura-gateway bash scripts/probe-polaris-trino.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATEWAY_BIN="${MASKURA_GATEWAY_BIN:-$ROOT/target/debug/maskura-gateway}"
# Docker Desktop shares /Users, not the macOS per-process TMPDIR; the Trino
# catalog file is mounted from here.
mkdir -p "$HOME/.cache"
WORK="$(mktemp -d "$HOME/.cache/maskura-polaris-probe.XXXXXX")"
STORAGE="$WORK/storage"

GW_PORT="${MASKURA_PROBE_GATEWAY_PORT:-19000}"
POLARIS_PORT="${MASKURA_PROBE_POLARIS_PORT:-18181}"
POLARIS_MGMT_PORT="${MASKURA_PROBE_POLARIS_MGMT_PORT:-18182}"
TRINO_PORT="${MASKURA_PROBE_TRINO_PORT:-18080}"

# Stable bootstrap API key (maskura_<32-hex> / maskura_secret_<32-hex>) and a
# fixed KEK so SigV4 verification survives the gateway restart below.
ACCESS_KEY="maskura_$(openssl rand -hex 16)"
SECRET_KEY="maskura_secret_$(openssl rand -hex 16)"
SECRET_KEK="$(openssl rand -base64 32)"
BUCKET="warehouse"
CATALOG="warehouse"
POLARIS_ROOT="root"
POLARIS_SECRET="s3cr3t"

POLARIS_CONTAINER="maskura-polaris-probe"
TRINO_CONTAINER="maskura-trino-probe"
GW_PID=""

log() { printf '\n==> %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

cleanup() {
  docker rm -f "$TRINO_CONTAINER" "$POLARIS_CONTAINER" >/dev/null 2>&1 || true
  if [ -n "$GW_PID" ] && kill -0 "$GW_PID" >/dev/null 2>&1; then
    kill "$GW_PID" >/dev/null 2>&1 || true
    wait "$GW_PID" >/dev/null 2>&1 || true
  fi
  printf '\nArtifacts: %s\n' "$WORK"
}
trap cleanup EXIT

start_gateway() {
  log "Starting gateway on :$GW_PORT (storage $STORAGE)"
  mkdir -p "$STORAGE"
  LISTEN_ADDR="127.0.0.1:$GW_PORT" \
  MASKURA_STORAGE_MODE=local \
  MASKURA_LOCAL_STORAGE_DIR="$STORAGE" \
  MASKURA_SINGLE_TENANT=true \
  MASKURA_BOOTSTRAP_KEY="$ACCESS_KEY" \
  MASKURA_BOOTSTRAP_SECRET="$SECRET_KEY" \
  MASKURA_SECRET_KEK="$SECRET_KEK" \
  MASKURA_BYTE_PRESERVING_SCOPES="$BUCKET" \
  MASKURA_MULTIPART_MODE=staged \
  MASKURA_SIGV4_REGION=us-east-1 \
  MASKURA_SPOOL_DIR="$WORK/spool" \
    "$GATEWAY_BIN" >"$WORK/gateway.log" 2>&1 &
  GW_PID=$!
  for _ in $(seq 1 120); do
    if curl -fsS "http://127.0.0.1:$GW_PORT/health" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$GW_PID" >/dev/null 2>&1; then
      tail -40 "$WORK/gateway.log" >&2 || true
      fail "gateway exited during startup"
    fi
    sleep 1
  done
  tail -40 "$WORK/gateway.log" >&2 || true
  fail "gateway did not become healthy"
}

stop_gateway() {
  if [ -n "$GW_PID" ] && kill -0 "$GW_PID" >/dev/null 2>&1; then
    kill "$GW_PID"
    wait "$GW_PID" >/dev/null 2>&1 || true
  fi
  GW_PID=""
}

s3() {
  AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
  AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
  AWS_DEFAULT_REGION=us-east-1 \
  AWS_EC2_METADATA_DISABLED=true \
    aws --endpoint-url "http://127.0.0.1:$GW_PORT" "$@"
}

token() {
  curl -fsS -X POST "http://127.0.0.1:$POLARIS_PORT/api/catalog/v1/oauth/tokens" \
    -d grant_type=client_credentials \
    -d "client_id=$POLARIS_ROOT" \
    -d "client_secret=$POLARIS_SECRET" \
    -d scope=PRINCIPAL_ROLE:ALL | jq -r .access_token
}

sql() {
  docker exec "$TRINO_CONTAINER" trino --output-format TSV_HEADER --execute "$1"
}

[ -x "$GATEWAY_BIN" ] || fail "gateway binary not found at $GATEWAY_BIN (set MASKURA_GATEWAY_BIN)"
command -v jq >/dev/null || fail "jq is required"
command -v aws >/dev/null || fail "aws CLI is required"

start_gateway

log "Creating the $BUCKET bucket"
s3 s3api create-bucket --bucket "$BUCKET" >/dev/null || fail "bucket creation failed"
s3 s3api head-bucket --bucket "$BUCKET" || fail "bucket head failed"

log "Starting Polaris 1.8.0"
docker run -d --rm --name "$POLARIS_CONTAINER" \
  -p "$POLARIS_PORT:8181" -p "$POLARIS_MGMT_PORT:8182" \
  -e POLARIS_BOOTSTRAP_CREDENTIALS="POLARIS,$POLARIS_ROOT,$POLARIS_SECRET" \
  -e polaris.realm-context.realms=POLARIS \
  -e AWS_REGION=us-east-1 \
  -e AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
  -e quarkus.otel.sdk.disabled=true \
  apache/polaris:1.8.0 >/dev/null

for _ in $(seq 1 120); do
  if curl -fsS "http://127.0.0.1:$POLARIS_MGMT_PORT/q/health/ready" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS "http://127.0.0.1:$POLARIS_MGMT_PORT/q/health/ready" >/dev/null \
  || { docker logs --tail 80 "$POLARIS_CONTAINER" >&2 || true; fail "Polaris did not become ready"; }

TOKEN="$(token)"
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || fail "Polaris token request failed"

log "Creating the Polaris catalog '$CATALOG' (S3 endpoint = gateway)"
CATALOG_PAYLOAD="$(jq -n \
  --arg name "$CATALOG" \
  --arg location "s3://$BUCKET" \
  --arg endpoint "http://host.docker.internal:$GW_PORT" \
  '{catalog: {name: $name, type: "INTERNAL", readOnly: false,
    properties: {"default-base-location": $location},
    storageConfigInfo: {storageType: "S3", allowedLocations: [$location],
      endpoint: $endpoint, endpointInternal: $endpoint,
      pathStyleAccess: true, region: "us-east-1", stsUnavailable: true}}}')"
curl -fsS -X POST "http://127.0.0.1:$POLARIS_PORT/api/management/v1/catalogs" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Polaris-Realm: POLARIS" \
  -H "Content-Type: application/json" \
  -d "$CATALOG_PAYLOAD" >/dev/null || fail "catalog creation failed"

# The catalog_admin role needs content management for CREATE TABLE.
curl -fsS -X PUT \
  "http://127.0.0.1:$POLARIS_PORT/api/management/v1/catalogs/$CATALOG/catalog-roles/catalog_admin/grants" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Polaris-Realm: POLARIS" \
  -H "Content-Type: application/json" \
  -d '{"type":"catalog","privilege":"CATALOG_MANAGE_CONTENT"}' >/dev/null \
  || fail "CATALOG_MANAGE_CONTENT grant failed"

log "Starting Trino 484 with the Iceberg REST catalog"
mkdir -p "$WORK/trino/catalog"
cat >"$WORK/trino/catalog/iceberg.properties" <<EOF
connector.name=iceberg
iceberg.catalog.type=rest
iceberg.rest-catalog.uri=http://host.docker.internal:$POLARIS_PORT/api/catalog
iceberg.rest-catalog.warehouse=$CATALOG
iceberg.rest-catalog.security=OAUTH2
iceberg.rest-catalog.oauth2.credential=$POLARIS_ROOT:$POLARIS_SECRET
iceberg.rest-catalog.oauth2.scope=PRINCIPAL_ROLE:ALL
iceberg.rest-catalog.vended-credentials-enabled=false
fs.native-s3.enabled=true
s3.endpoint=http://host.docker.internal:$GW_PORT
s3.path-style-access=true
s3.region=us-east-1
s3.aws-access-key=$ACCESS_KEY
s3.aws-secret-key=$SECRET_KEY
EOF
docker run -d --rm --name "$TRINO_CONTAINER" \
  -p "$TRINO_PORT:8080" \
  -v "$WORK/trino/catalog:/etc/trino/catalog:ro" \
  trinodb/trino:484 >/dev/null

for _ in $(seq 1 180); do
  if curl -fsS "http://127.0.0.1:$TRINO_PORT/v1/info" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS "http://127.0.0.1:$TRINO_PORT/v1/info" >/dev/null \
  || { docker logs --tail 80 "$TRINO_CONTAINER" >&2 || true; fail "Trino did not become ready"; }
# /v1/info answers before the server accepts queries; wait for a real query.
for _ in $(seq 1 180); do
  if docker exec "$TRINO_CONTAINER" trino --execute "SELECT 1" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$TRINO_CONTAINER" trino --execute "SELECT 1" >/dev/null 2>&1 \
  || { docker logs --tail 120 "$TRINO_CONTAINER" >&2 || true; fail "Trino did not accept queries"; }

log "CREATE SCHEMA / CREATE TABLE / INSERT / SELECT through Polaris"
sql "CREATE SCHEMA iceberg.probe" >/dev/null
sql "CREATE TABLE iceberg.probe.sample (x integer)" >/dev/null
SNAPSHOTS_BEFORE="$(sql 'SELECT count(*) FROM iceberg.probe."sample$snapshots"' | tail -n 1 | tr -d '\r')"
sql "INSERT INTO iceberg.probe.sample VALUES (1), (2), (3)" >/dev/null
ROWS="$(sql 'SELECT x FROM iceberg.probe.sample ORDER BY x')"
printf '%s\n' "$ROWS"
ROWS_VALUES="$(printf '%s\n' "$ROWS" | tail -n +2 | tr -d '\r' | tr '\n' ',' | sed 's/,$//')"
[ "$ROWS_VALUES" = "1,2,3" ] || fail "row readback mismatch ($ROWS_VALUES)"

SNAPSHOTS_AFTER="$(sql 'SELECT count(*) FROM iceberg.probe."sample$snapshots"' | tail -n 1 | tr -d '\r')"
printf 'snapshot count: after create=%s, after insert=%s\n' "$SNAPSHOTS_BEFORE" "$SNAPSHOTS_AFTER"
[ "$SNAPSHOTS_AFTER" -gt "$SNAPSHOTS_BEFORE" ] \
  || fail "the Iceberg snapshot did not advance"

log "Objects stored under the scope (byte-preserving)"
find "$STORAGE" -type f | sed "s|$STORAGE/||" | sort | head -20

log "Restarting the gateway over the same FileStore"
stop_gateway
start_gateway
ROWS_AFTER_RESTART="$(sql 'SELECT x FROM iceberg.probe.sample ORDER BY x')"
printf '%s\n' "$ROWS_AFTER_RESTART"
[ "$ROWS_AFTER_RESTART" = "$ROWS" ] || fail "row readback changed after the gateway restart"

log "Probe passed: Polaris commit, Trino readback, snapshot, and restart"
