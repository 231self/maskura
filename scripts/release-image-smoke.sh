#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <gateway-image-ref>" >&2
  exit 2
fi

IMAGE_REF="$1"
RUN_ID="${GITHUB_RUN_ID:-$$}-${GITHUB_RUN_ATTEMPT:-0}-${RANDOM}"
NETWORK="maskura-release-smoke-${RUN_ID}"
MINIO_NAME="maskura-minio-${RUN_ID}"
POSTGRES_NAME="maskura-postgres-${RUN_ID}"
GATEWAY_NAME="maskura-gateway-${RUN_ID}"
MINIO_IMAGE="quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"
POSTGRES_IMAGE="postgres:17-trixie@sha256:e38411452a464af89e5adadb8d223bf53b898d47d6ef918b2d58c08707350449"
MC_IMAGE="quay.io/minio/mc:RELEASE.2025-08-13T08-35-41Z@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727"
MC_CONF="maskura-release-smoke-mc-${RUN_ID}"
LOCAL_VOLUME="maskura-release-smoke-local-${RUN_ID}"
GATEWAY_PORT="${MASKURA_RELEASE_SMOKE_PORT:-18080}"

cleanup() {
  docker rm -f "$GATEWAY_NAME" "$MINIO_NAME" "$POSTGRES_NAME" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  docker volume rm "$MC_CONF" "$LOCAL_VOLUME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create "$NETWORK" >/dev/null
docker volume create "$MC_CONF" >/dev/null
docker run -d --name "$MINIO_NAME" --network "$NETWORK" \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin \
  "$MINIO_IMAGE" server /data >/dev/null

ready=0
for _ in $(seq 1 30); do
  if docker exec "$MINIO_NAME" curl --fail --silent \
      http://127.0.0.1:9000/minio/health/live >/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  docker logs "$MINIO_NAME" || true
  echo "ERROR: release-smoke MinIO did not become ready" >&2
  exit 1
fi

# Release builds have no in-memory operation journal, so the gateway needs a
# Postgres for the durable journal the streaming S3 sink requires.
docker run -d --name "$POSTGRES_NAME" --network "$NETWORK" \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=maskura \
  "$POSTGRES_IMAGE" >/dev/null
pg_ready=0
for _ in $(seq 1 30); do
  if docker exec "$POSTGRES_NAME" pg_isready -U postgres -d maskura >/dev/null 2>&1; then
    pg_ready=1
    break
  fi
  sleep 1
done
if [ "$pg_ready" -ne 1 ]; then
  docker logs "$POSTGRES_NAME" || true
  echo "ERROR: release-smoke Postgres did not become ready" >&2
  exit 1
fi

docker run --rm --network "$NETWORK" -v "$MC_CONF:/root/.mc" "$MC_IMAGE" --no-color \
  alias set local "http://${MINIO_NAME}:9000" minioadmin minioadmin >/dev/null
docker run --rm --network "$NETWORK" -v "$MC_CONF:/root/.mc" "$MC_IMAGE" --no-color \
  mb "local/maskura-release-smoke" --ignore-existing >/dev/null

docker run -d --name "$GATEWAY_NAME" --network "$NETWORK" \
  -p "127.0.0.1:${GATEWAY_PORT}:8080" \
  -e AUTH_DISABLED=true \
  -e MASKURA_STREAMING_S3_PROVIDER=minio \
  -e DATABASE_URL="postgres://postgres:postgres@${POSTGRES_NAME}:5432/maskura" \
  -e MASKURA_KEYS_FILE=/tmp/keys.json \
  -e S3_ENDPOINT="http://${MINIO_NAME}:9000" \
  -e S3_ACCESS_KEY_ID=minioadmin \
  -e S3_SECRET_ACCESS_KEY=minioadmin \
  -e S3_REGION=us-east-1 \
  "$IMAGE_REF" >/dev/null

ready=0
for _ in $(seq 1 30); do
  if curl --fail --silent "http://127.0.0.1:${GATEWAY_PORT}/health" >/dev/null; then
    ready=1
    break
  fi
  if [ "$(docker inspect --format '{{.State.Running}}' "$GATEWAY_NAME")" != "true" ]; then
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  docker logs "$GATEWAY_NAME" || true
  echo "ERROR: packaged gateway did not become ready" >&2
  exit 1
fi

INPUT='contact release-smoke@example.com card 4111111111111111'
curl --fail --silent --show-error \
  -X PUT \
  -H 'Content-Type: text/plain' \
  --data-binary "$INPUT" \
  "http://127.0.0.1:${GATEWAY_PORT}/maskura-release-smoke/object.txt" >/dev/null

READBACK="$(docker run --rm --network "$NETWORK" -v "$MC_CONF:/root/.mc" "$MC_IMAGE" --no-color \
  cat 'local/maskura-release-smoke/object.txt')"
case "$READBACK" in
  *'[REDACTED_EMAIL]'*'[REDACTED_CARD]'*) ;;
  *)
    echo "ERROR: packaged gateway did not persist expected transformed markers" >&2
    exit 1
    ;;
esac
if [[ "$READBACK" == *"release-smoke@example.com"* || "$READBACK" == *"4111111111111111"* ]]; then
  echo "ERROR: packaged gateway persisted raw PII" >&2
  exit 1
fi

echo "release image data-plane smoke passed"

# The public Docker quickstart is the zero-config local appliance: one volume,
# no env vars, generated root credentials, byte-preserving storage, the
# canonical `maskura` bucket, and the MinIO-convention port 9000.
docker rm -f "$GATEWAY_NAME" >/dev/null
docker volume create "$LOCAL_VOLUME" >/dev/null
docker run -d --name "$GATEWAY_NAME" \
  -p "127.0.0.1:${GATEWAY_PORT}:9000" \
  -v "$LOCAL_VOLUME:/data" \
  "$IMAGE_REF" >/dev/null

ready=0
for _ in $(seq 1 30); do
  if curl --fail --silent "http://127.0.0.1:${GATEWAY_PORT}/ready" >/dev/null; then
    ready=1
    break
  fi
  if [ "$(docker inspect --format '{{.State.Running}}' "$GATEWAY_NAME")" != "true" ]; then
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  docker logs "$GATEWAY_NAME" || true
  echo "ERROR: zero-config gateway did not become ready" >&2
  exit 1
fi

# The generated root credential is disclosed once in the container logs.
CRED_LINE="$(docker logs "$GATEWAY_NAME" 2>&1 | grep 'generated local root credentials' | head -1)"
ACCESS_KEY="$(printf '%s\n' "$CRED_LINE" | grep -o 'access_key=[^ ]*' | cut -d= -f2-)"
SECRET_KEY="$(printf '%s\n' "$CRED_LINE" | grep -o 'secret_key=[^ ]*' | cut -d= -f2-)"
if [ -z "$ACCESS_KEY" ] || [ -z "$SECRET_KEY" ]; then
  docker logs "$GATEWAY_NAME" || true
  echo "ERROR: zero-config gateway did not disclose generated root credentials" >&2
  exit 1
fi

# Byte-preserving round trip into the canonical bucket (no prior `mb`).
AUTH_HEADERS=(-H "x-maskura-access-key: $ACCESS_KEY" -H "x-maskura-secret-key: $SECRET_KEY")
curl --fail --silent --show-error \
  -X PUT \
  "${AUTH_HEADERS[@]}" \
  -H 'Content-Type: text/plain' \
  --data-binary "$INPUT" \
  "http://127.0.0.1:${GATEWAY_PORT}/maskura/object.txt" >/dev/null

READBACK="$(curl --fail --silent --show-error \
  "${AUTH_HEADERS[@]}" \
  "http://127.0.0.1:${GATEWAY_PORT}/maskura/object.txt")"
if [ "$READBACK" != "$INPUT" ]; then
  echo "ERROR: zero-config gateway did not preserve bytes on round trip" >&2
  exit 1
fi

# Restart against the same volume; the persisted credential and object must
# survive, and the credential must not be re-printed.
docker rm -f "$GATEWAY_NAME" >/dev/null
docker run -d --name "$GATEWAY_NAME" \
  -p "127.0.0.1:${GATEWAY_PORT}:9000" \
  -v "$LOCAL_VOLUME:/data" \
  "$IMAGE_REF" >/dev/null
ready=0
for _ in $(seq 1 30); do
  if curl --fail --silent "http://127.0.0.1:${GATEWAY_PORT}/ready" >/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  docker logs "$GATEWAY_NAME" || true
  echo "ERROR: zero-config gateway did not recover after restart" >&2
  exit 1
fi
if docker logs "$GATEWAY_NAME" 2>&1 | grep -q 'generated local root credentials'; then
  echo "ERROR: zero-config gateway re-disclosed the root secret on restart" >&2
  exit 1
fi
READBACK="$(curl --fail --silent --show-error \
  "${AUTH_HEADERS[@]}" \
  "http://127.0.0.1:${GATEWAY_PORT}/maskura/object.txt")"
if [ "$READBACK" != "$INPUT" ]; then
  echo "ERROR: zero-config gateway did not persist bytes across restart" >&2
  exit 1
fi

# Credential override: a fresh volume plus explicit MASKURA_ROOT_USER/PASSWORD.
docker rm -f "$GATEWAY_NAME" >/dev/null
docker volume rm "$LOCAL_VOLUME" >/dev/null
docker volume create "$LOCAL_VOLUME" >/dev/null
docker run -d --name "$GATEWAY_NAME" \
  -p "127.0.0.1:${GATEWAY_PORT}:9000" \
  -v "$LOCAL_VOLUME:/data" \
  -e MASKURA_ROOT_USER=smoke-root \
  -e MASKURA_ROOT_PASSWORD=smoke-secret \
  "$IMAGE_REF" >/dev/null
ready=0
for _ in $(seq 1 30); do
  if curl --fail --silent "http://127.0.0.1:${GATEWAY_PORT}/ready" >/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  docker logs "$GATEWAY_NAME" || true
  echo "ERROR: zero-config gateway with credential override did not become ready" >&2
  exit 1
fi
curl --fail --silent --show-error \
  -X PUT \
  -H "x-maskura-access-key: smoke-root" \
  -H "x-maskura-secret-key: smoke-secret" \
  -H 'Content-Type: text/plain' \
  --data-binary "$INPUT" \
  "http://127.0.0.1:${GATEWAY_PORT}/maskura/override.txt" >/dev/null

echo "release image zero-config local appliance smoke passed"
