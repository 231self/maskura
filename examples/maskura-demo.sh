#!/usr/bin/env bash
set -euo pipefail

EP="http://127.0.0.1:8791"
IMG="ghcr.io/231self/maskura/maskura:latest"
NAME="maskura-demo"
VOLUME="maskura-demo-data"
F="/tmp/customers.jsonl"
export AWS_ACCESS_KEY_ID=demo AWS_SECRET_ACCESS_KEY=demo AWS_EC2_METADATA_DISABLED=true

docker rm -f "$NAME" >/dev/null 2>&1 || true

comment() { printf '\n\033[90m# %s\033[0m\n' "$*"; sleep 1; }
cmd()    { printf '\033[1;32m$\033[0m \033[1m%s\033[0m\n' "$*"; "$@"; }
show()   { printf '\033[1;32m$\033[0m \033[1m%s\033[0m\n' "$*"; }

plugs()  { curl -s "$EP/dashboard/api/plugins"; }
pipeline() {
  local target="$1"
  for id in $(plugs | jq -r '.[].id'); do
    curl -s -X PUT "$EP/dashboard/api/plugins/$id" -H 'Content-Type: application/json' -d '{"enabled":false}' >/dev/null
  done
  if [ "$target" != none ]; then
    local id; id=$(plugs | jq -r ".[]|select(.name==\"$target\")|.id")
    curl -s -X PUT "$EP/dashboard/api/plugins/$id" -H 'Content-Type: application/json' -d '{"enabled":true}' >/dev/null
  fi
}

comment "pull the gateway image"
cmd docker pull "$IMG"

comment "run the Maskura container — local S3 API, durable FileStore"
cmd docker run --rm -d --name "$NAME" -p 127.0.0.1:8791:8080 \
  -v "$VOLUME:/data" \
  -e AUTH_DISABLED=true \
  -e MASKURA_KEYS_FILE=/data/keys.json \
  -e MASKURA_STORAGE_MODE=local \
  -e MASKURA_LOCAL_STORAGE_DIR=/data \
  -e MASKURA_MULTIPART_MODE=staged \
  -e MASKURA_STREAMING_READ_MODE=passthrough "$IMG"

for _ in $(seq 1 30); do curl -s -m 2 "$EP/health" >/dev/null 2>&1 && break; sleep 1; done

comment "it prints a demo key at startup — grab it"
show "docker logs $NAME 2>&1 | grep -E 'MASKURA_(ACCESS|SECRET)_KEY'"
docker logs "$NAME" 2>&1 | grep -E 'MASKURA_(ACCESS|SECRET)_KEY'
AK=$(docker logs "$NAME" 2>&1 | sed -n 's/^MASKURA_ACCESS_KEY=//p' | tail -1)
SK=$(docker logs "$NAME" 2>&1 | sed -n 's/^MASKURA_SECRET_KEY=//p' | tail -1)

printf '{"email":"alice@example.com","card":"4111111111111111","ssn":"123-45-6789","name":"Alice"}\n'  > "$F"
printf '{"email":"bob@example.com","card":"5555555555554444","ssn":"765-43-2198","name":"Bob"}\n'    >> "$F"
comment "the file we're pushing through, three ways"
cmd cat "$F"

comment "mode 1 — no plugins, straight passthrough"
cmd pipeline none
cmd aws s3 --endpoint-url "$EP" cp "$F" s3://s4-local/store/customers.jsonl --content-type application/x-ndjson
comment "read it back — untouched"
cmd aws s3 --endpoint-url "$EP" cp s3://s4-local/store/customers.jsonl -

comment "mode 2 — turn on the PII redactor, push the same file"
cmd pipeline pii-default
cmd aws s3 --endpoint-url "$EP" cp "$F" s3://s4-local/redact/customers.jsonl --content-type application/x-ndjson
comment "read it back — redacted"
cmd aws s3 --endpoint-url "$EP" cp s3://s4-local/redact/customers.jsonl -

comment "mode 3 — stable-encrypt (deterministic), fields email + ssn"
cmd pipeline stable-encrypt.component
cmd curl -s -X PUT "$EP/s4-local/join/customers.jsonl" \
  -H "x-maskura-access-key: $AK" \
  -H "x-maskura-secret-key: $SK" \
  -H 'Content-Type: application/x-ndjson' \
  -H 'x-maskura-stable-fields: email,ssn' \
  --data-binary "@$F"
comment "read it back — email and ssn are ciphertext; same value = same ciphertext"
cmd aws s3 --endpoint-url "$EP" cp s3://s4-local/join/customers.jsonl -

docker rm -f "$NAME" >/dev/null 2>&1 || true
comment "the Docker volume keeps local objects and multipart state durable"
show "docker volume inspect $VOLUME"
