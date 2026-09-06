#!/usr/bin/env bash
# Maskura demo — one gateway, three ways to store a PII file.
# Recorded with: asciinema rec -c "bash maskura-demo.sh" maskura.cast
set -euo pipefail

EP="http://127.0.0.1:8791"
FILE="/tmp/customers.jsonl"
export AWS_ACCESS_KEY_ID=demo AWS_SECRET_ACCESS_KEY=demo AWS_EC2_METADATA_DISABLED=true

say() { printf '\n\033[1;36m%s\033[0m\n' "$*"; sleep 2; }

say "Object storage is everywhere. And now your AI agent can read all of it."
say "What if you could sit a filter in front of S3 — redact, encrypt, or pass through, field by field?"

# --- pull + run --------------------------------------------------------------
say "Let's pull the gateway. One container, no database, no cloud account."
docker pull ghcr.io/231self/maskura/maskura:latest

docker run --rm -p 127.0.0.1:8791:8080 \
  -e AUTH_DISABLED=true \
  -e MASKURA_STREAMING_WRITE_MODE=single \
  -e MASKURA_STREAMING_READ_MODE=passthrough \
  ghcr.io/231self/maskura/maskura:latest > /tmp/maskura-gw.log 2>&1 &
GW_PID=$!
trap 'kill $GW_PID 2>/dev/null || true' EXIT

AK=""; SK=""
for _ in $(seq 1 30); do
  AK="$(sed -n 's/^MASKURA_ACCESS_KEY=//p' /tmp/maskura-gw.log | tail -1 || true)"
  [ -n "$AK" ] && break
  sleep 1
done
SK="$(sed -n 's/^MASKURA_SECRET_KEY=//p' /tmp/maskura-gw.log | tail -1)"

say "It just handed us a demo access key. That's the whole auth story for this box."

printf '{"email":"alice@example.com","card":"4111111111111111","ssn":"123-45-6789","name":"Alice Doe","id":"c-001"}\n' > "$FILE"
printf '{"email":"bob@example.com","card":"5555555555554444","ssn":"765-43-2198","name":"Bob Smith","id":"c-002"}\n' >> "$FILE"

plugs() { curl -sS "$EP/dashboard/api/plugins"; }
enable()  { curl -sS -X PUT "$EP/dashboard/api/plugins/$(plugs | jq -r ".[]|select(.name==\"$1\")|.id")" -H 'Content-Type: application/json' -d '{"enabled":true}'  >/dev/null; }
disable() { curl -sS -X PUT "$EP/dashboard/api/plugins/$(plugs | jq -r ".[]|select(.name==\"$1\")|.id")" -H 'Content-Type: application/json' -d '{"enabled":false}' >/dev/null; }
disable_all() { for id in $(plugs | jq -r '.[].id'); do curl -sS -X PUT "$EP/dashboard/api/plugins/$id" -H 'Content-Type: application/json' -d '{"enabled":false}' >/dev/null; done; }

AWS="aws --endpoint-url $EP"

# --- 1) store: pure passthrough ---------------------------------------------
say "Mode one: just store it. I'm switching off every plugin, so Maskura is a dumb pipe."
disable_all

$AWS s3 cp "$FILE" s3://s4-local/store/customers.jsonl --content-type application/x-ndjson

say "Read it back — byte for byte what we sent."
$AWS s3 cp s3://s4-local/store/customers.jsonl -

# --- 2) store-redact: PII redaction -----------------------------------------
say "Mode two: redact on the way in. One plugin — the PII redactor."
enable pii-default

$AWS s3 cp "$FILE" s3://s4-local/redact/customers.jsonl --content-type application/x-ndjson

say "Same file, same bucket, different result. The stored object is already redacted."
$AWS s3 cp s3://s4-local/redact/customers.jsonl -

say "Emails, cards, SSNs — gone before they ever hit the bucket. Your agent can read all day and never see the real values."

# --- 3) store-encrypted-joinable: deterministic encryption -------------------
say "Mode three: encrypt, but keep it joinable. Redaction hides values; sometimes you still need to match on them."
disable pii-default
enable stable-encrypt.component

say "Stable encryption — same input always maps to the same ciphertext, so joins and dedup still work."
curl -sS -X PUT "$EP/s4-local/join/customers.jsonl" \
  -H "x-maskura-access-key: $AK" \
  -H "x-maskura-secret-key: $SK" \
  -H 'Content-Type: application/x-ndjson' \
  -H 'x-maskura-stable-fields: email,ssn' \
  --data-binary "@$FILE" -o /dev/null

$AWS s3 cp s3://s4-local/join/customers.jsonl -

say "Email and SSN are ciphertext now. Can't read them — but records with the same email still produce the same ciphertext, so you can join on it."

say "Three modes, one gateway, no rebuild. Redact it, encrypt it, or leave it alone — the pipeline decides."
say "That's Maskura: a privacy boundary between your agents and your S3 data."
