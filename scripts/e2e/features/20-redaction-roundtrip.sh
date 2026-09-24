#!/usr/bin/env bash
# Feature: PII redaction round trip — upload the PII fixture through the
# gateway pipeline and verify the object stored in the local S3 backend is
# redacted with no plaintext leakage. This is the historical core of the e2e.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"
begin_feature "PII redaction round trip through local S3"

# Run the CLI fixture upload (demo mode, unauthenticated local gateway).
echo "--- Running maskura test upload ---"
MASKURA_GATEWAY_URL="$E2E_GW_URL" "$E2E_MASKURA_BIN" test upload

# Read the stored object straight out of the S3 backend (bypassing the
# gateway), signed with the appliance's fixed dev root credential.
echo "--- Reading stored object from the local S3 backend ---"
AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin \
    AWS_DEFAULT_REGION=us-east-1 \
    aws s3 cp --endpoint-url http://127.0.0.1:9000 \
    "s3://$E2E_BUCKET/test-upload.txt" - > "$E2E_TMP/20-readback.txt" 2>"$E2E_TMP/20-readback.err" || {
    cat "$E2E_TMP/20-readback.err" >&2
    fail "aws s3 cp could not read s3://$E2E_BUCKET/test-upload.txt from the local S3 backend"
}

for marker in "REDACTED_EMAIL" "REDACTED_SSN" "REDACTED_CARD"; do
    if grep -q "\[$marker\]" "$E2E_TMP/20-readback.txt"; then
        pass "[$marker] present in the stored object"
    else
        fail "[$marker] missing from the stored object"
    fi
done

assert_absent "$E2E_TMP/20-readback.txt" "jane.doe@example.com" "original email absent from the stored object"
assert_absent "$E2E_TMP/20-readback.txt" "4111111111111111" "original card absent from the stored object"

end_feature "PII redaction round trip"
