set shell := ["bash", "-euo", "pipefail", "-c"]

export RUSTFLAGS := "-D warnings"

_default:
  @just --list

# Fast format + clippy (used by pre-commit hook)
check-fast: check-fmt check-lint
  @echo "Fast checks passed"

# Full check: format, lint, build filters, tests
check: check-fmt check-lint build-plugins test
  @echo "All checks passed"

check-fmt:
  cargo fmt --check

check-lint:
  cargo clippy --locked --all-targets -- -D warnings

# Keep the public evidence entry points executable and parseable without
# starting Docker or reaching the network.
check-evidence: check-release check-plugin-contract check-public-copy test-release-notifications
  bash -n examples/prove-maskura.sh examples/local-quickstart.sh examples/maskura-demo.sh scripts/bench-plugins.sh scripts/release-notes.sh scripts/post-release-discord.sh scripts/test-release-notifications.sh
  python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("examples/python-hybrid-roundtrip.py").read_text())'

test-release-notifications:
  bash scripts/test-release-notifications.sh

check-plugin-contract:
  python3 scripts/check-plugin-contract.py

check-public-copy:
  python3 scripts/check-public-copy.py

# Ensure every public version surface agrees before a release tag can be cut.
check-release:
  python3 scripts/check-release-contract.py

test:
  cargo test --locked --workspace

build-plugins:
  bash scripts/build-plugins.sh

deny:
  cargo deny check

audit:
  bash scripts/audit-rust.sh

# Audit every shipped dependency ecosystem and verify immutable build inputs.
audit-dependencies:
  bash scripts/audit-dependencies.sh

# Canonical fast local gate before publishing a jj bookmark. The protected CI
# remains responsible for the long Wasm, SDK, database, interop, and E2E suites.
pre-push: check-fast check-evidence audit-dependencies
  @echo "Pre-push checks passed"

# Safe publishing path for this jj repository. Extra arguments are passed to jj.
push *args: pre-push
  jj git push {{args}}

# Meta-linter: runs all static checks + Rust dependency policy
lint: check-fmt check-lint deny
  @echo "Meta-lint passed"

# Full lint including security audit and tests
lint-full: lint audit test
  @echo "Full lint passed"

# End-to-end validation with MinIO (requires Docker)
e2e:
  bash scripts/e2e-local.sh

# Streaming data-plane focused suite (the gateway crate is the streaming plane)
test-streaming:
  cargo test -p maskura-gateway

# Streaming end-to-end against MinIO (direct S3 sink; requires Docker)
e2e-streaming:
  bash scripts/e2e-local.sh

# Unmodified AWS CLI + boto3 interop (requires awscli/boto3 on PATH)
interop:
  cargo test -p maskura-gateway --test s3_frontdoor_test available_aws_cli_and_boto3_interoperate

# Public, black-box evidence: AWS CLI redaction, runtime Wasm import, and the
# Python X25519 + ML-KEM-768 encrypted round trip. Optional mode: redaction,
# plugin, or python (default: all).
proof *args:
  bash examples/prove-maskura.sh {{args}}

# Fault-injection suite: multipart staging fault matrix + streaming failure paths
fault-streaming:
  cargo test -p maskura-gateway multipart_staging::tests
  cargo test -p maskura-gateway --test s3_frontdoor_test streaming_put_limit_failure_has_no_partial_visibility
  cargo test -p maskura-gateway --test s3_frontdoor_test unsafe_transformed_failures_never_disclose_early_late_or_finish_output
  cargo test -p maskura-gateway --test s3_frontdoor_test valid_sigv4_seed_polls_then_rejects_payload_hash_mismatch

# Fixed-RSS memory bound (1 GiB source; asserts allocation is object-size-independent)
bench-rss:
  cargo test -p maskura-gateway --test streaming_rss -- --nocapture

# Micro-benchmark: per-plugin Wasm fuel, latency, and expansion (Tier 1)
bench-plugins: build-plugins
  bash scripts/bench-plugins.sh

# Soak: high-case-count property tests + repeated streaming round-trips
soak-streaming:
  PROPTEST_CASES=10000 cargo test -p maskura-gateway --test property --test record_decoder
  MASKURA_SOAK_ITERATIONS=500 cargo test -p maskura-gateway --test s3_frontdoor_test soak_streaming_roundtrip_holds_under_repetition -- --ignored

# Release image smoke (boot smoke against the built OCI image)
release-smoke IMAGE_REF:
  bash scripts/release-image-smoke.sh {{IMAGE_REF}}

# Run the CI workflow locally with act (no GitHub minutes)
ci-local:
  act -W .github/workflows/ci.yml

# Run the release workflow locally with act (tag event; GHCR push needs a
# token with packages scope)
release-local:
  act -W .github/workflows/release.yml -e act/event-tag.json

# Build + test in a dagger container (cargo registry + target cached)
build-local:
  dagger call ci

# Build the deploy image locally (dagger)
image-local:
  dagger call image

# Build + publish the deploy image to GHCR (needs: docker login ghcr.io once)
publish-local TAG='latest':
  dagger call publish --tag={{TAG}}

# Start local dev environment (Docker Compose + local S3 appliance + gateway)
dev-up: build-plugins
  docker compose -f local/docker-compose.yml up -d --build --wait s3 gateway
  echo "Local dev environment ready:"
  echo "  Local S3:   http://localhost:9000 (maskura appliance, root: minioadmin)"
  echo "  Gateway:   http://localhost:8080/health"
  AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin AWS_DEFAULT_REGION=us-east-1 aws s3api list-buckets --endpoint-url http://localhost:9000 --query "Buckets[?Name=='maskura-local'] | length(@)" --output text | grep -qx 1 || AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin AWS_DEFAULT_REGION=us-east-1 aws s3api create-bucket --endpoint-url http://localhost:9000 --bucket maskura-local
  echo "  S3 bucket: maskura-local (created)"

# Stop local dev environment
dev-down:
  docker compose -f local/docker-compose.yml down

# Full dev flow: start infra + run E2E test
dev: dev-up
  cargo run -p maskura -- test upload

# Generate client SDKs from OpenAPI spec (requires Docker)
# Produces sdks/python/ and sdks/typescript/
build-sdks: build-plugins
  bash scripts/generate-sdks.sh
