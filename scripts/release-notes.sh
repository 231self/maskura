#!/usr/bin/env bash
# Author release notes for a tag.
#
# The source material is GitHub's own PR-based "What's Changed" text for the
# tag (the same content `gh release create --generate-notes` would produce).
# When DEEPSEEK_API_KEY is set, that text is rewritten by the DeepSeek chat
# API into polished Markdown release notes. Any failure, timeout, or missing
# key silently falls back to the raw GitHub-generated notes so a release is
# never blocked.
#
# Usage:
#   scripts/release-notes.sh <tag> [output-file]
#
# Environment:
#   GH_TOKEN             GitHub token for the generate-notes API (or gh auth).
#   GITHUB_REPOSITORY    owner/repo (default: 231self/maskura).
#   DEEPSEEK_API_KEY     optional; enables the LLM rewrite.
#   DEEPSEEK_MODEL       optional; default: deepseek-chat.
#   DEEPSEEK_API_URL     optional; default: https://api.deepseek.com/chat/completions.
#   PREVIOUS_TAG         optional; pins the comparison base.

set -euo pipefail

usage() {
  echo "usage: $0 <tag> [output-file]" >&2
}

TAG="${1:-}"
OUT="${2:-release-notes.md}"
if [ -z "$TAG" ]; then
  usage
  exit 2
fi

REPO="${GITHUB_REPOSITORY:-231self/maskura}"
MODEL="${DEEPSEEK_MODEL:-deepseek-chat}"
API_URL="${DEEPSEEK_API_URL:-https://api.deepseek.com/chat/completions}"

for bin in gh jq; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "ERROR: $bin not found" >&2
    exit 1
  fi
done

# 1. GitHub's generated PR notes: the LLM input and the fallback body.
generate_args=(--method POST "repos/$REPO/releases/generate-notes" -f "tag_name=$TAG")
if [ -n "${PREVIOUS_TAG:-}" ]; then
  generate_args+=(-f "previous_tag_name=$PREVIOUS_TAG")
fi

raw_notes="$(gh api "${generate_args[@]}" -q .body 2>/dev/null || true)"
if [ -z "$raw_notes" ]; then
  echo "WARN: GitHub generate-notes returned no content; using a minimal fallback" >&2
  raw_notes="Release $TAG"
fi

# 2. Optional DeepSeek rewrite.
notes="$raw_notes"
source_used="github-generated"

if [ -z "${DEEPSEEK_API_KEY:-}" ]; then
  echo "INFO: DEEPSEEK_API_KEY not set; using GitHub-generated notes" >&2
elif ! command -v curl >/dev/null 2>&1; then
  echo "WARN: curl not found; using GitHub-generated notes" >&2
else
  system_prompt="You are the release-notes writer for Maskura, an S3-compatible object gateway that cleanses PII. Rewrite the provided merged-PR list into professional GitHub release notes in Markdown. Start with a single-sentence summary of the release. Then a '## Highlights' section as a bullet list of user-visible changes, grouping related items and omitting pure internal chores unless they are notable. Include '## Breaking changes' only if any exist among the input. Include '## Upgrade notes' only if an action is required. Do not invent features, versions, dates, or links, and do not drop the PR references present in the input. Output only the Markdown body: no top-level title heading (the release title is separate), no preamble, no code fences around the whole output."

  user_prompt="Release tag: $TAG

Raw merged-PR notes from GitHub:
$raw_notes"

  payload="$(jq -n \
    --arg model "$MODEL" \
    --arg system "$system_prompt" \
    --arg user "$user_prompt" \
    '{model: $model, temperature: 0.3, messages: [{role: "system", content: $system}, {role: "user", content: $user}]}')"

  response="$(curl -sS --max-time 90 \
    -H "Authorization: Bearer $DEEPSEEK_API_KEY" \
    -H 'Content-Type: application/json' \
    -d "$payload" \
    "$API_URL" 2>/dev/null || true)"

  content="$(printf '%s' "$response" | jq -r '.choices[0].message.content // empty' 2>/dev/null || true)"
  if [ -n "$content" ]; then
    notes="$content"
    source_used="deepseek:$MODEL"
  else
    echo "WARN: DeepSeek returned no usable content; falling back to GitHub-generated notes" >&2
  fi
fi

printf '%s\n' "$notes" > "$OUT"
echo "Wrote release notes to $OUT (source: $source_used)"
