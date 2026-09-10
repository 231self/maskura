#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT

printf '%s\n' '## Highlights' '- Safe release notes' > "$test_dir/notes.md"
payload="$(
  GITHUB_REPOSITORY=231self/maskura \
    bash "$repo_root/scripts/post-release-discord.sh" \
      v1.2.3 "$test_dir/notes.md" --dry-run 2> "$test_dir/dry-run.log"
)"

jq -e '
  .allowed_mentions.parse == []
  and .embeds[0].title == "Maskura v1.2.3"
  and .embeds[0].url == "https://github.com/231self/maskura/releases/tag/v1.2.3"
  and .components[0].components[0].label == "View on GitHub"
' <<< "$payload" >/dev/null
grep -q 'payload built, not posted' "$test_dir/dry-run.log"

awk 'BEGIN { for (i = 0; i < 5000; i++) printf "x" }' > "$test_dir/long-notes.md"
long_payload="$(
  GITHUB_REPOSITORY=231self/maskura \
    bash "$repo_root/scripts/post-release-discord.sh" \
      v1.2.3 "$test_dir/long-notes.md" --dry-run 2>/dev/null
)"
jq -e '
  (.embeds[0].description | length) <= 4096
  and (.embeds[0].description | endswith(
    "…[Read the full notes](https://github.com/231self/maskura/releases/tag/v1.2.3)"
  ))
' <<< "$long_payload" >/dev/null

mkdir "$test_dir/bin"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  "printf '%s\\n' '## What changed' '- fixed #1'" \
  > "$test_dir/bin/gh"
chmod +x "$test_dir/bin/gh"

PATH="$test_dir/bin:$PATH" \
  GITHUB_REPOSITORY=231self/maskura \
  bash "$repo_root/scripts/release-notes.sh" \
    v1.2.3 "$test_dir/generated-notes.md" 2> "$test_dir/release-notes.log"

grep -q '^## What changed$' "$test_dir/generated-notes.md"
grep -q 'using GitHub-generated notes' "$test_dir/release-notes.log"

if bash "$repo_root/scripts/post-release-discord.sh" \
  v1.2.3 "$test_dir/missing.md" --dry-run >/dev/null 2>&1; then
  echo 'expected a missing notes file to fail' >&2
  exit 1
fi

echo 'Release notification tests passed'
