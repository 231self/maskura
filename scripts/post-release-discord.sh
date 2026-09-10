#!/usr/bin/env bash
# Post a release to a Discord channel through an Incoming Webhook.
#
# Builds a rich embed (title, notes, release link, timestamp, footer) plus a
# "View on GitHub" link button. Notes longer than Discord's 4096-character
# embed limit are truncated with a link to the full release.
#
# Usage:
#   scripts/post-release-discord.sh <tag> <notes-file> [--dry-run]
#
# Environment:
#   DISCORD_WEBHOOK_URL   required unless --dry-run.
#   GITHUB_REPOSITORY     owner/repo (default: 231self/maskura).

set -euo pipefail

usage() {
  echo "usage: $0 <tag> <notes-file> [--dry-run]" >&2
}

TAG=""
NOTES=""
DRY_RUN=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      if [ -z "$TAG" ]; then
        TAG="$arg"
      elif [ -z "$NOTES" ]; then
        NOTES="$arg"
      else
        usage
        exit 2
      fi
      ;;
  esac
done

if [ -z "$TAG" ] || [ -z "$NOTES" ]; then
  usage
  exit 2
fi
if [ ! -f "$NOTES" ]; then
  echo "ERROR: notes file not found: $NOTES" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq not found" >&2
  exit 1
fi

REPO="${GITHUB_REPOSITORY:-231self/maskura}"
RELEASE_URL="https://github.com/$REPO/releases/tag/$TAG"
TITLE="Maskura $TAG"
MAX_DESCRIPTION=4096

body="$(cat "$NOTES")"
suffix="$(printf '\n\n…[Read the full notes](%s)' "$RELEASE_URL")"

# Character length, not bytes: Discord counts characters.
if [ "$(printf '%s' "$body" | wc -m | tr -d ' ')" -gt "$MAX_DESCRIPTION" ]; then
  suffix_len="$(printf '%s' "$suffix" | wc -m | tr -d ' ')"
  keep=$((MAX_DESCRIPTION - suffix_len))
  truncated="$(printf '%s' "$body" | cut -c1-"$keep")"
  description="${truncated}${suffix}"
else
  description="$body"
fi

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

payload="$(jq -n \
  --arg title "$TITLE" \
  --arg url "$RELEASE_URL" \
  --arg desc "$description" \
  --arg ts "$timestamp" \
  --arg footer "Maskura release $TAG" \
  '{
    allowed_mentions: {parse: []},
    embeds: [{
      title: $title,
      url: $url,
      description: $desc,
      color: 4177232,
      timestamp: $ts,
      footer: {text: $footer}
    }],
    components: [{
      type: 1,
      components: [{
        type: 2,
        style: 5,
        label: "View on GitHub",
        url: $url
      }]
    }]
  }')"

if [ "$DRY_RUN" = true ]; then
  printf '%s\n' "$payload"
  echo "dry-run: payload built, not posted to Discord" >&2
  exit 0
fi

if [ -z "${DISCORD_WEBHOOK_URL:-}" ]; then
  echo "ERROR: DISCORD_WEBHOOK_URL not set" >&2
  exit 1
fi

status="$(curl -sS --max-time 30 -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d "$payload" \
  "$DISCORD_WEBHOOK_URL")"

case "$status" in
  2*)
    echo "Posted $TAG to Discord (HTTP $status)"
    ;;
  *)
    echo "ERROR: Discord webhook returned HTTP $status" >&2
    exit 1
    ;;
esac
