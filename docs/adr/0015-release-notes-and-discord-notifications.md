# ADR 0015: Release orchestration, authored notes, and Discord announcements

- Status: Accepted
- Date: 2026-09-10

## Context

Releases are cut from `main` by `.github/workflows/release.yml` on `v*` tags.
The version-bump workflow originally used a personal access token to push the
tag so GitHub would start the release workflow as a second event. That added a
maintainer-owned credential whose expiry or permission drift could stop all
releases after the code had already merged.
GitHub Releases previously used GitHub's raw list of merged-PR titles. That
text is accurate but reads as an internal changelog: it has no summary,
grouping, or upgrade guidance, so it is a weak official note for users.

There was also no channel for telling users that a version shipped. An earlier
proposal used the Reddit API to post to r/maskura, but Reddit requires a
registered OAuth application and either a stored account password or a
one-time refresh-token exchange, plus a moderator or approved-submitter
relationship for the posting account. For a one-way release notification,
that is a disproportionate credential and trust surface. A Discord Incoming
Webhook needs a single URL, no bot, no OAuth, and no user account in the loop.

## Decision

Release notes are authored in CI with no required human step:

1. `scripts/release-notes.sh` fetches GitHub's PR-based generated notes for the
   tag through the `releases/generate-notes` API. This reuses GitHub's merged-PR
   discovery instead of reimplementing it.
2. When `DEEPSEEK_API_KEY` is present, that text is rewritten by the DeepSeek
   chat API (`deepseek-chat`, overridable with `DEEPSEEK_MODEL`) into a summary
   plus grouped highlights, with breaking-change and upgrade sections only
   when the input supports them. The prompt forbids inventing features,
   versions, dates, or links and requires retaining input PR references.
3. On a missing key, network error, timeout, non-success status, or empty
   response, the script falls back to GitHub's generated notes. The LLM is an
   optional editorial pass, never a release dependency.

The resulting notes become both the GitHub Release body and the source of the
announcement.

Announcements go to Discord through an Incoming Webhook
(`DISCORD_WEBHOOK_URL`). `scripts/post-release-discord.sh` builds a rich embed
with the title, notes, release link, timestamp, and footer, plus a "View on
GitHub" button. It truncates notes past Discord's 4096-character embed limit
and links to the full release. Mentions are disabled in the webhook payload.
The automatic step is gated on the release having been created in that run and
is non-fatal, so a webhook problem never blocks a release and a workflow rerun
does not double-post.

`.github/workflows/announce-release.yml` provides a manual replay for an
already-published version, with a dry-run preview. It validates the tag input
and reads the canonical release body from GitHub before posting.

`tag-on-version-bump.yml` creates the immutable tag with the scoped
`GITHUB_TOKEN`, then invokes `release.yml` through `workflow_call` with that tag
as an explicit input. GitHub does not fan out a new workflow from a tag pushed
with `GITHUB_TOKEN`; the reusable-workflow call deliberately avoids depending
on that behavior. Directly pushed `v*` tags remain supported by the release
workflow's existing `push.tags` trigger.

The two optional integration secrets (`DEEPSEEK_API_KEY` and
`DISCORD_WEBHOOK_URL`) are configured as GitHub Actions repository secrets and
never appear in the repository. No personal access token is required for
tagging or release orchestration. When `DEEPSEEK_API_KEY` is absent, releases
ship with GitHub-generated notes.

Reddit publishing is deferred, not rejected; the same notes and secrets
pattern can drive it later if a public community channel is wanted.

## Consequences

- Every release gets a summarized note with no required manual authoring, and
  users can be notified where they already are.
- Notes are non-deterministic across runs and depend on an external LLM
  provider. The fallback makes this a quality risk rather than an availability
  risk; cost is bounded to one request per release with a 90-second timeout.
- A Discord webhook is a bearer credential that can post to its channel. It is
  stored only as a GitHub Actions secret and rotated in the secret store.
- Automatic tagging and release execution use short-lived, repository-scoped
  GitHub tokens; a maintainer PAT cannot expire underneath the release path.
- Discord announcement failures are non-fatal and may require a manual replay;
  the release itself remains available and verifiable.
- No `CHANGELOG.md` is committed; GitHub Releases remain the canonical,
  per-version record.
