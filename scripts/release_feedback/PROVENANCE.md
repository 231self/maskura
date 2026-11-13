# Packaged FileStore release feedback regressions

SPDX-License-Identifier: Apache-2.0. These sources use the repository's Apache-2.0
license. They are portable repository code with normal imports: no temp paths,
AST inheritance or native-library attestation framework. The versioning rows
require the installed, unmodified AWS CLI; credentials are passed only through
the isolated captured-child environment.

## Reviewed origins

- `cases.py` preserves the reviewed 29-case FileStore contract from the original
  pure `filestore_cases.py`, SHA256
  `10313f66163bd399447520467732948e529920a627b29a8d0bfca8bd50f29d55`.
  Its one behavioral correction is the accepted v2 representation oracle:
  Content-Encoding must be **absent**, not `identity`. Original v2 case wrapper:
  `6132c394916ba30e0efc16f7e4fc6e3a2c569afe6fb233b6d3358395953ef454`.
- `transport.py` directly flattens the reviewed absolute nonblocking HTTP/stdlib
  parser algorithm from v2 runtime SHA256
  `bb539db39627b7d4124843c6fa458cde45176dfd695dde486bad58e28ea0111f`, and
  captured-child polling/reaping, permanent ESRCH retirement, sticky command
  failures and the one shared cleanup reserve from v3 runtime SHA256
  `5f0afa7b47273a59bc98c805c7e7d5e034467e87e7b19729241cfb09923d33a3`.
  The portable `Budget` explicitly combines those nested ceilings/shared reserve;
  imports and instance setup replace the old temp-handoff inheritance. The actual
  ImageIO guard force-closes an inflight socket before nested command cleanup.
- The in-memory fixture retains all 18 reviewed case mutations, with provenance
  from original `test_contract.py` SHA256
  `fff7ec63327e145d3e8c5e4a19e7d6ecfbf37afe1abb9cdd2f2623ffc63fd5ac`.
  They test real case/oracle logic, not image acceptance.
- The new signer follows `crates/gateway/src/sigv4.rs` and
  `crates/gateway/src/integrity.rs`, specifically `signed_chunk`,
  `signed_and_unsigned_trailers_are_verified`, and the frontdoor
  `signed_request_with_signable` Single/Disabled path settings. It uses ordinary
  stdlib HMAC/SHA256, real signed seed + payload/zero-chunk + trailer signatures.
  The independent test parser reconstructs canonical seeds, derives keys, parses
  frames and verifies every HMAC without calling signer internals. It also verifies
  binary/empty payloads, tampering and truncations.

No predecessor source/evidence is changed or loaded at runtime by this package.

## Scope: 29 core rows + 2 signed rows + 4 versioning SDK rows

`release-feedback.py --execute` always uses the actual loaded image ID. There is
no fake/mock transport option in the executable. The runner tests the packaged
entrypoint's local FileStore profile with synthetic credentials and objects only.

The first 29 rows cover runtime version, metadata/type/encoding GET+HEAD+LIST,
invalid credentials without mutation, overwrite metadata replacement/clearing,
all seven reserved metadata keys (PUT and multipart initiation), all four multipart
type combinations, bad/malformed Content-MD5 before deletion, per-key mixed/repeat/
quiet DeleteObjects outcomes, and actual restart/persistence/port re-resolution.

Two additional rows are mandatory:

1. Signed aws-chunked DeleteObjects: bad-MD5/good-checksum, good-MD5/bad-checksum,
   bad/bad all return BadDigest and preserve both objects and list sizes before
   any successful signed deletion. Every checksum trailer, including a deliberately
   wrong checksum value, has a valid trailer HMAC. Then good/good must actually
   delete both objects. An always-rejecting or side-effects-before-validation
   implementation cannot pass.
2. Signed decoded representation cleanup: PUT in signed payload and signed trailer
   modes, plus a signed multipart part. GET/HEAD/LIST must expose decoded bytes,
   decoded lengths, original client metadata/type, **no transport Content-Encoding**,
   no remaining completed upload, and stable data after an actual container restart.

Multipart initiation in this row uses ordinary `c.request` without aws-chunked
transport encoding; **only UploadPart is signed**, not CreateMultipartUpload.
It therefore does not exercise signed multipart-initiation decoding or transport
encoding cleanup in the initiation-time metadata snapshot. That behavior remains
unqualified and is explicitly excluded as
`signed-multipart-initiation-decoding-snapshot-cleanup` in runner reports. Streaming
initiation may be unsupported/rejected before staging; no successful streaming-init
requirement or production decoder change is introduced by these regressions.
The ordinary multipart-initiation metadata/default-Content-Type cases remain
mandatory, as do all signed PUT/UploadPart/restart and MD5 cross-negative assertions.

Signed requests use only SigV4 Authorization, not raw x-maskura credential headers,
AUTH_DISABLED, fake signatures, UNSIGNED streaming, TLS exemptions or test routes.
The core-only oracle's historical `unimplemented` list is superseded **only for
the narrow operations above after their actual execution succeeds**, not for signed
multipart initiation or all request formats. A passing receipt requires
exactly all 35 rows plus all cleanup facts; `full_feedback_matrix_passed=false`.

The four `versioning.py` rows invoke the unmodified AWS CLI through the existing
captured-child boundary: durable Enabled state and exact A/B GET/HEAD after
restart (plus legacy null reads); multipart completion/replay behind an overwrite
and restart without duplicate history; markers and Suspended/null replacement;
and paired listing pagination, URL-encoded delimiter listing, same-key batch
version deletion and empty-bucket deletion. They use a separate disposable bucket
inside the same owned volume. CLI deadlines are 15s under the unchanged campaign
clock, with 2s connect/8s read limits and one SDK attempt. The CLI resolves the
current owned relay port on every call. No caller secrets, provider credentials,
raw CLI output, object identities or content enter reports.
Each SDK process also has a 128-block file-size limit (at most 128 KiB on the
supported shells), so unexpected GET output cannot fill the host filesystem
between periodic attempt-directory checks. The shell uses `exec`, retaining the
existing captured-child process identity and cleanup rules.

| Surface | Claim by this runner |
|---|---|
| Packaged FileStore core + signed + versioning SDK rows | Qualified only if the actual image run passes |
| Signed multipart-initiation decoding/snapshot cleanup | Not exercised; only UploadPart is signed, with ordinary initiation |
| Memory / direct S3 / managed / Postgres | Not exercised |
| Protected pipeline / official encryption | Existing `prove-maskura.sh` remains a separate required gate |
| Kill/crash process recovery / non-versioning unmodified SDK / reporter environment | Not exercised by this runner |
| Full feedback matrix or 13 managed cases | Never claimed |

No TEST component is installed. The image must contain exactly the fourteen regular
official component/manifest files and no extra entries/symlinks in `/app/components`.
The packaged binary's ELF machine must match the native Linux runner and Docker
daemon/image architecture. Existing protected proof and security/SQLite/release
contract checks are not replaced or removed.

## Portable bounds and ownership

- One 1800s campaign clock, 1780s normal work, original 1200s stage ceiling, HTTP8
  absolute deadline across connect/write/header/body and guard work. HTTP parsing
  is `http.client` over the bounded nonblocking adapter; no HTTP worker outlives it.
- One shared <=20s cleanup reserve, clipped to original whole deadline, never
  renewed per command. Captured Popen direct-child reap, group ESRCH and reader
  joins/retirement are independent requirements. An expired measurement does not
  prevent unconditional polling/reaping during cleanup. Signals are cooperative
  and sticky so cancellation cannot interrupt Popen's return-to-capture gap.
- CI uses its isolated Linux runner and does not wait on a shared local lock.
  Shared-daemon local Linux use must explicitly pass `--lock-existing PATH`;
  it opens only an existing owned regular file, NOFOLLOW, nonblocking bounded
  <=600s wait using the same campaign clock. No Mac path or automatic lock creation.
- Actual host free-space floors are 12 GiB on the private attempt filesystem and
  the **local Linux daemon's DockerRootDir filesystem**, before image creation and
  periodically during work. During optional pre-daemon local lock waiting only
  the attempt floor is known. DockerRootDir must subsequently resolve on that host;
  no Docker Desktop/VM free-byte assertion or unavailable-path fallback is made.
- Owned `/data` guard: `docker exec` into only the verified owned container, using
  existing Debian `find` to return sizes only, never names or payloads. Count <=4096
  entries and sum <=64 MiB. Directory apparent sizes are included conservatively;
  no reduction of the store bound. Projected Docker `.SizeRw` <=64 MiB separately.
  All inventory/ownership/find/size work shares one aggregate 2s monitor ceiling.
  Missing tools/permissions/invalid metadata fail closed, not a fake monitor pass.
- Private host attempt <=1 MiB/128 entries; request/response payloads <=1 MiB;
  captured command output <=64 KiB. Container <=2 CPUs/1 GiB/256 PIDs, no core dumps,
  internal owned network, an explicitly owned numeric loopback relay, fresh HOME/TMP/Docker config.
  No inherited customer/provider/proxy/auth env or container output/log bodies.
- Docker 28 does not publish host ports for an internal network. The connector
  therefore removes `-p`, not `--internal`: an in-process TCP relay binds only
  kernel-allocated `127.0.0.1:0` (at most eight attempts, excluding default database
  ports). Before any connection, projected container/network metadata must match
  the existing verified IDs, labels and births, one exact owned bridge network,
  a shared EndpointID, and one numeric RFC1918 IPv4 address in its owned IPAM
  subnet. Extra networks/endpoints, host publications, IPv6, global/loopback/link-
  local destinations and DNS/proxy targets are rejected. The destination port is
  always 9000. Empty Docker port metadata is expected, but is never connector or
  qualification evidence by itself. Endpoint drift is checked inside the existing
  aggregate 2s store monitor, without extending that ceiling.
- The relay uses one tracked nonblocking selector worker, backlog/concurrency <=8,
  <=64 KiB queued per direction/connection and <=2 MiB wire bytes per direction
  (<=4 MiB total/connection). Backpressure disables reads when a queue is full.
  Every connection has an absolute <=25s deadline clipped to the original work/
  stage deadline; activity cannot renew it. The HTTP client's existing absolute
  8s deadline and 2 MiB receive-wire bound remain unchanged. Relay failures are
  sticky closed codes, never payloads or exception text. Listener, channels,
  selector and worker are explicitly retired under the existing shared cleanup
  reserve; no-active-handles and no-sticky-failure cleanup facts include them.
  Restart closes the old relay, proves exact ECONNREFUSED on its allocated ports,
  re-verifies ownership and the new endpoint, then allocates a fresh relay. Every
  allocated relay port is also checked for exact kernel refusal at final cleanup.
  Fake I/O tests do not establish actual TCP or packaged-image qualification.
- Resources have random private ownership labels. Creation intent is recorded
  before the create command. Exact successful inventory requires exit0 and parses
  projected names/IDs; Docker exit1/errors are not absence. Before deletion, exact
  identity, creation time and ownership label must match; post-delete inventory
  must succeed and be empty for that exact name. No global prune/name scan/kill.
- Socket closure means exact kernel ECONNREFUSED only. Open, permission, timeout
  and unknown errors are not closure. Cleanup facts, including reserve expiry,
  are required by the receipt parser; failed/interrupted work cannot become green.

`find` and `od` are existing Debian base utilities used inside the owned packaged
container. No image dependency installation or new workflow action is added; if
the packaging lacks them the real gate fails and that concrete issue must be fixed,
not silently skipped. Source preparation has not run these image checks.

## Required release path

The existing required `ci.yml:release-image-smoke` job is a native matrix: amd64 on
`ubuntu-24.04` / `linux/amd64`, arm64 on `ubuntu-24.04-arm` / `linux/arm64`, without
QEMU. Each leg copies and version-checks its native CLI filename, loads its labelled
architecture-suffixed candidate, resolves the actual ID once, runs the existing
smoke and the same 31-row regression runner with its matching `--arch`, then the
unchanged protected proof by that ID. Both legs must succeed through the unchanged
aggregate required `check` dependency before merge/tag publication; post-tag release
ARM64 replay alone is not pre-tag qualification. The 90-minute per-leg job budget,
two Cargo jobs and HTTP8/1800s regression limits are unchanged. New cheap tests run
in existing `fmt`, including native runner/platform/CLI/architecture binding and
failure controls for missing ARM64 or repeated amd64 hardcoding. These are workflow
requirements, not evidence of any actual candidate execution at authoring time.

Each native release build runs boot smoke and the 31-row gate before push. The push
must still name that exact local config ID. Push explicitly selects the native
platform (modern Docker API >=1.46, already provided by the Linux CI toolchain),
so a containerd multi-platform store cannot substitute an index for a child.
The existing canonical GitHub provenance attestation remains required. Its successful push digest is captured
from bounded Docker push output, not re-resolved from a mutable arch tag. On the
same native architecture runner, explicit pull by that digest is followed by a
local-ID/RepoDigest/platform/label-bound replay; every test container is pull=never.
The child raw manifest digest and config ID are checked before sealing a receipt.

Both receipts bind source SHA/version/native arch/config ID/child digest/harness
SHA, all 31 cases, pre-push and replay phases, and cleanup. The existing release
index job accepts exactly two distinct qualified amd64/arm64 children. It creates
the version index from **digest references**, hashes/verifies the canonical raw
index and requires exactly those two children before protected proof, provenance
and promotion. `latest` is promoted from the verified canonical **digest**, never
the mutable version tag, and its resulting digest must match. Artifact extraction
also uses the qualified amd64 digest. Existing action pins, native ARM64/no-QEMU,
anonymous verification, release contract, audits and SQLite guards remain.

These are CI execution gates, not evidence that this patch's images passed. The
authoring checkpoint ran only socket/Docker/process-free unittest logic; actual
candidate/native/replay image cases and publication are unrun. Parent integrates
the staged patch and owns docs/ADR/version/public gates; those overlapping files
were deliberately not edited here.
