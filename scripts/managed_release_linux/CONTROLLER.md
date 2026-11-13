# Native Linux host warden and coordinator

Source implementation only: no kernel control, Linux capability, product-pass,
or cleanup evidence is supplied by the offline tests. ADR 0034 and the approved
2026-11-12 design/plan are normative.

## Trust boundaries

`managed-release-linux.py --execute --prepare --source-sha <commit>` is the only
network/build phase. Its single nonrenewing budget is 1200 seconds. It stages
only tracked `SOURCEALLOWLIST` inputs, excluding VCS metadata, credentials, HOME,
unknown spools and payload evidence. Public fixture bytes are compared directly,
not hashed into receipts. Source directories/files become 0555/0444. The genuine
built component is retained; an **empty** placeholder gives Docker a mountpoint
for the **original Cargo-selected executable**, at its original absolute path.
No retained executable copy qualifies. Native ELF identity and pinned runtime
loader dependency/version resolution are checked before the campaign.

`--execute --warden` is a root-only host boundary on a fresh standard Linux
AMD64 VM. Only this process has Docker/cgroup/BPF and scoped host-mount authority. It clears the
Docker-client environment, uses `--pull=never`, owns creation receipts, retains
pidfds/namespace/cgroup directory FDs, verifies readback, independently maps
fixture identities, and owns final cleanup. Root authority is not represented
as an unprivileged coordinator sandbox.

`coordinator.py` is a **different OS process/container**, not an in-process root
planner. Its sole input mount is a root-owned 0444 read-only plan with fixed
case names, source revision, campaign nonce and original deadline. No passwords,
host resource IDs, arbitrary commands, paths or environments enter that plan.
The entrypoint is the pinned native product guard with `--profile coordinator`;
root initially has only SETUID/SETGID, then the guard selects UID/GID 20001,
clears capabilities/groups, enables NNP and installs the coordinator deny-default
seccomp profile **before Python starts**. That profile denies all socket/network
syscalls, so there is no initial planner network-policy attachment race.
Before its first request the planner additionally requires actual EPERM from
IPv4, IPv6, Unix, UDP and raw socket-creation controls; route failures do not pass.

The coordinator has a read-only root, private PID/mount/network/IPC/UTS
namespaces, no Docker socket, host proc, source, cgroup FDs, HOME or case mounts.
`--ipc=none` gives a private IPC namespace without a writable `/dev/shm` mount.
It can request only the next fixed case IDs, in fixed batches of at most four,
using <=8192-byte sequenced source/nonce-bound frames. The warden compares each
request against its **own** constants; it never joins coordinator input into
argv, resource IDs or paths. Coordinator PID/cgroup/namespace ownership, empty
cgroup, adapter reaping and acknowledged Docker removal are separately checked.

After an identity-verified Docker stop, empty-cgroup proof additionally requires
the held init pidfd to report exit. If Docker has already removed the cgroup,
`cgroup.procs` may return ENOENT. Only then may the verifier use the original
held directory's unchanged device/inode and the kernel's `/proc/self/fd` deleted
marker: Linux cannot remove a populated cgroup. A missing path, a dead init,
changed directory identity, permission error, or remaining member never suffices.
This applies to both coordinator and case cleanup; all other cleanup gates remain.

Cases use trusted root PID-1 init with only SETUID/SETGID/KILL. Products run via
the separate default native product-guard policy as UID/GID 20001, with stdio
only. See `SUPERVISOR.md` for the exact unchanged seven-field descriptor input
hash contract. Host-owned case roots are 0700/20001 **before init starts**;
root-owned descriptors/canaries are mounted separately read-only. The warden
checks actual Docker mount sources and kernel namespace/mount flags. A case
ledger alone never authorizes a host signal. Host `/proc` reads enumerate only
acknowledged cgroup members and match NSpid/NSpgid, UID, boot/start ticks,
namespace and direct parentage before hash-bound ACK.

Before Docker case creation the host warden self-bind-mounts only its acknowledged
staged source, original Cargo ELF, private case root and init-config directory.
Shared source/ELF mounts are established once per campaign; case/config mounts
are established before init. Each is remounted `nosuid,nodev,ro` (source, ELF,
config) or `nosuid,nodev,rw` (case). No host root/HOME, arbitrary path or recursive
mount operation is accepted. Existing/stacked/descendant mounts are refused.
The ledger registers pending creation **before** invoking mount, including when
the bind/remount/readback subsequently fails. It pins the host mount namespace
FD, device/inode, baseline mount IDs, source device/root and resulting mount ID
and flags. Actual kernel readback, not command intent, establishes admission.

## Database, scheduling and cleanup

Only product cases get a fresh pinned Postgres 17 container and named local
tmpfs volume. PG runs as the pinned image's UID/GID 999, without capabilities,
with read-only root, private network/IPC, no published host ports, a chosen
nondefault port and explicit CPU/memory/PID bounds. Only reviewed tmpfs driver
options are accepted: 5 GiB maximum, uid/gid 999, 0700, nosuid/nodev/noexec.
Read-only, networkless metadata helpers scan complete bounded volume trees and
allocated blocks; they read no payload files and are independently owned/removed.
PG is stopped before the final scan/removal. A 5-GiB PG tmpfs is **not** also
required to have 12 GiB free. The unchanged 12-GiB floors cover source/target,
case staging and Docker backing filesystems. Checks include each actual target,
executable and staged-source path, plus the validated operator `DockerRootDir`
returned by Docker info, rather than assuming `/var/lib/docker`. Memory admission covers four slots;
coverage is never reduced to fit a weaker runner.

Four slots span PG creation through verified cleanup. Case deadlines start
before PG creation: startup 40s, existing owner 185s/closure 180s, case 240s with
20s cleanup, one campaign 3600s including 120s cleanup reserve. Bounded channel
heartbeats recheck ownership, coordinator liveness, filesystem floors and PG
usage. Real controls precede all 13 products; each product requires exactly one
pass, zero ignores and both closed markers. Tests do not assert kernel controls.
Validated, case/nonce-bound failed result frames produce a closed per-case diagnostic
before acceptance checks: case ID, init's pass/status, bounded counts, local
cleanup flags and allowlisted panic location codes/line/column. Failed results
still fail acceptance. No nonce, descriptor, path, raw output, exception or
payload hash is printed; these local facts never substitute for host cleanup.
The first planner request has a bounded startup wait and a <=0.1-second
cancellation/liveness heartbeat; cancellation prevents further product starts.
Runtime host commands are capped at ten seconds **within**, never instead of,
their original case/campaign deadline. Preparation retains its original budget.
The native guard receives that same deadline serialized to nine fractional
decimal digits, floored rather than rounded: Python float addition can otherwise
produce more digits than the native parser permits. Serialization never extends
or renews the original budget; the native grammar stays strict.

Init-only cgroup membership and listener closure are independently checked
before BPF STOP, while the trusted init remains in its result/wait-stop state.
Owned BPF detach and zero guard exit must be acknowledged **before** sending STOP
to that init. No product may still run when policy is detached. After init exit,
the pinned empty/deleted-cgroup proof above applies; Docker may already have
removed its empty cgroup. Removal uses captured IDs and re-inspection;
only successful complete enumeration proves absence. EPERM, transport errors,
bad metadata and stderr never imply absence. Cleanup continues across failures.
Only fixed acknowledged root entries are removed, never a broad unknown tree.
Cancellation, loss, timeout and uncertain cleanup remain failed attempts;
fresh-VM disposal cannot manufacture a successful cleanup receipt.

Docker mutations first register a finite pending reservation containing the exact
UUID name, campaign/nonce, expected image or reviewed volume options, pre-create
inventory and creation-time floor. Lost create responses or inspect failures are
reconciled only through successful complete inventory and the exact reserved
name, labels, birth and identity. Wrong labels/birth, replacements and unresolved
resources never authorize deletion. A full acknowledgment is retained before
later admission validation can fail. This applies to case helpers, coordinator
and preparation ABI helper; a recovered resource does not turn a failed attempt
into acceptance. No campaign-prefix deletion or stderr-based absence exists.

A timed-out create request remains unresolved even through repeated empty
inventories: killing the CLI does not cancel the daemon operation. Only actual
successful command completion establishes completion of that request. A later
visible, fully verified owned resource may be removed, but that does not clear
the original uncertainty or authorize a successful cleanup claim or input unmount.

Containers, captured cgroups and BPF policies must be independently cleaned
before case input mounts are released. Unmount requires the exact captured mount
ID/path/inode in the held host namespace, no stacked/transitive mount, and
successful post-unmount absence/identity inspection. No recursive, lazy or forced
unmount exists. Only then may case files be removed; shared source/ELF mounts are
released at final cleanup. Uncertain resource proof blocks unmount/deletion.

Internal receipts additionally bind all controller/coordinator/native C sources,
both compiled native guards, source/lock/toolchain, selected Cargo JSON record,
Dockerfile, seccomp profile, component, native image IDs and input inode/time
identities. Changed inputs or rebuilds invalidate preparation. Exported reports
are closed metadata only: no passwords, bodies, keys, prompts, payload hashes or
raw stdout/stderr/spools. Failed reports make no cleanup claim.

Preparation emits only fixed stage labels and runs native guard compilation and
construction checks before the heavy Rust build, within the same original
20-minute budget. Failures export only a fixed category allowlist; unknown
exceptions become `internal-failure`, never exception text or command arguments.

## Closed startup diagnostics

Before the first request, four fixed sources can explain a coordinator that
produces no frame, without exporting any raw text:

0. After `docker create`, the warden verifies the daemon applied the exact
   guard entrypoint and coordinator command
   (`coordinator-entrypoint-unproved` otherwise): an image-default entrypoint
   would run `controller.py` with coordinator arguments and exit 2 before main.
   During preparation, a fixed helper container then runs this exact guard
   context (init seccomp + NNP + uid 20001) against the real script path and
   prints only closed facts — `opened`, errno integers, octal modes and uids —
   mapping failures to `coordinator-script-missing` /
   `coordinator-script-permission` / `coordinator-script-policy` before the
   campaign can start. The coordinator uses a fixed `python -c` bootstrap to
   open and execute the same script with script-mode arguments; the guarded
   file-argument launcher was denied despite the guarded open succeeding.
   Native tracing subsequently identified its FIOCLEX request; the guard now
   permits only that close-on-exec operation, also enabling the real probe and
   Python fixtures to launch without bootstrap wrappers.
   An unguarded file-argument mirror must reach the coordinator's identity
   check, checking the init-only launch used by the supervisor; script-open
   failure reports `init-script-blocked`. Preparation creates mirror plans with
   verified root ownership, matching the root warden's actual campaign plans.
   Preparation then **reproduces exact-runtime coordinator
   startup** with a mirror container (identical entrypoint, command, seccomp,
   interactive flag and plan mount) and bisects failures across
   `no_interactive` / `no_plan_mount` variants; the first accepted mirror emits
   its initial `run-case` request frame through the real request validator.
   Categories `mirror-still-running` / `mirror-cleanup-unproved` cover its
   owned cleanup.
   Runtime binding and final-cleanup failures report only fixed stage labels,
   allowlisted contract categories, and generic missing/permission categories;
   exception messages and paths are never exported.
1. The native guard's own stdout frame
   `{"schema":1,"kind":"product-guard","ok":false,"code":"<allowlisted>"}` maps
   to `guard-<code>` (`arguments`, `authority`, `policy_build`, `credentials`,
   `no_new_privileges`, `descriptors`, `seccomp`, `exec`, `self_test`).
2. The coordinator emits `{"schema":1,"kind":"coordinator-startup","code":"..."}`
   for a fixed startup phase (`arguments`, `identity`, `network`, `plan`,
   `request`, `internal`, or `interpreter` from its early excepthook), mapping to
   `coordinator-<code>`. Exit codes 11-15 mirror those phases for a lost frame.
3. If the stream is empty, the warden waits boundedly for the captured
   `docker start --attach` adapter and reads only `State.StartedAt` and
   `State.ExitCode` (booleans/integers; OCI error strings are never inspected):
   never-started wins first. For a started container it then classifies at most
   8192 bytes of adapter stderr against fixed byte markers
   (`can't open file`, `coordinator.py: error:`, `Traceback (most recent call
   last)`, `Unknown option`, `usage:`, `Error response from daemon`,
   `OCI runtime`) into `coordinator-script-unopened`,
   `coordinator-argparse-uncaught`, `coordinator-interpreter-traceback`,
   `coordinator-interpreter-argv`, `coordinator-adapter-error` or
   `coordinator-runtime-error`; unrecognized non-empty stderr becomes
   `coordinator-stderr-unclassified`, and empty stderr falls back to the exit map
   (`coordinator-arguments` for 2, `coordinator-startup-crash` for 1,
   `coordinator-startup-exit` otherwise). The classified bytes are discarded
   immediately; only the enum, the integer facts (`adapter_exit`,
   `container_started`, `container_exit`) and stage labels are retained.
   An unresolved adapter or unprovable state fails as
   `coordinator-adapter-unresolved` / `coordinator-state-unproved`.

Runtime stage labels (`managed-linux-runtime: admission|input-mounts|
coordinator-create|coordinator-first-frame`) localize a failure in the step log.
All emitted frames are exact-schema, ASCII, fixed-vocabulary records; unknown
codes collapse to `internal`, and no exception text, path, plan or environment
value is ever serialized.

## CI and actual mount qualification

The reusable job has a 90-minute wall limit, a single 20-minute preparation
step, and a separate 60-minute explicit runtime step. Checkout does not persist
credentials, permissions are contents-read only, and there are no secrets,
customer resources, services or larger runners. The required CI aggregate
depends on `managed-release`. Final release tag/source is freshly qualified
after `contract` and before the image-build job can mutate a registry.

**Docker bind mounts do not provide a nosuid option.** The owned host setup above
supplies nosuid/nodev sources, but flag inheritance into Docker is **unverified**
until the fresh runner executes its actual controls. Container kernel readback
still fails `mount-flags-unproved` if any required bind loses nosuid/nodev or the
required ro/rw state. NNP is not a substitute. Missing mount-tool compatibility,
BPF/cgroup/seccomp, native ABI, memory or disk facilities likewise fail closed;
no policy fallback or native/runtime qualification is claimed by source tests.

Offline tests: `python3 -B -m unittest discover -s tests -p 'test_managed_linux_controller.py'`.
They deny real process, socket, FFI, signal, privilege and lock actions; mocks
qualify controller logic only. The parent owns actual authorized GHA execution.
