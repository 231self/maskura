# ADR 0034: Isolated native Linux managed qualification

- Status: Accepted
- Date: 2026-11-12

## Context

The corrective S3 release requires 13 actual managed HTTP/Postgres/provider cases,
separately from ADR 0033's native packaged FileStore cases. The reviewed Mac
launcher failed before product execution because this host rejects nested
deny-default sandbox initialization. Its original campaign expired; neither
removing isolation nor renewing that deadline is acceptable evidence.

The owner selected a native Linux backend design on a fresh standard GitHub
Actions Ubuntu AMD64 runner. A single-entry Darwin executor design was considered
but not selected. The owner subsequently approved implementation and execution
under the explicit standard-runner/time/resource limits. No Linux isolation
capability or managed acceptance is established by that approval.

## Decision

Use Docker-created per-case namespaces plus a narrowly scoped trusted host
warden, rather than a new container runtime or plain Docker isolation alone.
The coordinator remains unprivileged and restricted. The warden alone controls
acknowledged Docker resources, cgroups and exact-port BPF policies. A pinned idle
case init waits for independently verified confinement before launching a fixed
selector as a non-root, capability-restricted product process.

Each case shares only its own isolated Postgres network namespace, with no host
port publication. Its filesystem exposes allowlisted read-only inputs and its
private writable root, not host credentials, Docker access or sibling state.
Bind namespace-local process ledgers to independently verified host identities
before ACK/START. Enforce real controls, unchanged product assertions and owned
resource-absence evidence; missing capabilities fail closed.

The PostgreSQL volume contract permits only an explicitly bounded,
reviewed tmpfs configuration capped at 5 GiB, not arbitrary volume options.
Retain four active product slots, existing per-case/closure deadlines, 12-GiB
filesystem floors and a nonrenewing 3600-second campaign with cleanup reserve.
Storage-check CI wall time is at most 90 minutes per run, including preparation.

The complete contract and approval checkpoints are in the
[Linux qualification design](../superpowers/specs/2026-11-12-native-linux-managed-qualification-design.md).

## Consequences

### Runtime teardown clarification

Docker may remove an empty cgroup before the verifier reopens `cgroup.procs`.
Following an identity-verified container stop, cleanup requires the pinned init
pidfd to report exit and either a readback of zero members or, on ENOENT only,
the held original cgroup directory's unchanged device/inode plus the kernel
deleted-directory marker. Linux refuses removal of populated cgroups. A missing
path or a dead init alone is not cleanup proof, and unreadable/replaced state
remains fail-closed. No migration or additional cgroup authority is granted.

Normal case teardown independently verifies init-only membership and listener
absence, requests owned BPF detach while the trusted init is still waiting for
STOP, requires its exact detach acknowledgement and zero helper exit, then sends
STOP to the init. Detaching after Docker removes the cgroup cannot provide that
acknowledgement. No policy is removed while a product or descendant is alive.

The guarded syscall surface permits FIOCLEX solely to set close-on-exec on a
descriptor, as required by CPython's file-argument launcher. Native tracing
confirmed the prior EPERM; FIONCLEX (clearing close-on-exec) remains denied.

The two deliberately killed owner controls discard stdout rather than treating
it as acceptance evidence. A bounded unfinished libtest stdout prefix is allowed
only in that discard mode; all stderr, size bounds and product acceptance records
remain strict, and the controls still require the actual injected SIGKILL plus
independently verified ownership, process/listener absence and cleanup.

Local process readback pins `/proc/<pid>` and reads both `stat` and `status`
relative to that held directory, so PID reuse cannot mix records. The UID check
uses the kernel-reported effective UID, not proc-file ownership: Linux changes
that ownership to root on zombie transition even though the effective UID and
start identity remain unchanged. Birth, PID, PGID and effective UID mismatches
still reject signal authority. A zombie is not absence; actual reaping and group
absence remain required. Permission errors and malformed records fail closed.

The native policy helper's deadline grammar remains bounded to nine fractional
digits. Serialize the existing campaign end with decimal flooring to that
precision; do not pass Python's unconstrained float representation, round it up,
or establish a fresh budget. This prevents float-addition serialization failures
without granting any runtime extension.

- A new required `managed-release` CI job must execute all 13 exact cases; ordinary
  tests that ignore them and FileStore image smoke do not satisfy that gate.
- Privileged warden/init behavior is an explicit trust boundary requiring source
  review, independent ownership verification and actual kernel controls.
- Port identity includes its private network namespace. Old host-port reservations
  and Mac runtime receipts cannot be copied as Linux evidence.
- Runner facilities, native ABI, BPF/seccomp compatibility, memory admission and
  cancellation cleanup require actual verification. No permissive fallback exists.
- The design shares the Linux kernel and provides no VM-escape or independent
  execution attestation. Failed or uncertain cleanup remains a failed result.
- No inference, production/customer access, deployment or historical tag mutation
  is authorized. Release-qualification storage-check runs are authorized only within the separately
  approved standard-runner, time and resource limits. Existing release approval
  remains conditional on genuine qualification of the final source.
