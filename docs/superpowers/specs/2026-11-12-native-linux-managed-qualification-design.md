# Native Linux managed-storage qualification

Status: Design, implementation and bounded CI execution approved; implementation in progress, not qualified.
Date: 2026-11-12

## Plain-English decision

Add one required check to the corrective PR. It runs the 13 currently missing
managed-storage tests on a fresh standard GitHub Actions Ubuntu AMD64 machine,
not the maintainer's Mac or shared local Docker environment. Each test receives
its own database and private temporary storage. Tests cannot reach the internet,
production, GitHub credentials or another test's files and services.

At most four tests are active. The check must verify that its processes and
temporary resources are gone before reporting success. Missing machine features,
failed tests, cancellation and uncertain cleanup all fail the check; none turn
into a skip. Production authentication, policy, privacy and integrity checks stay
unchanged.

Approved authorization is **at most 90 minutes per storage-check run**, including a bounded
20-minute preparation/build phase and a separate 60-minute test campaign. The
last two minutes of the campaign are reserved for cleanup. Only normal GitHub
Actions runner usage is proposed: no larger paid runners, inference services,
customer resources or production deployment. Billing availability is not assumed.

The old Mac campaign remains expired and closed. This proposal does not renew it.
The owner separately approved building and running this check under those limits;
the earlier release approval alone was not used as execution authorization.

## Purpose and exclusions

The current Mac launcher cannot apply its case sandbox inside the coordinator's
deny-default sandbox. Kernel diagnostics identify `forbidden-sandbox-reinit`.
Removing either restriction is not an acceptable correction.

This proposal supplies equivalent explicit Linux isolation and an actual
13-case acceptance gate. It is not a general test platform, an S3 emulator,
external-provider certification, production schema enablement, model execution
or execution attestation. Native AMD64/ARM64 packaged-image qualification remains
separate and required. The existing FileStore runner cannot substitute for this
managed/Postgres evidence.

## Architecture and trust boundaries

Use Docker's existing namespace construction rather than writing a replacement
container runtime. Docker alone is insufficient; a narrowly scoped host warden
adds exact network restrictions, independent process verification and cleanup.

1. **Preparation** checks out the reviewed source, installs pinned tooling and
   clients, fetches the pinned native Postgres/runtime images and compiles the
   actual Cargo-selected executable. Preparation may access dependency services.
   Runtime may not download, install, pull images or contact registries.
2. **Coordinator** runs unprivileged, without Docker access, in its own restricted
   filesystem/process/network environment. It selects only fixed case identifiers
   and receives closed status records. It cannot supply arbitrary commands.
3. **Host warden** is the sole trusted Docker, cgroup and BPF controller on the
   disposable machine. Its privileged setup and lifecycle operations address only
   newly created, independently acknowledged campaign resources. This is an
   explicit privileged trust boundary, not an unprivileged-sandbox claim.
4. **Case executor** is a container with private PID, mount, IPC and UTS namespaces.
   Its network joins only its acknowledged Postgres container's network namespace.
   It has a read-only root, allowlisted read-only inputs and one private writable
   case root. No host HOME, Git metadata, Cargo credentials, Docker socket, host
   PID namespace, writable cgroups or sibling-case mounts are exposed.
5. **Trusted case init** is the pinned PID-1 supervisor. It starts idle, receives
   no arbitrary program description, and launches exactly one compiled-in case
   selector only after the warden authorizes START. Product descendants receive
   a cleared environment and descriptor set, a separate non-root UID, empty
   effective/permitted/inheritable/ambient capability sets, `no_new_privs`, and
   their own restrictive seccomp policy.

Init may retain only the credential-switching/supervision capabilities required
by its reviewed implementation: SETUID, SETGID and KILL. Its policy differs from
the product policy. Do not claim the product capability bounding set is empty
unless an actual additional drop step proves it. Mounts are non-suid and product
children cannot regain privileges. Case-root files are untrusted protocol input,
not authority to signal a PID or remove a resource.

Build credentials never enter runtime descriptors, mounts or environment. Use
checkout without persisted credentials and an explicit staged input allowlist.
Retain only source/artifact identities and synthetic fixture byte-equality
results; do not hash fixture payloads into evidence.

## Native artifact and platform binding

Bind the full source revision, Cargo.lock, Rust 1.97.0 toolchain, Cargo JSON
artifact record, executable identity, genuine test component, runtime/init image
digests, native architecture, helper sources and security profiles. The approved
candidate includes rustix 1.1.6. Old Mac binaries and the historical 381-input
snapshot remain untouched and do not qualify a changed source or lockfile.

Execute the actual Cargo output through a read-only bind at its original absolute
path, not a retained copy. Preserve the compiled `CARGO_MANIFEST_DIR` path and
allowlisted fixture/component paths inside the executor. Verify native ELF and
rootfs ABI compatibility before product execution. No QEMU qualification.

## Network and database confinement

Create each Postgres container with the pinned native image, `--network=none`,
no published host ports and an explicitly assigned nondefault server port. The
case executor joins precisely that acknowledged network namespace. Provider,
TLS relay and gateway listeners use that namespace's IPv4 loopback.

Before product START, the host warden binds the idle init's PID/pidfd, namespace
identities and unique cgroup directory identity. It attaches and reads back
immutable cgroup-BPF bind/connect rules for only that case's declared IPv4
loopback ports. Seccomp excludes IPv6, packet/raw/alternative network access and
namespace/privilege escape operations outside the reviewed syscall allowlist.
Missing cgroup v2, attachment/readback support or seccomp compatibility fails
admission. Lack of an external route is not proof of a policy denial.

Postgres uses fresh nonce-labelled containers and named volumes, a read-only
root, bounded temporary mounts and explicit CPU/memory/PID limits. The proposed
volume contract allows only a specifically reviewed tmpfs configuration capped
at 5 GiB and initialized for the pinned image's PG UID/GID. This changes the old
adapter's blanket prohibition on volume options; it is not permission for
arbitrary driver options or host bind paths. Continue complete bounded volume
usage checks. Admission verifies enough memory for four active cases and the
supervisors; insufficient capacity fails, rather than silently reducing coverage.

No Docker network object is needed. Record its expected absence explicitly.

## Port and process ownership protocols

Host-wide port reservations cannot be reused unchanged. Postgres first creates
its private network namespace and binds its selected server port. Idle case init
then reserves the five exact fixture ports inside that namespace and preserves
their release/readiness handshake. A port identity is now the network namespace,
address and port tuple, not a globally unique host port. No collision retry may
silently change a declared product port.

Keep fixture PID/birth ledgers namespace-local. The host warden independently maps
only members of the acknowledged case cgroup using host `/proc` NSpid values,
namespace identities, boot ID, start ticks, UID and direct parentage. Retain the
namespace references, init pidfd, cgroup directory identity and creation receipts.
Only after matching the complete identity may the warden authorize the existing
hash-bound ACK, followed by START. Local PID 1 is the trusted supervisor, never
the test/TLS identity. Stale, ambiguous or missing mappings fail closed. No time
namespace or renewed deadlines are introduced.

Use private bounded, sequenced control messages bound to campaign, case, source
and deadline. Operations are finite lifecycle requests, not arbitrary argv,
environment, paths, Docker arguments, namespace joins or caller-selected IDs.
Product descendants inherit no warden channels, privileged descriptors, supervisor
credentials or global-lock handles. Malformed, replayed, oversized or late
messages fail closed and trigger owned cleanup.

## Scheduling and deadlines

- Four active product slots, counted from PG creation through verified cleanup.
- Existing 40-second startup, 180/185-second closure/runtime bounds.
- One original 240-second case deadline, with its final 20 seconds for cleanup.
  Multiple closures do not each create a fresh outer case budget.
- One original 3600-second runtime campaign deadline, with a 120-second cleanup
  reserve; setup, controls, waits and retries within that campaign count.
- At least 12 GiB free on the host/source/target/case-staging and Docker backing
  filesystems, and at most 5 GiB per owned PG volume. The dedicated capped PG
  tmpfs has its own hard cap, complete usage scan and memory admission, not an
  additional 12-GiB-free requirement on a 5-GiB filesystem. No host/backing
  resource-floor downgrade is allowed to obtain a pass.
- Proposed CI job wall timeout: 90 minutes. A different source/retry is a distinct
  explicitly bounded run, never a continuation that resets an expired clock.

Coordinator loss, timeout or cancellation causes independent warden cleanup.
The warden cannot depend on the failed product process to report its own absence.
If external CI termination prevents cleanup proof, the result is failed/cancelled;
VM disposal is not a successful cleanup receipt.

## Required controls and acceptance

Before any product case, actual kernel controls must prove positive owned file
and loopback access and negative forbidden read/write, sibling-case access,
undeclared loopback ports, default 5432/54322, IPv6/external network, descriptor
leakage, privileged operations and stale process identity. Retain the existing
provider, TLS-cause, startup, slow-peer, early-parent-exit and surviving-descendant
controls with meaningful positive and negative outcomes. Mocks qualify only the
controller logic, not these boundaries.

Execute all 13 exact managed selectors with one pass, zero ignores and their
expected closed markers each. A failed setup, skipped case or missing marker
cannot become an empty successful suite. Preserve production authentication,
policy, metadata privacy, checksums, recovery, SDK certificate verification and
all product assertions.

The warden verifies captured process reaping, cgroup emptiness, listener closure
in the acknowledged namespace, init exit, PG/container/volume absence, namespace
reference release and lock release. Permission, transport or enumeration errors
never establish absence. Reports contain only allowlisted statuses, case names,
counts, source/image identities and ownership/cleanup assertions—no customer
bodies, credentials, prompts, envelope keys, payload hashes or raw spool data.

Add the resulting `managed-release` job to the required aggregate `check`.
That job succeeds only for the exact current source, all 13 product passes,
successful controls and complete cleanup. The existing ordinary DB tests may
still list ignored release selectors; only the dedicated exact execution supplies
their acceptance. Final version changes require matching fresh qualification.

## Delivery and approval checkpoints

1. Review this design and ADR 0034. No infrastructure is launched by
   creating these documents.
2. Implementation and the explicit per-run preparation/runtime limits were approved
   separately after review. Release approval is already recorded separately and
   will not be requested again. Approval is not a capability or acceptance result.
3. Implement the smallest typed controller/init/kernel-policy boundary, pure
   regression tests and mandatory CI wiring. Reuse reviewed ownership/drainer
   algorithms, not old source-bound receipts or platform assumptions.
4. Run an actual bounded capability/control phase on the selected fresh runner.
   Unsupported facilities stop the run; no fallback weakens confinement.
5. Run current-source product acceptance only after controls pass, inspect cleanup
   evidence, and retain failed attempts as failures.

Runner capabilities, seccomp compatibility, BPF enforcement, tmpfs memory capacity
and cancellation cleanup are unverified until their actual controls execute.
Namespaces share the host kernel; this design is not VM-escape attestation or
independent witness evidence. No implementation or runtime pass is claimed.
