# Native Linux qualification implementation plan

Status: Approved design; implementation in progress, no native capability/product pass.
Design: [native Linux managed qualification](../superpowers/specs/2026-11-12-native-linux-managed-qualification-design.md).
Decision: [ADR 0034](../adr/0034-isolated-native-linux-managed-qualification.md).

## Workstream boundaries

1. Native kernel/product guards: `scripts/managed_release_linux/kernel_guard.c`,
   `product_guard.c`, focused tests and interface notes.
2. Case protocol/supervision: `protocol.py`, `supervisor.py`, `probe.py` and their
   socket-free unit tests. No Docker/host authority.
3. Host controller and integration: `controller.py`, standalone entry CLI, case
   Dockerfile, CI wiring and controller tests. No production Rust changes.
4. Parent: interface/privacy review, local gates, actual bounded Linux evidence,
   native-image/Postgres CI tracking and final-source release qualification.

Imports and cheap tests perform no process, socket, FFI, namespace, cgroup,
Docker, lock or privilege operations. Runtime requires explicit authorization
and source/artifact bindings. No old Mac artifact/receipt becomes Linux evidence.

## Frozen interfaces

- Package `scripts/managed_release_linux`; standalone entry
  `scripts/managed-release-linux.py`. Default invocation is non-executing.
- Native kernel helper: already owned/open cgroup descriptor, bounded exact IPv4
  loopback ports and original absolute deadline. Attach/read back four bind/
  connect policies, emit closed READY, retain program FDs, detach only its own
  programs on bounded STOP/EOF/deadline. No raw verifier/upstream diagnostics.
- Product guard: trusted init supplies the pinned executable and fixed selector.
  Set product UID/GID, remove supplementary groups and effective/permitted/
  inheritable/ambient capabilities, set no-new-privileges and deny-default seccomp,
  close nonstandard descriptors, then execute. Do not claim an empty bounding
  set without an actual additional drop step.
- Init reads a bounded root-owned descriptor at a fixed path, not arbitrary stdin
  commands. Reserve five fixture ports in the owned PG namespace. Warden approval
  precedes real controls and START. JSON control frames are bounded, sequenced and
  source/case/nonce/deadline-bound. No caller-selected argv, paths, environment,
  Docker arguments, IDs or namespace joins.
- Init's product filesystem UID may be selected through SETUID/SETGID when writing
  private fixture files. Do not add CHOWN/DAC/SYS_ADMIN capabilities or pass any
  supervisor authority to products. Product UID differs from init UID.
- Preserve existing case-root/schema, exact port-handoff, TLS ledger/ACK/START/
  STOP and marker contracts. Init uses local PID metadata; warden independently
  maps acknowledged cgroup members through namespace IDs, NSpid/NSpgid, birth,
  UID and parentage before ACK or signal authorization.
- Init owns bounded marker/output drains, captured local groups and local listener
  checks. Warden owns independent host identity, cgroup, Docker/volume and final
  cleanup proof. Untrusted case files alone authorize neither signals nor deletion.

## Sequence and gates

1. Add pure malformed-input, deadline, ownership, replay, startup failure, privacy
   and cleanup regressions; do not represent mocks as kernel enforcement.
2. Implement narrow native guards with self-tests; compile/run native code only
   on the newly authorized fresh Linux runner.
3. Implement finite init lifecycle, meaningful real controls and exact selectors.
4. Implement pinned inputs, cleared runtime environment, typed Docker lifecycle,
   hard resource admission, policy attachment/readback, independent identity and
   cancellation cleanup. Preserve four active slots through verified removal.
5. Wire a required `managed-release` check for all 13 exact passes, zero ignores,
   controls and complete cleanup. Missing capabilities/evidence fail; no skips or
   lower coverage. Qualify final release source before registry publication, not
   just an older PR revision.
6. Run cheap tests and correctness/security gates before guarded publication.
   Storage-check preparation/build is bounded to 20 minutes and runtime to one
   nonrenewing 60-minute campaign with its 120-second cleanup reserve, within a
   90-minute job. Existing 40/180/185/240-second limits, 20-second case reserve,
   12-GiB floors and 5-GiB PG cap remain mandatory.
7. Inspect actual positive/negative controls before accepting products. Preserve
   failed receipts; fix concrete defects without relaxing policy.

## Completion evidence

Require native source/lock/executable/profile bindings, real kernel controls,
all 13 product passes, existing provider/TLS/slow-peer/ownership controls, limits
and independent owned cleanup. VM disposal, mocks and boot smoke are insufficient.
Bodies, credentials, prompts, keys, payload hashes and raw spool data never enter
public evidence. No implementation or runtime qualification is claimed yet.

## Integration checkpoint (2026-11-12)

Native guards and case supervision are implemented. Parent reruns passed 34
native-construction and 60 supervisor mocked regressions under OS network denial.
Independent source reviews of both boundaries reported no concrete P1/P2 finding.
These checks do not establish native compilation or kernel enforcement.

The host controller, separate coordinator, runtime image and mandatory CI/release
wiring are implemented. Parent initially reran all 157 managed harness regressions
under OS network denial; five additional offline wiring checks verify current-source
CI, non-skipped aggregate success, bounded standard-runner execution, final-tag
qualification before registry build, and failure-receipt retention.

Controller integration is closing three concrete gaps before the first Linux run:
prove actual nosuid mount flags through owned host setup rather than relying on
Docker's bind options; reconcile partial Docker creation before cleanup; and make
stalled coordinator reads observe cancellation promptly. None permits weakening
policy, changing product assertions or renewing an expired budget. Actual native
controls, cleanup and all 13 product passes remain outstanding.

Those three source corrections are now implemented. An additional daemon-timeout
regression keeps a create request unresolved even if it is initially absent from
inventory or a later visible resource is removed; no completion/cleanup claim is
fabricated. Parent reruns now pass 194 offline managed harness regressions, including
fixed failure-category privacy and immutable-source workflow wiring. Native guards
compile first during the forthcoming preparation phase, without adding or renewing
any budget. These source checks still do not qualify a real mount, daemon, policy
or product case.

The ready image connector was independently published additively as PR head
`9427e06fd72c062bf1ccfb0dfd657e6fdaa5cbb3`; CI run `43229853337` is executing
its native image checks. Linux integration must build on that source, not replace
it with the older authoring tree. Version synchronization is deferred until
genuine qualification, then requires fresh final-source checks. v0.7.33 stays
unchanged; private schema expansion remains paused.
