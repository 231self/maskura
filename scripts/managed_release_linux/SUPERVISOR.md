# Trusted case init / controller interface

Source implementation, not Linux isolation or product acceptance evidence.
ADR 0034 and the approved Linux design remain normative. This module has no
Docker, host namespace, cgroup or BPF authority. The host warden owns independent
mapping, mount inspection and final absence proof.

## Frozen entry and descriptor

Run only as the isolated container's PID 1:

```
/usr/bin/python3 -I -B /opt/managed_release_linux/supervisor.py --descriptor /run/maskura/descriptor.json
```

The direct-script bootstrap adds only the immutable `/opt` module directory.
Importing the package performs no process, socket, FFI or privilege operation.
Init is root with only SETUID/SETGID/KILL. Product UID/GID are 20001. Private
fixture I/O temporarily selects fsuid 20001, without CHOWN/DAC capabilities.

The descriptor is a canonical, root-owned, regular, no-follow 0400 file, at most
16384 bytes. Exact keys: `schema` (integer 1), `kind`, `case`, `nonce`, `root`,
`source_root`, `executable`, `product_guard`, `product_uid`, `product_gid`,
`campaign_end`, `case_started`, `pg`, `source_sha`, `inputs`. No optional keys.
`kind` is product or a member of `protocol.CONTROL_CASES`; control `case` equals
its kind. Product cases/selectors are exactly `protocol.CASES` (13 entries).
`nonce` is UUID hex; root basename is `managed-release-case-<hyphenated UUID>`.
Paths are canonical absolute original build paths, not shell fragments.
`product_guard` is exactly `/usr/local/bin/maskura-product-guard`.
`case_started` was captured **before** PG creation. Both deadlines use the same
host CLOCK_MONOTONIC, without a time namespace. They are never renewed.

`pg` is null except for product. Product PG has exactly `host`, `port`, `user`,
`database`, `password`: IPv4 127.0.0.1, nondefault unprivileged port,
`managed_release`, `managed_release_<nonce>`, synthetic 32-lowerhex password.
It is private in-memory transport, NEVER a channel or log field.
`source_sha` is 40 lowerhex. `inputs` requires **all seven** 64-lowerhex hashes:
`executable_sha256`, `tls_sha256`, `python_test_sha256`,
`product_guard_sha256`, `protocol_sha256`, `supervisor_sha256`, `probe_sha256`.
The warden must additionally bind full source/lock/Cargo/component/image inputs.

## Bounded control channel (v1)

stdin/stdout are private newline-delimited canonical ASCII JSON, <=8192 bytes
including newline. No product inherits these FDs. Each direction independently
starts `seq=1` and increments by one. Every frame has `schema:1`, `kind`, `case`,
`nonce`, `seq`. Extra fields are rejected. Commands contain only these fields,
except `identity-ack`, which also requires `ledger_sha256`. Commands are
`controls`, `start`, `identity-ack`, `abort`, `stop`; no argv/path/env/PID commands.
Do not pipeline commands: await the applicable response/identity request before
sending the next command. Multiple complete commands in one read are rejected.

1. Init emits `ready`, plus `ports` (role -> integer port). Product and both
   ownership controls reserve provider/tls/gateway-1/gateway-2/gateway-3.
   Slow-peer reserves slow-peer/slow-relay. Isolation-controls reserves all five.
   Pure provider/deadline/Python contracts reserve none. PG is in the descriptor,
   not the role map. IPv4 exact loopback reservations stay bound until the fixture
   readiness/hash handshake. No reservation FD enters a product.
2. Warden independently acknowledges init/cgroup/netns and attaches/reads back
   exact policies for the advertised ports plus PG, **then** sends `controls`.
3. Init runs the fixed product-guard child probe and emits `controls`, plus
   `passed` and `results` (closed boolean fields). Product probe connects to PG;
   isolation-controls uses the reserved provider socket as a real local listener.
   Other kinds with no PG use file/security controls only; the dedicated
   isolation case supplies the independent positive network control.
   On a failed/uncertain probe, init performs bounded cleanup then emits
   controls passed=false with all result fields false (unknown is not proof),
   followed by the failed case result when the channel/deadline permits.
4. Only after successful controls may the host send `start`. Isolation-controls
   completes after controls and does not accept start. Other kinds launch only a
   compiled-in selector. Root-owned canaries must be supplied by the controller
   under `/run/maskura/protected/` (0700 root-owned ancestor): `read-canary`,
   `write-canary`, `sibling-canary`; denied reads require EACCES/EPERM, not ENOENT.
   Warden separately verifies no sibling mount; a canary is not that proof.
5. After a locally verified TLS registration, init emits `identity-request`, plus
   `test_identity`, `tls_identity`, `ledger_sha256`. Warden independently maps
   both full Linux identities to the acknowledged cgroup/netns/UID/parentage,
   including **NSpid and NSpgid**, boot ID and start ticks (not PID-only mapping).
   Only `identity-ack` matching that digest permits writing `owned-tls-ack.json`.
   Replayed, unsolicited, late or wrong-hash ACK fails closed. Before-start
   control never requests/accepts ACK: it kills only captured main and proves TLS
   pipe-EOF exit without any TLS signal or key/listener creation.
6. Init emits `case-result`, plus `passed`, `status`, `counts`,
   `panic_locations`, `cleanup`, `control`. All fields are closed, body-free
   facts, not host cleanup assertions. `cleanup` contains main_group_absent,
   main_reaped, tls_group_absent, tls_reaped, listeners_closed,
   reservations_closed, within_deadline. False/unknown is not absence.
   `status` is `passed`, `failed`, or `cleanup-incomplete`; only `passed` can
   accompany acceptance. Counts always have selected/passed/summary/complete/
   shutdown integer keys (zero when no libtest output exists). `control` has
   before_start_eof, descendant_live_after_leader_exit, descendant_sigkill,
   strict_provider, deadline_contract, python_mocks, slow_peer,
   isolation_controls (booleans) and python_tests_run (0 or actual 5).
7. Init remains PID 1 for host cgroup/proc-set inspection. Host sends `stop`
   only after checking init is the sole remaining process, listeners are closed,
   and owned BPF detach is acknowledged while the init/cgroup still exist; then independently
   proves empty cgroup and all owned Docker/volume/namespace resources absent.
   EOF, abort, malformed frames or original deadlines trigger bounded cleanup;
   they never manufacture a pass. Stop before a result aborts the case.

Runtime limits: original case 240s (220 work/20 cleanup), campaign cleanup
reserve 120s, startup <=40s, owner runtime <=185s, Rust closure <=180s.
The host retains responsibility for filesystem floors, PG volume measurements,
four active slots and overall nonrenewing 3600s campaign.
Init verifies its actual E/P/bounding capabilities are precisely KILL, SETGID,
SETUID and I/ambient sets are empty. Runtime signal handlers request failure and
bounded cleanup; a later signal cannot interrupt the cleanup operation itself.
PID 1 uses raw waitpid statuses and reconciles every captured-child result with
its Popen object, including the race between direct WNOHANG and orphan reaping.
Popen's ECHILD-to-zero fallback is never acceptance evidence. Both expected-abort
controls require an actual SIGKILL wait status; a zombie is not group absence.
Local Linux identities read `stat` and `status` relative to a pinned
`/proc/<pid>` directory. UID means the kernel-reported effective UID from
`status`, not proc-file ownership (which Linux changes to root for zombies).
PID/group/start ticks/boot identity and UID still all have to match before
signalling. Missing or malformed status is never permission to ignore a mismatch;
only ENOENT means absence, and zombies still require reaping/group-absence proof.
Their bounded stdout is discard-only, not test-acceptance evidence, so an
unterminated libtest prefix at the deliberate kill is allowed. Line/total-byte
bounds, stderr checks and all non-discard product acceptance parsing remain strict.

Native product guard ABI:
`maskura-product-guard --uid 20001 --gid 20001 -- EXE ARGS...`.
It execv's, clears groups/caps E/P/I/ambient, sets no-new-privileges, applies
deny-default seccomp and closes all FDs >=3. No empty bounding-set claim is made.
Probe additionally verifies the actual runtime status, FDs and denial errnos.

Integration: `results.owned_loopback` is **false**, not a fabricated true, for
nonproduct/non-isolation cases (their ready map is empty or held reservations,
and they have no PG). All other probe booleans must be true. Product and the
dedicated isolation case require owned_loopback true. The controller must use
this kind-specific exact expectation rather than `all(results.values())`.
