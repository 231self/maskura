# Native Linux guard interfaces

These two helpers are source-only until compiled and exercised on the approved
fresh Ubuntu AMD64 CI runner: **native execution is unverified**. They do not
replace the warden's ownership, namespace, mount, identity, positive/negative
control or cleanup proofs. No local Mac native probe is authorized.

## Build and construction checks (approved Linux preparation only)

```sh
gcc -std=c11 -O2 -Wall -Wextra -Werror scripts/managed_release_linux/kernel_guard.c -o kernel-guard
gcc -std=c11 -O2 -Wall -Wextra -Werror scripts/managed_release_linux/product_guard.c -o product-guard
./kernel-guard --self-test
./product-guard --self-test
```

Only Linux UAPI headers and libc are needed, not libbpf/libseccomp, clang, a BPF
compiler or runtime downloads. Compile-time OS/architecture checks reject other
targets; the seccomp architecture gate kills non-AMD64/x32 syscalls. Required
runner facilities include cgroup v2, the four sock-address hooks, exclusive BPF
attachment, direct/effective program query, program-info lookup, seccomp filter,
ambient capability operations and `close_range`. Missing support fails closed.
There is no unspecified older-kernel/other-architecture compatibility fallback.

`--self-test` is unprivileged and construction-only. It interprets the generated
instructions without installing any policy, entering a namespace or opening a
socket. The kernel builder tests all 65,536 ports, exact loopback, nonexact
loopback/external addresses, empty policies and IPv6-deny programs. Product
builder tests cover socket families/types/protocols, high argument words,
clone flags, ioctl requests, prctl options, close-range flags, dangerous/unknown
syscalls, architecture gates, default/explicit/invalid profile parsing and the
coordinator's network-deny matrix. Both emit one closed JSON record with `schema:1`,
`kind:kernel-policy-self-test` or `product-guard-self-test`, and `ok:true`.
Self-tests and the Python source regressions are **not kernel enforcement evidence**.

## Host kernel guard

```text
kernel-guard --cgroup-fd N --ports CSV --deadline SECONDS
```

Only the trusted host controller invokes this root helper. `N >= 3` is its
already-acknowledged, inherited, `O_DIRECTORY|O_NOFOLLOW` cgroup directory FD, not
a path to resolve. The helper checks descriptor flags, directory identity and
`fstatfs(CGROUP2_SUPER_MAGIC)`. The controller separately verifies ownership and
membership before invocation; cgroup filesystem identity alone is not ownership.
Pass only standard streams and that directory FD. Keep a captured process group
and the helper's private stdin/stdout channels.

`CSV` is empty or 1–16 distinct decimal ports, inclusive range 1024–65535,
excluding 5432 and 54322. No whitespace, signs or empty CSV elements are accepted.
Each token has at most five digits; accepted leading zeros do not change port
identity. Empty means **deny all**.
Output ports are numerically sorted. `SECONDS` is the original absolute
`CLOCK_MONOTONIC` deadline: decimal integer or fixed fraction (up to 9 fractional
digits and 12 integer digits), strictly future and no more than 3600 seconds away. No exponents,
nonfinite values, relative budgets or time namespaces are accepted. The controller
is responsible for binding this value to the original campaign/case deadline.

The immutable IPv4 bind/connect programs allow only `127.0.0.1` and a listed port;
IPv6 bind/connect always deny. Network byte order is explicit using `htonl` and
`htons`; field offsets come from `offsetof(struct bpf_sock_addr, user_ip4)` and
`offsetof(struct bpf_sock_addr, user_port)`. There are no mutable maps, helper
calls or verifier-log buffers. The helper retains all four program FDs.

Existing direct or effective programs on any of the four hooks fail admission.
Attachment is exclusive: no replace/override/multi flags. Before READY, all four
direct and effective query results must match the corresponding unique retained
program-info IDs exactly. The guard rechecks attachments while waiting. A
changed, added or replaced attachment is failure, never silently accepted.

READY is exactly one newline-delimited JSON object with these fields only:

```json
{"schema":1,"kind":"kernel-policy","ready":true,"program_ids":[1,2,3,4],"cgroup_device":1,"cgroup_inode":2,"allowed_ports":[15432,18080]}
```

IDs and directory device/inode above are examples, not caller inputs. The
controller must validate them against its acknowledged cgroup and source.
No product can start before this record and the real kernel controls succeed.

After READY, stdin accepts exactly `STOP\n` (including fragmented delivery), or
clean EOF without a partial command. Malformed/oversized input fails. EOF,
SIGTERM/SIGINT/SIGHUP or the original deadline initiates owned detach. Signal
handlers only set a flag; polling is capped at 250 ms. Stdout is nonblocking so
an undrained pipe cannot hold policy cleanup hostage. SIGPIPE is ignored.

The helper detaches only by its own retained program FDs, including partial-setup
rollback, then requires empty direct/effective hook queries and closes every
retained program/cgroup FD. On proven normal shutdown it emits exactly:

```json
{"schema":1,"kind":"kernel-policy","stopped":true,"detached":true}
```

The exit status is 0 only after READY, accepted shutdown, proven detach and
successful status writes. A deadline-triggered detach is not campaign success:
the controller must still reject late campaigns and prove product/resource
cleanup. Policy detach is not proof of cgroup emptiness or listener/process
absence. The controller stops product execution before intentional policy removal.

All helper errors use this closed object and exit 1 (no raw errno/verifier/path):

```json
{"schema":1,"kind":"kernel-policy","ready":false,"code":"cleanup_uncertain"}
```

Allowed codes: `arguments`, `authority`, `cgroup_identity`, `control_channel`,
`signals`, `policy_failed`, `cleanup_uncertain`, `self_test`. `ready:false` is
also the terminal failure format after an earlier READY. It revokes success;
never reinterpret it as a successful detach receipt. An unwritable stdout may
prevent any record; missing/malformed records and nonzero/signal exits fail.
SIGKILL cannot supply a detach receipt: exclusive cgroup attachments can survive
helper death. The warden must fail and perform independently owned cleanup, not
equate process disappearance or VM disposal with successful cleanup.

## Product credential/seccomp guard

```text
product-guard [--profile product|coordinator] --uid 20001 --gid 20001 -- /absolute/pinned/executable ARGS...
```

`product` is the default, preserving the existing case-init API unchanged.
An explicit `--profile product` selects exactly the same policy. Options may
appear in any order before `--`; unknown/missing profile values, unknown options,
duplicate options (even identical values), missing UID/GID or relative executables
fail as `arguments`, with no execution or policy fallback. Executable arguments
after `--` are never interpreted as guard options.

Product mode is invoked only by the pinned trusted root case init, as a direct
child of private-namespace PID 1; it must not itself be PID 1. Coordinator mode
may instead be the pinned container entrypoint (PID 1), or its direct child.
Both require real/effective UID 0 before dropping credentials. These are
precondition checks, not cryptographic identification of init: host admission
must pin the image/entrypoint/init and namespace identity independently. Never
expose this argv interface to the coordinator. Init builds only fixed selectors and acknowledges the pinned
read-only executable at its original absolute path. There is no PATH search or
shell. At most 128 executable/argument entries and 65,536 total bytes (including
NULs) are accepted. Only UID/GID 20001 are accepted, never root or arbitrary IDs.

Before `execv` it:

1. Sets hard/soft `RLIMIT_CORE` to zero, clears supplementary groups and drops
   all real/effective/saved GID/UID values to 20001, with identity readback.
2. Clears and reads back effective/permitted/inheritable capability words and
   clears/checks ambient capabilities. The bounding set is **not** claimed empty:
   init retains only SETUID/SETGID/KILL, not SETPCAP. Empty granted capabilities,
   verified `no_new_privs` and required non-suid mounts prevent privilege regain.
3. Closes every descriptor >= 3 with `close_range(3, UINT_MAX, 0)`. Failure is
   fatal; there is no guessed RLIMIT or racy `/proc` descriptor fallback.
   Init retains fixture reservation sockets; none reach the product. Init must
   provide only safe standard streams and a cleared, explicit product environment;
   the guard preserves that curated environment for fixed fixture configuration.
4. Installs a deny-default classic seccomp-BPF allowlist and executes directly.

The allowlist permits normal Rust/Wasmtime/OpenSSL/Python file, memory/JIT,
process, thread, signal, polling and TCP operations inside the independently
confined filesystem/PID/cgroup boundary in **product** mode. `socket` permits IPv4 TCP stream only
(protocol 0/6), or Unix stream/datagram/seqpacket (protocol 0); `socketpair` is
Unix-only. Only CLOEXEC/NONBLOCK type flags are allowed. IPv6, IPv4 UDP, raw,
packet, netlink and unknown socket variants are denied. The cgroup programs,
not seccomp pointer inspection, enforce exact IPv4 bind/connect destinations.

Legacy clone accepts only ordinary fork/thread flags via a positive mask; NEW*,
PTRACE, UNTRACED, PARENT, IO, high-word and unknown flags are denied. `clone3`
returns **ENOSYS** specifically to permit glibc's legacy-clone fallback.
`ioctl` permits only FIONBIO, FIONREAD, FIOCLEX, TCGETS, TIOCGWINSZ and TIOCGPGRP.
FIOCLEX is needed by CPython's file launcher to set close-on-exec on its script
descriptor. It reduces descriptor inheritance; FIONCLEX (clearing that bit) and
all other requests remain denied. The native self-test checks that distinction.
`prctl` permits only PR_SET_NAME/PR_GET_NAME for ordinary thread names, never
privilege, ptracer, capability or seccomp manipulation. Product `close_range`
permits flags zero/CLOEXEC only, not UNSHARE. Privileged namespace/kernel operations,
ptrace/process_vm, bpf, io_uring, capability/identity changes and unknown syscalls
are denied. Private-namespace fork/exec/thread and own-group signal operations
remain available for fixtures. These operations must not run in a host PID
namespace or with writable host/sibling mounts.

**Coordinator mode** uses exactly the same UID/GID, capability, core-limit,
descriptor and `no_new_privs` drops before installing its own policy and executing
the pinned Python planner. It grants none of the product socket permissions:
`socket`, `socketpair`, `connect`, `bind`, `listen`, `accept`, `accept4`,
`getsockname`, `getpeername`, `shutdown`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`,
`sendmmsg`, `recvmmsg`, `setsockopt` and `getsockopt` are all default-denied with
EPERM for every argument combination. Basic Python file/read/write/poll/memory/
exec syscalls remain available. Host admission must provide a private restricted
container with `--network=none`, safe pipe/file standard streams, no authority
descriptors/mounts and a fixed JSON-stdio planner; this is not a root Python class.
The coordinator's seccomp is installed before Python exec, so it needs no BPF
attachment before planner startup. Product-case network permission still requires
the separately attached exact-port cgroup BPF policy and actual kernel controls.
No profile adds a capability, privileged operation, path or permissive fallback.

Seccomp and cgroup network rejection return **EPERM**. Wrong ABI/x32 kills the
process rather than pretending to be EPERM. Missing files, EACCES, connection
refusal, timeout, ENETUNREACH and other errors do **not** prove the network policy
denied anything. The actual CI controls must observe the precise expected cause
and positive access; unknown/ambiguous outcomes fail. No errno-driven permissive
policy widening is allowed to obtain a compile or runtime pass.

Success emits no guard record: `execv` replaces it and the existing trusted
drainer owns product stdout/stderr. Failures emit only:

```json
{"schema":1,"kind":"product-guard","ok":false,"code":"seccomp"}
```

Allowed codes: `arguments`, `authority`, `policy_build`, `credentials`,
`no_new_privileges`, `descriptors`, `seccomp`, `exec`, `self_test`. Exit is 1;
the helper never prints errno, argv, paths, environment or stderr diagnostics.
After successful exec, exit/signal semantics belong to the product and are
interpreted with its exact required markers by init. A clean exit alone is not
an executed/passed test or a confinement/cleanup receipt.
