#!/usr/bin/env python3
"""Trusted PID-1 case supervisor. Explicit Linux runtime entry only.

No host Docker/cgroup/namespace authority; no import-time probes. Public output
contains only closed facts. See SUPERVISOR.md for the controller protocol.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import errno
import os
from pathlib import Path
import select
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time

if __package__:
    from . import protocol as P
elif __name__ == "__main__":
    sys.path.insert(0, "/opt")
    from managed_release_linux import protocol as P


@contextmanager
def product_fsuid(uid):
    """Runtime only: no CHOWN/DAC capability, no change to effective identity."""
    import ctypes
    library = ctypes.CDLL(None, use_errno=True)
    setfsuid = library.setfsuid
    setfsuid.argtypes = [ctypes.c_uint]
    setfsuid.restype = ctypes.c_int
    previous = setfsuid(uid)
    try:
        P.need(setfsuid(2**32 - 1) == uid, "fsuid-switch")
        yield
    finally:
        setfsuid(previous)
        P.need(setfsuid(2**32 - 1) == previous, "fsuid-restore")


class Deadlines:
    def __init__(self, descriptor):
        started, end = descriptor["case_started"], descriptor["campaign_end"]
        self.work = min(started + 220, end - 120)
        self.cleanup = min(started + 240, end)
        self.startup = None
        self.owner = None

    def launch(self, now):
        P.need(now < self.work and self.startup is None, "launch-deadline")
        self.startup = min(self.work, now + 40)
        self.owner = min(self.work, now + 185)


class Lifecycle:
    """Pure command/replay/late-ACK gate; no caller-supplied execution inputs."""
    def __init__(self, descriptor):
        self.case, self.nonce, self.kind = descriptor["case"], descriptor["nonce"], descriptor["kind"]
        self.deadlines = Deadlines(descriptor)
        self.phase, self.next_seq = "ready", 1
        self.pending_hash = None
        self.acked_hash = None

    def command(self, value, now):
        P.need(type(value) is dict, "command-object")
        kind = value.get("kind")
        P.need(type(kind) is str and kind in ("controls", "start", "identity-ack", "abort", "stop"),
               "command-kind")
        names = ("schema", "kind", "case", "nonce", "seq")
        P.exact(value, names + (("ledger_sha256",) if kind == "identity-ack" else ()))
        P.need(type(value["schema"]) is int and value["schema"] == 1
               and value["case"] == self.case and value["nonce"] == self.nonce
               and type(value["seq"]) is int and value["seq"] == self.next_seq,
               "command-binding-or-replay")
        P.need(now < self.deadlines.cleanup and self.phase != "stopped", "command-expired")
        if kind in ("abort", "stop"):
            self.phase = "stopped"
        else:
            P.need(now < self.deadlines.work, "command-work-deadline")
            if kind == "controls":
                P.need(self.phase == "ready", "controls-order")
                self.phase = "controlling"
            elif kind == "start":
                P.need(self.phase == "controlled" and self.kind != "isolation-controls", "start-order")
                self.deadlines.launch(now)
                self.phase = "running"
            else:
                P.need(self.phase == "running" and self.kind != "control-before-start"
                       and self.deadlines.startup is not None and now < self.deadlines.startup
                       and P.hash_text(value["ledger_sha256"])
                       and self.pending_hash == value["ledger_sha256"] and self.acked_hash is None,
                       "identity-ack-rejected")
                self.acked_hash = self.pending_hash
                self.pending_hash = None
        self.next_seq += 1
        return kind

    def controls_done(self):
        P.need(self.phase == "controlling", "controls-completion-order")
        self.phase = "controlled"

    def request_identity(self, digest):
        P.need(self.phase == "running" and self.kind != "control-before-start"
               and self.pending_hash is None and self.acked_hash is None and P.hash_text(digest),
               "identity-request-order")
        self.pending_hash = digest


class Channel:
    """Bounded nonblocking private stdin/stdout frames; never log input."""
    def __init__(self, descriptor, lifecycle):
        self.descriptor, self.lifecycle = descriptor, lifecycle
        self.pending, self.sequence = bytearray(), 1
        os.set_blocking(0, False)
        os.set_blocking(1, False)

    def send(self, kind, **fields):
        record = dict(schema=1, kind=kind, case=self.descriptor["case"],
                      nonce=self.descriptor["nonce"], seq=self.sequence, **fields)
        P.validate_event(record)
        data = P.encode_json(record) + b"\n"
        P.need(len(data) <= P.FRAME_LIMIT, "event-size")
        while data:
            remaining = self.lifecycle.deadlines.cleanup - time.monotonic()
            P.need(remaining > 0, "event-deadline")
            P.need(select.select([], [1], [], min(.1, remaining))[1] or remaining > .1,
                   "event-write-timeout")
            try:
                count = os.write(1, data)
                P.need(count > 0, "event-write")
                data = data[count:]
            except BlockingIOError:
                continue
        self.sequence += 1

    def poll(self):
        frames = []
        if select.select([0], [], [], 0)[0]:
            data = os.read(0, P.FRAME_LIMIT + 1)
            P.need(data, "warden-eof")
            self.pending.extend(data)
        while b"\n" in self.pending:
            line, _, rest = self.pending.partition(b"\n")
            P.need(len(line) + 1 <= P.FRAME_LIMIT, "command-size")
            frames.append(P.decode_json(bytes(line), P.FRAME_LIMIT - 1))
            self.pending = bytearray(rest)
            P.need(len(frames) <= 8, "command-burst")
        P.need(len(self.pending) < P.FRAME_LIMIT, "command-size")
        P.need(len(frames) <= 1, "command-pipelining-forbidden")
        return frames


class OwnedGroup:
    """Full captured birth, irreversible retirement, no ledger-only signal."""
    def __init__(self, identity, uid, child=None, authorized=True):
        P.validate_identity(identity)
        P.need(identity["alive"] and identity["pid"] == identity["pgid"]
               and identity["uid"] == uid, "group-capture")
        self.identity, self.child = identity, child
        self.authorized, self.retired = authorized, False
        self.reaped, self.sent = False, []
        self.wait_status = None
        self.exit_code = None

    def record_wait_status(self, status):
        """Reconcile PID-1 waitpid with Popen; never accept ECHILD's fake zero."""
        P.need(self.child is not None and self.wait_status is None
               and (os.WIFEXITED(status) or os.WIFSIGNALED(status)), "unexpected-child-wait-status")
        try:
            code = os.waitstatus_to_exitcode(status)
        except ValueError:
            raise P.ContractError("invalid-child-wait-status") from None
        self.wait_status, self.exit_code = status, code
        self.child.returncode = code
        self.reaped = True

    def wait_owned(self, end, reap):
        P.need(self.child is not None, "direct-child-wait-required")
        while self.wait_status is None and time.monotonic() < end:
            reap()
            if self.wait_status is None:
                time.sleep(.01)
        P.need(self.wait_status is not None and self.reaped, "actual-child-exit-status-required")
        return self.exit_code

    def absent(self):
        if self.retired:
            return True
        current = P.capture_local(self.identity["pid"])
        P.need(current is None or P.same_process(current, self.identity), "group-birth-mismatch")
        try:
            os.killpg(self.identity["pgid"], 0)
        except ProcessLookupError:
            self.retired = True
            return True
        # PermissionError and all other errors propagate, never absence.
        return False

    def send(self, number):
        P.need(self.authorized, "unacknowledged-group-no-signal")
        if self.absent():
            return
        current = P.capture_local(self.identity["pid"])
        P.need(current is None or P.same_process(current, self.identity), "group-birth-mismatch")
        try:
            os.killpg(self.identity["pgid"], number)
            self.sent.append(number)
        except ProcessLookupError:
            self.retired = True

    def stop(self, end, reap):
        reap()
        residual = not self.absent()
        if residual:
            self.send(signal.SIGTERM)
            grace = min(end, time.monotonic() + 1)
            while time.monotonic() < grace:
                reap()
                if self.absent():
                    break
                time.sleep(.01)
            if not self.absent():
                self.send(signal.SIGKILL)
        while time.monotonic() < end:
            reap()
            if self.absent():
                break
            time.sleep(.01)
        P.need(self.absent(), "owned-group-cleanup-incomplete")
        if self.child is not None:
            self.wait_owned(end, reap)
        else:
            reap()
            self.reaped = P.capture_local(self.identity["pid"]) is None
            P.need(self.reaped, "tls-leader-not-reaped")
        return residual


def guard_argv(descriptor, argv):
    return [P.PRODUCT_GUARD, "--uid", "20001", "--gid", "20001", "--"] + list(argv)


def clean_environment(root):
    # No inherited HOME, proxies, auth tokens, build credentials or caller env.
    return dict(HOME=str(root / "home"), TMPDIR=str(root / "tmp"),
                CARGO_HOME=str(root / "cargo-home"), PATH="/usr/bin:/bin",
                LC_ALL="C", RUST_BACKTRACE="0", AWS_EC2_METADATA_DISABLED="true",
                CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0",
                CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0")


def spawn_owned(descriptor, argv, env, end):
    child = subprocess.Popen(guard_argv(descriptor, argv), cwd=descriptor["source_root"],
        env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        close_fds=True, pass_fds=(), start_new_session=True)
    try:
        # Guard starts as root then switches credentials; do not capture the
        # transitional root identity as product authority. Do not reap before
        # capture. A dead/failed guard never authorizes a group signal.
        while time.monotonic() < end:
            identity = P.capture_local(child.pid)
            P.need(identity is not None and identity["alive"]
                   and identity["ppid"] == os.getpid() and identity["pgid"] == child.pid,
                   "spawn-parent-or-liveness")
            if identity["uid"] == descriptor["product_uid"]:
                return child, OwnedGroup(identity, descriptor["product_uid"], child)
            P.need(identity["uid"] == 0, "spawn-uid")
            time.sleep(.001)
        raise P.ContractError("spawn-credential-deadline")
    except Exception:
        # The still-held direct child object is the sole authority here. Never
        # turn failed capture into os.killpg(child.pid, ...).
        if child.poll() is None:
            child.kill()
        child.wait(timeout=max(.001, end - time.monotonic()))
        for stream in (child.stdout, child.stderr):
            if stream is not None:
                stream.close()
        raise


def file_hash(path, limit, end=None):
    import hashlib
    path = Path(path)
    P.need(path.is_absolute() and path.resolve(strict=True) == path, "artifact-path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        P.need(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "artifact-size-type")
        digest, count = hashlib.sha256(), 0
        while True:
            P.need(end is None or time.monotonic() < end, "artifact-read-deadline")
            data = os.read(fd, 1024 * 1024)
            if not data:
                break
            count += len(data)
            P.need(count <= limit, "artifact-growth")
            digest.update(data)
        after = os.fstat(fd)
        P.need(count == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
               == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "artifact-changed")
        return digest.hexdigest()
    finally:
        os.close(fd)


def validate_init_capabilities(status):
    names = ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd")
    P.exact(status, names)
    try:
        values = {key: int(value, 16) for key, value in status.items()}
    except (TypeError, ValueError):
        raise P.ContractError("init-capabilities") from None
    # Linux CAP_KILL=5, CAP_SETGID=6, CAP_SETUID=7. No DAC/CHOWN/SYS_ADMIN.
    allowed = (1 << 5) | (1 << 6) | (1 << 7)
    P.need(values == dict(CapEff=allowed, CapPrm=allowed, CapInh=0,
                          CapAmb=0, CapBnd=allowed), "init-capabilities")


def check_init_capabilities():
    with open("/proc/self/status", "r", encoding="ascii") as stream:
        data = stream.read(16385)
    P.need(len(data) <= 16384, "init-status-size")
    result = {}
    for line in data.splitlines():
        name, separator, value = line.partition(":")
        if separator and name in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"):
            P.need(name not in result, "init-status-duplicate")
            result[name] = value.strip()
    validate_init_capabilities(result)


class Supervisor:
    def __init__(self, descriptor, channel=None):
        self.descriptor = P.validate_descriptor(descriptor)
        self.lifecycle = Lifecycle(self.descriptor)
        self.deadlines = self.lifecycle.deadlines
        self.channel = channel  # instantiated explicitly by run(), not import
        self.root = Path(descriptor["root"])
        self.uid = descriptor["product_uid"]
        self.reservations, self.ports = {}, {}
        self.main = self.tls = self.probe_group = None
        self.child = None
        self.binding = self.ledger_hash = None
        self.ports_released = self.control_injected = self.control_exit_gate = False
        self.descendant = None
        self.result_sent = False
        self.cancelled = False
        self.out = self.err = None
        self.probe_results = None
        self.controls_attempted = self.controls_sent = False
        self.control = dict(before_start_eof=False, descendant_live_after_leader_exit=False,
                            descendant_sigkill=False, strict_provider=False,
                            deadline_contract=False, python_mocks=False,
                            slow_peer=False, isolation_controls=False, python_tests_run=0)

    def install_handlers(self):
        # Explicit runtime only. A second signal cannot interrupt owned cleanup.
        def cancelled(_number, _frame):
            self.cancelled = True
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(number, cancelled)

    @contextmanager
    def private(self):
        with product_fsuid(self.uid):
            yield

    def read_bytes(self, name, limit=4096):
        with self.private():
            return P.read_private_bytes(self.root / name, self.uid, limit)

    def read(self, name, optional=False):
        try:
            return P.decode_json(self.read_bytes(name), 4096)
        except FileNotFoundError:
            if optional:
                return None
            raise

    def write(self, name, value):
        with self.private():
            P.atomic_record(self.root / name, value)

    def initialize(self):
        P.need(sys.platform.startswith("linux") and os.getpid() == 1 and os.geteuid() == 0,
               "isolated-root-pid1-required")
        check_init_capabilities()
        now = time.monotonic()
        P.need(self.descriptor["case_started"] <= now < self.deadlines.work, "case-already-expired")
        for name in ("source_root", "executable", "root"):
            path = Path(self.descriptor[name])
            # root requires fsuid to traverse if ancestors are private product dirs.
            with self.private() if name == "root" else _nothing():
                P.need(path.resolve(strict=True) == path, "runtime-canonical-path")
        source = Path(self.descriptor["source_root"])
        pins = {
            "executable_sha256": (Path(self.descriptor["executable"]), 2 * 2**30),
            "tls_sha256": (source / "scripts/tests/managed_release_tls.py", 2**20),
            "python_test_sha256": (source / "scripts/tests/test_managed_release_tls.py", 2**20),
            "product_guard_sha256": (Path(P.PRODUCT_GUARD), 2**20),
            "protocol_sha256": (Path(P.MODULE_ROOT) / "protocol.py", 2**20),
            "supervisor_sha256": (Path(P.MODULE_ROOT) / "supervisor.py", 2**20),
            "probe_sha256": (Path(P.MODULE_ROOT) / "probe.py", 2**20),
        }
        for key, (path, limit) in pins.items():
            P.need(file_hash(path, limit, self.deadlines.work) == self.descriptor["inputs"][key], "runtime-input-mismatch")
            P.need(not self.cancelled and time.monotonic() < self.deadlines.work, "input-verification-deadline")
        with self.private():
            meta = self.root.stat()
            P.need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == self.uid
                   and stat.S_IMODE(meta.st_mode) == 0o700, "case-root-private")
            for name in ("home", "tmp", "spool", "staging", "cargo-home"):
                path = self.root / name
                try:
                    path.mkdir(mode=0o700)
                except FileExistsError:
                    pass
                child_meta = path.lstat()
                P.need(stat.S_ISDIR(child_meta.st_mode) and child_meta.st_uid == self.uid
                       and stat.S_IMODE(child_meta.st_mode) == 0o700
                       and path.resolve(strict=True) == path, "case-directory-private")
        self.reserve()

    def reserve(self):
        try:
            for role in P.case_roles(self.descriptor["kind"]):
                connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.reservations[role] = connection  # owned before any failure
                connection.set_inheritable(False)
                connection.bind(("127.0.0.1", 0))
                host, port = connection.getsockname()
                P.need(host == "127.0.0.1" and P.valid_port(port)
                       and port not in self.ports.values()
                       and (self.descriptor["pg"] is None or port != self.descriptor["pg"]["port"]),
                       "reservation-not-declared-port")
                self.ports[role] = port
        except Exception:
            self.close_reservations()
            raise

    def close_reservations(self):
        for connection in self.reservations.values():
            connection.close()
        self.reservations.clear()

    def reap(self):
        # PID 1 reaps adopted descendants, but discovery never authorizes a
        # signal. Use raw wait statuses for held direct children, NOT Popen.poll
        # (its ECHILD fallback fabricates returncode=0). Reconcile every status,
        # including a main that exits between the direct and generic waits.
        direct = {}
        for group in (self.main, self.probe_group):
            if group is not None and group.child is not None and group.wait_status is None:
                pid = group.identity["pid"]
                P.need(pid not in direct, "ambiguous-held-child")
                direct[pid] = group
                try:
                    waited, status = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    raise P.ContractError("direct-child-status-lost") from None
                if waited:
                    P.need(waited == pid, "direct-child-wait-pid")
                    group.record_wait_status(status)
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if pid == 0:
                break
            if pid in direct:
                direct[pid].record_wait_status(status)
            elif self.tls is not None and pid == self.tls.identity["pid"]:
                self.tls.reaped = True

    def stop_binding(self):
        return dict(schema=1, case=self.descriptor["case"], nonce=self.descriptor["nonce"],
                    ledger_sha256=self.ledger_hash)

    def publish_parent(self):
        self.write("owned-main-group.json", self.main.identity)
        self.write("owned-ports.json", dict(schema=1, case=self.descriptor["case"],
            nonce=self.descriptor["nonce"], host="127.0.0.1", ports=self.ports))
        self.write("owned-case-parent.json", dict(schema=1, case=self.descriptor["case"],
            nonce=self.descriptor["nonce"], root_uid=self.uid, test_identity=self.main.identity))
        self.binding = dict(schema=1, case=self.descriptor["case"], nonce=self.descriptor["nonce"],
            parent_sha256=P.sha(self.read_bytes("owned-case-parent.json")),
            ports_sha256=P.sha(self.read_bytes("owned-ports.json", 1024)))

    def accept_tls_ledger(self, ledger, raw):
        P.exact(ledger, ("schema", "kind", "case", "nonce", "root_uid", "ports_sha256",
                         "test_identity", "tls_identity"))
        P.need(type(ledger["schema"]) is int and ledger["schema"] == 2
               and ledger["kind"] == "owned-managed-release-tls"
               and ledger["case"] == self.descriptor["case"] and ledger["nonce"] == self.descriptor["nonce"]
               and type(ledger["root_uid"]) is int and ledger["root_uid"] == self.uid
               and ledger["ports_sha256"] == self.binding["ports_sha256"]
               and ledger["test_identity"] == self.main.identity, "tls-ledger-binding")
        P.validate_identity(ledger["test_identity"])
        candidate = P.validate_identity(ledger["tls_identity"])
        P.need(candidate["alive"] and candidate["ppid"] == self.main.identity["pid"]
               and candidate["pid"] == candidate["pgid"] and candidate["uid"] == self.uid
               and candidate["pid"] != self.main.identity["pid"], "tls-ledger-scope")
        before = P.capture_local(self.main.identity["pid"])
        actual = P.capture_local(candidate["pid"])
        after = P.capture_local(self.main.identity["pid"])
        P.need(before == self.main.identity == after and actual == candidate, "tls-local-verification")
        self.ledger_hash = P.sha(raw)
        self.tls = OwnedGroup(actual, self.uid, authorized=False)
        if self.descriptor["kind"] == "control-before-start":
            # Never ACK/START/signal TLS. EOF on its parent's pipe must suffice.
            self.main.send(signal.SIGKILL)
            self.control_injected = True
        else:
            self.lifecycle.request_identity(self.ledger_hash)
            self.channel.send("identity-request", test_identity=self.main.identity,
                              tls_identity=self.tls.identity, ledger_sha256=self.ledger_hash)

    def identity_ack(self):
        P.need(self.tls is not None and self.lifecycle.acked_hash == self.ledger_hash,
               "tls-ack-not-requested")
        # Recheck live full identities after host response, before irreversible ACK.
        P.need(P.capture_local(self.main.identity["pid"]) == self.main.identity
               and P.capture_local(self.tls.identity["pid"]) == self.tls.identity
               and time.monotonic() < self.deadlines.startup, "tls-ack-stale")
        self.tls.authorized = True
        self.write("owned-tls-ack.json", self.stop_binding())

    def observe(self):
        kind = self.descriptor["kind"]
        if not self.ports_released:
            P.need(time.monotonic() < self.deadlines.startup, "startup-original-budget")
            ready = self.read("owned-case-ready.json", optional=True)
            if ready is not None:
                P.need(P.equal_record(ready, self.binding) and P.capture_local(self.main.identity["pid"]) == self.main.identity,
                       "port-handoff-parent-binding")
                self.close_reservations()
                self.write("owned-port-handoff.json", self.binding)
                self.ports_released = True
        if kind == "slow-peer":
            return
        if self.tls is None:
            try:
                raw = self.read_bytes("owned-tls-group.json")
            except FileNotFoundError:
                P.need(time.monotonic() < self.deadlines.startup, "tls-registration-deadline")
            else:
                P.need(time.monotonic() < self.deadlines.startup, "tls-registration-deadline")
                self.accept_tls_ledger(P.decode_json(raw, 4096), raw)
        if self.tls is not None and self.tls.authorized:
            stop = self.read("owned-tls-stop.json", optional=True)
            if stop is not None:
                P.need(P.equal_record(stop, self.stop_binding()), "tls-stop-binding")
                self.tls.stop(min(self.deadlines.cleanup, time.monotonic() + 3), self.reap)
        if kind == "control-descendant" and self.tls is not None and self.tls.authorized and not self.control_injected:
            self.observe_descendant()

    def observe_descendant(self):
        record = self.read("owned-control-descendant.json", optional=True)
        listeners = self.read("owned-listeners.json", optional=True)
        if record is None or listeners is None or listeners.get("tls") is None:
            return
        P.exact(record, ("schema", "case", "nonce", "ports_sha256", "identity"))
        descendant = P.validate_identity(record["identity"])
        P.need(type(record["schema"]) is int and record["schema"] == 1
               and record["case"] == self.descriptor["case"] and record["nonce"] == self.descriptor["nonce"]
               and record["ports_sha256"] == self.binding["ports_sha256"]
               and descendant["ppid"] == self.tls.identity["pid"]
               and descendant["pgid"] == self.tls.identity["pgid"]
               and descendant["uid"] == self.uid and descendant["alive"], "descendant-binding")
        if not self.control_exit_gate:
            P.need(P.capture_local(descendant["pid"]) == descendant
                   and P.capture_local(self.tls.identity["pid"]) == self.tls.identity, "descendant-live-parent")
            self.descendant = descendant
            self.write("owned-control-exit.json", dict(schema=1, case=self.descriptor["case"],
                nonce=self.descriptor["nonce"], ports_sha256=self.binding["ports_sha256"]))
            self.control_exit_gate = True
        else:
            P.need(descendant == self.descendant, "descendant-record-changed")
        exited = self.read("owned-control-leader-exited.json", optional=True)
        if exited is not None:
            current = P.capture_local(descendant["pid"])
            P.need(P.equal_record(exited, self.stop_binding()) and P.capture_local(self.tls.identity["pid"]) is None
                   and P.same_process(current, descendant) and current["alive"]
                   and not self.tls.absent(), "descendant-after-leader-exit")
            with socket.create_connection(("127.0.0.1", self.ports["tls"]), timeout=.15):
                pass
            self.control["descendant_live_after_leader_exit"] = True
            self.main.send(signal.SIGKILL)
            self.control_injected = True

    def poll_commands(self, allow_controls=False):
        for value in self.channel.poll():
            command = self.lifecycle.command(value, time.monotonic())
            if command in ("abort", "stop"):
                raise P.ContractError("warden-stop-or-abort")
            if command == "identity-ack":
                self.identity_ack()
            else:
                P.need(allow_controls, "unexpected-active-command")
                return command
        return None

    def pump(self, child, out, err, end, observer=None):
        with selectors.DefaultSelector() as selected:
            for stream, sink in ((child.stdout, out), (child.stderr, err)):
                os.set_blocking(stream.fileno(), False)
                selected.register(stream, selectors.EVENT_READ, sink)
            while selected.get_map():
                P.need(not self.cancelled and time.monotonic() < end, "owned-command-deadline")
                self.poll_commands()
                if observer is not None:
                    observer()
                for key, _events in selected.select(.01):
                    data = os.read(key.fd, 16384)
                    if data:
                        key.data.feed(data)
                        P.need(not key.data.bad, "closed-output-rejected")
                    else:
                        selected.unregister(key.fileobj)
                        key.fileobj.close()
            if observer is not None:
                observer()

    def run_controls(self):
        self.controls_attempted = True
        kind = self.descriptor["kind"]
        listener = None
        positive = self.descriptor["pg"]["port"] if self.descriptor["pg"] is not None else None
        if kind == "isolation-controls":
            listener = self.reservations["provider"]
            listener.listen(1)
            listener.setblocking(False)
            positive = self.ports["provider"]
        declared = set(self.ports.values()) | {positive, 5432, 54322}
        denied_port = next(port for port in range(1024, 65536) if port not in declared)
        self.write("owned-probe.json", dict(schema=1, root=str(self.root), uid=self.uid, gid=self.uid,
            loopback_port=positive, denied_port=denied_port))
        digest = P.sha(self.read_bytes("owned-probe.json"))
        argv = ["/usr/bin/python3", "-I", "-B", P.MODULE_ROOT + "/probe.py",
                "--contract", str(self.root / "owned-probe.json"), "--sha256", digest]
        end = min(self.deadlines.work, time.monotonic() + 40)
        env = clean_environment(self.root)
        child, self.probe_group = spawn_owned(self.descriptor, argv, env, end)
        env.clear()
        out, err = P.JsonDrain(), P.ClosedDrain(stderr=True)
        accepted = False

        def service_listener():
            nonlocal accepted
            if listener is not None:
                try:
                    connection, address = listener.accept()
                except BlockingIOError:
                    return
                with connection:
                    P.need(address[0] == "127.0.0.1" and not accepted, "probe-positive-peer")
                    accepted = True

        try:
            self.pump(child, out, err, end, service_listener)
            P.need(self.probe_group.wait_owned(end, self.reap) == 0, "isolation-probe-failed")
            record = out.finish("probe")
            err.finish()
            expected = {key: True for key in P.PROBE_FIELDS}
            expected["owned_loopback"] = positive is not None
            P.need(record["results"] == expected and (listener is None or accepted), "probe-incomplete")
            P.need(not self.probe_group.stop(min(self.deadlines.cleanup, time.monotonic() + 3), self.reap),
                   "probe-left-descendants")
            self.probe_results = expected
            self.lifecycle.controls_done()
            self.channel.send("controls", passed=True, results=expected)
            self.controls_sent = True
        finally:
            for stream in (child.stdout, child.stderr):
                if stream is not None:
                    stream.close()

    def run_product(self):
        kind = self.descriptor["kind"]
        env = clean_environment(self.root)
        if P.case_roles(kind):
            env.update(MASKURA_RELEASE_ROOT=str(self.root), MASKURA_RELEASE_CASE=self.descriptor["case"])
        if kind == "product":
            pg = self.descriptor["pg"]
            target = dict(schema=1, case=self.descriptor["case"], nonce=self.descriptor["nonce"],
                          **{key: pg[key] for key in ("host", "port", "user", "database")})
            self.write("owned-target.json", target)
            env["DATABASE_URL"] = "postgresql://managed_release:" + pg["password"] + "@127.0.0.1:" + str(pg["port"]) + "/" + pg["database"]
            self.out = P.ClosedDrain(case=self.descriptor["case"])
        elif kind in ("slow-peer", "python-mocks"):
            self.out = P.JsonDrain()
        elif kind in ("control-before-start", "control-descendant"):
            self.out = P.ClosedDrain(discard=True)
        else:
            self.out = P.ClosedDrain(selector=P.CONTROL_SELECTORS[kind])
        self.err = P.ClosedDrain(stderr=True)
        try:
            self.child, self.main = spawn_owned(self.descriptor, P.fixed_argv(self.descriptor), env,
                                               self.deadlines.startup)
        finally:
            env.clear()
        self.write("owned-main-group.json", self.main.identity)
        has_ports = bool(P.case_roles(kind))
        if has_ports:
            self.publish_parent()
        self.pump(self.child, self.out, self.err, self.deadlines.owner, self.observe if has_ports else None)
        code = self.main.wait_owned(self.deadlines.owner, self.reap)
        if kind in ("control-before-start", "control-descendant"):
            P.need(self.control_injected and code == -signal.SIGKILL, "negative-control-not-injected")
            self.out.finish()
        else:
            P.need(code == 0, "exact-test-process-failed")
            if kind in ("slow-peer", "python-mocks"):
                self.out.finish(kind)
            else:
                self.out.finish()
        self.err.finish()
        if kind == "strict-provider":
            self.control["strict_provider"] = True
        elif kind == "deadline-contract":
            self.control["deadline_contract"] = True
        elif kind == "python-mocks":
            self.control["python_mocks"] = True
            self.control["python_tests_run"] = 5
        elif kind == "slow-peer":
            self.control["slow_peer"] = True
        P.need(time.monotonic() < self.deadlines.owner, "owner-185-budget")
        P.need(not self.main.stop(min(self.deadlines.cleanup, time.monotonic() + 3), self.reap),
               "main-left-descendants")
        if kind in ("product", "control-before-start", "control-descendant"):
            P.need(self.tls is not None, "missing-tls-identity")
            if self.tls.authorized:
                self.tls.stop(min(self.deadlines.cleanup, time.monotonic() + 3), self.reap)
            else:
                self.wait_unacked_tls()
            if kind == "control-descendant":
                self.control["descendant_sigkill"] = signal.SIGKILL in self.tls.sent
                P.need(self.control["descendant_live_after_leader_exit"]
                       and self.control["descendant_sigkill"], "descendant-kill-not-exercised")
        if has_ports:
            self.validate_listeners()
            self.listeners_closed()
        P.need(time.monotonic() < self.deadlines.work, "original-case-work-budget")

    def wait_unacked_tls(self):
        end = min(self.deadlines.cleanup, time.monotonic() + 3)
        while time.monotonic() < end:
            self.reap()
            if self.tls.absent():
                break
            time.sleep(.01)
        P.need(self.tls.absent() and not self.tls.sent
               and P.capture_local(self.tls.identity["pid"]) is None, "prestart-eof-absence")
        self.tls.reaped = True
        if self.descriptor["kind"] == "control-before-start":
            with self.private():
                # lstat errors other than ENOENT must fail, not imply absence.
                for name in ("tls", "owned-tls-listener.json", "owned-tls-ack.json"):
                    try:
                        (self.root / name).lstat()
                    except FileNotFoundError:
                        pass
                    else:
                        raise P.ContractError("prestart-created-tls-state")
            self.control["before_start_eof"] = True

    def validate_listeners(self):
        kind = self.descriptor["kind"]
        if kind == "slow-peer":
            record = self.read("owned-slow-listeners.json")
            P.need(P.equal_record(record, dict(schema=1, case=self.descriptor["case"], nonce=self.descriptor["nonce"],
                ports_sha256=self.binding["ports_sha256"], ports=[self.ports[role] for role in P.SLOW_ROLES])),
                "slow-listener-binding")
            return
        record = self.read("owned-listeners.json")
        P.exact(record, ("schema", "case", "nonce", "ports_sha256", "provider", "tls", "gateway", "closed"))
        P.need(type(record["schema"]) is int and record["schema"] == 1
               and record["case"] == self.descriptor["case"] and record["nonce"] == self.descriptor["nonce"]
               and record["ports_sha256"] == self.binding["ports_sha256"], "listener-ledger-binding")
        address = lambda role: dict(host="127.0.0.1", port=self.ports[role])
        P.need(record["provider"] == address("provider")
               and record["gateway"] == [address(role) for role in P.ROLES[2:]], "listener-addresses")
        if kind in ("product", "control-descendant"):
            P.need(record["tls"] == address("tls"), "tls-listener-address")
        else:
            P.need(record["tls"] is None, "prestart-listener-appeared")
        if kind == "product":
            P.need(record["closed"] == list(P.ROLES), "fixture-listeners-closed-marker")

    def listeners_closed(self):
        for port in self.ports.values():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                connection.settimeout(.15)
                P.need(connection.connect_ex(("127.0.0.1", port)) == errno.ECONNREFUSED,
                       "listener-closure-not-proved")
        return True

    def cleanup(self):
        facts = dict(main_group_absent=False, main_reaped=False, tls_group_absent=False,
                     tls_reaped=False, listeners_closed=False, reservations_closed=False,
                     within_deadline=False)
        failed = False
        for group in (self.probe_group, self.main, self.tls):
            if group is None:
                continue
            try:
                if group is self.tls and not group.authorized:
                    self.wait_unacked_tls()
                else:
                    group.stop(min(self.deadlines.cleanup, time.monotonic() + 3), self.reap)
            except Exception:
                failed = True
        try:
            self.close_reservations()
            facts["reservations_closed"] = True
        except Exception:
            failed = True
        try:
            self.reap()
            facts["main_group_absent"] = self.main is None or self.main.absent()
            facts["main_reaped"] = self.main is None or self.main.reaped
            facts["tls_group_absent"] = self.tls is None or self.tls.absent()
            facts["tls_reaped"] = self.tls is None or self.tls.reaped
            facts["listeners_closed"] = self.listeners_closed()
        except Exception:
            failed = True
        facts["within_deadline"] = time.monotonic() < self.deadlines.cleanup
        if self.probe_group is not None:
            try:
                failed |= not (self.probe_group.absent() and self.probe_group.reaped)
            except Exception:
                failed = True
        for group in (self.main, self.probe_group):
            if group is not None and group.child is not None:
                for stream in (group.child.stdout, group.child.stderr):
                    if stream is not None:
                        stream.close()
        return facts, not failed and all(facts.values())

    def emit_result(self, passed, status, cleanup):
        self.result_sent = True
        self.lifecycle.phase = "result"
        counts = self.out.counts if isinstance(self.out, P.ClosedDrain) else dict(
            selected=0, passed=0, summary=0, complete=0, shutdown=0)
        locations = self.err.panic_locations if self.err is not None else []
        self.channel.send("case-result", passed=passed, status=status, counts=counts,
                          panic_locations=locations, cleanup=cleanup, control=self.control)

    def wait_stop(self):
        while time.monotonic() < self.deadlines.cleanup:
            P.need(not self.cancelled, "init-cancelled")
            self.reap()
            for value in self.channel.poll():
                command = self.lifecycle.command(value, time.monotonic())
                P.need(command == "stop", "stop-required-after-result")
                return
            time.sleep(.01)
        raise P.ContractError("stop-original-deadline")

    def run(self):
        passed = False
        status = "failed"
        try:
            self.initialize()
            if self.channel is None:
                self.channel = Channel(self.descriptor, self.lifecycle)
            self.channel.send("ready", ports=self.ports)
            while time.monotonic() < self.deadlines.work:
                P.need(not self.cancelled, "init-cancelled")
                command = self.poll_commands(allow_controls=True)
                if command == "controls":
                    self.run_controls()
                    if self.descriptor["kind"] == "isolation-controls":
                        self.control["isolation_controls"] = True
                        passed = True
                        break
                elif command == "start":
                    self.run_product()
                    passed = True
                    break
                time.sleep(.01)
            P.need(passed, "case-work-expired")
            status = "passed"
        except Exception:
            # Never expose raw exceptions, descriptor fields, env, paths or logs.
            passed = False
        finally:
            cleanup, complete = self.cleanup()
            passed &= complete and not self.cancelled
            if self.cancelled:
                status = "failed"
            if not complete:
                status = "cleanup-incomplete"
            if self.descriptor["pg"] is not None:
                self.descriptor["pg"]["password"] = None
            try:
                if self.channel is not None:
                    if self.controls_attempted and not self.controls_sent:
                        # False includes unproved/unknown, never fabricated
                        # positive evidence. Send only after owned cleanup.
                        self.channel.send("controls", passed=False,
                                          results={key: False for key in P.PROBE_FIELDS})
                        self.controls_sent = True
                    self.emit_result(bool(passed), status, cleanup)
            except Exception:
                passed = False
        try:
            # Preserve PID 1 until independent host proc-set inspection and STOP.
            if self.channel is not None:
                self.wait_stop()
            else:
                passed = False
        except Exception:
            passed = False
        return 0 if passed else 1


@contextmanager
def _nothing():
    yield


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--descriptor", required=True, choices=(P.DESCRIPTOR_PATH,))
    args = parser.parse_args(argv)
    try:
        P.need(sys.platform.startswith("linux") and os.getpid() == 1 and os.geteuid() == 0,
               "runtime-boundary-required")
        data = P.read_private_bytes(args.descriptor, 0, P.DESCRIPTOR_LIMIT, mode=0o400)
        descriptor = P.validate_descriptor(P.decode_json(data, P.DESCRIPTOR_LIMIT))
        supervisor = Supervisor(descriptor)
        # Drop redundant private transport references before the long runtime.
        data = b""
        if descriptor["pg"] is not None:
            descriptor["pg"]["password"] = None
        supervisor.install_handlers()
        return supervisor.run()
    except Exception:
        # An invalid descriptor supplies no safe case/nonce to echo.
        return 2


if __name__ == "__main__":
    sys.exit(main())
