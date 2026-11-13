# SPDX-License-Identifier: Apache-2.0
"""Source-bound Linux qualification. Importing this module has no side effects.

The coordinator is a separate non-root, networkless container. Only Warden runs
on the disposable host with Docker/cgroup authority. No coordinator field is
ever incorporated into argv, a path, an environment, or a Docker identifier.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, ROUND_FLOOR
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid


PG_IMAGE = "postgres:17-trixie@sha256:e38411452a464af89e5adadb8d223bf53b898d47d6ef918b2d58c08707350449"
BASE_IMAGE = "debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f"
PRODUCT_UID = 20001
PG_UID = 999
GIB = 1024 ** 3
PG_BYTES = 5 * GIB
FREE_BYTES = 12 * GIB
MIN_MEMORY = 7 * GIB
FRAME_BYTES = 8192
PREP_SECONDS = 1200
CAMPAIGN_SECONDS = 3600
CLEANUP_RESERVE = 120
CASE_SECONDS = 240
CASE_CLEANUP = 20
STARTUP_SECONDS = 40
MAX_ACTIVE = 4
LABEL = "org.maskura.managed-release"
HARNESS = Path("/opt/managed_release_linux")
DESCRIPTOR = "/run/maskura/descriptor.json"
PREP_DIR = ".managed-release-prepared"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SOURCE_SHA = re.compile(r"[0-9a-f]{40}\Z")
DOCKER_ID = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
CASES = (
    "http", "recovery-valid", "recovery-customer", "recovery-content-type",
    "recovery-encoding", "recovery-identity", "recovery-codec",
    "recovery-physical-key", "recovery-versioning", "repair-valid",
    "repair-source-mismatch", "tls-unrelated-ca", "tls-wrong-numeric-san",
)
CONTROLS = ("isolation-controls", "control-before-start", "control-descendant",
            "strict-provider", "deadline-contract", "python-mocks", "slow-peer")
FIXTURES = tuple("tests/fixtures/pii/" + name for name in (
    "sample1.txt", "sample1.expected.txt", "sample2.jsonl", "sample2.expected.jsonl",
    "sample3.csv", "sample3.expected.csv", "comprehensive.jsonl"))
HELPERS = ("controller.py", "coordinator.py", "protocol.py", "supervisor.py", "probe.py",
           "product_guard.c", "kernel_guard.c")
INPUT_NAMES = ("executable_sha256", "tls_sha256", "python_test_sha256",
               "product_guard_sha256", "protocol_sha256", "supervisor_sha256", "probe_sha256")
COORDINATOR_ENTRYPOINT = "/usr/local/bin/maskura-product-guard"
SCRIPT_PATH = "/opt/managed_release_linux/coordinator.py"
# Launch through the proven -c path: before the narrow FIOCLEX allowance,
# CPython's file-argument runner received EPERM while open() inside -c worked.
# Native tracing identified that launcher difference. This fixed
# bootstrap opens the real module with that proven primitive and executes it
# with script-mode semantics; it accepts no caller input.
COORDINATOR_BOOTSTRAP = (
    "import sys\n"
    "p='" + SCRIPT_PATH + "'\n"
    "sys.argv[0]=p\n"
    "with open(p,'rb') as f:\n"
    " src=f.read()\n"
    "g={'__name__':'__main__','__file__':p,'__package__':None,'__cached__':None,"
    "'__spec__':None,'__doc__':None,'__builtins__':__builtins__}\n"
    "exec(compile(src,p,'exec'),g)\n"
)
COORDINATOR_COMMAND = ("--uid", "20001", "--gid", "20001", "--profile", "coordinator",
                       "--", "/usr/bin/python3", "-I", "-B", "-c", COORDINATOR_BOOTSTRAP,
                       "--plan", "/run/maskura/plan.json")
SCRIPT_OPEN_FAILURES = frozenset((
    "coordinator-script-missing", "coordinator-script-permission",
    "coordinator-script-policy", "coordinator-script-unopened",
))
# Fixed, caller-independent preflight source: it opens the real coordinator
# script under the exact guard/init-seccomp/uid context and prints only closed
# metadata (booleans, errno integers, octal mode strings, uids).
SCRIPT_PREFLIGHT_CODE = (
    "import json,os,stat,sys\n"
    "path='" + SCRIPT_PATH + "'\n"
    "out={'schema':1,'kind':'coordinator-script-preflight','opened':False,'open_errno':None,"
    "'mode':None,'uid':None,'gid':None,'dir_mode':None,'dir_uid':None}\n"
    "try:\n"
    " info=os.stat(os.path.dirname(path))\n"
    " out['dir_mode']=oct(stat.S_IMODE(info.st_mode))[2:];out['dir_uid']=info.st_uid\n"
    "except OSError as error:\n"
    " out['dir_errno']=error.errno\n"
    "try:\n"
    " info=os.stat(path)\n"
    " out['mode']=oct(stat.S_IMODE(info.st_mode))[2:];out['uid']=info.st_uid;out['gid']=info.st_gid\n"
    "except OSError as error:\n"
    " out['stat_errno']=error.errno\n"
    "try:\n"
    " with open(path,'rb') as stream:\n"
    "  stream.read(1)\n"
    " out['opened']=True\n"
    "except OSError as error:\n"
    " out['open_errno']=error.errno\n"
    "sys.stdout.write(json.dumps(out,sort_keys=True,separators=(',',':'))+'\\n')\n"
)
# Bounded startup-stderr classification: only these fixed byte markers are
# inspected; raw bytes are discarded after mapping and never exported.
STDERR_LIMIT = 8192
STDERR_CLASSES = (
    (b"can't open file", "coordinator-script-unopened"),
    (b"coordinator.py: error:", "coordinator-argparse-uncaught"),
    (b"Traceback (most recent call last)", "coordinator-interpreter-traceback"),
    (b"Unknown option", "coordinator-interpreter-argv"),
    (b"usage:", "coordinator-interpreter-argv"),
    (b"Error response from daemon", "coordinator-adapter-error"),
    (b"OCI runtime", "coordinator-runtime-error"),
)
SOURCEALLOWLIST = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
                   "Dockerfile.managed-tests", "crates/", "plugins/", "migrations/",
                   "scripts/managed_release_linux/", "scripts/managed-release-linux.py",
                   "scripts/tests/managed_release_tls.py", "scripts/tests/test_managed_release_tls.py")


class Refused(RuntimeError):
    """Only closed categories, never upstream text or product output."""


GUARD_STARTUP_CODES = ("arguments", "authority", "policy_build", "credentials",
                       "no_new_privileges", "descriptors", "seccomp", "exec", "self_test")
COORDINATOR_STARTUP_CODES = ("arguments", "identity", "network", "plan", "request",
                             "internal", "interpreter")

CLOSED_FAILURES = frozenset((
    "command-failed", "command-deadline", "command-output-bound", "command-transport",
    "source-dirty", "source-head-mismatch", "source-kind-invalid", "source-input-missing",
    "native-linux-amd64-required", "rootfs-native-abi", "postgres-digest-mismatch",
    "runtime-image-changed", "cgroup-v2-required", "filesystem-floor",
    "four-slot-memory-admission", "docker-security-capabilities", "mount-flags-unproved",
    "host-mount-flags-unproved", "channel-eof", "channel-deadline", "campaign-cancelled",
    "case-or-cleanup-failed", "cleanup-unproved", "pending-creation-cleanup-unproved",
    "host-mount-users-cleanup-unproved", "case-host-mount-cleanup-unproved",
    "creation-request-unresolved",
    "coordinator-frame", "coordinator-capabilities", "coordinator-seccomp",
    "coordinator-host-namespace", "coordinator-extra-fds", "coordinator-mounts",
    "coordinator-lost", "coordinator-adapter-unresolved", "coordinator-state-unproved",
    "coordinator-never-started", "coordinator-startup-crash", "coordinator-startup-exit",
    "guard-startup-frame", "coordinator-startup-frame", "schema-invalid",
    "coordinator-entrypoint-unproved", "coordinator-script-unopened",
    "coordinator-script-missing", "coordinator-script-permission",
    "coordinator-script-policy", "mirror-still-running", "mirror-cleanup-unproved",
    "init-script-blocked", "mirror-plan-owner",
    "coordinator-argparse-uncaught", "coordinator-interpreter-traceback",
    "coordinator-interpreter-argv", "coordinator-stderr-unclassified",
    "coordinator-adapter-error", "coordinator-runtime-error",
    "cgroup-path", "init-identity", "init-not-idle", "cgroup-member-bound",
    "cgroup-member-invalid", "coordinator-cleanup-unproved", "campaign-root-changed",
    "plan-owner", "campaign-root-not-empty", "resource-missing", "permission-denied",
    "proc-invalid", "proc-stat-invalid", "proc-status-invalid",
    "error-type", "error-value", "error-attribute", "error-key", "error-name",
)) | {"guard-" + code for code in GUARD_STARTUP_CODES} \
  | {"coordinator-" + code for code in COORDINATOR_STARTUP_CODES}


def failure_category(error):
    # Never call str() on an exception or serialize arbitrary Refused arguments.
    if (type(error) is Refused and len(error.args) == 1 and type(error.args[0]) is str
            and error.args[0] in CLOSED_FAILURES):
        return error.args[0]
    if isinstance(error, OSError):
        if error.errno == 2:
            return "resource-missing"
        if error.errno in (1, 13):
            return "permission-denied"
    return "internal-failure"


def diagnostic_category(error):
    category = failure_category(error)
    if category != "internal-failure":
        return category
    mount_codes = frozenset(("host-mount-outside-owned-scope", "host-mount-scope",
                             "host-mount-namespace-changed", "host-mount-canonical-path",
                             "host-mount-input-kind", "host-mount-input-changed",
                             "host-mount-preexisting-or-transitive", "host-mount-source-missing",
                             "host-mount-source-ambiguous", "host-mount-descendants",
                             "host-mount-target-ambiguous", "host-mount-creation-mismatch",
                             "host-mount-replaced", "host-mount-table-invalid",
                             "host-mount-id-ambiguous", "host-mount-path-invalid",
                             "host-mount-table-bound", "deadline-invalid", "deadline-expired"))
    if (type(error) is Refused and len(error.args) == 1
            and type(error.args[0]) is str and error.args[0] in mount_codes):
        return error.args[0]
    from . import protocol
    descriptor_codes = frozenset(("unexpected-schema", "descriptor-schema", "descriptor-kind",
                                  "descriptor-case", "descriptor-nonce", "absolute-path", "canonical-path",
                                  "descriptor-root-binding", "product-identity", "descriptor-deadline",
                                  "descriptor-source", "descriptor-inputs", "descriptor-pg", "unexpected-pg",
                                  "json-encoding", "json-size", "json-decoding"))
    if (type(error) is protocol.ContractError and len(error.args) == 1
            and type(error.args[0]) is str and error.args[0] in descriptor_codes):
        return "protocol-" + error.args[0]
    for kind, category in ((TypeError, "error-type"), (ValueError, "error-value"),
                           (AttributeError, "error-attribute"), (KeyError, "error-key"),
                           (NameError, "error-name")):
        if type(error) is kind:
            return category
    return "internal-failure"


def script_failure_category(errno_value):
    """Fixed errno-to-category map; only validated integers or None reach here."""
    return {2: "coordinator-script-missing", 13: "coordinator-script-permission",
            1: "coordinator-script-policy"}.get(errno_value, "coordinator-script-unopened")


@dataclass(frozen=True)
class MountEntry:
    identity: int
    parent: int
    device: str
    root: str
    target: Path
    flags: frozenset[str]


def mount_path(value):
    # mountinfo escapes only these four bytes. Never interpret general escapes.
    substitutions = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}
    need(not re.search(r"\\(?!040|011|012|134)", value), "mount-path-escape")
    return re.sub(r"\\(040|011|012|134)", lambda match: substitutions[match[1]], value)


def mount_entries(text):
    need(type(text) is str and 0 < len(text) <= 1024 * 1024, "host-mount-table-bound")
    entries, ids = [], set()
    for line in text.splitlines():
        fields = line.split()
        need(len(fields) >= 10 and fields.count("-") == 1, "host-mount-table-invalid")
        split = fields.index("-")
        need(split >= 6 and len(fields) == split + 4 and fields[0].isdigit()
             and fields[1].isdigit() and re.fullmatch(r"[0-9]+:[0-9]+", fields[2]), "host-mount-table-invalid")
        identity = int(fields[0])
        need(identity > 0 and identity not in ids, "host-mount-id-ambiguous")
        ids.add(identity)
        root, target = mount_path(fields[3]), Path(mount_path(fields[4]))
        # nsfs and other unrelated mountinfo entries can have non-path roots.
        # Targets must still be canonical so overlap detection cannot miss them;
        # bind() validates the chosen source root before deriving authority.
        need(target.is_absolute() and ".." not in target.parts,
             "host-mount-path-invalid")
        entries.append(MountEntry(identity, int(fields[1]), fields[2], root, target,
                                  frozenset(fields[5].split(","))))
    need(len(entries) <= 8192, "host-mount-table-bound")
    return entries


@dataclass
class OwnedMount:
    path: Path
    kind: str
    readonly: bool
    namespace: tuple[int, int]
    inode: tuple[int, int]
    source_device: str
    source_root: str
    baseline_ids: frozenset[int]
    mount_id: int | None = None
    initial_flags: frozenset[str] = frozenset()
    flags: frozenset[str] = frozenset()
    removed: bool = False
    source_flags: frozenset[str] = frozenset()
    created_monotonic: float = 0


class HostMounts:
    """Only self-binds of already acknowledged inputs; no recursive/lazy operations.

    A pending creation receipt is registered BEFORE invoking mount. Even a failed
    bind/remount/readback is therefore visible to independently bounded cleanup.
    """
    def __init__(self, host, end):
        self.host, self.end, self.receipts = host, end, []
        self.namespace_fd = os.open("/proc/self/ns/mnt", os.O_RDONLY)
        meta = os.fstat(self.namespace_fd)
        self.namespace = (meta.st_dev, meta.st_ino)

    def table(self):
        return mount_entries(Path("/proc/self/mountinfo").read_text())

    def same_namespace(self):
        meta = Path("/proc/self/ns/mnt").stat()
        held = os.fstat(self.namespace_fd)
        need((meta.st_dev, meta.st_ino) == (held.st_dev, held.st_ino) == self.namespace,
             "host-mount-namespace-changed")

    def identity(self, path):
        need(path.is_absolute() and path.resolve(strict=True) == path, "host-mount-canonical-path")
        meta = path.lstat()
        need(stat.S_ISREG(meta.st_mode) or stat.S_ISDIR(meta.st_mode), "host-mount-input-kind")
        return meta.st_dev, meta.st_ino

    def capture(self, receipt, absent_ok=False):
        self.same_namespace()
        need(receipt.namespace == self.namespace and self.identity(receipt.path) == receipt.inode,
             "host-mount-input-changed")
        entries = self.table()
        exact_targets = [entry for entry in entries if entry.target == receipt.path]
        need(not any(entry.target != receipt.path and entry.target.is_relative_to(receipt.path)
                     for entry in entries), "host-mount-descendants")
        if not exact_targets and absent_ok and receipt.mount_id is None:
            return None
        need(len(exact_targets) == 1, "host-mount-target-ambiguous")
        entry = exact_targets[0]
        need(entry.identity not in receipt.baseline_ids and entry.device == receipt.source_device
             and entry.root == receipt.source_root, "host-mount-creation-mismatch")
        if receipt.mount_id is None:
            receipt.mount_id = entry.identity
            receipt.initial_flags = entry.flags
        need(entry.identity == receipt.mount_id, "host-mount-replaced")
        return entry

    def bind(self, path, kind, readonly, deadline=None):
        need(kind in ("source", "executable", "case", "config") and type(readonly) is bool,
             "host-mount-scope")
        self.same_namespace()
        inode = self.identity(path)
        entries = self.table()
        need(not any(entry.target == path or entry.target.is_relative_to(path) for entry in entries),
             "host-mount-preexisting-or-transitive")
        ancestors = [entry for entry in entries if path.is_relative_to(entry.target)]
        need(ancestors, "host-mount-source-missing")
        closest_depth = max(len(entry.target.parts) for entry in ancestors)
        closest = [entry for entry in ancestors if len(entry.target.parts) == closest_depth]
        need(len(closest) == 1, "host-mount-source-ambiguous")
        source = closest[0]
        need(source.root.startswith("/") and ".." not in PurePosixPath(source.root).parts,
             "host-mount-path-invalid")
        relative = path.relative_to(source.target)
        root = str(PurePosixPath(source.root) / relative)
        receipt = OwnedMount(path, kind, readonly, self.namespace, inode, source.device,
                             root, frozenset(entry.identity for entry in entries))
        receipt.source_flags = source.flags
        receipt.created_monotonic = self.host.clock()
        self.receipts.append(receipt)
        end = self.end() if deadline is None else min(self.end(), deadline)
        self.host.run(["/usr/bin/mount", "--bind", "--", str(path), str(path)], end)
        self.capture(receipt)
        self.host.run(["/usr/bin/mount", "-o", "remount,bind,nosuid,nodev," + ("ro" if readonly else "rw"),
                       "--", str(path)], end)
        entry = self.capture(receipt)
        expected = {"nosuid", "nodev", "ro" if readonly else "rw"}
        need(expected <= entry.flags and not ({"ro", "rw"} - expected) & entry.flags,
             "host-mount-flags-unproved")
        receipt.flags = entry.flags
        return receipt

    def remove(self, receipt, deadline=None):
        need(not receipt.removed, "host-mount-already-removed")
        entry = self.capture(receipt, absent_ok=True)
        if entry is not None:
            end = self.end() if deadline is None else min(self.end(), deadline)
            self.host.run(["/usr/bin/umount", "--", str(receipt.path)], end)
            self.same_namespace()
            after = self.table()
            need(not any(item.identity == receipt.mount_id or item.target == receipt.path
                         or item.target.is_relative_to(receipt.path) for item in after),
                 "host-mount-removal-unproved")
            need(self.identity(receipt.path) == receipt.inode, "host-unmounted-input-changed")
        receipt.removed = True

    def close(self):
        if self.namespace_fd is not None:
            os.close(self.namespace_fd)
            self.namespace_fd = None


def need(condition, category="contract-invalid"):
    if not condition:
        raise Refused(category)


def exact(value, keys):
    need(type(value) is dict and set(value) == set(keys), "schema-invalid")


def decode(data, limit=FRAME_BYTES):
    need(type(data) is bytes and 0 < len(data) <= limit, "frame-size")
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate-key")
            result[key] = value
        return result
    try:
        value = json.loads(data, object_pairs_hook=pairs,
                           parse_constant=lambda _: need(False, "number-invalid"))
        pending, count = [(value, 0)], 0
        while pending:
            item, depth = pending.pop()
            count += 1
            need(depth <= 32 and count <= 32768, "json-complexity")
            if type(item) in (dict, list):
                pending.extend((child, depth + 1) for child in (item.values() if type(item) is dict else item))
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise Refused("json-invalid") from None


def encode(value):
    data = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    need(len(data) <= FRAME_BYTES, "frame-size")
    return data


def digest(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "input-kind")
        h = hashlib.sha256()
        while block := os.read(fd, 1024 * 1024):
            h.update(block)
        after = os.fstat(fd)
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "input-mutated")
        return h.hexdigest()
    finally:
        os.close(fd)


def input_identity(path):
    meta = path.lstat()
    need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1, "input-kind")
    return [meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns, meta.st_uid, meta.st_mode]


def private_read(path, uid, limit=FRAME_BYTES):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == uid and meta.st_nlink == 1
             and stat.S_IMODE(meta.st_mode) in (0o400, 0o600) and meta.st_size <= limit, "private-file")
        data = os.read(fd, limit + 1)
        need(len(data) == meta.st_size, "private-file-size")
        after = os.fstat(fd)
        need((meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns) ==
             (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "private-file-mutated")
        return data
    finally:
        os.close(fd)


@dataclass(frozen=True)
class Budget:
    origin: float
    duration: float
    reserve: float

    @property
    def end(self):
        return self.origin + self.duration

    def remaining(self, now, cleanup=False):
        need(all(type(x) in (int, float) and math.isfinite(x) for x in
                 (self.origin, self.duration, self.reserve, now))
             and self.duration > self.reserve >= 0 and now >= self.origin, "deadline-invalid")
        left = self.end - now - (0 if cleanup else self.reserve)
        need(left > 0, "deadline-expired")
        return left


def chosen_port(nonce):
    need(type(nonce) is str and re.fullmatch(r"[0-9a-f]{32}", nonce), "nonce-invalid")
    port = 20000 + int(nonce[:8], 16) % 30000
    need(port not in (5432, 54322), "port-invalid")
    return port


def source_allowed(name):
    path = PurePosixPath(name)
    if path.is_absolute() or str(path) != name or any(p in ("", ".", "..") or p.startswith(".") for p in path.parts):
        return False
    if name in FIXTURES:
        return True
    if name.startswith(("crates/", "plugins/")) and path.suffix not in (".rs", ".toml", ".wit", ".sql"):
        return False
    if name.startswith("migrations/") and path.suffix != ".sql":
        return False
    if name.startswith("scripts/managed_release_linux/") and path.name not in (*HELPERS, "__init__.py"):
        return False
    return any(name.startswith(item) if item.endswith("/") else name == item for item in SOURCEALLOWLIST)


def native_elf(header):
    need(len(header) >= 64 and header[:6] == b"\x7fELF\x02\x01"
         and int.from_bytes(header[18:20], "little") == 62, "native-elf-required")


def cargo_executable(data, root):
    matches = []
    for line in data.splitlines():
        item = decode(line, 1024 * 1024)
        if (item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "db_keys_test"
                and item.get("profile", {}).get("test") is True and item.get("executable")):
            matches.append(item)
    need(len(matches) == 1, "cargo-artifact-ambiguous")
    path = Path(matches[0]["executable"])
    need(path.is_absolute() and path.resolve(strict=True) == path
         and path.is_relative_to(root / "target") and path.is_file(), "cargo-artifact-path")
    with path.open("rb") as f:
        native_elf(f.read(64))
    return path, matches[0]


def clean_env():
    # Never copy caller HOME, credentials, proxies, Docker context, or DB defaults.
    return {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}


class Channel:
    """Bounded byte protocol. stderr is discarded at creation, never exported."""
    def __init__(self, process, clock=time.monotonic):
        self.process, self.clock, self.buffer = process, clock, bytearray()
        self.selector = selectors.DefaultSelector()
        self.selector.register(process.stdout, selectors.EVENT_READ)

    def read(self, end, limit=FRAME_BYTES, heartbeat=None, heartbeat_interval=10):
        need(self.clock() < end, "channel-deadline")
        next_check = self.clock()
        while b"\n" not in self.buffer:
            left = end - self.clock()
            need(left > 0, "channel-deadline")
            if heartbeat is not None and self.clock() >= next_check:
                heartbeat()
                next_check = self.clock() + heartbeat_interval
            events = self.selector.select(min(left, 0.1))
            if not events:
                continue
            block = os.read(self.process.stdout.fileno(), min(4096, limit + 1))
            need(bool(block), "channel-eof")
            self.buffer.extend(block)
            need(len(self.buffer) <= limit, "channel-overflow")
        line, _, rest = self.buffer.partition(b"\n")
        self.buffer = bytearray(rest)
        need(self.clock() < end, "channel-deadline")
        return decode(bytes(line), limit)

    def send(self, frame):
        try:
            self.process.stdin.write(encode(frame))
            self.process.stdin.flush()
        except (OSError, ValueError):
            raise Refused("channel-write") from None

    def close(self):
        self.selector.close()
        for stream in (self.process.stdin, self.process.stdout):
            if stream:
                stream.close()


class Host:
    """All process creation lives behind this adapter; pure tests replace it."""
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.command_limit = None

    def spawn(self, argv, *, pass_fds=(), cwd=None, env=None, stderr=subprocess.DEVNULL):
        return subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=stderr, close_fds=True, pass_fds=pass_fds,
                                cwd=cwd, env=clean_env() if env is None else env)

    def run(self, argv, end, *, limit=1024 * 1024, cwd=None, env=None):
        outer_end = end
        if self.command_limit is not None:
            end = min(end, self.clock() + self.command_limit)
        need(end > self.clock(), "command-deadline")
        child = self.spawn(argv, cwd=cwd, env=env)
        child.stdin.close()
        result = bytearray()
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ)
        try:
            while selector.get_map():
                need(self.clock() < end, "command-deadline")
                for _key, _event in selector.select(min(0.2, end - self.clock())):
                    block = os.read(child.stdout.fileno(), 8192)
                    if not block:
                        selector.unregister(child.stdout)
                    else:
                        result.extend(block)
                        need(len(result) <= limit, "command-output-bound")
            need(child.wait(timeout=max(0, end - self.clock())) == 0, "command-failed")
            return bytes(result)
        except (OSError, subprocess.TimeoutExpired):
            raise Refused("command-transport") from None
        finally:
            selector.close()
            if child.poll() is None:
                child.kill()  # Only this directly captured adapter child, never a reported PID.
                try:
                    child.wait(timeout=max(0, min(5, outer_end - self.clock())))
                except subprocess.TimeoutExpired:
                    raise Refused("command-reap-unproved") from None
            child.stdout.close()

    def docker(self, args, end, limit=1024 * 1024):
        return self.run(["/usr/bin/docker", *args], end, limit=limit)

    def inspect(self, kind, identity, end):
        value = decode(self.docker([kind, "inspect", identity], end), 1024 * 1024)
        need(type(value) is list and len(value) == 1 and type(value[0]) is dict, "inspect-invalid")
        return value[0]

    def inventory(self, kind, end):
        # Successful full enumeration is required; inspect errors never mean absence.
        if kind == "container":
            args = ["container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}"]
        elif kind == "volume":
            args = ["volume", "ls", "--format", "{{.Name}}"]
        else:
            need(kind == "network", "inventory-kind")
            args = ["network", "ls", "--no-trunc", "--format", "{{.ID}}"]
        lines = self.docker(args, end).decode("ascii").splitlines()
        need(len(lines) <= 4096 and len(lines) == len(set(lines)), "inventory-invalid")
        need(all(DOCKER_ID.fullmatch(x) if kind in ("container", "network") else re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", x)
                 for x in lines), "inventory-invalid")
        return set(lines)

    def named_inventory(self, kind, end):
        if kind == "volume":
            return {name: name for name in self.inventory(kind, end)}
        need(kind == "container", "inventory-kind")
        wire = self.docker(["container", "ls", "--all", "--no-trunc", "--format", "{{.ID}} {{.Names}}"], end)
        result, identities = {}, set()
        for line in wire.decode("ascii").splitlines():
            match = re.fullmatch(r"([0-9a-f]{64}) ([A-Za-z0-9][A-Za-z0-9_.-]*)", line)
            need(match and match[2] not in result and match[1] not in identities, "named-inventory-invalid")
            result[match[2]] = match[1]
            identities.add(match[1])
        need(len(result) <= 4096, "named-inventory-bound")
        return result


@dataclass(frozen=True)
class Owned:
    kind: str
    identity: str
    name: str
    nonce: str
    created: str
    image: str | None = None

    def verify(self, value, campaign):
        need(value.get("Created") == self.created, "resource-birth-changed")
        if self.kind == "container":
            need(value.get("Id") == self.identity and value.get("Name") == "/" + self.name
                 and value.get("Image") == self.image, "container-identity")
            labels = value.get("Config", {}).get("Labels")
        else:
            need(value.get("Name") == self.name and value.get("Driver") == "local"
                 and value.get("Scope") == "local", "volume-identity")
            labels = value.get("Labels")
        need(type(labels) is dict and labels.get(LABEL) == campaign
             and labels.get(LABEL + ".nonce") == self.nonce, "resource-labels")


@dataclass
class PendingCreation:
    kind: str
    name: str
    nonce: str
    image: str | None
    creation_floor: int
    baseline_ids: frozenset[str]
    owned: Owned | None = None
    returned_identity: str | None = None
    absent: bool = False
    removed: bool = False
    attempted: bool = False
    completed: bool = False


class CreationLedger:
    """Finite pending reservations, including lost create/inspect responses."""
    def __init__(self, host, campaign, wall=time.time):
        self.host, self.campaign, self.wall, self.pending = host, campaign, wall, []

    def reserve(self, kind, name, nonce, image, end):
        before = self.host.named_inventory(kind, end)
        need(name not in before, "reserved-resource-already-exists")
        pending = PendingCreation(kind, name, nonce, image, int(self.wall()), frozenset(before.values()))
        self.pending.append(pending)  # BEFORE the mutating daemon request.
        return pending

    def reconcile(self, pending, end):
        inventory = self.host.named_inventory(pending.kind, end)
        identity = inventory.get(pending.name)
        if identity is None:
            # Killing/timing out the CLI does not cancel the daemon request.
            # An empty inventory cannot prove that a late create will not land.
            need(not pending.attempted or pending.completed, "creation-request-unresolved")
            need(pending.owned is None and pending.returned_identity is None, "acknowledged-resource-disappeared")
            pending.absent = True
            return None
        need(identity not in pending.baseline_ids and
             (pending.returned_identity is None or pending.returned_identity == identity), "reserved-resource-replaced")
        value = self.host.inspect(pending.kind, identity, end)
        created = value.get("Created" if pending.kind == "container" else "CreatedAt")
        need(type(created) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+(?:Z|\+00:00)", created),
             "reserved-resource-birth")
        try:
            birth = datetime.fromisoformat(created.replace("Z", "+00:00")).timestamp()
        except ValueError:
            raise Refused("reserved-resource-birth") from None
        need(pending.creation_floor <= birth <= self.wall() + 1, "reserved-resource-birth")
        candidate = Owned(pending.kind, identity, pending.name, pending.nonce, created, pending.image)
        candidate.verify(dict(value, Created=created), self.campaign)
        if pending.kind == "volume":
            need(value.get("Options") == pg_options(), "reserved-volume-options")
        if pending.owned:
            need(candidate == pending.owned, "reserved-resource-replaced")
        pending.owned = candidate  # Full identity acknowledged before later config validation.
        pending.absent = False
        return candidate

    def create(self, pending, args, end, reconcile_end):
        try:
            pending.attempted = True
            wire = self.host.docker(args, end)
            pending.completed = True  # Successful CLI completion, not enumeration.
            raw = wire.strip().decode("ascii")
            need((DOCKER_ID.fullmatch(raw) if pending.kind == "container" else raw == pending.name),
                 "create-receipt-invalid")
            pending.returned_identity = raw
            owned = self.reconcile(pending, end)
            need(owned is not None, "create-not-observed")
            return owned
        except Exception:
            try:
                self.reconcile(pending, reconcile_end())
            except Exception:
                pass  # Pending reservation survives; uncertainty never authorizes deletion.
            raise


def resource_limits(memory="768m", pids=128, ipc="none"):
    return ["--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
            "--cpus=0.5", "--memory=" + memory, "--memory-swap=" + memory, "--pids-limit=" + str(pids),
            "--ipc=" + ipc, "--cgroupns=private", "--log-driver=none", "--restart=no"]


def pg_options():
    return {"type": "tmpfs", "device": "tmpfs",
            "o": f"size={PG_BYTES},uid={PG_UID},gid={PG_UID},mode=0700,nosuid,nodev,noexec"}


def pg_create(name, labels, volume, image, nonce, password):
    need(IMAGE_ID.fullmatch(image), "image-id-invalid")
    need(re.fullmatch(r"[0-9a-f]{32}", password), "password-invalid")
    args = ["create", "--name", name, "--pull=never", "--platform=linux/amd64",
            "--network=none", "--user=999:999", *resource_limits(ipc="private"), *labels,
            "--mount", f"type=volume,source={volume},target=/var/lib/postgresql/data,volume-nocopy",
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=67108864,uid=999,gid=999,mode=0700",
            "--tmpfs", "/var/run/postgresql:rw,nosuid,nodev,noexec,size=16777216,uid=999,gid=999,mode=0700",
            "--env", "PGDATA=/var/lib/postgresql/data/pgdata",
            "--env", "POSTGRES_USER=managed_release", "--env", "POSTGRES_DB=managed_release_" + nonce,
            "--env", "POSTGRES_PASSWORD=" + password, image,
            "postgres", "-p", str(chosen_port(nonce)), "-c", "listen_addresses=127.0.0.1",
            "-c", "unix_socket_directories=/var/run/postgresql", "-c", "max_connections=40",
            "-c", "shared_buffers=64MB"]
    return args


def init_policy():
    """Deny escape/network bypass syscalls; Docker's normal policy is not disabled.

    Product guard installs its separate deny-default syscall policy before exec.
    Init needs libc/Python process supervision; the three capabilities are explicit.
    """
    denied = ("mount", "umount2", "pivot_root", "setns", "unshare", "bpf", "ptrace",
              "process_vm_readv", "process_vm_writev", "open_by_handle_at", "kexec_load",
              "init_module", "finit_module", "delete_module", "reboot", "swapon", "swapoff",
              "io_uring_setup", "io_uring_enter", "io_uring_register", "keyctl", "add_key", "request_key")
    return {"defaultAction": "SCMP_ACT_ALLOW", "architectures": ["SCMP_ARCH_X86_64"],
            "syscalls": [{"names": list(denied), "action": "SCMP_ACT_ERRNO", "errnoRet": 1},
                         {"names": ["socket"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1,
                          "args": [{"index": 0, "value": 10, "op": "SCMP_CMP_EQ"}]}]}


@dataclass(frozen=True)
class Proc:
    host: int
    parent: int
    group: int
    uid: int
    ticks: int
    boot: str
    nspid: tuple[int, ...]
    nspgid: tuple[int, ...]
    pidns: int
    alive: bool


def proc_record(pid, stat_text, status_text, boot, pidns, uid):
    need(type(pid) is int and pid > 1 and stat_text.startswith(str(pid) + " ("), "proc-invalid")
    end = stat_text.rfind(")")
    fields = stat_text[end + 2:].split()
    need(end > 0 and len(fields) >= 20, "proc-stat-invalid")
    status = {}
    for line in status_text.splitlines():
        key, sep, value = line.partition(":")
        need(sep and key not in status, "proc-status-invalid")
        status[key] = value.split()
    try:
        uids = tuple(map(int, status["Uid"]))
        nspid = tuple(map(int, status["NSpid"]))
        nspgid = tuple(map(int, status["NSpgid"]))
        need(len(uids) == 4 and len(set(uids)) == 1 and uids[0] == uid
             and len(nspid) == len(nspgid) == 2 and nspid[0] == pid
             and str(uuid.UUID(boot)) == boot, "proc-status-invalid")
        return Proc(pid, int(fields[1]), int(fields[2]), uid, int(fields[19]), boot,
                    nspid, nspgid, pidns, fields[0] not in ("Z", "X", "x"))
    except (ValueError, KeyError):
        raise Refused("proc-status-invalid") from None


def local_matches(local, host, init, parent):
    exact(local, ("pid", "ppid", "pgid", "uid", "alive", "birth"))
    birth = local["birth"]
    exact(birth, ("system", "start_sec", "start_subsec", "boot"))
    need(all(type(local[k]) is int for k in ("pid", "ppid", "pgid", "uid")), "identity-types")
    need(local["pid"] > 1 and local["pgid"] > 1 and local["alive"] is True and host.alive
         and local["uid"] == host.uid == PRODUCT_UID and host.pidns == init.pidns
         and host.parent == parent.host and host.nspid[-1] == local["pid"]
         and parent.nspid[-1] == local["ppid"] and host.nspgid[-1] == local["pgid"]
         and birth == {"system": "linux", "start_sec": 0, "start_subsec": host.ticks, "boot": host.boot},
         "identity-mismatch")


class Binding:
    """Pinned pidfd, namespace FDs and cgroup directory; no host /proc sweep."""
    def __init__(self, pid, expected_uid=0):
        self.fds = []
        try:
            self.pidfd = os.pidfd_open(pid, 0)
            self.fds.append(self.pidfd)
            self.boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            self.pid = pid
            self.namespaces = {}
            for name in ("pid", "net", "mnt", "ipc", "uts", "user", "cgroup"):
                fd = os.open(f"/proc/{pid}/ns/{name}", os.O_RDONLY)
                self.fds.append(fd)
                self.namespaces[name] = os.fstat(fd).st_ino
            lines = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
            need(len(lines) == 1 and lines[0].startswith("0::/"), "cgroup-v2-required")
            relative = lines[0][4:]
            need(relative and ".." not in PurePosixPath(relative).parts, "cgroup-path")
            path = Path("/sys/fs/cgroup") / relative
            need(path.resolve(strict=True) == path, "cgroup-path")
            self.cgroup = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.fds.append(self.cgroup)
            meta = os.fstat(self.cgroup)
            self.device, self.inode = meta.st_dev, meta.st_ino
            self.init = self.proc(pid)
            need(self.init.nspid[-1] == 1 and self.init.uid == expected_uid and self.init.alive, "init-identity")
            need(self.members() == [pid], "init-not-idle")
        except BaseException:
            self.close()
            raise

    def proc(self, pid):
        base = Path("/proc") / str(pid)
        meta = base.stat()
        return proc_record(pid, (base / "stat").read_text(), (base / "status").read_text(),
                           self.boot, (base / "ns/pid").stat().st_ino, meta.st_uid)

    def members(self):
        fd = os.open("cgroup.procs", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.cgroup)
        try:
            data = os.read(fd, 16385)
        finally:
            os.close(fd)
        need(len(data) <= 16384, "cgroup-member-bound")
        try:
            values = [int(x) for x in data.split()]
        except ValueError:
            raise Refused("cgroup-member-invalid") from None
        need(len(values) == len(set(values)) and all(x > 1 for x in values), "cgroup-member-invalid")
        return values

    def verify_pair(self, test, tls):
        init = self.proc(self.pid)
        need(init == self.init, "init-birth-changed")
        members = {pid: self.proc(pid) for pid in self.members()}
        def find(local):
            hits = [x for x in members.values() if x.nspid[-1] == local.get("pid")]
            need(len(hits) == 1, "identity-ambiguous")
            return hits[0]
        test_host, tls_host = find(test), find(tls)
        local_matches(test, test_host, init, init)
        local_matches(tls, tls_host, init, test_host)
        need(self.proc(test_host.host) == test_host and self.proc(tls_host.host) == tls_host,
             "identity-changed")
        return test_host, tls_host

    def only_init(self):
        need(self.members() == [self.pid] and self.proc(self.pid) == self.init, "descendants-survived")

    def prove_empty_after_stop(self, category):
        """Called only after identity-verified Docker stop; never signal authority.

        Docker may remove the empty cgroup before our next read. Linux refuses
        rmdir on a populated cgroup. A missing file is accepted only when the
        *held original* kernfs directory is deleted and its pinned init exited.
        A missing pathname or a dead init alone proves neither fact.
        """
        with selectors.DefaultSelector() as poll:
            poll.register(self.pidfd, selectors.EVENT_READ)
            need(bool(poll.select(0)), category)
        try:
            need(self.members() == [], category)
        except FileNotFoundError as error:
            need(error.errno == 2, category)
            meta = os.fstat(self.cgroup)
            need((meta.st_dev, meta.st_ino) == (self.device, self.inode)
                 and os.readlink(f"/proc/self/fd/{self.cgroup}").endswith(" (deleted)"), category)

    def close(self):
        for fd in self.fds:
            os.close(fd)
        self.fds = []


def native_deadline(end):
    """Serialize the original deadline within the native nine-digit grammar.

    Float addition can produce more than nine fractional digits even when the
    monotonic clock has nanosecond resolution. Decimal flooring never renews
    or rounds up the already established budget.
    """
    need(type(end) in (int, float) and 0 < end < 10**12 and math.isfinite(end), "native-deadline")
    return format(Decimal(end).quantize(Decimal("0.000000001"), rounding=ROUND_FLOOR), "f")


def policy_ready(value, binding, ports):
    exact(value, ("schema", "kind", "ready", "program_ids", "cgroup_device", "cgroup_inode", "allowed_ports"))
    need(type(value["schema"]) is int and value["schema"] == 1 and value["kind"] == "kernel-policy"
         and value["ready"] is True and value["cgroup_device"] == binding.device
         and value["cgroup_inode"] == binding.inode and value["allowed_ports"] == sorted(ports), "policy-readback")
    ids = value["program_ids"]
    need(type(ids) is list and len(ids) == len(set(ids)) == 4
         and all(type(x) is int and x > 0 for x in ids), "policy-programs")


def validate_init_event(frame):
    from . import protocol
    try:
        return protocol.validate_event(frame)
    except protocol.ContractError:
        raise Refused("init-event-invalid") from None


def check_ready(frame, case, nonce):
    validate_init_event(frame)
    exact(frame, ("schema", "kind", "case", "nonce", "seq", "ports"))
    need(frame["schema"] == 1 and type(frame["schema"]) is int and frame["kind"] == "ready"
         and frame["case"] == case and frame["nonce"] == nonce and type(frame["seq"]) is int
         and frame["seq"] == 1, "ready-binding")
    roles = ("provider", "tls", "gateway-1", "gateway-2", "gateway-3") if case in CASES or case in (
        "control-before-start", "control-descendant", "isolation-controls") else (
        ("slow-peer", "slow-relay") if case == "slow-peer" else ())
    exact(frame["ports"], roles)
    ports = list(frame["ports"].values())
    need(all(type(p) is int and 1024 <= p <= 65535 and p not in (5432, 54322) for p in ports)
         and len(set(ports)) == len(ports), "ready-ports")
    return ports


def closed_result(frame, case, nonce):
    from . import protocol
    validate_init_event(frame)
    exact(frame, ("schema", "kind", "case", "nonce", "seq", "passed", "status", "counts",
                  "panic_locations", "cleanup", "control"))
    need(frame["schema"] == 1 and type(frame["schema"]) is int and frame["kind"] == "case-result"
         and frame["case"] == case and frame["nonce"] == nonce, "case-result-failed")
    # Emit only the already validated, request-bound closed facts. A failed init
    # result must remain diagnosable before acceptance rejects it; never include
    # the nonce, descriptor, raw output, exception text, paths or payload hashes.
    if not frame["passed"]:
        print("managed-linux-case-result: " + encode(dict(case=case, init_passed=frame["passed"],
              status=frame["status"], counts=frame["counts"], local_cleanup=frame["cleanup"],
              panic_locations=frame["panic_locations"])).decode("ascii"), flush=True)
    need(frame["passed"] is True and frame["status"] == "passed" and frame["panic_locations"] == [],
         "case-result-failed")
    exact(frame["cleanup"], ("main_group_absent", "main_reaped", "tls_group_absent", "tls_reaped",
                              "listeners_closed", "reservations_closed", "within_deadline"))
    need(all(x is True for x in frame["cleanup"].values()), "local-cleanup-failed")
    need(case in CASES + CONTROLS, "unknown-case")
    exact(frame["counts"], ("selected", "passed", "summary", "complete", "shutdown"))
    need(all(type(x) is int for x in frame["counts"].values()), "count-types")
    if case in CASES:
        exact(frame["counts"], ("selected", "passed", "summary", "complete", "shutdown"))
        need(frame["counts"] == dict(selected=1, passed=1, summary=1, complete=1, shutdown=1)
             and all(type(x) is int for x in frame["counts"].values()), "case-counts")
    elif case in ("strict-provider", "deadline-contract"):
        need(frame["counts"] == dict(selected=1, passed=1, summary=1, complete=0, shutdown=0), "control-counts")
    elif case in ("python-mocks", "slow-peer", "isolation-controls"):
        need(frame["counts"] == dict(selected=0, passed=0, summary=0, complete=0, shutdown=0), "control-counts")
    elif case in ("control-before-start", "control-descendant"):
        need(frame["counts"] == dict(selected=0, passed=0, summary=0, complete=0, shutdown=0), "control-counts")
    exact(frame["control"], ("before_start_eof", "descendant_live_after_leader_exit", "descendant_sigkill",
                             "strict_provider", "deadline_contract", "python_mocks", "slow_peer",
                             "isolation_controls", "python_tests_run"))
    need(all(type(x) is bool for key, x in frame["control"].items() if key != "python_tests_run")
         and type(frame["control"]["python_tests_run"]) is int, "control-types")
    if case == "control-before-start":
        need(frame["control"]["before_start_eof"] is True, "before-start-control")
    if case == "control-descendant":
        need(frame["control"]["descendant_live_after_leader_exit"] is True
             and frame["control"]["descendant_sigkill"] is True, "descendant-control")
    for case_name, field_name in (("strict-provider", "strict_provider"), ("deadline-contract", "deadline_contract"),
                                  ("python-mocks", "python_mocks"), ("slow-peer", "slow_peer"),
                                  ("isolation-controls", "isolation_controls")):
        if case == case_name:
            need(frame["control"][field_name] is True, "control-evidence-missing")
    if case == "python-mocks":
        need(frame["control"]["python_tests_run"] == 5, "five-mocks-required")
    need(tuple(x for x, _ in protocol.CASES) == CASES, "selector-drift")
    return {"case": case, "passed": True, "cleanup": True}


def coordinator_request(data, campaign, source, seq, expected):
    exact(data, ("schema", "kind", "campaign", "source_sha", "seq", "case"))
    need(type(data["schema"]) is int and data["schema"] == 1 and data["kind"] == "run-case"
         and data["campaign"] == campaign and type(data["seq"]) is int and data["seq"] == seq
         and data["source_sha"] == source and data["case"] == expected, "coordinator-frame")


def coordinator_startup(data):
    """Dispatch fixed startup frames; never import or echo exception content.

    The guard emits {"schema","kind":"product-guard","ok","code"} on stdout before
    exec; the coordinator emits {"schema","kind":"coordinator-startup","code"} when
    it fails before or between request frames. Codes are statically allowlisted.
    """
    if type(data) is not dict:
        return None
    kind = data.get("kind")
    if kind == "product-guard":
        exact(data, ("schema", "kind", "ok", "code"))
        need(data["schema"] == 1 and data["ok"] is False and type(data["code"]) is str
             and data["code"] in GUARD_STARTUP_CODES, "guard-startup-frame")
        return "guard-" + data["code"]
    if kind == "coordinator-startup":
        exact(data, ("schema", "kind", "code"))
        need(data["schema"] == 1 and type(data["code"]) is str
             and data["code"] in COORDINATOR_STARTUP_CODES, "coordinator-startup-frame")
        return "coordinator-" + data["code"]
    return None


def coordinator_config(value):
    """Exact daemon-applied entrypoint/command check for the coordinator."""
    config = value.get("Config", {})
    return (config.get("Entrypoint") == [COORDINATOR_ENTRYPOINT]
            and config.get("Cmd") == list(COORDINATOR_COMMAND))


def coordinator_stderr_class(data):
    """Map bounded startup stderr to one fixed category; never retain/export bytes."""
    if not data:
        return None
    need(type(data) is bytes and len(data) <= STDERR_LIMIT + 1, "stderr-class-size")
    for marker, category in STDERR_CLASSES:
        if marker in data:
            if category == "coordinator-script-unopened":
                # Closed errno integers embedded in CPython's fixed message.
                for errno_marker, refined in ((b"[Errno 13]", "coordinator-script-permission"),
                                              (b"[Errno 2]", "coordinator-script-missing"),
                                              (b"[Errno 1]", "coordinator-script-policy")):
                    if errno_marker in data:
                        return refined
            return category
    return "coordinator-stderr-unclassified"


def script_preflight(data):
    """Validate the fixed preflight's closed metadata record."""
    core = ("schema", "kind", "opened", "open_errno", "mode", "uid", "gid",
            "dir_mode", "dir_uid")
    need(type(data) is dict and all(key in data for key in core)
         and set(data) <= set(core) | {"stat_errno", "dir_errno"}, "script-preflight-shape")
    need(type(data["schema"]) is int and data["schema"] == 1
         and type(data["kind"]) is str and data["kind"] == "coordinator-script-preflight"
         and type(data["opened"]) is bool, "script-preflight-shape")
    for key in ("open_errno", "stat_errno", "dir_errno", "uid", "gid"):
        if key in data:
            value = data[key]
            need(value is None or (type(value) is int and not isinstance(value, bool)
                                   and 0 <= value <= 65535), "script-preflight-shape")
    for key in ("mode", "dir_mode"):
        value = data[key]
        need(value is None or (type(value) is str and 1 <= len(value) <= 4
                               and value.isdigit()), "script-preflight-shape")
    return data


def fixed_batches():
    # Controls finish and are removed before the first product is admitted.
    return [(x,) for x in CONTROLS] + [CASES[i:i + MAX_ACTIVE] for i in range(0, len(CASES), MAX_ACTIVE)]


def run_mirror_variant(host, end, directory, images, source, variant, interactive, mount_plan, guard):
    """Run the exact runtime coordinator startup in preparation; closed outcome.

    `full` mirrors the campaign container byte-for-byte. The other variants
    isolate the only configuration differences when `full` cannot start.
    """
    nonce = uuid.uuid4().hex
    name = "maskura-managed-mirror-" + nonce
    plan = directory / ("mirror-plan-" + variant + ".json")
    ledger = CreationLedger(host, nonce)
    pending = ledger.reserve("container", name, nonce, images["runtime"], end)
    ident = None
    process = channel = None
    outcome = "internal-failure"
    try:
        if mount_plan:
            plan.write_bytes(encode(dict(schema=1, campaign=nonce, source_sha=source,
                                         campaign_end=host.clock() + 600,
                                         cases=list(CONTROLS + CASES))))
            plan.chmod(0o444)
            # Preparation runs as the runner user; campaign plans are created by
            # the root warden. Preserve the same strict ownership contract here.
            host.run(["/usr/bin/sudo", "--", "/usr/bin/chown", "0:0", str(plan)], end)
            meta = plan.lstat()
            need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_gid == 0
                 and meta.st_nlink == 1 and stat.S_IMODE(meta.st_mode) == 0o444,
                 "mirror-plan-owner")
        args = ["create", "--name", name, "--pull=never", "--platform=linux/amd64"]
        if interactive:
            args.append("--interactive")
        args += ["--network=none", "--user=0:0", *resource_limits("128m", 32),
                 "--label", LABEL + "=" + nonce, "--label", LABEL + ".nonce=" + nonce,
                 "--cap-add=SETUID", "--cap-add=SETGID",
                 "--security-opt=seccomp=" + str(directory / "init-seccomp.json")]
        if mount_plan:
            args += ["--mount", f"type=bind,source={plan},target=/run/maskura/plan.json,readonly"]
        if guard:
            args += ["--entrypoint=" + COORDINATOR_ENTRYPOINT, images["runtime"], *COORDINATOR_COMMAND]
        else:
            args += ["--entrypoint=/usr/bin/python3", images["runtime"], "-I", "-B",
                     SCRIPT_PATH, "--plan", "/run/maskura/plan.json"]
        owned = ledger.create(pending, args, end, lambda: end)
        ident = owned.identity
        start = ["start", "--attach"]
        if interactive:
            start.append("--interactive")
        start.append(ident)
        process = host.spawn(["/usr/bin/docker", *start], stderr=subprocess.PIPE)
        channel = Channel(process, host.clock)
        try:
            data = channel.read(min(end, host.clock() + 15))
            startup = coordinator_startup(data)
            if startup is not None:
                outcome = startup  # guard or coordinator startup frame
            else:
                coordinator_request(data, nonce, source, 1, CONTROLS[0])
                outcome = "frame-ok"
        except Refused as error:
            if type(error) is Refused and error.args == ("channel-eof",):
                try:
                    code = process.wait(timeout=max(0.01, min(3.0, end - host.clock())))
                except subprocess.TimeoutExpired:
                    outcome = "coordinator-adapter-unresolved"
                else:
                    raw = b""
                    if process.stderr is not None:
                        try:
                            raw = process.stderr.read(STDERR_LIMIT + 1) or b""
                        except Exception:
                            raw = b""
                    outcome = coordinator_stderr_class(raw)
                    if outcome is None:
                        outcome = {2: "coordinator-arguments",
                                   1: "coordinator-startup-crash"}.get(
                                       code, "coordinator-startup-exit")
            else:
                outcome = failure_category(error)
    except Exception as error:
        outcome = failure_category(error)
    finally:
        # Owned cleanup: container first (unmounts the plan), then the adapter,
        # then the written plan. Any cleanup failure overrides a startup outcome.
        try:
            if ident is None:
                # A lost create response may still have landed in the daemon.
                adopted = ledger.reconcile(pending, end)
                if adopted is not None:
                    ident = adopted.identity
            if ident is not None:
                value = host.inspect("container", ident, end)
                pending.owned.verify(value, nonce)
                if value.get("State", {}).get("Running"):
                    host.docker(["kill", "--signal=KILL", ident], end)
                    value = host.inspect("container", ident, end)
                    pending.owned.verify(value, nonce)
                need(value.get("State", {}).get("Running") is False, "mirror-still-running")
                host.docker(["container", "rm", ident], end)
                need(ident not in host.inventory("container", end), "mirror-cleanup-unproved")
                pending.removed = True
            if process is not None:
                try:
                    process.wait(timeout=max(0.01, min(5.0, end - host.clock())))
                except Exception:
                    process.kill()
                    process.wait(timeout=5)
        except Exception as cleanup_error:
            outcome = failure_category(cleanup_error)
        finally:
            if channel is not None:
                try:
                    channel.close()
                except Exception:
                    pass
            if process is not None and getattr(process, "stderr", None) is not None:
                try:
                    process.stderr.close()
                except Exception:
                    pass
            if mount_plan:
                try:
                    plan.unlink()
                except FileNotFoundError:
                    pass
    return outcome


def mirror_startup_preflight(host, end, directory, images, source):
    """Prove exact-runtime coordinator startup in preparation, bisecting diffs."""
    print("managed Linux preparation: coordinator-mirror-preflight", flush=True)
    outcomes = {}
    for variant, interactive, mount_plan, guard in (("no_guard", True, True, False),
                                                    ("full", True, True, True),
                                                    ("no_interactive", False, True, True),
                                                    ("no_plan_mount", True, False, True)):
        outcome = run_mirror_variant(host, end, directory, images, source,
                                     variant, interactive, mount_plan, guard)
        outcomes[variant] = outcome
        print("managed Linux preparation: coordinator-mirror " + variant + "=" + outcome,
              flush=True)
        if variant == "no_guard":
            if outcome in SCRIPT_OPEN_FAILURES:
                raise Refused("init-script-blocked")
            need(outcome == "coordinator-identity", outcome if outcome in CLOSED_FAILURES else "internal-failure")
        if outcome == "frame-ok" and variant == "full":
            break
    if outcomes.get("full") != "frame-ok":
        raise Refused(outcomes["full"])


def prepare(root, source, host):
    """Preparation is the only phase allowed to build/install/pull."""
    need(platform.system() == "Linux" and platform.machine() == "x86_64", "native-linux-amd64-required")
    need(SOURCE_SHA.fullmatch(source), "source-invalid")
    end = host.clock() + PREP_SECONDS
    directory = root / PREP_DIR
    directory.mkdir(mode=0o700)  # Existing receipts are never resumed/relabelled.
    need(host.run(["/usr/bin/git", "rev-parse", "HEAD"], end, cwd=root).strip().decode() == source,
         "source-head-mismatch")
    need(not host.run(["/usr/bin/git", "diff", "--name-only", "HEAD"], end, cwd=root).strip(), "source-dirty")
    tracked = host.run(["/usr/bin/git", "ls-files", "--stage", "-z"], end, cwd=root)
    entries = []
    source_executables = set()
    for record in tracked.split(b"\0"):
        if not record:
            continue
        mode_record, name = record.decode("utf-8").split("\t", 1)
        mode, _object, stage = mode_record.split()
        if source_allowed(name):
            need(mode in ("100644", "100755") and stage == "0", "source-kind-invalid")
            path = root / name
            need(path.resolve(strict=True) == path and path.is_file(), "source-symlink")
            entries.append(name)
            if mode == "100755":
                source_executables.add(name)
    need(len(entries) == len(set(entries)) and 0 < len(entries) <= 20000, "source-bound")
    mandatory = {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "Dockerfile.managed-tests", *FIXTURES,
                 "scripts/managed_release_linux/__init__.py",
                 "scripts/tests/managed_release_tls.py", "scripts/tests/test_managed_release_tls.py"}
    mandatory.update("scripts/managed_release_linux/" + x for x in HELPERS)
    need(mandatory <= set(entries), "source-input-missing")
    before_build = {name: (input_identity(root / name), None if name in FIXTURES else digest(root / name))
                     for name in entries}
    print("managed Linux preparation: native-guards", flush=True)
    for source_file, output in (("product_guard.c", "product-guard"), ("kernel_guard.c", "kernel-guard")):
        host.run(["/usr/bin/gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fstack-protector-strong",
                  "-D_FORTIFY_SOURCE=2", "-o", str(directory / output),
                  str(root / "scripts/managed_release_linux" / source_file)], end, limit=65536)
        (directory / output).chmod(0o555)
    host.run([str(directory / "kernel-guard"), "--self-test"], end, limit=FRAME_BYTES)
    host.run([str(directory / "product-guard"), "--self-test"], end, limit=FRAME_BYTES)
    (directory / "init-seccomp.json").write_bytes(json.dumps(init_policy(), sort_keys=True).encode())
    (directory / "init-seccomp.json").chmod(0o444)
    # Build with a deliberately explicit native Cargo target directory. The ELF
    # stays at Cargo's selected original absolute path throughout qualification.
    build_env = dict(os.environ)
    for name in list(build_env):
        if "proxy" in name.lower() or name in ("CARGO_TARGET_DIR", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"):
            del build_env[name]
    # No job-count override: cargo defaults to the fresh runner's actual core
    # count, so a bounded preparation phase is not artificially serialized.
    build_env.update(CARGO_TARGET_DIR=str(root / "target"), RUSTFLAGS="-D warnings")
    print("managed Linux preparation: rust-and-components", flush=True)
    for args in (
        ["rustup", "toolchain", "install", "1.97.0", "--profile", "minimal", "--target", "wasm32-wasip1,wasm32-unknown-unknown"],
        ["cargo", "+1.97.0", "install", "--locked", "wasm-tools", "--version", "1.255.0"],
        ["bash", "scripts/build-plugins.sh"],
    ):
        host.run(args, end, cwd=root, env=build_env, limit=32 * 1024 * 1024)
    print("managed Linux preparation: native-test-artifact", flush=True)
    artifact_wire = host.run(["cargo", "+1.97.0", "test", "--locked", "-p", "maskura-gateway", "--test",
                              "db_keys_test", "--no-run", "--message-format=json-render-diagnostics"],
                             end, cwd=root, env=build_env, limit=64 * 1024 * 1024)
    executable, artifact = cargo_executable(artifact_wire, root)
    executable.chmod(0o555)
    print("managed Linux preparation: pinned-runtime-images", flush=True)
    host.docker(["pull", "--platform=linux/amd64", PG_IMAGE], end)
    host.docker(["pull", "--platform=linux/amd64", BASE_IMAGE], end)
    tag = "maskura-managed-runtime:" + source
    host.docker(["build", "--pull=false", "--platform=linux/amd64", "--file", "Dockerfile.managed-tests",
                 "--tag", tag, "."], end, limit=32 * 1024 * 1024)
    images = {}
    for name, ref in (("runtime", tag), ("postgres", PG_IMAGE)):
        image = host.inspect("image", ref, end)
        need(image.get("Os") == "linux" and image.get("Architecture") == "amd64"
             and IMAGE_ID.fullmatch(image.get("Id", "")), "native-image-required")
        if name == "postgres":
            need("postgres@" + PG_IMAGE.split("@", 1)[1] in image.get("RepoDigests", []), "postgres-digest-mismatch")
        images[name] = image["Id"]
    staged = directory / "source"
    staged.mkdir(mode=0o755)
    hashes = {}
    for name in sorted(entries):
        source_path, destination = root / name, staged / name
        need(input_identity(source_path) == before_build[name][0]
             and (name in FIXTURES or digest(source_path) == before_build[name][1]), "source-changed-during-build")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, destination, follow_symlinks=False)
        destination.chmod(0o555 if name in source_executables else 0o444)
        if name in FIXTURES:
            need(source_path.read_bytes() == destination.read_bytes(), "fixture-bytes-changed")
        else:
            hashes[name] = digest(source_path)
    component = root / "target/test-components/test-transformer.component.wasm"
    need(component.is_file() and component.stat().st_size > 8, "genuine-component-missing")
    with component.open("rb") as component_file:
        need(component_file.read(8) == b"\x00asm\x0d\x00\x01\x00", "genuine-component-format")
    dest = staged / "target/test-components/test-transformer.component.wasm"
    dest.parent.mkdir(parents=True)
    shutil.copyfile(component, dest)
    dest.chmod(0o444)
    # An empty mountpoint, NOT a retained executable copy. The original Cargo ELF
    # is overmounted read-only at its original absolute path before init starts.
    executable_mountpoint = staged / executable.relative_to(root)
    executable_mountpoint.parent.mkdir(parents=True, exist_ok=True)
    executable_mountpoint.touch(mode=0o555, exist_ok=False)
    for base, dirs, _files in os.walk(staged, topdown=False):
        for name in dirs:
            (Path(base) / name).chmod(0o555)
    staged.chmod(0o555)
    print("managed Linux preparation: native-abi", flush=True)
    abi_nonce = uuid.uuid4().hex
    abi_name = "maskura-managed-abi-" + abi_nonce
    abi_args = ["create", "--name", abi_name, "--pull=never", "--platform=linux/amd64",
                          "--network=none", "--user=20001:20001", *resource_limits("128m", 32),
                          "--label", LABEL + "=" + abi_nonce, "--label", LABEL + ".nonce=" + abi_nonce,
                          "--mount", f"type=bind,source={executable},target={executable},readonly",
                          "--entrypoint=/lib64/ld-linux-x86-64.so.2", images["runtime"], "--list", str(executable)]
    abi_ledger = CreationLedger(host, abi_nonce)
    abi_pending = abi_ledger.reserve("container", abi_name, abi_nonce, images["runtime"], end)
    try:
        abi_owned = abi_ledger.create(abi_pending, abi_args, end, lambda: end)
        abi_id = abi_owned.identity
        # ld.so --list checks interpreter/dependency symbol versions without
        # transferring control to product constructors or main.
        host.docker(["start", "--attach", abi_id], end, limit=65536)
        abi_value = host.inspect("container", abi_id, end)
        abi_owned.verify(abi_value, abi_nonce)
        need(abi_value.get("State", {}).get("ExitCode") == 0
             and abi_value["State"].get("Running") is False, "rootfs-native-abi")
    finally:
        abi_owned = abi_ledger.reconcile(abi_pending, end)
        if abi_owned:
            abi_id = abi_owned.identity
            abi_value = host.inspect("container", abi_id, end)
            abi_owned.verify(abi_value, abi_nonce)
            if abi_value.get("State", {}).get("Running"):
                host.docker(["kill", "--signal=KILL", abi_id], end)
                abi_value = host.inspect("container", abi_id, end)
                abi_owned.verify(abi_value, abi_nonce)
            need(abi_value.get("State", {}).get("Running") is False, "abi-still-running")
            host.docker(["container", "rm", abi_id], end)
            need(abi_id not in host.inventory("container", end), "abi-cleanup-unproved")
            abi_pending.removed = True
    # Exact runtime context preflight: guard + init seccomp + NNP + uid 20001
    # open the real coordinator script and report only closed metadata facts.
    print("managed Linux preparation: coordinator-script-preflight", flush=True)
    pre_nonce = uuid.uuid4().hex
    pre_name = "maskura-managed-preflight-" + pre_nonce
    pre_args = ["create", "--name", pre_name, "--pull=never", "--platform=linux/amd64",
                "--network=none", "--user=0:0", *resource_limits("128m", 32),
                "--cap-add=SETUID", "--cap-add=SETGID",
                "--security-opt=seccomp=" + str(directory / "init-seccomp.json"),
                "--label", LABEL + "=" + pre_nonce, "--label", LABEL + ".nonce=" + pre_nonce,
                "--entrypoint=" + COORDINATOR_ENTRYPOINT, images["runtime"],
                "--uid", "20001", "--gid", "20001", "--profile", "coordinator", "--",
                "/usr/bin/python3", "-I", "-B", "-c", SCRIPT_PREFLIGHT_CODE]
    pre_ledger = CreationLedger(host, pre_nonce)
    pre_pending = pre_ledger.reserve("container", pre_name, pre_nonce, images["runtime"], end)
    try:
        pre_owned = pre_ledger.create(pre_pending, pre_args, end, lambda: end)
        raw = host.docker(["start", "--attach", pre_owned.identity], end, limit=FRAME_BYTES)
        facts = script_preflight(decode(raw.strip(), FRAME_BYTES))
        print("managed Linux preparation: coordinator-script " + " ".join(
            key + "=" + repr(facts[key]) for key in
            ("opened", "open_errno", "stat_errno", "mode", "uid", "gid",
             "dir_mode", "dir_uid", "dir_errno") if key in facts), flush=True)
        need(facts["opened"], script_failure_category(facts.get("open_errno")))
    finally:
        pre_reconciled = pre_ledger.reconcile(pre_pending, end)
        if pre_reconciled:
            pre_id = pre_reconciled.identity
            value = host.inspect("container", pre_id, end)
            pre_reconciled.verify(value, pre_nonce)
            if value.get("State", {}).get("Running"):
                host.docker(["kill", "--signal=KILL", pre_id], end)
                value = host.inspect("container", pre_id, end)
                pre_reconciled.verify(value, pre_nonce)
            need(value.get("State", {}).get("Running") is False, "preflight-still-running")
            host.docker(["container", "rm", pre_id], end)
            need(pre_id not in host.inventory("container", end), "preflight-cleanup-unproved")
            pre_pending.removed = True
    # Exact-runtime startup reproduction: the `full` variant uses the campaign
    # container byte-for-byte; failures bisect across the two configuration
    # differences within the same preparation budget.
    mirror_startup_preflight(host, end, directory, images, source)
    inputs = {
        "executable_sha256": digest(executable),
        "tls_sha256": digest(root / "scripts/tests/managed_release_tls.py"),
        "python_test_sha256": digest(root / "scripts/tests/test_managed_release_tls.py"),
        "product_guard_sha256": digest(directory / "product-guard"),
        **{name + "_sha256": digest(root / "scripts/managed_release_linux" / (name + ".py"))
           for name in ("protocol", "supervisor", "probe")},
    }
    bound_paths = [root / name for name in entries] + [staged / name for name in entries]
    bound_paths += [executable, component, dest, directory / "product-guard", directory / "kernel-guard"]
    identities = {str(path): input_identity(path) for path in bound_paths}
    identities[str(directory / "init-seccomp.json")] = input_identity(directory / "init-seccomp.json")
    harness_hashes = {name: digest(root / "scripts/managed_release_linux" / name) for name in HELPERS}
    harness_hashes.update({name: digest(root / name) for name in ("Dockerfile.managed-tests", "Cargo.lock", "rust-toolchain.toml")})
    harness_hashes.update({"init-seccomp.json": digest(directory / "init-seccomp.json"),
                           "product-guard": digest(directory / "product-guard"),
                           "kernel-guard": digest(directory / "kernel-guard"),
                           "cargo-artifact.json": hashlib.sha256(json.dumps(artifact, sort_keys=True).encode()).hexdigest()})
    receipt = dict(schema=1, source_sha=source, architecture="linux/amd64", source_root=str(root),
                   executable=str(executable), inputs=inputs, source_hashes=hashes,
                   fixtures_equal=list(FIXTURES), component_sha256=digest(component),
                   kernel_guard_sha256=digest(directory / "kernel-guard"), images=images,
                   cargo_artifact=artifact, toolchain="1.97.0", pg_image=PG_IMAGE, base_image=BASE_IMAGE,
                   input_identities=identities, harness_hashes=harness_hashes)
    (directory / "receipt.json").write_bytes(json.dumps(receipt, sort_keys=True).encode())
    (directory / "receipt.json").chmod(0o400)
    need(host.clock() < end, "preparation-deadline")
    return receipt


def validate_prepared(root, source):
    directory = root / PREP_DIR
    receipt = decode((directory / "receipt.json").read_bytes(), 16 * 1024 * 1024)
    exact(receipt, ("schema", "source_sha", "architecture", "source_root", "executable", "inputs",
                    "source_hashes", "fixtures_equal", "component_sha256", "kernel_guard_sha256", "images",
                    "cargo_artifact", "toolchain", "pg_image", "base_image", "input_identities", "harness_hashes"))
    need(receipt["schema"] == 1 and receipt["source_sha"] == source and SOURCE_SHA.fullmatch(source)
         and receipt["architecture"] == "linux/amd64" and receipt["source_root"] == str(root)
         and receipt["toolchain"] == "1.97.0" and receipt["pg_image"] == PG_IMAGE
         and receipt["base_image"] == BASE_IMAGE, "preparation-binding")
    exact(receipt["images"], ("runtime", "postgres"))
    need(all(IMAGE_ID.fullmatch(x) for x in receipt["images"].values()), "image-binding")
    exact(receipt["inputs"], INPUT_NAMES)
    need(all(SHA256.fullmatch(x) for x in receipt["inputs"].values()), "input-binding")
    need(type(receipt["source_hashes"]) is dict and 0 < len(receipt["source_hashes"]) <= 20000, "source-bound")
    need(type(receipt["input_identities"]) is dict and 0 < len(receipt["input_identities"]) <= 40010, "identity-bound")
    for name, expected in receipt["input_identities"].items():
        path = Path(name)
        need(path.is_absolute() and path.resolve(strict=True) == path and path.is_relative_to(root)
             and type(expected) is list and len(expected) == 7
             and all(type(x) is int for x in expected), "input-identity-invalid")
        need(input_identity(path) == expected, "input-rebuilt-or-mutated")
    for name, expected in receipt["source_hashes"].items():
        need(source_allowed(name) and name not in FIXTURES and SHA256.fullmatch(expected), "source-receipt-invalid")
        need(digest(root / name) == digest(directory / "source" / name) == expected, "source-input-changed")
    need(receipt["fixtures_equal"] == list(FIXTURES), "fixture-set-changed")
    for name in FIXTURES:
        need((root / name).read_bytes() == (directory / "source" / name).read_bytes(), "fixture-bytes-changed")
    executable = Path(receipt["executable"])
    need(executable.resolve(strict=True) == executable and executable.is_relative_to(root / "target")
         and receipt["cargo_artifact"].get("executable") == str(executable), "executable-binding")
    need(digest(executable) == receipt["inputs"]["executable_sha256"], "executable-changed")
    need(digest(directory / "product-guard") == receipt["inputs"]["product_guard_sha256"]
         and digest(directory / "kernel-guard") == receipt["kernel_guard_sha256"], "guard-changed")
    need(digest(root / "target/test-components/test-transformer.component.wasm") ==
         digest(directory / "source/target/test-components/test-transformer.component.wasm") ==
         receipt["component_sha256"], "component-changed")
    need(decode((directory / "init-seccomp.json").read_bytes(), 65536) == init_policy(), "init-profile-changed")
    expected_harness = {name: digest(root / "scripts/managed_release_linux" / name) for name in HELPERS}
    expected_harness.update({name: digest(root / name) for name in ("Dockerfile.managed-tests", "Cargo.lock", "rust-toolchain.toml")})
    expected_harness.update({"init-seccomp.json": digest(directory / "init-seccomp.json"),
                             "product-guard": digest(directory / "product-guard"),
                             "kernel-guard": digest(directory / "kernel-guard"),
                             "cargo-artifact.json": hashlib.sha256(json.dumps(receipt["cargo_artifact"], sort_keys=True).encode()).hexdigest()})
    need(receipt["harness_hashes"] == expected_harness, "harness-changed")
    return receipt


def volume_scan():
    """Fixed read-only metadata/du scan; only used in an owned helper container."""
    root, seen, size, count = Path("/pgdata"), set(), 0, 0
    root_meta = root.stat()
    need(stat.S_ISDIR(root_meta.st_mode) and root_meta.st_uid == PG_UID
         and stat.S_IMODE(root_meta.st_mode) == 0o700, "volume-root-metadata")
    capacity = os.statvfs(root)
    need(0 < capacity.f_blocks * capacity.f_frsize <= PG_BYTES, "volume-capacity")
    device = root_meta.st_dev
    for base, dirs, files in os.walk(root, followlinks=False):
        need(len(dirs) + len(files) <= 20000, "volume-entry-bound")
        for name in dirs + files:
            meta = (Path(base) / name).lstat()
            count += 1
            need(count <= 100000 and meta.st_dev == device and meta.st_uid == PG_UID
                 and not stat.S_ISLNK(meta.st_mode)
                 and (stat.S_ISREG(meta.st_mode) or stat.S_ISDIR(meta.st_mode)), "volume-metadata")
            key = meta.st_dev, meta.st_ino
            if key not in seen:
                size += meta.st_blocks * 512
                seen.add(key)
            need(size <= PG_BYTES, "volume-cap-exceeded")
    print(json.dumps(dict(schema=1, kind="volume-scan", bytes=size, entries=count, passed=True)))
    return 0


@dataclass
class CaseResources:
    case: str
    nonce: str
    budget: Budget
    root: Path
    root_identity: tuple[int, int]
    owned: list[Owned] = field(default_factory=list)
    binding: Binding | None = None
    channel: Channel | None = None
    guard: Channel | None = None
    guard_detached: bool = False
    pg: Owned | None = None
    executor: Owned | None = None
    command_seq: int = 0
    response_seq: int = 1
    cleaned: bool = False
    ports: list[int] = field(default_factory=list)
    mounts: list[OwnedMount] = field(default_factory=list)
    pending: list[PendingCreation] = field(default_factory=list)


class Warden:
    def __init__(self, root, receipt, host, origin=None):
        need(os.geteuid() == 0 and platform.system() == "Linux" and platform.machine() == "x86_64",
             "fresh-linux-root-warden-required")
        self.root, self.receipt, self.host = root, receipt, host
        self.campaign = uuid.uuid4().hex
        self.budget = Budget(host.clock() if origin is None else origin, CAMPAIGN_SECONDS, CLEANUP_RESERVE)
        self.directory = root / PREP_DIR
        # Never nest writable case destinations beneath the read-only source
        # bind: that would require runc to mutate the staged public source.
        self.runtime = Path("/var/tmp") / ("maskura-managed-campaign-" + self.campaign)
        self.runtime.mkdir(mode=0o711)
        meta = self.runtime.stat()
        self.runtime_identity = (meta.st_dev, meta.st_ino)
        self.resources = []
        self.coordinator_owned = None
        self.coordinator_channel = None
        self.coordinator_binding = None
        self.coordinator_removed = False
        self.runtime_removed = False
        self.plan_created = False
        self.cancelled = False
        self.results = []
        # Closed startup diagnostics for an empty coordinator stream.
        self.last_adapter_exit = None
        self.last_container_started = None
        self.last_container_exit = None
        self.last_stderr_class = None
        self.host.command_limit = 10
        self.mounts = HostMounts(host, lambda: self.end(cleanup=True))
        self.creations = CreationLedger(host, self.campaign)

    def mount_input(self, path, kind, case=None):
        need(not self.cancelled, "campaign-cancelled")
        expected = {"source": self.directory / "source", "executable": Path(self.receipt["executable"])}
        if case:
            expected.update(case=case.root, config=self.runtime / ("init-" + case.nonce))
        need(kind in expected and path == expected[kind], "host-mount-outside-owned-scope")
        readonly = kind != "case"
        try:
            return self.mounts.bind(path, kind, readonly, deadline=self.end(case))
        finally:
            if case:
                # bind() registers pending creation before any command/readback.
                for receipt in self.mounts.receipts:
                    if receipt.path == path and receipt not in case.mounts:
                        case.mounts.append(receipt)

    def end(self, case=None, cleanup=False):
        self.budget.remaining(self.host.clock(), cleanup)
        if case:
            case.budget.remaining(self.host.clock(), cleanup)
        return min(self.budget.end - (0 if cleanup else CLEANUP_RESERVE),
                   case.budget.end - (0 if cleanup else CASE_CLEANUP) if case else self.budget.end)

    def wait_owned(self, process, case=None, limit=5, expected=None):
        code = process.wait(timeout=max(0, min(limit, self.end(case, True) - self.host.clock())))
        if expected is not None:
            need(code == expected, "owned-process-exit-unproved")
        return code

    def labels(self, nonce):
        return ["--label", LABEL + "=" + self.campaign, "--label", LABEL + ".nonce=" + nonce]

    def admit(self):
        need(os.geteuid() == 0 and platform.system() == "Linux" and platform.machine() == "x86_64",
             "fresh-linux-root-warden-required")
        need(Path("/sys/fs/cgroup/cgroup.controllers").is_file(), "cgroup-v2-required")
        memory = Path("/proc/meminfo").read_text()
        match = re.search(r"(?m)^MemAvailable:\s+(\d+) kB$", memory)
        need(match and int(match[1]) * 1024 >= MIN_MEMORY, "four-slot-memory-admission")
        for name in ("runtime", "postgres"):
            image = self.host.inspect("image", self.receipt["images"][name], self.end())
            need(image.get("Id") == self.receipt["images"][name] and image.get("Architecture") == "amd64"
                 and image.get("Os") == "linux", "runtime-image-changed")
        info = decode(self.host.docker(["info", "--format", "{{json .}}"], self.end()), 1024 * 1024)
        need(info.get("CgroupVersion") == "2" and any("seccomp" in str(x) for x in info.get("SecurityOptions", [])),
             "docker-security-capabilities")
        docker_root = info.get("DockerRootDir")
        need(type(docker_root) is str and Path(docker_root).is_absolute()
             and Path(docker_root) != Path("/") and Path(docker_root).resolve(strict=True) == Path(docker_root),
             "docker-root-invalid")
        self.required_paths = (self.root, self.root / "target", Path(self.receipt["executable"]),
                               self.directory / "source", self.runtime, Path(docker_root))
        self.floors()
        need(not self.host.inventory("container", self.end()), "fresh-vm-containers-required")
        need(not self.host.inventory("volume", self.end()), "fresh-vm-volumes-required")
        self.network_baseline = self.host.inventory("network", self.end())

    def create(self, args, name, nonce, resources=None, kind="container", cleanup=False):
        need(not self.cancelled or cleanup, "campaign-cancelled")
        end = self.end(resources, cleanup)
        images = [value for value in args if type(value) is str and IMAGE_ID.fullmatch(value)]
        need(len(images) == (1 if kind == "container" else 0), "creation-image-binding")
        pending = self.creations.reserve(kind, name, nonce, images[0] if images else None, end)
        if resources:
            resources.pending.append(pending)
        try:
            return self.creations.create(pending, args, end, lambda: self.end(resources, True))
        finally:
            if resources and pending.owned and pending.owned not in resources.owned:
                resources.owned.append(pending.owned)

    def verify(self, owned, case=None, cleanup=False, identity_only=False):
        value = self.host.inspect(owned.kind, owned.identity, self.end(case, cleanup))
        if owned.kind == "volume":
            value = dict(value, Created=value.get("CreatedAt"))
            need(value.get("Options") == pg_options(), "volume-options-changed")
        owned.verify(value, self.campaign)
        if owned.kind == "container" and not identity_only:
            config = value.get("HostConfig", {})
            need(config.get("ReadonlyRootfs") is True and config.get("Privileged") is False
                 and not config.get("PortBindings") and config.get("PublishAllPorts") is False
                 and config.get("PidMode", "") == "" and config.get("IpcMode") in ("private", "none")
                 and config.get("CgroupnsMode") == "private" and config.get("PidsLimit", 0) > 0
                 and 0 < config.get("Memory", 0) <= 768 * 1024 * 1024
                 and config.get("MemorySwap") == config.get("Memory")
                 and 0 < config.get("NanoCpus", 0) <= 500000000, "resource-guards-changed")
            env = value.get("Config", {}).get("Env")
            need(type(env) is list and all(type(x) is str and "=" in x
                 and "proxy" not in x.split("=", 1)[0].lower() for x in env), "proxy-env-forbidden")
        return value

    def start(self, owned, case):
        need(not self.cancelled, "campaign-cancelled")
        self.verify(owned, case)
        need(self.host.docker(["start", owned.identity], self.end(case)).strip().decode() == owned.identity,
             "start-receipt")

    def new_case(self, case):
        need(case in CASES + CONTROLS and not self.cancelled, "case-not-admitted")
        budget = Budget(self.host.clock(), CASE_SECONDS, CASE_CLEANUP)
        nonce = uuid.uuid4().hex
        root = self.runtime / ("managed-release-case-" + str(uuid.UUID(hex=nonce)))
        root.mkdir(mode=0o700)
        os.chown(root, PRODUCT_UID, PRODUCT_UID)
        for name in ("home", "tmp", "spool", "staging"):
            path = root / name
            path.mkdir(mode=0o700)
            os.chown(path, PRODUCT_UID, PRODUCT_UID)
        meta = root.stat()
        resources = CaseResources(case, nonce, budget, root, (meta.st_dev, meta.st_ino))
        self.resources.append(resources)
        return resources

    def database(self, case):
        name = "maskura-managed-pg-" + case.nonce
        volume_name = "maskura-managed-data-" + case.nonce
        options = []
        for key, value in pg_options().items():
            options += ["--opt", key + "=" + value]
        volume = self.create(["volume", "create", "--driver=local", *self.labels(case.nonce), *options,
                              volume_name], volume_name, case.nonce, case, "volume")
        self.verify(volume, case)
        password = uuid.uuid4().hex
        pg = self.create(pg_create(name, self.labels(case.nonce), volume.identity,
                                  self.receipt["images"]["postgres"], case.nonce, password),
                         name, case.nonce, case)
        case.pg = pg
        value = self.verify(pg, case)
        config = value.get("HostConfig", {})
        need(config.get("NetworkMode") == "none" and value.get("Config", {}).get("User") == "999:999"
             and set(config.get("CapDrop", [])) == {"ALL"} and not config.get("CapAdd")
             and not config.get("Binds"), "postgres-isolation-config")
        mounts = value.get("Mounts")
        need(type(mounts) is list and all(x.get("Type") in ("volume", "tmpfs") for x in mounts), "postgres-mounts")
        data_mounts = [x for x in mounts if x.get("Type") == "volume"]
        need(len(data_mounts) == 1 and data_mounts[0].get("Name") == volume.identity
             and data_mounts[0].get("Destination") == "/var/lib/postgresql/data"
             and data_mounts[0].get("Driver") == "local" and data_mounts[0].get("RW") is True, "postgres-data-mount")
        need(set(config.get("Tmpfs", {})) == {"/tmp", "/var/run/postgresql"}, "postgres-tmpfs")
        self.start(pg, case)
        startup = min(self.end(case), case.budget.origin + STARTUP_SECONDS)
        # pg_isready is the only allowed in-PG operation. No host-published port.
        while self.host.clock() < startup:
            self.verify(pg, case)
            try:
                self.host.docker(["exec", "--user=999:999", pg.identity, "pg_isready", "-q",
                                  "-h", "127.0.0.1", "-p", str(chosen_port(case.nonce)),
                                  "-U", "managed_release", "-d", "managed_release_" + case.nonce], startup)
                return dict(host="127.0.0.1", port=chosen_port(case.nonce), user="managed_release",
                            database="managed_release_" + case.nonce, password=password)
            except Refused as error:
                need(str(error) == "command-failed", "postgres-readiness-transport")
                time.sleep(0.1)
        raise Refused("postgres-startup-deadline")

    def executor(self, case, pg):
        descriptor = dict(schema=1, kind="product" if case.case in CASES else case.case,
                          case=case.case, nonce=case.nonce, root=str(case.root),
                          source_root=str(self.root), executable=self.receipt["executable"],
                          product_guard="/usr/local/bin/maskura-product-guard", product_uid=PRODUCT_UID,
                          product_gid=PRODUCT_UID, campaign_end=self.budget.end,
                          case_started=case.budget.origin, pg=pg, source_sha=self.receipt["source_sha"],
                          inputs=self.receipt["inputs"])
        from . import protocol
        protocol.validate_descriptor(descriptor)
        print("managed-linux-executor: descriptor-valid", flush=True)
        config = self.runtime / ("init-" + case.nonce)
        config.mkdir(mode=0o755)
        path = config / "descriptor.json"
        path.write_bytes(encode(descriptor))
        path.chmod(0o400)
        protected = config / "protected"
        protected.mkdir(mode=0o700)
        for name in ("read-canary", "write-canary", "sibling-canary"):
            canary = protected / name
            canary.write_bytes(b"synthetic-control\n")
            canary.chmod(0o600)
        print("managed-linux-executor: inputs-created", flush=True)
        self.mount_input(case.root, "case", case)
        print("managed-linux-executor: case-mounted", flush=True)
        self.mount_input(config, "config", case)
        print("managed-linux-executor: config-mounted", flush=True)
        name = "maskura-managed-case-" + case.nonce
        args = ["create", "--name", name, "--pull=never", "--platform=linux/amd64", "--interactive",
                "--network=" + ("container:" + case.pg.identity if case.pg else "none"),
                *resource_limits(), "--cap-add=SETUID", "--cap-add=SETGID", "--cap-add=KILL",
                "--security-opt=seccomp=" + str(self.directory / "init-seccomp.json"),
                "--user=0:0", *self.labels(case.nonce)]
        mounts = ((self.directory / "source", str(self.root), True),
                  (Path(self.receipt["executable"]), self.receipt["executable"], True),
                  (case.root, str(case.root), False), (config, "/run/maskura", True))
        for source, target, readonly in mounts:
            args += ["--mount", f"type=bind,source={source},target={target}" + (",readonly" if readonly else "")]
        args += ["--entrypoint=/usr/bin/python3", self.receipt["images"]["runtime"], "-I", "-B",
                 "/opt/managed_release_linux/supervisor.py", "--descriptor", DESCRIPTOR]
        case.executor = self.create(args, name, case.nonce, case)
        inspected = self.verify(case.executor, case)
        self.inspect_mounts(case, inspected, mounts)
        process = self.host.spawn(["/usr/bin/docker", "start", "--attach", "--interactive", case.executor.identity])
        case.channel = Channel(process, self.host.clock)
        frame = case.channel.read(min(self.end(case), case.budget.origin + STARTUP_SECONDS))
        ports = check_ready(frame, case.case, case.nonce)
        case.ports = list(ports)
        value = self.verify(case.executor, case)
        pid = value.get("State", {}).get("Pid")
        need(type(pid) is int and pid > 1 and value["State"].get("Running") is True, "container-pid")
        case.binding = Binding(pid)
        status = Path(f"/proc/{pid}/status").read_text()
        for field_name in ("CapEff", "CapPrm", "CapBnd"):
            match = re.search(r"(?m)^" + field_name + r":\s+([0-9a-fA-F]+)$", status)
            need(match and int(match[1], 16) == 0xE0, "init-capabilities-unproved")
        need(re.search(r"(?m)^NoNewPrivs:\s+1$", status) and re.search(r"(?m)^Seccomp:\s+2$", status),
             "init-nnp-seccomp-unproved")
        self.inspect_kernel_mounts(case)
        if case.pg:
            pg_pid = self.verify(case.pg, case)["State"]["Pid"]
            need(Path(f"/proc/{pg_pid}/ns/net").stat().st_ino == case.binding.namespaces["net"], "wrong-pg-netns")
            ports.append(pg["port"])
        need(len(ports) == len(set(ports)), "pg-port-collision")
        guard = self.host.spawn([str(self.directory / "kernel-guard"), "--cgroup-fd", str(case.binding.cgroup),
                                 "--ports", ",".join(map(str, sorted(ports))), "--deadline", native_deadline(self.budget.end)],
                                pass_fds=(case.binding.cgroup,))
        case.guard = Channel(guard, self.host.clock)
        policy_ready(case.guard.read(min(self.end(case), case.budget.origin + STARTUP_SECONDS)), case.binding, ports)
        return frame

    def inspect_mounts(self, case, value, mounts):
        expected = {target: (str(source), not readonly) for source, target, readonly in mounts}
        actual = value.get("Mounts")
        need(type(actual) is list and len(actual) == len(expected), "unexpected-case-mounts")
        seen = set()
        for mount in actual:
            target = mount.get("Destination")
            need(target in expected and target not in seen and mount.get("Type") == "bind"
                 and (mount.get("Source"), mount.get("RW")) == expected[target]
                 and mount.get("Propagation") in ("rprivate", "private"), "unexpected-case-mounts")
            seen.add(target)
        config = value.get("HostConfig", {})
        need(config.get("ReadonlyRootfs") is True and config.get("Privileged") is False
             and config.get("PidMode", "") == "" and config.get("CgroupnsMode") == "private"
             and set(config.get("CapDrop", [])) == {"ALL"}
             and set(config.get("CapAdd", [])) in ({"SETUID", "SETGID", "KILL"},
                                                   {"CAP_SETUID", "CAP_SETGID", "CAP_KILL"})
             and not config.get("PortBindings"), "case-security-config")

    def inspect_kernel_mounts(self, case):
        text = Path(f"/proc/{case.binding.pid}/mountinfo").read_text()
        need(len(text) <= 1024 * 1024, "mountinfo-bound")
        mounts = {}
        for line in text.splitlines():
            fields = line.split()
            need(len(fields) >= 10 and "-" in fields and fields[4] not in mounts, "mountinfo-invalid")
            mounts[fields[4]] = set(fields[5].split(","))
        # Kernel flags, not Docker command-line intent. Missing flags are a hard
        # capability failure; NNP is not represented as a nosuid mount.
        for path, readonly in ((str(self.root), True), (self.receipt["executable"], True),
                               (str(case.root), False), ("/run/maskura", True)):
            need(path in mounts and {"nosuid", "nodev"} <= mounts[path]
                 and ("ro" in mounts[path] if readonly else "rw" in mounts[path]), "mount-flags-unproved")
        for other in self.resources:
            if other is not case:
                need(not any(x == str(other.root) or x.startswith(str(other.root) + "/") for x in mounts),
                     "sibling-mount-visible")
        need("/sys/fs/cgroup" in mounts and "ro" in mounts["/sys/fs/cgroup"], "writable-cgroup-visible")
        need(case.binding.namespaces["pid"] != Path("/proc/self/ns/pid").stat().st_ino
             and case.binding.namespaces["mnt"] != Path("/proc/self/ns/mnt").stat().st_ino
             and case.binding.namespaces["net"] != Path("/proc/self/ns/net").stat().st_ino
             and case.binding.namespaces["ipc"] != Path("/proc/self/ns/ipc").stat().st_ino
             and case.binding.namespaces["uts"] != Path("/proc/self/ns/uts").stat().st_ino,
             "host-namespace-visible")

    def listener_absence(self, case):
        # Read only the acknowledged init's network view, while init is still
        # alive and its namespace identity is pinned. PG can retain its own port.
        need(case.binding.proc(case.binding.pid) == case.binding.init, "listener-init-changed")
        for table in ("tcp", "tcp6"):
            text = Path(f"/proc/{case.binding.pid}/net/{table}").read_text()
            need(len(text) <= 1024 * 1024, "listener-scan-bound")
            for line in text.splitlines()[1:]:
                fields = line.split()
                need(len(fields) >= 10 and re.fullmatch(r"[0-9A-Fa-f]+:[0-9A-Fa-f]{4}", fields[1]), "listener-scan-invalid")
                need(not (fields[3] == "0A" and int(fields[1].rsplit(":", 1)[1], 16) in case.ports),
                     "case-listener-survived")

    def floors(self):
        need(not self.cancelled, "campaign-cancelled")
        for path in self.required_paths:
            need(shutil.disk_usage(path).free >= FREE_BYTES, "filesystem-floor")

    def heartbeat(self, case):
        self.floors()
        need(self.coordinator_channel.process.poll() is None, "coordinator-lost")
        need(self.verify(self.coordinator_owned)["State"].get("Running") is True, "coordinator-lost")
        self.coordinator_binding.only_init()
        self.verify(case.executor, case)
        for owned in list(case.owned):
            if owned.kind == "volume":
                self.measure(case, owned)

    def planner_heartbeat(self):
        need(not self.cancelled, "campaign-cancelled")
        self.budget.remaining(self.host.clock())
        need(self.coordinator_channel.process.poll() is None, "coordinator-lost")
        if self.coordinator_binding:
            self.coordinator_binding.only_init()

    def command(self, case, kind, **extra):
        need(not self.cancelled or kind in ("stop", "abort"), "campaign-cancelled")
        self.end(case)
        case.command_seq += 1
        case.channel.send(dict(schema=1, kind=kind, case=case.case, nonce=case.nonce,
                               seq=case.command_seq, **extra))

    def response(self, case):
        frame = case.channel.read(self.end(case), heartbeat=lambda: self.heartbeat(case))
        validate_init_event(frame)
        case.response_seq += 1
        need(type(frame) is dict and type(frame.get("schema")) is int and frame.get("schema") == 1 and frame.get("case") == case.case
             and frame.get("nonce") == case.nonce and type(frame.get("seq")) is int
             and frame["seq"] == case.response_seq, "response-binding")
        return frame

    def identity(self, case, frame):
        exact(frame, ("schema", "kind", "case", "nonce", "seq", "test_identity", "tls_identity", "ledger_sha256"))
        need(SHA256.fullmatch(frame["ledger_sha256"]), "ledger-hash")
        # Private files are compared, but only independently mapped cgroup members
        # are acknowledged; no PID in a ledger authorizes a host signal.
        ledger = private_read(case.root / "owned-tls-group.json", PRODUCT_UID)
        need(hashlib.sha256(ledger).hexdigest() == frame["ledger_sha256"], "ledger-changed")
        parsed = decode(ledger)
        from . import protocol
        protocol.validate_identity(frame["test_identity"])
        protocol.validate_identity(frame["tls_identity"])
        need(parsed.get("case") == case.case and parsed.get("nonce") == case.nonce
             and parsed.get("root_uid") == PRODUCT_UID
             and parsed.get("test_identity") == frame["test_identity"]
             and parsed.get("tls_identity") == frame["tls_identity"], "ledger-binding")
        case.binding.verify_pair(frame["test_identity"], frame["tls_identity"])
        need(private_read(case.root / "owned-tls-group.json", PRODUCT_UID) == ledger, "ledger-mutated")
        self.command(case, "identity-ack", ledger_sha256=frame["ledger_sha256"])

    def run_case(self, name):
        try:
            case = self.new_case(name)
        except Exception as error:
            print("managed-linux-case: new-case=" + diagnostic_category(error), flush=True)
            raise
        passed = False
        try:
            pg = self.database(case) if name in CASES else None
            print("managed-linux-case: executor", flush=True)
            self.executor(case, pg)
            self.command(case, "controls")
            controls = self.response(case)
            from . import protocol
            exact(controls, ("schema", "kind", "case", "nonce", "seq", "passed", "results"))
            exact(controls["results"], protocol.PROBE_FIELDS)
            expected_controls = {key: True for key in protocol.PROBE_FIELDS}
            expected_controls["owned_loopback"] = name in CASES or name == "isolation-controls"
            need(controls["kind"] == "controls" and controls["passed"] is True
                 and controls["results"] == expected_controls
                 and all(type(x) is bool for x in controls["results"].values()), "kernel-controls-failed")
            if name != "isolation-controls":
                self.command(case, "start")
            ack_count = 0
            while True:
                frame = self.response(case)
                if frame.get("kind") == "identity-request":
                    ack_count += 1
                    need(ack_count <= 3 and name in CASES + ("control-descendant",), "unexpected-identity-request")
                    self.identity(case, frame)
                else:
                    result = closed_result(frame, name, case.nonce)
                    break
            self.detach_policy(case)
            self.command(case, "stop")
            passed = True
            return result
        except Exception as error:
            print("managed-linux-case: execution-failure=" + diagnostic_category(error), flush=True)
            raise
        finally:
            try:
                self.cleanup_case(case, passed)
            except Exception as error:
                print("managed-linux-case: cleanup-failure=" + diagnostic_category(error), flush=True)
                raise

    def detach_policy(self, case):
        # The trusted init remains in wait_stop while its cgroup still exists.
        # Never lift confinement while any product/descendant or listener lives.
        need(case.guard is not None and case.binding is not None, "policy-detach-unproved")
        case.binding.only_init()
        self.listener_absence(case)
        case.guard.process.stdin.write(b"STOP\n")
        case.guard.process.stdin.flush()
        stopped = case.guard.read(self.end(case, True))
        need(stopped == dict(schema=1, kind="kernel-policy", stopped=True, detached=True), "policy-detach-unproved")
        self.wait_owned(case.guard.process, case, expected=0)
        case.guard_detached = True

    def measure(self, case, volume):
        self.verify(volume, case, True)
        # A short-lived, acknowledged helper has no network, no authority and a
        # read-only single-volume mount. It is itself tracked through removal.
        name = "maskura-managed-scan-" + uuid.uuid4().hex
        args = ["create", "--name", name, "--pull=never", "--platform=linux/amd64", "--network=none",
                "--user=999:999", *resource_limits("128m", 32), *self.labels(case.nonce),
                "--mount", f"type=volume,source={volume.identity},target=/pgdata,readonly,volume-nocopy",
                "--entrypoint=/usr/bin/python3", self.receipt["images"]["runtime"], "-I", "-B",
                "/opt/managed_release_linux/controller.py", "--volume-scan"]
        # create() uses work budget; measurement must happen before that expires.
        scan = self.create(args, name, case.nonce, case, cleanup=True)
        try:
            self.verify(scan, case, True)
            raw = self.host.docker(["start", "--attach", scan.identity], self.end(case, True), limit=FRAME_BYTES)
            value = decode(raw)
            exact(value, ("schema", "kind", "bytes", "entries", "passed"))
            need(value["schema"] == 1 and value["kind"] == "volume-scan" and value["passed"] is True
                 and type(value["bytes"]) is int and 0 <= value["bytes"] <= PG_BYTES
                 and type(value["entries"]) is int and 0 <= value["entries"] <= 100000, "volume-scan-failed")
        finally:
            self.remove(scan, case)
            case.owned.remove(scan)

    def remove(self, owned, case=None):
        # Cleanup authority is the full creation identity, not an admission
        # configuration that may itself be the reason this attempt failed.
        value = self.verify(owned, case, True, identity_only=True)
        if owned.kind == "container" and value.get("State", {}).get("Running"):
            self.host.docker(["kill", "--signal=KILL", owned.identity], self.end(case, True))
            value = self.verify(owned, case, True, identity_only=True)
            need(value.get("State", {}).get("Running") is False, "container-kill-unproved")
        self.host.docker([owned.kind, "rm", owned.identity], self.end(case, True))
        need(owned.identity not in self.host.inventory(owned.kind, self.end(case, True)), "resource-removal-unproved")
        if hasattr(self, "creations"):
            for pending in self.creations.pending:
                if pending.owned == owned:
                    pending.removed = True

    def cleanup_case(self, case, passed):
        errors = []
        def attempt(action):
            try:
                action()
            except Exception:
                errors.append("cleanup-unproved")
        if case.channel:
            if not passed:
                def abort():
                    case.command_seq += 1
                    case.channel.send(dict(schema=1, kind="abort", case=case.case, nonce=case.nonce, seq=case.command_seq))
                attempt(abort)
            def wait_init():
                self.wait_owned(case.channel.process, case, limit=10, expected=0)
            attempt(wait_init)
        authority_start = len(errors)
        for pending in case.pending:
            if not pending.removed:
                def reconcile(pending=pending):
                    owned = self.creations.reconcile(pending, self.end(case, True))
                    if owned and owned not in case.owned:
                        case.owned.append(owned)
                attempt(reconcile)
            attempt(lambda pending=pending: need(not pending.attempted or pending.completed,
                                                "creation-request-unresolved"))
        if case.executor:
            def stop_executor():
                value = self.verify(case.executor, case, True, identity_only=True)
                if value.get("State", {}).get("Running"):
                    self.host.docker(["kill", "--signal=KILL", case.executor.identity], self.end(case, True))
                    value = self.verify(case.executor, case, True, identity_only=True)
                need(value.get("State", {}).get("Running") is False, "init-still-running")
            attempt(stop_executor)
        if case.binding:
            attempt(lambda: case.binding.prove_empty_after_stop("case-cgroup-not-empty"))
        if case.guard:
            if not case.guard_detached:
                attempt(lambda: self.detach_policy(case))
            attempt(case.guard.close)
            attempt(lambda: self.wait_owned(case.guard.process, case, expected=0))
        if case.binding:
            attempt(case.binding.close)
        if case.channel:
            attempt(case.channel.close)
            attempt(lambda: self.wait_owned(case.channel.process, case))
        for owned in list(reversed(case.owned)):
            if owned.kind == "volume":
                attempt(lambda owned=owned: self.measure(case, owned))
            attempt(lambda owned=owned: self.remove(owned, case))
        if len(errors) == authority_start:
            for mount in reversed(case.mounts):
                if not mount.removed:
                    attempt(lambda mount=mount: self.mounts.remove(mount, deadline=self.end(case, True)))
            if all(mount.removed for mount in case.mounts):
                attempt(lambda: self.remove_root(case))
                attempt(lambda: self.remove_descriptor(case))
        case.cleaned = not errors
        need(case.cleaned, "cleanup-unproved")

    def remove_root(self, case):
        meta = case.root.lstat()
        need(stat.S_ISDIR(meta.st_mode) and (meta.st_dev, meta.st_ino) == case.root_identity
             and meta.st_uid == PRODUCT_UID and case.root.parent == self.runtime, "root-ownership-changed")
        count = 0
        for base, dirs, files in os.walk(case.root, topdown=False, followlinks=False):
            for name in files + dirs:
                path = Path(base) / name
                entry = path.lstat()
                count += 1
                need(count <= 100000 and entry.st_dev == meta.st_dev and entry.st_uid == PRODUCT_UID,
                     "root-entry-ownership")
                if stat.S_ISDIR(entry.st_mode):
                    path.rmdir()
                else:
                    need(stat.S_ISREG(entry.st_mode) or stat.S_ISLNK(entry.st_mode), "root-entry-kind")
                    path.unlink()  # Symlink itself, never its target.
        case.root.rmdir()
        need(not case.root.exists(), "root-removal-unproved")

    def remove_descriptor(self, case):
        config = self.runtime / ("init-" + case.nonce)
        try:
            meta = config.lstat()
        except FileNotFoundError:
            # This path may be absent only if executor setup never created it.
            need(case.executor is None, "descriptor-disappeared")
            return
        need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and not config.is_symlink(), "descriptor-owner")
        expected = {"descriptor.json", "protected"}
        need({x.name for x in config.iterdir()} <= expected, "unexpected-init-files")
        protected = config / "protected"
        if protected.exists():
            meta = protected.lstat()
            need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0, "canary-owner")
            need({x.name for x in protected.iterdir()} <= {"read-canary", "write-canary", "sibling-canary"},
                 "unexpected-canary-files")
            for path in protected.iterdir():
                meta = path.lstat()
                need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1, "canary-owner")
                path.unlink()
            protected.rmdir()
        descriptor = config / "descriptor.json"
        if descriptor.exists():
            meta = descriptor.lstat()
            need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1, "descriptor-owner")
            descriptor.unlink()
        config.rmdir()

    def remove_runtime(self):
        meta = self.runtime.lstat()
        need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0
             and (meta.st_dev, meta.st_ino) == self.runtime_identity, "campaign-root-changed")
        plan = self.runtime / "plan.json"
        if self.plan_created:
            meta = plan.lstat()
            need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1, "plan-owner")
            plan.unlink()
            self.plan_created = False
        need(not list(self.runtime.iterdir()), "campaign-root-not-empty")
        self.runtime.rmdir()
        self.runtime_removed = True

    def cleanup_coordinator(self):
        errors = []
        def attempt(label, action):
            try:
                action()
            except Exception as error:
                print("managed-linux-coordinator-cleanup: " + label + "=" + diagnostic_category(error), flush=True)
                if label == "cgroup" and isinstance(error, FileNotFoundError):
                    try:
                        unlinked = os.fstat(self.coordinator_binding.cgroup).st_nlink == 0
                        deleted = os.readlink(f"/proc/self/fd/{self.coordinator_binding.cgroup}").endswith(" (deleted)")
                        with selectors.DefaultSelector() as selector:
                            selector.register(self.coordinator_binding.pidfd, selectors.EVENT_READ)
                            exited = bool(selector.select(0))
                        print("managed-linux-coordinator-cleanup: cgroup-unlinked=" + str(unlinked)
                              + " cgroup-deleted=" + str(deleted) + " pidfd-exited=" + str(exited), flush=True)
                    except Exception:
                        print("managed-linux-coordinator-cleanup: cgroup-facts-unavailable", flush=True)
                errors.append("coordinator-cleanup-unproved")
        if self.coordinator_owned and not self.coordinator_removed:
            def stop():
                value = self.verify(self.coordinator_owned, cleanup=True, identity_only=True)
                if value.get("State", {}).get("Running"):
                    self.host.docker(["kill", "--signal=KILL", self.coordinator_owned.identity], self.end(cleanup=True))
                value = self.verify(self.coordinator_owned, cleanup=True, identity_only=True)
                need(value.get("State", {}).get("Running") is False, "coordinator-still-running")
            attempt("stop", stop)
            if self.coordinator_binding:
                attempt("cgroup", lambda: self.coordinator_binding.prove_empty_after_stop("coordinator-cgroup-not-empty"))
                attempt("binding-close", self.coordinator_binding.close)
            def remove():
                self.remove(self.coordinator_owned)
                self.coordinator_removed = True
            attempt("remove", remove)
        if self.coordinator_channel:
            attempt("channel-close", self.coordinator_channel.close)
            def reap_adapter():
                self.wait_owned(self.coordinator_channel.process)
            attempt("adapter-reap", reap_adapter)
        need(not errors, "coordinator-cleanup-unproved")

    def final_cleanup(self):
        authority_cleared = False
        try:
            try:
                self.cleanup_coordinator()
            finally:
                self.cleanup_pending()
            authority_cleared = True
        finally:
            try:
                need(authority_cleared, "host-mount-users-cleanup-unproved")
                need(all(mount.removed for case in self.resources for mount in case.mounts),
                     "case-host-mount-cleanup-unproved")
                for receipt in reversed(self.mounts.receipts):
                    if receipt.kind in ("source", "executable") and not receipt.removed:
                        self.mounts.remove(receipt)
                if not self.runtime_removed:
                    self.remove_runtime()
            finally:
                self.mounts.close()

    def cleanup_pending(self):
        failed = False
        for pending in self.creations.pending:
            if pending.attempted and not pending.completed:
                # Sticky uncertainty even if a visible owned resource was
                # removed: the original daemon request has no completion proof.
                failed = True
            if pending.removed:
                continue
            try:
                owned = self.creations.reconcile(pending, self.end(cleanup=True))
                if owned:
                    self.remove(owned)
                else:
                    need(pending.absent, "pending-absence-unproved")
            except Exception:
                failed = True
        need(not failed, "pending-creation-cleanup-unproved")

    def coordinator_eof_category(self, end):
        """Map an empty coordinator stream to closed adapter/container facts.

        Only the captured adapter's exit status and State booleans/integers are
        read. Raw docker/runc/OCI error strings are never inspected or exported.
        """
        process = self.coordinator_channel.process
        try:
            self.last_adapter_exit = process.wait(timeout=max(0.01, min(3.0, end - self.host.clock())))
        except subprocess.TimeoutExpired:
            return "coordinator-adapter-unresolved"
        need(type(self.last_adapter_exit) is int, "coordinator-adapter-unresolved")
        try:
            value = self.host.inspect("container", self.coordinator_owned.identity,
                                      self.end(cleanup=True))
            state = value.get("State")
        except Exception:
            raise Refused("coordinator-state-unproved") from None
        need(type(state) is dict, "coordinator-state-unproved")
        started_at, exit_code = state.get("StartedAt"), state.get("ExitCode")
        need(type(started_at) is str and type(exit_code) is int
             and not isinstance(exit_code, bool), "coordinator-state-unproved")
        self.last_container_started = started_at not in ("", "0001-01-01T00:00:00Z")
        self.last_container_exit = exit_code
        if not self.last_container_started:
            return "coordinator-never-started"
        # Bounded startup-stderr classification: fixed byte markers only; the
        # bytes themselves are closed immediately and never exported.
        raw = b""
        stream = getattr(process, "stderr", None)
        if stream is not None:
            try:
                raw = stream.read(STDERR_LIMIT + 1) or b""
            except Exception:
                # Diagnostics never mask the primary closed failure category.
                raw = b""
            finally:
                try:
                    stream.close()
                except Exception:
                    pass
        self.last_stderr_class = coordinator_stderr_class(raw)
        if self.last_stderr_class is not None:
            return self.last_stderr_class
        if exit_code == 2:
            return "coordinator-arguments"
        if exit_code == 1:
            # Interpreter-level exit before any frame: fixed code unavailable.
            return "coordinator-startup-crash"
        return "coordinator-startup-exit"

    def read_coordinator(self, end):
        try:
            data = self.coordinator_channel.read(end, heartbeat=self.planner_heartbeat,
                                                 heartbeat_interval=0.1)
        except Refused as error:
            if type(error) is Refused and error.args == ("channel-eof",):
                raise Refused(self.coordinator_eof_category(end)) from None
            raise
        startup = coordinator_startup(data)
        if startup is not None:
            raise Refused(startup)
        return data

    def run(self):
        print("managed-linux-runtime: admission", flush=True)
        self.admit()
        print("managed-linux-runtime: input-mounts", flush=True)
        self.mount_input(self.directory / "source", "source")
        self.mount_input(Path(self.receipt["executable"]), "executable")
        name = "maskura-managed-coordinator-" + self.campaign
        plan = self.runtime / "plan.json"
        plan.write_bytes(encode(dict(schema=1, campaign=self.campaign, source_sha=self.receipt["source_sha"],
                                     campaign_end=self.budget.end, cases=list(CONTROLS + CASES))))
        plan.chmod(0o444)
        self.plan_created = True
        args = ["create", "--name", name, "--pull=never", "--platform=linux/amd64", "--interactive",
                "--network=none", "--user=0:0", *resource_limits("128m", 32), *self.labels(self.campaign),
                "--cap-add=SETUID", "--cap-add=SETGID",
                "--security-opt=seccomp=" + str(self.directory / "init-seccomp.json"),
                "--mount", f"type=bind,source={plan},target=/run/maskura/plan.json,readonly",
                "--entrypoint=" + COORDINATOR_ENTRYPOINT, self.receipt["images"]["runtime"],
                *COORDINATOR_COMMAND]
        print("managed-linux-runtime: coordinator-create", flush=True)
        self.coordinator_owned = self.create(args, name, self.campaign)
        inspected = self.verify(self.coordinator_owned)
        need(len(inspected.get("Mounts", [])) == 1 and inspected["Mounts"][0].get("Source") == str(plan)
             and inspected["Mounts"][0].get("Destination") == "/run/maskura/plan.json"
             and inspected["Mounts"][0].get("RW") is False, "coordinator-mounts")
        # The daemon must have applied the override: an image-default entrypoint
        # would run controller.py with coordinator arguments and exit before main.
        need(coordinator_config(inspected), "coordinator-entrypoint-unproved")
        process = self.host.spawn(["/usr/bin/docker", "start", "--attach", "--interactive",
                                   self.coordinator_owned.identity], stderr=subprocess.PIPE)
        self.coordinator_channel = Channel(process, self.host.clock)
        coordinator_started = self.host.clock()
        print("managed-linux-runtime: coordinator-first-frame", flush=True)
        try:
            seq = 0
            with ThreadPoolExecutor(max_workers=MAX_ACTIVE) as pool:
                for batch in fixed_batches():
                    need(not self.cancelled, "campaign-cancelled")
                    requests = []
                    for case in batch:
                        seq += 1
                        data = self.read_coordinator(
                            min(self.end(), coordinator_started + STARTUP_SECONDS) if self.coordinator_binding is None else self.end())
                        coordinator_request(data, self.campaign, self.receipt["source_sha"], seq, case)
                        requests.append((case, seq))
                    if self.coordinator_binding is None:
                        print("managed-linux-runtime: coordinator-frame-validated", flush=True)
                        pid = self.verify(self.coordinator_owned)["State"]["Pid"]
                        print("managed-linux-runtime: coordinator-binding", flush=True)
                        self.coordinator_binding = Binding(pid, PRODUCT_UID)
                        print("managed-linux-runtime: coordinator-binding-verified", flush=True)
                        status = Path(f"/proc/{pid}/status").read_text()
                        for field_name in ("CapEff", "CapPrm", "CapInh", "CapAmb"):
                            match = re.search(r"(?m)^" + field_name + r":\s+([0-9a-fA-F]+)$", status)
                            need(match and int(match[1], 16) == 0, "coordinator-capabilities")
                        need(re.search(r"(?m)^NoNewPrivs:\s+1$", status)
                             and re.search(r"(?m)^Seccomp:\s+2$", status), "coordinator-seccomp")
                        need(self.coordinator_binding.namespaces["pid"] != Path("/proc/self/ns/pid").stat().st_ino
                             and self.coordinator_binding.namespaces["net"] != Path("/proc/self/ns/net").stat().st_ino
                             and self.coordinator_binding.namespaces["mnt"] != Path("/proc/self/ns/mnt").stat().st_ino
                             and self.coordinator_binding.namespaces["ipc"] != Path("/proc/self/ns/ipc").stat().st_ino
                             and self.coordinator_binding.namespaces["uts"] != Path("/proc/self/ns/uts").stat().st_ino,
                             "coordinator-host-namespace")
                        need(set(x.name for x in Path(f"/proc/{pid}/fd").iterdir()) == {"0", "1", "2"},
                             "coordinator-extra-fds")
                    futures = [pool.submit(self.run_case, case) for case in batch]
                    # Every submitted case finishes cleanup, including failures.
                    results, errors = [], []
                    for future in futures:
                        try:
                            results.append(future.result())
                        except Exception:
                            errors.append("case-failed")
                    need(not errors and all(c.cleaned for c in self.resources), "case-or-cleanup-failed")
                    self.results.extend(results)
                    for case, case_seq in requests:
                        self.coordinator_channel.send(dict(schema=1, kind="case-status", campaign=self.campaign,
                                                           source_sha=self.receipt["source_sha"],
                                                           case=case, seq=case_seq, passed=True))
            self.wait_owned(process, expected=0)
            need([x["case"] for x in self.results if x["case"] in CASES] == list(CASES), "thirteen-cases-required")
            validate_prepared(self.root, self.receipt["source_sha"])
        except Exception as error:
            print("managed-linux-runtime: execution-failure=" + failure_category(error), flush=True)
            raise
        finally:
            self.cleanup_coordinator()
        need(all(x.cleaned for x in self.resources), "campaign-cleanup-unproved")
        need(not self.host.inventory("container", self.end(cleanup=True)), "container-inventory-not-empty")
        volumes = self.host.inventory("volume", self.end(cleanup=True))
        need(not any(x.startswith("maskura-managed-data-") for x in volumes), "owned-volume-survived")
        need(self.host.inventory("network", self.end(cleanup=True)) == self.network_baseline, "unexpected-network-object")
        self.remove_runtime()
        return dict(schema=1, kind="managed-linux-qualification", source_sha=self.receipt["source_sha"],
                    architecture="linux/amd64", passed=True, cases=13, ignored=0, controls=len(CONTROLS),
                    cleanup=True, network_objects=0, results=self.results,
                    inputs=self.receipt["inputs"], images=self.receipt["images"],
                    harness_hashes=self.receipt["harness_hashes"])


def main(argv=None):
    parser = argparse.ArgumentParser(description="Bounded native Linux managed qualification (explicit execution only)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--prepare", action="store_true")
    mode.add_argument("--warden", action="store_true")
    mode.add_argument("--volume-scan", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--source-sha")
    options = parser.parse_args(argv)
    if options.volume_scan:
        return volume_scan()
    if not options.execute:
        print("managed Linux qualification not executed; --execute and a phase are required")
        return 2
    need(options.prepare or options.warden, "phase-required")
    root = Path(__file__).resolve().parents[2]
    warden = None
    try:
        need(options.source_sha and SOURCE_SHA.fullmatch(options.source_sha), "source-required")
        if options.prepare:
            prepare(root, options.source_sha, Host())
            print("managed Linux preparation completed; no runtime qualification claimed")
            return 0
        host = Host()
        origin = host.clock()  # Includes source revalidation and all admission.
        receipt = validate_prepared(root, options.source_sha)
        warden = Warden(root, receipt, host, origin=origin)
        previous = {}
        def cancel(_number, _frame):
            warden.cancelled = True
        for number in (signal.SIGINT, signal.SIGTERM):
            previous[number] = signal.signal(number, cancel)
        try:
            result = warden.run()
        finally:
            try:
                warden.final_cleanup()
            except Exception as error:
                print("managed-linux-runtime: final-cleanup-failure=" + failure_category(error), flush=True)
                raise
            finally:
                for number, handler in previous.items():
                    signal.signal(number, handler)
        # The only exported file is closed metadata, not descriptors or spools.
        report = root / PREP_DIR / "qualification.json"
        result["host_mounts"] = [dict(kind=mount.kind, mount_id=mount.mount_id, namespace=list(mount.namespace),
                                      device=mount.inode[0], inode=mount.inode[1], readonly=mount.readonly,
                                      nosuid="nosuid" in mount.flags, nodev="nodev" in mount.flags,
                                      removed=mount.removed) for mount in warden.mounts.receipts]
        report.write_bytes(json.dumps(result, sort_keys=True).encode() + b"\n")
        report.chmod(0o644)
        print("managed Linux qualification passed: 13 cases, zero ignores, cleanup proved")
        return 0
    except Exception as error:
        if options.warden:
            report = root / PREP_DIR / "qualification.json"
            # Closed failed-attempt record. No resource absence is asserted.
            try:
                source = options.source_sha if options.source_sha and SOURCE_SHA.fullmatch(options.source_sha) else "0" * 40
                adapter_exit = getattr(warden, "last_adapter_exit", None)
                started = getattr(warden, "last_container_started", None)
                container_exit = getattr(warden, "last_container_exit", None)
                report.write_bytes(encode(dict(schema=1, kind="managed-linux-qualification", source_sha=source,
                                               architecture="linux/amd64", passed=False, cases=0, ignored=0,
                                               cleanup=False, status="qualification-failed",
                                               failure_category=failure_category(error),
                                               adapter_exit=adapter_exit if type(adapter_exit) is int else None,
                                               container_started=started if type(started) is bool else None,
                                               container_exit=container_exit if type(container_exit) is int else None)))
                report.chmod(0o644)
            except Exception:
                pass  # Failure to retain evidence is never converted to success.
        print("managed Linux qualification failed: " + failure_category(error)
              + "; no acceptance or cleanup claim", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
