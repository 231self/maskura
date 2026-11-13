"""Pure contracts and explicit bounded I/O for the trusted Linux case init.

No import-time filesystem, process, socket, FFI or privilege operations.
Exceptions contain closed codes only; never interpolate runtime input.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import uuid

CASES = (
    ("http", "managed_release_http_put_multipart_restart_and_replay"),
    ("recovery-valid", "managed_release_recovery_valid"),
    ("recovery-customer", "managed_release_recovery_customer"),
    ("recovery-content-type", "managed_release_recovery_content_type"),
    ("recovery-encoding", "managed_release_recovery_encoding"),
    ("recovery-identity", "managed_release_recovery_identity"),
    ("recovery-codec", "managed_release_recovery_codec"),
    ("recovery-physical-key", "managed_release_recovery_physical_key"),
    ("recovery-versioning", "managed_release_recovery_versioning"),
    ("repair-valid", "managed_release_repair_valid"),
    ("repair-source-mismatch", "managed_release_repair_source_mismatch"),
    ("tls-unrelated-ca", "managed_release_tls_unrelated_ca"),
    ("tls-wrong-numeric-san", "managed_release_tls_wrong_numeric_san"),
)
SELECTORS = {case: "managed_release::" + selector for case, selector in CASES}
CONTROL_CASES = (
    "control-before-start", "control-descendant", "strict-provider",
    "deadline-contract", "python-mocks", "slow-peer", "isolation-controls",
)
CONTROL_SELECTORS = {
    "control-before-start": "managed_release_fixture::owned_tls_main_exit_before_start",
    "control-descendant": "managed_release_fixture::owned_tls_leader_exit_with_live_descendant",
    "strict-provider": "managed_release_fixture::strict_managed_provider_contract",
    "deadline-contract": "managed_release_fixture::owned_tls_startup_deadline_contract",
}
ROLES = ("provider", "tls", "gateway-1", "gateway-2", "gateway-3")
SLOW_ROLES = ("slow-peer", "slow-relay")
INPUTS = (
    "executable_sha256", "tls_sha256", "python_test_sha256",
    "product_guard_sha256", "protocol_sha256", "supervisor_sha256", "probe_sha256",
)
PRODUCT_GUARD = "/usr/local/bin/maskura-product-guard"
MODULE_ROOT = "/opt/managed_release_linux"
DESCRIPTOR_PATH = "/run/maskura/descriptor.json"
FRAME_LIMIT = 8192
DESCRIPTOR_LIMIT = 16384
SHUTDOWN = "MANAGED_RELEASE_SHUTDOWN group-absent workers-ended listeners-closed"
PROBE_FIELDS = (
    "owned_file", "owned_loopback", "forbidden_read", "forbidden_write",
    "sibling_read", "external_network", "undeclared_port", "default_5432",
    "default_54322", "ipv6", "raw_socket", "ptrace", "setns",
    "capabilities", "no_new_privs", "standard_fds", "no_extra_fds", "identity",
)
CLEANUP_FIELDS = ("main_group_absent", "main_reaped", "tls_group_absent", "tls_reaped",
                  "listeners_closed", "reservations_closed", "within_deadline")
CONTROL_FIELDS = ("before_start_eof", "descendant_live_after_leader_exit", "descendant_sigkill",
                  "strict_provider", "deadline_contract", "python_mocks", "slow_peer",
                  "isolation_controls", "python_tests_run")
COUNT_FIELDS = ("selected", "passed", "summary", "complete", "shutdown")


class ContractError(Exception):
    """Only statically authored, privacy-safe codes belong in this exception."""


def need(condition, code="contract-rejected"):
    if not condition:
        raise ContractError(code)


def exact(value, keys):
    need(type(value) is dict and set(value) == set(keys), "unexpected-schema")


def integer(value, minimum=0, maximum=2**63 - 1):
    return type(value) is int and minimum <= value <= maximum


def hash_text(value, length=64):
    return type(value) is str and re.fullmatch("[0-9a-f]{%d}" % length, value) is not None


def sha(data):
    return hashlib.sha256(data).hexdigest()


def equal_record(actual, expected):
    """JSON structural equality without Python's bool==1 / float==int aliases."""
    return encode_json(actual) == encode_json(expected)


def encode_json(value):
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False,
                          sort_keys=True, separators=(",", ":")).encode("ascii")
    except (ValueError, TypeError, RecursionError):
        raise ContractError("json-encoding") from None


def decode_json(data, max_bytes=DESCRIPTOR_LIMIT):
    need(type(data) is bytes and len(data) <= max_bytes, "json-size")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "duplicate-json-key")
            result[key] = value
        return result

    def constant(_value):
        raise ContractError("json-constant")

    try:
        return json.loads(data.decode("ascii"), object_pairs_hook=unique,
                          parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ContractError("json-decoding") from None


def absolute_path(value):
    need(type(value) is str and 1 <= len(value) <= 4096
         and "\x00" not in value and "\\" not in value, "absolute-path")
    path = PurePosixPath(value)
    need(path.is_absolute() and str(path) == value and ".." not in path.parts,
         "canonical-path")
    return value


def clock_value(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def validate_descriptor(value):
    exact(value, ("schema", "kind", "case", "nonce", "root", "source_root",
                  "executable", "product_guard", "product_uid", "product_gid",
                  "campaign_end", "case_started", "pg", "source_sha", "inputs"))
    need(type(value["schema"]) is int and value["schema"] == 1, "descriptor-schema")
    kind, case, nonce = value["kind"], value["case"], value["nonce"]
    need(type(kind) is str and kind in ("product",) + CONTROL_CASES, "descriptor-kind")
    need(type(case) is str and (case in SELECTORS if kind == "product" else case == kind),
         "descriptor-case")
    need(hash_text(nonce, 32), "descriptor-nonce")
    for name in ("root", "source_root", "executable"):
        absolute_path(value[name])
    need(PurePosixPath(value["root"]).name == "managed-release-case-" + str(uuid.UUID(hex=nonce)),
         "descriptor-root-binding")
    need(value["product_guard"] == PRODUCT_GUARD and type(value["product_uid"]) is int
         and type(value["product_gid"]) is int
         and value["product_uid"] == value["product_gid"] == 20001, "product-identity")
    need(clock_value(value["campaign_end"]) and clock_value(value["case_started"])
         and value["case_started"] < value["campaign_end"]
         and value["campaign_end"] - value["case_started"] <= 3600, "descriptor-deadline")
    need(hash_text(value["source_sha"], 40), "descriptor-source")
    exact(value["inputs"], INPUTS)
    need(all(hash_text(item) for item in value["inputs"].values()), "descriptor-inputs")
    pg = value["pg"]
    if kind == "product":
        exact(pg, ("host", "port", "user", "database", "password"))
        need(pg["host"] == "127.0.0.1" and valid_port(pg["port"])
             and pg["user"] == "managed_release"
             and pg["database"] == "managed_release_" + nonce
             and hash_text(pg["password"], 32), "descriptor-pg")
    else:
        need(pg is None, "unexpected-pg")
    # Break caller aliases; canonical ASCII also rejects nonfinite nested data.
    return decode_json(encode_json(value))


def valid_port(value):
    return integer(value, 1024, 65535) and value not in (5432, 54322)


def read_private_bytes(path, uid, max_bytes=4096, mode=0o600):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "canonical-private-file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == uid
             and stat.S_IMODE(before.st_mode) == mode and before.st_size <= max_bytes
             and before.st_nlink == 1, "private-file-metadata")
        data = os.read(fd, max_bytes + 1)
        after = os.fstat(fd)
        need(len(data) == before.st_size and len(data) <= max_bytes
             and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                  before.st_uid, before.st_mode, before.st_nlink)
             == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                 after.st_uid, after.st_mode, after.st_nlink), "private-file-changed")
        return data
    finally:
        os.close(fd)


def read_private_json(path, uid, max_bytes=4096):
    result = decode_json(read_private_bytes(path, uid, max_bytes), max_bytes)
    need(type(result) is dict, "record-object")
    return result


def atomic_record(path, value):
    """Caller selects product fsuid; fresh files are 0600, never chmod/chown."""
    path = Path(path)
    need(path.is_absolute() and path.parent.resolve(strict=True) == path.parent,
         "canonical-record-parent")
    data = encode_json(value) + b"\n"
    need(len(data) <= 4096, "record-size")
    temporary = path.with_name(path.name + ".new-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def validate_identity(value):
    exact(value, ("pid", "ppid", "pgid", "uid", "alive", "birth"))
    need(all(integer(value[key], 0, 2**32 - 1) for key in ("pid", "ppid", "pgid", "uid"))
         and value["pid"] > 1 and value["pgid"] > 1 and type(value["alive"]) is bool,
         "identity-fields")
    birth = value["birth"]
    exact(birth, ("system", "start_sec", "start_subsec", "boot"))
    need(birth["system"] == "linux" and type(birth["start_sec"]) is int
         and birth["start_sec"] == 0 and integer(birth["start_subsec"], 1)
         and type(birth["boot"]) is str, "identity-birth")
    try:
        need(str(uuid.UUID(birth["boot"])) == birth["boot"], "identity-boot")
    except ValueError:
        raise ContractError("identity-boot") from None
    return value


def capture_local(pid):
    """Public fixture's Linux birth schema, with kernel effective-UID readback.

    Call only for self, a held direct child, or a locally validated ledger's
    candidate while its captured direct parent is live. Never enumerate /proc.
    Only ENOENT is absence; permission/malformed metadata is an error.
    """
    need(sys.platform.startswith("linux") and integer(pid, 2, 2**32 - 1), "local-pid")
    try:
        directory = os.open(Path("/proc") / str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    try:
        # The pinned proc directory prevents combining a reused PID's status
        # with the original process's stat. File ownership is not process UID:
        # Linux makes proc files root-owned when a process becomes a zombie.
        records = []
        for name, limit in (("stat", 4096), ("status", 16384)):
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            except FileNotFoundError:
                return None
            try:
                record = os.read(fd, limit + 1)
                need(len(record) <= limit, "proc-stat-size")
                records.append(record)
            finally:
                os.close(fd)
    finally:
        os.close(directory)
    try:
        data, status = records
        status = status.decode("ascii").splitlines()
        uids = [line.split()[1:] for line in status if line.startswith("Uid:")]
        pids = [line.split()[1:] for line in status if line.startswith("Pid:")]
        need(len(uids) == 1 and len(uids[0]) == 4
             and all(re.fullmatch(r"[0-9]+", value) for value in uids[0])
             and all(integer(int(value), 0, 2**32 - 1) for value in uids[0])
             and pids == [[str(pid)]], "proc-status-identity")
        text = data.decode("ascii")
        end = text.rfind(")")
        need(end > 0 and text.split(" (", 1)[0] == str(pid), "proc-stat-pid")
        fields = text[end + 2:].split()
        need(len(fields) >= 20 and fields[0] in ("R", "S", "D", "Z", "T", "t", "X", "x", "I", "P", "W"),
             "proc-stat-fields")
        # Exactly the public fixture's start tick/boot representation.
        with open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii") as stream:
            boot = stream.read(65).strip()
        return validate_identity(dict(pid=pid, ppid=int(fields[1]), pgid=int(fields[2]),
            uid=int(uids[0][1]), alive=fields[0] not in ("Z", "X", "x"),
            birth=dict(system="linux", start_sec=0, start_subsec=int(fields[19]), boot=boot)))
    except (ValueError, UnicodeError, IndexError):
        raise ContractError("proc-stat-malformed") from None


def same_process(actual, expected):
    return actual is not None and all(actual[key] == expected[key] for key in ("pid", "pgid", "uid", "birth"))


def case_roles(kind):
    if kind in ("product", "control-before-start", "control-descendant", "isolation-controls"):
        return ROLES
    return SLOW_ROLES if kind == "slow-peer" else ()


def validate_event(value):
    """Closed public output allowlist. Descriptors/bodies cannot become events."""
    need(type(value) is dict, "event-object")
    kind = value.get("kind")
    extra = {
        "ready": ("ports",),
        "controls": ("passed", "results"),
        "identity-request": ("test_identity", "tls_identity", "ledger_sha256"),
        "case-result": ("passed", "status", "counts", "panic_locations", "cleanup", "control"),
    }
    need(type(kind) is str and kind in extra, "event-kind")
    exact(value, ("schema", "kind", "case", "nonce", "seq") + extra[kind])
    case = value["case"]
    need(type(value["schema"]) is int and value["schema"] == 1
         and type(case) is str and case in tuple(SELECTORS) + CONTROL_CASES
         and hash_text(value["nonce"], 32) and integer(value["seq"], 1, 1000000), "event-binding")
    if kind == "ready":
        exact(value["ports"], case_roles("product" if case in SELECTORS else case))
        ports = list(value["ports"].values())
        need(all(valid_port(port) for port in ports) and len(ports) == len(set(ports)), "event-ports")
    elif kind == "controls":
        need(type(value["passed"]) is bool, "event-passed")
        exact(value["results"], PROBE_FIELDS)
        need(all(type(item) is bool for item in value["results"].values()), "event-probe-types")
        if value["passed"]:
            expected = {key: True for key in PROBE_FIELDS}
            expected["owned_loopback"] = case in SELECTORS or case == "isolation-controls"
            need(value["results"] == expected, "event-probe-facts")
    elif kind == "identity-request":
        need(case in SELECTORS or case == "control-descendant", "event-identity-case")
        parent, child = validate_identity(value["test_identity"]), validate_identity(value["tls_identity"])
        need(hash_text(value["ledger_sha256"]) and parent["uid"] == child["uid"] == 20001
             and parent["alive"] and child["alive"] and parent["pgid"] == parent["pid"]
             and parent["ppid"] == 1 and child["pgid"] == child["pid"]
             and child["pid"] != parent["pid"] and child["ppid"] == parent["pid"], "event-identity-scope")
    else:
        need(type(value["passed"]) is bool and value["status"] in ("passed", "failed", "cleanup-incomplete")
             and (value["passed"] == (value["status"] == "passed")), "event-result-status")
        exact(value["counts"], COUNT_FIELDS)
        need(all(integer(item, 0, 2**20) for item in value["counts"].values()), "event-counts")
        exact(value["cleanup"], CLEANUP_FIELDS)
        need(all(type(item) is bool for item in value["cleanup"].values()), "event-cleanup")
        exact(value["control"], CONTROL_FIELDS)
        need(all(type(item) is bool for key, item in value["control"].items() if key != "python_tests_run")
             and type(value["control"]["python_tests_run"]) is int
             and value["control"]["python_tests_run"] in (0, 5), "event-control")
        locations = value["panic_locations"]
        need(type(locations) is list and len(locations) <= 16, "event-panic-bound")
        for location in locations:
            exact(location, ("code", "line", "column"))
            need(location["code"] in ("DB_OWNER", "MANAGED_CASE", "MANAGED_FIXTURE")
                 and integer(location["line"], 0, 999999) and integer(location["column"], 0, 999999),
                 "event-panic-location")
        if value["passed"]:
            need(all(value["cleanup"].values()) and not locations, "event-acceptance-cleanup")
            if case in SELECTORS:
                need(value["counts"] == dict(selected=1, passed=1, summary=1, complete=1, shutdown=1),
                     "event-acceptance-markers")
            elif case in ("strict-provider", "deadline-contract"):
                need(value["counts"] == dict(selected=1, passed=1, summary=1, complete=0, shutdown=0),
                     "event-contract-counts")
            if case == "control-before-start":
                need(value["control"]["before_start_eof"], "event-before-start")
            elif case == "control-descendant":
                need(value["control"]["descendant_live_after_leader_exit"]
                     and value["control"]["descendant_sigkill"], "event-descendant")
            elif case in CONTROL_CASES:
                flag = case.replace("-", "_")
                need(value["control"][flag], "event-control-proof")
                if case == "python-mocks":
                    need(value["control"]["python_tests_run"] == 5, "event-five-mocks")
    return value


def fixed_argv(descriptor):
    kind, case = descriptor["kind"], descriptor["case"]
    if kind in ("python-mocks", "slow-peer"):
        argv = ["/usr/bin/python3", "-I", "-B",
                str(PurePosixPath(descriptor["source_root"]) / "scripts/tests/test_managed_release_tls.py")]
        if kind == "slow-peer":
            argv += ["--owned-slow-peer-root", descriptor["root"]]
        return argv
    need(kind != "isolation-controls", "isolation-has-no-product")
    selector = SELECTORS[case] if kind == "product" else CONTROL_SELECTORS[kind]
    argv = [descriptor["executable"], "--exact", selector]
    if kind in ("product", "control-before-start", "control-descendant"):
        argv.append("--ignored")
    return argv + ["--test-threads=1", "--nocapture"]


class ClosedDrain:
    """Bounded incremental parsing; never retain bodies, URLs or raw errors."""
    MAX_BYTES = 1024 * 1024
    MAX_LINE = 4096

    def __init__(self, case=None, selector=None, stderr=False, discard=False):
        need(case is None or case in SELECTORS, "drain-case")
        self.case = case
        self.selector = selector or SELECTORS.get(case)
        self.stderr, self.discard = stderr, discard
        self.pending = bytearray()
        self.total, self.prefixes = 0, 0
        self.bad = False
        self.counts = dict(selected=0, passed=0, summary=0, complete=0, shutdown=0)
        self.panic_locations = []

    def feed(self, data):
        self.total += len(data)
        if self.total > self.MAX_BYTES:
            self.bad = True
        if self.bad:
            self.pending.clear()
            return
        for byte in data:
            if byte == 10:
                self.line(bytes(self.pending))
                self.pending.clear()
                if self.bad:
                    return
            elif len(self.pending) >= self.MAX_LINE:
                self.bad = True
                self.pending.clear()
                return
            else:
                self.pending.append(byte)

    def line(self, raw):
        if self.stderr:
            if b"panicked at" in raw or b"MANAGED_RELEASE_" in raw:
                self.bad = True
                location = re.search(rb"crates/gateway/tests/db_keys_test/(main\.rs|managed_release\.rs|managed_release_fixture\.rs):([0-9]{1,6}):([0-9]{1,6})", raw)
                if location and len(self.panic_locations) < 16:
                    codes = {b"main.rs": "DB_OWNER", b"managed_release.rs": "MANAGED_CASE",
                             b"managed_release_fixture.rs": "MANAGED_FIXTURE"}
                    self.panic_locations.append(dict(code=codes[location[1]], line=int(location[2]), column=int(location[3])))
            return
        if self.discard:
            return
        prefix = ("test " + self.selector + " ... ").encode("ascii")
        if raw.startswith(prefix):
            self.prefixes += 1
            self.bad |= self.prefixes != 1
            raw = raw[len(prefix):]
        if raw == b"running 1 test":
            self.counts["selected"] += 1
        elif raw == b"ok" and self.prefixes == 1:
            self.counts["passed"] += 1
        elif re.fullmatch(rb"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s", raw):
            self.counts["summary"] += 1
        elif self.case is not None and raw == ("MANAGED_RELEASE_COMPLETE " + self.case + " assertions-ok").encode("ascii"):
            self.bad |= self.counts["shutdown"] != 1
            self.counts["complete"] += 1
        elif raw == SHUTDOWN.encode("ascii"):
            self.counts["shutdown"] += 1
        elif raw.startswith(b"MANAGED_RELEASE_") or b" ... ignored" in raw or b" ... FAILED" in raw or raw.startswith(b"test result: FAILED"):
            self.bad = True

    def finish(self):
        # Negative controls deliberately SIGKILL the fixture owner mid-test.
        # Their stdout is discarded, not acceptance evidence, and libtest may
        # leave an unterminated prefix. Size/line bounds and stderr stay strict.
        need(not self.bad and (not self.pending or (self.discard and not self.stderr)),
             "output-overflow-failure-or-truncation")
        if not self.stderr and not self.discard:
            need(self.prefixes == 1 and self.counts == dict(selected=1, passed=1, summary=1,
                 complete=int(self.case is not None), shutdown=int(self.case is not None)),
                 "missing-or-duplicate-acceptance-record")
        return True


class JsonDrain:
    """Retains at most one small private record, exports only closed fields."""
    def __init__(self, limit=4096):
        self.limit, self.data, self.bad = limit, bytearray(), False

    def feed(self, data):
        if len(self.data) + len(data) > self.limit:
            self.bad = True
            self.data.clear()
        elif not self.bad:
            self.data.extend(data)

    def finish(self, kind):
        need(not self.bad and self.data.endswith(b"\n") and self.data.count(b"\n") == 1, "closed-json-output")
        record = decode_json(bytes(self.data), self.limit)
        if kind == "python-mocks":
            expected = dict(kind="socket-free-mock", tests_run=5, failures=0, errors=0,
                            real_network=False, tls_executed=False, openssl_executed=False)
            exact(record, expected)
            need(record == expected and all(type(record[key]) is type(value) for key, value in expected.items()),
                 "python-five-mocks")
        elif kind == "slow-peer":
            fields = ("no_receive_after_write_failure", "received_prefix_ordered",
                      "fixture_failure_not_gateway_result", "workers_ended",
                      "listeners_closed", "connections_closed")
            exact(record, ("kind", "passed") + fields)
            need(record["kind"] == "owned-slow-peer" and record["passed"] is True
                 and all(record[key] is True for key in fields), "real-slow-peer-not-proved")
        elif kind == "probe":
            exact(record, ("kind", "passed", "results"))
            exact(record["results"], PROBE_FIELDS)
            need(record["kind"] == "isolation-probe" and record["passed"] is True
                 and all(type(item) is bool for item in record["results"].values()), "probe-record")
        else:
            raise ContractError("unknown-json-result")
        self.data.clear()
        return record
