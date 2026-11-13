"""Cheap source-only tests. No Linux/native/FFI/socket/process execution.

Audit tripwires make an accidentally unmocked runtime operation a test failure.
These tests are not kernel controls or product qualification receipts.
"""
from contextlib import nullcontext
import copy
import errno
import importlib
import io
import os
from pathlib import Path
import re
import signal
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock
import uuid

from scripts.managed_release_linux import protocol as P
from scripts.managed_release_linux import supervisor as S
from scripts.managed_release_linux import probe as Q


AUDIT = {"active": False}


def guard(event, _args):
    if AUDIT["active"] and (event.startswith("socket.") or event.startswith("subprocess.")
                            or event.startswith("ctypes.") or event in (
                                "os.kill", "os.killpg", "os.fork", "os.posix_spawn",
                                "os.exec", "fcntl.flock")):
        raise AssertionError("unit test attempted runtime operation")


sys.addaudithook(guard)


def descriptor(kind="product"):
    nonce = "12345678123456781234567812345678"
    return dict(schema=1, kind=kind, case="http" if kind == "product" else kind,
                nonce=nonce, root="/run/cases/managed-release-case-" + str(uuid.UUID(hex=nonce)),
                source_root="/build/source", executable="/build/target/debug/deps/db_keys_test-1234",
                product_guard=P.PRODUCT_GUARD, product_uid=20001, product_gid=20001,
                campaign_end=3700.0, case_started=100.0,
                pg=dict(host="127.0.0.1", port=15432, user="managed_release",
                        database="managed_release_" + nonce, password="a" * 32) if kind == "product" else None,
                source_sha="b" * 40, inputs={key: "c" * 64 for key in P.INPUTS})


def identity(pid=42, ppid=1, pgid=None, uid=20001, ticks=1234, alive=True):
    return dict(pid=pid, ppid=ppid, pgid=pid if pgid is None else pgid, uid=uid, alive=alive,
                birth=dict(system="linux", start_sec=0, start_subsec=ticks,
                           boot="12345678-1234-5678-1234-567812345678"))


def command(kind, seq=1, value=None, **extra):
    value = value or descriptor()
    return dict(schema=1, kind=kind, case=value["case"], nonce=value["nonce"], seq=seq, **extra)


def running(kind="product"):
    value = descriptor(kind)
    state = S.Lifecycle(value)
    state.command(command("controls", value=value), 101)
    state.controls_done()
    state.command(command("start", seq=2, value=value), 102)
    return value, state


class GuardedTest(unittest.TestCase):
    def setUp(self):
        AUDIT["active"] = True
        self.addCleanup(AUDIT.__setitem__, "active", False)


class DescriptorTests(GuardedTest):
    def test_audit_guard_is_armed(self):
        for event in ("socket.__new__", "subprocess.Popen", "ctypes.dlopen", "os.killpg", "fcntl.flock"):
            with self.assertRaises(AssertionError):
                sys.audit(event)

    def test_imports_are_definitions_only(self):
        with mock.patch.object(S.os, "open", side_effect=AssertionError("import file operation")), \
             mock.patch.object(S.os, "getpid", side_effect=AssertionError("import process operation")):
            for module in (P, S, Q):
                importlib.reload(module)

    def test_exact_thirteen_selectors_match_unchanged_public_source(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / "crates/gateway/tests/db_keys_test/managed_release.rs").read_text()
        names = re.findall(r'#\[test\]\s*#\[ignore = "requires owned managed release qualification launcher"\]\s*fn\s+(\w+)\s*\(', source)
        self.assertEqual(sorted(names), sorted(name for _case, name in P.CASES))
        fixture = (root / "crates/gateway/tests/db_keys_test/managed_release_fixture.rs").read_text()
        for selector in P.CONTROL_SELECTORS.values():
            self.assertIn("fn " + selector.split("::")[-1] + "(", fixture)

    def test_descriptor_roundtrip_and_alias_separation(self):
        value = descriptor()
        normalized = P.validate_descriptor(value)
        self.assertEqual(normalized, value)
        normalized["inputs"]["tls_sha256"] = "e" * 64
        self.assertNotEqual(value, normalized)
        self.assertTrue(P.encode_json(value).isascii())

    def test_descriptor_exact_schema_and_type_rejection(self):
        changes = [dict(schema=True), dict(product_uid=True), dict(product_gid=0),
                   dict(kind="arbitrary"), dict(case="missing"), dict(nonce="A" * 32),
                   dict(root="/run/cases/not-case"), dict(source_root="/a/../b"),
                   dict(executable="relative"), dict(product_guard="/bin/sh"),
                   dict(campaign_end=float("nan")), dict(case_started=True),
                   dict(case_started=3700), dict(campaign_end=3701),
                   dict(source_sha="a" * 64), dict(extra="secret")]
        for change in changes:
            with self.subTest(change=list(change)):
                value = descriptor()
                value.update(change)
                with self.assertRaises(P.ContractError):
                    P.validate_descriptor(value)
        for key in descriptor():
            value = descriptor()
            del value[key]
            with self.assertRaises(P.ContractError):
                P.validate_descriptor(value)

    def test_pg_and_input_allowlist(self):
        for update in (dict(host="localhost"), dict(port=5432), dict(port=54322),
                       dict(port=True), dict(user="postgres"), dict(password="customer-secret"),
                       dict(database="shared"), dict(url="postgres://secret")):
            value = descriptor()
            value["pg"].update(update)
            with self.assertRaises(P.ContractError):
                P.validate_descriptor(value)
        for key in P.INPUTS:
            value = descriptor()
            del value["inputs"][key]
            with self.assertRaises(P.ContractError):
                P.validate_descriptor(value)
        value = descriptor()
        value["inputs"]["payload_sha256"] = "a" * 64
        with self.assertRaises(P.ContractError):
            P.validate_descriptor(value)

    def test_all_control_kinds(self):
        for kind in P.CONTROL_CASES:
            value = descriptor(kind)
            self.assertEqual(P.validate_descriptor(value), value)
            value["pg"] = descriptor()["pg"]
            with self.assertRaises(P.ContractError):
                P.validate_descriptor(value)

    def test_duplicate_json_nonfinite_unicode_and_size(self):
        for data in (b'{"a":1,"a":2}', b'{"x":{"a":1,"a":2}}',
                     b'{"a":NaN}', b'{"a":Infinity}', b'\xff', b'{bad'):
            with self.assertRaises(P.ContractError):
                P.decode_json(data, 1024)
        with self.assertRaises(P.ContractError):
            P.decode_json(b" " * 1025, 1024)
        with self.assertRaises(P.ContractError):
            P.encode_json({"a": float("inf")})
        self.assertEqual(P.decode_json(P.encode_json({"a": "\u2603"})), {"a": "\u2603"})

    def test_json_record_equality_does_not_alias_boolean_or_float_schema(self):
        self.assertFalse(P.equal_record({"schema": True}, {"schema": 1}))
        self.assertFalse(P.equal_record({"schema": 1.0}, {"schema": 1}))
        self.assertTrue(P.equal_record({"a": 2, "schema": 1}, {"schema": 1, "a": 2}))

    def test_fixed_argv_no_shell_or_extra_selector(self):
        for case, _name in P.CASES:
            value = descriptor()
            value["case"] = case
            argv = P.fixed_argv(value)
            self.assertEqual(argv, [value["executable"], "--exact", P.SELECTORS[case],
                                    "--ignored", "--test-threads=1", "--nocapture"])
        for kind in ("strict-provider", "deadline-contract"):
            self.assertNotIn("--ignored", P.fixed_argv(descriptor(kind)))
        self.assertEqual(P.fixed_argv(descriptor("slow-peer"))[-2:],
                         ["--owned-slow-peer-root", descriptor()["root"]])
        self.assertEqual(P.case_roles("isolation-controls"), P.ROLES)
        self.assertEqual(P.case_roles("slow-peer"), P.SLOW_ROLES)
        self.assertEqual(P.case_roles("python-mocks"), ())

    def test_environment_is_cleared_not_copied(self):
        with mock.patch.dict(os.environ, {"CUSTOMER_SECRET": "secret", "HTTPS_PROXY": "secret"}):
            env = S.clean_environment(Path(descriptor()["root"]))
        self.assertNotIn("CUSTOMER_SECRET", env)
        self.assertNotIn("HTTPS_PROXY", env)
        self.assertNotIn("DATABASE_URL", env)
        self.assertNotIn("secret", repr(env))

    def test_public_event_allowlist_rejects_descriptor_and_secret_fields(self):
        frame = command("ready", ports={role: 12345 + index for index, role in enumerate(P.ROLES)})
        self.assertEqual(P.validate_event(frame), frame)
        for extra in (dict(pg=descriptor()["pg"]), dict(password="secret"),
                      dict(body="customer"), dict(root=descriptor()["root"]), dict(inputs=descriptor()["inputs"])):
            with self.assertRaises(P.ContractError):
                P.validate_event(dict(frame, **extra))
        with self.assertRaises(P.ContractError):
            P.validate_event(dict(frame, ports={}))

    def test_public_pass_requires_actual_product_counts_and_complete_cleanup(self):
        frame = command("case-result", passed=True, status="passed", panic_locations=[],
                        counts=dict(selected=1, passed=1, summary=1, complete=1, shutdown=1),
                        cleanup={key: True for key in P.CLEANUP_FIELDS},
                        control={key: (0 if key == "python_tests_run" else False) for key in P.CONTROL_FIELDS})
        self.assertEqual(P.validate_event(frame), frame)
        for change in (dict(counts=dict(frame["counts"], complete=0)),
                       dict(cleanup=dict(frame["cleanup"], main_reaped=False)),
                       dict(panic_locations=[dict(code="MANAGED_CASE", line=1, column=2)]),
                       dict(status="failed")):
            with self.assertRaises(P.ContractError):
                P.validate_event(dict(frame, **change))


class LifecycleTests(GuardedTest):
    def test_controls_and_start_are_both_required(self):
        value, state = descriptor(), S.Lifecycle(descriptor())
        with self.assertRaises(P.ContractError):
            state.command(command("start"), 101)
        state.command(command("controls"), 101)
        with self.assertRaises(P.ContractError):
            state.command(command("start", seq=2), 102)
        state.controls_done()
        state.command(command("start", seq=2), 103)
        self.assertEqual(state.phase, "running")
        self.assertEqual(state.deadlines.startup, 143)
        self.assertEqual(state.deadlines.owner, 288)

    def test_replay_binding_and_unknown_fields(self):
        for update in (dict(seq=True), dict(seq=2), dict(nonce="f" * 32),
                       dict(case="repair-valid"), dict(schema=True), dict(path="/bin/sh"),
                       dict(kind="exec"), dict(pid=42)):
            frame = command("controls")
            frame.update(update)
            with self.assertRaises(P.ContractError):
                S.Lifecycle(descriptor()).command(frame, 101)
        state = S.Lifecycle(descriptor())
        state.command(command("controls"), 101)
        with self.assertRaises(P.ContractError):
            state.command(command("controls"), 101)

    def test_unsolicited_wrong_hash_duplicate_and_late_ack(self):
        value, state = running()
        ack = command("identity-ack", seq=3, ledger_sha256="a" * 64)
        with self.assertRaises(P.ContractError):
            state.command(ack, 103)
        state.request_identity("b" * 64)
        with self.assertRaises(P.ContractError):
            state.command(ack, 103)
        ack["ledger_sha256"] = "b" * 64
        with self.assertRaises(P.ContractError):
            state.command(ack, 142)
        state.command(ack, 104)
        self.assertEqual(state.acked_hash, "b" * 64)
        with self.assertRaises(P.ContractError):
            state.command(dict(ack, seq=4), 105)

    def test_before_start_control_never_accepts_ack(self):
        value, state = running("control-before-start")
        with self.assertRaises(P.ContractError):
            state.request_identity("a" * 64)
        state.pending_hash = "a" * 64
        with self.assertRaises(P.ContractError):
            state.command(command("identity-ack", seq=3, value=value, ledger_sha256="a" * 64), 103)

    def test_original_case_campaign_and_startup_bounds_never_renew(self):
        value = descriptor()
        value["campaign_end"] = 400
        state = S.Lifecycle(value)
        self.assertEqual(state.deadlines.work, 280)
        self.assertEqual(state.deadlines.cleanup, 340)
        state.command(command("controls", value=value), 101)
        state.controls_done()
        state.command(command("start", seq=2, value=value), 279)
        self.assertEqual(state.deadlines.startup, 280)
        self.assertEqual(state.deadlines.owner, 280)
        with self.assertRaises(P.ContractError):
            state.command(command("stop", seq=3, value=value), 340)
        with self.assertRaises(P.ContractError):
            state.deadlines.launch(279)

    def test_isolation_controls_cannot_start_arbitrary_product(self):
        value = descriptor("isolation-controls")
        state = S.Lifecycle(value)
        state.command(command("controls", value=value), 101)
        state.controls_done()
        with self.assertRaises(P.ContractError):
            state.command(command("start", seq=2, value=value), 102)

    def test_channel_oversize_duplicate_eof_and_no_pipelining(self):
        value = descriptor()
        for payload in (b"a" * P.FRAME_LIMIT, b'{"kind":"x","kind":"y"}\n', b"",
                        P.encode_json(command("controls")) + b"\n" + P.encode_json(command("start", seq=2)) + b"\n"):
            channel = object.__new__(S.Channel)
            channel.pending = bytearray()
            with mock.patch.object(S.select, "select", return_value=([0], [], [])), \
                 mock.patch.object(S.os, "read", return_value=payload):
                with self.assertRaises(P.ContractError):
                    channel.poll()

    def test_channel_fragmentation_and_sequence(self):
        channel = object.__new__(S.Channel)
        channel.pending = bytearray()
        data = P.encode_json(command("controls")) + b"\n"
        with mock.patch.object(S.select, "select", return_value=([0], [], [])), \
             mock.patch.object(S.os, "read", side_effect=[data[:10], data[10:]]):
            self.assertEqual(channel.poll(), [])
            self.assertEqual(channel.poll(), [command("controls")])
        channel.descriptor, channel.lifecycle = descriptor(), S.Lifecycle(descriptor())
        channel.sequence = 1
        writes = []
        with mock.patch.object(S.time, "monotonic", return_value=101), \
             mock.patch.object(S.select, "select", return_value=([], [1], [])), \
             mock.patch.object(S.os, "write", side_effect=lambda _fd, data: writes.append(data) or len(data)):
            channel.send("ready", ports={role: 12345 + index for index, role in enumerate(P.ROLES)})
            channel.send("controls", passed=True, results={key: True for key in P.PROBE_FIELDS})
        self.assertEqual([P.decode_json(data)["seq"] for data in writes], [1, 2])
        self.assertNotIn(b"password", b"".join(writes))
        self.assertNotIn(b"source_root", b"".join(writes))


class IdentityTests(GuardedTest):
    def test_init_caps_are_exactly_credential_switch_and_kill(self):
        status = dict(CapEff="e0", CapPrm="e0", CapInh="0", CapAmb="0", CapBnd="e0")
        S.validate_init_capabilities(status)
        for key in status:
            wrong = dict(status)
            wrong[key] = "ffffffff"
            with self.assertRaises(P.ContractError):
                S.validate_init_capabilities(wrong)

    def test_linux_full_birth_and_namespace_pid_not_one(self):
        self.assertEqual(P.validate_identity(identity()), identity())
        for update in (dict(pid=1), dict(pgid=1), dict(uid=True), dict(alive=1), dict(pid=-1),
                       dict(birth=dict(system="darwin", start_sec=0, start_subsec=2, boot=None))):
            value = identity()
            value.update(update)
            with self.assertRaises(P.ContractError):
                P.validate_identity(value)
        for update in (dict(start_sec=1), dict(start_subsec=0), dict(boot="bad"), dict(extra=1)):
            value = identity()
            value["birth"].update(update)
            with self.assertRaises(P.ContractError):
                P.validate_identity(value)

    def test_capture_matches_public_linux_start_tick_representation(self):
        fields = ["S", "1", "42"] + ["0"] * 16 + ["1234"]
        raw = ("42 (helper name) " + " ".join(fields)).encode()
        with mock.patch.object(P.sys, "platform", "linux"), \
             mock.patch.object(P.os, "open", side_effect=[9, 10, 11]) as opened, \
             mock.patch.object(P.os, "read", side_effect=[raw, b"Pid:\t42\nUid:\t20001\t20001\t20001\t20001\n"]), \
             mock.patch.object(P.os, "close"), \
             mock.patch("builtins.open", mock.mock_open(read_data=identity()["birth"]["boot"] + "\n")):
             self.assertEqual(P.capture_local(42), identity())
             self.assertEqual(opened.call_args_list[1:], [
                 mock.call("stat", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=9),
                 mock.call("status", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=9)])
        with mock.patch.object(P.sys, "platform", "linux"), \
             mock.patch.object(P.os, "open", side_effect=PermissionError(errno.EACCES, "private")):
            with self.assertRaises(PermissionError):
                P.capture_local(42)
        with mock.patch.object(P.sys, "platform", "linux"), \
             mock.patch.object(P.os, "open", side_effect=FileNotFoundError()):
             self.assertIsNone(P.capture_local(42))

    def capture_status(self, status, state="Z"):
        fields = [state, "1", "42"] + ["0"] * 16 + ["1234"]
        raw = ("42 (helper name) " + " ".join(fields)).encode()
        with mock.patch.object(P.sys, "platform", "linux"), \
             mock.patch.object(P.os, "open", side_effect=[9, 10, 11]), \
             mock.patch.object(P.os, "read", side_effect=[raw, status]), \
             mock.patch.object(P.os, "fstat", side_effect=AssertionError("proc ownership is not UID")), \
             mock.patch.object(P.os, "close"), \
             mock.patch("builtins.open", mock.mock_open(read_data=identity()["birth"]["boot"] + "\n")):
            return P.capture_local(42)

    def test_zombie_uses_effective_uid_not_proc_file_ownership(self):
        actual = self.capture_status(b"Pid:\t42\nUid:\t123\t20001\t456\t789\n")
        self.assertEqual(actual, identity(alive=False))
        self.assertTrue(P.same_process(actual, identity()))
        group = S.OwnedGroup(identity(), 20001)
        with mock.patch.object(P, "capture_local", return_value=actual), \
             mock.patch.object(S.os, "killpg", return_value=None):
            self.assertFalse(group.absent())

    def test_changed_effective_uid_still_cannot_authorize_signals(self):
        actual = self.capture_status(b"Pid:\t42\nUid:\t20001\t0\t20001\t20001\n", state="S")
        group = S.OwnedGroup(identity(), 20001)
        with mock.patch.object(P, "capture_local", return_value=actual), \
             mock.patch.object(S.os, "killpg") as kill:
            with self.assertRaises(P.ContractError):
                group.send(signal.SIGKILL)
            kill.assert_not_called()

    def test_status_identity_requires_exact_pid_and_four_bounded_uids(self):
        for status in (b"Pid:\t42\n", b"Pid:\t43\nUid:\t1\t2\t3\t4\n",
                       b"Pid:\t42\nUid:\t1\t2\t3\n", b"Pid:\t42\nUid:\t1\t-2\t3\t4\n",
                       b"Pid:\t42\nUid:\t1\t4294967296\t3\t4\n",
                       b"Pid:\t42\nUid:\t1\t2\t3\t4\nUid:\t1\t2\t3\t4\n",
                       b"Pid:\t42\nPid:\t42\nUid:\t1\t2\t3\t4\n"):
            with self.subTest(status=status), self.assertRaises(P.ContractError):
                self.capture_status(status)

    def test_disappearing_pinned_process_is_absent_but_permission_is_not(self):
        for error in (FileNotFoundError(), PermissionError(errno.EACCES, "private")):
            with mock.patch.object(P.sys, "platform", "linux"), \
                 mock.patch.object(P.os, "open", side_effect=[9, error]), \
                 mock.patch.object(P.os, "close") as closed:
                if isinstance(error, FileNotFoundError):
                    self.assertIsNone(P.capture_local(42))
                else:
                    with self.assertRaises(PermissionError):
                        P.capture_local(42)
                closed.assert_called_once_with(9)

    def test_status_read_is_bounded_and_all_owned_descriptors_close(self):
        fields = ["Z", "1", "42"] + ["0"] * 16 + ["1234"]
        raw = ("42 (helper name) " + " ".join(fields)).encode()
        with mock.patch.object(P.sys, "platform", "linux"), \
             mock.patch.object(P.os, "open", side_effect=[9, 10, 11]), \
             mock.patch.object(P.os, "read", side_effect=[raw, b"x" * 16385]), \
             mock.patch.object(P.os, "close") as closed:
            with self.assertRaises(P.ContractError):
                P.capture_local(42)
            self.assertEqual(closed.call_args_list, [mock.call(10), mock.call(11), mock.call(9)])

    def test_unknown_or_wrong_uid_group_cannot_signal(self):
        with mock.patch.object(S.os, "killpg") as kill:
            for candidate in (identity(uid=0), identity(pgid=999), identity(alive=False)):
                with self.assertRaises(P.ContractError):
                    S.OwnedGroup(candidate, 20001)
            group = S.OwnedGroup(identity(), 20001, authorized=False)
            with self.assertRaises(P.ContractError):
                group.send(signal.SIGKILL)
            kill.assert_not_called()

    def test_birth_mismatch_and_permission_are_not_absence(self):
        group = S.OwnedGroup(identity(), 20001)
        with mock.patch.object(P, "capture_local", return_value=identity(ticks=999)), \
             mock.patch.object(S.os, "killpg") as kill:
            with self.assertRaises(P.ContractError):
                group.send(signal.SIGKILL)
            kill.assert_not_called()
        with mock.patch.object(P, "capture_local", return_value=None), \
             mock.patch.object(S.os, "killpg", side_effect=PermissionError(errno.EPERM, "private")):
            with self.assertRaises(PermissionError):
                group.absent()
        self.assertFalse(group.retired)

    def test_esrch_retires_irreversibly_no_later_pid_lookup_or_signal(self):
        group = S.OwnedGroup(identity(), 20001)
        with mock.patch.object(P, "capture_local", return_value=None) as capture, \
             mock.patch.object(S.os, "killpg", side_effect=ProcessLookupError()) as kill:
            self.assertTrue(group.absent())
            count = capture.call_count
            group.send(signal.SIGTERM)
            group.send(signal.SIGKILL)
            self.assertTrue(group.absent())
            self.assertEqual(capture.call_count, count)
            kill.assert_called_once_with(42, 0)
        self.assertEqual(group.sent, [])

    def test_owned_group_survives_leader_exit_only_while_group_exists(self):
        group = S.OwnedGroup(identity(), 20001)
        with mock.patch.object(P, "capture_local", return_value=None), \
             mock.patch.object(S.os, "killpg") as kill:
            group.send(signal.SIGKILL)
            self.assertEqual(kill.call_args_list, [mock.call(42, 0), mock.call(42, signal.SIGKILL)])
        self.assertEqual(group.sent, [signal.SIGKILL])

    def test_zombie_is_not_absence_before_actual_waitpid_reaping(self):
        group = S.OwnedGroup(identity(), 20001)
        with mock.patch.object(P, "capture_local", return_value=identity(alive=False)), \
             mock.patch.object(S.os, "killpg", return_value=None):
            self.assertFalse(group.absent())
        self.assertFalse(group.retired)
        self.assertFalse(group.reaped)


class PrivateFilesTests(GuardedTest):
    def test_private_atomic_schema_and_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "record.json"
            P.atomic_record(path, {"schema": 1, "value": "closed"})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(P.read_private_json(path, os.geteuid()), {"schema": 1, "value": "closed"})
            with self.assertRaises(P.ContractError):
                P.read_private_json(path, os.geteuid() + 1)
            path.chmod(0o644)
            with self.assertRaises(P.ContractError):
                P.read_private_json(path, os.geteuid())
            path.chmod(0o600)
            link = path.with_name("link.json")
            link.symlink_to(path)
            with self.assertRaises(P.ContractError):
                P.read_private_json(link, os.geteuid())
            with self.assertRaises(P.ContractError):
                P.read_private_json(path, os.geteuid(), 2)

    def test_descriptor_mode_must_be_0400_not_product_0600(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "descriptor.json"
            path.write_bytes(P.encode_json(descriptor()))
            path.chmod(0o400)
            self.assertEqual(P.decode_json(P.read_private_bytes(path, os.geteuid(), 16384, mode=0o400)), descriptor())
            with self.assertRaises(P.ContractError):
                P.read_private_json(path, os.geteuid(), 16384)


class DrainTests(GuardedTest):
    def product_output(self, case="http"):
        return ("running 1 test\n" + "test " + P.SELECTORS[case] + " ... " + P.SHUTDOWN + "\n"
                + "MANAGED_RELEASE_COMPLETE " + case + " assertions-ok\nok\n"
                + "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 14 filtered out; finished in 0.2s\n").encode()

    def test_exact_rows_and_markers_in_chunked_stdout(self):
        output = self.product_output()
        drain = P.ClosedDrain(case="http")
        for offset in range(0, len(output), 7):
            drain.feed(output[offset:offset + 7])
        self.assertTrue(drain.finish())
        self.assertEqual(drain.counts, dict(selected=1, passed=1, summary=1, complete=1, shutdown=1))

    def test_discard_only_stdout_may_end_mid_prefix_after_deliberate_kill(self):
        drain = P.ClosedDrain(discard=True)
        drain.feed(b"running 1 test\ntest deliberately_killed ... ")
        self.assertTrue(drain.finish())
        self.assertEqual(drain.counts, dict(selected=0, passed=0, summary=0, complete=0, shutdown=0))
        for options in (dict(stderr=True), dict(stderr=True, discard=True), dict(case="http")):
            with self.subTest(options=options), self.assertRaises(P.ContractError):
                strict = P.ClosedDrain(**options)
                strict.feed(b"unterminated")
                strict.finish()

    def test_discard_does_not_relax_output_bounds(self):
        for data in (b"x" * 4097, b"x\n" * (P.ClosedDrain.MAX_BYTES // 2 + 1)):
            with self.assertRaises(P.ContractError):
                drain = P.ClosedDrain(discard=True)
                drain.feed(data)
                drain.finish()

    def test_empty_skip_extra_row_wrong_marker_and_truncation_fail(self):
        output = self.product_output()
        invalid = [b"", output.replace(b"0 ignored", b"1 ignored"),
                   output.replace(b"1 passed", b"0 passed"), output.replace(b"1 passed", b"2 passed"),
                   output.replace(b"MANAGED_RELEASE_COMPLETE http", b"MANAGED_RELEASE_COMPLETE repair-valid"),
                   output.replace(P.SHUTDOWN.encode() + b"\n", b""),
                   output + P.SHUTDOWN.encode() + b"\n", output[:-1],
                   output.replace(b"assertions-ok", b"assertions-failed"),
                   b"MANAGED_RELEASE_COMPLETE http assertions-ok\n" + output]
        for data in invalid:
            drain = P.ClosedDrain(case="http")
            drain.feed(data)
            with self.assertRaises(P.ContractError):
                drain.finish()

    def test_bodies_errors_and_credentials_never_enter_closed_output(self):
        drain = P.ClosedDrain(case="http")
        secret = b"https://user:secret@example.test/private?token=secret <Body>customer</Body>"
        drain.feed(secret + b"\n" + self.product_output())
        drain.finish()
        self.assertNotIn("secret", repr(drain.__dict__))
        self.assertNotIn("customer", repr(drain.__dict__))
        stderr = P.ClosedDrain(stderr=True)
        stderr.feed(b"thread panicked at crates/gateway/tests/db_keys_test/managed_release.rs:123:4 secret\n")
        with self.assertRaises(P.ContractError):
            stderr.finish()
        self.assertEqual(stderr.panic_locations, [dict(code="MANAGED_CASE", line=123, column=4)])
        self.assertNotIn("secret", repr(stderr.__dict__))

    def test_overflow_sticky_even_after_valid_suffix(self):
        for data in (b"x" * 4097, b"x\n" * (P.ClosedDrain.MAX_BYTES // 2 + 1)):
            drain = P.ClosedDrain(case="http")
            drain.feed(data)
            drain.feed(self.product_output())
            with self.assertRaises(P.ContractError):
                drain.finish()
            self.assertLessEqual(len(drain.pending), 4096)

    def test_python_exact_five_mocks_and_no_extra_fields(self):
        record = dict(kind="socket-free-mock", tests_run=5, failures=0, errors=0,
                      real_network=False, tls_executed=False, openssl_executed=False)
        for update in ({}, dict(tests_run=0), dict(real_network=True), dict(body="secret"), dict(errors=True)):
            drain = P.JsonDrain()
            drain.feed(P.encode_json(dict(record, **update)) + b"\n")
            if update:
                with self.assertRaises(P.ContractError):
                    drain.finish("python-mocks")
            else:
                self.assertEqual(drain.finish("python-mocks"), record)

    def test_real_slow_peer_requires_all_closed_facts(self):
        record = dict(kind="owned-slow-peer", passed=True, no_receive_after_write_failure=True,
                      received_prefix_ordered=True, fixture_failure_not_gateway_result=True,
                      workers_ended=True, listeners_closed=True, connections_closed=True)
        for key in record:
            drain = P.JsonDrain()
            wrong = dict(record)
            wrong[key] = False
            drain.feed(P.encode_json(wrong) + b"\n")
            with self.assertRaises(P.ContractError):
                drain.finish("slow-peer")
        drain = P.JsonDrain()
        drain.feed(P.encode_json(record) + b"\n")
        self.assertEqual(drain.finish("slow-peer"), record)


class SupervisorTests(GuardedTest):
    def make(self, kind="product"):
        supervisor = S.Supervisor(descriptor(kind), mock.Mock())
        supervisor.main = S.OwnedGroup(identity(), 20001, mock.Mock())
        supervisor.binding = dict(ports_sha256="a" * 64)
        _value, supervisor.lifecycle = running(kind)
        supervisor.deadlines = supervisor.lifecycle.deadlines
        return supervisor

    def ledger(self, supervisor):
        return dict(schema=2, kind="owned-managed-release-tls", case=supervisor.descriptor["case"],
                    nonce=supervisor.descriptor["nonce"], root_uid=20001,
                    ports_sha256=supervisor.binding["ports_sha256"], test_identity=supervisor.main.identity,
                    tls_identity=identity(pid=43, ppid=42))

    def test_pid1_generic_reaper_reconciles_main_race_actual_sigkill(self):
        supervisor = S.Supervisor(descriptor("control-before-start"), mock.Mock())
        child = mock.Mock(pid=42, returncode=None)
        child.poll.side_effect = AssertionError("Popen ECHILD fallback is forbidden")
        supervisor.main = S.OwnedGroup(identity(), 20001, child)
        # Main exits after the held-child WNOHANG and before orphan waitpid(-1).
        with mock.patch.object(S.os, "waitpid", side_effect=[(0, 0), (42, signal.SIGKILL), ChildProcessError()]):
            supervisor.reap()
        self.assertEqual(child.returncode, -signal.SIGKILL)
        self.assertEqual(supervisor.main.exit_code, -signal.SIGKILL)
        self.assertEqual(supervisor.main.wait_status, signal.SIGKILL)
        self.assertEqual(supervisor.main.wait_owned(200, supervisor.reap), -signal.SIGKILL)
        child.poll.assert_not_called()
        child.wait.assert_not_called()

    def test_pid1_lost_status_never_accepts_popens_fabricated_zero(self):
        supervisor = S.Supervisor(descriptor(), mock.Mock())
        child = mock.Mock(pid=42, returncode=0)
        supervisor.main = S.OwnedGroup(identity(), 20001, child)
        with mock.patch.object(S.os, "waitpid", side_effect=ChildProcessError()), \
             mock.patch.object(S.time, "monotonic", return_value=103):
            with self.assertRaises(P.ContractError):
                supervisor.main.wait_owned(200, supervisor.reap)
        self.assertIsNone(supervisor.main.wait_status)
        self.assertFalse(supervisor.main.reaped)

    def test_pid1_reconciles_both_direct_children_and_unknown_orphan_without_signals(self):
        supervisor = S.Supervisor(descriptor(), mock.Mock())
        main, probe = mock.Mock(pid=42, returncode=None), mock.Mock(pid=43, returncode=None)
        supervisor.main = S.OwnedGroup(identity(), 20001, main)
        supervisor.probe_group = S.OwnedGroup(identity(pid=43), 20001, probe)
        waits = [(0, 0), (43, 0), (42, 5 << 8), (99, 0), (0, 0)]
        with mock.patch.object(S.os, "waitpid", side_effect=waits), \
             mock.patch.object(S.os, "killpg") as kill:
            supervisor.reap()
            kill.assert_not_called()
        self.assertEqual(main.returncode, 5)
        self.assertEqual(probe.returncode, 0)
        self.assertEqual(supervisor.main.wait_status, 5 << 8)
        self.assertEqual(supervisor.probe_group.wait_status, 0)
        self.assertTrue(supervisor.main.reaped and supervisor.probe_group.reaped)

    def test_ledger_does_not_ack_until_independent_host_approval(self):
        supervisor = self.make()
        ledger = self.ledger(supervisor)
        raw = P.encode_json(ledger) + b"\n"
        with mock.patch.object(P, "capture_local", side_effect=[identity(), ledger["tls_identity"], identity()]), \
             mock.patch.object(supervisor, "write") as write:
            supervisor.accept_tls_ledger(ledger, raw)
            write.assert_not_called()
        self.assertFalse(supervisor.tls.authorized)
        supervisor.channel.send.assert_called_once_with("identity-request", test_identity=identity(),
            tls_identity=ledger["tls_identity"], ledger_sha256=P.sha(raw))
        with mock.patch.object(supervisor, "write") as write:
            with self.assertRaises(P.ContractError):
                supervisor.identity_ack()
            write.assert_not_called()
        supervisor.lifecycle.command(command("identity-ack", seq=3, ledger_sha256=P.sha(raw)), 103)
        with mock.patch.object(P, "capture_local", side_effect=[identity(), ledger["tls_identity"]]), \
             mock.patch.object(S.time, "monotonic", return_value=104), \
             mock.patch.object(supervisor, "write") as write:
            supervisor.identity_ack()
            write.assert_called_once_with("owned-tls-ack.json", supervisor.stop_binding())
        self.assertTrue(supervisor.tls.authorized)

    def test_stale_ack_rechecks_full_kernel_birth_no_write(self):
        supervisor = self.make()
        supervisor.tls = S.OwnedGroup(identity(pid=43, ppid=42), 20001, authorized=False)
        supervisor.ledger_hash = "d" * 64
        supervisor.lifecycle.acked_hash = "d" * 64
        with mock.patch.object(P, "capture_local", side_effect=[identity(), identity(pid=43, ppid=42, ticks=999)]), \
             mock.patch.object(supervisor, "write") as write:
            with self.assertRaises(P.ContractError):
                supervisor.identity_ack()
            write.assert_not_called()
        self.assertFalse(supervisor.tls.authorized)

    def test_ledger_scope_parent_source_hash_uid_mismatch_never_signals(self):
        for update in (dict(root_uid=0), dict(ports_sha256="e" * 64), dict(case="repair-valid"),
                       dict(nonce="f" * 32), dict(test_identity=identity(ticks=999)),
                       dict(tls_identity=identity(pid=43, ppid=999)),
                       dict(tls_identity=identity(pid=43, ppid=42, uid=0))):
            supervisor = self.make()
            ledger = self.ledger(supervisor)
            ledger.update(update)
            with mock.patch.object(S.os, "killpg") as kill, \
                 mock.patch.object(supervisor, "write") as write:
                with self.assertRaises(P.ContractError):
                    supervisor.accept_tls_ledger(ledger, P.encode_json(ledger))
                kill.assert_not_called()
                write.assert_not_called()
            supervisor.channel.send.assert_not_called()

    def test_before_start_kills_only_captured_main_never_ack_tls(self):
        supervisor = self.make("control-before-start")
        ledger = self.ledger(supervisor)
        supervisor.main.send = mock.Mock()
        with mock.patch.object(P, "capture_local", side_effect=[identity(), ledger["tls_identity"], identity()]), \
             mock.patch.object(supervisor, "write") as write:
            supervisor.accept_tls_ledger(ledger, P.encode_json(ledger))
            write.assert_not_called()
        supervisor.main.send.assert_called_once_with(signal.SIGKILL)
        supervisor.channel.send.assert_not_called()
        self.assertFalse(supervisor.tls.authorized)
        self.assertTrue(supervisor.control_injected)

    def test_probe_requires_every_actual_expected_fact_with_kind_specific_network(self):
        for kind in ("product", "strict-provider", "control-before-start", "python-mocks", "slow-peer"):
            for failed in (False, True):
                supervisor = S.Supervisor(descriptor(kind), mock.Mock())
                supervisor.lifecycle.command(command("controls", value=descriptor(kind)), 101)
                expected = {key: True for key in P.PROBE_FIELDS}
                expected["owned_loopback"] = kind == "product"
                results = dict(expected)
                if failed:
                    results["capabilities"] = False
                child, group = mock.Mock(), mock.Mock()
                child.wait.return_value = 0
                group.stop.return_value = False
                group.wait_owned.return_value = 0

                def pump(_child, out, _err, _end, _observer):
                    out.feed(P.encode_json(dict(kind="isolation-probe", passed=True, results=results)) + b"\n")

                with mock.patch.object(supervisor, "write"), \
                     mock.patch.object(supervisor, "read_bytes", return_value=b"private-contract"), \
                     mock.patch.object(S, "spawn_owned", return_value=(child, group)), \
                     mock.patch.object(supervisor, "pump", side_effect=pump), \
                     mock.patch.object(S.time, "monotonic", return_value=103):
                    if failed:
                        with self.assertRaises(P.ContractError):
                            supervisor.run_controls()
                        supervisor.channel.send.assert_not_called()
                    else:
                        supervisor.run_controls()
                        self.assertEqual(supervisor.lifecycle.phase, "controlled")
                        supervisor.channel.send.assert_called_once_with("controls", passed=True, results=expected)

    def test_declared_reservations_remain_held_until_exact_live_ready(self):
        supervisor = self.make()
        supervisor.descriptor["kind"] = "slow-peer"
        supervisor.binding = dict(schema=1, case="slow-peer", nonce=descriptor()["nonce"],
                                  parent_sha256="b" * 64, ports_sha256="a" * 64)
        reservation = mock.Mock()
        supervisor.reservations = {"slow-peer": reservation}
        with mock.patch.object(S.time, "monotonic", return_value=103), \
             mock.patch.object(supervisor, "read", return_value=supervisor.binding), \
             mock.patch.object(P, "capture_local", return_value=identity()), \
             mock.patch.object(supervisor, "write") as write:
            supervisor.observe()
        reservation.close.assert_called_once()
        write.assert_called_once_with("owned-port-handoff.json", supervisor.binding)
        self.assertTrue(supervisor.ports_released)
        self.assertEqual(supervisor.reservations, {})

    def test_descendant_control_requires_real_listener_and_surviving_full_identity(self):
        supervisor = self.make("control-descendant")
        supervisor.tls = S.OwnedGroup(identity(pid=43, ppid=42), 20001)
        supervisor.tls.absent = mock.Mock(return_value=False)
        supervisor.control_exit_gate = True
        supervisor.ports = dict(tls=12345)
        supervisor.descendant = identity(pid=44, ppid=43, pgid=43)
        supervisor.ledger_hash = "f" * 64
        record = dict(schema=1, case="control-descendant", nonce=descriptor()["nonce"],
                      ports_sha256="a" * 64, identity=supervisor.descendant)
        replies = {"owned-control-descendant.json": record, "owned-listeners.json": {"tls": {}},
                   "owned-control-leader-exited.json": supervisor.stop_binding()}
        survivor = identity(pid=44, ppid=1, pgid=43)
        supervisor.main.send = mock.Mock()
        with mock.patch.object(supervisor, "read", side_effect=lambda name, **_kw: replies[name]), \
             mock.patch.object(P, "capture_local", side_effect=[survivor, None]), \
             mock.patch.object(S.socket, "create_connection") as connect:
            supervisor.observe_descendant()
        connect.assert_called_once_with(("127.0.0.1", 12345), timeout=.15)
        supervisor.main.send.assert_called_once_with(signal.SIGKILL)
        self.assertTrue(supervisor.control["descendant_live_after_leader_exit"])

    def test_missing_descendant_or_refused_listener_does_not_prove_positive_control(self):
        supervisor = self.make("control-descendant")
        supervisor.tls = S.OwnedGroup(identity(pid=43, ppid=42), 20001)
        supervisor.tls.absent = mock.Mock(return_value=False)
        supervisor.control_exit_gate = True
        supervisor.ports = dict(tls=12345)
        supervisor.descendant = identity(pid=44, ppid=43, pgid=43)
        supervisor.ledger_hash = "f" * 64
        record = dict(schema=1, case="control-descendant", nonce=descriptor()["nonce"],
                      ports_sha256="a" * 64, identity=supervisor.descendant)
        replies = {"owned-control-descendant.json": record, "owned-listeners.json": {"tls": {}},
                   "owned-control-leader-exited.json": supervisor.stop_binding()}
        supervisor.main.send = mock.Mock()
        with mock.patch.object(supervisor, "read", side_effect=lambda name, **_kw: replies[name]), \
             mock.patch.object(P, "capture_local", side_effect=[None, None]), \
             mock.patch.object(S.socket, "create_connection") as connect:
            with self.assertRaises(P.ContractError):
                supervisor.observe_descendant()
            connect.assert_not_called()
        supervisor.main.send.assert_not_called()

    def test_prestart_eof_checks_no_tls_state_and_never_signals_tls(self):
        supervisor = self.make("control-before-start")
        supervisor.tls = S.OwnedGroup(identity(pid=43, ppid=42), 20001, authorized=False)
        supervisor.tls.absent = mock.Mock(return_value=True)
        with mock.patch.object(supervisor, "reap"), \
             mock.patch.object(P, "capture_local", return_value=None), \
             mock.patch.object(S.time, "monotonic", return_value=103), \
             mock.patch.object(supervisor, "private", side_effect=lambda: nullcontext()), \
             mock.patch.object(S.Path, "lstat", side_effect=FileNotFoundError()), \
             mock.patch.object(S.os, "killpg") as kill:
            supervisor.wait_unacked_tls()
        self.assertTrue(supervisor.control["before_start_eof"])
        self.assertTrue(supervisor.tls.reaped)
        kill.assert_not_called()
        with mock.patch.object(supervisor, "reap"), \
             mock.patch.object(P, "capture_local", return_value=None), \
             mock.patch.object(S.time, "monotonic", return_value=103), \
             mock.patch.object(supervisor, "private", side_effect=lambda: nullcontext()), \
             mock.patch.object(S.Path, "lstat", side_effect=PermissionError()):
            with self.assertRaises(PermissionError):
                supervisor.wait_unacked_tls()

    def test_failed_spawn_capture_never_group_signals(self):
        child = mock.Mock(pid=42)
        child.poll.return_value = None
        with mock.patch.object(S.subprocess, "Popen", return_value=child) as popen, \
             mock.patch.object(P, "capture_local", return_value=identity(ppid=999)), \
             mock.patch.object(S.os, "getpid", return_value=1), \
             mock.patch.object(S.os, "killpg") as kill, \
             mock.patch.object(S.time, "monotonic", return_value=101):
            with self.assertRaises(P.ContractError):
                S.spawn_owned(descriptor(), ["/fixed/exe"], {}, 120)
            child.kill.assert_called_once()
            child.wait.assert_called_once()
            kill.assert_not_called()
            self.assertTrue(popen.call_args.kwargs["close_fds"])
            self.assertEqual(popen.call_args.kwargs["pass_fds"], ())
            self.assertEqual(popen.call_args.kwargs["stdin"], S.subprocess.DEVNULL)
            self.assertNotIn("shell", popen.call_args.kwargs)

    def test_partial_reservation_failure_closes_only_captured_sockets(self):
        supervisor = S.Supervisor(descriptor(), mock.Mock())
        first, second = mock.Mock(), mock.Mock()
        first.getsockname.return_value = ("127.0.0.1", 12345)
        second.bind.side_effect = OSError("private failure body")
        with mock.patch.object(S.socket, "socket", side_effect=[first, second]):
            with self.assertRaises(OSError):
                supervisor.reserve()
        first.close.assert_called_once()
        second.close.assert_called_once()
        self.assertEqual(supervisor.reservations, {})

    def test_no_port_release_until_exact_private_ready_binding(self):
        supervisor = self.make()
        supervisor.ports_released = False
        supervisor.binding = dict(schema=1, case="http", nonce=descriptor()["nonce"],
                                  parent_sha256="b" * 64, ports_sha256="a" * 64)
        reservation = mock.Mock()
        supervisor.reservations = {"provider": reservation}
        with mock.patch.object(S.time, "monotonic", return_value=103), \
             mock.patch.object(supervisor, "read", return_value=dict(supervisor.binding, nonce="f" * 32)), \
             mock.patch.object(supervisor, "write") as write:
            with self.assertRaises(P.ContractError):
                supervisor.observe()
            reservation.close.assert_not_called()
            write.assert_not_called()

    def test_cleanup_permission_failure_is_false_not_success(self):
        supervisor = self.make()
        supervisor.main = mock.Mock()
        supervisor.main.stop.side_effect = PermissionError(errno.EPERM, "secret")
        supervisor.main.absent.side_effect = PermissionError(errno.EPERM, "secret")
        with mock.patch.object(supervisor, "reap"), mock.patch.object(supervisor, "listeners_closed", return_value=True), \
             mock.patch.object(S.time, "monotonic", return_value=103):
            facts, complete = supervisor.cleanup()
        self.assertFalse(complete)
        self.assertFalse(facts["main_group_absent"])
        self.assertNotIn("secret", P.encode_json(facts).decode())

    def test_failed_runtime_never_passes_even_if_cleanup_is_complete(self):
        supervisor = S.Supervisor(descriptor(), mock.Mock())
        cleanup = {key: True for key in ("main_group_absent", "main_reaped", "tls_group_absent",
                                        "tls_reaped", "listeners_closed", "reservations_closed", "within_deadline")}
        with mock.patch.object(supervisor, "initialize", side_effect=RuntimeError("secret password body")), \
             mock.patch.object(supervisor, "cleanup", return_value=(cleanup, True)), \
             mock.patch.object(supervisor, "wait_stop") as stop:
            self.assertEqual(supervisor.run(), 1)
        frame = supervisor.channel.send.call_args
        self.assertFalse(frame.kwargs["passed"])
        self.assertEqual(frame.kwargs["status"], "failed")
        self.assertNotIn("secret", repr(frame))
        self.assertIsNone(supervisor.descriptor["pg"]["password"])
        stop.assert_called_once()

    def test_source_pin_mismatch_fails_before_any_reservation(self):
        supervisor = S.Supervisor(descriptor(), mock.Mock())
        with mock.patch.object(S.sys, "platform", "linux"), \
             mock.patch.object(S.os, "getpid", return_value=1), \
             mock.patch.object(S.os, "geteuid", return_value=0), \
             mock.patch.object(S, "check_init_capabilities"), \
             mock.patch.object(S.time, "monotonic", return_value=101), \
             mock.patch.object(supervisor, "private", side_effect=lambda: nullcontext()), \
             mock.patch.object(S.Path, "resolve", lambda path, **_kw: path), \
             mock.patch.object(S, "file_hash", return_value="f" * 64), \
             mock.patch.object(supervisor, "reserve") as reserve:
            with self.assertRaises(P.ContractError):
                supervisor.initialize()
            reserve.assert_not_called()

    def test_stop_wait_keeps_init_alive_for_independent_host_inspection(self):
        supervisor = S.Supervisor(descriptor(), mock.Mock())
        supervisor.lifecycle.phase = "result"
        supervisor.channel.poll.side_effect = [[], [command("stop")]]
        with mock.patch.object(S.time, "monotonic", return_value=101), \
             mock.patch.object(S.time, "sleep") as sleep, mock.patch.object(supervisor, "reap"):
            supervisor.wait_stop()
        sleep.assert_called_once_with(.01)
        self.assertEqual(supervisor.lifecycle.phase, "stopped")


class ProbeTests(GuardedTest):
    def test_high_fd_leak_is_rejected_not_just_descriptors_below_1024(self):
        metadata = [types.SimpleNamespace(st_mode=stat.S_IFCHR),
                    types.SimpleNamespace(st_mode=stat.S_IFIFO),
                    types.SimpleNamespace(st_mode=stat.S_IFIFO)]
        with mock.patch.object(Q.os, "fstat", side_effect=metadata), \
             mock.patch.object(Q.os, "listdir", return_value=["0", "1", "2", "2048"]), \
             mock.patch.object(Q.fcntl, "fcntl", return_value=0):
            with self.assertRaises(P.ContractError):
                Q.check_fds()

    def test_closed_listdir_fd_is_not_misclassified_as_leak(self):
        metadata = [types.SimpleNamespace(st_mode=stat.S_IFCHR),
                    types.SimpleNamespace(st_mode=stat.S_IFIFO),
                    types.SimpleNamespace(st_mode=stat.S_IFIFO)]
        with mock.patch.object(Q.os, "fstat", side_effect=metadata), \
             mock.patch.object(Q.os, "listdir", return_value=["0", "1", "2", "3"]), \
             mock.patch.object(Q.fcntl, "fcntl", side_effect=OSError(errno.EBADF, "private")):
            Q.check_fds()

    def test_refused_unreachable_missing_timeout_are_not_denial(self):
        for code in (errno.ECONNREFUSED, errno.ENOENT, errno.ENETUNREACH, errno.ETIMEDOUT, errno.EBADF):
            with self.assertRaises(P.ContractError):
                Q.denied(mock.Mock(side_effect=OSError(code, "secret")))
        self.assertTrue(Q.denied(mock.Mock(side_effect=PermissionError(errno.EPERM, "private"))))
        with self.assertRaises(P.ContractError):
            Q.denied(lambda: None)

    def test_import_does_not_load_ffi_and_main_errors_are_closed(self):
        output = types.SimpleNamespace(buffer=io.BytesIO())
        with mock.patch.object(Q.sys, "stdout", output), \
             mock.patch.object(P, "read_private_bytes", side_effect=RuntimeError("secret body")):
            self.assertEqual(Q.main(["--contract", "/fixed/private", "--sha256", "a" * 64]), 1)
        self.assertEqual(P.decode_json(output.buffer.getvalue()), dict(kind="isolation-probe", passed=False))


if __name__ == "__main__":
    unittest.main()
