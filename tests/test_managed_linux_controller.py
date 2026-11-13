# SPDX-License-Identifier: Apache-2.0
"""Offline host-warden contracts. Never launches Docker/processes/sockets/FFI."""
import contextlib
import copy
import ctypes
import dataclasses
import errno
import fcntl
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import re
import resource
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import MagicMock, Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from managed_release_linux import controller as C
from managed_release_linux import protocol as P
from managed_release_linux import coordinator as K

NONCE = "a" * 32
CAMPAIGN = "b" * 32
SOURCE = "c" * 40
IMAGE = "sha256:" + "d" * 64
IDENTITY = "e" * 64
BOOT = "11111111-1111-4111-8111-111111111111"


class Offline(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for name in ("subprocess.run", "subprocess.Popen", "socket.socket", "socket.create_connection",
                     "ctypes.CDLL", "os.system", "os.fork", "os.posix_spawn", "os.kill", "os.killpg",
                     "os.chown", "os.setuid", "os.setgid", "os.setgroups", "fcntl.flock", "fcntl.lockf",
                     "resource.setrlimit"):
            self.stack.enter_context(patch(name, side_effect=AssertionError("external action forbidden")))
        if hasattr(os, "pidfd_open"):
            self.stack.enter_context(patch("os.pidfd_open", side_effect=AssertionError("pidfd forbidden")))

    def refused(self, function, *args):
        with self.assertRaises(C.Refused):
            function(*args)


class FrameTests(Offline):
    def test_decoder_rejects_duplicates_oversize_nonfinite_and_malformed(self):
        for wire in (b"", b"{", b'{}{}', b'{"a":1,"a":2}', b'{"a":NaN}', b'"\xff"',
                     b" " * (C.FRAME_BYTES + 1), b"[" * 1500 + b"]" * 1500):
            with self.subTest(length=len(wire)):
                self.refused(C.decode, wire)

    def test_exact_schema_and_canonical_roundtrip(self):
        frame = dict(schema=1, kind="run-case", campaign=CAMPAIGN, source_sha=SOURCE, seq=1, case="http")
        self.assertEqual(C.decode(C.encode(frame)), frame)
        C.coordinator_request(frame, CAMPAIGN, SOURCE, 1, "http")
        for key, value in (("schema", True), ("seq", True), ("seq", 2), ("campaign", NONCE),
                           ("case", "arbitrary"), ("kind", "shell"), ("source_sha", "d" * 40)):
            bad = dict(frame, **{key: value})
            self.refused(C.coordinator_request, bad, CAMPAIGN, SOURCE, 1, "http")
        self.refused(C.coordinator_request, dict(frame, argv=["sh"]), CAMPAIGN, SOURCE, 1, "http")

    def test_every_coordinator_batch_is_fixed_and_bounded(self):
        batches = C.fixed_batches()
        self.assertTrue(all(len(x) <= 4 for x in batches))
        flat = [x for batch in batches for x in batch]
        self.assertEqual(flat, list(C.CONTROLS + C.CASES))
        self.assertEqual(len(set(flat)), 20)
        self.assertEqual(C.CASES, tuple(x for x, _ in P.CASES))

    def test_no_execution_is_default(self):
        for flags in ([], ["--warden"], ["--prepare"]):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(C.main(flags), 2)
            self.assertIn("not executed", output.getvalue())

    def test_nonroot_coordinator_rejects_root_without_io(self):
        with patch.object(K.os, "geteuid", return_value=0), contextlib.redirect_stdout(io.StringIO()):
            # Fixed identity-phase code; the closed startup frame requires a
            # buffered stdout and is covered by the dedicated startup tests.
            self.assertEqual(K.main(["--plan", K.PLAN]), 12)


def planner_plan():
    return dict(schema=1, campaign=CAMPAIGN, source_sha=SOURCE, campaign_end=3700,
                cases=list(K.CONTROLS + K.CASES))


class CoordinatorTests(Offline):
    def test_plan_has_only_source_nonce_deadline_and_fixed_case_names(self):
        plan = planner_plan()
        self.assertEqual(K.validate_plan(plan, 100), plan)
        for key, value in (("password", "PRIVATE"), ("argv", ["sh"]), ("path", "/root"),
                           ("resource_id", IDENTITY), ("env", {"HOME": "/root"})):
            with self.assertRaises(K.Refused):
                K.validate_plan(dict(plan, **{key: value}), 100)

    def test_expired_nonfinite_reordered_and_extended_plans_fail(self):
        for change in (dict(campaign_end=100), dict(campaign_end=3701), dict(campaign_end=math.inf),
                       dict(schema=True), dict(cases=list(reversed(planner_plan()["cases"]))),
                       dict(campaign="wrong"), dict(source_sha="tag")):
            with self.assertRaises(K.Refused):
                K.validate_plan(dict(planner_plan(), **change), 100)

    def test_planner_emits_all_twenty_fixed_requests_and_never_commands(self):
        plan, statuses = planner_plan(), []
        for seq, case in enumerate(K.CONTROLS + K.CASES, 1):
            statuses.append(C.encode(dict(schema=1, kind="case-status", campaign=CAMPAIGN,
                                          source_sha=SOURCE, case=case, seq=seq, passed=True)))
        outgoing = io.BytesIO()
        self.assertEqual(K.run(plan, io.BytesIO(b"".join(statuses)), outgoing, clock=lambda: 100), 0)
        frames = [C.decode(x) for x in outgoing.getvalue().splitlines()]
        self.assertEqual([x["case"] for x in frames], list(K.CONTROLS + K.CASES))
        self.assertEqual([x["seq"] for x in frames], list(range(1, 21)))
        for frame in frames:
            self.assertEqual(set(frame), {"schema", "kind", "campaign", "source_sha", "case", "seq"})
            self.assertEqual(frame["kind"], "run-case")
        self.assertEqual(C.fixed_batches(), K.batches())

    def test_false_replayed_cross_campaign_extra_and_truncated_status_fail(self):
        good = dict(schema=1, kind="case-status", campaign=CAMPAIGN, source_sha=SOURCE,
                    case=K.CONTROLS[0], seq=1, passed=True)
        for bad in (dict(good, passed=False), dict(good, seq=2), dict(good, seq=True),
                    dict(good, campaign=NONCE), dict(good, stdout="PRIVATE")):
            with self.assertRaises(K.Refused):
                K.run(planner_plan(), io.BytesIO(C.encode(bad)), io.BytesIO(), clock=lambda: 100)
        with self.assertRaises(K.Refused):
            K.run(planner_plan(), io.BytesIO(C.encode(good).rstrip()), io.BytesIO(), clock=lambda: 100)

    def test_planner_never_renews_deadline_after_reply(self):
        good = dict(schema=1, kind="case-status", campaign=CAMPAIGN, source_sha=SOURCE,
                    case=K.CONTROLS[0], seq=1, passed=True)
        times = iter((100, 100, 100, 3580))
        with self.assertRaises(K.Refused):
            K.run(planner_plan(), io.BytesIO(C.encode(good)), io.BytesIO(), clock=lambda: next(times))

    def test_plan_reader_requires_root_owned_readonly_single_link_regular_file(self):
        metadata = NS(st_mode=0o100444, st_uid=0, st_nlink=1, st_size=2, st_ino=3, st_mtime_ns=4, st_ctime_ns=5)
        with patch.object(K.os, "open", return_value=77), patch.object(K.os, "close"), \
             patch.object(K.os, "read", return_value=b"{}"), patch.object(K.os, "fstat", return_value=metadata):
            self.assertEqual(K.read_plan(), {})
        for field, value in (("st_mode", 0o100644), ("st_uid", 20001), ("st_nlink", 2), ("st_size", 8193)):
            bad = copy.copy(metadata)
            setattr(bad, field, value)
            with patch.object(K.os, "open", return_value=77), patch.object(K.os, "close"), \
                 patch.object(K.os, "fstat", return_value=bad), self.assertRaises(K.Refused):
                K.read_plan()

    def test_native_coordinator_network_controls_require_actual_policy_errno(self):
        with patch.object(K.socket, "socket", side_effect=OSError(errno.EPERM, "closed")) as create:
            K.network_denials()
        self.assertEqual(create.call_count, 5)
        for number in (errno.EAFNOSUPPORT, errno.EACCES, errno.ENETUNREACH, errno.ECONNREFUSED):
            with patch.object(K.socket, "socket", side_effect=OSError(number, "PRIVATE")), self.assertRaises(K.Refused):
                K.network_denials()
        connection = NS(close=Mock())
        with patch.object(K.socket, "socket", return_value=connection), self.assertRaises(K.Refused):
            K.network_denials()
        connection.close.assert_called_once()


class DeadlineTests(Offline):
    def test_native_deadline_is_fixed_precision_and_never_extends_original(self):
        from decimal import Decimal
        for end in (100, 100.0000000001, 3700.0000000001, 3700.123456789123,
                    999999999999.9999, 0.000000001, 123456.78912345678):
            with self.subTest(end=end):
                text = C.native_deadline(end)
                self.assertRegex(text, r"^[0-9]{1,12}\.[0-9]{9}$")
                self.assertLessEqual(Decimal(text), Decimal(end))
                self.assertLess(Decimal(end) - Decimal(text), Decimal("0.000000001"))
        self.assertEqual(C.native_deadline(3700.0000000001), "3700.000000000")

    def test_native_deadline_rejects_nonfinite_negative_or_unbounded_values(self):
        for end in (True, "100", float("nan"), float("inf"), -1, 0, 10**12, 10**1000):
            self.refused(C.native_deadline, end)

    def test_single_case_origin_and_cleanup_reserve(self):
        budget = C.Budget(100, 240, 20)
        self.assertEqual(budget.end, 340)
        self.assertEqual(budget.remaining(319), 1)
        self.refused(budget.remaining, 320)
        self.assertEqual(budget.remaining(339, True), 1)
        self.refused(budget.remaining, 340, True)

    def test_campaign_has_original_cleanup_reserve(self):
        budget = C.Budget(100, 3600, 120)
        self.assertEqual(budget.remaining(3579), 1)
        self.refused(budget.remaining, 3580)
        self.assertEqual(budget.remaining(3699, True), 1)
        self.refused(budget.remaining, 3700, True)

    def test_nonfinite_backward_and_invalid_reserves_refused(self):
        for origin, duration, reserve, now in ((1, 240, 20, 0), (1, 20, 20, 1),
                (1, 240, -1, 1), (1, 240, 20, math.nan), (1, math.inf, 20, 1), (True, 240, 20, 1)):
            self.refused(C.Budget(origin, duration, reserve).remaining, now)

    def test_warden_takes_minimum_not_renewed_end(self):
        warden = C.Warden.__new__(C.Warden)
        warden.budget, warden.host = C.Budget(1, 3600, 120), NS(clock=lambda: 20)
        case = NS(budget=C.Budget(10, 240, 20))
        self.assertEqual(warden.end(case), 230)
        self.assertEqual(warden.end(case, True), 250)
        warden.host.clock = lambda: 230
        self.refused(warden.end, case)


class InputTests(Offline):
    def test_source_allowlist_excludes_credentials_and_unknown_spools(self):
        for name in (".git/config", ".jj/repo", ".env", "Cargo/credentials", "home/key", "spool/output",
                     "crates/.env", "crates/gateway/spool/private.log", "plugins/unknown.wasm",
                     "scripts/managed_release_linux/secret.json", "migrations/scratch.txt",
                     "crates/../Cargo.toml", "/Cargo.lock", "crates//gateway/src/lib.rs"):
            with self.subTest(name=name):
                self.assertFalse(C.source_allowed(name))
        for name in ("Cargo.lock", "crates/gateway/src/lib.rs", "migrations/001.sql", C.FIXTURES[0],
                     "scripts/managed_release_linux/protocol.py"):
            self.assertTrue(C.source_allowed(name), name)

    def test_native_elf_rejects_cross_arch_and_nonelf(self):
        header = bytearray(64)
        header[:6], header[18:20] = b"\x7fELF\x02\x01", (62).to_bytes(2, "little")
        C.native_elf(bytes(header))
        for offset, byte in ((4, 1), (5, 2), (18, 183)):
            bad = bytearray(header)
            bad[offset] = byte
            self.refused(C.native_elf, bytes(bad))
        self.refused(C.native_elf, b"MZ")

    def test_proxy_secret_home_and_db_environment_are_not_inherited(self):
        with patch.dict(os.environ, {"HTTPS_PROXY": "PRIVATE", "DATABASE_URL": "PRIVATE", "HOME": "PRIVATE",
                                     "GH_TOKEN": "PRIVATE", "DOCKER_HOST": "PRIVATE"}):
            self.assertEqual(C.clean_env(), dict(PATH="/usr/bin:/bin", LANG="C", LC_ALL="C"))

    def test_input_digest_and_private_file_check_without_processes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "input"
            path.write_bytes(b"public-source")
            path.chmod(0o600)
            self.assertEqual(C.private_read(path, path.stat().st_uid), b"public-source")
            self.assertEqual(C.digest(path), C.hashlib.sha256(b"public-source").hexdigest())
            self.refused(C.private_read, path, path.stat().st_uid + 1)
            path.chmod(0o644)
            self.refused(C.private_read, path, path.stat().st_uid)

    def test_mutated_input_rejected(self):
        before = NS(st_mode=0o100600, st_nlink=1, st_dev=1, st_ino=2, st_size=3, st_mtime_ns=4, st_ctime_ns=5)
        after = copy.copy(before)
        after.st_ctime_ns += 1
        with patch.object(C.os, "open", return_value=77), patch.object(C.os, "close"), \
             patch.object(C.os, "read", side_effect=[b"abc", b""]), \
             patch.object(C.os, "fstat", side_effect=[before, after]):
            self.refused(C.digest, Path("/fake/input"))


class FakeSelector:
    def __init__(self):
        self.registered = False

    def register(self, *_args):
        self.registered = True

    def unregister(self, *_args):
        self.registered = False

    def get_map(self):
        return {987: True} if self.registered else {}

    def select(self, _timeout):
        return [(None, None)] if self.registered else []

    def close(self):
        self.registered = False


class FakeProcess:
    def __init__(self, exit_code=0):
        self.stdin = io.BytesIO()
        self.stdout = NS(fileno=lambda: 987, close=Mock())
        self.returncode, self.exit_code = None, exit_code
        self.kills = 0

    def poll(self):
        return self.returncode

    def wait(self, timeout):
        self.returncode = self.exit_code if self.returncode is None else self.returncode
        return self.returncode

    def kill(self):
        self.kills += 1
        self.returncode = -9


class ProcessAdapterTests(Offline):
    def test_bounded_adapter_captures_no_stderr_and_accepts_only_exit_zero(self):
        for code in (0, 1):
            host, process = C.Host(clock=lambda: 100), FakeProcess(code)
            with patch.object(host, "spawn", return_value=process), \
                 patch.object(C.selectors, "DefaultSelector", FakeSelector), \
                 patch.object(C.os, "read", side_effect=[b"closed", b""]):
                if code == 0:
                    self.assertEqual(host.run(["fixed"], 110), b"closed")
                else:
                    self.refused(host.run, ["fixed"], 110)
            self.assertEqual(process.kills, 0)
            process.stdout.close.assert_called_once()

    def test_overflow_kills_only_captured_adapter_child_and_reaps_it(self):
        host, process = C.Host(clock=lambda: 100), FakeProcess()
        with patch.object(host, "spawn", return_value=process), \
             patch.object(C.selectors, "DefaultSelector", FakeSelector), \
             patch.object(C.os, "read", return_value=b"PRIVATE" * 1024):
            with self.assertRaisesRegex(C.Refused, "command-output-bound"):
                host.run(["fixed"], 110, limit=32)
        self.assertEqual(process.kills, 1)
        self.assertEqual(process.returncode, -9)

    def test_expired_command_does_not_spawn(self):
        host = C.Host(clock=lambda: 100)
        with patch.object(host, "spawn") as spawn:
            self.refused(host.run, ["fixed"], 100)
        spawn.assert_not_called()

    def test_runtime_command_cap_does_not_replace_shorter_original_deadline(self):
        for original_end, expected in ((1000, 10), (103, 3)):
            host, process = C.Host(clock=lambda: 100), FakeProcess()
            host.command_limit = 10
            process.wait = Mock(wraps=process.wait)
            with patch.object(host, "spawn", return_value=process), \
                 patch.object(C.selectors, "DefaultSelector", FakeSelector), patch.object(C.os, "read", return_value=b""):
                host.run(["fixed"], original_end)
            self.assertEqual(process.wait.call_args.kwargs["timeout"], expected)

    def test_queued_frame_does_not_bypass_expired_channel_deadline(self):
        with patch.object(C.selectors, "DefaultSelector", FakeSelector):
            channel = C.Channel(FakeProcess(), clock=lambda: 100)
            channel.buffer = bytearray(b'{"schema":1}\n')
            self.refused(channel.read, 100)

    def test_channel_fragmentation_eof_and_oversize_are_bounded(self):
        with patch.object(C.selectors, "DefaultSelector", FakeSelector), \
             patch.object(C.os, "read", side_effect=[b'{"schema":', b'1}\n']):
            channel = C.Channel(FakeProcess(), clock=lambda: 100)
            self.assertEqual(channel.read(110), dict(schema=1))
        for data in (b"", b"x" * (C.FRAME_BYTES + 1)):
            with patch.object(C.selectors, "DefaultSelector", FakeSelector), patch.object(C.os, "read", return_value=data):
                channel = C.Channel(FakeProcess(), clock=lambda: 100)
                self.refused(channel.read, 110)


def owned(kind="container"):
    return C.Owned(kind, IDENTITY if kind == "container" else "managed-data", "managed-case" if kind == "container" else "managed-data",
                   NONCE, "2026-11-12T00:00:00Z", IMAGE if kind == "container" else None)


def inspected(obj):
    labels = {C.LABEL: CAMPAIGN, C.LABEL + ".nonce": NONCE}
    if obj.kind == "container":
        return dict(Id=obj.identity, Name="/" + obj.name, Image=obj.image, Created=obj.created,
                    Config=dict(Labels=labels))
    return dict(Name=obj.name, Driver="local", Scope="local", Created=obj.created, Labels=labels)


class DockerTests(Offline):
    def test_owned_resource_requires_id_name_nonce_image_and_birth(self):
        obj = owned()
        value = inspected(obj)
        obj.verify(value, CAMPAIGN)
        for key, bad in (("Id", "f" * 64), ("Name", "/other"), ("Image", "sha256:" + "f" * 64),
                         ("Created", "2026-11-13T00:00:00Z")):
            self.refused(obj.verify, dict(value, **{key: bad}), CAMPAIGN)
        bad = copy.deepcopy(value)
        bad["Config"]["Labels"][C.LABEL + ".nonce"] = CAMPAIGN
        self.refused(obj.verify, bad, CAMPAIGN)
        self.refused(obj.verify, value, NONCE)

    def test_volume_scope_and_driver_must_be_local(self):
        obj = owned("volume")
        value = inspected(obj)
        obj.verify(value, CAMPAIGN)
        self.refused(obj.verify, dict(value, Driver="nfs"), CAMPAIGN)
        self.refused(obj.verify, dict(value, Scope="global"), CAMPAIGN)

    def test_postgres_args_are_private_nondefault_pinned_and_bounded(self):
        args = C.pg_create("owned-pg", [], "owned-volume", IMAGE, NONCE, "1" * 32)
        before = args[:args.index(IMAGE)]
        self.assertIn("--network=none", before)
        self.assertIn("--pull=never", before)
        self.assertIn("--platform=linux/amd64", before)
        self.assertIn("--user=999:999", before)
        self.assertIn("--read-only", before)
        self.assertIn("--cap-drop=ALL", before)
        self.assertIn("--security-opt=no-new-privileges:true", before)
        self.assertFalse(any(x.startswith(("--publish", "--network=host", "--privileged")) for x in before))
        self.assertNotIn("-p", before)
        self.assertEqual(args[args.index("-p") + 1], str(C.chosen_port(NONCE)))
        self.assertIn("POSTGRES_DB=managed_release_" + NONCE, args)
        self.assertFalse(any("PROXY" in x for x in args))
        self.refused(C.pg_create, "pg", [], "volume", "postgres:latest", NONCE, "1" * 32)

    def test_pg_volume_options_have_only_reviewed_bounded_tmpfs_fields(self):
        self.assertEqual(C.pg_options(), {"type": "tmpfs", "device": "tmpfs",
            "o": "size=5368709120,uid=999,gid=999,mode=0700,nosuid,nodev,noexec"})

    def test_port_selection_stays_unprivileged_and_avoids_default(self):
        for nonce in ("0" * 32, "f" * 32, NONCE):
            self.assertTrue(1024 <= C.chosen_port(nonce) <= 65535)
            self.assertNotIn(C.chosen_port(nonce), (5432, 54322))
        self.refused(C.chosen_port, "../unsafe")

    def test_inventory_requires_successful_enumeration_not_stderr_guess(self):
        host = C.Host()
        with patch.object(host, "docker", return_value=(IDENTITY + "\n").encode()):
            self.assertEqual(host.inventory("container", 20), {IDENTITY})
        with patch.object(host, "docker", side_effect=C.Refused("transport")):
            self.refused(host.inventory, "container", 20)
        for output in (b"No such container\n", (IDENTITY + "\n" + IDENTITY + "\n").encode()):
            with patch.object(host, "docker", return_value=output):
                self.refused(host.inventory, "container", 20)
        with patch.object(host, "docker", return_value=b""):
            self.assertEqual(host.inventory("container", 20), set())

    def test_inspection_must_be_single_structured_object(self):
        host = C.Host()
        for output in (b"[]", b"{}", b"[{},{}]", b'["not-object"]'):
            with patch.object(host, "docker", return_value=output):
                self.refused(host.inspect, "container", IDENTITY, 20)

    def test_adapter_spawn_clears_environment_and_discards_stderr(self):
        host = C.Host()
        with patch("subprocess.Popen", return_value=NS()) as spawn:
            host.spawn(["/usr/bin/docker", "info"], pass_fds=(17,))
        _args, kwargs = spawn.call_args
        self.assertEqual(kwargs["env"], C.clean_env())
        self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
        self.assertIs(kwargs["close_fds"], True)
        self.assertEqual(kwargs["pass_fds"], (17,))

    def test_init_policy_never_uses_unconfined_and_denies_escape(self):
        policy = C.init_policy()
        denied = policy["syscalls"][0]["names"]
        for name in ("mount", "setns", "unshare", "bpf", "ptrace", "io_uring_setup"):
            self.assertIn(name, denied)
        self.assertEqual(policy["architectures"], ["SCMP_ARCH_X86_64"])

    def test_no_shared_writable_shm_for_case_or_coordinator(self):
        self.assertIn("--ipc=none", C.resource_limits())
        self.assertIn("--ipc=private", C.resource_limits(ipc="private"))

    def test_resource_guard_or_proxy_mutation_refused(self):
        obj = owned()
        value = inspected(obj)
        value["Config"]["Env"] = ["PATH=/usr/bin:/bin", "LANG=C"]
        value["HostConfig"] = dict(ReadonlyRootfs=True, Privileged=False, PortBindings={}, PublishAllPorts=False,
                                   PidMode="", IpcMode="none", CgroupnsMode="private", PidsLimit=128,
                                   Memory=768 * 1024 * 1024, MemorySwap=768 * 1024 * 1024, NanoCpus=500000000)
        warden = C.Warden.__new__(C.Warden)
        warden.campaign, warden.end = CAMPAIGN, lambda *_args: 100
        warden.host = NS(inspect=lambda *_args: value)
        warden.verify(obj)
        for key, bad in (("ReadonlyRootfs", False), ("Privileged", True), ("PortBindings", {"1234/tcp": []}),
                         ("PidMode", "host"), ("IpcMode", "host"), ("CgroupnsMode", "host"),
                         ("Memory", 0), ("PidsLimit", 0), ("NanoCpus", 0), ("MemorySwap", -1)):
            old = value["HostConfig"][key]
            value["HostConfig"][key] = bad
            self.refused(warden.verify, obj)
            value["HostConfig"][key] = old
        value["Config"]["Env"].append("https_proxy=PRIVATE")
        self.refused(warden.verify, obj)


def host_proc(pid, local_pid, parent, local_parent, ticks=100, uid=C.PRODUCT_UID):
    return C.Proc(pid, parent, pid, uid, ticks, BOOT, (pid, local_pid), (pid, local_pid), 123, True)


def local_identity(host, parent):
    return dict(pid=host.nspid[-1], ppid=parent.nspid[-1], pgid=host.nspgid[-1], uid=host.uid, alive=True,
                birth=dict(system="linux", start_sec=0, start_subsec=host.ticks, boot=host.boot))


class IdentityTests(Offline):
    def setUp(self):
        super().setUp()
        self.init = host_proc(1000, 1, 1, 0, uid=0)
        self.test = host_proc(1001, 2, 1000, 1)
        self.tls = host_proc(1002, 3, 1001, 2)

    def test_full_host_mapping_requires_namespace_birth_uid_parent_and_group(self):
        local = local_identity(self.test, self.init)
        C.local_matches(local, self.test, self.init, self.init)
        for field, value in (("ticks", 101), ("uid", 0), ("pidns", 124), ("parent", 999), ("alive", False),
                             ("nspgid", (1001, 9)), ("boot", "22222222-2222-4222-8222-222222222222")):
            self.refused(C.local_matches, local, dataclasses.replace(self.test, **{field: value}), self.init, self.init)
        self.refused(C.local_matches, dict(local, pid=1), self.test, self.init, self.init)
        self.refused(C.local_matches, dict(local, pid=True), self.test, self.init, self.init)

    def test_identity_pair_maps_only_acknowledged_cgroup_members(self):
        binding = C.Binding.__new__(C.Binding)
        binding.pid, binding.init = self.init.host, self.init
        mapping = {x.host: x for x in (self.init, self.test, self.tls)}
        binding.proc = mapping.__getitem__
        binding.members = lambda: list(mapping)
        pair = binding.verify_pair(local_identity(self.test, self.init), local_identity(self.tls, self.test))
        self.assertEqual(pair, (self.test, self.tls))
        binding.members = lambda: [self.init.host, self.test.host]
        self.refused(binding.verify_pair, local_identity(self.test, self.init), local_identity(self.tls, self.test))

    def test_identity_mapping_rechecks_birth_after_matching(self):
        binding = C.Binding.__new__(C.Binding)
        binding.pid, binding.init = self.init.host, self.init
        binding.members = lambda: [1000, 1001, 1002]
        binding.proc = Mock(side_effect=[self.init, self.init, self.test, self.tls,
                                        dataclasses.replace(self.test, ticks=999)])
        self.refused(binding.verify_pair, local_identity(self.test, self.init), local_identity(self.tls, self.test))

    def test_proc_parser_checks_host_namespace_chain_and_boot(self):
        fields = ["S", "1000", "1001"] + ["0"] * 16 + ["100"]
        text = "1001 (untrusted process name) " + " ".join(fields)
        status = "Uid:\t20001\t20001\t20001\t20001\nNSpid:\t1001\t2\nNSpgid:\t1001\t2\n"
        result = C.proc_record(1001, text, status, BOOT, 123, 20001)
        self.assertEqual(result.nspid, (1001, 2))
        self.assertEqual(result.ticks, 100)
        for bad in (status.replace("1001\t2", "1001", 1), status + "NSpid:\t1001\t2\n",
                    status.replace("20001", "0", 1)):
            self.refused(C.proc_record, 1001, text, bad, BOOT, 123, 20001)

    def test_permission_error_cannot_be_absence(self):
        binding = C.Binding.__new__(C.Binding)
        binding.cgroup = 77
        with patch.object(C.os, "open", side_effect=PermissionError("PRIVATE")):
            with self.assertRaises(PermissionError):
                binding.members()
        binding.proc = Mock(side_effect=PermissionError("PRIVATE"))
        binding.members = lambda: [1000]
        binding.pid, binding.init = 1000, self.init
        with self.assertRaises(PermissionError):
            binding.only_init()


class KernelPolicyTests(Offline):
    def setUp(self):
        super().setUp()
        self.binding = NS(device=7, inode=9)
        self.ready = dict(schema=1, kind="kernel-policy", ready=True, program_ids=[1, 2, 3, 4],
                          cgroup_device=7, cgroup_inode=9, allowed_ports=[12345, 23456])

    def test_ready_requires_four_distinct_readback_programs_and_exact_cgroup(self):
        C.policy_ready(self.ready, self.binding, [23456, 12345])
        for key, value in (("ready", False), ("program_ids", [1, 2, 3]), ("program_ids", [1, 1, 2, 3]),
                           ("cgroup_inode", 10), ("cgroup_device", 8), ("allowed_ports", [12345]), ("schema", True)):
            self.refused(C.policy_ready, dict(self.ready, **{key: value}), self.binding, [12345, 23456])

    def test_empty_port_set_deny_all_is_valid(self):
        C.policy_ready(dict(self.ready, allowed_ports=[]), self.binding, [])

    def test_ready_roles_are_exact_for_each_kind(self):
        for case in C.CASES + C.CONTROLS:
            kind = "product" if case in C.CASES else case
            roles = P.case_roles(kind)
            frame = dict(schema=1, kind="ready", case=case, nonce=NONCE, seq=1,
                         ports={role: 12000 + i for i, role in enumerate(roles)})
            self.assertEqual(len(C.check_ready(frame, case, NONCE)), len(roles))
            self.refused(C.check_ready, dict(frame, nonce=CAMPAIGN), case, NONCE)
            self.refused(C.check_ready, dict(frame, seq=2), case, NONCE)

    def test_default_duplicate_privileged_and_ipv6_port_roles_rejected(self):
        frame = dict(schema=1, kind="ready", case="http", nonce=NONCE, seq=1,
                     ports=dict(zip(P.ROLES, range(12000, 12005))))
        for bad in (0, 1023, 5432, 54322, 65536, True, "12000", 12001):
            bad_frame = copy.deepcopy(frame)
            bad_frame["ports"][P.ROLES[0]] = bad
            self.refused(C.check_ready, bad_frame, "http", NONCE)


def result(case="http"):
    return dict(schema=1, kind="case-result", case=case, nonce=NONCE, seq=3, passed=True, status="passed",
                counts=dict(selected=1, passed=1, summary=1, complete=1, shutdown=1), panic_locations=[],
                cleanup={x: True for x in ("main_group_absent", "main_reaped", "tls_group_absent", "tls_reaped",
                                           "listeners_closed", "reservations_closed", "within_deadline")},
                control=dict(before_start_eof=False, descendant_live_after_leader_exit=False, descendant_sigkill=False,
                             strict_provider=False, deadline_contract=False, python_mocks=False, slow_peer=False,
                             isolation_controls=False, python_tests_run=0))


class AcceptanceTests(Offline):
    def test_each_product_needs_exactly_one_pass_and_both_closed_markers(self):
        for case in C.CASES:
            frame = result(case)
            self.assertEqual(C.closed_result(frame, case, NONCE), dict(case=case, passed=True, cleanup=True))
            for key in frame["counts"]:
                for value in (0, 2, True):
                    bad = copy.deepcopy(frame)
                    bad["counts"][key] = value
                    self.refused(C.closed_result, bad, case, NONCE)

    def test_each_cleanup_fact_is_required(self):
        for key in result()["cleanup"]:
            bad = result()
            bad["cleanup"][key] = False
            self.refused(C.closed_result, bad, "http", NONCE)

    def test_unknown_fields_raw_output_and_panic_are_not_exportable(self):
        frame = result()
        self.refused(C.closed_result, dict(frame, stdout="PRIVATE_PAYLOAD"), "http", NONCE)
        self.refused(C.closed_result, dict(frame, panic_locations=[{"code": "DB_OWNER", "line": 1}]), "http", NONCE)
        self.refused(C.closed_result, dict(frame, passed=False), "http", NONCE)

    def test_owned_negative_controls_require_real_negative_facts(self):
        for case, fields in (("control-before-start", ("before_start_eof",)),
                              ("control-descendant", ("descendant_live_after_leader_exit", "descendant_sigkill"))):
            frame = result(case)
            frame["counts"] = dict(selected=0, passed=0, summary=0, complete=0, shutdown=0)
            self.refused(C.closed_result, frame, case, NONCE)
            for field in fields:
                frame["control"][field] = True
            C.closed_result(frame, case, NONCE)

    def test_pure_controls_require_individual_evidence_and_five_mocks(self):
        for case, field in (("strict-provider", "strict_provider"), ("deadline-contract", "deadline_contract"),
                             ("python-mocks", "python_mocks"), ("slow-peer", "slow_peer"),
                             ("isolation-controls", "isolation_controls")):
            frame = result(case)
            frame["counts"] = dict(selected=1, passed=1, summary=1, complete=0, shutdown=0) if case in (
                "strict-provider", "deadline-contract") else dict(selected=0, passed=0, summary=0, complete=0, shutdown=0)
            self.refused(C.closed_result, frame, case, NONCE)
            frame["control"][field] = True
            if case == "python-mocks":
                self.refused(C.closed_result, frame, case, NONCE)
                frame["control"]["python_tests_run"] = 5
            C.closed_result(frame, case, NONCE)


class CleanupTests(Offline):
    def warden(self):
        warden = C.Warden.__new__(C.Warden)
        warden.campaign, warden.host = CAMPAIGN, NS(clock=lambda: 100)
        warden.budget = C.Budget(1, 3600, 120)
        warden.verify = Mock(return_value=dict(State=dict(Running=False)))
        warden.host.docker, warden.host.inventory = Mock(), Mock(return_value=set())
        return warden

    def test_removal_needs_successful_absence_enumeration(self):
        warden, obj = self.warden(), owned()
        warden.remove(obj)
        warden.host.docker.assert_called_once_with(["container", "rm", obj.identity], 3601)
        warden.host.inventory = Mock(return_value={IDENTITY})
        self.refused(warden.remove, obj)
        warden.host.inventory = Mock(side_effect=C.Refused("transport-failed"))
        self.refused(warden.remove, obj)

    def test_resource_mismatch_never_attempts_delete(self):
        warden = self.warden()
        warden.verify.side_effect = C.Refused("resource-birth-changed")
        self.refused(warden.remove, owned())
        warden.host.docker.assert_not_called()

    def test_running_owned_container_is_killed_by_captured_id_only(self):
        warden = self.warden()
        warden.verify.side_effect = [dict(State=dict(Running=True)), dict(State=dict(Running=False))]
        warden.remove(owned())
        self.assertEqual(warden.host.docker.call_args_list[0].args[0], ["kill", "--signal=KILL", IDENTITY])

    def test_failure_cleanup_attempts_other_resources_and_never_reports_success(self):
        warden = self.warden()
        obj, volume = owned(), owned("volume")
        case = C.CaseResources("http", NONCE, C.Budget(1, 240, 20), Path("/fake/root"), (1, 2), owned=[volume, obj])
        warden.remove = Mock(side_effect=C.Refused("delete-failed"))
        warden.measure = Mock(side_effect=C.Refused("scan-failed"))
        warden.remove_root = Mock()
        self.refused(warden.cleanup_case, case, False)
        self.assertFalse(case.cleaned)
        self.assertEqual(warden.remove.call_count, 2)
        warden.remove_root.assert_not_called()  # No file/mount cleanup before owned-resource proof.

    def test_root_replacement_cannot_authorize_deletion(self):
        warden = self.warden()
        with tempfile.TemporaryDirectory() as temp:
            warden.runtime = Path(temp)
            root = Path(temp) / "managed-release-case-11111111-1111-4111-8111-111111111111"
            root.mkdir()
            case = C.CaseResources("http", NONCE, C.Budget(1, 240, 20), root, (1, 2))
            self.refused(warden.remove_root, case)
            self.assertTrue(root.is_dir())

    def test_missing_nosuid_is_not_misrepresented_as_isolation(self):
        warden = self.warden()
        warden.root, warden.receipt, warden.resources = Path("/source"), {"executable": "/source/target/test"}, []
        case = NS(root=Path("/case"), binding=NS(pid=1001))
        data = "\n".join(f"{i} 1 1:1 / {path} ro,relatime - ext4 disk rw"
                         for i, path in enumerate(("/source", "/source/target/test", "/case", "/run/maskura"), 2))
        with patch.object(C.Path, "read_text", return_value=data):
            self.refused(warden.inspect_kernel_mounts, case)

    def test_coordinator_cleanup_continues_after_cgroup_inspection_failure(self):
        warden = self.warden()
        warden.coordinator_owned, warden.coordinator_removed = owned(), False
        warden.coordinator_binding = NS(prove_empty_after_stop=Mock(side_effect=PermissionError("PRIVATE")), close=Mock())
        warden.coordinator_channel = NS(close=Mock(), process=NS(wait=Mock(return_value=0)))
        warden.remove = Mock()
        self.refused(warden.cleanup_coordinator)
        warden.coordinator_binding.close.assert_called_once()
        warden.remove.assert_called_once()
        warden.coordinator_channel.close.assert_called_once()

    def test_volume_scan_limits_capacity_and_never_reads_payload_files(self):
        root_meta = NS(st_mode=0o40700, st_uid=999, st_dev=7)
        metadata = NS(st_mode=0o100600, st_uid=999, st_dev=7, st_ino=9, st_blocks=8)
        capacity = NS(f_blocks=C.PG_BYTES // 4096, f_frsize=4096)
        with patch.object(C.Path, "stat", return_value=root_meta), patch.object(C.os, "statvfs", return_value=capacity), \
             patch.object(C.Path, "lstat", return_value=metadata), patch.object(C.os, "walk", return_value=[("/pgdata", [], ["opaque"])]), \
             patch.object(C.Path, "open", side_effect=AssertionError("payload read forbidden")), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(C.volume_scan(), 0)
        value = C.decode(output.getvalue().encode())
        self.assertEqual(value["bytes"], 4096)
        self.assertEqual(value["entries"], 1)
        self.assertNotIn("opaque", output.getvalue())

    def test_volume_scan_rejects_oversized_capacity_and_symlink(self):
        root_meta = NS(st_mode=0o40700, st_uid=999, st_dev=7)
        with patch.object(C.Path, "stat", return_value=root_meta), \
             patch.object(C.os, "statvfs", return_value=NS(f_blocks=C.PG_BYTES, f_frsize=4096)):
            self.refused(C.volume_scan)
        with patch.object(C.Path, "stat", return_value=root_meta), \
             patch.object(C.os, "statvfs", return_value=NS(f_blocks=1024, f_frsize=4096)), \
             patch.object(C.os, "walk", return_value=[("/pgdata", [], ["link"])]), \
             patch.object(C.Path, "lstat", return_value=NS(st_mode=0o120777, st_uid=999, st_dev=7)):
            self.refused(C.volume_scan)


class HostMountTests(Offline):
    def manager(self):
        manager = C.HostMounts.__new__(C.HostMounts)
        manager.host, manager.end = NS(run=Mock(), clock=lambda: 10), lambda: 100
        manager.namespace, manager.namespace_fd, manager.receipts = (1, 2), 77, []
        manager.same_namespace = Mock()
        manager.identity = Mock(return_value=(7, 8))
        manager.table = Mock()
        return manager

    def entries(self, flags="ro,nosuid,nodev", identity=2):
        root = C.MountEntry(1, 0, "8:1", "/", Path("/"), frozenset({"rw"}))
        mount = C.MountEntry(identity, 1, "8:1", "/owned/source", Path("/owned/source"), frozenset(flags.split(",")))
        return root, mount

    def test_mountinfo_is_bounded_and_decodes_only_kernel_path_escapes(self):
        value = C.mount_entries("1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 8:1 /owned/a\\040b /owned/a\\040b ro,nosuid,nodev - ext4 /dev/root rw\n")
        self.assertEqual(value[1].target, Path("/owned/a b"))
        self.assertEqual(value[1].flags, frozenset(("ro", "nosuid", "nodev")))
        for wire in ("", "bad", "1 0 8:1 / / rw - ext4 disk rw\n1 0 8:1 / / rw - ext4 disk rw\n",
                     "1 0 8:1 /bad\\777 / rw - ext4 disk rw\n"):
            self.refused(C.mount_entries, wire)

    def test_non_path_roots_are_safe_only_for_unrelated_mounts(self):
        entries = C.mount_entries("1 0 8:1 / / rw - ext4 disk rw\n"
                                  "2 1 0:4 net:[123] /unrelated rw - nsfs nsfs rw\n")
        self.assertEqual(entries[1].root, "net:[123]")
        manager = self.manager()
        manager.table.return_value = entries
        self.refused(manager.bind, Path("/unrelated/child"), "case", False)
        manager.host.run.assert_not_called()
        self.refused(C.mount_entries, "1 0 8:1 / relative rw - ext4 disk rw\n")
        self.refused(C.mount_entries, "1 0 8:1 / /a/../b rw - ext4 disk rw\n")
    def test_executor_requires_exact_caps_in_either_docker_spelling(self):
        value = dict(Mounts=[], HostConfig=dict(ReadonlyRootfs=True, Privileged=False,
                     PidMode="", CgroupnsMode="private", CapDrop=["ALL"], PortBindings={}))
        for caps in (["SETUID", "SETGID", "KILL"], ["CAP_SETUID", "CAP_SETGID", "CAP_KILL"]):
            value["HostConfig"]["CapAdd"] = caps
            C.Warden.inspect_mounts(None, None, value, [])
        for caps in ([], ["SETUID", "SETGID"], ["CAP_SETUID", "CAP_SETGID", "CAP_KILL", "CAP_SYS_ADMIN"],
                     ["CAP_SETUID", "SETGID", "KILL"], ["CAP_CAP_SETUID", "CAP_SETGID", "CAP_KILL"]):
            value["HostConfig"]["CapAdd"] = caps
            self.refused(C.Warden.inspect_mounts, None, None, value, [])

    def binding(self, members):
        binding = C.Binding.__new__(C.Binding)
        binding.pidfd, binding.cgroup, binding.device, binding.inode = 51, 52, 7, 8
        binding.members = Mock(side_effect=members if isinstance(members, Exception) else None,
                               return_value=members)
        return binding

    def prove(self, binding, exited=True, deleted=True, inode=8):
        poll = MagicMock()
        poll.__enter__.return_value.select.return_value = [True] if exited else []
        with patch.object(C.selectors, "DefaultSelector", return_value=poll), \
             patch.object(C.os, "fstat", return_value=NS(st_dev=7, st_ino=inode)), \
             patch.object(C.os, "readlink", return_value="/held/cgroup" + (" (deleted)" if deleted else "")):
            binding.prove_empty_after_stop("coordinator-cgroup-not-empty")

    def test_live_empty_cgroup_and_exited_pidfd_are_proof(self):
        self.prove(self.binding([]))

    def test_deleted_pinned_cgroup_and_exited_pidfd_are_proof(self):
        self.prove(self.binding(FileNotFoundError(2, "PRIVATE")))

    def test_missing_cgroup_alone_is_never_proof(self):
        for options in (dict(exited=False), dict(deleted=False), dict(inode=9)):
            with self.subTest(options=options):
                with self.assertRaises(C.Refused):
                    self.prove(self.binding(FileNotFoundError(2, "PRIVATE")), **options)

    def test_populated_cgroup_and_permission_errors_remain_failures(self):
        self.refused(self.prove, self.binding([1234]))
        with self.assertRaises(PermissionError):
            self.prove(self.binding(PermissionError(13, "PRIVATE")))

    def detach_setup(self):
        warden = C.Warden.__new__(C.Warden)
        case = NS(binding=NS(only_init=Mock()), guard=NS(process=NS(stdin=io.BytesIO()),
                  read=Mock(return_value=dict(schema=1, kind="kernel-policy", stopped=True, detached=True))),
                  guard_detached=False)
        warden.end = Mock(return_value=100)
        warden.listener_absence = Mock()
        warden.wait_owned = Mock()
        return warden, case

    def test_policy_detach_requires_quiescence_ack_and_reaped_guard(self):
        warden, case = self.detach_setup()
        warden.detach_policy(case)
        case.binding.only_init.assert_called_once()
        warden.listener_absence.assert_called_once_with(case)
        self.assertEqual(case.guard.process.stdin.getvalue(), b"STOP\n")
        warden.wait_owned.assert_called_once_with(case.guard.process, case, expected=0)
        self.assertTrue(case.guard_detached)

    def test_policy_stays_attached_when_descendants_or_listeners_remain(self):
        for fail in ("descendants", "listeners"):
            warden, case = self.detach_setup()
            operation = case.binding.only_init if fail == "descendants" else warden.listener_absence
            operation.side_effect = C.Refused("not-quiescent")
            self.refused(warden.detach_policy, case)
            self.assertFalse(case.guard_detached)
            self.assertEqual(case.guard.process.stdin.getvalue(), b"")

    def test_missing_ack_or_nonzero_guard_exit_cannot_prove_detachment(self):
        for fail in ("ack", "exit"):
            warden, case = self.detach_setup()
            if fail == "ack":
                case.guard.read.return_value = dict(schema=1, kind="kernel-policy", stopped=True, detached=False)
            else:
                warden.wait_owned.side_effect = C.Refused("owned-process-exit-unproved")
            self.refused(warden.detach_policy, case)
            self.assertFalse(case.guard_detached)

    def test_successful_case_detaches_before_sending_init_stop(self):
        from scripts.managed_release_linux import protocol
        warden = C.Warden.__new__(C.Warden)
        case = NS(nonce=NONCE)
        warden.new_case = Mock(return_value=case)
        warden.executor = Mock()
        events = []
        warden.command = lambda _case, kind: events.append(kind)
        warden.detach_policy = lambda _case: events.append("detach")
        controls = dict(schema=1, kind="controls", case="isolation-controls", nonce=NONCE, seq=2,
                        passed=True, results={key: True for key in protocol.PROBE_FIELDS})
        warden.response = Mock(side_effect=[controls, {}])
        warden.cleanup_case = lambda _case, passed: events.append(("cleanup", passed))
        with patch.object(C, "closed_result", return_value={"case": "isolation-controls"}):
            warden.run_case("isolation-controls")
        self.assertEqual(events, ["controls", "detach", "stop", ("cleanup", True)])

    def test_self_bind_and_remount_are_exact_and_kernel_read_back(self):
        manager = self.manager()
        root, mount = self.entries()
        manager.table.side_effect = [[root], [root, dataclasses.replace(mount, flags=frozenset({"rw"}))], [root, mount]]
        receipt = manager.bind(Path("/owned/source"), "source", True, deadline=90)
        self.assertEqual(receipt.mount_id, 2)
        self.assertEqual(receipt.namespace, (1, 2))
        self.assertEqual(receipt.inode, (7, 8))
        self.assertEqual(receipt.flags, mount.flags)
        self.assertEqual(manager.host.run.call_args_list[0].args,
                         (["/usr/bin/mount", "--bind", "--", "/owned/source", "/owned/source"], 90))
        self.assertEqual(manager.host.run.call_args_list[1].args,
                         (["/usr/bin/mount", "-o", "remount,bind,nosuid,nodev,ro", "--", "/owned/source"], 90))

    def test_pending_mount_registered_before_even_failed_bind_command(self):
        manager = self.manager()
        root, mount = self.entries("rw")
        manager.table.return_value = [root]
        def fail(*_args):
            self.assertEqual(len(manager.receipts), 1)
            self.assertIsNone(manager.receipts[0].mount_id)
            raise C.Refused("transport-failed-after-creation")
        manager.host.run.side_effect = fail
        self.refused(manager.bind, Path("/owned/source"), "source", True)
        manager.host.run.side_effect = None
        manager.table.side_effect = [[root, mount], [root]]
        manager.remove(manager.receipts[0])
        self.assertTrue(manager.receipts[0].removed)
        self.assertEqual(manager.host.run.call_args.args[0], ["/usr/bin/umount", "--", "/owned/source"])

    def test_failed_remount_keeps_captured_creation_for_cleanup(self):
        manager = self.manager()
        root, mount = self.entries("rw")
        manager.table.side_effect = [[root], [root, mount]]
        manager.host.run.side_effect = [None, C.Refused("remount-failed")]
        self.refused(manager.bind, Path("/owned/source"), "config", True)
        receipt = manager.receipts[0]
        self.assertEqual(receipt.mount_id, 2)
        manager.host.run.side_effect = None
        manager.table.side_effect = [[root, mount], [root]]
        manager.remove(receipt)
        self.assertTrue(receipt.removed)

    def test_rw_case_root_has_only_reviewed_flags(self):
        manager = self.manager()
        root, mount = self.entries("rw,nosuid,nodev")
        manager.table.side_effect = [[root], [root, mount], [root, mount]]
        receipt = manager.bind(Path("/owned/source"), "case", False)
        self.assertFalse(receipt.readonly)
        self.assertIn("remount,bind,nosuid,nodev,rw", manager.host.run.call_args.args[0])

    def test_preexisting_stacked_and_descendant_mounts_refused_before_command(self):
        for mode in ("existing", "stacked", "descendant"):
            manager = self.manager()
            root, mount = self.entries()
            values = [root, mount]
            if mode == "stacked":
                values.append(dataclasses.replace(mount, identity=3))
            if mode == "descendant":
                values = [root, dataclasses.replace(mount, target=Path("/owned/source/child"))]
            manager.table.return_value = values
            self.refused(manager.bind, Path("/owned/source"), "source", True)
            manager.host.run.assert_not_called()
            self.assertEqual(manager.receipts, [])

    def test_wrong_flags_never_qualify_even_when_bind_succeeded(self):
        for flags in ("ro", "ro,nosuid", "rw,nosuid,nodev", "ro,rw,nosuid,nodev"):
            manager = self.manager()
            root, mount = self.entries(flags)
            manager.table.side_effect = [[root], [root, mount], [root, mount]]
            self.refused(manager.bind, Path("/owned/source"), "executable", True)
            self.assertEqual(len(manager.receipts), 1)

    def test_unmount_refuses_replacement_inode_namespace_and_permission_errors(self):
        for mutation in ("id", "inode", "namespace", "permission"):
            manager = self.manager()
            root, mount = self.entries()
            receipt = C.OwnedMount(Path("/owned/source"), "source", True, (1, 2), (7, 8), "8:1", "/owned/source", frozenset({1}), 2)
            manager.table.return_value = [root, mount]
            if mutation == "id":
                manager.table.return_value = [root, dataclasses.replace(mount, identity=3)]
            elif mutation == "inode":
                manager.identity.return_value = (7, 9)
            elif mutation == "namespace":
                manager.same_namespace.side_effect = C.Refused("namespace-changed")
            else:
                manager.table.side_effect = PermissionError("PRIVATE")
            with self.assertRaises((C.Refused, PermissionError)):
                manager.remove(receipt)
            manager.host.run.assert_not_called()
            self.assertFalse(receipt.removed)

    def test_successful_umount_command_without_absence_proof_is_not_cleanup(self):
        manager = self.manager()
        root, mount = self.entries()
        receipt = C.OwnedMount(Path("/owned/source"), "source", True, (1, 2), (7, 8), "8:1", "/owned/source", frozenset({1}), 2)
        manager.table.return_value = [root, mount]
        self.refused(manager.remove, receipt)
        self.assertFalse(receipt.removed)


class FakeDaemon:
    def __init__(self, mode="ok", inspect_failures=0):
        self.names, self.values, self.calls = {}, {}, []
        self.mode, self.inspect_failures, self.ledger = mode, inspect_failures, None

    def named_inventory(self, kind, end):
        return dict(self.names)

    def inventory(self, kind, end):
        return set(self.names.values())

    def inspect(self, kind, identity, end):
        if self.inspect_failures:
            self.inspect_failures -= 1
            raise C.Refused("inspect-transport")
        return copy.deepcopy(self.values[identity])

    def docker(self, args, end, limit=1024 * 1024):
        self.calls.append(args)
        if args[0] == "create":
            self.assert_pending_registered()
            obj = owned()
            self.names[obj.name] = obj.identity
            self.values[obj.identity] = inspected(obj)
            if self.mode == "transport":
                raise C.Refused("create-transport")
            return b"" if self.mode == "lost-receipt" else (obj.identity + "\n").encode()
        if args[:2] == ["container", "rm"]:
            identity = args[2]
            self.names = {name: value for name, value in self.names.items() if value != identity}
            return (identity + "\n").encode()
        raise AssertionError("unexpected daemon action")

    def assert_pending_registered(self):
        if not self.ledger or len(self.ledger.pending) != 1:
            raise AssertionError("mutation preceded pending reservation")


class PendingCreationTests(Offline):
    def ledger(self, mode="ok", inspect_failures=0):
        daemon = FakeDaemon(mode, inspect_failures)
        wall = C.datetime.fromisoformat(owned().created.replace("Z", "+00:00")).timestamp()
        ledger = C.CreationLedger(daemon, CAMPAIGN, wall=lambda: wall)
        daemon.ledger = ledger
        return ledger, daemon

    def test_lost_receipt_and_client_failure_reconcile_exact_owned_resource(self):
        for mode in ("lost-receipt", "transport"):
            ledger, daemon = self.ledger(mode)
            pending = ledger.reserve("container", owned().name, NONCE, IMAGE, 100)
            self.refused(ledger.create, pending, ["create", IMAGE], 100, lambda: 110)
            self.assertEqual(pending.owned, owned())
            self.assertEqual(pending.owned.identity, IDENTITY)
            self.assertEqual(len(ledger.pending), 1)

    def test_daemon_creation_then_inspect_failure_is_retained_and_reconciled(self):
        ledger, daemon = self.ledger(inspect_failures=1)
        pending = ledger.reserve("container", owned().name, NONCE, IMAGE, 100)
        self.refused(ledger.create, pending, ["create", IMAGE], 100, lambda: 110)
        self.assertEqual(pending.returned_identity, IDENTITY)
        self.assertEqual(pending.owned, owned())
        self.assertIn(IDENTITY, daemon.inventory("container", 110))

    def test_core_create_failure_publishes_ack_before_case_cleanup(self):
        ledger, daemon = self.ledger("transport")
        warden = C.Warden.__new__(C.Warden)
        warden.creations, warden.host, warden.cancelled = ledger, daemon, False
        warden.end = lambda *_args: 100
        case = C.CaseResources("http", NONCE, C.Budget(1, 240, 20), Path("/owned/root"), (1, 2))
        self.refused(warden.create, ["create", IMAGE], owned().name, NONCE, case)
        self.assertEqual(case.owned, [owned()])
        self.assertEqual(len(case.pending), 1)
        warden.verify = Mock(return_value={"State": {"Running": False}})
        warden.remove(owned(), case)
        self.assertTrue(case.pending[0].removed)
        self.assertEqual(daemon.calls[-1], ["container", "rm", IDENTITY])

    def test_wrong_labels_image_birth_or_replacement_never_authorizes_deletion(self):
        for mutation in ("labels", "image", "birth", "replacement"):
            ledger, daemon = self.ledger()
            pending = ledger.reserve("container", owned().name, NONCE, IMAGE, 100)
            daemon.names[owned().name] = IDENTITY
            daemon.values[IDENTITY] = inspected(owned())
            if mutation == "labels":
                daemon.values[IDENTITY]["Config"]["Labels"][C.LABEL] = NONCE
            elif mutation == "image":
                daemon.values[IDENTITY]["Image"] = "sha256:" + "f" * 64
            elif mutation == "birth":
                daemon.values[IDENTITY]["Created"] = "2026-11-11T00:00:00Z"
            else:
                pending.returned_identity = "f" * 64
            self.refused(ledger.reconcile, pending, 110)
            self.assertIsNone(pending.owned)
            self.assertEqual(daemon.calls, [])

    def test_successful_exact_name_inventory_absence_is_not_stderr_guess(self):
        ledger, daemon = self.ledger()
        pending = ledger.reserve("container", owned().name, NONCE, IMAGE, 100)
        self.assertIsNone(ledger.reconcile(pending, 100))
        self.assertTrue(pending.absent)
        daemon.named_inventory = Mock(side_effect=PermissionError("PRIVATE"))
        with self.assertRaises(PermissionError):
            ledger.reconcile(pending, 100)

    def test_coordinator_pending_without_returned_assignment_is_cleaned(self):
        ledger, daemon = self.ledger("lost-receipt")
        pending = ledger.reserve("container", owned().name, NONCE, IMAGE, 100)
        self.refused(ledger.create, pending, ["create", IMAGE], 100, lambda: 110)
        warden = C.Warden.__new__(C.Warden)
        warden.creations, warden.host = ledger, daemon
        warden.end = lambda *_args, **_kwargs: 110
        warden.verify = Mock(return_value={"State": {"Running": False}})
        warden.cleanup_pending()
        self.assertTrue(pending.removed)
        self.assertEqual(daemon.calls[-1], ["container", "rm", IDENTITY])

    def test_failed_admission_configuration_does_not_erase_owned_deletion_authority(self):
        obj, value = owned(), inspected(owned())
        value["HostConfig"], value["State"] = {"ReadonlyRootfs": False}, {"Running": False}
        warden = C.Warden.__new__(C.Warden)
        warden.campaign, warden.end = CAMPAIGN, lambda *_args: 100
        warden.host = NS(inspect=Mock(return_value=value), docker=Mock(), inventory=Mock(return_value=set()))
        self.refused(warden.verify, obj)
        warden.remove(obj)
        warden.host.docker.assert_called_once_with(["container", "rm", IDENTITY], 100)

    def test_abi_helper_uses_same_pending_ledger_inside_cleanup_scope(self):
        source = (ROOT / "scripts/managed_release_linux/controller.py").read_text()
        self.assertIn('abi_ledger = CreationLedger(host, abi_nonce)', source)
        self.assertIn('abi_pending = abi_ledger.reserve(', source)
        self.assertIn('try:\n        abi_owned = abi_ledger.create(', source)
        self.assertIn('finally:\n        abi_owned = abi_ledger.reconcile(', source)


class CancellationAndMountOrderTests(Offline):
    def test_stalled_first_request_cancellation_enters_cleanup_without_starting_products(self):
        warden = C.Warden.__new__(C.Warden)
        clock = [100.0]
        process = FakeProcess()
        warden.host = NS(clock=lambda: clock[0], spawn=Mock(return_value=process))
        warden.budget, warden.cancelled = C.Budget(1, 3600, 120), False
        warden.admit, warden.mount_input, warden.create = Mock(), Mock(), Mock(return_value=owned())
        warden.root, warden.directory, warden.runtime = Path("/source"), Path("/prepared"), Path("/owned")
        warden.receipt = dict(executable="/source/target/test", source_sha=SOURCE, images={"runtime": IMAGE})
        warden.campaign, warden.coordinator_binding = CAMPAIGN, None
        warden.verify = Mock(return_value={"Mounts": [{"Source": "/owned/plan.json", "Destination": K.PLAN, "RW": False}],
                                           "Config": {"Entrypoint": [C.COORDINATOR_ENTRYPOINT],
                                                      "Cmd": list(C.COORDINATOR_COMMAND)}})
        warden.run_case, warden.cleanup_coordinator = Mock(), Mock()
        class CancelSelector(FakeSelector):
            def select(self, timeout):
                clock[0] += min(timeout, .1)
                warden.cancelled = True
                return []
        with patch.object(C.Path, "write_bytes"), patch.object(C.Path, "chmod"), \
             patch.object(C.selectors, "DefaultSelector", CancelSelector), \
             patch.object(C, "ThreadPoolExecutor"):
            with self.assertRaisesRegex(C.Refused, "campaign-cancelled"):
                warden.run()
        self.assertLess(clock[0] - 100, .3)
        warden.cleanup_coordinator.assert_called_once()
        warden.run_case.assert_not_called()

    def test_shared_unmounts_follow_all_owned_authority_cleanup_and_precede_files(self):
        events = []
        warden = C.Warden.__new__(C.Warden)
        warden.cleanup_coordinator = lambda: events.append("coordinator")
        warden.cleanup_pending = lambda: events.append("pending")
        source = NS(kind="source", removed=False)
        executable = NS(kind="executable", removed=False)
        def remove(mount):
            events.append("unmount-" + mount.kind)
            mount.removed = True
        warden.mounts = NS(receipts=[source, executable], remove=remove, close=lambda: events.append("close"))
        warden.resources, warden.runtime_removed = [], False
        warden.remove_runtime = lambda: events.append("files")
        warden.final_cleanup()
        self.assertEqual(events, ["coordinator", "pending", "unmount-executable", "unmount-source", "files", "close"])

    def test_uncertain_container_or_case_mount_cleanup_blocks_shared_unmounts(self):
        for failure in ("pending", "case"):
            warden = C.Warden.__new__(C.Warden)
            warden.cleanup_coordinator = Mock()
            warden.cleanup_pending = Mock(side_effect=C.Refused("pending-unknown") if failure == "pending" else None)
            warden.mounts = NS(receipts=[NS(kind="source", removed=False)], remove=Mock(), close=Mock())
            warden.resources = [NS(mounts=[NS(removed=False)])] if failure == "case" else []
            warden.runtime_removed, warden.remove_runtime = False, Mock()
            self.refused(warden.final_cleanup)
            warden.mounts.remove.assert_not_called()
            warden.remove_runtime.assert_not_called()
            warden.mounts.close.assert_called_once()

    def test_cancellation_prevents_new_resource_creation_and_start_commands(self):
        warden = C.Warden.__new__(C.Warden)
        warden.cancelled = True
        warden.creations, warden.host = Mock(), Mock()
        self.refused(warden.create, ["create", IMAGE], "owned", NONCE)
        self.refused(warden.start, owned(), NS())
        self.refused(warden.command, NS(), "start")
        warden.creations.reserve.assert_not_called()
        warden.host.docker.assert_not_called()

    def test_floors_cover_each_actual_path_and_never_pg_tmpfs(self):
        warden = C.Warden.__new__(C.Warden)
        warden.cancelled = False
        paths = ("/source", "/source/target", "/source/target/test", "/staged", "/case-staging", "/operator/docker")
        warden.required_paths = tuple(map(Path, paths))
        with patch.object(C.shutil, "disk_usage", return_value=NS(free=C.FREE_BYTES)) as usage:
            warden.floors()
        self.assertEqual([call.args[0] for call in usage.call_args_list], list(warden.required_paths))
        with patch.object(C.shutil, "disk_usage", side_effect=[NS(free=C.FREE_BYTES), NS(free=C.FREE_BYTES - 1)]):
            self.refused(warden.floors)
class WorkflowTests(Offline):
    def test_required_job_final_release_source_and_aggregate(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        release = (ROOT / ".github/workflows/release.yml").read_text()
        managed = (ROOT / ".github/workflows/managed-release.yml").read_text()
        self.assertIn("test_managed_linux_*.py", ci)
        self.assertRegex(ci, r"(?m)^    needs: \[.*managed-release.*\]$")
        self.assertIn("  managed-release:\n    needs: contract\n", release)
        self.assertIn("  build:\n    needs: [contract, managed-release]", release)
        self.assertIn("source_ref: ${{ github.sha }}", release)
        self.assertIn("source_ref: ${{ github.sha }}", ci)
        self.assertIn("runs-on: ubuntu-24.04\n", managed)
        self.assertIn("timeout-minutes: 90\n", managed)
        self.assertIn("timeout-minutes: 20\n", managed)
        self.assertIn("timeout-minutes: 60\n", managed)
        self.assertIn("persist-credentials: false", managed)
        self.assertIn("--execute --prepare", managed)
        self.assertIn("--execute --warden", managed)
        self.assertNotIn("secrets:", managed)
        self.assertNotIn("services:", managed)
        self.assertNotIn("continue-on-error", managed)

    def test_runtime_image_is_native_pinned_debian_and_readonly_harness(self):
        dockerfile = (ROOT / "Dockerfile.managed-tests").read_text()
        self.assertIn("FROM " + C.BASE_IMAGE, dockerfile)
        self.assertIn("python3 openssl libc6", dockerfile)
        for name in ("__init__.py", "controller.py", "coordinator.py", "protocol.py", "supervisor.py", "probe.py"):
            self.assertIn("scripts/managed_release_linux/" + name, dockerfile)
        self.assertNotIn("COPY scripts/managed_release_linux/ /opt", dockerfile)
        self.assertNotIn("COPY . .", dockerfile)
        self.assertNotIn("VOLUME", dockerfile)
        self.assertNotIn("EXPOSE", dockerfile)

    def test_separate_native_guarded_coordinator_is_not_a_root_python_class(self):
        source = (ROOT / "scripts/managed_release_linux/controller.py").read_text()
        self.assertIn('"--profile", "coordinator"', source)
        self.assertIn('"/opt/managed_release_linux/coordinator.py"', source)
        self.assertIn('COORDINATOR_ENTRYPOINT = "/usr/local/bin/maskura-product-guard"', source)
        self.assertIn('"--entrypoint=" + COORDINATOR_ENTRYPOINT', source)
        self.assertIn('coordinator_config(inspected)', source)
        self.assertIn('self.coordinator_binding = Binding(pid, PRODUCT_UID)', source)
        self.assertIn('"coordinator-cgroup-not-empty"', source)
        self.assertIn('"coordinator-extra-fds"', source)
        self.assertNotIn("def coordinator(", source)


if __name__ == "__main__":
    unittest.main()
