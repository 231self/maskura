# SPDX-License-Identifier: Apache-2.0
"""Offline closed startup-frame regressions; no container or kernel execution.

These tests qualify only the fixed diagnostic vocabulary. They never establish
that a coordinator starts, that seccomp/BPF enforce anything, or that a managed
case passes.
"""
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import Mock, patch

from scripts.managed_release_linux import controller as C
from scripts.managed_release_linux import coordinator as K

ROOT = Path(__file__).resolve().parents[1]


IDENTITY = "a" * 64


def buffered_stdout():
    out = io.BytesIO()
    return NS(buffer=out), out


def frame(out):
    return json.loads(out.getvalue().decode("ascii"))


class CoordinatorFrameTests(unittest.TestCase):
    def test_startup_frame_is_exact_ascii_fixed_code_only(self):
        stdout, out = buffered_stdout()
        with patch("sys.stdout", stdout):
            K.emit_startup("plan")
        self.assertEqual(frame(out), {"schema": 1, "kind": "coordinator-startup", "code": "plan"})

    def test_non_allowlisted_code_becomes_internal(self):
        stdout, out = buffered_stdout()
        with patch("sys.stdout", stdout):
            K.emit_startup("PRIVATE_EXCEPTION_TEXT")
        self.assertEqual(frame(out)["code"], "internal")
        self.assertNotIn(b"PRIVATE", out.getvalue())

    def test_frame_write_failure_never_propagates(self):
        broken = NS(buffer=NS(write=Mock(side_effect=OSError("PRIVATE")),
                              flush=Mock(side_effect=OSError("PRIVATE"))))
        with patch("sys.stdout", broken):
            K.emit_startup("identity")  # must not raise

    def test_interpreter_hook_emits_only_the_fixed_interpreter_code(self):
        stdout, out = buffered_stdout()
        with patch("sys.stdout", stdout):
            K._startup_hook(ValueError, ValueError("PRIVATE_PROMPT"), None)
        self.assertEqual(frame(out),
                         {"schema": 1, "kind": "coordinator-startup", "code": "interpreter"})

    def test_test_imports_never_replace_the_interpreter_hook(self):
        import sys
        # The real coordinator entry installs the hook only under __main__;
        # importing it as a library must leave interpreter-wide behavior alone.
        self.assertIsNot(sys.excepthook, K._startup_hook)
        self.assertNotEqual(K.__name__, "__main__")


class CoordinatorPhaseTests(unittest.TestCase):
    def run_main(self, argv=None, uid=0):
        stdout, out = buffered_stdout()
        argv = ["--plan", K.PLAN] if argv is None else argv
        with patch("sys.stdout", stdout), patch("sys.stderr", io.StringIO()):
            code = K.main(argv)
        return code, out

    def test_argument_failure_returns_fixed_arguments_code_and_frame(self):
        code, out = self.run_main(["--plan", "not-the-fixed-plan-path"])
        self.assertEqual(code, 11)
        self.assertEqual(frame(out)["code"], "arguments")

    def test_identity_phase_returns_its_own_code_and_frame(self):
        with patch.object(K.os, "getuid", return_value=0):
            code, out = self.run_main()
        self.assertEqual(code, 12)
        self.assertEqual(frame(out)["code"], "identity")

    def test_network_plan_and_request_phases_are_distinct_fixed_codes(self):
        cases = (
            ("network", 13, dict(network_denials=Mock(side_effect=OSError("PRIVATE")),
                                 read_plan=Mock(return_value={}),
                                 run=Mock(return_value=0))),
            ("plan", 14, dict(network_denials=Mock(return_value=None),
                              read_plan=Mock(side_effect=K.Refused("coordinator-contract")),
                              run=Mock(return_value=0))),
            ("request", 15, dict(network_denials=Mock(return_value=None),
                                 read_plan=Mock(return_value={}),
                                 run=Mock(side_effect=K.Refused("coordinator-contract")))),
        )
        identity = dict(getuid=Mock(return_value=20001), geteuid=Mock(return_value=20001),
                        getgid=Mock(return_value=20001), getegid=Mock(return_value=20001),
                        getgroups=Mock(return_value=[]))
        for phase, expected, overrides in cases:
            with self.subTest(phase=phase), \
                 patch.multiple(K.os, **identity), \
                 patch.multiple(K, **overrides):
                code, out = self.run_main()
            self.assertEqual(code, expected)
            self.assertEqual(frame(out),
                             {"schema": 1, "kind": "coordinator-startup", "code": phase})

    def test_success_returns_zero_without_any_startup_frame(self):
        identity = dict(getuid=Mock(return_value=20001), geteuid=Mock(return_value=20001),
                        getgid=Mock(return_value=20001), getegid=Mock(return_value=20001),
                        getgroups=Mock(return_value=[]))
        with patch.multiple(K.os, **identity), \
             patch.object(K, "network_denials", return_value=None), \
             patch.object(K, "read_plan", return_value={}), \
             patch.object(K, "run", return_value=0):
            code, out = self.run_main()
        self.assertEqual(code, 0)
        self.assertEqual(out.getvalue(), b"")

    def test_startup_codes_match_the_warden_allowlist_exactly(self):
        self.assertEqual(set(K.STARTUP_CODES), set(C.COORDINATOR_STARTUP_CODES))


class WardenDispatchTests(unittest.TestCase):
    def warden(self, read=None, wait=0, state=None, inspect_error=None, stderr=None):
        warden = C.Warden.__new__(C.Warden)
        warden.last_adapter_exit = None
        warden.last_container_started = None
        warden.last_container_exit = None
        warden.last_stderr_class = None
        warden.coordinator_owned = NS(identity=IDENTITY)
        warden.coordinator_channel = NS(read=Mock(side_effect=read) if isinstance(read, Exception)
                                        else Mock(return_value=read),
                                        process=NS(wait=Mock(side_effect=wait) if isinstance(wait, Exception)
                                                   else Mock(return_value=wait),
                                                   stderr=stderr))
        warden.host = NS(clock=lambda: 100.0,
                         inspect=Mock(side_effect=inspect_error) if inspect_error
                         else Mock(return_value=state or {}))
        warden.end = lambda case=None, cleanup=False: 5000.0
        return warden

    def state(self, started="2026-11-12T00:00:00Z", exit_code=1):
        return {"State": {"StartedAt": started, "ExitCode": exit_code}}

    def test_guard_and_coordinator_frames_dispatch_to_fixed_categories(self):
        for data, category in (
                ({"schema": 1, "kind": "product-guard", "ok": False, "code": "seccomp"},
                 "guard-seccomp"),
                ({"schema": 1, "kind": "coordinator-startup", "code": "network"},
                 "coordinator-network")):
            warden = self.warden(read=data)
            with self.subTest(category=category), self.assertRaises(C.Refused) as error:
                warden.read_coordinator(4000.0)
            self.assertEqual(error.exception.args, (category,))

    def test_malformed_startup_frames_fail_closed(self):
        malformed = (
            {"schema": 1, "kind": "product-guard", "ok": False, "code": "PRIVATE"},
            {"schema": 1, "kind": "product-guard", "ok": False, "code": "seccomp", "extra": 1},
            {"schema": 1, "kind": "coordinator-startup", "code": "raw-exception-text"},
            {"schema": 1, "kind": "coordinator-startup", "code": "plan", "path": "/x"},
        )
        for data in malformed:
            warden = self.warden(read=data)
            with self.subTest(data=data), self.assertRaises(C.Refused) as error:
                warden.read_coordinator(4000.0)
            self.assertIn(error.exception.args[0],
                          ("schema-invalid", "guard-startup-frame", "coordinator-startup-frame"))

    def test_valid_run_case_frame_passes_through_undispatched(self):
        request = {"schema": 1, "kind": "run-case", "campaign": "b" * 32,
                   "source_sha": "c" * 40, "seq": 1, "case": "isolation-controls"}
        warden = self.warden(read=request)
        self.assertEqual(warden.read_coordinator(4000.0), request)

    def test_non_eof_channel_errors_are_not_remapped(self):
        warden = self.warden(read=C.Refused("channel-deadline"))
        with self.assertRaises(C.Refused) as error:
            warden.read_coordinator(4000.0)
        self.assertEqual(error.exception.args, ("channel-deadline",))
        warden.host.inspect.assert_not_called()

    def test_eof_uses_container_started_and_exit_facts_only(self):
        for started, exit_code, category in (
                ("0001-01-01T00:00:00Z", 0, "coordinator-never-started"),
                ("2026-11-12T00:00:00Z", 2, "coordinator-arguments"),
                ("2026-11-12T00:00:00Z", 1, "coordinator-startup-crash"),
                ("2026-11-12T00:00:00Z", 130, "coordinator-startup-exit")):
            warden = self.warden(read=C.Refused("channel-eof"),
                                 state=self.state(started, exit_code))
            with self.subTest(category=category), self.assertRaises(C.Refused) as error:
                warden.read_coordinator(4000.0)
            self.assertEqual(error.exception.args, (category,))
            self.assertEqual(warden.last_adapter_exit, 0)
            self.assertEqual(warden.last_container_exit, exit_code)
            self.assertEqual(warden.last_container_started, started != "0001-01-01T00:00:00Z")

    def test_unresolved_adapter_or_state_never_becomes_a_pass_or_absence(self):
        timeout = self.warden(read=C.Refused("channel-eof"),
                              wait=subprocess.TimeoutExpired(cmd=("docker",), timeout=1))
        with self.assertRaises(C.Refused) as error:
            timeout.read_coordinator(4000.0)
        self.assertEqual(error.exception.args, ("coordinator-adapter-unresolved",))

        for bad_state in ({}, {"State": {}}, {"State": {"StartedAt": 1, "ExitCode": 1}},
                          {"State": {"StartedAt": "x", "ExitCode": True}}):
            warden = self.warden(read=C.Refused("channel-eof"), state=bad_state)
            with self.subTest(state=bad_state), self.assertRaises(C.Refused) as error:
                warden.read_coordinator(4000.0)
            self.assertEqual(error.exception.args, ("coordinator-state-unproved",))

        broken = self.warden(read=C.Refused("channel-eof"),
                             inspect_error=C.Refused("command-failed"))
        with self.assertRaises(C.Refused) as error:
            broken.read_coordinator(4000.0)
        self.assertEqual(error.exception.args, ("coordinator-state-unproved",))

    def test_every_generated_startup_category_is_exportable_verbatim(self):
        categories = [f"guard-{code}" for code in C.GUARD_STARTUP_CODES]
        categories += [f"coordinator-{code}" for code in C.COORDINATOR_STARTUP_CODES]
        categories += ["coordinator-never-started", "coordinator-startup-crash",
                       "coordinator-startup-exit", "coordinator-adapter-unresolved",
                       "coordinator-state-unproved", "coordinator-entrypoint-unproved",
                       "coordinator-script-unopened", "coordinator-argparse-uncaught",
                       "coordinator-interpreter-traceback", "coordinator-interpreter-argv",
                       "coordinator-stderr-unclassified", "coordinator-adapter-error",
                       "coordinator-runtime-error", "coordinator-script-missing",
                       "coordinator-script-permission", "coordinator-script-policy", "init-script-blocked"]
        for category in categories:
            self.assertEqual(C.failure_category(C.Refused(category)), category)

    def test_binding_failures_are_closed_and_os_errors_do_not_expose_details(self):
        for category in ("cgroup-path", "init-identity", "init-not-idle", "proc-invalid",
                         "proc-stat-invalid", "proc-status-invalid", "coordinator-cleanup-unproved"):
            self.assertEqual(C.failure_category(C.Refused(category)), category)
        self.assertEqual(C.failure_category(FileNotFoundError(2, "private")), "resource-missing")
        self.assertEqual(C.failure_category(PermissionError(13, "private")), "permission-denied")
        self.assertEqual(C.failure_category(OSError(5, "private")), "internal-failure")
        self.assertEqual(C.failure_category(C.Refused("private")), "internal-failure")
        for error, expected in ((TypeError("private"), "error-type"),
                                (ValueError("private"), "error-value"),
                                (AttributeError("private"), "error-attribute"),
                                (KeyError("private"), "error-key"),
                                (NameError("private"), "error-name")):
            self.assertEqual(C.diagnostic_category(error), expected)
        from scripts.managed_release_linux import protocol
        self.assertEqual(C.diagnostic_category(protocol.ContractError("descriptor-kind")),
                         "protocol-descriptor-kind")
        self.assertEqual(C.diagnostic_category(protocol.ContractError("private")), "internal-failure")
        self.assertEqual(C.diagnostic_category(C.Refused("host-mount-source-ambiguous")),
                         "host-mount-source-ambiguous")
        self.assertEqual(C.diagnostic_category(C.Refused("host-mount-private-data")), "internal-failure")


class StderrClassificationTests(unittest.TestCase):
    def test_fixed_markers_map_to_one_closed_category(self):
        cases = (
            (b"", None),
            (b"python3: can't open file '/opt/managed_release_linux/coordinator.py': "
             b"[Errno 2] No such file or directory\n", "coordinator-script-missing"),
            (b"coordinator.py: error: argument --plan: invalid choice: 'x'\n",
             "coordinator-argparse-uncaught"),
            (b"Traceback (most recent call last):\n  File \"x\", line 1\n"
             b"Refused: coordinator-contract\n", "coordinator-interpreter-traceback"),
            (b"Unknown option: --pl\n", "coordinator-interpreter-argv"),
            (b"usage: coordinator.py [--plan PATH]\n", "coordinator-interpreter-argv"),
            (b"Error response from daemon: PRIVATE_DETAIL\n", "coordinator-adapter-error"),
            (b"OCI runtime error: PRIVATE_DETAIL\n", "coordinator-runtime-error"),
            (b"unrecognized private detail\n", "coordinator-stderr-unclassified"),
        )
        for raw, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(C.coordinator_stderr_class(raw), expected)

    def test_classification_never_returns_the_raw_bytes(self):
        result = C.coordinator_stderr_class(b"can't open file PRIVATE_DETAIL")
        self.assertEqual(result, "coordinator-script-unopened")
        self.assertNotIsInstance(result, bytes)

    def test_oversized_stderr_is_rejected_not_summarized(self):
        with self.assertRaises(C.Refused) as error:
            C.coordinator_stderr_class(b"x" * (C.STDERR_LIMIT + 2))
        self.assertEqual(error.exception.args, ("stderr-class-size",))

    def test_stderr_class_precedes_exit_map_but_never_overrides_container_state(self):
        cannot_open = b"python3: can't open file '/opt/x': [Errno 2]\n"
        # Started container: fixed stderr marker beats the generic exit-2 map.
        warden = WardenDispatchTests.warden(self, read=C.Refused("channel-eof"),
                                            state=WardenDispatchTests.state(self),
                                            stderr=io.BytesIO(cannot_open))
        with self.assertRaises(C.Refused) as error:
            warden.read_coordinator(4000.0)
        self.assertEqual(error.exception.args, ("coordinator-script-missing",))
        self.assertEqual(warden.last_stderr_class, "coordinator-script-missing")

        # Started with empty stderr: exit-based map still applies.
        warden = WardenDispatchTests.warden(self, read=C.Refused("channel-eof"),
                                            state=WardenDispatchTests.state(self, exit_code=2),
                                            stderr=io.BytesIO(b""))
        with self.assertRaises(C.Refused) as error:
            warden.read_coordinator(4000.0)
        self.assertEqual(error.exception.args, ("coordinator-arguments",))

        # Never-started container: state fact wins over any daemon text.
        warden = WardenDispatchTests.warden(self, read=C.Refused("channel-eof"),
                                            state=WardenDispatchTests.state(self, started="0001-01-01T00:00:00Z"),
                                            stderr=io.BytesIO(cannot_open))
        with self.assertRaises(C.Refused) as error:
            warden.read_coordinator(4000.0)
        self.assertEqual(error.exception.args, ("coordinator-never-started",))


class EntrypointBindingTests(unittest.TestCase):
    def test_daemon_must_apply_the_exact_guard_entrypoint_and_command(self):
        good = {"Config": {"Entrypoint": [C.COORDINATOR_ENTRYPOINT],
                           "Cmd": list(C.COORDINATOR_COMMAND)}}
        self.assertTrue(C.coordinator_config(good))
        for config in (None, {}, {"Entrypoint": [C.COORDINATOR_ENTRYPOINT]},
                       {"Cmd": list(C.COORDINATOR_COMMAND)},
                       {"Entrypoint": ["/usr/bin/python3", "-I", "-B",
                                       "/opt/managed_release_linux/controller.py"],
                        "Cmd": list(C.COORDINATOR_COMMAND)},
                       {"Entrypoint": [C.COORDINATOR_ENTRYPOINT],
                        "Cmd": list(C.COORDINATOR_COMMAND) + ["EXTRA"]}):
            with self.subTest(config=config):
                self.assertFalse(C.coordinator_config({} if config is None else {"Config": config}))

    def test_default_adapter_spawn_still_discards_stderr(self):
        with patch("subprocess.Popen", return_value=NS()) as popen:
            C.Host().spawn(["/usr/bin/docker", "info"])
        self.assertIs(popen.call_args.kwargs["stderr"], subprocess.DEVNULL)

    def test_coordinator_adapter_spawn_is_the_only_bounded_captured_stream(self):
        with patch("subprocess.Popen", return_value=NS()) as popen:
            C.Host().spawn(["/usr/bin/docker", "start", "--attach"], stderr=subprocess.PIPE)
        self.assertIs(popen.call_args.kwargs["stderr"], subprocess.PIPE)


class ScriptPreflightTests(unittest.TestCase):
    def test_errno_mapping_is_fixed_and_closed(self):
        self.assertEqual(C.script_failure_category(2), "coordinator-script-missing")
        self.assertEqual(C.script_failure_category(13), "coordinator-script-permission")
        self.assertEqual(C.script_failure_category(1), "coordinator-script-policy")
        for value in (None, 7, 21, 121):
            self.assertEqual(C.script_failure_category(value), "coordinator-script-unopened")

    def test_stderr_errno_refines_only_the_unopened_marker(self):
        cases = (
            (b"python3: can't open file '/x': [Errno 2] No such file or directory\n",
             "coordinator-script-missing"),
            (b"python3: can't open file '/x': [Errno 13] Permission denied\n",
             "coordinator-script-permission"),
            (b"python3: can't open file '/x': [Errno 1] Operation not permitted\n",
             "coordinator-script-policy"),
            (b"python3: can't open file '/x'\n", "coordinator-script-unopened"),
            (b"coordinator.py: error: bad argument [Errno 2]\n", "coordinator-argparse-uncaught"),
        )
        for raw, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(C.coordinator_stderr_class(raw), expected)

    def test_fixed_preflight_source_emits_a_valid_closed_record(self):
        import contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            exec(C.SCRIPT_PREFLIGHT_CODE, {"__builtins__": __builtins__})
        record = json.loads(out.getvalue())
        self.assertEqual(C.script_preflight(record), record)
        self.assertIn(record["opened"], (True, False))
        self.assertEqual(record["kind"], "coordinator-script-preflight")

    def test_preflight_validator_rejects_non_closed_shapes(self):
        base = {"schema": 1, "kind": "coordinator-script-preflight", "opened": False,
                "open_errno": 2, "mode": None, "uid": None, "gid": None,
                "dir_mode": None, "dir_uid": None}
        C.script_preflight(dict(base))
        for change in (dict(schema=True), dict(kind="other"), dict(opened="yes"),
                       dict(open_errno="2"), dict(open_errno=True), dict(mode="rwx"),
                       dict(uid=-1), dict(extra=1),
                       dict(stat_errno="nope")):
            with self.subTest(change=change), self.assertRaises(C.Refused) as error:
                C.script_preflight(dict(base, **change))
            self.assertEqual(error.exception.args, ("script-preflight-shape",))

    def test_prepare_runs_the_guarded_script_preflight(self):
        source = (ROOT / "scripts/managed_release_linux/controller.py").read_text()
        prep = source.split("def prepare(", 1)[1].split("def validate_prepared(", 1)[0]
        self.assertIn("coordinator-script-preflight", prep)
        self.assertIn("SCRIPT_PREFLIGHT_CODE", prep)
        self.assertIn('"--profile", "coordinator", "--",', prep)
        self.assertIn("script_failure_category", prep)

    def test_mirror_preflight_bisects_the_runtime_only_differences(self):
        source = (ROOT / "scripts/managed_release_linux/controller.py").read_text()
        prep = source.split("def prepare(", 1)[1].split("def validate_prepared(", 1)[0]
        self.assertIn("mirror_startup_preflight(host, end, directory, images, source)", prep)
        mirror = source.split("def run_mirror_variant(", 1)[1].split("def mirror_startup_preflight(", 1)[0]
        self.assertIn('("no_guard", True, True, False)', source)
        self.assertIn('("full", True, True, True)', source)
        self.assertIn('("no_interactive", False, True, True)', source)
        self.assertIn('("no_plan_mount", True, False, True)', source)
        # The full variant must reproduce the campaign container exactly.
        self.assertIn("*COORDINATOR_COMMAND", mirror)
        self.assertIn('"--security-opt=seccomp="', mirror)
        self.assertIn("type=bind,source={plan},target=/run/maskura/plan.json,readonly", mirror)
        self.assertIn('"/usr/bin/sudo", "--", "/usr/bin/chown", "0:0"', mirror)
        self.assertIn('"mirror-plan-owner"', mirror)
        self.assertIn('args.append("--interactive")', mirror)
        # Outcomes are closed values only: frame dispatch and the shared maps.
        self.assertIn("coordinator_startup(data)", mirror)
        self.assertIn("coordinator_stderr_class(raw)", mirror)
        self.assertIn("failure_category(", mirror)
        for closed in ("frame-ok", "coordinator-adapter-unresolved",
                       "coordinator-arguments", "coordinator-startup-crash",
                       "coordinator-startup-exit"):
            self.assertIn(closed, mirror)
        for category in ("mirror-still-running", "mirror-cleanup-unproved"):
            self.assertEqual(C.failure_category(C.Refused(category)), category)

    def test_bootstrap_preserves_script_arguments_and_main_context(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "coordinator.py"
            script.write_text("import json,sys\nprint(json.dumps([__name__,__file__,__package__,sys.argv]))\n")
            bootstrap = C.COORDINATOR_BOOTSTRAP.replace(C.SCRIPT_PATH, str(script))
            result = subprocess.run([sys.executable, "-I", "-B", "-c", bootstrap, "--plan", "value"],
                                    capture_output=True, check=True, text=True)
            self.assertEqual(json.loads(result.stdout),
                             ["__main__", str(script), None, [str(script), "--plan", "value"]])

    def test_mirror_requires_unguarded_identity_and_full_frame(self):
        def run(outcomes):
            with patch.object(C, "run_mirror_variant", side_effect=outcomes) as mirror:
                C.mirror_startup_preflight(None, 1, None, None, "a" * 40)
                return mirror.call_count
        self.assertEqual(run(["coordinator-identity", "frame-ok"]), 2)
        with self.assertRaises(C.Refused) as error:
            run(["coordinator-script-policy"])
        self.assertEqual(error.exception.args, ("init-script-blocked",))
        with self.assertRaises(C.Refused) as error:
            run(["coordinator-startup-crash"])
        self.assertEqual(error.exception.args, ("coordinator-startup-crash",))
        with self.assertRaises(C.Refused) as error:
            run(["coordinator-identity", "coordinator-plan", "frame-ok", "coordinator-plan"])
        self.assertEqual(error.exception.args, ("coordinator-plan",))


if __name__ == "__main__":
    unittest.main()
