import datetime as dt
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sqlite_guard", ROOT / "scripts/sqlite-guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

NOW = dt.datetime(2026, 11, 10, tzinfo=dt.timezone.utc)
GOOD = "maskura v0.7.29 (/repo/crates/cli)\nserde v1.0.1\n"


class GuardTests(unittest.TestCase):
    def inspect(self, output=GOOD, returncode=0, now=NOW):
        result = subprocess.CompletedProcess([], returncode, output, "")
        with patch.object(guard.subprocess, "run", return_value=result):
            guard.check(now=now, shapes=[("test", ["--workspace"], "maskura")])

    def test_absent_sqlite_passes(self):
        self.inspect()

    def test_sqlite_dependency_fails(self):
        with self.assertRaises(guard.GuardError):
            self.inspect(GOOD + "libsqlite3-sys v0.30.1\n")

    def test_graph_failures_are_not_absence(self):
        for output, code in [("", 0), ("garbage\n", 0), (GOOD + "not a package\n", 0), (GOOD, 1), ("serde v1.0.1\n", 0)]:
            with self.subTest(output=output, code=code), self.assertRaises(guard.GuardError):
                self.inspect(output, code)

    def test_exact_expiry_and_bad_clock_fail(self):
        for now in [dt.datetime(2026, 12, 10, tzinfo=dt.timezone.utc), dt.datetime(2026, 11, 10), None]:
            with self.subTest(now=now), self.assertRaises(guard.GuardError):
                self.inspect(now=now)

    def test_bad_expiry_fails(self):
        with patch.object(guard, "EXPIRY", "not-a-time"), self.assertRaises(guard.GuardError):
            self.inspect()

    def test_process_exception_fails(self):
        with patch.object(guard.subprocess, "run", side_effect=OSError("unavailable")), self.assertRaises(guard.GuardError):
            guard.check(now=NOW, shapes=[("test", ["--workspace"], "maskura")])

    def test_inspection_timeout_fails_closed(self):
        with patch.object(guard.subprocess, "run", side_effect=subprocess.TimeoutExpired("cargo", 1)) as run, self.assertRaises(guard.GuardError):
            guard.check(now=NOW, shapes=[("test", ["--workspace"], "maskura")])
        self.assertGreater(run.call_args.kwargs["timeout"], 0)

    def test_failed_or_stderr_only_process_does_not_disclose_stderr(self):
        for code, stdout in [(1, GOOD), (0, "")]:
            result = subprocess.CompletedProcess([], code, stdout, "sensitive arbitrary stderr")
            with patch.object(guard.subprocess, "run", return_value=result), self.assertRaises(guard.GuardError) as error:
                guard.check(now=NOW, shapes=[("test", [], "maskura")])
            self.assertNotIn("sensitive arbitrary stderr", str(error.exception))

    def test_nonce_required_and_validated_for_builder_guard(self):
        for value in ["", "invalid", "a" * 63, "G" * 64]:
            with self.subTest(value=value), self.assertRaises(guard.GuardError):
                guard.validate_nonce(value)
        guard.validate_nonce("a" * 64)

    def test_shape_matrix_contains_release_targets(self):
        commands = " ".join(" ".join(args) for _, args, _ in guard.SHAPES)
        for expected in ["--all-features", "--target all", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "wasm32-wasip1", "wasm32-unknown-unknown"]:
            self.assertIn(expected, commands)

    def test_patched_mcp_and_removed_pin_utils_cannot_regress_in_lockfile(self):
        packages = guard.tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]
        for name in ("rmcp", "rmcp-macros"):
            versions = [package["version"] for package in packages if package["name"] == name]
            self.assertTrue(versions, f"missing patched dependency: {name}")
            for version in versions:
                self.assertRegex(version, r"^\d+\.\d+\.\d+$")
                self.assertGreaterEqual(tuple(map(int, version.split("."))), (3, 9, 0))
        self.assertNotIn("pin-utils", {package["name"] for package in packages})
        for path in ("scripts/audit-rust.sh", "deny.toml"):
            self.assertNotIn("RUSTSEC-2026-0441", (ROOT / path).read_text())

    def test_supported_graph_inspection_does_not_require_a_warm_registry(self):
        def cold_registry(command, **kwargs):
            # A cold runner needs normal locked registry resolution; an offline
            # graph check can fail before any dependency assertion is exercised.
            if "--offline" in command:
                return subprocess.CompletedProcess(command, 101, "", "synthetic cold registry")
            return subprocess.CompletedProcess(command, 0, "maskura-mcp v0.7.30\nrmcp v3.9.0\n", "")

        with patch.object(subprocess, "run", side_effect=cold_registry) as run:
            self.test_real_supported_graph_contains_patched_mcp_without_pin_utils()
        command = run.call_args.args[0]
        self.assertIn("--locked", command)
        self.assertIn("--all-features", command)
        self.assertIn("all", command)

    def test_real_supported_graph_contains_patched_mcp_without_pin_utils(self):
        result = subprocess.run(
            ["cargo", "tree", "--locked", "--workspace", "--all-features",
             "--target", "all", "--color", "never", "--prefix", "none", "--format", "{p}"],
            cwd=ROOT, capture_output=True, text=True, timeout=guard.INSPECTION_TIMEOUT_SECONDS,
        )
        self.assertEqual(result.returncode, 0, "supported dependency graph could not be inspected")
        packages = [guard.PACKAGE.fullmatch(line) for line in result.stdout.splitlines() if line]
        self.assertTrue(packages)
        self.assertTrue(all(package is not None for package in packages))
        names = {package.group(1) for package in packages}
        self.assertIn("maskura-mcp", names)
        self.assertIn("rmcp", names)
        self.assertNotIn("pin-utils", names)

    def test_later_build_shape_cannot_reuse_an_earlier_absence_result(self):
        shapes = [("first", ["-p", "first"], "first"), ("second", ["-p", "second"], "second")]
        results = [subprocess.CompletedProcess([], 0, "first v1.0.0\n", ""),
                   subprocess.CompletedProcess([], 0, "second v1.0.0\nsqlx-sqlite v0.8.6\n", "")]
        with patch.object(guard.subprocess, "run", side_effect=results) as run:
            with self.assertRaises(guard.GuardError):
                guard.check(now=NOW, shapes=shapes)
        self.assertEqual(run.call_count, 2)
        self.assertIn("second", run.call_args.args[0])

    def test_real_feature_enabled_cargo_graph_rejects_sqlite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "src").mkdir()
            (root / "src/lib.rs").write_text("")
            (root / "sqlite/src").mkdir(parents=True)
            (root / "sqlite/src/lib.rs").write_text("")
            (root / "sqlite/Cargo.toml").write_text('[package]\nname="libsqlite3-sys"\nversion="0.30.1"\nedition="2021"\n')
            (root / "Cargo.toml").write_text('[package]\nname="graph-fixture"\nversion="1.0.0"\nedition="2021"\n[features]\nsqlite=["dep:libsqlite3-sys"]\n[dependencies]\nlibsqlite3-sys={path="sqlite",optional=true}\n')
            subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=root, check=True, capture_output=True)
            with patch.object(guard, "ROOT", root):
                guard.check(now=NOW, shapes=[("disabled", [], "graph-fixture")])
                with self.assertRaises(guard.GuardError):
                    guard.check(now=NOW, shapes=[("enabled", ["--features", "sqlite"], "graph-fixture")])

    def test_security_wiring_and_no_static_exception(self):
        audit = (ROOT / "scripts/audit-rust.sh").read_text()
        self.assertLess(audit.index("sqlite-guard.py"), audit.index("cargo audit --ignore"))
        self.assertIn("--ignore RUSTSEC-2026-0459", audit)
        self.assertNotIn("RUSTSEC-2026-0457", audit)
        self.assertNotIn("RUSTSEC-2026-0462", audit)
        self.assertNotIn("RUSTSEC-2026-0459", (ROOT / "deny.toml").read_text())
        for path in ["scripts/audit-dependencies.sh", "justfile"]:
            self.assertIn("sqlite-guard.py deny", (ROOT / path).read_text())
        release = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertEqual(release.count("python3 scripts/sqlite-guard.py"), 8)
        self.assertIn("python3 scripts/sqlite-guard.py", (ROOT / "Dockerfile").read_text())
        self.assertIn('"scripts/sqlite-guard.py"', (ROOT / "dagger/src/maskura/__init__.py").read_text())

    def test_deny_gets_only_guarded_temporary_ignore(self):
        seen = []

        def run(command, **kwargs):
            config = pathlib.Path(command[command.index("--config") + 1])
            seen.append(config)
            parsed = guard.tomllib.loads(config.read_text())
            self.assertEqual(parsed["advisories"]["ignore"].count(guard.ADVISORY), 1)
            self.assertNotIn("RUSTSEC-2026-0457", parsed["advisories"]["ignore"])
            self.assertNotIn("RUSTSEC-2026-0462", parsed["advisories"]["ignore"])
            return subprocess.CompletedProcess(command, 0)

        with patch.object(sys, "argv", ["sqlite-guard.py", "deny"]), patch.object(guard, "check") as check, patch.object(guard.subprocess, "run", side_effect=run):
            self.assertEqual(guard.main(), 0)
            check.assert_called_once()
        self.assertEqual(len(seen), 1)
        self.assertFalse(seen[0].exists())

    def test_deny_does_not_run_if_guard_fails(self):
        with patch.object(sys, "argv", ["sqlite-guard.py", "deny"]), patch.object(guard, "check", side_effect=guard.GuardError("expired")), patch.object(guard.subprocess, "run") as run:
            self.assertEqual(guard.main(), 1)
            run.assert_not_called()

    def test_unconditional_sqlite_exception_is_rejected_even_after_graph_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "deny.toml").write_text('[advisories]\nignore = ["RUSTSEC-2026-0459"]\n')
            with patch.object(sys, "argv", ["sqlite-guard.py", "deny"]), patch.object(guard, "ROOT", root), patch.object(guard, "check"), patch.object(guard.subprocess, "run") as run:
                self.assertEqual(guard.main(), 1)
                run.assert_not_called()

    def test_deny_rechecks_time_after_graph_resolution(self):
        with patch.object(sys, "argv", ["sqlite-guard.py", "deny"]), patch.object(guard, "check"), patch.object(guard, "validate_time", side_effect=guard.GuardError("expired")), patch.object(guard.subprocess, "run") as run:
            self.assertEqual(guard.main(), 1)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
