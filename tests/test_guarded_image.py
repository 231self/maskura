import base64
import asyncio
import datetime as dt
import importlib.util
import pathlib
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("guarded_image", ROOT / "scripts/guarded-image.py")
image = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image)


class ImageEntryTests(unittest.TestCase):
    def test_preflight_precedes_each_fresh_docker_invocation(self):
        calls = []
        def run(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0)
        with patch.object(image.subprocess, "run", side_effect=run), patch.object(image.secrets, "token_hex", side_effect=["a" * 64, "b" * 64]):
            self.assertEqual(image.main(["docker", "--tag", "maskura:test"]), 0)
            self.assertEqual(image.main(["docker", "--tag", "maskura:test"]), 0)
        self.assertIn("sqlite-guard.py", calls[0][-1])
        self.assertEqual(calls[1][0:2], ["docker", "build"])
        self.assertIn("MASKURA_GUARD_NONCE=" + "a" * 64, calls[1])
        self.assertIn("sqlite-guard.py", calls[2][-1])
        self.assertIn("MASKURA_GUARD_NONCE=" + "b" * 64, calls[3])

    def test_failed_preflight_never_runs_engine(self):
        with patch.object(image.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)) as run:
            self.assertNotEqual(image.main(["docker", "--tag", "maskura:test"]), 0)
            self.assertEqual(run.call_count, 1)

    def test_expiry_blocks_a_previously_successful_cached_docker_build(self):
        guard_spec = importlib.util.spec_from_file_location("cache_test_sqlite_guard", ROOT / "scripts/sqlite-guard.py")
        guard = importlib.util.module_from_spec(guard_spec)
        guard_spec.loader.exec_module(guard)
        now = [dt.datetime(2026, 11, 10, tzinfo=dt.timezone.utc)]
        engines = []

        def run(command, **kwargs):
            if command[0] == sys.executable:
                try:
                    guard.validate_time(now[0])
                except guard.GuardError:
                    return subprocess.CompletedProcess(command, 1)
            else:
                # A cache hit would succeed indefinitely without the host check.
                engines.append(command)
            return subprocess.CompletedProcess(command, 0)

        with patch.object(image.subprocess, "run", side_effect=run), patch.object(image.secrets, "token_hex", return_value="a" * 64):
            self.assertEqual(image.main(["docker", "--tag", "maskura:test"]), 0)
            now[0] = dt.datetime(2026, 12, 10, tzinfo=dt.timezone.utc)
            self.assertEqual(image.main(["docker", "--tag", "maskura:test"]), 1)
        self.assertEqual(len(engines), 1, "expired invocation reached the cached engine")

    def test_invalid_freshness_never_runs_engine(self):
        with patch.object(image.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run, patch.object(image.secrets, "token_hex", return_value="invalid"):
            self.assertNotEqual(image.main(["docker", "--tag", "maskura:test"]), 0)
            self.assertEqual(run.call_count, 1)

    def test_dagger_gets_fresh_nonce_trusted_guard_and_requested_ref(self):
        calls = []
        def run(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0)
        with patch.object(image.subprocess, "run", side_effect=run), patch.object(image.secrets, "token_hex", return_value="c" * 64):
            self.assertEqual(image.main(["dagger", "--action", "image", "--ref", "main"]), 0)
        cmd = calls[1]
        self.assertEqual(cmd[:3], ["dagger", "call", "image"])
        self.assertEqual(cmd[cmd.index("--ref") + 1], "main")
        self.assertEqual(cmd[cmd.index("--guard-nonce") + 1], "c" * 64)
        supplied = base64.b64decode(cmd[cmd.index("--guard-source-b64") + 1])
        self.assertEqual(supplied, (ROOT / "scripts/sqlite-guard.py").read_bytes())

    def test_compose_build_is_guarded_before_build_and_before_start(self):
        calls = []
        def run(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0)
        with patch.object(image.subprocess, "run", side_effect=run), patch.object(image.secrets, "token_hex", return_value="d" * 64):
            self.assertEqual(image.main(["compose"]), 0)
        self.assertIn("sqlite-guard.py", calls[0][-1])
        self.assertEqual(calls[1][:2], ["docker", "compose"])
        self.assertIn("MASKURA_GUARD_NONCE=" + "d" * 64, calls[1])
        self.assertIn("sqlite-guard.py", calls[2][-1])
        self.assertIn("--no-build", calls[3])

    def test_compose_second_preflight_failure_never_starts(self):
        for exit_code in (1, 2):
            with self.subTest(exit_code=exit_code):
                results = [subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], exit_code)]
                with patch.object(image.subprocess, "run", side_effect=results) as run, patch.object(image.secrets, "token_hex", return_value="d" * 64):
                    self.assertEqual(image.main(["compose"]), exit_code)
                self.assertEqual(run.call_count, 3)
                self.assertIn("sqlite-guard.py", run.call_args_list[2].args[0][-1])
                self.assertFalse(any("up" in call.args[0] for call in run.call_args_list))

    def test_engine_failure_never_advances_to_start_or_publish(self):
        for args in (["compose"], ["docker", "--tag", "maskura:test"], ["dagger", "--action", "publish", "--tag", "v0.0.0"]):
            with self.subTest(args=args):
                results = [subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 7)]
                with patch.object(image.subprocess, "run", side_effect=results) as run, patch.object(image.secrets, "token_hex", return_value="e" * 64):
                    self.assertEqual(image.main(args), 7)
                self.assertEqual(run.call_count, 2)
                self.assertNotIn("up", run.call_args_list[1].args[0])

    def test_dagger_publish_wrapper_preflights_and_propagates_inputs(self):
        with patch.object(image.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run, patch.object(image.secrets, "token_hex", return_value="f" * 64):
            self.assertEqual(image.main(["dagger", "--action", "publish", "--tag", "v0.0.0", "--ref", "fixture-ref"]), 0)
        self.assertEqual(run.call_count, 2)
        self.assertIn("sqlite-guard.py", run.call_args_list[0].args[0][-1])
        cmd = run.call_args_list[1].args[0]
        self.assertEqual(cmd[:3], ["dagger", "call", "publish"])
        self.assertEqual(cmd[cmd.index("--ref") + 1], "fixture-ref")
        self.assertEqual(cmd[cmd.index("--guard-nonce") + 1], "f" * 64)
        self.assertEqual(base64.b64decode(cmd[cmd.index("--guard-source-b64") + 1]), (ROOT / "scripts/sqlite-guard.py").read_bytes())

    def test_contract_uses_fresh_graph_for_actual_engine_source(self):
        docker = (ROOT / "Dockerfile").read_text()
        self.assertLess(docker.index("cargo build --locked"), docker.index("ARG MASKURA_GUARD_NONCE"))
        self.assertLess(docker.index("ARG MASKURA_GUARD_NONCE"), docker.index("COPY --from=build"))
        self.assertIn("--nonce", docker)
        dagger = (ROOT / "dagger/src/maskura/__init__.py").read_text()
        self.assertIn('with_new_file("/src/scripts/sqlite-guard.py"', dagger)
        self.assertIn('"--nonce", guard_nonce', dagger)
        self.assertIn("--nonce", (ROOT / "local/Dockerfile").read_text())

    def test_mocked_dagger_checks_actual_remote_graph_with_fresh_nonce(self):
        events = []
        cache = set()

        class Container:
            def __init__(self):
                self.ref = None
                self.source = None
                self.guard_nonce = None
                self.dependencies = []

            def from_(self, *args): return self
            def with_workdir(self, *args): return self
            def with_env_variable(self, *args): return self
            def with_mounted_cache(self, *args): return self
            def with_file(self, path, source):
                self.dependencies.append(source)
                return self
            def with_exposed_port(self, *args): return self
            def with_entrypoint(self, *args): return self
            def file(self, path): return self
            def directory(self, path): return self

            async def publish(self, name):
                self.resolve()
                events.append(("publish", name))
                return name

            async def sync(self):
                self.resolve()

            def with_directory(self, path, tree):
                if path == "/src":
                    self.ref = tree
                elif isinstance(tree, Container):
                    self.dependencies.append(tree)
                return self

            def with_new_file(self, path, contents):
                self.source = contents
                return self

            def with_exec(self, command):
                if "--nonce" in command:
                    self.guard_nonce = command[-1]
                return self

            def resolve(self):
                for dependency in self.dependencies:
                    dependency.resolve()
                if self.guard_nonce is not None:
                    key = (self.ref, self.guard_nonce)
                    if key not in cache:
                        self.assert_trusted_source()
                        events.append(key)
                        if self.ref == "sqlite-enabled":
                            raise RuntimeError("remote SQLite graph rejected")
                        if self.ref == "engine-failed":
                            raise RuntimeError("mock engine build failed")
                        cache.add(key)

            def assert_trusted_source(self):
                if self.source != (ROOT / "scripts/sqlite-guard.py").read_text():
                    raise AssertionError("remote ref did not use trusted guard")

        class Git:
            def branch(self, ref): self.ref = ref; return self
            def tree(self): return self.ref

        class Dag:
            def git(self, url): return Git()
            def container(self): return Container()
            def cache_volume(self, name): return name

        fake = types.SimpleNamespace(dag=Dag(), function=lambda x: x, object_type=lambda x: x, Container=Container)
        module_spec = importlib.util.spec_from_file_location("mock_maskura_dagger", ROOT / "dagger/src/maskura/__init__.py")
        module = importlib.util.module_from_spec(module_spec)
        with patch.dict(sys.modules, {"dagger": fake}):
            module_spec.loader.exec_module(module)
        source = base64.b64encode((ROOT / "scripts/sqlite-guard.py").read_bytes()).decode()
        instance = module.Maskura()
        first = asyncio.run(instance.image("1" * 64, source, "safe-ref"))
        second = asyncio.run(instance.image("2" * 64, source, "safe-ref"))
        self.assertEqual(events, [])  # Dagger graphs are lazy until consumed.
        asyncio.run(first.sync())
        asyncio.run(second.sync())
        with self.assertRaisesRegex(RuntimeError, "remote SQLite graph"):
            asyncio.run(asyncio.run(instance.image("3" * 64, source, "sqlite-enabled")).sync())
        self.assertEqual(events, [("safe-ref", "1" * 64), ("safe-ref", "2" * 64), ("sqlite-enabled", "3" * 64)])
        with self.assertRaises(ValueError):
            asyncio.run(instance.image("invalid", source, "safe-ref"))
        asyncio.run(instance.publish("v0.0.0", "4" * 64, source, "safe-ref"))
        self.assertEqual(events[-3], ("safe-ref", "4" * 64))
        self.assertEqual([event[0] for event in events[-2:]], ["publish", "publish"])
        prior_publishes = sum(event[0] == "publish" for event in events)
        with self.assertRaisesRegex(RuntimeError, "remote SQLite graph"):
            asyncio.run(instance.publish("v0.0.0", "5" * 64, source, "sqlite-enabled"))
        self.assertEqual(sum(event[0] == "publish" for event in events), prior_publishes)
        with self.assertRaisesRegex(RuntimeError, "mock engine build failed"):
            asyncio.run(instance.publish("v0.0.0", "6" * 64, source, "engine-failed"))
        self.assertEqual(sum(event[0] == "publish" for event in events), prior_publishes)


if __name__ == "__main__":
    unittest.main()
