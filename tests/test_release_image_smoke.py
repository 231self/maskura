"""Synthetic harness controls; real packaged-image behavior is a separate CI job."""
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PHASES = ["protected_put", "local_put", "local_get", "local_restart_get", "local_override_put", "local_override_get"]

# No real daemon, credentials, bodies or external endpoints are used by these
# controls. The fake tools never forward arguments or credential fields to logs.
FAKE_TOOL = r'''
import os,pathlib,sys
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
state=pathlib.Path(os.environ["SMOKE_FAKE_STATE"])
count=int(state.read_text()) if state.exists() else 0
if name=="docker":
    if args[:1]==["run"] and args[-1]=="synthetic:fixture":
        state.write_text(str(count+1))
    elif args[:1]==["logs"] and count==2:
        print("generated local root credentials access_key=PUBLIC_ACCESS_TRAP secret_key=PUBLIC_SECRET_TRAP")
    elif args[:1]==["inspect"]:
        print("false" if count==2 and os.environ.get("SMOKE_FAIL_PHASE")=="local_ready" else "true")
elif name=="aws":
    if "list-buckets" in args: print("1")
    elif args[:2]==["s3","cp"]: print("contact [REDACTED_EMAIL] card [REDACTED_CARD]")
elif name=="curl":
    url=args[-1]
    if url.endswith(("/ready","/health")):
        sys.exit(22 if count==2 and os.environ.get("SMOKE_FAIL_PHASE")=="local_ready" else 0)
    if "-w" in args:
        print("403",end="")
        sys.exit(0)
    put="PUT" in args
    phase={1:"protected_put",2:"local_put" if put else "local_get",3:"local_restart_get",4:"local_override_put" if put else "local_override_get"}[count]
    if phase==os.environ.get("SMOKE_FAIL_PHASE"):
        print("curl: (22) The requested URL returned error: 403",file=sys.stderr)
        sys.exit(22)
    if not put: print("contact release-smoke@example.com card 4111111111111111",end="")
'''


class ReleaseSmokeTests(unittest.TestCase):
    def run_smoke(self, failure=None):
        with tempfile.TemporaryDirectory(prefix="release-smoke-harness-") as temporary:
            root = pathlib.Path(temporary)
            tools = root / "bin"
            tools.mkdir(mode=0o700)
            for name in ("docker", "aws", "curl"):
                path = tools / name
                path.write_text(f"#!{sys.executable}\n" + FAKE_TOOL)
                path.chmod(0o700)
            home = root / "home"
            home.mkdir(mode=0o700)
            environment = {
                "HOME": str(home), "TMPDIR": str(root),
                "PATH": str(tools) + ":/usr/bin:/bin",
                "SMOKE_FAKE_STATE": str(root / "gateway-count"),
            }
            if failure is not None:
                environment["SMOKE_FAIL_PHASE"] = failure
            return subprocess.run(
                ["/bin/bash", str(ROOT / "scripts/release-image-smoke.sh"), "synthetic:fixture"],
                cwd=root, env=environment, capture_output=True, text=True, timeout=20,
            )

    def test_success_exercises_every_phase_without_disclosing_credentials(self):
        result = self.run_smoke()
        self.assertEqual(result.returncode, 0, "synthetic smoke harness failed")
        self.assertEqual(re.findall(r"^smoke phase: (\w+)$", result.stdout, re.M), PHASES)
        for sentinel in ("PUBLIC_ACCESS_TRAP", "PUBLIC_SECRET_TRAP", "smoke-secret"):
            self.assertNotIn(sentinel, result.stdout + result.stderr)

    def test_every_request_failure_reports_only_its_static_phase_and_stops(self):
        for index, phase in enumerate(PHASES):
            with self.subTest(phase=phase):
                result = self.run_smoke(phase)
                self.assertEqual(result.returncode, 22)
                self.assertEqual(re.findall(r"^smoke phase: (\w+)$", result.stdout, re.M), PHASES[:index + 1])
                for sentinel in ("PUBLIC_ACCESS_TRAP", "PUBLIC_SECRET_TRAP", "smoke-secret"):
                    self.assertNotIn(sentinel, result.stdout + result.stderr)

    def test_readiness_failure_does_not_dump_generated_root_credentials(self):
        result = self.run_smoke("local_ready")
        self.assertEqual(result.returncode, 1)
        self.assertIn("zero-config gateway did not become ready", result.stderr)
        for sentinel in ("PUBLIC_ACCESS_TRAP", "PUBLIC_SECRET_TRAP"):
            self.assertNotIn(sentinel, result.stdout + result.stderr)

    def test_ci_requires_the_real_image_smoke_before_merge(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("  release-image-smoke:", workflow)
        release = (ROOT / ".github/workflows/release.yml").read_text()
        build = "cargo build --locked --release -p maskura-gateway -p maskura-mcp -p maskura"
        self.assertIn(build, workflow)
        self.assertIn(build, release)
        candidate = workflow.split("  release-image-smoke:", 1)[1].split("  postgres:", 1)[0]
        self.assertIn("runs-on: ${{ matrix.runs-on }}", candidate)
        for architecture, runner in (("amd64", "ubuntu-24.04"), ("arm64", "ubuntu-24.04-arm")):
            self.assertIn(
                f"- platform: linux/{architecture}\n"
                f"            suffix: {architecture}\n"
                f"            runs-on: {runner}\n",
                candidate,
            )
        self.assertIn("ARCH: ${{ matrix.suffix }}", candidate)
        self.assertIn('cp target/release/maskura-mcp "dist/maskura-mcp-linux-$ARCH"', candidate)
        self.assertIn('cp target/release/maskura "dist/maskura-linux-$ARCH"', candidate)
        self.assertIn('test "$(dist/maskura-linux-$ARCH --version)" = "$expected"', candidate)
        self.assertIn("file: Dockerfile.release", workflow)
        self.assertIn("bash scripts/release-image-smoke.sh", workflow)
        aggregate = workflow[workflow.index("  check:"):]
        self.assertIn("release-image-smoke", aggregate)
        script = (ROOT / "scripts/release-image-smoke.sh").read_text()
        self.assertIn('trap cleanup EXIT', script)
        self.assertIn('set -euo pipefail', script)


if __name__ == "__main__":
    unittest.main()
