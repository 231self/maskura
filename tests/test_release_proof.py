"""Synthetic proof-harness controls; only CI's real image qualifies behavior."""
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FAKE = r'''
import hashlib,json,os,pathlib,sys
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
state=pathlib.Path(os.environ["PROOF_TEST_STATE"])
def event(value):
    with state.open("a") as f: f.write(value+"\n")
if name=="python3":
    if args and args[0].endswith("python-hybrid-roundtrip.py"):
        event("python-proof")
        print("PASS  synthetic python proof")
    else:
        os.execv(sys.executable,[sys.executable]+args)
elif name=="docker":
    if args[:2]==["image","inspect"]: sys.exit(0)
    if args[:1]==["pull"]: event("pull")
    elif args[:1]==["run"]:
        required=("MASKURA_TRANSFORMED_READ_SPOOL=encrypted", "MASKURA_SPOOL_DIR=/data/proof-spool", "MASKURA_SPOOL_MAX_OBJECT_BYTES=1048576", "MASKURA_SPOOL_QUOTA_BYTES=4194304", "MASKURA_SECRET_KEK")
        if not all(x in args for x in required): sys.exit(41)
        if not os.environ.get("MASKURA_SECRET_KEK"): sys.exit(42)
        event("run")
    elif args[:1]==["logs"]: print("SECRET_OUTPUT_TRAP")
    elif args[:1]==["cp"]:
        source=args[1]
        if "/metadata/" in source:
            paths=["proof/redaction.txt","proof/plugin.txt","proof/python-hybrid.txt"]
            match=[p for p in paths if hashlib.sha256(p.encode()).hexdigest()+".json" in source]
            if len(match)!=1: sys.exit(47)
            index=paths.index(match[0])+1
            name=f"00000000-0000-0000-0000-{index:012d}.data"
            pathlib.Path(args[-1]).write_text(json.dumps({"key":match[0],"data_file":name}))
        elif "/objects/" in source:
            if "000000000001.data" in source: value="[REDACTED_EMAIL] [REDACTED_CARD]"
            elif "000000000002.data" in source: value="[REDACTED_EMAIL] 4111111111111111"
            else: value='{"alg":"X25519+ML-KEM-768/AES-256-GCM"}'
            if os.environ.get("PROOF_FAIL")=="stored-plaintext": value="jane@example.com 4111111111111111"
            pathlib.Path(args[-1]).write_text(value)
            event("stored")
        else: pathlib.Path(args[-1]).write_bytes(b"component")
    elif args[:1]==["rm"]:
        event("container-cleanup")
        if os.environ.get("PROOF_FAIL")=="cleanup": sys.exit(48)
    elif args[:2]==["volume","rm"]: event("volume-cleanup")
elif name=="curl":
    if args[-1].endswith("/health") and os.environ.get("PROOF_FAIL")=="health":
        sys.exit(22)
    if args[-1].endswith("/dashboard/api/plugins") and "POST" not in args:
        print('[{"id":"p1","name":"pii-default"},{"id":"p2","name":"envelope-encrypt"}]')
    elif "POST" in args:
        print('{"name":"proof-email-only","enabled":true}')
elif name=="aws":
    if args[:1]==["s3"] and "cp" in args:
        if args[args.index("cp")+1].startswith("s3://"): sys.exit(44)
        event("put")
    elif args[:1]==["s3api"] and "head-object" in args:
        event("head")
        if os.environ.get("PROOF_FAIL")=="head-accepted": sys.exit(0)
        print("An error occurred (400) when calling the HeadObject operation: Bad Request",file=sys.stderr)
        sys.exit(255)
    elif args[:1]==["s3api"] and "get-object" in args:
        event("get")
        if os.environ.get("PROOF_FAIL")=="get": sys.exit(45)
        key=args[args.index("--key")+1]
        content="[REDACTED_EMAIL] [REDACTED_CARD]" if key.endswith("redaction.txt") else "[REDACTED_EMAIL] 4111111111111111"
        pathlib.Path(args[-1]).write_text(content)
        print("BODY_OUTPUT_TRAP")
    else: sys.exit(46)
'''


class ReleaseProofTests(unittest.TestCase):
    def run_proof(self, fail=None, legacy_get=False):
        with tempfile.TemporaryDirectory(prefix="release-proof-control-") as temporary:
            root = pathlib.Path(temporary)
            tools = root / "bin"
            tools.mkdir(mode=0o700)
            for name in ("docker", "aws", "curl", "python3", "sleep"):
                path = tools / name
                path.write_text(f"#!{sys.executable}\n" + FAKE)
                path.chmod(0o700)
            home = root / "home"
            home.mkdir(mode=0o700)
            state = root / "events"
            env = {"HOME": str(home), "TMPDIR": str(root), "PATH": str(tools) + ":/usr/bin:/bin",
                   "PROOF_TEST_STATE": str(state), "MASKURA_PROOF_IMAGE": "fixture:local",
                   "MASKURA_PROOF_IMAGE_LOCAL": "1"}
            if fail:
                env["PROOF_FAIL"] = fail
            script = ROOT / "examples/prove-maskura.sh"
            if legacy_get:
                source = script.read_text()
                old = 'aws s3api --endpoint-url "$ENDPOINT" \\\n    get-object --bucket maskura --key "$key" "$destination" >/dev/null'
                new = 'aws s3 --endpoint-url "$ENDPOINT" \\\n    cp "s3://maskura/$key" -'
                assert source.count(old) == 1
                script = root / "legacy-proof.sh"
                script.write_text(source.replace(old, new))
            result = subprocess.run(["/bin/bash", str(script)],
                                    cwd=root, env=env, capture_output=True, text=True, timeout=30)
            events = state.read_text().splitlines() if state.exists() else []
            return result, events

    def test_proof_uses_direct_get_spool_and_all_claims(self):
        result, events = self.run_proof()
        self.assertEqual(result.returncode, 0, "synthetic proof should succeed")
        self.assertEqual(events.count("get"), 2)
        self.assertIn("head", events)
        self.assertIn("python-proof", events)
        self.assertEqual(events.count("stored"), 3)
        self.assertNotIn("pull", events)
        self.assertIn("container-cleanup", events)
        self.assertIn("volume-cleanup", events)
        self.assertNotIn("BODY_OUTPUT_TRAP", result.stdout + result.stderr)
        self.assertNotIn("SECRET_OUTPUT_TRAP", result.stdout + result.stderr)

    def test_head_must_deny_and_get_failure_stops_and_cleans(self):
        for failure in ("head-accepted", "get"):
            with self.subTest(failure=failure):
                result, events = self.run_proof(failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("head" if failure == "head-accepted" else "get", events)
                self.assertNotIn("python-proof", events)
                self.assertIn("container-cleanup", events)
                self.assertIn("volume-cleanup", events)
                self.assertNotIn("BODY_OUTPUT_TRAP", result.stdout + result.stderr)

    def test_legacy_high_level_download_is_detected(self):
        result, events = self.run_proof(legacy_get=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("head", events)
        self.assertNotIn("get", events)
        self.assertNotIn("python-proof", events)
        self.assertIn("volume-cleanup", events)

    def test_cleanup_failure_is_not_a_success(self):
        result, events = self.run_proof("cleanup")
        self.assertIn("python-proof", events)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("volume-cleanup", events)

    def test_plaintext_stored_bytes_fail_even_when_get_would_be_redacted(self):
        result, events = self.run_proof("stored-plaintext")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stored", events)
        self.assertNotIn("get", events)
        self.assertNotIn("python-proof", events)
        self.assertIn("container-cleanup", events)
        self.assertNotIn("jane@example.com", result.stdout + result.stderr)

    def test_readiness_failure_does_not_dump_container_output(self):
        result, events = self.run_proof("health")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("container-cleanup", events)
        self.assertIn("volume-cleanup", events)
        self.assertNotIn("SECRET_OUTPUT_TRAP", result.stdout + result.stderr)

    def test_required_ci_runs_same_real_final_proof(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        release = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("bash examples/prove-maskura.sh", ci)
        self.assertIn("bash examples/prove-maskura.sh", release)
        self.assertIn("MASKURA_PROOF_IMAGE_LOCAL", ci)
        self.assertIn("release-image-smoke", ci[ci.index("  check:"):])


if __name__ == "__main__":
    unittest.main()
