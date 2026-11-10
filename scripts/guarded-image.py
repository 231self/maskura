#!/usr/bin/env python3
"""Supported host entrypoint: uncached preflight and fresh engine nonce."""

import argparse
import base64
import pathlib
import re
import secrets
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="engine", required=True)
    docker = sub.add_parser("docker")
    docker.add_argument("--tag", required=True)
    sub.add_parser("compose")
    dagger = sub.add_parser("dagger")
    dagger.add_argument("--action", choices=("ci", "image", "publish"), required=True)
    dagger.add_argument("--ref", default="main")
    dagger.add_argument("--tag")
    args = parser.parse_args(argv)
    if args.engine == "dagger" and ((args.action == "publish") != (args.tag is not None)):
        parser.error("--tag is required only for dagger publish")
    try:
        result = subprocess.run([sys.executable, str(ROOT / "scripts/sqlite-guard.py")], cwd=ROOT, check=False)
        if result.returncode:
            return result.returncode
        nonce = secrets.token_hex(32)
        if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
            raise ValueError("invalid generated freshness nonce")
        if args.engine == "docker":
            command = ["docker", "build", "--file", "Dockerfile", "--tag", args.tag, "--build-arg", f"MASKURA_GUARD_NONCE={nonce}", "."]
        elif args.engine == "compose":
            command = ["docker", "compose", "-f", "local/docker-compose.yml", "build", "--build-arg", f"MASKURA_GUARD_NONCE={nonce}", "gateway"]
        else:
            source = base64.b64encode((ROOT / "scripts/sqlite-guard.py").read_bytes()).decode("ascii")
            command = ["dagger", "call", args.action, "--ref", args.ref, "--guard-nonce", nonce, "--guard-source-b64", source]
            if args.tag is not None:
                command += ["--tag", args.tag]
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode or args.engine != "compose":
            return result.returncode
        result = subprocess.run([sys.executable, str(ROOT / "scripts/sqlite-guard.py")], cwd=ROOT, check=False)
        if result.returncode:
            return result.returncode
        return subprocess.run(["docker", "compose", "-f", "local/docker-compose.yml", "up", "-d", "--no-build", "--wait", "s3", "gateway"], cwd=ROOT, check=False).returncode
    except (OSError, ValueError) as exc:
        print(f"error: guarded image invocation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
