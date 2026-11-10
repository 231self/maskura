#!/usr/bin/env python3
"""Fail closed before using the temporary, lockfile-only SQLite exception."""

import datetime as dt
import pathlib
import re
import subprocess
import sys
import tempfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPIRY = "2026-12-10T00:00:00Z"
ADVISORY = "RUSTSEC-2026-0459"
INSPECTION_TIMEOUT_SECONDS = 120
SHAPES = [
    ("workspace all features/all targets", ["--workspace", "--all-features", "--target", "all"], "maskura"),
    ("Linux x86_64 release", ["-p", "maskura-gateway", "-p", "maskura-mcp", "-p", "maskura", "--target", "x86_64-unknown-linux-gnu"], "maskura-gateway"),
    ("Linux arm64 release", ["-p", "maskura-gateway", "-p", "maskura-mcp", "-p", "maskura", "--target", "aarch64-unknown-linux-gnu"], "maskura-gateway"),
    ("macOS arm64 release", ["-p", "maskura-mcp", "-p", "maskura", "--target", "aarch64-apple-darwin"], "maskura-mcp"),
    ("WASI components", ["--workspace", "--target", "wasm32-wasip1"], "maskura"),
    ("bare Wasm components", ["--workspace", "--target", "wasm32-unknown-unknown"], "maskura"),
]
PACKAGE = re.compile(r"^([A-Za-z0-9_-]+) v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.+-]+)?(?: \([^\n]*\))?(?: \(\*\))?$")


class GuardError(Exception):
    pass


def validate_nonce(nonce):
    if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
        raise GuardError("missing or malformed builder freshness nonce")


def validate_time(now):
    try:
        expiry = dt.datetime.strptime(EXPIRY, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        approved = dt.datetime(2026, 11, 10, tzinfo=dt.timezone.utc)
        if now is None or now.utcoffset() != dt.timedelta(0) or not approved <= now < expiry:
            raise GuardError("exception expired or UTC clock invalid")
    except (ValueError, TypeError, OverflowError) as exc:
        raise GuardError("invalid exception expiry or UTC clock") from exc


def check(*, now, shapes=SHAPES):
    validate_time(now)
    for name, args, expected_root in shapes:
        command = ["cargo", "tree", "--locked", "--color", "never", "--prefix", "none", "--format", "{p}", *args]
        try:
            result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=INSPECTION_TIMEOUT_SECONDS)
        except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
            raise GuardError(f"{name}: cargo inspection failed") from exc
        if result.returncode != 0:
            raise GuardError(f"{name}: cargo inspection failed (exit {result.returncode})")
        # Cargo separates multiple workspace roots with empty lines.
        lines = [line for line in result.stdout.splitlines() if line != ""]
        packages = [PACKAGE.fullmatch(line) for line in lines]
        if not packages or any(match is None for match in packages):
            raise GuardError(f"{name}: empty or malformed cargo graph")
        names = {match.group(1) for match in packages}
        required_roots = {expected_root} | {args[i + 1] for i, arg in enumerate(args[:-1]) if arg == "-p"}
        if not required_roots <= names:
            raise GuardError(f"{name}: expected workspace root missing")
        if "libsqlite3-sys" in names or "sqlx-sqlite" in names:
            raise GuardError(f"{name}: SQLite dependency is active")
        print(f"SQLite guard: {name}: absent", flush=True)


def main():
    try:
        args = sys.argv[1:]
        if len(args) == 2 and args[0] == "--nonce":
            validate_nonce(args[1])
        elif args not in ([], ["deny"]):
            raise GuardError("usage: sqlite-guard.py [deny | --nonce NONCE]")
        check(now=dt.datetime.now(dt.timezone.utc))
        # Graph resolution can be slow: do not accept a check that crossed expiry.
        validate_time(dt.datetime.now(dt.timezone.utc))
        if sys.argv[1:] == ["deny"]:
            config = (ROOT / "deny.toml").read_text(encoding="utf-8")
            before = tomllib.loads(config)
            if ADVISORY in before["advisories"]["ignore"] or config.count("ignore = [") != 1:
                raise GuardError("unexpected deny policy; refusing to modify")
            amended = config.replace("ignore = [", f'ignore = [\n  "{ADVISORY}",', 1)
            after = tomllib.loads(amended)
            after["advisories"]["ignore"].remove(ADVISORY)
            if before != after:
                raise GuardError("temporary deny policy differs unexpectedly")
            with tempfile.TemporaryDirectory(prefix="maskura-deny-") as directory:
                path = pathlib.Path(directory) / "deny.toml"
                path.write_text(amended, encoding="utf-8")
                validate_time(dt.datetime.now(dt.timezone.utc))
                return subprocess.run(["cargo", "deny", "--locked", "--config", str(path), "check", "--hide-inclusion-graph"], cwd=ROOT, check=False).returncode
        return 0
    except (GuardError, OSError, UnicodeError, KeyError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"ERROR: SQLite exception guard: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
