# SPDX-License-Identifier: Apache-2.0
"""Finite planner, always behind the native coordinator seccomp profile.

No Docker, host filesystem, process, socket, signal, FFI or privilege authority.
Imports are inert. The plan has no passwords, privileged paths or resource IDs.
"""
from __future__ import annotations

# Closed startup diagnostics, installed before any other import: an uncaught
# interpreter failure (including one raised during a later module import) emits
# exactly one allowlisted code on the protocol stream and never exception text,
# paths, arguments, plan contents or tracebacks.
STARTUP_CODES = ("arguments", "identity", "network", "plan", "request", "internal",
                 "interpreter")


def emit_startup(code):
    if code not in STARTUP_CODES:
        code = "internal"
    try:
        import sys
        sys.stdout.buffer.write(
            b'{"schema":1,"kind":"coordinator-startup","code":"' + code.encode("ascii") + b'"}\n')
        sys.stdout.buffer.flush()
    except BaseException:
        pass


def _startup_hook(_kind, _value, _traceback):
    emit_startup("interpreter")


if __name__ == "__main__":
    # Only the real script entry mutates interpreter state; test imports stay
    # inert. Every later import failure is still routed to the fixed frame.
    try:
        import sys
        sys.excepthook = _startup_hook
    except BaseException:
        pass

import argparse
import errno
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import sys
import time

CASES = ("http", "recovery-valid", "recovery-customer", "recovery-content-type", "recovery-encoding",
         "recovery-identity", "recovery-codec", "recovery-physical-key", "recovery-versioning", "repair-valid",
         "repair-source-mismatch", "tls-unrelated-ca", "tls-wrong-numeric-san")
CONTROLS = ("isolation-controls", "control-before-start", "control-descendant", "strict-provider",
            "deadline-contract", "python-mocks", "slow-peer")
PLAN = "/run/maskura/plan.json"
LIMIT = 8192


class Refused(Exception):
    pass


def need(condition):
    if not condition:
        raise Refused("coordinator-contract")


def decode(data):
    need(type(data) is bytes and 0 < len(data) <= LIMIT)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result)
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=unique, parse_constant=lambda _: need(False))
    except (ValueError, UnicodeError, RecursionError):
        raise Refused("coordinator-json") from None


def validate_plan(value, now):
    need(type(value) is dict and set(value) == {"schema", "campaign", "source_sha", "campaign_end", "cases"})
    need(type(value["schema"]) is int and value["schema"] == 1
         and type(value["campaign"]) is str and re.fullmatch(r"[0-9a-f]{32}", value["campaign"])
         and type(value["source_sha"]) is str and re.fullmatch(r"[0-9a-f]{40}", value["source_sha"])
         and type(value["campaign_end"]) in (int, float) and math.isfinite(value["campaign_end"])
         and 0 < value["campaign_end"] - now <= 3600
         and value["cases"] == list(CONTROLS + CASES))
    return value


def batches():
    return [(x,) for x in CONTROLS] + [CASES[i:i + 4] for i in range(0, len(CASES), 4)]


def request(plan, case, seq):
    need(case in CONTROLS + CASES and type(seq) is int and 1 <= seq <= 20)
    return dict(schema=1, kind="run-case", campaign=plan["campaign"], source_sha=plan["source_sha"], case=case, seq=seq)


def validate_status(value, plan, case, seq):
    expected = dict(schema=1, kind="case-status", campaign=plan["campaign"], source_sha=plan["source_sha"],
                    case=case, seq=seq, passed=True)
    need(type(value) is dict and set(value) == set(expected) and value == expected
         and all(type(value[key]) is type(item) for key, item in expected.items()))


def run(plan, incoming, outgoing, clock=time.monotonic):
    validate_plan(plan, clock())
    seq = 0
    for batch in batches():
        requests = []
        for case in batch:
            need(clock() < plan["campaign_end"] - 120)
            seq += 1
            frame = request(plan, case, seq)
            wire = json.dumps(frame, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            need(len(wire) <= LIMIT)
            outgoing.write(wire)
            outgoing.flush()
            requests.append((case, seq))
        for case, expected_seq in requests:
            need(clock() < plan["campaign_end"] - 120)
            wire = incoming.readline(LIMIT + 1)
            need(wire.endswith(b"\n"))
            validate_status(decode(wire), plan, case, expected_seq)
            need(clock() < plan["campaign_end"] - 120)
    return 0


def read_plan():
    fd = os.open(PLAN, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
             and stat.S_IMODE(before.st_mode) == 0o444 and before.st_size <= LIMIT)
        data = os.read(fd, LIMIT + 1)
        after = os.fstat(fd)
        need(len(data) == before.st_size and (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
        return decode(data)
    finally:
        os.close(fd)


def network_denials():
    """Actual seccomp controls, before the first request; never a route test."""
    for family, kind in ((socket.AF_INET, socket.SOCK_STREAM), (socket.AF_INET6, socket.SOCK_STREAM),
                         (socket.AF_UNIX, socket.SOCK_STREAM), (socket.AF_INET, socket.SOCK_DGRAM),
                         (socket.AF_INET, socket.SOCK_RAW)):
        try:
            connection = socket.socket(family, kind)
        except OSError as error:
            need(error.errno == errno.EPERM)
        else:
            connection.close()
            raise Refused("coordinator-network-not-denied")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, choices=[PLAN])
    try:
        parser.parse_args(argv)
    except SystemExit as error:
        if type(error.code) is int and error.code == 0:
            raise
        emit_startup("arguments")
        return 11
    phase = "identity"
    try:
        need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 20001 and os.getgroups() == [])
        phase = "network"
        network_denials()
        phase = "plan"
        plan = read_plan()
        phase = "request"
        return run(plan, sys.stdin.buffer, sys.stdout.buffer)
    except Exception:
        # Fixed phase code only; no raw exception, plan, path or environment value.
        emit_startup(phase)
        return {"identity": 12, "network": 13, "plan": 14, "request": 15}[phase]


if __name__ == "__main__":
    raise SystemExit(main())
