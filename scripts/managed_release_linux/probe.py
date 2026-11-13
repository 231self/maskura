#!/usr/bin/env python3
"""Explicit product-guard child controls. Never execute during import/discovery."""
from __future__ import annotations

import argparse
import errno
import fcntl
import os
from pathlib import Path
import socket
import stat
import sys

if __package__:
    from . import protocol as P
elif __name__ == "__main__":
    # -I does not add the script directory. This sole immutable location is
    # installed by the reviewed rootfs, not supplied by a descriptor or env.
    sys.path.insert(0, "/opt")
    from managed_release_linux import protocol as P


def denied(action, allowed=(errno.EPERM,)):
    """Refusal, no route, ENOENT, timeout and EBADF are not policy denials."""
    try:
        result = action()
        if hasattr(result, "close"):
            result.close()
    except OSError as error:
        P.need(error.errno in allowed, "probe-denial-errno")
        return True
    raise P.ContractError("probe-not-denied")


def connect(port, host="127.0.0.1"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(1)
        connection.connect((host, port))


def bind(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", port))


def privileged_call(name, *args):
    # Runtime only. No FFI library is loaded by imports or local unit tests.
    import ctypes
    library = ctypes.CDLL(None, use_errno=True)
    function = getattr(library, name)
    function.restype = ctypes.c_long if name == "ptrace" else ctypes.c_int
    ctypes.set_errno(0)
    result = function(*args)
    if result == -1:
        raise OSError(ctypes.get_errno(), "probe-syscall")
    return result


def status_fields():
    with open("/proc/self/status", "r", encoding="ascii") as stream:
        text = stream.read(16385)
    P.need(len(text) <= 16384, "probe-status-size")
    names = ("CapEff", "CapPrm", "CapInh", "CapAmb", "NoNewPrivs", "Seccomp")
    result = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator and key in names:
            P.need(key not in result, "probe-status-duplicate")
            result[key] = value.strip()
    P.exact(result, names)
    return result


def check_fds():
    """Inspect only descriptor numbers, never FD targets or their contents."""
    P.need(stat.S_ISCHR(os.fstat(0).st_mode)
           and all(stat.S_ISFIFO(os.fstat(fd).st_mode) for fd in (1, 2)), "probe-standard-fds")
    # listdir's own temporary directory FD may appear, but must be closed when
    # checked. Do not cap inspection at 1024 and miss a high-numbered leak.
    entries = os.listdir("/proc/self/fd")
    P.need(len(entries) <= 4096, "probe-fd-count")
    for entry in entries:
        P.need(entry.isascii() and entry.isdecimal(), "probe-fd-name")
        descriptor = int(entry)
        if descriptor < 3:
            continue
        try:
            fcntl.fcntl(descriptor, fcntl.F_GETFD)
        except OSError as error:
            P.need(error.errno == errno.EBADF, "probe-fd-error")
        else:
            raise P.ContractError("probe-inherited-fd")


def run(contract):
    P.exact(contract, ("schema", "root", "uid", "gid", "loopback_port", "denied_port"))
    P.need(type(contract["schema"]) is int and contract["schema"] == 1
           and type(contract["uid"]) is int and type(contract["gid"]) is int
           and contract["uid"] == contract["gid"] == 20001, "probe-contract")
    root = Path(P.absolute_path(contract["root"]))
    P.need(root.resolve(strict=True) == root, "probe-root")
    meta = root.stat()
    P.need(stat.S_ISDIR(meta.st_mode) and stat.S_IMODE(meta.st_mode) == 0o700
           and meta.st_uid == contract["uid"], "probe-root-metadata")
    port = contract["loopback_port"]
    P.need(port is None or P.valid_port(port), "probe-positive-port")
    P.need(P.valid_port(contract["denied_port"]) and contract["denied_port"] != port,
           "probe-negative-port")
    results = {key: False for key in P.PROBE_FIELDS}
    P.need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 20001
           and os.getgroups() == [], "probe-identity")
    results["identity"] = True
    positive = root / "tmp/probe-positive"
    fd = os.open(positive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(b"owned-positive\n")
    with positive.open("rb") as stream:
        P.need(stream.read(32) == b"owned-positive\n", "probe-file-positive")
    positive.unlink()
    results["owned_file"] = True
    if port is not None:
        connect(port)
        results["owned_loopback"] = True
    protected = Path("/run/maskura/protected")

    def read_file(path):
        with path.open("rb") as stream:
            stream.read(1)

    def write_file():
        fd = os.open(protected / "write-canary", os.O_WRONLY | os.O_NOFOLLOW)
        os.close(fd)  # never mutate/truncate the canary even on broken isolation

    results["forbidden_read"] = denied(lambda: read_file(protected / "read-canary"), (errno.EACCES, errno.EPERM))
    results["forbidden_write"] = denied(write_file, (errno.EACCES, errno.EPERM))
    results["sibling_read"] = denied(lambda: read_file(protected / "sibling-canary"), (errno.EACCES, errno.EPERM))
    results["external_network"] = denied(lambda: connect(443, "192.0.2.1"))
    for name, destination in (("undeclared_port", contract["denied_port"]),
                              ("default_5432", 5432), ("default_54322", 54322)):
        results[name] = denied(lambda: connect(destination)) and denied(lambda: bind(destination))
    results["ipv6"] = denied(lambda: socket.socket(socket.AF_INET6, socket.SOCK_STREAM))
    results["raw_socket"] = denied(lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP))
    results["ptrace"] = denied(lambda: privileged_call("ptrace", 16, 1, 0, 0))
    results["setns"] = denied(lambda: privileged_call("setns", -1, 0))
    status = status_fields()
    P.need(all(int(status[key], 16) == 0 for key in ("CapEff", "CapPrm", "CapInh", "CapAmb")),
           "probe-capabilities")
    results["capabilities"] = True
    P.need(status["NoNewPrivs"] == "1" and status["Seccomp"] == "2", "probe-seccomp")
    results["no_new_privs"] = True
    # stdin is /dev/null, stdout/stderr are fresh output pipes, never warden FDs.
    check_fds()
    results["standard_fds"] = True
    results["no_extra_fds"] = True
    return dict(kind="isolation-probe", passed=True, results=results)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args(argv)
    try:
        P.need(P.hash_text(args.sha256), "probe-contract-hash")
        data = P.read_private_bytes(args.contract, 20001, 4096)
        P.need(P.sha(data) == args.sha256, "probe-contract-binding")
        record = run(P.decode_json(data, 4096))
        sys.stdout.buffer.write(P.encode_json(record) + b"\n")
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        # Never serialize raw exception text, denied paths or the contract.
        sys.stdout.buffer.write(b'{"kind":"isolation-probe","passed":false}\n')
        sys.stdout.buffer.flush()
        return 1


if __name__ == "__main__":
    sys.exit(main())
