#!/usr/bin/env python3
"""Owned test-only TLS bridge. Never use operator certificates or host trust.

The caller supplies an already-owned private case root and its owned Rust S3
fixture's allocated IPv4 loopback port. stdout is a single closed readiness
record; errors never include paths, URLs, certificates, bodies or credentials.
No certificate or network operation occurs on import.
"""

import argparse
import concurrent.futures
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import uuid

MAX_CONNECTIONS = 8
MAX_CONNECTION_BYTES = 96 * 1024 * 1024
CONNECTION_SECONDS = 25
LIFETIME_SECONDS = 180
STOP = threading.Event()
STARTUP_END = None


def exact_keys(value, names):
    require(isinstance(value, dict) and set(value) == set(names))


def decode_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique,
        parse_constant=lambda _value: require(False))


def private_bytes(path, limit=4096):
    require(path.is_absolute() and path.resolve(strict=True) == path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.geteuid()
                and stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_size <= limit)
        data = os.read(fd, limit + 1)
        require(len(data) == meta.st_size and len(data) <= limit)
        after = os.fstat(fd)
        require((meta.st_ino, meta.st_size, meta.st_mtime_ns) ==
                (after.st_ino, after.st_size, after.st_mtime_ns))
        return data
    finally:
        os.close(fd)


def atomic_record(path, value):
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    require(len(data) <= 4096)
    temporary = path.with_name(path.name + ".new-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def kernel_identity(pid):
    """Read ONLY the supplied, causally owned PID. No enumeration/name lookup.

    Caller owns the metadata barrier: self/direct child before registration, or
    an already captured identity afterwards. None means kernel ENOENT/ESRCH;
    permission, short records and malformed metadata are sticky failures.
    """
    require(type(pid) is int and pid > 1)
    if sys.platform == "darwin":
        class BsdInfo(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint32) for name in (
                "flags", "status", "xstatus", "pid", "ppid", "uid", "gid",
                "ruid", "rgid", "svuid", "svgid", "rfu")]
            _fields_ += [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
            _fields_ += [(name, ctypes.c_uint32) for name in ("nfiles", "pgid", "pjobc", "e_tdev", "e_tpgid")]
            _fields_ += [("nice", ctypes.c_int32), ("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64)]
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        query = library.proc_pidinfo
        query.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        query.restype = ctypes.c_int
        info = BsdInfo()
        ctypes.set_errno(0)
        count = query(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))  # PROC_PIDTBSDINFO
        if count <= 0 and ctypes.get_errno() in (errno.ESRCH, errno.ENOENT):
            return None
        require(count == ctypes.sizeof(info) and info.pid == pid and info.start_usec < 1000000)
        require(0 < info.status <= 7)
        return dict(pid=info.pid, ppid=info.ppid, pgid=info.pgid, uid=info.uid, alive=info.status != 5,
                    birth=dict(system="darwin", start_sec=info.start_sec,
                               start_subsec=info.start_usec, boot=None))
    require(sys.platform.startswith("linux"))
    # No broad /proc access. Exactly this known PID's public metadata and boot ID.
    path = Path("/proc") / str(pid) / "stat"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    try:
        meta = os.fstat(fd)
        data = os.read(fd, 4097)
        require(len(data) <= 4096)
    finally:
        os.close(fd)
    text = data.decode("ascii")
    end = text.rfind(")")
    require(end > 0 and text.split(" (", 1)[0] == str(pid))
    fields = text[end + 2:].split()
    require(len(fields) >= 20)
    boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    require(str(uuid.UUID(boot)) == boot)
    return dict(pid=pid, ppid=int(fields[1]), pgid=int(fields[2]), uid=meta.st_uid,
                alive=fields[0] not in ("Z", "X", "x"),
                birth=dict(system="linux", start_sec=0, start_subsec=int(fields[19]), boot=boot))


def validate_identity(value):
    exact_keys(value, ("pid", "ppid", "pgid", "uid", "alive", "birth"))
    require(all(type(value[name]) is int and value[name] >= 0 for name in ("pid", "ppid", "pgid", "uid")))
    require(value["pid"] > 1 and value["pgid"] > 1 and type(value["alive"]) is bool)
    birth = value["birth"]
    exact_keys(birth, ("system", "start_sec", "start_subsec", "boot"))
    require(birth["system"] in ("darwin", "linux")
            and type(birth["start_sec"]) is int and birth["start_sec"] >= 0
            and type(birth["start_subsec"]) is int and birth["start_subsec"] >= 0)
    if birth["system"] == "darwin":
        require(birth["start_subsec"] < 1000000 and birth["boot"] is None)
    else:
        require(isinstance(birth["boot"], str) and str(uuid.UUID(birth["boot"])) == birth["boot"])
    return value


def port_manifest(root, roles):
    data = private_bytes(root / "owned-ports.json", 1024)
    record = decode_json(data)
    exact_keys(record, ("schema", "case", "nonce", "host", "ports"))
    nonce = uuid.UUID(root.name[len("managed-release-case-"):])
    require(type(record["schema"]) is int and record["schema"] == 1
            and record["nonce"] == nonce.hex and record["host"] == "127.0.0.1"
            and isinstance(record["case"], str) and 1 <= len(record["case"]) <= 64)
    exact_keys(record["ports"], roles)
    ports = list(record["ports"].values())
    require(all(type(port) is int and 1024 <= port <= 65535 and port not in (5432, 54322) for port in ports)
            and len(set(ports)) == len(ports))
    return record, hashlib.sha256(data).hexdigest()


def wait_record(path, end):
    while time.monotonic() < end:
        try:
            value = decode_json(private_bytes(path))
            require(time.monotonic() < end)
            return value
        except FileNotFoundError:
            time.sleep(0.01)
    require(False)


def case_handoff(root, roles, end):
    parent = wait_record(root / "owned-case-parent.json", end)
    exact_keys(parent, ("schema", "case", "nonce", "root_uid", "test_identity"))
    require(type(parent["schema"]) is int and parent["schema"] == 1 and parent["root_uid"] == os.geteuid()
            and parent["test_identity"] == kernel_identity(os.getpid()) and parent["test_identity"]["alive"] is True)
    ports, ports_hash = port_manifest(root, roles)
    require((parent["case"], parent["nonce"]) == (ports["case"], ports["nonce"]))
    binding = dict(schema=1, case=ports["case"], nonce=ports["nonce"],
                   parent_sha256=hashlib.sha256(private_bytes(root / "owned-case-parent.json")).hexdigest(),
                   ports_sha256=ports_hash)
    require(time.monotonic() < end)
    atomic_record(root / "owned-case-ready.json", binding)
    require(wait_record(root / "owned-port-handoff.json", end) == binding)
    require(time.monotonic() < end)
    return ports, ports_hash


def startup_registration(root, ports_hash, end):
    require(time.monotonic() < end)
    parent = decode_json(private_bytes(root / "owned-case-parent.json"))
    exact_keys(parent, ("schema", "case", "nonce", "root_uid", "test_identity"))
    require(type(parent["schema"]) is int and parent["schema"] == 1 and parent["root_uid"] == os.geteuid())
    self_identity = validate_identity(kernel_identity(os.getpid()))
    test_identity = validate_identity(kernel_identity(os.getppid()))
    require(test_identity == parent["test_identity"] and self_identity["ppid"] == test_identity["pid"]
            and self_identity["pgid"] == self_identity["pid"]
            and self_identity["alive"] is True and test_identity["alive"] is True
            and self_identity["uid"] == test_identity["uid"] == os.geteuid())
    ports, actual_hash = port_manifest(root, ("provider", "tls", "gateway-1", "gateway-2", "gateway-3"))
    require(actual_hash == ports_hash and parent["case"] == ports["case"] and parent["nonce"] == ports["nonce"])
    # Private identity pipe only. No key/certificate/socket/subprocess before START.
    identity = dict(schema=2, kind="owned-managed-release-tls", case=ports["case"],
                    nonce=ports["nonce"], root_uid=os.geteuid(), ports_sha256=actual_hash,
                    test_identity=test_identity, tls_identity=self_identity)
    require(time.monotonic() < end)
    print(json.dumps(identity, sort_keys=True, separators=(",", ":")), flush=True)
    with selectors.DefaultSelector() as gate:
        gate.register(sys.stdin.buffer, selectors.EVENT_READ)
        remaining = end - time.monotonic()
        require(remaining > 0)
        require(gate.select(remaining))
        require(os.read(sys.stdin.buffer.fileno(), 16) == b"START\n")
        require(time.monotonic() < end)
    ledger = private_bytes(root / "owned-tls-group.json")
    require(decode_json(ledger) == identity)
    ack = decode_json(private_bytes(root / "owned-tls-ack.json"))
    exact_keys(ack, ("schema", "case", "nonce", "ledger_sha256"))
    require(type(ack["schema"]) is int and ack == dict(schema=1, case=identity["case"], nonce=identity["nonce"],
                         ledger_sha256=hashlib.sha256(ledger).hexdigest()))
    require(time.monotonic() < end)
    return ports


def record_tls_listener(root, ports, ports_hash, listener):
    address = listener.getsockname()
    require(address == ("127.0.0.1", ports["ports"]["tls"]))
    atomic_record(root / "owned-tls-listener.json", dict(schema=1, case=ports["case"],
        nonce=ports["nonce"], ports_sha256=ports_hash, host=address[0], port=address[1]))


def control_descendant(root, descriptor):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    with socket.socket(fileno=descriptor) as listener:
        ports, ports_hash = port_manifest(root, ("provider", "tls", "gateway-1", "gateway-2", "gateway-3"))
        require(listener.getsockname() == ("127.0.0.1", ports["ports"]["tls"]))
        atomic_record(root / "owned-control-descendant.json", dict(schema=1, case=ports["case"],
            nonce=ports["nonce"], ports_sha256=ports_hash,
            identity=kernel_identity(os.getpid())))
        # Finite synthetic child; outer must use its captured group, never a name.
        time.sleep(60)
    return 0


class RelayWriteError(OSError):
    """Closed fixture failure, never a product rejection or recoverable read."""


def record_write_failure(folder):
    path = folder / "relay-write-failed"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        return
    except OSError:
        os._exit(70)  # fail closed; outer owned-group guardian still applies
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(b"MANAGED_RELAY_WRITE_FAILED\n")
            output.flush()
            os.fsync(output.fileno())
    except OSError:
        os._exit(70)


def require(condition):
    if not condition:
        raise RuntimeError("owned TLS fixture contract failed")


def owned_root(value):
    path = Path(value)
    require(path.is_absolute() and path.resolve(strict=True) == path)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid())
    require(info.st_mode & 0o077 == 0)
    require(path.name.startswith("managed-release-case-") and len(path.name) == 57)
    require(path.name == "managed-release-case-" + str(uuid.UUID(path.name[21:])))
    return path


def mint(root, mode):
    require(STARTUP_END is not None and time.monotonic() < STARTUP_END)
    # All keys below are fresh synthetic test keys, never repository PEMs.
    folder = root / "tls"
    folder.mkdir(mode=0o700)
    config = folder / "openssl.cnf"
    config.write_text(
        "[req]\nprompt=no\ndistinguished_name=dn\n"
        "[dn]\nCN=Owned Managed Release Test\n"
        "[ca]\nbasicConstraints=critical,CA:TRUE\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        "[server]\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
        + ("subjectAltName=IP:127.0.0.2\n" if mode == "wrong-name"
         else "subjectAltName=IP:127.0.0.1\n"),
        encoding="ascii",
    )
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(root / "home"),
        "TMPDIR": str(root / "tmp"),
        "OPENSSL_CONF": str(config),
    }

    def openssl(*args):
        require(STARTUP_END is not None and time.monotonic() < STARTUP_END)
        subprocess.run(
            ["/usr/bin/openssl", *args],
            cwd=folder,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=min(10, max(0.001, STARTUP_END - time.monotonic())),
        )

    openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ca.key")
    openssl("req", "-new", "-x509", "-sha256", "-days", "1", "-set_serial", "1",
            "-key", "ca.key", "-out", "ca.pem", "-config", str(config), "-extensions", "ca")
    openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "server.key")
    openssl("req", "-new", "-sha256", "-key", "server.key", "-out", "server.csr",
            "-config", str(config))
    openssl("x509", "-req", "-sha256", "-days", "1", "-set_serial", "2",
            "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
            "-out", "server.pem", "-extfile", str(config), "-extensions", "server")
    if mode == "unrelated-ca":
        unrelated = folder / "unrelated.cnf"
        unrelated.write_text(config.read_text(encoding="ascii").replace(
            "CN=Owned Managed Release Test", "CN=Unrelated Owned Managed Release Test"),
            encoding="ascii")
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "unrelated.key")
        openssl("req", "-new", "-x509", "-sha256", "-days", "1", "-set_serial", "3",
                "-key", "unrelated.key", "-out", "unrelated.pem", "-config", str(unrelated),
                "-extensions", "ca")
    return folder


def tls_context(folder):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain(folder / "server.pem", folder / "server.key")

    def sni_guard(_connection, name, _context):
        # wrong.invalid exists solely to test CLIENT hostname rejection. It
        # must not be rejected here, or that control would prove the wrong thing.
        if name not in (None, "localhost", "wrong.invalid"):
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        return None

    context.set_servername_callback(sni_guard)
    return context


def pump(tls_socket, upstream):
    # A bounded duplex relay preserves HTTP framing and SDK requests verbatim.
    sockets = (tls_socket, upstream)
    end = time.monotonic() + CONNECTION_SECONDS
    total = 0
    with selectors.DefaultSelector() as selector:
        for connection in sockets:
            connection.settimeout(1)
            selector.register(connection, selectors.EVENT_READ)
        while not STOP.is_set() and time.monotonic() < end:
            # SSL can have buffered plaintext while the fd is not readable.
            ready = [(None, None)] if tls_socket.pending() else selector.select(0.25)
            for key, _events in ready:
                source = tls_socket if key is None else key.fileobj
                target = upstream if source is tls_socket else tls_socket
                try:
                    data = source.recv(64 * 1024)
                except (socket.timeout, ssl.SSLWantReadError):
                    continue
                if not data:
                    return
                total += len(data)
                require(total <= MAX_CONNECTION_BYTES)
                # sendall may have emitted an unknown prefix before failing.
                # NEVER retry as though it were recv readiness: that would drop
                # the remainder and receive/reorder the next chunk. Tear down
                # both directions and classify this as an owned fixture failure.
                try:
                    target.sendall(data)
                except (OSError, ssl.SSLError) as error:
                    raise RelayWriteError("owned relay write failed") from error


def serve_connection(connection, context, upstream_port, on_write_failure=None):
    try:
        connection.settimeout(3)
        with context.wrap_socket(connection, server_side=True) as secure:
            # Fixed numeric endpoint only: no URL parsing, DNS, redirects or
            # client-selected upstream addresses, even for Host/CONNECT requests.
            with socket.create_connection(("127.0.0.1", upstream_port), timeout=3) as upstream:
                pump(secure, upstream)
    except RelayWriteError:
        if on_write_failure is not None:
            on_write_failure()
    except (OSError, ssl.SSLError, RuntimeError):
        pass
    finally:
        connection.close()


def trust_controls(port, folder, mode):
    trusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    trusted.minimum_version = ssl.TLSVersion.TLSv1_2
    trusted.load_verify_locations(cafile=folder / "ca.pem")
    require(trusted.check_hostname and trusted.verify_mode == ssl.CERT_REQUIRED)
    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
        # Same reachable TCP listener in every mode. Only the verifier's
        # reference name differs in this Python preflight, never DNS or bind.
        with trusted.wrap_socket(raw, server_hostname=(
                "127.0.0.2" if mode == "wrong-name" else "127.0.0.1")):
            pass
    untrusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    require(untrusted.check_hostname and untrusted.verify_mode == ssl.CERT_REQUIRED)
    for context, name, wrong_name in (
        (untrusted, "127.0.0.1", False),
        (trusted, "wrong.invalid", True),
    ):
        rejected = False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
                with context.wrap_socket(raw, server_hostname=name):
                    pass
        except ssl.SSLCertVerificationError as error:
            rejected = True
            if wrong_name:
                require(error.verify_code in (62, 64))
        require(rejected)


def main():
    global STARTUP_END
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--mode", default="trusted", choices=("trusted", "unrelated-ca", "wrong-name"))
    parser.add_argument("--startup-millis", type=int)
    parser.add_argument("--owned-control", choices=("early-main-exit", "live-descendant"))
    parser.add_argument("--control-descendant-fd", type=int)
    args = parser.parse_args()
    os.umask(0o077)
    root = owned_root(args.root)
    if args.control_descendant_fd is not None:
        require(args.control_descendant_fd >= 3 and args.owned_control is None)
        return control_descendant(root, args.control_descendant_fd)
    require(type(args.startup_millis) is int and 0 < args.startup_millis <= 40000)
    STARTUP_END = time.monotonic() + args.startup_millis / 1000
    ports, ports_hash = port_manifest(root, ("provider", "tls", "gateway-1", "gateway-2", "gateway-3"))
    startup_registration(root, ports_hash, STARTUP_END)
    # START is only sent AFTER the independently kernel-validated outer ACK.
    # No listener/subprocess has existed before this point.
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, lambda _number, _frame: STOP.set())
    require(time.monotonic() < STARTUP_END)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        require(time.monotonic() < STARTUP_END)
        listener.bind(("127.0.0.1", ports["ports"]["tls"]))
        listener.listen(MAX_CONNECTIONS)
        listener.settimeout(0.25)
        record_tls_listener(root, ports, ports_hash, listener)
        if args.owned_control is not None:
            require(args.owned_control == "live-descendant")  # early-main-exit never gets START
            require(time.monotonic() < STARTUP_END)
            child = subprocess.Popen([sys.executable, "-B", "-I", str(Path(__file__).resolve()),
                "--root", str(root), "--control-descendant-fd", str(listener.fileno())],
                pass_fds=(listener.fileno(),), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "HOME": str(root / "home"), "TMPDIR": str(root / "tmp")})
            # Same captured group, synthetic finite child; no TLS/PG claim.
            record = wait_record(root / "owned-control-descendant.json", STARTUP_END)
            exact_keys(record, ("schema", "case", "nonce", "ports_sha256", "identity"))
            require(record["identity"]["pid"] == child.pid and record["ports_sha256"] == ports_hash)
            print("MANAGED_TLS_CONTROL_READY", flush=True)
            exit_gate = wait_record(root / "owned-control-exit.json", STARTUP_END)
            require(exit_gate == dict(schema=1, case=ports["case"], nonce=ports["nonce"], ports_sha256=ports_hash))
            os._exit(73)  # deliberately retain descendant + listener for the outer oracle
        # Bind collision has already failed BEFORE keys, TLS precontrols/clients.
        require(time.monotonic() < STARTUP_END)
        folder = mint(root, args.mode)
        context = tls_context(folder)
        port = listener.getsockname()[1]
        slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

        def accept_loop():
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONNECTIONS) as workers:
                while not STOP.is_set():
                    try:
                        connection, peer = listener.accept()
                    except socket.timeout:
                        continue
                    require(peer[0] == "127.0.0.1")
                    if not slots.acquire(blocking=False):
                        connection.close()
                        continue

                    def run(connection=connection):
                        try:
                            serve_connection(connection, context, ports["ports"]["provider"],
                                             lambda: record_write_failure(folder))
                        finally:
                            slots.release()

                    workers.submit(run)

        worker = threading.Thread(target=accept_loop)
        worker.start()
        try:
            trust_controls(port, folder, args.mode)
            print(f"MANAGED_TLS_READY {port} TRUST_CONTROLS_3 {args.mode}", flush=True)
            # Parent death closes the private pipe; no process/name polling.
            threading.Thread(target=lambda: (sys.stdin.buffer.read(1), STOP.set()), daemon=True).start()
            STOP.wait(LIFETIME_SECONDS)
        finally:
            STOP.set()
            worker.join(timeout=CONNECTION_SECONDS + 5)
            require(not worker.is_alive())


if __name__ == "__main__":
    try:
        main()
    except Exception:
        STOP.set()
        print("MANAGED_TLS_FAILED", file=sys.stderr, flush=True)
        sys.exit(1)
