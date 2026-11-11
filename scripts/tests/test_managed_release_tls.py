"""Socket-free mocks by default; real slow-peer control is EXPLICIT opt-in.

Import/unittest discovery never mints certificates, opens sockets, or launches
commands. The --owned-slow-peer-root mode is authored for LATER owned execution.
It is not part of the mock result and must not be reported as already passed.
"""
import ast
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import threading
import time
import types
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "owned_managed_release_tls", Path(__file__).with_name("managed_release_tls.py"))
tls = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tls)  # definitions/imports ONLY; main is guarded


class FakePeer:
    def __init__(self, reads=(), fail_write=None):
        self.reads = list(reads)
        self.fail_write = fail_write
        self.recv_count = 0
        self.send_count = 0
        self.sent = bytearray()
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def close(self):
        self.closed = True

    def settimeout(self, _seconds):
        pass

    def pending(self):
        return 0

    def recv(self, _size):
        self.recv_count += 1
        item = self.reads.pop(0) if self.reads else b""
        if isinstance(item, BaseException):
            raise item
        return item

    def sendall(self, data):
        self.send_count += 1
        if self.fail_write is not None:
            # Emulate a timeout/error AFTER an unknown prefix was transmitted.
            self.sent.extend(data[:5])
            raise self.fail_write
        self.sent.extend(data)


class FakeSelector:
    def __init__(self, source):
        self.source = source
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True

    def register(self, *_args):
        pass

    def select(self, _timeout):
        return [(types.SimpleNamespace(fileobj=self.source), None)]


class TestSocketFreeRelay(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        tls.STOP.clear()
        self.addCleanup(tls.STOP.clear)
        # Hard tripwires: even an accidental code-path change cannot make these
        # default tests open a real socket, construct TLS, or invoke openssl.
        for owner, name in [(tls.socket, "socket"), (tls.socket, "create_connection"),
                            (tls.ssl, "SSLContext"), (tls.subprocess, "run"), (tls, "mint")]:
            self.stack.enter_context(mock.patch.object(owner, name,
                side_effect=AssertionError("mock control attempted real external access")))
        tick = iter(range(1000))
        self.stack.enter_context(mock.patch.object(tls.time, "monotonic", side_effect=lambda: next(tick) / 10))

    def run_relay(self, direction, error=None, read_waits=False):
        payloads = [b"first-frame-is-not-complete", b"next-frame-must-not-follow-a-failed-write", b""]
        reads = ([tls.socket.timeout(), tls.ssl.SSLWantReadError()] if read_waits else []) + payloads
        source = FakePeer(reads)
        target = FakePeer(fail_write=error)
        secure, upstream = (source, target) if direction == "to-provider" else (target, source)
        raw = FakePeer()
        selector = FakeSelector(source)
        context = types.SimpleNamespace(wrap_socket=lambda *_args, **_kwargs: secure)
        failed = mock.Mock()
        with mock.patch.object(tls.socket, "create_connection", return_value=upstream), \
                mock.patch.object(tls.selectors, "DefaultSelector", return_value=selector):
            tls.serve_connection(raw, context, 12345, failed)
        self.assertTrue(raw.closed and secure.closed and upstream.closed and selector.closed)
        if error is not None:
            self.assertEqual(source.recv_count, 1, "relay read a new chunk after a partial write failure")
            self.assertEqual(target.send_count, 1)
            self.assertEqual(bytes(target.sent), payloads[0][:5])
            failed.assert_called_once_with()  # classified as FIXTURE failure
        else:
            self.assertEqual(bytes(target.sent), payloads[0] + payloads[1])
            self.assertEqual(source.recv_count, 5 if read_waits else 3)
            failed.assert_not_called()

    def test_partial_send_timeout_closes_both_directions(self):
        for direction in ("to-provider", "to-client"):
            with self.subTest(direction=direction):
                self.run_relay(direction, tls.socket.timeout())

    def test_partial_send_error_closes_both_directions(self):
        for direction in ("to-provider", "to-client"):
            with self.subTest(direction=direction):
                self.run_relay(direction, BrokenPipeError())

    def test_recv_wait_retries_preserve_order_and_complete_payload(self):
        for direction in ("to-provider", "to-client"):
            with self.subTest(direction=direction):
                self.run_relay(direction, read_waits=True)

    def test_real_counted_tls_delegates_selector_fileno(self):
        # Compile ONLY the actual nested instrumentation class, never the
        # network/mint function containing it. Exercise selectors' descriptor
        # protocol conversion without registering an actual OS descriptor.
        syntax = ast.parse(Path(__file__).read_text())
        slow_peer = next(node for node in syntax.body
            if isinstance(node, ast.FunctionDef) and node.name == "run_owned_slow_peer")
        counted = next(node for node in slow_peer.body
            if isinstance(node, ast.ClassDef) and node.name == "CountedTls")
        namespace = {"state": {"reads": 0}}
        exec(compile(ast.Module(body=[counted], type_ignores=[]),
            "<owned-real-CountedTls-protocol>", "exec"), namespace)
        connection = types.SimpleNamespace(fileno=mock.Mock(return_value=17))
        wrapped = namespace["CountedTls"](connection)
        self.assertEqual(tls.selectors._fileobj_to_fd(wrapped), 17)
        connection.fileno.assert_called_once_with()
        # Sensitivity control: the original missing-delegation class must fail
        # that SAME protocol conversion, not a no-op FakeSelector test.
        original = ast.parse(ast.unparse(counted)).body[0]
        original.body = [node for node in original.body
            if not (isinstance(node, ast.FunctionDef) and node.name == "fileno")]
        legacy = {"state": {"reads": 0}}
        exec(compile(ast.Module(body=[original], type_ignores=[]),
            "<owned-missing-CountedTls-protocol>", "exec"), legacy)
        with self.assertRaises(ValueError):
            tls.selectors._fileobj_to_fd(legacy["CountedTls"](connection))

    def test_write_failure_record_is_closed_fixture_evidence(self):
        output = mock.MagicMock()
        output.__enter__.return_value = output
        output.fileno.return_value = 123
        with mock.patch.object(tls.os, "open", return_value=123) as opened, \
                mock.patch.object(tls.os, "fdopen", return_value=output), \
                mock.patch.object(tls.os, "fsync"), \
                mock.patch.object(tls.os, "_exit", side_effect=AssertionError("unexpected mock exit")):
            tls.record_write_failure(Path("/synthetic-owned-tls"))
        self.assertEqual(opened.call_args.args[0], Path("/synthetic-owned-tls/relay-write-failed"))
        self.assertEqual(opened.call_args.args[2], 0o600)
        output.write.assert_called_once_with(b"MANAGED_RELAY_WRITE_FAILED\n")


def run_owned_slow_peer(root_value):
    """REAL TLS/TCP control, never called by unittest discovery/default mode.

    Parent must first launch this exact mode in a new owned process/group/root,
    empty environment and sandbox, respecting its existing slots/deadlines.
    It generates only fresh synthetic keys under root/tls via the fixture mint.
    """
    root = tls.owned_root(root_value)
    startup_end = time.monotonic() + 40
    ports, ports_hash = tls.case_handoff(root, ("slow-peer", "slow-relay"), startup_end)
    tls.STARTUP_END = startup_end
    tls.STOP.clear()
    failed_write = threading.Event()
    peer_accepted = threading.Event()
    state = {"reads": 0, "reads_at_failure": None, "prefix": b"", "errors": [], "eof": False}
    live = []
    workers = []
    payload = bytes(range(256)) * (64 * 1024 * 1024 // 256)

    class CountedTls:
        def __init__(self, connection):
            self.connection = connection

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.connection.close()

        def settimeout(self, seconds):
            self.connection.settimeout(seconds)

        def pending(self):
            return self.connection.pending()

        def fileno(self):
            return self.connection.fileno()

        def recv(self, size):
            state["reads"] += 1
            return self.connection.recv(size)

        def sendall(self, data):
            self.connection.sendall(data)

    class CountedContext:
        def __init__(self):
            self.context = tls.tls_context(folder)

        def wrap_socket(self, connection, **kwargs):
            secure = self.context.wrap_socket(connection, **kwargs)
            live.append(secure)
            return CountedTls(secure)

    def fixture_write_failed():
        state["reads_at_failure"] = state["reads"]
        tls.record_write_failure(folder)
        failed_write.set()

    with contextlib.ExitStack() as resources:
        tls.require(time.monotonic() < startup_end)
        peer_listener = resources.enter_context(tls.socket.socket(tls.socket.AF_INET, tls.socket.SOCK_STREAM))
        peer_listener.setsockopt(tls.socket.SOL_SOCKET, tls.socket.SO_RCVBUF, 4096)
        tls.require(time.monotonic() < startup_end)
        peer_listener.bind(("127.0.0.1", ports["ports"]["slow-peer"]))
        peer_listener.listen(1)
        peer_listener.settimeout(3)
        tls.require(time.monotonic() < startup_end)
        relay_listener = resources.enter_context(tls.socket.socket(tls.socket.AF_INET, tls.socket.SOCK_STREAM))
        tls.require(time.monotonic() < startup_end)
        relay_listener.bind(("127.0.0.1", ports["ports"]["slow-relay"]))
        relay_listener.listen(1)
        relay_listener.settimeout(3)
        tls.atomic_record(root / "owned-slow-listeners.json", dict(schema=1, case=ports["case"],
            nonce=ports["nonce"], ports_sha256=ports_hash,
            ports=[peer_listener.getsockname()[1], relay_listener.getsockname()[1]]))
        # Both exact binds succeed BEFORE any mint/TLS/client operation.
        folder = tls.mint(root, "trusted")
        server_context = CountedContext()

        def slow_peer():
            try:
                connection, address = peer_listener.accept()
                live.append(connection)
                tls.require(address[0] == "127.0.0.1")
                with connection:
                    connection.settimeout(0.25)
                    peer_accepted.set()
                    # Intentionally do not read until the actual relay write
                    # times out. Then inspect only the bounded received prefix.
                    tls.require(failed_write.wait(5))
                    end = time.monotonic() + 2
                    prefix = bytearray()
                    while time.monotonic() < end:
                        try:
                            chunk = connection.recv(64 * 1024)
                        except tls.socket.timeout:
                            continue
                        if not chunk:
                            state["eof"] = True
                            break
                        prefix.extend(chunk)
                        tls.require(len(prefix) <= 16 * 1024 * 1024)
                    state["prefix"] = bytes(prefix)
            except Exception:
                state["errors"].append(True)

        def relay():
            try:
                connection, address = relay_listener.accept()
                live.append(connection)
                tls.require(address[0] == "127.0.0.1")
                tls.serve_connection(connection, server_context, peer_listener.getsockname()[1], fixture_write_failed)
            except Exception:
                state["errors"].append(True)

        try:
            for target in (slow_peer, relay):
                worker = threading.Thread(target=target, daemon=True)
                workers.append(worker)
                worker.start()
            client_context = tls.ssl.SSLContext(tls.ssl.PROTOCOL_TLS_CLIENT)
            client_context.load_verify_locations(cafile=folder / "ca.pem")
            tls.require(client_context.check_hostname and client_context.verify_mode == tls.ssl.CERT_REQUIRED)
            with tls.socket.create_connection(relay_listener.getsockname(), timeout=3) as raw:
                raw.setsockopt(tls.socket.SOL_SOCKET, tls.socket.SO_SNDBUF, 4096)
                with client_context.wrap_socket(raw, server_hostname="127.0.0.1") as client:
                    client.settimeout(3)
                    tls.require(peer_accepted.wait(2))
                    try:
                        client.sendall(payload)
                    except (OSError, tls.ssl.SSLError):
                        pass
                    tls.require(failed_write.wait(4))
            for worker in workers:
                worker.join(timeout=5)
            tls.require(not any(worker.is_alive() for worker in workers))
            tls.require(not state["errors"] and state["eof"])
            tls.require(state["reads"] == state["reads_at_failure"])
            prefix = state["prefix"]
            tls.require(0 < len(prefix) < len(payload) and prefix == payload[:len(prefix)])
            tls.require((folder / "relay-write-failed").is_file())
        finally:
            for connection in live:
                connection.close()
            for worker in workers:
                worker.join(timeout=1)
            tls.require(not any(worker.is_alive() for worker in workers))
    tls.require(peer_listener.fileno() == -1 and relay_listener.fileno() == -1)
    tls.require(all(connection.fileno() == -1 for connection in live))
    print(json.dumps({"kind": "owned-slow-peer", "passed": True,
        "no_receive_after_write_failure": True, "received_prefix_ordered": True,
        "fixture_failure_not_gateway_result": True, "workers_ended": True,
        "listeners_closed": True, "connections_closed": True}))


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--owned-slow-peer-root":
        try:
            run_owned_slow_peer(sys.argv[2])
            return 0
        except Exception:
            print(json.dumps({"kind": "owned-slow-peer", "passed": False}))
            return 1
    if len(sys.argv) != 1:
        print(json.dumps({"kind": "socket-free-mock", "invalid_invocation": True}))
        return 2
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestSocketFreeRelay)
    result = unittest.TestResult()
    suite.run(result)
    print(json.dumps({"kind": "socket-free-mock", "tests_run": result.testsRun,
        "failures": len(result.failures), "errors": len(result.errors),
        "real_network": False, "tls_executed": False, "openssl_executed": False}))
    return 0 if result.wasSuccessful() and result.testsRun == 5 else 1


if __name__ == "__main__":
    sys.exit(main())
