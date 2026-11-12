# SPDX-License-Identifier: Apache-2.0
"""Owned internal-container connector; opaque, bounded, numeric IPv4 TCP only."""
from dataclasses import dataclass, field
import errno
import ipaddress
import re
import selectors
import socket
import threading
import time
from .transport import BoundaryError

RELAY_CODES = frozenset((
    'relay-endpoint-invalid', 'relay-endpoint-changed', 'relay-state-invalid',
    'relay-listener-invalid', 'relay-bind-failed', 'relay-peer-invalid',
    'relay-upstream-failed', 'relay-wire-bound', 'relay-connection-deadline',
    'relay-work-deadline', 'relay-worker-failed', 'relay-cleanup-incomplete',
))
BUFFER = 64 * 1024
WIRE = 2 * 2**20  # Per direction, hence <=4 MiB aggregate per connection.
CONNECTIONS = 8
SECONDS = 25
DB_PORTS = frozenset((1433, 1521, 3306, 33060, 5432, 5433, 6379, 8123, 9000, 26257, 27017, 27018))
PRIVATE = tuple(ipaddress.IPv4Network(value) for value in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))

@dataclass(frozen=True)
class Loopback:
    port: int
    host: str = field(default='127.0.0.1', init=False)
    kind: str = field(default='owned-tcp-relay', init=False)

    def __post_init__(self):
        if type(self.port) is not int or not 1 <= self.port <= 65535 or self.port in DB_PORTS:
            raise BoundaryError('relay-listener-invalid')

@dataclass(frozen=True, repr=False)
class Endpoint:
    container_id: str
    network_id: str
    endpoint_id: str
    address: str
    subnet: str

    def __post_init__(self):
        try:
            if not all(type(value) is str and re.fullmatch('[0-9a-f]{64}', value)
                       for value in (self.container_id, self.network_id, self.endpoint_id)): raise ValueError
            address = ipaddress.IPv4Address(self.address); subnet = ipaddress.IPv4Network(self.subnet)
            if str(address) != self.address or str(subnet) != self.subnet: raise ValueError
            if not any(subnet.subnet_of(private) for private in PRIVATE): raise ValueError
            if address not in subnet or address in (subnet.network_address, subnet.broadcast_address): raise ValueError
        except (TypeError, ValueError): raise BoundaryError('relay-endpoint-invalid') from None

def verify_endpoint(container, network, container_id, network_id, container_name, network_name):
    """Cross-check two projections AFTER ImageIO verifies labels, IDs and births."""
    try:
        if container['id'] != container_id or network['id'] != network_id: raise ValueError
        if container['running'] is not True or network['internal'] is not True or network['driver'] != 'bridge': raise ValueError
        if container['network_mode'] not in (network_name, network_id): raise ValueError
        if set(container['networks']) != {network_name} or set(network['containers']) != {container_id}: raise ValueError
        if container['bindings'] not in (None, {}): raise ValueError
        ports = {} if container['ports'] is None else container['ports']
        # Internal Docker endpoints have no host publication. A relay is mandatory.
        if not isinstance(ports, dict) or set(ports) - {'9000/tcp'} or any(value not in (None, []) for value in ports.values()): raise ValueError
        attached = container['networks'][network_name]; member = network['containers'][container_id]
        if attached['NetworkID'] != network_id or attached['EndpointID'] != member['EndpointID']: raise ValueError
        if member['Name'] != container_name or member['IPv6Address'] or attached['GlobalIPv6Address']: raise ValueError
        if len(network['ipam']) != 1: raise ValueError
        subnet = ipaddress.IPv4Network(network['ipam'][0]['Subnet'])
        interface = ipaddress.IPv4Interface(member['IPv4Address'])
        if interface.network != subnet or str(interface.ip) != attached['IPAddress']: raise ValueError
        if type(attached['IPPrefixLen']) is not int or attached['IPPrefixLen'] != subnet.prefixlen: raise ValueError
        return Endpoint(container_id, network_id, attached['EndpointID'], str(interface.ip), str(subnet))
    except (KeyError, TypeError, ValueError, AttributeError):
        raise BoundaryError('relay-endpoint-invalid') from None

class Connection:
    def __init__(self, client, upstream, connecting, deadline):
        self.sockets = (client, upstream); self.connecting = connecting; self.deadline = deadline
        self.buffers = (bytearray(), bytearray()); self.wire = [0, 0]
        self.eof = [False, False]; self.shutdown = [False, False]

class Relay:
    """One worker, <=8 connections, no DNS, proxies, payload reporting or retries.

    start() returns a kernel-owned 127.0.0.1 port. stop(deadline) uses the caller's
    existing deadline; it never allocates/renews a cleanup reserve. Factories are
    injectable solely for offline tests; production uses stdlib sockets/selectors.
    """
    def __init__(self, endpoint, work_deadline, clock=time.monotonic, *, socket_factory=socket.socket,
                 selector_factory=selectors.DefaultSelector, thread_factory=threading.Thread):
        if type(endpoint) is not Endpoint: raise BoundaryError('relay-endpoint-invalid')
        self.endpoint = endpoint; self.work_deadline = work_deadline; self.clock = clock
        self.socket_factory = socket_factory; self.selector_factory = selector_factory; self.thread_factory = thread_factory
        self.listener = self.selector = self.thread = None; self.selector_closed = True
        self.owned = set(); self.connections = {}; self.registered = {}; self.ports = set(); self.port = None
        self.binding = None
        self.stopping = False; self.failure_code = None

    def fail(self, code):
        if self.failure_code is None: self.failure_code = code if code in RELAY_CODES else 'relay-worker-failed'

    def _socket(self):
        if self.stopping: raise BoundaryError('relay-state-invalid')
        raw = self.socket_factory(socket.AF_INET, socket.SOCK_STREAM)
        self.owned.add(raw); raw.setblocking(False); return raw

    def _interest(self, raw, events, data):
        if events:
            if raw in self.registered: self.selector.modify(raw, events, data)
            else: self.selector.register(raw, events, data)
            self.registered[raw] = True
        elif raw in self.registered:
            self.selector.unregister(raw); self.registered.pop(raw, None)

    def _close(self, raw):
        if raw in self.registered:
            try: self.selector.unregister(raw)
            except (KeyError, ValueError, OSError): pass
            except BaseException: self.fail('relay-cleanup-incomplete')
            self.registered.pop(raw, None)
        try: raw.close()
        except BaseException: self.fail('relay-cleanup-incomplete')
        try:
            if raw.fileno() < 0: self.owned.discard(raw)
            else: self.fail('relay-cleanup-incomplete')
        except BaseException: self.fail('relay-cleanup-incomplete')

    def _close_all(self):
        for raw in tuple(self.owned): self._close(raw)
        self.connections.clear(); self.listener = None

    def _close_selector(self):
        if self.selector is not None and not self.selector_closed:
            try: self.selector.close(); self.selector_closed = True
            except BaseException: self.fail('relay-cleanup-incomplete')

    def start(self):
        if self.thread is not None or self.stopping or self.failure_code: raise BoundaryError('relay-state-invalid')
        try:
            if self.clock() >= self.work_deadline: raise BoundaryError('relay-work-deadline')
            self.selector = self.selector_factory(); self.selector_closed = False
            for _ in range(8):
                if self.clock() >= self.work_deadline: raise BoundaryError('relay-work-deadline')
                raw = self._socket(); raw.bind(('127.0.0.1', 0)); address = raw.getsockname()
                if not isinstance(address, tuple) or len(address) != 2 or address[0] != '127.0.0.1' or type(address[1]) is not int or not 1 <= address[1] <= 65535:
                    raise BoundaryError('relay-listener-invalid')
                self.ports.add(address[1])
                if address[1] in DB_PORTS: self._close(raw); continue
                raw.listen(CONNECTIONS); self.listener = raw; self.binding = Loopback(address[1]); self.port = self.binding.port; break
            if self.listener is None: raise BoundaryError('relay-bind-failed')
            if self.clock() >= self.work_deadline: raise BoundaryError('relay-work-deadline')
            self._interest(self.listener, selectors.EVENT_READ, None)
            self.thread = self.thread_factory(target=self.run, daemon=True, name='maskura-feedback-relay')
            self.thread.start(); self.check(); return self.port
        except BaseException as exc:
            code = exc.args[0] if isinstance(exc, BoundaryError) and len(exc.args) == 1 and type(exc.args[0]) is str and exc.args[0] in RELAY_CODES else 'relay-bind-failed'
            self.fail(code); self.stopping = True; self._close_all(); self._close_selector()
            raise BoundaryError(code) from None

    def check(self):
        if self.failure_code: raise BoundaryError(self.failure_code)
        if not self.stopping and (self.thread is None or not self.thread.is_alive()):
            self.fail('relay-worker-failed'); raise BoundaryError('relay-worker-failed')

    def _drop(self, connection):
        self.connections.pop(id(connection), None)
        for raw in connection.sockets: self._close(raw)

    def _refresh(self, connection):
        for index, raw in enumerate(connection.sockets):
            other = 1 - index
            if connection.eof[other] and not connection.buffers[other] and not connection.shutdown[index] and not connection.connecting:
                try: raw.shutdown(socket.SHUT_WR)
                except OSError: pass
                connection.shutdown[index] = True
        if all(connection.eof) and not any(connection.buffers): self._drop(connection); return
        for index, raw in enumerate(connection.sockets):
            if index == 1 and connection.connecting: events = selectors.EVENT_WRITE
            else:
                events = selectors.EVENT_READ if not connection.eof[index] and len(connection.buffers[index]) < BUFFER else 0
                if connection.buffers[1 - index]: events |= selectors.EVENT_WRITE
            self._interest(raw, events, (connection, index))

    def _accept(self):
        if len(self.connections) >= CONNECTIONS: return
        accepted_at = self.clock()
        try: client, peer = self.listener.accept()
        except (BlockingIOError, InterruptedError): return
        self.owned.add(client); client.setblocking(False)
        if self.stopping: self._close(client); return
        if not isinstance(peer, tuple) or len(peer) != 2 or peer[0] != '127.0.0.1' or type(peer[1]) is not int or not 1 <= peer[1] <= 65535:
            raise BoundaryError('relay-peer-invalid')
        upstream = self._socket()
        result = upstream.connect_ex((self.endpoint.address, 9000))
        if result == errno.ECONNREFUSED: self._close(client); self._close(upstream); return
        if result not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, errno.EINTR): raise BoundaryError('relay-upstream-failed')
        connection = Connection(client, upstream, result != 0, min(accepted_at + SECONDS, self.work_deadline))
        self.connections[id(connection)] = connection; self._live(connection); self._refresh(connection)

    def _live(self, connection):
        now = self.clock()
        if now >= self.work_deadline: raise BoundaryError('relay-work-deadline')
        if now >= connection.deadline: raise BoundaryError('relay-connection-deadline')

    def _transfer(self, connection, index, events):
        self._live(connection)
        raw = connection.sockets[index]
        if index == 1 and connection.connecting:
            result = raw.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if result == errno.ECONNREFUSED: self._drop(connection); return
            if result in (errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK, errno.EINTR): return
            if result: raise BoundaryError('relay-upstream-failed')
            connection.connecting = False
            self._live(connection)
        if events & selectors.EVENT_WRITE and connection.buffers[1 - index]:
            buffer = connection.buffers[1 - index]
            try: count = raw.send(buffer)
            except (BlockingIOError, InterruptedError): count = 0
            self._live(connection)
            if count < 0 or count > len(buffer): raise BoundaryError('relay-worker-failed')
            del buffer[:count]
        if events & selectors.EVENT_READ and not connection.eof[index] and len(connection.buffers[index]) < BUFFER:
            limit = min(BUFFER - len(connection.buffers[index]), WIRE - connection.wire[index] + 1)
            try: data = raw.recv(limit)
            except (BlockingIOError, InterruptedError): data = None
            self._live(connection)
            if data is not None:
                if len(data) > limit: raise BoundaryError('relay-wire-bound')
                connection.wire[index] += len(data)
                if connection.wire[index] > WIRE: raise BoundaryError('relay-wire-bound')
                if data: connection.buffers[index].extend(data)
                else: connection.eof[index] = True
        self._refresh(connection)

    def step(self):
        now = self.clock()
        if now >= self.work_deadline: raise BoundaryError('relay-work-deadline')
        if any(now >= connection.deadline for connection in self.connections.values()): raise BoundaryError('relay-connection-deadline')
        self._interest(self.listener, selectors.EVENT_READ if len(self.connections) < CONNECTIONS else 0, None)
        deadline = min([self.work_deadline, *(connection.deadline for connection in self.connections.values())])
        events = self.selector.select(min(0.05, max(0, deadline - now)))
        for key, mask in events:
            if self.stopping: return
            if self.clock() >= deadline:
                raise BoundaryError('relay-work-deadline' if deadline == self.work_deadline else 'relay-connection-deadline')
            if key.data is None: self._accept()
            else:
                connection, index = key.data
                if id(connection) not in self.connections: continue
                try: self._transfer(connection, index, mask)
                except (ConnectionResetError, BrokenPipeError): self._drop(connection)

    def run(self):
        try:
            while not self.stopping: self.step()
        except BaseException as exc:
            if not (self.stopping and isinstance(exc, OSError) and exc.errno in (errno.EBADF, errno.ENOTSOCK)):
                code = exc.args[0] if isinstance(exc, BoundaryError) and len(exc.args) == 1 and type(exc.args[0]) is str and exc.args[0] in RELAY_CODES else 'relay-worker-failed'
                self.fail(code)
        finally: self._close_all(); self._close_selector()

    def stop(self, deadline):
        self.stopping = True
        # Wake channels without racing FD reuse/selector modification. The worker
        # retires its FDs in finally; after the bounded join we close any leftovers.
        for raw in tuple(self.owned):
            try: raw.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            except BaseException: self.fail('relay-cleanup-incomplete')
        if self.thread is not None:
            try: self.thread.join(timeout=max(0, deadline - self.clock()))
            except RuntimeError:
                if self.thread.is_alive(): self.fail('relay-cleanup-incomplete')
        self._close_all()
        if self.thread is None or not self.thread.is_alive(): self._close_selector()
        if not self.clear(): self.fail('relay-cleanup-incomplete')
        return self.clear()

    def clear(self):
        return (self.stopping and not self.owned and not self.connections and self.selector_closed
                and (self.thread is None or not self.thread.is_alive()))
