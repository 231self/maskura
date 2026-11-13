# SPDX-License-Identifier: Apache-2.0
"""Pure fake I/O connector regressions. Not TCP or packaged-image qualification."""
import copy
from contextlib import ExitStack
import errno
import json
import pathlib
import selectors
import socket
import sys
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from release_feedback import image, receipts, relay, transport

AUDITING = False
AUDIT_TRIPS = []
def deny_external(event, args):
    if AUDITING and (event.startswith(('socket.', 'subprocess.')) or event in
                     ('os.system', 'os.fork', 'os.posix_spawn', 'os.kill', 'os.killpg', 'resource.setrlimit')):
        AUDIT_TRIPS.append(event); raise AssertionError('external I/O forbidden')
sys.addaudithook(deny_external)

CID, NID, EID = 'a' * 64, 'b' * 64, 'c' * 64
def projections():
    container = dict(id=CID, running=True, network_mode='owned-network', bindings={}, ports={'9000/tcp': None},
        networks={'owned-network': dict(NetworkID=NID, EndpointID=EID, IPAddress='172.18.0.2', IPPrefixLen=16, GlobalIPv6Address='')})
    network = dict(id=NID, internal=True, driver='bridge', ipam=[dict(Subnet='172.18.0.0/16')],
        containers={CID: dict(Name='owned-container', EndpointID=EID, IPv4Address='172.18.0.2/16', IPv6Address='')})
    return container, network
def endpoint(address='172.18.0.2'):
    return relay.Endpoint(CID, NID, EID, address, '172.18.0.0/16')
def verify(container, network):
    return relay.verify_endpoint(container, network, CID, NID, 'owned-container', 'owned-network')

class Clock:
    def __init__(self): self.now = 0
    def __call__(self): return self.now

class Socket:
    def __init__(self, port=41000):
        self.fd = 123; self.address = ('127.0.0.1', port); self.accepted = []; self.reads = []
        self.recv_limits = []; self.sent = bytearray(); self.send_max = relay.BUFFER
        self.result = self.so_error = 0; self.bind_error = self.close_error = False
        self.shutdowns = []; self.target = None
    def setblocking(self, value): self.blocking = value
    def bind(self, address):
        self.bound = address
        if self.bind_error: raise OSError('PRIVATE_BIND_ERROR')
    def getsockname(self): return self.address
    def listen(self, count): self.backlog = count
    def accept(self):
        if self.accepted: return self.accepted.pop(0)
        raise BlockingIOError
    def connect_ex(self, address): self.target = address; return self.result
    def getsockopt(self, *args): return self.so_error
    def recv(self, limit):
        self.recv_limits.append(limit)
        if not self.reads: raise BlockingIOError
        data = self.reads.pop(0)
        if isinstance(data, BaseException): raise data
        if len(data) > limit: self.reads.insert(0, data[limit:])
        return data[:limit]
    def send(self, data):
        count = min(len(data), self.send_max); self.sent.extend(data[:count]); return count
    def shutdown(self, how): self.shutdowns.append(how)
    def close(self):
        if self.close_error: raise OSError('PRIVATE_CLOSE_ERROR')
        self.fd = -1
    def fileno(self): return self.fd

class Selector:
    def __init__(self): self.keys = {}; self.events = []; self.closed = False; self.timeouts = []; self.error = None
    def register(self, raw, events, data):
        if raw in self.keys: raise KeyError
        self.keys[raw] = NS(fileobj=raw, events=events, data=data)
    def modify(self, raw, events, data):
        if raw not in self.keys: raise KeyError
        self.keys[raw] = NS(fileobj=raw, events=events, data=data)
    def unregister(self, raw): return self.keys.pop(raw)
    def select(self, timeout):
        self.timeouts.append(timeout)
        if self.error: raise self.error
        events, self.events = self.events, []
        return [(self.keys[raw], mask) for raw, mask in events if raw in self.keys]
    def close(self): self.closed = True; self.keys.clear()

class Thread:
    def __init__(self, target, **kwargs):
        self.target = target; self.alive = False; self.finish = True; self.join_timeouts = []
    def start(self): self.alive = True
    def is_alive(self): return self.alive
    def join(self, timeout):
        self.join_timeouts.append(timeout)
        if self.finish: self.target(); self.alive = False

class RelayTests(unittest.TestCase):
    def test_harness_identity_covers_every_runtime_module_including_connector(self):
        modules = {path.name for path in (ROOT / 'scripts/release_feedback').glob('*.py')}
        self.assertEqual(set(receipts.CODE), modules)
        original = receipts.harness_sha()
        read_bytes = pathlib.Path.read_bytes
        def changed(path):
            body = read_bytes(path)
            return body + b'\n# changed connector\n' if path.name == 'relay.py' else body
        with patch.object(pathlib.Path, 'read_bytes', changed):
            self.assertNotEqual(receipts.harness_sha(), original)

    def setUp(self):
        global AUDITING
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        for target in ('socket.socket', 'socket.create_connection', 'subprocess.Popen', 'subprocess.run',
                       'threading.Thread', 'selectors.DefaultSelector', 'resource.setrlimit', 'signal.signal', 'fcntl.flock', 'os.killpg'):
            self.stack.enter_context(patch(target, side_effect=AssertionError('real external action forbidden')))
        self.audit_start = len(AUDIT_TRIPS); AUDITING = True
        def finish():
            global AUDITING
            AUDITING = False; self.assertEqual(AUDIT_TRIPS[self.audit_start:], [])
        self.addCleanup(finish)
    def make(self, *, ports=(41000,), deadline=100):
        clock = Clock(); selector = Selector(); made = []; threads = []
        ports = iter(ports)
        def factory(family, kind):
            self.assertEqual((family, kind), (socket.AF_INET, socket.SOCK_STREAM))
            raw = Socket(next(ports, 41001)); made.append(raw); return raw
        def thread_factory(**kwargs):
            thread = Thread(**kwargs); threads.append(thread); return thread
        obj = relay.Relay(endpoint(), deadline, clock, socket_factory=factory,
                          selector_factory=lambda: selector, thread_factory=thread_factory)
        return obj, clock, selector, made, threads
    def accept(self, obj, selector, made, *, result=0):
        client = Socket(); obj.listener.accepted.append((client, ('127.0.0.1', 42000)))
        # The next created socket is the fixed upstream, never an arbitrary host.
        factory = obj.socket_factory
        def upstream(*args):
            raw = factory(*args); raw.result = result; return raw
        obj.socket_factory = upstream
        selector.events = [(obj.listener, selectors.EVENT_READ)]; obj.step()
        obj.socket_factory = factory
        return client, made[-1]
    def test_verified_internal_endpoint_accepts_empty_docker_publication_only_as_metadata(self):
        container, network = projections()
        self.assertEqual(verify(container, network), endpoint())
        for ports in (None, {}, {'9000/tcp': []}):
            container['ports'] = ports; self.assertEqual(verify(container, network), endpoint())
        # Verification alone creates no socket, relay or passing qualification.
    def test_invalid_global_unowned_extra_network_and_endpoint_replacement_rejected(self):
        mutations = (
            lambda c,n: c.update(id='d' * 64), lambda c,n: n.update(id='d' * 64),
            lambda c,n: n.update(internal=False), lambda c,n: n.update(driver='host'),
            lambda c,n: c.update(running=False), lambda c,n: c.update(network_mode='host'),
            lambda c,n: c['networks'].update(extra=copy.deepcopy(c['networks']['owned-network'])),
            lambda c,n: n['containers'].update({'d' * 64: copy.deepcopy(n['containers'][CID])}),
            lambda c,n: c['networks']['owned-network'].update(NetworkID='d' * 64),
            lambda c,n: c['networks']['owned-network'].update(EndpointID='d' * 64),
            lambda c,n: n['containers'][CID].update(Name='not-owned'),
            lambda c,n: c['networks']['owned-network'].update(IPAddress='8.8.8.8'),
            lambda c,n: n['ipam'][0].update(Subnet='8.8.8.0/24'),
            lambda c,n: n['containers'][CID].update(IPv4Address='172.19.0.2/16'),
            lambda c,n: c['networks']['owned-network'].update(IPPrefixLen=True),
            lambda c,n: c['networks']['owned-network'].update(GlobalIPv6Address='::1'),
            lambda c,n: c.update(bindings={'9000/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '9000'}]}),
            lambda c,n: c.update(ports={'9000/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '41000'}]}),
        )
        for mutate in mutations:
            c,n = projections(); mutate(c,n)
            with self.subTest(mutation=mutate), self.assertRaisesRegex(transport.BoundaryError, '^relay-endpoint-invalid$'): verify(c,n)
        for address, subnet in (('127.0.0.1','127.0.0.0/8'), ('169.254.1.2','169.254.0.0/16'),
                                ('8.8.8.8','8.8.8.0/24'), ('172.18.0.0','172.18.0.0/16'), ('172.18.255.255','172.18.0.0/16')):
            with self.assertRaises(transport.BoundaryError): relay.Endpoint(CID,NID,EID,address,subnet)
    def test_listener_kernel_allocated_loopback_bounded_retries_and_fixed_target(self):
        obj, clock, selector, made, threads = self.make(ports=(5432,3306,41000))
        self.assertEqual(obj.start(),41000); self.assertEqual(obj.ports,{5432,3306,41000})
        self.assertEqual(obj.binding,relay.Loopback(41000)); self.assertEqual(obj.binding.kind,'owned-tcp-relay')
        self.assertEqual(obj.binding.host,'127.0.0.1')
        self.assertTrue(all(raw.bound == ('127.0.0.1',0) for raw in made))
        self.assertTrue(all(raw.fileno() < 0 for raw in made[:2])); self.assertEqual(made[2].backlog,8)
        client, upstream = self.accept(obj,selector,made)
        self.assertEqual(upstream.target,('172.18.0.2',9000)); self.assertFalse(upstream.blocking)
        self.assertTrue(obj.stop(20)); self.assertTrue(obj.clear())
    def test_invalid_listener_and_startup_errors_close_owned_fds_without_exception_text(self):
        for failure in ('address','bind','thread'):
            obj, clock, selector, made, threads = self.make()
            factory = obj.socket_factory
            def bad_socket(*args):
                raw = factory(*args)
                if failure == 'address': raw.address = ('0.0.0.0',41000)
                if failure == 'bind': raw.bind_error = True
                return raw
            obj.socket_factory = bad_socket
            if failure == 'thread': obj.thread_factory = lambda **kwargs: (_ for _ in ()).throw(RuntimeError('PRIVATE_THREAD_ERROR'))
            with self.assertRaises(transport.BoundaryError) as raised: obj.start()
            self.assertIn(raised.exception.args[0],relay.RELAY_CODES); self.assertNotIn('PRIVATE',repr(raised.exception.args))
            self.assertTrue(all(raw.fileno() < 0 for raw in made)); self.assertTrue(selector.closed)
            self.assertTrue(obj.clear()); self.assertIsNotNone(obj.failure_code)
        obj, _, _, made, _ = self.make(ports=(5432,)*8)
        with self.assertRaisesRegex(transport.BoundaryError,'^relay-bind-failed$'): obj.start()
        self.assertEqual(len(made),8); self.assertTrue(obj.clear())
        for port in (True,0,65536,5432,'41000'):
            with self.assertRaisesRegex(transport.BoundaryError,'^relay-listener-invalid$'): relay.Loopback(port)
    def test_backpressure_caps_each_direction_and_never_overreads(self):
        obj, _, selector, made, _ = self.make(); obj.start(); client, upstream = self.accept(obj,selector,made)
        client.reads = [b'A' * (relay.BUFFER + 10)]; upstream.send_max = 0
        selector.events = [(client,selectors.EVENT_READ)]; obj.step()
        connection = next(iter(obj.connections.values()))
        self.assertEqual(len(connection.buffers[0]),relay.BUFFER); self.assertNotIn(client,selector.keys)
        selector.events = [(upstream,selectors.EVENT_WRITE)]; obj.step()
        self.assertEqual(client.recv_limits,[relay.BUFFER]); self.assertEqual(len(connection.buffers[0]),relay.BUFFER)
        upstream.send_max = 7; selector.events = [(upstream,selectors.EVENT_WRITE)]; obj.step()
        selector.events = [(client,selectors.EVENT_READ)]; obj.step()
        self.assertEqual(client.recv_limits[-1],7); self.assertLessEqual(len(connection.buffers[0]),relay.BUFFER)
        self.assertTrue(obj.stop(20))
    def test_connect_in_progress_bidirectional_bytes_and_half_close_drain(self):
        obj, _, selector, made, _ = self.make(); obj.start(); client, upstream = self.accept(obj,selector,made,result=errno.EINPROGRESS)
        client.reads = [b'opaque-request',b'']; upstream.reads = [b'opaque-response',b'']
        for raw, mask in ((client,1),(upstream,2),(client,1),(upstream,1),(client,2),(upstream,1)):
            selector.events=[(raw,mask)]; obj.step()
        self.assertEqual(bytes(upstream.sent),b'opaque-request'); self.assertEqual(bytes(client.sent),b'opaque-response')
        self.assertIn(socket.SHUT_WR,upstream.shutdowns); self.assertIn(socket.SHUT_WR,client.shutdowns)
        self.assertFalse(obj.connections); self.assertLess(client.fileno(),0); self.assertLess(upstream.fileno(),0)
        self.assertTrue(obj.stop(20))
    def test_boot_readiness_connection_refusal_closes_only_that_connection(self):
        for result in (errno.ECONNREFUSED,errno.EINPROGRESS):
            obj, _, selector, made, _ = self.make(); obj.start()
            client, upstream = self.accept(obj,selector,made,result=result)
            if result == errno.EINPROGRESS:
                upstream.so_error=errno.ECONNREFUSED; selector.events=[(upstream,selectors.EVENT_WRITE)]; obj.step()
            self.assertFalse(obj.connections); self.assertIsNone(obj.failure_code)
            self.assertLess(client.fileno(),0); self.assertLess(upstream.fileno(),0)
            self.assertTrue(obj.stop(20))
    def test_concurrency_backlog_and_peer_address_are_bounded(self):
        obj, _, selector, made, _ = self.make(); obj.start()
        for _ in range(8): self.accept(obj,selector,made)
        self.assertEqual(len(obj.connections),8); obj.step(); self.assertNotIn(obj.listener,selector.keys)
        before = len(made); obj._accept(); self.assertEqual(len(made),before)
        self.assertTrue(obj.stop(20)); self.assertTrue(all(raw.fileno() < 0 for raw in made))
        obj, _, selector, made, _ = self.make(); obj.start(); peer = Socket()
        obj.listener.accepted=[(peer,('8.8.8.8',42000))]
        with self.assertRaisesRegex(transport.BoundaryError,'^relay-peer-invalid$'): obj._accept()
        self.assertTrue(obj.stop(20)); self.assertLess(peer.fileno(),0)
    def test_wire_cap_and_absolute_connection_and_work_deadlines_are_sticky(self):
        for failure in ('wire','connection','work'):
            obj, clock, selector, made, _ = self.make(deadline=10 if failure=='work' else 100)
            obj.start(); client, upstream = self.accept(obj,selector,made)
            connection = next(iter(obj.connections.values()))
            if failure=='wire':
                connection.wire[1]=relay.WIRE; upstream.reads=[b'X']; selector.events=[(upstream,1)]
            elif failure=='connection': clock.now=25
            else: clock.now=10
            obj.run()
            self.assertEqual(obj.failure_code,{'wire':'relay-wire-bound','connection':'relay-connection-deadline','work':'relay-work-deadline'}[failure])
            with self.assertRaises(transport.BoundaryError): obj.check()
            self.assertTrue(obj.stop(20 if failure=='wire' else clock.now+1)); self.assertTrue(obj.clear())
            self.assertIsNotNone(obj.failure_code)
    def test_drips_never_extend_connection_deadline(self):
        obj, clock, selector, made, _ = self.make(); obj.start(); client, upstream = self.accept(obj,selector,made)
        connection = next(iter(obj.connections.values()))
        for now in (1,10,24.9):
            clock.now=now; client.reads=[b'x']; selector.events=[(client,1)]; obj.step()
            self.assertEqual(connection.deadline,25)
        clock.now=25
        with self.assertRaisesRegex(transport.BoundaryError,'^relay-connection-deadline$'): obj.step()
        self.assertTrue(obj.stop(26))
    def test_worker_exception_is_generic_and_shutdown_closes_fds_joins_original_deadline(self):
        obj, clock, selector, made, threads = self.make(); obj.start(); self.accept(obj,selector,made)
        selector.error=RuntimeError('PRIVATE_RESPONSE_CREDENTIAL_HASH'); obj.run()
        self.assertEqual(obj.failure_code,'relay-worker-failed'); clock.now=18
        self.assertTrue(obj.stop(20)); self.assertEqual(threads[0].join_timeouts,[2])
        self.assertTrue(selector.closed); self.assertTrue(all(raw.fileno()<0 for raw in made))
        self.assertTrue(obj.clear()); self.assertEqual(obj.failure_code,'relay-worker-failed')
    def test_unexpected_worker_exception_racing_shutdown_is_still_sticky(self):
        obj, _, selector, _, _ = self.make(); obj.start()
        def fail_during_stop(timeout):
            obj.stopping=True
            raise RuntimeError('PRIVATE_WORKER_ERROR_DURING_STOP')
        selector.select=fail_during_stop; obj.run()
        self.assertEqual(obj.failure_code,'relay-worker-failed'); self.assertTrue(obj.stop(20))
        self.assertEqual(obj.failure_code,'relay-worker-failed')
    def test_stuck_worker_or_fd_close_error_cannot_be_clean(self):
        obj, clock, selector, made, threads = self.make(); obj.start(); threads[0].finish=False
        clock.now=20; self.assertFalse(obj.stop(20)); self.assertEqual(threads[0].join_timeouts,[0])
        self.assertFalse(obj.clear()); self.assertEqual(obj.failure_code,'relay-cleanup-incomplete')
        threads[0].finish=True; self.assertTrue(obj.stop(20)); self.assertIsNotNone(obj.failure_code)
        obj, _, _, made, _ = self.make(); obj.start(); made[0].close_error=True
        self.assertFalse(obj.stop(20)); self.assertFalse(obj.clear()); made[0].close_error=False
        self.assertTrue(obj.stop(20)); self.assertEqual(obj.failure_code,'relay-cleanup-incomplete')
    def image_io(self):
        obj = object.__new__(image.ImageIO); clock=Clock(); transport.IO.__init__(obj,ROOT,transport.Budget(clock),True)
        obj.names={'container':'owned-container','network':'owned-network','volume':'owned-volume'}; obj.relays=[]; obj.relay=None; obj.endpoint=None
        obj.ports=set(); obj.created=[]; obj.lock_fd=None; obj.env={}; obj.identities={}; obj.token='owner'
        obj.owner=lambda kind: CID if kind=='container' else NID
        return obj,clock
    def test_image_launch_retains_internal_network_all_caps_and_no_docker_publication(self):
        obj,_=self.image_io(); obj.arch='amd64'; obj.image_id='sha256:'+'d'*64; created={}; steps=[]
        obj.create=lambda kind,args:created.update({kind:args})
        def docker(action,*args,**kwargs):
            if action=='start-packaged-image': return 0,b''
            if action=='internal-network': return 0,b'true'
            if action=='official-components-only': return 0,'\n'.join('f '+name for name in sorted(image.EXPECTED_FILES)).encode()
            if action=='native-packaged-elf':
                header=bytearray(20); header[:6]=b'\x7fELF\x02\x01'; header[18]=62
                return 0,' '.join(str(value) for value in header).encode()
            self.fail('unexpected Docker action')
        obj.docker=docker; obj.resolve_port=lambda:steps.append('relay'); obj.ready=lambda:steps.append('ready')
        obj.start(); self.assertEqual(steps,['relay','ready']); self.assertIn('--internal',created['network'])
        args=created['container']; self.assertNotIn('-p',args); self.assertNotIn('--publish',args)
        for flag,value in (('--network','owned-network'),('--cpus','2'),('--memory','1g'),('--pids-limit','256'),('--log-driver=none',None)):
            self.assertIn(flag,args)
            if value is not None:self.assertEqual(args[args.index(flag)+1],value)
        self.assertIn('--pull=never',args); self.assertEqual(args[args.index('--ulimit')+1],'core=0')
    def test_image_endpoint_projections_are_narrow_and_cross_checked(self):
        obj,_=self.image_io(); container,network=projections(); calls=[]
        def docker(action,args,**kwargs):
            calls.append((action,args,kwargs))
            return 0,json.dumps(container if action=='owned-container-endpoint' else network).encode()
        obj.docker=docker; self.assertEqual(obj.owned_endpoint(),endpoint())
        self.assertEqual([call[0] for call in calls],['owned-container-endpoint','owned-network-endpoint'])
        for _,args,kwargs in calls:
            self.assertIn('--format',args); self.assertNotIn('Env',' '.join(args)); self.assertNotIn('logs',args)
            self.assertEqual(kwargs['timeout'],2)
    def test_image_endpoint_owner_birth_verification_precedes_metadata(self):
        obj,_=self.image_io(); calls=[]
        def owner(kind):
            calls.append(kind)
            if kind=='network': raise transport.BoundaryError('owned-resource-replaced')
            return CID
        obj.owner=owner; obj.docker=lambda *a,**k:self.fail('metadata must not bypass owner verification')
        with self.assertRaisesRegex(transport.BoundaryError,'^owned-resource-replaced$'): obj.owned_endpoint()
        self.assertEqual(calls,['container','network']); self.assertFalse(obj.relays)
    def test_restart_closes_old_listener_and_revalidates_new_endpoint_before_new_relay(self):
        obj,clock=self.image_io(); targets=iter((endpoint(),endpoint('172.18.0.3'))); obj.owned_endpoint=lambda:next(targets)
        made=[]; events=[]
        def factory(target,deadline,callback):
            value,_,_,_,_=self.make(ports=(41000+len(made),),deadline=deadline)
            value.endpoint=target; value.clock=callback; made.append(value); return value
        obj.relay_factory=factory; obj.docker=lambda action,*a,**k:events.append(action)
        obj.ready=lambda:events.append('ready')
        with patch.object(image,'closed_port',return_value=True) as refused:
            obj.resolve_port(); obj.restart_and_resolve_port()
            self.assertEqual(refused.call_args.args[0],41000)
        self.assertTrue(made[0].clear()); self.assertEqual(made[1].endpoint.address,'172.18.0.3')
        self.assertEqual(obj.port,41001); self.assertEqual(obj.ports,{41000,41001})
        self.assertEqual(events,['restart-owned-container','ready']); self.assertTrue(made[1].stop(20))
    def test_restart_refusal_failure_is_sticky_and_does_not_restart_container(self):
        obj,_=self.image_io(); value,*_=self.make(); value.start(); obj.relays=[value]; obj.relay=value
        obj.docker=lambda *a,**k:self.fail('must not restart after unproven relay closure')
        with patch.object(image,'closed_port',return_value=False), self.assertRaisesRegex(transport.BoundaryError,'^relay-cleanup-incomplete$'):
            obj.restart_and_resolve_port()
        self.assertEqual(value.failure_code,'relay-cleanup-incomplete')
    def test_cleanup_includes_relay_workers_fds_sticky_failure_and_every_allocated_port(self):
        obj,_=self.image_io(); value,*_=self.make(ports=(5432,41000)); value.start(); value.fail('relay-worker-failed')
        obj.relays=[value]; obj.relay=value; obj.ports.update(value.ports)
        with patch.object(image,'closed_port',return_value=True) as refused:
            result=obj.cleanup()
        self.assertTrue(result['no_active_handles']); self.assertFalse(result['no_sticky_command_failure'])
        self.assertEqual({call.args[0] for call in refused.call_args_list},{5432,41000})
        self.assertEqual(obj.budget.cleanup_deadline,20)
    def test_image_cleanup_cannot_pass_with_a_live_relay_worker_or_selector(self):
        obj,_=self.image_io(); value,_,_,_,threads=self.make(); value.start(); threads[0].finish=False
        obj.relays=[value]; obj.relay=value; obj.ports.update(value.ports)
        with patch.object(image,'closed_port',return_value=True): result=obj.cleanup()
        self.assertFalse(result['no_active_handles']); self.assertFalse(result['no_sticky_command_failure'])
        threads[0].finish=True; self.assertTrue(value.stop(20))
    def test_monitor_rejects_changed_endpoint_with_existing_aggregate_deadline(self):
        obj,_=self.image_io(); obj.endpoint=endpoint(); obj.owned_endpoint=lambda:endpoint('172.18.0.3')
        with self.assertRaisesRegex(transport.BoundaryError,'^relay-endpoint-changed$'): obj.monitor()

if __name__ == '__main__': unittest.main()
