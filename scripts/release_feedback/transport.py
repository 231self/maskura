# SPDX-License-Identifier: Apache-2.0
"""Portable reviewed absolute HTTP and captured-child algorithms (see PROVENANCE).

Normal imports only. No temp dependencies, AST inheritance or import-time actions.
"""
import contextlib
import errno
import http.client
import io
import os
import select
import signal
import socket
import subprocess
import threading
import time
from .cases import Reply

class BoundaryError(Exception): pass

class Budget:
    def __init__(self, clock=time.monotonic):
        self.clock = clock; self.origin = clock(); self.ceilings = []; self.cleanup_deadline = None
    def begin_cleanup(self):
        if self.cleanup_deadline is None: self.cleanup_deadline = min(self.clock() + 20, self.origin + 1800)
        return self.cleanup_deadline
    def cleanup_remaining(self):
        value = self.begin_cleanup() - self.clock()
        if value <= 0: raise BoundaryError('cleanup-deadline')
        return value
    def remaining(self, cleanup=False):
        if cleanup: return self.cleanup_remaining()
        value = 1780 - (self.clock() - self.origin)
        if value <= 0: raise BoundaryError('overall-deadline')
        if self.ceilings:
            deadline, category = min(self.ceilings, key=lambda item: item[0])
            value = min(value, deadline - self.clock())
            if value <= 0: raise BoundaryError(category)
        return value
    def limit(self, seconds, cleanup=False): return min(seconds, self.remaining(cleanup))
    def stage(self): return self.clock() + self.limit(1200)
    def check_stage(self, deadline):
        self.remaining()
        if self.clock() >= deadline: raise BoundaryError('stage-deadline')
    @contextlib.contextmanager
    def until(self, deadline, category):
        item = (deadline, category); self.ceilings.append(item)
        try:
            self.remaining(); yield; self.remaining()
        finally: self.ceilings.remove(item)
    @contextlib.contextmanager
    def scope(self, seconds, category):
        with self.until(self.clock() + self.limit(seconds), category): yield

class AbsoluteTransport:
    def __init__(self, raw, deadline, clock, guard, waiter=select.select):
        self.raw = raw; self.deadline = deadline; self.clock = clock; self.guard = guard; self.waiter = waiter
        self.files = 0; self.released = False; self.forced = False; self.received = 0
    def check(self):
        if self.forced: raise BoundaryError('http-socket-closed')
        if self.clock() >= self.deadline: raise BoundaryError('http-absolute-deadline')
        self.guard()
        if self.clock() >= self.deadline: raise BoundaryError('http-absolute-deadline')
    def wait(self, write=False):
        self.check(); remaining = self.deadline - self.clock()
        ready = self.waiter([] if write else [self.raw], [self.raw] if write else [], [], min(0.05, remaining))
        self.check(); return bool(ready[1] if write else ready[0])
    def connect(self, address):
        self.check(); self.raw.setblocking(False); result = self.raw.connect_ex(address)
        allowed = (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, errno.EINTR)
        if result not in allowed: raise BoundaryError('http-connect-failed')
        while result != 0:
            if not self.wait(True): continue
            result = self.raw.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if result not in allowed: raise BoundaryError('http-connect-failed')
        self.check()
    def sendall(self, data):
        view = memoryview(data)
        while view:
            self.check()
            try: sent = self.raw.send(view)
            except (BlockingIOError, InterruptedError): self.wait(True); continue
            if sent <= 0: raise BoundaryError('http-write-failed')
            view = view[sent:]; self.check()
    def readinto(self, target):
        while True:
            self.check()
            try: count = self.raw.recv_into(target)
            except (BlockingIOError, InterruptedError): self.wait(); continue
            self.received += count
            if self.received > 2 * 2**20: raise BoundaryError('http-wire-bound')
            self.check(); return count
    def makefile(self, mode, buffering=None):
        if mode != 'rb': raise BoundaryError('unexpected-http-file-mode')
        self.check(); self.files += 1; return io.BufferedReader(DeadlineFile(self), buffer_size=8192)
    def close(self):
        self.released = True
        if self.files == 0: self.force_close()
    def file_closed(self):
        self.files -= 1
        if self.released and self.files == 0: self.force_close()
    def force_close(self):
        if self.forced: return
        self.forced = True
        try: self.raw.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        finally: self.raw.close()
class DeadlineFile(io.RawIOBase):
    def __init__(self, transport): super().__init__(); self.transport = transport
    def readable(self): return True
    def readinto(self, buffer): return self.transport.readinto(buffer)
    def close(self):
        if not self.closed: super().close(); self.transport.file_closed()

class Child:
    def __init__(self, process, entry):
        self.process = process; self.pid = process.pid; self.entry = entry
        self.reaped = False; self.group_absent = False; self.retired = False
        self.readers = []; self.signals = set(); self.cleanup_failed_ever = False

class IO:
    def __init__(self, root, budget=None, permit=False):
        self.root = root; self.budget = budget or Budget(); self.permit = permit
        self.env = {}; self.children = {}; self.active = {}; self.commands = []
        self.command_failure_category = None; self.cleaning = False; self.cancelled = False
        self.http_transport = None; self.http_attempts = 0; self.port = None; self.access = self.secret = None
        self.stage_deadline = self.budget.stage()
    def allowed(self):
        if self.permit is not True: raise BoundaryError('explicit-execute-guard-required')
    def guard(self):
        self.allowed(); self.budget.remaining(self.cleaning)
        if not self.cleaning:
            if self.cancelled: raise BoundaryError('supervisor-interrupted')
            if self.command_failure_category: raise BoundaryError(self.command_failure_category)
            if self.budget.cleanup_deadline is not None: raise BoundaryError('work-ended-for-cleanup')
            self.budget.check_stage(self.stage_deadline)
    def _spawn(self, args, entry):
        self.allowed(); factory = getattr(self, 'popen_factory', subprocess.Popen)
        process = factory(args, env=self.env, cwd=self.root, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        if type(process.pid) is not int or process.pid <= 0 or process.pid in self.active: raise BoundaryError('invalid-captured-child')
        child = Child(process, entry); self.children[id(process)] = child; self.active[process.pid] = process
        return child
    def _owned(self, process):
        self.allowed(); child = self.children.get(id(process))
        if child is None or child.process is not process or process.pid != child.pid: raise BoundaryError('uncaptured-child-handle')
        return child
    def group_alive(self, process):
        child = self._owned(process)
        if child.group_absent: return False
        try: os.killpg(child.pid, 0); return True
        except ProcessLookupError: child.group_absent = True; return False
    def _sample(self, child):
        if not child.reaped and child.process.poll() is not None: child.reaped = True
        if not child.group_absent and not self.group_alive(child.process): child.group_absent = True
        child.entry.update(child_reaped=child.reaped, group_absent=child.group_absent)
    def _pause(self, seconds):
        if seconds > 0: getattr(self, 'pause', time.sleep)(seconds)
    def _join_readers(self, child, wait=False):
        for reader in child.readers:
            timeout = 0
            if wait:
                try: timeout = min(0.1, self.budget.cleanup_remaining())
                except BoundaryError: timeout = 0
            try: reader.join(timeout=timeout)
            except RuntimeError:
                if reader.is_alive(): return False
        return not any(reader.is_alive() for reader in child.readers)
    def _finish(self, child):
        readers_done = self._join_readers(child)
        child.entry.update(child_reaped=child.reaped, group_absent=child.group_absent, readers_joined=readers_done)
        if child.reaped and child.group_absent and readers_done:
            for stream in (child.process.stdin, child.process.stdout, child.process.stderr):
                if stream is not None: stream.close()
            child.retired = True; self.active.pop(child.pid, None); child.entry['handle_retired'] = True; return True
        return False
    def _failed_stop(self, child):
        child.cleanup_failed_ever = True; child.entry['cleanup_failed_ever'] = True
        if self.command_failure_category is None: self.command_failure_category = 'owned-child-cleanup-incomplete'
        return False
    def stop(self, process):
        child = self._owned(process)
        if child.retired: return True
        try: self._sample(child)
        except BaseException: return self._failed_stop(child)
        if self._finish(child): return True
        self.budget.begin_cleanup()
        if self.http_transport is not None: self.http_transport.force_close()
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try: self.budget.cleanup_remaining()
            except BoundaryError: break
            if not child.group_absent and sig not in child.signals:
                try: os.killpg(child.pid, sig)
                except ProcessLookupError: child.group_absent = True
                except OSError: return self._failed_stop(child)
                child.signals.add(sig)
            try: self._sample(child)
            except BaseException: return self._failed_stop(child)
            if self._finish(child): return True
            until = min(self.budget.clock() + 2, self.budget.begin_cleanup())
            while self.budget.clock() < until:
                self._pause(min(0.05, until - self.budget.clock()))
                try: self._sample(child)
                except BaseException: return self._failed_stop(child)
                if self._finish(child): return True
        try: self._sample(child)
        except BaseException: return self._failed_stop(child)
        self._join_readers(child, wait=True)
        if self._finish(child): return True
        return self._failed_stop(child)
    def command(self, action, args, timeout=30, check=True):
        self.allowed(); self.guard(); began = self.budget.clock()
        deadline = began + self.budget.limit(timeout, self.cleaning)
        child = None; output = bytearray(); state = {'limit': False, 'reader_failed': False}
        failure = None; result = None; clean = False
        entry = dict(action=action, passed=False, group_absent=False, child_reaped=False,
                     handle_retired=False, cleanup_failed_ever=False, child_captured=False)
        def drain(stream, keep):
            try:
                while chunk := stream.read(4096):
                    if keep:
                        if len(output) + len(chunk) <= 65536: output.extend(chunk)
                        else: state['limit'] = True
            except BaseException: state['reader_failed'] = True
            finally: stream.close()
        try:
            child = self._spawn(args, entry); entry['child_captured'] = True
            factory = getattr(self, 'reader_factory', threading.Thread)
            for stream, keep in ((child.process.stdout, True), (child.process.stderr, False)):
                reader = factory(target=drain, args=(stream, keep), daemon=True); child.readers.append(reader); reader.start()
            while True:
                self.guard()
                if self.budget.clock() >= deadline: raise BoundaryError('command-deadline')
                self._sample(child)
                if child.reaped: break
                if state['limit']: raise BoundaryError('command-output-bound')
                self._pause(min(0.05, deadline - self.budget.clock(), self.budget.remaining(self.cleaning)))
            if not child.group_absent: raise BoundaryError('residual-owned-process-group')
            while not self._join_readers(child):
                self.guard()
                if self.budget.clock() >= deadline: raise BoundaryError('command-drain-bound')
                self._pause(min(0.05, deadline - self.budget.clock(), self.budget.remaining(self.cleaning)))
            if state['limit'] or state['reader_failed']: raise BoundaryError('command-output-bound')
            if check and child.process.returncode != 0: raise BoundaryError('command-nonzero')
            result = (child.process.returncode, bytes(output)); entry['passed'] = child.process.returncode == 0
        except BaseException as exc:
            failure = exc; entry['failure_category'] = str(exc) if isinstance(exc, BoundaryError) else 'command-internal-error'
            if self.command_failure_category is None: self.command_failure_category = entry['failure_category']
        finally:
            if child is not None:
                try: clean = self.stop(child.process)
                except BaseException: clean = self._failed_stop(child)
                if not clean:
                    self._failed_stop(child); entry['passed'] = False; entry.setdefault('failure_category', 'owned-child-cleanup-incomplete')
                entry.update(child_reaped=child.reaped, group_absent=child.group_absent, handle_retired=child.retired, cleanup_failed_ever=child.cleanup_failed_ever)
            else: clean = True
            self.commands.append(entry)
            if not clean and self.command_failure_category is None: self.command_failure_category = 'owned-child-cleanup-incomplete'
        if failure is not None: raise failure
        if not clean: raise BoundaryError('owned-child-cleanup-incomplete')
        return result
    def request(self, method, path, body=None, headers=None, authenticated=True, wrong_secret=False):
        self.allowed()
        if body is not None and len(body) > 2**20: raise BoundaryError('request-body-bound')
        started = self.budget.clock(); timeout = self.budget.limit(8)
        deadline = min(started + timeout, self.stage_deadline)
        if hasattr(self, 'ready_deadline'): deadline = min(deadline, self.ready_deadline)
        if self.port is None or not path.startswith('/') or '\r' in path or '\n' in path: raise BoundaryError('request-target-invalid')
        fields = {'Connection': 'close'}
        if authenticated: fields.update({'x-maskura-access-key': self.access, 'x-maskura-secret-key': 'invalid-synthetic-secret' if wrong_secret else self.secret})
        fields.update(headers or {}); response = connection = transport = None
        try:
            with self.budget.until(deadline, 'http-absolute-deadline'):
                self.guard(); self.budget.check_stage(self.stage_deadline)
                raw = self.socket_factory() if hasattr(self, 'socket_factory') else socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                transport = AbsoluteTransport(raw, deadline, self.budget.clock, self.guard,
                    self.socket_waiter if hasattr(self, 'socket_waiter') else select.select)
                self.http_transport = transport; self.http_attempts += 1; transport.connect(('127.0.0.1', self.port))
                connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=timeout); connection.sock = transport
                connection.request(method, path, body=body, headers=fields)
                response = connection.getresponse(); data = response.read(2**20 + 1)
                if len(data) > 2**20: raise BoundaryError('response-body-bound')
                self.budget.remaining(); self.guard()
                result = Reply(response.status, {k.lower(): v for k, v in response.getheaders()}, data)
                self.guard(); self.budget.check_stage(self.stage_deadline)
            return result
        except BoundaryError: raise
        except BaseException: raise BoundaryError('http-transport-error') from None
        finally:
            if transport is not None: transport.force_close()
            self.http_transport = None
            if response is not None: response.close()
            if connection is not None: connection.close()
