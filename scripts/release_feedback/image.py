# SPDX-License-Identifier: Apache-2.0
"""Linux native packaged-image boundary. Local IDs only; never pulls/pushes."""
import errno
import fcntl
import json
import os
import platform
import re
import secrets
import shutil
import socket
import stat
import time
from pathlib import Path
from .transport import IO, BoundaryError
from .signing import streaming

LABEL = 'maskura.release.feedback'
COMPONENTS = ('noop', 'pii-default', 'email-detect', 'ssn-detect', 'card-detect', 'envelope-encrypt', 'stable-encrypt')
EXPECTED_FILES = {name + suffix for name in COMPONENTS for suffix in ('.component.wasm', '.plugin.toml')}
ID = re.compile(r'sha256:[0-9a-f]{64}')

def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise BoundaryError('json-duplicate-field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)
def integer(value):
    if not isinstance(value, str) or not value.isascii() or not value.isdigit() or len(value) > 20: raise BoundaryError('numeric-metadata-shape')
    return int(value)
def closed_port(port, timeout=0.25):
    if not 0 < timeout <= 0.25: return False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(timeout); return probe.connect_ex(('127.0.0.1', port)) == errno.ECONNREFUSED
    except OSError: return False
def root_usage(root):
    size = entries = 0
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            info = (Path(directory) / name).lstat(); entries += 1
            if stat.S_ISLNK(info.st_mode): raise BoundaryError('owned-root-symlink')
            if stat.S_ISREG(info.st_mode): size += info.st_size
    return size, entries

class ImageIO(IO):
    def __init__(self, root, image_id, arch, source, version, permit=False, budget=None):
        super().__init__(root, budget, permit)
        if not ID.fullmatch(image_id): raise BoundaryError('actual-image-id-required')
        self.image_id = image_id; self.arch = arch; self.source = source; self.version = version
        self.token = secrets.token_hex(16); self.names = {kind: 'maskura-feedback-' + kind + '-' + self.token for kind in ('container', 'volume', 'network')}
        self.created = []; self.identities = {}; self.ports = set(); self.lock_fd = None
        self.running = False; self.in_monitor = False; self.last_monitor = -1e30; self.docker_root = None
        for name in ('home', 'tmp', 'docker-config'): (root / name).mkdir(mode=0o700)
        self.access = 'feedback-' + secrets.token_hex(12); self.secret = secrets.token_urlsafe(32)
        self.env = dict(PATH='/usr/bin:/bin:/usr/local/bin', HOME=str(root / 'home'), TMPDIR=str(root / 'tmp'),
            DOCKER_CONFIG=str(root / 'docker-config'), DOCKER_HOST='unix:///var/run/docker.sock',
            MASKURA_ROOT_USER=self.access, MASKURA_ROOT_PASSWORD=self.secret,
            AWS_EC2_METADATA_DISABLED='true', OTEL_SDK_DISABLED='true')
    def guard(self):
        try:
            super().guard()
            if not self.cleaning:
                for path in (self.root, self.docker_root or self.root):
                    if shutil.disk_usage(path).free < 12 * 2**30: raise BoundaryError('host-12GiB-floor')
                size, entries = root_usage(self.root)
                if size > 2**20 or entries > 128: raise BoundaryError('owned-attempt-cap')
                if self.running and not self.in_monitor and self.budget.clock() - self.last_monitor >= 1:
                    self.monitor()
        except BaseException:
            if self.http_transport is not None: self.http_transport.force_close()
            raise
    def docker(self, action, args, timeout=30, check=True):
        return self.command(action, ['docker', *args], timeout, check)
    @staticmethod
    def inventory_args(kind, name):
        if kind not in ('container', 'volume', 'network') or not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]{0,160}', name): raise BoundaryError('owned-name-shape')
        field = '.Names' if kind == 'container' else '.Name'; identity = '.Name' if kind == 'volume' else '.ID'
        fmt = '{"name":{{json ' + field + '}},"id":{{json ' + identity + '}}}'
        return [kind, 'ls', *(['--all'] if kind == 'container' else []), *(['--no-trunc'] if kind != 'volume' else []), '--filter', 'name=' + name, '--format', fmt]
    def inventory(self, kind):
        name = self.names[kind]
        code, raw = self.docker('inventory-' + kind, self.inventory_args(kind, name), timeout=2, check=False)
        if code != 0: raise BoundaryError('successful-inventory-required')
        rows = []; seen = set()
        for line in raw.splitlines():
            row = strict_json(line)
            if set(row) != {'name', 'id'} or not all(isinstance(v, str) for v in row.values()): raise BoundaryError('inventory-shape')
            if row['name'] in seen: raise BoundaryError('inventory-ambiguous')
            seen.add(row['name'])
            if not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]{0,160}', row['name']): raise BoundaryError('inventory-name')
            if kind == 'volume':
                if row['id'] != row['name']: raise BoundaryError('inventory-identity')
            elif not re.fullmatch('[0-9a-f]{64}', row['id']): raise BoundaryError('inventory-identity')
            if row['name'] == name: rows.append(row['id'])
        if len(rows) > 1: raise BoundaryError('inventory-ambiguous')
        return rows[0] if rows else None
    def owner(self, kind):
        identity = self.inventory(kind)
        if identity is None: raise BoundaryError('owned-resource-disappeared')
        labels = '.Config.Labels' if kind == 'container' else '.Labels'
        created = '.CreatedAt' if kind == 'volume' else '.Created'
        ident = '.Name' if kind == 'volume' else '.Id'
        fmt = '{"name":{{json .Name}},"id":{{json ' + ident + '}},"owner":{{json (index ' + labels + ' "' + LABEL + '")}},"created":{{json ' + created + '}}}'
        _, raw = self.docker('owner-' + kind, [kind, 'inspect', identity, '--format', fmt], timeout=2)
        value = strict_json(raw)
        if set(value) != {'name', 'id', 'owner', 'created'}: raise BoundaryError('ownership-shape')
        name = value['name'].removeprefix('/') if kind == 'container' else value['name']
        if name != self.names[kind] or value['id'] != identity or value['owner'] != self.token or not isinstance(value['created'], str) or not 1 <= len(value['created']) <= 64: raise BoundaryError('ownership-mismatch')
        bound = (identity, value['created'])
        if kind in self.identities and self.identities[kind] != bound: raise BoundaryError('owned-resource-replaced')
        self.identities[kind] = bound
        return identity
    def create(self, kind, args):
        if self.inventory(kind) is not None: raise BoundaryError('owned-name-collision')
        self.created.append(kind)
        self.docker('create-' + kind, [kind, 'create', *args]); self.owner(kind)
    def acquire_existing_lock(self, path):
        self.guard()
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK); self.lock_fd = fd
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1: raise BoundaryError('existing-lock-ownership')
        deadline = self.budget.clock() + self.budget.limit(600)
        while True:
            self.guard()
            try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); return
            except BlockingIOError:
                if self.budget.clock() >= deadline: raise BoundaryError('existing-lock-600s')
                time.sleep(min(0.1, deadline - self.budget.clock()))
    def preflight(self, published_ref=None):
        native = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
        if platform.system() != 'Linux' or native != self.arch: raise BoundaryError('native-linux-runner-required')
        _, raw = self.docker('daemon-platform', ['info', '--format', '{"os":{{json .OSType}},"arch":{{json .Architecture}},"root":{{json .DockerRootDir}}}'])
        daemon = strict_json(raw); aliases = {'x86_64': 'amd64', 'aarch64': 'arm64', 'amd64': 'amd64', 'arm64': 'arm64'}
        if daemon.get('os') != 'linux' or aliases.get(daemon.get('arch')) != self.arch: raise BoundaryError('native-daemon-platform')
        self.docker_root = Path(daemon['root'])
        if not self.docker_root.is_absolute(): raise BoundaryError('docker-host-root-required')
        self.guard()
        fmt = '{"id":{{json .Id}},"os":{{json .Os}},"arch":{{json .Architecture}},"revision":{{json (index .Config.Labels "org.opencontainers.image.revision")}},"version":{{json (index .Config.Labels "org.opencontainers.image.version")}},"digests":{{json .RepoDigests}}}'
        _, raw = self.docker('bound-local-image', ['image', 'inspect', self.image_id, '--format', fmt])
        value = strict_json(raw)
        if (value.get('id'), value.get('os'), value.get('arch'), value.get('revision'), value.get('version')) != (self.image_id, 'linux', self.arch, self.source, 'v' + self.version): raise BoundaryError('image-source-version-platform-binding')
        if published_ref is not None and published_ref not in (value.get('digests') or []): raise BoundaryError('pulled-repodigest-binding')
    def start(self):
        label = LABEL + '=' + self.token
        self.create('network', ['--internal', '--label', label, self.names['network']])
        _, raw = self.docker('internal-network', ['network', 'inspect', self.owner('network'), '--format', '{{json .Internal}}'])
        if strict_json(raw) is not True: raise BoundaryError('internal-network-required')
        self.create('volume', ['--label', label, self.names['volume']])
        self.create('container', ['--pull=never', '--platform=linux/' + self.arch, '--name', self.names['container'],
            '--label', label, '--network', self.names['network'], '--cpus', '2', '--memory', '1g', '--pids-limit', '256',
            '--log-driver=none', '--ulimit', 'core=0', '-p', '127.0.0.1::9000', '--mount', 'type=volume,source=' + self.names['volume'] + ',target=/data',
            '-e', 'MASKURA_ROOT_USER', '-e', 'MASKURA_ROOT_PASSWORD', self.image_id])
        self.docker('start-packaged-image', ['start', self.owner('container')]); self.running = True
        self.resolve_port(); self.ready()
        container = self.owner('container')
        _, raw = self.docker('official-components-only', ['exec', container, 'find', '/app/components', '-mindepth', '1', '-printf', '%y %P\n'])
        if set(raw.decode('ascii').splitlines()) != {'f ' + name for name in EXPECTED_FILES}: raise BoundaryError('official-packaged-components-required')
        _, raw = self.docker('native-packaged-elf', ['exec', container, 'od', '-An', '-t', 'u1', '-N', '20', '/usr/local/bin/maskura-gateway'])
        header = bytes(integer(v) for v in raw.decode('ascii').split())
        if len(header) != 20 or header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != (62 if self.arch == 'amd64' else 183): raise BoundaryError('native-packaged-elf-required')
    def monitor(self):
        self.in_monitor = True
        try:
            with self.budget.scope(2, 'owned-store-monitor-total-deadline'):
                container = self.owner('container')
                _, raw = self.docker('owned-store-metadata-only', ['exec', container, 'find', '/data', '-xdev', '-printf', '%s\n'], timeout=2)
                sizes = [integer(line) for line in raw.decode('ascii').splitlines()]
                if not sizes or len(sizes) > 4096 or sum(sizes) > 64 * 2**20: raise BoundaryError('owned-store-cap')
                _, raw = self.docker('owned-writable-layer-size', ['container', 'inspect', '--size', container, '--format', '{{json .SizeRw}}'], timeout=2)
                if integer(raw.decode('ascii').strip()) > 64 * 2**20: raise BoundaryError('owned-writable-layer-cap')
        finally: self.in_monitor = False; self.last_monitor = self.budget.clock()
    def resolve_port(self):
        _, raw = self.docker('owned-loopback-port', ['container', 'inspect', self.owner('container'), '--format', '{{json (index .NetworkSettings.Ports "9000/tcp")}}'])
        entries = strict_json(raw)
        if not isinstance(entries, list) or len(entries) != 1 or entries[0].get('HostIp') != '127.0.0.1': raise BoundaryError('numeric-loopback-publication')
        port = integer(entries[0]['HostPort'])
        if not 1 <= port <= 65535: raise BoundaryError('owned-port-range')
        self.port = port; self.ports.add(port)
    def ready(self):
        self.ready_deadline = self.budget.clock() + self.budget.limit(45)
        try:
            while True:
                self.guard()
                try:
                    if self.request('GET', '/ready', authenticated=False).status == 200: return
                except BoundaryError as exc:
                    if str(exc) not in ('http-connect-failed', 'http-transport-error'): raise
                if self.budget.clock() >= self.ready_deadline: raise BoundaryError('image-readiness-deadline')
                time.sleep(min(0.1, self.ready_deadline - self.budget.clock()))
        finally: del self.ready_deadline
    def invalid_secret(self, path): return self.request('GET', path, wrong_secret=True)
    def signed_request(self, method, path, body, headers, **kwargs):
        wire, fields = streaming(method, path, '127.0.0.1:' + str(self.port), self.access, self.secret, body, headers, **kwargs)
        return self.request(method, path, wire, fields, authenticated=False)
    def restart_and_resolve_port(self):
        self.docker('restart-owned-container', ['restart', '--time', '2', self.owner('container')])
        self.resolve_port(); self.ready()
    def cleanup(self):
        self.allowed(); self.cleaning = True; self.budget.begin_cleanup(); results = []
        if self.http_transport is not None: self.http_transport.force_close(); self.http_transport = None
        try:
            for process in list(self.active.values()): results.append(self.stop(process))
            for kind in ('container', 'volume', 'network'):
                if kind not in self.created: continue
                try:
                    if self.inventory(kind) is not None:
                        identity = self.owner(kind)
                        self.docker('remove-owned-' + kind, [kind, 'rm', *(['-f'] if kind == 'container' else []), identity], timeout=2)
                    results.append(self.inventory(kind) is None)
                except BaseException: results.append(False)
            refused = True
            for port in self.ports:
                try: refused &= closed_port(port, min(0.25, self.budget.cleanup_remaining()))
                except BaseException: refused = False
        finally:
            if self.lock_fd is not None: os.close(self.lock_fd); self.lock_fd = None
            self.access = self.secret = None
            self.env.pop('MASKURA_ROOT_PASSWORD', None); self.env.pop('MASKURA_ROOT_USER', None)
        return dict(owned_resources_absent=all(results), allocated_ports_kernel_refused=refused,
            captured_children_reaped=all(c.reaped and c.group_absent and c.retired for c in self.children.values()),
            no_active_handles=not self.active, no_sticky_command_failure=self.command_failure_category is None,
            lock_released=self.lock_fd is None, cleanup_within_shared_reserve=self.budget.clock() <= self.budget.begin_cleanup())
