# SPDX-License-Identifier: Apache-2.0
"""Closed receipts and fail-closed native-child/index qualification binding."""
import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from .cases import IMPLEMENTED
from .signed_cases import SIGNED_CASES
from .image import strict_json

SCOPE = 'packaged-filestore-core'
PHASES = ('candidate', 'native-child', 'published-replay')
EXCLUSIONS = ('memory', 'direct-s3', 'managed', 'postgres', 'protected-pipeline', 'process-recovery', 'unmodified-sdk', 'reporter-environment',
              'signed-multipart-initiation-decoding-snapshot-cleanup')
CODE = ('__init__.py', 'cases.py', 'signing.py', 'signed_cases.py', 'transport.py', 'image.py', 'receipts.py')

def require(condition):
    if not condition: raise ValueError('release-feedback-receipt-invalid')
def digest(value): require(isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value)); return value
def sha(body): return hashlib.sha256(body).hexdigest()
def harness_sha():
    root = Path(__file__).resolve().parent
    values = {name: sha((root / name).read_bytes()) for name in CODE}
    values['../release-feedback.py'] = sha((root.parent / 'release-feedback.py').read_bytes())
    values['../release-feedback-receipts.py'] = sha((root.parent / 'release-feedback-receipts.py').read_bytes())
    return sha(''.join(n + '\0' + d + '\n' for n, d in sorted(values.items())).encode())
def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 2**20 and info.st_nlink == 1)
        body = os.read(fd, 2**20 + 1); require(len(body) == info.st_size); return body
    finally: os.close(fd)
def write(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
def identity(source, version, arch):
    require(isinstance(source, str) and re.fullmatch('[0-9a-f]{40}', source))
    require(isinstance(version, str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version))
    require(arch in ('amd64', 'arm64'))
def validate_report(value, source, version, arch, phase, expected_harness):
    identity(source, version, arch)
    expected_keys = {'schema_version', 'scope', 'status', 'source_sha', 'version', 'architecture', 'image_id', 'phase', 'digest', 'harness_sha256', 'cases', 'cleanup', 'full_feedback_matrix_passed', 'scope_exclusions'}
    require(set(value) == expected_keys)
    require(value['schema_version'] == 1 and type(value['schema_version']) is int and value['scope'] == SCOPE and value['status'] == 'passed')
    require((value['source_sha'], value['version'], value['architecture'], value['phase'], value['harness_sha256']) == (source, version, arch, phase, expected_harness))
    digest(value['image_id']); require(value['full_feedback_matrix_passed'] is False and value['scope_exclusions'] == list(EXCLUSIONS))
    if phase == 'published-replay': digest(value['digest'])
    else: require(value['digest'] is None)
    rows = value['cases']; require(isinstance(rows, list) and len(rows) == 31)
    require(all(isinstance(row, dict) and set(row) == {'case', 'passed'} and row['passed'] is True for row in rows))
    require(len({row['case'] for row in rows}) == 31 and {row['case'] for row in rows} == set(IMPLEMENTED + SIGNED_CASES))
    keys = {'owned_resources_absent', 'allocated_ports_kernel_refused', 'captured_children_reaped', 'no_active_handles', 'no_sticky_command_failure', 'lock_released', 'cleanup_within_shared_reserve'}
    require(set(value['cleanup']) == keys and all(value['cleanup'][key] is True for key in keys))
    return value
def bound_manifest(raw, expected_digest):
    digest(expected_digest)
    # Docker's --raw stdout can append one LF; do not canonicalize/reformat JSON.
    candidates = [raw] + ([raw[:-1]] if raw.endswith(b'\n') else [])
    matches = [body for body in candidates if 'sha256:' + sha(body) == expected_digest]
    require(len(matches) == 1); return strict_json(matches[0])
def seal(local, published, raw_manifest, source, version, arch, expected_harness):
    validate_report(local, source, version, arch, 'native-child', expected_harness)
    validate_report(published, source, version, arch, 'published-replay', expected_harness)
    require(local['image_id'] == published['image_id'])
    child = bound_manifest(raw_manifest, published['digest'])
    require(type(child.get('schemaVersion')) is int and child['schemaVersion'] == 2 and child.get('mediaType') in ('application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'))
    require(child.get('config', {}).get('digest') == local['image_id'] and 'manifests' not in child)
    return dict(schema_version=1, scope=SCOPE, phase='qualified-native-child', source_sha=source, version=version,
        architecture=arch, image_id=local['image_id'], digest=published['digest'], harness_sha256=expected_harness,
        case_count=31, pre_push_passed=True, published_replay_passed=True, full_feedback_matrix_passed=False)
def children(receipts, source, version, expected_harness):
    require(len(receipts) == 2); result = {}
    keys = {'schema_version', 'scope', 'phase', 'source_sha', 'version', 'architecture', 'image_id', 'digest', 'harness_sha256', 'case_count', 'pre_push_passed', 'published_replay_passed', 'full_feedback_matrix_passed'}
    for row in receipts:
        require(set(row) == keys); arch = row['architecture']; identity(source, version, arch)
        require(type(row['schema_version']) is int and row['schema_version'] == 1 and row['scope'] == SCOPE and row['phase'] == 'qualified-native-child')
        require((row['source_sha'], row['version'], row['harness_sha256']) == (source, version, expected_harness))
        require(arch not in result and type(row['case_count']) is int and row['case_count'] == 31 and row['pre_push_passed'] is True and row['published_replay_passed'] is True and row['full_feedback_matrix_passed'] is False)
        digest(row['digest']); digest(row['image_id']); result[arch] = row
    require(set(result) == {'amd64', 'arm64'} and len({r['digest'] for r in result.values()}) == 2 and len({r['image_id'] for r in result.values()}) == 2)
    return result
def verify_index(raw, canonical, qualified):
    value = bound_manifest(raw, canonical)
    require(type(value.get('schemaVersion')) is int and value['schemaVersion'] == 2 and value.get('mediaType') in ('application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json'))
    entries = value.get('manifests'); require(isinstance(entries, list) and len(entries) == 2)
    actual = {}
    for row in entries:
        p = row.get('platform', {}); arch = p.get('architecture')
        require(p.get('os') == 'linux' and arch in qualified and arch not in actual)
        require(row.get('digest') == qualified[arch]['digest']); actual[arch] = row['digest']
    require(set(actual) == {'amd64', 'arm64'}); return True
def push_digest(raw):
    require(len(raw) <= 2**20)
    values = re.findall(rb'^\S+: digest: (sha256:[0-9a-f]{64}) size: [0-9]+\s*$', raw, re.M)
    require(len(values) == 1); return values[0].decode()

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('push-digest', 'seal', 'children', 'index', 'canonical'))
    for name in ('local', 'published', 'manifest', 'source', 'version', 'arch', 'output', 'canonical', 'github-output'): parser.add_argument('--' + name)
    parser.add_argument('--receipt', action='append', default=[])
    args = parser.parse_args(argv)
    try:
        if args.action == 'push-digest': print(push_digest(read(args.manifest))); return 0
        if args.action == 'canonical':
            print(digest(strict_json(read(args.manifest))['digest'])); return 0
        expected = harness_sha()
        if args.action == 'seal':
            value = seal(strict_json(read(args.local)), strict_json(read(args.published)), read(args.manifest), args.source, args.version, args.arch, expected)
        else:
            value = children([strict_json(read(p)) for p in args.receipt], args.source, args.version, expected)
            if args.action == 'index': verify_index(read(args.manifest), args.canonical, value)
        if args.output: write(args.output, value)
        if args.github_output:
            with open(args.github_output, 'a', encoding='utf-8') as out:
                if args.action == 'index': out.write('canonical=' + digest(args.canonical) + '\n')
                else:
                    for arch in ('amd64', 'arm64'): out.write(arch + '=' + value[arch]['digest'] + '\n')
        return 0
    except BaseException:
        print('release-feedback-receipt-invalid'); return 1
