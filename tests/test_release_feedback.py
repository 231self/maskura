# SPDX-License-Identifier: Apache-2.0
"""Cheap actual case/signer/receipt logic. Docker, sockets and processes are forbidden."""
import ast
import base64
import copy
import contextlib
import hashlib
import hmac
import importlib.util
import io
import json
import pathlib
import re
import sys
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch
from urllib.parse import parse_qsl, quote, unquote, urlsplit

ROOT = pathlib.Path(__file__).resolve().parents[1]
TRIPS = {}
AUDIT_ACTIVE = False
AUDIT_TRIPS = []
def deny_external(event, args):
    if AUDIT_ACTIVE and (event.startswith(('socket.', 'subprocess.')) or event in
                         ('os.system', 'os.fork', 'os.posix_spawn', 'os.kill', 'os.killpg', 'resource.setrlimit')):
        AUDIT_TRIPS.append(event)
        raise AssertionError('external action forbidden by audit hook')
sys.addaudithook(deny_external)
sys.path.insert(0, str(ROOT / 'scripts'))
from release_feedback import cases, image, receipts, signing, transport
from release_feedback.signed_cases import SIGNED_CASES, run_signed
from release_feedback_fixture import FakeHTTP, FAULTS, error

def verify_signed(method, target, fields, wire, secret):
    """Independent protocol parser/HMAC verifier, not the production signer helpers."""
    def need(value):
        if not value: raise ValueError('signature-or-framing-invalid')
    need(not {'x-maskura-access-key', 'x-maskura-secret-key'} & set(fields))
    auth = re.fullmatch(r'AWS4-HMAC-SHA256 Credential=([^/]+)/([^,]+), SignedHeaders=([^,]+), Signature=([0-9a-f]{64})', fields['authorization']); need(auth)
    access, scope, signed, previous = auth.groups(); need(bool(access))
    day, region, service, end = scope.split('/'); need((region, service, end) == ('us-east-1', 's3', 'aws4_request'))
    key = ('AWS4' + secret).encode()
    for value in (day, region, service, end): key = hmac.digest(key, value.encode(), 'sha256')
    names = signed.split(';'); need(names == sorted(set(names)))
    mandatory = {'host', 'x-amz-date', 'x-amz-content-sha256', 'content-encoding', 'x-amz-decoded-content-length'}
    mandatory |= {n for n in fields if n.startswith('x-amz-') or n in ('content-type', 'content-md5')}
    need(mandatory <= set(names)); need(fields['x-amz-date'].startswith(day))
    mode = fields['x-amz-content-sha256']; need(mode in ('STREAMING-AWS4-HMAC-SHA256-PAYLOAD', 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER'))
    need(fields['content-encoding'] == 'aws-chunked' and int(fields['content-length']) == len(wire))
    u = urlsplit(target); query = '&'.join(k + '=' + v for k, v in sorted((quote(k, safe='~'), quote(v, safe='~')) for k, v in parse_qsl(u.query, keep_blank_values=True)))
    canonical = method + '\n' + quote(unquote(u.path), safe='/~') + '\n' + query + '\n'
    canonical += ''.join(name + ':' + fields[name] + '\n' for name in names) + '\n' + signed + '\n' + mode
    expected = hmac.new(key, ('AWS4-HMAC-SHA256\n' + fields['x-amz-date'] + '\n' + scope + '\n' + hashlib.sha256(canonical.encode()).hexdigest()).encode(), 'sha256').hexdigest()
    need(hmac.compare_digest(previous, expected)); offset = 0; decoded = bytearray()
    while True:
        line_end = wire.find(b'\r\n', offset); need(line_end >= 0)
        match = re.fullmatch(rb'([0-9A-Fa-f]+);chunk-signature=([0-9a-f]{64})', wire[offset:line_end]); need(match)
        size = int(match[1], 16); signature = match[2].decode(); offset = line_end + 2
        data = wire[offset:offset + size]; need(len(data) == size); offset += size
        to_sign = '\n'.join(('AWS4-HMAC-SHA256-PAYLOAD', fields['x-amz-date'], scope, previous, hashlib.sha256(b'').hexdigest(), hashlib.sha256(data).hexdigest()))
        need(hmac.compare_digest(signature, hmac.new(key, to_sign.encode(), 'sha256').hexdigest())); previous = signature
        if size == 0: break
        need(wire[offset:offset + 2] == b'\r\n'); offset += 2; decoded.extend(data)
    good_checksum = True
    if mode.endswith('-TRAILER'):
        end = wire.find(b'\r\n\r\n', offset); need(end >= 0 and end + 4 == len(wire))
        trailer, signature = wire[offset:end].decode().split('\r\n')
        name, checksum = trailer.split(':', 1); need(name == fields['x-amz-trailer'] == 'x-amz-checksum-sha256')
        key_name, signature_value = signature.split(':', 1); need(key_name == 'x-amz-trailer-signature')
        to_sign = '\n'.join(('AWS4-HMAC-SHA256-TRAILER', fields['x-amz-date'], scope, previous, hashlib.sha256((trailer + '\n').encode()).hexdigest()))
        need(hmac.compare_digest(signature_value, hmac.new(key, to_sign.encode(), 'sha256').hexdigest()))
        good_checksum = base64.b64decode(checksum, validate=True) == hashlib.sha256(decoded).digest()
    else: need(wire[offset:] == b'\r\n')
    need(len(decoded) == int(fields['x-amz-decoded-content-length']))
    return bytes(decoded), good_checksum

class SignedHTTP(FakeHTTP):
    def __init__(self, fault=None): super().__init__(fault); self.signed_checks = []; self.leaked = set()
    def request(self, method, path, *args, **kwargs):
        response = super().request(method, path, *args, **kwargs)
        if self.fault == 'signed-encoding-stored' and method in ('GET', 'HEAD') and path.removeprefix('/maskura/') in self.leaked:
            response.headers['content-encoding'] = 'aws-chunked'
        return response
    def restart_and_resolve_port(self):
        super().restart_and_resolve_port()
        if self.fault == 'signed-restart-metadata-lost' and self.restarts == 2:
            self.objects = {key: (body, content_type, {}) for key, (body, content_type, metadata) in self.objects.items()}
    def signed_request(self, method, path, body, headers, **kwargs):
        wire, fields = signing.streaming(method, path, '127.0.0.1:41000', 'synthetic-access', 'synthetic-secret', body, headers,
            timestamp='20261112T120000Z', **kwargs)
        decoded, valid = verify_signed(method, path, fields, wire, 'synthetic-secret'); self.signed_checks.append((method, path, valid))
        if not valid:
            if self.fault == 'signed-trailer-deletes':
                for key in ('signed-delete-a', 'signed-delete-b'): self.objects.pop(key, None)
            if self.fault != 'signed-trailer-accepted': return error('BadDigest')
        fields.pop('content-encoding', None)
        if self.fault == 'signed-md5-accepted' and 'content-md5' in fields: fields['content-md5'] = base64.b64encode(hashlib.md5(decoded).digest()).decode()
        response = super().request(method, path, wire if self.fault == 'signed-framing-stored' and method == 'PUT' else decoded, fields)
        if self.fault == 'signed-encoding-stored' and method == 'PUT' and '?' not in path:
            self.leaked.add(path.removeprefix('/maskura/'))
        return response

class Clock:
    def __init__(self): self.now = 0
    def __call__(self): return self.now
class Reader:
    def __init__(self, target, args, **kw): self.target = target; self.args = args; self.done = False
    def start(self): self.target(*self.args); self.done = True
    def join(self, timeout=0): pass
    def is_alive(self): return not self.done
class Process:
    pid = 99999999
    def __init__(self):
        self.returncode = None; self.ready = False; self.stdin = None; self.stdout = io.BytesIO(); self.stderr = io.BytesIO()
    def poll(self):
        if self.ready: self.returncode = -9
        return self.returncode

def report(arch='amd64', phase='native-child', child_digest=None, harness=None):
    return dict(schema_version=1, scope=receipts.SCOPE, status='passed', source_sha='a' * 40, version='9.9.9',
        architecture=arch, image_id='sha256:' + ('b' if arch == 'amd64' else 'c') * 64,
        phase=phase, digest=child_digest, harness_sha256=harness or receipts.harness_sha(),
        cases=[dict(case=name, passed=True) for name in cases.IMPLEMENTED + SIGNED_CASES],
        cleanup={key: True for key in ('owned_resources_absent', 'allocated_ports_kernel_refused', 'captured_children_reaped', 'no_active_handles', 'no_sticky_command_failure', 'lock_released', 'cleanup_within_shared_reserve')},
        full_feedback_matrix_passed=False, scope_exclusions=list(receipts.EXCLUSIONS))
def child_receipt(arch='amd64'):
    local = report(arch)
    raw = json.dumps(dict(schemaVersion=2, mediaType='application/vnd.oci.image.manifest.v1+json', config={'digest': local['image_id']}, layers=[])).encode()
    published = report(arch, 'published-replay', 'sha256:' + receipts.sha(raw))
    return receipts.seal(local, published, raw, 'a' * 40, '9.9.9', arch, receipts.harness_sha())

class MainImage(SignedHTTP):
    """Main-level fixture only; never starts an image or represents image evidence."""
    def __init__(self, fault=None):
        super().__init__(fault)
        self.budget = transport.Budget(Clock()); self.commands = []
        self.preflight_error = self.start_error = self.cleanup_error = None
        self.cleanup_value = report()['cleanup']; self.cleanup_calls = 0
    def preflight(self, ref):
        if self.preflight_error is not None: raise self.preflight_error
    def start(self):
        if self.start_error is not None: raise self.start_error
    def cleanup(self):
        self.cleanup_calls += 1
        if self.cleanup_error is not None: raise self.cleanup_error
        return self.cleanup_value

class FeedbackTests(unittest.TestCase):
    def setUp(self):
        self.stack = []
        def forbidden(target):
            def call(*a, **kw):
                TRIPS[target] = TRIPS.get(target, 0) + 1
                raise AssertionError('real Docker/socket/process action forbidden')
            return call
        for target in ('subprocess.Popen', 'subprocess.run', 'socket.socket', 'socket.create_connection',
            'http.client.HTTPConnection', 'urllib.request.urlopen', 'fcntl.flock', 'os.killpg', 'threading.Thread', 'time.sleep', 'signal.signal', 'resource.setrlimit'):
            item = patch(target, new=forbidden(target)); item.start(); self.stack.append(item)
        self.addCleanup(lambda: [item.stop() for item in reversed(self.stack)])
    def invoke_main(self, obj, configure=None):
        global AUDIT_ACTIVE
        spec = importlib.util.spec_from_file_location('release_feedback_entry_test', ROOT / 'scripts/release-feedback.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        captured = []; output = io.StringIO(); errors = io.StringIO()
        def save(path, value): captured.append(copy.deepcopy(value))
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(module, 'ImageIO', return_value=obj))
            stack.enter_context(patch.object(module.tempfile, 'mkdtemp', return_value=str(ROOT / 'not-created-feedback-test')))
            stack.enter_context(patch.object(module.resource, 'setrlimit'))
            stack.enter_context(patch.object(module.signal, 'signal', return_value=None))
            stack.enter_context(patch.object(module, 'write', side_effect=save))
            stack.enter_context(contextlib.redirect_stdout(output)); stack.enter_context(contextlib.redirect_stderr(errors))
            if configure is not None: configure(module, stack)
            before = len(AUDIT_TRIPS); AUDIT_ACTIVE = True
            try:
                code = module.main(['--execute', '--image-id', 'sha256:' + 'b' * 64, '--arch', 'amd64',
                    '--source-sha', 'a' * 40, '--version', '9.9.9', '--phase', 'candidate', '--report', 'ignored.json'])
            finally: AUDIT_ACTIVE = False
            self.assertEqual(AUDIT_TRIPS[before:], [])
        self.assertEqual(len(captured), 1); self.assertEqual(errors.getvalue(), '')
        value = captured[0]; summary = json.loads(output.getvalue())
        self.assertEqual(summary['case_count'], len(value['cases']))
        self.assertEqual(summary['status'], value['status'])
        self.assertFalse(value['full_feedback_matrix_passed']); self.assertFalse(summary['full_feedback_matrix_passed'])
        self.assertEqual(obj.cleanup_calls, 1)
        if code:
            self.assertEqual(value['status'], 'failed')
            self.assertEqual(summary['failure'], value['failure'])
            with self.assertRaises(ValueError):
                receipts.validate_report(value, 'a' * 40, '9.9.9', 'amd64', 'candidate', receipts.harness_sha())
            with self.assertRaises(ValueError):
                receipts.seal(value, value, b'{}', 'a' * 40, '9.9.9', 'amd64', receipts.harness_sha())
        return code, value, summary, module
    def test_main_preserves_preflight_and_start_boundary_codes_and_fixed_actions(self):
        for stage, category, action in (('preflight', 'native-daemon-platform', 'daemon-platform'),
                                        ('start', 'command-nonzero', 'create-container'),
                                        ('start', 'relay-endpoint-invalid', 'owned-container-endpoint')):
            obj = MainImage(); setattr(obj, stage + '_error', transport.BoundaryError(category))
            obj.commands = [dict(action=action, passed=False, stdout='PRIVATE_COMMAND_OUTPUT' + 'f' * 64, stderr='PRIVATE_ERROR_OUTPUT')]
            code, value, summary, _ = self.invoke_main(obj)
            self.assertEqual(code, 1); self.assertEqual(value['cases'], [])
            self.assertEqual(value['failure'], dict(category=category, stage=stage, action=action))
            self.assertNotIn('PRIVATE_', json.dumps([value, summary]))
            self.assertNotIn('f' * 64, json.dumps([value, summary]))
    def test_main_all_relay_failure_codes_remain_closed_and_allowlisted(self):
        from release_feedback.relay import RELAY_CODES
        for category in RELAY_CODES:
            obj = MainImage(); obj.start_error = transport.BoundaryError(category)
            code, value, _, _ = self.invoke_main(obj)
            self.assertEqual(code, 1)
            self.assertEqual(value['failure'], dict(category=category, stage='start'))
    def test_main_preserves_core_rows_after_passes_and_failed_row(self):
        code, value, _, _ = self.invoke_main(MainImage('invalid-auth-accepted'))
        self.assertEqual(code, 1)
        self.assertEqual(value['cases'], [dict(case=name, passed=i < 2) for i, name in enumerate(cases.IMPLEMENTED[:3])])
        self.assertEqual(value['failure'], dict(category='invalid-secret-accepted', stage='core', case=cases.IMPLEMENTED[2], status=200))
    def test_main_preserves_partial_signed_rows_without_duplicating_core(self):
        code, value, _, _ = self.invoke_main(MainImage('signed-encoding-stored'))
        self.assertEqual(code, 1); self.assertEqual(len(value['cases']), 31)
        self.assertEqual(value['cases'][:29], cases.Cases(FakeHTTP(), '9.9.9').run()['cases'])
        self.assertEqual(value['cases'][29:], [dict(case=SIGNED_CASES[0], passed=True), dict(case=SIGNED_CASES[1], passed=False)])
        self.assertEqual(value['failure'], dict(category='representation-encoding-not-customer', stage='signed', case=SIGNED_CASES[1]))
    def test_main_unknown_exceptions_retain_rows_and_never_echo_private_text(self):
        class HostileError(Exception):
            def __str__(self): raise AssertionError('exception string must never be inspected')
        for exc in (RuntimeError('PRIVATE_CREDENTIAL_BODY_HASH'), HostileError('PRIVATE_CREDENTIAL_BODY_HASH'),
                    KeyboardInterrupt('PRIVATE_INTERRUPT'), SystemExit('PRIVATE_EXIT'),
                    transport.BoundaryError('plausible-but-private-code')):
            def configure(module, stack):
                def run(suite):
                    suite.rows.append(dict(case=cases.IMPLEMENTED[0], passed=True))
                    suite.case = cases.IMPLEMENTED[1]
                    raise exc
                stack.enter_context(patch.object(module.Cases, 'run', new=run))
            code, value, summary, _ = self.invoke_main(MainImage(), configure)
            self.assertEqual(code, 1)
            self.assertEqual(value['cases'], [dict(case=cases.IMPLEMENTED[0], passed=True), dict(case=cases.IMPLEMENTED[1], passed=False)])
            self.assertEqual(value['failure'], dict(category='packaged-image-regression-failed', stage='core', case=cases.IMPLEMENTED[1]))
            for marker in ('PRIVATE', 'plausible-but-private-code'):
                self.assertNotIn(marker, json.dumps([value, summary]))
    def test_main_unknown_signed_failure_retains_first_signed_pass(self):
        obj = MainImage(); signed = obj.signed_request
        def fail_put(method, *args, **kwargs):
            if method == 'PUT': raise RuntimeError('PRIVATE_SIGNED_REQUEST')
            return signed(method, *args, **kwargs)
        obj.signed_request = fail_put
        code, value, summary, _ = self.invoke_main(obj)
        self.assertEqual(code, 1); self.assertEqual(len(value['cases']), 31)
        self.assertEqual(len({row['case'] for row in value['cases']}), 31)
        self.assertEqual(value['cases'][29:], [dict(case=SIGNED_CASES[0], passed=True), dict(case=SIGNED_CASES[1], passed=False)])
        self.assertEqual(value['failure'], dict(category='packaged-image-regression-failed', stage='signed', case=SIGNED_CASES[1]))
        self.assertNotIn('PRIVATE_', json.dumps([value, summary]))
    def test_main_signed_parser_failure_inherits_the_current_allowlisted_case(self):
        def configure(module, stack):
            stack.enter_context(patch('release_feedback.signed_cases.parse_xml', side_effect=cases.Failure('xml-invalid')))
        code, value, _, _ = self.invoke_main(MainImage(), configure)
        self.assertEqual(code, 1); self.assertEqual(len(value['cases']), 31)
        self.assertEqual(value['cases'][-1], dict(case=SIGNED_CASES[1], passed=False))
        self.assertEqual(value['failure'], dict(category='xml-invalid', stage='signed', case=SIGNED_CASES[1]))
    def test_main_failure_fields_are_closed_and_statuses_are_bounded(self):
        for status in (True, 99, 600, '403', 100, 403, 599):
            def configure(module, stack):
                def run(suite):
                    suite.case = cases.IMPLEMENTED[0]
                    exc = cases.Failure('PRIVATE_CATEGORY', 'PRIVATE_CASE', status, 'PRIVATE_S3_CODE')
                    exc.code = 'PRIVATE_S3_CODE'
                    raise exc
                stack.enter_context(patch.object(module.Cases, 'run', new=run))
            obj = MainImage(); obj.commands = [dict(action='PRIVATE_ACTION', passed=False)]
            code, value, summary, _ = self.invoke_main(obj, configure)
            expected = dict(category='packaged-image-regression-failed', stage='core', case=cases.IMPLEMENTED[0])
            if type(status) is int and 100 <= status <= 599: expected['status'] = status
            self.assertEqual(code, 1); self.assertEqual(value['failure'], expected)
            self.assertNotIn('PRIVATE_', json.dumps([value, summary]))
        code, value, _, _ = self.invoke_main(MainImage('per-key-error-hidden'))
        self.assertEqual(code, 1); self.assertEqual(value['failure']['code'], 'AccessDenied')
        self.assertEqual(value['failure']['status'], 200)
    def test_main_cleanup_failure_is_separate_and_cannot_replace_primary_reason(self):
        obj = MainImage('invalid-auth-accepted'); obj.cleanup_error = transport.BoundaryError('cleanup-deadline')
        code, value, summary, _ = self.invoke_main(obj)
        self.assertEqual(code, 1); self.assertEqual(value['failure']['category'], 'invalid-secret-accepted')
        self.assertEqual(value['cleanup_failure'], dict(category='cleanup-deadline', stage='cleanup'))
        self.assertEqual(summary['cleanup_failure'], value['cleanup_failure'])
        self.assertEqual(value['cleanup'], dict.fromkeys(report()['cleanup'], False))
    def test_main_cleanup_false_missing_extra_and_hostile_errors_never_pass(self):
        for fault in ('false', 'missing', 'extra', 'hostile'):
            obj = MainImage()
            if fault == 'false': obj.cleanup_value['allocated_ports_kernel_refused'] = False
            if fault == 'missing': del obj.cleanup_value['lock_released']
            if fault == 'extra': obj.cleanup_value['PRIVATE_EXTRA'] = 'PRIVATE_VALUE'
            if fault == 'hostile': obj.cleanup_error = RuntimeError('PRIVATE_CLEANUP_ERROR')
            code, value, summary, _ = self.invoke_main(obj)
            self.assertEqual(code, 1); self.assertEqual(len(value['cases']), 31)
            self.assertTrue(all(row['passed'] for row in value['cases']))
            self.assertEqual(set(value['cleanup']), set(report()['cleanup']))
            self.assertEqual(value['failure'], value['cleanup_failure'])
            self.assertNotIn('PRIVATE_', json.dumps([value, summary]))
            if fault == 'false':
                self.assertTrue(value['cleanup']['owned_resources_absent'])
                self.assertFalse(value['cleanup']['allocated_ports_kernel_refused'])
    def test_main_success_keeps_exact_31_row_receipt_contract(self):
        code, value, summary, _ = self.invoke_main(MainImage())
        self.assertEqual(code, 0)
        expected = report(phase='candidate')
        expected['cases'] = cases.Cases(FakeHTTP(), '9.9.9').run()['cases'] + [dict(case=name, passed=True) for name in SIGNED_CASES]
        self.assertEqual(value, expected)
        self.assertEqual(summary, dict(scope=receipts.SCOPE, status='passed', case_count=31, full_feedback_matrix_passed=False))
        receipts.validate_report(value, 'a' * 40, '9.9.9', 'amd64', 'candidate', receipts.harness_sha())
    def test_main_missing_signed_row_cannot_qualify(self):
        def configure(module, stack):
            def partial(suite, rows): rows.append(dict(case=SIGNED_CASES[0], passed=True))
            stack.enter_context(patch.object(module, 'run_signed', new=partial))
        code, value, _, _ = self.invoke_main(MainImage(), configure)
        self.assertEqual(code, 1); self.assertEqual(len(value['cases']), 30)
        self.assertEqual(value['failure'], dict(category='receipt-contract-failed', stage='receipt'))
    def test_main_invalid_row_material_is_omitted_without_making_a_valid_receipt(self):
        def configure(module, stack):
            run = module.Cases.run
            def corrupt(suite):
                value = run(suite); suite.rows[0]['PRIVATE_FIELD'] = 'PRIVATE_RESPONSE_BODY'
                return value
            stack.enter_context(patch.object(module.Cases, 'run', new=corrupt))
        code, value, summary, _ = self.invoke_main(MainImage(), configure)
        self.assertEqual(code, 1); self.assertEqual(len(value['cases']), 31)
        self.assertEqual(value['failure'], dict(category='receipt-contract-failed', stage='receipt'))
        self.assertNotIn('PRIVATE_', json.dumps([value, summary]))
    def test_all_29_core_cases_and_18_regressions(self):
        value = cases.Cases(FakeHTTP(), '9.9.9').run()
        self.assertEqual(value['case_count'], 29); self.assertFalse(value['full_feedback_matrix_passed'])
        self.assertEqual(len(FAULTS), 18)
        for fault in FAULTS:
            suite = cases.Cases(FakeHTTP(fault), '9.9.9')
            with self.subTest(fault=fault), self.assertRaises(cases.Failure): suite.run()
            self.assertEqual(sum(not row['passed'] for row in suite.rows), 1)
    def test_actual_signed_case_logic_and_mutations(self):
        io_fixture = SignedHTTP(); suite = cases.Cases(io_fixture, '9.9.9'); suite.run()
        rows = run_signed(suite); self.assertEqual([r['case'] for r in rows], list(SIGNED_CASES))
        self.assertEqual(len(io_fixture.signed_checks), 7)
        self.assertEqual([valid for _, path, valid in io_fixture.signed_checks[:4]], [True, False, False, True])
        self.assertEqual(io_fixture.restarts, 2)
        for fault in ('signed-trailer-deletes', 'signed-trailer-accepted', 'signed-md5-accepted', 'signed-framing-stored', 'signed-encoding-stored', 'signed-restart-metadata-lost'):
            suite = cases.Cases(SignedHTTP(fault), '9.9.9'); suite.run()
            with self.subTest(fault=fault), self.assertRaises(cases.Failure): run_signed(suite)
    def test_independent_seed_chunk_and_trailer_HMAC_verification(self):
        for trailer in (False, True):
            for data in (b'PUBLIC_SYNTHETIC', b'\x00\xffbinary\r\nbytes', b''):
                path = '/maskura/a%20b?z=2&a=1&a=0'
                wire, fields = signing.streaming('PUT', path, '127.0.0.1:41000', 'access', 'secret', data, {'Content-Type': 'text/plain'}, trailer=trailer, timestamp='20261112T120000Z')
                self.assertEqual(verify_signed('PUT', path, fields, wire, 'secret'), (data, True))
                changed = dict(fields); changed['content-type'] = 'other'
                with self.assertRaises(ValueError): verify_signed('PUT', path, changed, wire, 'secret')
                for end in range(len(wire)):
                    with self.assertRaises(ValueError): verify_signed('PUT', path, fields, wire[:end], 'secret')
                if data:
                    mutated = wire.replace(data, bytes([data[0] ^ 1]) + data[1:], 1)
                    with self.assertRaises(ValueError): verify_signed('PUT', path, fields, mutated, 'secret')
    def test_bad_checksum_is_validly_signed_not_fake_signature(self):
        wire, fields = signing.streaming('POST', '/maskura?delete', '127.0.0.1:41000', 'access', 'secret', b'PUBLIC', bad_checksum=True, timestamp='20261112T120000Z')
        self.assertEqual(verify_signed('POST', '/maskura?delete', fields, wire, 'secret'), (b'PUBLIC', False))
        tampered = wire[:-4] + b'0' + wire[-3:]
        with self.assertRaises(ValueError): verify_signed('POST', '/maskura?delete', fields, tampered, 'secret')
    def test_image_signed_transport_never_adds_raw_auth_headers(self):
        obj = object.__new__(image.ImageIO); obj.port = 41000; obj.access = 'access'; obj.secret = 'secret'; captured = []
        obj.request = lambda *args, **kw: captured.append((args, kw))
        obj.signed_request('PUT', '/maskura/object', b'PUBLIC', {'Content-Type': 'text/plain'}, timestamp='20261112T120000Z')
        args, kw = captured[0]; self.assertIs(kw['authenticated'], False)
        self.assertEqual(verify_signed(args[0], args[1], args[3], args[2], 'secret'), (b'PUBLIC', True))
    def test_ambiguous_signed_auth_is_rejected_before_transport(self):
        for headers in ({'Authorization': 'other'}, {'x-maskura-access-key': 'other'}, {'x-maskura-secret-key': 'other'}, {'Transfer-Encoding': 'chunked'}):
            with self.assertRaises(ValueError): signing.streaming('PUT', '/maskura/object', '127.0.0.1:41000', 'a', 'b', b'PUBLIC', headers)
    def test_default_cli_and_portable_imports_have_no_runtime_actions(self):
        spec = importlib.util.spec_from_file_location('release_feedback_entry', ROOT / 'scripts/release-feedback.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with patch('sys.stdout', io.StringIO()): self.assertEqual(module.main([]), 2)
        for path in (ROOT / 'scripts/release_feedback').glob('*.py'):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import): self.assertNotIn('ast', {name.name for name in node.names})
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    self.assertFalse(node.value.startswith(('/private/var/', '/Users/')))
    def test_native_image_identity_labels_and_host_floors_are_real_guards(self):
        obj = object.__new__(image.ImageIO); transport.IO.__init__(obj, ROOT, transport.Budget(Clock()), True)
        obj.image_id = 'sha256:' + 'b' * 64; obj.arch = 'amd64'; obj.source = 'a' * 40; obj.version = '9.9.9'
        obj.docker_root = None; obj.running = False; obj.in_monitor = False; calls = []
        metadata = dict(id=obj.image_id, os='linux', arch='amd64', revision=obj.source, version='v9.9.9', digests=['registry.invalid/image@sha256:' + 'd' * 64])
        def docker(action, args, **kw):
            calls.append((action, args))
            return 0, json.dumps(dict(os='linux', arch='x86_64', root='/owned-docker') if action == 'daemon-platform' else metadata).encode()
        obj.docker = docker
        with patch('platform.system', new=lambda: 'Linux'), patch('platform.machine', new=lambda: 'x86_64'), patch('shutil.disk_usage', new=lambda p: NS(free=13 * 2**30)), patch.object(image, 'root_usage', new=lambda p: (0, 0)):
            obj.preflight(metadata['digests'][0])
            self.assertEqual(calls[-1][1][0:3], ['image', 'inspect', obj.image_id])
            self.assertNotIn('Env', ' '.join(calls[-1][1])); self.assertNotIn('logs', ' '.join(calls[-1][1]))
            metadata['revision'] = 'f' * 40
            with self.assertRaises(transport.BoundaryError): obj.preflight()
            for usage in ((2**20 + 1, 0), (0, 129)):
                with patch.object(image, 'root_usage', new=lambda p: usage), self.assertRaisesRegex(transport.BoundaryError, 'owned-attempt-cap'): obj.guard()
        with patch('shutil.disk_usage', new=lambda p: NS(free=12 * 2**30 - 1)):
            with self.assertRaisesRegex(transport.BoundaryError, 'host-12GiB-floor'): obj.guard()
    def test_lock_is_explicit_existing_and_bounded_not_mac_specific(self):
        text = ast.unparse(next(n for n in ast.walk(ast.parse((ROOT / 'scripts/release_feedback/image.py').read_text())) if isinstance(n, ast.FunctionDef) and n.name == 'acquire_existing_lock'))
        self.assertIn('limit(600)', text); self.assertIn('LOCK_NB', text); self.assertIn('O_NOFOLLOW', text); self.assertNotIn('O_CREAT', text)
        self.assertIn('if args.lock_existing:', (ROOT / 'scripts/release-feedback.py').read_text())
    def test_absent_encoding_not_identity_and_xml_privacy(self):
        class Identity(FakeHTTP):
            def request(self, *a, **kw):
                response = super().request(*a, **kw)
                if a[0] == 'HEAD': response.headers['content-encoding'] = 'identity'
                return response
        with self.assertRaises(cases.Failure): cases.Cases(Identity(), '9.9.9').run()
        for body in (b'<!DOCTYPE x><Delete/>', b'<Delete xmlns="https://unknown.invalid"/>', b'<CompleteMultipartUploadResult/><Error/>'):
            with self.assertRaises(cases.Failure): cases.parse_xml(body)
        self.assertNotIn('PRIVATE', repr(cases.Reply(400, {'private': 'PRIVATE'}, b'PRIVATE')))
    def test_inventory_exit_1_is_never_absence_and_queries_are_projected(self):
        obj = object.__new__(image.ImageIO); obj.names = {'container': 'synthetic-container'}
        obj.docker = lambda *a, **kw: (1, b'')
        with self.assertRaises(transport.BoundaryError): obj.inventory('container')
        obj.docker = lambda *a, **kw: (0, b''); self.assertIsNone(obj.inventory('container'))
        obj.docker = lambda *a, **kw: (0, b'{"name":"synthetic-container-other","id":"' + b'a' * 64 + b'"}')
        self.assertIsNone(obj.inventory('container'))
        for kind in ('container', 'network', 'volume'):
            args = image.ImageIO.inventory_args(kind, 'synthetic-owned')
            self.assertIn('--format', args); self.assertNotIn('Env', ' '.join(args)); self.assertIn('name=synthetic-owned', args)
    def test_wrong_owner_is_not_deleted_and_replacement_rejected(self):
        clock = Clock(); obj = object.__new__(image.ImageIO)
        obj.budget = transport.Budget(clock); obj.permit = True; obj.active = {}; obj.children = {}; obj.http_transport = None
        obj.created = ['container']; obj.names = {'container': 'synthetic-container'}; obj.token = 'owner'; obj.identities = {}; obj.ports = set()
        obj.lock_fd = None; obj.env = {}; obj.command_failure_category = None; calls = []
        def docker(action, args, **kw):
            calls.append(action)
            if action.startswith('inventory'): return 0, json.dumps(dict(name='synthetic-container', id='a' * 64)).encode()
            return 0, json.dumps(dict(name='/synthetic-container', id='a' * 64, owner='WRONG', created='time')).encode()
        obj.docker = docker
        self.assertFalse(obj.cleanup()['owned_resources_absent']); self.assertNotIn('remove-owned-container', calls)
        obj.token = 'WRONG'; obj.identities['container'] = ('a' * 64, 'old-time')
        with self.assertRaises(transport.BoundaryError): obj.owner('container')
    def test_refusal_only_closure_and_socket_closed(self):
        class Probe:
            def __enter__(self): return self
            def __exit__(self, *a): self.closed = True
            def settimeout(self, t): self.timeout = t
            def connect_ex(self, address): self.address = address; return self.result
        import errno
        for result in (0, errno.EACCES, errno.EPERM, errno.ETIMEDOUT, 12345, errno.ECONNREFUSED):
            raw = Probe(); raw.result = result
            with patch('socket.socket', new=lambda *a: raw): self.assertEqual(image.closed_port(41000), result == errno.ECONNREFUSED)
            self.assertTrue(raw.closed); self.assertEqual(raw.timeout, 0.25); self.assertEqual(raw.address, ('127.0.0.1', 41000))
    def test_monitor_limits_cover_store_inodes_bytes_and_writable_layer(self):
        for sizes, layer in ((b'1\n' * 4097, 0), (str(64 * 2**20 + 1).encode(), 0), (b'1\n', 64 * 2**20 + 1)):
            obj = object.__new__(image.ImageIO); obj.budget = transport.Budget(Clock()); obj.owner = lambda kind: 'a' * 64
            obj.docker = lambda action, *a, **kw: (0, sizes if action == 'owned-store-metadata-only' else str(layer).encode())
            with self.assertRaises(transport.BoundaryError): obj.monitor()
    def test_absolute_8s_transport_does_not_renew_on_drips(self):
        clock = Clock()
        def recv(target): clock.now += 0.25; target[0] = 65; return 1
        adapter = transport.AbsoluteTransport(NS(recv_into=recv), 8, clock, lambda: None)
        with self.assertRaisesRegex(transport.BoundaryError, '^http-absolute-deadline$'):
            for _ in range(100): adapter.readinto(bytearray(1))
        self.assertEqual(clock.now, 8)
    def test_expired_measurement_still_TERM_KILL_reaps_same_cleanup_reserve(self):
        clock = Clock(); obj = transport.IO(ROOT, transport.Budget(clock), True); process = Process(); signals = []
        obj.popen_factory = lambda *a, **kw: process; obj.reader_factory = Reader
        obj.pause = lambda seconds: setattr(clock, 'now', clock.now + seconds)
        def kernel(pid, sig):
            self.assertEqual(pid, process.pid)
            if process.returncode is not None: raise ProcessLookupError()
            if sig: signals.append(sig)
            if sig == 9: process.ready = True
        with patch('os.killpg', new=kernel), self.assertRaises(transport.BoundaryError):
            with obj.budget.scope(2, 'measurement-expired'): obj.command('synthetic-timeout', ['fake'])
        self.assertEqual(signals, [15, 9]); self.assertFalse(obj.active); self.assertTrue(obj.commands[0]['child_reaped'])
        deadline = obj.budget.cleanup_deadline; self.assertEqual(obj.budget.begin_cleanup(), deadline)
        self.assertFalse(obj.commands[0]['passed']); self.assertEqual(obj.commands[0]['failure_category'], 'measurement-expired')
    def test_receipt_rejects_missing_case_cleanup_or_false_fullmatrix(self):
        value = report(); receipts.validate_report(value, 'a' * 40, '9.9.9', 'amd64', 'native-child', receipts.harness_sha())
        for mutate in ('case', 'cleanup', 'reserve', 'full', 'phase', 'source', 'harness'):
            value = report()
            if mutate == 'case': value['cases'].pop()
            if mutate == 'cleanup': value['cleanup']['allocated_ports_kernel_refused'] = False
            if mutate == 'reserve': value['cleanup']['cleanup_within_shared_reserve'] = False
            if mutate == 'full': value['full_feedback_matrix_passed'] = True
            if mutate == 'phase': value['phase'] = 'candidate'
            if mutate == 'source': value['source_sha'] = 'f' * 40
            if mutate == 'harness': value['harness_sha256'] = '0' * 64
            with self.assertRaises(ValueError): receipts.validate_report(value, 'a' * 40, '9.9.9', 'amd64', 'native-child', receipts.harness_sha())
    def test_signed_multipart_initiation_cleanup_is_explicitly_unqualified(self):
        exclusion = 'signed-multipart-initiation-decoding-snapshot-cleanup'
        self.assertIn(exclusion, receipts.EXCLUSIONS)
        value = report()
        self.assertIn(exclusion, value['scope_exclusions'])
        self.assertEqual(len(value['cases']), 31); self.assertFalse(value['full_feedback_matrix_passed'])
        value['scope_exclusions'].remove(exclusion)
        with self.assertRaises(ValueError):
            receipts.validate_report(value, 'a' * 40, '9.9.9', 'amd64', 'native-child', receipts.harness_sha())
        self.assertIn('| Signed multipart-initiation decoding/snapshot cleanup | Not exercised;',
                      (ROOT / 'scripts/release_feedback/PROVENANCE.md').read_text())
    def test_two_native_receipts_bind_source_version_arch_and_both_phases(self):
        rows = [child_receipt('amd64'), child_receipt('arm64')]
        self.assertEqual(set(receipts.children(rows, 'a' * 40, '9.9.9', receipts.harness_sha())), {'amd64', 'arm64'})
        for key, value in (('source_sha', 'f' * 40), ('version', '1.0.0'), ('published_replay_passed', False), ('pre_push_passed', False), ('architecture', 'amd64'), ('digest', rows[0]['digest'])):
            changed = copy.deepcopy(rows); changed[1][key] = value
            with self.assertRaises(ValueError): receipts.children(changed, 'a' * 40, '9.9.9', receipts.harness_sha())
    def test_child_and_index_digest_integrity_and_exact_two_children(self):
        rows = [child_receipt('amd64'), child_receipt('arm64')]
        qualified = receipts.children(rows, 'a' * 40, '9.9.9', receipts.harness_sha())
        index = dict(schemaVersion=2, mediaType='application/vnd.oci.image.index.v1+json', manifests=[dict(digest=row['digest'], platform={'os': 'linux', 'architecture': row['architecture']}) for row in rows])
        raw = json.dumps(index).encode(); canonical = 'sha256:' + receipts.sha(raw)
        self.assertTrue(receipts.verify_index(raw, canonical, qualified))
        self.assertTrue(receipts.verify_index(raw + b'\n', canonical, qualified))
        with self.assertRaises(ValueError): receipts.verify_index(raw, 'sha256:' + '0' * 64, qualified)
        for change in ('extra', 'duplicate', 'wrong-child'):
            value = copy.deepcopy(index)
            if change == 'extra': value['manifests'].append(value['manifests'][0])
            if change == 'duplicate': value['manifests'][1] = value['manifests'][0]
            if change == 'wrong-child': value['manifests'][0]['digest'] = 'sha256:' + '0' * 64
            body = json.dumps(value).encode()
            with self.assertRaises(ValueError): receipts.verify_index(body, 'sha256:' + receipts.sha(body), qualified)
    def test_push_digest_parser_never_uses_mutable_tag_or_ambiguous_output(self):
        good = b'v1-amd64: digest: sha256:' + b'a' * 64 + b' size: 1234\n'
        self.assertEqual(receipts.push_digest(good), 'sha256:' + 'a' * 64)
        for bad in (b'', b'latest', good + good, good.replace(b'sha256:', b'other:')):
            with self.assertRaises(ValueError): receipts.push_digest(bad)
    def test_workflow_required_candidate_and_native_order(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text(); release = (ROOT / '.github/workflows/release.yml').read_text()
        job = ci.split('  release-image-smoke:', 1)[1].split('  postgres:', 1)[0]
        names = ['Build local image without publication', 'Resolve loaded candidate once', 'Real packaged-image smoke', 'Packaged FileStore feedback regressions before merge', 'Prove the packaged image before merge']
        self.assertEqual([job.index(name) for name in names], sorted(job.index(name) for name in names))
        self.assertIn('release-image-smoke', ci.split('  check:', 1)[1]); self.assertNotIn('continue-on-error', job)
        build = release.split('  build:', 1)[1].split('  build-macos:', 1)[0]
        names = ['Resolve native loaded image once', 'Boot-smoke image', 'Qualify native child before push', 'Push image', 'Replay published child on the same native runner', 'Upload qualified native child receipt']
        self.assertEqual([build.index(name) for name in names], sorted(build.index(name) for name in names))
        self.assertIn('ubuntu-24.04-arm', build); self.assertNotIn('setup-qemu', release)
        self.assertIn('--phase published-replay --published-ref "$published"', build)
    def assert_native_candidate_matrix(self, ci):
        job = re.search(r'^  release-image-smoke:\n.*?(?=^  [a-zA-Z][a-zA-Z0-9_-]*:|\Z)', ci, re.M | re.S).group()
        header = job.split('    steps:', 1)[0]
        self.assertIn('    strategy:\n      fail-fast: false\n      matrix:\n        include:\n', header)
        rows = re.findall(r'^          - platform: (\S+)\n            suffix: (\S+)\n            runs-on: (\S+)$', header, re.M)
        self.assertEqual(rows, [('linux/amd64', 'amd64', 'ubuntu-24.04'), ('linux/arm64', 'arm64', 'ubuntu-24.04-arm')])
        self.assertIn('    runs-on: ${{ matrix.runs-on }}\n', header)
        self.assertIn('    timeout-minutes: 90\n', header)
        self.assertRegex(ci, r'(?m)^  CARGO_BUILD_JOBS: 2$')
        self.assertNotRegex(header, r'(?m)^    if:|^        exclude:')
        self.assertNotIn('qemu', job.lower()); self.assertNotIn('continue-on-error', job)
        def step(name):
            return job.split('      - name: ' + name + '\n', 1)[1].split('      - ', 1)[0]
        build = step('Build components and packaged release binary')
        self.assertIn('ARCH: ${{ matrix.suffix }}', build)
        self.assertIn('cp target/release/maskura-mcp "dist/maskura-mcp-linux-$ARCH"', build)
        self.assertIn('cp target/release/maskura "dist/maskura-linux-$ARCH"', build)
        self.assertIn('test "$(dist/maskura-linux-$ARCH --version)" = "$expected"', build)
        self.assertNotRegex(job, r'dist/maskura(?:-mcp)?-linux-(?:amd64|arm64)|--arch (?:amd64|arm64)')
        image_build = step('Build local image without publication')
        self.assertIn('platforms: ${{ matrix.platform }}', image_build)
        self.assertIn('load: true', image_build); self.assertIn('push: false', image_build)
        candidate = 'maskura-pr-smoke:${{ github.sha }}-${{ matrix.suffix }}'
        self.assertIn('tags: ' + candidate, image_build)
        self.assertIn('IMAGE_REF: ' + candidate, step('Resolve loaded candidate once'))
        regression = step('Packaged FileStore feedback regressions before merge')
        self.assertIn('ARCH: ${{ matrix.suffix }}', regression)
        self.assertIn('--arch "$ARCH"', regression); self.assertIn('--phase candidate', regression)
        self.assertIn('IMAGE_ID: ${{ steps.feedback-image.outputs.image_id }}', regression)
        self.assertIn('IMAGE_REF: ${{ steps.feedback-image.outputs.image_id }}', step('Real packaged-image smoke'))
        self.assertIn('MASKURA_PROOF_IMAGE: ${{ steps.feedback-image.outputs.image_id }}', step('Prove the packaged image before merge'))
        self.assertIn('MASKURA_PROOF_IMAGE_LOCAL: "1"', step('Prove the packaged image before merge'))
        aggregate = ci.split('  check:\n', 1)[1]
        self.assertRegex(aggregate, r'(?m)^    needs: \[[^\n]*\brelease-image-smoke\b[^\n]*\]$')
        self.assertIn("'failure'", aggregate); self.assertIn("'cancelled'", aggregate); self.assertIn("'skipped'", aggregate)
    def test_required_candidate_matrix_qualifies_both_native_architectures(self):
        self.assert_native_candidate_matrix((ROOT / '.github/workflows/ci.yml').read_text())
    def test_native_candidate_matrix_rejects_hardcoding_and_missing_arm_controls(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text()
        arm_row = '          - platform: linux/arm64\n            suffix: arm64\n            runs-on: ubuntu-24.04-arm\n'
        controls = {
            'missing-arm': (arm_row, ''),
            'duplicate-amd64': (arm_row, arm_row.replace('arm64', 'amd64').replace('ubuntu-24.04-arm', 'ubuntu-24.04')),
            'wrong-arm-runner': ('runs-on: ubuntu-24.04-arm', 'runs-on: ubuntu-24.04'),
            'hardcoded-runner': ('runs-on: ${{ matrix.runs-on }}', 'runs-on: ubuntu-24.04'),
            'hardcoded-platform': ('platforms: ${{ matrix.platform }}', 'platforms: linux/amd64'),
            'hardcoded-copied-cli': ('cp target/release/maskura "dist/maskura-linux-$ARCH"', 'cp target/release/maskura dist/maskura-linux-amd64'),
            'hardcoded-version-check': ('$(dist/maskura-linux-$ARCH --version)', '$(dist/maskura-linux-amd64 --version)'),
            'hardcoded-case-arch': ('--arch "$ARCH"', '--arch amd64'),
            'hardcoded-arch-env': ('ARCH: ${{ matrix.suffix }}', 'ARCH: amd64'),
            'mutable-unsuffixed-ref': ('IMAGE_REF: maskura-pr-smoke:${{ github.sha }}-${{ matrix.suffix }}', 'IMAGE_REF: maskura-pr-smoke:${{ github.sha }}'),
            'dropped-aggregate-dependency': ('e2e, release-image-smoke, postgres', 'e2e, postgres'),
            'optional-matrix-job': ('  release-image-smoke:\n', '  release-image-smoke:\n    if: false\n'),
        }
        for name, (before, after) in controls.items():
            self.assertIn(before, ci)
            with self.subTest(control=name), self.assertRaises(AssertionError):
                self.assert_native_candidate_matrix(ci.replace(before, after))
    def test_index_and_latest_use_only_qualified_digests_preserving_gates(self):
        release = (ROOT / '.github/workflows/release.yml').read_text()
        merge = release.split('      - name: Merge multi-arch manifest from qualified digests', 1)[1].split('      - name:', 1)[0]
        self.assertIn('"$IMAGE@$AMD64_DIGEST"', merge); self.assertIn('"$IMAGE@$ARM64_DIGEST"', merge)
        self.assertNotIn('RELEASE_TAG }}-amd64', merge)
        latest = release.split('      - name: Promote verified images to latest', 1)[1].split('      - name:', 1)[0]
        self.assertIn('@${{ steps.image-digests.outputs.canonical }}', latest); self.assertNotIn('${{ env.IMAGE }}:${{ env.RELEASE_TAG }}', latest)
        self.assertLess(release.index('scripts/release-feedback-receipts.py index'), release.index('Promote verified images to latest'))
        self.assertIn('bash examples/prove-maskura.sh', release); self.assertIn('scripts/check-release-contract.py --tag', release)
        self.assertIn('              dist/QUALIFIED_IMAGE_CHILDREN.json \\', release)
        self.assertIn('test -f verify-dist/QUALIFIED_IMAGE_CHILDREN.json', release)
        self.assertIn('bash scripts/audit-dependencies.sh', (ROOT / '.github/workflows/ci.yml').read_text())
        # The independently guarded managed-release caller also binds its source
        # input. Native child/index jobs must still use the single RELEASE_TAG.
        native_release = re.sub(r'^  managed-release:\n.*?(?=^  [a-zA-Z][a-zA-Z0-9_-]*:|\Z)', '', release, flags=re.M | re.S)
        self.assertEqual(native_release.count('github.ref_name'), 1)
        for path in ('.github/workflows/ci.yml', '.github/workflows/release.yml'):
            for action in re.findall(r'uses: ([^\s]+)', (ROOT / path).read_text()):
                if action.startswith('./'):
                    # This reusable workflow is bound to the caller's own commit.
                    self.assertEqual(action, './.github/workflows/managed-release.yml')
                else: self.assertRegex(action, r'@[0-9a-f]{40}$')

if __name__ == '__main__': unittest.main()
