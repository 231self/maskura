# SPDX-License-Identifier: Apache-2.0
"""Reviewed 29-case FileStore oracle; portable source origins in PROVENANCE.md."""
import base64
from dataclasses import dataclass, field
import hashlib
import json
import re
from urllib.parse import quote
import xml.etree.ElementTree as ET

MAX_BODY = 2**20
MAX_PAYLOAD = 2**20
REQUEST_SECONDS = 8
TYPE = 'Text/Plain; charset=utf-8'
PAYLOAD = b'PUBLIC_SYNTHETIC_FILESTORE_COMPATIBILITY_CHECK'
META = {'project': 'synthetic-A', 'content-type': 'customer-type', 'content-encoding': 'customer-encoding'}
RESERVED = ('maskura-operation-id', 'maskura-sha256', 'maskura-size', 'maskura-generation',
            'maskura-provider-instance', 'maskura-provider-account', 'maskura-credential-epoch')
IMPLEMENTED = ('runtime-version', 'metadata-get-head-list', 'invalid-secret-preserves-object',
               'overwrite-B', 'overwrite-absent', *('reserved-put-' + str(i) for i in range(7)),
               *('reserved-mpu-' + str(i) for i in range(7)),
               'mpu-00', 'mpu-01', 'mpu-10', 'mpu-11',
               'batch-wrong-md5', 'batch-malformed-md5', 'batch-valid-mixed',
               'batch-repeat', 'batch-quiet', 'restart-get-head-list')
UNIMPLEMENTED = ('signed-aws-chunked-md5-trailer-cross-negatives', 'decoded-aws-chunked-representation-cleanup')
CODES = {'InvalidRequest', 'BadDigest', 'InvalidDigest', 'AccessDenied', 'NoSuchUpload',
         'NoSuchKey', 'NoSuchBucket', 'MalformedXML', 'InternalError', 'EntityTooLarge'}

class Failure(Exception):
    """Only closed failure fields may be persisted; never exception messages from I/O."""
    def __init__(self, category, case=None, status=None, code=None):
        self.category = category; self.case = case; self.status = status
        self.code = code if code in CODES else ('other' if code is not None else None)
        super().__init__(category)
    def closed(self):
        return {k: v for k, v in {'category': self.category, 'case': self.case,
                'status': self.status, 'code': self.code}.items() if v is not None}

@dataclass(repr=False)
class Reply:
    status: int
    headers: dict = field(repr=False)
    body: bytes = field(repr=False)

def parse_xml(body, root=None):
    # Adapted from the retained auditor's bounded xml_value/error_category path.
    if not isinstance(body, bytes) or len(body) > MAX_BODY: raise Failure('xml-size-bound')
    upper = body.upper()
    if b'<!DOCTYPE' in upper or b'<!ENTITY' in upper: raise Failure('xml-declaration-forbidden')
    try: tree = ET.fromstring(body)
    except ET.ParseError: raise Failure('xml-invalid') from None
    for node in tree.iter():
        if node.tag.startswith('{') and not node.tag.startswith('{http://s3.amazonaws.com/doc/2006-03-01/}'):
            raise Failure('xml-namespace-invalid')
    if root is not None and local(tree.tag) != root: raise Failure('xml-root-invalid')
    return tree

def local(tag): return tag.rsplit('}', 1)[-1]
def values(tree, name): return [n.text or '' for n in tree.iter() if local(n.tag) == name]
def xml_one(tree, name):
    found = values(tree, name)
    if len(found) != 1 or not found[0]: raise Failure('xml-required-field')
    return found[0]

def error_code(body):
    try:
        result = values(parse_xml(body), 'Code')
        return result[0] if len(result) == 1 and result[0] in CODES else 'other'
    except Failure: return 'unparsed'

def delete_body(keys, quiet=False):
    root = ET.Element('Delete')
    for key in keys: ET.SubElement(ET.SubElement(root, 'Object'), 'Key').text = key
    if quiet: ET.SubElement(root, 'Quiet').text = 'true'
    return ET.tostring(root, encoding='utf-8')

def delete_result(body):
    tree = parse_xml(body, 'DeleteResult'); result = []
    for child in tree:
        kind = local(child.tag)
        if kind not in ('Deleted', 'Error'): raise Failure('unexpected-delete-result-entry')
        key = xml_one(child, 'Key')
        code = xml_one(child, 'Code') if kind == 'Error' else None
        result.append((kind, key, code if code in CODES else ('other' if code else None)))
    return result

class Cases:
    """All response material remains in memory. Reports contain no object identities."""
    def __init__(self, io, version):
        self.io = io; self.version = version; self.case = None; self.rows = []
    def check(self, condition, category, reply=None):
        if not condition:
            raise Failure(category, self.case, reply.status if reply else None,
                          error_code(reply.body) if reply and reply.status >= 400 else None)
    def row(self, name, action):
        if name not in IMPLEMENTED: raise Failure('unknown-case')
        self.case = name
        try: action()
        except Failure as exc:
            if exc.case is None: exc.case = name
            self.rows.append({'case': name, 'passed': False}); raise
        self.rows.append({'case': name, 'passed': True})
    def request(self, method, path, body=None, headers=None, authenticated=True):
        if body is not None and len(body) > MAX_PAYLOAD: raise Failure('synthetic-payload-bound', self.case)
        response = self.io.request(method, path, body, headers or {}, authenticated)
        self.check(isinstance(response, Reply) and len(response.body) <= MAX_BODY, 'response-bound')
        return response
    @staticmethod
    def path(key): return '/maskura/' + quote(key, safe='/')
    def put(self, key, body=PAYLOAD, metadata=None, content_type=TYPE):
        headers = {'Content-Type': content_type}
        headers.update({'x-amz-meta-' + k: v for k, v in (metadata or {}).items()})
        response = self.request('PUT', self.path(key), body, headers)
        self.check(response.status == 200, 'put-status', response)
    def object(self, key, body=PAYLOAD, metadata=None, content_type=TYPE):
        for method in ('GET', 'HEAD'):
            r = self.request(method, self.path(key))
            self.check(r.status == 200, 'object-status', r)
            self.check(r.headers.get('content-type') == content_type, 'representation-type')
            self.check(r.headers.get('content-encoding') is None, 'representation-encoding-not-customer')
            for name in META:
                self.check(r.headers.get('x-amz-meta-' + name) == (metadata or {}).get(name), 'customer-metadata')
            self.check(r.body == (body if method == 'GET' else b''), 'object-byte-equality')
            self.check(r.headers.get('content-length') == str(len(body)), 'object-length')
    def listing(self):
        r = self.request('GET', '/maskura?list-type=2')
        self.check(r.status == 200, 'list-status', r)
        tree = parse_xml(r.body, 'ListBucketResult'); found = {}
        self.check(values(tree, 'IsTruncated') == ['false'], 'list-unexpected-pagination')
        for child in tree:
            if local(child.tag) == 'Contents':
                key = xml_one(child, 'Key'); size = xml_one(child, 'Size')
                self.check(size.isascii() and size.isdigit() and len(size) <= 10 and key not in found, 'list-shape')
                found[key] = int(size)
        return found
    def listed(self, key, body=PAYLOAD): self.check(self.listing().get(key) == len(body), 'list-membership-size')
    def uploads(self):
        r = self.request('GET', '/maskura?uploads')
        self.check(r.status == 200, 'upload-list-status', r)
        tree = parse_xml(r.body, 'ListMultipartUploadsResult')
        self.check(values(tree, 'IsTruncated') == ['false'], 'uploads-unexpected-pagination')
        return sorted((xml_one(n, 'Key'), xml_one(n, 'UploadId')) for n in tree if local(n.tag) == 'Upload')
    def mpu(self, initiation, completion):
        key = 'multipart-' + str(int(initiation)) + str(int(completion))
        headers = {'x-amz-meta-' + k: v for k, v in META.items()}
        if initiation: headers['Content-Type'] = TYPE
        r = self.request('POST', self.path(key) + '?uploads', headers=headers)
        self.check(r.status == 200, 'mpu-init-status', r)
        upload = xml_one(parse_xml(r.body, 'InitiateMultipartUploadResult'), 'UploadId')
        suffix = 'uploadId=' + quote(upload, safe='')
        r = self.request('PUT', self.path(key) + '?partNumber=1&' + suffix, PAYLOAD, {'Content-Type': 'application/octet-stream'})
        self.check(r.status == 200 and bool(r.headers.get('etag')), 'mpu-part-status-etag', r)
        completion_xml = ET.Element('CompleteMultipartUpload'); part = ET.SubElement(completion_xml, 'Part')
        ET.SubElement(part, 'PartNumber').text = '1'; ET.SubElement(part, 'ETag').text = r.headers['etag']
        r = self.request('POST', self.path(key) + '?' + suffix, ET.tostring(completion_xml), {'Content-Type': 'application/xml'} if completion else {})
        self.check(r.status == 200, 'mpu-complete-status', r)
        parse_xml(r.body, 'CompleteMultipartUploadResult')  # HTTP 200 containing <Error> is not success.
        self.object(key, metadata=META, content_type=TYPE if initiation else 'application/octet-stream')
        self.listed(key)
        self.check(not any(k == key for k, _ in self.uploads()), 'completed-upload-still-listed')
    def rejected_reserved(self, index, mpu):
        name = RESERVED[index]; mixed = ''.join(c.upper() if i % 2 else c for i, c in enumerate(name))
        before = self.uploads() if mpu else None
        r = self.request('POST' if mpu else 'PUT', self.path('reserved') + ('?uploads' if mpu else ''),
            None if mpu else b'REJECTED_SYNTHETIC_REPLACEMENT', {'Content-Type': 'text/plain', 'x-amz-meta-' + mixed: 'synthetic'})
        self.check(r.status == 400 and error_code(r.body) == 'InvalidRequest', 'reserved-not-rejected', r)
        self.check(not values(parse_xml(r.body), 'UploadId'), 'rejected-admission-returned-upload-id')
        if mpu: self.check(self.uploads() == before, 'reserved-upload-list-delta')
        self.object('reserved', metadata=META); self.listed('reserved')
    def batch(self, keys, quiet=False, digest=None):
        body = delete_body(keys, quiet)
        checksum = digest if digest is not None else base64.b64encode(hashlib.md5(body).digest()).decode()
        return self.request('POST', '/maskura?delete', body, {'Content-Type': 'application/xml', 'Content-MD5': checksum})
    def negative_batch(self, digest):
        r = self.batch(['negative-a', 'negative-b'], digest=digest)
        self.check(r.status == 400 and error_code(r.body) == 'BadDigest', 'batch-integrity-not-rejected', r)
        for key in ('negative-a', 'negative-b'): self.object(key, metadata=META); self.listed(key)
    def mixed_batch(self, repeat=False, quiet=False):
        keys = ['mixed-a', 'mixed-b', 'mixed-never-created']
        if quiet:
            self.put('quiet-a'); keys = ['quiet-a', 'quiet-never-created']
        r = self.batch(keys, quiet)
        self.check(r.status == 200, 'batch-valid-status', r)
        entries = delete_result(r.body)
        errors = [code for kind, _, code in entries if kind == 'Error']
        if errors: raise Failure('batch-per-key-error', self.case, r.status, errors[0])
        self.check(entries == [] if quiet else sorted(entries) == sorted(('Deleted', k, None) for k in keys), 'batch-per-key-outcome')
        for key in keys:
            r = self.request('GET', self.path(key)); self.check(r.status == 404, 'deleted-object-still-readable', r)
        listing = self.listing(); self.check(not any(k in listing for k in keys), 'deleted-object-still-listed')
    def run(self):
        def version():
            r = self.request('GET', '/openapi.json', authenticated=False)
            self.check(r.status == 200, 'openapi-status', r)
            try: actual = json.loads(r.body)['info']['version']
            except (ValueError, TypeError, KeyError): raise Failure('openapi-shape', self.case) from None
            self.check(actual == self.version, 'runtime-version-mismatch')
        self.row('runtime-version', version)
        def metadata():
            self.put('single', metadata=META); self.object('single', metadata=META); self.listed('single')
        self.row('metadata-get-head-list', metadata)
        def invalid():
            r = self.io.invalid_secret(self.path('single'))
            self.check(r.status == 403, 'invalid-secret-accepted', r)
            self.object('single', metadata=META); self.listed('single')
        self.row('invalid-secret-preserves-object', invalid)
        changed = {k: v.replace('A', 'B') + '-B' for k, v in META.items()}
        def overwrite():
            self.put('single', b'PUBLIC_SYNTHETIC_OVERWRITE_B', changed)
            self.object('single', b'PUBLIC_SYNTHETIC_OVERWRITE_B', changed); self.listed('single', b'PUBLIC_SYNTHETIC_OVERWRITE_B')
        self.row('overwrite-B', overwrite)
        def clear():
            self.put('single', metadata={}); self.object('single', metadata={}); self.listed('single')
        self.row('overwrite-absent', clear)
        for i in range(7):
            def reserved_put(i=i):
                if i == 0: self.put('reserved', metadata=META)
                self.rejected_reserved(i, False)
            self.row('reserved-put-' + str(i), reserved_put)
            self.row('reserved-mpu-' + str(i), lambda i=i: self.rejected_reserved(i, True))
        for init in (False, True):
            for complete in (False, True): self.row('mpu-' + str(int(init)) + str(int(complete)), lambda a=init, b=complete: self.mpu(a, b))
        def bad_md5():
            for key in ('negative-a', 'negative-b'): self.put(key, metadata=META)
            self.negative_batch('AAAAAAAAAAAAAAAAAAAAAA==')
        self.row('batch-wrong-md5', bad_md5)
        self.row('batch-malformed-md5', lambda: self.negative_batch('not-base64'))
        def mixed():
            for key in ('mixed-a', 'mixed-b'): self.put(key)
            self.mixed_batch()
        self.row('batch-valid-mixed', mixed)
        self.row('batch-repeat', lambda: self.mixed_batch(repeat=True))
        self.row('batch-quiet', lambda: self.mixed_batch(quiet=True))
        def restart():
            self.put('restart', metadata=META); before = self.listing()
            self.io.restart_and_resolve_port()
            self.object('restart', metadata=META); self.object('single', metadata={})
            self.check(self.listing() == before, 'restart-list-membership-size')
        self.row('restart-get-head-list', restart)
        self.check(len(self.rows) == len(IMPLEMENTED) and all(r['passed'] for r in self.rows), 'case-count-or-selected-failure')
        return {'profile': 'filestore-core', 'core_assertions_passed': True, 'case_count': len(self.rows),
                'cases': self.rows, 'full_feedback_matrix_passed': False, 'unimplemented': list(UNIMPLEMENTED),
                'scope_exclusions': ['memory', 'direct-s3', 'managed', 'postgres', 'protected-pipeline', 'process-recovery', 'unmodified-sdk', 'reporter-environment']}
