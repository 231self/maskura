# SPDX-License-Identifier: Apache-2.0
"""In-memory 29-case fixture + 18 historical mutations; never an image substitute."""
import base64
import hashlib
import json
from urllib.parse import parse_qs, unquote, urlsplit
import xml.etree.ElementTree as ET
from release_feedback import cases

FAULTS = ('metadata-loss', 'type-parameters-lost', 'collision-leak', 'invalid-auth-accepted',
          'overwrite-stale', 'reserved-accepted', 'reserved-mutated-on-reject', 'reserved-upload-admitted',
          'missing-init-type-rejected', 'completion-type-wins', 'bad-md5-accepted', 'bad-md5-deleted',
          'per-key-error-hidden', 'quiet-deleted-leak', 'restart-metadata-lost', 'restart-stale-port',
          'list-size-wrong', 'runtime-version-wrong')
def xml(root, entries=()):
    tree = ET.Element(root)
    for name, value in entries: ET.SubElement(tree, name).text = value
    return ET.tostring(tree)
def error(code, status=400): return cases.Reply(status, {}, xml('Error', [('Code', code), ('Message', 'PRIVATE_SYNTHETIC_TRAP')]))

class FakeHTTP:
    def __init__(self, fault=None):
        self.fault = fault; self.objects = {}; self.uploads = {}; self.port = 10101; self.active_port = self.port
        self.requests = []; self.restarts = 0
    def invalid_secret(self, path): return cases.Reply(200 if self.fault == 'invalid-auth-accepted' else 403, {}, b'')
    def restart_and_resolve_port(self):
        self.restarts += 1; self.active_port = 20202
        if self.fault != 'restart-stale-port': self.port = self.active_port
        if self.fault == 'restart-metadata-lost': self.objects = {k: (b, t, {}) for k, (b, t, m) in self.objects.items()}
    def request(self, method, path, body=None, headers=None, authenticated=True):
        if self.port != self.active_port: raise cases.Failure('mocked-port-not-reresolved')
        self.requests.append((method, path)); headers = {k.lower(): v for k, v in (headers or {}).items()}
        query = parse_qs(urlsplit(path).query, keep_blank_values=True); key = unquote(urlsplit(path).path.removeprefix('/maskura/'))
        if path == '/openapi.json': return cases.Reply(200, {}, json.dumps({'info': {'version': '0.7.33' if self.fault == 'runtime-version-wrong' else '9.9.9'}}).encode())
        if method == 'GET' and path.startswith('/maskura?'):
            if 'uploads' in query:
                tree = ET.Element('ListMultipartUploadsResult'); ET.SubElement(tree, 'IsTruncated').text = 'false'
                for upload, value in self.uploads.items():
                    node = ET.SubElement(tree, 'Upload'); ET.SubElement(node, 'Key').text = value[0]; ET.SubElement(node, 'UploadId').text = upload
            else:
                tree = ET.Element('ListBucketResult'); ET.SubElement(tree, 'IsTruncated').text = 'false'
                for name, (data, _, _) in self.objects.items():
                    node = ET.SubElement(tree, 'Contents'); ET.SubElement(node, 'Key').text = name
                    ET.SubElement(node, 'Size').text = str(len(data) + (1 if self.fault == 'list-size-wrong' else 0))
            return cases.Reply(200, {}, ET.tostring(tree))
        metadata = {k[len('x-amz-meta-'):]: v for k, v in headers.items() if k.startswith('x-amz-meta-')}
        if any(k in cases.RESERVED for k in metadata):
            if self.fault == 'reserved-accepted': return cases.Reply(200, {}, b'')
            if self.fault == 'reserved-mutated-on-reject': self.objects['reserved'] = (b'changed', 'text/plain', {})
            if self.fault == 'reserved-upload-admitted' and 'uploads' in query: self.uploads['synthetic-rejected-upload'] = (key, 'text/plain', {}, b'')
            return error('InvalidRequest')
        if method == 'POST' and 'uploads' in query:
            upload = 'synthetic-upload-' + str(len(self.uploads)); self.uploads[upload] = (key, headers.get('content-type', 'application/octet-stream'), metadata, b'')
            return cases.Reply(200, {}, xml('InitiateMultipartUploadResult', [('UploadId', upload)]))
        if 'uploadId' in query:
            upload = query['uploadId'][0]; old_key, content_type, meta, data = self.uploads[upload]
            if method == 'PUT':
                self.uploads[upload] = (old_key, content_type, meta, body); return cases.Reply(200, {'etag': '"synthetic-etag<&>"'}, b'')
            if self.fault == 'missing-init-type-rejected' and content_type == 'application/octet-stream': return error('InvalidRequest')
            if self.fault == 'completion-type-wins': content_type = headers.get('content-type', content_type)
            self.objects[old_key] = (data, content_type, meta); del self.uploads[upload]
            return cases.Reply(200, {}, xml('CompleteMultipartUploadResult'))
        if method == 'POST' and 'delete' in query:
            expected = base64.b64encode(hashlib.md5(body).digest()).decode(); tree = cases.parse_xml(body, 'Delete')
            keys = cases.values(tree, 'Key'); quiet = cases.values(tree, 'Quiet') == ['true']
            if headers.get('content-md5') != expected:
                if self.fault == 'bad-md5-deleted':
                    for name in keys: self.objects.pop(name, None)
                if self.fault != 'bad-md5-accepted': return error('BadDigest')
            result = ET.Element('DeleteResult')
            for name in keys:
                self.objects.pop(name, None)
                if self.fault == 'per-key-error-hidden' and name == 'mixed-a':
                    node = ET.SubElement(result, 'Error'); ET.SubElement(node, 'Key').text = name; ET.SubElement(node, 'Code').text = 'AccessDenied'
                elif not quiet or self.fault == 'quiet-deleted-leak': ET.SubElement(ET.SubElement(result, 'Deleted'), 'Key').text = name
            return cases.Reply(200, {}, ET.tostring(result))
        if method == 'PUT':
            if self.fault == 'overwrite-stale' and key in self.objects: metadata = self.objects[key][2]
            self.objects[key] = (body, headers['content-type'], metadata); return cases.Reply(200, {}, b'')
        if key not in self.objects: return error('NoSuchKey', 404)
        data, content_type, metadata = self.objects[key]
        h = {'content-type': content_type.split(';')[0] if self.fault == 'type-parameters-lost' else content_type, 'content-length': str(len(data))}
        if self.fault != 'metadata-loss': h.update({'x-amz-meta-' + k: v for k, v in metadata.items()})
        if self.fault == 'collision-leak': h['content-encoding'] = metadata.get('content-encoding', 'identity')
        return cases.Reply(200, h, data if method == 'GET' else b'')
