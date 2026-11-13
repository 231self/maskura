# SPDX-License-Identifier: Apache-2.0
"""Two actual signed-transport image rows, additional to the reviewed core29."""
import base64
import hashlib
from urllib.parse import quote
import xml.etree.ElementTree as ET
from .cases import META, PAYLOAD, TYPE, delete_body, delete_result, error_code, parse_xml, xml_one

SIGNED_CASES = ('signed-aws-chunked-md5-trailer-cross-negatives', 'decoded-aws-chunked-representation-cleanup')

def run_signed(c, rows=None):
    # An optional caller-owned sink retains completed rows if a later case fails.
    rows = [] if rows is None else rows
    def signed(method, path, body, headers, **kwargs):
        response = c.io.signed_request(method, path, body, headers, **kwargs)
        c.check(len(response.body) <= 2**20, 'signed-response-bound'); return response
    c.case = SIGNED_CASES[0]
    keys = ['signed-delete-a', 'signed-delete-b']; body = delete_body(keys)
    for key in keys: c.put(key, metadata=META)
    # Every negative precedes ANY successful deletion; bad checksum VALUE is
    # signed correctly, so neither seed nor trailer authentication is bypassed.
    for good_md5, good_trailer in ((False, True), (True, False), (False, False)):
        checksum = base64.b64encode(hashlib.md5(body if good_md5 else b'BAD_SYNTHETIC').digest()).decode()
        response = signed('POST', '/maskura?delete', body, {'Content-Type': 'application/xml', 'Content-MD5': checksum}, bad_checksum=not good_trailer)
        c.check(response.status == 400 and error_code(response.body) == 'BadDigest', 'signed-delete-integrity-before-side-effects', response)
        for key in keys: c.object(key, metadata=META); c.listed(key)
    checksum = base64.b64encode(hashlib.md5(body).digest()).decode()
    response = signed('POST', '/maskura?delete', body, {'Content-Type': 'application/xml', 'Content-MD5': checksum})
    c.check(response.status == 200, 'signed-delete-valid-status', response)
    c.check(sorted(delete_result(response.body)) == sorted(('Deleted', key, None) for key in keys), 'signed-delete-valid-outcomes')
    for key in keys: c.check(c.request('GET', c.path(key)).status == 404, 'signed-delete-not-deleted')
    c.check(not any(key in c.listing() for key in keys), 'signed-delete-still-listed')
    rows.append({'case': c.case, 'passed': True})

    c.case = SIGNED_CASES[1]
    metadata = {'x-amz-meta-' + k: v for k, v in META.items()}
    for trailer in (False, True):
        key = 'signed-put-' + str(int(trailer))
        response = signed('PUT', c.path(key), PAYLOAD, dict(metadata, **{'Content-Type': TYPE}), trailer=trailer)
        c.check(response.status == 200, 'signed-put-status', response)
        c.object(key, metadata=META); c.listed(key)
    key = 'signed-multipart'
    response = c.request('POST', c.path(key) + '?uploads', headers=dict(metadata, **{'Content-Type': TYPE}))
    c.check(response.status == 200, 'signed-mpu-init', response)
    upload = xml_one(parse_xml(response.body, 'InitiateMultipartUploadResult'), 'UploadId')
    suffix = 'uploadId=' + quote(upload, safe='')
    response = signed('PUT', c.path(key) + '?partNumber=1&' + suffix, PAYLOAD, {'Content-Type': 'application/octet-stream'})
    c.check(response.status == 200 and bool(response.headers.get('etag')), 'signed-mpu-part', response)
    complete = ET.Element('CompleteMultipartUpload'); part = ET.SubElement(complete, 'Part')
    ET.SubElement(part, 'PartNumber').text = '1'; ET.SubElement(part, 'ETag').text = response.headers['etag']
    response = c.request('POST', c.path(key) + '?' + suffix, ET.tostring(complete), {'Content-Type': 'application/xml'})
    c.check(response.status == 200, 'signed-mpu-complete', response); parse_xml(response.body, 'CompleteMultipartUploadResult')
    c.object(key, metadata=META); c.listed(key)
    c.check(not any(k == key for k, _ in c.uploads()), 'signed-mpu-still-open')
    c.io.restart_and_resolve_port()
    for key in ('signed-put-0', 'signed-put-1', 'signed-multipart'): c.object(key, metadata=META); c.listed(key)
    rows.append({'case': c.case, 'passed': True})
    return rows
