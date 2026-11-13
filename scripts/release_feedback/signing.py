# SPDX-License-Identifier: Apache-2.0
"""Ordinary SigV4 header seed + chained AWS signed payload/trailer framing.

Protocol matches gateway sigv4.rs (Single/Disabled path settings) and
integrity.rs signed_chunk/signed_and_unsigned_trailers_are_verified tests.
There are no raw-auth headers or trusted-TLS/unsigned streaming exemptions.
"""
import base64
import datetime
import hashlib
import hmac
from urllib.parse import parse_qsl, quote, unquote, urlsplit

EMPTY = hashlib.sha256(b'').hexdigest()
SIGNED = 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD'
TRAILER = SIGNED + '-TRAILER'

def digest(data): return hashlib.sha256(data).hexdigest()
def mac(key, text): return hmac.new(key, text.encode(), hashlib.sha256).digest()
def key_for(secret, date):
    key = ('AWS4' + secret).encode()
    for item in (date, 'us-east-1', 's3', 'aws4_request'): key = mac(key, item)
    return key

def streaming(method, path, host, access, secret, data, headers=None, *, trailer=True, bad_checksum=False, timestamp=None):
    if len(data) > 2**20: raise ValueError('signed-payload-bound')
    timestamp = timestamp or datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    scope = timestamp[:8] + '/us-east-1/s3/aws4_request'; key = key_for(secret, timestamp[:8])
    fields = {k.lower(): v for k, v in (headers or {}).items()}
    if any(k in fields for k in ('authorization', 'x-maskura-access-key', 'x-maskura-secret-key', 'transfer-encoding')): raise ValueError('ambiguous-stream-auth')
    fields.update(host=host, **{'x-amz-date': timestamp, 'x-amz-content-sha256': TRAILER if trailer else SIGNED,
        'content-encoding': 'aws-chunked', 'x-amz-decoded-content-length': str(len(data))})
    checksum = base64.b64encode(hashlib.sha256(b'BAD_SYNTHETIC' if bad_checksum else data).digest()).decode()
    if trailer:
        fields.update({'x-amz-trailer': 'x-amz-checksum-sha256', 'x-amz-sdk-checksum-algorithm': 'SHA256'})
    names = sorted(k for k in fields if k not in ('connection', 'content-length', 'user-agent', 'expect'))
    if any(v != ' '.join(v.split()) for v in fields.values()): raise ValueError('noncanonical-signed-header')
    target = urlsplit(path)
    query = '&'.join(k + '=' + v for k, v in sorted((quote(k, safe='~'), quote(v, safe='~')) for k, v in parse_qsl(target.query, keep_blank_values=True)))
    canonical = '\n'.join((method, quote(unquote(target.path), safe='/~'), query,
        ''.join(k + ':' + fields[k] + '\n' for k in names), ';'.join(names), fields['x-amz-content-sha256']))
    seed = mac(key, 'AWS4-HMAC-SHA256\n' + timestamp + '\n' + scope + '\n' + digest(canonical.encode())).hex()
    fields['authorization'] = f'AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={";".join(names)}, Signature={seed}'
    previous = seed; wire = bytearray()
    for part in ([data] if data else []) + [b'']:
        signature = mac(key, '\n'.join(('AWS4-HMAC-SHA256-PAYLOAD', timestamp, scope, previous, EMPTY, digest(part)))).hex()
        wire.extend(f'{len(part):X};chunk-signature={signature}\r\n'.encode())
        if part: wire.extend(part + b'\r\n')
        previous = signature
    if trailer:
        canonical_trailer = 'x-amz-checksum-sha256:' + checksum + '\n'
        signature = mac(key, '\n'.join(('AWS4-HMAC-SHA256-TRAILER', timestamp, scope, previous, digest(canonical_trailer.encode())))).hex()
        wire.extend(f'x-amz-checksum-sha256:{checksum}\r\nx-amz-trailer-signature:{signature}\r\n'.encode())
    wire.extend(b'\r\n')
    fields['content-length'] = str(len(wire))
    return bytes(wire), fields
