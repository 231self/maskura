# SPDX-License-Identifier: Apache-2.0
"""Unmodified AWS CLI versioning rows, inside the existing owned image boundary."""
import json
from pathlib import Path
import shutil
import uuid
from urllib.parse import quote

from .cases import Failure, parse_xml, values

VERSIONING_CASES = (
    'versioning-sdk-exact-restart',
    'versioning-sdk-multipart-replay',
    'versioning-sdk-markers-suspension',
    'versioning-sdk-pagination-delete',
)


def run_versioning(c, rows=None):
    rows = [] if rows is None else rows
    c.case = VERSIONING_CASES[0]
    executable = shutil.which('aws')
    c.check(executable is not None, 'versioning-sdk-unavailable')
    io = c.io
    bucket = 'versioning-qualification'
    source = Path(io.root) / 'versioning-input'
    output = Path(io.root) / 'versioning-output'
    original = {name: io.env.get(name) for name in (
        'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_DEFAULT_REGION',
        'AWS_MAX_ATTEMPTS', 'AWS_PAGER',
    )}
    io.env.update(AWS_ACCESS_KEY_ID=io.access, AWS_SECRET_ACCESS_KEY=io.secret,
                  AWS_DEFAULT_REGION='us-east-1', AWS_MAX_ATTEMPTS='1', AWS_PAGER='')

    def api(operation, outfile=None, **parameters):
        # Endpoint is resolved afresh after each owned-container restart. No
        # credential or raw command output is included in a receipt/diagnostic.
        args = [executable, '--endpoint-url', f'http://127.0.0.1:{io.port}',
                '--cli-connect-timeout', '2', '--cli-read-timeout', '8',
                '--output', 'json', '--no-paginate', 's3api', operation, '--bucket', bucket]
        for name, value in parameters.items():
            args += ['--' + name.replace('_', '-'),
                     json.dumps(value) if isinstance(value, (dict, list)) else str(value)]
        if outfile is not None:
            outfile.unlink(missing_ok=True)
            args.append(str(outfile))
        # Bound a surprising SDK GET response at the OS file-write boundary,
        # before the periodic attempt-directory guard could observe it. exec
        # preserves the captured process identity; no credentials enter argv.
        command = ['/bin/sh', '-c', 'ulimit -f 128 || exit 125; exec "$@"',
                   'versioning-sdk', *args]
        code, raw = io.command('versioning-sdk', command, timeout=15)
        c.check(code == 0, 'versioning-sdk-command')
        try:
            result = json.loads(raw) if raw.strip() else {}
        except (ValueError, TypeError):
            raise Failure('versioning-sdk-json', c.case) from None
        c.check(isinstance(result, dict), 'versioning-sdk-json')
        return result

    def state(status):
        api('put-bucket-versioning', versioning_configuration={'Status': status})
        c.check(api('get-bucket-versioning').get('Status') == status, 'versioning-state')

    def put(key, body, label):
        source.write_bytes(body)
        result = api('put-object', key=key, body=str(source), content_type='text/plain',
                     metadata={'fixture': label})
        return result

    def concrete(result):
        value = result.get('VersionId')
        c.check(isinstance(value, str) and value != 'null', 'versioning-identity')
        try:
            canonical = str(uuid.UUID(value))
        except (ValueError, AttributeError):
            raise Failure('versioning-identity', c.case) from None
        c.check(canonical == value, 'versioning-identity')
        return value

    def exact(key, version, body, label, etag=None):
        for method in ('get-object', 'head-object'):
            result = api(method, outfile=output if method == 'get-object' else None,
                         key=key, version_id=version)
            c.check(result.get('VersionId') == version, 'versioning-exact-identity')
            c.check(result.get('ContentType') == 'text/plain'
                    and result.get('ContentLength') == len(body)
                    and result.get('Metadata') == {'fixture': label}, 'versioning-exact-metadata')
            if etag is not None:
                c.check(result.get('ETag') == etag, 'versioning-exact-metadata')
            if method == 'get-object':
                c.check(output.stat().st_size == len(body) and output.read_bytes() == body,
                        'versioning-exact-bytes')

    def path(key, version=None):
        return '/' + bucket + '/' + quote(key, safe='/') + (
            '?versionId=' + quote(version, safe='') if version is not None else '')

    try:
        api('create-bucket')
        c.check('Status' not in api('get-bucket-versioning'), 'versioning-state')
        put('legacy', b'legacy', 'legacy')
        state('Enabled')
        a = put('payload', b'A', 'A')
        b = put('payload', b'B', 'B')
        aid, bid = concrete(a), concrete(b)
        c.check(aid != bid, 'versioning-identity')
        io.restart_and_resolve_port()
        c.check(api('get-bucket-versioning').get('Status') == 'Enabled', 'versioning-state')
        exact('payload', aid, b'A', 'A', a.get('ETag'))
        exact('payload', bid, b'B', 'B', b.get('ETag'))
        exact('legacy', 'null', b'legacy', 'legacy')
        missing = c.request('GET', path('payload', str(uuid.UUID(int=0))))
        c.check(missing.status == 404 and values(parse_xml(missing.body), 'Code') == ['NoSuchVersion'],
                'versioning-missing-version')
        rows.append(dict(case=c.case, passed=True))

        c.case = VERSIONING_CASES[1]
        initiated = api('create-multipart-upload', key='multipart', content_type='text/plain',
                        metadata={'fixture': 'multipart'})
        upload = initiated['UploadId']
        source.write_bytes(b'multipart')
        part = api('upload-part', key='multipart', upload_id=upload, part_number=1, body=str(source))
        recipe = {'Parts': [{'PartNumber': 1, 'ETag': part['ETag']}]}
        completed = api('complete-multipart-upload', key='multipart', upload_id=upload, multipart_upload=recipe)
        mid = concrete(completed)
        put('multipart', b'newer', 'newer')
        io.restart_and_resolve_port()
        for _ in range(2):
            replay = api('complete-multipart-upload', key='multipart', upload_id=upload, multipart_upload=recipe)
            c.check(replay.get('VersionId') == mid and replay.get('ETag') == completed.get('ETag'),
                    'versioning-multipart-replay')
        exact('multipart', mid, b'multipart', 'multipart', completed.get('ETag'))
        listed = api('list-object-versions', prefix='multipart')
        c.check(len(listed.get('Versions', [])) == 2, 'versioning-multipart-duplicate')
        rows.append(dict(case=c.case, passed=True))

        c.case = VERSIONING_CASES[2]
        marker = api('delete-object', key='payload')
        marker_id = concrete(marker)
        c.check(marker.get('DeleteMarker') is True, 'versioning-marker')
        for method, selector, status in [('GET', None, 404), ('HEAD', marker_id, 405)]:
            reply = c.request(method, path('payload', selector))
            c.check(reply.status == status and reply.headers.get('x-amz-delete-marker') == 'true'
                    and reply.headers.get('x-amz-version-id') == marker_id, 'versioning-marker')
        exact('payload', aid, b'A', 'A')
        api('delete-object', key='payload', version_id=marker_id)
        state('Suspended')
        for body in (b'null-A', b'null-B'):
            c.check(put('payload', body, 'null').get('VersionId') == 'null', 'versioning-null')
        exact('payload', 'null', b'null-B', 'null')
        c.check(len(api('list-object-versions', prefix='payload').get('Versions', [])) == 3, 'versioning-null')
        marker = api('delete-object', key='payload')
        c.check(marker.get('VersionId') == 'null' and marker.get('DeleteMarker') is True, 'versioning-null')
        api('delete-object', key='payload', version_id='null')
        exact('payload', bid, b'B', 'B')
        state('Enabled')
        rows.append(dict(case=c.case, passed=True))

        c.case = VERSIONING_CASES[3]
        for key in ('pages/a b', 'pages/a b', 'pages/dir/é'):
            put(key, b'page', 'page')
        seen = set()
        parameters = {'prefix': 'pages/', 'max_keys': 1}
        for _ in range(8):
            page = api('list-object-versions', **parameters)
            entries = page.get('Versions', []) + page.get('DeleteMarkers', [])
            c.check(len(entries) == 1, 'versioning-pagination')
            identity = (entries[0]['Key'], entries[0]['VersionId'])
            c.check(identity not in seen, 'versioning-pagination')
            seen.add(identity)
            if page.get('IsTruncated') is not True:
                break
            parameters.update(key_marker=page['NextKeyMarker'], version_id_marker=page['NextVersionIdMarker'])
        c.check(len(seen) == 3 and page.get('IsTruncated') is False, 'versioning-pagination')
        encoded = c.request('GET', '/' + bucket + '?versions&prefix=pages%2F&delimiter=%2F&encoding-type=url')
        c.check(encoded.status == 200 and b'pages%2Fa%20b' in encoded.body
                and b'pages%2Fdir%2F' in encoded.body, 'versioning-pagination')
        listing = api('list-object-versions')
        entries = listing.get('Versions', []) + listing.get('DeleteMarkers', [])
        c.check(0 < len(entries) < 20, 'versioning-pagination')
        deleted = api('delete-objects', delete={'Objects': [
            {'Key': item['Key'], 'VersionId': item['VersionId']} for item in entries]})
        c.check(not deleted.get('Errors') and len(deleted.get('Deleted', [])) == len(entries),
                'versioning-batch-delete')
        final = api('list-object-versions')
        c.check(not final.get('Versions') and not final.get('DeleteMarkers'), 'versioning-batch-delete')
        api('delete-bucket')
        rows.append(dict(case=c.case, passed=True))
        return rows
    finally:
        source.unlink(missing_ok=True)
        output.unlink(missing_ok=True)
        for name, value in original.items():
            if value is None:
                io.env.pop(name, None)
            else:
                io.env[name] = value
