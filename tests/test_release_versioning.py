"""Socket/process-free oracle controls; these never qualify a packaged image."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from release_feedback.cases import Cases, Failure, Reply
from release_feedback.versioning import run_versioning, VERSIONING_CASES
from release_feedback import receipts


class FakeCLI:
    def __init__(self, root, fault=None):
        self.root = root
        self.fault = fault
        self.env = {}
        self.access, self.secret = 'PUBLIC_ACCESS_TRAP', 'PUBLIC_SECRET_TRAP'
        self.port = 10101
        self.restarts = 0
        self.status = None
        self.histories = {}
        self.uploads = {}
        self.serial = 0
        self.calls = []

    def next_id(self):
        self.serial += 1
        return str(uuid.UUID(int=self.serial))

    def store(self, key, body, metadata, marker=False):
        history = self.histories.setdefault(key, [])
        identity = self.next_id() if self.status == 'Enabled' else 'null'
        if self.fault == 'same-id' and key == 'payload' and history:
            identity = history[0]['VersionId']
        if identity == 'null' and self.fault != 'null-retained':
            history[:] = [entry for entry in history if entry['VersionId'] != 'null']
        if self.fault == 'lost-old' and key == 'payload':
            history.clear()
        entry = dict(Key=key, VersionId=identity, Body=body, Metadata=metadata,
                     ContentType='text/plain', ContentLength=len(body), ETag='"synthetic-etag"',
                     DeleteMarker=marker)
        history.insert(0, entry)
        return entry

    def command(self, action, args, timeout):
        assert action == 'versioning-sdk' and timeout == 15 and '--no-paginate' in args
        assert args[:4] == ['/bin/sh', '-c', 'ulimit -f 128 || exit 125; exec "$@"', 'versioning-sdk']
        assert self.access not in args and self.secret not in args
        assert args[args.index('--endpoint-url') + 1] == f'http://127.0.0.1:{self.port}'
        self.calls.append(args)
        start = args.index('s3api')
        operation = args[start + 1]
        parameters = {}
        tail = args[start + 2:]
        while tail and tail[0].startswith('--'):
            name, value, *tail = tail
            parameters[name[2:].replace('-', '_')] = value
        key = parameters.get('key')
        result = {}
        if operation == 'get-bucket-versioning':
            result = {'Status': self.status} if self.status else {}
        elif operation == 'put-bucket-versioning':
            self.status = json.loads(parameters['versioning_configuration'])['Status']
        elif operation == 'put-object':
            result = self.store(key, Path(parameters['body']).read_bytes(), json.loads(parameters['metadata']))
        elif operation == 'create-multipart-upload':
            self.uploads['upload'] = dict(key=key, metadata=json.loads(parameters['metadata']), result=None)
            result = dict(UploadId='upload')
        elif operation == 'upload-part':
            self.uploads['upload']['body'] = Path(parameters['body']).read_bytes()
            result = dict(ETag='"part"')
        elif operation == 'complete-multipart-upload':
            upload = self.uploads['upload']
            if upload['result'] is None or self.fault == 'replay-new':
                upload['result'] = self.store(key, upload['body'], upload['metadata'])
            result = upload['result']
        elif operation in ('get-object', 'head-object'):
            selected = next((entry for entry in self.histories.get(key, [])
                             if entry['VersionId'] == parameters['version_id']), None)
            if selected is None:
                raise Failure('versioning-sdk-command')
            result = copy.deepcopy(selected)
            if self.fault == 'metadata' and operation == 'head-object':
                result['Metadata'] = {}
            if operation == 'get-object':
                Path(tail[0]).write_bytes(selected['Body'])
        elif operation == 'delete-object':
            history = self.histories[key]
            if 'version_id' in parameters:
                history[:] = [entry for entry in history if entry['VersionId'] != parameters['version_id']]
            else:
                result = self.store(key, b'', {}, marker=True)
        elif operation == 'list-object-versions':
            entries = []
            for name, history in sorted(self.histories.items()):
                if name.startswith(parameters.get('prefix', '')):
                    entries += [dict(Key=name, VersionId=entry['VersionId'], IsLatest=index == 0,
                                     DeleteMarker=entry['DeleteMarker']) for index, entry in enumerate(history)]
            if 'key_marker' in parameters and self.fault != 'pagination-loop':
                pair = (parameters['key_marker'], parameters['version_id_marker'])
                index = next(index for index, entry in enumerate(entries) if (entry['Key'], entry['VersionId']) == pair)
                entries = entries[index + 1:]
            limit = int(parameters.get('max_keys', '1000'))
            truncated = len(entries) > limit
            page = entries[:limit]
            result = dict(Versions=[entry for entry in page if not entry['DeleteMarker']],
                          DeleteMarkers=[entry for entry in page if entry['DeleteMarker']], IsTruncated=truncated)
            if truncated:
                result.update(NextKeyMarker=page[-1]['Key'], NextVersionIdMarker=page[-1]['VersionId'])
        elif operation == 'delete-objects':
            entries = json.loads(parameters['delete'])['Objects']
            for index, entry in enumerate(entries):
                if self.fault == 'batch-skips-version' and index == 0:
                    continue
                history = self.histories[entry['Key']]
                history[:] = [item for item in history if item['VersionId'] != entry['VersionId']]
            result = dict(Deleted=entries)
        elif operation == 'delete-bucket':
            assert not any(self.histories.values())
        elif operation != 'create-bucket':
            raise AssertionError('unexpected mock operation')
        result = {name: value for name, value in result.items() if name not in ('Body', 'DeleteMarker') or name == 'DeleteMarker' and value}
        return 0, b'not-json' if self.fault == 'sdk-json' else json.dumps(result).encode()

    def restart_and_resolve_port(self):
        self.restarts += 1
        self.port += 1
        if self.fault == 'restart-state':
            self.status = None
        if self.fault == 'restart-bytes':
            self.histories['payload'][-1]['Body'] = b'bad'

    def request(self, method, target, body, headers, authenticated):
        query = parse_qs(urlsplit(target).query, keep_blank_values=True)
        if 'versions' in query:
            return Reply(200, {}, b'<ListVersionsResult><Key>pages%2Fa%20b</Key><CommonPrefixes><Prefix>pages%2Fdir%2F</Prefix></CommonPrefixes></ListVersionsResult>')
        key = unquote(urlsplit(target).path.split('/', 2)[2])
        selector = query.get('versionId', [None])[0]
        history = self.histories.get(key, [])
        if selector is not None:
            entry = next((entry for entry in history if entry['VersionId'] == selector), None)
            if entry is None:
                return Reply(404, {}, b'<Error><Code>NoSuchVersion</Code></Error>')
        else:
            entry = history[0]
        status = 405 if selector else 404
        fields = {'x-amz-version-id': entry['VersionId'], 'x-amz-delete-marker': 'true'}
        if self.fault == 'marker-not-hidden' and selector is None:
            status = 200
        if self.fault == 'marker-head' and method == 'HEAD':
            fields.clear()
        return Reply(status, fields, b'')


class VersioningControls(unittest.TestCase):
    def test_all_sdk_rows_require_restart_exact_bytes_metadata_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            io = FakeCLI(Path(directory))
            with patch('shutil.which', return_value='/synthetic/aws'):
                rows = run_versioning(Cases(io, '9.9.9'))
            self.assertEqual(rows, [dict(case=name, passed=True) for name in VERSIONING_CASES])
            self.assertEqual(io.restarts, 2)
            self.assertEqual(io.env, {})
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_each_synthetic_regression_prevents_qualification_and_restores_environment(self):
        for fault in ('lost-old', 'same-id', 'restart-state', 'restart-bytes', 'metadata', 'replay-new',
                      'null-retained', 'marker-not-hidden', 'marker-head', 'pagination-loop',
                      'batch-skips-version', 'sdk-json'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                io = FakeCLI(Path(directory), fault)
                io.env['AWS_ACCESS_KEY_ID'] = 'prior-value'
                with patch('shutil.which', return_value='/synthetic/aws'), self.assertRaises(Failure):
                    run_versioning(Cases(io, '9.9.9'))
                self.assertEqual(io.env, {'AWS_ACCESS_KEY_ID': 'prior-value'})
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_cli_missing_fails_without_launch_or_fabricated_pass(self):
        with patch('shutil.which', return_value=None), self.assertRaises(Failure):
            run_versioning(Cases(None, '9.9.9'))

    def test_receipt_requires_all_versioning_rows_and_binds_their_source(self):
        self.assertTrue(set(VERSIONING_CASES) <= set(receipts.ALL_CASES))
        self.assertIn('versioning.py', receipts.CODE)
        self.assertEqual(receipts.CASE_COUNT, 35)
        runner = (ROOT / 'scripts/release-feedback.py').read_text()
        self.assertIn('run_versioning(suite, rows=versioning_rows)', runner)
        self.assertIn('suite.rows + signed_rows + versioning_rows', runner)

    def test_native_ci_and_release_require_the_bounded_real_enospc_case(self):
        for workflow in ('ci.yml', 'release.yml'):
            self.assertIn('bash scripts/test-filestore-enospc.sh',
                          (ROOT / '.github/workflows' / workflow).read_text())
        script = (ROOT / 'scripts/test-filestore-enospc.sh').read_text()
        self.assertIn('size=8m,nodev,nosuid,noexec', script)
        self.assertIn('--ignored --exact', script)
        self.assertIn("1 passed; 0 failed; 0 ignored;", script)
        self.assertIn('sudo -n umount "$root"', script)


if __name__ == '__main__':
    unittest.main()
