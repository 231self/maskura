#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute actual loaded-image FileStore regressions; scope deliberately not full matrix."""
import argparse
import json
import re
import resource
import signal
import tempfile
from pathlib import Path
from release_feedback.cases import Cases, Failure, IMPLEMENTED, CODES
from release_feedback.signed_cases import run_signed, SIGNED_CASES
from release_feedback.versioning import run_versioning, VERSIONING_CASES
from release_feedback.image import ImageIO, ID
from release_feedback.transport import Budget, BoundaryError
from release_feedback.relay import RELAY_CODES
from release_feedback.receipts import EXCLUSIONS, PHASES, SCOPE, digest, harness_sha, identity, validate_report, write

# Closed vocabulary only: never persist exception text, command output or I/O data.
BOUNDARY_CODES = frozenset((
    'cleanup-deadline', 'command-deadline', 'command-drain-bound', 'command-nonzero',
    'command-output-bound', 'command-internal-error', 'explicit-execute-guard-required',
    'http-absolute-deadline', 'http-connect-failed', 'http-socket-closed', 'http-transport-error',
    'http-wire-bound', 'http-write-failed', 'invalid-captured-child', 'overall-deadline',
    'owned-child-cleanup-incomplete', 'request-body-bound', 'request-target-invalid',
    'residual-owned-process-group', 'response-body-bound', 'stage-deadline',
    'supervisor-interrupted', 'uncaptured-child-handle', 'unexpected-http-file-mode',
    'work-ended-for-cleanup', 'actual-image-id-required', 'docker-host-root-required',
    'existing-lock-600s', 'existing-lock-ownership', 'host-12GiB-floor',
    'image-readiness-deadline', 'image-source-version-platform-binding',
    'internal-network-required', 'inventory-ambiguous', 'inventory-identity',
    'inventory-name', 'inventory-shape', 'json-duplicate-field', 'native-daemon-platform',
    'native-linux-runner-required', 'native-packaged-elf-required',
    'numeric-loopback-publication', 'numeric-metadata-shape',
    'official-packaged-components-required', 'owned-attempt-cap', 'owned-name-collision',
    'owned-name-shape', 'owned-port-range', 'owned-resource-disappeared',
    'owned-resource-replaced', 'owned-root-symlink', 'owned-store-cap',
    'owned-writable-layer-cap', 'ownership-mismatch', 'ownership-shape',
    'pulled-repodigest-binding', 'successful-inventory-required',
    'owned-store-monitor-total-deadline',
)) | RELAY_CODES
ASSERTION_CODES = frozenset((
    'batch-per-key-error', 'openapi-shape', 'synthetic-payload-bound',
    'unexpected-delete-result-entry', 'unknown-case', 'xml-declaration-forbidden',
    'xml-invalid', 'xml-namespace-invalid', 'xml-required-field', 'xml-root-invalid',
    'xml-size-bound', 'batch-integrity-not-rejected', 'batch-per-key-outcome',
    'batch-valid-status', 'case-count-or-selected-failure', 'completed-upload-still-listed',
    'customer-metadata', 'deleted-object-still-listed', 'deleted-object-still-readable',
    'invalid-secret-accepted', 'list-membership-size', 'list-shape', 'list-status',
    'list-unexpected-pagination', 'mpu-complete-status', 'mpu-init-status',
    'mpu-part-status-etag', 'object-byte-equality', 'object-length', 'object-status',
    'openapi-status', 'put-status', 'rejected-admission-returned-upload-id',
    'representation-encoding-not-customer', 'representation-type', 'reserved-not-rejected',
    'reserved-upload-list-delta', 'response-bound', 'restart-list-membership-size',
    'runtime-version-mismatch', 'upload-list-status', 'uploads-unexpected-pagination',
    'signed-delete-integrity-before-side-effects', 'signed-delete-not-deleted',
    'signed-delete-still-listed', 'signed-delete-valid-outcomes', 'signed-delete-valid-status',
    'signed-mpu-complete', 'signed-mpu-init', 'signed-mpu-part', 'signed-mpu-still-open',
    'signed-put-status', 'signed-response-bound',
    'versioning-sdk-unavailable', 'versioning-sdk-command', 'versioning-sdk-json',
    'versioning-state', 'versioning-identity', 'versioning-exact-identity',
    'versioning-exact-metadata', 'versioning-exact-bytes', 'versioning-missing-version',
    'versioning-multipart-replay', 'versioning-multipart-duplicate',
    'versioning-marker', 'versioning-null', 'versioning-pagination', 'versioning-batch-delete',
))
CASE_NAMES = frozenset(IMPLEMENTED + SIGNED_CASES + VERSIONING_CASES)
STAGES = frozenset(('setup', 'lock', 'preflight', 'start', 'core', 'signed', 'versioning', 'cleanup', 'receipt'))
ACTIONS = frozenset((
    'daemon-platform', 'bound-local-image', 'internal-network', 'start-packaged-image',
    'official-components-only', 'native-packaged-elf', 'owned-store-metadata-only',
    'owned-writable-layer-size', 'owned-loopback-port', 'restart-owned-container',
    'owned-container-endpoint', 'owned-network-endpoint',
    'versioning-sdk',
    *(prefix + kind for prefix in ('inventory-', 'owner-', 'create-', 'remove-owned-')
      for kind in ('container', 'volume', 'network')),
))
CLEANUP_KEYS = ('owned_resources_absent', 'allocated_ports_kernel_refused',
    'captured_children_reaped', 'no_active_handles', 'no_sticky_command_failure',
    'lock_released', 'cleanup_within_shared_reserve')

def known(value, vocabulary):
    return type(value) is str and value in vocabulary

def closed_failure(exc, stage, io=None, suite=None):
    result = {'category': 'packaged-image-regression-failed',
              'stage': stage if known(stage, STAGES) else 'setup'}
    if isinstance(exc, BoundaryError):
        if len(exc.args) == 1 and known(exc.args[0], BOUNDARY_CODES): result['category'] = exc.args[0]
    elif isinstance(exc, Failure):
        if known(exc.category, ASSERTION_CODES): result['category'] = exc.category
        if type(exc.status) is int and 100 <= exc.status <= 599: result['status'] = exc.status
        if known(exc.code, CODES | {'other'}): result['code'] = exc.code
    case = exc.case if isinstance(exc, Failure) else getattr(suite, 'case', None)
    if not known(case, CASE_NAMES): case = getattr(suite, 'case', None)
    if known(case, CASE_NAMES): result['case'] = case
    commands = getattr(io, 'commands', ())
    if commands and isinstance(commands[-1], dict) and commands[-1].get('passed') is False:
        action = commands[-1].get('action')
        if known(action, ACTIONS): result['action'] = action
    return result

def closed_rows(rows):
    return [dict(case=row['case'], passed=row['passed']) for row in rows
            if isinstance(row, dict) and known(row.get('case'), CASE_NAMES)
            and type(row.get('passed')) is bool]

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    for name in ('image-id', 'arch', 'source-sha', 'version', 'phase', 'report', 'published-ref', 'lock-existing'): parser.add_argument('--' + name)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({'status': 'not-executed', 'scope': SCOPE, 'full_feedback_matrix_passed': False})); return 2
    budget = Budget(); io = suite = None; signed_rows = []; versioning_rows = []; stage = 'setup'; previous = {}; interrupted = [False]
    def stop_requested(signum, frame):
        interrupted[0] = True
        if io is not None: io.cancelled = True  # Cooperative; capture gap remains safe.
    report = dict(schema_version=1, scope=SCOPE, status='failed', source_sha=None, version=None,
        architecture=None, image_id=None, phase=None, digest=None, harness_sha256=harness_sha(),
        cases=[], cleanup={}, full_feedback_matrix_passed=False, scope_exclusions=list(EXCLUSIONS))
    try:
        identity(args.source_sha, args.version, args.arch)
        if args.phase not in PHASES or not ID.fullmatch(args.image_id or ''): raise ValueError('runner-identity')
        report.update(source_sha=args.source_sha, version=args.version, architecture=args.arch, image_id=args.image_id, phase=args.phase)
        if args.phase == 'published-replay':
            if not args.published_ref or '@' not in args.published_ref: raise ValueError('published-reference-required')
            report['digest'] = digest(args.published_ref.rsplit('@', 1)[1])
        elif args.published_ref: raise ValueError('unexpected-published-reference')
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP): previous[sig] = signal.signal(sig, stop_requested)
        root = Path(tempfile.mkdtemp(prefix='maskura-release-feedback-'))
        io = ImageIO(root, args.image_id, args.arch, args.source_sha, args.version, permit=True, budget=budget)
        if interrupted[0]: io.cancelled = True
        if args.lock_existing:
            stage = 'lock'; io.acquire_existing_lock(Path(args.lock_existing))
        stage = 'preflight'; io.preflight(args.published_ref)
        stage = 'start'; io.start()
        stage = 'core'; suite = Cases(io, args.version); suite.run()
        stage = 'signed'; run_signed(suite, rows=signed_rows)
        stage = 'versioning'; run_versioning(suite, rows=versioning_rows); report['status'] = 'passed'
    except BaseException as exc:
        report['failure'] = closed_failure(exc, stage, io, suite)
    finally:
        if suite is not None:
            rows = suite.rows + signed_rows + versioning_rows
            report['cases'] = closed_rows(rows)
            if len(report['cases']) != len(rows) or any(set(row) != {'case', 'passed'} for row in rows if isinstance(row, dict)):
                report['status'] = 'failed'
                report.setdefault('failure', {'category': 'receipt-contract-failed', 'stage': 'receipt'})
            case = getattr(suite, 'case', None)
            if stage in ('core', 'signed', 'versioning') and report['status'] == 'failed' and known(case, CASE_NAMES):
                if not any(row['case'] == case for row in report['cases']):
                    report['cases'].append(dict(case=case, passed=False))
        report['cleanup'] = dict.fromkeys(CLEANUP_KEYS, False)
        if io is not None:
            try:
                cleanup = io.cleanup()
                if isinstance(cleanup, dict):
                    report['cleanup'] = {key: cleanup.get(key) is True for key in CLEANUP_KEYS}
                if not isinstance(cleanup, dict) or set(cleanup) != set(CLEANUP_KEYS) or not all(report['cleanup'].values()):
                    report['cleanup_failure'] = {'category': 'cleanup-incomplete', 'stage': 'cleanup'}
            except BaseException as exc:
                report['cleanup_failure'] = closed_failure(exc, 'cleanup', io)
        else: report['cleanup_failure'] = {'category': 'cleanup-not-started', 'stage': 'cleanup'}
        if 'cleanup_failure' in report:
            report['status'] = 'failed'; report.setdefault('failure', report['cleanup_failure'].copy())
        if interrupted[0]:
            report['status'] = 'failed'; report.setdefault('failure', {'category': 'supervisor-interrupted', 'stage': stage})
        if io is not None and io.budget.clock() > io.budget.origin + 1800:
            report['status'] = 'failed'; report.setdefault('failure', {'category': 'overall-deadline', 'stage': 'cleanup'})
        if report['status'] == 'passed':
            try: validate_report(report, args.source_sha, args.version, args.arch, args.phase, harness_sha())
            except BaseException: report['status'] = 'failed'; report['failure'] = {'category': 'receipt-contract-failed', 'stage': 'receipt'}
        try:
            if args.report: write(args.report, report)
            summary = {'scope': SCOPE, 'status': report['status'], 'case_count': len(report['cases']), 'full_feedback_matrix_passed': False}
            for key in ('failure', 'cleanup_failure'):
                if key in report: summary[key] = report[key]
            print(json.dumps(summary))
        finally:
            for sig, handler in previous.items(): signal.signal(sig, handler)
    return 0 if report['status'] == 'passed' else 1

if __name__ == '__main__': raise SystemExit(main())
