use proptest::prelude::*;
use serde_json::json;
use std::sync::Arc;

use super::*;
use crate::filesystem_persistence::FaultPoint;
use crate::multipart_staging::MultipartSnapshot;

const DAY_MS: i64 = 24 * 60 * 60 * 1_000;

fn identity(upload_id: &str, tenant: &str) -> MultipartIdentity {
    MultipartIdentity {
        tenant_id: tenant.to_string(),
        credential_policy_id: "policy".to_string(),
        bucket: "bucket".to_string(),
        key: "key".to_string(),
        upload_id: upload_id.to_string(),
    }
}

fn upload(identity: MultipartIdentity, max_staged_bytes: u64) -> MultipartUpload {
    MultipartUpload {
        identity,
        namespace_epoch: Some(7),
        snapshot: MultipartSnapshot {
            metadata: BTreeMap::new(),
            tags: BTreeMap::new(),
            checksum_mode: Some("SHA256".to_string()),
            destination: json!({"mode": "local"}),
            plugin_snapshot: json!({"revision": "one"}),
            max_staged_bytes,
        },
        lifecycle: MultipartLifecycle::Open,
        staged_bytes: 0,
        reserved_bytes: 0,
        created_at_ms: 100,
        expires_at_ms: 10_000,
        updated_at_ms: 100,
        tombstone_until_ms: None,
        complete_request_fingerprint: None,
        completion_lease_owner: None,
        completion_lease_expires_at_ms: None,
        completion_fencing_token: 0,
        destination_operation_id: None,
        publishing_started_at_ms: None,
        destination_commit: None,
        completion_result: None,
    }
}

fn event(
    identity: &MultipartIdentity,
    sequence: u64,
    transition: FileMultipartTransitionV1,
) -> FileMultipartEventV1 {
    FileMultipartEventV1 {
        schema_version: FILE_MULTIPART_SCHEMA_VERSION,
        sequence,
        event_id: Uuid::from_u128(sequence as u128),
        identity: identity.clone(),
        transition,
    }
}

fn create_event(identity: &MultipartIdentity, max: u64) -> FileMultipartEventV1 {
    event(
        identity,
        1,
        FileMultipartTransitionV1::UploadCreated {
            upload: Box::new(upload(identity.clone(), max)),
        },
    )
}

fn pending(identity: &MultipartIdentity, number: u32, attempt: u32, bytes: u64) -> PendingPart {
    PendingPart {
        upload_id: identity.upload_id.clone(),
        part_number: number,
        attempt,
        artifact_key: format!("multipart/{}/{number}/{attempt}", identity.upload_id),
        reserved_bytes: bytes,
    }
}

fn part(pending: &PendingPart, bytes: u64) -> MultipartPart {
    MultipartPart {
        upload_id: pending.upload_id.clone(),
        part_number: pending.part_number,
        attempt: pending.attempt,
        artifact_key: pending.artifact_key.clone(),
        etag: format!("etag-{}", pending.attempt),
        checksum_sha256: format!("sha-{}", pending.attempt),
        size_bytes: bytes,
        created_at_ms: 200 + i64::from(pending.attempt),
    }
}

fn completion_result() -> MultipartCompletionResult {
    MultipartCompletionResult {
        etag: Some("final-etag".to_string()),
        checksum_sha256: "final-sha".to_string(),
        version_id: Some("version".to_string()),
        source_bytes: 200,
        size_bytes: 180,
        pipeline_evidence: None,
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("maskura-file-multipart-{}", Uuid::now_v7()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn adapter_identity(tenant: &str, key: &str) -> MultipartIdentity {
    MultipartIdentity {
        tenant_id: tenant.to_string(),
        credential_policy_id: "policy".to_string(),
        bucket: "bucket".to_string(),
        key: key.to_string(),
        upload_id: Uuid::now_v7().to_string(),
    }
}

fn adapter_upload(identity: MultipartIdentity, max_staged_bytes: u64) -> MultipartUpload {
    let mut upload = upload(identity, max_staged_bytes);
    upload.created_at_ms = 0;
    upload.updated_at_ms = 0;
    upload.expires_at_ms = i64::MAX / 2;
    upload
}

fn limits(bytes: u64) -> StagingQuotaLimits {
    StagingQuotaLimits::new(bytes, bytes).unwrap()
}

fn open_adapter(root: &Path, bytes: u64) -> FileMultipartRepository {
    FileMultipartRepository::open_for_test(
        root.to_path_buf(),
        limits(bytes),
        FilesystemPersistence::default(),
    )
    .unwrap()
}

fn selected(part: &MultipartPart) -> CompletePart {
    CompletePart {
        part_number: part.part_number,
        etag: part.etag.clone(),
        checksum_sha256: Some(part.checksum_sha256.clone()),
    }
}

fn apply_ok(reducer: &mut FileMultipartReducer, event: FileMultipartEventV1) {
    assert_eq!(reducer.apply(&event), Ok(ReducerApply::Applied));
}

fn reducer_with_current_part() -> (FileMultipartReducer, MultipartIdentity, PendingPart) {
    let identity = identity("upload", "tenant");
    let mut reducer = FileMultipartReducer::empty();
    apply_ok(&mut reducer, create_event(&identity, 1_000));
    let pending = pending(&identity, 1, 1, 400);
    apply_ok(
        &mut reducer,
        event(
            &identity,
            2,
            FileMultipartTransitionV1::PartReserved {
                pending: pending.clone(),
                created_at_ms: 200,
            },
        ),
    );
    apply_ok(
        &mut reducer,
        event(
            &identity,
            3,
            FileMultipartTransitionV1::PartCommitted {
                pending: pending.clone(),
                part: part(&pending, 300),
                updated_at_ms: 210,
            },
        ),
    );
    (reducer, identity, pending)
}

#[test]
fn full_lifecycle_replay_enforces_replacement_outbox_and_publication() {
    let (mut reducer, identity, first) = reducer_with_current_part();
    let second = pending(&identity, 1, 2, 400);
    apply_ok(
        &mut reducer,
        event(
            &identity,
            4,
            FileMultipartTransitionV1::PartReserved {
                pending: second.clone(),
                created_at_ms: 220,
            },
        ),
    );
    assert_eq!(
        reducer.snapshot().upload.as_ref().unwrap().staged_bytes,
        300
    );
    assert_eq!(
        reducer.snapshot().upload.as_ref().unwrap().reserved_bytes,
        400
    );
    apply_ok(
        &mut reducer,
        event(
            &identity,
            5,
            FileMultipartTransitionV1::PartCommitted {
                pending: second.clone(),
                part: part(&second, 200),
                updated_at_ms: 230,
            },
        ),
    );
    assert_eq!(
        reducer.snapshot().upload.as_ref().unwrap().staged_bytes,
        500
    );
    assert_eq!(
        reducer
            .snapshot()
            .attempts
            .iter()
            .filter(|attempt| attempt.lifecycle == FilePartAttemptLifecycleV1::Current)
            .count(),
        1
    );
    apply_ok(
        &mut reducer,
        event(
            &identity,
            6,
            FileMultipartTransitionV1::ArtifactDeleted {
                artifact_key: first.artifact_key,
                updated_at_ms: 240,
            },
        ),
    );

    let selected = vec![CompletePart {
        part_number: 1,
        etag: "etag-2".to_string(),
        checksum_sha256: Some("sha-2".to_string()),
    }];
    apply_ok(
        &mut reducer,
        event(
            &identity,
            7,
            FileMultipartTransitionV1::CompletionAcquired {
                fingerprint: "fingerprint".to_string(),
                selected_parts: selected,
                owner: "worker-a".to_string(),
                lease_expires_at_ms: 400,
                fencing_token: 1,
                updated_at_ms: 300,
            },
        ),
    );
    apply_ok(
        &mut reducer,
        event(
            &identity,
            8,
            FileMultipartTransitionV1::CompletionRenewed {
                fencing_token: 1,
                lease_expires_at_ms: 450,
                updated_at_ms: 310,
            },
        ),
    );
    let operation_id =
        DestinationCommitPermit::deterministic_operation_id(&identity, "fingerprint");
    let permit = DestinationCommitPermit {
        upload_id: identity.upload_id.clone(),
        completion_fingerprint: "fingerprint".to_string(),
        fencing_token: 1,
        operation_id,
    };
    apply_ok(
        &mut reducer,
        event(
            &identity,
            9,
            FileMultipartTransitionV1::DestinationCommitBegun {
                permit: permit.clone(),
                publishing_started_at_ms: 320,
            },
        ),
    );
    let result = completion_result();
    apply_ok(
        &mut reducer,
        event(
            &identity,
            10,
            FileMultipartTransitionV1::DestinationCommitRecorded {
                permit: permit.clone(),
                record: DestinationCommitRecord {
                    operation_id,
                    result: result.clone(),
                    committed_at_ms: 330,
                },
                updated_at_ms: 330,
            },
        ),
    );
    apply_ok(
        &mut reducer,
        event(
            &identity,
            11,
            FileMultipartTransitionV1::CompletionCompleted {
                permit,
                result,
                completed_at_ms: 340,
                tombstone_until_ms: 340 + DAY_MS,
            },
        ),
    );
    assert_eq!(
        reducer.snapshot().upload.as_ref().unwrap().lifecycle,
        MultipartLifecycle::Completed
    );
    assert!(
        reducer
            .snapshot()
            .attempts
            .iter()
            .all(|attempt| { attempt.lifecycle == FilePartAttemptLifecycleV1::Retired })
    );
    apply_ok(
        &mut reducer,
        event(
            &identity,
            12,
            FileMultipartTransitionV1::ArtifactDeleted {
                artifact_key: second.artifact_key,
                updated_at_ms: 350,
            },
        ),
    );
    apply_ok(
        &mut reducer,
        event(
            &identity,
            13,
            FileMultipartTransitionV1::DestinationCommitReferenceCleared {
                expected_operation_id: operation_id,
                updated_at_ms: 360,
            },
        ),
    );
    apply_ok(
        &mut reducer,
        event(
            &identity,
            14,
            FileMultipartTransitionV1::CleanupAudited {
                audit: CleanupAudit {
                    id: Uuid::from_u128(999),
                    upload_id: identity.upload_id.clone(),
                    kind: "retired".to_string(),
                    detail: json!({"evidence": [{"artifact": "gone"}]}),
                    created_at_ms: 370,
                },
            },
        ),
    );
    apply_ok(
        &mut reducer,
        event(
            &identity,
            15,
            FileMultipartTransitionV1::TerminalUploadRetired {
                retired_at_ms: 340 + DAY_MS,
            },
        ),
    );
    assert!(reducer.snapshot().upload.is_none());
}

#[test]
fn exact_duplicate_is_idempotent_and_conflicting_duplicates_fail() {
    let identity = identity("duplicate", "tenant");
    let mut reducer = FileMultipartReducer::empty();
    let create = create_event(&identity, 100);
    assert_eq!(reducer.apply(&create), Ok(ReducerApply::Applied));
    let before = serde_json::to_value(reducer.snapshot()).unwrap();
    assert_eq!(reducer.apply(&create), Ok(ReducerApply::ExactDuplicate));
    assert_eq!(serde_json::to_value(reducer.snapshot()).unwrap(), before);

    let mut conflict = create;
    conflict.transition = FileMultipartTransitionV1::UploadCreated {
        upload: Box::new(upload(identity.clone(), 101)),
    };
    assert_eq!(
        reducer.apply(&conflict),
        Err(FileMultipartReducerError::ConflictingDuplicate)
    );
    let reused_id = FileMultipartEventV1 {
        sequence: 2,
        event_id: Uuid::from_u128(1),
        transition: FileMultipartTransitionV1::UploadAborted {
            aborted_at_ms: 200,
            tombstone_until_ms: 200 + DAY_MS,
        },
        schema_version: FILE_MULTIPART_SCHEMA_VERSION,
        identity,
    };
    assert_eq!(
        reducer.apply(&reused_id),
        Err(FileMultipartReducerError::ConflictingDuplicate)
    );
}

#[test]
fn snapshot_plus_event_replay_equals_full_replay_and_skips_compacted_log() {
    let (full, identity, pending) = reducer_with_current_part();
    let events = [
        create_event(&identity, 1_000),
        event(
            &identity,
            2,
            FileMultipartTransitionV1::PartReserved {
                pending: pending.clone(),
                created_at_ms: 200,
            },
        ),
        event(
            &identity,
            3,
            FileMultipartTransitionV1::PartCommitted {
                pending,
                part: full.snapshot().attempts[0].part.clone(),
                updated_at_ms: 210,
            },
        ),
    ];
    let mut compacted = FileMultipartReducer::from_snapshot(full.compacted_snapshot()).unwrap();
    for old in &events {
        assert_eq!(compacted.apply(old), Ok(ReducerApply::CompactedDuplicate));
    }
    assert_eq!(
        serde_json::to_value(compacted.snapshot()).unwrap(),
        serde_json::to_value(full.snapshot()).unwrap()
    );

    let abort = event(
        &identity,
        4,
        FileMultipartTransitionV1::UploadAborted {
            aborted_at_ms: 300,
            tombstone_until_ms: 300 + DAY_MS,
        },
    );
    let mut complete_replay = FileMultipartReducer::empty();
    for old in &events {
        apply_ok(&mut complete_replay, old.clone());
    }
    apply_ok(&mut complete_replay, abort.clone());
    apply_ok(&mut compacted, abort);
    assert_eq!(
        serde_json::to_value(compacted.snapshot()).unwrap(),
        serde_json::to_value(complete_replay.snapshot()).unwrap()
    );
}

#[test]
fn illegal_lifecycle_fence_permit_and_reference_transitions_fail_atomically() {
    let (base, identity, current_pending) = reducer_with_current_part();
    let selected = vec![CompletePart {
        part_number: 1,
        etag: "etag-1".to_string(),
        checksum_sha256: None,
    }];
    let invalid = vec![
        FileMultipartTransitionV1::CompletionRenewed {
            fencing_token: 1,
            lease_expires_at_ms: 500,
            updated_at_ms: 300,
        },
        FileMultipartTransitionV1::ArtifactDeleted {
            artifact_key: current_pending.artifact_key,
            updated_at_ms: 300,
        },
        FileMultipartTransitionV1::CompletionAcquired {
            fingerprint: "fingerprint".to_string(),
            selected_parts: selected.clone(),
            owner: "worker".to_string(),
            lease_expires_at_ms: 400,
            fencing_token: 2,
            updated_at_ms: 300,
        },
        FileMultipartTransitionV1::DestinationCommitReferenceCleared {
            expected_operation_id: Uuid::from_u128(8),
            updated_at_ms: 300,
        },
        FileMultipartTransitionV1::PartReserved {
            pending: pending(&identity, 10_001, 1, 1),
            created_at_ms: 300,
        },
    ];
    for transition in invalid {
        let mut reducer = FileMultipartReducer::from_snapshot(base.compacted_snapshot()).unwrap();
        let before = serde_json::to_value(reducer.snapshot()).unwrap();
        assert!(reducer.apply(&event(&identity, 4, transition)).is_err());
        assert_eq!(serde_json::to_value(reducer.snapshot()).unwrap(), before);
    }

    let mut reducer = FileMultipartReducer::from_snapshot(base.compacted_snapshot()).unwrap();
    apply_ok(
        &mut reducer,
        event(
            &identity,
            4,
            FileMultipartTransitionV1::CompletionAcquired {
                fingerprint: "fingerprint".to_string(),
                selected_parts: selected,
                owner: "worker".to_string(),
                lease_expires_at_ms: 400,
                fencing_token: 1,
                updated_at_ms: 300,
            },
        ),
    );
    let stale_takeover = event(
        &identity,
        5,
        FileMultipartTransitionV1::CompletionAcquired {
            fingerprint: "fingerprint".to_string(),
            selected_parts: vec![CompletePart {
                part_number: 1,
                etag: "etag-1".to_string(),
                checksum_sha256: None,
            }],
            owner: "other".to_string(),
            lease_expires_at_ms: 450,
            fencing_token: 2,
            updated_at_ms: 350,
        },
    );
    assert_eq!(
        reducer.apply(&stale_takeover),
        Err(FileMultipartReducerError::InvalidFence)
    );
}

#[test]
fn unknown_and_cross_tenant_references_fail_closed() {
    let upload_identity = identity("unknown", "tenant");
    let mut reducer = FileMultipartReducer::empty();
    let reserve = event(
        &upload_identity,
        1,
        FileMultipartTransitionV1::PartReserved {
            pending: pending(&upload_identity, 1, 1, 10),
            created_at_ms: 200,
        },
    );
    assert_eq!(
        reducer.apply(&reserve),
        Err(FileMultipartReducerError::UnknownReference)
    );

    apply_ok(&mut reducer, create_event(&upload_identity, 100));
    let thief = identity("unknown", "other-tenant");
    assert_eq!(
        reducer.apply(&event(
            &thief,
            2,
            FileMultipartTransitionV1::UploadAborted {
                aborted_at_ms: 200,
                tombstone_until_ms: 200 + DAY_MS,
            },
        )),
        Err(FileMultipartReducerError::IdentityConflict)
    );
    assert_eq!(
        reducer.apply(&event(
            &upload_identity,
            2,
            FileMultipartTransitionV1::ArtifactDeleted {
                artifact_key: "missing".to_string(),
                updated_at_ms: 200,
            },
        )),
        Err(FileMultipartReducerError::UnknownReference)
    );
}

#[test]
fn quota_overflow_and_aggregate_limits_are_rejected() {
    let identity = identity("quota", "tenant");
    let mut reducer = FileMultipartReducer::empty();
    apply_ok(&mut reducer, create_event(&identity, u64::MAX));
    apply_ok(
        &mut reducer,
        event(
            &identity,
            2,
            FileMultipartTransitionV1::PartReserved {
                pending: pending(&identity, 1, 1, u64::MAX),
                created_at_ms: 200,
            },
        ),
    );
    assert_eq!(
        reducer.apply(&event(
            &identity,
            3,
            FileMultipartTransitionV1::PartReserved {
                pending: pending(&identity, 2, 1, 1),
                created_at_ms: 201,
            },
        )),
        Err(FileMultipartReducerError::InvalidAccounting)
    );
    assert_eq!(reducer.snapshot().final_event_sequence, 2);

    assert_eq!(
        reconstruct_file_multipart_quotas(
            [reducer.snapshot()],
            StagingQuotaLimits::new(100, 100).unwrap(),
        ),
        Err(FileMultipartReducerError::InvalidAccounting)
    );
}

#[test]
fn corrupted_snapshots_and_history_bounds_are_rejected() {
    let (reducer, identity, _) = reducer_with_current_part();
    let mut wrong_counter = reducer.compacted_snapshot();
    wrong_counter.upload.as_mut().unwrap().staged_bytes += 1;
    assert!(matches!(
        FileMultipartReducer::from_snapshot(wrong_counter),
        Err(FileMultipartReducerError::InvalidAccounting)
    ));

    let mut two_current = reducer.compacted_snapshot();
    let mut duplicate = two_current.attempts[0].clone();
    duplicate.part.attempt = 2;
    duplicate.part.artifact_key = "another-artifact".to_string();
    two_current.attempts.push(duplicate);
    two_current.upload.as_mut().unwrap().staged_bytes *= 2;
    assert!(matches!(
        FileMultipartReducer::from_snapshot(two_current),
        Err(FileMultipartReducerError::InvalidPart)
    ));

    let mut too_many_audits = reducer.compacted_snapshot();
    too_many_audits.cleanup_audits = (0..=MAX_FILE_MULTIPART_AUDITS)
        .map(|index| CleanupAudit {
            id: Uuid::from_u128(10_000 + index as u128),
            upload_id: identity.upload_id.clone(),
            kind: "cleanup".to_string(),
            detail: json!({}),
            created_at_ms: 300,
        })
        .collect();
    assert!(matches!(
        FileMultipartReducer::from_snapshot(too_many_audits),
        Err(FileMultipartReducerError::BoundExceeded)
    ));

    let mut audit_reducer =
        FileMultipartReducer::from_snapshot(reducer.compacted_snapshot()).unwrap();
    let evidence = vec![json!({}); MAX_FILE_MULTIPART_EVIDENCE_RECORDS + 1];
    assert_eq!(
        audit_reducer.apply(&event(
            &identity,
            4,
            FileMultipartTransitionV1::CleanupAudited {
                audit: CleanupAudit {
                    id: Uuid::from_u128(5_000),
                    upload_id: identity.upload_id.clone(),
                    kind: "oversized".to_string(),
                    detail: serde_json::Value::Array(evidence),
                    created_at_ms: 300,
                },
            },
        )),
        Err(FileMultipartReducerError::BoundExceeded)
    );
}

#[test]
fn release_requires_exact_uncommitted_publishing_permit() {
    let (mut reducer, identity, _) = reducer_with_current_part();
    apply_ok(
        &mut reducer,
        event(
            &identity,
            4,
            FileMultipartTransitionV1::CompletionAcquired {
                fingerprint: "fingerprint".to_string(),
                selected_parts: vec![CompletePart {
                    part_number: 1,
                    etag: "etag-1".to_string(),
                    checksum_sha256: None,
                }],
                owner: "worker".to_string(),
                lease_expires_at_ms: 400,
                fencing_token: 1,
                updated_at_ms: 300,
            },
        ),
    );
    let permit = DestinationCommitPermit {
        upload_id: identity.upload_id.clone(),
        completion_fingerprint: "fingerprint".to_string(),
        fencing_token: 1,
        operation_id: DestinationCommitPermit::deterministic_operation_id(&identity, "fingerprint"),
    };
    apply_ok(
        &mut reducer,
        event(
            &identity,
            5,
            FileMultipartTransitionV1::DestinationCommitBegun {
                permit: permit.clone(),
                publishing_started_at_ms: 320,
            },
        ),
    );
    let mut stale = permit.clone();
    stale.fencing_token = 0;
    assert_eq!(
        reducer.apply(&event(
            &identity,
            6,
            FileMultipartTransitionV1::DestinationCommitReleased {
                permit: stale,
                updated_at_ms: 330,
            },
        )),
        Err(FileMultipartReducerError::InvalidPermit)
    );
    apply_ok(
        &mut reducer,
        event(
            &identity,
            6,
            FileMultipartTransitionV1::DestinationCommitReleased {
                permit,
                updated_at_ms: 330,
            },
        ),
    );
    assert_eq!(
        reducer.snapshot().upload.as_ref().unwrap().lifecycle,
        MultipartLifecycle::Completing
    );
}

#[test]
fn expiry_requires_deadline_and_terminal_cleanup_before_deletion() {
    let (mut reducer, identity, pending) = reducer_with_current_part();
    assert_eq!(
        reducer.apply(&event(
            &identity,
            4,
            FileMultipartTransitionV1::UploadExpired {
                expired_at_ms: 9_999,
                tombstone_until_ms: 9_999 + DAY_MS,
            },
        )),
        Err(FileMultipartReducerError::InvalidExpiry)
    );
    apply_ok(
        &mut reducer,
        event(
            &identity,
            4,
            FileMultipartTransitionV1::UploadExpired {
                expired_at_ms: 10_000,
                tombstone_until_ms: 10_000 + DAY_MS,
            },
        ),
    );
    assert_eq!(
        reducer.apply(&event(
            &identity,
            5,
            FileMultipartTransitionV1::TerminalUploadDeleted,
        )),
        Err(FileMultipartReducerError::IllegalLifecycle)
    );
    apply_ok(
        &mut reducer,
        event(
            &identity,
            5,
            FileMultipartTransitionV1::ArtifactDeleted {
                artifact_key: pending.artifact_key,
                updated_at_ms: 10_001,
            },
        ),
    );
    apply_ok(
        &mut reducer,
        event(
            &identity,
            6,
            FileMultipartTransitionV1::TerminalUploadDeleted,
        ),
    );
    assert!(reducer.snapshot().upload.is_none());
}

#[test]
fn completion_fingerprint_commit_and_result_are_immutable() {
    let (mut reducer, identity, _) = reducer_with_current_part();
    let selected = vec![CompletePart {
        part_number: 1,
        etag: "etag-1".to_string(),
        checksum_sha256: None,
    }];
    apply_ok(
        &mut reducer,
        event(
            &identity,
            4,
            FileMultipartTransitionV1::CompletionAcquired {
                fingerprint: "fingerprint".to_string(),
                selected_parts: selected.clone(),
                owner: "worker".to_string(),
                lease_expires_at_ms: 400,
                fencing_token: 1,
                updated_at_ms: 300,
            },
        ),
    );
    assert_eq!(
        reducer.apply(&event(
            &identity,
            5,
            FileMultipartTransitionV1::CompletionAcquired {
                fingerprint: "different".to_string(),
                selected_parts: selected,
                owner: "other".to_string(),
                lease_expires_at_ms: 500,
                fencing_token: 2,
                updated_at_ms: 401,
            },
        )),
        Err(FileMultipartReducerError::CompletionConflict)
    );
    let permit = DestinationCommitPermit {
        upload_id: identity.upload_id.clone(),
        completion_fingerprint: "fingerprint".to_string(),
        fencing_token: 1,
        operation_id: DestinationCommitPermit::deterministic_operation_id(&identity, "fingerprint"),
    };
    apply_ok(
        &mut reducer,
        event(
            &identity,
            5,
            FileMultipartTransitionV1::DestinationCommitBegun {
                permit: permit.clone(),
                publishing_started_at_ms: 320,
            },
        ),
    );
    let result = completion_result();
    apply_ok(
        &mut reducer,
        event(
            &identity,
            6,
            FileMultipartTransitionV1::DestinationCommitRecorded {
                permit: permit.clone(),
                record: DestinationCommitRecord {
                    operation_id: permit.operation_id,
                    result: result.clone(),
                    committed_at_ms: 330,
                },
                updated_at_ms: 330,
            },
        ),
    );
    let mut conflicting = result.clone();
    conflicting.checksum_sha256 = "different".to_string();
    assert_eq!(
        reducer.apply(&event(
            &identity,
            7,
            FileMultipartTransitionV1::DestinationCommitRecorded {
                permit: permit.clone(),
                record: DestinationCommitRecord {
                    operation_id: permit.operation_id,
                    result: conflicting.clone(),
                    committed_at_ms: 331,
                },
                updated_at_ms: 331,
            },
        )),
        Err(FileMultipartReducerError::CompletionConflict)
    );
    assert_eq!(
        reducer.apply(&event(
            &identity,
            7,
            FileMultipartTransitionV1::CompletionCompleted {
                permit,
                result: conflicting,
                completed_at_ms: 340,
                tombstone_until_ms: 340 + DAY_MS,
            },
        )),
        Err(FileMultipartReducerError::CompletionConflict)
    );
}

#[tokio::test]
async fn adapter_completion_lifecycle_survives_every_restart_boundary() {
    let directory = TempDir::new();
    let identity = adapter_identity("tenant", "complete/key");
    let repo = open_adapter(directory.path(), 2_000);
    assert!(repo.is_durable());
    repo.create(adapter_upload(identity.clone(), 1_000))
        .await
        .unwrap();
    let pending = repo.begin_part(&identity, 1, 400, 10).await.unwrap();
    let committed = part(&pending, 300);
    assert!(
        repo.commit_part(&identity, &pending, committed.clone())
            .await
            .unwrap()
            .is_empty()
    );
    drop(repo);

    let repo = open_adapter(directory.path(), 2_000);
    assert_eq!(
        repo.get_authorized(&identity).await.unwrap().staged_bytes,
        300
    );
    assert_eq!(repo.list_parts(&identity, 0, 10).await.unwrap().0.len(), 1);
    let selection = [selected(&committed)];
    let now = now_ms();
    let first_lease = match repo
        .acquire_completion(
            &identity,
            "fingerprint",
            &selection,
            "worker-a",
            i64::MAX / 4,
            now,
        )
        .await
        .unwrap()
    {
        CompletionAcquire::Acquired(lease) => lease,
        _ => panic!("expected completion lease"),
    };
    drop(repo);

    let repo = open_adapter(directory.path(), 2_000);
    repo.check_completion_lease(&identity, first_lease.fencing_token, now + 1)
        .await
        .unwrap();
    repo.renew_completion(&identity, first_lease.fencing_token, i64::MAX / 3)
        .await
        .unwrap();
    let operation_id =
        DestinationCommitPermit::deterministic_operation_id(&identity, "fingerprint");
    let first_permit = repo
        .begin_destination_commit(
            &identity,
            "fingerprint",
            first_lease.fencing_token,
            operation_id,
            now_ms(),
        )
        .await
        .unwrap();
    drop(repo);

    let repo = open_adapter(directory.path(), 2_000);
    repo.validate_destination_commit_permit(&first_permit)
        .await
        .unwrap();
    assert_eq!(
        repo.publishing_uploads(10).await.unwrap()[0].permit,
        first_permit
    );
    repo.release_destination_commit_after_proven_absence(&first_permit, now_ms())
        .await
        .unwrap();
    let second_lease = match repo
        .acquire_completion(
            &identity,
            "fingerprint",
            &selection,
            "worker-b",
            i64::MAX / 2,
            now_ms(),
        )
        .await
        .unwrap()
    {
        CompletionAcquire::Acquired(lease) => lease,
        _ => panic!("expected completion takeover"),
    };
    let permit = repo
        .begin_destination_commit(
            &identity,
            "fingerprint",
            second_lease.fencing_token,
            operation_id,
            now_ms(),
        )
        .await
        .unwrap();
    drop(repo);

    let repo = open_adapter(directory.path(), 2_000);
    let result = completion_result();
    repo.record_destination_commit(&permit, result.clone(), now_ms())
        .await
        .unwrap();
    drop(repo);

    let repo = open_adapter(directory.path(), 2_000);
    let publishing = repo.publishing_uploads(10).await.unwrap();
    assert_eq!(
        publishing[0].destination_commit.as_ref().unwrap().result,
        result
    );
    let completed_at = now_ms();
    repo.complete_completion(&identity, &permit, result.clone(), completed_at)
        .await
        .unwrap();
    drop(repo);

    let repo = open_adapter(directory.path(), 2_000);
    assert!(matches!(
        repo.acquire_completion(
            &identity,
            "fingerprint",
            &selection,
            "worker-c",
            i64::MAX / 2,
            now_ms(),
        )
            .await,
        Ok(CompletionAcquire::Replayed(ref replayed)) if replayed == &result
    ));
    repo.audit(CleanupAudit {
        id: Uuid::now_v7(),
        upload_id: identity.upload_id.clone(),
        kind: "completion-cleanup".to_string(),
        detail: json!({"artifact": committed.artifact_key}),
        created_at_ms: now_ms(),
    })
    .await
    .unwrap();
    repo.confirm_artifact_deleted(&committed.artifact_key)
        .await
        .unwrap();
    repo.clear_destination_commit_reference(&identity, operation_id)
        .await
        .unwrap();
    let retired = repo
        .retire_terminal_uploads(completed_at + DAY_MS, 10)
        .await
        .unwrap();
    assert_eq!(retired.len(), 1);
    assert_eq!(retired[0].upload_id, identity.upload_id);
    assert!(repo.known_artifact_keys().await.unwrap().is_empty());
    assert!(matches!(
        repo.get_authorized(&identity).await,
        Err(StagingError::NotFound)
    ));
    drop(repo);
    assert!(matches!(
        open_adapter(directory.path(), 2_000)
            .get_authorized(&identity)
            .await,
        Err(StagingError::NotFound)
    ));
}

#[tokio::test]
async fn adapter_abort_expiry_discard_replace_and_cleanup_lifecycle() {
    let directory = TempDir::new();
    let repo = open_adapter(directory.path(), 5_000);

    let aborted = adapter_identity("tenant", "abort");
    repo.create(adapter_upload(aborted.clone(), 1_000))
        .await
        .unwrap();
    let discarded = repo.begin_part(&aborted, 2, 100, 1).await.unwrap();
    repo.discard_pending(&aborted, &discarded).await.unwrap();
    let pending = repo.begin_part(&aborted, 1, 300, now_ms()).await.unwrap();
    let first = part(&pending, 250);
    repo.commit_part(&aborted, &pending, first.clone())
        .await
        .unwrap();
    let mut replacement = first.clone();
    replacement.attempt += 1;
    replacement.artifact_key.push_str("-replacement");
    replacement.etag.push_str("-replacement");
    assert_eq!(
        repo.replace_part(&aborted, replacement.clone())
            .await
            .unwrap()
            .unwrap()
            .artifact_key,
        first.artifact_key
    );
    let aborted_at = now_ms();
    let aborted_parts = repo.abort(&aborted, aborted_at).await.unwrap();
    assert_eq!(aborted_parts.len(), 1);
    assert_eq!(aborted_parts[0].artifact_key, replacement.artifact_key);
    assert_eq!(
        repo.cleanup_candidates(aborted_at + 1, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    repo.confirm_artifact_deleted(&replacement.artifact_key)
        .await
        .unwrap();
    repo.delete_terminal_upload(&aborted).await.unwrap();

    let expired = adapter_identity("tenant", "expired");
    let mut expiring_upload = adapter_upload(expired.clone(), 1_000);
    expiring_upload.expires_at_ms = 10_000;
    repo.create(expiring_upload).await.unwrap();
    assert_eq!(repo.reap_expired(9_999, 10).await.unwrap().len(), 0);
    assert!(repo.reap_expired(10_000, 10).await.unwrap().is_empty());
    repo.delete_terminal_upload(&expired).await.unwrap();
    assert!(
        repo.cleanup_candidates(i64::MAX, 10)
            .await
            .unwrap()
            .is_empty()
    );
    drop(repo);
    let repo = open_adapter(directory.path(), 5_000);
    assert!(matches!(
        repo.get_authorized(&aborted).await,
        Err(StagingError::NotFound)
    ));
    assert!(matches!(
        repo.get_authorized(&expired).await,
        Err(StagingError::NotFound)
    ));
}

#[tokio::test]
async fn adapter_reconstructs_quota_and_serializes_concurrent_reservations() {
    let directory = TempDir::new();
    let first = adapter_identity("tenant", "first");
    let second = adapter_identity("tenant", "second");
    let repo = open_adapter(directory.path(), 100);
    repo.create(adapter_upload(first.clone(), 100))
        .await
        .unwrap();
    repo.create(adapter_upload(second.clone(), 100))
        .await
        .unwrap();
    repo.begin_part(&first, 1, 60, 1).await.unwrap();
    drop(repo);

    assert!(matches!(
        FileMultipartRepository::open(directory.path().to_path_buf(), limits(50)),
        Err(StagingError::Persistence(_))
    ));
    let repo = Arc::new(open_adapter(directory.path(), 100));
    let left = {
        let repo = Arc::clone(&repo);
        let first = first.clone();
        tokio::spawn(async move { repo.begin_part(&first, 2, 40, 2).await })
    };
    let right = {
        let repo = Arc::clone(&repo);
        let second = second.clone();
        tokio::spawn(async move { repo.begin_part(&second, 1, 40, 2).await })
    };
    let outcomes = [left.await.unwrap(), right.await.unwrap()];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(StagingError::QuotaExceeded)))
            .count(),
        1
    );
    drop(repo);
    open_adapter(directory.path(), 100);
}

#[tokio::test]
async fn adapter_authorized_listing_is_paginated_and_persisted() {
    let directory = TempDir::new();
    let repo = open_adapter(directory.path(), 10_000);
    let mut identities = Vec::new();
    for (key, tenant) in [
        ("b", "tenant"),
        ("a", "tenant"),
        ("dir/x", "tenant"),
        ("a", "tenant"),
        ("secret", "other"),
    ] {
        let identity = adapter_identity(tenant, key);
        repo.create(adapter_upload(identity.clone(), 100))
            .await
            .unwrap();
        identities.push(identity);
    }
    drop(repo);

    let repo = open_adapter(directory.path(), 10_000);
    let request = ListMultipartUploadsRequest {
        tenant_id: "tenant".to_string(),
        credential_policy_id: "policy".to_string(),
        bucket: "bucket".to_string(),
        prefix: String::new(),
        delimiter: None,
        key_marker: None,
        upload_id_marker: None,
        max_uploads: 2,
    };
    let first = repo.list_authorized_uploads(&request).await.unwrap();
    assert_eq!(
        first
            .uploads
            .iter()
            .map(|upload| upload.identity.key.as_str())
            .collect::<Vec<_>>(),
        ["a", "a"]
    );
    assert!(first.is_truncated);
    let second = repo
        .list_authorized_uploads(&ListMultipartUploadsRequest {
            key_marker: first.next_key_marker,
            upload_id_marker: first.next_upload_id_marker,
            ..request.clone()
        })
        .await
        .unwrap();
    assert_eq!(
        second
            .uploads
            .iter()
            .map(|upload| upload.identity.key.as_str())
            .collect::<Vec<_>>(),
        ["b", "dir/x"]
    );
    let delimited = repo
        .list_authorized_uploads(&ListMultipartUploadsRequest {
            delimiter: Some("/".to_string()),
            max_uploads: 10,
            ..request.clone()
        })
        .await
        .unwrap();
    assert_eq!(delimited.common_prefixes, ["dir/"]);
    let unauthorized = repo
        .list_authorized_uploads(&ListMultipartUploadsRequest {
            tenant_id: "other-missing".to_string(),
            max_uploads: 10,
            ..request
        })
        .await
        .unwrap();
    assert!(unauthorized.uploads.is_empty());
    assert!(matches!(
        repo.get_authorized(&MultipartIdentity {
            tenant_id: "other".to_string(),
            ..identities[0].clone()
        })
        .await,
        Err(StagingError::NotFound)
    ));
}

#[tokio::test]
async fn adapter_zero_byte_final_part_survives_replay() {
    let directory = TempDir::new();
    let repo = open_adapter(directory.path(), 10_000);
    let identity = adapter_identity("tenant", "key");
    repo.create(adapter_upload(identity.clone(), 100))
        .await
        .unwrap();
    let started = now_ms();
    let pending = repo
        .begin_part(&identity, 1, 0, started)
        .await
        .expect("a zero-byte reservation is a valid final part");
    let zero = MultipartPart {
        upload_id: identity.upload_id.clone(),
        part_number: 1,
        attempt: pending.attempt,
        artifact_key: pending.artifact_key.clone(),
        etag: "\"empty\"".to_string(),
        checksum_sha256: "empty-sha".to_string(),
        size_bytes: 0,
        created_at_ms: started,
    };
    repo.commit_part(&identity, &pending, zero.clone())
        .await
        .unwrap();
    let acquired_at = now_ms();
    let lease = match repo
        .acquire_completion(
            &identity,
            "zero-final",
            &[selected(&zero)],
            "worker",
            acquired_at + 10_000,
            acquired_at,
        )
        .await
        .unwrap()
    {
        CompletionAcquire::Acquired(lease) => lease,
        _ => panic!("expected a completion lease for a zero-byte final part"),
    };
    assert_eq!(lease.selected_parts.len(), 1);
    assert_eq!(lease.selected_parts[0].size_bytes, 0);
    drop(repo);

    let reopened = open_adapter(directory.path(), 10_000);
    let (parts, truncated) = reopened.list_parts(&identity, 0, 10).await.unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].size_bytes, 0);
    assert_eq!(parts[0].etag, "\"empty\"");
    assert!(!truncated);
}

#[tokio::test]
async fn adapter_compacts_and_reopens_without_losing_completion_lease() {
    let directory = TempDir::new();
    let identity = adapter_identity("tenant", "compaction");
    let repo = open_adapter(directory.path(), 1_000);
    repo.create(adapter_upload(identity.clone(), 1_000))
        .await
        .unwrap();
    let pending = repo.begin_part(&identity, 1, 100, 1).await.unwrap();
    let committed = part(&pending, 90);
    repo.commit_part(&identity, &pending, committed.clone())
        .await
        .unwrap();
    let now = now_ms();
    let lease = match repo
        .acquire_completion(
            &identity,
            "compact",
            &[selected(&committed)],
            "worker",
            now + 10_000,
            now,
        )
        .await
        .unwrap()
    {
        CompletionAcquire::Acquired(lease) => lease,
        _ => panic!("expected completion lease"),
    };
    for offset in 10_001..10_260 {
        repo.renew_completion(&identity, lease.fencing_token, now + offset)
            .await
            .unwrap();
    }
    let upload_directory = directory.path().join("uploads").join(&identity.upload_id);
    assert!(upload_directory.join(SNAPSHOT_FILE).is_file());
    drop(repo);

    let repo = open_adapter(directory.path(), 1_000);
    repo.check_completion_lease(&identity, lease.fencing_token, now + 100)
        .await
        .unwrap();
    assert_eq!(repo.list_parts(&identity, 0, 10).await.unwrap().0.len(), 1);
}

#[tokio::test]
async fn adapter_reloads_after_mutation_unknown_and_recovers_committed_frame() {
    let directory = TempDir::new();
    let persistence = FilesystemPersistence::default();
    let repo = FileMultipartRepository::open_for_test(
        directory.path().to_path_buf(),
        limits(1_000),
        persistence.clone(),
    )
    .unwrap();
    let identity = adapter_identity("tenant", "unknown");
    repo.create(adapter_upload(identity.clone(), 1_000))
        .await
        .unwrap();
    persistence.fail_once(FaultPoint::AppendSync);
    assert!(matches!(
        repo.begin_part(&identity, 1, 100, 1).await,
        Err(StagingError::Persistence(_))
    ));
    let recovered = repo.get_authorized(&identity).await.unwrap();
    assert_eq!(recovered.reserved_bytes, 100);
    repo.begin_part(&identity, 2, 100, 2).await.unwrap();
}

#[tokio::test]
async fn adapter_rejects_corruption_symlinks_and_unknown_entries() {
    let unknown = TempDir::new();
    std::fs::create_dir(unknown.path().join("uploads")).unwrap();
    std::fs::write(unknown.path().join("uploads/unknown"), b"unknown").unwrap();
    assert!(matches!(
        FileMultipartRepository::open(unknown.path().to_path_buf(), limits(1_000)),
        Err(StagingError::Persistence(_))
    ));

    let corrupt = TempDir::new();
    let identity = adapter_identity("tenant", "corrupt");
    let repo = open_adapter(corrupt.path(), 1_000);
    repo.create(adapter_upload(identity.clone(), 1_000))
        .await
        .unwrap();
    drop(repo);
    std::fs::write(
        corrupt
            .path()
            .join("uploads")
            .join(identity.upload_id)
            .join(EVENT_LOG_FILE),
        b"not-an-event-log",
    )
    .unwrap();
    assert!(matches!(
        FileMultipartRepository::open(corrupt.path().to_path_buf(), limits(1_000)),
        Err(StagingError::Persistence(_))
    ));

    #[cfg(unix)]
    {
        let symlink = TempDir::new();
        std::fs::create_dir(symlink.path().join("uploads")).unwrap();
        std::os::unix::fs::symlink(
            symlink.path(),
            symlink
                .path()
                .join("uploads")
                .join(Uuid::now_v7().to_string()),
        )
        .unwrap();
        assert!(matches!(
            FileMultipartRepository::open(symlink.path().to_path_buf(), limits(1_000)),
            Err(StagingError::Persistence(_))
        ));
    }
}

proptest! {
    #[test]
    fn aggregate_quota_reconstruction_is_deterministic(sizes in prop::collection::vec(1u64..10_000, 1..64)) {
        let identity = identity("property", "tenant");
        let max = sizes.iter().copied().sum::<u64>();
        let mut reducer = FileMultipartReducer::empty();
        apply_ok(&mut reducer, create_event(&identity, max));
        for (index, size) in sizes.iter().copied().enumerate() {
            let number = u32::try_from(index + 1).unwrap();
            let pending = pending(&identity, number, 1, size);
            apply_ok(
                &mut reducer,
                event(
                    &identity,
                    u64::try_from(index + 2).unwrap(),
                    FileMultipartTransitionV1::PartReplaced {
                        part: part(&pending, size),
                        updated_at_ms: 200 + i64::try_from(index).unwrap(),
                    },
                ),
            );
        }
        let limits = StagingQuotaLimits::new(max, max).unwrap();
        let first = reconstruct_file_multipart_quotas([reducer.snapshot()], limits).unwrap();
        let serialized = serde_json::to_vec(reducer.snapshot()).unwrap();
        let restored: FileMultipartSnapshotV1 = serde_json::from_slice(&serialized).unwrap();
        let second = reconstruct_file_multipart_quotas([&restored], limits).unwrap();
        prop_assert_eq!(&first, &second);
        prop_assert_eq!(first.global.staged_bytes, max);
        prop_assert_eq!(first.global.reserved_bytes, 0);
    }
}
