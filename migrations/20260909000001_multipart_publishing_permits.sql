-- Durable client-multipart publication fencing and explicit journal references.
-- All references are nullable so legacy rows remain valid without inferred IDs.
alter table multipart_uploads
    drop constraint if exists multipart_uploads_lifecycle_check;
alter table multipart_uploads
    add constraint multipart_uploads_lifecycle_check
    check (lifecycle in (
        'OPEN', 'COMPLETING', 'PUBLISHING', 'COMPLETED', 'ABORTED', 'EXPIRED'
    ));

alter table multipart_uploads
    add column if not exists destination_operation_id uuid,
    add column if not exists publishing_started_at_ms bigint,
    add column if not exists destination_commit jsonb;

create unique index if not exists multipart_uploads_destination_operation_idx
    on multipart_uploads (destination_operation_id)
    where destination_operation_id is not null;
create index if not exists multipart_uploads_publishing_recovery_idx
    on multipart_uploads (publishing_started_at_ms, upload_id)
    where lifecycle = 'PUBLISHING';
create index if not exists multipart_uploads_authorized_listing_idx
    on multipart_uploads (
        tenant_id, credential_policy_id, bucket, object_key, upload_id
    )
    where lifecycle in ('OPEN', 'COMPLETING', 'PUBLISHING');

alter table object_operations
    add column if not exists client_multipart_upload_id text;

create index if not exists object_operations_client_multipart_idx
    on object_operations (client_multipart_upload_id)
    where client_multipart_upload_id is not null;
