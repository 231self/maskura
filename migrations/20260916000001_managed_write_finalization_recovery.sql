-- Durable managed-write publication recipes and logical recovery claims.
alter table managed_logical_operations
    drop constraint managed_logical_operations_state_check,
    add column publication_recipe_version integer,
    add column admitted_placement_version bigint,
    add column recipe_primary_backend_id text,
    add column recipe_replica_backend_id text,
    add column authority_metadata jsonb,
    add column intended_primary_status text,
    add column intended_replica_status text,
    add column recovery_owner text,
    add column recovery_token uuid,
    add column recovery_expires_at_ms bigint,
    add constraint managed_logical_operations_state_check check (state in (
        'INTENT', 'OPEN', 'COMPLETING', 'COMMIT_UNKNOWN', 'RECOVERY_BLOCKED',
        'COMMITTED', 'PROVEN_ABORTED'
    )),
    add constraint managed_logical_operations_recipe_check check (
        (publication_recipe_version is null
            and admitted_placement_version is null
            and recipe_primary_backend_id is null
            and recipe_replica_backend_id is null
            and authority_metadata is null
            and intended_primary_status is null
            and intended_replica_status is null)
        or (publication_recipe_version is not null
            and publication_recipe_version = 1
            and admitted_placement_version is not null
            and admitted_placement_version > 0
            and recipe_primary_backend_id is not null
            and char_length(recipe_primary_backend_id) between 1 and 128
            and (recipe_replica_backend_id is null
                or char_length(recipe_replica_backend_id) between 1 and 128)
            and recipe_primary_backend_id = backend_id
            and authority_metadata is not null
            and jsonb_typeof(authority_metadata) = 'object'
            and intended_primary_status is not null
            and intended_primary_status = 'READY'
            and intended_replica_status is not null
            and ((recipe_replica_backend_id is null
                    and intended_replica_status = 'ABSENT')
                or (recipe_replica_backend_id is not null
                    and recipe_replica_backend_id <> recipe_primary_backend_id
                    and intended_replica_status = 'REPAIR_PENDING')))
    ),
    add constraint managed_logical_operations_recipe_kind_check check (
        operation_kind = 'PUT' or publication_recipe_version is null
    ),
    add constraint managed_logical_operations_recovery_claim_check check (
        (recovery_owner is null and recovery_token is null and recovery_expires_at_ms is null)
        or (recovery_owner is not null
            and char_length(recovery_owner) between 1 and 256
            and recovery_token is not null
            and recovery_expires_at_ms is not null
            and recovery_expires_at_ms > 0)
    ),
    add constraint managed_logical_operations_terminal_claim_check check (
        state not in ('COMMITTED', 'PROVEN_ABORTED')
        or recovery_owner is null
    ),
    add constraint managed_logical_operations_blocked_reason_check check (
        state <> 'RECOVERY_BLOCKED'
        or (last_error_class is not null
            and char_length(last_error_class) between 1 and 128)
    );

create index managed_logical_operations_recovery_claim_idx
    on managed_logical_operations (updated_at_ms, recovery_expires_at_ms)
    where state not in ('COMMITTED', 'PROVEN_ABORTED');

-- Publication facts are admitted once and must never follow mutable routing
-- configuration. Recovery claim fields deliberately remain mutable.
create or replace function s4_managed_logical_evidence_immutable()
returns trigger language plpgsql as $$
begin
    if (new.receipt_id, new.tenant_id, new.bucket, new.logical_key,
        new.operation_kind, new.generation, new.namespace_epoch,
        new.routing_epoch, new.expected_authority_cas,
        new.prior_logical_size, new.primary_child_operation_id,
        new.backend_id, new.provider_bucket, new.physical_key,
        new.occurred_at_ms, new.rate_version, new.usage_route,
        new.request_kind, new.max_processed_bytes, new.created_at_ms,
        new.publication_recipe_version, new.admitted_placement_version,
        new.recipe_primary_backend_id, new.recipe_replica_backend_id,
        new.authority_metadata, new.intended_primary_status,
        new.intended_replica_status)
       is distinct from
       (old.receipt_id, old.tenant_id, old.bucket, old.logical_key,
        old.operation_kind, old.generation, old.namespace_epoch,
        old.routing_epoch, old.expected_authority_cas,
        old.prior_logical_size, old.primary_child_operation_id,
        old.backend_id, old.provider_bucket, old.physical_key,
        old.occurred_at_ms, old.rate_version, old.usage_route,
        old.request_kind, old.max_processed_bytes, old.created_at_ms,
        old.publication_recipe_version, old.admitted_placement_version,
        old.recipe_primary_backend_id, old.recipe_replica_backend_id,
        old.authority_metadata, old.intended_primary_status,
        old.intended_replica_status) then
        raise exception 'managed logical operation identity is immutable';
    end if;
    return new;
end;
$$;
