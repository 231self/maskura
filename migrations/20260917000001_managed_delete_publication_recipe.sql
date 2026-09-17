-- Atomic managed deletes persist the placement and tombstone statuses used by
-- their terminal logical operation. PUT recipes retain their stricter rules.
alter table managed_logical_operations
    drop constraint managed_logical_operations_recipe_check,
    drop constraint managed_logical_operations_recipe_kind_check,
    add constraint managed_logical_operations_recipe_check check (
        (publication_recipe_version is null
            and admitted_placement_version is null
            and recipe_primary_backend_id is null
            and recipe_replica_backend_id is null
            and authority_metadata is null
            and intended_primary_status is null
            and intended_replica_status is null)
        or (publication_recipe_version = 1
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
            and intended_replica_status is not null
            and ((operation_kind = 'PUT'
                    and intended_primary_status = 'READY'
                    and ((recipe_replica_backend_id is null
                            and intended_replica_status = 'ABSENT')
                        or (recipe_replica_backend_id is not null
                            and recipe_replica_backend_id <> recipe_primary_backend_id
                            and intended_replica_status = 'REPAIR_PENDING')))
                or (operation_kind = 'DELETE'
                    and intended_primary_status = 'ABSENT'
                    and intended_replica_status = 'ABSENT')))),
    add constraint managed_logical_operations_recipe_kind_check check (
        publication_recipe_version is null
        or operation_kind in ('PUT', 'DELETE')
    );
