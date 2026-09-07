-- Existing user-only credentials cannot be assigned safely without hosted
-- membership history. They remain NULL and authentication rejects them until
-- an operator replaces them with workspace-bound credentials.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS workspace_id TEXT;
ALTER TABLE mcp_tokens ADD COLUMN IF NOT EXISTS workspace_id TEXT;

-- Earlier hosted deployments added api_keys.workspace_id as UUID with a
-- workspaces foreign key. Preserve valid bindings in canonical UUID text while
-- removing the incompatible cross-schema relationship.
DO $$
DECLARE
    constraint_name TEXT;
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_attribute
        WHERE attrelid = 'api_keys'::regclass
          AND attname = 'workspace_id'
          AND atttypid = 'uuid'::regtype
          AND NOT attisdropped
    ) THEN
        FOR constraint_name IN
            SELECT conname
            FROM pg_constraint
            WHERE conrelid = 'api_keys'::regclass
              AND contype = 'f'
              AND conkey @> ARRAY[(
                  SELECT attnum
                  FROM pg_attribute
                  WHERE attrelid = 'api_keys'::regclass
                    AND attname = 'workspace_id'
              )]::SMALLINT[]
        LOOP
            EXECUTE format('ALTER TABLE api_keys DROP CONSTRAINT %I', constraint_name);
        END LOOP;
        ALTER TABLE api_keys
            ALTER COLUMN workspace_id TYPE TEXT USING workspace_id::text;
    END IF;
END
$$;

ALTER TABLE api_keys ADD CONSTRAINT api_keys_workspace_id_valid CHECK (
    workspace_id IS NULL OR (
        length(workspace_id) BETWEEN 1 AND 128
        AND workspace_id ~ '^[A-Za-z0-9._-]+$'
    )
);
ALTER TABLE mcp_tokens ADD CONSTRAINT mcp_tokens_workspace_id_valid CHECK (
    workspace_id IS NULL OR (
        length(workspace_id) BETWEEN 1 AND 128
        AND workspace_id ~ '^[A-Za-z0-9._-]+$'
    )
);

CREATE INDEX IF NOT EXISTS api_keys_workspace_id_idx ON api_keys (workspace_id)
    WHERE workspace_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS mcp_tokens_workspace_id_idx ON mcp_tokens (workspace_id)
    WHERE workspace_id IS NOT NULL;

CREATE OR REPLACE FUNCTION reject_credential_workspace_change()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.workspace_id IS DISTINCT FROM NEW.workspace_id THEN
        RAISE EXCEPTION 'credential workspace binding is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER api_keys_workspace_id_immutable
BEFORE UPDATE OF workspace_id ON api_keys
FOR EACH ROW EXECUTE FUNCTION reject_credential_workspace_change();

CREATE TRIGGER mcp_tokens_workspace_id_immutable
BEFORE UPDATE OF workspace_id ON mcp_tokens
FOR EACH ROW EXECUTE FUNCTION reject_credential_workspace_change();
