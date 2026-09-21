use super::*;

#[test]
fn engine_migration_helper_ignores_unknown_private_versions_but_rejects_checksum_mismatch() {
    with_pool(|pool| async move {
        let unknown_version = 99_999_999_999_999_i64;
        sqlx::query(
            "INSERT INTO _sqlx_migrations \
             (version, description, installed_on, success, checksum, execution_time) \
             VALUES ($1, $2, NOW(), TRUE, $3, 0)",
        )
        .bind(unknown_version)
        .bind("private integration migration")
        .bind(vec![0x5a_u8; 32])
        .execute(&pool)
        .await
        .unwrap();
        maskura_gateway::run_engine_migrations(&pool)
            .await
            .expect("unknown private migration must be ignored");
        sqlx::query("DELETE FROM _sqlx_migrations WHERE version = $1")
            .bind(unknown_version)
            .execute(&pool)
            .await
            .unwrap();

        let version = 20260809000001_i64;
        let checksum: Vec<u8> = sqlx::query_scalar(
            "SELECT checksum FROM _sqlx_migrations WHERE version = $1 AND success = TRUE",
        )
        .bind(version)
        .fetch_one(&pool)
        .await
        .unwrap();
        let mut mismatched = checksum.clone();
        mismatched[0] ^= 0xff;
        sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = $2")
            .bind(&mismatched)
            .bind(version)
            .execute(&pool)
            .await
            .unwrap();
        let mismatch = maskura_gateway::run_engine_migrations(&pool).await;
        sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = $2")
            .bind(&checksum)
            .bind(version)
            .execute(&pool)
            .await
            .unwrap();
        assert!(mismatch.is_err(), "public checksum mismatch must fail");
        maskura_gateway::run_engine_migrations(&pool)
            .await
            .expect("restored public checksum must migrate cleanly");
    });
}

#[test]
fn public_migrations_apply_fresh_after_private_shared_history() {
    with_pool(|pool| async move {
        let schema = format!("fresh_public_{}", uuid::Uuid::new_v4().simple());
        sqlx::raw_sql(&format!(
            "CREATE SCHEMA \"{schema}\"; \
             CREATE TABLE \"{schema}\"._sqlx_migrations (\
                version BIGINT PRIMARY KEY, description TEXT NOT NULL, \
                installed_on TIMESTAMPTZ NOT NULL DEFAULT NOW(), success BOOLEAN NOT NULL, \
                checksum BYTEA NOT NULL, execution_time BIGINT NOT NULL); \
             INSERT INTO \"{schema}\"._sqlx_migrations \
                (version, description, success, checksum, execution_time) \
             VALUES (20260907000001, 'private artifact inventory cycle', TRUE, '\\x01', 0)"
        ))
        .execute(&pool)
        .await
        .unwrap();

        let url = std::env::var("DATABASE_URL").unwrap();
        let setup_schema = schema.clone();
        let isolated = PgPoolOptions::new()
            .max_connections(1)
            .after_connect(move |connection, _| {
                let statement = format!("SET search_path TO \"{setup_schema}\"");
                Box::pin(async move {
                    sqlx::query(&statement).execute(&mut *connection).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        maskura_gateway::run_engine_migrations(&isolated)
            .await
            .expect("fresh public schema must migrate around private history");

        let workspace_type: String = sqlx::query_scalar(
            "SELECT data_type FROM information_schema.columns \
             WHERE table_schema = $1 AND table_name = 'api_keys' AND column_name = 'workspace_id'",
        )
        .bind(&schema)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(workspace_type, "text");
        let versions: Vec<i64> = sqlx::query_scalar(&format!(
            "SELECT version FROM \"{schema}\"._sqlx_migrations \
             WHERE version >= 20260907000001 ORDER BY version"
        ))
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            versions,
            [
                20260907000001,
                20260907000002,
                20260909000001,
                20260916000001,
                20260917000001,
            ]
        );
        isolated.close().await;
        sqlx::raw_sql(&format!("DROP SCHEMA \"{schema}\" CASCADE"))
            .execute(&pool)
            .await
            .unwrap();
    });
}

#[test]
fn workspace_credential_migration_upgrades_hosted_uuid_schema() {
    with_pool(|pool| async move {
        let schema = format!("hosted_upgrade_{}", uuid::Uuid::new_v4().simple());
        let api_keys = include_str!("../../../../migrations/20260809000001_api_keys.sql");
        let mcp_tokens = include_str!("../../../../migrations/20260816000001_mcp_tokens.sql");
        let migration =
            include_str!("../../../../migrations/20260907000002_workspace_bound_credentials.sql");
        let bound = uuid::Uuid::new_v4();
        let upgrade = format!(
            "CREATE SCHEMA \"{schema}\"; SET search_path TO \"{schema}\"; \
             {api_keys} {mcp_tokens} \
             CREATE TABLE workspaces (id UUID PRIMARY KEY); \
             ALTER TABLE api_keys ADD COLUMN workspace_id UUID \
                REFERENCES workspaces(id) ON DELETE SET NULL; \
             INSERT INTO workspaces (id) VALUES ('{bound}'); \
             INSERT INTO api_keys (key_id, secret_hash, user_id, label, created_at, workspace_id) \
                 VALUES ('maskura_bound', 'hash', 'user', 'bound', '1970-01-01T00:00:00Z', '{bound}'), \
                        ('maskura_unbound', 'hash2', 'user', 'unbound', '1970-01-01T00:00:00Z', NULL); \
             {migration}"
        );
        sqlx::raw_sql(&upgrade).execute(&pool).await.unwrap();

        let rows: Vec<(String, Option<String>)> = sqlx::query_as(&format!(
            "SELECT key_id, workspace_id FROM \"{schema}\".api_keys ORDER BY key_id"
        ))
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            rows,
            [
                ("maskura_bound".to_string(), Some(bound.to_string())),
                ("maskura_unbound".to_string(), None),
            ]
        );
        let foreign_keys: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_constraint c \
             JOIN pg_class t ON t.oid = c.conrelid \
             JOIN pg_namespace n ON n.oid = t.relnamespace \
             WHERE n.nspname = $1 AND t.relname = 'api_keys' AND c.contype = 'f'",
        )
        .bind(&schema)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(foreign_keys, 0);
        sqlx::raw_sql(&format!("DROP SCHEMA \"{schema}\" CASCADE"))
            .execute(&pool)
            .await
            .unwrap();
    });
}

#[test]
fn managed_store_migration_fails_closed_with_existing_authority_rows() {
    with_pool(|pool| async move {
        let schema = format!("managed_upgrade_{}", uuid::Uuid::new_v4().simple());
        let migration =
            include_str!("../../../../migrations/20260901000003_managed_store_operations.sql");
        let upgrade = format!(
            "CREATE SCHEMA \"{schema}\"; SET search_path TO \"{schema}\"; \
             CREATE TABLE managed_object_authorities (\
                tenant_id text NOT NULL, bucket text NOT NULL, logical_key text NOT NULL, \
                tombstone boolean NOT NULL); \
             CREATE TABLE managed_physical_write_intents (intent_id uuid); \
             CREATE TABLE managed_physical_object_versions (tenant_id text); \
             INSERT INTO managed_object_authorities VALUES \
                ('existing-tenant', 'bucket', 'key', false); {migration}"
        );
        let error = sqlx::raw_sql(&upgrade)
            .execute(&pool)
            .await
            .expect_err("existing managed rows must make the upgrade fail closed");
        assert!(
            error.to_string().contains(
                "cannot enable managed store operations with existing managed authority or physical ledger state"
            ),
            "unexpected migration error: {error}"
        );

        sqlx::raw_sql(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
            .execute(&pool)
            .await
            .unwrap();
    });
}
