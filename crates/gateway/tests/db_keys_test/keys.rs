use super::*;

#[test]
fn postgres_secret_envelope_roundtrip() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let cipher = Arc::new(SecretCipher::new(Arc::new(LocalKeyWrapping::with_kek(
            TEST_KEK,
        ))));
        let store = PostgresKeyStore::with_cipher(pool, cipher);
        let user = format!("unit-{}", uuid::Uuid::new_v4());
        let (secret, created) = store
            .create_key(
                &user,
                &WorkspaceId::new(user.clone()).unwrap(),
                "encrypted",
                0,
                None,
            )
            .await
            .expect("create encrypted Postgres API key");
        let key_id = created.key_id;

        let persisted = store
            .get_key(&key_id)
            .await
            .expect("read persisted key")
            .expect("persisted key");
        let envelope = persisted.secret_encrypted.expect("encrypted secret");
        assert!(envelope.starts_with("v2:"));
        assert!(!envelope.contains(&secret));
        assert_eq!(
            store.decrypt_secret(&key_id).await.unwrap().as_deref(),
            Some(secret.as_str())
        );
        delete_api_key(&db, &key_id).await;
    });
}

#[test]
fn postgres_v1_secret_is_rewrapped_to_identity_bound_v2() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let cipher = Arc::new(SecretCipher::new(Arc::new(LocalKeyWrapping::with_kek(
            TEST_KEK,
        ))));
        let store = PostgresKeyStore::with_cipher(pool, cipher.clone());
        let user = format!("unit-v1-{}", uuid::Uuid::new_v4());
        let (secret, created) = store
            .create_key(
                &user,
                &WorkspaceId::new(user.clone()).unwrap(),
                "legacy-rewrap",
                0,
                None,
            )
            .await
            .expect("create Postgres API key");
        let key_id = created.key_id;
        let legacy = v1_envelope(&secret);
        update_secret_state(&db, &key_id, None, &legacy).await;

        assert_eq!(
            store.decrypt_secret(&key_id).await.unwrap().as_deref(),
            Some(secret.as_str())
        );

        let persisted = fetch_api_key(&db, &key_id).await;
        let rewrapped = persisted.secret_encrypted.expect("rewrapped envelope");
        assert!(rewrapped.starts_with("v2:"));
        assert_ne!(rewrapped, legacy);
        assert_eq!(
            cipher.decrypt(&key_id, &rewrapped).as_deref(),
            Some(secret.as_str())
        );
        assert_eq!(cipher.decrypt("different-key-id", &rewrapped), None);
        delete_api_key(&db, &key_id).await;
    });
}

#[test]
fn postgres_v1_hash_mismatch_returns_none_without_rewrap() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let cipher = Arc::new(SecretCipher::new(Arc::new(LocalKeyWrapping::with_kek(
            TEST_KEK,
        ))));
        let store = PostgresKeyStore::with_cipher(pool, cipher);
        let user = format!("unit-v1-hash-{}", uuid::Uuid::new_v4());
        let (secret, created) = store
            .create_key(
                &user,
                &WorkspaceId::new(user.clone()).unwrap(),
                "legacy-hash-mismatch",
                0,
                None,
            )
            .await
            .expect("create Postgres API key");
        let key_id = created.key_id;
        let legacy = v1_envelope(&secret);
        let mismatched_hash = sha256_hash("different-secret");
        update_secret_state(&db, &key_id, Some(&mismatched_hash), &legacy).await;

        assert_eq!(store.decrypt_secret(&key_id).await.unwrap(), None);

        let persisted = fetch_api_key(&db, &key_id).await;
        assert_eq!(persisted.secret_hash, mismatched_hash);
        assert_eq!(persisted.secret_encrypted.as_deref(), Some(legacy.as_str()));
        delete_api_key(&db, &key_id).await;
    });
}

#[test]
fn postgres_v1_rewrap_cas_accepts_concurrent_matching_v2() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let initial_store = PostgresKeyStore::new(pool.clone());
        let user = format!("unit-v1-cas-{}", uuid::Uuid::new_v4());
        let (secret, created) = initial_store
            .create_key(
                &user,
                &WorkspaceId::new(user.clone()).unwrap(),
                "legacy-cas",
                0,
                None,
            )
            .await
            .expect("create hash-only Postgres API key");
        let key_id = created.key_id;
        let legacy = v1_envelope(&secret);
        update_secret_state(&db, &key_id, None, &legacy).await;

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let blocking_cipher = Arc::new(SecretCipher::new(Arc::new(BlockingWrapping {
            inner: LocalKeyWrapping::with_kek(TEST_KEK),
            entered: Mutex::new(Some(entered_tx)),
            release: Mutex::new(release_rx),
        })));
        let decrypt_store = PostgresKeyStore::with_cipher(pool, blocking_cipher);
        let decrypt_key_id = key_id.clone();
        // Run the racing database operation on this test's Tokio runtime. A
        // short-lived second runtime can strand SQLx pool connections when it
        // shuts down, starving the fixture cleanup below in CI.
        let runtime = tokio::runtime::Handle::current();
        let decrypt = tokio::task::spawn_blocking(move || {
            runtime.block_on(decrypt_store.decrypt_secret(&decrypt_key_id))
        });

        tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(5)))
            .await
            .expect("join rewrap signal waiter")
            .expect("legacy rewrap reached conditional update window");
        let winner_cipher = SecretCipher::new(Arc::new(LocalKeyWrapping::with_kek(TEST_KEK)));
        let winner = winner_cipher
            .encrypt(&key_id, &secret)
            .expect("create concurrent v2 winner");
        update_secret_state(&db, &key_id, None, &winner).await;
        release_tx.send(()).expect("release legacy rewrap");

        assert_eq!(
            decrypt
                .await
                .expect("join legacy decrypt")
                .unwrap()
                .as_deref(),
            Some(secret.as_str())
        );
        let persisted = fetch_api_key(&db, &key_id).await;
        assert_eq!(persisted.secret_encrypted.as_deref(), Some(winner.as_str()));
        delete_api_key(&db, &key_id).await;
    });
}

#[test]
fn postgres_key_roundtrip() {
    with_pool(|pool| async move {
        let store = PostgresKeyStore::new(pool);
        let user = format!("unit-{}", uuid::Uuid::new_v4());
        let (secret, created) = store
            .create_key(
                &user,
                &WorkspaceId::new(user.clone()).unwrap(),
                "roundtrip",
                0,
                None,
            )
            .await
            .expect("create Postgres API key");
        let key_id = created.key_id.clone();
        let persisted = store
            .get_key(&key_id)
            .await
            .expect("read persisted key")
            .expect("persisted key");
        assert_eq!(created, persisted);
        let (uid, pk) = store
            .resolve_credentials(&key_id, &secret)
            .await
            .unwrap()
            .expect("valid credentials resolve");
        assert_eq!(uid.user_id, user);
        assert_eq!(uid.workspace_id.as_str(), uid.user_id);
        assert!(pk.is_none());
        assert!(
            store
                .resolve_credentials(&key_id, "wrong-secret")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .resolve_credentials("missing-key", &secret)
                .await
                .unwrap()
                .is_none()
        );

        let keys = store.list_for_user(&user).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys[0].secret_hash.is_empty(), "list must strip the hash");
        assert_eq!(keys[0].label, "roundtrip");

        assert!(store.delete_key(&key_id, &user).await.unwrap());
        assert!(!store.delete_key(&key_id, &user).await.unwrap());
        assert!(store.get_key(&key_id).await.unwrap().is_none());
    });
}

#[test]
fn postgres_public_key_binding() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let store = PostgresKeyStore::new(pool);
        let user = format!("unit-{}", uuid::Uuid::new_v4());
        let (secret, created) = store
            .create_key(
                &user,
                &WorkspaceId::new(user.clone()).unwrap(),
                "enc",
                0,
                None,
            )
            .await
            .expect("create Postgres API key");
        let key_id = created.key_id;
        assert!(
            store
                .set_public_key(&key_id, &user, TEST_PUBLIC_KEY_PEM)
                .await
                .unwrap()
        );
        assert!(
            !store
                .set_public_key(&key_id, "someone-else", TEST_PUBLIC_KEY_2_PEM)
                .await
                .unwrap()
        );

        let (uid, pk) = store
            .resolve_credentials(&key_id, &secret)
            .await
            .unwrap()
            .expect("resolve after binding");
        assert_eq!(uid.user_id, user);
        assert_eq!(pk.as_deref(), Some(TEST_PUBLIC_KEY_PEM.trim()));
        delete_api_key(&db, &key_id).await;
    });
}

#[test]
fn postgres_expired_key_rejected() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let store = PostgresKeyStore::new(pool);
        let user = format!("unit-{}", uuid::Uuid::new_v4());
        let (secret, created) = store
            .create_key(
                &user,
                &WorkspaceId::new(user.clone()).unwrap(),
                "exp",
                1,
                None,
            )
            .await
            .expect("create Postgres API key");
        let key_id = created.key_id;
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        assert!(
            store
                .resolve_credentials(&key_id, &secret)
                .await
                .unwrap()
                .is_none(),
            "expired key must be rejected"
        );
        delete_api_key(&db, &key_id).await;
    });
}

#[test]
fn postgres_mcp_creation_returns_persisted_metadata() {
    with_pool(|pool| async move {
        let store = PostgresKeyStore::new(pool);
        let user = format!("unit-{}", uuid::Uuid::new_v4());
        let (token, created) = store
            .create_mcp_token(
                &user,
                &WorkspaceId::new(user.clone()).unwrap(),
                "  agent  ",
                3600,
            )
            .await
            .expect("create Postgres MCP token");
        let listed = store
            .list_mcp_tokens(&user)
            .await
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.token_hash == created.token_hash)
            .expect("persisted MCP token is listed");

        assert!(token.starts_with("maskura_mcp_"));
        assert_eq!(created, listed);
        let principal = store
            .resolve_mcp_token(&token)
            .await
            .unwrap()
            .expect("persisted MCP token resolves");
        let principal_id = principal.credential_id().to_string();
        assert_eq!(
            created.credential_id.as_deref(),
            Some(principal_id.as_str())
        );
        assert_eq!(
            principal.credential_policy_id(),
            format!("mcp:{}", principal.credential_id())
        );
        assert_eq!(created.label, "agent");
        assert!(created.expires_at.is_some());
        assert!(
            store
                .delete_mcp_token(&created.token_hash, &user)
                .await
                .unwrap()
        );
    });
}
