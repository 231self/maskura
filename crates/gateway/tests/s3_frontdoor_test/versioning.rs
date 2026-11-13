use super::*;

#[tokio::test]
async fn exact_filestore_version_keeps_protected_read_processing_and_head_denial() {
    let root = owned_fixture_spool_dir();
    let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
    store.create_bucket("versions").await.unwrap();
    store
        .set_versioning(
            "versions",
            maskura_gateway::file_store::FileVersioning::Enabled,
        )
        .await
        .unwrap();
    store
        .put(
            "versions",
            "key",
            "historical alice@example.com\n",
            "text/plain",
        )
        .await
        .unwrap();
    let id = store.list_versions("versions").await.unwrap()[0]
        .version_id
        .clone();
    store
        .put("versions", "key", "latest bob@example.com\n", "text/plain")
        .await
        .unwrap();
    let mut state = spooled_test_state().await;
    Arc::get_mut(&mut state).unwrap().file_store = Some(store);
    let (ak, sk) = make_key(&state).await;
    let headers = auth_headers(&ak, &sk);
    let app = build_router(state);
    let path = format!("/versions/key?versionId={id}");
    let response = call(&app, &headers, "GET", &path, Body::empty()).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-amz-version-id"], id);
    let body = text(response).await;
    assert!(body.contains("historical"), "{body}");
    assert!(body.contains("[REDACTED_EMAIL]"), "{body}");
    assert!(
        !body.contains("alice@example.com") && !body.contains("latest"),
        "{body}"
    );
    let head = call(&app, &headers, "HEAD", &path, Body::empty()).await;
    assert!(!head.status().is_success());
    assert!(!head.headers().contains_key("x-amz-version-id"));
    let unauthenticated = app
        .oneshot(Request::builder().uri(&path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::FORBIDDEN);
    tokio::fs::remove_dir_all(root).await.unwrap();
}

async fn call(
    app: &Router,
    headers: &[(&'static str, String)],
    method: &str,
    path: &str,
    body: impl Into<Body>,
) -> axum::response::Response {
    let content_type = if path.contains("?versioning") || path.contains("?delete") {
        "application/xml"
    } else {
        "text/plain"
    };
    app.clone()
        .oneshot(add_headers(
            Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", content_type)
                .body(body.into())
                .unwrap(),
            headers,
        ))
        .await
        .unwrap()
}

async fn text(response: axum::response::Response) -> String {
    String::from_utf8(
        axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

async fn fixture(root: &std::path::Path) -> (Router, Arc<AppState>, Vec<(&'static str, String)>) {
    let mut state = explicit_passthrough_test_state(None).await;
    Arc::get_mut(&mut state).unwrap().file_store =
        Some(Arc::new(FileStore::new(root.to_owned()).await.unwrap()));
    let (ak, sk) = make_key(&state).await;
    let headers = auth_headers(&ak, &sk);
    (build_router(state.clone()), state, headers)
}

async fn enable(app: &Router, headers: &[(&'static str, String)], state: &str) {
    let response = call(app, headers, "PUT", "/versions?versioning", format!("<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>{state}</Status></VersioningConfiguration>")).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{}",
        text(response).await
    );
}

#[tokio::test]
async fn filestore_versioning_exact_get_head_and_settings_survive_gateway_restart() {
    let root = owned_fixture_spool_dir();
    let (app, state, headers) = fixture(&root).await;
    assert_eq!(
        call(&app, &headers, "PUT", "/versions", Body::empty())
            .await
            .status(),
        StatusCode::OK
    );
    let initial = call(&app, &headers, "GET", "/versions?versioning", Body::empty()).await;
    assert!(!text(initial).await.contains("<Status>"));
    enable(&app, &headers, "Enabled").await;
    let mut ids = Vec::new();
    for body in ["A", "B"] {
        let request = add_headers(
            Request::builder()
                .method("PUT")
                .uri("/versions/key")
                .header("content-type", "text/plain")
                .header("x-amz-meta-fixture", body)
                .body(Body::from(body))
                .unwrap(),
            &headers,
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        ids.push(
            response.headers()["x-amz-version-id"]
                .to_str()
                .unwrap()
                .to_owned(),
        );
    }
    assert_ne!(ids[0], ids[1]);
    let keys = state.keys.clone();
    drop(app);
    drop(state);
    let mut state = explicit_passthrough_test_state(None).await;
    let unique = Arc::get_mut(&mut state).unwrap();
    unique.keys = keys;
    unique.file_store = Some(Arc::new(FileStore::new(root.clone()).await.unwrap()));
    let app = build_router(state);
    assert!(
        text(call(&app, &headers, "GET", "/versions?versioning", Body::empty()).await)
            .await
            .contains("<Status>Enabled</Status>")
    );
    for (id, body) in ids.iter().zip(["A", "B"]) {
        let path = format!("/versions/key?versionId={id}");
        for method in ["GET", "HEAD"] {
            let response = call(&app, &headers, method, &path, Body::empty()).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["x-amz-version-id"], id.as_str());
            assert_eq!(response.headers()["x-amz-meta-fixture"], body);
            assert_eq!(response.headers()["content-type"], "text/plain");
            assert_eq!(response.headers()["content-length"], "1");
            assert_eq!(
                text(response).await,
                if method == "GET" { body } else { "" }
            );
        }
    }
    let missing = call(
        &app,
        &headers,
        "GET",
        &format!("/versions/key?versionId={}", uuid::Uuid::new_v4()),
        Body::empty(),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert!(text(missing).await.contains("<Code>NoSuchVersion</Code>"));
    let range = add_headers(
        Request::builder()
            .uri(format!("/versions/key?versionId={}", ids[0]))
            .header("range", "bytes=0-0")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    assert_eq!(text(app.oneshot(range).await.unwrap()).await, "A");
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn filestore_versioning_markers_suspension_and_same_key_batch_versions() {
    let root = owned_fixture_spool_dir();
    let (app, _state, headers) = fixture(&root).await;
    call(&app, &headers, "PUT", "/versions", Body::empty()).await;
    call(&app, &headers, "PUT", "/versions/key", "legacy").await;
    enable(&app, &headers, "Enabled").await;
    let a = call(&app, &headers, "PUT", "/versions/key", "A").await;
    assert_eq!(a.status(), StatusCode::OK);
    let id = a.headers()["x-amz-version-id"].to_str().unwrap().to_owned();
    let marker = call(&app, &headers, "DELETE", "/versions/key", Body::empty()).await;
    assert_eq!(marker.status(), StatusCode::NO_CONTENT);
    assert_eq!(marker.headers()["x-amz-delete-marker"], "true");
    let marker_id = marker.headers()["x-amz-version-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let hidden = call(&app, &headers, "GET", "/versions/key", Body::empty()).await;
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);
    assert_eq!(hidden.headers()["x-amz-delete-marker"], "true");
    let exact_marker = call(
        &app,
        &headers,
        "HEAD",
        &format!("/versions/key?versionId={marker_id}"),
        Body::empty(),
    )
    .await;
    assert_eq!(exact_marker.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(exact_marker.headers().contains_key("last-modified"));
    assert!(
        !text(call(&app, &headers, "GET", "/versions", Body::empty()).await)
            .await
            .contains("<Key>key</Key>")
    );
    assert_eq!(
        call(&app, &headers, "DELETE", "/versions", Body::empty())
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let batch = format!(
        "<Delete><Object><Key>key</Key><VersionId>{marker_id}</VersionId></Object><Object><Key>key</Key><VersionId>{id}</VersionId></Object></Delete>"
    );
    let response = call(&app, &headers, "POST", "/versions?delete", batch).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = text(response).await;
    assert_eq!(body.matches("<Deleted>").count(), 2);
    assert!(body.contains("<DeleteMarker>true</DeleteMarker>"));
    assert_eq!(
        text(
            call(
                &app,
                &headers,
                "GET",
                "/versions/key?versionId=null",
                Body::empty()
            )
            .await
        )
        .await,
        "legacy"
    );
    enable(&app, &headers, "Suspended").await;
    for value in ["nullA", "nullB"] {
        let response = call(&app, &headers, "PUT", "/versions/key", value).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-amz-version-id"], "null");
    }
    let listing =
        text(call(&app, &headers, "GET", "/versions?versions", Body::empty()).await).await;
    assert_eq!(listing.matches("<Version>").count(), 1);
    let deleted = call(&app, &headers, "DELETE", "/versions/key", Body::empty()).await;
    assert_eq!(deleted.headers()["x-amz-version-id"], "null");
    assert_eq!(
        call(
            &app,
            &headers,
            "DELETE",
            "/versions/key?versionId=null",
            Body::empty()
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&app, &headers, "DELETE", "/versions", Body::empty())
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn filestore_versioning_listing_pages_resume_inside_a_key() {
    let root = owned_fixture_spool_dir();
    let (app, _state, headers) = fixture(&root).await;
    call(&app, &headers, "PUT", "/versions", Body::empty()).await;
    enable(&app, &headers, "Enabled").await;
    let mut ids = Vec::new();
    for value in ["A", "B", "C"] {
        let response = call(&app, &headers, "PUT", "/versions/a", value).await;
        assert_eq!(response.status(), StatusCode::OK);
        ids.push(
            response.headers()["x-amz-version-id"]
                .to_str()
                .unwrap()
                .to_owned(),
        );
    }
    for (index, id) in ids.iter().rev().enumerate() {
        let path = if index == 0 {
            "/versions?versions&max-keys=1".into()
        } else {
            format!(
                "/versions?versions&max-keys=1&key-marker=a&version-id-marker={}",
                ids[ids.len() - index]
            )
        };
        let listing = text(call(&app, &headers, "GET", &path, Body::empty()).await).await;
        assert_eq!(listing.matches("<Version>").count(), 1);
        assert!(
            listing.contains(&format!("<VersionId>{id}</VersionId>")),
            "{listing}"
        );
        assert!(listing.contains(if index < 2 {
            "<IsTruncated>true</IsTruncated>"
        } else {
            "<IsTruncated>false</IsTruncated>"
        }));
    }
    let empty = text(
        call(
            &app,
            &headers,
            "GET",
            "/versions?versions&max-keys=0",
            Body::empty(),
        )
        .await,
    )
    .await;
    assert!(!empty.contains("<Version>"));
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn filestore_versioning_rejects_invalid_requests_and_nonlocal_backends_without_mutation() {
    let root = owned_fixture_spool_dir();
    let (app, state, headers) = fixture(&root).await;
    for method in ["GET", "PUT"] {
        let response = call(
            &app,
            &headers,
            method,
            "/missing?versioning",
            "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(text(response).await.contains("<Code>NoSuchBucket</Code>"));
        assert!(
            !state
                .file_store
                .as_ref()
                .unwrap()
                .bucket_exists("missing")
                .await
                .unwrap()
        );
    }
    call(&app, &headers, "PUT", "/versions", Body::empty()).await;
    for body in [
        "<VersioningConfiguration><Status>Enabled</Status><MfaDelete>Enabled</MfaDelete></VersioningConfiguration>",
        "<VersioningConfiguration><Status>Enabled</Status><Status>Suspended</Status></VersioningConfiguration>",
    ] {
        assert_eq!(
            call(&app, &headers, "PUT", "/versions?versioning", body)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert!(
        !text(call(&app, &headers, "GET", "/versions?versioning", Body::empty()).await)
            .await
            .contains("<Status>")
    );
    let polls = Arc::new(AtomicUsize::new(0));
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/versions?versioning")
                .body(Body::new(PollTrackingBody {
                    polls: polls.clone(),
                    data: Some(Bytes::from_static(b"private fixture")),
                }))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(!response.status().is_success());
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    for (method, path) in [
        ("PUT", "/versions/key?versionId=null"),
        ("DELETE", "/versions?versioning"),
        ("GET", "/versions/key?versionId=null&version%49d=null"),
        ("GET", "/versions?versions&version-id-marker=null"),
    ] {
        assert_eq!(
            call(&app, &headers, method, path, "never store")
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert!(
        state
            .file_store
            .as_ref()
            .unwrap()
            .list_objects("versions")
            .await
            .unwrap()
            .is_empty()
    );
    let (memory_app, memory_state) = explicit_passthrough_router().await;
    let (ak, sk) = make_key(&memory_state).await;
    let auth = auth_headers(&ak, &sk);
    for (method, path) in [
        ("GET", "/versions?versions"),
        ("PUT", "/versions?versioning"),
        ("GET", "/versions/key?versionId=null"),
        ("DELETE", "/versions/key?versionId=null"),
    ] {
        assert_eq!(
            call(&memory_app, &auth, method, path, Body::empty())
                .await
                .status(),
            StatusCode::NOT_IMPLEMENTED
        );
    }
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn filestore_versioning_unmodified_sdk_over_tcp_survives_restart() {
    use aws_sdk_s3::{
        config::{BehaviorVersion, Credentials, Region, retry::RetryConfig},
        types::{BucketVersioningStatus, VersioningConfiguration},
    };
    let root = owned_fixture_spool_dir();
    let mut state = explicit_passthrough_test_state(None).await;
    Arc::get_mut(&mut state).unwrap().file_store =
        Some(Arc::new(FileStore::new(root.clone()).await.unwrap()));
    let keys = state.keys.clone();
    let (access, secret) = make_key(&state).await;
    let mut versions = Vec::new();
    for restart in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let app = build_router(state.clone());
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        let client = aws_sdk_s3::Client::from_conf(
            aws_sdk_s3::config::Builder::new()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new("us-east-1"))
                .credentials_provider(Credentials::new(
                    &access,
                    &secret,
                    None,
                    None,
                    "synthetic-local",
                ))
                .endpoint_url(endpoint)
                .force_path_style(true)
                .retry_config(RetryConfig::standard().with_max_attempts(1))
                .build(),
        );
        if !restart {
            client
                .create_bucket()
                .bucket("versions")
                .send()
                .await
                .unwrap();
            client
                .put_bucket_versioning()
                .bucket("versions")
                .versioning_configuration(
                    VersioningConfiguration::builder()
                        .status(BucketVersioningStatus::Enabled)
                        .build(),
                )
                .send()
                .await
                .unwrap();
            for bytes in [b"A".as_slice(), b"B".as_slice()] {
                let result = client
                    .put_object()
                    .bucket("versions")
                    .key("key")
                    .content_type("text/plain")
                    .body(aws_sdk_s3::primitives::ByteStream::from_static(bytes))
                    .send()
                    .await
                    .unwrap();
                versions.push(result.version_id.unwrap());
            }
        }
        assert_eq!(
            client
                .get_bucket_versioning()
                .bucket("versions")
                .send()
                .await
                .unwrap()
                .status(),
            Some(&BucketVersioningStatus::Enabled)
        );
        for (id, bytes) in versions.iter().zip([b"A", b"B"]) {
            let get = client
                .get_object()
                .bucket("versions")
                .key("key")
                .version_id(id)
                .send()
                .await
                .unwrap();
            assert_eq!(get.version_id(), Some(id.as_str()));
            assert_eq!(
                get.body.collect().await.unwrap().into_bytes().as_ref(),
                bytes
            );
            let head = client
                .head_object()
                .bucket("versions")
                .key("key")
                .version_id(id)
                .send()
                .await
                .unwrap();
            assert_eq!(head.version_id(), Some(id.as_str()));
            assert_eq!(head.content_length(), Some(1));
        }
        let listing = client
            .list_object_versions()
            .bucket("versions")
            .max_keys(1)
            .send()
            .await
            .unwrap();
        assert_eq!(listing.versions().len(), 1);
        assert_eq!(listing.is_truncated(), Some(true));
        let next = client
            .list_object_versions()
            .bucket("versions")
            .max_keys(1)
            .key_marker(listing.next_key_marker().unwrap())
            .version_id_marker(listing.next_version_id_marker().unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(next.versions()[0].version_id(), Some(versions[0].as_str()));
        if restart {
            let marker = client
                .delete_object()
                .bucket("versions")
                .key("key")
                .send()
                .await
                .unwrap();
            assert_eq!(marker.delete_marker(), Some(true));
            let listed = client
                .list_object_versions()
                .bucket("versions")
                .send()
                .await
                .unwrap();
            assert_eq!(listed.delete_markers().len(), 1);
            client
                .delete_object()
                .bucket("versions")
                .key("key")
                .version_id(marker.version_id().unwrap())
                .send()
                .await
                .unwrap();
            assert!(
                client
                    .get_object()
                    .bucket("versions")
                    .key("key")
                    .send()
                    .await
                    .is_ok()
            );
        }
        drop(client);
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
        if !restart {
            drop(state);
            state = explicit_passthrough_test_state(None).await;
            let unique = Arc::get_mut(&mut state).unwrap();
            unique.keys = keys.clone();
            unique.file_store = Some(Arc::new(FileStore::new(root.clone()).await.unwrap()));
        }
    }
    drop(state);
    tokio::fs::remove_dir_all(root).await.unwrap();
}
