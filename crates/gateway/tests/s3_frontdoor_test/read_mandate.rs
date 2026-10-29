//! Mandatory read pipeline matrix: the resolved read pipeline governs every
//! read surface. A read the pipeline cannot fully serve is denied; stored
//! bytes are served only under an authored `explicit_passthrough` scope.

use super::*;

async fn protected_router() -> (Router, Arc<AppState>) {
    // The catalog chain is prefix-unsafe by default: protected reads run
    // through the encrypted spool.
    let state = spooled_test_state().await;
    (build_router(state.clone()), state)
}

#[tokio::test]
async fn protected_reads_deny_unservable_request_shapes() {
    let (app, state) = protected_router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    state.store.put(
        "mandate",
        "notes.txt",
        Bytes::from_static(b"contact a@b.com"),
        "text/plain",
    );
    state.store.put(
        "mandate",
        "page.html",
        Bytes::from_static(b"<html>contact a@b.com</html>"),
        "text/html",
    );

    // A partial read cannot cross the transform faithfully: denied.
    let ranged = add_headers(
        Request::builder()
            .method("GET")
            .uri("/mandate/notes.txt")
            .header(header::RANGE, "bytes=0-3")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let response = app.clone().oneshot(ranged).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // A format the pipeline cannot decode is denied — never raw passthrough.
    let html = add_headers(
        Request::builder()
            .method("GET")
            .uri("/mandate/page.html")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let response = app.clone().oneshot(html).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&body).contains("a@b.com"),
        "a denied read must not disclose the stored object"
    );
}

#[tokio::test]
async fn unassigned_read_scope_denies_head_without_metadata() {
    let mut state = test_state().await;
    {
        let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
        for plugin in state_mut.plugins.list() {
            state_mut.plugins.set_enabled(&plugin.id, false);
        }
    }
    let (ak, sk) = make_key(&state).await;
    let app = build_router(state.clone());
    state.store.put(
        "mandate",
        "notes.txt",
        Bytes::from_static(b"x"),
        "text/plain",
    );
    let head = add_headers(
        Request::builder()
            .method("HEAD")
            .uri("/mandate/notes.txt")
            .body(Body::empty())
            .unwrap(),
        &auth_headers(&ak, &sk),
    );
    let response = app.oneshot(head).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn presigned_backends_require_an_explicit_passthrough_scope() {
    // A presigned-HTTP backend cannot provide the stored-metadata preflight a
    // protected read needs, so the read is denied — never served raw. (The
    // sigv4 suite covers the served case under a passthrough scope.)
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut state = spooled_test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.presigned_http_policy = PresignedHttpPolicy::new(
        Vec::<String>::new(),
        ["127.0.0.1".to_string()],
        true,
        Duration::ZERO,
        Arc::new(TokioAddressResolver),
    )
    .unwrap();
    let (ak, sk) = make_key(&state).await;
    let app = build_router(state.clone());
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let signed_url = format!(
        "https://{address}/object?X-Amz-Credential=AKIA_TEST%2F20260828%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=DO_NOT_DISCLOSE&Expires={expires}"
    );
    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/mandate/presigned.txt")
            .header("x-maskura-backend-url", &signed_url)
            .body(Body::empty())
            .unwrap(),
        &auth_headers(&ak, &sk),
    );
    let response = app.oneshot(get).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&body).contains("DO_NOT_DISCLOSE"),
        "a denied read must not disclose signed URL material"
    );
}
