//! Real router and memory-transaction coverage for the native validation seam.
use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use bytes::Bytes;
use maskura_customer_config::Config;
use maskura_gateway::{
    control::NoopControlPlane,
    key_cipher::LocalKeyWrapping,
    server::{
        AppState, FinalOutputContext, FinalOutputValidationFactory, FinalOutputValidator,
        ValidationFailure, build_router, build_state, install_static_panic_reporter,
    },
    workspace_storage::InMemoryWorkspaceStorageRepository,
};
use tower::ServiceExt;

#[path = "support/isolated_process.rs"]
mod isolated_process;

macro_rules! isolated_router_test {
    ($name:ident) => {
        if let Some(outcome) = isolated_process::dispatch(stringify!($name), true) {
            outcome.assert_success();
            return;
        }
    };
}

type Observations = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

const SIGNED_FIXTURE_TOML: &str = r#"
schema_version = 1
signer_id = "fixture"
[write]
[[write.steps]]
plugin = "pii-default:0.1.0"
[read]
explicit_passthrough = true
"#;

#[derive(Clone, Copy)]
enum Failure {
    None,
    Begin,
    Observe,
    Finish,
    PanicBegin,
    PanicObserve,
    PanicFinish,
}

struct Factory {
    failure: Failure,
    completed: Observations,
}

struct Validator {
    failure: Failure,
    key: String,
    data: Vec<u8>,
    completed: Observations,
}

// Production state construction reads operator-owned environment variables
// even with Config::default(). As defense in depth, reject known operator
// variable names and require a temporary HOME before calling it. Only presence
// is checked; credential values are never dereferenced or reported. This finite
// denylist cannot prove the environment clean: dispatch clears the scenario
// child environment; the separate launcher isolates Cargo configuration.
#[cfg(unix)]
fn require_isolated_fixture_environment() {
    let forbidden = [
        c"DATABASE_URL",
        c"MASKURA_SERVICE_BUCKETS",
        c"MASKURA_GATEWAY_URL",
        c"MASKURA_ACCESS_KEY",
        c"MASKURA_SECRET_KEY",
        c"MASKURA_MCP_TOKEN",
        c"MASKURA_SECRET_KEK",
        c"MASKURA_BOOTSTRAP_KEY",
        c"MASKURA_BOOTSTRAP_SECRET",
        c"MASKURA_ROOT_USER",
        c"MASKURA_ROOT_PASSWORD",
        c"MASKURA_KEYS_FILE",
        c"MASKURA_SPOOL_DIR",
        c"MASKURA_LOCAL_STORAGE_DIR",
        c"MASKURA_STORAGE_MODE",
        c"MASKURA_MULTIPART_STAGING_ACCESS_KEY_ID",
        c"MASKURA_MULTIPART_STAGING_SECRET_ACCESS_KEY",
        c"SUPABASE_ANON_KEY",
        c"SUPABASE_JWT_SECRET",
        c"SUPABASE_URL",
        c"SUPABASE_SERVICE_ROLE_KEY",
        c"AUTH_DISABLED",
        c"S3_ENDPOINT",
        c"S3_ACCESS_KEY_ID",
        c"S3_SECRET_ACCESS_KEY",
        c"AWS_ACCESS_KEY_ID",
        c"AWS_SECRET_ACCESS_KEY",
        c"AWS_SESSION_TOKEN",
        c"AWS_PROFILE",
        c"AWS_REGION",
        c"AWS_DEFAULT_REGION",
        c"AWS_ENDPOINT_URL",
        c"AWS_ENDPOINT_URL_S3",
        c"AWS_CONFIG_FILE",
        c"AWS_SHARED_CREDENTIALS_FILE",
        c"AWS_ROLE_ARN",
        c"AWS_WEB_IDENTITY_TOKEN_FILE",
        c"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        c"AWS_CONTAINER_CREDENTIALS_FULL_URI",
        c"AWS_CONTAINER_AUTHORIZATION_TOKEN",
        c"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
        c"AWS_EC2_METADATA_SERVICE_ENDPOINT",
        c"AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
        c"HTTP_PROXY",
        c"HTTPS_PROXY",
        c"ALL_PROXY",
        c"http_proxy",
        c"https_proxy",
        c"all_proxy",
    ];
    for name in forbidden {
        // SAFETY: this test binary never mutates its process environment.
        // We only compare the returned pointer with null and never read it.
        let absent = unsafe { libc::getenv(name.as_ptr()).is_null() };
        assert!(
            absent,
            "run this test binary in a clean isolated environment"
        );
    }
    let tmp = std::env::var_os("TMPDIR").expect("an isolated TMPDIR is required");
    let home = std::env::var_os("HOME").expect("an isolated HOME is required");
    let tmp = std::fs::canonicalize(tmp).expect("isolated TMPDIR must exist");
    let home = std::fs::canonicalize(home).expect("isolated HOME must exist");
    use std::os::unix::fs::MetadataExt as _;
    // SAFETY: geteuid has no preconditions and does not inspect environment values.
    let uid = unsafe { libc::geteuid() };
    for path in [&tmp, &home] {
        let metadata = std::fs::metadata(path).expect("isolated directory metadata unavailable");
        assert!(
            metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o077 == 0,
            "isolated directories must be private and owned by the test user"
        );
    }
    assert!(
        std::env::var_os("PATH").as_deref() == Some(std::ffi::OsStr::new("/usr/bin:/bin")),
        "isolated child requires the minimal test PATH"
    );
    let named_test_home = home
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("maskura-final-validation-home-"));
    assert!(
        home != tmp && home.starts_with(&tmp) && named_test_home,
        "HOME must be a dedicated path inside the isolated TMPDIR"
    );
    if let Some(path) = std::env::var_os("MASKURA_TEST_VALIDATION_COMPONENT") {
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .expect("component override requires an explicit CARGO_TARGET_DIR");
        let target = std::path::PathBuf::from(target).join("test-components");
        let path = std::path::PathBuf::from(path);
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        assert!(
            path.parent() == Some(target.as_path())
                && name.starts_with("validation-test-transformer-")
                && name.ends_with(".component.wasm"),
            "component override must refer to the dedicated test fixture"
        );
    }
}

#[cfg(not(unix))]
fn require_isolated_fixture_environment() {
    panic!("an isolated test launcher is required on this platform");
}

#[async_trait::async_trait]
impl FinalOutputValidationFactory for Factory {
    async fn begin(
        &self,
        context: &FinalOutputContext,
    ) -> Result<Box<dyn FinalOutputValidator>, ValidationFailure> {
        assert!(
            !matches!(self.failure, Failure::PanicBegin),
            "synthetic callback panic"
        );
        assert_eq!(context.grant.bucket(), "bucket");
        assert_eq!(
            context.grant.pipeline_fingerprint(),
            Some(context.resolution.locator.fingerprint.as_str())
        );
        if matches!(self.failure, Failure::Begin) {
            return Err(ValidationFailure::Rejected);
        }
        Ok(Box::new(Validator {
            failure: self.failure,
            key: context.key.clone(),
            data: Vec::new(),
            completed: self.completed.clone(),
        }))
    }
}

#[async_trait::async_trait]
impl FinalOutputValidator for Validator {
    async fn observe(&mut self, bytes: &[u8]) -> Result<(), ValidationFailure> {
        assert!(
            !matches!(self.failure, Failure::PanicObserve),
            "synthetic callback panic"
        );
        if matches!(self.failure, Failure::Observe) {
            return Err(ValidationFailure::Rejected);
        }
        self.data.extend_from_slice(bytes);
        Ok(())
    }
    async fn finish(self: Box<Self>) -> Result<(), ValidationFailure> {
        assert!(
            !matches!(self.failure, Failure::PanicFinish),
            "synthetic callback panic"
        );
        if matches!(self.failure, Failure::Finish) {
            return Err(ValidationFailure::Rejected);
        }
        self.completed.lock().unwrap().push((self.key, self.data));
        Ok(())
    }
}

async fn base_state() -> Arc<AppState> {
    require_isolated_fixture_environment();
    let mut config = Config::default();
    // Build with authentication enabled so startup chooses the in-memory key
    // repository, never the operator's default local key-store file.
    config.auth.disabled = false;
    config.storage.single_tenant = true;
    config.features.dev_memory_streaming = true;
    config.spool.dir = Some(
        std::env::temp_dir()
            .join(format!("put-validation-spool-{}", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .into_owned(),
    );
    config.wasm.filter_component = Some(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/pii-default.component.wasm")
            .to_string_lossy()
            .into_owned(),
    );
    let mut base = build_state(
        Arc::new(NoopControlPlane),
        Arc::new(LocalKeyWrapping::ephemeral()),
        Arc::new(InMemoryWorkspaceStorageRepository::new()),
        &config,
    )
    .await
    .unwrap();
    Arc::get_mut(&mut base).unwrap().auth_disabled = true;
    base
}

async fn new_state(failure: Failure) -> (Arc<AppState>, Observations) {
    let base = base_state().await;
    let completed = Arc::new(Mutex::new(Vec::new()));
    let factory = Factory {
        failure,
        completed: completed.clone(),
    };
    let state =
        base.with_final_output_validation(install_static_panic_reporter(), Arc::new(factory));
    (Arc::new(state), completed)
}

#[tokio::test]
async fn absent_factory_retains_ordinary_put_and_headers_cannot_install_one() {
    isolated_router_test!(absent_factory_retains_ordinary_put_and_headers_cannot_install_one);
    let state = base_state().await;
    let request = Request::builder()
        .method("PUT")
        .uri("/bucket/baseline.txt")
        .header(header::CONTENT_TYPE, "text/plain")
        .header("x-maskura-validation-enable", "true")
        .body(Body::from("hello a@b.com"))
        .unwrap();
    let response = build_router(state.clone()).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        state.store.get("bucket", "baseline.txt").unwrap().data,
        Bytes::from_static(b"hello [REDACTED_EMAIL]")
    );
}

#[test]
fn router_fixture_discards_poisoned_parent_operator_environment() {
    // Only synthetic, owned paths are poisoned. Never supply real operator
    // credentials, a shared key store, or an external database/provider here.
    let temporary = std::env::temp_dir().join(format!(
        "maskura-poisoned-parent-regression-{}",
        uuid::Uuid::new_v4()
    ));
    let mut directory = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        directory.mode(0o700);
    }
    directory.create(&temporary).unwrap();
    let home = temporary.join("poisoned-home");
    let spool = temporary.join("poisoned-spool");
    std::fs::create_dir(&home).unwrap();
    std::fs::create_dir(&spool).unwrap();
    let keys = home.join("synthetic-keys.json");
    let marker = b"PUBLIC_SYNTHETIC_OPERATOR_STORE_TRAP";
    std::fs::write(&keys, marker).unwrap();
    let stale = spool.join("maskura-spool-public-trap.tmp");
    let file = std::fs::File::create_new(&stale).unwrap();
    file.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 60 * 60))
        .unwrap();
    drop(file);
    // Keep this compile-time reference paired with stringify!, so a renamed
    // scenario cannot silently turn --exact into a successful zero-test run.
    let _scenario_must_exist = absent_factory_retains_ordinary_put_and_headers_cannot_install_one;
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .env("HOME", &home)
        .env("TMPDIR", &temporary)
        .env("PATH", "/synthetic-unusable-path")
        .env("DATABASE_URL", "synthetic-invalid-database-url")
        .env("MASKURA_SERVICE_BUCKETS", "synthetic-invalid-provider")
        .env("MASKURA_KEYS_FILE", &keys)
        .env("MASKURA_SPOOL_DIR", &spool)
        .env("MASKURA_STORAGE_MODE", "synthetic-invalid-storage-mode")
        .env("AUTH_DISABLED", "true")
        .env("AWS_CONFIG_FILE", home.join("must-not-read"))
        .env("HTTPS_PROXY", "synthetic-invalid-proxy")
        .current_dir(&temporary)
        .arg("--exact")
        .arg(stringify!(
            absent_factory_retains_ordinary_put_and_headers_cannot_install_one
        ))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("synthetic poisoned-parent scenario could not start");
    assert!(
        status.success(),
        "router fixture inherited poisoned operator configuration"
    );
    assert_eq!(std::fs::read(keys).unwrap(), marker);
    assert!(
        stale.is_file(),
        "fixture cleaned its parent's synthetic spool"
    );
}

#[tokio::test]
async fn fixture_startup_preserves_owned_default_key_and_stale_spool_traps() {
    isolated_router_test!(fixture_startup_preserves_owned_default_key_and_stale_spool_traps);
    // These paths are defaults *inside this exact child's private HOME/TMPDIR*,
    // never the user's real default locations. Old startup ordering would prune
    // this aged recognized spool file before assigning the fixture's own spool.
    let keys = dirs::config_dir().unwrap().join("maskura/keys.json");
    std::fs::create_dir_all(keys.parent().unwrap()).unwrap();
    let marker = b"PUBLIC_SYNTHETIC_DEFAULT_STORE_TRAP";
    std::fs::write(&keys, marker).unwrap();
    let spool = std::env::temp_dir().join("maskura-spool");
    std::fs::create_dir(&spool).unwrap();
    let stale = spool.join("maskura-spool-public-default-trap.tmp");
    let file = std::fs::File::create_new(&stale).unwrap();
    file.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 60 * 60))
        .unwrap();
    drop(file);
    let state = base_state().await;
    let response = build_router(state)
        .oneshot(put(
            "fixture-default-trap.txt",
            Body::from("PUBLIC_SYNTHETIC_CONTENT"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(std::fs::read(keys).unwrap(), marker);
    assert!(
        stale.is_file(),
        "startup pruned a synthetic default spool before selecting its owned directory"
    );
    // Positive control: prove the trap is recognized and old enough for the
    // actual production cleaner. This removes only the file created above in
    // this child's owned scratch, after the startup-preservation assertions.
    let removed = maskura_gateway::transaction::CompatibilitySpoolTransaction::cleanup_stale(
        &maskura_gateway::transaction::CompatibilitySpoolConfig {
            directory: spool,
            max_object_bytes: 1024,
            stale_after: std::time::Duration::from_secs(24 * 60 * 60),
        },
    )
    .await
    .unwrap();
    assert_eq!(removed, 1, "synthetic default-spool trap was ineffective");
    assert!(!stale.exists());
}

fn put(key: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(format!("/bucket/{key}"))
        .header(header::CONTENT_TYPE, "text/plain")
        .header("x-maskura-validation-bypass", "true")
        .body(body)
        .unwrap()
}

#[tokio::test]
async fn final_observations_are_exactly_the_committed_transformed_bytes() {
    isolated_router_test!(final_observations_are_exactly_the_committed_transformed_bytes);
    let (state, completed) = new_state(Failure::None).await;
    let body = Body::new(Frames(std::collections::VecDeque::from([
        Bytes::from_static(b"contact a@"),
        Bytes::from_static(b"b.com\r\nsecond\n"),
    ])));
    let response = build_router(state.clone())
        .oneshot(put("object.txt", body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let object = state.store.get("bucket", "object.txt").unwrap();
    let finished = completed.lock().unwrap();
    assert_eq!(finished.len(), 1);
    assert_eq!(finished[0].1.as_slice(), object.data.as_ref());
    assert_eq!(
        object.data,
        Bytes::from_static(b"contact [REDACTED_EMAIL]\r\nsecond\n")
    );
}

struct Frames(std::collections::VecDeque<Bytes>);

impl http_body::Body for Frames {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        std::task::Poll::Ready(
            self.0
                .pop_front()
                .map(|chunk| Ok(http_body::Frame::data(chunk))),
        )
    }
}

#[tokio::test]
async fn validator_failures_never_publish_even_with_a_bypass_header() {
    isolated_router_test!(validator_failures_never_publish_even_with_a_bypass_header);
    for failure in [
        Failure::Begin,
        Failure::Observe,
        Failure::Finish,
        Failure::PanicBegin,
        Failure::PanicObserve,
        Failure::PanicFinish,
    ] {
        let (state, completed) = new_state(failure).await;
        let response = build_router(state.clone())
            .oneshot(put("failure.txt", Body::from("some text")))
            .await
            .unwrap();
        assert!(!response.status().is_success());
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        for sentinel in ["some text", "failure.txt", "synthetic callback panic"] {
            assert!(
                !body
                    .windows(sentinel.len())
                    .any(|window| window == sentinel.as_bytes())
            );
        }
        assert!(state.store.get("bucket", "failure.txt").is_none());
        assert!(completed.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn empty_output_still_requires_successful_finish() {
    isolated_router_test!(empty_output_still_requires_successful_finish);
    let (state, completed) = new_state(Failure::Finish).await;
    let response = build_router(state.clone())
        .oneshot(put("empty.txt", Body::empty()))
        .await
        .unwrap();
    assert!(!response.status().is_success());
    assert!(state.store.get("bucket", "empty.txt").is_none());
    assert!(completed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn source_limit_and_invalid_framing_never_publish() {
    isolated_router_test!(source_limit_and_invalid_framing_never_publish);
    let (mut state, completed) = new_state(Failure::None).await;
    Arc::get_mut(&mut state)
        .unwrap()
        .source_body_limits
        .max_bytes = 3;
    let response = build_router(state.clone())
        .oneshot(put("too-big.txt", Body::from("1234")))
        .await
        .unwrap();
    assert!(!response.status().is_success());
    assert!(state.store.get("bucket", "too-big.txt").is_none());
    assert!(completed.lock().unwrap().is_empty());

    let (state, completed) = new_state(Failure::None).await;
    let request = Request::builder()
        .method("PUT")
        .uri("/bucket/bad-json")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{bad"))
        .unwrap();
    let response = build_router(state.clone()).oneshot(request).await.unwrap();
    assert!(!response.status().is_success());
    assert!(state.store.get("bucket", "bad-json").is_none());
    assert!(completed.lock().unwrap().is_empty());
}

struct TrackingBody(Arc<std::sync::atomic::AtomicUsize>);

impl http_body::Body for TrackingBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::task::Poll::Ready(None)
    }
}

#[tokio::test]
async fn unsupported_binary_and_table_candidates_never_read_the_body() {
    isolated_router_test!(unsupported_binary_and_table_candidates_never_read_the_body);
    let (state, completed) = new_state(Failure::None).await;
    for (path, content_type) in [
        ("/bucket/blob", "application/octet-stream"),
        (
            "/bucket/table/metadata/v1.metadata.json",
            "application/json",
        ),
    ] {
        let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let request = Request::builder()
            .method("PUT")
            .uri(path)
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::new(TrackingBody(polls.clone())))
            .unwrap();
        let response = build_router(state.clone()).oneshot(request).await.unwrap();
        assert!(!response.status().is_success());
        assert_eq!(polls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
    assert!(completed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unsupported_filestore_validation_rejects_before_body() {
    isolated_router_test!(unsupported_filestore_validation_rejects_before_body);
    let (mut state, completed) = new_state(Failure::None).await;
    let root = std::env::temp_dir().join(format!("validation-file-{}", uuid::Uuid::new_v4()));
    let store = Arc::new(
        maskura_gateway::file_store::FileStore::new(root)
            .await
            .unwrap(),
    );
    store.create_bucket("bucket").await.unwrap();
    Arc::get_mut(&mut state).unwrap().file_store = Some(store.clone());
    let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let response = build_router(state)
        .oneshot(put("file.txt", Body::new(TrackingBody(polls.clone()))))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(polls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(store.head("bucket", "file.txt").await.unwrap().is_none());
    assert!(completed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn concurrent_requests_use_distinct_sessions() {
    isolated_router_test!(concurrent_requests_use_distinct_sessions);
    let (state, completed) = new_state(Failure::None).await;
    let router = build_router(state.clone());
    let (left, right) = tokio::join!(
        router
            .clone()
            .oneshot(put("left.txt", Body::from("left\n"))),
        router.oneshot(put("right.txt", Body::from("right\n"))),
    );
    assert_eq!(left.unwrap().status(), StatusCode::OK);
    assert_eq!(right.unwrap().status(), StatusCode::OK);
    let results = completed.lock().unwrap();
    assert_eq!(results.len(), 2);
    for (key, bytes) in results.iter() {
        assert_eq!(
            bytes.as_slice(),
            state.store.get("bucket", key).unwrap().data.as_ref()
        );
    }
}

struct IdentityFactory {
    captured: Arc<Mutex<Vec<(String, String)>>>,
    completed: Observations,
}

#[async_trait::async_trait]
impl FinalOutputValidationFactory for IdentityFactory {
    async fn begin(
        &self,
        context: &FinalOutputContext,
    ) -> Result<Box<dyn FinalOutputValidator>, ValidationFailure> {
        self.captured.lock().unwrap().push((
            context.authenticated.user_id.clone(),
            context.authenticated.workspace_id.as_str().to_string(),
        ));
        Ok(Box::new(Validator {
            failure: Failure::None,
            key: context.key.clone(),
            data: Vec::new(),
            completed: self.completed.clone(),
        }))
    }
}

#[tokio::test]
async fn factory_receives_actual_jwt_identity_and_workspace() {
    isolated_router_test!(factory_receives_actual_jwt_identity_and_workspace);
    let (mut state, completed) = new_state(Failure::None).await;
    let secret = b"synthetic-test-signing-key";
    let mutable = Arc::get_mut(&mut state).unwrap();
    mutable.auth_disabled = false;
    mutable.supabase_url = "https://example.test".to_string();
    mutable.jwt_decoder = Some(Arc::new(jsonwebtoken::DecodingKey::from_secret(secret)));
    let captured = Arc::new(Mutex::new(Vec::new()));
    let state = Arc::new(state.with_final_output_validation(
        install_static_panic_reporter(),
        Arc::new(IdentityFactory {
            captured: captured.clone(),
            completed,
        }),
    ));
    let token = jsonwebtoken::encode(&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256), &serde_json::json!({
        "sub":"real-test-user", "iss":"https://example.test/auth/v1", "aud":"authenticated", "exp":u64::MAX,
    }), &jsonwebtoken::EncodingKey::from_secret(secret)).unwrap();
    let request = Request::builder()
        .method("PUT")
        .uri("/bucket/identity.txt")
        .header(header::CONTENT_TYPE, "text/plain")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from("authenticated"))
        .unwrap();
    let response = build_router(state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        &*captured.lock().unwrap(),
        &[("real-test-user".to_string(), "real-test-user".to_string())]
    );
}

struct WaitingFactory(Arc<tokio::sync::Notify>);
struct WaitingValidator(Arc<tokio::sync::Notify>);
struct WaitingFinishFactory(Arc<tokio::sync::Notify>);
struct WaitingFinishValidator(Arc<tokio::sync::Notify>);

#[async_trait::async_trait]
impl FinalOutputValidationFactory for WaitingFactory {
    async fn begin(
        &self,
        _: &FinalOutputContext,
    ) -> Result<Box<dyn FinalOutputValidator>, ValidationFailure> {
        Ok(Box::new(WaitingValidator(self.0.clone())))
    }
}

#[async_trait::async_trait]
impl FinalOutputValidator for WaitingValidator {
    async fn observe(&mut self, _: &[u8]) -> Result<(), ValidationFailure> {
        self.0.notify_one();
        std::future::pending().await
    }
    async fn finish(self: Box<Self>) -> Result<(), ValidationFailure> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl FinalOutputValidationFactory for WaitingFinishFactory {
    async fn begin(
        &self,
        _: &FinalOutputContext,
    ) -> Result<Box<dyn FinalOutputValidator>, ValidationFailure> {
        Ok(Box::new(WaitingFinishValidator(self.0.clone())))
    }
}

#[async_trait::async_trait]
impl FinalOutputValidator for WaitingFinishValidator {
    async fn observe(&mut self, _: &[u8]) -> Result<(), ValidationFailure> {
        Ok(())
    }
    async fn finish(self: Box<Self>) -> Result<(), ValidationFailure> {
        self.0.notify_one();
        std::future::pending().await
    }
}

struct ReleaseControl(Arc<tokio::sync::Notify>);

#[async_trait::async_trait]
impl maskura_gateway::control::ControlPlane for ReleaseControl {
    async fn authorize(
        &self,
        _: &maskura_gateway::control::AuthenticatedRequestContext,
        request: &maskura_gateway::control::UsageAuthorization,
    ) -> Result<
        maskura_gateway::control::AuthorizationDecision,
        maskura_gateway::control::AuthorizationError,
    > {
        Ok(maskura_gateway::control::AuthorizationDecision::Granted(
            maskura_gateway::control::AuthorizationGrant::new(request, chrono::Utc::now(), 0),
        ))
    }
    async fn release(
        &self,
        _: &maskura_gateway::control::AuthenticatedRequestContext,
        _: uuid::Uuid,
    ) -> Result<(), maskura_gateway::control::AuthorizationError> {
        self.0.notify_one();
        Ok(())
    }
    async fn record(
        &self,
        _: &maskura_gateway::control::AuthenticatedRequestContext,
        _: &maskura_gateway::control::UsageEvent,
    ) -> Result<(), maskura_gateway::control::MeteringError> {
        panic!("unexpected successful settlement")
    }
}

#[tokio::test]
async fn dropping_request_cancels_owned_worker_and_releases_after_abort() {
    isolated_router_test!(dropping_request_cancels_owned_worker_and_releases_after_abort);
    let (mut state, _) = new_state(Failure::None).await;
    let released = Arc::new(tokio::sync::Notify::new());
    Arc::get_mut(&mut state).unwrap().control = Arc::new(ReleaseControl(released.clone()));
    let entered = Arc::new(tokio::sync::Notify::new());
    let state = Arc::new(state.with_final_output_validation(
        install_static_panic_reporter(),
        Arc::new(WaitingFactory(entered.clone())),
    ));
    let client =
        tokio::spawn(build_router(state.clone()).oneshot(put("cancel.txt", Body::from("content"))));
    tokio::time::timeout(std::time::Duration::from_secs(10), entered.notified())
        .await
        .unwrap();
    client.abort();
    tokio::time::timeout(std::time::Duration::from_secs(10), released.notified())
        .await
        .unwrap();
    assert!(state.store.get("bucket", "cancel.txt").is_none());
}

struct DropPanicFactory(Arc<std::sync::atomic::AtomicUsize>);
struct DropPanicValidator(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for DropPanicValidator {
    fn drop(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        panic!("synthetic-validator-drop-sentinel");
    }
}

#[async_trait::async_trait]
impl FinalOutputValidationFactory for DropPanicFactory {
    async fn begin(
        &self,
        _: &FinalOutputContext,
    ) -> Result<Box<dyn FinalOutputValidator>, ValidationFailure> {
        Ok(Box::new(DropPanicValidator(self.0.clone())))
    }
}

#[async_trait::async_trait]
impl FinalOutputValidator for DropPanicValidator {
    async fn observe(&mut self, _: &[u8]) -> Result<(), ValidationFailure> {
        Ok(())
    }
    async fn finish(self: Box<Self>) -> Result<(), ValidationFailure> {
        Ok(())
    }
}

#[tokio::test]
async fn unfinished_validator_drop_panic_does_not_skip_real_abort_or_release() {
    if let Some(outcome) = isolated_process::dispatch(
        "unfinished_validator_drop_panic_does_not_skip_real_abort_or_release",
        true,
    ) {
        outcome.assert_success();
        let sentinel = b"synthetic-validator-drop-sentinel";
        for stream in [&outcome.stdout.bytes, &outcome.stderr.bytes] {
            assert!(!stream.windows(sentinel.len()).any(|part| part == sentinel));
        }
        return;
    }
    let (mut state, _) = new_state(Failure::None).await;
    let released = Arc::new(tokio::sync::Notify::new());
    Arc::get_mut(&mut state).unwrap().control = Arc::new(ReleaseControl(released.clone()));
    let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let state = Arc::new(state.with_final_output_validation(
        install_static_panic_reporter(),
        Arc::new(DropPanicFactory(dropped.clone())),
    ));
    let request = Request::builder()
        .method("PUT")
        .uri("/bucket/drop-panic.json")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{bad"))
        .unwrap();
    let response = build_router(state.clone()).oneshot(request).await.unwrap();
    assert!(!response.status().is_success());
    tokio::time::timeout(std::time::Duration::from_secs(10), released.notified())
        .await
        .unwrap();
    assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(state.store.get("bucket", "drop-panic.json").is_none());
    let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
        .await
        .unwrap();
    let sentinel = b"synthetic-validator-drop-sentinel";
    assert!(!body.windows(sentinel.len()).any(|part| part == sentinel));
}

struct TrustedFactory {
    operation_id: uuid::Uuid,
    completed: Observations,
}

#[async_trait::async_trait]
impl FinalOutputValidationFactory for TrustedFactory {
    async fn begin(
        &self,
        context: &FinalOutputContext,
    ) -> Result<Box<dyn FinalOutputValidator>, ValidationFailure> {
        assert_eq!(context.authenticated.user_id, "mcp-test-user");
        assert_eq!(
            context.authenticated.workspace_id.as_str(),
            "mcp-test-workspace"
        );
        assert_eq!(context.grant.operation_id(), self.operation_id);
        Ok(Box::new(Validator {
            failure: Failure::None,
            key: context.key.clone(),
            data: Vec::new(),
            completed: self.completed.clone(),
        }))
    }
}

async fn genuine_mcp_context(
    state: &Arc<AppState>,
) -> maskura_gateway::server::TrustedInvocationContext {
    let workspace =
        maskura_gateway::workspace_storage::WorkspaceId::new("mcp-test-workspace").unwrap();
    let (token, _) = state
        .keys
        .create_mcp_token("mcp-test-user", &workspace, "validation-test", 0)
        .await
        .unwrap();
    let principal = state.keys.resolve_mcp_token(&token).await.unwrap().unwrap();
    maskura_gateway::server::TrustedInvocationContext::new(principal)
}

fn mcp_put_request(key: &str) -> maskura_gateway::mcp::ToolRequest {
    maskura_gateway::mcp::ToolRequest::PutObject(maskura_gateway::mcp::PutObjectRequest {
        bucket: "bucket".to_string(),
        key: key.to_string(),
        body: "mcp text".to_string(),
        content_type: "text/plain".to_string(),
    })
}

#[tokio::test]
async fn supervised_mcp_keeps_real_task_local_identity_and_operation() {
    isolated_router_test!(supervised_mcp_keeps_real_task_local_identity_and_operation);
    let (state, completed) = new_state(Failure::None).await;
    let context = genuine_mcp_context(&state).await;
    let operation_id = uuid::Uuid::now_v7();
    let state = Arc::new(state.with_final_output_validation(
        install_static_panic_reporter(),
        Arc::new(TrustedFactory {
            operation_id,
            completed: completed.clone(),
        }),
    ));
    let result = maskura_gateway::server::invoke_mcp(
        state.clone(),
        context,
        operation_id,
        mcp_put_request("mcp.txt"),
        maskura_gateway::server::InvocationLimits::default(),
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(matches!(
        result,
        maskura_gateway::mcp::ToolResult::PutObject(_)
    ));
    assert_eq!(
        completed.lock().unwrap()[0].1.as_slice(),
        state.store.get("bucket", "mcp.txt").unwrap().data.as_ref()
    );
}

#[tokio::test]
async fn supervised_mcp_cancellation_waits_for_owned_abort() {
    isolated_router_test!(supervised_mcp_cancellation_waits_for_owned_abort);
    let (mut state, _) = new_state(Failure::None).await;
    let context = genuine_mcp_context(&state).await;
    let released = Arc::new(tokio::sync::Notify::new());
    Arc::get_mut(&mut state).unwrap().control = Arc::new(ReleaseControl(released.clone()));
    let entered = Arc::new(tokio::sync::Notify::new());
    let state = Arc::new(state.with_final_output_validation(
        install_static_panic_reporter(),
        Arc::new(WaitingFactory(entered.clone())),
    ));
    let cancel = tokio_util::sync::CancellationToken::new();
    let request = tokio::spawn(maskura_gateway::server::invoke_mcp(
        state.clone(),
        context,
        uuid::Uuid::now_v7(),
        mcp_put_request("mcp-cancel.txt"),
        maskura_gateway::server::InvocationLimits::default(),
        cancel.clone(),
    ));
    tokio::time::timeout(std::time::Duration::from_secs(10), entered.notified())
        .await
        .unwrap();
    cancel.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(10), released.notified())
        .await
        .unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(10), request)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        result,
        Err(maskura_gateway::server::InvocationError::Cancelled)
    ));
    assert!(state.store.get("bucket", "mcp-cancel.txt").is_none());
}

struct FixedResolver(maskura_gateway::pipeline::PipelineResolution);

struct DeniedResolver;

#[async_trait::async_trait]
impl maskura_gateway::pipeline::PipelineResolver for DeniedResolver {
    async fn resolve(
        &self,
        _: &str,
        _: &str,
        _: maskura_gateway::pipeline::PipelineDirection,
    ) -> Result<maskura_gateway::pipeline::PipelineResolution, maskura_error::MaskuraError> {
        Err(maskura_error::MaskuraError::new(
            maskura_error::codes::UNSUPPORTED_TABLE_OPERATION,
            "synthetic-resolver-path-and-value",
        ))
    }
}

#[tokio::test]
async fn rejected_resolution_does_not_echo_dynamic_error_or_key() {
    isolated_router_test!(rejected_resolution_does_not_echo_dynamic_error_or_key);
    let (mut state, completed) = new_state(Failure::None).await;
    let mutable = Arc::get_mut(&mut state).unwrap();
    mutable.gateway = Arc::new(
        mutable
            .gateway
            .as_ref()
            .clone()
            .with_resolver(Arc::new(DeniedResolver), mutable.plugins.clone()),
    );
    let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let response = build_router(state)
        .oneshot(put(
            "resolution-private-path",
            Body::new(TrackingBody(polls.clone())),
        ))
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
        .await
        .unwrap();
    assert!(!status.is_success());
    for sentinel in [
        "synthetic-resolver-path-and-value",
        "resolution-private-path",
    ] {
        assert!(
            !body
                .windows(sentinel.len())
                .any(|window| window == sentinel.as_bytes())
        );
    }
    assert_eq!(polls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(completed.lock().unwrap().is_empty());
}

#[async_trait::async_trait]
impl maskura_gateway::pipeline::PipelineResolver for FixedResolver {
    async fn resolve(
        &self,
        _: &str,
        _: &str,
        direction: maskura_gateway::pipeline::PipelineDirection,
    ) -> Result<maskura_gateway::pipeline::PipelineResolution, maskura_error::MaskuraError> {
        let mut resolution = self.0.clone();
        resolution.locator.fingerprint = maskura_gateway::pipeline::resolution_fingerprint(
            direction,
            &resolution.steps,
            resolution.explicit_passthrough,
            resolution.limits,
        );
        Ok(resolution)
    }
}

async fn fixture_state(failure: Failure, action: Option<&str>) -> (Arc<AppState>, Observations) {
    use maskura_gateway::pipeline::PipelineResolver as _;
    let (mut state, completed) = new_state(failure).await;
    for plugin in state.plugins.list() {
        state.plugins.set_enabled(&plugin.id, false);
    }
    let fixture = std::env::var_os("MASKURA_TEST_VALIDATION_COMPONENT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/test-components/test-transformer.component.wasm")
        });
    let component = std::fs::read(fixture).expect("build the test transformer fixture");
    state
        .plugins
        .import("validation-fixture", &component)
        .unwrap();
    let mut resolution =
        maskura_gateway::pipeline::StaticPipelineResolver::new(state.plugins.clone())
            .resolve(
                "fixture",
                "bucket",
                maskura_gateway::pipeline::PipelineDirection::Write,
            )
            .await
            .unwrap();
    let step = resolution
        .steps
        .iter_mut()
        .find(|step| step.enabled)
        .unwrap();
    step.config_json = action.map(|value| format!("\"{value}\""));
    let state_mut = Arc::get_mut(&mut state).unwrap();
    state_mut.gateway = Arc::new(state_mut.gateway.as_ref().clone().with_resolver(
        Arc::new(FixedResolver(resolution)),
        state_mut.plugins.clone(),
    ));
    (state, completed)
}

#[tokio::test]
async fn finish_emitted_bytes_reach_observer_and_real_memory_sink() {
    isolated_router_test!(finish_emitted_bytes_reach_observer_and_real_memory_sink);
    let (state, completed) = fixture_state(Failure::None, Some("emit-tail")).await;
    let response = build_router(state.clone())
        .oneshot(put("finish.txt", Body::from("first\n")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let object = state.store.get("bucket", "finish.txt").unwrap();
    assert_eq!(object.data, Bytes::from_static(b"first\ntail\n"));
    assert_eq!(
        completed.lock().unwrap()[0].1.as_slice(),
        object.data.as_ref()
    );
}

#[tokio::test]
async fn malformed_finish_output_fails_existing_framing_before_host_finish() {
    isolated_router_test!(malformed_finish_output_fails_existing_framing_before_host_finish);
    let (state, completed) = fixture_state(Failure::None, Some("emit-tail")).await;
    let request = Request::builder()
        .method("PUT")
        .uri("/bucket/invalid-finish.json")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"x":1}"#))
        .unwrap();
    let response = build_router(state.clone()).oneshot(request).await.unwrap();
    assert!(!response.status().is_success());
    assert!(state.store.get("bucket", "invalid-finish.json").is_none());
    assert!(completed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn transform_finish_and_dropped_records_still_fail_closed() {
    isolated_router_test!(transform_finish_and_dropped_records_still_fail_closed);
    for (action, input) in [(None, "reject"), (Some("finish-trap"), "first")] {
        let (state, completed) = fixture_state(Failure::None, action).await;
        let response = build_router(state.clone())
            .oneshot(put("plugin-failure.txt", Body::from(input)))
            .await
            .unwrap();
        assert!(!response.status().is_success());
        assert!(state.store.get("bucket", "plugin-failure.txt").is_none());
        assert!(completed.lock().unwrap().is_empty());
    }
    let (state, completed) = fixture_state(Failure::None, None).await;
    let response = build_router(state.clone())
        .oneshot(put("dropped.txt", Body::from("drop")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        state
            .store
            .get("bucket", "dropped.txt")
            .unwrap()
            .data
            .is_empty()
    );
    assert_eq!(
        completed.lock().unwrap().as_slice(),
        &[("dropped.txt".to_string(), Vec::new())]
    );

    let (state, _) = fixture_state(Failure::Finish, None).await;
    let response = build_router(state.clone())
        .oneshot(put("drop-rejected.txt", Body::from("drop")))
        .await
        .unwrap();
    assert!(!response.status().is_success());
    assert!(state.store.get("bucket", "drop-rejected.txt").is_none());
}

struct BoundGate {
    deadline_ms: u64,
    observed: Arc<Mutex<Option<maskura_gateway::pipeline::PipelineResolution>>>,
}

struct DeniedGate;

#[async_trait::async_trait]
impl maskura_gateway::policy_gate::PolicyGate for DeniedGate {
    async fn enforce(
        &self,
        _: &maskura_gateway::policy_gate::PolicyRequest<'_>,
    ) -> Result<maskura_gateway::policy_gate::VerifiedPolicy, maskura_error::MaskuraError> {
        Err(maskura_error::MaskuraError::new(
            maskura_error::codes::POLICY_DENIED,
            "synthetic-record-path-and-value",
        ))
    }
}

#[tokio::test]
async fn denied_policy_keeps_code_without_leaking_dynamic_detail_or_object_key() {
    isolated_router_test!(denied_policy_keeps_code_without_leaking_dynamic_detail_or_object_key);
    let (mut state, completed) = new_state(Failure::None).await;
    Arc::get_mut(&mut state).unwrap().policy_gate = Some(Arc::new(DeniedGate));
    let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let response = build_router(state)
        .oneshot(put(
            "policy-private-path",
            Body::new(TrackingBody(polls.clone())),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
        .await
        .unwrap();
    assert!(
        body.windows(b"policy.denied".len())
            .any(|window| window == b"policy.denied")
    );
    for sentinel in ["synthetic-record-path-and-value", "policy-private-path"] {
        assert!(
            !body
                .windows(sentinel.len())
                .any(|window| window == sentinel.as_bytes())
        );
    }
    assert_eq!(polls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(completed.lock().unwrap().is_empty());
}

#[async_trait::async_trait]
impl maskura_gateway::policy_gate::PolicyGate for BoundGate {
    async fn enforce(
        &self,
        request: &maskura_gateway::policy_gate::PolicyRequest<'_>,
    ) -> Result<maskura_gateway::policy_gate::VerifiedPolicy, maskura_error::MaskuraError> {
        *self.observed.lock().unwrap() = request.resolution.cloned();
        Ok(maskura_gateway::policy_gate::VerifiedPolicy {
            schema_version: maskura_gateway::policy_gate::VERIFIED_POLICY_SCHEMA_VERSION,
            binding: Some(maskura_gateway::policy_gate::PolicyBinding {
                workspace_id: request.workspace_id.to_string(),
                operation: request.operation,
                route_prefix: String::new(),
                envelope_digest: "e".repeat(64),
                envelope_version: 1,
                effective_state_digest: "d".repeat(64),
                receipt_seq: 1,
                receipt_body_digest: "b".repeat(64),
                authorization_epoch: 1,
                destination: request.snapshot.binding.clone(),
                managed_placement: request.snapshot.managed_placement(),
                limits: maskura_pipeline_config::PolicyLimits {
                    record_max_bytes: 1024,
                    object_max_bytes: 4096,
                    memory_bytes: 67_108_864,
                    fuel: 10_000_000,
                    deadline_ms: self.deadline_ms,
                },
            }),
        })
    }
}

struct BoundFactory {
    observed: Arc<Mutex<Option<maskura_gateway::pipeline::PipelineResolution>>>,
    completed: Observations,
    expected_revision: Option<String>,
}

#[async_trait::async_trait]
impl FinalOutputValidationFactory for BoundFactory {
    async fn begin(
        &self,
        context: &FinalOutputContext,
    ) -> Result<Box<dyn FinalOutputValidator>, ValidationFailure> {
        assert_eq!(
            self.observed.lock().unwrap().as_ref(),
            Some(&context.resolution)
        );
        let binding = context.policy.binding.as_ref().unwrap();
        assert_eq!(binding.destination, context.destination.binding);
        assert_eq!(binding.receipt_body_digest, "b".repeat(64));
        assert_eq!(
            context.grant.pipeline_fingerprint(),
            Some(context.resolution.locator.fingerprint.as_str())
        );
        if let Some(revision) = &self.expected_revision {
            assert_eq!(&context.resolution.locator.revision, revision);
            assert_eq!(context.grant.pipeline_revision(), Some(revision.as_str()));
        }
        Ok(Box::new(Validator {
            failure: Failure::None,
            key: context.key.clone(),
            data: Vec::new(),
            completed: self.completed.clone(),
        }))
    }
}

#[tokio::test]
async fn policy_bound_resolution_and_receipt_evidence_reach_factory_unchanged() {
    isolated_router_test!(policy_bound_resolution_and_receipt_evidence_reach_factory_unchanged);
    let (mut state, completed) = new_state(Failure::None).await;
    let observed = Arc::new(Mutex::new(None));
    Arc::get_mut(&mut state).unwrap().policy_gate = Some(Arc::new(BoundGate {
        deadline_ms: 30_000,
        observed: observed.clone(),
    }));
    let state = Arc::new(state.with_final_output_validation(
        install_static_panic_reporter(),
        Arc::new(BoundFactory {
            observed,
            completed: completed.clone(),
            expected_revision: None,
        }),
    ));
    let response = build_router(state.clone())
        .oneshot(put("bound.txt", Body::from("bound")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        completed.lock().unwrap()[0].1.as_slice(),
        state
            .store
            .get("bucket", "bound.txt")
            .unwrap()
            .data
            .as_ref()
    );
}

#[tokio::test]
async fn signed_resolution_and_bound_policy_are_not_changed_by_validation() {
    isolated_router_test!(signed_resolution_and_bound_policy_are_not_changed_by_validation);
    let mut file =
        maskura_pipeline_config::PipelineFile::from_toml_str(SIGNED_FIXTURE_TOML).unwrap();
    // Synthetic, deterministic Ed25519 test vector, not an operational key.
    file.signature = Some(
        "syQxqiE/VbUNj7XK24IxCTCam6il8DHCjdcCGcUXUWhWpslmllmD8PaPlYDZw79clgqudeigGE0B3IM33fPfCQ=="
            .to_string(),
    );
    let roots = maskura_pipeline_config::parse_trust_roots(
        "fixture=ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
    )
    .unwrap();
    file.verify(&roots).unwrap();
    let revision = file.revision().unwrap();
    let (mut state, completed) = new_state(Failure::None).await;
    let resolver =
        maskura_gateway::pipeline_config::SignedTomlPipelineResolver::from_registry_with_revision(
            file,
            &state.plugins,
            revision.clone(),
        )
        .unwrap();
    let observed = Arc::new(Mutex::new(None));
    let mutable = Arc::get_mut(&mut state).unwrap();
    mutable.gateway = Arc::new(
        mutable
            .gateway
            .as_ref()
            .clone()
            .with_resolver(Arc::new(resolver), mutable.plugins.clone()),
    );
    mutable.policy_gate = Some(Arc::new(BoundGate {
        deadline_ms: 30_000,
        observed: observed.clone(),
    }));
    let state = Arc::new(state.with_final_output_validation(
        install_static_panic_reporter(),
        Arc::new(BoundFactory {
            observed,
            completed: completed.clone(),
            expected_revision: Some(revision),
        }),
    ));
    let response = build_router(state.clone())
        .oneshot(put("signed.txt", Body::from("signed")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        completed.lock().unwrap()[0].1.as_slice(),
        state
            .store
            .get("bucket", "signed.txt")
            .unwrap()
            .data
            .as_ref()
    );
}

#[tokio::test]
async fn bound_original_deadline_cancels_pending_final_validation() {
    isolated_router_test!(bound_original_deadline_cancels_pending_final_validation);
    let (mut state, _) = new_state(Failure::None).await;
    Arc::get_mut(&mut state).unwrap().policy_gate = Some(Arc::new(BoundGate {
        deadline_ms: 1_000,
        observed: Arc::new(Mutex::new(None)),
    }));
    let entered = Arc::new(tokio::sync::Notify::new());
    let state = Arc::new(state.with_final_output_validation(
        install_static_panic_reporter(),
        Arc::new(WaitingFinishFactory(entered.clone())),
    ));
    let request =
        tokio::spawn(build_router(state.clone()).oneshot(put("deadline.txt", Body::from("body"))));
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), request)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!response.status().is_success());
    assert!(state.store.get("bucket", "deadline.txt").is_none());
}
