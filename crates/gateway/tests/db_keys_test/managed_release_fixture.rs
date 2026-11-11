//! Strict, deliberately finite TEST provider. Not an AWS/B2 emulator or provider
//! qualification. No production client injection or certificate bypass exists.
use super::*;
use axum::http::HeaderMap;
use maskura_gateway::managed::ManagedStreamingMode;
use maskura_gateway::service_storage::{ServiceBackend, ServiceStorage, parse_service_backends};
use maskura_gateway::transaction::{
    BackendCapabilities, CompletionReconciliation, ConditionalReadCapability,
    IncompleteUploadDiscovery, ListCapability, MultipartResponseCapability,
    ResponseChecksumCapability, VersioningCapability,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::future::IntoFuture;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Instant;

pub const PRIMARY: &str = "release-primary";
pub const SECONDARY: &str = "release-secondary";
pub const STAGING: &str = "release-staging";
pub const TENANT: &str = "release-workspace";
pub const CONTENT_TYPE: &str = "text/plain; charset=utf-8";
const BODY_LIMIT: usize = 32 * 1024 * 1024;

pub fn must<T, E>(value: Result<T, E>, message: &'static str) -> T {
    value.unwrap_or_else(|_| panic!("{message}"))
}

fn private(path: &Path, directory: bool) {
    let meta = must(
        std::fs::symlink_metadata(path),
        "release ownership metadata missing",
    );
    // SAFETY: geteuid has no preconditions and does not read process state.
    let uid = unsafe { libc::geteuid() };
    assert!(
        meta.uid() == uid
            && meta.mode() & 0o077 == 0
            && if directory {
                meta.is_dir()
            } else {
                meta.is_file()
            },
        "release resource is not private and owned"
    );
}

pub fn root() -> PathBuf {
    let value = std::env::var_os("MASKURA_RELEASE_ROOT")
        .unwrap_or_else(|| panic!("mandatory owned release root missing"));
    let path = PathBuf::from(value);
    assert!(path.is_absolute(), "release root must be absolute");
    assert!(
        must(std::fs::canonicalize(&path), "release root unavailable") == path
            && path
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|v| { v.starts_with("managed-release-case-") && v.len() == 57 }),
        "release root identity invalid"
    );
    private(&path, true);
    for name in ["home", "tmp", "spool", "staging"] {
        private(&path.join(name), true);
    }
    for (key, name) in [("HOME", "home"), ("TMPDIR", "tmp")] {
        assert!(
            std::env::var_os(key).as_deref() == Some(path.join(name).as_os_str()),
            "release process environment is not isolated"
        );
    }
    path
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    schema: u8,
    case: String,
    nonce: String,
    host: String,
    port: u16,
    database: String,
    user: String,
}

pub fn assert_owned_target(case: &'static str) -> String {
    let root = root();
    assert!(
        std::env::var("MASKURA_RELEASE_CASE").ok().as_deref() == Some(case),
        "release case requires an exact-case isolated launcher"
    );
    let path = root.join("owned-target.json");
    private(&path, false);
    assert!(
        must(std::fs::metadata(&path), "release target metadata missing").len() <= 1024,
        "release target manifest exceeded bound"
    );
    let target: Target = must(
        serde_json::from_slice(&must(
            std::fs::read(path),
            "release target manifest unavailable",
        )),
        "release target manifest invalid",
    );
    let nonce = must(
        uuid::Uuid::parse_str(&target.nonce),
        "release target nonce invalid",
    );
    assert!(
        target.schema == 1
            && target.case == case
            && target.nonce == nonce.simple().to_string()
            && root.file_name().and_then(|v| v.to_str())
                == Some(format!("managed-release-case-{nonce}").as_str())
            && target.host == "127.0.0.1"
            && target.port >= 1024
            && target.port != 54322
            && target.user == "managed_release"
            && target.database == format!("managed_release_{}", target.nonce),
        "release target is not the launcher's fresh owned target"
    );
    let raw = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| panic!("mandatory owned release database missing"));
    let url = must(url::Url::parse(&raw), "release database URL invalid");
    let password = url.password().unwrap_or("");
    assert!(
        password.len() == 32 && password.bytes().all(|b| b.is_ascii_hexdigit()),
        "release password must be fresh synthetic hex"
    );
    let expected = format!(
        "postgresql://managed_release:{password}@127.0.0.1:{}/{}",
        target.port, target.database
    );
    assert!(
        raw == expected,
        "release database URL does not exactly match owned target"
    );
    // No fallback/default/shared server is accepted. The parent must create and
    // attest this database/container before launching exactly one case process.
    raw
}

pub fn complete(case: &'static str) {
    // Call ONLY inside the DB closure, after every assertion and reopen check.
    assert_owned_target(case);
    println!("MANAGED_RELEASE_COMPLETE {case} assertions-ok");
}

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct BirthIdentity {
    system: String,
    start_sec: u64,
    start_subsec: u64,
    boot: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct KernelIdentity {
    pid: u32,
    ppid: u32,
    pgid: u32,
    uid: u32,
    alive: bool,
    birth: BirthIdentity,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CaseParent {
    schema: u8,
    case: String,
    nonce: String,
    root_uid: u32,
    test_identity: KernelIdentity,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnedPorts {
    schema: u8,
    case: String,
    nonce: String,
    host: String,
    ports: BTreeMap<String, u16>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PortGate {
    schema: u8,
    case: String,
    nonce: String,
    parent_sha256: String,
    ports_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TlsLedger {
    schema: u8,
    kind: String,
    case: String,
    nonce: String,
    root_uid: u32,
    ports_sha256: String,
    test_identity: KernelIdentity,
    tls_identity: KernelIdentity,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TlsAck {
    schema: u8,
    case: String,
    nonce: String,
    ledger_sha256: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ListenerAddress {
    host: String,
    port: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsListenerRecord {
    schema: u8,
    case: String,
    nonce: String,
    ports_sha256: String,
    host: String,
    port: u16,
}

#[derive(Serialize)]
struct ListenerLedger<'a> {
    schema: u8,
    case: &'a str,
    nonce: &'a str,
    ports_sha256: &'a str,
    provider: ListenerAddress,
    tls: Option<ListenerAddress>,
    gateway: Vec<ListenerAddress>,
    closed: Vec<&'a str>,
}

fn private_bytes(path: &Path) -> Vec<u8> {
    let mut file = must(
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path),
        "release protocol file unavailable",
    );
    let before = must(file.metadata(), "release protocol metadata unavailable");
    // SAFETY: geteuid has no preconditions.
    assert!(
        before.is_file()
            && before.uid() == unsafe { libc::geteuid() }
            && before.mode() & 0o777 == 0o600
            && before.len() <= 4096,
        "release protocol file is not private or bounded"
    );
    let mut bytes = Vec::new();
    must(
        (&mut file).take(4097).read_to_end(&mut bytes),
        "release protocol read failed",
    );
    let after = must(file.metadata(), "release protocol metadata changed");
    assert!(
        bytes.len() as u64 == before.len()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "release protocol file changed"
    );
    bytes
}

fn write_private<T: Serialize>(path: &Path, value: &T) {
    let bytes = must(
        serde_json::to_vec(value),
        "release protocol serialization failed",
    );
    assert!(
        bytes.len() <= 4096,
        "release protocol output exceeded bound"
    );
    let temporary = path.with_extension(format!("new-{}", uuid::Uuid::now_v7().simple()));
    let mut file = must(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary),
        "release protocol output unavailable",
    );
    must(file.write_all(&bytes), "release protocol output failed");
    must(file.sync_all(), "release protocol output flush failed");
    must(
        std::fs::rename(temporary, path),
        "release protocol publication failed",
    );
}

fn wait_private<T: serde::de::DeserializeOwned>(path: &Path, end: Instant) -> T {
    loop {
        assert!(Instant::now() < end, "release startup deadline exceeded");
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                return must(
                    serde_json::from_slice(&private_bytes(path)),
                    "release protocol schema invalid",
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => panic!("release protocol metadata failed"),
        }
        assert!(Instant::now() < end, "release startup deadline exceeded");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[derive(Clone)]
struct LaunchContext {
    root: PathBuf,
    case: String,
    nonce: String,
    ports: OwnedPorts,
    ports_hash: String,
    parent: CaseParent,
    end: Instant,
}

impl LaunchContext {
    fn new(case: &'static str) -> Self {
        let end = Instant::now() + Duration::from_secs(40);
        let root = root();
        assert!(
            std::env::var("MASKURA_RELEASE_CASE").ok().as_deref() == Some(case),
            "release protocol case mismatch"
        );
        let parent: CaseParent = wait_private(&root.join("owned-case-parent.json"), end);
        let nonce = must(
            uuid::Uuid::parse_str(&parent.nonce),
            "release protocol nonce invalid",
        );
        // SAFETY: these identity getters have no preconditions.
        let (uid, ppid, pgid) = unsafe { (libc::geteuid(), libc::getppid(), libc::getpgrp()) };
        assert!(
            parent.schema == 1
                && parent.case == case
                && parent.root_uid == uid
                && parent.nonce == nonce.simple().to_string()
                && root.file_name().and_then(|value| value.to_str())
                    == Some(format!("managed-release-case-{nonce}").as_str())
                && parent.test_identity.pid == std::process::id()
                && parent.test_identity.uid == uid
                && parent.test_identity.alive
                && parent.test_identity.ppid == ppid as u32
                && parent.test_identity.pgid == pgid as u32,
            "release protocol parent binding invalid"
        );
        let bytes = private_bytes(&root.join("owned-ports.json"));
        assert!(bytes.len() <= 1024, "release ports manifest exceeded bound");
        let ports: OwnedPorts = must(
            serde_json::from_slice(&bytes),
            "release ports schema invalid",
        );
        let roles: BTreeSet<_> = ["provider", "tls", "gateway-1", "gateway-2", "gateway-3"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert!(
            ports.schema == 1
                && ports.case == case
                && ports.nonce == parent.nonce
                && ports.host == "127.0.0.1"
                && ports.ports.keys().cloned().collect::<BTreeSet<_>>() == roles
                && ports
                    .ports
                    .values()
                    .all(|port| *port >= 1024 && ![5432, 54322].contains(port))
                && ports.ports.values().collect::<BTreeSet<_>>().len() == 5,
            "release ports must be exact unique owned loopback ports"
        );
        let gate = PortGate {
            schema: 1,
            case: case.into(),
            nonce: parent.nonce.clone(),
            parent_sha256: digest(&private_bytes(&root.join("owned-case-parent.json"))),
            ports_sha256: digest(&bytes),
        };
        write_private(&root.join("owned-case-ready.json"), &gate);
        let handoff: PortGate = wait_private(&root.join("owned-port-handoff.json"), end);
        assert!(handoff == gate, "release port handoff binding invalid");
        Self {
            root,
            case: case.into(),
            nonce: parent.nonce.clone(),
            ports,
            ports_hash: gate.ports_sha256,
            parent,
            end,
        }
    }

    fn address(&self, role: &str) -> std::net::SocketAddr {
        std::net::SocketAddr::from((
            [127, 0, 0, 1],
            *self
                .ports
                .ports
                .get(role)
                .expect("literal release port role"),
        ))
    }

    fn bind(&self, role: &str) -> std::net::TcpListener {
        assert!(
            Instant::now() < self.end,
            "release startup deadline exceeded"
        );
        let listener = must(
            std::net::TcpListener::bind(self.address(role)),
            "release exact owned port bind failed",
        );
        assert!(
            must(
                listener.local_addr(),
                "release listener address unavailable"
            ) == self.address(role),
            "release listener used an undeclared port"
        );
        listener
    }

    fn listeners(&self, tls_bound: bool, closed: bool) {
        let address = |role: &str| ListenerAddress {
            host: "127.0.0.1".into(),
            port: self.address(role).port(),
        };
        write_private(
            &self.root.join("owned-listeners.json"),
            &ListenerLedger {
                schema: 1,
                case: &self.case,
                nonce: &self.nonce,
                ports_sha256: &self.ports_hash,
                provider: address("provider"),
                tls: tls_bound.then(|| address("tls")),
                gateway: ["gateway-1", "gateway-2", "gateway-3"]
                    .into_iter()
                    .map(address)
                    .collect(),
                closed: if closed {
                    vec!["provider", "tls", "gateway-1", "gateway-2", "gateway-3"]
                } else {
                    Vec::new()
                },
            },
        );
    }
}

#[derive(Clone, Copy)]
pub enum Representation {
    Ordinary,
    Identity,
}

impl Representation {
    pub fn encoding(self) -> Option<&'static str> {
        match self {
            Self::Ordinary => None,
            Self::Identity => Some("identity"),
        }
    }
    pub fn journal_metadata(self) -> BTreeMap<String, String> {
        match self {
            Self::Ordinary => ordinary_metadata(),
            Self::Identity => identity_metadata(),
        }
    }
}

pub fn ordinary_metadata() -> BTreeMap<String, String> {
    // Custom-header ordinary PUT has no body verifier: representation encoding
    // is deliberately ABSENT, while the colliding customer field is retained.
    BTreeMap::from([
        (":maskura:metadata-version".into(), "1".into()),
        ("content-type".into(), CONTENT_TYPE.into()),
        (":maskura:user:content-type".into(), "customer-type".into()),
        (
            ":maskura:user:content-encoding".into(),
            "customer-encoding".into(),
        ),
    ])
}

pub fn identity_metadata() -> BTreeMap<String, String> {
    BTreeMap::from([
        (":maskura:metadata-version".into(), "1".into()),
        ("content-type".into(), CONTENT_TYPE.into()),
        (
            ":maskura:representation:content-encoding".into(),
            "identity".into(),
        ),
        (":maskura:user:content-type".into(), "customer-type".into()),
        (
            ":maskura:user:content-encoding".into(),
            "customer-encoding".into(),
        ),
    ])
}

pub fn capabilities() -> BackendCapabilities {
    BackendCapabilities {
        incomplete_upload_discovery: IncompleteUploadDiscovery::ExactKeyAndStartTime,
        abort_incomplete_upload: true,
        cleanup_sla: Some(Duration::from_secs(300)),
        lifecycle_rule: true,
        versioning: VersioningCapability::Optional,
        conditional_reads: ConditionalReadCapability::VersionAndEtag,
        response_checksums: ResponseChecksumCapability::Standard,
        list_operations: ListCapability::V1AndV2,
        multipart_responses: MultipartResponseCapability::Standard,
        completion_reconciliation: CompletionReconciliation::HeadWithOperationIdentity,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Version {
    pub id: String,
    pub etag: String,
    pub headers: HeaderMap,
    pub bytes: Bytes,
    pub modified: String,
}

/// Expected facts originate from the synthetic request/admitted parent and
/// configured target identity; never derive them from the returned Version.
pub struct ExpectedPhysical<'a> {
    pub bytes: &'a [u8],
    pub representation: Representation,
    pub operation_id: uuid::Uuid,
    pub generation: uuid::Uuid,
    pub instance: &'a str,
    pub account: &'a str,
    pub credential_epoch: u64,
    pub selected_version: &'a str,
}

impl ExpectedPhysical<'_> {
    pub fn child_metadata(&self) -> BTreeMap<String, String> {
        let mut expected = self.representation.journal_metadata();
        expected.extend(BTreeMap::from([
            ("maskura-generation".into(), self.generation.to_string()),
            ("maskura-provider-instance".into(), self.instance.into()),
            ("maskura-provider-account".into(), self.account.into()),
            (
                "maskura-credential-epoch".into(),
                self.credential_epoch.to_string(),
            ),
        ]));
        expected
    }

    pub fn wire_metadata(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("x-amz-meta-content-type".into(), "customer-type".into()),
            (
                "x-amz-meta-content-encoding".into(),
                "customer-encoding".into(),
            ),
            (
                "x-amz-meta-maskura-operation-id".into(),
                self.operation_id.to_string(),
            ),
            (
                "x-amz-meta-maskura-generation".into(),
                self.generation.to_string(),
            ),
            (
                "x-amz-meta-maskura-provider-instance".into(),
                self.instance.into(),
            ),
            (
                "x-amz-meta-maskura-provider-account".into(),
                self.account.into(),
            ),
            (
                "x-amz-meta-maskura-credential-epoch".into(),
                self.credential_epoch.to_string(),
            ),
            ("x-amz-meta-maskura-sha256".into(), digest(self.bytes)),
            (
                "x-amz-meta-maskura-size".into(),
                self.bytes.len().to_string(),
            ),
        ])
    }
}

pub fn representation_matches(headers: &HeaderMap, expected: Representation) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        == Some(CONTENT_TYPE)
        && headers
            .get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            == expected.encoding()
        && headers
            .get("x-amz-meta-content-type")
            .and_then(|v| v.to_str().ok())
            == Some("customer-type")
        && headers
            .get("x-amz-meta-content-encoding")
            .and_then(|v| v.to_str().ok())
            == Some("customer-encoding")
}

pub fn wire_metadata_matches(headers: &HeaderMap, expected: &BTreeMap<String, String>) -> bool {
    let fields: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.as_str().starts_with("x-amz-meta-"))
        .collect();
    let actual: Option<BTreeMap<String, String>> = fields
        .iter()
        .map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect();
    fields.len() == expected.len() && actual.as_ref() == Some(expected)
}

pub fn physical_object_matches(version: &Version, expected: &ExpectedPhysical<'_>) -> bool {
    !expected.selected_version.is_empty()
        && version.id == expected.selected_version
        && version.bytes.as_ref() == expected.bytes
        && representation_matches(&version.headers, expected.representation)
        && wire_metadata_matches(&version.headers, &expected.wire_metadata())
        && version
            .headers
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok())
            == Some("AES256")
}

/// Pure oracle negative controls on CLONES, not a claim that the gateway ran
/// and rejected corrupt output. The actual repaired provider Version must pass
/// separately before these prove the assertion would catch lost/wrong fields.
pub fn assert_corrupt_clone_controls(version: &Version, expected: &ExpectedPhysical<'_>) {
    let metadata = expected.wire_metadata();
    let representation_fields = [
        "content-type",
        "content-encoding",
        "x-amz-server-side-encryption",
    ];
    for name in
        metadata
            .keys()
            .map(String::as_str)
            .chain(representation_fields.into_iter().filter(|name| {
                *name != "content-encoding" || expected.representation.encoding().is_some()
            }))
    {
        let mut missing = version.clone();
        missing.headers.remove(name);
        assert!(
            missing.bytes == version.bytes && !physical_object_matches(&missing, expected),
            "release metadata oracle accepted a missing field with correct bytes"
        );
        let mut wrong = version.clone();
        wrong.headers.insert(
            must(
                axum::http::header::HeaderName::from_bytes(name.as_bytes()),
                "literal oracle header invalid",
            ),
            "wrong".parse().expect("literal oracle value"),
        );
        assert!(
            wrong.bytes == version.bytes && !physical_object_matches(&wrong, expected),
            "release metadata oracle accepted a wrong field with correct bytes"
        );
    }
    let mut wrong_version = version.clone();
    wrong_version.id = "not-the-journaled-version".into();
    assert!(
        !physical_object_matches(&wrong_version, expected),
        "release oracle accepted wrong selected version"
    );
}

#[derive(Clone)]
struct Upload {
    bucket: String,
    key: String,
    headers: HeaderMap,
    parts: BTreeMap<u32, (String, Bytes)>,
    started: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Call {
    pub bucket: String,
    pub operation: &'static str,
}

#[derive(Default)]
pub struct ProviderData {
    pub objects: BTreeMap<(String, String), Vec<Version>>,
    /// Immutable accepted-publication history survives exact-version deletion;
    /// Bytes clones share allocations, they do not duplicate object bodies.
    pub history: Vec<(String, String, Version)>,
    uploads: BTreeMap<String, Upload>,
    pub calls: Vec<Call>,
    pub mutations: Vec<Call>,
    mutation_counts: BTreeMap<String, usize>,
    pub fail_writes: BTreeSet<String>,
    next: u64,
}

#[derive(Clone, Default)]
pub struct Provider(pub Arc<Mutex<ProviderData>>);

impl Provider {
    pub fn mutation_count(&self, bucket: &str) -> usize {
        self.0
            .lock()
            .expect("release fixture lock")
            .mutation_counts
            .get(bucket)
            .copied()
            .unwrap_or_default()
    }
    pub fn operation_count(&self, bucket: &str, operation: &str) -> usize {
        self.0
            .lock()
            .expect("release fixture lock")
            .calls
            .iter()
            .filter(|call| call.bucket == bucket && call.operation == operation)
            .count()
    }
    pub fn versions(&self, bucket: &str, key: &str) -> Vec<Version> {
        self.0
            .lock()
            .expect("release fixture lock")
            .objects
            .get(&(bucket.into(), key.into()))
            .cloned()
            .unwrap_or_default()
    }
    pub fn history(&self, bucket: &str, key: &str) -> Vec<Version> {
        self.0
            .lock()
            .expect("release fixture lock")
            .history
            .iter()
            .filter(|(b, k, _)| b == bucket && k == key)
            .map(|(_, _, v)| v.clone())
            .collect()
    }
    pub fn fail_writes(&self, bucket: &str, fail: bool) {
        let mut data = self.0.lock().expect("release fixture lock");
        if fail {
            data.fail_writes.insert(bucket.into());
        } else {
            data.fail_writes.remove(bucket);
        }
    }
    pub fn tamper_latest_type(&self, bucket: &str, key: &str) {
        let mut data = self.0.lock().expect("release fixture lock");
        let version = data
            .objects
            .get_mut(&(bucket.into(), key.into()))
            .and_then(|v| v.last_mut())
            .expect("release repair source missing");
        version.headers.insert(
            header::CONTENT_TYPE,
            "application/json".parse().expect("literal header"),
        );
    }
}

fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn response(status: StatusCode, body: String) -> axum::response::Response {
    axum::response::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/xml")
        .body(Body::from(body))
        .expect("literal fixture response")
}

fn error(status: StatusCode, code: &'static str) -> axum::response::Response {
    response(
        status,
        format!("<Error><Code>{code}</Code><Message>TEST provider rejection</Message></Error>"),
    )
}

fn stored_headers(input: &HeaderMap) -> HeaderMap {
    let mut output: HeaderMap = input
        .iter()
        .filter(|(name, _)| {
            **name == header::CONTENT_TYPE
                || **name == header::CONTENT_ENCODING
                || name.as_str().starts_with("x-amz-meta-")
                || name.as_str() == "x-amz-server-side-encryption"
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    // Like S3, remove SDK aws-chunked transport framing from the stored
    // representation; preserve every other actual Content-Encoding token.
    if let Some(value) = input
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
    {
        let value = value
            .split(',')
            .map(str::trim)
            .filter(|v| *v != "aws-chunked")
            .collect::<Vec<_>>()
            .join(",");
        if value.is_empty() {
            output.remove(header::CONTENT_ENCODING);
        } else {
            output.insert(
                header::CONTENT_ENCODING,
                value.parse().expect("validated fixture encoding"),
            );
        }
    }
    output
}

fn complete_parts(body: &[u8]) -> Option<Vec<(u32, String)>> {
    let text = std::str::from_utf8(body).ok()?;
    let mut stack = Vec::new();
    let mut roots = 0;
    let mut number = None;
    let mut etag = None;
    let mut output = Vec::new();
    for token in xmlparser::Tokenizer::from(text) {
        match token.ok()? {
            xmlparser::Token::ElementStart { local, .. } => {
                let name = local.as_str();
                if stack.is_empty() {
                    roots += 1;
                    if roots != 1 {
                        return None;
                    }
                }
                let allowed = matches!(
                    (stack.last().copied(), name),
                    (None, "CompleteMultipartUpload")
                        | (Some("CompleteMultipartUpload"), "Part")
                        | (Some("Part"), "PartNumber" | "ETag")
                );
                if !allowed {
                    return None;
                }
                stack.push(name);
            }
            xmlparser::Token::Text { text } => match stack.last().copied() {
                Some("PartNumber") if number.is_none() => {
                    number = Some(text.as_str().parse().ok()?)
                }
                Some("ETag") if etag.is_none() => {
                    etag = Some(text.as_str().replace("&quot;", "\""))
                }
                _ if text.as_str().trim().is_empty() => {}
                _ => return None,
            },
            xmlparser::Token::ElementEnd {
                end: xmlparser::ElementEnd::Close(_, name),
                ..
            } => {
                if stack.pop()? != name.as_str() {
                    return None;
                }
                if name.as_str() == "Part" {
                    output.push((number.take()?, etag.take()?));
                }
            }
            xmlparser::Token::ElementEnd {
                end: xmlparser::ElementEnd::Open,
                ..
            }
            | xmlparser::Token::Declaration { .. } => {}
            xmlparser::Token::Attribute {
                prefix,
                local,
                value,
                ..
            } if prefix.as_str().is_empty()
                && local.as_str() == "xmlns"
                && value.as_str() == "http://s3.amazonaws.com/doc/2006-03-01/"
                && stack.as_slice() == ["CompleteMultipartUpload"] => {}
            _ => return None,
        }
    }
    if roots != 1
        || !stack.is_empty()
        || output.is_empty()
        || output.len() > 10_000
        || output.iter().any(|(n, _)| *n == 0 || *n > 10_000)
        || output.windows(2).any(|v| v[0].0 >= v[1].0)
    {
        return None;
    }
    Some(output)
}

fn decoded_body(headers: &HeaderMap, body: Bytes) -> Option<Bytes> {
    if !headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|v| v.trim() == "aws-chunked"))
    {
        return Some(body);
    }
    let mut output = Vec::new();
    let mut rest = body.as_ref();
    loop {
        let end = rest.windows(2).position(|v| v == b"\r\n")?;
        let line = std::str::from_utf8(&rest[..end]).ok()?;
        let size = usize::from_str_radix(line.split(';').next()?, 16).ok()?;
        rest = &rest[end + 2..];
        if size == 0 {
            // Only trailer/header lines remain; never treat a truncated data
            // frame as a successful empty body like the older permissive mock.
            if !(rest.ends_with(b"\r\n\r\n") || rest == b"\r\n") {
                return None;
            }
            return Some(output.into());
        }
        if size > rest.len()
            || rest.get(size..size + 2)? != b"\r\n"
            || output.len().checked_add(size)? > BODY_LIMIT
        {
            return None;
        }
        output.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

fn add_version(
    data: &mut ProviderData,
    bucket: &str,
    key: &str,
    headers: HeaderMap,
    bytes: Bytes,
) -> Option<Version> {
    if data.history.len() >= 64
        || data
            .history
            .iter()
            .map(|(_, _, v)| v.bytes.len())
            .sum::<usize>()
            + bytes.len()
            > 128 * 1024 * 1024
    {
        return None;
    }
    data.next += 1;
    let version = Version {
        id: format!("test-version-{:08}", data.next),
        etag: format!("\"{}\"", digest(&bytes)),
        headers,
        bytes,
        modified: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    };
    data.objects
        .entry((bucket.into(), key.into()))
        .or_default()
        .push(version.clone());
    data.history
        .push((bucket.into(), key.into(), version.clone()));
    Some(version)
}

pub async fn provider_handler(
    State(provider): State<Provider>,
    request: Request<Body>,
) -> axum::response::Response {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path().trim_start_matches('/');
    let (bucket, key) = path.split_once('/').unwrap_or((path, ""));
    let query: BTreeMap<String, String> =
        url::form_urlencoded::parse(parts.uri.query().unwrap_or("").as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
    let upload_id = query.get("uploadId");
    let copy = parts.headers.contains_key("x-amz-copy-source");
    let operation = match (
        &parts.method,
        upload_id.is_some(),
        query.contains_key("uploads"),
        copy,
    ) {
        (&Method::POST, false, true, _) => "create",
        (&Method::POST, true, _, _) => "complete",
        (&Method::PUT, true, _, true) => "copy",
        (&Method::PUT, true, _, false) => "part",
        (&Method::PUT, false, _, _) => "put",
        (&Method::DELETE, true, _, _) => "abort",
        (&Method::DELETE, false, _, _) => "delete",
        (&Method::HEAD, _, _, _) => "head",
        (&Method::GET, true, _, _) => "parts",
        (&Method::GET, false, true, _) => "uploads",
        (&Method::GET, false, false, _) if query.contains_key("versions") => "versions",
        (&Method::GET, false, false, _) if query.contains_key("versioning") => "versioning",
        (&Method::GET, false, false, _) if query.contains_key("list-type") => "list",
        (&Method::GET, _, _, _) => "get",
        _ => "unsupported",
    };
    let mutation = matches!(
        operation,
        "create" | "complete" | "copy" | "part" | "put" | "abort" | "delete"
    );
    {
        let mut data = provider.0.lock().expect("release fixture lock");
        let call = Call {
            bucket: bucket.into(),
            operation,
        };
        // Count attempted mutations BEFORE every validation/fault, including
        // requests that fail. Negative tests compare this independent counter.
        if mutation {
            let count_key = if [PRIMARY, SECONDARY, STAGING].contains(&bucket) {
                bucket
            } else {
                "unknown"
            };
            *data.mutation_counts.entry(count_key.into()).or_default() += 1;
        }
        if data.calls.len() >= 4096 {
            return error(StatusCode::TOO_MANY_REQUESTS, "SlowDown");
        }
        data.calls.push(call.clone());
        if mutation {
            data.mutations.push(call);
        }
        if ![PRIMARY, SECONDARY, STAGING].contains(&bucket) {
            return error(StatusCode::NOT_FOUND, "NoSuchBucket");
        }
        if !parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("AWS4-HMAC-SHA256 Credential=managed-fixture-access/"))
        {
            return error(StatusCode::FORBIDDEN, "AccessDenied");
        }
        if mutation && data.fail_writes.contains(bucket) {
            return error(StatusCode::SERVICE_UNAVAILABLE, "ServiceUnavailable");
        }
    }
    let bytes = match axum::body::to_bytes(body, BODY_LIMIT).await {
        Ok(bytes) => match decoded_body(&parts.headers, bytes) {
            Some(bytes) => bytes,
            None => return error(StatusCode::BAD_REQUEST, "InvalidRequest"),
        },
        Err(_) => return error(StatusCode::PAYLOAD_TOO_LARGE, "EntityTooLarge"),
    };
    let mut data = provider.0.lock().expect("release fixture lock");
    match operation {
        "versioning" => response(StatusCode::OK,
            "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>".into()),
        "create" => {
            if data.uploads.len() >= 64 { return error(StatusCode::TOO_MANY_REQUESTS, "SlowDown"); }
            if bucket != STAGING && parts.headers.get("x-amz-server-side-encryption")
                .and_then(|v| v.to_str().ok()) != Some("AES256") {
                return error(StatusCode::BAD_REQUEST, "InvalidEncryptionAlgorithmError");
            }
            let id = uuid::Uuid::now_v7().to_string();
            data.uploads.insert(id.clone(), Upload { bucket: bucket.into(), key: key.into(),
                headers: stored_headers(&parts.headers), parts: BTreeMap::new(),
                started: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true) });
            response(StatusCode::OK, format!("<InitiateMultipartUploadResult><Bucket>{bucket}</Bucket><Key>{}</Key><UploadId>{id}</UploadId></InitiateMultipartUploadResult>", xml(key)))
        }
        "part" | "copy" => {
            let Some(id) = upload_id else { return error(StatusCode::BAD_REQUEST, "InvalidRequest"); };
            let Some(number) = query.get("partNumber").and_then(|v| v.parse::<u32>().ok()).filter(|v| (1..=10_000).contains(v)) else {
                return error(StatusCode::BAD_REQUEST, "InvalidArgument");
            };
            let Some(upload) = data.uploads.get(id) else { return error(StatusCode::NOT_FOUND, "NoSuchUpload"); };
            if upload.bucket != bucket || upload.key != key { return error(StatusCode::NOT_FOUND, "NoSuchUpload"); }
            let payload = if operation == "copy" {
                let Some(source) = parts.headers.get("x-amz-copy-source").and_then(|v| v.to_str().ok()) else {
                    return error(StatusCode::BAD_REQUEST, "InvalidArgument");
                };
                let Ok(source) = url::Url::parse(&format!("http://127.0.0.1/{}", source.trim_start_matches('/'))) else {
                    return error(StatusCode::BAD_REQUEST, "InvalidArgument");
                };
                let Some((source_bucket, source_key)) = source.path().trim_start_matches('/').split_once('/') else {
                    return error(StatusCode::BAD_REQUEST, "InvalidArgument");
                };
                let selected = source.query_pairs().find(|(k, _)| k == "versionId").map(|(_, v)| v.into_owned());
                let Some(version) = data.objects.get(&(source_bucket.into(), source_key.into()))
                    .and_then(|versions| versions.iter().find(|v| Some(&v.id) == selected.as_ref())) else {
                    return error(StatusCode::NOT_FOUND, "NoSuchVersion");
                };
                if parts.headers.get("x-amz-copy-source-if-match").and_then(|v| v.to_str().ok()) != Some(version.etag.as_str()) {
                    return error(StatusCode::PRECONDITION_FAILED, "PreconditionFailed");
                }
                let range = parts.headers.get("x-amz-copy-source-range").and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("bytes=")).and_then(|v| v.split_once('-'))
                    .and_then(|(a, b)| Some((a.parse::<usize>().ok()?, b.parse::<usize>().ok()?)));
                let Some((a, b)) = range.filter(|(a, b)| a <= b && *b < version.bytes.len()) else {
                    return error(StatusCode::RANGE_NOT_SATISFIABLE, "InvalidRange");
                };
                version.bytes.slice(a..=b)
            } else { bytes };
            let etag = format!("\"{}\"", digest(&payload));
            let staged: usize = data.uploads.values().flat_map(|u| u.parts.values()).map(|(_, bytes)| bytes.len()).sum();
            if staged + payload.len() > 128 * 1024 * 1024 {
                return error(StatusCode::INSUFFICIENT_STORAGE, "InsufficientStorage");
            }
            data.uploads.get_mut(id).expect("checked upload").parts.insert(number, (etag.clone(), payload));
            if operation == "copy" {
                response(StatusCode::OK, format!("<CopyPartResult><LastModified>{}</LastModified><ETag>{}</ETag></CopyPartResult>", chrono::Utc::now().to_rfc3339(), xml(&etag)))
            } else {
                axum::response::Response::builder().status(StatusCode::OK).header(header::ETAG, etag)
                    .body(Body::empty()).expect("literal part response")
            }
        }
        "complete" => {
            let Some(id) = upload_id else { return error(StatusCode::BAD_REQUEST, "InvalidRequest"); };
            let Some(upload) = data.uploads.get(id).cloned().filter(|u| u.bucket == bucket && u.key == key) else {
                return error(StatusCode::NOT_FOUND, "NoSuchUpload");
            };
            let Some(selected) = complete_parts(&bytes) else { return error(StatusCode::BAD_REQUEST, "MalformedXML"); };
            let mut assembled = Vec::new();
            for (index, (number, etag)) in selected.iter().enumerate() {
                let Some((stored_etag, part)) = upload.parts.get(number).filter(|(e, _)| e == etag) else {
                    return error(StatusCode::BAD_REQUEST, "InvalidPart");
                };
                let _ = stored_etag;
                if index + 1 < selected.len() && part.len() < 5 * 1024 * 1024 {
                    return error(StatusCode::BAD_REQUEST, "EntityTooSmall");
                }
                if assembled.len() + part.len() > BODY_LIMIT { return error(StatusCode::PAYLOAD_TOO_LARGE, "EntityTooLarge"); }
                assembled.extend_from_slice(part);
            }
            // Completion headers MUST NOT alter initiation metadata or SSE.
            let Some(version) = add_version(&mut data, bucket, key, upload.headers, assembled.into()) else {
                return error(StatusCode::INSUFFICIENT_STORAGE, "InsufficientStorage");
            };
            data.uploads.remove(id);
            let body = format!("<CompleteMultipartUploadResult><Location>/{bucket}/{}</Location><Bucket>{bucket}</Bucket><Key>{}</Key><ETag>{}</ETag></CompleteMultipartUploadResult>", xml(key), xml(key), xml(&version.etag));
            let mut result = response(StatusCode::OK, body);
            result.headers_mut().insert("x-amz-version-id", version.id.parse().expect("fixture version"));
            if let Some(value) = version.headers.get("x-amz-server-side-encryption") {
                result.headers_mut().insert("x-amz-server-side-encryption", value.clone());
            }
            result
        }
        "put" => {
            if copy { return error(StatusCode::BAD_REQUEST, "InvalidRequest"); }
            if bucket != STAGING && parts.headers.get("x-amz-server-side-encryption")
                .and_then(|v| v.to_str().ok()) != Some("AES256") {
                return error(StatusCode::BAD_REQUEST, "InvalidEncryptionAlgorithmError");
            }
            let Some(version) = add_version(&mut data, bucket, key, stored_headers(&parts.headers), bytes) else {
                return error(StatusCode::INSUFFICIENT_STORAGE, "InsufficientStorage");
            };
            let mut result = axum::response::Response::builder().status(StatusCode::OK)
                .header(header::ETAG, version.etag).header("x-amz-version-id", version.id);
            if let Some(value) = version.headers.get("x-amz-server-side-encryption") { result = result.header("x-amz-server-side-encryption", value); }
            result.body(Body::empty()).expect("literal put response")
        }
        "head" | "get" => {
            let selected = query.get("versionId");
            let Some(version) = data.objects.get(&(bucket.into(), key.into())).and_then(|versions|
                match selected { Some(id) => versions.iter().find(|v| &v.id == id), None => versions.last() }) else {
                return error(StatusCode::NOT_FOUND, "NoSuchKey");
            };
            if parts.headers.get(header::IF_MATCH).and_then(|v| v.to_str().ok()).is_some_and(|v| v != version.etag) {
                return error(StatusCode::PRECONDITION_FAILED, "PreconditionFailed");
            }
            let mut result = axum::response::Response::builder().status(StatusCode::OK)
                .header(header::CONTENT_LENGTH, version.bytes.len())
                .header(header::ETAG, &version.etag).header("x-amz-version-id", &version.id)
                .header(header::LAST_MODIFIED, "Thu, 12 Nov 2026 00:00:00 GMT");
            for (name, value) in &version.headers { result = result.header(name, value); }
            result.body(if operation == "head" { Body::empty() } else { Body::from(version.bytes.clone()) })
                .expect("literal object response")
        }
        "versions" => {
            let prefix = query.get("prefix").map(String::as_str).unwrap_or("");
            let mut body = "<ListVersionsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><IsTruncated>false</IsTruncated>".to_string();
            for ((b, k), versions) in &data.objects {
                if b != bucket || !k.starts_with(prefix) { continue; }
                for (index, version) in versions.iter().enumerate() {
                    body.push_str(&format!("<Version><Key>{}</Key><VersionId>{}</VersionId><IsLatest>{}</IsLatest><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Version>", xml(k), xml(&version.id), index + 1 == versions.len(), version.modified, xml(&version.etag), version.bytes.len()));
                }
            }
            body.push_str("</ListVersionsResult>"); response(StatusCode::OK, body)
        }
        "uploads" => {
            let prefix = query.get("prefix").map(String::as_str).unwrap_or("");
            let mut body = "<ListMultipartUploadsResult><IsTruncated>false</IsTruncated>".to_string();
            for (id, upload) in &data.uploads {
                if upload.bucket == bucket && upload.key.starts_with(prefix) {
                    body.push_str(&format!("<Upload><Key>{}</Key><UploadId>{}</UploadId><Initiated>{}</Initiated></Upload>", xml(&upload.key), id, upload.started));
                }
            }
            body.push_str("</ListMultipartUploadsResult>"); response(StatusCode::OK, body)
        }
        "parts" => {
            let Some(upload) = upload_id.and_then(|id| data.uploads.get(id)).filter(|u| u.bucket == bucket && u.key == key) else {
                return error(StatusCode::NOT_FOUND, "NoSuchUpload");
            };
            let mut body = "<ListPartsResult><IsTruncated>false</IsTruncated>".to_string();
            for (number, (etag, bytes)) in &upload.parts {
                body.push_str(&format!("<Part><PartNumber>{number}</PartNumber><ETag>{}</ETag><Size>{}</Size><LastModified>{}</LastModified></Part>", xml(etag), bytes.len(), upload.started));
            }
            body.push_str("</ListPartsResult>"); response(StatusCode::OK, body)
        }
        "list" => {
            let prefix = query.get("prefix").map(String::as_str).unwrap_or("");
            let mut body = "<ListBucketResult><IsTruncated>false</IsTruncated>".to_string();
            for ((b, k), versions) in &data.objects {
                if b == bucket && k.starts_with(prefix) && let Some(v) = versions.last() {
                    body.push_str(&format!("<Contents><Key>{}</Key><Size>{}</Size><LastModified>{}</LastModified></Contents>", xml(k), v.bytes.len(), v.modified));
                }
            }
            body.push_str("</ListBucketResult>"); response(StatusCode::OK, body)
        }
        "abort" => {
            if let Some(id) = upload_id && data.uploads.get(id).is_some_and(|u| u.bucket == bucket && u.key == key) { data.uploads.remove(id); }
            response(StatusCode::NO_CONTENT, String::new())
        }
        "delete" => {
            if let Some(id) = query.get("versionId") {
                if let Some(versions) = data.objects.get_mut(&(bucket.into(), key.into())) { versions.retain(|v| &v.id != id); }
            } else { data.objects.remove(&(bucket.into(), key.into())); }
            response(StatusCode::NO_CONTENT, String::new())
        }
        _ => error(StatusCode::NOT_IMPLEMENTED, "NotImplemented"),
    }
}

#[derive(Clone, Copy)]
pub enum TlsMode {
    Trusted,
    UnrelatedCa,
    WrongName,
}

impl TlsMode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::UnrelatedCa => "unrelated-ca",
            Self::WrongName => "wrong-name",
        }
    }
    pub fn trust_file(self) -> &'static str {
        match self {
            Self::UnrelatedCa => "unrelated.pem",
            _ => "ca.pem",
        }
    }
    pub fn certificate_cause(self) -> &'static str {
        match self {
            Self::UnrelatedCa => "invalid peer certificate: UnknownIssuer",
            Self::WrongName => {
                "invalid peer certificate: certificate not valid for name \"127.0.0.1\"; certificate is only valid for IpAddress(127.0.0.2)"
            }
            Self::Trusted => panic!("trusted fixture is not a rejection control"),
        }
    }
}

fn bounded_join<T>(thread: std::thread::JoinHandle<T>, duration: Duration) -> Result<T, ()> {
    let end = Instant::now() + duration;
    while !thread.is_finished() {
        if Instant::now() >= end {
            return Err(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // is_finished is true: this join cannot wait for live thread execution.
    thread.join().map_err(|_| ())
}

fn listener_closed(address: std::net::SocketAddr) -> bool {
    match std::net::TcpStream::connect_timeout(&address, Duration::from_millis(150)) {
        Err(error) => error.kind() == std::io::ErrorKind::ConnectionRefused,
        Ok(stream) => {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            false
        }
    }
}

/// One absolute startup deadline, including already-queued records and join.
/// The injectable clock/receiver/join make boundary cases deterministic in the
/// normal pure contract test; cleanup remains the OwnedTls caller's job.
fn startup_record<T>(
    end: Instant,
    mut clock: impl FnMut() -> Instant,
    receive: impl FnOnce(Duration) -> Result<T, ()>,
    join: impl FnOnce(Instant) -> bool,
) -> Result<T, ()> {
    let now = clock();
    if now >= end {
        return Err(());
    }
    let value = receive(end.duration_since(now))?;
    if clock() >= end {
        return Err(());
    }
    if !join(end) || clock() >= end {
        return Err(());
    }
    Ok(value)
}

#[test]
fn owned_tls_startup_deadline_contract() {
    let start = Instant::now();
    let end = start + Duration::from_secs(40);
    for samples in [
        [end, end, end],
        [start, end, end],
        [start, start, end],
        [start, start, end - Duration::from_nanos(1)],
    ] {
        let mut clock = std::collections::VecDeque::from(samples);
        let (tx, rx) = mpsc::sync_channel(1);
        tx.send("queued").expect("pure startup fixture send");
        let received = std::cell::Cell::new(false);
        let joined = std::cell::Cell::new(false);
        let result = startup_record(
            end,
            || clock.pop_front().expect("pure startup clock"),
            |_| {
                received.set(true);
                rx.try_recv().map_err(|_| ())
            },
            |_| {
                joined.set(true);
                true
            },
        );
        assert_eq!(
            received.get(),
            samples[0] < end,
            "expired queued record was received"
        );
        assert_eq!(
            joined.get(),
            samples[0] < end && samples[1] < end,
            "expired record reached join"
        );
        assert_eq!(
            result.is_ok(),
            samples.into_iter().all(|sample| sample < end),
            "queued/processing/join deadline bypass"
        );
    }
}

struct OwnedTls {
    child: Child,
    /// Captured exactly at spawn with process_group(0), never looked up by name.
    pgid: libc::pid_t,
    listener: Option<std::net::SocketAddr>,
    stopped: bool,
    registered: bool,
    context: LaunchContext,
    ledger_hash: String,
}

impl OwnedTls {
    fn new(child: Child, context: &LaunchContext) -> Self {
        let pgid = child.id() as libc::pid_t;
        let mut owned = Self {
            child,
            pgid,
            listener: None,
            stopped: false,
            registered: false,
            context: context.clone(),
            ledger_hash: String::new(),
        };
        let identity = owned.line(context.end);
        let ledger: TlsLedger = must(
            serde_json::from_str(&identity),
            "release TLS identity schema invalid",
        );
        assert!(
            ledger.schema == 2
                && ledger.kind == "owned-managed-release-tls"
                && ledger.case == context.case
                && ledger.nonce == context.nonce
                && ledger.root_uid == context.parent.root_uid
                && ledger.ports_sha256 == context.ports_hash
                && ledger.test_identity == context.parent.test_identity
                && ledger.tls_identity.pid == owned.child.id()
                && ledger.tls_identity.pgid == owned.child.id()
                && ledger.tls_identity.ppid == std::process::id()
                && ledger.tls_identity.alive
                && ledger.tls_identity.uid == context.parent.root_uid,
            "release TLS child identity did not match captured Child"
        );
        write_private(&context.root.join("owned-tls-group.json"), &ledger);
        owned.ledger_hash = digest(&private_bytes(&context.root.join("owned-tls-group.json")));
        // Outer MUST independently verify both live kernel identities and direct
        // parentage. The child self-report alone is never group authorization.
        let ack: TlsAck = wait_private(&context.root.join("owned-tls-ack.json"), context.end);
        assert!(
            ack.schema == 1
                && ack.case == context.case
                && ack.nonce == context.nonce
                && ack.ledger_sha256 == owned.ledger_hash,
            "release TLS ACK binding invalid"
        );
        assert!(
            Instant::now() < context.end,
            "release startup deadline exceeded"
        );
        owned.registered = true;
        let pipe = owned
            .child
            .stdin
            .as_mut()
            .expect("release TLS start pipe missing");
        must(
            pipe.write_all(b"START\n"),
            "release TLS start gate write failed",
        );
        must(pipe.flush(), "release TLS start gate flush failed");
        owned
    }

    fn line(&mut self, end: Instant) -> String {
        if Instant::now() >= end {
            self.failed_line(None);
        }
        let mut stdout = self
            .child
            .stdout
            .take()
            .expect("release TLS private pipe missing");
        let (tx, rx) = mpsc::sync_channel(1);
        let mut reader = Some(std::thread::spawn(move || {
            let mut line = Vec::new();
            for _ in 0..4096 {
                let mut byte = [0];
                if stdout.read_exact(&mut byte).is_err() {
                    break;
                }
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            let _ = tx.send((line, stdout));
        }));
        let received = startup_record(
            end,
            Instant::now,
            |remaining| rx.recv_timeout(remaining).map_err(|_| ()),
            |deadline| {
                while !reader.as_ref().expect("release reader owned").is_finished() {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                reader.take().expect("release reader owned").join().is_ok()
            },
        );
        let (line, stdout) = match received {
            Ok(value) => value,
            Err(_) => self.failed_line(reader),
        };
        self.child.stdout = Some(stdout);
        assert!(
            line.last() == Some(&b'\n') && line.len() <= 4096,
            "release TLS private record truncated"
        );
        must(
            String::from_utf8(line),
            "release TLS private record invalid",
        )
    }

    fn failed_line(&mut self, mut reader: Option<std::thread::JoinHandle<()>>) -> ! {
        // Startup cannot renew the response budget. Only the EXISTING 1+2s
        // owned TLS cleanup allowance is available; never detach a live reader.
        let cleanup_end = Instant::now() + Duration::from_secs(3);
        if !self.stop() {
            eprintln!("MANAGED_RELEASE_SHUTDOWN_FAILED startup-child-cleanup");
            std::process::abort();
        }
        if let Some(thread) = reader.as_ref() {
            while !thread.is_finished() {
                if Instant::now() >= cleanup_end {
                    eprintln!("MANAGED_RELEASE_SHUTDOWN_FAILED startup-reader-cleanup");
                    std::process::abort();
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        if let Some(thread) = reader.take() {
            assert!(thread.join().is_ok(), "release startup reader failed");
        }
        panic!("release TLS bounded private pipe failed");
    }

    fn group_absent(&self) -> Result<bool, ()> {
        // SAFETY: negative pgid addresses ONLY the captured private group.
        if unsafe { libc::kill(-self.pgid, 0) } == 0 {
            return Ok(false);
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => Ok(true),
            _ => Err(()), // EPERM or unknown status is never absence proof.
        }
    }

    fn reap_and_prove(&mut self, duration: Duration) -> bool {
        let end = Instant::now() + duration;
        loop {
            let reaped = match self.child.try_wait() {
                Ok(Some(_)) => true,
                Ok(None) => false,
                Err(_) => return false,
            };
            // Reaping the leader is NOT sufficient. Descendants keep the owned
            // group alive; its ID stays reserved while those members exist.
            if reaped && self.group_absent() == Ok(true) {
                self.stopped = true; // Never signal this PGID after proven absence.
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn stop(&mut self) -> bool {
        if !self.stopped {
            self.child.stdin.take(); // graceful private-pipe EOF first
            if self.registered {
                // Only the outer owner has the shared kernel-identity reader.
                // Ask it to revalidate leader birth before any TERM/KILL. Rust
                // never signals a ledger-supplied or already-reaped group.
                write_private(
                    &self.context.root.join("owned-tls-stop.json"),
                    &TlsAck {
                        schema: 1,
                        case: self.context.case.clone(),
                        nonce: self.context.nonce.clone(),
                        ledger_sha256: self.ledger_hash.clone(),
                    },
                );
                if !self.reap_and_prove(Duration::from_secs(3)) {
                    return false;
                }
            } else if !self.reap_and_prove(Duration::from_secs(1)) {
                // Before ACK/START the child cannot have descendants. kill()
                // addresses ONLY our still-unreaped captured direct Child PID.
                match self.child.try_wait() {
                    Ok(None) => {
                        if self.child.kill().is_err() {
                            return false;
                        }
                    }
                    Ok(Some(_)) => {}
                    Err(_) => return false,
                }
                if !self.reap_and_prove(Duration::from_secs(2)) {
                    return false;
                }
            }
        }
        if let Some(address) = self.listener {
            if !listener_closed(address) {
                return false;
            }
            // Do not probe a possibly reallocated port again during Drop.
            self.listener = None;
        }
        true
    }
}

impl Drop for OwnedTls {
    fn drop(&mut self) {
        if !self.stop() {
            eprintln!("MANAGED_RELEASE_SHUTDOWN_FAILED tls-group-or-listener");
        }
    }
}

fn bind_owned_listeners(
    context: &LaunchContext,
) -> (std::net::TcpListener, Vec<Option<std::net::TcpListener>>) {
    let provider = context.bind("provider");
    let gateway = ["gateway-1", "gateway-2", "gateway-3"]
        .into_iter()
        .map(|role| Some(context.bind(role)))
        .collect();
    context.listeners(false, false);
    (provider, gateway)
}

fn spawn_tls(context: &LaunchContext, mode: TlsMode, control: Option<&'static str>) -> OwnedTls {
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/tests/managed_release_tls.py");
    let remaining = context
        .end
        .saturating_duration_since(Instant::now())
        .as_millis();
    assert!(
        remaining > 0 && remaining <= 40000,
        "release startup deadline exceeded"
    );
    let mut command = Command::new("/usr/bin/python3");
    command
        .arg("-B")
        .arg("-I")
        .arg(script)
        .arg("--root")
        .arg(&context.root)
        .arg("--mode")
        .arg(mode.name())
        .arg("--startup-millis")
        .arg(remaining.to_string());
    if let Some(control) = control {
        command.arg("--owned-control").arg(control);
    }
    OwnedTls::new(
        must(
            command
                .env_clear()
                .env("HOME", context.root.join("home"))
                .env("TMPDIR", context.root.join("tmp"))
                .env("PATH", "/usr/bin:/bin")
                .process_group(0)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn(),
            "release TLS child unavailable",
        ),
        context,
    )
}

fn tls_listener_record(context: &LaunchContext) {
    let record: TlsListenerRecord =
        wait_private(&context.root.join("owned-tls-listener.json"), context.end);
    assert!(
        record.schema == 1
            && record.case == context.case
            && record.nonce == context.nonce
            && record.ports_sha256 == context.ports_hash
            && record.host == "127.0.0.1"
            && record.port == context.address("tls").port(),
        "release actual TLS listener binding invalid"
    );
    context.listeners(true, false);
}

fn owned_tls_control(case: &'static str, mode: &'static str) {
    // No DB constructor/URL/attestation here. These expected-abort controls only
    // exercise the SAME owned ports, registration, START and cleanup protocol.
    assert!(
        std::env::var_os("DATABASE_URL").is_none(),
        "ownership control must not inherit a database"
    );
    let context = LaunchContext::new(case);
    let _listeners = bind_owned_listeners(&context);
    let mut tls = spawn_tls(&context, TlsMode::Trusted, Some(mode));
    assert!(
        mode == "live-descendant",
        "outer failed to abort before START"
    );
    assert!(
        tls.line(context.end).trim_end() == "MANAGED_TLS_CONTROL_READY",
        "owned descendant control not ready"
    );
    tls_listener_record(&context);
    let mut leader_reaped = false;
    loop {
        assert!(
            Instant::now() < context.end,
            "outer failed to inject owned control exit"
        );
        if !leader_reaped
            && must(tls.child.try_wait(), "owned control leader wait failed").is_some()
        {
            leader_reaped = true;
            write_private(
                &context.root.join("owned-control-leader-exited.json"),
                &TlsAck {
                    schema: 1,
                    case: context.case.clone(),
                    nonce: context.nonce.clone(),
                    ledger_sha256: tls.ledger_hash.clone(),
                },
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "requires owned managed release qualification launcher"]
fn owned_tls_main_exit_before_start() {
    owned_tls_control("control-before-start", "early-main-exit");
}

#[test]
#[ignore = "requires owned managed release qualification launcher"]
fn owned_tls_leader_exit_with_live_descendant() {
    owned_tls_control("control-descendant", "live-descendant");
}

pub struct Fixture {
    pub provider: Provider,
    pub endpoint: String,
    tls: Mutex<OwnedTls>,
    stop: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    provider_address: std::net::SocketAddr,
    relay_failure_path: PathBuf,
    finished: AtomicBool,
    shutdown_failed: AtomicBool,
    context: LaunchContext,
    gateway_listeners: Mutex<Vec<Option<std::net::TcpListener>>>,
}

impl Fixture {
    pub fn start(case: &'static str, two_backends: bool) -> Self {
        Self::start_tls_mode(case, two_backends, TlsMode::Trusted)
    }

    pub fn start_tls_mode(case: &'static str, two_backends: bool, mode: TlsMode) -> Self {
        assert_owned_target(case); // BEFORE any listener/client/startup work.
        let context = LaunchContext::new(case);
        let root = context.root.clone();
        let (listener, gateway_listeners) = bind_owned_listeners(&context);
        let provider_address = must(
            listener.local_addr(),
            "release provider address unavailable",
        );
        let mut tls = spawn_tls(&context, mode, None);
        let ready = tls.line(context.end);
        let fields: Vec<_> = ready.split_whitespace().collect();
        assert!(
            fields.len() == 4
                && fields[0] == "MANAGED_TLS_READY"
                && fields[2] == "TRUST_CONTROLS_3"
                && fields[3] == mode.name(),
            "release TLS controls did not complete"
        );
        let tls_port: u16 = must(fields[1].parse(), "release TLS port invalid");
        assert!(
            tls_port == context.address("tls").port(),
            "release TLS readiness used unknown port"
        );
        tls_listener_record(&context);
        tls.listener = Some(std::net::SocketAddr::from(([127, 0, 0, 1], tls_port)));
        let endpoint = format!("https://127.0.0.1:{tls_port}");
        let definition = |instance: &str, bucket: &str| {
            format!(
                "b2|{instance}|release-account|1|{endpoint}|us-east-1|{bucket}|managed-fixture-access|managed-fixture-secret"
            )
        };
        let mut backends = definition("release-primary", PRIMARY);
        if two_backends {
            backends.push(';');
            backends.push_str(&definition("release-secondary", SECONDARY));
        }
        // SAFETY: launcher runs one exact case per freshly cleared process.
        // This executes before every Tokio runtime/provider worker and before
        // Smithy's process-wide native-root cache can initialize.
        unsafe {
            std::env::set_var("SSL_CERT_FILE", root.join("tls").join(mode.trust_file()));
            std::env::remove_var("SSL_CERT_DIR");
            std::env::set_var("MASKURA_SERVICE_BUCKETS", backends);
            std::env::set_var(
                "MASKURA_MULTIPART_STAGING_ACCESS_KEY_ID",
                "managed-fixture-access",
            );
            std::env::set_var(
                "MASKURA_MULTIPART_STAGING_SECRET_ACCESS_KEY",
                "managed-fixture-secret",
            );
            std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
            for name in [
                "S3_ENDPOINT",
                "MASKURA_KEYS_FILE",
                "MASKURA_SECRET_KEK",
                "AWS_PROFILE",
                "AWS_CONFIG_FILE",
                "AWS_SHARED_CREDENTIALS_FILE",
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "ALL_PROXY",
            ] {
                assert!(
                    std::env::var_os(name).is_none(),
                    "release inherited forbidden environment"
                );
            }
        }
        let provider = Provider::default();
        let router = axum::Router::new()
            .fallback(provider_handler)
            .with_state(provider.clone());
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            // A single owned thread runs this provider; no detached async
            // runtime worker can survive a successful bounded thread join.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("release provider runtime");
            rt.block_on(async move {
                must(
                    listener.set_nonblocking(true),
                    "release provider socket mode",
                );
                let listener = must(
                    tokio::net::TcpListener::from_std(listener),
                    "release provider listener",
                );
                tokio::select! {
                    _ = axum::serve(listener, router).into_future() => {},
                    _ = stopped => {},
                }
            });
            drop(rt);
        });
        Self {
            provider,
            endpoint,
            tls: Mutex::new(tls),
            stop: Mutex::new(Some(stop)),
            thread: Mutex::new(Some(thread)),
            provider_address,
            finished: AtomicBool::new(false),
            shutdown_failed: AtomicBool::new(false),
            relay_failure_path: root.join("tls/relay-write-failed"),
            context,
            gateway_listeners: Mutex::new(gateway_listeners),
        }
    }

    fn shutdown(&self) -> bool {
        if self.finished.load(Ordering::Acquire) {
            return true;
        }
        // Non-HTTP cases still prebound all gateway ports before TLS controls.
        // Close those unused listeners; consumed ones belonged to ended runtimes.
        for listener in self
            .gateway_listeners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter_mut()
        {
            drop(listener.take());
        }
        let tls_ended = self
            .tls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stop();
        if let Some(stop) = self
            .stop
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = stop.send(());
        }
        let worker_ended = self
            .thread
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .is_none_or(|thread| bounded_join(thread, Duration::from_secs(6)).is_ok());
        if !worker_ended {
            self.shutdown_failed.store(true, Ordering::Release);
        }
        let relay_clean = matches!(std::fs::symlink_metadata(&self.relay_failure_path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound);
        let closed = tls_ended
            && worker_ended
            && !self.shutdown_failed.load(Ordering::Acquire)
            && listener_closed(self.provider_address)
            && ["gateway-1", "gateway-2", "gateway-3"]
                .into_iter()
                .all(|role| listener_closed(self.context.address(role)))
            && relay_clean;
        if closed {
            self.context.listeners(true, true);
            self.finished.store(true, Ordering::Release);
        }
        closed
    }

    pub fn finish(&self) {
        assert!(
            self.shutdown(),
            "release owned group/worker/listener shutdown was not proved"
        );
        println!("MANAGED_RELEASE_SHUTDOWN group-absent workers-ended listeners-closed");
    }

    pub fn numeric_tls_address(&self) -> std::net::SocketAddr {
        self.tls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .listener
            .expect("release numeric TLS listener unavailable")
    }

    pub fn backends(&self) -> Vec<ServiceBackend> {
        must(
            parse_service_backends(
                &std::env::var("MASKURA_SERVICE_BUCKETS").expect("release backend configuration"),
            ),
            "release backend parse failed",
        )
    }

    pub fn service(&self, pool: PgPool) -> Arc<ServiceStorage> {
        let service = Arc::new(
            ServiceStorage::with_management(
                self.backends(),
                Arc::new(PostgresManagedRepository::new(pool)),
                ManagedStreamingMode::Enforce,
                1,
            )
            .with_managed_capabilities(Some(capabilities())),
        );
        must(
            service.validate_managed_launch_configuration(),
            "release managed launch validation failed",
        );
        service
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Close the private stdin pipe and terminate only our owned process
        // group; never look up processes by name or touch shared listeners.
        if !self.shutdown() {
            if std::thread::panicking() {
                eprintln!("MANAGED_RELEASE_SHUTDOWN_FAILED owned-fixture");
            } else {
                panic!("release owned fixture shutdown was not proved");
            }
        }
        // Launcher removes exact owned resources AFTER this case process exits.
    }
}

pub async fn build_release_state(
    endpoint: &str,
    control: Arc<MultipartBillingControl>,
) -> Arc<AppState> {
    let root = root();
    let component = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-components/test-transformer.component.wasm");
    let bytes = must(
        std::fs::read(&component),
        "genuine TEST transformer missing",
    );
    let mut config = Config::default();
    config.auth.disabled = false;
    config.storage.single_tenant = false;
    config.wasm.filter_component = Some(component.display().to_string());
    config.features.managed_streaming_mode =
        maskura_customer_config::config::ManagedStreamingMode::Enforce;
    config.features.managed_streaming_transactional = true;
    config.features.multipart_mode = maskura_customer_config::config::MultipartMode::Staged;
    config.spool.dir = Some(root.join("spool").display().to_string());
    config.spool.max_object_bytes = Some(BODY_LIMIT as u64);
    config.spool.quota_bytes = Some(128 * 1024 * 1024);
    config.multipart_staging.endpoint = Some(endpoint.into());
    config.multipart_staging.bucket = Some(STAGING.into());
    config.multipart_staging.region = Some("us-east-1".into());
    config.multipart_staging.dir = Some(root.join("staging").display().to_string());
    config.multipart_staging.tenant_quota_bytes = Some(64 * 1024 * 1024);
    config.multipart_staging.global_quota_bytes = Some(128 * 1024 * 1024);
    config.limits.max_object_bytes = Some(BODY_LIMIT as u64);
    let mut state = must(
        build_state(
            control,
            Arc::new(LocalKeyWrapping::with_kek(TEST_KEK)),
            Arc::new(maskura_gateway::workspace_storage::InMemoryWorkspaceStorageRepository::new()),
            &config,
        )
        .await,
        "release normal managed startup failed",
    );
    let registry = Arc::new(PluginRegistry::new());
    must(
        registry.import("release-test-transformer", &bytes),
        "release TEST pipeline import failed",
    );
    let write = StaticPipelineResolver::new(registry.clone());
    let engine = must(
        maskura_wasm_runtime::FilterEngine::new(&bytes),
        "release TEST engine failed",
    );
    Arc::get_mut(&mut state)
        .expect("release state uniquely owned")
        .gateway = Arc::new(Gateway::with_registry(engine, registry).with_resolver(
        Arc::new(PassthroughReadResolver { write }),
        Arc::new(FixedComponentSource(bytes.into())),
    ));
    assert!(
        !state.auth_disabled && !state.explicit_single_tenant && state.s3_client.is_none(),
        "release HTTP case did not select authenticated managed storage"
    );
    state
}

pub async fn serve_gateway(state: Arc<AppState>, fixture: &Fixture) -> (reqwest::Client, String) {
    let listener = fixture
        .gateway_listeners
        .lock()
        .expect("release gateway listener lock")
        .iter_mut()
        .find_map(Option::take)
        .expect("release gateway phases exhausted");
    must(
        listener.set_nonblocking(true),
        "release HTTP listener mode failed",
    );
    let listener = must(
        tokio::net::TcpListener::from_std(listener),
        "release HTTP listener runtime conversion failed",
    );
    let endpoint = format!(
        "http://{}",
        must(listener.local_addr(), "release HTTP address failed")
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, build_router(state)).await;
    });
    let client = must(
        reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(120))
            .build(),
        "release HTTP client failed",
    );
    (client, endpoint)
}

/// Fixture contract only: this is NOT counted as managed PG/router coverage.
/// Authoring it is cheap; execution is deferred to the parent's test window.
#[tokio::test]
async fn strict_managed_provider_contract() {
    async fn call(
        provider: &Provider,
        method: Method,
        uri: &str,
        headers: &[(&str, String)],
        body: Vec<u8>,
    ) -> axum::response::Response {
        let mut request = Request::builder().method(method).uri(uri)
            .header(header::AUTHORIZATION,
                "AWS4-HMAC-SHA256 Credential=managed-fixture-access/test, SignedHeaders=host, Signature=synthetic");
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        provider_handler(
            State(provider.clone()),
            request
                .body(Body::from(body))
                .expect("literal fixture contract request"),
        )
        .await
    }
    let provider = Provider::default();
    let headers = vec![
        ("content-type", CONTENT_TYPE.into()),
        ("content-encoding", "identity".into()),
        ("x-amz-meta-content-type", "customer-type".into()),
        ("x-amz-server-side-encryption", "AES256".into()),
    ];
    let missing_sse = call(
        &provider,
        Method::PUT,
        "/release-primary/rejected",
        &[],
        vec![1],
    )
    .await;
    assert!(
        missing_sse.status() == StatusCode::BAD_REQUEST && provider.mutation_count(PRIMARY) == 1,
        "fixture failed mutation must be counted"
    );
    assert!(
        call(
            &provider,
            Method::PUT,
            "/release-primary/source",
            &headers,
            b"abcde".to_vec()
        )
        .await
        .status()
            == StatusCode::OK,
        "fixture source PUT failed"
    );
    let source = provider
        .versions(PRIMARY, "source")
        .pop()
        .expect("fixture source absent");
    let created = call(
        &provider,
        Method::POST,
        "/release-primary/target?uploads",
        &headers,
        Vec::new(),
    )
    .await;
    assert!(created.status() == StatusCode::OK, "fixture create failed");
    let body = must(
        axum::body::to_bytes(created.into_body(), 4096).await,
        "fixture create body failed",
    );
    let upload = extract_xml(
        must(std::str::from_utf8(&body), "fixture XML invalid"),
        "UploadId",
    );
    assert!(!upload.is_empty(), "fixture upload ID absent");
    let uri = format!("/release-primary/target?uploadId={upload}&partNumber=1");
    for (version, etag, range, status) in [
        (
            "unknown",
            source.etag.as_str(),
            "bytes=1-3",
            StatusCode::NOT_FOUND,
        ),
        (
            source.id.as_str(),
            "\"wrong\"",
            "bytes=1-3",
            StatusCode::PRECONDITION_FAILED,
        ),
        (
            source.id.as_str(),
            source.etag.as_str(),
            "bytes=1-9",
            StatusCode::RANGE_NOT_SATISFIABLE,
        ),
    ] {
        let before = provider.mutation_count(PRIMARY);
        let response = call(
            &provider,
            Method::PUT,
            &uri,
            &[
                (
                    "x-amz-copy-source",
                    format!("release-primary/source?versionId={version}"),
                ),
                ("x-amz-copy-source-if-match", etag.into()),
                ("x-amz-copy-source-range", range.into()),
            ],
            Vec::new(),
        )
        .await;
        assert!(
            response.status() == status
                && provider.mutation_count(PRIMARY) == before + 1
                && provider.versions(PRIMARY, "target").is_empty(),
            "fixture copy version/condition/range rejection contract failed"
        );
        assert!(
            provider
                .0
                .lock()
                .expect("fixture lock")
                .uploads
                .get(&upload)
                .expect("fixture upload absent")
                .parts
                .is_empty(),
            "fixture rejected copy changed pending parts"
        );
    }
    let response = call(
        &provider,
        Method::PUT,
        &uri,
        &[
            (
                "x-amz-copy-source",
                format!("release-primary/source?versionId={}", source.id),
            ),
            ("x-amz-copy-source-if-match", source.etag.clone()),
            ("x-amz-copy-source-range", "bytes=1-3".into()),
        ],
        Vec::new(),
    )
    .await;
    assert!(
        response.status() == StatusCode::OK,
        "fixture valid copy failed"
    );
    let completion_uri = format!("/release-primary/target?uploadId={upload}");
    let wrong = b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>wrong</ETag></Part></CompleteMultipartUpload>";
    assert!(
        call(
            &provider,
            Method::POST,
            &completion_uri,
            &[],
            wrong.to_vec()
        )
        .await
        .status()
            == StatusCode::BAD_REQUEST
            && provider.versions(PRIMARY, "target").is_empty(),
        "fixture accepted a completion with wrong part ETag"
    );
    let etag = format!("\"{}\"", digest(b"bcd"));
    let correct = format!(
        "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        xml(&etag)
    );
    assert!(
        complete_parts(b"<CompleteMultipartUpload><Part>").is_none()
            && complete_parts(correct.repeat(2).as_bytes()).is_none(),
        "fixture accepted partial XML or multiple root documents"
    );
    assert!(
        call(
            &provider,
            Method::POST,
            &completion_uri,
            &[
                ("content-type", "application/xml".into()),
                (
                    "x-amz-meta-content-type",
                    "completion-must-not-replace-initiation".into()
                ),
            ],
            correct.into_bytes()
        )
        .await
        .status()
            == StatusCode::OK,
        "fixture valid completion failed"
    );
    let target = provider
        .versions(PRIMARY, "target")
        .pop()
        .expect("fixture target absent");
    assert!(
        target.bytes.as_ref() == b"bcd"
            && target
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                == Some(CONTENT_TYPE)
            && target
                .headers
                .get("x-amz-meta-content-type")
                .and_then(|v| v.to_str().ok())
                == Some("customer-type")
            && target
                .headers
                .get("x-amz-server-side-encryption")
                .and_then(|v| v.to_str().ok())
                == Some("AES256"),
        "fixture failed to freeze initiation metadata/SSE or copied wrong range"
    );
    let head = call(
        &provider,
        Method::HEAD,
        &format!("/release-primary/target?versionId={}", target.id),
        &[],
        Vec::new(),
    )
    .await;
    assert!(
        head.status() == StatusCode::OK
            && head
                .headers()
                .get("x-amz-version-id")
                .and_then(|v| v.to_str().ok())
                == Some(target.id.as_str())
            && head
                .headers()
                .get("x-amz-server-side-encryption")
                .and_then(|v| v.to_str().ok())
                == Some("AES256"),
        "fixture exact-version HEAD/SSE replay failed"
    );
    assert!(
        call(
            &provider,
            Method::GET,
            "/release-primary/target?versionId=unknown",
            &[],
            Vec::new()
        )
        .await
        .status()
            == StatusCode::NOT_FOUND,
        "fixture silently substituted latest version"
    );
    assert!(
        provider.mutation_count(PRIMARY) == 9,
        "fixture failed/success mutation accounting drifted"
    );
}
