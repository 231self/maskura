//! `maskura policy` CLI integration tests over the committed fixture
//! directory (Slice 4 spec §3, §7): the pin invariants (auto-bootstrap from a
//! customer artifact; a server-fetched bundle can never establish a pin),
//! completeness honesty, trust-reset discontinuity, `--at` historical
//! validity, unknown-schema fail-closed, and checkpoint gap flagging.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use maskura_pipeline_config::{EvidenceBundle, TrustBundle};

const WORKSPACE: &str = "ws-1";

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("policy")
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(fixture_dir().join(name)).unwrap()
}

fn root_fingerprint() -> String {
    TrustBundle::from_json(&fixture("trust_root.json"))
        .unwrap()
        .digest()
        .unwrap()
}

fn reset_fingerprint() -> String {
    TrustBundle::from_json(&fixture("trust_root_reset.json"))
        .unwrap()
        .digest()
        .unwrap()
}

fn temp_dir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "maskura-policy-cli-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn write_file(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

/// Run `maskura policy <args>` against a trust store. Asserts nothing about
/// the exit status; callers do.
fn run(trust_dir: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_maskura"));
    command
        .arg("policy")
        .args(args)
        .arg("--trust-dir")
        .arg(trust_dir)
        .env_remove("MASKURA_POLICY_TRUST_DIR")
        .env_remove("MASKURA_WORKSPACE_ID")
        .env_remove("MASKURA_ACCESS_TOKEN");
    command.output().unwrap()
}

fn run_ok(trust_dir: &Path, args: &[&str]) -> String {
    let output = run(trust_dir, args);
    assert!(
        output.status.success(),
        "policy {:?} failed:\nstdout: {}\nstderr: {}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn run_fail(trust_dir: &Path, args: &[&str]) -> String {
    let output = run(trust_dir, args);
    assert!(
        !output.status.success(),
        "policy {:?} unexpectedly succeeded:\nstdout: {}",
        args,
        String::from_utf8_lossy(&output.stdout)
    );
    let mut text = String::from_utf8(output.stdout.clone()).unwrap();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

fn pinned_root(trust_dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(trust_dir.join("trust.json")).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    Some(
        value["pins"][0]["root_fingerprint"]
            .as_str()
            .unwrap()
            .to_string(),
    )
}

fn serve(body: String) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let task = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buffer = [0u8; 8192];
            let _ = stream.read(&mut buffer);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body.as_bytes()).unwrap();
        }
    });
    (format!("http://{address}"), task)
}

// ---------------------------------------------------------------------------
// Pin invariants
// ---------------------------------------------------------------------------

#[test]
fn trust_import_auto_pins_the_root_from_the_customer_artifact() {
    let trust_dir = temp_dir("auto-pin");
    let file = write_file(&trust_dir, "bundle.json", &fixture("evidence_seq1.json"));
    let out = run_ok(&trust_dir, &["trust", "import", file.to_str().unwrap()]);
    assert!(out.contains("pinned"), "{out}");
    assert_eq!(pinned_root(&trust_dir).unwrap(), root_fingerprint());
    // The import also retains the post-publish checkpoint and audits the file.
    assert!(trust_dir.join("checkpoints/ws-1/1.json").exists());
    let index: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(trust_dir.join("index.json")).unwrap())
            .unwrap();
    assert_eq!(index["artifacts"][0]["workspace_id"], WORKSPACE);
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

#[test]
fn trust_import_refuses_a_tampered_artifact_and_writes_no_pin() {
    let trust_dir = temp_dir("tampered");
    let mut value: serde_json::Value =
        serde_json::from_str(&fixture("evidence_seq1.json")).unwrap();
    value["receipt"]["body"]["envelope_version"] = 99.into();
    let file = write_file(&trust_dir, "bundle.json", &value.to_string());
    let out = run_fail(&trust_dir, &["trust", "import", file.to_str().unwrap()]);
    assert!(out.contains("import refused"), "{out}");
    assert!(pinned_root(&trust_dir).is_none(), "no pin may be written");
    assert!(!trust_dir.join("trust.json").exists());
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

#[test]
fn trust_import_is_idempotent_for_the_same_root() {
    let trust_dir = temp_dir("idempotent");
    let file = write_file(&trust_dir, "bundle.json", &fixture("evidence_seq1.json"));
    run_ok(&trust_dir, &["trust", "import", file.to_str().unwrap()]);
    let out = run_ok(&trust_dir, &["trust", "import", file.to_str().unwrap()]);
    assert!(out.contains("already pinned"), "{out}");
    assert_eq!(pinned_root(&trust_dir).unwrap(), root_fingerprint());
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

#[test]
fn trust_import_refuses_pin_overwrite_without_force() {
    let trust_dir = temp_dir("no-overwrite");
    let first = write_file(&trust_dir, "first.json", &fixture("evidence_seq1.json"));
    run_ok(&trust_dir, &["trust", "import", first.to_str().unwrap()]);
    let reset = write_file(
        &trust_dir,
        "reset.json",
        &fixture("evidence_reset_root.json"),
    );
    let out = run_fail(&trust_dir, &["trust", "import", reset.to_str().unwrap()]);
    assert!(
        out.contains("discontinuity: new root not accepted"),
        "{out}"
    );
    // Even an import whose verification passes on its own root cannot replace
    // the pin without explicit --force + confirmation.
    let out = run_fail(
        &trust_dir,
        &["trust", "import", reset.to_str().unwrap(), "--force"],
    );
    assert!(
        out.contains("not confirmed") || out.contains("discontinuity"),
        "{out}"
    );
    assert_eq!(pinned_root(&trust_dir).unwrap(), root_fingerprint());
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

#[test]
fn trust_import_force_replaces_the_pin_and_archives_checkpoints() {
    let trust_dir = temp_dir("force-replace");
    let first = write_file(&trust_dir, "first.json", &fixture("evidence_seq1.json"));
    run_ok(&trust_dir, &["trust", "import", first.to_str().unwrap()]);
    let reset = write_file(
        &trust_dir,
        "reset.json",
        &fixture("evidence_reset_root.json"),
    );
    let out = run_ok(
        &trust_dir,
        &[
            "trust",
            "import",
            reset.to_str().unwrap(),
            "--force",
            "--yes",
        ],
    );
    assert!(out.contains("explicit acceptance"), "{out}");
    assert_eq!(pinned_root(&trust_dir).unwrap(), reset_fingerprint());
    // The superseded lineage's checkpoints are archived, not deleted.
    let retired: Vec<String> = std::fs::read_dir(trust_dir.join("checkpoints"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains("retired"))
        .collect();
    assert_eq!(
        retired.len(),
        1,
        "expected an archived lineage: {retired:?}"
    );
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

#[test]
fn trust_add_is_the_manual_strict_path() {
    let trust_dir = temp_dir("manual");
    let bundle = write_file(&trust_dir, "root.json", &fixture("trust_root.json"));
    let fingerprint = root_fingerprint();
    run_ok(
        &trust_dir,
        &[
            "trust",
            "add",
            &fingerprint,
            "--workspace",
            WORKSPACE,
            "--bundle",
            bundle.to_str().unwrap(),
        ],
    );
    assert_eq!(pinned_root(&trust_dir).unwrap(), fingerprint);
    // A snapshot that does not digest to the fingerprint is refused.
    let out = run_fail(
        &trust_dir,
        &[
            "trust",
            "add",
            &"a".repeat(64),
            "--workspace",
            "ws-2",
            "--bundle",
            bundle.to_str().unwrap(),
        ],
    );
    assert!(out.contains("does not match"), "{out}");
    // Non-hex fingerprints are refused.
    let out = run_fail(
        &trust_dir,
        &["trust", "add", "not-hex", "--workspace", "ws-2"],
    );
    assert!(out.contains("64 lowercase hex"), "{out}");
    let shown = run_ok(&trust_dir, &["trust", "show"]);
    assert!(shown.contains(&fingerprint), "{shown}");
    assert!(shown.contains("manual"), "{shown}");
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

#[test]
fn trust_fetch_never_establishes_a_pin() {
    let trust_dir = temp_dir("fetch-no-pin");
    let (url, _server) = serve(fixture("trust_root.json"));
    // The CLI refuses before any request is made, so the server thread is
    // expected to stay unanswered.
    let out = run_fail(&trust_dir, &["trust", "fetch", "--url", &url]);
    assert!(
        out.contains("can never establish a pin"),
        "the no-server-pin invariant must be explicit: {out}"
    );
    assert!(pinned_root(&trust_dir).is_none());
    assert!(!trust_dir.join("trust.json").exists());
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

#[test]
fn trust_fetch_compares_and_refreshes_only_a_matching_pin() {
    let trust_dir = temp_dir("fetch-match");
    let file = write_file(&trust_dir, "bundle.json", &fixture("evidence_seq1.json"));
    run_ok(&trust_dir, &["trust", "import", file.to_str().unwrap()]);

    // Matching bundle: the stored snapshot is refreshed, the pin is unchanged.
    let (url, server) = serve(fixture("trust_root.json"));
    let out = run_ok(
        &trust_dir,
        &["trust", "fetch", "--workspace", WORKSPACE, "--url", &url],
    );
    server.join().unwrap();
    assert!(out.contains("refreshed"), "{out}");
    assert_eq!(pinned_root(&trust_dir).unwrap(), root_fingerprint());
    let text = std::fs::read_to_string(trust_dir.join("trust.json")).unwrap();
    assert!(text.contains("\"bundle\""), "snapshot retained: {text}");

    // Non-matching bundle: comparison only, nothing updated.
    let (url, server) = serve(fixture("trust_root_reset.json"));
    let out = run_fail(
        &trust_dir,
        &["trust", "fetch", "--workspace", WORKSPACE, "--url", &url],
    );
    server.join().unwrap();
    assert!(out.contains("DIFFERENT"), "{out}");
    assert_eq!(pinned_root(&trust_dir).unwrap(), root_fingerprint());
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

// ---------------------------------------------------------------------------
// Verify: completeness honesty, --at, discontinuity, unknown schema
// ---------------------------------------------------------------------------

#[test]
fn policy_verify_is_refused_without_a_pin() {
    let trust_dir = temp_dir("verify-unpinned");
    let file = write_file(&trust_dir, "bundle.json", &fixture("evidence_seq1.json"));
    let out = run_fail(&trust_dir, &["verify", file.to_str().unwrap()]);
    assert!(out.contains("unpinned"), "{out}");
    assert!(
        !out.contains("verdict:       VERIFIED"),
        "must not present continuity: {out}"
    );
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

#[test]
fn policy_verify_first_run_reports_unverified_completeness() {
    let trust_dir = temp_dir("verify-first-run");
    let bundle = write_file(&trust_dir, "root.json", &fixture("trust_root.json"));
    let fingerprint = root_fingerprint();
    run_ok(
        &trust_dir,
        &[
            "trust",
            "add",
            &fingerprint,
            "--workspace",
            WORKSPACE,
            "--bundle",
            bundle.to_str().unwrap(),
        ],
    );
    let file = write_file(&trust_dir, "bundle.json", &fixture("evidence_seq1.json"));
    let out = run_ok(&trust_dir, &["verify", file.to_str().unwrap()]);
    assert!(out.contains("VERIFIED"), "{out}");
    assert!(
        out.contains("completeness:  UNVERIFIED (no prior checkpoint)"),
        "first-run honesty is normative: {out}"
    );
    assert!(out.contains("first-run"), "{out}");
    assert!(out.contains("not-witness-verified"), "{out}");
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

#[test]
fn policy_verify_extends_retained_history_after_import() {
    let trust_dir = temp_dir("verify-extend");
    let first = write_file(&trust_dir, "first.json", &fixture("evidence_seq1.json"));
    run_ok(&trust_dir, &["trust", "import", first.to_str().unwrap()]);
    let second = write_file(&trust_dir, "second.json", &fixture("evidence_seq2.json"));
    let out = run_ok(&trust_dir, &["verify", second.to_str().unwrap()]);
    assert!(out.contains("VERIFIED"), "{out}");
    assert!(
        out.contains("COMPARED (seq 2..=2 against retained head 1)"),
        "{out}"
    );
    assert!(out.contains("extended-ok"), "{out}");
    // The verify run retained checkpoint 2 as the new head.
    assert!(trust_dir.join("checkpoints/ws-1/2.json").exists());
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

#[test]
fn policy_verify_json_emits_the_versioned_report() {
    let trust_dir = temp_dir("verify-json");
    let bundle = write_file(&trust_dir, "root.json", &fixture("trust_root.json"));
    let fingerprint = root_fingerprint();
    run_ok(
        &trust_dir,
        &[
            "trust",
            "add",
            &fingerprint,
            "--workspace",
            WORKSPACE,
            "--bundle",
            bundle.to_str().unwrap(),
        ],
    );
    let file = write_file(&trust_dir, "bundle.json", &fixture("evidence_seq1.json"));
    let out = run_ok(&trust_dir, &["verify", file.to_str().unwrap(), "--json"]);
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["verdict"], "verified");
    assert_eq!(report["witness"], "not-witness-verified");
    assert_eq!(report["completeness"]["status"], "unverified");
    assert_eq!(report["completeness"]["reason"], "no prior checkpoint");
    assert!(report["findings"].as_array().unwrap().len() >= 2);
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

#[test]
fn policy_verify_at_historical_instant() {
    let trust_dir = temp_dir("verify-at");
    let bundle = write_file(&trust_dir, "root.json", &fixture("trust_root.json"));
    let fingerprint = root_fingerprint();
    run_ok(
        &trust_dir,
        &[
            "trust",
            "add",
            &fingerprint,
            "--workspace",
            WORKSPACE,
            "--bundle",
            bundle.to_str().unwrap(),
        ],
    );
    let file = write_file(&trust_dir, "bundle.json", &fixture("evidence_seq1.json"));
    // The fixture's approval was issued at 1100: not yet valid at 1000.
    let out = run_fail(
        &trust_dir,
        &["verify", file.to_str().unwrap(), "--at", "1000"],
    );
    assert!(out.contains("not-yet-valid"), "{out}");
    // Historical validity after issuance passes.
    let out = run_ok(
        &trust_dir,
        &["verify", file.to_str().unwrap(), "--at", "1500"],
    );
    assert!(out.contains("VERIFIED"), "{out}");
    // RFC3339 is accepted too (2026-01-01 is long after issuance).
    let out = run_ok(
        &trust_dir,
        &[
            "verify",
            file.to_str().unwrap(),
            "--at",
            "2026-01-01T00:00:00Z",
        ],
    );
    assert!(out.contains("VERIFIED"), "{out}");
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

#[test]
fn policy_verify_flags_gaps_against_retained_history() {
    let trust_dir = temp_dir("verify-gap");
    let bundle = write_file(&trust_dir, "root.json", &fixture("trust_root.json"));
    let fingerprint = root_fingerprint();
    run_ok(
        &trust_dir,
        &[
            "trust",
            "add",
            &fingerprint,
            "--workspace",
            WORKSPACE,
            "--bundle",
            bundle.to_str().unwrap(),
        ],
    );
    std::fs::create_dir_all(trust_dir.join("checkpoints/ws-1")).unwrap();
    std::fs::copy(
        fixture_dir().join("checkpoint_seq1.json"),
        trust_dir.join("checkpoints/ws-1/1.json"),
    )
    .unwrap();
    // Drop the chain_tail so the artifact jumps from retained seq 1 to seq 3.
    let mut value: serde_json::Value =
        serde_json::from_str(&fixture("evidence_seq3_tail.json")).unwrap();
    value.as_object_mut().unwrap().remove("chain_tail");
    let file = write_file(&trust_dir, "bundle.json", &value.to_string());
    let out = run_fail(&trust_dir, &["verify", file.to_str().unwrap()]);
    assert!(out.contains("gap:"), "{out}");
    assert!(out.contains("FAILED"), "{out}");
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

#[test]
fn policy_verify_flags_divergent_history_as_rollback_suspect() {
    let trust_dir = temp_dir("verify-rollback");
    let first = write_file(&trust_dir, "first.json", &fixture("evidence_seq1.json"));
    run_ok(&trust_dir, &["trust", "import", first.to_str().unwrap()]);
    // A divergent retained record at seq 2 (split-view suspicion).
    let mut divergent: serde_json::Value =
        serde_json::from_str(&fixture("checkpoint_seq2.json")).unwrap();
    divergent["receipt_sha256"] = "a".repeat(64).into();
    std::fs::write(
        trust_dir.join("checkpoints/ws-1/2.json"),
        serde_json::to_string_pretty(&divergent).unwrap(),
    )
    .unwrap();
    let second = write_file(&trust_dir, "second.json", &fixture("evidence_seq2.json"));
    let out = run_fail(&trust_dir, &["verify", second.to_str().unwrap()]);
    assert!(out.contains("rollback-suspect"), "{out}");
    assert!(out.contains("divergent history"), "{out}");
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

#[test]
fn trust_reset_discontinuity_is_never_presented_as_continuity() {
    let trust_dir = temp_dir("verify-discontinuity");
    let first = write_file(&trust_dir, "first.json", &fixture("evidence_seq1.json"));
    run_ok(&trust_dir, &["trust", "import", first.to_str().unwrap()]);
    let reset = write_file(
        &trust_dir,
        "reset.json",
        &fixture("evidence_reset_root.json"),
    );
    let out = run_fail(&trust_dir, &["verify", reset.to_str().unwrap()]);
    assert!(
        out.contains("discontinuity: new root not accepted"),
        "{out}"
    );
    assert!(
        !out.contains("extended-ok"),
        "never present continuity: {out}"
    );
    assert!(out.contains("UNVERIFIED"), "{out}");
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

#[test]
fn unknown_schema_is_rejected_by_the_cli() {
    let trust_dir = temp_dir("unknown-schema");
    let mut value: serde_json::Value =
        serde_json::from_str(&fixture("evidence_seq1.json")).unwrap();
    value["schema_version"] = 99.into();
    let file = write_file(&trust_dir, "bundle.json", &value.to_string());
    let out = run_fail(&trust_dir, &["verify", file.to_str().unwrap()]);
    assert!(out.contains("schema_version"), "{out}");
    let out = run_fail(&trust_dir, &["trust", "import", file.to_str().unwrap()]);
    assert!(out.contains("schema_version"), "{out}");
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

#[test]
fn chain_bundle_imports_and_verifies_whole_history() {
    let trust_dir = temp_dir("chain");
    let file = write_file(&trust_dir, "chain.json", &fixture("chain_seq1_to3.json"));
    let out = run_ok(&trust_dir, &["trust", "import", file.to_str().unwrap()]);
    assert!(out.contains("pinned"), "{out}");
    assert_eq!(pinned_root(&trust_dir).unwrap(), root_fingerprint());
    // All carried checkpoints were retained.
    for seq in [1, 2, 3] {
        assert!(
            trust_dir
                .join(format!("checkpoints/ws-1/{seq}.json"))
                .exists(),
            "missing retained checkpoint {seq}"
        );
    }
    let out = run_ok(&trust_dir, &["verify", file.to_str().unwrap()]);
    assert!(out.contains("VERIFIED"), "{out}");
    assert!(
        out.contains("re-confirms") || out.contains("extended-ok"),
        "{out}"
    );
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

// ---------------------------------------------------------------------------
// Checkpoints listing
// ---------------------------------------------------------------------------

#[test]
fn policy_checkpoints_lists_heads_and_flags_gaps() {
    let trust_dir = temp_dir("checkpoints");
    std::fs::create_dir_all(trust_dir.join("checkpoints/ws-1")).unwrap();
    std::fs::copy(
        fixture_dir().join("checkpoint_seq1.json"),
        trust_dir.join("checkpoints/ws-1/1.json"),
    )
    .unwrap();
    std::fs::copy(
        fixture_dir().join("checkpoint_seq3.json"),
        trust_dir.join("checkpoints/ws-1/3.json"),
    )
    .unwrap();
    let out = run_ok(&trust_dir, &["checkpoints", "--workspace", WORKSPACE]);
    assert!(out.contains("seq    1"), "{out}");
    assert!(out.contains("seq    3"), "{out}");
    assert!(out.contains("head: seq 3"), "{out}");
    assert!(out.contains("gaps: missing seq 2"), "{out}");
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

#[test]
fn trust_store_layout_is_portable_and_bounded() {
    let trust_dir = temp_dir("layout");
    let file = write_file(&trust_dir, "bundle.json", &fixture("evidence_seq1.json"));
    run_ok(&trust_dir, &["trust", "import", file.to_str().unwrap()]);
    let mut top: Vec<String> = std::fs::read_dir(&trust_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    top.sort();
    assert_eq!(
        top,
        vec!["bundle.json", "checkpoints", "index.json", "trust.json"]
    );
    // No temp files survive atomic writes anywhere in the store.
    for entry in walk(&trust_dir) {
        assert!(!entry.contains(".tmp-"), "temp file leaked: {entry}");
    }
    std::fs::remove_dir_all(&trust_dir).unwrap();
}

fn walk(dir: &Path) -> Vec<String> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        names.push(name.clone());
        if entry.path().is_dir() {
            names.extend(walk(&entry.path()));
        }
    }
    names
}

#[test]
fn evidence_bundle_fixtures_are_the_parse_target() {
    // The CLI suite reads the same committed vectors the facade suite pins:
    // the parse target and the emission contract stay in lockstep.
    for name in [
        "evidence_seq1.json",
        "evidence_seq2.json",
        "evidence_seq3_tail.json",
        "chain_seq1_to3.json",
        "evidence_reset_root.json",
    ] {
        let bundle = EvidenceBundle::from_json(&fixture(name)).unwrap();
        assert_eq!(bundle.workspace_id(), WORKSPACE);
        assert!(!bundle.trust_root_fingerprint().is_empty());
    }
}
