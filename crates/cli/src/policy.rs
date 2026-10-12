//! `maskura policy` — customer-side verification of approval history against
//! customer-retained evidence (Slice 4).
//!
//! The trust store under `~/.config/maskura/policy/` (override: `--trust-dir`
//! or `MASKURA_POLICY_TRUST_DIR`) is portable and customer-controlled:
//!
//! - `trust.json` — root pins (workspace → root fingerprint + imported COSE
//!   bundle snapshot). **A pin is written only from customer-controlled
//!   input**: `policy trust import <file>` (auto-established from the
//!   customer's own artifact on first import) or `policy trust add`
//!   (manual/strict). A server-fetched bundle can never establish a pin.
//! - `checkpoints/<workspace>/<seq>.json` — retained checkpoints, append-only
//!   by sequence; the highest is the effective head.
//! - `index.json` — imported artifact digests (dedupe/audit).
//!
//! All writes are atomic (temp + rename). This is customer-verifiable
//! approval history — not execution attestation and not witness-verified.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use maskura_pipeline_config::canonical::{is_hex64, sha256_hex};
use maskura_pipeline_config::{
    Checkpoint, Completeness, EvidenceBundle, TrustBundle, TrustPin, TrustState,
    VerificationReport, Verdict, VerifyOptions, verify, verify_artifact,
};
use serde::{Deserialize, Serialize};

/// Trust-store schema version. Unknown versions fail closed.
pub const TRUST_STORE_SCHEMA_VERSION: u32 = 1;

/// Where a pin came from. Only customer-controlled sources can establish one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinSource {
    /// Auto-established from the customer's own imported artifact.
    CustomerImport,
    /// `policy trust add` — manual/strict path.
    Manual,
}

impl PinSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::CustomerImport => "customer-import",
            Self::Manual => "manual",
        }
    }
}

/// One pinned trust root.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinRecord {
    pub workspace_id: String,
    pub root_fingerprint: String,
    /// Imported COSE trust-bundle snapshot (refreshed only on a fingerprint
    /// match).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<TrustBundle>,
    pub source: PinSource,
    pub pinned_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustFile {
    schema_version: u32,
    pins: Vec<PinRecord>,
}

/// One imported artifact record (dedupe/audit).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexEntry {
    pub sha256: String,
    pub kind: String,
    pub workspace_id: String,
    pub head_seq: u64,
    pub imported_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexFile {
    schema_version: u32,
    artifacts: Vec<IndexEntry>,
}

/// Result of a pin write.
#[derive(Debug)]
pub enum PinOutcome {
    Established,
    Unchanged,
    Replaced { archived_checkpoints: Option<PathBuf> },
}

/// The customer-controlled policy trust store.
#[derive(Debug, Clone)]
pub struct TrustStore {
    pub root: PathBuf,
}

impl TrustStore {
    /// Resolution order: explicit `--trust-dir`, `MASKURA_POLICY_TRUST_DIR`,
    /// then `~/.config/maskura/policy`.
    pub fn resolve(explicit: Option<PathBuf>) -> PathBuf {
        if let Some(dir) = explicit {
            return dir;
        }
        if let Ok(dir) = std::env::var("MASKURA_POLICY_TRUST_DIR")
            && !dir.trim().is_empty()
        {
            return PathBuf::from(dir);
        }
        crate::config_dir().join("policy")
    }

    pub fn open(root: PathBuf) -> anyhow::Result<Self> {
        std::fs::create_dir_all(root.join("checkpoints"))
            .with_context(|| format!("cannot create trust store at {}", root.display()))?;
        Ok(Self { root })
    }

    fn trust_path(&self) -> PathBuf {
        self.root.join("trust.json")
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn checkpoints_dir(&self, workspace: &str) -> anyhow::Result<PathBuf> {
        validate_workspace_dir(workspace)?;
        Ok(self.root.join("checkpoints").join(workspace))
    }

    pub fn load_pins(&self) -> anyhow::Result<Vec<PinRecord>> {
        let path = self.trust_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let file: TrustFile = serde_json::from_str(&text)
            .with_context(|| format!("trust file {} is not valid", path.display()))?;
        if file.schema_version != TRUST_STORE_SCHEMA_VERSION {
            bail!(
                "unsupported trust file schema_version {}; expected {TRUST_STORE_SCHEMA_VERSION}",
                file.schema_version
            );
        }
        for pin in &file.pins {
            validate_pin(pin)?;
        }
        Ok(file.pins)
    }

    fn save_pins(&self, pins: &[PinRecord]) -> anyhow::Result<()> {
        let file = TrustFile {
            schema_version: TRUST_STORE_SCHEMA_VERSION,
            pins: pins.to_vec(),
        };
        write_atomically(
            &self.trust_path(),
            serde_json::to_string_pretty(&file)?.as_bytes(),
        )
    }

    pub fn pin_for(&self, workspace: &str) -> anyhow::Result<Option<PinRecord>> {
        Ok(self
            .load_pins()?
            .into_iter()
            .find(|pin| pin.workspace_id == workspace))
    }

    /// Pin write rules: first import establishes; a matching fingerprint is
    /// immutable; a different fingerprint is refused unless `--force` **and**
    /// an explicit confirmation. Force-replacing a pin archives the previous
    /// lineage's retained checkpoints (they stay separately verifiable).
    pub fn write_pin(
        &self,
        record: PinRecord,
        force: bool,
        confirm_yes: bool,
    ) -> anyhow::Result<PinOutcome> {
        validate_pin(&record)?;
        let mut pins = self.load_pins()?;
        if let Some(existing) = pins.iter().find(|pin| pin.workspace_id == record.workspace_id) {
            if existing.root_fingerprint == record.root_fingerprint {
                return Ok(PinOutcome::Unchanged);
            }
            if !force {
                bail!(
                    "refusing to replace the pinned root {} for workspace {:?} with {}; \
                     pass --force (and confirm) to accept the new root explicitly",
                    existing.root_fingerprint,
                    record.workspace_id,
                    record.root_fingerprint
                );
            }
            if !confirm_replacement(&record.workspace_id, confirm_yes)? {
                bail!("pin replacement was not confirmed; nothing changed");
            }
            let archived = self.archive_checkpoints(
                &record.workspace_id,
                &existing.root_fingerprint,
            )?;
            pins.retain(|pin| pin.workspace_id != record.workspace_id);
            pins.push(record);
            self.save_pins(&pins)?;
            return Ok(PinOutcome::Replaced {
                archived_checkpoints: archived,
            });
        }
        pins.push(record);
        self.save_pins(&pins)?;
        Ok(PinOutcome::Established)
    }

    /// Refresh only the snapshot of an existing pin (fingerprint must match).
    pub fn refresh_snapshot(
        &self,
        workspace: &str,
        fingerprint: &str,
        bundle: TrustBundle,
    ) -> anyhow::Result<()> {
        let mut pins = self.load_pins()?;
        let Some(pin) = pins.iter_mut().find(|pin| pin.workspace_id == workspace) else {
            bail!("no local pin for workspace {workspace:?}; nothing refreshed");
        };
        if pin.root_fingerprint != fingerprint {
            bail!(
                "refusing to refresh a snapshot that does not match the pinned root {}",
                pin.root_fingerprint
            );
        }
        pin.bundle = Some(bundle);
        pin.updated_at = now_secs();
        self.save_pins(&pins)
    }

    /// Retained checkpoints for one workspace, ascending by sequence.
    pub fn retained(&self, workspace: &str) -> anyhow::Result<Vec<Checkpoint>> {
        let dir = self.checkpoints_dir(workspace)?;
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut checkpoints = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("cannot read {}", path.display()))?;
            let checkpoint = Checkpoint::from_json(&text)
                .with_context(|| format!("retained checkpoint {} is invalid", path.display()))?;
            checkpoints.push(checkpoint);
        }
        checkpoints.sort_by_key(|checkpoint| checkpoint.receipt_seq);
        Ok(checkpoints)
    }

    /// Append-only by sequence: identical bytes are idempotent, different
    /// bytes at an occupied sequence are refused.
    pub fn retain_checkpoint(&self, checkpoint: &Checkpoint) -> anyhow::Result<bool> {
        checkpoint
            .validate()
            .context("refusing to retain an invalid checkpoint")?;
        validate_workspace_dir(&checkpoint.workspace_id)?;
        let dir = self.root.join("checkpoints").join(&checkpoint.workspace_id);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{}.json", checkpoint.receipt_seq));
        let bytes = serde_json::to_string_pretty(checkpoint)?;
        if path.exists() {
            let existing = std::fs::read_to_string(&path)?;
            if existing == bytes {
                return Ok(false);
            }
            bail!(
                "retained checkpoint at seq {} for workspace {:?} already exists with different \
                 content; checkpoints are append-only by sequence (a trust reset restarts the \
                 sequence — archive the old lineage explicitly)",
                checkpoint.receipt_seq,
                checkpoint.workspace_id
            );
        }
        write_atomically(&path, bytes.as_bytes())?;
        Ok(true)
    }

    /// Record an imported artifact digest (dedupe by digest).
    pub fn record_artifact(&self, entry: &IndexEntry) -> anyhow::Result<()> {
        let path = self.index_path();
        let mut file = if path.exists() {
            let text = std::fs::read_to_string(&path)?;
            let file: IndexFile = serde_json::from_str(&text)
                .with_context(|| format!("index file {} is not valid", path.display()))?;
            if file.schema_version != TRUST_STORE_SCHEMA_VERSION {
                bail!(
                    "unsupported index schema_version {}; expected {TRUST_STORE_SCHEMA_VERSION}",
                    file.schema_version
                );
            }
            file
        } else {
            IndexFile {
                schema_version: TRUST_STORE_SCHEMA_VERSION,
                artifacts: Vec::new(),
            }
        };
        if file.artifacts.iter().any(|item| item.sha256 == entry.sha256) {
            return Ok(());
        }
        file.artifacts.push(entry.clone());
        write_atomically(&path, serde_json::to_string_pretty(&file)?.as_bytes())
    }

    pub fn load_index(&self) -> anyhow::Result<Vec<IndexEntry>> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let text = std::fs::read_to_string(&path)?;
        let file: IndexFile = serde_json::from_str(&text)
            .with_context(|| format!("index file {} is not valid", path.display()))?;
        if file.schema_version != TRUST_STORE_SCHEMA_VERSION {
            bail!(
                "unsupported index schema_version {}; expected {TRUST_STORE_SCHEMA_VERSION}",
                file.schema_version
            );
        }
        Ok(file.artifacts)
    }

    /// Archive a superseded lineage's retained checkpoints (per ADR 0024 the
    /// old chain stays separately verifiable). Returns the archive directory.
    pub fn archive_checkpoints(
        &self,
        workspace: &str,
        fingerprint: &str,
    ) -> anyhow::Result<Option<PathBuf>> {
        let dir = self.checkpoints_dir(workspace)?;
        if !dir.exists() {
            return Ok(None);
        }
        if std::fs::read_dir(&dir)?.next().is_none() {
            return Ok(None);
        }
        let prefix = &fingerprint[..8.min(fingerprint.len())];
        let archive = dir.with_file_name(format!("{workspace}-retired-{prefix}"));
        std::fs::rename(&dir, &archive)
            .with_context(|| format!("cannot archive checkpoints to {}", archive.display()))?;
        std::fs::create_dir_all(&dir)?;
        Ok(Some(archive))
    }
}

fn validate_pin(pin: &PinRecord) -> anyhow::Result<()> {
    if pin.workspace_id.trim().is_empty() {
        bail!("pin workspace must not be empty");
    }
    validate_workspace_dir(&pin.workspace_id)?;
    if !is_hex64(&pin.root_fingerprint) {
        bail!(
            "trust-root fingerprint must be 64 lowercase hex, got {:?}",
            pin.root_fingerprint
        );
    }
    Ok(())
}

fn validate_workspace_dir(workspace: &str) -> anyhow::Result<()> {
    if workspace.trim().is_empty()
        || workspace.contains('/')
        || workspace.contains('\\')
        || workspace.contains("..")
    {
        bail!("workspace id {:?} is not safe for the trust-store layout", workspace);
    }
    Ok(())
}

fn confirm_replacement(workspace: &str, yes: bool) -> anyhow::Result<bool> {
    if yes {
        return Ok(true);
    }
    eprint!(
        "Replace the pinned trust root for workspace {workspace}? This is a recorded \
         discontinuity. Type 'yes' to accept: "
    );
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim() == "yes")
}

fn write_atomically(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let dir = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file");
    let temp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
    std::fs::write(&temp, bytes)
        .with_context(|| format!("cannot write {}", temp.display()))?;
    std::fs::rename(&temp, path).with_context(|| format!("cannot replace {}", path.display()))?;
    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Parse `--at <time>`: unix seconds or RFC3339 UTC (`YYYY-MM-DD[THH:MM:SSZ]`).
pub fn parse_at(value: &str) -> anyhow::Result<u64> {
    let value = value.trim();
    if let Ok(secs) = value.parse::<u64>() {
        return Ok(secs);
    }
    let (date, time) = match value.split_once('T') {
        Some((date, time)) => (date, Some(time)),
        None => (value, None),
    };
    let mut parts = date.split('-');
    let (Some(year), Some(month), Some(day), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        bail!("cannot parse time {value:?}; use unix seconds or RFC3339 UTC");
    };
    let year: i64 = year
        .parse()
        .with_context(|| format!("cannot parse year in {value:?}"))?;
    let month: u32 = month
        .parse()
        .with_context(|| format!("cannot parse month in {value:?}"))?;
    let day: u32 = day
        .parse()
        .with_context(|| format!("cannot parse day in {value:?}"))?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        bail!("cannot parse date in {value:?}");
    }
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400;
    let Some(time) = time else {
        return Ok(seconds.max(0) as u64);
    };
    let time = time.trim_end_matches('Z');
    let mut clock = time.split(':');
    let (Some(hour), Some(minute), Some(second), None) = (
        clock.next(),
        clock.next(),
        clock.next(),
        clock.next(),
    ) else {
        bail!("cannot parse time {value:?}; use unix seconds or RFC3339 UTC");
    };
    let hour: i64 = hour.parse().with_context(|| format!("cannot parse hour in {value:?}"))?;
    let minute: i64 = minute
        .parse()
        .with_context(|| format!("cannot parse minute in {value:?}"))?;
    let second: i64 = second
        .parse()
        .with_context(|| format!("cannot parse second in {value:?}"))?;
    if !(0..24).contains(&hour) || !(0..60).contains(&minute) || !(0..60).contains(&second) {
        bail!("cannot parse clock in {value:?}");
    }
    Ok((seconds + hour * 3_600 + minute * 60 + second).max(0) as u64)
}

/// Days since the Unix epoch for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) as i64 + 2) / 5
        + day as i64
        - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn pin_to_trust_state(pin: &PinRecord) -> TrustPin {
    TrustPin {
        workspace_id: pin.workspace_id.clone(),
        root_fingerprint: pin.root_fingerprint.clone(),
        bundle: pin.bundle.clone(),
    }
}

/// The artifact's carried post-state checkpoints (one for `evidence`, all for
/// `chain`).
fn carried_checkpoints(bundle: &EvidenceBundle) -> Vec<&Checkpoint> {
    verify::chain_checkpoints(bundle)
}

/// The highest carried authority snapshot (the "imported COSE bundle
/// snapshot" of `trust.json`).
fn imported_snapshot(bundle: &EvidenceBundle) -> Option<TrustBundle> {
    carried_checkpoints(bundle)
        .into_iter()
        .max_by_key(|checkpoint| checkpoint.receipt_seq)
        .map(|checkpoint| checkpoint.authorization.clone())
}

fn read_artifact(path: &Path) -> anyhow::Result<(String, EvidenceBundle, IndexEntry)> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    let text = String::from_utf8(bytes.clone())
        .with_context(|| format!("artifact {} is not UTF-8", path.display()))?;
    let bundle = EvidenceBundle::from_json(&text)
        .with_context(|| format!("artifact {} was rejected", path.display()))?;
    let entry = IndexEntry {
        sha256: sha256_hex(&bytes),
        kind: match bundle {
            EvidenceBundle::Evidence(_) => "evidence",
            EvidenceBundle::Chain(_) => "chain",
        }
        .to_string(),
        workspace_id: bundle.workspace_id().to_string(),
        head_seq: verify::evidence_head_seq(&bundle),
        imported_at: now_secs(),
    };
    Ok((text, bundle, entry))
}

fn print_report(report: &VerificationReport) {
    let verdict = match report.verdict {
        Verdict::Verified => "VERIFIED",
        Verdict::Failed => "FAILED",
    };
    println!("Policy approval verification report");
    if let Some(kind) = report.artifact.kind {
        let kind = match kind {
            maskura_pipeline_config::EvidenceKind::Evidence => "evidence",
            maskura_pipeline_config::EvidenceKind::Chain => "chain",
        };
        let workspace = report.artifact.workspace_id.as_deref().unwrap_or("?");
        let head = report
            .artifact
            .head_seq
            .map(|seq| seq.to_string())
            .unwrap_or_else(|| "?".to_string());
        let digest = report
            .artifact
            .head_receipt_sha256
            .as_deref()
            .map(|digest| format!("{}…", &digest[..12.min(digest.len())]))
            .unwrap_or_else(|| "?".to_string());
        println!("  artifact:      {kind}  workspace {workspace}  head seq {head} ({digest})");
    }
    println!(
        "  evaluated at:  {} (skew ±{}s)",
        report.evaluated_at, report.clock_skew_seconds
    );
    println!("  verdict:       {verdict}");
    println!("  completeness:  {}", report.completeness);
    println!("  witness:       {}", witness_status());
    if !report.findings.is_empty() {
        println!();
        println!("Findings:");
        for finding in &report.findings {
            let severity = if finding.fatal { "error" } else { "info" };
            println!("  [{severity}] {:?}: {}", finding.step, finding.message);
        }
    }
    if matches!(report.completeness, Completeness::Unverified { .. }) {
        println!();
        println!(
            "Completeness is UNVERIFIED: without a customer-retained checkpoint this \
             artifact is not linked to your pinned history."
        );
    }
}

/// `maskura policy trust import <file>` — verify the customer's own artifact,
/// then auto-establish the root pin on first import (owner Q2).
pub fn trust_import(
    store: &TrustStore,
    file: &Path,
    force: bool,
    yes: bool,
) -> anyhow::Result<()> {
    let (text, bundle, entry) = read_artifact(file)?;
    let workspace = bundle.workspace_id().to_string();
    let fingerprint = bundle.trust_root_fingerprint().to_string();
    let candidate = PinRecord {
        workspace_id: workspace.clone(),
        root_fingerprint: fingerprint.clone(),
        bundle: imported_snapshot(&bundle),
        source: PinSource::CustomerImport,
        pinned_at: now_secs(),
        updated_at: now_secs(),
    };
    let retained = store.retained(&workspace)?;
    // Verification anchors on the customer's existing pin when one exists.
    // A new root (trust reset) is verified only after explicit acceptance:
    // without --force the facade reports `discontinuity: new root not
    // accepted` and the import is refused; --force verifies against the
    // artifact's own root and then requires confirmation to replace the pin.
    let existing = store.pin_for(&workspace)?;
    let trust_pin = match (&existing, force) {
        (Some(pin), false) => pin_to_trust_state(pin),
        _ => pin_to_trust_state(&candidate),
    };
    let trust_state = TrustState {
        pin: Some(trust_pin),
        retained,
    };
    let report = verify_artifact(&text, &trust_state, &VerifyOptions { at: None });
    print_report(&report);
    if !report.ok() {
        bail!("import refused: the artifact did not verify (see findings above)");
    }
    let outcome = store.write_pin(candidate, force, yes)?;
    let mut retained_now = 0usize;
    for checkpoint in carried_checkpoints(&bundle) {
        if store.retain_checkpoint(checkpoint)? {
            retained_now += 1;
        }
    }
    store.record_artifact(&entry)?;
    println!();
    match outcome {
        PinOutcome::Established => {
            println!(
                "Trust root {fingerprint} pinned for workspace {workspace:?} from your own \
                 artifact (source: customer-import)."
            );
        }
        PinOutcome::Unchanged => {
            println!("Trust root {fingerprint} already pinned for workspace {workspace:?}; pin unchanged.");
        }
        PinOutcome::Replaced {
            archived_checkpoints,
        } => {
            println!(
                "Trust root replaced for workspace {workspace:?} (explicit acceptance). New \
                 root: {fingerprint}."
            );
            if let Some(archive) = archived_checkpoints {
                println!(
                    "Previous lineage's checkpoints archived at {} (they remain separately verifiable).",
                    archive.display()
                );
            }
        }
    }
    println!("Retained {retained_now} new checkpoint(s); run `maskura policy checkpoints` to list.");
    Ok(())
}

/// `maskura policy trust add <fingerprint> --workspace <id>` — manual/strict
/// pin path.
pub fn trust_add(
    store: &TrustStore,
    fingerprint: &str,
    workspace: &str,
    bundle_file: Option<&Path>,
    force: bool,
    yes: bool,
) -> anyhow::Result<()> {
    if !is_hex64(fingerprint) {
        bail!("trust-root fingerprint must be 64 lowercase hex");
    }
    let bundle = match bundle_file {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("cannot read {}", path.display()))?;
            let bundle = TrustBundle::from_json(&text)
                .with_context(|| format!("trust bundle {} was rejected", path.display()))?;
            let digest = bundle.digest()?;
            if digest != fingerprint {
                bail!(
                    "trust bundle digest {digest} does not match the fingerprint {fingerprint}"
                );
            }
            Some(bundle)
        }
        None => None,
    };
    let record = PinRecord {
        workspace_id: workspace.to_string(),
        root_fingerprint: fingerprint.to_string(),
        bundle,
        source: PinSource::Manual,
        pinned_at: now_secs(),
        updated_at: now_secs(),
    };
    match store.write_pin(record, force, yes)? {
        PinOutcome::Established => {
            println!("Trust root {fingerprint} pinned for workspace {workspace:?} (source: manual).");
        }
        PinOutcome::Unchanged => {
            println!("Trust root {fingerprint} already pinned for workspace {workspace:?}; pin unchanged.");
        }
        PinOutcome::Replaced {
            archived_checkpoints,
        } => {
            println!("Trust root replaced for workspace {workspace:?} (explicit acceptance).");
            if let Some(archive) = archived_checkpoints {
                println!(
                    "Previous lineage's checkpoints archived at {} (they remain separately verifiable).",
                    archive.display()
                );
            }
        }
    }
    Ok(())
}

/// `maskura policy trust show`.
pub fn trust_show(store: &TrustStore, workspace: Option<&str>) -> anyhow::Result<()> {
    let pins = store.load_pins()?;
    let pins: Vec<&PinRecord> = pins
        .iter()
        .filter(|pin| workspace.is_none_or(|want| pin.workspace_id == want))
        .collect();
    if pins.is_empty() {
        println!(
            "No pinned trust roots. Import your own artifact with `maskura policy trust import <file>`."
        );
        return Ok(());
    }
    for pin in pins {
        let snapshot = if pin.bundle.is_some() {
            "bundle snapshot retained"
        } else {
            "no bundle snapshot"
        };
        println!(
            "{}  root {}  source {}  {}",
            pin.workspace_id,
            pin.root_fingerprint,
            pin.source.as_str(),
            snapshot
        );
    }
    Ok(())
}

/// `maskura policy trust fetch` — download a served bundle ONLY to compare or
/// refresh one already matching a local pin. A server-fetched bundle never
/// establishes a pin.
pub async fn trust_fetch(
    store: &TrustStore,
    workspace: Option<&str>,
    url: Option<&str>,
    gateway: &str,
) -> anyhow::Result<()> {
    let pins = store.load_pins()?;
    let workspace = match workspace {
        Some(workspace) => workspace.to_string(),
        None if pins.len() == 1 => pins[0].workspace_id.clone(),
        None if pins.is_empty() => {
            bail!(
                "no local pin; a server-fetched bundle can never establish a pin — import your \
                 own artifact with `maskura policy trust import`"
            )
        }
        None => bail!(
            "specify --workspace (the trust store holds {} pins)",
            pins.len()
        ),
    };
    let Some(pin) = pins.into_iter().find(|pin| pin.workspace_id == workspace) else {
        bail!(
            "no local pin for workspace {workspace:?}; a server-fetched bundle can never \
             establish a pin — import your own artifact with `maskura policy trust import`"
        );
    };
    let url = url
        .map(str::to_string)
        .unwrap_or_else(|| format!("{gateway}/dashboard/api/policy/trust-bundle"));
    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("cannot download {url}"))?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        bail!("GET {url}: {status} — {body}");
    }
    let served = TrustBundle::from_json(&body)
        .with_context(|| format!("served bundle from {url} was rejected"))?;
    let digest = served.digest()?;
    if digest == pin.root_fingerprint {
        store.refresh_snapshot(&workspace, &pin.root_fingerprint, served)?;
        println!(
            "Served trust bundle matches pinned root {digest}; the stored snapshot was refreshed."
        );
        Ok(())
    } else {
        println!("Served trust bundle digest: {digest}");
        println!("Pinned trust root:          {}", pin.root_fingerprint);
        println!("Comparison result:          DIFFERENT (nothing updated)");
        bail!(
            "the served bundle does not match the local pin; a server-fetched bundle can only \
             compare or refresh an already matching pin, never establish or replace one"
        );
    }
}

/// `maskura policy verify <file>` — the verification facade.
pub fn policy_verify(
    store: &TrustStore,
    file: &Path,
    at: Option<&str>,
    json: bool,
) -> anyhow::Result<()> {
    let (text, bundle, entry) = read_artifact(file)?;
    let workspace = bundle.workspace_id().to_string();
    let pin = store.pin_for(&workspace)?;
    let trust_state = TrustState {
        pin: pin.as_ref().map(pin_to_trust_state),
        retained: store.retained(&workspace)?,
    };
    let at = at.map(parse_at).transpose()?;
    let report = verify_artifact(&text, &trust_state, &VerifyOptions { at });
    if json {
        println!("{}", report.to_json()?);
    } else {
        print_report(&report);
    }
    if report.ok() {
        let mut retained_now = 0usize;
        for checkpoint in carried_checkpoints(&bundle) {
            if store.retain_checkpoint(checkpoint)? {
                retained_now += 1;
            }
        }
        store.record_artifact(&entry)?;
        if !json && retained_now > 0 {
            println!("Retained {retained_now} new checkpoint(s).");
        }
    }
    if !report.ok() {
        std::process::exit(1);
    }
    Ok(())
}

/// `maskura policy checkpoints` — list retained heads and flag gaps.
pub fn checkpoints(store: &TrustStore, workspace: Option<&str>) -> anyhow::Result<()> {
    let workspaces: Vec<String> = match workspace {
        Some(workspace) => vec![workspace.to_string()],
        None => {
            let dir = store.root.join("checkpoints");
            let mut names = Vec::new();
            if dir.exists() {
                for entry in std::fs::read_dir(&dir)? {
                    let entry = entry?;
                    if entry.path().is_dir()
                        && let Some(name) = entry.file_name().to_str()
                    {
                        names.push(name.to_string());
                    }
                }
            }
            names.sort();
            names
        }
    };
    if workspaces.is_empty() {
        println!("No checkpoints retained yet.");
        return Ok(());
    }
    for workspace in workspaces {
        let retained = store.retained(&workspace)?;
        if retained.is_empty() {
            println!("{workspace}: no checkpoints retained.");
            continue;
        }
        println!("{workspace}:");
        for checkpoint in &retained {
            println!(
                "  seq {:>4}  {}  verified_at {}  envelope v{}",
                checkpoint.receipt_seq,
                short(&checkpoint.receipt_sha256),
                checkpoint.verified_at,
                checkpoint.envelope_version
            );
        }
        let head = retained.last().map(|checkpoint| checkpoint.receipt_seq).unwrap_or(0);
        println!(
            "  head: seq {head} ({} of {} sequence(s) retained)",
            retained.len(),
            head
        );
        let mut gaps = Vec::new();
        for seq in 1..=head {
            if !retained.iter().any(|checkpoint| checkpoint.receipt_seq == seq) {
                gaps.push(seq.to_string());
            }
        }
        if gaps.is_empty() {
            println!("  gaps: none");
        } else {
            println!("  gaps: missing seq {}", gaps.join(", "));
        }
    }
    let imported = store.load_index()?.len();
    println!("imported artifacts: {imported} (see index.json)");
    Ok(())
}

fn short(value: &str) -> String {
    format!("{}…", &value[..12.min(value.len())])
}

/// Kept for claim-copy parity: the witness status is never upgraded while the
/// external witness program is gated.
pub fn witness_status() -> &'static str {
    maskura_pipeline_config::WITNESS_STATUS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store(name: &str) -> TrustStore {
        let root = std::env::temp_dir().join(format!(
            "maskura-policy-store-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        TrustStore::open(root).unwrap()
    }

    fn golden_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("tests")
            .join("fixtures")
            .join("policy")
    }

    fn fixture(name: &str) -> (String, EvidenceBundle) {
        let text = std::fs::read_to_string(golden_dir().join(name)).unwrap();
        let bundle = EvidenceBundle::from_json(&text).unwrap();
        (text, bundle)
    }

    fn fingerprint_of(bundle: &EvidenceBundle) -> String {
        bundle.trust_root_fingerprint().to_string()
    }

    fn pin_record(bundle: &EvidenceBundle) -> PinRecord {
        PinRecord {
            workspace_id: bundle.workspace_id().to_string(),
            root_fingerprint: fingerprint_of(bundle),
            bundle: imported_snapshot(bundle),
            source: PinSource::CustomerImport,
            pinned_at: 10,
            updated_at: 10,
        }
    }

    #[test]
    fn pin_write_is_idempotent_for_the_same_root_and_immutable() {
        let store = temp_store("pin-immutable");
        let (_, evidence) = fixture("evidence_seq1.json");
        let record = pin_record(&evidence);
        assert!(matches!(
            store.write_pin(record.clone(), false, false).unwrap(),
            PinOutcome::Established
        ));
        assert!(matches!(
            store.write_pin(record.clone(), false, false).unwrap(),
            PinOutcome::Unchanged
        ));
        let pins = store.load_pins().unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].root_fingerprint, record.root_fingerprint);
        std::fs::remove_dir_all(&store.root).unwrap();
    }

    #[test]
    fn pin_overwrite_is_refused_without_force() {
        let store = temp_store("pin-refuse");
        let (_, evidence) = fixture("evidence_seq1.json");
        let (_, reset) = fixture("evidence_reset_root.json");
        store.write_pin(pin_record(&evidence), false, false).unwrap();
        let error = store
            .write_pin(pin_record(&reset), false, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("refusing to replace"), "{error}");
        let pins = store.load_pins().unwrap();
        assert_eq!(pins[0].root_fingerprint, fingerprint_of(&evidence));
        std::fs::remove_dir_all(&store.root).unwrap();
    }

    #[test]
    fn pin_replacement_with_force_and_confirmation_archives_checkpoints() {
        let store = temp_store("pin-force");
        let (_, evidence) = fixture("evidence_seq1.json");
        let (_, reset) = fixture("evidence_reset_root.json");
        store.write_pin(pin_record(&evidence), false, false).unwrap();
        let retained = verify::chain_checkpoints(&evidence);
        for checkpoint in &retained {
            store.retain_checkpoint(checkpoint).unwrap();
        }
        let outcome = store.write_pin(pin_record(&reset), true, true).unwrap();
        let PinOutcome::Replaced {
            archived_checkpoints: Some(archive),
        } = outcome
        else {
            panic!("expected replacement with archive");
        };
        assert!(archive.to_string_lossy().contains("retired"));
        assert!(archive.exists());
        assert!(store.retained("ws-1").unwrap().is_empty());
        // The old lineage remains separately verifiable from the archive.
        assert!(std::fs::read_dir(&archive).unwrap().next().is_some());
        std::fs::remove_dir_all(&store.root).unwrap();
    }

    #[test]
    fn checkpoints_are_append_only_by_sequence() {
        let store = temp_store("append-only");
        let (_, evidence) = fixture("evidence_seq1.json");
        let checkpoint = verify::chain_checkpoints(&evidence)[0].clone();
        assert!(store.retain_checkpoint(&checkpoint).unwrap());
        // Identical bytes are idempotent.
        assert!(!store.retain_checkpoint(&checkpoint).unwrap());
        // Different bytes at the same sequence are refused.
        let mut divergent = checkpoint.clone();
        divergent.receipt_sha256 = "a".repeat(64);
        let error = store.retain_checkpoint(&divergent).unwrap_err().to_string();
        assert!(error.contains("append-only"), "{error}");
        std::fs::remove_dir_all(&store.root).unwrap();
    }

    #[test]
    fn index_dedupes_by_artifact_digest() {
        let store = temp_store("index");
        let entry = IndexEntry {
            sha256: "b".repeat(64),
            kind: "evidence".into(),
            workspace_id: "ws-1".into(),
            head_seq: 1,
            imported_at: 10,
        };
        store.record_artifact(&entry).unwrap();
        store.record_artifact(&entry).unwrap();
        assert_eq!(store.load_index().unwrap().len(), 1);
        std::fs::remove_dir_all(&store.root).unwrap();
    }

    #[test]
    fn atomic_writes_leave_no_partial_files() {
        let store = temp_store("atomic");
        let (_, evidence) = fixture("evidence_seq1.json");
        store.write_pin(pin_record(&evidence), false, false).unwrap();
        let entries: Vec<String> = std::fs::read_dir(&store.root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(entries.contains(&"trust.json".to_string()));
        assert!(
            entries.iter().all(|name| !name.contains(".tmp-")),
            "temp files leaked: {entries:?}"
        );
        std::fs::remove_dir_all(&store.root).unwrap();
    }

    #[test]
    fn resolution_prefers_explicit_then_env_then_default() {
        let explicit = PathBuf::from("/explicit/trust");
        assert_eq!(TrustStore::resolve(Some(explicit.clone())), explicit);

        let key = "MASKURA_POLICY_TRUST_DIR";
        let previous = std::env::var(key).ok();
        // SAFETY: this is the only test touching MASKURA_POLICY_TRUST_DIR and
        // it restores the prior value before returning.
        unsafe {
            std::env::set_var(key, "/env/trust");
        }
        assert_eq!(TrustStore::resolve(None), PathBuf::from("/env/trust"));
        unsafe {
            match previous {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        let default = TrustStore::resolve(None);
        assert!(default.ends_with("policy"), "{default:?}");
    }

    #[test]
    fn workspace_dir_names_are_validated() {
        assert!(validate_workspace_dir("../escape").is_err());
        assert!(validate_workspace_dir("a/b").is_err());
        assert!(validate_workspace_dir("").is_err());
        assert!(validate_workspace_dir("ws-1").is_ok());
    }

    #[test]
    fn parse_at_accepts_unix_seconds_and_rfc3339() {
        assert_eq!(parse_at("1500").unwrap(), 1_500);
        assert_eq!(parse_at("1970-01-01").unwrap(), 0);
        assert_eq!(parse_at("1970-01-02T00:00:00Z").unwrap(), 86_400);
        assert_eq!(parse_at("1970-01-01T01:00:30Z").unwrap(), 3_630);
        assert!(parse_at("not-a-time").is_err());
        assert!(parse_at("2026-13-01").is_err());
    }

    #[test]
    fn refresh_snapshot_requires_matching_pin() {
        let store = temp_store("refresh");
        let (_, evidence) = fixture("evidence_seq1.json");
        let (_, reset) = fixture("evidence_reset_root.json");
        store.write_pin(pin_record(&evidence), false, false).unwrap();
        let snapshot = imported_snapshot(&reset).unwrap();
        assert!(
            store
                .refresh_snapshot("ws-1", &fingerprint_of(&reset), snapshot.clone())
                .is_err()
        );
        store
            .refresh_snapshot("ws-1", &fingerprint_of(&evidence), snapshot)
            .unwrap();
        std::fs::remove_dir_all(&store.root).unwrap();
    }
}
