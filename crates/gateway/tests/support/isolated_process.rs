//! Test-only self-reexecution with an empty environment and private scratch.
//! Captured child output is bounded and is never forwarded to the caller.
//! CI must impose an outer job timeout: a native callback that hangs cannot be
//! preempted by this helper or by an async timeout.

use std::ffi::OsString;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

const CHILD_MARKER: &str = "MASKURA_FINAL_VALIDATION_TEST_CHILD";
const CAPTURE_LIMIT: usize = 16 * 1024;

pub(crate) struct Captured {
    pub(crate) bytes: Vec<u8>,
    pub(crate) truncated: bool,
}

pub(crate) struct Outcome {
    status: ExitStatus,
    pub(crate) stdout: Captured,
    pub(crate) stderr: Captured,
}

impl Outcome {
    pub(crate) fn assert_success(&self) {
        // Do not forward child output or dynamic OS error details. All child
        // diagnostics are captured to a fixed bound and otherwise discarded.
        let ran_one_test = self
            .stdout
            .bytes
            .split(|byte| *byte == b'\n')
            .any(|line| line == b"running 1 test");
        assert!(
            self.status.success()
                && ran_one_test
                && !self.stdout.truncated
                && !self.stderr.truncated
                && self.stdout.bytes.len() <= CAPTURE_LIMIT
                && self.stderr.bytes.len() <= CAPTURE_LIMIT,
            "isolated synthetic test failed or exceeded its diagnostic bound"
        );
    }
}

fn private_dir(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn capture_and_drain(mut input: impl Read) -> io::Result<Captured> {
    let mut bytes = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 4096];
    loop {
        let count = match input.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let retained = count.min(CAPTURE_LIMIT.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&buffer[..retained]);
        truncated |= retained != count;
    }
    Ok(Captured { bytes, truncated })
}

fn component_metadata() -> Option<(OsString, OsString)> {
    let component = std::env::var_os("MASKURA_TEST_VALIDATION_COMPONENT")?;
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .expect("test component override needs an explicit target directory");
    let target_path = PathBuf::from(&target);
    let expected = PathBuf::from(&component);
    let name = expected
        .file_name()
        .and_then(|name| name.to_str())
        .expect("invalid fixture name");
    assert!(
        name.starts_with("validation-test-transformer-")
            && name.ends_with(".component.wasm")
            && expected.parent() == Some(target_path.join("test-components").as_path()),
        "invalid test component override"
    );
    let target_real =
        std::fs::canonicalize(&target_path).expect("test target directory unavailable");
    let component_dir = std::fs::canonicalize(target_path.join("test-components"))
        .expect("test component directory unavailable");
    assert!(
        component_dir.starts_with(target_real),
        "test component directory escapes target"
    );
    let metadata = std::fs::symlink_metadata(&expected).expect("test component unavailable");
    assert!(
        metadata.file_type().is_file(),
        "test component must be a regular file"
    );
    Some((component, target))
}

/// Return `None` only in the exact isolated child. In the original test process
/// return a bounded result from a freshly spawned child. The caller must invoke
/// this at the first line of each real-router scenario, before building state.
pub(crate) fn dispatch(scenario: &'static str, include_component: bool) -> Option<Outcome> {
    if let Some(marker) = std::env::var_os(CHILD_MARKER) {
        assert!(
            marker == scenario,
            "unexpected isolated synthetic test marker"
        );
        verify_child_home();
        return None;
    }

    let id = uuid::Uuid::new_v4();
    let temporary = std::env::temp_dir().join(format!("maskura-final-validation-run-{id}"));
    private_dir(&temporary).expect("cannot create isolated synthetic test directory");
    let home = temporary.join(format!("maskura-final-validation-home-{id}"));
    private_dir(&home).expect("cannot create isolated synthetic test home");

    let mut command = Command::new(std::env::current_exe().expect("test executable unavailable"));
    command
        .env_clear()
        .env(CHILD_MARKER, scenario)
        .env("TMPDIR", &temporary)
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .current_dir(&temporary)
        .arg("--exact")
        .arg(scenario)
        .arg("--nocapture")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    command.env("TMP", &temporary).env("TEMP", &temporary);
    if include_component && let Some((component, target)) = component_metadata() {
        command
            .env("MASKURA_TEST_VALIDATION_COMPONENT", component)
            .env("CARGO_TARGET_DIR", target);
    }
    let mut child = command
        .spawn()
        .expect("cannot start isolated synthetic test");
    let stdout = child.stdout.take().expect("test stdout unavailable");
    let stderr = child.stderr.take().expect("test stderr unavailable");
    let stdout = std::thread::spawn(move || capture_and_drain(stdout));
    let stderr = std::thread::spawn(move || capture_and_drain(stderr));
    let status = child
        .wait()
        .expect("isolated synthetic test did not finish");
    let stdout = stdout
        .join()
        .expect("test stdout capture failed")
        .expect("test stdout read failed");
    let stderr = stderr
        .join()
        .expect("test stderr capture failed")
        .expect("test stderr read failed");
    Some(Outcome {
        status,
        stdout,
        stderr,
    })
}

#[cfg(unix)]
fn verify_child_home() {
    use std::os::unix::fs::MetadataExt as _;
    let tmp = std::fs::canonicalize(std::env::var_os("TMPDIR").expect("missing isolated TMPDIR"))
        .expect("isolated TMPDIR unavailable");
    let home = std::fs::canonicalize(std::env::var_os("HOME").expect("missing isolated HOME"))
        .expect("isolated HOME unavailable");
    let name = home
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    assert!(
        home.parent() == Some(tmp.as_path()) && name.starts_with("maskura-final-validation-home-"),
        "invalid isolated home"
    );
    // SAFETY: geteuid has no preconditions and does not read the environment.
    let uid = unsafe { libc::geteuid() };
    for path in [&tmp, &home] {
        let metadata = std::fs::metadata(path).expect("isolated directory unavailable");
        assert!(
            metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o077 == 0,
            "isolated directories must be private and owned"
        );
    }
}

#[cfg(not(unix))]
fn verify_child_home() {
    panic!("isolated synthetic tests require a Unix platform");
}
