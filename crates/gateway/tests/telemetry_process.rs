//! Process-level proof of the telemetry boundary on the real binary.
//!
//! Starts `maskura-gateway` with export disabled, confirms every response
//! surface carries a server-generated request id, and confirms SIGTERM drains
//! and exits within the documented bounds.

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// OTEL variables that could enable export from the ambient environment.
const OTEL_ENV_VARS: &[&str] = &[
    "OTEL_SERVICE_NAME",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_EXPORTER_OTLP_INSECURE",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_TIMEOUT",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
    "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
    "OTEL_TRACES_EXPORTER",
    "OTEL_LOGS_EXPORTER",
    "OTEL_METRICS_EXPORTER",
];

struct Gateway {
    child: Child,
    _dir: std::path::PathBuf,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self._dir);
    }
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn start_gateway() -> (Gateway, u16) {
    let port = free_port();
    let dir = std::env::temp_dir().join(format!(
        "maskura-telemetry-process-{}-{}",
        std::process::id(),
        port
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("maskura.toml");
    let component = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/pii-default.component.wasm");
    std::fs::write(
        &config,
        format!(
            "[server]\nlisten_addr = \"127.0.0.1:{port}\"\n\n[wasm]\nfilter_component = \"{}\"\n",
            component.display()
        ),
    )
    .unwrap();

    let stderr = std::fs::File::create(dir.join("stderr.log")).unwrap();
    let stdout = std::fs::File::create(dir.join("stdout.log")).unwrap();
    let data_dir = dir.join("data");

    let mut command = Command::new(env!("CARGO_BIN_EXE_maskura-gateway"));
    command
        .arg("--config")
        .arg(&config)
        .env("MASKURA_LOCAL_STORAGE_DIR", &data_dir)
        .env("MASKURA_SINGLE_TENANT", "true")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    for name in OTEL_ENV_VARS {
        command.env_remove(name);
    }

    let child = command.spawn().expect("spawn maskura-gateway");
    (Gateway { child, _dir: dir }, port)
}

fn http_get(port: u16, path: &str) -> Option<(u16, Vec<(String, String)>)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).ok()?;
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            break;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    Some((status, headers))
}

fn request_id(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .find(|(name, _)| name == "x-maskura-request-id")
        .map(|(_, value)| value.clone())
        .unwrap_or_default()
}

fn assert_uuid_v7(headers: &[(String, String)], context: &str) {
    let id = request_id(headers);
    let parsed = uuid::Uuid::parse_str(&id).unwrap_or_else(|_| panic!("{context}: id `{id}`"));
    assert_eq!(parsed.get_version_num(), 7, "{context}: {id}");
}

#[test]
fn gateway_binary_starts_export_disabled_issues_ids_and_drains_on_sigterm() {
    let (_gateway, port) = start_gateway();

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut ready = false;
    while Instant::now() < deadline {
        if let Some((200, headers)) = http_get(port, "/ready") {
            assert_uuid_v7(&headers, "/ready");
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !ready {
        let stderr = std::fs::read_to_string(_gateway._dir.join("stderr.log")).unwrap_or_default();
        let stdout = std::fs::read_to_string(_gateway._dir.join("stdout.log")).unwrap_or_default();
        panic!("gateway did not become ready\nstderr:\n{stderr}\nstdout:\n{stdout}");
    }

    let (status, headers) = http_get(port, "/health").expect("/health response");
    assert_eq!(status, 200);
    assert_uuid_v7(&headers, "/health");

    let (status, headers) = http_get(port, "/definitely-not-a-route").expect("unmatched response");
    assert!(status >= 400, "unmatched route should not succeed");
    assert_uuid_v7(&headers, "unmatched");

    let (status, headers) = http_get(port, "/some-bucket/some-key").expect("s3 response");
    assert!(status >= 400, "unconfigured storage should not succeed");
    assert_uuid_v7(&headers, "s3");

    // SIGTERM must drain and flush within the fixed bounds.
    let pid = _gateway.child.id() as libc::pid_t;
    let started = Instant::now();
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);

    let mut gateway = _gateway;
    let exit_deadline = Instant::now() + Duration::from_secs(45);
    loop {
        match gateway.child.try_wait().expect("wait") {
            Some(_) => break,
            None if Instant::now() >= exit_deadline => {
                panic!("gateway did not exit after SIGTERM")
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    assert!(
        started.elapsed() < Duration::from_secs(45),
        "shutdown exceeded the drain plus flush bound"
    );
}
