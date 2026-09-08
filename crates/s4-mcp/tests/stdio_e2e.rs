use std::{collections::BTreeMap, ffi::OsString, process::Stdio, sync::Arc};

use maskura_mcp_protocol::tool_definitions;
use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, CallToolResult},
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use s4_gateway::{
    control::NoopControlPlane,
    key_cipher::default_wrapping,
    server::{build_router, build_state},
    workspace_storage::{InMemoryWorkspaceStorageRepository, WorkspaceStorageRepository},
};

struct EnvironmentGuard {
    previous: BTreeMap<&'static str, Option<OsString>>,
}

impl EnvironmentGuard {
    fn apply(values: &[(&'static str, Option<&str>)]) -> Self {
        let previous = values
            .iter()
            .map(|(name, _)| (*name, std::env::var_os(name)))
            .collect();
        for (name, value) in values {
            // This integration test is its own process and is the only test in
            // this binary, so no other thread observes these startup settings.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
        Self { previous }
    }
}

impl Drop for EnvironmentGuard {
    fn drop(&mut self) {
        for (name, value) in &self.previous {
            // See EnvironmentGuard::apply: this test binary owns these values.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

fn arguments(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    value
        .as_object()
        .expect("tool arguments are an object")
        .clone()
}

fn result_text(result: &CallToolResult) -> &str {
    result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|text| text.text.as_str())
        .expect("tool returned text content")
}

#[tokio::test]
async fn stdio_client_round_trips_through_the_real_gateway() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let component = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/components/pii-default.component.wasm");
    assert!(
        component.is_file(),
        "missing {}; run `just build-filters`",
        component.display()
    );
    let keys_file = temporary.path().join("keys.json");
    let _environment = EnvironmentGuard::apply(&[
        ("AUTH_DISABLED", None),
        ("MASKURA_SINGLE_TENANT", Some("true")),
        (
            "MASKURA_FILTER_COMPONENT",
            Some(component.to_str().expect("component path is UTF-8")),
        ),
        (
            "MASKURA_KEYS_FILE",
            Some(keys_file.to_str().expect("keys path is UTF-8")),
        ),
        ("MASKURA_DEV_MEMORY_STREAMING", Some("true")),
        ("MASKURA_STREAMING_READ_MODE", Some("passthrough")),
        ("DATABASE_URL", None),
        ("S3_ENDPOINT", None),
        ("S4_SERVICE_BUCKETS", None),
    ]);

    let workspaces = Arc::new(InMemoryWorkspaceStorageRepository::new());
    let state = build_state(
        Arc::new(NoopControlPlane),
        default_wrapping()?,
        workspaces.clone(),
    )
    .await?;
    let workspace = workspaces.resolve_workspace("mcp-e2e-user").await?;
    let (token, _) = state
        .keys
        .create_mcp_token("mcp-e2e-user", &workspace, "stdio-e2e", 300)
        .await?;

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let gateway_url = format!("http://{}", listener.local_addr()?);
    let gateway = tokio::spawn(async move { axum::serve(listener, app).await });

    let (transport, _) = TokioChildProcess::builder(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_maskura-mcp")).configure(|command| {
            command
                .env("MASKURA_GATEWAY_URL", &gateway_url)
                .env("MASKURA_MCP_TOKEN", &token)
                .env_remove("MASKURA_ACCESS_KEY")
                .env_remove("MASKURA_SECRET_KEY");
        }),
    )
    .stderr(Stdio::null())
    .spawn()?;
    let client = ().serve(transport).await?;

    let mut names = client
        .list_all_tools()
        .await?
        .into_iter()
        .map(|tool| tool.name.into_owned())
        .collect::<Vec<_>>();
    names.sort();
    let mut expected = tool_definitions()
        .into_iter()
        .map(|tool| tool.name)
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(names, expected);

    let put = client
        .call_tool(
            CallToolRequestParams::new("maskura_put_object").with_arguments(arguments(
                serde_json::json!({
                    "bucket": "agent-data",
                    "key": "runs/first.txt",
                    "body": "email alice@example.com",
                    "content_type": "text/plain; charset=utf-8"
                }),
            )),
        )
        .await?;
    assert_eq!(put.is_error, Some(false));
    assert!(result_text(&put).contains("stored agent-data/runs/first.txt"));

    let get = client
        .call_tool(
            CallToolRequestParams::new("maskura_get_object").with_arguments(arguments(
                serde_json::json!({
                    "bucket": "agent-data",
                    "key": "runs/first.txt"
                }),
            )),
        )
        .await?;
    assert_eq!(get.is_error, Some(false));
    assert_eq!(result_text(&get), "email [REDACTED_EMAIL]");

    let list = client
        .call_tool(
            CallToolRequestParams::new("maskura_list_objects").with_arguments(arguments(
                serde_json::json!({
                    "bucket": "agent-data",
                    "prefix": "runs/",
                    "max_keys": 1
                }),
            )),
        )
        .await?;
    assert_eq!(list.is_error, Some(false));
    assert_eq!(result_text(&list), "runs/first.txt");

    let delete = client
        .call_tool(
            CallToolRequestParams::new("maskura_delete_object").with_arguments(arguments(
                serde_json::json!({
                    "bucket": "agent-data",
                    "key": "runs/first.txt"
                }),
            )),
        )
        .await?;
    assert_eq!(delete.is_error, Some(false));
    assert!(result_text(&delete).contains("deleted agent-data/runs/first.txt"));

    let missing = client
        .call_tool(
            CallToolRequestParams::new("maskura_get_object").with_arguments(arguments(
                serde_json::json!({
                    "bucket": "agent-data",
                    "key": "runs/first.txt"
                }),
            )),
        )
        .await?;
    assert_eq!(missing.is_error, Some(true));
    assert!(result_text(&missing).contains("NoSuchKey"));

    client.cancel().await?;
    gateway.abort();
    let _ = gateway.await;

    // Exercise the exact local-init contract documented for desktop clients:
    // an auth-disabled loopback gateway plus an explicit placeholder key pair.
    unsafe {
        std::env::set_var("AUTH_DISABLED", "true");
    }
    let local_workspaces = Arc::new(InMemoryWorkspaceStorageRepository::new());
    let local_state = build_state(
        Arc::new(NoopControlPlane),
        default_wrapping()?,
        local_workspaces,
    )
    .await?;
    let local_app = build_router(local_state);
    let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let local_gateway_url = format!("http://{}", local_listener.local_addr()?);
    let local_gateway = tokio::spawn(async move { axum::serve(local_listener, local_app).await });

    let example =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/mcp-client.py");
    let output = tokio::process::Command::new("python3")
        .arg(example)
        .env("MASKURA_GATEWAY_URL", &local_gateway_url)
        .env_remove("MASKURA_MCP_TOKEN")
        .env("MASKURA_ACCESS_KEY", "local")
        .env("MASKURA_SECRET_KEY", "local")
        .env("MASKURA_MCP_COMMAND", env!("CARGO_BIN_EXE_maskura-mcp"))
        .env("MCP_EXAMPLE_RUN_MUTATIONS", "1")
        .env("MCP_EXAMPLE_BUCKET", "agent-data")
        .env("MCP_EXAMPLE_KEY", "examples/python-client.txt")
        .output()
        .await?;
    assert!(
        output.status.success(),
        "example failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert!(
        stdout.contains("Connected to maskura-mcp"),
        "unexpected stdout: {stdout}"
    );
    assert!(
        stdout.contains("Read: Contact [REDACTED_EMAIL]"),
        "unexpected stdout: {stdout}"
    );
    assert!(
        stdout.contains("List: examples/python-client.txt"),
        "unexpected stdout: {stdout}"
    );
    assert!(
        stdout.contains("Deleted agent-data/examples/python-client.txt"),
        "unexpected stdout: {stdout}"
    );

    local_gateway.abort();
    Ok(())
}
