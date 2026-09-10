use std::sync::Arc;

use maskura_gateway::control::NoopControlPlane;
use maskura_gateway::key_cipher::default_wrapping;
use maskura_gateway::server::{build_router, build_state};
use maskura_gateway::workspace_storage::InMemoryWorkspaceStorageRepository;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    // OSS self-host: no policy. Authorization/metering is a no-op.
    let state = build_state(
        Arc::new(NoopControlPlane),
        default_wrapping()?,
        Arc::new(InMemoryWorkspaceStorageRepository::new()),
    )
    .await?;
    let app = build_router(state);

    info!("Maskura Gateway listening on {listen_addr} (OSS, no control plane)");
    info!("Dashboard: http://localhost:8080");

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
