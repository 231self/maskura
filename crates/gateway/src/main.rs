use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use maskura_customer_config::Config;
use maskura_gateway::control::NoopControlPlane;
use maskura_gateway::key_cipher::default_wrapping;
use maskura_gateway::server::{build_router, build_state, default_listen_addr};
use maskura_gateway::workspace_storage::InMemoryWorkspaceStorageRepository;
use tracing::info;

fn parse_args(args: impl IntoIterator<Item = String>) -> anyhow::Result<(Option<PathBuf>, bool)> {
    let mut args = args.into_iter();
    let mut config = None;
    let mut healthcheck = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" if config.is_none() => {
                let path = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("`--config` requires a path argument"))?;
                config = Some(PathBuf::from(path));
            }
            "--healthcheck" if !healthcheck => healthcheck = true,
            "--config" => anyhow::bail!("`--config` may be specified only once"),
            "--healthcheck" => anyhow::bail!("`--healthcheck` may be specified only once"),
            other => anyhow::bail!(
                "unexpected argument `{other}` (expected `--config <path>` or `--healthcheck`)"
            ),
        }
    }
    Ok((config, healthcheck))
}

fn config_path_from_process_cmdline(cmdline: &[u8]) -> Option<PathBuf> {
    let mut parts = cmdline
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty());
    let executable = std::path::Path::new(std::str::from_utf8(parts.next()?).ok()?);
    if executable.file_name()?.to_str()? != "maskura-gateway" {
        return None;
    }
    let args = parts.map(|arg| String::from_utf8_lossy(arg).into_owned());
    parse_args(args).ok().and_then(|(path, _)| path)
}

fn container_process_config_path() -> Option<PathBuf> {
    let mut pids: Vec<u32> = std::fs::read_dir("/proc")
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
        .collect();
    pids.sort_unstable();
    pids.into_iter()
        .filter(|pid| *pid != std::process::id())
        .find_map(|pid| {
            std::fs::read(format!("/proc/{pid}/cmdline"))
                .ok()
                .and_then(|cmdline| config_path_from_process_cmdline(&cmdline))
        })
}

/// Resolve the config file with documented discovery: `--config <path>`,
/// then `MASKURA_CONFIG`, then `./maskura.toml` when present, else env + defaults.
fn resolve_config(explicit: Option<PathBuf>) -> anyhow::Result<Config> {
    let explicit = explicit.or_else(|| std::env::var("MASKURA_CONFIG").ok().map(PathBuf::from));
    match explicit {
        Some(path) => Ok(Config::resolve(Some(&path))?),
        None => {
            let default = PathBuf::from("maskura.toml");
            if default.exists() {
                Ok(Config::resolve(Some(&default))?)
            } else {
                Ok(Config::resolve(None)?)
            }
        }
    }
}

fn configured_listen_addr(config: &Config) -> anyhow::Result<SocketAddr> {
    config
        .server
        .listen_addr
        .as_deref()
        .unwrap_or_else(|| default_listen_addr(config))
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid listen address: {error}"))
}

fn healthcheck_addr(mut addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        addr.set_ip(match addr.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        });
    }
    addr
}

async fn run_healthcheck(config: &Config) -> anyhow::Result<()> {
    let addr = healthcheck_addr(configured_listen_addr(config)?);
    reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?
        .get(format!("http://{addr}/ready"))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let (mut config_path, healthcheck) = parse_args(std::env::args().skip(1))?;
    if healthcheck && config_path.is_none() {
        config_path = container_process_config_path();
    }
    let config = resolve_config(config_path)?;
    if healthcheck {
        return run_healthcheck(&config).await;
    }
    let listen_addr = configured_listen_addr(&config)?;

    // OSS self-host: no policy. Authorization/metering is a no-op.
    let state = build_state(
        Arc::new(NoopControlPlane),
        default_wrapping()?,
        Arc::new(InMemoryWorkspaceStorageRepository::new()),
        &config,
    )
    .await?;
    let app = build_router(state);

    info!("Maskura Gateway listening on {listen_addr} (OSS, no control plane)");

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_healthcheck_and_config_in_either_order() {
        let (path, healthcheck) = parse_args([
            "--healthcheck".to_string(),
            "--config".to_string(),
            "/tmp/maskura.toml".to_string(),
        ])
        .unwrap();
        assert_eq!(path, Some(PathBuf::from("/tmp/maskura.toml")));
        assert!(healthcheck);
    }

    #[test]
    fn healthcheck_can_reuse_the_container_process_config_path() {
        assert_eq!(
            config_path_from_process_cmdline(
                b"maskura-gateway\0--config\0/etc/maskura/custom.toml\0"
            ),
            Some(PathBuf::from("/etc/maskura/custom.toml"))
        );
        assert_eq!(config_path_from_process_cmdline(b"maskura-gateway\0"), None);
        assert_eq!(
            config_path_from_process_cmdline(
                b"/usr/bin/docker-init\0--config\0/etc/maskura/wrong.toml\0"
            ),
            None
        );
    }

    #[test]
    fn healthcheck_uses_loopback_for_unspecified_listeners() {
        assert_eq!(
            healthcheck_addr("0.0.0.0:9123".parse().unwrap()),
            "127.0.0.1:9123".parse().unwrap()
        );
        assert_eq!(
            healthcheck_addr("[::]:9123".parse().unwrap()),
            "[::1]:9123".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn healthcheck_uses_the_resolved_custom_listen_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().route("/ready", axum::routing::get(|| async { "ready" }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let mut config = Config::default();
        config.server.listen_addr = Some(addr.to_string());
        run_healthcheck(&config).await.unwrap();
        server.abort();
    }
}
