//! ShrouDB Veil — encrypted search service.
//!
//! Supports two modes:
//! - **Embedded** (default): runs Transit's engine in-process. No external server needed.
//! - **Remote**: proxies cryptographic operations to an external Transit server over TCP.
//!
//! Mode is determined by configuration: if `[transit]` has `addr`, remote mode is used.
//! If the `embedded` feature is enabled (default) and no remote addr is configured,
//! embedded mode is used.

mod config;
mod connection;
mod server;

use std::sync::Arc;

use clap::Parser;
use shroudb_veil_protocol::TransitBackend;
use shroudb_veil_protocol::search_engine::SearchConfig;
use tracing_subscriber::Layer as _;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser)]
#[command(
    name = "shroudb-veil",
    about = "Encrypted search over E2EE data",
    version
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, default_value = "veil.toml")]
    config: std::path::PathBuf,

    /// Transit server address (overrides config file, forces remote mode).
    #[arg(long)]
    transit: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Disable core dumps to prevent leaking decrypted plaintext (Linux only).
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }

    let cli = Cli::parse();

    let cfg = match config::load(&cli.config)? {
        Some(mut cfg) => {
            if let Some(ref addr) = cli.transit {
                cfg.transit.addr = Some(addr.clone());
            }
            init_logging()?;
            tracing::info!(config = %cli.config.display(), "configuration loaded");
            cfg
        }
        None => {
            init_logging()?;
            let mut cfg = config::VeilConfig::default();
            if let Some(ref addr) = cli.transit {
                cfg.transit.addr = Some(addr.clone());
            }
            tracing::info!("no config file found, starting with defaults");
            cfg
        }
    };

    let search_config = SearchConfig {
        max_batch_size: cfg.search.max_batch_size,
        default_result_limit: cfg.search.default_result_limit,
        decrypt_batch_size: cfg.search.decrypt_batch_size,
    };

    // Install Prometheus metrics recorder.
    let metrics_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install metrics recorder");

    // Shutdown signal (SIGTERM + SIGINT).
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    // Decide mode and run.
    if let Some(ref addr) = cfg.transit.addr {
        run_remote(&cfg, addr, search_config, metrics_handle, shutdown_rx).await
    } else {
        run_embedded(&cfg, search_config, metrics_handle, shutdown_rx).await
    }
}

/// Run in remote mode — proxy to external Transit server.
async fn run_remote(
    cfg: &config::VeilConfig,
    addr: &str,
    search_config: SearchConfig,
    metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    use shroudb_veil_protocol::remote::{RemoteTransit, RemoteTransitConfig};

    let remote_config = RemoteTransitConfig {
        addr: addr.to_string(),
        tls: cfg.transit.tls,
        auth_token: cfg.transit.token.clone(),
        pool_size: cfg.transit.pool_size,
    };

    let backend = Arc::new(RemoteTransit::new(remote_config));

    // Verify connectivity.
    tracing::info!(transit = %addr, mode = "remote", "connecting to Transit");
    let health = backend
        .health()
        .await
        .map_err(|e| anyhow::anyhow!("cannot reach Transit at {addr}: {e}"))?;
    tracing::info!(transit_state = %health.state, "Transit connection verified");

    let dispatcher = Arc::new(shroudb_veil_protocol::CommandDispatcher::new(
        backend,
        search_config,
    ));

    tracing::info!(bind = %cfg.server.bind, transit = %addr, mode = "remote", "shroudb-veil ready");
    server::run(&cfg.server, dispatcher, metrics_handle, shutdown_rx).await?;

    tracing::info!("shroudb-veil shut down cleanly");
    Ok(())
}

/// Run in embedded mode — Transit engine in-process.
#[cfg(feature = "embedded")]
async fn run_embedded(
    cfg: &config::VeilConfig,
    search_config: SearchConfig,
    metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    use shroudb_veil_protocol::embedded::EmbeddedTransit;

    tracing::info!(mode = "embedded", "initializing embedded Transit engine");

    let (dispatcher_arc, _engine) = config::build_embedded_transit(cfg)?;
    let backend = Arc::new(EmbeddedTransit::new(dispatcher_arc));

    let health = backend
        .health()
        .await
        .map_err(|e| anyhow::anyhow!("embedded Transit health check failed: {e}"))?;
    tracing::info!(transit_state = %health.state, "embedded Transit ready");

    let dispatcher = Arc::new(shroudb_veil_protocol::CommandDispatcher::new(
        backend,
        search_config,
    ));

    tracing::info!(bind = %cfg.server.bind, mode = "embedded", "shroudb-veil ready");
    server::run(&cfg.server, dispatcher, metrics_handle, shutdown_rx).await?;

    tracing::info!("shroudb-veil shut down cleanly");
    Ok(())
}

#[cfg(not(feature = "embedded"))]
async fn run_embedded(
    _cfg: &config::VeilConfig,
    _search_config: SearchConfig,
    _metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
    _shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    anyhow::bail!(
        "no [transit] addr configured and the `embedded` feature is disabled. \
         Either set transit.addr in the config or build with --features embedded"
    )
}

fn init_logging() -> anyhow::Result<()> {
    use tracing_subscriber::filter::Targets;

    let env_filter = resolve_log_filter();
    let console_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_filter(env_filter);

    let audit_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_filter(Targets::new().with_target("veil::audit", tracing::Level::INFO));

    tracing_subscriber::registry()
        .with(console_layer)
        .with(audit_layer)
        .init();

    Ok(())
}

fn resolve_log_filter() -> tracing_subscriber::EnvFilter {
    if let Ok(level) = std::env::var("LOG_LEVEL") {
        return tracing_subscriber::EnvFilter::new(level);
    }
    tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
}

async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to listen for ctrl+c");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
