mod config;
mod http;
mod tcp;

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use shroudb_store::Store;
use shroudb_veil_engine::engine::{VeilConfig, VeilEngine};

use crate::config::{VeilServerConfig, load_config};

#[derive(Parser)]
#[command(name = "shroudb-veil", about = "Veil blind index engine")]
struct Cli {
    /// Path to config file.
    #[arg(short, long, env = "VEIL_CONFIG")]
    config: Option<String>,

    /// Data directory (overrides config).
    #[arg(long, env = "VEIL_DATA_DIR")]
    data_dir: Option<String>,

    /// TCP bind address (overrides config).
    #[arg(long, env = "VEIL_TCP_BIND")]
    tcp_bind: Option<String>,

    /// HTTP bind address (overrides config).
    #[arg(long, env = "VEIL_HTTP_BIND")]
    http_bind: Option<String>,

    /// Log level.
    #[arg(long, env = "VEIL_LOG_LEVEL", default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load config
    let mut cfg = load_config(cli.config.as_deref())?;

    // Resolve log level
    let log_level = if cli.log_level != "info" {
        cli.log_level.clone()
    } else {
        cfg.server
            .log_level
            .take()
            .unwrap_or_else(|| "info".to_string())
    };

    // Bootstrap: logging + core dumps + key source
    let key_source = shroudb_server_bootstrap::bootstrap(&log_level);

    // CLI overrides
    if let Some(ref dir) = cli.data_dir {
        cfg.store.data_dir = dir.into();
    }
    if let Some(ref bind) = cli.tcp_bind {
        cfg.server.tcp_bind = bind.parse().context("invalid TCP bind address")?;
    }
    if let Some(ref bind) = cli.http_bind {
        cfg.server.http_bind = Some(bind.clone());
    }

    // Store: embedded or remote
    match cfg.store.mode.as_str() {
        "embedded" => {
            let storage =
                shroudb_server_bootstrap::open_storage(&cfg.store.data_dir, key_source.as_ref())
                    .await
                    .context("failed to open storage engine")?;
            let store = Arc::new(shroudb_storage::EmbeddedStore::new(storage.clone(), "veil"));
            run_server(cfg, store, Some(storage)).await
        }
        "remote" => {
            let uri = cfg
                .store
                .uri
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("remote mode requires store.uri"))?;
            tracing::info!(uri, "connecting to remote store");
            let store = Arc::new(
                shroudb_client::RemoteStore::connect(uri)
                    .await
                    .context("failed to connect to remote store")?,
            );
            run_server(cfg, store, None).await
        }
        other => anyhow::bail!("unknown store mode: {other}"),
    }
}

async fn run_server<S: Store + 'static>(
    cfg: VeilServerConfig,
    store: Arc<S>,
    storage: Option<Arc<shroudb_storage::StorageEngine>>,
) -> anyhow::Result<()> {
    // Resolve [audit] and [policy] capabilities. Omitted sections default to
    // embedded Chronicle/Sentry on the shared storage (see
    // shroudb-engine-bootstrap 0.3.0). Operators that want to refuse start-up
    // unless these resolve to `Enabled` set `engine.require_audit = true` /
    // `engine.require_policy = true` and pass the knob into `VeilConfig` —
    // that engine-level enforcement composes with the bootstrap default.
    let audit_cfg = cfg.audit.clone().unwrap_or_default();
    let audit_cap = audit_cfg
        .resolve(storage.clone())
        .await
        .context("failed to resolve [audit] capability")?;
    let policy_cfg = cfg.policy.clone().unwrap_or_default();
    let policy_cap = policy_cfg
        .resolve(storage.clone(), audit_cap.as_ref().cloned())
        .await
        .context("failed to resolve [policy] capability")?;

    // Veil engine
    let veil_config = VeilConfig {
        default_result_limit: cfg.engine.default_result_limit,
        require_audit: cfg.engine.require_audit,
        require_policy: cfg.engine.require_policy,
        prefix_threshold: cfg.engine.prefix_threshold,
        fuzzy_threshold: cfg.engine.fuzzy_threshold,
        ..Default::default()
    };
    let engine = Arc::new(
        VeilEngine::new(store, veil_config, policy_cap, audit_cap)
            .await
            .context("failed to initialize veil engine")?,
    );

    // Seed indexes from config
    for name in &cfg.engine.indexes {
        engine
            .index_manager()
            .seed_if_absent(name)
            .await
            .with_context(|| format!("failed to seed index '{name}'"))?;
    }

    // Shutdown signal
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Auth
    let token_validator = cfg.auth.build_validator();
    if token_validator.is_some() {
        tracing::info!(tokens = cfg.auth.tokens.len(), "token-based auth enabled");
    }

    // Audit-on requires an authenticated actor at the engine layer.
    // Refuse to start with [audit] enabled but [auth].tokens empty.
    audit_cfg
        .require_auth_validator(token_validator.is_some())
        .context("invalid [audit] / [auth] composition")?;

    // TCP server
    let tcp_listener = tokio::net::TcpListener::bind(cfg.server.tcp_bind)
        .await
        .context("failed to bind TCP")?;

    let tls_acceptor = cfg
        .server
        .tls
        .as_ref()
        .map(shroudb_server_tcp::build_tls_acceptor)
        .transpose()
        .context("failed to build TLS acceptor")?;

    let tcp_engine = engine.clone();
    let tcp_validator = token_validator.clone();
    let tcp_shutdown = shutdown_rx.clone();
    let tcp_handle = tokio::spawn(async move {
        tcp::run_tcp(
            tcp_listener,
            tcp_engine,
            tcp_validator,
            tcp_shutdown,
            tls_acceptor,
        )
        .await;
    });

    // HTTP server (optional)
    let http_handle = if let Some(ref http_bind) = cfg.server.http_bind {
        let http_listener = tokio::net::TcpListener::bind(http_bind)
            .await
            .context("failed to bind HTTP listener")?;
        let http_router = http::router(engine.clone(), token_validator);
        Some(tokio::spawn(async move {
            axum::serve(http_listener, http_router)
                .await
                .unwrap_or_else(|e| tracing::error!(error = %e, "HTTP server error"));
        }))
    } else {
        None
    };

    // Banner
    shroudb_server_bootstrap::print_banner(
        "Veil",
        env!("CARGO_PKG_VERSION"),
        &cfg.server.tcp_bind.to_string(),
        &cfg.store.data_dir,
    );
    if let Some(ref http_bind) = cfg.server.http_bind {
        eprintln!("\u{251c}\u{2500} http:    {http_bind}");
    }

    // Wait for shutdown
    shroudb_server_bootstrap::wait_for_shutdown(shutdown_tx).await?;
    let _ = tcp_handle.await;
    if let Some(h) = http_handle {
        h.abort();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_debug_asserts() {
        Cli::command().debug_assert();
    }

    #[test]
    fn cli_accepts_config_flag() {
        let parsed = Cli::try_parse_from(["shroudb-veil", "--config", "veil.toml"]).unwrap();
        assert_eq!(parsed.config.as_deref(), Some("veil.toml"));
    }
}
