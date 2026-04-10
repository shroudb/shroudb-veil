mod config;
mod tcp;

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use shroudb_veil_engine::engine::{VeilConfig, VeilEngine};

use crate::config::load_config;

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

    // Store mode validation
    if cfg.store.mode == "remote" {
        anyhow::bail!(
            "remote store mode not yet implemented (uri: {:?})",
            cfg.store.uri
        );
    }

    // Storage engine
    let storage = shroudb_server_bootstrap::open_storage(&cfg.store.data_dir, key_source.as_ref())
        .await
        .context("failed to open storage engine")?;
    let store = Arc::new(shroudb_storage::EmbeddedStore::new(storage, "veil"));

    // Veil engine
    let veil_config = VeilConfig {
        default_result_limit: cfg.engine.default_result_limit,
        ..Default::default()
    };
    let engine = Arc::new(
        VeilEngine::new(store, veil_config, None, None)
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

    // Banner
    shroudb_server_bootstrap::print_banner(
        "Veil",
        env!("CARGO_PKG_VERSION"),
        &cfg.server.tcp_bind.to_string(),
        &cfg.store.data_dir,
    );

    // Wait for shutdown
    shroudb_server_bootstrap::wait_for_shutdown(shutdown_tx).await?;
    let _ = tcp_handle.await;

    Ok(())
}
