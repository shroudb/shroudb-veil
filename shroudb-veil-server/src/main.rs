mod config;
mod tcp;

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use shroudb_storage::{
    ChainedMasterKeySource, EnvMasterKey, FileMasterKey, MasterKeySource, StorageEngineConfig,
};
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

    // Logging
    let log_level = if cli.log_level != "info" {
        cli.log_level.clone()
    } else {
        cfg.server
            .log_level
            .take()
            .unwrap_or_else(|| "info".to_string())
    };
    let filter = tracing_subscriber::EnvFilter::try_new(&log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();

    // Disable core dumps — sensitive key material must not leak to disk.
    disable_core_dumps();

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

    // Master key
    let key_source: Box<dyn MasterKeySource> = Box::new(ChainedMasterKeySource::new(vec![
        Box::new(EnvMasterKey::new()),
        Box::new(FileMasterKey::new()),
        Box::new(EphemeralKey),
    ]));

    // Storage engine
    let engine_config = StorageEngineConfig {
        data_dir: cfg.store.data_dir.clone(),
        ..Default::default()
    };
    let storage_engine = shroudb_storage::StorageEngine::open(engine_config, key_source.as_ref())
        .await
        .context("failed to open storage engine")?;
    let store = Arc::new(shroudb_storage::EmbeddedStore::new(
        Arc::new(storage_engine),
        "veil",
    ));

    // Veil engine
    let veil_config = VeilConfig {
        default_result_limit: cfg.engine.default_result_limit,
    };
    let engine = Arc::new(
        VeilEngine::new(store, veil_config)
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
    let token_validator = config::build_token_validator(&cfg.auth);
    if token_validator.is_some() {
        tracing::info!(tokens = cfg.auth.tokens.len(), "token-based auth enabled");
    }

    // TCP server
    let tcp_listener = tokio::net::TcpListener::bind(cfg.server.tcp_bind)
        .await
        .context("failed to bind TCP")?;

    let tcp_engine = engine.clone();
    let tcp_validator = token_validator.clone();
    let tcp_shutdown = shutdown_rx.clone();
    let tcp_handle = tokio::spawn(async move {
        tcp::run_tcp(tcp_listener, tcp_engine, tcp_validator, tcp_shutdown).await;
    });

    // Banner
    eprintln!();
    eprintln!("Veil v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("├─ tcp:     {}", cfg.server.tcp_bind);
    eprintln!("├─ data:    {}", cfg.store.data_dir.display());
    eprintln!(
        "└─ key:     {}",
        if std::env::var("SHROUDB_MASTER_KEY").is_ok()
            || std::env::var("SHROUDB_MASTER_KEY_FILE").is_ok()
        {
            "configured"
        } else {
            "ephemeral (dev mode)"
        }
    );
    eprintln!();
    eprintln!("Ready.");

    // Wait for shutdown
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for ctrl-c")?;
    tracing::info!("shutting down");
    let _ = shutdown_tx.send(true);
    let _ = tcp_handle.await;

    Ok(())
}

/// Disable core dumps so sensitive key material cannot leak to disk.
fn disable_core_dumps() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
            tracing::warn!("failed to disable core dumps via prctl");
        }
    }

    #[cfg(target_os = "macos")]
    {
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } != 0 {
            tracing::warn!("failed to disable core dumps via setrlimit");
        }
    }
}

/// Ephemeral master key for dev mode (data won't survive restarts).
struct EphemeralKey;

impl MasterKeySource for EphemeralKey {
    fn source_name(&self) -> &str {
        "ephemeral"
    }

    fn load<'a>(
        &'a self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<shroudb_crypto::SecretBytes, shroudb_storage::StorageError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async {
            tracing::warn!("using ephemeral master key — data will not survive restart");
            let key = ring::rand::SystemRandom::new();
            let mut bytes = vec![0u8; 32];
            ring::rand::SecureRandom::fill(&key, &mut bytes)
                .map_err(|_| shroudb_storage::StorageError::Internal("RNG failed".into()))?;
            Ok(shroudb_crypto::SecretBytes::new(bytes))
        })
    }
}
