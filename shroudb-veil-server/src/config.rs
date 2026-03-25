use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct VeilConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub transit: TransitConfig,
    #[serde(default)]
    pub search: SearchConfig,
    /// Keyring definitions (used in embedded mode).
    #[serde(default)]
    pub keyrings: std::collections::HashMap<String, KeyringConfig>,
    /// Storage config (used in embedded mode).
    #[serde(default)]
    pub storage: StorageConfig,
}

/// How Veil connects to Transit.
///
/// If `addr` is set, remote mode is used. Otherwise embedded mode is used
/// (requires the `embedded` feature).
#[derive(Debug, Deserialize)]
pub struct TransitConfig {
    /// Remote Transit server address. When set, forces remote mode.
    #[serde(default)]
    pub addr: Option<String>,
    /// Use TLS for the remote Transit connection.
    #[serde(default)]
    pub tls: bool,
    /// Auth token for remote Transit.
    #[serde(default)]
    pub token: Option<String>,
    /// Number of connections in the remote pool.
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
}

impl Default for TransitConfig {
    fn default() -> Self {
        Self {
            addr: None,
            tls: false,
            token: None,
            pool_size: default_pool_size(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SearchConfig {
    #[serde(default = "default_max_batch_size")]
    pub max_batch_size: usize,
    #[serde(default = "default_result_limit")]
    pub default_result_limit: usize,
    #[serde(default = "default_decrypt_batch_size")]
    pub decrypt_batch_size: usize,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: default_max_batch_size(),
            default_result_limit: default_result_limit(),
            decrypt_batch_size: default_decrypt_batch_size(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
    #[serde(default)]
    pub tls_client_ca: Option<PathBuf>,
    #[serde(default)]
    pub rate_limit: Option<u32>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            tls_cert: None,
            tls_key: None,
            tls_client_ca: None,
            rate_limit: None,
        }
    }
}

/// Keyring configuration (embedded mode).
#[derive(Debug, Deserialize)]
pub struct KeyringConfig {
    pub algorithm: String,
    #[serde(default = "default_rotation_days")]
    pub rotation_days: u32,
    #[serde(default = "default_drain_days")]
    pub drain_days: u32,
    #[serde(default)]
    pub convergent: bool,
}

/// Storage configuration (embedded mode).
#[derive(Debug, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default = "default_fsync_mode")]
    pub wal_fsync_mode: String,
    #[serde(default = "default_fsync_interval")]
    pub wal_fsync_interval_ms: u64,
    #[serde(default = "default_segment_size")]
    pub wal_segment_max_bytes: u64,
    #[serde(default = "default_snapshot_entries")]
    pub snapshot_interval_entries: u64,
    #[serde(default = "default_snapshot_minutes")]
    pub snapshot_interval_minutes: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            wal_fsync_mode: default_fsync_mode(),
            wal_fsync_interval_ms: default_fsync_interval(),
            wal_segment_max_bytes: default_segment_size(),
            snapshot_interval_entries: default_snapshot_entries(),
            snapshot_interval_minutes: default_snapshot_minutes(),
        }
    }
}

// ---------------------------------------------------------------------------
// Serde defaults
// ---------------------------------------------------------------------------

fn default_bind() -> SocketAddr {
    "0.0.0.0:6599".parse().unwrap()
}

fn default_pool_size() -> usize {
    4
}

fn default_max_batch_size() -> usize {
    50_000
}

fn default_result_limit() -> usize {
    100
}

fn default_decrypt_batch_size() -> usize {
    500
}

fn default_rotation_days() -> u32 {
    90
}

fn default_drain_days() -> u32 {
    30
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./veil-data")
}

fn default_fsync_mode() -> String {
    "batched".to_string()
}

fn default_fsync_interval() -> u64 {
    10
}

fn default_segment_size() -> u64 {
    64 * 1024 * 1024
}

fn default_snapshot_entries() -> u64 {
    100_000
}

fn default_snapshot_minutes() -> u64 {
    60
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

pub fn load(path: &Path) -> anyhow::Result<Option<VeilConfig>> {
    if !path.exists() {
        return Ok(None);
    }
    let contents =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let expanded = expand_env_vars(&contents);
    let config: VeilConfig =
        toml::from_str(&expanded).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(config))
}

fn expand_env_vars(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next();
            let mut var_name = String::new();
            let mut found_closing = false;
            for c in chars.by_ref() {
                if c == '}' {
                    found_closing = true;
                    break;
                }
                var_name.push(c);
            }
            if !found_closing {
                result.push_str("${");
                result.push_str(&var_name);
            } else {
                match std::env::var(&var_name) {
                    Ok(val) => result.push_str(&val),
                    Err(_) => {
                        result.push_str("${");
                        result.push_str(&var_name);
                        result.push('}');
                    }
                }
            }
        } else {
            result.push(ch);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Embedded Transit builder (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "embedded")]
pub fn build_embedded_transit(
    cfg: &VeilConfig,
) -> anyhow::Result<(
    std::sync::Arc<shroudb_transit_protocol::CommandDispatcher>,
    std::sync::Arc<shroudb_storage::StorageEngine>,
)> {
    use std::sync::Arc;

    use shroudb_storage::{FsyncMode, StorageEngine, StorageEngineConfig};
    use shroudb_transit_core::keyring::Keyring;
    use shroudb_transit_protocol::{AuthRegistry, KeyringIndex};

    // Resolve master key.
    let key_source = resolve_master_key()?;

    // Build engine config from the storage section.
    let fsync_mode = match cfg.storage.wal_fsync_mode.as_str() {
        "per_write" => FsyncMode::PerWrite,
        "batched" => FsyncMode::Batched {
            interval_ms: cfg.storage.wal_fsync_interval_ms,
        },
        "periodic" => FsyncMode::Periodic {
            interval_ms: cfg.storage.wal_fsync_interval_ms,
        },
        other => anyhow::bail!("unknown wal_fsync_mode: {other}"),
    };

    let engine_config = StorageEngineConfig {
        data_dir: cfg.storage.data_dir.clone(),
        fsync_mode,
        max_segment_bytes: cfg.storage.wal_segment_max_bytes,
        snapshot_entry_threshold: cfg.storage.snapshot_interval_entries,
        snapshot_time_threshold_secs: cfg.storage.snapshot_interval_minutes * 60,
        ..StorageEngineConfig::default()
    };

    // Open storage engine synchronously (WAL recovery happens here).
    let rt = tokio::runtime::Handle::current();
    let engine = rt.block_on(StorageEngine::open(engine_config, &*key_source))?;
    let engine = Arc::new(engine);
    tracing::info!("embedded storage engine ready");

    // Register keyrings.
    let keyrings = Arc::new(KeyringIndex::new());
    for (name, kr_config) in &cfg.keyrings {
        let algorithm = parse_algorithm(&kr_config.algorithm)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let keyring = Keyring {
            name: name.clone(),
            algorithm,
            rotation_days: kr_config.rotation_days,
            drain_days: kr_config.drain_days,
            convergent: kr_config.convergent,
            created_at: now,
            disabled: false,
            policy: Default::default(),
            key_versions: Vec::new(),
        };
        keyrings.register_metadata_only(keyring);
        tracing::info!(
            keyring = %name,
            algorithm = %kr_config.algorithm,
            convergent = kr_config.convergent,
            "registered keyring"
        );
    }

    // Replay WAL to restore key versions.
    let replayed = rt.block_on(shroudb_transit_protocol::recovery::replay_transit_wal(
        &engine, &keyrings,
    ))?;
    if replayed > 0 {
        tracing::info!(entries = replayed, "WAL replay complete");
    }

    // Seed any empty keyrings.
    let seeded = rt.block_on(shroudb_transit_protocol::recovery::seed_empty_keyrings(
        &engine, &keyrings,
    ))?;
    if seeded > 0 {
        tracing::info!(count = seeded, "seeded initial keys for new keyrings");
    }
    tracing::info!(count = keyrings.len(), "keyrings ready");

    // Permissive auth — Veil manages its own auth layer.
    let auth_registry = Arc::new(AuthRegistry::permissive());

    let dispatcher = Arc::new(shroudb_transit_protocol::CommandDispatcher::new(
        Arc::clone(&engine),
        Arc::clone(&keyrings),
        auth_registry,
    ));

    Ok((dispatcher, engine))
}

#[cfg(feature = "embedded")]
fn parse_algorithm(s: &str) -> anyhow::Result<shroudb_transit_core::keyring::KeyringAlgorithm> {
    use shroudb_transit_core::keyring::KeyringAlgorithm;
    match s.to_lowercase().replace('-', "_").as_str() {
        "aes_256_gcm" | "aes256gcm" => Ok(KeyringAlgorithm::Aes256Gcm),
        "chacha20_poly1305" | "chacha20poly1305" => Ok(KeyringAlgorithm::ChaCha20Poly1305),
        "ed25519" => Ok(KeyringAlgorithm::Ed25519),
        "ecdsa_p256" | "ecdsap256" => Ok(KeyringAlgorithm::EcdsaP256),
        "hmac_sha256" | "hmacsha256" => Ok(KeyringAlgorithm::HmacSha256),
        _ => anyhow::bail!("unknown algorithm: {s}"),
    }
}

#[cfg(feature = "embedded")]
fn resolve_master_key() -> anyhow::Result<Box<dyn shroudb_storage::MasterKeySource>> {
    use shroudb_storage::ChainedMasterKeySource;

    if std::env::var("SHROUDB_MASTER_KEY").is_ok()
        || std::env::var("SHROUDB_MASTER_KEY_FILE").is_ok()
    {
        return Ok(Box::new(ChainedMasterKeySource::default_chain()));
    }

    anyhow::bail!(
        "embedded mode requires SHROUDB_MASTER_KEY or SHROUDB_MASTER_KEY_FILE environment variable"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_parses() {
        let cfg = VeilConfig::default();
        assert_eq!(cfg.server.bind, default_bind());
        assert!(cfg.transit.addr.is_none());
    }

    #[test]
    fn veil_uses_port_6599() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.bind.port(), 6599);
    }

    #[test]
    fn remote_transit_config_from_toml() {
        let toml_str = r#"
[transit]
addr = "transit.internal:6499"
tls = true
token = "veil-service-token"
pool_size = 8
"#;
        let cfg: VeilConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.transit.addr.as_deref(), Some("transit.internal:6499"));
        assert!(cfg.transit.tls);
        assert_eq!(cfg.transit.token.as_deref(), Some("veil-service-token"));
        assert_eq!(cfg.transit.pool_size, 8);
    }

    #[test]
    fn embedded_mode_when_no_addr() {
        let toml_str = r#"
[keyrings.messages]
algorithm = "aes-256-gcm"

[keyrings."messages:tokens"]
algorithm = "aes-256-gcm"
convergent = true
"#;
        let cfg: VeilConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.transit.addr.is_none());
        assert_eq!(cfg.keyrings.len(), 2);
        assert!(cfg.keyrings["messages:tokens"].convergent);
    }

    #[test]
    fn search_config_defaults() {
        let cfg = SearchConfig::default();
        assert_eq!(cfg.max_batch_size, 50_000);
        assert_eq!(cfg.default_result_limit, 100);
        assert_eq!(cfg.decrypt_batch_size, 500);
    }
}
