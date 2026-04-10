use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use shroudb_acl::ServerAuthConfig;

#[derive(Debug, Deserialize, Default)]
pub struct VeilServerConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub engine: EngineConfig,
    #[serde(default)]
    pub auth: ServerAuthConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_tcp_bind")]
    pub tcp_bind: SocketAddr,
    #[serde(default)]
    pub http_bind: Option<String>,
    #[serde(default)]
    pub log_level: Option<String>,
    #[serde(default)]
    pub tls: Option<shroudb_server_tcp::TlsConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            tcp_bind: default_tcp_bind(),
            http_bind: None,
            log_level: None,
            tls: None,
        }
    }
}

fn default_tcp_bind() -> SocketAddr {
    "0.0.0.0:6799".parse().expect("valid hardcoded address")
}

#[derive(Debug, Deserialize)]
pub struct StoreConfig {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default)]
    pub uri: Option<String>,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            data_dir: default_data_dir(),
            uri: None,
        }
    }
}

fn default_mode() -> String {
    "embedded".to_string()
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./veil-data")
}

#[derive(Debug, Deserialize)]
pub struct EngineConfig {
    #[serde(default = "default_result_limit")]
    pub default_result_limit: usize,
    #[serde(default)]
    pub indexes: Vec<String>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            default_result_limit: default_result_limit(),
            indexes: Vec::new(),
        }
    }
}

fn default_result_limit() -> usize {
    100
}

/// Load config from a TOML file, or return defaults.
pub fn load_config(path: Option<&str>) -> anyhow::Result<VeilServerConfig> {
    match path {
        Some(p) => {
            let raw = std::fs::read_to_string(p)
                .map_err(|e| anyhow::anyhow!("failed to read config: {e}"))?;
            let config: VeilServerConfig =
                toml::from_str(&raw).map_err(|e| anyhow::anyhow!("failed to parse config: {e}"))?;
            Ok(config)
        }
        None => Ok(VeilServerConfig::default()),
    }
}
