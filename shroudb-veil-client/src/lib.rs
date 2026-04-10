//! Typed Rust client library for Veil.
//!
//! Provides a high-level async API for interacting with a Veil server
//! over TCP (RESP3 wire protocol).

mod connection;
mod error;

pub use error::ClientError;

use connection::Connection;

/// Result from a search operation.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub scanned: u64,
    pub matched: u64,
    pub results: Vec<SearchHit>,
}

/// A single search hit.
#[derive(Debug, Clone)]
pub struct SearchHit {
    pub id: String,
    pub score: f64,
}

/// Result from a tokenize operation.
#[derive(Debug, Clone)]
pub struct TokenizeResult {
    pub words: u64,
    pub trigrams: u64,
    pub tokens: serde_json::Value,
}

/// A Veil client connected via TCP.
pub struct VeilClient {
    conn: Connection,
}

impl VeilClient {
    /// Connect directly to a standalone Veil server.
    pub async fn connect(addr: &str) -> Result<Self, ClientError> {
        let conn = Connection::connect(addr).await?;
        Ok(Self { conn })
    }

    /// Connect to a Veil engine through a Moat gateway.
    ///
    /// Commands are automatically prefixed with `VEIL` for Moat routing.
    /// Meta-commands (AUTH, HEALTH, PING) are sent without prefix.
    pub async fn connect_moat(addr: &str) -> Result<Self, ClientError> {
        let conn = Connection::connect_moat(addr).await?;
        Ok(Self { conn })
    }

    /// Authenticate this connection.
    pub async fn auth(&mut self, token: &str) -> Result<(), ClientError> {
        let resp = self.meta_command(&["AUTH", token]).await?;
        check_status(&resp)
    }

    /// Health check.
    pub async fn health(&mut self) -> Result<(), ClientError> {
        let resp = self.meta_command(&["HEALTH"]).await?;
        check_status(&resp)
    }

    // ── Index management ──────────────────────────────────────────

    /// Create a blind index.
    pub async fn index_create(&mut self, name: &str) -> Result<serde_json::Value, ClientError> {
        let resp = self.command(&["INDEX", "CREATE", name]).await?;
        check_status(&resp)?;
        Ok(resp)
    }

    /// List all index names.
    pub async fn index_list(&mut self) -> Result<Vec<String>, ClientError> {
        let resp = self.command(&["INDEX", "LIST"]).await?;
        resp.as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .ok_or_else(|| ClientError::ResponseFormat("expected array".into()))
    }

    /// Get index info.
    pub async fn index_info(&mut self, name: &str) -> Result<serde_json::Value, ClientError> {
        let resp = self.command(&["INDEX", "INFO", name]).await?;
        check_status(&resp)?;
        Ok(resp)
    }

    // ── Tokenize ──────────────────────────────────────────────────

    /// Generate blind tokens without storing.
    pub async fn tokenize(
        &mut self,
        index: &str,
        plaintext_b64: &str,
        field: Option<&str>,
    ) -> Result<TokenizeResult, ClientError> {
        let mut args = vec!["TOKENIZE", index, plaintext_b64];
        let field_owned;
        if let Some(f) = field {
            field_owned = f.to_string();
            args.push("FIELD");
            args.push(&field_owned);
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;
        Ok(TokenizeResult {
            words: resp["words"].as_u64().unwrap_or(0),
            trigrams: resp["trigrams"].as_u64().unwrap_or(0),
            tokens: resp["tokens"].clone(),
        })
    }

    // ── Entry operations ──────────────────────────────────────────

    /// Index an entry.
    ///
    /// In standard mode (`blind=false`): `data_b64` is base64-encoded plaintext.
    /// In blind mode (`blind=true`): `data_b64` is base64-encoded BlindTokenSet JSON.
    pub async fn put(
        &mut self,
        index: &str,
        id: &str,
        data_b64: &str,
        field: Option<&str>,
        blind: bool,
    ) -> Result<u64, ClientError> {
        let mut args = vec!["PUT", index, id, data_b64];
        let field_owned;
        if let Some(f) = field {
            field_owned = f.to_string();
            args.push("FIELD");
            args.push(&field_owned);
        }
        if blind {
            args.push("BLIND");
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;
        resp["version"]
            .as_u64()
            .ok_or_else(|| ClientError::ResponseFormat("missing version".into()))
    }

    /// Delete an entry from the index.
    pub async fn delete(&mut self, index: &str, id: &str) -> Result<(), ClientError> {
        let resp = self.command(&["DELETE", index, id]).await?;
        check_status(&resp)
    }

    // ── Search ────────────────────────────────────────────────────

    /// Search a blind index.
    ///
    /// In standard mode (`blind=false`): `query` is plain text.
    /// In blind mode (`blind=true`): `query` is base64-encoded BlindTokenSet JSON.
    pub async fn search(
        &mut self,
        index: &str,
        query: &str,
        mode: Option<&str>,
        field: Option<&str>,
        limit: Option<usize>,
        blind: bool,
    ) -> Result<SearchResult, ClientError> {
        let mut args = vec!["SEARCH", index, query];
        let mode_owned;
        if let Some(m) = mode {
            mode_owned = m.to_string();
            args.push("MODE");
            args.push(&mode_owned);
        }
        let field_owned;
        if let Some(f) = field {
            field_owned = f.to_string();
            args.push("FIELD");
            args.push(&field_owned);
        }
        let limit_str;
        if let Some(l) = limit {
            limit_str = l.to_string();
            args.push("LIMIT");
            args.push(&limit_str);
        }
        if blind {
            args.push("BLIND");
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;

        let results = resp["results"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        Some(SearchHit {
                            id: v["id"].as_str()?.to_string(),
                            score: v["score"].as_f64()?,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(SearchResult {
            scanned: resp["scanned"].as_u64().unwrap_or(0),
            matched: resp["matched"].as_u64().unwrap_or(0),
            results,
        })
    }

    // ── Internal ──────────────────────────────────────────────────

    async fn command(&mut self, args: &[&str]) -> Result<serde_json::Value, ClientError> {
        self.conn.send_command(args).await
    }

    async fn meta_command(&mut self, args: &[&str]) -> Result<serde_json::Value, ClientError> {
        self.conn.send_meta_command(args).await
    }
}

fn check_status(resp: &serde_json::Value) -> Result<(), ClientError> {
    if let Some(status) = resp.get("status").and_then(|s| s.as_str())
        && status == "ok"
    {
        return Ok(());
    }
    if resp.is_array() || resp.is_object() {
        return Ok(());
    }
    Err(ClientError::ResponseFormat("unexpected response".into()))
}
