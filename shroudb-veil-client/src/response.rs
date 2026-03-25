//! Typed result structs for Veil responses.

use crate::error::ClientError;

/// Result from a search command (FUZZY, CONTAINS, EXACT, PREFIX).
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub scanned: i64,
    pub matched: i64,
    pub filtered: i64,
    pub results: Vec<SearchResultEntry>,
}

impl SearchResult {
    pub fn from_json(json: serde_json::Value) -> Result<Self, ClientError> {
        let scanned = json
            .get("scanned")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| ClientError::Protocol("missing 'scanned' field".into()))?;
        let matched = json
            .get("matched")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| ClientError::Protocol("missing 'matched' field".into()))?;
        let filtered = json.get("filtered").and_then(|v| v.as_i64()).unwrap_or(0);

        let results = match json.get("results") {
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .map(SearchResultEntry::from_json)
                .collect::<Result<Vec<_>, _>>()?,
            _ => Vec::new(),
        };

        Ok(Self {
            scanned,
            matched,
            filtered,
            results,
        })
    }
}

/// A single entry in the search results.
#[derive(Debug, Clone)]
pub struct SearchResultEntry {
    pub id: String,
    pub score: f64,
    /// Present only when `REWRAP` was requested.
    pub ciphertext: Option<String>,
    /// Present only when `REWRAP` was requested.
    pub key_version: Option<i64>,
}

impl SearchResultEntry {
    fn from_json(json: &serde_json::Value) -> Result<Self, ClientError> {
        Ok(Self {
            id: json
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            score: json.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0),
            ciphertext: json
                .get("ciphertext")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            key_version: json.get("key_version").and_then(|v| v.as_i64()),
        })
    }
}

/// Result from a HEALTH command.
#[derive(Debug, Clone)]
pub struct HealthResult {
    pub state: String,
    pub transit: Option<String>,
}

impl HealthResult {
    pub fn from_json(json: serde_json::Value) -> Result<Self, ClientError> {
        let state = json
            .get("state")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ClientError::Protocol("missing 'state' field".into()))?
            .to_string();
        let transit = json
            .get("transit")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        Ok(Self { state, transit })
    }
}

/// Result from an INDEX command.
#[derive(Debug, Clone)]
pub struct IndexResult {
    pub ciphertext: String,
    pub key_version: i64,
    pub tokens: Vec<String>,
}

impl IndexResult {
    pub fn from_json(json: serde_json::Value) -> Result<Self, ClientError> {
        let ciphertext = json
            .get("ciphertext")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ClientError::Protocol("missing 'ciphertext' field".into()))?
            .to_string();
        let key_version = json
            .get("key_version")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| ClientError::Protocol("missing 'key_version' field".into()))?;
        let tokens = json
            .get("tokens")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| t.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            ciphertext,
            key_version,
            tokens,
        })
    }
}
