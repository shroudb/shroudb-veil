//! `shroudb-veil-client` — typed Rust client library for ShrouDB Veil.
//!
//! Provides a high-level async API for interacting with a Veil server.
//! Commands use match mode as the verb: FUZZY, CONTAINS, EXACT, PREFIX.
//!
//! # Example
//!
//! ```no_run
//! use shroudb_veil_client::VeilClient;
//!
//! # async fn example() -> Result<(), shroudb_veil_client::ClientError> {
//! let mut client = VeilClient::connect("127.0.0.1:6599").await?;
//!
//! let results = client.contains(
//!     "messages",
//!     "dinner",
//!     Some("body"),
//!     None,
//!     Some(50),
//!     &["v1:gcm:abc...", "v1:gcm:def..."],
//! ).await?;
//!
//! println!("Found {} matches", results.matched);
//! # Ok(())
//! # }
//! ```

pub mod error;
pub mod response;

pub use error::ClientError;
pub use response::{HealthResult, IndexResult, SearchResult, SearchResultEntry};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;

/// Default Veil server port.
const DEFAULT_PORT: u16 = 6599;

/// A client for interacting with a ShrouDB Veil server.
pub struct VeilClient {
    reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: BufWriter<tokio::io::WriteHalf<TcpStream>>,
}

impl VeilClient {
    /// Connect to a Veil server at the given address (e.g. `"127.0.0.1:6599"`).
    pub async fn connect(addr: &str) -> Result<Self, ClientError> {
        let stream = TcpStream::connect(addr).await?;
        let (r, w) = tokio::io::split(stream);
        Ok(Self {
            reader: BufReader::new(r),
            writer: BufWriter::new(w),
        })
    }

    /// Send a raw command line and read the JSON response.
    async fn send(&mut self, line: &str) -> Result<serde_json::Value, ClientError> {
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await?;

        let mut response_line = String::new();
        let n = self.reader.read_line(&mut response_line).await?;
        if n == 0 {
            return Err(ClientError::Protocol("connection closed".into()));
        }

        let json: serde_json::Value = serde_json::from_str(response_line.trim())
            .map_err(|e| ClientError::Protocol(format!("invalid JSON response: {e}")))?;

        if let Some(err) = json.get("error").and_then(|e| e.as_str()) {
            return Err(ClientError::Server(err.to_string()));
        }

        Ok(json)
    }

    /// Build a search command string.
    fn build_search_cmd(
        verb: &str,
        keyring: &str,
        query: &str,
        field: Option<&str>,
        context: Option<&str>,
        limit: Option<usize>,
        ciphertexts: &[&str],
    ) -> String {
        let mut cmd = format!("{verb} {keyring} QUERY \"{query}\"");
        if let Some(f) = field {
            cmd.push_str(&format!(" FIELD {f}"));
        }
        if let Some(ctx) = context {
            cmd.push_str(&format!(" CONTEXT {ctx}"));
        }
        if let Some(lim) = limit {
            cmd.push_str(&format!(" LIMIT {lim}"));
        }
        cmd.push_str(" CIPHERTEXTS");
        for ct in ciphertexts {
            cmd.push(' ');
            cmd.push_str(ct);
        }
        cmd
    }

    /// Fuzzy search (Levenshtein distance, typo-tolerant).
    pub async fn fuzzy(
        &mut self,
        keyring: &str,
        query: &str,
        field: Option<&str>,
        context: Option<&str>,
        limit: Option<usize>,
        ciphertexts: &[&str],
    ) -> Result<SearchResult, ClientError> {
        let cmd =
            Self::build_search_cmd("FUZZY", keyring, query, field, context, limit, ciphertexts);
        let json = self.send(&cmd).await?;
        SearchResult::from_json(json)
    }

    /// Substring search (case-insensitive contains).
    pub async fn contains(
        &mut self,
        keyring: &str,
        query: &str,
        field: Option<&str>,
        context: Option<&str>,
        limit: Option<usize>,
        ciphertexts: &[&str],
    ) -> Result<SearchResult, ClientError> {
        let cmd = Self::build_search_cmd(
            "CONTAINS",
            keyring,
            query,
            field,
            context,
            limit,
            ciphertexts,
        );
        let json = self.send(&cmd).await?;
        SearchResult::from_json(json)
    }

    /// Exact equality search (case-insensitive).
    pub async fn exact(
        &mut self,
        keyring: &str,
        query: &str,
        field: Option<&str>,
        context: Option<&str>,
        limit: Option<usize>,
        ciphertexts: &[&str],
    ) -> Result<SearchResult, ClientError> {
        let cmd =
            Self::build_search_cmd("EXACT", keyring, query, field, context, limit, ciphertexts);
        let json = self.send(&cmd).await?;
        SearchResult::from_json(json)
    }

    /// Prefix search (word-boundary aware).
    pub async fn prefix(
        &mut self,
        keyring: &str,
        query: &str,
        field: Option<&str>,
        context: Option<&str>,
        limit: Option<usize>,
        ciphertexts: &[&str],
    ) -> Result<SearchResult, ClientError> {
        let cmd =
            Self::build_search_cmd("PREFIX", keyring, query, field, context, limit, ciphertexts);
        let json = self.send(&cmd).await?;
        SearchResult::from_json(json)
    }

    /// Encrypt plaintext and generate search tokens for indexing.
    pub async fn index(
        &mut self,
        keyring: &str,
        plaintext_b64: &str,
        field: Option<&str>,
        context: Option<&str>,
    ) -> Result<IndexResult, ClientError> {
        let mut cmd = format!("INDEX {keyring} {plaintext_b64}");
        if let Some(f) = field {
            cmd.push_str(&format!(" FIELD {f}"));
        }
        if let Some(ctx) = context {
            cmd.push_str(&format!(" CONTEXT {ctx}"));
        }
        let json = self.send(&cmd).await?;
        IndexResult::from_json(json)
    }

    /// Check server health.
    pub async fn health(&mut self) -> Result<HealthResult, ClientError> {
        let json = self.send("HEALTH").await?;
        HealthResult::from_json(json)
    }
}

/// Parse a Veil connection URI.
///
/// Format: `shroudb-veil://[token@]host[:port]`
pub fn parse_uri(uri: &str) -> Result<(String, Option<String>), ClientError> {
    let rest = uri
        .strip_prefix("shroudb-veil://")
        .ok_or_else(|| ClientError::Protocol(format!("invalid URI scheme: {uri}")))?;

    let (auth_token, hostport) = if let Some(at_pos) = rest.find('@') {
        (Some(rest[..at_pos].to_string()), &rest[at_pos + 1..])
    } else {
        (None, rest)
    };

    let hostport = hostport.split('/').next().unwrap_or(hostport);

    let addr = if hostport.contains(':') {
        hostport.to_string()
    } else {
        format!("{hostport}:{DEFAULT_PORT}")
    };

    Ok((addr, auth_token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uri_plain() {
        let (addr, token) = parse_uri("shroudb-veil://localhost").unwrap();
        assert_eq!(addr, "localhost:6599");
        assert!(token.is_none());
    }

    #[test]
    fn parse_uri_with_port() {
        let (addr, _) = parse_uri("shroudb-veil://localhost:7000").unwrap();
        assert_eq!(addr, "localhost:7000");
    }

    #[test]
    fn parse_uri_with_auth() {
        let (addr, token) = parse_uri("shroudb-veil://mytoken@host:6599").unwrap();
        assert_eq!(addr, "host:6599");
        assert_eq!(token.as_deref(), Some("mytoken"));
    }

    #[test]
    fn parse_uri_invalid_scheme() {
        assert!(parse_uri("redis://localhost").is_err());
    }
}
