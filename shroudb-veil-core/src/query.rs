//! Search request and response types.

use crate::matcher::MatchMode;

/// A search request: decrypt ciphertexts, match against a query.
#[derive(Debug, Clone)]
pub struct SearchRequest {
    /// Transit keyring to use for decrypt/encrypt operations.
    pub keyring: String,
    /// The search query string.
    pub query: String,
    /// How to match: exact, contains, prefix, or fuzzy.
    pub match_mode: MatchMode,
    /// Which field(s) in the decrypted JSON to search.
    pub field: FieldSelector,
    /// Optional AAD context for Transit decrypt/encrypt.
    pub context: Option<String>,
    /// Maximum number of results to return.
    pub limit: usize,
    /// If true, re-encrypt matches with the active key (opportunistic rewrap).
    pub rewrap: bool,
    /// The batch of encrypted entries to search over.
    pub ciphertexts: Vec<CiphertextEntry>,
}

/// An encrypted entry with an opaque ID for correlation.
#[derive(Debug, Clone)]
pub struct CiphertextEntry {
    /// Opaque identifier from the caller (e.g., database row ID).
    pub id: String,
    /// The Transit ciphertext envelope string.
    pub ciphertext: String,
    /// Pre-computed encrypted search tokens (from the INDEX command).
    /// When present, enables token-based pre-filtering before decryption.
    pub tokens: Option<Vec<String>>,
}

/// Which fields of a decrypted JSON payload to search.
#[derive(Debug, Clone)]
pub enum FieldSelector {
    /// Search all string values in the top-level JSON object.
    All,
    /// Search a specific named field.
    Named(String),
}

/// The response from an encrypted search.
#[derive(Debug, Clone)]
pub struct SearchResponse {
    /// Matching entries, sorted by descending score.
    pub results: Vec<SearchResultEntry>,
    /// Total number of ciphertexts that were scanned (after token filtering).
    pub scanned: usize,
    /// Total number of ciphertexts that matched (before limit truncation).
    pub matched: usize,
    /// Number of ciphertexts skipped by token pre-filtering.
    pub filtered: usize,
}

/// A single matching entry in the search results.
#[derive(Debug, Clone)]
pub struct SearchResultEntry {
    /// The opaque ID from the original CiphertextEntry.
    pub id: String,
    /// Match relevance score (0.0 to 1.0).
    pub score: f32,
    /// Re-encrypted ciphertext (only present when `rewrap` is true).
    pub ciphertext: Option<String>,
    /// Key version used for re-encryption (only present when `rewrap` is true).
    pub key_version: Option<u32>,
}
