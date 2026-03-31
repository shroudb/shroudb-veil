use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use shroudb_crypto::SecretBytes;
use shroudb_store::Store;
use shroudb_veil_core::error::VeilError;
use shroudb_veil_core::matching::MatchMode;
use shroudb_veil_core::tokenizer;

use crate::hmac_ops::{self, BlindTokenSet};
use crate::index_manager::{IndexManager, tokens_namespace};
use crate::search::{self, SearchHit};

/// Configuration for the Veil engine.
pub struct VeilConfig {
    pub default_result_limit: usize,
}

impl Default for VeilConfig {
    fn default() -> Self {
        Self {
            default_result_limit: 100,
        }
    }
}

/// Result from a tokenize operation (tokens without storage).
#[derive(Debug)]
pub struct TokenizeResult {
    pub words: Vec<String>,
    pub trigrams: Vec<String>,
}

/// Result from a search operation.
#[derive(Debug)]
pub struct SearchResult {
    pub hits: Vec<SearchHit>,
    pub scanned: usize,
    pub matched: usize,
}

/// Result from an index info query.
#[derive(Debug)]
pub struct IndexInfoResult {
    pub name: String,
    pub created_at: u64,
    pub entry_count: u64,
}

/// The unified Veil engine. Single entry point for all operations.
///
/// Generic over `S: Store` — works identically with `EmbeddedStore`
/// (in-process ShrouDB) or `RemoteStore` (TCP to ShrouDB server).
pub struct VeilEngine<S: Store> {
    pub(crate) indexes: IndexManager<S>,
    pub(crate) config: VeilConfig,
}

impl<S: Store> VeilEngine<S> {
    /// Create a new Veil engine.
    pub async fn new(store: Arc<S>, config: VeilConfig) -> Result<Self, VeilError> {
        let indexes = IndexManager::new(store);
        indexes.init().await?;
        Ok(Self { indexes, config })
    }

    // ── Index management ──────────────────────────────────────────

    pub async fn index_create(&self, name: &str) -> Result<IndexInfoResult, VeilError> {
        let idx = self.indexes.create(name).await?;
        Ok(IndexInfoResult {
            name: idx.name,
            created_at: idx.created_at,
            entry_count: 0,
        })
    }

    pub fn index_list(&self) -> Vec<String> {
        self.indexes.list()
    }

    pub async fn index_info(&self, name: &str) -> Result<IndexInfoResult, VeilError> {
        let idx = self.indexes.get(name)?;
        let ns = tokens_namespace(name);
        let mut count = 0u64;
        let mut cursor = None;
        loop {
            let page = self
                .indexes
                .store()
                .list(&ns, None, cursor.as_deref(), 100)
                .await
                .map_err(|e| VeilError::Store(e.to_string()))?;
            count += page.keys.len() as u64;
            if page.cursor.is_none() {
                break;
            }
            cursor = page.cursor;
        }
        Ok(IndexInfoResult {
            name: idx.name,
            created_at: idx.created_at,
            entry_count: count,
        })
    }

    /// Access the index manager (for seeding from config).
    pub fn index_manager(&self) -> &IndexManager<S> {
        &self.indexes
    }

    // ── Tokenize (pure, no storage) ───────────────────────────────

    pub fn tokenize(
        &self,
        index_name: &str,
        plaintext_b64: &str,
        field: Option<&str>,
    ) -> Result<TokenizeResult, VeilError> {
        let idx = self.indexes.get(index_name)?;
        let plaintext = decode_b64(plaintext_b64)?;
        let text = tokenizer::extract_text(&plaintext, field);
        let tokens = tokenizer::tokenize(&text);
        let key = decode_key(&idx)?;
        let blind = hmac_ops::blind_token_set(&key, &tokens);

        Ok(TokenizeResult {
            words: blind.words,
            trigrams: blind.trigrams,
        })
    }

    // ── Put (tokenize + store) ────────────────────────────────────

    pub async fn put(
        &self,
        index_name: &str,
        id: &str,
        plaintext_b64: &str,
        field: Option<&str>,
    ) -> Result<u64, VeilError> {
        if id.is_empty() {
            return Err(VeilError::InvalidArgument(
                "entry ID cannot be empty".into(),
            ));
        }

        let idx = self.indexes.get(index_name)?;
        let plaintext = decode_b64(plaintext_b64)?;
        let text = tokenizer::extract_text(&plaintext, field);
        let tokens = tokenizer::tokenize(&text);
        let key = decode_key(&idx)?;
        let blind = hmac_ops::blind_token_set(&key, &tokens);

        let ns = tokens_namespace(index_name);
        let value = serde_json::to_vec(&blind)
            .map_err(|e| VeilError::Internal(format!("serialization failed: {e}")))?;

        let version = self
            .indexes
            .store()
            .put(&ns, id.as_bytes(), &value, None)
            .await
            .map_err(|e| VeilError::Store(e.to_string()))?;

        Ok(version)
    }

    // ── Delete ────────────────────────────────────────────────────

    pub async fn delete(&self, index_name: &str, id: &str) -> Result<(), VeilError> {
        let _ = self.indexes.get(index_name)?;
        let ns = tokens_namespace(index_name);

        self.indexes
            .store()
            .delete(&ns, id.as_bytes())
            .await
            .map_err(|e| VeilError::Store(e.to_string()))?;

        Ok(())
    }

    // ── Search ────────────────────────────────────────────────────

    pub async fn search(
        &self,
        index_name: &str,
        query: &str,
        mode: MatchMode,
        field: Option<&str>,
        limit: Option<usize>,
    ) -> Result<SearchResult, VeilError> {
        if query.is_empty() {
            return Err(VeilError::InvalidArgument("query cannot be empty".into()));
        }

        let idx = self.indexes.get(index_name)?;
        let key = decode_key(&idx)?;

        // Tokenize and blind the query
        let text = if field.is_some() {
            // If searching a field, the query is plain text (not JSON)
            query.to_string()
        } else {
            query.to_string()
        };
        let query_tokens = tokenizer::tokenize(&text);
        let query_blind = hmac_ops::blind_token_set(&key, &query_tokens);

        // Scan all entries in the index
        let ns = tokens_namespace(index_name);
        let limit = limit.unwrap_or(self.config.default_result_limit);
        let mut hits = Vec::new();
        let mut scanned = 0usize;
        let mut cursor = None;

        loop {
            let page = self
                .indexes
                .store()
                .list(&ns, None, cursor.as_deref(), 100)
                .await
                .map_err(|e| VeilError::Store(e.to_string()))?;

            for entry_key in &page.keys {
                scanned += 1;

                let entry = self
                    .indexes
                    .store()
                    .get(&ns, entry_key, None)
                    .await
                    .map_err(|e| VeilError::Store(e.to_string()))?;

                let entry_blind: BlindTokenSet = match serde_json::from_slice(&entry.value) {
                    Ok(b) => b,
                    Err(_) => continue,
                };

                if let Some(score) = search::score_entry(mode, &query_blind, &entry_blind) {
                    let id = String::from_utf8_lossy(entry_key).into_owned();
                    hits.push(SearchHit { id, score });

                    // All exact matches have score 1.0, no ranking needed
                    if mode == MatchMode::Exact && hits.len() >= limit {
                        break;
                    }
                }
            }

            // Break out of pagination if we already have enough exact matches
            if mode == MatchMode::Exact && hits.len() >= limit {
                break;
            }

            if page.cursor.is_none() {
                break;
            }
            cursor = page.cursor;
        }

        // Sort by descending score
        hits.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let matched = hits.len();
        hits.truncate(limit);

        Ok(SearchResult {
            hits,
            scanned,
            matched,
        })
    }
}

fn decode_b64(input: &str) -> Result<Vec<u8>, VeilError> {
    STANDARD
        .decode(input)
        .map_err(|e| VeilError::InvalidArgument(format!("invalid base64: {e}")))
}

fn decode_key(idx: &shroudb_veil_core::index::BlindIndex) -> Result<SecretBytes, VeilError> {
    let bytes = hex::decode(idx.key_material.as_str())
        .map_err(|e| VeilError::Internal(format!("corrupt key material hex: {e}")))?;
    Ok(SecretBytes::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup() -> VeilEngine<shroudb_storage::EmbeddedStore> {
        let store = shroudb_storage::test_util::create_test_store("veil-test").await;
        VeilEngine::new(store, VeilConfig::default()).await.unwrap()
    }

    #[tokio::test]
    async fn put_and_search_exact() {
        let engine = setup().await;
        engine.index_create("users").await.unwrap();

        engine
            .put("users", "1", &STANDARD.encode(b"Alice Johnson"), None)
            .await
            .unwrap();
        engine
            .put("users", "2", &STANDARD.encode(b"Bob Smith"), None)
            .await
            .unwrap();
        engine
            .put("users", "3", &STANDARD.encode(b"Charlie Johnson"), None)
            .await
            .unwrap();

        let result = engine
            .search("users", "johnson", MatchMode::Exact, None, None)
            .await
            .unwrap();
        assert_eq!(result.matched, 2);
        assert_eq!(result.scanned, 3);
    }

    #[tokio::test]
    async fn put_and_search_contains() {
        let engine = setup().await;
        engine.index_create("messages").await.unwrap();

        engine
            .put(
                "messages",
                "m1",
                &STANDARD.encode(b"hello world foo bar"),
                None,
            )
            .await
            .unwrap();
        engine
            .put(
                "messages",
                "m2",
                &STANDARD.encode(b"goodbye world baz"),
                None,
            )
            .await
            .unwrap();

        let result = engine
            .search("messages", "hello world", MatchMode::Contains, None, None)
            .await
            .unwrap();

        // m1 matches both "hello" and "world" (score 1.0)
        // m2 matches "world" only (score 0.5)
        assert_eq!(result.matched, 2);
        assert!(result.hits[0].score > result.hits[1].score);
    }

    #[tokio::test]
    async fn search_with_json_field() {
        let engine = setup().await;
        engine.index_create("contacts").await.unwrap();

        let data = serde_json::json!({"name": "Alice", "city": "Portland"});
        engine
            .put(
                "contacts",
                "c1",
                &STANDARD.encode(data.to_string().as_bytes()),
                Some("name"),
            )
            .await
            .unwrap();

        let result = engine
            .search("contacts", "alice", MatchMode::Exact, None, None)
            .await
            .unwrap();
        assert_eq!(result.matched, 1);
    }

    #[tokio::test]
    async fn delete_entry() {
        let engine = setup().await;
        engine.index_create("test").await.unwrap();

        engine
            .put("test", "a", &STANDARD.encode(b"hello"), None)
            .await
            .unwrap();
        engine.delete("test", "a").await.unwrap();

        let result = engine
            .search("test", "hello", MatchMode::Exact, None, None)
            .await
            .unwrap();
        assert_eq!(result.matched, 0);
    }

    #[tokio::test]
    async fn tokenize_returns_blind_tokens() {
        let engine = setup().await;
        engine.index_create("test").await.unwrap();

        let result = engine
            .tokenize("test", &STANDARD.encode(b"hello world"), None)
            .unwrap();
        assert_eq!(result.words.len(), 2);
        assert!(!result.trigrams.is_empty());

        // Tokens should be hex-encoded HMAC values (64 chars each)
        for w in &result.words {
            assert_eq!(w.len(), 64);
        }
    }

    #[tokio::test]
    async fn search_limit_applied() {
        let engine = setup().await;
        engine.index_create("test").await.unwrap();

        for i in 0..10 {
            engine
                .put(
                    "test",
                    &format!("e{i}"),
                    &STANDARD.encode(b"common word"),
                    None,
                )
                .await
                .unwrap();
        }

        let result = engine
            .search("test", "common", MatchMode::Exact, None, Some(3))
            .await
            .unwrap();
        assert_eq!(result.hits.len(), 3);
        // Exact mode early-exits after reaching the limit — not all entries are scanned
        assert!(result.matched >= 3);
        assert!(result.scanned <= 10);
    }

    #[tokio::test]
    async fn empty_query_rejected() {
        let engine = setup().await;
        engine.index_create("test").await.unwrap();

        let err = engine
            .search("test", "", MatchMode::Exact, None, None)
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn nonexistent_index_rejected() {
        let engine = setup().await;

        let err = engine
            .search("nope", "query", MatchMode::Exact, None, None)
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn index_info_returns_entry_count() {
        let engine = setup().await;
        engine.index_create("test").await.unwrap();

        engine
            .put("test", "a", &STANDARD.encode(b"hello"), None)
            .await
            .unwrap();
        engine
            .put("test", "b", &STANDARD.encode(b"world"), None)
            .await
            .unwrap();

        let info = engine.index_info("test").await.unwrap();
        assert_eq!(info.name, "test");
        assert_eq!(info.entry_count, 2);
    }

    #[tokio::test]
    async fn fuzzy_search_finds_similar() {
        let engine = setup().await;
        engine.index_create("test").await.unwrap();

        engine
            .put("test", "1", &STANDARD.encode(b"hello"), None)
            .await
            .unwrap();
        engine
            .put("test", "2", &STANDARD.encode(b"helicopter"), None)
            .await
            .unwrap();
        engine
            .put("test", "3", &STANDARD.encode(b"goodbye"), None)
            .await
            .unwrap();

        let result = engine
            .search("test", "helo", MatchMode::Fuzzy, None, None)
            .await
            .unwrap();

        // "helo" shares trigrams with "hello" (hel) and "helicopter" (hel)
        // but not with "goodbye"
        assert!(result.matched >= 1);
        assert!(result.hits.iter().all(|h| h.id != "3"));
    }
}
