use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::Arc;
use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use shroudb_chronicle_core::event::{Engine as AuditEngine, Event, EventResult};
use shroudb_chronicle_core::ops::ChronicleOps;
use shroudb_crypto::SecretBytes;
use shroudb_store::Store;
use shroudb_veil_core::error::VeilError;
use shroudb_veil_core::matching::MatchMode;
use shroudb_veil_core::tokenizer;

use crate::hmac_ops::{self, BlindTokenSet};
use crate::index_manager::{IndexManager, tokens_namespace};
use crate::search::{self, SearchHit};

/// A wrapper around `SearchHit` that implements a min-heap ordering by score.
/// This lets us maintain a bounded heap of the top-N highest-scoring hits:
/// the root is always the *lowest* score in the heap, so we can efficiently
/// evict it when a better candidate arrives.
struct MinScoreHit(SearchHit);

impl PartialEq for MinScoreHit {
    fn eq(&self, other: &Self) -> bool {
        self.0.score == other.0.score
    }
}

impl Eq for MinScoreHit {}

impl PartialOrd for MinScoreHit {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MinScoreHit {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering: lower score = higher priority in the heap.
        // This makes BinaryHeap behave as a min-heap by score.
        other
            .0
            .score
            .partial_cmp(&self.0.score)
            .unwrap_or(Ordering::Equal)
    }
}

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

/// Result from a reconciliation operation.
#[derive(Debug)]
pub struct ReconcileResult {
    pub orphans_removed: usize,
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
    chronicle: Option<Arc<dyn ChronicleOps>>,
}

impl<S: Store> VeilEngine<S> {
    /// Create a new Veil engine.
    pub async fn new(
        store: Arc<S>,
        config: VeilConfig,
        chronicle: Option<Arc<dyn ChronicleOps>>,
    ) -> Result<Self, VeilError> {
        let indexes = IndexManager::new(store);
        indexes.init().await?;
        Ok(Self {
            indexes,
            config,
            chronicle,
        })
    }

    /// Emit an audit event to Chronicle. If chronicle is not configured, this
    /// is a no-op. If chronicle is configured but unreachable, returns an error
    /// so security-critical callers can fail closed.
    async fn emit_audit_event(
        &self,
        operation: &str,
        resource: &str,
        result: EventResult,
        actor: Option<&str>,
        start: Instant,
    ) -> Result<(), VeilError> {
        let Some(chronicle) = &self.chronicle else {
            return Ok(());
        };
        let mut event = Event::new(
            AuditEngine::Veil,
            operation.to_string(),
            resource.to_string(),
            result,
            actor.unwrap_or("anonymous").to_string(),
        );
        event.duration_ms = start.elapsed().as_millis() as u64;
        chronicle
            .record(event)
            .await
            .map_err(|e| VeilError::Internal(format!("audit failed: {e}")))?;
        Ok(())
    }

    // ── Index management ──────────────────────────────────────────

    pub async fn index_create(&self, name: &str) -> Result<IndexInfoResult, VeilError> {
        let start = Instant::now();
        let idx = self.indexes.create(name).await?;
        self.emit_audit_event("INDEX_CREATE", name, EventResult::Ok, None, start)
            .await?;
        Ok(IndexInfoResult {
            name: idx.name.clone(),
            created_at: idx.created_at,
            entry_count: 0,
        })
    }

    pub fn index_list(&self) -> Vec<String> {
        self.indexes.list()
    }

    pub async fn index_info(&self, name: &str) -> Result<IndexInfoResult, VeilError> {
        let idx = self.indexes.get(name)?;
        let count = self.indexes.entry_count(name);
        Ok(IndexInfoResult {
            name: idx.name.clone(),
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
        let start = Instant::now();
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

        // Check whether this is a new entry or an update to an existing one.
        let is_new = self
            .indexes
            .store()
            .get(&ns, id.as_bytes(), None)
            .await
            .is_err();

        let version = self
            .indexes
            .store()
            .put(&ns, id.as_bytes(), &value, None)
            .await
            .map_err(|e| VeilError::Store(e.to_string()))?;

        if is_new {
            self.indexes.increment_entry_count(index_name);
        }

        let resource = format!("{index_name}/{id}");
        self.emit_audit_event("PUT", &resource, EventResult::Ok, None, start)
            .await?;
        Ok(version)
    }

    // ── Delete ────────────────────────────────────────────────────

    pub async fn delete(&self, index_name: &str, id: &str) -> Result<(), VeilError> {
        let start = Instant::now();
        let _ = self.indexes.get(index_name)?;
        let ns = tokens_namespace(index_name);

        // Check whether the entry exists before deleting so we can
        // accurately decrement the cached count.
        let existed = self
            .indexes
            .store()
            .get(&ns, id.as_bytes(), None)
            .await
            .is_ok();

        self.indexes
            .store()
            .delete(&ns, id.as_bytes())
            .await
            .map_err(|e| VeilError::Store(e.to_string()))?;

        if existed {
            self.indexes.decrement_entry_count(index_name);
        }

        let resource = format!("{index_name}/{id}");
        self.emit_audit_event("DELETE", &resource, EventResult::Ok, None, start)
            .await?;
        Ok(())
    }

    // ── Reconciliation ────────────────────────────────────────────

    /// Remove blind index entries whose IDs are not in the provided valid set.
    ///
    /// Called externally (by Moat or an operator) with the authoritative list
    /// of entity IDs from the upstream engine (e.g. Sigil). Any entry in the
    /// index that is not in `valid_entry_ids` is considered orphaned and deleted.
    pub async fn reconcile_orphans(
        &self,
        index_name: &str,
        valid_entry_ids: &[String],
    ) -> Result<ReconcileResult, VeilError> {
        use std::collections::HashSet;

        let start = Instant::now();
        let _ = self.indexes.get(index_name)?;
        let ns = tokens_namespace(index_name);

        let valid_set: HashSet<&str> = valid_entry_ids.iter().map(|s| s.as_str()).collect();

        let mut orphans_removed = 0usize;
        let mut cursor = None;

        loop {
            let page = self
                .indexes
                .store()
                .list(&ns, None, cursor.as_deref(), 100)
                .await
                .map_err(|e| VeilError::Store(e.to_string()))?;

            for entry_key in &page.keys {
                let id = String::from_utf8_lossy(entry_key);
                if !valid_set.contains(id.as_ref()) {
                    self.indexes
                        .store()
                        .delete(&ns, entry_key)
                        .await
                        .map_err(|e| VeilError::Store(e.to_string()))?;
                    self.indexes.decrement_entry_count(index_name);
                    orphans_removed += 1;
                }
            }

            if page.cursor.is_none() {
                break;
            }
            cursor = page.cursor;
        }

        let resource = format!("{index_name}/*");
        self.emit_audit_event("RECONCILE", &resource, EventResult::Ok, None, start)
            .await?;

        Ok(ReconcileResult { orphans_removed })
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
        let start = Instant::now();
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

        // Scan entries, keeping only the top-`limit` hits in a bounded min-heap.
        // This avoids collecting ALL matches into memory — the heap never exceeds
        // `limit` entries, and we skip the final sort by draining in order.
        let ns = tokens_namespace(index_name);
        let limit = limit.unwrap_or(self.config.default_result_limit);
        let mut heap: BinaryHeap<MinScoreHit> = BinaryHeap::with_capacity(limit + 1);
        let mut scanned = 0usize;
        let mut matched = 0usize;
        let mut perfect_count = 0usize;
        let mut cursor = None;

        'pages: loop {
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
                    matched += 1;
                    let id = String::from_utf8_lossy(entry_key).into_owned();

                    if score >= 1.0 {
                        perfect_count += 1;
                    }

                    // Push into the min-heap; if we exceed `limit`, evict the
                    // lowest-scoring entry. This keeps memory bounded to O(limit).
                    heap.push(MinScoreHit(SearchHit { id, score }));
                    if heap.len() > limit {
                        heap.pop(); // remove the lowest score
                    }

                    // Early exit: Exact mode always yields score 1.0, so once
                    // we have `limit` hits there is no better set to find.
                    if mode == MatchMode::Exact && matched >= limit {
                        break 'pages;
                    }

                    // For non-exact modes: if we already have `limit` perfect
                    // (1.0) scores, no remaining entry can displace them.
                    if mode != MatchMode::Exact && perfect_count >= limit {
                        break 'pages;
                    }
                }
            }

            if page.cursor.is_none() {
                break;
            }
            cursor = page.cursor;
        }

        // Drain the min-heap into a vec sorted by descending score.
        let len = heap.len();
        let mut hits = Vec::with_capacity(len);
        while let Some(MinScoreHit(hit)) = heap.pop() {
            hits.push(hit);
        }
        hits.reverse();

        let _ = self
            .emit_audit_event("SEARCH", index_name, EventResult::Ok, None, start)
            .await;
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
        VeilEngine::new(store, VeilConfig::default(), None)
            .await
            .unwrap()
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
    async fn test_reconcile_removes_orphans() {
        let engine = setup().await;
        engine.index_create("test").await.unwrap();

        engine
            .put("test", "a", &STANDARD.encode(b"alpha"), None)
            .await
            .unwrap();
        engine
            .put("test", "b", &STANDARD.encode(b"bravo"), None)
            .await
            .unwrap();
        engine
            .put("test", "c", &STANDARD.encode(b"charlie"), None)
            .await
            .unwrap();

        // Only "b" is valid — "a" and "c" are orphans.
        let result = engine
            .reconcile_orphans("test", &["b".to_string()])
            .await
            .unwrap();
        assert_eq!(result.orphans_removed, 2);

        // Verify entry count reflects removals.
        let info = engine.index_info("test").await.unwrap();
        assert_eq!(info.entry_count, 1);

        // Verify only "b" remains searchable.
        let search = engine
            .search("test", "bravo", MatchMode::Exact, None, None)
            .await
            .unwrap();
        assert_eq!(search.matched, 1);
        assert_eq!(search.hits[0].id, "b");

        let search = engine
            .search("test", "alpha", MatchMode::Exact, None, None)
            .await
            .unwrap();
        assert_eq!(search.matched, 0);
    }

    #[tokio::test]
    async fn test_reconcile_no_orphans() {
        let engine = setup().await;
        engine.index_create("test").await.unwrap();

        engine
            .put("test", "a", &STANDARD.encode(b"alpha"), None)
            .await
            .unwrap();
        engine
            .put("test", "b", &STANDARD.encode(b"bravo"), None)
            .await
            .unwrap();
        engine
            .put("test", "c", &STANDARD.encode(b"charlie"), None)
            .await
            .unwrap();

        // All three are valid — nothing to remove.
        let result = engine
            .reconcile_orphans("test", &["a".to_string(), "b".to_string(), "c".to_string()])
            .await
            .unwrap();
        assert_eq!(result.orphans_removed, 0);

        let info = engine.index_info("test").await.unwrap();
        assert_eq!(info.entry_count, 3);
    }

    #[tokio::test]
    async fn test_reconcile_empty_index() {
        let engine = setup().await;
        engine.index_create("test").await.unwrap();

        let result = engine
            .reconcile_orphans("test", &["a".to_string()])
            .await
            .unwrap();
        assert_eq!(result.orphans_removed, 0);
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
