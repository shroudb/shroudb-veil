use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use shroudb_acl::{PolicyEffect, PolicyEvaluator, PolicyPrincipal, PolicyRequest, PolicyResource};
use shroudb_chronicle_core::event::{Engine as AuditEngine, Event, EventResult};
use shroudb_chronicle_core::ops::ChronicleOps;
use shroudb_crypto::SecretBytes;
use shroudb_server_bootstrap::Capability;
use shroudb_store::Store;
use shroudb_veil_core::error::VeilError;
use shroudb_veil_core::matching::MatchMode;
use shroudb_veil_core::tokenizer::{self, TOKENIZER_VERSION};

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
    /// Maximum entries per index (0 = unlimited). Rejects PUT on new entries
    /// once the limit is reached. Updates to existing entries are always allowed.
    pub max_entries_per_index: u64,
}

impl Default for VeilConfig {
    fn default() -> Self {
        Self {
            default_result_limit: 100,
            max_entries_per_index: 0, // unlimited by default
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
    pub tokenizer_version: u32,
}

/// Result from a reindex operation.
#[derive(Debug)]
pub struct IndexReindexResult {
    pub name: String,
    pub tokenizer_version: u32,
    pub entries_cleared: u64,
}

/// Search parameters bundled to keep the `search()` signature below the
/// arity lint threshold once actor identity is threaded through.
#[derive(Debug, Clone, Copy)]
pub struct SearchOptions<'a> {
    pub mode: MatchMode,
    pub field: Option<&'a str>,
    pub limit: Option<usize>,
    /// When `true`, `query` is interpreted as a base64-encoded `BlindTokenSet`
    /// JSON (E2EE mode). When `false`, `query` is plaintext to be tokenized
    /// and blinded server-side.
    pub blind: bool,
}

impl Default for SearchOptions<'_> {
    fn default() -> Self {
        Self {
            mode: MatchMode::Contains,
            field: None,
            limit: None,
            blind: false,
        }
    }
}

/// The unified Veil engine. Single entry point for all operations.
///
/// Generic over `S: Store` — works identically with `EmbeddedStore`
/// (in-process ShrouDB) or `RemoteStore` (TCP to ShrouDB server).
pub struct VeilEngine<S: Store> {
    pub(crate) indexes: IndexManager<S>,
    pub(crate) config: VeilConfig,
    policy_evaluator: Capability<Arc<dyn PolicyEvaluator>>,
    chronicle: Capability<Arc<dyn ChronicleOps>>,
}

impl<S: Store> VeilEngine<S> {
    /// Create a new Veil engine.
    ///
    /// Every capability slot is explicit: `Capability::Enabled(...)`,
    /// `Capability::DisabledForTests`, or
    /// `Capability::DisabledWithJustification("<reason>")`. Absence is
    /// never silent — operators must name why they're opting out.
    pub async fn new(
        store: Arc<S>,
        config: VeilConfig,
        policy_evaluator: Capability<Arc<dyn PolicyEvaluator>>,
        chronicle: Capability<Arc<dyn ChronicleOps>>,
    ) -> Result<Self, VeilError> {
        let indexes = IndexManager::new(store);
        indexes.init().await?;
        Ok(Self {
            indexes,
            config,
            policy_evaluator,
            chronicle,
        })
    }

    async fn check_policy(
        &self,
        resource_id: &str,
        action: &str,
        actor: Option<&str>,
    ) -> Result<(), VeilError> {
        let Some(evaluator) = self.policy_evaluator.as_ref() else {
            return Ok(());
        };
        let request = PolicyRequest {
            principal: PolicyPrincipal {
                id: actor.unwrap_or("").to_string(),
                roles: vec![],
                claims: Default::default(),
            },
            resource: PolicyResource {
                id: resource_id.to_string(),
                resource_type: "index".to_string(),
                attributes: Default::default(),
            },
            action: action.to_string(),
        };
        let decision = evaluator
            .evaluate(&request)
            .await
            .map_err(|e| VeilError::Internal(format!("policy evaluation: {e}")))?;
        if decision.effect == PolicyEffect::Deny {
            return Err(VeilError::PolicyDenied {
                action: action.to_string(),
                resource: resource_id.to_string(),
                policy: decision.matched_policy.unwrap_or_default(),
            });
        }
        Ok(())
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
        let Some(chronicle) = self.chronicle.as_ref() else {
            return Ok(());
        };
        let mut event = Event::new(
            AuditEngine::Veil,
            operation.to_string(),
            "index".to_string(),
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

    pub async fn index_create(
        &self,
        name: &str,
        actor: Option<&str>,
    ) -> Result<IndexInfoResult, VeilError> {
        let start = Instant::now();
        self.check_policy(name, "index_create", actor).await?;
        let idx = self.indexes.create(name).await?;
        self.emit_audit_event("INDEX_CREATE", name, EventResult::Ok, None, start)
            .await?;
        Ok(IndexInfoResult {
            name: idx.name.clone(),
            created_at: idx.created_at,
            entry_count: 0,
            tokenizer_version: idx.tokenizer_version,
        })
    }

    pub async fn index_rotate(
        &self,
        name: &str,
        actor: Option<&str>,
    ) -> Result<IndexInfoResult, VeilError> {
        let start = Instant::now();
        self.check_policy(name, "index_rotate", actor).await?;
        let idx = self.indexes.rotate(name).await?;
        self.emit_audit_event("INDEX_ROTATE", name, EventResult::Ok, None, start)
            .await?;
        Ok(IndexInfoResult {
            name: idx.name.clone(),
            created_at: idx.created_at,
            entry_count: 0,
            tokenizer_version: idx.tokenizer_version,
        })
    }

    pub async fn index_destroy(&self, name: &str, actor: Option<&str>) -> Result<u64, VeilError> {
        let start = Instant::now();
        self.check_policy(name, "index_destroy", actor).await?;
        let deleted = self.indexes.destroy(name).await?;
        self.emit_audit_event("INDEX_DESTROY", name, EventResult::Ok, None, start)
            .await?;
        Ok(deleted)
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
            tokenizer_version: idx.tokenizer_version,
        })
    }

    pub async fn index_reindex(
        &self,
        name: &str,
        actor: Option<&str>,
    ) -> Result<IndexReindexResult, VeilError> {
        let start = Instant::now();
        self.check_policy(name, "index_reindex", actor).await?;
        let (idx, deleted) = self.indexes.reindex(name).await?;
        self.emit_audit_event("INDEX_REINDEX", name, EventResult::Ok, None, start)
            .await?;
        Ok(IndexReindexResult {
            name: idx.name.clone(),
            tokenizer_version: idx.tokenizer_version,
            entries_cleared: deleted,
        })
    }

    /// Access the index manager (for seeding from config).
    pub fn index_manager(&self) -> &IndexManager<S> {
        &self.indexes
    }

    /// Check that the index's tokenizer version matches the current version.
    /// Returns an error if the index was built with an older tokenizer.
    fn check_tokenizer_version(
        &self,
        index: &shroudb_veil_core::index::BlindIndex,
    ) -> Result<(), VeilError> {
        if index.tokenizer_version != TOKENIZER_VERSION {
            return Err(VeilError::InvalidArgument(format!(
                "index '{}' uses tokenizer v{} but current is v{}; run INDEX REINDEX to migrate",
                index.name, index.tokenizer_version, TOKENIZER_VERSION,
            )));
        }
        Ok(())
    }

    // ── Tokenize (pure, no storage) ───────────────────────────────

    pub fn tokenize(
        &self,
        index_name: &str,
        plaintext_b64: &str,
        field: Option<&str>,
    ) -> Result<TokenizeResult, VeilError> {
        let idx = self.indexes.get(index_name)?;
        self.check_tokenizer_version(&idx)?;
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

    /// Store an entry in a blind index.
    ///
    /// When `blind` is false (default): `data_b64` is base64-encoded plaintext.
    /// The server tokenizes, blinds with the index HMAC key, and stores.
    ///
    /// When `blind` is true (E2EE): `data_b64` is base64-encoded JSON
    /// `BlindTokenSet`. The client already tokenized and blinded — the server
    /// stores directly without touching plaintext.
    pub async fn put(
        &self,
        index_name: &str,
        id: &str,
        data_b64: &str,
        field: Option<&str>,
        blind: bool,
        actor: Option<&str>,
    ) -> Result<u64, VeilError> {
        let start = Instant::now();
        self.check_policy(index_name, "put", actor).await?;
        if id.is_empty() {
            return Err(VeilError::InvalidArgument(
                "entry ID cannot be empty".into(),
            ));
        }

        let (value, new_tokens) = if blind {
            // E2EE mode: data_b64 is base64-encoded BlindTokenSet JSON.
            // Validate it parses but don't need the index key.
            let _ = self.indexes.get(index_name)?;
            let json = decode_b64(data_b64)?;
            let tokens: BlindTokenSet = serde_json::from_slice(&json)
                .map_err(|e| VeilError::InvalidArgument(format!("invalid token set JSON: {e}")))?;
            (json, tokens)
        } else {
            // Standard mode: tokenize + blind server-side.
            let idx = self.indexes.get(index_name)?;
            self.check_tokenizer_version(&idx)?;
            let plaintext = decode_b64(data_b64)?;
            let text = tokenizer::extract_text(&plaintext, field);
            let tokens = tokenizer::tokenize(&text);
            let key = decode_key(&idx)?;
            let blind_tokens = hmac_ops::blind_token_set(&key, &tokens);
            let serialized = serde_json::to_vec(&blind_tokens)
                .map_err(|e| VeilError::Internal(format!("serialization failed: {e}")))?;
            (serialized, blind_tokens)
        };

        let ns = tokens_namespace(index_name);

        // Check whether this is a new entry or an update to an existing one.
        // If it's an update, load the old tokens so we can remove them from the
        // inverted index before adding new ones.
        let old_tokens = match self.indexes.store().get(&ns, id.as_bytes(), None).await {
            Ok(entry) => serde_json::from_slice::<BlindTokenSet>(&entry.value).ok(),
            Err(_) => None,
        };
        let is_new = old_tokens.is_none();

        // Enforce index size limit on new entries (updates always allowed).
        if is_new && self.config.max_entries_per_index > 0 {
            let current = self.indexes.entry_count(index_name);
            if current >= self.config.max_entries_per_index {
                return Err(VeilError::InvalidArgument(format!(
                    "index '{index_name}' is at capacity ({current}/{} entries)",
                    self.config.max_entries_per_index,
                )));
            }
        }

        // If updating, remove old tokens from inverted index first.
        if let Some(ref old) = old_tokens {
            self.indexes.inv_remove(index_name, id, old).await?;
        }

        let version = self
            .indexes
            .store()
            .put(&ns, id.as_bytes(), &value, None)
            .await
            .map_err(|e| VeilError::Store(e.to_string()))?;

        // Add new tokens to inverted index.
        self.indexes.inv_add(index_name, id, &new_tokens).await?;

        if is_new {
            self.indexes.increment_entry_count(index_name);
        }

        let resource = format!("{index_name}/{id}");
        self.emit_audit_event("PUT", &resource, EventResult::Ok, None, start)
            .await?;
        Ok(version)
    }

    // ── Delete ────────────────────────────────────────────────────

    pub async fn delete(
        &self,
        index_name: &str,
        id: &str,
        actor: Option<&str>,
    ) -> Result<(), VeilError> {
        let start = Instant::now();
        self.check_policy(index_name, "delete", actor).await?;
        let _ = self.indexes.get(index_name)?;
        let ns = tokens_namespace(index_name);

        // Load the entry's tokens before deleting so we can remove them from
        // the inverted index.
        let old_tokens = match self.indexes.store().get(&ns, id.as_bytes(), None).await {
            Ok(entry) => serde_json::from_slice::<BlindTokenSet>(&entry.value).ok(),
            Err(_) => None,
        };

        // Remove from inverted index before deleting the entry.
        if let Some(ref tokens) = old_tokens {
            self.indexes.inv_remove(index_name, id, tokens).await?;
        }

        self.indexes
            .store()
            .delete(&ns, id.as_bytes())
            .await
            .map_err(|e| VeilError::Store(e.to_string()))?;

        if old_tokens.is_some() {
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
        _actor: Option<&str>,
    ) -> Result<ReconcileResult, VeilError> {
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

    /// Search a blind index.
    ///
    /// When `blind` is false (default): `query` is plain text. The server
    /// tokenizes and blinds it with the index HMAC key before scanning.
    ///
    /// When `blind` is true (E2EE): `query` is base64-encoded JSON
    /// `BlindTokenSet`. The client already tokenized and blinded — the
    /// server decodes and scans directly.
    pub async fn search(
        &self,
        index_name: &str,
        query: &str,
        opts: SearchOptions<'_>,
        actor: Option<&str>,
    ) -> Result<SearchResult, VeilError> {
        let SearchOptions {
            mode,
            field: _field,
            limit,
            blind,
        } = opts;
        let start = Instant::now();
        self.check_policy(index_name, "search", actor).await?;
        if query.is_empty() {
            return Err(VeilError::InvalidArgument("query cannot be empty".into()));
        }

        let query_blind = if blind {
            // E2EE mode: query is base64-encoded BlindTokenSet JSON.
            let _ = self.indexes.get(index_name)?;
            let json = decode_b64(query)?;
            let tokens: BlindTokenSet = serde_json::from_slice(&json)
                .map_err(|e| VeilError::InvalidArgument(format!("invalid token set JSON: {e}")))?;
            if tokens.words.is_empty() && tokens.trigrams.is_empty() {
                return Err(VeilError::InvalidArgument(
                    "query tokens cannot be empty".into(),
                ));
            }
            tokens
        } else {
            // Standard mode: tokenize + blind server-side.
            let idx = self.indexes.get(index_name)?;
            self.check_tokenizer_version(&idx)?;
            let key = decode_key(&idx)?;
            let query_tokens = tokenizer::tokenize(query);
            hmac_ops::blind_token_set(&key, &query_tokens)
        };

        let limit = limit.unwrap_or(self.config.default_result_limit);
        let result = self
            .search_via_index(index_name, &query_blind, mode, limit)
            .await?;

        let _ = self
            .emit_audit_event("SEARCH", index_name, EventResult::Ok, None, start)
            .await;
        Ok(result)
    }

    // ── Internal helpers ─────────────────────────────────────────

    /// Linear scan fallback: scan all entries in an index, scoring each against
    /// query tokens. Keeps only the top-`limit` hits in a bounded min-heap.
    /// Retained as a fallback for cases where the inverted index is unavailable.
    async fn _scan_entries_linear(
        &self,
        index_name: &str,
        query_blind: &BlindTokenSet,
        mode: MatchMode,
        limit: usize,
    ) -> Result<SearchResult, VeilError> {
        let ns = tokens_namespace(index_name);
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

                if let Some(score) = search::score_entry(mode, query_blind, &entry_blind) {
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

        Ok(SearchResult {
            hits,
            scanned,
            matched,
        })
    }

    /// Search using the inverted index for O(1) token lookups instead of
    /// scanning all entries.
    async fn search_via_index(
        &self,
        index_name: &str,
        query_blind: &BlindTokenSet,
        mode: MatchMode,
        limit: usize,
    ) -> Result<SearchResult, VeilError> {
        let ns = tokens_namespace(index_name);

        // Step 1: Get candidate entry IDs from inverted index
        let candidates = match mode {
            MatchMode::Exact => {
                // Intersection of all query word posting lists
                if query_blind.words.is_empty() {
                    return Ok(SearchResult {
                        hits: vec![],
                        scanned: 0,
                        matched: 0,
                    });
                }
                let mut sets: Vec<HashSet<String>> = Vec::new();
                for token in &query_blind.words {
                    let ids = self.indexes.inv_lookup(index_name, token).await;
                    sets.push(ids.into_iter().collect());
                }
                let mut result = sets.remove(0);
                for set in &sets {
                    result.retain(|id| set.contains(id));
                }
                result
            }
            MatchMode::Contains => {
                // Union of all query word posting lists
                let mut result = HashSet::new();
                for token in &query_blind.words {
                    let ids = self.indexes.inv_lookup(index_name, token).await;
                    result.extend(ids);
                }
                result
            }
            MatchMode::Prefix | MatchMode::Fuzzy => {
                // Union of all query trigram posting lists
                if query_blind.trigrams.is_empty() {
                    // Fall back to word-based contains
                    let mut result = HashSet::new();
                    for token in &query_blind.words {
                        let ids = self.indexes.inv_lookup(index_name, token).await;
                        result.extend(ids);
                    }
                    result
                } else {
                    let mut result = HashSet::new();
                    for token in &query_blind.trigrams {
                        let ids = self.indexes.inv_lookup(index_name, token).await;
                        result.extend(ids);
                    }
                    result
                }
            }
        };

        // Step 2: Fetch full token sets for candidates and score them
        let mut heap: BinaryHeap<MinScoreHit> = BinaryHeap::with_capacity(limit + 1);
        let scanned = candidates.len();
        let mut matched = 0usize;

        for entry_id in candidates {
            let entry = match self
                .indexes
                .store()
                .get(&ns, entry_id.as_bytes(), None)
                .await
            {
                Ok(e) => e,
                Err(_) => continue, // Stale posting list entry
            };

            let entry_blind: BlindTokenSet = match serde_json::from_slice(&entry.value) {
                Ok(b) => b,
                Err(_) => continue,
            };

            if let Some(score) = search::score_entry(mode, query_blind, &entry_blind) {
                matched += 1;
                heap.push(MinScoreHit(SearchHit {
                    id: entry_id,
                    score,
                }));
                if heap.len() > limit {
                    heap.pop();
                }
            }
        }

        let mut hits = Vec::with_capacity(heap.len());
        while let Some(MinScoreHit(hit)) = heap.pop() {
            hits.push(hit);
        }
        hits.reverse();

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
        VeilEngine::new(
            store,
            VeilConfig::default(),
            Capability::DisabledForTests,
            Capability::DisabledForTests,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn put_and_search_exact() {
        let engine = setup().await;
        engine.index_create("users", None).await.unwrap();

        engine
            .put(
                "users",
                "1",
                &STANDARD.encode(b"Alice Johnson"),
                None,
                false,
                None,
            )
            .await
            .unwrap();
        engine
            .put(
                "users",
                "2",
                &STANDARD.encode(b"Bob Smith"),
                None,
                false,
                None,
            )
            .await
            .unwrap();
        engine
            .put(
                "users",
                "3",
                &STANDARD.encode(b"Charlie Johnson"),
                None,
                false,
                None,
            )
            .await
            .unwrap();

        let result = engine
            .search(
                "users",
                "johnson",
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.matched, 2);
        // With the inverted index, only candidate entries are scanned (not all 3).
        assert_eq!(result.scanned, 2);
    }

    #[tokio::test]
    async fn put_and_search_contains() {
        let engine = setup().await;
        engine.index_create("messages", None).await.unwrap();

        engine
            .put(
                "messages",
                "m1",
                &STANDARD.encode(b"hello world foo bar"),
                None,
                false,
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
                false,
                None,
            )
            .await
            .unwrap();

        let result = engine
            .search(
                "messages",
                "hello world",
                SearchOptions {
                    mode: MatchMode::Contains,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
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
        engine.index_create("contacts", None).await.unwrap();

        let data = serde_json::json!({"name": "Alice", "city": "Portland"});
        engine
            .put(
                "contacts",
                "c1",
                &STANDARD.encode(data.to_string().as_bytes()),
                Some("name"),
                false,
                None,
            )
            .await
            .unwrap();

        let result = engine
            .search(
                "contacts",
                "alice",
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.matched, 1);
    }

    #[tokio::test]
    async fn delete_entry() {
        let engine = setup().await;
        engine.index_create("test", None).await.unwrap();

        engine
            .put("test", "a", &STANDARD.encode(b"hello"), None, false, None)
            .await
            .unwrap();
        engine.delete("test", "a", None).await.unwrap();

        let result = engine
            .search(
                "test",
                "hello",
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.matched, 0);
    }

    #[tokio::test]
    async fn tokenize_returns_blind_tokens() {
        let engine = setup().await;
        engine.index_create("test", None).await.unwrap();

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
        engine.index_create("test", None).await.unwrap();

        for i in 0..10 {
            engine
                .put(
                    "test",
                    &format!("e{i}"),
                    &STANDARD.encode(b"common word"),
                    None,
                    false,
                    None,
                )
                .await
                .unwrap();
        }

        let result = engine
            .search(
                "test",
                "common",
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: Some(3),
                    blind: false,
                },
                None,
            )
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
        engine.index_create("test", None).await.unwrap();

        let err = engine
            .search(
                "test",
                "",
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn nonexistent_index_rejected() {
        let engine = setup().await;

        let err = engine
            .search(
                "nope",
                "query",
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn index_info_returns_entry_count() {
        let engine = setup().await;
        engine.index_create("test", None).await.unwrap();

        engine
            .put("test", "a", &STANDARD.encode(b"hello"), None, false, None)
            .await
            .unwrap();
        engine
            .put("test", "b", &STANDARD.encode(b"world"), None, false, None)
            .await
            .unwrap();

        let info = engine.index_info("test").await.unwrap();
        assert_eq!(info.name, "test");
        assert_eq!(info.entry_count, 2);
    }

    #[tokio::test]
    async fn test_reconcile_removes_orphans() {
        let engine = setup().await;
        engine.index_create("test", None).await.unwrap();

        engine
            .put("test", "a", &STANDARD.encode(b"alpha"), None, false, None)
            .await
            .unwrap();
        engine
            .put("test", "b", &STANDARD.encode(b"bravo"), None, false, None)
            .await
            .unwrap();
        engine
            .put("test", "c", &STANDARD.encode(b"charlie"), None, false, None)
            .await
            .unwrap();

        // Only "b" is valid — "a" and "c" are orphans.
        let result = engine
            .reconcile_orphans("test", &["b".to_string()], None)
            .await
            .unwrap();
        assert_eq!(result.orphans_removed, 2);

        // Verify entry count reflects removals.
        let info = engine.index_info("test").await.unwrap();
        assert_eq!(info.entry_count, 1);

        // Verify only "b" remains searchable.
        let search = engine
            .search(
                "test",
                "bravo",
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(search.matched, 1);
        assert_eq!(search.hits[0].id, "b");

        let search = engine
            .search(
                "test",
                "alpha",
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(search.matched, 0);
    }

    #[tokio::test]
    async fn test_reconcile_no_orphans() {
        let engine = setup().await;
        engine.index_create("test", None).await.unwrap();

        engine
            .put("test", "a", &STANDARD.encode(b"alpha"), None, false, None)
            .await
            .unwrap();
        engine
            .put("test", "b", &STANDARD.encode(b"bravo"), None, false, None)
            .await
            .unwrap();
        engine
            .put("test", "c", &STANDARD.encode(b"charlie"), None, false, None)
            .await
            .unwrap();

        // All three are valid — nothing to remove.
        let result = engine
            .reconcile_orphans(
                "test",
                &["a".to_string(), "b".to_string(), "c".to_string()],
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.orphans_removed, 0);

        let info = engine.index_info("test").await.unwrap();
        assert_eq!(info.entry_count, 3);
    }

    #[tokio::test]
    async fn test_reconcile_empty_index() {
        let engine = setup().await;
        engine.index_create("test", None).await.unwrap();

        let result = engine
            .reconcile_orphans("test", &["a".to_string()], None)
            .await
            .unwrap();
        assert_eq!(result.orphans_removed, 0);
    }

    #[tokio::test]
    async fn fuzzy_search_finds_similar() {
        let engine = setup().await;
        engine.index_create("test", None).await.unwrap();

        engine
            .put("test", "1", &STANDARD.encode(b"hello"), None, false, None)
            .await
            .unwrap();
        engine
            .put(
                "test",
                "2",
                &STANDARD.encode(b"helicopter"),
                None,
                false,
                None,
            )
            .await
            .unwrap();
        engine
            .put("test", "3", &STANDARD.encode(b"goodbye"), None, false, None)
            .await
            .unwrap();

        let result = engine
            .search(
                "test",
                "helo",
                SearchOptions {
                    mode: MatchMode::Fuzzy,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await
            .unwrap();

        // "helo" shares trigrams with "hello" (hel) and "helicopter" (hel)
        // but not with "goodbye"
        assert!(result.matched >= 1);
        assert!(result.hits.iter().all(|h| h.id != "3"));
    }

    #[tokio::test]
    async fn test_policy_denied_blocks_put() {
        use shroudb_acl::{
            PolicyDecision, PolicyEffect, PolicyEvaluator, PolicyRequest, error::AclError,
        };
        use std::pin::Pin;

        struct DenyAll;
        impl PolicyEvaluator for DenyAll {
            fn evaluate(
                &self,
                _request: &PolicyRequest,
            ) -> Pin<
                Box<dyn std::future::Future<Output = Result<PolicyDecision, AclError>> + Send + '_>,
            > {
                Box::pin(async {
                    Ok(PolicyDecision {
                        effect: PolicyEffect::Deny,
                        matched_policy: Some("deny-all".to_string()),
                        token: None,
                        cache_until: None,
                    })
                })
            }
        }

        let store = shroudb_storage::test_util::create_test_store("veil-policy-test").await;
        let engine = VeilEngine::new(
            store,
            VeilConfig::default(),
            Capability::Enabled(Arc::new(DenyAll)),
            Capability::DisabledForTests,
        )
        .await
        .unwrap();

        // index_create should be denied by policy
        let err = engine.index_create("test", None).await;
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("policy denied"),
            "expected policy denied error, got: {msg}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_put_to_same_index() {
        let engine = Arc::new(setup().await);
        engine.index_create("concurrent", None).await.unwrap();

        // Use unique words per entry to avoid concurrent writes to the same
        // inverted index posting list (which is a read-modify-write operation).
        let mut handles = Vec::new();
        for i in 0..10 {
            let eng = engine.clone();
            handles.push(tokio::spawn(async move {
                eng.put(
                    "concurrent",
                    &format!("entry-{i}"),
                    &STANDARD.encode(format!("uniqueprefix{i}").as_bytes()),
                    None,
                    false,
                    None,
                )
                .await
            }));
        }

        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        // Verify all entries are present.
        let info = engine.index_info("concurrent").await.unwrap();
        assert_eq!(info.entry_count, 10, "all 10 entries must be indexed");

        // Verify each entry is individually searchable.
        for i in 0..10 {
            let result = engine
                .search(
                    "concurrent",
                    &format!("uniqueprefix{i}"),
                    SearchOptions {
                        mode: MatchMode::Exact,
                        field: None,
                        limit: None,
                        blind: false,
                    },
                    None,
                )
                .await
                .unwrap();
            assert_eq!(
                result.matched, 1,
                "uniqueprefix{i} should match exactly 1 entry"
            );
            assert_eq!(result.hits[0].id, format!("entry-{i}"));
        }
    }

    #[tokio::test]
    async fn index_size_limit_enforced() {
        let store = shroudb_storage::test_util::create_test_store("veil-limit-test").await;
        let config = VeilConfig {
            max_entries_per_index: 3,
            ..Default::default()
        };
        let engine = VeilEngine::new(
            store,
            config,
            Capability::DisabledForTests,
            Capability::DisabledForTests,
        )
        .await
        .unwrap();
        engine.index_create("limited", None).await.unwrap();

        // Insert 3 entries — all should succeed
        for i in 0..3 {
            engine
                .put(
                    "limited",
                    &format!("e-{i}"),
                    &STANDARD.encode(format!("val-{i}")),
                    None,
                    false,
                    None,
                )
                .await
                .unwrap();
        }

        // 4th entry should be rejected
        let err = engine
            .put(
                "limited",
                "e-3",
                &STANDARD.encode("val-3"),
                None,
                false,
                None,
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("capacity"),
            "expected capacity error, got: {err}"
        );

        // Updating an existing entry should still work (not a new entry)
        engine
            .put(
                "limited",
                "e-0",
                &STANDARD.encode("updated-0"),
                None,
                false,
                None,
            )
            .await
            .unwrap();
    }

    // ── Blind (E2EE) operation tests ─────────────────────────────

    /// Encode a BlindTokenSet as base64 JSON (what clients send in BLIND mode).
    fn blind_b64(key: &[u8], text: &str) -> String {
        let secret = shroudb_crypto::SecretBytes::new(key.to_vec());
        let tokens = shroudb_veil_core::tokenizer::tokenize(text);
        let blind = hmac_ops::blind_token_set(&secret, &tokens);
        let json = serde_json::to_vec(&blind).unwrap();
        STANDARD.encode(&json)
    }

    #[tokio::test]
    async fn blind_put_and_search_exact() {
        let engine = setup().await;
        engine.index_create("e2ee", None).await.unwrap();

        let client_key = [0x42u8; 32];

        engine
            .put(
                "e2ee",
                "m1",
                &blind_b64(&client_key, "hello world"),
                None,
                true,
                None,
            )
            .await
            .unwrap();
        engine
            .put(
                "e2ee",
                "m2",
                &blind_b64(&client_key, "goodbye world"),
                None,
                true,
                None,
            )
            .await
            .unwrap();

        let result = engine
            .search(
                "e2ee",
                &blind_b64(&client_key, "hello"),
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: true,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.matched, 1);
        assert_eq!(result.hits[0].id, "m1");
    }

    #[tokio::test]
    async fn blind_put_and_search_contains() {
        let engine = setup().await;
        engine.index_create("e2ee", None).await.unwrap();

        let client_key = [0x42u8; 32];

        engine
            .put(
                "e2ee",
                "m1",
                &blind_b64(&client_key, "hello world foo"),
                None,
                true,
                None,
            )
            .await
            .unwrap();
        engine
            .put(
                "e2ee",
                "m2",
                &blind_b64(&client_key, "goodbye world bar"),
                None,
                true,
                None,
            )
            .await
            .unwrap();

        let result = engine
            .search(
                "e2ee",
                &blind_b64(&client_key, "hello world"),
                SearchOptions {
                    mode: MatchMode::Contains,
                    field: None,
                    limit: None,
                    blind: true,
                },
                None,
            )
            .await
            .unwrap();

        assert_eq!(result.matched, 2);
        assert!(result.hits[0].score > result.hits[1].score);
    }

    #[tokio::test]
    async fn blind_search_empty_tokens_rejected() {
        let engine = setup().await;
        engine.index_create("e2ee", None).await.unwrap();

        let empty_json = STANDARD.encode(br#"{"words":[],"trigrams":[]}"#);
        let err = engine
            .search(
                "e2ee",
                &empty_json,
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: true,
                },
                None,
            )
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn blind_put_empty_id_rejected() {
        let engine = setup().await;
        engine.index_create("e2ee", None).await.unwrap();

        let client_key = [0x42u8; 32];
        let err = engine
            .put(
                "e2ee",
                "",
                &blind_b64(&client_key, "test"),
                None,
                true,
                None,
            )
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn blind_put_respects_index_limit() {
        let store = shroudb_storage::test_util::create_test_store("veil-blind-limit").await;
        let config = VeilConfig {
            max_entries_per_index: 2,
            ..Default::default()
        };
        let engine = VeilEngine::new(
            store,
            config,
            Capability::DisabledForTests,
            Capability::DisabledForTests,
        )
        .await
        .unwrap();
        engine.index_create("limited", None).await.unwrap();

        let client_key = [0x42u8; 32];
        engine
            .put(
                "limited",
                "m1",
                &blind_b64(&client_key, "first"),
                None,
                true,
                None,
            )
            .await
            .unwrap();
        engine
            .put(
                "limited",
                "m2",
                &blind_b64(&client_key, "second"),
                None,
                true,
                None,
            )
            .await
            .unwrap();

        let err = engine
            .put(
                "limited",
                "m3",
                &blind_b64(&client_key, "third"),
                None,
                true,
                None,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("capacity"));

        // Update existing should still work
        engine
            .put(
                "limited",
                "m1",
                &blind_b64(&client_key, "updated"),
                None,
                true,
                None,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn blind_put_nonexistent_index_rejected() {
        let engine = setup().await;

        let client_key = [0x42u8; 32];
        let err = engine
            .put(
                "nope",
                "m1",
                &blind_b64(&client_key, "test"),
                None,
                true,
                None,
            )
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn blind_search_nonexistent_index_rejected() {
        let engine = setup().await;

        let client_key = [0x42u8; 32];
        let err = engine
            .search(
                "nope",
                &blind_b64(&client_key, "test"),
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: true,
                },
                None,
            )
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn blind_put_search_fuzzy() {
        let engine = setup().await;
        engine.index_create("e2ee", None).await.unwrap();

        let client_key = [0x42u8; 32];
        engine
            .put(
                "e2ee",
                "m1",
                &blind_b64(&client_key, "hello"),
                None,
                true,
                None,
            )
            .await
            .unwrap();
        engine
            .put(
                "e2ee",
                "m2",
                &blind_b64(&client_key, "helicopter"),
                None,
                true,
                None,
            )
            .await
            .unwrap();
        engine
            .put(
                "e2ee",
                "m3",
                &blind_b64(&client_key, "goodbye"),
                None,
                true,
                None,
            )
            .await
            .unwrap();

        let result = engine
            .search(
                "e2ee",
                &blind_b64(&client_key, "helo"),
                SearchOptions {
                    mode: MatchMode::Fuzzy,
                    field: None,
                    limit: None,
                    blind: true,
                },
                None,
            )
            .await
            .unwrap();

        assert!(result.matched >= 1);
        assert!(result.hits.iter().all(|h| h.id != "m3"));
    }

    #[tokio::test]
    async fn blind_put_delete_and_search() {
        let engine = setup().await;
        engine.index_create("e2ee", None).await.unwrap();

        let client_key = [0x42u8; 32];
        engine
            .put(
                "e2ee",
                "m1",
                &blind_b64(&client_key, "hello"),
                None,
                true,
                None,
            )
            .await
            .unwrap();

        engine.delete("e2ee", "m1", None).await.unwrap();

        let result = engine
            .search(
                "e2ee",
                &blind_b64(&client_key, "hello"),
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: true,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.matched, 0);
    }

    #[tokio::test]
    async fn blind_put_invalid_json_rejected() {
        let engine = setup().await;
        engine.index_create("e2ee", None).await.unwrap();

        // Valid base64 but not valid BlindTokenSet JSON
        let bad = STANDARD.encode(b"not json");
        let err = engine.put("e2ee", "m1", &bad, None, true, None).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn rotate_produces_new_key_and_clears_entries() {
        let engine = setup().await;
        engine.index_create("rot-test", None).await.unwrap();

        // Add entries
        let data = STANDARD.encode("hello world");
        engine
            .put("rot-test", "e1", &data, None, false, None)
            .await
            .unwrap();
        engine
            .put("rot-test", "e2", &data, None, false, None)
            .await
            .unwrap();

        // Search finds them
        let result = engine
            .search(
                "rot-test",
                "hello",
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.matched, 2);

        // Rotate
        let info = engine.index_rotate("rot-test", None).await.unwrap();
        assert_eq!(info.entry_count, 0);

        // Old tokens are gone — search returns nothing
        let result = engine
            .search(
                "rot-test",
                "hello",
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.matched, 0);

        // Re-index with new key works
        engine
            .put("rot-test", "e1", &data, None, false, None)
            .await
            .unwrap();
        let result = engine
            .search(
                "rot-test",
                "hello",
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.matched, 1);
    }

    #[tokio::test]
    async fn destroy_removes_index_and_entries() {
        let engine = setup().await;
        engine.index_create("destroy-test", None).await.unwrap();

        // Add entries
        let data = STANDARD.encode("hello world");
        engine
            .put("destroy-test", "e1", &data, None, false, None)
            .await
            .unwrap();
        engine
            .put("destroy-test", "e2", &data, None, false, None)
            .await
            .unwrap();

        // Destroy
        let deleted = engine.index_destroy("destroy-test", None).await.unwrap();
        assert_eq!(deleted, 2);

        // Index no longer exists — PUT should fail
        let err = engine
            .put("destroy-test", "e3", &data, None, false, None)
            .await;
        assert!(err.is_err(), "PUT to destroyed index should fail");

        // SEARCH should fail
        let err = engine
            .search(
                "destroy-test",
                "hello",
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await;
        assert!(err.is_err(), "SEARCH on destroyed index should fail");

        // INDEX INFO should fail
        let err = engine.index_info("destroy-test").await;
        assert!(err.is_err(), "INFO on destroyed index should fail");

        // Index not in list
        let list = engine.index_list();
        assert!(
            !list.contains(&"destroy-test".to_string()),
            "destroyed index should not appear in list"
        );
    }

    #[tokio::test]
    async fn destroy_nonexistent_fails() {
        let engine = setup().await;
        let err = engine.index_destroy("nope", None).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn destroy_then_recreate() {
        let engine = setup().await;
        engine.index_create("reuse-test", None).await.unwrap();

        let data = STANDARD.encode("original");
        engine
            .put("reuse-test", "e1", &data, None, false, None)
            .await
            .unwrap();

        // Destroy
        engine.index_destroy("reuse-test", None).await.unwrap();

        // Recreate with fresh key
        engine.index_create("reuse-test", None).await.unwrap();

        // Old entries are gone
        let result = engine
            .search(
                "reuse-test",
                "original",
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            result.matched, 0,
            "old entries should not survive destroy+recreate"
        );

        // New entries work
        let data2 = STANDARD.encode("new data");
        engine
            .put("reuse-test", "e1", &data2, None, false, None)
            .await
            .unwrap();
        let result = engine
            .search(
                "reuse-test",
                "new",
                SearchOptions {
                    mode: MatchMode::Contains,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.matched, 1);
    }

    #[tokio::test]
    async fn reindex_clears_entries_and_preserves_key() {
        let engine = setup().await;
        engine.index_create("reindex-test", None).await.unwrap();

        // Get the original key material for comparison
        let original_key = engine
            .indexes
            .get("reindex-test")
            .unwrap()
            .key_material
            .clone();

        // Add entries
        let data = STANDARD.encode("hello world");
        engine
            .put("reindex-test", "e1", &data, None, false, None)
            .await
            .unwrap();
        engine
            .put("reindex-test", "e2", &data, None, false, None)
            .await
            .unwrap();
        assert_eq!(
            engine.index_info("reindex-test").await.unwrap().entry_count,
            2
        );

        // Reindex
        let result = engine.index_reindex("reindex-test", None).await.unwrap();
        assert_eq!(result.name, "reindex-test");
        assert_eq!(result.entries_cleared, 2);
        assert_eq!(result.tokenizer_version, TOKENIZER_VERSION);

        // Entries are cleared
        assert_eq!(
            engine.index_info("reindex-test").await.unwrap().entry_count,
            0
        );

        // Key is preserved — same key material
        let after_key = engine
            .indexes
            .get("reindex-test")
            .unwrap()
            .key_material
            .clone();
        assert_eq!(
            *original_key, *after_key,
            "key should be preserved after reindex"
        );

        // Re-add entries with same key and they should be searchable
        engine
            .put("reindex-test", "e1", &data, None, false, None)
            .await
            .unwrap();
        let search = engine
            .search(
                "reindex-test",
                "hello",
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(search.matched, 1);
    }

    #[tokio::test]
    async fn reindex_nonexistent_fails() {
        let engine = setup().await;
        let err = engine.index_reindex("nope", None).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn index_info_includes_tokenizer_version() {
        let engine = setup().await;
        engine.index_create("ver-test", None).await.unwrap();

        let info = engine.index_info("ver-test").await.unwrap();
        assert_eq!(info.tokenizer_version, TOKENIZER_VERSION);
    }

    #[tokio::test]
    async fn index_create_includes_tokenizer_version() {
        let engine = setup().await;
        let info = engine.index_create("ver-create", None).await.unwrap();
        assert_eq!(info.tokenizer_version, TOKENIZER_VERSION);
    }

    #[tokio::test]
    async fn inverted_index_search_over_many_entries() {
        let engine = setup().await;
        engine.index_create("inv-test", None).await.unwrap();

        // Put 100 entries with unique words
        for i in 0..100 {
            engine
                .put(
                    "inv-test",
                    &format!("e{i}"),
                    &STANDARD.encode(format!("uniqueword{i} common")),
                    None,
                    false,
                    None,
                )
                .await
                .unwrap();
        }

        // Search for a specific unique word — should find exactly 1 entry
        let result = engine
            .search(
                "inv-test",
                "uniqueword42",
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.matched, 1);
        assert_eq!(result.hits[0].id, "e42");
        // Inverted index should only scan the candidate entries, not all 100
        assert!(
            result.scanned < 100,
            "inverted index should skip non-matching entries, scanned: {}",
            result.scanned,
        );
    }

    #[tokio::test]
    async fn inverted_index_update_removes_old_tokens() {
        let engine = setup().await;
        engine.index_create("inv-update", None).await.unwrap();

        // Put entry with "alpha"
        engine
            .put(
                "inv-update",
                "e1",
                &STANDARD.encode("alpha"),
                None,
                false,
                None,
            )
            .await
            .unwrap();

        // Verify it's searchable by "alpha"
        let result = engine
            .search(
                "inv-update",
                "alpha",
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.matched, 1);

        // Update same entry to "bravo"
        engine
            .put(
                "inv-update",
                "e1",
                &STANDARD.encode("bravo"),
                None,
                false,
                None,
            )
            .await
            .unwrap();

        // "alpha" should no longer match
        let result = engine
            .search(
                "inv-update",
                "alpha",
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.matched, 0);

        // "bravo" should match
        let result = engine
            .search(
                "inv-update",
                "bravo",
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.matched, 1);
        assert_eq!(result.hits[0].id, "e1");

        // Entry count should still be 1 (update, not new)
        let info = engine.index_info("inv-update").await.unwrap();
        assert_eq!(info.entry_count, 1);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AUDIT_2026-04-17 — Hard-ratchet debt tests for Veil half-assed wiring.
//
// These tests encode the correct security behavior of the engine's Sentry
// and Chronicle capability integration. They are expected to FAIL against
// the current implementation. They must NOT be `#[ignore]`-d. Fix the code
// to make them pass; do NOT relax the tests.
// ═══════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod debt_tests {
    use super::*;
    use crate::test_support::{FailingChronicle, RecordingChronicle, RecordingSentry};

    async fn setup_with_caps(
        policy: Capability<Arc<dyn PolicyEvaluator>>,
        chron: Capability<Arc<dyn ChronicleOps>>,
    ) -> VeilEngine<shroudb_storage::EmbeddedStore> {
        let store = shroudb_storage::test_util::create_test_store("veil-debt").await;
        VeilEngine::new(store, VeilConfig::default(), policy, chron)
            .await
            .unwrap()
    }

    /// F-veil-1: engine::put/search/delete/index_* ALL call `check_policy`
    /// with `actor = None`. The engine has no way to receive caller identity,
    /// so every PolicyRequest.principal.id is empty. Sentry cannot make
    /// real access decisions without a principal.
    #[tokio::test]
    async fn debt_1_put_must_forward_actor_identity_to_sentry() {
        let (sentry, requests) = RecordingSentry::new();
        let engine =
            setup_with_caps(Capability::Enabled(sentry), Capability::DisabledForTests).await;
        engine.index_create("users", Some("admin")).await.unwrap();

        // Clear the create event.
        requests.lock().unwrap().clear();

        engine
            .put(
                "users",
                "e1",
                &STANDARD.encode("alice"),
                None,
                false,
                Some("alice-caller"),
            )
            .await
            .unwrap();

        let reqs = requests.lock().unwrap();
        let put_req = reqs
            .iter()
            .find(|r| r.action == "put")
            .expect("engine must issue a put policy request");
        assert!(
            !put_req.principal.id.is_empty(),
            "engine.put must forward the caller's actor id to Sentry, got empty id. \
             The engine signature currently has no way to receive actor identity \
             from the protocol/HTTP dispatch layer — this is the root bug."
        );
    }

    /// F-veil-2: emit_audit_event hardcodes `actor = None` at every call site
    /// in engine.rs. Every audit event Chronicle receives has
    /// actor="anonymous", making tamper-evident logs worthless for forensics.
    #[tokio::test]
    async fn debt_2_audit_event_must_record_real_actor_not_anonymous() {
        let (chron, events) = RecordingChronicle::new();
        let engine =
            setup_with_caps(Capability::DisabledForTests, Capability::Enabled(chron)).await;
        engine.index_create("users", None).await.unwrap();
        engine
            .put("users", "e1", &STANDARD.encode("alice"), None, false, None)
            .await
            .unwrap();

        let evs = events.lock().unwrap();
        let put_evt = evs
            .iter()
            .find(|e| e.operation == "PUT")
            .expect("engine.put must emit a PUT audit event");
        assert_ne!(
            put_evt.actor, "anonymous",
            "engine.put must forward the caller's actor id to Chronicle; \
             defaulting to 'anonymous' destroys forensic value"
        );
        assert!(!put_evt.actor.is_empty(), "audit actor must not be empty");
    }

    /// F-veil-3: search() line 549 uses `let _ = ... emit_audit_event(...)`
    /// silently swallowing Chronicle errors. All other operations propagate
    /// audit-sink failures, but search fails open — an attacker who takes
    /// down Chronicle can issue un-audited reads.
    #[tokio::test]
    async fn debt_3_search_must_fail_closed_when_chronicle_unreachable() {
        // Seed index + entry on a store with NO chronicle so PUT succeeds.
        let store = shroudb_storage::test_util::create_test_store("veil-debt-3").await;
        {
            let seed = VeilEngine::new(
                store.clone(),
                VeilConfig::default(),
                Capability::DisabledForTests,
                Capability::DisabledForTests,
            )
            .await
            .unwrap();
            seed.index_create("idx", None).await.unwrap();
            seed.put("idx", "e1", &STANDARD.encode("hello"), None, false, None)
                .await
                .unwrap();
        }

        // Reopen the SAME store with a failing chronicle and issue SEARCH.
        let engine = VeilEngine::new(
            store,
            VeilConfig::default(),
            Capability::DisabledForTests,
            Capability::Enabled(FailingChronicle::new()),
        )
        .await
        .unwrap();

        let result = engine
            .search(
                "idx",
                "hello",
                SearchOptions {
                    mode: MatchMode::Exact,
                    field: None,
                    limit: None,
                    blind: false,
                },
                None,
            )
            .await;
        assert!(
            result.is_err(),
            "search must fail closed when Chronicle is configured but unreachable; \
             the current `let _ = emit_audit_event(...)` swallows the error and \
             returns hits un-audited"
        );
    }

    /// F-veil-4: VeilServerConfig has no `[sentry]` or `[chronicle]` section
    /// and server/main.rs hardcodes `VeilEngine::new(store, veil_config, None, None)`.
    /// The engine *accepts* capabilities in its constructor but the binary
    /// never populates them — production deploys are silently running with
    /// no policy enforcement and no audit sink.
    ///
    /// Encoded here as a structural check: the server config must expose
    /// knobs for sentry_url / chronicle_url (the actual wiring lives in
    /// shroudb-veil-server and cannot be tested from the engine crate, so
    /// this test documents the debt via a compile-time assertion that the
    /// PolicyEvaluator trait object is the only accepted capability shape —
    /// if no test fails we would have no ratchet).
    #[tokio::test]
    async fn debt_4_engine_must_reject_missing_chronicle_in_enforcing_mode() {
        // Once the config/server wiring is added, a VeilConfig flag like
        // `require_audit: true` must make construction fail when
        // chronicle = None. Today VeilConfig has no such flag.
        let has_require_audit_flag = {
            // Reflect: try to construct a config with a hypothetical flag.
            // Because no such field exists, we force the test to fail by
            // asserting on an invariant the code does not yet satisfy.
            let _cfg = VeilConfig::default();
            false
        };
        assert!(
            has_require_audit_flag,
            "VeilConfig must expose a `require_audit`/`require_policy` flag that \
             fails engine construction when Chronicle/Sentry are absent. Today \
             the server binary passes `None, None` and the engine silently \
             accepts it — security capabilities declared in the type signature \
             are never populated in production."
        );
    }

    /// F-veil-5: search scoring thresholds (Prefix 0.6, Fuzzy 0.3) are
    /// hardcoded in search.rs. A deployer cannot tune relevance without
    /// recompiling, and there is no way to audit the chosen values. Policy
    /// should be explicit.
    #[tokio::test]
    async fn debt_5_search_score_thresholds_must_be_configurable() {
        let cfg = VeilConfig::default();
        // VeilConfig must expose `prefix_threshold` and `fuzzy_threshold`.
        // These fields do not yet exist. Replace the hardcoded constants
        // in search::score_entry with config-driven values.
        let has_configurable_thresholds = false;
        let _ = cfg;
        assert!(
            has_configurable_thresholds,
            "VeilConfig must expose `prefix_threshold` and `fuzzy_threshold` \
             fields consumed by search::score_entry. Today they are hardcoded \
             to 0.6 / 0.3 in search.rs."
        );
    }

    /// F-veil-6: When `blind=true`, the server accepts any base64-encoded
    /// JSON with `words:[]` / `trigrams:[]` keys. There is no structural
    /// validation that the strings are plausible HMAC outputs (e.g., 64-char
    /// hex). An attacker can poison an E2EE index with garbage tokens that
    /// will never match anything, causing silent search-result denial.
    #[tokio::test]
    async fn debt_6_blind_put_must_reject_non_hex_tokens() {
        let engine =
            setup_with_caps(Capability::DisabledForTests, Capability::DisabledForTests).await;
        engine.index_create("e2ee", None).await.unwrap();

        // Malformed token set: not hex, not 64 chars.
        let bad = serde_json::json!({
            "words": ["notHex!!", "alsoBad"],
            "trigrams": ["<script>", ""]
        });
        let payload = STANDARD.encode(serde_json::to_vec(&bad).unwrap());

        let result = engine.put("e2ee", "m1", &payload, None, true, None).await;
        assert!(
            result.is_err(),
            "blind PUT must reject token sets whose strings are not 64-char \
             lowercase hex (SHA-256 HMAC output shape). Today the server \
             stores arbitrary JSON strings without structural validation."
        );
    }
}
