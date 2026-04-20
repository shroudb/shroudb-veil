//! Store-backed blind index management with in-memory cache.
//!
//! All search operations read index configs from the in-memory DashMap cache.
//! Mutations write-through to the Store, then update the cache.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use shroudb_store::Store;
use shroudb_veil_core::error::VeilError;
use shroudb_veil_core::index::BlindIndex;

use shroudb_veil_core::tokenizer::TOKENIZER_VERSION;

use crate::hmac_ops::{self, BlindTokenSet};

const INDEXES_NAMESPACE: &str = "veil.indexes";

/// Manages blind indexes with a Store-backed persistence layer and in-memory cache.
pub struct IndexManager<S: Store> {
    store: Arc<S>,
    cache: DashMap<String, Arc<BlindIndex>>,
    /// Cached entry counts per index. Avoids full pagination scans for `index_info()`.
    entry_counts: DashMap<String, AtomicU64>,
}

impl<S: Store> IndexManager<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            cache: DashMap::new(),
            entry_counts: DashMap::new(),
        }
    }

    /// Initialize: create namespace and load all indexes into cache.
    pub async fn init(&self) -> Result<(), VeilError> {
        match self
            .store
            .namespace_create(INDEXES_NAMESPACE, shroudb_store::NamespaceConfig::default())
            .await
        {
            Ok(()) => {}
            Err(shroudb_store::StoreError::NamespaceExists(_)) => {}
            Err(e) => return Err(VeilError::Store(e.to_string())),
        }

        let mut cursor = None;
        loop {
            let page = self
                .store
                .list(INDEXES_NAMESPACE, None, cursor.as_deref(), 100)
                .await
                .map_err(|e| VeilError::Store(e.to_string()))?;

            for key in &page.keys {
                let entry = self
                    .store
                    .get(INDEXES_NAMESPACE, key, None)
                    .await
                    .map_err(|e| VeilError::Store(e.to_string()))?;
                let index: BlindIndex = serde_json::from_slice(&entry.value)
                    .map_err(|e| VeilError::Internal(format!("corrupt index data: {e}")))?;
                self.cache.insert(index.name.clone(), Arc::new(index));
            }

            if page.cursor.is_none() {
                break;
            }
            cursor = page.cursor;
        }

        let count = self.cache.len();
        if count > 0 {
            tracing::info!(count, "loaded blind indexes from store");
        }

        // Ensure inverted index namespaces exist for each loaded index.
        for entry in self.cache.iter() {
            let inv_ns = inv_namespace(entry.key());
            match self
                .store
                .namespace_create(&inv_ns, shroudb_store::NamespaceConfig::default())
                .await
            {
                Ok(()) => {}
                Err(shroudb_store::StoreError::NamespaceExists(_)) => {}
                Err(e) => return Err(VeilError::Store(e.to_string())),
            }
        }

        // Initialize entry counts for each loaded index by scanning token namespaces.
        for entry in self.cache.iter() {
            let name = entry.key();
            let ns = tokens_namespace(name);
            let mut entry_count = 0u64;
            let mut token_cursor = None;
            loop {
                let page = self
                    .store
                    .list(&ns, None, token_cursor.as_deref(), 100)
                    .await
                    .map_err(|e| VeilError::Store(e.to_string()))?;
                entry_count += page.keys.len() as u64;
                if page.cursor.is_none() {
                    break;
                }
                token_cursor = page.cursor;
            }
            self.entry_counts
                .insert(name.clone(), AtomicU64::new(entry_count));
        }

        Ok(())
    }

    /// Create a new blind index with a fresh HMAC key.
    pub async fn create(&self, name: &str) -> Result<Arc<BlindIndex>, VeilError> {
        validate_index_name(name)?;

        if self.cache.contains_key(name) {
            return Err(VeilError::IndexExists(name.to_string()));
        }

        let key_material = hmac_ops::generate_key_material()?;
        let now = unix_now();

        let index = BlindIndex {
            name: name.to_string(),
            key_material: zeroize::Zeroizing::new(hex::encode(key_material.as_bytes())),
            created_at: now,
            tokenizer_version: TOKENIZER_VERSION,
        };

        // Create the token storage namespace for this index
        let tokens_ns = tokens_namespace(name);
        match self
            .store
            .namespace_create(&tokens_ns, shroudb_store::NamespaceConfig::default())
            .await
        {
            Ok(()) => {}
            Err(shroudb_store::StoreError::NamespaceExists(_)) => {}
            Err(e) => return Err(VeilError::Store(e.to_string())),
        }

        // Create the inverted index namespace for this index
        let inv_ns = inv_namespace(name);
        match self
            .store
            .namespace_create(&inv_ns, shroudb_store::NamespaceConfig::default())
            .await
        {
            Ok(()) => {}
            Err(shroudb_store::StoreError::NamespaceExists(_)) => {}
            Err(e) => return Err(VeilError::Store(e.to_string())),
        }

        self.save(&index).await?;
        let index = Arc::new(index);
        self.cache.insert(name.to_string(), Arc::clone(&index));
        self.entry_counts
            .insert(name.to_string(), AtomicU64::new(0));

        tracing::info!(index = name, "blind index created");

        Ok(index)
    }

    /// Get a blind index by name from cache.
    pub fn get(&self, name: &str) -> Result<Arc<BlindIndex>, VeilError> {
        self.cache
            .get(name)
            .map(|r| Arc::clone(r.value()))
            .ok_or_else(|| VeilError::IndexNotFound(name.to_string()))
    }

    /// List all index names from cache.
    pub fn list(&self) -> Vec<String> {
        self.cache.iter().map(|r| r.key().clone()).collect()
    }

    /// Get the Store reference for direct entry operations.
    pub fn store(&self) -> &Arc<S> {
        &self.store
    }

    /// Rotate an index's HMAC key. Generates a new key, deletes all existing
    /// entries (they are invalid under the new key), and persists the updated index.
    ///
    /// After rotation, the application must re-index all entries with the new key.
    /// For blind-mode clients, the new key material can be retrieved via `INDEX INFO`.
    pub async fn rotate(&self, name: &str) -> Result<Arc<BlindIndex>, VeilError> {
        // Verify the index exists
        if !self.cache.contains_key(name) {
            return Err(VeilError::IndexNotFound(name.to_string()));
        }

        // Generate new key material
        let new_key = hmac_ops::generate_key_material()?;
        let now = unix_now();

        let updated = BlindIndex {
            name: name.to_string(),
            key_material: zeroize::Zeroizing::new(hex::encode(new_key.as_bytes())),
            created_at: now,
            tokenizer_version: TOKENIZER_VERSION,
        };

        // Delete all existing entries (they're invalid under the new key)
        let tokens_ns = tokens_namespace(name);
        let mut cursor = None;
        let mut deleted = 0u64;
        loop {
            let page = self
                .store
                .list(&tokens_ns, None, cursor.as_deref(), 100)
                .await
                .map_err(|e| VeilError::Store(e.to_string()))?;

            if page.keys.is_empty() {
                break;
            }

            for key in &page.keys {
                self.store
                    .delete(&tokens_ns, key)
                    .await
                    .map_err(|e| VeilError::Store(e.to_string()))?;
                deleted += 1;
            }

            cursor = page.cursor;
            if cursor.is_none() {
                break;
            }
        }

        // Delete all entries in the inverted index namespace
        let inv_ns = inv_namespace(name);
        let mut inv_cursor = None;
        loop {
            let page = self
                .store
                .list(&inv_ns, None, inv_cursor.as_deref(), 100)
                .await
                .map_err(|e| VeilError::Store(e.to_string()))?;

            if page.keys.is_empty() {
                break;
            }

            for key in &page.keys {
                self.store
                    .delete(&inv_ns, key)
                    .await
                    .map_err(|e| VeilError::Store(e.to_string()))?;
            }

            inv_cursor = page.cursor;
            if inv_cursor.is_none() {
                break;
            }
        }

        // Persist updated index
        self.save(&updated).await?;
        let updated = Arc::new(updated);
        self.cache.insert(name.to_string(), Arc::clone(&updated));

        // Reset entry count
        self.entry_counts
            .insert(name.to_string(), AtomicU64::new(0));

        tracing::info!(index = name, deleted_entries = deleted, "index key rotated");

        Ok(updated)
    }

    /// Re-index: clear all entries and update the tokenizer version to current.
    ///
    /// Unlike `rotate()`, this keeps the same HMAC key — it only clears entries
    /// that were built with an outdated tokenizer algorithm. After reindex, the
    /// application must re-submit all entries via PUT.
    pub async fn reindex(&self, name: &str) -> Result<(Arc<BlindIndex>, u64), VeilError> {
        let existing = self
            .cache
            .get(name)
            .map(|r| Arc::clone(r.value()))
            .ok_or_else(|| VeilError::IndexNotFound(name.to_string()))?;

        // Delete all existing entries
        let tokens_ns = tokens_namespace(name);
        let mut cursor = None;
        let mut deleted = 0u64;
        loop {
            let page = self
                .store
                .list(&tokens_ns, None, cursor.as_deref(), 100)
                .await
                .map_err(|e| VeilError::Store(e.to_string()))?;

            if page.keys.is_empty() {
                break;
            }

            for key in &page.keys {
                self.store
                    .delete(&tokens_ns, key)
                    .await
                    .map_err(|e| VeilError::Store(e.to_string()))?;
                deleted += 1;
            }

            cursor = page.cursor;
            if cursor.is_none() {
                break;
            }
        }

        // Delete all entries in the inverted index namespace
        let inv_ns = inv_namespace(name);
        let mut inv_cursor = None;
        loop {
            let page = self
                .store
                .list(&inv_ns, None, inv_cursor.as_deref(), 100)
                .await
                .map_err(|e| VeilError::Store(e.to_string()))?;

            if page.keys.is_empty() {
                break;
            }

            for key in &page.keys {
                self.store
                    .delete(&inv_ns, key)
                    .await
                    .map_err(|e| VeilError::Store(e.to_string()))?;
            }

            inv_cursor = page.cursor;
            if inv_cursor.is_none() {
                break;
            }
        }

        // Update tokenizer version, keep the same key material
        let updated = BlindIndex {
            name: name.to_string(),
            key_material: existing.key_material.clone(),
            created_at: existing.created_at,
            tokenizer_version: TOKENIZER_VERSION,
        };

        self.save(&updated).await?;
        let updated = Arc::new(updated);
        self.cache.insert(name.to_string(), Arc::clone(&updated));
        self.entry_counts
            .insert(name.to_string(), AtomicU64::new(0));

        tracing::info!(
            index = name,
            deleted_entries = deleted,
            tokenizer_version = TOKENIZER_VERSION,
            "index reindexed (entries cleared, tokenizer version updated)"
        );

        Ok((updated, deleted))
    }

    /// Destroy an index: zeroize key material, delete all entries, and remove
    /// the index from the Store and cache. After destruction, the index name
    /// can be reused via `INDEX CREATE`.
    pub async fn destroy(&self, name: &str) -> Result<u64, VeilError> {
        if !self.cache.contains_key(name) {
            return Err(VeilError::IndexNotFound(name.to_string()));
        }

        // Delete all entries in the token namespace
        let tokens_ns = tokens_namespace(name);
        let mut cursor = None;
        let mut deleted = 0u64;
        loop {
            let page = self
                .store
                .list(&tokens_ns, None, cursor.as_deref(), 100)
                .await
                .map_err(|e| VeilError::Store(e.to_string()))?;

            if page.keys.is_empty() {
                break;
            }

            for key in &page.keys {
                self.store
                    .delete(&tokens_ns, key)
                    .await
                    .map_err(|e| VeilError::Store(e.to_string()))?;
                deleted += 1;
            }

            cursor = page.cursor;
            if cursor.is_none() {
                break;
            }
        }

        // Delete all entries in the inverted index namespace
        let inv_ns = inv_namespace(name);
        let mut inv_cursor = None;
        loop {
            let page = self
                .store
                .list(&inv_ns, None, inv_cursor.as_deref(), 100)
                .await
                .map_err(|e| VeilError::Store(e.to_string()))?;

            if page.keys.is_empty() {
                break;
            }

            for key in &page.keys {
                self.store
                    .delete(&inv_ns, key)
                    .await
                    .map_err(|e| VeilError::Store(e.to_string()))?;
            }

            inv_cursor = page.cursor;
            if inv_cursor.is_none() {
                break;
            }
        }

        // Delete the index metadata from the Store (key material is zeroized
        // when the Arc<BlindIndex> is dropped — Zeroizing<String> handles this)
        self.store
            .delete(INDEXES_NAMESPACE, name.as_bytes())
            .await
            .map_err(|e| VeilError::Store(e.to_string()))?;

        // Remove from cache (this drops the Arc, triggering zeroize on the key)
        self.cache.remove(name);
        self.entry_counts.remove(name);

        tracing::info!(
            index = name,
            deleted_entries = deleted,
            "index destroyed (crypto-shred)"
        );

        Ok(deleted)
    }

    /// Seed an index from config if it doesn't already exist.
    pub async fn seed_if_absent(&self, name: &str) -> Result<(), VeilError> {
        if self.cache.contains_key(name) {
            tracing::debug!(index = name, "index already exists, skipping seed");
            return Ok(());
        }
        self.create(name).await?;
        Ok(())
    }

    /// Get the cached entry count for an index. Returns 0 if not tracked.
    pub fn entry_count(&self, name: &str) -> u64 {
        self.entry_counts
            .get(name)
            .map(|c| c.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    /// Increment the cached entry count for an index.
    pub fn increment_entry_count(&self, name: &str) {
        if let Some(c) = self.entry_counts.get(name) {
            c.fetch_add(1, Ordering::Release);
        }
    }

    /// Decrement the cached entry count for an index (saturating at 0).
    pub fn decrement_entry_count(&self, name: &str) {
        if let Some(c) = self.entry_counts.get(name) {
            // Use a CAS loop to avoid underflow.
            loop {
                let current = c.load(Ordering::Acquire);
                if current == 0 {
                    break;
                }
                if c.compare_exchange_weak(
                    current,
                    current - 1,
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
                {
                    break;
                }
            }
        }
    }

    /// Add an entry's tokens to the inverted index.
    pub async fn inv_add(
        &self,
        index_name: &str,
        entry_id: &str,
        tokens: &BlindTokenSet,
    ) -> Result<(), VeilError> {
        let ns = inv_namespace(index_name);
        for token in tokens.words.iter().chain(tokens.trigrams.iter()) {
            let mut ids = self.inv_load_posting(&ns, token).await?;
            if !ids.contains(&entry_id.to_string()) {
                ids.push(entry_id.to_string());
                self.inv_save_posting(&ns, token, &ids).await?;
            }
        }
        Ok(())
    }

    /// Remove an entry's tokens from the inverted index.
    pub async fn inv_remove(
        &self,
        index_name: &str,
        entry_id: &str,
        tokens: &BlindTokenSet,
    ) -> Result<(), VeilError> {
        let ns = inv_namespace(index_name);
        for token in tokens.words.iter().chain(tokens.trigrams.iter()) {
            let mut ids = self.inv_load_posting(&ns, token).await?;
            ids.retain(|id| id != entry_id);
            if ids.is_empty() {
                // A concurrent update to the same entry may have already
                // deleted this empty posting; treat NotFound as idempotent
                // success rather than surfacing a spurious "not found" error
                // to the caller. Any other store error still fails the op.
                match self.store.delete(&ns, token.as_bytes()).await {
                    Ok(_) => {}
                    Err(shroudb_store::StoreError::NotFound) => {}
                    Err(e) => return Err(VeilError::Store(e.to_string())),
                }
            } else {
                self.inv_save_posting(&ns, token, &ids).await?;
            }
        }
        Ok(())
    }

    /// Look up entry IDs that contain the given token. Returns an error if
    /// the posting list exists but is corrupt (e.g. not valid JSON) — a
    /// silent empty-vector fallback would mask index damage.
    pub async fn inv_lookup(
        &self,
        index_name: &str,
        token: &str,
    ) -> Result<Vec<String>, VeilError> {
        let ns = inv_namespace(index_name);
        self.inv_load_posting(&ns, token).await
    }

    async fn inv_load_posting(&self, ns: &str, token: &str) -> Result<Vec<String>, VeilError> {
        match self.store.get(ns, token.as_bytes(), None).await {
            Ok(entry) => serde_json::from_slice(&entry.value).map_err(|e| {
                VeilError::Internal(format!("posting list at {ns}/{token} is corrupt: {e}"))
            }),
            // A missing posting list is the normal "no hits" case.
            Err(_) => Ok(Vec::new()),
        }
    }

    async fn inv_save_posting(
        &self,
        ns: &str,
        token: &str,
        ids: &[String],
    ) -> Result<(), VeilError> {
        let value = serde_json::to_vec(ids)
            .map_err(|e| VeilError::Internal(format!("serialize posting list: {e}")))?;
        self.store
            .put(ns, token.as_bytes(), &value, None)
            .await
            .map_err(|e| VeilError::Store(e.to_string()))?;
        Ok(())
    }

    /// Persist an index to the Store.
    async fn save(&self, index: &BlindIndex) -> Result<(), VeilError> {
        let value = serde_json::to_vec(index)
            .map_err(|e| VeilError::Internal(format!("serialization failed: {e}")))?;
        self.store
            .put(INDEXES_NAMESPACE, index.name.as_bytes(), &value, None)
            .await
            .map_err(|e| VeilError::Store(e.to_string()))?;
        Ok(())
    }
}

/// Build the namespace name for token storage within an index.
pub fn tokens_namespace(index_name: &str) -> String {
    format!("veil.{index_name}")
}

/// Build the namespace name for the inverted index within an index.
pub fn inv_namespace(index_name: &str) -> String {
    format!("veil.{index_name}.inv")
}

fn validate_index_name(name: &str) -> Result<(), VeilError> {
    if name.is_empty() {
        return Err(VeilError::InvalidArgument(
            "index name cannot be empty".into(),
        ));
    }
    if name.len() > 255 {
        return Err(VeilError::InvalidArgument(
            "index name exceeds 255 characters".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(VeilError::InvalidArgument(
            "index name must contain only alphanumeric characters, hyphens, and underscores".into(),
        ));
    }
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_and_get_index() {
        let store = shroudb_storage::test_util::create_test_store("veil-test").await;
        let mgr = IndexManager::new(store);
        mgr.init().await.unwrap();

        let idx = mgr.create("users").await.unwrap();
        assert_eq!(idx.name, "users");
        assert!(!idx.key_material.is_empty());

        let fetched = mgr.get("users").unwrap();
        assert_eq!(fetched.name, "users");
    }

    #[tokio::test]
    async fn create_duplicate_fails() {
        let store = shroudb_storage::test_util::create_test_store("veil-test").await;
        let mgr = IndexManager::new(store);
        mgr.init().await.unwrap();

        mgr.create("users").await.unwrap();
        let err = mgr.create("users").await.unwrap_err();
        assert!(matches!(err, VeilError::IndexExists(_)));
    }

    #[tokio::test]
    async fn list_indexes() {
        let store = shroudb_storage::test_util::create_test_store("veil-test").await;
        let mgr = IndexManager::new(store);
        mgr.init().await.unwrap();

        mgr.create("a").await.unwrap();
        mgr.create("b").await.unwrap();

        let mut names = mgr.list();
        names.sort();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn persistence_survives_reload() {
        let store = shroudb_storage::test_util::create_test_store("veil-test").await;

        let mgr1 = IndexManager::new(store.clone());
        mgr1.init().await.unwrap();
        mgr1.create("users").await.unwrap();

        let mgr2 = IndexManager::new(store);
        mgr2.init().await.unwrap();
        let idx = mgr2.get("users").unwrap();
        assert_eq!(idx.name, "users");
    }

    #[tokio::test]
    async fn seed_if_absent_creates_new() {
        let store = shroudb_storage::test_util::create_test_store("veil-test").await;
        let mgr = IndexManager::new(store);
        mgr.init().await.unwrap();

        mgr.seed_if_absent("users").await.unwrap();
        assert!(mgr.get("users").is_ok());

        // Second call is a no-op
        mgr.seed_if_absent("users").await.unwrap();
    }

    #[tokio::test]
    async fn test_corrupt_index_data_handled() {
        let store = shroudb_storage::test_util::create_test_store("veil-test").await;

        // Create the namespace manually and write invalid JSON bytes
        store
            .namespace_create("veil.indexes", shroudb_store::NamespaceConfig::default())
            .await
            .unwrap();
        store
            .put(
                "veil.indexes",
                b"corrupt-index",
                b"not valid json {{{",
                None,
            )
            .await
            .unwrap();

        // init() should return an error for the corrupt entry, not panic
        let mgr = IndexManager::new(store);
        let result = mgr.init().await;
        assert!(
            result.is_err(),
            "init should return an error for corrupt data"
        );
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("corrupt") || msg.contains("invalid") || msg.contains("expected"),
            "error should mention corruption: {msg}"
        );
    }

    #[tokio::test]
    async fn rotate_produces_new_key() {
        let store = shroudb_storage::test_util::create_test_store("veil-test").await;
        let mgr = IndexManager::new(store.clone());
        mgr.init().await.unwrap();

        let original = mgr.create("rotate-test").await.unwrap();
        let original_key = original.key_material.clone();

        // Put some entries
        let ns = tokens_namespace("rotate-test");
        store
            .put(&ns, b"entry-1", b"{\"words\":[],\"trigrams\":[]}", None)
            .await
            .unwrap();
        store
            .put(&ns, b"entry-2", b"{\"words\":[],\"trigrams\":[]}", None)
            .await
            .unwrap();
        mgr.increment_entry_count("rotate-test");
        mgr.increment_entry_count("rotate-test");
        assert_eq!(mgr.entry_count("rotate-test"), 2);

        // Rotate
        let rotated = mgr.rotate("rotate-test").await.unwrap();

        // New key is different
        assert_ne!(*rotated.key_material, *original_key);
        assert_eq!(rotated.name, "rotate-test");

        // Old entries deleted
        assert_eq!(mgr.entry_count("rotate-test"), 0);

        // Verify entries are gone from store
        let page = store.list(&ns, None, None, 100).await.unwrap();
        assert!(page.keys.is_empty());
    }

    #[tokio::test]
    async fn rotate_nonexistent_fails() {
        let store = shroudb_storage::test_util::create_test_store("veil-test").await;
        let mgr = IndexManager::new(store);
        mgr.init().await.unwrap();

        let err = mgr.rotate("nope").await.unwrap_err();
        assert!(matches!(err, VeilError::IndexNotFound(_)));
    }

    #[tokio::test]
    async fn invalid_names_rejected() {
        let store = shroudb_storage::test_util::create_test_store("veil-test").await;
        let mgr = IndexManager::new(store);
        mgr.init().await.unwrap();

        assert!(mgr.create("").await.is_err());
        assert!(mgr.create("has spaces").await.is_err());
        assert!(mgr.create("has.dots").await.is_err());
    }

    #[tokio::test]
    async fn reindex_clears_entries_preserves_key() {
        let store = shroudb_storage::test_util::create_test_store("veil-test").await;
        let mgr = IndexManager::new(store.clone());
        mgr.init().await.unwrap();

        let original = mgr.create("reindex-test").await.unwrap();
        let original_key = original.key_material.clone();

        // Put some entries
        let ns = tokens_namespace("reindex-test");
        store
            .put(&ns, b"entry-1", b"{\"words\":[],\"trigrams\":[]}", None)
            .await
            .unwrap();
        store
            .put(&ns, b"entry-2", b"{\"words\":[],\"trigrams\":[]}", None)
            .await
            .unwrap();
        mgr.increment_entry_count("reindex-test");
        mgr.increment_entry_count("reindex-test");
        assert_eq!(mgr.entry_count("reindex-test"), 2);

        // Reindex
        let (updated, deleted) = mgr.reindex("reindex-test").await.unwrap();
        assert_eq!(deleted, 2);

        // Same key preserved
        assert_eq!(*updated.key_material, *original_key);
        assert_eq!(updated.tokenizer_version, TOKENIZER_VERSION);

        // Entry count reset
        assert_eq!(mgr.entry_count("reindex-test"), 0);

        // Verify entries are gone from store
        let page = store.list(&ns, None, None, 100).await.unwrap();
        assert!(page.keys.is_empty());
    }

    #[tokio::test]
    async fn reindex_nonexistent_fails() {
        let store = shroudb_storage::test_util::create_test_store("veil-test").await;
        let mgr = IndexManager::new(store);
        mgr.init().await.unwrap();

        let err = mgr.reindex("nope").await.unwrap_err();
        assert!(matches!(err, VeilError::IndexNotFound(_)));
    }

    #[tokio::test]
    async fn create_sets_tokenizer_version() {
        let store = shroudb_storage::test_util::create_test_store("veil-test").await;
        let mgr = IndexManager::new(store);
        mgr.init().await.unwrap();

        let idx = mgr.create("versioned").await.unwrap();
        assert_eq!(idx.tokenizer_version, TOKENIZER_VERSION);
    }

    #[tokio::test]
    async fn rotate_sets_tokenizer_version() {
        let store = shroudb_storage::test_util::create_test_store("veil-test").await;
        let mgr = IndexManager::new(store);
        mgr.init().await.unwrap();

        mgr.create("rotate-ver").await.unwrap();
        let rotated = mgr.rotate("rotate-ver").await.unwrap();
        assert_eq!(rotated.tokenizer_version, TOKENIZER_VERSION);
    }

    /// F-veil-7: `inv_load_posting` used `unwrap_or_default()` when
    /// deserializing a posting list, and `inv_remove` used `let _ = ...`
    /// on the delete. Both swallow errors silently — a corrupt posting
    /// list looks identical to an empty one, letting search return zero
    /// hits for tokens whose posting list has been tampered with. Lookup
    /// must surface the deserialization error.
    #[tokio::test]
    async fn debt_7_inv_lookup_must_surface_corrupt_posting_list() {
        let store = shroudb_storage::test_util::create_test_store("veil-debt-7").await;
        let mgr = IndexManager::new(store.clone());
        mgr.init().await.unwrap();
        mgr.create("idx").await.unwrap();

        // Plant a garbage posting list directly in the inverted namespace.
        // A well-formed posting list is a JSON array of strings; "not json"
        // is neither, so deserialization must fail.
        let ns = inv_namespace("idx");
        store
            .put(&ns, b"some-token", b"not json", None)
            .await
            .unwrap();

        let result = mgr.inv_lookup("idx", "some-token").await;
        assert!(
            result.is_err(),
            "inv_lookup must propagate deserialization failures — a corrupt \
             posting list silently returning an empty Vec hides index damage",
        );
    }

    mod fuzz {
        use super::*;
        use proptest::prelude::*;

        // Arbitrary strings never panic validate_index_name.
        proptest! {
            #[test]
            fn arbitrary_string_never_panics(s in "\\PC{0,512}") {
                let _ = validate_index_name(&s);
            }
        }

        // Names from the allowed alphabet always pass.
        proptest! {
            #[test]
            fn valid_alphabet_names_accepted(s in "[a-zA-Z0-9_-]{1,100}") {
                prop_assert!(validate_index_name(&s).is_ok(), "valid name rejected: {s}");
            }
        }

        // Names > 255 chars always rejected.
        proptest! {
            #[test]
            fn oversized_names_rejected(extra in 1..300usize) {
                let name = "a".repeat(255 + extra);
                prop_assert!(validate_index_name(&name).is_err());
            }
        }

        // Any accepted name contains only allowed chars and is ≤255.
        proptest! {
            #[test]
            fn accepted_names_are_safe(s in "\\PC{1,300}") {
                if validate_index_name(&s).is_ok() {
                    prop_assert!(s.len() <= 255, "accepted name too long");
                    prop_assert!(
                        s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                        "accepted name has invalid chars: {s}"
                    );
                }
            }
        }
    }
}
