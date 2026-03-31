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

use crate::hmac_ops;

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
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Increment the cached entry count for an index.
    pub fn increment_entry_count(&self, name: &str) {
        if let Some(c) = self.entry_counts.get(name) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Decrement the cached entry count for an index (saturating at 0).
    pub fn decrement_entry_count(&self, name: &str) {
        if let Some(c) = self.entry_counts.get(name) {
            // Use a CAS loop to avoid underflow.
            loop {
                let current = c.load(Ordering::Relaxed);
                if current == 0 {
                    break;
                }
                if c.compare_exchange_weak(
                    current,
                    current - 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
                {
                    break;
                }
            }
        }
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
    async fn invalid_names_rejected() {
        let store = shroudb_storage::test_util::create_test_store("veil-test").await;
        let mgr = IndexManager::new(store);
        mgr.init().await.unwrap();

        assert!(mgr.create("").await.is_err());
        assert!(mgr.create("has spaces").await.is_err());
        assert!(mgr.create("has.dots").await.is_err());
    }
}
