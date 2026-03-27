//! Integration tests for ShrouDB Veil — encrypted search.
//!
//! Uses an embedded Transit backend so no external server is needed.
//! Tests INDEX, EXACT/PREFIX/CONTAINS/FUZZY search, HEALTH, and CONFIG.

use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use shroudb_crypto::SecretBytes;
use shroudb_storage::{
    MasterKeySource, RecoveryMode, StorageEngine, StorageEngineConfig, StorageError,
};
use shroudb_transit_core::{Keyring, KeyringAlgorithm, KeyringPolicy};
use shroudb_transit_protocol::auth::AuthRegistry as TransitAuth;
use shroudb_transit_protocol::keyring_index::KeyringIndex;
use shroudb_transit_protocol::recovery;
use shroudb_transit_protocol::CommandDispatcher as TransitDispatcher;

use shroudb_veil_protocol::command::{Command, IndexArgs, SearchArgs, SearchEntry};
use shroudb_veil_protocol::embedded::EmbeddedTransit;
use shroudb_veil_protocol::response::{CommandResponse, ResponseValue};
use shroudb_veil_protocol::search_engine::SearchConfig;
use shroudb_veil_protocol::CommandDispatcher;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

struct TestKeySource;

impl MasterKeySource for TestKeySource {
    fn load(
        &self,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<SecretBytes, StorageError>> + Send + '_>>
    {
        Box::pin(async { Ok(SecretBytes::new(vec![0x42; 32])) })
    }

    fn source_name(&self) -> &str {
        "test"
    }
}

fn test_config(dir: &Path) -> StorageEngineConfig {
    StorageEngineConfig {
        data_dir: dir.to_path_buf(),
        recovery_mode: RecoveryMode::Recover,
        fsync_mode: shroudb_storage::FsyncMode::PerWrite,
        ..Default::default()
    }
}

async fn open_engine(dir: &Path) -> StorageEngine {
    StorageEngine::open(test_config(dir), &TestKeySource)
        .await
        .unwrap()
}

fn make_convergent_keyring(name: &str) -> Keyring {
    Keyring {
        name: name.to_string(),
        algorithm: KeyringAlgorithm::Aes256Gcm,
        rotation_days: 90,
        drain_days: 30,
        convergent: true,
        created_at: 1000,
        disabled: false,
        policy: KeyringPolicy::default(),
        key_versions: Vec::new(),
    }
}

async fn setup_transit(dir: &Path) -> Arc<TransitDispatcher> {
    let engine = Arc::new(open_engine(dir).await);
    let index = Arc::new(KeyringIndex::new());

    index.register_metadata_only(make_convergent_keyring("veil-kr"));
    index.register_metadata_only(make_convergent_keyring("veil-kr:tokens"));

    recovery::replay_transit_wal(&engine, &index).await.unwrap();
    recovery::seed_empty_keyrings(&engine, &index)
        .await
        .unwrap();

    let auth = Arc::new(TransitAuth::permissive());
    Arc::new(TransitDispatcher::new(engine, index, auth))
}

async fn setup(dir: &Path) -> CommandDispatcher<EmbeddedTransit> {
    let transit = setup_transit(dir).await;
    let embedded = Arc::new(EmbeddedTransit::new(transit));
    let search_config = SearchConfig {
        max_batch_size: 100,
        default_result_limit: 50,
        decrypt_batch_size: 10,
    };
    CommandDispatcher::new(embedded, search_config)
}

fn is_success(resp: &CommandResponse) -> bool {
    matches!(resp, CommandResponse::Success(_))
}

fn is_error(resp: &CommandResponse) -> bool {
    matches!(resp, CommandResponse::Error(_))
}

fn field_str(resp: &CommandResponse, key: &str) -> String {
    match resp {
        CommandResponse::Success(map) => map
            .fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| match v {
                ResponseValue::String(s) => s.clone(),
                ResponseValue::Integer(n) => n.to_string(),
                ResponseValue::Boolean(b) => b.to_string(),
                other => format!("{other:?}"),
            })
            .unwrap_or_else(|| {
                let keys: Vec<&str> = map.fields.iter().map(|(k, _)| k.as_str()).collect();
                panic!("field '{key}' not found, available: {keys:?}")
            }),
        other => panic!("expected Success, got: {other:?}"),
    }
}

fn field_int(resp: &CommandResponse, key: &str) -> i64 {
    match resp {
        CommandResponse::Success(map) => map
            .fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| match v {
                ResponseValue::Integer(n) => *n,
                other => panic!("field '{key}' is not an integer: {other:?}"),
            })
            .unwrap_or_else(|| panic!("field '{key}' not found")),
        other => panic!("expected Success, got: {other:?}"),
    }
}

/// Base64-encode a string.
fn b64(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

/// INDEX a plaintext string with the embedded Transit backend.
/// Returns the ciphertext and tokens from the response.
async fn index_text(
    dispatcher: &CommandDispatcher<EmbeddedTransit>,
    text: &str,
) -> (String, Vec<String>) {
    let resp = dispatcher
        .execute(Command::Index(IndexArgs {
            keyring: "veil-kr".into(),
            plaintext_b64: b64(text),
            field: None,
            context: Some("veil-test".into()),
        }))
        .await;
    assert!(is_success(&resp), "INDEX should succeed: {resp:?}");

    let ciphertext = field_str(&resp, "ciphertext");

    let tokens = match &resp {
        CommandResponse::Success(map) => map
            .fields
            .iter()
            .find(|(k, _)| k == "tokens")
            .map(|(_, v)| match v {
                ResponseValue::Array(arr) => arr
                    .iter()
                    .filter_map(|v| match v {
                        ResponseValue::String(s) => Some(s.clone()),
                        _ => None,
                    })
                    .collect(),
                _ => vec![],
            })
            .unwrap_or_default(),
        _ => vec![],
    };

    (ciphertext, tokens)
}

// ---------------------------------------------------------------------------
// HEALTH
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_returns_ok() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let resp = dispatcher.execute(Command::Health).await;
    assert!(is_success(&resp), "HEALTH should succeed: {resp:?}");
}

// ---------------------------------------------------------------------------
// PING
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ping_returns_pong() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let resp = dispatcher.execute(Command::Ping).await;
    assert!(is_success(&resp), "PING should succeed: {resp:?}");
    assert_eq!(field_str(&resp, "message"), "PONG");
}

// ---------------------------------------------------------------------------
// COMMAND LIST
// ---------------------------------------------------------------------------

#[tokio::test]
async fn command_list_returns_all_verbs() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let resp = dispatcher.execute(Command::CommandList).await;
    assert!(is_success(&resp), "COMMAND LIST should succeed: {resp:?}");
    let count = field_int(&resp, "count");
    assert!(count >= 8, "should have at least 8 commands, got {count}");
}

// ---------------------------------------------------------------------------
// INDEX
// ---------------------------------------------------------------------------

#[tokio::test]
async fn index_text_returns_ciphertext_and_tokens() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let (ciphertext, tokens) = index_text(&dispatcher, "john doe").await;
    assert!(!ciphertext.is_empty(), "should return ciphertext");
    assert!(!tokens.is_empty(), "should return search tokens");
}

// ---------------------------------------------------------------------------
// EXACT search
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exact_search_finds_match() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let (ct1, tok1) = index_text(&dispatcher, "alice smith").await;
    let (ct2, tok2) = index_text(&dispatcher, "bob jones").await;

    let resp = dispatcher
        .execute(Command::Exact(SearchArgs {
            keyring: "veil-kr".into(),
            query: "alice smith".into(),
            field: None,
            context: Some("veil-test".into()),
            limit: None,
            rewrap: false,
            entries: vec![
                SearchEntry {
                    ciphertext: ct1,
                    tokens: Some(tok1),
                },
                SearchEntry {
                    ciphertext: ct2,
                    tokens: Some(tok2),
                },
            ],
        }))
        .await;

    assert!(is_success(&resp), "EXACT search should succeed: {resp:?}");
    assert_eq!(field_int(&resp, "matched"), 1, "should find exactly 1 match");
}

#[tokio::test]
async fn exact_search_no_match_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let (ct1, tok1) = index_text(&dispatcher, "alice smith").await;

    let resp = dispatcher
        .execute(Command::Exact(SearchArgs {
            keyring: "veil-kr".into(),
            query: "bob jones".into(),
            field: None,
            context: Some("veil-test".into()),
            limit: None,
            rewrap: false,
            entries: vec![SearchEntry {
                ciphertext: ct1,
                tokens: Some(tok1),
            }],
        }))
        .await;

    assert!(is_success(&resp), "EXACT search should succeed: {resp:?}");
    assert_eq!(field_int(&resp, "matched"), 0);
}

// ---------------------------------------------------------------------------
// PREFIX search
// ---------------------------------------------------------------------------

#[tokio::test]
async fn prefix_search_finds_matches() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let (ct1, tok1) = index_text(&dispatcher, "alice smith").await;
    let (ct2, tok2) = index_text(&dispatcher, "bob jones").await;

    let resp = dispatcher
        .execute(Command::Prefix(SearchArgs {
            keyring: "veil-kr".into(),
            query: "ali".into(),
            field: None,
            context: Some("veil-test".into()),
            limit: None,
            rewrap: false,
            entries: vec![
                SearchEntry {
                    ciphertext: ct1,
                    tokens: Some(tok1),
                },
                SearchEntry {
                    ciphertext: ct2,
                    tokens: Some(tok2),
                },
            ],
        }))
        .await;

    assert!(is_success(&resp), "PREFIX search should succeed: {resp:?}");
    assert_eq!(field_int(&resp, "matched"), 1);
}

// ---------------------------------------------------------------------------
// CONTAINS search
// ---------------------------------------------------------------------------

#[tokio::test]
async fn contains_search_finds_substring() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let (ct1, tok1) = index_text(&dispatcher, "alice smith").await;
    let (ct2, tok2) = index_text(&dispatcher, "bob jones").await;

    let resp = dispatcher
        .execute(Command::Contains(SearchArgs {
            keyring: "veil-kr".into(),
            query: "smit".into(),
            field: None,
            context: Some("veil-test".into()),
            limit: None,
            rewrap: false,
            entries: vec![
                SearchEntry {
                    ciphertext: ct1,
                    tokens: Some(tok1),
                },
                SearchEntry {
                    ciphertext: ct2,
                    tokens: Some(tok2),
                },
            ],
        }))
        .await;

    assert!(is_success(&resp), "CONTAINS search should succeed: {resp:?}");
    assert_eq!(field_int(&resp, "matched"), 1);
}

// ---------------------------------------------------------------------------
// FUZZY search
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fuzzy_search_finds_approximate() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let (ct1, tok1) = index_text(&dispatcher, "alice smith").await;
    let (ct2, tok2) = index_text(&dispatcher, "bob jones").await;

    // "alce" is Levenshtein distance 1 from "alice" — fuzzy should find it.
    // Fuzzy bypasses the token pre-filter and decrypts all entries.
    let resp = dispatcher
        .execute(Command::Fuzzy(SearchArgs {
            keyring: "veil-kr".into(),
            query: "alce".into(),
            field: None,
            context: Some("veil-test".into()),
            limit: None,
            rewrap: false,
            entries: vec![
                SearchEntry {
                    ciphertext: ct1,
                    tokens: Some(tok1),
                },
                SearchEntry {
                    ciphertext: ct2,
                    tokens: Some(tok2),
                },
            ],
        }))
        .await;

    assert!(is_success(&resp), "FUZZY search should succeed: {resp:?}");
    assert_eq!(
        field_int(&resp, "scanned"),
        2,
        "fuzzy should decrypt and scan ALL entries (token filter bypassed)"
    );
    assert!(
        field_int(&resp, "matched") >= 1,
        "fuzzy should find 'alice smith' as approximate match for 'alce'"
    );
}

#[tokio::test]
async fn fuzzy_search_without_tokens_decrypts_all() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let (ct1, _tok1) = index_text(&dispatcher, "alice smith").await;
    let (ct2, _tok2) = index_text(&dispatcher, "bob jones").await;

    // Pass entries WITHOUT tokens — fuzzy should still decrypt and match
    let resp = dispatcher
        .execute(Command::Fuzzy(SearchArgs {
            keyring: "veil-kr".into(),
            query: "alice".into(),
            field: None,
            context: Some("veil-test".into()),
            limit: None,
            rewrap: false,
            entries: vec![
                SearchEntry {
                    ciphertext: ct1,
                    tokens: None,
                },
                SearchEntry {
                    ciphertext: ct2,
                    tokens: None,
                },
            ],
        }))
        .await;

    assert!(is_success(&resp), "FUZZY without tokens should succeed: {resp:?}");
    assert_eq!(field_int(&resp, "scanned"), 2);
    assert_eq!(field_int(&resp, "matched"), 1);
}

// ---------------------------------------------------------------------------
// CONFIG
// ---------------------------------------------------------------------------

#[tokio::test]
async fn config_get_returns_value() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let resp = dispatcher
        .execute(Command::ConfigGet {
            key: "search.max_batch_size".into(),
        })
        .await;
    assert!(is_success(&resp), "CONFIG GET should succeed: {resp:?}");
    assert_eq!(field_str(&resp, "value"), "100");
}

#[tokio::test]
async fn config_set_updates_value() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let set_resp = dispatcher
        .execute(Command::ConfigSet {
            key: "search.max_batch_size".into(),
            value: "200".into(),
        })
        .await;
    assert!(is_success(&set_resp), "CONFIG SET should succeed: {set_resp:?}");

    let get_resp = dispatcher
        .execute(Command::ConfigGet {
            key: "search.max_batch_size".into(),
        })
        .await;
    assert_eq!(field_str(&get_resp, "value"), "200");
}

#[tokio::test]
async fn config_get_unknown_key_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let resp = dispatcher
        .execute(Command::ConfigGet {
            key: "nonexistent.key".into(),
        })
        .await;
    assert!(is_error(&resp), "unknown config key should error: {resp:?}");
}

#[tokio::test]
async fn config_list_returns_all() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let resp = dispatcher.execute(Command::ConfigList).await;
    // ConfigList returns a map with config keys as fields (not standard ResponseMap with status)
    match &resp {
        CommandResponse::Success(map) => {
            assert!(
                map.fields.len() >= 3,
                "should have at least 3 config entries"
            );
        }
        other => panic!("CONFIG LIST should succeed: {other:?}"),
    }
}
