mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use shroudb_veil_blind::{BlindKey, encode_for_wire, tokenize_and_blind};

// ═══════════════════════════════════════════════════════════════════════
// TCP: Full blind index lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_full_blind_index_lifecycle() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    // Health
    client.health().await.expect("health check failed");

    // Create index
    client
        .index_create("users")
        .await
        .expect("index create failed");

    // List indexes
    let names = client.index_list().await.expect("index list failed");
    assert!(names.contains(&"users".to_string()));

    // Put entries
    client
        .put(
            "users",
            "u1",
            &STANDARD.encode(b"Alice Johnson"),
            None,
            false,
        )
        .await
        .expect("put u1 failed");
    client
        .put("users", "u2", &STANDARD.encode(b"Bob Smith"), None, false)
        .await
        .expect("put u2 failed");
    client
        .put(
            "users",
            "u3",
            &STANDARD.encode(b"Charlie Johnson"),
            None,
            false,
        )
        .await
        .expect("put u3 failed");

    // Search: exact match on "johnson"
    let result = client
        .search("users", "johnson", Some("exact"), None, None, false)
        .await
        .expect("search failed");
    assert_eq!(result.scanned, 3);
    assert_eq!(result.matched, 2);
    let ids: Vec<&str> = result.results.iter().map(|h| h.id.as_str()).collect();
    assert!(ids.contains(&"u1"));
    assert!(ids.contains(&"u3"));

    // Search: contains "alice"
    let result = client
        .search("users", "alice", Some("contains"), None, None, false)
        .await
        .expect("search failed");
    assert_eq!(result.matched, 1);
    assert_eq!(result.results[0].id, "u1");

    // Index info
    let info = client.index_info("users").await.expect("info failed");
    assert_eq!(info["index"], "users");
    assert_eq!(info["entry_count"], 3);
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Search modes
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_search_modes() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.index_create("test").await.unwrap();

    client
        .put("test", "1", &STANDARD.encode(b"hello world"), None, false)
        .await
        .unwrap();
    client
        .put("test", "2", &STANDARD.encode(b"hello planet"), None, false)
        .await
        .unwrap();
    client
        .put("test", "3", &STANDARD.encode(b"goodbye world"), None, false)
        .await
        .unwrap();

    // Exact: "hello world" must have BOTH words
    let result = client
        .search("test", "hello world", Some("exact"), None, None, false)
        .await
        .unwrap();
    assert_eq!(result.matched, 1);
    assert_eq!(result.results[0].id, "1");

    // Contains: "hello" in entries 1 and 2
    let result = client
        .search("test", "hello", Some("contains"), None, None, false)
        .await
        .unwrap();
    assert_eq!(result.matched, 2);

    // Contains: "world" in entries 1 and 3
    let result = client
        .search("test", "world", Some("contains"), None, None, false)
        .await
        .unwrap();
    assert_eq!(result.matched, 2);
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Fuzzy search
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_fuzzy_search() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.index_create("test").await.unwrap();

    client
        .put("test", "1", &STANDARD.encode(b"hello"), None, false)
        .await
        .unwrap();
    client
        .put("test", "2", &STANDARD.encode(b"helicopter"), None, false)
        .await
        .unwrap();
    client
        .put("test", "3", &STANDARD.encode(b"xyzzy"), None, false)
        .await
        .unwrap();

    // Fuzzy "helo" should match "hello" and "helicopter" (shared trigrams) but not "xyzzy"
    let result = client
        .search("test", "helo", Some("fuzzy"), None, None, false)
        .await
        .unwrap();
    assert!(result.matched >= 1);
    let ids: Vec<&str> = result.results.iter().map(|h| h.id.as_str()).collect();
    assert!(!ids.contains(&"3"), "xyzzy should not match 'helo'");
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Delete entry
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_delete_entry() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.index_create("test").await.unwrap();

    client
        .put("test", "a", &STANDARD.encode(b"hello"), None, false)
        .await
        .unwrap();
    client
        .put("test", "b", &STANDARD.encode(b"hello"), None, false)
        .await
        .unwrap();

    // Delete one
    client.delete("test", "a").await.unwrap();

    // Only "b" should remain
    let result = client
        .search("test", "hello", Some("exact"), None, None, false)
        .await
        .unwrap();
    assert_eq!(result.matched, 1);
    assert_eq!(result.results[0].id, "b");
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Tokenize (no storage)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_tokenize() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.index_create("test").await.unwrap();

    let result = client
        .tokenize("test", &STANDARD.encode(b"hello world"), None)
        .await
        .unwrap();
    assert_eq!(result.words, 2);
    assert!(result.trigrams > 0);
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Search with LIMIT
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_search_with_limit() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.index_create("test").await.unwrap();

    for i in 0..10 {
        client
            .put(
                "test",
                &format!("e{i}"),
                &STANDARD.encode(b"common term"),
                None,
                false,
            )
            .await
            .unwrap();
    }

    let result = client
        .search("test", "common", Some("exact"), None, Some(3), false)
        .await
        .unwrap();
    assert_eq!(result.results.len(), 3);
    // Exact mode early-exits after reaching the limit — not all entries are scanned
    assert!(result.matched >= 3);
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: JSON field extraction
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_json_field_extraction() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.index_create("contacts").await.unwrap();

    let data = serde_json::json!({"name": "Alice", "city": "Portland"});
    client
        .put(
            "contacts",
            "c1",
            &STANDARD.encode(data.to_string().as_bytes()),
            Some("name"),
            false,
        )
        .await
        .unwrap();

    // Search by name field value
    let result = client
        .search("contacts", "alice", Some("exact"), None, None, false)
        .await
        .unwrap();
    assert_eq!(result.matched, 1);
    assert_eq!(result.results[0].id, "c1");

    // "portland" should NOT match since we indexed only the "name" field
    let result = client
        .search("contacts", "portland", Some("exact"), None, None, false)
        .await
        .unwrap();
    assert_eq!(result.matched, 0);
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Config-seeded indexes
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_config_seeded_indexes() {
    let config = TestServerConfig {
        indexes: vec!["pre-seeded".to_string(), "pre-contacts".to_string()],
        ..Default::default()
    };

    let server = TestServer::start_with_config(config)
        .await
        .expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    // Seeded indexes should be usable immediately
    client
        .put(
            "pre-seeded",
            "a",
            &STANDARD.encode(b"test data"),
            None,
            false,
        )
        .await
        .expect("put on seeded index failed");

    let result = client
        .search("pre-seeded", "test", Some("exact"), None, None, false)
        .await
        .expect("search on seeded index failed");
    assert_eq!(result.matched, 1);
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Error handling
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_error_responses() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    // Nonexistent index
    let err = client
        .search("nope", "query", Some("exact"), None, None, false)
        .await;
    assert!(err.is_err(), "nonexistent index should error");

    // Duplicate index
    client.index_create("dup").await.unwrap();
    let err = client.index_create("dup").await;
    assert!(err.is_err(), "duplicate index should error");

    // Empty query
    client.index_create("test").await.unwrap();
    let err = client
        .search("test", "", Some("exact"), None, None, false)
        .await;
    assert!(err.is_err(), "empty query should error");

    // Invalid base64
    let err = client.put("test", "a", "!!!invalid!!!", None, false).await;
    assert!(err.is_err(), "invalid base64 should error");

    // Invalid match mode
    let err = client
        .search("test", "query", Some("nonexistent"), None, None, false)
        .await;
    assert!(err.is_err(), "invalid mode should error");
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Update entry (overwrite)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_update_entry() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.index_create("test").await.unwrap();

    // Put initial data
    client
        .put("test", "a", &STANDARD.encode(b"hello"), None, false)
        .await
        .unwrap();

    // Search for "hello"
    let result = client
        .search("test", "hello", Some("exact"), None, None, false)
        .await
        .unwrap();
    assert_eq!(result.matched, 1);

    // Overwrite with new data
    client
        .put("test", "a", &STANDARD.encode(b"goodbye"), None, false)
        .await
        .unwrap();

    // "hello" should no longer match
    let result = client
        .search("test", "hello", Some("exact"), None, None, false)
        .await
        .unwrap();
    assert_eq!(result.matched, 0);

    // "goodbye" should match
    let result = client
        .search("test", "goodbye", Some("exact"), None, None, false)
        .await
        .unwrap();
    assert_eq!(result.matched, 1);
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Edge cases
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_empty_query_rejected() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.index_create("test").await.unwrap();

    let err = client
        .search("test", "", Some("exact"), None, None, false)
        .await;
    assert!(err.is_err(), "empty query should be rejected");

    let err = client
        .search("test", "", Some("contains"), None, None, false)
        .await;
    assert!(
        err.is_err(),
        "empty query in contains mode should be rejected"
    );

    let err = client
        .search("test", "", Some("fuzzy"), None, None, false)
        .await;
    assert!(err.is_err(), "empty query in fuzzy mode should be rejected");
}

#[tokio::test]
async fn test_invalid_utf8_in_search() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.index_create("test").await.unwrap();

    // Non-printable control characters and unusual unicode — the engine
    // should handle gracefully without panicking.
    let bad_query = "\u{0000}\u{0001}\u{007F}";
    let result = client
        .search("test", bad_query, Some("exact"), None, None, false)
        .await;
    // Either an error or zero results is acceptable — not a panic
    match result {
        Err(_) => {} // rejected at protocol or engine level
        Ok(r) => assert_eq!(r.matched, 0, "control characters should not match anything"),
    }
}

#[tokio::test]
async fn test_max_length_entry() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.index_create("test").await.unwrap();

    // 10KB of text with word boundaries, base64-encoded
    let words: Vec<&str> = (0..1024).map(|_| "searchable data payload").collect();
    let long_text = words.join(" ");
    let encoded = STANDARD.encode(long_text.as_bytes());

    client
        .put("test", "big1", &encoded, None, false)
        .await
        .expect("put 10KB entry failed");

    // Should be searchable by a word that appears in the long text
    let result = client
        .search("test", "searchable", Some("contains"), None, None, false)
        .await
        .expect("search on 10KB entry failed");
    assert_eq!(result.matched, 1);
    assert_eq!(result.results[0].id, "big1");
}

// ═══════════════════════════════════════════════════════════════════════
// ACL: Token-based auth
// ═══════════════════════════════════════════════════════════════════════

fn auth_server_config() -> TestServerConfig {
    TestServerConfig {
        tokens: vec![
            TestToken {
                raw: "admin-token".to_string(),
                tenant: "tenant-a".to_string(),
                actor: "admin".to_string(),
                platform: true,
                grants: vec![],
            },
            TestToken {
                raw: "app-token".to_string(),
                tenant: "tenant-a".to_string(),
                actor: "my-app".to_string(),
                platform: false,
                grants: vec![TestGrant {
                    namespace: "veil.users.*".to_string(),
                    scopes: vec!["read".to_string(), "write".to_string()],
                }],
            },
            TestToken {
                raw: "readonly-token".to_string(),
                tenant: "tenant-a".to_string(),
                actor: "reader".to_string(),
                platform: false,
                grants: vec![TestGrant {
                    namespace: "veil.users.*".to_string(),
                    scopes: vec!["read".to_string()],
                }],
            },
        ],
        indexes: vec![],
    }
}

#[tokio::test]
async fn acl_unauthenticated_rejected_for_protected_commands() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    // Health is public
    client.health().await.expect("health should be public");

    // Index list is public
    let _ = client
        .index_list()
        .await
        .expect("index list should be public");

    // Index create requires Admin
    let err = client.index_create("test").await;
    assert!(err.is_err(), "unauthenticated index create should fail");

    // Put requires Write
    let err = client
        .put("users", "u1", &STANDARD.encode(b"data"), None, false)
        .await;
    assert!(err.is_err(), "unauthenticated put should fail");
}

#[tokio::test]
async fn acl_admin_token_full_access() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.auth("admin-token").await.expect("admin auth failed");

    // Admin can create indexes
    client
        .index_create("users")
        .await
        .expect("admin should create indexes");

    // Admin can put and search
    client
        .put("users", "u1", &STANDARD.encode(b"Alice"), None, false)
        .await
        .expect("admin should put");
    let result = client
        .search("users", "alice", Some("exact"), None, None, false)
        .await
        .expect("admin should search");
    assert_eq!(result.matched, 1);
}

#[tokio::test]
async fn acl_wrong_token_rejected() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    let err = client.auth("totally-wrong-token").await;
    assert!(err.is_err(), "wrong token should be rejected");
}

#[tokio::test]
async fn acl_non_admin_cannot_create_index() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.auth("app-token").await.expect("app auth failed");

    let err = client.index_create("test").await;
    assert!(err.is_err(), "non-admin should not create indexes");
}

#[tokio::test]
async fn acl_scoped_token_can_operate_on_granted_index() {
    let mut config = auth_server_config();
    config.indexes.push("users".to_string());

    let server = TestServer::start_with_config(config)
        .await
        .expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.auth("app-token").await.expect("app auth failed");

    // App token has veil.users.* with read+write
    client
        .put("users", "u1", &STANDARD.encode(b"Alice"), None, false)
        .await
        .expect("scoped token should put on granted index");
    client
        .search("users", "alice", Some("exact"), None, None, false)
        .await
        .expect("scoped token should search on granted index");
}

#[tokio::test]
async fn acl_readonly_token_cannot_put() {
    let mut config = auth_server_config();
    config.indexes.push("users".to_string());

    let server = TestServer::start_with_config(config)
        .await
        .expect("server failed to start");

    // First put something as admin
    let mut admin = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .unwrap();
    admin.auth("admin-token").await.unwrap();
    admin
        .put("users", "u1", &STANDARD.encode(b"Alice"), None, false)
        .await
        .unwrap();

    // Now connect as readonly
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");
    client
        .auth("readonly-token")
        .await
        .expect("readonly auth failed");

    // Read-only can search (Read scope)
    client
        .search("users", "alice", Some("exact"), None, None, false)
        .await
        .expect("readonly should search");

    // Read-only CANNOT put (Write scope required)
    let err = client
        .put("users", "u2", &STANDARD.encode(b"Bob"), None, false)
        .await;
    assert!(err.is_err(), "readonly should not put");

    // Read-only CANNOT delete (Write scope required)
    let err = client.delete("users", "u1").await;
    assert!(err.is_err(), "readonly should not delete");
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Blind (E2EE) operations
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_blind_put_and_search() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.index_create("e2ee").await.unwrap();

    // Client-side key — never sent to the server.
    let key = BlindKey::from_bytes(vec![0x42u8; 32]).unwrap();

    // BLIND_PUT: tokenize + blind locally, send pre-computed tokens
    let tokens1 = tokenize_and_blind(&key, "hello world");
    let tokens1_b64 = encode_for_wire(&tokens1).unwrap();
    client
        .put("e2ee", "m1", &tokens1_b64, None, true)
        .await
        .expect("blind_put m1 failed");

    let tokens2 = tokenize_and_blind(&key, "goodbye world");
    let tokens2_b64 = encode_for_wire(&tokens2).unwrap();
    client
        .put("e2ee", "m2", &tokens2_b64, None, true)
        .await
        .expect("blind_put m2 failed");

    // BLIND_SEARCH: exact match on "hello"
    let query = tokenize_and_blind(&key, "hello");
    let query_b64 = encode_for_wire(&query).unwrap();
    let result = client
        .search("e2ee", &query_b64, Some("exact"), None, None, true)
        .await
        .expect("blind_search failed");
    assert_eq!(result.matched, 1);
    assert_eq!(result.results[0].id, "m1");

    // BLIND_SEARCH: contains "world" should match both
    let query = tokenize_and_blind(&key, "world");
    let query_b64 = encode_for_wire(&query).unwrap();
    let result = client
        .search("e2ee", &query_b64, Some("contains"), None, None, true)
        .await
        .expect("blind_search failed");
    assert_eq!(result.matched, 2);
}

#[tokio::test]
async fn tcp_blind_search_with_limit() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.index_create("e2ee").await.unwrap();

    let key = BlindKey::from_bytes(vec![0x42u8; 32]).unwrap();

    for i in 0..10 {
        let tokens = tokenize_and_blind(&key, "common term");
        let tokens_b64 = encode_for_wire(&tokens).unwrap();
        client
            .put("e2ee", &format!("m{i}"), &tokens_b64, None, true)
            .await
            .unwrap();
    }

    let query = tokenize_and_blind(&key, "common");
    let query_b64 = encode_for_wire(&query).unwrap();
    let result = client
        .search("e2ee", &query_b64, Some("exact"), None, Some(3), true)
        .await
        .unwrap();
    assert_eq!(result.results.len(), 3);
}

#[tokio::test]
async fn tcp_blind_put_then_delete() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.index_create("e2ee").await.unwrap();

    let key = BlindKey::from_bytes(vec![0x42u8; 32]).unwrap();

    let tokens = tokenize_and_blind(&key, "secret message");
    let tokens_b64 = encode_for_wire(&tokens).unwrap();
    client
        .put("e2ee", "m1", &tokens_b64, None, true)
        .await
        .unwrap();

    // Delete the entry
    client.delete("e2ee", "m1").await.unwrap();

    // Should no longer be found
    let query = tokenize_and_blind(&key, "secret");
    let query_b64 = encode_for_wire(&query).unwrap();
    let result = client
        .search("e2ee", &query_b64, Some("exact"), None, None, true)
        .await
        .unwrap();
    assert_eq!(result.matched, 0);
}

#[tokio::test]
async fn tcp_blind_fuzzy_search() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.index_create("e2ee").await.unwrap();

    let key = BlindKey::from_bytes(vec![0x42u8; 32]).unwrap();

    let tokens = tokenize_and_blind(&key, "hello");
    client
        .put("e2ee", "m1", &encode_for_wire(&tokens).unwrap(), None, true)
        .await
        .unwrap();

    let tokens = tokenize_and_blind(&key, "helicopter");
    client
        .put("e2ee", "m2", &encode_for_wire(&tokens).unwrap(), None, true)
        .await
        .unwrap();

    let tokens = tokenize_and_blind(&key, "goodbye");
    client
        .put("e2ee", "m3", &encode_for_wire(&tokens).unwrap(), None, true)
        .await
        .unwrap();

    // Fuzzy "helo" should match hello and helicopter, not goodbye
    let query = tokenize_and_blind(&key, "helo");
    let query_b64 = encode_for_wire(&query).unwrap();
    let result = client
        .search("e2ee", &query_b64, Some("fuzzy"), None, None, true)
        .await
        .unwrap();
    assert!(result.matched >= 1);
    let ids: Vec<&str> = result.results.iter().map(|h| h.id.as_str()).collect();
    assert!(!ids.contains(&"m3"), "goodbye should not match helo");
}

#[tokio::test]
async fn tcp_blind_put_invalid_base64_rejected() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.index_create("e2ee").await.unwrap();

    let err = client
        .put("e2ee", "m1", "not-valid-base64!!!", None, true)
        .await;
    assert!(err.is_err(), "invalid base64 should be rejected");
}

#[tokio::test]
async fn tcp_blind_put_invalid_json_rejected() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.index_create("e2ee").await.unwrap();

    // Valid base64 but not a valid BlindTokenSet JSON
    let bad = STANDARD.encode(b"not json");
    let err = client.put("e2ee", "m1", &bad, None, true).await;
    assert!(err.is_err(), "invalid token JSON should be rejected");
}

#[tokio::test]
async fn tcp_blind_search_empty_tokens_rejected() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.index_create("e2ee").await.unwrap();

    // Empty token set
    let empty = STANDARD.encode(br#"{"words":[],"trigrams":[]}"#);
    let err = client
        .search("e2ee", &empty, Some("exact"), None, None, true)
        .await;
    assert!(err.is_err(), "empty tokens should be rejected");
}

#[tokio::test]
async fn tcp_blind_put_nonexistent_index_rejected() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    let key = BlindKey::from_bytes(vec![0x42u8; 32]).unwrap();
    let tokens = tokenize_and_blind(&key, "test");
    let tokens_b64 = encode_for_wire(&tokens).unwrap();

    let err = client
        .put("nonexistent", "m1", &tokens_b64, None, true)
        .await;
    assert!(err.is_err(), "nonexistent index should be rejected");
}

#[tokio::test]
async fn tcp_blind_different_keys_dont_cross_search() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.index_create("e2ee").await.unwrap();

    // Two different client keys — simulating two different conversations
    let key_a = BlindKey::from_bytes(vec![0x42u8; 32]).unwrap();
    let key_b = BlindKey::from_bytes(vec![0x43u8; 32]).unwrap();

    // Put with key_a
    let tokens = tokenize_and_blind(&key_a, "hello world");
    client
        .put("e2ee", "m1", &encode_for_wire(&tokens).unwrap(), None, true)
        .await
        .unwrap();

    // Search with key_b — should NOT find anything because HMAC keys differ
    let query = tokenize_and_blind(&key_b, "hello");
    let result = client
        .search(
            "e2ee",
            &encode_for_wire(&query).unwrap(),
            Some("exact"),
            None,
            None,
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        result.matched, 0,
        "different HMAC keys must not cross-match"
    );

    // Search with key_a — should find it
    let query = tokenize_and_blind(&key_a, "hello");
    let result = client
        .search(
            "e2ee",
            &encode_for_wire(&query).unwrap(),
            Some("exact"),
            None,
            None,
            true,
        )
        .await
        .unwrap();
    assert_eq!(result.matched, 1, "same HMAC key should match");
}

#[tokio::test]
async fn acl_blind_put_requires_write_scope() {
    let mut config = auth_server_config();
    config.indexes.push("users".to_string());

    let server = TestServer::start_with_config(config)
        .await
        .expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .auth("readonly-token")
        .await
        .expect("readonly auth failed");

    let key = BlindKey::from_bytes(vec![0x42u8; 32]).unwrap();
    let tokens = tokenize_and_blind(&key, "test");
    let tokens_b64 = encode_for_wire(&tokens).unwrap();

    // BLIND_PUT requires Write scope — readonly should fail
    let err = client.put("users", "m1", &tokens_b64, None, true).await;
    assert!(err.is_err(), "readonly should not blind_put");
}

#[tokio::test]
async fn acl_blind_search_allowed_with_read_scope() {
    let mut config = auth_server_config();
    config.indexes.push("users".to_string());

    let server = TestServer::start_with_config(config)
        .await
        .expect("server failed to start");
    let mut client = shroudb_veil_client::VeilClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .auth("readonly-token")
        .await
        .expect("readonly auth failed");

    let key = BlindKey::from_bytes(vec![0x42u8; 32]).unwrap();
    let query = tokenize_and_blind(&key, "test");
    let query_b64 = encode_for_wire(&query).unwrap();

    // BLIND_SEARCH requires Read scope — readonly should succeed
    let result = client
        .search("users", &query_b64, Some("exact"), None, None, true)
        .await;
    assert!(result.is_ok(), "readonly should be able to blind_search");
}
