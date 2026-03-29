mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;

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
        .put("users", "u1", &STANDARD.encode(b"Alice Johnson"), None)
        .await
        .expect("put u1 failed");
    client
        .put("users", "u2", &STANDARD.encode(b"Bob Smith"), None)
        .await
        .expect("put u2 failed");
    client
        .put("users", "u3", &STANDARD.encode(b"Charlie Johnson"), None)
        .await
        .expect("put u3 failed");

    // Search: exact match on "johnson"
    let result = client
        .search("users", "johnson", Some("exact"), None, None)
        .await
        .expect("search failed");
    assert_eq!(result.scanned, 3);
    assert_eq!(result.matched, 2);
    let ids: Vec<&str> = result.results.iter().map(|h| h.id.as_str()).collect();
    assert!(ids.contains(&"u1"));
    assert!(ids.contains(&"u3"));

    // Search: contains "alice"
    let result = client
        .search("users", "alice", Some("contains"), None, None)
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
        .put("test", "1", &STANDARD.encode(b"hello world"), None)
        .await
        .unwrap();
    client
        .put("test", "2", &STANDARD.encode(b"hello planet"), None)
        .await
        .unwrap();
    client
        .put("test", "3", &STANDARD.encode(b"goodbye world"), None)
        .await
        .unwrap();

    // Exact: "hello world" must have BOTH words
    let result = client
        .search("test", "hello world", Some("exact"), None, None)
        .await
        .unwrap();
    assert_eq!(result.matched, 1);
    assert_eq!(result.results[0].id, "1");

    // Contains: "hello" in entries 1 and 2
    let result = client
        .search("test", "hello", Some("contains"), None, None)
        .await
        .unwrap();
    assert_eq!(result.matched, 2);

    // Contains: "world" in entries 1 and 3
    let result = client
        .search("test", "world", Some("contains"), None, None)
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
        .put("test", "1", &STANDARD.encode(b"hello"), None)
        .await
        .unwrap();
    client
        .put("test", "2", &STANDARD.encode(b"helicopter"), None)
        .await
        .unwrap();
    client
        .put("test", "3", &STANDARD.encode(b"xyzzy"), None)
        .await
        .unwrap();

    // Fuzzy "helo" should match "hello" and "helicopter" (shared trigrams) but not "xyzzy"
    let result = client
        .search("test", "helo", Some("fuzzy"), None, None)
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
        .put("test", "a", &STANDARD.encode(b"hello"), None)
        .await
        .unwrap();
    client
        .put("test", "b", &STANDARD.encode(b"hello"), None)
        .await
        .unwrap();

    // Delete one
    client.delete("test", "a").await.unwrap();

    // Only "b" should remain
    let result = client
        .search("test", "hello", Some("exact"), None, None)
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
            )
            .await
            .unwrap();
    }

    let result = client
        .search("test", "common", Some("exact"), None, Some(3))
        .await
        .unwrap();
    assert_eq!(result.results.len(), 3);
    assert_eq!(result.matched, 10);
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
        )
        .await
        .unwrap();

    // Search by name field value
    let result = client
        .search("contacts", "alice", Some("exact"), None, None)
        .await
        .unwrap();
    assert_eq!(result.matched, 1);
    assert_eq!(result.results[0].id, "c1");

    // "portland" should NOT match since we indexed only the "name" field
    let result = client
        .search("contacts", "portland", Some("exact"), None, None)
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
        .put("pre-seeded", "a", &STANDARD.encode(b"test data"), None)
        .await
        .expect("put on seeded index failed");

    let result = client
        .search("pre-seeded", "test", Some("exact"), None, None)
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
        .search("nope", "query", Some("exact"), None, None)
        .await;
    assert!(err.is_err(), "nonexistent index should error");

    // Duplicate index
    client.index_create("dup").await.unwrap();
    let err = client.index_create("dup").await;
    assert!(err.is_err(), "duplicate index should error");

    // Empty query
    client.index_create("test").await.unwrap();
    let err = client.search("test", "", Some("exact"), None, None).await;
    assert!(err.is_err(), "empty query should error");

    // Invalid base64
    let err = client.put("test", "a", "!!!invalid!!!", None).await;
    assert!(err.is_err(), "invalid base64 should error");

    // Invalid match mode
    let err = client
        .search("test", "query", Some("nonexistent"), None, None)
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
        .put("test", "a", &STANDARD.encode(b"hello"), None)
        .await
        .unwrap();

    // Search for "hello"
    let result = client
        .search("test", "hello", Some("exact"), None, None)
        .await
        .unwrap();
    assert_eq!(result.matched, 1);

    // Overwrite with new data
    client
        .put("test", "a", &STANDARD.encode(b"goodbye"), None)
        .await
        .unwrap();

    // "hello" should no longer match
    let result = client
        .search("test", "hello", Some("exact"), None, None)
        .await
        .unwrap();
    assert_eq!(result.matched, 0);

    // "goodbye" should match
    let result = client
        .search("test", "goodbye", Some("exact"), None, None)
        .await
        .unwrap();
    assert_eq!(result.matched, 1);
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
        .put("users", "u1", &STANDARD.encode(b"data"), None)
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
        .put("users", "u1", &STANDARD.encode(b"Alice"), None)
        .await
        .expect("admin should put");
    let result = client
        .search("users", "alice", Some("exact"), None, None)
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
        .put("users", "u1", &STANDARD.encode(b"Alice"), None)
        .await
        .expect("scoped token should put on granted index");
    client
        .search("users", "alice", Some("exact"), None, None)
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
        .put("users", "u1", &STANDARD.encode(b"Alice"), None)
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
        .search("users", "alice", Some("exact"), None, None)
        .await
        .expect("readonly should search");

    // Read-only CANNOT put (Write scope required)
    let err = client
        .put("users", "u2", &STANDARD.encode(b"Bob"), None)
        .await;
    assert!(err.is_err(), "readonly should not put");

    // Read-only CANNOT delete (Write scope required)
    let err = client.delete("users", "u1").await;
    assert!(err.is_err(), "readonly should not delete");
}
