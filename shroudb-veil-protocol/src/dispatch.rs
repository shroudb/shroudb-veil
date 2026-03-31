use shroudb_acl::AuthContext;
use shroudb_store::Store;
use shroudb_veil_core::matching::MatchMode;
use shroudb_veil_engine::engine::VeilEngine;

use crate::commands::VeilCommand;
use crate::response::VeilResponse;

const SUPPORTED_COMMANDS: &[&str] = &[
    "AUTH",
    "INDEX CREATE",
    "INDEX LIST",
    "INDEX INFO",
    "TOKENIZE",
    "PUT",
    "DELETE",
    "SEARCH",
    "HEALTH",
    "PING",
    "COMMAND LIST",
];

/// Dispatch a parsed command to the VeilEngine and produce a response.
///
/// `auth_context` is the authenticated identity for this connection/request.
/// `None` means auth is disabled (dev mode / no auth config).
/// AUTH commands are handled externally by the TCP layer — dispatch never sees them.
pub async fn dispatch<S: Store>(
    engine: &VeilEngine<S>,
    cmd: VeilCommand,
    auth_context: Option<&AuthContext>,
) -> VeilResponse {
    // Check ACL requirement before dispatch
    let requirement = cmd.acl_requirement();
    if let Some(ctx) = auth_context
        && let Err(e) = ctx.check(&requirement)
    {
        return VeilResponse::error(format!("access denied: {e}"));
    }

    match cmd {
        VeilCommand::Auth { .. } => VeilResponse::error("AUTH handled at connection layer"),

        // ── Index management ──────────────────────────────────────
        VeilCommand::IndexCreate { name } => match engine.index_create(&name).await {
            Ok(info) => VeilResponse::ok(serde_json::json!({
                "status": "ok",
                "index": info.name,
                "created_at": info.created_at,
            })),
            Err(e) => VeilResponse::error(e.to_string()),
        },

        VeilCommand::IndexList => {
            let names = engine.index_list();
            VeilResponse::ok(serde_json::json!(names))
        }

        VeilCommand::IndexInfo { name } => match engine.index_info(&name).await {
            Ok(info) => VeilResponse::ok(serde_json::json!({
                "index": info.name,
                "created_at": info.created_at,
                "entry_count": info.entry_count,
            })),
            Err(e) => VeilResponse::error(e.to_string()),
        },

        // ── Tokenize ──────────────────────────────────────────────
        VeilCommand::Tokenize {
            index,
            plaintext,
            field,
        } => match engine.tokenize(&index, &plaintext, field.as_deref()) {
            Ok(result) => VeilResponse::ok(serde_json::json!({
                "status": "ok",
                "words": result.words.len(),
                "trigrams": result.trigrams.len(),
                "tokens": {
                    "words": result.words,
                    "trigrams": result.trigrams,
                },
            })),
            Err(e) => VeilResponse::error(e.to_string()),
        },

        // ── Put ───────────────────────────────────────────────────
        VeilCommand::Put {
            index,
            id,
            plaintext,
            field,
        } => match engine.put(&index, &id, &plaintext, field.as_deref()).await {
            Ok(version) => VeilResponse::ok(serde_json::json!({
                "status": "ok",
                "id": id,
                "version": version,
            })),
            Err(e) => VeilResponse::error(e.to_string()),
        },

        // ── Delete ────────────────────────────────────────────────
        VeilCommand::Delete { index, id } => match engine.delete(&index, &id).await {
            Ok(()) => VeilResponse::ok(serde_json::json!({
                "status": "ok",
                "id": id,
            })),
            Err(e) => VeilResponse::error(e.to_string()),
        },

        // ── Search ────────────────────────────────────────────────
        VeilCommand::Search {
            index,
            query,
            mode,
            field,
            limit,
        } => {
            let match_mode = match MatchMode::parse(&mode) {
                Ok(m) => m,
                Err(e) => return VeilResponse::error(e),
            };
            match engine
                .search(&index, &query, match_mode, field.as_deref(), limit)
                .await
            {
                Ok(result) => {
                    let hits: Vec<serde_json::Value> = result
                        .hits
                        .iter()
                        .map(|h| {
                            serde_json::json!({
                                "id": h.id,
                                "score": h.score,
                            })
                        })
                        .collect();
                    VeilResponse::ok(serde_json::json!({
                        "status": "ok",
                        "scanned": result.scanned,
                        "matched": result.matched,
                        "results": hits,
                    }))
                }
                Err(e) => VeilResponse::error(e.to_string()),
            }
        }

        // ── Operational ───────────────────────────────────────────
        VeilCommand::Health => VeilResponse::ok(serde_json::json!({
            "status": "ok",
        })),

        VeilCommand::Ping => VeilResponse::ok(serde_json::json!("PONG")),

        VeilCommand::CommandList => VeilResponse::ok(serde_json::json!({
            "count": SUPPORTED_COMMANDS.len(),
            "commands": SUPPORTED_COMMANDS,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::parse_command;
    use shroudb_veil_engine::engine::VeilConfig;

    async fn setup() -> VeilEngine<shroudb_storage::EmbeddedStore> {
        let store = shroudb_storage::test_util::create_test_store("veil-test").await;
        VeilEngine::new(store, VeilConfig::default(), None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn full_put_and_search_flow() {
        let engine = setup().await;

        // Create index
        let cmd = parse_command(&["INDEX", "CREATE", "users"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "index create failed: {resp:?}");

        // Put
        let cmd = parse_command(&["PUT", "users", "u1", "QWxpY2UgSm9obnNvbg=="]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "put failed: {resp:?}");

        // Search
        let cmd = parse_command(&["SEARCH", "users", "alice", "MODE", "exact"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "search failed: {resp:?}");

        match &resp {
            VeilResponse::Ok(v) => {
                assert_eq!(v["matched"], 1);
                assert_eq!(v["results"][0]["id"], "u1");
            }
            _ => panic!("expected ok"),
        }
    }

    #[tokio::test]
    async fn tokenize_flow() {
        let engine = setup().await;

        let cmd = parse_command(&["INDEX", "CREATE", "test"]).unwrap();
        dispatch(&engine, cmd, None).await;

        let cmd = parse_command(&["TOKENIZE", "test", "SGVsbG8gV29ybGQ="]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());

        match &resp {
            VeilResponse::Ok(v) => {
                assert!(v["words"].as_u64().unwrap() > 0);
            }
            _ => panic!("expected ok"),
        }
    }

    #[tokio::test]
    async fn delete_flow() {
        let engine = setup().await;

        let cmd = parse_command(&["INDEX", "CREATE", "test"]).unwrap();
        dispatch(&engine, cmd, None).await;

        let cmd = parse_command(&["PUT", "test", "a", "SGVsbG8="]).unwrap();
        dispatch(&engine, cmd, None).await;

        let cmd = parse_command(&["DELETE", "test", "a"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn health_and_ping() {
        let engine = setup().await;

        let cmd = parse_command(&["HEALTH"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());

        let cmd = parse_command(&["PING"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn index_list_flow() {
        let engine = setup().await;

        let cmd = parse_command(&["INDEX", "CREATE", "a"]).unwrap();
        dispatch(&engine, cmd, None).await;
        let cmd = parse_command(&["INDEX", "CREATE", "b"]).unwrap();
        dispatch(&engine, cmd, None).await;

        let cmd = parse_command(&["INDEX", "LIST"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn nonexistent_index_returns_error() {
        let engine = setup().await;

        let cmd = parse_command(&["SEARCH", "nope", "query"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(!resp.is_ok());
    }

    // ── ACL tests ─────────────────────────────────────────────────────

    fn read_only_context() -> AuthContext {
        use shroudb_acl::{Grant, Scope};
        AuthContext::tenant(
            "tenant-a",
            "read-user",
            vec![Grant {
                namespace: "veil.users.*".into(),
                scopes: vec![Scope::Read],
            }],
            None,
        )
    }

    fn write_context() -> AuthContext {
        use shroudb_acl::{Grant, Scope};
        AuthContext::tenant(
            "tenant-a",
            "write-user",
            vec![Grant {
                namespace: "veil.users.*".into(),
                scopes: vec![Scope::Read, Scope::Write],
            }],
            None,
        )
    }

    #[tokio::test]
    async fn test_unauthorized_write_rejected() {
        let engine = setup().await;
        let ctx = read_only_context();

        // PUT requires Write scope on veil.<index>.*
        let cmd = parse_command(&["PUT", "users", "u1", "QWxpY2U="]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(!resp.is_ok(), "read-only context should not be able to PUT");

        match resp {
            VeilResponse::Error(msg) => assert!(
                msg.contains("access denied"),
                "error should mention access denied, got: {msg}"
            ),
            _ => panic!("expected error response"),
        }
    }

    #[tokio::test]
    async fn test_unauthorized_admin_rejected() {
        let engine = setup().await;
        let ctx = write_context();

        // INDEX CREATE requires Admin scope
        let cmd = parse_command(&["INDEX", "CREATE", "users"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(
            !resp.is_ok(),
            "non-admin context should not be able to create indexes"
        );

        match resp {
            VeilResponse::Error(msg) => assert!(
                msg.contains("access denied"),
                "error should mention access denied, got: {msg}"
            ),
            _ => panic!("expected error response"),
        }
    }
}
