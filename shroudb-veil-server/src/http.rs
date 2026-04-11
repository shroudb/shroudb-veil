use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use tower_http::cors::{Any, CorsLayer};

use shroudb_acl::{AclRequirement, AuthContext, Scope, TokenValidator};
use shroudb_store::Store;
use shroudb_veil_core::matching::MatchMode;
use shroudb_veil_engine::engine::VeilEngine;

// -- State ------------------------------------------------------------------

struct AppState<S: Store> {
    engine: Arc<VeilEngine<S>>,
    token_validator: Option<Arc<dyn TokenValidator>>,
}

impl<S: Store> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
            token_validator: self.token_validator.clone(),
        }
    }
}

// -- Router -----------------------------------------------------------------

pub fn router<S: Store + 'static>(
    engine: Arc<VeilEngine<S>>,
    token_validator: Option<Arc<dyn TokenValidator>>,
) -> Router {
    let state = AppState {
        engine,
        token_validator,
    };

    Router::new()
        .route("/index/create", post(index_create::<S>))
        .route("/index/destroy", post(index_destroy::<S>))
        .route("/index/rotate", post(index_rotate::<S>))
        .route("/index/reindex", post(index_reindex::<S>))
        .route("/index/reconcile", post(index_reconcile::<S>))
        .route("/index/info", get(index_info::<S>))
        .route("/index/list", get(index_list::<S>))
        .route("/put", post(put::<S>))
        .route("/entry", delete(delete_entry::<S>))
        .route("/search", get(search::<S>))
        .route("/tokenize", post(tokenize::<S>))
        .route("/health", get(health::<S>))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state)
}

// -- Auth -------------------------------------------------------------------

fn extract_auth_context<S: Store>(
    state: &AppState<S>,
    headers: &HeaderMap,
) -> Result<Option<AuthContext>, Box<Response>> {
    let Some(ref validator) = state.token_validator else {
        return Ok(None);
    };

    let Some(auth_header) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        Box::new(err_response(
            StatusCode::UNAUTHORIZED,
            "expected Bearer token",
        ))
    })?;

    match validator.validate(token) {
        Ok(tok) => Ok(Some(tok.into_context())),
        Err(e) => Err(Box::new(err_response(
            StatusCode::UNAUTHORIZED,
            &format!("invalid token: {e}"),
        ))),
    }
}

fn require_auth<S: Store>(
    state: &AppState<S>,
    headers: &HeaderMap,
    acl: &AclRequirement,
) -> Result<Option<AuthContext>, Box<Response>> {
    let auth = extract_auth_context(state, headers)?;

    if state.token_validator.is_some() && auth.is_none() && *acl != AclRequirement::None {
        return Err(Box::new(err_response(
            StatusCode::UNAUTHORIZED,
            "authentication required — provide Authorization: Bearer <token>",
        )));
    }

    if let Err(e) = shroudb_acl::check_dispatch_acl(auth.as_ref(), acl) {
        return Err(Box::new(err_response(StatusCode::FORBIDDEN, &e)));
    }

    Ok(auth)
}

// -- Response helpers -------------------------------------------------------

fn err_response(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({"error": msg}))).into_response()
}

fn veil_err(msg: &str) -> Response {
    let status = if msg.contains("access denied") {
        StatusCode::FORBIDDEN
    } else if msg.contains("not found") || msg.contains("no such index") {
        StatusCode::NOT_FOUND
    } else if msg.contains("already exists") {
        StatusCode::CONFLICT
    } else if msg.contains("invalid") || msg.contains("bad") {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (status, Json(json!({"error": msg}))).into_response()
}

// -- Request types ----------------------------------------------------------

#[derive(Debug, Deserialize)]
struct NameParam {
    name: String,
}

#[derive(Debug, Deserialize)]
struct PutBody {
    index: String,
    entry_id: String,
    data: String,
    #[serde(default)]
    field: Option<String>,
    #[serde(default)]
    blind: bool,
}

#[derive(Debug, Deserialize)]
struct DeleteParams {
    index: String,
    entry_id: String,
}

#[derive(Debug, Deserialize)]
struct SearchParams {
    index: String,
    query: String,
    #[serde(default = "default_mode")]
    mode: String,
    #[serde(default)]
    field: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    blind: bool,
}

fn default_mode() -> String {
    "contains".into()
}

#[derive(Debug, Deserialize)]
struct TokenizeBody {
    index: String,
    data: String,
    #[serde(default)]
    field: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReconcileBody {
    name: String,
    valid_ids: Vec<String>,
}

// -- Handlers ---------------------------------------------------------------

async fn index_create<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Json(body): Json<NameParam>,
) -> Response {
    let _auth = match require_auth(&state, &headers, &AclRequirement::Admin) {
        Ok(a) => a,
        Err(r) => return *r,
    };

    match state.engine.index_create(&body.name).await {
        Ok(info) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "index": info.name,
                "created_at": info.created_at,
                "tokenizer_version": info.tokenizer_version,
            })),
        )
            .into_response(),
        Err(e) => veil_err(&e.to_string()),
    }
}

async fn index_destroy<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Json(body): Json<NameParam>,
) -> Response {
    let _auth = match require_auth(&state, &headers, &AclRequirement::Admin) {
        Ok(a) => a,
        Err(r) => return *r,
    };

    match state.engine.index_destroy(&body.name).await {
        Ok(deleted) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "index": body.name,
                "deleted_entries": deleted,
            })),
        )
            .into_response(),
        Err(e) => veil_err(&e.to_string()),
    }
}

async fn index_rotate<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Json(body): Json<NameParam>,
) -> Response {
    let _auth = match require_auth(&state, &headers, &AclRequirement::Admin) {
        Ok(a) => a,
        Err(r) => return *r,
    };

    match state.engine.index_rotate(&body.name).await {
        Ok(info) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "index": info.name,
                "rotated_at": info.created_at,
                "entry_count": info.entry_count,
            })),
        )
            .into_response(),
        Err(e) => veil_err(&e.to_string()),
    }
}

async fn index_reindex<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Json(body): Json<NameParam>,
) -> Response {
    let _auth = match require_auth(&state, &headers, &AclRequirement::Admin) {
        Ok(a) => a,
        Err(r) => return *r,
    };

    match state.engine.index_reindex(&body.name).await {
        Ok(result) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "index": result.name,
                "tokenizer_version": result.tokenizer_version,
                "entries_cleared": result.entries_cleared,
            })),
        )
            .into_response(),
        Err(e) => veil_err(&e.to_string()),
    }
}

async fn index_reconcile<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Json(body): Json<ReconcileBody>,
) -> Response {
    let _auth = match require_auth(&state, &headers, &AclRequirement::Admin) {
        Ok(a) => a,
        Err(r) => return *r,
    };

    match state
        .engine
        .reconcile_orphans(&body.name, &body.valid_ids)
        .await
    {
        Ok(result) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "index": body.name,
                "orphans_removed": result.orphans_removed,
            })),
        )
            .into_response(),
        Err(e) => veil_err(&e.to_string()),
    }
}

async fn index_info<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Query(params): Query<NameParam>,
) -> Response {
    let acl = AclRequirement::Namespace {
        ns: format!("veil.{}.*", params.name),
        scope: Scope::Read,
        tenant_override: None,
    };
    let _auth = match require_auth(&state, &headers, &acl) {
        Ok(a) => a,
        Err(r) => return *r,
    };

    match state.engine.index_info(&params.name).await {
        Ok(info) => (
            StatusCode::OK,
            Json(json!({
                "index": info.name,
                "created_at": info.created_at,
                "entry_count": info.entry_count,
                "tokenizer_version": info.tokenizer_version,
            })),
        )
            .into_response(),
        Err(e) => veil_err(&e.to_string()),
    }
}

async fn index_list<S: Store + 'static>(State(state): State<AppState<S>>) -> Response {
    let names = state.engine.index_list();
    (StatusCode::OK, Json(json!(names))).into_response()
}

async fn put<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Json(body): Json<PutBody>,
) -> Response {
    let acl = AclRequirement::Namespace {
        ns: format!("veil.{}.*", body.index),
        scope: Scope::Write,
        tenant_override: None,
    };
    let _auth = match require_auth(&state, &headers, &acl) {
        Ok(a) => a,
        Err(r) => return *r,
    };

    match state
        .engine
        .put(
            &body.index,
            &body.entry_id,
            &body.data,
            body.field.as_deref(),
            body.blind,
        )
        .await
    {
        Ok(version) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "id": body.entry_id,
                "version": version,
            })),
        )
            .into_response(),
        Err(e) => veil_err(&e.to_string()),
    }
}

async fn delete_entry<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Query(params): Query<DeleteParams>,
) -> Response {
    let acl = AclRequirement::Namespace {
        ns: format!("veil.{}.*", params.index),
        scope: Scope::Write,
        tenant_override: None,
    };
    let _auth = match require_auth(&state, &headers, &acl) {
        Ok(a) => a,
        Err(r) => return *r,
    };

    match state.engine.delete(&params.index, &params.entry_id).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "id": params.entry_id,
            })),
        )
            .into_response(),
        Err(e) => veil_err(&e.to_string()),
    }
}

async fn search<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Query(params): Query<SearchParams>,
) -> Response {
    let acl = AclRequirement::Namespace {
        ns: format!("veil.{}.*", params.index),
        scope: Scope::Read,
        tenant_override: None,
    };
    let _auth = match require_auth(&state, &headers, &acl) {
        Ok(a) => a,
        Err(r) => return *r,
    };

    let match_mode = match MatchMode::parse(&params.mode) {
        Ok(m) => m,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, &e),
    };

    match state
        .engine
        .search(
            &params.index,
            &params.query,
            match_mode,
            params.field.as_deref(),
            params.limit,
            params.blind,
        )
        .await
    {
        Ok(result) => {
            let hits: Vec<serde_json::Value> = result
                .hits
                .iter()
                .map(|h| {
                    json!({
                        "id": h.id,
                        "score": h.score,
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(json!({
                    "status": "ok",
                    "scanned": result.scanned,
                    "matched": result.matched,
                    "results": hits,
                })),
            )
                .into_response()
        }
        Err(e) => veil_err(&e.to_string()),
    }
}

async fn tokenize<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Json(body): Json<TokenizeBody>,
) -> Response {
    let acl = AclRequirement::Namespace {
        ns: format!("veil.{}.*", body.index),
        scope: Scope::Read,
        tenant_override: None,
    };
    let _auth = match require_auth(&state, &headers, &acl) {
        Ok(a) => a,
        Err(r) => return *r,
    };

    match state
        .engine
        .tokenize(&body.index, &body.data, body.field.as_deref())
    {
        Ok(result) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "words": result.words.len(),
                "trigrams": result.trigrams.len(),
                "tokens": {
                    "words": result.words,
                    "trigrams": result.trigrams,
                },
            })),
        )
            .into_response(),
        Err(e) => veil_err(&e.to_string()),
    }
}

async fn health<S: Store + 'static>(State(state): State<AppState<S>>) -> Response {
    let index_count = state.engine.index_list().len();
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "indexes": index_count,
        })),
    )
        .into_response()
}
