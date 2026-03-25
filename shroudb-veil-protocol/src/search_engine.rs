//! Search engine: decrypt -> match pipeline with batched Transit operations.
//!
//! Veil takes a batch of ciphertexts, optionally filters by pre-computed search
//! tokens, decrypts candidates via Transit, runs the match engine, and returns
//! results. Plaintext is zeroized on drop.
//!
//! When `rewrap` is enabled, matching entries are re-encrypted with the active
//! key. Otherwise only `{id, score}` is returned — the caller already has the
//! ciphertexts.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

use shroudb_veil_core::{
    FieldSelector, SearchRequest, SearchResponse, SearchResultEntry, VeilError,
    matcher::{DefaultMatcher, Matcher},
    tokenize_query,
};

use crate::error::CommandError;
use crate::transit_backend::TransitBackend;

/// Configurable search parameters wired from the server config.
#[derive(Debug, Clone)]
pub struct SearchConfig {
    /// Maximum number of ciphertexts allowed in a single request.
    pub max_batch_size: usize,
    /// Default result limit when not specified in the request.
    pub default_result_limit: usize,
    /// Number of ciphertexts to decrypt per batch call.
    pub decrypt_batch_size: usize,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 50_000,
            default_result_limit: 100,
            decrypt_batch_size: 500,
        }
    }
}

/// Execute an encrypted search against a batch of ciphertexts.
pub async fn execute_search(
    transit: &impl TransitBackend,
    request: &SearchRequest,
    config: &SearchConfig,
) -> Result<SearchResponse, CommandError> {
    if request.ciphertexts.len() > config.max_batch_size {
        return Err(CommandError::Veil(VeilError::BatchTooLarge {
            count: request.ciphertexts.len(),
            limit: config.max_batch_size,
        }));
    }

    if request.query.is_empty() {
        return Err(CommandError::Veil(VeilError::EmptyQuery));
    }

    let matcher = DefaultMatcher::new(request.match_mode);
    let context = request.context.as_deref();

    // Token pre-filtering: encrypt query tokens and filter entries.
    let has_any_tokens = request.ciphertexts.iter().any(|e| e.tokens.is_some());
    let encrypted_query_tokens = if has_any_tokens {
        encrypt_query_tokens(transit, &request.keyring, &request.query, context).await?
    } else {
        Vec::new()
    };

    // Partition into candidates (pass token filter) and filtered-out.
    let mut candidates: Vec<(usize, &shroudb_veil_core::CiphertextEntry)> = Vec::new();
    let mut filtered: usize = 0;

    for (idx, entry) in request.ciphertexts.iter().enumerate() {
        if let Some(ref tokens) = entry.tokens
            && !encrypted_query_tokens.is_empty()
            && !tokens.iter().any(|t| encrypted_query_tokens.contains(t))
        {
            filtered += 1;
            continue;
        }
        candidates.push((idx, entry));
    }

    let scanned = candidates.len();

    // Decrypt in batches.
    let mut results: Vec<SearchResultEntry> = Vec::new();
    let mut matched: usize = 0;

    for chunk in candidates.chunks(config.decrypt_batch_size) {
        let ct_refs: Vec<&str> = chunk.iter().map(|(_, e)| e.ciphertext.as_str()).collect();

        let decrypt_results = transit
            .decrypt_batch(&request.keyring, &ct_refs, context)
            .await?;

        for (batch_idx, decrypt_result) in decrypt_results.into_iter().enumerate() {
            let (_, entry) = chunk[batch_idx];

            let plaintext_b64 = match decrypt_result {
                Ok(pt) => pt,
                Err(e) => {
                    tracing::warn!(id = %entry.id, error = %e, "skipping undecryptable ciphertext");
                    continue;
                }
            };

            let plaintext = match STANDARD.decode(&plaintext_b64) {
                Ok(pt) => Zeroizing::new(pt),
                Err(e) => {
                    tracing::warn!(id = %entry.id, error = %e, "skipping invalid base64 plaintext");
                    continue;
                }
            };

            let search_text = match extract_search_text(&plaintext, &request.field) {
                Ok(t) => t,
                Err(_) => match std::str::from_utf8(&plaintext) {
                    Ok(s) => s.to_string(),
                    Err(_) => continue,
                },
            };

            let match_result = matcher.matches(&request.query, &search_text);

            if match_result.matched {
                matched += 1;

                if results.len() < request.limit {
                    let (ciphertext, key_version) = if request.rewrap {
                        match transit.encrypt(&request.keyring, &plaintext, context).await {
                            Ok(r) => (Some(r.ciphertext), Some(r.key_version as u32)),
                            Err(e) => {
                                tracing::warn!(id = %entry.id, error = %e, "re-encryption failed");
                                (None, None)
                            }
                        }
                    } else {
                        (None, None)
                    };

                    results.push(SearchResultEntry {
                        id: entry.id.clone(),
                        score: match_result.score,
                        ciphertext,
                        key_version,
                    });
                }
            }
        }
    }

    results.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(SearchResponse {
        results,
        scanned,
        matched,
        filtered,
    })
}

/// Encrypt query tokens with convergent encryption for token pre-filtering.
async fn encrypt_query_tokens(
    transit: &impl TransitBackend,
    keyring: &str,
    query: &str,
    context: Option<&str>,
) -> Result<Vec<String>, CommandError> {
    let query_tokens = tokenize_query(query);
    if query_tokens.is_empty() {
        return Ok(Vec::new());
    }

    let token_keyring = format!("{keyring}:tokens");
    let token_context = context.unwrap_or(&token_keyring);

    let mut encrypted = Vec::with_capacity(query_tokens.len());
    for token in &query_tokens {
        match transit
            .encrypt_convergent(&token_keyring, token.as_bytes(), token_context)
            .await
        {
            Ok(r) => encrypted.push(r.ciphertext),
            Err(e) => {
                tracing::warn!(error = %e, "failed to encrypt query token, disabling token filter");
                return Ok(Vec::new());
            }
        }
    }

    Ok(encrypted)
}

/// Extract searchable text from a decrypted payload.
pub(crate) fn extract_search_text(
    plaintext: &[u8],
    field: &FieldSelector,
) -> Result<String, VeilError> {
    let text = std::str::from_utf8(plaintext).map_err(|_| VeilError::InvalidUtf8)?;

    let json: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return Ok(text.to_string()),
    };

    match field {
        FieldSelector::Named(name) => {
            let value = json
                .get(name)
                .ok_or_else(|| VeilError::FieldNotFound(name.clone()))?;
            match value {
                serde_json::Value::String(s) => Ok(s.clone()),
                other => Ok(other.to_string()),
            }
        }
        FieldSelector::All => {
            let mut parts = Vec::new();
            if let serde_json::Value::Object(map) = &json {
                for value in map.values() {
                    if let serde_json::Value::String(s) = value {
                        parts.push(s.as_str());
                    }
                }
            }
            if parts.is_empty() {
                Ok(text.to_string())
            } else {
                Ok(parts.join(" "))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_named_field() {
        let json = br#"{"sender":"alice","body":"Want to grab dinner?"}"#;
        let text = extract_search_text(json, &FieldSelector::Named("body".into())).unwrap();
        assert_eq!(text, "Want to grab dinner?");
    }

    #[test]
    fn extract_all_fields() {
        let json = br#"{"sender":"alice","body":"Want to grab dinner?"}"#;
        let text = extract_search_text(json, &FieldSelector::All).unwrap();
        assert!(text.contains("alice"));
        assert!(text.contains("dinner"));
    }

    #[test]
    fn extract_plain_text() {
        let plain = b"just a plain message";
        let text = extract_search_text(plain, &FieldSelector::All).unwrap();
        assert_eq!(text, "just a plain message");
    }

    #[test]
    fn extract_missing_field() {
        let json = br#"{"sender":"alice"}"#;
        let result = extract_search_text(json, &FieldSelector::Named("body".into()));
        assert!(result.is_err());
    }
}
