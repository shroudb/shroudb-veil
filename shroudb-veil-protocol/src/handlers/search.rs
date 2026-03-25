use shroudb_veil_core::{CiphertextEntry, FieldSelector, MatchMode, SearchRequest};

use crate::command::SearchArgs;
use crate::error::CommandError;
use crate::response::{ResponseMap, ResponseValue};
use crate::search_engine::{self, SearchConfig};
use crate::transit_backend::TransitBackend;

pub async fn handle_search(
    transit: &impl TransitBackend,
    mode: MatchMode,
    args: &SearchArgs,
    config: &SearchConfig,
) -> Result<ResponseMap, CommandError> {
    let field_selector = match &args.field {
        Some(name) => FieldSelector::Named(name.clone()),
        None => FieldSelector::All,
    };

    let request = SearchRequest {
        keyring: args.keyring.clone(),
        query: args.query.clone(),
        match_mode: mode,
        field: field_selector,
        context: args.context.clone(),
        limit: args.limit.unwrap_or(config.default_result_limit),
        rewrap: args.rewrap,
        ciphertexts: args
            .entries
            .iter()
            .enumerate()
            .map(|(i, e)| CiphertextEntry {
                id: i.to_string(),
                ciphertext: e.ciphertext.clone(),
                tokens: e.tokens.clone(),
            })
            .collect(),
    };

    let response = search_engine::execute_search(transit, &request, config).await?;

    let result_entries: Vec<ResponseValue> = response
        .results
        .iter()
        .map(|entry| {
            let mut map = ResponseMap::ok()
                .with("id", ResponseValue::String(entry.id.clone()))
                .with("score", ResponseValue::Float(entry.score as f64));
            if let Some(ref ct) = entry.ciphertext {
                map = map.with("ciphertext", ResponseValue::String(ct.clone()));
            }
            if let Some(kv) = entry.key_version {
                map = map.with("key_version", ResponseValue::Integer(kv as i64));
            }
            ResponseValue::Map(map)
        })
        .collect();

    Ok(ResponseMap::ok()
        .with("scanned", ResponseValue::Integer(response.scanned as i64))
        .with("matched", ResponseValue::Integer(response.matched as i64))
        .with("filtered", ResponseValue::Integer(response.filtered as i64))
        .with("results", ResponseValue::Array(result_entries)))
}
