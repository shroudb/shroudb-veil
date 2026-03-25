use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use shroudb_veil_core::{FieldSelector, tokenize};

use crate::command::IndexArgs;
use crate::error::CommandError;
use crate::response::{ResponseMap, ResponseValue};
use crate::search_engine::extract_search_text;
use crate::transit_backend::TransitBackend;

/// Encrypt plaintext and generate convergent-encrypted search tokens.
pub async fn handle_index(
    transit: &impl TransitBackend,
    args: &IndexArgs,
) -> Result<ResponseMap, CommandError> {
    let plaintext = STANDARD
        .decode(&args.plaintext_b64)
        .map_err(|e| CommandError::BadArg {
            message: format!("invalid base64 plaintext: {e}"),
        })?;

    let context = args.context.as_deref();

    // Encrypt the full plaintext.
    let encrypt_result = transit.encrypt(&args.keyring, &plaintext, context).await?;

    // Extract searchable text for tokenization.
    let field = match &args.field {
        Some(name) => FieldSelector::Named(name.clone()),
        None => FieldSelector::All,
    };
    let search_text = match extract_search_text(&plaintext, &field) {
        Ok(t) => t,
        Err(_) => match std::str::from_utf8(&plaintext) {
            Ok(s) => s.to_string(),
            Err(_) => String::new(),
        },
    };

    // Generate tokens.
    let tokens = tokenize(&search_text);

    // Encrypt each token with convergent encryption on the derived keyring.
    let token_keyring = format!("{}:tokens", args.keyring);
    let token_context = context.unwrap_or(&token_keyring);

    let mut encrypted_tokens = Vec::with_capacity(tokens.len());
    for token in &tokens {
        let token_result = transit
            .encrypt_convergent(&token_keyring, token.as_bytes(), token_context)
            .await?;
        encrypted_tokens.push(token_result.ciphertext);
    }

    let token_values: Vec<ResponseValue> = encrypted_tokens
        .into_iter()
        .map(ResponseValue::String)
        .collect();

    Ok(ResponseMap::ok()
        .with(
            "ciphertext",
            ResponseValue::String(encrypt_result.ciphertext),
        )
        .with(
            "key_version",
            ResponseValue::Integer(encrypt_result.key_version),
        )
        .with("tokens", ResponseValue::Array(token_values)))
}
