//! HMAC-based blind token derivation.
//!
//! Each token is transformed via HMAC-SHA256(index_key, token_string)
//! to produce a deterministic blind token. Same input + same key = same output,
//! enabling equality comparison without revealing the plaintext.

use ring::hmac;
use shroudb_crypto::SecretBytes;
use shroudb_veil_core::error::VeilError;
use shroudb_veil_core::tokenizer::TokenSet;

/// Generate HMAC key material (32 bytes from CSPRNG).
pub fn generate_key_material() -> Result<Vec<u8>, VeilError> {
    let rng = ring::rand::SystemRandom::new();
    let mut key = vec![0u8; 32];
    ring::rand::SecureRandom::fill(&rng, &mut key)
        .map_err(|_| VeilError::Internal("CSPRNG failed".into()))?;
    Ok(key)
}

/// Derive blind tokens from a TokenSet using HMAC-SHA256.
///
/// Each token string is HMAC'd with the index key, producing a hex-encoded
/// blind token. The result is deterministic: same key + same input = same output.
pub fn blind_token_set(key: &SecretBytes, tokens: &TokenSet) -> BlindTokenSet {
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key.as_bytes());

    let words = tokens
        .words
        .iter()
        .map(|t| blind_one(&signing_key, t))
        .collect();

    let trigrams = tokens
        .trigrams
        .iter()
        .map(|t| blind_one(&signing_key, t))
        .collect();

    BlindTokenSet { words, trigrams }
}

fn blind_one(key: &hmac::Key, token: &str) -> String {
    let tag = hmac::sign(key, token.as_bytes());
    hex::encode(tag.as_ref())
}

/// A set of HMAC-derived blind tokens, ready for storage or comparison.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlindTokenSet {
    pub words: Vec<String>,
    pub trigrams: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroudb_veil_core::tokenizer::tokenize;

    #[test]
    fn deterministic_blinding() {
        let key = SecretBytes::new(vec![0x42u8; 32]);
        let tokens = tokenize("hello world");

        let blind1 = blind_token_set(&key, &tokens);
        let blind2 = blind_token_set(&key, &tokens);

        assert_eq!(blind1.words, blind2.words);
        assert_eq!(blind1.trigrams, blind2.trigrams);
    }

    #[test]
    fn different_keys_produce_different_tokens() {
        let key1 = SecretBytes::new(vec![0x42u8; 32]);
        let key2 = SecretBytes::new(vec![0x43u8; 32]);
        let tokens = tokenize("hello");

        let blind1 = blind_token_set(&key1, &tokens);
        let blind2 = blind_token_set(&key2, &tokens);

        assert_ne!(blind1.words, blind2.words);
    }

    #[test]
    fn blind_tokens_are_hex() {
        let key = SecretBytes::new(vec![0x42u8; 32]);
        let tokens = tokenize("hello");
        let blind = blind_token_set(&key, &tokens);

        for w in &blind.words {
            assert!(hex::decode(w).is_ok());
            assert_eq!(w.len(), 64); // SHA256 = 32 bytes = 64 hex chars
        }
    }

    #[test]
    fn generate_key_material_produces_32_bytes() {
        let key = generate_key_material().unwrap();
        assert_eq!(key.len(), 32);
    }
}
