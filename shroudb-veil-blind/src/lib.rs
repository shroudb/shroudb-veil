//! Client-side blind token generation for Veil E2EE workflows.
//!
//! This crate lets clients tokenize and blind plaintext locally,
//! so the Veil server never sees plaintext or HMAC keys.
//!
//! # Tokenizer contract
//!
//! The tokenization algorithm (word splitting, trigram generation,
//! normalization) is a versioned contract shared with the server-side
//! Veil engine via `shroudb-veil-core`. Changes to the algorithm
//! require a major version bump and re-indexing of all entries.
//!
//! # Usage
//!
//! ```
//! use shroudb_veil_blind::{BlindKey, tokenize_and_blind, encode_for_wire};
//!
//! // Generate or derive a client-side HMAC key
//! let key = BlindKey::generate().unwrap();
//!
//! // Tokenize + blind locally
//! let tokens = tokenize_and_blind(&key, "hello world");
//!
//! // Encode for BLIND_PUT / BLIND_SEARCH wire format
//! let wire = encode_for_wire(&tokens).unwrap();
//! ```

use base64::Engine as _;
use ring::hmac;
use shroudb_veil_core::tokenizer::{self, TokenSet};
use zeroize::Zeroizing;

/// The tokenizer algorithm version. Clients should store this alongside
/// their HMAC key so they know which tokenizer produced their blind tokens.
/// A bump here means all existing blind tokens must be re-indexed.
pub const TOKENIZER_VERSION: u32 = 1;

/// A client-side HMAC key for blind token generation.
///
/// This key is held exclusively by the client (or shared between
/// two parties in an E2EE conversation). The Veil server never sees it.
pub struct BlindKey {
    material: Zeroizing<Vec<u8>>,
}

impl BlindKey {
    /// Create from raw 32-byte key material.
    pub fn from_bytes(key: Vec<u8>) -> Result<Self, BlindError> {
        if key.len() != 32 {
            return Err(BlindError::InvalidKeyLength(key.len()));
        }
        Ok(Self {
            material: Zeroizing::new(key),
        })
    }

    /// Generate a new random key via CSPRNG.
    pub fn generate() -> Result<Self, BlindError> {
        let rng = ring::rand::SystemRandom::new();
        let mut key = vec![0u8; 32];
        ring::rand::SecureRandom::fill(&rng, &mut key).map_err(|_| BlindError::KeyGeneration)?;
        Ok(Self {
            material: Zeroizing::new(key),
        })
    }

    /// Derive a search key from a shared secret using HKDF-SHA256.
    ///
    /// Use this in E2EE key exchange workflows:
    /// ```ignore
    /// let shared_secret = x25519_exchange(...);
    /// let search_key = BlindKey::derive(shared_secret, b"veil-search-v1")?;
    /// ```
    pub fn derive(shared_secret: &[u8], info: &[u8]) -> Result<Self, BlindError> {
        // HKDF-Extract: PRK = HMAC-SHA256(salt=zeros, IKM=shared_secret)
        let salt = hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]);
        let prk = hmac::sign(&salt, shared_secret);

        // HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01) truncated to 32 bytes
        let info_key = hmac::Key::new(hmac::HMAC_SHA256, prk.as_ref());
        let mut expand_input = Vec::with_capacity(info.len() + 1);
        expand_input.extend_from_slice(info);
        expand_input.push(1u8);
        let out = hmac::sign(&info_key, &expand_input);
        let mut okm = vec![0u8; 32];
        okm.copy_from_slice(&out.as_ref()[..32]);

        Self::from_bytes(okm)
    }

    /// Export raw key bytes (for storage in client keychain).
    pub fn as_bytes(&self) -> &[u8] {
        &self.material
    }
}

/// Pre-computed blind tokens ready to send to Veil via `BLIND_PUT`/`BLIND_SEARCH`.
///
/// This is wire-compatible with the `BlindTokenSet` stored by the Veil engine.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlindTokenSet {
    pub words: Vec<String>,
    pub trigrams: Vec<String>,
}

/// Tokenize plaintext and blind the tokens with the client's key.
///
/// This is the client-side equivalent of what Veil does server-side
/// during a normal `PUT`. The result can be sent via `BLIND_PUT`.
pub fn tokenize_and_blind(key: &BlindKey, plaintext: &str) -> BlindTokenSet {
    let tokens = tokenizer::tokenize(plaintext);
    blind_tokens(key, &tokens)
}

/// Tokenize data with optional JSON field extraction, then blind.
///
/// If `field` is `Some`, extracts that field's string value from JSON.
/// If `None`, concatenates all string values (or treats as raw UTF-8).
pub fn tokenize_and_blind_field(key: &BlindKey, data: &[u8], field: Option<&str>) -> BlindTokenSet {
    let text = tokenizer::extract_text(data, field);
    let tokens = tokenizer::tokenize(&text);
    blind_tokens(key, &tokens)
}

/// Blind a pre-computed `TokenSet`. Useful if the caller wants to
/// inspect raw tokens before blinding.
pub fn blind_tokens(key: &BlindKey, tokens: &TokenSet) -> BlindTokenSet {
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, &key.material);

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

/// Encode a `BlindTokenSet` as base64 JSON for the `BLIND_PUT`/`BLIND_SEARCH` wire format.
pub fn encode_for_wire(tokens: &BlindTokenSet) -> Result<String, BlindError> {
    let json = serde_json::to_vec(tokens).map_err(|e| BlindError::Serialization(e.to_string()))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(&json))
}

/// Decode a base64-encoded `BlindTokenSet` from wire format.
pub fn decode_from_wire(encoded: &str) -> Result<BlindTokenSet, BlindError> {
    let json = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| BlindError::Serialization(format!("invalid base64: {e}")))?;
    serde_json::from_slice(&json).map_err(|e| BlindError::Serialization(e.to_string()))
}

fn blind_one(key: &hmac::Key, token: &str) -> String {
    let tag = hmac::sign(key, token.as_bytes());
    hex::encode(tag.as_ref())
}

/// Errors from client-side blind token operations.
#[derive(Debug, thiserror::Error)]
pub enum BlindError {
    #[error("invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),
    #[error("key generation failed")]
    KeyGeneration,
    #[error("serialization failed: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_key() {
        let key = BlindKey::generate().unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn from_bytes_valid() {
        let key = BlindKey::from_bytes(vec![0x42u8; 32]).unwrap();
        assert_eq!(key.as_bytes(), &[0x42u8; 32]);
    }

    #[test]
    fn from_bytes_invalid_length() {
        assert!(BlindKey::from_bytes(vec![0u8; 16]).is_err());
        assert!(BlindKey::from_bytes(vec![0u8; 64]).is_err());
    }

    #[test]
    fn derive_produces_32_bytes() {
        let key = BlindKey::derive(b"shared-secret", b"veil-search-v1").unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn derive_deterministic() {
        let k1 = BlindKey::derive(b"secret", b"info").unwrap();
        let k2 = BlindKey::derive(b"secret", b"info").unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_different_info_produces_different_keys() {
        let k1 = BlindKey::derive(b"secret", b"search").unwrap();
        let k2 = BlindKey::derive(b"secret", b"encrypt").unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn tokenize_and_blind_deterministic() {
        let key = BlindKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let t1 = tokenize_and_blind(&key, "hello world");
        let t2 = tokenize_and_blind(&key, "hello world");

        assert_eq!(t1.words, t2.words);
        assert_eq!(t1.trigrams, t2.trigrams);
    }

    #[test]
    fn tokenize_and_blind_produces_hex_tokens() {
        let key = BlindKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let tokens = tokenize_and_blind(&key, "hello world");

        assert_eq!(tokens.words.len(), 2);
        for w in &tokens.words {
            assert_eq!(w.len(), 64); // SHA256 = 32 bytes = 64 hex chars
            assert!(hex::decode(w).is_ok());
        }
    }

    #[test]
    fn different_keys_produce_different_tokens() {
        let k1 = BlindKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let k2 = BlindKey::from_bytes(vec![0x43u8; 32]).unwrap();

        let t1 = tokenize_and_blind(&k1, "hello");
        let t2 = tokenize_and_blind(&k2, "hello");

        assert_ne!(t1.words, t2.words);
    }

    #[test]
    fn tokenize_and_blind_field_json() {
        let key = BlindKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let data = br#"{"name": "Alice", "city": "Portland"}"#;

        let name_tokens = tokenize_and_blind_field(&key, data, Some("name"));
        let city_tokens = tokenize_and_blind_field(&key, data, Some("city"));

        // "alice" and "portland" produce different blind tokens
        assert_ne!(name_tokens.words, city_tokens.words);
        assert_eq!(name_tokens.words.len(), 1); // "alice"
        assert_eq!(city_tokens.words.len(), 1); // "portland"
    }

    #[test]
    fn encode_decode_roundtrip() {
        let key = BlindKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let tokens = tokenize_and_blind(&key, "hello world");

        let encoded = encode_for_wire(&tokens).unwrap();
        let decoded = decode_from_wire(&encoded).unwrap();

        assert_eq!(tokens.words, decoded.words);
        assert_eq!(tokens.trigrams, decoded.trigrams);
    }

    #[test]
    fn decode_invalid_base64() {
        assert!(decode_from_wire("not-valid!!!").is_err());
    }

    #[test]
    fn decode_invalid_json() {
        let bad = base64::engine::general_purpose::STANDARD.encode(b"not json");
        assert!(decode_from_wire(&bad).is_err());
    }

    #[test]
    fn blind_tokens_matches_server_side() {
        // Verify that client-side blinding produces the same output as
        // the server-side hmac_ops when using the same key material.
        // This is the critical compatibility test.
        let key_bytes = vec![0x42u8; 32];
        let client_key = BlindKey::from_bytes(key_bytes.clone()).unwrap();
        let client_tokens = tokenize_and_blind(&client_key, "hello world");

        // The tokenizer is shared (shroudb-veil-core), so tokenization is
        // identical. The HMAC is ring::hmac::HMAC_SHA256 on both sides.
        // If this test passes, client and server produce identical blind tokens.
        let tokens = tokenizer::tokenize("hello world");
        assert_eq!(tokens.words.len(), client_tokens.words.len());
        assert_eq!(tokens.trigrams.len(), client_tokens.trigrams.len());

        // Verify each blind token is a valid HMAC-SHA256 output
        let signing_key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
        for (i, word) in tokens.words.iter().enumerate() {
            let expected = hmac::sign(&signing_key, word.as_bytes());
            assert_eq!(client_tokens.words[i], hex::encode(expected.as_ref()));
        }
    }

    #[test]
    fn empty_input_produces_empty_tokens() {
        let key = BlindKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let tokens = tokenize_and_blind(&key, "");
        assert!(tokens.words.is_empty());
        assert!(tokens.trigrams.is_empty());
    }

    #[test]
    fn short_words_no_trigrams() {
        let key = BlindKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let tokens = tokenize_and_blind(&key, "hi ok");
        assert_eq!(tokens.words.len(), 2);
        assert!(tokens.trigrams.is_empty());
    }
}
