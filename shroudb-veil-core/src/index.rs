use zeroize::Zeroizing;

/// A named blind index configuration.
///
/// Each blind index has an HMAC key used to derive deterministic blind tokens.
/// The key is generated via CSPRNG at creation time and stored encrypted in
/// the ShrouDB Store.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlindIndex {
    /// Index name (alphanumeric, hyphens, underscores).
    pub name: String,
    /// HMAC key material (hex-encoded). Used for blind token derivation.
    pub key_material: Zeroizing<String>,
    /// Unix timestamp of creation.
    pub created_at: u64,
    /// Tokenizer algorithm version used to build entries in this index.
    /// Entries built under an older version are invalid and must be re-indexed.
    #[serde(default = "default_tokenizer_version")]
    pub tokenizer_version: u32,
}

fn default_tokenizer_version() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialization_roundtrip() {
        let idx = BlindIndex {
            name: "users-email".into(),
            key_material: Zeroizing::new("deadbeefcafebabe".into()),
            created_at: 1700000000,
            tokenizer_version: 1,
        };

        let json = serde_json::to_string(&idx).unwrap();
        let deserialized: BlindIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "users-email");
        assert_eq!(deserialized.key_material.as_str(), "deadbeefcafebabe");
        assert_eq!(deserialized.created_at, 1700000000);
        assert_eq!(deserialized.tokenizer_version, 1);
    }

    #[test]
    fn deserialize_without_tokenizer_version_defaults_to_1() {
        let json = r#"{"name":"old","key_material":"aabb","created_at":0}"#;
        let idx: BlindIndex = serde_json::from_str(json).unwrap();
        assert_eq!(idx.tokenizer_version, 1);
    }

    #[test]
    fn clone_preserves_key_material() {
        let idx = BlindIndex {
            name: "test".into(),
            key_material: Zeroizing::new("secret".into()),
            created_at: 0,
            tokenizer_version: 1,
        };
        let cloned = idx.clone();
        assert_eq!(cloned.key_material.as_str(), "secret");
    }
}
