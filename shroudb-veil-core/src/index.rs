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
        };

        let json = serde_json::to_string(&idx).unwrap();
        let deserialized: BlindIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "users-email");
        assert_eq!(deserialized.key_material.as_str(), "deadbeefcafebabe");
        assert_eq!(deserialized.created_at, 1700000000);
    }

    #[test]
    fn clone_preserves_key_material() {
        let idx = BlindIndex {
            name: "test".into(),
            key_material: Zeroizing::new("secret".into()),
            created_at: 0,
        };
        let cloned = idx.clone();
        assert_eq!(cloned.key_material.as_str(), "secret");
    }
}
