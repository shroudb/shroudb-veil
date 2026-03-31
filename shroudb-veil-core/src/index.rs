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
