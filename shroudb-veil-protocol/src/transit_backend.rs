//! Transit backend abstraction.
//!
//! The [`TransitBackend`] trait defines the cryptographic operations Veil needs
//! from Transit. Two implementations:
//!
//! - **Remote**: proxies over TCP to an external Transit server (always available).
//! - **Embedded**: runs Transit's engine in-process (requires `embedded` feature).

use crate::error::CommandError;

/// Result of an encrypt operation.
#[derive(Debug, Clone)]
pub struct EncryptOutput {
    pub ciphertext: String,
    pub key_version: i64,
}

/// Result of a decrypt operation.
#[derive(Debug, Clone)]
pub struct DecryptOutput {
    pub plaintext_b64: String,
}

/// Result of a health check.
#[derive(Debug, Clone)]
pub struct HealthOutput {
    pub state: String,
}

/// Trait abstracting Transit operations so Veil is mode-agnostic.
///
/// All methods take `&self` — implementations manage their own internal
/// mutability (connection pools, engine locks, etc.).
pub trait TransitBackend: Send + Sync {
    /// Encrypt plaintext with the named keyring.
    fn encrypt(
        &self,
        keyring: &str,
        plaintext: &[u8],
        context: Option<&str>,
    ) -> impl std::future::Future<Output = Result<EncryptOutput, CommandError>> + Send;

    /// Encrypt with convergent (deterministic) encryption.
    fn encrypt_convergent(
        &self,
        keyring: &str,
        plaintext: &[u8],
        context: &str,
    ) -> impl std::future::Future<Output = Result<EncryptOutput, CommandError>> + Send;

    /// Decrypt ciphertext with the named keyring.
    fn decrypt(
        &self,
        keyring: &str,
        ciphertext: &str,
        context: Option<&str>,
    ) -> impl std::future::Future<Output = Result<DecryptOutput, CommandError>> + Send;

    /// Batch-decrypt ciphertexts. Returns one result per input.
    fn decrypt_batch(
        &self,
        keyring: &str,
        ciphertexts: &[&str],
        context: Option<&str>,
    ) -> impl std::future::Future<Output = Result<Vec<Result<String, String>>, CommandError>> + Send;

    /// Health check.
    fn health(
        &self,
    ) -> impl std::future::Future<Output = Result<HealthOutput, CommandError>> + Send;
}
