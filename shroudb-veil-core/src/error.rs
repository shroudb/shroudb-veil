/// Errors that originate in the Veil core domain.
#[derive(Debug, thiserror::Error)]
pub enum VeilError {
    #[error("search query is empty")]
    EmptyQuery,

    #[error("ciphertext batch too large: {count} exceeds limit {limit}")]
    BatchTooLarge { count: usize, limit: usize },

    #[error("field not found in decrypted payload: {0}")]
    FieldNotFound(String),

    #[error("decrypted payload is not valid UTF-8")]
    InvalidUtf8,

    #[error("decrypted payload is not valid JSON: {0}")]
    InvalidJson(String),

    #[error("search timed out after {0} ms")]
    Timeout(u64),

    #[error("transit client error: {0}")]
    Transit(String),
}
