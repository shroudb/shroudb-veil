/// Errors produced by the Veil engine.
#[derive(Debug, thiserror::Error)]
pub enum VeilError {
    #[error("index not found: {0}")]
    IndexNotFound(String),

    #[error("index already exists: {0}")]
    IndexExists(String),

    #[error("entry not found: {index}/{id}")]
    EntryNotFound { index: String, id: String },

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("store error: {0}")]
    Store(String),

    #[error("internal error: {0}")]
    Internal(String),
}
