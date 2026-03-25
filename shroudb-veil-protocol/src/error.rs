/// Command execution errors with machine-parseable code prefixes.
#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("DENIED {reason}")]
    Denied { reason: String },

    #[error("BADARG {message}")]
    BadArg { message: String },

    #[error("NOTREADY {0}")]
    NotReady(String),

    #[error("VEIL {0}")]
    Veil(#[from] shroudb_veil_core::VeilError),

    #[error("TRANSIT {0}")]
    Transit(String),

    #[error("INTERNAL {0}")]
    Internal(String),
}
