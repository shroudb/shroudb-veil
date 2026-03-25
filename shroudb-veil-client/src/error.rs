/// Errors that can occur when using the Veil client.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// TCP connection or I/O error.
    #[error("connection failed: {0}")]
    Connection(#[from] std::io::Error),

    /// The server returned an error response.
    #[error("server error: {0}")]
    Server(String),

    /// Protocol-level error (malformed response, unexpected type, etc.).
    #[error("protocol error: {0}")]
    Protocol(String),
}
