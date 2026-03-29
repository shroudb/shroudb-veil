/// A Veil command response, ready for RESP3 serialization.
#[derive(Debug)]
pub enum VeilResponse {
    /// Success with data.
    Ok(serde_json::Value),
    /// Error response.
    Error(String),
}

impl VeilResponse {
    pub fn ok(data: serde_json::Value) -> Self {
        Self::Ok(data)
    }

    pub fn ok_simple() -> Self {
        Self::Ok(serde_json::json!({"status": "ok"}))
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self::Error(msg.into())
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }
}
