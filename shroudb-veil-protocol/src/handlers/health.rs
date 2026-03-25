use crate::error::CommandError;
use crate::response::{ResponseMap, ResponseValue};
use crate::transit_backend::TransitBackend;

/// Health check — also verifies the Transit backend is alive.
pub async fn handle_health(transit: &impl TransitBackend) -> Result<ResponseMap, CommandError> {
    let health = transit.health().await?;

    Ok(ResponseMap::ok()
        .with("state", ResponseValue::String("ready".into()))
        .with("transit", ResponseValue::String(health.state)))
}
