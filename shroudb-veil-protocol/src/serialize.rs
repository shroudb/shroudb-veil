//! Serialize Veil command responses to JSON for wire output.

use crate::response::{CommandResponse, ResponseMap, ResponseValue};

/// Convert a `CommandResponse` to a JSON value.
pub fn response_to_json(response: &CommandResponse) -> serde_json::Value {
    match response {
        CommandResponse::Success(map) => map_to_json(map),
        CommandResponse::Error(e) => serde_json::json!({ "error": e.to_string() }),
        CommandResponse::Array(items) => {
            serde_json::Value::Array(items.iter().map(response_to_json).collect())
        }
    }
}

fn map_to_json(map: &ResponseMap) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    for (k, v) in &map.fields {
        obj.insert(k.clone(), value_to_json(v));
    }
    serde_json::Value::Object(obj)
}

fn value_to_json(value: &ResponseValue) -> serde_json::Value {
    match value {
        ResponseValue::String(s) => serde_json::Value::String(s.clone()),
        ResponseValue::Integer(n) => serde_json::json!(n),
        ResponseValue::Float(f) => serde_json::json!(f),
        ResponseValue::Boolean(b) => serde_json::json!(b),
        ResponseValue::Null => serde_json::Value::Null,
        ResponseValue::Map(m) => map_to_json(m),
        ResponseValue::Array(items) => {
            serde_json::Value::Array(items.iter().map(value_to_json).collect())
        }
    }
}
