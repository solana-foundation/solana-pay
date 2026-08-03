use axum::Json;
use serde_json::{Value, json};

pub async fn handler() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}
