//! Settings-only reset; the retained worker owns shutdown, removal and reboot.
use std::sync::Arc;
use axum::{Json, Router, http::StatusCode, routing::post};
use serde::Deserialize;
use serde_json::{json, Value};
use crate::AppState;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request { confirmation: String }

async fn reset(Json(request): Json<Request>) -> (StatusCode, Json<Value>) {
    if request.confirmation != "RESET DCENT_OS SETTINGS" {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "confirmation_required",
            "detail": "Type RESET DCENT_OS SETTINGS to clear DCENT settings and credentials."})));
    }
    if let Err(error) = crate::reset_default::verify_installed_reset_default().await {
        return (StatusCode::CONFLICT, Json(json!({"error": "reset_default_unverified", "detail": error})));
    }
    let result = tokio::time::timeout(std::time::Duration::from_secs(5),
        tokio::process::Command::new("/usr/bin/python3")
            .args(["/usr/libexec/dcentos/dcentos-reset-settings.py", "schedule"])
            .kill_on_drop(true).output()).await;
    match result {
        Ok(Ok(output)) if output.status.success() && serde_json::from_slice::<Value>(&output.stdout)
            .ok().is_some_and(|v| v["status"] == "scheduled" && v["operation"] == "reset_settings") =>
            (StatusCode::ACCEPTED, Json(json!({"status": "scheduled", "operation": "reset_settings",
                "detail": "Waiting for checked mining shutdown. Settings are cleared only after it succeeds; the miner then reboots with mining disabled."}))),
        _ => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "reset_unavailable",
            "detail": "The retained settings-reset worker could not be scheduled. Settings were not cleared by this request."}))),
    }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/system/reset-settings", post(reset))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn confirmation_is_exact_and_never_launches_worker_on_refusal() {
        for phrase in ["", "true", "RESET DCENT_OS SETTINGS ", "reset dcent_os settings"] {
            assert_eq!(reset(Json(Request { confirmation: phrase.into() })).await.0, StatusCode::BAD_REQUEST);
        }
        assert!(serde_json::from_value::<Request>(json!({"confirmation": "x", "force": true})).is_err());
    }
}
