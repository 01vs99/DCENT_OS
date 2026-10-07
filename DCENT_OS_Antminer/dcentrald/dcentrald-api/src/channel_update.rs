//! Explicit check -> download/verify -> apply. A feed never overrides OTA policy.
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use axum::{
    extract::{DefaultBodyLimit, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use dcent_schema::update::{ChannelFeedTarget, UpdateChannel};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{channel_download as download, channel_feed, AppState};

static OPERATION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static STATUS: OnceLock<Mutex<Option<(String, Value)>>> = OnceLock::new();
type Reply = (StatusCode, Json<Value>);

fn status_value(id: &str, value: Value) {
    if let Ok(mut status) = STATUS.get_or_init(|| Mutex::new(None)).lock() {
        *status = Some((id.to_owned(), value));
    }
}

fn progress(id: &str, phase: &str, bytes: u64, total: u64) {
    status_value(
        id,
        json!({"operation_id": id, "phase": phase, "downloaded_bytes": bytes,
                            "total_bytes": total, "update_started": false}),
    );
}

fn complete(id: &str, result: Result<Value, String>, success: &str) {
    status_value(
        id,
        match result {
            Ok(value) => json!({"operation_id": id, "phase": success, "result": value}),
            Err(detail) => json!({"operation_id": id, "phase": "failed", "detail": detail,
            "update_started": if success == "scheduled" { Value::Null } else { json!(false) }}),
        },
    );
}

fn error(detail: impl Into<String>) -> Reply {
    (
        StatusCode::CONFLICT,
        Json(json!({"error": "channel_update_refused", "detail": detail.into()})),
    )
}

struct Context {
    board: String,
    version: String,
    recipe: String,
    channel: UpdateChannel,
    url: String,
}

async fn context(state: &Arc<AppState>) -> Result<Context, String> {
    // This is the same capability + exact target/storage policy boundary used
    // by uploaded packages, before any network request or stage creation.
    let board = crate::rest::require_channel_update_policy(state).await?;
    let image =
        crate::runtime_image::verify_installed_runtime_image(&board, env!("CARGO_PKG_VERSION"))
            .await?;
    let (channel, label) = match image.channel() {
        dcentrald_common::ReleaseChannel::Beta => (UpdateChannel::Beta, "beta"),
        dcentrald_common::ReleaseChannel::Stable => (UpdateChannel::Stable, "stable"),
        dcentrald_common::ReleaseChannel::Unsupported => {
            return Err("Unsupported images have no update channel.".into())
        }
    };
    let base = option_env!("DCENT_UPDATE_FEED_BASE_URL")
        .ok_or("This image has no configured release channel URL.")?;
    let base = channel_feed::artifact_url(base)?;
    let url = format!("{}/{label}.json", base.as_str().trim_end_matches('/'));
    channel_feed::artifact_url(&url)?;
    Ok(Context {
        board,
        version: image.version().into(),
        recipe: image.hardware_recipe().as_str().into(),
        channel,
        url,
    })
}

fn selection(
    raw: &[u8],
    context: &Context,
    pin: Option<&Pin>,
) -> Result<(String, ChannelFeedTarget), String> {
    let feed = channel_feed::verify(raw, context.channel)?;
    let target = feed
        .select_update(&context.board, &context.version, &context.recipe)?
        .clone();
    if let Some(pin) = pin {
        if feed.sha256() != pin.feed_sha256 || target.sha256 != pin.artifact_sha256 {
            return Err(
                "The release changed since it was selected. Check the channel again.".into(),
            );
        }
    }
    Ok((feed.sha256().into(), target))
}

async fn check(State(state): State<Arc<AppState>>) -> Reply {
    let result = tokio::time::timeout(std::time::Duration::from_secs(8), async {
        let context = context(&state).await?;
        let client = download::client()?;
        let raw = download::feed(&client, &context.url).await?;
        let (feed_sha256, candidate) = selection(&raw, &context, None)?;
        Ok::<_, String>(json!({"status": "available", "board_target": context.board,
            "current_version": context.version, "release_channel": context.channel,
            "feed_sha256": feed_sha256, "candidate": candidate, "update_started": false}))
    })
    .await;
    match result {
        Ok(Ok(value)) => (StatusCode::OK, Json(value)),
        Ok(Err(detail)) => error(detail),
        Err(_) => error("Channel check timed out. Retry when the release service is reachable."),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    feed_sha256: String,
    artifact_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Apply {
    download_id: String,
    feed_sha256: String,
    artifact_sha256: String,
    confirmation: String,
}

async fn fetch(State(state): State<Arc<AppState>>, Json(pin): Json<Pin>) -> Reply {
    let Ok(operation) = OPERATION.try_lock() else {
        return error("A channel download or apply is already in progress.");
    };
    let id = uuid::Uuid::new_v4().to_string();
    progress(&id, "checking", 0, 0);
    let worker_id = id.clone();
    tokio::spawn(async move {
        let _operation = operation;
        let result = fetch_selected(state, pin, &worker_id).await;
        complete(&worker_id, result, "staged");
    });
    (
        StatusCode::ACCEPTED,
        Json(json!({"operation_id": id, "phase": "checking", "update_started": false})),
    )
}

async fn fetch_selected(
    state: Arc<AppState>,
    pin: Pin,
    operation_id: &str,
) -> Result<Value, String> {
    let context = context(&state).await?;
    let client = download::client()?;
    let raw = download::feed(&client, &context.url).await?;
    let (feed_sha256, target) = selection(&raw, &context, Some(&pin))?;
    let size = target.size;
    let stage = tokio::task::spawn_blocking(move || {
        download::create_download(Path::new(download::ROOT), size)
    })
    .await
    .map_err(|_| "Could not prepare the channel stage.")??;
    progress(operation_id, "downloading", 0, size);
    download::download(&client, &target, &stage, |bytes| {
        progress(operation_id, "downloading", bytes, size)
    })
    .await?;
    progress(operation_id, "verifying", size, size);
    let package = stage.package();
    let (status, Json(validation)) =
        crate::rest::finish_channel_package(state, package, target.clone(), false).await;
    if !status.is_success() {
        return Err(validation["detail"]
            .as_str()
            .or(validation["error"].as_str())
            .unwrap_or("Package preflight failed.")
            .to_owned());
    }
    let id = tokio::task::spawn_blocking(move || stage.retain(&raw))
        .await
        .map_err(|_| "Could not retain the verified channel stage.")??;
    Ok(
        json!({"status": "staged", "download_id": id, "feed_sha256": feed_sha256,
            "artifact_sha256": target.sha256, "candidate": target, "update_started": false,
            "message": "Downloaded bytes and signed package passed verification. Apply is a separate explicit action."}),
    )
}

async fn apply(State(state): State<Arc<AppState>>, Json(request): Json<Apply>) -> Reply {
    if request.confirmation != "INSTALL VERIFIED UPDATE" {
        return error("Type INSTALL VERIFIED UPDATE to schedule this update.");
    }
    let Ok(operation) = OPERATION.try_lock() else {
        return error("A channel download or apply is already in progress.");
    };
    let id = uuid::Uuid::new_v4().to_string();
    progress(&id, "applying", 0, 0);
    let worker_id = id.clone();
    tokio::spawn(async move {
        let _operation = operation;
        let (status, Json(value)) = apply_selected(state, request).await;
        let result = if status.is_success() && value["update_started"] == true {
            Ok(value)
        } else {
            Err(value["detail"]
                .as_str()
                .or(value["error"].as_str())
                .unwrap_or("Update apply was not scheduled.")
                .to_owned())
        };
        complete(&worker_id, result, "scheduled");
    });
    (
        StatusCode::ACCEPTED,
        Json(json!({"operation_id": id, "phase": "applying", "update_started": null})),
    )
}

async fn apply_selected(state: Arc<AppState>, request: Apply) -> Reply {
    let context = match context(&state).await {
        Ok(value) => value,
        Err(detail) => return error(detail),
    };
    let id = request.download_id;
    let retained =
        tokio::task::spawn_blocking(move || download::retained(Path::new(download::ROOT), &id))
            .await;
    let (package, raw) = match retained {
        Ok(Ok(value)) => value,
        Ok(Err(detail)) => return error(detail),
        Err(_) => return error("Could not inspect the retained channel stage."),
    };
    let pin = Pin {
        feed_sha256: request.feed_sha256,
        artifact_sha256: request.artifact_sha256,
    };
    let target = match selection(&raw, &context, Some(&pin)) {
        Ok((_, target)) => target,
        Err(detail) => return error(detail),
    };
    // The shared upload finisher independently verifies the actual package,
    // target/version, rollback and sysupgrade preflight before the retained
    // update owner is launched. No installer process exists in the fetch path.
    crate::rest::finish_channel_package(state, package, target, true).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusQuery {
    operation_id: String,
}

async fn status(Query(query): Query<StatusQuery>) -> Reply {
    let current = STATUS.get_or_init(|| Mutex::new(None)).lock();
    if let Ok(current) = current {
        if let Some((id, value)) = &*current {
            if id == &query.operation_id {
                return (StatusCode::OK, Json(value.clone()));
            }
        }
    }
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": "channel_operation_unknown",
        "detail": "This operation is no longer observed. A daemon restart does not prove update completion."})),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Discard {
    download_id: String,
}

async fn stored() -> Reply {
    let Ok(_operation) = OPERATION.try_lock() else {
        return error("A channel operation is in progress.");
    };
    match tokio::task::spawn_blocking(|| download::stored(Path::new(download::ROOT))).await {
        Ok(Ok(ids)) => (StatusCode::OK, Json(json!({"download_ids":ids}))),
        Ok(Err(detail)) => error(detail),
        Err(_) => error("Could not inspect stored downloads."),
    }
}

async fn discard(Json(request): Json<Discard>) -> Reply {
    let Ok(_operation) = OPERATION.try_lock() else {
        return error("A channel operation is in progress; its files cannot be discarded.");
    };
    match tokio::task::spawn_blocking(move || {
        download::discard(Path::new(download::ROOT), &request.download_id)
    })
    .await
    {
        Ok(Ok(())) => (
            StatusCode::OK,
            Json(json!({"discarded":true,"update_started":false})),
        ),
        Ok(Err(detail)) => error(detail),
        Err(_) => error("Could not discard the stored download."),
    }
}

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/system/update/check", get(check))
        .route("/api/system/update/fetch", post(fetch))
        .route("/api/system/update/apply", post(apply))
        .route("/api/system/update/operation", get(status))
        .route("/api/system/update/downloads", get(stored))
        .route("/api/system/update/discard", post(discard))
        .layer(DefaultBodyLimit::max(4096))
}
