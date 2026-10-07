//! Read-only build/crash observations. These confer no hardware authority.
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

pub const LAST_PANIC_PATH: &str = "/var/log/dcentos/last-panic.json";
const MAX_RECORD: usize = 16 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PanicRecord {
    pub version: String,
    pub unix_seconds: u64,
    pub location: Option<String>,
    pub message: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageBuildStamp {
    git_sha: Option<String>,
    drop: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetStatus {
    phase: String,
    unix_seconds: u64,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Diagnostics {
    pub board_target: Option<String>,
    pub image_version: Option<String>,
    pub daemon_version: &'static str,
    pub git_sha: Option<String>,
    pub channel: Option<String>,
    pub drop: Option<String>,
    pub active_slot: Option<String>,
    pub signature_state: &'static str,
    pub signature_detail: Option<String>,
    pub last_panic: Option<PanicRecord>,
    pub reset_status: Option<ResetStatus>,
    pub warnings: Vec<String>,
}

pub(crate) fn read_bounded(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("diagnostic source is not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::other("diagnostic source exceeds its size limit"));
    }
    Ok(bytes)
}

fn text_at(root: &Path, path: &str) -> Option<String> {
    let bytes = read_bounded(&root.join(path), 256).ok()?;
    let value = std::str::from_utf8(&bytes).ok()?.trim();
    (!value.is_empty() && !value.chars().any(char::is_control)).then(|| value.to_owned())
}

fn observe_files(root: &Path) -> Diagnostics {
    let mut warnings = Vec::new();
    let stamp = read_bounded(&root.join("etc/dcentos/build-info.json"), 1024)
        .ok().and_then(|bytes| serde_json::from_slice::<ImageBuildStamp>(&bytes).ok())
        .unwrap_or_default();
    let git_sha = stamp.git_sha.filter(|s| s.len() == 40 && s.bytes().all(|c| c.is_ascii_hexdigit()));
    let drop = stamp.drop.filter(|s| matches!(s.as_str(), "1" | "2" | "3"));
    if git_sha.is_none() { warnings.push("Image Git revision is unavailable.".into()); }
    let last_panic = match read_bounded(&root.join("var/log/dcentos/last-panic.json"), MAX_RECORD) {
        Ok(bytes) => match serde_json::from_slice::<PanicRecord>(&bytes) {
            Ok(mut record) => {
                record.message = crate::routes::stock_parity::scrub(&record.message);
                record.location = record.location.map(|s| crate::routes::stock_parity::scrub(&s));
                Some(record)
            }
            Err(_) => { warnings.push("Last panic record is malformed.".into()); None }
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(_) => { warnings.push("Last panic record is unreadable or unsafe.".into()); None }
    };
    let reset_status = read_bounded(&root.join("data/dcent/reset-settings-status.json"), 4096).ok()
        .and_then(|bytes| serde_json::from_slice::<ResetStatus>(&bytes).ok())
        .filter(|status| matches!(status.phase.as_str(), "pending_shutdown" | "stopped" | "settings_reset" | "failed"))
        .map(|mut status| {
            status.error = status.error.map(|error| crate::routes::stock_parity::scrub(&error));
            status
        });
    Diagnostics {
        board_target: text_at(root, "etc/dcentos/board_target"),
        image_version: text_at(root, "etc/dcentos-version"),
        daemon_version: env!("CARGO_PKG_VERSION"),
        git_sha, drop, channel: None,
        // This is an observation from boot, never a guessed slot or fw_setenv call.
        active_slot: text_at(root, "run/dcentos/active-slot"),
        signature_state: "unverified", signature_detail: None, last_panic, reset_status, warnings,
    }
}

pub async fn snapshot() -> Diagnostics {
    let mut result = tokio::task::spawn_blocking(|| observe_files(Path::new("/")))
        .await.unwrap_or_else(|_| observe_files(Path::new("/nonexistent")));
    if let Some(board) = result.board_target.as_deref() {
        match crate::runtime_image::verify_installed_runtime_image(board, env!("CARGO_PKG_VERSION")).await {
            Ok(image) => {
                result.signature_state = "verified";
                result.channel = Some(image.channel().as_str().to_owned());
            }
            Err(error) => result.signature_detail = Some(crate::routes::stock_parity::scrub(&error)),
        }
    } else {
        result.signature_detail = Some("Exact board identity is unavailable.".into());
    }
    result
}

/// Called only AFTER every existing emergency cutoff hook. Synchronous and
/// best effort because a panic-abort process cannot await an async writer.
/// Refuses re-entry; never invokes a subprocess, a device, or a config writer.
pub fn record_panic(info: &std::panic::PanicHookInfo<'_>) {
    static RECORDING: AtomicBool = AtomicBool::new(false);
    if RECORDING.swap(true, Ordering::AcqRel) { return; }
    let message = info.payload().downcast_ref::<&str>().copied()
        .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload");
    let record = PanicRecord {
        version: env!("CARGO_PKG_VERSION").into(),
        unix_seconds: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0),
        location: info.location().map(|p| format!("{}:{}:{}", p.file(), p.line(), p.column())),
        message: crate::routes::stock_parity::scrub(&message.chars().take(2048).collect::<String>()),
    };
    let _ = persist_panic(Path::new(LAST_PANIC_PATH), &record);
    RECORDING.store(false, Ordering::Release);
}

fn persist_panic(path: &Path, record: &PanicRecord) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| io::Error::other("missing panic directory"))?;
    fs::create_dir_all(parent)?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir() { return Err(io::Error::other("unsafe panic directory")); }
    #[cfg(unix)] {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        // SAFETY: geteuid takes no pointers and only observes this process UID.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            return Err(io::Error::other("unprotected panic directory"));
        }
        // A new sibling and rename avoid following any previous record symlink.
        let temporary = parent.join(format!(".last-panic.{}.tmp", std::process::id()));
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW).open(&temporary)?;
        let result = (|| {
            let bytes = serde_json::to_vec(record)?;
            if bytes.len() > MAX_RECORD { return Err(io::Error::other("panic record too large")); }
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, path)?;
            fs::File::open(parent)?.sync_all()
        })();
        if result.is_err() { let _ = fs::remove_file(temporary); }
        result
    }
    #[cfg(not(unix))] { let _ = record; Err(io::Error::other("Unix panic persistence required")) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_record_roundtrip_is_bounded_and_redacted() {
        let root = std::env::temp_dir().join(format!("dcent-diagnostics-{}", uuid::Uuid::new_v4()));
        let path = root.join("var/log/dcentos/last-panic.json");
        let record = PanicRecord { version: "1.2.3".into(), unix_seconds: 42,
            location: Some("owner.rs:4".into()), message: "Authorization: Bearer never-export-this".into() };
        persist_panic(&path, &record).unwrap();
        let snapshot = observe_files(&root);
        assert!(!serde_json::to_string(&snapshot).unwrap().contains("never-export-this"));
        assert_eq!(snapshot.last_panic.unwrap().unix_seconds, 42);
        fs::write(&path, vec![b'x'; MAX_RECORD + 1]).unwrap();
        assert!(observe_files(&root).last_panic.is_none());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn absent_or_malformed_metadata_never_claims_verified_identity() {
        let value = observe_files(Path::new("/nonexistent-dcent-diagnostics"));
        assert_eq!(value.signature_state, "unverified");
        assert!(value.git_sha.is_none() && value.active_slot.is_none() && value.channel.is_none());
    }
    #[test]
    fn unassigned_drop_and_reset_failure_are_truthful_and_redacted() {
        let root = std::env::temp_dir().join(format!("dcent-build-diagnostics-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("etc/dcentos")).unwrap();
        fs::create_dir_all(root.join("data/dcent")).unwrap();
        fs::write(root.join("etc/dcentos/build-info.json"), r#"{"git_sha":null,"drop":"debug"}"#).unwrap();
        fs::write(root.join("data/dcent/reset-settings-status.json"),
            r#"{"phase":"failed","unix_seconds":42,"error":"password=never-export-this"}"#).unwrap();
        let value = observe_files(&root);
        assert!(value.drop.is_none());
        assert_eq!(value.reset_status.as_ref().unwrap().phase, "failed");
        assert!(!serde_json::to_string(&value).unwrap().contains("never-export-this"));
        fs::write(root.join("etc/dcentos/build-info.json"), r#"{"git_sha":null,"drop":"2"}"#).unwrap();
        assert_eq!(observe_files(&root).drop.as_deref(), Some("2"));
        fs::remove_dir_all(root).unwrap();
    }
}
