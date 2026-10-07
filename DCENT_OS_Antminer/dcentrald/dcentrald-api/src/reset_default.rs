//! Reset authorization is narrower than runtime image admission: old signed
//! images still boot, but cannot reset without a signed mining-off default.
use std::path::Path;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const DEFAULT_SETTINGS_PATH: &str = "/usr/share/dcentos/default-dcentrald.toml";

#[derive(Debug, Serialize)]
pub struct CheckedResetDefault {
    settings_default_sha256: String,
    bytes: usize,
}

pub async fn verify_installed_reset_default() -> Result<CheckedResetDefault, String> {
    let board = tokio::fs::read_to_string("/etc/dcentos/board_target").await
        .map_err(|_| "reset: exact installed board identity unavailable")?;
    let image = crate::runtime_image::verify_installed_runtime_image(board.trim(), env!("CARGO_PKG_VERSION")).await?;
    let expected = image.settings_default_sha256().ok_or("reset: this signed image has no settings default binding")?.to_owned();
    tokio::task::spawn_blocking(move || {
        let bytes = protected_default(Path::new(DEFAULT_SETTINGS_PATH))?;
        validate_default(&bytes, &expected)
    }).await.map_err(|_| "reset: default validation task failed")?
}

fn protected_default(path: &Path) -> Result<Vec<u8>, String> {
    #[cfg(unix)] {
        use std::os::unix::fs::MetadataExt;
        for ancestor in path.ancestors() {
            let metadata = std::fs::symlink_metadata(ancestor).map_err(|_| "reset: default path unavailable")?;
            if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err("reset: default path is not protected image content".into());
            }
            if ancestor == path && (!metadata.is_file() || metadata.nlink() != 1) {
                return Err("reset: default is not an exact regular image file".into());
            }
        }
    }
    crate::diagnostics::read_bounded(path, 1024 * 1024).map_err(|_| "reset: default is unreadable or oversized".into())
}

fn validate_default(bytes: &[u8], expected: &str) -> Result<CheckedResetDefault, String> {
    let digest = format!("{:x}", Sha256::digest(bytes));
    if digest != expected { return Err("reset: settings default differs from the signed image".into()); }
    let text = std::str::from_utf8(bytes).map_err(|_| "reset: invalid UTF-8 default")?;
    let value: toml::Value = toml::from_str(text).map_err(|_| "reset: malformed default TOML")?;
    if value.get("mining").and_then(|v| v.get("enabled")).and_then(toml::Value::as_bool) != Some(false) {
        return Err("reset: signed default must explicitly disable mining".into());
    }
    Ok(CheckedResetDefault { settings_default_sha256: digest, bytes: bytes.len() })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_toml_semantics_and_signed_digest_are_both_required() {
        let good = b"[mining]\nenabled = false\n";
        let digest = format!("{:x}", Sha256::digest(good));
        assert_eq!(validate_default(good, &digest).unwrap().bytes, good.len());
        assert!(validate_default(good, &"a".repeat(64)).is_err());
        for bad in ["[mining]\nenabled=true\n", "[mining]\nenabled='false'\n", "[mining]\n", "[mining]\nenabled=false\nenabled=true\n", "invalid"] {
            assert!(validate_default(bad.as_bytes(), &format!("{:x}", Sha256::digest(bad))).is_err());
        }
    }
}
