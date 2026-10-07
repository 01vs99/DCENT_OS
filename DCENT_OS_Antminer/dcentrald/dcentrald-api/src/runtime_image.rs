//! Signed identity of the installed daemon, checked before hardware dispatch.
//!
//! The detached signature covers the exact manifest bytes. Its trust anchor is
//! compiled into this binary; neither an installed public-key file nor a runtime
//! environment variable can authorize a release image. Only the running daemon
//! is hashed, so installing the manifest never creates a rootfs hash cycle.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::Path;

use dcentrald_common::runtime_hardware_recipe::HardwareRecipeProfile;
use dcentrald_common::{BoardDesc, ReleaseChannel};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const RUNTIME_IMAGE_MANIFEST_PATH: &str = "/etc/dcentos/runtime-image.json";
pub const RUNTIME_IMAGE_SIGNATURE_PATH: &str = "/etc/dcentos/runtime-image.sig";
pub const RUNTIME_IMAGE_MANIFEST_PROFILE: &str = "dcentos-runtime-image/v1";
pub const MAX_RUNTIME_MANIFEST_BYTES: u64 = 4096;
pub const MAX_RUNTIME_DAEMON_BYTES: u64 = 256 * 1024 * 1024;
const SIGNATURE_BYTES: u64 = 64;

/// Authority minted only after signature, registry, build and executable checks.
/// Fields are private, with no public constructor or deserialization support.
///
/// ```compile_fail
/// use dcentrald_api::runtime_image::VerifiedRuntimeImage;
/// let image: VerifiedRuntimeImage = serde_json::from_str("{}").unwrap();
/// ```
///
/// ```compile_fail
/// use dcentrald_api::runtime_image::VerifiedRuntimeImage;
/// let image = VerifiedRuntimeImage {
///     board_target: "am1-s9".into(),
///     channel: dcentrald_common::ReleaseChannel::Beta,
///     version: "unsigned".into(),
///     daemon_sha256: "00".repeat(32),
///     daemon_size: 1,
/// };
/// ```
#[derive(Debug)]
pub struct VerifiedRuntimeImage {
    board_target: String,
    channel: ReleaseChannel,
    hardware_recipe: HardwareRecipeProfile,
    version: String,
    daemon_sha256: String,
    daemon_size: u64,
    settings_default_sha256: Option<String>,
}

impl VerifiedRuntimeImage {
    pub fn board_target(&self) -> &str {
        &self.board_target
    }

    pub fn channel(&self) -> ReleaseChannel {
        self.channel
    }

    pub fn hardware_recipe(&self) -> HardwareRecipeProfile {
        self.hardware_recipe
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn daemon_sha256(&self) -> &str {
        &self.daemon_sha256
    }

    pub fn settings_default_sha256(&self) -> Option<&str> {
        self.settings_default_sha256.as_deref()
    }

    pub fn daemon_size(&self) -> u64 {
        self.daemon_size
    }
}

// Deriving Deserialize for this private wire shape rejects duplicate fields,
// including escaped spellings of the same field. The authority above does not
// implement Deserialize. Unknown fields, missing fields and wrong types fail.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeManifest {
    manifest_profile: String,
    board_target: String,
    channel: String,
    #[serde(default = "default_hardware_recipe")]
    hardware_recipe: String,
    version: String,
    daemon_sha256: String,
    daemon_size: u64,
    #[serde(default, deserialize_with = "present_settings_digest")]
    settings_default_sha256: Option<String>,
}

fn present_settings_digest<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

fn default_hardware_recipe() -> String {
    HardwareRecipeProfile::BoardDefault.as_str().to_owned()
}

/// Verify the fixed installed metadata against the actual running executable.
/// Call with the exact registered target and this daemon's compiled build version.
/// Missing metadata/key and lab builds fail closed; there is no Lab fallback.
pub async fn verify_installed_runtime_image(
    expected_board_target: &str,
    expected_version: &str,
) -> Result<VerifiedRuntimeImage, String> {
    validate_expectations(expected_board_target, expected_version)?;
    let expected_board_target = expected_board_target.to_owned();
    let expected_version = expected_version.to_owned();
    tokio::task::spawn_blocking(move || {
        verify_paths_with_trust(
            Path::new(RUNTIME_IMAGE_MANIFEST_PATH),
            Path::new(RUNTIME_IMAGE_SIGNATURE_PATH),
            Path::new("/proc/self/exe"),
            &expected_board_target,
            &expected_version,
            crate::ota_signature::compiled_public_key_hex(),
            dcentrald_common::lab_env::compiled(),
        )
    })
    .await
    .map_err(|error| format!("runtime image verification worker failed: {error}"))?
}

fn validate_expectations(board_target: &str, version: &str) -> Result<(), String> {
    if BoardDesc::lookup(board_target).is_none() {
        return Err(
            "runtime image: expected board target is not an exact registered target".into(),
        );
    }
    if version.is_empty()
        || version.len() > 128
        || !version.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err("runtime image: invalid expected build version".into());
    }
    Ok(())
}

fn verify_paths_with_trust(
    manifest_path: &Path,
    signature_path: &Path,
    executable_path: &Path,
    expected_board_target: &str,
    expected_version: &str,
    compiled_key_hex: Option<&str>,
    lab_compiled: bool,
) -> Result<VerifiedRuntimeImage, String> {
    validate_expectations(expected_board_target, expected_version)?;
    if lab_compiled {
        return Err(
            "runtime image: signed beta/stable images refuse compiled lab overrides".into(),
        );
    }
    let key_hex =
        compiled_key_hex.ok_or("runtime image: no OTA public key compiled into this daemon")?;
    if key_hex.len() != 64 {
        return Err("runtime image: compiled OTA public key must be 32 bytes of hex".into());
    }
    let key_bytes = decode_sha256_hex(&key_hex.to_ascii_lowercase())
        .map_err(|_| "runtime image: compiled OTA public key must be 32 bytes of hex")?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|error| format!("runtime image: invalid compiled OTA public key: {error}"))?;
    let manifest_bytes = read_bounded_metadata(manifest_path, MAX_RUNTIME_MANIFEST_BYTES)?;
    let signature_bytes = read_bounded_metadata(signature_path, SIGNATURE_BYTES)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| "runtime image: detached signature must be exactly 64 raw bytes")?;
    key.verify_strict(&manifest_bytes, &signature)
        .map_err(|_| {
            "runtime image: manifest signature does not verify under the compiled OTA key"
        })?;

    let manifest: RuntimeManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("runtime image: invalid manifest JSON: {error}"))?;
    if manifest.manifest_profile != RUNTIME_IMAGE_MANIFEST_PROFILE {
        return Err("runtime image: unknown manifest profile".into());
    }
    if manifest.board_target != expected_board_target {
        return Err("runtime image: signed board target does not match the expected target".into());
    }
    let board = BoardDesc::lookup(&manifest.board_target)
        .ok_or("runtime image: signed board target is not registered")?;
    let channel = manifest
        .channel
        .parse::<ReleaseChannel>()
        .map_err(|_| "runtime image: unknown release channel")?;
    validate_channel(channel, board.release_channel)?;
    let hardware_recipe = manifest
        .hardware_recipe
        .parse::<HardwareRecipeProfile>()
        .map_err(|_| "runtime image: unknown signed hardware recipe")?;
    if hardware_recipe == HardwareRecipeProfile::Xil25Loki && manifest.board_target != "am2-s19j" {
        return Err("runtime image: Xil25 Loki recipe requires exact am2-s19j board".into());
    }
    if manifest.version != expected_version {
        return Err(
            "runtime image: signed version does not match the compiled build version".into(),
        );
    }
    let expected_hash = decode_sha256_hex(&manifest.daemon_sha256)
        .map_err(|_| "runtime image: daemon_sha256 must be 32 bytes of lowercase hex")?;
    if manifest.daemon_size == 0 || manifest.daemon_size > MAX_RUNTIME_DAEMON_BYTES {
        return Err("runtime image: daemon_size exceeds the nonzero executable size bound".into());
    }
    if let Some(digest) = &manifest.settings_default_sha256 {
        decode_sha256_hex(digest).map_err(|_| "runtime image: invalid settings default digest")?;
    }
    verify_executable(executable_path, manifest.daemon_size, &expected_hash)?;

    Ok(VerifiedRuntimeImage {
        board_target: manifest.board_target,
        channel,
        hardware_recipe,
        version: manifest.version,
        daemon_sha256: manifest.daemon_sha256,
        daemon_size: manifest.daemon_size,
        settings_default_sha256: manifest.settings_default_sha256,
    })
}

fn validate_channel(image: ReleaseChannel, registry: ReleaseChannel) -> Result<(), String> {
    if !image.is_publishable() || !registry.is_publishable() {
        return Err(
            "runtime image: unsupported image or board channel cannot authorize dispatch".into(),
        );
    }
    if image != registry {
        return Err(
            "runtime image: signed release channel does not match the registered board channel"
                .into(),
        );
    }
    Ok(())
}

fn decode_sha256_hex(value: &str) -> Result<[u8; 32], ()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(());
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |byte: u8| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        bytes[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Ok(bytes)
}

fn open_regular(path: &Path, follow_symlink: bool) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Nonblocking open prevents a substituted FIFO from stalling startup.
        // Only /proc/self/exe is permitted to follow its kernel-owned symlink.
        let flags =
            libc::O_NONBLOCK | libc::O_CLOEXEC | if follow_symlink { 0 } else { libc::O_NOFOLLOW };
        options.custom_flags(flags);
    }
    let file = options
        .open(path)
        .map_err(|error| format!("runtime image: cannot open {}: {error}", path.display()))?;
    if !file
        .metadata()
        .map_err(|error| error.to_string())?
        .is_file()
    {
        return Err(format!(
            "runtime image: {} is not a regular file",
            path.display()
        ));
    }
    Ok(file)
}

fn read_bounded_metadata(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let file = open_regular(path, false)?;
    let size = file.metadata().map_err(|error| error.to_string())?.len();
    if size == 0 || size > limit {
        return Err(format!(
            "runtime image: {} exceeds its nonzero metadata size bound",
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("runtime image: cannot read {}: {error}", path.display()))?;
    if bytes.len() as u64 != size || bytes.len() as u64 > limit {
        return Err("runtime image: metadata changed size while reading".into());
    }
    Ok(bytes)
}

fn verify_executable(
    path: &Path,
    expected_size: u64,
    expected_hash: &[u8; 32],
) -> Result<(), String> {
    let file = open_regular(path, true)?;
    if file.metadata().map_err(|error| error.to_string())?.len() != expected_size {
        return Err("runtime image: executable size does not match the signed daemon_size".into());
    }
    let mut reader = file.take(expected_size + 1);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut observed_size = 0u64;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| format!("runtime image: cannot hash running executable: {error}"))?;
        if count == 0 {
            break;
        }
        observed_size += count as u64;
        hasher.update(&buffer[..count]);
    }
    if observed_size != expected_size {
        return Err("runtime image: executable changed size while hashing".into());
    }
    let observed_hash: [u8; 32] = hasher.finalize().into();
    if observed_hash != *expected_hash {
        return Err(
            "runtime image: executable SHA-256 does not match the signed daemon_sha256".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{json, Value};
    use std::path::PathBuf;

    const TARGET: &str = "am1-s9";
    const VERSION: &str = "0.9.0-test";
    const DAEMON: &[u8] = b"throwaway runtime executable fixture";

    struct Fixture {
        dir: PathBuf,
        key: SigningKey,
    }

    impl Fixture {
        fn new() -> Self {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).unwrap();
            let key = SigningKey::from_bytes(&seed);
            let dir = std::env::temp_dir().join(format!(
                "dcent-runtime-image-{}",
                hex::encode(key.verifying_key().as_bytes())
            ));
            std::fs::create_dir(&dir).unwrap();
            std::fs::write(dir.join("daemon"), DAEMON).unwrap();
            let fixture = Self { dir, key };
            fixture.sign_value(fixture.manifest());
            fixture
        }

        fn manifest(&self) -> Value {
            json!({
                "manifest_profile": RUNTIME_IMAGE_MANIFEST_PROFILE,
                "board_target": TARGET,
                "channel": "beta",
                "version": VERSION,
                "daemon_sha256": hex::encode(Sha256::digest(DAEMON)),
                "daemon_size": DAEMON.len(),
            })
        }

        fn sign_bytes(&self, bytes: &[u8]) {
            std::fs::write(self.dir.join("manifest"), bytes).unwrap();
            std::fs::write(self.dir.join("signature"), self.key.sign(bytes).to_bytes()).unwrap();
        }

        fn sign_value(&self, manifest: Value) {
            self.sign_bytes(&serde_json::to_vec(&manifest).unwrap());
        }

        fn verify(&self) -> Result<VerifiedRuntimeImage, String> {
            self.verify_with(
                TARGET,
                VERSION,
                Some(&hex::encode(self.key.verifying_key().as_bytes())),
                false,
            )
        }

        fn verify_with(
            &self,
            target: &str,
            version: &str,
            key: Option<&str>,
            lab: bool,
        ) -> Result<VerifiedRuntimeImage, String> {
            verify_paths_with_trust(
                &self.dir.join("manifest"),
                &self.dir.join("signature"),
                &self.dir.join("daemon"),
                target,
                version,
                key,
                lab,
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).unwrap();
        }
    }

    #[test]
    fn runtime_image_valid_signature_joins_registry_build_and_executable() {
        let fixture = Fixture::new();
        let verified = fixture.verify().unwrap();
        assert_eq!(verified.board_target(), TARGET);
        assert_eq!(verified.channel(), ReleaseChannel::Beta);
        assert_eq!(
            verified.hardware_recipe(),
            HardwareRecipeProfile::BoardDefault
        );
        assert_eq!(verified.version(), VERSION);
        assert_eq!(verified.daemon_size(), DAEMON.len() as u64);
        assert_eq!(
            verified.daemon_sha256(),
            hex::encode(Sha256::digest(DAEMON))
        );
        let uppercase_key =
            hex::encode(fixture.key.verifying_key().as_bytes()).to_ascii_uppercase();
        assert!(fixture
            .verify_with(TARGET, VERSION, Some(&uppercase_key), false)
            .is_ok());
    }

    #[test]
    fn runtime_image_reset_binding_is_optional_signed_and_strict() {
        let fixture = Fixture::new();
        assert!(fixture.verify().unwrap().settings_default_sha256().is_none());
        let mut value = fixture.manifest();
        value["settings_default_sha256"] = json!("a".repeat(64));
        fixture.sign_value(value.clone());
        assert_eq!(fixture.verify().unwrap().settings_default_sha256(), Some("a".repeat(64).as_str()));
        value["settings_default_sha256"] = json!("b".repeat(64));
        std::fs::write(fixture.dir.join("manifest"), serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(fixture.verify().is_err());
        for bad in [Value::Null, json!(42), json!("A".repeat(64)), json!("bad")] {
            value["settings_default_sha256"] = bad;
            fixture.sign_value(value.clone());
            assert!(fixture.verify().is_err());
        }
    }

    #[test]
    fn runtime_image_signed_hardware_recipe_is_exact_and_board_bound() {
        let fixture = Fixture::new();
        let mut manifest = fixture.manifest();
        manifest["hardware_recipe"] = json!("board-default");
        fixture.sign_value(manifest.clone());
        assert_eq!(
            fixture.verify().unwrap().hardware_recipe(),
            HardwareRecipeProfile::BoardDefault
        );
        manifest["hardware_recipe"] = json!("am2-s19j-xil-loki");
        fixture.sign_value(manifest.clone());
        assert!(fixture.verify().unwrap_err().contains("requires exact"));
        manifest["board_target"] = json!("am2-s19j");
        fixture.sign_value(manifest.clone());
        let key = hex::encode(fixture.key.verifying_key().as_bytes());
        let verified = fixture
            .verify_with("am2-s19j", VERSION, Some(&key), false)
            .unwrap();
        assert_eq!(verified.hardware_recipe(), HardwareRecipeProfile::Xil25Loki);
        for value in [json!("am2-xil-loki"), json!("unknown"), json!(null)] {
            manifest["hardware_recipe"] = value;
            fixture.sign_value(manifest.clone());
            assert!(fixture
                .verify_with("am2-s19j", VERSION, Some(&key), false)
                .is_err());
        }
        manifest["hardware_recipe"] = json!("board-default");
        let raw = serde_json::to_string(&manifest).unwrap();
        let duplicate = format!(
            "{},\"hardware_recipe\":\"board-default\"}}",
            &raw[..raw.len() - 1]
        );
        fixture.sign_bytes(duplicate.as_bytes());
        assert!(fixture
            .verify_with("am2-s19j", VERSION, Some(&key), false)
            .unwrap_err()
            .contains("duplicate field"));
    }

    #[test]
    fn runtime_image_unsigned_missing_metadata_and_missing_key_fail_closed() {
        let fixture = Fixture::new();
        assert!(fixture
            .verify_with(TARGET, VERSION, None, false)
            .unwrap_err()
            .contains("no OTA public key"));
        for key in ["", "00", &"g".repeat(64)] {
            assert!(fixture
                .verify_with(TARGET, VERSION, Some(key), false)
                .unwrap_err()
                .contains("compiled OTA public key"));
        }
        std::fs::remove_file(fixture.dir.join("signature")).unwrap();
        assert!(fixture.verify().unwrap_err().contains("cannot open"));
        fixture.sign_value(fixture.manifest());
        std::fs::remove_file(fixture.dir.join("manifest")).unwrap();
        assert!(fixture.verify().unwrap_err().contains("cannot open"));
    }

    #[test]
    fn runtime_image_tamper_and_untrusted_signer_fail() {
        let fixture = Fixture::new();
        let other = Fixture::new();
        let wrong_key = hex::encode(other.key.verifying_key().as_bytes());
        assert!(fixture
            .verify_with(TARGET, VERSION, Some(&wrong_key), false)
            .unwrap_err()
            .contains("signature does not verify"));
        let mut manifest = fixture.manifest();
        manifest["version"] = json!("tampered");
        std::fs::write(
            fixture.dir.join("manifest"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(fixture
            .verify()
            .unwrap_err()
            .contains("signature does not verify"));
        fixture.sign_value(fixture.manifest());
        let mut signature = std::fs::read(fixture.dir.join("signature")).unwrap();
        signature[0] ^= 1;
        std::fs::write(fixture.dir.join("signature"), signature).unwrap();
        assert!(fixture
            .verify()
            .unwrap_err()
            .contains("signature does not verify"));
    }

    #[test]
    fn runtime_image_signed_duplicate_keys_and_malformed_json_fail() {
        let fixture = Fixture::new();
        let original = String::from_utf8(serde_json::to_vec(&fixture.manifest()).unwrap()).unwrap();
        for duplicate in [
            r#""channel":"beta""#,
            r#""ch\u0061nnel":"beta""#,
            r#""daemon_size":36"#,
        ] {
            fixture.sign_bytes(format!("{{{duplicate},{}", &original[1..]).as_bytes());
            assert!(fixture.verify().unwrap_err().contains("duplicate field"));
        }
        for malformed in [b"{".as_slice(), b"[]", b"null", b"{} {}", b"\xff"] {
            fixture.sign_bytes(malformed);
            assert!(fixture
                .verify()
                .unwrap_err()
                .contains("invalid manifest JSON"));
        }
        for (field, value) in [
            ("extra", json!(true)),
            ("daemon_size", json!(1.5)),
            ("daemon_size", json!(-1)),
            ("daemon_size", json!("36")),
            ("version", json!({"nested": 1})),
        ] {
            let mut manifest = fixture.manifest();
            manifest[field] = value;
            fixture.sign_value(manifest);
            assert!(fixture
                .verify()
                .unwrap_err()
                .contains("invalid manifest JSON"));
        }
        for field in [
            "manifest_profile",
            "board_target",
            "channel",
            "version",
            "daemon_sha256",
            "daemon_size",
        ] {
            let mut manifest = fixture.manifest();
            manifest.as_object_mut().unwrap().remove(field);
            fixture.sign_value(manifest);
            assert!(fixture.verify().unwrap_err().contains("missing field"));
        }
    }

    #[test]
    fn runtime_image_signed_identity_channel_and_version_mismatches_fail() {
        let fixture = Fixture::new();
        for (field, value, expected_error) in [
            ("manifest_profile", "other/v1", "manifest profile"),
            ("board_target", "am3-s21", "signed board target"),
            ("board_target", "unknown", "signed board target"),
            ("board_target", "AM1-S9", "signed board target"),
            ("version", "0.9.0-other", "compiled build version"),
            ("channel", "unsupported", "unsupported image or board"),
            ("channel", "stable", "registered board channel"),
            ("channel", "lab", "unknown release channel"),
            ("channel", "Beta", "unknown release channel"),
        ] {
            let mut manifest = fixture.manifest();
            manifest[field] = json!(value);
            fixture.sign_value(manifest);
            assert!(fixture.verify().unwrap_err().contains(expected_error));
        }
        assert!(fixture
            .verify_with("unknown", VERSION, None, false)
            .unwrap_err()
            .contains("exact registered target"));
        assert!(fixture
            .verify_with(TARGET, "", None, false)
            .unwrap_err()
            .contains("expected build version"));
    }

    #[test]
    fn runtime_image_all_registry_channel_pairs_are_checked() {
        for image in [
            ReleaseChannel::Beta,
            ReleaseChannel::Stable,
            ReleaseChannel::Unsupported,
        ] {
            for registry in [
                ReleaseChannel::Beta,
                ReleaseChannel::Stable,
                ReleaseChannel::Unsupported,
            ] {
                assert_eq!(
                    validate_channel(image, registry).is_ok(),
                    image == registry && image != ReleaseChannel::Unsupported
                );
            }
        }
        let fixture = Fixture::new();
        let unsupported = BoardDesc::all_registered()
            .iter()
            .find(|board| board.release_channel == ReleaseChannel::Unsupported)
            .unwrap();
        let mut manifest = fixture.manifest();
        manifest["board_target"] = json!(unsupported.board_target);
        fixture.sign_value(manifest);
        let key = hex::encode(fixture.key.verifying_key().as_bytes());
        assert!(fixture
            .verify_with(unsupported.board_target, VERSION, Some(&key), false)
            .unwrap_err()
            .contains("unsupported image or board"));
    }

    #[test]
    fn runtime_image_executable_hash_and_size_are_measured() {
        let fixture = Fixture::new();
        let mut changed = DAEMON.to_vec();
        changed[0] ^= 1;
        std::fs::write(fixture.dir.join("daemon"), &changed).unwrap();
        assert!(fixture.verify().unwrap_err().contains("executable SHA-256"));
        changed.push(0);
        std::fs::write(fixture.dir.join("daemon"), &changed).unwrap();
        assert!(fixture.verify().unwrap_err().contains("executable size"));
        for size in [0, MAX_RUNTIME_DAEMON_BYTES + 1] {
            let mut manifest = fixture.manifest();
            manifest["daemon_size"] = json!(size);
            fixture.sign_value(manifest);
            assert!(fixture.verify().unwrap_err().contains("size bound"));
        }
        for hash in ["00".to_owned(), "g".repeat(64), "A".repeat(64)] {
            let mut manifest = fixture.manifest();
            manifest["daemon_sha256"] = json!(hash);
            fixture.sign_value(manifest);
            assert!(fixture.verify().unwrap_err().contains("daemon_sha256 must"));
        }
    }

    #[test]
    fn runtime_image_metadata_and_signature_reads_are_bounded() {
        let fixture = Fixture::new();
        std::fs::write(
            fixture.dir.join("manifest"),
            vec![b' '; MAX_RUNTIME_MANIFEST_BYTES as usize + 1],
        )
        .unwrap();
        assert!(fixture
            .verify()
            .unwrap_err()
            .contains("metadata size bound"));
        for size in [0, 63, 65, 128] {
            fixture.sign_value(fixture.manifest());
            std::fs::write(fixture.dir.join("signature"), vec![0; size]).unwrap();
            assert!(fixture.verify().is_err());
        }
        fixture.sign_value(fixture.manifest());
        std::fs::remove_file(fixture.dir.join("manifest")).unwrap();
        std::fs::create_dir(fixture.dir.join("manifest")).unwrap();
        assert!(fixture.verify().unwrap_err().contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn runtime_image_metadata_symlinks_are_refused() {
        let fixture = Fixture::new();
        std::fs::rename(
            fixture.dir.join("manifest"),
            fixture.dir.join("real-manifest"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            fixture.dir.join("real-manifest"),
            fixture.dir.join("manifest"),
        )
        .unwrap();
        assert!(fixture.verify().unwrap_err().contains("cannot open"));
    }

    #[test]
    fn runtime_image_lab_feature_union_cannot_authorize_signed_channels() {
        let fixture = Fixture::new();
        let key = hex::encode(fixture.key.verifying_key().as_bytes());
        assert!(fixture
            .verify_with(TARGET, VERSION, Some(&key), true)
            .unwrap_err()
            .contains("compiled lab overrides"));
    }

    #[tokio::test]
    async fn runtime_image_production_trust_has_no_missing_key_or_lab_fallback() {
        if dcentrald_common::lab_env::compiled() {
            assert!(verify_installed_runtime_image(TARGET, VERSION)
                .await
                .unwrap_err()
                .contains("compiled lab overrides"));
        } else if crate::ota_signature::compiled_public_key_hex().is_none() {
            assert!(verify_installed_runtime_image(TARGET, VERSION)
                .await
                .unwrap_err()
                .contains("no OTA public key"));
        }
    }
}
