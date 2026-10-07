//! Authenticated public-key enrollment for exact AML and native SD data owners.
//! Dashboard passwords remain dashboard credentials; root stays locked.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::AppState;

const MAX_BYTES: usize = 8192;
const MAX_KEYS: usize = 16;
// The retained Dropbear server admits at most 4200 bytes per authorized-key
// line. Keep room for line endings and reject before trimming existing bytes.
const MAX_KEY_LINE: usize = 4096;
const AUTHORIZED_KEYS: &str = "authorized_keys";
const ENABLE_HELPER: &str = "/usr/sbin/dcent-enable-ssh";
static ENROLLMENT: Mutex<()> = Mutex::new(());

type Checked<T> = Result<T, String>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentRequest {
    public_keys: String,
    enable_ssh: bool,
}

#[derive(Debug, Serialize)]
struct EnrollmentStatus {
    available: bool,
    scope: &'static str,
    reason: Option<String>,
    fingerprints: Vec<String>,
    operator_disabled: bool,
    root_password_changed: bool,
}

#[derive(Debug, Serialize)]
struct EnrollmentResult {
    status: EnrollmentStatus,
    persisted: bool,
    durable: bool,
    activation: &'static str,
    activation_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MountProof {
    schema: u8,
    boot_id: String,
    volume_mount_id: String,
    data_mount_id: String,
    keys_mount_id: String,
    device: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StorageProfile {
    Classic,
    S19k,
    A126,
    Plus120,
    NativeSd(&'static str),
}

impl StorageProfile {
    fn from_target(target: &[u8]) -> Checked<Self> {
        match target {
            b"am3-s19k\n" => Ok(Self::S19k),
            b"am3-s19jpro-aml\n" => Ok(Self::Classic),
            b"am3-s19jproa\n" => Ok(Self::A126),
            b"am3-s19jproplus\n" => Ok(Self::Plus120),
            b"am1-s9i\n" => Ok(Self::NativeSd("am1-s9i")),
            b"am1-s9j\n" => Ok(Self::NativeSd("am1-s9j")),
            b"am2-s17p\n" => Ok(Self::NativeSd("am2-s17p")),
            b"am2-s17plus\n" => Ok(Self::NativeSd("am2-s17plus")),
            b"am2-t17\n" => Ok(Self::NativeSd("am2-t17")),
            b"am2-t17plus\n" => Ok(Self::NativeSd("am2-t17plus")),
            b"am2-s19pro\n" => Ok(Self::NativeSd("am2-s19pro")),
            _ => Err(refused(
                "SSH enrollment is not yet qualified for this board",
            )),
        }
    }

    fn target(self) -> &'static str {
        match self {
            Self::S19k => "am3-s19k",
            Self::Classic => "am3-s19jpro-aml",
            Self::A126 => "am3-s19jproa",
            Self::Plus120 => "am3-s19jproplus",
            Self::NativeSd(target) => target,
        }
    }

    fn helper(self) -> &'static str {
        match self {
            Self::S19k => "/usr/sbin/dcent-s19k-data-mount",
            Self::Classic => "/usr/libexec/dcentos/classic-aml-storage.py",
            Self::A126 | Self::Plus120 => "/usr/libexec/dcentos/bm1362-nopic-storage.py",
            Self::NativeSd(_) => "/usr/libexec/dcentos/native-zynq-sd-storage.py",
        }
    }

    fn receipt(self) -> &'static str {
        match self {
            Self::S19k => "",
            Self::Classic => "classic-storage-ready.json",
            Self::A126 | Self::Plus120 => "nopic-bm1362-storage-ready.json",
            Self::NativeSd(_) => "native-zynq-sd-ready",
        }
    }

    fn scope(self) -> &'static str {
        match self {
            Self::S19k => "s19k_mtd4_overlay",
            Self::Classic => "classic_aml_nvdata",
            Self::A126 | Self::Plus120 => "nopic_aml_nvdata",
            Self::NativeSd(_) => "native_zynq_sd_data",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StorageProof {
    profile: StorageProfile,
    mounts: MountProof,
}

fn parse_storage_proof(
    profile: StorageProfile,
    bytes: &[u8],
    boot_id: &str,
) -> Checked<StorageProof> {
    if matches!(profile, StorageProfile::NativeSd(_) | StorageProfile::S19k) {
        return Err(refused(
            "Storage readiness requires current namespace verification",
        ));
    }
    // Preserve Classic's original strict schema. NoPIC adds exactly one field
    // which must name this target; it cannot import a sibling's readiness.
    // Deserialize through a struct first so duplicate JSON fields also refuse.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NoPicProof {
        schema: u8,
        board_target: String,
        boot_id: String,
        volume_mount_id: String,
        data_mount_id: String,
        keys_mount_id: String,
        device: String,
    }
    let invalid = |_| refused("Invalid storage readiness");
    let mounts = if profile == StorageProfile::Classic {
        serde_json::from_slice::<MountProof>(bytes).map_err(invalid)?
    } else {
        let proof: NoPicProof = serde_json::from_slice(bytes).map_err(invalid)?;
        if proof.board_target != profile.target() {
            return Err(refused("Storage readiness belongs to another board"));
        }
        MountProof {
            schema: proof.schema,
            boot_id: proof.boot_id,
            volume_mount_id: proof.volume_mount_id,
            data_mount_id: proof.data_mount_id,
            keys_mount_id: proof.keys_mount_id,
            device: proof.device,
        }
    };
    if mounts.schema != 1 || mounts.boot_id != boot_id {
        return Err(refused("Storage readiness belongs to another boot"));
    }
    Ok(StorageProof { profile, mounts })
}

fn refused(message: impl Into<String>) -> String {
    message.into()
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({"error": message.into()}))).into_response()
}

fn require_admin(header: Option<&str>) -> Result<(), Response> {
    // Explicit bearer validation remains mandatory even on development images
    // with password opt-out or trusted local-proxy middleware exceptions.
    let id = crate::auth::current_session_id(header)?;
    let data = crate::auth::load_auth()
        .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "Owner session required"))?;
    if data
        .sessions
        .iter()
        .any(|session| session.id == id && session.role.can_write())
    {
        Ok(())
    } else {
        Err(error_response(
            StatusCode::FORBIDDEN,
            "An admin session is required to manage SSH keys",
        ))
    }
}

fn authorization(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            result.push(ALPHABET[((buffer >> bits) & 63) as usize] as char);
        }
        buffer &= (1 << bits) - 1;
    }
    if bits != 0 {
        result.push(ALPHABET[((buffer << (6 - bits)) & 63) as usize] as char);
    }
    result
}

#[derive(Clone, Debug)]
struct PublicKey {
    encoded: String,
    line: String,
    fingerprint: String,
}

fn parse_keys(input: &str) -> Checked<Vec<PublicKey>> {
    if input.len() > MAX_BYTES
        || !input.is_ascii()
        || input
            .bytes()
            .any(|byte| !(0x20..=0x7e).contains(&byte) && !matches!(byte, b'\n' | b'\r' | b'\t'))
    {
        return Err(refused(
            "Use at most 8192 ASCII bytes of Ed25519 public keys",
        ));
    }
    let mut keys = Vec::new();
    let mut seen = BTreeSet::new();
    for line in input.lines() {
        if line.len() > MAX_KEY_LINE {
            return Err(refused("Each public-key line must be at most 4096 bytes"));
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line
            .bytes()
            .any(|byte| !(0x20..=0x7e).contains(&byte) && byte != b'\t')
        {
            return Err(refused("Public-key lines contain a control character"));
        }
        let mut fields = line.split_ascii_whitespace();
        if fields.next() != Some("ssh-ed25519") {
            return Err(refused("Use ssh-ed25519 public keys without authorized_keys options; never submit a private key"));
        }
        let encoded = fields
            .next()
            .ok_or_else(|| refused("Missing Ed25519 public-key data"))?;
        // The SSH Ed25519 wire form is exactly 51 bytes and therefore 68 base64
        // characters with no padding. No permissive decoder or trailing blob.
        if encoded.len() != 68 {
            return Err(refused("Ed25519 public-key data has the wrong length"));
        }
        let mut blob = Vec::with_capacity(51);
        let (mut buffer, mut bits) = (0u32, 0u32);
        for byte in encoded.bytes() {
            let value = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => return Err(refused("Invalid Ed25519 base64 data")),
            };
            buffer = (buffer << 6) | u32::from(value);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                blob.push((buffer >> bits) as u8);
                buffer &= (1 << bits) - 1;
            }
        }
        if blob.len() != 51 || blob[..19] != *b"\0\0\0\x0bssh-ed25519\0\0\0\x20" {
            return Err(refused("Public-key wire type differs from ssh-ed25519"));
        }
        let public: [u8; 32] = blob[19..]
            .try_into()
            .map_err(|_| refused("Invalid public key"))?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&public)
            .map_err(|_| refused("Invalid Ed25519 public point"))?;
        if key.is_weak() {
            return Err(refused("Weak Ed25519 public keys are refused"));
        }
        if seen.insert(encoded.to_string()) {
            keys.push(PublicKey {
                encoded: encoded.to_string(),
                line: line.to_string(),
                fingerprint: format!("SHA256:{}", base64(&Sha256::digest(&blob))),
            });
        }
        if keys.len() > MAX_KEYS {
            return Err(refused("At most 16 distinct public keys are supported"));
        }
    }
    Ok(keys)
}

fn cstring(value: &str) -> Checked<std::ffi::CString> {
    std::ffi::CString::new(value).map_err(|_| refused("Invalid internal path"))
}

fn io_error(error: std::io::Error) -> String {
    error.to_string()
}

fn open_at(directory: &File, name: &str, flags: i32, mode: u32) -> std::io::Result<File> {
    let name = std::ffi::CString::new(name).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    // SAFETY: the descriptor and NUL-terminated name remain live across openat;
    // every successful new descriptor transfers exactly once into File.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn protected(metadata: &std::fs::Metadata, directory: bool) -> bool {
    metadata.uid() == 0
        && metadata.gid() == 0
        && metadata.mode() & 0o022 == 0
        && if directory {
            metadata.is_dir()
        } else {
            metadata.is_file() && metadata.nlink() == 1
        }
}

fn secure_dir(root: &Path, relative: &str) -> Checked<File> {
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
        .map_err(io_error)?;
    if !protected(&directory.metadata().map_err(io_error)?, true) {
        return Err(refused("Unsafe root directory"));
    }
    for component in relative.split('/').filter(|part| !part.is_empty()) {
        if component == "." || component == ".." {
            return Err(refused("Invalid internal directory"));
        }
        directory = open_at(&directory, component, libc::O_RDONLY | libc::O_DIRECTORY, 0)
            .map_err(io_error)?;
        if !protected(&directory.metadata().map_err(io_error)?, true) {
            return Err(refused("Unsafe persistent directory"));
        }
    }
    Ok(directory)
}

fn read_at(
    directory: &File,
    name: &str,
    mode: Option<u32>,
    maximum: usize,
) -> Checked<Option<Vec<u8>>> {
    let entry = cstring(name)?;
    let mut before = std::mem::MaybeUninit::<libc::stat>::uninit();
    // Inspect before open: even a nonblocking special-device open can have
    // side effects. A changed entry is rejected again through the descriptor.
    let status = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            entry.as_ptr(),
            before.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status != 0 {
        let error = std::io::Error::last_os_error();
        return if error.kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(io_error(error))
        };
    }
    let before = unsafe { before.assume_init() };
    if before.st_mode & libc::S_IFMT != libc::S_IFREG
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o022 != 0
        || before.st_size < 0
        || before.st_size as u64 > maximum as u64
        || mode.is_some_and(|expected| before.st_mode & 0o7777 != expected)
    {
        return Err(refused(
            "Persistent file type, owner, links, mode or size is unsafe",
        ));
    }
    let mut file = match open_at(directory, name, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(error)),
    };
    let metadata = file.metadata().map_err(io_error)?;
    if metadata.dev() != before.st_dev
        || metadata.ino() != before.st_ino
        || !protected(&metadata, false)
        || metadata.len() > maximum as u64
        || mode.is_some_and(|expected| metadata.mode() & 0o7777 != expected)
    {
        return Err(refused(
            "Persistent file type, owner, links, mode or size is unsafe",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > maximum {
        return Err(refused("Persistent file exceeded its size bound"));
    }
    Ok(Some(bytes))
}

fn mount_id(file: &File) -> Checked<String> {
    let information = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))
        .map_err(io_error)?;
    let mut values = information
        .lines()
        .filter_map(|line| line.strip_prefix("mnt_id:"));
    let value = values
        .next()
        .map(str::trim)
        .ok_or_else(|| refused("Kernel mount identity unavailable"))?;
    if values.next().is_some() || value.parse::<u64>().is_err() {
        return Err(refused("Invalid kernel mount identity"));
    }
    Ok(value.to_string())
}

fn fixed_command(program: &str, arguments: &[&str]) -> Checked<()> {
    let mut child = Command::new(program)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(io_error)?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(io_error)? {
            return if status.success() {
                Ok(())
            } else {
                Err(refused("Qualified startup helper refused the operation"))
            };
        }
        if start.elapsed() >= Duration::from_secs(10) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(refused("Qualified startup helper timed out"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

trait Owner: Send + Sync {
    fn root(&self) -> &Path;
    fn check(&self) -> Checked<StorageProof>;
    fn activate(&self) -> Checked<()>;
    fn before_publish(&self) -> Checked<()> {
        Ok(())
    }
    fn sync_directory(&self, directory: &File) -> Checked<()> {
        directory.sync_all().map_err(io_error)
    }
}

struct AmlogicOwner;

fn native_sd_storage_proof(
    root: &Path,
    profile: StorageProfile,
    bytes: &[u8],
    boot_id: &str,
) -> Checked<StorageProof> {
    if !matches!(profile, StorageProfile::NativeSd(_))
        || uuid::Uuid::parse_str(boot_id)
            .map(|value| value.to_string())
            .ok()
            .as_deref()
            != Some(boot_id)
        || bytes != format!("{boot_id}\n").as_bytes()
    {
        return Err(refused("Native SD readiness belongs to another boot"));
    }
    // The fixed SD helper has just reverified exact target/root/removable card,
    // partition offset/size/UUID, and its actual ext4 mount. Join our descriptors
    // to that same /data mount and the startup-owned persistent host-key bind.
    let volume = secure_dir(root, "data")?;
    let data = secure_dir(root, "data/dcent")?;
    let persistent_keys = secure_dir(root, "data/keys/dropbear")?;
    let keys = secure_dir(root, "etc/dropbear")?;
    let volume_mount = mount_id(&volume)?;
    let data_mount = mount_id(&data)?;
    if data_mount != volume_mount || mount_id(&persistent_keys)? != volume_mount {
        return Err(refused(
            "Native SD application or key directory changed mount",
        ));
    }
    let persistent_metadata = persistent_keys.metadata().map_err(io_error)?;
    let mounted_metadata = keys.metadata().map_err(io_error)?;
    if persistent_metadata.dev() != mounted_metadata.dev()
        || persistent_metadata.ino() != mounted_metadata.ino()
    {
        return Err(refused(
            "Native SD SSH host keys are not the persistent bind",
        ));
    }
    Ok(StorageProof {
        profile,
        mounts: MountProof {
            schema: 1,
            boot_id: boot_id.to_string(),
            volume_mount_id: volume_mount,
            data_mount_id: data_mount,
            keys_mount_id: mount_id(&keys)?,
            device: format!(
                "native-sd:{}:{}",
                profile.target(),
                persistent_metadata.dev()
            ),
        },
    })
}

fn s19k_storage_proof(root: &Path, boot_id: &str) -> Checked<StorageProof> {
    if uuid::Uuid::parse_str(boot_id)
        .map(|value| value.to_string())
        .ok()
        .as_deref()
        != Some(boot_id)
    {
        return Err(refused("S19k storage boot identity is invalid"));
    }
    // The fixed S19k shell owner has just checked the complete six-MTD map,
    // exact mtd4 identity, sole dynamic overlay UBI volume and rw/nosuid/nodev/
    // noexec UBIFS mount. Bind held directory descriptors to that same mount;
    // no Classic/NoPIC receipt or another target's helper can substitute.
    let volume = secure_dir(root, "data")?;
    let data = secure_dir(root, "data/dcent")?;
    let keys = secure_dir(root, "data/dcent/dropbear")?;
    let volume_mount = mount_id(&volume)?;
    let data_mount = mount_id(&data)?;
    let keys_mount = mount_id(&keys)?;
    if volume_mount != data_mount || volume_mount != keys_mount {
        return Err(refused(
            "S19k application or SSH keys changed persistent mount",
        ));
    }
    Ok(StorageProof {
        profile: StorageProfile::S19k,
        mounts: MountProof {
            schema: 1,
            boot_id: boot_id.to_owned(),
            volume_mount_id: volume_mount,
            data_mount_id: data_mount,
            keys_mount_id: keys_mount,
            device: format!(
                "s19k-mtd4-overlay:{}",
                volume.metadata().map_err(io_error)?.dev()
            ),
        },
    })
}

fn check_storage(
    root: &Path,
    check_helper: impl FnOnce(&str) -> Checked<()>,
) -> Checked<StorageProof> {
    let identity = secure_dir(root, "etc/dcentos")?;
    let target = read_at(&identity, "board_target", None, 64)?
        .ok_or_else(|| refused("Board identity missing"))?;
    let profile = StorageProfile::from_target(&target)?;
    let helpers = secure_dir(
        root,
        if profile == StorageProfile::S19k {
            "usr/sbin"
        } else {
            "usr/libexec/dcentos"
        },
    )?;
    let helper_name = profile.helper().rsplit('/').next().unwrap_or_default();
    read_at(&helpers, helper_name, Some(0o755), 128 * 1024)?
        .ok_or_else(|| refused("Qualified storage checker is missing"))?;
    // Each fixed helper rechecks its own exact storage contract. Only its
    // observational check/--verify action is called here.
    check_helper(profile.helper())?;
    if read_at(&identity, "board_target", None, 64)?.as_deref() != Some(target.as_slice()) {
        return Err(refused(
            "Board identity changed during storage verification",
        ));
    }
    let boot_id =
        std::fs::read_to_string(root.join("proc/sys/kernel/random/boot_id")).map_err(io_error)?;
    if profile == StorageProfile::S19k {
        return s19k_storage_proof(root, boot_id.trim());
    }
    let run = secure_dir(root, "run/dcentos")?;
    let bytes = read_at(&run, profile.receipt(), Some(0o600), 4096)?
        .ok_or_else(|| refused("Current storage readiness is missing"))?;
    if matches!(profile, StorageProfile::NativeSd(_)) {
        native_sd_storage_proof(root, profile, &bytes, boot_id.trim())
    } else {
        parse_storage_proof(profile, &bytes, boot_id.trim())
    }
}

impl Owner for AmlogicOwner {
    fn root(&self) -> &Path {
        Path::new("/")
    }
    fn check(&self) -> Checked<StorageProof> {
        check_storage(self.root(), |helper| {
            if helper == "/usr/sbin/dcent-s19k-data-mount" {
                return fixed_command("/bin/sh", &[helper, "verify"]);
            }
            let action = if helper == "/usr/libexec/dcentos/native-zynq-sd-storage.py" {
                "--verify"
            } else {
                "check"
            };
            fixed_command("/usr/bin/python3", &["-I", helper, action])
        })
    }
    fn activate(&self) -> Checked<()> {
        let helpers = secure_dir(self.root(), "usr/sbin")?;
        read_at(&helpers, "dcent-enable-ssh", Some(0o755), 128 * 1024)?
            .ok_or_else(|| refused("SSH activation helper is missing"))?;
        fixed_command(ENABLE_HELPER, &["keys"])
    }
}

fn status_for(profile: StorageProfile, keys: &[PublicKey], disabled: bool) -> EnrollmentStatus {
    EnrollmentStatus {
        available: true,
        scope: profile.scope(),
        reason: None,
        fingerprints: keys.iter().map(|key| key.fingerprint.clone()).collect(),
        operator_disabled: disabled,
        root_password_changed: false,
    }
}

fn namespace(owner: &dyn Owner) -> Checked<(StorageProof, File)> {
    let proof = owner.check()?;
    let data = secure_dir(owner.root(), "data/dcent")?;
    if mount_id(&data)? != proof.mounts.data_mount_id {
        return Err(refused("Persistent directory changed mount identity"));
    }
    let keys = secure_dir(
        owner.root(),
        if proof.profile == StorageProfile::S19k {
            "data/dcent/dropbear"
        } else {
            "etc/dropbear"
        },
    )?;
    if mount_id(&keys)? != proof.mounts.keys_mount_id {
        return Err(refused("SSH host-key mount identity changed"));
    }
    let ssh = secure_dir(owner.root(), "root/.ssh")?;
    let name = cstring(AUTHORIZED_KEYS)?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid output buffer and live directory/name; NOFOLLOW inspects the link itself.
    if unsafe {
        libc::fstatat(
            ssh.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(refused("Persistent root SSH link is missing"));
    }
    let metadata = unsafe { metadata.assume_init() };
    let mut bytes = [0u8; 128];
    let size = unsafe {
        libc::readlinkat(
            ssh.as_raw_fd(),
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFLNK
        || metadata.st_uid != 0
        || metadata.st_gid != 0
        || size < 0
        || &bytes[..usize::try_from(size)
            .unwrap_or(bytes.len())
            .min(bytes.len())]
            != b"/data/dcent/authorized_keys"
    {
        return Err(refused(
            "Root SSH link does not point exactly to persistent operator keys",
        ));
    }
    Ok((proof, data))
}

fn existing_keys(directory: &File) -> Checked<(Option<Vec<u8>>, Vec<PublicKey>)> {
    let bytes = read_at(directory, AUTHORIZED_KEYS, Some(0o600), MAX_BYTES)?;
    let text = std::str::from_utf8(bytes.as_deref().unwrap_or_default())
        .map_err(|_| refused("Existing keys are not UTF-8"))?;
    let keys = parse_keys(text)?;
    Ok((bytes, keys))
}

fn disabled(directory: &File) -> Checked<bool> {
    Ok(read_at(directory, ".ssh-disabled", None, 4096)?.is_some())
}

fn inspect(owner: &dyn Owner) -> Checked<EnrollmentStatus> {
    let (proof, directory) = namespace(owner)?;
    let (_, keys) = existing_keys(&directory)?;
    Ok(status_for(proof.profile, &keys, disabled(&directory)?))
}

struct Temporary<'a> {
    directory: &'a File,
    name: std::ffi::CString,
}
impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        // SAFETY: cleanup is restricted to our random child name in the held directory.
        unsafe {
            libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0);
        }
    }
}

fn enroll(owner: &dyn Owner, requested: &str, enable: bool) -> Checked<EnrollmentResult> {
    let added = parse_keys(requested)?;
    if added.is_empty() {
        return Err(refused("Provide at least one Ed25519 public key"));
    }
    let (proof, directory) = namespace(owner)?;
    let (original, mut keys) = existing_keys(&directory)?;
    let is_disabled = disabled(&directory)?;
    let mut contents = original.clone().unwrap_or_default();
    for key in added {
        if !keys.iter().any(|old| old.encoded == key.encoded) {
            if !contents.is_empty() && !contents.ends_with(b"\n") {
                contents.push(b'\n');
            }
            contents.extend_from_slice(key.line.as_bytes());
            contents.push(b'\n');
            keys.push(key);
        }
    }
    if contents.len() > MAX_BYTES || keys.len() > MAX_KEYS {
        return Err(refused(
            "Combined keys exceed 16 keys or 8192 bytes; existing keys were preserved",
        ));
    }
    let name = format!(".authorized_keys.{}.tmp", uuid::Uuid::new_v4());
    let temporary = Temporary {
        directory: &directory,
        name: cstring(&name)?,
    };
    let mut file = open_at(
        &directory,
        &name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )
    .map_err(io_error)?;
    file.write_all(&contents).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    owner.before_publish()?;
    if owner.check()? != proof
        || mount_id(&directory)? != proof.mounts.data_mount_id
        || existing_keys(&directory)?.0 != original
    {
        return Err(refused(
            "Storage or keys changed during enrollment; retry after checking the current state",
        ));
    }
    let target = cstring(AUTHORIZED_KEYS)?;
    // SAFETY: both child names are fixed/random validated C strings and refer
    // to the same retained directory; rename publishes the complete file atomically.
    if unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            temporary.name.as_ptr(),
            directory.as_raw_fd(),
            target.as_ptr(),
        )
    } != 0
    {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    let mut result = EnrollmentResult {
        status: status_for(proof.profile, &keys, is_disabled),
        persisted: true,
        durable: false,
        activation: "not_requested",
        activation_error: None,
    };
    if let Err(error) = owner.sync_directory(&directory) {
        result.activation_error = Some(format!(
            "Key file published but directory durability is unconfirmed: {error}"
        ));
        return Ok(result);
    }
    match read_at(&directory, AUTHORIZED_KEYS, Some(0o600), MAX_BYTES) {
        Ok(Some(observed)) if observed == contents => {}
        Ok(_) => {
            result.activation_error =
                Some("Published key readback differs; inspect storage before retrying".to_string());
            return Ok(result);
        }
        Err(error) => {
            result.activation_error =
                Some(format!("Key was published but readback failed: {error}"));
            return Ok(result);
        }
    }
    result.durable = true;
    if enable {
        result.status.operator_disabled = match disabled(&directory) {
            Ok(value) => value,
            Err(error) => {
                result.activation = "failed";
                result.activation_error = Some(error);
                return Ok(result);
            }
        };
        if result.status.operator_disabled {
            result.activation = "disabled_by_operator";
        } else {
            let activate = (|| {
                if owner.check()? != proof {
                    return Err(refused("Storage changed before SSH activation"));
                }
                // The legacy helper writes this fixed temporary name. Refuse
                // inherited indirection instead of allowing its shell redirection.
                if read_at(&directory, ".ssh-enabled.tmp", None, 4096)?.is_some() {
                    return Err(refused(
                        "An earlier SSH activation temporary file requires review",
                    ));
                }
                read_at(&directory, ".ssh-enabled", None, 4096)?;
                owner.activate()
            })();
            match activate {
                Ok(()) => result.activation = "requested",
                Err(error) => {
                    result.activation = "failed";
                    result.activation_error = Some(error);
                }
            }
        }
    }
    Ok(result)
}

async fn get_keys(headers: HeaderMap) -> Response {
    if let Err(response) = require_admin(authorization(&headers)) {
        return response;
    }
    let result = tokio::task::spawn_blocking(|| {
        let _guard = ENROLLMENT
            .lock()
            .map_err(|_| refused("Enrollment owner is unavailable"))?;
        inspect(&AmlogicOwner)
    })
    .await;
    match result {
        Ok(Ok(status)) => Json(status).into_response(),
        Ok(Err(reason)) => Json(EnrollmentStatus {
            available: false,
            scope: "unavailable",
            reason: Some(reason),
            fingerprints: Vec::new(),
            operator_disabled: false,
            root_password_changed: false,
        })
        .into_response(),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SSH enrollment worker is unavailable",
        ),
    }
}

async fn post_keys(headers: HeaderMap, Json(body): Json<EnrollmentRequest>) -> Response {
    if let Err(response) = require_admin(authorization(&headers)) {
        return response;
    }
    if let Err(error) = parse_keys(&body.public_keys) {
        return error_response(StatusCode::BAD_REQUEST, error);
    }
    let bearer = authorization(&headers).unwrap_or_default().to_string();
    // Once scheduled, the blocking worker owns the entire durable transaction
    // and activation attempt. Dropping the HTTP waiter cannot cancel publication.
    let task = schedule_enrollment(
        Arc::new(AmlogicOwner),
        body.public_keys,
        body.enable_ssh,
        move || {
            require_admin(Some(&bearer))
                .map_err(|_| refused("Admin session expired before enrollment"))
        },
    )
    .await;
    match task {
        Ok(Ok(result)) => Json(result).into_response(),
        Ok(Err(error)) => error_response(StatusCode::CONFLICT, error),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Enrollment worker failed; inspect key status before retrying",
        ),
    }
}

fn schedule_enrollment(
    owner: Arc<dyn Owner>,
    public_keys: String,
    enable: bool,
    authorize: impl FnOnce() -> Checked<()> + Send + 'static,
) -> tokio::task::JoinHandle<Checked<EnrollmentResult>> {
    tokio::task::spawn_blocking(move || {
        let _guard = ENROLLMENT
            .lock()
            .map_err(|_| refused("Enrollment owner is unavailable"))?;
        authorize()?;
        enroll(owner.as_ref(), &public_keys, enable)
    })
}

fn routes() -> Router {
    Router::new()
        .route("/api/system/ssh/keys", get(get_keys).post(post_keys))
        .layer(DefaultBodyLimit::max(MAX_BYTES * 6 + 1024))
}

pub fn router() -> Router<Arc<AppState>> {
    routes().with_state(())
}

#[cfg(test)]
#[path = "ssh_keys_tests.rs"]
mod tests;
