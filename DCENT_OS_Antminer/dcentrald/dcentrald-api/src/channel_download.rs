//! Bounded HTTPS transport and protected staging for channel downloads.
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use dcent_schema::update::{ChannelFeedTarget, MAX_CHANNEL_FEED_BYTES};

pub(crate) const ROOT: &str = "/data/dcentos-channel-updates";
const MAX_RETAINED_STAGES: usize = 2;

pub(crate) fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|error| format!("Channel HTTPS client: {error}"))
}

async fn response(client: &reqwest::Client, url: &str) -> Result<reqwest::Response, String> {
    let url = crate::channel_feed::artifact_url(url)?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| format!("Release request failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "Release server returned {} (redirects are refused).",
            response.status()
        ));
    }
    Ok(response)
}

pub(crate) async fn feed(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    let mut response = response(client, url).await?;
    if response
        .content_length()
        .is_some_and(|size| size > MAX_CHANNEL_FEED_BYTES as u64)
    {
        return Err("Channel feed exceeds the input limit.".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("Channel stream failed: {error}"))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_CHANNEL_FEED_BYTES {
            return Err("Channel feed exceeds the streamed input limit.".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn protected(path: &Path, directory: bool) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let info = std::fs::symlink_metadata(path)
        .map_err(|error| format!("Inspect update staging: {error}"))?;
    // SAFETY: geteuid has no pointer arguments and only reads this process UID.
    if info.uid() != unsafe { libc::geteuid() }
        || info.mode() & 0o022 != 0
        || (directory && !info.is_dir())
        || (!directory && (!info.is_file() || info.nlink() != 1))
    {
        return Err("Update staging is not a protected direct path.".into());
    }
    Ok(())
}

fn ancestors(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no pointer arguments and only observes this UID.
    let uid = unsafe { libc::geteuid() };
    for parent in path.ancestors() {
        let info = std::fs::symlink_metadata(parent).map_err(|error| error.to_string())?;
        // A root-owned sticky ancestor (e.g. /tmp in host fixtures) cannot
        // rename another owner's private child. Writable non-sticky ancestry,
        // foreign ownership and every symlink remain refused.
        let sticky_root = info.uid() == 0 && info.mode() & 0o1000 != 0;
        if !info.is_dir()
            || info.uid() != 0 && info.uid() != uid
            || info.mode() & 0o022 != 0 && !sticky_root
        {
            return Err("Update stage has unsafe directory ancestry.".into());
        }
    }
    Ok(())
}

pub(crate) struct Stage {
    directory: PathBuf,
    keep: bool,
}

/// Called under the channel operation lock. An interrupted stage still counts;
/// only an explicit discard removes it, never age or a new release selection.
pub(crate) fn stored(root: &Path) -> Result<Vec<String>, String> {
    if !root.try_exists().map_err(|error| error.to_string())? {
        return Ok(Vec::new());
    }
    ancestors(root)?;
    protected(root, true)?;
    let mut ids = Vec::new();
    for entry in std::fs::read_dir(root)
        .map_err(|error| error.to_string())?
        .take(MAX_RETAINED_STAGES + 1)
    {
        let entry = entry.map_err(|error| error.to_string())?;
        let id = entry
            .file_name()
            .into_string()
            .map_err(|_| "Invalid stage name")?;
        exact_id(&id)?;
        protected(&entry.path(), true)?;
        ids.push(id);
    }
    if ids.len() > MAX_RETAINED_STAGES {
        return Err(
            "Update staging exceeds its directory limit; local inspection is required.".into(),
        );
    }
    ids.sort();
    Ok(ids)
}

pub(crate) fn create_download(root: &Path, size: u64) -> Result<Stage, String> {
    if stored(root)?.len() >= MAX_RETAINED_STAGES {
        return Err("Two stored downloads already exist. Discard a stored download before fetching another.".into());
    }
    Stage::create(root, size)
}

fn exact_id(id: &str) -> Result<(), String> {
    if uuid::Uuid::parse_str(id)
        .map(|value| value.to_string() != id)
        .unwrap_or(true)
    {
        return Err("Exact channel download identifier required.".into());
    }
    Ok(())
}

pub(crate) fn discard(root: &Path, id: &str) -> Result<(), String> {
    exact_id(id)?;
    if !stored(root)?.iter().any(|stored| stored == id) {
        return Err("Stored download is absent.".into());
    }
    let directory = root.join(id);
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(&directory)
        .map_err(|error| error.to_string())?
        .take(3)
    {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry.file_name() != "package.tar" && entry.file_name() != "feed.json" {
            return Err("Unexpected stage contents require local inspection.".into());
        }
        protected(&entry.path(), false)?;
        entries.push(entry.path());
    }
    for path in entries {
        std::fs::remove_file(path).map_err(|error| error.to_string())?;
    }
    std::fs::remove_dir(directory).map_err(|error| error.to_string())?;
    std::fs::File::open(root)
        .and_then(|file| file.sync_all())
        .map_err(|error| error.to_string())
}

impl Stage {
    pub(crate) fn create(root: &Path, size: u64) -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt;
        let parent = root.parent().ok_or("Missing staging parent.")?;
        ancestors(parent)?;
        match std::fs::DirBuilder::new().mode(0o700).create(root) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(format!("Create update root: {error}")),
        }
        protected(root, true)?;
        // Reserve space for settings/logs. The bound applies before accepting
        // any package bytes; statvfs observes capacity and never touches media.
        let name = std::ffi::CString::new(root.as_os_str().as_encoded_bytes())
            .map_err(|_| "Invalid staging path.")?;
        let mut info = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: NUL-terminated path and writable statvfs storage remain live.
        if unsafe { libc::statvfs(name.as_ptr(), info.as_mut_ptr()) } != 0 {
            return Err("Cannot establish update staging free space.".into());
        }
        // SAFETY: successful statvfs initialized the complete structure.
        let info = unsafe { info.assume_init() };
        if (info.f_bavail as u64).saturating_mul(info.f_frsize as u64)
            < size.saturating_add(32 * 1024 * 1024)
        {
            return Err("Insufficient /data space for the update and settings reserve.".into());
        }
        let directory = root.join(uuid::Uuid::new_v4().to_string());
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|error| format!("Create private update stage: {error}"))?;
        Ok(Self {
            directory,
            keep: false,
        })
    }

    pub(crate) fn id(&self) -> String {
        self.directory
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }
    pub(crate) fn package(&self) -> PathBuf {
        self.directory.join("package.tar")
    }

    pub(crate) fn retain(mut self, raw_feed: &[u8]) -> Result<String, String> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.directory.join("feed.json"))
            .map_err(|error| error.to_string())?;
        file.write_all(raw_feed)
            .and_then(|_| file.sync_all())
            .map_err(|error| error.to_string())?;
        std::fs::File::open(&self.directory)
            .and_then(|file| file.sync_all())
            .map_err(|error| error.to_string())?;
        self.keep = true;
        Ok(self.id())
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        if !self.keep {
            // Only the two exact entries created in this private random stage.
            let _ = std::fs::remove_file(self.directory.join("package.tar"));
            let _ = std::fs::remove_file(self.directory.join("feed.json"));
            let _ = std::fs::remove_dir(&self.directory);
        }
    }
}

pub(crate) async fn download(
    client: &reqwest::Client,
    target: &ChannelFeedTarget,
    stage: &Stage,
    progress: impl Fn(u64),
) -> Result<(), String> {
    if target.size == 0 || target.size > crate::channel_feed::MAX_REMOTE_UPDATE_BYTES {
        return Err("Download size exceeds the device limit.".into());
    }
    let mut response = response(client, &target.url).await?;
    if response
        .content_length()
        .is_some_and(|size| size != target.size)
    {
        return Err("Release Content-Length differs from the signed size.".into());
    }
    let mut output = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(stage.package())
        .await
        .map_err(|error| error.to_string())?;
    let mut size = 0u64;
    let mut digest = Sha256::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("Release stream failed: {error}"))?
    {
        size = size
            .checked_add(chunk.len() as u64)
            .ok_or("Download size overflow.")?;
        if size > target.size {
            return Err("Release stream exceeds the signed size.".into());
        }
        digest.update(&chunk);
        output
            .write_all(&chunk)
            .await
            .map_err(|error| format!("Write staged release: {error}"))?;
        progress(size);
    }
    if size != target.size || format!("{:x}", digest.finalize()) != target.sha256 {
        return Err("Downloaded package differs from its signed size or SHA-256.".into());
    }
    output
        .sync_all()
        .await
        .map_err(|error| format!("Sync staged release: {error}"))
}

pub(crate) fn retained(root: &Path, id: &str) -> Result<(PathBuf, Vec<u8>), String> {
    exact_id(id)?;
    let directory = root.join(id);
    ancestors(&directory)?;
    let path = directory.join("feed.json");
    let feed = read(&path, MAX_CHANNEL_FEED_BYTES)?;
    let package = directory.join("package.tar");
    protected(&package, false)?;
    Ok((package, feed))
}

fn read(path: &Path, bound: usize) -> Result<Vec<u8>, String> {
    use std::os::unix::fs::OpenOptionsExt;
    protected(path, false)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    file.take(bound as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > bound {
        return Err("Retained channel metadata exceeds its bound.".into());
    }
    Ok(bytes)
}

pub(crate) fn verify_package_bytes(path: &Path, target: &ChannelFeedTarget) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    protected(path, false)?;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| error.to_string())?;
    if file.metadata().map_err(|error| error.to_string())?.len() != target.size {
        return Err("Staged update size changed.".into());
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let count = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or("Staged update size overflow.")?;
        if total > target.size {
            return Err("Staged update grew beyond its signed size.".into());
        }
        digest.update(&buffer[..count]);
    }
    if total != target.size || format!("{:x}", digest.finalize()) != target.sha256 {
        return Err("Staged update digest changed.".into());
    }
    Ok(())
}

pub(crate) fn copy_for_worker(source: &Path, root: &Path, expected: &str) -> Result<Stage, String> {
    use std::os::unix::fs::OpenOptionsExt;
    protected(source, false)?;
    let mut input = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source)
        .map_err(|error| error.to_string())?;
    let size = input.metadata().map_err(|error| error.to_string())?.len();
    if size == 0 || size > crate::channel_feed::MAX_REMOTE_UPDATE_BYTES {
        return Err("Channel worker copy exceeds the device limit.".into());
    }
    let stage = Stage::create(root, size)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(stage.package())
        .map_err(|error| error.to_string())?;
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let length = input.read(&mut buffer).map_err(|error| error.to_string())?;
        if length == 0 {
            break;
        }
        total += length as u64;
        if total > size {
            return Err("Channel package grew during worker reservation.".into());
        }
        digest.update(&buffer[..length]);
        output
            .write_all(&buffer[..length])
            .map_err(|error| error.to_string())?;
    }
    if total != size || format!("{:x}", digest.finalize()) != expected {
        return Err(
            "Channel package changed before worker reservation; no worker was scheduled.".into(),
        );
    }
    output.sync_all().map_err(|error| error.to_string())?;
    Ok(stage)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use dcent_schema::update::{ChannelArtifactKind, ChannelInstallRoute, UpdateChannel};
    use std::os::unix::fs::DirBuilderExt;
    use std::process::{Child, Command, Stdio};

    pub(crate) struct HttpsFixture {
        pub(crate) root: PathBuf,
        pub(crate) url: String,
        pub(crate) client: reqwest::Client,
        child: Child,
    }

    impl HttpsFixture {
        pub(crate) fn new() -> Self {
            let root = std::env::temp_dir().join(format!("dcent-channel-{}", uuid::Uuid::new_v4()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .unwrap();
            std::fs::write(root.join("package.tar"), b"bounded download fixture").unwrap();
            std::fs::write(root.join("feed.json"), b"{}").unwrap();
            let ready = root.join("ready.json");
            let script = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../scripts/test_channel_https_server.py");
            let mut child = Command::new("python3")
                .arg(script)
                .arg("--serve")
                .arg("--root")
                .arg(&root)
                .arg("--ready")
                .arg(&ready)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(8);
            while !ready.exists() {
                if child.try_wait().unwrap().is_some() || std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("loopback HTTPS fixture failed to start");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let data: serde_json::Value =
                serde_json::from_slice(&std::fs::read(ready).unwrap()).unwrap();
            let certificate =
                reqwest::Certificate::from_pem(&std::fs::read(root.join("tls-ca.pem")).unwrap())
                    .unwrap();
            let client = reqwest::Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .add_root_certificate(certificate)
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap();
            Self {
                root,
                url: data["url"].as_str().unwrap().into(),
                client,
                child,
            }
        }

        pub(crate) fn target(&self, suffix: &str) -> ChannelFeedTarget {
            let bytes = std::fs::read(self.root.join("package.tar")).unwrap();
            ChannelFeedTarget {
                board_target: "am1-s9".into(),
                version: "1.2.3".into(),
                minimum_version: "0.9.0".into(),
                release_channel: UpdateChannel::Beta,
                artifact_kind: ChannelArtifactKind::SysupgradeTar,
                install_route: ChannelInstallRoute::FirstInstallAndSelfUpdate,
                hardware_recipe: "board-default".into(),
                sha256: format!("{:x}", Sha256::digest(&bytes)),
                size: bytes.len() as u64,
                url: format!("{}{suffix}", self.url),
            }
        }
    }

    impl Drop for HttpsFixture {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }

    #[test]
    fn retained_stage_limit_and_explicit_discard_include_interrupted_downloads() {
        let fixture = HttpsFixture::new();
        let root = fixture.root.join("stages");
        let first = create_download(&root, 1).unwrap();
        let first_id = first.id();
        // Simulate process death: a direct empty directory remains, and still
        // consumes the budget. It can be discarded without unsigned metadata.
        std::mem::forget(first);
        let second = create_download(&root, 1).unwrap();
        let second_id = second.retain(b"private stored metadata").unwrap();
        assert_eq!(stored(&root).unwrap().len(), 2);
        assert!(create_download(&root, 1).is_err());
        assert!(discard(&root, "../other").is_err());
        discard(&root, &first_id).unwrap();
        assert!(!root.join(first_id).exists());
        assert!(
            root.join(&second_id).exists(),
            "another selected stage is untouched"
        );
        let third = create_download(&root, 1).unwrap();
        std::os::unix::fs::symlink(fixture.root.join("package.tar"), third.package()).unwrap();
        assert!(discard(&root, &third.id()).is_err());
        assert!(fixture.root.join("package.tar").exists());
        drop(third);
        discard(&root, &second_id).unwrap();
        assert!(stored(&root).unwrap().is_empty());
    }

    #[tokio::test]
    async fn actual_https_download_is_bounded_and_retained_bytes_are_rechecked() {
        let fixture = HttpsFixture::new();
        let target = fixture.target("/package.tar");
        let stage_root = fixture.root.join("stages");
        let stage = Stage::create(&stage_root, target.size).unwrap();
        let observed = std::sync::atomic::AtomicU64::new(0);
        download(&fixture.client, &target, &stage, |bytes| {
            observed.store(bytes, std::sync::atomic::Ordering::Relaxed)
        })
        .await
        .unwrap();
        assert_eq!(
            observed.load(std::sync::atomic::Ordering::Relaxed),
            target.size
        );
        verify_package_bytes(&stage.package(), &target).unwrap();
        let id = stage
            .retain(b"retained exact signed envelope is verified by the caller")
            .unwrap();
        let (package, raw) = retained(&stage_root, &id).unwrap();
        assert!(raw.starts_with(b"retained exact"));
        std::fs::write(&package, b"modified artifact").unwrap();
        assert!(verify_package_bytes(&package, &target).is_err());
        assert!(retained(&stage_root, "../other").is_err());

        for endpoint in ["/too-long", "/truncated", "/redirect", "/package.tar"] {
            let mut target = fixture.target(endpoint);
            if endpoint == "/package.tar" {
                target.sha256 = "e".repeat(64);
            }
            let stage = Stage::create(&stage_root, target.size).unwrap();
            let path = stage.package();
            assert!(
                download(&fixture.client, &target, &stage, |_| ())
                    .await
                    .is_err(),
                "{endpoint}"
            );
            drop(stage);
            assert!(
                !path.exists(),
                "failed bytes must not become a retained stage"
            );
        }
        let mut plaintext = fixture.target("/package.tar");
        plaintext.url = plaintext.url.replacen("https:", "http:", 1);
        let stage = Stage::create(&stage_root, plaintext.size).unwrap();
        assert!(download(&fixture.client, &plaintext, &stage, |_| ())
            .await
            .unwrap_err()
            .contains("HTTPS"));
    }

    #[tokio::test]
    async fn actual_https_feed_signature_and_stream_bounds_fail_closed() {
        use ed25519_dalek::{Signer, SigningKey};
        let fixture = HttpsFixture::new();
        let payload = serde_json::json!({"schema": 1, "product": "DCENT_OS", "release_channel": "beta",
            "source_commit": "a".repeat(40), "targets": [fixture.target("/package.tar")]});
        let payload = serde_json::to_string(&payload).unwrap();
        let key = SigningKey::from_bytes(&[17; 32]);
        let signature: String = key
            .sign(payload.as_bytes())
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let raw = serde_json::to_vec(
            &serde_json::json!({"profile": dcent_schema::update::CHANNEL_FEED_PROFILE,
            "payload": payload, "signature": signature}),
        )
        .unwrap();
        std::fs::write(fixture.root.join("feed.json"), &raw).unwrap();
        let fetched = feed(&fixture.client, &format!("{}/feed.json", fixture.url))
            .await
            .unwrap();
        let verified = crate::channel_feed::test_verify(
            &fetched,
            UpdateChannel::Beta,
            &key.verifying_key().to_bytes(),
        )
        .unwrap();
        assert_eq!(
            verified
                .select_update("am1-s9", "1.2.2", "board-default")
                .unwrap()
                .version,
            "1.2.3"
        );
        assert!(verified
            .select_update("am1-s9i", "1.2.2", "board-default")
            .is_err());
        assert!(verified
            .select_update("am1-s9", "1.2.4", "board-default")
            .is_err());
        assert!(crate::channel_feed::test_verify(&fetched, UpdateChannel::Beta, &[9; 32]).is_err());
        std::fs::write(
            fixture.root.join("feed.json"),
            vec![b'x'; MAX_CHANNEL_FEED_BYTES + 1],
        )
        .unwrap();
        assert!(feed(&fixture.client, &format!("{}/feed.json", fixture.url))
            .await
            .is_err());
        assert!(feed(&fixture.client, &format!("{}/redirect", fixture.url))
            .await
            .is_err());
    }
}
