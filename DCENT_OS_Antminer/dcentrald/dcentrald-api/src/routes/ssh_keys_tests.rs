use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Barrier;

struct Fixture {
    root: std::path::PathBuf,
    proof: StorageProof,
    checks: AtomicUsize,
    activations: AtomicUsize,
    change_boot: AtomicBool,
    refuse_storage: AtomicBool,
    fail_publish: AtomicBool,
    fail_sync: AtomicBool,
    fail_activate: AtomicBool,
    checked_storage: bool,
    rebind_profile: AtomicBool,
    barrier: Option<Arc<Barrier>>,
}

impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("dcent-ssh-keys-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["data/dcent", "root/.ssh", "etc/dropbear"] {
            std::fs::create_dir_all(root.join(name)).unwrap();
            std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        symlink(
            "/data/dcent/authorized_keys",
            root.join("root/.ssh/authorized_keys"),
        )
        .unwrap();
        let mount = mount_id(&secure_dir(&root, "data/dcent").unwrap()).unwrap();
        Self {
            root,
            proof: StorageProof {
                profile: StorageProfile::Classic,
                mounts: MountProof {
                    schema: 1,
                    boot_id: "fixture-boot".into(),
                    volume_mount_id: mount.clone(),
                    data_mount_id: mount.clone(),
                    keys_mount_id: mount,
                    device: "fixture".into(),
                },
            },
            checks: AtomicUsize::new(0),
            activations: AtomicUsize::new(0),
            change_boot: AtomicBool::new(false),
            refuse_storage: AtomicBool::new(false),
            fail_publish: AtomicBool::new(false),
            fail_sync: AtomicBool::new(false),
            fail_activate: AtomicBool::new(false),
            checked_storage: false,
            rebind_profile: AtomicBool::new(false),
            barrier: None,
        }
    }
    fn keys(&self) -> std::path::PathBuf {
        self.root.join("data/dcent/authorized_keys")
    }
    fn install(&self, content: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.keys())
            .unwrap();
        file.write_all(content).unwrap();
    }
    fn no_temporary_files(&self) {
        assert!(!std::fs::read_dir(self.root.join("data/dcent"))
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".authorized_keys.")));
    }

    fn storage_files(&self, profile: StorageProfile) {
        for name in [
            "etc/dcentos",
            "usr/libexec/dcentos",
            "usr/sbin",
            "run/dcentos",
            "proc/sys/kernel/random",
        ] {
            std::fs::create_dir_all(self.root.join(name)).unwrap();
        }
        std::fs::write(
            self.root.join("etc/dcentos/board_target"),
            format!("{}\n", profile.target()),
        )
        .unwrap();
        std::fs::write(
            self.root.join("proc/sys/kernel/random/boot_id"),
            if matches!(profile, StorageProfile::NativeSd(_) | StorageProfile::S19k) {
                "943abf27-74a5-4cfa-8eab-bfedec7f268e\n"
            } else {
                "fixture-boot\n"
            },
        )
        .unwrap();
        let helper = self.root.join(profile.helper().trim_start_matches('/'));
        std::fs::write(&helper, b"inert fixture helper; never executed").unwrap();
        std::fs::set_permissions(helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        if profile == StorageProfile::S19k {
            std::fs::create_dir(self.root.join("data/dcent/dropbear")).unwrap();
            std::fs::set_permissions(
                self.root.join("data/dcent/dropbear"),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            return;
        }
        let path = self.root.join("run/dcentos").join(profile.receipt());
        std::fs::write(
            &path,
            if matches!(profile, StorageProfile::NativeSd(_)) {
                b"943abf27-74a5-4cfa-8eab-bfedec7f268e\n".to_vec()
            } else {
                serde_json::to_vec(&proof_json(profile, &self.proof.mounts)).unwrap()
            },
        )
        .unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn proof_json(profile: StorageProfile, mounts: &MountProof) -> serde_json::Value {
    let mut value = serde_json::json!({"schema": mounts.schema, "boot_id": mounts.boot_id,
        "volume_mount_id": mounts.volume_mount_id, "data_mount_id": mounts.data_mount_id,
        "keys_mount_id": mounts.keys_mount_id, "device": mounts.device});
    if profile != StorageProfile::Classic {
        value["board_target"] = profile.target().into();
    }
    value
}

impl Owner for Fixture {
    fn root(&self) -> &Path {
        &self.root
    }
    fn check(&self) -> Checked<StorageProof> {
        if self.refuse_storage.load(Ordering::SeqCst) {
            return Err("fixture storage refused".into());
        }
        let calls = self.checks.fetch_add(1, Ordering::SeqCst);
        if self.checked_storage {
            if calls > 0 && self.rebind_profile.load(Ordering::SeqCst) {
                self.storage_files(StorageProfile::Plus120);
            }
            return check_storage(&self.root, |helper| {
                assert!(matches!(
                    helper,
                    "/usr/libexec/dcentos/classic-aml-storage.py"
                        | "/usr/libexec/dcentos/bm1362-nopic-storage.py"
                        | "/usr/libexec/dcentos/native-zynq-sd-storage.py"
                        | "/usr/sbin/dcent-s19k-data-mount"
                ));
                Ok(())
            });
        }
        let mut proof = self.proof.clone();
        if calls > 0 && self.change_boot.load(Ordering::SeqCst) {
            proof.mounts.boot_id = "new-boot".into();
        }
        Ok(proof)
    }
    fn activate(&self) -> Checked<()> {
        self.activations.fetch_add(1, Ordering::SeqCst);
        if self.fail_activate.load(Ordering::SeqCst) {
            Err("fixture service failed".into())
        } else {
            Ok(())
        }
    }
    fn before_publish(&self) -> Checked<()> {
        if let Some(barrier) = &self.barrier {
            barrier.wait();
            barrier.wait();
        }
        if self.fail_publish.load(Ordering::SeqCst) {
            Err("fixture publication refused".into())
        } else {
            Ok(())
        }
    }
    fn sync_directory(&self, directory: &File) -> Checked<()> {
        if self.fail_sync.load(Ordering::SeqCst) {
            Err("fixture directory I/O error".into())
        } else {
            directory.sync_all().map_err(io_error)
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn key(seed: u8) -> String {
    let public = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key();
    let mut wire = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
    wire.extend_from_slice(public.as_bytes());
    format!("ssh-ed25519 {} fixture-{seed}", base64(&wire))
}

#[test]
fn exact_classic_a_plus_s19k_owner_enrolls_through_real_identity_and_proof_reader() {
    for profile in [
        StorageProfile::Classic,
        StorageProfile::A126,
        StorageProfile::Plus120,
        StorageProfile::S19k,
    ] {
        let mut owner = Fixture::new();
        owner.checked_storage = true;
        owner.storage_files(profile);
        let original = format!("{}\n", key(1));
        owner.install(original.as_bytes());
        let result = enroll(&owner, &key(2), true).unwrap();
        assert!(result.persisted && result.durable);
        assert_eq!(result.activation, "requested");
        assert_eq!(result.status.scope, profile.scope());
        assert_eq!(result.status.fingerprints.len(), 2);
        assert!(std::fs::read(owner.keys())
            .unwrap()
            .starts_with(original.as_bytes()));
        assert_eq!(inspect(&owner).unwrap().scope, profile.scope());
        assert_eq!(owner.activations.load(Ordering::SeqCst), 1);
        owner.no_temporary_files();
    }
}

#[test]
fn s19k_enrollment_requires_exact_target_live_owner_and_persistent_namespace() {
    let mut owner = Fixture::new();
    owner.checked_storage = true;
    owner.storage_files(StorageProfile::S19k);
    for target in [b"am3-s19kpro\n".as_slice(), b"am3-s19k", b"am3-s19xp\n"] {
        assert!(StorageProfile::from_target(target).is_err());
    }
    assert!(parse_storage_proof(
        StorageProfile::S19k,
        &serde_json::to_vec(&proof_json(StorageProfile::Classic, &owner.proof.mounts)).unwrap(),
        "943abf27-74a5-4cfa-8eab-bfedec7f268e"
    )
    .is_err());
    let error = check_storage(&owner.root, |helper| {
        assert_eq!(helper, "/usr/sbin/dcent-s19k-data-mount");
        Err("exact mtd4 overlay layout refused".into())
    })
    .unwrap_err();
    assert!(error.contains("mtd4"));
    assert!(!owner.keys().exists());
    std::fs::write(
        owner.root.join("proc/sys/kernel/random/boot_id"),
        "not-a-boot\n",
    )
    .unwrap();
    assert!(enroll(&owner, &key(2), true).is_err());
    assert!(!owner.keys().exists());
    std::fs::write(
        owner.root.join("proc/sys/kernel/random/boot_id"),
        "943abf27-74a5-4cfa-8eab-bfedec7f268e\n",
    )
    .unwrap();
    let keys = owner.root.join("data/dcent/dropbear");
    std::fs::remove_dir(&keys).unwrap();
    symlink(owner.root.join("etc/dropbear"), &keys).unwrap();
    assert!(enroll(&owner, &key(2), true).is_err());
    assert!(!owner.keys().exists());
    assert_eq!(owner.activations.load(Ordering::SeqCst), 0);
}

const SD_TARGETS: [&str; 7] = [
    "am1-s9i",
    "am1-s9j",
    "am2-s17p",
    "am2-s17plus",
    "am2-t17",
    "am2-t17plus",
    "am2-s19pro",
];

struct HostDirectoryBind(std::path::PathBuf);

impl HostDirectoryBind {
    fn new(root: &Path, source: &str, destination: &str) -> Self {
        assert_eq!(std::env::var("DCENT_TEST_HOST_BINDS").as_deref(), Ok("1"));
        assert_ne!(
            std::fs::read_link("/proc/self/ns/mnt").unwrap(),
            std::fs::read_link("/proc/1/ns/mnt").unwrap()
        );
        let source = root.join(source);
        let destination = root.join(destination);
        assert!(source.canonicalize().unwrap().starts_with(root));
        assert!(destination.canonicalize().unwrap().starts_with(root));
        assert!(Command::new("/bin/mount")
            .arg("--bind")
            .arg(&source)
            .arg(&destination)
            .status()
            .unwrap()
            .success());
        Self(destination)
    }
}

impl Drop for HostDirectoryBind {
    fn drop(&mut self) {
        let result = Command::new("/bin/umount").arg(&self.0).status().unwrap();
        assert!(
            result.success(),
            "private host-directory bind cleanup failed"
        );
    }
}

#[test]
#[ignore = "requires explicit isolated host mount namespace; no device or media mount"]
fn seven_native_sd_owners_enroll_through_actual_directory_binds() {
    for target in SD_TARGETS {
        let profile = StorageProfile::from_target(format!("{target}\n").as_bytes()).unwrap();
        assert_eq!(profile, StorageProfile::NativeSd(target));
        let mut owner = Fixture::new();
        owner.checked_storage = true;
        owner.storage_files(profile);
        std::fs::create_dir_all(owner.root.join("data/keys/dropbear")).unwrap();
        let _bind = HostDirectoryBind::new(&owner.root, "data/keys/dropbear", "etc/dropbear");
        let original = format!("{}\n", key(1));
        owner.install(original.as_bytes());
        let result = enroll(&owner, &key(2), true).unwrap();
        assert!(result.persisted && result.durable);
        assert_eq!(result.activation, "requested");
        assert_eq!(result.status.scope, "native_zynq_sd_data");
        assert_eq!(result.status.fingerprints.len(), 2);
        assert_eq!(inspect(&owner).unwrap().fingerprints.len(), 2);
        assert!(std::fs::read(owner.keys())
            .unwrap()
            .starts_with(original.as_bytes()));
        assert_eq!(owner.activations.load(Ordering::SeqCst), 1);
        owner.no_temporary_files();
    }
}

#[test]
fn native_sd_neighbours_and_aml_json_readiness_are_refused() {
    let fixture = Fixture::new();
    for target in SD_TARGETS {
        for candidate in [
            target.to_string(),
            format!("{target}-extra\n"),
            format!(" {target}\n"),
        ] {
            assert!(StorageProfile::from_target(candidate.as_bytes()).is_err());
        }
        assert!(parse_storage_proof(
            StorageProfile::NativeSd(target),
            &serde_json::to_vec(&proof_json(StorageProfile::Classic, &fixture.proof.mounts))
                .unwrap(),
            "fixture-boot"
        )
        .is_err());
    }
    for target in [
        b"am1-s9se\n".as_slice(),
        b"am1-s9k\n",
        b"am1-s15\n",
        b"am1-t15\n",
        b"am2-s19j\n",
    ] {
        assert!(StorageProfile::from_target(target).is_err());
    }
}

#[test]
fn native_sd_missing_persistent_bind_and_bad_boot_refuse_before_publication() {
    let mut owner = Fixture::new();
    owner.checked_storage = true;
    owner.storage_files(StorageProfile::NativeSd("am1-s9i"));
    std::fs::create_dir_all(owner.root.join("data/keys/dropbear")).unwrap();
    assert!(enroll(&owner, &key(1), true)
        .unwrap_err()
        .contains("persistent bind"));
    let ready = owner.root.join("run/dcentos/native-zynq-sd-ready");
    for content in [
        b"prior-boot\n".as_slice(),
        b"943abf27-74a5-4cfa-8eab-bfedec7f268e",
        b"{\"schema\":1}",
    ] {
        std::fs::write(&ready, content).unwrap();
        assert!(enroll(&owner, &key(1), true)
            .unwrap_err()
            .contains("another boot"));
    }
    assert!(!owner.keys().exists());
    assert_eq!(owner.activations.load(Ordering::SeqCst), 0);
}

#[test]
#[ignore = "requires explicit isolated host mount namespace; no device or media mount"]
fn native_sd_foreign_application_bind_is_refused() {
    let mut owner = Fixture::new();
    owner.checked_storage = true;
    owner.storage_files(StorageProfile::NativeSd("am2-s17p"));
    std::fs::create_dir_all(owner.root.join("data/keys/dropbear")).unwrap();
    std::fs::create_dir_all(owner.root.join("foreign-data")).unwrap();
    let _keys = HostDirectoryBind::new(&owner.root, "data/keys/dropbear", "etc/dropbear");
    let _data = HostDirectoryBind::new(&owner.root, "foreign-data", "data/dcent");
    assert!(enroll(&owner, &key(1), true)
        .unwrap_err()
        .contains("changed mount"));
    assert!(!owner.keys().exists());
    assert_eq!(owner.activations.load(Ordering::SeqCst), 0);
}

#[test]
fn storage_profile_and_original_schemas_refuse_sibling_stale_duplicate_or_extended_proofs() {
    let fixture = Fixture::new();
    for profile in [
        StorageProfile::Classic,
        StorageProfile::A126,
        StorageProfile::Plus120,
    ] {
        let value = proof_json(profile, &fixture.proof.mounts);
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(parse_storage_proof(profile, &bytes, "fixture-boot").is_ok());
        assert!(parse_storage_proof(profile, &bytes, "other-boot").is_err());
        for other in [
            StorageProfile::Classic,
            StorageProfile::A126,
            StorageProfile::Plus120,
        ] {
            if other != profile {
                assert!(parse_storage_proof(other, &bytes, "fixture-boot").is_err());
            }
        }
        let mut extra = value.clone();
        extra["unexpected"] = true.into();
        assert!(parse_storage_proof(
            profile,
            &serde_json::to_vec(&extra).unwrap(),
            "fixture-boot"
        )
        .is_err());
        let duplicate = format!(
            "{{\"schema\":1,{}",
            std::str::from_utf8(&bytes).unwrap().trim_start_matches('{')
        );
        assert!(parse_storage_proof(profile, duplicate.as_bytes(), "fixture-boot").is_err());
        let mut wrong_schema = value;
        wrong_schema["schema"] = 2.into();
        assert!(parse_storage_proof(
            profile,
            &serde_json::to_vec(&wrong_schema).unwrap(),
            "fixture-boot"
        )
        .is_err());
    }
}

#[test]
fn unsupported_identity_and_rebinding_never_publish_or_activate() {
    for target in [
        "am3-s19jproa-extra\n",
        "am3-s19jproplus-extra\n",
        "am3-bb-s19jpro\n",
        "am3-s19jproa",
        "am3-s19kpro\n",
    ] {
        let owner = Fixture::new();
        owner.storage_files(StorageProfile::A126);
        std::fs::write(owner.root.join("etc/dcentos/board_target"), target).unwrap();
        assert!(check_storage(&owner.root, |_| panic!(
            "unexpected storage helper on foreign target"
        ))
        .is_err());
    }
    let mut owner = Fixture::new();
    owner.checked_storage = true;
    owner.storage_files(StorageProfile::A126);
    owner.install(key(1).as_bytes());
    owner.rebind_profile.store(true, Ordering::SeqCst);
    assert!(enroll(&owner, &key(2), true).is_err());
    assert_eq!(std::fs::read(owner.keys()).unwrap(), key(1).as_bytes());
    assert_eq!(owner.activations.load(Ordering::SeqCst), 0);
    owner.no_temporary_files();
}

#[test]
fn helper_refusal_and_identity_change_during_check_refuse() {
    let owner = Fixture::new();
    owner.storage_files(StorageProfile::A126);
    assert!(check_storage(
        &owner.root,
        |_| Err("fixture kernel/DT/UBI mismatch".into())
    )
    .is_err());
    assert!(check_storage(&owner.root, |_| {
        owner.storage_files(StorageProfile::Plus120);
        Ok(())
    })
    .is_err());
    assert!(!owner.keys().exists());
}

#[test]
fn parser_accepts_canonical_public_keys_and_deduplicates_wire_identity() {
    let value = key(1);
    let parsed = parse_keys(&format!("{value}\n{value}\r\n")).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].line, value);
    assert!(parsed[0].fingerprint.starts_with("SHA256:"));
    assert_eq!(parsed[0].fingerprint.len(), 50);
    assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    assert_eq!(base64(b"f"), "Zg");
}

#[test]
fn parser_rejects_private_options_wrong_wire_controls_weak_and_oversized_input() {
    let valid = key(2);
    let weak = format!(
        "ssh-ed25519 {}",
        base64(&[b"\0\0\0\x0bssh-ed25519\0\0\0\x20".as_slice(), &[0u8; 32]].concat())
    );
    for input in [
        concat!("-----BEGIN OPENSSH ", "PRIVATE KEY-----").to_string(),
        format!("command=evil {valid}"),
        valid.replace("ssh-ed25519 ", "ssh-rsa "),
        format!("\x0b{valid}"),
        valid.replace("AAAAC", "AAAA="),
        "x".repeat(MAX_BYTES + 1),
        weak,
    ] {
        assert!(
            parse_keys(&input).is_err(),
            "invalid public-key fixture was accepted"
        );
    }
    let values = (1..=17).map(key).collect::<Vec<_>>().join("\n");
    assert!(parse_keys(&values).is_err());
}

#[test]
fn individual_line_limit_matches_server_admission_before_whitespace_trimming() {
    let valid = key(2);
    let boundary = format!("{valid} {}", "x".repeat(MAX_KEY_LINE - valid.len() - 1));
    assert_eq!(boundary.len(), MAX_KEY_LINE);
    assert!(parse_keys(&boundary).is_ok());
    assert!(parse_keys(&(boundary + "x")).is_err());
    assert!(parse_keys(&format!("{}{valid}", " ".repeat(MAX_KEY_LINE))).is_err());
    let owner = Fixture::new();
    let original = format!("{valid} {}", "x".repeat(MAX_KEY_LINE));
    owner.install(original.as_bytes());
    assert!(enroll(&owner, &key(3), true).is_err());
    assert_eq!(std::fs::read(owner.keys()).unwrap(), original.as_bytes());
    assert_eq!(owner.activations.load(Ordering::SeqCst), 0);
    owner.no_temporary_files();
}

#[test]
fn enrollment_preserves_existing_bytes_adds_distinct_key_and_retries_idempotently() {
    let owner = Fixture::new();
    let original = format!("{}\n", key(1));
    owner.install(original.as_bytes());
    let result = enroll(&owner, &key(2), true).unwrap();
    assert!(result.persisted && result.durable);
    assert_eq!(result.activation, "requested");
    assert!(!result.status.root_password_changed);
    let bytes = std::fs::read(owner.keys()).unwrap();
    assert!(bytes.starts_with(original.as_bytes()));
    assert_eq!(result.status.fingerprints.len(), 2);
    assert_eq!(
        std::fs::metadata(owner.keys()).unwrap().mode() & 0o7777,
        0o600
    );
    enroll(&owner, &key(2), false).unwrap();
    assert_eq!(std::fs::read(owner.keys()).unwrap(), bytes);
    assert_eq!(owner.activations.load(Ordering::SeqCst), 1);
    assert_eq!(inspect(&owner).unwrap().fingerprints.len(), 2);
    owner.no_temporary_files();
}

#[test]
fn foreign_storage_root_link_and_mount_ids_refuse_before_key_publication() {
    for kind in ["storage", "link", "mount"] {
        let mut owner = Fixture::new();
        match kind {
            "storage" => owner.refuse_storage.store(true, Ordering::SeqCst),
            "mount" => owner.proof.mounts.data_mount_id = "999999999".into(),
            _ => {
                std::fs::remove_file(owner.root.join("root/.ssh/authorized_keys")).unwrap();
                symlink("/etc/shadow", owner.root.join("root/.ssh/authorized_keys")).unwrap();
            }
        }
        assert!(enroll(&owner, &key(1), true).is_err());
        assert!(!owner.keys().exists());
        assert_eq!(owner.activations.load(Ordering::SeqCst), 0);
        owner.no_temporary_files();
    }
}

#[test]
fn existing_symlink_fifo_hardlink_and_writable_credentials_are_not_opened_or_replaced() {
    for kind in ["symlink", "fifo", "hardlink", "mode"] {
        let owner = Fixture::new();
        match kind {
            "symlink" => symlink("/etc/shadow", owner.keys()).unwrap(),
            "fifo" => {
                let name = std::ffi::CString::new(owner.keys().to_str().unwrap()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            "hardlink" => {
                owner.install(key(1).as_bytes());
                std::fs::hard_link(owner.keys(), owner.root.join("alias")).unwrap();
            }
            _ => {
                owner.install(key(1).as_bytes());
                std::fs::set_permissions(owner.keys(), std::fs::Permissions::from_mode(0o666))
                    .unwrap();
            }
        }
        let before = std::fs::symlink_metadata(owner.keys()).unwrap().ino();
        assert!(enroll(&owner, &key(2), true).is_err());
        assert_eq!(
            std::fs::symlink_metadata(owner.keys()).unwrap().ino(),
            before
        );
        assert_eq!(owner.activations.load(Ordering::SeqCst), 0);
        owner.no_temporary_files();
    }
}

#[test]
fn publication_and_boot_change_faults_preserve_prior_key_and_remove_scratch() {
    for changed_boot in [false, true] {
        let owner = Fixture::new();
        let original = key(1);
        owner.install(original.as_bytes());
        owner.change_boot.store(changed_boot, Ordering::SeqCst);
        owner.fail_publish.store(!changed_boot, Ordering::SeqCst);
        assert!(enroll(&owner, &key(2), true).is_err());
        assert_eq!(std::fs::read(owner.keys()).unwrap(), original.as_bytes());
        assert_eq!(owner.activations.load(Ordering::SeqCst), 0);
        owner.no_temporary_files();
    }
}

#[test]
fn durable_publication_and_activation_failure_are_reported_separately() {
    let owner = Fixture::new();
    owner.fail_activate.store(true, Ordering::SeqCst);
    let result = enroll(&owner, &key(1), true).unwrap();
    assert!(result.persisted && result.durable);
    assert_eq!(result.activation, "failed");
    assert!(result.activation_error.is_some());
    assert_eq!(
        parse_keys(&std::fs::read_to_string(owner.keys()).unwrap())
            .unwrap()
            .len(),
        1
    );
    owner.no_temporary_files();
}

#[test]
fn directory_sync_failure_never_requests_service_and_can_be_retried() {
    let owner = Fixture::new();
    owner.fail_sync.store(true, Ordering::SeqCst);
    let result = enroll(&owner, &key(1), true).unwrap();
    assert!(result.persisted && !result.durable);
    assert_eq!(result.activation, "not_requested");
    assert_eq!(owner.activations.load(Ordering::SeqCst), 0);
    owner.fail_sync.store(false, Ordering::SeqCst);
    assert!(enroll(&owner, &key(1), true).unwrap().durable);
    assert_eq!(inspect(&owner).unwrap().fingerprints.len(), 1);
    owner.no_temporary_files();
}

#[test]
fn operator_opt_out_and_unsafe_activation_temporary_are_preserved() {
    for disabled_flag in [true, false] {
        let owner = Fixture::new();
        if disabled_flag {
            std::fs::write(owner.root.join("data/dcent/.ssh-disabled"), b"").unwrap();
        } else {
            symlink(
                "/etc/shadow",
                owner.root.join("data/dcent/.ssh-enabled.tmp"),
            )
            .unwrap();
        }
        let result = enroll(&owner, &key(1), true).unwrap();
        assert!(result.persisted && result.durable);
        assert_eq!(
            result.activation,
            if disabled_flag {
                "disabled_by_operator"
            } else {
                "failed"
            }
        );
        assert_eq!(owner.activations.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn canceled_http_waiter_does_not_cancel_persistent_transaction() {
    let barrier = Arc::new(Barrier::new(2));
    let mut owner = Fixture::new();
    owner.barrier = Some(barrier.clone());
    let owner = Arc::new(owner);
    let job = schedule_enrollment(owner.clone(), key(1), true, || Ok(()));
    let completion = job.abort_handle();
    let waiter = tokio::spawn(async move { job.await });
    // The barrier is a controlled inert publication pause, never a device IO.
    barrier.wait();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    barrier.wait();
    // Observe the detached worker itself, rather than assuming its durable
    // filesystem transaction finishes within 500ms under concurrent test I/O.
    // The handle only observes completion; it never cancels the worker.
    tokio::time::timeout(Duration::from_secs(10), async {
        while !completion.is_finished() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("detached enrollment worker did not finish");
    assert_eq!(Arc::strong_count(&owner), 1);
    assert_eq!(owner.activations.load(Ordering::SeqCst), 1);
    assert_eq!(
        parse_keys(&std::fs::read_to_string(owner.keys()).unwrap())
            .unwrap()
            .len(),
        1
    );
    owner.no_temporary_files();
}

#[tokio::test]
async fn revoked_authorization_before_worker_never_creates_a_key() {
    let owner = Arc::new(Fixture::new());
    let result = schedule_enrollment(owner.clone(), key(1), true, || {
        Err("revoked fixture session".into())
    })
    .await
    .unwrap();
    assert!(result.is_err());
    assert!(!owner.keys().exists());
    assert_eq!(owner.checks.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn actual_route_requires_bearer_and_is_not_an_auth_exemption() {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;
    assert!(!crate::auth::is_auth_exempt("/api/system/ssh/keys"));
    for method in ["GET", "POST"] {
        let response = routes()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri("/api/system/ssh/keys")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"public_keys":key(1),"enable_ssh":true}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
