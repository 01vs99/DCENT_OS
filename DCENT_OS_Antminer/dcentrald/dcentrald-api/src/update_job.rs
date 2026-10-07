//! A browser update outlives the mining daemon's checked shutdown.
use std::path::Path;

pub(crate) async fn launch(
    package: &str,
    authority: &crate::ota_signature::AuthorizedSysupgrade,
) -> Result<serde_json::Value, String> {
    launch_inner(
        package,
        authority,
        None,
        Path::new("/usr/libexec/dcentos/dcentos-update-job.py"),
    )
    .await
}

/// A channel apply retains the operator-selected content identity through the
/// worker's own read/hash/copy handoff, rather than trusting a previous read.
pub(crate) async fn launch_pinned(
    package: &str,
    authority: &crate::ota_signature::AuthorizedSysupgrade,
    expected_sha256: &str,
) -> Result<serde_json::Value, String> {
    launch_channel_inner(
        package,
        authority,
        expected_sha256,
        Path::new("/tmp/dcentos-upgrade"),
        Path::new("/usr/libexec/dcentos/dcentos-update-job.py"),
    )
    .await
}

async fn launch_channel_inner(
    package: &str,
    authority: &crate::ota_signature::AuthorizedSysupgrade,
    expected_sha256: &str,
    upload_root: &Path,
    helper: &Path,
) -> Result<serde_json::Value, String> {
    // The existing worker reserves a RAM-backed upload inode by rename. A
    // downloaded /data package reaches that owner only after explicit apply,
    // through a bounded copy whose bytes retain the selected signed digest.
    let source = std::path::PathBuf::from(package);
    let root = upload_root.to_path_buf();
    let expected = expected_sha256.to_owned();
    let stage = tokio::task::spawn_blocking(move || {
        crate::channel_download::copy_for_worker(&source, &root, &expected)
    })
    .await
    .map_err(|error| error.to_string())??;
    launch_inner(
        stage
            .package()
            .to_str()
            .ok_or("Invalid worker staging path")?,
        authority,
        Some(expected_sha256),
        helper,
    )
    .await
}

async fn launch_inner(
    package: &str,
    authority: &crate::ota_signature::AuthorizedSysupgrade,
    expected_sha256: Option<&str>,
    helper: &Path,
) -> Result<serde_json::Value, String> {
    if authority.board_target().is_empty() || authority.version().is_empty() {
        return Err("update job requires authenticated target/version authority".into());
    }
    let input = package.to_string();
    let bounded = expected_sha256.is_some();
    let digest = tokio::task::spawn_blocking(move || {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(input)
            .map_err(|e| e.to_string())?;
        if !file.metadata().map_err(|e| e.to_string())?.is_file() {
            return Err("update package is not a regular file".into());
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 65536];
        let mut size = 0u64;
        loop {
            let length = file.read(&mut buffer).map_err(|e| e.to_string())?;
            if length == 0 {
                break;
            }
            size = size
                .checked_add(length as u64)
                .ok_or("update package size overflow")?;
            if bounded && size > crate::channel_feed::MAX_REMOTE_UPDATE_BYTES {
                return Err("channel update package exceeds the device size bound".into());
            }
            hasher.update(&buffer[..length]);
        }
        Ok::<_, String>(format!("{:x}", hasher.finalize()))
    })
    .await
    .map_err(|e| e.to_string())??;
    if expected_sha256.is_some_and(|expected| expected != digest) {
        return Err(
            "Update package changed after channel verification; no worker was scheduled.".into(),
        );
    }
    let job_id = uuid::Uuid::new_v4().to_string();
    let source_boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|e| format!("update source boot identity: {e}"))?;
    let source_boot = uuid::Uuid::parse_str(source_boot.trim())
        .map_err(|e| format!("update source boot identity: {e}"))?
        .to_string();
    let result = tokio::process::Command::new("/usr/bin/python3")
        .arg(helper)
        .args([package, &digest, &job_id])
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .map_err(|e| format!("update job launcher: {e}"))?;
    if !result.status.success() {
        return Err(format!(
            "update job was not scheduled: {}",
            String::from_utf8_lossy(&result.stderr)
        ));
    }
    let record: serde_json::Value = serde_json::from_slice(&result.stdout)
        .map_err(|e| format!("update job launch receipt: {e}"))?;
    if !valid_launch_receipt(&record, &job_id, &digest, &source_boot) {
        return Err("update launcher did not return its exact scheduled job".into());
    }
    Ok(record)
}

fn valid_launch_receipt(
    record: &serde_json::Value,
    job_id: &str,
    package_sha256: &str,
    source_boot_id: &str,
) -> bool {
    record.get("schema").and_then(|v| v.as_u64()) == Some(1)
        && record.get("state").and_then(|v| v.as_str()) == Some("scheduled")
        && record.get("boot_verified").and_then(|v| v.as_bool()) == Some(false)
        && [
            ("job_id", job_id),
            ("package_sha256", package_sha256),
            ("source_boot_id", source_boot_id),
        ]
        .iter()
        .all(|(key, expected)| record.get(*key).and_then(|v| v.as_str()) == Some(*expected))
}

/// The inactive data volume is copied before the old worker publishes its
/// final status. A new boot may legitimately inherit a running journal, but
/// that historical PID must never be displayed as a current update worker.
fn reconcile_boot(record: &mut serde_json::Value, current_boot: Option<&str>) {
    let current_boot = current_boot.and_then(|value| uuid::Uuid::parse_str(value.trim()).ok());
    let source_boot = record
        .get("source_boot_id")
        .and_then(|value| value.as_str())
        .and_then(|value| uuid::Uuid::parse_str(value).ok());
    let pending = matches!(
        record.get("state").and_then(|value| value.as_str()),
        Some("preparing" | "scheduled" | "running")
    );
    match (source_boot, current_boot) {
        (Some(source), Some(current)) if source != current => {
            record["boot_changed"] = true.into();
            record["worker_running"] = false.into();
            if pending {
                record["saved_worker_state"] = record["state"].clone();
                record["state"] = "previous_boot_result_unconfirmed".into();
                record["status_detail"] = "The device booted after this update was scheduled; its saved worker result is incomplete.".into();
            }
        }
        (Some(_), Some(_)) => {
            record["boot_changed"] = false.into();
        }
        _ if pending => {
            record["saved_worker_state"] = record["state"].clone();
            record["state"] = "worker_boot_unknown".into();
            record["status_detail"] = "This saved update has no matching boot identity; the worker result needs verification.".into();
        }
        _ => {}
    }
    // Neither the boot UUID nor a worker exit code proves the installed image
    // or hashing. Exact S99/transaction evidence owns any future promotion.
}

fn reconcile_observation(
    record: &mut serde_json::Value,
    observation: &serde_json::Value,
    current_boot: Option<&str>,
) {
    let Some(current) = current_boot.and_then(|value| uuid::Uuid::parse_str(value.trim()).ok())
    else {
        return;
    };
    let Some(observed) = observation
        .get("observed_boot_id")
        .and_then(|v| v.as_str())
        .and_then(|v| uuid::Uuid::parse_str(v).ok())
    else {
        return;
    };
    let Some(source) = record
        .get("source_boot_id")
        .and_then(|v| v.as_str())
        .and_then(|v| uuid::Uuid::parse_str(v).ok())
    else {
        return;
    };
    let valid_digest = |key: &str| {
        observation
            .get(key)
            .and_then(|v| v.as_str())
            .is_some_and(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
    };
    if observation.get("schema").and_then(|v| v.as_str())
        != Some("dcentos.am2-native-boot-commit-observation.v1")
        || observation
            .get("boot_environment_committed")
            .and_then(|v| v.as_bool())
            != Some(true)
        || observation
            .get("physical_hashing_verified")
            .and_then(|v| v.as_bool())
            != Some(false)
        || observed != current
        || !valid_digest("native_transaction")
        || !valid_digest("receipt_sha256")
        || !valid_digest("package_sha256")
        || !matches!(
            observation.get("firmware").and_then(|v| v.as_u64()),
            Some(1 | 2)
        )
        || !["job_id", "package_sha256", "source_boot_id"]
            .iter()
            .all(|key| {
                let value = observation.get(*key).and_then(|v| v.as_str());
                value.is_some() && value == record.get(*key).and_then(|v| v.as_str())
            })
        || source == current
    {
        return;
    }
    record["state"] = "boot_committed".into();
    record["boot_verified"] = true.into();
    record["physical_hashing_verified"] = false.into();
    record["worker_running"] = false.into();
    record["boot_observation"] = observation.clone();
    record["status_detail"] =
        "The device booted into this update and committed its boot environment.".into();
}

fn read_boot_observation(path: &Path) -> Option<serde_json::Value> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() || metadata.len() > 8192 {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return None;
        }
    }
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

pub(crate) fn read_jobs(root: &Path) -> Vec<serde_json::Value> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let current_boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok();
    let mut records = Vec::new();
    for entry in entries.take(256).flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if uuid::Uuid::parse_str(&name)
            .map(|id| id.to_string() != name)
            .unwrap_or(true)
            || !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false)
        {
            continue;
        }
        let path = entry.path().join("status.json");
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.file_type().is_file() || metadata.len() > 8192 {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                continue;
            }
        }
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(mut record) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        if record.get("job_id").and_then(|v| v.as_str()) == Some(&name)
            && record.get("schema").and_then(|v| v.as_u64()) == Some(1)
        {
            reconcile_boot(&mut record, current_boot.as_deref());
            if let Some(observation) =
                read_boot_observation(&entry.path().join("boot-observation.json"))
            {
                reconcile_observation(&mut record, &observation, current_boot.as_deref());
            }
            records.push(record);
        }
    }
    records.sort_by_key(|record| {
        std::cmp::Reverse(
            record
                .get("scheduled_at")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
        )
    });
    records.truncate(16);
    records
}

#[cfg(test)]
mod tests {
    use super::*;
    const BEFORE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const AFTER: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

    #[tokio::test]
    async fn signed_https_package_reaches_real_worker_only_with_exact_selection() {
        use crate::{channel_download as download, channel_feed, ota_signature};
        use dcent_schema::update::UpdateChannel;
        use ed25519_dalek::{Signer, SigningKey};
        let fixture = download::tests::HttpsFixture::new();
        let (package_bytes, public) =
            ota_signature::tests::channel_package_fixture("am1-s9", "1.2.3");
        std::fs::write(fixture.root.join("package.tar"), &package_bytes).unwrap();
        let public_path = fixture.root.join("trusted-public.raw");
        std::fs::write(&public_path, public).unwrap();
        let target = fixture.target("/package.tar");
        let payload = serde_json::to_string(&serde_json::json!({"schema":1,"product":"DCENT_OS",
            "release_channel":"beta","source_commit":"a".repeat(40),"targets":[target]}))
        .unwrap();
        let key = SigningKey::from_bytes(&[17; 32]);
        let signature: String = key
            .sign(payload.as_bytes())
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let raw = serde_json::to_vec(
            &serde_json::json!({"profile":dcent_schema::update::CHANNEL_FEED_PROFILE,
            "payload":payload,"signature":signature}),
        )
        .unwrap();
        std::fs::write(fixture.root.join("feed.json"), &raw).unwrap();
        let raw = download::feed(&fixture.client, &format!("{}/feed.json", fixture.url))
            .await
            .unwrap();
        let verified = channel_feed::test_verify(&raw, UpdateChannel::Beta, &public).unwrap();
        let selected = verified
            .select_update("am1-s9", "1.2.2", "board-default")
            .unwrap();
        let data_root = fixture.root.join("data-stages");
        let stage = download::Stage::create(&data_root, selected.size).unwrap();
        download::download(&fixture.client, selected, &stage, |_| ())
            .await
            .unwrap();
        let id = stage.retain(&raw).unwrap();
        let (package, retained_feed) = download::retained(&data_root, &id).unwrap();
        assert_eq!(raw, retained_feed);
        download::verify_package_bytes(&package, selected).unwrap();
        let authority =
            ota_signature::verify_sysupgrade_bundle(&package, false, Some(&public_path))
                .unwrap()
                .authorize_public_update("am1-s9")
                .unwrap();
        channel_feed::check_package_identity(&authority, selected).unwrap();
        for (board, version) in [("am1-s9i", "1.2.3"), ("am1-s9", "1.2.4")] {
            let mut stale = selected.clone();
            stale.board_target = board.into();
            stale.version = version.into();
            assert!(channel_feed::check_package_identity(&authority, &stale).is_err());
        }
        let mut stale_digest = selected.clone();
        stale_digest.sha256 = "f".repeat(64);
        assert!(download::verify_package_bytes(&package, &stale_digest).is_err());

        // Import the production launcher in a real child process. Only its
        // filesystem roots and final updater command are private fixture paths.
        // The command records ordinary-file evidence and cannot reach a miner.
        let helper = fixture.root.join("launch.py");
        let worker = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentos-update-job.py");
        let worker = std::fs::canonicalize(worker).unwrap();
        let upload = fixture.root.join("ram-upload");
        let journal = fixture.root.join("journal");
        let work = fixture.root.join("reserved-work");
        let command = fixture.root.join("updater.py");
        let marker = fixture.root.join("worker-ran.json");
        let invoked = fixture.root.join("launcher-ran");
        std::fs::write(&command, format!("import hashlib,json,os,pathlib,sys\np=pathlib.Path(sys.argv[1])\npathlib.Path({}).write_text(json.dumps({{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'job':os.environ['DCENT_UPDATE_JOB_ID']}}))\n",serde_json::to_string(&marker).unwrap())).unwrap();
        std::fs::write(&helper, format!(r#"import importlib.util,json,pathlib,sys
pathlib.Path({invoked}).write_text('started')
spec=importlib.util.spec_from_file_location('worker',{worker})
worker=importlib.util.module_from_spec(spec); spec.loader.exec_module(worker)
record=worker.launch_job(pathlib.Path(sys.argv[1]),sys.argv[2],sys.argv[3],stage_root=pathlib.Path({upload}),journal_root=pathlib.Path({journal}),work_root=pathlib.Path({work}),command=(sys.executable,{command}),delay=0)
print(json.dumps(record),flush=True)
"#, invoked=serde_json::to_string(&invoked).unwrap(),worker=serde_json::to_string(&worker).unwrap(),upload=serde_json::to_string(&upload).unwrap(),journal=serde_json::to_string(&journal).unwrap(),work=serde_json::to_string(&work).unwrap(),command=serde_json::to_string(&command).unwrap())).unwrap();
        let wrong = launch_channel_inner(
            package.to_str().unwrap(),
            &authority,
            &"e".repeat(64),
            &upload,
            &helper,
        )
        .await;
        assert!(wrong.is_err());
        assert!(
            !invoked.exists(),
            "digest refusal must precede any worker process"
        );
        let receipt = launch_channel_inner(
            package.to_str().unwrap(),
            &authority,
            &selected.sha256,
            &upload,
            &helper,
        )
        .await
        .unwrap();
        assert_eq!(receipt["state"], "scheduled");
        assert_eq!(receipt["boot_verified"], false);
        let status = journal
            .join(receipt["job_id"].as_str().unwrap())
            .join("status.json");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let value: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&status).unwrap()).unwrap();
            if value["state"] == "command_completed" {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "actual fixture worker did not finish: {value}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let observed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(marker).unwrap()).unwrap();
        assert_eq!(observed["sha256"], selected.sha256);
        assert_eq!(observed["job"], receipt["job_id"]);
        assert!(
            package.exists(),
            "worker owns an independent reservation, so failed apply can be retried deliberately"
        );
        std::fs::remove_file(&invoked).unwrap();
        std::fs::write(&package, b"changed after successful verification").unwrap();
        assert!(launch_channel_inner(
            package.to_str().unwrap(),
            &authority,
            &selected.sha256,
            &upload,
            &helper
        )
        .await
        .is_err());
        assert!(!invoked.exists());
    }

    #[test]
    fn launch_receipt_must_bind_the_reserved_package_to_this_job_and_boot() {
        let package = "d".repeat(64);
        let receipt = serde_json::json!({"schema":1,"job_id":AFTER,"package_sha256":package,
            "source_boot_id":BEFORE,"state":"scheduled","boot_verified":false});
        assert!(valid_launch_receipt(&receipt, AFTER, &package, BEFORE));
        for key in [
            "schema",
            "job_id",
            "package_sha256",
            "source_boot_id",
            "state",
            "boot_verified",
        ] {
            let mut altered = receipt.clone();
            altered[key] = serde_json::Value::Null;
            assert!(
                !valid_launch_receipt(&altered, AFTER, &package, BEFORE),
                "{key}"
            );
        }
        assert!(!valid_launch_receipt(&receipt, BEFORE, &package, BEFORE));
        assert!(!valid_launch_receipt(
            &receipt,
            AFTER,
            &"e".repeat(64),
            BEFORE
        ));
        assert!(!valid_launch_receipt(&receipt, AFTER, &package, AFTER));
    }

    fn observed_fixture() -> (serde_json::Value, serde_json::Value) {
        let job = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        let package = "d".repeat(64);
        (
            serde_json::json!({"job_id":job,"package_sha256":package,"source_boot_id":BEFORE,"state":"running","boot_verified":false}),
            serde_json::json!({"schema":"dcentos.am2-native-boot-commit-observation.v1","job_id":job,"package_sha256":package,
            "source_boot_id":BEFORE,"observed_boot_id":AFTER,"native_transaction":"e".repeat(64),
            "receipt_sha256":"f".repeat(64),"firmware":2,"boot_environment_committed":true,"physical_hashing_verified":false}),
        )
    }

    #[test]
    fn exact_new_boot_observation_completes_copied_worker_without_claiming_hashing() {
        let (mut record, observation) = observed_fixture();
        reconcile_boot(&mut record, Some(AFTER));
        reconcile_observation(&mut record, &observation, Some(AFTER));
        assert_eq!(record["state"], "boot_committed");
        assert_eq!(record["boot_verified"], true);
        assert_eq!(record["physical_hashing_verified"], false);
        assert_eq!(record["worker_running"], false);
    }

    #[test]
    fn unrelated_or_stale_boot_observations_never_promote_worker_results() {
        for key in [
            "job_id",
            "package_sha256",
            "source_boot_id",
            "observed_boot_id",
            "native_transaction",
            "receipt_sha256",
            "schema",
        ] {
            let (mut record, mut observation) = observed_fixture();
            observation[key] = "foreign".into();
            reconcile_observation(&mut record, &observation, Some(AFTER));
            assert_eq!(record["boot_verified"], false, "{key}");
            assert_eq!(record["state"], "running", "{key}");
        }
        let (mut record, observation) = observed_fixture();
        reconcile_observation(&mut record, &observation, Some(BEFORE));
        reconcile_observation(&mut record, &observation, None);
        assert_eq!(record["boot_verified"], false);
    }

    #[test]
    fn copied_running_journal_cannot_claim_current_worker_after_boot_change() {
        let mut record = serde_json::json!({"state":"running","source_boot_id":BEFORE,"worker_pid":42,"boot_verified":false});
        reconcile_boot(&mut record, Some(AFTER));
        assert_eq!(record["state"], "previous_boot_result_unconfirmed");
        assert_eq!(record["saved_worker_state"], "running");
        assert_eq!(record["worker_running"], false);
        assert_eq!(record["boot_verified"], false);
    }

    #[test]
    fn same_boot_and_recorded_command_result_are_preserved() {
        let mut pending =
            serde_json::json!({"state":"running","source_boot_id":BEFORE,"boot_verified":false});
        reconcile_boot(&mut pending, Some(BEFORE));
        assert_eq!(pending["state"], "running");
        assert_eq!(pending["boot_changed"], false);
        for state in ["command_completed", "command_failed", "worker_failed"] {
            let mut record =
                serde_json::json!({"state":state,"source_boot_id":BEFORE,"boot_verified":false});
            reconcile_boot(&mut record, Some(AFTER));
            assert_eq!(record["state"], state);
            assert_eq!(record["boot_verified"], false);
        }
    }

    #[test]
    fn legacy_or_unreadable_boot_identity_does_not_claim_active_worker() {
        for source in [
            serde_json::Value::Null,
            serde_json::json!("invalid"),
            serde_json::json!(BEFORE),
        ] {
            let mut record = serde_json::json!({"state":"scheduled","source_boot_id":source,"boot_verified":false});
            reconcile_boot(&mut record, None);
            assert_eq!(record["state"], "worker_boot_unknown");
            assert_eq!(record["boot_verified"], false);
        }
    }
}
