//! Crash-durability integration proof for the mutation-disposition journal.
//!
//! Technique: the proven fabric-lease subprocess + SIGKILL pattern
//! (`dcentrald-fabric-lease/src/lib.rs` tests) against the real kernel. A
//! subprocess journals a Quarantined disposition for a fabric and is
//! SIGKILLed with no cleanup (modeling `panic=abort` / power-cut after the
//! controlled-teardown journal write). A FRESH process's adjudication must
//! return Unresolved and the admission gate must return a TYPED refusal
//! until an explicit resolution (typed SafeOff receipts, then durable clear)
//! is written. Fail-closed is the whole point: no path in this file lets a
//! journal problem admit hardware.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use dcentrald_common::mutation_disposition::{
    admit_hardware_after_mutation_adjudication, clear_mutation_disposition,
    load_and_adjudicate_mutation_disposition, load_and_adjudicate_mutation_disposition_for_slot,
    persist_mutation_disposition, MutationDispositionEntry, MutationDispositionRecord,
    MutationEndpointClass, MutationEntryDisposition, MutationQuarantineReason,
    MutationSessionReason, MutationUnresolvedReason, TypedSafeOffReceipt,
};
use dcentrald_hal::i2c::{
    snapshot_i2c_fabric_dispositions, I2cFabricDispositionSnapshot, I2cFabricDispositionState,
    I2cFabricEndpointClass, I2cFabricQuarantineDisposition,
};

const CHILD_JOURNAL: &str = "DCENT_MUTATION_JOURNAL_CHILD_PATH";
const CHILD_READY: &str = "DCENT_MUTATION_JOURNAL_CHILD_READY";
const CHILD_BOOT: &str = "DCENT_MUTATION_JOURNAL_CHILD_BOOT_ID";

/// Mirror of the daemon's HAL-snapshot → journal-entry projection: only
/// Mutated/Quarantined dispositions are journaled and no SafeOff receipt is
/// ever auto-minted (process state is not rail-cut evidence).
fn journal_entry_from_hal_shape(
    snapshot: &I2cFabricDispositionSnapshot,
) -> Option<MutationDispositionEntry> {
    let disposition = match snapshot.disposition {
        I2cFabricDispositionState::Clean | I2cFabricDispositionState::Active => return None,
        I2cFabricDispositionState::Mutated => MutationEntryDisposition::Mutated,
        I2cFabricDispositionState::Quarantined(reason) => {
            MutationEntryDisposition::Quarantined(match reason {
                I2cFabricQuarantineDisposition::PreparationAborted => {
                    MutationQuarantineReason::PreparationAborted
                }
                I2cFabricQuarantineDisposition::WorkerPanicked => {
                    MutationQuarantineReason::WorkerPanicked
                }
                I2cFabricQuarantineDisposition::UnresolvedPic16State => {
                    MutationQuarantineReason::UnresolvedPic16State
                }
                I2cFabricQuarantineDisposition::UnresolvedClassicAmlPicState => {
                    MutationQuarantineReason::UnresolvedClassicAmlPicState
                }
                I2cFabricQuarantineDisposition::UnexpectedLeaseDrop => {
                    MutationQuarantineReason::UnexpectedLeaseDrop
                }
                I2cFabricQuarantineDisposition::RegistryInvariantLost => {
                    MutationQuarantineReason::RegistryInvariantLost
                }
            })
        }
    };
    Some(MutationDispositionEntry {
        fabric_key: snapshot.fabric_key.clone(),
        allocation_id: snapshot.allocation_id,
        endpoint_class: match snapshot.endpoint_class {
            I2cFabricEndpointClass::RuntimeService => MutationEndpointClass::RuntimeService,
            I2cFabricEndpointClass::RawLease => MutationEndpointClass::RawLease,
        },
        disposition,
        safe_off_receipt: None,
    })
}

/// The HAL-shaped quarantine disposition the crashed owner journals.
fn quarantined_hal_snapshot() -> I2cFabricDispositionSnapshot {
    I2cFabricDispositionSnapshot {
        fabric_key: "linux-adapter-0".to_string(),
        allocation_id: 41,
        endpoint_class: I2cFabricEndpointClass::RuntimeService,
        disposition: I2cFabricDispositionState::Quarantined(
            I2cFabricQuarantineDisposition::WorkerPanicked,
        ),
    }
}

const CRASH_SLOT: &str = "firmware-crash-test";

fn crashed_owner_record(boot_id: &str) -> MutationDispositionRecord {
    let entry = journal_entry_from_hal_shape(&quarantined_hal_snapshot())
        .expect("a quarantined disposition must be journaled");
    MutationDispositionRecord {
        boot_id: boot_id.to_string(),
        image_version: "crash-test".to_string(),
        platform: "zynq-bm3-am2".to_string(),
        slot_identity: CRASH_SLOT.to_string(),
        session_reason: MutationSessionReason::UnresolvedFabricQuarantine,
        recorded_unix_s: 1_800_000_000,
        entries: vec![entry],
    }
}

fn load_crash_journal(
    path: &Path,
    boot_id: &str,
) -> dcentrald_common::mutation_disposition::MutationDispositionAdjudication {
    load_and_adjudicate_mutation_disposition_for_slot(path, boot_id, CRASH_SLOT)
}

#[test]
fn sigkilled_owner_leaves_unresolved_journal_and_typed_refusal_until_resolution() {
    // ---- CHILD BRANCH (re-exec'd by the parent below) ----
    if let (Ok(journal), Ok(ready), Ok(boot)) = (
        std::env::var(CHILD_JOURNAL),
        std::env::var(CHILD_READY),
        std::env::var(CHILD_BOOT),
    ) {
        let record = crashed_owner_record(&boot);
        persist_mutation_disposition(Path::new(&journal), &record)
            .expect("child journals the quarantined disposition");
        std::fs::write(&ready, b"ready").expect("publish child readiness");
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    // ---- PARENT ----
    let dir = std::env::temp_dir().join(format!(
        "dcent-mutation-crash-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let journal = dir.join("mutation-disposition-v1");
    let ready = dir.join("child-ready");
    let boot_this = "crash-test-boot-a";

    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("sigkilled_owner_leaves_unresolved_journal_and_typed_refusal_until_resolution")
        .arg("--nocapture")
        .env(CHILD_JOURNAL, &journal)
        .env(CHILD_READY, &ready)
        .env(CHILD_BOOT, boot_this)
        .spawn()
        .expect("spawn journal-owning child");

    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.is_file() && Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("journal-owning child exited before readiness: {status}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(ready.is_file(), "journal-owning child did not become ready");

    // SIGKILL: no Drop, no unwind, no teardown — the crash the durable
    // journal exists to survive.
    child.kill().expect("SIGKILL journal owner");
    child.wait().expect("reap journal owner");

    // A FRESH process context (this parent never wrote the journal) must see
    // Unresolved and receive a typed admission refusal.
    let adjudication = load_crash_journal(&journal, boot_this);
    let record = adjudication
        .unresolved_record()
        .expect("expected Unresolved after SIGKILL");
    let reasons = adjudication
        .unresolved_reasons()
        .expect("unresolved reasons after SIGKILL");
    assert_eq!(record.entries.len(), 1);
    assert_eq!(
        reasons,
        [MutationUnresolvedReason::EntryWithoutSafeOffReceipt {
            fabric_key: "linux-adapter-0".to_string(),
        }]
    );
    let refusal = admit_hardware_after_mutation_adjudication(&adjudication)
        .expect_err("admission-construction for the quarantined fabric must be refused");
    let refusal_text = refusal.to_string();
    assert!(
        refusal_text.contains("linux-adapter-0"),
        "typed refusal must name the fabric: {refusal_text}"
    );

    // A reboot (different boot id) must NOT auto-clear the prior boot's
    // unresolved mutation.
    let after_reboot = load_crash_journal(&journal, "crash-test-boot-b");
    let reasons = after_reboot
        .unresolved_reasons()
        .expect("expected Unresolved across reboot");
    assert!(reasons.contains(&MutationUnresolvedReason::ForeignBootId {
        recorded_boot_id: boot_this.to_string(),
    }));
    assert!(admit_hardware_after_mutation_adjudication(&after_reboot).is_err());

    // Explicit resolution: an operator writes typed SafeOff receipts for
    // every non-Clean entry. Only then does the same-boot adjudication
    // resolve and admit.
    let mut resolved = crashed_owner_record(boot_this);
    for entry in &mut resolved.entries {
        entry.safe_off_receipt = Some(TypedSafeOffReceipt::OperatorCleared {
            observed_unix_s: 1_800_000_500,
        });
    }
    persist_mutation_disposition(&journal, &resolved).expect("write explicit resolution record");
    let adjudication = load_crash_journal(&journal, boot_this);
    assert!(adjudication.is_resolved() && adjudication.resolved_record().is_some());
    let admission = admit_hardware_after_mutation_adjudication(&adjudication)
        .expect("typed SafeOff receipts are the explicit resolution that admits");

    // Accepted resolution is then durably cleared; absence resolves clean.
    clear_mutation_disposition(
        admission
            .into_clearance()
            .expect("loaded resolved journal carries exact-path clearance"),
    )
    .expect("durable clear after explicit resolution");
    let absent = load_and_adjudicate_mutation_disposition(&journal, boot_this);
    assert!(absent.is_resolved() && absent.resolved_record().is_none());

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn corrupted_journal_after_crash_is_unreadable_refusal_never_admission() {
    let dir = std::env::temp_dir().join(format!(
        "dcent-mutation-corrupt-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let journal = dir.join("mutation-disposition-v1");

    // A torn/corrupted journal (e.g. power loss mid-publication on a broken
    // filesystem) must refuse, never read as absent.
    std::fs::write(&journal, b"DCENT_MUTATION_DISPOSITION_V1|torn").unwrap();
    let adjudication = load_and_adjudicate_mutation_disposition(&journal, "any-boot");
    assert!(adjudication.unreadable_detail().is_some());
    assert!(admit_hardware_after_mutation_adjudication(&adjudication).is_err());

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn hal_snapshot_is_readonly_deterministic_and_journal_token_shaped() {
    let snapshot = snapshot_i2c_fabric_dispositions();
    for entry in &snapshot {
        assert!(!entry.fabric_key.is_empty());
        assert!(
            entry
                .fabric_key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':')),
            "fabric key must already be journal-token shaped: {}",
            entry.fabric_key
        );
    }
    // Read-only: a second snapshot observes identical state.
    assert_eq!(snapshot, snapshot_i2c_fabric_dispositions());

    // The daemon-side projection filters live/clean states and journals the
    // dangerous ones without ever minting a SafeOff receipt.
    assert!(journal_entry_from_hal_shape(&I2cFabricDispositionSnapshot {
        disposition: I2cFabricDispositionState::Clean,
        ..quarantined_hal_snapshot()
    })
    .is_none());
    assert!(journal_entry_from_hal_shape(&I2cFabricDispositionSnapshot {
        disposition: I2cFabricDispositionState::Active,
        ..quarantined_hal_snapshot()
    })
    .is_none());
    let mutated = journal_entry_from_hal_shape(&I2cFabricDispositionSnapshot {
        disposition: I2cFabricDispositionState::Mutated,
        ..quarantined_hal_snapshot()
    })
    .expect("mutated must be journaled");
    assert_eq!(mutated.disposition, MutationEntryDisposition::Mutated);
    assert!(mutated.safe_off_receipt.is_none());
    assert!(mutated.blocks_admission());
}
