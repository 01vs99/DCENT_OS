//! Durable, typed, fail-closed hardware MUTATION-DISPOSITION JOURNAL.
//!
//! The HAL's rich quarantine states (worker panic, unresolved PIC16 state,
//! mutated-during-preparation, unexpected lease drop, registry invariant loss)
//! live in a process-local registry and evaporate on `panic=abort`, SIGKILL,
//! or power loss. This module is the durable half named by
//! `CONTROLLER_RECOVERY_AUTHORITY.md`: a boot/platform/fabric/allocation-bound
//! mutation-disposition journal with typed SafeOff receipts.
//!
//! Contract (mirrors [`crate::thermal_lockout`]):
//! - versioned prefix `DCENT_MUTATION_DISPOSITION_V2`, bounded size, strict
//!   decode: truncated / oversized / wrong-version / malformed records are
//!   errors, never "absent". Predecessor `V1` records are Unreadable, not
//!   silently upgraded (do not tighten a published predecessor schema in place).
//! - Header carries slot/image identity plus a session-reason enum
//!   (`expected-zero-awaiting-typed-disposition` vs `safeoff-failed`).
//! - [`persist_mutation_disposition`] is an atomic temp+fsync+rename write and
//!   returns every IO error (fail-closed, never swallowed).
//! - Production persist always writes `safe_off_receipt: None`.
//!   [`TypedSafeOffReceipt::VerifiedRailCut`] is test-only and is never minted
//!   from software SafeOff. Operator clearance remains
//!   [`TypedSafeOffReceipt::OperatorCleared`].
//! - [`load_and_adjudicate_mutation_disposition`] resolves ONLY when the file
//!   is absent, or when a same-boot **and same-slot** record's every entry is
//!   `Clean` or every non-`Clean` entry carries a typed SafeOff receipt. A
//!   foreign `boot_id` or `slot_identity` is `Unresolved` (a prior boot/slot's
//!   unresolved mutation), NOT auto-cleared. Any read/parse problem is
//!   `Unreadable` and refuses admission.
//! - [`clear_mutation_disposition`] removes the record and is callable ONLY
//!   after an explicit resolution (operator clearance or a typed SafeOff
//!   resolution record) — mirror of `remove_thermal_lockout`.
//!
//! SAFETY BOUNDARY: a Resolved journal is NOT a typed SafeOff receipt for the
//! rails, never authorizes skipping the supervisor session latch
//! (`dcentrald-session-latch.sh`), and never re-enables automatic daemon
//! restart (`restart.rs::schedule_daemon_restart` keeps returning `false`).
//! Sysupgrade admit is a latch-reason split, not `VerifiedRailCut`.

use crate::atomic_file::{
    atomic_write, remove_file, AtomicRemoveError, AtomicRemoveOutcome, AtomicWriteError,
    AtomicWriteOptions, AtomicWriteOutcome,
};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

const RECORD_PREFIX: &str = "DCENT_MUTATION_DISPOSITION_V2";
/// Predecessor schema. Decoding it is [`MutationDispositionParseError::UnsupportedVersion`],
/// never a silent upgrade.
const RECORD_PREFIX_V1: &str = "DCENT_MUTATION_DISPOSITION_V1";
const RECORD_FOOTER: &str = "DCENT_MUTATION_DISPOSITION_END";
const ENTRY_TAG: &str = "E";
/// Env override for [`current_slot_image_identity`]. Supervisor/export only.
const SLOT_IDENTITY_ENV: &str = "DCENT_SLOT_IDENTITY";
const SLOT_IDENTITY_BOOTSLOT_ENV: &str = "DCENT_BOOTSLOT";
const SLOT_IDENTITY_FIRMWARE_ENV: &str = "DCENT_FIRMWARE_SLOT";
const SLOT_IDENTITY_UNAME_ENV: &str = "DCENT_UNAME_PLACEHOLDER";
/// Env override for [`MutationSessionReason::from_env`].
const SESSION_REASON_ENV: &str = "DCENT_MUTATION_SESSION_REASON";

/// Hard byte bound for the whole encoded record (mirrors the bounded
/// thermal-lockout record; a journal is a small tombstone, not a log).
pub const MUTATION_DISPOSITION_MAX_BYTES: usize = 8192;
/// Hard entry bound. More simultaneous quarantined fabrics than this is
/// itself an unresolved condition; encode refuses rather than truncates.
pub const MUTATION_DISPOSITION_MAX_ENTRIES: usize = 64;
/// Bound for every free-text token (boot id, image version, platform,
/// fabric key). Linux boot ids are 36 bytes.
pub const MUTATION_DISPOSITION_MAX_TOKEN_LEN: usize = 96;

/// Why a fabric entry is quarantined. Mirrors the HAL's process-local
/// `I2cServiceQuarantineReason` roster; decoding an unknown reason is a parse
/// error (=> `Unreadable` => refuse), never a silent downgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationQuarantineReason {
    PreparationAborted,
    WorkerPanicked,
    UnresolvedPic16State,
    UnresolvedClassicAmlPicState,
    UnexpectedLeaseDrop,
    RegistryInvariantLost,
}

impl MutationQuarantineReason {
    fn encode(self) -> &'static str {
        match self {
            Self::PreparationAborted => "preparation-aborted",
            Self::WorkerPanicked => "worker-panicked",
            Self::UnresolvedPic16State => "unresolved-pic16-state",
            Self::UnresolvedClassicAmlPicState => "unresolved-classic-aml-pic-state",
            Self::UnexpectedLeaseDrop => "unexpected-lease-drop",
            Self::RegistryInvariantLost => "registry-invariant-lost",
        }
    }

    fn decode(value: &str) -> Result<Self, MutationDispositionParseError> {
        match value {
            "preparation-aborted" => Ok(Self::PreparationAborted),
            "worker-panicked" => Ok(Self::WorkerPanicked),
            "unresolved-pic16-state" => Ok(Self::UnresolvedPic16State),
            "unresolved-classic-aml-pic-state" => Ok(Self::UnresolvedClassicAmlPicState),
            "unexpected-lease-drop" => Ok(Self::UnexpectedLeaseDrop),
            "registry-invariant-lost" => Ok(Self::RegistryInvariantLost),
            _ => Err(MutationDispositionParseError::InvalidQuarantineReason),
        }
    }
}

/// Which kind of process-local fabric owner produced the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationEndpointClass {
    RuntimeService,
    RawLease,
}

impl MutationEndpointClass {
    fn encode(self) -> &'static str {
        match self {
            Self::RuntimeService => "runtime-service",
            Self::RawLease => "raw-lease",
        }
    }

    fn decode(value: &str) -> Result<Self, MutationDispositionParseError> {
        match value {
            "runtime-service" => Ok(Self::RuntimeService),
            "raw-lease" => Ok(Self::RawLease),
            _ => Err(MutationDispositionParseError::InvalidEndpointClass),
        }
    }
}

/// Why this journal record was written. Mirrors the supervisor latch reason
/// split (`expected-zero-awaiting-typed-disposition` may sysupgrade;
/// `safeoff-failed` must not). This is **not** a rail-cut receipt and never
/// authorizes `S82 start` or automatic restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationSessionReason {
    /// Clean / expected-zero stop after software SafeOff. Sysupgrade admit
    /// may proceed; start stays latched. Not `VerifiedRailCut`.
    ExpectedZeroAwaitingTypedDisposition,
    /// Software SafeOff failed or was not confirmed. Update window stays
    /// refused. Not `VerifiedRailCut`.
    SafeOffFailed,
    /// HAL fabric still Mutated/Quarantined at controlled teardown. Default
    /// when the persist site cannot distinguish the two latch reasons.
    UnresolvedFabricQuarantine,
}

impl MutationSessionReason {
    pub const fn encode(self) -> &'static str {
        match self {
            Self::ExpectedZeroAwaitingTypedDisposition => {
                "expected-zero-awaiting-typed-disposition"
            }
            Self::SafeOffFailed => "safeoff-failed",
            Self::UnresolvedFabricQuarantine => "unresolved-fabric-quarantine",
        }
    }

    fn decode(value: &str) -> Result<Self, MutationDispositionParseError> {
        match value {
            "expected-zero-awaiting-typed-disposition" => {
                Ok(Self::ExpectedZeroAwaitingTypedDisposition)
            }
            "safeoff-failed" => Ok(Self::SafeOffFailed),
            "unresolved-fabric-quarantine" => Ok(Self::UnresolvedFabricQuarantine),
            _ => Err(MutationDispositionParseError::InvalidSessionReason),
        }
    }

    /// Supervisor/export override. Unknown or absent env is
    /// [`Self::UnresolvedFabricQuarantine`] (never a silent expected-zero).
    pub fn from_env() -> Self {
        match std::env::var(SESSION_REASON_ENV).as_deref().map(str::trim) {
            Ok("expected-zero-awaiting-typed-disposition") => {
                Self::ExpectedZeroAwaitingTypedDisposition
            }
            Ok("safeoff-failed") => Self::SafeOffFailed,
            Ok("unresolved-fabric-quarantine") => Self::UnresolvedFabricQuarantine,
            _ => Self::UnresolvedFabricQuarantine,
        }
    }
}

/// Final disposition of one fabric/allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationEntryDisposition {
    Clean,
    Mutated,
    Quarantined(MutationQuarantineReason),
}

impl MutationEntryDisposition {
    /// True for every disposition that needs a typed SafeOff receipt (or an
    /// operator clearance) before hardware admission may proceed.
    pub const fn requires_safe_off_receipt(self) -> bool {
        !matches!(self, Self::Clean)
    }

    fn encode(self) -> String {
        match self {
            Self::Clean => "clean".to_string(),
            Self::Mutated => "mutated".to_string(),
            Self::Quarantined(reason) => format!("quarantined:{}", reason.encode()),
        }
    }

    fn decode(value: &str) -> Result<Self, MutationDispositionParseError> {
        match value {
            "clean" => Ok(Self::Clean),
            "mutated" => Ok(Self::Mutated),
            _ => value
                .strip_prefix("quarantined:")
                .ok_or(MutationDispositionParseError::InvalidDisposition)
                .and_then(MutationQuarantineReason::decode)
                .map(Self::Quarantined),
        }
    }
}

/// Typed evidence that the hardware behind a non-Clean entry has been made
/// safe. Process exit, a clean journal, and lease release are explicitly NOT
/// receipts — only a checked rail cut or a deliberate operator clearance is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedSafeOffReceipt {
    /// An operator deliberately verified/AC-cycled the unit and cleared the
    /// entry (the interim manual resolution path). Production resolution.
    OperatorCleared { observed_unix_s: u64 },
    /// A checked, readback-verified rail cut receipt was produced by the
    /// closeout machinery for this fabric.
    ///
    /// TEST-ONLY: production persist never writes this variant. Software
    /// SafeOff is not a rail proof and must not stamp `VerifiedRailCut`.
    VerifiedRailCut { observed_unix_s: u64 },
}

impl TypedSafeOffReceipt {
    fn encode(self) -> String {
        match self {
            Self::OperatorCleared { observed_unix_s } => {
                format!("safe-off:operator-cleared:{observed_unix_s}")
            }
            Self::VerifiedRailCut { observed_unix_s } => {
                format!("safe-off:verified-rail-cut:{observed_unix_s}")
            }
        }
    }

    fn decode(value: &str) -> Result<Self, MutationDispositionParseError> {
        let body = value
            .strip_prefix("safe-off:")
            .ok_or(MutationDispositionParseError::InvalidSafeOffReceipt)?;
        let (kind, unix_s) = body
            .rsplit_once(':')
            .ok_or(MutationDispositionParseError::InvalidSafeOffReceipt)?;
        let observed_unix_s = unix_s
            .parse::<u64>()
            .map_err(|_| MutationDispositionParseError::InvalidNumber)?;
        match kind {
            "operator-cleared" => Ok(Self::OperatorCleared { observed_unix_s }),
            "verified-rail-cut" => Ok(Self::VerifiedRailCut { observed_unix_s }),
            _ => Err(MutationDispositionParseError::InvalidSafeOffReceipt),
        }
    }
}

/// One fabric/allocation-bound disposition entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationDispositionEntry {
    /// Stable textual fabric identity (for example `linux-adapter-0`).
    pub fabric_key: String,
    /// Process-local allocation counter at the time the disposition was
    /// captured (diagnostic binding, not an authority).
    pub allocation_id: u64,
    pub endpoint_class: MutationEndpointClass,
    pub disposition: MutationEntryDisposition,
    pub safe_off_receipt: Option<TypedSafeOffReceipt>,
}

impl MutationDispositionEntry {
    /// True when this entry blocks hardware admission: a non-Clean
    /// disposition with no typed SafeOff receipt.
    pub fn blocks_admission(&self) -> bool {
        self.disposition.requires_safe_off_receipt() && self.safe_off_receipt.is_none()
    }

    fn encode(&self) -> Result<String, MutationDispositionEncodeError> {
        if !valid_token(&self.fabric_key) {
            return Err(MutationDispositionEncodeError::InvalidToken {
                field: "fabric_key",
            });
        }
        let receipt = match self.safe_off_receipt {
            None => "none".to_string(),
            Some(receipt) => receipt.encode(),
        };
        Ok(format!(
            "{ENTRY_TAG}|{}|{}|{}|{}|{receipt}\n",
            self.fabric_key,
            self.allocation_id,
            self.endpoint_class.encode(),
            self.disposition.encode(),
        ))
    }

    fn decode(line: &str) -> Result<Self, MutationDispositionParseError> {
        let mut fields = line.split('|');
        if fields.next() != Some(ENTRY_TAG) {
            return Err(MutationDispositionParseError::InvalidEntryTag);
        }
        let fabric_key = token_field(fields.next())?;
        let allocation_id = parse_field::<u64>(fields.next())?;
        let endpoint_class = MutationEndpointClass::decode(
            fields
                .next()
                .ok_or(MutationDispositionParseError::MissingField)?,
        )?;
        let disposition = MutationEntryDisposition::decode(
            fields
                .next()
                .ok_or(MutationDispositionParseError::MissingField)?,
        )?;
        let safe_off_receipt = match fields
            .next()
            .ok_or(MutationDispositionParseError::MissingField)?
        {
            "none" => None,
            value => Some(TypedSafeOffReceipt::decode(value)?),
        };
        if fields.next().is_some() {
            return Err(MutationDispositionParseError::ExtraField);
        }
        Ok(Self {
            fabric_key,
            allocation_id,
            endpoint_class,
            disposition,
            safe_off_receipt,
        })
    }
}

/// The full boot/image/platform/slot-bound journal record (schema v2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationDispositionRecord {
    /// The writing boot's kernel boot id (or a deliberate sentinel token).
    /// A record whose boot id does not match the adjudicating boot is a prior
    /// boot's unresolved mutation and never auto-clears.
    pub boot_id: String,
    pub image_version: String,
    pub platform: String,
    /// Slot/image identity (U-Boot `firmware`/`bootslot`, supervisor export,
    /// or an uname placeholder). A foreign slot is unresolved: the other A/B
    /// image's `/data` must not admit this image's hardware.
    pub slot_identity: String,
    /// Latch-aligned session reason. Never a rail-cut receipt.
    pub session_reason: MutationSessionReason,
    pub recorded_unix_s: u64,
    pub entries: Vec<MutationDispositionEntry>,
}

impl MutationDispositionRecord {
    pub fn encode(&self) -> Result<String, MutationDispositionEncodeError> {
        if !valid_token(&self.boot_id) {
            return Err(MutationDispositionEncodeError::InvalidToken { field: "boot_id" });
        }
        if !valid_token(&self.image_version) {
            return Err(MutationDispositionEncodeError::InvalidToken {
                field: "image_version",
            });
        }
        if !valid_token(&self.platform) {
            return Err(MutationDispositionEncodeError::InvalidToken { field: "platform" });
        }
        if !valid_token(&self.slot_identity) {
            return Err(MutationDispositionEncodeError::InvalidToken {
                field: "slot_identity",
            });
        }
        if self.entries.len() > MUTATION_DISPOSITION_MAX_ENTRIES {
            return Err(MutationDispositionEncodeError::TooManyEntries {
                count: self.entries.len(),
            });
        }
        let mut encoded = format!(
            "{RECORD_PREFIX}|{}|{}|{}|{}|{}|{}|{}\n",
            self.boot_id,
            self.image_version,
            self.platform,
            self.slot_identity,
            self.session_reason.encode(),
            self.recorded_unix_s,
            self.entries.len(),
        );
        for entry in &self.entries {
            encoded.push_str(&entry.encode()?);
        }
        encoded.push_str(RECORD_FOOTER);
        encoded.push('\n');
        if encoded.len() > MUTATION_DISPOSITION_MAX_BYTES {
            return Err(MutationDispositionEncodeError::Oversize {
                bytes: encoded.len(),
            });
        }
        Ok(encoded)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MutationDispositionParseError> {
        if bytes.is_empty() || bytes.len() > MUTATION_DISPOSITION_MAX_BYTES {
            return Err(MutationDispositionParseError::InvalidLength);
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| MutationDispositionParseError::InvalidEncoding)?;
        let text = text
            .strip_suffix('\n')
            .ok_or(MutationDispositionParseError::MissingTerminator)?;
        if text.contains('\r') {
            return Err(MutationDispositionParseError::UnexpectedWhitespace);
        }
        let mut lines = text.split('\n');
        let header = lines
            .next()
            .ok_or(MutationDispositionParseError::MissingField)?;
        let mut fields = header.split('|');
        match fields.next() {
            Some(RECORD_PREFIX) => {}
            Some(prefix) if prefix == RECORD_PREFIX_V1 => {
                return Err(MutationDispositionParseError::UnsupportedVersion);
            }
            _ => return Err(MutationDispositionParseError::UnsupportedVersion),
        }
        let boot_id = token_field(fields.next())?;
        let image_version = token_field(fields.next())?;
        let platform = token_field(fields.next())?;
        let slot_identity = token_field(fields.next())?;
        let session_reason = MutationSessionReason::decode(
            fields
                .next()
                .ok_or(MutationDispositionParseError::MissingField)?,
        )?;
        let recorded_unix_s = parse_field::<u64>(fields.next())?;
        let entry_count = parse_field::<usize>(fields.next())?;
        if fields.next().is_some() {
            return Err(MutationDispositionParseError::ExtraField);
        }
        if entry_count > MUTATION_DISPOSITION_MAX_ENTRIES {
            return Err(MutationDispositionParseError::TooManyEntries);
        }
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let line = lines
                .next()
                .ok_or(MutationDispositionParseError::TruncatedEntries)?;
            entries.push(MutationDispositionEntry::decode(line)?);
        }
        if lines.next() != Some(RECORD_FOOTER) {
            return Err(MutationDispositionParseError::MissingFooter);
        }
        if lines.next().is_some() {
            return Err(MutationDispositionParseError::ExtraField);
        }
        Ok(Self {
            boot_id,
            image_version,
            platform,
            slot_identity,
            session_reason,
            recorded_unix_s,
            entries,
        })
    }
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MUTATION_DISPOSITION_MAX_TOKEN_LEN
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}

/// Reduce an arbitrary string to a journal-safe token: disallowed characters
/// become `-`, over-length input is truncated, and an empty result becomes
/// `"unknown"`. Deliberately lossy — callers must not treat the sanitized
/// value as a reversible identity.
pub fn sanitize_journal_token(value: &str) -> String {
    let mut token: String = value
        .chars()
        .take(MUTATION_DISPOSITION_MAX_TOKEN_LEN)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':') {
                c
            } else {
                '-'
            }
        })
        .collect();
    if token.is_empty() {
        token.push_str("unknown");
    }
    token
}

/// Slot/image identity for journal v2. Prefers supervisor-exported env
/// (`DCENT_SLOT_IDENTITY`, then `DCENT_BOOTSLOT` / `DCENT_FIRMWARE_SLOT`),
/// then `DCENT_UNAME_PLACEHOLDER` / `HOSTNAME`, then a compile-time
/// `uname` placeholder (`slot-unknown:{arch}-{os}`). Does **not** invoke
/// `fw_printenv` or write U-Boot env (that is the overlay `fw_setenv --script`
/// helper). Never invents a live slot by reading mtd4.
pub fn current_slot_image_identity() -> String {
    for key in [
        SLOT_IDENTITY_ENV,
        SLOT_IDENTITY_BOOTSLOT_ENV,
        SLOT_IDENTITY_FIRMWARE_ENV,
    ] {
        if let Ok(value) = std::env::var(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return sanitize_journal_token(trimmed);
            }
        }
    }
    let uname = std::env::var(SLOT_IDENTITY_UNAME_ENV)
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS));
    sanitize_journal_token(&format!("slot-unknown:{uname}"))
}

fn token_field(field: Option<&str>) -> Result<String, MutationDispositionParseError> {
    let value = field.ok_or(MutationDispositionParseError::MissingField)?;
    if !valid_token(value) {
        return Err(MutationDispositionParseError::InvalidToken);
    }
    Ok(value.to_string())
}

fn parse_field<T: std::str::FromStr>(
    field: Option<&str>,
) -> Result<T, MutationDispositionParseError> {
    field
        .ok_or(MutationDispositionParseError::MissingField)?
        .parse::<T>()
        .map_err(|_| MutationDispositionParseError::InvalidNumber)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationDispositionParseError {
    InvalidLength,
    InvalidEncoding,
    MissingTerminator,
    UnexpectedWhitespace,
    UnsupportedVersion,
    MissingField,
    ExtraField,
    InvalidNumber,
    InvalidToken,
    InvalidEntryTag,
    InvalidEndpointClass,
    InvalidDisposition,
    InvalidQuarantineReason,
    InvalidSessionReason,
    InvalidSafeOffReceipt,
    TooManyEntries,
    TruncatedEntries,
    MissingFooter,
}

impl fmt::Display for MutationDispositionParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid mutation-disposition record: {self:?}")
    }
}

impl std::error::Error for MutationDispositionParseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationDispositionEncodeError {
    InvalidToken { field: &'static str },
    TooManyEntries { count: usize },
    Oversize { bytes: usize },
}

impl fmt::Display for MutationDispositionEncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "mutation-disposition record cannot be encoded: {self:?}"
        )
    }
}

impl std::error::Error for MutationDispositionEncodeError {}

/// Persist failure: either the record itself is unencodable or the atomic
/// durable write failed. Both are returned, never swallowed.
#[derive(Debug)]
pub enum MutationDispositionPersistError {
    Encode(MutationDispositionEncodeError),
    Write(AtomicWriteError),
}

impl fmt::Display for MutationDispositionPersistError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(error) => write!(formatter, "{error}"),
            Self::Write(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for MutationDispositionPersistError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encode(error) => Some(error),
            Self::Write(error) => Some(error),
        }
    }
}

/// Atomically (temp + fsync + rename + directory fsync) publish the record.
/// The parent directory must already exist; any IO failure is returned.
pub fn persist_mutation_disposition(
    path: impl AsRef<Path>,
    record: &MutationDispositionRecord,
) -> Result<AtomicWriteOutcome, MutationDispositionPersistError> {
    let encoded = record
        .encode()
        .map_err(MutationDispositionPersistError::Encode)?;
    atomic_write(
        path,
        encoded,
        AtomicWriteOptions::state_file(MUTATION_DISPOSITION_MAX_BYTES),
    )
    .map_err(MutationDispositionPersistError::Write)
}

/// Why a same-boot or foreign record does not resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationUnresolvedReason {
    /// The record was written by a different boot. A prior boot's journal is
    /// never auto-cleared — even if its entries look clean or receipted —
    /// because this boot cannot re-derive the prior boot's live evidence.
    ForeignBootId { recorded_boot_id: String },
    /// The record was written for a different slot/image. The other A/B
    /// image's `/data` is not this image's hardware disposition.
    ForeignSlotIdentity {
        recorded_slot_identity: String,
        current_slot_identity: String,
    },
    /// A non-Clean entry carries no typed SafeOff receipt.
    EntryWithoutSafeOffReceipt { fabric_key: String },
}

impl fmt::Display for MutationUnresolvedReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForeignBootId { recorded_boot_id } => write!(
                formatter,
                "journal was written by a prior boot ({recorded_boot_id}) and is not auto-cleared"
            ),
            Self::ForeignSlotIdentity {
                recorded_slot_identity,
                current_slot_identity,
            } => write!(
                formatter,
                "journal was written for slot {recorded_slot_identity} (this image is {current_slot_identity}) and is not auto-cleared"
            ),
            Self::EntryWithoutSafeOffReceipt { fabric_key } => write!(
                formatter,
                "fabric {fabric_key} has a mutated/quarantined disposition without a typed SafeOff receipt"
            ),
        }
    }
}

/// Private state behind a loaded mutation-disposition adjudication.
///
/// Keeping this enum private prevents callers from constructing a synthetic
/// `Resolved` value and using it to mint journal-clear authority.
#[derive(Debug, Clone)]
enum MutationDispositionState {
    /// Absent file, or a same-boot record whose every entry is Clean or
    /// carries a typed SafeOff receipt.
    Resolved {
        record: Option<MutationDispositionRecord>,
    },
    /// The record exists and does not resolve. Admission must be refused.
    Unresolved {
        record: MutationDispositionRecord,
        reasons: Vec<MutationUnresolvedReason>,
    },
    /// The record could not be proven readable/valid. Admission must be
    /// refused — corruption is never permission to pretend absence.
    Unreadable { detail: String },
}

/// Startup adjudication of the durable journal.
///
/// This value is opaque outside this module and retains the exact path that
/// was inspected. Callers can inspect the decision through accessors, but only
/// [`admit_hardware_after_mutation_adjudication`] can mint a path-bound
/// [`MutationClearance`] for a loaded, resolved record.
#[derive(Debug, Clone)]
pub struct MutationDispositionAdjudication {
    path: PathBuf,
    state: MutationDispositionState,
}

impl MutationDispositionAdjudication {
    pub fn is_resolved(&self) -> bool {
        matches!(self.state, MutationDispositionState::Resolved { .. })
    }

    pub fn resolved_record(&self) -> Option<&MutationDispositionRecord> {
        match &self.state {
            MutationDispositionState::Resolved { record } => record.as_ref(),
            MutationDispositionState::Unresolved { .. }
            | MutationDispositionState::Unreadable { .. } => None,
        }
    }

    pub fn unresolved_record(&self) -> Option<&MutationDispositionRecord> {
        match &self.state {
            MutationDispositionState::Unresolved { record, .. } => Some(record),
            MutationDispositionState::Resolved { .. }
            | MutationDispositionState::Unreadable { .. } => None,
        }
    }

    pub fn unresolved_reasons(&self) -> Option<&[MutationUnresolvedReason]> {
        match &self.state {
            MutationDispositionState::Unresolved { reasons, .. } => Some(reasons),
            MutationDispositionState::Resolved { .. }
            | MutationDispositionState::Unreadable { .. } => None,
        }
    }

    pub fn unreadable_detail(&self) -> Option<&str> {
        match &self.state {
            MutationDispositionState::Unreadable { detail } => Some(detail),
            MutationDispositionState::Resolved { .. }
            | MutationDispositionState::Unresolved { .. } => None,
        }
    }

    fn resolved(path: &Path, record: Option<MutationDispositionRecord>) -> Self {
        Self {
            path: path.to_path_buf(),
            state: MutationDispositionState::Resolved { record },
        }
    }

    fn unresolved(
        path: &Path,
        record: MutationDispositionRecord,
        reasons: Vec<MutationUnresolvedReason>,
    ) -> Self {
        Self {
            path: path.to_path_buf(),
            state: MutationDispositionState::Unresolved { record, reasons },
        }
    }

    fn unreadable(path: &Path, detail: String) -> Self {
        Self {
            path: path.to_path_buf(),
            state: MutationDispositionState::Unreadable { detail },
        }
    }
}

/// Load the journal and decide whether hardware admission may proceed,
/// using [`current_slot_image_identity`] as the slot/image identity.
///
/// ONLY `Resolved` admits. Every IO/parse problem is `Unreadable`; a foreign
/// boot id, foreign slot, or a receipt-less non-Clean entry is `Unresolved`.
/// There is no code path from a journal problem to admission.
pub fn load_and_adjudicate_mutation_disposition(
    path: impl AsRef<Path>,
    current_boot_id: &str,
) -> MutationDispositionAdjudication {
    load_and_adjudicate_mutation_disposition_for_slot(
        path,
        current_boot_id,
        &current_slot_image_identity(),
    )
}

/// Load and adjudicate against an explicit slot/image identity (journal v2).
pub fn load_and_adjudicate_mutation_disposition_for_slot(
    path: impl AsRef<Path>,
    current_boot_id: &str,
    current_slot_identity: &str,
) -> MutationDispositionAdjudication {
    let path = path.as_ref();
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return MutationDispositionAdjudication::resolved(path, None);
        }
        Err(error) => {
            return MutationDispositionAdjudication::unreadable(
                path,
                format!("stat failed: {error}"),
            );
        }
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return MutationDispositionAdjudication::unreadable(
            path,
            "journal path is not a regular non-symlink file".to_string(),
        );
    }
    if metadata.len() > MUTATION_DISPOSITION_MAX_BYTES as u64 {
        return MutationDispositionAdjudication::unreadable(
            path,
            "journal exceeds its bounded size".to_string(),
        );
    }
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return MutationDispositionAdjudication::unreadable(
                path,
                format!("read failed: {error}"),
            );
        }
    };
    let record = match MutationDispositionRecord::decode(&bytes) {
        Ok(record) => record,
        Err(error) => {
            return MutationDispositionAdjudication::unreadable(path, error.to_string());
        }
    };
    let mut reasons = Vec::new();
    if record.boot_id != current_boot_id {
        reasons.push(MutationUnresolvedReason::ForeignBootId {
            recorded_boot_id: record.boot_id.clone(),
        });
    }
    if record.slot_identity != current_slot_identity {
        reasons.push(MutationUnresolvedReason::ForeignSlotIdentity {
            recorded_slot_identity: record.slot_identity.clone(),
            current_slot_identity: current_slot_identity.to_string(),
        });
    }
    for entry in &record.entries {
        if entry.blocks_admission() {
            reasons.push(MutationUnresolvedReason::EntryWithoutSafeOffReceipt {
                fabric_key: entry.fabric_key.clone(),
            });
        }
    }
    if reasons.is_empty() {
        MutationDispositionAdjudication::resolved(path, Some(record))
    } else {
        MutationDispositionAdjudication::unresolved(path, record, reasons)
    }
}

/// Typed refusal returned by [`admit_hardware_after_mutation_adjudication`].
#[derive(Debug, Clone)]
pub enum MutationAdmissionRefusal {
    Unresolved {
        reasons: Vec<MutationUnresolvedReason>,
    },
    Unreadable {
        detail: String,
    },
}

impl fmt::Display for MutationAdmissionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unresolved { reasons } => {
                write!(
                    formatter,
                    "unresolved mutation-disposition journal ({} reason(s)):",
                    reasons.len()
                )?;
                for reason in reasons {
                    write!(formatter, " [{reason}]")?;
                }
                Ok(())
            }
            Self::Unreadable { detail } => {
                write!(
                    formatter,
                    "unreadable mutation-disposition journal: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for MutationAdmissionRefusal {}

/// Opaque, one-use authority to remove the exact loaded journal path.
///
/// The field is private, so external callers cannot construct or retarget the
/// token. The token is intentionally not `Clone` or `Copy`.
#[derive(Debug)]
pub struct MutationClearance {
    path: PathBuf,
}

/// Successful admission. A loaded, resolved journal carries a one-use
/// clearance; an absent journal admits without one.
#[derive(Debug)]
pub struct MutationAdmission {
    clearance: Option<MutationClearance>,
}

impl MutationAdmission {
    pub fn into_clearance(self) -> Option<MutationClearance> {
        self.clearance
    }
}

/// The single admission gate over an adjudication. Success is possible only
/// for a privately constructed Resolved state. Unresolved and Unreadable both
/// return a typed refusal (fail-closed).
pub fn admit_hardware_after_mutation_adjudication(
    adjudication: &MutationDispositionAdjudication,
) -> Result<MutationAdmission, MutationAdmissionRefusal> {
    match &adjudication.state {
        MutationDispositionState::Resolved { record } => Ok(MutationAdmission {
            clearance: record.as_ref().map(|_| MutationClearance {
                path: adjudication.path.clone(),
            }),
        }),
        MutationDispositionState::Unresolved { reasons, .. } => {
            Err(MutationAdmissionRefusal::Unresolved {
                reasons: reasons.clone(),
            })
        }
        MutationDispositionState::Unreadable { detail } => {
            Err(MutationAdmissionRefusal::Unreadable {
                detail: detail.clone(),
            })
        }
    }
}

/// Durably remove the exact journal bound into a one-use clearance.
///
/// A clearance exists only when a journal loaded from that path was accepted
/// as Resolved. This prevents direct path-only clear calls and accidental
/// retargeting. It does not authenticate how a typed SafeOff receipt was
/// produced; physical/operator receipt authority remains a separate boundary.
pub fn clear_mutation_disposition(
    clearance: MutationClearance,
) -> Result<AtomicRemoveOutcome, AtomicRemoveError> {
    remove_file(clearance.path)
}

/// A software terminal closeout is deliberately separate from a rail-cut
/// receipt. It never resolves or removes a mutation journal.
pub const SOFTWARE_CLOSEOUT_PATH: &str = "/data/dcent/dcentrald-software-closeout-v1";
const SOFTWARE_CLOSEOUT_JOURNAL: &str = "/data/dcent/dcentrald-mutation-disposition-v1";
const SOFTWARE_CLOSEOUT_SESSION: &str = "/data/dcent/dcentrald-hardware-session.unresolved";
const SOFTWARE_CLOSEOUT_PREFIX: &str = "DCENT_SOFTWARE_CLOSEOUT_V1";
const SOFTWARE_CLOSEOUT_MAX: usize = 2048;

/// Captured at the beginning of the checked shutdown. Private fields prevent
/// a caller from changing the process, image or supervisor session afterwards.
#[derive(Debug, PartialEq, Eq)]
pub struct SoftwareCloseoutRun {
    boot: String,
    pid: u32,
    start_ticks: u64,
    board: String,
    image: String,
    executable_hash: String,
    slot: String,
    session: String,
}

fn closeout_field(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'|')
}

fn process_start_ticks(stat: &str) -> Result<u64, String> {
    // comm can contain spaces and ')'; field 22 follows the final ')'.
    stat.rsplit_once(')')
        .and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| "invalid process start-time identity".into())
}

fn checked_closeout_read(path: &Path, private: bool, owner_uid: u32) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let before = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !before.is_file() || before.len() == 0 || before.len() > SOFTWARE_CLOSEOUT_MAX as u64 {
        return Err("closeout input is not a bounded regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let forbidden = if private { 0o077 } else { 0o022 };
        if before.uid() != owner_uid || before.mode() & forbidden != 0 || before.nlink() != 1 {
            return Err("closeout input lacks protected root ownership/mode".into());
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x20000 | 0x800); // O_NOFOLLOW | O_NONBLOCK
    }
    let file = options.open(path).map_err(|error| error.to_string())?;
    let opened = file.metadata().map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err("closeout input changed while opening".into());
        }
    }
    let mut bytes = Vec::new();
    file.take(SOFTWARE_CLOSEOUT_MAX as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 != opened.len() || bytes.len() > SOFTWARE_CLOSEOUT_MAX {
        return Err("closeout input changed size while reading".into());
    }
    Ok(bytes)
}

fn protected_closeout_directory(path: &Path, owner_uid: u32) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_dir() {
        return Err("closeout directory is not a real directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != owner_uid || metadata.mode() & 0o077 != 0 {
            return Err("closeout directory lacks private root ownership/mode".into());
        }
    }
    Ok(())
}

fn absent_closeout_journal(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(
            "an existing or unreadable mutation journal forbids software restart clearance".into(),
        ),
    }
}

fn closeout_marker_identity(bytes: &[u8]) -> Result<(&str, &str, &str), String> {
    let source = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    if !source.ends_with('\n') || source.contains('\r') {
        return Err("invalid session marker".into());
    }
    let field = |name: &str| -> Result<&str, String> {
        let prefix = format!("{name}=");
        let mut matches = source.lines().filter_map(|line| line.strip_prefix(&prefix));
        let value = matches.next().ok_or("missing session marker identity")?;
        if matches.next().is_some() || !closeout_field(value) {
            return Err("ambiguous session marker identity".into());
        }
        Ok(value)
    };
    if field("schema")? != "1" || field("state")? != "unresolved" {
        return Err("session marker is not the active unresolved session".into());
    }
    Ok((
        field("boot_id")?,
        field("image_version")?,
        field("session_token")?,
    ))
}

fn software_closeout_slot() -> Result<String, String> {
    let mounts =
        std::fs::read_to_string("/proc/self/mountinfo").map_err(|error| error.to_string())?;
    let roots: Vec<_> = mounts
        .lines()
        .filter_map(|line| {
            let (left, right) = line.split_once(" - ")?;
            let fields: Vec<_> = left.split_whitespace().collect();
            let fs: Vec<_> = right.split_whitespace().collect();
            (fields.len() >= 5 && fields[4] == "/" && fs.len() >= 2)
                .then(|| format!("{}:{}:{}:{}", fields[2], fields[3], fs[0], fs[1]))
        })
        .collect();
    match roots.as_slice() {
        [root] if closeout_field(root) => Ok(root.clone()),
        _ => Err("root filesystem slot identity is absent or ambiguous".into()),
    }
}

fn running_executable_hash() -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    const MAX_DAEMON: u64 = 256 * 1024 * 1024;
    let file = std::fs::File::open("/proc/self/exe").map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_DAEMON {
        return Err("running executable is outside its regular-file size bound".into());
    }
    let mut reader = file.take(metadata.len() + 1);
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut size = 0u64;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        size += count as u64;
        hash.update(&buffer[..count]);
    }
    if size != metadata.len() {
        return Err("running executable changed size while hashing".into());
    }
    Ok(hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

impl SoftwareCloseoutRun {
    fn encode(&self) -> Result<String, String> {
        if self.pid == 0
            || self.start_ticks == 0
            || [
                &self.boot,
                &self.board,
                &self.image,
                &self.slot,
                &self.session,
            ]
            .into_iter()
            .any(|field| !closeout_field(field))
        {
            return Err("invalid software closeout identity".into());
        }
        if self.executable_hash.len() != 64
            || !self
                .executable_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid executable SHA256 in software closeout".into());
        }
        Ok(format!(
            "{SOFTWARE_CLOSEOUT_PREFIX}|{}|{}|{}|{}|{}|{}|{}|{}\n",
            self.boot,
            self.pid,
            self.start_ticks,
            self.board,
            self.image,
            self.slot,
            self.session,
            self.executable_hash
        ))
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        let source = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
        let fields: Vec<_> = source
            .strip_suffix('\n')
            .ok_or("missing closeout terminator")?
            .split('|')
            .collect();
        if fields.len() != 9 || fields[0] != SOFTWARE_CLOSEOUT_PREFIX {
            return Err("invalid software closeout schema".into());
        }
        let run = Self {
            boot: fields[1].into(),
            pid: fields[2].parse().map_err(|_| "invalid closeout PID")?,
            start_ticks: fields[3]
                .parse()
                .map_err(|_| "invalid closeout start time")?,
            board: fields[4].into(),
            image: fields[5].into(),
            slot: fields[6].into(),
            session: fields[7].into(),
            executable_hash: fields[8].into(),
        };
        if run.encode()?.as_bytes() != bytes {
            return Err("noncanonical software closeout".into());
        }
        Ok(run)
    }

    fn current() -> Result<Self, String> {
        protected_closeout_directory(Path::new("/data/dcent"), 0)?;
        let read_identity = |path: &str| -> Result<String, String> {
            String::from_utf8(checked_closeout_read(Path::new(path), false, 0)?)
                .map(|value| value.trim().to_string())
                .map_err(|error| error.to_string())
        };
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| error.to_string())?
            .trim()
            .to_string();
        let board = read_identity("/etc/dcentos/board_target")?;
        if crate::BoardDesc::lookup(&board).is_none() {
            return Err("unregistered closeout board".into());
        }
        let image = read_identity("/etc/dcentos-version")?;
        let marker = checked_closeout_read(Path::new(SOFTWARE_CLOSEOUT_SESSION), true, 0)?;
        let (marker_boot, marker_image, session) = closeout_marker_identity(&marker)?;
        if marker_boot != boot || marker_image != image {
            return Err("foreign session boot/image".into());
        }
        let run = Self {
            boot,
            pid: std::process::id(),
            start_ticks: process_start_ticks(
                &std::fs::read_to_string("/proc/self/stat").map_err(|error| error.to_string())?,
            )?,
            board,
            image,
            slot: software_closeout_slot()?,
            session: session.into(),
            executable_hash: running_executable_hash()?,
        };
        run.encode()?;
        Ok(run)
    }
}

/// Capture current protected supervisor/process/image identity before shutdown.
pub fn capture_software_closeout_run(board_target: &str) -> Result<SoftwareCloseoutRun, String> {
    absent_closeout_journal(Path::new(SOFTWARE_CLOSEOUT_JOURNAL))?;
    let run = SoftwareCloseoutRun::current()?;
    if run.board != board_target {
        return Err("shutdown board differs from installed image".into());
    }
    Ok(run)
}

/// Called only after the owner's typed terminal closeout and watchdog join.
/// An empty unresolved roster is required; no Mutated/Quarantined fabric is
/// resolved by this unit-wide software evidence. The journal is never written.
pub fn persist_orderly_software_closeout(
    run: SoftwareCloseoutRun,
    unresolved: &[MutationDispositionEntry],
) -> Result<(), String> {
    if !unresolved.is_empty() {
        return Err("unresolved fabrics forbid software closeout".into());
    }
    if run != SoftwareCloseoutRun::current()? {
        return Err("software closeout run/context changed".into());
    }
    absent_closeout_journal(Path::new(SOFTWARE_CLOSEOUT_JOURNAL))?;
    atomic_write(
        SOFTWARE_CLOSEOUT_PATH,
        run.encode()?,
        AtomicWriteOptions::state_file(SOFTWARE_CLOSEOUT_MAX),
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn validate_software_closeout_at(
    receipt_path: &Path,
    journal_path: &Path,
    expected: &SoftwareCloseoutRun,
    process_stat: Result<String, io::Error>,
    owner_uid: u32,
) -> Result<(), String> {
    protected_closeout_directory(
        receipt_path.parent().ok_or("missing receipt directory")?,
        owner_uid,
    )?;
    absent_closeout_journal(journal_path)?;
    let actual =
        SoftwareCloseoutRun::decode(&checked_closeout_read(receipt_path, true, owner_uid)?)?;
    if actual != *expected {
        return Err("foreign or stale software closeout receipt".into());
    }
    match process_stat {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(stat) if process_start_ticks(&stat)? != expected.start_ticks => {} // PID reused; old run is dead.
        Ok(_) => return Err("software closeout process is still alive".into()),
        Err(error) => {
            return Err(format!(
                "cannot establish software closeout owner death: {error}"
            ))
        }
    }
    Ok(())
}

/// Pure no-hardware CLI consumer. All paths and installed board/image/slot
/// identity are fixed internally; argv cannot nominate another receipt/journal.
/// The caller must hold the supervisor session lock and have observed an
/// expected zero exit plus successful emergency safety action. Consume once.
pub fn consume_orderly_software_closeout(
    pid: u32,
    start_ticks: u64,
    boot: &str,
    session: &str,
) -> Result<(), String> {
    let mut expected = SoftwareCloseoutRun::current()?;
    if expected.boot != boot || expected.session != session {
        return Err("foreign supervisor closeout request".into());
    }
    expected.pid = pid;
    expected.start_ticks = start_ticks;
    validate_software_closeout_at(
        Path::new(SOFTWARE_CLOSEOUT_PATH),
        Path::new(SOFTWARE_CLOSEOUT_JOURNAL),
        &expected,
        std::fs::read_to_string(format!("/proc/{pid}/stat")),
        0,
    )?;
    remove_file(SOFTWARE_CLOSEOUT_PATH).map_err(|error| error.to_string())?;
    Ok(())
}

#[cfg(all(test, unix))]
mod software_closeout_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn run() -> SoftwareCloseoutRun {
        SoftwareCloseoutRun {
            boot: "boot-a".into(),
            pid: 123,
            start_ticks: 456,
            board: "am1-s9".into(),
            image: "1.2.3".into(),
            slot: "0:20:/:ubifs:ubi0:rootfs".into(),
            session: "boot-a.789".into(),
            executable_hash: "ab".repeat(32),
        }
    }
    struct Fixture {
        dir: PathBuf,
        receipt: PathBuf,
        journal: PathBuf,
        uid: u32,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "software-closeout-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            let uid = std::fs::metadata(&dir).unwrap().uid();
            let fixture = Self {
                receipt: dir.join("receipt"),
                journal: dir.join("journal"),
                dir,
                uid,
            };
            fixture.write(run().encode().unwrap().as_bytes());
            fixture
        }
        fn write(&self, bytes: &[u8]) {
            std::fs::write(&self.receipt, bytes).unwrap();
            std::fs::set_permissions(&self.receipt, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        fn validate(
            &self,
            expected: &SoftwareCloseoutRun,
            process: Result<String, io::Error>,
        ) -> Result<(), String> {
            validate_software_closeout_at(&self.receipt, &self.journal, expected, process, self.uid)
        }
        fn dead(&self, expected: &SoftwareCloseoutRun) -> Result<(), String> {
            self.validate(expected, Err(io::Error::from(io::ErrorKind::NotFound)))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
    fn proc_stat(ticks: u64) -> String {
        format!(
            "123 (a comm with ) spaces) S {} {ticks}",
            vec!["1"; 18].join(" ")
        )
    }

    #[test]
    fn exact_dead_run_allows_software_restart_without_removing_any_journal() {
        let fixture = Fixture::new();
        fixture.dead(&run()).unwrap();
        assert!(fixture.receipt.is_file());
        assert!(!fixture.journal.exists());
        assert!(!run().encode().unwrap().contains("verified-rail-cut"));
    }
    #[test]
    fn every_foreign_run_board_image_slot_and_session_is_refused() {
        let fixture = Fixture::new();
        for field in 0..8 {
            let mut other = run();
            match field {
                0 => other.boot = "other-boot".into(),
                1 => other.pid += 1,
                2 => other.start_ticks += 1,
                3 => other.board = "am3-s19k".into(),
                4 => other.image = "1.2.4".into(),
                5 => other.slot = "other-slot".into(),
                6 => other.session = "other-session".into(),
                _ => other.executable_hash = "cd".repeat(32),
            }
            assert!(fixture.dead(&other).is_err(), "foreign field {field}");
        }
    }
    #[test]
    fn live_owner_and_uncertain_death_refuse_but_pid_reuse_is_distinguished() {
        let fixture = Fixture::new();
        assert_eq!(process_start_ticks(&proc_stat(456)).unwrap(), 456);
        assert!(fixture.validate(&run(), Ok(proc_stat(456))).is_err());
        assert!(fixture.validate(&run(), Ok("malformed".into())).is_err());
        assert!(fixture
            .validate(
                &run(),
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            )
            .is_err());
        fixture.validate(&run(), Ok(proc_stat(999))).unwrap();
    }
    #[test]
    fn any_existing_mutation_journal_stays_untouched_and_blocks_restart() {
        let fixture = Fixture::new();
        for bytes in [
            b"unclean".as_slice(),
            b"DCENT_MUTATION_DISPOSITION_V2\n",
            b"",
        ] {
            std::fs::write(&fixture.journal, bytes).unwrap();
            assert!(fixture.dead(&run()).is_err());
            assert_eq!(std::fs::read(&fixture.journal).unwrap(), bytes);
        }
        std::fs::remove_file(&fixture.journal).unwrap();
        std::os::unix::fs::symlink(fixture.dir.join("missing"), &fixture.journal).unwrap();
        assert!(fixture.dead(&run()).is_err());
    }
    #[test]
    fn malformed_forged_and_oversized_receipt_bytes_are_refused() {
        let fixture = Fixture::new();
        let good = run().encode().unwrap();
        for bytes in [
            String::new(),
            good.trim_end().into(),
            good.replace("V1", "V2"),
            good.replace("|123|", "|0123|"),
            good.replace("|123|", "|0|"),
            good.replace("\n", "|extra\n"),
            good.replace("\n", "\r\n"),
            "x".repeat(2049),
        ] {
            fixture.write(bytes.as_bytes());
            assert!(fixture.dead(&run()).is_err(), "accepted {bytes:?}");
        }
    }
    #[test]
    fn symlink_hardlink_public_mode_and_foreign_owner_are_refused() {
        let fixture = Fixture::new();
        std::fs::set_permissions(&fixture.receipt, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(fixture.dead(&run()).is_err());
        fixture.write(run().encode().unwrap().as_bytes());
        assert!(validate_software_closeout_at(
            &fixture.receipt,
            &fixture.journal,
            &run(),
            Err(io::Error::from(io::ErrorKind::NotFound)),
            fixture.uid + 1
        )
        .is_err());
        std::fs::hard_link(&fixture.receipt, fixture.dir.join("link")).unwrap();
        assert!(fixture.dead(&run()).is_err());
        std::fs::remove_file(fixture.dir.join("link")).unwrap();
        std::fs::rename(&fixture.receipt, fixture.dir.join("actual")).unwrap();
        std::os::unix::fs::symlink(fixture.dir.join("actual"), &fixture.receipt).unwrap();
        assert!(fixture.dead(&run()).is_err());
    }
    #[test]
    fn missing_or_duplicate_supervisor_binding_is_not_completion_authority() {
        let good = "schema=1\nstate=unresolved\nboot_id=boot-a\nimage_version=1.2.3\nsession_token=boot-a.789\n";
        assert_eq!(
            closeout_marker_identity(good.as_bytes()).unwrap(),
            ("boot-a", "1.2.3", "boot-a.789")
        );
        for bad in [
            good.replace("session_token=boot-a.789\n", ""),
            format!("{good}session_token=other\n"),
            good.replace("unresolved", "clean"),
            good.replace('\n', "\r\n"),
        ] {
            assert!(closeout_marker_identity(bad.as_bytes()).is_err());
        }
    }
    #[test]
    fn mutated_and_quarantined_rosters_never_mint_software_closeout() {
        for disposition in [
            MutationEntryDisposition::Mutated,
            MutationEntryDisposition::Quarantined(MutationQuarantineReason::WorkerPanicked),
        ] {
            let entry = MutationDispositionEntry {
                fabric_key: "adapter-1".into(),
                allocation_id: 1,
                endpoint_class: MutationEndpointClass::RuntimeService,
                disposition,
                safe_off_receipt: None,
            };
            assert!(persist_orderly_software_closeout(run(), &[entry])
                .unwrap_err()
                .contains("unresolved fabrics"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT_A: &str = "4b2a2fd2-8bc4-4b3e-9d5a-remote-boot-a";
    const BOOT_B: &str = "9d8e6c11-1111-4f00-b222-remote-boot-b";
    const SLOT_A: &str = "firmware-1";
    const SLOT_B: &str = "firmware-2";

    fn quarantined_entry() -> MutationDispositionEntry {
        MutationDispositionEntry {
            fabric_key: "linux-adapter-0".to_string(),
            allocation_id: 7,
            endpoint_class: MutationEndpointClass::RuntimeService,
            disposition: MutationEntryDisposition::Quarantined(
                MutationQuarantineReason::WorkerPanicked,
            ),
            safe_off_receipt: None,
        }
    }

    fn record_with(entries: Vec<MutationDispositionEntry>) -> MutationDispositionRecord {
        MutationDispositionRecord {
            boot_id: BOOT_A.to_string(),
            image_version: "0.5.0-test".to_string(),
            platform: "zynq-bm3-am2".to_string(),
            slot_identity: SLOT_A.to_string(),
            session_reason: MutationSessionReason::ExpectedZeroAwaitingTypedDisposition,
            recorded_unix_s: 1_800_000_000,
            entries,
        }
    }

    fn load_slot_a(path: &std::path::Path, boot_id: &str) -> MutationDispositionAdjudication {
        load_and_adjudicate_mutation_disposition_for_slot(path, boot_id, SLOT_A)
    }

    fn unique_temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dcent-mutation-disposition-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn record_round_trips_every_disposition_and_receipt_kind() {
        let record = record_with(vec![
            MutationDispositionEntry {
                fabric_key: "linux-adapter-0".to_string(),
                allocation_id: 1,
                endpoint_class: MutationEndpointClass::RuntimeService,
                disposition: MutationEntryDisposition::Clean,
                safe_off_receipt: None,
            },
            MutationDispositionEntry {
                fabric_key: "topology-fabric-1".to_string(),
                allocation_id: 2,
                endpoint_class: MutationEndpointClass::RawLease,
                disposition: MutationEntryDisposition::Mutated,
                safe_off_receipt: Some(TypedSafeOffReceipt::OperatorCleared {
                    observed_unix_s: 1_800_000_001,
                }),
            },
            MutationDispositionEntry {
                fabric_key: "linux-adapter-1".to_string(),
                allocation_id: 3,
                endpoint_class: MutationEndpointClass::RuntimeService,
                disposition: MutationEntryDisposition::Quarantined(
                    MutationQuarantineReason::UnresolvedPic16State,
                ),
                safe_off_receipt: Some(TypedSafeOffReceipt::VerifiedRailCut {
                    observed_unix_s: 1_800_000_002,
                }),
            },
        ]);
        let encoded = record.encode().unwrap();
        assert_eq!(
            MutationDispositionRecord::decode(encoded.as_bytes()).unwrap(),
            record
        );

        for reason in [
            MutationSessionReason::ExpectedZeroAwaitingTypedDisposition,
            MutationSessionReason::SafeOffFailed,
            MutationSessionReason::UnresolvedFabricQuarantine,
        ] {
            let mut record = record_with(vec![quarantined_entry()]);
            record.session_reason = reason;
            let encoded = record.encode().unwrap();
            assert!(
                encoded.starts_with("DCENT_MUTATION_DISPOSITION_V2|"),
                "journal v2 prefix required"
            );
            assert!(encoded.contains(&format!("|{SLOT_A}|{}|", reason.encode())));
            assert_eq!(
                MutationDispositionRecord::decode(encoded.as_bytes()).unwrap(),
                record
            );
        }

        for reason in [
            MutationQuarantineReason::PreparationAborted,
            MutationQuarantineReason::WorkerPanicked,
            MutationQuarantineReason::UnresolvedPic16State,
            MutationQuarantineReason::UnresolvedClassicAmlPicState,
            MutationQuarantineReason::UnexpectedLeaseDrop,
            MutationQuarantineReason::RegistryInvariantLost,
        ] {
            let record = record_with(vec![MutationDispositionEntry {
                disposition: MutationEntryDisposition::Quarantined(reason),
                ..quarantined_entry()
            }]);
            let encoded = record.encode().unwrap();
            assert_eq!(
                MutationDispositionRecord::decode(encoded.as_bytes()).unwrap(),
                record
            );
        }
    }

    #[test]
    fn corrupt_truncated_or_ambiguous_records_never_parse() {
        let valid = record_with(vec![quarantined_entry()]).encode().unwrap();

        // Truncation at EVERY byte boundary must fail, never partially parse.
        for cut in 0..valid.len() {
            assert!(
                MutationDispositionRecord::decode(valid[..cut].as_bytes()).is_err(),
                "truncation at byte {cut} parsed"
            );
        }

        for bytes in [
            b"".as_slice(),
            b"DCENT_MUTATION_DISPOSITION_V0|b|i|p|s|r|1|0\nDCENT_MUTATION_DISPOSITION_END\n".as_slice(),
            // Predecessor V1 schema is not silently upgraded.
            b"DCENT_MUTATION_DISPOSITION_V1|b|i|p|1|0\nDCENT_MUTATION_DISPOSITION_END\n".as_slice(),
            // Missing footer.
            b"DCENT_MUTATION_DISPOSITION_V2|b|i|p|s|expected-zero-awaiting-typed-disposition|1|0\n".as_slice(),
            // Entry-count larger than actual entries.
            b"DCENT_MUTATION_DISPOSITION_V2|b|i|p|s|expected-zero-awaiting-typed-disposition|1|1\nDCENT_MUTATION_DISPOSITION_END\n"
                .as_slice(),
            // Entry-count smaller than actual entries.
            b"DCENT_MUTATION_DISPOSITION_V2|b|i|p|s|expected-zero-awaiting-typed-disposition|1|0\nE|k|1|runtime-service|clean|none\nDCENT_MUTATION_DISPOSITION_END\n"
                .as_slice(),
            // Unknown quarantine reason fails closed.
            b"DCENT_MUTATION_DISPOSITION_V2|b|i|p|s|expected-zero-awaiting-typed-disposition|1|1\nE|k|1|runtime-service|quarantined:new-shiny-reason|none\nDCENT_MUTATION_DISPOSITION_END\n"
                .as_slice(),
            // Unknown session reason fails closed.
            b"DCENT_MUTATION_DISPOSITION_V2|b|i|p|s|auto-restarted|1|0\nDCENT_MUTATION_DISPOSITION_END\n"
                .as_slice(),
            // Unknown receipt kind fails closed.
            b"DCENT_MUTATION_DISPOSITION_V2|b|i|p|s|expected-zero-awaiting-typed-disposition|1|1\nE|k|1|runtime-service|mutated|safe-off:process-exited:1\nDCENT_MUTATION_DISPOSITION_END\n"
                .as_slice(),
            // CR contamination.
            b"DCENT_MUTATION_DISPOSITION_V2|b|i|p|s|expected-zero-awaiting-typed-disposition|1|0\r\nDCENT_MUTATION_DISPOSITION_END\n"
                .as_slice(),
            // Trailing garbage after the footer.
            b"DCENT_MUTATION_DISPOSITION_V2|b|i|p|s|expected-zero-awaiting-typed-disposition|1|0\nDCENT_MUTATION_DISPOSITION_END\nextra\n"
                .as_slice(),
            // Header field with an embedded invalid character.
            b"DCENT_MUTATION_DISPOSITION_V2|b b|i|p|s|expected-zero-awaiting-typed-disposition|1|0\nDCENT_MUTATION_DISPOSITION_END\n"
                .as_slice(),
        ] {
            assert!(MutationDispositionRecord::decode(bytes).is_err());
        }

        // Oversized input is rejected before any parsing.
        let oversized = vec![b'A'; MUTATION_DISPOSITION_MAX_BYTES + 1];
        assert_eq!(
            MutationDispositionRecord::decode(&oversized),
            Err(MutationDispositionParseError::InvalidLength)
        );
    }

    #[test]
    fn encode_refuses_invalid_tokens_and_unbounded_entry_lists() {
        let mut record = record_with(vec![quarantined_entry()]);
        record.boot_id = "has a space".to_string();
        assert_eq!(
            record.encode(),
            Err(MutationDispositionEncodeError::InvalidToken { field: "boot_id" })
        );

        let mut record = record_with(vec![quarantined_entry()]);
        record.slot_identity = "has a space".to_string();
        assert_eq!(
            record.encode(),
            Err(MutationDispositionEncodeError::InvalidToken {
                field: "slot_identity"
            })
        );

        let mut record = record_with(vec![quarantined_entry()]);
        record.entries[0].fabric_key = "pipe|inside".to_string();
        assert!(matches!(
            record.encode(),
            Err(MutationDispositionEncodeError::InvalidToken {
                field: "fabric_key"
            })
        ));

        let record = record_with(vec![
            quarantined_entry();
            MUTATION_DISPOSITION_MAX_ENTRIES + 1
        ]);
        assert!(matches!(
            record.encode(),
            Err(MutationDispositionEncodeError::TooManyEntries { .. })
        ));
    }

    #[test]
    fn sanitize_journal_token_is_bounded_and_never_empty() {
        assert_eq!(sanitize_journal_token("zynq-bm3-am2"), "zynq-bm3-am2");
        assert_eq!(sanitize_journal_token("has space|pipe"), "has-space-pipe");
        assert_eq!(sanitize_journal_token(""), "unknown");
        let long = "x".repeat(500);
        assert_eq!(
            sanitize_journal_token(&long).len(),
            MUTATION_DISPOSITION_MAX_TOKEN_LEN
        );
        assert!(valid_token(&sanitize_journal_token(
            "weird\nstuff\u{1F600}"
        )));
    }

    #[test]
    fn absent_file_resolves_and_clean_same_boot_record_resolves() {
        let dir = unique_temp_dir("clean");
        let path = dir.join("journal");

        let adjudication = load_slot_a(&path, BOOT_A);
        assert!(adjudication.is_resolved() && adjudication.resolved_record().is_none());
        assert!(admit_hardware_after_mutation_adjudication(&adjudication).is_ok());

        #[cfg(unix)]
        {
            let record = record_with(vec![MutationDispositionEntry {
                disposition: MutationEntryDisposition::Clean,
                ..quarantined_entry()
            }]);
            persist_mutation_disposition(&path, &record).unwrap();
            let adjudication = load_slot_a(&path, BOOT_A);
            assert_eq!(adjudication.resolved_record(), Some(&record));
            let admission = admit_hardware_after_mutation_adjudication(&adjudication).unwrap();
            assert_eq!(
                clear_mutation_disposition(
                    admission
                        .into_clearance()
                        .expect("loaded resolved journal carries exact-path clearance")
                )
                .unwrap(),
                AtomicRemoveOutcome::Removed
            );
            let absent = load_and_adjudicate_mutation_disposition(&path, BOOT_A);
            assert!(absent.is_resolved() && absent.resolved_record().is_none());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn mutated_without_receipt_refuses_and_typed_safe_off_receipt_admits() {
        let dir = unique_temp_dir("mutated");
        let path = dir.join("journal");
        let record = record_with(vec![quarantined_entry()]);
        persist_mutation_disposition(&path, &record).unwrap();

        let adjudication = load_slot_a(&path, BOOT_A);
        assert_eq!(
            adjudication
                .unresolved_reasons()
                .expect("expected Unresolved"),
            [MutationUnresolvedReason::EntryWithoutSafeOffReceipt {
                fabric_key: "linux-adapter-0".to_string(),
            }]
        );
        let refusal = admit_hardware_after_mutation_adjudication(&adjudication)
            .expect_err("mutated entry without receipt must refuse admission");
        assert!(refusal.to_string().contains("linux-adapter-0"));

        // A typed SafeOff receipt is the explicit resolution that admits.
        let mut resolved = record.clone();
        resolved.entries[0].safe_off_receipt = Some(TypedSafeOffReceipt::OperatorCleared {
            observed_unix_s: 1_800_000_100,
        });
        persist_mutation_disposition(&path, &resolved).unwrap();
        let adjudication = load_slot_a(&path, BOOT_A);
        assert!(adjudication.is_resolved() && adjudication.resolved_record().is_some());
        assert!(admit_hardware_after_mutation_adjudication(&adjudication).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn foreign_boot_id_is_unresolved_and_never_auto_cleared() {
        let dir = unique_temp_dir("foreign");
        let path = dir.join("journal");

        // Even a fully receipted record from a prior boot must not resolve.
        let mut record = record_with(vec![quarantined_entry()]);
        record.entries[0].safe_off_receipt = Some(TypedSafeOffReceipt::VerifiedRailCut {
            observed_unix_s: 1_800_000_200,
        });
        persist_mutation_disposition(&path, &record).unwrap();

        let adjudication = load_slot_a(&path, BOOT_B);
        assert_eq!(
            adjudication
                .unresolved_reasons()
                .expect("expected Unresolved"),
            [MutationUnresolvedReason::ForeignBootId {
                recorded_boot_id: BOOT_A.to_string(),
            }]
        );
        assert!(admit_hardware_after_mutation_adjudication(&adjudication).is_err());

        // The file must still be present: adjudication never deletes.
        assert!(path.is_file());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn missing_directory_write_fails_closed_and_is_returned() {
        let dir = unique_temp_dir("missing-dir");
        let path = dir.join("does-not-exist").join("journal");
        let record = record_with(vec![quarantined_entry()]);
        assert!(matches!(
            persist_mutation_disposition(&path, &record),
            Err(MutationDispositionPersistError::Write(_))
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn corruption_and_symlinks_are_unreadable_refusals_never_absence() {
        let dir = unique_temp_dir("corrupt");
        let path = dir.join("journal");

        std::fs::write(&path, b"corrupt\n").unwrap();
        let adjudication = load_and_adjudicate_mutation_disposition(&path, BOOT_A);
        assert!(adjudication.unreadable_detail().is_some());
        assert!(admit_hardware_after_mutation_adjudication(&adjudication).is_err());

        // A symlinked journal is never trusted.
        let target = dir.join("target");
        let record = record_with(vec![]);
        persist_mutation_disposition(&target, &record).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(load_and_adjudicate_mutation_disposition(&link, BOOT_A)
            .unreadable_detail()
            .is_some());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn clear_authority_is_one_use_and_bound_to_the_loaded_resolved_path() {
        let dir = unique_temp_dir("clearance-path");
        let admitted_path = dir.join("admitted-journal");
        let other_path = dir.join("other-journal");
        let record = record_with(vec![]);
        persist_mutation_disposition(&admitted_path, &record).unwrap();
        persist_mutation_disposition(&other_path, &record).unwrap();

        let adjudication = load_slot_a(&admitted_path, BOOT_A);
        let admission = admit_hardware_after_mutation_adjudication(&adjudication).unwrap();
        let clearance = admission
            .into_clearance()
            .expect("loaded resolved journal carries clearance");
        assert_eq!(
            clear_mutation_disposition(clearance).unwrap(),
            AtomicRemoveOutcome::Removed
        );
        assert!(!admitted_path.exists());
        assert!(
            other_path.is_file(),
            "clearance must not retarget another path"
        );

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn daemon_adjudicates_mutation_journal_before_hardware_admission() {
        // Source contract against a DIFFERENT file (daemon.rs), mirroring the
        // thermal-lockout pins: the durable mutation journal must be
        // adjudicated during standard init AFTER the thermal lockout load and
        // BEFORE the measured thermal admission / Phase 1 watchdog authority,
        // with a fail-closed latch + bail refusal path.
        let daemon = include_str!("../../dcentrald/src/daemon.rs");
        let init = daemon
            .split_once("async fn init(")
            .expect("standard init")
            .1;
        let thermal_load = init
            .find("load_thermal_lockout(&thermal_lockout_path)")
            .expect("thermal lockout load");
        let adjudicate = init
            .find("load_and_adjudicate_mutation_disposition(")
            .expect("mutation journal adjudication");
        let refusal = init[adjudicate..]
            .find("mutation-disposition journal refuses hardware admission")
            .map(|offset| adjudicate + offset)
            .expect("fail-closed journal refusal");
        let measured = init
            .find("self.startup_thermal_safety = measured_startup_thermal_state(")
            .expect("measured startup admission");
        let phase_one = init
            .find("// ---- Phase 1: Watchdog ----")
            .expect("first post-admission phase");
        assert!(
            thermal_load < adjudicate
                && adjudicate < refusal
                && refusal < measured
                && measured < phase_one,
            "mutation journal must be adjudicated before any hardware admission authority"
        );
        let gate_block = &init[adjudicate..measured];
        assert!(
            gate_block.contains("latch_terminal_safe_off()")
                && gate_block.contains("anyhow::bail!"),
            "journal refusal must latch terminal safe-off and terminate init"
        );
        assert!(
            gate_block.contains("clear_mutation_disposition("),
            "an accepted resolution must be durably removed (mirror remove_thermal_lockout)"
        );
    }

    #[test]
    fn daemon_journals_dispositions_at_controlled_teardown_not_unwind() {
        let daemon = include_str!("../../dcentrald/src/daemon.rs");

        // Typed shutdown journals after the positive closeout boundary.
        let shutdown = daemon
            .split_once("async fn shutdown(&mut self)")
            .expect("typed shutdown")
            .1;
        let complete = shutdown
            .find("info!(\"=== SHUTDOWN COMPLETE ===\")")
            .expect("positive closeout boundary");
        assert!(
            shutdown[complete..].contains("persist_unresolved_mutation_dispositions_with_reason("),
            "typed shutdown must journal unresolved fabric dispositions"
        );
        assert!(
            shutdown[complete..]
                .contains("MutationSessionReason::ExpectedZeroAwaitingTypedDisposition")
                && shutdown[complete..].contains("MutationSessionReason::SafeOffFailed"),
            "typed shutdown must distinguish expected-zero vs safeoff-failed"
        );

        // Both thermal terminal arms journal at the same watchdog-feed-closed
        // point where the thermal lockout is persisted.
        let emergency_start = daemon
            .find("ThermalAction::EmergencyShutdown => {")
            .expect("emergency arm");
        let fan_start = daemon[emergency_start..]
            .find("ThermalAction::FanFailure => {")
            .map(|offset| emergency_start + offset)
            .expect("fan-failure arm");
        let restart_start = daemon[fan_start..]
            .find("ThermalAction::RestartInit => {")
            .map(|offset| fan_start + offset)
            .expect("restart arm");
        for (name, arm) in [
            ("emergency", &daemon[emergency_start..fan_start]),
            ("fan-failure", &daemon[fan_start..restart_start]),
        ] {
            let thermal_persist = arm
                .find("persist_terminal_thermal_generation_bounded")
                .expect("bounded thermal persistence");
            let journal = arm
                .find("persist_unresolved_mutation_dispositions_with_reason(")
                .unwrap_or_else(|| panic!("{name} arm must journal fabric dispositions"));
            assert!(
                thermal_persist < journal,
                "{name}: journal after the bounded thermal persist, same terminal point"
            );
        }

        // The journal must never relax the no-auto-restart policy.
        let restart = include_str!("../../dcentrald/src/restart.rs");
        assert!(restart.contains(
            "Automatic daemon restart refused: no typed hardware disposition receipt is available"
        ));
        assert!(restart.contains("\n    false\n"));
    }

    #[test]
    fn production_persist_always_writes_receipt_none_and_never_stamps_verified_rail_cut() {
        let daemon = include_str!("../../dcentrald/src/daemon.rs");
        let entries_fn = daemon
            .split_once("fn unresolved_mutation_journal_entries(")
            .expect("HAL projection")
            .1;
        let entries_fn = entries_fn
            .split_once("pub(crate) fn persist_unresolved_mutation_dispositions(")
            .expect("projection bound")
            .0;
        assert!(
            entries_fn.contains("safe_off_receipt: None"),
            "production persist must write receipt=None"
        );
        assert!(
            !entries_fn.contains("TypedSafeOffReceipt::")
                && !entries_fn.contains("safe-off:verified-rail-cut"),
            "production persist must not mint any typed SafeOff receipt"
        );

        let persist_fn = daemon
            .split_once("pub(crate) fn persist_unresolved_mutation_dispositions_with_reason(")
            .expect("production persist")
            .1;
        let persist_fn = persist_fn
            .split_once("\nasync fn persist_terminal_thermal_generation_bounded(")
            .expect("persist function bound")
            .0;
        assert!(
            persist_fn.contains("slot_identity") && persist_fn.contains("session_reason"),
            "production persist must fill journal v2 slot/reason fields"
        );
        assert!(
            persist_fn.contains("current_slot_image_identity()"),
            "production persist must bind slot/image identity"
        );
        assert!(
            !persist_fn.contains("TypedSafeOffReceipt::"),
            "production persist must not mint any typed SafeOff receipt"
        );
    }

    #[test]
    fn current_slot_image_identity_is_a_journal_token() {
        let identity = current_slot_image_identity();
        assert!(valid_token(&identity), "{identity}");
        assert!(
            identity.starts_with("slot-unknown:")
                || identity
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':')),
            "{identity}"
        );
    }

    #[test]
    fn foreign_slot_and_boot_reasons_are_not_auto_cleared() {
        let slot = MutationUnresolvedReason::ForeignSlotIdentity {
            recorded_slot_identity: SLOT_A.to_string(),
            current_slot_identity: SLOT_B.to_string(),
        };
        let text = slot.to_string();
        assert!(text.contains(SLOT_A) && text.contains(SLOT_B));
        let boot = MutationUnresolvedReason::ForeignBootId {
            recorded_boot_id: BOOT_B.to_string(),
        };
        assert!(boot.to_string().contains(BOOT_B));
        assert!(!text.contains("VerifiedRailCut"));
    }

    #[test]
    fn session_reason_from_env_never_silently_expected_zero() {
        assert_eq!(
            MutationSessionReason::from_env(),
            MutationSessionReason::UnresolvedFabricQuarantine
        );
        assert_eq!(
            MutationSessionReason::ExpectedZeroAwaitingTypedDisposition.encode(),
            "expected-zero-awaiting-typed-disposition"
        );
        assert_eq!(
            MutationSessionReason::SafeOffFailed.encode(),
            "safeoff-failed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn foreign_slot_identity_is_unresolved_and_never_auto_cleared() {
        let dir = unique_temp_dir("foreign-slot");
        let path = dir.join("journal");
        let mut record = record_with(vec![quarantined_entry()]);
        record.entries[0].safe_off_receipt = Some(TypedSafeOffReceipt::OperatorCleared {
            observed_unix_s: 1_800_000_300,
        });
        persist_mutation_disposition(&path, &record).unwrap();

        let adjudication = load_and_adjudicate_mutation_disposition_for_slot(&path, BOOT_A, SLOT_B);
        assert_eq!(
            adjudication
                .unresolved_reasons()
                .expect("expected Unresolved"),
            [MutationUnresolvedReason::ForeignSlotIdentity {
                recorded_slot_identity: SLOT_A.to_string(),
                current_slot_identity: SLOT_B.to_string(),
            }]
        );
        assert!(admit_hardware_after_mutation_adjudication(&adjudication).is_err());
        assert!(path.is_file(), "adjudication never deletes");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn verified_rail_cut_round_trips_but_is_test_only() {
        let mut record = record_with(vec![quarantined_entry()]);
        record.session_reason = MutationSessionReason::SafeOffFailed;
        record.entries[0].safe_off_receipt = Some(TypedSafeOffReceipt::VerifiedRailCut {
            observed_unix_s: 1_800_000_400,
        });
        let encoded = record.encode().unwrap();
        assert!(encoded.contains("safe-off:verified-rail-cut:"));
        assert_eq!(
            MutationDispositionRecord::decode(encoded.as_bytes()).unwrap(),
            record
        );
    }

    #[test]
    fn fw_setenv_helper_never_nandwrites_mtd4_and_emits_script_form() {
        let helper = include_str!(
            "../../../br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-hw-unresolved-env.sh"
        );
        assert!(helper.contains("NEVER nandwrite"));
        assert!(helper.contains("fw_setenv --script"));
        assert!(helper.contains("ENV_NAME=dcent_hw_unresolved"));
        assert!(helper.contains("ENV_SET_VALUE=1"));
        assert!(
            helper.contains("print_set_script") && helper.contains("print_clear_script"),
            "helper must emit set and clear fw_setenv --script payloads"
        );
        for line in helper.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') {
                continue;
            }
            assert!(
                !trimmed.starts_with("nandwrite") && !trimmed.starts_with("flash_erase"),
                "helper command line must not invoke nandwrite/flash_erase: {line}"
            );
        }
    }
}
