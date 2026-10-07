//! FPGA bitstream **identity, provenance, and lifecycle contracts** (HAL-free).
//!
//!  / W8, 2026-08-03. Closes the read-only half of `GAP-C2-3` ("no
//! bitstream identity, version, or provenance — anywhere") and pins the
//! `GAP-C2-2` refusal ("the signed-package bitstream slot is validated and then
//! ignored"). Census that produced both gaps:
//! .
//!
//! # Scope, stated up front
//!
//! Everything here is **pure, read-only, and about an artifact at rest**. This
//! module:
//!
//! * parses the ASCII identity header a Xilinx `.bit` file carries, so a
//!   bitstream *file* can name itself (design, part, build date/time);
//! * classifies an artifact that has **no** such header, and reports
//!   [`BitstreamArtifactKind::Unknown`] rather than guessing;
//! * records what DCENT actually holds, per artifact, with measured bytes.
//!
//! It deliberately does **not**:
//!
//! * program, write, install, or stage a bitstream anywhere;
//! * claim to know which bitstream a running unit's PL fabric is configured
//!   with. See [`LOADED_FABRIC_IDENTITY_IS_UNDETERMINED`] — that remains an
//!   open negative, and the honest answer is `UNKNOWN`.
//!
//! # Why "no installer" is a deliberate refusal, not an omission
//!
//! The signed sysupgrade package admits an `fpga_bitstream.bit` payload leaf,
//! validates it (exactly-one/zero bidirectional consistency, manifest hash
//! binding), and then **installs nothing**. That is correct and must stay
//! correct:
//!
//! 1. A package-directed write target is exactly the blast-radius expansion the
//!    campaign's blocked-items section forbids.
//! 2. On a Zynq whose `BOOT.bin` carries the **RSA-verified** fabric stage, a
//!    bitstream write is a **brick vector with no software route back** — the
//!    boot chain is `BootROM -> FSBL(RSA) -> FPGA(RSA) -> U-Boot(RSA) -> ...`.
//!
//! The source contract in this module's test section pins that no-op so it
//! stays deliberate and greppable.
//!
//! # Held artifacts (measured 2026-08-03, desk only, no hardware)
//!
//! See [`HELD_BITSTREAM_ARTIFACTS`]. Only **one** of the four held Zynq
//! artifacts carries a readable identity header.

use serde::{Deserialize, Serialize};

/// Xilinx configuration-stream sync word as it appears in a `.bit` file
/// (big-endian byte order): `AA 99 55 66`.
///
/// Measured in `DCENT_OS_Antminer/
/// at file offset `0xA6`.
pub const SYNC_WORD_BIT_ORDER: [u8; 4] = [0xAA, 0x99, 0x55, 0x66];

/// The same sync word after the 32-bit **word byte-swap** that `bootgen` /
/// `bit2bin` applies when producing a `.bin` for `xdevcfg` / `fpga_manager`:
/// `66 55 99 AA`.
///
/// Measured in
///
/// at file offset `0x30`. This is a **byte-order swap within each 32-bit
/// word**, not a bit reversal: the preceding words `00 00 00 BB` / `11 22 00 44`
/// appear as `BB 00 00 00` / `44 00 22 11`.
pub const SYNC_WORD_BIN_WORD_SWAPPED: [u8; 4] = [0x66, 0x55, 0x99, 0xAA];

/// Number of leading bytes we are willing to scan for a sync word before
/// declaring an artifact unclassifiable. Generous enough to cover the largest
/// header we have measured (118 bytes) plus a `.bin` dummy-word run, small
/// enough that a multi-megabyte padded partition read cannot be "classified"
/// by an accidental match deep inside unrelated data.
pub const SYNC_SCAN_WINDOW: usize = 4096;

/// What kind of artifact a candidate bitstream file actually is.
///
/// **Fail-closed:** anything we cannot positively recognize is
/// [`BitstreamArtifactKind::Unknown`]. There is no `Default`, and no variant
/// means "probably fine".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitstreamArtifactKind {
    /// A Xilinx `.bit` with a well-formed ASCII identity header followed by a
    /// configuration stream in `.bit` byte order. Identity is **readable**.
    BitWithHeader,
    /// A headerless configuration stream in `.bit` byte order (sync word
    /// `AA 99 55 66` found, no parseable header). Identity is **not** readable;
    /// only the content hash identifies it.
    RawStreamBitOrder,
    /// A headerless configuration stream in word-swapped `.bin` byte order
    /// (sync word `66 55 99 AA`). Identity is **not** readable; only the
    /// content hash identifies it. This is what `fpga_manager` consumes.
    RawStreamWordSwapped,
    /// No recognizable configuration stream in the scanned window. Could be a
    /// padded partition read, a compressed container, a mis-sliced extraction,
    /// or something else entirely. **Never treat this as a bitstream.**
    Unknown,
}

/// Identity a `.bit` header declares about itself.
///
/// Every field is exactly what the file says, with no normalization and no
/// inference. A field that is absent from the header is `None` — never a
/// substituted default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitstreamHeaderIdentity {
    /// Field `a` — the design/top-module name. On Vivado output this usually
    /// also carries `;UserID=0x...;Version=<vivado release>`.
    pub design_name: Option<String>,
    /// Field `b` — the target device, e.g. `7z010clg400`.
    pub part: Option<String>,
    /// Field `c` — build date as the tool wrote it, e.g. `2020/12/04`.
    pub build_date: Option<String>,
    /// Field `d` — build time as the tool wrote it, e.g. `15:46:27`.
    pub build_time: Option<String>,
    /// Field `e` — declared configuration-stream length in bytes.
    pub payload_len: Option<u32>,
    /// Byte offset at which the configuration stream begins.
    pub payload_offset: Option<usize>,
}

impl BitstreamHeaderIdentity {
    /// An identity with nothing known. This is the value every failure path
    /// returns — it can never masquerade as a successful read because
    /// [`BitstreamHeaderIdentity::is_identified`] is `false`.
    pub const fn unknown() -> Self {
        Self {
            design_name: None,
            part: None,
            build_date: None,
            build_time: None,
            payload_len: None,
            payload_offset: None,
        }
    }

    /// `true` only when the header named at least a design and a part. A
    /// consumer may claim "this artifact identifies itself" only when this is
    /// `true`.
    pub fn is_identified(&self) -> bool {
        self.design_name.is_some() && self.part.is_some()
    }

    /// Human-facing single line, explicitly `UNKNOWN` when nothing was read.
    /// Callers must not invent a friendlier fallback.
    pub fn describe(&self) -> String {
        if !self.is_identified() {
            return "UNKNOWN".to_string();
        }
        let design = self.design_name.as_deref().unwrap_or("UNKNOWN");
        let part = self.part.as_deref().unwrap_or("UNKNOWN");
        let date = self.build_date.as_deref().unwrap_or("UNKNOWN");
        let time = self.build_time.as_deref().unwrap_or("UNKNOWN");
        format!("{design} part={part} built={date} {time}")
    }
}

/// Result of inspecting a candidate bitstream artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitstreamInspection {
    /// What the artifact is, fail-closed.
    pub kind: BitstreamArtifactKind,
    /// What it says about itself. All-`None` unless `kind` is
    /// [`BitstreamArtifactKind::BitWithHeader`].
    pub identity: BitstreamHeaderIdentity,
    /// Total artifact length in bytes, as supplied.
    pub artifact_len: usize,
}

impl BitstreamInspection {
    /// The fail-closed value: unknown kind, unknown identity.
    pub fn unknown(artifact_len: usize) -> Self {
        Self {
            kind: BitstreamArtifactKind::Unknown,
            identity: BitstreamHeaderIdentity::unknown(),
            artifact_len,
        }
    }
}

fn read_u16_be(bytes: &[u8], at: usize) -> Option<u16> {
    let hi = *bytes.get(at)?;
    let lo = *bytes.get(at.checked_add(1)?)?;
    Some(u16::from_be_bytes([hi, lo]))
}

fn read_u32_be(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let slice = bytes.get(at..end)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Read one `key + u16 length + NUL-terminated ASCII` header field.
/// Returns the value and the offset immediately after the field.
fn read_string_field(bytes: &[u8], at: usize, expect_key: u8) -> Option<(String, usize)> {
    if *bytes.get(at)? != expect_key {
        return None;
    }
    let len = read_u16_be(bytes, at.checked_add(1)?)? as usize;
    let start = at.checked_add(3)?;
    let end = start.checked_add(len)?;
    let raw = bytes.get(start..end)?;
    // The field is NUL-terminated; drop the terminator and refuse anything
    // that is not printable ASCII rather than emitting mojibake.
    let text = raw.split(|b| *b == 0).next()?;
    if text.is_empty() || !text.iter().all(|b| (0x20..0x7F).contains(b)) {
        return None;
    }
    let value = core::str::from_utf8(text).ok()?.to_string();
    Some((value, end))
}

/// Parse the ASCII identity header of a Xilinx `.bit` file.
///
/// Format, confirmed byte-for-byte against
/// `DCENT_OS_Antminer/:
///
/// ```text
/// u16 be len (=9) | 9 preamble bytes | u16 be (=1)
/// 'a' u16 be len  design-name\0
/// 'b' u16 be len  part\0
/// 'c' u16 be len  date\0
/// 'd' u16 be len  time\0
/// 'e' u32 be len  <configuration stream>
/// ```
///
/// Returns [`BitstreamHeaderIdentity::unknown`] on **any** deviation. This
/// function performs no I/O, allocates only the field strings, and cannot
/// panic on adversarial input (every index goes through a checked accessor).
pub fn parse_bit_header(bytes: &[u8]) -> BitstreamHeaderIdentity {
    let unknown = BitstreamHeaderIdentity::unknown();

    let Some(preamble_len) = read_u16_be(bytes, 0) else {
        return unknown;
    };
    let Some(after_preamble) = (preamble_len as usize).checked_add(2) else {
        return unknown;
    };
    if bytes.len() <= after_preamble {
        return unknown;
    }
    // A 2-byte field count of exactly 1 separates the preamble from key 'a'.
    if read_u16_be(bytes, after_preamble) != Some(1) {
        return unknown;
    }
    let mut cursor = match after_preamble.checked_add(2) {
        Some(c) => c,
        None => return unknown,
    };

    let Some((design_name, next)) = read_string_field(bytes, cursor, b'a') else {
        return unknown;
    };
    cursor = next;
    let Some((part, next)) = read_string_field(bytes, cursor, b'b') else {
        return unknown;
    };
    cursor = next;
    let Some((build_date, next)) = read_string_field(bytes, cursor, b'c') else {
        return unknown;
    };
    cursor = next;
    let Some((build_time, next)) = read_string_field(bytes, cursor, b'd') else {
        return unknown;
    };
    cursor = next;

    if bytes.get(cursor) != Some(&b'e') {
        return unknown;
    }
    let Some(payload_len) = read_u32_be(bytes, cursor.saturating_add(1)) else {
        return unknown;
    };
    let Some(payload_offset) = cursor.checked_add(5) else {
        return unknown;
    };

    BitstreamHeaderIdentity {
        design_name: Some(design_name),
        part: Some(part),
        build_date: Some(build_date),
        build_time: Some(build_time),
        payload_len: Some(payload_len),
        payload_offset: Some(payload_offset),
    }
}

fn window_contains(bytes: &[u8], needle: &[u8; 4]) -> bool {
    let limit = bytes.len().min(SYNC_SCAN_WINDOW);
    bytes
        .get(..limit)
        .map(|w| w.windows(4).any(|c| c == needle))
        .unwrap_or(false)
}

/// Inspect a candidate bitstream artifact, fail-closed.
///
/// A caller may only say "this is bitstream X" when the returned `kind` is
/// [`BitstreamArtifactKind::BitWithHeader`] **and**
/// [`BitstreamHeaderIdentity::is_identified`] is `true`. Every other outcome
/// means the artifact's identity is `UNKNOWN` and must be reported as such.
pub fn inspect_bitstream_artifact(bytes: &[u8]) -> BitstreamInspection {
    let identity = parse_bit_header(bytes);
    if identity.is_identified() {
        return BitstreamInspection {
            kind: BitstreamArtifactKind::BitWithHeader,
            identity,
            artifact_len: bytes.len(),
        };
    }
    if window_contains(bytes, &SYNC_WORD_BIT_ORDER) {
        return BitstreamInspection {
            kind: BitstreamArtifactKind::RawStreamBitOrder,
            identity: BitstreamHeaderIdentity::unknown(),
            artifact_len: bytes.len(),
        };
    }
    if window_contains(bytes, &SYNC_WORD_BIN_WORD_SWAPPED) {
        return BitstreamInspection {
            kind: BitstreamArtifactKind::RawStreamWordSwapped,
            identity: BitstreamHeaderIdentity::unknown(),
            artifact_len: bytes.len(),
        };
    }
    BitstreamInspection::unknown(bytes.len())
}

/// Evidence class behind a held-artifact record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactEvidence {
    /// Bytes on disk were read and hashed this wave.
    MeasuredOnDisk,
}

/// One programmable-logic artifact DCENT actually holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldBitstreamArtifact {
    /// Repo-relative path.
    pub path: &'static str,
    /// Size in bytes, measured.
    pub len: usize,
    /// SHA-256 of the file, measured.
    pub sha256: &'static str,
    /// Classification produced by [`inspect_bitstream_artifact`].
    pub kind: BitstreamArtifactKind,
    /// What the artifact says about itself, or `None` when it says nothing.
    pub declared_identity: Option<&'static str>,
    /// Evidence class.
    pub evidence: ArtifactEvidence,
    /// Anything a later reader must not misread.
    pub caveat: &'static str,
}

/// Every Zynq programmable-logic artifact DCENT holds, measured 2026-08-03.
///
/// **The headline fact: exactly one of these four names itself.** Any claim
/// that we "know which bitstream" the other three are rests on a file path and
/// a hash, not on the artifact's own declaration.
pub const HELD_BITSTREAM_ARTIFACTS: &[HeldBitstreamArtifact] = &[
    HeldBitstreamArtifact {
        path: "DCENT_OS_Antminer/",
        len: 2_083_858,
        sha256: "980532de5eb666508dafb111466f30169a70b8b6ea662bdda61e17dbd55a4421",
        kind: BitstreamArtifactKind::BitWithHeader,
        declared_identity: Some(
            "system_wrapper;UserID=0XFFFFFFFF;Version=2017.4_AR70455 \
             part=7z010clg400 built=2020/12/04 15:46:27",
        ),
        evidence: ArtifactEvidence::MeasuredOnDisk,
        caveat: "The bitstream we SHIP. Vivado 2017.4_AR70455 + top module \
                 `system_wrapper` are the Braiins zynq-io signature; part \
                 7z010clg400 is XC7Z010 (am1-s9 class), NOT the XC7Z007S that \
                 the am2 defconfigs describe. We redistribute it with no \
                 in-tree build recipe and no attribution note.",
    },
    HeldBitstreamArtifact {
        path: "\
               zynq_boot_parts/FPGA_Zynq7007_miner.bit",
        len: 2_083_744,
        sha256: "894471e307aa3fc652614a4200718fe9f745ba9526e52f887aeb56c543d88ee7",
        kind: BitstreamArtifactKind::Unknown,
        declared_identity: None,
        evidence: ArtifactEvidence::MeasuredOnDisk,
        caveat: "NOT A USABLE BITSTREAM despite the .bit extension. First 59,284 \
                 bytes are zero, only 678,645 of 2,083,744 bytes are non-zero, no \
                 sync word appears in the scan window, and the tail holds U-Boot \
                 strings (\"Boot Capacity:\", \"NAND %s:\", \"Really scrub\"). It is a \
                 mis-sliced BOOT.bin partition extraction that runs into U-Boot. \
                 Cite it as a held artifact, never as a readable stock bitstream.",
    },
    HeldBitstreamArtifact {
        path: "\
               xilinx/base/z007_xilinx.bit.bin",
        len: 2_083_744,
        sha256: "7e858f9230609d02c3545cd7e8c5f2ee5eb4932fe55425954f2acc2876b88af2",
        kind: BitstreamArtifactKind::RawStreamWordSwapped,
        declared_identity: None,
        evidence: ArtifactEvidence::MeasuredOnDisk,
        caveat: "ePIC's OWN fabric. Headerless word-swapped .bin for fpga_manager. \
                 Equal length to the Bitmain slice above carries NO information — a \
                 full config stream for a given part is a fixed frame count. Their \
                 PL addresses are in THEIR bitstream and must never enter our tables.",
    },
    HeldBitstreamArtifact {
        path: "",
        len: 2_097_152,
        sha256: "f9317611efc031705af33d1b595db20c62802f7aa45a3afc64cedbb62527d005",
        kind: BitstreamArtifactKind::Unknown,
        declared_identity: None,
        evidence: ArtifactEvidence::MeasuredOnDisk,
        caveat: "Exactly 2 MiB — a padded partition read, so the CONTAINER is not a \
                 bitstream and this hash identifies the partition, not the fabric. Its \
                 first bytes are a GZIP member (1f 8b 08 08) whose stored filename is \
                 `system.bit`. Inflate first, then inspect: see \
                 AM2_BITSTREAM_INSIDE_S19J_PARTITION.",
    },
];

/// Evidence state for the CPLD-interface axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpldInterfaceInventoryState {
    /// A completed binary-aware part scan, independent filename-extension
    /// census, and source-registry scan found no CPLD device, image, or
    /// executable interface in the held scope.
    HeldCorpusNegativeNoDeviceOrConfigArtifact,
}

/// First-class negative capability record for the CPLD axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpldInterfaceCapability {
    pub identifier: &'static str,
    pub state: CpldInterfaceInventoryState,
    pub evidence_source: &'static str,
    pub completed_binary_part_scan: bool,
    pub fresh_config_extension_census: bool,
    pub fresh_source_registry_scan: bool,
    pub independent_second_extractions_scan_complete: bool,
    pub cpld_device_observed: bool,
    pub cpld_config_artifact_observed: bool,
    pub executable_interface_observed: bool,
    pub runtime_admission_authorized: bool,
    pub programming_authorized: bool,
}

/// Canonical CPLD-interface inventory for the held DCENT hardware scope.
///
/// The single row is a declared absence, not an unknown or a failed actuator.
/// Programmable glue that does exist is FPGA soft logic and remains inventoried
/// separately.  The incomplete independent second pass is retained explicitly
/// rather than hidden behind the otherwise high-confidence negative.
pub const CPLD_INTERFACE_CAPABILITIES: &[CpldInterfaceCapability] = &[CpldInterfaceCapability {
    identifier: "held-corpus-no-cpld-device-or-config-artifact",
    state: CpldInterfaceInventoryState::HeldCorpusNegativeNoDeviceOrConfigArtifact,
    evidence_source: "C2-CPLD-GLUE-LOGIC plus fresh 2026-08-09 extension/source census",
    completed_binary_part_scan: true,
    fresh_config_extension_census: true,
    fresh_source_registry_scan: true,
    independent_second_extractions_scan_complete: false,
    cpld_device_observed: false,
    cpld_config_artifact_observed: false,
    executable_interface_observed: false,
    runtime_admission_authorized: false,
    programming_authorized: false,
}];

/// **The am2 fabric, identified at the desk (2026-08-03).**
///
/// The GZIP member at the head of
///  inflates to a
/// well-formed `.bit` of **2,083,859** bytes, sha256
/// `4e2f7a0bb5d65b8f7ad43bea1290c8646c5f7b49321c768418bdfdc9e04afe22`, whose own
/// header reads:
///
/// ```text
/// design : system_wrapper;UserID=0XFFFFFFFF;Version=2017.4_AR70455
/// part   : 7z007sclg225        (XC7Z007S — the am2 control-board part)
/// built  : 2022/11/28 11:43:49
/// payload: 0x001FCB9C bytes at offset 119
/// ```
///
/// Two things follow, and both are new:
///
/// 1. **The am2 bitstream now names itself.** Before this, am2 fabric identity
///    existed only as prose in a defconfig header comment. Same top module and
///    same Vivado release (`2017.4_AR70455`) as the S9 artifact we ship, which
///    corroborates the Braiins `zynq-io` lineage for both — from the artifacts,
///    not from a comment.
/// 2. **Our prose is off by ten days.** `dcentos_am2_s19jpro_defconfig:6`,
///    `dcentos_am2_s19pro_defconfig:6`, and `dcentos_am2_s17pro_zynq_defconfig:17`
///    all say *"Braiins s9-io-am2 bitstream (2022-12-08)"*; the artifact says
///    **2022/11/28**. The comment may be describing a packaging date rather than
///    a synthesis date, so this is recorded as a **discrepancy to reconcile**,
///    not as a proven error in the comment. Do not "fix" either side without
///    establishing which date each refers to.
///
/// This identifies an artifact at rest. It still does **not** tell us what a
/// running unit has loaded — see [`LOADED_FABRIC_IDENTITY_IS_UNDETERMINED`].
pub const AM2_BITSTREAM_INSIDE_S19J_PARTITION: HeldBitstreamArtifact = HeldBitstreamArtifact {
    path: " (inflated GZIP member)",
    len: 2_083_859,
    sha256: "4e2f7a0bb5d65b8f7ad43bea1290c8646c5f7b49321c768418bdfdc9e04afe22",
    kind: BitstreamArtifactKind::BitWithHeader,
    declared_identity: Some(
        "system_wrapper;UserID=0XFFFFFFFF;Version=2017.4_AR70455 \
         part=7z007sclg225 built=2022/11/28 11:43:49",
    ),
    evidence: ArtifactEvidence::MeasuredOnDisk,
    caveat: "Identity of an artifact AT REST, extracted from a partition read of an \
             am2 unit. It is not proof that any particular live unit has this fabric \
             configured, and the defconfig comments say 2022-12-08 while the artifact \
             says 2022/11/28 — reconcile before citing either as the build date.",
};

/// **Open negative, recorded deliberately.**
///
/// We cannot today determine, read-only, which bitstream a running unit's PL
/// fabric is configured with.
///
/// What we *can* read is a **declaration**, never a measurement:
/// * the UIO/device-tree node census tells us the fabric's *shape* (which IP
///   the DT says is present), and the DT is loaded from `BOOT.bin`, not read
///   back from the fabric;
/// * a defconfig header comment names a bitstream in prose.
///
/// Neither is evidence of what is actually configured. Three things would
/// settle it, in increasing cost:
///
/// 1. **A fabric that identifies itself.** A `USR_ACCESS`-backed or plain
///    AXI-mapped version register whose value is set at synthesis. Requires
///    owning our own bitstream — we do not build one today.
/// 2. **Reading the boot artifact instead of the fabric.** Hash the
///    `BOOT.bin` the unit actually booted and compare it to a recorded
///    manifest. This is achievable read-only, but raw MTD reads sit behind the
///    runtime hardware-ownership boundary and need a broker, not a direct
///    consumer read.
/// 3. **PCAP/ICAP readback of the configuration memory.** Requires issuing
///    commands to the configuration port. **Not read-only**, and out of scope.
///
/// Until one of those lands, any runtime "loaded bitstream" field must report
/// `UNKNOWN`. Populating it from a defconfig comment would be fabrication.
pub const LOADED_FABRIC_IDENTITY_IS_UNDETERMINED: bool = true;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpld_axis_is_a_typed_negative_not_an_unknown_interface() {
        assert_eq!(CPLD_INTERFACE_CAPABILITIES.len(), 1);
        let capability = CPLD_INTERFACE_CAPABILITIES[0];
        assert_eq!(
            capability.state,
            CpldInterfaceInventoryState::HeldCorpusNegativeNoDeviceOrConfigArtifact
        );
        assert!(capability.completed_binary_part_scan);
        assert!(capability.fresh_config_extension_census);
        assert!(capability.fresh_source_registry_scan);
        assert!(!capability.independent_second_extractions_scan_complete);
        assert!(!capability.cpld_device_observed);
        assert!(!capability.cpld_config_artifact_observed);
        assert!(!capability.executable_interface_observed);
        assert!(!capability.runtime_admission_authorized);
        assert!(!capability.programming_authorized);
    }

    /// The first 118 bytes of
    /// `DCENT_OS_Antminer/
    /// (sha256 `980532de…4421`, 2,083,858 B), transcribed from a hexdump of the
    /// real file on 2026-08-03. Embedded rather than `include_bytes!`-ing 2 MB.
    const REAL_SYSTEM_BIT_HEADER: &[u8] = &[
        0x00, 0x09, 0x0f, 0xf0, 0x0f, 0xf0, 0x0f, 0xf0, 0x0f, 0xf0, 0x00, 0x00, 0x01, 0x61, 0x00,
        0x38, b's', b'y', b's', b't', b'e', b'm', b'_', b'w', b'r', b'a', b'p', b'p', b'e', b'r',
        b';', b'U', b's', b'e', b'r', b'I', b'D', b'=', b'0', b'X', b'F', b'F', b'F', b'F', b'F',
        b'F', b'F', b'F', b';', b'V', b'e', b'r', b's', b'i', b'o', b'n', b'=', b'2', b'0', b'1',
        b'7', b'.', b'4', b'_', b'A', b'R', b'7', b'0', b'4', b'5', b'5', 0x00, 0x62, 0x00, 0x0c,
        b'7', b'z', b'0', b'1', b'0', b'c', b'l', b'g', b'4', b'0', b'0', 0x00, 0x63, 0x00, 0x0b,
        b'2', b'0', b'2', b'0', b'/', b'1', b'2', b'/', b'0', b'4', 0x00, 0x64, 0x00, 0x09, b'1',
        b'5', b':', b'4', b'6', b':', b'2', b'7', 0x00, 0x65, 0x00, 0x1f, 0xcb, 0x9c,
    ];

    #[test]
    fn parses_the_real_shipped_system_bit_header() {
        let id = parse_bit_header(REAL_SYSTEM_BIT_HEADER);
        assert!(id.is_identified(), "the shipped system.bit names itself");
        assert_eq!(
            id.design_name.as_deref(),
            Some("system_wrapper;UserID=0XFFFFFFFF;Version=2017.4_AR70455")
        );
        assert_eq!(id.part.as_deref(), Some("7z010clg400"));
        assert_eq!(id.build_date.as_deref(), Some("2020/12/04"));
        assert_eq!(id.build_time.as_deref(), Some("15:46:27"));
        assert_eq!(id.payload_len, Some(0x001F_CB9C));
        assert_eq!(id.payload_offset, Some(118));
    }

    #[test]
    fn header_arithmetic_reproduces_the_measured_file_length() {
        // payload_offset + declared payload length must equal the real file
        // size (2,083,858). If this ever drifts, the parser's field walk is
        // wrong, not the file.
        let id = parse_bit_header(REAL_SYSTEM_BIT_HEADER);
        let offset = id.payload_offset.expect("offset");
        let len = id.payload_len.expect("len") as usize;
        assert_eq!(offset + len, 2_083_858);
    }

    #[test]
    fn inspection_of_the_real_header_is_bit_with_header() {
        let got = inspect_bitstream_artifact(REAL_SYSTEM_BIT_HEADER);
        assert_eq!(got.kind, BitstreamArtifactKind::BitWithHeader);
        assert!(got.identity.is_identified());
    }

    /// The first 119 bytes of the **inflated** GZIP member inside
    ///  (inflated sha256
    /// `4e2f7a0b…fe22`, 2,083,859 B), transcribed 2026-08-03. Note the part
    /// field is 13 bytes here versus 12 in the S9 artifact, so this fixture also
    /// exercises variable field widths.
    const REAL_AM2_BIT_HEADER: &[u8] = &[
        0x00, 0x09, 0x0f, 0xf0, 0x0f, 0xf0, 0x0f, 0xf0, 0x0f, 0xf0, 0x00, 0x00, 0x01, 0x61, 0x00,
        0x38, b's', b'y', b's', b't', b'e', b'm', b'_', b'w', b'r', b'a', b'p', b'p', b'e', b'r',
        b';', b'U', b's', b'e', b'r', b'I', b'D', b'=', b'0', b'X', b'F', b'F', b'F', b'F', b'F',
        b'F', b'F', b'F', b';', b'V', b'e', b'r', b's', b'i', b'o', b'n', b'=', b'2', b'0', b'1',
        b'7', b'.', b'4', b'_', b'A', b'R', b'7', b'0', b'4', b'5', b'5', 0x00, 0x62, 0x00, 0x0d,
        b'7', b'z', b'0', b'0', b'7', b's', b'c', b'l', b'g', b'2', b'2', b'5', 0x00, 0x63, 0x00,
        0x0b, b'2', b'0', b'2', b'2', b'/', b'1', b'1', b'/', b'2', b'8', 0x00, 0x64, 0x00, 0x09,
        b'1', b'1', b':', b'4', b'3', b':', b'4', b'9', 0x00, 0x65, 0x00, 0x1f, 0xcb, 0x9c,
    ];

    #[test]
    fn parses_the_am2_bitstream_header_from_the_s19j_partition() {
        let id = parse_bit_header(REAL_AM2_BIT_HEADER);
        assert!(id.is_identified());
        assert_eq!(id.part.as_deref(), Some("7z007sclg225"));
        assert_eq!(id.build_date.as_deref(), Some("2022/11/28"));
        assert_eq!(id.build_time.as_deref(), Some("11:43:49"));
        assert_eq!(id.payload_offset, Some(119));
        // offset + declared payload must reproduce the measured inflated size.
        assert_eq!(
            id.payload_offset.unwrap() + id.payload_len.unwrap() as usize,
            2_083_859
        );
        assert_eq!(
            AM2_BITSTREAM_INSIDE_S19J_PARTITION.declared_identity,
            Some(id.describe().as_str())
        );
    }

    #[test]
    fn s9_and_am2_artifacts_share_a_toolchain_but_not_a_part() {
        let s9 = parse_bit_header(REAL_SYSTEM_BIT_HEADER);
        let am2 = parse_bit_header(REAL_AM2_BIT_HEADER);
        assert_eq!(s9.design_name, am2.design_name, "same top module + Vivado");
        assert_ne!(
            s9.part, am2.part,
            "XC7Z010 vs XC7Z007S — different carriers"
        );
        assert_ne!(s9.build_date, am2.build_date);
    }

    #[test]
    fn unknown_identity_describes_itself_as_unknown_never_a_guess() {
        let id = BitstreamHeaderIdentity::unknown();
        assert!(!id.is_identified());
        assert_eq!(id.describe(), "UNKNOWN");
    }

    #[test]
    fn empty_truncated_and_garbage_inputs_fail_closed() {
        for probe in [
            &b""[..],
            &b"\x00"[..],
            &b"\x00\x09"[..],
            // Correct preamble length but truncated before key 'a'.
            &b"\x00\x09\x0f\xf0\x0f\xf0\x0f\xf0\x0f\xf0\x00\x00\x01"[..],
            // Wrong field-count word.
            &b"\x00\x09\x0f\xf0\x0f\xf0\x0f\xf0\x0f\xf0\x00\x00\x02\x61\x00\x02A\x00"[..],
            &[0xFF; 64][..],
        ] {
            let id = parse_bit_header(probe);
            assert!(!id.is_identified(), "must not identify {probe:?}");
            assert_eq!(id.describe(), "UNKNOWN");
        }
    }

    #[test]
    fn truncated_prefixes_of_the_real_header_never_partially_identify() {
        // Every strict prefix must either fail closed or, at minimum, never
        // claim a payload it does not have.
        for cut in 0..REAL_SYSTEM_BIT_HEADER.len() {
            let id = parse_bit_header(&REAL_SYSTEM_BIT_HEADER[..cut]);
            if id.is_identified() {
                panic!("prefix of {cut} bytes wrongly identified as a full header");
            }
        }
    }

    #[test]
    fn headerless_word_swapped_stream_is_classified_but_not_identified() {
        // The ePIC .bin shape: dummy 0xFF run, then the word-swapped sync word.
        let mut art = vec![0xFFu8; 32];
        art.extend_from_slice(&SYNC_WORD_BIN_WORD_SWAPPED);
        art.extend_from_slice(&[0x00; 32]);
        let got = inspect_bitstream_artifact(&art);
        assert_eq!(got.kind, BitstreamArtifactKind::RawStreamWordSwapped);
        assert!(
            !got.identity.is_identified(),
            "a headerless stream must report UNKNOWN identity"
        );
    }

    #[test]
    fn a_zero_padded_partition_read_is_unknown_not_a_bitstream() {
        // The shape of the mis-sliced Bitmain slice: a long zero run and no
        // sync word anywhere in the scan window.
        let art = vec![0u8; SYNC_SCAN_WINDOW * 2];
        let got = inspect_bitstream_artifact(&art);
        assert_eq!(got.kind, BitstreamArtifactKind::Unknown);
        assert!(!got.identity.is_identified());
    }

    #[test]
    fn sync_word_beyond_the_scan_window_does_not_classify() {
        // A coincidental deep match must not promote an unrelated blob into a
        // "bitstream". This is the fail-closed direction on purpose.
        let mut art = vec![0u8; SYNC_SCAN_WINDOW + 64];
        let at = SYNC_SCAN_WINDOW + 8;
        art[at..at + 4].copy_from_slice(&SYNC_WORD_BIT_ORDER);
        assert_eq!(
            inspect_bitstream_artifact(&art).kind,
            BitstreamArtifactKind::Unknown
        );
    }

    #[test]
    fn held_artifact_table_is_honest_about_what_names_itself() {
        let identified: Vec<_> = HELD_BITSTREAM_ARTIFACTS
            .iter()
            .filter(|a| a.kind == BitstreamArtifactKind::BitWithHeader)
            .collect();
        assert_eq!(
            identified.len(),
            1,
            "exactly one held Zynq artifact carries a readable identity header"
        );
        assert_eq!(
            identified[0].path,
            "DCENT_OS_Antminer/"
        );
        for artifact in HELD_BITSTREAM_ARTIFACTS {
            if artifact.kind == BitstreamArtifactKind::BitWithHeader {
                assert!(artifact.declared_identity.is_some());
            } else {
                assert!(
                    artifact.declared_identity.is_none(),
                    "{} may not declare an identity it cannot read",
                    artifact.path
                );
            }
            assert!(!artifact.caveat.is_empty());
        }
    }

    #[test]
    fn loaded_fabric_identity_stays_an_open_negative() {
        // Flipping this to `false` is a claim that we can determine the loaded
        // fabric read-only. Do not flip it without shipping one of the three
        // mechanisms named in the constant's documentation.
        assert!(LOADED_FABRIC_IDENTITY_IS_UNDETERMINED);
    }

    // ---------------------------------------------------------------------
    // GAP-C2-2 source contract: the signed-package bitstream slot is admitted
    // and validated, and NO installer path writes it.
    //
    // Self-match note:
    // the haystack below is the *sysupgrade shell script*, never this file, so
    // the banned literals in these assertions are not part of what is searched.
    // Line handling is CRLF-tolerant by construction (`trim_end`).
    // ---------------------------------------------------------------------

    const SYSUPGRADE_SRC: &str =
        include_str!("../../../br2_external_dcentos/board/zynq/rootfs-overlay/usr/sbin/sysupgrade");

    /// Every command in the installer that can persistently mutate flash.
    const FLASH_WRITE_VERBS: &[&str] = &[
        "ubiupdatevol",
        "nandwrite",
        "flash_erase",
        "mtd write",
        "dd of=",
        "fw_setenv",
        "dcent_ubi_update_volume",
    ];

    /// Every mechanism by which a Zynq fabric can be programmed.
    const FABRIC_PROGRAMMING_MECHANISMS: &[&str] = &[
        "fpga load",
        "fpga_manager",
        "xdevcfg",
        "devcfg",
        "program_bitstream",
    ];

    fn sysupgrade_lines() -> Vec<(usize, String)> {
        SYSUPGRADE_SRC
            .split('\n')
            .enumerate()
            .map(|(i, l)| (i + 1, l.trim_end_matches('\r').to_string()))
            .collect()
    }

    #[test]
    fn sysupgrade_source_is_present_and_anchored() {
        // If this count drifts, the bitstream admission logic changed and every
        // contract below must be re-read, not silently re-anchored.
        let hits = SYSUPGRADE_SRC.matches("fpga_bitstream.bit").count();
        assert_eq!(
            hits, 6,
            "fpga_bitstream.bit occurrence count changed ({hits}); \
             re-read the bitstream admission logic before touching this contract"
        );
    }

    #[test]
    fn no_installer_line_mentioning_a_bitstream_performs_a_flash_write() {
        let mut offenders = Vec::new();
        for (lineno, line) in sysupgrade_lines() {
            let lower = line.to_ascii_lowercase();
            if !lower.contains("bitstream") {
                continue;
            }
            for verb in FLASH_WRITE_VERBS {
                if lower.contains(verb) {
                    offenders.push(format!("{lineno}: {line}"));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "GAP-C2-2 REFUSAL VIOLATED — a bitstream-bearing line now writes flash.\n\
             A package-directed bitstream write on a Zynq whose BOOT.bin carries the \
             RSA-verified fabric stage is a brick vector with no software route back. \
             Offending lines:\n{}",
            offenders.join("\n")
        );
    }

    #[test]
    fn installer_contains_no_fabric_programming_mechanism_at_all() {
        let lower = SYSUPGRADE_SRC.to_ascii_lowercase();
        for mechanism in FABRIC_PROGRAMMING_MECHANISMS {
            assert!(
                !lower.contains(mechanism),
                "installer gained a fabric-programming mechanism ({mechanism}); \
                 the bitstream slot must stay a validated no-op"
            );
        }
    }

    #[test]
    fn the_only_flash_writes_target_kernel_and_rootfs() {
        let writes: Vec<String> = sysupgrade_lines()
            .into_iter()
            .filter(|(_, l)| {
                let t = l.trim_start();
                // Skip comments and the refusal/diagnostic `echo` lines that
                // deliberately NAME the banned raw-write path.
                !t.starts_with('#')
                    && !t.starts_with("echo")
                    && FLASH_WRITE_VERBS.iter().any(|v| l.contains(v))
            })
            .map(|(n, l)| format!("{n}: {}", l.trim()))
            .collect();
        for w in &writes {
            let lower = w.to_ascii_lowercase();
            assert!(
                !lower.contains("bitstream"),
                "a flash-write site now references a bitstream: {w}"
            );
        }
        // Positive half: the kernel and rootfs writes must still be there, so
        // this contract cannot pass by the installer having lost its writes.
        assert!(
            writes.iter().any(|w| w.contains("dcent_ubi_update_volume 1 0 \"$KERNEL_SOURCE\"")),
            "kernel volume write vanished; contract is no longer meaningful"
        );
        assert!(
            writes.iter().any(|w| w.contains("dcent_ubi_update_volume 1 1 \"$ROOTFS\"")),
            "rootfs volume write vanished; contract is no longer meaningful"
        );
    }

    #[test]
    fn the_bitstream_slot_is_still_strictly_validated() {
        // The refusal is "validate and ignore", not "ignore". If the validation
        // is deleted, an unsigned bitstream could ride along in a signed
        // package — so the no-op must stay a *checked* no-op.
        assert_eq!(
            SYSUPGRADE_SRC
                .matches("validate_manifest_payload_binding bitstream fpga_bitstream.bit")
                .count(),
            1,
            "the bitstream payload/manifest hash binding must remain exactly once"
        );
        assert!(
            SYSUPGRADE_SRC
                .contains("Package contains fpga_bitstream.bit without exactly one signed bitstream declaration"),
            "present-payload-without-declaration refusal must remain"
        );
        assert!(
            SYSUPGRADE_SRC
                .contains("Package manifest declares bitstream but fpga_bitstream.bit is absent"),
            "declared-without-payload refusal must remain"
        );
    }
}
