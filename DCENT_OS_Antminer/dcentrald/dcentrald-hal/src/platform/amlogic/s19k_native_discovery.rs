//! SPDX-License-Identifier: GPL-3.0-or-later
//! DCENT-owned passive service discovery for the native S19k executor.
//!
//! Campaign `2026-09-07-antminer-beta-execution`, lane R11 (S19k native
//! clean-image operation, acceptance: "a clean DCENT rootfs reaches the
//! native executor without bos_* or raw I2C tools"). This module is the
//! native-mode replacement for the inherited overlay-file discovery:
//!
//! - it reads exactly one DCENT-owned marker file
//!   (`/etc/dcentos-platform`, written by the clean Buildroot rootfs
//!   overlay and sealed by `S37board_setup`);
//! - it performs NO subprocess of any kind (no I2C helper tools, no
//!   environment tools), NO bus transaction, NO inherited-binary receipt
//!   hashing, and NO read of any Braiins overlay configuration file;
//! - every failure is fail-closed: a missing marker, an unqualified
//!   marker value, or a marker naming a different SKU refuses native
//!   S19k admission before any hardware evidence is collected.
//!
//! The inherited Track-1 path keeps its own overlay-file/I2C-helper/
//! receipt-bound inherited discovery (`serial_mining::s19k_capture_live_identity`)
//! untouched and separate; native mode deliberately does not consume it.
//! Cross-checks that complete the identity join live in
//! [`super::S19kNativeAggregateAdmission::detect`]: the boot-safe handoff
//! receipt binds `/etc/dcentos/platform`, `/etc/dcentos/board_target`,
//! the live `boot_id`, the GPIO437 rail marker, and live sysfs rail/PWM/
//! reset revalidation to the same generation before any mutation.

use super::AmlogicNoPicProfile;
use crate::{HalError, Result};
use std::fs;

/// The only file this discovery reads. Written by the DCENT clean rootfs
/// (`br2_external_dcentos/board/amlogic/rootfs-overlay`); absent on stock
/// or Braiins overlay rootfs images, which therefore refuse native mode.
pub(super) const DCENT_PLATFORM_MARKER: &str = "/etc/dcentos-platform";

/// Marker values that discover the exact native S19k identity. The generic
/// cross-SKU `am3-aml` marker and every other SKU-qualified value refuse:
/// a marker that names a different control board must never be upgraded to
/// S19k by substring, config, or adjacency evidence.
pub(super) fn s19k_profile_from_dcent_marker(marker: &str) -> Option<AmlogicNoPicProfile> {
    match super::nopic_profile_for_dcentos_marker(marker) {
        Some(profile @ AmlogicNoPicProfile::S19k) => Some(profile),
        _ => None,
    }
}

/// Passive DCENT-owned profile discovery for native S19k admission.
///
/// Read-only, single-file, fail-closed. This replaces the previous native
/// consultation of [`super::detect_amlogic_nopic_profile`], whose second
/// priority source is the Braiins overlay model file: that inherited
/// source remains available to overlay/Track-1 consumers but is no longer
/// part of the native discovery chain at all.
pub(super) fn detect_dcent_owned_profile() -> Result<AmlogicNoPicProfile> {
    let marker = fs::read_to_string(DCENT_PLATFORM_MARKER).map_err(|error| {
        HalError::Platform(format!(
            "native S19k discovery requires the DCENT platform marker {DCENT_PLATFORM_MARKER}: {error}; Braiins overlay files are not native identity evidence"
        ))
    })?;
    s19k_profile_from_dcent_marker(&marker).ok_or_else(|| {
        HalError::Platform(format!(
            "native S19k discovery: {DCENT_PLATFORM_MARKER} value {:?} is not the exact SKU-qualified am3-aml S19k identity",
            marker.trim()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dcent_marker_discovers_exact_s19k_only() {
        assert_eq!(
            s19k_profile_from_dcent_marker("am3-aml-s19k"),
            Some(AmlogicNoPicProfile::S19k)
        );
        // The live S19k Pro alias shares the same single native profile.
        assert_eq!(
            s19k_profile_from_dcent_marker("am3-aml-s19kpro"),
            Some(AmlogicNoPicProfile::S19k)
        );
        // Trailing newline/whitespace is rootfs formatting, not identity.
        assert_eq!(
            s19k_profile_from_dcent_marker("am3-aml-s19k\n"),
            Some(AmlogicNoPicProfile::S19k)
        );
        // A different SKU-qualified marker is a refusal, never a fallback.
        for other in [
            "am3-aml-s21",
            "am3-aml-s21pro",
            "am3-aml-s21xp",
            "am3-aml-s19xp",
            "am3-aml-s19jxp",
        ] {
            assert_eq!(
                s19k_profile_from_dcent_marker(other),
                None,
                "marker {other} must not discover S19k"
            );
        }
        // Generic, empty, garbage, and non-marker values refuse (fail-closed).
        for bad in [
            "",
            "am3-aml",
            "S19K Pro",
            "am3-s19k",
            "am3-aml-s19k-extra",
            "bhb56902",
        ] {
            assert_eq!(
                s19k_profile_from_dcent_marker(bad),
                None,
                "marker {bad:?} must not discover S19k"
            );
        }
    }

    #[test]
    fn native_discovery_consumes_no_inherited_identity_source() {
        // Structural, not aspirational: this file is the whole native
        // discovery surface, so the forbidden-source list is checked against
        // the implementation half of its own bytes (the test module below
        // necessarily spells the forbidden names out).
        let source = include_str!("s19k_native_discovery.rs");
        let implementation_end = source
            .find("#[cfg(test)]")
            .expect("discovery module test section marker");
        let implementation = &source[..implementation_end];
        for forbidden in [
            "bos_platform",
            "bos_mode",
            "bosminer",
            "i2cget",
            "i2cdetect",
            "Command::new",
            "runner",
            "DCENT_S19K_LIVE_IDENTITY_SHA256",
        ] {
            assert!(
                !implementation.contains(forbidden),
                "native S19k discovery implementation must not reference {forbidden}"
            );
        }
        // Exactly one file read, and it is the DCENT marker constant.
        assert_eq!(implementation.matches("fs::read_to_string").count(), 1);
        assert!(implementation.contains("DCENT_PLATFORM_MARKER: &str = \"/etc/dcentos-platform\""));
    }

    #[test]
    fn aggregate_native_detect_wires_dcent_owned_discovery() {
        let source = include_str!("mod.rs");
        let start = source
            .find("impl S19kNativeAggregateAdmission")
            .expect("aggregate S19k admission implementation");
        let end = source[start..]
            .find("impl S19kNativePopulationAdmission")
            .map(|offset| start + offset)
            .expect("aggregate S19k admission implementation end");
        let body = &source[start..end];
        // The native aggregate admission uses the DCENT-owned discovery…
        assert!(body.contains("s19k_native_discovery::detect_dcent_owned_profile()"));
        // …and no longer consults the shared multi-source detector whose
        // fallback chain includes the Braiins overlay file.
        assert!(!body.contains("detect_amlogic_nopic_profile"));
        assert!(!body.contains("bosminer"));
        assert!(!body.contains("i2cget"));
        assert!(!body.contains("i2cdetect"));
    }

    #[test]
    fn discovery_error_names_the_missing_dcent_marker() {
        let source = include_str!("s19k_native_discovery.rs");
        // Fail-closed refusal text must tell the operator which DCENT-owned
        // evidence is missing and that Braiins files grant nothing native.
        assert!(source.contains("requires the DCENT platform marker"));
        assert!(source.contains("Braiins overlay files are not native identity evidence"));
        assert!(source.contains("is not the exact SKU-qualified am3-aml S19k identity"));
    }
}
