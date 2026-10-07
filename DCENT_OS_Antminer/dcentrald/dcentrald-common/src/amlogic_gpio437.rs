//! Exact-target GPIO437 polarity policy. Pure lookup; no GPIO or environment I/O.
//!
//! The generated table comes from `contracts/hardware/amlogic-gpio437.json`.
//! Two distinct vendors must each establish the exact model/controller join and
//! both semantic enable/disable paths to the raw pin. Shared backends, startup
//! writes and recorded observations do not satisfy that rule. Software traces
//! are not electrical measurements. A recipe supplies parameters, not release
//! admission, hardware identity, fabric ownership or permission to energize.
//!
//! Keep the returned recipe in the hardware owner through terminal SafeOff.
//! Do not resolve again from a mutable board marker during shutdown. GPIO907
//! belongs to the separate AM2 hardware recipe and never enters this table.

/// Legacy global GPIO number, after the caller has resolved the exact carrier.
pub const GPIO437: u32 = 437;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Vendor {
    Braiins,
    Vnish,
    Epic,
    Bitmain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvidenceKind {
    CompleteModelTrace,
    SharedBackendOnly,
    StartupOnly,
    RecordedModelObservation,
}

#[derive(Clone, Copy, Debug)]
struct Evidence {
    board_target: &'static str,
    hashboard_names: &'static [&'static str],
    vendor: Vendor,
    kind: EvidenceKind,
    on_raw: Option<u8>,
    off_raw: Option<u8>,
}

#[derive(Debug)]
struct BoardPolarityProfile {
    board_target: &'static str,
    hashboard_names: &'static [&'static str],
    evidence: &'static [Evidence],
}

include!("amlogic_gpio437_table.rs");

/// Refusal always means undriven, never a guessed OFF level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolarityRefusal {
    UnknownBoardTarget,
    UnknownHashboard,
    EmptyPopulation,
    InsufficientIndependentVendors { found: u8 },
    ConflictingCompleteTraces,
    InvalidEvidence,
}

/// Validated raw levels, immutable and bound to the exact requested target.
/// Only this module can construct one. `active_low` must be normalized to zero
/// by the hardware owner before using these raw sysfs values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gpio437DriveRecipe {
    board_target: &'static str,
    on_raw: u8,
    off_raw: u8,
}

impl Gpio437DriveRecipe {
    pub const fn board_target(self) -> &'static str {
        self.board_target
    }

    pub const fn on_raw(self) -> u8 {
        self.on_raw
    }

    pub const fn off_raw(self) -> u8 {
        self.off_raw
    }

    /// Glitch-free initial output direction for the established OFF level.
    pub const fn off_direction(self) -> &'static str {
        if self.off_raw == 1 {
            "high"
        } else {
            "low"
        }
    }
}

/// Exact comparison only: no trimming, sibling fallback, alias or environment.
pub fn resolve_drive_recipe(board_target: &str) -> Result<Gpio437DriveRecipe, PolarityRefusal> {
    qualify(find_profile(board_target)?)
}

/// Boot has no live hashboard identity. Only complete revision coverage can
/// supply an output level; a known but unqualified profile stays input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootGpio437Policy {
    QualifiedOff(Gpio437DriveRecipe),
    Undriven,
}

pub fn resolve_boot_policy(board_target: &str) -> Result<BootGpio437Policy, PolarityRefusal> {
    let profile = find_profile(board_target)?;
    Ok(match qualify(profile) {
        Ok(recipe) => BootGpio437Policy::QualifiedOff(recipe),
        Err(_) => BootGpio437Policy::Undriven,
    })
}

fn find_profile(board_target: &str) -> Result<&'static BoardPolarityProfile, PolarityRefusal> {
    PROFILES
        .iter()
        .find(|profile| profile.board_target == board_target)
        .ok_or(PolarityRefusal::UnknownBoardTarget)
}

/// Resolve only after independently validating a hashboard's live identity.
/// A partial source covers its explicit names, never an unproved sibling.
pub fn resolve_identity_recipe(
    board_target: &str,
    hashboard_name: &str,
) -> Result<Gpio437DriveRecipe, PolarityRefusal> {
    qualify_identity(find_profile(board_target)?, hashboard_name)
}

/// Every selected board must have a qualified identity and agree on raw levels.
/// The caller retains this result with the same population's hardware owner.
pub fn resolve_population_recipe(
    board_target: &str,
    hashboard_names: &[&str],
) -> Result<Gpio437DriveRecipe, PolarityRefusal> {
    let profile = find_profile(board_target)?;
    let (first, rest) = hashboard_names
        .split_first()
        .ok_or(PolarityRefusal::EmptyPopulation)?;
    let recipe = qualify_identity(profile, first)?;
    for name in rest {
        if qualify_identity(profile, name)? != recipe {
            return Err(PolarityRefusal::ConflictingCompleteTraces);
        }
    }
    Ok(recipe)
}

fn qualify(profile: &BoardPolarityProfile) -> Result<Gpio437DriveRecipe, PolarityRefusal> {
    let (first, rest) = profile
        .hashboard_names
        .split_first()
        .ok_or(PolarityRefusal::InvalidEvidence)?;
    let recipe = qualify_identity(profile, first)?;
    for name in rest {
        if qualify_identity(profile, name)? != recipe {
            return Err(PolarityRefusal::ConflictingCompleteTraces);
        }
    }
    Ok(recipe)
}

fn qualify_identity(
    profile: &BoardPolarityProfile,
    hashboard_name: &str,
) -> Result<Gpio437DriveRecipe, PolarityRefusal> {
    if !profile.hashboard_names.contains(&hashboard_name) {
        return Err(PolarityRefusal::UnknownHashboard);
    }
    let mut vendors = [false; 4];
    let mut levels = None;
    for evidence in profile.evidence {
        if evidence.board_target != profile.board_target {
            return Err(PolarityRefusal::InvalidEvidence);
        }
        if evidence.kind != EvidenceKind::CompleteModelTrace
            || !evidence.hashboard_names.contains(&hashboard_name)
        {
            continue;
        }
        let pair = match (evidence.on_raw, evidence.off_raw) {
            (Some(on @ 0..=1), Some(off @ 0..=1)) if on != off => (on, off),
            _ => return Err(PolarityRefusal::InvalidEvidence),
        };
        if let Some(previous) = levels {
            if previous != pair {
                return Err(PolarityRefusal::ConflictingCompleteTraces);
            }
        }
        levels = Some(pair);
        vendors[evidence.vendor as usize] = true;
    }
    let found = vendors.iter().filter(|present| **present).count() as u8;
    if found < 2 {
        return Err(PolarityRefusal::InsufficientIndependentVendors { found });
    }
    let (on_raw, off_raw) = levels.ok_or(PolarityRefusal::InvalidEvidence)?;
    Ok(Gpio437DriveRecipe {
        board_target: profile.board_target,
        on_raw,
        off_raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOW: Evidence = Evidence {
        board_target: "test-exact",
        hashboard_names: &["TEST01"],
        vendor: Vendor::Braiins,
        kind: EvidenceKind::CompleteModelTrace,
        on_raw: Some(0),
        off_raw: Some(1),
    };

    fn resolve(evidence: &'static [Evidence]) -> Result<Gpio437DriveRecipe, PolarityRefusal> {
        qualify(&BoardPolarityProfile {
            board_target: "test-exact",
            hashboard_names: &["TEST01"],
            evidence,
        })
    }

    #[test]
    fn two_distinct_vendors_establish_immutable_raw_levels() {
        let recipe = resolve(&[
            LOW,
            Evidence {
                vendor: Vendor::Vnish,
                ..LOW
            },
        ])
        .unwrap();
        assert_eq!(recipe.board_target(), "test-exact");
        assert_eq!(
            (recipe.on_raw(), recipe.off_raw(), recipe.off_direction()),
            (0, 1, "high")
        );
        const HIGH: Evidence = Evidence {
            on_raw: Some(1),
            off_raw: Some(0),
            ..LOW
        };
        let recipe = resolve(&[
            HIGH,
            Evidence {
                vendor: Vendor::Epic,
                ..HIGH
            },
        ])
        .unwrap();
        assert_eq!(
            (recipe.on_raw(), recipe.off_raw(), recipe.off_direction()),
            (1, 0, "low")
        );
    }

    #[test]
    fn same_vendor_repackaging_and_incomplete_sources_cannot_admit() {
        for evidence in [
            &[LOW][..],
            &[LOW, LOW][..],
            &[
                LOW,
                Evidence {
                    vendor: Vendor::Vnish,
                    kind: EvidenceKind::StartupOnly,
                    ..LOW
                },
            ][..],
            &[
                LOW,
                Evidence {
                    vendor: Vendor::Epic,
                    kind: EvidenceKind::SharedBackendOnly,
                    ..LOW
                },
            ][..],
            &[
                LOW,
                Evidence {
                    vendor: Vendor::Bitmain,
                    kind: EvidenceKind::RecordedModelObservation,
                    ..LOW
                },
            ][..],
        ] {
            assert_eq!(
                resolve(evidence),
                Err(PolarityRefusal::InsufficientIndependentVendors { found: 1 })
            );
        }
    }

    #[test]
    fn any_complete_conflict_refuses_even_after_two_agree() {
        assert_eq!(
            resolve(&[
                LOW,
                Evidence {
                    vendor: Vendor::Vnish,
                    ..LOW
                },
                Evidence {
                    vendor: Vendor::Epic,
                    on_raw: Some(1),
                    off_raw: Some(0),
                    ..LOW
                },
            ]),
            Err(PolarityRefusal::ConflictingCompleteTraces)
        );
        assert_eq!(
            resolve(&[
                LOW,
                Evidence {
                    on_raw: Some(1),
                    off_raw: Some(0),
                    ..LOW
                }
            ]),
            Err(PolarityRefusal::ConflictingCompleteTraces)
        );
    }

    #[test]
    fn malformed_or_wrong_target_evidence_refuses() {
        assert_eq!(
            resolve(&[
                LOW,
                Evidence {
                    board_target: "test-sibling",
                    vendor: Vendor::Vnish,
                    ..LOW
                }
            ]),
            Err(PolarityRefusal::InvalidEvidence)
        );
        assert_eq!(
            resolve(&[
                LOW,
                Evidence {
                    vendor: Vendor::Vnish,
                    on_raw: Some(2),
                    ..LOW
                }
            ]),
            Err(PolarityRefusal::InvalidEvidence)
        );
        assert_eq!(
            resolve(&[
                LOW,
                Evidence {
                    vendor: Vendor::Vnish,
                    off_raw: Some(0),
                    ..LOW
                }
            ]),
            Err(PolarityRefusal::InvalidEvidence)
        );
        assert_eq!(
            resolve(&[
                LOW,
                Evidence {
                    vendor: Vendor::Vnish,
                    off_raw: None,
                    ..LOW
                }
            ]),
            Err(PolarityRefusal::InvalidEvidence)
        );
    }

    #[test]
    fn unknown_targets_have_no_grandfathered_drive_permission() {
        for target in [
            "",
            "am2-s19j",
            "am3-s21plus",
            "AM3-S21",
            "am3-s21 ",
            "am3-s19xp\n",
        ] {
            assert_eq!(
                resolve_drive_recipe(target),
                Err(PolarityRefusal::UnknownBoardTarget)
            );
        }
    }

    #[test]
    fn qualified_s19k_drive_matches_retained_historical_proof_expectations() {
        use crate::s19k_am3_gpio437::{
            S19K_AM3_GPIO437_ACTIVE_LOW, S19K_AM3_GPIO437_VALUE_OFF, S19K_AM3_GPIO437_VALUE_ON,
        };
        // These constants describe the retained S19k evidence and Track-1
        // contract. They cannot become an independent runtime polarity table.
        let recipe = resolve_drive_recipe("am3-s19k").unwrap();
        assert_eq!(recipe.on_raw(), S19K_AM3_GPIO437_VALUE_ON);
        assert_eq!(recipe.off_raw(), S19K_AM3_GPIO437_VALUE_OFF);
        assert_eq!(recipe.on_raw() == 0, S19K_AM3_GPIO437_ACTIVE_LOW);
        assert_eq!(
            resolve_boot_policy("am3-s19k"),
            Ok(BootGpio437Policy::QualifiedOff(recipe))
        );
    }

    #[test]
    fn classic_population_uses_exact_pic_revision_coverage() {
        let target = "am3-s19jpro-aml";
        let recipe =
            resolve_population_recipe(target, &["BHB42601", "BHB42621", "BHB42641"]).unwrap();
        assert_eq!(
            (recipe.on_raw(), recipe.off_raw(), recipe.off_direction()),
            (0, 1, "high")
        );
        assert_eq!(recipe.board_target(), target);
        for name in ["BHB42612", "BHB42699", "BHB426", "bhb42641"] {
            assert_eq!(
                resolve_population_recipe(target, &["BHB42601", name]),
                Err(PolarityRefusal::UnknownHashboard)
            );
        }
        assert_eq!(
            resolve_population_recipe(target, &[]),
            Err(PolarityRefusal::EmptyPopulation)
        );
        assert_eq!(
            resolve_boot_policy(target),
            Ok(BootGpio437Policy::QualifiedOff(recipe))
        );
    }

    #[test]
    fn partial_revision_trace_never_authorizes_boot_or_sibling_identity() {
        let profile = BoardPolarityProfile {
            board_target: "test-exact",
            hashboard_names: &["TEST01", "TEST02"],
            evidence: &[
                Evidence {
                    hashboard_names: &["TEST01", "TEST02"],
                    ..LOW
                },
                Evidence {
                    vendor: Vendor::Vnish,
                    ..LOW
                },
            ],
        };
        assert!(qualify_identity(&profile, "TEST01").is_ok());
        assert_eq!(
            qualify_identity(&profile, "TEST02"),
            Err(PolarityRefusal::InsufficientIndependentVendors { found: 1 })
        );
        assert_eq!(
            qualify(&profile),
            Err(PolarityRefusal::InsufficientIndependentVendors { found: 1 })
        );
        assert_eq!(
            qualify_identity(&profile, "TEST03"),
            Err(PolarityRefusal::UnknownHashboard)
        );
    }
}
