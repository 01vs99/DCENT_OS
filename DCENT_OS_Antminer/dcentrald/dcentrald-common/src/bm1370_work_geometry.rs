//! BM1370 work-space research, independent of hardware transport and admission.
//!
//! Sources: S21 Pro factory wire observations in Mujina REFERENCE.md at
//! 019d1b0916457bb7ecd7cb7e93fee63c0329f9a2 (nonce response, domain boundaries,
//! nonce offsets, HCN); held S21 Pro/XP board geometry in our silicon profiles.
//! The offset-to-counter mapping and ~130-tick overrun were measured on one
//! BM1370, not validated on an industrial chain. These plans are diagnostic
//! data, deliberately not TransportOps or permission to change a live chain.
//! Nominal 128 x 16 slots must not replace our separately evidenced 2040
//! effective hashing units or promote a platform's support status.

/// Architectural counter width, not a measured active-core count.
pub const BM1370_COUNTER_BITS: u32 = 25;
pub const BM1370_NOMINAL_SUBCORES: u32 = 128 * 16;
pub const BM1370_COUNTER_SPACE: u32 = 1 << BM1370_COUNTER_BITS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1370NonceFields {
    pub core_id: u8,
    pub counter: u32,
}

impl Bm1370NonceFields {
    /// Input is the header nonce (little-endian wire interpretation), NOT a
    /// platform-specific FPGA FIFO word. No chip address is encoded here.
    pub const fn from_header_nonce(nonce: u32) -> Self {
        Self::from_wire_field_word(nonce.swap_bytes())
    }

    /// Input interprets the four received nonce bytes most significant first.
    pub const fn from_wire_field_word(word: u32) -> Self {
        Self {
            core_id: (word >> 25) as u8,
            counter: word & (BM1370_COUNTER_SPACE - 1),
        }
    }
}

/// A candidate range attribution is not verified physical chip identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1370Attribution {
    Unknown,
    Candidate { address: u8 },
    Ambiguous,
}

/// The industrial FPGA path has no admitted offset schedule / range witness.
/// Callers must retain shares but exclude them from per-chip control decisions.
pub const fn bm1370_physical_chip_index() -> Option<u8> {
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkGeometryError {
    UnsupportedTopology,
    InvalidPll,
    InvalidWindow,
    GuardExhaustsWindow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterWindow {
    pub address: u8,
    pub offset: u16,
    /// Includes measured/assumed overrun when using this for replay.
    pub candidates: u32,
}

impl CounterWindow {
    pub fn contains(self, counter: u32) -> bool {
        counter < BM1370_COUNTER_SPACE
            && self.candidates > 0
            && self.candidates <= BM1370_COUNTER_SPACE
            && (counter.wrapping_sub(u32::from(self.offset) << 9) & (BM1370_COUNTER_SPACE - 1))
                < self.candidates
    }
}

pub fn replay_attribution(
    fields: Bm1370NonceFields,
    windows: &[CounterWindow],
) -> Bm1370Attribution {
    let mut matched = None;
    for window in windows
        .iter()
        .filter(|window| window.contains(fields.counter))
    {
        if matched.replace(window.address).is_some() {
            return Bm1370Attribution::Ambiguous;
        }
    }
    matched.map_or(Bm1370Attribution::Unknown, |address| {
        Bm1370Attribution::Candidate { address }
    })
}

/// Dividers decoded from BM136x/1370 PLL0's minus-one postdivider format.
/// This is arithmetic evidence only; model-specific VCO limits remain owned
/// by the existing PLL solver and admission policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashClockDividers {
    feedback: u16,
    reference: u8,
    post1: u8,
    post2: u8,
}

impl HashClockDividers {
    pub fn from_pll0(register: u32) -> Result<Self, WorkGeometryError> {
        let feedback = ((register >> 16) & 0x0fff) as u16;
        let reference = ((register >> 8) & 0x3f) as u8;
        let post1 = ((register >> 4) & 0xf) as u8 + 1;
        let post2 = (register & 0xf) as u8 + 1;
        if register & 0x4000_0000 == 0
            || register & 0x2000_c000 != 0
            || feedback == 0
            || reference == 0
            || post1 > 7
            || post2 > 7
        {
            return Err(WorkGeometryError::InvalidPll);
        }
        Ok(Self {
            feedback,
            reference,
            post1,
            post2,
        })
    }

    fn divisor(self) -> u64 {
        u64::from(self.reference) * u64::from(self.post1) * u64::from(self.post2)
    }

    /// Floor once, using the ACTUAL solved PLL rather than rounded target MHz.
    /// `slice` is an explicit core-counter window, never inferred from a
    /// nameplate core count or rounded chip count. `guard_ticks` is supplied
    /// evidence/policy; no unmeasured model inherits the BM1370 experiment.
    pub fn hcn_for_window(self, slice: u32, guard_ticks: u32) -> Result<u32, WorkGeometryError> {
        if slice == 0 || slice > BM1370_COUNTER_SPACE {
            return Err(WorkGeometryError::InvalidWindow);
        }
        let ticks = u64::from(slice) * self.divisor() / (2 * u64::from(self.feedback));
        let guarded = ticks
            .checked_sub(u64::from(guard_ticks))
            .filter(|v| *v > 0)
            .ok_or(WorkGeometryError::GuardExhaustsWindow)?;
        u32::try_from(guarded).map_err(|_| WorkGeometryError::InvalidWindow)
    }

    /// Predicted candidates for an observed HCN, including an explicit overrun.
    pub fn window_for_hcn(self, hcn: u32, overrun_ticks: u32) -> u64 {
        (u64::from(hcn) + u64::from(overrun_ticks)) * 2 * u64::from(self.feedback) / self.divisor()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResearchRegisterWrite {
    pub address: u8,
    pub register: u8,
    pub value: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResearchBroadcastWrite {
    pub register: u8,
    pub value: u32,
}

/// Research plan for the exact S21 Pro geometry. Captured first/second/last
/// offsets constrain the rational schedule; intermediate values are derived,
/// not claimed as independently captured. No SKU identity is inferred here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S21ProWorkResearchPlan {
    /// Apply only after a first work frame in the captured sequence.
    pub offsets_after_first_job: Vec<ResearchRegisterWrite>,
    /// First phase: last-chip clock drive, in increasing chain address order.
    pub boundary_clock_writes: Vec<ResearchRegisterWrite>,
    /// Captured broadcast separates the clock pass from the relay pass.
    pub ring_pad_guard: ResearchBroadcastWrite,
    /// Third phase: relay pass, far domains first, both ends of each domain.
    pub boundary_relay_writes: Vec<ResearchRegisterWrite>,
    pub smallest_counter_slice: u32,
}

/// Runtime-visible arithmetic assessment; no values in this structure are
/// permission to change PLL, HCN, offsets, or domain register configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1370WindowAssessment {
    pub configured_window_candidates: u64,
    pub candidate_hcn_with_experimental_guard: Option<u32>,
    pub physical_chip_attribution: Option<u8>,
}

pub fn assess_bm1370_window(
    pll0: u32,
    declared_chips: u16,
    hcn: u32,
) -> Result<Bm1370WindowAssessment, WorkGeometryError> {
    let clock = HashClockDividers::from_pll0(pll0)?;
    // A declared 65-chip count permits comparison to the held S21 Pro
    // geometry, not a claim that this unit has that exact board topology.
    let candidate_hcn_with_experimental_guard = if declared_chips == 65 {
        let research = S21ProWorkResearchPlan::for_exact_topology(0x1370, 65, 13, 5)?;
        Some(clock.hcn_for_window(research.smallest_counter_slice, 200)?)
    } else {
        None
    };
    Ok(Bm1370WindowAssessment {
        configured_window_candidates: clock.window_for_hcn(hcn, 0),
        candidate_hcn_with_experimental_guard,
        physical_chip_attribution: bm1370_physical_chip_index(),
    })
}

impl S21ProWorkResearchPlan {
    pub fn for_exact_topology(
        chip_id: u16,
        chips: u16,
        domains: u8,
        per_domain: u8,
    ) -> Result<Self, WorkGeometryError> {
        if (chip_id, chips, domains, per_domain) != (0x1370, 65, 13, 5) {
            return Err(WorkGeometryError::UnsupportedTopology);
        }
        // Factory capture: second offset 0x03F1, final 0xFC10. Round the
        // complete index product upward; a fixed rounded stride drifts.
        let offsets_after_first_job = (0..65_u32)
            .map(|index| ResearchRegisterWrite {
                address: (index * 2) as u8,
                register: 0x0c,
                value: 0x8000_0000 | (index * 65_536).div_ceil(65),
            })
            .collect::<Vec<_>>();
        let boundary_clock_writes = (0..13_u8)
            .map(|domain| ResearchRegisterWrite {
                address: domain * 10 + 8,
                register: 0x58,
                value: 0x0001_f111,
            })
            .collect();
        let mut boundary_relay_writes = Vec::with_capacity(26);
        for domain in (0..13_u8).rev() {
            let first = domain * 10;
            let last = first + 8;
            // S21 Pro capture: gap 0x4F at near domain to 0x13 at far.
            let relay = (u32::from(0x4f - domain * 5) << 16) | 3;
            boundary_relay_writes.push(ResearchRegisterWrite {
                address: first,
                register: 0x2c,
                value: relay,
            });
            boundary_relay_writes.push(ResearchRegisterWrite {
                address: last,
                register: 0x2c,
                value: relay,
            });
        }
        Ok(Self {
            offsets_after_first_job,
            boundary_clock_writes,
            ring_pad_guard: ResearchBroadcastWrite {
                register: 0x68,
                value: 0x5aa5_5aa5,
            },
            boundary_relay_writes,
            smallest_counter_slice: (65_536 / 65) << 9,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bm1370_captured_header_nonce_has_counter_not_chip_address() {
        // Public Bitaxe wire RX nonce bytes 18 00 A6 40; header nonce 40A60018.
        let fields = Bm1370NonceFields::from_header_nonce(0x40a6_0018);
        assert_eq!(
            fields,
            Bm1370NonceFields {
                core_id: 12,
                counter: 0xa640
            }
        );
        assert_eq!(bm1370_physical_chip_index(), None);
        assert_eq!(BM1370_NOMINAL_SUBCORES, 2048);
    }

    #[test]
    fn bm1370_replay_handles_wrap_holes_and_overlap_without_promoting_identity() {
        let wrap = CounterWindow {
            address: 2,
            offset: 0xffff,
            candidates: 1024,
        };
        assert!(wrap.contains(BM1370_COUNTER_SPACE - 1));
        assert!(wrap.contains(0));
        assert!(!wrap.contains(512));
        let fields = Bm1370NonceFields {
            core_id: 127,
            counter: 100,
        };
        assert_eq!(
            replay_attribution(fields, &[wrap]),
            Bm1370Attribution::Candidate { address: 2 }
        );
        assert_eq!(
            replay_attribution(
                fields,
                &[
                    wrap,
                    CounterWindow {
                        address: 4,
                        offset: 0,
                        candidates: 101
                    }
                ]
            ),
            Bm1370Attribution::Ambiguous
        );
        assert_eq!(replay_attribution(fields, &[]), Bm1370Attribution::Unknown);
        assert!(!CounterWindow {
            candidates: 0,
            ..wrap
        }
        .contains(0));
    }

    #[test]
    fn bm1370_research_plan_pins_captured_endpoints_and_domain_phases() {
        let plan = S21ProWorkResearchPlan::for_exact_topology(0x1370, 65, 13, 5).unwrap();
        assert_eq!(plan.offsets_after_first_job[1].value, 0x8000_03f1);
        assert_eq!(plan.offsets_after_first_job[64].value, 0x8000_fc10);
        assert_eq!(
            plan.boundary_clock_writes[0],
            ResearchRegisterWrite {
                address: 0x08,
                register: 0x58,
                value: 0x0001_f111
            }
        );
        assert_eq!(plan.boundary_clock_writes[12].address, 0x80);
        assert_eq!(
            plan.ring_pad_guard,
            ResearchBroadcastWrite {
                register: 0x68,
                value: 0x5aa5_5aa5
            }
        );
        assert_eq!(
            plan.boundary_relay_writes[0].value.to_be_bytes(),
            [0x00, 0x13, 0x00, 0x03]
        );
        assert_eq!(
            plan.boundary_relay_writes[25].value.to_be_bytes(),
            [0x00, 0x4f, 0x00, 0x03]
        );
        for tuple in [
            (0x1362, 65, 13, 5),
            (0x1370, 91, 13, 7),
            (0x1370, 55, 11, 5),
            (0x1370, 65, 5, 13),
        ] {
            assert!(
                S21ProWorkResearchPlan::for_exact_topology(tuple.0, tuple.1, tuple.2, tuple.3)
                    .is_err()
            );
        }
    }

    #[test]
    fn actual_pll_hcn_uses_one_floor_and_explicit_guard() {
        let clock = HashClockDividers::from_pll0(0x40a8_0230).unwrap(); // 525 MHz
        assert_eq!(clock.hcn_for_window(1 << 18, 0), Ok(6241));
        assert_eq!(clock.hcn_for_window(1 << 18, 200), Ok(6041));
        assert!(clock.window_for_hcn(6041, 132) <= 1 << 18);
        let half_clock = HashClockDividers::from_pll0(0x40a8_0231).unwrap();
        assert_eq!(half_clock.hcn_for_window(1 << 18, 0), Ok(12483));
        for value in [0, 0x60a8_0230, 0x40a8_0030, 0x4000_0230, 0x40a8_0270] {
            assert_eq!(
                HashClockDividers::from_pll0(value),
                Err(WorkGeometryError::InvalidPll)
            );
        }
        assert!(clock.hcn_for_window(1, 200).is_err());
        assert!(clock.hcn_for_window(0, 0).is_err());
        let assessed = assess_bm1370_window(0x40a8_0230, 65, 0x1eb5).unwrap();
        assert_eq!(assessed.physical_chip_attribution, None);
        assert_eq!(assessed.configured_window_candidates, 330162);
        assert_eq!(assessed.candidate_hcn_with_experimental_guard, Some(12088));
        assert_eq!(
            assess_bm1370_window(0x40a8_0230, 91, 0x1eb5)
                .unwrap()
                .candidate_hcn_with_experimental_guard,
            None
        );
    }

    #[test]
    fn hcn_never_crosses_requested_window_across_fractional_clocks() {
        for fb in 160..=239_u32 {
            for post in 0..7_u32 {
                let clock =
                    HashClockDividers::from_pll0(0x4000_0200 | (fb << 16) | (post << 4)).unwrap();
                for slice in [1 << 18, 1008 << 9, 1 << 25] {
                    let hcn = clock.hcn_for_window(slice, 200).unwrap();
                    assert!(clock.window_for_hcn(hcn, 200) <= u64::from(slice));
                    assert!(clock.window_for_hcn(hcn + 1, 200) >= u64::from(slice));
                }
            }
        }
    }
}
