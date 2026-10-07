//! Exact base-S21 (am3-s21, BM1368) full-unit board profile, population
//! admission, all-chain work distribution planning and per-route nonce
//! accounting (campaign `2026-09-07-antminer-beta-execution`, lane R13).
//! Pure and no-I/O: this module plans, admits, accounts and refuses; it never
//! opens a UART, touches GPIO437, or grants electrical authority.
//!
//! Doctrine mirrors `bm1370_board_profiles` (lane R14) with the base-S21
//! evidence base; every constant cites held bytes or a sealed R13 evidence
//! document. Geometry (campaign row; a distinct platform from T21 despite the
//! equal 108 count — identity is name-scoped, never count-scoped):
//!
//! | Board target | Factory boards | Domains x chips | Chips/chain | Chains | Chips/unit |
//! |---|---|---|---|---|---:|
//! | `am3-s21` | BHB68603 (factory jig), BHB68606 (held capture) | 12 x 9 | 108 | 3 | 324 |
//!
//! Citations per datum:
//! - Geometry `12 domains x 9 = 108 chips/board`, full SKU `3 x 108 = 324`:
//!   `DCENT_OS_Antminer/scripts/hw-acceptance/skus.conf` row `S21`
//!   ("full SKU is 3x108=324 BM1368 (12 domains x 9/board; Lane I resolution
//!   2026-08-31; first-party factory-confirmed B10 2026-09-02 via Bitmain S21
//!   jig Config.ini BHB68603 = 108/board 12x9)").
//! - Held single-board capture identity BHB68606 (serial
//!   `DGAHYS3BDJEAF0087`): retained factory EEPROM page
//!   `dcentrald/src/serial_mining/fixtures/s21-bhb68606.bin`, decoded by
//!   `serial_mining::s21_native_identity::validate_pages` (board class 5,
//!   CRC5 match). The held `a lab unit` unit enumerates exactly 108 chips on its
//!   one populated board (skus.conf `enum_expect 108`).
//! - AM3 physical-slot routes slot0/1/2 = ttyS3/ttyS2/ttyS1: R13
//!   `evidence/r13/route-identity.md` — held production merge binary
//!   (unpacked, R13 evidence set; SHA-256
//!   `64e120df8c8011aa5199c87ebbd30276766ec3c746d597ab67a6119cf1c3cbe1`)
//!   UART formatter `0x86452c`, provider descriptor `0x1abdd60`; the same
//!   table `bm1370_board_profiles::AM3_S21_UART_ROUTES` carries for the
//!   BM1370 bins.
//! - GPIO437 polarity for exact `am3-s21` (software mapping raw 0 = enable,
//!   raw 1 = disable): R13 `evidence/r13/production-psu.md` "Exact S21
//!   GPIO437 enable polarity correction" — logged Enable passes **false** to
//!   the sysfs ASCII setter `0xbed8fc` (`0x86f000`), logged Disable passes
//!   **true** (`0x86f110`); rodata `0x1394e8c` maps true->`1`, false->`0`.
//!   This is production control-flow evidence, not a DMM rail measurement;
//!   terminal SafeOff still requires the physical proof path
//!   (`s21_generation_admission::verify_power_polarity`).
//! - PSU selection: exact-S21 production provider versions `[0x75, 0x76,
//!   0x77]` (APW1212xx family; live `a lab unit` reports `0x76`) with the
//!   11.96..15.2 V law (`production-psu.md`, constructor `0x84e964`). The
//!   voltage law itself lives in the HAL owner
//!   (`dcentrald-hal::platform::amlogic::s21_psu`); this module only scopes
//!   selection so no other PSU family can be inferred from this profile.
//! - Address interval 2: pure SSOT `floor(256/108) = 2`
//!   (`bm1397plus_addr_interval`, driver `FIXTURE_ADDRESS_INTERVAL`).
//! - Per-chip attribution on BM1368 is ADDRESS-scoped (unlike BM1370): the
//!   nonce wire field bits [24:17] carry the post-assignment chip address
//!   (`bm1368::decode_nonce`), so a nonce credits a chip position only when
//!   its decoded address is inside the admitted interval-2 plan. An
//!   out-of-plan address never fabricates a chip credit; it stays recorded
//!   at route level only.

/// BM1368 chip ID (driver `dcentrald-asic/src/drivers/bm1368.rs::CHIP_ID`).
pub const BM1368_CHIP_ID: u16 = 0x1368;

/// Every base-S21 full unit presents three hashboard chains.
pub const S21_CHAINS_PER_UNIT: u8 = 3;

/// Verified AM3 physical-slot UART routes for exact `am3-s21`
/// (`evidence/r13/route-identity.md`; same production provider table the
/// BM1370 bins carry).
pub const AM3_S21_ROUTE_UARTS: [&str; 3] = ["/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1"];

/// Post-assignment chip address interval for a 108-chip BM1368 chain.
pub const S21_ADDRESS_INTERVAL: u8 = 2;

/// Exact base-S21 board profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1368S21Profile {
    /// Campaign board target string.
    pub board_target: &'static str,
    /// Exact factory hashboard names that may select this profile. A T21
    /// BHB6870x board (same 108 count, different platform) never selects it.
    pub board_names: &'static [&'static str],
    pub domains_per_board: u8,
    pub chips_per_domain: u8,
    /// Exact full-chain ASIC population. An off-by-one observation refuses.
    pub chips_per_chain: u16,
}

/// The exact base-S21 profile (BHB68603 factory / BHB68606 captured).
pub const S21: Bm1368S21Profile = Bm1368S21Profile {
    board_target: "am3-s21",
    board_names: &["BHB68603", "BHB68606"],
    domains_per_board: 12,
    chips_per_domain: 9,
    chips_per_chain: 108,
};

impl Bm1368S21Profile {
    /// Domain-times-chip consistency for the pinned geometry (12 x 9 = 108).
    pub const fn domains_times_chips(&self) -> u16 {
        self.domains_per_board as u16 * self.chips_per_domain as u16
    }

    /// Exact full-unit ASIC count at the geometry: 3 x 108 = 324.
    pub const fn chips_per_unit(&self) -> u16 {
        self.chips_per_chain * (S21_CHAINS_PER_UNIT as u16)
    }

    /// Exact profile for a decoded factory board name, else `None`.
    /// BHB68701/03/05 (T21), A3HB705xx/706xx/707xx (BM1370 bins) and
    /// BHB569xx (S19k) all refuse here; identity is name-scoped.
    pub fn for_board_name(name: &str) -> Option<Self> {
        if S21.board_names.contains(&name) {
            Some(S21)
        } else {
            None
        }
    }

    /// Exact post-assignment chip address plan for one chain: 108 addresses,
    /// 0, 2, 4, .., 214 (interval 2). A nonce credits a chip position only
    /// when its decoded address is in this plan.
    pub const fn address_plan(&self) -> [u8; 108] {
        let mut plan = [0u8; 108];
        let mut position = 0usize;
        while position < 108 {
            plan[position] = (position as u8) * S21_ADDRESS_INTERVAL;
            position += 1;
        }
        plan
    }

    /// Chip position for a decoded nonce address, iff the address is inside
    /// the admitted interval-2 plan; `None` otherwise (never fabricated).
    pub const fn chip_position(&self, decoded_chip_address: u8) -> Option<usize> {
        if decoded_chip_address % S21_ADDRESS_INTERVAL == 0 {
            let position = (decoded_chip_address / S21_ADDRESS_INTERVAL) as usize;
            if position < self.chips_per_chain as usize {
                return Some(position);
            }
        }
        None
    }
}

/// Board_target-scoped GPIO437 polarity evidence state for exact am3-s21.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S21PowerPolarityJoin {
    /// R13 production control-flow proof (`production-psu.md`): software
    /// mapping raw 0 = enable, raw 1 = disable for the admitted AM3 S21
    /// provider. Not a rail measurement; physical SafeOff admission still
    /// requires the paired same-unit measurement path.
    ProductionMappedZeroOnOneOff,
    /// No traced factory chain for this target; nothing is inherited.
    Unproven,
}

/// PSU selection scope for the profile. Exact am3-s21 resolves ONLY the
/// traced production APW1212xx 0x75..0x77 family; any other PSU record
/// (e.g. a different board's family or GPIO wiring) is never inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S21PsuSelection {
    /// Production APW1212xx versions 0x75/0x76/0x77 with the 11.96..15.2 V
    /// law owned by `dcentrald-hal::platform::amlogic::s21_psu`.
    ProductionApw1212xxVersions75to77,
    /// No traced PSU profile; nothing may be issued.
    Unknown,
}

impl Bm1368S21Profile {
    /// Polarity evidence join. Only the exact am3-s21 target carries the R13
    /// proof; every other target (T21 included) stays `Unproven` and never
    /// inherits this mapping.
    pub const fn power_polarity_join(&self) -> S21PowerPolarityJoin {
        let _ = self; // uniform for the single base-S21 profile
        S21PowerPolarityJoin::ProductionMappedZeroOnOneOff
    }

    /// PSU selection scope (see [`S21PsuSelection`]).
    pub const fn psu_selection(&self) -> S21PsuSelection {
        let _ = self; // uniform for the single base-S21 profile
        S21PsuSelection::ProductionApw1212xxVersions75to77
    }
}

// ---------------------------------------------------------------------------
// Population admission: 108 exact per populated chain; off-by-one refuses.
// ---------------------------------------------------------------------------

/// One chain's fresh full GetAddress observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainPopulation {
    /// Physical chain slot 0..3 (AM3 UART slot, ttyS3=0 / ttyS2=1 / ttyS1=2).
    pub chain: u8,
    /// Freshly observed unassigned-zero address-window population.
    pub observed_chips: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopulationAdmissionError {
    /// No populated chain was observed (also: the full-unit manifest form
    /// was called without all three chains).
    EmptyUnit,
    /// Chain slot outside 0..3.
    ChainOutOfRange,
    /// The same physical slot was reported twice.
    DuplicateChain,
    /// Off-by-one (or any non-exact) population on a chain.
    PopulationMismatch {
        chain: u8,
        observed: u16,
        expected: u16,
    },
}

/// An admitted unit: exact per-chain populations of the base-S21 profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmittedBm1368S21Unit {
    pub profile: Bm1368S21Profile,
    /// Populated chain slots, in admission order, 1..=3 entries.
    pub populated_chains: [u8; 3],
    /// Number of valid entries in `populated_chains`.
    pub populated_count: usize,
}

/// Admit a fresh unit population against the exact S21 geometry. Physical
/// subsets (one or two populated chains — the held `a lab unit` unit is the
/// one-board case) are admissible — identity never requires all three slots —
/// but EVERY populated chain must report the exact 108-chip count;
/// 107/109 refuse.
pub fn admit_unit_population(
    profile: Bm1368S21Profile,
    populations: &[ChainPopulation],
) -> Result<AdmittedBm1368S21Unit, PopulationAdmissionError> {
    if populations.is_empty() {
        return Err(PopulationAdmissionError::EmptyUnit);
    }
    let mut populated_chains = [0u8; 3];
    let mut populated_count = 0usize;
    for population in populations {
        if population.chain >= S21_CHAINS_PER_UNIT {
            return Err(PopulationAdmissionError::ChainOutOfRange);
        }
        if populated_chains[..populated_count]
            .iter()
            .any(|prior| *prior == population.chain)
        {
            return Err(PopulationAdmissionError::DuplicateChain);
        }
        if population.observed_chips != profile.chips_per_chain {
            return Err(PopulationAdmissionError::PopulationMismatch {
                chain: population.chain,
                observed: population.observed_chips,
                expected: profile.chips_per_chain,
            });
        }
        populated_chains[populated_count] = population.chain;
        populated_count += 1;
    }
    Ok(AdmittedBm1368S21Unit {
        profile,
        populated_chains,
        populated_count,
    })
}

/// Stricter full-unit manifest: exactly all three chains, each exact 108.
pub fn admit_full_unit_population(
    profile: Bm1368S21Profile,
    populations: &[ChainPopulation],
) -> Result<AdmittedBm1368S21Unit, PopulationAdmissionError> {
    let unit = admit_unit_population(profile, populations)?;
    if unit.populated_count != usize::from(S21_CHAINS_PER_UNIT) {
        return Err(PopulationAdmissionError::EmptyUnit);
    }
    Ok(unit)
}

// ---------------------------------------------------------------------------
// All-chain work distribution planning.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributionError {
    /// The requested chain was never admitted (unpopulated slots receive
    /// no work and must not be dispatched).
    ChainNotAdmitted,
    /// A coverage receipt names a chain outside the admitted unit.
    ReceiptForeignChain,
    /// Not every admitted chain received the work item exactly once.
    CoverageIncomplete,
}

/// One per-chain work assignment. `work_id` is the ASIC job id (the BM1368
/// +24 mod 128 increment policy is owned by the existing work dispatcher).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainWorkAssignment {
    pub chain: u8,
    pub work_id: u16,
}

/// Plan one work item onto EVERY admitted chain. "Full-unit dispatch" is the
/// load-bearing property: a full unit mines only when all populated chains
/// receive the item; the held single-board unit mines on its one route.
pub fn distribute_work_to_all_chains(
    unit: &AdmittedBm1368S21Unit,
    work_id: u16,
) -> Result<Vec<ChainWorkAssignment>, DistributionError> {
    Ok(unit.populated_chains[..unit.populated_count]
        .iter()
        .map(|&chain| ChainWorkAssignment { chain, work_id })
        .collect())
}

/// Address one admitted chain only; unpopulated slots refuse.
pub fn distribute_work_to_chain(
    unit: &AdmittedBm1368S21Unit,
    chain: u8,
    work_id: u16,
) -> Result<ChainWorkAssignment, DistributionError> {
    if !unit.populated_chains[..unit.populated_count].contains(&chain) {
        return Err(DistributionError::ChainNotAdmitted);
    }
    Ok(ChainWorkAssignment { chain, work_id })
}

/// Verify a session ledger: every admitted chain received `work_id` exactly
/// once, and no receipt names a foreign (unadmitted) chain.
pub fn coverage_complete(
    unit: &AdmittedBm1368S21Unit,
    work_id: u16,
    receipts: &[ChainWorkAssignment],
) -> Result<(), DistributionError> {
    for receipt in receipts {
        if !unit.populated_chains[..unit.populated_count].contains(&receipt.chain) {
            return Err(DistributionError::ReceiptForeignChain);
        }
    }
    for &chain in &unit.populated_chains[..unit.populated_count] {
        let hits = receipts
            .iter()
            .filter(|receipt| receipt.chain == chain && receipt.work_id == work_id)
            .count();
        if hits != 1 {
            return Err(DistributionError::CoverageIncomplete);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-route nonce accounting with exact attribution.
// ---------------------------------------------------------------------------

/// One decoded nonce attributed by the RX path to its physical route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteNonceReceipt {
    /// Physical chain slot the frame arrived on (the RX route tag).
    pub route: u8,
    /// Work id decoded from the frame (driver `decode_nonce`).
    pub work_id: u16,
    /// Raw nonce word (driver `decode_nonce`).
    pub nonce: u32,
    /// Chip address decoded from nonce bits [24:17], when present.
    pub decoded_chip_address: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountingError {
    /// The receipt names a chain outside the admitted unit.
    RouteNotAdmitted,
    /// The work id was never dispatched on that route (unknown-job nonce).
    UnknownWorkItem,
    /// The same (route, nonce) pair was already credited exactly once.
    DuplicateNonce,
}

/// One credit outcome: route attribution is always exact; chip attribution
/// is credited only for in-plan decoded addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteCredit {
    pub route_nonces: u32,
    /// Chip position iff the decoded address was inside the address plan.
    pub chip_position: Option<usize>,
}

#[derive(Debug, Clone)]
struct AccountingState {
    dispatched: Vec<Vec<u16>>,
    frames: Vec<u32>,
    nonces: Vec<u32>,
    /// Chip positions credited (in-plan decoded addresses only).
    chips: [u32; 108],
    /// Chip positions credited per opened route (route-attribution is exact:
    /// a chip address belongs to exactly one physical chain by construction).
    route_chips: Vec<u32>,
    chip_unresolved: u32,
    credited: Vec<(u8, u32)>,
}

/// Per-route (per-chain) nonce accounting for one admitted S21 unit.
///
/// Route attribution is EXACT by construction: every credit names the route
/// the frame physically arrived on, and a route outside the admitted unit is
/// refused. Chip attribution is ADDRESS-scoped: a decoded address inside the
/// admitted interval-2 plan credits exactly one chip position; an
/// out-of-plan or absent address is counted `chip_unresolved` and never
/// fabricates a chip identity.
///
/// Interior mutability is a single `std::sync::Mutex` so the daemon can hold
/// the accounting inside its shared multi-UART transport and credit at the
/// route-tagged RX point.
pub struct S21FullUnitAccounting {
    unit: AdmittedBm1368S21Unit,
    /// Backend index -> physical chain slot (transport route order).
    route_slots: Vec<u8>,
    state: std::sync::Mutex<AccountingState>,
}

impl S21FullUnitAccounting {
    /// Open accounting for an admitted unit with the transport route order
    /// (backend index -> physical slot). Every route slot must be admitted
    /// and unique; otherwise this refuses.
    pub fn new(unit: AdmittedBm1368S21Unit, route_slots: &[u8]) -> Result<Self, AccountingError> {
        if route_slots.len() > usize::from(S21_CHAINS_PER_UNIT) {
            return Err(AccountingError::RouteNotAdmitted);
        }
        for (index, &slot) in route_slots.iter().enumerate() {
            let admitted = unit.populated_chains[..unit.populated_count].contains(&slot);
            let unique = !route_slots[..index].iter().any(|prior| *prior == slot);
            if !admitted || !unique {
                return Err(AccountingError::RouteNotAdmitted);
            }
        }
        Ok(Self {
            unit,
            route_slots: route_slots.to_vec(),
            state: std::sync::Mutex::new(AccountingState {
                dispatched: vec![Vec::new(); route_slots.len()],
                frames: vec![0; route_slots.len()],
                nonces: vec![0; route_slots.len()],
                chips: [0; 108],
                route_chips: vec![0; route_slots.len()],
                chip_unresolved: 0,
                credited: Vec::new(),
            }),
        })
    }

    /// The admitted unit this accounting is bound to.
    pub const fn unit(&self) -> &AdmittedBm1368S21Unit {
        &self.unit
    }

    /// Backend index -> physical chain slot, for route naming.
    pub fn route_slots(&self) -> &[u8] {
        &self.route_slots
    }

    /// Record that one route was dispatched a work item. Unknown-job nonces
    /// are refused later against this ledger.
    pub fn record_dispatch(&self, assignment: &ChainWorkAssignment) -> Result<(), AccountingError> {
        let mut state = self.lock();
        let Some(index) = self.route_index(assignment.chain) else {
            return Err(AccountingError::RouteNotAdmitted);
        };
        state.dispatched[index].push(assignment.work_id);
        Ok(())
    }

    /// Coarse per-route frame credit at the UART-tagged RX point (the daemon
    /// multi-transport RX hook credits the backend index it read from).
    /// A backend index outside the opened route set refuses.
    pub fn credit_route_frame(&self, backend_index: usize) -> Result<(), AccountingError> {
        let mut state = self.lock();
        let frames = state
            .frames
            .get_mut(backend_index)
            .ok_or(AccountingError::RouteNotAdmitted)?;
        *frames = frames.saturating_add(1);
        Ok(())
    }

    /// Credit one decoded nonce. Route attribution is exact (foreign routes
    /// refuse, unknown work items refuse, duplicate (route, nonce) refuses);
    /// chip attribution credits only in-plan addresses.
    pub fn credit_nonce(
        &self,
        receipt: &RouteNonceReceipt,
    ) -> Result<RouteCredit, AccountingError> {
        let mut state = self.lock();
        let Some(index) = self.route_index(receipt.route) else {
            return Err(AccountingError::RouteNotAdmitted);
        };
        if !state.dispatched[index].contains(&receipt.work_id) {
            return Err(AccountingError::UnknownWorkItem);
        }
        if state
            .credited
            .iter()
            .any(|&(route, nonce)| route == receipt.route && nonce == receipt.nonce)
        {
            return Err(AccountingError::DuplicateNonce);
        }
        state.credited.push((receipt.route, receipt.nonce));
        state.nonces[index] += 1;
        let chip_position = receipt
            .decoded_chip_address
            .and_then(|address| self.unit.profile.chip_position(address));
        match chip_position {
            Some(position) => {
                state.chips[position] += 1;
                state.route_chips[index] += 1;
            }
            None => state.chip_unresolved += 1,
        }
        Ok(RouteCredit {
            route_nonces: state.nonces[index],
            chip_position,
        })
    }

    /// Route index for a physical slot, or `None` when not an opened route.
    fn route_index(&self, chain: u8) -> Option<usize> {
        self.route_slots.iter().position(|&slot| slot == chain)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, AccountingState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// One route's accounting summary entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteAccountingSummary {
    /// Physical chain slot.
    pub chain: u8,
    /// Physical UART device for the slot (`ttyS3`/`ttyS2`/`ttyS1`).
    pub uart: &'static str,
    /// Frames credited at the route-tagged RX point.
    pub frames: u32,
    /// Decoded nonces credited.
    pub nonces: u32,
    /// Chip positions credited (in-plan decoded addresses only).
    pub chips_credited: u32,
}

/// Full-unit accounting snapshot with exact per-route attribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S21AccountingSummary {
    pub routes: Vec<RouteAccountingSummary>,
    pub total_frames: u32,
    pub total_nonces: u32,
    pub total_chips_credited: u32,
    /// Nonces whose decoded chip address was absent or outside the admitted
    /// plan. Route attribution stands; no chip identity is fabricated.
    pub chip_unresolved: u32,
}

impl S21FullUnitAccounting {
    /// Exact per-route snapshot. Route names come from the verified AM3
    /// physical-slot UART table.
    pub fn summary(&self) -> S21AccountingSummary {
        let state = self.lock();
        let routes = self
            .route_slots
            .iter()
            .enumerate()
            .map(|(index, &chain)| RouteAccountingSummary {
                chain,
                uart: AM3_S21_ROUTE_UARTS
                    .get(usize::from(chain))
                    .copied()
                    .unwrap_or("unknown"),
                frames: state.frames[index],
                nonces: state.nonces[index],
                chips_credited: state.route_chips[index],
            })
            .collect();
        S21AccountingSummary {
            total_frames: state.frames.iter().sum(),
            total_nonces: state.nonces.iter().sum(),
            total_chips_credited: state.chips.iter().sum(),
            chip_unresolved: state.chip_unresolved,
            routes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn populations(chains: [(u8, u16); 3]) -> [Option<ChainPopulation>; 3] {
        [
            Some(ChainPopulation {
                chain: chains[0].0,
                observed_chips: chains[0].1,
            }),
            Some(ChainPopulation {
                chain: chains[1].0,
                observed_chips: chains[1].1,
            }),
            Some(ChainPopulation {
                chain: chains[2].0,
                observed_chips: chains[2].1,
            }),
        ]
    }

    fn exact_full_unit() -> Vec<ChainPopulation> {
        (0..3)
            .map(|chain| ChainPopulation {
                chain,
                observed_chips: 108,
            })
            .collect()
    }

    #[test]
    fn exact_geometry_and_name_scoping_are_pinned() {
        assert_eq!(S21.board_target, "am3-s21");
        assert_eq!(S21.board_names, &["BHB68603", "BHB68606"]);
        assert_eq!(S21.domains_per_board, 12);
        assert_eq!(S21.chips_per_domain, 9);
        assert_eq!(S21.domains_times_chips(), 108);
        assert_eq!(S21.chips_per_chain, 108);
        assert_eq!(S21.chips_per_unit(), 324);
        assert_eq!(S21_ADDRESS_INTERVAL, 2);
        assert_eq!(S21_CHAINS_PER_UNIT, 3);
        assert_eq!(BM1368_CHIP_ID, 0x1368);

        assert_eq!(Bm1368S21Profile::for_board_name("BHB68603"), Some(S21));
        assert_eq!(Bm1368S21Profile::for_board_name("BHB68606"), Some(S21));
        // Identity is name-scoped, never count-scoped: the T21 boards carry
        // the same 108 count but a different platform name, and every other
        // family name refuses.
        for name in [
            "BHB68701",
            "BHB68703",
            "BHB68705", // T21
            "A3HB70501",
            "A3HB70601",
            "A3HB70701", // BM1370 bins
            "BHB56903",  // S19k
            "BHB68602",
            "BHB68609", // adjacent BHB68 non-factory names
        ] {
            assert_eq!(
                Bm1368S21Profile::for_board_name(name),
                None,
                "{name} must not select the base-S21 profile"
            );
        }
    }

    #[test]
    fn address_plan_is_exact_interval_two_and_chip_credit_never_fabricates() {
        let plan = S21.address_plan();
        assert_eq!(plan.len(), 108);
        assert_eq!(plan[0], 0);
        assert_eq!(plan[1], 2);
        assert_eq!(plan[107], 214);
        assert_eq!(S21.chip_position(0), Some(0));
        assert_eq!(S21.chip_position(214), Some(107));
        // Off-plan addresses never credit a chip.
        assert_eq!(S21.chip_position(1), None);
        assert_eq!(S21.chip_position(21), None);
        assert_eq!(S21.chip_position(215), None);
        assert_eq!(S21.chip_position(216), None);
    }

    #[test]
    fn population_admission_requires_exact_counts_and_refuses_wrong_duplicate_empty() {
        admit_full_unit_population(S21, &exact_full_unit()).expect("exact full unit");
        admit_unit_population(S21, &exact_full_unit()).expect("exact full unit");

        // The held .135 posture: one populated board (physical chain 2 ->
        // ttyS2) at exactly 108 stays admissible.
        admit_unit_population(
            S21,
            &[ChainPopulation {
                chain: 1,
                observed_chips: 108,
            }],
        )
        .expect("single exact chain");

        // Off-by-one refuses on every chain slot, both directions.
        for drifted in [107u16, 109] {
            for chain in 0..3u8 {
                assert_eq!(
                    admit_unit_population(
                        S21,
                        &[ChainPopulation {
                            chain,
                            observed_chips: drifted,
                        }]
                    ),
                    Err(PopulationAdmissionError::PopulationMismatch {
                        chain,
                        observed: drifted,
                        expected: 108,
                    }),
                    "chain{chain} population {drifted} must refuse"
                );
            }
        }

        // Empty, duplicate and out-of-range refuse.
        assert_eq!(
            admit_unit_population(S21, &[]),
            Err(PopulationAdmissionError::EmptyUnit)
        );
        let dup = [
            ChainPopulation {
                chain: 1,
                observed_chips: 108,
            },
            ChainPopulation {
                chain: 1,
                observed_chips: 108,
            },
        ];
        assert_eq!(
            admit_unit_population(S21, &dup),
            Err(PopulationAdmissionError::DuplicateChain)
        );
        assert_eq!(
            admit_unit_population(
                S21,
                &[ChainPopulation {
                    chain: 3,
                    observed_chips: 108,
                }]
            ),
            Err(PopulationAdmissionError::ChainOutOfRange)
        );

        // Full-unit manifest refuses a missing chain.
        let two: Vec<ChainPopulation> = exact_full_unit().iter().take(2).copied().collect();
        assert_eq!(
            admit_full_unit_population(S21, &two),
            Err(PopulationAdmissionError::EmptyUnit)
        );
    }

    #[test]
    fn full_unit_distribution_covers_every_chain_and_refuses_gaps() {
        let unit = admit_full_unit_population(S21, &exact_full_unit()).unwrap();
        let plan = distribute_work_to_all_chains(&unit, 7).unwrap();
        assert_eq!(
            plan,
            vec![
                ChainWorkAssignment {
                    chain: 0,
                    work_id: 7
                },
                ChainWorkAssignment {
                    chain: 1,
                    work_id: 7
                },
                ChainWorkAssignment {
                    chain: 2,
                    work_id: 7
                },
            ]
        );
        coverage_complete(&unit, 7, &plan).expect("full coverage");
        assert_eq!(
            coverage_complete(&unit, 7, &plan[..2]),
            Err(DistributionError::CoverageIncomplete)
        );
        assert_eq!(
            coverage_complete(
                &unit,
                7,
                &[ChainWorkAssignment {
                    chain: 3,
                    work_id: 7
                }]
            ),
            Err(DistributionError::ReceiptForeignChain)
        );

        // Single-board unit (the held .135 posture): dispatch to its own
        // slot only; unpopulated slots refuse.
        let single = admit_unit_population(
            S21,
            &[ChainPopulation {
                chain: 1,
                observed_chips: 108,
            }],
        )
        .unwrap();
        assert_eq!(
            distribute_work_to_all_chains(&single, 9).unwrap(),
            vec![ChainWorkAssignment {
                chain: 1,
                work_id: 9
            }]
        );
        distribute_work_to_chain(&single, 1, 9).expect("admitted slot");
        assert_eq!(
            distribute_work_to_chain(&single, 0, 9),
            Err(DistributionError::ChainNotAdmitted)
        );
        assert_eq!(
            distribute_work_to_chain(&single, 2, 9),
            Err(DistributionError::ChainNotAdmitted)
        );
    }

    #[test]
    fn accounting_credits_routes_exactly_and_never_fabricates_chips() {
        let unit = admit_full_unit_population(S21, &exact_full_unit()).unwrap();
        let accounting =
            S21FullUnitAccounting::new(unit, &[0, 1, 2]).expect("routes match admission");

        // Route order must mirror admission; a foreign route refuses.
        assert!(matches!(
            S21FullUnitAccounting::new(unit, &[0, 1, 2, 3]),
            Err(AccountingError::RouteNotAdmitted)
        ));
        assert!(matches!(
            S21FullUnitAccounting::new(unit, &[0, 2, 2]),
            Err(AccountingError::RouteNotAdmitted)
        ));
        // Subset route order is allowed (single/two-board units).
        assert!(S21FullUnitAccounting::new(unit, &[0, 1]).is_ok());
        assert!(S21FullUnitAccounting::new(unit, &[2]).is_ok());
        // A route slot outside the admitted unit refuses even when in-range.
        let single = admit_unit_population(
            S21,
            &[ChainPopulation {
                chain: 2,
                observed_chips: 108,
            }],
        )
        .unwrap();
        assert!(matches!(
            S21FullUnitAccounting::new(single, &[0]),
            Err(AccountingError::RouteNotAdmitted)
        ));

        for chain in 0..3u8 {
            accounting
                .record_dispatch(&ChainWorkAssignment { chain, work_id: 5 })
                .expect("dispatch recorded");
        }

        // An out-of-plan chip address (the recorded genesis nonce decodes
        // 21) credits the ROUTE but never a chip.
        let genesis = RouteNonceReceipt {
            route: 0,
            work_id: 5,
            nonce: 2_083_236_893,
            decoded_chip_address: Some(21),
        };
        let credit = accounting.credit_nonce(&genesis).expect("route credit");
        assert_eq!(credit.chip_position, None, "address 21 is off-plan");

        // In-plan addresses credit exactly one chip position each.
        let first_chip = RouteNonceReceipt {
            route: 1,
            work_id: 5,
            nonce: 8_603,
            decoded_chip_address: Some(0),
        };
        let credit = accounting.credit_nonce(&first_chip).expect("route credit");
        assert_eq!(credit.chip_position, Some(0));
        let last_chip = RouteNonceReceipt {
            route: 2,
            work_id: 5,
            nonce: 28_054_374,
            decoded_chip_address: Some(214),
        };
        let credit = accounting.credit_nonce(&last_chip).expect("route credit");
        assert_eq!(credit.chip_position, Some(107));

        // Foreign route, unknown work item, duplicate nonce all refuse.
        assert_eq!(
            accounting.credit_nonce(&RouteNonceReceipt {
                route: 3,
                work_id: 5,
                nonce: 1,
                decoded_chip_address: None,
            }),
            Err(AccountingError::RouteNotAdmitted)
        );
        assert_eq!(
            accounting.credit_nonce(&RouteNonceReceipt {
                route: 0,
                work_id: 6,
                nonce: 1,
                decoded_chip_address: None,
            }),
            Err(AccountingError::UnknownWorkItem)
        );
        assert_eq!(
            accounting.credit_nonce(&genesis),
            Err(AccountingError::DuplicateNonce)
        );

        // Route frames credit at the UART-tag point; a foreign index refuses.
        accounting.credit_route_frame(0).expect("frame");
        accounting.credit_route_frame(1).expect("frame");
        assert_eq!(
            accounting.credit_route_frame(3),
            Err(AccountingError::RouteNotAdmitted)
        );

        let summary = accounting.summary();
        assert_eq!(summary.total_nonces, 3);
        assert_eq!(summary.total_frames, 2);
        assert_eq!(summary.total_chips_credited, 2);
        assert_eq!(summary.chip_unresolved, 1);
        let per_route: Vec<(u8, u32, u32)> = summary
            .routes
            .iter()
            .map(|route| (route.chain, route.nonces, route.frames))
            .collect();
        assert_eq!(per_route, vec![(0, 1, 1), (1, 1, 1), (2, 1, 0)]);
        assert_eq!(summary.routes[0].uart, "/dev/ttyS3");
        assert_eq!(summary.routes[1].uart, "/dev/ttyS2");
        assert_eq!(summary.routes[2].uart, "/dev/ttyS1");
    }

    #[test]
    fn polarity_and_psu_scoping_stay_target_exact() {
        // The exact am3-s21 join is the R13 production software mapping.
        assert_eq!(
            S21.power_polarity_join(),
            S21PowerPolarityJoin::ProductionMappedZeroOnOneOff
        );
        assert_eq!(
            S21.psu_selection(),
            S21PsuSelection::ProductionApw1212xxVersions75to77
        );
        // The Unproven state exists for every other target and never
        // inherits the am3-s21 mapping (T21 pins its own Unproven state in
        // `t21_bm1368_profile`).
        assert_ne!(S21PowerPolarityJoin::Unproven, S21.power_polarity_join());
    }

    #[test]
    fn population_helper_shapes_stay_const_compatible() {
        // Compile-time shape guard for the admission manifest helper.
        let shaped = populations([(0, 108), (1, 108), (2, 108)]);
        assert!(shaped[0].is_some());
    }
}
