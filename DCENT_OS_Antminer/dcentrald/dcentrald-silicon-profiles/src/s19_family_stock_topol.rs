//! S19-family **stock topology** transcribed byte-exactly from Bitmain's own
//! firmware images held in the `asicminingsupplies` mirror (Gauntlet Phase A,
//! 2026-09-01). Covers the four boards lane B5b owns:
//!
//! | board | model | stock image |
//! |---|---|---|
//! | `NBS1902` | Antminer S19 (classic, 76/chain bin) | `s19-20211116` |
//! | `NBP1901` | Antminer S19 Pro | `s19-pro-20211116` |
//! | `NBT1903` | Antminer T19 | `t19-20230320` |
//! | `BHB42701` | Antminer S19j (classic — **BM1362, NOT BM1398**) | `s19j-merge-20221226` |
//!
//! This module is deliberately *only* a transcription surface (same rule as
//! [`crate::scrypt_stock_topology`]): every field is `Option`, a field is
//! `Some` **only** when a held stock artifact states it literally, and nothing
//! is inherited from a sibling board or a research document. It declares no
//! [`crate::SiliconTable`] — [`crate::bm1398::BM1398_TABLE`] and
//! [`crate::bm1362`] remain the single silicon profiles for the two chip
//! families. Data + refusals only; no energization, voltage, or runtime
//! authority lives here.
//!
//! # Held artifacts (gitignored extraction trees, mirror-held)
//!
//! Source mirror:
//! (HEAD `d140bd0f`, third-party public mirror — internal-consistency-verified
//! only; see `PHASE_A_EVIDENCE_REPORT.md` §1.3 caveats class).
//!
//! | record | topol path (under ) | SHA-256 |
//! |---|---|---|
//! | S19 | `s19-20211116/components/minerfs.image.gz.tree/etc/topol.conf` | [`NBS1902_TOPOL_SHA256`] |
//! | S19 Pro | `s19-pro-20211116/components/minerfs.image.gz.tree/etc/topol.conf` | [`NBP1901_TOPOL_SHA256`] |
//! | T19 | `t19-20230320/components/minerfs.image.gz.tree/etc/topol.conf` | [`NBT1903_TOPOL_SHA256`] |
//! | S19j | `s19j-merge-20221226/{00_Antminer_S19j_zynq7007_BHB42XXX,02_Antminer_S19j_zynq7007}/components/minerfs.image.gz.tree/etc/topol.conf` | [`S19J_MERGE_TOPOL_SHA256`] (both records byte-identical, 15-machine `config[]` DB) |
//!
//! # The two roster verdicts these bytes settle
//!
//! 1. **The S19 "76-hint vs 114 divergence is board-dependent, not a bug.**
//!    Stock itself ships TWO S19-classic-generation machine records: NBS1902
//!    at **76**/chain and the S19 Pro's NBP1901 at **114**/chain (both
//!    BM1398P). Any consumer that treated the daemon's historical 76 hint as
//!    contradicting the 114 enum (or vice versa) was reading two real boards
//!    as one.
//! 2. **The S19j-classic is BM1362, refuting the old "BM1398 identity-only"
//!    roster claim.** The S19j merge image's own multi-machine topology DB
//!    states `BHB42701: asic_id "BM1362", asic_addr "0x1362", 108/chain
//!    (12×9), 36 domains × 3` — same silicon generation as the S19j Pro
//!    boards in the same DB (BHB42601 126/chain, BHB42611 120/chain,
//!    BHB42803 84/chain…), NOT the S19 classic's BM1398P.
//!
//! # `chain_num` caveat (load-bearing, Phase A §1.3.5)
//!
//! Every one of these records states `chain_num: 4` — including SKUs we know
//! are 3-board machines. On this generation the field counts **connector
//! slots** on the control board, not populated hashboards. It is therefore
//! transcribed as [`S19FamilyStockTopol::stock_chain_num_field`] (the literal
//! field) and deliberately NOT exposed as a physical `chain_count`; physical
//! population stays a runtime/live question (the sole 3-chain record in the
//! S19j DB, BHB42803, says `chain_num: 3` — the field means different things
//! per record and only cross-checks disambiguate).
//!
//! # Controller naming caveat
//!
//! Every record labels the per-chain voltage MCU `"type": "PIC1704"` at I²C
//! `0x20` (with LM75A sensors at `0x48..=0x4b`). That is Bitmain's topol
//! label for the slot whose populated part our live probes of the sibling
//! BHB42601 generation identified as dsPIC33EP16GS202 (framed, 7-bit
//! `0x20..=0x22` at probe). A stock label is not a populated-part proof for a
//! never-contacted board; consumers must keep treating the concrete part as
//! runtime-discovered.
//!
//! Likewise `"type": "AWP12"` (S19/S19 Pro/T19) is Bitmain's own misspelling
//! of APW12 (their `AWP12+` appears on BHB428xx boards) — transcribed
//! verbatim with that note, never "corrected" in the pinned constants.

/// A stock `topol.conf` machine record, transcribed. `None` = the stock bytes
/// are silent (never interpolated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19FamilyStockTopol {
    /// Marketing model this row belongs to.
    pub model: &'static str,
    /// Bitmain machine/hashboard id exactly as stated (`machine` field).
    pub machine_id: &'static str,
    /// Stock control-board processor type string.
    pub processor: Option<&'static str>,
    /// ASIC part name **as stated by the stock image itself**.
    pub asic_id: &'static str,
    /// Numeric chip id **as stated by the stock image itself**.
    pub chip_type: u16,
    /// Big (hashing) cores per ASIC (`asic_core_num`).
    pub asic_big_core_num: Option<u32>,
    /// Small cores per ASIC (`asic_small_core_num`).
    pub asic_small_core_num: Option<u32>,
    /// Small cores per big core (`core_small_core_num`).
    pub core_small_core_num: Option<u32>,
    /// Chip-address stride used during enumeration (`asic_addr_interval`).
    pub asic_addr_interval: Option<u32>,
    /// `chain_row` — literal stock field. Part of a **physical placement
    /// grid**: row × column does NOT necessarily multiply to
    /// `chips_per_chain` (NBS1902 declares an 8×10 grid for 76 ASICs, NBP1901
    /// a 12×10 grid for 114 — grid slots are not all populated;
    /// test-pinned).
    pub chain_row: Option<u32>,
    /// `chain_column` — literal stock field (placement grid, see
    /// [`Self::chain_row`]).
    pub chain_column: Option<u32>,
    /// ASICs per chain (`chain_asic_num`).
    pub chips_per_chain: u32,
    /// Voltage domains per chain (`chain_domain_num`).
    pub chain_domain_num: Option<u32>,
    /// ASICs per voltage domain (`domain_asic_num`).
    pub domain_asic_num: Option<u32>,
    /// The literal `chain_num` field — **connector slots on this control
    /// board generation, NOT populated-board count** (see module docs).
    pub stock_chain_num_field: Option<u32>,
    /// Chain voltage-MCU topol label (`pic.type`) — a label, not a
    /// populated-part proof (see module docs).
    pub pic_topol_label: Option<&'static str>,
    /// Chain voltage-MCU 7-bit I²C address (`pic.i2c_addr`).
    pub pic_i2c_addr: Option<u8>,
    /// PSU family string, verbatim (`power.type` — Bitmain's own `AWP12`
    /// misspelling is preserved).
    pub psu_type: Option<&'static str>,
    /// PSU 7-bit I²C address (`power.i2c_addr`).
    pub psu_i2c_addr: Option<u8>,
    /// PSU power GPIO (`power.gpio`).
    pub psu_gpio: Option<u32>,
    /// Hashboard EEPROM type (`eeprom.type`).
    pub eeprom_type: Option<&'static str>,
    /// Hashboard EEPROM 7-bit I²C address (`eeprom.i2c_addr`).
    pub eeprom_i2c_addr: Option<u8>,
    /// Exact provenance sentence for this row.
    pub evidence: &'static str,
}

impl S19FamilyStockTopol {
    /// Row × column product of the placement grid — **NOT** a chip count
    /// (see [`Self::chain_row`]: grid slots are not all populated on the
    /// BM1398P records). Kept as a method so consumers cannot mistake it for
    /// geometry; the test pins where it diverges from `chips_per_chain`.
    pub const fn row_column_product(&self) -> Option<u32> {
        match (self.chain_row, self.chain_column) {
            (Some(r), Some(c)) => Some(r * c),
            _ => None,
        }
    }

    /// Domains × per-domain reproduces `chips_per_chain` exactly on every
    /// transcribed row — this, not the grid, is the stock per-chain count's
    /// internal cross-check (test-pinned).
    pub const fn domain_product(&self) -> Option<u32> {
        match (self.chain_domain_num, self.domain_asic_num) {
            (Some(d), Some(a)) => Some(d * a),
            _ => None,
        }
    }
}

/// SHA-256 of the S19 stock `topol.conf` (machine `NBS1902`).
pub const NBS1902_TOPOL_SHA256: &str =
    "59d911b44a5b68177b5f86f46cb187f3fd84a42432cdee43f242f62088a5ad11";
/// SHA-256 of the S19 Pro stock `topol.conf` (machine `NBP1901`).
pub const NBP1901_TOPOL_SHA256: &str =
    "351f6361abe4ccb68bd93e2e42f6cdebb1b3f4fd15b8e4e01f7539388bcb8de4";
/// SHA-256 of the T19 stock `topol.conf` (machine `NBT1903`).
pub const NBT1903_TOPOL_SHA256: &str =
    "360af8228ebeb5aadc2f623227aa476ad3d3067d7caa9cfc70eb688c78b10c98";
/// SHA-256 of the S19j merge image's 15-machine topology DB (both zynq7007
/// records are byte-identical copies).
pub const S19J_MERGE_TOPOL_SHA256: &str =
    "61a6404ba73cbd81a178656f3677ecd111283984c8ce88d46e83614396d0ffe8";

// --- The headline pinned geometry constants (the B5b lane deliverable) ---

/// **S19 classic, NBS1902 bin: 76 BM1398P per chain** (8 rows × 10 columns,
/// 38 voltage domains × 2). First-party stock evidence settling that the
/// historical 76-hint was a real board, not a bug.
pub const S19_NBS1902_CHIPS_PER_CHAIN: u32 = 76;
/// **S19 Pro, NBP1901: 114 BM1398P per chain** (12 × 10, 38 domains × 3,
/// address interval 2). The other half of the "deliberate divergence".
pub const S19_PRO_NBP1901_CHIPS_PER_CHAIN: u32 = 114;
/// **T19, NBT1903: 76 BM1398P per chain** (8 × 10, 38 domains × 2, interval
/// 3 — geometry identical to the S19's NBS1902 bin). Settles the T19
/// geometry blocker desk-side; 3-chain physical population remains the
/// live-capture question.
pub const T19_NBT1903_CHIPS_PER_CHAIN: u32 = 76;
/// **S19j classic, BHB42701: 108 BM1362 per chain** (12 × 9, 36 domains × 3,
/// interval 2). Refutes the old roster's "BM1398 identity-only" claim for
/// the S19j.
pub const S19J_CLASSIC_BHB42701_CHIPS_PER_CHAIN: u32 = 108;
/// The S19j-classic stock chip id (`asic_addr "0x1362"`) — pinned so the
/// refuted `0x1398` attribution cannot silently return.
pub const S19J_CLASSIC_CHIP_TYPE: u16 = 0x1362;
/// The refuted value: model.rs historically keyed `s19j` to the BM1398
/// family on identity-only evidence. Test-pinned as NOT the stock value.
pub const S19J_CLASSIC_REFUTED_CHIP_TYPE: u16 = 0x1398;

/// BM1398P stock core census shared by NBS1902 / NBP1901 / NBT1903
/// (`asic_core_num` + `asic_small_core_num`).
pub const BM1398P_BIG_CORES: u32 = 156;
/// Small cores per BM1398P as stated by stock.
pub const BM1398P_SMALL_CORES: u32 = 623;
/// BM1362 stock core census (S19j-family boards, `asic_core_num` +
/// `asic_small_core_num`).
pub const BM1362_BIG_CORES: u32 = 65;
/// Small cores per BM1362 as stated by stock.
pub const BM1362_SMALL_CORES: u32 = 514;

/// Antminer S19 classic stock row — `s19-20211116` (fw BR 2019.02.7-g386747fa,
/// ZYNQ7007 single-machine record).
pub const S19_NBS1902_STOCK: S19FamilyStockTopol = S19FamilyStockTopol {
    model: "Antminer S19",
    machine_id: "NBS1902",
    processor: Some("ZYNQ7007"),
    asic_id: "BM1398P",
    chip_type: 0x1398,
    asic_big_core_num: Some(BM1398P_BIG_CORES),
    asic_small_core_num: Some(BM1398P_SMALL_CORES),
    core_small_core_num: Some(4),
    asic_addr_interval: Some(3),
    chain_row: Some(8),
    chain_column: Some(10),
    chips_per_chain: S19_NBS1902_CHIPS_PER_CHAIN,
    chain_domain_num: Some(38),
    domain_asic_num: Some(2),
    stock_chain_num_field: Some(4),
    pic_topol_label: Some("PIC1704"),
    pic_i2c_addr: Some(0x20),
    psu_type: Some("AWP12"),
    psu_i2c_addr: Some(0x10),
    psu_gpio: Some(907),
    eeprom_type: Some("AT24C02D"),
    eeprom_i2c_addr: Some(0x50),
    evidence: "asicminingsupplies s19-20211116 etc/topol.conf machine NBS1902 (sha256 59d911b4..5ad11); \
               AWP12 is Bitmain's own APW12 misspelling, transcribed verbatim",
};

/// Antminer S19 Pro stock row — `s19-pro-20211116` (fw BR 2019.02.7-g386747fa).
pub const S19_PRO_NBP1901_STOCK: S19FamilyStockTopol = S19FamilyStockTopol {
    model: "Antminer S19 Pro",
    machine_id: "NBP1901",
    processor: Some("ZYNQ7007"),
    asic_id: "BM1398P",
    chip_type: 0x1398,
    asic_big_core_num: Some(BM1398P_BIG_CORES),
    asic_small_core_num: Some(BM1398P_SMALL_CORES),
    core_small_core_num: Some(4),
    asic_addr_interval: Some(2),
    chain_row: Some(12),
    chain_column: Some(10),
    chips_per_chain: S19_PRO_NBP1901_CHIPS_PER_CHAIN,
    chain_domain_num: Some(38),
    domain_asic_num: Some(3),
    stock_chain_num_field: Some(4),
    pic_topol_label: Some("PIC1704"),
    pic_i2c_addr: Some(0x20),
    psu_type: Some("AWP12"),
    psu_i2c_addr: Some(0x10),
    psu_gpio: Some(907),
    eeprom_type: Some("AT24C02D"),
    eeprom_i2c_addr: Some(0x50),
    evidence: "asicminingsupplies s19-pro-20211116 etc/topol.conf machine NBP1901 (sha256 351f6361..b8de4)",
};

/// Antminer T19 stock row — `t19-20230320` (fw BR 2019.02.7-gdd076742).
pub const T19_NBT1903_STOCK: S19FamilyStockTopol = S19FamilyStockTopol {
    model: "Antminer T19",
    machine_id: "NBT1903",
    processor: Some("ZYNQ7007"),
    asic_id: "BM1398P",
    chip_type: 0x1398,
    asic_big_core_num: Some(BM1398P_BIG_CORES),
    asic_small_core_num: Some(BM1398P_SMALL_CORES),
    core_small_core_num: Some(4),
    asic_addr_interval: Some(3),
    chain_row: Some(8),
    chain_column: Some(10),
    chips_per_chain: T19_NBT1903_CHIPS_PER_CHAIN,
    chain_domain_num: Some(38),
    domain_asic_num: Some(2),
    stock_chain_num_field: Some(4),
    pic_topol_label: Some("PIC1704"),
    pic_i2c_addr: Some(0x20),
    psu_type: Some("AWP12"),
    psu_i2c_addr: Some(0x10),
    psu_gpio: Some(907),
    eeprom_type: Some("AT24C02D"),
    eeprom_i2c_addr: Some(0x50),
    evidence: "asicminingsupplies t19-20230320 etc/topol.conf machine NBT1903 (sha256 360af822..10c98)",
};

/// Antminer S19j classic stock row — entry `BHB42701` of the 15-machine
/// `config[]` DB inside the S19j merge image (fw BR 2019.02.7-gdd076742).
pub const S19J_CLASSIC_BHB42701_STOCK: S19FamilyStockTopol = S19FamilyStockTopol {
    model: "Antminer S19j",
    machine_id: "BHB42701",
    processor: Some("ZYNQ7007"),
    asic_id: "BM1362",
    chip_type: S19J_CLASSIC_CHIP_TYPE,
    asic_big_core_num: Some(BM1362_BIG_CORES),
    asic_small_core_num: Some(BM1362_SMALL_CORES),
    core_small_core_num: Some(8),
    asic_addr_interval: Some(2),
    chain_row: Some(12),
    chain_column: Some(9),
    chips_per_chain: S19J_CLASSIC_BHB42701_CHIPS_PER_CHAIN,
    chain_domain_num: Some(36),
    domain_asic_num: Some(3),
    stock_chain_num_field: Some(4),
    pic_topol_label: Some("PIC1704"),
    pic_i2c_addr: Some(0x20),
    psu_type: Some("APW12"),
    psu_i2c_addr: Some(0x10),
    psu_gpio: Some(907),
    eeprom_type: Some("AT24C02D"),
    eeprom_i2c_addr: Some(0x50),
    evidence: "asicminingsupplies s19j-merge-20221226 02_Antminer_S19j_zynq7007 etc/topol.conf \
               config[BHB42701] (sha256 61a6404b..0ffe8, byte-identical in the 00_..BHB42XXX record)",
};

/// Every transcribed row (row order: S19, S19 Pro, T19, S19j).
pub const S19_FAMILY_STOCK_TOPOLOGIES: [S19FamilyStockTopol; 4] = [
    S19_NBS1902_STOCK,
    S19_PRO_NBP1901_STOCK,
    T19_NBT1903_STOCK,
    S19J_CLASSIC_BHB42701_STOCK,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The headline geometry pins — the numbers the B5b lane exists to land.
    #[test]
    fn s19_family_stock_geometry_pins() {
        assert_eq!(S19_NBS1902_CHIPS_PER_CHAIN, 76);
        assert_eq!(S19_PRO_NBP1901_CHIPS_PER_CHAIN, 114);
        assert_eq!(T19_NBT1903_CHIPS_PER_CHAIN, 76);
        assert_eq!(S19J_CLASSIC_BHB42701_CHIPS_PER_CHAIN, 108);
    }

    /// The "76-hint vs 114 divergence is deliberate" verdict, machine-visible:
    /// stock ships BOTH S19-classic-generation boards as separate machine
    /// records. Neither number is a bug and neither may be "fixed" into the
    /// other.
    #[test]
    fn s19_76_vs_114_divergence_is_two_real_stock_boards() {
        assert_ne!(
            S19_NBS1902_CHIPS_PER_CHAIN, S19_PRO_NBP1901_CHIPS_PER_CHAIN,
            "NBS1902 and NBP1901 are separate stock machine records at different \
             per-chain counts; the historical daemon divergence was board-dependent"
        );
        // Both halves of the divergence are BM1398P — same silicon, different
        // population.
        assert_eq!(S19_NBS1902_STOCK.asic_id, "BM1398P");
        assert_eq!(S19_PRO_NBP1901_STOCK.asic_id, "BM1398P");
        assert_eq!(S19_NBS1902_STOCK.chip_type, 0x1398);
        assert_eq!(S19_PRO_NBP1901_STOCK.chip_type, 0x1398);
    }

    /// The refuted S19j identity claim, pinned so it cannot silently return:
    /// stock BHB42701 is BM1362 (0x1362), NOT the BM1398 (0x1398) the old
    /// model.rs identity-only row asserted.
    #[test]
    fn s19j_classic_is_bm1362_not_the_refuted_bm1398() {
        assert_eq!(S19J_CLASSIC_CHIP_TYPE, 0x1362);
        assert_ne!(S19J_CLASSIC_CHIP_TYPE, S19J_CLASSIC_REFUTED_CHIP_TYPE);
        assert_eq!(S19J_CLASSIC_BHB42701_STOCK.asic_id, "BM1362");
        // Same BM1362 core census as the sibling S19j Pro boards in the same
        // stock DB (65+514, 8 small per big core) — a real second-generation
        // S19j-family board, not an S19-classic BM1398P variant.
        assert_eq!(S19J_CLASSIC_BHB42701_STOCK.asic_big_core_num, Some(65));
        assert_eq!(S19J_CLASSIC_BHB42701_STOCK.asic_small_core_num, Some(514));
        assert_eq!(S19J_CLASSIC_BHB42701_STOCK.core_small_core_num, Some(8));
    }

    /// T19 geometry settled desk-side: NBT1903 shares the S19 NBS1902
    /// per-chain geometry exactly (76/chain, 8×10, 38 dom × 2, interval 3) —
    /// same silicon family, same bin. Physical chain population remains the
    /// capture-first question and is NOT claimed here.
    #[test]
    fn t19_nbt1903_geometry_matches_the_s19_76_bin() {
        assert_eq!(T19_NBT1903_STOCK.chips_per_chain, S19_NBS1902_STOCK.chips_per_chain);
        assert_eq!(T19_NBT1903_STOCK.chain_row, S19_NBS1902_STOCK.chain_row);
        assert_eq!(T19_NBT1903_STOCK.chain_column, S19_NBS1902_STOCK.chain_column);
        assert_eq!(
            T19_NBT1903_STOCK.chain_domain_num,
            S19_NBS1902_STOCK.chain_domain_num
        );
        assert_eq!(
            T19_NBT1903_STOCK.domain_asic_num,
            S19_NBS1902_STOCK.domain_asic_num
        );
        assert_eq!(
            T19_NBT1903_STOCK.asic_addr_interval,
            S19_NBS1902_STOCK.asic_addr_interval
        );
        // The boards remain distinct machine records — never alias one onto
        // the other in a future registry edit.
        assert_ne!(T19_NBT1903_STOCK.machine_id, S19_NBS1902_STOCK.machine_id);
    }

    /// Stock internal consistency: domains × per-domain reproduces the stated
    /// per-chain count on every row — the real cross-check in this schema.
    #[test]
    fn stock_domain_geometry_is_internally_consistent() {
        for row in S19_FAMILY_STOCK_TOPOLOGIES {
            assert_eq!(
                row.domain_product(),
                Some(row.chips_per_chain),
                "{}: chain_domain_num x domain_asic_num must equal chain_asic_num",
                row.machine_id
            );
        }
    }

    /// The `chain_row × chain_column` fields are a **placement grid, not a
    /// product**: on the BM1398P records the grid is LARGER than the ASIC
    /// count (NBS1902/NBT1903: 8×10 = 80 grid slots for 76 ASICs; NBP1901:
    /// 12×10 = 120 slots for 114). Pinned so nobody derives a false 80/120
    /// chip count from the grid. Only BHB42701's grid is exactly populated
    /// (12×9 = 108).
    #[test]
    fn row_column_is_a_placement_grid_not_a_chip_product() {
        assert_eq!(S19_NBS1902_STOCK.row_column_product(), Some(80));
        assert_eq!(S19_NBS1902_STOCK.chips_per_chain, 76);
        assert_eq!(T19_NBT1903_STOCK.row_column_product(), Some(80));
        assert_eq!(T19_NBT1903_STOCK.chips_per_chain, 76);
        assert_eq!(S19_PRO_NBP1901_STOCK.row_column_product(), Some(120));
        assert_eq!(S19_PRO_NBP1901_STOCK.chips_per_chain, 114);
        assert_eq!(S19J_CLASSIC_BHB42701_STOCK.row_column_product(), Some(108));
        assert_eq!(S19J_CLASSIC_BHB42701_STOCK.chips_per_chain, 108);
    }

    /// The `chain_num: 4` slot-semantics caveat stays machine-visible: the
    /// field is transcribed as a literal and never surfaces as a physical
    /// populated-board claim (these are 3-board SKUs on a 4-slot control
    /// board; only BHB42803 in the same DB says 3).
    #[test]
    fn chain_num_field_is_slot_semantics_not_board_count() {
        for row in S19_FAMILY_STOCK_TOPOLOGIES {
            assert_eq!(
                row.stock_chain_num_field,
                Some(4),
                "{}: this generation's chain_num counts connector slots",
                row.machine_id
            );
        }
    }

    /// Controller/PSU/EEPROM contracts transcribed verbatim — including
    /// Bitmain's `AWP12` misspelling, which is preserved, never "corrected".
    #[test]
    fn controller_psu_eeprom_contracts_transcribed_verbatim() {
        for row in S19_FAMILY_STOCK_TOPOLOGIES {
            assert_eq!(row.pic_topol_label, Some("PIC1704"));
            assert_eq!(row.pic_i2c_addr, Some(0x20));
            assert_eq!(row.psu_i2c_addr, Some(0x10));
            assert_eq!(row.psu_gpio, Some(907));
            assert_eq!(row.eeprom_type, Some("AT24C02D"));
            assert_eq!(row.eeprom_i2c_addr, Some(0x50));
        }
        // The S19/S19 Pro/T19 records carry Bitmain's misspelling; the S19j
        // DB spells it correctly. Both are literal transcriptions.
        assert_eq!(S19_NBS1902_STOCK.psu_type, Some("AWP12"));
        assert_eq!(S19_PRO_NBP1901_STOCK.psu_type, Some("AWP12"));
        assert_eq!(T19_NBT1903_STOCK.psu_type, Some("AWP12"));
        assert_eq!(S19J_CLASSIC_BHB42701_STOCK.psu_type, Some("APW12"));
    }

    /// These rows are evidence records, never a silicon-table rival and never
    /// an energization authority: the module pins no freq/voltage datum and
    /// the struct carries no such field.
    #[test]
    fn rows_carry_no_energization_or_frequency_datum() {
        // Compile-time by construction (no such fields); the runtime pin is
        // the machine count itself so a future edit that widens this module
        // beyond transcription re-visits this test.
        assert_eq!(S19_FAMILY_STOCK_TOPOLOGIES.len(), 4);
        let ids: Vec<&str> = S19_FAMILY_STOCK_TOPOLOGIES
            .iter()
            .map(|r| r.machine_id)
            .collect();
        assert_eq!(ids, ["NBS1902", "NBP1901", "NBT1903", "BHB42701"]);
    }
}
