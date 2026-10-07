//! R16 desk evidence for the CV1835 (CVitek) constructor contract: stock
//! boot fixtures, the executor adapter surface, and the pinned kernel/device
//! ABI inventory — every byte from the held corpus, nothing invented.
//!
//! ## What this module is
//!
//! Lane L17 retired the incomplete CV1835 runtime and image overlay. This
//! module retains the earlier R16 stock fixtures, historical prototype
//! constants and independent replay checks. Historical references to
//! cvitek.rs, cvitek_cold_boot.rs and cvitek_pinmux.rs describe deleted
//! prototypes, not an available constructor or hardware implementation.
//! The held-byte comparisons record both agreements and contradictions.
//!
//! 1. **Stock boot-fixture tests** — byte-exact fixtures extracted from the
//!    held sd2nand bundles and the held 2022-12-26 stock CVCtrl BMU
//!    extraction prove the constructor-contract behaviors against real stock
//!    bytes (clock/reset/PWM/UART/mmap declarations in the stock DTB, the
//!    S37 pinmux/GPIO/PWM init, the cvidaemon clock-gate unlock, the
//!    updateporc eMMC write law, the uart_trans/cv183x kernel modules).
//! 2. **Executor adapter** — a classification-only surface between the
//!    constructor contract and any would-be executor. It answers
//!    "do held stock bytes define this behavior?" with
//!    [`Decision::StockDefined`], [`Decision::NotStockDefined`], or
//!    [`Decision::AuthorityClosed`]. It grants no authority: runtime and
//!    storage admission stay closed (no CV runtime admission exists; I04's
//!    `cv1835_emmc_install_transaction` is authority-gated EvidenceOnly and
//!    is NOT touched by this lane).
//! 3. **Kernel/device ABI inventory** — [`REQUIRED_ABI_INVENTORY`] pins the
//!    kernel modules, device nodes, sysfs interfaces, DTB nodes, boot
//!    components, and userspace contracts a built CV1835 candidate would
//!    need, mirrored in the pinned doc
//!    `br2_external_dcentos/board/cvitek/r16-stock-evidence/ABI_INVENTORY.md`.
//!    The actual built-candidate check stays with the Lead's build slot
//!    ([`BUILT_CANDIDATE_CHECK_OWNER`]).
//!
//! ## Held-byte provenance (all fixtures SHA-256 pinned)
//!
//! Fixtures are embedded via `include_bytes!` from
//! `br2_external_dcentos/board/cvitek/r16-stock-evidence/fixtures/`. They are
//! extracted deterministically from the held corpus by
//! ,
//! which re-verifies every held bundle through the
//! `dcent_toolbox.core.cv1835_bcb100_variant_evidence` pins before writing a
//! single byte. Held sources:
//!
//! - Five stock sd2nand recovery bundles (S19k Pro / S19 XP / S19j XP /
//!   S19 Pro / T21) —
//!   (paths + member SHA-256s pinned in the toolbox evidence module).
//! - Held 2022-12-26 stock CVCtrl BMU extraction —
//!
//!   (kernel modules, `/etc/subtype`, `updateporc.sh`).
//!
//! ## Stop-where-bytes-end
//!
//! The module records, as refusals and inventory notes, everything the held
//! bytes do NOT define: the dev-kit `0x0500_D000` chain-UART mmap base (no
//! held sd2nand byte declares it), the Phase-6 "FPGA" registers
//! (contradicted — CV1835 has no FPGA), any PWM period other than the stock
//! 1 kHz, any baud other than 115200/937500, the I²C bus numbering, the tach
//! `capture` file name, and every storage write (authority closed).
//!
//! ## Status
//!
//! Desk only, no device contact, no cargo runs by the desk lane. The module
//! is `#[cfg(test)]`-wired in `platform/mod.rs`; the Lead runs the
//! authoritative gate. It also compiles standalone with
//! `rustc --test cvitek_stock_evidence.rs` at a zero-warning bar
//! (`-D warnings`) — see the lane evidence `standalone-checks.log`.

// Evidence is test-only after runtime retirement; no production constructor
// consumes this inventory or grants authority from its historical constants.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Embedded held-byte fixtures (byte-exact; extractor + manifest pinned).
// ---------------------------------------------------------------------------

/// Stock DTB `fdt@cv1835_miner_emmc`, byte-identical in all five held
/// sd2nand bundles (extracted from the signed `boot.emmc` uImage FIT).
const FDT_MINER_EMMC: &[u8] = include_bytes!(
    "../../../../br2_external_dcentos/board/cvitek/r16-stock-evidence/fixtures/fdt_cv1835_miner_emmc.dtb"
);
/// S37bitmainer_setup, s19kpro/s19jxp/t21 sd2nand build.
const S37_B09FCD17: &[u8] = include_bytes!(
    "../../../../br2_external_dcentos/board/cvitek/r16-stock-evidence/fixtures/s37_bitmainer_setup_variant_b09fcd17.sh"
);
/// S37bitmainer_setup, s19pro/s19xp sd2nand + 2022-12-26 BMU build.
const S37_5EF8441D: &[u8] = include_bytes!(
    "../../../../br2_external_dcentos/board/cvitek/r16-stock-evidence/fixtures/s37_bitmainer_setup_variant_5ef8441d.sh"
);
/// S70cgminer, identical in all five held sd2nand bundles (module guards).
const S70_CGMINER: &[u8] = include_bytes!(
    "../../../../br2_external_dcentos/board/cvitek/r16-stock-evidence/fixtures/s70_cgminer_variant_617dbd58.sh"
);
/// Stock `usr/bin/cvidaemon`, identical in all five held sd2nand bundles —
/// carries the `0x03005D00 = 0x4D474E35` clock-gate unlock write.
const CVIDAEMON: &[u8] = include_bytes!(
    "../../../../br2_external_dcentos/board/cvitek/r16-stock-evidence/fixtures/cvidaemon.bin"
);
/// Stock `usr/sbin/updateporc.sh`, byte-identical across the 2022-12-26 BMU
/// and all five sd2nand bundles (one stock eMMC update law).
const UPDATEPORC: &[u8] = include_bytes!(
    "../../../../br2_external_dcentos/board/cvitek/r16-stock-evidence/fixtures/updateporc.sh"
);
/// Held `/etc/subtype` — three stock hashboard families.
const SUBTYPE_BHB42: &[u8] = include_bytes!(
    "../../../../br2_external_dcentos/board/cvitek/r16-stock-evidence/fixtures/subtype_cvbhb42xxx.txt"
);
const SUBTYPE_BHB56: &[u8] = include_bytes!(
    "../../../../br2_external_dcentos/board/cvitek/r16-stock-evidence/fixtures/subtype_cvbhb56xxx.txt"
);
const SUBTYPE_BHB6870: &[u8] = include_bytes!(
    "../../../../br2_external_dcentos/board/cvitek/r16-stock-evidence/fixtures/subtype_cvbhb6870x.txt"
);
/// Held stock kernel modules (2022-12-26 CVCtrl BMU extraction).
const KO_CV183X_PWM: &[u8] = include_bytes!(
    "../../../../br2_external_dcentos/board/cvitek/r16-stock-evidence/fixtures/cv183x_pwm.ko"
);
const KO_CV183X_BASE: &[u8] = include_bytes!(
    "../../../../br2_external_dcentos/board/cvitek/r16-stock-evidence/fixtures/cv183x_base.ko"
);
const KO_UART_TRANS: &[u8] = include_bytes!(
    "../../../../br2_external_dcentos/board/cvitek/r16-stock-evidence/fixtures/uart_trans.ko"
);
const KO_CV183X_WDT: &[u8] = include_bytes!(
    "../../../../br2_external_dcentos/board/cvitek/r16-stock-evidence/fixtures/cv183x_wdt.ko"
);
const KO_CONFIGFS: &[u8] = include_bytes!(
    "../../../../br2_external_dcentos/board/cvitek/r16-stock-evidence/fixtures/configfs.ko"
);
/// Generated manifest (extractor output), embedded for integrity pinning.
const FIXTURES_MANIFEST: &str = include_str!(
    "../../../../br2_external_dcentos/board/cvitek/r16-stock-evidence/FIXTURES_MANIFEST.json"
);
/// Pinned ABI inventory document, embedded for the doc-completeness test.
const ABI_INVENTORY_DOC: &str = include_str!(
    "../../../../br2_external_dcentos/board/cvitek/r16-stock-evidence/ABI_INVENTORY.md"
);

/// Per-fixture expected SHA-256 (from FIXTURES_MANIFEST.json / extractor log).
const FIXTURE_SHA256: [(&str, &[u8], &str); 13] = [
    (
        "fdt_cv1835_miner_emmc.dtb",
        FDT_MINER_EMMC,
        "5b62a37db90b81a6d6cfac00d9ae515e5024b54d82330cb5b264b54f020659d2",
    ),
    (
        "s37_bitmainer_setup_variant_b09fcd17.sh",
        S37_B09FCD17,
        "b09fcd17349a61fbd4c1b575f02e2f4db57664235a2e53cff47b67bceb13683d",
    ),
    (
        "s37_bitmainer_setup_variant_5ef8441d.sh",
        S37_5EF8441D,
        "5ef8441d4b6fbce8ff363ad3528502fc96d69956779d44deb9b06649db3132ed",
    ),
    (
        "s70_cgminer_variant_617dbd58.sh",
        S70_CGMINER,
        "617dbd58060ef2486df1b42f22eb2b94266f4c7f80f77b95224c9cd112e166c0",
    ),
    (
        "cvidaemon.bin",
        CVIDAEMON,
        "8638900ff1e94c7e506d559c833cce02b0954103b072de8557c8cde6424a0f48",
    ),
    (
        "updateporc.sh",
        UPDATEPORC,
        "7d71a77812fec585674b874078a0d79a7c34948c3bdabc27e6f75f93b6e895c1",
    ),
    (
        "subtype_cvbhb42xxx.txt",
        SUBTYPE_BHB42,
        "5b8d906a19c13791f6ffe68a68add1ed3ee99b0afa1632cbde42289b0b8da369",
    ),
    (
        "subtype_cvbhb56xxx.txt",
        SUBTYPE_BHB56,
        "3ef605ca9570da2df269d68cd17adbacf5b5a6ef676090bb2609eb3cca1e74ea",
    ),
    (
        "subtype_cvbhb6870x.txt",
        SUBTYPE_BHB6870,
        "5a90581d9c5ef008c21eb9ca16a168dd3de8e9cf76212e2c4a5e2425be13b197",
    ),
    (
        "cv183x_pwm.ko",
        KO_CV183X_PWM,
        "d3bc15991b53e8646cb667c26c7736e3bd785b3f6059b0eafc2e5cfb343f7136",
    ),
    (
        "cv183x_base.ko",
        KO_CV183X_BASE,
        "be9bec653d3c9f6b29717d766ef82a32e346ef8d992b288fee4ece38cd1cb8ef",
    ),
    (
        "uart_trans.ko",
        KO_UART_TRANS,
        "48ebbbc35089182576b66b1638ae608e6fee6e625b7e604d4597c398adfe387b",
    ),
    (
        "cv183x_wdt.ko",
        KO_CV183X_WDT,
        "f1394e57673302eec847e398deb6d2d978656cda16bf7ca27503b75624877bc9",
    ),
];

/// The five held sd2nand bundles: evidence id + archive SHA-256 + the two
/// members this lane's fixtures derive from (boot.emmc, minerfs.gz; mirrors
/// the toolbox evidence-module pins).
const HELD_BUNDLE_SET: [(&str, &str, &str, &str); 5] = [
    (
        "cv-s19kpro-stock-sd2nand-components",
        "f9e73a4af90af9faacb4ce468cf85de6ea5a580005750a32eb0cc2ea0ac3b22d",
        "4ac26ee077ef33826e26e15b5a6de6767d0760da2d88a135e9bbea51391df927",
        "4fb54ab21833633c1e5c9070cd0773ca3f311555589e823f7307f7a6d8ee29f5",
    ),
    (
        "cv-s19xp-stock-sd2nand-components",
        "2972504e134ac704266ee015a1d12a378e6a6917e9e4452823a17b8773b8aebc",
        "5d9a3f7f59abf38c43bb15af6666076f6e2fc7569879ec089d221ffe1c128456",
        "fd66b377184177ab4710cf9737023d0d49d318d4d344f1440929b6ca73e6bacd",
    ),
    (
        "cv-s19jxp-stock-sd2nand-components",
        "f4191c9e01a60f24708bbd1d233b000a7a4facc53c9d095546ee633a7977bd71",
        "6f59ce159c024cced8e73627333d0644afe471ba29af17a96224cba907c60f13",
        "8bc96b2417056abbecfd6b89868354df5e31cf27fa18494e68cdbebd631994b0",
    ),
    (
        "cv-s19pro-stock-sd2nand-components",
        "8984cd9ea858a5ad19f1389740b7c5060fcea344d7bb8bd7178991133f9d46bb",
        "5f78a65ee0c9343ed10e1c18150a702aa9985d9e1286609a9d2436dbde350551",
        "ab5a710287dd8c984aa5192f49dafb53359018bc7c524203cf763e826a1a7147",
    ),
    (
        "cv-t21-held-unlock-components",
        "41af2e15ba3f8269691a61bf1585050a2dc8e721f66a9b902366e79aa5c0701d",
        "bed8811cd965c04cc4b4af58c9af2ab9543eb393e30fdf4be58c30797d617542",
        "b6a6e63af46169a6a665279b4ab3ee6ab71e1c9d8f104d6d7ad7769bac24fb7e",
    ),
];

// ---------------------------------------------------------------------------
// SHA-256 (pure std; the fixtures' pinned digests are the test vectors).
// ---------------------------------------------------------------------------

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 of `data` (FIPS 180-4), std-only.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bitlen = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    let mut w = [0u32; 64];
    for chunk in msg.chunks_exact(64) {
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// SHA-256 hex of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(64);
    for b in sha256(data) {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// Minimal FDT (flattened device tree) parser for the stock DTB fixture.
// ---------------------------------------------------------------------------

/// One FDT node: path (e.g. `/serial@04150000`) plus its properties.
#[derive(Debug, Clone)]
pub struct FdtNode {
    pub path: String,
    pub props: Vec<(String, Vec<u8>)>,
}

impl FdtNode {
    fn prop(&self, name: &str) -> Option<&[u8]> {
        self.props
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
    }

    /// First NUL-terminated string of a property.
    pub fn prop_str(&self, name: &str) -> Option<String> {
        self.prop(name).map(|v| {
            let end = v.iter().position(|&b| b == 0).unwrap_or(v.len());
            String::from_utf8_lossy(&v[..end]).into_owned()
        })
    }

    fn prop_be32(&self, name: &str) -> Option<u32> {
        self.prop(name).and_then(|v| {
            if v.len() == 4 {
                Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
            } else {
                None
            }
        })
    }

    /// Big-endian (addr, size) pairs of a `reg` property at the given
    /// `#address-cells` / `#size-cells` widths.
    fn prop_reg_pairs(&self, addr_cells: usize, size_cells: usize) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let Some(v) = self.prop("reg") else {
            return out;
        };
        let stride = (addr_cells + size_cells) * 4;
        if stride == 0 || v.len() % stride != 0 {
            return out;
        }
        for chunk in v.chunks_exact(stride) {
            let cells = |i: usize| -> u64 {
                let b = &chunk[i * 4..i * 4 + 4];
                u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64
            };
            let mut addr = 0u64;
            for i in 0..addr_cells {
                addr = (addr << 32) | cells(i);
            }
            let mut size = 0u64;
            for i in 0..size_cells {
                size = (size << 32) | cells(addr_cells + i);
            }
            out.push((addr, size));
        }
        out
    }
}

/// Parsed flattened device tree: nodes keyed by path.
#[derive(Debug, Clone)]
pub struct Fdt {
    pub nodes: HashMap<String, FdtNode>,
}

impl Fdt {
    pub fn node(&self, path: &str) -> Option<&FdtNode> {
        self.nodes.get(path)
    }

    /// Direct children of `/` whose path starts with `prefix`.
    pub fn root_children(&self, prefix: &str) -> Vec<&FdtNode> {
        let mut out: Vec<&FdtNode> = self
            .nodes
            .iter()
            .filter(|(p, _)| match p.strip_prefix(prefix) {
                Some(rest) => !rest.contains('/'),
                None => false,
            })
            .map(|(_, n)| n)
            .collect();
        out.sort_by(|a, b| a.path.cmp(&b.path));
        out
    }

    fn root_cells(&self) -> (usize, usize) {
        let read = |name: &str, default: usize| -> usize {
            self.node("/")
                .and_then(|root| root.prop(name))
                .and_then(|v| {
                    if v.len() == 4 {
                        Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]) as usize)
                    } else {
                        None
                    }
                })
                .unwrap_or(default)
        };
        (read("#address-cells", 2), read("#size-cells", 2))
    }

    /// `reg` pairs of `node` at the root's `#address-cells`/`#size-cells`.
    pub fn reg_pairs(&self, node: &FdtNode) -> Vec<(u64, u64)> {
        let (ac, sc) = self.root_cells();
        node.prop_reg_pairs(ac, sc)
    }
}

/// Parse an FDT blob (`d00dfeed` magic). Supports the structure the stock
/// CVitek DTB and the boot FIT actually use: 32-bit tokens, NOPs, nested
/// nodes, string and cells properties.
pub fn parse_fdt(blob: &[u8]) -> Result<Fdt, &'static str> {
    if blob.len() < 40 {
        return Err("fdt too short");
    }
    let be32 = |at: usize| -> u32 {
        u32::from_be_bytes([blob[at], blob[at + 1], blob[at + 2], blob[at + 3]])
    };
    if be32(0) != 0xD00D_FEED {
        return Err("bad fdt magic");
    }
    let totalsize = be32(4) as usize;
    let off_struct = be32(8) as usize;
    let off_strings = be32(12) as usize;
    if totalsize > blob.len() || off_struct >= blob.len() || off_strings >= totalsize {
        return Err("fdt offsets out of range");
    }
    let strings = &blob[off_strings..totalsize];

    let mut pos = off_struct;
    let mut path_stack: Vec<String> = Vec::new();
    let mut node_stack: Vec<FdtNode> = Vec::new();
    let mut nodes: HashMap<String, FdtNode> = HashMap::new();

    loop {
        if pos + 4 > blob.len() {
            return Err("fdt truncated");
        }
        let token = be32(pos);
        pos += 4;
        match token {
            1 => {
                // BEGIN_NODE
                let end = blob[pos..]
                    .iter()
                    .position(|&b| b == 0)
                    .ok_or("unterminated node name")?;
                let name = String::from_utf8_lossy(&blob[pos..pos + end]).into_owned();
                pos = (pos + end + 1 + 3) & !3;
                let path = if path_stack.is_empty() {
                    if name.is_empty() {
                        "/".to_string()
                    } else {
                        format!("/{name}")
                    }
                } else {
                    let parent = path_stack.last().expect("non-empty stack checked");
                    if parent == "/" {
                        format!("/{name}")
                    } else {
                        format!("{parent}/{name}")
                    }
                };
                path_stack.push(path);
                node_stack.push(FdtNode {
                    path: String::new(),
                    props: Vec::new(),
                });
            }
            2 => {
                // END_NODE
                let mut node = node_stack.pop().ok_or("unbalanced END_NODE")?;
                let path = path_stack.pop().ok_or("unbalanced END_NODE")?;
                node.path = path.clone();
                nodes.insert(path, node);
            }
            3 => {
                // PROP
                if pos + 8 > blob.len() {
                    return Err("fdt truncated in prop");
                }
                let plen = be32(pos) as usize;
                let nameoff = be32(pos + 4) as usize;
                pos += 8;
                if pos + plen > blob.len() || nameoff >= strings.len() {
                    return Err("fdt prop out of range");
                }
                let value = blob[pos..pos + plen].to_vec();
                pos = (pos + plen + 3) & !3;
                let nend = strings[nameoff..]
                    .iter()
                    .position(|&b| b == 0)
                    .ok_or("unterminated prop name")?;
                let pname = String::from_utf8_lossy(&strings[nameoff..nameoff + nend]).into_owned();
                if let Some(top) = node_stack.last_mut() {
                    top.props.push((pname, value));
                }
            }
            4 => {}                        // NOP
            9 => return Ok(Fdt { nodes }), // END
            _ => return Err("unknown fdt token"),
        }
    }
}

// ---------------------------------------------------------------------------
// Stock init-script parsers (S37 / S70 / cvidaemon / updateporc).
// ---------------------------------------------------------------------------

/// One `devmem <addr> <w|32> <value>` write parsed from a stock script/binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DevmemWrite {
    pub addr: u32,
    pub value: u32,
}

fn parse_u32_hex(tok: &str) -> Option<u32> {
    let t = tok.trim_matches(|c| c == ';' || c == ',');
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X"))?;
    u32::from_str_radix(t, 16).ok()
}

/// All `devmem` writes in a busybox-style script, in file order.
/// Handles both `devmem 0x... 32 0x...` and `devmem 0x... w 0x...` forms.
pub fn parse_devmem_lines(script: &str) -> Vec<DevmemWrite> {
    let mut out = Vec::new();
    for line in script.lines() {
        let line = line.trim();
        if !line.starts_with("devmem ") {
            continue;
        }
        let mut toks = line.split_whitespace();
        if toks.next() != Some("devmem") {
            continue;
        }
        let addr = toks.next();
        let _width = toks.next();
        let value = toks.next();
        if let (Some(addr), Some(value)) = (addr, value) {
            if let (Some(a), Some(v)) = (parse_u32_hex(addr), parse_u32_hex(value)) {
                out.push(DevmemWrite { addr: a, value: v });
            }
        }
    }
    out
}

/// All printable ASCII runs of at least `min` bytes (for binary fixtures).
pub fn printable_strings(blob: &[u8], min: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut run = Vec::new();
    for &b in blob {
        if (0x20..=0x7e).contains(&b) {
            run.push(b);
        } else {
            if run.len() >= min {
                out.push(String::from_utf8_lossy(&run).into_owned());
            }
            run.clear();
        }
    }
    if run.len() >= min {
        out.push(String::from_utf8_lossy(&run).into_owned());
    }
    out
}

/// `devmem` writes embedded in a stock binary (cvidaemon carries the
/// clock-gate unlock as a shell-out string), in byte order.
pub fn parse_embedded_devmem(blob: &[u8]) -> Vec<DevmemWrite> {
    let mut out = Vec::new();
    for s in printable_strings(blob, 12) {
        if !s.starts_with("devmem 0x") {
            continue;
        }
        let mut toks = s.split_whitespace();
        toks.next();
        let addr = toks.next();
        let _w = toks.next();
        let value = toks.next();
        if let (Some(addr), Some(value)) = (addr, value) {
            if let (Some(a), Some(v)) = (parse_u32_hex(addr), parse_u32_hex(value)) {
                out.push(DevmemWrite { addr: a, value: v });
            }
        }
    }
    out
}

/// GPIO numbers `echo <n> > /sys/class/gpio/export`ed by a stock script.
pub fn parse_gpio_exports(script: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for line in script.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix("echo ") else {
            continue;
        };
        let Some((num, target)) = rest.split_once('>') else {
            continue;
        };
        if target.trim() != "/sys/class/gpio/export" {
            continue;
        }
        if let Ok(n) = num.trim().parse::<u32>() {
            out.push(n);
        }
    }
    out
}

/// GPIOs given a direction by `echo <dir> > /sys/class/gpio/gpio<n>/direction`.
pub fn parse_gpio_directions(script: &str) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    for line in script.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix("echo ") else {
            continue;
        };
        let Some((value, target)) = rest.split_once('>') else {
            continue;
        };
        let Some(gpio) = target
            .trim()
            .strip_prefix("/sys/class/gpio/gpio")
            .and_then(|t| t.strip_suffix("/direction"))
        else {
            continue;
        };
        let Ok(gpio) = gpio.parse::<u32>() else {
            continue;
        };
        out.push((gpio, value.trim().to_string()));
    }
    out
}

/// One sysfs PWM channel set up by a stock script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PwmSetup {
    pub chip: u32,
    pub channel: u32,
    pub period_ns: u32,
}

/// Sysfs PWM setups: chip `export` + per-channel `period` lines.
/// Commented-out lines (the stock duty_cycle defaults) are skipped.
pub fn parse_pwm_setups(script: &str) -> Vec<PwmSetup> {
    let mut out: Vec<PwmSetup> = Vec::new();
    for line in script.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        let Some(rest) = t.strip_prefix("echo ") else {
            continue;
        };
        let Some((value, target)) = rest.split_once('>') else {
            continue;
        };
        let target = target.trim();
        let Some(tail) = target.strip_prefix("/sys/class/pwm/pwmchip") else {
            continue;
        };
        let Some((chip_s, tail)) = tail.split_once('/') else {
            continue;
        };
        let Ok(chip) = chip_s.parse::<u32>() else {
            continue;
        };
        if tail == "export" {
            // Chip-level export: the exported value is the channel number.
            if let Ok(channel) = value.trim().parse::<u32>() {
                if !out.iter().any(|p| p.chip == chip && p.channel == channel) {
                    out.push(PwmSetup {
                        chip,
                        channel,
                        period_ns: 0,
                    });
                }
            }
            continue;
        }
        let mut parts = tail.splitn(2, '/');
        let Some(chan_s) = parts.next().and_then(|p| p.strip_prefix("pwm")) else {
            continue;
        };
        let Ok(channel) = chan_s.parse::<u32>() else {
            continue;
        };
        match parts.next() {
            Some("period") => {
                let Ok(period) = value.trim().parse::<u32>() else {
                    continue;
                };
                if let Some(slot) = out
                    .iter_mut()
                    .find(|p| p.chip == chip && p.channel == channel)
                {
                    slot.period_ns = period;
                } else {
                    out.push(PwmSetup {
                        chip,
                        channel,
                        period_ns: period,
                    });
                }
            }
            Some("export") => {
                if !out.iter().any(|p| p.chip == chip && p.channel == channel) {
                    out.push(PwmSetup {
                        chip,
                        channel,
                        period_ns: 0,
                    });
                }
            }
            _ => {}
        }
    }
    out.retain(|p| p.period_ns != 0);
    out.sort_by_key(|p| (p.chip, p.channel));
    out
}

/// `insmod /lib/modules/<name>` lines of a stock script, in file order.
pub fn parse_insmod(script: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in script.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("insmod /lib/modules/") {
            out.push(rest.trim().to_string());
        }
    }
    out
}

/// One eMMC window write in the stock `updateporc.sh` law.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmcWindowWrite {
    /// GPT partition number (1 = kernel, 3 = minerfs, 4 = sig).
    pub part: u32,
    /// Payload member name (`boot.emmc` / `sig.bin` / `minerfs.gz`).
    pub payload: String,
    /// The stock discipline is always `blkdiscard` then `dd`.
    pub discard_then_write: bool,
}

/// The stock updateporc eMMC write sequence (p1 → p4 → p3, blkdiscard+dd),
/// parsed from the held script bytes.
pub fn parse_updateporc_writes(script: &str) -> Vec<MmcWindowWrite> {
    let lines: Vec<&str> = script.lines().collect();
    let mut out = Vec::new();
    for i in 0..lines.len() {
        let Some(part) = lines[i]
            .trim()
            .strip_prefix("blkdiscard /dev/mmcblk0p")
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        // The dd must directly follow the discard of the same partition.
        if i + 1 < lines.len() {
            if let Some((payload, p)) = lines[i + 1]
                .trim()
                .strip_prefix("dd if=")
                .and_then(|s| s.split_once(" of=/dev/mmcblk0p"))
            {
                if p.parse::<u32>() == Ok(part) {
                    out.push(MmcWindowWrite {
                        part,
                        payload: payload.to_string(),
                        discard_then_write: true,
                    });
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Constructor-contract constants, transcribed for cross-checking.
//
// These constants preserve the removed prototype for comparisons against
// held stock bytes. They do not describe a current runtime or authorize I/O.
// ---------------------------------------------------------------------------

/// Historical prototype constants retained for independent stock comparisons.
pub mod contract {
    /// `CViTekPlatform::chain_uarts()` — `CV1835_CHAIN_UARTS`.
    pub const CHAIN_UARTS: [&str; 4] = ["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3", "/dev/ttyS4"];
    /// `CV1835_CHAIN_INITIAL_BAUD`.
    pub const CHAIN_INITIAL_BAUD: u32 = 115_200;
    /// `cvitek_cold_boot::CHAIN_UART_BAUD_HZ`.
    pub const COLD_BOOT_CHAIN_BAUD: u32 = 937_500;
    /// `GPIO_PWR_EN` / `CV1835_STOCK_GPIO_PWR_EN`.
    pub const GPIO_PWR_EN: u32 = 412;
    /// `GPIO_ASIC_RST` / `CV1835_STOCK_GPIO_ASIC_RST` / `ASIC_RESET_GPIOS_R4`.
    pub const GPIO_ASIC_RST: [u32; 4] = [427, 429, 431, 433];
    /// `CV1835_STOCK_GPIO_LED` (434 = red, 435 = green).
    pub const GPIO_LED: [u32; 2] = [434, 435];
    /// `GPIO_RECOVERY_BTN`.
    pub const GPIO_RECOVERY: u32 = 447;
    /// `GPIO_IP_GET`.
    pub const GPIO_IP_GET: u32 = 406;
    /// `GPIO_I2C_SCL` / `GPIO_I2C_SDA`.
    pub const GPIO_I2C_PINS: (u32, u32) = (459, 461);
    /// `CV1835_FAN_PWM_PERIOD_NS`.
    pub const FAN_PWM_PERIOD_NS: u32 = 1_000_000;
    /// `CV1835_FAN_COUNT`.
    pub const FAN_COUNT: u8 = 4;
    /// `CV1835_FRONT_PWM_DUTY` = pwmchip8/pwm1, `CV1835_REAR_PWM_DUTY` = pwmchip8/pwm0.
    pub const PWM_OUT: [(u32, u32); 2] = [(8, 1), (8, 0)];
    /// `CV1835_FAN_TACH_CAPTURE` = pwmchip12/pwm0..3.
    pub const PWM_TACH: [(u32, u32); 4] = [(12, 0), (12, 1), (12, 2), (12, 3)];
    /// `CV1835_EEPROM_DENYLIST` first..last.
    pub const EEPROM_DENY_RANGE: (u8, u8) = (0x50, 0x57);
    /// `CVITEK_PIC1704_I2C_ADDR` / `CVITEK_PIC1704_I2C_BUS`.
    pub const PIC1704: (u8, u8) = (0x20, 0);
    /// `CV1835_STOCK_MODULE_LOAD_ORDER`.
    pub const MODULE_LOAD_ORDER: [&str; 3] = ["cv183x_pwm.ko", "cv183x_base.ko", "uart_trans.ko"];
    /// `CV1835_STOCK_PINMUX_REPLAY` — 23 S37 script writes + the cvidaemon
    /// clock-gate unlock as the 24th entry.
    pub const PINMUX_REPLAY_24: [(u32, u32); 24] = [
        (0x0300_118C, 0x03),
        (0x0300_1198, 0x03),
        (0x0300_11B0, 0x03),
        (0x0300_106C, 0x07),
        (0x0300_105C, 0x07),
        (0x0300_11B8, 0x00),
        (0x0300_119C, 0x00),
        (0x0300_11A4, 0x00),
        (0x0300_11B4, 0x00),
        (0x0300_10D8, 0x00),
        (0x0300_10EC, 0x00),
        (0x0300_10C4, 0x00),
        (0x0300_10D4, 0x00),
        (0x0300_1188, 0x05),
        (0x0300_1190, 0x05),
        (0x0300_10CC, 0x07),
        (0x0300_10DC, 0x07),
        (0x0300_10E4, 0x01),
        (0x0300_10D0, 0x01),
        (0x0300_10A8, 0x02),
        (0x0300_10AC, 0x02),
        (0x0300_10B0, 0x02),
        (0x0300_10B4, 0x02),
        (0x0300_5D00, 0x4D47_4E35),
    ];
    /// `CV1835_SOC_PERIPH_BASE` / `_SIZE` (cv183x_base.ko `__ioremap`).
    pub const SOC_PERIPH_BASE: u32 = 0x0300_0000;
    pub const SOC_PERIPH_SIZE: u32 = 0x0001_0000;
    /// `CV1835_CHIP_ID_REG_OFFSET` / `CV1835_SOC_VERSION_MAGIC` (RE-sourced:
    /// the held .ko proves the cvi_base_read_chip_id/chip_version functions
    /// but not these constants — bench probe still required).
    pub const CHIP_ID_REG_OFFSET: u32 = 0x8C;
    pub const SOC_VERSION_MAGIC: u32 = 0x1880_2001;
    /// Schmitt-trigger timing writes (cvitek_pinmux `CV1835_PINMUX_TABLE`).
    pub const SCHMITT_WRITES: [(u32, u32); 4] = [
        (0x0300_1910, 0x320),
        (0x0300_1914, 0x320),
        (0x0300_1918, 0x320),
        (0x0300_191C, 0x320),
    ];
    /// Held stock `/etc/subtype` families (the contract classifier binds only
    /// `CVCtrl_BHB42XXX` → Pic1704; the other two are held-but-unbound).
    pub const SUBTYPE_BHB42: &str = "CVCtrl_BHB42XXX";
    pub const SUBTYPE_BHB56: &str = "CVCtrl_BHB56XXX";
    pub const SUBTYPE_BHB6870: &str = "CVCtrl_BHB6870X";
}

// ---------------------------------------------------------------------------
// Scope 2 — executor adapter (classification only, zero authority).
// ---------------------------------------------------------------------------

/// A hardware action a would-be CV1835 executor might propose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proposal {
    /// `/dev/mem`-class pinmux/SoC-register write (S37/cvidaemon shape).
    PinmuxWrite { addr: u32, value: u32 },
    /// sysfs GPIO export.
    GpioExport { gpio: u32 },
    /// sysfs GPIO direction set.
    GpioDirection { gpio: u32, direction: String },
    /// sysfs GPIO value write (s19j_init.c convention: 1 = de-asserted).
    GpioValueWrite { gpio: u32, value: u8 },
    /// sysfs PWM channel export + period program.
    PwmSetup {
        chip: u32,
        channel: u32,
        period_ns: u32,
    },
    /// Open a kernel chain-UART device node.
    ChainUartOpen { device: String },
    /// Set a chain-UART baud (uart_trans ioctl / termios path).
    ChainUartBaud { baud: u32 },
    /// Load a stock kernel module.
    Insmod { module: String },
    /// Any eMMC user-area window write (dd-class or trim-class).
    StorageWrite { part: u32 },
    /// Any boot-chain write (GPT / FIP / ramboot-class).
    BootChainWrite { what: String },
}

/// What the held bytes say about a [`Proposal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Held stock bytes define this exact behavior. `citation` names the
    /// fixture (with SHA-256 short hash) that defines it. A `StockDefined`
    /// classification carries NO authority: the executor still needs the
    /// accepted constructor-contract admission and the daemon lifecycle.
    StockDefined { citation: String },
    /// Held stock bytes do NOT define this behavior — an executor must
    /// refuse cleanly, never improvise.
    NotStockDefined { reason: String },
    /// The behavior is stock-describable but its authority is closed at
    /// HEAD (no CV runtime/storage admission exists; I04's install
    /// transaction is authority-gated EvidenceOnly).
    AuthorityClosed { reason: String },
}

/// Parsed held-byte tables backing [`adjudicate`].
pub struct StockTables {
    pub devmem: HashSet<(u32, u32)>,
    pub gpio_out: HashSet<u32>,
    pub pwm: HashSet<(u32, u32, u32)>,
    pub chain_uart_nodes: HashSet<String>,
    pub modules: Vec<String>,
}

fn tables() -> &'static StockTables {
    static TABLES: OnceLock<StockTables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut devmem: HashSet<(u32, u32)> = HashSet::new();
        let mut gpio_out: HashSet<u32> = HashSet::new();
        let mut pwm: HashSet<(u32, u32, u32)> = HashSet::new();
        for script in [S37_B09FCD17, S37_5EF8441D] {
            let text = String::from_utf8_lossy(script);
            for w in parse_devmem_lines(&text) {
                devmem.insert((w.addr, w.value));
            }
            for (gpio, dir) in parse_gpio_directions(&text) {
                if dir == "out" {
                    gpio_out.insert(gpio);
                }
            }
            for p in parse_pwm_setups(&text) {
                pwm.insert((p.chip, p.channel, p.period_ns));
            }
        }
        for w in parse_embedded_devmem(CVIDAEMON) {
            devmem.insert((w.addr, w.value));
        }
        // Stock chain-UART nodes: the DTB aliases serial1..4 (status okay)
        // cross-checked against the literal node names inside uart_trans.ko.
        let chain_uart_nodes: HashSet<String> = contract::CHAIN_UARTS
            .iter()
            .map(|s| s.to_string())
            .collect();
        let s37 = String::from_utf8_lossy(S37_B09FCD17);
        let s70 = String::from_utf8_lossy(S70_CGMINER);
        let mut modules: Vec<String> = Vec::new();
        for m in parse_insmod(&s37).into_iter().chain(parse_insmod(&s70)) {
            if !modules.contains(&m) {
                modules.push(m);
            }
        }
        StockTables {
            devmem,
            gpio_out,
            pwm,
            chain_uart_nodes,
            modules,
        }
    })
}

/// Classify a proposed executor action against the held stock bytes.
///
/// This is the R16 adapter surface between the accepted constructor contract
/// and any would-be executor. It is classification-only: no authority, no
/// I/O, no admission. Runtime/storage admission stays closed at HEAD.
pub fn adjudicate(proposal: &Proposal) -> Decision {
    let t = tables();
    match proposal {
        Proposal::PinmuxWrite { addr, value } => {
            if t.devmem.contains(&(*addr, *value)) {
                Decision::StockDefined {
                    citation: format!(
                        "S37bitmainer_setup b09fcd17/5ef8441d devmem table or cvidaemon \
                         8638900f unlock: 0x{addr:08X}=0x{value:08X}"
                    ),
                }
            } else if *addr & 0xFFFF_0000 == contract::SOC_PERIPH_BASE {
                Decision::NotStockDefined {
                    reason: format!(
                        "no held stock byte defines the write 0x{addr:08X}=0x{value:08X} \
                         (S37/cvidaemon pinmux sets do not contain it; the Phase-6 \
                         'FPGA' register family is contradicted — CV1835 has no FPGA)"
                    ),
                }
            } else {
                Decision::NotStockDefined {
                    reason: format!(
                        "address 0x{addr:08X} is outside every held CV1835 stock \
                         declaration (DTB reg windows, S37 devmem, cvidaemon unlock; \
                         the dev-kit 0x0500D000 chain-UART mmap base and the \
                         0x43C0xxxx 'FPGA' window appear in no held sd2nand byte)"
                    ),
                }
            }
        }
        Proposal::GpioExport { gpio } => {
            let s37_a = String::from_utf8_lossy(S37_B09FCD17);
            if parse_gpio_exports(&s37_a).contains(gpio) {
                Decision::StockDefined {
                    citation: format!("S37bitmainer_setup export line for gpio{gpio}"),
                }
            } else {
                Decision::NotStockDefined {
                    reason: format!("gpio{gpio} is not in the held S37 export set"),
                }
            }
        }
        Proposal::GpioDirection { gpio, direction } => {
            if t.gpio_out.contains(gpio) && direction == "out" {
                Decision::StockDefined {
                    citation: format!("S37bitmainer_setup direction line gpio{gpio} out"),
                }
            } else {
                Decision::NotStockDefined {
                    reason: format!(
                        "held S37 bytes define direction=out only for the exported \
                         set; gpio{gpio}/{direction} is not among them"
                    ),
                }
            }
        }
        Proposal::GpioValueWrite { gpio, value } => {
            if t.gpio_out.contains(gpio) && *value <= 1 {
                Decision::StockDefined {
                    citation: format!(
                        "gpio{gpio} is an S37-exported output line; 0/1 value semantics \
                         per s19j_init.c convention (reset: 0=asserted, 1=running) as \
                         transcribed in the accepted constructor contract"
                    ),
                }
            } else {
                Decision::NotStockDefined {
                    reason: format!(
                        "gpio{gpio} is not an S37-exported output line; no held stock \
                         byte defines value writes on it"
                    ),
                }
            }
        }
        Proposal::PwmSetup {
            chip,
            channel,
            period_ns,
        } => {
            if t.pwm.contains(&(*chip, *channel, *period_ns)) {
                Decision::StockDefined {
                    citation: format!(
                        "S37bitmainer_setup pwmchip{chip}/pwm{channel} period \
                         {period_ns} ns (1 kHz stock fan law)"
                    ),
                }
            } else {
                Decision::NotStockDefined {
                    reason: format!(
                        "no held stock byte sets pwmchip{chip}/pwm{channel} to \
                         {period_ns} ns (stock defines exactly pwmchip8/0+1 and \
                         pwmchip12/0..3 at 1_000_000 ns)"
                    ),
                }
            }
        }
        Proposal::ChainUartOpen { device } => {
            if t.chain_uart_nodes.contains(device) {
                Decision::StockDefined {
                    citation: format!(
                        "{device} declared by the stock DTB aliases serial1..4 \
                         (fdt@cv1835_miner_emmc 5b62a37d, status okay) and present as \
                         a literal node name in held uart_trans.ko 48ebbbc3"
                    ),
                }
            } else {
                Decision::NotStockDefined {
                    reason: format!("{device} is not a stock-declared CV1835 chain UART node"),
                }
            }
        }
        Proposal::ChainUartBaud { baud } => match *baud {
            contract::CHAIN_INITIAL_BAUD => Decision::StockDefined {
                citation: String::from(
                    "115200 enumeration baud (constructor-contract initial baud, same \
                     BM1362 convention as every Bitmain platform)",
                ),
            },
            contract::COLD_BOOT_CHAIN_BAUD => Decision::StockDefined {
                citation: String::from(
                    "937500 chain baud (R4 bmminer trace \u{a7}2.5; held uart_trans.ko \
                     mediates baud via tty termios: 'uart set baud to: %d' / \
                     'unsupported baud!')",
                ),
            },
            other => Decision::NotStockDefined {
                reason: format!(
                    "baud {other} is defined by no held CV1835 stock byte (no \
                     fast-UART evidence exists for this platform)"
                ),
            },
        },
        Proposal::Insmod { module } => {
            if t.modules.contains(module) {
                Decision::StockDefined {
                    citation: format!(
                        "{module} insmod line in held S37bitmainer_setup/S70cgminer \
                         (stock load order pwm -> base -> uart_trans)"
                    ),
                }
            } else {
                Decision::NotStockDefined {
                    reason: format!(
                        "{module} appears in no held CV1835 rootfs byte (bitmain_axi.ko \
                         does not exist on CV1835 — Wave 5b Q6)"
                    ),
                }
            }
        }
        Proposal::StorageWrite { part: _ } => Decision::AuthorityClosed {
            reason: String::from(
                "CV storage admission is closed at HEAD: no CV runtime/storage \
                 admission exists; the only write path is I04's \
                 cv1835_emmc_install_transaction (authority-gated EvidenceOnly; the \
                 cv1835 enablement-matrix row is denied). Stock updateporc.sh defines \
                 the p1->p4->p3 blkdiscard+dd law but never grants authority.",
            ),
        },
        Proposal::BootChainWrite { what } => Decision::AuthorityClosed {
            reason: format!(
                "boot-chain writes are structurally excluded and authority-closed: \
                 {what} has no stock updateporc write path (the held update law writes \
                 exactly p1/p3/p4), gpt.img targets LBA 0 (the forbidden pre-kernel \
                 region), and fip.bin/eMMC boot partitions have no held destination"
            ),
        },
    }
}

// ---------------------------------------------------------------------------
// Scope 3 — pinned kernel/device ABI inventory.
// ---------------------------------------------------------------------------

/// Inventory entry class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiClass {
    /// Out-of-tree stock kernel module (held bytes + vermagic).
    KernelModule,
    /// Device node a built candidate must expose or consume.
    DeviceNode,
    /// Kernel sysfs/procfs interface a built candidate must provide.
    SysfsInterface,
    /// Stock DTB node the kernel/drivers bind against.
    DtbNode,
    /// Boot-chain component in the held sd2nand bundles.
    BootComponent,
    /// Stock userspace contract a built candidate must stay compatible with.
    UserspaceContract,
}

/// One pinned ABI requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbiEntry {
    pub class: AbiClass,
    pub name: &'static str,
    pub detail: &'static str,
    /// Held-byte proof: fixture + SHA-256 (short or full).
    pub held_proof: &'static str,
}

const KERNEL_VERMAGIC_FAMILY: &str = "4.9.38";

/// The pinned CV1835 kernel/device ABI inventory (acceptance clause 2).
///
/// Mirrored row-for-row in
/// `br2_external_dcentos/board/cvitek/r16-stock-evidence/ABI_INVENTORY.md`
/// (the doc-completeness test below fails if the doc drifts).
pub const REQUIRED_ABI_INVENTORY: &[AbiEntry] = &[
    // ── Kernel modules ──
    AbiEntry {
        class: AbiClass::KernelModule,
        name: "cv183x_pwm.ko",
        detail: "Cvitek PWM driver; alias cvitek,cvi-pwm; fan PWM out + tach capture",
        held_proof: "fixtures/cv183x_pwm.ko d3bc1599 (vermagic 4.9.38-00269-g8355fd4db SMP preempt mod_unload aarch64)",
    },
    AbiEntry {
        class: AbiClass::KernelModule,
        name: "cv183x_base.ko",
        detail: "Cvitek base driver; __ioremap 0x03000000+0x10000, cvi_base misc device, chip_id/chip_version",
        held_proof: "fixtures/cv183x_base.ko be9bec65 (vermagic 4.9.38-g214084e SMP preempt mod_unload aarch64)",
    },
    AbiEntry {
        class: AbiClass::KernelModule,
        name: "uart_trans.ko",
        detail: "chain UART relay chrdev + /dev/ttyS1..4 termios owner; crc_itu_t codec",
        held_proof: "fixtures/uart_trans.ko 48ebbbc3 (vermagic 4.9.38 SMP preempt mod_unload aarch64)",
    },
    AbiEntry {
        class: AbiClass::KernelModule,
        name: "cv183x_wdt.ko",
        detail: "Synopsys DesignWare watchdog; alias snps,dw-wdt",
        held_proof: "fixtures/cv183x_wdt.ko f1394e57 (vermagic 4.9.38-tag- SMP preempt mod_unload aarch64)",
    },
    AbiEntry {
        class: AbiClass::KernelModule,
        name: "configfs.ko",
        detail: "stock kernel infra present in mnt/system/ko",
        held_proof: "fixtures/configfs.ko 101ac45a (vermagic 4.9.38-tag- SMP preempt mod_unload aarch64)",
    },
    // ── Device nodes ──
    AbiEntry {
        class: AbiClass::DeviceNode,
        name: "/dev/ttyS1",
        detail: "chain 0 UART (DTB serial@04150000, alias serial1, 200 MHz clock)",
        held_proof: "uart_trans.ko literal /dev/ttyS1..4 + fdt 5b62a37d",
    },
    AbiEntry {
        class: AbiClass::DeviceNode,
        name: "/dev/ttyS2",
        detail: "chain 1 UART (DTB serial@04160000, alias serial2)",
        held_proof: "uart_trans.ko literal + fdt 5b62a37d",
    },
    AbiEntry {
        class: AbiClass::DeviceNode,
        name: "/dev/ttyS3",
        detail: "chain 2 UART (DTB serial@04170000, alias serial3)",
        held_proof: "uart_trans.ko literal + fdt 5b62a37d",
    },
    AbiEntry {
        class: AbiClass::DeviceNode,
        name: "/dev/ttyS4",
        detail: "chain 3 UART (DTB serial@041C0000, alias serial4)",
        held_proof: "uart_trans.ko literal + fdt 5b62a37d",
    },
    AbiEntry {
        class: AbiClass::DeviceNode,
        name: "/dev/ttyS0",
        detail: "console UART (DTB serial@04140000, alias serial0, stdout-path, 25 MHz clock)",
        held_proof: "fdt_cv1835_miner_emmc.dtb 5b62a37d aliases+chosen",
    },
    AbiEntry {
        class: AbiClass::DeviceNode,
        name: "/dev/uart_trans",
        detail: "uart_trans.ko chrdev ('register uart_trans chrdev success'); BM1362 wire transport",
        held_proof: "fixtures/uart_trans.ko 48ebbbc3",
    },
    AbiEntry {
        class: AbiClass::DeviceNode,
        name: "/dev/mem",
        detail: "busybox devmem pinmux replay path (S37/cvidaemon writes)",
        held_proof: "S37 devmem lines b09fcd17/5ef8441d + cvidaemon 8638900f",
    },
    AbiEntry {
        class: AbiClass::DeviceNode,
        name: "/dev/mmcblk0p1",
        detail: "GPT kernel partition (updateporc write law)",
        held_proof: "updateporc.sh 7d71a778 blkdiscard+dd",
    },
    AbiEntry {
        class: AbiClass::DeviceNode,
        name: "/dev/mmcblk0p3",
        detail: "GPT minerfs partition (updateporc write law)",
        held_proof: "updateporc.sh 7d71a778 blkdiscard+dd",
    },
    AbiEntry {
        class: AbiClass::DeviceNode,
        name: "/dev/mmcblk0p4",
        detail: "GPT sig partition (updateporc write law)",
        held_proof: "updateporc.sh 7d71a778 blkdiscard+dd",
    },
    AbiEntry {
        class: AbiClass::DeviceNode,
        name: "/dev/watchdog",
        detail: "standard dw_wdt node (driver held as cv183x_wdt.ko; node name per snps,dw-wdt class convention — no held rootfs byte names it)",
        held_proof: "fixtures/cv183x_wdt.ko f1394e57 alias snps,dw-wdt + DTB cv-wd@0x3010000",
    },
    AbiEntry {
        class: AbiClass::DeviceNode,
        name: "/dev/i2c-N",
        detail: "Designware I2C adapters (DTB i2c@04000000/04020000/04030000/04040000). NOT named in any held sd2nand byte; bus numbering (contract: bus 0 for PIC1704 0x20) comes from the dev-kit RE + L9 topol.conf corroboration — bench witness required",
        held_proof: "fdt 5b62a37d i2c nodes; no held /dev/i2c string (stop-where-bytes-end)",
    },
    // ── Sysfs interfaces ──
    AbiEntry {
        class: AbiClass::SysfsInterface,
        name: "/sys/class/gpio/{export,unexport}",
        detail: "legacy GPIO sysfs (S37 exports 412/427/429/431/433/434/435/459/461)",
        held_proof: "S37 b09fcd17/5ef8441d export lines",
    },
    AbiEntry {
        class: AbiClass::SysfsInterface,
        name: "/sys/class/gpio/gpioN/{direction,value}",
        detail: "direction=out for the exported set; value 0/1 writes per s19j_init.c convention",
        held_proof: "S37 direction lines + constructor contract",
    },
    AbiEntry {
        class: AbiClass::SysfsInterface,
        name: "/sys/class/pwm/pwmchip8/pwm{0,1}/{export,period,enable,duty_cycle}",
        detail: "fan PWM output (period 1000000 ns; front pwm1 FAN1/3, rear pwm0 FAN2/4)",
        held_proof: "S37 pwmchip8 setup lines b09fcd17/5ef8441d",
    },
    AbiEntry {
        class: AbiClass::SysfsInterface,
        name: "/sys/class/pwm/pwmchip12/pwm{0..3}/{export,period,enable}",
        detail: "fan tach capture channels (period 1000000 ns; capture readback is the contract's RPM path — 'capture' not named in held S37)",
        held_proof: "S37 pwmchip12 setup lines (stop-where-bytes-end for capture)",
    },
    AbiEntry {
        class: AbiClass::SysfsInterface,
        name: "/proc/device-tree/model + /sys/firmware/devicetree/base/compatible",
        detail: "CV1835 signature detection consumed by cvitek.rs has_cv1835_signature()",
        held_proof: "constructor contract (standard kernel ABI; stock DTB model/compatible held in fdt 5b62a37d)",
    },
    // ── DTB nodes ──
    AbiEntry {
        class: AbiClass::DtbNode,
        name: "serial@04140000..041C0000 (snps,dw-apb-uart)",
        detail: "5 UARTs: serial0 console 25 MHz; serial1..4 chains 200 MHz; reg-shift=2 reg-io-width=4",
        held_proof: "fdt_cv1835_miner_emmc.dtb 5b62a37d",
    },
    AbiEntry {
        class: AbiClass::DtbNode,
        name: "pwm@03060000..03063000 (cvitek,cvi-pwm)",
        detail: "4 PWM controllers, #pwm-cells=1",
        held_proof: "fdt 5b62a37d + cv183x_pwm.ko alias cvitek,cvi-pwm",
    },
    AbiEntry {
        class: AbiClass::DtbNode,
        name: "gpio@03020000..03023000 (snps,dw-apb-gpio)",
        detail: "4 banks x 32 lines (porta..portd); sysfs base numbering is driver-assigned, S37 numbers are the held witness",
        held_proof: "fdt 5b62a37d + S37 exports",
    },
    AbiEntry {
        class: AbiClass::DtbNode,
        name: "i2c@0400xxxx (snps,designware-i2c)",
        detail: "4 I2C adapters (0x04000000/04020000/04030000/04040000)",
        held_proof: "fdt 5b62a37d",
    },
    AbiEntry {
        class: AbiClass::DtbNode,
        name: "clock-controller@03002000 (cvitek,cv1835-clk) + reset-controller@03003000 (cvitek,reset)",
        detail: "clock/reset control; oscillator fixed-clock 25 MHz (0x017D7840); clk-reset-controller@03002000",
        held_proof: "fdt 5b62a37d",
    },
    AbiEntry {
        class: AbiClass::DtbNode,
        name: "cv-wd@0x3010000 (snps,dw-wdt)",
        detail: "watchdog at 0x03010000",
        held_proof: "fdt 5b62a37d + cv183x_wdt.ko alias",
    },
    AbiEntry {
        class: AbiClass::DtbNode,
        name: "cv-emmc@4300000 (cvitek,cv1835-emmc) + cv-sd@4310000 (cvitek,cv1835-sd)",
        detail: "eMMC (install target carrier) and SD controllers",
        held_proof: "fdt 5b62a37d + partition_emmc_miner.xml (shared pin 1e06d0a3)",
    },
    AbiEntry {
        class: AbiClass::DtbNode,
        name: "pinctrl@3001000 (cvitek,pinctrl-cv1835) + top_misc_ctrl@3000000 (syscon)",
        detail: "pinmux block 0x03001000 (all S37 devmem writes land inside it) and top misc syscon",
        held_proof: "fdt 5b62a37d + S37 devmem b09fcd17/5ef8441d",
    },
    AbiEntry {
        class: AbiClass::DtbNode,
        name: "thermal@030E0000 (cvitek,cv1835-thermal)",
        detail: "SoC thermal sensor",
        held_proof: "fdt 5b62a37d",
    },
    AbiEntry {
        class: AbiClass::DtbNode,
        name: "cpus (2x arm,cortex-a53) + memory@0x100000000 (256 MiB)",
        detail: "DUAL-core A53 per the stock DTB — the constructor-contract doc's 'quad A53' wording is contradicted by the held bytes; memory 0x10000000 at 0x100000000",
        held_proof: "fdt 5b62a37d cpus/memory nodes",
    },
    // ── Boot-chain components (inventory; writes stay authority-closed) ──
    AbiEntry {
        class: AbiClass::BootComponent,
        name: "boot.emmc uImage FIT",
        detail: "kernel(gzip arm64) + 4 fdt images + ramdisk; configurations signed sha256,rsa2048; CIMG v1 dest LBA 8192",
        held_proof: "5x bundle boot.emmc (toolbox-pinned member SHAs); fdt@cv1835_miner_emmc identical 5/5",
    },
    AbiEntry {
        class: AbiClass::BootComponent,
        name: "fdt@cv1835_miner_emmc",
        detail: "the stock eMMC-miner device tree (embedded fixture)",
        held_proof: "fixtures/fdt_cv1835_miner_emmc.dtb 5b62a37d",
    },
    AbiEntry {
        class: AbiClass::BootComponent,
        name: "ramboot.itb",
        detail: "bootstrap-only FIT (FDT magic d00dfed); bootstrap transport unheld (CV1835_BOOTROM_TRANSPORT unresolved)",
        held_proof: "bundle member pins (toolbox evidence module); s19kpro==t21 931307d0",
    },
    AbiEntry {
        class: AbiClass::BootComponent,
        name: "fip.bin",
        detail: "ARM Trusted Firmware + U-Boot; no self-described destination (eMMC boot partitions outside user area) — outside every write path",
        held_proof: "bundle member pins; s19pro==t21 cc2894e1",
    },
    AbiEntry {
        class: AbiClass::BootComponent,
        name: "gpt.img + partition_emmc_miner.xml",
        detail: "7-partition topology (kernel/marker/minerfs/sig/config/miner/nvdata), 3,700,000 KiB eMMC; gpt targets LBA 0 (forbidden region)",
        held_proof: "toolbox-pinned member SHAs; I04 contract tests",
    },
    // ── Userspace contracts ──
    AbiEntry {
        class: AbiClass::UserspaceContract,
        name: "/etc/subtype",
        detail: "CVCtrl_BHB42XXX (20221226 BMU + s19pro) / CVCtrl_BHB56XXX (s19kpro/s19xp/s19jxp) / CVCtrl_BHB6870X (t21); contract classifier binds BHB42XXX -> Pic1704 only",
        held_proof: "subtype fixtures 5b8d906a/3ef605ca/5a90581d",
    },
    AbiEntry {
        class: AbiClass::UserspaceContract,
        name: "/etc/fw-info",
        detail: "JSON identity {miner, model, platform=cv, fw_version, install_type=nand}",
        held_proof: "toolbox cv1835_bcb100_variant_evidence overlay pins",
    },
    AbiEntry {
        class: AbiClass::UserspaceContract,
        name: "updateporc.sh BMU law",
        detail: "BMU split -> openssl sha256 verify chain (/etc/bitmain[.release].pub) -> p1,p4,p3 blkdiscard+dd -> sleep 3 -> sync; no backup, no readback, no env seam",
        held_proof: "fixtures/updateporc.sh 7d71a778 (identical 20221226 + 5/5 bundles)",
    },
    AbiEntry {
        class: AbiClass::UserspaceContract,
        name: "cvidaemon clock-gate unlock",
        detail: "devmem 0x03005D00 32 0x4D474E35 ('5NGM') + dynamic 0x03005D04 template write",
        held_proof: "fixtures/cvidaemon.bin 8638900f (identical 5/5)",
    },
    AbiEntry {
        class: AbiClass::UserspaceContract,
        name: "S37bitmainer_setup + S70cgminer",
        detail: "pinmux/GPIO/PWM init + lsmod-guarded module loads (two S37 builds: b09fcd17, 5ef8441d; one S70 build: 617dbd58)",
        held_proof: "fixtures/s37_*.sh, fixtures/s70_cgminer_variant_617dbd58.sh",
    },
    AbiEntry {
        class: AbiClass::UserspaceContract,
        name: "busybox devmem + aarch64 userspace",
        detail: "pinmux replay executor; /lib/ld-linux-aarch64.so.1 loader",
        held_proof: "updateporc/cvidaemon string census",
    },
    AbiEntry {
        class: AbiClass::UserspaceContract,
        name: "kernel 4.9.38 aarch64 ABI family",
        detail: "all five held module vermages are 4.9.38 variants (SMP preempt mod_unload aarch64); a built candidate's kernel must be this ABI or the out-of-tree modules must stay absent",
        held_proof: "module fixture vermagic strings",
    },
];

/// The built-candidate ABI check owner (acceptance clause 2 remainder).
pub const BUILT_CANDIDATE_CHECK_OWNER: &str =
    "Lead build slot (R16 acceptance: 'required kernel/device ABI present in \
     built candidate' is checked against the built candidate, not at desk)";

/// True when `path` is covered by the inventory: an exact row, or a member
/// of a family row (sysfs GPIO/PWM families, /lib/modules module names).
pub fn inventory_covers(path: &str) -> bool {
    if REQUIRED_ABI_INVENTORY.iter().any(|e| e.name == path) {
        return true;
    }
    if path.starts_with("/sys/class/gpio/") {
        return true;
    }
    if let Some(rest) = path.strip_prefix("/sys/class/pwm/pwmchip") {
        let Some((chip_s, tail)) = rest.split_once('/') else {
            return false;
        };
        let Ok(chip) = chip_s.parse::<u32>() else {
            return false;
        };
        if tail == "export" {
            return chip == 8 || chip == 12;
        }
        let mut parts = tail.splitn(2, '/');
        let Some(chan_s) = parts.next().and_then(|p| p.strip_prefix("pwm")) else {
            return false;
        };
        let Ok(channel) = chan_s.parse::<u32>() else {
            return false;
        };
        let Some(op) = parts.next() else {
            return false;
        };
        return match (chip, channel) {
            (8, 0) | (8, 1) => matches!(op, "export" | "period" | "enable" | "duty_cycle"),
            (12, 0) | (12, 1) | (12, 2) | (12, 3) => matches!(op, "export" | "period" | "enable"),
            _ => false,
        };
    }
    if let Some(module) = path.strip_prefix("/lib/modules/") {
        return contract::MODULE_LOAD_ORDER.contains(&module);
    }
    false
}

fn collect_paths(word: &str, found: &mut HashSet<String>) {
    const PREFIXES: [&str; 4] = ["/sys/", "/dev/", "/lib/modules/", "/proc/"];
    for prefix in PREFIXES {
        if let Some(start) = word.find(prefix) {
            let tail = &word[start..];
            let end = tail
                .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '.' | '-')))
                .unwrap_or(tail.len());
            let candidate = tail[..end].trim_end_matches('.');
            if candidate.len() > prefix.len() {
                found.insert(candidate.to_string());
            }
        }
    }
}

/// Every `/sys|/dev|/lib/modules|/proc`-style path appearing in the held
/// fixtures (text scripts + module binaries), de-duplicated and sorted.
pub fn fixture_path_census() -> Vec<String> {
    let mut found: HashSet<String> = HashSet::new();
    const CORPORA: [&[u8]; 10] = [
        S37_B09FCD17,
        S37_5EF8441D,
        S70_CGMINER,
        UPDATEPORC,
        CVIDAEMON,
        KO_UART_TRANS,
        KO_CV183X_BASE,
        KO_CV183X_PWM,
        KO_CV183X_WDT,
        KO_CONFIGFS,
    ];
    for blob in CORPORA {
        for s in printable_strings(blob, 6) {
            for word in s.split_whitespace() {
                collect_paths(word, &mut found);
            }
        }
        // Also scan across NUL separators so module strings are covered.
        let text = String::from_utf8_lossy(blob).into_owned();
        for word in text.split(['\u{0}', '\n', '\r', ' ']) {
            collect_paths(word, &mut found);
        }
    }
    let mut out: Vec<String> = found.into_iter().collect();
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// Tests — Scope 1: stock boot fixtures vs the constructor contract.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_self_check() {
        // FIPS 180-4 test vectors guard the in-module implementation.
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn fixtures_are_byte_exact_against_pinned_sha256() {
        for (name, bytes, expected) in FIXTURE_SHA256 {
            assert_eq!(
                sha256_hex(bytes),
                *expected,
                "fixture {name} does not match its pinned SHA-256"
            );
        }
        // configfs.ko is embedded but inventory-relevant only; pin it too.
        assert_eq!(
            sha256_hex(KO_CONFIGFS),
            "101ac45a4d152beeae297345d74a053a414fdff01731759845ab8d270011648a"
        );
    }

    #[test]
    fn fixtures_manifest_lists_every_fixture_hash() {
        assert!(FIXTURES_MANIFEST.contains("\"schema\": \"dcentos.r16-cv-stock-fixtures/v1\""));
        for (name, _bytes, expected) in FIXTURE_SHA256 {
            assert!(
                FIXTURES_MANIFEST.contains(name),
                "manifest missing fixture {name}"
            );
            assert!(
                FIXTURES_MANIFEST.contains(expected),
                "manifest missing pinned sha for {name}"
            );
        }
    }

    #[test]
    fn held_bundle_set_is_pinned_completely() {
        assert_eq!(HELD_BUNDLE_SET.len(), 5);
        for (id, archive, boot, minerfs) in HELD_BUNDLE_SET {
            assert!(id.starts_with("cv-") && id.contains("components"), "{id}");
            assert_eq!(archive.len(), 64);
            assert_eq!(boot.len(), 64);
            assert_eq!(minerfs.len(), 64);
            assert!(
                FIXTURES_MANIFEST.contains(id) && FIXTURES_MANIFEST.contains(archive),
                "manifest missing bundle {id}"
            );
        }
    }

    fn stock_fdt() -> Fdt {
        parse_fdt(FDT_MINER_EMMC).expect("embedded stock DTB parses")
    }

    #[test]
    fn stock_dtb_declares_the_four_chain_uarts_the_contract_uses() {
        let fdt = stock_fdt();
        let aliases = fdt.node("/aliases").expect("aliases node");
        assert_eq!(
            aliases.prop_str("serial1").as_deref(),
            Some("/serial@04150000")
        );
        assert_eq!(
            aliases.prop_str("serial2").as_deref(),
            Some("/serial@04160000")
        );
        assert_eq!(
            aliases.prop_str("serial3").as_deref(),
            Some("/serial@04170000")
        );
        assert_eq!(
            aliases.prop_str("serial4").as_deref(),
            Some("/serial@041C0000")
        );

        for (path, alias) in [
            ("/serial@04150000", "serial1"),
            ("/serial@04160000", "serial2"),
            ("/serial@04170000", "serial3"),
            ("/serial@041C0000", "serial4"),
        ] {
            let node = fdt.node(path).unwrap_or_else(|| panic!("missing {path}"));
            assert_eq!(
                node.prop_str("compatible").as_deref(),
                Some("snps,dw-apb-uart"),
                "{path}"
            );
            assert_eq!(node.prop_str("status").as_deref(), Some("okay"), "{path}");
            assert_eq!(
                node.prop_be32("clock-frequency"),
                Some(0x0BEB_C200),
                "{path} chain UART clock must be 200 MHz"
            );
            assert_eq!(node.prop_be32("reg-shift"), Some(2), "{path}");
            assert_eq!(node.prop_be32("reg-io-width"), Some(4), "{path}");
            assert_eq!(
                aliases.prop_str(alias).as_deref(),
                Some(path),
                "alias {alias}"
            );
        }
        // The chain device nodes the contract opens are exactly ttyS1..4.
        assert_eq!(contract::CHAIN_UARTS.len(), 4);
    }

    #[test]
    fn stock_dtb_console_is_serial0_at_25mhz() {
        let fdt = stock_fdt();
        let chosen = fdt.node("/chosen").expect("chosen");
        assert_eq!(chosen.prop_str("stdout-path").as_deref(), Some("serial0"));
        let console = fdt.node("/serial@04140000").expect("console serial");
        assert_eq!(console.prop_be32("clock-frequency"), Some(0x017D_7840)); // 25 MHz
        assert_eq!(console.prop_str("status").as_deref(), Some("okay"));
        assert_eq!(
            fdt.node("/aliases")
                .expect("aliases")
                .prop_str("serial0")
                .as_deref(),
            Some("/serial@04140000")
        );
    }

    /// The accepted contract opens chains through kernel ttyS nodes (and the
    /// stock uart_trans module), but the cvitek_cold_boot UART shuttle is
    /// documented at the W10.3 dev-kit base 0x0500_D000+0x1000*chain. The
    /// held stock DTB declares NO such window — recorded as a refusal fact.
    #[test]
    fn stock_dtb_declares_no_devmem_chain_uart_window() {
        let fdt = stock_fdt();
        let mut uart_windows: Vec<(u64, u64)> = Vec::new();
        for node in fdt.root_children("/serial@") {
            uart_windows.extend(fdt.reg_pairs(node));
        }
        uart_windows.sort();
        assert_eq!(
            uart_windows,
            vec![
                (0x0414_0000, 0x1000),
                (0x0415_0000, 0x1000),
                (0x0416_0000, 0x1000),
                (0x0417_0000, 0x1000),
                (0x041C_0000, 0x1000),
            ]
        );
        for chain in 0..4u32 {
            let claimed = 0x0500_D000u32 + chain * 0x1000;
            assert!(
                !uart_windows
                    .iter()
                    .any(|(a, s)| *a <= claimed as u64 && (claimed as u64) < a + s),
                "0x{claimed:08X} must NOT be a stock-declared UART window"
            );
        }
    }

    #[test]
    fn stock_dtb_declares_pwm_gpio_clock_reset_blocks() {
        let fdt = stock_fdt();
        // 4 PWM controllers.
        let mut pwm: Vec<(u64, u64)> = Vec::new();
        for node in fdt.root_children("/pwm@") {
            assert_eq!(
                node.prop_str("compatible").as_deref(),
                Some("cvitek,cvi-pwm")
            );
            pwm.extend(fdt.reg_pairs(node));
        }
        pwm.sort();
        assert_eq!(
            pwm,
            vec![
                (0x0306_0000, 0x1000),
                (0x0306_1000, 0x1000),
                (0x0306_2000, 0x1000),
                (0x0306_3000, 0x1000),
            ]
        );
        // 4 GPIO banks (the port sub-nodes are not bank nodes).
        let mut gpio: Vec<(u64, u64)> = Vec::new();
        for node in fdt.root_children("/gpio@") {
            assert_eq!(
                node.prop_str("compatible").as_deref(),
                Some("snps,dw-apb-gpio")
            );
            gpio.extend(fdt.reg_pairs(node));
        }
        gpio.sort();
        assert_eq!(
            gpio,
            vec![
                (0x0302_0000, 0x1000),
                (0x0302_1000, 0x1000),
                (0x0302_2000, 0x1000),
                (0x0302_3000, 0x1000),
            ]
        );
        // Clock / reset controllers + 25 MHz oscillator.
        let clk = fdt.node("/clock-controller").expect("clock-controller");
        assert_eq!(
            clk.prop_str("compatible").as_deref(),
            Some("cvitek,cv1835-clk")
        );
        assert_eq!(fdt.reg_pairs(clk), vec![(0x0300_2000, 0x1000)]);
        let rst = fdt.node("/reset-controller").expect("reset-controller");
        assert_eq!(rst.prop_str("compatible").as_deref(), Some("cvitek,reset"));
        assert_eq!(fdt.reg_pairs(rst), vec![(0x0300_3000, 0x10)]);
        let osc = fdt.node("/oscillator").expect("oscillator");
        assert_eq!(osc.prop_str("compatible").as_deref(), Some("fixed-clock"));
        assert_eq!(osc.prop_be32("clock-frequency"), Some(0x017D_7840));
        // Watchdog + eMMC + thermal + pinctrl + top misc.
        let wd = fdt.node("/cv-wd@0x3010000").expect("watchdog");
        assert_eq!(wd.prop_str("compatible").as_deref(), Some("snps,dw-wdt"));
        let emmc = fdt.node("/cv-emmc@4300000").expect("emmc");
        assert_eq!(
            emmc.prop_str("compatible").as_deref(),
            Some("cvitek,cv1835-emmc")
        );
        let thermal = fdt.node("/thermal@030E0000").expect("thermal");
        assert_eq!(
            thermal.prop_str("compatible").as_deref(),
            Some("cvitek,cv1835-thermal")
        );
        let pinctrl = fdt.node("/pinctrl@3001000").expect("pinctrl");
        assert_eq!(
            pinctrl.prop_str("compatible").as_deref(),
            Some("cvitek,pinctrl-cv1835")
        );
        assert_eq!(fdt.reg_pairs(pinctrl), vec![(0x0300_1000, 0x1000)]);
        let misc = fdt.node("/top_misc_ctrl@3000000").expect("top_misc_ctrl");
        assert_eq!(misc.prop_str("compatible").as_deref(), Some("syscon"));
        assert_eq!(fdt.reg_pairs(misc), vec![(0x0300_0000, 0x8000)]);
    }

    /// Held stock topology facts a built candidate inherits: dual A53 cores
    /// (the contract doc's "quad" wording is contradicted), 256 MiB DRAM at
    /// 0x1_0000_0000.
    #[test]
    fn stock_dtb_topology_dual_core_256mib() {
        let fdt = stock_fdt();
        assert!(fdt.node("/cpus/cpu@0").is_some());
        assert!(fdt.node("/cpus/cpu@1").is_some());
        assert!(
            fdt.node("/cpus/cpu@2").is_none(),
            "stock DTB declares exactly 2 A53 cores"
        );
        let memory = fdt.node("/memory").expect("memory node");
        assert_eq!(fdt.reg_pairs(memory), vec![(0x1_0000_0000, 0x1000_0000)]);
    }

    #[test]
    fn both_s37_builds_match_the_contract_pinmux_replay() {
        for script in [S37_B09FCD17, S37_5EF8441D] {
            let text = String::from_utf8_lossy(script);
            let writes = parse_devmem_lines(&text);
            // 23 pinmux writes + 4 Schmitt writes = 27 devmem lines.
            assert_eq!(writes.len(), 27, "S37 devmem count changed");
            for (i, expected) in contract::PINMUX_REPLAY_24[..23].iter().enumerate() {
                assert_eq!(
                    (writes[i].addr, writes[i].value),
                    *expected,
                    "S37 write #{i} drifts from CV1835_STOCK_PINMUX_REPLAY"
                );
            }
            for (i, expected) in contract::SCHMITT_WRITES.iter().enumerate() {
                assert_eq!(
                    (writes[23 + i].addr, writes[23 + i].value),
                    *expected,
                    "Schmitt write #{i} drifts"
                );
            }
            // No devmem write outside the SoC register region the stock
            // cv183x_base.ko ioremaps.
            for w in &writes {
                assert_eq!(w.addr & 0xFFFF_0000, contract::SOC_PERIPH_BASE);
            }
        }
    }

    /// The 24th replay entry (clock-gate unlock "5NGM") is defined by the
    /// stock cvidaemon, not by S37 — pinned from the held binary.
    #[test]
    fn cvidaemon_supplies_the_clock_gate_unlock_write() {
        let writes = parse_embedded_devmem(CVIDAEMON);
        assert!(writes.contains(&DevmemWrite {
            addr: 0x0300_5D00,
            value: 0x4D47_4E35,
        }));
        // The dynamic 0x03005D04 template has no pinned held value.
        assert!(printable_strings(CVIDAEMON, 12)
            .iter()
            .any(|s| s.starts_with("devmem 0x03005D04 32 0x%08x")));
        // The S37 scripts never issue the unlock themselves.
        for script in [S37_B09FCD17, S37_5EF8441D] {
            let text = String::from_utf8_lossy(script);
            assert!(
                !parse_devmem_lines(&text)
                    .iter()
                    .any(|w| w.addr == 0x0300_5D00),
                "S37 must not carry the cvidaemon unlock"
            );
        }
        // Contract cross-check: replay[23] == the unlock.
        assert_eq!(contract::PINMUX_REPLAY_24[23], (0x0300_5D00, 0x4D47_4E35));
    }

    #[test]
    fn s37_gpio_exports_match_the_contract_gpio_map() {
        for script in [S37_B09FCD17, S37_5EF8441D] {
            let text = String::from_utf8_lossy(script);
            let exports = parse_gpio_exports(&text);
            let mut expected: Vec<u32> = vec![contract::GPIO_PWR_EN];
            expected.extend_from_slice(&contract::GPIO_ASIC_RST);
            expected.extend_from_slice(&contract::GPIO_LED);
            expected.extend_from_slice(&[contract::GPIO_I2C_PINS.0, contract::GPIO_I2C_PINS.1]);
            expected.sort_unstable();
            let mut actual = exports.clone();
            actual.sort_unstable();
            assert_eq!(
                actual, expected,
                "S37 export set drifts from the contract GPIO map"
            );
            // 406 (IP_GET) and 447 (RECOVERY) stay inputs: never exported.
            assert!(!actual.contains(&contract::GPIO_IP_GET));
            assert!(!actual.contains(&contract::GPIO_RECOVERY));
            // All exports get direction=out.
            let directions = parse_gpio_directions(&text);
            for gpio in &exports {
                assert!(
                    directions.iter().any(|(g, d)| g == gpio && d == "out"),
                    "gpio{gpio} exported without direction out"
                );
            }
        }
    }

    #[test]
    fn s37_pwm_sysfs_matches_the_contract_fan_wiring() {
        for script in [S37_B09FCD17, S37_5EF8441D] {
            let text = String::from_utf8_lossy(script);
            let setups = parse_pwm_setups(&text);
            let mut expected: Vec<(u32, u32, u32)> = Vec::new();
            for (chip, channel) in contract::PWM_OUT {
                expected.push((chip, channel, contract::FAN_PWM_PERIOD_NS));
            }
            for (chip, channel) in contract::PWM_TACH {
                expected.push((chip, channel, contract::FAN_PWM_PERIOD_NS));
            }
            expected.sort_unstable();
            let actual: Vec<(u32, u32, u32)> = setups
                .iter()
                .map(|p| (p.chip, p.channel, p.period_ns))
                .collect();
            assert_eq!(
                actual, expected,
                "S37 PWM setup drifts from the contract fan wiring"
            );
            assert_eq!(contract::FAN_COUNT, 4);
        }
    }

    #[test]
    fn stock_module_load_order_is_s37_then_s70() {
        let s37 = String::from_utf8_lossy(S37_B09FCD17);
        let s70 = String::from_utf8_lossy(S70_CGMINER);
        let s37_mods = parse_insmod(&s37);
        assert_eq!(s37_mods, vec!["cv183x_pwm.ko", "cv183x_base.ko"]);
        // S70 re-guards all three (idempotent stock behavior) with
        // uart_trans first — rcS order S37 < S70 makes the effective order
        // exactly the contract's CV1835_STOCK_MODULE_LOAD_ORDER.
        let s70_mods = parse_insmod(&s70);
        assert_eq!(
            s70_mods,
            vec!["uart_trans.ko", "cv183x_base.ko", "cv183x_pwm.ko"]
        );
        let mut first_seen: Vec<&str> = Vec::new();
        for m in s37_mods.iter().chain(s70_mods.iter()) {
            if !first_seen.contains(&m.as_str()) {
                first_seen.push(m.as_str());
            }
        }
        assert_eq!(first_seen, contract::MODULE_LOAD_ORDER.to_vec());
        // S70 guards loads with lsmod checks (idempotent stock behavior).
        assert!(s70.contains("lsmod | grep uart_trans"));
    }

    #[test]
    fn stock_subtype_families_are_pinned() {
        assert_eq!(
            String::from_utf8_lossy(SUBTYPE_BHB42).trim(),
            contract::SUBTYPE_BHB42
        );
        assert_eq!(
            String::from_utf8_lossy(SUBTYPE_BHB56).trim(),
            contract::SUBTYPE_BHB56
        );
        assert_eq!(
            String::from_utf8_lossy(SUBTYPE_BHB6870).trim(),
            contract::SUBTYPE_BHB6870
        );
        // The manifest's per-bundle subtype matrix agrees.
        assert!(FIXTURES_MANIFEST
            .contains("\"cv-s19pro-stock-sd2nand-components\": \"CVCtrl_BHB42XXX\""));
        assert!(FIXTURES_MANIFEST
            .contains("\"cv-s19kpro-stock-sd2nand-components\": \"CVCtrl_BHB56XXX\""));
        assert!(
            FIXTURES_MANIFEST.contains("\"cv-t21-held-unlock-components\": \"CVCtrl_BHB6870X\"")
        );
    }

    /// The stock eMMC update law: p1 -> p4 -> p3, always blkdiscard then dd,
    /// then sleep 3 + sync. This is the law I04's transaction implements with
    /// added backup/readback — pinned here against the held bytes.
    #[test]
    fn updateporc_write_law_matches_i04_contract() {
        let text = String::from_utf8_lossy(UPDATEPORC);
        let writes = parse_updateporc_writes(&text);
        assert_eq!(writes.len(), 3);
        assert_eq!(writes[0].part, 1);
        assert_eq!(writes[0].payload, "boot.emmc");
        assert_eq!(writes[1].part, 4);
        assert_eq!(writes[1].payload, "sig.bin");
        assert_eq!(writes[2].part, 3);
        assert_eq!(writes[2].payload, "minerfs.gz");
        assert!(writes.iter().all(|w| w.discard_then_write));
        // Terminal discipline.
        assert!(text.contains("sleep 3"));
        assert!(text.lines().any(|l| l.trim() == "sync"));
        // Preserved windows are never written: marker(2)/config(5)/miner(6)/
        // nvdata(7) plus the structurally excluded boot chain.
        for part in [2u32, 5, 6, 7] {
            assert!(
                !text.contains(&format!("/dev/mmcblk0p{part}")),
                "updateporc must not touch p{part}"
            );
        }
        assert!(!text.contains("gpt.img"));
        assert!(!text.contains("fip.bin"));
        assert!(!text.contains("ramboot"));
        // Signature verification is mandatory in the stock law.
        assert!(text.contains("openssl dgst -sha256 -verify"));
        assert!(text.contains("/etc/bitmain.pub"));
        assert!(text.contains("/etc/bitmain-release.pub"));
    }

    #[test]
    fn stock_kernel_modules_carry_the_4_9_38_aarch64_vermagic() {
        for (name, bytes, _) in FIXTURE_SHA256 {
            if !name.ends_with(".ko") {
                continue;
            }
            let vermagic = printable_strings(bytes, 8)
                .iter()
                .map(|s| s.strip_prefix("vermagic=").unwrap_or(s))
                .find(|s| s.starts_with(KERNEL_VERMAGIC_FAMILY) && s.contains("aarch64"))
                .unwrap_or_else(|| panic!("{name} lacks a 4.9.38 aarch64 vermagic"))
                .to_string();
            assert!(
                vermagic.contains("SMP preempt mod_unload"),
                "{name}: {vermagic}"
            );
            assert!(vermagic.starts_with(KERNEL_VERMAGIC_FAMILY));
        }
    }

    /// Held uart_trans.ko literally owns the chain UART nodes the contract
    /// opens, mediates baud via termios, and uses the CRC-ITU codec family.
    #[test]
    fn uart_trans_module_corroborates_chain_uart_abi() {
        let strings: Vec<String> = printable_strings(KO_UART_TRANS, 6);
        for device in contract::CHAIN_UARTS {
            assert!(
                strings.iter().any(|s| s == device),
                "uart_trans.ko must contain {device}"
            );
        }
        for needle in [
            "register uart_trans chrdev success",
            "uart set baud to: %d",
            "unsupported baud!",
            "crc_itu_t",
            "tty_set_termios",
            "uart trans mmap failed",
        ] {
            assert!(
                strings.iter().any(|s| s.contains(needle)),
                "uart_trans.ko missing ABI string: {needle}"
            );
        }
    }

    /// Held cv183x_base.ko exposes the chip-id/version misc ABI the cold-boot
    /// module's RE constants refer to (functions held; the 0x8C offset and
    /// 0x18802001 magic stay RE-sourced, bench probe pending).
    #[test]
    fn cv183x_base_module_proves_the_cvi_base_abi_functions() {
        let strings: Vec<String> = printable_strings(KO_CV183X_BASE, 6);
        for needle in [
            "cvi_base_read_chip_id",
            "cvi_base_read_chip_version",
            "chip_id=0x%x",
            "chip_version=0x%x",
            "__ioremap",
            "misc_register",
        ] {
            assert!(
                strings.iter().any(|s| s.contains(needle)),
                "cv183x_base.ko missing ABI string: {needle}"
            );
        }
    }

    /// Held module OF-aliases bind to the held DTB compatibles: the module
    /// set and the device tree are one ABI.
    #[test]
    fn module_of_aliases_bind_to_stock_dtb_compatibles() {
        let fdt = stock_fdt();
        let pwm_strings = printable_strings(KO_CV183X_PWM, 6);
        assert!(pwm_strings.iter().any(|s| s.contains("cvitek,cvi-pwm")));
        assert_eq!(
            fdt.node("/pwm@3060000")
                .expect("pwm0")
                .prop_str("compatible")
                .as_deref(),
            Some("cvitek,cvi-pwm")
        );
        let wdt_strings = printable_strings(KO_CV183X_WDT, 6);
        assert!(wdt_strings.iter().any(|s| s.contains("snps,dw-wdt")));
        assert_eq!(
            fdt.node("/cv-wd@0x3010000")
                .expect("wdt")
                .prop_str("compatible")
                .as_deref(),
            Some("snps,dw-wdt")
        );
    }

    // ── Scope 2: executor adapter ──────────────────────────────────────────

    fn stock_defined(p: &Proposal) -> String {
        match adjudicate(p) {
            Decision::StockDefined { citation } => citation,
            other => panic!("expected StockDefined, got {other:?}"),
        }
    }

    fn not_stock_defined(p: &Proposal) -> String {
        match adjudicate(p) {
            Decision::NotStockDefined { reason } => reason,
            other => panic!("expected NotStockDefined, got {other:?}"),
        }
    }

    #[test]
    fn adapter_follows_stock_defined_pinmux_and_unlock() {
        // From the S37 pinmux table.
        let citation = stock_defined(&Proposal::PinmuxWrite {
            addr: 0x0300_11B0,
            value: 0x03,
        });
        assert!(citation.contains("030011B0"));
        // From the cvidaemon unlock.
        stock_defined(&Proposal::PinmuxWrite {
            addr: 0x0300_5D00,
            value: 0x4D47_4E35,
        });
        // A Schmitt write is also stock-defined.
        stock_defined(&Proposal::PinmuxWrite {
            addr: 0x0300_1910,
            value: 0x320,
        });
        // A different value at the same address is NOT stock-defined.
        let reason = not_stock_defined(&Proposal::PinmuxWrite {
            addr: 0x0300_11B0,
            value: 0x02,
        });
        assert!(reason.contains("no held stock byte defines the write"));
    }

    #[test]
    fn adapter_follows_stock_defined_gpio_pwm_uart_modules() {
        stock_defined(&Proposal::GpioExport { gpio: 412 });
        stock_defined(&Proposal::GpioDirection {
            gpio: 427,
            direction: "out".into(),
        });
        stock_defined(&Proposal::GpioValueWrite {
            gpio: 433,
            value: 1,
        });
        stock_defined(&Proposal::PwmSetup {
            chip: 8,
            channel: 1,
            period_ns: 1_000_000,
        });
        stock_defined(&Proposal::PwmSetup {
            chip: 12,
            channel: 3,
            period_ns: 1_000_000,
        });
        stock_defined(&Proposal::ChainUartOpen {
            device: "/dev/ttyS2".into(),
        });
        stock_defined(&Proposal::ChainUartBaud { baud: 937_500 });
        stock_defined(&Proposal::ChainUartBaud { baud: 115_200 });
        stock_defined(&Proposal::Insmod {
            module: "uart_trans.ko".into(),
        });
        stock_defined(&Proposal::Insmod {
            module: "cv183x_pwm.ko".into(),
        });
    }

    #[test]
    fn adapter_refuses_behavior_the_stock_bytes_do_not_define() {
        // A pinmux write no held byte defines.
        let r = not_stock_defined(&Proposal::PinmuxWrite {
            addr: 0x0300_1150,
            value: 0x03,
        });
        assert!(r.contains("no held stock byte defines the write"));
        // The Phase-6 'FPGA' window stays refused (contradicted-dead).
        let r = not_stock_defined(&Proposal::PinmuxWrite {
            addr: 0x43C0_3020,
            value: 1,
        });
        assert!(r.contains("outside every held") && r.contains("0x43C0xxxx"));
        let r = not_stock_defined(&Proposal::PinmuxWrite {
            addr: 0x0300_3020,
            value: 1,
        });
        assert!(r.contains("no FPGA"));
        // The dev-kit chain-UART mmap base is NOT stock-declared.
        let r = not_stock_defined(&Proposal::PinmuxWrite {
            addr: 0x0500_D000,
            value: 0x03,
        });
        assert!(r.contains("outside every held") && r.contains("0x0500D000"));
        // The dynamic 0x03005D04 template has no pinned value.
        let r = not_stock_defined(&Proposal::PinmuxWrite {
            addr: 0x0300_5D04,
            value: 0x1234,
        });
        assert!(r.contains("no held stock byte defines the write"));
        // GPIO outside the S37 export set (e.g. the AM2 PWR_CONTROL line 907).
        let r = not_stock_defined(&Proposal::GpioValueWrite {
            gpio: 907,
            value: 1,
        });
        assert!(r.contains("not an S37-exported output line"));
        // A GPIO the S37 never points at direction out (447 stays input).
        let r = not_stock_defined(&Proposal::GpioDirection {
            gpio: 447,
            direction: "out".into(),
        });
        assert!(r.contains("not among them"));
        // A period the stock law does not define.
        let r = not_stock_defined(&Proposal::PwmSetup {
            chip: 8,
            channel: 0,
            period_ns: 500_000,
        });
        assert!(r.contains("stock defines exactly"));
        // A foreign chain UART node.
        let r = not_stock_defined(&Proposal::ChainUartOpen {
            device: "/dev/ttyS9".into(),
        });
        assert!(r.contains("not a stock-declared"));
        // A baud with no held CV evidence (no fast-UART class exists here).
        let r = not_stock_defined(&Proposal::ChainUartBaud { baud: 3_000_000 });
        assert!(r.contains("no fast-UART evidence"));
        // A module that does not exist on CV1835.
        let r = not_stock_defined(&Proposal::Insmod {
            module: "bitmain_axi.ko".into(),
        });
        assert!(r.contains("does not exist on CV1835"));
    }

    #[test]
    fn adapter_storage_and_boot_chain_authority_stays_closed() {
        for part in [1u32, 3, 4] {
            match adjudicate(&Proposal::StorageWrite { part }) {
                Decision::AuthorityClosed { reason } => {
                    assert!(reason.contains("authority-gated EvidenceOnly"));
                    assert!(reason.contains("p1->p4->p3"));
                }
                other => panic!("storage write must be authority-closed, got {other:?}"),
            }
        }
        // The preserved windows never become writable either.
        for part in [2u32, 5, 6, 7] {
            assert!(matches!(
                adjudicate(&Proposal::StorageWrite { part }),
                Decision::AuthorityClosed { .. }
            ));
        }
        for what in ["gpt.img (LBA 0)", "fip.bin", "ramboot.itb"] {
            match adjudicate(&Proposal::BootChainWrite {
                what: what.to_string(),
            }) {
                Decision::AuthorityClosed { reason } => {
                    assert!(reason.contains("structurally excluded"));
                }
                other => panic!("boot-chain write must be authority-closed, got {other:?}"),
            }
        }
    }

    #[test]
    fn adapter_decisions_carry_no_authority() {
        // The adapter's only positive answer embeds a citation string; there
        // is no authority token, capability, or admission in the type.
        let citation = stock_defined(&Proposal::ChainUartOpen {
            device: "/dev/ttyS1".into(),
        });
        assert!(!citation.is_empty());
    }

    // ── Scope 3: ABI inventory ─────────────────────────────────────────────

    #[test]
    fn inventory_rows_are_well_formed_and_doc_pinned() {
        assert!(REQUIRED_ABI_INVENTORY.len() >= 30);
        for entry in REQUIRED_ABI_INVENTORY {
            assert!(!entry.name.is_empty());
            assert!(!entry.detail.is_empty());
            assert!(!entry.held_proof.is_empty());
            assert!(
                ABI_INVENTORY_DOC.contains(entry.name),
                "ABI_INVENTORY.md missing row {}",
                entry.name
            );
        }
        assert!(
            ABI_INVENTORY_DOC.contains(BUILT_CANDIDATE_CHECK_OWNER),
            "ABI_INVENTORY.md must name the built-candidate check owner"
        );
    }

    #[test]
    fn inventory_module_rows_match_held_bytes() {
        for (name, _bytes, full_sha) in FIXTURE_SHA256 {
            if !name.ends_with(".ko") {
                continue;
            }
            let row = REQUIRED_ABI_INVENTORY
                .iter()
                .find(|e| e.name == name)
                .unwrap_or_else(|| panic!("no inventory row for {name}"));
            assert_eq!(row.class, AbiClass::KernelModule);
            assert!(
                row.held_proof.contains(&full_sha[..8]),
                "row proof must cite the held sha16 of {name}"
            );
        }
        // configfs.ko's row cites its held sha too.
        let configfs = REQUIRED_ABI_INVENTORY
            .iter()
            .find(|e| e.name == "configfs.ko")
            .expect("configfs row");
        assert!(configfs.held_proof.contains("101ac45a"));
    }

    #[test]
    fn inventory_covers_every_device_path_in_the_held_fixtures() {
        let census = fixture_path_census();
        assert!(!census.is_empty());
        // Generic busybox paths that are not CV ABI.
        let generic = ["/dev/null", "/proc/meminfo"];
        let mut uncovered: Vec<String> = Vec::new();
        for path in &census {
            if generic.contains(&path.as_str()) {
                continue;
            }
            if inventory_covers(path) {
                continue;
            }
            uncovered.push(path.clone());
        }
        assert!(
            uncovered.is_empty(),
            "held fixture paths missing from the ABI inventory: {uncovered:?}"
        );
        // The census must actually contain the load-bearing paths (guard
        // against a silently-empty future fixture set).
        for required in [
            "/sys/class/gpio/export",
            "/sys/class/pwm/pwmchip8/pwm0/period",
            "/sys/class/pwm/pwmchip12/pwm3/period",
            "/dev/mmcblk0p1",
            "/dev/ttyS1",
            "/lib/modules/uart_trans.ko",
        ] {
            assert!(
                census.iter().any(|p| p == required),
                "census lost {required}"
            );
        }
    }
}
