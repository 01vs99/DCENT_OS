//! Reproducible Braiins Track-1 `/tmp` deploy policy (host-testable).
//!
//! Userspace is **armhf ELF32**. Kernel aarch64 is not the ABI.
//! Does not SSH. The sibling script `scripts/dcentrald_s19k_tmp_deploy.sh`
//! executes this policy.

use crate::s19k_am3_gpio437::passthrough_must_keep_gpio437_engaged;
use crate::s19k_am3_install::S19K_LIVE_IDENTITY_ALIASES;
use crate::s19k_braiins_chain_discover::admit_braiins_mining_on_ports;
use crate::s19k_braiins_job::{classify_job_wire_prefix, JobWirePrefixKind};
use crate::s19k_uart_trans_job::{BRAIINS_TTYS_BAUD, BRAIINS_TTYS_CANDIDATES};
use std::collections::BTreeMap;

pub const REQUIRED_TARGET_TRIPLE: &str = "armv7-unknown-linux-musleabihf";
pub const REQUIRED_ELF_CLASS: &str = "ELF32";
pub const REQUIRED_MACHINE: &str = "ARM";
/// ELF `e_ident[EI_CLASS]` ELF32.
pub const ELF_CLASS_32: u8 = 1;
/// ELF `e_ident[EI_DATA]` ELFDATA2LSB.
pub const ELF_DATA_LSB: u8 = 1;
/// ELF `e_machine` EM_ARM (not EM_AARCH64=183).
pub const ELF_MACHINE_ARM: u16 = 40;
pub const ELF32_EHDR_LEN: usize = 52;
pub const ELF32_PHDR_LEN: usize = 32;
pub const ELF_TYPE_EXEC: u16 = 2;
pub const ELF_TYPE_DYN: u16 = 3;
pub const PT_LOAD: u32 = 1;
pub const PT_INTERP: u32 = 3;
pub const PF_X: u32 = 1;
/// ARM EABI hard-float (`EF_ARM_ABI_FLOAT_HARD`).
pub const EF_ARM_ABI_FLOAT_HARD: u32 = 0x0000_0400;
/// ARM ELF ABI version occupies the high byte of `e_flags`.
pub const EF_ARM_EABIMASK: u32 = 0xff00_0000;
/// Both the armv7 musl target and every held ARM32 miner executable use EABI5.
pub const EF_ARM_EABI_VER5: u32 = 0x0500_0000;
pub const GLIBC_INTERP_NEEDLE: &str = "ld-linux";
pub const TMP_DEPLOY_PLAN_SCHEMA: &str = "dcentos.s19k-tmp-deploy/v12";
/// Empty SHA-256 (FIPS 180-4). Pins the local hasher.
pub const S19K_SHA256_EMPTY: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// SHA-256("abc").
pub const S19K_SHA256_ABC: &str =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kTmpDeployError {
    WrongTriple,
    /// Path claimed armv7 but the file is not ELF32 ARM (L1).
    WrongElf,
    /// `mining.enabled=true` with `passthrough=false` is native BM1366 (refused).
    NativeMiningOnForbidden,
    SinglePortRegression,
    RailsNotEngaged,
    WrongJobPrefix,
    UartTransOnBraiins,
    /// Config/`/etc/dcentos/board_target` is not a live S19k AML alias.
    WrongBoardTarget,
    /// ELF32 ARM but `EI_DATA` is not LSB.
    BadEndian,
    /// Missing `EF_ARM_ABI_FLOAT_HARD` — Braiins userspace is armhf.
    SoftFloat,
    /// ARM ELF does not declare EABI5 in the high byte of `e_flags`.
    WrongEabi,
    /// `PT_INTERP` names glibc `ld-linux` — not the musl `/tmp` ABI.
    GlibcInterp,
    /// Any `PT_INTERP` — Track-1 `/tmp` admits static musl only.
    DynamicInterp,
    /// Plan missing `sha256=` / not 64 hex / `bytes=` missing.
    HashMissing,
    /// Post-scp `sha256sum` does not match the plan.
    HashMismatch,
    /// Post-scp byte count does not match the plan.
    SizeMismatch,
}

/// L1: Braiins userspace is armhf ELF32. Kernel aarch64 ≠ ABI.
/// Path containing the rustc triple is **not** sufficient.
pub fn admit_s19k_armhf_elf(hdr: &[u8]) -> Result<(), S19kTmpDeployError> {
    if hdr.len() < 20 {
        return Err(S19kTmpDeployError::WrongElf);
    }
    if hdr[0] != 0x7F || hdr[1] != b'E' || hdr[2] != b'L' || hdr[3] != b'F' {
        return Err(S19kTmpDeployError::WrongElf);
    }
    if hdr[4] != ELF_CLASS_32 {
        return Err(S19kTmpDeployError::WrongElf);
    }
    let machine = u16::from_le_bytes([hdr[18], hdr[19]]);
    if machine != ELF_MACHINE_ARM {
        return Err(S19kTmpDeployError::WrongElf);
    }
    Ok(())
}

/// Parsed ELF32 ARM identity for Track-1 `/tmp` (musl-static armhf).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kArmhfElf {
    pub class: u8,
    pub machine: u16,
    pub elf_type: u16,
    pub flags: u32,
    pub eabi_version: u8,
    pub hard_float: bool,
    pub interp: Option<String>,
}

pub fn parse_s19k_armhf_elf(blob: &[u8]) -> Result<S19kArmhfElf, S19kTmpDeployError> {
    admit_s19k_armhf_elf(blob)?;
    if blob.len() < ELF32_EHDR_LEN {
        return Err(S19kTmpDeployError::WrongElf);
    }
    if blob[5] != ELF_DATA_LSB || blob[6] != 1 {
        return Err(S19kTmpDeployError::BadEndian);
    }
    let elf_type = u16::from_le_bytes([blob[16], blob[17]]);
    if elf_type != ELF_TYPE_EXEC && elf_type != ELF_TYPE_DYN {
        return Err(S19kTmpDeployError::WrongElf);
    }
    if u32::from_le_bytes([blob[20], blob[21], blob[22], blob[23]]) != 1 {
        return Err(S19kTmpDeployError::WrongElf);
    }
    let entry = u32::from_le_bytes([blob[24], blob[25], blob[26], blob[27]]);
    if entry == 0 {
        return Err(S19kTmpDeployError::WrongElf);
    }
    let flags = u32::from_le_bytes([blob[36], blob[37], blob[38], blob[39]]);
    let phoff = u32::from_le_bytes([blob[28], blob[29], blob[30], blob[31]]) as usize;
    let ehsize = u16::from_le_bytes([blob[40], blob[41]]) as usize;
    let phentsize = u16::from_le_bytes([blob[42], blob[43]]) as usize;
    let phnum = u16::from_le_bytes([blob[44], blob[45]]) as usize;
    if ehsize != ELF32_EHDR_LEN
        || phentsize != ELF32_PHDR_LEN
        || phnum == 0
        || phnum == u16::MAX as usize
        || phoff < ELF32_EHDR_LEN
    {
        return Err(S19kTmpDeployError::WrongElf);
    }
    let ph_table_len = phentsize
        .checked_mul(phnum)
        .ok_or(S19kTmpDeployError::WrongElf)?;
    let ph_table_end = phoff
        .checked_add(ph_table_len)
        .ok_or(S19kTmpDeployError::WrongElf)?;
    if ph_table_end > blob.len() {
        return Err(S19kTmpDeployError::WrongElf);
    }
    let mut interp = None;
    let mut entry_in_executable_load = false;
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        let p_type = u32::from_le_bytes([blob[off], blob[off + 1], blob[off + 2], blob[off + 3]]);
        let p_offset =
            u32::from_le_bytes([blob[off + 4], blob[off + 5], blob[off + 6], blob[off + 7]])
                as usize;
        let p_vaddr =
            u32::from_le_bytes([blob[off + 8], blob[off + 9], blob[off + 10], blob[off + 11]]);
        let p_filesz = u32::from_le_bytes([
            blob[off + 16],
            blob[off + 17],
            blob[off + 18],
            blob[off + 19],
        ]) as usize;
        let p_memsz = u32::from_le_bytes([
            blob[off + 20],
            blob[off + 21],
            blob[off + 22],
            blob[off + 23],
        ]) as usize;
        let p_flags = u32::from_le_bytes([
            blob[off + 24],
            blob[off + 25],
            blob[off + 26],
            blob[off + 27],
        ]);
        if p_type == PT_LOAD {
            let segment_end = p_offset
                .checked_add(p_filesz)
                .ok_or(S19kTmpDeployError::WrongElf)?;
            if p_filesz > p_memsz || segment_end > blob.len() {
                return Err(S19kTmpDeployError::WrongElf);
            }
            if p_flags & PF_X != 0
                && p_filesz > 0
                && entry
                    .checked_sub(p_vaddr)
                    .is_some_and(|delta| (delta as usize) < p_filesz)
            {
                entry_in_executable_load = true;
            }
        }
        if p_type != PT_INTERP {
            continue;
        }
        let interp_end = p_offset
            .checked_add(p_filesz)
            .ok_or(S19kTmpDeployError::WrongElf)?;
        if p_filesz == 0 || interp_end > blob.len() {
            return Err(S19kTmpDeployError::WrongElf);
        }
        let raw = &blob[p_offset..interp_end];
        let text = std::str::from_utf8(raw)
            .unwrap_or("")
            .trim_end_matches('\0');
        interp = Some(text.to_string());
    }
    if !entry_in_executable_load {
        return Err(S19kTmpDeployError::WrongElf);
    }
    Ok(S19kArmhfElf {
        class: ELF_CLASS_32,
        machine: ELF_MACHINE_ARM,
        elf_type,
        flags,
        eabi_version: ((flags & EF_ARM_EABIMASK) >> 24) as u8,
        hard_float: flags & EF_ARM_ABI_FLOAT_HARD != 0,
        interp,
    })
}

/// Track-1 `/tmp` admits static musl armhf only: hard-float, no `PT_INTERP`.
pub fn admit_s19k_armhf_musl_static(elf: &S19kArmhfElf) -> Result<(), S19kTmpDeployError> {
    if elf.flags & EF_ARM_EABIMASK != EF_ARM_EABI_VER5 {
        return Err(S19kTmpDeployError::WrongEabi);
    }
    if !elf.hard_float {
        return Err(S19kTmpDeployError::SoftFloat);
    }
    match elf.interp.as_deref() {
        None | Some("") => Ok(()),
        Some(interp) if interp.contains(GLIBC_INTERP_NEEDLE) => {
            Err(S19kTmpDeployError::GlibcInterp)
        }
        Some(_) => Err(S19kTmpDeployError::DynamicInterp),
    }
}

/// FIPS 180-4 SHA-256. Used so the plan hash is host-testable without a crate.
pub fn s19k_sha256_hex(data: &[u8]) -> String {
    let h = s19k_sha256(data);
    let mut out = String::with_capacity(64);
    for b in h {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn s19k_sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).saturating_mul(8);
    let mut buf = data.to_vec();
    buf.push(0x80);
    while (buf.len() % 64) != 56 {
        buf.push(0);
    }
    buf.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in buf.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
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
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn admit_s19k_tmp_deploy_sha256_hex(hex: &str) -> Result<(), S19kTmpDeployError> {
    if hex.len() != 64 {
        return Err(S19kTmpDeployError::HashMissing);
    }
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(S19kTmpDeployError::HashMissing);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kTmpDeployContentHash {
    pub sha256: String,
    pub bytes: u64,
}

fn parse_s19k_tmp_deploy_plan_fields<'a>(
    plan: &'a str,
) -> Result<BTreeMap<&'a str, &'a str>, S19kTmpDeployError> {
    let mut fields = BTreeMap::new();
    for line in plan.lines() {
        let (key, value) = line.split_once('=').ok_or(S19kTmpDeployError::WrongElf)?;
        if key.is_empty() || value.is_empty() || fields.insert(key, value).is_some() {
            return Err(S19kTmpDeployError::WrongElf);
        }
    }
    Ok(fields)
}

pub fn parse_s19k_tmp_deploy_content_hash(
    plan: &str,
) -> Result<S19kTmpDeployContentHash, S19kTmpDeployError> {
    let fields = parse_s19k_tmp_deploy_plan_fields(plan)?;
    let sha256 = fields
        .get("sha256")
        .ok_or(S19kTmpDeployError::HashMissing)?
        .to_ascii_lowercase();
    admit_s19k_tmp_deploy_sha256_hex(&sha256)?;
    let bytes = fields
        .get("bytes")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(S19kTmpDeployError::HashMissing)?;
    if bytes == 0 {
        return Err(S19kTmpDeployError::HashMissing);
    }
    Ok(S19kTmpDeployContentHash { sha256, bytes })
}

/// Post-scp: remote `sha256sum` + size must match the plan, then re-admit ELF.
pub fn admit_s19k_tmp_deploy_post_scp(
    plan: &str,
    remote_sha256: &str,
    remote_bytes: u64,
    remote_elf: &[u8],
) -> Result<(), S19kTmpDeployError> {
    admit_s19k_tmp_deploy_launch_plan(plan)?;
    let expected = parse_s19k_tmp_deploy_content_hash(plan)?;
    let got = remote_sha256.trim().to_ascii_lowercase();
    admit_s19k_tmp_deploy_sha256_hex(&got)?;
    if got != expected.sha256 {
        return Err(S19kTmpDeployError::HashMismatch);
    }
    if remote_bytes != expected.bytes || remote_elf.len() as u64 != expected.bytes {
        return Err(S19kTmpDeployError::SizeMismatch);
    }
    let elf = parse_s19k_armhf_elf(remote_elf)?;
    admit_s19k_armhf_musl_static(&elf)
}

/// Machine-readable launch plan. Does not SSH or flash.
pub fn format_s19k_tmp_deploy_launch_plan(
    remote_dir: &str,
    board_target: &str,
    mining_on: bool,
    handoff_no_work: bool,
    bounded_work_proof: bool,
    endurance_work_proof: bool,
    dry_run: bool,
    hard_float: bool,
    interp: Option<&str>,
    sha256_hex: &str,
    bytes: u64,
    config_sha256_hex: &str,
    config_bytes: u64,
    runner_sha256_hex: &str,
    runner_bytes: u64,
    custody_observer_sha256_hex: &str,
    custody_observer_bytes: u64,
    stock_restart_helper_sha256_hex: &str,
    stock_restart_helper_bytes: u64,
    endurance_collector_sha256_hex: &str,
    endurance_collector_bytes: u64,
    endurance_verifier_sha256_hex: &str,
    endurance_verifier_bytes: u64,
    endurance_baseline: Option<(&str, u64)>,
    miner_target_sha256_hex: &str,
    expected_host_key_sha256: Option<&str>,
) -> String {
    let (mode, work_authority) = if !mining_on {
        ("stage-only", "not-applicable")
    } else if usize::from(handoff_no_work)
        + usize::from(bounded_work_proof)
        + usize::from(endurance_work_proof)
        > 1
    {
        ("invalid-mutually-exclusive", "invalid")
    } else if handoff_no_work {
        ("handoff-no-work", "disabled")
    } else if bounded_work_proof {
        ("bounded-work-proof", "bounded-proof")
    } else if endurance_work_proof {
        ("endurance-work-proof", "endurance-proof")
    } else {
        ("mining-on-passthrough", "enabled")
    };
    let interp_field = interp.unwrap_or("none");
    let (ssh_host_key_admission, ssh_host_key_sha256) = match expected_host_key_sha256 {
        Some(fingerprint) => ("exact-operator-pin", fingerprint),
        None => ("not-applicable-no-contact", "not-supplied"),
    };
    let (endurance_baseline_sha256, endurance_baseline_bytes) = endurance_baseline
        .map(|(sha256, bytes)| (sha256, bytes.to_string()))
        .unwrap_or(("not-applicable", "0".to_string()));
    format!(
        "schema={TMP_DEPLOY_PLAN_SCHEMA}\n\
triple={REQUIRED_TARGET_TRIPLE}\n\
elf_class=32\n\
e_machine=40\n\
arm_eabi=5\n\
hard_float={hard_float}\n\
pt_interp={interp_field}\n\
musl_static=true\n\
sha256={sha256_hex}\n\
bytes={bytes}\n\
operator_artifact_pin=required-and-matched\n\
expected_artifact_sha256={sha256_hex}\n\
expected_artifact_bytes={bytes}\n\
post_scp=sha256sum\n\
re_admit=elf32_arm_musl_static\n\
remote_dir={remote_dir}\n\
remote_bin={remote_dir}/dcentrald\n\
config_sha256={config_sha256_hex}\n\
config_bytes={config_bytes}\n\
runner_sha256={runner_sha256_hex}\n\
runner_bytes={runner_bytes}\n\
custody_observer_sha256={custody_observer_sha256_hex}\n\
custody_observer_bytes={custody_observer_bytes}\n\
stock_restart_helper_sha256={stock_restart_helper_sha256_hex}\n\
stock_restart_helper_bytes={stock_restart_helper_bytes}\n\
endurance_collector_sha256={endurance_collector_sha256_hex}\n\
endurance_collector_bytes={endurance_collector_bytes}\n\
endurance_verifier_sha256={endurance_verifier_sha256_hex}\n\
endurance_verifier_bytes={endurance_verifier_bytes}\n\
endurance_baseline_sha256={endurance_baseline_sha256}\n\
endurance_baseline_bytes={endurance_baseline_bytes}\n\
identity_probe={remote_dir}/run_trial identity {remote_dir} {board_target} {mode} {sha256_hex} {bytes} {config_sha256_hex} {config_bytes} {runner_sha256_hex} {runner_bytes} {custody_observer_sha256_hex} {custody_observer_bytes} {stock_restart_helper_sha256_hex} {stock_restart_helper_bytes}\n\
launch={remote_dir}/run_trial run {remote_dir} {board_target} {mode} {sha256_hex} {bytes} {config_sha256_hex} {config_bytes} {runner_sha256_hex} {runner_bytes} {custody_observer_sha256_hex} {custody_observer_bytes} {stock_restart_helper_sha256_hex} {stock_restart_helper_bytes}\n\
runtime_recovery={remote_dir}/run_trial restore {remote_dir} {board_target} recovery {sha256_hex} {bytes} {config_sha256_hex} {config_bytes} {runner_sha256_hex} {runner_bytes} {custody_observer_sha256_hex} {custody_observer_bytes} {stock_restart_helper_sha256_hex} {stock_restart_helper_bytes}\n\
runtime_reverify=bin+config+runner+custody-observer+stock-restart-helper-sha256-and-bytes\n\
persistent_mutation=false\n\
ephemeral_runtime_env=DCENTOS_EPHEMERAL_RUNTIME=1\n\
serial_mode_flag=--serial-mining\n\
explicit_loud_authority={mining_on}\n\
loud_flag=--allow-loud\n\
no_work_flag=--s19k-track1-no-work\n\
bounded_work_proof_flag=--s19k-track1-bounded-work-proof\n\
endurance_work_proof_flag=--s19k-track1-endurance-work-proof\n\
work_proof_timeout_s=600\n\
work_evidence=content-bound-terminal-transcript+all-crc-admitted-rx+all-required-path-tx+exact-pool-result-origin\n\
work_proof_success=accepted-share-per-required-logical-uart+checked-terminal-safeoff\n\
work_authority={work_authority}\n\
endurance_minimum_s=86400\n\
endurance_maximum_s=93600\n\
endurance_interval_s=60\n\
endurance_acceptance_windows=4x6h-per-required-uart\n\
endurance_collector_ack_timeout_s=300\n\
endurance_max_unacked_segments=6\n\
endurance_max_unacked_bytes=524288\n\
endurance_evidence=hash-chained-minute-aggregates+accepted-share-lineage+off-target-manifest-acks\n\
endurance_terminal=manifest-head+terminal-handoff+checked-safeoff+host-semantic-verification\n\
chmod=755\n\
required_ports=population-selected:/dev/ttyS3,/dev/ttyS2,/dev/ttyS1\n\
baud=3000000\n\
keep_rails={KEEP_RAILS_BOSMINER_STOP}\n\
handoff_identity=supervisor+child-pid+start+ppid+pgrp+session+comm+exe+argv-sha256\n\
handoff_watchdog=armed-before-signal\n\
handoff_signal=j3-ptrace-all-thread-freeze+supervisor-first-sigkill-terminal+child-second-sigkill-terminal+event-drain\n\
live_identity_schema=dcentos.s19k-braiins-live-identity/v2\n\
live_identity_profile_rule=mutually-exclusive-complete-tuple\n\
live_identity_profile_live88_two_bhb56903_slots_2_3=2xBHB56903@2,3+addr1-undetected-placeholder+eeprom-0x50-absent-0x51-0x52-0511\n\
live_identity_profile_held78_three_bhb56902_slots_1_2_3=3xBHB56902@1,2,3+eeprom-0x50-0x51-0x52-0511\n\
live_identity_profile_bhb56902_only=one-to-three-BHB56902+exact-address/eeprom-join\n\
live_identity_profile_bhb56903_only=one-to-three-BHB56903+exact-address/eeprom-join\n\
live_identity_profile_mixed_bhb56902_bhb56903=one-to-three-mixed-boards+exact-address/eeprom-join\n\
live_identity_profile_all_three_uarts_populated=addresses-1,2,3+ttyS3,ttyS2,ttyS1\n\
live_identity_evidence=aarch64+a113d-cpu+bos-platform-mode+exact-mtd+typed-profile\n\
live_identity_recheck=pre-handoff+pre-recovery-safeoff\n\
runtime_receipt_schema=dcentos.s19k-tmp-runtime/v5\n\
runtime_lock=board-global-atomic-mkdir+v6-artifact-bound-owner+typed-pending-retention\n\
receipt_clear=checked-safeoff-to-exact-stock-restart-helper-only\n\
recovery_safeoff_receipt=dcentos.s19k-track1-safeoff/v1\n\
runtime_log_ring=/tmp/dcent/log\n\
forbidden_stop={FORBIDDEN_RAILS_DROP_STOP}\n\
mode={mode}\n\
native_bm1366=refused\n\
clear_for_flash=false\n\
execute=CLEAR_FOR_FLASH\n\
dry_run={dry_run}\n\
miner_target_sha256={miner_target_sha256_hex}\n\
miner_target_record=sha256-only\n\
ssh_host_key_admission={ssh_host_key_admission}\n\
ssh_host_key_sha256={ssh_host_key_sha256}\n\
ssh_global_known_hosts=disabled-on-contact\n"
    )
}

pub fn admit_s19k_tmp_deploy_launch_plan(plan: &str) -> Result<(), S19kTmpDeployError> {
    const REQUIRED_FIELDS: &[&str] = &[
        "schema",
        "triple",
        "elf_class",
        "e_machine",
        "arm_eabi",
        "hard_float",
        "pt_interp",
        "musl_static",
        "sha256",
        "bytes",
        "operator_artifact_pin",
        "expected_artifact_sha256",
        "expected_artifact_bytes",
        "post_scp",
        "re_admit",
        "remote_dir",
        "remote_bin",
        "config_sha256",
        "config_bytes",
        "runner_sha256",
        "runner_bytes",
        "custody_observer_sha256",
        "custody_observer_bytes",
        "stock_restart_helper_sha256",
        "stock_restart_helper_bytes",
        "endurance_collector_sha256",
        "endurance_collector_bytes",
        "endurance_verifier_sha256",
        "endurance_verifier_bytes",
        "endurance_baseline_sha256",
        "endurance_baseline_bytes",
        "identity_probe",
        "launch",
        "runtime_recovery",
        "runtime_reverify",
        "persistent_mutation",
        "ephemeral_runtime_env",
        "serial_mode_flag",
        "explicit_loud_authority",
        "loud_flag",
        "no_work_flag",
        "bounded_work_proof_flag",
        "endurance_work_proof_flag",
        "work_proof_timeout_s",
        "work_evidence",
        "work_proof_success",
        "work_authority",
        "endurance_minimum_s",
        "endurance_maximum_s",
        "endurance_interval_s",
        "endurance_acceptance_windows",
        "endurance_collector_ack_timeout_s",
        "endurance_max_unacked_segments",
        "endurance_max_unacked_bytes",
        "endurance_evidence",
        "endurance_terminal",
        "chmod",
        "required_ports",
        "baud",
        "keep_rails",
        "handoff_identity",
        "handoff_watchdog",
        "handoff_signal",
        "live_identity_schema",
        "live_identity_profile_rule",
        "live_identity_profile_live88_two_bhb56903_slots_2_3",
        "live_identity_profile_held78_three_bhb56902_slots_1_2_3",
        "live_identity_profile_bhb56902_only",
        "live_identity_profile_bhb56903_only",
        "live_identity_profile_mixed_bhb56902_bhb56903",
        "live_identity_profile_all_three_uarts_populated",
        "live_identity_evidence",
        "live_identity_recheck",
        "runtime_receipt_schema",
        "runtime_lock",
        "receipt_clear",
        "recovery_safeoff_receipt",
        "runtime_log_ring",
        "forbidden_stop",
        "mode",
        "native_bm1366",
        "clear_for_flash",
        "execute",
        "dry_run",
        "miner_target_sha256",
        "miner_target_record",
        "ssh_host_key_admission",
        "ssh_host_key_sha256",
        "ssh_global_known_hosts",
    ];
    let fields = parse_s19k_tmp_deploy_plan_fields(plan)?;
    if fields.len() != REQUIRED_FIELDS.len()
        || REQUIRED_FIELDS.iter().any(|key| !fields.contains_key(key))
    {
        return Err(S19kTmpDeployError::WrongElf);
    }
    let require = |key: &str, value: &str| -> Result<(), S19kTmpDeployError> {
        (fields.get(key).copied() == Some(value))
            .then_some(())
            .ok_or(S19kTmpDeployError::WrongElf)
    };
    require("schema", TMP_DEPLOY_PLAN_SCHEMA)?;
    require("triple", REQUIRED_TARGET_TRIPLE)?;
    require("elf_class", "32")?;
    require("e_machine", "40")?;
    require("arm_eabi", "5")?;
    require("hard_float", "true")?;
    require("pt_interp", "none")?;
    require("musl_static", "true")?;
    require("operator_artifact_pin", "required-and-matched")?;
    if fields.get("expected_artifact_sha256") != fields.get("sha256")
        || fields.get("expected_artifact_bytes") != fields.get("bytes")
    {
        return Err(S19kTmpDeployError::HashMismatch);
    }
    require("post_scp", "sha256sum")?;
    require("re_admit", "elf32_arm_musl_static")?;
    require(
        "runtime_reverify",
        "bin+config+runner+custody-observer+stock-restart-helper-sha256-and-bytes",
    )?;
    require("persistent_mutation", "false")?;
    require("ephemeral_runtime_env", "DCENTOS_EPHEMERAL_RUNTIME=1")?;
    require("serial_mode_flag", "--serial-mining")?;
    require("loud_flag", "--allow-loud")?;
    require("no_work_flag", "--s19k-track1-no-work")?;
    require(
        "bounded_work_proof_flag",
        "--s19k-track1-bounded-work-proof",
    )?;
    require(
        "endurance_work_proof_flag",
        "--s19k-track1-endurance-work-proof",
    )?;
    require("work_proof_timeout_s", "600")?;
    require(
        "work_evidence",
        "content-bound-terminal-transcript+all-crc-admitted-rx+all-required-path-tx+exact-pool-result-origin",
    )?;
    require(
        "work_proof_success",
        "accepted-share-per-required-logical-uart+checked-terminal-safeoff",
    )?;
    require("endurance_minimum_s", "86400")?;
    require("endurance_maximum_s", "93600")?;
    require("endurance_interval_s", "60")?;
    require("endurance_acceptance_windows", "4x6h-per-required-uart")?;
    require("endurance_collector_ack_timeout_s", "300")?;
    require("endurance_max_unacked_segments", "6")?;
    require("endurance_max_unacked_bytes", "524288")?;
    require(
        "endurance_evidence",
        "hash-chained-minute-aggregates+accepted-share-lineage+off-target-manifest-acks",
    )?;
    require(
        "endurance_terminal",
        "manifest-head+terminal-handoff+checked-safeoff+host-semantic-verification",
    )?;
    require("chmod", "755")?;
    require(
        "required_ports",
        "population-selected:/dev/ttyS3,/dev/ttyS2,/dev/ttyS1",
    )?;
    require("baud", "3000000")?;
    require("keep_rails", KEEP_RAILS_BOSMINER_STOP)?;
    require(
        "handoff_identity",
        "supervisor+child-pid+start+ppid+pgrp+session+comm+exe+argv-sha256",
    )?;
    require("handoff_watchdog", "armed-before-signal")?;
    require(
        "handoff_signal",
        "j3-ptrace-all-thread-freeze+supervisor-first-sigkill-terminal+child-second-sigkill-terminal+event-drain",
    )?;
    require(
        "live_identity_schema",
        "dcentos.s19k-braiins-live-identity/v2",
    )?;
    require(
        "live_identity_profile_rule",
        "mutually-exclusive-complete-tuple",
    )?;
    require(
        "live_identity_profile_live88_two_bhb56903_slots_2_3",
        "2xBHB56903@2,3+addr1-undetected-placeholder+eeprom-0x50-absent-0x51-0x52-0511",
    )?;
    require(
        "live_identity_profile_held78_three_bhb56902_slots_1_2_3",
        "3xBHB56902@1,2,3+eeprom-0x50-0x51-0x52-0511",
    )?;
    require(
        "live_identity_profile_bhb56902_only",
        "one-to-three-BHB56902+exact-address/eeprom-join",
    )?;
    require(
        "live_identity_profile_bhb56903_only",
        "one-to-three-BHB56903+exact-address/eeprom-join",
    )?;
    require(
        "live_identity_profile_mixed_bhb56902_bhb56903",
        "one-to-three-mixed-boards+exact-address/eeprom-join",
    )?;
    require(
        "live_identity_profile_all_three_uarts_populated",
        "addresses-1,2,3+ttyS3,ttyS2,ttyS1",
    )?;
    require(
        "live_identity_evidence",
        "aarch64+a113d-cpu+bos-platform-mode+exact-mtd+typed-profile",
    )?;
    require("live_identity_recheck", "pre-handoff+pre-recovery-safeoff")?;
    require("runtime_receipt_schema", "dcentos.s19k-tmp-runtime/v5")?;
    require(
        "runtime_lock",
        "board-global-atomic-mkdir+v6-artifact-bound-owner+typed-pending-retention",
    )?;
    require(
        "receipt_clear",
        "checked-safeoff-to-exact-stock-restart-helper-only",
    )?;
    require("recovery_safeoff_receipt", "dcentos.s19k-track1-safeoff/v1")?;
    require("runtime_log_ring", "/tmp/dcent/log")?;
    require("forbidden_stop", FORBIDDEN_RAILS_DROP_STOP)?;
    require("native_bm1366", "refused")?;
    require("clear_for_flash", "false")?;
    require("execute", "CLEAR_FOR_FLASH")?;
    require("miner_target_record", "sha256-only")?;

    parse_s19k_tmp_deploy_content_hash(plan)?;
    for key in [
        "config_sha256",
        "runner_sha256",
        "custody_observer_sha256",
        "stock_restart_helper_sha256",
        "endurance_collector_sha256",
        "endurance_verifier_sha256",
        "miner_target_sha256",
    ] {
        admit_s19k_tmp_deploy_sha256_hex(fields[key])?;
    }
    for key in [
        "config_bytes",
        "runner_bytes",
        "custody_observer_bytes",
        "stock_restart_helper_bytes",
        "endurance_collector_bytes",
        "endurance_verifier_bytes",
    ] {
        if fields[key]
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .is_none()
        {
            return Err(S19kTmpDeployError::HashMissing);
        }
    }
    let remote_dir = fields["remote_dir"];
    let remote_suffix = remote_dir.strip_prefix("/tmp/dcentrald_bench_t1_");
    if remote_suffix.is_none_or(|suffix| {
        suffix.is_empty()
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    }) {
        return Err(S19kTmpDeployError::WrongElf);
    }
    require("remote_bin", &format!("{remote_dir}/dcentrald"))?;
    let mode = fields["mode"];
    let loud = fields["explicit_loud_authority"];
    let work_authority = fields["work_authority"];
    match mode {
        "stage-only" if loud == "false" && work_authority == "not-applicable" => {}
        "handoff-no-work" if loud == "true" && work_authority == "disabled" => {}
        "bounded-work-proof" if loud == "true" && work_authority == "bounded-proof" => {}
        "endurance-work-proof" if loud == "true" && work_authority == "endurance-proof" => {
            admit_s19k_tmp_deploy_sha256_hex(fields["endurance_baseline_sha256"])?;
            if fields["endurance_baseline_bytes"]
                .parse::<u64>()
                .ok()
                .filter(|value| *value > 0)
                .is_none()
            {
                return Err(S19kTmpDeployError::HashMissing);
            }
        }
        "mining-on-passthrough" if loud == "true" && work_authority == "enabled" => {}
        _ => return Err(S19kTmpDeployError::NativeMiningOnForbidden),
    }
    if mode != "endurance-work-proof"
        && (fields["endurance_baseline_sha256"] != "not-applicable"
            || fields["endurance_baseline_bytes"] != "0")
    {
        return Err(S19kTmpDeployError::WrongElf);
    }
    if !matches!(fields["dry_run"], "true" | "false") {
        return Err(S19kTmpDeployError::WrongElf);
    }
    require("ssh_global_known_hosts", "disabled-on-contact")?;
    match fields["ssh_host_key_admission"] {
        "not-applicable-no-contact"
            if fields["dry_run"] == "true" && fields["ssh_host_key_sha256"] == "not-supplied" => {}
        "exact-operator-pin" => {
            let Some(digest) = fields["ssh_host_key_sha256"].strip_prefix("SHA256:") else {
                return Err(S19kTmpDeployError::WrongElf);
            };
            if digest.len() != 43
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
            {
                return Err(S19kTmpDeployError::WrongElf);
            }
        }
        _ => return Err(S19kTmpDeployError::WrongElf),
    }
    let expected_launch = S19K_LIVE_IDENTITY_ALIASES.iter().any(|board_target| {
        fields["identity_probe"]
            == format!(
                "{remote_dir}/run_trial identity {remote_dir} {board_target} {mode} {} {} {} {} {} {} {} {} {} {}",
                fields["sha256"],
                fields["bytes"],
                fields["config_sha256"],
                fields["config_bytes"],
                fields["runner_sha256"],
                fields["runner_bytes"],
                fields["custody_observer_sha256"],
                fields["custody_observer_bytes"],
                fields["stock_restart_helper_sha256"],
                fields["stock_restart_helper_bytes"],
            )
            && fields["launch"]
            == format!(
                "{remote_dir}/run_trial run {remote_dir} {board_target} {mode} {} {} {} {} {} {} {} {} {} {}",
                fields["sha256"],
                fields["bytes"],
                fields["config_sha256"],
                fields["config_bytes"],
                fields["runner_sha256"],
                fields["runner_bytes"],
                fields["custody_observer_sha256"],
                fields["custody_observer_bytes"],
                fields["stock_restart_helper_sha256"],
                fields["stock_restart_helper_bytes"],
            )
            && fields["runtime_recovery"]
                == format!(
                    "{remote_dir}/run_trial restore {remote_dir} {board_target} recovery {} {} {} {} {} {} {} {} {} {}",
                    fields["sha256"],
                    fields["bytes"],
                    fields["config_sha256"],
                    fields["config_bytes"],
                    fields["runner_sha256"],
                    fields["runner_bytes"],
                    fields["custody_observer_sha256"],
                    fields["custody_observer_bytes"],
                    fields["stock_restart_helper_sha256"],
                    fields["stock_restart_helper_bytes"],
                )
    });
    if !expected_launch {
        return Err(S19kTmpDeployError::WrongElf);
    }
    Ok(())
}

/// Deploy helper must admit musl-static armhf and write a launch plan.
pub fn admit_s19k_tmp_deploy_script_musl_static(script: &str) -> Result<(), &'static str> {
    if !script.contains("--dry-run") {
        return Err("deploy must accept --dry-run");
    }
    if !script.contains("--handoff-no-work") {
        return Err("deploy must accept the exact supervised no-work mode");
    }
    if !script.contains("--bounded-work-proof") {
        return Err("deploy must accept the exact bounded work-proof mode");
    }
    if !script.contains("--endurance-work-proof") || !script.contains("--endurance-baseline") {
        return Err("deploy must accept the exact receipt-bound endurance mode and baseline");
    }
    if !script.contains("TMP_DEPLOY_PLAN") {
        return Err("deploy must write TMP_DEPLOY_PLAN");
    }
    if !script.contains("schema=dcentos.s19k-tmp-deploy/v12") {
        return Err("deploy must emit the v12 operator-pinned endurance/work-proof/no-work plan");
    }
    if !script.contains("hard_float")
        || !script.contains("EF_ARM_ABI_FLOAT_HARD")
        || !script.contains("flags & 0xff000000 != 0x05000000")
        || !script.contains("flags & 0x400 == 0")
    {
        return Err("deploy must check ARM EABI5 and EF_ARM_ABI_FLOAT_HARD");
    }
    if !script.contains("ld-linux") {
        return Err("deploy must refuse glibc ld-linux interp");
    }
    if !script.contains("pt_interp=none") {
        return Err("deploy plan must name pt_interp=none");
    }
    if !script.contains("musl_static=true") {
        return Err("deploy plan must name musl_static=true");
    }
    if !script.contains("sha256=") {
        return Err("deploy plan must name sha256=");
    }
    if !script.contains("bytes=") {
        return Err("deploy plan must name bytes=");
    }
    if !script.contains("--expected-artifact-sha256)")
        || !script.contains("--expected-artifact-bytes)")
        || !script.contains("operator_artifact_pin=$ARTIFACT_OPERATOR_PIN")
        || !script.contains("expected_artifact_sha256=$EXPECTED_ARTIFACT_SHA256")
        || !script.contains("expected_artifact_bytes=$EXPECTED_ARTIFACT_BYTES")
        || !script.contains("selected artifact does not match exact sealed operator authority")
    {
        return Err("deploy must bind the operator-selected sealed artifact before contact");
    }
    if !script.contains("post_scp=sha256sum") {
        return Err("deploy plan must name post_scp=sha256sum");
    }
    if !script.contains("admit_s19k_tmp_deploy_post_scp") {
        return Err("deploy must name the post-scp re-admit");
    }
    if !script.contains("entry_in_executable_load")
        || !script.contains("phnum in (0, 0xffff)")
        || !script.contains("p_filesz > p_memsz")
    {
        return Err("deploy must require a runnable file-backed executable PT_LOAD");
    }
    if !script.contains("dcentrald_s19k_tmp_remote_run.sh")
        || !script.contains("dcentrald_s19k_braiins_supervisor_custody.sh")
        || !script.contains("dcentrald_s19k_stock_restart_from_safeoff.sh")
        || !script.contains("custody_observer_sha256=$CUSTODY_SHA")
        || !script.contains("custody_observer_bytes=$CUSTODY_BYTES")
        || !script.contains("stock_restart_helper_sha256=$STOCK_RESTART_HELPER_SHA")
        || !script.contains("stock_restart_helper_bytes=$STOCK_RESTART_HELPER_BYTES")
        || !script.contains("serial_mode_flag=--serial-mining")
        || !script.contains("explicit_loud_authority=$LOUD_AUTHORITY")
        || !script.contains("loud_flag=--allow-loud")
        || !script.contains("no_work_flag=--s19k-track1-no-work")
        || !script.contains("bounded_work_proof_flag=--s19k-track1-bounded-work-proof")
        || !script.contains("endurance_work_proof_flag=--s19k-track1-endurance-work-proof")
        || !script.contains("work_proof_timeout_s=600")
        || !script.contains("work_evidence=content-bound-terminal-transcript+all-crc-admitted-rx+all-required-path-tx+exact-pool-result-origin")
        || !script.contains("work_proof_success=accepted-share-per-required-logical-uart+checked-terminal-safeoff")
        || !script.contains("work_authority=$WORK_AUTHORITY")
        || !script.contains("endurance_minimum_s=86400")
        || !script.contains("endurance_maximum_s=93600")
        || !script.contains("endurance_interval_s=60")
        || !script.contains("endurance_acceptance_windows=4x6h-per-required-uart")
        || !script.contains("endurance_collector_ack_timeout_s=300")
        || !script.contains("endurance_max_unacked_segments=6")
        || !script.contains("endurance_max_unacked_bytes=524288")
        || !script.contains("endurance_collector_sha256=$COLLECTOR_SHA")
        || !script.contains("endurance_verifier_sha256=$ENDURANCE_VERIFIER_SHA")
        || !script.contains("endurance_baseline_sha256=$ENDURANCE_BASELINE_SHA")
    {
        return Err("deploy plan must bind the supervised Track-1 runner and authority flags");
    }
    if !script.contains("runtime_reverify=bin+config+runner+custody-observer+stock-restart-helper-sha256-and-bytes")
        || !script.contains("persistent_mutation=false")
        || !script.contains("ephemeral_runtime_env=DCENTOS_EPHEMERAL_RUNTIME=1")
        || !script.contains("RECOVERY_COMMAND=\"$REMOTE_HELPER restore")
        || !script.contains("runtime_recovery=$RECOVERY_COMMAND")
        || !script.contains("arm_eabi=5")
        || !script.contains("handoff_identity=supervisor+child-pid+start+ppid+pgrp+session+comm+exe+argv-sha256")
        || !script.contains("handoff_watchdog=armed-before-signal")
        || !script.contains("handoff_signal=j3-ptrace-all-thread-freeze+supervisor-first-sigkill-terminal+child-second-sigkill-terminal+event-drain")
        || !script.contains("IDENTITY_COMMAND=\"$REMOTE_HELPER identity")
        || !script.contains("identity_probe=$IDENTITY_COMMAND")
        || !script.contains("live_identity_schema=dcentos.s19k-braiins-live-identity/v2")
        || !script.contains("live_identity_profile_rule=mutually-exclusive-complete-tuple")
        || !script.contains("live_identity_profile_live88_two_bhb56903_slots_2_3=2xBHB56903@2,3+addr1-undetected-placeholder+eeprom-0x50-absent-0x51-0x52-0511")
        || !script.contains("live_identity_profile_held78_three_bhb56902_slots_1_2_3=3xBHB56902@1,2,3+eeprom-0x50-0x51-0x52-0511")
        || !script.contains("live_identity_profile_bhb56902_only=one-to-three-BHB56902+exact-address/eeprom-join")
        || !script.contains("live_identity_profile_bhb56903_only=one-to-three-BHB56903+exact-address/eeprom-join")
        || !script.contains("live_identity_profile_mixed_bhb56902_bhb56903=one-to-three-mixed-boards+exact-address/eeprom-join")
        || !script.contains("live_identity_profile_all_three_uarts_populated=addresses-1,2,3+ttyS3,ttyS2,ttyS1")
        || !script.contains("mixed-bhb56902-bhb56903")
        || !script.contains("partial-logical-uarts-populated|all-three-uarts-populated")
        || !script.contains("board_names=BHB5690(2|3)(,BHB5690(2|3)){0,2}")
        || !script.contains("live_identity_recheck=pre-handoff+pre-recovery-safeoff")
        || !script.contains("runtime_receipt_schema=dcentos.s19k-tmp-runtime/v5")
        || !script.contains("runtime_lock=board-global-atomic-mkdir+v6-artifact-bound-owner+typed-pending-retention")
        || !script.contains("receipt_clear=checked-safeoff-to-exact-stock-restart-helper-only")
        || !script.contains("recovery_safeoff_receipt=dcentos.s19k-track1-safeoff/v1")
        || !script.contains("runtime_log_ring=/tmp/dcent/log")
        || !script.contains("--expected-host-key-sha256")
        || !script.contains("ssh-keygen -F \"$MINER_IP\" -f \"$KNOWN_HOSTS\"")
        || !script.contains("ssh_host_key_admission=$SSH_HOST_KEY_ADMISSION")
        || !script.contains("ssh_host_key_sha256=$SSH_HOST_KEY_PLAN")
        || !script.contains("ssh_global_known_hosts=disabled-on-contact")
        || !script.contains("GlobalKnownHostsFile=/dev/null")
        || !script.contains("CONFIG_ADMIT_OUT")
        || !script.contains("tomllib")
    {
        return Err(
            "deploy must bind runner/config content, non-persistence, recovery, and scoped TOML",
        );
    }
    let dry = script.find("[DRY RUN]").ok_or("missing DRY RUN marker")?;
    let ssh = script
        .find("ssh_trial \"root@$MINER_IP\"")
        .ok_or("missing strict SSH execution")?;
    if dry > ssh {
        return Err("dry-run must write the plan before SSH");
    }
    let scp = script
        .find("scp_trial \"$BIN\"")
        .ok_or("missing binary scp")?;
    let post = script
        .find("admit_s19k_tmp_deploy_post_scp")
        .ok_or("missing post-scp admit")?;
    let chmod = script.find("chmod 755").ok_or("missing chmod")?;
    if scp > post || post > chmod {
        return Err("post-scp hash re-admit must run after scp and before chmod");
    }
    Ok(())
}

/// The target-side Track-1 supervisor must remain a genuinely ephemeral
/// process wrapper. In particular, its crash recovery must never depend on a
/// `/tmp` backup of persistent identity files: a watchdog reset can erase the
/// backup while leaving the persistent mutation behind. Both environment
/// guards are required independently so the daemon disables persistence and
/// performs checked reset-before-power-cut on every terminal path.
/// Trial-root prefix of every ephemeral Track-1 trial directory.
pub const S19K_EPHEMERAL_TRIAL_PREFIX: &str = "/tmp/dcentrald_bench_t1_";
/// Global custody lock directory (`owner` is its only admitted journal).
pub const S19K_GLOBAL_RUNTIME_LOCK_DIR: &str = "/tmp/dcent-s19k-track1-runtime-lock";
/// Basename of the global custody owner record.
pub const S19K_GLOBAL_RUNTIME_LOCK_OWNER: &str = "owner";
/// Trial-relative directory holding the runner's endurance acknowledgements.
pub const S19K_ENDURANCE_ACK_SUBDIR: &str = "endurance_evidence/acks";
/// Scratch prefix of an endurance acknowledgement before publication.
pub const S19K_ENDURANCE_ACK_SCRATCH_PREFIX: &str = ".ack.";

/// Trial-relative journal basenames the daemon's `publisher-v1` bootstrap may
/// no-clobber hard-link.
///
/// This is the single admission set: `dcentrald`'s
/// `s19k_publish_ephemeral_journal_from_cli` classifies every destination with
/// [`classify_s19k_ephemeral_journal_destination`], and
/// [`admit_s19k_tmp_remote_runner_ephemeral`] resolves every
/// `publish_no_clobber_journal*` destination in the runner against the same
/// set. The two sides drifted once (2026-09-01 live bounded-work proof on
/// `a lab unit`): the runner published five post-SafeOff receipt names the sealed
/// daemon had never admitted, so every transcript seal failed with
/// `S19k journal destination is not an admitted startup authority path` while
/// the offline fake daemon linked anything. Add a runner destination here and
/// the daemon admits it; forget to, and the runner contract fails at host-test
/// time instead of on the bench.
pub const S19K_EPHEMERAL_JOURNAL_TRIAL_DESTINATIONS: &[&str] = &[
    "runtime_startup_c1_child_identity",
    "runtime_startup_j2_child_bound",
    "runtime_startup_release",
    "runtime_startup_retired_terminal",
    "runtime_startup_retire_cleanup_commit",
    "runtime_startup_prefix_pre_safeoff",
    "runtime_safeoff_terminal_receipt",
    "runtime_install_custody_transcript",
    "runtime_handoff_no_work_transcript",
    "runtime_bounded_work_transcript",
    "runtime_endurance_work_receipt",
    "runtime_endurance_failure_receipt",
];

/// Which admitted publication form a `publisher-v1` request takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kEphemeralJournalDestination {
    /// `<trial>/<name>` with `<name>` in [`S19K_EPHEMERAL_JOURNAL_TRIAL_DESTINATIONS`].
    TrialJournal,
    /// `<trial>/endurance_evidence/acks/ack.NNNNNN.kv` from a `.ack.*` scratch in that directory.
    EnduranceAck,
    /// `/tmp/dcent-s19k-track1-runtime-lock/owner` from a trial-root scratch.
    GlobalOwner,
}

pub const S19K_EPHEMERAL_JOURNAL_REFUSAL: &str =
    "S19k journal destination is not an admitted startup authority path";

fn s19k_split_journal_path(path: &str) -> Result<(&str, &str), &'static str> {
    if !path.starts_with('/') || path.ends_with('/') || path.contains("//") {
        return Err("S19k journal source/destination must be absolute normalized paths");
    }
    let (parent, name) = path
        .rsplit_once('/')
        .ok_or("S19k journal path has no parent")?;
    if name.is_empty() || name == "." || name == ".." || parent.is_empty() {
        return Err("S19k journal path has no admissible basename");
    }
    if path
        .split('/')
        .skip(1)
        .any(|component| component == "." || component == "..")
    {
        return Err("S19k journal path must not contain dot components");
    }
    Ok((parent, name))
}

fn s19k_trial_suffix_is_safe(suffix: &str) -> bool {
    !suffix.is_empty()
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

/// Trial root of a publication parent: either the trial directory itself or
/// its `endurance_evidence/acks` subdirectory. Returns `(root, in_ack_dir)`.
fn s19k_journal_parent_kind(parent: &str) -> Result<(&str, bool), &'static str> {
    let suffix = parent
        .strip_prefix(S19K_EPHEMERAL_TRIAL_PREFIX)
        .ok_or("S19k ephemeral publication is outside the trial namespace")?;
    let ack_tail = format!("/{S19K_ENDURANCE_ACK_SUBDIR}");
    if let Some(trial) = suffix.strip_suffix(ack_tail.as_str()) {
        if s19k_trial_suffix_is_safe(trial) {
            let root_len = S19K_EPHEMERAL_TRIAL_PREFIX.len() + trial.len();
            return Ok((&parent[..root_len], true));
        }
        return Err("S19k ephemeral publication trial suffix is unsafe");
    }
    if s19k_trial_suffix_is_safe(suffix) {
        return Ok((parent, false));
    }
    Err("S19k ephemeral publication trial suffix is unsafe")
}

fn s19k_endurance_ack_name_is_exact(name: &str) -> bool {
    name.strip_prefix("ack.")
        .and_then(|rest| rest.strip_suffix(".kv"))
        .map(|digits| digits.len() >= 6 && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .unwrap_or(false)
}

/// Pure admission of a `publisher-v1` request. Path strings only; the caller
/// still proves ownership/mode/inode facts on the filesystem.
pub fn classify_s19k_ephemeral_journal_destination(
    source: &str,
    destination: &str,
) -> Result<S19kEphemeralJournalDestination, &'static str> {
    let (source_parent, source_name) = s19k_split_journal_path(source)?;
    let (destination_parent, destination_name) = s19k_split_journal_path(destination)?;
    let (_trial_root, source_in_ack_dir) = s19k_journal_parent_kind(source_parent)?;
    if destination_parent == S19K_GLOBAL_RUNTIME_LOCK_DIR {
        if !source_in_ack_dir && destination_name == S19K_GLOBAL_RUNTIME_LOCK_OWNER {
            return Ok(S19kEphemeralJournalDestination::GlobalOwner);
        }
        return Err(S19K_EPHEMERAL_JOURNAL_REFUSAL);
    }
    if destination_parent != source_parent {
        return Err(S19K_EPHEMERAL_JOURNAL_REFUSAL);
    }
    if source_in_ack_dir {
        if source_name.starts_with(S19K_ENDURANCE_ACK_SCRATCH_PREFIX)
            && s19k_endurance_ack_name_is_exact(destination_name)
        {
            return Ok(S19kEphemeralJournalDestination::EnduranceAck);
        }
        return Err(S19K_EPHEMERAL_JOURNAL_REFUSAL);
    }
    if S19K_EPHEMERAL_JOURNAL_TRIAL_DESTINATIONS.contains(&destination_name) {
        return Ok(S19kEphemeralJournalDestination::TrialJournal);
    }
    Err(S19K_EPHEMERAL_JOURNAL_REFUSAL)
}

/// Every `(source_var, destination_var)` pair the runner hands to its journal
/// publisher, in script order. Only call sites are collected; the wrapper's
/// own `JOURNAL_SOURCE`/`JOURNAL_DESTINATION` delegation is excluded and must
/// occur exactly once.
pub fn s19k_runner_journal_publications(
    script: &str,
) -> Result<Vec<(String, String)>, &'static str> {
    let mut publications = Vec::new();
    let mut delegations = 0usize;
    for line in script.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        let rest =
            if let Some(rest) = trimmed.strip_prefix("publish_no_clobber_journal_keep_source ") {
                rest
            } else if let Some(rest) = trimmed.strip_prefix("publish_no_clobber_journal ") {
                rest
            } else {
                continue;
            };
        let mut vars = Vec::new();
        let mut cursor = rest;
        for _ in 0..2 {
            let after_open = cursor
                .strip_prefix("\"$")
                .ok_or("Track-1 journal publication must pass two \"$VAR\" arguments")?;
            let close = after_open
                .find('"')
                .ok_or("Track-1 journal publication argument is unterminated")?;
            let var = &after_open[..close];
            if var.is_empty()
                || !var
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b'_' || byte.is_ascii_digit())
            {
                return Err("Track-1 journal publication must name plain shell variables");
            }
            vars.push(var.to_string());
            cursor = after_open[close + 1..].trim_start();
        }
        if vars[0] == "JOURNAL_SOURCE" && vars[1] == "JOURNAL_DESTINATION" {
            delegations += 1;
            continue;
        }
        publications.push((vars[0].clone(), vars[1].clone()));
    }
    if delegations != 1 {
        return Err(
            "Track-1 runner must delegate exactly once from publish_no_clobber_journal to its keep-source form",
        );
    }
    if publications.is_empty() {
        return Err("Track-1 runner publishes no journals");
    }
    Ok(publications)
}

/// Every non-empty `VAR=...` assignment of a runner variable, in script
/// order. Bare `VAR=` initialisers are ignored.
fn s19k_runner_assignments<'a>(script: &'a str, var: &str) -> Vec<&'a str> {
    let prefix = format!("{var}=");
    script
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix(prefix.as_str()))
        .filter(|value| !value.is_empty())
        .collect()
}

/// The single admitted assignment of a runner variable: at least one
/// non-empty assignment, all identical.
fn s19k_runner_assignment<'a>(script: &'a str, var: &str) -> Option<&'a str> {
    let assignments = s19k_runner_assignments(script, var);
    let first = *assignments.first()?;
    assignments
        .iter()
        .all(|assignment| *assignment == first)
        .then_some(first)
}

fn s19k_runner_assignments_start_with(script: &str, var: &str, prefix: &str) -> bool {
    let assignments = s19k_runner_assignments(script, var);
    !assignments.is_empty()
        && assignments
            .iter()
            .all(|assignment| assignment.starts_with(prefix))
}

/// Resolve each runner journal destination variable to its admitted form and
/// return the trial basenames the runner publishes, in script order.
pub fn admit_s19k_runner_journal_destinations(script: &str) -> Result<Vec<String>, &'static str> {
    let mut names = Vec::new();
    let lock_dir = s19k_runner_assignment(script, "RUNTIME_LOCK")
        .ok_or("Track-1 runner must define RUNTIME_LOCK")?;
    if lock_dir != S19K_GLOBAL_RUNTIME_LOCK_DIR {
        return Err(
            "Track-1 runner RUNTIME_LOCK must be the daemon's admitted global lock directory",
        );
    }
    for (source_var, destination_var) in s19k_runner_journal_publications(script)? {
        if s19k_runner_assignments(script, &source_var).is_empty() {
            return Err("Track-1 journal publication source variable is never assigned");
        }
        match destination_var.as_str() {
            "RUNTIME_LOCK_OWNER" => {
                if s19k_runner_assignment(script, "RUNTIME_LOCK_OWNER")
                    != Some("\"$RUNTIME_LOCK/owner\"")
                {
                    return Err(
                        "Track-1 runner RUNTIME_LOCK_OWNER must be the global lock owner record",
                    );
                }
                if !s19k_runner_assignments_start_with(script, &source_var, "\"$TRIAL_DIR/.") {
                    return Err(
                        "Track-1 global owner publication must originate from a trial-root scratch",
                    );
                }
            }
            "ENDURANCE_ACK" => {
                if s19k_runner_assignment(script, "ENDURANCE_ACK")
                    != Some("$(endurance_ack_path \"$ENDURANCE_SEQUENCE\") || exit 1")
                    || !script.contains(
                        "printf '%s/ack.%s.kv\\n' \"$ENDURANCE_ACK_DIR\" \"$ENDURANCE_ACK_SUFFIX\"",
                    )
                    || s19k_runner_assignment(script, "ENDURANCE_ACK_DIR")
                        != Some("\"$ENDURANCE_EVIDENCE_DIR/acks\"")
                    || s19k_runner_assignment(script, "ENDURANCE_EVIDENCE_DIR")
                        != Some("\"$TRIAL_DIR/endurance_evidence\"")
                {
                    return Err(
                        "Track-1 endurance acknowledgement path must be <trial>/endurance_evidence/acks/ack.NNNNNN.kv",
                    );
                }
                if !s19k_runner_assignments_start_with(
                    script,
                    &source_var,
                    "\"$ENDURANCE_ACK_DIR/.ack.",
                ) {
                    return Err("Track-1 endurance acknowledgement scratch must live beside its destination");
                }
            }
            _ => {
                let assignment = s19k_runner_assignment(script, &destination_var)
                    .ok_or("Track-1 journal publication destination variable is never assigned")?;
                let name = assignment
                    .strip_prefix("\"$TRIAL_DIR/")
                    .and_then(|rest| rest.strip_suffix('"'))
                    .ok_or("Track-1 journal destination must be a fixed trial-root basename")?;
                if !S19K_EPHEMERAL_JOURNAL_TRIAL_DESTINATIONS.contains(&name) {
                    return Err(
                        "Track-1 runner publishes a journal destination the daemon publisher does not admit",
                    );
                }
                if !s19k_runner_assignments_start_with(script, &source_var, "\"$TRIAL_DIR/.") {
                    return Err("Track-1 trial journal publication must originate from a trial-root scratch");
                }
                names.push(name.to_string());
            }
        }
    }
    Ok(names)
}

pub fn admit_s19k_tmp_remote_runner_ephemeral(script: &str) -> Result<(), &'static str> {
    // Policy comments are expected to name the paths they forbid. Inspect only
    // executable shell lines so those comments cannot either false-positive or
    // hide a real command.
    let executable = script
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    if executable.contains("/etc/dcentos") || executable.contains("/etc/dcentos-platform") {
        return Err("Track-1 runner must not mutate persistent /etc identity");
    }
    if executable.contains("/data") {
        return Err("Track-1 runner must not create persistent /data state");
    }
    let global_path = script
        .find("PATH=/usr/bin:/bin:/usr/sbin:/sbin\nexport PATH")
        .ok_or("Track-1 wrapper must pin PATH before any admission command")?;
    let first_admission_command = script
        .find("verify_bound_file() {")
        .ok_or("Track-1 runner must define content admission")?;
    if global_path > first_admission_command {
        return Err("Track-1 wrapper must pin PATH before any admission command");
    }
    if !script.contains("DCENTOS_EPHEMERAL_RUNTIME=1") {
        return Err("Track-1 runner must enable the daemon's ephemeral runtime policy");
    }
    if !script.contains(
        "stage-only|mining-on-passthrough|handoff-no-work|bounded-work-proof|endurance-work-proof",
    ) || !script.contains("set -- \"$@\" --s19k-track1-no-work")
        || !script.contains("set -- \"$@\" --s19k-track1-bounded-work-proof")
        || !script.contains("set -- \"$@\" --s19k-track1-endurance-work-proof")
        || !script.contains("S19K_ENDURANCE_ACK_OK")
        || !script.contains("publish_endurance_work_receipt")
    {
        return Err("Track-1 runner must bind exact no-work/work-proof/endurance modes and collector acknowledgements");
    }
    if !script.contains(
        "NO_WORK_TRANSCRIPT_RECEIPT=\"$TRIAL_DIR/runtime_handoff_no_work_transcript\"",
    ) || !script.contains("handoff_no_work_transcript_receipt_is_exact() {")
        || !script.contains("publish_handoff_no_work_transcript_receipt() {")
        || !script.contains("schema=dcentos.s19k-handoff-no-work-transcript/v1")
        || !script.contains("semantic_verification=host-plus-independent-instruments-required")
        || !script.contains(
            "[ \"$(wc -l < \"$NO_WORK_TRANSCRIPT_RECEIPT\" | tr -d ' \\t\\r\\n')\" -eq 65 ]",
        )
        || !script.contains(
            "if [ \"$DEPLOY_MODE\" = install-custody-safeoff ] \\\n    || [ \"$DEPLOY_MODE\" = handoff-no-work ] \\\n    || [ \"$DEPLOY_MODE\" = bounded-work-proof ]; then\n    exec 6< \"$STARTUP_DAEMON_TRANSCRIPT\"",
        )
        || !script.contains("\"$@\" 6>&- 9>&-")
    {
        return Err(
            "Track-1 no-work mode must retain and publish an exact transcript receipt for independent verification",
        );
    }
    let no_work_publisher_start = script
        .find("publish_handoff_no_work_transcript_receipt() {")
        .ok_or("Track-1 no-work transcript publisher is missing")?;
    let no_work_publisher_tail = &script[no_work_publisher_start..];
    let no_work_publisher_end = no_work_publisher_tail
        .find("\n}\n")
        .ok_or("Track-1 no-work transcript publisher is unterminated")?;
    let no_work_publisher = &no_work_publisher_tail[..no_work_publisher_end];
    for binding in [
        "transcript_sha256=%s",
        "source_runtime_active_sha256=%s",
        "pending_runtime_sha256=%s",
        "terminal_handoff_receipt_sha256=%s",
        "safeoff_receipt_sha256=%s",
        "startup_c1_sha256=%s",
        "startup_j1_sha256=%s",
        "startup_j2_sha256=%s",
        "startup_release_sha256=%s",
        "no_work_active_count=%s",
        "discarded_job_count=%s",
        "full_frame_count=%s",
        "bounded_tx_count=%s",
        "dispatch_admitted_count=%s",
        "publish_no_clobber_journal \"$NO_WORK_TMP\" \"$NO_WORK_TRANSCRIPT_RECEIPT\"",
    ] {
        if !no_work_publisher.contains(binding) {
            return Err("Track-1 no-work receipt must bind exact target bytes and safety evidence");
        }
    }
    // 2026-08-30 (f2d3b9bc6) consolidated the per-mode receipt publishes into
    // one fail-closed publish_mode_specific_receipts_after_safeoff() invoked on
    // every checked-SafeOff exit path. The no-work publisher is therefore
    // called exactly once, from inside that function, and the function itself
    // must follow checked SafeOff + the typed stock-restart transition on both
    // the signal ($EXIT_CODE) and ordinary child ($CHILD_STATUS) exits.
    let unified_start = script
        .find("publish_mode_specific_receipts_after_safeoff() {")
        .ok_or(
            "Track-1 runner must publish mode-specific receipts from one fail-closed function",
        )?;
    let unified_tail = &script[unified_start..];
    let unified_end = unified_tail
        .find("\n}\n")
        .ok_or("Track-1 mode-specific receipt publisher is unterminated")?;
    let unified = &unified_tail[..unified_end];
    for publisher in [
        "publish_install_custody_transcript_receipt \"$MODE_WRAPPER_EXIT_STATUS\"",
        "publish_handoff_no_work_transcript_receipt \"$MODE_WRAPPER_EXIT_STATUS\"",
        "publish_bounded_work_transcript_receipt \"$MODE_WRAPPER_EXIT_STATUS\"",
        "publish_endurance_work_receipt \"$MODE_WRAPPER_EXIT_STATUS\"",
    ] {
        if unified.matches(publisher).count() != 1 {
            return Err("Track-1 mode-specific receipt publisher must call each receipt publisher exactly once");
        }
    }
    if script
        .matches("publish_handoff_no_work_transcript_receipt \"$")
        .count()
        != 1
    {
        return Err("Track-1 no-work receipt must be published only through the unified publisher");
    }
    let unified_calls = script
        .match_indices("publish_mode_specific_receipts_after_safeoff \"$")
        .map(|(offset, _)| offset)
        .collect::<Vec<_>>();
    let mut checked_signal_exit = false;
    let mut checked_child_exit = false;
    for call in unified_calls {
        let prefix = &script[..call];
        let argument = &script[call..];
        let signal_exit =
            argument.starts_with("publish_mode_specific_receipts_after_safeoff \"$EXIT_CODE\"");
        let child_exit =
            argument.starts_with("publish_mode_specific_receipts_after_safeoff \"$CHILD_STATUS\"");
        if !signal_exit && !child_exit {
            return Err("Track-1 mode-specific receipts must bind the signal or child exit status");
        }
        let previous_line = prefix.trim_end().rsplit('\n').next().unwrap_or("").trim();
        match previous_line {
            "clear_runtime_obligation_after_safeoff || exit 1" => {
                let checked_safeoff = prefix
                    .rfind("if perform_checked_safeoff; then")
                    .ok_or("Track-1 mode-specific receipts must follow checked SafeOff")?;
                let pending_transition = prefix
                    .rfind("clear_runtime_obligation_after_safeoff || exit 1")
                    .ok_or("Track-1 mode-specific receipts must follow the typed stock-restart transition")?;
                if checked_safeoff > pending_transition {
                    return Err(
                        "Track-1 mode-specific receipts must follow checked SafeOff and typed stock-restart publication",
                    );
                }
                checked_signal_exit |= signal_exit;
                checked_child_exit |= child_exit;
            }
            "transition_startup_stock_loss_to_pending || exit 1" => {}
            _ => {
                return Err(
                    "Track-1 mode-specific receipts must directly follow the typed stock-restart or stock-loss transition",
                );
            }
        }
    }
    if !checked_signal_exit || !checked_child_exit {
        return Err("Track-1 mode-specific receipts must cover signal and ordinary child exits after checked SafeOff");
    }
    if !script.contains("DCENT_S19K_TRACK1_STOP_SAFEOFF=1") {
        return Err("Track-1 runner must require checked terminal SafeOff");
    }
    if !script.contains("persistent_mutation=false")
        || !script.contains("schema=dcentos.s19k-tmp-runtime/v5")
    {
        return Err("Track-1 runner must publish an explicit non-persistent runtime receipt");
    }
    if !script.contains("[ \"$(wc -l < \"$ACTIVE\" | tr -d ' \\t\\r\\n')\" -eq 40 ]")
        || !script.contains("ERROR: runtime receipt has an inexact field set")
    {
        return Err("Track-1 restore must admit the exact runtime receipt field set");
    }
    if !script.contains("RUNTIME_LOCK=/tmp/dcent-s19k-track1-runtime-lock")
        || !script.contains("RUNTIME_LOCK_OWNER=\"$RUNTIME_LOCK/owner\"")
        || !script.contains("schema=dcentos.s19k-track1-runtime-lock/v6")
        || !script.contains("printf 'trial_dir=%s\\n' \"$TRIAL_DIR\"")
        || !script.contains("printf 'runner_sha256=%s\\n' \"$RUNNER_SHA\"")
        || !script.contains("printf 'custody_observer_sha256=%s\\n' \"$CUSTODY_SHA\"")
        || !script.contains("printf 'custody_observer_bytes=%s\\n' \"$CUSTODY_BYTES\"")
        || !script
            .contains("printf 'stock_restart_helper_sha256=%s\\n' \"$STOCK_RESTART_HELPER_SHA\"")
        || !script
            .contains("printf 'stock_restart_helper_bytes=%s\\n' \"$STOCK_RESTART_HELPER_BYTES\"")
        || !script.contains("printf 'live_identity_sha256=%s\\n' \"$EXPECTED_LIVE_IDENTITY_SHA\"")
        || !script.contains("WRAPPER_SCAN_PREFIX=$PREFIX")
        || !script
            .contains("EFFECT_WRAPPER_PREFIX=${WRAPPER_SCAN_PREFIX:-/tmp/dcentrald_bench_t1_}")
        || !script.contains("\"$EFFECT_WRAPPER_PREFIX\"*/run_trial)")
        || !script.contains("admit_runtime_lock_owner_record() {")
        || !script.contains("runtime_lock_owner_matches_current() {")
        || !script.contains("replace_runtime_lock_owner_for_receiptless_recovery() {")
    {
        return Err("Track-1 custody lock must be board-global with an exact bound owner record");
    }
    if !script.contains("[ \"$LOCK_TRIAL\" = \"$TRIAL_DIR\" ]")
        || !script.contains("[ \"$LOCK_RUNNER_SHA\" = \"$RUNNER_SHA\" ]")
        || !script.contains("[ \"$LOCK_RUNNER_BYTES\" = \"$RUNNER_BYTES\" ]")
        || !script.contains("[ \"$LOCK_CUSTODY_SHA\" = \"$CUSTODY_SHA\" ]")
        || !script.contains("[ \"$LOCK_CUSTODY_BYTES\" = \"$CUSTODY_BYTES\" ]")
    {
        return Err("Track-1 custody owner must bind this exact trial and runner");
    }
    if !script.contains("RECOVERY_LOCK_MODE=${1:-bound}")
        || !script.contains("bound|receiptless)")
        || !script.contains("ensure_runtime_lock_for_recovery bound")
        || !script.contains("ensure_runtime_lock_for_recovery receiptless")
        || !script.contains("[ \"$RECOVERY_LOCK_MODE\" = receiptless ]")
        || !script.contains("STALE_OWNER_SHA=$(sha256sum \"$RUNTIME_LOCK_OWNER\"")
        || !script.contains("global custody owner changed during receiptless recovery rebind")
        || !script.contains("mv -f \"$REBIND_TMP\" \"$RUNTIME_LOCK_OWNER\"")
    {
        return Err("Track-1 stale custody rebind must be atomic and receiptless-recovery-only");
    }
    let ensure_lock_start = script
        .find("ensure_runtime_lock_for_recovery() {")
        .ok_or("Track-1 recovery must define global-lock acquisition")?;
    let ensure_lock_tail = &script[ensure_lock_start..];
    let ensure_lock_end = ensure_lock_tail
        .find("\n}\n")
        .ok_or("Track-1 recovery global-lock acquisition is unterminated")?;
    let ensure_lock = &ensure_lock_tail[..ensure_lock_end];
    let lock_classifier_start = script
        .find("runtime_lock_container_is_exact() {")
        .ok_or("Track-1 global lock classifier is missing")?;
    let lock_classifier_tail = &script[lock_classifier_start..];
    let lock_classifier_end = lock_classifier_tail
        .find("\n}\n")
        .ok_or("Track-1 global lock classifier is unterminated")?;
    let lock_classifier = &lock_classifier_tail[..lock_classifier_end];
    if !lock_classifier
        .contains("[ -d \"$RUNTIME_LOCK\" ] && [ ! -L \"$RUNTIME_LOCK\" ] || return 1")
    {
        return Err("Track-1 global lock classifier must reject non-directories and symlinks");
    }
    let existing_lock_type = ensure_lock
        .find("runtime_lock_container_is_exact || {")
        .ok_or("Track-1 recovery must reject a non-directory or symlink global lock")?;
    let unpublished_owner = ensure_lock
        .find("if [ ! -e \"$RUNTIME_LOCK_OWNER\" ] && [ ! -L \"$RUNTIME_LOCK_OWNER\" ]; then")
        .ok_or("Track-1 recovery must handle only an exact unpublished lock owner")?;
    let existing_lock_admit = ensure_lock
        .find("admit_runtime_lock_owner_record")
        .ok_or("Track-1 recovery must parse an existing global-lock owner")?;
    let receiptless_rebind = ensure_lock
        .find("replace_runtime_lock_owner_for_receiptless_recovery")
        .ok_or("Track-1 recovery must explicitly scope stale-owner rebind")?;
    if existing_lock_type > unpublished_owner
        || existing_lock_type > existing_lock_admit
        || existing_lock_admit > receiptless_rebind
    {
        return Err("Track-1 recovery must validate the existing global lock before owner access");
    }
    for binding in [
        "binary_sha256=%s",
        "binary_bytes=%s",
        "config_sha256=%s",
        "config_bytes=%s",
        "runner_sha256=%s",
        "runner_bytes=%s",
        "custody_observer_sha256=%s",
        "custody_observer_bytes=%s",
        "stock_restart_helper_sha256=%s",
        "stock_restart_helper_bytes=%s",
        "supervisor_pid=%s",
        "supervisor_start=%s",
        "supervisor_ppid=%s",
        "supervisor_pgrp=%s",
        "supervisor_session=%s",
        "supervisor_exe=%s",
        "supervisor_cmdline_sha256=%s",
        "supervisor_cmdline_bytes=%s",
        "bosminer_pid=%s",
        "bosminer_start=%s",
        "bosminer_ppid=%s",
        "bosminer_pgrp=%s",
        "bosminer_session=%s",
        "bosminer_exe=%s",
        "bosminer_cmdline_sha256=%s",
        "bosminer_cmdline_bytes=%s",
        "live_identity_schema=dcentos.s19k-braiins-live-identity/v2",
        "live_identity_profile=%s",
        "live_identity_sha256=%s",
    ] {
        if !script.contains(binding) {
            return Err("Track-1 runtime receipt must bind content and inherited owner identity");
        }
    }
    let publisher_start = script
        .find("publish_no_clobber_journal_keep_source() {")
        .ok_or("Track-1 runner must define its no-clobber journal publisher")?;
    let publisher_tail = &script[publisher_start..];
    let publisher_end = publisher_tail
        .find("\n}\n")
        .ok_or("Track-1 no-clobber journal publisher is unterminated")?;
    let publisher = &publisher_tail[..publisher_end];
    if !publisher.contains("/usr/bin/env -i")
        || !publisher.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin")
        || !publisher.contains("DCENT_S19K_STARTUP_BOOTSTRAP=publisher-v1")
        || !publisher.contains("DCENT_S19K_STARTUP_WRAPPER_PID=\"$$\"")
        || !publisher.contains("DCENT_S19K_STARTUP_WRAPPER_START=\"$SELF_START\"")
    {
        return Err("Track-1 journal publisher must use its exact clean bootstrap environment");
    }
    let perform_start = script
        .find("perform_checked_safeoff() {")
        .ok_or("Track-1 runner must define checked recovery SafeOff")?;
    let perform_tail = &script[perform_start..];
    let perform_end = perform_tail
        .find("\n}\n")
        .ok_or("Track-1 recovery SafeOff wrapper is unterminated")?;
    let perform = &perform_tail[..perform_end];
    let runtime_lock = perform
        .find("runtime_lock_container_is_exact")
        .ok_or("Track-1 recovery must hold the exact atomic runtime custody lock")?;
    let runtime_lock_owner = perform
        .find("admit_runtime_lock_owner || return 1")
        .ok_or("Track-1 recovery must admit the board-global custody owner record")?;
    let checked_call = perform
        .find("run_checked_safeoff_command")
        .ok_or("Track-1 recovery wrapper must invoke the checked SafeOff command")?;
    if runtime_lock > checked_call || runtime_lock_owner > checked_call {
        return Err("Track-1 recovery must hold exact custody before checked SafeOff");
    }
    let safeoff_start = script
        .find("run_checked_safeoff_command() {")
        .ok_or("Track-1 runner must define the checked recovery SafeOff command")?;
    let safeoff_tail = &script[safeoff_start..];
    let safeoff_end = safeoff_tail
        .find("\n}\n")
        .ok_or("Track-1 recovery SafeOff function is unterminated")?;
    let safeoff = &safeoff_tail[..safeoff_end];
    let identity_recheck = safeoff
        .find("require_same_live_s19k_identity")
        .ok_or("Track-1 recovery must recheck the bound live S19k identity")?;
    let exact_owner = safeoff
        .find("process_matches \"${BOUND_SUPERVISOR_PID:-0}\" \"${BOUND_SUPERVISOR_START:-0}\"")
        .ok_or("Track-1 recovery must refuse the bound stock supervisor lifetime")?;
    let any_owner = safeoff
        .find("bosminer_custody_owner_is_live")
        .ok_or("Track-1 recovery must refuse any live stock supervisor or child")?;
    let competing_wrapper = safeoff
        .find("another_trial_wrapper_is_live")
        .ok_or("Track-1 recovery must refuse another live wrapper")?;
    let mutation = safeoff
        .find("--s19k-track1-recovery-safeoff")
        .ok_or("Track-1 recovery must use the checked daemon SafeOff command")?;
    if identity_recheck > mutation
        || exact_owner > mutation
        || any_owner > mutation
        || competing_wrapper > mutation
    {
        return Err("Track-1 recovery must reject stock ownership before SafeOff mutation");
    }
    // 2026-08-30 (f2d3b9bc6): the receipt schema/resets/GPIO expectations are
    // bound per SafeOff source mode. The Track-1 (non-install) branch must
    // still pin the exact identity-bound reset+GPIO437 receipt.
    if !script.contains(
        "    else\n        EXPECTED_SAFEOFF_SCHEMA=dcentos.s19k-track1-safeoff/v1\n        EXPECTED_SAFEOFF_RESETS=454:0,455:0,456:0\n        EXPECTED_SAFEOFF_GPIO_RAW=437:1,454:0,455:0,456:0\n        EXPECTED_SAFEOFF_RECEIPT=\"DCENT_S19K_TRACK1_SAFEOFF_RECEIPT schema=$EXPECTED_SAFEOFF_SCHEMA live_identity_sha256=$EXPECTED_LIVE_IDENTITY_SHA live_identity_profile=$EXPECTED_LIVE_IDENTITY_PROFILE live_identity_model_sha256=$LIVE_IDENTITY_MODEL_SHA live_identity_board_count=$BOARD_COUNT live_identity_physical_addresses=$LIVE_IDENTITY_PHYSICAL_ADDRESSES live_identity_board_names=$LIVE_IDENTITY_BOARD_NAMES live_identity_eeprom=$LIVE_IDENTITY_EEPROM_SLOTS resets=$EXPECTED_SAFEOFF_RESETS psu=437:1\"\n    fi\n}",
    ) {
        return Err("Track-1 recovery must require the exact identity-bound reset/GPIO437 SafeOff receipt");
    }
    let exact_safeoff_receipt = safeoff
        .find("set_expected_safeoff_receipt")
        .ok_or("Track-1 recovery must construct its exact SafeOff receipt after execution")?;
    if !safeoff.contains("grep -Fxq \"$EXPECTED_SAFEOFF_RECEIPT\"") {
        return Err("Track-1 recovery must compare the entire identity-bound SafeOff receipt");
    }
    if exact_safeoff_receipt < mutation {
        return Err("Track-1 recovery must observe the exact SafeOff receipt after mutation");
    }
    let safeoff_clean_env = safeoff
        .find("/usr/bin/env -i")
        .ok_or("Track-1 recovery must discard the inherited operator environment")?;
    let safeoff_path = safeoff
        .find("PATH=/usr/bin:/bin:/usr/sbin:/sbin")
        .ok_or("Track-1 recovery must use the exact pinned command path")?;
    let safeoff_ephemeral = safeoff
        .find("DCENTOS_EPHEMERAL_RUNTIME=1")
        .ok_or("Track-1 recovery must explicitly restore ephemeral runtime policy")?;
    let safeoff_identity = safeoff
        .find("DCENT_S19K_LIVE_IDENTITY_SHA256=\"$EXPECTED_LIVE_IDENTITY_SHA\"")
        .ok_or("Track-1 recovery must pass the receipt-bound live identity")?;
    if safeoff_clean_env > safeoff_path
        || safeoff_path > safeoff_ephemeral
        || safeoff_ephemeral > safeoff_identity
        || safeoff_identity > mutation
    {
        return Err("Track-1 recovery clean environment must precede SafeOff execution");
    }
    let clear_start = script
        .find("clear_runtime_obligation_after_safeoff() {")
        .ok_or("Track-1 runner must define checked runtime-obligation release")?;
    let clear_tail = &script[clear_start..];
    let clear_end = clear_tail
        .find("\n}\n")
        .ok_or("Track-1 runtime-obligation release is unterminated")?;
    let clear = &clear_tail[..clear_end];
    if clear.contains("rmdir \"$RUNTIME_LOCK\"")
        || clear.contains("rm -f \"$RUNTIME_LOCK_OWNER\"")
        || clear.contains("rm -f \"$ACTIVE\"")
    {
        return Err("Track-1 SafeOff is not stock recovery; custody evidence must remain held");
    }
    for transition in [
        "PRE_SAFEOFF_ACTIVE=\"$TRIAL_DIR/runtime_active_pre_safeoff\"",
        "SAFEOFF_TERMINAL_RECEIPT=\"$TRIAL_DIR/runtime_safeoff_terminal_receipt\"",
        "STOCK_INIT=/etc/init.d/S99bosminer",
        "STOCK_INIT_EXPECTED_SHA=6d9cce12caa49249396b48296101b0fbbcc6456cb3fa09bdbe2858bdcba948c9",
        "STOCK_INIT_EXPECTED_BYTES=1330",
        "PENDING_SCHEMA=dcentos.s19k-stock-restart-pending/v3",
        "PENDING_SCHEMA=dcentos.s19k-stock-restart-pending/v4",
        "OWNER_SCHEMA=dcentos.s19k-track1-runtime-lock/v7",
        "OWNER_SCHEMA=dcentos.s19k-track1-runtime-lock/v8",
        "PENDING_LINES=45",
        "PENDING_LINES=49",
        "OWNER_LINES=14",
        "OWNER_LINES=15",
        "printf 'phase=terminal-safeoff-stock-restart-pending\\n'",
        "printf 'next_authority=exact-stock-restart-helper-only\\n'",
        "printf 'terminal_handoff_receipt_schema=dcentos.s19k-terminal-safeoff-partial-stock-owner/v1\\n'",
        "mv -f \"$PENDING_TMP\" \"$ACTIVE\"",
        "mv -f \"$OWNER_TMP\" \"$RUNTIME_LOCK_OWNER\"",
        "pending_terminal_binding_is_exact",
        "stock-restart-pending final fence failed; global custody lock retained",
    ] {
        if !script.contains(transition) {
            return Err("Track-1 SafeOff must publish an exact retained stock-restart obligation");
        }
    }
    let post_safeoff_fence = clear
        .find("gpio_safeoff_is_exact")
        .ok_or("Track-1 SafeOff transition must revalidate the exact GPIO tuple")?;
    let stock_init = clear
        .find("STOCK_INIT=/etc/init.d/S99bosminer")
        .ok_or("Track-1 SafeOff transition must bind the exact stock init artifact")?;
    let predecessor = clear
        .find("ln \"$ACTIVE\" \"$PRE_SAFEOFF_ACTIVE\"")
        .ok_or("Track-1 SafeOff transition must preserve the predecessor receipt")?;
    let safeoff_receipt = clear
        .find("ln \"$SAFE_TMP\" \"$SAFEOFF_TERMINAL_RECEIPT\"")
        .ok_or("Track-1 SafeOff transition must publish the exact terminal receipt")?;
    let pending_publication = clear
        .find("mv -f \"$PENDING_TMP\" \"$ACTIVE\"")
        .ok_or("Track-1 SafeOff transition must atomically publish pending stock restart")?;
    let owner_publication = clear
        .find("mv -f \"$OWNER_TMP\" \"$RUNTIME_LOCK_OWNER\"")
        .ok_or("Track-1 SafeOff transition must atomically publish its new custody owner")?;
    let final_fence = clear
        .find("# Final fence after both atomic transitions")
        .ok_or("Track-1 SafeOff transition must perform a final evidence fence")?;
    if post_safeoff_fence > stock_init
        || stock_init > predecessor
        || predecessor > safeoff_receipt
        || safeoff_receipt > pending_publication
        || pending_publication > owner_publication
        || owner_publication > final_fence
    {
        return Err("Track-1 retained stock-restart transition is ordered unsafely");
    }

    let self_bind = script
        .find("SELF_START=$(process_start \"$$\")")
        .ok_or("Track-1 wrapper must bind its own process lifetime")?;
    let identity_mode = script
        .find("if [ \"$MODE\" = identity ]; then")
        .ok_or("Track-1 runner must define identity mode")?;
    if self_bind > identity_mode {
        return Err("Track-1 wrapper identity must be bound before identity and recovery modes");
    }

    let receiptless_start = script
        .find("publish_receiptless_restart_pending_after_safeoff() {")
        .ok_or("Track-1 runner must type receiptless SafeOff separately")?;
    let receiptless_tail = &script[receiptless_start..];
    let receiptless_end = receiptless_tail
        .find("\n}\n")
        .ok_or("Track-1 receiptless SafeOff publication is unterminated")?;
    let receiptless = &receiptless_tail[..receiptless_end];
    for binding in [
        "schema=dcentos.s19k-receiptless-stock-restart-pending/v2",
        "source=receiptless-recovery-no-v4-active",
        "schema=dcentos.s19k-track1-runtime-lock/v9",
        "owner_kind=receiptless-stock-restart-pending",
        "[ \"$(wc -l < \"$PENDING_TMP\" | tr -d ' \\t\\r\\n')\" -eq 42 ]",
        "[ \"$(wc -l < \"$RUNTIME_LOCK_OWNER\" | tr -d ' \\t\\r\\n')\" -eq 13 ]",
        "printf 'next_authority=exact-stock-restart-helper-only\\n'",
    ] {
        if !receiptless.contains(binding) {
            return Err("Track-1 receiptless SafeOff must publish an exact distinct custody type");
        }
    }
    let receiptless_fence = receiptless
        .find("gpio_safeoff_is_exact")
        .ok_or("Track-1 receiptless transition must revalidate exact SafeOff GPIO")?;
    let receiptless_stock_init = receiptless
        .find("STOCK_INIT=/etc/init.d/S99bosminer")
        .ok_or("Track-1 receiptless transition must bind the exact stock init")?;
    let receiptless_safeoff = receiptless
        .find("ln \"$SAFE_TMP\" \"$SAFEOFF_TERMINAL_RECEIPT\"")
        .ok_or("Track-1 receiptless transition must preserve its SafeOff receipt")?;
    let receiptless_active = receiptless
        .find("mv \"$PENDING_TMP\" \"$ACTIVE\"")
        .ok_or("Track-1 receiptless transition must publish ACTIVE without clobber")?;
    let receiptless_owner = receiptless
        .find("mv -f \"$OWNER_TMP\" \"$RUNTIME_LOCK_OWNER\"")
        .ok_or("Track-1 receiptless transition must atomically upgrade the lock owner")?;
    if receiptless_fence > receiptless_stock_init
        || receiptless_stock_init > receiptless_safeoff
        || receiptless_safeoff > receiptless_active
        || receiptless_active > receiptless_owner
    {
        return Err("Track-1 receiptless retained-custody transition is ordered unsafely");
    }
    for resume in [
        "upgrade_interrupted_receiptless_pending_owner_after_safeoff() {",
        "upgrade_interrupted_pending_owner_after_safeoff() {",
        "dcentos.s19k-receiptless-stock-restart-pending/v2)",
        "receiptless stock restart is pending; use the exact stock-restart helper",
        "stock remains stopped after crash-resume; exact stock-restart helper is required",
    ] {
        if !script.contains(resume) {
            return Err(
                "Track-1 interrupted SafeOff publication must remain resumable and fail closed",
            );
        }
    }

    let launch_start = script
        .find("write_startup_j0_owner_prefork || {")
        .ok_or("Track-1 runner must publish immutable J0 before fork")?;
    let launch_tail = &script[launch_start..];
    let launch_end = launch_tail
        .find("CHILD_PID=$!")
        .ok_or("Track-1 runner must bind the launched child PID")?;
    let launch = &launch_tail[..launch_end];
    let atomic_lock = script
        .find("if ! mkdir \"$RUNTIME_LOCK\" 2>/dev/null; then")
        .ok_or("Track-1 runner must atomically serialize custody before J0")?;
    if atomic_lock > launch_start {
        return Err("Track-1 atomic custody lock must precede immutable J0");
    }
    let pre_j0 = &script[atomic_lock..launch_start];
    let post_lock_stock_recheck = pre_j0.find("require_same_exact_stock_tree").ok_or(
        "Track-1 runner must recheck the exact stock supervisor/child tree while holding custody",
    )?;
    let post_lock_wrapper_recheck = pre_j0
        .find("another_trial_wrapper_is_live")
        .ok_or("Track-1 runner must reject a competing wrapper while holding custody")?;
    let launch_identity = pre_j0
        .rfind("require_same_live_s19k_identity")
        .ok_or("Track-1 must recheck the bound live identity immediately before J0")?;
    if post_lock_stock_recheck == 0 || post_lock_wrapper_recheck == 0 || launch_identity == 0 {
        return Err("Track-1 post-lock owner checks are malformed");
    }
    let child_clean_env = launch
        .find("/usr/bin/env -i")
        .ok_or("Track-1 child must discard the inherited operator environment")?;
    let child_path = launch
        .find("PATH=/usr/bin:/bin:/usr/sbin:/sbin")
        .ok_or("Track-1 child must use the exact pinned command path")?;
    let child_ephemeral = launch
        .find("DCENTOS_EPHEMERAL_RUNTIME=1")
        .ok_or("Track-1 child must explicitly restore ephemeral runtime policy")?;
    let child_safeoff = launch
        .find("DCENT_S19K_TRACK1_STOP_SAFEOFF=1")
        .ok_or("Track-1 child must explicitly restore terminal SafeOff policy")?;
    let child_identity = launch
        .find("DCENT_S19K_LIVE_IDENTITY_SHA256=\"$EXPECTED_LIVE_IDENTITY_SHA\"")
        .ok_or("Track-1 child must receive the freshly bound live identity")?;
    let child_exec = launch
        .find("\"$@\" 6>&- 9>&-")
        .ok_or("Track-1 child launch must execute the J0-bound canonical daemon argv")?;
    if !script[..launch_start].contains("--s19k-track1-runtime-active \"$ACTIVE\"")
        || !script[..launch_start]
            .contains("--s19k-stock-owner-retained-receipt \"$STOCK_RETAINED_RECEIPT\"")
    {
        return Err("Track-1 child must bind runtime-active and retained-stock receipts");
    }
    if child_clean_env > child_path
        || child_path > child_ephemeral
        || child_ephemeral > child_safeoff
        || child_safeoff > child_identity
        || child_identity > child_exec
    {
        return Err("Track-1 child clean environment must precede daemon execution");
    }
    // Attempt-10 hard-ceiling backstop (2026-08-28 lifecycle audit): the
    // historical blanket "never SIGKILL" invariant is superseded by an exact
    // one — the ONLY kill -KILL anywhere is the trial ceiling's
    // identity-fenced SIGKILL of the exact daemon child inside
    // enforce_trial_ceiling_exit, and it can never name stock supervisor
    // processes. Mirrors scripts/test_s19k_tmp_deploy_safety.py and
    // scripts/s19k_host_verify.py.
    let kill_count = script.matches("kill -KILL").count();
    if kill_count > 1 {
        return Err("Track-1 runner carries more than the single ceiling SIGKILL");
    }
    if kill_count == 1 {
        let ceiling_start = script
            .find("enforce_trial_ceiling_exit() {")
            .ok_or("Track-1 ceiling SIGKILL exists without its fence function")?;
        let ceiling_end = script[ceiling_start..]
            .find("\n}\n")
            .map(|offset| ceiling_start + offset)
            .ok_or("Track-1 ceiling function is unterminated")?;
        let ceiling = &script[ceiling_start..ceiling_end];
        if !ceiling.contains("kill -KILL") {
            return Err("Track-1 runner's only SIGKILL must sit inside the trial ceiling fence");
        }
        if !ceiling.contains("exact_dcentrald_child_matches") {
            return Err("Track-1 ceiling SIGKILL must be identity-fenced to the daemon child");
        }
    }
    for source in [
        "LIVE_CPUINFO=/proc/cpuinfo",
        "LIVE_UNAME=uname",
        "LIVE_PROC_MTD=/proc/mtd",
        "LIVE_BOS_PLATFORM=/etc/bos_platform",
        "LIVE_BOS_MODE=/etc/bos_mode",
        "LIVE_BOSMINER_MODEL=/etc/bosminer_model.json",
        "LIVE_I2CGET=/usr/sbin/i2cget",
        "Antminer S19K Pro NoPic",
        "live88_two_bhb56903_slots_2_3",
        "held78_three_bhb56902_slots_1_2_3",
        "HASHBOARD_ROWS=$(awk",
        "objects != 3",
        "HB not detected. Board name unknown. hashrate_ths is calculated.",
        "1||0|HB not detected. Board name unknown. hashrate_ths is calculated.",
        "2|BHB56903|1|",
        "3|BHB56903|1|",
        "1|BHB56902|1|",
        "2|BHB56902|1|",
        "3|BHB56902|1|",
        "[ \"$HASHBOARD_ROWS\" = \"$LIVE88_HASHBOARD_ROWS\" ]",
        "[ \"$HASHBOARD_ROWS\" = \"$HELD78_HASHBOARD_ROWS\" ]",
        "PROFILE_SUMMARY=$(printf",
        "mixed-bhb56902-bhb56903",
        "all-three-uarts-populated",
        "LIVE_IDENTITY_EXPECTED_MASK",
        "EEPROM_MASK",
        "[ \"$EEPROM_MASK\" = \"$LIVE_IDENTITY_EXPECTED_MASK\" ]",
        "0x05:0x11",
        "profile=$LIVE_IDENTITY_PROFILE",
        "physical_addresses=$LIVE_IDENTITY_PHYSICAL_ADDRESSES",
        "board_names=$LIVE_IDENTITY_BOARD_NAMES",
        "dcentos.s19k-braiins-live-identity/v2",
        "DCENT_S19K_LIVE_IDENTITY schema=dcentos.s19k-braiins-live-identity/v2 profile=%s sha256=%s model_sha256=%s board_names=%s physical_addresses=%s eeprom=%s",
        "[ \"$LIVE_IDENTITY_PROFILE\" = \"$EXPECTED_LIVE_IDENTITY_PROFILE\" ]",
        "EXPECTED_LIVE_IDENTITY_PROFILE=$(active_field live_identity_profile)",
        "EXPECTED_LIVE_IDENTITY_PROFILE=$LIVE_IDENTITY_PROFILE",
    ] {
        if !script.contains(source) {
            return Err("Track-1 runner lacks exact process-independent live identity evidence");
        }
    }
    let restore_identity = script
        .find(
            "        require_same_live_s19k_identity\n        if process_matches \"$WRAPPER_PID\"",
        )
        .ok_or("Track-1 restore must recheck live identity before signaling a child")?;
    let restore_exact_child = script
        .find("            exact_dcentrald_child_matches \"$CHILD_PID\" \"$CHILD_START\"")
        .ok_or("Track-1 restore must recheck the exact child comm/exe before signaling")?;
    let restore_kill = script
        .find("            kill -TERM \"$CHILD_PID\"")
        .ok_or("Track-1 restore must stop only its bound child")?;
    if restore_identity > restore_exact_child || restore_exact_child > restore_kill {
        return Err("Track-1 restore live/child identity gates must precede child signaling");
    }
    let restore_start = script
        .find("if [ \"$MODE\" = restore ]; then")
        .ok_or("Track-1 runner must define content-bound restore")?;
    let restore_end = script[restore_start..]
        .find("\nfi\n\n[ \"$MODE\" = run ]")
        .map(|offset| restore_start + offset)
        .ok_or("Track-1 restore block is unterminated")?;
    let restore = &script[restore_start..restore_end];
    for phase_gate in [
        "[ \"$CHILD_PID:$CHILD_START\" = 0:0 ]",
        "valid_pid_start \"$CHILD_PID\" \"$CHILD_START\"",
        "valid_pid_start \"$WRAPPER_PID\" \"$WRAPPER_START\"",
        "valid_pid_start \"$BOUND_SUPERVISOR_PID\" \"$BOUND_SUPERVISOR_START\"",
        "valid_pid_start \"$BOUND_BOSMINER_PID\" \"$BOUND_BOSMINER_START\"",
    ] {
        if !restore.contains(phase_gate) {
            return Err("Track-1 receipt phase/lifetime semantics are not exact");
        }
    }
    let receiptless_owner_refusal = restore
        .find("ERROR: a bosminer supervisor or child is live without a bound runtime receipt")
        .ok_or("Track-1 receiptless recovery must refuse a live stock owner")?;
    let receiptless_daemon_refusal = restore
        .find("ERROR: dcentrald is live without a bound runtime receipt")
        .ok_or("Track-1 receiptless recovery must refuse a live daemon owner")?;
    let receiptless_wrapper_refusal = restore
        .find("ERROR: another Track-1 wrapper is live without a bound runtime receipt")
        .ok_or("Track-1 receiptless recovery must refuse a competing wrapper")?;
    let receiptless_executable_scan = restore
        .find("bosminer_custody_owner_is_live")
        .ok_or("Track-1 receiptless recovery must scan process executables")?;
    let receiptless_identity = restore
        .find(
            "        capture_exact_live_s19k_identity\n        EXPECTED_LIVE_IDENTITY_PROFILE=$LIVE_IDENTITY_PROFILE\n        EXPECTED_LIVE_IDENTITY_SHA=$LIVE_IDENTITY_SHA",
        )
        .ok_or("Track-1 receiptless recovery must establish fresh exact live identity")?;
    let receiptless_safeoff = restore[receiptless_identity..]
        .find("        perform_checked_safeoff")
        .map(|offset| receiptless_identity + offset)
        .ok_or("Track-1 receiptless recovery must require checked reset+cut")?;
    let receiptless_lock = restore[receiptless_identity..]
        .find("        ensure_runtime_lock_for_recovery receiptless")
        .map(|offset| receiptless_identity + offset)
        .ok_or("Track-1 receiptless recovery must acquire atomic custody before SafeOff")?;
    if receiptless_owner_refusal > receiptless_identity
        || receiptless_daemon_refusal > receiptless_identity
        || receiptless_wrapper_refusal > receiptless_identity
        || receiptless_executable_scan > receiptless_identity
        || receiptless_identity > receiptless_lock
        || receiptless_lock > receiptless_safeoff
    {
        return Err("Track-1 receiptless recovery must refuse owners, bind identity, then SafeOff");
    }
    admit_s19k_runner_journal_destinations(script)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kTmpDeployRequest<'a> {
    pub binary_path_hint: &'a str,
    pub mining_enabled: bool,
    /// Required true when `mining_enabled` (daemon-owned exact bosminer handoff).
    pub passthrough: bool,
    pub open_ports: &'a [&'a str],
    pub gpio437_value: Option<u8>,
    pub uart_trans_present: bool,
    pub first_job_prefix: Option<&'a [u8]>,
    /// Live `/etc/dcentos/board_target` / toml identity.
    pub board_target: &'a str,
}

/// Overlay/S37 may write `am3-s19kpro`. Do not refuse that as `/tmp` identity.
pub fn admit_s19k_tmp_deploy_board_target(name: &str) -> Result<(), S19kTmpDeployError> {
    if S19K_LIVE_IDENTITY_ALIASES.contains(&name) {
        Ok(())
    } else {
        Err(S19kTmpDeployError::WrongBoardTarget)
    }
}

pub fn admit_s19k_tmp_deploy(req: S19kTmpDeployRequest<'_>) -> Result<(), S19kTmpDeployError> {
    if !req.binary_path_hint.contains(REQUIRED_TARGET_TRIPLE) {
        return Err(S19kTmpDeployError::WrongTriple);
    }
    admit_s19k_tmp_deploy_board_target(req.board_target)?;
    if req.mining_enabled && !req.passthrough {
        return Err(S19kTmpDeployError::NativeMiningOnForbidden);
    }
    if admit_braiins_mining_on_ports(req.open_ports).is_err() {
        return Err(S19kTmpDeployError::SinglePortRegression);
    }
    match req.gpio437_value {
        Some(v) => passthrough_must_keep_gpio437_engaged(v)
            .map_err(|_| S19kTmpDeployError::RailsNotEngaged)?,
        None => {}
    }
    if req.uart_trans_present {
        return Err(S19kTmpDeployError::UartTransOnBraiins);
    }
    if let Some(p) = req.first_job_prefix {
        if classify_job_wire_prefix(p) != JobWirePrefixKind::Closed11d {
            return Err(S19kTmpDeployError::WrongJobPrefix);
        }
    }
    Ok(())
}

pub fn required_baud() -> u32 {
    BRAIINS_TTYS_BAUD
}

pub fn required_ports() -> &'static [&'static str] {
    BRAIINS_TTYS_CANDIDATES
}

/// How to free ttyS without dropping rails: the daemon binds exact stock
/// process identity, arms its closeout watchdog, then terminates that lifetime.
pub const KEEP_RAILS_BOSMINER_STOP: &str = "dcentrald-exact-braiins-supervisor-and-child-handoff";
pub const FORBIDDEN_RAILS_DROP_STOP: &str = "/etc/init.d/S99bosminer stop";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_refuses_single_port_and_21_56_and_s99_stop() {
        let ok = S19kTmpDeployRequest {
            binary_path_hint: "target/s19k-tmp/armv7-unknown-linux-musleabihf/release/dcentrald",
            mining_enabled: false,
            passthrough: false,
            open_ports: &["/dev/ttyS1", "/dev/ttyS2"],
            gpio437_value: Some(0),
            uart_trans_present: false,
            first_job_prefix: Some(&crate::s19k_braiins_job::CLOSED_11D_PREFIX),
            board_target: "am3-s19k",
        };
        assert!(admit_s19k_tmp_deploy_board_target("am3-s19kpro").is_ok());
        assert!(admit_s19k_tmp_deploy_board_target("am3-aml-s19kpro").is_ok());
        assert_eq!(
            admit_s19k_tmp_deploy_board_target("am3-s21"),
            Err(S19kTmpDeployError::WrongBoardTarget)
        );
        let mut pro = ok;
        pro.board_target = "am3-s19kpro";
        assert!(admit_s19k_tmp_deploy(pro).is_ok());
        assert!(admit_s19k_tmp_deploy(ok).is_ok());
        let mut mining_on = ok;
        mining_on.mining_enabled = true;
        mining_on.passthrough = true;
        assert!(admit_s19k_tmp_deploy(mining_on).is_ok());
        let mut bad = ok;
        bad.open_ports = &["/dev/ttyS1"];
        assert_eq!(
            admit_s19k_tmp_deploy(bad),
            Err(S19kTmpDeployError::SinglePortRegression)
        );
        bad = ok;
        bad.first_job_prefix = Some(&[0x55, 0xAA, 0x21, 0x56]);
        assert_eq!(
            admit_s19k_tmp_deploy(bad),
            Err(S19kTmpDeployError::WrongJobPrefix)
        );
        bad = ok;
        bad.gpio437_value = Some(1);
        assert_eq!(
            admit_s19k_tmp_deploy(bad),
            Err(S19kTmpDeployError::RailsNotEngaged)
        );
        bad = ok;
        bad.mining_enabled = true;
        bad.passthrough = false;
        assert_eq!(
            admit_s19k_tmp_deploy(bad),
            Err(S19kTmpDeployError::NativeMiningOnForbidden)
        );
        bad = ok;
        bad.board_target = "am3-s21";
        assert_eq!(
            admit_s19k_tmp_deploy(bad),
            Err(S19kTmpDeployError::WrongBoardTarget)
        );
        assert_eq!(required_baud(), 3_000_000);
        assert_eq!(required_ports(), &["/dev/ttyS1", "/dev/ttyS2"]);
        let mut three = ok;
        three.open_ports = &["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"];
        assert!(admit_s19k_tmp_deploy(three).is_ok());
        assert_eq!(
            KEEP_RAILS_BOSMINER_STOP,
            "dcentrald-exact-braiins-supervisor-and-child-handoff"
        );
        assert!(FORBIDDEN_RAILS_DROP_STOP.contains("S99bosminer"));
        let ckpool = include_str!("../../dcentrald_s19k_braiins_ckpool.toml");
        assert!(ckpool.contains("passthrough = true"));
        assert!(ckpool.contains("enabled = true"));
        let deploy_sh = include_str!("../../../scripts/dcentrald_s19k_tmp_deploy.sh");
        assert!(
            deploy_sh.contains("CONFIG_ADMIT_OUT") && deploy_sh.contains("tomllib"),
            "deploy helper must admit mining-on from scoped TOML, not grep-shaped comments"
        );
        assert!(
            deploy_sh.contains("refuse single-port /tmp deploy"),
            "deploy helper must refuse a missing ttyS2"
        );
        assert!(deploy_sh.contains("NativeMiningOn"));
        assert!(
            deploy_sh.contains("admit_s19k_armhf_elf"),
            "deploy helper must parse ELF class/machine, not just the rustc triple in the path"
        );
        assert!(deploy_sh.contains("dcentrald_s19k_tmp_remote_run.sh"));
        assert!(deploy_sh.contains("board_target not in"));
        assert!(deploy_sh.contains("am3-s19kpro"));
        assert!(deploy_sh.contains("am3-aml-s19kpro"));
        let trial_sh = include_str!("../../../scripts/dcentrald_s19k_tmp_remote_run.sh");
        let runner_admission = admit_s19k_tmp_remote_runner_ephemeral(trial_sh);
        assert!(
            runner_admission.is_ok(),
            "content-bound runner must remain non-persistent and retain both safety policies: {runner_admission:?}"
        );
        assert!(!trial_sh.contains("/etc/dcentos"));
        assert!(!trial_sh.contains("/data"));
        assert!(trial_sh.contains("DCENTOS_EPHEMERAL_RUNTIME=1"));
        assert!(trial_sh.contains("DCENT_S19K_TRACK1_STOP_SAFEOFF=1"));
        assert!(
            trial_sh.contains("--serial-mining --allow-loud"),
            "mining-on runner must select serial mining with explicit loud authority"
        );
        assert!(trial_sh.contains("am3-s19kpro"));
        for (mutation_index, mutation) in [
            trial_sh.replace("DCENTOS_EPHEMERAL_RUNTIME=1", "DCENTOS_EPHEMERAL_RUNTIME=0"),
            trial_sh.replace(
                "DCENT_S19K_TRACK1_STOP_SAFEOFF=1",
                "DCENT_S19K_TRACK1_STOP_SAFEOFF=0",
            ),
            trial_sh.replace(
                "schema=dcentos.s19k-handoff-no-work-transcript/v1",
                "schema=dcentos.s19k-handoff-no-work-transcript/unbound",
            ),
            trial_sh.replace(
                "semantic_verification=host-plus-independent-instruments-required",
                "semantic_verification=target-only",
            ),
            trial_sh.replace(
                "publish_mode_specific_receipts_after_safeoff \"$EXIT_CODE\" || exit 1",
                "true \"$EXIT_CODE\" || exit 1",
            ),
            trial_sh.replace(
                "DCENT_S19K_LIVE_IDENTITY_SHA256=\"$EXPECTED_LIVE_IDENTITY_SHA\"",
                "DCENT_S19K_LIVE_IDENTITY_SHA256=unbound",
            ),
            trial_sh.replace(
                "bosminer_custody_owner_is_live",
                "missing_stock_custody_scan",
            ),
            trial_sh.replace("another_trial_wrapper_is_live", "missing_wrapper_scan"),
            trial_sh.replace(
                "RUNTIME_LOCK=/tmp/dcent-s19k-track1-runtime-lock",
                "RUNTIME_LOCK=\"$TRIAL_DIR/runtime_lock\"",
            ),
            trial_sh.replace(
                "schema=dcentos.s19k-track1-runtime-lock/v6",
                "schema=dcentos.s19k-track1-runtime-lock/unbound",
            ),
            trial_sh.replace(
                "WRAPPER_SCAN_PREFIX=$PREFIX",
                "WRAPPER_SCAN_PREFIX=$TRIAL_DIR",
            ),
            trial_sh.replace("write_startup_j0_owner_prefork || {", "true || {"),
            trial_sh.replace(
                "ensure_runtime_lock_for_recovery receiptless",
                "ensure_runtime_lock_for_recovery bound",
            ),
            trial_sh.replace(
                "replace_runtime_lock_owner_for_receiptless_recovery",
                "replace_runtime_lock_owner_without_scope",
            ),
            trial_sh.replace(
                "mv -f \"$REBIND_TMP\" \"$RUNTIME_LOCK_OWNER\"",
                "cp \"$REBIND_TMP\" \"$RUNTIME_LOCK_OWNER\"",
            ),
            trial_sh.replace("    admit_runtime_lock_owner || return 1", "    true"),
            trial_sh.replace(
                "PENDING_SCHEMA=dcentos.s19k-stock-restart-pending/v3",
                "PENDING_SCHEMA=dcentos.s19k-stock-restart-pending/untyped",
            ),
            trial_sh.replace(
                "schema=dcentos.s19k-receiptless-stock-restart-pending/v2",
                "schema=dcentos.s19k-receiptless-stock-restart-pending/untyped",
            ),
            trial_sh.replace(
                "owner_kind=receiptless-stock-restart-pending",
                "owner_kind=receiptless-unbound",
            ),
            trial_sh.replace(
                "EXPECTED_SAFEOFF_RESETS=454:0,455:0,456:0",
                "EXPECTED_SAFEOFF_RESETS=453:0,455:0,456:0",
            ),
            trial_sh.replacen("/usr/bin/env -i", "/usr/bin/env", 1),
            trial_sh.replacen(
                "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
                "PATH=/operator/inherited/bin",
                1,
            ),
            trial_sh.replacen("/usr/bin/env -i", "/usr/bin/env", 2),
            trial_sh.replace("runner_bytes=%s", "unbound_runner=%s"),
            trial_sh.replace(
                "LIVE_BOSMINER_MODEL=/etc/bosminer_model.json",
                "LIVE_BOSMINER_MODEL=/tmp/operator-claimed-model.json",
            ),
            trial_sh.replace(
                "live88_two_bhb56903_slots_2_3",
                "untyped_two_board_union",
            ),
            trial_sh.replace(
                "held78_three_bhb56902_slots_1_2_3",
                "untyped_three_board_union",
            ),
            trial_sh.replace(
                "if (in_array || in_object || !completed || seen_array != 1 || objects != 3) exit 1",
                "if (in_array || in_object || !completed || seen_array != 1 || objects < 1) exit 1",
            ),
            trial_sh.replace(
                "1||0|HB not detected. Board name unknown. hashrate_ths is calculated.",
                "3||0|HB not detected. Board name unknown. hashrate_ths is calculated.",
            ),
            trial_sh.replace(
                "[ \"$EEPROM_MASK\" = \"$LIVE_IDENTITY_EXPECTED_MASK\" ]",
                "[ \"$EEPROM_MASK\" = 111 ]",
            ),
            trial_sh.replace(
                "        require_same_live_s19k_identity\n        if process_matches \"$WRAPPER_PID\"",
                "        true\n        if process_matches \"$WRAPPER_PID\"",
            ),
            trial_sh.replace(
                "            exact_dcentrald_child_matches \"$CHILD_PID\" \"$CHILD_START\" || {",
                "            true || {",
            ),
            trial_sh.replace(
                "if ! mkdir \"$RUNTIME_LOCK\" 2>/dev/null; then",
                "if false; then",
            ),
            trial_sh.replace(
                "require_same_exact_stock_tree || {",
                "true || {",
            ),
            trial_sh.replace(
                "        ensure_runtime_lock_for_recovery receiptless\n        perform_checked_safeoff",
                "        true\n        perform_checked_safeoff",
            ),
            trial_sh.replacen(
                "    [ -d \"$RUNTIME_LOCK\" ] && [ ! -L \"$RUNTIME_LOCK\" ] || return 1",
                "    true || return 1",
                1,
            ),
            trial_sh.replace(
                "mv -f \"$PENDING_TMP\" \"$ACTIVE\"",
                "cp \"$PENDING_TMP\" \"$ACTIVE\"",
            ),
            trial_sh.replace(
                "mv -f \"$OWNER_TMP\" \"$RUNTIME_LOCK_OWNER\"",
                "cp \"$OWNER_TMP\" \"$RUNTIME_LOCK_OWNER\"",
            ),
            trial_sh.replace(
                "                valid_pid_start \"$CHILD_PID\" \"$CHILD_START\" || {",
                "                true || {",
            ),
            trial_sh.replace(
                "                [ \"$CHILD_PID:$CHILD_START\" = 0:0 ] || {",
                "                true || {",
            ),
            trial_sh.replacen("    require_same_live_s19k_identity || return 1", "    true", 1),
            trial_sh.replace(
                "        capture_exact_live_s19k_identity\n        EXPECTED_LIVE_IDENTITY_PROFILE=$LIVE_IDENTITY_PROFILE\n        EXPECTED_LIVE_IDENTITY_SHA=$LIVE_IDENTITY_SHA",
                "        true",
            ),
            format!("{trial_sh}\nprintf x > /etc/dcentos/board_target"),
            format!("{trial_sh}\nkill -KILL 123"),
        ]
        .into_iter()
        .enumerate()
        {
            assert_ne!(
                mutation, trial_sh,
                "runner mutation {mutation_index} did not alter the source"
            );
            assert!(
                admit_s19k_tmp_remote_runner_ephemeral(&mutation).is_err(),
                "runner mutation {mutation_index} slipped through admission"
            );
        }
        let mut elf32_arm = [0u8; 20];
        elf32_arm[0] = 0x7F;
        elf32_arm[1] = b'E';
        elf32_arm[2] = b'L';
        elf32_arm[3] = b'F';
        elf32_arm[4] = ELF_CLASS_32;
        elf32_arm[5] = 1;
        elf32_arm[18..20].copy_from_slice(&ELF_MACHINE_ARM.to_le_bytes());
        assert!(admit_s19k_armhf_elf(&elf32_arm).is_ok());
        let mut elf64 = elf32_arm;
        elf64[4] = 2;
        assert_eq!(
            admit_s19k_armhf_elf(&elf64),
            Err(S19kTmpDeployError::WrongElf)
        );
        let mut aarch64 = elf32_arm;
        aarch64[4] = 2;
        aarch64[18..20].copy_from_slice(&183u16.to_le_bytes());
        assert_eq!(
            admit_s19k_armhf_elf(&aarch64),
            Err(S19kTmpDeployError::WrongElf)
        );
        assert_eq!(
            admit_s19k_armhf_elf(b"MZ"),
            Err(S19kTmpDeployError::WrongElf)
        );
        bad = ok;
        bad.uart_trans_present = true;
        assert_eq!(
            admit_s19k_tmp_deploy(bad),
            Err(S19kTmpDeployError::UartTransOnBraiins)
        );
        bad = ok;
        bad.open_ports = &["/dev/ttyS0", "/dev/ttyS1", "/dev/ttyS2"];
        assert_eq!(
            admit_s19k_tmp_deploy(bad),
            Err(S19kTmpDeployError::SinglePortRegression)
        );

        fn make_elf32_arm(hard: bool, interp: Option<&[u8]>) -> Vec<u8> {
            let phnum = if interp.is_some() { 2 } else { 1 };
            let payload_off = ELF32_EHDR_LEN + phnum * ELF32_PHDR_LEN;
            let interp_len = interp.map_or(0, <[u8]>::len);
            let mut blob = vec![0u8; payload_off + 4 + interp_len];
            blob[0] = 0x7F;
            blob[1] = b'E';
            blob[2] = b'L';
            blob[3] = b'F';
            blob[4] = ELF_CLASS_32;
            blob[5] = ELF_DATA_LSB;
            blob[6] = 1;
            blob[16..18].copy_from_slice(&ELF_TYPE_EXEC.to_le_bytes());
            blob[18..20].copy_from_slice(&ELF_MACHINE_ARM.to_le_bytes());
            blob[20..24].copy_from_slice(&1u32.to_le_bytes());
            blob[24..28].copy_from_slice(&0x0001_0000u32.to_le_bytes());
            blob[28..32].copy_from_slice(&(ELF32_EHDR_LEN as u32).to_le_bytes());
            let flags = EF_ARM_EABI_VER5 | if hard { EF_ARM_ABI_FLOAT_HARD } else { 0 };
            blob[36..40].copy_from_slice(&flags.to_le_bytes());
            blob[40..42].copy_from_slice(&(ELF32_EHDR_LEN as u16).to_le_bytes());
            blob[42..44].copy_from_slice(&(ELF32_PHDR_LEN as u16).to_le_bytes());
            blob[44..46].copy_from_slice(&(phnum as u16).to_le_bytes());
            let load = ELF32_EHDR_LEN;
            blob[load..load + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
            blob[load + 4..load + 8].copy_from_slice(&(payload_off as u32).to_le_bytes());
            blob[load + 8..load + 12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
            blob[load + 16..load + 20].copy_from_slice(&4u32.to_le_bytes());
            blob[load + 20..load + 24].copy_from_slice(&4u32.to_le_bytes());
            blob[load + 24..load + 28].copy_from_slice(&(PF_X | 4).to_le_bytes());
            blob[payload_off..payload_off + 4].copy_from_slice(&0xe1a0_0000u32.to_le_bytes());
            if let Some(path) = interp {
                let ph = ELF32_EHDR_LEN + ELF32_PHDR_LEN;
                blob[ph..ph + 4].copy_from_slice(&PT_INTERP.to_le_bytes());
                let str_off = payload_off + 4;
                blob[ph + 4..ph + 8].copy_from_slice(&(str_off as u32).to_le_bytes());
                blob[ph + 16..ph + 20].copy_from_slice(&(path.len() as u32).to_le_bytes());
                blob[str_off..str_off + path.len()].copy_from_slice(path);
            }
            blob
        }

        let static_blob = make_elf32_arm(true, None);
        let static_hf = parse_s19k_armhf_elf(&static_blob).unwrap();
        assert_eq!(static_hf.eabi_version, 5);
        assert!(static_hf.hard_float);
        assert!(static_hf.interp.is_none());
        assert!(admit_s19k_armhf_musl_static(&static_hf).is_ok());
        for (label, mutate) in [
            ("zero program headers", (44usize, [0u8, 0u8])),
            ("undersized program header", (42usize, 20u16.to_le_bytes())),
        ] {
            let mut malformed = static_blob.clone();
            malformed[mutate.0..mutate.0 + 2].copy_from_slice(&mutate.1);
            assert_eq!(
                parse_s19k_armhf_elf(&malformed),
                Err(S19kTmpDeployError::WrongElf),
                "{label}"
            );
        }
        let mut zero_entry = static_blob.clone();
        zero_entry[24..28].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_s19k_armhf_elf(&zero_entry),
            Err(S19kTmpDeployError::WrongElf)
        );
        let mut entry_outside = static_blob.clone();
        entry_outside[24..28].copy_from_slice(&0x0001_0004u32.to_le_bytes());
        assert_eq!(
            parse_s19k_armhf_elf(&entry_outside),
            Err(S19kTmpDeployError::WrongElf)
        );
        let mut non_executable = static_blob.clone();
        non_executable[ELF32_EHDR_LEN + 24..ELF32_EHDR_LEN + 28]
            .copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(
            parse_s19k_armhf_elf(&non_executable),
            Err(S19kTmpDeployError::WrongElf)
        );
        let mut load_outside = static_blob.clone();
        load_outside[ELF32_EHDR_LEN + 4..ELF32_EHDR_LEN + 8]
            .copy_from_slice(&(static_blob.len() as u32).to_le_bytes());
        assert_eq!(
            parse_s19k_armhf_elf(&load_outside),
            Err(S19kTmpDeployError::WrongElf)
        );
        let soft = parse_s19k_armhf_elf(&make_elf32_arm(false, None)).unwrap();
        assert_eq!(
            admit_s19k_armhf_musl_static(&soft),
            Err(S19kTmpDeployError::SoftFloat)
        );
        let mut non_eabi5 = static_blob.clone();
        non_eabi5[36..40].copy_from_slice(&EF_ARM_ABI_FLOAT_HARD.to_le_bytes());
        let non_eabi5 = parse_s19k_armhf_elf(&non_eabi5).unwrap();
        assert_eq!(
            admit_s19k_armhf_musl_static(&non_eabi5),
            Err(S19kTmpDeployError::WrongEabi)
        );
        let glibc =
            parse_s19k_armhf_elf(&make_elf32_arm(true, Some(b"/lib/ld-linux-armhf.so.3\0")))
                .unwrap();
        assert_eq!(
            admit_s19k_armhf_musl_static(&glibc),
            Err(S19kTmpDeployError::GlibcInterp)
        );
        let dyn_musl =
            parse_s19k_armhf_elf(&make_elf32_arm(true, Some(b"/lib/ld-musl-armhf.so.1\0")))
                .unwrap();
        assert_eq!(
            admit_s19k_armhf_musl_static(&dyn_musl),
            Err(S19kTmpDeployError::DynamicInterp)
        );
        assert_eq!(s19k_sha256_hex(b""), S19K_SHA256_EMPTY);
        assert_eq!(s19k_sha256_hex(b"abc"), S19K_SHA256_ABC);
        let digest = s19k_sha256_hex(&static_blob);
        assert!(admit_s19k_tmp_deploy_sha256_hex(&digest).is_ok());
        assert!(admit_s19k_tmp_deploy_sha256_hex("dead").is_err());
        let plan = format_s19k_tmp_deploy_launch_plan(
            "/tmp/dcentrald_bench_t1_DRYRUN",
            "am3-s19k",
            false,
            false,
            false,
            false,
            true,
            true,
            None,
            &digest,
            static_blob.len() as u64,
            S19K_SHA256_ABC,
            123,
            S19K_SHA256_EMPTY,
            456,
            S19K_SHA256_ABC,
            789,
            S19K_SHA256_EMPTY,
            987,
            S19K_SHA256_ABC,
            654,
            S19K_SHA256_EMPTY,
            321,
            None,
            S19K_SHA256_ABC,
            None,
        );
        assert!(admit_s19k_tmp_deploy_launch_plan(&plan).is_ok());
        assert!(plan.contains("schema=dcentos.s19k-tmp-deploy/v12"));
        assert!(plan.contains("arm_eabi=5"));
        assert!(plan.contains(&format!("sha256={digest}")));
        assert!(plan.contains(&format!("bytes={}", static_blob.len())));
        assert!(plan.contains("operator_artifact_pin=required-and-matched"));
        assert!(plan.contains(&format!("expected_artifact_sha256={digest}")));
        assert!(plan.contains(&format!("expected_artifact_bytes={}", static_blob.len())));
        let wrong_operator_pin = plan.replace(
            &format!("expected_artifact_sha256={digest}"),
            &format!("expected_artifact_sha256={S19K_SHA256_EMPTY}"),
        );
        assert_eq!(
            admit_s19k_tmp_deploy_launch_plan(&wrong_operator_pin),
            Err(S19kTmpDeployError::HashMismatch)
        );
        assert!(plan.contains("post_scp=sha256sum"));
        assert!(plan.contains("serial_mode_flag=--serial-mining"));
        assert!(plan.contains("explicit_loud_authority=false"));
        assert!(plan.contains("no_work_flag=--s19k-track1-no-work"));
        assert!(plan.contains("bounded_work_proof_flag=--s19k-track1-bounded-work-proof"));
        assert!(plan.contains("work_proof_timeout_s=600"));
        assert!(plan.contains("work_authority=not-applicable"));
        assert!(plan.contains("persistent_mutation=false"));
        assert!(plan.contains("ephemeral_runtime_env=DCENTOS_EPHEMERAL_RUNTIME=1"));
        assert!(plan.contains("runtime_recovery="));
        assert!(plan.contains(
            "handoff_identity=supervisor+child-pid+start+ppid+pgrp+session+comm+exe+argv-sha256"
        ));
        assert!(plan.contains("handoff_watchdog=armed-before-signal"));
        assert!(plan.contains(
            "handoff_signal=j3-ptrace-all-thread-freeze+supervisor-first-sigkill-terminal+child-second-sigkill-terminal+event-drain"
        ));
        assert!(plan.contains("identity_probe="));
        assert!(plan.contains("live_identity_schema=dcentos.s19k-braiins-live-identity/v2"));
        assert!(plan.contains("live_identity_profile_rule=mutually-exclusive-complete-tuple"));
        assert!(plan.contains(
            "live_identity_profile_live88_two_bhb56903_slots_2_3=2xBHB56903@2,3+addr1-undetected-placeholder+eeprom-0x50-absent-0x51-0x52-0511"
        ));
        assert!(plan.contains(
            "live_identity_profile_held78_three_bhb56902_slots_1_2_3=3xBHB56902@1,2,3+eeprom-0x50-0x51-0x52-0511"
        ));
        assert!(plan.contains("live_identity_recheck=pre-handoff+pre-recovery-safeoff"));
        assert!(plan.contains("runtime_receipt_schema=dcentos.s19k-tmp-runtime/v5"));
        assert!(
            plan.contains("runtime_lock=board-global-atomic-mkdir+v6-artifact-bound-owner+typed-pending-retention")
        );
        assert!(plan.contains(&format!("custody_observer_sha256={S19K_SHA256_ABC}")));
        assert!(plan.contains("custody_observer_bytes=789"));
        assert!(plan.contains(&format!("stock_restart_helper_sha256={S19K_SHA256_EMPTY}")));
        assert!(plan.contains("stock_restart_helper_bytes=987"));
        assert!(plan.contains(&format!("endurance_collector_sha256={S19K_SHA256_ABC}")));
        assert!(plan.contains("endurance_collector_bytes=654"));
        assert!(plan.contains(&format!("endurance_verifier_sha256={S19K_SHA256_EMPTY}")));
        assert!(plan.contains("endurance_verifier_bytes=321"));
        assert!(plan.contains("endurance_baseline_sha256=not-applicable"));
        assert!(plan.contains("endurance_baseline_bytes=0"));
        assert!(plan.contains("receipt_clear=checked-safeoff-to-exact-stock-restart-helper-only"));
        assert!(plan.contains("recovery_safeoff_receipt=dcentos.s19k-track1-safeoff/v1"));
        assert!(plan.contains("runtime_log_ring=/tmp/dcent/log"));
        assert!(plan.contains("ssh_host_key_admission=not-applicable-no-contact"));
        assert!(plan.contains("ssh_host_key_sha256=not-supplied"));
        assert!(plan.contains("ssh_global_known_hosts=disabled-on-contact"));
        assert!(!plan.contains("identity_restore="));
        assert!(plan.contains("/run_trial identity "));
        assert!(plan.contains("/run_trial run "));
        assert!(
            plan.contains("/run_trial restore /tmp/dcentrald_bench_t1_DRYRUN am3-s19k recovery ")
        );
        assert!(admit_s19k_tmp_deploy_post_scp(
            &plan,
            &digest,
            static_blob.len() as u64,
            &static_blob,
        )
        .is_ok());
        assert_eq!(
            admit_s19k_tmp_deploy_post_scp(
                &plan,
                S19K_SHA256_EMPTY,
                static_blob.len() as u64,
                &static_blob,
            ),
            Err(S19kTmpDeployError::HashMismatch)
        );
        assert_eq!(
            admit_s19k_tmp_deploy_post_scp(&plan, &digest, 1, &static_blob),
            Err(S19kTmpDeployError::SizeMismatch)
        );
        let swapped = make_elf32_arm(true, Some(b"/lib/ld-linux-armhf.so.3\0"));
        let swapped_plan = format_s19k_tmp_deploy_launch_plan(
            "/tmp/dcentrald_bench_t1_swapped",
            "am3-s19kpro",
            false,
            false,
            false,
            false,
            false,
            true,
            None,
            &s19k_sha256_hex(&swapped),
            swapped.len() as u64,
            S19K_SHA256_ABC,
            123,
            S19K_SHA256_EMPTY,
            456,
            S19K_SHA256_ABC,
            789,
            S19K_SHA256_EMPTY,
            987,
            S19K_SHA256_ABC,
            654,
            S19K_SHA256_EMPTY,
            321,
            None,
            S19K_SHA256_ABC,
            Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        );
        assert_eq!(
            admit_s19k_tmp_deploy_post_scp(
                &swapped_plan,
                &s19k_sha256_hex(&swapped),
                swapped.len() as u64,
                &swapped,
            ),
            Err(S19kTmpDeployError::GlibcInterp)
        );
        let no_work_plan = format_s19k_tmp_deploy_launch_plan(
            "/tmp/dcentrald_bench_t1_no_work",
            "am3-s19k",
            true,
            true,
            false,
            false,
            true,
            true,
            None,
            &digest,
            static_blob.len() as u64,
            S19K_SHA256_ABC,
            123,
            S19K_SHA256_EMPTY,
            456,
            S19K_SHA256_ABC,
            789,
            S19K_SHA256_EMPTY,
            987,
            S19K_SHA256_ABC,
            654,
            S19K_SHA256_EMPTY,
            321,
            None,
            S19K_SHA256_ABC,
            None,
        );
        assert!(admit_s19k_tmp_deploy_launch_plan(&no_work_plan).is_ok());
        assert!(no_work_plan.contains("mode=handoff-no-work"));
        assert!(no_work_plan.contains("explicit_loud_authority=true"));
        assert!(no_work_plan.contains("work_authority=disabled"));
        let bounded_work_plan = format_s19k_tmp_deploy_launch_plan(
            "/tmp/dcentrald_bench_t1_bounded_work",
            "am3-s19k",
            true,
            false,
            true,
            false,
            true,
            true,
            None,
            &digest,
            static_blob.len() as u64,
            S19K_SHA256_ABC,
            123,
            S19K_SHA256_EMPTY,
            456,
            S19K_SHA256_ABC,
            789,
            S19K_SHA256_EMPTY,
            987,
            S19K_SHA256_ABC,
            654,
            S19K_SHA256_EMPTY,
            321,
            None,
            S19K_SHA256_ABC,
            None,
        );
        assert!(admit_s19k_tmp_deploy_launch_plan(&bounded_work_plan).is_ok());
        assert!(bounded_work_plan.contains("mode=bounded-work-proof"));
        assert!(bounded_work_plan.contains("work_authority=bounded-proof"));
        assert!(bounded_work_plan.contains(
            "work_proof_success=accepted-share-per-required-logical-uart+checked-terminal-safeoff"
        ));
        let endurance_work_plan = format_s19k_tmp_deploy_launch_plan(
            "/tmp/dcentrald_bench_t1_endurance",
            "am3-s19k",
            true,
            false,
            false,
            true,
            true,
            true,
            None,
            &digest,
            static_blob.len() as u64,
            S19K_SHA256_ABC,
            123,
            S19K_SHA256_EMPTY,
            456,
            S19K_SHA256_ABC,
            789,
            S19K_SHA256_EMPTY,
            987,
            S19K_SHA256_ABC,
            654,
            S19K_SHA256_EMPTY,
            321,
            Some((S19K_SHA256_ABC, 111)),
            S19K_SHA256_ABC,
            None,
        );
        assert!(admit_s19k_tmp_deploy_launch_plan(&endurance_work_plan).is_ok());
        assert!(endurance_work_plan.contains("mode=endurance-work-proof"));
        assert!(endurance_work_plan.contains("work_authority=endurance-proof"));
        assert!(
            endurance_work_plan.contains(&format!("endurance_baseline_sha256={S19K_SHA256_ABC}"))
        );
        assert!(endurance_work_plan.contains("endurance_baseline_bytes=111"));
        assert!(admit_s19k_tmp_deploy_launch_plan("schema=only").is_err());
        assert!(parse_s19k_tmp_deploy_content_hash("sha256=aa\nbytes=1\n").is_err());
        let duplicate_hash = format!("{plan}sha256={digest}\n");
        assert!(admit_s19k_tmp_deploy_launch_plan(&duplicate_hash).is_err());
        let stale_direct_launch = plan.replace(
            plan.lines().find(|line| line.starts_with("launch=")).unwrap(),
            "launch=/tmp/dcentrald_bench_t1_DRYRUN/dcentrald --config /tmp/dcentrald_bench_t1_DRYRUN/dcentrald_s19k.toml",
        );
        assert!(admit_s19k_tmp_deploy_launch_plan(&stale_direct_launch).is_err());
        let traversal = plan.replace(
            "/tmp/dcentrald_bench_t1_DRYRUN",
            "/tmp/dcentrald_bench_t1_DRYRUN/../../etc",
        );
        assert!(admit_s19k_tmp_deploy_launch_plan(&traversal).is_err());
        let weakened_lock = plan.replace(
            "runtime_lock=board-global-atomic-mkdir+v6-artifact-bound-owner+typed-pending-retention",
            "runtime_lock=best-effort",
        );
        assert!(admit_s19k_tmp_deploy_launch_plan(&weakened_lock).is_err());
        let false_contact = plan
            .replace(
                "ssh_host_key_admission=not-applicable-no-contact",
                "ssh_host_key_admission=exact-operator-pin",
            )
            .replace("dry_run=true", "dry_run=false");
        assert!(admit_s19k_tmp_deploy_launch_plan(&false_contact).is_err());
        let malformed_pin = swapped_plan.replace(
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "SHA256:not-an-openssh-fingerprint",
        );
        assert!(admit_s19k_tmp_deploy_launch_plan(&malformed_pin).is_err());
        let implicit_global = plan.replace(
            "ssh_global_known_hosts=disabled-on-contact",
            "ssh_global_known_hosts=enabled",
        );
        assert!(admit_s19k_tmp_deploy_launch_plan(&implicit_global).is_err());
        assert!(admit_s19k_tmp_deploy_script_musl_static(deploy_sh).is_ok());
        assert!(admit_s19k_tmp_deploy_script_musl_static("ssh_trial").is_err());
        assert!(trial_sh.contains("verify_bound_file \"$TRIAL_BIN\""));
        assert!(trial_sh.contains("verify_bound_file \"$TRIAL_CFG\""));
        assert!(trial_sh.contains("verify_bound_file \"$TRIAL_RUNNER\""));
    }
}

#[cfg(test)]
mod s19k_ephemeral_journal_admission_tests {
    use super::*;

    const TRIAL: &str = "/tmp/dcentrald_bench_t1_20260901133057_320";

    #[test]
    fn every_runner_journal_destination_is_admitted_by_the_daemon_set() {
        let runner = include_str!("../../../scripts/dcentrald_s19k_tmp_remote_run.sh");
        let names = admit_s19k_runner_journal_destinations(runner)
            .expect("runner journal destinations must all be admitted");
        for required in [
            "runtime_install_custody_transcript",
            "runtime_handoff_no_work_transcript",
            "runtime_bounded_work_transcript",
            "runtime_endurance_work_receipt",
            "runtime_endurance_failure_receipt",
            "runtime_safeoff_terminal_receipt",
            "runtime_startup_prefix_pre_safeoff",
        ] {
            assert!(names.iter().any(|name| name == required), "{required}");
        }
        let publications = s19k_runner_journal_publications(runner).unwrap();
        assert!(publications
            .iter()
            .any(|(_, destination)| destination == "RUNTIME_LOCK_OWNER"));
        assert!(publications
            .iter()
            .any(|(_, destination)| destination == "ENDURANCE_ACK"));
    }

    #[test]
    fn runner_contract_fails_when_a_receipt_name_leaves_the_daemon_set() {
        let runner = include_str!("../../../scripts/dcentrald_s19k_tmp_remote_run.sh");
        let mutated = runner.replace(
            "BOUNDED_TRANSCRIPT_RECEIPT=\"$TRIAL_DIR/runtime_bounded_work_transcript\"",
            "BOUNDED_TRANSCRIPT_RECEIPT=\"$TRIAL_DIR/runtime_bounded_work_transcript_v2\"",
        );
        assert_ne!(mutated, runner);
        assert_eq!(
            admit_s19k_runner_journal_destinations(&mutated),
            Err("Track-1 runner publishes a journal destination the daemon publisher does not admit")
        );
        assert!(admit_s19k_tmp_remote_runner_ephemeral(&mutated).is_err());
        let relocated = runner.replace(
            "ENDURANCE_ACK_DIR=\"$ENDURANCE_EVIDENCE_DIR/acks\"",
            "ENDURANCE_ACK_DIR=\"$TRIAL_DIR/acks\"",
        );
        assert!(admit_s19k_runner_journal_destinations(&relocated).is_err());
    }

    #[test]
    fn classifier_admits_exactly_the_three_publication_forms() {
        for name in S19K_EPHEMERAL_JOURNAL_TRIAL_DESTINATIONS {
            assert_eq!(
                classify_s19k_ephemeral_journal_destination(
                    &format!("{TRIAL}/.{name}.tmp.32685.350473"),
                    &format!("{TRIAL}/{name}"),
                ),
                Ok(S19kEphemeralJournalDestination::TrialJournal),
                "{name}"
            );
        }
        assert_eq!(
            classify_s19k_ephemeral_journal_destination(
                &format!("{TRIAL}/.runtime_lock_owner.tmp.1.2"),
                "/tmp/dcent-s19k-track1-runtime-lock/owner",
            ),
            Ok(S19kEphemeralJournalDestination::GlobalOwner)
        );
        assert_eq!(
            classify_s19k_ephemeral_journal_destination(
                &format!("{TRIAL}/endurance_evidence/acks/.ack.7.tmp.32685.350473"),
                &format!("{TRIAL}/endurance_evidence/acks/ack.000007.kv"),
            ),
            Ok(S19kEphemeralJournalDestination::EnduranceAck)
        );
    }

    #[test]
    fn classifier_refuses_the_2026_09_01_shape_and_its_neighbours() {
        let refusals = [
            // A name outside the set (the pre-fix failure shape).
            (
                format!("{TRIAL}/.runtime_bounded_work_transcript.tmp.1.2"),
                format!("{TRIAL}/runtime_bounded_work_transcript.sealed"),
            ),
            // Cross-trial publication.
            (
                format!("{TRIAL}/.runtime_bounded_work_transcript.tmp.1.2"),
                "/tmp/dcentrald_bench_t1_other/runtime_bounded_work_transcript".to_string(),
            ),
            // Ack destination from the trial root, or a trial journal from the ack dir.
            (
                format!("{TRIAL}/.ack.7.tmp.1.2"),
                format!("{TRIAL}/ack.000007.kv"),
            ),
            (
                format!("{TRIAL}/endurance_evidence/acks/.runtime_bounded_work_transcript.tmp.1.2"),
                format!("{TRIAL}/endurance_evidence/acks/runtime_bounded_work_transcript"),
            ),
            // Malformed ack names and scratch prefixes.
            (
                format!("{TRIAL}/endurance_evidence/acks/.ack.7.tmp.1.2"),
                format!("{TRIAL}/endurance_evidence/acks/ack.7.kv"),
            ),
            (
                format!("{TRIAL}/endurance_evidence/acks/segment.000007.kv"),
                format!("{TRIAL}/endurance_evidence/acks/ack.000007.kv"),
            ),
            // Global owner from the ack dir or under another name.
            (
                format!("{TRIAL}/endurance_evidence/acks/.ack.7.tmp.1.2"),
                "/tmp/dcent-s19k-track1-runtime-lock/owner".to_string(),
            ),
            (
                format!("{TRIAL}/.runtime_lock_owner.tmp.1.2"),
                "/tmp/dcent-s19k-track1-runtime-lock/owner2".to_string(),
            ),
        ];
        for (source, destination) in refusals {
            assert_eq!(
                classify_s19k_ephemeral_journal_destination(&source, &destination),
                Err(S19K_EPHEMERAL_JOURNAL_REFUSAL),
                "{source} -> {destination}"
            );
        }
        for (source, destination) in [
            (
                "/tmp/dcentrald_bench_t1_x/../y/.a.tmp",
                "/tmp/dcentrald_bench_t1_x/runtime_startup_release",
            ),
            (
                "/tmp/other_t1_x/.a.tmp",
                "/tmp/other_t1_x/runtime_startup_release",
            ),
            (
                "/tmp/dcentrald_bench_t1_x/sub/.a.tmp",
                "/tmp/dcentrald_bench_t1_x/sub/runtime_startup_release",
            ),
            (
                "tmp/dcentrald_bench_t1_x/.a.tmp",
                "/tmp/dcentrald_bench_t1_x/runtime_startup_release",
            ),
        ] {
            assert!(
                classify_s19k_ephemeral_journal_destination(source, destination).is_err(),
                "{source} -> {destination}"
            );
        }
    }
}
