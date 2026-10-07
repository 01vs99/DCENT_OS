//! S19k Amlogic persistent-install **architecture** (host-testable).
//!
//! Does not flash, SSH, or claim CLEAR_FOR_FLASH. Encodes the NAND
//! geometry already used by `install_amlogic_persistent.sh` +
//! `am3-s19kpro/README.md` and the SKU-scoped GPIO437 SafeOff polarity
//! (T6: am3-s19k SafeOff = 1).

use crate::s19k_am3_gpio437::{
    am3_s19k_install_safe_off_value, refuse_re4c_safe_off_as_am3_s19k_cut,
};

/// FLASH is still NOT_YET. This module is architecture + safety pins.
pub const CLEAR_FOR_FLASH: bool = false;

/// Single refuse-until-cleared gate for AML persistent-install / backup /
/// rollback / rescue. Backup and plans may admit. Execute is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kAmlMutationIntent {
    BackupOnly,
    RestorePlan,
    RestoreExecute,
    RollbackPlan,
    RollbackExecute,
    RescueConsole,
    SysupgradeExecute,
}

pub fn admit_s19k_aml_mutation(intent: S19kAmlMutationIntent) -> Result<(), &'static str> {
    match intent {
        S19kAmlMutationIntent::BackupOnly
        | S19kAmlMutationIntent::RestorePlan
        | S19kAmlMutationIntent::RollbackPlan
        | S19kAmlMutationIntent::RescueConsole => Ok(()),
        S19kAmlMutationIntent::RestoreExecute
        | S19kAmlMutationIntent::RollbackExecute
        | S19kAmlMutationIntent::SysupgradeExecute => {
            if CLEAR_FOR_FLASH {
                Ok(())
            } else {
                Err("AML execute stays CLEAR_FOR_FLASH=false; refuse nandwrite/gpio437/fw_setenv")
            }
        }
    }
}

/// live436 leftover-admitted Chain Inactive is UART CMD=3 on `/tmp`.
/// It is not a NAND/GPIO437 grant. FLASH stays false.
pub fn refuse_s19k_leftover_admitted_inactive_as_flash_grant() -> Result<(), &'static str> {
    if CLEAR_FOR_FLASH {
        return Err("CLEAR_FOR_FLASH must stay false during leftover-admitted UART soaks");
    }
    match admit_s19k_aml_mutation(S19kAmlMutationIntent::SysupgradeExecute) {
        Err(_) => {}
        Ok(()) => return Err("sysupgrade execute must stay refused while leftover-admit soaks"),
    }
    match admit_s19k_aml_mutation(S19kAmlMutationIntent::RestoreExecute) {
        Err(_) => {}
        Ok(()) => return Err("restore execute must stay refused while leftover-admit soaks"),
    }
    if !crate::s19k_braiins_job::s19k_leftover_hit_admits_experimental_inactive(
        crate::s19k_braiins_job::S19K_LIVE436_WRAP_RETIRE_LEFTOVER_HIT,
        crate::s19k_braiins_job::S19K_LIVE436_WRAP_RETIRE_LEFTOVER_HEADER,
        crate::s19k_braiins_job::S19K_LIVE436_WRAP_RETIRE_MEETS,
    ) {
        return Err("live436 wrap-retire leftover still admits UART inactive only");
    }
    Err("leftover-admitted Chain Inactive is UART CMD=3; CLEAR_FOR_FLASH stays false")
}

pub fn refuse_s19k_backup_as_nandwrite_grant() -> Result<(), &'static str> {
    if admit_s19k_aml_mutation(S19kAmlMutationIntent::BackupOnly).is_err() {
        return Err("backup-only must admit while FLASH is false");
    }
    match admit_s19k_aml_mutation(S19kAmlMutationIntent::SysupgradeExecute) {
        Err(_) => Err("backup-only is not a nandwrite grant; CLEAR_FOR_FLASH=false"),
        Ok(()) => Err("sysupgrade execute must stay refused while FLASH is false"),
    }
}

/// Installer artifact names map onto the single refuse-until-cleared gate.
pub fn s19k_aml_intent_from_artifact(name: &str) -> Option<S19kAmlMutationIntent> {
    match name {
        "BACKUP_LEDGER.txt" | "BACKUP-ONLY" => Some(S19kAmlMutationIntent::BackupOnly),
        "RECOVER_TO_STOCK_PLAN.txt" => Some(S19kAmlMutationIntent::RollbackPlan),
        "RECOVER_EXECUTE_REFUSE.txt" | "RECOVER_EXECUTE" => {
            Some(S19kAmlMutationIntent::RollbackExecute)
        }
        "RESCUE_CONSOLE.txt" => Some(S19kAmlMutationIntent::RescueConsole),
        "sysupgrade-am3-s19k.tar" => Some(S19kAmlMutationIntent::SysupgradeExecute),
        _ => None,
    }
}

pub fn admit_s19k_aml_artifact(name: &str) -> Result<(), &'static str> {
    let intent = s19k_aml_intent_from_artifact(name).ok_or("unknown AML artifact")?;
    admit_s19k_aml_mutation(intent)
}

pub fn refuse_s19k_rescue_console_as_nandwrite_grant() -> Result<(), &'static str> {
    if admit_s19k_aml_mutation(S19kAmlMutationIntent::RescueConsole).is_err() {
        return Err("rescue console must admit while FLASH is false");
    }
    match admit_s19k_aml_mutation(S19kAmlMutationIntent::SysupgradeExecute) {
        Err(_) => Err("rescue console is not a nandwrite grant; CLEAR_FOR_FLASH=false"),
        Ok(()) => Err("sysupgrade execute must stay refused while FLASH is false"),
    }
}

pub fn refuse_s19k_rollback_plan_as_execute_grant() -> Result<(), &'static str> {
    if admit_s19k_aml_artifact("RECOVER_TO_STOCK_PLAN.txt").is_err() {
        return Err("recover-to-stock plan must admit while FLASH is false");
    }
    match admit_s19k_aml_artifact("RECOVER_EXECUTE_REFUSE.txt") {
        Err(_) => Ok(()),
        Ok(()) => Err("recover execute must stay refused while FLASH is false"),
    }
}

/// recover_amlogic_to_stock.sh must refuse FLASH before GPIO/NAND.
pub fn admit_s19k_recover_script_refuses_execute_before_gpio(
    script: &str,
) -> Result<(), &'static str> {
    if !script.contains("CLEAR_FOR_FLASH=false — refusing gpio437 SafeOff/flash_erase/nandwrite")
    {
        return Err("recover execute must refuse CLEAR_FOR_FLASH before GPIO/NAND");
    }
    let refuse = script
        .find("CLEAR_FOR_FLASH=false — refusing gpio437 SafeOff/flash_erase/nandwrite")
        .ok_or("missing recover FLASH refuse")?;
    let gpio = script
        .find("gpio437 SafeOff (am3-s19k-active-low, value=1)")
        .ok_or("missing recover gpio SafeOff")?;
    if refuse > gpio {
        return Err("recover FLASH refuse must precede GPIO SafeOff");
    }
    Ok(())
}

/// Braiins `/tmp` is a 70 MiB tmpfs. live426 died after three 23 MiB
/// `dcentrald` copies filled it (`df` Available=0; live427 `cp` truncated
/// to 4096 B). Hardlink the binary; refuse a new copy unless log reserve fits.
pub const S19K_TRACK1_TMPFS_LOG_RESERVE_BYTES: u64 = 8 * 1024 * 1024;
pub const S19K_LIVE426_TMPFS_AVAIL_BYTES: u64 = 0;
pub const S19K_LIVE425_DCENTRALD_BYTES: u64 = 23_419_988;

/// `extra_copy` is a second inode (cp). Hardlink (`ln`) is `extra_copy=false`.
pub fn s19k_track1_tmpfs_stage_allowed(
    avail_bytes: u64,
    binary_bytes: u64,
    extra_copy: bool,
) -> bool {
    let need = if extra_copy {
        binary_bytes.saturating_add(S19K_TRACK1_TMPFS_LOG_RESERVE_BYTES)
    } else {
        S19K_TRACK1_TMPFS_LOG_RESERVE_BYTES
    };
    avail_bytes >= need
}

pub fn refuse_s19k_live426_enospc_as_chain_inactive_result() -> Result<(), &'static str> {
    if s19k_track1_tmpfs_stage_allowed(
        S19K_LIVE426_TMPFS_AVAIL_BYTES,
        S19K_LIVE425_DCENTRALD_BYTES,
        true,
    ) {
        return Err("live426 /tmp Available=0 must refuse another dcentrald copy");
    }
    Err("live426 ENOSPC is not a Chain Inactive leftover result")
}

/// live427: 620 s ended with 0 mid-run cleans (ckpool / Bitcoin ~10 min).
/// Stop after the first mid-run clean has been observed for
/// `S19K_TRACK1_SOAK_MIN_POST_CLEAN_S`, or at `S19K_TRACK1_SOAK_MAX_S`.
pub const S19K_TRACK1_SOAK_MAX_S: u64 = 1500;
pub const S19K_TRACK1_SOAK_MIN_POST_CLEAN_S: u64 = 180;
pub const S19K_LIVE427_SOAK_S: u64 = 620;

/// live430: MULTI died ~T+130 (wrap-4) with gpio437=0; leftover cannot
/// be measured after one wrap of silence. Stop instead of waiting 1500 s.
pub const S19K_TRACK1_SOAK_RX_DEAD_S: u64 = 90;
/// live431 stopped at T+220 after 180 s post-clean while wrap-6 RX was
/// still live (S1 last T+200.4). leftover_hit is already measured; keep
/// going until wrap-7 and T+600, or RX death.
pub const S19K_TRACK1_SOAK_T600_S: u64 = 600;
pub const S19K_TRACK1_SOAK_WRAP7: u64 = 7;
pub const S19K_LIVE431_SOAK_STOP_S: u64 = 220;
pub const S19K_LIVE431_WRAP_AT_STOP: u64 = 6;

/// A bounded Track-1 bench run can finish normally for one of two fixed
/// evidence reasons.  These are deliberately not production endurance stop
/// conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kTrack1BenchCompletion {
    /// At least seven UART-RX wraps were observed and the run reached T+600.
    T600Wrap7,
    /// The fixed 1,500-second bench deadline was reached.
    Max1500,
}

/// Typed Track-1 liveness decision.  `RxDead` is a safety failure in both
/// bench and production modes; `BenchComplete` is reachable only under
/// explicit bounded-bench authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kTrack1SoakDecision {
    Continue,
    RxDead,
    BenchComplete(S19kTrack1BenchCompletion),
}

pub fn s19k_track1_soak_rx_dead(nonce_silent_s: u64) -> bool {
    nonce_silent_s >= S19K_TRACK1_SOAK_RX_DEAD_S
}

/// live432: 5 s alive tick printed silent=88 then 93 — never `=90`.
/// live433: tracing ANSI sits between `nonce_silent_s` and `=`, so
/// `nonce_silent_s=204` never appears as a contiguous token.
pub fn s19k_strip_ansi(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'm' {
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

pub fn s19k_track1_parse_nonce_silent_s(line: &str) -> Option<u64> {
    let stripped = s19k_strip_ansi(line);
    let idx = stripped.find("nonce_silent_s")?;
    let after = &stripped[idx + "nonce_silent_s".len()..];
    let eq = after.find('=')?;
    let digits: String = after[eq + 1..]
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// Launch must treat any `nonce_silent_s>=90` as rx_dead, including
/// ANSI-split structured fields (live433 soak missed silent=204).
pub fn s19k_track1_alive_line_rx_dead(line: &str) -> bool {
    s19k_track1_parse_nonce_silent_s(line)
        .map(s19k_track1_soak_rx_dead)
        .unwrap_or(false)
}

pub fn admit_s19k_track1_launch_rx_dead_is_ge_90(src: &str) -> Result<(), &'static str> {
    let active = src
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    if active.contains("nonce_silent_s=90") && !active.contains("nonce_silent_s=(9[0-9]") {
        return Err("exact nonce_silent_s=90 misses 5s ticks (live432 88 then 93)");
    }
    if !src.contains("nonce_silent_s=(9[0-9]") && !src.contains("nonce_silent_s.{0,40}") {
        return Err("launch must grep nonce_silent_s>=90 (9x or 100+)");
    }
    Ok(())
}

/// live433 soak grepped contiguous `nonce_silent_s=` while tracing
/// inserted ANSI. Next launch must disable color or allow 40 chars.
pub fn admit_s19k_track1_launch_rx_dead_ignores_ansi(src: &str) -> Result<(), &'static str> {
    let active = src
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    if active.contains("RUST_LOG_STYLE=never") || active.contains("nonce_silent_s.{0,40}") {
        return Ok(());
    }
    Err("launch must set RUST_LOG_STYLE=never or grep nonce_silent_s with ANSI gap (live433)")
}

/// live435: `RUST_LOG_STYLE=never` was exported but `init_logging` built
/// a custom fmt subscriber that never called `with_ansi`, so run.log
/// still split `nonce_silent_s` from `=`. Honor the env.
pub fn s19k_track1_tracing_ansi_enabled(raw: Option<&str>) -> bool {
    raw != Some("never")
}

pub fn admit_s19k_production_honors_rust_log_style_never(src: &str) -> Result<(), &'static str> {
    if !src.contains("s19k_track1_tracing_ansi_enabled") {
        return Err("init_logging must honor RUST_LOG_STYLE=never (live433/435 ANSI split)");
    }
    if !src.contains("with_ansi(") {
        return Err("init_logging must set with_ansi from RUST_LOG_STYLE");
    }
    Ok(())
}

/// Legacy bounded-bench predicate retained while launch/runtime callers move
/// to [`s19k_track1_soak_decision`].  It always supplies bounded-bench
/// authority and therefore must not be used by the production endurance loop.
pub fn s19k_track1_soak_should_stop(
    elapsed_s: u64,
    midrun_cleans: u64,
    post_clean_elapsed_s: u64,
    nonce_silent_s: u64,
    wrap_rx: u64,
) -> bool {
    let _ = (midrun_cleans, post_clean_elapsed_s);
    !matches!(
        s19k_track1_soak_decision(elapsed_s, nonce_silent_s, wrap_rx, true),
        S19kTrack1SoakDecision::Continue
    )
}

/// Classify Track-1 liveness without conflating a healthy bounded bench
/// completion with RX death.  Production endurance passes
/// `bounded_bench_authority=false`, so the fixed T+600/T+1500 caps cannot
/// terminate an otherwise healthy run.  The 90-second RX-death fence always
/// applies and has precedence over every bench completion condition.
pub fn s19k_track1_soak_decision(
    elapsed_s: u64,
    nonce_silent_s: u64,
    wrap_rx: u64,
    bounded_bench_authority: bool,
) -> S19kTrack1SoakDecision {
    if s19k_track1_soak_rx_dead(nonce_silent_s) {
        return S19kTrack1SoakDecision::RxDead;
    }
    if !bounded_bench_authority {
        return S19kTrack1SoakDecision::Continue;
    }
    // wrap_rx = wrap at last UART RX. live432 wrap_idx=9 after MULTI
    // death is TX-only and must not satisfy wrap-7 + T+600.
    if elapsed_s >= S19K_TRACK1_SOAK_T600_S && wrap_rx >= S19K_TRACK1_SOAK_WRAP7 {
        return S19kTrack1SoakDecision::BenchComplete(S19kTrack1BenchCompletion::T600Wrap7);
    }
    if elapsed_s >= S19K_TRACK1_SOAK_MAX_S {
        return S19kTrack1SoakDecision::BenchComplete(S19kTrack1BenchCompletion::Max1500);
    }
    S19kTrack1SoakDecision::Continue
}

pub fn s19k_track1_parse_wrap_rx(line: &str) -> Option<u64> {
    let stripped = s19k_strip_ansi(line);
    let idx = stripped.find("wrap_rx")?;
    let after = &stripped[idx + "wrap_rx".len()..];
    let eq = after.find('=')?;
    let digits: String = after[eq + 1..]
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

pub fn s19k_track1_alive_line_wrap7(line: &str) -> bool {
    s19k_track1_parse_wrap_rx(line)
        .map(|n| n >= S19K_TRACK1_SOAK_WRAP7)
        .unwrap_or(false)
}

/// live432 TX wrap_idx climbed to 9 after last RX wrap_rx=5. T+600 +
/// wrap_idx=7+ is not wrap-7 dual-port RX.
pub fn admit_s19k_live432_tx_wrap_does_not_stop_wrap7_t600() -> Result<(), &'static str> {
    if s19k_track1_soak_should_stop(S19K_TRACK1_SOAK_T600_S, 1, 180, 50, 5) {
        return Err("live432 wrap_rx=5 at T+600 must not stop as wrap-7");
    }
    if !s19k_track1_soak_should_stop(S19K_TRACK1_SOAK_T600_S, 1, 180, 50, 7) {
        return Err("wrap_rx=7 at T+600 must stop");
    }
    if s19k_track1_soak_should_stop(599, 1, 180, 50, 7) {
        return Err("wrap_rx=7 before T+600 must not stop");
    }
    if s19k_track1_alive_line_wrap7("wrap_idx=9 wrap_rx=5") {
        return Err("wrap_idx=9 must not count as wrap-7 RX");
    }
    if !s19k_track1_alive_line_wrap7("wrap_idx=9 wrap_rx=7") {
        return Err("wrap_rx=7 must count as wrap-7 RX");
    }
    Ok(())
}

pub fn refuse_s19k_live431_220s_as_wrap7_t600() -> Result<(), &'static str> {
    Err("live431 stopped at T+220 wrap-6 after 180 s post-clean; RX was still live; not wrap-7/T+600")
}

/// Track-1 restore starts S99bosminer. It must never write GPIO437.
pub fn admit_s19k_track1_restore_never_writes_gpio437(script: &str) -> Result<(), &'static str> {
    let active = script
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    if active.contains("echo 1 > /sys/class/gpio/gpio437/value")
        || active.contains("echo 0 > /sys/class/gpio/gpio437/value")
    {
        return Err("Track-1 restore must not write GPIO437");
    }
    if !script.contains("S99bosminer start") {
        return Err("Track-1 restore must start S99bosminer");
    }
    Ok(())
}

/// live427 MULTI died T+188 with no mid-run clean. The 5 s alive line must
/// print GPIO437 so a rail drop is not mistaken for wrap-barrier death.
pub fn s19k_track1_alive_gpio437_field(value: Option<u8>) -> &'static str {
    match value {
        Some(0) => "0",
        Some(1) => "1",
        _ => "unread",
    }
}

/// live429: live428 `launch.sh` `kill $(pidof dcentrald)` sent SIGTERM at
/// T+9s when the 1500 s window (14:50) ended. A soak may kill only the
/// pid it wrote to `dcentrald.pid`.
pub const S19K_LIVE429_SIGTERM_S: u64 = 9;

pub fn s19k_track1_launch_may_kill(owned_pid: u32, candidate_pid: u32) -> bool {
    owned_pid != 0 && owned_pid == candidate_pid
}

pub fn admit_s19k_track1_launch_kills_owned_pid_only(src: &str) -> Result<(), &'static str> {
    let active = src
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    if active.contains("kill $(pidof dcentrald)") || active.contains("kill -9 $(pidof dcentrald)") {
        return Err("soak launch must not kill pidof dcentrald (live429 T+9 SIGTERM)");
    }
    if !src.contains("dcentrald.pid") {
        return Err("soak launch must record the owned dcentrald.pid");
    }
    if !active.contains("kill \"$OWNED\"") && !active.contains("kill \"$owned\"") {
        return Err("soak launch must kill only the owned pid");
    }
    Ok(())
}

pub fn refuse_s19k_live429_sigterm_as_leftover_or_wrap() -> Result<(), &'static str> {
    Err("live429 SIGTERM at T+9s is a foreign launch.sh pidof kill, not leftover/wrap")
}

/// Live `/etc/dcentos/board_target` values this SKU must treat as S19k.
/// Persistent overlay writes `am3-s19k` (sysupgrade prefix brick-rule).
/// `am3-s19kpro` is the extra HAL/S37 SafeOff admit. `am3-aml-s19kpro` is
/// Toolbox family / thermal / `/tmp` stamp — **not** S21 polarity.
pub const S19K_LIVE_IDENTITY_ALIASES: &[&str] = &["am3-s19k", "am3-s19kpro", "am3-aml-s19kpro"];

/// Shared admit so GPIO437 SafeOff cannot drift off the alias table.
pub fn s19k_board_target_is_live_alias(name: &str) -> bool {
    S19K_LIVE_IDENTITY_ALIASES.contains(&name.trim())
}

pub const ROOTFS_MTD: &str = "/dev/mtd5";
/// Local ramdisk window = `nandrootfs − physical mtd5`. `a lab unit` dmesg
/// `system @ 0x06700000` → `0x0B800000-0x06700000=0x05100000`.
pub const ROOTFS_OFFSET_HEX: &str = "0x05100000";
pub const ROOTFS_WINDOW_HEX: &str = "0x02800000";
pub const ROOTFS_ERASE_COUNT: u32 = 320;
pub const ROOTFS_ERASESIZE: u32 = 131_072;
/// Local recovery flag = `nandrecovery_flag_offset − physical mtd5`.
/// `a lab unit`: `0x0B400000-0x06700000=0x04D00000`.
pub const RECOVERY_FLAG_OFFSET_HEX: &str = "0x04D00000";
pub const NAND_ENV_DEV: &str = "/dev/nand_env";

/// U-Boot `nandrecovery_flag_offset` on .78 (`nand_env.bin`).
pub const RECOVERY_FLAG_GLOBAL: u64 = 0x0B40_0000;
/// U-Boot `nandrootfs` on .78. Local = global − observed mtd5 base.
pub const NANDROOTFS_GLOBAL: u64 = 0x0B80_0000;
/// `system.sh` `DCENTOS_OFFSET_FROM_END_MTD0_TO_MTD1`. Live `a lab unit` dmesg:
/// bootloader ends `0x200000`, tpl starts `0x800000`.
pub const OFFSET_FROM_END_MTD0_TO_MTD1: u64 = 0x60_0000;
/// Naive ∑(mtd0..mtd4 sizes) on `a lab unit`. **Not** the physical mtd5 start —
/// it omits the 6 MiB hole. Refuse as a nandwrite base.
pub const S19K_78_MTD5_SIZE_SUM: u64 = 0x0610_0000;
/// Live `a lab unit` dmesg `system` partition start (`0x06700000-0x10000000`).
pub const S19K_78_MTD5_BASE: u64 = 0x0670_0000;
/// U-Boot `nandrecovery_env_offset`. Local = global − physical mtd5.
pub const NANDRECOVERY_ENV_GLOBAL: u64 = 0x0B00_0000;
pub const NANDRECOVERY_ENV_LEN: u64 = 0x1_0000;
/// `a lab unit` `/proc/mtd` `system` size.
pub const S19K_78_MTD5_LEN: u64 = 0x0990_0000;
pub const RECOVERY_FLAG_INSTALLED: u8 = 0x01;
pub const RECOVERY_FLAG_FIRST_BOOT: u8 = 0x02;
pub const RECOVERY_FLAG_SUCCESSFUL: u8 = 0x03;

/// Local flag = global − **physical** mtd5 start. `a lab unit` dmesg:
/// `0x0B400000-0x06700000=0x04D00000`. Size-sum `0x06100000` is refused.
pub fn recovery_flag_local_offset(mtd5_base: u64) -> Option<u64> {
    if mtd5_base == 0 || mtd5_base > RECOVERY_FLAG_GLOBAL {
        return None;
    }
    Some(RECOVERY_FLAG_GLOBAL - mtd5_base)
}

/// Local nandrecovery_env = global − physical mtd5. `a lab unit`: `0x04900000`.
pub fn nandrecovery_env_local_offset(mtd5_base: u64) -> Option<u64> {
    if mtd5_base == 0 || mtd5_base > NANDRECOVERY_ENV_GLOBAL {
        return None;
    }
    Some(NANDRECOVERY_ENV_GLOBAL - mtd5_base)
}

/// Full mtd5 nanddump covers U-Boot `nandrecovery_env` and the flag byte.
pub fn admit_s19k_mtd5_backup_covers_recovery(
    mtd5_len: u64,
    mtd5_base: u64,
) -> Result<(), &'static str> {
    let flag = recovery_flag_local_offset(mtd5_base).ok_or("cannot compute recovery-flag local")?;
    let env =
        nandrecovery_env_local_offset(mtd5_base).ok_or("cannot compute nandrecovery_env local")?;
    if mtd5_len <= flag {
        return Err("mtd5 backup shorter than recovery-flag local");
    }
    if mtd5_len < env + NANDRECOVERY_ENV_LEN {
        return Err("mtd5 backup shorter than nandrecovery_env window");
    }
    Ok(())
}

/// Index helper: read one byte at a local mtd5 offset (fixture-sized).
pub fn read_s19k_mtd5_backup_byte(mtd5: &[u8], local: u64) -> Result<u8, &'static str> {
    mtd5.get(local as usize)
        .copied()
        .ok_or("local offset past mtd5 backup")
}

/// `/dev/nand_env` backup is not the U-Boot `nandrecovery_env` blob.
pub fn refuse_nand_env_bak_as_nandrecovery_env() -> Result<(), &'static str> {
    Err(
        "nand_env.bak is /dev/nand_env; recover_to_stock imports nandrecovery_env at mtd5 local 0x04900000",
    )
}

/// `a lab unit` local offset of U-Boot `nandrecovery_env` inside physical mtd5.
pub const S19K_78_NANDRECOVERY_ENV_LOCAL: u64 = 0x0490_0000;
/// Sidecar name for the sliced recover_env import blob.
pub const S19K_BACKUP_NANDRECOVERY_ENV_NAME: &str = "nandrecovery_env.bin";

/// Slice `nandrecovery_env` out of a full mtd5 nanddump. Host-side, no NAND write.
pub fn extract_s19k_nandrecovery_env_from_mtd5_backup(
    mtd5: &[u8],
    mtd5_base: u64,
) -> Result<&[u8], &'static str> {
    admit_s19k_physical_mtd5_base(mtd5_base)?;
    let local =
        nandrecovery_env_local_offset(mtd5_base).ok_or("cannot compute nandrecovery_env local")?;
    if (mtd5.len() as u64) < local + NANDRECOVERY_ENV_LEN {
        return Err("mtd5 backup shorter than nandrecovery_env window");
    }
    let start = local as usize;
    let end = start + NANDRECOVERY_ENV_LEN as usize;
    mtd5.get(start..end)
        .ok_or("mtd5 backup shorter than nandrecovery_env window")
}

/// Sidecar name for the sliced 128 KiB recovery-flag eraseblock.
pub const S19K_BACKUP_RECOVERY_FLAG_EB_NAME: &str = "recovery_flag_eb.bin";

/// Slice the 128 KiB recovery-flag eraseblock out of a full mtd5 nanddump.
/// Host-side, no NAND write. `a lab unit` start is local `0x04D00000`.
pub fn extract_s19k_recovery_flag_eraseblock_from_mtd5_backup(
    mtd5: &[u8],
    mtd5_base: u64,
) -> Result<&[u8], &'static str> {
    admit_s19k_physical_mtd5_base(mtd5_base)?;
    let local =
        recovery_flag_local_offset(mtd5_base).ok_or("cannot compute recovery-flag local")?;
    let eb = plan_s19k_recovery_flag_eraseblock(local)
        .map_err(|_| "cannot plan recovery-flag eraseblock")?;
    let start = eb.eraseblock_start as usize;
    let end = start
        .checked_add(ROOTFS_ERASESIZE as usize)
        .ok_or("recovery-flag eraseblock overflow")?;
    if mtd5.len() < end {
        return Err("mtd5 backup shorter than recovery-flag eraseblock");
    }
    mtd5.get(start..end)
        .ok_or("mtd5 backup shorter than recovery-flag eraseblock")
}

/// Admit a sliced recover_env blob: 64 KiB, CRC-valid, at least one var.
pub fn admit_s19k_nandrecovery_env_slice(
    slice: &[u8],
) -> Result<crate::s19k_nand_env::S19kNandEnv, &'static str> {
    if slice.len() != crate::s19k_nand_env::S19K_NAND_ENV_LEN {
        return Err("nandrecovery_env slice must be 65536 bytes");
    }
    let env = crate::s19k_nand_env::parse_s19k_nand_env(slice)?;
    if !env.crc_ok {
        return Err("nandrecovery_env CRC32 mismatch");
    }
    Ok(env)
}

/// `recover_env` imports the mtd5 sidecar, never `/dev/nand_env`.
pub fn refuse_s19k_nand_env_bak_as_recover_env_import(
    source_name: &str,
) -> Result<(), &'static str> {
    match source_name {
        "nand_env.bak" | "nand_env.bin" => {
            Err("nand_env.bak/bin is /dev/nand_env; recover_env imports nandrecovery_env.bin")
        }
        S19K_BACKUP_NANDRECOVERY_ENV_NAME => Ok(()),
        _ => Err("unknown recover_env source name"),
    }
}

/// Recoverability certificate for a staged `--artifact-dir`.
/// Stricter than [`admit_s19k_backup_filenames`]: CRC-admits both
/// `/dev/nand_env` and `nandrecovery_env.bin`, refuses using
/// `nand_env.bak` as recover import, and emits a plan + refuse ledger.
/// FLASH stays NOT_YET.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kBackupArtifactAdmit {
    pub nand_env_crc_ok: bool,
    pub nandrecovery_env_crc_ok: bool,
    pub recovery_flag_byte: Option<u8>,
    pub recover_plan: String,
    pub recover_refuse: String,
}

/// Recoverability-complete artifact-dir must name the sidecar.
pub fn admit_s19k_backup_requires_nandrecovery_sidecar(names: &[&str]) -> Result<(), &'static str> {
    if !names
        .iter()
        .any(|n| *n == S19K_BACKUP_NANDRECOVERY_ENV_NAME)
    {
        return Err("artifact-dir missing nandrecovery_env.bin sidecar");
    }
    Ok(())
}

/// CRC + recover-plan admit for a staged backup dir. Host-side, no NAND write.
pub fn admit_s19k_backup_artifact_dir(
    names: &[&str],
    nand_env: &[u8],
    nandrecovery_env: &[u8],
    mtd5: &[u8],
    mtd5_base: u64,
) -> Result<S19kBackupArtifactAdmit, &'static str> {
    if CLEAR_FOR_FLASH {
        return Err("CLEAR_FOR_FLASH must stay false");
    }
    admit_s19k_backup_requires_nandrecovery_sidecar(names)?;
    admit_s19k_backup_filenames(names).map_err(|_| "artifact-dir missing nand_env/mtd5/gpio437")?;
    refuse_s19k_nand_env_bak_as_recover_env_import(S19K_BACKUP_NANDRECOVERY_ENV_NAME)?;
    if nand_env.len() != NAND_ENV_BACKUP_LEN {
        return Err("nand_env.bak/bin must be 65536 bytes");
    }
    let nand_parsed = crate::s19k_nand_env::parse_s19k_nand_env(nand_env)?;
    if !nand_parsed.crc_ok {
        return Err("nand_env CRC32 mismatch");
    }
    let rec_env = admit_s19k_nandrecovery_env_slice(nandrecovery_env)?;
    if let Some(env_local) = nandrecovery_env_local_offset(mtd5_base) {
        if (mtd5.len() as u64) >= env_local + NANDRECOVERY_ENV_LEN {
            let sliced = extract_s19k_nandrecovery_env_from_mtd5_backup(mtd5, mtd5_base)?;
            if sliced != nandrecovery_env {
                return Err("nandrecovery_env.bin does not match mtd5 slice");
            }
        }
    }
    let recovery_flag_byte = recovery_flag_local_offset(mtd5_base)
        .and_then(|off| read_s19k_mtd5_backup_byte(mtd5, off).ok());
    let recover_plan =
        format_s19k_recover_to_stock_plan(mtd5_base, S19K_BACKUP_NANDRECOVERY_ENV_NAME, &rec_env)?;
    let recover_refuse =
        format_s19k_recover_execute_refuse(mtd5_base, S19K_BACKUP_NANDRECOVERY_ENV_NAME);
    admit_s19k_recover_execute_refuse_names_78_nand_src(&recover_refuse)?;
    Ok(S19kBackupArtifactAdmit {
        nand_env_crc_ok: true,
        nandrecovery_env_crc_ok: rec_env.crc_ok,
        recovery_flag_byte,
        recover_plan,
        recover_refuse,
    })
}

/// nand_env.bak alone is not a recoverability-complete backup.
pub fn refuse_s19k_backup_without_nandrecovery_sidecar() -> Result<(), &'static str> {
    Err(
        "a recoverability-complete artifact-dir requires nandrecovery_env.bin; nand_env.bak is not recover_env",
    )
}

/// Restore / recover import must CRC-admit `nandrecovery_env.bin`.
/// `nand_env.bak` is never the recover source.
pub fn admit_s19k_restore_sidecar_crc(
    source_name: &str,
    nandrecovery_env: &[u8],
) -> Result<(), &'static str> {
    refuse_s19k_nand_env_bak_as_recover_env_import(source_name)?;
    let env = admit_s19k_nandrecovery_env_slice(nandrecovery_env)?;
    if !env.crc_ok {
        return Err("nandrecovery_env CRC32 mismatch");
    }
    Ok(())
}

/// Host restore plan fields after CRC-admitting the sidecar. No NAND write.
pub fn format_s19k_restore_crc_admit(
    source_name: &str,
    nandrecovery_crc_ok: bool,
    nand_env_crc_ok: bool,
) -> Result<String, &'static str> {
    refuse_s19k_nand_env_bak_as_recover_env_import(source_name)?;
    if !nandrecovery_crc_ok {
        return Err("nandrecovery_env CRC32 mismatch");
    }
    Ok(format!(
        "schema=dcentos.amlogic-restore-crc/v1\nrecover_env_source={source_name}\nnand_env_bak_is_not_nandrecovery_env=true\nnandrecovery_env_crc_ok=true\nnand_env_crc_ok={nand_env_crc_ok}\nclear_for_flash=false\n"
    ))
}

/// Restore shell must call `s19k_nand_env_crc.py` and refuse bak-only recover.
pub fn admit_s19k_restore_script_crc_admits_sidecar(script: &str) -> Result<(), &'static str> {
    if !script.contains("s19k_nand_env_crc.py") {
        return Err("restore must CRC-admit via s19k_nand_env_crc.py");
    }
    if !script.contains("nandrecovery_env.bin CRC32 mismatch") {
        return Err("restore must refuse nandrecovery CRC mismatch");
    }
    if !script.contains("cannot CRC-admit nandrecovery_env.bin") {
        return Err("restore must refuse missing py/python3");
    }
    if !script.contains("nandrecovery_env_crc_ok=") {
        return Err("restore must emit nandrecovery_env_crc_ok");
    }
    if !script.contains("recover_env_source=nandrecovery_env.bin") {
        return Err("restore recover_env_source must be nandrecovery_env.bin");
    }
    if script.contains("recover_env_source=nand_env.bak") {
        return Err("restore must not import nand_env.bak");
    }
    Ok(())
}

/// Restore must bind installer `nandrecovery_env_sha256` to the sidecar file.
pub fn admit_s19k_restore_script_sidecar_sha256(script: &str) -> Result<(), &'static str> {
    if !script.contains("nandrecovery_env_sha256") {
        return Err("restore must read ledger nandrecovery_env_sha256");
    }
    if !script.contains("nandrecovery_env_sha256 is not 64 hex chars")
        && !script.contains("missing nandrecovery_env_sha256")
    {
        return Err("restore must refuse missing/short nandrecovery_env_sha256");
    }
    if !script.contains("nandrecovery_env.bin sha256 drift") {
        return Err("restore must refuse sidecar SHA drift vs ledger");
    }
    if !script.contains("nandrecovery_env_sha256_ok=true") {
        return Err("restore must emit nandrecovery_env_sha256_ok");
    }
    let sha = script.find("nandrecovery_env.bin sha256 drift");
    let verify = script.find("VERIFY_OK hashes match ledger");
    match (sha, verify) {
        (Some(s), Some(v)) if s < v => Ok(()),
        _ => Err("restore must SHA-check nandrecovery_env before VERIFY_OK"),
    }
}

/// Restore must prove the sidecar bytes are the mtd5 recover_env window.
/// CRC-valid `nand_env.bak` copied as `nandrecovery_env.bin` is refused.
pub fn admit_s19k_restore_script_sidecar_matches_mtd5_slice(
    script: &str,
) -> Result<(), &'static str> {
    admit_s19k_restore_script_crc_admits_sidecar(script)?;
    if !script.contains("dcent_am3_extract_nandrecovery_env") {
        return Err("restore must slice nandrecovery_env from mtd5_pre_install.bin");
    }
    if !script.contains("nandrecovery_env.bin does not match mtd5 slice") {
        return Err("restore must refuse sidecar that is not the mtd5 recover window");
    }
    if !script.contains("nandrecovery_env_matches_mtd5_slice=true") {
        return Err("restore must emit nandrecovery_env_matches_mtd5_slice");
    }
    let extract = script.find("dcent_am3_extract_nandrecovery_env");
    let verify = script.find("VERIFY_OK hashes match ledger");
    match (extract, verify) {
        (Some(e), Some(v)) if e < v => Ok(()),
        _ => Err("restore must slice-compare nandrecovery_env before VERIFY_OK"),
    }
}

/// Local ramdisk window = `nandrootfs` − physical mtd5 start.
/// `a lab unit`: `0x0B800000-0x06700000=0x05100000`.
pub fn rootfs_local_offset(mtd5_base: u64) -> Option<u64> {
    if mtd5_base == 0 || mtd5_base > NANDROOTFS_GLOBAL {
        return None;
    }
    Some(NANDROOTFS_GLOBAL - mtd5_base)
}

/// Physical mtd5 start. Size-sum without the mtd0→mtd1 hole is a brick offset.
pub fn admit_s19k_physical_mtd5_base(mtd5_base: u64) -> Result<u64, &'static str> {
    if mtd5_base == 0 {
        return Err("mtd5 base 0 is not a physical system partition");
    }
    if mtd5_base == S19K_78_MTD5_SIZE_SUM {
        return Err(
            "0x06100000 is sum(mtd0-4) without the 6MiB mtd0→mtd1 hole; refuse as physical mtd5",
        );
    }
    Ok(mtd5_base)
}

/// Split `/proc/mtd` records. Installer ledger uses `|` instead of newlines.
pub fn proc_mtd_records(proc_mtd: &str) -> impl Iterator<Item = &str> {
    proc_mtd
        .split(|c| c == '\n' || c == '\r' || c == '|')
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// `a lab unit` `/proc/mtd` size-sum plus the Amlogic 6 MiB hole. Matches
/// `system.sh` `mtd_device_offset` for mtd5. Accepts newline **or** `|`
/// (BACKUP_LEDGER `proc_mtd=` line).
pub fn mtd5_base_from_proc_mtd(proc_mtd: &str) -> Option<u64> {
    let mut sum = 0u64;
    let mut saw_mtd5 = false;
    for line in proc_mtd_records(proc_mtd) {
        if line.starts_with("dev:") {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(dev) = parts.next() else {
            continue;
        };
        let Some(size_hex) = parts.next() else {
            continue;
        };
        if dev == "mtd5:" {
            saw_mtd5 = true;
            break;
        }
        if !dev.starts_with("mtd") {
            continue;
        }
        let size = u64::from_str_radix(size_hex.trim_start_matches("0x"), 16).ok()?;
        sum = sum.checked_add(size)?;
    }
    if !saw_mtd5 || sum == 0 {
        return None;
    }
    sum.checked_add(OFFSET_FROM_END_MTD0_TO_MTD1)
}

/// Locals implied by a captured `/proc/mtd` plus `a lab unit` U-Boot globals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kComputedGeometry {
    pub mtd5_base: u64,
    pub rootfs_local: u64,
    pub recovery_flag_local: u64,
}

pub fn compute_s19k_geometry_from_proc_mtd(proc_mtd: &str) -> Option<S19kComputedGeometry> {
    let mtd5_base = mtd5_base_from_proc_mtd(proc_mtd)?;
    admit_s19k_physical_mtd5_base(mtd5_base).ok()?;
    Some(S19kComputedGeometry {
        mtd5_base,
        rootfs_local: rootfs_local_offset(mtd5_base)?,
        recovery_flag_local: recovery_flag_local_offset(mtd5_base)?,
    })
}

/// Planned installer locals must match the `/proc/mtd` computation.
pub fn admit_s19k_planned_locals_match_computed(
    proc_mtd: &str,
    planned_rootfs: u64,
    planned_flag: u64,
) -> Result<S19kComputedGeometry, &'static str> {
    let geo = compute_s19k_geometry_from_proc_mtd(proc_mtd)
        .ok_or("cannot compute mtd5 geometry from /proc/mtd")?;
    if geo.rootfs_local != planned_rootfs {
        return Err("planned ROOTFS_OFFSET != nandrootfs − computed physical mtd5");
    }
    if geo.recovery_flag_local != planned_flag {
        return Err("planned recovery-flag local != nandrecovery_flag − computed physical mtd5");
    }
    Ok(geo)
}

/// Refuse a flash plan whose window is not the offset implied by the observed base.
pub fn admit_s19k_rootfs_window(mtd5_base: u64, planned_local: u64) -> Result<u64, &'static str> {
    admit_s19k_physical_mtd5_base(mtd5_base)?;
    let Some(computed) = rootfs_local_offset(mtd5_base) else {
        return Err("mtd5 base cannot produce nandrootfs local offset");
    };
    if computed != planned_local {
        return Err("planned ROOTFS_OFFSET does not match nandrootfs − mtd5_base; refuse FLASH");
    }
    Ok(computed)
}

/// Exact factory-bad eraseblocks reported by the held `a lab unit` boot transcript,
/// converted from global NAND addresses to mtd5-local offsets using the proven
/// physical mtd5 base `0x0670_0000`.
///
/// This tuple is evidence for that captured unit only. It is not a default for
/// another S19k Pro and it is not permission to write NAND.
pub const S19K_78_HELD_MTD5_BAD_ERASEBLOCKS: [u64; 4] =
    [0x0590_0000, 0x0592_0000, 0x0976_0000, 0x097A_0000];

/// Map one input byte to the mtd offset at which mtd-utils `nandwrite` will
/// program it when normal bad-block skipping is enabled.
///
/// The model is deliberately narrow: start and bad-block offsets must be
/// eraseblock-aligned, the bad-block list must be strictly increasing, and the
/// requested byte must fit in the device. It mirrors the held
/// mtd-utils-2.2.1 `nand-utils/nandwrite.c` ordering: check/skip a target
/// eraseblock before consuming input for that eraseblock. It does **not** model
/// Amlogic U-Boot `nand read`, ECC/OOB, power loss, or write-failure marking.
pub fn map_mtdutils_nandwrite_input_byte(
    start: u64,
    input_byte: u64,
    erase_size: u64,
    device_size: u64,
    bad_eraseblocks: &[u64],
) -> Result<u64, &'static str> {
    if erase_size == 0 || start % erase_size != 0 {
        return Err("nandwrite mapping requires a nonzero erase size and aligned start");
    }
    let mut previous = None;
    for &bad in bad_eraseblocks {
        if bad % erase_size != 0 || bad >= device_size {
            return Err("bad eraseblock is unaligned or outside the MTD device");
        }
        if previous.is_some_and(|prior| bad <= prior) {
            return Err("bad eraseblocks must be unique and strictly increasing");
        }
        previous = Some(bad);
    }

    let input_block = input_byte / erase_size;
    let within_block = input_byte % erase_size;
    let mut target_block = start / erase_size;
    let mut good_blocks_seen = 0_u64;
    let device_blocks = device_size / erase_size;

    while target_block < device_blocks {
        let target = target_block
            .checked_mul(erase_size)
            .ok_or("nandwrite target offset overflow")?;
        if bad_eraseblocks.binary_search(&target).is_err() {
            if good_blocks_seen == input_block {
                return target
                    .checked_add(within_block)
                    .filter(|offset| *offset < device_size)
                    .ok_or("mapped nandwrite byte is outside the MTD device");
            }
            good_blocks_seen = good_blocks_seen
                .checked_add(1)
                .ok_or("nandwrite input block count overflow")?;
        }
        target_block = target_block
            .checked_add(1)
            .ok_or("nandwrite target block overflow")?;
    }
    Err("nandwrite input does not fit after skipping bad eraseblocks")
}

/// Linux writer mapping is not proof that the stock Amlogic U-Boot reader
/// reconstructs the same logical byte stream or fixed-length endpoint.
pub fn refuse_s19k_linux_badblock_map_as_uboot_read_authority() -> Result<(), &'static str> {
    Err("mtd-utils nandwrite bad-block mapping does not prove Amlogic U-Boot nand-read mapping")
}

/// Stock web rail (`a lab unit` extract): `upgrade.cgi` writes `update.bmu` and execs
/// `/usr/sbin/daemonc`. That ELF32 ARM (7240 B) is **identical** to
/// `update-daemon` and `system()`s `updateporc.sh`. The S19k `a lab unit` extract
/// still has **no** `updateporc.sh`. The held copy is CVCtrl/CV183X eMMC.
pub const S19K_STOCK_BMU_NAME: &str = "update.bmu";
pub const S19K_STOCK_DAEMONC_PATH: &str = "/usr/sbin/daemonc";
pub const S19K_STOCK_DAEMONC_BYTES: usize = 7240;
pub const S19K_STOCK_UPDATEPORC_IN_EXTRACT: bool = false;
/// Corpus hunt: no S19k Amlogic NAND `updateporc.sh` plaintext.
/// Held scripts are CV183X eMMC (3920 B) and Zynq UBI mtd6 (2627 B).
/// 20231108 inner component is an `ANDROID!` boot.img whose kernel/ramdisk
/// bodies are high-entropy (not gzip); no `updateporc` bytes.
/// : `a lab unit` `mtd3_stock_config.bin` is UBI (40 x 128KiB), 0 porc /
/// FileParser / uart_trans hits.
/// : `a lab unit` `mtd2_stock_system.bin` is 50 MiB with ANDROID! @
/// 0x200000 (ramdisk 0) and 0x1200000 (ramdisk 0x662000); 0 porc /
/// FileParser / uart_trans / 4cc0 / bitmain.pub / miner.pem / daemonc.
pub const S19K_AML_UPDATEPORC_IN_HELD_CORPUS: bool = false;
pub const UIMAGE_MAGIC: [u8; 4] = [0x27, 0x05, 0x19, 0x56];
/// U-Boot `IH_ARCH_ARM` / `IH_ARCH_ARM64`.
pub const UIMAGE_ARCH_ARM: u8 = 2;
pub const UIMAGE_ARCH_ARM64: u8 = 22;
/// Held HashSource S19 Pro / Hydro / SD uImages (not S19k AML).
pub const HELD_S19PRO_UIMAGE_BYTES: usize = 4_057_320;
pub const HELD_S19PRO_UIMAGE_IH_SIZE: u32 = 4_057_256;
pub const HELD_S19PRO_UIMAGE_NAME: &str = "Linux-4.6.0-xilinx-g03c746f7";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kUimageHeader {
    pub ih_size: u32,
    pub ih_load: u32,
    pub ih_ep: u32,
    pub ih_os: u8,
    pub ih_arch: u8,
    pub ih_type: u8,
    pub ih_comp: u8,
    pub ih_name: String,
}

pub fn parse_s19k_uimage_header(blob: &[u8]) -> Result<S19kUimageHeader, &'static str> {
    if blob.len() < 64 {
        return Err("uImage header is 64 bytes");
    }
    if blob[0..4] != UIMAGE_MAGIC {
        return Err("not uImage 27051956");
    }
    let be = |o: usize| u32::from_be_bytes([blob[o], blob[o + 1], blob[o + 2], blob[o + 3]]);
    let name = blob[32..64]
        .split(|b| *b == 0)
        .next()
        .and_then(|s| std::str::from_utf8(s).ok())
        .unwrap_or("")
        .to_string();
    Ok(S19kUimageHeader {
        ih_size: be(12),
        ih_load: be(16),
        ih_ep: be(20),
        ih_os: blob[28],
        ih_arch: blob[29],
        ih_type: blob[30],
        ih_comp: blob[31],
        ih_name: name,
    })
}

/// `a lab unit` kernel is aarch64 (`uname` 4.9.113). Xilinx ARM32 uImage is not AML.
pub fn refuse_xilinx_arm32_uimage_as_s19k_aml(hdr: &S19kUimageHeader) -> Result<(), &'static str> {
    if hdr.ih_arch == UIMAGE_ARCH_ARM && hdr.ih_name.contains("xilinx") {
        return Err(
            "held uImage is ARM32 Linux-4.6.0-xilinx; S19k AML is aarch64, refuse mtd5 nandwrite",
        );
    }
    if hdr.ih_arch == UIMAGE_ARCH_ARM64 {
        return Ok(());
    }
    Err("S19k AML revert uImage must be IH_ARCH_ARM64 (22); ARM32 refused")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kUpgradeBlobKind {
    StockBitmainBmu,
    DcentSysupgradeTar,
    AmlFactoryEnc,
    /// `stock-20231115` sd2nand-**cvctrl**: `boot.emmc` + `partition_emmc_miner.xml`.
    CvitekSd2NandFactory,
    /// `sd-recover-bmu-s19k-pro-*`: Xilinx `uImage` + `update.bmu`, not AML NAND.
    XilSdRecoverFactory,
    UimageRootfs,
    Unknown,
}

/// Btmu first byte (HashSource unpacker `magic != 38`). Held S19k 20231108 BMU matches.
pub const S19K_BTMU_MAGIC: u8 = 0x26;
/// `Antminer-S19k-Pro-merge-release-20231108091327.bmu` extracted `update.bmu`.
pub const S19K_STOCK_20231108_BMU_BYTES: usize = 12_792_832;
/// LE u64 at BMU offset 2 (miner_type hash). Not a FileParser writer proof.
pub const S19K_STOCK_20231108_MINER_TYPE_HASH: u64 = 0xB090_9B8B_D8F3_6BFB;
pub const S19K_BMU_PEM_PREFIX: &[u8] = b"-----BEGIN PUBLIC KEY-----";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kBmuHeader {
    pub miner_type_hash: u64,
    pub pem_visible: bool,
}

pub fn parse_s19k_bmu_header(head: &[u8]) -> Result<S19kBmuHeader, &'static str> {
    if head.len() < 32 {
        return Err("BMU header too short");
    }
    if head[0] != S19K_BTMU_MAGIC {
        return Err("not a Btmu (magic != 0x26)");
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&head[2..10]);
    let miner_type_hash = u64::from_le_bytes(raw);
    let pem_visible = head
        .windows(S19K_BMU_PEM_PREFIX.len())
        .any(|w| w == S19K_BMU_PEM_PREFIX);
    if !pem_visible {
        return Err("BMU header missing miner.pem PEM prefix");
    }
    Ok(S19kBmuHeader {
        miner_type_hash,
        pem_visible: true,
    })
}

/// `_summary.json` said `rec_count=3 rec_size=0xac` at `hdr_size=0x24`.
/// On the held 20231108 BMU those bytes are the **PEM body**, not a TOC.
pub const S19K_BMU_FALSE_TOC_OFF: usize = 0x24;
pub const S19K_BMU_FALSE_REC_SIZE: usize = 0xAC;
pub const S19K_BMU_DATA_START: usize = 0x4000;
/// FileParser/HashSource miner.pem.sig offset (256 B RSA). Held file matches.
pub const S19K_BMU_PEM_SIG_OFF: usize = 0x418;
pub const S19K_BMU_PEM_SIG_LEN: usize = 256;
pub const S19K_20231108_MINER_PEM_OFF: usize = 0x18;
pub const S19K_20231108_MINER_PEM_LEN: usize = 451;
pub const S19K_20231108_MINER_PEM_BEGIN: &[u8] = b"-----BEGIN PUBLIC KEY-----";
pub const S19K_20231108_MINER_PEM_SHA256_HEX: &[u8; 64] =
    b"f03c6e8345cb3cfec6792b3ef545cc2e2166661492683c20e8f0166aba8c8ad0";
pub const S19K_20231108_PEM_SIG_HEAD: [u8; 4] = [0x02, 0x2E, 0x5A, 0xE0];
pub const S19K_CVCTRL_BITMAIN_PUB_BYTES: usize = 451;
pub const S19K_HASSOURCE_S19PRO_BITMAIN_PUB_BYTES: usize = 460;
/// PKCS1v15 SHA256/SHA1 against held CVCtrl 451 B and HashSource 460 B roots.
pub const S19K_MINER_PEM_SIG_HELD_ROOT_VERIFIED: bool = false;
/// Bytes at merge-container `0x4000` (mid-kernel). **Not** the single-BMU
/// component start — that is `0x800` (`ANDROID!`).
pub const S19K_STOCK_20231108_PAYLOAD_HEAD: [u8; 4] = [0xCA, 0x78, 0xC9, 0x44];
/// FileParser single-BMU header (2048 B). Component data starts here.
pub const S19K_SINGLE_BMU_HEADER_LEN: usize = 2048;
pub const S19K_SINGLE_BMU_PEM_LEN_OFF: usize = 22;
pub const S19K_SINGLE_BMU_FILE_COUNT_OFF: usize = 1304;
pub const S19K_SINGLE_BMU_FILE_DESC_OFF: usize = 1309;
pub const S19K_SINGLE_BMU_FILE_DESC_STRIDE: usize = 5;
pub const S19K_SINGLE_BMU_TYPE_DATAFILE: u8 = 9;
pub const S19K_20231108_FILE_COUNT: u8 = 1;
pub const S19K_20231108_CONTENT_BITMAP: u16 = 0x0200;
pub const S19K_20231108_DATAFILE_SIZE: u32 = 12_790_272;
pub const S19K_20231108_DATAFILE_OFF: usize = 0x800;
pub const S19K_ANDROID_BOOT_MAGIC: &[u8; 8] = b"ANDROID!";
pub const S19K_20231108_KERNEL_SIZE: u32 = 0x005C_0800;
pub const S19K_20231108_RAMDISK_SIZE: u32 = 0x0066_A000;
/// Factory item 9 PARTITION/boot ramdisk. Not 20231108 `0x66A000`.
pub const S19K_FACTORY_BOOT_RAMDISK_SIZE: u32 = 0x0068_6800;
/// page(2048) + kernel(0x5C0800). `S19K_FACTORY_ANDROID_RAMDISK_OFF` is 4K-math leftover.
pub const S19K_FACTORY_BOOT_RAMDISK_OFF: usize = 0x5C_1000;
/// page + kernel + ramdisk inside factory item 9.
pub const S19K_FACTORY_BOOT_SECOND_OFF: usize = 12_875_776;
pub const S19K_FACTORY_BOOT_SECOND_HEAD: [u8; 4] = [0x27, 0x84, 0x7E, 0x00];
/// Factory item 17 recovery second at page+kernel. Not boot second / not meson1_ENC.
pub const S19K_FACTORY_RECOVERY_SECOND_HEAD: [u8; 4] = [0x68, 0xCA, 0xF5, 0xA1];
/// Shared factory boot/recovery kernel head (full 0x5C0800 compare equal).
pub const S19K_FACTORY_BOOT_KERNEL_HEAD: [u8; 4] = [0x30, 0x9C, 0xFC, 0x10];
/// Item 4/15 meson1_ENC head. 29728 B, not the 30720 B recovery second.
pub const S19K_FACTORY_MESON1_ENC_HEAD: [u8; 4] = [0x5D, 0xC7, 0x5D, 0x64];
/// ANDROID bootimg `name` at +48. Held S19k images leave 16 zero bytes.
pub const S19K_ANDROID_NAME_OFF: usize = 48;
pub const S19K_ANDROID_NAME_LEN: usize = 16;
pub const S19K_20231108_SECOND_SIZE: u32 = 30_720;
pub const S19K_20231108_PAGE_SIZE: u32 = 2048;
pub const S19K_20231108_KERNEL_ADDR: u32 = 0x0108_0000;
pub const S19K_20231108_RAMDISK_ADDR: u32 = 0x0100_0000;
pub const S19K_20231108_SECOND_ADDR: u32 = 0x00F0_0000;
pub const S19K_20231108_TAGS_ADDR: u32 = 0x0000_0100;
pub const S19K_20231108_CMDLINE: &[u8] = b"init=/sbin/init";
/// Factory boot ramdisk file offset: page + kernel (kernel is page-aligned).
pub const S19K_FACTORY_ANDROID_RAMDISK_OFF: usize = 0x5C_1800;
pub const S19K_FACTORY_S30V_BOOT_SLOT_BYTES: u64 = 0x200_0000;
pub const S19K_FACTORY_S30V_RECOVERY_SLOT_BYTES: u64 = 0x100_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kSingleBmuFile {
    pub type_id: u8,
    pub size: u32,
    pub data_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kSingleBmuToc {
    pub miner_type_hash: u64,
    pub content_bitmap: u16,
    pub pem_length: u16,
    pub file_count: u8,
    pub files: [S19kSingleBmuFile; 1],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kAndroidBootHdr {
    pub kernel_size: u32,
    pub kernel_addr: u32,
    pub ramdisk_size: u32,
    pub ramdisk_addr: u32,
    pub second_size: u32,
    pub second_addr: u32,
    pub tags_addr: u32,
    pub page_size: u32,
}

/// FileParser size check: `(file_count + 9) * 256 + sum(component sizes)`.
pub fn s19k_single_bmu_expected_size(file_count: u8, component_bytes: u32) -> u64 {
    (u64::from(file_count) + 9) * 256 + u64::from(component_bytes)
}

pub fn parse_s19k_single_bmu_toc(header: &[u8]) -> Result<S19kSingleBmuToc, &'static str> {
    if header.len() < S19K_SINGLE_BMU_HEADER_LEN {
        return Err("single-BMU header shorter than 2048");
    }
    if header[0] != S19K_BTMU_MAGIC {
        return Err("single-BMU magic != 0x26");
    }
    let mut hash = [0u8; 8];
    hash.copy_from_slice(&header[2..10]);
    let miner_type_hash = u64::from_le_bytes(hash);
    let content_bitmap = u16::from_be_bytes([header[11], header[12]]);
    let pem_length = u16::from_be_bytes([
        header[S19K_SINGLE_BMU_PEM_LEN_OFF],
        header[S19K_SINGLE_BMU_PEM_LEN_OFF + 1],
    ]);
    let file_count = header[S19K_SINGLE_BMU_FILE_COUNT_OFF];
    if file_count != 1 {
        return Err("this TOC parser admits the held 20231108 one-file layout only");
    }
    let desc = S19K_SINGLE_BMU_FILE_DESC_OFF;
    let type_id = header[desc];
    let size = u32::from_be_bytes([
        header[desc + 1],
        header[desc + 2],
        header[desc + 3],
        header[desc + 4],
    ]);
    Ok(S19kSingleBmuToc {
        miner_type_hash,
        content_bitmap,
        pem_length,
        file_count,
        files: [S19kSingleBmuFile {
            type_id,
            size,
            data_offset: S19K_SINGLE_BMU_HEADER_LEN,
        }],
    })
}

pub fn parse_s19k_android_boot_header(comp: &[u8]) -> Result<S19kAndroidBootHdr, &'static str> {
    if comp.len() < 48 {
        return Err("ANDROID boot header too short");
    }
    if &comp[..8] != S19K_ANDROID_BOOT_MAGIC {
        return Err("component is not ANDROID!");
    }
    let u32le = |o: usize| u32::from_le_bytes([comp[o], comp[o + 1], comp[o + 2], comp[o + 3]]);
    Ok(S19kAndroidBootHdr {
        kernel_size: u32le(8),
        kernel_addr: u32le(12),
        ramdisk_size: u32le(16),
        ramdisk_addr: u32le(20),
        second_size: u32le(24),
        second_addr: u32le(28),
        tags_addr: u32le(32),
        page_size: u32le(36),
    })
}

///  `0x4000` head is mid-kernel, not the component start.
pub fn refuse_s19k_bmu_0x4000_as_single_component_start() -> Result<(), &'static str> {
    Err("0x4000 is merge-container data_start / mid-kernel; single-BMU component starts at 0x800 ANDROID!")
}

pub fn refuse_s19k_android_ramdisk_as_plaintext_gzip(head: &[u8]) -> Result<(), &'static str> {
    if head.len() >= 2 && head[0] == 0x1F && head[1] == 0x8B {
        return Ok(());
    }
    Err("20231108 ANDROID ramdisk head is not gzip; body is high-entropy / encrypted")
}

/// Page-0 vendor stamp (not the S21 `AMLSECU!` RSA-OAEP/AES-CBC container).
pub const S19K_ANDROID_AMLSECU_STAMP_OFF: usize = 0x400;
pub const S19K_AMLSECU_MAGIC: &[u8; 8] = b"AMLSECU!";
/// S21 parser requires `header_size >= 0x40`. The 20231108 stamp stores `3`.
pub const S19K_S21_AMLSECU_HEADER_MIN: u32 = 0x40;
pub const S19K_20231108_AMLSECU_STAMP_TIME: &[u8; 16] = b"2023110817065673";
/// Factory SD item-9 PARTITION/boot page0 stamp. Same geometry as 20231108, different date.
pub const S19K_FACTORY_AMLSECU_BOOT_TIME: &[u8; 16] = b"2023111515304766";
/// Factory SD item-17 PARTITION/recovery page0 stamp. ramdisk_size=0.
pub const S19K_FACTORY_AMLSECU_RECOVERY_TIME: &[u8; 16] = b"2023111515304721";
/// AMLSECU `declared_header_len`: 2 = recovery-class (ramdisk 0), 3 = boot-class.
pub const S19K_AMLSECU_KIND_RECOVERY: u32 = 2;
pub const S19K_AMLSECU_KIND_BOOT: u32 = 3;
pub const S19K_20231108_AMLSECU_KIND: u32 = S19K_AMLSECU_KIND_BOOT;
pub const S19K_FACTORY_BOOT_AMLSECU_KIND: u32 = S19K_AMLSECU_KIND_BOOT;
pub const S19K_FACTORY_RECOVERY_AMLSECU_KIND: u32 = S19K_AMLSECU_KIND_RECOVERY;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kAmlsecuImageKind {
    Bmu20231108,
    FactorySdBoot,
    FactorySdRecovery,
    /// `a lab unit` mtd2 first ANDROID (ramdisk 0, AMLSECU kind 2).
    Mtd2Android1,
    /// `a lab unit` mtd2 second ANDROID (ramdisk 0x662000, AMLSECU kind 3).
    Mtd2Android2,
}
pub const S19K_78_CONSOLE_TTY: &str = "/dev/ttyS0";
pub const S19K_78_CONSOLE_BAUD: u32 = 115_200;
pub const S19K_78_CONSOLE_MMIO: u32 = 0xFF80_3000;
pub const S19K_78_CONSOLE_IRQ: u32 = 13;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kAndroidAmlsecuStamp {
    pub version_le: u32,
    pub declared_header_len: u32,
    pub page_size: u32,
    pub kernel_size_repeat: u32,
}

fn parse_s19k_android_amlsecu_fields(
    page0: &[u8],
) -> Result<(S19kAndroidAmlsecuStamp, [u8; 16]), &'static str> {
    let off = S19K_ANDROID_AMLSECU_STAMP_OFF;
    if page0.len() < off + 48 {
        return Err("ANDROID page0 shorter than AMLSECU stamp");
    }
    if &page0[off..off + 8] != S19K_AMLSECU_MAGIC {
        return Err("page0 0x400 is not AMLSECU!");
    }
    let u32le = |o: usize| u32::from_le_bytes([page0[o], page0[o + 1], page0[o + 2], page0[o + 3]]);
    let mut time = [0u8; 16];
    time.copy_from_slice(&page0[off + 16..off + 32]);
    Ok((
        S19kAndroidAmlsecuStamp {
            version_le: u32le(off + 8),
            declared_header_len: u32le(off + 12),
            page_size: u32le(off + 32),
            kernel_size_repeat: u32le(off + 40),
        },
        time,
    ))
}

/// 20231108-only stamp. Factory 20231115 SD uses `parse_s19k_android_amlsecu_stamp_raw`.
pub fn parse_s19k_android_amlsecu_stamp(
    page0: &[u8],
) -> Result<S19kAndroidAmlsecuStamp, &'static str> {
    let (stamp, time) = parse_s19k_android_amlsecu_fields(page0)?;
    if &time != S19K_20231108_AMLSECU_STAMP_TIME {
        return Err("AMLSECU stamp timestamp is not 2023110817065673");
    }
    Ok(stamp)
}

/// Any `AMLSECU!` @ 0x400. Classify the 16-byte date separately.
pub fn parse_s19k_android_amlsecu_stamp_raw(
    page0: &[u8],
) -> Result<(S19kAndroidAmlsecuStamp, [u8; 16]), &'static str> {
    parse_s19k_android_amlsecu_fields(page0)
}

pub fn classify_s19k_amlsecu_time(time: &[u8]) -> Result<S19kAmlsecuImageKind, &'static str> {
    if time == S19K_20231108_AMLSECU_STAMP_TIME {
        return Ok(S19kAmlsecuImageKind::Bmu20231108);
    }
    if time == S19K_FACTORY_AMLSECU_BOOT_TIME {
        return Ok(S19kAmlsecuImageKind::FactorySdBoot);
    }
    if time == S19K_FACTORY_AMLSECU_RECOVERY_TIME {
        return Ok(S19kAmlsecuImageKind::FactorySdRecovery);
    }
    if time == S19K_78_MTD2_AMLSECU_A1_TIME {
        return Ok(S19kAmlsecuImageKind::Mtd2Android1);
    }
    if time == S19K_78_MTD2_AMLSECU_A2_TIME {
        return Ok(S19kAmlsecuImageKind::Mtd2Android2);
    }
    Err("unknown S19k AMLSECU stamp time")
}

pub fn refuse_s19k_factory_amlsecu_as_20231108_bmu(
    kind: S19kAmlsecuImageKind,
) -> Result<(), &'static str> {
    if matches!(
        kind,
        S19kAmlsecuImageKind::FactorySdBoot | S19kAmlsecuImageKind::FactorySdRecovery
    ) {
        return Err("factory 20231115 AMLSECU stamp is not the 20231108 single-BMU datafile");
    }
    Ok(())
}

/// Factory item 9 ANDROID header. Kernel/second/page match 20231108; ramdisk is 0x686800.
pub fn admit_s19k_factory_android_boot_header(h: S19kAndroidBootHdr) -> Result<(), &'static str> {
    if h.kernel_size != S19K_20231108_KERNEL_SIZE
        || h.ramdisk_size != S19K_FACTORY_BOOT_RAMDISK_SIZE
        || h.second_size != S19K_20231108_SECOND_SIZE
        || h.page_size != S19K_20231108_PAGE_SIZE
        || h.kernel_addr != S19K_20231108_KERNEL_ADDR
        || h.ramdisk_addr != S19K_20231108_RAMDISK_ADDR
        || h.second_addr != S19K_20231108_SECOND_ADDR
        || h.tags_addr != S19K_20231108_TAGS_ADDR
    {
        return Err("factory PARTITION/boot ANDROID geometry is 6031360/6842368/30720 @ 0x1080000/0x1000000/0xf00000");
    }
    Ok(())
}

pub fn refuse_s19k_20231108_ramdisk_as_factory_boot(ramdisk_size: u32) -> Result<(), &'static str> {
    if ramdisk_size == S19K_20231108_RAMDISK_SIZE {
        return Err("20231108 datafile ramdisk 0x66A000 is not factory item 9 ramdisk 0x686800");
    }
    Ok(())
}

pub fn admit_s19k_factory_android_second_layout(
    page: u32,
    kernel: u32,
    ramdisk: u32,
    second_off: usize,
) -> Result<(), &'static str> {
    if page != S19K_20231108_PAGE_SIZE
        || kernel != S19K_20231108_KERNEL_SIZE
        || ramdisk != S19K_FACTORY_BOOT_RAMDISK_SIZE
    {
        return Err(
            "factory second layout requires page 2048 + kernel 0x5C0800 + ramdisk 0x686800",
        );
    }
    let want = page as usize + kernel as usize + ramdisk as usize;
    if second_off != want || second_off != S19K_FACTORY_BOOT_SECOND_OFF {
        return Err("factory ANDROID second starts at 12875776 inside item 9");
    }
    if S19K_FACTORY_BOOT_RAMDISK_OFF != page as usize + kernel as usize {
        return Err("factory ramdisk starts at page+kernel = 0x5C1000");
    }
    Ok(())
}

pub fn refuse_s19k_4k_ramdisk_off_as_factory_page2048(off: usize) -> Result<(), &'static str> {
    if off == S19K_FACTORY_ANDROID_RAMDISK_OFF {
        return Err("0x5C1800 is 4K-page math; factory item 9 page is 2048 so ramdisk is 0x5C1000");
    }
    Ok(())
}

pub fn refuse_s19k_factory_second_as_plaintext_android(blob: &[u8]) -> Result<(), &'static str> {
    if blob.starts_with(S19K_ANDROID_BOOT_MAGIC)
        || (blob.len() >= 2 && blob[0] == 0x1F && blob[1] == 0x8B)
    {
        return Ok(());
    }
    for n in [
        b"updateporc".as_slice(),
        b"uart_trans",
        b"nandrecovery",
        b"AMLSECU",
    ] {
        if blob.windows(n.len()).any(|w| w == n) {
            return Ok(());
        }
    }
    Err("factory ANDROID second is high-entropy; not ANDROID/gzip/updateporc/nandrecovery")
}

pub fn admit_s19k_factory_android_second_head(blob: &[u8]) -> Result<(), &'static str> {
    if blob.len() < 4 || blob[..4] != S19K_FACTORY_BOOT_SECOND_HEAD {
        return Err("factory ANDROID second head is 27 84 7e 00");
    }
    if blob.len() != S19K_20231108_SECOND_SIZE as usize {
        return Err("factory ANDROID second is 30720 B");
    }
    Ok(())
}

/// Factory boot ramdisk at 0x5C1800 is not gzip/lz4.
pub fn admit_s19k_factory_android_ramdisk_not_gzip(head: &[u8]) -> Result<(), &'static str> {
    if head.len() >= 2 && head[0] == 0x1F && head[1] == 0x8B {
        return Err("factory boot ramdisk is not gzip");
    }
    if head.len() >= 4 && head[0] == 0x04 && head[1] == 0x22 && head[2] == 0x4D && head[3] == 0x18 {
        return Err("factory boot ramdisk is not lz4 frame");
    }
    Ok(())
}

pub fn refuse_s19k_factory_android_page0_as_gpio437(page0: &[u8]) -> Result<(), &'static str> {
    for n in [
        b"gpio437".as_slice(),
        b"PWR_CONTROL",
        b"recover_env",
        b"updateporc",
        b"uart_trans",
    ] {
        if page0.windows(n.len()).any(|w| w == n) {
            return Ok(());
        }
    }
    Err("factory ANDROID page0 has no gpio437/PWR_CONTROL/updateporc/uart_trans")
}

pub fn refuse_s19k_factory_android_as_s30v_full_slot(
    item_len: u64,
    slot_len: u64,
) -> Result<(), &'static str> {
    if item_len != slot_len {
        return Err("factory ANDROID item is not the full s30v nand_partition slot; do not nandwrite as a padded dump");
    }
    Ok(())
}

/// Factory recovery is kernel+second only. ramdisk_size=0.
pub fn admit_s19k_factory_android_recovery_header(
    h: S19kAndroidBootHdr,
) -> Result<(), &'static str> {
    if h.kernel_size != S19K_20231108_KERNEL_SIZE
        || h.ramdisk_size != 0
        || h.second_size != S19K_20231108_SECOND_SIZE
        || h.page_size != S19K_20231108_PAGE_SIZE
    {
        return Err("factory PARTITION/recovery is kernel+second, ramdisk_size=0");
    }
    Ok(())
}

pub fn refuse_s19k_factory_recovery_as_boot_ramdisk(
    h: S19kAndroidBootHdr,
) -> Result<(), &'static str> {
    if h.ramdisk_size == 0 {
        return Err("factory recovery ramdisk_size=0; cannot extract updateporc from this item");
    }
    Ok(())
}

pub fn refuse_s19k_factory_boot_as_20231108_datafile(item_len: usize) -> Result<(), &'static str> {
    if item_len == S19K_AML_UPGRADE_ITEM9_BOOT_SIZE as usize
        && item_len != S19K_20231108_DATAFILE_SIZE as usize
    {
        return Err(
            "factory PARTITION/boot is 12907008 B AmlImagePack item 9, not 20231108 datafile 12790272",
        );
    }
    Ok(())
}

/// S21 `parse_amlsecu` rejects this stamp (`header_size=3 < 0x40`).
pub fn refuse_s19k_amlsecu_stamp_as_s21_decrypt_container(
    stamp: S19kAndroidAmlsecuStamp,
) -> Result<(), &'static str> {
    if stamp.declared_header_len < S19K_S21_AMLSECU_HEADER_MIN {
        return Err(
            "20231108 AMLSECU! @ 0x400 is a dated vendor stamp (hdr_len=3); not S21 RSA-OAEP/AES container",
        );
    }
    Ok(())
}

pub fn refuse_s19k_boot_decrypt_without_vendor_rsa() -> Result<(), &'static str> {
    Err("S19k ANDROID kernel/ramdisk stay encrypted; Bitmain RSA private key is not in this repo")
}

pub fn refuse_s19k_android_boot_as_mtd5_uimage(magic: &[u8]) -> Result<(), &'static str> {
    if magic.len() >= 8 && &magic[..8] == S19K_ANDROID_BOOT_MAGIC {
        return Err(
            "20231108 datafile is ANDROID! boot.img; revert_to_stock requires uImage 27051956, refuse nandwrite to mtd5",
        );
    }
    if magic.len() >= 4 && magic[..4] == UIMAGE_MAGIC {
        return Ok(());
    }
    Err("payload is neither ANDROID! nor uImage")
}

/// `a lab unit` dmesg: `console=ttyS0,115200` `earlycon=aml_uart,0xff803000` irq 13.
/// Header pinout remains unmapped.
pub fn admit_s19k_uart_rescue_console(path: &str, baud: u32) -> Result<(), &'static str> {
    if path == "/dev/ttyS1" || path == "/dev/ttyS2" || path == "/dev/ttyS3" {
        return Err("ttyS1/S2/S3 are hash UARTs; rescue console is ttyS0");
    }
    if path != S19K_78_CONSOLE_TTY {
        return Err("S19k rescue console is /dev/ttyS0 (dmesg console enabled)");
    }
    if baud != S19K_78_CONSOLE_BAUD {
        return Err("S19k rescue console baud is 115200");
    }
    Ok(())
}

pub fn admit_s19k_20231108_single_bmu(blob: &[u8]) -> Result<S19kSingleBmuToc, &'static str> {
    if blob.len() != S19K_STOCK_20231108_BMU_BYTES {
        return Err("20231108 BMU size is 12792832");
    }
    let toc = parse_s19k_single_bmu_toc(&blob[..S19K_SINGLE_BMU_HEADER_LEN])?;
    if toc.miner_type_hash != S19K_STOCK_20231108_MINER_TYPE_HASH {
        return Err("20231108 miner_type_hash mismatch");
    }
    if toc.content_bitmap != S19K_20231108_CONTENT_BITMAP {
        return Err("20231108 content_bitmap is 0x0200 (type 9 datafile)");
    }
    if toc.files[0].type_id != S19K_SINGLE_BMU_TYPE_DATAFILE {
        return Err("20231108 component 0 is type 9 datafile");
    }
    if toc.files[0].size != S19K_20231108_DATAFILE_SIZE {
        return Err("20231108 datafile size is 12790272");
    }
    let expected = s19k_single_bmu_expected_size(toc.file_count, toc.files[0].size);
    if expected != S19K_STOCK_20231108_BMU_BYTES as u64 {
        return Err("FileParser size formula does not match on-disk 20231108");
    }
    let comp = &blob[S19K_20231108_DATAFILE_OFF..];
    let boot = parse_s19k_android_boot_header(comp)?;
    if boot.kernel_size != S19K_20231108_KERNEL_SIZE
        || boot.ramdisk_size != S19K_20231108_RAMDISK_SIZE
        || boot.page_size != S19K_20231108_PAGE_SIZE
        || boot.kernel_addr != S19K_20231108_KERNEL_ADDR
    {
        return Err("20231108 ANDROID boot header sizes/addr mismatch");
    }
    if !comp
        .windows(S19K_20231108_CMDLINE.len())
        .any(|w| w == S19K_20231108_CMDLINE)
    {
        return Err("20231108 ANDROID cmdline is not init=/sbin/init");
    }
    Ok(toc)
}
/// ASCII at 0x24 on the held file (`UBLIC KEY-----`).
pub const S19K_BMU_FALSE_TOC_ASCII: &[u8] = b"UBLIC KEY-";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kBmuPayloadKind {
    HighEntropyOpaque,
    Uimage,
    Gzip,
    Elf,
    NestedBtmu,
    Unknown,
}

/// Classify the blob at [`S19K_BMU_DATA_START`]. Does not inflate or write NAND.
pub fn classify_s19k_bmu_payload_head(head: &[u8]) -> S19kBmuPayloadKind {
    if head.len() < 4 {
        return S19kBmuPayloadKind::Unknown;
    }
    if head[0..4] == UIMAGE_MAGIC {
        return S19kBmuPayloadKind::Uimage;
    }
    if head[0] == 0x1F && head[1] == 0x8B {
        return S19kBmuPayloadKind::Gzip;
    }
    if head[0..4] == *b"\x7fELF" {
        return S19kBmuPayloadKind::Elf;
    }
    if head[0] == S19K_BTMU_MAGIC {
        return S19kBmuPayloadKind::NestedBtmu;
    }
    if !head[0].is_ascii_graphic() {
        return S19kBmuPayloadKind::HighEntropyOpaque;
    }
    S19kBmuPayloadKind::Unknown
}

pub fn refuse_s19k_bmu_payload_as_rootfs_uimage(
    kind: S19kBmuPayloadKind,
) -> Result<(), &'static str> {
    if kind != S19kBmuPayloadKind::Uimage {
        return Err(
            "BMU payload @ 0x4000 is not uImage (held 20231108 is high-entropy/ciphertext); refuse as mtd5 rootfs",
        );
    }
    Err("even a uImage inside a BMU needs FileParser split; refuse raw nandwrite")
}

pub fn s19k_bmu_pem_sig_present(blob: &[u8]) -> bool {
    if blob.len() < S19K_BMU_PEM_SIG_OFF + 4 {
        return false;
    }
    blob[S19K_BMU_PEM_SIG_OFF..S19K_BMU_PEM_SIG_OFF + 4]
        .iter()
        .any(|&b| b != 0)
}

pub fn admit_s19k_20231108_miner_pem(blob: &[u8]) -> Result<(), &'static str> {
    let off = S19K_20231108_MINER_PEM_OFF;
    let len = S19K_20231108_MINER_PEM_LEN;
    if blob.len() >= 0x18 && blob.len() >= off + S19K_20231108_MINER_PEM_BEGIN.len() {
        if &blob[off..off + S19K_20231108_MINER_PEM_BEGIN.len()] != S19K_20231108_MINER_PEM_BEGIN {
            if !blob
                .windows(S19K_20231108_MINER_PEM_BEGIN.len())
                .any(|w| w == S19K_20231108_MINER_PEM_BEGIN)
            {
                return Err("20231108 BMU miner.pem must start with BEGIN PUBLIC KEY");
            }
        }
    } else if !blob
        .windows(S19K_20231108_MINER_PEM_BEGIN.len())
        .any(|w| w == S19K_20231108_MINER_PEM_BEGIN)
    {
        return Err("20231108 BMU miner.pem must start with BEGIN PUBLIC KEY");
    }
    if blob.len() >= 0x18 {
        let declared = u16::from_be_bytes([blob[0x16], blob[0x17]]) as usize;
        if declared != 0 && declared != len {
            return Err("20231108 miner_pem_len at 0x16 is 451");
        }
    }
    Ok(())
}

pub fn admit_s19k_20231108_pem_sig_head(blob: &[u8]) -> Result<(), &'static str> {
    let off = S19K_BMU_PEM_SIG_OFF;
    if blob.len() >= off + 4 && blob[off..off + 4] == S19K_20231108_PEM_SIG_HEAD {
        return Ok(());
    }
    if blob.windows(4).any(|w| w == S19K_20231108_PEM_SIG_HEAD) {
        return Ok(());
    }
    Err("20231108 miner.pem.sig starts 02 2e 5a e0")
}

pub fn admit_held_fileparser_uses_sha256_rsa_verify(src: &str) -> Result<(), &'static str> {
    if !src.contains(HELD_FILEPARSER_SHA256_INIT) || !src.contains(HELD_FILEPARSER_RSA_VERIFY) {
        return Err("FileParser must import SHA256_Init and RSA_verify");
    }
    if !src.contains(HELD_FILEPARSER_PEM_READ) {
        return Err("FileParser must import PEM_read_bio_RSA_PUBKEY");
    }
    Ok(())
}

pub fn admit_s19k_held_root_does_not_verify_pem_sig(verified: bool) -> Result<(), &'static str> {
    if verified || S19K_MINER_PEM_SIG_HELD_ROOT_VERIFIED {
        return Err(
            "held CVCtrl/HashSource bitmain.pub PKCS1v15 SHA256/SHA1 must not be recorded as verifying 20231108 miner.pem.sig",
        );
    }
    Ok(())
}

pub fn refuse_s19k_unverified_pem_sig_as_nand_grant() -> Result<(), &'static str> {
    Err("unverified miner.pem.sig is BMU authenticity material, not a nandwrite grant")
}

pub fn refuse_s19k_cvctrl_pub_as_miner_pem(same_key: bool) -> Result<(), &'static str> {
    if same_key {
        return Ok(());
    }
    Err("CVCtrl /etc/bitmain.pub modulus is not the 20231108 miner.pem key")
}

pub fn s19k_bmu_offset_24_is_pem_not_toc(head: &[u8]) -> bool {
    head.len() >= S19K_BMU_FALSE_TOC_OFF + S19K_BMU_FALSE_TOC_ASCII.len()
        && &head[S19K_BMU_FALSE_TOC_OFF..S19K_BMU_FALSE_TOC_OFF + S19K_BMU_FALSE_TOC_ASCII.len()]
            == S19K_BMU_FALSE_TOC_ASCII
}

pub fn refuse_s19k_bmu_extraction_notes_as_toc() -> Result<(), &'static str> {
    Err(
        "stock-20231108 extraction_notes rec_count=3/rec_size=0xac at 0x24 is miner.pem, not a file TOC",
    )
}

/// A BMU is a signed container. nandwrite of the file to mtd5 is not restore.
pub fn refuse_s19k_bmu_as_raw_nand_image(kind: S19kUpgradeBlobKind) -> Result<(), &'static str> {
    if kind == S19kUpgradeBlobKind::StockBitmainBmu {
        return Err(
            "BMU is magic 0x26 + miner.pem + opaque payload @ 0x4000; refuse nandwrite of the BMU to mtd5",
        );
    }
    Ok(())
}

pub fn classify_s19k_upgrade_blob(name: &str, head: &[u8]) -> S19kUpgradeBlobKind {
    let lower = name.to_ascii_lowercase();
    if lower.contains("partition_emmc")
        || lower == "boot.emmc"
        || lower.contains("sd2nand")
        || lower.contains("cvctrl") && lower.contains("s19k")
    {
        return S19kUpgradeBlobKind::CvitekSd2NandFactory;
    }
    if lower.ends_with(".bmu")
        || lower.ends_with("update.bmu")
        || head.first() == Some(&S19K_BTMU_MAGIC)
    {
        return S19kUpgradeBlobKind::StockBitmainBmu;
    }
    if lower.contains("aml_upgrade")
        || lower.contains("aml_sdc_burn")
        || (lower.contains("aml-19k") && lower.contains("sd-card"))
        || lower.contains("aml-19k-pro")
    {
        return S19kUpgradeBlobKind::AmlFactoryEnc;
    }
    if lower.contains("recover-bmu") && lower.contains("s19k") {
        return S19kUpgradeBlobKind::XilSdRecoverFactory;
    }
    if lower.contains("sysupgrade")
        && (lower.ends_with(".tar") || lower.ends_with(".tar.gz") || lower.ends_with(".tgz"))
    {
        return S19kUpgradeBlobKind::DcentSysupgradeTar;
    }
    if head.len() >= 4 && head[0..4] == UIMAGE_MAGIC {
        return S19kUpgradeBlobKind::UimageRootfs;
    }
    S19kUpgradeBlobKind::Unknown
}

/// Factory SD burn (`erase_bootloader=1`) is a board wipe, not DCENT sysupgrade.
pub fn refuse_aml_sdc_burn_as_dcent(ini: &str) -> Result<(), &'static str> {
    let compact: String = ini.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.to_ascii_lowercase().contains("erase_bootloader=1") {
        return Err(
            "aml_sdc_burn erase_bootloader=1 wipes the control board; not a DCENT sysupgrade",
        );
    }
    Ok(())
}

/// Held `AML-19k-Pro-202311151447-sd-card.zip` members. Not `updateporc.sh`.
pub const S19K_AML_FACTORY_SD_INI_BYTES: usize = 602;
pub const S19K_AML_FACTORY_SD_UBOOT_BYTES: usize = 818_688;
pub const S19K_AML_FACTORY_SD_IMG_BYTES: usize = 23_134_392;
pub const S19K_AML_FACTORY_SD_ARCHIVE_BYTES: usize = 23_470_887;
pub const S19K_AML_FACTORY_SD_ARCHIVE_SHA256: &str =
    "46214d02b3c246ad4f98bcbe50b83705392a23a9fa5007120cb21d033e98dcf4";
pub const S19K_AML_FACTORY_SD_INI_SHA256: &str =
    "23026acac61ff4144e0e70521a91f7d527fd3bb8c31d22efce980900ebf2c5f0";
pub const S19K_AML_FACTORY_SD_UBOOT_SHA256: &str =
    "546ca8c4540ab584792716b2871d42ee304f594880f8c907e1018f68f6ab9cbc";
pub const S19K_AML_FACTORY_SD_IMG_SHA256: &str =
    "539da235cdf816a2cbfbf2037b056ad1b2dc5ab704efc97ed0050e6e0b313678";
pub const S19K_AML_FACTORY_SD_TOC_SHA256: &str =
    "efb21fd2d67e651a4ac2d4558a21099ccab250df73032b1c0acecee78cda20d8";
pub const S19K_AML_FACTORY_SD_MEMBERS: &[&str] = &[
    "aml_sdc_burn.ini",
    "aml_sdc_burn.UBOOT.ENC",
    "aml_upgrade_package_enc.img",
];
/// VNish S19k `aml_sdc_burn.UBOOT.ENC` is a Git LFS pointer, not factory U-Boot.
pub const VNISH_AML_SD_UBOOT_POINTER_BYTES: usize = 131;
/// Shared VNish `aml_upgrade_package_enc.img` across S19j+/S19j Pro/S21/T21/S19k VNish SD.
pub const VNISH_SHARED_AML_UPGRADE_IMG_BYTES: usize = 22_991_024;
/// `sd-recover-bmu-s19k-pro-202311151452` `uImage` is ARM32 Xilinx, not AML aarch64.
pub const S19K_XIL_SD_RECOVER_UIMAGE_BYTES: usize = HELD_S19PRO_UIMAGE_BYTES;
pub const S19K_XIL_SD_RECOVER_UIMAGE_NAME: &str = "Linux-4.6.0-xilinx-g77a5f591";
pub const S19K_SD_RECOVER_BMU_BYTES: usize = 18_113_781;
pub const S19K_AML_FACTORY_SD_PACKAGE: &str = "aml_upgrade_package_enc.img";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kAmlSdcBurnIni {
    pub erase_bootloader: bool,
    pub erase_flash: bool,
    pub reboot: bool,
    pub package_is_enc_img: bool,
}

/// Parse the exact functional grammar of the held S19k factory INI.
///
/// Whole-line `;`/`#` comments are ignored. Sections, keys, and values are
/// otherwise exact; duplicates, unknown directives, misplaced directives,
/// and conflicting shadow values all fail closed. The outer evidence contract
/// separately binds the complete 602-byte file hash, including comments.
pub fn parse_s19k_aml_sdc_burn_ini(ini: &str) -> Result<S19kAmlSdcBurnIni, &'static str> {
    #[derive(Clone, Copy)]
    enum Section {
        None,
        Common,
        BurnEx,
    }

    let mut section = Section::None;
    let mut common_seen = false;
    let mut burn_ex_seen = false;
    let mut erase_bootloader = None;
    let mut erase_flash = None;
    let mut reboot = None;
    let mut package = None;

    for raw in ini.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            section = match line {
                "[common]" if !common_seen => {
                    common_seen = true;
                    Section::Common
                }
                "[burn_ex]" if !burn_ex_seen => {
                    burn_ex_seen = true;
                    Section::BurnEx
                }
                "[common]" | "[burn_ex]" => {
                    return Err("aml_sdc_burn.ini contains a duplicate section");
                }
                _ => return Err("aml_sdc_burn.ini contains an unknown section"),
            };
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or("aml_sdc_burn.ini directive must contain one equals sign")?;
        let key = key.trim();
        let value = value.trim();
        match (section, key) {
            (Section::Common, "erase_bootloader") if erase_bootloader.is_none() => {
                erase_bootloader = Some(value)
            }
            (Section::Common, "erase_flash") if erase_flash.is_none() => erase_flash = Some(value),
            (Section::Common, "reboot") if reboot.is_none() => reboot = Some(value),
            (Section::BurnEx, "package") if package.is_none() => package = Some(value),
            (Section::Common, "erase_bootloader" | "erase_flash" | "reboot")
            | (Section::BurnEx, "package") => {
                return Err("aml_sdc_burn.ini contains a duplicate directive");
            }
            (Section::None, _) => {
                return Err("aml_sdc_burn.ini directive appears before a section");
            }
            _ => return Err("aml_sdc_burn.ini contains an unknown or misplaced directive"),
        }
    }
    if !common_seen || !burn_ex_seen {
        return Err("aml_sdc_burn.ini requires one [common] and one [burn_ex]");
    }
    if erase_bootloader != Some("1")
        || erase_flash != Some("1")
        || reboot != Some("1")
        || package != Some(S19K_AML_FACTORY_SD_PACKAGE)
    {
        return Err("S19k stock factory INI must exact full-erase, reboot, and encrypted package");
    }
    Ok(S19kAmlSdcBurnIni {
        erase_bootloader: true,
        erase_flash: true,
        reboot: true,
        package_is_enc_img: true,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kAmlSdPackKind {
    /// Stock `AML-19k-Pro-202311151447-sd-card.zip`: 818688 U-Boot + unique 23134392 img.
    StockS19kFactorySd,
    /// VNish SD: 131-byte LFS pointer + shared 22991024 img. Not S19k stock.
    VnishSharedLfsPointer,
    /// Other AML SD sizes (S19j 22997160, S21, …). Comparative only.
    ComparativeOtherAml,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kAmlFactorySdEvidence<'a> {
    pub kind: S19kAmlSdPackKind,
    pub archive_bytes: usize,
    pub archive_sha256: &'a str,
    pub members: &'a [&'a str],
    pub ini_bytes: usize,
    pub ini_sha256: &'a str,
    pub uboot_bytes: usize,
    pub uboot_sha256: &'a str,
    pub img_bytes: usize,
    pub img_sha256: &'a str,
    pub toc_sha256: &'a str,
    pub upgrade_header: S19kAmlUpgradeHeader,
}

pub fn admit_s19k_aml_factory_sd_evidence(
    evidence: S19kAmlFactorySdEvidence<'_>,
) -> Result<(), &'static str> {
    if evidence.kind != S19kAmlSdPackKind::StockS19kFactorySd {
        return Err("factory stock-return plan requires exact StockS19kFactorySd kind");
    }
    if evidence.archive_bytes != S19K_AML_FACTORY_SD_ARCHIVE_BYTES
        || evidence.archive_sha256 != S19K_AML_FACTORY_SD_ARCHIVE_SHA256
    {
        return Err("S19k AML factory archive size/hash mismatch");
    }
    if evidence.members != S19K_AML_FACTORY_SD_MEMBERS {
        return Err("S19k AML factory archive must contain exactly three canonical members");
    }
    if evidence.ini_bytes != S19K_AML_FACTORY_SD_INI_BYTES
        || evidence.ini_sha256 != S19K_AML_FACTORY_SD_INI_SHA256
        || evidence.uboot_bytes != S19K_AML_FACTORY_SD_UBOOT_BYTES
        || evidence.uboot_sha256 != S19K_AML_FACTORY_SD_UBOOT_SHA256
        || evidence.img_bytes != S19K_AML_FACTORY_SD_IMG_BYTES
        || evidence.img_sha256 != S19K_AML_FACTORY_SD_IMG_SHA256
    {
        return Err("S19k AML factory member size/hash mismatch");
    }
    if evidence.toc_sha256 != S19K_AML_FACTORY_SD_TOC_SHA256 {
        return Err("S19k AML factory 11008-byte TOC hash mismatch");
    }
    admit_s19k_aml_upgrade_header(evidence.upgrade_header)
}

pub fn classify_s19k_aml_sd_pack(uboot_len: usize, img_len: usize) -> S19kAmlSdPackKind {
    if uboot_len == S19K_AML_FACTORY_SD_UBOOT_BYTES && img_len == S19K_AML_FACTORY_SD_IMG_BYTES {
        S19kAmlSdPackKind::StockS19kFactorySd
    } else if uboot_len == VNISH_AML_SD_UBOOT_POINTER_BYTES
        && img_len == VNISH_SHARED_AML_UPGRADE_IMG_BYTES
    {
        S19kAmlSdPackKind::VnishSharedLfsPointer
    } else {
        S19kAmlSdPackKind::ComparativeOtherAml
    }
}

pub fn refuse_vnish_lfs_uboot_as_s19k_factory(uboot_len: usize) -> Result<(), &'static str> {
    if uboot_len == VNISH_AML_SD_UBOOT_POINTER_BYTES {
        return Err(
            "VNish aml_sdc_burn.UBOOT.ENC is 131-byte Git LFS pointer; not S19k factory 818688 U-Boot",
        );
    }
    Ok(())
}

pub fn refuse_vnish_shared_img_as_s19k_stock(img_len: usize) -> Result<(), &'static str> {
    if img_len == VNISH_SHARED_AML_UPGRADE_IMG_BYTES {
        return Err("VNish shared 22991024 aml_upgrade_package_enc.img is not S19k stock 23134392");
    }
    Ok(())
}

pub fn refuse_s19k_aml_factory_sd_as_dcent_sysupgrade(
    kind: S19kAmlSdPackKind,
) -> Result<(), &'static str> {
    match kind {
        S19kAmlSdPackKind::StockS19kFactorySd => Err(
            "AML-19k-Pro-202311151447-sd-card is factory aml_sdc_burn (erase_bootloader=1); not DCENT NAND sysupgrade",
        ),
        S19kAmlSdPackKind::VnishSharedLfsPointer => Err(
            "VNish AML SD is LFS-pointer U-Boot + shared img; not S19k stock and not DCENT sysupgrade",
        ),
        S19kAmlSdPackKind::ComparativeOtherAml => Err(
            "comparative AML SD pack is not S19k stock factory and not DCENT sysupgrade",
        ),
    }
}

pub fn refuse_s19k_aml_factory_sd_as_nandrecovery_env(name: &str) -> Result<(), &'static str> {
    let lower = name.to_ascii_lowercase();
    if lower.contains("aml_upgrade")
        || lower.contains("aml_sdc_burn")
        || (lower.contains("aml-19k") && lower.contains("sd-card"))
    {
        return Err(
            "aml_upgrade_package_enc.img / AML-19k SD is factory burn, not nandrecovery_env",
        );
    }
    Ok(())
}

pub fn refuse_s19k_xil_sd_recover_as_aml_nand(
    kind: S19kUpgradeBlobKind,
) -> Result<(), &'static str> {
    if kind == S19kUpgradeBlobKind::XilSdRecoverFactory {
        return Err("sd-recover-bmu-s19k-pro is Xilinx uImage+update.bmu; refuse as am3-s19k NAND");
    }
    Ok(())
}

pub fn refuse_s19k_xil_recover_uimage_as_aml_nand(
    bytes: usize,
    ih_name: &str,
) -> Result<(), &'static str> {
    if bytes == S19K_XIL_SD_RECOVER_UIMAGE_BYTES && ih_name.contains("xilinx") {
        return Err("sd-recover-bmu uImage is ARM32 Linux-4.6.0-xilinx; S19k AML is aarch64");
    }
    Ok(())
}

/// Plan-only. Factory SD burn is not NAND write and not updateporc.
pub fn format_s19k_aml_factory_sd_plan(
    evidence: S19kAmlFactorySdEvidence<'_>,
    ini: S19kAmlSdcBurnIni,
) -> Result<String, &'static str> {
    if !ini.erase_bootloader || !ini.erase_flash || !ini.package_is_enc_img {
        return Err(
            "S19k AML factory SD plan requires erase_bootloader=1 erase_flash=1 package=img",
        );
    }
    admit_s19k_aml_factory_sd_evidence(evidence)?;
    Ok(format!(
        "schema=dcentos.amlogic-factory-sd/v1\n\
kind={kind:?}\n\
archive_bytes={archive_bytes}\n\
archive_sha256={archive_sha}\n\
members=aml_sdc_burn.ini,aml_sdc_burn.UBOOT.ENC,aml_upgrade_package_enc.img\n\
ini_bytes={ini_bytes}\n\
ini_sha256={ini_sha}\n\
uboot_bytes={uboot}\n\
uboot_sha256={uboot_sha}\n\
img_bytes={img}\n\
img_sha256={sha}\n\
toc_sha256={toc_sha}\n\
package={pkg}\n\
erase_bootloader={eb}\n\
erase_flash={ef}\n\
reboot={rb}\n\
classification=vendor-encrypted-amlogic-sd-full-erase\n\
factory_toc_scope=_aml_dtb+boot+bootloader+recovery+conf-keys+platform\n\
unit_specific_state_restore=false\n\
destroyed_state=/config+/nvdata+/miner+device-calibration\n\
media_preparation=evidence-bounded-dedicated-fat32+exact-three-root-members\n\
required_preburn_backup=dcentos.s19k-aml-full-logical-rescue/v1+six-mtd-hashes+stable-badblock-counts+boot-nand-transcript+encrypted-offhost-copy\n\
preburn_backup_is_physical_replay=false\n\
required_unit_state_restore=config+nvdata+miner+eeprom+calibration-import-live-unproven\n\
bench_sequence=verify-FULL_RESCUE_LEDGER.txt+validate-unit-state-restore+power-off+insert-card+power-on+do-not-interrupt+verify-stock-version\n\
live_choreography=usb-button-completion-signal-unproven\n\
linux_raw_restore_equivalent=false\n\
updateporc=false\n\
nandrecovery_env=false\n\
nandwrite=false\n\
execute=false\n\
clear_for_flash=false\n\
reason=CLEAR_FOR_FLASH\n",
        kind = evidence.kind,
        archive_bytes = S19K_AML_FACTORY_SD_ARCHIVE_BYTES,
        archive_sha = S19K_AML_FACTORY_SD_ARCHIVE_SHA256,
        ini_bytes = S19K_AML_FACTORY_SD_INI_BYTES,
        ini_sha = S19K_AML_FACTORY_SD_INI_SHA256,
        uboot = S19K_AML_FACTORY_SD_UBOOT_BYTES,
        uboot_sha = S19K_AML_FACTORY_SD_UBOOT_SHA256,
        img = S19K_AML_FACTORY_SD_IMG_BYTES,
        sha = S19K_AML_FACTORY_SD_IMG_SHA256,
        toc_sha = S19K_AML_FACTORY_SD_TOC_SHA256,
        pkg = S19K_AML_FACTORY_SD_PACKAGE,
        eb = ini.erase_bootloader as u8,
        ef = ini.erase_flash as u8,
        rb = ini.reboot as u8,
    ))
}

pub fn admit_s19k_aml_factory_sd_execute() -> Result<(), &'static str> {
    if !CLEAR_FOR_FLASH {
        return Err("AML factory SD --execute is CLEAR_FOR_FLASH=false; refuse NAND/eMMC burn");
    }
    Err("AML factory SD --execute is CLEAR_FOR_FLASH=false; refuse NAND/eMMC burn")
}

/// AmlImagePack v2 magic (`56 19 B5 27`). Same as TNA S19-XP / bible packs.
pub const S19K_AML_UPGRADE_MAGIC: u32 = 0x27B5_1956;
/// CRC field of held S19k factory `aml_upgrade_package_enc.img`. Not bible S19/S21/T21.
pub const S19K_AML_UPGRADE_CRC: u32 = 0x1CCB_07DA;
pub const : u32 = 0x9C6E_1B2C;
pub const : u32 = 0xF61B_B630;
pub const : u32 = 0x7BF6_F59F;
pub const S19K_AML_UPGRADE_VERSION: u32 = 2;
pub const S19K_AML_UPGRADE_ITEM_NUM: u32 = 19;
pub const S19K_AML_UPGRADE_ITEM_ALIGN: u32 = 8;
/// 256-byte type fields. 0x80 (32-byte types) is the wrong published stride.
pub const S19K_AML_UPGRADE_ITEM_STRIDE: usize = 0x240;
pub const S19K_AML_UPGRADE_HEADER_LEN: usize = 0x40;
pub const S19K_AML_UPGRADE_TOC_BYTES: usize = S19K_AML_UPGRADE_HEADER_LEN
    + (S19K_AML_UPGRADE_ITEM_NUM as usize) * S19K_AML_UPGRADE_ITEM_STRIDE;
pub const S19K_AML_UPGRADE_ITEM2_USB_UBOOT_OFF: u64 = 109_312;
pub const S19K_AML_UPGRADE_ITEM2_USB_UBOOT_SIZE: u64 = 769_024;
pub const S19K_AML_UPGRADE_ITEM4_AML_DTB_OFF: u64 = 1_647_360;
pub const S19K_AML_UPGRADE_ITEM4_AML_DTB_SIZE: u64 = 29_728;
/// ASCII VERIFY item: `sha1sum ` + 40 hex. Matches sha1(item4).
pub const S19K_AML_VERIFY_PREFIX: &[u8] = b"sha1sum ";
pub const S19K_AML_VERIFY_ITEM_BYTES: usize = 48;
pub const S19K_AML_DTB_ENC_SHA1_HEX: &[u8; 40] = b"8e1890fd2c43f6e7e10cc04b23c2073e88d7ab1b";
pub const S19K_AML_BOOT_SHA1_HEX: &[u8; 40] = b"97107df8e67ce465c3d71a7816d32b7b86f71d8e";
pub const S19K_AML_BOOTLOADER_SHA1_HEX: &[u8; 40] = b"377d37642c69b9b7665cac669361693755bec457";
pub const S19K_AML_RECOVERY_SHA1_HEX: &[u8; 40] = b"b6441d919a9e3c2ad6e503fe21b6ca0e361ac4c3";
pub const S19K_AML_UPGRADE_ITEM5_VERIFY_DTB_OFF: u64 = 1_677_088;
pub const S19K_AML_UPGRADE_ITEM10_VERIFY_BOOT_OFF: u64 = 16_222_128;
pub const S19K_AML_UPGRADE_ITEM11_BOOTLOADER_OFF: u64 = 16_222_176;
pub const S19K_AML_UPGRADE_ITEM11_BOOTLOADER_SIZE: u64 = 818_688;
pub const S19K_AML_UPGRADE_ITEM12_VERIFY_BL_OFF: u64 = 17_040_864;
pub const S19K_AML_UPGRADE_ITEM18_VERIFY_REC_OFF: u64 = 23_134_344;
pub const S19K_AML_UPGRADE_ITEM7_UBOOT_ENC_OFF: u64 = 2_495_824;
pub const S19K_AML_UPGRADE_ITEM7_UBOOT_ENC_SIZE: u64 = 818_688;
pub const S19K_AML_UPGRADE_ITEM14_MESON1_OFF: u64 = 17_040_928;
pub const S19K_AML_UPGRADE_ITEM14_MESON1_SIZE: u64 = 28_568;
pub const S19K_AML_UPGRADE_ITEM9_BOOT_OFF: u64 = 3_315_120;
pub const S19K_AML_UPGRADE_ITEM9_BOOT_SIZE: u64 = 12_907_008;
pub const S19K_AML_UPGRADE_ITEM17_RECOVERY_OFF: u64 = 17_069_704;
pub const S19K_AML_UPGRADE_ITEM17_RECOVERY_SIZE: u64 = 6_064_640;
/// Held factory TOC PARTITION/sub names. Not config/misc/nvdata/tpl.
pub const S19K_FACTORY_PARTITION_SUBS: &[&str] = &["_aml_dtb", "boot", "bootloader", "recovery"];
/// s30v/BOS slots the factory SD cannot restock.
pub const S19K_FACTORY_RESTOCK_MISSING: &[&str] = &["config", "misc", "nvdata", "tpl"];
pub const S19K_AML_UPGRADE_PLATFORM: &str = "Platform:0x0811";
pub const S19K_AML_UPGRADE_SECURE_BOOT: &str = "secure_boot_set";
/// USB UBOOT / SD-burn UBOOT identity. Not a 4cc0/ko string.
pub const S19K_AML_UPGRADE_UBOOT_IDENTITY: &str = "S19k-Pro_BHB56XXX";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kAmlUpgradeHeader {
    pub crc: u32,
    pub version: u32,
    pub magic: u32,
    pub image_sz: u64,
    pub item_align: u32,
    pub item_num: u32,
}

/// Parse the 0x40 AmlImagePack v2 header. Does not decrypt.
pub fn parse_s19k_aml_upgrade_header(head: &[u8]) -> Result<S19kAmlUpgradeHeader, &'static str> {
    if head.len() < S19K_AML_UPGRADE_HEADER_LEN {
        return Err("AmlImagePack header is 0x40 bytes");
    }
    let crc = u32::from_le_bytes(head[0..4].try_into().unwrap());
    let version = u32::from_le_bytes(head[4..8].try_into().unwrap());
    let magic = u32::from_le_bytes(head[8..12].try_into().unwrap());
    let image_sz = u64::from_le_bytes(head[12..20].try_into().unwrap());
    let item_align = u32::from_le_bytes(head[20..24].try_into().unwrap());
    let item_num = u32::from_le_bytes(head[24..28].try_into().unwrap());
    if magic != S19K_AML_UPGRADE_MAGIC {
        return Err("not AmlImagePack v2 magic 0x27b51956");
    }
    if version != S19K_AML_UPGRADE_VERSION {
        return Err("S19k factory pack version is 2");
    }
    Ok(S19kAmlUpgradeHeader {
        crc,
        version,
        magic,
        image_sz,
        item_align,
        item_num,
    })
}

pub fn admit_s19k_aml_upgrade_header(h: S19kAmlUpgradeHeader) -> Result<(), &'static str> {
    if h.crc != S19K_AML_UPGRADE_CRC {
        return Err("S19k factory CRC is 0x1ccb07da, not bible S19/S21/T21");
    }
    if h.image_sz != S19K_AML_FACTORY_SD_IMG_BYTES as u64 {
        return Err("S19k factory imageSz must be 23134392");
    }
    if h.item_num != S19K_AML_UPGRADE_ITEM_NUM || h.item_align != S19K_AML_UPGRADE_ITEM_ALIGN {
        return Err("S19k factory TOC is 19 items, align 8");
    }
    Ok(())
}

pub fn refuse_bible_aml_crc_as_s19k_factory(crc: u32) -> Result<(), &'static str> {
    if crc == 
        || crc == 
        || crc == 
    {
        return Err("bible S19/S21/T21 AmlImagePack CRC is not the S19k factory pack");
    }
    Ok(())
}

pub fn refuse_s19k_aml_crc_as_decrypt_key() -> Result<(), &'static str> {
    Err("AmlImagePack CRC field is a header checksum, not an OTP AES key; no offline decrypt")
}

pub fn refuse_aml_img_80_stride_as_s19k_toc(stride: usize) -> Result<(), &'static str> {
    if stride == 0x80 {
        return Err("S19k factory TOC uses 0x240 stride (256-byte types), not 0x80");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kAmlUpgradeItem {
    pub id: u32,
    pub main: String,
    pub sub: String,
    pub offset: u64,
    pub size: u64,
}

fn aml_item_cstr(buf: &[u8]) -> String {
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Parse one 0x240-byte TOC entry.
pub fn parse_s19k_aml_upgrade_item(entry: &[u8]) -> Result<S19kAmlUpgradeItem, &'static str> {
    if entry.len() < S19K_AML_UPGRADE_ITEM_STRIDE {
        return Err("AmlImagePack item is 0x240 bytes");
    }
    let id = u32::from_le_bytes(entry[0..4].try_into().unwrap());
    let offset = u64::from_le_bytes(entry[0x10..0x18].try_into().unwrap());
    let size = u64::from_le_bytes(entry[0x18..0x20].try_into().unwrap());
    Ok(S19kAmlUpgradeItem {
        id,
        main: aml_item_cstr(&entry[0x20..0x120]),
        sub: aml_item_cstr(&entry[0x120..0x220]),
        offset,
        size,
    })
}

pub fn admit_s19k_aml_upgrade_uboot_enc_item(
    item: &S19kAmlUpgradeItem,
) -> Result<(), &'static str> {
    if item.main != "UBOOT.ENC" || item.sub != "aml_sdc_burn" {
        return Err("item 7 is UBOOT.ENC/aml_sdc_burn");
    }
    if item.offset != S19K_AML_UPGRADE_ITEM7_UBOOT_ENC_OFF
        || item.size != S19K_AML_UPGRADE_ITEM7_UBOOT_ENC_SIZE
    {
        return Err("S19k UBOOT.ENC item is 818688 B at 2495824");
    }
    Ok(())
}

pub fn admit_s19k_aml_upgrade_usb_uboot_item(
    item: &S19kAmlUpgradeItem,
) -> Result<(), &'static str> {
    if item.main != "USB" || item.sub != "UBOOT" {
        return Err("item 2 is USB/UBOOT");
    }
    if item.offset != S19K_AML_UPGRADE_ITEM2_USB_UBOOT_OFF
        || item.size != S19K_AML_UPGRADE_ITEM2_USB_UBOOT_SIZE
    {
        return Err("S19k USB UBOOT is 769024 B at 109312");
    }
    Ok(())
}

pub fn admit_s19k_aml_upgrade_meson1_item(item: &S19kAmlUpgradeItem) -> Result<(), &'static str> {
    if item.main != "dtb" || item.sub != "meson1" {
        return Err("item 14 is dtb/meson1");
    }
    if item.offset != S19K_AML_UPGRADE_ITEM14_MESON1_OFF
        || item.size != S19K_AML_UPGRADE_ITEM14_MESON1_SIZE
    {
        return Err("S19k dtb/meson1 gzip is 28568 B at 17040928");
    }
    Ok(())
}

pub fn admit_s19k_aml_upgrade_boot_item(item: &S19kAmlUpgradeItem) -> Result<(), &'static str> {
    if item.main != "PARTITION" || item.sub != "boot" {
        return Err("item 9 is PARTITION/boot");
    }
    if item.offset != S19K_AML_UPGRADE_ITEM9_BOOT_OFF
        || item.size != S19K_AML_UPGRADE_ITEM9_BOOT_SIZE
    {
        return Err("S19k PARTITION/boot is 12907008 B at 3315120");
    }
    Ok(())
}

pub fn admit_s19k_aml_upgrade_recovery_item(item: &S19kAmlUpgradeItem) -> Result<(), &'static str> {
    if item.main != "PARTITION" || item.sub != "recovery" {
        return Err("item 17 is PARTITION/recovery");
    }
    if item.offset != S19K_AML_UPGRADE_ITEM17_RECOVERY_OFF
        || item.size != S19K_AML_UPGRADE_ITEM17_RECOVERY_SIZE
    {
        return Err("S19k PARTITION/recovery is 6064640 B at 17069704");
    }
    Ok(())
}

/// Item 4 `PARTITION/_aml_dtb` is not the gzip meson1 (item 14).
pub fn refuse_s19k_aml_dtb_partition_as_gzip_meson1(head: &[u8]) -> Result<(), &'static str> {
    if head.len() >= 2 && head[0] == 0x1F && head[1] == 0x8B {
        return Ok(());
    }
    Err("PARTITION/_aml_dtb is not gzip meson1; item 14 is the gzip meson1")
}

pub fn admit_s19k_aml_upgrade_aml_dtb_item(item: &S19kAmlUpgradeItem) -> Result<(), &'static str> {
    if item.main != "PARTITION" || item.sub != "_aml_dtb" {
        return Err("item 4 is PARTITION/_aml_dtb");
    }
    if item.offset != S19K_AML_UPGRADE_ITEM4_AML_DTB_OFF
        || item.size != S19K_AML_UPGRADE_ITEM4_AML_DTB_SIZE
    {
        return Err("S19k PARTITION/_aml_dtb is 29728 B at 1647360");
    }
    Ok(())
}

pub fn admit_s19k_aml_upgrade_meson1_enc_item(
    item: &S19kAmlUpgradeItem,
) -> Result<(), &'static str> {
    if item.main != "dtb" || item.sub != "meson1_ENC" {
        return Err("item 15 is dtb/meson1_ENC");
    }
    if item.offset != S19K_AML_UPGRADE_ITEM4_AML_DTB_OFF
        || item.size != S19K_AML_UPGRADE_ITEM4_AML_DTB_SIZE
    {
        return Err("meson1_ENC is the same 29728 B blob as PARTITION/_aml_dtb");
    }
    Ok(())
}

pub fn admit_s19k_aml_dtb_alias_meson1_enc(
    dtb: &S19kAmlUpgradeItem,
    enc: &S19kAmlUpgradeItem,
) -> Result<(), &'static str> {
    if dtb.offset != enc.offset || dtb.size != enc.size {
        return Err("item 4 and item 15 must share offset/size");
    }
    admit_s19k_aml_upgrade_aml_dtb_item(dtb)?;
    admit_s19k_aml_upgrade_meson1_enc_item(enc)?;
    Ok(())
}

/// Parse `sha1sum <40 hex>` (48 B VERIFY item).
pub fn parse_s19k_aml_verify_item(blob: &[u8]) -> Result<[u8; 20], &'static str> {
    if blob.len() != S19K_AML_VERIFY_ITEM_BYTES {
        return Err("AmlImagePack VERIFY item is 48 bytes");
    }
    if !blob.starts_with(S19K_AML_VERIFY_PREFIX) {
        return Err("VERIFY item is ASCII sha1sum <hex>");
    }
    let hex = &blob[S19K_AML_VERIFY_PREFIX.len()..];
    if hex.len() != 40 {
        return Err("VERIFY sha1 hex is 40 chars");
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        let hi = hex_nibble(hex[i * 2])?;
        let lo = hex_nibble(hex[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, &'static str> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("VERIFY sha1 hex is not 0-9a-f"),
    }
}

pub fn admit_s19k_aml_dtb_verify_hex(hex: &[u8]) -> Result<(), &'static str> {
    if hex == S19K_AML_DTB_ENC_SHA1_HEX {
        return Ok(());
    }
    Err("factory VERIFY/_aml_dtb sha1 is 8e1890fd2c43f6e7e10cc04b23c2073e88d7ab1b")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kAmlVerifyKind {
    AmlDtbEnc,
    Boot,
    Bootloader,
    Recovery,
}

pub fn classify_s19k_aml_verify_sub(sub: &str) -> Result<S19kAmlVerifyKind, &'static str> {
    match sub {
        "_aml_dtb" => Ok(S19kAmlVerifyKind::AmlDtbEnc),
        "boot" => Ok(S19kAmlVerifyKind::Boot),
        "bootloader" => Ok(S19kAmlVerifyKind::Bootloader),
        "recovery" => Ok(S19kAmlVerifyKind::Recovery),
        _ => Err("unknown AmlImagePack VERIFY sub"),
    }
}

pub fn classify_s19k_aml_verify_hex(hex: &[u8]) -> Result<S19kAmlVerifyKind, &'static str> {
    if hex == S19K_AML_DTB_ENC_SHA1_HEX {
        return Ok(S19kAmlVerifyKind::AmlDtbEnc);
    }
    if hex == S19K_AML_BOOT_SHA1_HEX {
        return Ok(S19kAmlVerifyKind::Boot);
    }
    if hex == S19K_AML_BOOTLOADER_SHA1_HEX {
        return Ok(S19kAmlVerifyKind::Bootloader);
    }
    if hex == S19K_AML_RECOVERY_SHA1_HEX {
        return Ok(S19kAmlVerifyKind::Recovery);
    }
    Err("unknown factory VERIFY sha1 hex")
}

pub fn admit_s19k_aml_verify_pair(
    sub: &str,
    hex: &[u8],
) -> Result<S19kAmlVerifyKind, &'static str> {
    let by_sub = classify_s19k_aml_verify_sub(sub)?;
    let by_hex = classify_s19k_aml_verify_hex(hex)?;
    if by_sub != by_hex {
        return Err("VERIFY sub and sha1 hex disagree");
    }
    Ok(by_sub)
}

pub fn admit_s19k_aml_upgrade_verify_item(
    item: &S19kAmlUpgradeItem,
    kind: S19kAmlVerifyKind,
) -> Result<(), &'static str> {
    if item.main != "VERIFY" || item.size != S19K_AML_VERIFY_ITEM_BYTES as u64 {
        return Err("VERIFY items are 48-byte sha1sum records");
    }
    let want = match kind {
        S19kAmlVerifyKind::AmlDtbEnc => ("_aml_dtb", S19K_AML_UPGRADE_ITEM5_VERIFY_DTB_OFF),
        S19kAmlVerifyKind::Boot => ("boot", S19K_AML_UPGRADE_ITEM10_VERIFY_BOOT_OFF),
        S19kAmlVerifyKind::Bootloader => ("bootloader", S19K_AML_UPGRADE_ITEM12_VERIFY_BL_OFF),
        S19kAmlVerifyKind::Recovery => ("recovery", S19K_AML_UPGRADE_ITEM18_VERIFY_REC_OFF),
    };
    if item.sub != want.0 || item.offset != want.1 {
        return Err("VERIFY item offset/sub mismatch");
    }
    Ok(())
}

pub fn admit_s19k_aml_upgrade_bootloader_item(
    item: &S19kAmlUpgradeItem,
) -> Result<(), &'static str> {
    if item.main != "PARTITION" || item.sub != "bootloader" {
        return Err("item 11 is PARTITION/bootloader");
    }
    if item.offset != S19K_AML_UPGRADE_ITEM11_BOOTLOADER_OFF
        || item.size != S19K_AML_UPGRADE_ITEM11_BOOTLOADER_SIZE
    {
        return Err("S19k PARTITION/bootloader is 818688 B at 16222176");
    }
    Ok(())
}

pub const S19K_AML_UPGRADE_ITEM6_UBOOT_OFF: u64 = 1_677_136;
pub const S19K_AML_UPGRADE_ITEM6_UBOOT_SIZE: u64 = 818_688;
pub const S19K_AML_UPGRADE_ITEM0_USB_DDR_OFF: u64 = 11_008;
pub const S19K_AML_UPGRADE_ITEM0_USB_DDR_SIZE: u64 = 49_152;
pub const S19K_AML_UPGRADE_ITEM1_USB_DDR_ENC_OFF: u64 = 60_160;
pub const S19K_AML_UPGRADE_ITEM1_USB_DDR_ENC_SIZE: u64 = 49_152;
pub const S19K_AML_UPGRADE_ITEM3_USB_UBOOT_ENC_OFF: u64 = 878_336;
pub const S19K_AML_UPGRADE_ITEM3_USB_UBOOT_ENC_SIZE: u64 = 769_024;
pub const S19K_AML_UPGRADE_ITEM8_INI_OFF: u64 = 3_314_512;
pub const S19K_AML_UPGRADE_ITEM8_INI_SIZE: u64 = 602;
pub const S19K_AML_UPGRADE_ITEM13_KEYS_OFF: u64 = 17_040_912;
pub const S19K_AML_UPGRADE_ITEM13_KEYS_SIZE: u64 = 16;
pub const S19K_AML_UPGRADE_ITEM16_PLATFORM_OFF: u64 = 17_069_496;
pub const S19K_AML_UPGRADE_ITEM16_PLATFORM_SIZE: u64 = 202;
pub const S19K_AML_UPGRADE_ENCRYPT_REG: u32 = 0xFF80_0228;
pub const S19K_AML_UPGRADE_KEYS_PAYLOAD: &[u8] = b"secure_boot_set\n";
pub const S19K_AML_UPGRADE_INI_PACKAGE: &[u8] = b"aml_upgrade_package.img";
pub const S19K_AML_UPGRADE_INI_ERASE_BL: &[u8] = b"erase_bootloader    = 1";
pub const S19K_AML_UPGRADE_ENCRYPT_REG_ASCII: &[u8] = b"Encrypt_reg:0xff800228";

pub fn admit_s19k_aml_upgrade_sdc_uboot_item(
    item: &S19kAmlUpgradeItem,
) -> Result<(), &'static str> {
    if item.main != "UBOOT" || item.sub != "aml_sdc_burn" {
        return Err("item 6 is UBOOT/aml_sdc_burn");
    }
    if item.offset != S19K_AML_UPGRADE_ITEM6_UBOOT_OFF
        || item.size != S19K_AML_UPGRADE_ITEM6_UBOOT_SIZE
    {
        return Err("S19k SDC UBOOT is 818688 B at 1677136");
    }
    Ok(())
}

pub fn admit_s19k_aml_upgrade_usb_ddr_item(item: &S19kAmlUpgradeItem) -> Result<(), &'static str> {
    if item.main != "USB" || item.sub != "DDR" {
        return Err("item 0 is USB/DDR");
    }
    if item.offset != S19K_AML_UPGRADE_ITEM0_USB_DDR_OFF
        || item.size != S19K_AML_UPGRADE_ITEM0_USB_DDR_SIZE
    {
        return Err("S19k USB/DDR is 49152 B at 11008");
    }
    Ok(())
}

pub fn admit_s19k_aml_upgrade_usb_ddr_enc_item(
    item: &S19kAmlUpgradeItem,
) -> Result<(), &'static str> {
    if item.main != "USB" || item.sub != "DDR_ENC" {
        return Err("item 1 is USB/DDR_ENC");
    }
    if item.offset != S19K_AML_UPGRADE_ITEM1_USB_DDR_ENC_OFF
        || item.size != S19K_AML_UPGRADE_ITEM1_USB_DDR_ENC_SIZE
    {
        return Err("S19k USB/DDR_ENC is 49152 B at 60160");
    }
    Ok(())
}

pub fn admit_s19k_aml_upgrade_usb_uboot_enc_item(
    item: &S19kAmlUpgradeItem,
) -> Result<(), &'static str> {
    if item.main != "USB" || item.sub != "UBOOT_ENC" {
        return Err("item 3 is USB/UBOOT_ENC");
    }
    if item.offset != S19K_AML_UPGRADE_ITEM3_USB_UBOOT_ENC_OFF
        || item.size != S19K_AML_UPGRADE_ITEM3_USB_UBOOT_ENC_SIZE
    {
        return Err("S19k USB/UBOOT_ENC is 769024 B at 878336");
    }
    Ok(())
}

pub fn admit_s19k_aml_upgrade_ini_item(item: &S19kAmlUpgradeItem) -> Result<(), &'static str> {
    if item.main != "ini" || item.sub != "aml_sdc_burn" {
        return Err("item 8 is ini/aml_sdc_burn");
    }
    if item.offset != S19K_AML_UPGRADE_ITEM8_INI_OFF || item.size != S19K_AML_UPGRADE_ITEM8_INI_SIZE
    {
        return Err("S19k ini/aml_sdc_burn is 602 B at 3314512");
    }
    Ok(())
}

pub fn admit_s19k_aml_upgrade_keys_item(item: &S19kAmlUpgradeItem) -> Result<(), &'static str> {
    if item.main != "conf" || item.sub != "keys" {
        return Err("item 13 is conf/keys");
    }
    if item.offset != S19K_AML_UPGRADE_ITEM13_KEYS_OFF
        || item.size != S19K_AML_UPGRADE_ITEM13_KEYS_SIZE
    {
        return Err("S19k conf/keys is 16 B at 17040912");
    }
    Ok(())
}

pub fn admit_s19k_aml_upgrade_platform_item(item: &S19kAmlUpgradeItem) -> Result<(), &'static str> {
    if item.main != "conf" || item.sub != "platform" {
        return Err("item 16 is conf/platform");
    }
    if item.offset != S19K_AML_UPGRADE_ITEM16_PLATFORM_OFF
        || item.size != S19K_AML_UPGRADE_ITEM16_PLATFORM_SIZE
    {
        return Err("S19k conf/platform is 202 B at 17069496");
    }
    Ok(())
}

pub fn admit_s19k_usb_ddr_enc_same_size(
    plain_len: usize,
    enc_len: usize,
) -> Result<(), &'static str> {
    if plain_len != S19K_AML_UPGRADE_ITEM0_USB_DDR_SIZE as usize
        || enc_len != S19K_AML_UPGRADE_ITEM1_USB_DDR_ENC_SIZE as usize
        || plain_len != enc_len
    {
        return Err("item 0 and item 1 are both 49152 B");
    }
    Ok(())
}

pub fn admit_s19k_usb_uboot_enc_same_size(
    plain_len: usize,
    enc_len: usize,
) -> Result<(), &'static str> {
    if plain_len != S19K_AML_UPGRADE_ITEM2_USB_UBOOT_SIZE as usize
        || enc_len != S19K_AML_UPGRADE_ITEM3_USB_UBOOT_ENC_SIZE as usize
        || plain_len != enc_len
    {
        return Err("item 2 and item 3 are both 769024 B");
    }
    Ok(())
}

pub fn admit_s19k_usb_enc_distinct(plain_eq_enc: bool) -> Result<(), &'static str> {
    if plain_eq_enc {
        return Err("USB ENC item must differ from its plaintext peer");
    }
    Ok(())
}

pub fn refuse_s19k_usb_ddr_enc_as_decrypt_key() -> Result<(), &'static str> {
    Err("USB/DDR_ENC ciphertext is not the OTP AES key")
}

pub fn refuse_s19k_usb_uboot_enc_as_decrypt_key() -> Result<(), &'static str> {
    Err("USB/UBOOT_ENC ciphertext is not the OTP AES key")
}

pub fn admit_s19k_factory_keys_payload(blob: &[u8]) -> Result<(), &'static str> {
    if blob != S19K_AML_UPGRADE_KEYS_PAYLOAD {
        return Err("item 13 conf/keys is exactly secure_boot_set newline");
    }
    Ok(())
}

pub fn refuse_s19k_conf_keys_as_aes_key() -> Result<(), &'static str> {
    Err("conf/keys secure_boot_set is a flag, not AES key material")
}

pub fn admit_s19k_factory_platform_payload(blob: &[u8]) -> Result<(), &'static str> {
    if blob.len() != S19K_AML_UPGRADE_ITEM16_PLATFORM_SIZE as usize {
        return Err("item 16 conf/platform is 202 B");
    }
    if !blob.starts_with(S19K_AML_UPGRADE_PLATFORM.as_bytes()) {
        return Err("item 16 must start with Platform:0x0811");
    }
    if !blob
        .windows(S19K_AML_UPGRADE_ENCRYPT_REG_ASCII.len())
        .any(|w| w == S19K_AML_UPGRADE_ENCRYPT_REG_ASCII)
    {
        return Err("item 16 must name Encrypt_reg:0xff800228");
    }
    Ok(())
}

pub fn refuse_s19k_encrypt_reg_as_otp_decrypt_key() -> Result<(), &'static str> {
    Err("Encrypt_reg 0xff800228 is AXG OTP MMIO, not ENC decrypt key bytes")
}

pub fn admit_s19k_factory_ini_payload(blob: &[u8]) -> Result<(), &'static str> {
    if blob.len() != S19K_AML_UPGRADE_ITEM8_INI_SIZE as usize {
        return Err("item 8 ini/aml_sdc_burn is 602 B");
    }
    if !blob
        .windows(S19K_AML_UPGRADE_INI_PACKAGE.len())
        .any(|w| w == S19K_AML_UPGRADE_INI_PACKAGE)
    {
        return Err("item 8 must name aml_upgrade_package.img");
    }
    if !blob
        .windows(S19K_AML_UPGRADE_INI_ERASE_BL.len())
        .any(|w| w == S19K_AML_UPGRADE_INI_ERASE_BL)
    {
        return Err("item 8 must name erase_bootloader = 1");
    }
    Ok(())
}

pub fn refuse_s19k_ini_erase_bootloader_as_execute() -> Result<(), &'static str> {
    Err("embedded aml_sdc_burn.ini erase_bootloader=1 is not a DCENT --execute grant")
}

/// Same size as item 7. Not the same ciphertext.
pub fn admit_s19k_bootloader_uboot_enc_same_size(
    bl_len: usize,
    enc_len: usize,
) -> Result<(), &'static str> {
    if bl_len != S19K_AML_UPGRADE_ITEM11_BOOTLOADER_SIZE as usize
        || enc_len != S19K_AML_UPGRADE_ITEM7_UBOOT_ENC_SIZE as usize
        || bl_len != enc_len
    {
        return Err("item 11 and item 7 are both 818688 B");
    }
    Ok(())
}

pub fn refuse_s19k_bootloader_as_uboot_enc(bl: &[u8], enc: &[u8]) -> Result<(), &'static str> {
    if !bl.is_empty() && bl == enc {
        return Ok(());
    }
    Err("item 11 PARTITION/bootloader is not item 7 UBOOT.ENC; same size, different ciphertext")
}

pub fn refuse_s19k_bootloader_as_plaintext_uboot(blob: &[u8]) -> Result<(), &'static str> {
    if blob
        .windows(b"S19k-Pro_BHB56XXX".len())
        .any(|w| w == b"S19k-Pro_BHB56XXX")
        || blob.windows(b"GPIOAO_3".len()).any(|w| w == b"GPIOAO_3")
    {
        return Ok(());
    }
    Err("item 11 PARTITION/bootloader has no S19k/GPIOAO_3 identity; not plaintext U-Boot")
}

/// Item 6 SDC UBOOT = 49664-byte AXG BL2 prefix + item 2 USB UBOOT.
pub const S19K_SDC_USB_UBOOT_PREFIX_BYTES: usize = 49_664;
pub const S19K_SDC_BL2_BUILD: &[u8] =
    b"Built : 10:38:43, Apr 14 2020. axg gf27ed33 - jenkins@walle02-sh";

pub fn admit_s19k_sdc_usb_uboot_sizes(sdc_len: usize, usb_len: usize) -> Result<(), &'static str> {
    if sdc_len != usb_len + S19K_SDC_USB_UBOOT_PREFIX_BYTES {
        return Err("SDC UBOOT is USB UBOOT plus 49664-byte BL2 prefix");
    }
    if S19K_SDC_USB_UBOOT_PREFIX_BYTES != 97 * 512 {
        return Err("BL2 prefix is 97 x 512-byte sectors");
    }
    Ok(())
}

pub fn admit_s19k_sdc_usb_uboot_suffix(sdc: &[u8], usb: &[u8]) -> Result<(), &'static str> {
    admit_s19k_sdc_usb_uboot_sizes(sdc.len(), usb.len())?;
    if &sdc[S19K_SDC_USB_UBOOT_PREFIX_BYTES..] != usb {
        return Err("SDC UBOOT suffix must be byte-identical to USB UBOOT");
    }
    Ok(())
}

pub fn admit_s19k_sdc_uboot_prefix_bl2(pref: &[u8]) -> Result<(), &'static str> {
    if pref.len() != S19K_SDC_USB_UBOOT_PREFIX_BYTES {
        return Err("SDC UBOOT prefix is 49664 bytes");
    }
    if !pref
        .windows(S19K_SDC_BL2_BUILD.len())
        .any(|w| w == S19K_SDC_BL2_BUILD)
    {
        return Err("SDC prefix is AXG BL2 built 2020-04-14 gf27ed33");
    }
    if !pref.windows(b"BL2".len()).any(|w| w == b"BL2")
        || !pref.windows(b"NAND init".len()).any(|w| w == b"NAND init")
    {
        return Err("SDC prefix names BL2 and NAND init");
    }
    Ok(())
}

/// BL2 storage-class table (NUL-separated). Not `a lab unit` or s30v NAND names.
pub const S19K_BL2_STORAGE_CLASSES: &[&str] =
    &["Rsv", "eMMC", "NAND", "SPI", "SD", "USB", "UNKNOWN"];
pub const S19K_BL2_NAND_INIT: &[u8] = b"NAND init\n";
pub const S19K_BL2_EMMC_BOOT: &[u8] = b"eMMC boot @ ";
pub const S19K_BL2_NO_STORAGE: &[u8] = b"!!!ERROR, No storage device init!\n";

pub fn parse_s19k_bl2_storage_classes(pref: &[u8]) -> Result<Vec<String>, &'static str> {
    let mut needle = Vec::new();
    for (i, name) in S19K_BL2_STORAGE_CLASSES.iter().enumerate() {
        if i > 0 {
            needle.push(0);
        }
        needle.extend_from_slice(name.as_bytes());
    }
    if pref.windows(needle.len()).any(|w| w == needle.as_slice()) {
        return Ok(S19K_BL2_STORAGE_CLASSES
            .iter()
            .map(|s| (*s).to_string())
            .collect());
    }
    Err("BL2 prefix missing Rsv/eMMC/NAND/SPI/SD/USB/UNKNOWN class table")
}

pub fn admit_s19k_bl2_storage_init(pref: &[u8]) -> Result<(), &'static str> {
    parse_s19k_bl2_storage_classes(pref)?;
    if !pref
        .windows(S19K_BL2_NAND_INIT.len())
        .any(|w| w == S19K_BL2_NAND_INIT)
    {
        return Err("BL2 prefix missing NAND init");
    }
    if !pref
        .windows(S19K_BL2_EMMC_BOOT.len())
        .any(|w| w == S19K_BL2_EMMC_BOOT)
    {
        return Err("BL2 prefix missing eMMC boot @");
    }
    if !pref
        .windows(S19K_BL2_NO_STORAGE.len())
        .any(|w| w == S19K_BL2_NO_STORAGE)
    {
        return Err("BL2 prefix missing no-storage error");
    }
    Ok(())
}

pub fn refuse_s19k_bl2_storage_as_78_mtd(names: &[&str]) -> Result<(), &'static str> {
    if names == S19K_BL2_STORAGE_CLASSES {
        return Err("BL2 Rsv/eMMC/NAND/SPI/SD/USB is a media class table, not .78 /proc/mtd");
    }
    Ok(())
}

pub fn refuse_s19k_bl2_storage_as_s30v_nand(names: &[&str]) -> Result<(), &'static str> {
    if names == S19K_BL2_STORAGE_CLASSES {
        return Err("BL2 media classes are not s30v tpl/misc/recovery/boot/config/nvdata");
    }
    Ok(())
}

pub fn refuse_s19k_bl2_emmc_boot_as_s19k_nand_map() -> Result<(), &'static str> {
    Err("BL2 eMMC boot @ is a storage-init path, not the S19k NAND partition map")
}

/// eMMC RPMB error path. Not `a lab unit` NAND / nandrecovery.
pub const S19K_BL2_RPMB_COUNTER_ERR: &[u8] = b"get rpmb counter error 0x";
pub const S19K_BL2_RPMB_COUNTER: &[u8] = b"BL2: rpmb counter: 0x";
pub const S19K_BL2_RPMB_SET_KEY: &[u8] = b"BL2: rpmb set key: 0x";
pub const S19K_BL2_RPMB_CANNOT_READ: &[u8] = b"Cannot read RPMB write counter";

pub fn admit_s19k_bl2_rpmb_emmc_errors(pref: &[u8]) -> Result<(), &'static str> {
    for needle in [
        S19K_BL2_RPMB_COUNTER_ERR,
        S19K_BL2_RPMB_COUNTER,
        S19K_BL2_RPMB_SET_KEY,
        S19K_BL2_RPMB_CANNOT_READ,
    ] {
        if !pref.windows(needle.len()).any(|w| w == needle) {
            return Err("BL2 prefix missing eMMC RPMB error/counter strings");
        }
    }
    Ok(())
}

pub fn refuse_s19k_bl2_rpmb_as_nandrecovery() -> Result<(), &'static str> {
    Err("BL2 RPMB counter/set-key is eMMC secure storage, not nandrecovery_env / mtd5")
}

pub fn refuse_s19k_bl2_rpmb_as_78_nand() -> Result<(), &'static str> {
    Err("BL2 RPMB/eMMC error path is not .78 NAND stock_system/overlay/system")
}

pub fn refuse_s19k_bl2_rpmb_as_s30v_nand() -> Result<(), &'static str> {
    Err("BL2 RPMB is not s30v tpl/misc/recovery/boot/config/nvdata")
}

/// BL2 NAND BBT/ECC scan error. Not live `a lab unit` nandnormal/twoplane ECC.
pub const S19K_BL2_SCAN_BBT_ECC: &[u8] = b"scan bbt ecc error happen:";
pub const S19K_BL2_SCAN_BBT_OFF: usize = 42_161;
pub const S19K_BL2_NBBT: &[u8] = b"nbbt";
pub const S19K_BL2_NBBT_OFF: usize = 42_156;
pub const S19K_BL2_READ_PAGE_ADDR: &[u8] = b"read page_addr:";
pub const S19K_BL2_READ_PAGE_OFF: usize = 42_189;

pub fn admit_s19k_bl2_scan_bbt_ecc(pref: &[u8]) -> Result<(), &'static str> {
    for needle in [
        S19K_BL2_SCAN_BBT_ECC,
        S19K_BL2_NBBT,
        S19K_BL2_READ_PAGE_ADDR,
    ] {
        if !pref.windows(needle.len()).any(|w| w == needle) {
            return Err("BL2 prefix missing scan bbt ecc / nbbt / read page_addr");
        }
    }
    Ok(())
}

pub fn refuse_s19k_bl2_bbt_as_78_nand_ecc() -> Result<(), &'static str> {
    Err("BL2 scan bbt ecc error is a BL2 NAND scan path, not .78 nandnormal/twoplane ECC")
}

pub fn refuse_s19k_bl2_bbt_as_s30v_nand() -> Result<(), &'static str> {
    Err("BL2 scan bbt ecc is not s30v tpl/misc/recovery/boot/config/nvdata")
}

pub fn refuse_s19k_bl2_bbt_as_nandrecovery() -> Result<(), &'static str> {
    Err("BL2 scan bbt ecc is not nandrecovery_env / mtd5 recover_env")
}

/// BL2 DDR training page save. Not a NAND page / nandrecovery record.
pub const S19K_BL2_DDR_SAVED_PAGE: &[u8] = b"ddr saved page: ";
pub const S19K_BL2_DDR_SAVED_PAGE_OFF: usize = 42_139;
/// BL2 storage lock check. Not gpio437 SafeOff.
pub const S19K_BL2_LOCK_CHECK: &[u8] = b"lock check ";
pub const S19K_BL2_LOCK_CHECK_OFF: usize = 42_206;
pub const S19K_BL2_LOCK_FAILED: &[u8] = b"lock failed! reset...\n";
pub const S19K_BL2_LOCK_FAILED_OFF: usize = 42_219;

pub fn admit_s19k_bl2_ddr_saved_page(pref: &[u8]) -> Result<(), &'static str> {
    if !pref
        .windows(S19K_BL2_DDR_SAVED_PAGE.len())
        .any(|w| w == S19K_BL2_DDR_SAVED_PAGE)
    {
        return Err("BL2 prefix missing ddr saved page: ");
    }
    Ok(())
}

pub fn admit_s19k_bl2_lock_check(pref: &[u8]) -> Result<(), &'static str> {
    if !pref
        .windows(S19K_BL2_LOCK_CHECK.len())
        .any(|w| w == S19K_BL2_LOCK_CHECK)
        || !pref
            .windows(S19K_BL2_LOCK_FAILED.len())
            .any(|w| w == S19K_BL2_LOCK_FAILED)
    {
        return Err("BL2 prefix missing lock check / lock failed! reset...");
    }
    Ok(())
}

pub fn refuse_s19k_bl2_ddr_page_as_nandrecovery() -> Result<(), &'static str> {
    Err("BL2 ddr saved page is DDR training, not nandrecovery_env / NAND page geometry")
}

pub fn refuse_s19k_bl2_lock_as_gpio437() -> Result<(), &'static str> {
    Err("BL2 lock check / lock failed! reset is storage lock, not gpio437 SafeOff")
}

pub fn refuse_s19k_bl2_lock_as_nandrecovery() -> Result<(), &'static str> {
    Err("BL2 lock failed! reset is not nandrecovery_env / recover_env")
}

/// AXG BL2 CPU reference clock. Not miner hash clock or UART baud.
pub const S19K_BL2_CPU_CLK_24MHZ: &[u8] = b"CPU clk: 24MHz\n";
pub const S19K_BL2_CPU_CLK_OFF: usize = 42_242;
pub const S19K_BL2_SYS_PLL: &[u8] = b"SYS PLL";
pub const S19K_BL2_SYS_PLL_OFF: usize = 42_258;
pub const S19K_BL2_FIX_PLL: &[u8] = b"FIX PLL";
pub const S19K_BL2_FIX_PLL_OFF: usize = 42_276;

pub fn admit_s19k_bl2_cpu_clk_24mhz(pref: &[u8]) -> Result<(), &'static str> {
    if !pref
        .windows(S19K_BL2_CPU_CLK_24MHZ.len())
        .any(|w| w == S19K_BL2_CPU_CLK_24MHZ)
    {
        return Err("BL2 prefix missing CPU clk: 24MHz");
    }
    Ok(())
}

pub fn admit_s19k_bl2_sys_fix_pll(pref: &[u8]) -> Result<(), &'static str> {
    if !pref
        .windows(S19K_BL2_SYS_PLL.len())
        .any(|w| w == S19K_BL2_SYS_PLL)
        || !pref
            .windows(S19K_BL2_FIX_PLL.len())
            .any(|w| w == S19K_BL2_FIX_PLL)
    {
        return Err("BL2 prefix missing SYS PLL / FIX PLL");
    }
    Ok(())
}

pub fn refuse_s19k_bl2_24mhz_as_hash_clock() -> Result<(), &'static str> {
    Err("BL2 CPU clk 24MHz is AXG BL2 reference clock, not BM1366 hash clock")
}

pub fn refuse_s19k_bl2_24mhz_as_uart_baud() -> Result<(), &'static str> {
    Err("BL2 CPU clk 24MHz is not Track-1 3M / stock 115200 / ESP 1M UART baud")
}

pub fn refuse_s19k_bl2_pll_as_asic_pll() -> Result<(), &'static str> {
    Err("BL2 SYS PLL / FIX PLL are Amlogic SoC PLLs, not BM1366 ASIC PLL")
}

/// AXG BL2 SoC SARADC sample-error. Not miner voltage/temp ADC.
pub const S19K_BL2_SARADC_ERR: &[u8] = b"Get saradc sample Error. Cnt_";
pub const S19K_BL2_SARADC_ERR_OFF: usize = 42_285;
pub const S19K_BL2_SARADC_CNT: &[u8] = b"Cnt_";
pub const S19K_BL2_SARADC_CNT_OFF: usize = 42_310;

pub fn admit_s19k_bl2_saradc_sample_error(pref: &[u8]) -> Result<(), &'static str> {
    if !pref
        .windows(S19K_BL2_SARADC_ERR.len())
        .any(|w| w == S19K_BL2_SARADC_ERR)
    {
        return Err("BL2 prefix missing Get saradc sample Error. Cnt_");
    }
    Ok(())
}

pub fn admit_s19k_bl2_saradc_cnt(pref: &[u8]) -> Result<(), &'static str> {
    if pref.len() >= S19K_BL2_SARADC_CNT_OFF + S19K_BL2_SARADC_CNT.len()
        && &pref[S19K_BL2_SARADC_CNT_OFF..S19K_BL2_SARADC_CNT_OFF + S19K_BL2_SARADC_CNT.len()]
            == S19K_BL2_SARADC_CNT
    {
        return Ok(());
    }
    if pref
        .windows(S19K_BL2_SARADC_ERR.len())
        .any(|w| w == S19K_BL2_SARADC_ERR)
        && pref
            .windows(S19K_BL2_SARADC_CNT.len())
            .any(|w| w == S19K_BL2_SARADC_CNT)
    {
        return Ok(());
    }
    Err("BL2 prefix missing Cnt_ on the SARADC error string")
}

pub fn refuse_s19k_bl2_saradc_as_miner_voltage_adc() -> Result<(), &'static str> {
    Err("BL2 Get saradc sample Error is AXG SoC SARADC, not miner voltage ADC / INA260 / dsPIC")
}

pub fn refuse_s19k_bl2_saradc_as_miner_temp_adc() -> Result<(), &'static str> {
    Err("BL2 SARADC Cnt_ is not miner chip/board temp ADC or XADC")
}

pub fn refuse_s19k_bl2_saradc_as_gpio437() -> Result<(), &'static str> {
    Err("BL2 Get saradc sample Error is not gpio437 / PWR_CONTROL")
}

/// AXG BL2 board-id format string. Not `a lab unit` chassis serial or BHB56 hashboard.
pub const S19K_BL2_BOARD_ID: &[u8] = b"Board ID = ";
pub const S19K_BL2_BOARD_ID_OFF: usize = 42_315;

pub fn admit_s19k_bl2_board_id(pref: &[u8]) -> Result<(), &'static str> {
    if !pref
        .windows(S19K_BL2_BOARD_ID.len())
        .any(|w| w == S19K_BL2_BOARD_ID)
    {
        return Err("BL2 prefix missing Board ID = ");
    }
    Ok(())
}

pub fn refuse_s19k_bl2_board_id_as_78_chassis() -> Result<(), &'static str> {
    Err("BL2 Board ID = is an AXG format string, not .78 JYZZYR chassis serial")
}

pub fn refuse_s19k_bl2_board_id_as_bhb56() -> Result<(), &'static str> {
    Err("BL2 Board ID = is not BHB5690x hashboard identity")
}

/// BL2 DRAM rank/type table. Not NAND geometry.
pub const S19K_BL2_RANK: &[u8] = b"rank: ";
pub const S19K_BL2_RANK_OFF: usize = 42_384;
/// NUL-padded DRAM types: DDR3 / DDR4 / LPDDR3 / LPDDR2.
pub const S19K_BL2_DDR_TYPE_TABLE: &[u8] = b"DDR3\x00\x00DDR4\x00\x00LPDDR3\x00\x00LPDDR2";
pub const S19K_BL2_DDR_TYPE_TABLE_OFF: usize = 42_560;
pub const S19K_BL2_DDR_TYPES: &[&str] = &["DDR3", "DDR4", "LPDDR3", "LPDDR2"];
pub const S19K_BL2_RANK_TABLE: &[u8] =
    b"Rank0 16bit\x00\x00Rank0\x00\x00Rank0+1\x00\x00Rank01 16bit";
pub const S19K_BL2_RANK_TABLE_OFF: usize = 42_588;
pub const S19K_BL2_DDR_INIT_FAIL: &[u8] = b"DDR init fail, reset...";
pub const S19K_BL2_DDR_INIT_FAIL_OFF: usize = 42_924;

pub fn parse_s19k_bl2_ddr_types(pref: &[u8]) -> Result<Vec<String>, &'static str> {
    if !pref
        .windows(S19K_BL2_DDR_TYPE_TABLE.len())
        .any(|w| w == S19K_BL2_DDR_TYPE_TABLE)
    {
        return Err("BL2 prefix missing DDR3/DDR4/LPDDR3/LPDDR2 type table");
    }
    Ok(S19K_BL2_DDR_TYPES
        .iter()
        .map(|s| (*s).to_string())
        .collect())
}

pub fn admit_s19k_bl2_ddr_table(pref: &[u8]) -> Result<(), &'static str> {
    parse_s19k_bl2_ddr_types(pref)?;
    if !pref
        .windows(S19K_BL2_RANK.len())
        .any(|w| w == S19K_BL2_RANK)
    {
        return Err("BL2 prefix missing rank: ");
    }
    if !pref
        .windows(S19K_BL2_RANK_TABLE.len())
        .any(|w| w == S19K_BL2_RANK_TABLE)
    {
        return Err("BL2 prefix missing Rank0 16bit / Rank0+1 table");
    }
    if !pref
        .windows(S19K_BL2_DDR_INIT_FAIL.len())
        .any(|w| w == S19K_BL2_DDR_INIT_FAIL)
    {
        return Err("BL2 prefix missing DDR init fail, reset...");
    }
    Ok(())
}

pub fn refuse_s19k_bl2_ddr_as_78_nand() -> Result<(), &'static str> {
    Err("BL2 DDR3/DDR4/LPDDR rank table is DRAM training, not .78 nandnormal/twoplane")
}

pub fn refuse_s19k_bl2_ddr_as_s30v_nand() -> Result<(), &'static str> {
    Err("BL2 DRAM types are not s30v tpl/misc/recovery/boot/config/nvdata")
}

pub fn refuse_s19k_bl2_ddr_init_as_nandrecovery() -> Result<(), &'static str> {
    Err("BL2 DDR init fail, reset is DRAM bring-up, not nandrecovery_env")
}

/// AXG DRAM SSC / DDR PLL. Not BM1366 hash PLL.
pub const S19K_BL2_DDR_SSC: &[u8] = b"Set ddr ssc: ppm";
pub const S19K_BL2_DDR_SSC_OFF: usize = 42_664;
pub const S19K_BL2_DDR_SSC_PPM: &[u8] = b"1000\n\x002000\n\x003000\n";
pub const S19K_BL2_DDR_SSC_PPM_OFF: usize = 42_681;
pub const S19K_BL2_DDR_PLL_BYPASS: &[u8] = b"DDR pll bypass enabled\n";
pub const S19K_BL2_DDR_PLL_BYPASS_OFF: usize = 42_710;
pub const S19K_BL2_DDR_PLL: &[u8] = b"DDR PLL";
pub const S19K_BL2_DDR_PLL_OFF: usize = 42_786;
pub const S19K_BL2_DDR_CLK_ERR: &[u8] = b"DDR clk err...\n";
pub const S19K_BL2_DDR_CLK_ERR_OFF: usize = 42_961;
pub const S19K_BL2_DDR_TIMING_ERR: &[u8] = b"DDR Timing err...\n";
pub const S19K_BL2_DDR_TIMING_ERR_OFF: usize = 42_977;

pub fn admit_s19k_bl2_ddr_ssc_pll(pref: &[u8]) -> Result<(), &'static str> {
    for needle in [
        S19K_BL2_DDR_SSC,
        S19K_BL2_DDR_SSC_PPM,
        S19K_BL2_DDR_PLL_BYPASS,
        S19K_BL2_DDR_PLL,
        S19K_BL2_DDR_CLK_ERR,
        S19K_BL2_DDR_TIMING_ERR,
    ] {
        if !pref.windows(needle.len()).any(|w| w == needle) {
            return Err("BL2 prefix missing Set ddr ssc / DDR pll bypass / DDR clk err");
        }
    }
    Ok(())
}

pub fn refuse_s19k_bl2_ddr_ssc_as_hash_pll() -> Result<(), &'static str> {
    Err("BL2 Set ddr ssc: ppm is DRAM spread-spectrum, not BM1366 hash PLL")
}

pub fn refuse_s19k_bl2_ddr_pll_bypass_as_asic_pll() -> Result<(), &'static str> {
    Err("BL2 DDR pll bypass / DDR PLL are DRAM PLLs, not BM1366 ASIC PLL")
}

pub fn refuse_s19k_bl2_ddr_clk_err_as_uart_baud() -> Result<(), &'static str> {
    Err("BL2 DDR clk/timing err is DRAM bring-up, not Track-1 UART baud or hash clock")
}

/// BL2 DRAM BIST token. Not NAND BIST / nandrecovery.
pub const S19K_BL2_BIST_TEST: &[u8] = b"bist_test ";
pub const S19K_BL2_BIST_TEST_OFF: usize = 42_950;
pub const S19K_BL2_BIST_PASS: &[u8] = b" - PASS\n";
pub const S19K_BL2_BIST_PASS_OFF: usize = 43_007;
pub const S19K_BL2_BIST_FAIL: &[u8] = b" - FAIL\n";
pub const S19K_BL2_BIST_FAIL_OFF: usize = 43_016;
pub const S19K_BL2_DDR_INIT_FAILED: &[u8] = b"DDR init failed";
pub const S19K_BL2_DDR_INIT_FAILED_OFF: usize = 43_025;

pub fn admit_s19k_bl2_bist_test(pref: &[u8]) -> Result<(), &'static str> {
    for needle in [
        S19K_BL2_BIST_TEST,
        S19K_BL2_BIST_PASS,
        S19K_BL2_BIST_FAIL,
        S19K_BL2_DDR_INIT_FAILED,
    ] {
        if !pref.windows(needle.len()).any(|w| w == needle) {
            return Err("BL2 prefix missing bist_test / PASS / FAIL / DDR init failed");
        }
    }
    Ok(())
}

pub fn refuse_s19k_bl2_bist_as_nand_bist() -> Result<(), &'static str> {
    Err("BL2 bist_test is DRAM BIST next to DDR clk/timing err, not NAND BIST / nandnormal")
}

pub fn refuse_s19k_bl2_bist_as_nandrecovery() -> Result<(), &'static str> {
    Err("BL2 bist_test PASS/FAIL is DRAM bring-up, not nandrecovery_env")
}

/// BL2 DRAM channel print. Not a hash-chain / tty map.
pub const S19K_BL2_CHL: &[u8] = b" chl: ";
pub const S19K_BL2_CHL_OFF: usize = 42_996;
pub const S19K_BL2_CHL_MHZ: &[u8] = b"MHz";
pub const S19K_BL2_CHL_MHZ_OFF: usize = 43_003;

pub fn admit_s19k_bl2_dram_chl_mhz(pref: &[u8]) -> Result<(), &'static str> {
    if pref.len() >= S19K_BL2_CHL_MHZ_OFF + S19K_BL2_CHL_MHZ.len()
        && &pref[S19K_BL2_CHL_OFF..S19K_BL2_CHL_OFF + S19K_BL2_CHL.len()] == S19K_BL2_CHL
        && &pref[S19K_BL2_CHL_MHZ_OFF..S19K_BL2_CHL_MHZ_OFF + S19K_BL2_CHL_MHZ.len()]
            == S19K_BL2_CHL_MHZ
    {
        return Ok(());
    }
    if pref.windows(S19K_BL2_CHL.len()).any(|w| w == S19K_BL2_CHL)
        && pref
            .windows(S19K_BL2_CHL_MHZ.len())
            .any(|w| w == S19K_BL2_CHL_MHZ)
    {
        return Ok(());
    }
    Err("BL2 prefix missing packed chl: / MHz after DDR Timing err")
}

pub fn refuse_s19k_bl2_chl_as_hash_chain() -> Result<(), &'static str> {
    Err("BL2 chl: MHz is DRAM channel next to bist PASS/FAIL, not a hash-chain or ttyS map")
}

pub fn refuse_s19k_bl2_chl_mhz_as_hash_clock() -> Result<(), &'static str> {
    Err("BL2 chl: MHz is DRAM clock print, not BM1366 hash clock or UART baud")
}

/// BL2 DRAM bring-up reset after `DDR init failed...`. Not gpio437 / HB reset.
pub const S19K_BL2_DDR_RESET: &[u8] = b"Reset...";
pub const S19K_BL2_DDR_RESET_OFF: usize = 43_044;
pub const S19K_BL2_ADDRBUS_FAIL: &[u8] = b"AddrBus test failed!!!";
pub const S19K_BL2_ADDRBUS_FAIL_OFF: usize = 43_054;
pub const S19K_BL2_DEVICE_FAIL: &[u8] = b"Device test failed!!!";
pub const S19K_BL2_DEVICE_FAIL_OFF: usize = 43_098;

pub fn admit_s19k_bl2_ddr_reset(pref: &[u8]) -> Result<(), &'static str> {
    for needle in [
        S19K_BL2_DDR_RESET,
        S19K_BL2_ADDRBUS_FAIL,
        S19K_BL2_DEVICE_FAIL,
    ] {
        if !pref.windows(needle.len()).any(|w| w == needle) {
            return Err(
                "BL2 prefix missing Reset... / AddrBus / Device test after DDR init failed",
            );
        }
    }
    Ok(())
}

pub fn refuse_s19k_bl2_reset_as_gpio437() -> Result<(), &'static str> {
    Err("BL2 Reset... after DDR init failed is DRAM bring-up, not gpio437 / PWR_CONTROL")
}

pub fn refuse_s19k_bl2_reset_as_hb_reset() -> Result<(), &'static str> {
    Err("BL2 Reset... / AddrBus test is DRAM memtest, not HB0_RESET / hashboard reset")
}

/// BL2 SDIO debug-board / secure-boot customer-ID. Not miner chassis identity.
pub const S19K_BL2_SDIO_DEBUG: &[u8] = b"sdio debug board detected";
pub const S19K_BL2_SDIO_DEBUG_OFF: usize = 43_177;
pub const S19K_BL2_NO_SDIO_DEBUG: &[u8] = b"no sdio debug board detected";
pub const S19K_BL2_NO_SDIO_DEBUG_OFF: usize = 43_205;
pub const S19K_BL2_CUSTOMER_ID: &[u8] = b"ERROR! Customer ID not match!";
pub const S19K_BL2_CUSTOMER_ID_OFF: usize = 43_236;

pub fn admit_s19k_bl2_sdio_customer_id(pref: &[u8]) -> Result<(), &'static str> {
    for needle in [
        S19K_BL2_SDIO_DEBUG,
        S19K_BL2_NO_SDIO_DEBUG,
        S19K_BL2_CUSTOMER_ID,
    ] {
        if !pref.windows(needle.len()).any(|w| w == needle) {
            return Err("BL2 prefix missing sdio debug board / Customer ID strings");
        }
    }
    Ok(())
}

pub fn refuse_s19k_bl2_sdio_as_miner_identity() -> Result<(), &'static str> {
    Err("BL2 sdio debug board detect is Amlogic BL2 debug path, not S19k miner identity")
}

pub fn refuse_s19k_bl2_customer_id_as_78_chassis() -> Result<(), &'static str> {
    Err("BL2 Customer ID not match is secure-boot OTP ID, not .78 JYZZYR / BHB56 / board_target")
}

/// BL2z / MEMDUMP path. Not nandrecovery_env / mtd5.
pub const S19K_BL2_MEMDUMP: &[u8] = b"@MEMDUMP";
pub const S19K_BL2_MEMDUMP_OFF: usize = 43_267;
pub const S19K_BL2_BL2Z_PTR: &[u8] = b"bl2z: ptr:";
pub const S19K_BL2_BL2Z_PTR_OFF: usize = 43_276;
pub const S19K_BL2_NO_BL2Z: &[u8] = b"NO BL2z!";
pub const S19K_BL2_NO_BL2Z_OFF: usize = 43_297;
pub const S19K_BL2_JUMP_BL2Z: &[u8] = b"jump to BL2z:";
pub const S19K_BL2_JUMP_BL2Z_OFF: usize = 43_307;

pub fn admit_s19k_bl2_memdump_bl2z(pref: &[u8]) -> Result<(), &'static str> {
    for needle in [
        S19K_BL2_MEMDUMP,
        S19K_BL2_BL2Z_PTR,
        S19K_BL2_NO_BL2Z,
        S19K_BL2_JUMP_BL2Z,
    ] {
        if !pref.windows(needle.len()).any(|w| w == needle) {
            return Err("BL2 prefix missing @MEMDUMP / bl2z / jump to BL2z");
        }
    }
    Ok(())
}

pub fn refuse_s19k_bl2_memdump_as_nandrecovery() -> Result<(), &'static str> {
    Err("BL2 @MEMDUMP / jump to BL2z is BL2z handoff, not nandrecovery_env / mtd5")
}

pub fn refuse_s19k_bl2_bl2z_as_78_nand() -> Result<(), &'static str> {
    Err("BL2z ptr/NO BL2z is Amlogic next-stage load, not .78 stock_system/nandnormal")
}

/// BL2 FIP / USB-boot path. Not AML NAND install / sdc_burn / nandrecovery.
pub const S19K_BL2_RETURN_BL2: &[u8] = b"return to BL2";
pub const S19K_BL2_RETURN_BL2_OFF: usize = 43_321;
pub const S19K_BL2_USB_MODE: &[u8] = b"USB mode!";
pub const S19K_BL2_USB_MODE_OFF: usize = 43_336;
pub const S19K_BL2_FIP_HDR_CHK: &[u8] = b"FIP HDR CHK:";
pub const S19K_BL2_FIP_HDR_CHK_OFF: usize = 43_347;
pub const S19K_BL2_BL3X_CHK: &[u8] = b"BL3x CHK:";
pub const S19K_BL2_BL3X_CHK_OFF: usize = 43_370;

pub fn admit_s19k_bl2_fip_usb_mode(pref: &[u8]) -> Result<(), &'static str> {
    for needle in [
        S19K_BL2_RETURN_BL2,
        S19K_BL2_USB_MODE,
        S19K_BL2_FIP_HDR_CHK,
        S19K_BL2_BL3X_CHK,
    ] {
        if !pref.windows(needle.len()).any(|w| w == needle) {
            return Err("BL2 prefix missing return to BL2 / USB mode / FIP HDR CHK");
        }
    }
    Ok(())
}

pub fn refuse_s19k_bl2_usb_mode_as_aml_install() -> Result<(), &'static str> {
    Err("BL2 USB mode! is USB boot, not aml_sdc_burn / factory SD NAND install")
}

pub fn refuse_s19k_bl2_fip_chk_as_nandrecovery() -> Result<(), &'static str> {
    Err("BL2 FIP HDR CHK / BL3x CHK is next-stage verify, not nandrecovery_env / updateporc")
}

/// BL2 FIP temp header / BL31 load / panic path. Not AML NAND install.
pub const S19K_BL2_FIP_TMP_HDR: &[u8] = b"FIP TMP HDR";
pub const S19K_BL2_FIP_TMP_HDR_OFF: usize = 43_381;
pub const S19K_BL2_BL31: &[u8] = b"BL31";
pub const S19K_BL2_BL31_OFF: usize = 43_393;
pub const S19K_BL2_NEVER_HERE: &[u8] = b"Never should be here!";
pub const S19K_BL2_NEVER_HERE_OFF: usize = 43_406;

pub fn admit_s19k_bl2_fip_tmp_bl31(pref: &[u8]) -> Result<(), &'static str> {
    for needle in [S19K_BL2_FIP_TMP_HDR, S19K_BL2_BL31, S19K_BL2_NEVER_HERE] {
        if !pref.windows(needle.len()).any(|w| w == needle) {
            return Err("BL2 prefix missing FIP TMP HDR / BL31 / Never should be here!");
        }
    }
    Ok(())
}

pub fn refuse_s19k_bl2_fip_tmp_as_aml_install() -> Result<(), &'static str> {
    Err("BL2 FIP TMP HDR is FIP load, not aml_sdc_burn / factory SD NAND install")
}

pub fn refuse_s19k_bl2_bl31_as_nandrecovery() -> Result<(), &'static str> {
    Err("BL2 BL31 next to FIP TMP HDR is ATF load, not nandrecovery_env / updateporc")
}

pub fn refuse_s19k_bl2_never_here_as_operator_install() -> Result<(), &'static str> {
    Err("BL2 Never should be here! is a BL2 panic path, not an install/recovery procedure")
}

/// BL2 FIP SHA family error labels. Not AmlImagePack `sha1sum` VERIFY.
pub const S19K_BL2_ERR_SHA_TABLE: &[u8] =
    b"Err:sha5\n\x00Err:sha4\n\x00Err:sha3\n\x00Err:sha1\n\x00Err:sha2\n\x00";
pub const S19K_BL2_ERR_SHA_TABLE_OFF: usize = 43_464;
pub const S19K_BL2_ERR_SHA_LABELS: &[&[u8]] = &[
    b"Err:sha5",
    b"Err:sha4",
    b"Err:sha3",
    b"Err:sha1",
    b"Err:sha2",
];

pub fn parse_s19k_bl2_err_sha_labels(pref: &[u8]) -> Result<Vec<String>, &'static str> {
    if !pref
        .windows(S19K_BL2_ERR_SHA_TABLE.len())
        .any(|w| w == S19K_BL2_ERR_SHA_TABLE)
    {
        return Err("BL2 prefix missing Err:sha5..sha2 FIP digest table");
    }
    Ok(S19K_BL2_ERR_SHA_LABELS
        .iter()
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect())
}

pub fn admit_s19k_bl2_err_sha_table(pref: &[u8]) -> Result<(), &'static str> {
    parse_s19k_bl2_err_sha_labels(pref)?;
    if pref
        .windows(S19K_AML_VERIFY_PREFIX.len())
        .any(|w| w == S19K_AML_VERIFY_PREFIX)
    {
        return Err("BL2 prefix must not carry AmlImagePack sha1sum VERIFY records");
    }
    Ok(())
}

pub fn refuse_s19k_bl2_err_sha_as_verify_sha1() -> Result<(), &'static str> {
    Err("BL2 Err:sha5..sha2 are FIP digest error labels, not AmlImagePack sha1sum + 40 hex")
}

pub fn refuse_s19k_bl2_err_sha_as_decrypt_key() -> Result<(), &'static str> {
    Err("BL2 Err:sha* is a FIP verify failure string, not an OTP AES / VERIFY decrypt key")
}

/// BL2 USB-boot skip / panic after FIP digest errors. Distinct from
/// `Never should be here!` @ 43406. Not factory SD NAND install.
pub const S19K_BL2_NEVER_BE_HERE: &[u8] = b"NEVER BE HERE";
pub const S19K_BL2_NEVER_BE_HERE_OFF: usize = 43_530;
pub const S19K_BL2_USB_LABEL: &[u8] = b"BL2 USB ";
pub const S19K_BL2_USB_LABEL_OFF: usize = 43_552;
pub const S19K_BL2_SKIP_USB: &[u8] = b"Skip usb!";
pub const S19K_BL2_SKIP_USB_OFF: usize = 43_562;

pub fn admit_s19k_bl2_never_be_here_skip_usb(pref: &[u8]) -> Result<(), &'static str> {
    for needle in [
        S19K_BL2_NEVER_BE_HERE,
        S19K_BL2_USB_LABEL,
        S19K_BL2_SKIP_USB,
    ] {
        if !pref.windows(needle.len()).any(|w| w == needle) {
            return Err("BL2 prefix missing NEVER BE HERE / BL2 USB / Skip usb!");
        }
    }
    if !pref
        .windows(S19K_BL2_NEVER_HERE.len())
        .any(|w| w == S19K_BL2_NEVER_HERE)
    {
        return Err(
            "BL2 prefix must still carry Never should be here! distinct from NEVER BE HERE",
        );
    }
    Ok(())
}

pub fn refuse_s19k_bl2_never_be_here_as_operator_install() -> Result<(), &'static str> {
    Err("BL2 NEVER BE HERE is a BL2 USB-boot panic, not an install/recovery procedure")
}

pub fn refuse_s19k_bl2_skip_usb_as_aml_install() -> Result<(), &'static str> {
    Err("BL2 Skip usb! is USB-boot skip, not aml_sdc_burn / factory SD NAND install")
}

/// BL2 USB/FIP register-dump format after `Skip usb!`. Not hash UART / nandrecovery.
pub const S19K_BL2_DUMP_TABLE: &[u8] =
    b"-W[0x\x00]:0x\x00,R:0x\x00DATA\x00ADDR\x00ADDR2\x00ADDR3\x00\nTotal Size 0x\x00FULL\x00FULL2";
pub const S19K_BL2_DUMP_TABLE_OFF: usize = 43_577;
pub const S19K_BL2_DUMP_LABELS: &[&[u8]] = &[
    b"-W[0x",
    b"]:0x",
    b",R:0x",
    b"DATA",
    b"ADDR",
    b"ADDR2",
    b"ADDR3",
    b"Total Size 0x",
    b"FULL",
    b"FULL2",
];

pub fn parse_s19k_bl2_dump_labels(pref: &[u8]) -> Result<Vec<String>, &'static str> {
    if !pref
        .windows(S19K_BL2_DUMP_TABLE.len())
        .any(|w| w == S19K_BL2_DUMP_TABLE)
    {
        return Err("BL2 prefix missing -W[0x / DATA / ADDR / Total Size dump table");
    }
    Ok(S19K_BL2_DUMP_LABELS
        .iter()
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect())
}

pub fn admit_s19k_bl2_reg_dump(pref: &[u8]) -> Result<(), &'static str> {
    parse_s19k_bl2_dump_labels(pref)?;
    Ok(())
}

pub fn refuse_s19k_bl2_reg_dump_as_hash_uart() -> Result<(), &'static str> {
    Err("BL2 -W[0x]/DATA/ADDR dump is BL2 USB/FIP hexdump, not BM1366 ttyS / 55 AA")
}

pub fn refuse_s19k_bl2_reg_dump_as_nandrecovery() -> Result<(), &'static str> {
    Err("BL2 Total Size/FULL/FULL2 is BL2 dump extent, not nandrecovery_env / mtd5")
}

pub fn refuse_s19k_sdc_uboot_prefix_as_gpio437(pref: &[u8]) -> Result<(), &'static str> {
    if pref.windows(b"GPIOAO_3".len()).any(|w| w == b"GPIOAO_3")
        || pref.windows(b"gpio437".len()).any(|w| w == b"gpio437")
        || pref
            .windows(b"PWR_CONTROL".len())
            .any(|w| w == b"PWR_CONTROL")
    {
        return Ok(());
    }
    Err("SDC BL2 prefix has no GPIOAO_3/gpio437/PWR_CONTROL")
}

pub fn refuse_s19k_sdc_usb_uboot_as_same_image(
    sdc_len: usize,
    usb_len: usize,
) -> Result<(), &'static str> {
    if sdc_len == usb_len {
        return Ok(());
    }
    Err("SDC UBOOT is not the same image as USB UBOOT; 49664-byte BL2 prefix")
}

pub fn refuse_s19k_aml_verify_as_decrypt() -> Result<(), &'static str> {
    Err("AmlImagePack VERIFY sha1sum is an integrity record, not an OTP AES key")
}

pub fn refuse_s19k_aml_verify_hex_as_other_kind(
    kind: S19kAmlVerifyKind,
    hex: &[u8],
) -> Result<(), &'static str> {
    match classify_s19k_aml_verify_hex(hex) {
        Ok(got) if got != kind => Err("VERIFY sha1 belongs to a different factory item"),
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn refuse_s19k_aml_dtb_as_plaintext_fdt(head: &[u8]) -> Result<(), &'static str> {
    if head.len() >= 4 && &head[..4] == b"AML_" {
        return Ok(());
    }
    if head.len() >= 4 && head[..4] == [0xd0, 0x0d, 0xfe, 0xed] {
        return Ok(());
    }
    if head.len() >= 2 && head[0] == 0x1F && head[1] == 0x8B {
        return Ok(());
    }
    Err("PARTITION/_aml_dtb is encrypted meson1_ENC; not AML_/FDT/gzip")
}

pub fn refuse_s19k_aml_dtb_as_gpio437(blob: &[u8]) -> Result<(), &'static str> {
    if blob.windows(b"gpio437".len()).any(|w| w == b"gpio437")
        || blob
            .windows(b"PWR_CONTROL".len())
            .any(|w| w == b"PWR_CONTROL")
    {
        return Ok(());
    }
    Err("encrypted _aml_dtb has 0 gpio437/PWR_CONTROL; cannot close polarity")
}

pub fn refuse_s19k_aml_img_as_updateporc(blob: &[u8]) -> Result<(), &'static str> {
    if blob
        .windows(b"updateporc".len())
        .any(|w| w == b"updateporc")
    {
        return Ok(());
    }
    Err("S19k factory AmlImagePack has 0 updateporc bytes; TOC is not updateporc.sh")
}

pub fn refuse_s19k_aml_img_as_4cc0_or_uart_trans(blob: &[u8]) -> Result<(), &'static str> {
    if blob
        .windows(b"uart_trans".len())
        .any(|w| w == b"uart_trans")
        || blob
            .windows(b"bmminer_4cc0".len())
            .any(|w| w == b"bmminer_4cc0")
    {
        return Ok(());
    }
    Err("S19k factory AmlImagePack has 0 uart_trans/bmminer_4cc0 bytes")
}

pub fn refuse_s19k_aml_uboot_identity_as_4cc0(ident: &str) -> Result<(), &'static str> {
    if ident.contains("S19k-Pro_BHB56") {
        return Err("S19k-Pro_BHB56XXX in USB UBOOT is board identity, not 4cc0/ko");
    }
    Ok(())
}

pub fn refuse_s19k_aml_android_boot_as_nandrecovery(magic: &[u8]) -> Result<(), &'static str> {
    if magic.len() >= 8 && &magic[..8] == S19K_ANDROID_BOOT_MAGIC {
        return Err("factory PARTITION/boot is ANDROID!; not nandrecovery_env");
    }
    Ok(())
}

pub fn refuse_s19k_embedded_ini_as_operator_sd_ini(
    embedded_reboot: bool,
) -> Result<(), &'static str> {
    if !embedded_reboot {
        return Err(
            "embedded item-8 ini is reboot=0 package=aml_upgrade_package.img; operator zip ini is reboot=1 _enc",
        );
    }
    Ok(())
}

pub fn refuse_s19k_cvctrl_sd2nand_as_aml_nand(
    kind: S19kUpgradeBlobKind,
) -> Result<(), &'static str> {
    if kind == S19kUpgradeBlobKind::CvitekSd2NandFactory {
        return Err(
            "stock-20231115 is CVCtrl sd2nand eMMC (boot.emmc/partition_emmc); refuse as am3-s19k NAND",
        );
    }
    Ok(())
}

pub fn refuse_stock_bmu_as_dcent_sysupgrade(kind: S19kUpgradeBlobKind) -> Result<(), &'static str> {
    if kind == S19kUpgradeBlobKind::StockBitmainBmu {
        return Err("stock update.bmu is daemonc→updateporc.sh; not a DCENT sysupgrade");
    }
    Ok(())
}

/// A classified DCENT sysupgrade tarball is still not an execute grant.
/// Classification ≠ nandwrite. FLASH stays false.
pub fn refuse_s19k_dcent_sysupgrade_execute_while_flash_false(
    kind: S19kUpgradeBlobKind,
) -> Result<(), &'static str> {
    if kind == S19kUpgradeBlobKind::DcentSysupgradeTar && !CLEAR_FOR_FLASH {
        return Err(
            "sysupgrade-am3-s19k.tar is a DCENT blob; execute stays CLEAR_FOR_FLASH=false; refuse nandwrite",
        );
    }
    if !CLEAR_FOR_FLASH {
        return Err("upgrade execute stays CLEAR_FOR_FLASH=false; refuse nandwrite");
    }
    Ok(())
}

pub fn refuse_s19k_stock_web_rail_as_unsigned() -> Result<(), &'static str> {
    Err(
        "S19k stock web rail is upgrade.cgi→daemonc client→127.0.0.1:22322 daemons→system(updateporc.sh ); updateporc.sh still absent from .78 extract; not a DCENT sysupgrade",
    )
}

/// `a lab unit` `usr_sbin_daemonc` == `usr_sbin_update-daemon` (7240 B ELF32 ARM).
pub const S19K_78_DAEMONC_ELF_CLASS: u8 = 1;
pub const S19K_78_DAEMONC_MACHINE: u16 = 40;
pub const S19K_78_DAEMONC_PORC_STR_OFF: u64 = 0xF54;
pub const S19K_STOCK_UPDATEPORC_PATH: &str = "/usr/sbin/updateporc.sh";
/// : `system()` prefix includes the trailing space (sprintf onto recv).
pub const S19K_STOCK_UPDATEPORC_PREFIX: &str = "/usr/sbin/updateporc.sh ";
pub const S19K_STOCK_DAEMONS_NAME: &str = "daemons";
pub const S19K_STOCK_DAEMONC_LISTEN_HOST: &str = "127.0.0.1";
pub const S19K_STOCK_DAEMONC_LISTEN_PORT: u16 = 22322;
pub const S19K_STOCK_DAEMONC_HOST_STR_OFF: u64 = 0x1414;
pub const S19K_STOCK_DAEMONC_PORT_STR_OFF: u64 = 0x1420;
pub const S19K_STOCK_DAEMONC_ARGV0_OFF: u64 = 0x1444;
pub const S19K_STOCK_DAEMONS_ARGV0_OFF: u64 = 0x144C;
pub const S19K_STOCK_DAEMONC_SOURCE: &str = "update-daemon.c";
pub const S19K_STOCK_DAEMONC_HTTP_OK: u16 = 200;
pub const S19K_78_DAEMONC_MOVW_DAEMONC_OFF: u64 = 0x8DC;
pub const S19K_78_DAEMONC_MOVW_DAEMONC_INSN: u32 = 0xE301_1444;
pub const S19K_78_DAEMONC_LDR_ARGV1_OFF: u64 = 0x8F8;
pub const S19K_78_DAEMONC_LDR_ARGV1_INSN: u32 = 0xE594_0004;
pub const S19K_78_DAEMONC_MOVW_DAEMONS_OFF: u64 = 0x908;
pub const S19K_78_DAEMONC_MOVW_DAEMONS_INSN: u32 = 0xE301_144C;
pub const S19K_78_DAEMONC_MOVW_HOST_OFF: u64 = 0x94C;
pub const S19K_78_DAEMONC_MOVW_HOST_INSN: u32 = 0xE301_0414;
pub const S19K_78_DAEMONC_MOVW_PORT_OFF: u64 = 0x964;
pub const S19K_78_DAEMONC_MOVW_PORT_INSN: u32 = 0xE301_0420;
pub const S19K_78_DAEMONC_MOVW_PORC_OFF: u64 = 0xC9C;
pub const S19K_78_DAEMONC_MOVW_PORC_INSN: u32 = 0xE300_EF54;
pub const S19K_78_DAEMONC_CMP_C8_OFF: u64 = 0xEBC;
pub const S19K_78_DAEMONC_CMP_C8_INSN: u32 = 0xE350_00C8;
/// Held `a lab unit` `mtd2_stock_system.bin` — NAND pages, not a porc source.
pub const S19K_78_MTD2_BYTES: usize = 52_428_800;
pub const S19K_78_MTD2_ANDROID_OFF: usize = 2_097_152;
/// Second ANDROID! (boot.img with ramdisk) at 18 MiB.
pub const S19K_78_MTD2_ANDROID2_OFF: usize = 0x0120_0000;
pub const S19K_78_MTD2_ANDROID_COUNT: usize = 2;
pub const S19K_78_MTD2_KERNEL_SIZE: u32 = 0x005C_2000;
pub const S19K_78_MTD2_ANDROID2_RAMDISK_SIZE: u32 = 0x0066_2000;
pub const S19K_78_MTD2_PAGE_SIZE: u32 = 2048;
pub const S19K_78_MTD2_SECOND_SIZE: u32 = 0x7800;
pub const S19K_78_MTD2_UPDATEPORC_HITS: usize = 0;
pub const S19K_78_MTD2_FILEPARSER_HITS: usize = 0;
pub const S19K_78_MTD2_UART_TRANS_HITS: usize = 0;
pub const S19K_78_MTD2_4CC0_HITS: usize = 0;
pub const S19K_78_MTD2_BITMAIN_PUB_HITS: usize = 0;
pub const S19K_78_MTD2_MINER_PEM_HITS: usize = 0;
pub const S19K_78_MTD2_DAEMONC_HITS: usize = 0;
/// Page-0 AMLSECU stamps. Same day as each other; not 20231108 / factory 20231115.
pub const S19K_78_MTD2_AMLSECU_A1_TIME: &[u8; 16] = b"2021111922403912";
pub const S19K_78_MTD2_AMLSECU_A2_TIME: &[u8; 16] = b"2021111922403917";
/// `declared_header_len` at AMLSECU +12. A1=2 (ramdisk 0), A2=3 (has ramdisk).
pub const S19K_78_MTD2_AMLSECU_A1_KIND: u32 = S19K_AMLSECU_KIND_RECOVERY;
pub const S19K_78_MTD2_AMLSECU_A2_KIND: u32 = S19K_AMLSECU_KIND_BOOT;
/// File offsets: page + aligned kernel (0x5C2000 already 2KiB-aligned).
pub const S19K_78_MTD2_A1_KERNEL_OFF: usize = 0x0020_0800;
pub const S19K_78_MTD2_A1_SECOND_OFF: usize = 0x007C_2800;
pub const S19K_78_MTD2_A2_KERNEL_OFF: usize = 0x0120_0800;
pub const S19K_78_MTD2_A2_RAMDISK_OFF: usize = 0x017C_2800;
pub const S19K_78_MTD2_A2_SECOND_OFF: usize = 0x01E2_4800;
pub const S19K_78_MTD2_KERNEL_HEAD: [u8; 4] = [0x39, 0xD4, 0xF7, 0xF5];
pub const S19K_78_MTD2_A1_SECOND_HEAD: [u8; 4] = [0x18, 0x13, 0xBB, 0x52];
pub const S19K_78_MTD2_A2_RAMDISK_HEAD: [u8; 4] = [0x27, 0x8C, 0x6E, 0xCC];
pub const S19K_78_MTD2_A2_SECOND_HEAD: [u8; 4] = [0x8F, 0xE0, 0x26, 0x5F];
/// Held `a lab unit` `mtd3_stock_config.bin` — UBI PEBs, not a porc/FileParser source.
pub const S19K_78_MTD3_NAME: &str = "stock_config";
/// s30v/stock same-index mtd3 is ANDROID recovery 16 MiB, not this UBI.
pub const S19K_S30V_MTD3_NAME: &str = "recovery";
/// Factory item 17 (6_064_640) minus BOS mtd3 (5_242_880).
pub const S19K_FACTORY_RECOVERY_OVERFLOW_VS_78_MTD3: u64 = 821_760;
/// Factory recovery second sits at page+kernel — same file offset as boot ramdisk.
pub const S19K_FACTORY_RECOVERY_SECOND_OFF: usize = 0x5C_1000;
pub const S19K_78_MTD3_BYTES: usize = 5_242_880;
pub const S19K_78_MTD3_PEB: usize = 131_072;
pub const S19K_78_MTD3_PEB_COUNT: usize = 40;
pub const S19K_78_MTD3_UBI_MAGIC: &[u8; 4] = b"UBI#";
pub const S19K_78_MTD3_UBI_VERSION: u8 = 1;
pub const S19K_78_MTD3_VID_HDR_OFF: u32 = 2048;
pub const S19K_78_MTD3_DATA_OFF: u32 = 4096;
pub const S19K_78_MTD3_UBI_BANG_OFF: usize = 395_264;
/// PEB 3 + data (4096). UBI volume-table record 0.
pub const S19K_78_MTD3_VTBL_OFF: usize = 397_312;
/// name[] at vtbl record +16.
pub const S19K_78_MTD3_VTBL_NAME_OFF: usize = 397_328;
/// UBI volume name. Not `/proc/mtd` `stock_config` and not s30v `recovery`.
pub const S19K_78_MTD3_UBI_VOL_NAME: &[u8] = b"config_data";
pub const S19K_78_MTD3_UBI_VOL_NAME_LEN: u16 = 11;
pub const S19K_78_MTD3_UBI_VOL_RESERVED_PEBS: u32 = 32;
pub const S19K_78_MTD3_UBI_VOL_TYPE_DYNAMIC: u8 = 1;
/// First `UBI!` VID vol_id is the layout volume (PEB 3).
pub const S19K_78_MTD3_LAYOUT_VOL_ID: u32 = 0x7FFF_EFFF;
/// Redundant UBI volume-table copy (PEB 4 + data).
pub const S19K_78_MTD3_VTBL_PEB4_OFF: usize = 528_384;
pub const S19K_78_MTD3_VTBL_PEB4_NAME_OFF: usize = 528_400;
pub const S19K_78_MTD3_UBI_BANG_PEB4_OFF: usize = 526_336;
pub const S19K_78_MTD3_UPDATEPORC_HITS: usize = 0;
pub const S19K_78_MTD3_FILEPARSER_HITS: usize = 0;
pub const S19K_78_MTD3_UART_TRANS_HITS: usize = 0;
pub const S19K_78_MTD3_CGMINER_CONF_OFF: usize = 3_283_000;
pub const S19K_78_MTD3_CGMINER_CONF: &[u8] = b"cgminer.conf";
pub const S19K_78_MTD3_NETWORK_CONF_OFF: usize = 3_283_392;
pub const S19K_78_MTD3_NETWORK_CONF: &[u8] = b"network.conf";
pub const S19K_78_MTD3_HOSTNAME_ANTMINER_OFF: usize = 3_412_368;
pub const S19K_78_MTD3_HOSTNAME_ANTMINER: &[u8] = b"hostname=Antminer";
/// `upgrade.cgi` writes this after daemonc exit 0.
pub const S19K_STOCK_MINER_ACT_SUCCESS: u8 = 2;
/// `upgrade_clear.cgi` writes this after daemonc exit 0.
pub const S19K_STOCK_MINER_ACT_CLEAR: u8 = 3;

/// L1: held daemonc is ELF32 ARM and embeds `updateporc.sh`.
pub fn admit_s19k_78_daemonc_elf(blob: &[u8]) -> Result<(), &'static str> {
    if blob.len() != S19K_STOCK_DAEMONC_BYTES {
        return Err("held .78 daemonc size is 7240");
    }
    if blob.len() < 20 || blob[0] != 0x7F || &blob[1..4] != b"ELF" {
        return Err("held .78 daemonc is not ELF");
    }
    if blob[4] != S19K_78_DAEMONC_ELF_CLASS {
        return Err("held .78 daemonc is not ELF32");
    }
    let machine = u16::from_le_bytes([blob[18], blob[19]]);
    if machine != S19K_78_DAEMONC_MACHINE {
        return Err("held .78 daemonc is not EM_ARM");
    }
    let off = S19K_78_DAEMONC_PORC_STR_OFF as usize;
    if blob.len() < off + S19K_STOCK_UPDATEPORC_PATH.len()
        || &blob[off..off + S19K_STOCK_UPDATEPORC_PATH.len()]
            != S19K_STOCK_UPDATEPORC_PATH.as_bytes()
    {
        return Err("held .78 daemonc missing /usr/sbin/updateporc.sh at 0xf54");
    }
    Ok(())
}

/// Held `a lab unit` `usr_sbin_daemonc` is byte-identical to `usr_sbin_update-daemon`.
pub fn admit_s19k_78_daemonc_is_update_daemon(a: &[u8], b: &[u8]) -> Result<(), &'static str> {
    admit_s19k_78_daemonc_elf(a)?;
    if a != b {
        return Err(".78 daemonc != update-daemon");
    }
    Ok(())
}

fn blob_str_at(blob: &[u8], off: u64, s: &str) -> bool {
    let off = off as usize;
    blob.len() >= off + s.len() && &blob[off..off + s.len()] == s.as_bytes()
}

/// `daemons` binds `127.0.0.1` and `atoi("22322")`.
pub fn admit_s19k_daemonc_listen_is_localhost_22322(blob: &[u8]) -> Result<(), &'static str> {
    admit_s19k_78_daemonc_elf(blob)?;
    if !blob_str_at(
        blob,
        S19K_STOCK_DAEMONC_HOST_STR_OFF,
        S19K_STOCK_DAEMONC_LISTEN_HOST,
    ) {
        return Err("daemonc missing 127.0.0.1 at 0x1414");
    }
    if !blob_str_at(blob, S19K_STOCK_DAEMONC_PORT_STR_OFF, "22322") {
        return Err("daemonc missing 22322 at 0x1420");
    }
    if S19K_STOCK_DAEMONC_LISTEN_PORT != 22322 {
        return Err("listen port is 22322");
    }
    if word32_le(blob, S19K_78_DAEMONC_MOVW_HOST_OFF) != S19K_78_DAEMONC_MOVW_HOST_INSN {
        return Err("MOVW r0,#0x1414 host");
    }
    if word32_le(blob, S19K_78_DAEMONC_MOVW_PORT_OFF) != S19K_78_DAEMONC_MOVW_PORT_INSN {
        return Err("MOVW r0,#0x1420 port");
    }
    Ok(())
}

/// argv0 `"daemonc"` loads argv[1]; argv0 `"daemons"` is the listen path.
pub fn admit_s19k_daemonc_argv0_roles(blob: &[u8]) -> Result<(), &'static str> {
    admit_s19k_78_daemonc_elf(blob)?;
    if !blob_str_at(blob, S19K_STOCK_DAEMONC_ARGV0_OFF, "daemonc") {
        return Err("argv0 daemonc at 0x1444");
    }
    if !blob_str_at(blob, S19K_STOCK_DAEMONS_ARGV0_OFF, S19K_STOCK_DAEMONS_NAME) {
        return Err("argv0 daemons at 0x144c");
    }
    if word32_le(blob, S19K_78_DAEMONC_MOVW_DAEMONC_OFF) != S19K_78_DAEMONC_MOVW_DAEMONC_INSN {
        return Err("MOVW r1,#0x1444");
    }
    if word32_le(blob, S19K_78_DAEMONC_LDR_ARGV1_OFF) != S19K_78_DAEMONC_LDR_ARGV1_INSN {
        return Err("LDR r0,[r4,#4] argv[1]");
    }
    if word32_le(blob, S19K_78_DAEMONC_MOVW_DAEMONS_OFF) != S19K_78_DAEMONC_MOVW_DAEMONS_INSN {
        return Err("MOVW r1,#0x144c");
    }
    Ok(())
}

/// Listener `system()` prefix is [`S19K_STOCK_UPDATEPORC_PREFIX`] (trailing space).
pub fn admit_s19k_daemons_system_prefix(blob: &[u8]) -> Result<(), &'static str> {
    admit_s19k_78_daemonc_elf(blob)?;
    if !blob_str_at(
        blob,
        S19K_78_DAEMONC_PORC_STR_OFF,
        S19K_STOCK_UPDATEPORC_PREFIX,
    ) {
        return Err("system prefix /usr/sbin/updateporc.sh[space] at 0xf54");
    }
    if word32_le(blob, S19K_78_DAEMONC_MOVW_PORC_OFF) != S19K_78_DAEMONC_MOVW_PORC_INSN {
        return Err("MOVW lr,#0xf54");
    }
    if !S19K_STOCK_UPDATEPORC_PREFIX.ends_with(' ') {
        return Err("prefix must keep the trailing space");
    }
    Ok(())
}

/// CGI `daemonc` is a 22322 client. Success is `cmp r0,#0xc8` (HTTP 200).
pub fn admit_s19k_daemonc_client_cmp_http_200(blob: &[u8]) -> Result<(), &'static str> {
    admit_s19k_78_daemonc_elf(blob)?;
    if word32_le(blob, S19K_78_DAEMONC_CMP_C8_OFF) != S19K_78_DAEMONC_CMP_C8_INSN {
        return Err("CMP r0,#0xc8");
    }
    if S19K_STOCK_DAEMONC_HTTP_OK != 200 {
        return Err("HTTP 200");
    }
    Ok(())
}

fn word32_le(blob: &[u8], off: u64) -> u32 {
    let off = off as usize;
    if blob.len() < off + 4 {
        return 0;
    }
    u32::from_le_bytes([blob[off], blob[off + 1], blob[off + 2], blob[off + 3]])
}

/// Exact `system()` line the listener builds. Not an executor.
pub fn s19k_stock_daemons_system_line(recv: &str) -> String {
    format!("{}{recv}", S19K_STOCK_UPDATEPORC_PREFIX)
}

/// daemonc/daemons never write NAND themselves.
pub fn refuse_s19k_daemonc_as_direct_nand_writer() -> Result<(), &'static str> {
    Err(
        "daemonc is a 127.0.0.1:22322 client; daemons system()s updateporc.sh+payload; neither flashes mtd5",
    )
}

/// Held `mtd2_stock_system.bin` is NAND pages (ANDROID! @ 2MiB), not porc plaintext.
pub fn refuse_s19k_mtd2_as_updateporc_source(blob: &[u8]) -> Result<(), &'static str> {
    if blob
        .windows(b"updateporc".len())
        .any(|w| w == b"updateporc")
    {
        return Ok(());
    }
    Err("mtd2_stock_system.bin has 0 updateporc bytes; ANDROID! at 0x200000 is not a porc script")
}

pub fn refuse_s19k_mtd2_as_fileparser_source(blob: &[u8]) -> Result<(), &'static str> {
    if blob
        .windows(b"FileParser".len())
        .any(|w| w == b"FileParser")
    {
        return Ok(());
    }
    Err("mtd2_stock_system.bin has 0 FileParser bytes")
}

pub fn refuse_s19k_mtd2_as_uart_trans_source(blob: &[u8]) -> Result<(), &'static str> {
    if blob
        .windows(b"uart_trans".len())
        .any(|w| w == b"uart_trans")
        || blob
            .windows(b"bmminer_4cc0".len())
            .any(|w| w == b"bmminer_4cc0")
        || blob.windows(b"4cc0".len()).any(|w| w == b"4cc0")
    {
        return Ok(());
    }
    Err("mtd2_stock_system.bin has 0 uart_trans/4cc0 bytes")
}

pub fn refuse_s19k_mtd2_as_bitmain_pub_source(blob: &[u8]) -> Result<(), &'static str> {
    if blob
        .windows(b"bitmain.pub".len())
        .any(|w| w == b"bitmain.pub")
        || blob.windows(b"miner.pem".len()).any(|w| w == b"miner.pem")
        || blob.windows(b"daemonc".len()).any(|w| w == b"daemonc")
    {
        return Ok(());
    }
    Err("mtd2_stock_system.bin has 0 bitmain.pub/miner.pem/daemonc bytes")
}

pub fn admit_s19k_78_mtd2_geometry(len: usize) -> Result<(), &'static str> {
    if len != S19K_78_MTD2_BYTES {
        return Err("mtd2_stock_system.bin is 50 MiB (52428800)");
    }
    Ok(())
}

/// Two ANDROID! headers: first ramdisk=0 @ 2MiB, second ramdisk 0x662000 @ 18MiB.
pub fn admit_s19k_78_mtd2_android_pair(blob: &[u8]) -> Result<(), &'static str> {
    if blob.len() < S19K_78_MTD2_ANDROID2_OFF + 24 {
        return Err("mtd2 fixture shorter than second ANDROID!");
    }
    if &blob[S19K_78_MTD2_ANDROID_OFF..S19K_78_MTD2_ANDROID_OFF + 8] != b"ANDROID!" {
        return Err("mtd2 first ANDROID! is at 0x200000");
    }
    if &blob[S19K_78_MTD2_ANDROID2_OFF..S19K_78_MTD2_ANDROID2_OFF + 8] != b"ANDROID!" {
        return Err("mtd2 second ANDROID! is at 0x1200000");
    }
    let rs1 = u32::from_le_bytes(
        blob[S19K_78_MTD2_ANDROID_OFF + 16..S19K_78_MTD2_ANDROID_OFF + 20]
            .try_into()
            .unwrap(),
    );
    let rs2 = u32::from_le_bytes(
        blob[S19K_78_MTD2_ANDROID2_OFF + 16..S19K_78_MTD2_ANDROID2_OFF + 20]
            .try_into()
            .unwrap(),
    );
    let ks2 = u32::from_le_bytes(
        blob[S19K_78_MTD2_ANDROID2_OFF + 8..S19K_78_MTD2_ANDROID2_OFF + 12]
            .try_into()
            .unwrap(),
    );
    if rs1 != 0 {
        return Err("mtd2 first ANDROID ramdisk_size is 0");
    }
    if rs2 != S19K_78_MTD2_ANDROID2_RAMDISK_SIZE {
        return Err("mtd2 second ANDROID ramdisk_size is 0x662000");
    }
    if ks2 != S19K_78_MTD2_KERNEL_SIZE {
        return Err("mtd2 ANDROID kernel_size is 0x5C2000");
    }
    Ok(())
}

pub fn refuse_s19k_mtd2_ramdisk_as_factory_boot(ramdisk: u32) -> Result<(), &'static str> {
    if ramdisk == S19K_FACTORY_BOOT_RAMDISK_SIZE {
        return Err("factory item 9 ramdisk 0x686800 is not mtd2 second ANDROID 0x662000");
    }
    Ok(())
}

pub fn refuse_s19k_mtd2_ramdisk_as_20231108(ramdisk: u32) -> Result<(), &'static str> {
    if ramdisk == S19K_20231108_RAMDISK_SIZE {
        return Err("20231108 ramdisk 0x66A000 is not mtd2 second ANDROID 0x662000");
    }
    Ok(())
}

pub fn refuse_s19k_mtd2_as_ubi_stock_config(blob: &[u8]) -> Result<(), &'static str> {
    if blob.windows(4).any(|w| w == b"UBI#") {
        return Ok(());
    }
    Err("mtd2_stock_system.bin is ANDROID stock_system, not UBI stock_config")
}

pub fn refuse_s19k_mtd2_amlsecu_as_20231108(
    kind: S19kAmlsecuImageKind,
) -> Result<(), &'static str> {
    if matches!(
        kind,
        S19kAmlsecuImageKind::Mtd2Android1 | S19kAmlsecuImageKind::Mtd2Android2
    ) {
        return Err("mtd2 AMLSECU 20211119 is not 20231108 single-BMU datafile");
    }
    Ok(())
}

pub fn refuse_s19k_mtd2_amlsecu_as_factory(kind: S19kAmlsecuImageKind) -> Result<(), &'static str> {
    if matches!(
        kind,
        S19kAmlsecuImageKind::Mtd2Android1 | S19kAmlsecuImageKind::Mtd2Android2
    ) {
        return Err("mtd2 AMLSECU 20211119 is not factory SD 20231115 boot/recovery");
    }
    Ok(())
}

pub fn refuse_s19k_mtd2_kernel_as_20231108(kernel: u32) -> Result<(), &'static str> {
    if kernel == S19K_20231108_KERNEL_SIZE {
        return Err("20231108/factory kernel 0x5C0800 is not mtd2 kernel 0x5C2000");
    }
    Ok(())
}

pub fn admit_s19k_78_mtd2_kernels_identical(equal: bool) -> Result<(), &'static str> {
    if !equal {
        return Err("mtd2 A1 and A2 kernels must be byte-identical");
    }
    Ok(())
}

pub fn refuse_s19k_mtd2_seconds_as_identical(equal: bool) -> Result<(), &'static str> {
    if equal {
        return Err("mtd2 A1/A2 second payloads are distinct high-entropy blobs");
    }
    Ok(())
}

pub fn admit_s19k_78_mtd2_a1_second_layout() -> Result<(), &'static str> {
    let want = S19K_78_MTD2_ANDROID_OFF
        + S19K_78_MTD2_PAGE_SIZE as usize
        + S19K_78_MTD2_KERNEL_SIZE as usize;
    if want != S19K_78_MTD2_A1_SECOND_OFF {
        return Err("A1 second is page+kernel because ramdisk_size=0");
    }
    Ok(())
}

pub fn admit_s19k_78_mtd2_a2_ramdisk_layout() -> Result<(), &'static str> {
    let want = S19K_78_MTD2_ANDROID2_OFF
        + S19K_78_MTD2_PAGE_SIZE as usize
        + S19K_78_MTD2_KERNEL_SIZE as usize;
    if want != S19K_78_MTD2_A2_RAMDISK_OFF {
        return Err("A2 ramdisk is page+kernel (0x5C2000 already 2KiB-aligned)");
    }
    Ok(())
}

pub fn admit_s19k_78_mtd2_cmdline(page0: &[u8]) -> Result<(), &'static str> {
    if page0.len() < 64 + S19K_20231108_CMDLINE.len() {
        return Err("mtd2 ANDROID page0 shorter than cmdline");
    }
    if &page0[64..64 + S19K_20231108_CMDLINE.len()] != S19K_20231108_CMDLINE {
        return Err("mtd2 ANDROID cmdline is init=/sbin/init");
    }
    Ok(())
}

pub fn admit_s19k_78_mtd2_android1_header(h: S19kAndroidBootHdr) -> Result<(), &'static str> {
    if h.kernel_size != S19K_78_MTD2_KERNEL_SIZE
        || h.ramdisk_size != 0
        || h.second_size != S19K_78_MTD2_SECOND_SIZE
        || h.page_size != S19K_78_MTD2_PAGE_SIZE
        || h.kernel_addr != S19K_20231108_KERNEL_ADDR
        || h.ramdisk_addr != S19K_20231108_RAMDISK_ADDR
        || h.second_addr != S19K_20231108_SECOND_ADDR
        || h.tags_addr != S19K_20231108_TAGS_ADDR
    {
        return Err("mtd2 A1 is kernel 0x5C2000 / ramdisk 0 / second 0x7800");
    }
    Ok(())
}

pub fn admit_s19k_78_mtd2_android2_header(h: S19kAndroidBootHdr) -> Result<(), &'static str> {
    if h.kernel_size != S19K_78_MTD2_KERNEL_SIZE
        || h.ramdisk_size != S19K_78_MTD2_ANDROID2_RAMDISK_SIZE
        || h.second_size != S19K_78_MTD2_SECOND_SIZE
        || h.page_size != S19K_78_MTD2_PAGE_SIZE
        || h.kernel_addr != S19K_20231108_KERNEL_ADDR
        || h.ramdisk_addr != S19K_20231108_RAMDISK_ADDR
        || h.second_addr != S19K_20231108_SECOND_ADDR
        || h.tags_addr != S19K_20231108_TAGS_ADDR
    {
        return Err("mtd2 A2 is kernel 0x5C2000 / ramdisk 0x662000 / second 0x7800");
    }
    Ok(())
}

pub fn refuse_s19k_mtd2_payload_as_gzip(head: &[u8]) -> Result<(), &'static str> {
    if head.len() >= 2 && head[0] == 0x1F && head[1] == 0x8B {
        return Ok(());
    }
    Err("mtd2 kernel/ramdisk/second heads are not gzip; high-entropy / encrypted")
}

/// Cross-corpus: AMLSECU kind 2 ⇔ ramdisk 0; kind 3 ⇔ ramdisk present.
/// Holds for factory item 17/9, 20231108 BMU, and `a lab unit` mtd2 A1/A2.
pub fn admit_s19k_amlsecu_kind_matches_ramdisk(
    kind: u32,
    ramdisk_size: u32,
) -> Result<(), &'static str> {
    match kind {
        S19K_AMLSECU_KIND_RECOVERY if ramdisk_size == 0 => Ok(()),
        S19K_AMLSECU_KIND_BOOT if ramdisk_size > 0 => Ok(()),
        S19K_AMLSECU_KIND_RECOVERY => {
            Err("AMLSECU kind 2 (recovery-class) requires ramdisk_size=0")
        }
        S19K_AMLSECU_KIND_BOOT => Err("AMLSECU kind 3 (boot-class) requires ramdisk_size>0"),
        _ => Err("unknown AMLSECU declared_header_len; not an admitted boot/recovery class"),
    }
}

pub fn refuse_s19k_amlsecu_kind2_as_boot_ramdisk(
    kind: u32,
    ramdisk_size: u32,
) -> Result<(), &'static str> {
    if kind == S19K_AMLSECU_KIND_RECOVERY && ramdisk_size > 0 {
        return Err("AMLSECU kind 2 with nonzero ramdisk is not an admitted boot image");
    }
    Ok(())
}

pub fn refuse_s19k_amlsecu_kind3_as_recovery(
    kind: u32,
    ramdisk_size: u32,
) -> Result<(), &'static str> {
    if kind == S19K_AMLSECU_KIND_BOOT && ramdisk_size == 0 {
        return Err("AMLSECU kind 3 with ramdisk_size=0 is not an admitted recovery image");
    }
    Ok(())
}

pub fn refuse_s19k_factory_recovery_as_mtd2_a1() -> Result<(), &'static str> {
    Err(
        "factory recovery kind 2 ramdisk 0 uses kernel 0x5C0800 + 20231115; mtd2 A1 is 0x5C2000 + 20211119",
    )
}

pub fn refuse_s19k_factory_boot_as_mtd2_a2() -> Result<(), &'static str> {
    Err("factory boot kind 3 ramdisk 0x686800 + 20231115; mtd2 A2 is ramdisk 0x662000 + 20211119")
}

pub fn refuse_s19k_20231108_as_mtd2_a2() -> Result<(), &'static str> {
    Err("20231108 kind 3 ramdisk 0x66A000; mtd2 A2 is ramdisk 0x662000 + 20211119")
}

/// Factory PARTITION/recovery does not fit `a lab unit` BOS mtd3 (UBI stock_config).
pub fn admit_s19k_factory_recovery_overflows_78_mtd3() -> Result<(), &'static str> {
    let item = S19K_AML_UPGRADE_ITEM17_RECOVERY_SIZE;
    let dest = S19K_78_MTD3_BYTES as u64;
    if item <= dest {
        return Err("factory recovery must overflow .78 BOS mtd3");
    }
    if item - dest != S19K_FACTORY_RECOVERY_OVERFLOW_VS_78_MTD3 {
        return Err("factory recovery overflow vs BOS mtd3 is 821760");
    }
    Ok(())
}

pub fn refuse_s19k_factory_recovery_item_as_78_bos_mtd3() -> Result<(), &'static str> {
    Err(
        "factory PARTITION/recovery 6064640 does not fit .78 BOS mtd3 stock_config 5242880; do not nandwrite",
    )
}

pub fn refuse_s19k_s30v_mtd3_name_as_78_bos(
    s30v_name: &str,
    bos_name: &str,
) -> Result<(), &'static str> {
    if s30v_name == S19K_S30V_MTD3_NAME && bos_name == S19K_78_MTD3_NAME {
        return Err("s30v mtd3 name recovery is not BOS stock_config");
    }
    Ok(())
}

pub fn admit_s19k_factory_recovery_second_layout() -> Result<(), &'static str> {
    let want = S19K_20231108_PAGE_SIZE as usize + S19K_20231108_KERNEL_SIZE as usize;
    if want != S19K_FACTORY_RECOVERY_SECOND_OFF {
        return Err("factory recovery second is page+kernel = 0x5C1000");
    }
    if S19K_FACTORY_RECOVERY_SECOND_OFF != S19K_FACTORY_BOOT_RAMDISK_OFF {
        return Err("factory recovery second offset equals factory boot ramdisk offset");
    }
    Ok(())
}

pub fn refuse_s19k_factory_recovery_second_as_boot_ramdisk() -> Result<(), &'static str> {
    Err("factory recovery 0x5C1000 is second-stage 30720 B, not factory boot ramdisk 0x686800")
}

pub fn admit_s19k_factory_partition_subs(subs: &[&str]) -> Result<(), &'static str> {
    if subs == S19K_FACTORY_PARTITION_SUBS {
        return Ok(());
    }
    Err("factory PARTITION subs are _aml_dtb/boot/bootloader/recovery")
}

pub fn admit_s19k_factory_pack_has_no_restock_partitions(
    items: &[S19kAmlUpgradeItem],
) -> Result<(), &'static str> {
    for it in items {
        if it.main == "PARTITION"
            && S19K_FACTORY_RESTOCK_MISSING
                .iter()
                .any(|n| *n == it.sub.as_str())
        {
            return Err("factory pack unexpectedly has PARTITION/config|misc|nvdata|tpl");
        }
    }
    Ok(())
}

pub fn refuse_s19k_factory_pack_as_s30v_restock() -> Result<(), &'static str> {
    Err(
        "factory SD has PARTITION/_aml_dtb|boot|bootloader|recovery only; no config/misc/nvdata/tpl; not a full s30v restock",
    )
}

pub fn refuse_s19k_factory_conf_as_partition_config(
    main: &str,
    sub: &str,
) -> Result<(), &'static str> {
    if main == "conf" && (sub == "keys" || sub == "platform") {
        return Err(
            "conf/keys and conf/platform are AmlImagePack conf items, not PARTITION/config",
        );
    }
    Ok(())
}

pub fn refuse_s19k_factory_partition_sub_as_restock_slot(sub: &str) -> Result<(), &'static str> {
    if S19K_FACTORY_RESTOCK_MISSING.contains(&sub) {
        return Err("factory pack has no PARTITION item for this s30v/BOS restock slot");
    }
    Ok(())
}

/// Size-fits is not permission. Factory boot is 12_907_008; BOS mtd2 is 52_428_800.
pub fn admit_s19k_factory_boot_size_fits_78_mtd2() -> Result<(), &'static str> {
    if (S19K_AML_UPGRADE_ITEM9_BOOT_SIZE as usize) >= S19K_78_MTD2_BYTES {
        return Err("factory PARTITION/boot must be smaller than .78 BOS mtd2");
    }
    Ok(())
}

pub fn refuse_s19k_factory_boot_item_as_78_mtd2_nandwrite() -> Result<(), &'static str> {
    Err(
        "factory PARTITION/boot 12907008 size-fits BOS mtd2 52428800 but is 20231115 kind-3 ramdisk 0x686800, not the 20211119 A1+A2 pair; do not nandwrite",
    )
}

pub fn refuse_s19k_s30v_boot_as_78_mtd2() -> Result<(), &'static str> {
    Err("s30v boot is 32 MiB; .78 BOS mtd2 is 50 MiB stock_system")
}

pub fn admit_s19k_android_name_empty(page0: &[u8]) -> Result<(), &'static str> {
    let end = S19K_ANDROID_NAME_OFF + S19K_ANDROID_NAME_LEN;
    if page0.len() < end {
        return Err("ANDROID page0 shorter than name field");
    }
    if page0[S19K_ANDROID_NAME_OFF..end].iter().any(|b| *b != 0) {
        return Err("S19k ANDROID name[48:64] is 16 zero bytes");
    }
    Ok(())
}

pub fn admit_s19k_factory_boot_recovery_kernels_identical(equal: bool) -> Result<(), &'static str> {
    if equal {
        return Ok(());
    }
    Err("factory boot/recovery share one 0x5C0800 kernel")
}

pub fn refuse_s19k_factory_recovery_second_as_boot_second() -> Result<(), &'static str> {
    Err("factory recovery second head 68caf5a1 is not boot second 27847e00")
}

pub fn refuse_s19k_factory_recovery_second_as_meson1_enc() -> Result<(), &'static str> {
    Err("factory recovery second is 30720 B head 68caf5a1; meson1_ENC is 29728 B head 5dc75d64")
}

/// Held `mtd3_stock_config.bin` is UBI stock_config (ubi2), not porc plaintext.
pub fn admit_s19k_78_mtd3_is_ubi_stock_config(blob: &[u8]) -> Result<(), &'static str> {
    if blob.len() >= 4 && &blob[..4] == S19K_78_MTD3_UBI_MAGIC {
        if blob.len() >= 24 {
            if blob[4] != S19K_78_MTD3_UBI_VERSION {
                return Err("mtd3 UBI version is 1");
            }
            let vid = u32::from_be_bytes(blob[16..20].try_into().unwrap());
            let data = u32::from_be_bytes(blob[20..24].try_into().unwrap());
            if vid != S19K_78_MTD3_VID_HDR_OFF || data != S19K_78_MTD3_DATA_OFF {
                return Err("mtd3 UBI vid_hdr=2048 data=4096 (BE)");
            }
        }
    } else if !blob.windows(4).any(|w| w == S19K_78_MTD3_UBI_MAGIC) {
        return Err("mtd3_stock_config.bin starts with UBI#");
    }
    if blob.len() == S19K_78_MTD3_BYTES {
        if &blob[S19K_78_MTD3_CGMINER_CONF_OFF
            ..S19K_78_MTD3_CGMINER_CONF_OFF + S19K_78_MTD3_CGMINER_CONF.len()]
            != S19K_78_MTD3_CGMINER_CONF
        {
            return Err("mtd3 cgminer.conf dent is at 3283000");
        }
        if &blob[S19K_78_MTD3_NETWORK_CONF_OFF
            ..S19K_78_MTD3_NETWORK_CONF_OFF + S19K_78_MTD3_NETWORK_CONF.len()]
            != S19K_78_MTD3_NETWORK_CONF
        {
            return Err("mtd3 network.conf dent is at 3283392");
        }
    } else if !blob
        .windows(S19K_78_MTD3_CGMINER_CONF.len())
        .any(|w| w == S19K_78_MTD3_CGMINER_CONF)
        || !blob
            .windows(S19K_78_MTD3_NETWORK_CONF.len())
            .any(|w| w == S19K_78_MTD3_NETWORK_CONF)
    {
        return Err("mtd3 UBI names cgminer.conf and network.conf");
    }
    Ok(())
}

pub fn admit_s19k_78_mtd3_geometry(len: usize) -> Result<(), &'static str> {
    if len != S19K_78_MTD3_BYTES || len / S19K_78_MTD3_PEB != S19K_78_MTD3_PEB_COUNT {
        return Err("mtd3 is 40 x 128KiB PEBs = 5242880");
    }
    Ok(())
}

pub fn refuse_s19k_mtd3_as_updateporc_source(blob: &[u8]) -> Result<(), &'static str> {
    if blob
        .windows(b"updateporc".len())
        .any(|w| w == b"updateporc")
    {
        return Ok(());
    }
    Err("mtd3_stock_config.bin has 0 updateporc bytes; UBI stock_config is not a porc script")
}

pub fn refuse_s19k_mtd3_as_fileparser_source(blob: &[u8]) -> Result<(), &'static str> {
    if blob
        .windows(b"FileParser".len())
        .any(|w| w == b"FileParser")
    {
        return Ok(());
    }
    Err("mtd3_stock_config.bin has 0 FileParser bytes")
}

pub fn refuse_s19k_mtd3_as_uart_trans_source(blob: &[u8]) -> Result<(), &'static str> {
    if blob
        .windows(b"uart_trans".len())
        .any(|w| w == b"uart_trans")
    {
        return Ok(());
    }
    Err("mtd3_stock_config.bin has 0 uart_trans bytes; not 4cc0/uart_trans.ko")
}

pub fn refuse_s19k_mtd3_as_android_system(blob: &[u8]) -> Result<(), &'static str> {
    if blob.windows(b"ANDROID!".len()).any(|w| w == b"ANDROID!") {
        return Ok(());
    }
    Err("mtd3 is UBI stock_config, not ANDROID stock_system")
}

pub fn refuse_s19k_mtd3_miner_conf_as_separate_dent() -> Result<(), &'static str> {
    Err("mtd3 miner.conf at 3283002 is the cgminer.conf substring, not a second dent")
}

pub fn admit_s19k_78_mtd3_ubi_volume_name(name: &[u8]) -> Result<(), &'static str> {
    if name == S19K_78_MTD3_UBI_VOL_NAME {
        return Ok(());
    }
    Err("mtd3 UBI volume name is config_data")
}

pub fn admit_s19k_78_mtd3_vtbl_name(blob: &[u8]) -> Result<(), &'static str> {
    let off = S19K_78_MTD3_VTBL_NAME_OFF;
    let n = S19K_78_MTD3_UBI_VOL_NAME;
    if blob.len() >= off + n.len() && &blob[off..off + n.len()] == n {
        return Ok(());
    }
    if blob.windows(n.len()).any(|w| w == n) {
        return Ok(());
    }
    Err("mtd3 UBI vtbl name at 397328 is config_data")
}

pub fn refuse_s19k_78_mtd3_ubi_vol_as_proc_mtd_name() -> Result<(), &'static str> {
    Err("UBI volume config_data is not /proc/mtd stock_config")
}

pub fn refuse_s19k_78_mtd3_ubi_vol_as_s30v_recovery() -> Result<(), &'static str> {
    Err("UBI volume config_data is not s30v mtd3 recovery")
}

pub fn refuse_s19k_78_nand_env_as_updateporc(blob: &[u8]) -> Result<(), &'static str> {
    if blob
        .windows(b"updateporc".len())
        .any(|w| w == b"updateporc")
    {
        return Ok(());
    }
    Err("nand_env.bin has 0 updateporc; nandrecovery is recover_to_stock, not updateporc.sh")
}

pub fn refuse_s19k_upgrade_cgi_as_updateporc_script(cgi: &str) -> Result<(), &'static str> {
    if cgi.contains("updateporc") {
        return Ok(());
    }
    Err("upgrade.cgi execs /usr/sbin/daemonc only; it is not updateporc.sh")
}

pub fn admit_s19k_78_mtd3_vtbl_peb4_name(blob: &[u8]) -> Result<(), &'static str> {
    let off = S19K_78_MTD3_VTBL_PEB4_NAME_OFF;
    let n = S19K_78_MTD3_UBI_VOL_NAME;
    if blob.len() >= off + n.len() && &blob[off..off + n.len()] == n {
        return Ok(());
    }
    if blob.windows(n.len()).any(|w| w == n) {
        return Ok(());
    }
    Err("mtd3 UBI vtbl PEB4 name at 528400 is config_data")
}

pub fn admit_s19k_78_mtd3_vtbl_copies_identical(equal: bool) -> Result<(), &'static str> {
    if equal {
        return Ok(());
    }
    Err("mtd3 UBI vtbl record 0 is identical on PEB3 and PEB4")
}

pub fn refuse_s19k_78_mtd3_single_vtbl_peb_as_complete() -> Result<(), &'static str> {
    Err("mtd3 UBI layout volume is a PEB3+PEB4 pair; restoring one copy is incomplete")
}

pub fn refuse_s19k_upgrade_clear_as_updateporc_script(cgi: &str) -> Result<(), &'static str> {
    if cgi.contains("updateporc") {
        return Ok(());
    }
    Err("upgrade_clear.cgi execs /usr/sbin/daemonc and miner_act=3; it is not updateporc.sh")
}

/// Braiins `S97recovery-flag` promotes FIRST_BOOT (0x02) to SUCCESSFUL (0x03).
/// : the write is compare-gated. `nanddump -l 1` must equal
/// FIRST_BOOT **before** `flash_erase` / `nandwrite`.
pub fn admit_s19k_s97_promotes_first_boot_to_successful(script: &str) -> Result<(), &'static str> {
    admit_s19k_s97_nanddump_02_before_write_03(script)
}

pub fn admit_s19k_s97_nanddump_02_before_write_03(script: &str) -> Result<(), &'static str> {
    if !script.contains("RECOVERY_FLAG_FIRST_BOOT") {
        return Err("S97 must read FIRST_BOOT");
    }
    if !script.contains("RECOVERY_FLAG_SUCCESSFUL") {
        return Err("S97 must write SUCCESSFUL");
    }
    if !script.contains("flash_erase") || !script.contains("nandwrite -p -s") {
        return Err("S97 must erase+nandwrite the flag eraseblock");
    }
    if !script.contains("BOS_MODE") || !script.contains("nand") {
        return Err("S97 only runs in NAND mode");
    }
    let dump = script
        .find("nanddump -s $LOCAL_RECOVERY_FLAGS_OFFSET_BOS_LAYOUT -l 1")
        .ok_or("S97 must nanddump 1 byte at LOCAL_RECOVERY_FLAGS_OFFSET_BOS_LAYOUT")?;
    let erase = script
        .find("flash_erase")
        .ok_or("S97 must flash_erase the flag eraseblock")?;
    let write = script
        .find("nandwrite -p -s")
        .ok_or("S97 must nandwrite the flag")?;
    if !(dump < erase && erase < write) {
        return Err("S97 must nanddump-compare FIRST_BOOT before flash_erase/nandwrite");
    }
    if !script.contains("RECOVERY_FLAG_FIRST_BOOT") {
        return Err("S97 compare target is FIRST_BOOT 0x02");
    }
    Ok(())
}

pub fn refuse_s19k_s97_as_unconditional_03() -> Result<(), &'static str> {
    Err("S97 writes 0x03 only if nanddump equals FIRST_BOOT 0x02; not unconditional")
}

pub fn refuse_s19k_s97_as_promote_01_to_03() -> Result<(), &'static str> {
    Err("S97 never reads RECOVERY_FLAG_INSTALLED 0x01; leftover 0x01 is a no-op")
}

/// Stock CGI must invoke daemonc and stamp `/tmp/miner_act`. Not DCENT.
/// 20231108 BMU is not a plaintext source of `updateporc.sh`.
pub fn refuse_s19k_20231108_bmu_as_plaintext_porc(blob: &[u8]) -> Result<(), &'static str> {
    if blob
        .windows(b"updateporc".len())
        .any(|w| w == b"updateporc")
    {
        return Ok(());
    }
    Err("20231108 BMU has no plaintext updateporc; payload @ 0x4000 is ciphertext, not a script")
}

pub fn admit_s19k_stock_upgrade_cgi(cgi: &str, miner_act: u8) -> Result<(), &'static str> {
    if !cgi.contains("/usr/sbin/daemonc") {
        return Err("stock upgrade CGI must exec /usr/sbin/daemonc");
    }
    if !cgi.contains("update.bmu") {
        return Err("stock upgrade CGI must stage update.bmu");
    }
    if miner_act == S19K_STOCK_MINER_ACT_SUCCESS {
        if !cgi.contains("echo 2 > /tmp/miner_act") {
            return Err("upgrade.cgi success must write miner_act=2");
        }
    } else if miner_act == S19K_STOCK_MINER_ACT_CLEAR {
        if !cgi.contains("echo 3 > /tmp/miner_act") {
            return Err("upgrade_clear.cgi success must write miner_act=3");
        }
    } else {
        return Err("stock miner_act must be 2 (upgrade) or 3 (clear)");
    }
    Ok(())
}

/// Held `updateporc.sh` copies. None is S19k Amlogic NAND.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kHeldUpdateporcKind {
    /// 2022-12-26 S19j Pro **CVCtrl** (3920 B): CV183X eMMC `mmcblk0p*`.
    CvitekEmmcComparative,
    /// HashSource S19 Pro Hydro/Zynq (2627 B): UBI on **mtd6** + marker
    /// `flash_erase /dev/mtd0 0x1B00000`. S19k 6-part map has no mtd6.
    ZynqUbiMtd6Comparative,
}

pub const HELD_CVITEK_UPDATEPORC_BANNER: &str = "for CV183X platform update";
pub const HELD_CVITEK_UPDATEPORC_BYTES: usize = 3920;
pub const HELD_CVITEK_EMMC_TARGETS: &[&str] =
    &["/dev/mmcblk0p1", "/dev/mmcblk0p3", "/dev/mmcblk0p4"];
pub const HELD_ZYNQ_UPDATEPORC_BYTES: usize = 2627;
pub const HELD_ZYNQ_UPDATE_UBI_MTD: u8 = 6;
pub const HELD_ZYNQ_UPDATE_MARKER_MTD: u8 = 0;
pub const HELD_ZYNQ_UPDATE_MARKER_OFF: &str = "0x1B00000";
pub const HELD_FILEPARSER_BYTES: usize = 20184;
pub const HELD_ZYNQ_FILEPARSER_BYTES: usize = 23912;
pub const HELD_FILEPARSER_MACHINE: u16 = 40;
pub const HELD_FILEPARSER_NOT_BTMU: &str = "Not A Btmu File!";
pub const HELD_FILEPARSER_TYPE_MISMATCH: &str = "input miner_type and bmu miner type donot match!";
pub const HELD_FILEPARSER_RSA_VERIFY: &str = "RSA_verify";
pub const HELD_FILEPARSER_SHA256_INIT: &str = "SHA256_Init";
pub const HELD_FILEPARSER_PEM_READ: &str = "PEM_read_bio_RSA_PUBKEY";
pub const HELD_FILEPARSER_DEBUG_PUB: &str = "/etc/bitmain.pub";
pub const HELD_FILEPARSER_RELEASE_PUB: &str = "/etc/bitmain-release.pub";

pub fn classify_held_updateporc(text: &str) -> Result<S19kHeldUpdateporcKind, &'static str> {
    let has_banner = text.contains(HELD_CVITEK_UPDATEPORC_BANNER);
    let has_emmc = HELD_CVITEK_EMMC_TARGETS.iter().all(|p| text.contains(p));
    if has_banner && has_emmc {
        return Ok(S19kHeldUpdateporcKind::CvitekEmmcComparative);
    }
    if text.contains("ubiattach")
        && text.contains("/dev/mtd6")
        && text.contains(HELD_ZYNQ_UPDATE_MARKER_OFF)
        && text.contains("flash_erase /dev/mtd0")
    {
        return Ok(S19kHeldUpdateporcKind::ZynqUbiMtd6Comparative);
    }
    Err("held updateporc.sh is neither CV183X eMMC nor Zynq mtd6; S19k NAND copy still absent")
}

/// Neither held `updateporc.sh` may write S19k NAND.
pub fn refuse_held_updateporc_as_s19k_nand_writer(
    kind: S19kHeldUpdateporcKind,
) -> Result<(), &'static str> {
    match kind {
        S19kHeldUpdateporcKind::CvitekEmmcComparative => Err(
            "held updateporc.sh writes CV183X eMMC mmcblk0p*; refuse as S19k Amlogic NAND writer",
        ),
        S19kHeldUpdateporcKind::ZynqUbiMtd6Comparative => Err(
            "held updateporc.sh uses UBI mtd6 + flash_erase mtd0 0x1B00000; S19k 6-part has no mtd6; bootloader write forbidden",
        ),
    }
}

///  name kept as an alias.
pub fn refuse_cvitek_updateporc_as_s19k_nand_writer(
    kind: S19kHeldUpdateporcKind,
) -> Result<(), &'static str> {
    refuse_held_updateporc_as_s19k_nand_writer(kind)
}

pub fn refuse_s19k_stock_flash_via_mmcblk0(path: &str) -> Result<(), &'static str> {
    if path.contains("mmcblk") {
        return Err("refuse mmcblk* write on am3-s19k NAND");
    }
    Ok(())
}

/// S19k 6-part map has no update volume at mtd6.
pub fn refuse_s19k_mtd6_update_volume(target_mtd: u8) -> Result<(), &'static str> {
    if target_mtd == HELD_ZYNQ_UPDATE_UBI_MTD || target_mtd > 5 {
        return Err("S19k 6-part NAND has no mtd6 update volume; refuse Zynq UBI writer");
    }
    Ok(())
}

/// Zynq `set_marker` erases bootloader mtd0 at 0x1B00000. Never on S19k.
pub fn refuse_s19k_zynq_mtd0_update_marker(
    target_mtd: u8,
    offset_hex: &str,
) -> Result<(), &'static str> {
    let off = offset_hex.to_ascii_lowercase();
    if target_mtd == 0 && off.contains("1b00000") {
        return Err(
            "refuse Zynq update marker flash_erase /dev/mtd0 0x1B00000 on S19k (bootloader)",
        );
    }
    Ok(())
}

/// FileParser is Gen-3 RSA-SHA256 BMU split/verify. Comparative, not S19k SoT.
pub fn refuse_fileparser_as_s19k_nand_sot() -> Result<(), &'static str> {
    Err(
        "held FileParser copies are CVCtrl 20184 B / Zynq 23912 B ELF32 ARM with RSA_verify; not the S19k Amlogic NAND writer",
    )
}

/// Held FileParser `datafile` string offsets. Type 9 is a **filename**, not an ANDROID decoder.
pub const HELD_CVITEK_FILEPARSER_BYTES: usize = 20184;
pub const HELD_CVITEK_FILEPARSER_DATAFILE_OFF: usize = 15460;
pub const HELD_ZYNQ_FILEPARSER_DATAFILE_OFF: usize = 16212;
pub const HELD_SD_FILEPARSER_BYTES: usize = 11620;
pub const S19K_FILEPARSER_IN_78_EXTRACT: bool = false;
pub const S19K_FILEPARSER_IN_AWESOME_AML_NAND: bool = false;

pub fn admit_held_fileparser_names_datafile(blob: &[u8], off: usize) -> Result<(), &'static str> {
    let n = b"datafile";
    if blob.len() < off + n.len() || &blob[off..off + n.len()] != n {
        return Err("FileParser blob does not name datafile at the pinned offset");
    }
    if blob.windows(7).any(|w| w == b"ANDROID") {
        return Err("this FileParser embeds ANDROID — unexpected for held copies");
    }
    Ok(())
}

/// FileParser type 9 writes the name `datafile` and dumps bytes. It does not parse ANDROID!.
pub fn refuse_held_fileparser_as_s19k_android_decoder() -> Result<(), &'static str> {
    Err(
        "held FileParser case 9 only names datafile (NBP1901 0x61746164/0x656c6966); no ANDROID decoder",
    )
}

/// FileParser-equivalent: slice the single-BMU type-9 payload. Does not decrypt.
pub fn extract_s19k_single_bmu_datafile(blob: &[u8]) -> Result<&[u8], &'static str> {
    if blob.len() < S19K_SINGLE_BMU_HEADER_LEN {
        return Err("blob shorter than single-BMU header");
    }
    let toc = parse_s19k_single_bmu_toc(&blob[..S19K_SINGLE_BMU_HEADER_LEN])?;
    let start = toc.files[0].data_offset;
    let end = start
        .checked_add(toc.files[0].size as usize)
        .ok_or("datafile size overflow")?;
    if blob.len() < end {
        return Err("blob shorter than TOC datafile");
    }
    Ok(&blob[start..end])
}

/// Single-system Amlogic NAND (no A/B). From am3-s19kpro README.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kNandSlot {
    pub mtd: u8,
    pub name: &'static str,
    pub role: &'static str,
    pub writable_by_sysupgrade: bool,
}

pub const S19K_NAND_MAP: &[S19kNandSlot] = &[
    S19kNandSlot {
        mtd: 0,
        name: "bootloader",
        role: "BL2 + FIP + U-Boot",
        writable_by_sysupgrade: false,
    },
    S19kNandSlot {
        mtd: 1,
        name: "tpl",
        role: "secondary U-Boot",
        writable_by_sysupgrade: false,
    },
    S19kNandSlot {
        mtd: 2,
        name: "stock_system",
        role: "Bitmain stock rootfs+kernel (rollback target)",
        writable_by_sysupgrade: false,
    },
    S19kNandSlot {
        mtd: 3,
        name: "stock_config",
        role: "stock UBIFS config (ubi2 on `a lab unit`)",
        writable_by_sysupgrade: false,
    },
    S19kNandSlot {
        mtd: 4,
        name: "overlay",
        role: "/data UBI",
        writable_by_sysupgrade: false,
    },
    S19kNandSlot {
        mtd: 5,
        name: "system",
        role: "DCENT_OS uImage window at LOCAL 0x05100000",
        writable_by_sysupgrade: true,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kInstallCarrier {
    BraiinsRootSsh,
    StockAmlCtrl,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kBackupManifest {
    pub nand_env: &'static str,
    pub mtd5_window: &'static str,
    pub fw_printenv: &'static str,
    pub gpio437_observed: &'static str,
}

pub const S19K_BACKUP_MANIFEST: S19kBackupManifest = S19kBackupManifest {
    nand_env: "nand_env.bin",
    mtd5_window: "mtd5_rootfs_window.bin",
    fw_printenv: "fw_printenv.txt",
    gpio437_observed: "gpio437.value",
};

/// Filenames the installer actually writes (`--backup-only`). Schema names above stay aliases.
pub const S19K_BACKUP_NAND_ENV_NAMES: &[&str] = &["nand_env.bin", "nand_env.bak"];
pub const S19K_BACKUP_MTD5_NAMES: &[&str] = &["mtd5_rootfs_window.bin", "mtd5_pre_install.bin"];
pub const S19K_BACKUP_FWENV_NAMES: &[&str] = &["fw_printenv.txt", "fw_env_pre.txt"];
pub const S19K_BACKUP_LEDGER_NAME: &str = "BACKUP_LEDGER.txt";

pub const S19K_BACKUP_SCHEMA: &str = "dcentos.amlogic-backup/v1";
/// Live Braiins AML `/dev/nand_env` copy is one 64 KiB `dd`.
pub const NAND_ENV_BACKUP_LEN: usize = 65_536;
/// Track-1 Braiins 25.07-plus on this AML image: no `fw_printenv`/`fw_setenv`.
pub const BRAIINS_AML_L3_HINT: &str =
    "Braiins AML image may lack fw_printenv/fw_setenv; backup nand_env+mtd5 is still required, env-flip/flash is refused";

/// Observed userspace tools on the target. Does not SSH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kTargetTools {
    pub dd: bool,
    pub sha256sum: bool,
    pub nanddump: bool,
    pub nandwrite: bool,
    pub flash_erase: bool,
    pub fw_printenv: bool,
    pub fw_setenv: bool,
}

impl S19kTargetTools {
    pub fn backup_ok(self) -> bool {
        self.dd && self.sha256sum && self.nanddump
    }

    pub fn env_flip_ok(self) -> bool {
        self.fw_setenv && self.fw_printenv
    }

    pub fn flash_tools_ok(self) -> bool {
        self.backup_ok() && self.nandwrite && self.flash_erase && self.env_flip_ok()
    }
}

/// Files actually staged in `--artifact-dir`. `fw_printenv` is optional (L3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kBackupCompleteness {
    pub nand_env: bool,
    pub mtd5_window: bool,
    pub gpio437: bool,
    pub fw_printenv: bool,
}

impl S19kBackupCompleteness {
    pub fn backup_complete(self) -> bool {
        self.nand_env && self.mtd5_window && self.gpio437
    }

    pub fn env_flip_ready(self) -> bool {
        self.backup_complete() && self.fw_printenv
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kBackupAdmitError {
    BackupToolsMissing,
    NandEnvSizeWrong,
    Mtd5Empty,
    MissingArtifact,
}

/// Backup is allowed when FLASH is not. L3 missing env tools do not block it.
pub fn admit_s19k_backup(
    tools: S19kTargetTools,
    nand_env_len: usize,
    mtd5_len: usize,
) -> Result<(), S19kBackupAdmitError> {
    if !tools.backup_ok() {
        return Err(S19kBackupAdmitError::BackupToolsMissing);
    }
    if nand_env_len != NAND_ENV_BACKUP_LEN {
        return Err(S19kBackupAdmitError::NandEnvSizeWrong);
    }
    if mtd5_len == 0 {
        return Err(S19kBackupAdmitError::Mtd5Empty);
    }
    Ok(())
}

/// Admit a staged `--artifact-dir` file list. Accepts schema names **or**
/// the installer aliases (`nand_env.bak`, `mtd5_pre_install.bin`).
pub fn admit_s19k_backup_filenames(
    names: &[&str],
) -> Result<S19kBackupCompleteness, S19kBackupAdmitError> {
    let completeness = S19kBackupCompleteness {
        nand_env: names.iter().any(|n| S19K_BACKUP_NAND_ENV_NAMES.contains(n)),
        mtd5_window: names.iter().any(|n| S19K_BACKUP_MTD5_NAMES.contains(n)),
        gpio437: names
            .iter()
            .any(|n| *n == S19K_BACKUP_MANIFEST.gpio437_observed),
        fw_printenv: names.iter().any(|n| S19K_BACKUP_FWENV_NAMES.contains(n)),
    };
    if !completeness.backup_complete() {
        return Err(S19kBackupAdmitError::MissingArtifact);
    }
    Ok(completeness)
}

/// Parse the installer `BACKUP_LEDGER.txt`. FLASH must stay false.
pub fn parse_s19k_backup_ledger(text: &str) -> Result<S19kBackupCompleteness, &'static str> {
    if !text.contains("schema=dcentos.amlogic-backup/v1") {
        return Err("backup ledger missing schema");
    }
    if !text.contains("clear_for_flash=false") {
        return Err("backup ledger must keep clear_for_flash=false");
    }
    if !text.contains("braiins_success_is_not_stock_go=true") {
        return Err("backup ledger must keep Braiins success != stock GO");
    }
    let nand = text.contains("nand_env=nand_env.bak") || text.contains("nand_env=nand_env.bin");
    let mtd5 = text.contains("mtd5_window=mtd5_pre_install.bin")
        || text.contains("mtd5_window=mtd5_rootfs_window.bin");
    let gpio = text.contains("gpio437_value=");
    let fw = text.contains("fw_printenv_present=true");
    let rec = text.contains("nandrecovery_env=nandrecovery_env.bin");
    let completeness = S19kBackupCompleteness {
        nand_env: nand,
        mtd5_window: mtd5,
        gpio437: gpio,
        fw_printenv: fw,
    };
    if !completeness.backup_complete() {
        return Err("backup ledger missing nand_env/mtd5/gpio437");
    }
    if !rec {
        return Err("backup ledger missing nandrecovery_env sidecar");
    }
    let rec_sha = ledger_field(text, "nandrecovery_env_sha256")
        .ok_or("backup ledger missing nandrecovery_env_sha256")?;
    admit_s19k_sha256_hex64(rec_sha)?;
    if let Some(nand_sha) = ledger_field(text, "nand_env_sha256") {
        if nand_sha.eq_ignore_ascii_case(rec_sha) {
            return Err("nandrecovery_env_sha256 must not equal nand_env_sha256");
        }
    }
    Ok(completeness)
}

///  leftover: a ledger without `nandrecovery_env.bin` is not recover-complete.
pub fn refuse_s19k_backup_ledger_without_nandrecovery_sidecar(
    text: &str,
) -> Result<(), &'static str> {
    if text.contains("nandrecovery_env=nandrecovery_env.bin") {
        return Ok(());
    }
    Err("BACKUP_LEDGER without nandrecovery_env.bin is not recover_env complete")
}

fn ledger_field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    text.lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .map(str::trim)
}

fn parse_u64_field(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Ledger honesty: live `/etc/dcentos/board_target` vs invented `--variant`.
pub const S19K_BOARD_TARGET_SOURCE_LIVE: &str = "live";
pub const S19K_BOARD_TARGET_SOURCE_PACKAGE: &str = "package";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kBackupIdentityRecord<'a> {
    /// Observed live file, or empty when source is package.
    pub board_target: &'a str,
    pub source: &'static str,
    pub package_name: &'a str,
}

/// Live file present → `live`. Missing/empty → `package`. Never infers SKU.
pub fn classify_s19k_backup_board_target_source(live: Option<&str>) -> &'static str {
    match live.map(str::trim).filter(|s| !s.is_empty()) {
        Some(_) => S19K_BOARD_TARGET_SOURCE_LIVE,
        None => S19K_BOARD_TARGET_SOURCE_PACKAGE,
    }
}

/// Package `--variant` is recorded separately. It is never copied into
/// `board_target` when the live file is missing.
pub fn record_s19k_backup_board_target<'a>(
    live_board_target: Option<&'a str>,
    package_name: &'a str,
) -> Result<S19kBackupIdentityRecord<'a>, &'static str> {
    let pkg = package_name.trim();
    if !s19k_board_target_is_live_alias(pkg) {
        return Err("package --variant is not an S19k live alias; refuse backup identity");
    }
    match live_board_target.map(str::trim).filter(|s| !s.is_empty()) {
        Some(name) => {
            if !s19k_board_target_is_live_alias(name) {
                return Err("live board_target is not an S19k alias; refuse backup identity");
            }
            Ok(S19kBackupIdentityRecord {
                board_target: name,
                source: S19K_BOARD_TARGET_SOURCE_LIVE,
                package_name: pkg,
            })
        }
        None => Ok(S19kBackupIdentityRecord {
            board_target: "",
            source: S19K_BOARD_TARGET_SOURCE_PACKAGE,
            package_name: pkg,
        }),
    }
}

/// `--execute` requires a live-observed identity. Package/`--variant` is not that.
pub fn refuse_s19k_restore_execute_package_identity(source: &str) -> Result<(), &'static str> {
    if source.trim() == S19K_BOARD_TARGET_SOURCE_LIVE {
        Ok(())
    } else {
        Err("restore --execute refuses board_target_source=package (invented from --variant)")
    }
}

/// Restore must not fail-open when `/etc/dcentos/board_target` is missing.
pub fn admit_s19k_restore_ledger_identity(board_target: &str) -> Result<(), &'static str> {
    let t = board_target.trim();
    if s19k_board_target_is_live_alias(t) {
        Ok(())
    } else if t.is_empty() {
        Err("restore ledger missing board_target; refuse fail-open on Braiins")
    } else {
        Err("restore ledger board_target is not am3-s19k")
    }
}

/// `--execute` must see a live SKU file. Missing is fail-open ( script).
pub fn admit_s19k_restore_live_board_target(
    live: Option<&str>,
    ledger_bt: &str,
) -> Result<(), &'static str> {
    let live = live.map(str::trim).filter(|s| !s.is_empty());
    let Some(live) = live else {
        return Err("restore --execute refuses missing live /etc/dcentos/board_target");
    };
    admit_s19k_restore_ledger_identity(live)?;
    if live != ledger_bt.trim() {
        return Err("live board_target != ledger board_target");
    }
    Ok(())
}

/// `/tmp` bench deploy stamps this so restore cannot treat Braiins as installed DCENT.
pub const S19K_TMP_DEPLOY_STAMP: &str = "/etc/dcentos/tmp_deploy";

pub fn refuse_s19k_restore_tmp_deploy_stamp(stamp_present: bool) -> Result<(), &'static str> {
    if stamp_present {
        return Err("restore refuses /etc/dcentos/tmp_deploy leftover from /tmp bench deploy");
    }
    Ok(())
}

pub fn admit_s19k_restore_mtd5_len(ledger_len: u64, file_len: u64) -> Result<(), &'static str> {
    if ledger_len == 0 || file_len == 0 {
        return Err("mtd5_len must be non-zero");
    }
    if ledger_len != file_len {
        return Err("mtd5_pre_install.bin length != ledger mtd5_len");
    }
    Ok(())
}

/// Bind BACKUP_LEDGER geometry/identity to the staged file and optional live `/proc/mtd`.
/// Does not flash. `CLEAR_FOR_FLASH` stays false.
pub fn admit_s19k_restore_ledger_vs_live(
    ledger: &str,
    file_mtd5_len: u64,
    live_proc_mtd: Option<&str>,
) -> Result<(), &'static str> {
    parse_s19k_backup_ledger(ledger)?;
    admit_s19k_restore_ledger_identity(ledger_field(ledger, "board_target").unwrap_or(""))?;
    let ledger_len = ledger_field(ledger, "mtd5_len")
        .and_then(parse_u64_field)
        .ok_or("restore ledger missing mtd5_len")?;
    admit_s19k_restore_mtd5_len(ledger_len, file_mtd5_len)?;
    let proc = ledger_field(ledger, "proc_mtd")
        .ok_or("restore ledger missing proc_mtd; refuse geometry-blind restore")?;
    let geo = compute_s19k_geometry_from_proc_mtd(proc)
        .ok_or("ledger proc_mtd cannot compute mtd5 geometry")?;
    admit_s19k_physical_mtd5_base(geo.mtd5_base)?;
    let claimed = ledger_field(ledger, "computed_mtd5_base")
        .and_then(parse_u64_field)
        .ok_or("restore ledger computed_mtd5_base unknown; refuse geometry-blind restore")?;
    if claimed != geo.mtd5_base {
        return Err("ledger computed_mtd5_base != recomputed from proc_mtd");
    }
    admit_s19k_mtd5_backup_covers_recovery(file_mtd5_len, geo.mtd5_base)?;
    if let Some(live) = live_proc_mtd {
        let live_geo = compute_s19k_geometry_from_proc_mtd(live)
            .ok_or("live /proc/mtd cannot compute mtd5 geometry")?;
        if live_geo.mtd5_base != geo.mtd5_base {
            return Err("live mtd5 base != backup ledger geometry");
        }
    }
    Ok(())
}

/// 64-hex SHA-256. Recovery cannot restore without a distinct hash per artifact.
pub fn admit_s19k_sha256_hex64(sha: &str) -> Result<(), &'static str> {
    let s = sha.trim();
    if s.len() != 64 {
        return Err("backup sha256 must be 64 hex chars");
    }
    if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("backup sha256 must be hex");
    }
    Ok(())
}

pub fn admit_s19k_backup_hashes(nand_env_sha: &str, mtd5_sha: &str) -> Result<(), &'static str> {
    admit_s19k_sha256_hex64(nand_env_sha)?;
    admit_s19k_sha256_hex64(mtd5_sha)?;
    if nand_env_sha.eq_ignore_ascii_case(mtd5_sha) {
        return Err("nand_env and mtd5 sha256 must not be identical");
    }
    Ok(())
}

/// Extract `nand_env_sha256` / `mtd5_sha256` from BACKUP_LEDGER and admit them.
pub fn admit_s19k_backup_ledger_hashes(text: &str) -> Result<(), &'static str> {
    let mut nand = None;
    let mut mtd5 = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("nand_env_sha256=") {
            nand = Some(v.trim());
        }
        if let Some(v) = line.strip_prefix("mtd5_sha256=") {
            mtd5 = Some(v.trim());
        }
    }
    match (nand, mtd5) {
        (Some(n), Some(m)) => admit_s19k_backup_hashes(n, m),
        _ => Err("backup ledger missing nand_env_sha256/mtd5_sha256"),
    }?;
    let rec = ledger_field(text, "nandrecovery_env_sha256")
        .ok_or("backup ledger missing nandrecovery_env_sha256")?;
    admit_s19k_sha256_hex64(rec)?;
    if let Some(n) = nand {
        if n.eq_ignore_ascii_case(rec) {
            return Err("nandrecovery_env_sha256 must not equal nand_env_sha256");
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kEnvFlipError {
    ClearForFlashNotYet,
    EnvToolsMissing,
    BackupIncomplete,
}

/// `fw_setenv` / firstboot flip. Always NOT_YET today; also refuse L3.
pub fn admit_s19k_env_flip(
    tools: S19kTargetTools,
    backup: S19kBackupCompleteness,
) -> Result<(), S19kEnvFlipError> {
    if !CLEAR_FOR_FLASH {
        return Err(S19kEnvFlipError::ClearForFlashNotYet);
    }
    if !tools.env_flip_ok() {
        return Err(S19kEnvFlipError::EnvToolsMissing);
    }
    if !backup.env_flip_ready() {
        return Err(S19kEnvFlipError::BackupIncomplete);
    }
    Ok(())
}

/// Installer `--backup-only` nanddumps **all of mtd5**, not the 0x05100000
/// uImage window. Restoring that file at [`ROOTFS_OFFSET_HEX`] would write
/// mtd5[0] onto the rootfs window.
pub const S19K_RESTORE_MTD5_USES_WINDOW_OFFSET: bool = false;

/// L3 / Braiins-without-fw_setenv can still restore the hashed mtd5 dump.
/// This is the opposite of FLASH: no env-flip, no DCENT image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kRestoreKind {
    /// `nandwrite -p /dev/mtd5 mtd5_pre_install.bin` after whole-partition erase.
    PreInstallMtd5Nanddump,
    /// Stock uImage + `fw_setenv firstboot` (L3 blocked).
    StockImageThenEnvFlip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kRestoreError {
    HashMismatch,
    BackupIncomplete,
    RestoreToolsMissing,
    BootloaderForbidden,
    WrongSafeOffPolarity,
    Stock7LayoutBlocked,
    EnvToolsMissing,
    WindowOffsetForbidden,
    RecoveryFlagOffsetMismatch,
    ClearForFlashNotYet,
    MissingLiveBoardTarget,
    TmpDeployStamp,
}

/// Compare ledger SHA-256s to hashes of the staged files.
pub fn admit_s19k_restore_file_hashes(
    ledger_nand_env: &str,
    ledger_mtd5: &str,
    file_nand_env: &str,
    file_mtd5: &str,
) -> Result<(), S19kRestoreError> {
    admit_s19k_backup_hashes(ledger_nand_env, ledger_mtd5)
        .map_err(|_| S19kRestoreError::HashMismatch)?;
    if !ledger_nand_env.eq_ignore_ascii_case(file_nand_env)
        || !ledger_mtd5.eq_ignore_ascii_case(file_mtd5)
    {
        return Err(S19kRestoreError::HashMismatch);
    }
    Ok(())
}

/// Tools for restoring the pre-install mtd5 nanddump. **No** fw_setenv.
pub fn admit_s19k_restore_nandwrite_preflight(
    tools: S19kTargetTools,
) -> Result<(), S19kRestoreError> {
    if !(tools.nandwrite && tools.nanddump && tools.flash_erase && tools.sha256sum) {
        return Err(S19kRestoreError::RestoreToolsMissing);
    }
    Ok(())
}

/// Refuse `nandwrite -s <rootfs window>` of `mtd5_pre_install.bin`.
pub fn refuse_s19k_restore_mtd5_at_rootfs_window_offset(
    use_window_offset: bool,
) -> Result<(), S19kRestoreError> {
    if use_window_offset || S19K_RESTORE_MTD5_USES_WINDOW_OFFSET {
        return Err(S19kRestoreError::WindowOffsetForbidden);
    }
    Ok(())
}

/// Hash-verified restore of the `--backup-only` mtd5 nanddump.
/// Independent of [`CLEAR_FOR_FLASH`]. Does not restore `/dev/nand_env`.
pub fn admit_s19k_restore_preinstall_window(
    tools: S19kTargetTools,
    backup: S19kBackupCompleteness,
    hashes_ok: bool,
    target_mtd: u8,
    safe_off: u8,
    layout: S19kStockReturnKind,
    use_window_offset: bool,
) -> Result<S19kRestoreKind, S19kRestoreError> {
    if !hashes_ok {
        return Err(S19kRestoreError::HashMismatch);
    }
    if !backup.backup_complete() {
        return Err(S19kRestoreError::BackupIncomplete);
    }
    admit_s19k_restore_nandwrite_preflight(tools)?;
    refuse_s19k_restore_mtd5_at_rootfs_window_offset(use_window_offset)?;
    if target_mtd == 0 || target_mtd == 1 {
        return Err(S19kRestoreError::BootloaderForbidden);
    }
    if target_mtd != 5 {
        return Err(S19kRestoreError::BootloaderForbidden);
    }
    if refuse_re4c_safe_off_as_am3_s19k_cut(safe_off).is_err() {
        return Err(S19kRestoreError::WrongSafeOffPolarity);
    }
    match layout {
        S19kStockReturnKind::Stock7Blocked => Err(S19kRestoreError::Stock7LayoutBlocked),
        S19kStockReturnKind::Mtd2StockSystem => Ok(S19kRestoreKind::PreInstallMtd5Nanddump),
    }
}

/// Plan admit is independent of FLASH. Execute is FLASH-gated ().
pub fn admit_s19k_restore_execute(
    tools: S19kTargetTools,
    backup: S19kBackupCompleteness,
    hashes_ok: bool,
    target_mtd: u8,
    safe_off: u8,
    layout: S19kStockReturnKind,
    use_window_offset: bool,
) -> Result<S19kRestoreKind, S19kRestoreError> {
    let _kind = admit_s19k_restore_preinstall_window(
        tools,
        backup,
        hashes_ok,
        target_mtd,
        safe_off,
        layout,
        use_window_offset,
    )?;
    if !CLEAR_FOR_FLASH {
        return Err(S19kRestoreError::ClearForFlashNotYet);
    }
    Err(S19kRestoreError::ClearForFlashNotYet)
}

/// Restore *plan* may admit a hash-complete mtd5 nanddump while FLASH is
/// false. Restore *execute* must still be ClearForFlashNotYet. Do not treat
/// a passing plan as a NAND grant.
pub fn refuse_s19k_restore_plan_as_execute_grant() -> Result<(), &'static str> {
    let tools = S19kTargetTools {
        dd: true,
        sha256sum: true,
        nanddump: true,
        nandwrite: true,
        flash_erase: true,
        fw_printenv: true,
        fw_setenv: true,
    };
    let backup = S19kBackupCompleteness {
        nand_env: true,
        mtd5_window: true,
        gpio437: true,
        fw_printenv: true,
    };
    if admit_s19k_restore_preinstall_window(
        tools,
        backup,
        true,
        5,
        1,
        S19kStockReturnKind::Mtd2StockSystem,
        false,
    )
    .is_err()
    {
        return Err("restore plan must admit a hash-complete mtd5 nanddump");
    }
    match admit_s19k_restore_execute(
        tools,
        backup,
        true,
        5,
        1,
        S19kStockReturnKind::Mtd2StockSystem,
        false,
    ) {
        Err(S19kRestoreError::ClearForFlashNotYet) => Ok(()),
        Ok(_) => Err("restore execute must not grant NAND while CLEAR_FOR_FLASH is false"),
        Err(_) => Err("restore execute must fail as ClearForFlashNotYet"),
    }
}

/// `--backup-only` snapshots gpio437.value (read) and exits before SafeOff.
pub fn admit_s19k_install_backup_reads_gpio437_before_safeoff(
    script: &str,
) -> Result<(), &'static str> {
    let snap = script
        .find("gpio437.value=$GPIO437_VAL")
        .ok_or("backup must log gpio437.value snapshot")?;
    let backup = script
        .find("[BACKUP-ONLY]")
        .ok_or("installer must have BACKUP-ONLY")?;
    let safeoff = script
        .find("gpio437 SafeOff OK")
        .ok_or("execute path must name gpio437 SafeOff OK")?;
    if !(snap < backup && backup < safeoff) {
        return Err("order must be gpio437 snapshot, BACKUP-ONLY exit, then SafeOff");
    }
    if !script.contains("FLASH not started") {
        return Err("BACKUP-ONLY must say FLASH not started");
    }
    Ok(())
}

/// The executable backup lane must never materialize `/dev/nand_env` in a
/// predictable target-side path.  Even with NAND writes disabled, a stale
/// `/tmp` symlink would turn `dd of=/tmp/...` into an arbitrary root write.
/// Two direct SSH streams into the private host artifact directory provide
/// both no-clobber target behavior and a stable duplicate-read witness.
pub fn admit_s19k_install_backup_host_streams_nand_env(script: &str) -> Result<(), &'static str> {
    const STREAM: &str = "ssh_stream_get \"dd if=/dev/nand_env bs=64K count=1 2>/dev/null\"";
    if script.matches(STREAM).count() != 2 {
        return Err("installer must host-stream two independent nand_env reads");
    }
    if script.contains("dd if=/dev/nand_env of=")
        || script.contains("/tmp/nand_env_pre.bin")
        || script.contains("/tmp/dcentos_root_readback.uimage")
        || script.contains("scp_get()")
    {
        return Err("installer must not use predictable target-side backup/readback files");
    }
    if !script.contains("duplicate host-streamed nand_env backup SHA mismatch")
        || !script.contains("host-streamed rootfs readback failed")
    {
        return Err("installer must hash-admit duplicate nand_env and streamed rootfs reads");
    }
    Ok(())
}

/// Package validation/staging happens before the intentionally unreachable
/// NAND writer, so it must itself be a no-clobber transaction.  A fixed
/// `/data` leaf can be a stale symlink and `rm -rf /data/sysupgrade` can erase
/// unrelated operator state even when `CLEAR_FOR_FLASH=false`.
pub fn admit_s19k_install_remote_staging_is_content_bound(
    script: &str,
) -> Result<(), &'static str> {
    if script.contains("/data/dcentos-sysupgrade.tar")
        || script.contains("rm -rf /data/sysupgrade")
        || script.contains("/data/.dcent_stage_check")
    {
        return Err("installer must not use or delete shared remote staging paths");
    }
    for required in [
        "DCENT_REQUIRE_INSTALLABLE_PACKAGE=1",
        "REMOTE_STAGE_DIR=\"/data/.dcentos-sysupgrade-$LOCAL_SHA\"",
        "[ ! -e '$REMOTE_STAGE_DIR' ]",
        "[ ! -L '$REMOTE_STAGE_DIR' ]",
        "mkdir '$REMOTE_STAGE_DIR'",
        "REMOTE_BUNDLE=\"$REMOTE_STAGE_DIR/bundle.tar\"",
        "REMOTE_EXTRACT=\"$REMOTE_STAGE_DIR/extracted\"",
        "tar xf '$REMOTE_BUNDLE' -C '$REMOTE_EXTRACT'",
    ] {
        if !script.contains(required) {
            return Err("installer lacks the exact content-bound remote staging transaction");
        }
    }
    let require_installable = script
        .find("DCENT_REQUIRE_INSTALLABLE_PACKAGE=1")
        .ok_or("installer must require installable package authority")?;
    let scp = script
        .find("scp_put \"$FIRMWARE\"")
        .ok_or("installer must have a package staging boundary")?;
    if require_installable > scp {
        return Err("installable package authority must precede every remote stage");
    }
    Ok(())
}

/// Execute path: after RESTORE confirm, refuse GPIO/NAND while FLASH-false.
pub fn admit_s19k_restore_script_execute_refuses_nandwrite(
    script: &str,
) -> Result<(), &'static str> {
    if !script.contains("CLEAR_FOR_FLASH=false — refusing gpio437 SafeOff/flash_erase/nandwrite")
    {
        return Err("restore execute must refuse CLEAR_FOR_FLASH before GPIO/NAND");
    }
    let confirm = script
        .find("Type 'RESTORE'")
        .ok_or("missing RESTORE confirm")?;
    let refuse = script
        .find("CLEAR_FOR_FLASH=false — refusing")
        .ok_or("missing restore execute refuse")?;
    let gpio = script
        .find("gpio437 SafeOff (am3-s19k-active-low, value=1)")
        .ok_or("missing restore gpio SafeOff")?;
    let erase = script
        .find("flash_erase \"$ROOTFS_MTD\" 0 0")
        .ok_or("missing flash_erase")?;
    let nw = script
        .find("nandwrite -p \"$ROOTFS_MTD\"")
        .ok_or("missing nandwrite")?;
    if refuse < confirm {
        return Err("execute refuse must follow RESTORE confirm");
    }
    if refuse > gpio {
        return Err("execute refuse must precede GPIO SafeOff");
    }
    if refuse > erase {
        return Err("execute refuse must precede flash_erase");
    }
    if refuse > nw {
        return Err("execute refuse must precede nandwrite");
    }
    Ok(())
}

/// Even the currently unreachable restore writer must keep readback inside the
/// private transaction directory. A fixed `/tmp` leaf can be an attacker- or
/// stale-run-controlled symlink if mutation authority is ever enabled.
pub fn admit_s19k_restore_script_private_readback(script: &str) -> Result<(), &'static str> {
    if script.contains("/tmp/mtd5_restore_readback.bin") {
        return Err("restore must not write readback through a fixed /tmp leaf");
    }
    for required in [
        "RESTORE_TMP=$(mktemp -d",
        "\"$RESTORE_TMP/mtd5_restore_readback.bin\"",
        "trap cleanup_restore_tmp EXIT",
    ] {
        if !script.contains(required) {
            return Err("restore lacks private readback transaction binding");
        }
    }
    Ok(())
}

/// : restore `--execute` must not skip geometry when `/proc/mtd` is absent.
pub fn admit_s19k_restore_execute_live_proc_mtd(
    live_proc_mtd: Option<&str>,
) -> Result<(), &'static str> {
    let live = live_proc_mtd
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or("restore --execute refuses missing live /proc/mtd; refuse geometry-blind NAND")?;
    compute_s19k_geometry_from_proc_mtd(live)
        .ok_or("live /proc/mtd cannot compute mtd5 geometry")?;
    Ok(())
}

/// Execute path: FLASH refuse < required /proc/mtd < gpio/nandwrite.
pub fn admit_s19k_restore_script_execute_requires_proc_mtd(
    script: &str,
) -> Result<(), &'static str> {
    if !script.contains("missing live /proc/mtd; refuse geometry-blind restore") {
        return Err("restore execute must refuse missing live /proc/mtd");
    }
    if script.contains("if [ -r /proc/mtd ]; then") {
        return Err("restore execute must not skip geometry when /proc/mtd is absent");
    }
    let refuse = script
        .find("CLEAR_FOR_FLASH=false — refusing")
        .ok_or("missing restore execute refuse")?;
    let proc = script
        .find("missing live /proc/mtd; refuse geometry-blind restore")
        .ok_or("missing restore /proc/mtd refuse")?;
    let gpio = script
        .find("gpio437 SafeOff (am3-s19k-active-low, value=1)")
        .ok_or("missing restore gpio SafeOff")?;
    let nw = script
        .find("nandwrite -p \"$ROOTFS_MTD\"")
        .ok_or("missing nandwrite")?;
    if proc < refuse {
        return Err("proc/mtd require must follow FLASH refuse");
    }
    if proc > gpio {
        return Err("proc/mtd require must precede GPIO SafeOff");
    }
    if proc > nw {
        return Err("proc/mtd require must precede nandwrite");
    }
    Ok(())
}

/// Plan output may describe only an offline full-eraseblock candidate and
/// complete readback; it must never teach the retired one-byte NAND recipe.
fn admit_s19k_recovery_flag_full_block_plan_contract(script: &str) -> Result<(), &'static str> {
    for field in [
        "candidate_required=full-0x20000-byte-eraseblock",
        "candidate_source=host-fixture-only",
        "write_command=false",
        "readback_required=full-0x20000-byte-sha256-and-byte-compare",
    ] {
        if script.matches(field).count() != 3 {
            return Err("all three recovery-flag plans must require the exact full-block contract");
        }
    }
    if script.contains("dry_flash_erase=")
        || script.contains("dry_nandwrite=")
        || script.contains("| nandwrite")
    {
        return Err("recovery-flag plans must not publish a retired one-byte NAND writer recipe");
    }
    if script.contains("byte_in_block must be 0")
        || !script.contains("EB_OFF=$((LOCAL_DEC % ERASESIZE))")
        || !script.contains("seek=\"$EB_OFF\"")
    {
        return Err("fixture-only recovery-flag plans must preserve arbitrary in-block offsets");
    }
    Ok(())
}

/// Recovery-flag execute is retired: env opt-in < exact live identity <
/// unconditional FLASH refusal, with no executable GPIO/erase/write tail.
pub fn admit_s19k_recovery_flag_script_execute_refuses_nandwrite(
    script: &str,
) -> Result<(), &'static str> {
    if !script.contains("CLEAR_FOR_FLASH=false — refusing gpio437 SafeOff/flash_erase/nandwrite")
    {
        return Err("recovery-flag execute must refuse CLEAR_FOR_FLASH before GPIO/NAND");
    }
    if !script.contains("missing exact live platform:target identity")
        || !script.contains("am3-aml-s19k:am3-s19k")
    {
        return Err("recovery-flag execute must require exact live S19k platform:target");
    }
    if !script.contains("one_byte_execute_retired=true")
        || !script.contains("full_eraseblock_candidate_required=true")
    {
        return Err("one-byte execute must be retired in favor of a full-block candidate");
    }
    admit_s19k_recovery_flag_full_block_plan_contract(script)?;
    if script.contains("mode=execute-eraseblock-rewrite")
        || script.contains("nand=erased+programmed")
        || script.contains("\nif ! flash_erase /dev/mtd5")
        || script.contains("\nif ! printf '\\002' | nandwrite")
        || script.contains("SYS=/sys/class/gpio")
    {
        return Err("retired recovery-flag helper retains executable GPIO/NAND code");
    }
    let env_gate = script
        .find(r#"if [ "${DCENT_S19K_RECOVERY_FLAG_EXECUTE:-0}" != 1 ]"#)
        .ok_or("missing recovery-flag EXECUTE env gate")?;
    let identity = script
        .find("missing exact live platform:target identity")
        .ok_or("missing recovery-flag exact identity refuse")?;
    let refuse = script
        .find("CLEAR_FOR_FLASH=false — refusing")
        .ok_or("missing recovery-flag execute refuse")?;
    if !(env_gate < identity && identity < refuse) {
        return Err("execute order must be env opt-in < exact identity < FLASH refusal");
    }
    Ok(())
}

/// Size-sum pairing that older wave-0d notes treated as `a lab unit` locals.
/// Physical mtd5 `0x06700000` implies `0x05100000`, not these.
pub const S19K_REVERT_SIZE_SUM_WINDOW: u64 = 0x0570_0000;
pub const S19K_REVERT_SIZE_SUM_FLAG: u64 = 0x0530_0000;
/// Admitted ramdisk window: `nandrootfs − physical mtd5`.
pub const S19K_REVERT_ADMITTED_ROOTFS_LOCAL: u64 = 0x0510_0000;

/// Live SKU must exist. Missing is fail-open on Braiins / stock.
pub fn admit_s19k_stock_revert_live_board_target(live: Option<&str>) -> Result<(), &'static str> {
    let live = live.map(str::trim).filter(|s| !s.is_empty());
    let Some(live) = live else {
        return Err("stock revert refuses missing live /etc/dcentos/board_target");
    };
    if s19k_board_target_is_live_alias(live) {
        Ok(())
    } else {
        Err("stock revert live board_target is not am3-s19k")
    }
}

/// `/tmp` bench deploy is not a NAND install; refuse stock nandwrite.
pub fn refuse_s19k_stock_revert_tmp_deploy_stamp(stamp_present: bool) -> Result<(), &'static str> {
    if stamp_present {
        return Err("stock revert refuses /etc/dcentos/tmp_deploy leftover from /tmp bench deploy");
    }
    Ok(())
}

/// Refuse size-sum `0x05700000`/`0x05300000` and anything except the
/// physical-base local `0x05100000`.
pub fn admit_s19k_stock_revert_rootfs_offset(offset: u64) -> Result<u64, &'static str> {
    if offset == S19K_REVERT_SIZE_SUM_WINDOW || offset == S19K_REVERT_SIZE_SUM_FLAG {
        return Err("0x05700000/0x05300000 is size-sum pairing; refuse as revert nandwrite base");
    }
    if offset == S19K_78_MTD5_SIZE_SUM {
        return Err("0x06100000 is size-sum without hole; refuse as revert base");
    }
    if offset != S19K_REVERT_ADMITTED_ROOTFS_LOCAL {
        return Err(
            "S19k stock revert rootfs local must be 0x05100000 (nandrootfs − physical 0x06700000)",
        );
    }
    Ok(offset)
}

/// Maximum uImage file size admitted for the 40 MiB mtd5 window.
pub const S19K_REVERT_UIMAGE_MAX_BYTES: u64 = 0x0280_0000;

/// : payload must be aarch64 uImage, not BMU / ANDROID! / ARM32.
pub fn admit_s19k_stock_revert_uimage(
    blob: &[u8],
    file_len: u64,
) -> Result<S19kUimageHeader, &'static str> {
    if file_len == 0 || file_len > S19K_REVERT_UIMAGE_MAX_BYTES {
        return Err("stock revert uImage larger than 0x02800000 window or empty");
    }
    if blob.len() >= 8 && &blob[..8] == S19K_ANDROID_BOOT_MAGIC {
        return Err("ANDROID! boot.img is not an mtd5 uImage; refuse nandwrite");
    }
    if !blob.is_empty() && blob[0] == S19K_BTMU_MAGIC {
        return Err("Btmu/BMU container is not an mtd5 uImage; refuse nandwrite");
    }
    let hdr = parse_s19k_uimage_header(blob)?;
    refuse_xilinx_arm32_uimage_as_s19k_aml(&hdr)?;
    if hdr.ih_arch != UIMAGE_ARCH_ARM64 {
        return Err("S19k AML revert uImage must be IH_ARCH_ARM64 (22)");
    }
    if u64::from(hdr.ih_size) + 64 != file_len {
        return Err("uImage file length must exactly equal ih_size + 64");
    }
    Ok(hdr)
}

/// SHA256 must be supplied. Optional hash was a fail-open.
pub fn admit_s19k_stock_revert_sha256_required(expected_sha: &str) -> Result<(), &'static str> {
    let s = expected_sha.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("stock revert requires expected SHA-256 (64 hex chars)");
    }
    Ok(())
}

/// Stock-image revert still needs env-flip tools. L3 stays blocked.
/// : also fail-closed on live SKU, `/tmp` stamp, and size-sum window.
/// : payload + required SHA.
pub fn admit_s19k_stock_image_revert(
    tools: S19kTargetTools,
    target_mtd: u8,
    live_board_target: Option<&str>,
    tmp_deploy_stamp: bool,
    rootfs_offset: u64,
) -> Result<S19kRestoreKind, S19kRestoreError> {
    admit_s19k_stock_revert_live_board_target(live_board_target)
        .map_err(|_| S19kRestoreError::MissingLiveBoardTarget)?;
    refuse_s19k_stock_revert_tmp_deploy_stamp(tmp_deploy_stamp)
        .map_err(|_| S19kRestoreError::TmpDeployStamp)?;
    admit_s19k_stock_revert_rootfs_offset(rootfs_offset)
        .map_err(|_| S19kRestoreError::WindowOffsetForbidden)?;
    if !tools.env_flip_ok() {
        return Err(S19kRestoreError::EnvToolsMissing);
    }
    if target_mtd != 5 {
        return Err(S19kRestoreError::BootloaderForbidden);
    }
    Ok(S19kRestoreKind::StockImageThenEnvFlip)
}

/// `a lab unit` local flag is `0x04D00000` on physical mtd5 `0x06700000`. Size-sum yields
/// `0x05300000` — that must not be used on a `a lab unit` mtd5 base.
pub fn admit_s19k_recovery_flag_offset(
    mtd5_base: u64,
    claimed_local: u64,
) -> Result<u64, S19kRestoreError> {
    admit_s19k_physical_mtd5_base(mtd5_base)
        .map_err(|_| S19kRestoreError::RecoveryFlagOffsetMismatch)?;
    let want = recovery_flag_local_offset(mtd5_base)
        .ok_or(S19kRestoreError::RecoveryFlagOffsetMismatch)?;
    if claimed_local != want {
        return Err(S19kRestoreError::RecoveryFlagOffsetMismatch);
    }
    Ok(want)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kRecoveryFlagIntent {
    /// Write `0x02` so next `bootcmd` falls through to `recover_to_stock`
    /// (restore env from `nandrecovery_env` + `nand erase.part nvdata`).
    /// That is not a direct `bootm` of mtd2.
    UbootStockRevert,
    /// Write `0x01` so `try_to_boot_bos_after_install` runs BOS then
    /// `recovery_set_flag_2`. Plan-only while `CLEAR_FOR_FLASH=false`.
    /// Not `fw_setenv firstboot` — `a lab unit` `bootcmd` never reads firstboot.
    InstallArm,
    /// Write `0x03` so next `bootcmd` takes `boot_bos` (keep BOS).
    /// S99 promotes `0x02 → 0x03` after a healthy first boot. Plan-only
    /// while `CLEAR_FOR_FLASH=false`. Not recover_to_stock and not mtd2.
    SuccessfulKeepBos,
}

/// Classify the flag byte. Does not authorize a NAND write.
pub fn classify_s19k_recovery_flag_intent(
    value: u8,
) -> Result<S19kRecoveryFlagIntent, S19kRestoreError> {
    match value {
        RECOVERY_FLAG_FIRST_BOOT => Ok(S19kRecoveryFlagIntent::UbootStockRevert),
        RECOVERY_FLAG_INSTALLED => Ok(S19kRecoveryFlagIntent::InstallArm),
        RECOVERY_FLAG_SUCCESSFUL => Ok(S19kRecoveryFlagIntent::SuccessfulKeepBos),
        _ => Err(S19kRestoreError::RecoveryFlagOffsetMismatch),
    }
}

/// Architecture-only. Writing `0x03` is a FLASH commit (still NOT_YET).
/// Writing `0x02` arms `recover_to_stock` and does not require `fw_setenv`.
pub fn admit_s19k_recovery_flag_write(
    value: u8,
    mtd5_base: u64,
    claimed_local: u64,
    target_mtd: u8,
) -> Result<S19kRecoveryFlagIntent, S19kRestoreError> {
    if target_mtd != 5 {
        return Err(S19kRestoreError::BootloaderForbidden);
    }
    admit_s19k_recovery_flag_offset(mtd5_base, claimed_local)?;
    match value {
        RECOVERY_FLAG_FIRST_BOOT => Ok(S19kRecoveryFlagIntent::UbootStockRevert),
        RECOVERY_FLAG_INSTALLED | RECOVERY_FLAG_SUCCESSFUL => {
            Err(S19kRestoreError::ClearForFlashNotYet)
        }
        _ => Err(S19kRestoreError::RecoveryFlagOffsetMismatch),
    }
}

/// Geometry lines for BACKUP_LEDGER v1 (additive; parse still v1).
pub fn format_s19k_backup_geometry_lines(
    proc_mtd: &str,
    mtd5_base: Option<u64>,
    recovery_flag_local: Option<u64>,
    rootfs_local: Option<u64>,
) -> String {
    let mtd5 = mtd5_base
        .map(|v| format!("0x{v:08X}"))
        .unwrap_or_else(|| "unknown".into());
    let flag = recovery_flag_local
        .map(|v| format!("0x{v:08X}"))
        .unwrap_or_else(|| "unknown".into());
    let root = rootfs_local
        .map(|v| format!("0x{v:08X}"))
        .unwrap_or_else(|| "unknown".into());
    format!(
        "proc_mtd={proc_mtd}\nmtd5_base={mtd5}\nnandrootfs_global=0x{NANDROOTFS_GLOBAL:08X}\nrecovery_flag_global=0x{RECOVERY_FLAG_GLOBAL:08X}\nrecovery_flag_local={flag}\nrootfs_local={root}\n"
    )
}

/// NAND eraseblock that contains the recovery-flag byte. A single-byte
/// `nandwrite` at `local_offset` is not a valid program on this flash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kRecoveryFlagEraseblock {
    pub local_offset: u64,
    pub eraseblock_size: u32,
    pub eraseblock_index: u64,
    pub eraseblock_start: u64,
    pub byte_in_block: u32,
}

/// `a lab unit` flag `0x04D00000` is eraseblock-aligned (`131072 * 616`).
pub fn plan_s19k_recovery_flag_eraseblock(
    local_offset: u64,
) -> Result<S19kRecoveryFlagEraseblock, S19kRestoreError> {
    if local_offset >= 0x0800_0000 {
        return Err(S19kRestoreError::RecoveryFlagOffsetMismatch);
    }
    let es = u64::from(ROOTFS_ERASESIZE);
    Ok(S19kRecoveryFlagEraseblock {
        local_offset,
        eraseblock_size: ROOTFS_ERASESIZE,
        eraseblock_index: local_offset / es,
        eraseblock_start: (local_offset / es) * es,
        byte_in_block: (local_offset % es) as u32,
    })
}

/// Raw one-byte poke cannot update NAND; only an eraseblock rewrite can.
pub fn refuse_s19k_recovery_flag_raw_byte_poke() -> Result<(), &'static str> {
    Err("am3-s19k recovery flag needs a 128 KiB eraseblock rewrite; refuse raw one-byte nandwrite")
}

/// An erase followed by a one-byte NAND program is retired even when the byte
/// is block-aligned. S99 and host fixtures preserve the complete eraseblock.
pub fn refuse_s19k_recovery_flag_one_byte_after_erase() -> Result<(), &'static str> {
    Err("recovery-flag update requires a full 128 KiB candidate and readback; refuse one-byte nandwrite")
}

/// Host-testable 128 KiB rewrite. Does not flash; live execute is refused.
pub fn rewrite_s19k_recovery_flag_eraseblock(
    block: &[u8],
    byte_in_block: u32,
    value: u8,
) -> Result<Vec<u8>, &'static str> {
    if block.len() != ROOTFS_ERASESIZE as usize {
        return Err("recovery-flag eraseblock must be exactly 131072 bytes");
    }
    let off = byte_in_block as usize;
    if off >= block.len() {
        return Err("byte_in_block is outside the eraseblock");
    }
    let mut out = block.to_vec();
    out[off] = value;
    Ok(out)
}

/// Plan-only install-arm. Execute stays `CLEAR_FOR_FLASH=false`.
/// firstboot is recorded as S99 WAL companion, not a `bootcmd` selector.
pub fn format_s19k_install_commit_plan(
    mtd5_base: u64,
    claimed_local: u64,
    target_mtd: u8,
) -> Result<String, S19kRestoreError> {
    if target_mtd != 5 {
        return Err(S19kRestoreError::BootloaderForbidden);
    }
    admit_s19k_recovery_flag_offset(mtd5_base, claimed_local)?;
    let intent = classify_s19k_recovery_flag_intent(RECOVERY_FLAG_INSTALLED)?;
    let eb = plan_s19k_recovery_flag_eraseblock(claimed_local)?;
    let uboot = crate::s19k_nand_env::classify_s19k_uboot_flag_action(RECOVERY_FLAG_INSTALLED);
    Ok(format!(
        "schema=dcentos.amlogic-install-commit/v1\nintent={intent:?}\nvalue=0x{value:02X}\nlocal_offset=0x{claimed_local:08X}\nmtd5_base=0x{mtd5_base:08X}\ntarget_mtd={target_mtd}\neraseblock_index={idx}\neraseblock_start=0x{start:08X}\nbyte_in_block=0x{off:X}\nerase_count=1\nrewriter=eraseblock_rewrite\nuboot_action={uboot:?}\nfirstboot=S99_WAL_companion_only\nbootcmd_reads_firstboot=false\nbootm_mtd2=false\nrecover_to_stock=false\nnandwrite=false\ngpio_write=false\nexecute=CLEAR_FOR_FLASH\nclear_for_flash=false\n",
        value = RECOVERY_FLAG_INSTALLED,
        idx = eb.eraseblock_index,
        start = eb.eraseblock_start,
        off = eb.byte_in_block,
    ))
}

/// : rust InstallArm plan and the flag helper must name the same fields.
pub fn admit_s19k_install_commit_plan(plan: &str) -> Result<(), &'static str> {
    if !plan.contains("schema=dcentos.amlogic-install-commit/v1") {
        return Err("install-commit plan must use rust schema");
    }
    if !plan.contains("intent=InstallArm") {
        return Err("install-commit plan must be InstallArm");
    }
    if !plan.contains("value=0x01") {
        return Err("install-commit plan must write flag 0x01");
    }
    if !plan.contains("uboot_action=FirstBosThenSetFlag2") {
        return Err("install-commit plan must name FirstBosThenSetFlag2");
    }
    if !plan.contains("eraseblock_start=") {
        return Err("install-commit plan must name eraseblock geometry");
    }
    if !plan.contains("rewriter=eraseblock_rewrite") {
        return Err("install-commit plan must rewrite an eraseblock");
    }
    if !plan.contains("firstboot=S99_WAL_companion_only") {
        return Err("install-commit firstboot is S99 WAL companion only");
    }
    if !plan.contains("bootcmd_reads_firstboot=false") {
        return Err("install-commit must not treat firstboot as bootcmd");
    }
    if !plan.contains("bootm_mtd2=false") {
        return Err("install-commit must not bootm mtd2");
    }
    if !plan.contains("recover_to_stock=false") {
        return Err("0x01 is not recover_to_stock");
    }
    if !plan.contains("clear_for_flash=false") {
        return Err("install-commit must stay FLASH-false");
    }
    if !plan.contains("nandwrite=false") {
        return Err("install-commit plan must keep nandwrite=false");
    }
    Ok(())
}

/// : flag helper plans 0x01 InstallArm and rewrites a host fixture.
pub fn admit_s19k_recovery_flag_script_plans_install_arm(script: &str) -> Result<(), &'static str> {
    admit_s19k_recovery_flag_full_block_plan_contract(script)?;
    if !script.contains("schema=dcentos.amlogic-install-commit/v1") {
        return Err("flag helper must emit rust install-commit schema");
    }
    if !script.contains("intent=InstallArm") {
        return Err("flag helper must name InstallArm");
    }
    if !script.contains("uboot_action=FirstBosThenSetFlag2") {
        return Err("flag helper 0x01 must name FirstBosThenSetFlag2");
    }
    if !script.contains("printf '\\001'") {
        return Err("flag helper fixture must write 0x01");
    }
    if !script.contains("recovery flag 0x01 execute is FLASH NOT_YET") {
        return Err("flag helper must refuse 0x01 execute");
    }
    admit_s19k_install_commit_plan(script)?;
    let plan = script
        .find("intent=InstallArm")
        .ok_or("missing InstallArm plan")?;
    let poke = script
        .find("printf '\\001'")
        .ok_or("missing 0x01 fixture poke")?;
    let helper = script
        .find("rewrite_recovery_flag_fixture()")
        .ok_or("missing shared fixture helper")?;
    let exec_refuse = script
        .find("recovery flag 0x01 execute is FLASH NOT_YET")
        .ok_or("missing 0x01 execute refuse")?;
    if poke < helper {
        return Err("0x01 poke must live in shared fixture helper");
    }
    if helper > plan {
        return Err("shared fixture helper must precede InstallArm plan");
    }
    if exec_refuse > plan {
        return Err("0x01 execute refusal must precede the non-executable plan");
    }
    if script.contains("recovery flag 0x01 is FLASH NOT_YET here (use INSTALL_COMMIT_PLAN)") {
        return Err("flag helper must plan 0x01 instead of bouncing to installer");
    }
    Ok(())
}

/// Plan-only keep-BOS successful-flag. Execute stays `CLEAR_FOR_FLASH=false`.
/// U-Boot `0x03` is `boot_bos`, not recover and not mtd2 `bootm`.
pub fn format_s19k_successful_flag_plan(
    mtd5_base: u64,
    claimed_local: u64,
    target_mtd: u8,
) -> Result<String, S19kRestoreError> {
    if target_mtd != 5 {
        return Err(S19kRestoreError::BootloaderForbidden);
    }
    admit_s19k_recovery_flag_offset(mtd5_base, claimed_local)?;
    let intent = classify_s19k_recovery_flag_intent(RECOVERY_FLAG_SUCCESSFUL)?;
    let eb = plan_s19k_recovery_flag_eraseblock(claimed_local)?;
    let uboot = crate::s19k_nand_env::classify_s19k_uboot_flag_action(RECOVERY_FLAG_SUCCESSFUL);
    Ok(format!(
        "schema=dcentos.amlogic-successful-flag/v1\nintent={intent:?}\nvalue=0x{value:02X}\nlocal_offset=0x{claimed_local:08X}\nmtd5_base=0x{mtd5_base:08X}\ntarget_mtd={target_mtd}\neraseblock_index={idx}\neraseblock_start=0x{start:08X}\nbyte_in_block=0x{off:X}\nerase_count=1\nrewriter=eraseblock_rewrite\nuboot_action={uboot:?}\npromote_from=0x02\nfirstboot=S99_WAL_companion_only\nbootcmd_reads_firstboot=false\nbootm_mtd2=false\nrecover_to_stock=false\nnandwrite=false\ngpio_write=false\nexecute=CLEAR_FOR_FLASH\nclear_for_flash=false\n",
        value = RECOVERY_FLAG_SUCCESSFUL,
        idx = eb.eraseblock_index,
        start = eb.eraseblock_start,
        off = eb.byte_in_block,
    ))
}

/// Host-testable successful-flag plan fields.
pub fn admit_s19k_successful_flag_plan(plan: &str) -> Result<(), &'static str> {
    for needle in [
        "schema=dcentos.amlogic-successful-flag/v1",
        "intent=SuccessfulKeepBos",
        "value=0x03",
        "uboot_action=BootBos",
        "promote_from=0x02",
        "firstboot=S99_WAL_companion_only",
        "bootm_mtd2=false",
        "recover_to_stock=false",
        "nandwrite=false",
        "gpio_write=false",
        "execute=CLEAR_FOR_FLASH",
        "clear_for_flash=false",
        "eraseblock_start=0x04D00000",
        "byte_in_block=0x0",
    ] {
        if !plan.contains(needle) {
            return Err("successful-flag plan missing required field");
        }
    }
    Ok(())
}

/// : flag helper plans 0x03 SuccessfulKeepBos and rewrites a host fixture.
pub fn admit_s19k_recovery_flag_script_plans_successful_keep_bos(
    script: &str,
) -> Result<(), &'static str> {
    admit_s19k_recovery_flag_full_block_plan_contract(script)?;
    if !script.contains("schema=dcentos.amlogic-successful-flag/v1") {
        return Err("flag helper must emit rust successful-flag schema");
    }
    if !script.contains("intent=SuccessfulKeepBos") {
        return Err("flag helper must name SuccessfulKeepBos");
    }
    if !script.contains("uboot_action=BootBos") {
        return Err("flag helper 0x03 must name BootBos");
    }
    if !script.contains("printf '\\003'") {
        return Err("flag helper fixture must write 0x03");
    }
    if !script.contains("recovery flag 0x03 execute is FLASH NOT_YET") {
        return Err("flag helper must refuse 0x03 execute");
    }
    if !script.contains("fixture_value=0x03") {
        return Err("flag helper must tag fixture_value=0x03");
    }
    let plan = script
        .find("intent=SuccessfulKeepBos")
        .ok_or("missing SuccessfulKeepBos plan")?;
    let poke = script
        .find("printf '\\003'")
        .ok_or("missing 0x03 fixture poke")?;
    let helper = script
        .find("rewrite_recovery_flag_fixture()")
        .ok_or("missing shared fixture helper")?;
    let exec_refuse = script
        .find("recovery flag 0x03 execute is FLASH NOT_YET")
        .ok_or("missing 0x03 execute refuse")?;
    if poke < helper {
        return Err("0x03 poke must live in shared fixture helper");
    }
    if helper > plan {
        return Err("shared fixture helper must precede SuccessfulKeepBos plan");
    }
    if exec_refuse > plan {
        return Err("0x03 execute refusal must precede the non-executable plan");
    }
    Ok(())
}

/// : 0x01/0x02/0x03 fixture rewrite is one helper, not three copies.
pub fn admit_s19k_recovery_flag_script_shares_fixture_rewrite(
    script: &str,
) -> Result<(), &'static str> {
    if !script.contains("rewrite_recovery_flag_fixture()") {
        return Err("flag helper must define rewrite_recovery_flag_fixture");
    }
    let together = "fixture-in and --fixture-out must be used together";
    if script.matches(together).count() != 1 {
        return Err("fixture pair-check must exist once in the shared helper");
    }
    let helper = script
        .find("rewrite_recovery_flag_fixture()")
        .ok_or("missing shared fixture helper")?;
    for poke in ["printf '\\001'", "printf '\\002'", "printf '\\003'"] {
        let at = script.find(poke).ok_or("missing shared fixture poke")?;
        if at < helper {
            return Err("fixture poke must live in shared helper");
        }
        let n = script.matches(poke).count();
        if n != 1 {
            return Err("each fixture poke must exist once in the shared helper");
        }
    }
    if script.matches("rewrite_recovery_flag_fixture").count() < 4 {
        return Err("0x01, 0x02, and 0x03 must call the shared helper");
    }
    Ok(())
}

/// DCENT `S99upgrade` leftover `0x02` is `recover_to_stock`, not `bootm` mtd2.
pub fn admit_s19k_s99_header_names_recover_to_stock(script: &str) -> Result<(), &'static str> {
    if script.contains("U-Boot reverts to mtd2") {
        return Err("S99 header must not claim leftover 0x02 bootm mtd2");
    }
    if script.contains("Two parallel U-Boot revert mechanisms") {
        return Err("S99 header must not call firstboot a parallel revert arm");
    }
    if !script.contains("recover_to_stock") {
        return Err("S99 header must name recover_to_stock as leftover 0x02 path");
    }
    if !script.contains("bootcmd never reads firstboot") {
        return Err("S99 header must say .78 bootcmd never reads firstboot");
    }
    if !script.contains("firstboot=0 is not the revert disarm") {
        return Err("S99 header must say firstboot=0 is not recover_to_stock disarm");
    }
    Ok(())
}

pub fn refuse_s19k_s99_leftover_02_as_mtd2_boot() -> Result<(), &'static str> {
    Err("leftover recovery flag 0x02 is recover_to_stock; not bootm mtd2 stock_system")
}

/// WAL-blocked 0x02→0x03 leaves flag 0x02. Next reboot is recover_to_stock,
/// not a firstboot env flip.
pub fn admit_s19k_s99_wal_block_leaves_flag_02(script: &str) -> Result<(), &'static str> {
    if !script.contains("refusing recovery-flag commit") {
        return Err("S99 WAL failure must refuse recovery-flag commit");
    }
    if !script.contains("next reboot is recover_to_stock") {
        return Err("S99 WAL-block must name leftover 0x02 as recover_to_stock");
    }
    if script.contains("U-Boot will revert on next reboot") {
        return Err("S99 must not say U-Boot will revert; leftover 0x02 is recover_to_stock");
    }
    Ok(())
}

pub fn refuse_s19k_s99_firstboot0_as_recover_disarm() -> Result<(), &'static str> {
    Err("fw_setenv firstboot=0 does not disarm recover_to_stock; only flag 0x03 keeps BOS")
}

/// : S19k identities must not refuse `0x02→0x03` solely because
/// the unused firstboot WAL marker could not be written.
pub fn admit_s19k_s99_identity_wal_does_not_block_03(script: &str) -> Result<(), &'static str> {
    if !script.contains("s19k_firstboot_is_wal_companion_only") {
        return Err("S99 must classify S19k firstboot as WAL companion only");
    }
    if !script.contains("am3-aml-s19k:am3-s19k") {
        return Err("S19k WAL companion must require the exact live platform:target pair");
    }
    if !script.contains("require_amlogic_ota08_identity || return 1") {
        return Err("S19k WAL companion must pass the shared exact live identity gate");
    }
    if !script.contains("proceeding to 0x02->0x03") {
        return Err("S19k WAL failure must proceed to 0x02->0x03");
    }
    if !script.contains("recover_to_stock is already disarmed by flag 0x03") {
        return Err("S19k firstboot=0 failure after 0x03 must not undo the flag commit");
    }
    let helper = script
        .find("s19k_firstboot_is_wal_companion_only")
        .ok_or("missing S19k WAL companion helper")?;
    let refuse = script
        .find("refusing recovery-flag commit")
        .ok_or("non-S19k WAL refuse missing")?;
    if helper > refuse {
        return Err("S19k companion helper must precede the non-S19k WAL refuse");
    }
    Ok(())
}

/// Held S21 Braiins `S97recovery-flag` is byte-identical to `a lab unit`.
/// That is the flag path, not a firstboot-bootcmd proof. No S21 `nand_env`.
pub fn admit_s21_s97_identical_to_78(s21: &str, s78: &str) -> Result<(), &'static str> {
    if s21 != s78 {
        return Err("held S21 S97recovery-flag must match .78 S97");
    }
    if !s21.contains("nanddump -s $LOCAL_RECOVERY_FLAGS_OFFSET_BOS_LAYOUT -l 1") {
        return Err("S21 S97 must nanddump-compare FIRST_BOOT");
    }
    Ok(())
}

pub fn refuse_s21_androidboot_firstboot_as_uboot_firstboot() -> Result<(), &'static str> {
    Err("S21 dmesg androidboot.firstboot=1 is kernel cmdline, not fw_setenv firstboot / bootcmd")
}

pub fn refuse_s21_held_s97_as_firstboot_bootcmd() -> Result<(), &'static str> {
    Err(
        "held S21 S97 is the 0x02->0x03 flag path; no S21 nand_env/bootcmd; not a firstboot WAL justification",
    )
}

/// DCENT `S99upgrade::commit_recovery_flag` promotes `0x02 → 0x03`.
pub fn admit_s19k_s99_promotes_02_to_03(script: &str) -> Result<(), &'static str> {
    if !script.contains("printf '\\003'") {
        return Err("S99 must patch the preserved eraseblock with 0x03");
    }
    if !script.contains("expected 0x03") {
        return Err("S99 must readback 0x03");
    }
    if !script.contains("0x02 -> 0x03") {
        return Err("S99 must log 0x02 -> 0x03");
    }
    if !script.contains("0x05300000") {
        return Err("S99 must refuse naive 0x05300000");
    }
    if !script.contains("--bb=padbad --omitoob")
        || !script.contains("eraseblock.before-duplicate.bin")
        || !script.contains("cmp -s \"$FLAG_BEFORE\" \"$FLAG_BEFORE_2\"")
    {
        return Err("S99 must duplicate-read a physical-offset-preserving eraseblock snapshot");
    }
    if !script.contains("flash_erase \"$RECOVERY_MTD\" \"$ERASEBLOCK_START\" 1")
        || !script
            .contains("nandwrite -p -s \"$ERASEBLOCK_START\" \"$RECOVERY_MTD\" \"$FLAG_EXPECTED\"")
    {
        return Err("S99 must erase+nandwrite the complete preserved flag eraseblock");
    }
    if !script.contains("cmp -s \"$FLAG_EXPECTED\" \"$FLAG_READBACK\"") {
        return Err("S99 must compare the complete eraseblock readback");
    }
    Ok(())
}

/// Exact live Amlogic platform:target pairs that may run the OTA-08 flag write.
/// T21 is deliberately excluded: its controller-specific flash geometry and
/// recovery-flag contract have not been reconstructed.
pub const S99_AMLOGIC_OTA08_IDENTITIES: &[&str] = &[
    "am3-aml-s19k:am3-s19k",
    "am3-aml-s19jpro:am3-s19jpro-aml",
    "am3-aml-s21:am3-s21",
    "am3-aml-s21pro:am3-s21pro",
];

/// : OTA-08 stays, but identity + pre/post readback must fail closed.
pub fn admit_s19k_s99_ota08_identity_and_readback(script: &str) -> Result<(), &'static str> {
    admit_s19k_s99_promotes_02_to_03(script)?;
    if !script.contains("AMLOGIC_RAW_NAND_RECOVERY_FLAG_EXCEPTION") {
        return Err("OTA-08 exception must stay named");
    }
    if !script.contains("require_amlogic_ota08_identity") {
        return Err("S99 OTA-08 must require a sealed Amlogic platform:target pair");
    }
    if !script.contains("missing live $PLATFORM_FILE") {
        return Err("S99 OTA-08 must refuse missing live platform");
    }
    if !script.contains("missing live $BOARD_TARGET_FILE") {
        return Err("S99 OTA-08 must refuse missing live board_target");
    }
    if !script.contains("am3-aml-s19k:am3-s19k") {
        return Err("S99 OTA-08 must admit only the canonical S19k platform:target pair");
    }
    for pair in S99_AMLOGIC_OTA08_IDENTITIES {
        if !script.contains(pair) {
            return Err("S99 OTA-08 is missing an exact shared Amlogic platform:target pair");
        }
    }
    if script.contains("am3-aml-s21xp:am3-s21xp") {
        return Err("S99 OTA-08 must not admit S21 XP without exact recovery geometry");
    }
    if script.contains("am3-aml-t21:am3-t21") {
        return Err("S99 OTA-08 must not admit T21 without exact recovery geometry");
    }
    if !script.contains("OLD=$(read_recovery_flag)") {
        return Err("S99 OTA-08 must pre-read the flag before erase");
    }
    if !script.contains("expected 0x02") {
        return Err("S99 OTA-08 must refuse pre-write values other than 0x02");
    }
    if !script.contains("ERROR: recovery flag readback = $NEW (expected 0x03)") {
        return Err("S99 OTA-08 post-write mismatch must be ERROR, not WARN");
    }
    let ident = script
        .find("require_amlogic_ota08_identity")
        .ok_or("missing OTA-08 identity helper")?;
    let old = script
        .find("OLD=$(read_recovery_flag)")
        .ok_or("missing OTA-08 pre-write read")?;
    let erase = script
        .find("flash_erase \"$RECOVERY_MTD\"")
        .ok_or("missing OTA-08 flash_erase")?;
    let nw = script
        .find("nandwrite -p -s \"$ERASEBLOCK_START\"")
        .ok_or("missing OTA-08 nandwrite")?;
    let new = script
        .find("NEW=$(read_recovery_flag)")
        .ok_or("missing OTA-08 post-write read")?;
    if ident > erase {
        return Err("OTA-08 identity must precede flash_erase");
    }
    if old > erase {
        return Err("OTA-08 pre-write 0x02 read must precede flash_erase");
    }
    if nw > new {
        return Err("OTA-08 post-write readback must follow nandwrite");
    }
    Ok(())
}

/// : leftover InstallArm (`0x01`) in userspace is ERROR, not WARN.
/// U-Boot must have written `0x02` before kernel handoff. S99 must not
/// promote `0x01 → 0x03` (that skips first-boot health + WAL).
pub fn admit_s19k_s99_leftover_01_is_error(script: &str) -> Result<(), &'static str> {
    if script.contains("[WARN] recovery flag = 0x01") {
        return Err("leftover 0x01 must not be WARN");
    }
    if !script.contains("ERROR: recovery flag = 0x01 (INSTALLED) leftover in userspace") {
        return Err("leftover 0x01 must be ERROR");
    }
    if script.contains("0x01 -> 0x03") {
        return Err("must not promote leftover 0x01 to 0x03");
    }
    let case01 = script
        .find("            0x01)")
        .ok_or("missing leftover 0x01 case")?;
    let err = script
        .find("ERROR: recovery flag = 0x01 (INSTALLED) leftover in userspace")
        .ok_or("missing leftover 0x01 ERROR")?;
    let err_star = script
        .find("            ERR_*)")
        .ok_or("missing ERR_* flag case")?;
    if err < case01 || err > err_star {
        return Err("leftover 0x01 ERROR must live in the 0x01 case");
    }
    let slice = &script[case01..err_star];
    if !slice.contains("exit 1") {
        return Err("leftover 0x01 must exit 1");
    }
    if slice.contains("exit 0") {
        return Err("leftover 0x01 must not exit 0");
    }
    if slice.contains("commit_recovery_flag") || slice.contains("printf '\\x3'") {
        return Err("leftover 0x01 must not nandwrite 0x03");
    }
    Ok(())
}

/// : unread (`ERR_*`) and unexpected flag values are ERROR, not WARN.
/// They must not promote to 0x03. Start already exits 0 when mtd5 is absent.
pub fn admit_s19k_s99_unread_or_unexpected_flag_is_error(script: &str) -> Result<(), &'static str> {
    if script.contains("[WARN] could not read recovery flag") {
        return Err("unread flag must not be WARN");
    }
    if script.contains("[WARN] unexpected recovery flag value:") {
        return Err("unexpected flag must not be WARN");
    }
    if !script.contains("ERROR: could not read recovery flag ($FLAG); refuse OTA-08") {
        return Err("unread flag must be ERROR");
    }
    if !script.contains("ERROR: unexpected recovery flag value: $FLAG; refuse OTA-08") {
        return Err("unexpected flag must be ERROR");
    }
    let err_star = script
        .find("            ERR_*)")
        .ok_or("missing ERR_* case")?;
    let unexpected = script
        .find("            *)")
        .ok_or("missing unexpected-flag case")?;
    if unexpected < err_star {
        return Err("unexpected-flag case must follow ERR_*");
    }
    let err_slice = &script[err_star..unexpected];
    let unexpected_end = script[unexpected..]
        .find("esac")
        .ok_or("cannot bound unexpected-flag case")?;
    let unexpected_slice = &script[unexpected..unexpected + unexpected_end];
    for (name, slice) in [("ERR_*", err_slice), ("unexpected", unexpected_slice)] {
        if !slice.contains("exit 1") {
            return Err(match name {
                "ERR_*" => "unread flag must exit 1",
                _ => "unexpected flag must exit 1",
            });
        }
        if slice.contains("exit 0") {
            return Err(match name {
                "ERR_*" => "unread flag must not exit 0",
                _ => "unexpected flag must not exit 0",
            });
        }
        if slice.contains("commit_recovery_flag") || slice.contains("printf '\\x3'") {
            return Err("unread/unexpected must not nandwrite 0x03");
        }
    }
    Ok(())
}

/// `0x03` is keep-BOS, not recover_to_stock / nvdata erase.
pub fn refuse_s19k_flag_03_as_recover_to_stock() -> Result<(), &'static str> {
    Err("recovery flag 0x03 is BootBos / SuccessfulKeepBos, not recover_to_stock")
}

/// `0x03` is not a direct `bootm` of mtd2 stock_system.
pub fn refuse_s19k_flag_03_as_mtd2_boot() -> Result<(), &'static str> {
    Err("recovery flag 0x03 is nand device 1 + go $loadaddr, not bootm mtd2")
}

/// `0x03` is a NAND flag rewrite, not `fw_setenv firstboot`.
pub fn refuse_s19k_successful_flag_as_fw_setenv_firstboot() -> Result<(), &'static str> {
    Err("0x03 successful-flag is an eraseblock rewrite; firstboot=0 is S99 WAL only")
}

/// Execute of `0x03` stays FLASH NOT_YET.
pub fn refuse_s19k_successful_flag_execute() -> Result<(), &'static str> {
    Err("0x03 successful-flag execute stays CLEAR_FOR_FLASH=false")
}

/// `a lab unit` `bootcmd` ignores firstboot. S19k revert commit is recover_env,
/// not `fw_setenv firstboot 1`.
pub fn refuse_s19k_firstboot_only_as_revert_commit() -> Result<(), &'static str> {
    Err(
        ".78 bootcmd never reads firstboot; S19k stock-return is recover_to_stock (recover_env + nvdata erase) via flag 0x02 / nandrecovery_env, not fw_setenv firstboot alone",
    )
}

/// Plan after a stock uImage nandwrite. Does not execute firstboot or flag 0x02.
pub fn format_s19k_stock_image_revert_plan() -> String {
    "schema=dcentos.amlogic-stock-image-revert/v1\n\
nandwrite_target=root\n\
rootfs_local=0x05100000\n\
rootfs_window=0x02800000\n\
commit=refused_firstboot_only\n\
bootcmd_reads_firstboot=false\n\
bootm_mtd2=false\n\
mix_flag_02=false\n\
uimage_write_is_not_recover_to_stock=true\n\
legacy_uimage_classifier_only=true\n\
uimage_crc_verified=false\n\
stock_payload_identity_verified=false\n\
vendor_factory_sd_is_only_evidence_bound_stock_route=true\n\
stock_return=recover_env_nandrecovery\n\
recover_env_source=nandrecovery_env.bin\n\
recover_env_ram=0x01060000\n\
nandrecovery_env_offset=0x0B000000\n\
env_size=0x10000\n\
uboot_recover_to_stock=run recover_env; nand erase.part nvdata; reset\n\
flag_02_helper=s19k_write_recovery_flag.sh\n\
does_not_arm_flag_02=true\n\
dry_run=false\n\
nandwrite=false\n\
gpio_write=false\n\
execute=CLEAR_FOR_FLASH\n\
clear_for_flash=false\n"
        .to_string()
}

pub fn admit_s19k_stock_image_revert_plan(plan: &str) -> Result<(), &'static str> {
    for needle in [
        "schema=dcentos.amlogic-stock-image-revert/v1",
        "nandwrite_target=root",
        "rootfs_local=0x05100000",
        "commit=refused_firstboot_only",
        "bootcmd_reads_firstboot=false",
        "bootm_mtd2=false",
        "mix_flag_02=false",
        "legacy_uimage_classifier_only=true",
        "uimage_crc_verified=false",
        "stock_payload_identity_verified=false",
        "vendor_factory_sd_is_only_evidence_bound_stock_route=true",
        "stock_return=recover_env_nandrecovery",
        "recover_env_source=nandrecovery_env.bin",
        "recover_env_ram=0x01060000",
        "nandrecovery_env_offset=0x0B000000",
        "does_not_arm_flag_02=true",
        "dry_run=false",
        "nandwrite=false",
        "gpio_write=false",
        "clear_for_flash=false",
    ] {
        if !plan.contains(needle) {
            return Err("stock-image revert plan missing required field");
        }
    }
    if plan.contains("commit=fw_setenv_firstboot") {
        return Err("plan must not commit firstboot");
    }
    Ok(())
}

/// S19k revert helper must refuse firstboot-only and name recover_env.
pub fn admit_s19k_revert_script_refuses_firstboot_only(script: &str) -> Result<(), &'static str> {
    if script.contains("\nfw_setenv firstboot 1\n") {
        return Err("revert must not execute fw_setenv firstboot 1");
    }
    if !script.contains("refusing firstboot-only") {
        return Err("revert must refuse firstboot-only commit");
    }
    if !script.contains("REVERT_COMMIT_PLAN") {
        return Err("revert must write REVERT_COMMIT_PLAN");
    }
    if !script.contains("recover_env") {
        return Err("revert must name recover_env");
    }
    if !script.contains("nandrecovery_env.bin") {
        return Err("revert must name nandrecovery_env.bin");
    }
    if !script.contains("does NOT arm flag 0x02") {
        return Err("revert must not arm flag 0x02");
    }
    if !script.contains("NOT recover_to_stock") {
        return Err("uImage write is not recover_to_stock");
    }
    if !script.contains("does NOT boot mtd2") {
        return Err("revert must not claim mtd2 boot");
    }
    Ok(())
}

/// The evidence-only classifier runs before `CLEAR_FOR_FLASH=false`; it must
/// not delete a shared `/tmp` directory or overwrite a fixed plan symlink.
pub fn admit_s19k_revert_script_private_transaction(script: &str) -> Result<(), &'static str> {
    for forbidden in [
        "/tmp/stock_extract",
        "/tmp/REVERT_COMMIT_PLAN.txt",
        "/tmp/stock_firmware_am3_aml_s19k",
    ] {
        if script.contains(forbidden) {
            return Err("stock-revert classifier must not use shared fixed /tmp paths");
        }
    }
    for required in [
        "REVERT_TMP=$(mktemp -d",
        "REVERT_PLAN=\"$REVERT_TMP/REVERT_COMMIT_PLAN.txt\"",
        "PRIVATE_FW=\"$REVERT_TMP/stock-candidate.tar.gz\"",
        "trap cleanup_revert_tmp EXIT",
        "cat \"$REVERT_PLAN\"",
        "MAX_ARCHIVE_BYTES=67108864",
        "(ulimit -f 2048 && tar -tzf \"$PRIVATE_FW\" > \"$TOC\")",
        "(ulimit -f 81920 && tar -xOzf \"$PRIVATE_FW\" -- \"$UIMAGE_MEMBER\"",
        "/*|-*|*/-*|..|../*|*/..|*/../*)",
        "firmware archive must contain exactly one uImage-like candidate",
        "POST_EXTRACT_SHA256=$(sha256sum \"$PRIVATE_FW\"",
        "does not exactly equal 64+ih_size",
    ] {
        if !script.contains(required) {
            return Err("stock-revert classifier lacks a private transaction boundary");
        }
    }
    Ok(())
}

/// : `--dry-run` writes the commit plan before GPIO/nandwrite.
pub fn admit_s19k_revert_script_dry_run_before_nandwrite(script: &str) -> Result<(), &'static str> {
    if !script.contains("--dry-run") {
        return Err("revert must accept --dry-run");
    }
    if !script.contains("[DRY RUN] writing REVERT_COMMIT_PLAN before GPIO/nandwrite") {
        return Err("dry-run must write plan before GPIO/nandwrite");
    }
    if !script.contains("dry_run=true") {
        return Err("dry-run plan must set dry_run=true");
    }
    if !script.contains("nandwrite=false") {
        return Err("dry-run plan must set nandwrite=false");
    }
    let dry = script.find("[DRY RUN]").ok_or("missing DRY RUN marker")?;
    let nw = script.find("nandwrite -p -s").ok_or("missing nandwrite")?;
    let gpio = script
        .find("gpio437 SafeOff")
        .ok_or("missing gpio SafeOff")?;
    if dry > nw {
        return Err("dry-run block must precede nandwrite");
    }
    if dry > gpio {
        return Err("dry-run block must precede GPIO SafeOff");
    }
    Ok(())
}

/// : execute must not nandwrite a uImage and then refuse commit.
pub fn refuse_s19k_revert_nandwrite_without_recover_commit() -> Result<(), &'static str> {
    Err(
        "uImage nandwrite without admitted recover commit is refused; firstboot-only is not stock-return; flag 0x02 execute stays CLEAR_FOR_FLASH=false",
    )
}

/// Execute path: after REVERT confirm, refuse GPIO/NAND while FLASH-false.
pub fn admit_s19k_revert_script_execute_refuses_nandwrite(
    script: &str,
) -> Result<(), &'static str> {
    if !script.contains("CLEAR_FOR_FLASH=false — refusing gpio437 SafeOff/nandwrite/fw_setenv") {
        return Err("execute must refuse CLEAR_FOR_FLASH before GPIO/NAND");
    }
    if !script.contains("write_revert_commit_plan false false") {
        return Err("execute refuse must write plan nandwrite=false");
    }
    if !script.contains("missing exact live platform:target identity")
        || !script.contains("am3-aml-s19k:am3-s19k")
    {
        return Err("revert must require exact live S19k platform:target before NAND");
    }
    let confirm = script
        .find("Type 'REVERT'")
        .ok_or("missing REVERT confirm")?;
    let refuse = script
        .find("CLEAR_FOR_FLASH=false — refusing")
        .ok_or("missing execute refuse")?;
    let nw = script.find("nandwrite -p -s").ok_or("missing nandwrite")?;
    let gpio = script
        .find("gpio437 SafeOff")
        .ok_or("missing gpio SafeOff")?;
    if refuse < confirm {
        return Err("execute refuse must follow REVERT confirm");
    }
    if refuse > nw {
        return Err("execute refuse must precede nandwrite");
    }
    if refuse > gpio {
        return Err("execute refuse must precede GPIO SafeOff");
    }
    Ok(())
}

/// `a lab unit` `bootcmd` ignores firstboot. Install arm is recovery-flag `0x01`.
pub fn refuse_s19k_firstboot_only_as_install_commit() -> Result<(), &'static str> {
    Err(
        ".78 bootcmd never reads firstboot; install arm is recovery-flag 0x01 (FirstBosThenSetFlag2), not fw_setenv firstboot alone",
    )
}

/// Installer residual must refuse firstboot-only and name flag `0x01`.
pub fn admit_s19k_install_script_refuses_firstboot_only_commit(
    script: &str,
) -> Result<(), &'static str> {
    if script.contains("Step 10/10: fw_setenv firstboot=1") {
        return Err("step 10 must not be firstboot-only");
    }
    if !script.contains("refusing firstboot-only") {
        return Err("install script must refuse firstboot-only commit");
    }
    if !script.contains("recovery-flag 0x01") {
        return Err("install commit must name flag 0x01");
    }
    if !script.contains("INSTALL_COMMIT_PLAN.txt") {
        return Err("install script must write INSTALL_COMMIT_PLAN.txt");
    }
    if !script.contains("firstboot=S99_WAL_companion_only") {
        return Err("commit plan must keep firstboot as S99 WAL companion");
    }
    Ok(())
}

/// : installer dry-run / FLASH-refuse / step-10 plans must match rust geometry.
pub fn admit_s19k_install_script_writes_install_commit_geometry(
    script: &str,
) -> Result<(), &'static str> {
    admit_s19k_install_commit_plan(script)?;
    if !script.contains("write_install_commit_plan()") {
        return Err("installer must define write_install_commit_plan helper");
    }
    if !script.contains("write_install_commit_plan \"dry_run=true\"") {
        return Err("dry-run must write rust InstallArm geometry");
    }
    if !script.contains("uboot_action=FirstBosThenSetFlag2") {
        return Err("installer commit plan must name FirstBosThenSetFlag2");
    }
    if !script.contains("eraseblock_index=") {
        return Err("installer commit plan must name eraseblock_index");
    }
    if !script.contains("eraseblock_start=") {
        return Err("installer commit plan must name eraseblock_start");
    }
    if !script.contains("byte_in_block=") {
        return Err("installer commit plan must name byte_in_block");
    }
    let helper = script
        .find("write_install_commit_plan()")
        .ok_or("missing commit-plan helper")?;
    let dry = script
        .find("write_install_commit_plan \"dry_run=true\"")
        .ok_or("missing dry-run commit-plan write")?;
    let flash = script
        .find("CLEAR_FOR_FLASH=false - refusing flash_erase/nandwrite/fw_setenv")
        .ok_or("missing FLASH refuse")?;
    let flash_slice = &script[flash..];
    if !flash_slice.contains("write_install_commit_plan") {
        return Err("FLASH refuse must write rust InstallArm plan");
    }
    let step10 = script
        .find("Step 10/10: recovery-flag 0x01")
        .ok_or("missing step 10 install commit")?;
    if helper > dry {
        return Err("commit-plan helper must precede dry-run write");
    }
    if dry > flash {
        return Err("dry-run commit plan must precede FLASH refuse");
    }
    if flash > step10 {
        return Err("FLASH refuse commit plan must precede step 10");
    }
    if !script[step10..].contains("write_install_commit_plan") {
        return Err("step 10 must write rust InstallArm plan");
    }
    Ok(())
}

/// : installer must emit the rust recover-to-stock plan after backup.
pub fn admit_s19k_install_script_writes_recover_to_stock_plan(
    script: &str,
) -> Result<(), &'static str> {
    if !script.contains("RECOVER_TO_STOCK_PLAN.txt") {
        return Err("install script must write RECOVER_TO_STOCK_PLAN.txt");
    }
    if !script.contains("schema=dcentos.amlogic-recover-to-stock/v1") {
        return Err("recover plan must use rust recover-to-stock schema");
    }
    if !script.contains("recover_env_source=nandrecovery_env.bin") {
        return Err("recover plan must name nandrecovery_env.bin");
    }
    if !script.contains("nand_erase_part=nvdata") {
        return Err("recover plan must erase nvdata");
    }
    if !script.contains("bootm_mtd2=false") {
        return Err("recover plan must not bootm mtd2");
    }
    if !script.contains("RECOVER_EXECUTE_REFUSE.txt") {
        return Err("install script must write RECOVER_EXECUTE_REFUSE.txt");
    }
    if !script.contains("recover_env_ram=0x01060000") {
        return Err("refuse ledger must name .78 recover_env RAM");
    }
    let ledger = script
        .find("BACKUP_LEDGER.txt written")
        .ok_or("missing BACKUP_LEDGER write")?;
    let plan = script
        .find("RECOVER_TO_STOCK_PLAN.txt")
        .ok_or("missing RECOVER_TO_STOCK_PLAN write")?;
    let backup_only = script
        .find("[BACKUP-ONLY]")
        .ok_or("missing backup-only exit")?;
    if plan < ledger {
        return Err("recover plan must follow BACKUP_LEDGER");
    }
    if plan > backup_only {
        return Err("recover plan must be written before backup-only exit");
    }
    if !script.contains("recover_amlogic_to_stock.sh") {
        return Err("install script must name recover-to-stock runner");
    }
    Ok(())
}

/// : installer must run recover --dry-run and refuse backup if it fails.
pub fn admit_s19k_install_script_runs_recover_dry_run(script: &str) -> Result<(), &'static str> {
    if !script.contains("recover_amlogic_to_stock.sh") {
        return Err("installer must name recover-to-stock runner");
    }
    if !script.contains("--dry-run") {
        return Err("installer must invoke recover --dry-run");
    }
    if !script.contains("recover-to-stock --dry-run failed; refusing successful backup") {
        return Err("installer must refuse backup if recover walk fails");
    }
    if !script.contains("RECOVER_WALK.txt") {
        return Err("installer must require RECOVER_WALK.txt after dry-run");
    }
    let plan = script
        .find("RECOVER_TO_STOCK_PLAN.txt written")
        .ok_or("missing recover plan write log")?;
    let invoke = script
        .find("sh \"$RECOVER_RUNNER\" --artifact-dir \"$ARTIFACT_DIR\" --dry-run")
        .ok_or("missing recover --dry-run invoke")?;
    let refuse = script
        .find("recover-to-stock --dry-run failed; refusing successful backup")
        .ok_or("missing recover-walk refuse")?;
    let walk = script
        .find("recover-to-stock --dry-run did not write RECOVER_WALK.txt")
        .ok_or("missing RECOVER_WALK require")?;
    let backup_only = script
        .find("[BACKUP-ONLY]")
        .ok_or("missing backup-only exit")?;
    if invoke < plan {
        return Err("recover --dry-run must follow RECOVER_TO_STOCK_PLAN write");
    }
    if refuse < invoke {
        return Err("walk-fail refuse must follow recover invoke");
    }
    if walk < invoke {
        return Err("RECOVER_WALK require must follow recover invoke");
    }
    if invoke > backup_only {
        return Err("recover --dry-run must run before backup-only exit");
    }
    Ok(())
}

/// : installer must slice the flag eraseblock and walk 0x01 fixture.
pub fn admit_s19k_install_script_runs_flag_01_fixture(script: &str) -> Result<(), &'static str> {
    if !script.contains("dcent_am3_extract_recovery_flag_eraseblock") {
        return Err("installer must slice recovery_flag_eb.bin from mtd5");
    }
    if !script.contains("s19k_write_recovery_flag.sh") {
        return Err("installer must name recovery-flag helper");
    }
    if !script.contains("--value 0x01") {
        return Err("installer must walk flag 0x01");
    }
    if !script.contains("--fixture-in") || !script.contains("--fixture-out") {
        return Err("installer must invoke helper fixture-in/out");
    }
    if !script.contains("--verify-only") {
        return Err("installer flag walk must be verify-only");
    }
    if !script.contains("recovery-flag 0x01 fixture walk failed; refusing successful backup") {
        return Err("installer must refuse backup if 0x01 fixture walk fails");
    }
    if !script.contains("INSTALL_COMMIT_WALK.txt") {
        return Err("installer must write INSTALL_COMMIT_WALK.txt");
    }
    if !script.contains("fixture_value=0x01") {
        return Err("installer must require fixture_value=0x01");
    }
    let mtd5 = script
        .find("mtd5_pre_install.bin")
        .ok_or("missing mtd5 backup")?;
    let extract = script
        .find("dcent_am3_extract_recovery_flag_eraseblock")
        .ok_or("missing flag eraseblock extract")?;
    let invoke = script
        .find("sh \"$FLAG_HELPER\" --value 0x01")
        .ok_or("missing 0x01 fixture helper invoke")?;
    let refuse = script
        .find("recovery-flag 0x01 fixture walk failed; refusing successful backup")
        .ok_or("missing 0x01 walk refuse")?;
    let backup_only = script
        .find("[BACKUP-ONLY]")
        .ok_or("missing backup-only exit")?;
    if extract < mtd5 {
        return Err("flag eraseblock extract must follow mtd5 backup");
    }
    if invoke < extract {
        return Err("0x01 fixture invoke must follow eraseblock slice");
    }
    if refuse < invoke {
        return Err("0x01 walk refuse must follow helper invoke");
    }
    if invoke > backup_only {
        return Err("0x01 fixture walk must run before backup-only exit");
    }
    let walk_slice = &script[invoke..backup_only];
    if walk_slice.contains("--execute") {
        return Err("0x01 fixture walk must not pass --execute");
    }
    Ok(())
}

/// : a walked 0x01 fixture is the 128 KiB blob, not a label.
pub fn admit_s19k_walked_flag_01_fixture(blob: &[u8]) -> Result<(), &'static str> {
    if blob.len() != ROOTFS_ERASESIZE as usize {
        return Err("walked 0x01 fixture must be exactly 131072 bytes");
    }
    if blob[0] != RECOVERY_FLAG_INSTALLED {
        return Err("walked 0x01 fixture byte0 must be 0x01");
    }
    Ok(())
}

/// : installer must refuse backup if walked 0x01 bytes are wrong.
pub fn admit_s19k_install_script_admits_flag_01_bytes(script: &str) -> Result<(), &'static str> {
    admit_s19k_install_script_runs_flag_01_fixture(script)?;
    if !script.contains("0x01 fixture-out length") {
        return Err("installer must refuse wrong 0x01 fixture length");
    }
    if !script.contains("0x01 fixture-out byte0=") {
        return Err("installer must refuse wrong 0x01 fixture first byte");
    }
    if !script.contains("(want 01)") {
        return Err("installer must require fixture byte0=01");
    }
    let exists = script
        .find("0x01 fixture-out missing after walk")
        .ok_or("missing fixture-out exists check")?;
    let len = script
        .find("0x01 fixture-out length")
        .ok_or("missing fixture-out length check")?;
    let byte0 = script
        .find("0x01 fixture-out byte0=")
        .ok_or("missing fixture-out byte0 check")?;
    let backup_only = script
        .find("[BACKUP-ONLY]")
        .ok_or("missing backup-only exit")?;
    if len < exists {
        return Err("length check must follow fixture-out exists");
    }
    if byte0 < len {
        return Err("byte0 check must follow length check");
    }
    if byte0 > backup_only {
        return Err("byte0 check must run before backup-only exit");
    }
    Ok(())
}

/// Geometry helper must slice the 128 KiB flag eraseblock.
pub fn admit_s19k_geometry_extracts_flag_eraseblock(geometry: &str) -> Result<(), &'static str> {
    if !geometry.contains("dcent_am3_extract_recovery_flag_eraseblock()") {
        return Err("geometry must define flag eraseblock extract");
    }
    if !geometry.contains("131072") {
        return Err("flag eraseblock extract must use 128 KiB");
    }
    Ok(())
}

/// : lab rootfs write/restore must not flash while FLASH-false.
pub fn admit_s19k_lab_rootfs_script_execute_refuses_nandwrite(
    script: &str,
) -> Result<(), &'static str> {
    if !script.contains("CLEAR_FOR_FLASH=false - refusing gpio437 SafeOff/flash_erase/nandwrite") {
        return Err("lab rootfs must refuse CLEAR_FOR_FLASH before GPIO/NAND");
    }
    if !script.contains("refuse_clear_for_flash_nand") {
        return Err("lab rootfs must name FLASH refuse helper");
    }
    if !script.contains("--lab-only is not a FLASH override") {
        return Err("lab flags must not override CLEAR_FOR_FLASH");
    }
    let write_case = script
        .find("    write)")
        .ok_or("missing write subcommand")?;
    let restore_case = script
        .find("    restore)")
        .ok_or("missing restore subcommand")?;
    if restore_case <= write_case {
        return Err("restore case must follow write case");
    }
    let write = &script[write_case..restore_case];
    let restore = &script[restore_case..];
    for (name, slice) in [("write", write), ("restore", restore)] {
        let refuse = slice
            .find("refuse_clear_for_flash_nand")
            .ok_or("lab rootfs FLASH refuse missing on write/restore")?;
        let gpio = slice
            .find("require_gpio437_safe_off_before_mutation")
            .ok_or("lab rootfs gpio helper missing on write/restore")?;
        let erase = slice
            .find("flash_erase $ROOTFS_MTD")
            .ok_or("lab rootfs flash_erase missing on write/restore")?;
        if refuse > gpio {
            return Err(if name == "write" {
                "write FLASH refuse must precede GPIO SafeOff"
            } else {
                "restore FLASH refuse must precede GPIO SafeOff"
            });
        }
        if refuse > erase {
            return Err(if name == "write" {
                "write FLASH refuse must precede flash_erase"
            } else {
                "restore FLASH refuse must precede flash_erase"
            });
        }
    }
    Ok(())
}

/// DCENT persistent install writes **root only** at nandrootfs−mtd5.
pub const S19K_INSTALL_ROOTFS_LOCAL: u64 = 0x0510_0000;
pub const S19K_INSTALL_ROOTFS_WINDOW: u64 = 0x0280_0000;

/// Locals of Braiins stage2 images inside physical mtd5 (`a lab unit`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kInstallPayloadPlan {
    pub mtd5_base: u64,
    pub uboot_local: Option<u64>,
    pub fdt_local: Option<u64>,
    pub kernel_local: Option<u64>,
    pub rootfs_local: u64,
    pub rootfs_window: u64,
    pub nandrecovery_env_local: u64,
    pub recovery_flag_local: u64,
}

fn ranges_overlap(a0: u64, a1: u64, b0: u64, b1: u64) -> bool {
    a0 < b1 && b0 < a1
}

/// Global NAND offset → local mtd5 offset. None if below the system start.
pub fn s19k_global_to_mtd5_local(global: u64, mtd5_base: u64) -> Option<u64> {
    global.checked_sub(mtd5_base)
}

/// Persistent install is rootfs-window-only. Braiins stage2 images must
/// already exist; package `kernel` is never nandwritten into the root window.
pub fn admit_s19k_install_rootfs_window_only(
    mtd5_base: u64,
    mtd5_len: u64,
) -> Result<S19kInstallPayloadPlan, &'static str> {
    admit_s19k_physical_mtd5_base(mtd5_base)?;
    let rootfs_local = rootfs_local_offset(mtd5_base).ok_or("cannot compute rootfs local")?;
    if mtd5_base == S19K_78_MTD5_BASE && rootfs_local != S19K_INSTALL_ROOTFS_LOCAL {
        return Err(".78 rootfs local must stay 0x05100000");
    }
    if rootfs_local
        .checked_add(S19K_INSTALL_ROOTFS_WINDOW)
        .ok_or("root window overflow")?
        > mtd5_len
    {
        return Err("root window exceeds mtd5 length");
    }
    let nandrecovery_env_local =
        nandrecovery_env_local_offset(mtd5_base).ok_or("cannot compute nandrecovery_env local")?;
    let recovery_flag_local =
        recovery_flag_local_offset(mtd5_base).ok_or("cannot compute recovery-flag local")?;
    let root_end = rootfs_local + S19K_INSTALL_ROOTFS_WINDOW;
    if ranges_overlap(
        rootfs_local,
        root_end,
        nandrecovery_env_local,
        nandrecovery_env_local + NANDRECOVERY_ENV_LEN,
    ) {
        return Err("root window overlaps nandrecovery_env");
    }
    if ranges_overlap(
        rootfs_local,
        root_end,
        recovery_flag_local,
        recovery_flag_local + 1,
    ) {
        return Err("root window overlaps recovery flag");
    }
    Ok(S19kInstallPayloadPlan {
        mtd5_base,
        uboot_local: s19k_global_to_mtd5_local(crate::s19k_nand_env::S19K_78_NANDUBOOT, mtd5_base),
        fdt_local: s19k_global_to_mtd5_local(crate::s19k_nand_env::S19K_78_NANDFDT, mtd5_base),
        kernel_local: s19k_global_to_mtd5_local(
            crate::s19k_nand_env::S19K_78_NANDKERNEL,
            mtd5_base,
        ),
        rootfs_local,
        rootfs_window: S19K_INSTALL_ROOTFS_WINDOW,
        nandrecovery_env_local,
        recovery_flag_local,
    })
}

/// Package `kernel` is hashed for presence only.
pub fn refuse_s19k_package_kernel_as_rootfs_nandwrite() -> Result<(), &'static str> {
    Err(
        "package kernel is hashed for presence only; nandwrite target is root at 0x05100000, never the kernel member",
    )
}

/// Host-side payload plan. FLASH stays NOT_YET.
pub fn format_s19k_install_payload_plan(plan: &S19kInstallPayloadPlan) -> String {
    format!(
        "schema=dcentos.amlogic-install-payload/v1\n\
nandwrite_target=root\n\
rootfs_local=0x{root:08X}\n\
rootfs_window=0x{win:08X}\n\
package_kernel_nandwrite=false\n\
nandrecovery_env_local=0x{env:08X}\n\
recovery_flag_local=0x{flag:08X}\n\
kernel_local={k}\n\
clear_for_flash=false\n",
        root = plan.rootfs_local,
        win = plan.rootfs_window,
        env = plan.nandrecovery_env_local,
        flag = plan.recovery_flag_local,
        k = plan
            .kernel_local
            .map(|v| format!("0x{v:08X}"))
            .unwrap_or_else(|| "absent".into()),
    )
}

/// Installer nandwrite must target `root`, never package `kernel`.
pub fn admit_s19k_install_script_nandwrites_root_only(script: &str) -> Result<(), &'static str> {
    let open_fd = script
        .find("exec 3< '$REMOTE_PREFIX/root'")
        .ok_or("installer must bind the admitted root inode before erase")?;
    let hash_fd = script
        .find("sha256sum /proc/self/fd/3")
        .ok_or("installer must hash the bound root inode")?;
    let erase = script
        .find("flash_erase $ROOTFS_MTD $ROOTFS_OFFSET_HEX $ROOTFS_ERASE_COUNT || exit 1")
        .ok_or("installer must fail closed on root-window erase")?;
    let write = script
        .find("nandwrite -p -s $ROOTFS_OFFSET_HEX $ROOTFS_MTD /proc/self/fd/3 || exit 1")
        .ok_or("installer must nandwrite the bound root inode at ROOTFS_OFFSET")?;
    if !(open_fd < hash_fd && hash_fd < erase && erase < write) {
        return Err("installer root inode hash/erase/write ordering is unsafe");
    }
    if !script.contains("cat /sys/class/mtd/mtd5/bad_blocks")
        || !script.contains("cat /sys/class/gpio/gpio437/value")
    {
        return Err("installer must recheck zero bad blocks and GPIO437 SafeOff in writer shell");
    }
    if script.contains("nandwrite -p -s $ROOTFS_OFFSET_HEX $ROOTFS_MTD '$REMOTE_PREFIX/root'")
        || script.contains("nandwrite -p -s $ROOTFS_OFFSET_HEX $ROOTFS_MTD '$REMOTE_PREFIX/kernel'")
    {
        return Err("installer must not nandwrite package kernel");
    }
    if !script.contains("INSTALL_PAYLOAD_PLAN.txt") {
        return Err("installer must write INSTALL_PAYLOAD_PLAN.txt");
    }
    if !script.contains("package_kernel_nandwrite=false") {
        return Err("payload plan must refuse kernel nandwrite");
    }
    Ok(())
}

/// U-Boot `recover_to_stock` steps after flag `0x02`. Plan-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kRecoverToStockStep {
    ImportNandrecoveryEnv,
    EraseNvdata,
    Reset,
}

pub const S19K_RECOVER_TO_STOCK_STEPS: [S19kRecoverToStockStep; 3] = [
    S19kRecoverToStockStep::ImportNandrecoveryEnv,
    S19kRecoverToStockStep::EraseNvdata,
    S19kRecoverToStockStep::Reset,
];

/// Bind flag `0x02` + CRC-admitted sidecar. Does not write NAND.
pub fn format_s19k_recover_to_stock_plan(
    mtd5_base: u64,
    source_name: &str,
    env: &crate::s19k_nand_env::S19kNandEnv,
) -> Result<String, &'static str> {
    refuse_s19k_nand_env_bak_as_recover_env_import(source_name)?;
    refuse_s19k_aml_factory_sd_as_nandrecovery_env(source_name)
        .map_err(|_| "aml factory SD is not nandrecovery_env")?;
    if !env.crc_ok {
        return Err("nandrecovery_env CRC32 mismatch");
    }
    let flag_local =
        recovery_flag_local_offset(mtd5_base).ok_or("cannot compute recovery-flag local")?;
    let env_local =
        nandrecovery_env_local_offset(mtd5_base).ok_or("cannot compute nandrecovery_env local")?;
    if classify_s19k_recovery_flag_intent(RECOVERY_FLAG_FIRST_BOOT)
        != Ok(S19kRecoveryFlagIntent::UbootStockRevert)
    {
        return Err("flag 0x02 is not UbootStockRevert");
    }
    Ok(format!(
        "schema=dcentos.amlogic-recover-to-stock/v1\nintent=UbootStockRevert\nflag_value=0x02\nflag_local=0x{flag_local:08X}\nnandrecovery_env_local=0x{env_local:08X}\nrecover_env_source={source_name}\nnand_env_bak_is_not_nandrecovery_env=true\nenv_crc_ok=true\nstep0=ImportNandrecoveryEnv\nstep1=EraseNvdata\nstep2=Reset\nnand_erase_part=nvdata\nbootm_mtd2=false\nuboot_recover_env=nand read + env import -d -c\nuboot_recover_to_stock=run recover_env; nand erase.part nvdata; reset\nexecute=CLEAR_FOR_FLASH\nclear_for_flash=false\n"
    ))
}

/// Why recover **execute** is refused. Plan-only until [`CLEAR_FOR_FLASH`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kRecoverExecuteError {
    ClearForFlashNotYet,
    BadEnvSource,
    EnvCrcBad,
    FlagNotRecover,
    ToolsMissing,
}

/// Fail-closed recover execute. Reads [`CLEAR_FOR_FLASH`] so callers cannot lie.
pub fn admit_s19k_recover_execute(
    source_name: &str,
    env_crc_ok: bool,
    flag: u8,
    tools: S19kTargetTools,
) -> Result<(), S19kRecoverExecuteError> {
    if refuse_s19k_nand_env_bak_as_recover_env_import(source_name).is_err()
        || refuse_s19k_aml_factory_sd_as_nandrecovery_env(source_name).is_err()
    {
        return Err(S19kRecoverExecuteError::BadEnvSource);
    }
    if !env_crc_ok {
        return Err(S19kRecoverExecuteError::EnvCrcBad);
    }
    if flag != RECOVERY_FLAG_FIRST_BOOT {
        return Err(S19kRecoverExecuteError::FlagNotRecover);
    }
    if admit_s19k_nandwrite_preflight(tools).is_err() {
        return Err(S19kRecoverExecuteError::ToolsMissing);
    }
    if !CLEAR_FOR_FLASH {
        return Err(S19kRecoverExecuteError::ClearForFlashNotYet);
    }
    Err(S19kRecoverExecuteError::ClearForFlashNotYet)
}

/// Bench/operator ledger: exact recover steps that stay unexecuted.
pub fn format_s19k_recover_execute_refuse(mtd5_base: u64, source_name: &str) -> String {
    let flag_local = recovery_flag_local_offset(mtd5_base).unwrap_or(0);
    let env_local = nandrecovery_env_local_offset(mtd5_base).unwrap_or(0);
    format!(
        "schema=dcentos.amlogic-recover-execute/v1\n\
execute=refused\nreason=CLEAR_FOR_FLASH\nclear_for_flash=false\n\
flag_value=0x02\nflag_local=0x{flag_local:08X}\n\
nandrecovery_env_local=0x{env_local:08X}\nrecover_env_source={source_name}\n\
recover_env_ram=0x{ram:08X}\nenv_import_size=0x{impsize:X}\n\
nandrecovery_env_offset=0x{nandenv:08X}\nenv_size=0x{envsz:X}\n\
step0=ImportNandrecoveryEnv\nstep1=EraseNvdata\nstep2=Reset\n\
nand_erase_part=nvdata\nbootm_mtd2=false\n\
pass=admit_s19k_recover_execute_returns_ClearForFlashNotYet\n\
fail=nand_erase_or_env_import_without_admit\n",
        ram = crate::s19k_nand_env::S19K_78_RECOVER_ENV_RAM,
        impsize = crate::s19k_nand_env::S19K_78_ENV_IMPORT_SIZE,
        nandenv = crate::s19k_nand_env::S19K_78_NANDRECOVERY_ENV,
        envsz = crate::s19k_nand_env::S19K_78_ENV_SIZE,
    )
}

/// Refuse ledger must name the `a lab unit` `recover_env` RAM import.
pub fn admit_s19k_recover_execute_refuse_names_78_ram(ledger: &str) -> Result<(), &'static str> {
    crate::s19k_nand_env::admit_s19k_78_recover_env_ram()?;
    if !ledger.contains("recover_env_ram=0x01060000") {
        return Err("refuse ledger missing recover_env_ram=0x01060000");
    }
    if !ledger.contains("env_import_size=0x10000") {
        return Err("refuse ledger missing env_import_size=0x10000");
    }
    if !ledger.contains("execute=refused") {
        return Err("refuse ledger must stay refused");
    }
    Ok(())
}

/// Refuse ledger must name the `a lab unit` NAND source offset and `env_size`.
pub fn admit_s19k_recover_execute_refuse_names_78_nand_src(
    ledger: &str,
) -> Result<(), &'static str> {
    crate::s19k_nand_env::admit_s19k_78_recover_env_nand_src()?;
    admit_s19k_recover_execute_refuse_names_78_ram(ledger)?;
    if !ledger.contains("nandrecovery_env_offset=0x0B000000") {
        return Err("refuse ledger missing nandrecovery_env_offset=0x0B000000");
    }
    if !ledger.contains("env_size=0x10000") {
        return Err("refuse ledger missing env_size=0x10000");
    }
    Ok(())
}

/// : dry-run walk of [`format_s19k_recover_to_stock_plan`]. No NAND.
pub const S19K_RECOVER_WALK_SCHEMA: &str = "dcentos.amlogic-recover-walk/v1";
/// `a lab unit` `recover_env` body (nand read + default + import + save).
pub const S19K_RECOVER_DRY_STEP0: &str =
    "nand read 01060000 ${nandrecovery_env_offset} ${env_size}; env default -a; env import -d -c 01060000 0x10000; env save";
pub const S19K_RECOVER_DRY_STEP1: &str = "nand erase.part nvdata";
pub const S19K_RECOVER_DRY_STEP2: &str = "reset";

/// Host walk ledger. CRC/source already admitted by the runner.
pub fn format_s19k_recover_walk_ledger(
    mtd5_base: u64,
    source_name: &str,
) -> Result<String, &'static str> {
    refuse_s19k_nand_env_bak_as_recover_env_import(source_name)?;
    let flag_local =
        recovery_flag_local_offset(mtd5_base).ok_or("cannot compute recovery-flag local")?;
    let env_local =
        nandrecovery_env_local_offset(mtd5_base).ok_or("cannot compute nandrecovery_env local")?;
    Ok(format!(
        "schema={schema}\n\
plan_schema=dcentos.amlogic-recover-to-stock/v1\n\
mode=dry-run\n\
intent=UbootStockRevert\n\
flag_value=0x02\n\
flag_local=0x{flag_local:08X}\n\
nandrecovery_env_local=0x{env_local:08X}\n\
recover_env_source={source_name}\n\
nand_env_bak_is_not_nandrecovery_env=true\n\
env_crc_ok=true\n\
step0=ImportNandrecoveryEnv\n\
step1=EraseNvdata\n\
step2=Reset\n\
dry_step0={step0}\n\
dry_step1={step1}\n\
dry_step2={step2}\n\
nand_erase_part=nvdata\n\
bootm_mtd2=false\n\
nandwrite=false\n\
gpio_write=false\n\
fw_setenv=false\n\
env_import=false\n\
execute=CLEAR_FOR_FLASH\n\
clear_for_flash=false\n\
dry_run=true nandwrite=false gpio_write=false\n\
pass=admit_s19k_recover_execute_returns_ClearForFlashNotYet\n\
fail=nand_erase_or_env_import_without_admit\n",
        schema = S19K_RECOVER_WALK_SCHEMA,
        step0 = S19K_RECOVER_DRY_STEP0,
        step1 = S19K_RECOVER_DRY_STEP1,
        step2 = S19K_RECOVER_DRY_STEP2,
    ))
}

/// CRC-admit a constructed sidecar + rust plan, then emit the walk ledger.
pub fn walk_s19k_recover_to_stock_artifact(
    plan: &str,
    source_name: &str,
    env_blob: &[u8],
) -> Result<String, &'static str> {
    refuse_s19k_nand_env_bak_as_recover_env_import(source_name)?;
    if !plan.contains("schema=dcentos.amlogic-recover-to-stock/v1") {
        return Err("recover walk requires rust recover-to-stock plan");
    }
    if !plan.contains("step0=ImportNandrecoveryEnv")
        || !plan.contains("step1=EraseNvdata")
        || !plan.contains("step2=Reset")
    {
        return Err("recover walk requires ImportNandrecoveryEnv / EraseNvdata / Reset");
    }
    if plan.contains("recover_env_source=nand_env.bak") {
        return Err("nand_env.bak is not recover_env");
    }
    let env = admit_s19k_nandrecovery_env_slice(env_blob)?;
    format_s19k_recover_walk_ledger(S19K_78_MTD5_BASE, source_name).and_then(|walk| {
        admit_s19k_recover_walk_ledger(&walk)?;
        let _ = env;
        Ok(walk)
    })
}

/// Walk ledger must name the three U-Boot steps and stay FLASH-false.
pub fn admit_s19k_recover_walk_ledger(ledger: &str) -> Result<(), &'static str> {
    if !ledger.contains("schema=dcentos.amlogic-recover-walk/v1") {
        return Err("walk ledger must use recover-walk schema");
    }
    if !ledger.contains("mode=dry-run") {
        return Err("walk ledger must be dry-run");
    }
    if !ledger.contains("step0=ImportNandrecoveryEnv") {
        return Err("walk ledger missing step0");
    }
    if !ledger.contains("step1=EraseNvdata") {
        return Err("walk ledger missing step1");
    }
    if !ledger.contains("step2=Reset") {
        return Err("walk ledger missing step2");
    }
    if !ledger.contains(S19K_RECOVER_DRY_STEP0) {
        return Err("walk ledger missing recover_env dry_step0");
    }
    if !ledger.contains("dry_step1=nand erase.part nvdata") {
        return Err("walk ledger missing dry_step1");
    }
    if !ledger.contains("dry_step2=reset") {
        return Err("walk ledger missing dry_step2");
    }
    if !ledger.contains("recover_env_source=nandrecovery_env.bin") {
        return Err("walk ledger must name nandrecovery_env.bin");
    }
    if !ledger.contains("nandwrite=false") {
        return Err("walk ledger must keep nandwrite=false");
    }
    if !ledger.contains("fw_setenv=false") {
        return Err("walk ledger must keep fw_setenv=false");
    }
    if !ledger.contains("env_import=false") {
        return Err("walk ledger must keep env_import=false");
    }
    if !ledger.contains("clear_for_flash=false") {
        return Err("walk ledger must keep clear_for_flash=false");
    }
    if ledger.contains("recover_env_source=nand_env.bak") {
        return Err("walk ledger must not import nand_env.bak");
    }
    Ok(())
}

/// : runner must CRC-admit the sidecar and walk the rust plan.
pub fn admit_s19k_recover_script_dry_run_walks_plan(script: &str) -> Result<(), &'static str> {
    if !script.contains("--dry-run") {
        return Err("recover runner must accept --dry-run");
    }
    if !script.contains("--verify-only") {
        return Err("recover runner must accept --verify-only");
    }
    if !script.contains("RECOVER_TO_STOCK_PLAN.txt") {
        return Err("recover runner must read RECOVER_TO_STOCK_PLAN.txt");
    }
    if !script.contains("s19k_nand_env_crc.py") {
        return Err("recover runner must CRC-admit nandrecovery_env.bin");
    }
    if !script.contains("nandrecovery_env.bin CRC32 mismatch") {
        return Err("recover runner must refuse sidecar CRC mismatch");
    }
    if !script.contains("nand_env.bak is not recover_env") {
        return Err("recover runner must refuse nand_env.bak as recover_env");
    }
    if !script.contains("RECOVER_WALK.txt") {
        return Err("recover runner must write RECOVER_WALK.txt");
    }
    if !script.contains("BACKUP_LEDGER.txt") || !script.contains("field_get_exact") {
        return Err("recover runner must parse exact-one plan and backup-ledger authority fields");
    }
    if !script.contains("nandrecovery_env_sha256")
        || !script.contains("nandrecovery_env_sha256_ok=true")
        || !script.contains("nandrecovery_env.bin sha256 does not match BACKUP_LEDGER")
    {
        return Err("recover runner must bind nandrecovery_env.bin to BACKUP_LEDGER sha256");
    }
    if !script.contains("0x04D00000") || !script.contains("0x04900000") {
        return Err("recover runner must seal .78 flag and nandrecovery offsets");
    }
    if !script.contains(".RECOVER_WALK.txt.tmp.XXXXXX")
        || !script.contains(".RECOVER_EXECUTE_REFUSE.txt.tmp.XXXXXX")
    {
        return Err("recover runner must publish derived evidence atomically");
    }
    if !script.contains(
        "[DRY RUN] walking RECOVER_TO_STOCK_PLAN before GPIO/nandwrite/fw_setenv/env import",
    ) {
        return Err("recover runner dry-run must walk the plan before GPIO/NAND");
    }
    admit_s19k_recover_walk_ledger(script)?;
    let dry = script
        .find("[DRY RUN] walking RECOVER_TO_STOCK_PLAN")
        .ok_or("missing dry-run walk banner")?;
    let nw = script
        .find("nandwrite -p /dev/mtd5")
        .ok_or("missing refused linux nandwrite substitute")?;
    if dry > nw {
        return Err("dry-run walk must precede refused nandwrite");
    }
    Ok(())
}

/// : recover `--execute` order matches restore/flag FLASH contract.
/// EXECUTE < FLASH < exact live platform:target < GPIO437 SafeOff=1 <
/// /proc/mtd < nandwrite.
pub fn admit_s19k_recover_script_execute_refuses_nandwrite(
    script: &str,
) -> Result<(), &'static str> {
    if !script.contains("CLEAR_FOR_FLASH=false — refusing gpio437 SafeOff/flash_erase/nandwrite")
    {
        return Err("recover execute must refuse CLEAR_FOR_FLASH before GPIO/NAND");
    }
    if !script.contains("missing live canonical platform/board_target pair")
        || !script.contains("am3-aml-s19k:am3-s19k")
    {
        return Err("recover execute must refuse without exact live S19k platform:target");
    }
    if !script.contains("missing live /proc/mtd; refuse geometry-blind recover-to-stock") {
        return Err("recover execute must refuse missing live /proc/mtd");
    }
    if script.contains("if [ -r /proc/mtd ]; then") {
        return Err("recover execute must not skip geometry when /proc/mtd is absent");
    }
    if script.contains("\nfw_setenv firstboot 1\n") {
        return Err("recover runner must not fw_setenv firstboot");
    }
    let confirm = script
        .find("Type 'RECOVER'")
        .ok_or("missing RECOVER confirm")?;
    let refuse = script
        .find("CLEAR_FOR_FLASH=false — refusing")
        .ok_or("missing recover execute refuse")?;
    let identity = script
        .find("require_exact_live_s19k_identity /etc/dcentos || exit 1")
        .ok_or("missing recover exact live identity invocation")?;
    let gpio = script
        .find("gpio437 SafeOff (am3-s19k-active-low, value=1)")
        .ok_or("missing recover gpio SafeOff")?;
    let proc = script
        .find("missing live /proc/mtd; refuse geometry-blind recover-to-stock")
        .ok_or("missing recover /proc/mtd refuse")?;
    let nw = script
        .find("nandwrite -p /dev/mtd5")
        .ok_or("missing refused linux nandwrite")?;
    if refuse < confirm {
        return Err("execute refuse must follow RECOVER confirm");
    }
    if refuse > identity {
        return Err("execute refuse must precede exact live identity check");
    }
    if refuse > gpio {
        return Err("execute refuse must precede GPIO SafeOff");
    }
    if refuse > proc {
        return Err("execute refuse must precede /proc/mtd require");
    }
    if refuse > nw {
        return Err("execute refuse must precede nandwrite");
    }
    if identity > gpio {
        return Err("exact live identity must precede GPIO SafeOff");
    }
    if gpio > proc {
        return Err("GPIO SafeOff must precede /proc/mtd require");
    }
    if proc > nw {
        return Err("/proc/mtd require must precede nandwrite");
    }
    Ok(())
}

/// Extract + CRC-admit `nandrecovery_env` from a full mtd5 dump, then plan.
pub fn plan_s19k_recover_to_stock(
    mtd5: &[u8],
    mtd5_base: u64,
    source_name: &str,
) -> Result<String, &'static str> {
    let slice = extract_s19k_nandrecovery_env_from_mtd5_backup(mtd5, mtd5_base)?;
    let env = admit_s19k_nandrecovery_env_slice(slice)?;
    format_s19k_recover_to_stock_plan(mtd5_base, source_name, &env)
}

/// Plan for writing the recovery-flag byte. Only `0x02` is admitted for execute
/// (U-Boot stock revert). `0x01` has a separate install-commit plan; `0x03` stays FLASH NOT_YET.
pub fn format_s19k_recovery_flag_write_plan(
    value: u8,
    mtd5_base: u64,
    claimed_local: u64,
    target_mtd: u8,
) -> Result<String, S19kRestoreError> {
    let intent = admit_s19k_recovery_flag_write(value, mtd5_base, claimed_local, target_mtd)?;
    let eb = plan_s19k_recovery_flag_eraseblock(claimed_local)?;
    Ok(format!(
        "schema=dcentos.amlogic-recovery-flag/v1\nintent={intent:?}\nvalue=0x{value:02X}\nlocal_offset=0x{claimed_local:08X}\nmtd5_base=0x{mtd5_base:08X}\ntarget_mtd={target_mtd}\neraseblock_index={idx}\neraseblock_start=0x{start:08X}\nbyte_in_block=0x{off:X}\nerase_count=1\nrewriter=eraseblock_rewrite\nclear_for_flash=false\nenv_flip=false\n",
        idx = eb.eraseblock_index,
        start = eb.eraseblock_start,
        off = eb.byte_in_block,
    ))
}

pub fn format_s19k_restore_plan(
    kind: S19kRestoreKind,
    target_mtd: u8,
    use_window_offset: bool,
) -> String {
    format!(
        "schema=dcentos.amlogic-restore/v1\nkind={kind:?}\ntarget_mtd={target_mtd}\nuse_window_offset={use_window_offset}\nrestore_nand_env=false\nnand_env_bak_is_not_nandrecovery_env=true\nrecover_env_source=nandrecovery_env.bin\nnandrecovery_env_crc_ok=true\nnandrecovery_env_local=0x04900000\nrecovery_flag_local=0x04D00000\nenv_flip=false\nclear_for_flash=false\nbraiins_success_is_not_stock_go=true\n"
    )
}

/// Revert/install NAND write preflight. Must run **before** nandwrite.
pub fn admit_s19k_nandwrite_preflight(tools: S19kTargetTools) -> Result<(), &'static str> {
    if !tools.nandwrite {
        return Err("nandwrite missing; refuse NAND write");
    }
    if !tools.fw_setenv {
        return Err(
            "fw_setenv missing (Braiins L3); refuse NAND write before env-flip is possible",
        );
    }
    Ok(())
}

/// Host-side backup ledger text. Does not read files or flash.
pub fn format_s19k_backup_manifest_v1(
    board_target: &str,
    gpio437_value: Option<u8>,
    fw_printenv_present: bool,
) -> String {
    let polarity = if board_target.contains("s19k") {
        "s19k_active_low"
    } else {
        "unresolved"
    };
    let gpio = gpio437_value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "unexported".into());
    let source = if board_target.trim().is_empty() {
        S19K_BOARD_TARGET_SOURCE_PACKAGE
    } else {
        S19K_BOARD_TARGET_SOURCE_LIVE
    };
    format!(
        "schema={S19K_BACKUP_SCHEMA}\nboard_target={board_target}\nboard_target_source={source}\nclear_for_flash=false\ngpio437_value={gpio}\ngpio437_polarity={polarity}\nfw_printenv_present={fw_printenv_present}\nnand_env={}\nmtd5_window={}\nbraiins_success_is_not_stock_go=true\n",
        S19K_BACKUP_MANIFEST.nand_env, S19K_BACKUP_MANIFEST.mtd5_window
    )
}

/// Incomplete ledger: L3 env-tool absence is recorded, but restore SHA
/// fields are absent. `parse_s19k_backup_ledger` refuses this output.
/// Use [`format_s19k_backup_ledger_with_hashes`] for a restore-complete ledger.
pub fn format_s19k_backup_ledger(
    board_target: &str,
    gpio437_value: Option<u8>,
    tools: S19kTargetTools,
    nand_env_len: usize,
    mtd5_len: usize,
) -> String {
    let base = format_s19k_backup_manifest_v1(board_target, gpio437_value, tools.fw_printenv);
    format!(
        "{base}nand_env_len={nand_env_len}\nmtd5_len={mtd5_len}\nfw_setenv_present={}\nbackup_tools_ok={}\nflash_tools_ok={}\nnandrecovery_env={S19K_BACKUP_NANDRECOVERY_ENV_NAME}\nnandrecovery_env_local=0x04900000\nrecovery_flag_local=0x04D00000\nnand_env_bak_is_not_nandrecovery_env=true\nl3_hint={BRAIINS_AML_L3_HINT}\n",
        tools.fw_setenv,
        tools.backup_ok(),
        tools.flash_tools_ok()
    )
}

/// Installer-shaped ledger including distinct SHA-256 lines required for restore.
pub fn format_s19k_backup_ledger_with_hashes(
    board_target: &str,
    gpio437_value: Option<u8>,
    tools: S19kTargetTools,
    nand_env_len: usize,
    mtd5_len: usize,
    nand_env_sha256: &str,
    mtd5_sha256: &str,
    nandrecovery_env_sha256: &str,
) -> Result<String, &'static str> {
    admit_s19k_backup_hashes(nand_env_sha256, mtd5_sha256)?;
    admit_s19k_sha256_hex64(nandrecovery_env_sha256)?;
    if nandrecovery_env_sha256.eq_ignore_ascii_case(nand_env_sha256) {
        return Err("nandrecovery_env_sha256 must not equal nand_env_sha256");
    }
    let base =
        format_s19k_backup_ledger(board_target, gpio437_value, tools, nand_env_len, mtd5_len);
    Ok(format!(
        "{base}nand_env_sha256={nand_env_sha256}\nmtd5_sha256={mtd5_sha256}\nnandrecovery_env_sha256={nandrecovery_env_sha256}\n"
    ))
}

/// No-hash formatter is not restore-complete ().
pub fn refuse_s19k_hashless_ledger_formatter_as_restore_complete(
    text: &str,
) -> Result<(), &'static str> {
    if text.contains("nandrecovery_env_sha256=") {
        return Ok(());
    }
    Err("format_s19k_backup_ledger without hashes is not restore-complete")
}

/// Hashed formatter must emit the sidecar SHA restore binds.
pub fn admit_s19k_hashed_ledger_formatter_emits_sidecar_sha(
    text: &str,
) -> Result<(), &'static str> {
    parse_s19k_backup_ledger(text)?;
    admit_s19k_backup_ledger_hashes(text)?;
    if !text.contains("nandrecovery_env_sha256=") {
        return Err("hashed ledger formatter must emit nandrecovery_env_sha256");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kFlashAdmitError {
    ClearForFlashNotYet,
    StockCarrierUnsupported,
    WrongSafeOffPolarity,
    BootloaderWriteForbidden,
}

/// Fail-closed flash admit. Always NOT_YET today.
pub fn admit_s19k_flash(
    carrier: S19kInstallCarrier,
    safe_off_value: u8,
    target_mtd: u8,
) -> Result<(), S19kFlashAdmitError> {
    if !CLEAR_FOR_FLASH {
        return Err(S19kFlashAdmitError::ClearForFlashNotYet);
    }
    if carrier == S19kInstallCarrier::StockAmlCtrl {
        return Err(S19kFlashAdmitError::StockCarrierUnsupported);
    }
    if refuse_re4c_safe_off_as_am3_s19k_cut(safe_off_value).is_err() {
        return Err(S19kFlashAdmitError::WrongSafeOffPolarity);
    }
    if target_mtd != 5 {
        return Err(S19kFlashAdmitError::BootloaderWriteForbidden);
    }
    Ok(())
}

pub fn gpio437_safe_off_for_variant(variant: &str) -> u8 {
    let v = variant.trim();
    // Live aliases share T6 SafeOff=1. CLI short names stay admitted.
    // Unknown (including S21) stays 0 — do not guess this SKU onto them.
    if s19k_board_target_is_live_alias(v) || matches!(v, "s19kpro" | "s19k") {
        am3_s19k_install_safe_off_value()
    } else {
        0
    }
}

/// SafeOff from **proven identity**, not a forgotten `--variant` default.
/// Empty board_target refuses (do not guess s19kpro=1 onto an S21).
pub fn gpio437_safe_off_for_identity(
    variant: &str,
    observed_board_target: &str,
) -> Result<u8, &'static str> {
    let target = observed_board_target.trim();
    if target.is_empty() {
        return Err("refuse GPIO437 SafeOff without proven board_target");
    }
    let from_target = gpio437_safe_off_for_variant(target);
    let from_variant = gpio437_safe_off_for_variant(variant);
    if from_target != from_variant {
        return Err("VARIANT and proven board_target disagree on GPIO437 SafeOff polarity");
    }
    Ok(from_target)
}

pub fn refuse_braiins_success_as_stock_go() -> Result<(), &'static str> {
    Err("Braiins /tmp mining ≠ stock AMLCtrl first-install GO")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kStockReturnKind {
    /// Braiins 6-part: U-Boot can revert to mtd2 `stock_system`.
    Mtd2StockSystem,
    /// Post-2021 stock 7-part map — no DCENT writer.
    Stock7Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kStockReturnError {
    ClearForFlashNotYet,
    BootloaderForbidden,
    Stock7LayoutBlocked,
    MissingBackupManifest,
}

/// Classify a live `/proc/mtd` name list. 6-part Braiins map with
/// `stock_system` is the only rollback-shaped layout. 7+ names are blocked.
/// Does not write NAND. FLASH still requires [`admit_s19k_flash`].
/// Restore/pre-install nanddump is 6-part only. 7-part and unknown maps refuse
/// independently of [`CLEAR_FOR_FLASH`].
pub fn admit_s19k_restore_nand_layout(
    mtd_names: &[&str],
) -> Result<S19kStockReturnKind, S19kRestoreError> {
    match classify_s19k_nand_layout(mtd_names) {
        Ok(S19kStockReturnKind::Mtd2StockSystem) => Ok(S19kStockReturnKind::Mtd2StockSystem),
        Ok(S19kStockReturnKind::Stock7Blocked) => Err(S19kRestoreError::Stock7LayoutBlocked),
        Err(_) => Err(S19kRestoreError::Stock7LayoutBlocked),
    }
}

pub fn classify_s19k_nand_layout(mtd_names: &[&str]) -> Result<S19kStockReturnKind, &'static str> {
    let mapped: Vec<&str> = S19K_NAND_MAP.iter().map(|slot| slot.name).collect();
    if mtd_names == mapped.as_slice() {
        return Ok(S19kStockReturnKind::Mtd2StockSystem);
    }
    if mtd_names.len() >= 7 {
        return Ok(S19kStockReturnKind::Stock7Blocked);
    }
    if mtd_names.iter().any(|name| *name == "stock_system") && mtd_names.len() == 6 {
        return Ok(S19kStockReturnKind::Mtd2StockSystem);
    }
    Err("unrecognized NAND name list; refuse stock-return writer")
}

pub fn admit_s19k_stock_return(
    kind: S19kStockReturnKind,
    target_mtd: u8,
    backup_complete: bool,
) -> Result<(), S19kStockReturnError> {
    if !CLEAR_FOR_FLASH {
        return Err(S19kStockReturnError::ClearForFlashNotYet);
    }
    if !backup_complete {
        return Err(S19kStockReturnError::MissingBackupManifest);
    }
    if target_mtd == 0 || target_mtd == 1 {
        return Err(S19kStockReturnError::BootloaderForbidden);
    }
    match kind {
        S19kStockReturnKind::Stock7Blocked => Err(S19kStockReturnError::Stock7LayoutBlocked),
        S19kStockReturnKind::Mtd2StockSystem => {
            if target_mtd != 2 && target_mtd != 5 {
                return Err(S19kStockReturnError::BootloaderForbidden);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSTALL_SCRIPT: &str = include_str!("../../../scripts/install_amlogic_persistent.sh");
    const LAB_ROOTFS: &str = include_str!("../../../scripts/amlogic_lab_rootfs.sh");
    const GEOMETRY: &str = include_str!("../../../scripts/lib/am3_geometry.sh");
    const S37: &str = include_str!(
        "../../../br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S37board_setup"
    );
    const HAL_AML: &str = include_str!("../../dcentrald-hal/src/platform/amlogic/mod.rs");
    const REVERT: &str = include_str!("../../../scripts/revert_to_stock_am3_aml_s19k.sh");
    const RESTORE: &str = include_str!("../../../scripts/restore_amlogic_mtd5_from_backup.sh");
    const RECOVER: &str = include_str!("../../../scripts/recover_amlogic_to_stock.sh");
    const COMMON: &str = include_str!(
        "../../../br2_external_dcentos/board/amlogic/rootfs-overlay/lib/functions/common.sh"
    );
    const S99: &str = include_str!(
        "../../../br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S99upgrade"
    );
    const SYSTEM: &str = include_str!(
        "../../../br2_external_dcentos/board/amlogic/rootfs-overlay/lib/functions/system.sh"
    );

    fn exact_factory_sd_header() -> S19kAmlUpgradeHeader {
        S19kAmlUpgradeHeader {
            crc: S19K_AML_UPGRADE_CRC,
            version: S19K_AML_UPGRADE_VERSION,
            magic: S19K_AML_UPGRADE_MAGIC,
            image_sz: S19K_AML_FACTORY_SD_IMG_BYTES as u64,
            item_align: S19K_AML_UPGRADE_ITEM_ALIGN,
            item_num: S19K_AML_UPGRADE_ITEM_NUM,
        }
    }

    fn exact_factory_sd_evidence(kind: S19kAmlSdPackKind) -> S19kAmlFactorySdEvidence<'static> {
        S19kAmlFactorySdEvidence {
            kind,
            archive_bytes: S19K_AML_FACTORY_SD_ARCHIVE_BYTES,
            archive_sha256: S19K_AML_FACTORY_SD_ARCHIVE_SHA256,
            members: S19K_AML_FACTORY_SD_MEMBERS,
            ini_bytes: S19K_AML_FACTORY_SD_INI_BYTES,
            ini_sha256: S19K_AML_FACTORY_SD_INI_SHA256,
            uboot_bytes: S19K_AML_FACTORY_SD_UBOOT_BYTES,
            uboot_sha256: S19K_AML_FACTORY_SD_UBOOT_SHA256,
            img_bytes: S19K_AML_FACTORY_SD_IMG_BYTES,
            img_sha256: S19K_AML_FACTORY_SD_IMG_SHA256,
            toc_sha256: S19K_AML_FACTORY_SD_TOC_SHA256,
            upgrade_header: exact_factory_sd_header(),
        }
    }

    #[test]
    fn s19k_dcent_sysupgrade_tar_still_refuses_execute() {
        assert_eq!(
            classify_s19k_upgrade_blob("sysupgrade-am3-s19k.tar", b""),
            S19kUpgradeBlobKind::DcentSysupgradeTar
        );
        assert!(refuse_s19k_dcent_sysupgrade_execute_while_flash_false(
            S19kUpgradeBlobKind::DcentSysupgradeTar
        )
        .is_err());
        assert!(!CLEAR_FOR_FLASH);
        assert!(refuse_s19k_leftover_admitted_inactive_as_flash_grant().is_err());
        assert_eq!(
            s19k_aml_intent_from_artifact("BACKUP_LEDGER.txt"),
            Some(S19kAmlMutationIntent::BackupOnly)
        );
        assert_eq!(
            s19k_aml_intent_from_artifact("RECOVER_TO_STOCK_PLAN.txt"),
            Some(S19kAmlMutationIntent::RollbackPlan)
        );
        assert_eq!(
            s19k_aml_intent_from_artifact("RECOVER_EXECUTE_REFUSE.txt"),
            Some(S19kAmlMutationIntent::RollbackExecute)
        );
        assert_eq!(
            s19k_aml_intent_from_artifact("RESCUE_CONSOLE.txt"),
            Some(S19kAmlMutationIntent::RescueConsole)
        );
        assert_eq!(
            s19k_aml_intent_from_artifact("sysupgrade-am3-s19k.tar"),
            Some(S19kAmlMutationIntent::SysupgradeExecute)
        );
        assert_eq!(admit_s19k_aml_artifact("BACKUP_LEDGER.txt"), Ok(()));
        assert_eq!(admit_s19k_aml_artifact("RECOVER_TO_STOCK_PLAN.txt"), Ok(()));
        assert_eq!(admit_s19k_aml_artifact("RESCUE_CONSOLE.txt"), Ok(()));
        assert!(admit_s19k_aml_artifact("RECOVER_EXECUTE_REFUSE.txt").is_err());
        assert!(admit_s19k_aml_artifact("sysupgrade-am3-s19k.tar").is_err());
        assert!(refuse_s19k_rescue_console_as_nandwrite_grant().is_err());
        assert_eq!(refuse_s19k_rollback_plan_as_execute_grant(), Ok(()));
        assert_eq!(
            admit_s19k_recover_script_refuses_execute_before_gpio(RECOVER),
            Ok(())
        );
        assert!(INSTALL_SCRIPT.contains("RECOVER_EXECUTE_REFUSE.txt"));
        assert!(INSTALL_SCRIPT.contains("execute=refused"));
    }

    #[test]
    fn leftover_admit_is_refused_as_flash_grant() {
        assert!(!CLEAR_FOR_FLASH);
        let grant = refuse_s19k_leftover_admitted_inactive_as_flash_grant();
        eprintln!("leftover_admit_flash_grant={grant:?}");
        assert!(grant.is_err());
        assert!(grant
            .unwrap_err()
            .contains("leftover-admitted Chain Inactive is UART CMD=3"));
        assert!(admit_s19k_aml_mutation(S19kAmlMutationIntent::SysupgradeExecute).is_err());
        assert!(admit_s19k_aml_mutation(S19kAmlMutationIntent::RestoreExecute).is_err());
    }

    #[test]
    fn flash_stays_not_yet_and_stock_is_separate() {
        assert!(!CLEAR_FOR_FLASH);
        assert_eq!(
            admit_s19k_aml_mutation(S19kAmlMutationIntent::BackupOnly),
            Ok(())
        );
        assert_eq!(
            admit_s19k_aml_mutation(S19kAmlMutationIntent::RestorePlan),
            Ok(())
        );
        assert_eq!(
            admit_s19k_aml_mutation(S19kAmlMutationIntent::RollbackPlan),
            Ok(())
        );
        assert_eq!(
            admit_s19k_aml_mutation(S19kAmlMutationIntent::RescueConsole),
            Ok(())
        );
        assert!(admit_s19k_aml_mutation(S19kAmlMutationIntent::RestoreExecute).is_err());
        assert!(admit_s19k_aml_mutation(S19kAmlMutationIntent::RollbackExecute).is_err());
        assert!(admit_s19k_aml_mutation(S19kAmlMutationIntent::SysupgradeExecute).is_err());
        assert!(refuse_s19k_backup_as_nandwrite_grant().is_err());
        assert_eq!(rootfs_local_offset(S19K_78_MTD5_BASE), Some(0x0510_0000));
        assert_eq!(rootfs_local_offset(0x0670_0000), Some(0x0510_0000));
        assert_eq!(
            admit_s19k_rootfs_window(S19K_78_MTD5_BASE, 0x0510_0000),
            Ok(0x0510_0000)
        );
        assert!(admit_s19k_rootfs_window(S19K_78_MTD5_BASE, 0x0570_0000).is_err());
        assert!(admit_s19k_physical_mtd5_base(S19K_78_MTD5_SIZE_SUM).is_err());
        let proc_mtd = "\
dev:    size   erasesize  name
mtd0: 00200000 00020000 \"bootloader\"
mtd1: 00800000 00020000 \"tpl\"
mtd2: 03200000 00020000 \"stock_system\"
mtd3: 00500000 00020000 \"stock_config\"
mtd4: 02000000 00020000 \"overlay\"
mtd5: 09900000 00020000 \"system\"
";
        assert_eq!(mtd5_base_from_proc_mtd(proc_mtd), Some(0x0670_0000));
        let piped = proc_mtd.replace('\n', "|");
        assert_eq!(mtd5_base_from_proc_mtd(&piped), Some(0x0670_0000));
        let geo = compute_s19k_geometry_from_proc_mtd(proc_mtd).unwrap();
        assert_eq!(geo.mtd5_base, 0x0670_0000);
        assert_eq!(geo.rootfs_local, 0x0510_0000);
        assert_eq!(geo.recovery_flag_local, 0x04D0_0000);
        assert!(
            admit_s19k_planned_locals_match_computed(proc_mtd, 0x0510_0000, 0x04D0_0000).is_ok()
        );
        assert!(
            admit_s19k_planned_locals_match_computed(proc_mtd, 0x0570_0000, 0x04D0_0000).is_err()
        );
        assert_eq!(OFFSET_FROM_END_MTD0_TO_MTD1, 0x60_0000);
        assert_eq!(
            admit_s19k_flash(S19kInstallCarrier::BraiinsRootSsh, 1, 5),
            Err(S19kFlashAdmitError::ClearForFlashNotYet)
        );
        assert!(refuse_braiins_success_as_stock_go().is_err());
        assert_eq!(gpio437_safe_off_for_variant("s19kpro"), 1);
        assert_eq!(gpio437_safe_off_for_variant("s21"), 0);
        assert_eq!(gpio437_safe_off_for_variant("am3-aml-s19kpro"), 1);
        assert!(s19k_board_target_is_live_alias("am3-aml-s19kpro"));
        assert!(!s19k_board_target_is_live_alias("am3-s21"));
        assert_eq!(
            gpio437_safe_off_for_identity("s19kpro", "am3-s19k").unwrap(),
            1
        );
        assert_eq!(
            gpio437_safe_off_for_identity("am3-s19kpro", "am3-aml-s19kpro").unwrap(),
            1
        );
        assert!(gpio437_safe_off_for_identity("s21", "am3-aml-s19kpro").is_err());
        assert!(gpio437_safe_off_for_identity("s19kpro", "").is_err());
        assert!(gpio437_safe_off_for_identity("s19kpro", "am3-s21").is_err());
        assert_eq!(
            admit_s19k_stock_return(S19kStockReturnKind::Mtd2StockSystem, 2, true),
            Err(S19kStockReturnError::ClearForFlashNotYet)
        );
        assert_eq!(crate::s19k_am3_gpio437::S19K_AM3_GPIO437_VALUE_OFF, 1);
        assert_eq!(S19K_NAND_MAP[5].mtd, 5);
        assert!(S19K_NAND_MAP[5].writable_by_sysupgrade);
        assert!(!S19K_NAND_MAP[0].writable_by_sysupgrade);
        assert!(!S19K_NAND_MAP[2].writable_by_sysupgrade);
        let refuse = INSTALL_SCRIPT
            .find("CLEAR_FOR_FLASH=false")
            .expect("installer must pin CLEAR_FOR_FLASH=false");
        let erase = INSTALL_SCRIPT
            .find("flash_erase $ROOTFS_MTD $ROOTFS_OFFSET_HEX")
            .expect("flash_erase");
        assert!(
            refuse < erase,
            "installer must refuse FLASH before flash_erase"
        );
        assert!(INSTALL_SCRIPT
            .contains("ERROR: CLEAR_FOR_FLASH=false - refusing flash_erase/nandwrite/fw_setenv"));
        assert!(
            INSTALL_SCRIPT.contains("recover_execute=refused reason=CLEAR_FOR_FLASH"),
            "installer must print recover-execute refuse beside CLEAR_FOR_FLASH"
        );
        assert_eq!(S19K_BACKUP_MANIFEST.nand_env, "nand_env.bin");
        let man = format_s19k_backup_manifest_v1("am3-s19k", Some(0), false);
        assert!(man.contains("schema=dcentos.amlogic-backup/v1"));
        assert!(man.contains("clear_for_flash=false"));
        assert!(man.contains("s19k_active_low"));
        assert!(man.contains("gpio437_value=0"));
        assert!(man.contains("braiins_success_is_not_stock_go=true"));
        assert!(man.contains("board_target_source=live"));
        let rec_live = record_s19k_backup_board_target(Some("am3-s19kpro"), "am3-s19k").unwrap();
        assert_eq!(rec_live.source, S19K_BOARD_TARGET_SOURCE_LIVE);
        assert_eq!(rec_live.board_target, "am3-s19kpro");
        let rec_pkg = record_s19k_backup_board_target(None, "am3-s19k").unwrap();
        assert_eq!(rec_pkg.source, S19K_BOARD_TARGET_SOURCE_PACKAGE);
        assert!(rec_pkg.board_target.is_empty());
        assert!(record_s19k_backup_board_target(None, "am3-s21").is_err());
        assert!(refuse_s19k_restore_execute_package_identity("package").is_err());
        assert!(refuse_s19k_restore_execute_package_identity("").is_err());
        assert!(refuse_s19k_restore_execute_package_identity("live").is_ok());
        let l3 = S19kTargetTools {
            dd: true,
            sha256sum: true,
            nanddump: true,
            nandwrite: true,
            flash_erase: true,
            fw_printenv: false,
            fw_setenv: false,
        };
        assert!(l3.backup_ok());
        assert!(!l3.env_flip_ok());
        assert!(!l3.flash_tools_ok());
        assert_eq!(admit_s19k_backup(l3, NAND_ENV_BACKUP_LEN, 1), Ok(()));
        assert_eq!(
            admit_s19k_backup(l3, 1, 1),
            Err(S19kBackupAdmitError::NandEnvSizeWrong)
        );
        assert_eq!(
            admit_s19k_env_flip(
                l3,
                S19kBackupCompleteness {
                    nand_env: true,
                    mtd5_window: true,
                    gpio437: true,
                    fw_printenv: false,
                }
            ),
            Err(S19kEnvFlipError::ClearForFlashNotYet)
        );
        assert!(admit_s19k_nandwrite_preflight(l3).is_err());
        let full = S19kTargetTools {
            fw_printenv: true,
            fw_setenv: true,
            ..l3
        };
        assert!(admit_s19k_nandwrite_preflight(full).is_ok());
        assert!(admit_s19k_flash(S19kInstallCarrier::BraiinsRootSsh, 1, 5).is_err());
        let six: Vec<&str> = S19K_NAND_MAP.iter().map(|s| s.name).collect();
        assert_eq!(
            classify_s19k_nand_layout(&six),
            Ok(S19kStockReturnKind::Mtd2StockSystem)
        );
        assert_eq!(
            classify_s19k_nand_layout(&[
                "bootloader",
                "tpl",
                "stock_system",
                "reserved",
                "overlay",
                "system",
                "recovery"
            ]),
            Ok(S19kStockReturnKind::Stock7Blocked)
        );
        assert!(classify_s19k_nand_layout(&["bootloader"]).is_err());
        assert!(admit_s19k_backup_filenames(&[
            "nand_env.bak",
            "mtd5_pre_install.bin",
            "gpio437.value",
            "fw_env_pre.txt",
            "BACKUP_LEDGER.txt",
        ])
        .unwrap()
        .backup_complete());
        assert_eq!(
            admit_s19k_backup_filenames(&["nand_env.bin"]),
            Err(S19kBackupAdmitError::MissingArtifact)
        );
        assert!(INSTALL_SCRIPT.contains("nand_env.bak"));
        assert!(INSTALL_SCRIPT.contains("BACKUP_LEDGER.txt"));
        let parsed = parse_s19k_backup_ledger(
            "schema=dcentos.amlogic-backup/v1\nclear_for_flash=false\nbraiins_success_is_not_stock_go=true\nnand_env=nand_env.bak\nmtd5_window=mtd5_pre_install.bin\ngpio437_value=0\nnandrecovery_env=nandrecovery_env.bin\nnandrecovery_env_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nfw_printenv_present=false\n",
        )
        .unwrap();
        assert!(parsed.backup_complete());
        assert!(!parsed.fw_printenv);
        assert!(parse_s19k_backup_ledger("schema=nope\n").is_err());
        let no_sidecar = "schema=dcentos.amlogic-backup/v1\nclear_for_flash=false\nbraiins_success_is_not_stock_go=true\nnand_env=nand_env.bak\nmtd5_window=mtd5_pre_install.bin\ngpio437_value=0\nfw_printenv_present=false\n";
        assert!(parse_s19k_backup_ledger(no_sidecar).is_err());
        assert!(refuse_s19k_backup_ledger_without_nandrecovery_sidecar(no_sidecar).is_err());
        assert!(refuse_s19k_backup_ledger_without_nandrecovery_sidecar(
            "nandrecovery_env=nandrecovery_env.bin\n"
        )
        .is_ok());
        let a = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let b = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        assert!(admit_s19k_backup_hashes(a, b).is_ok());
        assert!(admit_s19k_backup_hashes(a, a).is_err());
        assert!(admit_s19k_backup_hashes("nope", b).is_err());
        let rec = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let hashed = format!(
            "schema=dcentos.amlogic-backup/v1\nclear_for_flash=false\nbraiins_success_is_not_stock_go=true\nnand_env=nand_env.bak\nmtd5_window=mtd5_pre_install.bin\ngpio437_value=0\nnandrecovery_env=nandrecovery_env.bin\nnand_env_sha256={a}\nmtd5_sha256={b}\nnandrecovery_env_sha256={rec}\n"
        );
        assert!(parse_s19k_backup_ledger(
            "schema=dcentos.amlogic-backup/v1\nclear_for_flash=false\nbraiins_success_is_not_stock_go=true\nnand_env=nand_env.bak\nmtd5_window=mtd5_pre_install.bin\ngpio437_value=0\nnandrecovery_env=nandrecovery_env.bin\nfw_printenv_present=false\n"
        )
        .is_err());
        let bak_as_rec = format!(
            "schema=dcentos.amlogic-backup/v1\nclear_for_flash=false\nbraiins_success_is_not_stock_go=true\nnand_env=nand_env.bak\nmtd5_window=mtd5_pre_install.bin\ngpio437_value=0\nnandrecovery_env=nandrecovery_env.bin\nnand_env_sha256={a}\nmtd5_sha256={b}\nnandrecovery_env_sha256={a}\n"
        );
        assert!(parse_s19k_backup_ledger(&bak_as_rec).is_err());
        assert!(admit_s19k_backup_ledger_hashes(&hashed).is_ok());
        assert!(admit_s19k_backup_ledger_hashes("clear_for_flash=false\n").is_err());
        let proc_mtd = "dev: size erasesize name|mtd0: 00200000 00020000 \"bootloader\"|mtd1: 00800000 00020000 \"tpl\"|mtd2: 03200000 00020000 \"stock_system\"|mtd3: 00500000 00020000 \"stock_config\"|mtd4: 02000000 00020000 \"overlay\"|mtd5: 09900000 00020000 \"system\"";
        let restore_ok = format!(
            "{hashed}board_target=am3-s19k\nmtd5_len={}\nproc_mtd={proc_mtd}\ncomputed_mtd5_base=0x06700000\n",
            S19K_78_MTD5_LEN
        );
        assert!(
            admit_s19k_restore_ledger_vs_live(&restore_ok, S19K_78_MTD5_LEN, Some(proc_mtd))
                .is_ok()
        );
        let restore_tiny = format!(
            "{hashed}board_target=am3-s19k\nmtd5_len=4096\nproc_mtd={proc_mtd}\ncomputed_mtd5_base=0x06700000\n"
        );
        assert!(
            admit_s19k_restore_ledger_vs_live(&restore_tiny, 4096, Some(proc_mtd)).is_err(),
            "hash-matched 4KiB mtd5 must not cover recovery windows"
        );
        let restore_unknown = format!(
            "{hashed}board_target=am3-s19k\nmtd5_len={}\nproc_mtd={proc_mtd}\ncomputed_mtd5_base=unknown\n",
            S19K_78_MTD5_LEN
        );
        assert!(
            admit_s19k_restore_ledger_vs_live(&restore_unknown, S19K_78_MTD5_LEN, None).is_err()
        );
        assert!(admit_s19k_restore_ledger_identity("").is_err());
        assert!(admit_s19k_restore_ledger_identity("am3-s21").is_err());
        assert!(admit_s19k_restore_live_board_target(None, "am3-s19k").is_err());
        assert!(admit_s19k_restore_live_board_target(Some(""), "am3-s19k").is_err());
        assert!(admit_s19k_restore_live_board_target(Some("am3-s19k"), "am3-s19k").is_ok());
        assert!(
            admit_s19k_restore_live_board_target(Some("am3-aml-s19kpro"), "am3-aml-s19kpro")
                .is_ok()
        );
        assert!(admit_s19k_restore_live_board_target(Some("am3-s21"), "am3-s19k").is_err());
        assert!(RESTORE.contains("am3-s19k|am3-s19kpro|am3-aml-s19kpro"));
        assert!(refuse_s19k_restore_tmp_deploy_stamp(true).is_err());
        assert!(refuse_s19k_restore_tmp_deploy_stamp(false).is_ok());
        assert!(RESTORE.contains("tmp_deploy leftover"));
        assert!(RESTORE.contains("missing live canonical platform/board_target pair"));
        assert!(RESTORE.contains("am3-aml-s19k:am3-s19k"));
        assert!(admit_s19k_restore_mtd5_len(4096, 1).is_err());
        assert!(admit_s19k_restore_ledger_vs_live(&hashed, 4096, None).is_err());
        let wrong_len = format!("{hashed}board_target=am3-s19k\nmtd5_len=99\n");
        assert!(admit_s19k_restore_ledger_vs_live(&wrong_len, 4096, None).is_err());
        assert!(RESTORE.contains("mtd5_len"));
        assert!(RESTORE.contains("admit ledger board_target"));
        assert!(INSTALL_SCRIPT.contains("nand_env_sha256="));
        assert!(INSTALL_SCRIPT.contains("mtd5_sha256="));
        let formatted = format_s19k_backup_ledger_with_hashes(
            "am3-s19k",
            Some(0),
            l3,
            NAND_ENV_BACKUP_LEN,
            4096,
            a,
            b,
            rec,
        )
        .unwrap();
        assert!(admit_s19k_backup_ledger_hashes(&formatted).is_ok());
        assert!(formatted.contains("nand_env_bak_is_not_nandrecovery_env=true"));
        assert!(formatted.contains("nandrecovery_env_local=0x04900000"));
        assert_eq!(
            nandrecovery_env_local_offset(S19K_78_MTD5_BASE),
            Some(0x0490_0000)
        );
        assert_eq!(
            NANDRECOVERY_ENV_GLOBAL,
            crate::s19k_nand_env::S19K_78_NANDRECOVERY_ENV
        );
        assert!(
            admit_s19k_mtd5_backup_covers_recovery(S19K_78_MTD5_LEN, S19K_78_MTD5_BASE).is_ok()
        );
        assert!(admit_s19k_mtd5_backup_covers_recovery(0x04D0_0000, S19K_78_MTD5_BASE).is_err());
        let mut tiny = [0u8; 8];
        tiny[3] = RECOVERY_FLAG_FIRST_BOOT;
        assert_eq!(read_s19k_mtd5_backup_byte(&tiny, 3).unwrap(), 0x02);
        assert!(refuse_nand_env_bak_as_nandrecovery_env().is_err());
        assert_eq!(
            nandrecovery_env_local_offset(S19K_78_MTD5_BASE),
            Some(S19K_78_NANDRECOVERY_ENV_LOCAL)
        );
        assert!(refuse_s19k_nand_env_bak_as_recover_env_import("nand_env.bak").is_err());
        assert!(refuse_s19k_nand_env_bak_as_recover_env_import("nand_env.bin").is_err());
        assert!(
            refuse_s19k_nand_env_bak_as_recover_env_import(S19K_BACKUP_NANDRECOVERY_ENV_NAME)
                .is_ok()
        );
        let mut body = b"recover=1\0\0".to_vec();
        body.resize(crate::s19k_nand_env::S19K_NAND_ENV_LEN - 4, 0);
        let crc = crate::s19k_nand_env::crc32_iso_hdlc(&body);
        let mut env_blob = Vec::with_capacity(crate::s19k_nand_env::S19K_NAND_ENV_LEN);
        env_blob.extend_from_slice(&crc.to_le_bytes());
        env_blob.extend_from_slice(&body);
        let local = S19K_78_NANDRECOVERY_ENV_LOCAL as usize;
        let mut mtd5 = vec![0u8; local + crate::s19k_nand_env::S19K_NAND_ENV_LEN];
        mtd5[local..local + env_blob.len()].copy_from_slice(&env_blob);
        let sliced =
            extract_s19k_nandrecovery_env_from_mtd5_backup(&mtd5, S19K_78_MTD5_BASE).unwrap();
        assert_eq!(sliced, env_blob.as_slice());
        let admitted = admit_s19k_nandrecovery_env_slice(sliced).unwrap();
        assert!(admitted.crc_ok);
        assert_eq!(admitted.vars.get("recover").map(String::as_str), Some("1"));
        assert!(
            extract_s19k_nandrecovery_env_from_mtd5_backup(&mtd5[..8], S19K_78_MTD5_BASE).is_err()
        );
        assert!(
            extract_s19k_nandrecovery_env_from_mtd5_backup(&mtd5, S19K_78_MTD5_SIZE_SUM).is_err()
        );
        assert!(formatted.contains("nandrecovery_env=nandrecovery_env.bin"));
        assert!(INSTALL_SCRIPT.contains("nandrecovery_env.bin"));
        assert!(INSTALL_SCRIPT.contains("dcent_am3_extract_nandrecovery_env"));
        assert!(GEOMETRY.contains("dcent_am3_extract_nandrecovery_env"));
        assert!(formatted.contains("clear_for_flash=false"));
        assert_eq!(
            admit_s19k_stock_return(S19kStockReturnKind::Mtd2StockSystem, 2, true),
            Err(S19kStockReturnError::ClearForFlashNotYet)
        );
        let ledger = format_s19k_backup_ledger("am3-s19k", Some(0), l3, NAND_ENV_BACKUP_LEN, 4096);
        assert!(ledger.contains("fw_setenv_present=false"));
        assert!(ledger.contains("backup_tools_ok=true"));
        assert!(ledger.contains("flash_tools_ok=false"));
        assert!(ledger.contains("lack fw_printenv/fw_setenv"));
        assert!(ledger.contains("nandrecovery_env=nandrecovery_env.bin"));
        assert!(
            !ledger.contains("nandrecovery_env_sha256="),
            "hashless formatter must not pretend restore-complete"
        );
        assert!(refuse_s19k_hashless_ledger_formatter_as_restore_complete(&ledger).is_err());
        assert!(parse_s19k_backup_ledger(&ledger).is_err());
        assert!(admit_s19k_hashed_ledger_formatter_emits_sidecar_sha(&formatted).is_ok());
        assert!(formatted.contains("nandrecovery_env_sha256="));
        assert!(INSTALL_SCRIPT.contains("--backup-only"));
        assert!(INSTALL_SCRIPT.contains("ABSENT_BRAIINS_L3"));
        assert!(REVERT.contains("fw_setenv missing"));
        let revert_tools = REVERT
            .find("Step 1c: NAND/env tool preflight")
            .expect("preflight");
        let revert_write = REVERT.find("nandwrite -p -s").expect("nandwrite");
        assert!(revert_tools < revert_write);
        assert!(
            LAB_ROOTFS.contains("refuse GPIO437 SafeOff without proven board identity"),
            "lab rootfs must not default SafeOff=0 on unknown identity"
        );
        assert!(admit_s19k_lab_rootfs_script_execute_refuses_nandwrite(LAB_ROOTFS).is_ok());
    }

    #[test]
    fn held_78_bad_blocks_shift_linux_nandwrite_but_do_not_prove_uboot_read() {
        const ERASE: u64 = 0x0002_0000;
        const ROOT: u64 = 0x0510_0000;

        // The first 8 MiB of input precede the two adjacent bad eraseblocks.
        assert_eq!(
            map_mtdutils_nandwrite_input_byte(
                ROOT,
                0x007F_FFFF,
                ERASE,
                S19K_78_MTD5_LEN,
                &S19K_78_HELD_MTD5_BAD_ERASEBLOCKS,
            ),
            Ok(0x058F_FFFF)
        );
        // nandwrite skips both 128-KiB blocks before consuming the next byte.
        assert_eq!(
            map_mtdutils_nandwrite_input_byte(
                ROOT,
                0x0080_0000,
                ERASE,
                S19K_78_MTD5_LEN,
                &S19K_78_HELD_MTD5_BAD_ERASEBLOCKS,
            ),
            Ok(0x0594_0000)
        );
        // A full 40-MiB logical root payload therefore occupies through
        // local 0x0793_FFFF on this captured topology, not 0x078F_FFFF.
        assert_eq!(
            map_mtdutils_nandwrite_input_byte(
                ROOT,
                S19K_INSTALL_ROOTFS_WINDOW - 1,
                ERASE,
                S19K_78_MTD5_LEN,
                &S19K_78_HELD_MTD5_BAD_ERASEBLOCKS,
            ),
            Ok(0x0793_FFFF)
        );
        assert!(refuse_s19k_linux_badblock_map_as_uboot_read_authority().is_err());

        assert!(map_mtdutils_nandwrite_input_byte(ROOT + 1, 0, ERASE, 0x1000_0000, &[]).is_err());
        assert!(map_mtdutils_nandwrite_input_byte(
            ROOT,
            0,
            ERASE,
            0x1000_0000,
            &[0x0592_0000, 0x0590_0000],
        )
        .is_err());
    }

    fn crc_env_blob(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (k, v) in pairs {
            body.extend_from_slice(k.as_bytes());
            body.push(b'=');
            body.extend_from_slice(v.as_bytes());
            body.push(0);
        }
        body.resize(crate::s19k_nand_env::S19K_NAND_ENV_LEN - 4, 0);
        let crc = crate::s19k_nand_env::crc32_iso_hdlc(&body);
        let mut blob = Vec::with_capacity(crate::s19k_nand_env::S19K_NAND_ENV_LEN);
        blob.extend_from_slice(&crc.to_le_bytes());
        blob.extend_from_slice(&body);
        blob
    }

    #[test]
    fn wave225_backup_artifact_dir_crc_and_recover_plan() {
        assert!(!CLEAR_FOR_FLASH);
        assert!(admit_s19k_backup_requires_nandrecovery_sidecar(&[
            "nand_env.bak",
            "mtd5_pre_install.bin",
            "gpio437.value",
        ])
        .is_err());
        assert!(admit_s19k_backup_requires_nandrecovery_sidecar(&[
            "nand_env.bak",
            "mtd5_pre_install.bin",
            "gpio437.value",
            S19K_BACKUP_NANDRECOVERY_ENV_NAME,
        ])
        .is_ok());
        assert!(refuse_s19k_backup_without_nandrecovery_sidecar().is_err());
        let env = crc_env_blob(&[("bootcmd", "run recover_to_stock")]);
        let local = S19K_78_NANDRECOVERY_ENV_LOCAL as usize;
        let mut mtd5 = vec![0u8; local + env.len()];
        mtd5[local..local + env.len()].copy_from_slice(&env);
        let names = [
            "nand_env.bak",
            "mtd5_pre_install.bin",
            "gpio437.value",
            S19K_BACKUP_NANDRECOVERY_ENV_NAME,
        ];
        let admitted =
            admit_s19k_backup_artifact_dir(&names, &env, &env, &mtd5, S19K_78_MTD5_BASE).unwrap();
        assert!(admitted.nand_env_crc_ok);
        assert!(admitted.nandrecovery_env_crc_ok);
        assert!(admitted.recovery_flag_byte.is_none());
        assert!(admitted.recover_plan.contains("intent=UbootStockRevert"));
        assert!(admitted
            .recover_plan
            .contains("recover_env_source=nandrecovery_env.bin"));
        assert!(admitted.recover_plan.contains("clear_for_flash=false"));
        assert!(
            admit_s19k_recover_execute_refuse_names_78_nand_src(&admitted.recover_refuse).is_ok()
        );
        let mut other = crc_env_blob(&[("bootcmd", "other")]);
        assert!(
            admit_s19k_backup_artifact_dir(&names, &env, &other, &mtd5, S19K_78_MTD5_BASE,)
                .is_err()
        );
        other[4] ^= 0xFF;
        assert!(
            admit_s19k_backup_artifact_dir(&names, &other, &env, &mtd5, S19K_78_MTD5_BASE,)
                .is_err()
        );
        assert!(admit_s19k_backup_artifact_dir(
            &["nand_env.bak", "mtd5_pre_install.bin", "gpio437.value"],
            &env,
            &env,
            &mtd5,
            S19K_78_MTD5_BASE,
        )
        .is_err());
        assert!(admit_s19k_restore_sidecar_crc(S19K_BACKUP_NANDRECOVERY_ENV_NAME, &env).is_ok());
        assert!(admit_s19k_restore_sidecar_crc("nand_env.bak", &env).is_err());
        assert!(admit_s19k_restore_sidecar_crc("nand_env.bin", &env).is_err());
        let mut corrupt = env.clone();
        corrupt[4] ^= 0xFF;
        assert!(
            admit_s19k_restore_sidecar_crc(S19K_BACKUP_NANDRECOVERY_ENV_NAME, &corrupt).is_err()
        );
        let crc_plan =
            format_s19k_restore_crc_admit(S19K_BACKUP_NANDRECOVERY_ENV_NAME, true, true).unwrap();
        assert!(crc_plan.contains("schema=dcentos.amlogic-restore-crc/v1"));
        assert!(crc_plan.contains("recover_env_source=nandrecovery_env.bin"));
        assert!(crc_plan.contains("nandrecovery_env_crc_ok=true"));
        assert!(crc_plan.contains("nand_env_crc_ok=true"));
        assert!(format_s19k_restore_crc_admit("nand_env.bak", true, true).is_err());
        assert!(
            format_s19k_restore_crc_admit(S19K_BACKUP_NANDRECOVERY_ENV_NAME, false, true).is_err()
        );
        assert!(admit_s19k_restore_script_crc_admits_sidecar(RESTORE).is_ok());
        assert!(admit_s19k_restore_script_sidecar_matches_mtd5_slice(RESTORE).is_ok());
        assert!(admit_s19k_restore_script_sidecar_sha256(RESTORE).is_ok());
        assert!(RESTORE.contains("dcent_am3_extract_nandrecovery_env"));
        assert!(RESTORE.contains("nandrecovery_env.bin does not match mtd5 slice"));
        assert!(RESTORE.contains("nandrecovery_env_matches_mtd5_slice=true"));
        assert!(
            RESTORE.find("dcent_am3_extract_nandrecovery_env").unwrap()
                < RESTORE.find("VERIFY_OK hashes match ledger").unwrap()
        );
        assert!(admit_s19k_restore_script_sidecar_matches_mtd5_slice(
            "s19k_nand_env_crc.py\nnandrecovery_env.bin CRC32 mismatch\ncannot CRC-admit nandrecovery_env.bin\nnandrecovery_env_crc_ok=\nrecover_env_source=nandrecovery_env.bin\n"
        )
        .is_err());
    }

    #[test]
    fn wave227_install_rootfs_window_only() {
        let plan =
            admit_s19k_install_rootfs_window_only(S19K_78_MTD5_BASE, S19K_78_MTD5_LEN).unwrap();
        assert_eq!(plan.rootfs_local, 0x0510_0000);
        assert_eq!(plan.rootfs_window, 0x0280_0000);
        assert_eq!(plan.nandrecovery_env_local, 0x0490_0000);
        assert_eq!(plan.recovery_flag_local, 0x04D0_0000);
        assert_eq!(plan.kernel_local, Some(0x0110_0000));
        assert!(
            plan.kernel_local.unwrap() + crate::s19k_nand_env::S19K_78_NANDKERNEL_LEN
                <= plan.rootfs_local
        );
        let text = format_s19k_install_payload_plan(&plan);
        assert!(text.contains("nandwrite_target=root"));
        assert!(text.contains("package_kernel_nandwrite=false"));
        assert!(text.contains("clear_for_flash=false"));
        assert!(refuse_s19k_package_kernel_as_rootfs_nandwrite().is_err());
        assert!(admit_s19k_install_rootfs_window_only(S19K_78_MTD5_BASE, 0x0510_0000).is_err());
        assert!(
            admit_s19k_install_rootfs_window_only(S19K_78_MTD5_SIZE_SUM, S19K_78_MTD5_LEN).is_err()
        );
        assert!(admit_s19k_install_script_nandwrites_root_only(INSTALL_SCRIPT).is_ok());
        assert!(INSTALL_SCRIPT
            .contains("nandwrite -p -s $ROOTFS_OFFSET_HEX $ROOTFS_MTD /proc/self/fd/3 || exit 1"));
        assert!(INSTALL_SCRIPT.contains("exec 3< '$REMOTE_PREFIX/root'"));
        assert!(INSTALL_SCRIPT.contains("sha256sum /proc/self/fd/3"));
        assert!(!INSTALL_SCRIPT
            .contains("nandwrite -p -s $ROOTFS_OFFSET_HEX $ROOTFS_MTD '$REMOTE_PREFIX/kernel'"));
        assert!(INSTALL_SCRIPT.contains("INSTALL_PAYLOAD_PLAN.txt"));
        assert!(INSTALL_SCRIPT.contains("package_kernel_nandwrite=false"));
    }

    #[test]
    fn geometry_matches_shared_am3_script() {
        assert!(GEOMETRY.contains("DCENT_AM3_ROOTFS_MTD"));
        assert!(GEOMETRY.contains("0x05100000"));
        assert!(GEOMETRY.contains("0x02800000"));
        assert!(GEOMETRY.contains("0x04D00000"));
        assert!(GEOMETRY.contains("0x600000"));
        assert!(GEOMETRY.contains("dcent_am3_mtd5_covers_recovery"));
        assert!(GEOMETRY.contains("DCENT_AM3_NANDRECOVERY_ENV_GLOBAL"));
        assert!(SYSTEM.contains("DCENTOS_OFFSET_FROM_END_MTD0_TO_MTD1=0x600000"));
        assert_eq!(ROOTFS_MTD, "/dev/mtd5");
        assert_eq!(ROOTFS_OFFSET_HEX, "0x05100000");
        assert_eq!(RECOVERY_FLAG_OFFSET_HEX, "0x04D00000");
        assert_eq!(NAND_ENV_DEV, "/dev/nand_env");
        assert_eq!(ROOTFS_ERASE_COUNT, 320);
        assert_eq!(ROOTFS_ERASESIZE, 131_072);
    }

    #[test]
    fn install_script_s19k_safeoff_must_be_one() {
        // Safety pin: default variant is s19kpro; driving 0 ENGAGES rails.
        assert!(INSTALL_SCRIPT.contains("Step 7b/10: GPIO437 PWR_EN SafeOff"));
        assert!(
            INSTALL_SCRIPT.contains("s19kpro")
                && (INSTALL_SCRIPT.contains("GPIO437_SAFE_OFF=1")
                    || INSTALL_SCRIPT.contains("SAFE_OFF=1")
                    || INSTALL_SCRIPT.contains("am3-s19k-active-low")),
            "install_amlogic_persistent.sh must SKU-scope S19k SafeOff=1"
        );
        let safe = INSTALL_SCRIPT
            .find("Step 7b/10: GPIO437 PWR_EN SafeOff")
            .unwrap();
        let refusal = INSTALL_SCRIPT
            .find("CLEAR_FOR_FLASH=false")
            .expect("immutable flash refusal");
        let flash = INSTALL_SCRIPT
            .find("    flash_erase $ROOTFS_MTD $ROOTFS_OFFSET_HEX $ROOTFS_ERASE_COUNT")
            .unwrap();
        assert!(
            refusal < safe,
            "flash refusal must precede the unreachable writer"
        );
        assert!(safe < flash);
        assert!(S37.contains("am3-s19k|am3-s19kpro|am3-aml-s19kpro)"));
        let recipe = crate::amlogic_gpio437::resolve_drive_recipe("am3-s19k").unwrap();
        assert_eq!((recipe.on_raw(), recipe.off_raw(), recipe.off_direction()), (0, 1, "high"));
        assert!(S37.contains("dcent_gpio437_drive_levels \"$BOARD_TARGET\""));
        assert!(S37.contains("PWR_OFF_VALUE=$2"));
        assert!(S37.contains("PWR_OFF_DIRECTION=$3"));
        assert!(S37.contains("set_gpio_value_checked \"$PWR_GPIO\" \"$PWR_OFF_VALUE\""));
        assert!(S37.contains("IDENTITY_ROOT/board_target"));
        assert!(S37.contains("GPIO437 refuse: missing or unsealed board_target="));
        assert!(S37.contains("printf 'commanded_value=%s\\n' \"$PWR_OFF_VALUE\""));
        assert!(S37.contains("receipt_field_is commanded_value \"$PWR_OFF_VALUE\""));
        assert!(
            HAL_AML.contains("amlogic_gpio437::resolve_boot_policy(fields[\"board_target\"])")
                && HAL_AML.contains("require(\"commanded_value\", &recipe.off_raw().to_string())?"),
            "HAL boot-safe parser must use the same exact table OFF value"
        );
        assert!(HAL_AML.contains("boot_safe_handoff_s19k_requires_commanded_value_1"));
        assert!(HAL_AML.contains("amlogic_handoff_identity_matches_profile"));
        let revert_safe = REVERT
            .find("gpio437 SafeOff")
            .expect("s19k revert must SafeOff before nandwrite");
        let revert_write = REVERT.find("nandwrite -p -s").expect("nandwrite");
        assert!(revert_safe < revert_write);
        assert!(REVERT.contains("am3-s19k-active-low"));
        assert!(REVERT.contains("echo 1 > \"$SYS/gpio$PWR_GPIO/value\""));
        assert!(
            REVERT.find("missing exact live platform:target identity")
                < REVERT.find("Type 'REVERT'"),
            "identity gate must run before the REVERT prompt"
        );
        assert!(REVERT.contains("am3-aml-s19k:am3-s19k"));
        assert!(REVERT.contains("tmp_deploy leftover"));
        assert!(REVERT.contains("0x05700000/0x05300000"));
        assert!(REVERT.contains("admitted local 0x05100000"));
        assert!(admit_s19k_stock_revert_live_board_target(None).is_err());
        assert!(admit_s19k_stock_revert_live_board_target(Some("am3-s21")).is_err());
        assert!(admit_s19k_stock_revert_live_board_target(Some("am3-s19k")).is_ok());
        assert!(admit_s19k_restore_ledger_identity("am3-s19kpro").is_ok());
        assert!(admit_s19k_restore_ledger_identity("am3-aml-s19kpro").is_ok());
        assert!(S19K_LIVE_IDENTITY_ALIASES.contains(&"am3-s19kpro"));
        assert!(refuse_s19k_stock_revert_tmp_deploy_stamp(true).is_err());
        assert!(refuse_s19k_stock_revert_tmp_deploy_stamp(false).is_ok());
        assert!(admit_s19k_stock_revert_rootfs_offset(0x0570_0000).is_err());
        assert!(admit_s19k_stock_revert_rootfs_offset(0x0530_0000).is_err());
        assert!(admit_s19k_stock_revert_rootfs_offset(0x0610_0000).is_err());
        assert_eq!(
            admit_s19k_stock_revert_rootfs_offset(0x0510_0000),
            Ok(0x0510_0000)
        );
        assert!(
            REVERT.find("IH_ARCH") < REVERT.find("Type 'REVERT'"),
            "uImage arch classify must run before the REVERT prompt"
        );
        assert!(REVERT.contains("stock revert requires expected SHA-256"));
        assert!(REVERT.contains("ANDROID! boot.img"));
        assert!(REVERT.contains("not ARM64 (16)"));
        assert!(admit_s19k_stock_revert_sha256_required("").is_err());
        assert!(admit_s19k_stock_revert_sha256_required("ab").is_err());
        let sha_ok = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(admit_s19k_stock_revert_sha256_required(sha_ok).is_ok());
        let mut arm64 = [0u8; 80];
        arm64[0..4].copy_from_slice(&UIMAGE_MAGIC);
        arm64[12..16].copy_from_slice(&16u32.to_be_bytes());
        arm64[29] = UIMAGE_ARCH_ARM64;
        assert!(admit_s19k_stock_revert_uimage(&arm64, 80).is_ok());
        assert!(admit_s19k_stock_revert_uimage(&arm64, 81).is_err());
        let mut arm32 = arm64;
        arm32[29] = UIMAGE_ARCH_ARM;
        arm32[32..39].copy_from_slice(b"xilinx!");
        assert!(admit_s19k_stock_revert_uimage(&arm32, 80).is_err());
        let mut android = [0u8; 80];
        android[..8].copy_from_slice(S19K_ANDROID_BOOT_MAGIC);
        assert!(admit_s19k_stock_revert_uimage(&android, 80).is_err());
        assert!(admit_s19k_stock_revert_uimage(&arm64, S19K_REVERT_UIMAGE_MAX_BYTES + 1).is_err());
        assert!(!S19K_RESTORE_MTD5_USES_WINDOW_OFFSET);
        assert!(refuse_s19k_restore_mtd5_at_rootfs_window_offset(true).is_err());
        assert!(refuse_s19k_restore_mtd5_at_rootfs_window_offset(false).is_ok());
        let a = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let b = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        assert!(admit_s19k_restore_file_hashes(a, b, a, b).is_ok());
        assert_eq!(
            admit_s19k_restore_file_hashes(a, b, a, a),
            Err(S19kRestoreError::HashMismatch)
        );
        let restore_tools = S19kTargetTools {
            dd: true,
            sha256sum: true,
            nanddump: true,
            nandwrite: true,
            flash_erase: true,
            fw_printenv: false,
            fw_setenv: false,
        };
        assert!(admit_s19k_restore_nandwrite_preflight(restore_tools).is_ok());
        assert_eq!(
            admit_s19k_stock_image_revert(restore_tools, 5, Some("am3-s19k"), false, 0x0510_0000),
            Err(S19kRestoreError::EnvToolsMissing)
        );
        assert_eq!(
            admit_s19k_stock_image_revert(restore_tools, 5, None, false, 0x0510_0000,),
            Err(S19kRestoreError::MissingLiveBoardTarget)
        );
        assert_eq!(
            admit_s19k_stock_image_revert(restore_tools, 5, Some("am3-s19k"), true, 0x0510_0000,),
            Err(S19kRestoreError::TmpDeployStamp)
        );
        assert_eq!(
            admit_s19k_stock_image_revert(restore_tools, 5, Some("am3-s19k"), false, 0x0570_0000,),
            Err(S19kRestoreError::WindowOffsetForbidden)
        );
        let revert_ok_tools = S19kTargetTools {
            dd: true,
            sha256sum: true,
            nanddump: true,
            nandwrite: true,
            flash_erase: true,
            fw_printenv: true,
            fw_setenv: true,
        };
        assert_eq!(
            admit_s19k_stock_image_revert(revert_ok_tools, 5, Some("am3-s19k"), false, 0x0510_0000,),
            Ok(S19kRestoreKind::StockImageThenEnvFlip)
        );
        let complete = S19kBackupCompleteness {
            nand_env: true,
            mtd5_window: true,
            gpio437: true,
            fw_printenv: false,
        };
        assert_eq!(
            admit_s19k_restore_preinstall_window(
                restore_tools,
                complete,
                true,
                5,
                1,
                S19kStockReturnKind::Mtd2StockSystem,
                false,
            ),
            Ok(S19kRestoreKind::PreInstallMtd5Nanddump)
        );
        assert_eq!(
            admit_s19k_restore_preinstall_window(
                restore_tools,
                complete,
                true,
                5,
                0,
                S19kStockReturnKind::Mtd2StockSystem,
                false,
            ),
            Err(S19kRestoreError::WrongSafeOffPolarity)
        );
        assert_eq!(
            admit_s19k_restore_preinstall_window(
                restore_tools,
                complete,
                true,
                0,
                1,
                S19kStockReturnKind::Mtd2StockSystem,
                false,
            ),
            Err(S19kRestoreError::BootloaderForbidden)
        );
        assert_eq!(
            admit_s19k_restore_preinstall_window(
                restore_tools,
                complete,
                true,
                5,
                1,
                S19kStockReturnKind::Mtd2StockSystem,
                true,
            ),
            Err(S19kRestoreError::WindowOffsetForbidden)
        );
        assert!(CLEAR_FOR_FLASH == false);
        assert_eq!(
            admit_s19k_restore_execute(
                restore_tools,
                complete,
                true,
                5,
                1,
                S19kStockReturnKind::Mtd2StockSystem,
                false,
            ),
            Err(S19kRestoreError::ClearForFlashNotYet)
        );
        assert!(admit_s19k_restore_script_execute_refuses_nandwrite(RESTORE).is_ok());
        assert!(admit_s19k_restore_script_execute_requires_proc_mtd(RESTORE).is_ok());
        assert!(admit_s19k_restore_script_private_readback(RESTORE).is_ok());
        let fixed_restore_readback = RESTORE.replace(
            "\"$RESTORE_TMP/mtd5_restore_readback.bin\"",
            "/tmp/mtd5_restore_readback.bin",
        );
        assert!(admit_s19k_restore_script_private_readback(&fixed_restore_readback).is_err());
        assert!(admit_s19k_restore_execute_live_proc_mtd(None).is_err());
        assert!(admit_s19k_restore_execute_live_proc_mtd(Some("")).is_err());
        assert!(admit_s19k_restore_execute_live_proc_mtd(Some(
            "dev: size erasesize name\nmtd0: 00200000 00020000 \"bootloader\"\nmtd1: 00800000 00020000 \"tpl\"\nmtd2: 03200000 00020000 \"stock_system\"\nmtd3: 00500000 00020000 \"stock_config\"\nmtd4: 02000000 00020000 \"overlay\"\nmtd5: 09900000 00020000 \"system\"\n"
        ))
        .is_ok());
        let plan = format_s19k_restore_plan(S19kRestoreKind::PreInstallMtd5Nanddump, 5, false);
        assert!(plan.contains("clear_for_flash=false"));
        assert!(plan.contains("env_flip=false"));
        assert!(plan.contains("restore_nand_env=false"));
        assert!(plan.contains("nand_env_bak_is_not_nandrecovery_env=true"));
        assert!(RESTORE.contains("nand_env_bak_is_not_nandrecovery_env=true"));
        assert!(RESTORE.contains("nandrecovery_env_local=0x04900000"));
        assert!(RESTORE.contains("nandrecovery_env=nandrecovery_env.bin"));
        assert!(RESTORE.contains("nand_env.bak is not recover_env"));
        assert!(RESTORE.contains("s19k_nand_env_crc.py"));
        assert!(RESTORE.contains("nandrecovery_env.bin CRC32 mismatch"));
        assert!(RESTORE.contains("nandrecovery_env_crc_ok=true"));
        assert!(RESTORE.contains("recover_env_source=nandrecovery_env.bin"));
        assert!(!RESTORE.contains("recover_env_source=nand_env.bak"));
        assert!(RESTORE.contains("nandwrite -p \"$ROOTFS_MTD\""));
        assert!(!RESTORE.contains("nandwrite -p -s"));
        assert!(RESTORE.contains("current 0x05100000"));
        assert!(RESTORE.contains("stale 0x05700000 is size-sum geometry"));
        assert!(RESTORE.contains("refuse window-offset"));
        let restore_safe = RESTORE.find("gpio437 SafeOff").expect("restore SafeOff");
        let restore_write = RESTORE
            .find("nandwrite -p \"$ROOTFS_MTD\"")
            .expect("restore write");
        assert!(restore_safe < restore_write);
        assert!(RESTORE.contains("fw_setenv not required"));
        assert!(RESTORE.contains("clear_for_flash=false"));
        assert!(RESTORE.contains("--verify-only"));
        assert!(RESTORE.contains("dcent_am3_require_exact_s19k_mtd_map_file \"$PROC_TMP\""));
        assert!(RESTORE.contains("dcent_am3_require_exact_s19k_mtd_map_file /proc/mtd"));
        assert!(RESTORE.contains("backup ledger geometry is not exact S19k .78"));
        assert!(RESTORE.contains("live geometry is not exact S19k .78; refuse restore"));
        assert!(!RESTORE.contains("7-part map blocked"));
        assert!(RESTORE.contains("admit ledger board_target="));
        assert!(RESTORE.contains("refuse geometry-blind restore"));
        assert!(RESTORE.contains("covers_recovery=true"));
        assert!(RESTORE.contains("dcent_am3_mtd5_covers_recovery"));
        assert!(INSTALL_SCRIPT.contains("refuse geometry-blind backup"));
        assert!(INSTALL_SCRIPT.contains("board_target_source=$BOARD_TARGET_SOURCE"));
        assert!(INSTALL_SCRIPT.contains("record_s19k_backup_board_target"));
        assert!(!INSTALL_SCRIPT.contains("|| echo $BOARD_PKG_NAME"));
        assert!(
            RESTORE.contains("identity proof variant '$IDENTITY_PROOF_VARIANT' is not exact S19k")
        );
        assert!(RESTORE.contains(
            "package-sourced backup must not relabel a package target as a live board_target"
        ));
        assert!(RESTORE.contains("exact tuple proof independently re-admitted"));
        assert!(RESTORE.contains("board_target_source=package"));
        assert_eq!(
            admit_s19k_restore_nand_layout(&[
                "bootloader",
                "tpl",
                "stock_system",
                "stock_config",
                "overlay",
                "system"
            ]),
            Ok(S19kStockReturnKind::Mtd2StockSystem)
        );
        assert_eq!(S19K_NAND_MAP[3].name, "stock_config");
        assert_eq!(crate::s19k_nand_env::S19K_78_NANDROOTFS, NANDROOTFS_GLOBAL);
        assert_eq!(
            crate::s19k_nand_env::S19K_78_NANDRECOVERY_FLAG,
            RECOVERY_FLAG_GLOBAL
        );
        assert_eq!(
            crate::s19k_nand_env::S19K_78_RECOVERY_FLAG_FIRST_BOOT,
            RECOVERY_FLAG_FIRST_BOOT
        );
        assert!(crate::s19k_nand_env::refuse_s19k_78_mtd3_as_reserved("reserved").is_err());
        let mut ui = [0u8; 64];
        ui[0..4].copy_from_slice(&UIMAGE_MAGIC);
        ui[12..16].copy_from_slice(&HELD_S19PRO_UIMAGE_IH_SIZE.to_be_bytes());
        ui[29] = UIMAGE_ARCH_ARM;
        ui[32..32 + HELD_S19PRO_UIMAGE_NAME.len()]
            .copy_from_slice(HELD_S19PRO_UIMAGE_NAME.as_bytes());
        let hdr = parse_s19k_uimage_header(&ui).unwrap();
        assert_eq!(hdr.ih_arch, UIMAGE_ARCH_ARM);
        assert!(hdr.ih_name.contains("xilinx"));
        assert!(refuse_xilinx_arm32_uimage_as_s19k_aml(&hdr).is_err());
        let mut arm64 = ui;
        arm64[29] = UIMAGE_ARCH_ARM64;
        arm64[32..64].fill(0);
        arm64[32..40].copy_from_slice(b"linux-a6");
        assert!(
            refuse_xilinx_arm32_uimage_as_s19k_aml(&parse_s19k_uimage_header(&arm64).unwrap())
                .is_ok()
        );
        assert_eq!(
            admit_s19k_restore_nand_layout(&["a", "b", "c", "d", "e", "f", "g"]),
            Err(S19kRestoreError::Stock7LayoutBlocked)
        );
        assert_eq!(
            recovery_flag_local_offset(S19K_78_MTD5_BASE),
            Some(0x04D0_0000)
        );
        assert_eq!(recovery_flag_local_offset(0x0670_0000), Some(0x04D0_0000));
        assert_eq!(
            admit_s19k_recovery_flag_offset(S19K_78_MTD5_BASE, 0x04D0_0000),
            Ok(0x04D0_0000)
        );
        assert_eq!(
            admit_s19k_recovery_flag_offset(S19K_78_MTD5_BASE, 0x0530_0000),
            Err(S19kRestoreError::RecoveryFlagOffsetMismatch)
        );
        assert_eq!(
            admit_s19k_recovery_flag_offset(S19K_78_MTD5_SIZE_SUM, 0x0530_0000),
            Err(S19kRestoreError::RecoveryFlagOffsetMismatch)
        );
        assert_eq!(
            admit_s19k_recovery_flag_write(
                RECOVERY_FLAG_FIRST_BOOT,
                S19K_78_MTD5_BASE,
                0x04D0_0000,
                5,
            ),
            Ok(S19kRecoveryFlagIntent::UbootStockRevert)
        );
        assert_eq!(
            admit_s19k_recovery_flag_write(
                RECOVERY_FLAG_SUCCESSFUL,
                S19K_78_MTD5_BASE,
                0x04D0_0000,
                5,
            ),
            Err(S19kRestoreError::ClearForFlashNotYet)
        );
        assert_eq!(
            admit_s19k_recovery_flag_write(
                RECOVERY_FLAG_FIRST_BOOT,
                S19K_78_MTD5_BASE,
                0x04D0_0000,
                0,
            ),
            Err(S19kRestoreError::BootloaderForbidden)
        );
        let plan = format_s19k_recovery_flag_write_plan(
            RECOVERY_FLAG_FIRST_BOOT,
            S19K_78_MTD5_BASE,
            0x04D0_0000,
            5,
        )
        .unwrap();
        assert!(plan.contains("intent=UbootStockRevert"));
        assert!(plan.contains("value=0x02"));
        assert!(plan.contains("clear_for_flash=false"));
        assert!(plan.contains("eraseblock_start=0x04D00000"));
        assert!(plan.contains("byte_in_block=0x0"));
        assert!(plan.contains("rewriter=eraseblock_rewrite"));
        assert!(refuse_s19k_recovery_flag_one_byte_after_erase().is_err());
        let eb = plan_s19k_recovery_flag_eraseblock(0x04D0_0000).unwrap();
        assert_eq!(eb.eraseblock_index, 616);
        assert_eq!(eb.eraseblock_start, 0x04D0_0000);
        assert_eq!(eb.byte_in_block, 0);
        assert!(refuse_s19k_recovery_flag_raw_byte_poke().is_err());
        let mut blk = vec![0u8; ROOTFS_ERASESIZE as usize];
        blk[0] = 0x00;
        let rewritten =
            rewrite_s19k_recovery_flag_eraseblock(&blk, 0, RECOVERY_FLAG_FIRST_BOOT).unwrap();
        assert_eq!(rewritten.len(), ROOTFS_ERASESIZE as usize);
        assert_eq!(rewritten[0], 0x02);
        assert!(rewritten[1..].iter().all(|&b| b == 0));
        let rewritten01 =
            rewrite_s19k_recovery_flag_eraseblock(&blk, 0, RECOVERY_FLAG_INSTALLED).unwrap();
        assert_eq!(rewritten01[0], 0x01);
        assert!(rewrite_s19k_recovery_flag_eraseblock(&[0u8; 16], 0, 0x02).is_err());
        assert!(
            format_s19k_recovery_flag_write_plan(0x01, S19K_78_MTD5_BASE, 0x04D0_0000, 5).is_err()
        );
        assert_eq!(
            classify_s19k_recovery_flag_intent(RECOVERY_FLAG_INSTALLED),
            Ok(S19kRecoveryFlagIntent::InstallArm)
        );
        assert_eq!(
            crate::s19k_nand_env::classify_s19k_uboot_flag_action(RECOVERY_FLAG_INSTALLED),
            crate::s19k_nand_env::S19kUbootFlagAction::FirstBosThenSetFlag2
        );
        assert_eq!(
            admit_s19k_recovery_flag_write(
                RECOVERY_FLAG_INSTALLED,
                S19K_78_MTD5_BASE,
                0x04D0_0000,
                5,
            ),
            Err(S19kRestoreError::ClearForFlashNotYet)
        );
        let commit = format_s19k_install_commit_plan(S19K_78_MTD5_BASE, 0x04D0_0000, 5).unwrap();
        assert!(commit.contains("intent=InstallArm"));
        assert!(commit.contains("value=0x01"));
        assert!(commit.contains("rewriter=eraseblock_rewrite"));
        assert!(commit.contains("uboot_action=FirstBosThenSetFlag2"));
        assert!(commit.contains("firstboot=S99_WAL_companion_only"));
        assert!(commit.contains("bootcmd_reads_firstboot=false"));
        assert!(commit.contains("execute=CLEAR_FOR_FLASH"));
        assert!(commit.contains("clear_for_flash=false"));
        assert!(commit.contains("bootm_mtd2=false"));
        assert!(commit.contains("recover_to_stock=false"));
        assert!(commit.contains("nandwrite=false"));
        assert!(admit_s19k_install_commit_plan(&commit).is_ok());
        assert_eq!(
            classify_s19k_recovery_flag_intent(RECOVERY_FLAG_SUCCESSFUL),
            Ok(S19kRecoveryFlagIntent::SuccessfulKeepBos)
        );
        assert_eq!(
            crate::s19k_nand_env::classify_s19k_uboot_flag_action(RECOVERY_FLAG_SUCCESSFUL),
            crate::s19k_nand_env::S19kUbootFlagAction::BootBos
        );
        let keep = format_s19k_successful_flag_plan(S19K_78_MTD5_BASE, 0x04D0_0000, 5).unwrap();
        assert!(admit_s19k_successful_flag_plan(&keep).is_ok());
        assert!(keep.contains("schema=dcentos.amlogic-successful-flag/v1"));
        assert!(keep.contains("intent=SuccessfulKeepBos"));
        assert!(keep.contains("value=0x03"));
        assert!(keep.contains("uboot_action=BootBos"));
        assert!(keep.contains("promote_from=0x02"));
        assert!(keep.contains("bootm_mtd2=false"));
        assert!(keep.contains("recover_to_stock=false"));
        assert!(keep.contains("clear_for_flash=false"));
        assert!(keep.contains("nandwrite=false"));
        assert!(keep.contains("gpio_write=false"));
        let rewritten03 =
            rewrite_s19k_recovery_flag_eraseblock(&blk, 0, RECOVERY_FLAG_SUCCESSFUL).unwrap();
        assert_eq!(rewritten03[0], 0x03);
        assert!(format_s19k_successful_flag_plan(S19K_78_MTD5_BASE, 0x04D0_0000, 0).is_err());
        assert!(admit_s19k_s99_promotes_02_to_03(S99).is_ok());
        assert!(admit_s19k_s99_header_names_recover_to_stock(S99).is_ok());
        assert!(admit_s19k_s99_header_names_recover_to_stock(
            "U-Boot reverts to mtd2 stock_system"
        )
        .is_err());
        assert!(refuse_s19k_s99_leftover_02_as_mtd2_boot().is_err());
        assert!(admit_s19k_s99_promotes_02_to_03("flash_erase only").is_err());
        assert!(admit_s19k_s99_ota08_identity_and_readback(S99).is_ok());
        assert!(admit_s19k_s99_ota08_identity_and_readback(
            "printf '\\x3' expected 0x03 0x02 -> 0x03 0x05300000 flash_erase nandwrite -p -s"
        )
        .is_err());
        assert!(admit_s19k_s99_leftover_01_is_error(S99).is_ok());
        assert!(admit_s19k_s99_leftover_01_is_error(
            "            0x01)\n                echo \"  [WARN] recovery flag = 0x01\"\n                exit 0\n                ;;\n            ERR_*)\n"
        )
        .is_err());
        assert!(S99.contains("ERROR: recovery flag = 0x01 (INSTALLED) leftover in userspace"));
        assert!(!S99.contains("[WARN] recovery flag = 0x01"));
        assert!(admit_s19k_s99_unread_or_unexpected_flag_is_error(S99).is_ok());
        assert!(admit_s19k_s99_unread_or_unexpected_flag_is_error(
            "            ERR_*)\n                echo \"  [WARN] could not read recovery flag\"\n                exit 0\n                ;;\n            *)\n                echo \"  [WARN] unexpected recovery flag value:\"\n                exit 0\n                ;;\nesac\n"
        )
        .is_err());
        assert!(S99.contains("ERROR: could not read recovery flag ($FLAG); refuse OTA-08"));
        assert!(S99.contains("ERROR: unexpected recovery flag value: $FLAG; refuse OTA-08"));
        assert!(!S99.contains("[WARN] could not read recovery flag"));
        assert!(!S99.contains("[WARN] unexpected recovery flag value:"));
        assert!(S99_AMLOGIC_OTA08_IDENTITIES.contains(&"am3-aml-s19k:am3-s19k"));
        assert!(S99_AMLOGIC_OTA08_IDENTITIES.contains(&"am3-aml-s21:am3-s21"));
        assert!(!S99_AMLOGIC_OTA08_IDENTITIES.contains(&"am3-aml-s21xp:am3-s21xp"));
        assert!(!S99_AMLOGIC_OTA08_IDENTITIES.contains(&"am3-aml-t21:am3-t21"));
        for alias in S19K_LIVE_IDENTITY_ALIASES {
            assert!(
                !S99_AMLOGIC_OTA08_IDENTITIES.contains(alias),
                "bare S19k alias {alias} must not be OTA-08 mutation authority"
            );
        }
        assert!(refuse_s19k_flag_03_as_recover_to_stock().is_err());
        assert!(refuse_s19k_flag_03_as_mtd2_boot().is_err());
        assert!(refuse_s19k_successful_flag_as_fw_setenv_firstboot().is_err());
        assert!(refuse_s19k_successful_flag_execute().is_err());
        assert!(refuse_s19k_firstboot_only_as_install_commit().is_err());
        assert!(admit_s19k_install_script_refuses_firstboot_only_commit(INSTALL_SCRIPT).is_ok());
        assert!(admit_s19k_install_script_writes_install_commit_geometry(INSTALL_SCRIPT).is_ok());
        assert!(INSTALL_SCRIPT.contains("write_install_commit_plan()"));
        assert!(INSTALL_SCRIPT.contains("uboot_action=FirstBosThenSetFlag2"));
        assert!(INSTALL_SCRIPT.contains("eraseblock_index="));
        assert!(INSTALL_SCRIPT.contains("eraseblock_start="));
        assert!(INSTALL_SCRIPT.contains("byte_in_block="));
        assert!(INSTALL_SCRIPT.contains("write_install_commit_plan \"dry_run=true\""));
        assert!(admit_s19k_install_script_writes_recover_to_stock_plan(INSTALL_SCRIPT).is_ok());
        assert!(admit_s19k_install_script_runs_recover_dry_run(INSTALL_SCRIPT).is_ok());
        assert!(admit_s19k_geometry_extracts_flag_eraseblock(GEOMETRY).is_ok());
        assert!(admit_s19k_install_script_runs_flag_01_fixture(INSTALL_SCRIPT).is_ok());
        assert!(INSTALL_SCRIPT
            .contains("sh \"$FLAG_HELPER\" --value 0x01 --mtd5-base \"$COMPUTED_MTD5_BASE\""));
        assert!(INSTALL_SCRIPT.contains("recovery_flag_eb.bin"));
        assert!(INSTALL_SCRIPT.contains("recovery_flag_eb.0x01.bin"));
        assert!(INSTALL_SCRIPT.contains("INSTALL_COMMIT_WALK.txt"));
        assert!(INSTALL_SCRIPT.contains("fixture_value=0x01"));
        let flag_walk = INSTALL_SCRIPT
            .find("sh \"$FLAG_HELPER\" --value 0x01")
            .expect("0x01 fixture invoke");
        let backup_only = INSTALL_SCRIPT.find("[BACKUP-ONLY]").expect("backup-only");
        assert!(flag_walk < backup_only);
        assert!(!INSTALL_SCRIPT[flag_walk..backup_only].contains("--execute"));
        let mut mtd5 = vec![0u8; 0x04D0_0000 + ROOTFS_ERASESIZE as usize];
        mtd5[0x04D0_0000] = 0x00;
        let blk = extract_s19k_recovery_flag_eraseblock_from_mtd5_backup(&mtd5, S19K_78_MTD5_BASE)
            .expect("slice flag eraseblock");
        assert_eq!(blk.len(), ROOTFS_ERASESIZE as usize);
        assert_eq!(blk[0], 0x00);
        let rewritten =
            rewrite_s19k_recovery_flag_eraseblock(blk, 0, RECOVERY_FLAG_INSTALLED).unwrap();
        assert_eq!(rewritten[0], 0x01);
        assert_eq!(rewritten.len(), ROOTFS_ERASESIZE as usize);
        assert!(admit_s19k_walked_flag_01_fixture(&rewritten).is_ok());
        assert!(admit_s19k_walked_flag_01_fixture(blk).is_err());
        assert!(admit_s19k_walked_flag_01_fixture(&[0x01]).is_err());
        assert!(admit_s19k_install_script_admits_flag_01_bytes(INSTALL_SCRIPT).is_ok());
        assert!(INSTALL_SCRIPT.contains("0x01 fixture-out length"));
        assert!(INSTALL_SCRIPT.contains("(want 01)"));
        assert!(admit_s19k_install_script_admits_flag_01_bytes(
            "dcent_am3_extract_recovery_flag_eraseblock\ns19k_write_recovery_flag.sh\n--value 0x01\n--fixture-in\n--fixture-out\n--verify-only\nrecovery-flag 0x01 fixture walk failed; refusing successful backup\nINSTALL_COMMIT_WALK.txt\nfixture_value=0x01\nmtd5_pre_install.bin\nsh \"$FLAG_HELPER\" --value 0x01\n[BACKUP-ONLY]\n"
        )
        .is_err());
        assert!(INSTALL_SCRIPT
            .contains("sh \"$RECOVER_RUNNER\" --artifact-dir \"$ARTIFACT_DIR\" --dry-run"));
        assert!(INSTALL_SCRIPT
            .contains("recover-to-stock --dry-run failed; refusing successful backup"));
        assert!(INSTALL_SCRIPT.contains("RECOVER_WALK.txt"));
        assert!(refuse_s19k_firstboot_only_as_revert_commit().is_err());
        assert!(admit_s19k_revert_script_refuses_firstboot_only(REVERT).is_ok());
        assert!(admit_s19k_revert_script_private_transaction(REVERT).is_ok());
        let fixed_revert_extract = REVERT.replace(
            "${TMPDIR:-/tmp}/dcent-s19k-stock-revert.XXXXXX",
            "/tmp/stock_extract",
        );
        assert!(admit_s19k_revert_script_private_transaction(&fixed_revert_extract).is_err());
        let revert_plan = format_s19k_stock_image_revert_plan();
        assert!(admit_s19k_stock_image_revert_plan(&revert_plan).is_ok());
        assert!(revert_plan.contains("stock_return=recover_env_nandrecovery"));
        assert!(REVERT.contains("REVERT_COMMIT_PLAN"));
        assert!(REVERT.contains("refusing firstboot-only"));
        assert!(!REVERT.contains("\nfw_setenv firstboot 1\n"));
        assert!(admit_s19k_revert_script_dry_run_before_nandwrite(REVERT).is_ok());
        assert!(refuse_s19k_revert_nandwrite_without_recover_commit().is_err());
        assert!(admit_s19k_revert_script_execute_refuses_nandwrite(REVERT).is_ok());
        assert!(revert_plan.contains("nandwrite=false"));
        assert!(revert_plan.contains("gpio_write=false"));
        assert!(!INSTALL_SCRIPT.contains("Step 10/10: fw_setenv firstboot=1"));
        assert!(INSTALL_SCRIPT.contains("INSTALL_COMMIT_PLAN.txt"));
        assert!(INSTALL_SCRIPT.contains("recovery-flag 0x01"));
        assert!(INSTALL_SCRIPT.contains("S99 WAL"));
        assert!(INSTALL_SCRIPT.contains("s19k_nand_env_crc.py"));
        assert!(INSTALL_SCRIPT.contains("nandrecovery_env_crc_ok="));
        assert!(INSTALL_SCRIPT.contains("nand_env_crc_ok="));
        let mut rec_body = b"recover=1\0\0".to_vec();
        rec_body.resize(crate::s19k_nand_env::S19K_NAND_ENV_LEN - 4, 0);
        let rec_crc = crate::s19k_nand_env::crc32_iso_hdlc(&rec_body);
        let mut env_blob = Vec::with_capacity(crate::s19k_nand_env::S19K_NAND_ENV_LEN);
        env_blob.extend_from_slice(&rec_crc.to_le_bytes());
        env_blob.extend_from_slice(&rec_body);
        let rec_local = S19K_78_NANDRECOVERY_ENV_LOCAL as usize;
        let mut mtd5 = vec![0u8; rec_local + crate::s19k_nand_env::S19K_NAND_ENV_LEN];
        mtd5[rec_local..rec_local + env_blob.len()].copy_from_slice(&env_blob);
        let rec_env = admit_s19k_nandrecovery_env_slice(&env_blob).unwrap();
        let rec = format_s19k_recover_to_stock_plan(
            S19K_78_MTD5_BASE,
            S19K_BACKUP_NANDRECOVERY_ENV_NAME,
            &rec_env,
        )
        .unwrap();
        assert!(rec.contains("intent=UbootStockRevert"));
        assert!(rec.contains("flag_value=0x02"));
        assert!(rec.contains("recover_env_source=nandrecovery_env.bin"));
        assert!(rec.contains("step0=ImportNandrecoveryEnv"));
        assert!(rec.contains("step1=EraseNvdata"));
        assert!(rec.contains("step2=Reset"));
        assert!(rec.contains("nand_erase_part=nvdata"));
        assert!(rec.contains("bootm_mtd2=false"));
        assert!(!rec.contains("bootm "));
        assert!(rec.contains("clear_for_flash=false"));
        assert!(
            format_s19k_recover_to_stock_plan(S19K_78_MTD5_BASE, "nand_env.bak", &rec_env).is_err()
        );
        let rec2 =
            plan_s19k_recover_to_stock(&mtd5, S19K_78_MTD5_BASE, S19K_BACKUP_NANDRECOVERY_ENV_NAME)
                .unwrap();
        assert!(rec2.contains("env_crc_ok=true"));
        assert_eq!(
            S19K_RECOVER_TO_STOCK_STEPS[1],
            S19kRecoverToStockStep::EraseNvdata
        );
        let geo = format_s19k_backup_geometry_lines(
            "mtd5: 09900000 \"system\"",
            Some(S19K_78_MTD5_BASE),
            Some(0x04D0_0000),
            Some(0x0510_0000),
        );
        assert!(geo.contains("mtd5_base=0x06700000"));
        assert!(geo.contains("recovery_flag_local=0x04D00000"));
        assert!(geo.contains("rootfs_local=0x05100000"));
        assert!(INSTALL_SCRIPT.contains("proc_mtd="));
        assert!(INSTALL_SCRIPT.contains("recovery_flag_local="));
        assert!(INSTALL_SCRIPT.contains("dcent_am3_mtd5_base_from_proc_mtd"));
        assert!(INSTALL_SCRIPT.contains("computed_mtd5_base="));
        assert!(GEOMETRY.contains("dcent_am3_mtd5_base_from_proc_mtd"));
        const FLAG_SH: &str = include_str!("../../../scripts/s19k_write_recovery_flag.sh");
        assert!(FLAG_SH.contains("schema=dcentos.amlogic-successful-flag/v1"));
        assert!(FLAG_SH.contains("SUCCESSFUL_FLAG_PLAN"));
        assert!(FLAG_SH.contains("recover_env_source=nandrecovery_env.bin"));
        assert!(FLAG_SH.contains("nand_erase_part=nvdata"));
        assert!(FLAG_SH.contains("bootm_mtd2=false"));
        assert!(FLAG_SH.contains("recover_execute=refused"));
        assert!(FLAG_SH.contains("pass=admit_s19k_recover_execute_returns_ClearForFlashNotYet"));
        let tools_ok = S19kTargetTools {
            dd: true,
            sha256sum: true,
            nanddump: true,
            nandwrite: true,
            flash_erase: true,
            fw_printenv: true,
            fw_setenv: true,
        };
        assert_eq!(
            admit_s19k_recover_execute("nandrecovery_env.bin", true, 0x02, tools_ok),
            Err(S19kRecoverExecuteError::ClearForFlashNotYet)
        );
        assert_eq!(
            admit_s19k_recover_execute("nand_env.bak", true, 0x02, tools_ok),
            Err(S19kRecoverExecuteError::BadEnvSource)
        );
        assert_eq!(
            admit_s19k_recover_execute("nandrecovery_env.bin", false, 0x02, tools_ok),
            Err(S19kRecoverExecuteError::EnvCrcBad)
        );
        assert_eq!(
            admit_s19k_recover_execute("nandrecovery_env.bin", true, 0x01, tools_ok),
            Err(S19kRecoverExecuteError::FlagNotRecover)
        );
        let tools_bad = S19kTargetTools {
            nandwrite: false,
            fw_setenv: false,
            ..tools_ok
        };
        assert_eq!(
            admit_s19k_recover_execute("nandrecovery_env.bin", true, 0x02, tools_bad),
            Err(S19kRecoverExecuteError::ToolsMissing)
        );
        let exec_ledger =
            format_s19k_recover_execute_refuse(S19K_78_MTD5_BASE, "nandrecovery_env.bin");
        assert!(exec_ledger.contains("execute=refused"));
        assert!(exec_ledger.contains("reason=CLEAR_FOR_FLASH"));
        assert!(exec_ledger.contains("nand_erase_part=nvdata"));
        assert!(exec_ledger.contains("bootm_mtd2=false"));
        assert!(exec_ledger.contains("fail=nand_erase_or_env_import_without_admit"));
        assert!(admit_s19k_recover_execute_refuse_names_78_ram(&exec_ledger).is_ok());
        assert!(admit_s19k_recover_execute_refuse_names_78_nand_src(&exec_ledger).is_ok());
        let walk =
            format_s19k_recover_walk_ledger(S19K_78_MTD5_BASE, S19K_BACKUP_NANDRECOVERY_ENV_NAME)
                .unwrap();
        assert!(admit_s19k_recover_walk_ledger(&walk).is_ok());
        assert!(walk.contains("schema=dcentos.amlogic-recover-walk/v1"));
        assert!(walk.contains("dry_step0="));
        assert!(walk.contains(S19K_RECOVER_DRY_STEP0));
        assert_eq!(S19K_RECOVER_DRY_STEP1, "nand erase.part nvdata");
        assert_eq!(S19K_RECOVER_DRY_STEP2, "reset");
        assert!(format_s19k_recover_walk_ledger(S19K_78_MTD5_BASE, "nand_env.bak").is_err());
        assert!(admit_s19k_recover_script_dry_run_walks_plan(RECOVER).is_ok());
        assert!(admit_s19k_recover_script_execute_refuses_nandwrite(RECOVER).is_ok());
        assert!(RECOVER.contains("nandwrite=false"));
        assert!(RECOVER.contains("gpio_write=false"));
        assert!(RECOVER.contains("fw_setenv=false"));
        assert!(RECOVER.contains("env_import=false"));
        assert!(RECOVER.contains("DCENT_S19K_RECOVER_EXECUTE"));
        assert!(INSTALL_SCRIPT.contains("recover_amlogic_to_stock.sh"));
        let fixture = crate::s19k_nand_env::construct_s19k_nandrecovery_env_fixture();
        let rec_env = admit_s19k_nandrecovery_env_slice(&fixture).unwrap();
        let rec_plan = format_s19k_recover_to_stock_plan(
            S19K_78_MTD5_BASE,
            S19K_BACKUP_NANDRECOVERY_ENV_NAME,
            &rec_env,
        )
        .unwrap();
        let walked = walk_s19k_recover_to_stock_artifact(
            &rec_plan,
            S19K_BACKUP_NANDRECOVERY_ENV_NAME,
            &fixture,
        )
        .unwrap();
        assert!(admit_s19k_recover_walk_ledger(&walked).is_ok());
        assert!(walk_s19k_recover_to_stock_artifact(&rec_plan, "nand_env.bak", &fixture).is_err());
        let mut bad = rec_plan.clone();
        bad = bad.replace(
            "recover_env_source=nandrecovery_env.bin",
            "recover_env_source=nand_env.bak",
        );
        assert!(walk_s19k_recover_to_stock_artifact(
            &bad,
            S19K_BACKUP_NANDRECOVERY_ENV_NAME,
            &fixture
        )
        .is_err());
        let mut corrupt = fixture;
        corrupt[4] ^= 0xFF;
        assert!(walk_s19k_recover_to_stock_artifact(
            &rec_plan,
            S19K_BACKUP_NANDRECOVERY_ENV_NAME,
            &corrupt
        )
        .is_err());
        assert!(admit_s19k_recover_execute_refuse_names_78_ram(&exec_ledger).is_ok());
        assert!(exec_ledger.contains("recover_env_ram=0x01060000"));
        assert!(exec_ledger.contains("env_import_size=0x10000"));
        assert!(exec_ledger.contains("nandrecovery_env_offset=0x0B000000"));
        assert!(exec_ledger.contains("env_size=0x10000"));
        assert!(FLAG_SH.contains("intent=UbootStockRevert"));
        assert!(FLAG_SH.contains("FLASH NOT_YET"));
        assert!(FLAG_SH.contains("DCENT_S19K_RECOVERY_FLAG_EXECUTE"));
        assert!(FLAG_SH.contains("eraseblock_start="));
        assert!(FLAG_SH.contains("--proc-mtd"));
        assert!(FLAG_SH.contains("dcent_am3_mtd5_base_from_proc_mtd"));
        assert!(FLAG_SH.contains("rewriter=eraseblock_rewrite"));
        assert!(FLAG_SH.contains("--fixture-in"));
        assert!(!FLAG_SH.contains("byte_in_block must be 0"));
        assert!(FLAG_SH.contains("EB_OFF=$((LOCAL_DEC % ERASESIZE))"));
        assert!(FLAG_SH.contains("seek=\"$EB_OFF\""));
        assert!(FLAG_SH.contains("candidate_required=full-0x20000-byte-eraseblock"));
        assert!(FLAG_SH.contains("candidate_source=host-fixture-only"));
        assert!(FLAG_SH.contains("write_command=false"));
        assert!(FLAG_SH.contains("readback_required=full-0x20000-byte-sha256-and-byte-compare"));
        assert!(!FLAG_SH.contains("dry_flash_erase="));
        assert!(!FLAG_SH.contains("dry_nandwrite="));
        assert!(!FLAG_SH.contains("| nandwrite"));
        assert!(admit_s19k_recovery_flag_script_execute_refuses_nandwrite(FLAG_SH).is_ok());
        assert!(admit_s19k_recovery_flag_script_plans_install_arm(FLAG_SH).is_ok());
        assert!(admit_s19k_recovery_flag_script_plans_successful_keep_bos(FLAG_SH).is_ok());
        assert!(admit_s19k_recovery_flag_script_shares_fixture_rewrite(FLAG_SH).is_ok());
        assert!(FLAG_SH.contains("rewrite_recovery_flag_fixture()"));
        assert!(FLAG_SH.contains("printf '\\003'"));
        assert!(FLAG_SH.contains("fixture_value=0x03"));
        assert!(FLAG_SH.contains("SuccessfulKeepBos plan/fixture only"));
        assert!(FLAG_SH.contains("schema=dcentos.amlogic-install-commit/v1"));
        assert!(FLAG_SH.contains("intent=InstallArm"));
        assert!(FLAG_SH.contains("uboot_action=FirstBosThenSetFlag2"));
        assert!(FLAG_SH.contains("printf '\\001'"));
        assert!(FLAG_SH.contains("recovery flag 0x01 execute is FLASH NOT_YET"));
        assert!(
            !FLAG_SH.contains("recovery flag 0x01 is FLASH NOT_YET here (use INSTALL_COMMIT_PLAN)")
        );
        assert!(FLAG_SH.contains("nandwrite=false"));
        assert!(FLAG_SH.contains("gpio_write=false"));
        let weakened_block = FLAG_SH.replacen(
            "candidate_required=full-0x20000-byte-eraseblock",
            "candidate_required=one-byte",
            1,
        );
        assert!(
            admit_s19k_recovery_flag_script_execute_refuses_nandwrite(&weakened_block).is_err()
        );
        let injected_writer =
            format!("{FLAG_SH}\ndry_nandwrite=printf-byte-pipe-nandwrite\n| nandwrite\n");
        assert!(
            admit_s19k_recovery_flag_script_execute_refuses_nandwrite(&injected_writer).is_err()
        );
        assert!(!CLEAR_FOR_FLASH);
        assert_eq!(
            classify_s19k_upgrade_blob("update.bmu", b""),
            S19kUpgradeBlobKind::StockBitmainBmu
        );
        assert!(
            refuse_stock_bmu_as_dcent_sysupgrade(S19kUpgradeBlobKind::StockBitmainBmu).is_err()
        );
        assert!(refuse_s19k_dcent_sysupgrade_execute_while_flash_false(
            S19kUpgradeBlobKind::DcentSysupgradeTar
        )
        .is_err());
        assert!(!CLEAR_FOR_FLASH);
        assert!(
            refuse_stock_bmu_as_dcent_sysupgrade(S19kUpgradeBlobKind::DcentSysupgradeTar).is_ok()
        );
        assert_eq!(
            classify_s19k_upgrade_blob("sysupgrade-am3-s19k.tar", b""),
            S19kUpgradeBlobKind::DcentSysupgradeTar
        );
        assert_eq!(
            classify_s19k_upgrade_blob("aml_upgrade_package_enc.img", b""),
            S19kUpgradeBlobKind::AmlFactoryEnc
        );
        assert_eq!(
            classify_s19k_upgrade_blob("partition_emmc_miner.xml", b""),
            S19kUpgradeBlobKind::CvitekSd2NandFactory
        );
        assert_eq!(
            classify_s19k_upgrade_blob("boot.emmc", b""),
            S19kUpgradeBlobKind::CvitekSd2NandFactory
        );
        assert!(
            refuse_s19k_cvctrl_sd2nand_as_aml_nand(S19kUpgradeBlobKind::CvitekSd2NandFactory)
                .is_err()
        );
        assert!(
            refuse_s19k_cvctrl_sd2nand_as_aml_nand(S19kUpgradeBlobKind::DcentSysupgradeTar).is_ok()
        );
        let mut bmu_head = [0u8; 64];
        bmu_head[0] = S19K_BTMU_MAGIC;
        bmu_head[2..10].copy_from_slice(&S19K_STOCK_20231108_MINER_TYPE_HASH.to_le_bytes());
        bmu_head[23..23 + S19K_BMU_PEM_PREFIX.len()].copy_from_slice(S19K_BMU_PEM_PREFIX);
        let parsed = parse_s19k_bmu_header(&bmu_head).unwrap();
        assert_eq!(parsed.miner_type_hash, S19K_STOCK_20231108_MINER_TYPE_HASH);
        assert!(parsed.pem_visible);
        assert!(parse_s19k_bmu_header(&[0x55, 0xAA, 0x21, 0x36]).is_err());
        assert_eq!(S19K_STOCK_20231108_BMU_BYTES, 12_792_832);
        let mut pem_at_24 = [0u8; 0x40];
        pem_at_24[0] = S19K_BTMU_MAGIC;
        pem_at_24[2..10].copy_from_slice(&S19K_STOCK_20231108_MINER_TYPE_HASH.to_le_bytes());
        pem_at_24[23..23 + S19K_BMU_PEM_PREFIX.len()].copy_from_slice(S19K_BMU_PEM_PREFIX);
        pem_at_24[0x24..0x24 + S19K_BMU_FALSE_TOC_ASCII.len()]
            .copy_from_slice(S19K_BMU_FALSE_TOC_ASCII);
        assert!(s19k_bmu_offset_24_is_pem_not_toc(&pem_at_24));
        assert!(refuse_s19k_bmu_extraction_notes_as_toc().is_err());
        assert!(refuse_s19k_bmu_as_raw_nand_image(S19kUpgradeBlobKind::StockBitmainBmu).is_err());
        assert!(refuse_s19k_bmu_as_raw_nand_image(S19kUpgradeBlobKind::DcentSysupgradeTar).is_ok());
        assert_eq!(S19K_BMU_DATA_START, 0x4000);
        assert_eq!(
            classify_s19k_bmu_payload_head(&S19K_STOCK_20231108_PAYLOAD_HEAD),
            S19kBmuPayloadKind::HighEntropyOpaque
        );
        assert_eq!(
            classify_s19k_bmu_payload_head(&UIMAGE_MAGIC),
            S19kBmuPayloadKind::Uimage
        );
        assert_eq!(
            classify_s19k_bmu_payload_head(&[0x1F, 0x8B, 0x08, 0x00]),
            S19kBmuPayloadKind::Gzip
        );
        assert!(
            refuse_s19k_bmu_payload_as_rootfs_uimage(S19kBmuPayloadKind::HighEntropyOpaque)
                .is_err()
        );
        assert!(refuse_s19k_bmu_payload_as_rootfs_uimage(S19kBmuPayloadKind::Uimage).is_err());
        assert_eq!(S19K_BMU_PEM_SIG_OFF, 0x418);
        let mut sig_blob = vec![0u8; S19K_BMU_PEM_SIG_OFF + 4];
        assert!(!s19k_bmu_pem_sig_present(&sig_blob));
        sig_blob[S19K_BMU_PEM_SIG_OFF] = 0x02;
        assert!(s19k_bmu_pem_sig_present(&sig_blob));
        let mut pem_blob = vec![0u8; S19K_BMU_PEM_SIG_OFF + 4];
        pem_blob[0x16..0x18].copy_from_slice(&(S19K_20231108_MINER_PEM_LEN as u16).to_be_bytes());
        pem_blob[S19K_20231108_MINER_PEM_OFF
            ..S19K_20231108_MINER_PEM_OFF + S19K_20231108_MINER_PEM_BEGIN.len()]
            .copy_from_slice(S19K_20231108_MINER_PEM_BEGIN);
        pem_blob[S19K_BMU_PEM_SIG_OFF..S19K_BMU_PEM_SIG_OFF + 4]
            .copy_from_slice(&S19K_20231108_PEM_SIG_HEAD);
        assert!(admit_s19k_20231108_miner_pem(&pem_blob).is_ok());
        assert!(admit_s19k_20231108_pem_sig_head(&pem_blob).is_ok());
        assert!(admit_held_fileparser_uses_sha256_rsa_verify(
            "SHA256_Init\nSHA256_Update\nRSA_verify\nPEM_read_bio_RSA_PUBKEY"
        )
        .is_ok());
        assert!(admit_held_fileparser_uses_sha256_rsa_verify("RSA_verify only").is_err());
        assert!(admit_s19k_held_root_does_not_verify_pem_sig(false).is_ok());
        assert!(admit_s19k_held_root_does_not_verify_pem_sig(true).is_err());
        assert!(refuse_s19k_unverified_pem_sig_as_nand_grant().is_err());
        assert!(refuse_s19k_cvctrl_pub_as_miner_pem(false).is_err());
        assert!(!S19K_MINER_PEM_SIG_HELD_ROOT_VERIFIED);
        assert_eq!(S19K_20231108_MINER_PEM_LEN, 451);
        assert_eq!(S19K_CVCTRL_BITMAIN_PUB_BYTES, 451);
        assert_eq!(S19K_HASSOURCE_S19PRO_BITMAIN_PUB_BYTES, 460);
        assert_eq!(S19K_20231108_PEM_SIG_HEAD, [0x02, 0x2E, 0x5A, 0xE0]);
        let ini = ";\n[common]\nerase_bootloader    =1\nerase_flash         =1\npackage     =aml_upgrade_package_enc.img\n";
        assert!(refuse_aml_sdc_burn_as_dcent(ini).is_err());
        assert!(refuse_aml_sdc_burn_as_dcent("[common]\nerase_bootloader=0\n").is_ok());
        let stock_ini = parse_s19k_aml_sdc_burn_ini(
            "[common]\nerase_bootloader    =1\nerase_flash         =1\nreboot              =1\n[burn_ex]\npackage     =aml_upgrade_package_enc.img\n",
        )
        .unwrap();
        assert!(stock_ini.erase_bootloader && stock_ini.erase_flash && stock_ini.reboot);
        assert!(stock_ini.package_is_enc_img);
        for malformed in [
            "[common]\nerase_bootloader=1\nerase_bootloader=0\nerase_flash=1\nreboot=1\n[burn_ex]\npackage=aml_upgrade_package_enc.img\n",
            "[common]\nerase_bootloader=0\nerase_flash=1\nreboot=1\n[burn_ex]\npackage=aml_upgrade_package_enc.img\nerase_bootloader=1\n",
            "[common]\nerase_bootloader=1\nerase_flash=1\nreboot=0\n[burn_ex]\npackage=aml_upgrade_package_enc.img\n",
            "[common]\nerase_bootloader=1\nerase_flash=1\nreboot=1\npackage=aml_upgrade_package_enc.img\n[burn_ex]\n",
            "[common]\nerase_bootloader=1\nerase_flash=1\nreboot=1\nunknown=1\n[burn_ex]\npackage=aml_upgrade_package_enc.img\n",
            "[common]\nerase_bootloader=1\nerase_flash=1\nreboot=1\n[common]\n[burn_ex]\npackage=aml_upgrade_package_enc.img\n",
        ] {
            assert!(parse_s19k_aml_sdc_burn_ini(malformed).is_err());
        }
        assert_eq!(
            classify_s19k_aml_sd_pack(
                S19K_AML_FACTORY_SD_UBOOT_BYTES,
                S19K_AML_FACTORY_SD_IMG_BYTES
            ),
            S19kAmlSdPackKind::StockS19kFactorySd
        );
        assert_eq!(
            classify_s19k_aml_sd_pack(
                VNISH_AML_SD_UBOOT_POINTER_BYTES,
                VNISH_SHARED_AML_UPGRADE_IMG_BYTES
            ),
            S19kAmlSdPackKind::VnishSharedLfsPointer
        );
        assert_eq!(
            classify_s19k_aml_sd_pack(S19K_AML_FACTORY_SD_UBOOT_BYTES, 22_997_160),
            S19kAmlSdPackKind::ComparativeOtherAml
        );
        assert!(refuse_vnish_lfs_uboot_as_s19k_factory(131).is_err());
        assert!(refuse_vnish_lfs_uboot_as_s19k_factory(818_688).is_ok());
        assert!(refuse_vnish_shared_img_as_s19k_stock(22_991_024).is_err());
        assert!(refuse_vnish_shared_img_as_s19k_stock(23_134_392).is_ok());
        assert!(refuse_s19k_aml_factory_sd_as_dcent_sysupgrade(
            S19kAmlSdPackKind::StockS19kFactorySd
        )
        .is_err());
        assert!(
            refuse_s19k_aml_factory_sd_as_nandrecovery_env("aml_upgrade_package_enc.img").is_err()
        );
        assert!(refuse_s19k_aml_factory_sd_as_nandrecovery_env(
            "AML-19k-Pro-202311151447-sd-card.zip"
        )
        .is_err());
        assert!(refuse_s19k_aml_factory_sd_as_nandrecovery_env("nandrecovery_env.bin").is_ok());
        assert_eq!(
            classify_s19k_upgrade_blob("AML-19k-Pro-202311151447-sd-card.zip", b""),
            S19kUpgradeBlobKind::AmlFactoryEnc
        );
        assert_eq!(
            classify_s19k_upgrade_blob("sd-recover-bmu-s19k-pro-202311151452-release.zip", b""),
            S19kUpgradeBlobKind::XilSdRecoverFactory
        );
        assert!(
            refuse_s19k_xil_sd_recover_as_aml_nand(S19kUpgradeBlobKind::XilSdRecoverFactory)
                .is_err()
        );
        assert!(refuse_s19k_xil_recover_uimage_as_aml_nand(
            S19K_XIL_SD_RECOVER_UIMAGE_BYTES,
            S19K_XIL_SD_RECOVER_UIMAGE_NAME
        )
        .is_err());
        let evidence = exact_factory_sd_evidence(S19kAmlSdPackKind::StockS19kFactorySd);
        let plan = format_s19k_aml_factory_sd_plan(evidence, stock_ini).unwrap();
        assert!(plan.contains("schema=dcentos.amlogic-factory-sd/v1"));
        assert!(plan.contains("execute=false"));
        assert!(plan.contains("clear_for_flash=false"));
        assert!(plan.contains("updateporc=false"));
        assert!(plan.contains("nandrecovery_env=false"));
        assert!(plan.contains("nandwrite=false"));
        assert!(plan.contains("img_bytes=23134392"));
        assert!(plan.contains(S19K_AML_FACTORY_SD_ARCHIVE_SHA256));
        assert!(plan.contains(S19K_AML_FACTORY_SD_INI_SHA256));
        assert!(plan.contains(S19K_AML_FACTORY_SD_UBOOT_SHA256));
        assert!(plan.contains(S19K_AML_FACTORY_SD_TOC_SHA256));
        assert!(plan.contains("linux_raw_restore_equivalent=false"));
        assert!(plan.contains("required_preburn_backup=dcentos.s19k-aml-full-logical-rescue/v1"));
        assert!(plan.contains("stable-badblock-counts+boot-nand-transcript"));
        assert!(plan.contains("preburn_backup_is_physical_replay=false"));
        assert!(plan.contains("required_unit_state_restore="));
        assert!(!plan.contains("empty-badmap"));
        assert!(plan.contains("bench_sequence=verify-FULL_RESCUE_LEDGER.txt"));
        let mut wrong_hash = evidence;
        wrong_hash.img_sha256 = "039da235cdf816a2cbfbf2037b056ad1b2dc5ab704efc97ed0050e6e0b313678";
        assert!(format_s19k_aml_factory_sd_plan(wrong_hash, stock_ini).is_err());
        let mut wrong_outer = evidence;
        wrong_outer.archive_sha256 =
            "06214d02b3c246ad4f98bcbe50b83705392a23a9fa5007120cb21d033e98dcf4";
        assert!(format_s19k_aml_factory_sd_plan(wrong_outer, stock_ini).is_err());
        let mut wrong_toc = evidence;
        wrong_toc.toc_sha256 = "0fb21fd2d67e651a4ac2d4558a21099ccab250df73032b1c0acecee78cda20d8";
        assert!(format_s19k_aml_factory_sd_plan(wrong_toc, stock_ini).is_err());
        assert!(format_s19k_aml_factory_sd_plan(
            exact_factory_sd_evidence(S19kAmlSdPackKind::VnishSharedLfsPointer),
            stock_ini
        )
        .is_err());
        assert!(format_s19k_aml_factory_sd_plan(
            exact_factory_sd_evidence(S19kAmlSdPackKind::ComparativeOtherAml),
            stock_ini
        )
        .is_err());
        assert!(admit_s19k_aml_factory_sd_execute().is_err());
        assert!(!CLEAR_FOR_FLASH);
        assert_eq!(
            admit_s19k_recover_execute("aml_upgrade_package_enc.img", true, 0x02, tools_ok),
            Err(S19kRecoverExecuteError::BadEnvSource)
        );
        assert_eq!(
            admit_s19k_recover_execute(
                "AML-19k-Pro-202311151447-sd-card.zip",
                true,
                0x02,
                tools_ok
            ),
            Err(S19kRecoverExecuteError::BadEnvSource)
        );
        let mut hdr = [0u8; S19K_AML_UPGRADE_HEADER_LEN];
        hdr[0..4].copy_from_slice(&S19K_AML_UPGRADE_CRC.to_le_bytes());
        hdr[4..8].copy_from_slice(&S19K_AML_UPGRADE_VERSION.to_le_bytes());
        hdr[8..12].copy_from_slice(&S19K_AML_UPGRADE_MAGIC.to_le_bytes());
        hdr[12..20].copy_from_slice(&(S19K_AML_FACTORY_SD_IMG_BYTES as u64).to_le_bytes());
        hdr[20..24].copy_from_slice(&S19K_AML_UPGRADE_ITEM_ALIGN.to_le_bytes());
        hdr[24..28].copy_from_slice(&S19K_AML_UPGRADE_ITEM_NUM.to_le_bytes());
        let parsed = parse_s19k_aml_upgrade_header(&hdr).unwrap();
        assert_eq!(parsed.crc, S19K_AML_UPGRADE_CRC);
        assert_eq!(parsed.magic, S19K_AML_UPGRADE_MAGIC);
        assert_eq!(parsed.image_sz, S19K_AML_FACTORY_SD_IMG_BYTES as u64);
        assert_eq!(parsed.item_num, 19);
        assert!(admit_s19k_aml_upgrade_header(parsed).is_ok());
        assert!(refuse_bible_aml_crc_as_s19k_factory.is_err());
        assert!(refuse_bible_aml_crc_as_s19k_factory.is_err());
        assert!(refuse_bible_aml_crc_as_s19k_factory.is_err());
        assert!(refuse_bible_aml_crc_as_s19k_factory(S19K_AML_UPGRADE_CRC).is_ok());
        assert!(refuse_s19k_aml_crc_as_decrypt_key().is_err());
        assert!(refuse_aml_img_80_stride_as_s19k_toc(0x80).is_err());
        assert!(refuse_aml_img_80_stride_as_s19k_toc(0x240).is_ok());
        assert_eq!(S19K_AML_UPGRADE_TOC_BYTES, 11_008);
        let mut item = vec![0u8; S19K_AML_UPGRADE_ITEM_STRIDE];
        item[0..4].copy_from_slice(&7u32.to_le_bytes());
        item[0x10..0x18].copy_from_slice(&S19K_AML_UPGRADE_ITEM7_UBOOT_ENC_OFF.to_le_bytes());
        item[0x18..0x20].copy_from_slice(&S19K_AML_UPGRADE_ITEM7_UBOOT_ENC_SIZE.to_le_bytes());
        item[0x20..0x29].copy_from_slice(b"UBOOT.ENC");
        item[0x120..0x12C].copy_from_slice(b"aml_sdc_burn");
        let it = parse_s19k_aml_upgrade_item(&item).unwrap();
        assert_eq!(it.main, "UBOOT.ENC");
        assert_eq!(it.sub, "aml_sdc_burn");
        assert!(admit_s19k_aml_upgrade_uboot_enc_item(&it).is_ok());
        let mut usb_item = vec![0u8; S19K_AML_UPGRADE_ITEM_STRIDE];
        usb_item[0..4].copy_from_slice(&2u32.to_le_bytes());
        usb_item[0x10..0x18].copy_from_slice(&S19K_AML_UPGRADE_ITEM2_USB_UBOOT_OFF.to_le_bytes());
        usb_item[0x18..0x20].copy_from_slice(&S19K_AML_UPGRADE_ITEM2_USB_UBOOT_SIZE.to_le_bytes());
        usb_item[0x20..0x23].copy_from_slice(b"USB");
        usb_item[0x120..0x125].copy_from_slice(b"UBOOT");
        let usb_it = parse_s19k_aml_upgrade_item(&usb_item).unwrap();
        assert!(admit_s19k_aml_upgrade_usb_uboot_item(&usb_it).is_ok());
        let mut ddr_item = vec![0u8; S19K_AML_UPGRADE_ITEM_STRIDE];
        ddr_item[0..4].copy_from_slice(&0u32.to_le_bytes());
        ddr_item[0x10..0x18].copy_from_slice(&S19K_AML_UPGRADE_ITEM0_USB_DDR_OFF.to_le_bytes());
        ddr_item[0x18..0x20].copy_from_slice(&S19K_AML_UPGRADE_ITEM0_USB_DDR_SIZE.to_le_bytes());
        ddr_item[0x20..0x23].copy_from_slice(b"USB");
        ddr_item[0x120..0x123].copy_from_slice(b"DDR");
        assert!(admit_s19k_aml_upgrade_usb_ddr_item(
            &parse_s19k_aml_upgrade_item(&ddr_item).unwrap()
        )
        .is_ok());
        let mut ddr_enc = vec![0u8; S19K_AML_UPGRADE_ITEM_STRIDE];
        ddr_enc[0..4].copy_from_slice(&1u32.to_le_bytes());
        ddr_enc[0x10..0x18].copy_from_slice(&S19K_AML_UPGRADE_ITEM1_USB_DDR_ENC_OFF.to_le_bytes());
        ddr_enc[0x18..0x20].copy_from_slice(&S19K_AML_UPGRADE_ITEM1_USB_DDR_ENC_SIZE.to_le_bytes());
        ddr_enc[0x20..0x23].copy_from_slice(b"USB");
        ddr_enc[0x120..0x127].copy_from_slice(b"DDR_ENC");
        assert!(admit_s19k_aml_upgrade_usb_ddr_enc_item(
            &parse_s19k_aml_upgrade_item(&ddr_enc).unwrap()
        )
        .is_ok());
        let mut uboot_enc = vec![0u8; S19K_AML_UPGRADE_ITEM_STRIDE];
        uboot_enc[0..4].copy_from_slice(&3u32.to_le_bytes());
        uboot_enc[0x10..0x18]
            .copy_from_slice(&S19K_AML_UPGRADE_ITEM3_USB_UBOOT_ENC_OFF.to_le_bytes());
        uboot_enc[0x18..0x20]
            .copy_from_slice(&S19K_AML_UPGRADE_ITEM3_USB_UBOOT_ENC_SIZE.to_le_bytes());
        uboot_enc[0x20..0x23].copy_from_slice(b"USB");
        uboot_enc[0x120..0x129].copy_from_slice(b"UBOOT_ENC");
        assert!(admit_s19k_aml_upgrade_usb_uboot_enc_item(
            &parse_s19k_aml_upgrade_item(&uboot_enc).unwrap()
        )
        .is_ok());
        let mut ini_item = vec![0u8; S19K_AML_UPGRADE_ITEM_STRIDE];
        ini_item[0..4].copy_from_slice(&8u32.to_le_bytes());
        ini_item[0x10..0x18].copy_from_slice(&S19K_AML_UPGRADE_ITEM8_INI_OFF.to_le_bytes());
        ini_item[0x18..0x20].copy_from_slice(&S19K_AML_UPGRADE_ITEM8_INI_SIZE.to_le_bytes());
        ini_item[0x20..0x23].copy_from_slice(b"ini");
        ini_item[0x120..0x12C].copy_from_slice(b"aml_sdc_burn");
        assert!(
            admit_s19k_aml_upgrade_ini_item(&parse_s19k_aml_upgrade_item(&ini_item).unwrap())
                .is_ok()
        );
        let mut keys_item = vec![0u8; S19K_AML_UPGRADE_ITEM_STRIDE];
        keys_item[0..4].copy_from_slice(&13u32.to_le_bytes());
        keys_item[0x10..0x18].copy_from_slice(&S19K_AML_UPGRADE_ITEM13_KEYS_OFF.to_le_bytes());
        keys_item[0x18..0x20].copy_from_slice(&S19K_AML_UPGRADE_ITEM13_KEYS_SIZE.to_le_bytes());
        keys_item[0x20..0x24].copy_from_slice(b"conf");
        keys_item[0x120..0x124].copy_from_slice(b"keys");
        assert!(admit_s19k_aml_upgrade_keys_item(
            &parse_s19k_aml_upgrade_item(&keys_item).unwrap()
        )
        .is_ok());
        let mut plat_item = vec![0u8; S19K_AML_UPGRADE_ITEM_STRIDE];
        plat_item[0..4].copy_from_slice(&16u32.to_le_bytes());
        plat_item[0x10..0x18].copy_from_slice(&S19K_AML_UPGRADE_ITEM16_PLATFORM_OFF.to_le_bytes());
        plat_item[0x18..0x20].copy_from_slice(&S19K_AML_UPGRADE_ITEM16_PLATFORM_SIZE.to_le_bytes());
        plat_item[0x20..0x24].copy_from_slice(b"conf");
        plat_item[0x120..0x128].copy_from_slice(b"platform");
        assert!(admit_s19k_aml_upgrade_platform_item(
            &parse_s19k_aml_upgrade_item(&plat_item).unwrap()
        )
        .is_ok());
        assert!(admit_s19k_usb_ddr_enc_same_size(49_152, 49_152).is_ok());
        assert!(admit_s19k_usb_uboot_enc_same_size(769_024, 769_024).is_ok());
        assert!(admit_s19k_usb_enc_distinct(false).is_ok());
        assert!(admit_s19k_usb_enc_distinct(true).is_err());
        assert!(refuse_s19k_usb_ddr_enc_as_decrypt_key().is_err());
        assert!(refuse_s19k_usb_uboot_enc_as_decrypt_key().is_err());
        assert!(admit_s19k_factory_keys_payload(S19K_AML_UPGRADE_KEYS_PAYLOAD).is_ok());
        assert!(refuse_s19k_conf_keys_as_aes_key().is_err());
        let mut plat = vec![b'x'; S19K_AML_UPGRADE_ITEM16_PLATFORM_SIZE as usize];
        plat[..S19K_AML_UPGRADE_PLATFORM.len()]
            .copy_from_slice(S19K_AML_UPGRADE_PLATFORM.as_bytes());
        plat[40..40 + S19K_AML_UPGRADE_ENCRYPT_REG_ASCII.len()]
            .copy_from_slice(S19K_AML_UPGRADE_ENCRYPT_REG_ASCII);
        assert!(admit_s19k_factory_platform_payload(&plat).is_ok());
        assert!(refuse_s19k_encrypt_reg_as_otp_decrypt_key().is_err());
        assert_eq!(S19K_AML_UPGRADE_ENCRYPT_REG, 0xFF80_0228);
        let mut ini = vec![b'.'; S19K_AML_UPGRADE_ITEM8_INI_SIZE as usize];
        ini[10..10 + S19K_AML_UPGRADE_INI_PACKAGE.len()]
            .copy_from_slice(S19K_AML_UPGRADE_INI_PACKAGE);
        ini[80..80 + S19K_AML_UPGRADE_INI_ERASE_BL.len()]
            .copy_from_slice(S19K_AML_UPGRADE_INI_ERASE_BL);
        assert!(admit_s19k_factory_ini_payload(&ini).is_ok());
        assert!(refuse_s19k_ini_erase_bootloader_as_execute().is_err());
        let mut meson_item = vec![0u8; S19K_AML_UPGRADE_ITEM_STRIDE];
        meson_item[0..4].copy_from_slice(&14u32.to_le_bytes());
        meson_item[0x10..0x18].copy_from_slice(&S19K_AML_UPGRADE_ITEM14_MESON1_OFF.to_le_bytes());
        meson_item[0x18..0x20].copy_from_slice(&S19K_AML_UPGRADE_ITEM14_MESON1_SIZE.to_le_bytes());
        meson_item[0x20..0x23].copy_from_slice(b"dtb");
        meson_item[0x120..0x126].copy_from_slice(b"meson1");
        let meson_it = parse_s19k_aml_upgrade_item(&meson_item).unwrap();
        assert!(admit_s19k_aml_upgrade_meson1_item(&meson_it).is_ok());
        assert!(refuse_s19k_aml_dtb_partition_as_gzip_meson1(&[0x5D, 0xC7]).is_err());
        assert!(refuse_s19k_aml_dtb_partition_as_gzip_meson1(&[0x1F, 0x8B]).is_ok());
        let mut dtb_item = vec![0u8; S19K_AML_UPGRADE_ITEM_STRIDE];
        dtb_item[0..4].copy_from_slice(&4u32.to_le_bytes());
        dtb_item[0x10..0x18].copy_from_slice(&S19K_AML_UPGRADE_ITEM4_AML_DTB_OFF.to_le_bytes());
        dtb_item[0x18..0x20].copy_from_slice(&S19K_AML_UPGRADE_ITEM4_AML_DTB_SIZE.to_le_bytes());
        dtb_item[0x20..0x29].copy_from_slice(b"PARTITION");
        dtb_item[0x120..0x128].copy_from_slice(b"_aml_dtb");
        let dtb_it = parse_s19k_aml_upgrade_item(&dtb_item).unwrap();
        assert!(admit_s19k_aml_upgrade_aml_dtb_item(&dtb_it).is_ok());
        let mut enc_item = vec![0u8; S19K_AML_UPGRADE_ITEM_STRIDE];
        enc_item[0..4].copy_from_slice(&15u32.to_le_bytes());
        enc_item[0x10..0x18].copy_from_slice(&S19K_AML_UPGRADE_ITEM4_AML_DTB_OFF.to_le_bytes());
        enc_item[0x18..0x20].copy_from_slice(&S19K_AML_UPGRADE_ITEM4_AML_DTB_SIZE.to_le_bytes());
        enc_item[0x20..0x23].copy_from_slice(b"dtb");
        enc_item[0x120..0x12A].copy_from_slice(b"meson1_ENC");
        let enc_it = parse_s19k_aml_upgrade_item(&enc_item).unwrap();
        assert!(admit_s19k_aml_upgrade_meson1_enc_item(&enc_it).is_ok());
        assert!(admit_s19k_aml_dtb_alias_meson1_enc(&dtb_it, &enc_it).is_ok());
        let mut verify = [0u8; 48];
        verify[..8].copy_from_slice(S19K_AML_VERIFY_PREFIX);
        verify[8..].copy_from_slice(S19K_AML_DTB_ENC_SHA1_HEX);
        let digest = parse_s19k_aml_verify_item(&verify).unwrap();
        assert_eq!(digest[0], 0x8e);
        assert_eq!(digest[19], 0x1b);
        assert!(admit_s19k_aml_dtb_verify_hex(S19K_AML_DTB_ENC_SHA1_HEX).is_ok());
        assert_eq!(
            classify_s19k_aml_verify_hex(S19K_AML_BOOT_SHA1_HEX).unwrap(),
            S19kAmlVerifyKind::Boot
        );
        assert_eq!(
            classify_s19k_aml_verify_hex(S19K_AML_BOOTLOADER_SHA1_HEX).unwrap(),
            S19kAmlVerifyKind::Bootloader
        );
        assert_eq!(
            classify_s19k_aml_verify_hex(S19K_AML_RECOVERY_SHA1_HEX).unwrap(),
            S19kAmlVerifyKind::Recovery
        );
        assert_eq!(
            admit_s19k_aml_verify_pair("boot", S19K_AML_BOOT_SHA1_HEX).unwrap(),
            S19kAmlVerifyKind::Boot
        );
        assert!(admit_s19k_aml_verify_pair("boot", S19K_AML_DTB_ENC_SHA1_HEX).is_err());
        assert!(refuse_s19k_aml_verify_as_decrypt().is_err());
        assert!(refuse_s19k_aml_verify_hex_as_other_kind(
            S19kAmlVerifyKind::Boot,
            S19K_AML_DTB_ENC_SHA1_HEX
        )
        .is_err());
        assert!(refuse_s19k_aml_verify_hex_as_other_kind(
            S19kAmlVerifyKind::Boot,
            S19K_AML_BOOT_SHA1_HEX
        )
        .is_ok());
        let mut vboot = vec![0u8; S19K_AML_UPGRADE_ITEM_STRIDE];
        vboot[0x20..0x26].copy_from_slice(b"VERIFY");
        vboot[0x120..0x124].copy_from_slice(b"boot");
        vboot[0x10..0x18].copy_from_slice(&S19K_AML_UPGRADE_ITEM10_VERIFY_BOOT_OFF.to_le_bytes());
        vboot[0x18..0x20].copy_from_slice(&(S19K_AML_VERIFY_ITEM_BYTES as u64).to_le_bytes());
        assert!(admit_s19k_aml_upgrade_verify_item(
            &parse_s19k_aml_upgrade_item(&vboot).unwrap(),
            S19kAmlVerifyKind::Boot
        )
        .is_ok());
        let mut vbl = vec![0u8; S19K_AML_UPGRADE_ITEM_STRIDE];
        vbl[0x20..0x26].copy_from_slice(b"VERIFY");
        vbl[0x120..0x12A].copy_from_slice(b"bootloader");
        vbl[0x10..0x18].copy_from_slice(&S19K_AML_UPGRADE_ITEM12_VERIFY_BL_OFF.to_le_bytes());
        vbl[0x18..0x20].copy_from_slice(&(S19K_AML_VERIFY_ITEM_BYTES as u64).to_le_bytes());
        assert!(admit_s19k_aml_upgrade_verify_item(
            &parse_s19k_aml_upgrade_item(&vbl).unwrap(),
            S19kAmlVerifyKind::Bootloader
        )
        .is_ok());
        let mut vrec = vec![0u8; S19K_AML_UPGRADE_ITEM_STRIDE];
        vrec[0x20..0x26].copy_from_slice(b"VERIFY");
        vrec[0x120..0x128].copy_from_slice(b"recovery");
        vrec[0x10..0x18].copy_from_slice(&S19K_AML_UPGRADE_ITEM18_VERIFY_REC_OFF.to_le_bytes());
        vrec[0x18..0x20].copy_from_slice(&(S19K_AML_VERIFY_ITEM_BYTES as u64).to_le_bytes());
        assert!(admit_s19k_aml_upgrade_verify_item(
            &parse_s19k_aml_upgrade_item(&vrec).unwrap(),
            S19kAmlVerifyKind::Recovery
        )
        .is_ok());
        let mut bl_item = vec![0u8; S19K_AML_UPGRADE_ITEM_STRIDE];
        bl_item[0x20..0x29].copy_from_slice(b"PARTITION");
        bl_item[0x120..0x12A].copy_from_slice(b"bootloader");
        bl_item[0x10..0x18].copy_from_slice(&S19K_AML_UPGRADE_ITEM11_BOOTLOADER_OFF.to_le_bytes());
        bl_item[0x18..0x20].copy_from_slice(&S19K_AML_UPGRADE_ITEM11_BOOTLOADER_SIZE.to_le_bytes());
        assert!(admit_s19k_aml_upgrade_bootloader_item(
            &parse_s19k_aml_upgrade_item(&bl_item).unwrap()
        )
        .is_ok());
        let mut sdc_item = vec![0u8; S19K_AML_UPGRADE_ITEM_STRIDE];
        sdc_item[0x20..0x25].copy_from_slice(b"UBOOT");
        sdc_item[0x120..0x12C].copy_from_slice(b"aml_sdc_burn");
        sdc_item[0x10..0x18].copy_from_slice(&S19K_AML_UPGRADE_ITEM6_UBOOT_OFF.to_le_bytes());
        sdc_item[0x18..0x20].copy_from_slice(&S19K_AML_UPGRADE_ITEM6_UBOOT_SIZE.to_le_bytes());
        assert!(admit_s19k_aml_upgrade_sdc_uboot_item(
            &parse_s19k_aml_upgrade_item(&sdc_item).unwrap()
        )
        .is_ok());
        assert!(admit_s19k_bootloader_uboot_enc_same_size(818_688, 818_688).is_ok());
        assert!(refuse_s19k_bootloader_as_uboot_enc(b"\xb5enc-a", b"\xb8enc-b").is_err());
        assert!(refuse_s19k_bootloader_as_uboot_enc(b"same", b"same").is_ok());
        assert!(refuse_s19k_bootloader_as_plaintext_uboot(b"\xb5\x98ciphertext").is_err());
        assert!(refuse_s19k_bootloader_as_plaintext_uboot(b"S19k-Pro_BHB56XXX").is_ok());
        assert!(admit_s19k_sdc_usb_uboot_sizes(818_688, 769_024).is_ok());
        assert!(admit_s19k_sdc_usb_uboot_sizes(769_024, 769_024).is_err());
        let usb_tail = b"USB-UBOOT-TAIL";
        let mut sdc = vec![0u8; S19K_SDC_USB_UBOOT_PREFIX_BYTES];
        sdc[100..100 + S19K_SDC_BL2_BUILD.len()].copy_from_slice(S19K_SDC_BL2_BUILD);
        sdc[200..203].copy_from_slice(b"BL2");
        sdc[210..219].copy_from_slice(b"NAND init");
        assert!(admit_s19k_sdc_uboot_prefix_bl2(&sdc).is_ok());
        assert!(refuse_s19k_sdc_uboot_prefix_as_gpio437(&sdc).is_err());
        let mut classes = Vec::new();
        for (i, name) in S19K_BL2_STORAGE_CLASSES.iter().enumerate() {
            if i > 0 {
                classes.push(0);
            }
            classes.extend_from_slice(name.as_bytes());
        }
        sdc[300..300 + classes.len()].copy_from_slice(&classes);
        sdc[400..400 + S19K_BL2_NAND_INIT.len()].copy_from_slice(S19K_BL2_NAND_INIT);
        sdc[430..430 + S19K_BL2_EMMC_BOOT.len()].copy_from_slice(S19K_BL2_EMMC_BOOT);
        sdc[460..460 + S19K_BL2_NO_STORAGE.len()].copy_from_slice(S19K_BL2_NO_STORAGE);
        assert_eq!(
            parse_s19k_bl2_storage_classes(&sdc).unwrap(),
            S19K_BL2_STORAGE_CLASSES
                .iter()
                .map(|s| (*s).to_string())
                .collect::<Vec<_>>()
        );
        assert!(admit_s19k_bl2_storage_init(&sdc).is_ok());
        assert!(refuse_s19k_bl2_storage_as_78_mtd(S19K_BL2_STORAGE_CLASSES).is_err());
        assert!(refuse_s19k_bl2_storage_as_s30v_nand(S19K_BL2_STORAGE_CLASSES).is_err());
        assert!(refuse_s19k_bl2_emmc_boot_as_s19k_nand_map().is_err());
        sdc[500..500 + S19K_BL2_RPMB_COUNTER_ERR.len()].copy_from_slice(S19K_BL2_RPMB_COUNTER_ERR);
        sdc[540..540 + S19K_BL2_RPMB_COUNTER.len()].copy_from_slice(S19K_BL2_RPMB_COUNTER);
        sdc[580..580 + S19K_BL2_RPMB_SET_KEY.len()].copy_from_slice(S19K_BL2_RPMB_SET_KEY);
        sdc[620..620 + S19K_BL2_RPMB_CANNOT_READ.len()].copy_from_slice(S19K_BL2_RPMB_CANNOT_READ);
        assert!(admit_s19k_bl2_rpmb_emmc_errors(&sdc).is_ok());
        assert!(refuse_s19k_bl2_rpmb_as_nandrecovery().is_err());
        assert!(refuse_s19k_bl2_rpmb_as_78_nand().is_err());
        assert!(refuse_s19k_bl2_rpmb_as_s30v_nand().is_err());
        sdc[660..660 + S19K_BL2_SCAN_BBT_ECC.len()].copy_from_slice(S19K_BL2_SCAN_BBT_ECC);
        sdc[700..700 + S19K_BL2_NBBT.len()].copy_from_slice(S19K_BL2_NBBT);
        sdc[710..710 + S19K_BL2_READ_PAGE_ADDR.len()].copy_from_slice(S19K_BL2_READ_PAGE_ADDR);
        assert!(admit_s19k_bl2_scan_bbt_ecc(&sdc).is_ok());
        assert!(refuse_s19k_bl2_bbt_as_78_nand_ecc().is_err());
        assert!(refuse_s19k_bl2_bbt_as_s30v_nand().is_err());
        assert!(refuse_s19k_bl2_bbt_as_nandrecovery().is_err());
        assert_eq!(S19K_BL2_SCAN_BBT_OFF, 42_161);
        assert_eq!(S19K_BL2_NBBT_OFF, 42_156);
        assert_eq!(S19K_BL2_READ_PAGE_OFF, 42_189);
        sdc[740..740 + S19K_BL2_DDR_SAVED_PAGE.len()].copy_from_slice(S19K_BL2_DDR_SAVED_PAGE);
        sdc[770..770 + S19K_BL2_LOCK_CHECK.len()].copy_from_slice(S19K_BL2_LOCK_CHECK);
        sdc[790..790 + S19K_BL2_LOCK_FAILED.len()].copy_from_slice(S19K_BL2_LOCK_FAILED);
        assert!(admit_s19k_bl2_ddr_saved_page(&sdc).is_ok());
        assert!(admit_s19k_bl2_lock_check(&sdc).is_ok());
        assert!(refuse_s19k_bl2_ddr_page_as_nandrecovery().is_err());
        assert!(refuse_s19k_bl2_lock_as_gpio437().is_err());
        assert!(refuse_s19k_bl2_lock_as_nandrecovery().is_err());
        assert_eq!(S19K_BL2_DDR_SAVED_PAGE_OFF, 42_139);
        assert_eq!(S19K_BL2_LOCK_CHECK_OFF, 42_206);
        assert_eq!(S19K_BL2_LOCK_FAILED_OFF, 42_219);
        sdc[820..820 + S19K_BL2_CPU_CLK_24MHZ.len()].copy_from_slice(S19K_BL2_CPU_CLK_24MHZ);
        sdc[850..850 + S19K_BL2_SYS_PLL.len()].copy_from_slice(S19K_BL2_SYS_PLL);
        sdc[860..860 + S19K_BL2_FIX_PLL.len()].copy_from_slice(S19K_BL2_FIX_PLL);
        assert!(admit_s19k_bl2_cpu_clk_24mhz(&sdc).is_ok());
        assert!(admit_s19k_bl2_sys_fix_pll(&sdc).is_ok());
        assert!(refuse_s19k_bl2_24mhz_as_hash_clock().is_err());
        assert!(refuse_s19k_bl2_24mhz_as_uart_baud().is_err());
        assert!(refuse_s19k_bl2_pll_as_asic_pll().is_err());
        assert_eq!(S19K_BL2_CPU_CLK_OFF, 42_242);
        assert_eq!(S19K_BL2_SYS_PLL_OFF, 42_258);
        assert_eq!(S19K_BL2_FIX_PLL_OFF, 42_276);
        sdc[880..880 + S19K_BL2_SARADC_ERR.len()].copy_from_slice(S19K_BL2_SARADC_ERR);
        assert!(admit_s19k_bl2_saradc_sample_error(&sdc).is_ok());
        assert!(admit_s19k_bl2_saradc_cnt(&sdc).is_ok());
        assert!(refuse_s19k_bl2_saradc_as_miner_voltage_adc().is_err());
        assert!(refuse_s19k_bl2_saradc_as_miner_temp_adc().is_err());
        assert!(refuse_s19k_bl2_saradc_as_gpio437().is_err());
        assert_eq!(S19K_BL2_SARADC_ERR_OFF, 42_285);
        assert_eq!(S19K_BL2_SARADC_CNT_OFF, 42_310);
        sdc[920..920 + S19K_BL2_BOARD_ID.len()].copy_from_slice(S19K_BL2_BOARD_ID);
        assert!(admit_s19k_bl2_board_id(&sdc).is_ok());
        assert!(refuse_s19k_bl2_board_id_as_78_chassis().is_err());
        assert!(refuse_s19k_bl2_board_id_as_bhb56().is_err());
        assert_eq!(S19K_BL2_BOARD_ID_OFF, 42_315);
        sdc[940..940 + S19K_BL2_RANK.len()].copy_from_slice(S19K_BL2_RANK);
        sdc[960..960 + S19K_BL2_DDR_TYPE_TABLE.len()].copy_from_slice(S19K_BL2_DDR_TYPE_TABLE);
        sdc[1000..1000 + S19K_BL2_RANK_TABLE.len()].copy_from_slice(S19K_BL2_RANK_TABLE);
        sdc[1060..1060 + S19K_BL2_DDR_INIT_FAIL.len()].copy_from_slice(S19K_BL2_DDR_INIT_FAIL);
        assert_eq!(
            parse_s19k_bl2_ddr_types(&sdc).unwrap(),
            S19K_BL2_DDR_TYPES
                .iter()
                .map(|s| (*s).to_string())
                .collect::<Vec<_>>()
        );
        assert!(admit_s19k_bl2_ddr_table(&sdc).is_ok());
        assert!(refuse_s19k_bl2_ddr_as_78_nand().is_err());
        assert!(refuse_s19k_bl2_ddr_as_s30v_nand().is_err());
        assert!(refuse_s19k_bl2_ddr_init_as_nandrecovery().is_err());
        assert_eq!(S19K_BL2_RANK_OFF, 42_384);
        assert_eq!(S19K_BL2_DDR_TYPE_TABLE_OFF, 42_560);
        assert_eq!(S19K_BL2_RANK_TABLE_OFF, 42_588);
        assert_eq!(S19K_BL2_DDR_INIT_FAIL_OFF, 42_924);
        sdc[1100..1100 + S19K_BL2_DDR_SSC.len()].copy_from_slice(S19K_BL2_DDR_SSC);
        sdc[1120..1120 + S19K_BL2_DDR_SSC_PPM.len()].copy_from_slice(S19K_BL2_DDR_SSC_PPM);
        sdc[1145..1145 + S19K_BL2_DDR_PLL_BYPASS.len()].copy_from_slice(S19K_BL2_DDR_PLL_BYPASS);
        sdc[1175..1175 + S19K_BL2_DDR_PLL.len()].copy_from_slice(S19K_BL2_DDR_PLL);
        sdc[1190..1190 + S19K_BL2_DDR_CLK_ERR.len()].copy_from_slice(S19K_BL2_DDR_CLK_ERR);
        sdc[1210..1210 + S19K_BL2_DDR_TIMING_ERR.len()].copy_from_slice(S19K_BL2_DDR_TIMING_ERR);
        assert!(admit_s19k_bl2_ddr_ssc_pll(&sdc).is_ok());
        assert!(refuse_s19k_bl2_ddr_ssc_as_hash_pll().is_err());
        assert!(refuse_s19k_bl2_ddr_pll_bypass_as_asic_pll().is_err());
        assert!(refuse_s19k_bl2_ddr_clk_err_as_uart_baud().is_err());
        assert_eq!(S19K_BL2_DDR_SSC_OFF, 42_664);
        assert_eq!(S19K_BL2_DDR_PLL_BYPASS_OFF, 42_710);
        assert_eq!(S19K_BL2_DDR_PLL_OFF, 42_786);
        assert_eq!(S19K_BL2_DDR_CLK_ERR_OFF, 42_961);
        assert_eq!(S19K_BL2_DDR_TIMING_ERR_OFF, 42_977);
        sdc[1230..1230 + S19K_BL2_BIST_TEST.len()].copy_from_slice(S19K_BL2_BIST_TEST);
        sdc[1250..1250 + S19K_BL2_BIST_PASS.len()].copy_from_slice(S19K_BL2_BIST_PASS);
        sdc[1265..1265 + S19K_BL2_BIST_FAIL.len()].copy_from_slice(S19K_BL2_BIST_FAIL);
        sdc[1280..1280 + S19K_BL2_DDR_INIT_FAILED.len()].copy_from_slice(S19K_BL2_DDR_INIT_FAILED);
        assert!(admit_s19k_bl2_bist_test(&sdc).is_ok());
        assert!(refuse_s19k_bl2_bist_as_nand_bist().is_err());
        assert!(refuse_s19k_bl2_bist_as_nandrecovery().is_err());
        assert_eq!(S19K_BL2_BIST_TEST_OFF, 42_950);
        assert_eq!(S19K_BL2_BIST_PASS_OFF, 43_007);
        assert_eq!(S19K_BL2_BIST_FAIL_OFF, 43_016);
        assert_eq!(S19K_BL2_DDR_INIT_FAILED_OFF, 43_025);
        sdc[S19K_BL2_CHL_OFF..S19K_BL2_CHL_OFF + S19K_BL2_CHL.len()].copy_from_slice(S19K_BL2_CHL);
        sdc[S19K_BL2_CHL_MHZ_OFF..S19K_BL2_CHL_MHZ_OFF + S19K_BL2_CHL_MHZ.len()]
            .copy_from_slice(S19K_BL2_CHL_MHZ);
        assert!(admit_s19k_bl2_dram_chl_mhz(&sdc).is_ok());
        assert!(refuse_s19k_bl2_chl_as_hash_chain().is_err());
        assert!(refuse_s19k_bl2_chl_mhz_as_hash_clock().is_err());
        assert_eq!(S19K_BL2_CHL_OFF, 42_996);
        assert_eq!(S19K_BL2_CHL_MHZ_OFF, 43_003);
        sdc[S19K_BL2_DDR_RESET_OFF..S19K_BL2_DDR_RESET_OFF + S19K_BL2_DDR_RESET.len()]
            .copy_from_slice(S19K_BL2_DDR_RESET);
        sdc[S19K_BL2_ADDRBUS_FAIL_OFF..S19K_BL2_ADDRBUS_FAIL_OFF + S19K_BL2_ADDRBUS_FAIL.len()]
            .copy_from_slice(S19K_BL2_ADDRBUS_FAIL);
        sdc[S19K_BL2_DEVICE_FAIL_OFF..S19K_BL2_DEVICE_FAIL_OFF + S19K_BL2_DEVICE_FAIL.len()]
            .copy_from_slice(S19K_BL2_DEVICE_FAIL);
        assert!(admit_s19k_bl2_ddr_reset(&sdc).is_ok());
        assert!(refuse_s19k_bl2_reset_as_gpio437().is_err());
        assert!(refuse_s19k_bl2_reset_as_hb_reset().is_err());
        assert_eq!(S19K_BL2_DDR_RESET_OFF, 43_044);
        assert_eq!(S19K_BL2_ADDRBUS_FAIL_OFF, 43_054);
        assert_eq!(S19K_BL2_DEVICE_FAIL_OFF, 43_098);
        sdc[S19K_BL2_SDIO_DEBUG_OFF..S19K_BL2_SDIO_DEBUG_OFF + S19K_BL2_SDIO_DEBUG.len()]
            .copy_from_slice(S19K_BL2_SDIO_DEBUG);
        sdc[S19K_BL2_NO_SDIO_DEBUG_OFF..S19K_BL2_NO_SDIO_DEBUG_OFF + S19K_BL2_NO_SDIO_DEBUG.len()]
            .copy_from_slice(S19K_BL2_NO_SDIO_DEBUG);
        sdc[S19K_BL2_CUSTOMER_ID_OFF..S19K_BL2_CUSTOMER_ID_OFF + S19K_BL2_CUSTOMER_ID.len()]
            .copy_from_slice(S19K_BL2_CUSTOMER_ID);
        assert!(admit_s19k_bl2_sdio_customer_id(&sdc).is_ok());
        assert!(refuse_s19k_bl2_sdio_as_miner_identity().is_err());
        assert!(refuse_s19k_bl2_customer_id_as_78_chassis().is_err());
        assert_eq!(S19K_BL2_SDIO_DEBUG_OFF, 43_177);
        assert_eq!(S19K_BL2_NO_SDIO_DEBUG_OFF, 43_205);
        assert_eq!(S19K_BL2_CUSTOMER_ID_OFF, 43_236);
        sdc[S19K_BL2_MEMDUMP_OFF..S19K_BL2_MEMDUMP_OFF + S19K_BL2_MEMDUMP.len()]
            .copy_from_slice(S19K_BL2_MEMDUMP);
        sdc[S19K_BL2_BL2Z_PTR_OFF..S19K_BL2_BL2Z_PTR_OFF + S19K_BL2_BL2Z_PTR.len()]
            .copy_from_slice(S19K_BL2_BL2Z_PTR);
        sdc[S19K_BL2_NO_BL2Z_OFF..S19K_BL2_NO_BL2Z_OFF + S19K_BL2_NO_BL2Z.len()]
            .copy_from_slice(S19K_BL2_NO_BL2Z);
        sdc[S19K_BL2_JUMP_BL2Z_OFF..S19K_BL2_JUMP_BL2Z_OFF + S19K_BL2_JUMP_BL2Z.len()]
            .copy_from_slice(S19K_BL2_JUMP_BL2Z);
        assert!(admit_s19k_bl2_memdump_bl2z(&sdc).is_ok());
        assert!(refuse_s19k_bl2_memdump_as_nandrecovery().is_err());
        assert!(refuse_s19k_bl2_bl2z_as_78_nand().is_err());
        assert_eq!(S19K_BL2_MEMDUMP_OFF, 43_267);
        assert_eq!(S19K_BL2_JUMP_BL2Z_OFF, 43_307);
        sdc[S19K_BL2_RETURN_BL2_OFF..S19K_BL2_RETURN_BL2_OFF + S19K_BL2_RETURN_BL2.len()]
            .copy_from_slice(S19K_BL2_RETURN_BL2);
        sdc[S19K_BL2_USB_MODE_OFF..S19K_BL2_USB_MODE_OFF + S19K_BL2_USB_MODE.len()]
            .copy_from_slice(S19K_BL2_USB_MODE);
        sdc[S19K_BL2_FIP_HDR_CHK_OFF..S19K_BL2_FIP_HDR_CHK_OFF + S19K_BL2_FIP_HDR_CHK.len()]
            .copy_from_slice(S19K_BL2_FIP_HDR_CHK);
        sdc[S19K_BL2_BL3X_CHK_OFF..S19K_BL2_BL3X_CHK_OFF + S19K_BL2_BL3X_CHK.len()]
            .copy_from_slice(S19K_BL2_BL3X_CHK);
        assert!(admit_s19k_bl2_fip_usb_mode(&sdc).is_ok());
        assert!(refuse_s19k_bl2_usb_mode_as_aml_install().is_err());
        assert!(refuse_s19k_bl2_fip_chk_as_nandrecovery().is_err());
        assert_eq!(S19K_BL2_RETURN_BL2_OFF, 43_321);
        assert_eq!(S19K_BL2_USB_MODE_OFF, 43_336);
        assert_eq!(S19K_BL2_FIP_HDR_CHK_OFF, 43_347);
        assert_eq!(S19K_BL2_BL3X_CHK_OFF, 43_370);
        sdc[S19K_BL2_FIP_TMP_HDR_OFF..S19K_BL2_FIP_TMP_HDR_OFF + S19K_BL2_FIP_TMP_HDR.len()]
            .copy_from_slice(S19K_BL2_FIP_TMP_HDR);
        sdc[S19K_BL2_BL31_OFF..S19K_BL2_BL31_OFF + S19K_BL2_BL31.len()]
            .copy_from_slice(S19K_BL2_BL31);
        sdc[S19K_BL2_NEVER_HERE_OFF..S19K_BL2_NEVER_HERE_OFF + S19K_BL2_NEVER_HERE.len()]
            .copy_from_slice(S19K_BL2_NEVER_HERE);
        assert!(admit_s19k_bl2_fip_tmp_bl31(&sdc).is_ok());
        assert!(refuse_s19k_bl2_fip_tmp_as_aml_install().is_err());
        assert!(refuse_s19k_bl2_bl31_as_nandrecovery().is_err());
        assert!(refuse_s19k_bl2_never_here_as_operator_install().is_err());
        assert_eq!(S19K_BL2_FIP_TMP_HDR_OFF, 43_381);
        assert_eq!(S19K_BL2_BL31_OFF, 43_393);
        assert_eq!(S19K_BL2_NEVER_HERE_OFF, 43_406);
        sdc[S19K_BL2_ERR_SHA_TABLE_OFF..S19K_BL2_ERR_SHA_TABLE_OFF + S19K_BL2_ERR_SHA_TABLE.len()]
            .copy_from_slice(S19K_BL2_ERR_SHA_TABLE);
        let sha_labels = parse_s19k_bl2_err_sha_labels(&sdc).unwrap();
        assert_eq!(
            sha_labels,
            ["Err:sha5", "Err:sha4", "Err:sha3", "Err:sha1", "Err:sha2"]
        );
        assert!(admit_s19k_bl2_err_sha_table(&sdc).is_ok());
        assert!(refuse_s19k_bl2_err_sha_as_verify_sha1().is_err());
        assert!(refuse_s19k_bl2_err_sha_as_decrypt_key().is_err());
        assert_eq!(S19K_BL2_ERR_SHA_TABLE_OFF, 43_464);
        assert_eq!(S19K_BL2_ERR_SHA_TABLE.len(), 50);
        sdc[S19K_BL2_NEVER_BE_HERE_OFF..S19K_BL2_NEVER_BE_HERE_OFF + S19K_BL2_NEVER_BE_HERE.len()]
            .copy_from_slice(S19K_BL2_NEVER_BE_HERE);
        sdc[S19K_BL2_USB_LABEL_OFF..S19K_BL2_USB_LABEL_OFF + S19K_BL2_USB_LABEL.len()]
            .copy_from_slice(S19K_BL2_USB_LABEL);
        sdc[S19K_BL2_SKIP_USB_OFF..S19K_BL2_SKIP_USB_OFF + S19K_BL2_SKIP_USB.len()]
            .copy_from_slice(S19K_BL2_SKIP_USB);
        assert!(admit_s19k_bl2_never_be_here_skip_usb(&sdc).is_ok());
        assert!(refuse_s19k_bl2_never_be_here_as_operator_install().is_err());
        assert!(refuse_s19k_bl2_skip_usb_as_aml_install().is_err());
        assert_eq!(S19K_BL2_NEVER_BE_HERE_OFF, 43_530);
        assert_eq!(S19K_BL2_USB_LABEL_OFF, 43_552);
        assert_eq!(S19K_BL2_SKIP_USB_OFF, 43_562);
        assert_ne!(S19K_BL2_NEVER_BE_HERE, S19K_BL2_NEVER_HERE);
        sdc[S19K_BL2_DUMP_TABLE_OFF..S19K_BL2_DUMP_TABLE_OFF + S19K_BL2_DUMP_TABLE.len()]
            .copy_from_slice(S19K_BL2_DUMP_TABLE);
        let dump_labels = parse_s19k_bl2_dump_labels(&sdc).unwrap();
        assert_eq!(
            dump_labels,
            [
                "-W[0x",
                "]:0x",
                ",R:0x",
                "DATA",
                "ADDR",
                "ADDR2",
                "ADDR3",
                "Total Size 0x",
                "FULL",
                "FULL2"
            ]
        );
        assert!(admit_s19k_bl2_reg_dump(&sdc).is_ok());
        assert!(refuse_s19k_bl2_reg_dump_as_hash_uart().is_err());
        assert!(refuse_s19k_bl2_reg_dump_as_nandrecovery().is_err());
        assert_eq!(S19K_BL2_DUMP_TABLE_OFF, 43_577);
        assert_eq!(S19K_BL2_DUMP_TABLE.len(), 64);
        let mut usb_ctrl = crate::s19k_aml_dtb::S19K_USB_UBOOT_TXFIFO_FULL.to_vec();
        usb_ctrl.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_SPEED_ENUM);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_txfifo_speed_enum(&usb_ctrl).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_txfifo_as_hash_fifo().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_speed_enum_as_chip_enum().is_err());
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_addr_mask(
            crate::s19k_aml_dtb::S19K_USB_UBOOT_ADDR_MASK
        )
        .is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_addr_mask_as_nandrecovery().is_err());
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_ramoops(
            crate::s19k_aml_dtb::S19K_USB_UBOOT_RAMOOPS
        )
        .is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ramoops_as_recover_env().is_err());
        let mut cortex = crate::s19k_aml_dtb::S19K_USB_UBOOT_EXCEPTION.to_vec();
        cortex.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_PSTACK);
        cortex.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_CORTEX_TASK);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_cortex_exception(&cortex).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_cortex_exception_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_cortex_task_as_nandrecovery().is_err());
        let mut ec = crate::s19k_aml_dtb::S19K_USB_UBOOT_WAIT_EVT.to_vec();
        ec.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_TASK_READY);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_ec_task_table(&ec).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ec_task_table_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ec_task_table_as_nandrecovery().is_err());
        let mut svc = crate::s19k_aml_dtb::S19K_USB_UBOOT_MUTEX_LOCK.to_vec();
        svc.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_SVC_HANDLER);
        svc.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_TASK_EXIT);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_ec_mutex_svc(&svc).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ec_mutex_svc_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ec_mutex_svc_as_nandrecovery().is_err());
        let mut ov = crate::s19k_aml_dtb::S19K_USB_UBOOT_TASK_SET_EVENT.to_vec();
        ov.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_STACK_OV);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_ec_task_set_stack(&ov).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ec_task_set_stack_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ec_stack_ov_as_nandrecovery().is_err());
        let mut idle = crate::s19k_aml_dtb::S19K_USB_UBOOT_TASKS_READY.to_vec();
        idle.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_IDLE);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_ec_idle(&idle).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ec_idle_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ec_idle_as_nandrecovery().is_err());
        let mut hooks = crate::s19k_aml_dtb::S19K_USB_UBOOT_HOOKS.to_vec();
        hooks.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_TIMERTASK);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_ec_hooks_timer(&hooks).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ec_hooks_timer_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ec_hooks_timer_as_nandrecovery().is_err());
        let mut mbox = crate::s19k_aml_dtb::S19K_USB_UBOOT_LOWMAILBOX.to_vec();
        mbox.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_HIGHMAILBOX);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_ec_mailbox(&mbox).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ec_mailbox_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ec_mailbox_as_nandrecovery().is_err());
        let mut sec = crate::s19k_aml_dtb::S19K_USB_UBOOT_SECMAILBOX.to_vec();
        sec.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_USERLOWTASK);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_ec_sec_userlow(&sec).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ec_sec_userlow_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ec_sec_userlow_as_nandrecovery().is_err());
        let mut high = crate::s19k_aml_dtb::S19K_USB_UBOOT_USERHIGHTASK.to_vec();
        high.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_USERSECURETASK);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_ec_user_high_secure(&high).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ec_user_high_secure_as_hash_uart().is_err());
        assert!(
            crate::s19k_aml_dtb::refuse_s19k_usb_ec_user_high_secure_as_nandrecovery().is_err()
        );
        let mut adc = crate::s19k_aml_dtb::S19K_USB_UBOOT_TIMERFORADC.to_vec();
        adc.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_EMPTY_EFUSE);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_ec_timer_efuse(&adc).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ec_timer_efuse_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ec_timer_efuse_as_nandrecovery().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_empty_efuse_as_otp_decrypt().is_err());
        let mut es = crate::s19k_aml_dtb::S19K_USB_UBOOT_ES_CHIP.to_vec();
        es.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_DVFS_VOL);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_es_chip_dvfs(&es).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_es_chip_dvfs_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_es_chip_dvfs_as_nandrecovery().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_dvfs_as_hash_pll().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_es_chip_as_miner_identity().is_err());
        let mut dvfs = crate::s19k_aml_dtb::S19K_USB_UBOOT_GET_INIT_DVFS.to_vec();
        dvfs.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_GET_DVFS);
        dvfs.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_FREQ_TO_IDX);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_dvfs_freq(&dvfs).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_dvfs_freq_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_dvfs_freq_as_nandrecovery().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_freq_to_idx_as_hash_pll().is_err());
        let mut syspll = crate::s19k_aml_dtb::S19K_USB_UBOOT_SET_DVFS_INFO.to_vec();
        syspll.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_USE_SYS_PLL);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_dvfs_sys_pll(&syspll).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_dvfs_sys_pll_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_dvfs_sys_pll_as_nandrecovery().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_use_sys_pll_as_hash_pll().is_err());
        let mut fix = crate::s19k_aml_dtb::S19K_USB_UBOOT_USE_FIX_CLK.to_vec();
        fix.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_SYS_PLL_LOCK);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_fix_clk_pll_lock(&fix).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_fix_clk_pll_lock_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_fix_clk_pll_lock_as_nandrecovery().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_sys_pll_lock_as_hash_pll().is_err());
        let mut therm = crate::s19k_aml_dtb::S19K_USB_UBOOT_SET_DVFS.to_vec();
        therm.push(0);
        therm.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_CPU_CLK_SUSPEND);
        therm.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_SET_DVFS_BUSY);
        therm.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_HIGH_TASK_SET_DVFS);
        therm.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_AML_THERMAL);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_dvfs_thermal(&therm).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_dvfs_thermal_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_dvfs_thermal_as_nandrecovery().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_cpu_clk_suspend_as_hash_pll().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_aml_thermal_as_hash_thermal().is_err());
        let mut bl30 = crate::s19k_aml_dtb::S19K_USB_UBOOT_CPU_CLK_RESUME.to_vec();
        bl30.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_HIGH_TASK_INIT_DVFS);
        bl30.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_BL30_THERMAL);
        bl30.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_JTAG_FORCE);
        bl30.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_EFUSE_PW_EN);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_bl30_jtag_efuse(&bl30).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_bl30_jtag_efuse_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_bl30_jtag_efuse_as_nandrecovery().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_cpu_clk_resume_as_hash_pll().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_bl30_thermal_as_hash_thermal().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_efuse_pw_en_as_otp_decrypt().is_err());
        let mut trim = crate::s19k_aml_dtb::S19K_USB_UBOOT_HIGH_TASK_INIT_DVFSTBL.to_vec();
        trim.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_DISABLE_M3_JTAG);
        trim.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_EFUSE_BITS_DISABLED);
        trim.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_BL30_THERMAL_TRIM);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_dvfstbl_jtag_trim(&trim).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_dvfstbl_jtag_trim_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_dvfstbl_jtag_trim_as_nandrecovery().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_efuse_bits_disabled_as_otp_decrypt().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_bl30_thermal_trim_as_hash_thermal().is_err());
        let mut gxl = crate::s19k_aml_dtb::S19K_USB_UBOOT_DISABLE_A53_JTAG.to_vec();
        gxl.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_ENABLE_M3_JTAG);
        gxl.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_BL30_THERMAL_CALIB);
        gxl.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_GXL_ES_THERMAL);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_a53_gxl_thermal(&gxl).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_a53_gxl_thermal_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_a53_gxl_thermal_as_nandrecovery().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_bl30_thermal_calib_as_hash_thermal().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_gxl_es_thermal_as_miner_identity().is_err());
        let mut untrim = crate::s19k_aml_dtb::S19K_USB_UBOOT_ENABLE_A53_JTAG.to_vec();
        untrim.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_JTAG_TO_AO);
        untrim.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_BL30_THERMAL_CALIB_ERR);
        untrim.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_BL30_UNTRIMMED);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_a53_ao_untrimmed(&untrim).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_a53_ao_untrimmed_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_a53_ao_untrimmed_as_nandrecovery().is_err());
        assert!(
            crate::s19k_aml_dtb::refuse_s19k_usb_bl30_thermal_calib_err_as_hash_thermal().is_err()
        );
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_bl30_untrimmed_as_hash_thermal().is_err());
        let mut ee = crate::s19k_aml_dtb::S19K_USB_UBOOT_JTAG_TO_EE.to_vec();
        ee.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_INCORRECT_PASSWORD);
        ee.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_BL30_THERMAL_CAL_DATA);
        ee.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_BL30_AXG_VER);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_ee_pw_axg(&ee).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ee_pw_axg_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ee_pw_axg_as_nandrecovery().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_incorrect_password_as_miner_auth().is_err());
        assert!(
            crate::s19k_aml_dtb::refuse_s19k_usb_bl30_thermal_cal_data_as_hash_thermal().is_err()
        );
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_bl30_axg_ver_as_miner_identity().is_err());
        let mut inv = crate::s19k_aml_dtb::S19K_USB_UBOOT_INVALID_INPUT.to_vec();
        inv.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_PLEASE_TRY_AGAIN);
        inv.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_BL30_AXG_THERMAL0);
        inv.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_BL30_THERMAL_INIT_ERR);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_invalid_try_thermal0(&inv).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_invalid_try_thermal0_as_hash_uart().is_err());
        assert!(
            crate::s19k_aml_dtb::refuse_s19k_usb_invalid_try_thermal0_as_nandrecovery().is_err()
        );
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_invalid_input_as_miner_auth().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_bl30_axg_thermal0_as_hash_thermal().is_err());
        assert!(
            crate::s19k_aml_dtb::refuse_s19k_usb_bl30_thermal_init_err_as_hash_thermal().is_err()
        );
        let mut scpi = crate::s19k_aml_dtb::S19K_USB_UBOOT_OTP_BLOCK11.to_vec();
        scpi.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_SCPI_CSS);
        scpi.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_DDR_SUSPEND);
        scpi.extend_from_slice(crate::s19k_aml_dtb::S19K_USB_UBOOT_GCM_TAG);
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_scpi_ddr_gcm(&scpi).is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_scpi_ddr_gcm_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_scpi_ddr_gcm_as_nandrecovery().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_gcm_tag_as_android_decrypt().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_scpi_as_hash_uart().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_ddr_suspend_as_hashboard_rail().is_err());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_otp_block_as_gpio437().is_err());
        assert!(crate::s19k_aml_dtb::admit_s19k_usb_uboot_bl30_axg_stamp(
            crate::s19k_aml_dtb::S19K_USB_UBOOT_BL30_AXG_STAMP
        )
        .is_ok());
        assert!(crate::s19k_aml_dtb::refuse_s19k_usb_bl30_stamp_as_miner_identity().is_err());
        assert_eq!(crate::s19k_aml_dtb::S19K_USB_UBOOT_OTP_BLOCK11_OFF, 45_261);
        assert_eq!(crate::s19k_aml_dtb::S19K_USB_UBOOT_SCPI_CSS_OFF, 45_328);
        assert_eq!(crate::s19k_aml_dtb::S19K_USB_UBOOT_DDR_SUSPEND_OFF, 45_483);
        assert_eq!(crate::s19k_aml_dtb::S19K_USB_UBOOT_GCM_TAG_OFF, 45_797);
        assert_eq!(
            crate::s19k_aml_dtb::S19K_USB_UBOOT_BL30_AXG_STAMP_OFF,
            46_256
        );
        sdc.extend_from_slice(usb_tail);
        assert!(admit_s19k_sdc_usb_uboot_suffix(&sdc, usb_tail).is_ok());
        assert!(refuse_s19k_sdc_usb_uboot_as_same_image(818_688, 769_024).is_err());
        assert_eq!(S19K_SDC_USB_UBOOT_PREFIX_BYTES, 97 * 512);
        assert!(refuse_s19k_aml_dtb_as_plaintext_fdt(&[0x5D, 0xC7, 0x5D, 0x64]).is_err());
        assert!(refuse_s19k_aml_dtb_as_plaintext_fdt(b"AML_").is_ok());
        assert!(refuse_s19k_aml_dtb_as_gpio437(&[0x5D, 0xC7]).is_err());
        let mut boot_item = vec![0u8; S19K_AML_UPGRADE_ITEM_STRIDE];
        boot_item[0..4].copy_from_slice(&9u32.to_le_bytes());
        boot_item[0x10..0x18].copy_from_slice(&S19K_AML_UPGRADE_ITEM9_BOOT_OFF.to_le_bytes());
        boot_item[0x18..0x20].copy_from_slice(&S19K_AML_UPGRADE_ITEM9_BOOT_SIZE.to_le_bytes());
        boot_item[0x20..0x29].copy_from_slice(b"PARTITION");
        boot_item[0x120..0x124].copy_from_slice(b"boot");
        assert!(admit_s19k_aml_upgrade_boot_item(
            &parse_s19k_aml_upgrade_item(&boot_item).unwrap()
        )
        .is_ok());
        let mut rec_item = vec![0u8; S19K_AML_UPGRADE_ITEM_STRIDE];
        rec_item[0..4].copy_from_slice(&17u32.to_le_bytes());
        rec_item[0x10..0x18].copy_from_slice(&S19K_AML_UPGRADE_ITEM17_RECOVERY_OFF.to_le_bytes());
        rec_item[0x18..0x20].copy_from_slice(&S19K_AML_UPGRADE_ITEM17_RECOVERY_SIZE.to_le_bytes());
        rec_item[0x20..0x29].copy_from_slice(b"PARTITION");
        rec_item[0x120..0x128].copy_from_slice(b"recovery");
        assert!(admit_s19k_aml_upgrade_recovery_item(
            &parse_s19k_aml_upgrade_item(&rec_item).unwrap()
        )
        .is_ok());
        assert!(refuse_s19k_factory_boot_as_20231108_datafile(
            S19K_AML_UPGRADE_ITEM9_BOOT_SIZE as usize
        )
        .is_err());
        assert!(refuse_s19k_aml_img_as_updateporc(b"AmlImagePack USB DDR").is_err());
        assert!(refuse_s19k_aml_img_as_updateporc(b"xxupdateporc.sh").is_ok());
        assert!(refuse_s19k_aml_img_as_4cc0_or_uart_trans(b"S19k-Pro_BHB56XXX").is_err());
        assert!(refuse_s19k_aml_uboot_identity_as_4cc0(S19K_AML_UPGRADE_UBOOT_IDENTITY).is_err());
        assert!(refuse_s19k_aml_android_boot_as_nandrecovery(S19K_ANDROID_BOOT_MAGIC).is_err());
        assert!(refuse_s19k_embedded_ini_as_operator_sd_ini(false).is_err());
        assert!(refuse_s19k_embedded_ini_as_operator_sd_ini(true).is_ok());
        assert_eq!(S19K_AML_UPGRADE_PLATFORM, "Platform:0x0811");
        assert_eq!(S19K_AML_UPGRADE_SECURE_BOOT, "secure_boot_set");
        assert_eq!(
            classify_s19k_upgrade_blob("rootfs.img", &UIMAGE_MAGIC),
            S19kUpgradeBlobKind::UimageRootfs
        );
        assert!(refuse_s19k_stock_web_rail_as_unsigned().is_err());
        assert!(!S19K_STOCK_UPDATEPORC_IN_EXTRACT);
        assert!(!S19K_AML_UPDATEPORC_IN_HELD_CORPUS);
        assert_eq!(S19K_STOCK_DAEMONC_BYTES, 7240);
        assert!(refuse_s19k_20231108_bmu_as_plaintext_porc(b"\x26\x01ciphertext").is_err());
        assert!(refuse_s19k_20231108_bmu_as_plaintext_porc(b"xxupdateporc.sh").is_ok());
        assert_eq!(
            s19k_single_bmu_expected_size(1, S19K_20231108_DATAFILE_SIZE),
            S19K_STOCK_20231108_BMU_BYTES as u64
        );
        assert!(refuse_s19k_bmu_0x4000_as_single_component_start().is_err());
        assert!(refuse_s19k_android_ramdisk_as_plaintext_gzip(&[0x04, 0x45]).is_err());
        assert!(refuse_s19k_android_ramdisk_as_plaintext_gzip(&[0x1F, 0x8B]).is_ok());
        let mut hdr = vec![0u8; S19K_SINGLE_BMU_HEADER_LEN];
        hdr[0] = S19K_BTMU_MAGIC;
        hdr[2..10].copy_from_slice(&S19K_STOCK_20231108_MINER_TYPE_HASH.to_le_bytes());
        hdr[11..13].copy_from_slice(&S19K_20231108_CONTENT_BITMAP.to_be_bytes());
        hdr[S19K_SINGLE_BMU_PEM_LEN_OFF..S19K_SINGLE_BMU_PEM_LEN_OFF + 2]
            .copy_from_slice(&451u16.to_be_bytes());
        hdr[S19K_SINGLE_BMU_FILE_COUNT_OFF] = 1;
        hdr[S19K_SINGLE_BMU_FILE_DESC_OFF] = S19K_SINGLE_BMU_TYPE_DATAFILE;
        hdr[S19K_SINGLE_BMU_FILE_DESC_OFF + 1..S19K_SINGLE_BMU_FILE_DESC_OFF + 5]
            .copy_from_slice(&S19K_20231108_DATAFILE_SIZE.to_be_bytes());
        let toc = parse_s19k_single_bmu_toc(&hdr).unwrap();
        assert_eq!(toc.files[0].type_id, 9);
        assert_eq!(toc.files[0].size, S19K_20231108_DATAFILE_SIZE);
        assert_eq!(toc.files[0].data_offset, 0x800);
        let mut boot = vec![0u8; 80];
        boot[..8].copy_from_slice(S19K_ANDROID_BOOT_MAGIC);
        boot[8..12].copy_from_slice(&S19K_20231108_KERNEL_SIZE.to_le_bytes());
        boot[12..16].copy_from_slice(&S19K_20231108_KERNEL_ADDR.to_le_bytes());
        boot[16..20].copy_from_slice(&S19K_20231108_RAMDISK_SIZE.to_le_bytes());
        boot[24..28].copy_from_slice(&S19K_20231108_SECOND_SIZE.to_le_bytes());
        boot[36..40].copy_from_slice(&S19K_20231108_PAGE_SIZE.to_le_bytes());
        boot[64..64 + S19K_20231108_CMDLINE.len()].copy_from_slice(S19K_20231108_CMDLINE);
        let ah = parse_s19k_android_boot_header(&boot).unwrap();
        assert_eq!(ah.kernel_size, S19K_20231108_KERNEL_SIZE);
        assert_eq!(ah.page_size, 2048);
        assert!(parse_s19k_android_boot_header(b"NOTANDROID").is_err());
        assert!(!S19K_FILEPARSER_IN_78_EXTRACT);
        assert!(!S19K_FILEPARSER_IN_AWESOME_AML_NAND);
        assert!(refuse_held_fileparser_as_s19k_android_decoder().is_err());
        assert_eq!(HELD_CVITEK_FILEPARSER_BYTES, 20184);
        assert_eq!(HELD_CVITEK_FILEPARSER_DATAFILE_OFF, 15460);
        let mut fp = vec![0u8; HELD_CVITEK_FILEPARSER_DATAFILE_OFF + 8];
        fp[HELD_CVITEK_FILEPARSER_DATAFILE_OFF..].copy_from_slice(b"datafile");
        assert!(
            admit_held_fileparser_names_datafile(&fp, HELD_CVITEK_FILEPARSER_DATAFILE_OFF).is_ok()
        );
        fp[0..7].copy_from_slice(b"ANDROID");
        assert!(
            admit_held_fileparser_names_datafile(&fp, HELD_CVITEK_FILEPARSER_DATAFILE_OFF).is_err()
        );
        let mut packed = hdr.clone();
        packed.extend_from_slice(&boot);
        packed.resize(
            S19K_SINGLE_BMU_HEADER_LEN + S19K_20231108_DATAFILE_SIZE as usize,
            0,
        );
        packed[S19K_20231108_DATAFILE_OFF..S19K_20231108_DATAFILE_OFF + 8]
            .copy_from_slice(S19K_ANDROID_BOOT_MAGIC);
        let extracted = extract_s19k_single_bmu_datafile(&packed).unwrap();
        assert_eq!(extracted.len(), S19K_20231108_DATAFILE_SIZE as usize);
        assert_eq!(&extracted[..8], S19K_ANDROID_BOOT_MAGIC);
        assert!(extract_s19k_single_bmu_datafile(&hdr).is_err());
        let mut page0 = vec![0u8; 0x430];
        page0[0x400..0x408].copy_from_slice(S19K_AMLSECU_MAGIC);
        page0[0x408..0x40C].copy_from_slice(&0x0905u32.to_le_bytes());
        page0[0x40C..0x410].copy_from_slice(&3u32.to_le_bytes());
        page0[0x410..0x420].copy_from_slice(S19K_20231108_AMLSECU_STAMP_TIME);
        page0[0x420..0x424].copy_from_slice(&0x800u32.to_le_bytes());
        page0[0x428..0x42C].copy_from_slice(&S19K_20231108_KERNEL_SIZE.to_le_bytes());
        let stamp = parse_s19k_android_amlsecu_stamp(&page0).unwrap();
        assert_eq!(stamp.declared_header_len, 3);
        assert_eq!(stamp.page_size, 0x800);
        assert_eq!(stamp.kernel_size_repeat, S19K_20231108_KERNEL_SIZE);
        assert!(refuse_s19k_amlsecu_stamp_as_s21_decrypt_container(stamp).is_err());
        page0[0x410..0x420].copy_from_slice(S19K_FACTORY_AMLSECU_BOOT_TIME);
        assert!(parse_s19k_android_amlsecu_stamp(&page0).is_err());
        let (raw, time) = parse_s19k_android_amlsecu_stamp_raw(&page0).unwrap();
        assert_eq!(raw.declared_header_len, 3);
        assert_eq!(
            classify_s19k_amlsecu_time(&time).unwrap(),
            S19kAmlsecuImageKind::FactorySdBoot
        );
        assert!(
            refuse_s19k_factory_amlsecu_as_20231108_bmu(S19kAmlsecuImageKind::FactorySdBoot)
                .is_err()
        );
        assert!(
            refuse_s19k_factory_amlsecu_as_20231108_bmu(S19kAmlsecuImageKind::Bmu20231108).is_ok()
        );
        page0[0x410..0x420].copy_from_slice(S19K_FACTORY_AMLSECU_RECOVERY_TIME);
        let (_, rtime) = parse_s19k_android_amlsecu_stamp_raw(&page0).unwrap();
        assert_eq!(
            classify_s19k_amlsecu_time(&rtime).unwrap(),
            S19kAmlsecuImageKind::FactorySdRecovery
        );
        let factory_boot = S19kAndroidBootHdr {
            kernel_size: S19K_20231108_KERNEL_SIZE,
            kernel_addr: S19K_20231108_KERNEL_ADDR,
            ramdisk_size: S19K_FACTORY_BOOT_RAMDISK_SIZE,
            ramdisk_addr: S19K_20231108_RAMDISK_ADDR,
            second_size: S19K_20231108_SECOND_SIZE,
            second_addr: S19K_20231108_SECOND_ADDR,
            tags_addr: S19K_20231108_TAGS_ADDR,
            page_size: S19K_20231108_PAGE_SIZE,
        };
        assert!(admit_s19k_factory_android_boot_header(factory_boot).is_ok());
        let wrong_rd = S19kAndroidBootHdr {
            ramdisk_size: S19K_20231108_RAMDISK_SIZE,
            ..factory_boot
        };
        assert!(admit_s19k_factory_android_boot_header(wrong_rd).is_err());
        assert!(refuse_s19k_20231108_ramdisk_as_factory_boot(S19K_20231108_RAMDISK_SIZE).is_err());
        assert!(admit_s19k_factory_android_second_layout(
            S19K_20231108_PAGE_SIZE,
            S19K_20231108_KERNEL_SIZE,
            S19K_FACTORY_BOOT_RAMDISK_SIZE,
            S19K_FACTORY_BOOT_SECOND_OFF,
        )
        .is_ok());
        assert!(
            refuse_s19k_4k_ramdisk_off_as_factory_page2048(S19K_FACTORY_ANDROID_RAMDISK_OFF)
                .is_err()
        );
        assert_eq!(S19K_FACTORY_BOOT_RAMDISK_OFF, 0x5C1000);
        assert_eq!(S19K_FACTORY_BOOT_SECOND_OFF, 12_875_776);
        let mut second = vec![0u8; S19K_20231108_SECOND_SIZE as usize];
        second[..4].copy_from_slice(&S19K_FACTORY_BOOT_SECOND_HEAD);
        assert!(admit_s19k_factory_android_second_head(&second).is_ok());
        assert!(refuse_s19k_factory_second_as_plaintext_android(&second).is_err());
        let factory_rec = S19kAndroidBootHdr {
            ramdisk_size: 0,
            ..factory_boot
        };
        assert!(admit_s19k_factory_android_recovery_header(factory_rec).is_ok());
        assert!(refuse_s19k_factory_recovery_as_boot_ramdisk(factory_rec).is_err());
        assert!(refuse_s19k_factory_recovery_as_boot_ramdisk(factory_boot).is_ok());
        assert_eq!(S19K_FACTORY_ANDROID_RAMDISK_OFF, 0x5C1800);
        assert!(admit_s19k_factory_android_ramdisk_not_gzip(&[0x05, 0x60, 0x25, 0x0F]).is_ok());
        assert!(admit_s19k_factory_android_ramdisk_not_gzip(&[0x1F, 0x8B]).is_err());
        assert!(refuse_s19k_factory_android_page0_as_gpio437(b"ANDROID! init=/sbin/init").is_err());
        assert!(refuse_s19k_factory_android_as_s30v_full_slot(
            S19K_AML_UPGRADE_ITEM9_BOOT_SIZE,
            S19K_FACTORY_S30V_BOOT_SLOT_BYTES
        )
        .is_err());
        assert!(refuse_s19k_factory_android_as_s30v_full_slot(
            S19K_AML_UPGRADE_ITEM17_RECOVERY_SIZE,
            S19K_FACTORY_S30V_RECOVERY_SLOT_BYTES
        )
        .is_err());
        assert!(refuse_s19k_boot_decrypt_without_vendor_rsa().is_err());
        assert!(refuse_s19k_android_boot_as_mtd5_uimage(S19K_ANDROID_BOOT_MAGIC).is_err());
        assert!(refuse_s19k_android_boot_as_mtd5_uimage(&UIMAGE_MAGIC).is_ok());
        assert!(admit_s19k_uart_rescue_console("/dev/ttyS0", 115_200).is_ok());
        assert!(admit_s19k_uart_rescue_console("/dev/ttyS3", 115_200).is_err());
        assert!(admit_s19k_uart_rescue_console("/dev/ttyS0", 3_000_000).is_err());
        assert_eq!(S19K_78_CONSOLE_MMIO, 0xFF80_3000);
        assert!(REVERT.contains("27051956"));
        assert!(REVERT.contains("must contain exactly one uImage-like candidate"));
        assert_eq!(S19K_STOCK_UPDATEPORC_PATH, "/usr/sbin/updateporc.sh");
        assert_eq!(S19K_STOCK_MINER_ACT_SUCCESS, 2);
        assert_eq!(S19K_STOCK_MINER_ACT_CLEAR, 3);
        let upgrade_cgi =
            "file=$folder/update.bmu\n/usr/sbin/daemonc $file\necho 2 > /tmp/miner_act\n";
        let clear_cgi =
            "file=$folder/update.bmu\n/usr/sbin/daemonc $file\necho 3 > /tmp/miner_act\n";
        assert!(admit_s19k_stock_upgrade_cgi(upgrade_cgi, 2).is_ok());
        assert!(admit_s19k_stock_upgrade_cgi(clear_cgi, 3).is_ok());
        assert!(admit_s19k_stock_upgrade_cgi(upgrade_cgi, 3).is_err());
        let mut daemonc = vec![0u8; S19K_STOCK_DAEMONC_BYTES];
        daemonc[0] = 0x7F;
        daemonc[1..4].copy_from_slice(b"ELF");
        daemonc[4] = S19K_78_DAEMONC_ELF_CLASS;
        daemonc[18..20].copy_from_slice(&S19K_78_DAEMONC_MACHINE.to_le_bytes());
        let porc = S19K_STOCK_UPDATEPORC_PATH.as_bytes();
        let off = S19K_78_DAEMONC_PORC_STR_OFF as usize;
        daemonc[off..off + porc.len()].copy_from_slice(porc);
        assert!(admit_s19k_78_daemonc_elf(&daemonc).is_ok());
        assert!(admit_s19k_78_daemonc_elf(&[0u8; 8]).is_err());
        let prefix = S19K_STOCK_UPDATEPORC_PREFIX.as_bytes();
        daemonc[off..off + prefix.len()].copy_from_slice(prefix);
        daemonc[S19K_STOCK_DAEMONC_HOST_STR_OFF as usize
            ..S19K_STOCK_DAEMONC_HOST_STR_OFF as usize + S19K_STOCK_DAEMONC_LISTEN_HOST.len()]
            .copy_from_slice(S19K_STOCK_DAEMONC_LISTEN_HOST.as_bytes());
        daemonc[S19K_STOCK_DAEMONC_PORT_STR_OFF as usize
            ..S19K_STOCK_DAEMONC_PORT_STR_OFF as usize + 5]
            .copy_from_slice(b"22322");
        daemonc[S19K_STOCK_DAEMONC_ARGV0_OFF as usize..S19K_STOCK_DAEMONC_ARGV0_OFF as usize + 7]
            .copy_from_slice(b"daemonc");
        daemonc[S19K_STOCK_DAEMONS_ARGV0_OFF as usize..S19K_STOCK_DAEMONS_ARGV0_OFF as usize + 7]
            .copy_from_slice(b"daemons");
        daemonc[S19K_78_DAEMONC_MOVW_DAEMONC_OFF as usize
            ..S19K_78_DAEMONC_MOVW_DAEMONC_OFF as usize + 4]
            .copy_from_slice(&S19K_78_DAEMONC_MOVW_DAEMONC_INSN.to_le_bytes());
        daemonc[S19K_78_DAEMONC_LDR_ARGV1_OFF as usize..S19K_78_DAEMONC_LDR_ARGV1_OFF as usize + 4]
            .copy_from_slice(&S19K_78_DAEMONC_LDR_ARGV1_INSN.to_le_bytes());
        daemonc[S19K_78_DAEMONC_MOVW_DAEMONS_OFF as usize
            ..S19K_78_DAEMONC_MOVW_DAEMONS_OFF as usize + 4]
            .copy_from_slice(&S19K_78_DAEMONC_MOVW_DAEMONS_INSN.to_le_bytes());
        daemonc[S19K_78_DAEMONC_MOVW_HOST_OFF as usize..S19K_78_DAEMONC_MOVW_HOST_OFF as usize + 4]
            .copy_from_slice(&S19K_78_DAEMONC_MOVW_HOST_INSN.to_le_bytes());
        daemonc[S19K_78_DAEMONC_MOVW_PORT_OFF as usize..S19K_78_DAEMONC_MOVW_PORT_OFF as usize + 4]
            .copy_from_slice(&S19K_78_DAEMONC_MOVW_PORT_INSN.to_le_bytes());
        daemonc[S19K_78_DAEMONC_MOVW_PORC_OFF as usize..S19K_78_DAEMONC_MOVW_PORC_OFF as usize + 4]
            .copy_from_slice(&S19K_78_DAEMONC_MOVW_PORC_INSN.to_le_bytes());
        daemonc[S19K_78_DAEMONC_CMP_C8_OFF as usize..S19K_78_DAEMONC_CMP_C8_OFF as usize + 4]
            .copy_from_slice(&S19K_78_DAEMONC_CMP_C8_INSN.to_le_bytes());
        assert!(admit_s19k_daemonc_listen_is_localhost_22322(&daemonc).is_ok());
        assert!(admit_s19k_daemonc_argv0_roles(&daemonc).is_ok());
        assert!(admit_s19k_daemons_system_prefix(&daemonc).is_ok());
        assert!(admit_s19k_daemonc_client_cmp_http_200(&daemonc).is_ok());
        assert!(admit_s19k_78_daemonc_is_update_daemon(&daemonc, &daemonc).is_ok());
        assert!(refuse_s19k_daemonc_as_direct_nand_writer().is_err());
        assert_eq!(
            s19k_stock_daemons_system_line("/tmp/x/update.bmu"),
            "/usr/sbin/updateporc.sh /tmp/x/update.bmu"
        );
        assert_eq!(S19K_STOCK_DAEMONC_LISTEN_PORT, 22322);
        assert_eq!(S19K_STOCK_DAEMONC_HTTP_OK, 200);
        assert_eq!(S19K_78_DAEMONC_CMP_C8_INSN, 0xE350_00C8);
        let mut mtd2 = vec![0u8; S19K_78_MTD2_ANDROID_OFF + 8];
        mtd2[S19K_78_MTD2_ANDROID_OFF..S19K_78_MTD2_ANDROID_OFF + 8].copy_from_slice(b"ANDROID!");
        assert!(refuse_s19k_mtd2_as_updateporc_source(&mtd2).is_err());
        assert!(refuse_s19k_mtd2_as_fileparser_source(&mtd2).is_err());
        assert!(refuse_s19k_mtd2_as_uart_trans_source(&mtd2).is_err());
        assert!(refuse_s19k_mtd2_as_bitmain_pub_source(&mtd2).is_err());
        assert!(refuse_s19k_mtd2_as_ubi_stock_config(&mtd2).is_err());
        mtd2[0..10].copy_from_slice(b"updateporc");
        assert!(refuse_s19k_mtd2_as_updateporc_source(&mtd2).is_ok());
        let mut mtd3 = vec![0u8; 64];
        mtd3[0..4].copy_from_slice(S19K_78_MTD3_UBI_MAGIC);
        mtd3[4] = S19K_78_MTD3_UBI_VERSION;
        mtd3[16..20].copy_from_slice(&S19K_78_MTD3_VID_HDR_OFF.to_be_bytes());
        mtd3[20..24].copy_from_slice(&S19K_78_MTD3_DATA_OFF.to_be_bytes());
        mtd3[24..36].copy_from_slice(S19K_78_MTD3_CGMINER_CONF);
        mtd3[36..48].copy_from_slice(S19K_78_MTD3_NETWORK_CONF);
        assert!(admit_s19k_78_mtd3_is_ubi_stock_config(&mtd3).is_ok());
        assert!(admit_s19k_78_mtd3_geometry(S19K_78_MTD3_BYTES).is_ok());
        assert!(admit_s19k_78_mtd3_geometry(S19K_78_MTD2_BYTES).is_err());
        assert!(refuse_s19k_mtd3_as_updateporc_source(&mtd3).is_err());
        assert!(refuse_s19k_mtd3_as_fileparser_source(&mtd3).is_err());
        assert!(refuse_s19k_mtd3_as_uart_trans_source(&mtd3).is_err());
        assert!(refuse_s19k_mtd3_as_android_system(&mtd3).is_err());
        assert!(refuse_s19k_mtd3_miner_conf_as_separate_dent().is_err());
        mtd3[24..34].copy_from_slice(b"updateporc");
        assert!(refuse_s19k_mtd3_as_updateporc_source(&mtd3).is_ok());
        assert_eq!(S19K_78_MTD3_BYTES, 5_242_880);
        assert_eq!(S19K_78_MTD3_PEB_COUNT, 40);
        assert_eq!(S19K_78_MTD3_CGMINER_CONF_OFF, 3_283_000);
        assert_eq!(S19K_78_MTD3_NETWORK_CONF_OFF, 3_283_392);
        assert_eq!(S19K_78_MTD3_UBI_BANG_OFF, 395_264);
        assert_eq!(S19K_78_MTD3_UPDATEPORC_HITS, 0);
        assert_eq!(S19K_78_MTD3_FILEPARSER_HITS, 0);
        assert_eq!(S19K_78_MTD3_UART_TRANS_HITS, 0);
        assert!(!S19K_AML_UPDATEPORC_IN_HELD_CORPUS);
        let s97 = concat!(
            "local flag_after_boot=$(printf '\\\\x%x' $RECOVERY_FLAG_FIRST_BOOT)\n",
            "if [ \"$BOS_MODE\" = \"nand\" ]; then\n",
            "if [ \"$(nanddump -s $LOCAL_RECOVERY_FLAGS_OFFSET_BOS_LAYOUT -l 1 $env_mtd)\" = \"$(printf $flag_after_boot)\" ]; then\n",
            "flash_erase $env_mtd $LOCAL_RECOVERY_FLAGS_OFFSET_BOS_LAYOUT 1\n",
            "printf ... | nandwrite -p -s $LOCAL_RECOVERY_FLAGS_OFFSET_BOS_LAYOUT $env_mtd\n",
            "echo writing ${RECOVERY_FLAG_SUCCESSFUL}\n",
            "fi\n",
            "fi\n",
        );
        assert!(admit_s19k_s97_promotes_first_boot_to_successful(s97).is_ok());
        assert!(admit_s19k_s97_nanddump_02_before_write_03(s97).is_ok());
        let s97_no_dump = concat!(
            "local flag_after_boot=$(printf '\\\\x%x' $RECOVERY_FLAG_FIRST_BOOT)\n",
            "if [ \"$BOS_MODE\" = \"nand\" ]; then\n",
            "flash_erase $env_mtd $LOCAL_RECOVERY_FLAGS_OFFSET_BOS_LAYOUT 1\n",
            "printf ... | nandwrite -p -s $LOCAL_RECOVERY_FLAGS_OFFSET_BOS_LAYOUT $env_mtd\n",
            "echo writing ${RECOVERY_FLAG_SUCCESSFUL}\n",
            "fi\n",
        );
        assert!(admit_s19k_s97_promotes_first_boot_to_successful(s97_no_dump).is_err());
        assert!(admit_s19k_s97_promotes_first_boot_to_successful("flash_erase only").is_err());
        assert!(refuse_s19k_s97_as_unconditional_03().is_err());
        assert!(refuse_s19k_s97_as_promote_01_to_03().is_err());
        assert!(COMMON.contains("DCENTOS_RECOVERY_FLAG_FIRST_BOOT=0x2"));
        assert!(COMMON.contains("DCENTOS_GLOBAL_RW_FLAGS_OFFSET=0x00000B400000"));
        assert!(S99.contains("refuse naive 0x05300000"));
        assert!(S99.contains("RECOVERY_FLAG_SUCCESSFUL"));
        assert_eq!(RECOVERY_FLAG_OFFSET_HEX, "0x04D00000");
        let cvitek = concat!(
            "#!/bin/sh\n",
            "# for CV183X platform update, file description:\n",
            "blkdiscard /dev/mmcblk0p1\n",
            "dd if=boot.emmc of=/dev/mmcblk0p1\n",
            "blkdiscard /dev/mmcblk0p4\n",
            "dd if=sig.bin of=/dev/mmcblk0p4\n",
            "blkdiscard /dev/mmcblk0p3\n",
            "dd if=minerfs.gz of=/dev/mmcblk0p3\n",
        );
        assert_eq!(
            classify_held_updateporc(cvitek),
            Ok(S19kHeldUpdateporcKind::CvitekEmmcComparative)
        );
        assert!(refuse_cvitek_updateporc_as_s19k_nand_writer(
            S19kHeldUpdateporcKind::CvitekEmmcComparative
        )
        .is_err());
        assert!(classify_held_updateporc("#!/bin/sh\nnandwrite /dev/mtd5\n").is_err());
        assert!(refuse_s19k_stock_flash_via_mmcblk0("/dev/mmcblk0p3").is_err());
        assert!(refuse_s19k_stock_flash_via_mmcblk0("/dev/mtd5").is_ok());
        assert!(refuse_fileparser_as_s19k_nand_sot().is_err());
        assert_eq!(HELD_FILEPARSER_BYTES, 20184);
        assert_eq!(HELD_CVITEK_UPDATEPORC_BYTES, 3920);
        assert!(!S19K_STOCK_UPDATEPORC_IN_EXTRACT);
        let zynq = concat!(
            "#!/bin/sh\n",
            "/usr/bin/FileParser -f \"$subtype\" $FILE /etc/bitmain.pub\n",
            "ubiattach /dev/ubi_ctrl -m 6 -b 2\n",
            "flash_erase /dev/mtd6 0x0 0x0\n",
            "flash_erase /dev/mtd0 0x1B00000 0x1\n",
            "cp $FILE /tmp/updatedata/update.bmu\n",
        );
        assert_eq!(
            classify_held_updateporc(zynq),
            Ok(S19kHeldUpdateporcKind::ZynqUbiMtd6Comparative)
        );
        assert!(refuse_held_updateporc_as_s19k_nand_writer(
            S19kHeldUpdateporcKind::ZynqUbiMtd6Comparative
        )
        .is_err());
        assert!(refuse_s19k_mtd6_update_volume(6).is_err());
        assert!(refuse_s19k_mtd6_update_volume(5).is_ok());
        assert!(refuse_s19k_zynq_mtd0_update_marker(0, "0x1B00000").is_err());
        assert!(refuse_s19k_zynq_mtd0_update_marker(5, "0x05300000").is_ok());
        assert_eq!(S19K_NAND_MAP.len(), 6);
        assert!(S19K_NAND_MAP.iter().all(|s| s.mtd != 6));
        assert_eq!(HELD_ZYNQ_UPDATEPORC_BYTES, 2627);
        assert_eq!(HELD_ZYNQ_FILEPARSER_BYTES, 23912);
        assert!(!CLEAR_FOR_FLASH);
    }

    #[test]
    fn wave89_daemonc_is_22322_client_not_nand_writer() {
        assert_eq!(S19K_STOCK_UPDATEPORC_PREFIX, "/usr/sbin/updateporc.sh ");
        assert_eq!(S19K_STOCK_DAEMONC_LISTEN_PORT, 22322);
        assert_eq!(S19K_STOCK_DAEMONC_LISTEN_HOST, "127.0.0.1");
        assert_eq!(S19K_78_DAEMONC_MOVW_DAEMONC_INSN, 0xE301_1444);
        assert_eq!(S19K_78_DAEMONC_LDR_ARGV1_INSN, 0xE594_0004);
        assert_eq!(S19K_78_DAEMONC_MOVW_DAEMONS_INSN, 0xE301_144C);
        assert_eq!(S19K_78_DAEMONC_MOVW_HOST_INSN, 0xE301_0414);
        assert_eq!(S19K_78_DAEMONC_MOVW_PORT_INSN, 0xE301_0420);
        assert_eq!(S19K_78_DAEMONC_MOVW_PORC_INSN, 0xE300_EF54);
        assert_eq!(S19K_78_DAEMONC_CMP_C8_INSN, 0xE350_00C8);
        assert_eq!(S19K_STOCK_DAEMONC_HTTP_OK, 200);
        assert_eq!(S19K_78_MTD2_ANDROID_OFF, 2_097_152);
        assert_eq!(S19K_78_MTD2_ANDROID2_OFF, 0x0120_0000);
        assert_eq!(S19K_78_MTD2_ANDROID_COUNT, 2);
        assert_eq!(S19K_78_MTD2_KERNEL_SIZE, 0x005C_2000);
        assert_eq!(S19K_78_MTD2_ANDROID2_RAMDISK_SIZE, 0x0066_2000);
        assert_eq!(S19K_78_MTD2_PAGE_SIZE, 2048);
        assert_eq!(S19K_78_MTD2_UPDATEPORC_HITS, 0);
        assert_eq!(S19K_78_MTD2_FILEPARSER_HITS, 0);
        assert_eq!(S19K_78_MTD2_UART_TRANS_HITS, 0);
        assert_eq!(S19K_78_MTD2_4CC0_HITS, 0);
        assert_eq!(S19K_78_MTD2_BITMAIN_PUB_HITS, 0);
        assert_eq!(S19K_78_MTD2_MINER_PEM_HITS, 0);
        assert_eq!(S19K_78_MTD2_DAEMONC_HITS, 0);
        assert!(admit_s19k_78_mtd2_geometry(S19K_78_MTD2_BYTES).is_ok());
        assert!(admit_s19k_78_mtd2_geometry(S19K_78_MTD3_BYTES).is_err());
        assert!(refuse_s19k_mtd2_ramdisk_as_factory_boot(S19K_FACTORY_BOOT_RAMDISK_SIZE).is_err());
        assert!(
            refuse_s19k_mtd2_ramdisk_as_factory_boot(S19K_78_MTD2_ANDROID2_RAMDISK_SIZE).is_ok()
        );
        assert!(refuse_s19k_mtd2_ramdisk_as_20231108(S19K_20231108_RAMDISK_SIZE).is_err());
        assert!(refuse_s19k_mtd2_ramdisk_as_20231108(S19K_78_MTD2_ANDROID2_RAMDISK_SIZE).is_ok());
        let mut pair = vec![0u8; S19K_78_MTD2_ANDROID2_OFF + 24];
        pair[S19K_78_MTD2_ANDROID_OFF..S19K_78_MTD2_ANDROID_OFF + 8].copy_from_slice(b"ANDROID!");
        pair[S19K_78_MTD2_ANDROID2_OFF..S19K_78_MTD2_ANDROID2_OFF + 8].copy_from_slice(b"ANDROID!");
        pair[S19K_78_MTD2_ANDROID2_OFF + 8..S19K_78_MTD2_ANDROID2_OFF + 12]
            .copy_from_slice(&S19K_78_MTD2_KERNEL_SIZE.to_le_bytes());
        pair[S19K_78_MTD2_ANDROID2_OFF + 16..S19K_78_MTD2_ANDROID2_OFF + 20]
            .copy_from_slice(&S19K_78_MTD2_ANDROID2_RAMDISK_SIZE.to_le_bytes());
        assert!(admit_s19k_78_mtd2_android_pair(&pair).is_ok());
        pair[S19K_78_MTD2_ANDROID2_OFF + 16..S19K_78_MTD2_ANDROID2_OFF + 20]
            .copy_from_slice(&S19K_FACTORY_BOOT_RAMDISK_SIZE.to_le_bytes());
        assert!(admit_s19k_78_mtd2_android_pair(&pair).is_err());
        assert_eq!(
            S19K_78_MTD3_BYTES / S19K_78_MTD3_PEB,
            S19K_78_MTD3_PEB_COUNT
        );
        assert!(refuse_s19k_daemonc_as_direct_nand_writer().is_err());
        assert!(refuse_s19k_stock_web_rail_as_unsigned().is_err());
        assert_eq!(
            s19k_stock_daemons_system_line("update.bmu"),
            "/usr/sbin/updateporc.sh update.bmu"
        );
    }

    #[test]
    fn s19k_mtd2_stock_system_has_no_updateporc_or_fileparser() {
        assert_eq!(S19K_78_MTD2_BYTES, 52_428_800);
        assert_eq!(S19K_78_MTD2_ANDROID2_OFF, 18_874_368);
        assert_ne!(
            S19K_78_MTD2_ANDROID2_RAMDISK_SIZE,
            S19K_FACTORY_BOOT_RAMDISK_SIZE
        );
        assert_ne!(
            S19K_78_MTD2_ANDROID2_RAMDISK_SIZE,
            S19K_20231108_RAMDISK_SIZE
        );
        assert!(!S19K_AML_UPDATEPORC_IN_HELD_CORPUS);
        let empty = vec![0u8; 32];
        assert!(refuse_s19k_mtd2_as_fileparser_source(&empty).is_err());
        assert!(refuse_s19k_mtd2_as_uart_trans_source(&empty).is_err());
        assert!(refuse_s19k_mtd2_as_bitmain_pub_source(&empty).is_err());
        let mut hit = b"FileParser".to_vec();
        assert!(refuse_s19k_mtd2_as_fileparser_source(&hit).is_ok());
        hit = b"uart_trans.ko".to_vec();
        assert!(refuse_s19k_mtd2_as_uart_trans_source(&hit).is_ok());
        hit = b"bmminer_4cc0".to_vec();
        assert!(refuse_s19k_mtd2_as_uart_trans_source(&hit).is_ok());
        hit = b"bitmain.pub".to_vec();
        assert!(refuse_s19k_mtd2_as_bitmain_pub_source(&hit).is_ok());
    }

    #[test]
    fn s19k_mtd2_android_pair_amlsecu_and_shared_kernel() {
        assert_eq!(
            classify_s19k_amlsecu_time(S19K_78_MTD2_AMLSECU_A1_TIME).unwrap(),
            S19kAmlsecuImageKind::Mtd2Android1
        );
        assert_eq!(
            classify_s19k_amlsecu_time(S19K_78_MTD2_AMLSECU_A2_TIME).unwrap(),
            S19kAmlsecuImageKind::Mtd2Android2
        );
        assert!(refuse_s19k_mtd2_amlsecu_as_20231108(S19kAmlsecuImageKind::Mtd2Android1).is_err());
        assert!(refuse_s19k_mtd2_amlsecu_as_factory(S19kAmlsecuImageKind::Mtd2Android2).is_err());
        assert!(refuse_s19k_mtd2_amlsecu_as_20231108(S19kAmlsecuImageKind::Bmu20231108).is_ok());
        assert!(refuse_s19k_mtd2_kernel_as_20231108(S19K_20231108_KERNEL_SIZE).is_err());
        assert!(refuse_s19k_mtd2_kernel_as_20231108(S19K_78_MTD2_KERNEL_SIZE).is_ok());
        assert!(admit_s19k_78_mtd2_kernels_identical(true).is_ok());
        assert!(admit_s19k_78_mtd2_kernels_identical(false).is_err());
        assert!(refuse_s19k_mtd2_seconds_as_identical(false).is_ok());
        assert!(refuse_s19k_mtd2_seconds_as_identical(true).is_err());
        assert!(admit_s19k_78_mtd2_a1_second_layout().is_ok());
        assert!(admit_s19k_78_mtd2_a2_ramdisk_layout().is_ok());
        assert_eq!(S19K_78_MTD2_A1_SECOND_OFF, 0x007C_2800);
        assert_eq!(S19K_78_MTD2_A2_RAMDISK_OFF, 0x017C_2800);
        assert_eq!(S19K_78_MTD2_A2_SECOND_OFF, 0x01E2_4800);
        assert_eq!(S19K_78_MTD2_AMLSECU_A1_KIND, 2);
        assert_eq!(S19K_78_MTD2_AMLSECU_A2_KIND, 3);
        let mut page = [0u8; 80];
        page[64..64 + S19K_20231108_CMDLINE.len()].copy_from_slice(S19K_20231108_CMDLINE);
        assert!(admit_s19k_78_mtd2_cmdline(&page).is_ok());
        assert!(admit_s19k_78_mtd2_cmdline(&[0u8; 80]).is_err());
        let a1 = S19kAndroidBootHdr {
            kernel_size: S19K_78_MTD2_KERNEL_SIZE,
            kernel_addr: S19K_20231108_KERNEL_ADDR,
            ramdisk_size: 0,
            ramdisk_addr: S19K_20231108_RAMDISK_ADDR,
            second_size: S19K_78_MTD2_SECOND_SIZE,
            second_addr: S19K_20231108_SECOND_ADDR,
            tags_addr: S19K_20231108_TAGS_ADDR,
            page_size: S19K_78_MTD2_PAGE_SIZE,
        };
        let mut a2 = a1;
        a2.ramdisk_size = S19K_78_MTD2_ANDROID2_RAMDISK_SIZE;
        assert!(admit_s19k_78_mtd2_android1_header(a1).is_ok());
        assert!(admit_s19k_78_mtd2_android2_header(a2).is_ok());
        assert!(admit_s19k_78_mtd2_android1_header(a2).is_err());
        assert!(refuse_s19k_mtd2_payload_as_gzip(&S19K_78_MTD2_KERNEL_HEAD).is_err());
        assert!(refuse_s19k_mtd2_payload_as_gzip(&S19K_78_MTD2_A2_RAMDISK_HEAD).is_err());
        assert!(refuse_s19k_mtd2_payload_as_gzip(&[0x1F, 0x8B, 0x08, 0x00]).is_ok());
        assert_ne!(S19K_78_MTD2_A1_SECOND_HEAD, S19K_78_MTD2_A2_SECOND_HEAD);
        assert_ne!(S19K_78_MTD2_A2_RAMDISK_HEAD, S19K_FACTORY_BOOT_SECOND_HEAD);
    }

    #[test]
    fn s19k_amlsecu_kind_matches_ramdisk() {
        assert_eq!(S19K_AMLSECU_KIND_RECOVERY, 2);
        assert_eq!(S19K_AMLSECU_KIND_BOOT, 3);
        assert_eq!(S19K_78_MTD2_AMLSECU_A1_KIND, S19K_AMLSECU_KIND_RECOVERY);
        assert_eq!(S19K_78_MTD2_AMLSECU_A2_KIND, S19K_AMLSECU_KIND_BOOT);
        assert_eq!(
            S19K_FACTORY_RECOVERY_AMLSECU_KIND,
            S19K_AMLSECU_KIND_RECOVERY
        );
        assert_eq!(S19K_FACTORY_BOOT_AMLSECU_KIND, S19K_AMLSECU_KIND_BOOT);
        assert_eq!(S19K_20231108_AMLSECU_KIND, S19K_AMLSECU_KIND_BOOT);
        assert_eq!(
            classify_s19k_amlsecu_time(S19K_FACTORY_AMLSECU_RECOVERY_TIME).unwrap(),
            S19kAmlsecuImageKind::FactorySdRecovery
        );
        assert_eq!(
            classify_s19k_amlsecu_time(S19K_FACTORY_AMLSECU_BOOT_TIME).unwrap(),
            S19kAmlsecuImageKind::FactorySdBoot
        );
        assert_eq!(
            classify_s19k_amlsecu_time(S19K_20231108_AMLSECU_STAMP_TIME).unwrap(),
            S19kAmlsecuImageKind::Bmu20231108
        );
        assert!(
            admit_s19k_amlsecu_kind_matches_ramdisk(S19K_FACTORY_RECOVERY_AMLSECU_KIND, 0).is_ok()
        );
        assert!(admit_s19k_amlsecu_kind_matches_ramdisk(
            S19K_FACTORY_BOOT_AMLSECU_KIND,
            S19K_FACTORY_BOOT_RAMDISK_SIZE
        )
        .is_ok());
        assert!(admit_s19k_amlsecu_kind_matches_ramdisk(
            S19K_20231108_AMLSECU_KIND,
            S19K_20231108_RAMDISK_SIZE
        )
        .is_ok());
        assert!(admit_s19k_amlsecu_kind_matches_ramdisk(S19K_78_MTD2_AMLSECU_A1_KIND, 0).is_ok());
        assert!(admit_s19k_amlsecu_kind_matches_ramdisk(
            S19K_78_MTD2_AMLSECU_A2_KIND,
            S19K_78_MTD2_ANDROID2_RAMDISK_SIZE
        )
        .is_ok());
        assert!(admit_s19k_amlsecu_kind_matches_ramdisk(
            S19K_AMLSECU_KIND_RECOVERY,
            S19K_78_MTD2_ANDROID2_RAMDISK_SIZE
        )
        .is_err());
        assert!(admit_s19k_amlsecu_kind_matches_ramdisk(S19K_AMLSECU_KIND_BOOT, 0).is_err());
        assert!(admit_s19k_amlsecu_kind_matches_ramdisk(1, 0).is_err());
        assert!(refuse_s19k_amlsecu_kind2_as_boot_ramdisk(
            S19K_AMLSECU_KIND_RECOVERY,
            S19K_78_MTD2_ANDROID2_RAMDISK_SIZE
        )
        .is_err());
        assert!(refuse_s19k_amlsecu_kind2_as_boot_ramdisk(S19K_AMLSECU_KIND_RECOVERY, 0).is_ok());
        assert!(refuse_s19k_amlsecu_kind3_as_recovery(S19K_AMLSECU_KIND_BOOT, 0).is_err());
        assert!(refuse_s19k_amlsecu_kind3_as_recovery(
            S19K_AMLSECU_KIND_BOOT,
            S19K_78_MTD2_ANDROID2_RAMDISK_SIZE
        )
        .is_ok());
        assert!(refuse_s19k_factory_recovery_as_mtd2_a1().is_err());
        assert!(refuse_s19k_factory_boot_as_mtd2_a2().is_err());
        assert!(refuse_s19k_20231108_as_mtd2_a2().is_err());
        assert_ne!(S19K_FACTORY_BOOT_RAMDISK_SIZE, S19K_20231108_RAMDISK_SIZE);
        assert_ne!(
            S19K_FACTORY_BOOT_RAMDISK_SIZE,
            S19K_78_MTD2_ANDROID2_RAMDISK_SIZE
        );
        assert_ne!(
            S19K_20231108_RAMDISK_SIZE,
            S19K_78_MTD2_ANDROID2_RAMDISK_SIZE
        );
    }

    #[test]
    fn s19k_usb_uboot_scpi_ddr_gcm_is_soc_not_hash() {
        use crate::s19k_aml_dtb::{
            admit_s19k_usb_uboot_bl30_axg_stamp, admit_s19k_usb_uboot_scpi_ddr_gcm,
            refuse_s19k_usb_bl30_stamp_as_miner_identity,
            refuse_s19k_usb_ddr_suspend_as_hashboard_rail,
            refuse_s19k_usb_gcm_tag_as_android_decrypt, refuse_s19k_usb_otp_block_as_gpio437,
            refuse_s19k_usb_scpi_as_hash_uart, refuse_s19k_usb_scpi_ddr_gcm_as_hash_uart,
            refuse_s19k_usb_scpi_ddr_gcm_as_nandrecovery, S19K_USB_UBOOT_BL30_AXG_STAMP,
            S19K_USB_UBOOT_BL30_AXG_STAMP_OFF, S19K_USB_UBOOT_DDR_SUSPEND,
            S19K_USB_UBOOT_DDR_SUSPEND_OFF, S19K_USB_UBOOT_GCM_TAG, S19K_USB_UBOOT_GCM_TAG_OFF,
            S19K_USB_UBOOT_OTP_BLOCK11, S19K_USB_UBOOT_OTP_BLOCK11_OFF, S19K_USB_UBOOT_SCPI_CSS,
            S19K_USB_UBOOT_SCPI_CSS_OFF,
        };
        assert_eq!(S19K_USB_UBOOT_OTP_BLOCK11_OFF, 45_261);
        assert_eq!(S19K_USB_UBOOT_SCPI_CSS_OFF, 45_328);
        assert_eq!(S19K_USB_UBOOT_DDR_SUSPEND_OFF, 45_483);
        assert_eq!(S19K_USB_UBOOT_GCM_TAG_OFF, 45_797);
        assert_eq!(S19K_USB_UBOOT_BL30_AXG_STAMP_OFF, 46_256);
        let mut blob = S19K_USB_UBOOT_OTP_BLOCK11.to_vec();
        blob.extend_from_slice(S19K_USB_UBOOT_SCPI_CSS);
        blob.extend_from_slice(S19K_USB_UBOOT_DDR_SUSPEND);
        blob.extend_from_slice(S19K_USB_UBOOT_GCM_TAG);
        assert!(admit_s19k_usb_uboot_scpi_ddr_gcm(&blob).is_ok());
        assert!(admit_s19k_usb_uboot_scpi_ddr_gcm(b"missing").is_err());
        assert!(admit_s19k_usb_uboot_bl30_axg_stamp(S19K_USB_UBOOT_BL30_AXG_STAMP).is_ok());
        assert!(admit_s19k_usb_uboot_bl30_axg_stamp(b"missing").is_err());
        assert!(refuse_s19k_usb_scpi_ddr_gcm_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_scpi_ddr_gcm_as_nandrecovery().is_err());
        assert!(refuse_s19k_usb_gcm_tag_as_android_decrypt().is_err());
        assert!(refuse_s19k_usb_scpi_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_ddr_suspend_as_hashboard_rail().is_err());
        assert!(refuse_s19k_usb_otp_block_as_gpio437().is_err());
        assert!(refuse_s19k_usb_bl30_stamp_as_miner_identity().is_err());
    }

    #[test]
    fn s19k_factory_recovery_overflows_78_bos_mtd3() {
        assert_eq!(S19K_AML_UPGRADE_ITEM17_RECOVERY_SIZE, 6_064_640);
        assert_eq!(S19K_78_MTD3_BYTES, 5_242_880);
        assert_eq!(S19K_FACTORY_RECOVERY_OVERFLOW_VS_78_MTD3, 821_760);
        assert!(S19K_AML_UPGRADE_ITEM17_RECOVERY_SIZE as usize > S19K_78_MTD3_BYTES);
        assert!(admit_s19k_factory_recovery_overflows_78_mtd3().is_ok());
        assert!(refuse_s19k_factory_recovery_item_as_78_bos_mtd3().is_err());
        assert_eq!(S19K_78_MTD3_NAME, "stock_config");
        assert_eq!(S19K_S30V_MTD3_NAME, "recovery");
        assert!(
            refuse_s19k_s30v_mtd3_name_as_78_bos(S19K_S30V_MTD3_NAME, S19K_78_MTD3_NAME).is_err()
        );
        assert!(refuse_s19k_s30v_mtd3_name_as_78_bos("stock_config", "stock_config").is_ok());
        assert!(admit_s19k_factory_recovery_second_layout().is_ok());
        assert_eq!(
            S19K_FACTORY_RECOVERY_SECOND_OFF,
            S19K_FACTORY_BOOT_RAMDISK_OFF
        );
        assert_eq!(S19K_FACTORY_RECOVERY_SECOND_OFF, 0x5C_1000);
        assert_eq!(S19K_20231108_SECOND_SIZE, 30_720);
        assert_ne!(
            S19K_20231108_SECOND_SIZE as u32,
            S19K_FACTORY_BOOT_RAMDISK_SIZE
        );
        assert!(refuse_s19k_factory_recovery_second_as_boot_ramdisk().is_err());
        assert!(
            (crate::s19k_aml_dtb::S19K_FACTORY_S30V_RECOVERY_BYTES as usize)
                > S19K_AML_UPGRADE_ITEM17_RECOVERY_SIZE as usize
        );
    }

    #[test]
    fn s19k_factory_pack_is_not_s30v_restock() {
        assert_eq!(
            S19K_FACTORY_PARTITION_SUBS,
            &["_aml_dtb", "boot", "bootloader", "recovery"]
        );
        assert_eq!(
            S19K_FACTORY_RESTOCK_MISSING,
            &["config", "misc", "nvdata", "tpl"]
        );
        assert!(admit_s19k_factory_partition_subs(S19K_FACTORY_PARTITION_SUBS).is_ok());
        assert!(admit_s19k_factory_partition_subs(&["boot", "recovery"]).is_err());
        let items = [
            S19kAmlUpgradeItem {
                id: 4,
                main: "PARTITION".into(),
                sub: "_aml_dtb".into(),
                offset: S19K_AML_UPGRADE_ITEM4_AML_DTB_OFF,
                size: S19K_AML_UPGRADE_ITEM4_AML_DTB_SIZE,
            },
            S19kAmlUpgradeItem {
                id: 9,
                main: "PARTITION".into(),
                sub: "boot".into(),
                offset: S19K_AML_UPGRADE_ITEM9_BOOT_OFF,
                size: S19K_AML_UPGRADE_ITEM9_BOOT_SIZE,
            },
            S19kAmlUpgradeItem {
                id: 11,
                main: "PARTITION".into(),
                sub: "bootloader".into(),
                offset: S19K_AML_UPGRADE_ITEM11_BOOTLOADER_OFF,
                size: S19K_AML_UPGRADE_ITEM11_BOOTLOADER_SIZE,
            },
            S19kAmlUpgradeItem {
                id: 13,
                main: "conf".into(),
                sub: "keys".into(),
                offset: S19K_AML_UPGRADE_ITEM13_KEYS_OFF,
                size: S19K_AML_UPGRADE_ITEM13_KEYS_SIZE,
            },
            S19kAmlUpgradeItem {
                id: 16,
                main: "conf".into(),
                sub: "platform".into(),
                offset: S19K_AML_UPGRADE_ITEM16_PLATFORM_OFF,
                size: S19K_AML_UPGRADE_ITEM16_PLATFORM_SIZE,
            },
            S19kAmlUpgradeItem {
                id: 17,
                main: "PARTITION".into(),
                sub: "recovery".into(),
                offset: S19K_AML_UPGRADE_ITEM17_RECOVERY_OFF,
                size: S19K_AML_UPGRADE_ITEM17_RECOVERY_SIZE,
            },
        ];
        assert!(admit_s19k_factory_pack_has_no_restock_partitions(&items).is_ok());
        let mut bad = items[1].clone();
        bad.sub = "config".into();
        assert!(admit_s19k_factory_pack_has_no_restock_partitions(&[bad]).is_err());
        assert!(refuse_s19k_factory_pack_as_s30v_restock().is_err());
        assert!(refuse_s19k_factory_conf_as_partition_config("conf", "keys").is_err());
        assert!(refuse_s19k_factory_conf_as_partition_config("conf", "platform").is_err());
        assert!(refuse_s19k_factory_conf_as_partition_config("PARTITION", "boot").is_ok());
        assert!(refuse_s19k_factory_partition_sub_as_restock_slot("config").is_err());
        assert!(refuse_s19k_factory_partition_sub_as_restock_slot("misc").is_err());
        assert!(refuse_s19k_factory_partition_sub_as_restock_slot("nvdata").is_err());
        assert!(refuse_s19k_factory_partition_sub_as_restock_slot("tpl").is_err());
        assert!(refuse_s19k_factory_partition_sub_as_restock_slot("boot").is_ok());
        assert!(refuse_s19k_factory_partition_sub_as_restock_slot("recovery").is_ok());
    }

    #[test]
    fn s19k_factory_boot_size_fit_is_not_mtd2_nandwrite() {
        assert_eq!(S19K_AML_UPGRADE_ITEM9_BOOT_SIZE, 12_907_008);
        assert_eq!(S19K_78_MTD2_BYTES, 52_428_800);
        assert!((S19K_AML_UPGRADE_ITEM9_BOOT_SIZE as usize) < S19K_78_MTD2_BYTES);
        assert!(admit_s19k_factory_boot_size_fits_78_mtd2().is_ok());
        assert!(refuse_s19k_factory_boot_item_as_78_mtd2_nandwrite().is_err());
        assert!(refuse_s19k_factory_boot_as_mtd2_a2().is_err());
        assert!(refuse_s19k_s30v_boot_as_78_mtd2().is_err());
        assert_eq!(
            crate::s19k_aml_dtb::S19K_FACTORY_S30V_BOOT_BYTES,
            0x0200_0000
        );
        assert_ne!(
            crate::s19k_aml_dtb::S19K_FACTORY_S30V_BOOT_BYTES as usize,
            S19K_78_MTD2_BYTES
        );
        assert_ne!(
            S19K_FACTORY_BOOT_RAMDISK_SIZE,
            S19K_78_MTD2_ANDROID2_RAMDISK_SIZE
        );
    }

    #[test]
    fn s19k_mtd3_ubi_volume_is_config_data_not_updateporc() {
        assert_eq!(S19K_78_MTD3_NAME, "stock_config");
        assert_eq!(S19K_78_MTD3_UBI_VOL_NAME, b"config_data");
        assert_eq!(S19K_78_MTD3_UBI_VOL_NAME_LEN, 11);
        assert_eq!(S19K_78_MTD3_UBI_VOL_RESERVED_PEBS, 32);
        assert_eq!(S19K_78_MTD3_UBI_VOL_TYPE_DYNAMIC, 1);
        assert_eq!(S19K_78_MTD3_VTBL_OFF, 397_312);
        assert_eq!(S19K_78_MTD3_VTBL_NAME_OFF, 397_328);
        assert_eq!(S19K_78_MTD3_LAYOUT_VOL_ID, 0x7FFF_EFFF);
        assert_eq!(
            S19K_78_MTD3_VTBL_OFF,
            3 * S19K_78_MTD3_PEB + S19K_78_MTD3_DATA_OFF as usize
        );
        assert_eq!(S19K_78_MTD3_UBI_BANG_OFF, 3 * S19K_78_MTD3_PEB + 2048);
        assert!(admit_s19k_78_mtd3_ubi_volume_name(b"config_data").is_ok());
        assert!(admit_s19k_78_mtd3_ubi_volume_name(b"stock_config").is_err());
        assert!(admit_s19k_78_mtd3_ubi_volume_name(b"recovery").is_err());
        let mut vtbl = vec![0u8; S19K_78_MTD3_VTBL_NAME_OFF + 16];
        vtbl[S19K_78_MTD3_VTBL_NAME_OFF..S19K_78_MTD3_VTBL_NAME_OFF + 11]
            .copy_from_slice(S19K_78_MTD3_UBI_VOL_NAME);
        assert!(admit_s19k_78_mtd3_vtbl_name(&vtbl).is_ok());
        assert!(admit_s19k_78_mtd3_vtbl_name(&[0u8; 32]).is_err());
        assert!(refuse_s19k_78_mtd3_ubi_vol_as_proc_mtd_name().is_err());
        assert!(refuse_s19k_78_mtd3_ubi_vol_as_s30v_recovery().is_err());
        assert!(refuse_s19k_78_nand_env_as_updateporc(b"nandrecovery_env_offset").is_err());
        assert!(refuse_s19k_78_nand_env_as_updateporc(b"updateporc.sh").is_ok());
        assert!(refuse_s19k_upgrade_cgi_as_updateporc_script(
            "#!/bin/sh\n/usr/sbin/daemonc $file\necho 2 > /tmp/miner_act\n"
        )
        .is_err());
        assert!(
            refuse_s19k_upgrade_cgi_as_updateporc_script("/usr/sbin/updateporc.sh update.bmu")
                .is_ok()
        );
        assert!(!S19K_AML_UPDATEPORC_IN_HELD_CORPUS);
        assert_eq!(S19K_78_MTD3_UPDATEPORC_HITS, 0);
        assert_eq!(
            S19K_78_MTD3_VTBL_PEB4_OFF,
            4 * S19K_78_MTD3_PEB + S19K_78_MTD3_DATA_OFF as usize
        );
        assert_eq!(
            S19K_78_MTD3_VTBL_PEB4_NAME_OFF,
            S19K_78_MTD3_VTBL_PEB4_OFF + 16
        );
        assert_eq!(S19K_78_MTD3_UBI_BANG_PEB4_OFF, 4 * S19K_78_MTD3_PEB + 2048);
        let mut vtbl4 = vec![0u8; S19K_78_MTD3_VTBL_PEB4_NAME_OFF + 16];
        vtbl4[S19K_78_MTD3_VTBL_PEB4_NAME_OFF..S19K_78_MTD3_VTBL_PEB4_NAME_OFF + 11]
            .copy_from_slice(S19K_78_MTD3_UBI_VOL_NAME);
        assert!(admit_s19k_78_mtd3_vtbl_peb4_name(&vtbl4).is_ok());
        assert!(admit_s19k_78_mtd3_vtbl_peb4_name(&[0u8; 32]).is_err());
        assert!(admit_s19k_78_mtd3_vtbl_copies_identical(true).is_ok());
        assert!(admit_s19k_78_mtd3_vtbl_copies_identical(false).is_err());
        assert!(refuse_s19k_78_mtd3_single_vtbl_peb_as_complete().is_err());
        assert!(refuse_s19k_upgrade_clear_as_updateporc_script(
            "#!/bin/sh\n/usr/sbin/daemonc $file\necho 3 > /tmp/miner_act\n"
        )
        .is_err());
        assert!(refuse_s19k_upgrade_clear_as_updateporc_script("/usr/sbin/updateporc.sh").is_ok());
        assert!(admit_s19k_stock_upgrade_cgi(
            "file=$folder/update.bmu\n/usr/sbin/daemonc $file\necho 3 > /tmp/miner_act\n",
            3
        )
        .is_ok());
    }

    #[test]
    fn s19k_mtd3_vtbl_peb4_copy_is_required() {
        assert_eq!(S19K_78_MTD3_VTBL_PEB4_OFF, 528_384);
        assert_eq!(S19K_78_MTD3_VTBL_PEB4_NAME_OFF, 528_400);
        assert_eq!(S19K_78_MTD3_UBI_BANG_PEB4_OFF, 526_336);
        assert_ne!(S19K_78_MTD3_VTBL_OFF, S19K_78_MTD3_VTBL_PEB4_OFF);
        assert!(admit_s19k_78_mtd3_vtbl_copies_identical(true).is_ok());
        assert!(refuse_s19k_78_mtd3_single_vtbl_peb_as_complete().is_err());
        assert!(refuse_s19k_upgrade_clear_as_updateporc_script(
            "/usr/sbin/daemonc $file\necho 3 > /tmp/miner_act"
        )
        .is_err());
        assert_eq!(S19K_78_MTD3_UBI_VOL_NAME, b"config_data");
    }

    #[test]
    fn s19k_factory_boot_recovery_share_kernel_not_second() {
        assert_eq!(S19K_ANDROID_NAME_OFF, 48);
        assert_eq!(S19K_ANDROID_NAME_LEN, 16);
        assert_eq!(S19K_FACTORY_BOOT_KERNEL_HEAD, [0x30, 0x9C, 0xFC, 0x10]);
        assert_eq!(S19K_FACTORY_RECOVERY_SECOND_HEAD, [0x68, 0xCA, 0xF5, 0xA1]);
        assert_eq!(S19K_FACTORY_MESON1_ENC_HEAD, [0x5D, 0xC7, 0x5D, 0x64]);
        assert_ne!(
            S19K_FACTORY_RECOVERY_SECOND_HEAD,
            S19K_FACTORY_BOOT_SECOND_HEAD
        );
        assert_ne!(
            S19K_20231108_SECOND_SIZE as u64,
            S19K_AML_UPGRADE_ITEM4_AML_DTB_SIZE
        );
        let mut page = [0u8; 80];
        page[..8].copy_from_slice(S19K_ANDROID_BOOT_MAGIC);
        assert!(admit_s19k_android_name_empty(&page).is_ok());
        page[48] = b'b';
        assert!(admit_s19k_android_name_empty(&page).is_err());
        assert!(admit_s19k_factory_boot_recovery_kernels_identical(true).is_ok());
        assert!(admit_s19k_factory_boot_recovery_kernels_identical(false).is_err());
        assert!(refuse_s19k_factory_recovery_second_as_boot_second().is_err());
        assert!(refuse_s19k_factory_recovery_second_as_meson1_enc().is_err());
        assert!(
            admit_s19k_factory_android_second_head(&S19K_FACTORY_RECOVERY_SECOND_HEAD).is_err()
        );
        let mut boot_second = S19K_FACTORY_BOOT_SECOND_HEAD.to_vec();
        boot_second.resize(S19K_20231108_SECOND_SIZE as usize, 0);
        assert!(admit_s19k_factory_android_second_head(&boot_second).is_ok());
        assert!(!S19K_AML_UPDATEPORC_IN_HELD_CORPUS);
    }

    #[test]
    fn s19k_s97_nanddump_02_before_write_03() {
        const HELD: &str = include_str!(
            "../../../../../"
        );
        assert!(admit_s19k_s97_nanddump_02_before_write_03(HELD).is_ok());
        assert!(admit_s19k_s97_promotes_first_boot_to_successful(HELD).is_ok());
        assert!(HELD.contains("nanddump -s $LOCAL_RECOVERY_FLAGS_OFFSET_BOS_LAYOUT -l 1"));
        assert!(
            HELD.find("nanddump -s $LOCAL_RECOVERY_FLAGS_OFFSET_BOS_LAYOUT -l 1")
                .unwrap()
                < HELD.find("flash_erase").unwrap()
        );
        assert!(!HELD.contains("RECOVERY_FLAG_INSTALLED"));
        assert!(refuse_s19k_s97_as_unconditional_03().is_err());
        assert!(refuse_s19k_s97_as_promote_01_to_03().is_err());
    }

    #[test]
    fn s19k_s99_header_leftover_02_is_recover_to_stock_not_mtd2() {
        const S99: &str = include_str!(
            "../../../br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S99upgrade"
        );
        assert!(admit_s19k_s99_header_names_recover_to_stock(S99).is_ok());
        assert!(!S99.contains("U-Boot reverts to mtd2"));
        assert!(!S99.contains("Two parallel U-Boot revert mechanisms"));
        assert!(!S99.contains("U-Boot will revert on next reboot"));
        assert!(S99.contains("recover_to_stock"));
        assert!(S99.contains("bootcmd never reads firstboot"));
        assert!(S99.contains("firstboot=0 is not the revert disarm"));
        assert!(S99.contains("next reboot is recover_to_stock"));
        assert!(admit_s19k_s99_wal_block_leaves_flag_02(S99).is_ok());
        assert!(admit_s19k_s99_identity_wal_does_not_block_03(S99).is_ok());
        assert!(refuse_s19k_s99_leftover_02_as_mtd2_boot().is_err());
        assert!(refuse_s19k_s99_firstboot0_as_recover_disarm().is_err());
        assert!(crate::s19k_nand_env::refuse_s19k_flag_02_as_direct_mtd2_boot(0x02).is_err());
    }

    #[test]
    fn s19k_s21_s97_identical_to_78_not_firstboot_bootcmd() {
        const S21: &str = include_str!(
            "../../../../../"
        );
        const S78: &str = include_str!(
            "../../../../../"
        );
        assert!(admit_s21_s97_identical_to_78(S21, S78).is_ok());
        assert_eq!(S21, S78);
        assert!(admit_s21_s97_identical_to_78(S21, "different").is_err());
        assert!(refuse_s21_androidboot_firstboot_as_uboot_firstboot().is_err());
        assert!(refuse_s21_held_s97_as_firstboot_bootcmd().is_err());
        assert!(crate::s19k_nand_env::admit_s21_held_proc_mtd_matches_78().is_ok());
        assert_eq!(
            crate::s19k_nand_env::S21_HELD_PROC_MTD_SIZES,
            crate::s19k_nand_env::S19K_78_PROC_MTD_SIZES
        );
    }

    #[test]
    fn s19k_track1_tmpfs_refuses_live426_enospc_copy_and_admits_hardlink() {
        assert!(!s19k_track1_tmpfs_stage_allowed(
            S19K_LIVE426_TMPFS_AVAIL_BYTES,
            S19K_LIVE425_DCENTRALD_BYTES,
            true,
        ));
        assert!(!s19k_track1_tmpfs_stage_allowed(
            20 * 1024 * 1024,
            S19K_LIVE425_DCENTRALD_BYTES,
            true,
        ));
        assert!(s19k_track1_tmpfs_stage_allowed(
            20 * 1024 * 1024,
            S19K_LIVE425_DCENTRALD_BYTES,
            false,
        ));
        assert!(s19k_track1_tmpfs_stage_allowed(
            45 * 1024 * 1024,
            S19K_LIVE425_DCENTRALD_BYTES,
            false,
        ));
        assert!(refuse_s19k_live426_enospc_as_chain_inactive_result().is_err());
    }

    #[test]
    fn s19k_track1_soak_does_not_stop_at_live427_620s_without_clean() {
        assert!(!s19k_track1_soak_should_stop(
            S19K_LIVE427_SOAK_S,
            0,
            0,
            0,
            6
        ));
        assert!(!s19k_track1_soak_should_stop(300, 1, 60, 0, 1));
        assert!(!s19k_track1_soak_should_stop(
            S19K_LIVE431_SOAK_STOP_S,
            1,
            S19K_TRACK1_SOAK_MIN_POST_CLEAN_S,
            0,
            S19K_LIVE431_WRAP_AT_STOP
        ));
        assert!(refuse_s19k_live431_220s_as_wrap7_t600().is_err());
        assert!(s19k_track1_soak_should_stop(
            S19K_TRACK1_SOAK_T600_S,
            1,
            S19K_TRACK1_SOAK_MIN_POST_CLEAN_S,
            0,
            S19K_TRACK1_SOAK_WRAP7
        ));
        assert!(s19k_track1_soak_should_stop(
            S19K_TRACK1_SOAK_MAX_S,
            0,
            0,
            0,
            0
        ));
        assert!(!s19k_track1_soak_rx_dead(89));
        assert!(s19k_track1_soak_rx_dead(S19K_TRACK1_SOAK_RX_DEAD_S));
        assert!(s19k_track1_soak_should_stop(
            200,
            0,
            0,
            S19K_TRACK1_SOAK_RX_DEAD_S,
            4
        ));
        assert!(!s19k_track1_alive_line_rx_dead(
            "nonce_silent_s=88 wrap_idx=5"
        ));
        assert!(s19k_track1_alive_line_rx_dead(
            "nonce_silent_s=93 wrap_idx=5"
        ));
        assert!(s19k_track1_alive_line_rx_dead("nonce_silent_s=119"));
        assert!(!s19k_track1_alive_line_rx_dead("nonce_silent_s=9"));
        assert!(admit_s19k_live432_tx_wrap_does_not_stop_wrap7_t600().is_ok());
        assert!(!s19k_track1_alive_line_wrap7("wrap_idx=9 wrap_rx=5"));
        assert!(s19k_track1_alive_line_wrap7("wrap_idx=9 wrap_rx=7"));
        let ansi_wrap = "wrap_rx\u{1b}[3m\u{1b}[0m\u{1b}[2m=\u{1b}[0m7";
        assert_eq!(s19k_track1_parse_wrap_rx(ansi_wrap), Some(7));
        assert!(s19k_track1_alive_line_wrap7(ansi_wrap));
        let ansi = "nonce_silent_s\u{1b}[3m\u{1b}[0m\u{1b}[2m=\u{1b}[0m204";
        assert_eq!(s19k_track1_parse_nonce_silent_s(ansi), Some(204));
        assert!(s19k_track1_alive_line_rx_dead(ansi));
        assert!(!s19k_track1_alive_line_rx_dead(
            "nonce_silent_s\u{1b}[3m\u{1b}[0m\u{1b}[2m=\u{1b}[0m88"
        ));
        assert_eq!(s19k_track1_alive_gpio437_field(Some(0)), "0");
        assert_eq!(s19k_track1_alive_gpio437_field(Some(1)), "1");
        assert_eq!(s19k_track1_alive_gpio437_field(None), "unread");
    }

    #[test]
    fn s19k_track1_typed_soak_decision_separates_endurance_from_bench_completion() {
        use S19kTrack1BenchCompletion::{Max1500, T600Wrap7};
        use S19kTrack1SoakDecision::{BenchComplete, Continue, RxDead};

        assert_eq!(
            s19k_track1_soak_decision(599, 0, S19K_TRACK1_SOAK_WRAP7, true),
            Continue
        );
        assert_eq!(
            s19k_track1_soak_decision(S19K_TRACK1_SOAK_T600_S, 0, S19K_TRACK1_SOAK_WRAP7 - 1, true,),
            Continue
        );
        assert_eq!(
            s19k_track1_soak_decision(S19K_TRACK1_SOAK_T600_S, 0, S19K_TRACK1_SOAK_WRAP7, true,),
            BenchComplete(T600Wrap7)
        );
        assert_eq!(
            s19k_track1_soak_decision(S19K_TRACK1_SOAK_MAX_S, 0, 0, true),
            BenchComplete(Max1500)
        );

        // A healthy production/endurance run has no time-based stop.
        assert_eq!(
            s19k_track1_soak_decision(S19K_TRACK1_SOAK_T600_S, 0, S19K_TRACK1_SOAK_WRAP7, false,),
            Continue
        );
        assert_eq!(
            s19k_track1_soak_decision(S19K_TRACK1_SOAK_MAX_S, 0, 0, false),
            Continue
        );

        // RX death remains terminal in both modes and wins at simultaneous
        // bench thresholds.
        assert_eq!(
            s19k_track1_soak_decision(
                S19K_TRACK1_SOAK_T600_S,
                S19K_TRACK1_SOAK_RX_DEAD_S,
                S19K_TRACK1_SOAK_WRAP7,
                true,
            ),
            RxDead
        );
        assert_eq!(
            s19k_track1_soak_decision(S19K_TRACK1_SOAK_MAX_S, S19K_TRACK1_SOAK_RX_DEAD_S, 0, false,),
            RxDead
        );
    }

    #[test]
    fn s19k_track1_launch_kills_only_owned_pid() {
        assert!(s19k_track1_launch_may_kill(3667, 3667));
        assert!(!s19k_track1_launch_may_kill(3058, 3667));
        assert!(!s19k_track1_launch_may_kill(0, 3667));
        assert!(refuse_s19k_live429_sigterm_as_leftover_or_wrap().is_err());
        const LIVE428: &str = include_str!(
            "../../../../../"
        );
        assert!(admit_s19k_track1_launch_kills_owned_pid_only(LIVE428).is_err());
        const LIVE430: &str = include_str!(
            "../../../../../"
        );
        assert_eq!(
            admit_s19k_track1_launch_kills_owned_pid_only(LIVE430),
            Ok(())
        );
        assert_eq!(S19K_LIVE429_SIGTERM_S, 9);
        assert!(LIVE430.contains("nonce_silent_s=90"));
        const LIVE431: &str = include_str!(
            "../../../../../"
        );
        assert_eq!(
            admit_s19k_track1_launch_kills_owned_pid_only(LIVE431),
            Ok(())
        );
        assert!(LIVE431.contains("nonce_silent_s=90"));
        assert!(LIVE431.contains("s1_silent_s"));
        const LIVE432: &str = include_str!(
            "../../../../../"
        );
        assert_eq!(
            admit_s19k_track1_launch_kills_owned_pid_only(LIVE432),
            Ok(())
        );
        assert!(LIVE432.contains("nonce_silent_s=90"));
        assert!(admit_s19k_track1_launch_rx_dead_is_ge_90(LIVE432).is_err());
        assert!(LIVE432.contains("wrap7_and_t600"));
        assert!(LIVE432.contains("DCENT_S19K_EXPERIMENTAL_POST_CLEAN_CHAIN_INACTIVE=1"));
        const LIVE433: &str = include_str!(
            "../../../../../"
        );
        assert_eq!(
            admit_s19k_track1_launch_kills_owned_pid_only(LIVE433),
            Ok(())
        );
        assert_eq!(admit_s19k_track1_launch_rx_dead_is_ge_90(LIVE433), Ok(()));
        assert!(LIVE433.contains("wrap_rx="));
        assert!(admit_s19k_track1_launch_rx_dead_ignores_ansi(LIVE433).is_err());
        const LIVE434: &str = include_str!(
            "../../../../../"
        );
        assert_eq!(
            admit_s19k_track1_launch_kills_owned_pid_only(LIVE434),
            Ok(())
        );
        assert_eq!(admit_s19k_track1_launch_rx_dead_is_ge_90(LIVE434), Ok(()));
        assert_eq!(
            admit_s19k_track1_launch_rx_dead_ignores_ansi(LIVE434),
            Ok(())
        );
        assert!(LIVE434.contains("RUST_LOG_STYLE=never"));
        assert!(LIVE434.contains("wrap_rx="));
        const LIVE435: &str = include_str!(
            "../../../../../"
        );
        assert_eq!(
            admit_s19k_track1_launch_kills_owned_pid_only(LIVE435),
            Ok(())
        );
        assert_eq!(admit_s19k_track1_launch_rx_dead_is_ge_90(LIVE435), Ok(()));
        assert_eq!(
            admit_s19k_track1_launch_rx_dead_ignores_ansi(LIVE435),
            Ok(())
        );
        assert!(LIVE435.contains("RUST_LOG_STYLE=never"));
        assert!(LIVE435.contains("S19k wrap-retire leftover"));
        assert!(!s19k_track1_tracing_ansi_enabled(Some("never")));
        assert!(s19k_track1_tracing_ansi_enabled(None));
        const LOGGING: &str = include_str!("../../dcentrald/src/logging.rs");
        assert_eq!(
            admit_s19k_production_honors_rust_log_style_never(LOGGING),
            Ok(())
        );
        const RESTORE432: &str = include_str!(
            "../../../../../"
        );
        assert_eq!(
            admit_s19k_track1_restore_never_writes_gpio437(RESTORE432),
            Ok(())
        );
        assert_eq!(refuse_s19k_restore_plan_as_execute_grant(), Ok(()));
        const INSTALL: &str = include_str!("../../../scripts/install_amlogic_persistent.sh");
        assert_eq!(
            admit_s19k_install_backup_reads_gpio437_before_safeoff(INSTALL),
            Ok(())
        );
        assert_eq!(
            admit_s19k_install_backup_host_streams_nand_env(INSTALL),
            Ok(())
        );
        assert!(
            admit_s19k_install_backup_host_streams_nand_env(&INSTALL.replacen(
                "dd if=/dev/nand_env bs=64K count=1",
                "dd if=/dev/nand_env of=/tmp/nand_env_pre.bin bs=64K count=1",
                1
            ))
            .is_err()
        );
        assert_eq!(
            admit_s19k_install_remote_staging_is_content_bound(INSTALL),
            Ok(())
        );
        assert!(
            admit_s19k_install_remote_staging_is_content_bound(&INSTALL.replace(
                "REMOTE_STAGE_DIR=\"/data/.dcentos-sysupgrade-$LOCAL_SHA\"",
                "REMOTE_STAGE_DIR=\"/data/sysupgrade\"",
            ))
            .is_err()
        );
    }
}
