#!/bin/sh
# Offline source contract for Amlogic boot/runtime/crash power containment.

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
S37="$PROJECT_DIR/br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S37board_setup"
ALIAS="$PROJECT_DIR/br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S37bitmainer_setup"
S82="$PROJECT_DIR/br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S82dcentrald"
LATCH="$PROJECT_DIR/br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-session-latch.sh"
INIT="$PROJECT_DIR/dcentrald/dcentos-init/src/main.rs"
API_REBOOT="$PROJECT_DIR/dcentrald/dcentrald-api/src/rest/late.rs"
HAL="$PROJECT_DIR/dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs"
RECOVERY="$PROJECT_DIR/br2_external_dcentos/board/amlogic/rootfs-overlay/root/web/static/recovery.html"
DIAGNOSTIC="$PROJECT_DIR/br2_external_dcentos/board/amlogic/rootfs-overlay/root/web/static/diagnostic.html"
WEB_SERVER="$PROJECT_DIR/br2_external_dcentos/board/amlogic/rootfs-overlay/root/web/server.py"
FAILURES=0

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    FAILURES=$((FAILURES + 1))
}

pass() {
    printf 'PASS: %s\n' "$*"
}

require_literal() {
    FILE=$1
    LITERAL=$2
    LABEL=$3
    if grep -Fq -- "$LITERAL" "$FILE"; then
        pass "$LABEL"
    else
        fail "$LABEL"
    fi
}

require_file() {
    FILE=$1
    if [ -f "$FILE" ]; then
        pass "required file exists: $FILE"
    else
        fail "required file missing: $FILE"
    fi
}

for script in "$S37" "$ALIAS" "$S82" "$LATCH"; do
    if sh -n "$script"; then
        pass "$(basename "$script") is POSIX-shell parseable"
    else
        fail "$(basename "$script") is not POSIX-shell parseable"
    fi
done

# Policy drift is checked against the single JSON source. Executable S37/S99
# positive/refusal behavior is exercised by test_s21_boot_polarity.py.
if python3 "$PROJECT_DIR/scripts/generate_amlogic_gpio437.py" --check; then
    pass 'GPIO437 generated Rust and both installed shell helpers match the authority'
else
    fail 'GPIO437 policy generation drift'
fi
require_literal "$S37" 'GPIO437 refuse: missing or unsealed board_target=' \
    'S37 fail-closes GPIO437 when board_target is missing or unsealed'
require_literal "$S37" 'write_and_check "$ACTIVE_LOW_PATH" 0' \
    'S37 pins and checks GPIO437 raw active-high mode'
require_literal "$S37" 'FAN_BOOT_DUTY_NS=30000' \
    'S37 boot cooling is pinned to the PWM30 ceiling'
require_literal "$S37" 'fan0_period_ns=%s' \
    'S37 receipt records the complete PWM period/duty/enable state'
require_literal "$S37" 'for GPIO in 476 477' \
    'S37 configures both management-fabric pinmux guards together'
require_literal "$S37" 'configure_input_gpio "$GPIO" || return 1' \
    'S37 GPIO476/477 setup uses checked input direction'
require_literal "$S37" 'schema=dcentos.amlogic-safe-state/v2' \
    'S37 emits the reset-polarity-bound boot-safe receipt v2'
require_literal "$S37" 'gpio_active_low=0' \
    'S37 receipt records raw active-high GPIO semantics'
require_literal "$S37" 'physical_rail_measured=false' \
    'S37 receipt does not overclaim electrical rail proof'
require_literal "$S37" 'hashboard_reset_low_bitmap=0x7' \
    'S37 receipt binds all three checked reset-low legs'
require_literal "$S37" 'hashboard_reset_gpio454_active_low=0' \
    'S37 receipt binds reset GPIO454 to raw active_low=0'
require_literal "$S37" 'hashboard_reset_gpio456_active_low=0' \
    'S37 receipt binds reset GPIO456 to raw active_low=0'
require_literal "$S37" 'configure_reset_output_low_gpio "$GPIO"' \
    'S37 normalizes reset active_low before output-low assertion'
require_literal "$S37" 'verify_hashboards_reset_low || return 1' \
    'S37 live-revalidates all reset-low legs with the receipt'
require_literal "$S37" 'continuing to GPIO437 SafeOff' \
    'S37 emergency path still cuts the rail after a reset-leg failure'
require_literal "$S37" 'write_receipt runtime-handoff' \
    'S37 records an explicit boot-to-runtime handoff state'
require_literal "$S37" 'verify_start_safe_receipt || return 1' \
    'runtime handoff revalidates the checked boot or terminal start baseline'

if grep -Eq 'FAN_BOOT_DUTY_NS=100000' "$S37"; then
    fail 'S37 retains 100-percent boot PWM'
else
    pass 'S37 contains no 100-percent boot PWM'
fi

if grep -Fq '/etc/init.d/S37board_setup start' "$ALIAS"; then
    fail 'S37 compatibility alias still duplicates canonical initialization'
else
    pass 'S37 compatibility alias cannot execute board initialization twice'
fi

require_literal "$S82" 'verify_amlogic_boot_safe_state' \
    'S82 requires the checked boot-safe receipt'
require_literal "$S82" 'mark-runtime-handoff' \
    'S82 publishes a runtime handoff before supervisor launch'
require_literal "$S82" 'refusing a competing one-shot safety owner while dcentrald is live' \
    'S82 safety refuses a competing live owner'
require_literal "$S82" 'emergency_hardware_safe_state' \
    'S82 has a monotonic post-owner emergency SafeOff path'
require_literal "$S82" 'physical rail remains unmeasured' \
    'S82 stop reporting preserves the software-vs-electrical evidence boundary'
require_literal "$S82" 'period/duty/enable evidence failed' \
    'S82 prelaunch cooling checks full PWM state rather than duty alone'
require_literal "$S82" 'HAD_VERIFIED_CHILD' \
    'S82 gives the verified parent a bounded terminal-receipt interval'
require_literal "$S82" '[ "$STATE" = Z ] || return 0' \
    'S82 distinguishes a non-executing zombie from a possible live owner'
if grep -Fq 'kill -TERM "$WRAPPER_PID"' "$S82" \
    || grep -Fq 'kill -9 "$WRAPPER_PID"' "$S82"; then
    fail 'S82 can signal a wrapper PID without start-time identity'
else
    pass 'S82 never signals an unverified wrapper PID'
fi

require_literal "$LATCH" 'execute the platform' \
    'session supervisor documents cut-before-journal ordering'
require_literal "$LATCH" 'REASON=${REASON}-safeoff-failed' \
    'session supervisor records emergency-cut failure in terminal status'
require_literal "$LATCH" '[ "$SAFETY_OK" -eq 1 ] || return 1' \
    'session supervisor cannot return success after emergency-cut failure'
SAFETY_LINE=$(grep -n -F 'if "$SAFETY_SCRIPT" safety' "$LATCH" | head -n 1 | cut -d: -f1)
PROMOTE_LINE=$(grep -n -F 'if ! promote_unresolved "$TERMINAL_REASON"' "$LATCH" | head -n 1 | cut -d: -f1)
if [ -n "$SAFETY_LINE" ] && [ -n "$PROMOTE_LINE" ] && [ "$SAFETY_LINE" -lt "$PROMOTE_LINE" ]; then
    pass 'post-exit emergency cut precedes potentially blocking journal promotion'
else
    fail 'session supervisor can delay emergency cut behind journal promotion'
fi

STOP_LINE=$(grep -n -F 'run_init_scripts("stop", service_posture);' "$INIT" | head -n 1 | cut -d: -f1)
TERM_LINE=$(grep -n -F 'libc::kill(-1, libc::SIGTERM)' "$INIT" | head -n 1 | cut -d: -f1)
KILL_LINE=$(grep -n -F 'libc::kill(-1, libc::SIGKILL)' "$INIT" | head -n 1 | cut -d: -f1)
if [ -n "$STOP_LINE" ] && [ -n "$TERM_LINE" ] && [ -n "$KILL_LINE" ] \
    && [ "$STOP_LINE" -lt "$TERM_LINE" ] && [ "$TERM_LINE" -lt "$KILL_LINE" ]; then
    pass 'PID 1 runs typed service teardown before residual TERM/KILL'
else
    fail 'PID 1 can kill the hardware owner before its typed stop path'
fi

require_literal "$HAL" 'parse_amlogic_boot_safe_handoff' \
    'HAL parses the versioned handoff as typed evidence'
require_literal "$HAL" 'validate_amlogic_boot_safe_handoff(expected)?;' \
    'NoPic admission revalidates the boot handoff before plug GPIO mutation'
require_literal "$HAL" '"state", "runtime-handoff"' \
    'HAL accepts only the supervisor-published runtime handoff state'
require_literal "$HAL" '"physical_rail_measured", "false"' \
    'HAL pins the non-electrical evidence grade'
require_literal "$HAL" 'require("hashboard_reset_low_bitmap", "0x7")?;' \
    'HAL refuses runtime handoff without the complete reset-low bitmap'
require_literal "$HAL" 'require("hashboard_reset_gpio455_active_low", "0")?;' \
    'HAL refuses runtime handoff without reset active_low=0 evidence'
require_literal "$HAL" 'read_live("/sys/class/gpio/gpio454/direction")?;' \
    'HAL live-revalidates the first hashboard reset leg before admission'
require_literal "$HAL" 'read_live("/sys/class/gpio/gpio454/active_low")?;' \
    'HAL live-revalidates reset GPIO454 raw polarity before admission'
require_literal "$HAL" 'read_live("/sys/class/gpio/gpio456/value")?;' \
    'HAL live-revalidates the final hashboard reset leg before admission'
require_literal "$HAL" 'let active_low = read_live("/sys/class/gpio/gpio437/active_low")?;' \
    'HAL revalidates raw active-high mode before runtime admission'

require_literal "$API_REBOOT" 'Transfer authority before claiming acceptance' \
    'API observes init request acceptance before reporting success'
API_HANDLER_BODY=$(sed -n '/^pub(super) async fn post_action_reboot/,/^pub(super) enum RebootRequestError/p' "$API_REBOOT")
API_PRE_TRANSFER=$(printf '%s\n' "$API_HANDLER_BODY" | sed '/trigger_system_reboot().await/q')
if printf '%s\n' "$API_PRE_TRANSFER" | grep -Eq 'push_rest_audit_free|tracing::'; then
    fail 'API can block on audit or logging before init receives reboot authority'
else
    pass 'API transfers reboot authority before audit and logging'
fi
if printf '%s\n' "$API_HANDLER_BODY" | grep -Eq 'tokio::spawn|tokio::time::sleep|Command::new\("dd"\)|Command::new\("sync"\)'; then
    fail 'API can delay or block before transferring reboot authority to init'
else
    pass 'API has no delay, detached task, entropy write, or sync before init acceptance'
fi
API_REBOOT_BODY=$(sed -n '/^pub(super) async fn trigger_system_reboot()/,/^\/\/\/ POST \/api\/action\/sleep/p' "$API_REBOOT")
if printf '%s\n' "$API_REBOOT_BODY" | grep -Eq '/proc/sysrq-trigger|\.arg\("-f"\)|REBOOT_FALLBACK_GRACE_SECS'; then
    fail 'API retains a competing sysrq, forced-reboot, or timer authority'
else
    pass 'API has no competing sysrq, forced-reboot, or timer authority'
fi
require_literal "$INIT" 'libc::clock_nanosleep(' \
    'PID 1 shutdown watchdog uses a monotonic absolute sleep'
require_literal "$INIT" 'libc::TIMER_ABSTIME' \
    'PID 1 shutdown deadline cannot be reset by EINTR retries'
ARM_LINE=$(grep -n -F 'arm_emergency_watchdog(rb_action, SHUTDOWN_WATCHDOG_MS);' "$INIT" | head -n 1 | cut -d: -f1)
SHUTDOWN_LOG_LINE=$(grep -n -F '"[init] Shutdown requested (signal {} -> {})"' "$INIT" | head -n 1 | cut -d: -f1)
ORDERLY_LINE=$(grep -n -F 'do_shutdown(service_posture, &external_started_services);' "$INIT" | head -n 1 | cut -d: -f1)
if [ -n "$ARM_LINE" ] && [ -n "$SHUTDOWN_LOG_LINE" ] && [ -n "$ORDERLY_LINE" ] \
    && [ "$ARM_LINE" -lt "$SHUTDOWN_LOG_LINE" ] && [ "$SHUTDOWN_LOG_LINE" -lt "$ORDERLY_LINE" ]; then
    pass 'PID 1 arms its terminal deadline before shutdown logging or orderly work'
else
    fail 'PID 1 can block before its terminal shutdown deadline exists'
fi
WATCHDOG_BODY=$(sed -n '/^fn arm_emergency_watchdog/,/^fn unmount_all/p' "$INIT")
WATCHDOG_SPAWN_LINE=$(printf '%s\n' "$WATCHDOG_BODY" | grep -n -F '.spawn(move ||' | head -n 1 | cut -d: -f1)
WATCHDOG_SYSRQ_LINE=$(printf '%s\n' "$WATCHDOG_BODY" | grep -n -F 'write_kernel_control_byte(b"/proc/sys/kernel/sysrq' | head -n 1 | cut -d: -f1)
if [ -n "$WATCHDOG_SPAWN_LINE" ] && [ -n "$WATCHDOG_SYSRQ_LINE" ] \
    && [ "$WATCHDOG_SPAWN_LINE" -lt "$WATCHDOG_SYSRQ_LINE" ]; then
    pass 'PID 1 creates the deadline thread before best-effort sysrq preparation'
else
    fail 'PID 1 can block in sysrq preparation before creating its deadline thread'
fi
EMERGENCY_BODY=$(sed -n '/^fn emergency_kernel_action/,/^fn install_signal_handlers/p' "$INIT")
if printf '%s\n' "$EMERGENCY_BODY" | grep -Eq 'libc::sync|eprintln!|println!|fs::write'; then
    fail 'PID 1 emergency path can block on sync, logging, or std::fs before reboot'
else
    pass 'PID 1 emergency path reaches terminal kernel action without sync, logging, or std::fs'
fi
SYSRQ_LINE=$(printf '%s\n' "$EMERGENCY_BODY" | grep -n -F 'write_kernel_control_byte(b"/proc/sysrq-trigger' | head -n 1 | cut -d: -f1)
RAW_REBOOT_LINE=$(printf '%s\n' "$EMERGENCY_BODY" | grep -n -F 'libc::reboot(rb_action)' | head -n 1 | cut -d: -f1)
if [ -n "$SYSRQ_LINE" ] && [ -n "$RAW_REBOOT_LINE" ] && [ "$SYSRQ_LINE" -lt "$RAW_REBOOT_LINE" ]; then
    pass 'PID 1 terminal deadline uses immediate sysrq before orderly reboot fallback'
else
    fail 'PID 1 terminal deadline can block in orderly reboot before immediate sysrq'
fi

require_literal "$RECOVERY" '/etc/init.d/S37board_setup start' \
    'Amlogic manual recovery re-establishes the checked boot baseline'
require_literal "$WEB_SERVER" 'manual_resolution_required' \
    'Amlogic web control reports the manual recovery policy'
if grep -Fq 'Run guarded restart' "$RECOVERY" \
    || grep -Fq 'Run guarded restart' "$DIAGNOSTIC" \
    || grep -Fq '["/etc/init.d/S82dcentrald", "restart"]' "$WEB_SERVER"; then
    fail 'Amlogic web recovery still advertises or executes forbidden restart'
else
    pass 'Amlogic web recovery does not advertise or execute forbidden restart'
fi


INSTALL_PERSISTENT="$PROJECT_DIR/scripts/install_amlogic_persistent.sh"
require_literal "$INSTALL_PERSISTENT" 'Step 7b/10: GPIO437 PWR_EN SafeOff' \
    'persistent Amlogic install requires GPIO437 SafeOff before NAND mutation'
require_literal "$INSTALL_PERSISTENT" 'GPIO437_SAFE_OFF=1' \
    'persistent Amlogic install SafeOff=1 on s19kpro (0 ENGAGES rails)'
require_literal "$INSTALL_PERSISTENT" 'am3-s19k-active-low' \
    'persistent Amlogic install documents am3-s19k GPIO437 polarity'
require_literal "$INSTALL_PERSISTENT" 'ERROR: gpio437 value=' \
    'persistent Amlogic install proves GPIO437 matches SKU SafeOff after write'
require_literal "$INSTALL_PERSISTENT" 'refusing NAND mutation' \
    'persistent Amlogic install refuses flash when SafeOff fails'
# Ordering: immutable refusal must precede the dormant SafeOff and root-FD
# transaction; inside that one target-side shell, binding and hashing the root
# inode plus the final live SafeOff check must all precede erase, which must
# precede the FD-backed write.
CLEAR_FOR_FLASH_LINE=$(grep -n -F -x 'CLEAR_FOR_FLASH=false' "$INSTALL_PERSISTENT" | head -n 1 | cut -d: -f1)
SAFEOFF_LINE=$(grep -n -F 'Step 7b/10: GPIO437 PWR_EN SafeOff' "$INSTALL_PERSISTENT" | head -n 1 | cut -d: -f1)
ROOT_FD_LINE=$(grep -n -F "exec 3< '\$REMOTE_PREFIX/root'" "$INSTALL_PERSISTENT" | head -n 1 | cut -d: -f1)
ROOT_FD_HASH_LINE=$(grep -n -F 'sha256sum /proc/self/fd/3' "$INSTALL_PERSISTENT" | head -n 1 | cut -d: -f1)
LIVE_SAFEOFF_LINE=$(grep -n -F 'cat /sys/class/gpio/gpio437/value' "$INSTALL_PERSISTENT" | tail -n 1 | cut -d: -f1)
FLASH_LINE=$(grep -n -F 'flash_erase $ROOTFS_MTD $ROOTFS_OFFSET_HEX $ROOTFS_ERASE_COUNT || exit 1' "$INSTALL_PERSISTENT" | head -n 1 | cut -d: -f1)
NANDWRITE_LINE=$(grep -n -F 'nandwrite -p -s $ROOTFS_OFFSET_HEX $ROOTFS_MTD /proc/self/fd/3 || exit 1' "$INSTALL_PERSISTENT" | head -n 1 | cut -d: -f1)
if [ -n "$CLEAR_FOR_FLASH_LINE" ] && [ -n "$SAFEOFF_LINE" ] \
   && [ -n "$ROOT_FD_LINE" ] && [ -n "$ROOT_FD_HASH_LINE" ] \
   && [ -n "$LIVE_SAFEOFF_LINE" ] && [ -n "$FLASH_LINE" ] \
   && [ -n "$NANDWRITE_LINE" ] \
   && [ "$CLEAR_FOR_FLASH_LINE" -lt "$SAFEOFF_LINE" ] \
   && [ "$SAFEOFF_LINE" -lt "$ROOT_FD_LINE" ] \
   && [ "$ROOT_FD_LINE" -lt "$ROOT_FD_HASH_LINE" ] \
   && [ "$ROOT_FD_HASH_LINE" -lt "$LIVE_SAFEOFF_LINE" ] \
   && [ "$LIVE_SAFEOFF_LINE" -lt "$FLASH_LINE" ] \
   && [ "$FLASH_LINE" -lt "$NANDWRITE_LINE" ]; then
    pass 'persistent Amlogic install refusal, SafeOff, bound root hash, live GPIO check, erase, and FD-backed write are strictly ordered'
else
    fail 'persistent Amlogic install root-FD transaction can bypass immutable refusal, SafeOff, content binding, or erase-before-write ordering'
fi

S19K_RAIL="$PROJECT_DIR/br2_external_dcentos/board/amlogic/am3-s19kpro/rootfs-overlay/etc/dcentos/rail_gpio"
S19K_TARGET="$PROJECT_DIR/br2_external_dcentos/board/amlogic/am3-s19kpro/rootfs-overlay/etc/dcentos/board_target"
S19K_PLATFORM="$PROJECT_DIR/br2_external_dcentos/board/amlogic/am3-s19kpro/rootfs-overlay/etc/dcentos-platform"

LAB_ROOTFS="$PROJECT_DIR/scripts/amlogic_lab_rootfs.sh"
require_file "$LAB_ROOTFS"
require_literal "$LAB_ROOTFS" 'require_gpio437_safe_off_before_mutation' \
    'lab Amlogic rootfs write/restore requires GPIO437 SafeOff helper'
require_literal "$LAB_ROOTFS" 'GPIO437 PWR_EN SafeOff (polarity=' \
    'lab Amlogic rootfs documents SKU-scoped GPIO437 SafeOff before mutation'
require_literal "$LAB_ROOTFS" 'am3-s19k-active-low' \
    'lab Amlogic rootfs SafeOff=1 on am3-s19k (0 ENGAGES rails)'
require_literal "$LAB_ROOTFS" 'ERROR: gpio437 value=' \
    'lab Amlogic rootfs proves GPIO437 matches SKU SafeOff after write'
require_literal "$LAB_ROOTFS" 'refusing NAND mutation' \
    'lab Amlogic rootfs refuses flash when SafeOff fails'
require_literal "$LAB_ROOTFS" 'CLEAR_FOR_FLASH=false - refusing gpio437 SafeOff/flash_erase/nandwrite' \
    'lab Amlogic rootfs refuses NAND while FLASH-false'
require_literal "$LAB_ROOTFS" '--lab-only is not a FLASH override' \
    'lab Amlogic rootfs lab flags do not override FLASH'
require_literal "$LAB_ROOTFS" 'tr -d " \t\r\n"' \
    'lab Amlogic rootfs uses BusyBox-safe board-target whitespace deletion'
if grep -F 'tr -d "[:space:]"' "$LAB_ROOTFS" >/dev/null 2>&1; then
    fail 'lab Amlogic rootfs retains BusyBox-corrupting tr character-class deletion'
else
    pass 'lab Amlogic rootfs rejects BusyBox-corrupting tr character-class deletion'
fi
LAB_WRITE_FLASH=$(grep -n -F 'flash_erase $ROOTFS_MTD' "$LAB_ROOTFS" | head -n 1 | cut -d: -f1)
LAB_RESTORE_FLASH=$(grep -n -F 'flash_erase $ROOTFS_MTD' "$LAB_ROOTFS" | tail -n 1 | cut -d: -f1)
LAB_WRITE_CALL=$(grep -n -F 'require_gpio437_safe_off_before_mutation "$MINER_IP"' "$LAB_ROOTFS" | head -n 1 | cut -d: -f1)
LAB_RESTORE_CALL=$(grep -n -F 'require_gpio437_safe_off_before_mutation "$MINER_IP"' "$LAB_ROOTFS" | tail -n 1 | cut -d: -f1)
if [ -n "$LAB_WRITE_CALL" ] && [ -n "$LAB_WRITE_FLASH" ] && [ "$LAB_WRITE_CALL" -lt "$LAB_WRITE_FLASH" ] \
   && [ -n "$LAB_RESTORE_CALL" ] && [ -n "$LAB_RESTORE_FLASH" ] && [ "$LAB_RESTORE_CALL" -lt "$LAB_RESTORE_FLASH" ]; then
    pass 'lab Amlogic rootfs SafeOff precedes flash_erase on write and restore'
else
    fail 'lab Amlogic rootfs can flash_erase without prior GPIO437 SafeOff'
fi

require_literal "$S19K_RAIL" '437' 'S19k overlay rail_gpio is GPIO437'
require_literal "$S19K_TARGET" 'am3-s19k' 'S19k overlay board_target is am3-s19k'
require_literal "$S19K_PLATFORM" 'am3-aml-s19k' 'S19k overlay platform is am3-aml-s19k'

if [ "$FAILURES" -ne 0 ]; then
    printf 'Amlogic boot-safe-state contract failed: %s failure(s)\n' "$FAILURES" >&2
    exit 1
fi

printf 'Amlogic boot-safe-state contract passed.\n'
