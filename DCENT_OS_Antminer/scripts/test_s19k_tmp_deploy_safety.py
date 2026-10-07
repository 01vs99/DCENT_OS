#!/usr/bin/env python3
"""Offline invariants for the S19k armv7 /tmp deployment transaction."""

from pathlib import Path
import hashlib
import os
import re
import shlex
import struct
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
SUPERVISOR_CUSTODY = SCRIPTS / "dcentrald_s19k_braiins_supervisor_custody.sh"
STOCK_RESTART_HELPER = SCRIPTS / "dcentrald_s19k_stock_restart_from_safeoff.sh"
COMMON_DEPLOY_RS = ROOT / "dcentrald" / "dcentrald-common" / "src" / "s19k_braiins_tmp_deploy.rs"


def daemon_admitted_journal_destinations() -> list[str]:
    """Trial basenames the daemon's publisher-v1 admits, read from the single
    Rust admission set so no fake daemon below can be more permissive than the
    sealed binary (2026-09-01: the live daemon refused every post-SafeOff
    receipt while the fake daemon linked anything)."""
    source = COMMON_DEPLOY_RS.read_text(encoding="utf-8")
    start = source.index(
        "pub const S19K_EPHEMERAL_JOURNAL_TRIAL_DESTINATIONS: &[&str] = &["
    )
    end = source.index("];", start)
    names = re.findall(r'"([a-z0-9_]+)"', source[start:end])
    if len(names) < 7 or len(set(names)) != len(names):
        raise AssertionError("daemon journal admission set is unreadable")
    return names


DAEMON_ADMITTED_JOURNAL_DESTINATIONS = daemon_admitted_journal_destinations()


def publisher_admission_sh(source_var: str, destination_var: str, indent: str) -> str:
    """POSIX-sh mirror of classify_s19k_ephemeral_journal_destination() for the
    fake daemons: same-directory trial journals from the admitted set, the
    global lock ``owner`` (the harness remaps the lock dir to
    ``<trial>.board-global-lock``), and ``endurance_evidence/acks/ack.NNNNNN.kv``
    from a ``.ack.*`` scratch beside it. Anything else exits 87 without linking."""
    names = "|".join(DAEMON_ADMITTED_JOURNAL_DESTINATIONS)
    lines = [
        f'P_DST_NAME=${{{destination_var}##*/}}; P_DST_DIR=${{{destination_var}%/*}}; '
        f'P_SRC_DIR=${{{source_var}%/*}}; P_SRC_NAME=${{{source_var}##*/}}',
        'case "$P_DST_NAME" in',
        f'    {names}) [ "$P_DST_DIR" = "$P_SRC_DIR" ] && [ "${{P_SRC_DIR##*/}}" != acks ] '
        '&& [ "${P_SRC_NAME#.}" != "$P_SRC_NAME" ] || exit 87 ;;',
        '    owner) case "$P_DST_DIR" in /tmp/dcent-s19k-track1-runtime-lock|*.board-global-lock) ;; '
        '*) exit 87 ;; esac ;;',
        '    ack.[0-9][0-9][0-9][0-9][0-9][0-9].kv) [ "$P_DST_DIR" = "$P_SRC_DIR" ] '
        '&& [ "${P_SRC_DIR##*/}" = acks ] && [ "${P_SRC_NAME#.ack.}" != "$P_SRC_NAME" ] || exit 87 ;;',
        "    *) exit 87 ;;",
        "esac",
    ]
    return "".join(f"{indent}{line}\n" for line in lines)



# Fake Track-1 daemon for the J2/release orphan regression. It implements the
# daemon-v1 pre-runtime bootstrap contract exactly (C1/J1 ordered journals,
# J0-bound FIFO reader, blocked wait with wrapper-liveness polling, release
# token verification) with the POST-FIX wrapper-liveness semantics: the
# wrapper's pid/start/comm/exe/cmdline stay pinned; its live PPID is NOT
# re-pinned (kernel reparenting on parent exit must not kill the handshake).
# A #!/bin/sh child cannot present comm/exe/cmdline of the real ELF daemon, so
# the fixture runner adapts three child-identity conjuncts behind the
# .fake_daemon_adapter marker (see _j2_orphan_fixture_runner).
J2_ORPHAN_FAKE_DAEMON = r'''#!/bin/sh
TRIAL_DIR=$(dirname "$0")
LOCK="$TRIAL_DIR.board-global-lock"
OWNER="$LOCK/owner"
FIFO=$DCENT_S19K_STARTUP_FIFO
LOG=$DCENT_S19K_STARTUP_LOG
WRAP_PID=$DCENT_S19K_STARTUP_WRAPPER_PID
WRAP_START=$DCENT_S19K_STARTUP_WRAPPER_START
C1="$TRIAL_DIR/runtime_startup_c1_child_identity"
J1="$TRIAL_DIR/runtime_startup_j1_daemon_blocked"
J2F="$TRIAL_DIR/runtime_startup_j2_child_bound"
RELF="$TRIAL_DIR/runtime_startup_release"
DBG="$TRIAL_DIR/.fake_daemon_trace"
say() { printf '%s\n' "$*" >> "$DBG"; }
field() {
    F_FILE=$1; F_KEY=$2
    [ "$(grep -c "^$F_KEY=" "$F_FILE" 2>/dev/null || true)" -eq 1 ] || return 1
    sed -n "s/^$F_KEY=//p" "$F_FILE"
}
P_SRC=; P_DST=
PREV=
for A in "$@"; do
    case "$PREV" in
        src) P_SRC=$A ;;
        dst) P_DST=$A ;;
    esac
    case "$A" in
        --s19k-track1-journal-source) PREV=src; continue ;;
        --s19k-track1-journal-destination) PREV=dst; continue ;;
    esac
    PREV=
done
if [ -n "$P_SRC" ] && [ -n "$P_DST" ]; then
    ln "$P_SRC" "$P_DST"
    exit $?
fi
case " $* " in
    *' --s19k-track1-recovery-safeoff '*)
        printf '1\n' > "__GPIO__/gpio437/value"
        printf '0\n' > "__GPIO__/gpio454/value"
        printf '0\n' > "__GPIO__/gpio455/value"
        printf '0\n' > "__GPIO__/gpio456/value"
        printf '%s\n' "DCENT_S19K_TRACK1_SAFEOFF_RECEIPT schema=dcentos.s19k-track1-safeoff/v1 live_identity_sha256=$DCENT_S19K_LIVE_IDENTITY_SHA256 live_identity_profile=__PROFILE__ live_identity_model_sha256=__MODEL_SHA__ live_identity_board_count=3 live_identity_physical_addresses=1,2,3 live_identity_board_names=BHB56902,BHB56902,BHB56902 live_identity_eeprom=0x50=05:11,0x51=05:11,0x52=05:11 resets=454:0,455:0,456:0 psu=437:1"
        exit 0
        ;;
esac
say "daemon start pid=$$ ppid=$PPID"
for EXP_VAR in DCENTOS_EPHEMERAL_RUNTIME DCENTOS_LOG_RING_DIR \
    DCENT_S19K_LIVE_IDENTITY_SHA256 DCENT_S19K_STARTUP_BOOTSTRAP \
    DCENT_S19K_STARTUP_FIFO DCENT_S19K_STARTUP_LOG \
    DCENT_S19K_STARTUP_WRAPPER_PID DCENT_S19K_STARTUP_WRAPPER_START \
    DCENT_S19K_TRACK1_STOP_SAFEOFF PATH; do
    eval "EXP_VAL=\${$EXP_VAR:-}"
    [ -n "$EXP_VAL" ] || { say "env missing $EXP_VAR"; exit 81; }
done
[ "$DCENT_S19K_STARTUP_BOOTSTRAP" = daemon-v1 ] || exit 81
[ -f "$OWNER" ] || { say "owner absent"; exit 81; }
TXID=$(field "$OWNER" transaction_id) || exit 81
wrap_live() {
    W_STAT=$(cat "/proc/$WRAP_PID/stat" 2>/dev/null) || return 1
    case "$W_STAT" in *') '*) ;; *) return 1 ;; esac
    W_REST=${W_STAT##*) }
    set -- $W_REST
    [ "$#" -ge 20 ] || return 1
    W_STATE=$1
    shift 19
    W_LIVE_START=$1
    case "$W_STATE" in Z|X|x) return 1 ;; esac
    [ "$W_LIVE_START" = "$WRAP_START" ] || return 1
    [ "$(cat "/proc/$WRAP_PID/comm" 2>/dev/null || true)" = "$(field "$OWNER" wrapper_comm)" ] || return 1
    [ "$(readlink "/proc/$WRAP_PID/exe" 2>/dev/null || true)" = "$(field "$OWNER" wrapper_exe)" ] || return 1
    [ "$(sha256sum "/proc/$WRAP_PID/cmdline" 2>/dev/null | awk '{print $1}')" = "$(field "$OWNER" wrapper_cmdline_sha256)" ] || return 1
    return 0
}
SELF_STAT=$(cat /proc/$$/stat 2>/dev/null)
SELF_REST=${SELF_STAT##*) }
set -- $SELF_REST
shift 19
CHILD_START=$1
CHILD_COMM=$(cat /proc/$$/comm)
CHILD_EXE=$(readlink /proc/$$/exe)
CHILD_CMD_SHA=$(field "$OWNER" expected_daemon_cmdline_sha256)
CHILD_CMD_BYTES=$(field "$OWNER" expected_daemon_cmdline_bytes)
exec 4< "$LOG" || exit 81
LS_LINE=$(ls -lniL "/proc/$$/fd/4" 2>/dev/null || true)
set -- $LS_LINE
T_INODE=${1:-}
T_MNT=$(sed -n 's/^mnt_id:[[:space:]]*//p' "/proc/$$/fdinfo/4" 2>/dev/null)
exec 4>&-
T_PATH=$LOG
sha_bytes() {
    SB=$(sha256sum "$1" | awk '{print $1}')
    SBB=$(wc -c < "$1" | tr -d ' \t\r\n')
}
sha_bytes "$OWNER"
C1_TMP="$TRIAL_DIR/.runtime_startup_c1.tmp.$$.$CHILD_START"
{
    printf 'schema=dcentos.s19k-startup-c1-child-identity/v1\n'
    printf 'transaction_id=%s\n' "$TXID"
    printf 'ordinal=1\n'
    printf 'predecessor_schema=dcentos.s19k-startup-j0-prefork/v1\n'
    printf 'predecessor_sha256=%s\n' "$SB"
    printf 'predecessor_bytes=%s\n' "$SBB"
    printf 'runtime_owner_path=%s\n' "$OWNER"
    printf 'runtime_owner_sha256=%s\n' "$SB"
    printf 'runtime_owner_bytes=%s\n' "$SBB"
    printf 'child_pid=%s\nchild_start=%s\nchild_ppid=%s\n' "$$" "$CHILD_START" "$WRAP_PID"
    printf 'child_comm=%s\nchild_exe=%s\n' "$CHILD_COMM" "$CHILD_EXE"
    printf 'child_cmdline_sha256=%s\nchild_cmdline_bytes=%s\n' "$CHILD_CMD_SHA" "$CHILD_CMD_BYTES"
    printf 'child_environment_sha256=%s\n' "$(field "$OWNER" daemon_environment_sha256)"
    printf 'child_environment_bytes=%s\n' "$(field "$OWNER" daemon_environment_bytes)"
    printf 'child_environment_count=%s\n' "$(field "$OWNER" daemon_environment_count)"
    printf 'bootstrap_fd_set=stdio-only\nstdin_path=/dev/null\n'
    printf 'transcript_path=%s\n' "$T_PATH"
    printf 'transcript_mnt_id=%s\ntranscript_inode=%s\n' "$T_MNT" "$T_INODE"
    printf 'transcript_mode=0600\ntranscript_uid=0\ntranscript_gid=0\n'
    printf 'wrapper_pid=%s\nwrapper_start=%s\nwrapper_ppid=%s\n' "$WRAP_PID" "$WRAP_START" "$(field "$OWNER" wrapper_ppid)"
    printf 'wrapper_comm=%s\n' "$(field "$OWNER" wrapper_comm)"
    printf 'wrapper_exe=%s\n' "$(field "$OWNER" wrapper_exe)"
    printf 'wrapper_cmdline_sha256=%s\n' "$(field "$OWNER" wrapper_cmdline_sha256)"
    printf 'wrapper_cmdline_bytes=%s\n' "$(field "$OWNER" wrapper_cmdline_bytes)"
    printf 'binary_sha256=%s\nbinary_bytes=%s\n' "$(field "$OWNER" binary_sha256)" "$(field "$OWNER" binary_bytes)"
    printf 'pdeathsig=9\npdeathsig_scope=process-lifetime\n'
    printf 'watchdog_start_intent=false\nwatchdog_armed=false\nsignal_attempted=false\n'
    printf 'inherited_rails=false\nroute_or_uart_opened=false\nhardware_opened=false\n'
    printf 'parent_release=false\npersistent_mutation=false\n'
    printf 'publication=no-clobber-hard-link-after-fsync\n'
} > "$C1_TMP"
chmod 600 "$C1_TMP"
ln "$C1_TMP" "$C1" || { say "c1 ln failed"; rm -f "$C1_TMP"; exit 83; }
rm -f "$C1_TMP"
say "c1 published"
exec 3<> "$FIFO" || { say "fifo open failed"; exit 84; }
sha_bytes "$C1"
J1_TMP="$TRIAL_DIR/.runtime_startup_j1.tmp.$$.$CHILD_START"
{
    printf 'schema=dcentos.s19k-startup-j1-daemon-blocked/v1\n'
    printf 'transaction_id=%s\n' "$TXID"
    printf 'ordinal=2\n'
    printf 'predecessor_schema=dcentos.s19k-startup-c1-child-identity/v1\n'
    printf 'predecessor_sha256=%s\npredecessor_bytes=%s\n' "$SB" "$SBB"
    printf 'trial_dir=%s\n' "$TRIAL_DIR"
    printf 'runtime_active_path=not-published\nruntime_active_sha256=none\n'
    printf 'runtime_active_bytes=0\nruntime_active_phase=not-published\n'
    printf 'runtime_owner_path=%s\n' "$OWNER"
    sha_bytes "$OWNER"
    printf 'runtime_owner_sha256=%s\nruntime_owner_bytes=%s\n' "$SB" "$SBB"
    printf 'writer_role=daemon-blocked\nwriter_pid=%s\nwriter_start=%s\nwriter_ppid=%s\n' "$$" "$CHILD_START" "$WRAP_PID"
    printf 'daemon_pid=%s\ndaemon_start=%s\n' "$$" "$CHILD_START"
    printf 'wrapper_pid=%s\nwrapper_start=%s\nwrapper_ppid=%s\n' "$WRAP_PID" "$WRAP_START" "$(field "$OWNER" wrapper_ppid)"
    printf 'wrapper_comm=%s\n' "$(field "$OWNER" wrapper_comm)"
    printf 'wrapper_exe=%s\n' "$(field "$OWNER" wrapper_exe)"
    printf 'wrapper_cmdline_sha256=%s\n' "$(field "$OWNER" wrapper_cmdline_sha256)"
    printf 'wrapper_cmdline_bytes=%s\n' "$(field "$OWNER" wrapper_cmdline_bytes)"
    printf 'pdeathsig=9\npdeathsig_scope=process-lifetime\n'
    printf 'fifo_path=%s\n' "$(field "$OWNER" fifo_path)"
    printf 'fifo_mnt_id=%s\n' "$(field "$OWNER" fifo_mnt_id)"
    printf 'fifo_inode=%s\n' "$(field "$OWNER" fifo_inode)"
    printf 'fifo_mode=%s\n' "$(field "$OWNER" fifo_mode)"
    printf 'fifo_uid=%s\nfifo_gid=%s\n' "$(field "$OWNER" fifo_uid)" "$(field "$OWNER" fifo_gid)"
    printf 'fifo_reader_held=true\nbootstrap_fd_set=stdio-plus-single-fifo\nfifo_reader_fd=3\n'
    printf 'stdin_path=/dev/null\n'
    printf 'transcript_path=%s\n' "$T_PATH"
    printf 'transcript_mnt_id=%s\ntranscript_inode=%s\n' "$T_MNT" "$T_INODE"
    printf 'transcript_mode=0600\ntranscript_uid=0\ntranscript_gid=0\n'
    printf 'supervisor_pid=%s\n' "$(field "$OWNER" supervisor_pid)"
    printf 'supervisor_start=%s\n' "$(field "$OWNER" supervisor_start)"
    printf 'supervisor_ppid=%s\n' "$(field "$OWNER" supervisor_ppid)"
    printf 'supervisor_pgrp=%s\n' "$(field "$OWNER" supervisor_pgrp)"
    printf 'supervisor_session=%s\n' "$(field "$OWNER" supervisor_session)"
    printf 'supervisor_exe=%s\n' "$(field "$OWNER" supervisor_exe)"
    printf 'supervisor_cmdline_sha256=%s\n' "$(field "$OWNER" supervisor_cmdline_sha256)"
    printf 'supervisor_cmdline_bytes=%s\n' "$(field "$OWNER" supervisor_cmdline_bytes)"
    printf 'bosminer_pid=%s\n' "$(field "$OWNER" bosminer_pid)"
    printf 'bosminer_start=%s\n' "$(field "$OWNER" bosminer_start)"
    printf 'bosminer_ppid=%s\n' "$(field "$OWNER" bosminer_ppid)"
    printf 'bosminer_pgrp=%s\n' "$(field "$OWNER" bosminer_pgrp)"
    printf 'bosminer_session=%s\n' "$(field "$OWNER" bosminer_session)"
    printf 'bosminer_exe=%s\n' "$(field "$OWNER" bosminer_exe)"
    printf 'bosminer_cmdline_sha256=%s\n' "$(field "$OWNER" bosminer_cmdline_sha256)"
    printf 'bosminer_cmdline_bytes=%s\n' "$(field "$OWNER" bosminer_cmdline_bytes)"
    printf 'stock_pidfile_path=%s\n' "$(field "$OWNER" stock_pidfile_path)"
    printf 'stock_pidfile_sha256=%s\n' "$(field "$OWNER" stock_pidfile_sha256)"
    printf 'stock_pidfile_bytes=%s\n' "$(field "$OWNER" stock_pidfile_bytes)"
    printf 'binary_sha256=%s\nbinary_bytes=%s\n' "$(field "$OWNER" binary_sha256)" "$(field "$OWNER" binary_bytes)"
    printf 'config_sha256=%s\nconfig_bytes=%s\n' "$(field "$OWNER" config_sha256)" "$(field "$OWNER" config_bytes)"
    printf 'runner_sha256=%s\nrunner_bytes=%s\n' "$(field "$OWNER" runner_sha256)" "$(field "$OWNER" runner_bytes)"
    printf 'custody_observer_sha256=%s\n' "$(field "$OWNER" custody_observer_sha256)"
    printf 'custody_observer_bytes=%s\n' "$(field "$OWNER" custody_observer_bytes)"
    printf 'stock_restart_helper_sha256=%s\n' "$(field "$OWNER" stock_restart_helper_sha256)"
    printf 'stock_restart_helper_bytes=%s\n' "$(field "$OWNER" stock_restart_helper_bytes)"
    printf 'live_identity_schema=dcentos.s19k-braiins-live-identity/v2\n'
    printf 'live_identity_profile=%s\n' "$(field "$OWNER" live_identity_profile)"
    printf 'live_identity_sha256=%s\n' "$(field "$OWNER" live_identity_sha256)"
    printf 'gpio_raw=437:0,454:0,455:1,456:1\n'
    printf 'watchdog_start_intent=false\nwatchdog_armed=false\nsignal_attempted=false\n'
    printf 'inherited_rails=false\nroute_or_uart_opened=false\nhardware_opened=false\n'
    printf 'parent_release=false\npersistent_mutation=false\n'
    printf 'publication=no-clobber-hard-link-after-fsync\n'
} > "$J1_TMP"
chmod 600 "$J1_TMP"
ln "$J1_TMP" "$J1" || { say "j1 ln failed"; rm -f "$J1_TMP"; exit 83; }
rm -f "$J1_TMP"
say "j1 published; entering blocked wait"
while [ ! -e "$RELF" ]; do
    if ! wrap_live; then
        say "wrapper-live refused: state=$W_STATE start=$W_LIVE_START"
        exit 91
    fi
    [ -p "$FIFO" ] || { say "fifo vanished"; exit 92; }
    sleep 0.02
done
say "release observed"
[ -f "$J2F" ] || { say "release without J2"; exit 93; }
TOKEN=$(dd bs=64 count=1 2>/dev/null <&3)
exec 3>&-
J2_SHA=$(sha256sum "$J2F" | awk '{print $1}')
REL_SHA=$(sha256sum "$RELF" | awk '{print $1}')
WANT=$(printf '%s:%s:%s' "$TXID" "$J2_SHA" "$REL_SHA" | sha256sum | awk '{print $1}')
[ "$TOKEN" = "$WANT" ] || { say "token mismatch"; exit 94; }
say "token admitted; running bounded work"
sleep 1
say "daemon exit 0"
exit 0
'''

# Orphan launcher: runs the runner under setsid (so it survives the launcher's
# WSL session teardown) and exits the moment the trigger file appears, i.e. the
# wrapper is kernel-reparented between ACTIVE and J2/release publication. The
# runner path must never appear as a whole argv element of this launcher (the
# runner's competing-wrapper scan globs "$PREFIX"*/run_trial), so every path is
# derived from $0.
J2_ORPHAN_FAKE_DAEMON = J2_ORPHAN_FAKE_DAEMON.replace(
    'if [ -n "$P_SRC" ] && [ -n "$P_DST" ]; then\n    ln "$P_SRC" "$P_DST"\n',
    'if [ -n "$P_SRC" ] && [ -n "$P_DST" ]; then\n'
    + publisher_admission_sh("P_SRC", "P_DST", "    ")
    + '    ln "$P_SRC" "$P_DST"\n',
)
assert J2_ORPHAN_FAKE_DAEMON.count("exit 87") == 4

J2_ORPHAN_LAUNCHER = r'''#!/bin/sh
TRIGGER=$1; OUT=$2; PIDFILE=$3; shift 3
BASE=${0%.launcher}
TRIAL=$BASE
RUNNER=$BASE/run_trial
LOCK=$BASE.board-global-lock
setsid "$RUNNER" run "$TRIAL" am3-s19k mining-on-passthrough "$@" > "$OUT" 2>&1 &
WPID=$!
printf '%s\n' "$WPID" > "$PIDFILE"
N=0
while [ ! -e "$TRIAL/$TRIGGER" ]; do
    N=$((N + 1))
    [ "$N" -gt 4800 ] && { echo "trigger timeout" >> "$OUT"; break; }
    sleep 0.05
done
exit 0
'''

# Attempt-10 hard-ceiling launcher: runs the adapted runner in the FOREGROUND
# with an exported S19K_TMP_TRIAL_CEILING_SECONDS and records its exact exit
# status for post-run assertions.  The runner path is derived from $0 (never a
# whole launcher argv element) for the same competing-wrapper scan caution as
# J2_ORPHAN_LAUNCHER.
TRIAL_CEILING_LAUNCHER = r'''#!/bin/sh
OUT=$1; RCFILE=$2; CEILING=$3; DEPLOY_MODE=$4; TRIAL=$5; shift 5
BASE=${0%.launcher}
RUNNER=$BASE/run_trial
[ -n "$CEILING" ] && export S19K_TMP_TRIAL_CEILING_SECONDS="$CEILING"
"$RUNNER" run "$TRIAL" am3-s19k "$DEPLOY_MODE" "$@" > "$OUT" 2>&1
printf '%s\n' "$?" > "$RCFILE"
'''


class S19kTmpDeploySafetyTests(unittest.TestCase):
    @staticmethod
    def _armhf_executable(flags: int = 0x05000400) -> bytes:
        blob = bytearray(52 + 32 + 16)
        blob[:7] = b"\x7fELF\x01\x01\x01"
        struct.pack_into("<H", blob, 16, 2)  # ET_EXEC
        struct.pack_into("<H", blob, 18, 40)  # EM_ARM
        struct.pack_into("<I", blob, 20, 1)  # EV_CURRENT
        struct.pack_into("<I", blob, 24, 0x1000)  # e_entry
        struct.pack_into("<I", blob, 28, 52)  # e_phoff
        struct.pack_into("<I", blob, 36, flags)
        struct.pack_into("<H", blob, 40, 52)
        struct.pack_into("<H", blob, 42, 32)
        struct.pack_into("<H", blob, 44, 1)
        ph = 52
        struct.pack_into("<I", blob, ph, 1)  # PT_LOAD
        struct.pack_into("<I", blob, ph + 4, 84)
        struct.pack_into("<I", blob, ph + 8, 0x1000)
        struct.pack_into("<I", blob, ph + 16, 16)
        struct.pack_into("<I", blob, ph + 20, 16)
        struct.pack_into("<I", blob, ph + 24, 5)  # PF_R | PF_X
        return bytes(blob)

    @staticmethod
    def _shell_path(path: Path) -> str:
        if os.name != "nt":
            return str(path)
        resolved = path.resolve()
        drive = resolved.drive.rstrip(":").lower()
        relative = resolved.relative_to(resolved.anchor).as_posix()
        return f"/mnt/{drive}/{relative}"

    def _identity_bound_runner(
        self,
        temp: Path,
        remote_dir: str,
        boards: tuple[str, ...] = ("BHB56902", "BHB56902", "BHB56902"),
        physical_addresses: tuple[int, ...] | None = None,
        undetected_physical_addresses: tuple[int, ...] = (),
        eeprom_presence: tuple[bool, bool, bool] = (True, True, True),
        runtime_lock: str | None = None,
    ) -> Path:
        """Create a test-only runner whose immutable live-source paths use WSL fixtures."""
        fixture_dir = f"{remote_dir}/live_identity_fixture"
        subprocess.run(["wsl.exe", "mkdir", "-p", fixture_dir], check=True)
        cpuinfo = (
            "".join(
                f"processor\t: {index}\n"
                "CPU implementer\t: 0x41\n"
                "CPU architecture: 8\n"
                "CPU part\t: 0xd03\n\n"
                for index in range(4)
            )
            + "Hardware\t: Amlogic\n"
        )
        mtd = (
            "dev:    size   erasesize  name\n"
            'mtd0: 00200000 00020000 "bootloader"\n'
            'mtd1: 00800000 00020000 "tpl"\n'
            'mtd2: 03200000 00020000 "stock_system"\n'
            'mtd3: 00500000 00020000 "stock_config"\n'
            'mtd4: 02000000 00020000 "overlay"\n'
            'mtd5: 09900000 00020000 "system"\n'
        )
        if physical_addresses is None:
            physical_addresses = tuple(range(1, len(boards) + 1))
        if len(physical_addresses) != len(boards):
            raise ValueError("physical address count must match board count")
        board_rows = ",\n".join(
            "        {\n"
            f'          "physical_address": {physical_address},\n'
            f'          "board_name": "{name}",\n'
            f'          "serial_number": "FIXTURE-{physical_address}",\n'
            '          "hashrate_ths": 46.12146\n'
            "        }"
            for physical_address, name in zip(physical_addresses, boards)
        )
        undetected_rows = ",\n".join(
            "        {\n"
            f'          "physical_address": {physical_address},\n'
            '          "hashrate_ths": 46.12146,\n'
            '          "note": "HB not detected. Board name unknown. '
            'hashrate_ths is calculated."\n'
            "        }"
            for physical_address in undetected_physical_addresses
        )
        if undetected_rows:
            board_rows = (
                f"{undetected_rows},\n{board_rows}" if board_rows else undetected_rows
            )
        model = (
            '{\n  "config_descriptor": {\n    "miner": {\n'
            '      "model": "Antminer S19K Pro NoPic",\n'
            '      "vendor_name": "Antminer S19k Pro",\n'
            f'      "hashboards": [\n{board_rows}\n      ]\n'
            "    }\n  }\n}\n"
        )
        i2cget = (
            "#!/bin/sh\n"
            'case "$3:$4" in\n'
            + "".join(
                f"  0x{0x50 + index:02x}:0) echo 0x05 ;;\n"
                f"  0x{0x50 + index:02x}:1) echo 0x11 ;;\n"
                for index, present in enumerate(eeprom_presence)
                if present
            )
            + "  *) exit 1 ;;\nesac\n"
        )
        fixture_files = {
            "cpuinfo": cpuinfo,
            "proc_mtd": mtd,
            "bos_platform": "am3-aml\n",
            "bos_mode": "nand\n",
            "bosminer_model.json": model,
            "uname": "#!/bin/sh\necho aarch64\n",
            "i2cget": i2cget,
        }
        for name, text_value in fixture_files.items():
            source = temp / f"fixture_{name}"
            source.write_text(text_value, encoding="utf-8", newline="\n")
            subprocess.run(
                ["wsl.exe", "cp", self._shell_path(source), f"{fixture_dir}/{name}"],
                check=True,
            )
        subprocess.run(
            [
                "wsl.exe",
                "chmod",
                "755",
                f"{fixture_dir}/i2cget",
                f"{fixture_dir}/uname",
            ],
            check=True,
        )
        stock_files = {
            "bosminer.pid": "1458\n",
            "supervisor.stat": (
                "1458 (bos-tools) S 1 1457 1457 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1251\n"
            ),
            "supervisor.comm": "bos-tools\n",
            "supervisor.cmdline": (
                "/usr/bin/bos-tools\0run-and-watch\0--\0"
                "/usr/bin/bosminer\0--log-to-file\0"
            ),
            "child.stat": (
                "9495 (bosminer) S 1458 1457 1457 0 -1 0 0 0 0 0 0 0 0 0 "
                "20 0 1 0 1044815\n"
            ),
            "child.comm": "bosminer\n",
            "child.cmdline": "/usr/bin/bosminer\0--log-to-file\0",
        }
        subprocess.run(
            [
                "wsl.exe",
                "mkdir",
                "-p",
                f"{fixture_dir}/proc/1458",
                f"{fixture_dir}/proc/9495",
            ],
            check=True,
        )
        stock_destinations = {
            "bosminer.pid": f"{fixture_dir}/bosminer.pid",
            "supervisor.stat": f"{fixture_dir}/proc/1458/stat",
            "supervisor.comm": f"{fixture_dir}/proc/1458/comm",
            "supervisor.cmdline": f"{fixture_dir}/proc/1458/cmdline",
            "child.stat": f"{fixture_dir}/proc/9495/stat",
            "child.comm": f"{fixture_dir}/proc/9495/comm",
            "child.cmdline": f"{fixture_dir}/proc/9495/cmdline",
        }
        for name, text_value in stock_files.items():
            source_file = temp / f"fixture_{name}"
            source_file.write_text(text_value, encoding="utf-8", newline="\n")
            subprocess.run(
                [
                    "wsl.exe",
                    "cp",
                    self._shell_path(source_file),
                    stock_destinations[name],
                ],
                check=True,
            )
        subprocess.run(
            [
                "wsl.exe",
                "ln",
                "-sf",
                "/usr/bin/bos-tools",
                f"{fixture_dir}/proc/1458/exe",
            ],
            check=True,
        )
        subprocess.run(
            [
                "wsl.exe",
                "ln",
                "-sf",
                "/usr/bin/bosminer",
                f"{fixture_dir}/proc/9495/exe",
            ],
            check=True,
        )
        # Exact recovered-stock baseline observed on .88 after bosminer restart:
        # PSU cut deasserted and only physical chains 2/3 released from reset.
        for gpio, value in ((437, 0), (454, 0), (455, 1), (456, 1)):
            gpio_dir = f"{fixture_dir}/gpio/gpio{gpio}"
            subprocess.run(["wsl.exe", "mkdir", "-p", gpio_dir], check=True)
            for field, field_value in (
                ("direction", "out\n"),
                ("active_low", "0\n"),
                ("value", f"{value}\n"),
            ):
                source_file = temp / f"fixture_gpio{gpio}_{field}"
                source_file.write_text(field_value, encoding="utf-8", newline="\n")
                subprocess.run(
                    [
                        "wsl.exe",
                        "cp",
                        self._shell_path(source_file),
                        f"{gpio_dir}/{field}",
                    ],
                    check=True,
                )
        stock_init = temp / "fixture_S99bosminer"
        stock_init.write_text(
            "#!/bin/sh\n# offline exact-stock-init fixture\nexit 0\n",
            encoding="utf-8",
            newline="\n",
        )
        subprocess.run(
            [
                "wsl.exe",
                "cp",
                self._shell_path(stock_init),
                f"{fixture_dir}/S99bosminer",
            ],
            check=True,
        )
        stock_init_blob = stock_init.read_bytes()
        stock_init_sha = hashlib.sha256(stock_init_blob).hexdigest()
        source = (SCRIPTS / "dcentrald_s19k_tmp_remote_run.sh").read_text(
            encoding="utf-8"
        )
        # Production intentionally scans the board-global /tmp prefix. Give
        # each offline fixture a near-exact private prefix so concurrent test
        # processes cannot impersonate another fixture's live wrapper, while
        # the explicit same-fixture wrapper and board-global-lock regressions
        # still exercise the refusal path.
        fixture_prefix = remote_dir[:-1]
        replacements = {
            "WRAPPER_SCAN_PREFIX=$PREFIX": f"WRAPPER_SCAN_PREFIX={fixture_prefix}",
            "LIVE_CPUINFO=/proc/cpuinfo": f"LIVE_CPUINFO={fixture_dir}/cpuinfo",
            "LIVE_UNAME=uname": f"LIVE_UNAME={fixture_dir}/uname",
            "LIVE_PROC_MTD=/proc/mtd": f"LIVE_PROC_MTD={fixture_dir}/proc_mtd",
            "LIVE_BOS_PLATFORM=/etc/bos_platform": f"LIVE_BOS_PLATFORM={fixture_dir}/bos_platform",
            "LIVE_BOS_MODE=/etc/bos_mode": f"LIVE_BOS_MODE={fixture_dir}/bos_mode",
            "LIVE_BOSMINER_MODEL=/etc/bosminer_model.json": f"LIVE_BOSMINER_MODEL={fixture_dir}/bosminer_model.json",
            "LIVE_I2CGET=/usr/sbin/i2cget": f"LIVE_I2CGET={fixture_dir}/i2cget",
            'STOCK_OBSERVATION=$("$TRIAL_CUSTODY" capture /proc /var/run/bosminer.pid)': (
                'STOCK_OBSERVATION=$("$TRIAL_CUSTODY" capture '
                f"{fixture_dir}/proc {fixture_dir}/bosminer.pid)"
            ),
            '[ "$(stock_observation_field pidfile)" = /var/run/bosminer.pid ]': (
                f'[ "$(stock_observation_field pidfile)" = {fixture_dir}/bosminer.pid ]'
            ),
            '[ "$BOUND_STOCK_PIDFILE_PATH" = /var/run/bosminer.pid ]': (
                f'[ "$BOUND_STOCK_PIDFILE_PATH" = {fixture_dir}/bosminer.pid ]'
            ),
            '[ "$(runtime_lock_field_at "$OWNER_EVIDENCE" stock_pidfile_path)" = /var/run/bosminer.pid ]': (
                f'[ "$(runtime_lock_field_at "$OWNER_EVIDENCE" stock_pidfile_path)" = {fixture_dir}/bosminer.pid ]'
            ),
            '[ "$(startup_field_at "$CLEANUP_EVIDENCE" stock_pidfile_path)" = /var/run/bosminer.pid ]': (
                f'[ "$(startup_field_at "$CLEANUP_EVIDENCE" stock_pidfile_path)" = {fixture_dir}/bosminer.pid ]'
            ),
            "BASE=/sys/class/gpio/gpio437": f"BASE={fixture_dir}/gpio/gpio437",
            "BASE=/sys/class/gpio/gpio$GPIO": f"BASE={fixture_dir}/gpio/gpio$GPIO",
            "STOCK_INIT=/etc/init.d/S99bosminer": (
                f"STOCK_INIT={fixture_dir}/S99bosminer"
            ),
            "STOCK_INIT_EXPECTED_SHA=6d9cce12caa49249396b48296101b0fbbcc6456cb3fa09bdbe2858bdcba948c9": (
                f"STOCK_INIT_EXPECTED_SHA={stock_init_sha}"
            ),
            "STOCK_INIT_EXPECTED_BYTES=1330": (
                f"STOCK_INIT_EXPECTED_BYTES={len(stock_init_blob)}"
            ),
            '[ "$(active_field stock_init_path)" = /etc/init.d/S99bosminer ]': (
                f'[ "$(active_field stock_init_path)" = {fixture_dir}/S99bosminer ]'
            ),
            '[ "$(active_field stock_init_sha256)" = 6d9cce12caa49249396b48296101b0fbbcc6456cb3fa09bdbe2858bdcba948c9 ]': (
                f'[ "$(active_field stock_init_sha256)" = {stock_init_sha} ]'
            ),
            '[ "$(active_field stock_init_bytes)" = 1330 ]': (
                f'[ "$(active_field stock_init_bytes)" = {len(stock_init_blob)} ]'
            ),
        }
        for old, new in replacements.items():
            # STOCK_INIT / its SHA / its BYTES are each validated in BOTH the run path
            # and the independent safe-off recovery path (defense in depth), so an anchor
            # may appear more than once; require it to EXIST and replace every occurrence.
            self.assertGreaterEqual(source.count(old), 1, old)
            source = source.replace(old, new)
        if runtime_lock is not None:
            old_lock = "RUNTIME_LOCK=/tmp/dcent-s19k-track1-runtime-lock"
            self.assertEqual(source.count(old_lock), 1)
            source = source.replace(old_lock, f"RUNTIME_LOCK={runtime_lock}")
        patched = temp / "identity_bound_run_trial"
        patched.write_text(source, encoding="utf-8", newline="\n")
        return patched

    @staticmethod
    def _cleanup_identity_fixture(remote_dir: str) -> None:
        """Remove only the exact files and directories created by the live-source fixture."""
        fixture_dir = f"{remote_dir}/live_identity_fixture"
        root_files = (
            "cpuinfo",
            "proc_mtd",
            "bos_platform",
            "bos_mode",
            "bosminer_model.json",
            "uname",
            "i2cget",
            "bosminer.pid",
            "S99bosminer",
        )
        proc_files = tuple(
            f"proc/{pid}/{name}"
            for pid in (1458, 9495)
            for name in ("stat", "comm", "cmdline", "exe")
        )
        gpio_files = tuple(
            f"gpio/gpio{gpio}/{name}"
            for gpio in (437, 454, 455, 456)
            for name in ("direction", "active_low", "value")
        )
        subprocess.run(
            [
                "wsl.exe",
                "rm",
                "-f",
                *(
                    f"{fixture_dir}/{name}"
                    for name in root_files + proc_files + gpio_files
                ),
            ],
            check=False,
            capture_output=True,
        )
        directories = (
            "proc/1458",
            "proc/9495",
            "proc",
            "gpio/gpio437",
            "gpio/gpio454",
            "gpio/gpio455",
            "gpio/gpio456",
            "gpio",
        )
        subprocess.run(
            [
                "wsl.exe",
                "rmdir",
                *(f"{fixture_dir}/{name}" for name in directories),
                fixture_dir,
            ],
            check=False,
            capture_output=True,
        )

    def _assert_stock_restart_pending_and_reset_fixture(
        self, remote_dir: str, runtime_lock: str
    ) -> None:
        """Verify the terminal SafeOff custody transition, then reset only this fixture."""
        active_path = f"{remote_dir}/runtime_active"
        predecessor_path = f"{remote_dir}/runtime_active_pre_safeoff"
        safeoff_path = f"{remote_dir}/runtime_safeoff_terminal_receipt"
        owner_path = f"{runtime_lock}/owner"

        def exact_fields(path: str) -> tuple[list[str], dict[str, str]]:
            blob = subprocess.check_output(["wsl.exe", "cat", path], text=True)
            rows = blob.splitlines()
            fields: dict[str, str] = {}
            for row in rows:
                self.assertIn("=", row, row)
                key, value = row.split("=", 1)
                self.assertNotIn(key, fields, key)
                fields[key] = value
            return rows, fields

        for path in (active_path, safeoff_path, owner_path):
            self.assertEqual(
                subprocess.run(["wsl.exe", "test", "-f", path]).returncode,
                0,
                path,
            )
            self.assertNotEqual(
                subprocess.run(["wsl.exe", "test", "-L", path]).returncode,
                0,
                path,
            )

        active_rows, active = exact_fields(active_path)
        owner_rows, owner = exact_fields(owner_path)
        schema = active["schema"]
        if schema == "dcentos.s19k-stock-restart-pending/v3":
            self.assertEqual(len(active_rows), 45)
            self.assertEqual(len(owner_rows), 14)
            self.assertEqual(owner["schema"], "dcentos.s19k-track1-runtime-lock/v7")
            self.assertEqual(owner["owner_kind"], "stock-restart-pending")
            self.assertEqual(active["source_runtime_active_path"], predecessor_path)
            self.assertEqual(
                subprocess.run(["wsl.exe", "test", "-f", predecessor_path]).returncode,
                0,
            )
            self.assertNotEqual(
                subprocess.run(["wsl.exe", "test", "-L", predecessor_path]).returncode,
                0,
            )
        else:
            self.assertEqual(
                schema,
                "dcentos.s19k-receiptless-stock-restart-pending/v2",
            )
            self.assertEqual(len(active_rows), 42)
            self.assertEqual(len(owner_rows), 13)
            self.assertEqual(active["source"], "receiptless-recovery-no-v4-active")
            self.assertEqual(owner["schema"], "dcentos.s19k-track1-runtime-lock/v9")
            self.assertEqual(owner["owner_kind"], "receiptless-stock-restart-pending")
            self.assertNotEqual(
                subprocess.run(["wsl.exe", "test", "-e", predecessor_path]).returncode,
                0,
            )
        self.assertEqual(active["phase"], "terminal-safeoff-stock-restart-pending")
        self.assertEqual(active["terminal"], "true")
        self.assertEqual(active["trial_dir"], remote_dir)
        self.assertEqual(active["safeoff_receipt_path"], safeoff_path)
        self.assertEqual(active["next_authority"], "exact-stock-restart-helper-only")
        self.assertEqual(owner["trial_dir"], remote_dir)

        def sha256(path: str) -> str:
            return subprocess.check_output(
                ["wsl.exe", "sha256sum", path], text=True
            ).split()[0]

        self.assertEqual(owner["active_sha256"], sha256(active_path))
        self.assertEqual(owner["safeoff_receipt_sha256"], sha256(safeoff_path))
        if schema == "dcentos.s19k-stock-restart-pending/v3":
            self.assertEqual(
                owner["source_runtime_active_sha256"], sha256(predecessor_path)
            )
            self.assertEqual(
                active["source_runtime_active_sha256"],
                owner["source_runtime_active_sha256"],
            )
        self.assertEqual(
            active["safeoff_receipt_sha256"], owner["safeoff_receipt_sha256"]
        )

        # Tests may exercise several independent recovery origins in one WSL
        # fixture. Remove only the exact evidence just verified; production
        # requires the separately audited stock-restart helper to consume it.
        subprocess.run(
            [
                "wsl.exe",
                "rm",
                "-f",
                active_path,
                predecessor_path,
                safeoff_path,
                owner_path,
            ],
            check=True,
        )
        subprocess.run(["wsl.exe", "rmdir", runtime_lock], check=True)

    def _probe_identity(
        self, remote_dir: str, args: list[str], deploy_mode: str = "stage-only"
    ) -> str:
        result = subprocess.run(
            [
                "wsl.exe",
                "sh",
                f"{remote_dir}/run_trial",
                "identity",
                remote_dir,
                "am3-s19k",
                deploy_mode,
                *args,
            ],
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        match = re.search(r" sha256=([0-9a-f]{64}) ", result.stdout)
        self.assertIsNotNone(match, result.stdout)
        return match.group(1)

    def _run_deployer(
        self,
        temp: Path,
        config: str,
        allow_loud: bool,
        arm_flags: int = 0x05000400,
        handoff_no_work: bool = False,
        bounded_work_proof: bool = False,
        endurance_work_proof: bool = False,
        mining_on_passthrough: bool | None = None,
        artifact_pin: bool = True,
        expected_artifact_sha256: str | None = None,
        expected_artifact_bytes: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        binary = temp / "dcentrald"
        cfg = temp / "config.toml"
        binary.write_bytes(self._armhf_executable(arm_flags))
        cfg.write_text(config, encoding="utf-8")
        script = SCRIPTS / "dcentrald_s19k_tmp_deploy.sh"
        if os.name == "nt":
            command = [
                "wsl.exe",
                "--cd",
                "/tmp",
                "sh",
                self._shell_path(script),
                "--dry-run",
            ]
            cwd = ROOT
        else:
            command = ["sh", str(script), "--dry-run"]
            cwd = temp
        if allow_loud:
            command.append("--allow-loud")
        if mining_on_passthrough is None:
            mining_on_passthrough = allow_loud and not (
                handoff_no_work or bounded_work_proof or endurance_work_proof
            )
        if handoff_no_work:
            command.append("--handoff-no-work")
        if bounded_work_proof:
            command.append("--bounded-work-proof")
        if endurance_work_proof:
            baseline = temp / "endurance-baseline.kv"
            baseline.write_bytes(
                (
                    "schema=dcentos.s19k-endurance-baseline/v4\n"
                    f"phase3_plan_sha256={'0' * 64}\n"
                    "phase3_plan_bytes=1\n"
                    f"phase3_transcript_sha256={'1' * 64}\n"
                    "phase3_transcript_bytes=1\n"
                    f"phase3_receipt_sha256={'2' * 64}\n"
                    "phase3_receipt_bytes=1\n"
                    f"phase3_wall_power_csv_sha256={'3' * 64}\n"
                    "phase3_wall_power_csv_bytes=1\n"
                    "phase3_wall_power_sample_count=2\n"
                    "phase3_wall_power_first_unix_ms=1000\n"
                    "phase3_wall_power_last_unix_ms=61000\n"
                    f"phase3_verifier_sha256={'4' * 64}\n"
                    "phase3_verifier_bytes=1\n"
                    f"phase3_baseline_builder_sha256={'5' * 64}\n"
                    "phase3_baseline_builder_bytes=1\n"
                    f"phase3_host_verification_sha256={'6' * 64}\n"
                    "phase3_host_verification_bytes=1\n"
                    f"phase3_verification_id={'7' * 64}\n"
                    f"phase3_safeoff_manifest_sha256={'8' * 64}\n"
                    "phase3_safeoff_manifest_bytes=1\n"
                    f"phase3_instrumentation_preflight_sha256={'9' * 64}\n"
                    "phase3_instrumentation_preflight_bytes=1\n"
                    f"phase3_normalization_config_sha256={'a' * 64}\n"
                    "phase3_normalization_config_bytes=1\n"
                    f"phase3_instrument_source_sha256={'b' * 64}\n"
                    "phase3_instrument_source_bytes=1\n"
                    f"phase3_normalization_receipt_sha256={'c' * 64}\n"
                    "phase3_normalization_receipt_bytes=1\n"
                    f"phase3_safeoff_csv_sha256={'a' * 64}\n"
                    "phase3_safeoff_csv_bytes=1\n"
                    f"phase3_physical_verifier_sha256={'b' * 64}\n"
                    "phase3_physical_verifier_bytes=1\n"
                    f"phase3_safeoff_parser_sha256={'c' * 64}\n"
                    "phase3_safeoff_parser_bytes=1\n"
                    f"phase3_normalizer_sha256={'d' * 64}\n"
                    "phase3_normalizer_bytes=1\n"
                    f"phase3_physical_verification_sha256={'c' * 64}\n"
                    "phase3_physical_verification_bytes=1\n"
                    f"phase3_physical_verification_id={'d' * 64}\n"
                    "hashrate_min_millighs=90000000\n"
                    "hashrate_max_millighs=110000000\n"
                    "reject_rate_max_ppm=10000\n"
                    "wall_power_min_mw=2000000\n"
                    "wall_power_max_mw=4000000\n"
                    "safeoff_wall_power_max_mw=100000\n"
                    "warmup_intervals=5\n"
                    "autotuner=disabled\n"
                    "declared_before_launch_unix_s=62\n"
                    "publication=no-clobber-hard-link-after-fsync\n"
                ).encode("ascii")
            )
            command.extend(
                [
                    "--endurance-work-proof",
                    "--endurance-baseline",
                    self._shell_path(baseline),
                ]
            )
        if mining_on_passthrough:
            command.append("--mining-on-passthrough")
        if artifact_pin:
            command.extend(
                [
                    "--expected-artifact-sha256",
                    expected_artifact_sha256
                    or hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "--expected-artifact-bytes",
                    str(
                        expected_artifact_bytes
                        if expected_artifact_bytes is not None
                        else binary.stat().st_size
                    ),
                ]
            )
        command.extend(["192.0.2.1", self._shell_path(binary), self._shell_path(cfg)])
        result = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
        if os.name == "nt":
            for relative in re.findall(
                r"wrote (\./TMP_DEPLOY_PLAN\.[A-Za-z0-9.]+)", result.stdout
            ):
                subprocess.run(
                    ["wsl.exe", "rm", "-f", f"/tmp/{Path(relative).name}"],
                    check=False,
                )
        return result

    def test_compatibility_launcher_has_no_legacy_deploy_path(self) -> None:
        source = (SCRIPTS / "dcentrald_s19k_tmp_trial.sh").read_text()
        self.assertIn('exec "$SCRIPT_DIR/dcentrald_s19k_tmp_deploy.sh" "$@"', source)
        self.assertNotIn("StrictHostKeyChecking=no", source)
        self.assertNotIn("/etc/dcentos/board_target", source)

    def test_deployer_always_parses_elf_and_pins_ssh_identity(self) -> None:
        source = (SCRIPTS / "dcentrald_s19k_tmp_deploy.sh").read_text()
        self.assertIn('blob[:4] != b"\\x7fELF"', source)
        self.assertIn("machine != 40", source)
        self.assertIn("flags & 0xff000000 != 0x05000000", source)
        self.assertIn("EF_ARM_ABI_FLOAT_HARD", source)
        self.assertIn("PT_INTERP", source)
        self.assertIn("entry_in_executable_load", source)
        self.assertIn("phnum in (0, 0xffff)", source)
        self.assertIn("p_filesz > p_memsz", source)
        self.assertIn("StrictHostKeyChecking=yes", source)
        self.assertNotIn("StrictHostKeyChecking=no", source)
        self.assertIn("UserKnownHostsFile=$KNOWN_HOSTS", source)
        self.assertIn("GlobalKnownHostsFile=/dev/null", source)
        self.assertIn(
            "EXPECTED_HOST_KEY_SHA256=${DCENT_EXPECTED_HOST_KEY_SHA256:-}", source
        )
        self.assertIn("--expected-host-key-sha256)", source)
        self.assertIn("--expected-artifact-sha256)", source)
        self.assertIn("--expected-artifact-bytes)", source)
        self.assertIn(
            "exact sealed artifact authority requires --expected-artifact-sha256",
            source,
        )
        self.assertIn("operator_artifact_pin=$ARTIFACT_OPERATOR_PIN", source)
        self.assertIn("expected_artifact_sha256=$EXPECTED_ARTIFACT_SHA256", source)
        self.assertIn("expected_artifact_bytes=$EXPECTED_ARTIFACT_BYTES", source)
        self.assertIn("known-hosts must contain exactly the expected key", source)
        self.assertIn('ssh-keygen -F "$MINER_IP" -f "$KNOWN_HOSTS"', source)
        self.assertIn('PINNED_FINGERPRINT_COUNT" = 1', source)
        self.assertNotIn("binary path must contain armv7", source)
        self.assertIn(
            'BUILD_ARTIFACT_VERIFIER_SOURCE="$ROOT/scripts/s19k_tmp_build_artifact.py"',
            source,
        )
        shared_admission = (
            'ADMIT_OUT=$($PY "$BUILD_ARTIFACT_VERIFIER" verify-elf "$BIN")'
        )
        self.assertIn(shared_admission, source)
        self.assertIn(
            'cp -p "$BUILD_ARTIFACT_VERIFIER_SOURCE" '
            '"$HOST_STAGE_DIR/s19k_tmp_build_artifact.py"',
            source,
        )
        verifier = (SCRIPTS / "s19k_tmp_build_artifact.py").read_text()
        self.assertIn("flags & 0x200", verifier)
        self.assertIn("DT_NEEDED", verifier)
        self.assertLess(
            source.index(shared_admission), source.index("LOCAL_SHA=$(printf")
        )

    def test_s19k_tmp_build_has_dedicated_armv7_output_lane(self) -> None:
        source = (SCRIPTS / "build-dcentrald.sh").read_text()
        self.assertIn("s19k-tmp)", source)
        self.assertIn('TRIPLE="armv7-unknown-linux-musleabihf"', source)
        self.assertIn('ZIG_CC_FLAGS="-target arm-linux-musleabihf"', source)
        s19k_case = source.split("s19k-tmp)", 1)[1].split("amlogic)", 1)[0]
        self.assertNotIn("target-cpu", s19k_case)
        self.assertIn('TARGET_OUTPUT_PREFIX="target/s19k-tmp"', source)
        self.assertIn("CARGO_TARGET_DIR=/src/$TARGET_OUTPUT_PREFIX", source)
        self.assertIn(
            'BINARY="$BUILD_RESULT_ROOT/$TARGET_OUTPUT_PREFIX/$TRIPLE/release/dcentrald"',
            source,
        )
        success = source.split("# Check result", 1)[1]
        self.assertIn('[ "$TARGET" = "s19k-tmp" ]', success)
        self.assertIn(
            "./scripts/dcentrald_s19k_tmp_deploy.sh --dry-run "
            "--expected-artifact-sha256 <sha256> "
            "--expected-artifact-bytes <bytes> --known-hosts",
            success,
        )
        self.assertIn("--expected-host-key-sha256 SHA256:<fingerprint>", success)
        self.assertIn("--expected-artifact-sha256 <sha256>", success)
        self.assertIn("--expected-artifact-bytes <bytes>", success)
        self.assertIn("./dcentrald/dcentrald_s19k.toml", success)
        self.assertNotIn("./dcentrald/dcentrald_s19k_braiins.toml", success)
        self.assertIn("Phase-0 (zero target contact/mutation)", success)
        self.assertIn("Stage-only contact (/tmp mutation; no daemon)", success)
        s19k_deploy = success.index('elif [ "$TARGET" = "s19k-tmp" ]')
        generic_usr_bin = success.index("root@<miner-ip>:/usr/bin/dcentrald")
        self.assertLess(s19k_deploy, generic_usr_bin)

        host_verify = (SCRIPTS / "s19k_host_verify.py").read_text()
        self.assertIn('assert "dcentos.s19k-tmp-deploy/v12"', host_verify)
        self.assertNotIn('assert "dcentos.s19k-tmp-deploy/v4"', host_verify)
        self.assertNotIn("def admit_armhf_elf(hdr: bytes)", host_verify)
        self.assertIn(
            'production_serial = serial.split("\\n#[cfg(test)]\\nmod tests {", 1)[0]',
            host_verify,
        )
        self.assertIn(
            '"let serial = if braiins_bm1366_passthrough_handoff"',
            host_verify,
        )
        self.assertIn("bm1366_arm, generic_tail =", host_verify)
        self.assertIn("assert 0 <= bm1366_refusal < generic_open", host_verify)
        self.assertNotIn(
            'serial.split("let serial = if passthrough && is_bm1366", 1)',
            host_verify,
        )
        self.assertIn(
            'flag_sh.count("candidate_required=full-0x20000-byte-eraseblock") == 3',
            host_verify,
        )
        self.assertIn('assert "byte_in_block must be 0" not in flag_sh', host_verify)
        self.assertIn(
            'assert "full_eraseblock_candidate_required=true" in flag_sh',
            host_verify,
        )
        self.assertIn(
            "assert 'flash_erase /dev/mtd5 \"$EB_START_HEX\" 1' not in flag_sh",
            host_verify,
        )
        self.assertIn(
            "assert 'nandwrite -p -s \"$EB_START_HEX\" /dev/mtd5' not in flag_sh",
            host_verify,
        )
        self.assertIn(
            "recover_execute = recover_sh.split(",
            host_verify,
        )
        self.assertIn(
            'recover_execute.find("require_exact_live_s19k_identity /etc/dcentos")',
            host_verify,
        )
        self.assertNotIn("            import hashlib", host_verify)

    def test_every_staged_artifact_is_hashed_and_identity_is_not_written_during_stage(
        self,
    ) -> None:
        source = (SCRIPTS / "dcentrald_s19k_tmp_deploy.sh").read_text()
        for token in (
            "REMOTE_CFG_SUM",
            "REMOTE_CFG_BYTES",
            "REMOTE_HELPER_SUM",
            "REMOTE_HELPER_BYTES",
            "REMOTE_STOCK_RESTART_HELPER_SUM",
            "REMOTE_STOCK_RESTART_HELPER_BYTES",
            "CFG_SHA",
            "HELPER_SHA",
            "STOCK_RESTART_HELPER_SHA",
            "STOCK_RESTART_HELPER_BYTES",
        ):
            self.assertIn(token, source)
        self.assertNotIn("> /etc/dcentos/board_target", source)
        self.assertIn("mkdir '$REMOTE_DIR'", source)
        self.assertNotIn("mkdir -p '$REMOTE_DIR'", source)
        self.assertIn(
            "required_ports=population-selected:/dev/ttyS3,/dev/ttyS2,/dev/ttyS1",
            source,
        )
        self.assertIn("/dev/ttyS1 /dev/ttyS2 /dev/ttyS3 /dev/uart_trans", source)

    def test_config_authority_rejects_duplicate_applied_keys(self) -> None:
        source = (SCRIPTS / "dcentrald_s19k_tmp_deploy.sh").read_text()
        self.assertIn("import tomllib", source)
        self.assertIn('platform = document.get("platform")', source)
        self.assertIn('mining = document.get("mining")', source)
        self.assertIn('target != "am3-aml-s19k"', source)
        self.assertIn("type(enabled) is not bool", source)
        self.assertIn("NativeMiningOn", source)

    def test_mining_on_requires_explicit_loud_authority_and_bound_runner(self) -> None:
        source = (SCRIPTS / "dcentrald_s19k_tmp_deploy.sh").read_text()
        self.assertIn("--allow-loud) ALLOW_LOUD=true", source)
        self.assertIn(
            "--mining-on-passthrough) MINING_ON_PASSTHROUGH=true", source
        )
        self.assertIn("requires the operator's explicit --allow-loud authority", source)
        self.assertIn("schema=dcentos.s19k-tmp-deploy/v12", source)
        self.assertIn("arm_eabi=5", source)
        self.assertIn(
            "runtime_reverify=bin+config+runner+custody-observer+"
            "stock-restart-helper-sha256-and-bytes",
            source,
        )
        self.assertIn("persistent_mutation=false", source)
        self.assertIn("ephemeral_runtime_env=DCENTOS_EPHEMERAL_RUNTIME=1", source)
        self.assertIn("serial_mode_flag=--serial-mining", source)
        self.assertIn("explicit_loud_authority=$LOUD_AUTHORITY", source)
        self.assertIn("no_work_flag=--s19k-track1-no-work", source)
        self.assertIn(
            "bounded_work_proof_flag=--s19k-track1-bounded-work-proof", source
        )
        self.assertIn("work_proof_timeout_s=600", source)
        self.assertIn("work_authority=$WORK_AUTHORITY", source)
        self.assertIn("DEPLOY_MODE=handoff-no-work", source)
        self.assertIn("DEPLOY_MODE=bounded-work-proof", source)
        self.assertIn("RUN_COMMAND=", source)
        self.assertIn('IDENTITY_COMMAND="$REMOTE_HELPER identity', source)
        self.assertIn("identity_probe=$IDENTITY_COMMAND", source)
        self.assertIn(
            "live_identity_schema=dcentos.s19k-braiins-live-identity/v2", source
        )
        self.assertIn(
            "live_identity_profile_rule=mutually-exclusive-complete-tuple",
            source,
        )
        self.assertIn(
            "live_identity_profile_live88_two_bhb56903_slots_2_3="
            "2xBHB56903@2,3+addr1-undetected-placeholder+"
            "eeprom-0x50-absent-0x51-0x52-0511",
            source,
        )
        self.assertIn(
            "live_identity_profile_held78_three_bhb56902_slots_1_2_3="
            "3xBHB56902@1,2,3+eeprom-0x50-0x51-0x52-0511",
            source,
        )
        for marker in (
            "live_identity_profile_bhb56902_only=one-to-three-BHB56902",
            "live_identity_profile_bhb56903_only=one-to-three-BHB56903",
            "live_identity_profile_mixed_bhb56902_bhb56903=one-to-three-mixed-boards",
            "live_identity_profile_all_three_uarts_populated=addresses-1,2,3+ttyS3,ttyS2,ttyS1",
            "mixed-bhb56902-bhb56903",
            "partial-logical-uarts-populated|all-three-uarts-populated",
            "board_names=BHB5690(2|3)(,BHB5690(2|3)){0,2}",
        ):
            self.assertIn(marker, source)
        self.assertIn("live_identity_recheck=pre-handoff+pre-recovery-safeoff", source)
        self.assertIn(
            "runtime_lock=board-global-atomic-mkdir+v6-artifact-bound-owner+"
            "typed-pending-retention",
            source,
        )
        self.assertIn(
            "receipt_clear=checked-safeoff-to-exact-stock-restart-helper-only",
            source,
        )

    def test_local_inputs_are_snapshotted_before_parse_hash_and_scp(self) -> None:
        source = (SCRIPTS / "dcentrald_s19k_tmp_deploy.sh").read_text()
        snapshot = source.index("HOST_STAGE_DIR=$(mktemp -d")
        parse = source.index("ADMIT_OUT=$(")
        scp = source.index('scp_trial "$BIN"')
        self.assertLess(snapshot, parse)
        self.assertLess(parse, scp)
        self.assertIn("deploy input must be a regular non-symlink file", source)
        self.assertIn("cleanup_host_stage", source)

    def test_plan_is_private_unique_and_does_not_disclose_target(self) -> None:
        source = (SCRIPTS / "dcentrald_s19k_tmp_deploy.sh").read_text()
        self.assertIn("umask 077", source)
        self.assertIn('mktemp "./TMP_DEPLOY_PLAN.${STAMP}.$$.XXXXXX"', source)
        self.assertNotIn('TMP_DEPLOY_PLAN="./TMP_DEPLOY_PLAN.txt"', source)
        self.assertIn("miner_target_sha256=$MINER_TARGET_SHA", source)
        self.assertIn("miner_target_record=sha256-only", source)
        self.assertNotIn('echo "miner_ip=$MINER_IP"', source)

    def test_proc_fd_census_checks_procfs_link_before_descriptor_target(self) -> None:
        for script_name in (
            "dcentrald_s19k_tmp_remote_run.sh",
            "dcentrald_s19k_stock_restart_from_safeoff.sh",
            "dcentrald_s19k_tmp_current_recovered_stock_closeout_20260820.sh",
            "dcentrald_s19k_tmp_stock_retained_closeout.sh",
        ):
            source = (SCRIPTS / script_name).read_text(encoding="utf-8")
            self.assertIn(
                '[ -L "$FD" ] || [ -e "$FD" ] || continue', source, script_name
            )
            self.assertNotIn(
                '[ -e "$FD" ] || [ -L "$FD" ] || continue', source, script_name
            )
        for script_name in (
            "dcentrald_s19k_tmp_remote_run.sh",
            "dcentrald_s19k_stock_restart_from_safeoff.sh",
        ):
            source = (SCRIPTS / script_name).read_text(encoding="utf-8")
            self.assertIn(
                '[ ! -L "$FD" ] && [ ! -e "$FD" ] && continue', source, script_name
            )
            self.assertNotIn(
                '[ ! -e "$FD" ] && [ ! -L "$FD" ] && continue', source, script_name
            )
            census_start = source.index("collect_all_task_effect_snapshot() {")
            census_end = source.index("\n}\n", census_start)
            census = source[census_start:census_end]
            argv_loop = census.index("for PROC_ARG in $CMDLINE; do")
            self.assertLess(census.index("set -f", 0, argv_loop), argv_loop, script_name)
            self.assertGreater(census.index("set +f", argv_loop), argv_loop, script_name)
        runner = (SCRIPTS / "dcentrald_s19k_tmp_remote_run.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("filter_custody_relevant_task_effects() (\n    set -f", runner)
        helper = (SCRIPTS / "dcentrald_s19k_stock_restart_from_safeoff.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("filter_relevant_task_effects() (\n    set -f", helper)

    def test_remote_runner_is_ephemeral_and_supervises_safeoff(self) -> None:
        source = (SCRIPTS / "dcentrald_s19k_tmp_remote_run.sh").read_text()
        self.assertIn("trap 'stop_child 130' 2", source)
        self.assertNotIn("/etc/dcentos", source)
        self.assertNotIn("/data/", source)
        self.assertIn("runtime_active", source)
        self.assertIn("schema=dcentos.s19k-tmp-runtime/v5", source)
        self.assertIn("live_identity_profile=%s", source)
        self.assertIn("live_identity_sha256=%s", source)
        self.assertNotIn("write_active launch-pending-or-recovery-required", source)
        self.assertIn("write_active child-live-or-recovery-required", source)
        self.assertIn("schema=dcentos.s19k-startup-j0-prefork/v1", source)
        self.assertIn("schema=dcentos.s19k-startup-j2-child-bound/v1", source)
        self.assertIn("schema=dcentos.s19k-startup-release/v1", source)
        serial_source = (
            ROOT / "dcentrald/dcentrald/src/serial_mining.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("dcentos.s19k-startup-c1-child-identity/v1", serial_source)
        self.assertIn("dcentos.s19k-startup-j1-daemon-blocked/v1", serial_source)
        j0 = source.index("write_startup_j0_owner_prefork ||")
        fork = source.index('DCENT_S19K_STARTUP_BOOTSTRAP=daemon-v1 \\\n', j0)
        wait_j1 = source.index('while [ ! -e "$STARTUP_J1" ]', fork)
        active = source.index("write_active child-live-or-recovery-required", wait_j1)
        j2 = source.index("write_startup_j2_and_release", active)
        token = source.index("printf '%s' \"$RELEASE_TOKEN\" >&9", j2)
        self.assertLess(j0, fork)
        self.assertLess(fork, wait_j1)
        self.assertLess(wait_j1, active)
        self.assertLess(active, j2)
        self.assertLess(j2, token)
        self.assertIn("persistent_mutation=false", source)
        self.assertIn(
            'rsplit_once(") ")',
            (ROOT / "dcentrald/dcentrald/src/serial_mining.rs").read_text(
                encoding="utf-8"
            ),
        )
        self.assertIn(
            "mode must be run, identity, restore, endurance-read, "
            "endurance-ack, or endurance-final-read",
            source,
        )
        self.assertIn("publish_endurance_failure_receipt", source)
        self.assertIn("dcentos.s19k-endurance-daemon-failure/v1", source)
        self.assertIn("dcentos.s19k-endurance-failure-receipt/v1", source)
        self.assertIn(
            "daemon_failure) ENDURANCE_FINAL_FILE=$ENDURANCE_DAEMON_FAILURE",
            source,
        )
        self.assertIn(
            "endurance_failure_receipt) ENDURANCE_FINAL_FILE=$ENDURANCE_FAILURE_RECEIPT",
            source,
        )
        self.assertIn("verify_bound_file", source)
        self.assertIn("DCENTOS_EPHEMERAL_RUNTIME=1", source)
        self.assertIn("DCENT_S19K_TRACK1_STOP_SAFEOFF=1", source)
        self.assertEqual(source.count("/usr/bin/env -i"), 6)
        self.assertEqual(source.count("PATH=/usr/bin:/bin:/usr/sbin:/sbin"), 8)
        self.assertEqual(
            source.count(
                'DCENT_S19K_LIVE_IDENTITY_SHA256="$EXPECTED_LIVE_IDENTITY_SHA"'
            ),
            2,
        )
        self.assertEqual(
            source.count(
                "printf '%s\\000' \"DCENT_S19K_LIVE_IDENTITY_SHA256=$EXPECTED_LIVE_IDENTITY_SHA\""
            ),
            1,
        )

        def shell_function_body(name: str) -> str:
            start = source.index(f"{name}() {{")
            end = source.index("\n}\n", start)
            return source[start:end]

        for function_name, operation_marker in (
            (
                "publish_no_clobber_journal_keep_source",
                "--s19k-track1-journal-source",
            ),
            ("run_checked_safeoff_command", "--s19k-track1-recovery-safeoff"),
            (
                "guarded_unlink_transition_residue",
                "--s19k-track1-guarded-unlink-scratch",
            ),
            (
                "consume_guarded_transition_completion",
                "--s19k-track1-consume-completion",
            ),
            (
                "durable_replace_startup_record",
                "--s19k-track1-durable-replace-source",
            ),
        ):
            operation = shell_function_body(function_name)
            self.assertEqual(operation.count("/usr/bin/env -i"), 1, function_name)
            self.assertIn(operation_marker, operation, function_name)
        daemon_launch = source.index(
            "# The daemon completes C1/J1/J2/release, acquires the content-bound J3"
        )
        daemon_launch_body = source[daemon_launch:]
        self.assertEqual(daemon_launch_body.count("/usr/bin/env -i"), 1)
        self.assertIn("DCENT_S19K_STARTUP_BOOTSTRAP=daemon-v1", daemon_launch_body)
        self.assertIn(
            "umask 077\nPATH=/usr/bin:/bin:/usr/sbin:/sbin\nexport PATH",
            source,
        )
        self.assertIn('--s19k-bos-tools-pid "$BOUND_SUPERVISOR_PID"', source)
        self.assertIn('--s19k-bos-tools-start "$BOUND_SUPERVISOR_START"', source)
        self.assertIn('--s19k-bos-tools-ppid "$BOUND_SUPERVISOR_PPID"', source)
        self.assertIn('--s19k-bosminer-pid "$BOUND_BOSMINER_PID"', source)
        self.assertIn('--s19k-bosminer-start "$BOUND_BOSMINER_START"', source)
        self.assertIn('--s19k-bosminer-exe "$BOUND_BOSMINER_EXE"', source)
        self.assertIn('--s19k-track1-runtime-active "$ACTIVE"', source)
        self.assertIn(
            '--s19k-stock-owner-retained-receipt "$STOCK_RETAINED_RECEIPT"', source
        )
        self.assertIn("kill -TERM", source)
        # Attempt-10 hard-ceiling backstop (2026-08-28 lifecycle audit): the
        # wrapper's single historical "never SIGKILL" invariant is superseded
        # by an exact one — the ONLY kill -KILL anywhere is the trial
        # ceiling's identity-fenced SIGKILL of the exact daemon child inside
        # enforce_trial_ceiling_exit, and it can never name
        # S99bosminer/bosminer/stock supervisor processes.
        self.assertEqual(source.count("kill -KILL"), 1)
        ceiling_fn = source[
            source.index("enforce_trial_ceiling_exit() {"):
            source.index("set_expected_safeoff_receipt()")
        ]
        self.assertIn('kill -KILL "$CHILD_PID" 2>/dev/null', ceiling_fn)
        self.assertIn("exact_dcentrald_child_matches", ceiling_fn)
        self.assertIn('for TID_DIR in "$TG_DIR"/task/[0-9]*', source)
        self.assertIn('STAT_REST=${STAT_LINE##*) }', source)
        self.assertIn("dcentrald_all_threads_absent=true", source)
        self.assertIn("watchdog_all_threads_absent=true", source)
        self.assertIn("schema=dcentos.s19k-startup-retired-terminal/v1", source)
        self.assertIn('mv "$RUNTIME_LOCK_OWNER" "$STARTUP_RETIRED_OWNER"', source)
        retirement = source.index("retire_startup_no_effect_obligation()")
        active_retire = source.index(
            'mv "$ACTIVE" "$STARTUP_RETIRED_ACTIVE"', retirement
        )
        owner_retire = source.index(
            'mv "$RUNTIME_LOCK_OWNER" "$STARTUP_RETIRED_OWNER"', retirement
        )
        lock_release = source.index('rmdir "$RUNTIME_LOCK"', owner_retire)
        self.assertLess(active_retire, owner_retire)
        self.assertLess(owner_retire, lock_release)
        self.assertIn("perform_checked_safeoff", source)
        self.assertIn("DCENT_S19K_TRACK1_SAFEOFF_RECEIPT", source)
        self.assertIn("DCENT_S19K_INSTALL_CUSTODY_SAFEOFF_RECEIPT", source)
        self.assertIn(
            "EXPECTED_SAFEOFF_SCHEMA=dcentos.s19k-track1-safeoff/v1", source
        )
        self.assertIn("EXPECTED_SAFEOFF_RESETS=454:0,455:0,456:0", source)
        self.assertIn(
            "EXPECTED_SAFEOFF_GPIO_RAW=437:1,454:0,455:0,456:0", source
        )
        self.assertIn(
            "EXPECTED_SAFEOFF_SCHEMA=dcentos.s19k-install-custody-safeoff/v1",
            source,
        )
        self.assertIn("EXPECTED_SAFEOFF_RESETS=not-attempted", source)
        self.assertIn("EXPECTED_SAFEOFF_GPIO_RAW=437:1", source)
        self.assertEqual(source.count("resets=$EXPECTED_SAFEOFF_RESETS psu=437:1"), 2)
        self.assertIn('grep -Fxq "$EXPECTED_SAFEOFF_RECEIPT"', source)
        self.assertIn("bosminer_custody_owner_is_live", source)
        self.assertIn("no_dcentrald_thread_is_live", source)
        self.assertNotIn("process_exe_basename_matches dcentrald", source)
        self.assertIn("another_trial_wrapper_is_live", source)
        self.assertIn("exact_dcentrald_child_matches", source)
        self.assertIn("RUNTIME_LOCK=/tmp/dcent-s19k-track1-runtime-lock", source)
        self.assertIn('RUNTIME_LOCK_OWNER="$RUNTIME_LOCK/owner"', source)
        self.assertIn("schema=dcentos.s19k-track1-runtime-lock/v6", source)
        self.assertIn("printf 'trial_dir=%s\\n' \"$TRIAL_DIR\"", source)
        self.assertIn("printf 'runner_sha256=%s\\n' \"$RUNNER_SHA\"", source)
        self.assertIn("printf 'custody_observer_sha256=%s\\n' \"$CUSTODY_SHA\"", source)
        self.assertIn(
            "printf 'custody_observer_bytes=%s\\n' \"$CUSTODY_BYTES\"", source
        )
        self.assertIn(
            "printf 'stock_restart_helper_sha256=%s\\n' \"$STOCK_RESTART_HELPER_SHA\"",
            source,
        )
        self.assertIn(
            "printf 'stock_restart_helper_bytes=%s\\n' \"$STOCK_RESTART_HELPER_BYTES\"",
            source,
        )
        self.assertIn(
            "printf 'live_identity_sha256=%s\\n' \"$EXPECTED_LIVE_IDENTITY_SHA\"",
            source,
        )
        self.assertIn("WRAPPER_SCAN_PREFIX=$PREFIX", source)
        self.assertIn('"$EFFECT_WRAPPER_PREFIX"*/run_trial)', source)
        self.assertIn('mkdir "$RUNTIME_LOCK"', source)
        self.assertIn("ensure_runtime_lock_for_recovery", source)
        self.assertIn("RECOVERY_LOCK_MODE=${1:-bound}", source)
        self.assertIn("ensure_runtime_lock_for_recovery bound", source)
        self.assertIn("ensure_runtime_lock_for_recovery receiptless", source)
        self.assertIn("admit_runtime_lock_owner_record", source)
        self.assertIn("runtime_lock_owner_matches_current", source)
        self.assertIn("replace_runtime_lock_owner_for_receiptless_recovery", source)
        self.assertIn('mv -f "$REBIND_TMP" "$RUNTIME_LOCK_OWNER"', source)
        self.assertIn(
            "global custody owner changed during receiptless recovery rebind", source
        )
        self.assertIn("require_same_exact_stock_tree", source)
        self.assertIn("retire_released_startup_after_child_exit()", source)
        self.assertIn(
            'retained_prewatchdog_receipt_is_exact "$ACTIVE"', source
        )
        startup_closeout = source.index("retire_released_startup_after_child_exit()")
        receipt_removal = source.index(
            'rm -f "$STOCK_RETAINED_RECEIPT"', startup_closeout
        )
        startup_terminalize = source.index(
            "retire_startup_no_effect_obligation", receipt_removal
        )
        self.assertLess(receipt_removal, startup_terminalize)
        self.assertNotIn("stock-owner-retained/no-handoff", source)
        self.assertIn(
            "bound child lifetime no longer has the exact dcentrald comm/exe identity",
            source,
        )
        self.assertIn(
            "runtime receipt does not match the content-bound recovery command", source
        )
        self.assertIn(
            '[ "$(wc -l < "$ACTIVE" | tr -d \' \\t\\r\\n\')" -eq 40 ]',
            source,
        )
        self.assertIn("runtime receipt has an inexact field set", source)
        self.assertIn("binary_bytes", source)
        self.assertIn("runner_sha256", source)
        self.assertIn('case "$STATE" in Z|X|x) return 1', source)
        self.assertIn("no persistent mutation or daemon launch", source)
        for evidence in (
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
            "if (!(address in rows)) exit 1",
            "1||0|HB not detected. Board name unknown. hashrate_ths is calculated.",
            "2|BHB56903|1|",
            "3|BHB56903|1|",
            "profile=$LIVE_IDENTITY_PROFILE",
            "0x05:0x11",
        ):
            self.assertIn(evidence, source)
        self.assertLess(
            source.index(
                "        require_same_live_s19k_identity\n        if process_matches"
            ),
            source.index(
                '            exact_dcentrald_child_matches "$CHILD_PID" "$CHILD_START"'
            ),
        )
        self.assertLess(
            source.index(
                '            exact_dcentrald_child_matches "$CHILD_PID" "$CHILD_START"'
            ),
            source.index('            kill -TERM "$CHILD_PID"'),
        )
        receiptless = source.index(
            "ERROR: a bosminer supervisor or child is live without a bound runtime receipt"
        )
        receiptless_daemon = source.index(
            "ERROR: dcentrald is live without a bound runtime receipt"
        )
        receiptless_wrapper = source.index(
            "ERROR: another Track-1 wrapper is live without a bound runtime receipt"
        )
        receiptless_identity = source.index(
            "        capture_exact_live_s19k_identity\n"
            "        EXPECTED_LIVE_IDENTITY_PROFILE=$LIVE_IDENTITY_PROFILE\n"
            "        EXPECTED_LIVE_IDENTITY_SHA=$LIVE_IDENTITY_SHA",
            receiptless,
        )
        receiptless_safeoff = source.index(
            "        perform_checked_safeoff", receiptless_identity
        )
        self.assertLess(receiptless, receiptless_identity)
        self.assertLess(receiptless_daemon, receiptless_identity)
        self.assertLess(receiptless_wrapper, receiptless_identity)
        self.assertLess(receiptless_identity, receiptless_safeoff)

    def test_wrapper_snapshot_neutralizes_own_fork_cmdline_inheritance(self) -> None:
        source = (SCRIPTS / "dcentrald_s19k_tmp_remote_run.sh").read_text(
            encoding="utf-8"
        )
        # A busybox command-substitution fork keeps the wrapper's own
        # run_trial argv until exec; caught mid-enumeration it reads as a
        # second live wrapper (live refusals 2026-08-28 trials
        # 20260828093837 and 20260828120451, both with verified-clean
        # process tables before and after). The collector must take the
        # task's ppid from the already-parsed stat fields and clear the
        # wrapper marker for direct children of $$ before emitting the
        # task record, so snapshot stability and the competing-wrapper
        # fence only ever see genuinely foreign wrappers.
        ppid_capture = source.index("            STATE=$1\n            TASK_PPID=$2\n")
        self.assertLess(
            ppid_capture, source.index('            shift 19\n            TID_START=$1')
        )
        neutralize = source.index(
            '            [ "$TASK_PPID" = "$$" ] && TRACK1_WRAPPER_ARG=false\n'
        )
        emit = source.index("            printf 'T|%s|%s|%s|%s|comm=%s|exe=%s|argv0=%s|bosminer_arg=%s|track1_wrapper_arg=%s\\n' \\")
        self.assertLess(ppid_capture, neutralize)
        self.assertLess(neutralize, emit)
        # The neutralization must sit inside collect_all_task_effect_snapshot.
        collector = source.index("collect_all_task_effect_snapshot() {")
        stable = source.index("stable_all_task_effect_snapshot() {")
        self.assertLess(collector, ppid_capture)
        self.assertLess(ppid_capture, stable)

    def test_park_exit_closeout_keys_on_physical_safeoff_evidence(self) -> None:
        source = (SCRIPTS / "dcentrald_s19k_tmp_remote_run.sh").read_text(
            encoding="utf-8"
        )
        # A daemon-side terminal closeout (the management-only park path)
        # publishes no terminal-handoff receipt, so both post-exit closeout
        # sites must key the typed stock-loss transition on physical
        # evidence (rails checked-SafeOff + stock custody absent) before
        # attempting the live-tree retire, whose pidfile fence is
        # structurally doomed after the stock handoff.
        park_arm = "elif gpio_safeoff_is_exact && ! bosminer_custody_owner_is_live; then"
        self.assertEqual(source.count(park_arm), 2)
        wait_site = source.index('if wait "$CHILD_PID"; then')
        stop_child_site = source.index("stop_child() {")
        for site in (wait_site, stop_child_site):
            arm = source.index(park_arm, site)
            retire = source.index("retire_released_startup_after_child_exit; then", site)
            transition = source.index(
                "transition_startup_stock_loss_to_pending || exit 1", arm
            )
            self.assertLess(arm, retire)
            self.assertLess(arm, transition)

    def test_clean_startup_closeout_publishes_canonical_mode_receipts(self) -> None:
        source = (SCRIPTS / "dcentrald_s19k_tmp_remote_run.sh").read_text(
            encoding="utf-8"
        )
        serial = (
            ROOT / "dcentrald" / "dcentrald" / "src" / "serial_mining.rs"
        ).read_text(encoding="utf-8")

        self.assertEqual(
            len(
                re.findall(
                    r"transition_startup_stock_loss_to_pending \|\| exit 1\n"
                    r"\s+publish_mode_specific_receipts_after_safeoff",
                    source,
                )
            ),
            2,
        )
        publisher_start = source.index(
            "publish_mode_specific_receipts_after_safeoff()"
        )
        publisher_end = source.index("\n}\n", publisher_start)
        publisher = source[publisher_start:publisher_end]
        for call in (
            "publish_handoff_no_work_transcript_receipt",
            "publish_bounded_work_transcript_receipt",
            "publish_endurance_work_receipt",
        ):
            self.assertIn(call, publisher)

        transition_start = source.index("transition_startup_stock_loss_to_pending()")
        transition_end = source.index("\n}\n", transition_start)
        transition = source[transition_start:transition_end]
        terminal = transition.index('if [ -e "$TERMINAL_HANDOFF_RECEIPT" ]')
        canonical = transition.index(
            "publish_startup_canonical_pre_safeoff_active", terminal
        )
        v4 = transition.index("clear_runtime_obligation_after_safeoff", canonical)
        self.assertLess(terminal, canonical)
        self.assertLess(canonical, v4)

        clean_publication = serial.index(
            "clean S19k Track-1 terminal receipt publication failed"
        )
        terminal_classification = serial.index(
            "let terminal_result = classify_serial_terminal_result(",
            clean_publication,
        )
        self.assertLess(clean_publication, terminal_classification)
        self.assertIn(
            "s19k_publish_terminal_partial_handoff_receipt(",
            serial[clean_publication - 1200 : terminal_classification],
        )

    def test_stock_custody_guard_binds_exact_supervisor_not_bos_tools_multicall(self) -> None:
        source = (SCRIPTS / "dcentrald_s19k_tmp_remote_run.sh").read_text(
            encoding="utf-8"
        )

        def function(name: str) -> str:
            match = re.search(
                rf"(?ms)^{re.escape(name)}\(\) (?:\{{\n.*?^\}}\n|\(\n.*?^\)\n)",
                source,
            )
            self.assertIsNotNone(match, name)
            return match.group(0)

        # /usr/bin/bos-tools is a multi-call binary that also hosts dnsmasq
        # and boser run-and-watch daemons which legitimately survive the
        # stock handoff.  The stock custody guard must key on bosminer
        # itself, on a live task whose argv names the exact /usr/bin/bosminer
        # path (the run-and-watch MINING supervisor), or on the pid+start+exe
        # supervisor identity bound by the J0 owner record -- never on a
        # bare bos-tools exe/comm/argv0 match.
        matcher = function("all_task_snapshot_has_stock_owner")
        self.assertIn("runtime_lock_field_at", matcher)
        self.assertIn("dcentos.s19k-startup-j0-prefork/v1", matcher)
        for key in ("supervisor_pid", "supervisor_start", "supervisor_exe"):
            self.assertIn(
                'runtime_lock_field_at "$RUNTIME_LOCK_OWNER" ' + key, matcher
            )
        self.assertIn("'|bosminer_arg=true|'", matcher)
        self.assertIn("'|exe=/usr/bin/bosminer|'", matcher)
        for broad in (
            "'|exe=/usr/bin/bos-tools|'",
            "'|comm=bos-tools|'",
            "'|argv0=/usr/bin/bos-tools|'",
        ):
            self.assertNotIn(broad, matcher)
        guard = function("bosminer_custody_owner_is_live")
        self.assertIn("stable_all_task_effect_snapshot", guard)
        self.assertIn("all_task_snapshot_has_stock_owner", guard)
        # The typed-SafeOff divert chain fences through the sibling absence
        # helper, so it must compose the same exact matcher.
        sibling = function("no_stock_daemon_watchdog_or_competing_wrapper_is_live")
        self.assertIn("! all_task_snapshot_has_stock_owner", sibling)
        # The exact matcher is the live authority at both post-exit park
        # arms and at every terminal-handoff absence fence (the fourth
        # call site is the recovery SafeOff refusal in
        # run_checked_safeoff_command).
        self.assertEqual(
            source.count(
                "elif gpio_safeoff_is_exact && ! bosminer_custody_owner_is_live; then"
            ),
            2,
        )
        fences = re.findall(
            r'\[ "\$\(terminal_handoff_field global_stock_absence\)" != true \][ \\\n]+'
            r"\|\| bosminer_custody_owner_is_live; then",
            source,
        )
        self.assertEqual(len(fences), 3)

    @unittest.skipUnless(os.name == "nt", "WSL exact stock custody guard KAT")
    def test_stock_custody_guard_exact_identity_behavior(self) -> None:
        source = (SCRIPTS / "dcentrald_s19k_tmp_remote_run.sh").read_text(
            encoding="utf-8"
        )

        def function(name: str) -> str:
            match = re.search(
                rf"(?ms)^{re.escape(name)}\(\) (?:\{{\n.*?^\}}\n|\(\n.*?^\)\n)",
                source,
            )
            self.assertIsNotNone(match, name)
            return match.group(0)

        harness = "#!/bin/sh\nset -eu\n" + "\n".join(
            function(name)
            for name in (
                "valid_uint",
                "runtime_lock_field_at",
                "runtime_lock_container_is_exact",
                "collect_all_task_effect_snapshot",
                "filter_custody_relevant_task_effects",
                "stable_all_task_effect_snapshot",
                "all_task_snapshot_has_stock_owner",
                "bosminer_custody_owner_is_live",
            )
        )
        harness += r'''
ROOT=$1
TRIAL_DIR=$ROOT
SELF_START=424243
mkdir -p "$TRIAL_DIR"
mktask() {
    _pid=$1; _start=$2; _comm=$3; _exe=$4
    mkdir -p "$ROOT/$_pid/task/$_pid/fd"
    printf '%s\n' "$_pid ($_comm) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 $_start" > "$ROOT/$_pid/task/$_pid/stat"
    printf '%s\n' "$_comm" > "$ROOT/$_pid/task/$_pid/comm"
    shift 4
    ARGS=""
    for _a in "$@"; do ARGS="$ARGS$_a
"; done
    printf '%s' "$ARGS" | tr '\n' '\000' > "$ROOT/$_pid/task/$_pid/cmdline"
    ln -s "$_exe" "$ROOT/$_pid/task/$_pid/exe"
}
rmtask() { rm -rf "$ROOT/$1"; }
# Live am3-s19k shape: dnsmasq/boser run-and-watch daemons survive the
# stock handoff and must never satisfy the custody guard.
mktask 1192 111111 dnsmasq /usr/bin/bos-tools /usr/bin/bos-tools run-and-watch -- /usr/sbin/dnsmasq -C /etc/dnsmasq.conf
mktask 1450 222222 boser /usr/bin/bos-tools /usr/bin/bos-tools run-and-watch -- /usr/bin/boser --log-to-file
# J0 owner record binding the mining supervisor identity inside its custody container.
mkdir -p "$ROOT/lock"
printf 'schema=dcentos.s19k-startup-j0-prefork/v1\nsupervisor_pid=1458\nsupervisor_start=555555\nsupervisor_exe=/usr/bin/bos-tools\n' > "$ROOT/lock/owner"
RUNTIME_LOCK_OWNER="$ROOT/lock/owner"; export RUNTIME_LOCK_OWNER
RUNTIME_LOCK="$ROOT/lock"; export RUNTIME_LOCK
# 61: only the non-mining run-and-watch daemons are live -> not stock custody
bosminer_custody_owner_is_live "$ROOT" && exit 61
# 62: exact bound supervisor pid+start+exe is live (even without a bosminer argv) -> stock custody
mktask 1458 555555 bos-tools /usr/bin/bos-tools /usr/bin/bos-tools run-and-watch -- /usr/sbin/other
bosminer_custody_owner_is_live "$ROOT" || exit 62
# 63: recycled pid at the same exe with a different start -> not stock custody
rmtask 1458; mktask 1458 999999 bos-tools /usr/bin/bos-tools /usr/bin/bos-tools run-and-watch -- /usr/sbin/other
bosminer_custody_owner_is_live "$ROOT" && exit 63
# 64: any live task whose argv names the exact /usr/bin/bosminer path (the run-and-watch mining supervisor) -> stock custody
rmtask 1458; mktask 300 333333 bos-tools /usr/bin/bos-tools /usr/bin/bos-tools run-and-watch -- /usr/bin/bosminer --log-to-file
bosminer_custody_owner_is_live "$ROOT" || exit 64
# 65: bosminer itself under any pid -> stock custody
rmtask 300; mktask 1472 444444 bosminer /usr/bin/bosminer /usr/bin/bosminer --log-to-file
bosminer_custody_owner_is_live "$ROOT" || exit 65
rmtask 1472
# 66: malformed bound supervisor tuple -> fail closed as live/unknown
printf 'schema=dcentos.s19k-startup-j0-prefork/v1\nsupervisor_pid=1458\nsupervisor_exe=/usr/bin/bos-tools\n' > "$ROOT/lock/owner"
bosminer_custody_owner_is_live "$ROOT" || exit 66
# 67: unknown owner schema -> fail closed as live/unknown
printf 'schema=dcentos.s19k-track1-runtime-lock/v99\n' > "$ROOT/lock/owner"
bosminer_custody_owner_is_live "$ROOT" || exit 67
# 68: owner record lost while an INEXACT custody container remains -> fail closed as live/unknown
rm -f "$ROOT/lock/owner"
bosminer_custody_owner_is_live "$ROOT" || exit 68
# 71: exact EMPTY container with no record is the pre-J0-crash neutral
# state (live refusal of trials 20260828093837/20260828123513 reacquire)
# -> process-level tests only; the run-and-watch daemons do not count
chmod 700 "$ROOT/lock"
bosminer_custody_owner_is_live "$ROOT" && exit 71
# 72: exact container holding a foreign entry with no record -> fail closed as live/unknown
touch "$ROOT/lock/foreign"
bosminer_custody_owner_is_live "$ROOT" || exit 72
rm -f "$ROOT/lock/foreign"
# 69: tuple-less pending owner schema keeps process-only semantics; the run-and-watch daemons still do not count
printf 'schema=dcentos.s19k-track1-runtime-lock/v10\nowner_kind=startup-prefix-stock-restart-pending\n' > "$ROOT/lock/owner"
bosminer_custody_owner_is_live "$ROOT" && exit 69
# 70: fully unbound board (no container, no record) -> receiptless process-only semantics
rm -f "$ROOT/lock/owner"; rmdir "$ROOT/lock"
bosminer_custody_owner_is_live "$ROOT" && exit 70
exit 0
'''
        with tempfile.TemporaryDirectory() as raw_temp:
            local_harness = Path(raw_temp) / "exact_stock_custody_kat.sh"
            local_harness.write_text(harness, encoding="utf-8", newline="\n")
            fixture = subprocess.check_output(
                [
                    "wsl.exe",
                    "-d",
                    "Ubuntu-22.04",
                    "mktemp",
                    "-d",
                    "/tmp/s19k_exact_stock_custody.XXXXXX",
                ],
                text=True,
            ).strip()
            try:
                result = subprocess.run(
                    [
                        "wsl.exe",
                        "-d",
                        "Ubuntu-22.04",
                        "busybox",
                        "sh",
                        self._shell_path(local_harness),
                        fixture,
                    ],
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
                self.assertEqual(
                    result.returncode,
                    0,
                    f"stdout={result.stdout!r}\nstderr={result.stderr!r}",
                )
            finally:
                subprocess.run(
                    [
                        "wsl.exe",
                        "-d",
                        "Ubuntu-22.04",
                        "rm",
                        "-rf",
                        fixture,
                    ],
                    check=False,
                )

    def test_startup_prefix_safeoff_contract_is_exact_and_owner_last(self) -> None:
        source = (SCRIPTS / "dcentrald_s19k_tmp_remote_run.sh").read_text(
            encoding="utf-8"
        )
        serial = (
            ROOT / "dcentrald" / "dcentrald" / "src" / "serial_mining.rs"
        ).read_text(encoding="utf-8")
        main = (
            ROOT / "dcentrald" / "dcentrald" / "src" / "main.rs"
        ).read_text(encoding="utf-8")
        source_keys = (
            "schema transaction_id phase highest_phase trial_dir source_kind "
            "owner_present owner_path owner_sha256 owner_bytes "
            "c1_present c1_path c1_sha256 c1_bytes "
            "j1_present j1_path j1_sha256 j1_bytes "
            "active_present active_path active_sha256 active_bytes "
            "j2_present j2_path j2_sha256 j2_bytes "
            "release_present release_path release_sha256 release_bytes "
            "parent_lost_present parent_lost_path parent_lost_sha256 parent_lost_bytes "
            "terminal_present terminal_path terminal_sha256 terminal_bytes "
            "cleanup_present cleanup_path cleanup_sha256 cleanup_bytes "
            "preserved_owner_present preserved_owner_path preserved_owner_sha256 preserved_owner_bytes "
            "preserved_active_present preserved_active_path preserved_active_sha256 preserved_active_bytes "
            "fifo_present fifo_path fifo_mnt_id fifo_inode "
            "transcript_present transcript_path transcript_mnt_id transcript_inode "
            "transcript_mode transcript_uid transcript_gid transcript_sha256 transcript_bytes "
            "supervisor_pid supervisor_start supervisor_ppid supervisor_pgrp supervisor_session "
            "supervisor_exe supervisor_cmdline_sha256 supervisor_cmdline_bytes "
            "bosminer_pid bosminer_start bosminer_ppid bosminer_pgrp bosminer_session "
            "bosminer_exe bosminer_cmdline_sha256 bosminer_cmdline_bytes "
            "stock_pidfile_path stock_pidfile_sha256 stock_pidfile_bytes "
            "binary_sha256 binary_bytes config_sha256 config_bytes runner_sha256 runner_bytes "
            "custody_observer_sha256 custody_observer_bytes "
            "stock_restart_helper_sha256 stock_restart_helper_bytes "
            "live_identity_schema live_identity_profile live_identity_sha256 "
            "stock_supervisor stock_bosminer dcentrald watchdog_fd competing_wrapper "
            "watchdog_start_intent watchdog_armed signal_attempted inherited_rails "
            "route_or_uart_opened hardware_opened persistent_mutation publication"
        ).split()
        pending_keys = (
            "schema phase terminal trial_dir transaction_id highest_phase "
            "source_receipt_schema source_receipt_path source_receipt_sha256 source_receipt_bytes "
            "binary_sha256 binary_bytes config_sha256 config_bytes runner_sha256 runner_bytes "
            "custody_observer_sha256 custody_observer_bytes "
            "stock_restart_helper_sha256 stock_restart_helper_bytes "
            "live_identity_schema live_identity_profile live_identity_sha256 "
            "live_identity_model_sha256 live_identity_board_count "
            "live_identity_physical_addresses live_identity_board_names live_identity_eeprom "
            "safeoff_receipt_schema safeoff_receipt_path safeoff_receipt_sha256 safeoff_receipt_bytes "
            "resets psu gpio_raw dcentrald writer_wrapper_pid writer_wrapper_start "
            "wrapper_exit_required stock_supervisor stock_bosminer watchdog_fd "
            "stock_init_path stock_init_sha256 stock_init_bytes persistent_mutation next_authority"
        ).split()
        owner_keys = (
            "schema owner_kind trial_dir runner_sha256 runner_bytes "
            "custody_observer_sha256 custody_observer_bytes "
            "stock_restart_helper_sha256 stock_restart_helper_bytes live_identity_sha256 "
            "active_sha256 active_bytes transaction_id highest_phase "
            "source_receipt_sha256 safeoff_receipt_sha256"
        ).split()

        def ordered_sha(keys: list[str]) -> str:
            return hashlib.sha256(("\n".join(keys) + "\n").encode()).hexdigest()

        self.assertEqual(len(source_keys), 108)
        self.assertEqual(len(pending_keys), 47)
        self.assertEqual(len(owner_keys), 16)
        self.assertIn(
            f"STARTUP_PRESAFEOFF_SOURCE_KEYS_SHA={ordered_sha(source_keys)}", source
        )
        self.assertIn(
            f"STARTUP_PREFIX_PENDING_KEYS_SHA={ordered_sha(pending_keys)}", source
        )
        self.assertIn(
            f"STARTUP_PREFIX_OWNER_KEYS_SHA={ordered_sha(owner_keys)}", source
        )
        self.assertIn(
            "schema=dcentos.s19k-startup-prefix-safeoff-source/v1", source
        )
        self.assertIn(
            "schema=dcentos.s19k-startup-prefix-stock-restart-pending/v1", source
        )
        self.assertIn("schema=dcentos.s19k-track1-runtime-lock/v10", source)
        transition = source.index("publish_startup_prefix_pending_after_safeoff()")
        transition_end = source.index("\n}\n", transition)
        transition_body = source[transition:transition_end]
        active_durable = '"$PENDING_TMP" "$ACTIVE"'
        owner_durable = '"$OWNER_TMP" "$RUNTIME_LOCK_OWNER"'
        self.assertEqual(transition_body.count(active_durable), 2)
        self.assertEqual(transition_body.count(owner_durable), 2)
        self.assertLess(
            transition_body.rindex(active_durable),
            transition_body.index(owner_durable),
        )
        self.assertNotIn('mv -f "$PENDING_TMP" "$ACTIVE"', transition_body)
        self.assertNotIn('mv -f "$OWNER_TMP" "$RUNTIME_LOCK_OWNER"', transition_body)
        state_machine = source.index("transition_startup_stock_loss_to_pending()")
        state_machine_end = source.index("\n}\n", state_machine)
        state_machine_body = source[state_machine:state_machine_end]
        self.assertLess(
            state_machine_body.index("publish_startup_prefix_pending_after_safeoff"),
            state_machine_body.index(
                "consume_startup_transition_completions || return 1"
            ),
        )
        for flag in (
            "--s19k-track1-durable-replace-source",
            "--s19k-track1-durable-replace-destination",
            "--s19k-track1-durable-replace-old-sha256",
            "--s19k-track1-durable-replace-old-bytes",
            "--s19k-track1-durable-replace-new-sha256",
            "--s19k-track1-durable-replace-new-bytes",
        ):
            self.assertIn(flag, source)
            self.assertIn(flag, main)
        self.assertIn("s19k_durable_replace_from_cli", main)
        self.assertIn("libc::SYS_renameat2", serial)
        self.assertIn("S19kDurableReplacePhase::AfterNewFileFsync", serial)
        self.assertIn("S19kDurableReplacePhase::AfterSourceDirectoryFsync", serial)
        self.assertIn("S19kDurableReplacePhase::AfterDestinationDirectoryFsync", serial)
        self.assertIn("source is absent without the exact new destination", serial)
        self.assertIn("refuses simultaneous source and new destination", serial)
        restore = source.index('if [ "$MODE" = restore ]')
        source_dispatch = source.index(
            '[ -e "$STARTUP_PRESAFEOFF_SOURCE" ]', restore
        )
        cleanup_dispatch = source.index('[ -e "$STARTUP_RETIRE_CLEANUP" ]', restore)
        self.assertLess(source_dispatch, cleanup_dispatch)
        self.assertIn('preserve_startup_source_file "$SOURCE_ACTIVE_PATH"', source)
        self.assertIn("SOURCE_OWNER_PATH=$STARTUP_PRESAFEOFF_OWNER", source)
        self.assertIn("SOURCE_ACTIVE_PATH=$STARTUP_PRESAFEOFF_ACTIVE", source)
        self.assertIn(
            '[ "$(startup_source_field owner_path)" = "$STARTUP_PRESAFEOFF_OWNER" ]',
            source,
        )
        self.assertIn(
            '[ "$(startup_source_field active_path)" = "$STARTUP_PRESAFEOFF_ACTIVE" ]',
            source,
        )
        self.assertIn(
            'startup_source_optional_pair_equals_record "$HISTORICAL_PREFIX" "$STARTUP_RETIRE_TERMINAL" "$HISTORICAL_PREFIX"',
            source,
        )
        self.assertIn(
            '[ "$(startup_source_field fifo_path)" = "$(runtime_lock_field_at "$STARTUP_PRESAFEOFF_OWNER" fifo_path)" ]',
            source,
        )
        self.assertIn('startup_source_transcript_state_is_exact', source)
        for function_name in (
            "capture_startup_transcript_for_terminal",
            "startup_source_transcript_state_is_exact",
        ):
            function_start = source.index(f"{function_name}() {{")
            function_end = source.index("\n}\n", function_start)
            function_body = source[function_start:function_end]
            held_sha = function_body.index('sha256sum "/proc/$$/fd/8"')
            held_bytes = function_body.index('wc -c < "/proc/$$/fd/8"')
            fd_close = function_body.index('exec 8>&-')
            self.assertLess(held_sha, fd_close, function_name)
            self.assertLess(held_bytes, fd_close, function_name)
            self.assertNotIn('sha256sum "$STARTUP_TRANSCRIPT_PATH"', function_body)
            self.assertNotIn('sha256sum "$TRANSCRIPT_PATH"', function_body)
        self.assertIn(
            'startup_source_transcript_tuple_equals_record "$STARTUP_RETIRE_TERMINAL"',
            source,
        )
        rust_c1 = re.search(
            r"const S19K_C1_KEYS: \[&str; 47\] = \[(.*?)\];",
            serial,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(rust_c1)
        rust_c1_keys = set(re.findall(r'"([a-z0-9_]+)"', rust_c1.group(1)))
        self.assertEqual(len(rust_c1_keys), 47)
        shell_c1_relation_loops = re.findall(
            r'for KEY in ([^;]+); do\n\s*\[ "\$\(startup_field_at "\$STARTUP_C1" "\$KEY"\)"',
            source,
        )
        self.assertEqual(len(shell_c1_relation_loops), 4)
        for relation_keys in shell_c1_relation_loops:
            self.assertLessEqual(set(relation_keys.split()), rust_c1_keys)
        self.assertIn("runtime_startup_prefix_pre_safeoff", serial)
        self.assertIn("runtime_safeoff_terminal_receipt", serial)
        companion_start = source.index("publish_startup_prefix_safeoff_companion()")
        companion_end = source.index("\n}\n", companion_start)
        companion_body = source[companion_start:companion_end]
        self.assertLess(
            companion_body.index("set_expected_safeoff_receipt"),
            companion_body.index("ensure_startup_prefix_safeoff_lock"),
        )
        self.assertIn("guarded_unlink_transition_residue", source)
        self.assertIn(
            '"$TRANSITION_SCRATCH" "$TRANSITION_DESTINATION" "$TRANSITION_CLAIM"',
            source,
        )
        self.assertIn("--s19k-track1-guarded-unlink-scratch", source)
        self.assertIn("--s19k-track1-guarded-unlink-canonical", source)
        self.assertIn("--s19k-track1-guarded-unlink-claim", source)
        self.assertIn("--s19k-track1-guarded-unlink-completion", source)
        self.assertIn("--s19k-track1-consume-completion", source)
        self.assertIn("AfterCompletionRenameBeforeFsync", serial)
        self.assertIn("AfterCompletionFsync", serial)
        self.assertIn("AfterUnlinkBeforeFsync", serial)
        self.assertIn("AfterUnlinkFsync", serial)
        self.assertIn("libc::SYS_renameat2", serial)
        self.assertIn("libc::RENAME_NOREPLACE", serial)
        self.assertIn("libc::unlinkat", serial)
        self.assertIn("expected_after.nlink", serial)
        self.assertIn("directory.sync_all()", serial)
        consume_start = source.index("consume_startup_transition_completions()")
        consume_end = source.index("\n}\n", consume_start)
        consume_body = source[consume_start:consume_end]
        self.assertNotIn("OLD_IFS=", consume_body)
        caller_ifs_before_consumer = consume_body.index(
            "IFS=$CONSUME_COMPLETION_SAVED_IFS\n        case"
        )
        native_consumer = consume_body.index("consume_guarded_transition_completion")
        newline_after_consumer = consume_body.index(
            "IFS=$CONSUME_COMPLETION_NEWLINE_IFS", native_consumer
        )
        final_caller_ifs = consume_body.index(
            "IFS=$CONSUME_COMPLETION_SAVED_IFS", newline_after_consumer
        )
        final_proc_fence = consume_body.index(
            "no_stock_daemon_watchdog_or_competing_wrapper_is_live", final_caller_ifs
        )
        self.assertLess(caller_ifs_before_consumer, native_consumer)
        self.assertLess(native_consumer, newline_after_consumer)
        self.assertLess(newline_after_consumer, final_caller_ifs)
        self.assertLess(final_caller_ifs, final_proc_fence)

    @unittest.skipUnless(os.name == "nt", "WSL transition scratch classifier KAT")
    def test_startup_safeoff_pending_scratch_cutpoints_are_directly_retirable(self) -> None:
        source = (SCRIPTS / "dcentrald_s19k_tmp_remote_run.sh").read_text(
            encoding="utf-8"
        )
        prefix, marker, _ = source.partition(
            '\nSELF_START=$(process_start "$$")\n'
        )
        self.assertTrue(marker)
        harness = (
            prefix
            + '\nSELF_START=$(process_start "$$")\n'
            + "PRE_J0_EXCLUDED_PATHS=\n"
            + "classify_exact_pre_j0_residues\n"
            + "printf 'before=%s manifest=%s\\n' \"$PRE_J0_RESIDUE_COUNT\" \"$PRE_J0_RESIDUE_MANIFEST_SHA\"\n"
            + "remove_classified_pre_j0_residues\n"
            + "classify_exact_pre_j0_residues\n"
            + "printf 'after=%s manifest=%s\\n' \"$PRE_J0_RESIDUE_COUNT\" \"$PRE_J0_RESIDUE_MANIFEST_SHA\"\n"
        )
        remote_dir = subprocess.check_output(
            ["wsl.exe", "mktemp", "-d", "/tmp/dcentrald_bench_t1_scratch.XXXXXX"],
            text=True,
        ).strip()
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            harness_path = temp / "scratch_harness"
            harness_path.write_text(harness, encoding="utf-8", newline="\n")
            try:
                subprocess.run(
                    ["wsl.exe", "cp", self._shell_path(harness_path), f"{remote_dir}/harness"],
                    check=True,
                )
                subprocess.run(
                    ["wsl.exe", "chmod", "700", f"{remote_dir}/harness"], check=True
                )
                scratch_names = (
                    ".runtime_safeoff_terminal_receipt.tmp.990001.1",
                    ".runtime_safeoff_terminal_receipt_receiptless.tmp.990002.1",
                    ".runtime_active_stock_restart_pending.tmp.990003.1",
                    ".runtime_active_receiptless_stock_restart_pending.tmp.990004.1",
                    ".runtime_startup_prefix_pre_safeoff.tmp.990005.1",
                    ".runtime_safeoff_terminal_receipt_startup_prefix.tmp.990006.1",
                    ".runtime_active_startup_prefix_stock_restart_pending.tmp.990007.1",
                    ".runtime_owner_startup_prefix_stock_restart_pending.tmp.990008.1",
                    ".runtime_owner_startup_prefix_stock_restart_pending_resume.tmp.990009.1",
                )
                setup = [
                    f": > {shlex.quote(remote_dir + '/' + scratch_names[0])}",
                    f"printf partial > {shlex.quote(remote_dir + '/' + scratch_names[1])}",
                ]
                for index, name in enumerate(scratch_names[2:], start=2):
                    setup.append(
                        f"printf complete-{index} > {shlex.quote(remote_dir + '/' + name)}"
                    )
                setup.append(
                    f"ln {shlex.quote(remote_dir + '/' + scratch_names[4])} "
                    f"{shlex.quote(remote_dir + '/post_hardlink_destination')}"
                )
                setup.append(
                    "chmod 600 "
                    + " ".join(
                        shlex.quote(f"{remote_dir}/{name}") for name in scratch_names
                    )
                )
                subprocess.run(["wsl.exe", "sh", "-c", "; ".join(setup)], check=True)
                args = ["0" * 64, "1"] * 5
                result = subprocess.run(
                    [
                        "wsl.exe",
                        f"{remote_dir}/harness",
                        "fixture",
                        remote_dir,
                        "am3-s19k",
                        "recovery",
                        *args,
                    ],
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"before={len(scratch_names)} ", result.stdout)
                self.assertIn(
                    "after=0 manifest=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    result.stdout,
                )
                self.assertEqual(
                    subprocess.run(
                        ["wsl.exe", "test", "-f", f"{remote_dir}/post_hardlink_destination"]
                    ).returncode,
                    0,
                )
            finally:
                subprocess.run(
                    ["wsl.exe", "rm", "-f", f"{remote_dir}/harness", f"{remote_dir}/post_hardlink_destination"],
                    check=False,
                )
                for name in scratch_names if "scratch_names" in locals() else ():
                    subprocess.run(
                        ["wsl.exe", "rm", "-f", f"{remote_dir}/{name}"], check=False
                    )
                subprocess.run(["wsl.exe", "rmdir", remote_dir], check=False)

    @unittest.skipUnless(os.name == "nt", "WSL startup stock-loss transition KAT")
    def test_startup_stock_loss_refuses_untyped_j0_and_resumes_active_prefixes_to_v10(
        self,
    ) -> None:
        remote_dir = subprocess.check_output(
            ["wsl.exe", "mktemp", "-d", "/tmp/dcentrald_bench_t1_startuploss.XXXXXX"],
            text=True,
        ).strip()
        protocol_nonce = hashlib.sha256(
            f"startup-loss:{remote_dir}".encode("utf-8")
        ).hexdigest()
        protocol_dir = f"/tmp/.s19k-j0-protocol.{protocol_nonce}"
        remote_controller = f"/tmp/.s19k-j0-controller.{protocol_nonce}"
        remote_command = f"/tmp/.s19k-j0-command.{protocol_nonce}"
        remote_audit = f"/tmp/.s19k-j0-audit.{protocol_nonce}"
        protocol_names = (
            "probe",
            "probe.tmp",
            "probe_lifetime",
            "controller_lifetime",
            "ready",
            "ready.tmp",
            "trigger",
            "trigger.tmp",
            "signal_intent",
            "signal_intent.tmp",
            "ack",
            "ack.tmp",
            "reaped",
            "stock_lifetime",
            "runner_lifetime",
            "watchdog_status",
            "controller_status",
            "controller_status.tmp",
        )
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            runtime_lock = f"{remote_dir}.board-global-lock"
            helper = self._identity_bound_runner(
                temp, remote_dir, runtime_lock=runtime_lock
            )
            helper_text = helper.read_text(encoding="utf-8")
            launch_anchor = "}\n\nno_watchdog_fd_is_live || {"
            self.assertEqual(helper_text.count(launch_anchor), 1)
            helper.write_text(
                helper_text.replace(
                    launch_anchor,
                    "}\n\n"
                    "# Fixture-only deterministic cut after committed J0 and before fork.\n"
                    "if [ -n \"${DCENT_TEST_J0_PROTOCOL_DIR:-}\" ]; then\n"
                    "    TEST_READY=$DCENT_TEST_J0_PROTOCOL_DIR/ready\n"
                    "    TEST_TRIGGER=$DCENT_TEST_J0_PROTOCOL_DIR/trigger\n"
                    "    TEST_INTENT=$DCENT_TEST_J0_PROTOCOL_DIR/signal_intent\n"
                    "    TEST_ACK=$DCENT_TEST_J0_PROTOCOL_DIR/ack\n"
                    "    TEST_OWNER_SHA=$(sha256sum \"$RUNTIME_LOCK_OWNER\" | awk '{print $1}')\n"
                    "    TEST_OWNER_BYTES=$(wc -c < \"$RUNTIME_LOCK_OWNER\" | tr -d ' \\t\\r\\n')\n"
                    "    {\n"
                    "        printf 'schema=dcentos.test.s19k-j0-ready/v1\\n'\n"
                    "        printf 'nonce=%s\\n' \"$DCENT_TEST_J0_NONCE\"\n"
                    "        printf 'owner_sha256=%s\\n' \"$TEST_OWNER_SHA\"\n"
                    "        printf 'owner_bytes=%s\\n' \"$TEST_OWNER_BYTES\"\n"
                    "        printf 'runner_pid=%s\\n' \"$$\"\n"
                    "        printf 'runner_start=%s\\n' \"$SELF_START\"\n"
                    "        printf 'stock_pid=%s\\n' \"$DCENT_TEST_STOCK_PID\"\n"
                    "        printf 'stock_start=%s\\n' \"$DCENT_TEST_STOCK_START\"\n"
                    "    } > \"$TEST_READY.tmp\" || exit 91\n"
                    "    mv \"$TEST_READY.tmp\" \"$TEST_READY\" || exit 91\n"
                    "    TEST_WAIT=0\n"
                    "    while [ ! -f \"$TEST_TRIGGER\" ] && [ \"$TEST_WAIT\" -lt 10 ]; do\n"
                    "        sleep 1\n"
                    "        TEST_WAIT=$((TEST_WAIT + 1))\n"
                    "    done\n"
                    "    [ -f \"$TEST_TRIGGER\" ] || exit 92\n"
                    "    [ \"$(process_start \"$$\")\" = \"$SELF_START\" ] || exit 93\n"
                    "    [ \"$(process_start \"$DCENT_TEST_STOCK_PID\")\" = \"$DCENT_TEST_STOCK_START\" ] || exit 93\n"
                    "    [ \"$(sha256sum \"$RUNTIME_LOCK_OWNER\" | awk '{print $1}')\" = \"$TEST_OWNER_SHA\" ] || exit 93\n"
                    "    [ \"$(wc -c < \"$RUNTIME_LOCK_OWNER\" | tr -d ' \\t\\r\\n')\" = \"$TEST_OWNER_BYTES\" ] || exit 93\n"
                    "    [ \"$(wc -l < \"$TEST_TRIGGER\" | tr -d ' \\t\\r\\n')\" = 9 ] || exit 93\n"
                    "    [ \"$(startup_field_at \"$TEST_TRIGGER\" schema)\" = dcentos.test.s19k-j0-trigger/v1 ] || exit 93\n"
                    "    [ \"$(startup_field_at \"$TEST_TRIGGER\" nonce)\" = \"$DCENT_TEST_J0_NONCE\" ] || exit 93\n"
                    "    [ \"$(startup_field_at \"$TEST_TRIGGER\" owner_sha256)\" = \"$TEST_OWNER_SHA\" ] || exit 93\n"
                    "    [ \"$(startup_field_at \"$TEST_TRIGGER\" owner_bytes)\" = \"$TEST_OWNER_BYTES\" ] || exit 93\n"
                    "    [ \"$(startup_field_at \"$TEST_TRIGGER\" runner_pid)\" = \"$$\" ] || exit 93\n"
                    "    [ \"$(startup_field_at \"$TEST_TRIGGER\" runner_start)\" = \"$SELF_START\" ] || exit 93\n"
                    "    [ \"$(startup_field_at \"$TEST_TRIGGER\" stock_pid)\" = \"$DCENT_TEST_STOCK_PID\" ] || exit 93\n"
                    "    [ \"$(startup_field_at \"$TEST_TRIGGER\" stock_start)\" = \"$DCENT_TEST_STOCK_START\" ] || exit 93\n"
                    "    [ \"$(startup_field_at \"$TEST_TRIGGER\" action)\" = kill-stock-after-j0 ] || exit 93\n"
                    "    {\n"
                    "        printf 'schema=dcentos.test.s19k-j0-signal/v1\\nstatus=signal-intent\\n'\n"
                    "        printf 'nonce=%s\\nowner_sha256=%s\\nowner_bytes=%s\\n' \"$DCENT_TEST_J0_NONCE\" \"$TEST_OWNER_SHA\" \"$TEST_OWNER_BYTES\"\n"
                    "        printf 'runner_pid=%s\\nrunner_start=%s\\nstock_pid=%s\\nstock_start=%s\\n' \"$$\" \"$SELF_START\" \"$DCENT_TEST_STOCK_PID\" \"$DCENT_TEST_STOCK_START\"\n"
                    "    } > \"$TEST_INTENT.tmp\" || exit 94\n"
                    "    mv \"$TEST_INTENT.tmp\" \"$TEST_INTENT\" || exit 94\n"
                    "    kill -9 \"$DCENT_TEST_STOCK_PID\" 2>/dev/null || exit 95\n"
                    "    sed 's/status=signal-intent/status=signal-committed/' \"$TEST_INTENT\" > \"$TEST_ACK.tmp\" || exit 96\n"
                    "    mv \"$TEST_ACK.tmp\" \"$TEST_ACK\" || exit 96\n"
                    "    exit 97\n"
                    "fi\n\n"
                    "no_watchdog_fd_is_live || {",
                    1,
                ),
                encoding="utf-8",
                newline="\n",
            )
            helper_text = helper.read_text(encoding="utf-8")
            probe_anchor = 'if [ "$MODE" = identity ]; then'
            self.assertEqual(helper_text.count(probe_anchor), 1)
            helper.write_text(
                helper_text.replace(
                    probe_anchor,
                    "# Fixture-only production-classifier probe. The generic controller is\n"
                    "# live, but its argv contains no trial, runner, or Track-1 token.\n"
                    "if [ \"${DCENT_TEST_CLASSIFY_STARTUP_PREFIX_ONLY:-}\" = classifier-v1 ]; then\n"
                    "    classify_startup_prefix_for_safeoff\n"
                    "    exit $?\n"
                    "fi\n\n"
                    "if [ \"${DCENT_TEST_CONTROLLER_PROBE:-}\" = classifier-v1 ]; then\n"
                    "    TEST_PROBE=$DCENT_TEST_J0_PROTOCOL_DIR/probe\n"
                    "    [ \"$(process_start \"$DCENT_TEST_CONTROLLER_PID\")\" = \"$DCENT_TEST_CONTROLLER_START\" ] || exit 98\n"
                    "    if another_trial_wrapper_is_live; then\n"
                    "        TEST_CLASSIFIER=blocked\n"
                    "        TEST_PROBE_RC=98\n"
                    "    else\n"
                    "        TEST_CLASSIFIER=clear\n"
                    "        TEST_PROBE_RC=0\n"
                    "    fi\n"
                    "    [ \"$(process_start \"$DCENT_TEST_CONTROLLER_PID\")\" = \"$DCENT_TEST_CONTROLLER_START\" ] || exit 98\n"
                    "    {\n"
                    "        printf 'schema=dcentos.test.s19k-controller-probe/v1\\n'\n"
                    "        printf 'nonce=%s\\n' \"$DCENT_TEST_J0_NONCE\"\n"
                    "        printf 'controller_pid=%s\\n' \"$DCENT_TEST_CONTROLLER_PID\"\n"
                    "        printf 'controller_start=%s\\n' \"$DCENT_TEST_CONTROLLER_START\"\n"
                    "        printf 'classifier=%s\\n' \"$TEST_CLASSIFIER\"\n"
                    "    } > \"$TEST_PROBE.tmp\" || exit 98\n"
                    "    mv \"$TEST_PROBE.tmp\" \"$TEST_PROBE\" || exit 98\n"
                    "    exit \"$TEST_PROBE_RC\"\n"
                    "fi\n\n"
                    + probe_anchor,
                    1,
                ),
                encoding="utf-8",
                newline="\n",
            )
            self.assertIn(
                'schema=dcentos.test.s19k-j0-ready/v1',
                helper.read_text(encoding="utf-8"),
            )
            self.assertIn(
                'schema=dcentos.test.s19k-controller-probe/v1',
                helper.read_text(encoding="utf-8"),
            )
            self.assertIn(
                'DCENT_TEST_CLASSIFY_STARTUP_PREFIX_ONLY',
                helper.read_text(encoding="utf-8"),
            )
            self.assertNotIn(
                '[ "$(runtime_lock_field_at "$OWNER_EVIDENCE" stock_pidfile_path)" = /var/run/bosminer.pid ]',
                helper.read_text(encoding="utf-8"),
            )
            self.assertIn(
                f'[ "$(runtime_lock_field_at "$OWNER_EVIDENCE" stock_pidfile_path)" = {remote_dir}/live_identity_fixture/bosminer.pid ]',
                helper.read_text(encoding="utf-8"),
            )
            self.assertNotIn(
                '[ "$(startup_field_at "$CLEANUP_EVIDENCE" stock_pidfile_path)" = /var/run/bosminer.pid ]',
                helper.read_text(encoding="utf-8"),
            )
            self.assertIn(
                f'[ "$(startup_field_at "$CLEANUP_EVIDENCE" stock_pidfile_path)" = {remote_dir}/live_identity_fixture/bosminer.pid ]',
                helper.read_text(encoding="utf-8"),
            )
            helper_fixture_source = helper.read_text(encoding="utf-8")
            self.assertNotIn(
                '[ "$(active_field stock_init_path)" = /etc/init.d/S99bosminer ]',
                helper_fixture_source,
            )
            self.assertNotIn(
                '[ "$(active_field stock_init_sha256)" = 6d9cce12caa49249396b48296101b0fbbcc6456cb3fa09bdbe2858bdcba948c9 ]',
                helper_fixture_source,
            )
            self.assertNotIn(
                '[ "$(active_field stock_init_bytes)" = 1330 ]',
                helper_fixture_source,
            )
            self.assertIn(
                f'[ "$(active_field stock_init_path)" = {remote_dir}/live_identity_fixture/S99bosminer ]',
                helper_fixture_source,
            )
            self.assertIn(
                f'[ "$(active_field stock_init_sha256)" = {hashlib.sha256((temp / "fixture_S99bosminer").read_bytes()).hexdigest()} ]',
                helper_fixture_source,
            )
            self.assertIn(
                f'[ "$(active_field stock_init_bytes)" = {len((temp / "fixture_S99bosminer").read_bytes())} ]',
                helper_fixture_source,
            )
            model_sha = hashlib.sha256(
                (temp / "fixture_bosminer_model.json").read_bytes()
            ).hexdigest()
            binary = temp / "dcentrald"
            config = temp / "dcentrald_s19k.toml"
            binary.write_text(
                "#!/bin/sh\n"
                "source_path=; destination_path=; guarded_scratch=; guarded_canonical=; guarded_claim=; guarded_completion=; consume_completion=; durable_source=; durable_destination=; durable_old_sha=; durable_old_bytes=; durable_new_sha=; durable_new_bytes=; previous=\n"
                "for arg in \"$@\"; do\n"
                "  case \"$previous\" in source) source_path=$arg ;; destination) destination_path=$arg ;; "
                "guarded_scratch) guarded_scratch=$arg ;; guarded_canonical) guarded_canonical=$arg ;; "
                "guarded_claim) guarded_claim=$arg ;; guarded_completion) guarded_completion=$arg ;; "
                "consume_completion) consume_completion=$arg ;; durable_source) durable_source=$arg ;; "
                "durable_destination) durable_destination=$arg ;; durable_old_sha) durable_old_sha=$arg ;; "
                "durable_old_bytes) durable_old_bytes=$arg ;; durable_new_sha) durable_new_sha=$arg ;; "
                "durable_new_bytes) durable_new_bytes=$arg ;; esac\n"
                "  case \"$arg\" in --s19k-track1-journal-source) previous=source; continue ;; "
                "--s19k-track1-journal-destination) previous=destination; continue ;; "
                "--s19k-track1-guarded-unlink-scratch) previous=guarded_scratch; continue ;; "
                "--s19k-track1-guarded-unlink-canonical) previous=guarded_canonical; continue ;; "
                "--s19k-track1-guarded-unlink-claim) previous=guarded_claim; continue ;; "
                "--s19k-track1-guarded-unlink-completion) previous=guarded_completion; continue ;; "
                "--s19k-track1-consume-completion) previous=consume_completion; continue ;; "
                "--s19k-track1-durable-replace-source) previous=durable_source; continue ;; "
                "--s19k-track1-durable-replace-destination) previous=durable_destination; continue ;; "
                "--s19k-track1-durable-replace-old-sha256) previous=durable_old_sha; continue ;; "
                "--s19k-track1-durable-replace-old-bytes) previous=durable_old_bytes; continue ;; "
                "--s19k-track1-durable-replace-new-sha256) previous=durable_new_sha; continue ;; "
                "--s19k-track1-durable-replace-new-bytes) previous=durable_new_bytes; continue ;; esac\n"
                "  previous=\n"
                "done\n"
                "if [ -n \"$source_path\" ] && [ -n \"$destination_path\" ]; then\n"
                + publisher_admission_sh("source_path", "destination_path", "  ")
                + "  ln \"$source_path\" \"$destination_path\"; exit $?; fi\n"
                "if [ -n \"$durable_source\" ] || [ -n \"$durable_destination\" ]; then\n"
                "  [ -n \"$durable_source\" ] && [ -n \"$durable_destination\" ] && "
                "[ -n \"$durable_old_sha\" ] && [ -n \"$durable_old_bytes\" ] && "
                "[ -n \"$durable_new_sha\" ] && [ -n \"$durable_new_bytes\" ] || exit 91\n"
                "  if [ -f \"$durable_source\" ]; then\n"
                "    [ \"$(sha256sum \"$durable_source\" | awk '{print $1}')\" = \"$durable_new_sha\" ] || exit 92\n"
                "    [ \"$(wc -c < \"$durable_source\" | tr -d ' \\t\\r\\n')\" = \"$durable_new_bytes\" ] || exit 93\n"
                "    if [ -e \"$durable_destination\" ]; then "
                "[ \"$durable_old_sha\" != none ] && [ \"$(sha256sum \"$durable_destination\" | awk '{print $1}')\" = \"$durable_old_sha\" ] && "
                "[ \"$(wc -c < \"$durable_destination\" | tr -d ' \\t\\r\\n')\" = \"$durable_old_bytes\" ] || exit 94; "
                "else [ \"$durable_old_sha:$durable_old_bytes\" = none:0 ] || exit 95; fi\n"
                "    mv -f \"$durable_source\" \"$durable_destination\" || exit 96\n"
                "  fi\n"
                "  [ -f \"$durable_destination\" ] || exit 97\n"
                "  [ \"$(sha256sum \"$durable_destination\" | awk '{print $1}')\" = \"$durable_new_sha\" ] || exit 98\n"
                "  [ \"$(wc -c < \"$durable_destination\" | tr -d ' \\t\\r\\n')\" = \"$durable_new_bytes\" ] || exit 99\n"
                "  exit 0\n"
                "fi\n"
                "if [ -n \"$consume_completion\" ]; then\n"
                "  [ -n \"$guarded_canonical\" ] || exit 81\n"
                "  set -- $(ls -lni \"$guarded_canonical\"); canonical_inode=${1:-}\n"
                "  set -- $(ls -lni \"$consume_completion\"); [ \"${1:-}\" = \"$canonical_inode\" ] || exit 82\n"
                "  rm -f \"$consume_completion\" || exit 83\n"
                "  if [ -f \"$(dirname \"$consume_completion\")/guarded_consume_fault\" ]; then "
                "rm -f \"$(dirname \"$consume_completion\")/guarded_consume_fault\"; exit 84; fi\n"
                "  [ ! -e \"$consume_completion\" ] || exit 85\n"
                "  exit 0\n"
                "fi\n"
                "if [ -n \"$guarded_scratch\" ] || [ -n \"$guarded_canonical\" ] || [ -n \"$guarded_claim\" ] || [ -n \"$guarded_completion\" ]; then\n"
                "  [ -n \"$guarded_scratch\" ] && [ -n \"$guarded_canonical\" ] && [ -n \"$guarded_claim\" ] && [ -n \"$guarded_completion\" ] || exit 71\n"
                "  set -- $(ls -lni \"$guarded_canonical\")\n"
                "  canonical_inode=${1:-}\n"
                "  if [ -f \"$guarded_completion\" ] && [ ! -e \"$guarded_scratch\" ] && [ ! -e \"$guarded_claim\" ]; then "
                "set -- $(ls -lni \"$guarded_completion\"); [ \"${1:-}\" = \"$canonical_inode\" ] || exit 74; "
                "elif [ -f \"$guarded_scratch\" ] && [ ! -e \"$guarded_claim\" ] && [ ! -e \"$guarded_completion\" ]; then "
                "set -- $(ls -lni \"$guarded_scratch\"); [ \"${1:-}\" = \"$canonical_inode\" ] || exit 74; "
                "mv \"$guarded_scratch\" \"$guarded_claim\" || exit 72; "
                "elif [ ! -e \"$guarded_scratch\" ] && [ -f \"$guarded_claim\" ] && [ ! -e \"$guarded_completion\" ]; then "
                "set -- $(ls -lni \"$guarded_claim\"); [ \"${1:-}\" = \"$canonical_inode\" ] || exit 74; "
                "else exit 73; fi\n"
                "  if [ -f \"$guarded_claim\" ]; then mv \"$guarded_claim\" \"$guarded_completion\" || exit 75; fi\n"
                "  set -- $(ls -lni \"$guarded_completion\")\n"
                "  [ \"${1:-}\" = \"$canonical_inode\" ] || exit 74\n"
                "  [ ! -e \"$guarded_scratch\" ] && [ ! -e \"$guarded_claim\" ] && [ -f \"$guarded_completion\" ] || exit 76\n"
                "  exit 0\n"
                "fi\n"
                "case \" $* \" in\n"
                "  *' --s19k-track1-recovery-safeoff '*)\n"
                f"    printf '1\\n' > {shlex.quote(remote_dir + '/live_identity_fixture/gpio/gpio437/value')}\n"
                f"    printf '0\\n' > {shlex.quote(remote_dir + '/live_identity_fixture/gpio/gpio454/value')}\n"
                f"    printf '0\\n' > {shlex.quote(remote_dir + '/live_identity_fixture/gpio/gpio455/value')}\n"
                f"    printf '0\\n' > {shlex.quote(remote_dir + '/live_identity_fixture/gpio/gpio456/value')}\n"
                "    printf '%s\\n' \"DCENT_S19K_TRACK1_SAFEOFF_RECEIPT "
                "schema=dcentos.s19k-track1-safeoff/v1 "
                "live_identity_sha256=$DCENT_S19K_LIVE_IDENTITY_SHA256 "
                "live_identity_profile=held78_three_bhb56902_slots_1_2_3 "
                f"live_identity_model_sha256={model_sha} "
                "live_identity_board_count=3 live_identity_physical_addresses=1,2,3 "
                "live_identity_board_names=BHB56902,BHB56902,BHB56902 "
                "live_identity_eeprom=0x50=05:11,0x51=05:11,0x52=05:11 "
                "resets=454:0,455:0,456:0 psu=437:1\"\n"
                "    exit 0 ;;\n"
                "esac\n"
                "exit 1\n",
                encoding="utf-8",
                newline="\n",
            )
            config.write_text("startup-loss-fixture", encoding="utf-8", newline="\n")
            files = {
                "dcentrald": binary,
                "dcentrald_s19k.toml": config,
                "run_trial": helper,
                "supervisor_custody_observer": SUPERVISOR_CUSTODY,
                "stock_restart_helper": STOCK_RESTART_HELPER,
            }
            try:
                for name, local in files.items():
                    subprocess.run(
                        ["wsl.exe", "cp", self._shell_path(local), f"{remote_dir}/{name}"],
                        check=True,
                    )
                subprocess.run(
                    ["wsl.exe", "cp", "/bin/sleep", f"{remote_dir}/bosminer"],
                    check=True,
                )
                subprocess.run(
                    ["wsl.exe", "chmod", "755", f"{remote_dir}/dcentrald", f"{remote_dir}/bosminer"],
                    check=True,
                )
                args: list[str] = []
                for name in (
                    "dcentrald",
                    "dcentrald_s19k.toml",
                    "run_trial",
                    "supervisor_custody_observer",
                    "stock_restart_helper",
                ):
                    blob = files[name].read_bytes()
                    args.extend([hashlib.sha256(blob).hexdigest(), str(len(blob))])
                run_argv = [
                    f"{remote_dir}/run_trial",
                    "run",
                    remote_dir,
                    "am3-s19k",
                    "mining-on-passthrough",
                    *args,
                ]
                command = temp / "startup_loss_command.sh"
                command.write_text(
                    "#!/bin/sh\nexec "
                    + " ".join(shlex.quote(value) for value in ["/bin/sh", *run_argv])
                    + "\n",
                    encoding="utf-8",
                    newline="\n",
                )
                controller = temp / "startup_loss_controller.sh"
                controller.write_text(
                    """#!/bin/sh
set -u
PROTOCOL=${DCENT_TEST_PROTOCOL:?}
NONCE=${DCENT_TEST_NONCE:?}
STOCK=${DCENT_TEST_STOCK:?}
OWNER=${DCENT_TEST_OWNER:?}
COMMAND=${DCENT_TEST_COMMAND:?}

process_start() {
    TEST_STAT=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
    TEST_REST=${TEST_STAT##*) }
    set -- $TEST_REST
    [ "$#" -ge 20 ] || return 1
    printf '%s' "${20}"
}

exact_signal() {
    TEST_PID=$1
    TEST_START=$2
    TEST_SIGNAL=$3
    [ "$(process_start "$TEST_PID")" = "$TEST_START" ] || return 1
    kill -"$TEST_SIGNAL" "$TEST_PID"
}

field() {
    TEST_FILE=$1
    TEST_KEY=$2
    [ "$(grep -c "^$TEST_KEY=" "$TEST_FILE" 2>/dev/null || true)" -eq 1 ] || return 1
    sed -n "s/^$TEST_KEY=//p" "$TEST_FILE"
}

"$STOCK" 300 >/dev/null 2>&1 &
STOCK_PID=$!
STOCK_START=$(process_start "$STOCK_PID") || exit 81
printf '%s:%s\n' "$STOCK_PID" "$STOCK_START" > "$PROTOCOL/stock_lifetime"
CONTROLLER_PID=$$
CONTROLLER_START=$(process_start "$CONTROLLER_PID") || exit 83
printf '%s:%s\n' "$CONTROLLER_PID" "$CONTROLLER_START" > "$PROTOCOL/controller_lifetime"

signal_recorded_lifetime() {
    TEST_RECORD=$1
    [ -f "$TEST_RECORD" ] || return 1
    TEST_LIFETIME=$(cat "$TEST_RECORD") || return 1
    TEST_PID=${TEST_LIFETIME%%:*}
    TEST_START=${TEST_LIFETIME#*:}
    exact_signal "$TEST_PID" "$TEST_START" 9
}

(
    sleep 175
    printf 'state=watchdog-fired\n' > "$PROTOCOL/watchdog_status"
    signal_recorded_lifetime "$PROTOCOL/probe_lifetime" || true
    signal_recorded_lifetime "$PROTOCOL/runner_lifetime" || true
    exact_signal "$STOCK_PID" "$STOCK_START" 9 || true
    exact_signal "$CONTROLLER_PID" "$CONTROLLER_START" 9 || true
) </dev/null >/dev/null 2>&1 &
WATCHDOG_PID=$!
WATCHDOG_START=$(process_start "$WATCHDOG_PID") || exit 84

controller_cleanup() {
    TEST_RC=$?
    trap - EXIT HUP INT TERM
    signal_recorded_lifetime "$PROTOCOL/probe_lifetime" || true
    signal_recorded_lifetime "$PROTOCOL/runner_lifetime" || true
    exact_signal "$STOCK_PID" "$STOCK_START" 9 || true
    [ -z "${PROBE_PID:-}" ] || wait "$PROBE_PID" 2>/dev/null || true
    [ -z "${RUNNER_PID:-}" ] || wait "$RUNNER_PID" 2>/dev/null || true
    wait "$STOCK_PID" 2>/dev/null || true
    exact_signal "$WATCHDOG_PID" "$WATCHDOG_START" 9 || true
    wait "$WATCHDOG_PID" 2>/dev/null || true
    exit "$TEST_RC"
}
trap controller_cleanup EXIT HUP INT TERM

# Before the real wrapper exists, make a private probe call the unmodified
# production competing-wrapper classifier against this exact live controller.
DCENT_TEST_CONTROLLER_PROBE=classifier-v1 \
DCENT_TEST_J0_PROTOCOL_DIR="$PROTOCOL" \
DCENT_TEST_J0_NONCE="$NONCE" \
DCENT_TEST_CONTROLLER_PID="$CONTROLLER_PID" \
DCENT_TEST_CONTROLLER_START="$CONTROLLER_START" \
/bin/sh "$COMMAND" &
PROBE_PID=$!
PROBE_START=$(process_start "$PROBE_PID") || exit 82
printf '%s:%s\n' "$PROBE_PID" "$PROBE_START" > "$PROTOCOL/probe_lifetime"
PROBE_WAIT=0
PROBE_WAIT_LIMIT=30
while [ ! -f "$PROTOCOL/probe" ] && [ "$PROBE_WAIT" -lt "$PROBE_WAIT_LIMIT" ]; do
    [ "$(process_start "$PROBE_PID")" = "$PROBE_START" ] || break
    sleep 1
    PROBE_WAIT=$((PROBE_WAIT + 1))
done
[ -f "$PROTOCOL/probe" ] || exact_signal "$PROBE_PID" "$PROBE_START" 9 || true
wait "$PROBE_PID" 2>/dev/null
PROBE_RC=$?
[ "$PROBE_RC" -eq 0 ] \
    && [ "$(wc -l < "$PROTOCOL/probe" | tr -d ' \t\r\n')" = 5 ] \
    && [ "$(field "$PROTOCOL/probe" schema)" = dcentos.test.s19k-controller-probe/v1 ] \
    && [ "$(field "$PROTOCOL/probe" nonce)" = "$NONCE" ] \
    && [ "$(field "$PROTOCOL/probe" controller_pid)" = "$CONTROLLER_PID" ] \
    && [ "$(field "$PROTOCOL/probe" controller_start)" = "$CONTROLLER_START" ] \
    && [ "$(field "$PROTOCOL/probe" classifier)" = clear ] || {
        PROBE_PRESENT=false
        PROBE_SHA=none
        PROBE_BYTES=0
        PROBE_CLASSIFIER=none
        if [ -f "$PROTOCOL/probe" ]; then
            PROBE_PRESENT=true
            PROBE_SHA=$(sha256sum "$PROTOCOL/probe" | awk '{print $1}')
            PROBE_BYTES=$(wc -c < "$PROTOCOL/probe" | tr -d ' \t\r\n')
            PROBE_CLASSIFIER=$(field "$PROTOCOL/probe" classifier 2>/dev/null || true)
        fi
        {
            printf 'schema=dcentos.test.s19k-controller-status/v1\nphase=probe-refused\n'
            printf 'nonce=%s\nprobe_pid=%s\nprobe_start=%s\nprobe_rc=%s\n' "$NONCE" "$PROBE_PID" "$PROBE_START" "$PROBE_RC"
            printf 'probe_present=%s\nprobe_sha256=%s\nprobe_bytes=%s\nprobe_classifier=%s\n' "$PROBE_PRESENT" "$PROBE_SHA" "$PROBE_BYTES" "$PROBE_CLASSIFIER"
            printf 'controller_pid=%s\ncontroller_start=%s\ncontroller_current_start=%s\n' "$CONTROLLER_PID" "$CONTROLLER_START" "$(process_start "$CONTROLLER_PID" || true)"
            printf 'stock_pid=%s\nstock_start=%s\nstock_current_start=%s\n' "$STOCK_PID" "$STOCK_START" "$(process_start "$STOCK_PID" || true)"
        } > "$PROTOCOL/controller_status.tmp"
        mv "$PROTOCOL/controller_status.tmp" "$PROTOCOL/controller_status" || true
        exact_signal "$STOCK_PID" "$STOCK_START" 9 || true
        wait "$STOCK_PID" 2>/dev/null || true
        exact_signal "$WATCHDOG_PID" "$WATCHDOG_START" 9 || true
        wait "$WATCHDOG_PID" 2>/dev/null || true
        exit 85
    }

DCENT_TEST_J0_PROTOCOL_DIR="$PROTOCOL" \
DCENT_TEST_J0_NONCE="$NONCE" \
DCENT_TEST_STOCK_PID="$STOCK_PID" \
DCENT_TEST_STOCK_START="$STOCK_START" \
/bin/sh "$COMMAND" &
RUNNER_PID=$!
RUNNER_START=$(process_start "$RUNNER_PID") || {
    exact_signal "$STOCK_PID" "$STOCK_START" 9 || true
    wait "$STOCK_PID" 2>/dev/null || true
    exit 82
}
printf '%s:%s\n' "$RUNNER_PID" "$RUNNER_START" > "$PROTOCOL/runner_lifetime"

READY=$PROTOCOL/ready
READY_WAIT=0
while [ ! -f "$READY" ] && [ "$READY_WAIT" -lt 120 ]; do
    [ "$(process_start "$RUNNER_PID")" = "$RUNNER_START" ] || break
    [ "$(process_start "$STOCK_PID")" = "$STOCK_START" ] || break
    sleep 1
    READY_WAIT=$((READY_WAIT + 1))
done
if [ ! -f "$READY" ]; then
    printf 'state=ready-timeout-or-lifetime-loss\nwaited=%s\n' "$READY_WAIT" > "$PROTOCOL/controller_status"
    exact_signal "$RUNNER_PID" "$RUNNER_START" 9 || true
    exact_signal "$STOCK_PID" "$STOCK_START" 9 || true
    wait "$RUNNER_PID" 2>/dev/null || true
    wait "$STOCK_PID" 2>/dev/null || true
    exact_signal "$WATCHDOG_PID" "$WATCHDOG_START" 9 || true
    wait "$WATCHDOG_PID" 2>/dev/null || true
    exit 90
fi

OWNER_SHA=$(sha256sum "$OWNER" | awk '{print $1}') || exit 85
OWNER_BYTES=$(wc -c < "$OWNER" | tr -d ' \t\r\n') || exit 85
[ "$(wc -l < "$READY" | tr -d ' \t\r\n')" = 8 ] \
    && [ "$(field "$READY" schema)" = dcentos.test.s19k-j0-ready/v1 ] \
    && [ "$(field "$READY" nonce)" = "$NONCE" ] \
    && [ "$(field "$READY" owner_sha256)" = "$OWNER_SHA" ] \
    && [ "$(field "$READY" owner_bytes)" = "$OWNER_BYTES" ] \
    && [ "$(field "$READY" runner_pid)" = "$RUNNER_PID" ] \
    && [ "$(field "$READY" runner_start)" = "$RUNNER_START" ] \
    && [ "$(field "$READY" stock_pid)" = "$STOCK_PID" ] \
    && [ "$(field "$READY" stock_start)" = "$STOCK_START" ] || exit 86
[ "$(process_start "$RUNNER_PID")" = "$RUNNER_START" ] || exit 86
[ "$(process_start "$STOCK_PID")" = "$STOCK_START" ] || exit 86

TRIGGER=$PROTOCOL/trigger
{
    printf 'schema=dcentos.test.s19k-j0-trigger/v1\n'
    printf 'nonce=%s\nowner_sha256=%s\nowner_bytes=%s\n' "$NONCE" "$OWNER_SHA" "$OWNER_BYTES"
    printf 'runner_pid=%s\nrunner_start=%s\nstock_pid=%s\nstock_start=%s\n' "$RUNNER_PID" "$RUNNER_START" "$STOCK_PID" "$STOCK_START"
    printf 'action=kill-stock-after-j0\n'
} > "$TRIGGER.tmp" || exit 87
mv "$TRIGGER.tmp" "$TRIGGER" || exit 87

wait "$RUNNER_PID" 2>/dev/null
RUNNER_RC=$?
wait "$STOCK_PID" 2>/dev/null || true
[ "$RUNNER_RC" -eq 97 ] || exit 88
[ ! -r "/proc/$RUNNER_PID/stat" ] && [ ! -r "/proc/$STOCK_PID/stat" ] || exit 88
ACK=$PROTOCOL/ack
[ "$(wc -l < "$ACK" | tr -d ' \t\r\n')" = 9 ] \
    && [ "$(field "$ACK" schema)" = dcentos.test.s19k-j0-signal/v1 ] \
    && [ "$(field "$ACK" status)" = signal-committed ] \
    && [ "$(field "$ACK" nonce)" = "$NONCE" ] \
    && [ "$(field "$ACK" owner_sha256)" = "$OWNER_SHA" ] \
    && [ "$(field "$ACK" owner_bytes)" = "$OWNER_BYTES" ] \
    && [ "$(field "$ACK" runner_pid)" = "$RUNNER_PID" ] \
    && [ "$(field "$ACK" runner_start)" = "$RUNNER_START" ] \
    && [ "$(field "$ACK" stock_pid)" = "$STOCK_PID" ] \
    && [ "$(field "$ACK" stock_start)" = "$STOCK_START" ] || exit 89
{
    printf 'schema=dcentos.test.s19k-j0-reaped/v1\n'
    printf 'nonce=%s\nrunner_pid=%s\nrunner_start=%s\n' "$NONCE" "$RUNNER_PID" "$RUNNER_START"
    printf 'stock_pid=%s\nstock_start=%s\nrunner_terminal=true\nstock_terminal=true\n' "$STOCK_PID" "$STOCK_START"
} > "$PROTOCOL/reaped"
exact_signal "$WATCHDOG_PID" "$WATCHDOG_START" 9 || exit 89
wait "$WATCHDOG_PID" 2>/dev/null || true
exit "$RUNNER_RC"
""",
                    encoding="utf-8",
                    newline="\n",
                )
                audit = temp / "startup_loss_audit.sh"
                audit.write_text(
                    """#!/bin/sh
set -u
PROTOCOL=${DCENT_TEST_PROTOCOL:?}
OWNER=${DCENT_TEST_OWNER:?}
process_start() {
    TEST_STAT=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
    TEST_REST=${TEST_STAT##*) }
    set -- $TEST_REST
    [ "$#" -ge 20 ] || return 1
    printf '%s' "${20}"
}
"""
                    + "for TEST_NAME in "
                    + " ".join(protocol_names)
                    + "; do\n"
                    + "    TEST_PATH=$PROTOCOL/$TEST_NAME\n"
                    + "    if [ -f \"$TEST_PATH\" ]; then\n"
                    + "        printf 'FILE %s\\n' \"$TEST_NAME\"\n"
                    + "        cat \"$TEST_PATH\"\n"
                    + "    fi\n"
                    + "done\n"
                    + "if [ -f \"$OWNER\" ]; then\n"
                    + "    printf 'OWNER '; sha256sum \"$OWNER\"\n"
                    + "    printf 'OWNER_BYTES='; wc -c < \"$OWNER\"\n"
                    + "    sed -n '1p' \"$OWNER\"\n"
                    + "else\n"
                    + "    echo OWNER_ABSENT\n"
                    + "fi\n"
                    + "for TEST_KIND in controller probe runner stock; do\n"
                    + "    TEST_PATH=$PROTOCOL/${TEST_KIND}_lifetime\n"
                    + "    if [ -f \"$TEST_PATH\" ]; then\n"
                    + "        TEST_LIFETIME=$(cat \"$TEST_PATH\")\n"
                    + "        TEST_PID=${TEST_LIFETIME%%:*}\n"
                    + "        TEST_START=${TEST_LIFETIME#*:}\n"
                    + "        TEST_CURRENT=$(process_start \"$TEST_PID\" || true)\n"
                    + "        printf '%s_EXPECTED=%s:%s CURRENT_START=%s\\n' \"$TEST_KIND\" \"$TEST_PID\" \"$TEST_START\" \"$TEST_CURRENT\"\n"
                    + "    fi\n"
                    + "done\n",
                    encoding="utf-8",
                    newline="\n",
                )
                subprocess.run(["wsl.exe", "mkdir", protocol_dir], check=True)
                subprocess.run(
                    ["wsl.exe", "cp", self._shell_path(controller), remote_controller],
                    check=True,
                )
                subprocess.run(
                    ["wsl.exe", "cp", self._shell_path(command), remote_command], check=True
                )
                subprocess.run(
                    ["wsl.exe", "cp", self._shell_path(audit), remote_audit], check=True
                )
                subprocess.run(
                    ["wsl.exe", "chmod", "700", remote_controller, remote_audit], check=True
                )
                subprocess.run(
                    ["wsl.exe", "chmod", "600", remote_command], check=True
                )
                protocol_stdout = temp / "startup_protocol.stdout"
                protocol_stderr = temp / "startup_protocol.stderr"

                def protocol_audit() -> str:
                    try:
                        audited = subprocess.run(
                            [
                                "wsl.exe",
                                "env",
                                "-i",
                                "PATH=/usr/bin:/bin",
                                f"DCENT_TEST_PROTOCOL={protocol_dir}",
                                f"DCENT_TEST_OWNER={runtime_lock}/owner",
                                remote_audit,
                            ],
                            text=True,
                            capture_output=True,
                            timeout=20,
                        )
                        return f"audit_rc={audited.returncode} audit={audited.stdout!r} audit_err={audited.stderr!r}"
                    except subprocess.TimeoutExpired as audit_timeout:
                        return f"audit_timeout={audit_timeout!r}"

                with protocol_stdout.open("w", encoding="utf-8") as out, protocol_stderr.open(
                    "w", encoding="utf-8"
                ) as err:
                    try:
                        launched = subprocess.run(
                            [
                                "wsl.exe",
                                "env",
                                "-i",
                                "PATH=/usr/bin:/bin",
                                f"DCENT_TEST_PROTOCOL={protocol_dir}",
                                f"DCENT_TEST_NONCE={protocol_nonce}",
                                f"DCENT_TEST_STOCK={remote_dir}/bosminer",
                                f"DCENT_TEST_OWNER={runtime_lock}/owner",
                                f"DCENT_TEST_COMMAND={remote_command}",
                                remote_controller,
                            ],
                            text=True,
                            stdout=out,
                            stderr=err,
                            timeout=200,
                        )
                    except subprocess.TimeoutExpired as launch_timeout:
                        out.flush()
                        err.flush()
                        self.fail(
                            f"controller timeout={launch_timeout!r} "
                            f"stdout={protocol_stdout.read_text(encoding='utf-8')!r} "
                            f"stderr={protocol_stderr.read_text(encoding='utf-8')!r} "
                            f"{protocol_audit()}"
                        )
                protocol_output = (
                    f"stdout={protocol_stdout.read_text(encoding='utf-8')!r} "
                    f"stderr={protocol_stderr.read_text(encoding='utf-8')!r}"
                )
                self.assertEqual(
                    launched.returncode,
                    97,
                    msg=f"{protocol_output} {protocol_audit()}",
                )
                self.assertIn(
                    "status=signal-committed",
                    subprocess.check_output(["wsl.exe", "cat", f"{protocol_dir}/ack"], text=True),
                )
                self.assertIn(
                    "stock_terminal=true",
                    subprocess.check_output(["wsl.exe", "cat", f"{protocol_dir}/reaped"], text=True),
                )
                subprocess.run(
                    ["wsl.exe", "rm", "-f", *(f"{protocol_dir}/{name}" for name in protocol_names)],
                    check=True,
                )
                subprocess.run(["wsl.exe", "rmdir", protocol_dir], check=True)
                subprocess.run(
                    ["wsl.exe", "rm", "-f", remote_controller, remote_command, remote_audit],
                    check=True,
                )
                self.assertEqual(
                    subprocess.run(["wsl.exe", "test", "-f", f"{runtime_lock}/owner"]).returncode,
                    0,
                )
                self.assertIn(
                    "schema=dcentos.s19k-startup-j0-prefork/v1",
                    subprocess.check_output(["wsl.exe", "cat", f"{runtime_lock}/owner"], text=True),
                )

                # Remove the exact captured stock tree, leaving the immutable
                # J0 tuple as historical custody evidence. Global all-thread
                # scans also see no stock owner.
                subprocess.run(
                    [
                        "wsl.exe",
                        "rm",
                        "-f",
                        f"{remote_dir}/live_identity_fixture/bosminer.pid",
                        f"{remote_dir}/live_identity_fixture/proc/1458/stat",
                        f"{remote_dir}/live_identity_fixture/proc/1458/comm",
                        f"{remote_dir}/live_identity_fixture/proc/1458/cmdline",
                        f"{remote_dir}/live_identity_fixture/proc/1458/exe",
                        f"{remote_dir}/live_identity_fixture/proc/9495/stat",
                        f"{remote_dir}/live_identity_fixture/proc/9495/comm",
                        f"{remote_dir}/live_identity_fixture/proc/9495/cmdline",
                        f"{remote_dir}/live_identity_fixture/proc/9495/exe",
                    ],
                    check=True,
                )
                restore_argv = [
                    f"{remote_dir}/run_trial",
                    "restore",
                    remote_dir,
                    "am3-s19k",
                    "recovery",
                    *args,
                ]

                def restore() -> subprocess.CompletedProcess[str]:
                    try:
                        return subprocess.run(
                            ["wsl.exe", "sh", *restore_argv],
                            text=True,
                            capture_output=True,
                            # The production restore path has one bounded 60x1s
                            # exact-child exit fence.  Reserve another 30s for
                            # three-attempt all-task scans, native publication,
                            # and the WSL boundary used by this offline fixture.
                            timeout=90,
                        )
                    except subprocess.TimeoutExpired as error:
                        def timeout_text(value: str | bytes | None) -> str:
                            if value is None:
                                return ""
                            if isinstance(value, bytes):
                                return value.decode("utf-8", errors="replace")
                            return value

                        timeout_paths = (
                            f"{remote_dir}/runtime_startup_prefix_pre_safeoff",
                            f"{remote_dir}/runtime_safeoff_terminal_receipt",
                            f"{remote_dir}/runtime_active",
                            f"{runtime_lock}/owner",
                        )
                        quoted_paths = " ".join(shlex.quote(path) for path in timeout_paths)
                        audit_script = (
                            "proc_start() { "
                            "[ -r \"/proc/$1/stat\" ] || return 1; "
                            "S=$(cat \"/proc/$1/stat\") || return 1; "
                            "R=${S##*) }; set -- $R; shift 19; printf '%s' \"${1:-}\"; }; "
                            f"for P in {quoted_paths} "
                            f"{shlex.quote(remote_dir)}/.runtime_startup_prefix_pre_safeoff.completed.* "
                            f"{shlex.quote(remote_dir)}/.runtime_safeoff_terminal_receipt*.completed.*; do "
                            "[ -e \"$P\" ] || [ -L \"$P\" ] || continue; "
                            "printf 'path=%s\\n' \"$P\"; ls -ldni \"$P\" 2>&1; "
                            "if [ -f \"$P\" ] && [ ! -L \"$P\" ]; then "
                            "printf 'sha256='; sha256sum \"$P\" | awk '{print $1}'; "
                            "printf 'bytes='; wc -c < \"$P\" | tr -d ' \\t\\r\\n'; printf '\\n'; "
                            "sed -n 's/^schema=/schema=/p; s/^wrapper_pid=/pid=wrapper:/p; "
                            "s/^wrapper_start=/start=wrapper:/p; s/^writer_wrapper_pid=/pid=writer_wrapper:/p; "
                            "s/^writer_wrapper_start=/start=writer_wrapper:/p; s/^daemon_pid=/pid=daemon:/p; "
                            "s/^daemon_start=/start=daemon:/p' \"$P\"; fi; done; "
                            f"for R in {quoted_paths}; do "
                            "[ -f \"$R\" ] && [ ! -L \"$R\" ] || continue; "
                            "for ROLE in wrapper writer_wrapper daemon; do "
                            "PID=$(sed -n \"s/^${ROLE}_pid=//p\" \"$R\"); "
                            "START=$(sed -n \"s/^${ROLE}_start=//p\" \"$R\"); "
                            "[ -n \"$PID\" ] && [ -n \"$START\" ] || continue; "
                            "NOW=$(proc_start \"$PID\" 2>/dev/null || true); "
                            "printf 'lifetime=%s:%s expected_start=%s current_start=%s exact=%s\\n' "
                            "\"$ROLE\" \"$PID\" \"$START\" \"${NOW:-absent}\" "
                            "\"$([ \"$NOW\" = \"$START\" ] && printf true || printf false)\"; done; done"
                        )
                        audit = subprocess.run(
                            ["wsl.exe", "sh", "-c", audit_script],
                            text=True,
                            capture_output=True,
                            timeout=20,
                        )
                        timeout_audit = temp / "restore_timeout_diagnostics.txt"
                        timeout_audit.write_text(
                            "stdout:\n"
                            + timeout_text(error.stdout)
                            + "\nstderr:\n"
                            + timeout_text(error.stderr)
                            + "\nstate_stdout:\n"
                            + audit.stdout
                            + "\nstate_stderr:\n"
                            + audit.stderr,
                            encoding="utf-8",
                            newline="\n",
                        )
                        raise

                def fields(path: str) -> dict[str, str]:
                    rows = subprocess.check_output(["wsl.exe", "cat", path], text=True).splitlines()
                    result: dict[str, str] = {}
                    for row in rows:
                        key, value = row.split("=", 1)
                        self.assertNotIn(key, result)
                        result[key] = value
                    return result

                def rust_keys(name: str, count: int) -> list[str]:
                    serial_source = (
                        ROOT / "dcentrald" / "dcentrald" / "src" / "serial_mining.rs"
                    ).read_text(encoding="utf-8")
                    match = re.search(
                        rf"const {name}: \[&str; {count}\] = \[(.*?)\];",
                        serial_source,
                        flags=re.DOTALL,
                    )
                    self.assertIsNotNone(match)
                    keys = re.findall(r'"([a-z0-9_]+)"', match.group(1))
                    self.assertEqual(len(keys), count)
                    return keys

                def write_record(path: str, keys: list[str], values: dict[str, str]) -> None:
                    self.assertEqual(set(keys), set(values))
                    local_record = temp / f"record_{Path(path).name}"
                    local_record.write_text(
                        "".join(f"{key}={values[key]}\n" for key in keys),
                        encoding="utf-8",
                        newline="\n",
                    )
                    subprocess.run(
                        ["wsl.exe", "cp", self._shell_path(local_record), path],
                        check=True,
                    )
                    subprocess.run(["wsl.exe", "chmod", "600", path], check=True)

                source_path = f"{remote_dir}/runtime_startup_prefix_pre_safeoff"
                zero_source_scratch = (
                    f"{remote_dir}/.runtime_startup_prefix_pre_safeoff.tmp.999991.1"
                )
                partial_source_scratch = (
                    f"{remote_dir}/.runtime_startup_prefix_pre_safeoff.tmp.999992.1"
                )
                postlink_source_scratch = (
                    f"{remote_dir}/.runtime_startup_prefix_pre_safeoff.tmp.999993.1"
                )
                copied_source_scratch = (
                    f"{remote_dir}/.runtime_startup_prefix_pre_safeoff.tmp.999994.1"
                )
                subprocess.run(
                    [
                        "wsl.exe",
                        "sh",
                        "-c",
                        f": > {shlex.quote(zero_source_scratch)}; "
                        f"printf 'schema=dcentos.s19k-startup-prefix-safeoff-source/v1\\n' > {shlex.quote(partial_source_scratch)}; "
                        f"chmod 600 {shlex.quote(zero_source_scratch)} {shlex.quote(partial_source_scratch)}",
                    ],
                    check=True,
                )
                first = restore()
                self.assertNotEqual(first.returncode, 0)
                self.assertIn(
                    "recovery source deploy mode is unavailable",
                    first.stderr,
                )
                for prelink_scratch in (zero_source_scratch, partial_source_scratch):
                    self.assertNotEqual(
                        subprocess.run(
                            ["wsl.exe", "test", "-e", prelink_scratch], capture_output=True
                        ).returncode,
                        0,
                        prelink_scratch,
                    )
                subprocess.run(
                    ["wsl.exe", "cp", source_path, copied_source_scratch], check=True
                )
                subprocess.run(["wsl.exe", "chmod", "600", copied_source_scratch], check=True)
                copied_source_refusal = restore()
                self.assertNotEqual(copied_source_refusal.returncode, 0)
                self.assertNotIn("exact stock-restart helper", copied_source_refusal.stderr)
                self.assertEqual(
                    subprocess.run(
                        ["wsl.exe", "test", "-f", copied_source_scratch], capture_output=True
                    ).returncode,
                    0,
                )
                subprocess.run(["wsl.exe", "rm", "-f", copied_source_scratch], check=True)
                subprocess.run(
                    ["wsl.exe", "ln", source_path, postlink_source_scratch], check=True
                )
                pending_zero_scratch = (
                    f"{remote_dir}/.runtime_active_startup_prefix_stock_restart_pending.tmp.999996.1"
                )
                owner_partial_scratch = (
                    f"{remote_dir}/.runtime_owner_startup_prefix_stock_restart_pending.tmp.999997.1"
                )
                subprocess.run(
                    [
                        "wsl.exe",
                        "sh",
                        "-c",
                        f": > {shlex.quote(pending_zero_scratch)}; "
                        f"printf 'schema=dcentos.s19k-track1-runtime-lock/v10\\n' > {shlex.quote(owner_partial_scratch)}; "
                        f"chmod 600 {shlex.quote(pending_zero_scratch)} {shlex.quote(owner_partial_scratch)}",
                    ],
                    check=True,
                )
                first_replay = restore()
                self.assertNotEqual(first_replay.returncode, 0)
                self.assertIn("exact stock-restart helper", first_replay.stderr)
                for retired_transition_path in (
                    postlink_source_scratch,
                    pending_zero_scratch,
                    owner_partial_scratch,
                ):
                    self.assertNotEqual(
                        subprocess.run(
                            ["wsl.exe", "test", "-e", retired_transition_path],
                            capture_output=True,
                        ).returncode,
                        0,
                        retired_transition_path,
                    )
                active = fields(f"{remote_dir}/runtime_active")
                owner = fields(f"{runtime_lock}/owner")
                source_receipt = fields(f"{remote_dir}/runtime_startup_prefix_pre_safeoff")
                self.assertEqual(active["schema"], "dcentos.s19k-startup-prefix-stock-restart-pending/v1")
                self.assertEqual(owner["schema"], "dcentos.s19k-track1-runtime-lock/v10")
                self.assertEqual(source_receipt["highest_phase"], "j0")
                self.assertEqual(source_receipt["preserved_owner_present"], "true")
                self.assertEqual(
                    source_receipt["owner_path"],
                    f"{remote_dir}/runtime_startup_owner_pre_safeoff",
                )
                self.assertEqual(
                    source_receipt["owner_sha256"],
                    source_receipt["preserved_owner_sha256"],
                )
                self.assertEqual(source_receipt["active_present"], "false")
                self.assertEqual(source_receipt["active_path"], "none")
                active_path = f"{remote_dir}/runtime_active"
                owner_path = f"{runtime_lock}/owner"

                # The ordinary publisher removes its source scratch, so the
                # normal N2 path usually has no guarded completion sentinel.
                # Durable ACTIVE then OWNER publication must still have run.
                no_completion = subprocess.run(
                    [
                        "wsl.exe",
                        "sh",
                        "-c",
                        f"for P in {shlex.quote(remote_dir)}/.runtime_startup_prefix_pre_safeoff.completed.* "
                        f"{shlex.quote(remote_dir)}/.runtime_safeoff_terminal_receipt*.completed.*; do "
                        '[ -e "$P" ] || [ -L "$P" ] || continue; exit 1; done; exit 0',
                    ],
                    capture_output=True,
                )
                self.assertEqual(no_completion.returncode, 0)

                # Once pending/v10 are durable, a native consumer failure after
                # unlink must not infer a phase from completion absence.  The
                # next restore advances only from the exact pending/v10 pair.
                consume_fault_scratch = (
                    f"{remote_dir}/.runtime_startup_prefix_pre_safeoff.tmp.999990.1"
                )
                consume_fault_completion = (
                    f"{remote_dir}/.runtime_startup_prefix_pre_safeoff.completed.999990.1"
                )
                subprocess.run(
                    ["wsl.exe", "ln", source_path, consume_fault_scratch], check=True
                )
                subprocess.run(
                    [
                        "wsl.exe",
                        "sh",
                        "-c",
                        f": > {shlex.quote(remote_dir + '/guarded_consume_fault')}; "
                        f"chmod 600 {shlex.quote(remote_dir + '/guarded_consume_fault')}",
                    ],
                    check=True,
                )
                consume_fault = restore()
                self.assertNotEqual(consume_fault.returncode, 0)
                self.assertNotIn("exact stock-restart helper", consume_fault.stderr)
                for consumed_path in (
                    consume_fault_scratch,
                    consume_fault_completion,
                    f"{remote_dir}/guarded_consume_fault",
                ):
                    self.assertNotEqual(
                        subprocess.run(
                            ["wsl.exe", "test", "-e", consumed_path], capture_output=True
                        ).returncode,
                        0,
                        consumed_path,
                    )
                self.assertEqual(
                    fields(active_path)["schema"],
                    "dcentos.s19k-startup-prefix-stock-restart-pending/v1",
                )
                self.assertEqual(
                    fields(owner_path)["schema"], "dcentos.s19k-track1-runtime-lock/v10"
                )
                consume_fault_replay = restore()
                self.assertNotEqual(consume_fault_replay.returncode, 0)
                self.assertIn("exact stock-restart helper", consume_fault_replay.stderr)

                # Replay the three monotonic crash suffixes. Each restore must
                # converge to the same final v10 authority without guessing:
                # source-only, source+SafeOff, then pending ACTIVE+old J0 OWNER.
                preserved_owner = f"{remote_dir}/runtime_startup_owner_pre_safeoff"
                safeoff = f"{remote_dir}/runtime_safeoff_terminal_receipt"

                for cut in ("source-only", "safeoff", "active-before-owner"):
                    subprocess.run(["wsl.exe", "rm", "-f", owner_path], check=True)
                    subprocess.run(["wsl.exe", "ln", preserved_owner, owner_path], check=True)
                    if cut == "source-only":
                        subprocess.run(["wsl.exe", "rm", "-f", safeoff, active_path], check=True)
                        for gpio, value in ((437, 0), (454, 0), (455, 1), (456, 1)):
                            subprocess.run(
                                [
                                    "wsl.exe",
                                    "sh",
                                    "-c",
                                    f"printf '{value}\\n' > {shlex.quote(remote_dir + f'/live_identity_fixture/gpio/gpio{gpio}/value')}",
                                ],
                                check=True,
                            )
                    elif cut == "safeoff":
                        subprocess.run(["wsl.exe", "rm", "-f", active_path], check=True)
                        self.assertEqual(
                            subprocess.run(["wsl.exe", "test", "-f", safeoff]).returncode,
                            0,
                        )
                    else:
                        self.assertEqual(
                            fields(active_path)["schema"],
                            "dcentos.s19k-startup-prefix-stock-restart-pending/v1",
                        )
                    resumed = restore()
                    self.assertNotEqual(resumed.returncode, 0, cut)
                    self.assertEqual(
                        fields(owner_path)["schema"],
                        "dcentos.s19k-track1-runtime-lock/v10",
                        cut,
                    )
                    self.assertEqual(fields(active_path)["source_receipt_path"], source_path)

                # Build exact synthetic post-J1 prefixes without pretending a
                # shell fixture is the synchronous Rust bootstrap.  The
                # unmodified restore path must preserve ACTIVE before replacing
                # it, and must reject value corruption even when every outer
                # source -> pending -> owner digest is recomputed.
                c1_keys = rust_keys("S19K_C1_KEYS", 47)
                j1_j2_keys = rust_keys("S19K_J1_J2_KEYS", 87)
                release_keys = rust_keys("S19K_RELEASE_KEYS", 30)
                terminal_keys = (
                    "schema transaction_id phase highest_phase owner_sha256 owner_bytes "
                    "c1_sha256 c1_bytes j1_sha256 j1_bytes active_sha256 active_bytes "
                    "j2_sha256 j2_bytes release_sha256 release_bytes parent_lost_sha256 "
                    "parent_lost_bytes fifo_path fifo_mnt_id fifo_inode transcript_path "
                    "transcript_mnt_id transcript_inode transcript_mode transcript_uid "
                    "transcript_gid transcript_sha256 transcript_bytes supervisor_pid "
                    "supervisor_start supervisor_ppid supervisor_pgrp supervisor_session "
                    "supervisor_exe supervisor_cmdline_sha256 supervisor_cmdline_bytes "
                    "bosminer_pid bosminer_start bosminer_ppid bosminer_pgrp bosminer_session "
                    "bosminer_exe bosminer_cmdline_sha256 bosminer_cmdline_bytes "
                    "stock_pidfile_path stock_pidfile_sha256 stock_pidfile_bytes binary_sha256 "
                    "binary_bytes config_sha256 config_bytes runner_sha256 runner_bytes "
                    "custody_observer_sha256 custody_observer_bytes stock_restart_helper_sha256 "
                    "stock_restart_helper_bytes live_identity_profile live_identity_sha256 "
                    "watchdog_start_intent watchdog_armed signal_attempted inherited_rails "
                    "route_or_uart_opened hardware_opened stock_tree_revalidated "
                    "live_identity_revalidated gpio_raw gpio_stock_baseline_revalidated "
                    "gpio437_engaged dcentrald_all_threads_absent watchdog_all_threads_absent "
                    "persistent_mutation publication"
                ).split()
                self.assertEqual(len(terminal_keys), 75)
                active_keys = (
                    "schema phase wrapper_pid wrapper_start child_pid child_start "
                    "supervisor_pid supervisor_start supervisor_ppid supervisor_pgrp "
                    "supervisor_session supervisor_exe supervisor_cmdline_sha256 "
                    "supervisor_cmdline_bytes bosminer_pid bosminer_start bosminer_ppid "
                    "bosminer_pgrp bosminer_session bosminer_exe bosminer_cmdline_sha256 "
                    "bosminer_cmdline_bytes stock_pidfile_path stock_pidfile_sha256 "
                    "stock_pidfile_bytes binary_sha256 binary_bytes config_sha256 "
                    "config_bytes runner_sha256 runner_bytes custody_observer_sha256 "
                    "custody_observer_bytes stock_restart_helper_sha256 "
                    "stock_restart_helper_bytes live_identity_schema live_identity_profile "
                    "live_identity_sha256 deploy_mode persistent_mutation"
                ).split()
                self.assertEqual(len(active_keys), 40)

                def remote_tuple(path: str) -> tuple[str, str]:
                    blob = subprocess.check_output(["wsl.exe", "cat", path])
                    return hashlib.sha256(blob).hexdigest(), str(len(blob))

                j0 = fields(preserved_owner)
                base_source = source_receipt
                j0_sha, j0_bytes = remote_tuple(preserved_owner)
                child_pid = "424242"
                child_start = "242424"
                no_effect = {
                    key: "false"
                    for key in (
                        "watchdog_start_intent",
                        "watchdog_armed",
                        "signal_attempted",
                        "inherited_rails",
                        "route_or_uart_opened",
                        "hardware_opened",
                        "parent_release",
                        "persistent_mutation",
                    )
                }
                c1 = {
                    "schema": "dcentos.s19k-startup-c1-child-identity/v1",
                    "transaction_id": j0["transaction_id"],
                    "ordinal": "1",
                    "predecessor_schema": "dcentos.s19k-startup-j0-prefork/v1",
                    "predecessor_sha256": j0_sha,
                    "predecessor_bytes": j0_bytes,
                    "runtime_owner_path": owner_path,
                    "runtime_owner_sha256": j0_sha,
                    "runtime_owner_bytes": j0_bytes,
                    "child_pid": child_pid,
                    "child_start": child_start,
                    "child_ppid": j0["wrapper_pid"],
                    "child_comm": "dcentrald",
                    "child_exe": f"{remote_dir}/dcentrald",
                    "child_cmdline_sha256": j0["expected_daemon_cmdline_sha256"],
                    "child_cmdline_bytes": j0["expected_daemon_cmdline_bytes"],
                    "child_environment_sha256": j0["daemon_environment_sha256"],
                    "child_environment_bytes": j0["daemon_environment_bytes"],
                    "child_environment_count": "10",
                    "bootstrap_fd_set": "stdio-only",
                    "stdin_path": "/dev/null",
                    "transcript_path": base_source["transcript_path"],
                    "transcript_mnt_id": base_source["transcript_mnt_id"],
                    "transcript_inode": base_source["transcript_inode"],
                    "transcript_mode": "0600",
                    "transcript_uid": "0",
                    "transcript_gid": "0",
                    "wrapper_pid": j0["wrapper_pid"],
                    "wrapper_start": j0["wrapper_start"],
                    "wrapper_ppid": j0["wrapper_ppid"],
                    "wrapper_comm": j0["wrapper_comm"],
                    "wrapper_exe": j0["wrapper_exe"],
                    "wrapper_cmdline_sha256": j0["wrapper_cmdline_sha256"],
                    "wrapper_cmdline_bytes": j0["wrapper_cmdline_bytes"],
                    "binary_sha256": j0["binary_sha256"],
                    "binary_bytes": j0["binary_bytes"],
                    "pdeathsig": "9",
                    "pdeathsig_scope": "process-lifetime",
                    **no_effect,
                    "publication": "no-clobber-hard-link-after-fsync",
                }
                c1_content = "".join(f"{key}={c1[key]}\n" for key in c1_keys).encode()
                c1_sha = hashlib.sha256(c1_content).hexdigest()
                c1_bytes = str(len(c1_content))
                j1 = {
                    "schema": "dcentos.s19k-startup-j1-daemon-blocked/v1",
                    "transaction_id": j0["transaction_id"],
                    "ordinal": "2",
                    "predecessor_schema": "dcentos.s19k-startup-c1-child-identity/v1",
                    "predecessor_sha256": c1_sha,
                    "predecessor_bytes": c1_bytes,
                    "trial_dir": remote_dir,
                    "runtime_active_path": "not-published",
                    "runtime_active_sha256": "none",
                    "runtime_active_bytes": "0",
                    "runtime_active_phase": "not-published",
                    "runtime_owner_path": owner_path,
                    "runtime_owner_sha256": j0_sha,
                    "runtime_owner_bytes": j0_bytes,
                    "writer_role": "daemon-blocked",
                    "writer_pid": child_pid,
                    "writer_start": child_start,
                    "writer_ppid": j0["wrapper_pid"],
                    "daemon_pid": child_pid,
                    "daemon_start": child_start,
                    "wrapper_pid": j0["wrapper_pid"],
                    "wrapper_start": j0["wrapper_start"],
                    "wrapper_ppid": j0["wrapper_ppid"],
                    "wrapper_comm": j0["wrapper_comm"],
                    "wrapper_exe": j0["wrapper_exe"],
                    "wrapper_cmdline_sha256": j0["wrapper_cmdline_sha256"],
                    "wrapper_cmdline_bytes": j0["wrapper_cmdline_bytes"],
                    "pdeathsig": "9",
                    "pdeathsig_scope": "process-lifetime",
                    "fifo_path": j0["fifo_path"],
                    "fifo_mnt_id": j0["fifo_mnt_id"],
                    "fifo_inode": j0["fifo_inode"],
                    "fifo_mode": j0["fifo_mode"],
                    "fifo_uid": j0["fifo_uid"],
                    "fifo_gid": j0["fifo_gid"],
                    "fifo_reader_held": "true",
                    "bootstrap_fd_set": "stdio-plus-single-fifo",
                    "fifo_reader_fd": "3",
                    "stdin_path": "/dev/null",
                    "transcript_path": base_source["transcript_path"],
                    "transcript_mnt_id": base_source["transcript_mnt_id"],
                    "transcript_inode": base_source["transcript_inode"],
                    "transcript_mode": "0600",
                    "transcript_uid": "0",
                    "transcript_gid": "0",
                    **{key: j0[key] for key in (
                        "supervisor_pid", "supervisor_start", "supervisor_ppid",
                        "supervisor_pgrp", "supervisor_session", "supervisor_exe",
                        "supervisor_cmdline_sha256", "supervisor_cmdline_bytes",
                        "bosminer_pid", "bosminer_start", "bosminer_ppid", "bosminer_pgrp",
                        "bosminer_session", "bosminer_exe", "bosminer_cmdline_sha256",
                        "bosminer_cmdline_bytes", "stock_pidfile_path", "stock_pidfile_sha256",
                        "stock_pidfile_bytes", "binary_sha256", "binary_bytes", "config_sha256",
                        "config_bytes", "runner_sha256", "runner_bytes",
                        "custody_observer_sha256", "custody_observer_bytes",
                        "stock_restart_helper_sha256", "stock_restart_helper_bytes",
                        "live_identity_schema", "live_identity_profile", "live_identity_sha256",
                        "gpio_raw",
                    )},
                    **no_effect,
                    "publication": "no-clobber-hard-link-after-fsync",
                }
                j1_content = "".join(f"{key}={j1[key]}\n" for key in j1_j2_keys).encode()
                j1_sha = hashlib.sha256(j1_content).hexdigest()
                j1_bytes = str(len(j1_content))
                active_record = {
                    "schema": "dcentos.s19k-tmp-runtime/v5",
                    "phase": "child-live-or-recovery-required",
                    "wrapper_pid": j0["wrapper_pid"],
                    "wrapper_start": j0["wrapper_start"],
                    "child_pid": child_pid,
                    "child_start": child_start,
                    **{key: j0[key] for key in active_keys if key in j0 and key != "schema"},
                    "live_identity_schema": "dcentos.s19k-braiins-live-identity/v2",
                    "deploy_mode": "mining-on-passthrough",
                    "persistent_mutation": "false",
                }

                synthetic_paths = {
                    "c1": f"{remote_dir}/runtime_startup_c1_child_identity",
                    "j1": f"{remote_dir}/runtime_startup_j1_daemon_blocked",
                    "j2": f"{remote_dir}/runtime_startup_j2_child_bound",
                    "release": f"{remote_dir}/runtime_startup_release",
                    "terminal": f"{remote_dir}/runtime_startup_retired_terminal",
                    "preserved_active": f"{remote_dir}/runtime_startup_active_pre_safeoff",
                }
                for highest in ("j0", "active", "j2", "release"):
                    subprocess.run(
                        [
                            "wsl.exe", "rm", "-f", source_path, safeoff, active_path,
                            synthetic_paths["c1"], synthetic_paths["j1"], synthetic_paths["j2"],
                            synthetic_paths["release"], synthetic_paths["terminal"],
                            synthetic_paths["preserved_active"], owner_path,
                        ],
                        check=True,
                    )
                    subprocess.run(["wsl.exe", "ln", preserved_owner, owner_path], check=True)
                    for gpio, value in ((437, 0), (454, 0), (455, 1), (456, 1)):
                        subprocess.run(
                            ["wsl.exe", "sh", "-c", f"printf '{value}\\n' > {shlex.quote(remote_dir + f'/live_identity_fixture/gpio/gpio{gpio}/value')}"],
                            check=True,
                        )
                    active_sha, active_bytes = "none", "0"
                    if highest != "j0":
                        write_record(synthetic_paths["c1"], c1_keys, c1)
                        write_record(synthetic_paths["j1"], j1_j2_keys, j1)
                        write_record(active_path, active_keys, active_record)
                        active_sha, active_bytes = remote_tuple(active_path)
                    j2 = dict(j1)
                    j2.update(
                        schema="dcentos.s19k-startup-j2-child-bound/v1",
                        ordinal="3",
                        predecessor_schema="dcentos.s19k-startup-j1-daemon-blocked/v1",
                        predecessor_sha256=j1_sha,
                        predecessor_bytes=j1_bytes,
                        runtime_active_path=active_path,
                        runtime_active_sha256=active_sha,
                        runtime_active_bytes=active_bytes,
                        runtime_active_phase="child-live-or-recovery-required",
                        writer_role="wrapper",
                        writer_pid=j0["wrapper_pid"],
                        writer_start=j0["wrapper_start"],
                        writer_ppid=j0["wrapper_ppid"],
                    )
                    self.assertEqual(j1["writer_ppid"], j0["wrapper_pid"])
                    self.assertEqual(j2["writer_ppid"], j0["wrapper_ppid"])
                    if highest in ("j2", "release"):
                        write_record(synthetic_paths["j2"], j1_j2_keys, j2)
                    if highest == "release":
                        j2_sha, j2_bytes = remote_tuple(synthetic_paths["j2"])
                        release = {
                            "schema": "dcentos.s19k-startup-release/v1",
                            "transaction_id": j0["transaction_id"],
                            "ordinal": "3-release",
                            "predecessor_schema": "dcentos.s19k-startup-j2-child-bound/v1",
                            "predecessor_sha256": j2_sha,
                            "predecessor_bytes": j2_bytes,
                            "runtime_active_sha256": active_sha,
                            "runtime_active_bytes": active_bytes,
                            "runtime_owner_sha256": j0_sha,
                            "runtime_owner_bytes": j0_bytes,
                            "daemon_pid": child_pid,
                            "daemon_start": child_start,
                            "wrapper_pid": j0["wrapper_pid"],
                            "wrapper_start": j0["wrapper_start"],
                            "wrapper_ppid": j0["wrapper_ppid"],
                            "wrapper_comm": j0["wrapper_comm"],
                            "wrapper_exe": j0["wrapper_exe"],
                            "wrapper_cmdline_sha256": j0["wrapper_cmdline_sha256"],
                            "wrapper_cmdline_bytes": j0["wrapper_cmdline_bytes"],
                            "pdeathsig": "9",
                            "pdeathsig_scope": "process-lifetime",
                            "gpio_raw": "437:0,454:0,455:1,456:1",
                            **{key: "false" for key in (
                                "watchdog_start_intent", "watchdog_armed", "signal_attempted",
                                "inherited_rails", "route_or_uart_opened", "hardware_opened",
                            )},
                            "parent_release": "true",
                            "publication": "no-clobber-hard-link-after-fsync",
                        }
                        write_record(synthetic_paths["release"], release_keys, release)

                    c1_pair = remote_tuple(synthetic_paths["c1"]) if highest != "j0" else ("none", "0")
                    j1_pair = remote_tuple(synthetic_paths["j1"]) if highest != "j0" else ("none", "0")
                    j2_pair = remote_tuple(synthetic_paths["j2"]) if highest in ("j2", "release") else ("none", "0")
                    release_pair = remote_tuple(synthetic_paths["release"]) if highest == "release" else ("none", "0")
                    terminal = {
                        "schema": "dcentos.s19k-startup-retired-terminal/v1",
                        "transaction_id": j0["transaction_id"],
                        "phase": "startup-no-effect-retired",
                        "highest_phase": highest,
                        "owner_sha256": j0_sha,
                        "owner_bytes": j0_bytes,
                        "c1_sha256": c1_pair[0],
                        "c1_bytes": c1_pair[1],
                        "j1_sha256": j1_pair[0],
                        "j1_bytes": j1_pair[1],
                        "active_sha256": active_sha,
                        "active_bytes": active_bytes,
                        "j2_sha256": j2_pair[0],
                        "j2_bytes": j2_pair[1],
                        "release_sha256": release_pair[0],
                        "release_bytes": release_pair[1],
                        "parent_lost_sha256": "none",
                        "parent_lost_bytes": "0",
                        "fifo_path": j0["fifo_path"],
                        "fifo_mnt_id": j0["fifo_mnt_id"],
                        "fifo_inode": j0["fifo_inode"],
                        **{key: base_source[key] for key in (
                            "transcript_path", "transcript_mnt_id", "transcript_inode",
                            "transcript_mode", "transcript_uid", "transcript_gid",
                            "transcript_sha256", "transcript_bytes",
                        )},
                        **{key: j0[key] for key in (
                            "supervisor_pid", "supervisor_start", "supervisor_ppid",
                            "supervisor_pgrp", "supervisor_session", "supervisor_exe",
                            "supervisor_cmdline_sha256", "supervisor_cmdline_bytes",
                            "bosminer_pid", "bosminer_start", "bosminer_ppid", "bosminer_pgrp",
                            "bosminer_session", "bosminer_exe", "bosminer_cmdline_sha256",
                            "bosminer_cmdline_bytes", "stock_pidfile_path", "stock_pidfile_sha256",
                            "stock_pidfile_bytes", "binary_sha256", "binary_bytes", "config_sha256",
                            "config_bytes", "runner_sha256", "runner_bytes",
                            "custody_observer_sha256", "custody_observer_bytes",
                            "stock_restart_helper_sha256", "stock_restart_helper_bytes",
                            "live_identity_profile", "live_identity_sha256",
                        )},
                        "watchdog_start_intent": "false",
                        "watchdog_armed": "false",
                        "signal_attempted": "false",
                        "inherited_rails": "false",
                        "route_or_uart_opened": "false",
                        "hardware_opened": "false",
                        "stock_tree_revalidated": "true",
                        "live_identity_revalidated": "true",
                        "gpio_raw": "437:0,454:0,455:1,456:1",
                        "gpio_stock_baseline_revalidated": "true",
                        "gpio437_engaged": "true",
                        "dcentrald_all_threads_absent": "true",
                        "watchdog_all_threads_absent": "true",
                        "persistent_mutation": "false",
                        "publication": "no-clobber-hard-link-after-fsync",
                    }
                    write_record(synthetic_paths["terminal"], terminal_keys, terminal)

                    transitioned = restore()
                    self.assertNotEqual(transitioned.returncode, 0, highest)
                    self.assertIn("exact stock-restart helper is required", transitioned.stderr, highest)
                    produced_source = fields(source_path)
                    produced_pending = fields(active_path)
                    produced_owner = fields(owner_path)
                    self.assertEqual(produced_source["highest_phase"], highest)
                    self.assertEqual(produced_source["owner_path"], preserved_owner)
                    if highest == "j0":
                        self.assertEqual(produced_source["active_present"], "false")
                        self.assertEqual(produced_source["active_path"], "none")
                    else:
                        self.assertEqual(produced_source["active_path"], synthetic_paths["preserved_active"])
                        self.assertEqual(produced_source["active_sha256"], produced_source["preserved_active_sha256"])
                        self.assertEqual(produced_source["active_bytes"], produced_source["preserved_active_bytes"])
                    transitioned_replay = restore()
                    self.assertNotEqual(transitioned_replay.returncode, 0, f"replay:{highest}")
                    self.assertIn(
                        "exact stock-restart helper",
                        transitioned_replay.stderr,
                        f"replay:{highest}",
                    )

                    # A later canonical retired-owner object is not part of the
                    # source transaction.  Pending replay must reject it even
                    # when the preserved owner and v10 authority remain exact.
                    subprocess.run(
                        [
                            "wsl.exe",
                            "sh",
                            "-c",
                            f"printf 'unbound-owner\\n' > {shlex.quote(f'{remote_dir}/runtime_lock_owner.retired.startup-no-effect')}",
                        ],
                        check=True,
                    )
                    subprocess.run(
                        [
                            "wsl.exe",
                            "chmod",
                            "600",
                            f"{remote_dir}/runtime_lock_owner.retired.startup-no-effect",
                        ],
                        check=True,
                    )
                    pending_owner_recurrence = restore()
                    self.assertNotEqual(pending_owner_recurrence.returncode, 0)
                    self.assertNotIn(
                        "exact stock-restart helper",
                        pending_owner_recurrence.stderr,
                        f"pending-retired-owner-recurrence:{highest}",
                    )
                    subprocess.run(
                        [
                            "wsl.exe",
                            "rm",
                            "-f",
                            f"{remote_dir}/runtime_lock_owner.retired.startup-no-effect",
                        ],
                        check=True,
                    )

                    if highest == "j0":
                        # The same recurrence is rejected before SafeOff/pending,
                        # with the exact J0 restored as current source authority.
                        subprocess.run(
                            ["wsl.exe", "rm", "-f", active_path, safeoff, owner_path],
                            check=True,
                        )
                        subprocess.run(["wsl.exe", "ln", preserved_owner, owner_path], check=True)
                        subprocess.run(
                            [
                                "wsl.exe",
                                "ln",
                                "-s",
                                "/dev/null",
                                f"{remote_dir}/runtime_lock_owner.retired.startup-no-effect",
                            ],
                            check=True,
                        )
                        source_owner_recurrence = restore()
                        self.assertNotEqual(source_owner_recurrence.returncode, 0)
                        self.assertNotIn(
                            "exact stock-restart helper", source_owner_recurrence.stderr
                        )
                        subprocess.run(
                            [
                                "wsl.exe",
                                "rm",
                                "-f",
                                f"{remote_dir}/runtime_lock_owner.retired.startup-no-effect",
                            ],
                            check=True,
                        )
                        resumed_after_owner_recurrence = restore()
                        self.assertNotEqual(resumed_after_owner_recurrence.returncode, 0)
                        self.assertIn(
                            "exact stock-restart helper",
                            resumed_after_owner_recurrence.stderr,
                        )

                    if highest == "active":
                        # With no terminal ancestry, an ACTIVE source still
                        # rejects a newly introduced retired historical object.
                        no_terminal_source = dict(produced_source)
                        no_terminal_pending = dict(produced_pending)
                        no_terminal_owner = dict(produced_owner)
                        no_terminal_source.update(
                            terminal_present="false",
                            terminal_sha256="none",
                            terminal_bytes="0",
                        )
                        write_record(source_path, list(no_terminal_source), no_terminal_source)
                        no_terminal_source_sha, no_terminal_source_bytes = remote_tuple(source_path)
                        no_terminal_pending["source_receipt_sha256"] = no_terminal_source_sha
                        no_terminal_pending["source_receipt_bytes"] = no_terminal_source_bytes
                        write_record(active_path, list(no_terminal_pending), no_terminal_pending)
                        no_terminal_pending_sha, no_terminal_pending_bytes = remote_tuple(active_path)
                        no_terminal_owner["source_receipt_sha256"] = no_terminal_source_sha
                        no_terminal_owner["active_sha256"] = no_terminal_pending_sha
                        no_terminal_owner["active_bytes"] = no_terminal_pending_bytes
                        write_record(owner_path, list(no_terminal_owner), no_terminal_owner)
                        subprocess.run(
                            ["wsl.exe", "rm", "-f", synthetic_paths["terminal"]], check=True
                        )
                        subprocess.run(
                            [
                                "wsl.exe",
                                "ln",
                                "-s",
                                "/dev/null",
                                f"{remote_dir}/runtime_active.retired.startup-no-effect",
                            ],
                            check=True,
                        )
                        no_terminal_recurrence = restore()
                        self.assertNotEqual(no_terminal_recurrence.returncode, 0)
                        self.assertNotIn(
                            "exact stock-restart helper", no_terminal_recurrence.stderr
                        )
                        subprocess.run(
                            [
                                "wsl.exe",
                                "rm",
                                "-f",
                                f"{remote_dir}/runtime_active.retired.startup-no-effect",
                            ],
                            check=True,
                        )
                        write_record(source_path, list(produced_source), produced_source)
                        write_record(active_path, list(produced_pending), produced_pending)
                        write_record(owner_path, list(produced_owner), produced_owner)
                        write_record(synthetic_paths["terminal"], terminal_keys, terminal)

                    def assert_recomputed_outer_refusal(
                        changes: dict[str, str], label: str
                    ) -> None:
                        corrupt_source = dict(produced_source)
                        corrupt_pending = dict(produced_pending)
                        corrupt_owner = dict(produced_owner)
                        corrupt_source.update(changes)
                        write_record(source_path, list(corrupt_source), corrupt_source)
                        corrupt_source_sha, corrupt_source_bytes = remote_tuple(source_path)
                        corrupt_pending["source_receipt_sha256"] = corrupt_source_sha
                        corrupt_pending["source_receipt_bytes"] = corrupt_source_bytes
                        write_record(active_path, list(corrupt_pending), corrupt_pending)
                        corrupt_pending_sha, corrupt_pending_bytes = remote_tuple(active_path)
                        corrupt_owner["source_receipt_sha256"] = corrupt_source_sha
                        corrupt_owner["active_sha256"] = corrupt_pending_sha
                        corrupt_owner["active_bytes"] = corrupt_pending_bytes
                        write_record(owner_path, list(corrupt_owner), corrupt_owner)
                        refused = restore()
                        self.assertNotEqual(refused.returncode, 0, label)
                        self.assertNotIn("exact stock-restart helper is required", refused.stderr, label)

                    assert_recomputed_outer_refusal(
                        {
                            "j0": {"fifo_inode": "999999999"},
                            "active": {"active_path": active_path},
                            "j2": {"fifo_inode": "999999999"},
                            "release": {"transcript_present": "false"},
                        }[highest],
                        f"corruption:{highest}",
                    )
                    if highest == "active":
                        hidden_active = f"{synthetic_paths['preserved_active']}.corrupt-hidden"
                        subprocess.run(["wsl.exe", "rm", "-f", hidden_active], check=True)
                        subprocess.run(
                            ["wsl.exe", "mv", synthetic_paths["preserved_active"], hidden_active],
                            check=True,
                        )
                        try:
                            assert_recomputed_outer_refusal(
                                {
                                    "active_present": "false",
                                    "active_path": "none",
                                    "preserved_active_present": "false",
                                    "preserved_active_sha256": "none",
                                    "preserved_active_bytes": "0",
                                },
                                "corruption:active-consumed-without-cleanup",
                            )
                        finally:
                            subprocess.run(
                                ["wsl.exe", "mv", hidden_active, synthetic_paths["preserved_active"]],
                                check=True,
                            )
                    if highest == "release":
                        assert_recomputed_outer_refusal(
                            {
                                "release_present": "false",
                                "release_sha256": "none",
                                "release_bytes": "0",
                            },
                            "corruption:false-none-live-release",
                        )
                        transcript_path = produced_source["transcript_path"]
                        hidden_transcript = f"{transcript_path}.corrupt-hidden"
                        subprocess.run(["wsl.exe", "rm", "-f", hidden_transcript], check=True)
                        subprocess.run(
                            ["wsl.exe", "mv", transcript_path, hidden_transcript], check=True
                        )
                        subprocess.run(
                            ["wsl.exe", "cp", hidden_transcript, transcript_path], check=True
                        )
                        subprocess.run(["wsl.exe", "chmod", "600", transcript_path], check=True)
                        try:
                            assert_recomputed_outer_refusal(
                                {}, "corruption:transcript-path-swap"
                            )
                        finally:
                            subprocess.run(["wsl.exe", "rm", "-f", transcript_path], check=True)
                            subprocess.run(
                                ["wsl.exe", "mv", hidden_transcript, transcript_path], check=True
                            )

                # Exercise the classifier itself so malformed current/retired
                # custody objects can never be laundered into a fresh source
                # receipt before the checked-SafeOff transition.
                cleanup_path = f"{remote_dir}/runtime_startup_retire_cleanup_commit"
                retired_owner = f"{remote_dir}/runtime_lock_owner.retired.startup-no-effect"
                retired_active = f"{remote_dir}/runtime_active.retired.startup-no-effect"
                cleanup_keys = (
                    "schema transaction_id phase highest_phase trial_dir terminal_schema "
                    "terminal_sha256 terminal_bytes owner_sha256 owner_bytes active_sha256 "
                    "active_bytes fifo_path transcript_path transcript_mnt_id transcript_inode "
                    "transcript_mode transcript_uid transcript_gid transcript_sha256 transcript_bytes "
                    "residue_count residue_manifest_sha256 commit_source_path supervisor_pid "
                    "supervisor_start supervisor_ppid supervisor_pgrp supervisor_session supervisor_exe "
                    "supervisor_cmdline_sha256 supervisor_cmdline_bytes bosminer_pid bosminer_start "
                    "bosminer_ppid bosminer_pgrp bosminer_session bosminer_exe bosminer_cmdline_sha256 "
                    "bosminer_cmdline_bytes stock_pidfile_path stock_pidfile_sha256 stock_pidfile_bytes "
                    "binary_sha256 binary_bytes config_sha256 config_bytes runner_sha256 runner_bytes "
                    "custody_observer_sha256 custody_observer_bytes stock_restart_helper_sha256 "
                    "stock_restart_helper_bytes live_identity_profile live_identity_sha256 gpio_raw "
                    "watchdog_start_intent watchdog_armed signal_attempted inherited_rails "
                    "route_or_uart_opened hardware_opened persistent_mutation publication"
                ).split()
                self.assertEqual(len(cleanup_keys), 64)
                terminal_sha, terminal_bytes = remote_tuple(synthetic_paths["terminal"])
                cleanup = {
                    "schema": "dcentos.s19k-startup-retire-cleanup-commit/v1",
                    "transaction_id": j0["transaction_id"],
                    "phase": "startup-no-effect-cleanup-committed",
                    "highest_phase": "release",
                    "trial_dir": remote_dir,
                    "terminal_schema": "dcentos.s19k-startup-retired-terminal/v1",
                    "terminal_sha256": terminal_sha,
                    "terminal_bytes": terminal_bytes,
                    "owner_sha256": j0_sha,
                    "owner_bytes": j0_bytes,
                    "active_sha256": active_sha,
                    "active_bytes": active_bytes,
                    "fifo_path": j0["fifo_path"],
                    **{key: terminal[key] for key in (
                        "transcript_path", "transcript_mnt_id", "transcript_inode",
                        "transcript_mode", "transcript_uid", "transcript_gid",
                        "transcript_sha256", "transcript_bytes",
                    )},
                    "residue_count": "0",
                    "residue_manifest_sha256": hashlib.sha256(b"").hexdigest(),
                    "commit_source_path": f"{remote_dir}/.runtime_startup_retire_cleanup_commit.source.123.456",
                    **{key: j0[key] for key in (
                        "supervisor_pid", "supervisor_start", "supervisor_ppid",
                        "supervisor_pgrp", "supervisor_session", "supervisor_exe",
                        "supervisor_cmdline_sha256", "supervisor_cmdline_bytes",
                        "bosminer_pid", "bosminer_start", "bosminer_ppid", "bosminer_pgrp",
                        "bosminer_session", "bosminer_exe", "bosminer_cmdline_sha256",
                        "bosminer_cmdline_bytes", "stock_pidfile_path", "stock_pidfile_sha256",
                        "stock_pidfile_bytes", "binary_sha256", "binary_bytes", "config_sha256",
                        "config_bytes", "runner_sha256", "runner_bytes",
                        "custody_observer_sha256", "custody_observer_bytes",
                        "stock_restart_helper_sha256", "stock_restart_helper_bytes",
                        "live_identity_profile", "live_identity_sha256",
                    )},
                    "gpio_raw": "437:0,454:0,455:1,456:1",
                    "watchdog_start_intent": "false",
                    "watchdog_armed": "false",
                    "signal_attempted": "false",
                    "inherited_rails": "false",
                    "route_or_uart_opened": "false",
                    "hardware_opened": "false",
                    "persistent_mutation": "false",
                    "publication": "no-clobber-hard-link-after-fsync",
                }

                classifier_paths = (
                    source_path, safeoff, active_path, owner_path,
                    synthetic_paths["c1"], synthetic_paths["j1"], synthetic_paths["j2"],
                    synthetic_paths["release"], synthetic_paths["preserved_active"],
                    preserved_owner, cleanup_path, retired_owner, retired_active,
                )

                def classify_only() -> subprocess.CompletedProcess[str]:
                    return subprocess.run(
                        [
                            "wsl.exe", "env",
                            "DCENT_TEST_CLASSIFY_STARTUP_PREFIX_ONLY=classifier-v1",
                            "sh", *restore_argv,
                        ],
                        text=True,
                        capture_output=True,
                        timeout=45,
                    )

                def reset_cleanup_classifier_state() -> None:
                    subprocess.run(["wsl.exe", "rmdir", retired_active], check=False, capture_output=True)
                    subprocess.run(["wsl.exe", "rm", "-f", *classifier_paths], check=True)
                    # Production consumes the exact J0-bound FIFO before it
                    # publishes the cleanup commit.  A live FIFO is not an
                    # admissible cleanup suffix and must not be fabricated by
                    # this synthetic classifier state.
                    subprocess.run(["wsl.exe", "rm", "-f", j0["fifo_path"]], check=True)
                    self.assertNotEqual(
                        subprocess.run(
                            ["wsl.exe", "test", "-e", j0["fifo_path"]], capture_output=True
                        ).returncode,
                        0,
                    )
                    write_record(cleanup_path, cleanup_keys, cleanup)
                    write_record(retired_owner, list(j0), j0)
                    write_record(retired_active, active_keys, active_record)

                reset_cleanup_classifier_state()
                self.assertEqual(classify_only().returncode, 0, "exact-cleanup-residues")
                subprocess.run(["wsl.exe", "mv", retired_owner, owner_path], check=True)
                self.assertEqual(
                    classify_only().returncode,
                    0,
                    "exact-cleanup-current-j0-before-owner-retirement",
                )
                subprocess.run(
                    ["wsl.exe", "rm", "-f", owner_path, retired_owner, retired_active], check=True
                )
                self.assertEqual(classify_only().returncode, 0, "consumed-cleanup-residues")

                def assert_classifier_refusal(label: str) -> None:
                    refused = classify_only()
                    self.assertNotEqual(refused.returncode, 0, label)

                reset_cleanup_classifier_state()
                subprocess.run(["wsl.exe", "cp", retired_owner, owner_path], check=True)
                assert_classifier_refusal("current-and-retired-owner")

                reset_cleanup_classifier_state()
                subprocess.run(["wsl.exe", "rm", "-f", cleanup_path, owner_path], check=True)
                subprocess.run(["wsl.exe", "cp", retired_owner, owner_path], check=True)
                subprocess.run(["wsl.exe", "rm", "-f", retired_owner], check=True)
                subprocess.run(["wsl.exe", "cp", retired_active, active_path], check=True)
                assert_classifier_refusal("current-and-retired-active")

                reset_cleanup_classifier_state()
                subprocess.run(["wsl.exe", "rm", "-f", owner_path], check=True)
                subprocess.run(["wsl.exe", "ln", "-s", "/dev/null", owner_path], check=True)
                assert_classifier_refusal("current-owner-symlink")

                reset_cleanup_classifier_state()
                subprocess.run(
                    ["wsl.exe", "sh", "-c", f"printf 'malformed\\n' > {shlex.quote(owner_path)}"],
                    check=True,
                )
                subprocess.run(["wsl.exe", "chmod", "600", owner_path], check=True)
                assert_classifier_refusal("current-owner-malformed")

                reset_cleanup_classifier_state()
                subprocess.run(["wsl.exe", "cp", retired_active, active_path], check=True)
                assert_classifier_refusal("current-active-present")

                reset_cleanup_classifier_state()
                subprocess.run(["wsl.exe", "rm", "-f", retired_owner], check=True)
                subprocess.run(["wsl.exe", "ln", "-s", "/dev/null", retired_owner], check=True)
                assert_classifier_refusal("retired-owner-symlink")

                reset_cleanup_classifier_state()
                subprocess.run(["wsl.exe", "rm", "-f", retired_active], check=True)
                subprocess.run(["wsl.exe", "ln", "-s", "/dev/null", retired_active], check=True)
                assert_classifier_refusal("retired-active-symlink")

                reset_cleanup_classifier_state()
                subprocess.run(["wsl.exe", "rm", "-f", retired_active], check=True)
                subprocess.run(["wsl.exe", "mkdir", retired_active], check=True)
                try:
                    assert_classifier_refusal("retired-active-nonregular")
                finally:
                    subprocess.run(["wsl.exe", "rmdir", retired_active], check=True)

                reset_cleanup_classifier_state()
                mismatched_cleanup = dict(cleanup)
                mismatched_cleanup["active_sha256"] = "0" * 64
                write_record(cleanup_path, cleanup_keys, mismatched_cleanup)
                assert_classifier_refusal("cleanup-active-tuple-mismatch")

                reset_cleanup_classifier_state()
                none_cleanup = dict(cleanup)
                none_cleanup["active_sha256"] = "none"
                none_cleanup["active_bytes"] = "0"
                write_record(cleanup_path, cleanup_keys, none_cleanup)
                assert_classifier_refusal("cleanup-none-pair-with-retired-active")

                # Crash after the cleanup commit but before OWNER retirement:
                # the cleanup record, not the still-current J0, is the highest
                # authority.  The normal restore path must preserve that J0 and
                # the retired v5 ACTIVE, publish pending/v10, and replay exactly.
                reset_cleanup_classifier_state()
                subprocess.run(["wsl.exe", "mv", retired_owner, owner_path], check=True)
                for gpio, value in ((437, 0), (454, 0), (455, 1), (456, 1)):
                    subprocess.run(
                        [
                            "wsl.exe",
                            "sh",
                            "-c",
                            f"printf '{value}\\n' > {shlex.quote(remote_dir + f'/live_identity_fixture/gpio/gpio{gpio}/value')}",
                        ],
                        check=True,
                    )
                cleanup_transition = restore()
                self.assertNotEqual(cleanup_transition.returncode, 0)
                self.assertIn("exact stock-restart helper", cleanup_transition.stderr)
                cleanup_source = fields(source_path)
                self.assertEqual(cleanup_source["source_kind"], "startup-cleanup-commit")
                self.assertEqual(cleanup_source["owner_path"], preserved_owner)
                self.assertEqual(
                    cleanup_source["owner_sha256"], cleanup_source["preserved_owner_sha256"]
                )
                self.assertEqual(
                    cleanup_source["active_path"], synthetic_paths["preserved_active"]
                )
                self.assertEqual(
                    cleanup_source["active_sha256"],
                    cleanup_source["preserved_active_sha256"],
                )
                self.assertEqual(fields(active_path)["schema"], "dcentos.s19k-startup-prefix-stock-restart-pending/v1")
                self.assertEqual(fields(owner_path)["schema"], "dcentos.s19k-track1-runtime-lock/v10")
                cleanup_replay = restore()
                self.assertNotEqual(cleanup_replay.returncode, 0)
                self.assertIn("exact stock-restart helper", cleanup_replay.stderr)

                # Post-source recurrence must not be able to introduce a new
                # historical owner or ACTIVE beside the preserved evidence.
                subprocess.run(
                    ["wsl.exe", "sh", "-c", f"printf 'mismatch\\n' > {shlex.quote(retired_owner)}"],
                    check=True,
                )
                subprocess.run(["wsl.exe", "chmod", "600", retired_owner], check=True)
                recurrence_owner = restore()
                self.assertNotEqual(recurrence_owner.returncode, 0)
                self.assertNotIn("exact stock-restart helper", recurrence_owner.stderr)
                subprocess.run(["wsl.exe", "rm", "-f", retired_owner], check=True)
                hidden_retired_active = f"{retired_active}.recurrence-hidden"
                subprocess.run(["wsl.exe", "mv", retired_active, hidden_retired_active], check=True)
                subprocess.run(["wsl.exe", "ln", "-s", "/dev/null", retired_active], check=True)
                try:
                    recurrence_active = restore()
                    self.assertNotEqual(recurrence_active.returncode, 0)
                    self.assertNotIn("exact stock-restart helper", recurrence_active.stderr)
                finally:
                    subprocess.run(["wsl.exe", "rm", "-f", retired_active], check=True)
                    subprocess.run(
                        ["wsl.exe", "mv", hidden_retired_active, retired_active], check=True
                    )

                # A complete, key-exact 108-field prelink scratch without its
                # canonical source is not a committed hardlink. Repeated restore
                # must remain fail-closed and must preserve the scratch.
                complete_prelink = (
                    f"{remote_dir}/.runtime_startup_prefix_pre_safeoff.tmp.999995.1"
                )
                subprocess.run(["wsl.exe", "cp", source_path, complete_prelink], check=True)
                subprocess.run(["wsl.exe", "chmod", "600", complete_prelink], check=True)
                subprocess.run(["wsl.exe", "rm", "-f", source_path], check=True)
                for _ in range(2):
                    prelink_refusal = restore()
                    self.assertNotEqual(prelink_refusal.returncode, 0)
                    self.assertNotIn("exact stock-restart helper", prelink_refusal.stderr)
                    self.assertEqual(
                        subprocess.run(
                            ["wsl.exe", "test", "-f", complete_prelink],
                            capture_output=True,
                        ).returncode,
                        0,
                    )
            finally:
                subprocess.run(
                    ["wsl.exe", "rm", "-f", *(f"{protocol_dir}/{name}" for name in protocol_names)],
                    check=False,
                    capture_output=True,
                )
                subprocess.run(
                    ["wsl.exe", "rmdir", protocol_dir], check=False, capture_output=True
                )
                subprocess.run(
                    ["wsl.exe", "rm", "-f", remote_controller, remote_command, remote_audit],
                    check=False,
                    capture_output=True,
                )
                subprocess.run(
                    [
                        "wsl.exe",
                        "sh",
                        "-c",
                        f"rm -f {shlex.quote(remote_dir)}/* {shlex.quote(remote_dir)}/.* 2>/dev/null || true; "
                        f"rm -f {shlex.quote(runtime_lock)}/* 2>/dev/null || true; "
                        f"rmdir {shlex.quote(runtime_lock)} 2>/dev/null || true",
                    ],
                    check=False,
                )
                self._cleanup_identity_fixture(remote_dir)
                subprocess.run(
                    ["wsl.exe", "rm", "-rf", f"{remote_dir}/live_identity_fixture"],
                    check=False,
                )
                subprocess.run(["wsl.exe", "rmdir", remote_dir], check=False)

    @unittest.skipUnless(os.name == "nt", "WSL all-thread /proc snapshot KAT")
    def test_all_thread_effect_snapshot_catches_live_worker_after_leader_exit(self) -> None:
        source = (SCRIPTS / "dcentrald_s19k_tmp_remote_run.sh").read_text(
            encoding="utf-8"
        )

        def function(name: str) -> str:
            match = re.search(
                rf"(?ms)^{re.escape(name)}\(\) (?:\{{\n.*?^\}}\n|\(\n.*?^\)\n)",
                source,
            )
            self.assertIsNotNone(match, name)
            return match.group(0)

        harness = "#!/bin/sh\nset -eu\n" + "\n".join(
            function(name)
            for name in (
                "valid_uint",
                "collect_all_task_effect_snapshot",
                "filter_custody_relevant_task_effects",
                "stable_all_task_effect_snapshot",
                "all_task_snapshot_has_no_dcentrald",
                "no_dcentrald_thread_is_live",
                "all_task_snapshot_has_stock_owner",
                "bosminer_custody_owner_is_live",
                "all_task_snapshot_has_another_wrapper",
                "another_trial_wrapper_is_live",
                "all_task_snapshot_has_no_watchdog_fd",
                "no_watchdog_fd_is_live",
            )
        )
        harness += r'''
ROOT=$1
TRIAL_DIR=$ROOT
SELF_START=424243
mkdir -p "$ROOT/100/task/100/fd" "$ROOT/100/task/101/fd"
printf '%s\n' '100 (retired leader) Z 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 111111' > "$ROOT/100/task/100/stat"
printf '%s\n' 'retired leader' > "$ROOT/100/task/100/comm"
printf '%s\n' '101 (worker ) right space) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242' > "$ROOT/100/task/101/stat"
printf '%s\n' 'worker ) right space' > "$ROOT/100/task/101/comm"
printf '/opt/test/dcentrald\000--worker\000' > "$ROOT/100/task/101/cmdline"
ln -s /opt/test/dcentrald "$ROOT/100/task/101/exe"
ln -s /dev/watchdog0 "$ROOT/100/task/101/fd/7"
SNAP=$(collect_all_task_effect_snapshot "$ROOT")
printf '%s\n' "$SNAP" | grep -Fx 'T|100|101|S|424242|comm=worker ) right space|exe=/opt/test/dcentrald|argv0=/opt/test/dcentrald|bosminer_arg=false|track1_wrapper_arg=false'
printf '%s\n' "$SNAP" | grep -Fx 'F|100|101|7|target=/dev/watchdog0'
if no_dcentrald_thread_is_live "$ROOT"; then exit 41; fi
if no_watchdog_fd_is_live "$ROOT"; then exit 42; fi
rm -f "$ROOT/100/task/101/exe" "$ROOT/100/task/101/fd/7"
ln -s /usr/bin/bosminer "$ROOT/100/task/101/exe"
printf '/usr/bin/bosminer\000--log-to-file\000' > "$ROOT/100/task/101/cmdline"
bosminer_custody_owner_is_live "$ROOT" || exit 43
rm -f "$ROOT/100/task/101/exe"
ln -s /usr/bin/bos-tools "$ROOT/100/task/101/exe"
printf '/usr/bin/bos-tools\000run-and-watch\000--\000/usr/bin/bosminer\000--log-to-file\000' > "$ROOT/100/task/101/cmdline"
bosminer_custody_owner_is_live "$ROOT" || exit 44
rm -f "$ROOT/100/task/101/exe"
ln -s /bin/sh "$ROOT/100/task/101/exe"
printf '/bin/sh\000/tmp/dcentrald_bench_t1_competitor/run_trial\000' > "$ROOT/100/task/101/cmdline"
another_trial_wrapper_is_live "$ROOT" || exit 45
rm -f "$ROOT/100/task/101/exe"
ln -s /opt/test/other "$ROOT/100/task/101/exe"
printf '/opt/test/other\000--worker\000' > "$ROOT/100/task/101/cmdline"
no_dcentrald_thread_is_live "$ROOT"
no_watchdog_fd_is_live "$ROOT"
if bosminer_custody_owner_is_live "$ROOT"; then exit 46; fi
if another_trial_wrapper_is_live "$ROOT"; then exit 47; fi
'''
        with tempfile.TemporaryDirectory() as raw_temp:
            local_harness = Path(raw_temp) / "all_thread_snapshot_kat.sh"
            local_harness.write_text(harness, encoding="utf-8", newline="\n")
            fixture = subprocess.check_output(
                [
                    "wsl.exe",
                    "-d",
                    "Ubuntu-22.04",
                    "mktemp",
                    "-d",
                    "/tmp/s19k_all_thread_snapshot.XXXXXX",
                ],
                text=True,
            ).strip()
            try:
                result = subprocess.run(
                    [
                        "wsl.exe",
                        "-d",
                        "Ubuntu-22.04",
                        "busybox",
                        "sh",
                        self._shell_path(local_harness),
                        fixture,
                    ],
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
                self.assertEqual(
                    result.returncode, 0, f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
                )
            finally:
                subprocess.run(
                    [
                        "wsl.exe",
                        "-d",
                        "Ubuntu-22.04",
                        "rm",
                        "-rf",
                        fixture,
                    ],
                    check=False,
                )

    def test_historical_stock_retained_closeout_is_exact_and_non_mutating(self) -> None:
        source = (SCRIPTS / "dcentrald_s19k_tmp_stock_retained_closeout.sh").read_text(
            encoding="utf-8"
        )
        executable = "\n".join(
            line for line in source.splitlines() if not line.lstrip().startswith("#")
        )
        for required in (
            "CLEAR_STOCK_RETAINED",
            "EXPECTED_CFG_SHA=${8:?expected_config_sha256_from_host_plan}",
            "EXPECTED_RUNNER_SHA=${10:?expected_runner_sha256_from_host_plan}",
            "EXECUTE=${16:-}",
            "AUDITED_BIN_SHA=19b846ffd82446212863e556fdb4ec12099732e90cfd64e2484b6793062a5752",
            "AUDITED_BIN_BYTES=23656544",
            "AUDITED_SOURCE_SNAPSHOT_ID=2ee6982acee0c61128698ab36e1a05e9e6e37a9efcc326f35b1cc1b6f63db703",
            "AUDITED_SOURCE_DESCRIPTOR_SHA=ce94cac8677752fa26592444ce15ad05a2ff07ed8d694b1cca5ccb64685eafb0",
            "AUDITED_BUILD_RECEIPT_ID=321dd6704881ac23681974af0b58469e766213c01a992e94912b17763318a199",
            "AUDITED_BUILD_RECEIPT_FILE_SHA=be1bf2dc9de50e74c8e4bf43967a23557238b8f8936e4d4c2849825a1d5d69c6",
            "dcentos.s19k-tmp-runtime/v3",
            "child-live-or-recovery-required",
            "dcentos.s19k-track1-runtime-lock/v1",
            "live88_two_bhb56903_slots_2_3",
            "437:0,454:0,455:1,456:1",
            "bound config is not exact watchdog-disabled evidence",
            "/dev/watchdog|/dev/watchdog[0-9]*",
            '"$RUNNER" identity',
            "schema=dcentos.s19k-track1-stock-owner-retained/v1",
            "reason=watchdog-disabled-by-bound-config",
            "watchdog_device=not-opened-disabled-by-configuration",
            "hashboard_mutation=not-reached",
            "gpio_mutation=false",
            "safeoff=false",
            'rm -f "$OWNER"\nrmdir "$LOCK"',
            'regular "$ACTIVE"',
            "active_is_unchanged",
            "lock_is_unchanged",
            "closeout_is_exact",
            "require_exact_stock_owner",
            "require_no_watchdog_fd",
            "fresh_identity_matches",
            'rm -f "$ACTIVE"',
        ):
            self.assertIn(required, source)
        self.assertNotIn("kill -", executable)
        self.assertNotIn("--s19k-track1-recovery-safeoff", executable)
        self.assertNotIn("nandwrite", executable)
        self.assertNotIn("flash_erase", executable)
        self.assertNotRegex(executable, r">\s*/sys/class/gpio")
        self.assertLess(source.index('rm -f "$OWNER"'), source.index('rmdir "$LOCK"'))
        self.assertLess(source.index('rmdir "$LOCK"'), source.index('rm -f "$ACTIVE"'))
        publish = source.index('ln "$TMP" "$CLOSEOUT"')
        final_identity = source.rindex("&& fresh_identity_matches")
        final_closeout = source.rindex("&& closeout_is_exact")
        final_active = source.rindex("&& active_is_unchanged")
        final_lock = source.rindex("&& lock_is_unchanged")
        owner_clear = source.index('rm -f "$OWNER"')
        self.assertLess(publish, final_identity)
        self.assertLess(final_identity, final_closeout)
        self.assertLess(final_closeout, final_active)
        self.assertLess(final_active, final_lock)
        self.assertLess(final_lock, owner_clear)

    def test_dry_run_scoped_toml_and_explicit_loud_behavior(self) -> None:
        base = """
[platform]
target = "am3-aml-s19k"
board_target = "am3-s19k"
[mining]
enabled = {enabled}
passthrough = {passthrough}
"""
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            stage = self._run_deployer(
                temp, base.format(enabled="false", passthrough="false"), False
            )
            self.assertEqual(stage.returncode, 0, stage.stderr)
            self.assertIn("no ssh, no scp", stage.stdout)
            missing_loud = self._run_deployer(
                temp, base.format(enabled="true", passthrough="true"), False
            )
            self.assertNotEqual(missing_loud.returncode, 0)
            self.assertIn("explicit --allow-loud", missing_loud.stderr)
            mining = self._run_deployer(
                temp, base.format(enabled="true", passthrough="true"), True
            )
            self.assertEqual(mining.returncode, 0, mining.stderr)
            self.assertIn("mining-on-passthrough", mining.stdout)
            omitted_mode = self._run_deployer(
                temp,
                base.format(enabled="true", passthrough="true"),
                True,
                mining_on_passthrough=False,
            )
            self.assertNotEqual(omitted_mode.returncode, 0)
            self.assertIn("requires exactly one explicit deploy mode", omitted_mode.stderr)

            no_work_stage = self._run_deployer(
                temp,
                base.format(enabled="false", passthrough="false"),
                False,
                handoff_no_work=True,
            )
            self.assertNotEqual(no_work_stage.returncode, 0)
            self.assertIn(
                "requires an admitted mining-enabled passthrough config",
                no_work_stage.stderr,
            )
            no_work = self._run_deployer(
                temp,
                base.format(enabled="true", passthrough="true"),
                True,
                handoff_no_work=True,
            )
            self.assertEqual(no_work.returncode, 0, no_work.stderr)
            self.assertIn("mode=handoff-no-work", no_work.stdout)
            self.assertIn("work_authority=disabled", no_work.stdout)

            bounded = self._run_deployer(
                temp,
                base.format(enabled="true", passthrough="true"),
                True,
                bounded_work_proof=True,
            )
            self.assertEqual(bounded.returncode, 0, bounded.stderr)
            self.assertIn("mode=bounded-work-proof", bounded.stdout)
            self.assertIn("work_authority=bounded-proof", bounded.stdout)
            self.assertIn("work_proof_timeout_s=600", bounded.stdout)

            endurance = self._run_deployer(
                temp,
                base.format(enabled="true", passthrough="true"),
                True,
                endurance_work_proof=True,
            )
            self.assertEqual(endurance.returncode, 0, endurance.stderr)
            self.assertIn("S19K_ENDURANCE_BASELINE_OK", endurance.stdout)
            self.assertIn("mode=endurance-work-proof", endurance.stdout)
            self.assertIn("work_authority=endurance-proof", endurance.stdout)
            self.assertIn("minimum_s=86400 maximum_s=93600", endurance.stdout)
            self.assertIn("--resume-failure --plan", endurance.stdout)
            self.assertIn("--phase3-plan <accepted-live-bounded-plan>", endurance.stdout)
            self.assertIn("--phase3-trial-dir <copied-phase3-trial-dir>", endurance.stdout)
            self.assertIn("--phase3-wall-power-csv <canonical-phase3-meter.csv>", endurance.stdout)
            self.assertIn(
                "--phase3-physical-dir <sealed-phase3-physical-evidence-dir>",
                endurance.stdout,
            )

            wrong_scope = self._run_deployer(
                temp,
                """
[other]
target = "am3-aml-s19k"
board_target = "am3-s19k"
[platform]
target = "am3-aml-s21"
board_target = "am3-s21"
[mining]
enabled = false
passthrough = false
""",
                False,
            )
            self.assertNotEqual(wrong_scope.returncode, 0)
            self.assertIn("[platform].target", wrong_scope.stderr)

            non_eabi5 = self._run_deployer(
                temp,
                base.format(enabled="false", passthrough="false"),
                False,
                arm_flags=0x00000400,
            )
            self.assertNotEqual(non_eabi5.returncode, 0)
            self.assertIn("require ARM EABI5", non_eabi5.stderr)

            wrong_artifact = self._run_deployer(
                temp,
                base.format(enabled="true", passthrough="true"),
                True,
                handoff_no_work=True,
                expected_artifact_sha256="0" * 64,
            )
            self.assertNotEqual(wrong_artifact.returncode, 0)
            self.assertIn(
                "selected artifact does not match exact sealed operator authority",
                wrong_artifact.stderr,
            )

            missing_authority_pin = self._run_deployer(
                temp,
                base.format(enabled="true", passthrough="true"),
                True,
                handoff_no_work=True,
                artifact_pin=False,
            )
            self.assertNotEqual(missing_authority_pin.returncode, 0)
            self.assertIn("exact sealed artifact authority requires", missing_authority_pin.stderr)

    @unittest.skipUnless(os.name == "nt", "WSL stage-only transaction exercise")
    def test_remote_stage_only_reverify_does_not_mutate_identity(self) -> None:
        remote_dir = subprocess.check_output(
            ["wsl.exe", "mktemp", "-d", "/tmp/dcentrald_bench_t1_stagecheck.XXXXXX"],
            text=True,
        ).strip()
        helper = SCRIPTS / "dcentrald_s19k_tmp_remote_run.sh"
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            binary = temp / "dcentrald"
            config = temp / "dcentrald_s19k.toml"
            binary.write_bytes(b"stage-only-binary")
            config.write_bytes(b"stage-only-config")
            files = {
                "dcentrald": binary,
                "dcentrald_s19k.toml": config,
                "run_trial": helper,
                "supervisor_custody_observer": SUPERVISOR_CUSTODY,
                "stock_restart_helper": STOCK_RESTART_HELPER,
            }
            try:
                for name, source in files.items():
                    subprocess.run(
                        [
                            "wsl.exe",
                            "cp",
                            self._shell_path(source),
                            f"{remote_dir}/{name}",
                        ],
                        check=True,
                    )
                args: list[str] = []
                for name in (
                    "dcentrald",
                    "dcentrald_s19k.toml",
                    "run_trial",
                    "supervisor_custody_observer",
                    "stock_restart_helper",
                ):
                    blob = files[name].read_bytes()
                    args.extend([hashlib.sha256(blob).hexdigest(), str(len(blob))])
                result = subprocess.run(
                    [
                        "wsl.exe",
                        "sh",
                        f"{remote_dir}/run_trial",
                        "run",
                        remote_dir,
                        "am3-s19k",
                        "stage-only",
                        *args,
                    ],
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("no persistent mutation", result.stdout)
                for name in ("runtime_active", "identity_active", "identity_backup"):
                    probe = subprocess.run(
                        ["wsl.exe", "test", "-e", f"{remote_dir}/{name}"]
                    )
                    self.assertNotEqual(probe.returncode, 0, name)
            finally:
                subprocess.run(
                    [
                        "wsl.exe",
                        "rm",
                        "-f",
                        f"{remote_dir}/dcentrald",
                        f"{remote_dir}/dcentrald_s19k.toml",
                        f"{remote_dir}/run_trial",
                        f"{remote_dir}/supervisor_custody_observer",
                        f"{remote_dir}/stock_restart_helper",
                    ],
                    check=False,
                )
                subprocess.run(["wsl.exe", "rmdir", remote_dir], check=False)

    @unittest.skipUnless(os.name == "nt", "WSL pre-handoff custody exercise")
    def test_live_identity_accepts_profile_aware_902_903_populations(self) -> None:
        remote_dir = subprocess.check_output(
            ["wsl.exe", "mktemp", "-d", "/tmp/dcentrald_bench_t1_topology.XXXXXX"],
            text=True,
        ).strip()
        runtime_lock = f"{remote_dir}.board-global-lock"
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            binary = temp / "dcentrald"
            config = temp / "dcentrald_s19k.toml"
            binary.write_bytes(b"topology-identity-fixture")
            config.write_bytes(b"topology-config-fixture")
            cases = (
                (
                    "held78-exact",
                    ("BHB56902",) * 3,
                    (1, 2, 3),
                    (),
                    (True, True, True),
                    "held78_three_bhb56902_slots_1_2_3",
                    "board_names=BHB56902,BHB56902,BHB56902 physical_addresses=1,2,3 "
                    "eeprom=0x50=05:11,0x51=05:11,0x52=05:11",
                ),
                (
                    "live88-exact",
                    ("BHB56903",) * 2,
                    (2, 3),
                    (1,),
                    (False, True, True),
                    "live88_two_bhb56903_slots_2_3",
                    "board_names=BHB56903,BHB56903 physical_addresses=2,3 "
                    "eeprom=0x50=absent,0x51=05:11,0x52=05:11",
                ),
                (
                    "mixed-sku",
                    ("BHB56903", "BHB56902"),
                    (2, 3),
                    (1,),
                    (False, True, True),
                    "mixed-bhb56902-bhb56903:partial-logical-uarts-populated",
                    "board_names=BHB56903,BHB56902 physical_addresses=2,3 "
                    "eeprom=0x50=absent,0x51=05:11,0x52=05:11",
                ),
                (
                    "live88-mixed-count",
                    ("BHB56903",) * 3,
                    (1, 2, 3),
                    (),
                    (True, True, True),
                    "bhb56903-only:all-three-uarts-populated",
                    "board_names=BHB56903,BHB56903,BHB56903 physical_addresses=1,2,3 "
                    "eeprom=0x50=05:11,0x51=05:11,0x52=05:11",
                ),
                (
                    "live88-wrong-addresses",
                    ("BHB56903",) * 2,
                    (1, 2),
                    (3,),
                    (True, True, False),
                    "bhb56903-only:partial-logical-uarts-populated",
                    "board_names=BHB56903,BHB56903 physical_addresses=1,2 "
                    "eeprom=0x50=05:11,0x51=05:11,0x52=absent",
                ),
                (
                    "live88-duplicate-address",
                    ("BHB56903",) * 2,
                    (2, 2),
                    (1,),
                    (False, True, True),
                    None,
                    "hashboard objects are not the exact held descriptor shape",
                ),
                (
                    "live88-missing-placeholder",
                    ("BHB56903",) * 2,
                    (2, 3),
                    (),
                    (False, True, True),
                    None,
                    "hashboard objects are not the exact held descriptor shape",
                ),
                (
                    "live88-extra-object",
                    ("BHB56903",) * 3,
                    (2, 3, 3),
                    (1,),
                    (False, True, True),
                    None,
                    "hashboard objects are not the exact held descriptor shape",
                ),
                (
                    "live88-slot50-present",
                    ("BHB56903",) * 2,
                    (2, 3),
                    (1,),
                    (True, True, True),
                    None,
                    "EEPROM population contradicts the selected typed S19k profile",
                ),
                (
                    "held78-slot50-absent",
                    ("BHB56902",) * 3,
                    (1, 2, 3),
                    (),
                    (False, True, True),
                    None,
                    "EEPROM population contradicts the selected typed S19k profile",
                ),
                (
                    "held78-wrong-address",
                    ("BHB56902",) * 3,
                    (1, 2, 4),
                    (),
                    (True, True, True),
                    None,
                    "hashboard objects are not the exact held descriptor shape",
                ),
            )
            try:
                for (
                    label,
                    boards,
                    addresses,
                    undetected_addresses,
                    eeprom_presence,
                    profile,
                    detail,
                ) in cases:
                    case_temp = temp / label
                    case_temp.mkdir()
                    helper = self._identity_bound_runner(
                        case_temp,
                        remote_dir,
                        boards=boards,
                        physical_addresses=addresses,
                        undetected_physical_addresses=undetected_addresses,
                        eeprom_presence=eeprom_presence,
                        runtime_lock=runtime_lock,
                    )
                    files = {
                        "dcentrald": binary,
                        "dcentrald_s19k.toml": config,
                        "run_trial": helper,
                        "supervisor_custody_observer": SUPERVISOR_CUSTODY,
                        "stock_restart_helper": STOCK_RESTART_HELPER,
                    }
                    for name, source in files.items():
                        subprocess.run(
                            [
                                "wsl.exe",
                                "cp",
                                self._shell_path(source),
                                f"{remote_dir}/{name}",
                            ],
                            check=True,
                        )
                    args: list[str] = []
                    for name in (
                        "dcentrald",
                        "dcentrald_s19k.toml",
                        "run_trial",
                        "supervisor_custody_observer",
                        "stock_restart_helper",
                    ):
                        blob = files[name].read_bytes()
                        args.extend([hashlib.sha256(blob).hexdigest(), str(len(blob))])
                    result = subprocess.run(
                        [
                            "wsl.exe",
                            "sh",
                            f"{remote_dir}/run_trial",
                            "identity",
                            remote_dir,
                            "am3-s19k",
                            "stage-only",
                            *args,
                        ],
                        text=True,
                        capture_output=True,
                        timeout=45,
                    )
                    if profile is not None:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertRegex(
                            result.stdout,
                            rf"^DCENT_S19K_LIVE_IDENTITY .* profile={profile} .* {re.escape(detail)}$",
                        )
                    else:
                        self.assertNotEqual(result.returncode, 0, label)
                        self.assertIn(detail, result.stderr, label)
            finally:
                subprocess.run(
                    [
                        "wsl.exe",
                        "rm",
                        "-f",
                        f"{remote_dir}/dcentrald",
                        f"{remote_dir}/dcentrald_s19k.toml",
                        f"{remote_dir}/run_trial",
                        f"{remote_dir}/supervisor_custody_observer",
                        f"{remote_dir}/stock_restart_helper",
                    ],
                    check=False,
                )
                self._cleanup_identity_fixture(remote_dir)
                subprocess.run(["wsl.exe", "rmdir", remote_dir], check=False)

    @unittest.skipUnless(os.name == "nt", "WSL pre-handoff custody exercise")
    def test_child_refusal_while_bosminer_live_never_invokes_recovery(self) -> None:
        remote_dir = subprocess.check_output(
            ["wsl.exe", "mktemp", "-d", "/tmp/dcentrald_bench_t1_prehandoff.XXXXXX"],
            text=True,
        ).strip()
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            runtime_lock = f"{remote_dir}.board-global-lock"
            helper = self._identity_bound_runner(
                temp, remote_dir, runtime_lock=runtime_lock
            )
            binary = temp / "dcentrald"
            config = temp / "dcentrald_s19k.toml"
            binary.write_bytes(
                b"#!/bin/sh\n"
                b"source_path=; destination_path=; previous=\n"
                b"for arg in \"$@\"; do\n"
                b"  case \"$previous\" in\n"
                b"    source) source_path=$arg ;;\n"
                b"    destination) destination_path=$arg ;;\n"
                b"  esac\n"
                b"  case \"$arg\" in\n"
                b"    --s19k-track1-journal-source) previous=source; continue ;;\n"
                b"    --s19k-track1-journal-destination) previous=destination; continue ;;\n"
                b"  esac\n"
                b"  previous=\n"
                b"done\n"
                b"if [ -n \"$source_path\" ] && [ -n \"$destination_path\" ]; then\n"
                b"  ln \"$source_path\" \"$destination_path\"\n"
                b"  exit $?\n"
                b"fi\n"
                b'env > "$0.child-env"\n'
                b'case " $* " in\n'
                b"  *' --s19k-track1-recovery-safeoff '*) touch \"$DCENT_TEST_RECOVERY_MARK\"; exit 1 ;;\n"
                b"esac\n"
                b"sleep 2\n"
                b"exit 1\n"
            )
            config.write_text(
                "[watchdog]\nenabled = false\n", encoding="utf-8", newline="\n"
            )
            files = {
                "dcentrald": binary,
                "dcentrald_s19k.toml": config,
                "run_trial": helper,
                "supervisor_custody_observer": SUPERVISOR_CUSTODY,
                "stock_restart_helper": STOCK_RESTART_HELPER,
            }
            try:
                for name, source in files.items():
                    subprocess.run(
                        [
                            "wsl.exe",
                            "cp",
                            self._shell_path(source),
                            f"{remote_dir}/{name}",
                        ],
                        check=True,
                    )
                subprocess.run(
                    ["wsl.exe", "cp", "/bin/sleep", f"{remote_dir}/bosminer"],
                    check=True,
                )
                subprocess.run(
                    [
                        "wsl.exe",
                        "chmod",
                        "755",
                        f"{remote_dir}/dcentrald",
                        f"{remote_dir}/bosminer",
                    ],
                    check=True,
                )
                args: list[str] = []
                for name in (
                    "dcentrald",
                    "dcentrald_s19k.toml",
                    "run_trial",
                    "supervisor_custody_observer",
                    "stock_restart_helper",
                ):
                    blob = files[name].read_bytes()
                    args.extend([hashlib.sha256(blob).hexdigest(), str(len(blob))])
                marker = f"{remote_dir}/recovery_was_invoked"
                child_env = f"{remote_dir}/dcentrald.child-env"
                runner_argv = [
                    f"{remote_dir}/run_trial",
                    "run",
                    remote_dir,
                    "am3-s19k",
                    "mining-on-passthrough",
                    *args,
                ]
                command = (
                    f"{shlex.quote(remote_dir + '/bosminer')} 30 >/dev/null 2>&1 & "
                    "bosminer_pid=$!; "
                    "bosminer_ready=0; bosminer_wait=0; "
                    'while [ "$bosminer_wait" -lt 50 ]; do '
                    'case " $(pidof bosminer 2>/dev/null || true) " in '
                    '*" $bosminer_pid "*) bosminer_ready=1; break ;; esac; '
                    "bosminer_wait=$((bosminer_wait + 1)); /bin/sleep 0.1; done; "
                    'if [ "$bosminer_ready" -ne 1 ]; then '
                    "kill $bosminer_pid 2>/dev/null || true; "
                    "wait $bosminer_pid 2>/dev/null || true; exit 97; fi; "
                    f"DCENT_TEST_RECOVERY_MARK={shlex.quote(marker)} "
                    "DCENT_S19K_CHIP_FASTUART=1 "
                    "DCENT_S19K_TRACK1_RETRY_115200=1 "
                    "DCENT_S19K_EXPERIMENTAL_POST_CLEAN_CHAIN_INACTIVE=1 "
                    "DCENT_S19K_EXPERIMENTAL_POST_CLEAN_JOB_FLIP=1 "
                    "DCENT_S19K_EXPERIMENTAL_WRAP4_EARLY_CLEAN=1 "
                    "DCENT_BRAIINS_TTYS_BENCH_GO=1 "
                    "DCENT_S19K_UART_EEPROM=hostile "
                    "DCENT_S19K_I2CDETECT=hostile "
                    "PATH=/definitely/not/operator/path "
                    + " ".join(
                        shlex.quote(value) for value in ["/bin/sh", *runner_argv]
                    )
                    + "; runner_rc=$?; kill $bosminer_pid 2>/dev/null || true; "
                    'wait "$bosminer_pid" 2>/dev/null || true; '
                    'runner_rc=${runner_rc:-98}; exit "$runner_rc"'
                )
                result = subprocess.run(
                    ["wsl.exe", "sh", "-c", command],
                    text=True,
                    capture_output=True,
                    timeout=45,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "dcentrald exited before publishing immutable J1; J0 custody remains",
                    result.stderr,
                )
                self.assertNotEqual(
                    subprocess.run(["wsl.exe", "test", "-e", marker]).returncode,
                    0,
                )
                self.assertNotEqual(
                    subprocess.run(
                        ["wsl.exe", "test", "-f", f"{remote_dir}/runtime_active"]
                    ).returncode,
                    0,
                )
                self.assertEqual(
                    subprocess.run(["wsl.exe", "test", "-d", runtime_lock]).returncode,
                    0,
                )
                self.assertEqual(
                    subprocess.run(
                        ["wsl.exe", "test", "-f", f"{runtime_lock}/owner"]
                    ).returncode,
                    0,
                )
                owner = subprocess.check_output(
                    ["wsl.exe", "cat", f"{runtime_lock}/owner"], text=True
                )
                self.assertIn("schema=dcentos.s19k-startup-j0-prefork/v1", owner)
                self.assertIn("runtime_active_path=not-published", owner)
                self.assertNotEqual(
                    subprocess.run(
                        [
                            "wsl.exe",
                            "sh",
                            "-c",
                            f"test -e {shlex.quote(remote_dir)}/runtime_stock_owner_retained.*",
                        ]
                    ).returncode,
                    0,
                )
                captured = subprocess.check_output(
                    ["wsl.exe", "cat", child_env], text=True
                )
                self.assertIn("PATH=/usr/bin:/bin:/usr/sbin:/sbin", captured)
                self.assertIn("DCENTOS_EPHEMERAL_RUNTIME=1", captured)
                self.assertIn("DCENTOS_LOG_RING_DIR=/tmp/dcent/log", captured)
                self.assertIn("DCENT_S19K_TRACK1_STOP_SAFEOFF=1", captured)
                self.assertRegex(
                    captured,
                    r"(?m)^DCENT_S19K_LIVE_IDENTITY_SHA256=[0-9a-f]{64}$",
                )
                for hostile in (
                    "DCENT_TEST_RECOVERY_MARK",
                    "DCENT_S19K_CHIP_FASTUART",
                    "DCENT_S19K_TRACK1_RETRY_115200",
                    "DCENT_S19K_EXPERIMENTAL_POST_CLEAN_CHAIN_INACTIVE",
                    "DCENT_S19K_EXPERIMENTAL_POST_CLEAN_JOB_FLIP",
                    "DCENT_S19K_EXPERIMENTAL_WRAP4_EARLY_CLEAN",
                    "DCENT_BRAIINS_TTYS_BENCH_GO",
                    "DCENT_S19K_UART_EEPROM",
                    "DCENT_S19K_I2CDETECT",
                ):
                    self.assertNotIn(f"{hostile}=", captured)

            finally:
                subprocess.run(
                    [
                        "wsl.exe",
                        "sh",
                        "-c",
                        f"rm -f {shlex.quote(remote_dir)}/runtime_stock_owner_retained.* "
                        f"{shlex.quote(remote_dir)}/runtime_startup_* "
                        f"{shlex.quote(remote_dir)}/.startup_fifo.*",
                    ],
                    check=False,
                )
                subprocess.run(
                    [
                        "wsl.exe",
                        "rm",
                        "-f",
                        f"{remote_dir}/dcentrald",
                        f"{remote_dir}/dcentrald_s19k.toml",
                        f"{remote_dir}/run_trial",
                        f"{remote_dir}/supervisor_custody_observer",
                        f"{remote_dir}/stock_restart_helper",
                        f"{remote_dir}/bosminer",
                        f"{remote_dir}/runtime_active",
                        f"{remote_dir}/recovery_was_invoked",
                        f"{remote_dir}/dcentrald.child-env",
                    ],
                    check=False,
                )
                self._cleanup_identity_fixture(remote_dir)
                subprocess.run(
                    ["wsl.exe", "rm", "-f", f"{runtime_lock}/owner"], check=False
                )
                subprocess.run(["wsl.exe", "rmdir", runtime_lock], check=False)
                subprocess.run(["wsl.exe", "rmdir", remote_dir], check=False)

    def _j2_orphan_fixture_runner(
        self, temp: Path, remote_dir: str, runtime_lock: str
    ) -> Path:
        """Identity-bound runner plus the fake-daemon child-identity adapters.

        A #!/bin/sh fake daemon cannot present the comm/exe/cmdline identity of
        the real ELF dcentrald child, so exactly three child-identity conjuncts
        are gated on the trial-local .fake_daemon_adapter marker: the
        comm/exe pair in exact_dcentrald_child_matches, the live-child-cmdline
        sha/bytes pair in require_startup_j1_for_child (the J0-canonical
        equalities are kept), and the record child_exe comparison in
        startup_c1_is_exact_for_recovery. Every wrapper-identity conjunct —
        including the reparenting behavior under test — is untouched.
        """
        base = self._identity_bound_runner(temp, remote_dir, runtime_lock=runtime_lock)
        source = base.read_text(encoding="utf-8")
        marker = '[ -f "$TRIAL_DIR/.fake_daemon_adapter" ]'
        adapters = {
            '    [ "$(cat "/proc/$PID/comm" 2>/dev/null || true)" = dcentrald ] || return 1\n'
            '    [ "$(readlink "/proc/$PID/exe" 2>/dev/null || true)" = "$TRIAL_BIN" ]\n': (
                '    { [ "$(cat "/proc/$PID/comm" 2>/dev/null || true)" = dcentrald ] || '
                + marker + "; } || return 1\n"
                '    { [ "$(readlink "/proc/$PID/exe" 2>/dev/null || true)" = "$TRIAL_BIN" ] || '
                + marker + "; }\n"
            ),
            '        && [ "$(startup_field_at "$STARTUP_C1" child_cmdline_sha256)" = "$(sha256sum "/proc/$CHILD_PID/cmdline" 2>/dev/null | awk \'{print $1}\')" ] \\\n'
            '        && [ "$(startup_field_at "$STARTUP_C1" child_cmdline_sha256)" = "$(runtime_lock_field expected_daemon_cmdline_sha256)" ] \\\n'
            '        && [ "$(startup_field_at "$STARTUP_C1" child_cmdline_bytes)" = "$(wc -c < "/proc/$CHILD_PID/cmdline" 2>/dev/null | tr -d \' \\t\\r\\n\')" ] \\\n': (
                '        && { [ "$(startup_field_at "$STARTUP_C1" child_cmdline_sha256)" = "$(sha256sum "/proc/$CHILD_PID/cmdline" 2>/dev/null | awk \'{print $1}\')" ] \\\n'
                '            || ' + marker + '; } \\\n'
                '        && [ "$(startup_field_at "$STARTUP_C1" child_cmdline_sha256)" = "$(runtime_lock_field expected_daemon_cmdline_sha256)" ] \\\n'
                '        && { [ "$(startup_field_at "$STARTUP_C1" child_cmdline_bytes)" = "$(wc -c < "/proc/$CHILD_PID/cmdline" 2>/dev/null | tr -d \' \\t\\r\\n\')" ] \\\n'
                '            || ' + marker + '; } \\\n'
            ),
            '        && [ "$(startup_field_at "$STARTUP_C1" child_comm)" = dcentrald ] \\\n'
            '        && [ "$(startup_field_at "$STARTUP_C1" child_exe)" = "$TRIAL_BIN" ] \\\n': (
                '        && [ "$(startup_field_at "$STARTUP_C1" child_comm)" = dcentrald ] \\\n'
                '        && { [ "$(startup_field_at "$STARTUP_C1" child_exe)" = "$TRIAL_BIN" ] \\\n'
                '            || ' + marker + '; } \\\n'
            ),
        }
        for old, new in adapters.items():
            self.assertEqual(source.count(old), 1, old)
            source = source.replace(old, new)
        patched = temp / "j2_orphan_run_trial"
        patched.write_text(source, encoding="utf-8", newline="\n")
        return patched

    def test_wrapper_reparenting_fix_contract(self) -> None:
        source = (SCRIPTS / "dcentrald_s19k_tmp_remote_run.sh").read_text(
            encoding="utf-8"
        )
        serial = (
            ROOT / "dcentrald" / "dcentrald" / "src" / "serial_mining.rs"
        ).read_text(encoding="utf-8")
        # The live-PPID re-verification of the J0 wrapper is gone: reparenting
        # on parent exit is kernel-controlled and must not kill the J2/release
        # handshake (2026-08-26 live failure root cause).
        self.assertNotIn(
            '[ "$(process_ppid "$$")" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_ppid)" ]',
            source,
        )
        # J2's writer_ppid records the J1/J0 journal value, not a live ppid.
        self.assertIn(
            '    WRAPPER_PPID=$(startup_field_at "$STARTUP_J1" wrapper_ppid)\n'
            '    valid_uint "$WRAPPER_PPID" || return 1\n'
            '    ACTIVE_SHA=$(sha256sum "$ACTIVE" | awk \'{print $1}\')\n',
            source,
        )
        # The pre-fork J0 capture still reads the live ppid exactly once, and
        # the immediate pre-publication re-verify is intact.
        self.assertEqual(source.count('WRAPPER_PPID=$(process_ppid "$$")'), 1)
        self.assertIn('[ "$(process_ppid "$$")" = "$WRAPPER_PPID" ]', source)
        # Every other wrapper-identity conjunct remains pinned.
        self.assertIn(
            '&& [ "$(cat "/proc/$$/comm" 2>/dev/null || true)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_comm)" ]',
            source,
        )
        self.assertIn(
            '&& [ "$(readlink "/proc/$$/exe" 2>/dev/null || true)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_exe)" ]',
            source,
        )
        # The daemon-side record equality the journal-sourced writer_ppid must
        # keep satisfying (holds for both the old and fixed daemon lifetime
        # checks; the fixed daemon drops only the live-PPID conjunct).
        self.assertIn(
            's19k_journal_field(&j2, "writer_ppid")? == wrapper_ppid.to_string()',
            serial,
        )

    @unittest.skipUnless(os.name == "nt", "WSL J2 orphan publication exercise")
    def test_j2_release_publication_survives_wrapper_orphaning(self) -> None:
        """The J0->C1->J1->ACTIVE->J2/release handshake must survive wrapper
        reparenting (kernel reparenting on parent exit between ACTIVE and J2
        publication). On the pre-fix runner this reproduced the live 2026-08-26
        failure verbatim ("parent could not publish exact J2/release; child
        remains blocked and J0 custody remains"); with the fix the orphaned
        wrapper completes publication, the child admits the release token, and
        the trial retires cleanly without SafeOff or stock signaling."""
        remote_dir = subprocess.check_output(
            ["wsl.exe", "mktemp", "-d", "/tmp/dcentrald_bench_t1_j2orphan.XXXXXX"],
            text=True,
        ).strip()
        runtime_lock = f"{remote_dir}.board-global-lock"
        out_log = f"{remote_dir}.out"
        pid_file = f"{remote_dir}.wrapper_pid"
        launcher = f"{remote_dir}.launcher"
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            helper = self._j2_orphan_fixture_runner(temp, remote_dir, runtime_lock)
            model_sha = hashlib.sha256(
                (temp / "fixture_bosminer_model.json").read_bytes()
            ).hexdigest()
            fixture_dir = f"{remote_dir}/live_identity_fixture"
            binary = temp / "dcentrald"
            config = temp / "dcentrald_s19k.toml"
            binary.write_text(
                J2_ORPHAN_FAKE_DAEMON
                .replace("__GPIO__", f"{fixture_dir}/gpio")
                .replace("__PROFILE__", "held78_three_bhb56902_slots_1_2_3")
                .replace("__MODEL_SHA__", model_sha),
                encoding="utf-8",
                newline="\n",
            )
            config.write_text(
                "[watchdog]\nenabled = false\n", encoding="utf-8", newline="\n"
            )
            files = {
                "dcentrald": binary,
                "dcentrald_s19k.toml": config,
                "run_trial": helper,
                "supervisor_custody_observer": SUPERVISOR_CUSTODY,
                "stock_restart_helper": STOCK_RESTART_HELPER,
            }
            for name, local in files.items():
                subprocess.run(
                    ["wsl.exe", "cp", self._shell_path(local), f"{remote_dir}/{name}"],
                    check=True,
                )
            subprocess.run(
                ["wsl.exe", "chmod", "755", f"{remote_dir}/dcentrald",
                 f"{remote_dir}/run_trial"],
                check=True,
            )
            args: list[str] = []
            for name in (
                "dcentrald",
                "dcentrald_s19k.toml",
                "run_trial",
                "supervisor_custody_observer",
                "stock_restart_helper",
            ):
                blob = files[name].read_bytes()
                args.extend([hashlib.sha256(blob).hexdigest(), str(len(blob))])
            subprocess.run(
                ["wsl.exe", "touch", f"{remote_dir}/.fake_daemon_adapter"], check=True
            )
            launcher_local = temp / "j2_orphan_launcher.sh"
            launcher_local.write_text(
                J2_ORPHAN_LAUNCHER, encoding="utf-8", newline="\n"
            )
            subprocess.run(
                ["wsl.exe", "cp", self._shell_path(launcher_local), launcher],
                check=True,
            )
            subprocess.run(["wsl.exe", "chmod", "755", launcher], check=True)
            subprocess.run(
                [
                    "wsl.exe",
                    "sh",
                    "-c",
                    "exec "
                    + shlex.quote(launcher)
                    + " "
                    + " ".join(
                        shlex.quote(value)
                        for value in ["runtime_active", out_log, pid_file, *args]
                    ),
                ],
                timeout=300,
                check=False,
            )
            deadline = time.monotonic() + 300.0
            wrapper_exited = False
            while time.monotonic() < deadline:
                probe = subprocess.run(
                    [
                        "wsl.exe",
                        "sh",
                        "-c",
                        f"test -s {shlex.quote(pid_file)} && "
                        f"! kill -0 $(cat {shlex.quote(pid_file)}) 2>/dev/null",
                    ],
                    capture_output=True,
                )
                if probe.returncode == 0:
                    wrapper_exited = True
                    break
                time.sleep(2.0)
            self.assertTrue(wrapper_exited, "orphaned wrapper did not terminate")
            time.sleep(2.0)
            log = subprocess.check_output(
                ["wsl.exe", "cat", out_log], text=True
            )
            trace = subprocess.check_output(
                ["wsl.exe", "cat", f"{remote_dir}/.fake_daemon_trace"], text=True
            )
            self.assertNotIn(
                "parent could not publish exact J2/release", log
            )
            self.assertIn(
                "S19k pre-J3 startup custody retired and consumed without "
                "SafeOff or stock signaling",
                log,
            )
            self.assertIn("token admitted; running bounded work", trace)
            self.assertIn("daemon exit 0", trace)
            self.assertNotEqual(
                subprocess.run(
                    ["wsl.exe", "test", "-e", runtime_lock]
                ).returncode,
                0,
                "clean no-effect retirement must remove the lock container",
            )
        # Cleanup must use single-statement argv-mode wsl.exe calls: wsl.exe
        # re-splits multi-statement `sh -c` payloads on ';' and can drop the
        # trailing statements entirely.
        subprocess.run(
            [
                "wsl.exe",
                "sh",
                "-c",
                f"kill -9 $(cat {shlex.quote(pid_file)}) 2>/dev/null",
            ],
            check=False,
        )
        subprocess.run(
            [
                "wsl.exe",
                "pkill",
                "-f",
                "dcentrald_bench_t1_[j]2orphan",
            ],
            check=False,
        )
        self._cleanup_identity_fixture(remote_dir)
        subprocess.run(
            [
                "wsl.exe",
                "rm",
                "-rf",
                remote_dir,
                runtime_lock,
                launcher,
                out_log,
                pid_file,
            ],
            check=False,
        )

    @unittest.skipUnless(os.name == "nt", "WSL recovery environment exercise")
    def test_recovery_safeoff_discards_hostile_inherited_environment(self) -> None:
        remote_dir = subprocess.check_output(
            ["wsl.exe", "mktemp", "-d", "/tmp/dcentrald_bench_t1_cleanrecover.XXXXXX"],
            text=True,
        ).strip()
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            runtime_lock = f"{remote_dir}.board-global-lock"
            helper = self._identity_bound_runner(
                temp, remote_dir, runtime_lock=runtime_lock
            )
            model_sha = hashlib.sha256(
                (temp / "fixture_bosminer_model.json").read_bytes()
            ).hexdigest()
            binary = temp / "dcentrald"
            config = temp / "dcentrald_s19k.toml"
            binary.write_text(
                "#!/bin/sh\n"
                "source_path=; destination_path=; previous=\n"
                "for arg in \"$@\"; do\n"
                "  case \"$previous\" in\n"
                "    source) source_path=$arg ;;\n"
                "    destination) destination_path=$arg ;;\n"
                "  esac\n"
                "  case \"$arg\" in\n"
                "    --s19k-track1-journal-source) previous=source; continue ;;\n"
                "    --s19k-track1-journal-destination) previous=destination; continue ;;\n"
                "  esac\n"
                "  previous=\n"
                "done\n"
                "if [ -n \"$source_path\" ] && [ -n \"$destination_path\" ]; then\n"
                "  ln \"$source_path\" \"$destination_path\"\n"
                "  exit $?\n"
                "fi\n"
                f"printf '1\\n' > {shlex.quote(remote_dir + '/live_identity_fixture/gpio/gpio437/value')}\n"
                f"printf '0\\n' > {shlex.quote(remote_dir + '/live_identity_fixture/gpio/gpio454/value')}\n"
                f"printf '0\\n' > {shlex.quote(remote_dir + '/live_identity_fixture/gpio/gpio455/value')}\n"
                f"printf '0\\n' > {shlex.quote(remote_dir + '/live_identity_fixture/gpio/gpio456/value')}\n"
                'env > "$0.recovery-env"\n'
                "printf '%s\\n' \"DCENT_S19K_TRACK1_SAFEOFF_RECEIPT "
                "schema=dcentos.s19k-track1-safeoff/v1 "
                "live_identity_sha256=$DCENT_S19K_LIVE_IDENTITY_SHA256 "
                "live_identity_profile=held78_three_bhb56902_slots_1_2_3 "
                f"live_identity_model_sha256={model_sha} "
                "live_identity_board_count=3 "
                "live_identity_physical_addresses=1,2,3 "
                "live_identity_board_names=BHB56902,BHB56902,BHB56902 "
                "live_identity_eeprom=0x50=05:11,0x51=05:11,0x52=05:11 "
                'resets=454:0,455:0,456:0 psu=437:1"\n',
                encoding="utf-8",
                newline="\n",
            )
            config.write_text("recovery-fixture", encoding="utf-8")
            files = {
                "dcentrald": binary,
                "dcentrald_s19k.toml": config,
                "run_trial": helper,
                "supervisor_custody_observer": SUPERVISOR_CUSTODY,
                "stock_restart_helper": STOCK_RESTART_HELPER,
            }
            disguised_owner_pid = ""
            disguised_owner_process: subprocess.Popen[bytes] | None = None
            competing_wrapper_process: subprocess.Popen[bytes] | None = None
            second_bosminer_process: subprocess.Popen[bytes] | None = None
            second_bosminer_pid = ""
            second_remote_dir = ""
            try:
                for name, source in files.items():
                    subprocess.run(
                        [
                            "wsl.exe",
                            "cp",
                            self._shell_path(source),
                            f"{remote_dir}/{name}",
                        ],
                        check=True,
                    )
                subprocess.run(
                    ["wsl.exe", "chmod", "755", f"{remote_dir}/dcentrald"],
                    check=True,
                )
                bindings: dict[str, tuple[str, int]] = {}
                args: list[str] = []
                for name in (
                    "dcentrald",
                    "dcentrald_s19k.toml",
                    "run_trial",
                    "supervisor_custody_observer",
                    "stock_restart_helper",
                ):
                    blob = files[name].read_bytes()
                    binding = (hashlib.sha256(blob).hexdigest(), len(blob))
                    bindings[name] = binding
                    args.extend([binding[0], str(binding[1])])
                live_identity_sha = self._probe_identity(remote_dir, args)
                receipt = temp / "runtime_active"
                receipt.write_bytes(
                    (
                        "schema=dcentos.s19k-tmp-runtime/v5\n"
                        "phase=launch-pending-or-recovery-required\n"
                        "wrapper_pid=2147483647\n"
                        "wrapper_start=1\n"
                        "child_pid=0\n"
                        "child_start=0\n"
                        "supervisor_pid=1458\n"
                        "supervisor_start=1251\n"
                        "supervisor_ppid=1\n"
                        "supervisor_pgrp=1457\n"
                        "supervisor_session=1457\n"
                        "supervisor_exe=/usr/bin/bos-tools\n"
                        "supervisor_cmdline_sha256=2e8273fd19bccb1b1744b2f26f48825aae6de73e55be9919a472d0a953cfac52\n"
                        "supervisor_cmdline_bytes=68\n"
                        "bosminer_pid=9495\n"
                        "bosminer_start=1044815\n"
                        "bosminer_ppid=1458\n"
                        "bosminer_pgrp=1457\n"
                        "bosminer_session=1457\n"
                        "bosminer_exe=/usr/bin/bosminer\n"
                        "bosminer_cmdline_sha256=465804a74a48655761ec62edfd4e08659b6fcaf7486e475260c1e490f2e9d3d3\n"
                        "bosminer_cmdline_bytes=32\n"
                        f"stock_pidfile_path={remote_dir}/live_identity_fixture/bosminer.pid\n"
                        "stock_pidfile_sha256=4574cce19d396d4f7936ee9604f4d8ac809067746a51c6a6ba40d81a592d336c\n"
                        "stock_pidfile_bytes=5\n"
                        f"binary_sha256={bindings['dcentrald'][0]}\n"
                        f"binary_bytes={bindings['dcentrald'][1]}\n"
                        f"config_sha256={bindings['dcentrald_s19k.toml'][0]}\n"
                        f"config_bytes={bindings['dcentrald_s19k.toml'][1]}\n"
                        f"runner_sha256={bindings['run_trial'][0]}\n"
                        f"runner_bytes={bindings['run_trial'][1]}\n"
                        f"custody_observer_sha256={bindings['supervisor_custody_observer'][0]}\n"
                        f"custody_observer_bytes={bindings['supervisor_custody_observer'][1]}\n"
                        f"stock_restart_helper_sha256={bindings['stock_restart_helper'][0]}\n"
                        f"stock_restart_helper_bytes={bindings['stock_restart_helper'][1]}\n"
                        "live_identity_schema=dcentos.s19k-braiins-live-identity/v2\n"
                        "live_identity_profile=held78_three_bhb56902_slots_1_2_3\n"
                        f"live_identity_sha256={live_identity_sha}\n"
                        "deploy_mode=mining-on-passthrough\n"
                        "persistent_mutation=false\n"
                    ).encode("ascii")
                )
                subprocess.run(
                    [
                        "wsl.exe",
                        "cp",
                        self._shell_path(receipt),
                        f"{remote_dir}/runtime_active",
                    ],
                    check=True,
                )
                runner_argv = [
                    f"{remote_dir}/run_trial",
                    "restore",
                    remote_dir,
                    "am3-s19k",
                    "recovery",
                    *args,
                ]
                hostile_names = (
                    "DCENT_S19K_CHIP_FASTUART",
                    "DCENT_S19K_TRACK1_RETRY_115200",
                    "DCENT_S19K_EXPERIMENTAL_POST_CLEAN_CHAIN_INACTIVE",
                    "DCENT_S19K_EXPERIMENTAL_POST_CLEAN_JOB_FLIP",
                    "DCENT_S19K_EXPERIMENTAL_WRAP4_EARLY_CLEAN",
                    "DCENT_BRAIINS_TTYS_BENCH_GO",
                    "DCENT_S19K_UART_EEPROM",
                    "DCENT_S19K_I2CDETECT",
                )
                hostile_prefix = (
                    " ".join(f"{name}=hostile" for name in hostile_names)
                    + " PATH=/definitely/not/operator/path"
                )
                command = (
                    hostile_prefix
                    + " "
                    + " ".join(
                        shlex.quote(value) for value in ["/bin/sh", *runner_argv]
                    )
                )

                # Schema admission is exact: an unknown extra field cannot be
                # ignored by a newer/older recovery helper.
                extra_field_receipt = temp / "runtime_active.extra-field"
                extra_field_receipt.write_bytes(
                    receipt.read_bytes() + b"unknown_authority=true\n"
                )
                subprocess.run(
                    [
                        "wsl.exe",
                        "cp",
                        self._shell_path(extra_field_receipt),
                        f"{remote_dir}/runtime_active",
                    ],
                    check=True,
                )
                extra_field = subprocess.run(
                    ["wsl.exe", "sh", "-c", command],
                    text=True,
                    capture_output=True,
                    timeout=45,
                )
                self.assertNotEqual(extra_field.returncode, 0)
                self.assertIn(
                    "runtime receipt failed exact v5 field/pidfile/artifact admission",
                    extra_field.stderr,
                )
                self.assertNotEqual(
                    subprocess.run(["wsl.exe", "test", "-e", runtime_lock]).returncode,
                    0,
                )

                # Phase names are behavioral contracts, not labels.  A
                # pending receipt may not smuggle a child lifetime into the
                # signal path before the atomic custody lock is established.
                invalid_phase_receipt = temp / "runtime_active.invalid-phase"
                invalid_phase_receipt.write_bytes(
                    receipt.read_bytes()
                    .replace(b"child_pid=0\n", b"child_pid=2147483645\n")
                    .replace(b"child_start=0\n", b"child_start=1\n")
                )
                subprocess.run(
                    [
                        "wsl.exe",
                        "cp",
                        self._shell_path(invalid_phase_receipt),
                        f"{remote_dir}/runtime_active",
                    ],
                    check=True,
                )
                invalid_phase = subprocess.run(
                    ["wsl.exe", "sh", "-c", command],
                    text=True,
                    capture_output=True,
                    timeout=45,
                )
                self.assertNotEqual(invalid_phase.returncode, 0)
                self.assertIn(
                    "runtime receipt failed exact v5 field/pidfile/artifact admission",
                    invalid_phase.stderr,
                )
                self.assertNotEqual(
                    subprocess.run(["wsl.exe", "test", "-e", runtime_lock]).returncode,
                    0,
                )
                subprocess.run(
                    [
                        "wsl.exe",
                        "cp",
                        self._shell_path(receipt),
                        f"{remote_dir}/runtime_active",
                    ],
                    check=True,
                )
                result = subprocess.run(
                    ["wsl.exe", "sh", "-c", command],
                    text=True,
                    capture_output=True,
                    timeout=45,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                captured = subprocess.check_output(
                    ["wsl.exe", "cat", f"{remote_dir}/dcentrald.recovery-env"],
                    text=True,
                )
                self.assertIn("PATH=/usr/bin:/bin:/usr/sbin:/sbin", captured)
                self.assertIn("DCENTOS_EPHEMERAL_RUNTIME=1", captured)
                self.assertIn("DCENTOS_LOG_RING_DIR=/tmp/dcent/log", captured)
                self.assertNotIn("DCENT_S19K_TRACK1_STOP_SAFEOFF=", captured)
                self.assertIn(
                    f"DCENT_S19K_LIVE_IDENTITY_SHA256={live_identity_sha}", captured
                )
                for hostile in hostile_names:
                    self.assertNotIn(f"{hostile}=", captured)
                self._assert_stock_restart_pending_and_reset_fixture(
                    remote_dir, runtime_lock
                )

                # Losing a tmpfs receipt is not positive SafeOff evidence.
                # With no live owner, recovery must establish fresh exact
                # identity and invoke the same checked reset+cut command.
                subprocess.run(
                    ["wsl.exe", "rm", "-f", f"{remote_dir}/dcentrald.recovery-env"],
                    check=True,
                )
                # Model stock recovery before injecting a new run's pre-J0
                # crash. The live .88 baseline is PSU engaged with chains 2/3
                # released and the unused reset held low.
                for gpio, value in ((437, 0), (454, 0), (455, 1), (456, 1)):
                    baseline_value = temp / f"fixture_gpio{gpio}_stock_baseline"
                    baseline_value.write_text(
                        f"{value}\n", encoding="utf-8", newline="\n"
                    )
                    subprocess.run(
                        [
                            "wsl.exe",
                            "cp",
                            self._shell_path(baseline_value),
                            f"{remote_dir}/live_identity_fixture/gpio/gpio{gpio}/value",
                        ],
                        check=True,
                    )
                # Simulate SIGKILL in the tiny mkdir-to-J0-hardlink window.
                # The exact root-owned 0700 empty directory is only a neutral
                # container: recovery must reprove stock/identity/GPIO and
                # retire it without SafeOff or a restart obligation.
                subprocess.run(["wsl.exe", "mkdir", runtime_lock], check=True)
                subprocess.run(["wsl.exe", "chmod", "700", runtime_lock], check=True)
                self.assertNotEqual(
                    subprocess.run(
                        ["wsl.exe", "test", "-e", f"{runtime_lock}/owner"]
                    ).returncode,
                    0,
                )
                neutral_pre_j0 = subprocess.run(
                    ["wsl.exe", "sh", "-c", command],
                    text=True,
                    capture_output=True,
                    timeout=45,
                )
                self.assertEqual(neutral_pre_j0.returncode, 0, neutral_pre_j0.stderr)
                self.assertIn(
                    "neutral pre-J0 lock container retired without SafeOff or stock signaling",
                    neutral_pre_j0.stdout,
                )
                self.assertNotEqual(
                    subprocess.run(
                        [
                            "wsl.exe",
                            "test",
                            "-f",
                            f"{remote_dir}/dcentrald.recovery-env",
                        ]
                    ).returncode,
                    0,
                )
                self.assertNotEqual(
                    subprocess.run(["wsl.exe", "test", "-e", runtime_lock]).returncode,
                    0,
                )

                # A `pidof` miss is not proof that the daemon owner is gone.
                # This fixture forces every dcentrald pidof probe false; the
                # executable-basename scan must still refuse the live owner.
                subprocess.run(
                    ["wsl.exe", "rm", "-f", f"{remote_dir}/dcentrald.recovery-env"],
                    check=True,
                )
                subprocess.run(
                    ["wsl.exe", "mkdir", f"{remote_dir}/disguised-owner"], check=True
                )
                subprocess.run(
                    [
                        "wsl.exe",
                        "cp",
                        "/bin/sleep",
                        f"{remote_dir}/disguised-owner/dcentrald",
                    ],
                    check=True,
                )
                disguised_owner_process = subprocess.Popen(
                    ["wsl.exe", f"{remote_dir}/disguised-owner/dcentrald", "30"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                for _ in range(20):
                    owner_probe = subprocess.run(
                        ["wsl.exe", "pidof", "dcentrald"],
                        text=True,
                        capture_output=True,
                    )
                    if owner_probe.returncode == 0:
                        disguised_owner_pid = owner_probe.stdout.strip()
                        break
                    time.sleep(0.05)
                self.assertRegex(disguised_owner_pid, r"^[0-9]+$")
                disguised_refused = subprocess.run(
                    ["wsl.exe", "sh", "-c", command],
                    text=True,
                    capture_output=True,
                    timeout=45,
                )
                self.assertNotEqual(disguised_refused.returncode, 0)
                self.assertIn(
                    "dcentrald is live without a bound runtime receipt",
                    disguised_refused.stderr,
                )
                self.assertNotEqual(
                    subprocess.run(
                        [
                            "wsl.exe",
                            "test",
                            "-e",
                            f"{remote_dir}/dcentrald.recovery-env",
                        ]
                    ).returncode,
                    0,
                )
                subprocess.run(["wsl.exe", "kill", disguised_owner_pid], check=True)
                disguised_owner_pid = ""
                disguised_owner_process.wait(timeout=5)
                disguised_owner_process = None

                # A second wrapper can still own a pending handoff even when
                # its child is not visible and tmpfs receipt state was lost.
                competing_wrapper_process = subprocess.Popen(
                    [
                        "wsl.exe",
                        "sh",
                        "-c",
                        "sleep 30 & wait",
                        f"{remote_dir}/run_trial",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                time.sleep(0.1)
                wrapper_refused = subprocess.run(
                    ["wsl.exe", "sh", "-c", command],
                    text=True,
                    capture_output=True,
                    timeout=45,
                )
                self.assertNotEqual(wrapper_refused.returncode, 0)
                self.assertIn(
                    "another Track-1 wrapper is live without a bound runtime receipt",
                    wrapper_refused.stderr,
                )
                self.assertNotEqual(
                    subprocess.run(
                        [
                            "wsl.exe",
                            "test",
                            "-e",
                            f"{remote_dir}/dcentrald.recovery-env",
                        ]
                    ).returncode,
                    0,
                )
                competing_wrapper_process.terminate()
                competing_wrapper_process.wait(timeout=5)
                competing_wrapper_process = None

                # Custody is board-global, not content-directory-local.  A
                # stale owner record from a dead v1 wrapper must block a v2
                # launch, then permit only fresh-identity + checked-SafeOff
                # receiptless recovery after every process owner is gone.
                second_remote_dir = subprocess.check_output(
                    [
                        "wsl.exe",
                        "mktemp",
                        "-d",
                        "/tmp/dcentrald_bench_t1_crossversion.XXXXXX",
                    ],
                    text=True,
                ).strip()
                second_temp = temp / "version2"
                second_temp.mkdir()
                second_helper = self._identity_bound_runner(
                    second_temp,
                    second_remote_dir,
                    runtime_lock=runtime_lock,
                )
                second_helper.write_text(
                    second_helper.read_text(encoding="utf-8")
                    + "\n# distinct content version for board-global custody regression\n",
                    encoding="utf-8",
                    newline="\n",
                )
                second_binary = second_temp / "dcentrald"
                second_binary.write_bytes(
                    binary.read_bytes().replace(
                        remote_dir.encode("ascii"), second_remote_dir.encode("ascii")
                    )
                )
                second_files = {
                    "dcentrald": second_binary,
                    "dcentrald_s19k.toml": config,
                    "run_trial": second_helper,
                    "supervisor_custody_observer": SUPERVISOR_CUSTODY,
                    "stock_restart_helper": STOCK_RESTART_HELPER,
                }
                for name, source_file in second_files.items():
                    subprocess.run(
                        [
                            "wsl.exe",
                            "cp",
                            self._shell_path(source_file),
                            f"{second_remote_dir}/{name}",
                        ],
                        check=True,
                    )
                subprocess.run(
                    ["wsl.exe", "cp", "/bin/sleep", f"{second_remote_dir}/bosminer"],
                    check=True,
                )
                subprocess.run(
                    [
                        "wsl.exe",
                        "chmod",
                        "755",
                        f"{second_remote_dir}/dcentrald",
                        f"{second_remote_dir}/bosminer",
                    ],
                    check=True,
                )
                second_args: list[str] = []
                for name in (
                    "dcentrald",
                    "dcentrald_s19k.toml",
                    "run_trial",
                    "supervisor_custody_observer",
                    "stock_restart_helper",
                ):
                    blob = second_files[name].read_bytes()
                    second_args.extend(
                        [hashlib.sha256(blob).hexdigest(), str(len(blob))]
                    )
                self.assertEqual(
                    live_identity_sha,
                    self._probe_identity(second_remote_dir, second_args),
                )

                owner = temp / "dead-version-owner"
                owner.write_bytes(
                    (
                        "schema=dcentos.s19k-track1-runtime-lock/v6\n"
                        "owner_kind=launch\n"
                        f"trial_dir={remote_dir}\n"
                        f"runner_sha256={bindings['run_trial'][0]}\n"
                        f"runner_bytes={bindings['run_trial'][1]}\n"
                        f"custody_observer_sha256={bindings['supervisor_custody_observer'][0]}\n"
                        f"custody_observer_bytes={bindings['supervisor_custody_observer'][1]}\n"
                        f"stock_restart_helper_sha256={bindings['stock_restart_helper'][0]}\n"
                        f"stock_restart_helper_bytes={bindings['stock_restart_helper'][1]}\n"
                        f"live_identity_sha256={live_identity_sha}\n"
                    ).encode("ascii")
                )
                subprocess.run(["wsl.exe", "mkdir", runtime_lock], check=True)
                subprocess.run(["wsl.exe", "chmod", "700", runtime_lock], check=True)
                subprocess.run(
                    ["wsl.exe", "cp", self._shell_path(owner), f"{runtime_lock}/owner"],
                    check=True,
                )
                self.assertEqual(
                    subprocess.run(
                        ["wsl.exe", "test", "-f", f"{runtime_lock}/owner"]
                    ).returncode,
                    0,
                )
                second_run_argv = [
                    f"{second_remote_dir}/run_trial",
                    "run",
                    second_remote_dir,
                    "am3-s19k",
                    "mining-on-passthrough",
                    *second_args,
                ]
                second_bosminer_process = subprocess.Popen(
                    ["wsl.exe", f"{second_remote_dir}/bosminer", "30"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                for _ in range(20):
                    owner_probe = subprocess.run(
                        ["wsl.exe", "pidof", "bosminer"],
                        text=True,
                        capture_output=True,
                    )
                    if owner_probe.returncode == 0:
                        second_bosminer_pid = owner_probe.stdout.strip()
                        break
                    time.sleep(0.05)
                self.assertRegex(second_bosminer_pid, r"^[0-9]+$")
                second_launch = subprocess.run(
                    ["wsl.exe", "sh", *second_run_argv],
                    text=True,
                    capture_output=True,
                    timeout=45,
                )
                self.assertNotEqual(
                    second_launch.returncode,
                    0,
                    f"stdout={second_launch.stdout!r} stderr={second_launch.stderr!r}",
                )
                self.assertIn("board-global runtime lock", second_launch.stderr)
                self.assertNotEqual(
                    subprocess.run(
                        ["wsl.exe", "test", "-e", f"{second_remote_dir}/runtime_active"]
                    ).returncode,
                    0,
                )
                subprocess.run(["wsl.exe", "kill", second_bosminer_pid], check=True)
                second_bosminer_pid = ""
                second_bosminer_process.wait(timeout=5)
                second_bosminer_process = None
                second_restore_argv = [
                    f"{second_remote_dir}/run_trial",
                    "restore",
                    second_remote_dir,
                    "am3-s19k",
                    "recovery",
                    *second_args,
                ]
                second_restore = subprocess.run(
                    ["wsl.exe", "sh", *second_restore_argv],
                    text=True,
                    capture_output=True,
                    timeout=45,
                )
                self.assertNotEqual(
                    second_restore.returncode,
                    0,
                    f"stdout={second_restore.stdout!r} stderr={second_restore.stderr!r}",
                )
                self.assertIn(
                    "recovery source deploy mode is unavailable",
                    second_restore.stderr,
                    f"returncode={second_restore.returncode} stdout={second_restore.stdout!r}",
                )
                self.assertNotEqual(
                    subprocess.run(
                        [
                            "wsl.exe",
                            "test",
                            "-f",
                            f"{second_remote_dir}/dcentrald.recovery-env",
                        ]
                    ).returncode,
                    0,
                )
                for absent_path in (
                    f"{second_remote_dir}/runtime_active",
                    f"{second_remote_dir}/runtime_safeoff_terminal_receipt",
                ):
                    self.assertNotEqual(
                        subprocess.run(
                            ["wsl.exe", "test", "-e", absent_path]
                        ).returncode,
                        0,
                        absent_path,
                    )
                self.assertEqual(
                    subprocess.run(
                        ["wsl.exe", "test", "-f", f"{runtime_lock}/owner"]
                    ).returncode,
                    0,
                    "ambiguous recovery must retain global custody",
                )
                for gpio, expected in ((437, "0"), (454, "0"), (455, "1"), (456, "1")):
                    observed = subprocess.check_output(
                        [
                            "wsl.exe",
                            "cat",
                            f"{second_remote_dir}/live_identity_fixture/gpio/gpio{gpio}/value",
                        ],
                        text=True,
                    ).strip()
                    self.assertEqual(observed, expected, f"GPIO{gpio}")
                # Test-only teardown of the exact retained obligation lets the
                # independent wrong-receipt case below acquire its own lock.
                subprocess.run(
                    ["wsl.exe", "rm", "-f", f"{runtime_lock}/owner"], check=True
                )
                subprocess.run(["wsl.exe", "rmdir", runtime_lock], check=True)

                # A typed receipt is only authoritative for the exact held
                # reset/power tuple; schema-only or arbitrary GPIO admission
                # must not turn an incompatible action into success.
                prior_binary_binding = bindings["dcentrald"]
                binary.write_bytes(
                    binary.read_bytes().replace(
                        b"resets=454:0,455:0,456:0 psu=437:1",
                        b"resets=453:0,455:0,456:0 psu=437:1",
                    )
                )
                subprocess.run(
                    [
                        "wsl.exe",
                        "cp",
                        self._shell_path(binary),
                        f"{remote_dir}/dcentrald",
                    ],
                    check=True,
                )
                bad_receipt_blob = binary.read_bytes()
                bindings["dcentrald"] = (
                    hashlib.sha256(bad_receipt_blob).hexdigest(),
                    len(bad_receipt_blob),
                )
                wrong_tuple_receipt_blob = receipt.read_bytes()
                prior_binary_row = (
                    f"binary_sha256={prior_binary_binding[0]}\n"
                    f"binary_bytes={prior_binary_binding[1]}\n"
                ).encode("ascii")
                wrong_tuple_binary_row = (
                    f"binary_sha256={bindings['dcentrald'][0]}\n"
                    f"binary_bytes={bindings['dcentrald'][1]}\n"
                ).encode("ascii")
                self.assertEqual(wrong_tuple_receipt_blob.count(prior_binary_row), 1)
                wrong_tuple_receipt = temp / "runtime_active.wrong-tuple"
                wrong_tuple_receipt.write_bytes(
                    wrong_tuple_receipt_blob.replace(
                        prior_binary_row, wrong_tuple_binary_row
                    )
                )
                subprocess.run(
                    [
                        "wsl.exe",
                        "cp",
                        self._shell_path(wrong_tuple_receipt),
                        f"{remote_dir}/runtime_active",
                    ],
                    check=True,
                )
                args = []
                for name in (
                    "dcentrald",
                    "dcentrald_s19k.toml",
                    "run_trial",
                    "supervisor_custody_observer",
                    "stock_restart_helper",
                ):
                    binding = bindings[name]
                    args.extend([binding[0], str(binding[1])])
                self._probe_identity(remote_dir, args)
                runner_argv = [
                    f"{remote_dir}/run_trial",
                    "restore",
                    remote_dir,
                    "am3-s19k",
                    "recovery",
                    *args,
                ]
                command = (
                    hostile_prefix
                    + " "
                    + " ".join(
                        shlex.quote(value) for value in ["/bin/sh", *runner_argv]
                    )
                )
                wrong_tuple = subprocess.run(
                    ["wsl.exe", "sh", "-c", command],
                    text=True,
                    capture_output=True,
                    timeout=45,
                )
                self.assertNotEqual(wrong_tuple.returncode, 0)
                self.assertIn(
                    "recovery command returned no exact checked reset+cut receipt",
                    wrong_tuple.stderr,
                )
                self.assertEqual(
                    subprocess.run(["wsl.exe", "test", "-d", runtime_lock]).returncode,
                    0,
                )
                subprocess.run(
                    ["wsl.exe", "rm", "-f", f"{remote_dir}/runtime_active"],
                    check=True,
                )

                # A foreign same-total-size NAND layout must also stop the
                # receiptless route before the fake SafeOff binary is invoked.
                subprocess.run(
                    ["wsl.exe", "rm", "-f", f"{remote_dir}/dcentrald.recovery-env"],
                    check=True,
                )
                valid_mtd = (temp / "fixture_proc_mtd").read_text(encoding="utf-8")
                foreign_mtd = valid_mtd.replace(
                    "mtd2: 03200000", "mtd2: 03100000"
                ).replace("mtd4: 02000000", "mtd4: 02100000")
                self.assertEqual(len(foreign_mtd), len(valid_mtd))
                foreign_path = temp / "foreign_same_sum_proc_mtd"
                foreign_path.write_text(foreign_mtd, encoding="utf-8", newline="\n")
                subprocess.run(
                    [
                        "wsl.exe",
                        "cp",
                        self._shell_path(foreign_path),
                        f"{remote_dir}/live_identity_fixture/proc_mtd",
                    ],
                    check=True,
                )
                refused = subprocess.run(
                    ["wsl.exe", "sh", "-c", command],
                    text=True,
                    capture_output=True,
                    timeout=45,
                )
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn(
                    "not the exact held six-row Braiins AM3 layout", refused.stderr
                )
                self.assertNotEqual(
                    subprocess.run(
                        ["wsl.exe", "test", "-e", f"{remote_dir}/runtime_active"]
                    ).returncode,
                    0,
                )
                self.assertNotEqual(
                    subprocess.run(
                        [
                            "wsl.exe",
                            "test",
                            "-e",
                            f"{remote_dir}/dcentrald.recovery-env",
                        ]
                    ).returncode,
                    0,
                )
                self.assertEqual(
                    subprocess.run(
                        ["wsl.exe", "test", "-f", f"{runtime_lock}/owner"]
                    ).returncode,
                    0,
                    "malformed live identity must retain the global recovery obligation",
                )
            finally:
                if disguised_owner_pid:
                    subprocess.run(
                        ["wsl.exe", "kill", disguised_owner_pid], check=False
                    )
                if second_bosminer_pid:
                    subprocess.run(
                        ["wsl.exe", "kill", second_bosminer_pid], check=False
                    )
                for process in (
                    disguised_owner_process,
                    competing_wrapper_process,
                    second_bosminer_process,
                ):
                    if process is not None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                subprocess.run(
                    [
                        "wsl.exe",
                        "rm",
                        "-f",
                        f"{remote_dir}/dcentrald",
                        f"{remote_dir}/dcentrald_s19k.toml",
                        f"{remote_dir}/run_trial",
                        f"{remote_dir}/supervisor_custody_observer",
                        f"{remote_dir}/stock_restart_helper",
                        f"{remote_dir}/runtime_active",
                        f"{remote_dir}/dcentrald.recovery-env",
                        f"{remote_dir}/disguised-owner/dcentrald",
                    ],
                    check=False,
                )
                self._cleanup_identity_fixture(remote_dir)
                subprocess.run(
                    ["wsl.exe", "rmdir", f"{remote_dir}/disguised-owner"], check=False
                )
                if second_remote_dir:
                    subprocess.run(
                        [
                            "wsl.exe",
                            "rm",
                            "-f",
                            f"{second_remote_dir}/dcentrald",
                            f"{second_remote_dir}/dcentrald_s19k.toml",
                            f"{second_remote_dir}/run_trial",
                            f"{second_remote_dir}/supervisor_custody_observer",
                            f"{second_remote_dir}/stock_restart_helper",
                            f"{second_remote_dir}/bosminer",
                            f"{second_remote_dir}/runtime_active",
                            f"{second_remote_dir}/dcentrald.recovery-env",
                        ],
                        check=False,
                    )
                    self._cleanup_identity_fixture(second_remote_dir)
                    subprocess.run(["wsl.exe", "rmdir", second_remote_dir], check=False)
                subprocess.run(
                    ["wsl.exe", "rm", "-f", f"{runtime_lock}/owner"], check=False
                )
                subprocess.run(["wsl.exe", "rmdir", runtime_lock], check=False)
                subprocess.run(["wsl.exe", "rmdir", remote_dir], check=False)

    def _stage_trial_ceiling_fixture(
        self, temp: Path, stamp: str, daemon_text: str
    ) -> tuple[str, str, list[str]]:
        """Stage the proven J2-orphan WSL fixture (adapted runner, live-source
        trees, exact-stock baseline) for an attempt-10 hard-ceiling exercise
        with the supplied fake daemon text."""
        remote_dir = subprocess.check_output(
            ["wsl.exe", "mktemp", "-d", f"/tmp/dcentrald_bench_t1_{stamp}.XXXXXX"],
            text=True,
        ).strip()
        runtime_lock = f"{remote_dir}.board-global-lock"
        helper = self._j2_orphan_fixture_runner(temp, remote_dir, runtime_lock)
        model_sha = hashlib.sha256(
            (temp / "fixture_bosminer_model.json").read_bytes()
        ).hexdigest()
        fixture_dir = f"{remote_dir}/live_identity_fixture"
        binary = temp / f"{stamp}_dcentrald"
        config = temp / f"{stamp}_dcentrald_s19k.toml"
        binary.write_text(
            daemon_text
            .replace("__GPIO__", f"{fixture_dir}/gpio")
            .replace("__PROFILE__", "held78_three_bhb56902_slots_1_2_3")
            .replace("__MODEL_SHA__", model_sha),
            encoding="utf-8",
            newline="\n",
        )
        config.write_text(
            "[watchdog]\nenabled = false\n", encoding="utf-8", newline="\n"
        )
        files = {
            "dcentrald": binary,
            "dcentrald_s19k.toml": config,
            "run_trial": helper,
            "supervisor_custody_observer": SUPERVISOR_CUSTODY,
            "stock_restart_helper": STOCK_RESTART_HELPER,
        }
        for name, local in files.items():
            subprocess.run(
                ["wsl.exe", "cp", self._shell_path(local), f"{remote_dir}/{name}"],
                check=True,
            )
        subprocess.run(
            [
                "wsl.exe",
                "chmod",
                "755",
                f"{remote_dir}/dcentrald",
                f"{remote_dir}/run_trial",
            ],
            check=True,
        )
        subprocess.run(
            ["wsl.exe", "touch", f"{remote_dir}/.fake_daemon_adapter"], check=True
        )
        bound_args: list[str] = []
        for name in (
            "dcentrald",
            "dcentrald_s19k.toml",
            "run_trial",
            "supervisor_custody_observer",
            "stock_restart_helper",
        ):
            blob = files[name].read_bytes()
            bound_args.extend([hashlib.sha256(blob).hexdigest(), str(len(blob))])
        launcher_local = temp / f"{stamp}_launcher.sh"
        launcher_local.write_text(
            TRIAL_CEILING_LAUNCHER, encoding="utf-8", newline="\n"
        )
        subprocess.run(
            [
                "wsl.exe",
                "cp",
                self._shell_path(launcher_local),
                f"{remote_dir}.launcher",
            ],
            check=True,
        )
        subprocess.run(
            ["wsl.exe", "chmod", "755", f"{remote_dir}.launcher"], check=True
        )
        return remote_dir, runtime_lock, bound_args

    def _run_trial_ceiling_launcher(
        self,
        launcher: str,
        ceiling: str,
        deploy_mode: str,
        remote_dir: str,
        bound_args: list[str],
        out_log: str,
        rc_file: str,
        timeout: int,
    ) -> None:
        command = " ".join(
            shlex.quote(value)
            for value in [
                launcher,
                out_log,
                rc_file,
                ceiling,
                deploy_mode,
                remote_dir,
                *bound_args,
            ]
        )
        subprocess.run(
            ["wsl.exe", "sh", "-c", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def _cleanup_trial_ceiling_fixture(
        self,
        stamp: str,
        remote_dir: str,
        runtime_lock: str,
        out_log: str,
        rc_file: str,
    ) -> None:
        # The bracketed first stamp character keeps pkill from matching its
        # own command line (suite convention from the J2-orphan cleanup).
        subprocess.run(
            [
                "wsl.exe",
                "pkill",
                "-f",
                f"dcentrald_bench_t1_[{stamp[0]}]{stamp[1:]}",
            ],
            check=False,
        )
        self._cleanup_identity_fixture(remote_dir)
        subprocess.run(
            [
                "wsl.exe",
                "rm",
                "-rf",
                remote_dir,
                runtime_lock,
                f"{remote_dir}.launcher",
                out_log,
                rc_file,
            ],
            check=False,
        )

    def test_trial_ceiling_contract_is_exact_and_daemon_only(self) -> None:
        """Attempt-10 hard-ceiling source contract: the three one-shot Track-1
        trial authorities carry a wall-clock ceiling (attempt-9 wrapper
        deadlock defense-in-depth) whose only signal is an identity-fenced
        SIGKILL of the daemon child; stock supervisor/bosminer processes are
        never touched, the restore command is printed but never executed, the
        deployer's Run/Restore payload construction is untouched, and every
        non-one-shot mode keeps the original blocking wait."""
        source = (SCRIPTS / "dcentrald_s19k_tmp_remote_run.sh").read_text(
            encoding="utf-8"
        )
        # Default 900 s; operator override must be a canonical decimal
        # integer; sub-120 values are refused, never clamped.
        self.assertEqual(source.count("TRIAL_CEILING_SECONDS=900"), 1)
        self.assertIn(
            'if [ "$S19K_TMP_TRIAL_CEILING_SECONDS" -lt 120 ]; then',
            source,
        )
        self.assertIn(
            "S19K_TMP_TRIAL_CEILING_SECONDS must be at least 120",
            source,
        )
        self.assertIn("''|*[!0-9]*|0|0[0-9]*)", source)
        # Enforcement scope: exactly the four one-shot trial authorities
        # (install-custody-safeoff joined the ceiling set 2026-08-30; the
        # six-mode deploy validation above it stays intact).
        self.assertEqual(
            source.count(
                "    install-custody-safeoff|handoff-no-work|bounded-work-proof"
                "|endurance-work-proof)"
            ),
            1,
        )
        self.assertIn(
            "stage-only|mining-on-passthrough|install-custody-safeoff"
            "|handoff-no-work|bounded-work-proof|endurance-work-proof) ;;",
            source,
        )
        # The deadline arms only for enforced modes and only after the
        # admitted daemon fork.
        self.assertIn('if [ -n "$TRIAL_CEILING_SECONDS" ]; then', source)
        self.assertIn(
            "TRIAL_CEILING_DEADLINE=$(( $(date +%s) + TRIAL_CEILING_SECONDS ))",
            source,
        )
        # The final blocking wait is retained byte-for-byte for unenforced
        # modes and guarded by the deadline poll for the one-shot trials.
        self.assertEqual(source.count('if wait "$CHILD_PID"; then'), 1)
        self.assertIn('if [ -n "$TRIAL_CEILING_DEADLINE" ]; then', source)
        self.assertIn(
            'while process_matches "$CHILD_PID" "$CHILD_START"; do\n'
            "        trial_ceiling_expired && enforce_trial_ceiling_exit\n",
            source,
        )
        # The pre-J1 wait window is ceiling-bounded too (a daemon that never
        # publishes J1 and never exits must not pin the wrapper either).
        j1_wait = source[source.index('while [ ! -e "$STARTUP_J1" ]'):]
        self.assertIn(
            "trial_ceiling_expired && enforce_trial_ceiling_exit", j1_wait[:900]
        )
        # The enforcement block: the wrapper's ONLY kill -KILL anywhere is
        # the exact identity-fenced daemon child.
        self.assertEqual(source.count("kill -KILL"), 1)
        enforcement = source[
            source.index("enforce_trial_ceiling_exit() {"):
            source.index("set_expected_safeoff_receipt()")
        ]
        self.assertIn('kill -KILL "$CHILD_PID" 2>/dev/null', enforcement)
        self.assertIn("exact_dcentrald_child_matches", enforcement)
        # No stock-process targeting: outside comments, the enforcement code
        # never names or signals S99bosminer/bosminer/stock supervisors.
        enforcement_code = "\n".join(
            line
            for line in enforcement.splitlines()
            if not line.lstrip().startswith("#")
        )
        self.assertNotIn("bosminer", enforcement_code)
        self.assertNotIn("S99", enforcement_code)
        self.assertNotIn("pkill", enforcement_code)
        self.assertNotIn("killall", enforcement_code)
        # Typed transcript marker and a distinct wrapper exit status.
        self.assertIn(
            "S19K_TMP_TRIAL_CEILING_EXCEEDED schema=dcentos.s19k-trial-ceiling/v1",
            source,
        )
        self.assertIn("action=daemon-sigkill-restore-required", source)
        self.assertIn("ceiling_seconds=%s", source)
        self.assertEqual(source.count("exit 97"), 1)
        # The restore command is printed exactly once in the enforcement
        # block (echo only) and never executed there.
        self.assertEqual(enforcement.count("run_trial restore"), 1)
        self.assertIn('echo "  $TRIAL_DIR/run_trial restore', enforcement)
        # The deployer's Run/Restore payload construction is untouched, so
        # the printed payloads remain byte-identical for bench-card reuse.
        deployer = (SCRIPTS / "dcentrald_s19k_tmp_deploy.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'RECOVERY_COMMAND="$REMOTE_HELPER restore $REMOTE_DIR $CFG_BT recovery '
            "$LOCAL_SHA $LOCAL_BYTES $CFG_SHA $CFG_BYTES $HELPER_SHA $HELPER_BYTES "
            '$CUSTODY_SHA $CUSTODY_BYTES $STOCK_RESTART_HELPER_SHA '
            '$STOCK_RESTART_HELPER_BYTES"',
            deployer,
        )
        self.assertIn(
            'RUN_COMMAND="$REMOTE_HELPER run $REMOTE_DIR $CFG_BT $DEPLOY_MODE '
            "$LOCAL_SHA $LOCAL_BYTES $CFG_SHA $CFG_BYTES $HELPER_SHA $HELPER_BYTES "
            '$CUSTODY_SHA $CUSTODY_BYTES $STOCK_RESTART_HELPER_SHA '
            '$STOCK_RESTART_HELPER_BYTES"',
            deployer,
        )

    @unittest.skipUnless(os.name == "nt", "WSL trial ceiling refusal exercise")
    def test_trial_ceiling_refuses_sub_120_before_any_custody(self) -> None:
        """An S19K_TMP_TRIAL_CEILING_SECONDS below the 120 s floor or above
        the 2147483647 overflow bound must be refused with a typed usage
        error before any custody acquisition, bound-file verification side
        effects, or daemon fork."""
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            remote_dir, runtime_lock, bound_args = self._stage_trial_ceiling_fixture(
                temp, "ceilref", J2_ORPHAN_FAKE_DAEMON
            )
            out_log = f"{remote_dir}.out"
            rc_file = f"{remote_dir}.rc"
            try:
                self._run_trial_ceiling_launcher(
                    f"{remote_dir}.launcher",
                    "60",
                    "bounded-work-proof",
                    remote_dir,
                    bound_args,
                    out_log,
                    rc_file,
                    90,
                )
                rc = subprocess.check_output(
                    ["wsl.exe", "cat", rc_file], text=True
                ).strip()
                self.assertEqual(rc, "2")
                out = subprocess.check_output(
                    ["wsl.exe", "cat", out_log], text=True
                )
                self.assertIn(
                    "S19K_TMP_TRIAL_CEILING_SECONDS must be at least 120", out
                )
                # Refusal happened before the lock container, before the
                # runtime receipt, and before any daemon execution.
                self.assertNotEqual(
                    subprocess.run(
                        ["wsl.exe", "test", "-e", runtime_lock]
                    ).returncode,
                    0,
                )
                self.assertNotEqual(
                    subprocess.run(
                        ["wsl.exe", "test", "-e", f"{remote_dir}/runtime_active"]
                    ).returncode,
                    0,
                )
                self.assertNotEqual(
                    subprocess.run(
                        ["wsl.exe", "test", "-e", f"{remote_dir}/.fake_daemon_trace"]
                    ).returncode,
                    0,
                )
                # The same fail-closed refusal covers the overflow side: a
                # value above 2^31-1 must be refused before custody rather
                # than wrapping the deadline arithmetic into the past.  The
                # fixture stages exactly one launcher at .launcher and the
                # launcher truncates OUT/RCFILE per run, so re-invoke it.
                self._run_trial_ceiling_launcher(
                    f"{remote_dir}.launcher",
                    "2147483648",
                    "bounded-work-proof",
                    remote_dir,
                    bound_args,
                    out_log,
                    rc_file,
                    90,
                )
                rc = subprocess.check_output(
                    ["wsl.exe", "cat", rc_file], text=True
                ).strip()
                self.assertEqual(rc, "2")
                out = subprocess.check_output(
                    ["wsl.exe", "cat", out_log], text=True
                )
                self.assertIn(
                    "S19K_TMP_TRIAL_CEILING_SECONDS must be at most 2147483647", out
                )
                self.assertNotEqual(
                    subprocess.run(
                        ["wsl.exe", "test", "-e", runtime_lock]
                    ).returncode,
                    0,
                )
            finally:
                self._cleanup_trial_ceiling_fixture(
                    "ceilref", remote_dir, runtime_lock, out_log, rc_file
                )

    @unittest.skipUnless(os.name == "nt", "WSL trial ceiling expiry exercise")
    def test_trial_ceiling_expiry_sigkills_daemon_and_prints_restore(self) -> None:
        """Attempt-9 park reproduction under the attempt-10 ceiling: a daemon
        that completes the J0->C1->J1->release handshake and then parks
        without a terminal disposition must not pin the wrapper.  At the 120 s
        floor the wrapper SIGKILLs ONLY the identity-fenced daemon child,
        appends the typed ceiling marker to the daemon transcript, prints the
        exact deployer-format restore command without executing it, retains
        custody (runtime receipt and lock owner intact), and exits 97."""
        park_tail = (
            'say "token admitted; running bounded work"\n'
            "sleep 1\n"
            'say "daemon exit 0"\n'
            "exit 0\n"
        )
        self.assertEqual(J2_ORPHAN_FAKE_DAEMON.count(park_tail), 1)
        hanging_daemon = J2_ORPHAN_FAKE_DAEMON.replace(
            park_tail,
            'say "token admitted; parking without terminal disposition"\n'
            "while :; do sleep 5; done\n",
        )
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            remote_dir, runtime_lock, bound_args = self._stage_trial_ceiling_fixture(
                temp, "ceilkill", hanging_daemon
            )
            out_log = f"{remote_dir}.out"
            rc_file = f"{remote_dir}.rc"
            try:
                self._run_trial_ceiling_launcher(
                    f"{remote_dir}.launcher",
                    "120",
                    "bounded-work-proof",
                    remote_dir,
                    bound_args,
                    out_log,
                    rc_file,
                    300,
                )
                rc = subprocess.check_output(
                    ["wsl.exe", "cat", rc_file], text=True
                ).strip()
                self.assertEqual(rc, "97")
                out = subprocess.check_output(
                    ["wsl.exe", "cat", out_log], text=True
                )
                self.assertIn("exceeded the 120s hard ceiling", out)
                expected_restore = (
                    f"  {remote_dir}/run_trial restore {remote_dir} am3-s19k"
                    " recovery " + " ".join(bound_args)
                )
                self.assertIn(expected_restore, out)
                # The restore was printed, never executed: no restore-path
                # closeout ran and custody remains in place for the human
                # recovery decision.
                self.assertNotIn("S19k temporary runtime is stopped", out)
                self.assertNotIn("stock restart remains pending", out)
                self.assertEqual(
                    subprocess.run(
                        ["wsl.exe", "test", "-e", f"{remote_dir}/runtime_active"]
                    ).returncode,
                    0,
                    "custody receipt must remain for the printed restore",
                )
                self.assertEqual(
                    subprocess.run(
                        ["wsl.exe", "test", "-f", f"{runtime_lock}/owner"]
                    ).returncode,
                    0,
                    "the board-global lock owner must remain",
                )
                # The typed ceiling marker was appended to the daemon
                # transcript dotfile exactly once.
                transcript = subprocess.check_output(
                    [
                        "wsl.exe",
                        "sh",
                        "-c",
                        f"cat {shlex.quote(remote_dir)}/.startup_daemon_transcript.*",
                    ],
                    text=True,
                )
                self.assertEqual(
                    transcript.count("S19K_TMP_TRIAL_CEILING_EXCEEDED"), 1
                )
                self.assertIn(
                    "S19K_TMP_TRIAL_CEILING_EXCEEDED "
                    "schema=dcentos.s19k-trial-ceiling/v1 ceiling_seconds=120",
                    transcript,
                )
                self.assertIn("action=daemon-sigkill-restore-required", transcript)
                # The parked daemon child is dead and reaped.
                daemon_probe = subprocess.run(
                    [
                        "wsl.exe",
                        "sh",
                        "-c",
                        "kill -0 $(sed -n 's/^child_pid=//p' "
                        + shlex.quote(f"{remote_dir}/runtime_startup_c1_child_identity")
                        + ") 2>/dev/null",
                    ],
                )
                self.assertNotEqual(
                    daemon_probe.returncode,
                    0,
                    "the parked daemon child must be SIGKILLed",
                )
                trace = subprocess.check_output(
                    ["wsl.exe", "cat", f"{remote_dir}/.fake_daemon_trace"],
                    text=True,
                )
                self.assertIn("parking without terminal disposition", trace)
            finally:
                self._cleanup_trial_ceiling_fixture(
                    "ceilkill", remote_dir, runtime_lock, out_log, rc_file
                )

    @unittest.skipUnless(os.name == "nt", "WSL trial ceiling success-path exercise")
    def test_trial_ceiling_does_not_fire_on_prompt_bounded_completion(self) -> None:
        """The ceiling must be invisible to a one-shot bounded trial whose
        daemon exits promptly: with S19K_TMP_TRIAL_CEILING_SECONDS=120 set,
        the prompt J2-orphan daemon completes the handshake, exits 0, and the
        wrapper retires pre-J3 custody cleanly (exit 0, no ceiling marker,
        lock container removed) exactly as before the backstop."""
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            remote_dir, runtime_lock, bound_args = self._stage_trial_ceiling_fixture(
                temp, "ceilsucc", J2_ORPHAN_FAKE_DAEMON
            )
            out_log = f"{remote_dir}.out"
            rc_file = f"{remote_dir}.rc"
            try:
                self._run_trial_ceiling_launcher(
                    f"{remote_dir}.launcher",
                    "120",
                    "bounded-work-proof",
                    remote_dir,
                    bound_args,
                    out_log,
                    rc_file,
                    180,
                )
                rc = subprocess.check_output(
                    ["wsl.exe", "cat", rc_file], text=True
                ).strip()
                self.assertEqual(rc, "0")
                out = subprocess.check_output(
                    ["wsl.exe", "cat", out_log], text=True
                )
                self.assertIn(
                    "S19k pre-J3 startup custody retired and consumed without "
                    "SafeOff or stock signaling",
                    out,
                )
                self.assertNotIn("S19K_TMP_TRIAL_CEILING_EXCEEDED", out)
                self.assertNotIn("hard ceiling", out)
                # The clean pre-J3 retirement consumes the whole startup
                # evidence namespace, transcript dotfile included (verified
                # residue-free), so no ceiling marker can exist anywhere.
                self.assertNotEqual(
                    subprocess.run(
                        [
                            "wsl.exe",
                            "sh",
                            "-c",
                            "test -e "
                            + shlex.quote(remote_dir)
                            + "/.startup_daemon_transcript.*",
                        ],
                    ).returncode,
                    0,
                    "residue-free retirement must consume the transcript dotfile",
                )
                # Clean no-effect retirement removed the lock container.
                self.assertNotEqual(
                    subprocess.run(
                        ["wsl.exe", "test", "-e", runtime_lock]
                    ).returncode,
                    0,
                    "clean no-effect retirement must remove the lock container",
                )
                trace = subprocess.check_output(
                    ["wsl.exe", "cat", f"{remote_dir}/.fake_daemon_trace"],
                    text=True,
                )
                self.assertIn("daemon exit 0", trace)
            finally:
                self._cleanup_trial_ceiling_fixture(
                    "ceilsucc", remote_dir, runtime_lock, out_log, rc_file
                )


class S19kInstallCustodyStaticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = (SCRIPTS / "dcentrald_s19k_tmp_remote_run.sh").read_text(
            encoding="utf-8"
        )
        self.rust = (
            ROOT / "dcentrald" / "dcentrald" / "src" / "serial_mining.rs"
        ).read_text(encoding="utf-8")
        self.main = (
            ROOT / "dcentrald" / "dcentrald" / "src" / "main.rs"
        ).read_text(encoding="utf-8")

    def test_install_mode_is_exact_argv_and_runtime_receipt_bound(self) -> None:
        argv = self.runner.index(
            'set -- "$@" --s19k-install-custody-safeoff'
        )
        canonical = self.runner.index(
            'DAEMON_ARGV_CANON="$TRIAL_DIR/.startup_daemon_argv.'
        )
        self.assertLess(argv, canonical)
        for marker in (
            '"--s19k-install-custody-safeoff"',
            "require_install_custody_safeoff_policy",
            "install-custody-safeoff CLI authority does not match immutable "
            "runtime_active deploy_mode",
            "dcentos.s19k-install-custody-terminal-safeoff/v1",
            "dcentos.s19k-install-custody-safeoff/v1",
            "dcentos.s19k-install-custody-stock-restart-pending/v1",
            "dcentos.s19k-install-custody-transcript/v1",
        ):
            self.assertTrue(
                marker in self.runner or marker in self.rust or marker in self.main,
                marker,
            )
        self.assertIn("child_cmdline_sha256", self.runner)
        self.assertIn("child_environment_sha256", self.runner)
        self.assertIn("child_environment_count", self.runner)

        env_start = self.runner.index(
            "{\n    printf '%s\\000' 'DCENTOS_EPHEMERAL_RUNTIME=1'",
            canonical,
        )
        env_end = self.runner.index('} > "$DAEMON_ENV_CANON"', env_start)
        canonical_env = self.runner[env_start:env_end]
        self.assertEqual(canonical_env.count("printf '%s\\000'"), 10)
        for exact_entry in (
            "'DCENTOS_EPHEMERAL_RUNTIME=1'",
            "'DCENTOS_LOG_RING_DIR=/tmp/dcent/log'",
            '"DCENT_S19K_LIVE_IDENTITY_SHA256=$EXPECTED_LIVE_IDENTITY_SHA"',
            "'DCENT_S19K_STARTUP_BOOTSTRAP=daemon-v1'",
            '"DCENT_S19K_STARTUP_FIFO=$STARTUP_FIFO"',
            '"DCENT_S19K_STARTUP_LOG=$STARTUP_DAEMON_TRANSCRIPT"',
            '"DCENT_S19K_STARTUP_WRAPPER_PID=$$"',
            '"DCENT_S19K_STARTUP_WRAPPER_START=$SELF_START"',
            "'DCENT_S19K_TRACK1_STOP_SAFEOFF=1'",
            "'PATH=/usr/bin:/bin:/usr/sbin:/sbin'",
        ):
            self.assertIn(exact_entry, canonical_env)
        self.assertNotRegex(canonical_env, r"POOL|STRATUM|UART|ASIC")
        self.assertIn("DAEMON_ENVIRONMENT_COUNT=10", self.runner)

        receipt_start = self.runner.index(
            '    INSTALL_TMP="$TRIAL_DIR/.runtime_install_custody_transcript.tmp.'
        )
        receipt_end = self.runner.index('    } > "$INSTALL_TMP"', receipt_start)
        receipt = self.runner[receipt_start:receipt_end]
        formats = re.findall(r"printf '([^']*)'", receipt)
        keys: list[str] = []
        for fmt in formats:
            keys.extend(re.findall(r"(?:^|\\n)([a-z0-9_]+)=", fmt))
        self.assertEqual(len(keys), 77)
        self.assertEqual(len(set(keys)), 77)
        for required_key in (
            "child_cmdline_sha256",
            "child_environment_sha256",
            "child_environment_count",
            "terminal_handoff_receipt_sha256",
            "safeoff_receipt_sha256",
            "stock_restart_helper_sha256",
            "pool_connection_count",
            "uart_open_count",
            "asic_work_count",
            "reset_work_count",
        ):
            self.assertIn(required_key, keys)

    def test_install_terminal_cutpoint_precedes_every_uart_path(self) -> None:
        policy_start = self.main.index(
            "if s19k_install_custody_safeoff {",
            self.main.index("let s19k_track1_recovery_safeoff_mode"),
        )
        first_one_shot = self.main.index(
            'if let Some(pos) = args.iter().position(|a| a == "--set-fan")',
            policy_start,
        )
        self.assertLess(policy_start, first_one_shot)
        policy = self.main[policy_start:first_one_shot]
        for incompatible in (
            "--set-fan",
            "--hold-fan",
            "--get-fan",
            "--fan-sweep",
            "--safe-off",
            "--s19k-track1-recovery-safeoff",
            "--verify-bundle",
            "--stratum-proxy",
            "--stock-fpga",
        ):
            self.assertIn(f'"{incompatible}"', policy)

        branch = self.rust.index(
            "// This is the install-custody terminal cutpoint"
        )
        uart = self.rust.index("SerialChainBackend::open_passthrough_bm1366", branch)
        self.assertLess(branch, uart)
        terminal = self.rust[branch:uart]
        for required in (
            "closeout_s19k_install_custody_safeoff(",
            "s19k_publish_terminal_partial_handoff_receipt(",
            "return Ok(());",
        ):
            self.assertIn(required, terminal)
        for forbidden in (
            "open_passthrough_bm1366",
            "s19k_track1_reset_then_cut_checked",
            "SetAddress",
            "FULL FRAME ON WIRE",
        ):
            self.assertNotIn(forbidden, terminal)

        run_start = self.rust.index("pub async fn run(&mut self) -> Result<()> {")
        install_return = self.rust.index("return Ok(());", branch) + len(
            "return Ok(());"
        )
        install_execution_prefix = self.rust[run_start:install_return]
        for forbidden_call in (
            "SerialChainBackend::open(",
            "SerialChainBackend::open_passthrough",
            "build_stratum_config(",
            "actor_send_work(",
            ".send_write_reg_broadcast",
        ):
            self.assertNotIn(forbidden_call, install_execution_prefix)

    def test_install_receipt_rejects_mode_and_physical_contract_mismatch(self) -> None:
        publisher = self.rust[
            self.rust.index("fn s19k_publish_terminal_partial_handoff_receipt(") : self.rust.index(
                "fn s19k_require_path_absent(",
                self.rust.index("fn s19k_publish_terminal_partial_handoff_receipt("),
            )
        ]
        self.assertIn(
            "safeoff_contract.matches_install_custody_mode(install_custody_safeoff)",
            publisher,
        )
        self.assertIn(
            "terminal receipt deploy mode does not match the completed physical SafeOff contract",
            publisher,
        )
        matcher = self.rust[
            self.rust.index("impl S19kTrack1SafeOffContract {") : self.rust.index(
                "struct S19kTrack1SafeOffReceipt",
                self.rust.index("impl S19kTrack1SafeOffContract {"),
            )
        ]
        self.assertIn(
            "install_custody_mode == (self == Self::InstallCustodyGpio437Only)",
            matcher,
        )
        self.assertIn(
            "fn install_custody_receipt_contract_rejects_both_mode_mismatches()",
            self.rust,
        )

        runner_admission = self.runner[
            self.runner.index("terminal_handoff_receipt_is_exact() {") : self.runner.index(
                "terminal_handoff_leg_relation_is_exact() {"
            )
        ]
        for exact in (
            "install-custody-safeoff)",
            "EXPECTED_TERMINAL_HANDOFF_SCHEMA=dcentos.s19k-install-custody-terminal-safeoff/v1",
            "EXPECTED_TERMINAL_HANDOFF_DISPOSITION=install-custody-terminal-safeoff",
            "EXPECTED_TERMINAL_RESETS=not-attempted",
            '[ "$(terminal_handoff_field schema)" = "$EXPECTED_TERMINAL_HANDOFF_SCHEMA" ]',
            '[ "$(terminal_handoff_field disposition)" = "$EXPECTED_TERMINAL_HANDOFF_DISPOSITION" ]',
            '[ "$(terminal_handoff_field resets)" = "$EXPECTED_TERMINAL_RESETS" ]',
        ):
            self.assertIn(exact, runner_admission)

        restart = (
            SCRIPTS / "dcentrald_s19k_stock_restart_from_safeoff.sh"
        ).read_text(encoding="utf-8")
        restart_admission = restart[
            restart.index("admit_terminal_handoff() {") : restart.index(
                "admit_lock_owner() {"
            )
        ]
        self.assertIn(
            'if [ "$PENDING_VERSION" = install-custody ]; then',
            restart_admission,
        )
        self.assertIn(
            "EXPECTED_TERMINAL_SCHEMA=dcentos.s19k-install-custody-terminal-safeoff/v1",
            restart_admission,
        )
        self.assertIn("EXPECTED_TERMINAL_RESETS=not-attempted", restart_admission)

    def test_install_safeoff_has_no_reset_gpio_dependency(self) -> None:
        cut = self.rust[
            self.rust.index("fn s19k_track1_install_custody_cut_checked()") : self.rust.index(
                "pub(crate) fn s19k_track1_recovery_safeoff",
                self.rust.index("fn s19k_track1_install_custody_cut_checked()"),
            )
        ]
        self.assertEqual(cut.count("disable_s19k_track1_psu_checked()"), 1)
        self.assertIn("reset_gpios: None", cut)
        self.assertNotIn("set_amlogic_board_reset_checked", cut)
        self.assertNotIn("assert_s19k_native_all_resets_checked", cut)

        gpio_gate = self.runner[
            self.runner.index("gpio_safeoff_is_exact() {") : self.runner.index(
                "retained_magic_closed_receipt_is_exact() {"
            )
        ]
        install_leg = gpio_gate.split(
            '[ "$GPIO_SAFEOFF_MODE" = install-custody-safeoff ]', 1
        )[1].split("\n    fi", 1)[0]
        self.assertIn("GPIO_SAFEOFF_SPECS=437:1", install_leg)
        self.assertNotRegex(install_leg, r"454|455|456")

    def test_install_supervisor_first_watchdog_and_restart_obligations(self) -> None:
        handoff = self.rust[
            self.rust.index("// Acquire BOTH leases before the watchdog") : self.rust.index(
                "let mut s19k_active_tx_paths",
                self.rust.index("// Acquire BOTH leases before the watchdog"),
            )
        ]
        ordered = (
            ".freeze_for_handoff(retained_receipt_authority, expected)?",
            "expected.open_both_signal_leases_checked()?",
            "SafetyWatchdogOwner::start_before_energizing",
            ".assume_inherited_rails()",
            "S19kStockProcessRole::Supervisor",
            "child_after_supervisor_exit_at",
            "S19kStockProcessRole::Bosminer",
            "s19k_require_no_live_stock_custody_processes_at",
        )
        positions = [handoff.index(marker) for marker in ordered]
        self.assertEqual(positions, sorted(positions))
        terminal = handoff.index("// This is the install-custody terminal cutpoint")
        self.assertGreater(terminal, positions[-1])
        self.assertGreater(
            handoff.index("closeout_s19k_install_custody_safeoff(", terminal),
            terminal,
        )
        failure = handoff[
            handoff.index("if let Err(primary) = s19k_track1_post_handoff_result") : handoff.index(
                "s19k_terminal_receipt_context = Some"
            )
        ]
        self.assertIn("closeout_s19k_install_custody_safeoff(", failure)
        self.assertIn(
            "S19kTrack1SafeOffContract::InstallCustodyGpio437Only", failure
        )

        pre_effect = self.rust[
            self.rust.index("let runtime_binding =") : self.rust.index(
                "let s19k_track1_post_handoff_result: Result<()>"
            )
        ]
        for retained_obligation in (
            "S19kEarlyRetainedPhase::RuntimeBindingNotAdmitted",
            "S19kEarlyRetainedPhase::LiveIdentityNotAdmitted",
            "s19k_publish_stock_owner_retained_prewatchdog_receipt(",
            "close_s19k_track1_watchdog_never_handoff(",
            "s19k_publish_stock_owner_retained_receipt(",
        ):
            self.assertIn(retained_obligation, pre_effect)

        stop = self.runner[self.runner.index("stop_child() {") :]
        self.assertGreaterEqual(
            stop.count("transition_startup_stock_loss_to_pending || exit 1"), 2
        )
        self.assertGreaterEqual(
            stop.count("publish_mode_specific_receipts_after_safeoff"), 4
        )

    def test_malformed_bound_files_refuse_before_process_or_gpio_effect(self) -> None:
        verifier = self.runner[
            self.runner.index("verify_all_bound_files() {") : self.runner.index(
                "capture_exact_live_s19k_identity() {"
            )
        ]
        for forbidden in ("kill ", "/sys/class/gpio", "gpio_stock_baseline"):
            self.assertNotIn(forbidden, verifier)

        run = self.runner[self.runner.index('[ "$MODE" = run ] ||') :]
        bound_files = run.index("verify_all_bound_files")
        self.assertLess(run.index('case "$DEPLOY_MODE" in'), bound_files)
        for later_effect_fence in (
            "no_dcentrald_thread_is_live",
            "capture_exact_stock_tree",
            "gpio_stock_baseline_is_exact",
            "write_startup_j0_owner_prefork",
            "/usr/bin/env -i",
            "kill -TERM",
        ):
            self.assertLess(bound_files, run.index(later_effect_fence, bound_files))

    def test_install_runner_never_falls_back_to_reset_recovery(self) -> None:
        recovery = self.runner[
            self.runner.index("run_checked_safeoff_command() {") : self.runner.index(
                "perform_checked_safeoff() {"
            )
        ]
        self.assertIn(
            "install custody forbids the reset-capable recovery SafeOff command",
            recovery,
        )
        companion = self.runner[
            self.runner.index("publish_startup_prefix_safeoff_companion() {") : self.runner.index(
                "startup_prefix_pending_is_exact() {"
            )
        ]
        self.assertIn(
            '[ "$SAFEOFF_SOURCE_MODE" = install-custody-safeoff ]', companion
        )
        install_leg = companion.split(
            '[ "$SAFEOFF_SOURCE_MODE" = install-custody-safeoff ]', 1
        )[1].split("else", 1)[0]
        self.assertNotIn("run_checked_safeoff_command", install_leg)
        self.assertIn("terminal_handoff_receipt_is_exact", install_leg)
        self.assertIn("gpio_safeoff_is_exact", install_leg)

    def test_transcript_proves_zero_pool_uart_asic_reset_and_work_paths(self) -> None:
        publisher = self.runner[
            self.runner.index("publish_install_custody_transcript_receipt() {") : self.runner.index(
                "bounded_work_transcript_receipt_is_exact() {"
            )
        ]
        for count in (
            "INSTALL_POOL_COUNT",
            "INSTALL_STRATUM_COUNT",
            "INSTALL_UART_COUNT",
            "INSTALL_FULL_FRAME_COUNT",
            "INSTALL_BOUNDED_TX_COUNT",
            "INSTALL_DISPATCH_COUNT",
            "INSTALL_ASIC_COUNT",
            "INSTALL_RESET_COUNT",
        ):
            self.assertIn(f'[ "${count}" -eq 0 ]', publisher)
        self.assertIn('[ "$INSTALL_WRAPPER_EXIT_STATUS" -eq 0 ]', publisher)
        self.assertIn('[ "$INSTALL_SUCCESS_COUNT" -eq 1 ]', publisher)
        self.assertIn("reset_contract=not-attempted", publisher)
        self.assertIn("mining_config=disabled-and-route-free", publisher)

    def test_every_post_launch_exit_funnels_to_pending_restart_custody(self) -> None:
        stop = self.runner[self.runner.index("stop_child() {") :]
        self.assertGreaterEqual(
            stop.count("transition_startup_stock_loss_to_pending || exit 1"), 2
        )
        self.assertGreaterEqual(
            stop.count("clear_runtime_obligation_after_safeoff || exit 1"), 2
        )
        self.assertIn("next_authority=exact-stock-restart-helper-only", self.runner)
        self.assertIn("stock restart remains pending", self.runner)


class S19kJournalPublisherAdmissionTests(unittest.TestCase):
    """The daemon's publisher-v1 destination set, the runner's publications,
    and the offline fake daemons must agree. 2026-09-01 live regression: the
    sealed daemon refused every post-SafeOff receipt the runner published
    (``S19k journal destination is not an admitted startup authority path``)
    while the fake daemon linked anything, so 40/40 offline scenarios stayed
    green through a bench failure."""

    RECEIPTS = (
        "runtime_install_custody_transcript",
        "runtime_handoff_no_work_transcript",
        "runtime_bounded_work_transcript",
        "runtime_endurance_work_receipt",
        "runtime_endurance_failure_receipt",
    )

    def setUp(self) -> None:
        self.runner = (SCRIPTS / "dcentrald_s19k_tmp_remote_run.sh").read_text(
            encoding="utf-8"
        )
        self.common = COMMON_DEPLOY_RS.read_text(encoding="utf-8")
        self.rust = (
            ROOT / "dcentrald" / "dcentrald" / "src" / "serial_mining.rs"
        ).read_text(encoding="utf-8")

    @staticmethod
    def runner_publications(script: str) -> list[tuple[str, str]]:
        calls = re.findall(
            r'^\s*publish_no_clobber_journal(?:_keep_source)? "\$([A-Z0-9_]+)" "\$([A-Z0-9_]+)"',
            script,
            flags=re.M,
        )
        return [
            (source, destination)
            for source, destination in calls
            if (source, destination) != ("JOURNAL_SOURCE", "JOURNAL_DESTINATION")
        ]

    @staticmethod
    def trial_assignment(script: str, var: str) -> str | None:
        match = re.search(
            rf'^\s*{re.escape(var)}="\$TRIAL_DIR/([A-Za-z0-9_.-]+)"$', script, flags=re.M
        )
        return match.group(1) if match else None

    def test_runner_destinations_are_all_daemon_admitted(self) -> None:
        publications = self.runner_publications(self.runner)
        self.assertGreaterEqual(len(publications), 12)
        trial_names: list[str] = []
        special: list[str] = []
        for _source, destination in publications:
            name = self.trial_assignment(self.runner, destination)
            if name is None:
                special.append(destination)
                continue
            trial_names.append(name)
        self.assertEqual(sorted(set(special)), ["ENDURANCE_ACK", "RUNTIME_LOCK_OWNER"])
        self.assertEqual(
            sorted(set(trial_names) - set(DAEMON_ADMITTED_JOURNAL_DESTINATIONS)), []
        )
        for receipt in self.RECEIPTS:
            self.assertIn(receipt, trial_names)
            self.assertIn(receipt, DAEMON_ADMITTED_JOURNAL_DESTINATIONS)

    def test_daemon_publisher_and_runner_contract_share_the_set(self) -> None:
        self.assertIn(
            "classify_s19k_ephemeral_journal_destination(source, destination)", self.rust
        )
        self.assertNotIn('| "runtime_startup_j2_child_bound"', self.rust)
        self.assertIn("fn s19k_ephemeral_ack_parent(", self.rust)
        contract = self.common[
            self.common.index("pub fn admit_s19k_tmp_remote_runner_ephemeral(") :
        ]
        contract = contract[: contract.index("\npub struct S19kTmpDeployRequest")]
        self.assertIn("admit_s19k_runner_journal_destinations(script)?;", contract)
        for receipt in self.RECEIPTS:
            self.assertIn(f'    "{receipt}",\n', self.common)

    def test_fake_daemons_carry_the_admission_snippet(self) -> None:
        self.assertIn(publisher_admission_sh("P_SRC", "P_DST", "    "), J2_ORPHAN_FAKE_DAEMON)
        source = Path(__file__).read_text(encoding="utf-8")
        self.assertIn(
            'publisher_admission_sh("source_path", "destination_path", "  ")', source
        )

    def test_fake_daemon_refuses_what_the_daemon_refuses(self) -> None:
        # One WSL invocation for every case: a burst of wsl.exe sessions can
        # trip WSL_E_TTY_LIMIT and masquerade as a stub failure.
        admitted = [
            (f".{name}.tmp.1.2", name) for name in DAEMON_ADMITTED_JOURNAL_DESTINATIONS
        ] + [("endurance_evidence/acks/.ack.3.tmp.1.2", "endurance_evidence/acks/ack.000003.kv")]
        refused = [
            (
                ".runtime_bounded_work_transcript.tmp.9.9",
                "runtime_bounded_work_transcript_v2",
            ),
            (".ack.4.tmp.1.2", "ack.000004.kv"),
            (
                "endurance_evidence/acks/.runtime_startup_release.tmp.1.2",
                "endurance_evidence/acks/runtime_startup_release",
            ),
            (".runtime_startup_release.tmp.3.3", "endurance_evidence/runtime_startup_release"),
        ]
        probe = ["#!/bin/sh", 'D=$(dirname "$0")', "mkdir -p \"$D/endurance_evidence/acks\""]
        probe.append(
            'run() { printf \'x\\n\' > "$D/$1"; sh "$D/dcentrald" --s19k-track1-journal-source "$D/$1" '
            '--s19k-track1-journal-destination "$D/$2" >/dev/null 2>&1; rc=$?; '
            'if [ -e "$D/$2" ]; then ex=1; else ex=0; fi; printf \'%s %s %s\\n\' "$rc" "$ex" "$2"; }'
        )
        for source, destination in admitted + refused:
            probe.append(f'run "{source}" "{destination}"')
        remote_dir = subprocess.check_output(
            ["wsl.exe", "mktemp", "-d", "/tmp/dcentrald_bench_t1_pubstub.XXXXXX"],
            text=True,
        ).strip()
        try:
            subprocess.run(
                [
                    "wsl.exe",
                    "sh",
                    "-c",
                    f"cat > {shlex.quote(remote_dir)}/dcentrald "
                    f"&& chmod 700 {shlex.quote(remote_dir)}/dcentrald",
                ],
                input=J2_ORPHAN_FAKE_DAEMON.encode("utf-8"),
                check=True,
            )
            subprocess.run(
                ["wsl.exe", "sh", "-c", f"cat > {shlex.quote(remote_dir)}/probe.sh"],
                input="\n".join(probe).encode("utf-8") + b"\n",
                check=True,
            )
            output = subprocess.check_output(
                ["wsl.exe", "sh", f"{remote_dir}/probe.sh"], text=True
            )
        finally:
            subprocess.run(["wsl.exe", "rm", "-rf", remote_dir], check=False)
        observed = {}
        for line in output.splitlines():
            code, exists, destination = line.split(" ", 2)
            observed[destination] = (int(code), exists == "1")
        for _source, destination in admitted:
            self.assertEqual(observed.get(destination), (0, True), destination)
        for _source, destination in refused:
            self.assertEqual(observed.get(destination), (87, False), destination)
        self.assertEqual(len(observed), len(admitted) + len(refused))

if __name__ == "__main__":
    unittest.main()
