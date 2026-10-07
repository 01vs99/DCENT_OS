#!/bin/bash
# DCENTos - Amlogic persistent NAND install (exact am3-aml lab targets)
# D-Central Technologies, 2026
#
# Bridge-firmware-required workflow: target must be on BraiinsOS+ (or
# LuxOS) with root SSH BEFORE this script runs. Stock S19j Pro Amlogic
# only has miner:miner SSH; that path is not yet adapter-backed.
# See plans/zesty-cooking-bee.md Phase R for full context.
#
# Run from operator's host. Current executable behavior is backup, validation,
# and dry-run evidence only (`CLEAR_FOR_FLASH=false`). Steps 6-10 below are the
# unreachable future mutation contract, not an available install route:
#   0. Local package-only validation (prefix, manifest, SHA256SUMS, uImage).
#   1. SSH preflight: root shell, required tools (nandwrite, flash_erase,
#      fw_setenv, sha256sum), platform=am3-aml.
#   2. Backup /dev/nand_env + /dev/mtd5 + fw_printenv to --artifact-dir.
#      S19k --backup-only additionally captures all six logical MTD partitions
#      twice, with stable bad-block counts and private rescue metadata. This is
#      logical evidence, not physical replay authority.
#   3. SCP sysupgrade tar to /data, verify SHA256 (uses /data not /tmp --
# for rationale).
#   4. Extract tar, verify SHA256SUMS, validate MANIFEST.json board.
#   5. (--dry-run halts here; mining services are not stopped.)
#   6. Confirm destructive operation.
#   7. Stop bosminer/boser/bos-tools cleanly.
#   8. flash_erase + nandwrite rootfs to mtd5 LOCAL offset 0x05100000.
#   9. nanddump readback; install commit is recovery-flag 0x01
#      eraseblock rewrite (firstboot is S99 WAL companion only).
#  10. Print monitoring instructions.
#
# After reboot: operator polls `dcent detect <ip>` for DCENTOS state.
# Rollback is recovery-flag 0x02 -> recover_to_stock (env restore + erase
# nvdata), not a direct bootm of mtd2. firstboot is a DCENT/S99upgrade
# env key; .78 bootcmd never reads it.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/am3_geometry.sh"
. "$SCRIPT_DIR/lib/amlogic_identity_guard.sh"
ROOTFS_MTD="$DCENT_AM3_ROOTFS_MTD"
ROOTFS_OFFSET_HEX="$DCENT_AM3_ROOTFS_OFFSET_HEX"
ROOTFS_WINDOW_HEX="$DCENT_AM3_ROOTFS_WINDOW_HEX"
ROOTFS_ERASE_COUNT="$DCENT_AM3_ROOTFS_ERASE_COUNT"
ROOTFS_ERASESIZE_EXPECTED="$DCENT_AM3_ROOTFS_ERASESIZE_EXPECTED"
ROOTFS_OFFSET_DEC="$DCENT_AM3_ROOTFS_OFFSET_DEC"
ROOTFS_WINDOW_DEC="$DCENT_AM3_ROOTFS_WINDOW_DEC"
ROOTFS_END_DEC="$DCENT_AM3_ROOTFS_END_DEC"

usage() {
    cat >&2 <<USAGE
Usage: $(basename "$0") <miner_ip> --artifact-dir <new-dir> --known-hosts <file> [--firmware <sysupgrade.tar>] [--variant s19jpro-aml|s19jproplus|s19kpro|s21|s21pro] [--backup-only] [--dry-run] [--yes] [--accept-braiins-model-soc-identity]

Required:
  <miner_ip>             Target miner IP (must be on BraiinsOS+/LuxOS with root SSH)
  --artifact-dir <dir>   New private local dir for rollback/rescue evidence
  --known-hosts <file>   Pinned OpenSSH known_hosts file (required)

Options:
  --firmware <tar>       DCENT_OS AM3 package to validate/stage (no current write authority)
  --variant s19jpro-aml|s19jproplus|s19kpro|s21|s21pro
                         Package variant to validate/write (default: s19kpro)
  --backup-only          S19k: full six-MTD logical rescue capture; never flash
  --dry-run              Run preflight + backup + SHA256 verify only; no flash
  --yes                  Skip the future-step prompt; never grants FLASH authority
  --accept-braiins-model-soc-identity
                         S19k Pro only. BraiinsOS ships no /config CONF_* PCB
                         source, no sysfs eeprom node, and its device tree has
                         no cXX token, so the direct carrier-PCB observation is
                         genuinely unavailable. This explicit operator override
                         admits the alternative evidence tuple instead: exact
                         BOS_MODEL S19k Pro model + A113D/AXG SoC + zero PCB
                         tokens in any stock channel + a conflict-free BHB56
                         (05:11) hashboard EEPROM observation. The identity
                         receipt records pcb_observation=unavailable-braiins.

Braiins AML L3: some images lack fw_printenv/fw_setenv. Backup still runs.
FLASH / env-flip is refused until those tools exist. CLEAR_FOR_FLASH stays false.

Environment:
  DCENT_PASSWORD         Optional SSH password (else SSH agent / keys)
  DCENT_SSH_KNOWN_HOSTS  Alternative to --known-hosts
USAGE
    exit 2
}

[ $# -ge 1 ] || usage
MINER_IP="$1"
shift

FIRMWARE=""
ARTIFACT_DIR=""
KNOWN_HOSTS="${DCENT_SSH_KNOWN_HOSTS:-}"
VARIANT="s19kpro"
DRY_RUN=false
SKIP_CONFIRM=false
BACKUP_ONLY=false
BRAIINS_MODEL_SOC_IDENTITY=false

while [ $# -gt 0 ]; do
    case "$1" in
        --firmware)     FIRMWARE="${2:?--firmware requires path}"; shift 2 ;;
        --artifact-dir) ARTIFACT_DIR="${2:?--artifact-dir requires path}"; shift 2 ;;
        --known-hosts)  KNOWN_HOSTS="${2:?--known-hosts requires path}"; shift 2 ;;
        --variant)      VARIANT="${2:?--variant requires s19jpro-aml, s19jproplus, s19kpro, s21, or s21pro}"; shift 2 ;;
        --backup-only)  BACKUP_ONLY=true; shift ;;
        --dry-run)      DRY_RUN=true; shift ;;
        --yes)          SKIP_CONFIRM=true; shift ;;
        --accept-braiins-model-soc-identity) BRAIINS_MODEL_SOC_IDENTITY=true; shift ;;
        -h|--help)      usage ;;
        *)              echo "Unknown arg: $1" >&2; usage ;;
    esac
done

if [ "$BRAIINS_MODEL_SOC_IDENTITY" = true ]; then
    case "$VARIANT" in
        s19kpro|s19k) ;;
        *)
            echo "ERROR: --accept-braiins-model-soc-identity is held S19k Pro evidence only, not variant '$VARIANT'" >&2
            exit 2
            ;;
    esac
fi

[ -n "$ARTIFACT_DIR" ] || { echo "ERROR: --artifact-dir required" >&2; exit 2; }
[ -n "$KNOWN_HOSTS" ] || { echo "ERROR: --known-hosts (or DCENT_SSH_KNOWN_HOSTS) is required" >&2; exit 2; }
[ -f "$KNOWN_HOSTS" ] && [ ! -L "$KNOWN_HOSTS" ] && [ -s "$KNOWN_HOSTS" ] || {
    echo "ERROR: known-hosts must be a non-empty regular non-symlink file: $KNOWN_HOSTS" >&2
    exit 2
}
if [ "$BACKUP_ONLY" != true ]; then
    [ -n "$FIRMWARE" ] || { echo "ERROR: --firmware required (or pass --backup-only)" >&2; exit 2; }
    [ -f "$FIRMWARE" ] || { echo "ERROR: $FIRMWARE not found" >&2; exit 2; }
fi
if [ -e "$ARTIFACT_DIR" ] || [ -L "$ARTIFACT_DIR" ]; then
    echo "ERROR: --artifact-dir must not already exist (no-clobber backup transaction): $ARTIFACT_DIR" >&2
    exit 2
fi
umask 077
mkdir "$ARTIFACT_DIR"
chmod 0700 "$ARTIFACT_DIR"

case "$VARIANT" in
    s19jpro-aml|s19jpro|s19j)
        BOARD_PKG_NAME="am3-s19jpro-aml"
        PACKAGE_PREFIX="sysupgrade-am3-s19jpro-aml"
        ;;
    s19jproplus|s19j-pro-plus|s19jpro+)
        VARIANT="s19jproplus"
        BOARD_PKG_NAME="am3-s19jproplus"
        PACKAGE_PREFIX="sysupgrade-am3-s19jproplus"
        ;;
    s19xp)
        echo "ERROR: S19 XP is NOT-IMPLEMENTED and package-only; persistent install is refused" >&2
        exit 2
        ;;
    s19jxp|s19j-xp)
        echo "ERROR: S19j XP is NOT-IMPLEMENTED and package-only; persistent install is refused" >&2
        exit 2
        ;;
    s19kpro|s19k)
        BOARD_PKG_NAME="am3-s19k"
        PACKAGE_PREFIX="sysupgrade-am3-s19k"
        ;;
    s21)
        BOARD_PKG_NAME="am3-s21"
        PACKAGE_PREFIX="sysupgrade-am3-s21"
        ;;
    s21pro)
        BOARD_PKG_NAME="am3-s21pro"
        PACKAGE_PREFIX="sysupgrade-am3-s21pro"
        ;;
    s21xp)
        echo "ERROR: S21 XP is NOT-IMPLEMENTED and package-only; persistent install is refused" >&2
        exit 2
        ;;
    *)
        echo "ERROR: unsupported --variant: $VARIANT (supported: s19jpro-aml, s19jproplus, s19kpro, s21, s21pro)" >&2
        exit 2
        ;;
esac
SSH_OPTS=(-o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN_HOSTS" -o ConnectTimeout=10 -o BatchMode=no)
log() { printf '[install_amlogic_persistent] %s\n' "$*"; }

ssh_run() {
    if [ -n "${DCENT_PASSWORD:-}" ] && command -v sshpass >/dev/null 2>&1; then
        sshpass -p "$DCENT_PASSWORD" ssh "${SSH_OPTS[@]}" "root@${MINER_IP}" "$1"
    else
        ssh "${SSH_OPTS[@]}" "root@${MINER_IP}" "$1"
    fi
}

scp_put() {
    if [ -n "${DCENT_PASSWORD:-}" ] && command -v sshpass >/dev/null 2>&1; then
        sshpass -p "$DCENT_PASSWORD" scp -O "${SSH_OPTS[@]}" "$1" "root@${MINER_IP}:$2"
    else
        scp -O "${SSH_OPTS[@]}" "$1" "root@${MINER_IP}:$2"
    fi
}

ssh_stream_get() {
    remote_command=$1
    destination=$2
    if [ -n "${DCENT_PASSWORD:-}" ] && command -v sshpass >/dev/null 2>&1; then
        sshpass -p "$DCENT_PASSWORD" ssh "${SSH_OPTS[@]}" "root@${MINER_IP}" "$remote_command" > "$destination"
    else
        ssh "${SSH_OPTS[@]}" "root@${MINER_IP}" "$remote_command" > "$destination"
    fi
}

local_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    elif command -v shasum  >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
    else echo ""; fi
}

require_uint() {
    case "$2" in
        ''|*[!0-9]*) log "ERROR: $1 is not numeric: '$2'"; exit 1 ;;
    esac
}

normalize_target_signal() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]'
}

require_exact_amlogic_variant() {
    local variant="$1"
    local platform="$2"
    local identity
    local board_target
    local model
    local hwid
    local normalized
    local board_norm
    local model_norm
    local soc_norm
    local pcb_norm
    local identity_lower

    identity=$(ssh_run '
        printf "BOARD_TARGET=%s\n" "$(cat /etc/dcentos/board_target 2>/dev/null | head -1 | tr -d " \\t\\r\\n")"
        printf "MODEL=%s\n" "$(cat /config/CONF_MINER_TYPE 2>/dev/null | head -1)"
        printf "HWID=%s\n" "$(cat /config/CONF_HARDWARE_ID 2>/dev/null | head -1)"
        printf "PCB=%s\n" "$(for f in /config/CONF_CONTROL_BOARD /config/CONF_CTRL_BOARD_TYPE /config/CONF_BOARD_TYPE /etc/dcentos/pcb; do [ -r "$f" ] && { head -1 "$f"; break; }; done)"
        printf "BOS_MODEL=%s\n" "$(grep "^model" /etc/bosminer.toml 2>/dev/null | head -1)"
        printf "DT_MODEL=%s\n" "$(tr "\000" "\n" < /proc/device-tree/model 2>/dev/null | head -1)"
        printf "DT_COMPATIBLE=%s\n" "$(tr "\000" "\n" < /proc/device-tree/compatible 2>/dev/null | tr "\n" " ")"
        printf "CPU_SYSTEM=%s\n" "$(sed -n "s/^Hardware[[:space:]]*:[[:space:]]*//p;s/^model name[[:space:]]*:[[:space:]]*//p" /proc/cpuinfo 2>/dev/null | head -2 | tr "\n" " ")"
        printf "PCB_OBSERVATION=%s\n" "pending"
        printf "HASHBOARD_EEPROM=%s\n" "$(
            hb_reader=$(command -v i2cget 2>/dev/null) || hb_reader=""
            if [ -z "$hb_reader" ]; then
                for hb_p in /usr/sbin/i2cget /bin/i2cget /usr/bin/i2cget; do
                    [ -x "$hb_p" ] && { hb_reader=$hb_p; break; }
                done
            fi
            if [ -z "$hb_reader" ]; then
                printf "%s" "reader-unavailable"
            else
                hb_out=""
                for hb_addr in 50 51 52; do
                    hb_b0=$("$hb_reader" -y 1 0x$hb_addr 0 b 2>/dev/null | tr "A-F" "a-f")
                    if [ -z "$hb_b0" ]; then
                        hb_slot="absent"
                    else
                        hb_b1=$("$hb_reader" -y 1 0x$hb_addr 1 b 2>/dev/null | tr "A-F" "a-f")
                        if [ "$hb_b0:$hb_b1" = "0x05:0x11" ]; then
                            hb_slot="05:11"
                        elif [ -n "$hb_b1" ]; then
                            hb_slot="foreign:$hb_b0:$hb_b1"
                        else
                            hb_slot="partial:$hb_b0"
                        fi
                    fi
                    if [ -n "$hb_out" ]; then
                        hb_out="$hb_out,0x$hb_addr=$hb_slot"
                    else
                        hb_out="0x$hb_addr=$hb_slot"
                    fi
                done
                printf "%s" "$hb_out"
            fi
        )"
    ') || { log "ERROR: unable to read exact Amlogic target identity"; exit 1; }

    board_target=$(printf '%s\n' "$identity" | sed -n 's/^BOARD_TARGET=//p' | head -1)
    normalized=$(normalize_target_signal "$identity")
    board_norm=$(normalize_target_signal "$board_target")
    model_norm=$(printf '%s\n' "$identity" | sed -n '/^MODEL=/p;/^HWID=/p;/^BOS_MODEL=/p' | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]')
    soc_norm=$(printf '%s\n' "$identity" | sed -n '/^DT_MODEL=/p;/^DT_COMPATIBLE=/p;/^CPU_SYSTEM=/p' | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]')
    pcb_norm=$(printf '%s\n' "$identity" | sed -n '/^PCB=/p;/^HWID=/p;/^DT_MODEL=/p;/^DT_COMPATIBLE=/p' | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]')
    identity_lower=$(printf '%s' "$identity" | tr '[:upper:]' '[:lower:]')

    # Decide the PCB-observation dialect from the raw stock channels with the
    # same tested extractor the terminal gate uses.  "direct" whenever any
    # known carrier token was observed (the override then changes nothing);
    # "unavailable-braiins" only when every channel is empty AND the operator
    # explicitly requested the Braiins model+SoC evidence path.
    pcb_observation=direct
    pcb_channel_raw=$(printf '%s\n' "$identity" | sed -n '/^PCB=/p;/^HWID=/p;/^DT_MODEL=/p;/^DT_COMPATIBLE=/p')
    if [ -z "$(dcent_amlogic_exact_pcb_tokens "$pcb_channel_raw")" ]; then
        if [ "$BRAIINS_MODEL_SOC_IDENTITY" = true ]; then
            pcb_observation=unavailable-braiins
        fi
    fi
    identity=$(printf '%s\n' "$identity" | sed "s/^PCB_OBSERVATION=.*/PCB_OBSERVATION=$pcb_observation/")

    if sibling_rejection=$(
        dcent_amlogic_sibling_rejection "$variant" "$normalized" "$identity_lower"
    ); then
        log "ERROR: $sibling_rejection; refusing destructive flash"
        exit 1
    fi

    if tuple_receipt=$(dcent_amlogic_identity_record_admit "$variant" "$identity"); then
        # Preserve the raw, independently observed model/SoC/PCB evidence for
        # recovery.  Braiins/L3 normally has no DCENT board_target file, so a
        # package name must never be relabelled as a live identity.  Recovery
        # can instead hash-check this transcript and run the same tuple admit
        # again before accepting the pre-install backup.
        EXACT_AMLOGIC_IDENTITY_RECORD=$identity
        EXACT_AMLOGIC_IDENTITY_RECEIPT=$tuple_receipt
        EXACT_AMLOGIC_IDENTITY_VARIANT=$variant
        EXACT_AMLOGIC_IDENTITY_DIALECT=$pcb_observation
        EXACT_AMLOGIC_OBSERVED_BOARD_TARGET=$board_target
        log "  exact target OK: $tuple_receipt"
        if [ "$pcb_observation" = unavailable-braiins ]; then
            log "  braiins dialect: direct carrier-PCB observation is unavailable under BraiinsOS; operator override active"
            log "  hashboard EEPROM evidence: $(printf '%s\n' "$identity" | sed -n 's/^HASHBOARD_EEPROM=//p' | head -1)"
        elif [ "$BRAIINS_MODEL_SOC_IDENTITY" = true ]; then
            log "  braiins override unused: a direct PCB observation was available and the stock tuple gate decided"
        fi
        return 0
    fi
    log "ERROR: $tuple_receipt; refusing destructive flash"
    log "$identity"
    exit 1

    # Kept below as unreachable reference logic until the tuple gate has
    # accumulated exact-unit observations for every historical spelling.
    case "$normalized" in
        *s19jproplus*)
            if [ "$variant" != "s19jproplus" ]; then
                log "ERROR: ${model:-${hwid:-unknown}} is not the selected installer variant; refusing destructive flash"
                exit 1
            fi
            ;;
        *t19*|*s17*|*t17*)
            log "ERROR: ${model:-${hwid:-unknown}} is an Experimental feature / In development target for this installer; refusing destructive flash"
            exit 1
            ;;
    esac

    case "$variant" in
        s19jpro-aml|s19jpro|s19j)
            case "$identity_lower" in
                *s19j\ pro+*|*s19jpro+*|*s19j\ pro\ plus*|*s19jproplus*)
                    log "ERROR: --variant s19jpro-aml refuses S19j Pro+ identity"
                    exit 1
                    ;;
            esac
            case "$normalized" in
                *s19jxp*|*s19jproplus*)
                    log "ERROR: --variant s19jpro-aml refuses S19j XP / S19j Pro+ identity"
                    exit 1
                    ;;
            esac
            case "$board_norm" in
                am3s19jproaml|amlogics19j|amlogics19jpro)
                    case "$normalized" in
                        *s19jpro*)
                            log "  exact target OK: board_target=$board_target"
                            return 0
                            ;;
                    esac
                    ;;
            esac
            case "$normalized" in
                *s19jpro*) ;;
                *)
                    log "ERROR: --variant s19jpro-aml requires exact S19j Pro Amlogic target identity before flash"
                    log "$identity"
                    exit 1
                    ;;
            esac
            ;;
        s19jproplus)
            case "$identity_lower" in
                *s19j\ xp*|*s19jxp*|*s19\ xp*|*s19xp*|*hydro*)
                    log "ERROR: --variant s19jproplus requires exact S19j Pro+ identity; refusing S19 XP / S19j XP / Hydro variants"
                    exit 1
                    ;;
            esac
            case "$board_norm" in
                am3s19jproplus|amlogics19jproplus)
                    case "$identity_lower" in
                        *s19j\ pro+*|*s19jpro+*|*s19j\ pro\ plus*|*s19jproplus*)
                            log "  exact target OK: board_target=$board_target"
                            return 0
                            ;;
                    esac
                    ;;
            esac
            case "$identity_lower" in
                *s19j\ pro+*|*s19jpro+*|*s19j\ pro\ plus*|*s19jproplus*) ;;
                *)
                    log "ERROR: --variant s19jproplus requires exact S19j Pro+ Amlogic target identity before flash"
                    log "$identity"
                    exit 1
                    ;;
            esac
            ;;
        s19kpro|s19k)
            case "$board_norm" in
                am3s19k|amlogics19k)
                    log "  exact target OK: board_target=$board_target"
                    return 0
                    ;;
            esac
            case "$normalized" in
                *s19k*) ;;
                *)
                    log "ERROR: --variant $variant requires exact S19K target identity before flash"
                    log "$identity"
                    exit 1
                    ;;
            esac
            ;;
        s21)
            case "$normalized" in
                *s21pro*|*s21xp*)
                    log "ERROR: --variant s21 is base-S21 only; S21 Pro requires --variant s21pro and S21 XP is NOT-IMPLEMENTED"
                    exit 1
                    ;;
            esac
            case "$board_norm" in
                am3s21|amlogics21)
                    log "  exact target OK: board_target=$board_target"
                    return 0
                    ;;
            esac
            case "$normalized" in
                *s21*) ;;
                *)
                    log "ERROR: --variant s21 requires exact base-S21 target identity before flash"
                    log "$identity"
                    exit 1
                    ;;
            esac
            ;;
        s21pro)
            case "$normalized" in
                *s21xp*)
                    log "ERROR: --variant s21pro refuses S21 XP identity; S21 XP is NOT-IMPLEMENTED"
                    exit 1
                    ;;
            esac
            case "$board_norm" in
                am3s21pro|amlogics21pro)
                    case "$normalized" in
                        *s21pro*)
                            log "  exact target OK: board_target=$board_target"
                            return 0
                            ;;
                    esac
                    ;;
            esac
            case "$normalized" in
                *s21pro*) ;;
                *)
                    log "ERROR: --variant s21pro requires exact S21 Pro target identity before flash"
                    log "$identity"
                    exit 1
                    ;;
            esac
            ;;
        *)
            log "ERROR: unsupported variant identity gate: $variant"
            exit 1
            ;;
    esac
    log "  exact target OK: ${model:-${hwid:-$platform}}"
}

# --- Step 0: local package-only validation --------------------------------
if [ "$BACKUP_ONLY" != true ]; then
    log "Step 0/10: local package-only validation for $FIRMWARE ($BOARD_PKG_NAME)"
    # Persistent NAND staging never inherits the lab unsigned escape hatch.
    # A successful return therefore verifies authority-v1 against the operator's
    # pinned DCENT_RELEASE_PUBKEY_FILE and admits the exact board/installable
    # declaration. It does not mean this compatibility installer applied the
    # complete signed package: this route deliberately stages only `root` and
    # keeps the package `kernel` payload unwritten.
    DCENT_ALLOW_UNSIGNED_SYSUPGRADE=0 \
    DCENT_REQUIRE_INSTALLABLE_PACKAGE=1 \
        bash "$SCRIPT_DIR/pre_flash_validate.sh" --package-only "$FIRMWARE" "$BOARD_PKG_NAME"
else
    log "Step 0/10: --backup-only - skip package validation (no flash)"
fi

# --- Step 1: SSH + tool preflight ----------------------------------------
log "Step 1/10: SSH preflight on root@$MINER_IP"
ssh_run "echo SSH_OK" >/dev/null || { log "ERROR: SSH failed"; exit 1; }

PLATFORM=$(ssh_run "cat /etc/bos_platform 2>/dev/null || cat /etc/dcentos-platform 2>/dev/null || echo unknown")
log "  platform: $PLATFORM"
case "$PLATFORM" in
    am3-aml*) ;;
    *) log "ERROR: not am3-aml - refusing destructive flash on $PLATFORM"; exit 1 ;;
esac
require_exact_amlogic_variant "$VARIANT" "$PLATFORM"
[ -n "${EXACT_AMLOGIC_IDENTITY_RECORD:-}" ] && \
[ -n "${EXACT_AMLOGIC_IDENTITY_RECEIPT:-}" ] && \
[ -n "${EXACT_AMLOGIC_IDENTITY_VARIANT:-}" ] && \
[ -n "${EXACT_AMLOGIC_IDENTITY_DIALECT:-}" ] || {
    log "ERROR: exact Amlogic identity gate returned no typed recovery proof"
    exit 1
}
IDENTITY_PROOF_FILE=identity_tuple_pre.txt
printf '%s\n' "$EXACT_AMLOGIC_IDENTITY_RECORD" > "$ARTIFACT_DIR/$IDENTITY_PROOF_FILE"
IDENTITY_PROOF_SHA=$(local_sha256 "$ARTIFACT_DIR/$IDENTITY_PROOF_FILE")
IDENTITY_PROOF_RECEIPT=$EXACT_AMLOGIC_IDENTITY_RECEIPT
IDENTITY_PROOF_VARIANT=$EXACT_AMLOGIC_IDENTITY_VARIANT
case "$IDENTITY_PROOF_SHA" in
    *[!0-9a-f]*|'') log "ERROR: exact Amlogic identity proof hash is not lowercase hex"; exit 1 ;;
    *) ;;
esac
case "${#IDENTITY_PROOF_SHA}" in
    64) ;;
    *) log "ERROR: could not hash exact Amlogic identity proof"; exit 1 ;;
esac
log "  recovery identity proof: schema=dcentos.amlogic-identity-tuple/v1 variant=$EXACT_AMLOGIC_IDENTITY_VARIANT sha256=$IDENTITY_PROOF_SHA"

MISSING_BACKUP=$(ssh_run 'for t in sha256sum nanddump tar dd; do command -v $t >/dev/null 2>&1 || echo $t; done')
if [ -n "$MISSING_BACKUP" ]; then
    log "ERROR: missing backup tools on target: $MISSING_BACKUP"
    exit 1
fi
MISSING_FLASH=$(ssh_run 'for t in nandwrite flash_erase fw_setenv fw_printenv; do command -v $t >/dev/null 2>&1 || echo $t; done')
FLASH_TOOLS_OK=true
if [ -n "$MISSING_FLASH" ]; then
    FLASH_TOOLS_OK=false
    log "  FLASH blocked (Braiins L3 / missing env tools): $MISSING_FLASH"
    log "  backup nand_env+mtd5 still required; env-flip/flash refused"
    if [ "$BACKUP_ONLY" != true ] && [ "$DRY_RUN" != true ]; then
        log "ERROR: flash tools missing ($MISSING_FLASH). Use --backup-only on this image."
        exit 1
    fi
else
    log "  tools OK: nandwrite flash_erase fw_setenv nanddump tar sha256sum dd"
fi

MTD5_NAME=$(ssh_run "cat /sys/class/mtd/mtd5/name 2>/dev/null || echo unknown")
MTD5_SIZE=$(ssh_run "cat /sys/class/mtd/mtd5/size 2>/dev/null || echo 0")
MTD5_ERASESIZE=$(ssh_run "cat /sys/class/mtd/mtd5/erasesize 2>/dev/null || echo 0")
require_uint "mtd5 size" "$MTD5_SIZE"
require_uint "mtd5 erasesize" "$MTD5_ERASESIZE"
if [ "$MTD5_ERASESIZE" -ne "$ROOTFS_ERASESIZE_EXPECTED" ]; then
    log "ERROR: mtd5 erasesize $MTD5_ERASESIZE != expected $ROOTFS_ERASESIZE_EXPECTED"
    exit 1
fi
if [ "$MTD5_SIZE" -lt "$ROOTFS_END_DEC" ]; then
    log "ERROR: mtd5 size $MTD5_SIZE too small for rootfs window end $ROOTFS_END_DEC"
    exit 1
fi
case "$VARIANT" in
    s19kpro|s19k)
        S19K_MTD5_SIZE_EXPECTED=$((0x09900000))
        if [ "$MTD5_NAME" != system ]; then
            log "ERROR: S19k mtd5 name '$MTD5_NAME' != expected 'system'"
            exit 1
        fi
        if [ "$MTD5_SIZE" -ne "$S19K_MTD5_SIZE_EXPECTED" ]; then
            log "ERROR: S19k mtd5 size $MTD5_SIZE != expected $S19K_MTD5_SIZE_EXPECTED"
            exit 1
        fi
        ;;
esac
log "  mtd5 geometry OK: name=$MTD5_NAME size=$MTD5_SIZE erasesize=$MTD5_ERASESIZE window=${ROOTFS_OFFSET_HEX}+${ROOTFS_WINDOW_HEX}"

# A `nanddump --bb=padbad` image preserves physical offsets by inserting an
# eraseblock-sized placeholder for each bad block. Generic `nandwrite` skips a
# bad target block, but the held source corpus does not prove that it consumes
# the corresponding placeholder. Record the kernel MTD count on both sides of
# the duplicate backup read. Restore may admit only an explicitly stable zero;
# unknown/nonzero remains a valid backup artifact but not a replay grant.
MTD5_BAD_BLOCKS_BEFORE=$(ssh_run "cat /sys/class/mtd/mtd5/bad_blocks 2>/dev/null || echo unknown" | tr -d ' \t\r\n')
case "$MTD5_BAD_BLOCKS_BEFORE" in
    ''|*[!0-9]*) MTD5_BAD_BLOCKS_BEFORE=unknown ;;
esac

if ! ssh_stream_get "cat /proc/mtd" "$ARTIFACT_DIR/proc_mtd.txt"; then
    rm -f "$ARTIFACT_DIR/proc_mtd.txt"
    log "ERROR: could not read /proc/mtd"
    exit 1
fi
[ -s "$ARTIFACT_DIR/proc_mtd.txt" ] || { log "ERROR: /proc/mtd capture is empty"; exit 1; }
PROC_MTD=$(tr '\n' '|' < "$ARTIFACT_DIR/proc_mtd.txt")
case "$VARIANT" in
    s19kpro|s19k)
        dcent_am3_require_exact_s19k_mtd_map_file "$ARTIFACT_DIR/proc_mtd.txt" || exit 1
        ;;
esac
COMPUTED_MTD5_BASE=$(dcent_am3_mtd5_base_from_proc_mtd "$ARTIFACT_DIR/proc_mtd.txt" || true)
COMPUTED_ROOTFS_LOCAL=
COMPUTED_FLAG_LOCAL=
if [ -n "${COMPUTED_MTD5_BASE:-}" ]; then
    COMPUTED_ROOTFS_LOCAL=$(printf '0x%08X' $((DCENT_AM3_NANDROOTFS_GLOBAL - COMPUTED_MTD5_BASE)))
    COMPUTED_FLAG_LOCAL=$(printf '0x%08X' $((DCENT_AM3_RECOVERY_FLAG_GLOBAL - COMPUTED_MTD5_BASE)))
    if [ "$COMPUTED_MTD5_BASE" = "0x06100000" ]; then
        log "ERROR: computed mtd5 base 0x06100000 is size-sum without the 6MiB hole; refuse"
        exit 1
    fi
    if [ "$COMPUTED_ROOTFS_LOCAL" != "$DCENT_AM3_ROOTFS_OFFSET_HEX" ] || \
       [ "$COMPUTED_FLAG_LOCAL" != "$DCENT_AM3_RECOVERY_FLAG_OFFSET_HEX" ]; then
        log "ERROR: planned locals $DCENT_AM3_ROOTFS_OFFSET_HEX/$DCENT_AM3_RECOVERY_FLAG_OFFSET_HEX != computed $COMPUTED_ROOTFS_LOCAL/$COMPUTED_FLAG_LOCAL (base $COMPUTED_MTD5_BASE)"
        exit 1
    fi
    log "  computed mtd5_base=$COMPUTED_MTD5_BASE rootfs_local=$COMPUTED_ROOTFS_LOCAL flag_local=$COMPUTED_FLAG_LOCAL"
else
    log "ERROR: could not compute mtd5 base from /proc/mtd; refuse geometry-blind backup"
    exit 1
fi

# --- Step 2: backup nand_env + mtd5 + fw_env -----------------------------
log "Step 2/10: backup nand_env + mtd5 + fw_printenv to $ARTIFACT_DIR"
if ssh_run "command -v fw_printenv >/dev/null 2>&1"; then
    ssh_run "fw_printenv" > "$ARTIFACT_DIR/fw_env_pre.txt"
    [ -s "$ARTIFACT_DIR/fw_env_pre.txt" ] || { log "ERROR: fw_printenv backup is empty"; exit 1; }
    FW_PRINTENV_PRESENT=true
else
    printf '%s\n' "ABSENT_BRAIINS_L3" > "$ARTIFACT_DIR/fw_env_pre.txt"
    FW_PRINTENV_PRESENT=false
    log "  fw_printenv ABSENT_BRAIINS_L3 - nand_env dd is the env backup"
fi
GPIO437_VAL=$(ssh_run 'if [ -f /sys/class/gpio/gpio437/value ]; then cat /sys/class/gpio/gpio437/value; else echo unexported; fi')
printf '%s\n' "$GPIO437_VAL" > "$ARTIFACT_DIR/gpio437.value"
log "  gpio437.value=$GPIO437_VAL"
NAND_ENV_RECHECK="$ARTIFACT_DIR/.nand_env.recheck.bin"
if ! ssh_stream_get "dd if=/dev/nand_env bs=64K count=1 2>/dev/null" "$ARTIFACT_DIR/nand_env.bak"; then
    rm -f "$ARTIFACT_DIR/nand_env.bak" "$NAND_ENV_RECHECK"
    log "ERROR: first host-streamed nand_env backup read failed"
    exit 1
fi
if ! ssh_stream_get "dd if=/dev/nand_env bs=64K count=1 2>/dev/null" "$NAND_ENV_RECHECK"; then
    rm -f "$NAND_ENV_RECHECK"
    log "ERROR: duplicate host-streamed nand_env backup read failed"
    exit 1
fi
NAND_ENV_SIZE=$(wc -c < "$ARTIFACT_DIR/nand_env.bak")
require_uint "nand_env backup size" "$NAND_ENV_SIZE"
[ "$NAND_ENV_SIZE" -eq 65536 ] || {
    rm -f "$NAND_ENV_RECHECK"
    log "ERROR: nand_env backup size $NAND_ENV_SIZE != 65536"
    exit 1
}
NAND_ENV_RECHECK_SIZE=$(wc -c < "$NAND_ENV_RECHECK")
require_uint "nand_env duplicate-read size" "$NAND_ENV_RECHECK_SIZE"
[ "$NAND_ENV_RECHECK_SIZE" -eq 65536 ] || {
    rm -f "$NAND_ENV_RECHECK"
    log "ERROR: duplicate nand_env backup size $NAND_ENV_RECHECK_SIZE != 65536"
    exit 1
}
NAND_ENV_LOCAL_SHA=$(local_sha256 "$ARTIFACT_DIR/nand_env.bak")
NAND_ENV_RECHECK_SHA=$(local_sha256 "$NAND_ENV_RECHECK")
[ -n "$NAND_ENV_LOCAL_SHA" ] && [ "$NAND_ENV_RECHECK_SHA" = "$NAND_ENV_LOCAL_SHA" ] || {
    rm -f "$NAND_ENV_RECHECK"
    log "ERROR: duplicate host-streamed nand_env backup SHA mismatch: first $NAND_ENV_LOCAL_SHA second $NAND_ENV_RECHECK_SHA"
    exit 1
}
rm -f "$NAND_ENV_RECHECK"
log "  nand_env.bak: $NAND_ENV_SIZE bytes sha256=$NAND_ENV_LOCAL_SHA"

MTD5_RECHECK="$ARTIFACT_DIR/.mtd5_pre_install.recheck.bin"
if ! ssh_stream_get "nanddump --bb=padbad --omitoob '$ROOTFS_MTD'" "$ARTIFACT_DIR/mtd5_pre_install.bin"; then
    rm -f "$ARTIFACT_DIR/mtd5_pre_install.bin" "$MTD5_RECHECK"
    log "ERROR: first host-streamed mtd5 backup read failed"
    exit 1
fi
if ! ssh_stream_get "nanddump --bb=padbad --omitoob '$ROOTFS_MTD'" "$MTD5_RECHECK"; then
    rm -f "$MTD5_RECHECK"
    log "ERROR: duplicate host-streamed mtd5 backup read failed"
    exit 1
fi
MTD5_LOCAL_SHA=$(local_sha256 "$ARTIFACT_DIR/mtd5_pre_install.bin")
MTD5_BACKUP_SIZE=$(wc -c < "$ARTIFACT_DIR/mtd5_pre_install.bin")
require_uint "mtd5 backup size" "$MTD5_BACKUP_SIZE"
[ "$MTD5_BACKUP_SIZE" -eq "$MTD5_SIZE" ] || {
    rm -f "$MTD5_RECHECK"
    log "ERROR: mtd5 backup size $MTD5_BACKUP_SIZE != live mtd5 size $MTD5_SIZE"
    exit 1
}
MTD5_RECHECK_SIZE=$(wc -c < "$MTD5_RECHECK")
require_uint "mtd5 duplicate-read size" "$MTD5_RECHECK_SIZE"
[ "$MTD5_RECHECK_SIZE" -eq "$MTD5_SIZE" ] || {
    rm -f "$MTD5_RECHECK"
    log "ERROR: duplicate mtd5 backup size $MTD5_RECHECK_SIZE != live mtd5 size $MTD5_SIZE"
    exit 1
}
MTD5_RECHECK_SHA=$(local_sha256 "$MTD5_RECHECK")
[ -n "$MTD5_LOCAL_SHA" ] && [ "$MTD5_LOCAL_SHA" = "$MTD5_RECHECK_SHA" ] || {
    rm -f "$MTD5_RECHECK"
    log "ERROR: mtd5 backup SHA mismatch: duplicate reads differ: first $MTD5_LOCAL_SHA second $MTD5_RECHECK_SHA"
    exit 1
}
rm -f "$MTD5_RECHECK"
MTD5_BAD_BLOCKS_AFTER=$(ssh_run "cat /sys/class/mtd/mtd5/bad_blocks 2>/dev/null || echo unknown" | tr -d ' \t\r\n')
case "$MTD5_BAD_BLOCKS_AFTER" in
    ''|*[!0-9]*) MTD5_BAD_BLOCKS_AFTER=unknown ;;
esac
if [ "$MTD5_BAD_BLOCKS_BEFORE" = 0 ] && [ "$MTD5_BAD_BLOCKS_AFTER" = 0 ]; then
    MTD5_RESTORE_BAD_BLOCK_POLICY=zero-only-admitted
else
    MTD5_RESTORE_BAD_BLOCK_POLICY=refused-unmeasured-or-nonzero
fi
log "  mtd5_pre_install.bin: $MTD5_BACKUP_SIZE bytes sha256=$MTD5_LOCAL_SHA (padbad, OOB omitted, duplicate read matched)"
log "  mtd5 bad blocks before/after: $MTD5_BAD_BLOCKS_BEFORE/$MTD5_BAD_BLOCKS_AFTER (restore policy: $MTD5_RESTORE_BAD_BLOCK_POLICY)"

LIVE_BT=$(printf '%s' "${EXACT_AMLOGIC_OBSERVED_BOARD_TARGET:-}" | tr -d ' \t\r\n')
if [ -n "$LIVE_BT" ]; then
    BOARD_TARGET=$LIVE_BT
    BOARD_TARGET_SOURCE=live
else
    # Honesty: do not invent board_target from --variant / $BOARD_PKG_NAME.
    BOARD_TARGET=
    BOARD_TARGET_SOURCE=package
fi
log "  board_target='$BOARD_TARGET' board_target_source=$BOARD_TARGET_SOURCE package=$BOARD_PKG_NAME (record_s19k_backup_board_target)"
# : rust InstallArm commit plan (geometry + FirstBosThenSetFlag2).
# Extra lines (e.g. dry_run=true) are appended. Does not write NAND.
write_install_commit_plan() {
    FLAG_HEX="$COMPUTED_FLAG_LOCAL"
    BASE_HEX="$COMPUTED_MTD5_BASE"
    ERASESIZE=${ROOTFS_ERASESIZE_EXPECTED:-131072}
    FLAG_DEC=$((FLAG_HEX))
    EB_INDEX=$((FLAG_DEC / ERASESIZE))
    EB_START=$((EB_INDEX * ERASESIZE))
    EB_OFF=$((FLAG_DEC % ERASESIZE))
    EB_START_HEX=$(printf '0x%08X' "$EB_START")
    EB_OFF_HEX=$(printf '0x%X' "$EB_OFF")
    {
        echo "schema=dcentos.amlogic-install-commit/v1"
        echo "intent=InstallArm"
        echo "value=0x01"
        echo "local_offset=$FLAG_HEX"
        echo "mtd5_base=$BASE_HEX"
        echo "target_mtd=5"
        echo "eraseblock_index=$EB_INDEX"
        echo "eraseblock_start=$EB_START_HEX"
        echo "byte_in_block=$EB_OFF_HEX"
        echo "erase_count=1"
        echo "rewriter=eraseblock_rewrite"
        echo "uboot_action=FirstBosThenSetFlag2"
        echo "firstboot=S99_WAL_companion_only"
        echo "bootcmd_reads_firstboot=false"
        echo "bootm_mtd2=false"
        echo "recover_to_stock=false"
        echo "nandwrite=false"
        echo "gpio_write=false"
        echo "execute=CLEAR_FOR_FLASH"
        echo "clear_for_flash=false"
        if [ -n "${1:-}" ]; then
            echo "$1"
        fi
    } > "$ARTIFACT_DIR/INSTALL_COMMIT_PLAN.txt"
}
dcent_am3_mtd5_covers_recovery "$MTD5_BACKUP_SIZE" "$COMPUTED_MTD5_BASE" || {
    log "ERROR: mtd5 backup shorter than recovery-flag/nandrecovery_env window"
    exit 1
}
# recover_to_stock imports this window, never nand_env.bak.
dcent_am3_extract_nandrecovery_env \
    "$ARTIFACT_DIR/mtd5_pre_install.bin" \
    "$COMPUTED_MTD5_BASE" \
    "$ARTIFACT_DIR/nandrecovery_env.bin" || {
    log "ERROR: failed to slice nandrecovery_env.bin from mtd5 backup"
    exit 1
}
NANDRECOVERY_ENV_SIZE=$(wc -c < "$ARTIFACT_DIR/nandrecovery_env.bin")
if [ "$NANDRECOVERY_ENV_SIZE" -ne $((DCENT_AM3_NANDRECOVERY_ENV_LEN)) ]; then
    log "ERROR: nandrecovery_env.bin size $NANDRECOVERY_ENV_SIZE != $DCENT_AM3_NANDRECOVERY_ENV_LEN"
    exit 1
fi
NANDRECOVERY_ENV_SHA=$(local_sha256 "$ARTIFACT_DIR/nandrecovery_env.bin")
COMPUTED_ENV_LOCAL=$(printf '0x%08X' $((DCENT_AM3_NANDRECOVERY_ENV_GLOBAL - COMPUTED_MTD5_BASE)))
if command -v py >/dev/null 2>&1; then
    NAND_ENV_CRC_PY=py
elif command -v python3 >/dev/null 2>&1; then
    NAND_ENV_CRC_PY=python3
else
    log "ERROR: py/python3 missing; cannot CRC-admit nandrecovery_env.bin"
    exit 1
fi
"$NAND_ENV_CRC_PY" -3 "$SCRIPT_DIR/s19k_nand_env_crc.py" "$ARTIFACT_DIR/nandrecovery_env.bin" \
    || "$NAND_ENV_CRC_PY" "$SCRIPT_DIR/s19k_nand_env_crc.py" "$ARTIFACT_DIR/nandrecovery_env.bin" \
    || { log "ERROR: nandrecovery_env.bin CRC32 mismatch"; exit 1; }
"$NAND_ENV_CRC_PY" -3 "$SCRIPT_DIR/s19k_nand_env_crc.py" "$ARTIFACT_DIR/nand_env.bak" \
    || "$NAND_ENV_CRC_PY" "$SCRIPT_DIR/s19k_nand_env_crc.py" "$ARTIFACT_DIR/nand_env.bak" \
    || { log "ERROR: nand_env.bak CRC32 mismatch"; exit 1; }
NANDRECOVERY_ENV_CRC_OK=true
NAND_ENV_CRC_OK=true
log "  nandrecovery_env.bin: $NANDRECOVERY_ENV_SIZE bytes sha256=$NANDRECOVERY_ENV_SHA local=$COMPUTED_ENV_LOCAL crc_ok=true"

# Held .78 U-Boot recovery_set_flag erases the complete 0x20000 block and
# programs only its first byte. Linux-side RMW is therefore insufficient: any
# non-erased adjacent byte would be destroyed at the next boot. Prove the
# source block is exactly one eraseblock, byte0 is a stock state, and every
# remaining byte is already 0xFF before even calling the fixture writer.
dcent_am3_extract_recovery_flag_eraseblock \
    "$ARTIFACT_DIR/mtd5_pre_install.bin" \
    "$COMPUTED_MTD5_BASE" \
    "$ARTIFACT_DIR/recovery_flag_eb.bin" || {
    log "ERROR: failed to slice recovery_flag_eb.bin from mtd5 backup"
    exit 1
}
FLAG_EB_SHA=$(local_sha256 "$ARTIFACT_DIR/recovery_flag_eb.bin")
FLAG_EB_VALUE=$(od -An -tx1 -N1 "$ARTIFACT_DIR/recovery_flag_eb.bin" | tr -d ' \t\r\n')
FLAG_EB_TAIL_SHA=not-evaluated
FLAG_EB_EXCLUSIVE=not-evaluated-non-s19k
case "$VARIANT" in
    s19kpro|s19k)
        if ! dcent_am3_admit_recovery_flag_eraseblock_exclusive \
            "$ARTIFACT_DIR/recovery_flag_eb.bin"; then
            log "ERROR: recovery flag eraseblock is not byte0-only; held .78 U-Boot recovery_set_flag would destroy adjacent data"
            exit 1
        fi
        FLAG_EB_TAIL_SHA=$(dd if="$ARTIFACT_DIR/recovery_flag_eb.bin" bs=1 skip=1 2>/dev/null | sha256sum | awk '{print $1}')
        FLAG_EB_EXCLUSIVE=true
        log "  recovery_flag_eb.bin: sha256=$FLAG_EB_SHA byte0=$FLAG_EB_VALUE tail_all_ff=true (S19k .78 U-Boot one-byte rewrite safe)"
        ;;
esac

# `nand_env` + mtd5 is sufficient only for this installer's narrow rollback
# mechanics. Vendor factory SD erases the full device, including config/nvdata
# and unit calibration. For S19k --backup-only, produce a separate read-only
# six-part logical rescue capture. A logical `padbad`/OOB-omitted capture remains
# useful when factory bad blocks exist, but it is not a physical replay image:
# preserve stable per-partition counts and the boot NAND transcript without
# claiming that counts identify positions or that padbad can feed nandwrite.
FULL_RESCUE_CAPTURE=false
FULL_RESCUE_LEDGER=none
FULL_RESCUE_LEDGER_SHA=none
if [ "$BACKUP_ONLY" = true ] && { [ "$VARIANT" = s19kpro ] || [ "$VARIANT" = s19k ]; }; then
    case "$MTD5_BAD_BLOCKS_BEFORE:$MTD5_BAD_BLOCKS_AFTER" in
        *[!0-9:]*|:*)
            log "ERROR: full logical capture requires numeric mtd5 bad-block counts (got $MTD5_BAD_BLOCKS_BEFORE/$MTD5_BAD_BLOCKS_AFTER)"
            exit 1
            ;;
    esac
    if [ "$MTD5_BAD_BLOCKS_BEFORE" != "$MTD5_BAD_BLOCKS_AFTER" ]; then
        log "ERROR: mtd5 bad-block count changed across duplicate capture ($MTD5_BAD_BLOCKS_BEFORE -> $MTD5_BAD_BLOCKS_AFTER)"
        exit 1
    fi
    ssh_stream_get "dmesg" "$ARTIFACT_DIR/nand_boot_dmesg.txt" || {
        rm -f "$ARTIFACT_DIR/nand_boot_dmesg.txt"
        log "ERROR: could not retain the read-only boot NAND/ECC transcript"
        exit 1
    }
    [ -s "$ARTIFACT_DIR/nand_boot_dmesg.txt" ] || {
        log "ERROR: boot NAND/ECC transcript is empty"
        exit 1
    }
    NAND_BOOT_DMESG_SHA=$(local_sha256 "$ARTIFACT_DIR/nand_boot_dmesg.txt")
    FULL_RESCUE_ROWS=
    for MTD_INDEX in 0 1 2 3 4; do
        case "$MTD_INDEX" in
            0) MTD_EXPECTED_NAME=bootloader; MTD_EXPECTED_SIZE=$((0x00200000)) ;;
            1) MTD_EXPECTED_NAME=tpl; MTD_EXPECTED_SIZE=$((0x00800000)) ;;
            2) MTD_EXPECTED_NAME=stock_system; MTD_EXPECTED_SIZE=$((0x03200000)) ;;
            3) MTD_EXPECTED_NAME=stock_config; MTD_EXPECTED_SIZE=$((0x00500000)) ;;
            4) MTD_EXPECTED_NAME=overlay; MTD_EXPECTED_SIZE=$((0x02000000)) ;;
        esac
        MTD_DEV="/dev/mtd$MTD_INDEX"
        MTD_LIVE_NAME=$(ssh_run "cat /sys/class/mtd/mtd$MTD_INDEX/name 2>/dev/null || echo unknown" | tr -d ' \t\r\n')
        MTD_LIVE_SIZE=$(ssh_run "cat /sys/class/mtd/mtd$MTD_INDEX/size 2>/dev/null || echo 0" | tr -d ' \t\r\n')
        require_uint "mtd$MTD_INDEX size" "$MTD_LIVE_SIZE"
        if [ "$MTD_LIVE_NAME" != "$MTD_EXPECTED_NAME" ] || [ "$MTD_LIVE_SIZE" -ne "$MTD_EXPECTED_SIZE" ]; then
            log "ERROR: mtd$MTD_INDEX live identity $MTD_LIVE_NAME/$MTD_LIVE_SIZE != exact $MTD_EXPECTED_NAME/$MTD_EXPECTED_SIZE"
            exit 1
        fi
        MTD_BAD_BEFORE=$(ssh_run "cat /sys/class/mtd/mtd$MTD_INDEX/bad_blocks 2>/dev/null || echo unknown" | tr -d ' \t\r\n')
        case "$MTD_BAD_BEFORE" in
            ''|*[!0-9]*) log "ERROR: mtd$MTD_INDEX bad-block count is not numeric before capture: $MTD_BAD_BEFORE"; exit 1 ;;
        esac
        MTD_CAPTURE="$ARTIFACT_DIR/mtd${MTD_INDEX}_${MTD_EXPECTED_NAME}.padbad.bin"
        MTD_DUP="$ARTIFACT_DIR/.mtd${MTD_INDEX}_${MTD_EXPECTED_NAME}.duplicate.bin"
        MTD_LOCKED_PAGES=none
        if ! ssh_stream_get "nanddump --bb=padbad --omitoob '$MTD_DEV'" "$MTD_CAPTURE"; then
            # Locked-page reconstruct fallback (2026-08-31, live .80 evidence):
            # the Amlogic boot partition carries factory-locked pages the NAND
            # driver refuses at stream level (ENODEV at a fixed page), so the
            # fast full-stream dump can never complete for mtd0 on this
            # hardware. Reconstruct on the unit -- per-eraseblock windows,
            # per-page retry only inside failing blocks, unreadable pages
            # padded 0xFF with byte offsets recorded -- for BOTH passes, then
            # stream the two images and the page list back. Bad blocks (none
            # observed on this unit; counters recorded around capture) would
            # surface identically and are named in the same page list.
            log "  mtd$MTD_INDEX full stream refused (factory-locked pages); reconstructing per-eraseblock"
            MTD_RECONSTRUCT_SCRIPT="$ARTIFACT_DIR/.mtd${MTD_INDEX}.reconstruct.sh"
            cat > "$MTD_RECONSTRUCT_SCRIPT" <<'MTD_RECONSTRUCT'
DEV=$1
SIZE=$2
PASS=$3
EB=131072
PG=2048
IMG=/tmp/dcent_reconstruct.$PASS.image
PAGES=/tmp/dcent_reconstruct.$PASS.pages
: > "$IMG"
: > "$PAGES"
off=0
while [ "$off" -lt "$SIZE" ]; do
    if nanddump --omitoob -s "$off" -l "$EB" "$DEV" > /tmp/dcent_reconstruct.eb 2>/dev/null \
        && [ "$(wc -c < /tmp/dcent_reconstruct.eb)" -eq "$EB" ]; then
        cat /tmp/dcent_reconstruct.eb >> "$IMG"
    else
        p=0
        while [ "$p" -lt "$EB" ]; do
            if nanddump --omitoob -s $((off+p)) -l "$PG" "$DEV" > /tmp/dcent_reconstruct.pg 2>/dev/null \
                && [ "$(wc -c < /tmp/dcent_reconstruct.pg)" -eq "$PG" ]; then
                cat /tmp/dcent_reconstruct.pg >> "$IMG"
            else
                dd if=/dev/zero bs=1 count="$PG" 2>/dev/null | tr "\000" "\377" >> "$IMG"
                echo $((off+p)) >> "$PAGES"
            fi
            p=$((p+PG))
        done
    fi
    off=$((off+EB))
done
rm -f /tmp/dcent_reconstruct.eb /tmp/dcent_reconstruct.pg
[ "$(wc -c < "$IMG")" -eq "$SIZE" ] || { echo "RECONSTRUCT_SIZE_MISMATCH" >&2; exit 1; }
exit 0
MTD_RECONSTRUCT
            for MTD_DUMP_PASS in capture duplicate; do
                if ! ssh_run "sh -s '$MTD_DEV' '$MTD_EXPECTED_SIZE' '$MTD_DUMP_PASS'" < "$MTD_RECONSTRUCT_SCRIPT"; then
                    rm -f "$MTD_CAPTURE" "$MTD_DUP" "$ARTIFACT_DIR/mtd${MTD_INDEX}.locked_pages.txt" "$MTD_RECONSTRUCT_SCRIPT"
                    log "ERROR: mtd$MTD_INDEX locked-page reconstruction ($MTD_DUMP_PASS) failed"
                    exit 1
                fi
            done
            rm -f "$MTD_RECONSTRUCT_SCRIPT"
            ssh_stream_get "cat /tmp/dcent_reconstruct.capture.image" "$MTD_CAPTURE" || {
                rm -f "$MTD_CAPTURE" "$MTD_DUP"
                log "ERROR: mtd$MTD_INDEX reconstructed capture stream failed"
                exit 1
            }
            ssh_stream_get "cat /tmp/dcent_reconstruct.duplicate.image" "$MTD_DUP" || {
                rm -f "$MTD_DUP"
                log "ERROR: mtd$MTD_INDEX reconstructed duplicate stream failed"
                exit 1
            }
            ssh_stream_get "cat /tmp/dcent_reconstruct.capture.pages" "$ARTIFACT_DIR/mtd${MTD_INDEX}.locked_pages.txt" || {
                rm -f "$MTD_CAPTURE" "$MTD_DUP" "$ARTIFACT_DIR/mtd${MTD_INDEX}.locked_pages.txt"
                log "ERROR: mtd$MTD_INDEX locked-page list stream failed"
                exit 1
            }
            MTD_LOCKED_PAGES=$(ssh_run "tr '\n' '+' < /tmp/dcent_reconstruct.capture.pages" | sed 's/+$//' | tr -d ' \t\r\n')
            ssh_run "rm -f /tmp/dcent_reconstruct.capture.image /tmp/dcent_reconstruct.duplicate.image /tmp/dcent_reconstruct.capture.pages /tmp/dcent_reconstruct.duplicate.pages" || true
            log "  mtd$MTD_INDEX locked/unreadable pages (0xFF padded): ${MTD_LOCKED_PAGES:-none}"
        fi
        if [ "$MTD_LOCKED_PAGES" = "none" ]; then
            ssh_stream_get "nanddump --bb=padbad --omitoob '$MTD_DEV'" "$MTD_DUP" || {
                rm -f "$MTD_DUP"
                log "ERROR: mtd$MTD_INDEX duplicate full-rescue stream failed"
                exit 1
            }
        fi
        MTD_CAPTURE_SIZE=$(wc -c < "$MTD_CAPTURE" | tr -d ' \t')
        MTD_DUP_SIZE=$(wc -c < "$MTD_DUP" | tr -d ' \t')
        MTD_CAPTURE_SHA=$(local_sha256 "$MTD_CAPTURE")
        MTD_DUP_SHA=$(local_sha256 "$MTD_DUP")
        MTD_LIVE_OVERLAY=no
        if [ "$MTD_CAPTURE_SIZE" -ne "$MTD_EXPECTED_SIZE" ] || \
           [ "$MTD_DUP_SIZE" -ne "$MTD_EXPECTED_SIZE" ] || \
           [ -z "$MTD_CAPTURE_SHA" ] || [ "$MTD_CAPTURE_SHA" != "$MTD_DUP_SHA" ]; then
            # Live-overlay disposition (2026-08-31, live .80 evidence): the
            # running Braiins system continuously writes mtd4 (overlay), so two
            # sequential full reads legitimately differ and byte-identity can
            # never hold while stock stays untouched (never stop stock). Both
            # passes keep exact partition size; retain BOTH hashes in the
            # ledger with duplicate=mismatch-live-overlay. Any other partition
            # mismatching remains a hard failure.
            if [ "$MTD_INDEX" = "4" ] && [ "$MTD_CAPTURE_SIZE" -eq "$MTD_EXPECTED_SIZE" ] && [ "$MTD_DUP_SIZE" -eq "$MTD_EXPECTED_SIZE" ]; then
                MTD_LIVE_OVERLAY=yes
                log "  mtd4 overlay duplicate mismatch (live-written by stock); retaining both hashes"
                mv -f "$MTD_DUP" "$ARTIFACT_DIR/mtd4_overlay.duplicate.live-mismatch.bin"
            else
                rm -f "$MTD_DUP"
                log "ERROR: mtd$MTD_INDEX duplicate capture size/hash mismatch"
                exit 1
            fi
        fi
        rm -f "$MTD_DUP"
        MTD_BAD_AFTER=$(ssh_run "cat /sys/class/mtd/mtd$MTD_INDEX/bad_blocks 2>/dev/null || echo unknown" | tr -d ' \t\r\n')
        case "$MTD_BAD_AFTER" in
            ''|*[!0-9]*) log "ERROR: mtd$MTD_INDEX bad-block count is not numeric after capture: $MTD_BAD_AFTER"; exit 1 ;;
        esac
        if [ "$MTD_BAD_AFTER" != "$MTD_BAD_BEFORE" ]; then
            log "ERROR: mtd$MTD_INDEX bad-block count changed across duplicate capture ($MTD_BAD_BEFORE -> $MTD_BAD_AFTER)"
            exit 1
        fi
        if [ "$MTD_LIVE_OVERLAY" = "yes" ]; then
            MTD_DUPLICATE_FIELD="duplicate=mismatch-live-overlay,sha256_duplicate=$MTD_DUP_SHA"
        else
            MTD_DUPLICATE_FIELD="duplicate-match"
        fi
        printf -v FULL_RESCUE_ROWS '%s%s\n' "$FULL_RESCUE_ROWS" \
            "mtd${MTD_INDEX}=$MTD_EXPECTED_NAME,$MTD_CAPTURE_SIZE,$MTD_CAPTURE_SHA,padbad,omitoob,$MTD_DUPLICATE_FIELD,badblocks=$MTD_BAD_AFTER,locked_pages=$MTD_LOCKED_PAGES"
        log "  full rescue mtd$MTD_INDEX/$MTD_EXPECTED_NAME: $MTD_CAPTURE_SIZE bytes sha256=$MTD_CAPTURE_SHA $MTD_DUPLICATE_FIELD locked_pages=$MTD_LOCKED_PAGES"
    done
    printf -v FULL_RESCUE_ROWS '%s%s\n' "$FULL_RESCUE_ROWS" \
        "mtd5=system,$MTD5_BACKUP_SIZE,$MTD5_LOCAL_SHA,padbad,omitoob,duplicate-match,badblocks=$MTD5_BAD_BLOCKS_AFTER,locked_pages=none"
    FULL_RESCUE_LEDGER=FULL_RESCUE_LEDGER.txt
    {
        echo "schema=dcentos.s19k-aml-full-logical-rescue/v1"
        echo "capture=read-only"
        echo "execute=false"
        echo "clear_for_flash=false"
        echo "platform_observation=$PLATFORM"
        if [ "$EXACT_AMLOGIC_IDENTITY_DIALECT" = unavailable-braiins ]; then
            echo "identity_disposition=tuple-proven-$EXACT_AMLOGIC_IDENTITY_VARIANT-braiins-model-soc"
        else
            echo "identity_disposition=tuple-proven-$EXACT_AMLOGIC_IDENTITY_VARIANT"
        fi
        echo "package_target=$BOARD_PKG_NAME"
        echo "partition_count=6"
        echo "proc_mtd=proc_mtd.txt"
        echo "proc_mtd_sha256=$(local_sha256 "$ARTIFACT_DIR/proc_mtd.txt")"
        echo "identity_proof=$IDENTITY_PROOF_FILE"
        echo "identity_proof_sha256=$IDENTITY_PROOF_SHA"
        echo "logical_data=padbad"
        echo "oob=omitted"
        echo "duplicate_streams=true"
        echo "bad_block_counts=stable-per-partition"
        echo "bad_block_positions=not-proven-by-count-only-sysfs"
        echo "nand_boot_dmesg=nand_boot_dmesg.txt"
        echo "nand_boot_dmesg_sha256=$NAND_BOOT_DMESG_SHA"
        echo "raw_linux_restore=false"
        echo "padbad_nandwrite_replay=false"
        echo "physical_full_device_replay=false"
        echo "unit_specific_config_included=true"
        echo "sensitive_unit_data=true"
        echo "artifact_permissions=0700-dir+0600-files"
        echo "offhost_encrypted_copy_required=true"
        printf '%s' "$FULL_RESCUE_ROWS"
    } > "$ARTIFACT_DIR/$FULL_RESCUE_LEDGER"
    chmod 0600 "$ARTIFACT_DIR"/*.bin "$ARTIFACT_DIR"/*.txt
    FULL_RESCUE_LEDGER_SHA=$(local_sha256 "$ARTIFACT_DIR/$FULL_RESCUE_LEDGER")
    FULL_RESCUE_CAPTURE=true
    log "  $FULL_RESCUE_LEDGER written sha256=$FULL_RESCUE_LEDGER_SHA (read-only; contains sensitive unit state)"
fi
{
    echo "schema=dcentos.amlogic-backup/v1"
    echo "board_target=$BOARD_TARGET"
    echo "board_target_source=$BOARD_TARGET_SOURCE"
    echo "board_target_package=$BOARD_PKG_NAME"
    echo "identity_proof_schema=dcentos.amlogic-identity-tuple/v1"
    echo "identity_proof_variant=$EXACT_AMLOGIC_IDENTITY_VARIANT"
    echo "identity_proof_file=$IDENTITY_PROOF_FILE"
    echo "identity_proof_sha256=$IDENTITY_PROOF_SHA"
    echo "identity_proof_receipt=$EXACT_AMLOGIC_IDENTITY_RECEIPT"
    echo "clear_for_flash=false"
    echo "gpio437_value=$GPIO437_VAL"
    echo "fw_printenv_present=$FW_PRINTENV_PRESENT"
    echo "nand_env=nand_env.bak"
    echo "mtd5_window=mtd5_pre_install.bin"
    echo "nandrecovery_env=nandrecovery_env.bin"
    echo "nandrecovery_env_local=$COMPUTED_ENV_LOCAL"
    echo "nandrecovery_env_sha256=$NANDRECOVERY_ENV_SHA"
    echo "nandrecovery_env_crc_ok=$NANDRECOVERY_ENV_CRC_OK"
    echo "nand_env_crc_ok=$NAND_ENV_CRC_OK"
    echo "nand_env_bak_is_not_nandrecovery_env=true"
    echo "nand_env_len=$NAND_ENV_SIZE"
    echo "mtd5_len=$MTD5_BACKUP_SIZE"
    echo "mtd5_dump_bad_blocks=padbad"
    echo "mtd5_dump_oob=omitted"
    echo "mtd5_duplicate_read=true"
    echo "mtd5_bad_block_count_before=$MTD5_BAD_BLOCKS_BEFORE"
    echo "mtd5_bad_block_count_after=$MTD5_BAD_BLOCKS_AFTER"
    echo "mtd5_restore_bad_block_policy=$MTD5_RESTORE_BAD_BLOCK_POLICY"
    echo "nand_env_sha256=$NAND_ENV_LOCAL_SHA"
    echo "mtd5_sha256=$MTD5_LOCAL_SHA"
    echo "backup_scope=narrow-install-rollback-nand_env+mtd5"
    echo "complete_stock_byte_restore=false"
    echo "full_logical_six_mtd_capture=$FULL_RESCUE_CAPTURE"
    echo "factory_full_erase_capture_complete=false"
    echo "factory_full_erase_backup_ready=false"
    echo "factory_full_erase_backup_ready_blockers=logical-oob-omitted-capture-not-physical-replay+bad-block-positions-unproven+encrypted-offhost-copy+unit-state-restore-live-unproven"
    echo "full_rescue_ledger=$FULL_RESCUE_LEDGER"
    echo "full_rescue_ledger_sha256=$FULL_RESCUE_LEDGER_SHA"
    echo "recovery_flag_eraseblock=recovery_flag_eb.bin"
    echo "recovery_flag_eraseblock_sha256=$FLAG_EB_SHA"
    echo "recovery_flag_eraseblock_byte0=0x$FLAG_EB_VALUE"
    echo "recovery_flag_eraseblock_tail_sha256=$FLAG_EB_TAIL_SHA"
    echo "recovery_flag_eraseblock_exclusive=$FLAG_EB_EXCLUSIVE"
    echo "fw_setenv_present=$FLASH_TOOLS_OK"
    echo "backup_tools_ok=true"
    echo "flash_tools_ok=$FLASH_TOOLS_OK"
    echo "braiins_success_is_not_stock_go=true"
    echo "l3_hint=Braiins AML image may lack fw_printenv/fw_setenv; backup nand_env+mtd5 is still required, env-flip/flash is refused"
    echo "proc_mtd=$PROC_MTD"
    echo "mtd5_name=$MTD5_NAME"
    echo "nandrootfs_global=$DCENT_AM3_NANDROOTFS_GLOBAL"
    echo "recovery_flag_global=$DCENT_AM3_RECOVERY_FLAG_GLOBAL"
    echo "recovery_flag_local=$DCENT_AM3_RECOVERY_FLAG_OFFSET_HEX"
    echo "rootfs_local=$DCENT_AM3_ROOTFS_OFFSET_HEX"
    echo "computed_mtd5_base=${COMPUTED_MTD5_BASE:-unknown}"
    echo "computed_rootfs_local=${COMPUTED_ROOTFS_LOCAL:-unknown}"
    echo "computed_flag_local=${COMPUTED_FLAG_LOCAL:-unknown}"
} > "$ARTIFACT_DIR/BACKUP_LEDGER.txt"
log "  BACKUP_LEDGER.txt written (CLEAR_FOR_FLASH=false)"

# : rust already formats recover-to-stock. The installer must emit
# the plan next to the CRC-admitted sidecar. Execute stays FLASH-refused.
{
    echo "schema=dcentos.amlogic-recover-to-stock/v1"
    echo "intent=UbootStockRevert"
    echo "flag_value=0x02"
    echo "flag_local=$COMPUTED_FLAG_LOCAL"
    echo "nandrecovery_env_local=$COMPUTED_ENV_LOCAL"
    echo "recover_env_source=nandrecovery_env.bin"
    echo "nand_env_bak_is_not_nandrecovery_env=true"
    echo "env_crc_ok=true"
    echo "step0=ImportNandrecoveryEnv"
    echo "step1=EraseNvdata"
    echo "step2=Reset"
    echo "nand_erase_part=nvdata"
    echo "bootm_mtd2=false"
    echo "uboot_recover_env=nand read + env import -d -c"
    echo "uboot_recover_to_stock=run recover_env; nand erase.part nvdata; reset"
    echo "execute=CLEAR_FOR_FLASH"
    echo "clear_for_flash=false"
} > "$ARTIFACT_DIR/RECOVER_TO_STOCK_PLAN.txt"
{
    echo "schema=dcentos.amlogic-recover-execute/v1"
    echo "execute=refused"
    echo "reason=CLEAR_FOR_FLASH"
    echo "clear_for_flash=false"
    echo "flag_value=0x02"
    echo "flag_local=$COMPUTED_FLAG_LOCAL"
    echo "nandrecovery_env_local=$COMPUTED_ENV_LOCAL"
    echo "recover_env_source=nandrecovery_env.bin"
    echo "recover_env_ram=0x01060000"
    echo "env_import_size=0x10000"
    echo "nandrecovery_env_offset=0x0B000000"
    echo "env_size=0x10000"
    echo "step0=ImportNandrecoveryEnv"
    echo "step1=EraseNvdata"
    echo "step2=Reset"
    echo "nand_erase_part=nvdata"
    echo "bootm_mtd2=false"
    echo "pass=admit_s19k_recover_execute_returns_ClearForFlashNotYet"
    echo "fail=nand_erase_or_env_import_without_admit"
} > "$ARTIFACT_DIR/RECOVER_EXECUTE_REFUSE.txt"
log "  RECOVER_TO_STOCK_PLAN.txt written (plan-only; flag 0x02 / nandrecovery_env)"
log "  RECOVER_EXECUTE_REFUSE.txt written (execute=refused reason=CLEAR_FOR_FLASH)"

# : a plan without a successful walk is not a backup artifact.
RECOVER_RUNNER="$SCRIPT_DIR/recover_amlogic_to_stock.sh"
if [ ! -r "$RECOVER_RUNNER" ]; then
    log "ERROR: missing $RECOVER_RUNNER; backup artifact is not walkable"
    exit 1
fi
if ! sh "$RECOVER_RUNNER" --artifact-dir "$ARTIFACT_DIR" --dry-run; then
    log "ERROR: recover-to-stock --dry-run failed; refusing successful backup"
    exit 1
fi
if [ ! -f "$ARTIFACT_DIR/RECOVER_WALK.txt" ]; then
    log "ERROR: recover-to-stock --dry-run did not write RECOVER_WALK.txt"
    exit 1
fi
log "  recover-to-stock --dry-run OK (RECOVER_WALK.txt; FLASH/NAND still refused)"

# : a backup without a walked 0x01 fixture is not InstallArm-ready.
FLAG_HELPER="$SCRIPT_DIR/s19k_write_recovery_flag.sh"
if [ ! -r "$FLAG_HELPER" ]; then
    log "ERROR: missing $FLAG_HELPER; backup artifact is not InstallArm-walkable"
    exit 1
fi
write_install_commit_plan "walk=flag_01_fixture"
if ! sh "$FLAG_HELPER" --value 0x01 --mtd5-base "$COMPUTED_MTD5_BASE" \
    --fixture-in "$ARTIFACT_DIR/recovery_flag_eb.bin" \
    --fixture-out "$ARTIFACT_DIR/recovery_flag_eb.0x01.bin" \
    --verify-only > "$ARTIFACT_DIR/INSTALL_COMMIT_WALK.txt"; then
    log "ERROR: recovery-flag 0x01 fixture walk failed; refusing successful backup"
    exit 1
fi
if ! grep -q '^fixture_value=0x01$' "$ARTIFACT_DIR/INSTALL_COMMIT_WALK.txt"; then
    log "ERROR: 0x01 fixture walk did not write fixture_value=0x01"
    exit 1
fi
if [ ! -f "$ARTIFACT_DIR/recovery_flag_eb.0x01.bin" ]; then
    log "ERROR: 0x01 fixture-out missing after walk"
    exit 1
fi
FLAG_01_OUT="$ARTIFACT_DIR/recovery_flag_eb.0x01.bin"
FLAG_01_LEN=$(wc -c < "$FLAG_01_OUT" | tr -d ' \t')
if [ "$FLAG_01_LEN" -ne "$DCENT_AM3_ROOTFS_ERASESIZE_EXPECTED" ]; then
    log "ERROR: 0x01 fixture-out length $FLAG_01_LEN != $DCENT_AM3_ROOTFS_ERASESIZE_EXPECTED"
    exit 1
fi
FLAG_01_BYTE=$(od -An -tx1 -N1 "$FLAG_01_OUT" | tr -d ' \t\n')
if [ "$FLAG_01_BYTE" != "01" ]; then
    log "ERROR: 0x01 fixture-out byte0=$FLAG_01_BYTE (want 01); refusing successful backup"
    exit 1
fi
log "  recovery-flag 0x01 fixture walk OK (INSTALL_COMMIT_WALK.txt; byte0=01 len=$FLAG_01_LEN; FLASH/NAND still refused)"

if [ "$BACKUP_ONLY" = true ]; then
    if [ "$FULL_RESCUE_CAPTURE" = true ]; then
        log "[BACKUP-ONLY] six-MTD logical padbad/OOB-omitted capture staged with stable bad-block counts; positions and physical replay are not proven, and no raw restore is authorized. FLASH not started."
    else
        log "[BACKUP-ONLY] narrow nand_env+mtd5+gpio437 rollback artifact staged (not a complete stock/factory-erasure rescue capture). FLASH not started."
    fi
    exit 0
fi

# --- Step 3: SCP tar + SHA256 verify -------------------------------------
# Stage on /data not /tmp -- sysupgrade tarball + extracted squashfs blow the
# 64 MB tmpfs at /tmp on S9 and leave little headroom on Amlogic /tmp either.
#.
log "Step 3/10: /data free-space preflight on $MINER_IP"
DATA_FREE_KB=$(ssh_run "df -Pk /data 2>/dev/null | awk 'NR==2 {print \$4}'")
case "$DATA_FREE_KB" in
    ''|*[!0-9]*) log "ERROR: could not determine /data free space (got '$DATA_FREE_KB')"; exit 1 ;;
esac
log "  /data free: $((DATA_FREE_KB / 1024)) MB"
if [ "$DATA_FREE_KB" -lt 51200 ]; then
    log "ERROR: /data has only $((DATA_FREE_KB / 1024)) MB free; need >= 50 MB for one content-bound sysupgrade transaction."
    exit 1
fi
LOCAL_SHA=$(local_sha256 "$FIRMWARE")
[ -n "$LOCAL_SHA" ] || { log "ERROR: cannot compute local sha256"; exit 1; }
case "$LOCAL_SHA" in
    *[!0-9a-f]*|'') log "ERROR: local firmware sha256 is not lowercase hex"; exit 1 ;;
esac
[ "${#LOCAL_SHA}" -eq 64 ] || { log "ERROR: local firmware sha256 is not 64 hex chars"; exit 1; }
log "  local SHA256: $LOCAL_SHA"
REMOTE_STAGE_DIR="/data/.dcentos-sysupgrade-$LOCAL_SHA"
REMOTE_BUNDLE="$REMOTE_STAGE_DIR/bundle.tar"
REMOTE_EXTRACT="$REMOTE_STAGE_DIR/extracted"
REMOTE_PREFIX="$REMOTE_EXTRACT/$PACKAGE_PREFIX"
STAGE_READY=$(ssh_run "if [ ! -e '$REMOTE_STAGE_DIR' ] && [ ! -L '$REMOTE_STAGE_DIR' ] && umask 077 && mkdir '$REMOTE_STAGE_DIR' && chmod 0700 '$REMOTE_STAGE_DIR'; then echo yes; else echo no; fi")
[ "$STAGE_READY" = yes ] || {
    log "ERROR: content-bound remote transaction already exists or cannot be created: $REMOTE_STAGE_DIR"
    exit 1
}
log "Step 3/10: SCP $FIRMWARE -> $REMOTE_BUNDLE"
cat > "$ARTIFACT_DIR/install_preflight_manifest.json" <<EOF
{
  "stage": "backup_verified",
  "miner_ip": "$MINER_IP",
  "platform": "$PLATFORM",
  "rootfs_mtd": "$ROOTFS_MTD",
  "rootfs_offset": "$ROOTFS_OFFSET_HEX",
  "rootfs_window": "$ROOTFS_WINDOW_HEX",
  "mtd5_name": "$MTD5_NAME",
  "mtd5_size": $MTD5_SIZE,
  "mtd5_erasesize": $MTD5_ERASESIZE,
  "nand_env_sha256": "$NAND_ENV_LOCAL_SHA",
  "mtd5_backup_sha256": "$MTD5_LOCAL_SHA",
  "firmware_sha256": "$LOCAL_SHA",
  "remote_stage_dir": "$REMOTE_STAGE_DIR",
  "package_authority": "release_ed25519_authority_v1",
  "package_installable": true,
  "package_manifest_verified": true,
  "package_manifest_applied": false,
  "compatibility_projection": "rootfs_only_stock_kernel",
  "kernel_payload_applied": false,
  "dry_run": $DRY_RUN
}
EOF
log "  recovery manifest: $ARTIFACT_DIR/install_preflight_manifest.json"

scp_put "$FIRMWARE" "$REMOTE_BUNDLE"
REMOTE_SHA=$(ssh_run "[ -f '$REMOTE_BUNDLE' ] && [ ! -L '$REMOTE_BUNDLE' ] && sha256sum '$REMOTE_BUNDLE' | awk '{print \$1}'")
log "  remote SHA256: $REMOTE_SHA"
[ "$LOCAL_SHA" = "$REMOTE_SHA" ] || { log "ERROR: SHA256 mismatch after upload"; exit 1; }

# --- Step 4: extract + verify SHA256SUMS + validate MANIFEST -------------
log "Step 4/10: extract content-bound tar + verify SHA256SUMS + check MANIFEST.json"
ssh_run "[ ! -e '$REMOTE_EXTRACT' ] && [ ! -L '$REMOTE_EXTRACT' ] && umask 077 && mkdir '$REMOTE_EXTRACT' && tar xf '$REMOTE_BUNDLE' -C '$REMOTE_EXTRACT'"
ssh_run "cd '$REMOTE_PREFIX' && sha256sum -c SHA256SUMS" \
    || { log "ERROR: SHA256SUMS check failed on target"; exit 1; }

BOARD=$(ssh_run "grep -o '\"board\":[[:space:]]*\"[^\"]*\"' '$REMOTE_PREFIX/MANIFEST.json' | head -1" | tr -d '[:space:]')
PROFILE=$(ssh_run "grep -o '\"manifest_profile\":[[:space:]]*\"[^\"]*\"' '$REMOTE_PREFIX/MANIFEST.json' | head -1" | tr -d '[:space:]')
INSTALLABLE=$(ssh_run "grep -o '\"installable\":[[:space:]]*\(true\|false\)' '$REMOTE_PREFIX/MANIFEST.json' | head -1" | tr -d '[:space:]')
log "  manifest authority: $PROFILE $BOARD $INSTALLABLE"
[ "$BOARD" = "\"board\":\"$BOARD_PKG_NAME\"" ] \
    || { log "ERROR: verified MANIFEST board != exact $BOARD_PKG_NAME"; exit 1; }
[ "$PROFILE" = '"manifest_profile":"dcentos.sysupgrade-authority/v1"' ] \
    || { log "ERROR: persistent install requires verified authority-v1 manifest"; exit 1; }
[ "$INSTALLABLE" = '"installable":true' ] \
    || { log "ERROR: persistent install requires verified installable=true manifest"; exit 1; }

# --- Step 4b: in-band ed25519 re-verify (defense-in-depth, sentinel-gated) ----
# wf_c00e5d9e: if the on-device DCENT_OS exposes the verify-bundle capability
# sentinel (dropped by a verb-capable dcentrald at startup -- see main.rs), use its
# OWN pinned-key ed25519 verifier to re-check the INCOMING bundle ON-DEVICE before
# flashing -- defense-in-depth against a compromised install host. The normal case
# is already gated by host-side ed25519 + the on-device SHA256SUMS + MANIFEST checks
# above; this adds the on-device signature authority. The sentinel GUARANTEES the
# verb exists, so invoking it is SAFE (no risk of starting the daemon on a pre-verb
# binary -- the probe-safety problem). Skips gracefully when absent (fresh
# stock->DCENT_OS install, or a dcentrald predating the verb). A failed verify
# ABORTS before any flash (fail-closed).
if ssh_run "[ -f /data/dcentos/caps/verify-bundle ]"; then
    DCENTRALD_BIN=$(ssh_run "command -v dcentrald 2>/dev/null || echo /usr/bin/dcentrald")
    log "Step 4b/10: in-band ed25519 re-verify via on-device $DCENTRALD_BIN --verify-bundle"
    if ssh_run "'$DCENTRALD_BIN' --verify-bundle '$REMOTE_PREFIX'"; then
        log "  in-band ed25519 signature + MANIFEST verified on-device (known-good binary verified the incoming bundle)"
    else
        log "ERROR: in-band ed25519 re-verify FAILED -- aborting before flash (on-device verifier rejected the bundle)"
        exit 1
    fi
else
    log "Step 4b/10: in-band ed25519 re-verify SKIPPED -- no verify-bundle capability sentinel on-device (host-side ed25519 + on-device SHA256SUMS + MANIFEST already verified this bundle)"
fi

ROOT_SIZE=$(ssh_run "stat -c %s '$REMOTE_PREFIX/root'")
require_uint "root payload size" "$ROOT_SIZE"
if [ "$ROOT_SIZE" -gt "$ROOTFS_WINDOW_DEC" ]; then
    log "ERROR: root payload $ROOT_SIZE exceeds rootfs window $ROOTFS_WINDOW_DEC"
    exit 1
fi
ROOT_SHA=$(ssh_run "sha256sum '$REMOTE_PREFIX/root' | awk '{print \$1}'")
log "  root payload: $ROOT_SIZE bytes (expect ~25.6 MB)"
KERNEL_SIZE=$(ssh_run "stat -c %s '$REMOTE_PREFIX/kernel'")
require_uint "kernel payload size" "$KERNEL_SIZE"
KERNEL_SHA=$(ssh_run "sha256sum '$REMOTE_PREFIX/kernel' | awk '{print \$1}'")
log "  kernel payload: $KERNEL_SIZE bytes (expect ~16.5 MB)"

# Future mutation custody. CLEAR_FOR_FLASH remains false below, but a future
# reviewed enablement must not be able to reuse the identity, MTD map, bad-block
# count, backup, or staged payload observations collected minutes earlier. Each
# state-changing boundary gets a new no-clobber receipt. Nonzero/unknown bad
# blocks remain an absolute writer refusal because no physical replay or exact
# U-Boot/nandwrite mapping transform has been proven.
capture_pre_mutation_evidence() {
    local phase="$1"
    local identity_file="$ARTIFACT_DIR/identity_tuple_${phase}.txt"
    local proc_mtd_file="$ARTIFACT_DIR/proc_mtd_${phase}.txt"
    local receipt_file="$ARTIFACT_DIR/PRE_MUTATION_${phase}.txt"
    local current_platform current_identity_sha current_proc_mtd_sha
    local current_name current_size current_erasesize current_bad_blocks
    local staged_meta staged_bundle_sha staged_root_size staged_root_sha

    case "$phase" in
        pre_stop|pre_gpio|pre_nand) ;;
        *) log "ERROR: invalid pre-mutation evidence phase: $phase"; exit 1 ;;
    esac
    for evidence_path in "$identity_file" "$proc_mtd_file" "$receipt_file"; do
        [ ! -e "$evidence_path" ] && [ ! -L "$evidence_path" ] || {
            log "ERROR: refusing to clobber pre-mutation evidence: $evidence_path"
            exit 1
        }
    done

    current_platform=$(ssh_run "cat /etc/bos_platform 2>/dev/null || cat /etc/dcentos-platform 2>/dev/null || echo unknown")
    [ "$current_platform" = "$PLATFORM" ] || {
        log "ERROR: platform changed before $phase: '$PLATFORM' -> '$current_platform'"
        exit 1
    }
    require_exact_amlogic_variant "$VARIANT" "$current_platform"
    [ "$EXACT_AMLOGIC_IDENTITY_VARIANT" = "$IDENTITY_PROOF_VARIANT" ] && \
    [ "$EXACT_AMLOGIC_IDENTITY_RECEIPT" = "$IDENTITY_PROOF_RECEIPT" ] || {
        log "ERROR: typed Amlogic identity receipt changed before $phase"
        exit 1
    }
    printf '%s\n' "$EXACT_AMLOGIC_IDENTITY_RECORD" > "$identity_file"
    current_identity_sha=$(local_sha256 "$identity_file")
    [ "$current_identity_sha" = "$IDENTITY_PROOF_SHA" ] || {
        log "ERROR: raw Amlogic identity transcript changed before $phase"
        exit 1
    }

    ssh_stream_get "cat /proc/mtd" "$proc_mtd_file" || {
        rm -f "$proc_mtd_file"
        log "ERROR: could not re-read /proc/mtd before $phase"
        exit 1
    }
    case "$VARIANT" in
        s19kpro|s19k) dcent_am3_require_exact_s19k_mtd_map_file "$proc_mtd_file" || exit 1 ;;
    esac
    cmp -s "$ARTIFACT_DIR/proc_mtd.txt" "$proc_mtd_file" || {
        log "ERROR: /proc/mtd changed before $phase"
        exit 1
    }
    current_proc_mtd_sha=$(local_sha256 "$proc_mtd_file")

    current_name=$(ssh_run "cat /sys/class/mtd/mtd5/name 2>/dev/null || echo unknown" | tr -d ' \t\r\n')
    current_size=$(ssh_run "cat /sys/class/mtd/mtd5/size 2>/dev/null || echo unknown" | tr -d ' \t\r\n')
    current_erasesize=$(ssh_run "cat /sys/class/mtd/mtd5/erasesize 2>/dev/null || echo unknown" | tr -d ' \t\r\n')
    current_bad_blocks=$(ssh_run "cat /sys/class/mtd/mtd5/bad_blocks 2>/dev/null || echo unknown" | tr -d ' \t\r\n')
    [ "$current_name" = "$MTD5_NAME" ] && \
    [ "$current_size" = "$MTD5_SIZE" ] && \
    [ "$current_erasesize" = "$MTD5_ERASESIZE" ] || {
        log "ERROR: mtd5 identity/geometry changed before $phase"
        exit 1
    }
    [ "$MTD5_RESTORE_BAD_BLOCK_POLICY" = zero-only-admitted ] && \
    [ "$current_bad_blocks" = 0 ] || {
        log "ERROR: $phase refuses NAND mutation without stable current zero bad blocks (backup policy=$MTD5_RESTORE_BAD_BLOCK_POLICY current=$current_bad_blocks)"
        exit 1
    }

    [ "$(local_sha256 "$ARTIFACT_DIR/nand_env.bak")" = "$NAND_ENV_LOCAL_SHA" ] && \
    [ "$(local_sha256 "$ARTIFACT_DIR/mtd5_pre_install.bin")" = "$MTD5_LOCAL_SHA" ] && \
    [ "$(local_sha256 "$ARTIFACT_DIR/recovery_flag_eb.bin")" = "$FLAG_EB_SHA" ] || {
        log "ERROR: retained rollback evidence changed before $phase"
        exit 1
    }

    staged_meta=$(ssh_run "
        [ -d '$REMOTE_STAGE_DIR' ] && [ ! -L '$REMOTE_STAGE_DIR' ] &&
        [ -d '$REMOTE_EXTRACT' ] && [ ! -L '$REMOTE_EXTRACT' ] &&
        [ -d '$REMOTE_PREFIX' ] && [ ! -L '$REMOTE_PREFIX' ] &&
        [ -f '$REMOTE_BUNDLE' ] && [ ! -L '$REMOTE_BUNDLE' ] &&
        [ -f '$REMOTE_PREFIX/root' ] && [ ! -L '$REMOTE_PREFIX/root' ] || exit 1
        printf '%s %s %s\n' \"\$(sha256sum '$REMOTE_BUNDLE' | awk '{print \$1}')\" \"\$(stat -c %s '$REMOTE_PREFIX/root')\" \"\$(sha256sum '$REMOTE_PREFIX/root' | awk '{print \$1}')\"
    ") || { log "ERROR: staged transaction is not an exact regular no-symlink tree before $phase"; exit 1; }
    read -r staged_bundle_sha staged_root_size staged_root_sha <<EOF
$staged_meta
EOF
    [ "$staged_bundle_sha" = "$REMOTE_SHA" ] && \
    [ "$staged_root_size" = "$ROOT_SIZE" ] && \
    [ "$staged_root_sha" = "$ROOT_SHA" ] || {
        log "ERROR: content-bound staged bundle/root changed before $phase"
        exit 1
    }

    {
        echo "schema=dcentos.amlogic-pre-mutation-evidence/v1"
        echo "phase=$phase"
        echo "execute=false"
        echo "clear_for_flash=false"
        echo "identity_variant=$IDENTITY_PROOF_VARIANT"
        echo "identity_receipt=$IDENTITY_PROOF_RECEIPT"
        echo "identity_sha256=$current_identity_sha"
        echo "proc_mtd_sha256=$current_proc_mtd_sha"
        echo "mtd5_name=$current_name"
        echo "mtd5_size=$current_size"
        echo "mtd5_erasesize=$current_erasesize"
        echo "mtd5_bad_blocks=$current_bad_blocks"
        echo "bad_block_policy=zero-only-admitted"
        echo "remote_bundle_sha256=$staged_bundle_sha"
        echo "remote_root_size=$staged_root_size"
        echo "remote_root_sha256=$staged_root_sha"
        echo "target_tree=regular-no-symlink"
        echo "power_loss_recovery=live-unproven"
    } > "$receipt_file"
    chmod 0600 "$identity_file" "$proc_mtd_file" "$receipt_file"
    log "  $phase evidence revalidated and retained (writer still CLEAR_FOR_FLASH-refused)"
}
cat > "$ARTIFACT_DIR/install_preflight_manifest.json" <<EOF
{
  "stage": "payload_verified",
  "miner_ip": "$MINER_IP",
  "platform": "$PLATFORM",
  "rootfs_mtd": "$ROOTFS_MTD",
  "rootfs_offset": "$ROOTFS_OFFSET_HEX",
  "rootfs_window": "$ROOTFS_WINDOW_HEX",
  "mtd5_name": "$MTD5_NAME",
  "mtd5_size": $MTD5_SIZE,
  "mtd5_erasesize": $MTD5_ERASESIZE,
  "nand_env_size": $NAND_ENV_SIZE,
  "nand_env_sha256": "$NAND_ENV_LOCAL_SHA",
  "mtd5_backup_size": $MTD5_BACKUP_SIZE,
  "mtd5_backup_sha256": "$MTD5_LOCAL_SHA",
  "firmware_sha256": "$LOCAL_SHA",
  "remote_firmware_sha256": "$REMOTE_SHA",
  "remote_stage_dir": "$REMOTE_STAGE_DIR",
  "package_authority": "release_ed25519_authority_v1",
  "package_installable": true,
  "package_board": "$BOARD_PKG_NAME",
  "package_manifest_verified": true,
  "package_manifest_applied": false,
  "compatibility_projection": "rootfs_only_stock_kernel",
  "kernel_payload_applied": false,
  "root_payload_size": $ROOT_SIZE,
  "root_payload_sha256": "$ROOT_SHA",
  "kernel_payload_size": $KERNEL_SIZE,
  "kernel_payload_sha256": "$KERNEL_SHA",
  "dry_run": $DRY_RUN
}
EOF
log "  recovery manifest updated with payload hashes"

# --- Step 5: dry-run halts here ------------------------------------------
if [ "$DRY_RUN" = true ]; then
    log "[DRY RUN] preflight + backup + SHA256 + manifest + extract OK"
    log "[DRY RUN] mining services were not stopped."
    log "[DRY RUN] would now: GPIO437 SafeOff (SKU-scoped; s19kpro=1), flash_erase $ROOTFS_MTD $ROOTFS_OFFSET_HEX, nandwrite root, readback SHA verify, recovery-flag 0x01 eraseblock_rewrite (InstallArm; firstboot is S99 WAL companion only, not bootcmd), reboot"
    write_install_commit_plan "dry_run=true"
    {
        echo "schema=dcentos.amlogic-install-payload/v1"
        echo "nandwrite_target=root"
        echo "rootfs_local=$DCENT_AM3_ROOTFS_OFFSET_HEX"
        echo "rootfs_window=$DCENT_AM3_ROOTFS_WINDOW_HEX"
        echo "package_manifest_verified=true"
        echo "package_manifest_applied=false"
        echo "compatibility_projection=rootfs_only_stock_kernel"
        echo "kernel_payload_applied=false"
        echo "package_kernel_nandwrite=false"
        echo "nandrecovery_env_local=$COMPUTED_ENV_LOCAL"
        echo "recovery_flag_local=$COMPUTED_FLAG_LOCAL"
        echo "clear_for_flash=false"
        echo "dry_run=true"
    } > "$ARTIFACT_DIR/INSTALL_PAYLOAD_PLAN.txt"
    log "[DRY RUN] wrote $ARTIFACT_DIR/INSTALL_COMMIT_PLAN.txt (refusing firstboot-only)"
    log "[DRY RUN] wrote $ARTIFACT_DIR/INSTALL_PAYLOAD_PLAN.txt (root-window-only; kernel not nandwritten)"
    log "[DRY RUN] no destructive action taken. Exiting."
    exit 0
fi

# : rust admit_s19k_flash is ClearForFlashNotYet. This shell must not
# nandwrite / fw_setenv while that pin is false. --backup-only and --dry-run
# already exited. Do not treat --yes as a flash override.
# The held `a lab unit` unit reports four factory-bad blocks, including two inside the
# modeled root window. The current corpus does not prove that generic mtd-utils
# and this U-Boot consume/skip those blocks identically, so even a future
# clearance bit cannot bypass the independently derived zero-only writer gate.
if [ "$MTD5_RESTORE_BAD_BLOCK_POLICY" != zero-only-admitted ]; then
    log "ERROR: persistent writer requires stable zero bad blocks; current backup policy is $MTD5_RESTORE_BAD_BLOCK_POLICY"
    log "ERROR: no bad-block mapping/replay transform is proven for the S19k root window"
    exit 1
fi
CLEAR_FOR_FLASH=false
if [ "$CLEAR_FOR_FLASH" != true ]; then
    log "ERROR: CLEAR_FOR_FLASH=false - refusing flash_erase/nandwrite/fw_setenv. Backup is staged. FLASH NOT_YET. Use --backup-only."
    log "recover_execute=refused reason=CLEAR_FOR_FLASH pass=admit_s19k_recover_execute_returns_ClearForFlashNotYet"
    log "install_commit=recovery-flag 0x01 eraseblock_rewrite (InstallArm); refusing firstboot-only"
    write_install_commit_plan
    exit 1
fi

# --- Step 6: destructive confirmation gate -------------------------------
if [ "$SKIP_CONFIRM" != true ]; then
    cat >&2 <<EOF

  *** DESTRUCTIVE OPERATION ***
  About to flash DCENT_OS to $MINER_IP ${ROOTFS_MTD} LOCAL offset ${ROOTFS_OFFSET_HEX}.
  Backup of pre-state is in: $ARTIFACT_DIR
  Recovery: flag 0x02 arms recover_to_stock (env restore + erase nvdata), not a direct mtd2 bootm.
  Type YES (uppercase) to proceed:
EOF
    read -r CONFIRM
    [ "$CONFIRM" = "YES" ] || { log "User declined. Exiting."; exit 1; }
fi

# Process signaling is the first state change in the dormant path. Revalidate
# exact identity, storage geometry, rollback artifacts and staged bytes before
# crossing that boundary.
capture_pre_mutation_evidence pre_stop

# --- Step 7: stop bosminer cleanly ---------------------------------------
log "Step 7/10: stop bosminer/boser/bos-tools (after confirmation, graceful TERM, then KILL)"
ssh_run 'for p in bos-tools bosminer boser; do
    pid=$(pidof $p 2>/dev/null || true)
    [ -n "$pid" ] && kill -TERM $pid 2>/dev/null || true
done; sleep 5
for p in bos-tools bosminer boser; do
    pid=$(pidof $p 2>/dev/null || true)
    [ -n "$pid" ] && kill -9 $pid 2>/dev/null || true
done; true'

# The GPIO437 polarity is SKU-specific. Re-prove the same raw transcript after
# stock process teardown and immediately before changing the rail-enable GPIO.
capture_pre_mutation_evidence pre_gpio

# --- Step 7b: GPIO437 SafeOff before any NAND slot/rootfs mutation -------
# SKU-scoped polarity (T6 2026-08-12). Never invent auto-detect.
#   s19kpro / s19k: am3-s19k-active-low - 0=ON, SafeOff=1 (DISABLE).
#                   Driving 0 ENGAGES rails. Default VARIANT is s19kpro.
#   other AML (S21-family / RE-4C): active HIGH - 1=ON, SafeOff=0.
# Identity was proven by require_exact_amlogic_variant; refuse if VARIANT
# polarity would disagree with a proven s21/s19k board_target.
case "$VARIANT" in
    s19kpro|s19k)
        GPIO437_SAFE_OFF=1
        GPIO437_SAFE_DIR=high
        GPIO437_POLARITY=am3-s19k-active-low
        ;;
    *)
        GPIO437_SAFE_OFF=0
        GPIO437_SAFE_DIR=low
        GPIO437_POLARITY=re4c-active-high
        ;;
esac
log "Step 7b/10: GPIO437 PWR_EN SafeOff (variant=$VARIANT polarity=$GPIO437_POLARITY value=$GPIO437_SAFE_OFF) before NAND mutation"
ssh_run "PWR_GPIO=437
SAFE_OFF=$GPIO437_SAFE_OFF
SAFE_DIR=$GPIO437_SAFE_DIR
SYS=/sys/class/gpio
if [ ! -d \"\$SYS/gpio\$PWR_GPIO\" ]; then
  echo \"\$PWR_GPIO\" > \"\$SYS/export\" 2>/dev/null || true
fi
[ -d \"\$SYS/gpio\$PWR_GPIO\" ] || { echo \"ERROR: gpio\$PWR_GPIO missing after export\" >&2; exit 1; }
echo 0 > \"\$SYS/gpio\$PWR_GPIO/active_low\"
echo \"\$SAFE_DIR\" > \"\$SYS/gpio\$PWR_GPIO/direction\"
echo \"\$SAFE_OFF\" > \"\$SYS/gpio\$PWR_GPIO/value\"
AL=\$(cat \"\$SYS/gpio\$PWR_GPIO/active_low\")
DIR=\$(cat \"\$SYS/gpio\$PWR_GPIO/direction\")
VAL=\$(cat \"\$SYS/gpio\$PWR_GPIO/value\")
[ \"\$AL\" = \"0\" ] || { echo \"ERROR: gpio437 active_low=\$AL (want 0)\" >&2; exit 1; }
[ \"\$DIR\" = \"out\" ] || { echo \"ERROR: gpio437 direction=\$DIR (want out)\" >&2; exit 1; }
[ \"\$VAL\" = \"\$SAFE_OFF\" ] || { echo \"ERROR: gpio437 value=\$VAL after SafeOff (want \$SAFE_OFF)\" >&2; exit 1; }
echo \"gpio437 SafeOff OK polarity=$GPIO437_POLARITY active_low=\$AL direction=\$DIR value=\$VAL\"
" \
    || { log "ERROR: GPIO437 SafeOff failed - refusing NAND mutation"; exit 1; }
log "  GPIO437 SafeOff verified (polarity=$GPIO437_POLARITY value=$GPIO437_SAFE_OFF)"

# Revalidate a third time after the GPIO state change. This receipt separates
# process/rail custody from the future NAND transaction and detects target-side
# stage or MTD changes before flash_erase.
capture_pre_mutation_evidence pre_nand

# --- Step 8/9: one target-side root inode, flash_erase + nandwrite --------
log "Step 8-9/10: content-bound root fd + flash_erase + nandwrite (${ROOTFS_ERASE_COUNT} erase blocks of ${ROOTFS_ERASESIZE_EXPECTED} bytes)"
ssh_run "
    [ -d '$REMOTE_STAGE_DIR' ] && [ ! -L '$REMOTE_STAGE_DIR' ] &&
    [ -d '$REMOTE_EXTRACT' ] && [ ! -L '$REMOTE_EXTRACT' ] &&
    [ -d '$REMOTE_PREFIX' ] && [ ! -L '$REMOTE_PREFIX' ] &&
    [ -f '$REMOTE_PREFIX/root' ] && [ ! -L '$REMOTE_PREFIX/root' ] &&
    exec 3< '$REMOTE_PREFIX/root' &&
    [ \"\$(sha256sum /proc/self/fd/3 | awk '{print \$1}')\" = '$ROOT_SHA' ] &&
    [ \"\$(cat /sys/class/mtd/mtd5/name)\" = '$MTD5_NAME' ] &&
    [ \"\$(cat /sys/class/mtd/mtd5/size)\" = '$MTD5_SIZE' ] &&
    [ \"\$(cat /sys/class/mtd/mtd5/erasesize)\" = '$MTD5_ERASESIZE' ] &&
    [ \"\$(cat /sys/class/mtd/mtd5/bad_blocks)\" = '0' ] &&
    [ \"\$(cat /sys/class/gpio/gpio437/active_low)\" = '0' ] &&
    [ \"\$(cat /sys/class/gpio/gpio437/direction)\" = 'out' ] &&
    [ \"\$(cat /sys/class/gpio/gpio437/value)\" = '$GPIO437_SAFE_OFF' ] || exit 1
    flash_erase $ROOTFS_MTD $ROOTFS_OFFSET_HEX $ROOTFS_ERASE_COUNT || exit 1
    nandwrite -p -s $ROOTFS_OFFSET_HEX $ROOTFS_MTD /proc/self/fd/3 || exit 1
    exec 3<&-
" || { log "ERROR: atomic target-side root-fd/geometry/bad-block/SafeOff gate or erase/write failed"; exit 1; }

log "Step 9b/10: readback verify written rootfs SHA256"
if ! ssh_stream_get "nanddump --bb=skipbad -s $ROOTFS_OFFSET_HEX -l $ROOT_SIZE -q $ROOTFS_MTD" \
    "$ARTIFACT_DIR/root_write_readback.uimage"; then
    rm -f "$ARTIFACT_DIR/root_write_readback.uimage"
    log "ERROR: host-streamed rootfs readback failed"
    exit 1
fi
LOCAL_READBACK_SHA=$(local_sha256 "$ARTIFACT_DIR/root_write_readback.uimage")
[ "$LOCAL_READBACK_SHA" = "$ROOT_SHA" ] || {
    log "ERROR: rootfs readback SHA mismatch: expected $ROOT_SHA got host-streamed $LOCAL_READBACK_SHA"
    log "Backup is retained at $ARTIFACT_DIR; firstboot was not set and reboot was not triggered."
    exit 1
}
log "  rootfs readback verified: $LOCAL_READBACK_SHA"

# --- Step 10: install commit is recovery-flag 0x01, not firstboot --------
# .78 bootcmd never reads firstboot. firstboot is S99 WAL companion only.
log "Step 10/10: recovery-flag 0x01 eraseblock_rewrite (InstallArm); refusing firstboot-only"
write_install_commit_plan
log "ERROR: refusing firstboot-only install commit; flag 0x01 rewrite stays operator-authorized"
log "Backup retained at: $ARTIFACT_DIR (INSTALL_COMMIT_PLAN.txt written)"
exit 1
log "If install fails: flag 0x02 arms recover_to_stock (not a direct mtd2 bootm)."
