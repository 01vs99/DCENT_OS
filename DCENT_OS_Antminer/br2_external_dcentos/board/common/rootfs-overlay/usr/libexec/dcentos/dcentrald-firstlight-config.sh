#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Read-only firstlight config binding. S82 retains the existing deploy lock.
# Neither this record nor a phase observation grants SafeOff/restart authority.

DCENT_FIRSTLIGHT_BASE=/data/.dcent-firstlight
DCENT_FIRSTLIGHT_STAGE=$DCENT_FIRSTLIGHT_BASE/current

dcent_firstlight_directory() {
    [ -d "$1" ] && [ ! -L "$1" ] \
        && [ "$(stat -c '%u:%g:%a' "$1" 2>/dev/null)" = 0:0:700 ]
}

dcent_firstlight_identity() {
    firstlight_file=$1
    firstlight_kind=$2
    [ -f "$firstlight_file" ] && [ ! -L "$firstlight_file" ] || return 1
    firstlight_before=$(stat -c '%d:%i:%u:%g:%a:%h:%s:%Y' "$firstlight_file") || return 1
    firstlight_owner=$(stat -c '%u:%g:%a:%h:%s' "$firstlight_file") || return 1
    old_ifs=$IFS
    IFS=:
    set -- $firstlight_owner
    IFS=$old_ifs
    [ "$#" -eq 5 ] && [ "$1:$2" = 0:0 ] || return 1
    case "$firstlight_kind" in
        phase) [ "$3:$4" = 600:1 ] && [ "$5" -gt 0 ] && [ "$5" -le 1048576 ] || return 1 ;;
        record) [ "$3:$4" = 600:1 ] && [ "$5" -gt 0 ] && [ "$5" -le 4096 ] || return 1 ;;
        original)
            case "$3" in 400|600|444|644) ;; *) return 1 ;; esac
            [ "$4" -eq 1 ] && [ "$5" -gt 0 ] && [ "$5" -le 1048576 ] || return 1 ;;
        daemon)
            case "$3" in 555|755) ;; *) return 1 ;; esac
            [ "$4" -ge 1 ] && [ "$4" -le 2 ] && [ "$5" -gt 0 ] && [ "$5" -le 50331648 ] || return 1 ;;
        *) return 1 ;;
    esac
    firstlight_hash=$(sha256sum "$firstlight_file") || return 1
    firstlight_hash=${firstlight_hash%% *}
    [ "${#firstlight_hash}" -eq 64 ] || return 1
    case "$firstlight_hash" in *[!0-9a-f]*) return 1 ;; esac
    [ "$(stat -c '%d:%i:%u:%g:%a:%h:%s:%Y' "$firstlight_file")" = "$firstlight_before" ] || return 1
    printf '%s:%s\n' "$firstlight_before" "$firstlight_hash"
}

dcent_firstlight_field() {
    awk -F= -v name="$1" '$1 == name { print $2 }' "$DCENT_FIRSTLIGHT_STAGE/session"
}

dcent_firstlight_check_identity_record() {
    [ "${#1}" -eq 32 ] || return 1
    case "$1" in *[!0-9a-f]*) return 1 ;; esac
    [ ! -L /data ] && dcent_firstlight_directory "$DCENT_FIRSTLIGHT_BASE" \
        && dcent_firstlight_directory "$DCENT_FIRSTLIGHT_STAGE" || return 1
    # A shell loader never evaluates fields as commands or accepts extra keys.
    awk -F= '
        NF != 2 || seen[$1]++ { exit 1 }
        $1 !~ /^(schema|token|board|boot|daemon_path|daemon|original_path|original|census|work)$/ { exit 1 }
        END { if (NR != 10) exit 1 }
    ' "$DCENT_FIRSTLIGHT_STAGE/session" || return 1
    [ "$(dcent_firstlight_field schema)" = dcentos.firstlight-config.v1 ] \
        && [ "$(dcent_firstlight_field token)" = "$1" ] \
        && [ "$(dcent_firstlight_field board)" = "$(cat /etc/dcentos/board_target)" ] \
        && [ "$(dcent_firstlight_field boot)" = "$(cat /proc/sys/kernel/random/boot_id)" ] || return 1
    case "$(dcent_firstlight_field board)" in
        am1-s9|am1-s9i|am1-s9j|am2-s17p|am2-s17plus|am2-t17|am2-t17plus|am2-s19j) ;;
        *) return 1 ;;
    esac
}

dcent_firstlight_check_record() {
    dcent_firstlight_check_identity_record "$1" || return 1
    for firstlight_phase in census work; do
        firstlight_observed_phase=$(dcent_firstlight_identity "$DCENT_FIRSTLIGHT_STAGE/$firstlight_phase.toml" phase) || return 1
        [ "$firstlight_observed_phase" = "$(dcent_firstlight_field "$firstlight_phase")" ] || return 1
    done
}

dcent_firstlight_check_original() {
    firstlight_daemon=$(dcent_firstlight_field daemon_path)
    firstlight_original=$(dcent_firstlight_field original_path)
    case "$firstlight_daemon" in /usr/local/bin/dcentrald|/data/dcentrald) ;; *) return 1 ;; esac
    case "$firstlight_original" in /etc/dcentrald.toml|/data/dcentrald.toml) ;; *) return 1 ;; esac
    firstlight_observed_daemon=$(dcent_firstlight_identity "$firstlight_daemon" daemon) || return 1
    firstlight_observed_original=$(dcent_firstlight_identity "$firstlight_original" original) || return 1
    [ "$firstlight_observed_daemon" = "$(dcent_firstlight_field daemon)" ] \
        && [ "$firstlight_observed_original" = "$(dcent_firstlight_field original)" ]
}

dcent_firstlight_capture_config() {
    # Called after ordinary generation/selection checks and before session
    # prepare; retain exact original and phase identities until actual exec.
    DCENT_FIRSTLIGHT_TOKEN=$1
    DCENT_FIRSTLIGHT_PHASE=$2
    case "$2" in census|work) ;; *) return 1 ;; esac
    DCENT_FIRSTLIGHT_RECORD=$(dcent_firstlight_identity "$DCENT_FIRSTLIGHT_STAGE/session" record) || return 1
    dcent_firstlight_check_record "$1" && dcent_firstlight_check_original || return 1
    [ "$3" = "$(dcent_firstlight_field daemon_path)" ] \
        && [ "$4" = "$(dcent_firstlight_field original_path)" ] || return 1
    DCENT_FIRSTLIGHT_CONFIG=$DCENT_FIRSTLIGHT_STAGE/$2.toml
    DCENT_FIRSTLIGHT_CONFIG_ID=$(dcent_firstlight_identity "$DCENT_FIRSTLIGHT_CONFIG" phase) || return 1
    [ "$DCENT_FIRSTLIGHT_CONFIG_ID" = "$(dcent_firstlight_field "$2")" ] || return 1
    [ "$DCENT_FIRSTLIGHT_RECORD" = "$(dcent_firstlight_identity "$DCENT_FIRSTLIGHT_STAGE/session" record)" ]
}

dcent_firstlight_verify_config() {
    [ -n "$DCENT_FIRSTLIGHT_RECORD" ] \
        && [ "$DCENT_FIRSTLIGHT_RECORD" = "$(dcent_firstlight_identity "$DCENT_FIRSTLIGHT_STAGE/session" record)" ] \
        && dcent_firstlight_check_record "$DCENT_FIRSTLIGHT_TOKEN" \
        && dcent_firstlight_check_original \
        && [ "$1" = "$(dcent_firstlight_field daemon_path)" ] \
        && [ "$2" = "$(dcent_firstlight_field original_path)" ] \
        && [ "$DCENT_FIRSTLIGHT_CONFIG_ID" = "$(dcent_firstlight_identity "$DCENT_FIRSTLIGHT_CONFIG" phase)" ] \
        && [ "$DCENT_FIRSTLIGHT_RECORD" = "$(dcent_firstlight_identity "$DCENT_FIRSTLIGHT_STAGE/session" record)" ]
}
