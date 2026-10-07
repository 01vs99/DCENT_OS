#!/bin/sh
# Fail-closed capability reader for root-owned DCENTos mutation policy files.

dcent_mutation_policy_has() {
    policy_file=$1
    capability=$2
    case "$capability" in boot-safeoff|daemon-hardware|ota-storage) ;; *) return 1 ;; esac
    [ -f "$policy_file" ] && [ ! -L "$policy_file" ] && [ -r "$policy_file" ] || return 1

    policy_uid=$(stat -c '%u' "$policy_file" 2>/dev/null) || return 1
    [ "$policy_uid" = 0 ] || return 1
    policy_mode=$(stat -c '%a' "$policy_file" 2>/dev/null) || return 1
    case "$policy_mode" in
        400|440|444|600|640|644) ;;
        *) return 1 ;;
    esac

    # Legacy hardware-enabled was a wildcard, including storage permission.
    # Generated policies list independent exact capabilities; no wildcard or
    # malformed mixed policy may authorize a lifecycle operation.
    [ "$(stat -c '%h' "$policy_file" 2>/dev/null)" = 1 ] || return 1
    [ "$(stat -c '%s' "$policy_file" 2>/dev/null)" -le 128 ] || return 1
    awk '
        $0 == "boot-safeoff" || $0 == "daemon-hardware" || $0 == "ota-storage" { if (seen[$0]++) exit 1; next }
        { exit 1 }
    ' "$policy_file" || return 1
    grep -F -x "$capability" "$policy_file" >/dev/null 2>&1
}
