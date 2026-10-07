#!/bin/sh
# Persistent pre-launch disposition latch for the dcentrald hardware session.
#
# The supervisor records an unresolved session before dcentrald can touch
# hardware.  No process exit status is accepted as a physical SafeOff receipt.
# A checked orderly software closeout can retire its exact supervised session.
# Crash, forced stop, missing proof and unresolved mutation remain latched.

PATH=/usr/bin:/bin:/usr/sbin:/sbin

PERSISTENCE_PATH=/data
STATE_DIR=/data/dcent
UNRESOLVED_FILE=$STATE_DIR/dcentrald-hardware-session.unresolved
CRASH_LATCH_FILE=$STATE_DIR/dcentrald-hardware-session.crash-latched
LOCK_DIR=$STATE_DIR/.dcentrald-session-latch.lock
MOUNTS_FILE=/proc/mounts
MOUNTINFO_FILE=/proc/self/mountinfo
UBI_SYSFS_ROOT=/sys/class/ubi
UPDATE_LOCK_DIR=/run/dcentos-sysupgrade.lock
PARENT_DEATH_HELPER=/usr/libexec/dcentos/dcentos-deploy-lock
CLOSEOUT_VALIDATOR=/usr/local/bin/dcentrald
CENSUS_EXPECTED_EXIT=0

log() {
    printf 'dcentrald-session-latch: %s\n' "$*" >&2
}

path_exists() {
    [ -e "$1" ] || [ -L "$1" ]
}

sync_state() {
    if ! sync; then
        log 'persistent state sync failed'
        return 1
    fi
}

backing_store_is_persistent() {
    [ -r "$MOUNTS_FILE" ] || {
        log "cannot inspect mount table $MOUNTS_FILE"
        return 1
    }

    BACKING=$(awk -v path="$PERSISTENCE_PATH" '
        function covers(mountpoint) {
            if (mountpoint == "/")
                return 1
            return path == mountpoint || index(path, mountpoint "/") == 1
        }
        covers($2) && length($2) > best {
            best = length($2)
            fstype = $3
            options = $4
        }
        END {
            if (best == 0)
                exit 1
            print fstype " " options
        }
    ' "$MOUNTS_FILE") || {
        log "$PERSISTENCE_PATH has no identifiable backing mount"
        return 1
    }

    BACKING_FSTYPE=${BACKING%% *}
    BACKING_OPTIONS=${BACKING#* }
    case ",$BACKING_OPTIONS," in
        *,rw,*) ;;
        *)
            log "$PERSISTENCE_PATH backing store is not writable ($BACKING_FSTYPE $BACKING_OPTIONS)"
            return 1
            ;;
    esac

    # This is intentionally an allowlist.  Unknown, overlay, and memory-backed
    # filesystems cannot prove that a marker will survive a watchdog reboot.
    case "$BACKING_FSTYPE" in
        ubifs|jffs2|ext2|ext3|ext4|f2fs|btrfs|xfs) return 0 ;;
        *)
            log "$PERSISTENCE_PATH backing filesystem is not proven persistent ($BACKING_FSTYPE)"
            return 1
            ;;
    esac
}

prepare_state_dir() {
    backing_store_is_persistent || return 1
    if [ -L "$STATE_DIR" ]; then
        log "$STATE_DIR must not be a symbolic link"
        return 1
    fi
    mkdir -p "$STATE_DIR" || {
        log "cannot create $STATE_DIR"
        return 1
    }
    [ -d "$STATE_DIR" ] || {
        log "$STATE_DIR is not a directory"
        return 1
    }
    chown 0:0 "$STATE_DIR" || {
        log "cannot assign root ownership to $STATE_DIR"
        return 1
    }
    chmod 0700 "$STATE_DIR" || {
        log "cannot protect $STATE_DIR"
        return 1
    }
}

acquire_lock() {
    LOCK_TOKEN=$1
    if ! mkdir "$LOCK_DIR" 2>/dev/null; then
        log "persistent session lock is already held or stale ($LOCK_DIR)"
        return 1
    fi
    umask 077
    printf '%s\n' "$LOCK_TOKEN" > "$LOCK_DIR/admission-token" 2>/dev/null || {
        rmdir "$LOCK_DIR" 2>/dev/null || true
        log 'cannot record session-lock admission token'
        return 1
    }
    sync_state || return 1
}

release_lock() {
    rm -f "$LOCK_DIR/admission-token" 2>/dev/null || return 1
    rmdir "$LOCK_DIR" 2>/dev/null || return 1
    sync_state
}

lock_matches() {
    EXPECTED_TOKEN=$1
    ACTUAL_TOKEN=$(cat "$LOCK_DIR/admission-token" 2>/dev/null || true)
    [ -n "$EXPECTED_TOKEN" ] && [ "$ACTUAL_TOKEN" = "$EXPECTED_TOKEN" ]
}

update_transaction_is_absent() {
    if path_exists "$UPDATE_LOCK_DIR"; then
        log "hardware-session admission blocked by active update transaction $UPDATE_LOCK_DIR"
        return 1
    fi
    return 0
}

update_source_is_exact_active_rootfs_data() {
    CURRENT_MTD=$1
    case "$CURRENT_MTD" in
        ''|*[!0-9]*)
            log "update admission has invalid current MTD: ${CURRENT_MTD:-missing}"
            return 1
            ;;
    esac
    [ -r "$MOUNTS_FILE" ] && [ -r "$MOUNTINFO_FILE" ] || {
        log 'update admission cannot inspect active mount identity'
        return 1
    }
    awk -v path="$PERSISTENCE_PATH" '
        $1 == "ubi0:rootfs_data" && $2 == path && $3 == "ubifs" {
            writable = 0
            count = split($4, options, ",")
            for (i = 1; i <= count; i++)
                if (options[i] == "rw") writable = 1
            if (writable) matches++
        }
        END { exit matches == 1 ? 0 : 1 }
    ' "$MOUNTS_FILE" || {
        log "$PERSISTENCE_PATH is not the single writable ubi0:rootfs_data UBIFS mount"
        return 1
    }
    awk -v path="$PERSISTENCE_PATH" '
        {
            separator = 0
            for (i = 7; i <= NF; i++)
                if ($i == "-") { separator = i; break }
            if (separator == 0 || $4 != "/" || $5 != path ||
                $(separator + 1) != "ubifs" ||
                $(separator + 2) != "ubi0:rootfs_data") next
            writable = 0
            count = split($6, options, ",")
            for (i = 1; i <= count; i++)
                if (options[i] == "rw") writable = 1
            if (writable) matches++
        }
        END { exit matches == 1 ? 0 : 1 }
    ' "$MOUNTINFO_FILE" || {
        log "$PERSISTENCE_PATH is not the root of the active rootfs_data mount"
        return 1
    }
    UBI_ACTIVE_MTD=$(cat "$UBI_SYSFS_ROOT/ubi0/mtd_num" 2>/dev/null) || {
        log 'update admission cannot read ubi0 backing-MTD identity'
        return 1
    }
    [ "$UBI_ACTIVE_MTD" = "$CURRENT_MTD" ] || {
        log "ubi0 maps to mtd$UBI_ACTIVE_MTD, not booted mtd$CURRENT_MTD"
        return 1
    }
    return 0
}

# Serialize a sysupgrade admission check against the same persistent lock used
# by daemon launch. The caller must already own its /run transaction lock. Once
# this function releases the persistent lock, prepare_session() continues to
# refuse on the /run lock until reboot or a pre-commit cleanup.
admit_update_window() {
    PERSISTENCE_PATH=$1
    UPDATE_LOCK_DIR=$2
    CURRENT_MTD=$3
    STATE_DIR=$PERSISTENCE_PATH/dcent
    UNRESOLVED_FILE=$STATE_DIR/dcentrald-hardware-session.unresolved
    CRASH_LATCH_FILE=$STATE_DIR/dcentrald-hardware-session.crash-latched
    LOCK_DIR=$STATE_DIR/.dcentrald-session-latch.lock

    [ -n "$PERSISTENCE_PATH" ] && [ -n "$UPDATE_LOCK_DIR" ] && \
        [ -n "$CURRENT_MTD" ] || {
        log 'update admission requires persistence, transaction-lock, and current-MTD identity'
        return 1
    }
    path_exists "$UPDATE_LOCK_DIR" || {
        log "update admission requires an owned transaction lock at $UPDATE_LOCK_DIR"
        return 1
    }
    [ -d "$UPDATE_LOCK_DIR" ] && [ ! -L "$UPDATE_LOCK_DIR" ] || {
        log "update transaction lock is not a non-symlink directory: $UPDATE_LOCK_DIR"
        return 1
    }

    prepare_state_dir || return 1
    update_source_is_exact_active_rootfs_data "$CURRENT_MTD" || return 1
    UPDATE_ADMISSION_TOKEN=update.$$
    acquire_lock "$UPDATE_ADMISSION_TOKEN" || return 1
    UPDATE_ADMISSION_RESULT=0

    if ! path_exists "$UPDATE_LOCK_DIR" || [ ! -d "$UPDATE_LOCK_DIR" ] || \
       [ -L "$UPDATE_LOCK_DIR" ]; then
        log 'update transaction ownership disappeared during session admission'
        UPDATE_ADMISSION_RESULT=1
    elif path_exists "$CRASH_LATCH_FILE"; then
        # Operator 2026-08-19: expected-zero + successful software SafeOff
        # may sysupgrade. S82 start still refuses. This is not VerifiedRailCut.
        LATCH_STATE=$(awk -F= '/^state=/{print $2; exit}' "$CRASH_LATCH_FILE" 2>/dev/null || true)
        case "$LATCH_STATE" in
            *safeoff-failed*)
                log "update blocked by failed software SafeOff $CRASH_LATCH_FILE"
                UPDATE_ADMISSION_RESULT=1
                ;;
            *expected-zero-awaiting-typed-disposition*)
                log "update admitted after expected-zero software SafeOff; rails not proven"
                ;;
            *)
                log "update blocked by unresolved hardware disposition $CRASH_LATCH_FILE"
                UPDATE_ADMISSION_RESULT=1
                ;;
        esac
    elif path_exists "$UNRESOLVED_FILE"; then
        log "update blocked by active or unresolved hardware session $UNRESOLVED_FILE"
        UPDATE_ADMISSION_RESULT=1
    fi

    release_lock || UPDATE_ADMISSION_RESULT=1
    if [ "$UPDATE_ADMISSION_RESULT" -ne 0 ]; then
        return 1
    fi
    log 'update window admitted under hardware-session exclusion'
    return 0
}

write_marker() {
    MARKER=$1
    STATE=$2
    TMP_FILE=$MARKER.tmp.$$
    BOOT_ID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || printf unknown)
    IMAGE_VERSION=$(cat /etc/dcentos-version 2>/dev/null || printf unknown)
    # POSIX sh variables are global unless the shell provides a non-portable
    # `local`.  Do not overwrite a caller's PLATFORM identity: the safety
    # script invoked later in the same helper process consumes that value.
    MARKER_PLATFORM=$(cat /etc/dcentos-platform 2>/dev/null || printf unknown)

    umask 077
    if path_exists "$TMP_FILE"; then
        log "refusing pre-existing temporary marker $TMP_FILE"
        return 1
    fi
    if ! {
        printf 'schema=1\n'
        printf 'state=%s\n' "$STATE"
        printf 'boot_id=%s\n' "$BOOT_ID"
        printf 'image_version=%s\n' "$IMAGE_VERSION"
        printf 'platform=%s\n' "$MARKER_PLATFORM"
        printf 'writer_pid=%s\n' "$$"
        printf 'session_token=%s\n' "$ADMISSION_TOKEN"
        printf 'recorded_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf unknown)"
    } > "$TMP_FILE"; then
        rm -f "$TMP_FILE"
        log "cannot write temporary marker $TMP_FILE"
        return 1
    fi
    chmod 0600 "$TMP_FILE" || {
        rm -f "$TMP_FILE"
        log "cannot protect temporary marker $TMP_FILE"
        return 1
    }
    sync_state || {
        rm -f "$TMP_FILE"
        return 1
    }
    mv -f "$TMP_FILE" "$MARKER" || {
        rm -f "$TMP_FILE"
        log "cannot publish marker $MARKER"
        return 1
    }
    sync_state
}

promote_unresolved_locked() {
    REASON=${1:-abnormal-exit}
    if path_exists "$CRASH_LATCH_FILE"; then
        sync_state
        return $?
    fi
    if path_exists "$UNRESOLVED_FILE"; then
        write_marker "$CRASH_LATCH_FILE" "crash-latched:$REASON" || {
            log 'could not publish crash latch; unresolved state still blocks admission'
            return 1
        }
        rm -f "$UNRESOLVED_FILE" || {
            log 'crash latch is durable but unresolved marker cleanup failed'
            return 1
        }
        sync_state || return 1
        log "hardware session latched ($REASON)"
        return 0
    fi

    if write_marker "$CRASH_LATCH_FILE" "crash-latched:$REASON"; then
        log "hardware session latched without a prior marker ($REASON)"
        return 0
    fi
    return 1
}

promote_unresolved() {
    REASON=${1:-abnormal-exit}
    prepare_state_dir || return 1
    MUTATION_TOKEN=mutation.$$
    acquire_lock "$MUTATION_TOKEN" || return 1
    promote_unresolved_locked "$REASON"
    RESULT=$?
    release_lock || RESULT=1
    return "$RESULT"
}

# Only the fixed daemon validator can consume the protected, exact-run software
# receipt. Exit status and emergency command success alone never authorize this.
normalize_expected_stop_reason() {
    case "$EXPECTED_STOP_REASON" in
        '')
            # Existing shipped stop writers record only the verified child
            # PID. Missing/foreign PID still fails the exact consumer guard.
            [ -z "$EXPECTED_PID" ] || EXPECTED_STOP_REASON=requested-stop
            ;;
        requested-stop|forced-stop-timeout) ;;
        *) EXPECTED_STOP_REASON=invalid-stop-reason ;;
    esac
}

clear_orderly_software_session() {
    [ "$EXIT_CODE" -eq 0 ] && [ "$EXPECTED_PID" = "$CHILD_PID" ] \
        && [ "$EXPECTED_STOP_REASON" = requested-stop ] && [ "$SAFETY_OK" -eq 1 ] \
        || return 1
    acquire_lock "$ADMISSION_TOKEN" || return 1
    CLEAR_RESULT=1
    if path_exists "$UNRESOLVED_FILE" && ! path_exists "$CRASH_LATCH_FILE" \
        && "$CLOSEOUT_VALIDATOR" --check-software-closeout \
            "$CHILD_PID" "$CHILD_START_TICKS" "$CHILD_BOOT_ID" "$ADMISSION_TOKEN"; then
        # The Rust consumer has checked the still-current session token and
        # absent mutation journal while this supervisor owns the session lock.
        # Remove only this unresolved-session marker, never a mutation journal.
        if rm -f "$UNRESOLVED_FILE" && sync_state; then
            CLEAR_RESULT=0
            log 'exact-session orderly software closeout admitted restart; physical rail state remains unmeasured'
        fi
    fi
    release_lock || CLEAR_RESULT=1
    return "$CLEAR_RESULT"
}

terminate_unpublished_child() {
    CHILD_PID=$1
    kill -TERM "$CHILD_PID" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
        CHILD_STATE=$(awk '{print $3}' "/proc/$CHILD_PID/stat" 2>/dev/null || true)
        if [ "$CHILD_STATE" = Z ] || ! kill -0 "$CHILD_PID" 2>/dev/null; then
            wait "$CHILD_PID" 2>/dev/null || true
            return 0
        fi
        sleep 1
    done
    kill -KILL "$CHILD_PID" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
        CHILD_STATE=$(awk '{print $3}' "/proc/$CHILD_PID/stat" 2>/dev/null || true)
        if [ "$CHILD_STATE" = Z ] || ! kill -0 "$CHILD_PID" 2>/dev/null; then
            wait "$CHILD_PID" 2>/dev/null || true
            return 0
        fi
        sleep 1
    done
    return 1
}

contain_unpublished_child_failure() {
    FAILED_CHILD_PID=$1
    FAILED_SAFETY_SCRIPT=$2
    FAILED_REASON=$3

    if ! terminate_unpublished_child "$FAILED_CHILD_PID"; then
        FAILED_REASON=${FAILED_REASON}-owner-death-unverified
        promote_unresolved_locked "$FAILED_REASON" >/dev/null 2>&1 || true
        release_lock || true
        log "daemon PID $FAILED_CHILD_PID remains live; competing safe-off mutation suppressed"
        return 1
    fi

    if "$FAILED_SAFETY_SCRIPT" safety >> "$LOGFILE" 2>&1; then
        log 'unpublished owner terminated; emergency command/readback evidence recorded' \
            >> "$LOGFILE"
    else
        FAILED_REASON=${FAILED_REASON}-safeoff-failed
        log 'unpublished owner terminated but emergency safe-off failed' >> "$LOGFILE"
    fi
    promote_unresolved_locked "$FAILED_REASON" >/dev/null 2>&1 || true
    release_lock || true
    return 1
}

prepare_session() {
    update_transaction_is_absent || return 1
    prepare_state_dir || return 1
    BOOT_ID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || printf unknown)
    ADMISSION_TOKEN=$BOOT_ID.$$
    acquire_lock "$ADMISSION_TOKEN" || return 1

    if ! update_transaction_is_absent; then
        release_lock || true
        return 1
    fi

    if path_exists "$CRASH_LATCH_FILE"; then
        log "start blocked by $CRASH_LATCH_FILE"
        release_lock || true
        return 1
    fi
    if path_exists "$UNRESOLVED_FILE"; then
        promote_unresolved_locked previous-session-unresolved >/dev/null 2>&1 || true
        log 'start blocked: a previous hardware session has no clean disposition'
        release_lock || true
        return 1
    fi

    if write_marker "$UNRESOLVED_FILE" unresolved; then
        log 'persistent unresolved-session marker synchronized before launch'
        printf '%s\n' "$ADMISSION_TOKEN"
        return 0
    fi
    release_lock || true
    return 1
}

supervise_session() {
    ADMISSION_TOKEN=$1
    SAFETY_SCRIPT=$2
    LOGFILE=$3
    CHILD_PIDFILE=$4
    EXPECTFILE=$5
    shift 5
    if [ "$CENSUS_EXPECTED_EXIT" -ne 0 ]; then
        # The work timer is inside the daemon, before energizing. This shell
        # expectation still requires the real exact-session closeout consumer.
        if [ "$CENSUS_EXPECTED_EXIT" -eq 1 ]; then
            [ "$#" -eq 5 ] && [ "$4" = --firstlight-census ] || return 1
        else
            [ "$#" -eq 7 ] && [ "$4" = --firstlight-work ] \
                && [ "$6" = --firstlight-seconds ] || return 1
            case "$7" in ''|*[!0-9]*|0*) return 1 ;; esac
            [ "$7" -ge 1 ] && [ "$7" -le 300 ] || return 1
        fi
        [ "$2" = --config ] && [ "${#5}" -eq 32 ] || return 1
        case "$1:$3:$5" in
            /usr/local/bin/dcentrald:/*:*|/data/dcentrald:/*:*) ;;
            *) return 1 ;;
        esac
        case "$5" in *[!0-9a-f]*) return 1 ;; esac
    fi
    DEPLOY_LOCK_READY_FD=${DCENTOS_DEPLOY_LOCK_READY_FD:-}
    DEPLOY_LOCK_FD=${DCENTOS_DEPLOY_LOCK_FD:-}
    SUPERVISOR_PID=$$
    case "$DEPLOY_LOCK_READY_FD" in
        ''|*[!0-9]*) DEPLOY_LOCK_READY_FD= ;;
    esac
    case "$DEPLOY_LOCK_FD" in
        ''|*[!0-9]*) DEPLOY_LOCK_FD= ;;
    esac

    if ! lock_matches "$ADMISSION_TOKEN"; then
        log 'refusing daemon launch without ownership of the persistent admission lock'
        return 1
    fi
    if ! path_exists "$UNRESOLVED_FILE" || path_exists "$CRASH_LATCH_FILE"; then
        log 'refusing daemon launch without exactly one unresolved-session marker'
        release_lock || true
        return 1
    fi
    if [ "$#" -eq 0 ]; then
        promote_unresolved_locked missing-daemon-command >/dev/null 2>&1 || true
        release_lock || true
        log 'refusing empty daemon command'
        return 1
    fi
    if [ -n "$PARENT_DEATH_HELPER" ] && [ ! -x "$PARENT_DEATH_HELPER" ]; then
        promote_unresolved_locked parent-death-helper-missing >/dev/null 2>&1 || true
        release_lock || true
        log 'refusing daemon launch without the compiled parent-death boundary'
        return 1
    fi
    SESSION_WRAPPER_PIDFILE=${DCENTOS_SESSION_WRAPPER_PIDFILE:-}
    if [ -n "$SESSION_WRAPPER_PIDFILE" ]; then
        case "$SESSION_WRAPPER_PIDFILE" in
            /*) ;;
            *)
                promote_unresolved_locked wrapper-pidfile-invalid >/dev/null 2>&1 || true
                release_lock || true
                return 1
                ;;
        esac
        SESSION_WRAPPER_PIDFILE_TMP="$SESSION_WRAPPER_PIDFILE.$$"
        rm -f "$SESSION_WRAPPER_PIDFILE_TMP" || return 1
        [ ! -e "$SESSION_WRAPPER_PIDFILE" ] \
            && [ ! -L "$SESSION_WRAPPER_PIDFILE" ] || return 1
        umask 077
        printf '%s\n' "$$" >"$SESSION_WRAPPER_PIDFILE_TMP" || return 1
        chmod 600 "$SESSION_WRAPPER_PIDFILE_TMP" || return 1
        mv "$SESSION_WRAPPER_PIDFILE_TMP" "$SESSION_WRAPPER_PIDFILE" || return 1
        unset DCENTOS_SESSION_WRAPPER_PIDFILE
    fi

    if [ -n "$DEPLOY_LOCK_READY_FD" ]; then
        (
            eval "exec ${DEPLOY_LOCK_READY_FD}>&-"
            [ -z "$DEPLOY_LOCK_FD" ] || eval "exec ${DEPLOY_LOCK_FD}>&-"
            unset DCENTOS_DEPLOY_LOCK_READY_FD DCENTOS_DEPLOY_LOCK_FD
            if [ -n "$PARENT_DEATH_HELPER" ]; then
                exec "$PARENT_DEATH_HELPER" --parent-death-signal \
                    "$SUPERVISOR_PID" -- "$@"
            fi
            exec "$@"
        ) >> "$LOGFILE" 2>&1 &
    elif [ -n "$PARENT_DEATH_HELPER" ]; then
        "$PARENT_DEATH_HELPER" --parent-death-signal \
            "$SUPERVISOR_PID" -- "$@" \
            >> "$LOGFILE" 2>&1 &
    else
        "$@" >> "$LOGFILE" 2>&1 &
    fi
    CHILD_PID=$!
    CHILD_START_TICKS=$(awk '{print $22}' "/proc/$CHILD_PID/stat" 2>/dev/null) || {
        contain_unpublished_child_failure "$CHILD_PID" "$SAFETY_SCRIPT" \
            child-identity-unavailable || true
        log 'daemon launched but /proc start-time identity is unavailable'
        return 1
    }
    CHILD_BOOT_ID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) || {
        contain_unpublished_child_failure "$CHILD_PID" "$SAFETY_SCRIPT" \
            child-boot-identity-unavailable || true
        log 'daemon launched but kernel boot identity is unavailable'
        return 1
    }
    case "$ADMISSION_TOKEN:$CHILD_BOOT_ID" in
        *[!A-Za-z0-9._:-]*|:*|*:)
            contain_unpublished_child_failure "$CHILD_PID" "$SAFETY_SCRIPT" \
                child-session-identity-invalid || true
            log 'daemon launched but session/boot identity is invalid'
            return 1
            ;;
    esac
    umask 077
    printf '%s %s %s %s\n' "$CHILD_PID" "$CHILD_START_TICKS" \
        "$ADMISSION_TOKEN" "$CHILD_BOOT_ID" > "$CHILD_PIDFILE" || {
        contain_unpublished_child_failure "$CHILD_PID" "$SAFETY_SCRIPT" \
            child-identity-publication-failed || true
        log 'daemon launched but child identity publication failed'
        return 1
    }
    # The daemon child closed the admission descriptors before exec. Its
    # compiled launch boundary also armed PR_SET_PDEATHSIG(SIGKILL), so loss of
    # this supervisor cannot leave a stalled hardware owner alive. The already-
    # durable unresolved marker keeps every later admission fail-closed; normal
    # supervised stops still use dcentrald's graceful safe-off path.
    if ! release_lock; then
        log 'daemon launched but admission lock release failed; future admission remains blocked'
    fi
    wait "$CHILD_PID"
    EXIT_CODE=$?
    EXPECTED_RECORD=$(cat "$EXPECTFILE" 2>/dev/null || true)
    EXPECTED_PID=$(printf '%s\n' "$EXPECTED_RECORD" | awk 'NR == 1 {print $1}')
    EXPECTED_STOP_REASON=$(printf '%s\n' "$EXPECTED_RECORD" | awk 'NR == 1 {print $2}')
    if [ "$CENSUS_EXPECTED_EXIT" -ne 0 ] && [ -z "$EXPECTED_RECORD" ]; then
        # The supervisor captured PID/start/boot from its actual child and
        # waited for that exact process. No host-written PID marker races exit.
        EXPECTED_PID=$CHILD_PID
        EXPECTED_STOP_REASON=requested-stop
    fi
    normalize_expected_stop_reason

    if [ "$EXPECTED_PID" = "$CHILD_PID" ] \
        && [ "$EXPECTED_STOP_REASON" = forced-stop-timeout ]; then
        REASON=forced-stop-timeout-exit-$EXIT_CODE
        log "forced-stop timeout for PID $CHILD_PID ended with status $EXIT_CODE; hardware disposition is unresolved" >> "$LOGFILE"
    elif [ "$EXPECTED_PID" = "$CHILD_PID" ] && [ "$EXIT_CODE" -eq 0 ]; then
        REASON=expected-zero-awaiting-typed-disposition
        log "expected zero-status exit for PID $CHILD_PID remains unresolved" >> "$LOGFILE"
    elif [ "$EXPECTED_PID" = "$CHILD_PID" ]; then
        REASON=expected-nonzero-exit-$EXIT_CODE
        log "expected PID $CHILD_PID exited nonzero ($EXIT_CODE); hardware disposition is unresolved" >> "$LOGFILE"
    elif [ "$EXIT_CODE" -eq 0 ]; then
        REASON=unmarked-zero-exit
        log "unmarked zero-status exit for PID $CHILD_PID is ambiguous" >> "$LOGFILE"
    else
        REASON=unexpected-exit-$EXIT_CODE
        log "unexpected exit for PID $CHILD_PID (code $EXIT_CODE)" >> "$LOGFILE"
    fi

    rm -f "$EXPECTFILE"

    # The unresolved marker was durably published before the daemon launched.
    # After wait(2) observes owner death, execute the platform's monotonic
    # emergency cut before any additional filesystem sync or crash-journal
    # promotion can delay it.  This safety result never clears admission.
    SAFETY_OK=1
    if "$SAFETY_SCRIPT" safety >> "$LOGFILE" 2>&1; then
        log 'post-exit emergency safety action returned command/readback evidence; physical disposition remains separately classified' >> "$LOGFILE"
    else
        SAFETY_OK=0
        REASON=${REASON}-safeoff-failed
        log 'post-exit emergency safety action failed; power disposition remains unknown' >> "$LOGFILE"
    fi

    if clear_orderly_software_session >> "$LOGFILE" 2>&1; then
        rm -f "$CHILD_PIDFILE"
        return 0
    fi

    # Bind the terminal marker to the admission token and exact child identity
    # so stop consumers cannot mistake a stale crash latch for this helper's
    # safety completion receipt.
    TERMINAL_REASON="session-$ADMISSION_TOKEN-boot-$CHILD_BOOT_ID-pid-$CHILD_PID-start-$CHILD_START_TICKS-$REASON"
    if ! promote_unresolved "$TERMINAL_REASON" >> "$LOGFILE" 2>&1; then
        log 'could not promote the unresolved marker; admission remains blocked by unresolved state' >> "$LOGFILE"
    fi
    log 'no valid exact-session software closeout receipt; operator resolution is required before another start' >> "$LOGFILE"
    rm -f "$CHILD_PIDFILE"

    [ "$CENSUS_EXPECTED_EXIT" -eq 0 ] || return 1
    [ "$SAFETY_OK" -eq 1 ] || return 1
    if [ "$EXIT_CODE" -eq 0 ] && [ "$EXPECTED_PID" != "$CHILD_PID" ]; then
        return 1
    fi
    return "$EXIT_CODE"
}

abandon_session() {
    ADMISSION_TOKEN=$1
    REASON=${2:-supervisor-launch-failed}
    prepare_state_dir || return 1
    if ! lock_matches "$ADMISSION_TOKEN"; then
        log 'cannot abandon an admission lock owned by another session'
        return 1
    fi
    promote_unresolved_locked "$REASON"
    RESULT=$?
    release_lock || RESULT=1
    return "$RESULT"
}

show_status() {
    if path_exists "$CRASH_LATCH_FILE"; then
        printf 'crash-latched\n'
        return 2
    fi
    if path_exists "$UNRESOLVED_FILE"; then
        printf 'unresolved\n'
        return 1
    fi
    if path_exists "$LOCK_DIR"; then
        printf 'admission-locked\n'
        return 3
    fi
    printf 'clear\n'
    return 0
}

self_test() {
    TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dcentrald-session-latch.XXXXXX") || return 1
    TEST_FAILURES=0
    SELF_TEST_SAFETY_SCRIPT=${DCENT_TEST_SAFETY_SCRIPT:-/bin/true}
    SELF_TEST_EXPECT_SAFEOFF=${DCENT_TEST_EXPECT_SAFEOFF:-default}
    SELF_TEST_CALLER_PLATFORM=${PLATFORM-}
    # The compiled parent-death boundary has its own native lifecycle test.
    # Keep this pure shell state-machine fixture independent of the target rootfs.
    PARENT_DEATH_HELPER=
    # Production call sites retain the global sync barrier above. The offline
    # transition fixture uses private ephemeral state and must not flush every
    # Docker Desktop bind mount for each marker transition.
    sync_state() { return 0; }
    PERSISTENCE_PATH=$TEST_ROOT/data
    STATE_DIR=$PERSISTENCE_PATH/dcent
    UNRESOLVED_FILE=$STATE_DIR/dcentrald-hardware-session.unresolved
    CRASH_LATCH_FILE=$STATE_DIR/dcentrald-hardware-session.crash-latched
    LOCK_DIR=$STATE_DIR/.dcentrald-session-latch.lock
    MOUNTS_FILE=$TEST_ROOT/mounts
    MOUNTINFO_FILE=$TEST_ROOT/mountinfo
    UBI_SYSFS_ROOT=$TEST_ROOT/sys/class/ubi
    UPDATE_LOCK_DIR=$TEST_ROOT/run/dcentos-sysupgrade.lock
    mkdir -p "$PERSISTENCE_PATH" "$TEST_ROOT/run" "$UBI_SYSFS_ROOT/ubi0"
    printf 'ubi0:rootfs_data %s ubifs rw,relatime 0 0\n' \
        "$PERSISTENCE_PATH" > "$MOUNTS_FILE"
    printf '21 1 0:20 / %s rw,relatime - ubifs ubi0:rootfs_data rw\n' \
        "$PERSISTENCE_PATH" > "$MOUNTINFO_FILE"
    printf '7\n' > "$UBI_SYSFS_ROOT/ubi0/mtd_num"

    mkdir "$UPDATE_LOCK_DIR"
    admit_update_window "$PERSISTENCE_PATH" "$UPDATE_LOCK_DIR" 7 \
        >/dev/null 2>&1 || TEST_FAILURES=$((TEST_FAILURES + 1))
    path_exists "$LOCK_DIR" && TEST_FAILURES=$((TEST_FAILURES + 1))
    printf '8\n' > "$UBI_SYSFS_ROOT/ubi0/mtd_num"
    if admit_update_window "$PERSISTENCE_PATH" "$UPDATE_LOCK_DIR" 7 \
        >/dev/null 2>&1; then
        TEST_FAILURES=$((TEST_FAILURES + 1))
    fi
    printf '7\n' > "$UBI_SYSFS_ROOT/ubi0/mtd_num"
    printf '21 1 0:20 /subroot %s rw,relatime - ubifs ubi0:rootfs_data rw\n' \
        "$PERSISTENCE_PATH" > "$MOUNTINFO_FILE"
    if admit_update_window "$PERSISTENCE_PATH" "$UPDATE_LOCK_DIR" 7 \
        >/dev/null 2>&1; then
        TEST_FAILURES=$((TEST_FAILURES + 1))
    fi
    printf '21 1 0:20 / %s rw,relatime - ubifs ubi0:rootfs_data rw\n' \
        "$PERSISTENCE_PATH" > "$MOUNTINFO_FILE"
    if prepare_session >/dev/null 2>&1; then
        TEST_FAILURES=$((TEST_FAILURES + 1))
    fi
    printf 'unresolved\n' > "$UNRESOLVED_FILE"
    if admit_update_window "$PERSISTENCE_PATH" "$UPDATE_LOCK_DIR" 7 \
        >/dev/null 2>&1; then
        TEST_FAILURES=$((TEST_FAILURES + 1))
    fi
    rm -f "$UNRESOLVED_FILE"
    write_marker "$CRASH_LATCH_FILE" \
        "crash-latched:session-x-boot-y-pid-1-start-1-expected-zero-awaiting-typed-disposition" \
        || TEST_FAILURES=$((TEST_FAILURES + 1))
    admit_update_window "$PERSISTENCE_PATH" "$UPDATE_LOCK_DIR" 7 \
        >/dev/null 2>&1 || TEST_FAILURES=$((TEST_FAILURES + 1))
    write_marker "$CRASH_LATCH_FILE" \
        "crash-latched:session-x-boot-y-pid-1-start-1-expected-zero-awaiting-typed-disposition-safeoff-failed" \
        || TEST_FAILURES=$((TEST_FAILURES + 1))
    if admit_update_window "$PERSISTENCE_PATH" "$UPDATE_LOCK_DIR" 7 \
        >/dev/null 2>&1; then
        TEST_FAILURES=$((TEST_FAILURES + 1))
    fi
    rm -f "$CRASH_LATCH_FILE"
    rmdir "$UPDATE_LOCK_DIR"
    [ "${PLATFORM-}" = "$SELF_TEST_CALLER_PLATFORM" ] \
        || TEST_FAILURES=$((TEST_FAILURES + 1))

    TOKEN=$(prepare_session 2>/dev/null) || TEST_FAILURES=$((TEST_FAILURES + 1))
    path_exists "$UNRESOLVED_FILE" || TEST_FAILURES=$((TEST_FAILURES + 1))
    lock_matches "$TOKEN" || TEST_FAILURES=$((TEST_FAILURES + 1))
    if prepare_session >/dev/null 2>&1; then
        TEST_FAILURES=$((TEST_FAILURES + 1))
    fi
    path_exists "$CRASH_LATCH_FILE" && TEST_FAILURES=$((TEST_FAILURES + 1))

    if supervise_session "$TOKEN" "$SELF_TEST_SAFETY_SCRIPT" "$TEST_ROOT/supervisor.log" \
        "$TEST_ROOT/child.pid" "$TEST_ROOT/expected.pid" /bin/true \
        >/dev/null 2>&1; then
        TEST_FAILURES=$((TEST_FAILURES + 1))
    fi
    path_exists "$CRASH_LATCH_FILE" || TEST_FAILURES=$((TEST_FAILURES + 1))
    case "$SELF_TEST_EXPECT_SAFEOFF" in
        success)
            grep -Fq 'safeoff-failed' "$CRASH_LATCH_FILE" \
                && TEST_FAILURES=$((TEST_FAILURES + 1))
            ;;
        failure)
            grep -Fq 'safeoff-failed' "$CRASH_LATCH_FILE" \
                || TEST_FAILURES=$((TEST_FAILURES + 1))
            ;;
        default) ;;
        *) TEST_FAILURES=$((TEST_FAILURES + 1)) ;;
    esac

    rm -f "$UNRESOLVED_FILE" "$CRASH_LATCH_FILE"
    rm -rf "$LOCK_DIR"
    TOKEN=$(prepare_session 2>/dev/null) || TEST_FAILURES=$((TEST_FAILURES + 1))
    abandon_session "$TOKEN" supervisor-launch-failed >/dev/null 2>&1 || TEST_FAILURES=$((TEST_FAILURES + 1))
    path_exists "$CRASH_LATCH_FILE" || TEST_FAILURES=$((TEST_FAILURES + 1))

    # Adversarially exercise the two pre-publication failure branches through
    # their common containment primitive. A live/unverified owner must suppress
    # every safety invocation; once death is observed, safety status must be
    # reflected in the durable reason exactly like the normal wait path.
    TEST_SAFETY_SCRIPT=$TEST_ROOT/test-safety.sh
    TEST_SAFETY_COUNT_FILE=$TEST_ROOT/test-safety.count
    DCENT_TEST_SAFETY_COUNT_FILE=$TEST_SAFETY_COUNT_FILE
    printf '%s\n' '#!/bin/sh' \
        'printf "invoked\\n" >> "$DCENT_TEST_SAFETY_COUNT_FILE"' \
        'exit "${DCENT_TEST_SAFETY_RC:-0}"' > "$TEST_SAFETY_SCRIPT"
    chmod +x "$TEST_SAFETY_SCRIPT"
    export DCENT_TEST_SAFETY_COUNT_FILE TEST_TERMINATION_RESULT DCENT_TEST_SAFETY_RC
    terminate_unpublished_child() {
        [ "${TEST_TERMINATION_RESULT:-failure}" = success ]
    }

    for TEST_CASE in safety-success safety-failure owner-live; do
        rm -f "$UNRESOLVED_FILE" "$CRASH_LATCH_FILE" "$TEST_SAFETY_COUNT_FILE"
        rm -rf "$LOCK_DIR"
        TOKEN=$(prepare_session 2>/dev/null) || TEST_FAILURES=$((TEST_FAILURES + 1))
        case "$TEST_CASE" in
            safety-success)
                TEST_TERMINATION_RESULT=success
                DCENT_TEST_SAFETY_RC=0
                EXPECTED_REASON=child-identity-publication-failed
                EXPECTED_INVOCATIONS=1
                ;;
            safety-failure)
                TEST_TERMINATION_RESULT=success
                DCENT_TEST_SAFETY_RC=1
                EXPECTED_REASON=child-identity-publication-failed-safeoff-failed
                EXPECTED_INVOCATIONS=1
                ;;
            owner-live)
                TEST_TERMINATION_RESULT=failure
                DCENT_TEST_SAFETY_RC=0
                EXPECTED_REASON=child-identity-publication-failed-owner-death-unverified
                EXPECTED_INVOCATIONS=0
                ;;
        esac
        export TEST_TERMINATION_RESULT DCENT_TEST_SAFETY_RC
        contain_unpublished_child_failure 424242 "$TEST_SAFETY_SCRIPT" \
            child-identity-publication-failed >/dev/null 2>&1 || true
        grep -Fq "crash-latched:$EXPECTED_REASON" "$CRASH_LATCH_FILE" \
            || TEST_FAILURES=$((TEST_FAILURES + 1))
        if [ -f "$TEST_SAFETY_COUNT_FILE" ]; then
            ACTUAL_INVOCATIONS=$(wc -l < "$TEST_SAFETY_COUNT_FILE")
        else
            ACTUAL_INVOCATIONS=0
        fi
        [ "$ACTUAL_INVOCATIONS" -eq "$EXPECTED_INVOCATIONS" ] \
            || TEST_FAILURES=$((TEST_FAILURES + 1))
    done

    # The state transition uses an external validator result, never exit status
    # alone. Its Rust tests execute the strict record/process/image checks.
    CLOSEOUT_VALIDATOR=$TEST_ROOT/closeout-validator
    DCENT_TEST_CLOSEOUT_TRACE=$TEST_ROOT/closeout-arguments
    export DCENT_TEST_CLOSEOUT_TRACE DCENT_TEST_CLOSEOUT_RC
    printf '%s\n' '#!/bin/sh' \
        'printf "%s\\n" "$*" > "$DCENT_TEST_CLOSEOUT_TRACE"' \
        'exit "${DCENT_TEST_CLOSEOUT_RC:-1}"' > "$CLOSEOUT_VALIDATOR"
    chmod +x "$CLOSEOUT_VALIDATOR"
    for TEST_CASE in valid legacy-requested-stop missing-proof wrong-pid missing-pid error-exit forced-stop invalid-stop safety-failed foreign-latch; do
        rm -f "$UNRESOLVED_FILE" "$CRASH_LATCH_FILE" "$DCENT_TEST_CLOSEOUT_TRACE"
        rm -rf "$LOCK_DIR"
        ADMISSION_TOKEN=$(prepare_session 2>/dev/null) || TEST_FAILURES=$((TEST_FAILURES + 1))
        release_lock || TEST_FAILURES=$((TEST_FAILURES + 1))
        CHILD_PID=123
        CHILD_START_TICKS=456
        CHILD_BOOT_ID=test-boot
        EXPECTED_PID=123
        EXPECTED_STOP_REASON=requested-stop
        EXIT_CODE=0
        SAFETY_OK=1
        DCENT_TEST_CLOSEOUT_RC=0
        case "$TEST_CASE" in
            legacy-requested-stop) EXPECTED_STOP_REASON= ;;
            missing-proof) DCENT_TEST_CLOSEOUT_RC=1 ;;
            wrong-pid) EXPECTED_PID=124 ;;
            missing-pid) EXPECTED_PID=; EXPECTED_STOP_REASON= ;;
            error-exit) EXIT_CODE=1 ;;
            forced-stop) EXPECTED_STOP_REASON=forced-stop-timeout ;;
            invalid-stop) EXPECTED_STOP_REASON=unrecognized ;;
            safety-failed) SAFETY_OK=0 ;;
            foreign-latch) printf 'foreign\n' > "$CRASH_LATCH_FILE" ;;
        esac
        normalize_expected_stop_reason
        if clear_orderly_software_session >/dev/null 2>&1; then
            case "$TEST_CASE" in valid|legacy-requested-stop) ;; *) TEST_FAILURES=$((TEST_FAILURES + 1)) ;; esac
            path_exists "$UNRESOLVED_FILE" && TEST_FAILURES=$((TEST_FAILURES + 1))
            grep -Fqx -- "--check-software-closeout 123 456 test-boot $ADMISSION_TOKEN" \
                "$DCENT_TEST_CLOSEOUT_TRACE" || TEST_FAILURES=$((TEST_FAILURES + 1))
        else
            case "$TEST_CASE" in valid|legacy-requested-stop) TEST_FAILURES=$((TEST_FAILURES + 1)) ;; esac
            path_exists "$UNRESOLVED_FILE" || TEST_FAILURES=$((TEST_FAILURES + 1))
        fi
    done

    # A failed thermal/crash marker publication cannot remove the durable
    # prelaunch boundary. A regular-file parent fails even when tests run root.
    write_marker "$UNRESOLVED_FILE" unresolved || TEST_FAILURES=$((TEST_FAILURES + 1))
    cp "$UNRESOLVED_FILE" "$TEST_ROOT/original-unresolved"
    SELF_TEST_CRASH_LATCH=$CRASH_LATCH_FILE
    printf 'not a directory\n' > "$TEST_ROOT/blocked-parent"
    CRASH_LATCH_FILE=$TEST_ROOT/blocked-parent/crash
    if promote_unresolved_locked thermal-lockout-persistence-failed >/dev/null 2>&1; then
        TEST_FAILURES=$((TEST_FAILURES + 1))
    fi
    cmp "$UNRESOLVED_FILE" "$TEST_ROOT/original-unresolved" >/dev/null 2>&1 \
        || TEST_FAILURES=$((TEST_FAILURES + 1))
    CRASH_LATCH_FILE=$SELF_TEST_CRASH_LATCH

    rm -f "$UNRESOLVED_FILE" "$CRASH_LATCH_FILE"
    rm -rf "$LOCK_DIR"
    printf 'tmpfs / tmpfs rw,relatime 0 0\n' > "$MOUNTS_FILE"
    if prepare_session >/dev/null 2>&1; then
        TEST_FAILURES=$((TEST_FAILURES + 1))
    fi

    rm -rf "$TEST_ROOT"
    if [ "$TEST_FAILURES" -ne 0 ]; then
        log "self-test failed ($TEST_FAILURES assertion(s))"
        return 1
    fi
    printf 'dcentrald session latch self-test passed\n'
}

case "${1:-}" in
    prepare) prepare_session ;;
    admit-update) admit_update_window "${2:-}" "${3:-}" "${4:-}" ;;
    latch) promote_unresolved "${2:-abnormal-exit}" ;;
    abandon) abandon_session "${2:-}" "${3:-supervisor-launch-failed}" ;;
    supervise-firstlight-work)
        CENSUS_EXPECTED_EXIT=2
        shift
        supervise_session "$@"
        ;;
    supervise-census)
        CENSUS_EXPECTED_EXIT=1
        shift
        supervise_session "$@"
        ;;
    supervise)
        shift
        supervise_session "$@"
        ;;
    status) show_status ;;
    self-test) self_test ;;
    *)
        echo "Usage: $0 {prepare|admit-update persistence-root update-lock current-mtd|latch [reason]|abandon token [reason]|supervise ...|status|self-test}" >&2
        exit 64
        ;;
esac
