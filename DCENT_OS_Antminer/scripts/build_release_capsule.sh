#!/usr/bin/env bash
# Build and atomically publish one declared release from an exact Git-object snapshot.
#
# The first process is a bootstrap only: it selects one full commit OID and
# materializes it. All Cargo, Buildroot, evidence, signing, and publication
# drivers then execute from that authenticated snapshot under one invocation.

set -euo pipefail
umask 077
# Several authenticated helpers import sibling modules. NTFS does not enforce
# the snapshot's POSIX 0500 directory modes, so default Python bytecode caching
# would add __pycache__ entries and invalidate the exact source tree mid-run.
export PYTHONDONTWRITEBYTECODE=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LIVE_REPO_ROOT="$(cd "$PROJECT_DIR/../.." && pwd)"
OUTPUT_ROOT_OVERRIDE=""
RELEASE_CHANNEL="${DCENT_RELEASE_CHANNEL:-beta}"
RELEASE_PRODUCER=""
RELEASE_PRODUCERS=()
RELEASE_DATE_OVERRIDE=""
PRODUCER_RESULT_JSON=""
CHANNEL_FEED_BASE=""
CHANNEL_FEED_BASE_SET=0
unset DCENT_UPDATE_FEED_BASE_URL

while [ "$#" -gt 0 ]; do
    case "$1" in
        --producer|--date|--result-json|--feed-base-url)
            [ "$#" -ge 2 ] || { echo "ERROR: $1 requires a value" >&2; exit 2; }
            case "$1" in
                --producer) RELEASE_PRODUCERS+=("$2"); RELEASE_PRODUCER=$2 ;;
                --date) RELEASE_DATE_OVERRIDE=$2 ;;
                --result-json) PRODUCER_RESULT_JSON=$2 ;;
                --feed-base-url)
                    [ "$CHANNEL_FEED_BASE_SET" = 0 ] && [ -n "$2" ] || {
                        echo "ERROR: --feed-base-url requires one nonempty explicit value" >&2; exit 2;
                    }
                    CHANNEL_FEED_BASE=$2
                    CHANNEL_FEED_BASE_SET=1
                    ;;
            esac
            shift 2
            ;;
        --output-root)
            [ "$#" -ge 2 ] || { echo "ERROR: --output-root requires a path" >&2; exit 2; }
            OUTPUT_ROOT_OVERRIDE=$2
            shift 2
            ;;
        --channel)
            [ "$#" -ge 2 ] || { echo "ERROR: --channel requires a value" >&2; exit 2; }
            RELEASE_CHANNEL=$2
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 --producer ID [--producer ID ...] --channel beta|stable [--date YYYYMMDD] [--feed-base-url HTTPS_BASE] --output-root DIR --result-json FILE"
            exit 0
            ;;
        *)
            echo "ERROR: unsupported argument: $1" >&2
            exit 2
            ;;
    esac
done

if [ -n "$CHANNEL_FEED_BASE" ]; then
    python3 - "$SCRIPT_DIR" "$CHANNEL_FEED_BASE" <<'PYFEEDURL'
import sys
sys.path.insert(0, sys.argv[1])
from release_channel_feed import feed
feed.https_url(sys.argv[2])
PYFEEDURL
    export DCENT_UPDATE_FEED_BASE_URL="$CHANNEL_FEED_BASE"
fi

case "$RELEASE_CHANNEL" in
    beta|stable) ;;
    *) echo "ERROR: release capsule channel must be beta or stable" >&2; exit 2 ;;
esac

[ -n "$RELEASE_PRODUCER" ] && [ -n "$PRODUCER_RESULT_JSON" ] || {
    echo "ERROR: --producer and --result-json are required" >&2; exit 2;
}
python3 - "$SCRIPT_DIR" "$RELEASE_CHANNEL" "${RELEASE_PRODUCERS[@]}" <<'PYCOHORT'
import sys
sys.path.insert(0, sys.argv[1])
from release_producer import cohort
from runtime_image_manifest import registry_channel
for row in cohort(sys.argv[3:]):
    registry_channel(row.board_target, sys.argv[2])
PYCOHORT
RELEASE_PRODUCER=${RELEASE_PRODUCERS[0]}
case "${DCENT_ALLOW_UNSIGNED_SYSUPGRADE:-0}:${DCENT_DEV_IMAGE:-0}" in
    0:0) ;; *) echo "ERROR: Beta/Stable capsule refuses unsigned/lab image overrides" >&2; exit 2 ;;
esac
case "$PRODUCER_RESULT_JSON" in
    /*|[A-Za-z]:*) ;;
    *) PRODUCER_RESULT_JSON="$PWD/$PRODUCER_RESULT_JSON" ;;
esac
[ ! -e "$PRODUCER_RESULT_JSON" ] && [ ! -L "$PRODUCER_RESULT_JSON" ] || {
    echo "ERROR: producer result destination already exists" >&2; exit 2;
}

normalize_shell_path() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -u "$1"
    else
        printf '%s\n' "$1"
    fi
}

if [ -n "$OUTPUT_ROOT_OVERRIDE" ]; then
    case "$OUTPUT_ROOT_OVERRIDE" in
        /*|[A-Za-z]:*) PUBLIC_OUTPUT_ROOT="$OUTPUT_ROOT_OVERRIDE" ;;
        *) PUBLIC_OUTPUT_ROOT="$PROJECT_DIR/$OUTPUT_ROOT_OVERRIDE" ;;
    esac
else
    PUBLIC_OUTPUT_ROOT="$PROJECT_DIR/output"
fi
mkdir -p "$PUBLIC_OUTPUT_ROOT"
PUBLIC_OUTPUT_ROOT="$(cd "$PUBLIC_OUTPUT_ROOT" && pwd)"

require_release_environment() {
    for name in \
        DCENT_RELEASE_SIGNING_KEY \
        DCENT_RELEASE_PUBKEY_FILE \
        DCENT_MANIFEST_PUBLIC_KEY_HEX \
        DCENT_RUST_BUILDER_BASE; do
        if [ -z "${!name:-}" ]; then
            echo "ERROR: release capsule requires $name" >&2
            return 1
        fi
    done
    if ! printf '%s\n' "$DCENT_RUST_BUILDER_BASE" \
        | grep -Eq '^.+@sha256:[0-9a-f]{64}$'; then
        echo "ERROR: DCENT_RUST_BUILDER_BASE must be one exact lowercase sha256 digest reference" >&2
        return 1
    fi
    case "${DCENT_TOOLCHAIN_SHA256_VERIFIED:-}" in
        1|true|TRUE|yes|YES|y|Y) ;;
        *)
            echo "ERROR: release capsule requires DCENT_TOOLCHAIN_SHA256_VERIFIED=1" >&2
            return 1
            ;;
    esac
    # Fail closed at ENTRY, not ~2 h into a cohort: the amlogic post-image
    # (am3-s19kpro persistent image) hard-refuses without the release-key
    # posture, and Phase 6 forwards this var with a :0 default. Found by run
    # drop1-20260915-urcjsmd8 (2026-09-15).
    if [ "${DCENT_REQUIRE_RELEASE_KEY:-0}" != 1 ]; then
        echo "ERROR: release capsule requires DCENT_REQUIRE_RELEASE_KEY=1" >&2
        return 1
    fi
}
require_release_environment

# The active Git installation supplies both native and MSYS OpenSSL. Select
# its MSYS build for the long authenticated paths throughout this process tree.
HOST_TOOLS_DIRECTORY="$(python3 "$SCRIPT_DIR/release_host_tools.py")"
if [ -n "$HOST_TOOLS_DIRECTORY" ]; then
    export PATH="$(normalize_shell_path "$HOST_TOOLS_DIRECTORY"):$PATH"
fi

SOURCE_SNAPSHOT="${DCENT_CAPSULE_BOOTSTRAP_SOURCE_SNAPSHOT:-}"
SOURCE_DESTROY_TOKEN="${DCENT_CAPSULE_BOOTSTRAP_SOURCE_DESTROY_TOKEN:-}"
SOURCE_COMMIT="${DCENT_CAPSULE_BOOTSTRAP_SOURCE_COMMIT:-}"
SOURCE_TREE="${DCENT_CAPSULE_BOOTSTRAP_SOURCE_TREE:-}"
SOURCE_OWNED=0

bootstrap_cleanup() {
    status=${1:-$?}
    trap - EXIT INT TERM
    set +e
    if [ "$SOURCE_OWNED" = "1" ] && [ -n "$SOURCE_SNAPSHOT" ]; then
        python3 "$SCRIPT_DIR/source_snapshot.py" destroy \
            --token "$SOURCE_DESTROY_TOKEN" "$SOURCE_SNAPSHOT" >/dev/null 2>&1 || true
    fi
    exit "$status"
}

if [ "${DCENT_CAPSULE_BOOTSTRAPPED:-0}" != "1" ]; then
    SOURCE_COMMIT="$(python3 "$SCRIPT_DIR/release_source_git.py" --repo-root "$LIVE_REPO_ROOT" --field commit)"
    case "$SOURCE_COMMIT" in
        [0-9a-f][0-9a-f]*) ;;
        *) echo "ERROR: Git did not return a full lowercase commit OID" >&2; exit 1 ;;
    esac
    WORK_PARENT="$PUBLIC_OUTPUT_ROOT/.dcent-release-capsules"
    SOURCE_PARENT="$WORK_PARENT/sources"
    mkdir -p "$SOURCE_PARENT"
    SOURCE_CREATE_RESULT="$(python3 "$SCRIPT_DIR/source_snapshot.py" create \
        --profile release-workspace-v1 \
        --repo-root "$LIVE_REPO_ROOT" \
        --commit "$SOURCE_COMMIT" \
        --stage-parent "$SOURCE_PARENT")"
    source_result_field() {
        printf '%s\n' "$SOURCE_CREATE_RESULT" \
            | python3 "$SCRIPT_DIR/source_snapshot.py" query-result --field "$1"
    }
    SOURCE_SNAPSHOT="$(source_result_field snapshot)"
    SOURCE_DESTROY_TOKEN="$(source_result_field destroy_token)"
    SOURCE_TREE="$(normalize_shell_path "$(source_result_field tree)")"
    SOURCE_OWNED=1
    trap bootstrap_cleanup EXIT
    trap 'bootstrap_cleanup 130' INT
    trap 'bootstrap_cleanup 143' TERM
    SNAPSHOT_DRIVER="$SOURCE_TREE/DCENT_OS_Antminer/scripts/build_release_capsule.sh"
    [ -f "$SNAPSHOT_DRIVER" ] || {
        echo "ERROR: selected commit does not contain the release capsule driver" >&2
        echo "       commit the capsule implementation before attempting a release" >&2
        exit 1
    }
    export DCENT_CAPSULE_BOOTSTRAPPED=1
    export DCENT_CAPSULE_BOOTSTRAP_SOURCE_SNAPSHOT="$SOURCE_SNAPSHOT"
    export DCENT_CAPSULE_BOOTSTRAP_SOURCE_DESTROY_TOKEN="$SOURCE_DESTROY_TOKEN"
    export DCENT_CAPSULE_BOOTSTRAP_SOURCE_COMMIT="$SOURCE_COMMIT"
    export DCENT_CAPSULE_BOOTSTRAP_SOURCE_TREE="$SOURCE_TREE"
    export DCENT_CAPSULE_BOOTSTRAP_GIT_OBJECT_REPO="$LIVE_REPO_ROOT"
    export DCENT_CAPSULE_BOOTSTRAP_EXTERNAL_INPUT_ROOT="$LIVE_REPO_ROOT"
    export DCENT_CAPSULE_BOOTSTRAP_PUBLIC_OUTPUT_ROOT="$PUBLIC_OUTPUT_ROOT"
    # Forward the selected release target (if any) through the snapshot exec;
    # the resumed driver defaults to s9 exactly as before.
    [ -n "${DCENT_RELEASE_TARGET:-}" ] && export DCENT_RELEASE_TARGET
    cohort_arguments=()
    [ -z "$CHANNEL_FEED_BASE" ] || cohort_arguments+=(--feed-base-url "$CHANNEL_FEED_BASE")
    for dcent_producer in "${RELEASE_PRODUCERS[@]}"; do cohort_arguments+=(--producer "$dcent_producer"); done
    exec bash "$SNAPSHOT_DRIVER" \
        --output-root "$PUBLIC_OUTPUT_ROOT" --channel "$RELEASE_CHANNEL" \
        "${cohort_arguments[@]}" --date "$RELEASE_DATE_OVERRIDE" --result-json "$PRODUCER_RESULT_JSON"
fi

# Everything below executes from the authenticated committed snapshot.
SOURCE_OWNED=1
# The exec resets caught traps. Re-establish the minimal source authority before
# any resumed verification can fail; capsule_cleanup replaces it once the other
# private authorities have initialized.
trap bootstrap_cleanup EXIT
trap 'bootstrap_cleanup 130' INT
trap 'bootstrap_cleanup 143' TERM
GIT_OBJECT_REPO="${DCENT_CAPSULE_BOOTSTRAP_GIT_OBJECT_REPO:?missing bootstrap Git authority}"
EXTERNAL_INPUT_ROOT="${DCENT_CAPSULE_BOOTSTRAP_EXTERNAL_INPUT_ROOT:?missing external input root}"
PUBLIC_OUTPUT_ROOT="${DCENT_CAPSULE_BOOTSTRAP_PUBLIC_OUTPUT_ROOT:?missing output root}"
VERIFIED_SOURCE="$(python3 "$SCRIPT_DIR/source_snapshot.py" verify-against-git \
    --repo-root "$GIT_OBJECT_REPO" --commit "$SOURCE_COMMIT" "$SOURCE_SNAPSHOT")"
VERIFIED_TREE="$(printf '%s\n' "$VERIFIED_SOURCE" \
    | python3 "$SCRIPT_DIR/source_snapshot.py" query-verified --field tree)"
VERIFIED_TREE="$(normalize_shell_path "$VERIFIED_TREE")"
[ "$PROJECT_DIR" = "$VERIFIED_TREE/DCENT_OS_Antminer" ] || {
    echo "ERROR: resumed release driver is not inside the authenticated snapshot" >&2
    exit 1
}
# Snapshot/Git-authority anchors re-enter python as subprocess arguments,
# and python->python spawns get no MSYS argv conversion: a POSIX /d/...
# anchor becomes D:\d\... there (2026-09-13 producer). Verify in POSIX form
# above, then pin the working anchors native before any child spawns.
case "$SOURCE_SNAPSHOT" in
    /[a-zA-Z]/*) SOURCE_SNAPSHOT="$(cygpath -m "$SOURCE_SNAPSHOT")" ;;
esac
case "$GIT_OBJECT_REPO" in
    /[a-zA-Z]/*) GIT_OBJECT_REPO="$(cygpath -m "$GIT_OBJECT_REPO")" ;;
esac
case "$EXTERNAL_INPUT_ROOT" in
    /[a-zA-Z]/*) EXTERNAL_INPUT_ROOT="$(cygpath -m "$EXTERNAL_INPUT_ROOT")" ;;
esac
RELEASE_TARGET="$(python3 "$SCRIPT_DIR/release_producer.py" query "$RELEASE_PRODUCER" build_target)"
CARGO_VARIANT="$(python3 "$SCRIPT_DIR/release_producer.py" query "$RELEASE_PRODUCER" cargo_variant)"
PRIMARY_ARTIFACT="$(python3 "$SCRIPT_DIR/release_producer.py" query "$RELEASE_PRODUCER" primary_artifact)"
RELEASE_STEM="$(python3 "$SCRIPT_DIR/release_producer.py" query "$RELEASE_PRODUCER" release_stem)"
HARDWARE_RECIPE="${DCENT_RELEASE_HARDWARE_RECIPE:-$(python3 "$SCRIPT_DIR/release_producer.py" query "$RELEASE_PRODUCER" hardware_recipe)}"
RELEASE_VERSION="$(python3 - "$SCRIPT_DIR" <<'PYVERSION'
import sys
sys.path.insert(0, sys.argv[1])
from release_train import workspace_version
print(workspace_version())
PYVERSION
)"
SOURCE_DATE_EPOCH="$(python3 "$SCRIPT_DIR/release_source_git.py" --repo-root "$GIT_OBJECT_REPO" --field epoch --commit "$SOURCE_COMMIT")"
RELEASE_DATE="$(python3 - "$SOURCE_DATE_EPOCH" <<'PY'
import datetime
import sys
print(datetime.datetime.fromtimestamp(int(sys.argv[1]), datetime.timezone.utc).strftime("%Y%m%d"))
PY
)"
if [ -n "$RELEASE_DATE_OVERRIDE" ]; then RELEASE_DATE="$RELEASE_DATE_OVERRIDE"; fi
RELEASE_NAME="$(python3 - "$SCRIPT_DIR" "$RELEASE_PRODUCER" "$RELEASE_CHANNEL" "$RELEASE_DATE" <<'PYNAME'
import sys
sys.path.insert(0, sys.argv[1])
from release_producer import get_producer, release_name
print(release_name(get_producer(sys.argv[2]), sys.argv[3], sys.argv[4]))
PYNAME
)"
WORK_PARENT="$PUBLIC_OUTPUT_ROOT/.dcent-release-capsules"
INVOCATION_PARENT="$WORK_PARENT/invocations"
RESULT_PARENT="$WORK_PARENT/results"
INPUT_PARENT="$WORK_PARENT/inputs"
SIGNING_PARENT="$WORK_PARENT/signing-authorities"
RELEASE_STAGE_PARENT="$PUBLIC_OUTPUT_ROOT/.release-set-stages"
RELEASES_PARENT="$PUBLIC_OUTPUT_ROOT/releases"
mkdir -p "$INVOCATION_PARENT" "$RESULT_PARENT" "$INPUT_PARENT" "$SIGNING_PARENT" \
    "$RELEASE_STAGE_PARENT" "$RELEASES_PARENT"
# POSIX umask does not protect the Windows DACL inherited by this directory.
# Both signing and result-stage recovery records require a private parent.
python3 "$SCRIPT_DIR/release_signing_authority.py" prepare-result-parent "$WORK_PARENT"
# Release-set staging is a sibling of WORK_PARENT and needs its own protected
# DACL before create-stage. It cannot inherit WORK_PARENT's private policy.
python3 "$SCRIPT_DIR/release_signing_authority.py" prepare-result-parent "$RELEASE_STAGE_PARENT"

INVOCATION_STAGE=""
INVOCATION_CAPABILITY=""
RESULT_STAGE=""
RESULT_ROOT=""
RESULT_CAPABILITY=""
RESULT_CREATE_RESULT_FILE=""
CARGO_INPUT_SNAPSHOT=""
CARGO_INPUT_DESTROY_TOKEN=""
SIGNING_AUTHORITY_STAGE=""
SIGNING_AUTHORITY_CAPABILITY=""
SIGNING_AUTHORITY_PRIVATE_KEY=""
SIGNING_AUTHORITY_PUBLIC_KEY=""
SIGNING_AUTHORITY_RESULT_FILE=""
RELEASE_SET_STAGE=""
RELEASE_SET_CAPABILITY_FILE=""
RELEASE_SET_MANIFEST=""
RELEASE_SET_PUBLISHED=0
INVOCATION_ID=""
COHORT_MEMBER_RESULTS=()

capsule_cleanup() {
    status=${1:-$?}
    recovery_authority_required=0
    result_recovery_required=0
    trap - EXIT INT TERM
    set +e
    if [ "$RELEASE_SET_PUBLISHED" != "1" ] \
        && [ -n "$RELEASE_SET_CAPABILITY_FILE" ] \
        && [ -f "$RELEASE_SET_CAPABILITY_FILE" ]; then
        release_set_destroy_error="$(
            python3 "$SCRIPT_DIR/release_set_publication.py" destroy-stage \
                --capability-file "$RELEASE_SET_CAPABILITY_FILE" \
                2>&1 >/dev/null
        )"
        if [ "$?" -eq 0 ]; then
            rm -f -- "$RELEASE_SET_CAPABILITY_FILE" || status=1
            RELEASE_SET_CAPABILITY_FILE=""
        else
            echo "ERROR: release-set cleanup failed; capability retained for recovery: $RELEASE_SET_CAPABILITY_FILE" >&2
            if [ -n "$release_set_destroy_error" ]; then
                printf '%s\n' "$release_set_destroy_error" >&2
            fi
            status=1
            recovery_authority_required=1
        fi
    fi
    if [ -n "$RELEASE_SET_MANIFEST" ]; then
        rm -f -- "$RELEASE_SET_MANIFEST" || status=1
    fi
    if [ "$RELEASE_SET_PUBLISHED" = "1" ] \
        && [ -n "$RELEASE_SET_CAPABILITY_FILE" ]; then
        rm -f -- "$RELEASE_SET_CAPABILITY_FILE" || status=1
    fi
    if [ -n "$RESULT_CREATE_RESULT_FILE" ] \
        && [ -f "$RESULT_CREATE_RESULT_FILE" ]; then
        recovered_result_stage="$(python3 "$SCRIPT_DIR/release_result_stage.py" \
            query-result --field stage < "$RESULT_CREATE_RESULT_FILE" 2>/dev/null)"
        recovered_result_capability="$(python3 "$SCRIPT_DIR/release_result_stage.py" \
            query-result --field capability < "$RESULT_CREATE_RESULT_FILE" 2>/dev/null)"
        if [ -n "$recovered_result_stage" ] \
            && [ -n "$recovered_result_capability" ]; then
            RESULT_STAGE="$(normalize_shell_path "$recovered_result_stage")"
            RESULT_CAPABILITY="$(normalize_shell_path "$recovered_result_capability")"
        else
            echo "ERROR: result-stage recovery result is unreadable; retained: $RESULT_CREATE_RESULT_FILE" >&2
            status=1
            recovery_authority_required=1
            result_recovery_required=1
        fi
    fi
    if [ "$result_recovery_required" = "0" ] \
        && [ -n "$RESULT_CREATE_RESULT_FILE" ] \
        && [ -n "$RESULT_STAGE" ] && [ -e "$RESULT_STAGE" ] \
        && { [ ! -f "$RESULT_CAPABILITY" ] \
            || [ ! -f "$RESULT_STAGE/result-stage.json" ] \
            || [ ! -d "$RESULT_STAGE/results" ]; }; then
        result_create_recovery_error="$(python3 "$SCRIPT_DIR/release_result_stage.py" create \
            --stage-parent "$RESULT_PARENT" \
            --invocation-stage "$INVOCATION_STAGE" \
            --result-output "$RESULT_CREATE_RESULT_FILE" 2>&1 >/dev/null)"
        if [ "$?" -ne 0 ]; then
            echo "ERROR: result-stage creation recovery failed; locator retained: $RESULT_CREATE_RESULT_FILE" >&2
            [ -n "$result_create_recovery_error" ] \
                && printf '%s\n' "$result_create_recovery_error" >&2
            status=1
            recovery_authority_required=1
            result_recovery_required=1
        fi
    fi
    if [ "$result_recovery_required" = "0" ] \
        && [ -n "$RESULT_STAGE" ] && [ -n "$RESULT_CAPABILITY" ] \
        && { [ -e "$RESULT_STAGE" ] || [ -e "$RESULT_CAPABILITY" ]; }; then
        result_destroy_error="$(python3 "$SCRIPT_DIR/release_result_stage.py" destroy \
            --capability "$RESULT_CAPABILITY" \
            --invocation-stage "$INVOCATION_STAGE" \
            "$RESULT_STAGE" 2>&1 >/dev/null)"
        if [ "$?" -ne 0 ]; then
            echo "ERROR: result-stage cleanup failed; recovery result retained: $RESULT_CREATE_RESULT_FILE" >&2
            [ -n "$result_destroy_error" ] && printf '%s\n' "$result_destroy_error" >&2
            status=1
            recovery_authority_required=1
            result_recovery_required=1
        fi
    fi
    if [ "$result_recovery_required" = "0" ] \
        && [ -n "$RESULT_CREATE_RESULT_FILE" ] \
        && [ -f "$RESULT_CREATE_RESULT_FILE" ]; then
        rm -f -- "$RESULT_CREATE_RESULT_FILE" || status=1
    fi
    if [ -n "$CARGO_INPUT_SNAPSHOT" ] && [ -e "$CARGO_INPUT_SNAPSHOT" ]; then
        python3 "$SCRIPT_DIR/build_input_snapshot.py" destroy \
            --token "$CARGO_INPUT_DESTROY_TOKEN" "$CARGO_INPUT_SNAPSHOT" \
            >/dev/null 2>&1 || {
                status=1
                recovery_authority_required=1
            }
    fi
    if [ -n "$SIGNING_AUTHORITY_RESULT_FILE" ]; then
        if [ -f "$SIGNING_AUTHORITY_RESULT_FILE" ]; then
            recovered_signing_stage="$(python3 "$SCRIPT_DIR/release_signing_authority.py" \
                query-result --field stage < "$SIGNING_AUTHORITY_RESULT_FILE" 2>/dev/null)"
            recovered_signing_capability="$(python3 "$SCRIPT_DIR/release_signing_authority.py" \
                query-result --field capability < "$SIGNING_AUTHORITY_RESULT_FILE" 2>/dev/null)"
            if [ -n "$recovered_signing_stage" ] \
                && [ -n "$recovered_signing_capability" ]; then
                SIGNING_AUTHORITY_STAGE="$(normalize_shell_path "$recovered_signing_stage")"
                SIGNING_AUTHORITY_CAPABILITY="$(normalize_shell_path "$recovered_signing_capability")"
            else
                echo "ERROR: signing-authority recovery result is unreadable; retained: $SIGNING_AUTHORITY_RESULT_FILE" >&2
                status=1
                recovery_authority_required=1
            fi
        else
            echo "ERROR: registered signing-authority recovery result is missing; upstream authority retained: $SIGNING_AUTHORITY_RESULT_FILE" >&2
            status=1
            recovery_authority_required=1
        fi
    fi
    if [ -n "$SIGNING_AUTHORITY_STAGE" ] \
        && [ -n "$SIGNING_AUTHORITY_CAPABILITY" ] \
        && { [ -e "$SIGNING_AUTHORITY_STAGE" ] \
            || [ -e "$SIGNING_AUTHORITY_CAPABILITY" ]; }; then
        signing_destroy_error="$(python3 "$SCRIPT_DIR/release_signing_authority.py" destroy \
            --capability "$SIGNING_AUTHORITY_CAPABILITY" \
            "$SIGNING_AUTHORITY_STAGE" 2>&1 >/dev/null)"
        if [ "$?" -ne 0 ]; then
            echo "ERROR: signing-authority cleanup failed; recovery result retained: $SIGNING_AUTHORITY_RESULT_FILE" >&2
            [ -n "$signing_destroy_error" ] && printf '%s\n' "$signing_destroy_error" >&2
            status=1
            recovery_authority_required=1
        fi
    fi
    if [ "$recovery_authority_required" = "0" ] \
        && [ -n "$SIGNING_AUTHORITY_RESULT_FILE" ] \
        && [ -f "$SIGNING_AUTHORITY_RESULT_FILE" ]; then
        rm -f -- "$SIGNING_AUTHORITY_RESULT_FILE" || status=1
    fi
    if [ "$recovery_authority_required" = "0" ] \
        && [ -n "$INVOCATION_STAGE" ] && [ -e "$INVOCATION_STAGE" ]; then
        # Both build drivers must have removed their exact Docker resources
        # before the invocation control stage becomes eligible for destruction.
        external_resources_absent=1
        for resource_field in cargo_volume buildroot_volume results_volume; do
            resource_name="$(python3 "$SCRIPT_DIR/release_invocation.py" query \
                --field "$resource_field" "$INVOCATION_STAGE" 2>/dev/null)"
            if [ -n "$resource_name" ] \
                && docker volume inspect -- "$resource_name" >/dev/null 2>&1; then
                external_resources_absent=0
            fi
        done
        builder_tag="$(python3 "$SCRIPT_DIR/release_docker_resources.py" \
            query-builder-tag "$INVOCATION_STAGE" 2>/dev/null)"
        if [ -n "$builder_tag" ] \
            && docker image inspect "$builder_tag" >/dev/null 2>&1; then
            external_resources_absent=0
        fi
        if [ -n "$INVOCATION_ID" ] \
            && docker container inspect "dcentos-cargo-run-${INVOCATION_ID}" \
                >/dev/null 2>&1; then
            external_resources_absent=0
        fi
        if [ "$external_resources_absent" = "1" ]; then
            if ! {
                python3 "$SCRIPT_DIR/release_invocation.py" mark-gc-eligible \
                    --capability "$INVOCATION_CAPABILITY" \
                    --reason external-resources-disposed-and-output-state-finalized \
                    "$INVOCATION_STAGE" >/dev/null 2>&1 \
                    && python3 "$SCRIPT_DIR/release_invocation.py" destroy \
                        --capability "$INVOCATION_CAPABILITY" "$INVOCATION_STAGE" \
                        >/dev/null 2>&1
            }; then
                status=1
                recovery_authority_required=1
            fi
        else
            echo "ERROR: capsule Docker resources remain; invocation retained for recovery" >&2
            status=1
            recovery_authority_required=1
        fi
    elif [ "$recovery_authority_required" != "0" ] \
        && [ -n "$INVOCATION_STAGE" ] && [ -e "$INVOCATION_STAGE" ]; then
        echo "ERROR: dependent cleanup failed; invocation retained for recovery: $INVOCATION_STAGE" >&2
    fi
    # Destroy the authenticated source last because every cleanup authority
    # helper above is itself executed from that snapshot.
    if [ "$recovery_authority_required" = "0" ] \
        && [ "$SOURCE_OWNED" = "1" ] && [ -n "$SOURCE_SNAPSHOT" ]; then
        python3 "$SCRIPT_DIR/source_snapshot.py" destroy \
            --token "$SOURCE_DESTROY_TOKEN" "$SOURCE_SNAPSHOT" >/dev/null 2>&1 || status=1
        SOURCE_OWNED=0
    elif [ "$recovery_authority_required" != "0" ] \
        && [ "$SOURCE_OWNED" = "1" ] && [ -n "$SOURCE_SNAPSHOT" ]; then
        echo "ERROR: cleanup helper source retained for recovery: $SOURCE_SNAPSHOT" >&2
    fi
    for dcent_member_result in "${COHORT_MEMBER_RESULTS[@]}"; do
        rm -f -- "$dcent_member_result" || status=1
    done
    for empty_directory in \
        "$INVOCATION_PARENT/.dcentos-release-invocation-capabilities" \
        "$SIGNING_PARENT/.dcentos-release-signing-authority-capabilities" \
        "$RESULT_PARENT/.dcentos-release-result-capabilities" \
        "$INVOCATION_PARENT" "$SIGNING_PARENT" "$RESULT_PARENT" "$RELEASE_STAGE_PARENT" \
        "$INPUT_PARENT" "$WORK_PARENT/sources"; do
        [ -n "$empty_directory" ] && rmdir -- "$empty_directory" >/dev/null 2>&1 || true
    done
    exit "$status"
}
trap capsule_cleanup EXIT
trap 'capsule_cleanup 130' INT
trap 'capsule_cleanup 143' TERM

INVOCATION_RESULT="$(python3 "$SCRIPT_DIR/release_invocation.py" create \
    --stage-parent "$INVOCATION_PARENT" --name "$RELEASE_TARGET")"
invocation_result_field() {
    printf '%s\n' "$INVOCATION_RESULT" \
        | python3 "$SCRIPT_DIR/release_invocation.py" query-result --field "$1"
}
INVOCATION_STAGE="$(normalize_shell_path "$(invocation_result_field stage)")"
INVOCATION_CAPABILITY="$(normalize_shell_path "$(invocation_result_field capability)")"
INVOCATION_ID="$(python3 "$SCRIPT_DIR/release_invocation.py" query \
    --field invocation_id "$INVOCATION_STAGE")"

# Convert the two mutable operator pathnames into one invocation-owned private
# authority before proving or using the keypair. Every later signer/verifier,
# including Docker mounts, receives only these stable copies. The private stage
# is never a release-set member and is destroyed before the invocation record.
SIGNING_AUTHORITY_RESULT_FILE="$WORK_PARENT/signing-authority-${INVOCATION_ID}.result.json"
python3 "$SCRIPT_DIR/release_signing_authority.py" create \
    --stage-parent "$SIGNING_PARENT" \
    --invocation-stage "$INVOCATION_STAGE" \
    --private-key "$DCENT_RELEASE_SIGNING_KEY" \
    --public-key "$DCENT_RELEASE_PUBKEY_FILE" \
    --result-output "$SIGNING_AUTHORITY_RESULT_FILE" >/dev/null
SIGNING_AUTHORITY_RESULT="$(cat -- "$SIGNING_AUTHORITY_RESULT_FILE")"
signing_authority_result_field() {
    printf '%s\n' "$SIGNING_AUTHORITY_RESULT" \
        | python3 "$SCRIPT_DIR/release_signing_authority.py" query-result --field "$1"
}
SIGNING_AUTHORITY_STAGE="$(normalize_shell_path "$(signing_authority_result_field stage)")"
SIGNING_AUTHORITY_CAPABILITY="$(normalize_shell_path "$(signing_authority_result_field capability)")"
SIGNING_AUTHORITY_PRIVATE_KEY="$(normalize_shell_path "$(signing_authority_result_field private_key)")"
SIGNING_AUTHORITY_PUBLIC_KEY="$(normalize_shell_path "$(signing_authority_result_field public_key)")"
DCENT_RELEASE_SIGNING_KEY="$SIGNING_AUTHORITY_PRIVATE_KEY"
DCENT_RELEASE_PUBKEY_FILE="$SIGNING_AUTHORITY_PUBLIC_KEY"
export DCENT_RELEASE_SIGNING_KEY DCENT_RELEASE_PUBKEY_FILE
python3 "$SCRIPT_DIR/release_signing_authority.py" verify \
    --invocation-stage "$INVOCATION_STAGE" "$SIGNING_AUTHORITY_STAGE" >/dev/null
# The cryptographic/key-format admission remains a separate explicit proof;
# the snapshot helper intentionally makes no OpenSSL or trust-policy claim.
bash "$SCRIPT_DIR/verify_release_keypair.sh" \
    "$DCENT_RELEASE_SIGNING_KEY" \
    "$DCENT_RELEASE_PUBKEY_FILE" \
    "$DCENT_MANIFEST_PUBLIC_KEY_HEX" >/dev/null

CARGO_INPUT_CREATE_RESULT="$(python3 "$SCRIPT_DIR/build_input_snapshot.py" create \
    --repo-root "$EXTERNAL_INPUT_ROOT" \
    --selection-root "$VERIFIED_TREE" \
    --build-input-manifest "$SCRIPT_DIR/build_inputs.manifest" \
    --target cargo-workspace \
    --stage-parent "$INPUT_PARENT")"
cargo_input_result_field() {
    printf '%s\n' "$CARGO_INPUT_CREATE_RESULT" \
        | python3 "$SCRIPT_DIR/build_input_snapshot.py" query-result --field "$1"
}
CARGO_INPUT_SNAPSHOT="$(normalize_shell_path "$(cargo_input_result_field snapshot)")"
CARGO_INPUT_DESTROY_TOKEN="$(cargo_input_result_field destroy_token)"

RESULT_CREATE_RESULT_FILE="$WORK_PARENT/result-stage-${INVOCATION_ID}.result.json"
python3 "$SCRIPT_DIR/release_result_stage.py" create \
    --stage-parent "$RESULT_PARENT" --invocation-stage "$INVOCATION_STAGE" \
    --result-output "$RESULT_CREATE_RESULT_FILE" >/dev/null
RESULT_CREATE_RESULT="$(cat -- "$RESULT_CREATE_RESULT_FILE")"
result_create_field() {
    printf '%s\n' "$RESULT_CREATE_RESULT" \
        | python3 "$SCRIPT_DIR/release_result_stage.py" query-result --field "$1"
}
RESULT_STAGE="$(normalize_shell_path "$(result_create_field stage)")"
RESULT_ROOT="$(normalize_shell_path "$(result_create_field result_root)")"
RESULT_CAPABILITY="$(normalize_shell_path "$(result_create_field capability)")"


export DCENT_PACKAGE_STATUS=release
export DCENT_RELEASE_IMAGE=1
export DCENT_REQUIRE_RELEASE_PROVENANCE=1
export DCENT_ALLOW_UNSIGNED_SYSUPGRADE=0
export DCENT_RELEASE_CHANNEL="$RELEASE_CHANNEL"
export DCENT_RELEASE_PRODUCER="$RELEASE_PRODUCER"
export DCENT_RELEASE_HARDWARE_RECIPE="$HARDWARE_RECIPE"
export DCENT_OTA_PUBLIC_KEY_HEX="$(python3 - "$SCRIPT_DIR" "$DCENT_RELEASE_PUBKEY_FILE" <<'PYKEY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from runtime_image_manifest import public_key_bytes
print(public_key_bytes(Path(sys.argv[2])).hex())
PYKEY
)"
export DCENT_RELEASE_CAPSULE_MODE=1
export DCENT_CAPSULE_GIT_OBJECT_REPO="$GIT_OBJECT_REPO"
export DCENT_CAPSULE_SOURCE_SNAPSHOT="$SOURCE_SNAPSHOT"
export DCENT_CAPSULE_SOURCE_COMMIT="$SOURCE_COMMIT"
export DCENT_CAPSULE_INVOCATION_STAGE="$INVOCATION_STAGE"
export DCENT_CAPSULE_RELEASE_INVOCATION="$INVOCATION_STAGE"
export DCENT_CAPSULE_RESULT_STAGE="$RESULT_STAGE"
export DCENT_CAPSULE_RESULT_ROOT="$RESULT_ROOT"
export DCENT_CAPSULE_RESULT_CAPABILITY="$RESULT_CAPABILITY"
export DCENT_CAPSULE_CARGO_BUILD_INPUT_SNAPSHOT="$CARGO_INPUT_SNAPSHOT"
export DCENT_CAPSULE_EXTERNAL_INPUT_ROOT="$EXTERNAL_INPUT_ROOT"
export DCENT_CAPSULE_EXTERNAL_INPUT_REPO_ROOT="$EXTERNAL_INPUT_ROOT"
export DCENT_CAPSULE_RELEASE_SET_CAPABILITY_FILE="$RELEASE_SET_CAPABILITY_FILE"

bash "$SCRIPT_DIR/build-dcentrald.sh" "$CARGO_VARIANT"
python3 "$SCRIPT_DIR/release_result_stage.py" verify \
    --invocation-stage "$INVOCATION_STAGE" "$RESULT_STAGE" >/dev/null

# One sealed binary/dashboard result serves the whole architecture cohort.
# Every producer receives a fresh output stage and its own Buildroot input/
# volume lifecycle; no package can add bytes to the sealed Cargo result.
for RELEASE_PRODUCER in "${RELEASE_PRODUCERS[@]}"; do
RELEASE_TARGET="$(python3 "$SCRIPT_DIR/release_producer.py" query "$RELEASE_PRODUCER" build_target)"
PRIMARY_ARTIFACT="$(python3 "$SCRIPT_DIR/release_producer.py" query "$RELEASE_PRODUCER" primary_artifact)"
RELEASE_STEM="$(python3 "$SCRIPT_DIR/release_producer.py" query "$RELEASE_PRODUCER" release_stem)"
RELEASE_NAME="${RELEASE_STEM}_${RELEASE_CHANNEL}${RELEASE_DATE}"
export DCENT_RELEASE_PRODUCER="$RELEASE_PRODUCER"
RELEASE_SET_PUBLISHED=0
RELEASE_SET_CAPABILITY_FILE="$WORK_PARENT/release-set-${INVOCATION_ID}-${RELEASE_PRODUCER}.capability.json"
python3 "$SCRIPT_DIR/release_set_publication.py" create-stage \
    --parent "$RELEASE_STAGE_PARENT" --capability-output "$RELEASE_SET_CAPABILITY_FILE" >/dev/null
RELEASE_SET_STAGE="$(python3 "$SCRIPT_DIR/release_set_publication.py" query \
    --field stage-path < "$RELEASE_SET_CAPABILITY_FILE")"
RELEASE_SET_STAGE="$(normalize_shell_path "$RELEASE_SET_STAGE")"
export DCENT_CAPSULE_RELEASE_SET_CAPABILITY_FILE="$RELEASE_SET_CAPABILITY_FILE"
# Per-producer logs live beside the shared rolling cohort log: the cohort log
# alone is capped and interleaves every lane, which has twice destroyed the
# first-order evidence for a failing lane. tee preserves the lane exit status
# through pipefail while capturing stdout and stderr per producer.
bash "$SCRIPT_DIR/build_in_docker.sh" \
    --producer "$RELEASE_PRODUCER" --output-dir "$RELEASE_SET_STAGE" \
    2>&1 | tee "$PUBLIC_OUTPUT_ROOT/../lane-${RELEASE_PRODUCER}.log"

# Keep the authenticated audit projections before the private owners disappear.
# The signed producer result below includes these exact retained bytes.
python3 "$SCRIPT_DIR/release_producer_evidence.py" retain-live \
    --repo-root "$GIT_OBJECT_REPO" --source-commit "$SOURCE_COMMIT" \
    --source-snapshot "$SOURCE_SNAPSHOT" \
    --release-invocation "$INVOCATION_STAGE" \
    --cargo-input-snapshot "$CARGO_INPUT_SNAPSHOT" \
    --result-stage "$RESULT_STAGE" --artifact-dir "$RELEASE_SET_STAGE"

# Produce one exact result from this invocation-owned stage. No artifact glob
# chooses the primary: its basename comes only from the canonical producer.
if [ ! -f "$RELEASE_SET_STAGE/$PRIMARY_ARTIFACT.sig" ]; then
    python3 "$SCRIPT_DIR/sign_release_artifact.py" "$RELEASE_SET_STAGE/$PRIMARY_ARTIFACT" \
        --key "$DCENT_RELEASE_SIGNING_KEY" --pubkey "$DCENT_RELEASE_PUBKEY_FILE" \
        --staged-output >/dev/null
fi
producer_result_args=(--producer "$RELEASE_PRODUCER" --source-commit "$SOURCE_COMMIT"
    --version "$RELEASE_VERSION" --channel "$RELEASE_CHANNEL"
    --hardware-recipe "$HARDWARE_RECIPE" --pubkey "$DCENT_RELEASE_PUBKEY_FILE")
ancillary_names=()
for dcent_file in "$RELEASE_SET_STAGE"/*; do
    [ -f "$dcent_file" ] && [ ! -L "$dcent_file" ] || {
        echo "ERROR: release stage contains a nonregular payload" >&2; exit 1;
    }
    dcent_name=$(basename "$dcent_file")
    case "$dcent_name" in
        "$PRIMARY_ARTIFACT"|"$PRIMARY_ARTIFACT.sig"|"$PRIMARY_ARTIFACT.runtime-image.json"|"$PRIMARY_ARTIFACT.runtime-image.sig") ;;
        *) ancillary_names+=("$dcent_name") ;;
    esac
done
stage_result_args=()
for dcent_name in "${ancillary_names[@]}"; do stage_result_args+=(--ancillary "$dcent_name"); done
python3 "$SCRIPT_DIR/release_producer.py" create-result "${producer_result_args[@]}" \
    --root "$RELEASE_SET_STAGE" --primary "$PRIMARY_ARTIFACT" \
    --result-json "$RELEASE_SET_STAGE/producer-result.json" "${stage_result_args[@]}" >/dev/null
python3 "$SCRIPT_DIR/sign_release_artifact.py" "$RELEASE_SET_STAGE/producer-result.json" \
    --key "$DCENT_RELEASE_SIGNING_KEY" --pubkey "$DCENT_RELEASE_PUBKEY_FILE" \
    --staged-output >/dev/null

RELEASE_SET_MANIFEST="$WORK_PARENT/release-set-${INVOCATION_ID}-${RELEASE_PRODUCER}.files.json"
python3 "$SCRIPT_DIR/release_set_publication.py" manifest-stage \
    --capability-file "$RELEASE_SET_CAPABILITY_FILE" --output "$RELEASE_SET_MANIFEST" >/dev/null
python3 "$SCRIPT_DIR/release_set_publication.py" seal-stage \
    --capability-file "$RELEASE_SET_CAPABILITY_FILE" --manifest "$RELEASE_SET_MANIFEST" \
    --output-name "$RELEASE_NAME" >/dev/null
PUBLISH_RESULT="$(python3 "$SCRIPT_DIR/release_set_publication.py" publish \
    --capability-file "$RELEASE_SET_CAPABILITY_FILE" --output-parent "$RELEASES_PARENT")"
RELEASE_SET_PUBLISHED=1
PUBLISHED_PATH="$(printf '%s\n' "$PUBLISH_RESULT" \
    | python3 "$SCRIPT_DIR/release_set_publication.py" query --field published-path)"
PUBLISHED_PATH="$(normalize_shell_path "$PUBLISHED_PATH")"
# The external result uses paths relative to the caller's explicit output root.
# The signed in-directory result remains relative to its own release directory.
external_result_args=()
for dcent_name in "${ancillary_names[@]}" producer-result.json producer-result.json.sig; do
    external_result_args+=(--ancillary "releases/$RELEASE_NAME/$dcent_name")
done
python3 "$SCRIPT_DIR/release_producer.py" create-result "${producer_result_args[@]}" \
    --root "$PUBLIC_OUTPUT_ROOT" --primary "releases/$RELEASE_NAME/$PRIMARY_ARTIFACT" \
    --result-json "$WORK_PARENT/member-${INVOCATION_ID}-${RELEASE_PRODUCER}.json" "${external_result_args[@]}" >/dev/null
COHORT_MEMBER_RESULTS+=("$WORK_PARENT/member-${INVOCATION_ID}-${RELEASE_PRODUCER}.json")
rm -f -- "$RELEASE_SET_CAPABILITY_FILE" "$RELEASE_SET_MANIFEST"
RELEASE_SET_CAPABILITY_FILE=""
RELEASE_SET_MANIFEST=""
echo "Signed artifact set: $PUBLISHED_PATH"
done
cohort_result_args=()
for dcent_producer in "${RELEASE_PRODUCERS[@]}"; do cohort_result_args+=(--producer "$dcent_producer"); done
for dcent_member_result in "${COHORT_MEMBER_RESULTS[@]}"; do cohort_result_args+=(--member-result "$dcent_member_result"); done
python3 "$SCRIPT_DIR/release_producer.py" create-cohort-result "${cohort_result_args[@]}" \
    --source-commit "$SOURCE_COMMIT" --version "$RELEASE_VERSION" --channel "$RELEASE_CHANNEL" \
    --hardware-recipe "$HARDWARE_RECIPE" --pubkey "$DCENT_RELEASE_PUBKEY_FILE" \
    --root "$PUBLIC_OUTPUT_ROOT" --result-json "$PRODUCER_RESULT_JSON" >/dev/null
echo "Verified producer cohort result: $PRODUCER_RESULT_JSON"
