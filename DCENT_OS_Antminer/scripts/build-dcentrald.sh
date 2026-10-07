#!/bin/bash
# Build dcentrald for Antminer control boards
#
# Usage:
#   ./scripts/build-dcentrald.sh [target]
#
# Targets:
#   zynq      - Antminer S9/S17/S19 Zynq boards (ARMv7-A, Cortex-A9)  [default]
#   s19k-tmp  - S19k Pro Braiins /tmp handoff (ARMv7 hard-float compatibility ABI)
#   amlogic   - Antminer S19XP/S21+ Amlogic A113D boards (AArch64, Cortex-A53)
#   beaglebone - Antminer S19j BeagleBone AM335x boards (ARMv7-A, Cortex-A8)
#   native    - Build for the host machine (development/testing)
#
# Requires Docker Desktop running.
# Output: dcentrald/target/<triple>/release/dcentrald
#
# RELEASE BUILDS: export DCENT_MANIFEST_PUBLIC_KEY_HEX (64-hex ed25519
# verifying key) BEFORE running this script AND before
# scripts/build_in_docker.sh. The pin is baked into dcentrald HERE at
# cargo-build time (option_env! in dcentrald-api/src/ota_signature.rs);
# build_in_docker.sh Phase 5 then verifies the staged binary actually embeds
# the same hex and hard-fails otherwise. Exporting the pin only for
# build_in_docker.sh CANNOT retro-pin a binary that was already built here —
# this script fails fast (below) if a release context is indicated without
# the pin, instead of silently producing an unpinned (fail-open) binary.

set -euo pipefail

TARGET="${1:-zynq}"
ORIGINAL_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_DIR="$ORIGINAL_SCRIPT_DIR"
DCENTRALD_DIR="$(cd "$SCRIPT_DIR/../dcentrald" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CAPSULE_MODE=0
CAPSULE_SOURCE_WORKSPACE="DCENT_OS_Antminer/dcentrald"
CARGO_VOLUME_CREATED=0
BUILDER_TAG_CREATED=0
BUILDER_IMAGE_REUSED=0
CAPSULE_CONTAINER_STARTED=0
CAPSULE_BUILDER_RECIPE_SHA256=""
CAPSULE_BUILDER_RECIPE_TAG=""
BUILD_INPUT_SNAPSHOT=""
BUILD_INPUT_DESTROY_TOKEN=""
BUILD_INPUT_OWNED=0
DOCKER_BIN="${DCENT_DOCKER_BIN:-}"
S19K_SOURCE_RECEIPT=""
S19K_POST_SOURCE_SNAPSHOT=""
S19K_TMP_BUILD_RECEIPT=""
S19K_BUILD_OBSERVATION_ID=""
S19K_TMP_BUILD_VERIFIER="$SCRIPT_DIR/s19k_tmp_build_artifact.py"

_is_truthy() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|y|Y) return 0 ;;
        *) return 1 ;;
    esac
}

# WS-A4 (2026-09-01): RELEASE is the DEFAULT image posture. Resolve the
# canonical posture (scripts/lib/release_posture.sh): an explicitly-set
# DCENT_RELEASE_IMAGE wins; else DCENT_DEV_IMAGE=1 selects DEV/LAB; else
# RELEASE. Plain development/bench Cargo builds must opt out explicitly:
#   DCENT_DEV_IMAGE=1 bash scripts/build-dcentrald.sh <arch>
. "$SCRIPT_DIR/lib/release_posture.sh"
RELEASE_CONTEXT=""
if dcent_release_posture_is_release; then
    RELEASE_CONTEXT="DCENT_RELEASE_IMAGE=$(dcent_release_posture_value) (default posture; DCENT_DEV_IMAGE=1 opts out)"
elif _is_truthy "${DCENT_REQUIRE_RELEASE_PROVENANCE:-0}"; then
    RELEASE_CONTEXT="DCENT_REQUIRE_RELEASE_PROVENANCE=${DCENT_REQUIRE_RELEASE_PROVENANCE}"
elif _is_truthy "${DCENT_REQUIRE_RELEASE_KEY:-0}"; then
    RELEASE_CONTEXT="DCENT_REQUIRE_RELEASE_KEY=${DCENT_REQUIRE_RELEASE_KEY}"
else
    case "${DCENT_PACKAGE_STATUS:-}" in
        release|production|stable)
            RELEASE_CONTEXT="DCENT_PACKAGE_STATUS=${DCENT_PACKAGE_STATUS}" ;;
    esac
fi
if [ -z "$RELEASE_CONTEXT" ] && [ -n "${DCENT_MANIFEST_PUBLIC_KEY_HEX+set}" ] \
    && [ -z "${DCENT_MANIFEST_PUBLIC_KEY_HEX}" ]; then
    RELEASE_CONTEXT="DCENT_MANIFEST_PUBLIC_KEY_HEX exported but empty"
fi

# Cargo release-capsule mode is deliberately all-or-nothing. The caller
# supplies independent source, invocation, result-stage, and external-input
# authorities; a partial capsule is never interpreted as a development build.
CAPSULE_ENV_NAMES=(
    DCENT_CAPSULE_GIT_OBJECT_REPO
    DCENT_CAPSULE_SOURCE_SNAPSHOT
    DCENT_CAPSULE_SOURCE_COMMIT
    DCENT_CAPSULE_INVOCATION_STAGE
    DCENT_CAPSULE_RESULT_STAGE
    DCENT_CAPSULE_RESULT_ROOT
    DCENT_CAPSULE_RESULT_CAPABILITY
    DCENT_CAPSULE_EXTERNAL_INPUT_REPO_ROOT
    DCENT_CAPSULE_CARGO_BUILD_INPUT_SNAPSHOT
)
CAPSULE_ENV_COUNT=0
for capsule_env_name in "${CAPSULE_ENV_NAMES[@]}"; do
    if [ -n "${!capsule_env_name:-}" ]; then
        CAPSULE_ENV_COUNT=$((CAPSULE_ENV_COUNT + 1))
    fi
done
if [ "$CAPSULE_ENV_COUNT" -ne 0 ] && [ "$CAPSULE_ENV_COUNT" -ne "${#CAPSULE_ENV_NAMES[@]}" ]; then
    echo "ERROR: release capsule environment is incomplete; all capsule authorities are required" >&2
    for capsule_env_name in "${CAPSULE_ENV_NAMES[@]}"; do
        [ -n "${!capsule_env_name:-}" ] || echo "       missing: $capsule_env_name" >&2
    done
    exit 1
fi
if [ "$CAPSULE_ENV_COUNT" -eq "${#CAPSULE_ENV_NAMES[@]}" ] && [ -z "$RELEASE_CONTEXT" ]; then
    RELEASE_CONTEXT="authenticated release capsule"
fi
if [ "$CAPSULE_ENV_COUNT" -eq "${#CAPSULE_ENV_NAMES[@]}" ] \
    && _is_truthy "${DCENT_ALLOW_UNSIGNED_SYSUPGRADE:-0}"; then
    echo "ERROR: DCENT_ALLOW_UNSIGNED_SYSUPGRADE is forbidden in release capsule mode" >&2
    exit 1
fi
if [ -n "$RELEASE_CONTEXT" ] && [ "$CAPSULE_ENV_COUNT" -eq 0 ]; then
    echo "ERROR: release context indicated ($RELEASE_CONTEXT) without an authenticated release capsule" >&2
    echo "       direct working-tree Cargo builds are development-only" >&2
    echo "       for a DEV/LAB binary build, opt out explicitly: DCENT_DEV_IMAGE=1 $0 <arch>" >&2
    exit 1
fi

command -v python3 >/dev/null 2>&1 || {
    echo "ERROR: python3 is required for build lineage verification" >&2
    exit 1
}
# Imported verifier modules must never create __pycache__ inside the exact
# authenticated snapshot tree (some host filesystems do not enforce its 0500
# directory modes as strongly as native Linux filesystems).
export PYTHONDONTWRITEBYTECODE=1
normalize_shell_path() {
    path_value=$1
    if [[ "$path_value" == '\\?\'* ]]; then
        path_value="${path_value:4}"
    fi
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -u "$path_value"
    else
        printf '%s\n' "$path_value"
    fi
}

if [ "$CAPSULE_ENV_COUNT" -eq "${#CAPSULE_ENV_NAMES[@]}" ]; then
    CAPSULE_MODE=1
    case "$TARGET" in
        zynq|amlogic) ;;
        *)
            echo "ERROR: Cargo release capsule supports only targets zynq and amlogic" >&2
            exit 1
            ;;
    esac
    SNAPSHOT_VERIFY_RESULT="$(python3 "$SCRIPT_DIR/source_snapshot.py" verify-against-git \
        --repo-root "$DCENT_CAPSULE_GIT_OBJECT_REPO" \
        --commit "$DCENT_CAPSULE_SOURCE_COMMIT" \
        "$DCENT_CAPSULE_SOURCE_SNAPSHOT")"
    snapshot_verified_field() {
        printf '%s\n' "$SNAPSHOT_VERIFY_RESULT" \
            | python3 "$SCRIPT_DIR/source_snapshot.py" query-verified "$@"
    }
    CAPSULE_SOURCE_TREE="$(normalize_shell_path "$(snapshot_verified_field --field tree)")"
    CAPSULE_SOURCE_ID="$(snapshot_verified_field --field snapshot_id)"
    CAPSULE_RESULT_STAGE_SHELL="$(normalize_shell_path "$DCENT_CAPSULE_RESULT_STAGE")"
    CAPSULE_RESULT_ROOT_SHELL="$(normalize_shell_path "$DCENT_CAPSULE_RESULT_ROOT")"
    CAPSULE_RESULT_CAPABILITY_SHELL="$(normalize_shell_path "$DCENT_CAPSULE_RESULT_CAPABILITY")"
    CAPSULE_EXTERNAL_INPUT_ROOT_SHELL="$(normalize_shell_path "$DCENT_CAPSULE_EXTERNAL_INPUT_REPO_ROOT")"
    CAPSULE_CARGO_BUILD_INPUT_SNAPSHOT_SHELL="$(normalize_shell_path "$DCENT_CAPSULE_CARGO_BUILD_INPUT_SNAPSHOT")"
    EXPECTED_SCRIPT_DIR="$CAPSULE_SOURCE_TREE/DCENT_OS_Antminer/scripts"
    EXPECTED_SCRIPT="$EXPECTED_SCRIPT_DIR/build-dcentrald.sh"
    [ -f "$EXPECTED_SCRIPT" ] || {
        echo "ERROR: authenticated source snapshot does not contain build-dcentrald.sh" >&2
        exit 1
    }
    [ -d "$CAPSULE_SOURCE_TREE/$CAPSULE_SOURCE_WORKSPACE" ] || {
        echo "ERROR: authenticated source snapshot does not contain dcentrald workspace" >&2
        exit 1
    }

    # Execute the authenticated script object itself.  On the second entry,
    # require both the expected snapshot id and the physical script directory;
    # a caller-supplied marker cannot redirect execution back to the live tree.
    if [ "${DCENT_CAPSULE_REEXEC_ID:-}" != "$CAPSULE_SOURCE_ID" ] \
        || [ "$SCRIPT_DIR" != "$EXPECTED_SCRIPT_DIR" ]; then
        DCENT_CAPSULE_REEXEC_ID="$CAPSULE_SOURCE_ID" exec bash "$EXPECTED_SCRIPT" "$@"
    fi

    python3 "$SCRIPT_DIR/release_invocation.py" verify \
        "$DCENT_CAPSULE_INVOCATION_STAGE" >/dev/null
    python3 "$SCRIPT_DIR/release_result_stage.py" verify \
        --invocation-stage "$DCENT_CAPSULE_INVOCATION_STAGE" \
        "$DCENT_CAPSULE_RESULT_STAGE" >/dev/null
    result_stage_field() {
        python3 "$SCRIPT_DIR/release_result_stage.py" query \
            --invocation-stage "$DCENT_CAPSULE_INVOCATION_STAGE" \
            --field "$1" "$DCENT_CAPSULE_RESULT_STAGE"
    }
    [ "$(result_stage_field state)" = "building" ] || {
        echo "ERROR: Cargo result stage is not in building state" >&2
        exit 1
    }
    [ "$(normalize_shell_path "$(result_stage_field result_root)")" = "$CAPSULE_RESULT_ROOT_SHELL" ] || {
        echo "ERROR: supplied result root is not the authenticated result-stage root" >&2
        exit 1
    }
    [ "$(normalize_shell_path "$(result_stage_field capability)")" = "$CAPSULE_RESULT_CAPABILITY_SHELL" ] || {
        echo "ERROR: supplied result capability is not bound to the result stage" >&2
        exit 1
    }
    [ -z "$(find "$CAPSULE_RESULT_ROOT_SHELL" -mindepth 1 -print -quit)" ] || {
        echo "ERROR: Cargo result root is not empty at invocation start" >&2
        exit 1
    }
    CAPSULE_INVOCATION_ID="$(python3 "$SCRIPT_DIR/release_invocation.py" query \
        --field invocation_id "$DCENT_CAPSULE_INVOCATION_STAGE")"
    CAPSULE_CARGO_VOLUME="$(python3 "$SCRIPT_DIR/release_invocation.py" query \
        --field cargo_volume "$DCENT_CAPSULE_INVOCATION_STAGE")"
    CAPSULE_INVOCATION_CAPABILITY="$(python3 "$SCRIPT_DIR/release_invocation.py" query \
        --field capability "$DCENT_CAPSULE_INVOCATION_STAGE")"
    CAPSULE_BUILDER_TAG="$(python3 "$SCRIPT_DIR/release_docker_resources.py" \
        query-builder-tag "$DCENT_CAPSULE_INVOCATION_STAGE")"
    CAPSULE_CONTAINER_NAME="dcentos-cargo-run-${CAPSULE_INVOCATION_ID}"
    SCRIPT_DIR="$EXPECTED_SCRIPT_DIR"
    DCENTRALD_DIR="$CAPSULE_SOURCE_TREE/$CAPSULE_SOURCE_WORKSPACE"
    REPO_ROOT="$CAPSULE_SOURCE_TREE"
    [ -d "$CAPSULE_EXTERNAL_INPUT_ROOT_SHELL" ] || {
        echo "ERROR: capsule external-input repository root is not a directory" >&2
        exit 1
    }
else
    BUILD_INPUT_REPO_ROOT="$REPO_ROOT"
    BUILD_INPUT_MANIFEST="$SCRIPT_DIR/build_inputs.manifest"
fi

emit_build_receipts() {
    receipt_target=$1
    receipt_variant=$2
    receipt_release_dir=$3
    receipt_metadata=$4
    receipt_toolchain=$5
    receipt_compile_env=$6

    if [ "$CAPSULE_MODE" -ne 1 ]; then
        echo "WARNING: build receipt skipped: direct development builds do not satisfy schema-v4 capsule lineage" >&2
        return 0
    fi
    python3 "$SCRIPT_DIR/binary_build_receipt.py" create \
        --git-object-repo "$DCENT_CAPSULE_GIT_OBJECT_REPO" \
        --source-snapshot "$DCENT_CAPSULE_SOURCE_SNAPSHOT" \
        --source-commit "$DCENT_CAPSULE_SOURCE_COMMIT" \
        --source-workspace "$CAPSULE_SOURCE_WORKSPACE" \
        --release-invocation "$DCENT_CAPSULE_INVOCATION_STAGE" \
        --result-root "$DCENT_CAPSULE_RESULT_ROOT" \
        --build-input-snapshot "$BUILD_INPUT_SNAPSHOT" \
        --target "$receipt_target" \
        --profile release \
        --build-variant "$receipt_variant" \
        --metadata "$receipt_metadata" \
        --toolchain-context "$receipt_toolchain" \
        --compile-environment "$receipt_compile_env" \
        --binary "$receipt_release_dir/dcentrald" \
        --binary "$receipt_release_dir/dcentos-init" \
        --binary "$receipt_release_dir/dcentos-discovery"
}

# Keep an explicit Cargo external-input selection snapshot even while the
# current policy selects no files. Release receipts bind that empty selection
# to the authenticated manifest, so a future Cargo input cannot appear without
# an intentional policy and evidence change. A release capsule consumes the
# outer orchestrator's verified v2 snapshot and must not destroy it; direct
# development builds retain the local create/destroy lifecycle.
if [ "$CAPSULE_MODE" -eq 1 ]; then
    BUILD_INPUT_SNAPSHOT="$DCENT_CAPSULE_CARGO_BUILD_INPUT_SNAPSHOT"
    query_build_input_snapshot() {
        python3 "$SCRIPT_DIR/build_input_snapshot.py" query-snapshot \
            --target cargo-workspace "$@" "$BUILD_INPUT_SNAPSHOT"
    }
    BUILD_INPUT_STAGE_AUTHORITY="$(query_build_input_snapshot --field stage)"
    BUILD_INPUT_STAGE="$(normalize_shell_path "$BUILD_INPUT_STAGE_AUTHORITY")"
    [ "$CAPSULE_CARGO_BUILD_INPUT_SNAPSHOT_SHELL" \
        = "$BUILD_INPUT_STAGE/snapshot.json" ] || {
        echo "ERROR: Cargo build-input descriptor path is not canonical for its verified stage" >&2
        exit 1
    }
    [ "$(query_build_input_snapshot --field manifest_path)" \
        = "DCENT_OS_Antminer/scripts/build_inputs.manifest" ] || {
        echo "ERROR: Cargo build-input snapshot has the wrong manifest authority" >&2
        exit 1
    }
    # Querying the id is intentionally redundant: it forces one full verified
    # scalar read before any Docker resource is allocated.
    query_build_input_snapshot --field snapshot_id >/dev/null
else
    BUILD_INPUT_CREATE_RESULT="$(python3 "$SCRIPT_DIR/build_input_snapshot.py" create \
        --repo-root "$BUILD_INPUT_REPO_ROOT" \
        --build-input-manifest "$BUILD_INPUT_MANIFEST" \
        --target cargo-workspace)"
    snapshot_result_field() {
        printf '%s\n' "$BUILD_INPUT_CREATE_RESULT" \
            | python3 "$SCRIPT_DIR/build_input_snapshot.py" query-result "$@"
    }
    BUILD_INPUT_STAGE_AUTHORITY="$(snapshot_result_field --field stage)"
    BUILD_INPUT_STAGE="$(normalize_shell_path "$BUILD_INPUT_STAGE_AUTHORITY")"
    BUILD_INPUT_SNAPSHOT="$(snapshot_result_field --field snapshot)"
    BUILD_INPUT_DESTROY_TOKEN="$(snapshot_result_field --field destroy_token)"
    BUILD_INPUT_OWNED=1
fi
select_docker_bin() {
    if [ -n "$DOCKER_BIN" ]; then
        command -v "$DOCKER_BIN" >/dev/null 2>&1 || {
            echo "ERROR: configured Docker command not found: $DOCKER_BIN" >&2
            return 1
        }
    elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        DOCKER_BIN=docker
    elif command -v docker.exe >/dev/null 2>&1 && docker.exe info >/dev/null 2>&1; then
        DOCKER_BIN=docker.exe
    else
        echo "ERROR: Docker daemon not responding via docker or docker.exe" >&2
        return 1
    fi
}

if [ "$TARGET" != native ]; then
    select_docker_bin
fi

load_docker_spec_argv() {
    docker_spec=$1
    DOCKER_SPEC_ARGV=()
    mapfile -d '' -t DOCKER_SPEC_ARGV < <(
        printf '%s\n' "$docker_spec" \
            | python3 "$SCRIPT_DIR/release_docker_resources.py" emit-argv0 \
                "$DCENT_CAPSULE_INVOCATION_STAGE"
    )
    [ "${#DOCKER_SPEC_ARGV[@]}" -ge 3 ] && [ "${DOCKER_SPEC_ARGV[0]}" = docker ] || {
        echo "ERROR: Docker resource helper emitted no valid argv" >&2
        return 1
    }
    # The authenticated helper describes Docker semantics, while the host may
    # expose Docker Desktop through docker.exe (for example WSL without distro
    # integration). Preserve the verified argv and replace only its executable.
    DOCKER_SPEC_ARGV[0]="$DOCKER_BIN"
}
cleanup_build_resources() {
    status=$?
    trap - EXIT INT TERM
    if [ "$CAPSULE_CONTAINER_STARTED" -eq 1 ]; then
        observed_container="$("$DOCKER_BIN" container inspect --format '{{.Name}}|{{index .Config.Labels "org.dcentral.dcentos.release-invocation-id"}}|{{index .Config.Labels "org.dcentral.dcentos.resource-role"}}' "$CAPSULE_CONTAINER_NAME" 2>/dev/null || true)"
        expected_container="/$CAPSULE_CONTAINER_NAME|$CAPSULE_INVOCATION_ID|cargo-build"
        if [ -n "$observed_container" ]; then
            if [ "$observed_container" = "$expected_container" ]; then
                "$DOCKER_BIN" container rm -f "$CAPSULE_CONTAINER_NAME" >/dev/null 2>&1 || {
                    echo "ERROR: failed to remove invocation-owned Cargo container: $CAPSULE_CONTAINER_NAME" >&2
                    [ "$status" -ne 0 ] || status=1
                }
            else
                echo "ERROR: refusing to remove changed Cargo container: $CAPSULE_CONTAINER_NAME" >&2
                [ "$status" -ne 0 ] || status=1
            fi
        fi
    fi
    if [ "$BUILDER_TAG_CREATED" -eq 1 ]; then
        observed_image="$("$DOCKER_BIN" image inspect --format '{{.Id}}|{{index .Config.Labels "org.dcentral.dcentos.builder-recipe-sha256"}}|{{index .Config.Labels "org.dcentral.dcentos.builder-base-reference"}}' "$CAPSULE_BUILDER_TAG" 2>/dev/null || true)"
        observed_image_id="${observed_image%%|*}"
        observed_image_labels="${observed_image#*|}"
        observed_image_recipe="${observed_image_labels%%|*}"
        observed_image_base="${observed_image_labels#*|}"
        if [ -z "$observed_image" ]; then
            :
        elif printf '%s\n' "$observed_image_id" | grep -qE '^sha256:[0-9a-f]{64}$' \
            && [ "$observed_image_recipe" = "$CAPSULE_BUILDER_RECIPE_SHA256" ] \
            && [ "$observed_image_base" = "$RUST_BUILDER_BASE" ] \
            && { [ -z "${DOCKER_IMAGE_ID:-}" ] || [ "$observed_image_id" = "$DOCKER_IMAGE_ID" ]; }; then
            retained_recipe_id="$("$DOCKER_BIN" image inspect --format '{{.Id}}' "$CAPSULE_BUILDER_RECIPE_TAG" 2>/dev/null || true)"
            if [ "$retained_recipe_id" = "$observed_image_id" ]; then
                "$DOCKER_BIN" image rm "$CAPSULE_BUILDER_TAG" >/dev/null 2>&1 || {
                    echo "ERROR: failed to remove invocation-owned builder tag: $CAPSULE_BUILDER_TAG" >&2
                    [ "$status" -ne 0 ] || status=1
                }
            else
                echo "ERROR: refusing builder-alias removal without its exact recipe tag" >&2
                [ "$status" -ne 0 ] || status=1
            fi
        else
            echo "ERROR: refusing to remove changed invocation builder alias: $CAPSULE_BUILDER_TAG" >&2
            [ "$status" -ne 0 ] || status=1
        fi
    fi
    if [ "$CARGO_VOLUME_CREATED" -eq 1 ]; then
        if CARGO_INSPECT_SPEC="$(python3 "$SCRIPT_DIR/release_docker_resources.py" \
            inspect-spec --role cargo "$DCENT_CAPSULE_INVOCATION_STAGE")" \
            && load_docker_spec_argv "$CARGO_INSPECT_SPEC" \
            && CARGO_INSPECT_JSON="$("${DOCKER_SPEC_ARGV[@]}")" \
            && printf '%s\n' "$CARGO_INSPECT_JSON" \
                | python3 "$SCRIPT_DIR/release_docker_resources.py" verify-inspect \
                    --role cargo "$DCENT_CAPSULE_INVOCATION_STAGE" >/dev/null \
            && CARGO_DESTROY_SPEC="$(printf '%s\n' "$CARGO_INSPECT_JSON" \
                | python3 "$SCRIPT_DIR/release_docker_resources.py" destroy-spec \
                    --role cargo --capability "$CAPSULE_INVOCATION_CAPABILITY" \
                    --empty-or-disposable disposable "$DCENT_CAPSULE_INVOCATION_STAGE")" \
            && load_docker_spec_argv "$CARGO_DESTROY_SPEC" \
            && "${DOCKER_SPEC_ARGV[@]}" >/dev/null; then
            :
        else
            echo "ERROR: helper-authorized Cargo target volume cleanup failed" >&2
            [ "$status" -ne 0 ] || status=1
        fi
    fi
    if [ "$BUILD_INPUT_OWNED" -eq 1 ] \
        && [ -n "$BUILD_INPUT_SNAPSHOT" ] \
        && [ -n "$BUILD_INPUT_DESTROY_TOKEN" ]; then
        python3 "$SCRIPT_DIR/build_input_snapshot.py" destroy \
            --token "$BUILD_INPUT_DESTROY_TOKEN" "$BUILD_INPUT_SNAPSHOT" \
            >/dev/null 2>&1 || {
            echo "ERROR: failed to remove private build-input snapshot: $BUILD_INPUT_STAGE" >&2
            [ "$status" -ne 0 ] || status=1
        }
    fi
    if [ -n "$S19K_POST_SOURCE_SNAPSHOT" ]; then
        rm -f -- "$S19K_POST_SOURCE_SNAPSHOT" || {
            echo "ERROR: failed to remove owned S19k post-build source snapshot: $S19K_POST_SOURCE_SNAPSHOT" >&2
            [ "$status" -ne 0 ] || status=1
        }
    fi
    exit "$status"
}
trap cleanup_build_resources EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Resolve the OTA key independently of the stock-firmware manifest pin. This
# runs before Docker/Cargo and the same value is observed inside the compiler
# container and checked against the actual retained ELF identity below.
if [ "$CAPSULE_MODE" -eq 1 ]; then
    [ -n "${DCENT_RELEASE_PUBKEY_FILE:-}" ] || {
        echo "ERROR: release compilation requires an independently trusted public-key file" >&2
        exit 1
    }
    OTA_KEY_ARGS=(--pubkey "$(normalize_shell_path "$DCENT_RELEASE_PUBKEY_FILE")")
    if [ -n "${DCENT_OTA_PUBLIC_KEY_HEX+set}" ]; then
        OTA_KEY_ARGS+=(--expected "$DCENT_OTA_PUBLIC_KEY_HEX")
    fi
    DCENT_OTA_PUBLIC_KEY_HEX="$(python3 "$SCRIPT_DIR/release_build_identity.py" key "${OTA_KEY_ARGS[@]}")"
    export DCENT_OTA_PUBLIC_KEY_HEX
    python3 "$SCRIPT_DIR/release_dashboard.py" preflight --source "$SCRIPT_DIR/../dashboard"
    python3 "$SCRIPT_DIR/release_native_sd.py" preflight
fi
# -------- Release manifest-pin fail-fast (BUG-2, 2026-07-09) --------
# Two-step release contract: DCENT_MANIFEST_PUBLIC_KEY_HEX must be exported
# for BOTH build steps (this cross-compile AND the build_in_docker.sh package
# build). If it is exported only for the package build, the binary built here
# bakes an EMPTY pin and build_in_docker.sh fails deep in Phase 5 with
# "the prebuilt dcentrald binary does NOT contain that hex string" — hours
# late. Fail fast HERE, before the long cargo build. Dev/lab builds (no
# release env indicated, or DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1) are unchanged.
# A pin that is exported but EMPTY is release intent with a broken value —
# treat it as a release context rather than silently baking an unpinned
# binary (option_env! would embed nothing and the fallback is fail-open).
if [ -n "$RELEASE_CONTEXT" ] && [ -z "${DCENT_MANIFEST_PUBLIC_KEY_HEX:-}" ] \
    && ! _is_truthy "${DCENT_ALLOW_UNSIGNED_SYSUPGRADE:-0}"; then
    echo "" >&2
    echo "ERROR: release context indicated ($RELEASE_CONTEXT) but" >&2
    echo "       DCENT_MANIFEST_PUBLIC_KEY_HEX is empty." >&2
    echo "" >&2
    echo "  A release dcentrald bakes the stock-Bitmain manifest pubkey pin at" >&2
    echo "  COMPILE time (option_env!). Building now would produce an UNPINNED" >&2
    echo "  (fail-open) release binary, so the release capsule refuses it." >&2
    echo "  Export the pin before the one admitted S9 entry point:" >&2
    echo "      export DCENT_MANIFEST_PUBLIC_KEY_HEX=<hex64>" >&2
    echo "      make release RELEASE_TARGET=s9" >&2
    echo "  Other targets remain blocked until their capsule port lands." >&2
    echo "  Dev/lab escape hatch (never for release packages):" >&2
    echo "      DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1" >&2
    exit 1
fi
if [ -n "${DCENT_MANIFEST_PUBLIC_KEY_HEX:-}" ]; then
    # Same shape gate as build_in_docker.sh: 64 hex chars = raw 32-byte
    # ed25519 verifying key. A typo here would otherwise surface only at the
    # build_in_docker.sh Phase-5 strings check, after the full cargo build.
    if ! printf '%s' "$DCENT_MANIFEST_PUBLIC_KEY_HEX" | grep -qE '^[0-9a-f]{64}$'; then
        echo "ERROR: DCENT_MANIFEST_PUBLIC_KEY_HEX must be exactly 64 lowercase hex chars" >&2
        echo "       (raw 32-byte ed25519 verifying key). Got length ${#DCENT_MANIFEST_PUBLIC_KEY_HEX}." >&2
        exit 1
    fi
fi

# The default is the same immutable linux/amd64 Rust manifest used by the
# canonical workspace test image. Callers may replace it only with another
# digest-pinned image in release context.
RUST_BUILDER_BASE="${DCENT_RUST_BUILDER_BASE:-rust@sha256:3f6e6f8d8725a65a2db964bb828850f888d430c68784d661f753144e5d787207}"
if [ -n "$RELEASE_CONTEXT" ] \
    && ! _is_truthy "${DCENT_ALLOW_UNSIGNED_SYSUPGRADE:-0}" \
    && ! printf '%s\n' "$RUST_BUILDER_BASE" \
        | grep -qE '^([^/@]+/)*[^/@]+@sha256:[0-9a-f]{64}$'; then
    echo "ERROR: release cross-builds require DCENT_RUST_BUILDER_BASE=<image>@sha256:<64-hex>" >&2
    echo "       mutable Docker tags are development-only" >&2
    exit 1
fi
if [ "$TARGET" = "s19k-tmp" ] \
    && ! printf '%s\n' "$RUST_BUILDER_BASE" \
        | grep -qE '^([^/@]+/)*[^/@]+@sha256:[0-9a-f]{64}$'; then
    echo "ERROR: s19k-tmp requires DCENT_RUST_BUILDER_BASE=<image>@sha256:<64-hex>" >&2
    echo "       an experimental handoff still requires an immutable builder base" >&2
    exit 1
fi

# Map board name to Rust target triple and one C-toolchain ABI contract.
MUSL_ZIG_BUILDER=0
ZIG_CC_FLAGS=""
ZIG_VERSION="0.13.0"
ZIG_ARCHIVE_SHA256="d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea"
BUILDER_PACKAGE_RESOLUTION="apt-bookworm-live-not-reconstructibly-pinned"
TARGET_OUTPUT_PREFIX="target"
PATH_REMAP_FLAGS=""
# rustc applies the last matching --remap-path-prefix.  Keep the broad source
# mapping first so the later, more-specific normal target path wins; the
# capsule target path is disjoint and maps to the same stable build prefix.
# Carry all three flags in either build layout so compile-env evidence proves
# one canonical S19k /tmp path contract rather than the directory used today.
S19K_TMP_PATH_REMAP_FLAGS="--remap-path-prefix=/src=/dcent-source --remap-path-prefix=/src/target/s19k-tmp=/dcent-build --remap-path-prefix=/cargo-target=/dcent-build"
case "$TARGET" in
    zynq)
        # Canonical Zynq target per root  is musleabihf (static
        # musl libc — BraiinsOS rootfs is musl, glibc binaries fail
        # "not found" because the dynamic linker /lib/ld-linux-armhf.so.3
        # doesn't exist on bosminer's rootfs). musl-targeted Rust statically
        # links and runs on any Linux ARM kernel.
        TRIPLE="armv7-unknown-linux-musleabihf"
        CROSS_PKG=""
        CROSS_LINKER="rust-lld"
        CROSS_CC="/usr/local/bin/zig-cc-target-musl"
        CROSS_AR="/usr/local/bin/zig-ar"
        MUSL_ZIG_BUILDER=1
        ZIG_CC_FLAGS="-target arm-linux-musleabihf -mcpu=cortex_a9 -mfloat-abi=hard -mfpu=vfpv3"
        BUILDER_PACKAGE_RESOLUTION="official-zig-0.13.0-sha256-d45312e6"
        ARCH_FLAGS="-C target-cpu=cortex-a9 -C target-feature=+crt-static"
        echo "Building for Zynq (S9/S17/S19) — ARMv7-A Cortex-A9 (musl, static)"
        ;;
    s19k-tmp)
        # Track-1 is a userspace handoff into the held Braiins environment,
        # not the persistent DCENT_OS rootfs. Retained .88 runs prove that
        # ELF32 ARM EABI5 hard-float, static-musl binaries execute and reach
        # accepted shares on the A113D. Keep this compatibility artifact in
        # its own Cargo target directory so a later Zynq build cannot silently
        # replace it. Persistent am3-s19kpro images remain AArch64.
        TRIPLE="armv7-unknown-linux-musleabihf"
        CROSS_PKG=""
        CROSS_LINKER="rust-lld"
        CROSS_CC="/usr/local/bin/zig-cc-target-musl"
        CROSS_AR="/usr/local/bin/zig-ar"
        MUSL_ZIG_BUILDER=1
        # Stay generic ARMv7, matching the retained `.88` build instructions
        # and `.cargo/config.toml`. The logs prove the artifact ABI, not a
        # Cortex-specific optimization profile, so do not invent one here.
        ZIG_CC_FLAGS="-target arm-linux-musleabihf"
        BUILDER_PACKAGE_RESOLUTION="official-zig-0.13.0-sha256-d45312e6"
        ARCH_FLAGS="-C target-feature=+crt-static"
        TARGET_OUTPUT_PREFIX="target/s19k-tmp"
        PATH_REMAP_FLAGS="$S19K_TMP_PATH_REMAP_FLAGS"
        echo "Building S19k Braiins /tmp handoff - ARMv7 hard-float on A113D (musl, static)"
        ;;
    amlogic)
        # Amlogic A113D (S19j Pro AML / S19XP / S21 / S21 Pro) = AArch64
        # Cortex-A53, static musl (matches build_in_docker.sh and the
        # br2_external am3-aml post-build.sh target paths). A glibc dynamic
        # binary fails on the musl Buildroot rootfs (no dynamic linker) and
        # is not found by the post-build scripts (they read the musl path).
        TRIPLE="aarch64-unknown-linux-musl"
        CROSS_PKG=""
        CROSS_LINKER="rust-lld"
        CROSS_CC="/usr/local/bin/zig-cc-target-musl"
        CROSS_AR="/usr/local/bin/zig-ar"
        MUSL_ZIG_BUILDER=1
        ZIG_CC_FLAGS="-target aarch64-linux-musl -mcpu=cortex_a53"
        BUILDER_PACKAGE_RESOLUTION="official-zig-0.13.0-sha256-d45312e6"
        ARCH_FLAGS="-C target-cpu=cortex-a53 -C target-feature=+crt-static"
        echo "Building for Amlogic A113D (S19XP/S21+) — AArch64 Cortex-A53 (musl, static)"
        ;;
    beaglebone)
        TRIPLE="armv7-unknown-linux-gnueabihf"
        CROSS_PKG="gcc-arm-linux-gnueabihf"
        CROSS_LINKER="arm-linux-gnueabihf-gcc"
        CROSS_CC="arm-linux-gnueabihf-gcc"
        CROSS_AR="arm-linux-gnueabihf-ar"
        ARCH_FLAGS="-C target-cpu=cortex-a8"
        echo "Building for BeagleBone AM335x (S19j) — ARMv7-A Cortex-A8"
        ;;
    native)
        echo "Building for host (native)"
        cd "$DCENTRALD_DIR"
        cargo +1.90.0 build --release --locked
        NATIVE_TRIPLE="$(rustc +1.90.0 -vV | sed -n 's/^host: //p')"
        NATIVE_METADATA="$DCENTRALD_DIR/target/release-inventory/${NATIVE_TRIPLE}.metadata.json"
        NATIVE_TOOLCHAIN="$DCENTRALD_DIR/target/release-inventory/${NATIVE_TRIPLE}.toolchain.txt"
        NATIVE_COMPILE_ENV="$DCENTRALD_DIR/target/release-inventory/${NATIVE_TRIPLE}.compile-env.txt"
        mkdir -p "$(dirname "$NATIVE_METADATA")"
        cargo +1.90.0 metadata --locked --offline --filter-platform "$NATIVE_TRIPLE" \
            --format-version 1 > "$NATIVE_METADATA"
        {
            rustc +1.90.0 -vV
            cargo +1.90.0 -V
        } > "$NATIVE_TOOLCHAIN"
        {
            printf '%s\n' 'CARGO_BUILD_PROFILE=release'
            printf '%s\n' 'DCENT_BUILDER_KIND=native-host'
            printf '%s\n' 'DCENT_BUILDER_BASE_REFERENCE=not-containerized'
            printf '%s\n' 'DCENT_BUILDER_IMAGE_ID=not-applicable'
            printf '%s\n' 'DCENT_BUILDER_PACKAGE_RESOLUTION=host-toolchain-not-attested'
            env | LC_ALL=C sort | grep -E \
                '^(AR|CC|CFLAGS|CXXFLAGS|RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|RUSTC|RUSTC_WRAPPER|AR_[^=]*|CC_[^=]*|CARGO_BUILD_[^=]*|CARGO_PROFILE_RELEASE_[^=]*|CARGO_TARGET_[^=]*|DCENT_MANIFEST_[^=]*)=' \
                || true
        } | LC_ALL=C sort -u > "$NATIVE_COMPILE_ENV"
        emit_build_receipts \
            "$NATIVE_TRIPLE" native "$DCENTRALD_DIR/target/release" "$NATIVE_METADATA" \
            "$NATIVE_TOOLCHAIN" "$NATIVE_COMPILE_ENV"
        echo ""
        echo "Binary: $DCENTRALD_DIR/target/release/dcentrald"
        exit 0
        ;;
    *)
        echo "Unknown target: $TARGET"
        echo "Valid targets: zynq, s19k-tmp, amlogic, beaglebone, native"
        exit 1
        ;;
esac

echo "Target triple: $TRIPLE"
echo ""

if [ "$CAPSULE_MODE" -eq 1 ]; then
    CAPSULE_BUILDER_RECIPE_SHA256="$(
        python3 - "$SCRIPT_DIR/build-dcentrald.sh" "$TARGET" "$TRIPLE" \
            "$RUST_BUILDER_BASE" "$ZIG_VERSION" "$ZIG_ARCHIVE_SHA256" \
            "$BUILDER_PACKAGE_RESOLUTION" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

script, target, triple, base, zig_version, zig_sha256, packages = sys.argv[1:]
recipe = {
    "builder_base_reference": base,
    "builder_driver_sha256": hashlib.sha256(Path(script).read_bytes()).hexdigest(),
    "builder_package_resolution": packages,
    "target": target,
    "target_triple": triple,
    "zig_archive_sha256": zig_sha256,
    "zig_version": zig_version,
}
raw = (json.dumps(recipe, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
print(hashlib.sha256(raw).hexdigest())
PY
    )"
    printf '%s\n' "$CAPSULE_BUILDER_RECIPE_SHA256" \
        | grep -qE '^[0-9a-f]{64}$' || {
        echo "ERROR: failed to derive the immutable Cargo builder recipe" >&2
        exit 1
    }
    CAPSULE_BUILDER_RECIPE_TAG="dcentos-cargo-builder:${CAPSULE_BUILDER_RECIPE_SHA256}"
fi

# Development uses the historical cached tag.  Capsule builds reject any
# pre-existing invocation alias and allocate an invocation-labeled Cargo
# volume. Independent invocations reuse one recipe-qualified immutable builder
# image ID; invocation identity lives on the alias, container and resources,
# not in the image configuration.
if [ "$CAPSULE_MODE" -eq 1 ]; then
    if "$DOCKER_BIN" image inspect "$CAPSULE_BUILDER_TAG" >/dev/null 2>&1; then
        echo "ERROR: invocation builder tag already exists: $CAPSULE_BUILDER_TAG" >&2
        exit 1
    fi
    CARGO_INSPECT_SPEC="$(python3 "$SCRIPT_DIR/release_docker_resources.py" \
        inspect-spec --role cargo "$DCENT_CAPSULE_INVOCATION_STAGE")"
    load_docker_spec_argv "$CARGO_INSPECT_SPEC"
    if "${DOCKER_SPEC_ARGV[@]}" >/dev/null 2>&1; then
        echo "ERROR: invocation Cargo target volume already exists: $CAPSULE_CARGO_VOLUME" >&2
        exit 1
    fi
    if "$DOCKER_BIN" container inspect "$CAPSULE_CONTAINER_NAME" >/dev/null 2>&1; then
        echo "ERROR: invocation Cargo container already exists: $CAPSULE_CONTAINER_NAME" >&2
        exit 1
    fi
    CARGO_CREATE_SPEC="$(python3 "$SCRIPT_DIR/release_docker_resources.py" \
        create-spec --role cargo "$DCENT_CAPSULE_INVOCATION_STAGE")"
    load_docker_spec_argv "$CARGO_CREATE_SPEC"
    created_volume="$("${DOCKER_SPEC_ARGV[@]}")"
    [ "$created_volume" = "$CAPSULE_CARGO_VOLUME" ] || {
        echo "ERROR: Docker created an unexpected Cargo volume: $created_volume" >&2
        exit 1
    }
    CARGO_VOLUME_CREATED=1
    load_docker_spec_argv "$CARGO_INSPECT_SPEC"
    CARGO_INSPECT_JSON="$("${DOCKER_SPEC_ARGV[@]}")"
    printf '%s\n' "$CARGO_INSPECT_JSON" \
        | python3 "$SCRIPT_DIR/release_docker_resources.py" verify-inspect \
            --role cargo "$DCENT_CAPSULE_INVOCATION_STAGE" >/dev/null
    retained_builder="$("$DOCKER_BIN" image inspect --format '{{.Id}}|{{index .Config.Labels "org.dcentral.dcentos.builder-recipe-sha256"}}|{{index .Config.Labels "org.dcentral.dcentos.builder-base-reference"}}' "$CAPSULE_BUILDER_RECIPE_TAG" 2>/dev/null || true)"
    if [ -n "$retained_builder" ]; then
        retained_builder_id="${retained_builder%%|*}"
        retained_builder_labels="${retained_builder#*|}"
        retained_builder_recipe="${retained_builder_labels%%|*}"
        retained_builder_base="${retained_builder_labels#*|}"
        if ! printf '%s\n' "$retained_builder_id" | grep -qE '^sha256:[0-9a-f]{64}$' \
            || [ "$retained_builder_recipe" != "$CAPSULE_BUILDER_RECIPE_SHA256" ] \
            || [ "$retained_builder_base" != "$RUST_BUILDER_BASE" ]; then
            echo "ERROR: retained Cargo builder recipe tag is stale or malformed" >&2
            exit 1
        fi
        "$DOCKER_BIN" image tag "$retained_builder_id" "$CAPSULE_BUILDER_TAG"
        DOCKER_IMAGE_ID="$retained_builder_id"
        BUILDER_IMAGE_REUSED=1
        BUILDER_TAG_CREATED=1
    fi
    DOCKER_IMAGE="$CAPSULE_BUILDER_TAG"
else
    DOCKER_IMAGE="dcentrald-cross-${TARGET}"
fi

echo "Building Docker cross-compilation image: $DOCKER_IMAGE"
DOCKER_BUILD_CONTEXT="$DCENTRALD_DIR"
if [ "$DOCKER_BIN" = docker.exe ] && command -v wslpath >/dev/null 2>&1 \
    && grep -qi microsoft /proc/version 2>/dev/null; then
    DOCKER_BUILD_CONTEXT="$(wslpath -w "$DCENTRALD_DIR")"
elif command -v cygpath >/dev/null 2>&1; then
    # Same long-path rule as the mount conversions below: the extended
    # '\\?\' form is rejected by Docker Desktop; forward-slash form is not.
    windows_docker_path() {
        local win_value
        win_value="$(cygpath -w "$1")"
        if [[ "$win_value" == '\\?\'* ]]; then
            win_value="${win_value:4}"
            printf '%s\n' "${win_value//\\//}"
        else
            printf '%s\n' "$win_value"
        fi
    }
    DOCKER_BUILD_CONTEXT="$(windows_docker_path "$DCENTRALD_DIR")"
fi
if [ "$BUILDER_IMAGE_REUSED" -eq 0 ]; then
    [ "$CAPSULE_MODE" -ne 1 ] || BUILDER_TAG_CREATED=1
    "$DOCKER_BIN" build \
        --provenance=false \
        --label "org.dcentral.dcentos.builder-recipe-sha256=${CAPSULE_BUILDER_RECIPE_SHA256:-development}" \
        --label "org.dcentral.dcentos.builder-base-reference=${RUST_BUILDER_BASE}" \
        -t "$DOCKER_IMAGE" -f - "$DOCKER_BUILD_CONTEXT" <<DOCKERFILE
FROM ${RUST_BUILDER_BASE}
RUN if [ "${MUSL_ZIG_BUILDER}" = "1" ]; then \
        archive=/tmp/zig-linux-x86_64-${ZIG_VERSION}.tar.xz; \
        curl --fail --show-error --location \
            https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz \
            --output "\$archive"; \
        echo '${ZIG_ARCHIVE_SHA256}  /tmp/zig-linux-x86_64-${ZIG_VERSION}.tar.xz' \
            | sha256sum --check --strict; \
        mkdir -p /opt/zig; \
        tar -xJf "\$archive" -C /opt/zig --strip-components=1; \
        rm -f "\$archive"; \
        printf '%s\n' \
            '#!/usr/bin/env bash' \
            'set -euo pipefail' \
            'args=()' \
            'for arg in "\$@"; do' \
            '  case "\$arg" in' \
            '    --target=*|-target=*|-march=*|-mcpu=*|-mfpu=*|-mfloat-abi=*) ;;' \
            '    *) args+=("\$arg") ;;' \
            '  esac' \
            'done' \
            'exec /opt/zig/zig cc ${ZIG_CC_FLAGS} "\${args[@]}"' \
            > /usr/local/bin/zig-cc-target-musl; \
        printf '%s\n' '#!/bin/sh' 'exec /opt/zig/zig ar "\$@"' \
            > /usr/local/bin/zig-ar; \
        chmod 0755 /usr/local/bin/zig-cc-target-musl /usr/local/bin/zig-ar; \
        /opt/zig/zig version; \
    else \
        dpkg --add-architecture armhf 2>/dev/null || true; \
        apt-get update; \
        apt-get install -y ${CROSS_PKG}; \
        rm -rf /var/lib/apt/lists/*; \
    fi
RUN rustup target add ${TRIPLE}
RUN if [ "${TARGET}" = "s19k-tmp" ]; then \
        test "\$(rustc -vV | sed -n 's/^release: //p')" = "1.90.0"; \
        cargo -V | grep -qE '^cargo 1\.90\.0 '; \
    fi
# Resolve exactly one host rust-lld rather than an arbitrary search result.
RUN host_triple="\$(rustc -vV | sed -n 's/^host: //p')"; \
    rust_lld="\$(rustc --print sysroot)/lib/rustlib/\${host_triple}/bin/rust-lld"; \
    test -x "\$rust_lld"; \
    ln -s "\$rust_lld" /usr/local/bin/rust-lld; \
    rust-lld -flavor gnu --version
RUN mkdir -p /knowledge-base/firmware-archive
WORKDIR /src
DOCKERFILE
fi

DOCKER_IMAGE_ID="$("$DOCKER_BIN" image inspect --format '{{.Id}}' "$DOCKER_IMAGE")"
if ! printf '%s\n' "$DOCKER_IMAGE_ID" | grep -qE '^sha256:[0-9a-f]{64}$'; then
    echo "ERROR: Docker returned a non-immutable cross-builder image identity: $DOCKER_IMAGE_ID" >&2
    exit 1
fi
if [ "$CAPSULE_MODE" -eq 1 ] && [ "$BUILDER_IMAGE_REUSED" -eq 0 ]; then
    "$DOCKER_BIN" image tag "$DOCKER_IMAGE_ID" "$CAPSULE_BUILDER_RECIPE_TAG"
    retained_builder_id="$("$DOCKER_BIN" image inspect --format '{{.Id}}' "$CAPSULE_BUILDER_RECIPE_TAG")"
    [ "$retained_builder_id" = "$DOCKER_IMAGE_ID" ] || {
        echo "ERROR: immutable Cargo builder recipe tag changed during publication" >&2
        exit 1
    }
fi

echo ""
echo "Cross-compiling dcentrald..."

# Run the build inside Docker
# Mount source as /src, set linker and rustflags via environment
# dcentrald-api depends on `dcent-schema` via `path = "../../../dcent-schema"`,
# which from `/src/dcentrald-api/Cargo.toml` resolves to `/dcent-schema`.
# Mount the sibling workspace member at that container-side absolute path.
DCENT_SCHEMA_DIR="$(cd "$DCENTRALD_DIR/../dcent-schema" && pwd)"

# dcentrald-api/src/routes/restore_to_stock.rs uses include_str!/include_bytes!
# with `"../../../../../../"`,
# which from /src/dcentrald-api/src/routes/ resolves to /
# Mount the repo-root knowledge-base/ tree at that container-side absolute path.
STOCK_MANIFEST="$KNOWLEDGE_BASE_DIR/firmware-archive/stock-bitmain-manifest.json"
STOCK_MANIFEST_SIGNATURE="$KNOWLEDGE_BASE_DIR/firmware-archive/stock-bitmain-manifest.json.sig"
for required_manifest_input in "$STOCK_MANIFEST" "$STOCK_MANIFEST_SIGNATURE"; do
    [ -f "$required_manifest_input" ] || {
        echo "ERROR: required tracked Cargo input is missing: $required_manifest_input" >&2
        exit 1
    }
done

if [ "$TARGET" = "s19k-tmp" ]; then
    [ -f "$S19K_TMP_BUILD_VERIFIER" ] || {
        echo "ERROR: S19k build-artifact verifier is missing: $S19K_TMP_BUILD_VERIFIER" >&2
        exit 1
    }
    if [ "$CAPSULE_MODE" -eq 1 ]; then
        S19K_ARTIFACT_ROOT="$CAPSULE_RESULT_ROOT_SHELL"
    else
        S19K_ARTIFACT_ROOT="$DCENTRALD_DIR"
    fi
    S19K_INVENTORY_DIR="$S19K_ARTIFACT_ROOT/$TARGET_OUTPUT_PREFIX/release-inventory"
    mkdir -p "$S19K_INVENTORY_DIR"
    S19K_SOURCE_RECEIPT="$S19K_INVENTORY_DIR/s19k-tmp.source.json"
    S19K_TMP_BUILD_RECEIPT="$S19K_INVENTORY_DIR/s19k-tmp.build.json"
    S19K_BUILD_OBSERVATION_ID="$(python3 "$S19K_TMP_BUILD_VERIFIER" new-observation)"
    S19K_POST_SOURCE_SNAPSHOT="$(mktemp "${TMPDIR:-/tmp}/dcentos-s19k-source-after.XXXXXX.json")"
    python3 "$S19K_TMP_BUILD_VERIFIER" source-snapshot \
        --repo-root "$REPO_ROOT" \
        --dcentrald-root "$DCENTRALD_DIR" \
        --dcent-schema-root "$DCENT_SCHEMA_DIR" \
        --stock-manifest "$STOCK_MANIFEST" \
        --stock-signature "$STOCK_MANIFEST_SIGNATURE" \
        --build-script "$SCRIPT_DIR/build-dcentrald.sh" \
        --verifier "$S19K_TMP_BUILD_VERIFIER" \
        --output "$S19K_SOURCE_RECEIPT"
fi

# Cargo per-target env var name forms for the selected triple:
#   - upper/underscore for CARGO_TARGET_<TRIPLE>_{LINKER,RUSTFLAGS}
#   - lower/underscore for cc-rs's CC_<triple>/AR_<triple>
TRIPLE_UPPER="$(echo "$TRIPLE" | tr '[:lower:]-' '[:upper:]_')"
TRIPLE_LOWER="$(echo "$TRIPLE" | tr '-' '_')"

if [ "$DOCKER_BIN" = docker.exe ] && command -v wslpath >/dev/null 2>&1 \
    && grep -qi microsoft /proc/version 2>/dev/null; then
    DOCKER_DCENTRALD_DIR="$(wslpath -w "$DCENTRALD_DIR")"
    DOCKER_DCENT_SCHEMA_DIR="$(wslpath -w "$DCENT_SCHEMA_DIR")"
    DOCKER_STOCK_MANIFEST="$(wslpath -w "$STOCK_MANIFEST")"
    DOCKER_STOCK_MANIFEST_SIGNATURE="$(wslpath -w "$STOCK_MANIFEST_SIGNATURE")"
    if [ "$CAPSULE_MODE" -eq 1 ]; then
        DOCKER_RESULT_ROOT="$(wslpath -w "$CAPSULE_RESULT_ROOT_SHELL")"
    fi
elif command -v cygpath >/dev/null 2>&1; then
    # Windows long-path plumbing (2026-09-01, Lane H): cygpath -w emits the
    # extended-length '\\?\' prefix once a path exceeds MAX_PATH, and Docker
    # Desktop rejects that literal prefix as a bind-mount source ("is not a
    # valid Windows path" — observed on the capsule RESULT_ROOT stage, ~295
    # chars). Docker's Go runtime handles long forward-slash Windows paths
    # natively (verified byte-identical round-trip), so re-emit the forward-
    # slash form whenever the extended prefix appears. Short paths pass
    # through unchanged (native backslash form).
    windows_docker_path() {
        local win_value
        win_value="$(cygpath -w "$1")"
        if [[ "$win_value" == '\\?\'* ]]; then
            win_value="${win_value:4}"
            printf '%s\n' "${win_value//\\//}"
        else
            printf '%s\n' "$win_value"
        fi
    }
    DOCKER_DCENTRALD_DIR="$(windows_docker_path "$DCENTRALD_DIR")"
    DOCKER_DCENT_SCHEMA_DIR="$(windows_docker_path "$DCENT_SCHEMA_DIR")"
    DOCKER_STOCK_MANIFEST="$(windows_docker_path "$STOCK_MANIFEST")"
    DOCKER_STOCK_MANIFEST_SIGNATURE="$(windows_docker_path "$STOCK_MANIFEST_SIGNATURE")"
    if [ "$CAPSULE_MODE" -eq 1 ]; then
        DOCKER_RESULT_ROOT="$(windows_docker_path "$CAPSULE_RESULT_ROOT_SHELL")"
    fi
else
    DOCKER_DCENTRALD_DIR="$DCENTRALD_DIR"
    DOCKER_DCENT_SCHEMA_DIR="$DCENT_SCHEMA_DIR"
    DOCKER_STOCK_MANIFEST="$STOCK_MANIFEST"
    DOCKER_STOCK_MANIFEST_SIGNATURE="$STOCK_MANIFEST_SIGNATURE"
    if [ "$CAPSULE_MODE" -eq 1 ]; then
        DOCKER_RESULT_ROOT="$CAPSULE_RESULT_ROOT_SHELL"
    fi
fi

# Per-target cross C compiler/archiver for cc-rs (ring/secp256k1 C deps).
DOCKER_ENV_ARGS=(
    -e "CC_${TRIPLE_LOWER}=${CROSS_CC}"
    -e "AR_${TRIPLE_LOWER}=${CROSS_AR}"
)
# For static musl targets we link with rust-lld; mirror that into the
# per-target RUSTFLAGS so the linker override is unambiguous. Skipped for
# gcc-linked targets (e.g. beaglebone) so their CARGO_TARGET_<T>_LINKER wins.
if [ "$CROSS_LINKER" = "rust-lld" ]; then
    DOCKER_ENV_ARGS+=( -e "CARGO_TARGET_${TRIPLE_UPPER}_RUSTFLAGS=-C linker=rust-lld" )
fi

if [ "$CAPSULE_MODE" -eq 1 ]; then
    DOCKER_MOUNT_ARGS=(
        -v "${DOCKER_DCENTRALD_DIR}:/src:ro"
        -v "${DOCKER_DCENT_SCHEMA_DIR}:/dcent-schema:ro"
    )
else
    DOCKER_MOUNT_ARGS=(
        -v "${DOCKER_DCENTRALD_DIR}:/src"
        -v "${DOCKER_DCENT_SCHEMA_DIR}:/dcent-schema"
    )
fi
DOCKER_MOUNT_ARGS+=(
    -v "${DOCKER_STOCK_MANIFEST}:/knowledge-base/firmware-archive/stock-bitmain-manifest.json:ro"
    -v "${DOCKER_STOCK_MANIFEST_SIGNATURE}:/knowledge-base/firmware-archive/stock-bitmain-manifest.json.sig:ro"
)
if [ "$CAPSULE_MODE" -eq 1 ]; then
    DOCKER_MOUNT_ARGS+=(
        -v "${CAPSULE_CARGO_VOLUME}:/cargo-target"
        -v "${DOCKER_RESULT_ROOT}:/results"
    )
    DOCKER_ENV_ARGS+=(
        -e "CARGO_TARGET_DIR=/cargo-target"
        -e "DCENT_CAPSULE_MODE=1"
    )
    DOCKER_RUN_IDENTITY_ARGS=(
        --name "$CAPSULE_CONTAINER_NAME"
        --label "org.dcentral.dcentos.release-invocation-id=$CAPSULE_INVOCATION_ID"
        --label "org.dcentral.dcentos.resource-role=cargo-build"
    )
    CAPSULE_CONTAINER_STARTED=1
else
    DOCKER_ENV_ARGS+=( -e "DCENT_CAPSULE_MODE=0" )
    if [ "$TARGET_OUTPUT_PREFIX" != "target" ]; then
        DOCKER_ENV_ARGS+=(
            -e "CARGO_TARGET_DIR=/src/$TARGET_OUTPUT_PREFIX"
            -e "DCENT_DEVELOPMENT_INVENTORY_DIR=/src/$TARGET_OUTPUT_PREFIX/release-inventory"
        )
    fi
    DOCKER_RUN_IDENTITY_ARGS=()
fi
DOCKER_ENV_ARGS+=( -e "DCENT_TARGET_OUTPUT_PREFIX=${TARGET_OUTPUT_PREFIX}" )
if [ -n "${DCENT_UPDATE_FEED_BASE_URL:-}" ]; then
    DOCKER_ENV_ARGS+=( -e "DCENT_UPDATE_FEED_BASE_URL=${DCENT_UPDATE_FEED_BASE_URL}" )
fi

BUILD_RUSTFLAGS="-C link-arg=-s ${ARCH_FLAGS}"
if [ -n "$PATH_REMAP_FLAGS" ]; then
    BUILD_RUSTFLAGS="$BUILD_RUSTFLAGS $PATH_REMAP_FLAGS"
fi

MSYS_NO_PATHCONV=1 "$DOCKER_BIN" run --rm \
    "${DOCKER_RUN_IDENTITY_ARGS[@]}" \
    "${DOCKER_MOUNT_ARGS[@]}" \
    -e "CARGO_TARGET_${TRIPLE_UPPER}_LINKER=${CROSS_LINKER}" \
    "${DOCKER_ENV_ARGS[@]}" \
    -e "CARGO_BUILD_JOBS=2" \
    -e "CARGO_INCREMENTAL=0" \
    -e "RUSTFLAGS=${BUILD_RUSTFLAGS}" \
    -e "DCENT_MANIFEST_PUBLIC_KEY_HEX=${DCENT_MANIFEST_PUBLIC_KEY_HEX:-}" \
    -e "DCENT_MANIFEST_KEY_ID=${DCENT_MANIFEST_KEY_ID:-}" \
    -e "DCENT_OTA_PUBLIC_KEY_HEX=${DCENT_OTA_PUBLIC_KEY_HEX:-}" \
    -e "DCENT_BUILDER_KIND=docker-cross" \
    -e "DCENT_BUILDER_BASE_REFERENCE=${RUST_BUILDER_BASE}" \
    -e "DCENT_BUILDER_IMAGE_ID=${DOCKER_IMAGE_ID}" \
    -e "DCENT_BUILDER_PACKAGE_RESOLUTION=${BUILDER_PACKAGE_RESOLUTION}" \
    -e "DCENT_ZIG_ARCHIVE_SHA256=${ZIG_ARCHIVE_SHA256}" \
    -e "DCENT_METADATA_TARGET=${TRIPLE}" \
    "$DOCKER_IMAGE_ID" \
    bash -c '
        set -e
        # Cargo gives CARGO_ENCODED_RUSTFLAGS precedence over RUSTFLAGS.  A
        # builder-image value would bypass the canonical path-remap contract
        # while leaving a misleading ordinary RUSTFLAGS line in the receipt.
        unset CARGO_ENCODED_RUSTFLAGS
        # Fetch the complete locked graph (including dev-only packages used by
        # Cargo metadata) before entering the offline build/receipt phase.
        cargo fetch --locked
        cargo build --release --locked --offline --target "$DCENT_METADATA_TARGET"
        if [ "$DCENT_CAPSULE_MODE" = 1 ]; then
            release_dir="/results/${DCENT_TARGET_OUTPUT_PREFIX}/${DCENT_METADATA_TARGET}/release"
            inventory_dir="/results/${DCENT_TARGET_OUTPUT_PREFIX}/release-inventory"
            mkdir -p "$release_dir" "$inventory_dir"
            for binary in dcentrald dcentos-init dcentos-discovery; do
                install -m 0755 \
                    "/cargo-target/${DCENT_METADATA_TARGET}/release/${binary}" \
                    "$release_dir/${binary}"
            done
        else
            inventory_dir="${DCENT_DEVELOPMENT_INVENTORY_DIR:-/src/target/release-inventory}"
            mkdir -p "$inventory_dir"
            # Cargo normally hard-links the top-level executable to release/deps.
            # The receipt reader deliberately admits only a single-link frozen
            # pathname, so replace just the S19k handoff executable with an
            # independently allocated inode after compilation.
            if [ "$DCENT_TARGET_OUTPUT_PREFIX" = target/s19k-tmp ]; then
                s19k_binary="/src/${DCENT_TARGET_OUTPUT_PREFIX}/${DCENT_METADATA_TARGET}/release/dcentrald"
                s19k_snapshot="${s19k_binary}.receipt-snapshot.$$"
                install -m 0755 "$s19k_binary" "$s19k_snapshot"
                mv -f "$s19k_snapshot" "$s19k_binary"
            fi
        fi
        cargo metadata --locked --offline --filter-platform "$DCENT_METADATA_TARGET" \
            --format-version 1 \
            > "${inventory_dir}/${DCENT_METADATA_TARGET}.metadata.json"
        {
            rustc -vV
            cargo -V
            printf "%s\n" "builder_base_reference=$DCENT_BUILDER_BASE_REFERENCE"
            printf "%s\n" "builder_image_id=$DCENT_BUILDER_IMAGE_ID"
            printf "%s\n" "builder_package_resolution=$DCENT_BUILDER_PACKAGE_RESOLUTION"
            if [ -x /opt/zig/zig ]; then
                printf "%s\n" "zig_version=$(/opt/zig/zig version)"
                printf "%s\n" "zig_archive_sha256=$DCENT_ZIG_ARCHIVE_SHA256"
            fi
        } > "${inventory_dir}/${DCENT_METADATA_TARGET}.toolchain.txt"
        {
            printf "%s\n" "CARGO_BUILD_PROFILE=release"
            env | LC_ALL=C sort | grep -E \
                "^(AR|CC|CFLAGS|CXXFLAGS|RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_INCREMENTAL|RUSTC|RUSTC_WRAPPER|AR_[^=]*|CC_[^=]*|CARGO_BUILD_[^=]*|CARGO_PROFILE_RELEASE_[^=]*|CARGO_TARGET_[^=]*|DCENT_BUILDER_[^=]*|DCENT_MANIFEST_[^=]*|DCENT_OTA_PUBLIC_KEY_HEX|DCENT_UPDATE_FEED_BASE_URL)=" \
                || true
        } | LC_ALL=C sort -u \
            > "${inventory_dir}/${DCENT_METADATA_TARGET}.compile-env.txt"
    '

if [ "$TARGET" = "s19k-tmp" ]; then
    python3 "$S19K_TMP_BUILD_VERIFIER" source-snapshot \
        --repo-root "$REPO_ROOT" \
        --dcentrald-root "$DCENTRALD_DIR" \
        --dcent-schema-root "$DCENT_SCHEMA_DIR" \
        --stock-manifest "$STOCK_MANIFEST" \
        --stock-signature "$STOCK_MANIFEST_SIGNATURE" \
        --build-script "$SCRIPT_DIR/build-dcentrald.sh" \
        --verifier "$S19K_TMP_BUILD_VERIFIER" \
        --output "$S19K_POST_SOURCE_SNAPSHOT"
    python3 "$S19K_TMP_BUILD_VERIFIER" compare-source-snapshots \
        "$S19K_SOURCE_RECEIPT" "$S19K_POST_SOURCE_SNAPSHOT"
fi

# Check result
if [ "$CAPSULE_MODE" -eq 1 ]; then
    BUILD_RESULT_ROOT="$CAPSULE_RESULT_ROOT_SHELL"
else
    BUILD_RESULT_ROOT="$DCENTRALD_DIR"
fi
BINARY="$BUILD_RESULT_ROOT/$TARGET_OUTPUT_PREFIX/$TRIPLE/release/dcentrald"
if [ -f "$BINARY" ]; then
    RELEASE_DIR="$BUILD_RESULT_ROOT/$TARGET_OUTPUT_PREFIX/$TRIPLE/release"
    METADATA_FILE="$BUILD_RESULT_ROOT/$TARGET_OUTPUT_PREFIX/release-inventory/${TRIPLE}.metadata.json"
    TOOLCHAIN_CONTEXT="$BUILD_RESULT_ROOT/$TARGET_OUTPUT_PREFIX/release-inventory/${TRIPLE}.toolchain.txt"
    COMPILE_ENVIRONMENT="$BUILD_RESULT_ROOT/$TARGET_OUTPUT_PREFIX/release-inventory/${TRIPLE}.compile-env.txt"
    if [ "$CAPSULE_MODE" -eq 1 ]; then
        RELEASE_VERSION="$(cat "$SCRIPT_DIR/../br2_external_dcentos/board/zynq/rootfs-overlay/etc/dcentos-version")"
        python3 "$SCRIPT_DIR/release_build_identity.py" verify \
            --binary "$BINARY" --compile-environment "$COMPILE_ENVIRONMENT" \
            --pubkey "$(normalize_shell_path "$DCENT_RELEASE_PUBKEY_FILE")" \
            --version "$RELEASE_VERSION"
    fi
    if [ "$TARGET" = "s19k-tmp" ]; then
        python3 "$S19K_TMP_BUILD_VERIFIER" verify \
            --dcentrald-root "$DCENTRALD_DIR" \
            --artifact-root "$S19K_ARTIFACT_ROOT" \
            --binary "$BINARY" \
            --source-snapshot "$S19K_SOURCE_RECEIPT" \
            --post-source-snapshot "$S19K_POST_SOURCE_SNAPSHOT" \
            --metadata "$METADATA_FILE" \
            --toolchain-context "$TOOLCHAIN_CONTEXT" \
            --compile-environment "$COMPILE_ENVIRONMENT" \
            --expected-builder-base "$RUST_BUILDER_BASE" \
            --build-observation-id "$S19K_BUILD_OBSERVATION_ID" \
            --receipt "$S19K_TMP_BUILD_RECEIPT"
    else
        emit_build_receipts "$TRIPLE" "$TARGET" "$RELEASE_DIR" "$METADATA_FILE" \
            "$TOOLCHAIN_CONTEXT" "$COMPILE_ENVIRONMENT"
    fi
    if [ "$CAPSULE_MODE" -eq 1 ]; then
        python3 "$SCRIPT_DIR/release_dashboard.py" build \
            --source "$SCRIPT_DIR/../dashboard" \
            --output "$BUILD_RESULT_ROOT/dashboard"
        seal_result_stage() {
            python3 "$SCRIPT_DIR/release_result_stage.py" seal \
                --capability "$DCENT_CAPSULE_RESULT_CAPABILITY" \
                --invocation-stage "$DCENT_CAPSULE_INVOCATION_STAGE" \
                "$DCENT_CAPSULE_RESULT_STAGE"
        }
        if ! seal_output="$(seal_result_stage 2>&1)"; then
            # Native Windows can publish a delayed NTFS metadata transition on
            # the first read of a newly created receipt.  The failed attempt
            # leaves the stage in building state.  Retry only this exact race;
            # the second attempt independently re-walks and re-hashes every
            # byte, while every other seal failure remains immediately fatal.
            case "$seal_output" in
                *"metadata changed while it was hashed"*)
                    seal_output="$(seal_result_stage)" ;;
                *)
                    printf '%s\n' "$seal_output" >&2
                    exit 1 ;;
            esac
        fi
        printf '%s\n' "$seal_output"
    fi
    SIZE=$(ls -lh "$BINARY" | awk '{print $5}')
    echo ""
    if [ "$TARGET" = "s19k-tmp" ]; then
        echo "S19k /tmp artifact admitted for experimental ephemeral handoff."
        echo "Production readiness and two-build reproducibility are NOT proven."
    else
        echo "Build successful!"
    fi
    echo "Binary: $BINARY"
    echo "Size: $SIZE"
    echo "Target: $TRIPLE"
    echo ""
    if [ "$CAPSULE_MODE" -eq 1 ]; then
        echo "Sealed result stage: $CAPSULE_RESULT_STAGE_SHELL"
    elif [ "$TARGET" = "s19k-tmp" ]; then
        echo "Source receipt: $S19K_SOURCE_RECEIPT"
        echo "Build receipt: $S19K_TMP_BUILD_RECEIPT"
        echo "Two-observation byte comparison: python3 $S19K_TMP_BUILD_VERIFIER compare-receipts <first-build-receipt> <second-build-receipt>"
        echo "Phase-0 (zero target contact/mutation): ./scripts/dcentrald_s19k_tmp_deploy.sh --dry-run --expected-artifact-sha256 <sha256> --expected-artifact-bytes <bytes> --known-hosts <known-hosts> --expected-host-key-sha256 SHA256:<fingerprint> <miner-ip> $BINARY ./dcentrald/dcentrald_s19k.toml"
        echo "Stage-only contact (/tmp mutation; no daemon): ./scripts/dcentrald_s19k_tmp_deploy.sh --expected-artifact-sha256 <sha256> --expected-artifact-bytes <bytes> --known-hosts <known-hosts> --expected-host-key-sha256 SHA256:<fingerprint> <miner-ip> $BINARY ./dcentrald/dcentrald_s19k.toml"
    else
        echo "Deploy: scp $BINARY root@<miner-ip>:/usr/bin/dcentrald"
    fi
else
    echo "Build failed — binary not found at $BINARY"
    exit 1
fi
