#!/bin/bash
# Offline fake-Docker proof for build-dcentrald.sh release-capsule mode.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMPDIR_TEST="$(mktemp -d "${TMPDIR:-/tmp}/dcentos cargo capsule.XXXXXX")"
trap 'rm -rf "$TMPDIR_TEST"' EXIT
trap 'printf "cargo capsule fixture failed at line %s\n" "$LINENO" >&2' ERR

SOURCE_REPO="$TMPDIR_TEST/source-repo"
EXTERNAL_REPO="$TMPDIR_TEST/external-inputs"
CONTROL_PARENT="$TMPDIR_TEST/control"
FAKE_BIN="$TMPDIR_TEST/fake-bin"
FAKE_STATE="$TMPDIR_TEST/docker-state"
DOCKER_LOG="$TMPDIR_TEST/docker.log"
FIXTURE_DIR="$TMPDIR_TEST/elf-fixtures"
mkdir -p \
    "$SOURCE_REPO/DCENT_OS_Antminer/scripts" \
    "$SOURCE_REPO/DCENT_OS_Antminer/scripts/lib" \
    "$SOURCE_REPO/DCENT_OS_Antminer/scripts/hw-acceptance" \
    "$SOURCE_REPO/DCENT_OS_Antminer/docs/architecture" \
    "$SOURCE_REPO/DCENT_OS_Antminer/dcentrald" \
    "$SOURCE_REPO/projects/dcent-schema" \
    "$SOURCE_REPO/knowledge-base/firmware-archive" \
    "$EXTERNAL_REPO/DCENT_OS_Antminer/scripts" \
    "$EXTERNAL_REPO/knowledge-base/extractions/s9" \
    "$CONTROL_PARENT" "$FAKE_BIN" "$FAKE_STATE/images" \
    "$FAKE_STATE/volumes" "$FAKE_STATE/containers"

for helper in \
    atomic_publish_file.py durable_file_io.py \
    atomic_publish_directory.py release_set_publication.py \
    build-dcentrald.sh build_input_snapshot.py binary_build_receipt.py \
    release_capsule_lineage.py release_invocation.py release_result_stage.py \
    release_docker_resources.py source_closure.py source_snapshot.py; do
    cp "$SCRIPT_DIR/$helper" "$SOURCE_REPO/DCENT_OS_Antminer/scripts/$helper"
done
cp "$SCRIPT_DIR/lib/release_posture.sh" \
    "$SOURCE_REPO/DCENT_OS_Antminer/scripts/lib/release_posture.sh"
grep -Fq 'from atomic_publish_file import' \
    "$SOURCE_REPO/DCENT_OS_Antminer/scripts/binary_build_receipt.py"
grep -Fq 'from durable_file_io import' \
    "$SOURCE_REPO/DCENT_OS_Antminer/scripts/atomic_publish_file.py"
chmod +x "$SOURCE_REPO/DCENT_OS_Antminer/scripts/build-dcentrald.sh"
printf '%s\n' '[workspace]' > "$SOURCE_REPO/DCENT_OS_Antminer/dcentrald/Cargo.toml"
printf '%s\n' 'snapshot-only dcentrald source' > "$SOURCE_REPO/DCENT_OS_Antminer/dcentrald/source.txt"
printf '%s\n' 'test-sku' > "$SOURCE_REPO/DCENT_OS_Antminer/scripts/hw-acceptance/skus.conf"
printf '%s\n' 'test-matrix' > "$SOURCE_REPO/DCENT_OS_Antminer/docs/architecture/install_matrix.tsv"
printf '%s\n' '{"schema":1,"targets":[]}' \
    > "$SOURCE_REPO/DCENT_OS_Antminer/docs/architecture/hardware_enablement_matrix.json"
printf '%s\n' '[test]' > "$SOURCE_REPO/DCENT_OS_Antminer/dcentrald/dcentrald_s21xp.toml"
printf '%s\n' '#!/bin/sh' \
    > "$SOURCE_REPO/DCENT_OS_Antminer/scripts/s19k_aarch64_compile_check.sh"
printf '%s\n' '# fixture native build verifier' \
    > "$SOURCE_REPO/DCENT_OS_Antminer/scripts/s19k_native_build_verify.py"
printf '%s\n' 'snapshot-only schema source' > "$SOURCE_REPO/projects/dcent-schema/schema.txt"
printf '%s\n' '{}' > "$SOURCE_REPO/knowledge-base/firmware-archive/stock-bitmain-manifest.json"
: > "$SOURCE_REPO/knowledge-base/firmware-archive/stock-bitmain-manifest.json.sig"
printf '%s\n' 'fake authenticated S9 kernel' \
    > "$EXTERNAL_REPO/knowledge-base/extractions/s9/kernel.bin"
S9_KERNEL_SHA="$(sha256sum "$EXTERNAL_REPO/knowledge-base/extractions/s9/kernel.bin" | awk '{print $1}')"
printf '%s  %s\n' "$S9_KERNEL_SHA" \
    'knowledge-base/extractions/s9/kernel.bin' \
    > "$SOURCE_REPO/DCENT_OS_Antminer/scripts/build_inputs.manifest"
cp "$SOURCE_REPO/DCENT_OS_Antminer/scripts/build_inputs.manifest" \
    "$EXTERNAL_REPO/DCENT_OS_Antminer/scripts/build_inputs.manifest"
# The external checkout's mutable manifest is deliberately hostile.  Capsule
# selection authority must come only from the authenticated snapshot root;
# the external root supplies payload bytes and nothing else.
printf '%s\n' 'attacker-controlled manifest must not be opened' \
    > "$EXTERNAL_REPO/DCENT_OS_Antminer/scripts/build_inputs.manifest"

# Keep the real key/ELF, dashboard and native dependency validators in the
# authenticated snapshot. Only the expensive compiler/container and npm
# processes are represented by bounded fixtures; the produced bytes are real.
PYTHONDONTWRITEBYTECODE=1 python3 "$SCRIPT_DIR/cargo_capsule_fixture.py" \
    --source-repo "$SOURCE_REPO" --fixtures "$FIXTURE_DIR" --fake-bin "$FAKE_BIN"
OTA_PUBLIC_KEY_HEX="$(cat "$FIXTURE_DIR/ota-key.hex")"

git -C "$SOURCE_REPO" init -q
git -C "$SOURCE_REPO" config user.email test@example.invalid
git -C "$SOURCE_REPO" config user.name 'Capsule Test'
git -C "$SOURCE_REPO" add .
git -C "$SOURCE_REPO" commit -qm snapshot
SOURCE_COMMIT="$(git -C "$SOURCE_REPO" rev-parse HEAD)"
SNAPSHOT_RESULT="$(python3 "$SCRIPT_DIR/source_snapshot.py" create \
    --repo-root "$SOURCE_REPO" --commit "$SOURCE_COMMIT" \
    --stage-parent "$CONTROL_PARENT")"
SNAPSHOT_DESCRIPTOR="$(printf '%s\n' "$SNAPSHOT_RESULT" \
    | python3 "$SCRIPT_DIR/source_snapshot.py" query-result --field snapshot)"
SNAPSHOT_TREE="$(printf '%s\n' "$SNAPSHOT_RESULT" \
    | python3 "$SCRIPT_DIR/source_snapshot.py" query-result --field tree)"
CARGO_INPUT_RESULT="$(python3 "$SCRIPT_DIR/build_input_snapshot.py" create \
    --repo-root "$EXTERNAL_REPO" \
    --selection-root "$SNAPSHOT_TREE" \
    --build-input-manifest "$SNAPSHOT_TREE/DCENT_OS_Antminer/scripts/build_inputs.manifest" \
    --target cargo-workspace --stage-parent "$CONTROL_PARENT")"
CARGO_BUILD_INPUT_SNAPSHOT="$(printf '%s\n' "$CARGO_INPUT_RESULT" \
    | python3 "$SCRIPT_DIR/build_input_snapshot.py" query-result --field snapshot)"

cat > "$FAKE_BIN/docker" <<'FAKE_DOCKER'
#!/bin/bash
set -euo pipefail
state=${FAKE_DOCKER_STATE:?}
log=${FAKE_DOCKER_LOG:?}
printf '%q ' "$@" >> "$log"
printf '\n' >> "$log"
kind=${1:-}
shift || true
digest="sha256:$(printf '1%.0s' {1..64})"
fake_shell_path() {
    local value=$1
    if [[ "$value" == '\\?\'* ]]; then value="${value:4}"; fi
    case "$value" in
        [A-Za-z]:*|*\\*) cygpath -u "$value" ;;
        *) printf '%s\n' "$value" ;;
    esac
}

if [ "$kind" = image ]; then
    action=$1; shift
    if [ "$action" = inspect ]; then
        format=""; if [ "${1:-}" = --format ]; then format=$2; shift 2; fi
        tag=$1; [ -f "$state/images/$tag" ] || exit 1
        recipe=$(cut -d'|' -f2 "$state/images/$tag")
        base=$(cut -d'|' -f3- "$state/images/$tag")
        if [ "$format" = '{{.Id}}' ]; then
            printf '%s\n' "$digest"
        elif [ -n "$format" ]; then
            printf '%s|%s|%s\n' "$digest" "$recipe" "$base"
        fi
    elif [ "$action" = tag ]; then
        source=$1 target=$2
        record=""
        if [ -f "$state/images/$source" ]; then
            record=$(cat "$state/images/$source")
        elif printf '%s\n' "$source" | grep -qE '^sha256:[0-9a-f]{64}$'; then
            for candidate in "$state"/images/*; do
                [ -f "$candidate" ] || continue
                case "$(cat "$candidate")" in "$source"'|'*) record=$(cat "$candidate"); break;; esac
            done
        fi
        [ -n "$record" ] || exit 1
        printf '%s\n' "$record" > "$state/images/$target"
    elif [ "$action" = rm ]; then rm -f "$state/images/$1"; fi
    exit 0
fi
if [ "$kind" = volume ]; then
    action=$1; shift
    if [ "$action" = inspect ]; then
        format=""; if [ "${1:-}" = --format ]; then format=$2; shift 2; fi
        [ "${1:-}" = -- ] && shift
        name=$1; [ -f "$state/volumes/$name" ] || exit 1
        descriptor=$(cut -d'|' -f1 "$state/volumes/$name")
        invocation=$(cut -d'|' -f2 "$state/volumes/$name")
        role=$(cut -d'|' -f3 "$state/volumes/$name")
        schema=$(cut -d'|' -f4 "$state/volumes/$name")
        if [ -n "$format" ]; then
            printf '%s|%s|%s\n' "$name" "$invocation" "$role"
        else
            printf '[{"CreatedAt":"2026-07-12T12:34:56Z","Driver":"local","Labels":{"org.dcentral.dcentos.release-resource.invocation-descriptor-sha256":"%s","org.dcentral.dcentos.release-resource.invocation-id":"%s","org.dcentral.dcentos.release-resource.role":"%s","org.dcentral.dcentos.release-resource.schema":"%s"},"Mountpoint":"/var/lib/docker/volumes/%s/_data","Name":"%s","Options":null,"Scope":"local"}]\n' \
                "$descriptor" "$invocation" "$role" "$schema" "$name" "$name"
        fi
    elif [ "$action" = create ]; then
        descriptor="" invocation="" role="" schema="" name=""
        while [ $# -gt 0 ]; do
            case "$1" in
                --driver) shift 2 ;;
                --label)
                    case "$2" in
                        org.dcentral.dcentos.release-resource.invocation-descriptor-sha256=*) descriptor=${2#*=};;
                        org.dcentral.dcentos.release-resource.invocation-id=*) invocation=${2#*=};;
                        org.dcentral.dcentos.release-resource.role=*) role=${2#*=};;
                        org.dcentral.dcentos.release-resource.schema=*) schema=${2#*=};;
                    esac
                    shift 2 ;;
                --) shift; name=$1; shift ;;
                *) name=$1; shift ;;
            esac
        done
        printf '%s|%s|%s|%s\n' "$descriptor" "$invocation" "$role" "$schema" > "$state/volumes/$name"
        printf '%s\n' "$name"
    elif [ "$action" = rm ]; then [ "${1:-}" = -- ] && shift; rm -f "$state/volumes/$1"; fi
    exit 0
fi
if [ "$kind" = container ]; then
    action=$1; shift
    if [ "$action" = inspect ]; then
        format=""; if [ "${1:-}" = --format ]; then format=$2; shift 2; fi
        name=$1; [ -f "$state/containers/$name" ] || exit 1
        invocation=$(cut -d'|' -f2 "$state/containers/$name")
        if [ -n "$format" ]; then printf '/%s|%s|cargo-build\n' "$name" "$invocation"; fi
    elif [ "$action" = rm ]; then
        [ "${1:-}" = -f ] && shift
        rm -f "$state/containers/$1"
    fi
    exit 0
fi
if [ "$kind" = build ]; then
    tag=""; recipe=""; base=""; context=""
    while [ $# -gt 0 ]; do
        case "$1" in
            -t) tag=$2; shift 2 ;;
            --label)
                case "$2" in
                    org.dcentral.dcentos.builder-recipe-sha256=*) recipe=${2#*=};;
                    org.dcentral.dcentos.builder-base-reference=*) base=${2#*=};;
                esac
                shift 2 ;;
            *) context=$1; shift ;;
        esac
    done
    cat >/dev/null
    context="$(fake_shell_path "$context")"
    printf '%s\n' "$context" > "$state/observed-build-context"
    printf '%s|%s|%s\n' "$digest" "$recipe" "$base" > "$state/images/$tag"
    exit 0
fi
if [ "$kind" = run ]; then
    name=""; invocation=""; results=""; source_mount=""; schema_mount=""; cargo_mount=""; image=""; capsule_mode=0
    metadata_target="" manifest_public_key_hex="" ota_public_key_hex=""
    # Model conflicting image defaults; only explicit Docker assignments win.
    cargo_jobs=19 cargo_incremental=1
    cargo_jobs_seen=0 cargo_incremental_seen=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --rm) shift ;;
            --name) name=$2; shift 2 ;;
            --label)
                case "$2" in org.dcentral.dcentos.release-invocation-id=*) invocation=${2#*=};; esac
                shift 2 ;;
            -v)
                case "$2" in
                    *:/results) results=${2%:/results};;
                    *:/src:ro) source_mount=${2%:/src:ro};;
                    *:/src) source_mount=${2%:/src};;
                    *:/dcent-schema:ro) schema_mount=${2%:/dcent-schema:ro};;
                    *:/cargo-target) cargo_mount=${2%:/cargo-target};;
                esac
                shift 2 ;;
            -e)
                case "$2" in
                    DCENT_CAPSULE_MODE=*) capsule_mode=${2#*=};;
                    DCENT_METADATA_TARGET=*) metadata_target=${2#*=};;
                    CARGO_BUILD_JOBS=*) cargo_jobs=${2#*=}; cargo_jobs_seen=$((cargo_jobs_seen + 1));;
                    CARGO_INCREMENTAL=*) cargo_incremental=${2#*=}; cargo_incremental_seen=$((cargo_incremental_seen + 1));;
                    DCENT_MANIFEST_PUBLIC_KEY_HEX=*) manifest_public_key_hex=${2#*=};;
                    DCENT_OTA_PUBLIC_KEY_HEX=*) ota_public_key_hex=${2#*=};;
                esac
                shift 2 ;;
            sha256:*) image=$1; shift; break ;;
            *) shift ;;
        esac
    done
    [ "$cargo_jobs_seen" = 1 ] && [ "$cargo_jobs" = 2 ] || { echo "missing exact two-job container assignment" >&2; exit 94; }
    [ "$cargo_incremental_seen" = 1 ] && [ "$cargo_incremental" = 0 ] || { echo "missing explicit incremental-disable assignment" >&2; exit 95; }
    [ "$#" = 3 ] && [ "$1" = bash ] && [ "$2" = -c ] || { echo "unexpected container command" >&2; exit 96; }
    # Extract only the environment filter from the actual passed container body.
    # Never execute that body (it contains real Cargo commands).
    compile_env_filter="$(python3 - "$3" <<'PY_COMPILE_FILTER'
import sys

lines = sys.argv[1].splitlines()
marker = "env | LC_ALL=C sort | grep -E " + chr(92)
matches = []
for index, line in enumerate(lines):
    if line.strip() != marker:
        continue
    quoted = lines[index + 1].strip()
    assert quoted.endswith(chr(92)), "filter lacks line continuation"
    quoted = quoted[:-1].rstrip()
    assert quoted.startswith('"') and quoted.endswith('"'), "filter is not one quoted argument"
    matches.append(quoted[1:-1])
assert len(matches) == 1, "expected one actual Docker compile environment filter"
print(matches[0])
PY_COMPILE_FILTER
)"
    source_mount="$(fake_shell_path "$source_mount")"
    schema_mount="$(fake_shell_path "$schema_mount")"
    results="$(fake_shell_path "$results")"
    [ "$image" = "$digest" ] || { echo 'mutable image execution' >&2; exit 91; }
    [ -n "$source_mount" ] || { echo 'missing source mount' >&2; exit 92; }
    if [ "$capsule_mode" = 0 ]; then
        results=$source_mount
    else
        [ -n "$results" ] || { echo 'missing result mount' >&2; exit 92; }
        [ "$ota_public_key_hex" = "$(cat "$FAKE_ELF_DIR/ota-key.hex")" ] || {
            echo 'missing independently trusted OTA container assignment' >&2; exit 97;
        }
    fi
    printf '%s\n' "$source_mount" > "$state/observed-source-mount"
    printf '%s\n' "$schema_mount" > "$state/observed-schema-mount"
    printf '%s\n' "$cargo_mount" > "$state/observed-cargo-mount"
    printf '%s\n' "$results" > "$state/observed-result-mount"
    if [ -n "$name" ]; then printf '%s|%s\n' "$name" "$invocation" > "$state/containers/$name"; fi
    if [ "${FAKE_DOCKER_SIGNAL_RUN:-0}" = 1 ]; then
        printf '%s\n' "$PPID" > "$state/signal-ready"
        sleep 2
        exit 143
    fi
    if [ "${FAKE_DOCKER_FAIL_RUN:-0}" = 1 ]; then exit 93; fi
    triple=${metadata_target:-armv7-unknown-linux-musleabihf}
    release="$results/target/$triple/release"
    inventory="$results/target/release-inventory"
    mkdir -p "$release" "$inventory"
    for binary in dcentrald dcentos-init dcentos-discovery; do
        cp "$FAKE_ELF_DIR/$triple" "$release/$binary"
        chmod 755 "$release/$binary"
    done
    if [ "${FAKE_DOCKER_BAD_ELF_KEY:-0}" = 1 ]; then
        python3 - "$release/dcentrald" <<'PY_BAD_ELF'
from pathlib import Path
import sys
path = Path(sys.argv[1])
raw = bytearray(path.read_bytes())
profile = b'dcentos-build-identity/v1'.ljust(32, b'\0')
assert raw.count(profile) == 1
raw[raw.index(profile) + 36] ^= 1
path.write_bytes(raw)
PY_BAD_ELF
    fi
    if [ "${FAKE_DOCKER_BAD_OTA_OBSERVATION:-0}" = 1 ]; then
        ota_public_key_hex=$(printf '0%.0s' {1..64})
    fi
    printf '{}\n' > "$inventory/$triple.metadata.json"
    printf 'rustc 1.90.0\ncargo 1.90.0\nbuilder_base_reference=test\nbuilder_image_id=%s\nbuilder_package_resolution=test\n' "$digest" > "$inventory/$triple.toolchain.txt"
    {
        printf 'AR_aarch64_unknown_linux_musl=/usr/local/bin/zig-ar\n'
        printf 'CARGO_BUILD_JOBS=%s\n' "$cargo_jobs"
        printf 'CARGO_BUILD_PROFILE=release\n'
        printf 'CARGO_INCREMENTAL=%s\n' "$cargo_incremental"
        printf 'CARGO_INCREMENTAL_DECOY=1\n'
        printf 'CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld\n'
        printf 'CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS=-C linker=rust-lld\n'
        printf 'CARGO_TARGET_DIR=/cargo-target\n'
        printf 'CC_aarch64_unknown_linux_musl=/usr/local/bin/zig-cc-target-musl\n'
        printf 'DCENT_BUILDER_BASE_REFERENCE=%s\n' "${DCENT_RUST_BUILDER_BASE:?}"
        printf 'DCENT_BUILDER_IMAGE_ID=%s\n' "$digest"
        printf 'DCENT_BUILDER_KIND=docker-cross\n'
        printf 'DCENT_BUILDER_PACKAGE_RESOLUTION=official-zig-0.13.0-sha256-d45312e6\n'
        printf 'DCENT_MANIFEST_KEY_ID=\n'
        printf 'DCENT_MANIFEST_PUBLIC_KEY_HEX=%s\n' "$manifest_public_key_hex"
        printf 'DCENT_OTA_PUBLIC_KEY_HEX=%s\n' "$ota_public_key_hex"
        printf 'RUSTFLAGS=-C link-arg=-s -C target-cpu=cortex-a53 -C target-feature=+crt-static\n'
    } | LC_ALL=C sort | grep -E "$compile_env_filter" > "$inventory/$triple.compile-env.txt"
    if [ -n "$name" ]; then rm -f "$state/containers/$name"; fi
    exit 0
fi
echo "unsupported fake docker invocation: $kind $*" >&2
exit 99
FAKE_DOCKER
chmod +x "$FAKE_BIN/docker"

# Pin the Windows/Git-Bash transport branch as well as exercising every real
# capsule path above with spaces.  On a host that provides cygpath, this exact
# spelling must survive conversion without token splitting.
grep -Fq 'cygpath -u "$path_value"' "$SCRIPT_DIR/build-dcentrald.sh"
if command -v cygpath >/dev/null 2>&1; then
    test "$(cygpath -u 'C:\Capsule Root\result stage')" = '/c/Capsule Root/result stage'
fi
FAKE_CYGPATH_BIN="$TMPDIR_TEST/fake-cygpath"
mkdir -p "$FAKE_CYGPATH_BIN"
cat > "$FAKE_CYGPATH_BIN/cygpath" <<'FAKE_CYGPATH'
#!/bin/bash
set -euo pipefail
[ "$1" = -u ]
case "$2" in
    'C:\Capsule Root\result stage') printf '%s\n' '/c/Capsule Root/result stage' ;;
    *) printf '%s\n' "$2" ;;
esac
FAKE_CYGPATH
chmod +x "$FAKE_CYGPATH_BIN/cygpath"
eval "$(sed -n '/^normalize_shell_path()/,/^}/p' "$SCRIPT_DIR/build-dcentrald.sh")"
test "$(PATH="$FAKE_CYGPATH_BIN:$PATH" normalize_shell_path 'C:\Capsule Root\result stage')" \
    = '/c/Capsule Root/result stage'
unset -f normalize_shell_path

new_capsule() {
    local suffix=$1 invocation_result
    invocation_result="$(python3 "$SCRIPT_DIR/release_invocation.py" create \
        --stage-parent "$CONTROL_PARENT" --name "cargo-$suffix")"
    INVOCATION_STAGE="$(printf '%s\n' "$invocation_result" | python3 "$SCRIPT_DIR/release_invocation.py" query-result --field stage)"
    INVOCATION_ID="$(printf '%s\n' "$invocation_result" | python3 "$SCRIPT_DIR/release_invocation.py" query-result --field invocation_id)"
    CARGO_VOLUME="$(printf '%s\n' "$invocation_result" | python3 "$SCRIPT_DIR/release_invocation.py" query-result --field cargo_volume)"
    local result
    result="$(python3 "$SCRIPT_DIR/release_result_stage.py" create \
        --stage-parent "$CONTROL_PARENT" --invocation-stage "$INVOCATION_STAGE" \
        --result-output "$TMPDIR_TEST/result-stage-$suffix.json")"
    RESULT_STAGE="$(printf '%s\n' "$result" | python3 "$SCRIPT_DIR/release_result_stage.py" query-result --field stage)"
    RESULT_ROOT="$(printf '%s\n' "$result" | python3 "$SCRIPT_DIR/release_result_stage.py" query-result --field result_root)"
    RESULT_CAPABILITY="$(printf '%s\n' "$result" | python3 "$SCRIPT_DIR/release_result_stage.py" query-result --field capability)"
}

run_driver() {
    local target=${1:-zynq}
    env \
        PATH="$FAKE_BIN:$PATH" \
        DCENT_DOCKER_BIN=docker \
        FAKE_DOCKER_STATE="$FAKE_STATE" FAKE_DOCKER_LOG="$DOCKER_LOG" \
        FAKE_ELF_DIR="$FIXTURE_DIR" \
        DCENT_CAPSULE_GIT_OBJECT_REPO="$SOURCE_REPO" \
        DCENT_CAPSULE_SOURCE_SNAPSHOT="$SNAPSHOT_DESCRIPTOR" \
        DCENT_CAPSULE_SOURCE_COMMIT="$SOURCE_COMMIT" \
        DCENT_CAPSULE_INVOCATION_STAGE="$INVOCATION_STAGE" \
        DCENT_CAPSULE_RESULT_STAGE="$RESULT_STAGE" \
        DCENT_CAPSULE_RESULT_ROOT="$RESULT_ROOT" \
        DCENT_CAPSULE_RESULT_CAPABILITY="$RESULT_CAPABILITY" \
        DCENT_CAPSULE_EXTERNAL_INPUT_REPO_ROOT="$EXTERNAL_REPO" \
        DCENT_CAPSULE_CARGO_BUILD_INPUT_SNAPSHOT="${CARGO_BUILD_INPUT_SNAPSHOT_OVERRIDE:-$CARGO_BUILD_INPUT_SNAPSHOT}" \
        DCENT_MANIFEST_PUBLIC_KEY_HEX="$(printf 'a%.0s' {1..64})" \
        DCENT_RELEASE_PUBKEY_FILE="${RELEASE_PUBKEY_OVERRIDE-$FIXTURE_DIR/test-pub.pem}" \
        DCENT_RUST_BUILDER_BASE="rust-test@sha256:$(printf 'b%.0s' {1..64})" \
        "$SOURCE_REPO/DCENT_OS_Antminer/scripts/build-dcentrald.sh" "$target"
}

LIVE_SENTINEL="$SOURCE_REPO/DCENT_OS_Antminer/dcentrald/target/live-sentinel"
mkdir -p "$(dirname "$LIVE_SENTINEL")"
printf 'do-not-touch\n' > "$LIVE_SENTINEL"

new_capsule success
: > "$DOCKER_LOG"
if ! run_driver >"$TMPDIR_TEST/success.out" 2>&1; then
    cat "$TMPDIR_TEST/success.out" >&2
    exit 1
fi
grep -Fq 'seven exact source profiles verified' "$TMPDIR_TEST/success.out"
grep -Fq 'verified compiled release OTA identity' "$TMPDIR_TEST/success.out"
python3 "$SCRIPT_DIR/release_dashboard.py" verify \
    --source "$SNAPSHOT_TREE/DCENT_OS_Antminer/dashboard" --output "$RESULT_ROOT/dashboard" >/dev/null
test ! -e "$SNAPSHOT_TREE/DCENT_OS_Antminer/dashboard/node_modules"
test ! -e "$SNAPSHOT_TREE/DCENT_OS_Antminer/dashboard/dist"
TRIPLE=armv7-unknown-linux-musleabihf
for binary in dcentrald dcentos-init dcentos-discovery; do
    test -f "$RESULT_ROOT/target/$TRIPLE/release/$binary"
    test -f "$RESULT_ROOT/target/$TRIPLE/release/$binary.build-receipt.json"
    grep -q '"schema_version":4' "$RESULT_ROOT/target/$TRIPLE/release/$binary.build-receipt.json"
    grep -q '"build_inputs":' "$RESULT_ROOT/target/$TRIPLE/release/$binary.build-receipt.json"
    grep -q '"selection_authority":"manifest-from-same-git-authenticated-release-capsule-source-snapshot"' \
        "$RESULT_ROOT/target/$TRIPLE/release/$binary.build-receipt.json"
done
test "$(cat "$LIVE_SENTINEL")" = do-not-touch
test "$(python3 "$SCRIPT_DIR/release_result_stage.py" query --invocation-stage "$INVOCATION_STAGE" --field state "$RESULT_STAGE")" = sealed
test "$(cat "$FAKE_STATE/observed-build-context")" = "$SNAPSHOT_TREE/DCENT_OS_Antminer/dcentrald"
test "$(cat "$FAKE_STATE/observed-source-mount")" = "$SNAPSHOT_TREE/DCENT_OS_Antminer/dcentrald"
test "$(cat "$FAKE_STATE/observed-schema-mount")" = "$SNAPSHOT_TREE/projects/dcent-schema"
test "$(cat "$FAKE_STATE/observed-cargo-mount")" = "$CARGO_VOLUME"
test "$(cat "$FAKE_STATE/observed-result-mount")" = "$RESULT_ROOT"
grep -Fq "sha256:$(printf '1%.0s' {1..64})" "$DOCKER_LOG"
test ! -e "$FAKE_STATE/volumes/$CARGO_VOLUME"
test ! -e "$FAKE_STATE/images/dcentos-release-builder:$INVOCATION_ID"
test "$(find "$FAKE_STATE/images" -maxdepth 1 -type f -name 'dcentos-cargo-builder:*' | wc -l)" = 1
test -f "$CARGO_BUILD_INPUT_SNAPSHOT"

# The same authenticated Cargo capsule path must emit the AArch64 S19k native
# candidate without weakening its split source/result/invocation authorities.
new_capsule amlogic-success
: > "$DOCKER_LOG"
# Host environment must not remove the resource bound passed to Docker.
if ! CARGO_BUILD_JOBS=19 CARGO_INCREMENTAL=1 CARGO_PROFILE_RELEASE_INCREMENTAL=true \
    run_driver amlogic >"$TMPDIR_TEST/amlogic-success.out" 2>&1; then
    cat "$TMPDIR_TEST/amlogic-success.out" >&2
    exit 1
fi
TRIPLE=aarch64-unknown-linux-musl
grep -Fq "DCENT_MANIFEST_PUBLIC_KEY_HEX=$(printf 'a%.0s' {1..64})" "$DOCKER_LOG"
grep -Fq "DCENT_OTA_PUBLIC_KEY_HEX=$OTA_PUBLIC_KEY_HEX" "$DOCKER_LOG"
for binary in dcentrald dcentos-init dcentos-discovery; do
    test -f "$RESULT_ROOT/target/$TRIPLE/release/$binary"
    test -f "$RESULT_ROOT/target/$TRIPLE/release/$binary.build-receipt.json"
    grep -q '"schema_version":4' "$RESULT_ROOT/target/$TRIPLE/release/$binary.build-receipt.json"
done
PYTHONPATH="$SCRIPT_DIR" python3 - \
    "$RESULT_ROOT/target/$TRIPLE/release/dcentrald.build-receipt.json" "$OTA_PUBLIC_KEY_HEX" <<'PY'
import json
import sys
import s19k_native_build_verify as verifier

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    receipt = json.load(handle)
observed = receipt["build_environment"]["DCENT_MANIFEST_PUBLIC_KEY_HEX"]
assert observed == "a" * 64
compile_env = receipt["compile_environment"]["entries"]
# The historical S19k acceptance schema remains frozen. The current driver
# adds an independent OTA key and verifies it against the actual daemon ELF;
# retain an exact environment census here without rewriting that old schema.
assert compile_env == {
    **verifier.COMPILE_ENVIRONMENT,
    "DCENT_BUILDER_BASE_REFERENCE": receipt["builder"]["base_reference"],
    "DCENT_BUILDER_IMAGE_ID": receipt["builder"]["image_id"],
    "DCENT_MANIFEST_KEY_ID": "",
    "DCENT_MANIFEST_PUBLIC_KEY_HEX": observed,
    "DCENT_OTA_PUBLIC_KEY_HEX": sys.argv[2],
}
assert compile_env["CARGO_BUILD_JOBS"] == "2"
assert compile_env["CARGO_INCREMENTAL"] == "0"
assert compile_env["DCENT_OTA_PUBLIC_KEY_HEX"] == sys.argv[2]
assert "CARGO_INCREMENTAL_DECOY" not in compile_env
assert receipt["build_environment"] == {
    "DCENT_MANIFEST_KEY_ID": "",
    "DCENT_MANIFEST_PUBLIC_KEY_HEX": observed,
}
PY
test "$(python3 "$SCRIPT_DIR/release_result_stage.py" query --invocation-stage "$INVOCATION_STAGE" --field state "$RESULT_STAGE")" = sealed
test "$(cat "$FAKE_STATE/observed-source-mount")" = "$SNAPSHOT_TREE/DCENT_OS_Antminer/dcentrald"
test "$(cat "$FAKE_STATE/observed-result-mount")" = "$RESULT_ROOT"
test ! -e "$FAKE_STATE/volumes/$CARGO_VOLUME"
test ! -e "$FAKE_STATE/images/dcentos-release-builder:$INVOCATION_ID"
test -f "$CARGO_BUILD_INPUT_SNAPSHOT"

# A plausible compile observation cannot replace the actual retained ELF
# identity, and neither can a valid ELF excuse a wrong observation. Bad npm
# output must fail the real dashboard validator before the result is sealed.
for failure in elf-key ota-observation dashboard-assets; do
    new_capsule "$failure"
    case "$failure" in
        elf-key) failure_variable=FAKE_DOCKER_BAD_ELF_KEY ;;
        ota-observation) failure_variable=FAKE_DOCKER_BAD_OTA_OBSERVATION ;;
        dashboard-assets) failure_variable=FAKE_NPM_BAD_ASSETS ;;
    esac
    export "$failure_variable=1"
    if run_driver >"$TMPDIR_TEST/$failure.out" 2>&1; then
        echo "$failure unexpectedly entered a sealed Cargo result" >&2; exit 1
    fi
    unset "$failure_variable"
    case "$failure" in
        elf-key) grep -Fq 'actual daemon ELF does not contain' "$TMPDIR_TEST/$failure.out" ;;
        ota-observation) grep -Fq 'compile observation is missing' "$TMPDIR_TEST/$failure.out" ;;
        dashboard-assets) grep -Fq 'dashboard HTML/gzip/digest disagree' "$TMPDIR_TEST/$failure.out" ;;
    esac
    test "$(python3 "$SCRIPT_DIR/release_result_stage.py" query --invocation-stage "$INVOCATION_STAGE" --field state "$RESULT_STAGE")" != sealed
    test ! -e "$FAKE_STATE/volumes/$CARGO_VOLUME"
    test ! -e "$FAKE_STATE/images/dcentos-release-builder:$INVOCATION_ID"
    test ! -e "$SNAPSHOT_TREE/DCENT_OS_Antminer/dashboard/dist"
done

for failure in absent-trusted-key conflicting-ota-key; do
    new_capsule "$failure"
    docker_lines_before="$(wc -l < "$DOCKER_LOG")"
    if [ "$failure" = absent-trusted-key ]; then
        if RELEASE_PUBKEY_OVERRIDE='' run_driver >"$TMPDIR_TEST/$failure.out" 2>&1; then exit 1; fi
        grep -Fq 'independently trusted public-key file' "$TMPDIR_TEST/$failure.out"
    else
        if DCENT_OTA_PUBLIC_KEY_HEX="$(printf '0%.0s' {1..64})" run_driver >"$TMPDIR_TEST/$failure.out" 2>&1; then exit 1; fi
        grep -Fq 'compiled OTA key must equal' "$TMPDIR_TEST/$failure.out"
    fi
    test "$(wc -l < "$DOCKER_LOG")" = "$docker_lines_before"
done

# A compatibility handoff target cannot enter the native AArch64 capsule
# merely because every authority variable is present.
new_capsule unsupported-s19k-tmp
docker_lines_before="$(wc -l < "$DOCKER_LOG")"
if run_driver s19k-tmp >"$TMPDIR_TEST/unsupported-s19k-tmp.out" 2>&1; then
    echo 'unsupported s19k-tmp capsule unexpectedly succeeded' >&2
    exit 1
fi
grep -q 'supports only targets zynq and amlogic' "$TMPDIR_TEST/unsupported-s19k-tmp.out"
test "$(wc -l < "$DOCKER_LOG")" = "$docker_lines_before"

# The outer-owned descriptor is mandatory and must be split-authority v2.
# Both failures occur before any Docker resource allocation.
new_capsule missing-input
docker_lines_before="$(wc -l < "$DOCKER_LOG")"
if CARGO_BUILD_INPUT_SNAPSHOT_OVERRIDE="$CONTROL_PARENT/missing-input-snapshot.json" \
    run_driver >"$TMPDIR_TEST/missing-input.out" 2>&1; then
    echo 'missing outer Cargo snapshot unexpectedly succeeded' >&2
    exit 1
fi
grep -Eq 'snapshot|No such file|not found' "$TMPDIR_TEST/missing-input.out"
test "$(wc -l < "$DOCKER_LOG")" = "$docker_lines_before"

LEGACY_INPUT_ROOT="$TMPDIR_TEST/legacy-input-root"
mkdir -p "$LEGACY_INPUT_ROOT/DCENT_OS_Antminer/scripts" \
    "$LEGACY_INPUT_ROOT/knowledge-base/extractions/s9"
cp "$EXTERNAL_REPO/knowledge-base/extractions/s9/kernel.bin" \
    "$LEGACY_INPUT_ROOT/knowledge-base/extractions/s9/kernel.bin"
printf '%s  %s\n' "$S9_KERNEL_SHA" \
    'knowledge-base/extractions/s9/kernel.bin' \
    > "$LEGACY_INPUT_ROOT/DCENT_OS_Antminer/scripts/build_inputs.manifest"
LEGACY_INPUT_RESULT="$(python3 "$SCRIPT_DIR/build_input_snapshot.py" create \
    --repo-root "$LEGACY_INPUT_ROOT" \
    --build-input-manifest "$LEGACY_INPUT_ROOT/DCENT_OS_Antminer/scripts/build_inputs.manifest" \
    --target cargo-workspace --stage-parent "$CONTROL_PARENT")"
LEGACY_INPUT_SNAPSHOT="$(printf '%s\n' "$LEGACY_INPUT_RESULT" \
    | python3 "$SCRIPT_DIR/build_input_snapshot.py" query-result --field snapshot)"
new_capsule swapped-input
docker_lines_before="$(wc -l < "$DOCKER_LOG")"
if CARGO_BUILD_INPUT_SNAPSHOT_OVERRIDE="$LEGACY_INPUT_SNAPSHOT" \
    run_driver >"$TMPDIR_TEST/swapped-input.out" 2>&1; then
    echo 'legacy Cargo snapshot unexpectedly entered release capsule' >&2
    exit 1
fi
grep -q 'split-authority v2' "$TMPDIR_TEST/swapped-input.out"
test "$(wc -l < "$DOCKER_LOG")" = "$docker_lines_before"
test -f "$CARGO_BUILD_INPUT_SNAPSHOT"

# A result stage cannot be swapped under a different invocation authority.
OLD_RESULT_STAGE=$RESULT_STAGE OLD_RESULT_ROOT=$RESULT_ROOT OLD_RESULT_CAPABILITY=$RESULT_CAPABILITY
new_capsule swap
RESULT_STAGE=$OLD_RESULT_STAGE RESULT_ROOT=$OLD_RESULT_ROOT RESULT_CAPABILITY=$OLD_RESULT_CAPABILITY
if run_driver >"$TMPDIR_TEST/swap.out" 2>&1; then echo 'capsule swap unexpectedly succeeded' >&2; exit 1; fi
grep -Eq 'different|bound|invocation' "$TMPDIR_TEST/swap.out"

# A pre-existing derived volume is never adopted or deleted.
new_capsule preexisting
printf '%s|attacker\n' "$CARGO_VOLUME" > "$FAKE_STATE/volumes/$CARGO_VOLUME"
if run_driver >"$TMPDIR_TEST/preexisting.out" 2>&1; then echo 'pre-existing volume unexpectedly succeeded' >&2; exit 1; fi
grep -q 'already exists' "$TMPDIR_TEST/preexisting.out"
test -f "$FAKE_STATE/volumes/$CARGO_VOLUME"
rm -f "$FAKE_STATE/volumes/$CARGO_VOLUME"

# Build failure and TERM both remove only exact invocation-owned resources.
for mode in failure signal; do
    new_capsule "$mode"
    if [ "$mode" = failure ]; then
        if FAKE_DOCKER_FAIL_RUN=1 run_driver >"$TMPDIR_TEST/$mode.out" 2>&1; then exit 1; fi
    else
        rm -f "$FAKE_STATE/signal-ready"
        (FAKE_DOCKER_SIGNAL_RUN=1 run_driver >"$TMPDIR_TEST/$mode.out" 2>&1) &
        driver_pid=$!
        # The full offline aggregate can leave WSL CPU-starved after the
        # compile/test phases. Give the fake-Docker child up to 30 seconds to
        # publish readiness; this bounds fixture scheduling only, not a
        # production cleanup or build timeout.
        for _attempt in $(seq 1 1500); do
            [ -e "$FAKE_STATE/signal-ready" ] && break
            sleep 0.02
        done
        [ -e "$FAKE_STATE/signal-ready" ] || { echo 'signal run never reached Docker' >&2; exit 1; }
        build_pid="$(cat "$FAKE_STATE/signal-ready")"
        kill -TERM "$build_pid"
        if wait "$driver_pid"; then exit 1; fi
    fi
    test ! -e "$FAKE_STATE/volumes/$CARGO_VOLUME"
    test ! -e "$FAKE_STATE/images/dcentos-release-builder:$INVOCATION_ID"
    test ! -e "$FAKE_STATE/containers/dcentos-cargo-run-$INVOCATION_ID"
    test -f "$CARGO_BUILD_INPUT_SNAPSHOT"
done

# Release intent without a complete capsule fails before Docker.  A direct
# development build remains available, writes only its historical live target,
# and explicitly emits no lineage receipt.
if env PATH="$FAKE_BIN:$PATH" DCENT_RELEASE_IMAGE=1 \
    "$SOURCE_REPO/DCENT_OS_Antminer/scripts/build-dcentrald.sh" zynq \
    >"$TMPDIR_TEST/no-capsule.out" 2>&1; then
    echo 'release build without capsule unexpectedly succeeded' >&2
    exit 1
fi
grep -q 'without an authenticated release capsule' "$TMPDIR_TEST/no-capsule.out"
if ! env PATH="$FAKE_BIN:$PATH" DCENT_DOCKER_BIN=docker DCENT_DEV_IMAGE=1 \
    FAKE_DOCKER_STATE="$FAKE_STATE" FAKE_DOCKER_LOG="$DOCKER_LOG" \
    FAKE_ELF_DIR="$FIXTURE_DIR" \
    DCENT_RUST_BUILDER_BASE=rust:1.90-bookworm \
    "$SOURCE_REPO/DCENT_OS_Antminer/scripts/build-dcentrald.sh" zynq \
    >"$TMPDIR_TEST/development.out" 2>&1; then
    cat "$TMPDIR_TEST/development.out" >&2
    exit 1
fi
grep -q 'build receipt skipped' "$TMPDIR_TEST/development.out"
test "$(cat "$LIVE_SENTINEL")" = do-not-touch
TRIPLE=armv7-unknown-linux-musleabihf
for binary in dcentrald dcentos-init dcentos-discovery; do
    test -f "$SOURCE_REPO/DCENT_OS_Antminer/dcentrald/target/$TRIPLE/release/$binary"
    test ! -e "$SOURCE_REPO/DCENT_OS_Antminer/dcentrald/target/$TRIPLE/release/$binary.build-receipt.json"
done

echo "cargo capsule driver fake-Docker tests passed"
