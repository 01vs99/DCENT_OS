#!/bin/sh
# Network-enabled dependency materializer for the S19k Pro hermetic producer.
#
# This is deliberately a separate phase from s19k_hermetic_build_inner.sh.
# It may fetch only source/dependency bytes selected by the authenticated policy
# beside this script.  It never builds firmware, signs a release, contacts a
# miner, installs anything, or grants release/flash authority.  Its successful
# output is still untrusted until s19k_hermetic_image_producer.py exact-set
# seals it on the host.

set -eu
umask 022

fail() {
    echo "S19K_HERMETIC_MATERIALIZER_REFUSED: $*" >&2
    exit 1
}

require_env() {
    # The caller list below contains fixed shell identifiers only. Expansion of
    # the resulting value occurs in assignment context and is not re-evaluated.
    eval "required_value=\${$1-}"
    [ -n "$required_value" ] || fail "missing required environment: $1"
}

for required_name in \
    DCENT_MATERIALIZER_SOURCE_STAGE \
    DCENT_MATERIALIZER_SOURCE_COMMIT \
    DCENT_MATERIALIZER_BUILDER_IMAGE \
    DCENT_MATERIALIZER_TOOLCHAIN_ID \
    DCENT_MATERIALIZER_AMLOGIC_KERNEL \
    DCENT_MATERIALIZER_AMLOGIC_DTB \
    DCENT_MATERIALIZER_AMLOGIC_FW_INFO \
    DCENT_MATERIALIZER_WORK_ROOT \
    DCENT_MATERIALIZER_OUTPUT_ROOT \
    DCENT_MATERIALIZER_SELECTION \
    DCENT_MATERIALIZER_NETWORK_MODE
do
    require_env "$required_name"
done

[ "$DCENT_MATERIALIZER_NETWORK_MODE" = source-fetch-only ] ||
    fail "network mode must be source-fetch-only"

for required_command in python3 git cargo npm make tar
do
    command -v "$required_command" >/dev/null 2>&1 ||
        fail "required materializer command is absent: $required_command"
done

SOURCE_STAGE=$DCENT_MATERIALIZER_SOURCE_STAGE
SOURCE_ROOT=$SOURCE_STAGE/tree
SOURCE_DESCRIPTOR=$SOURCE_STAGE/snapshot.json
SOURCE_COMMIT=$DCENT_MATERIALIZER_SOURCE_COMMIT
BUILDER_IMAGE=$DCENT_MATERIALIZER_BUILDER_IMAGE
TOOLCHAIN_ID=$DCENT_MATERIALIZER_TOOLCHAIN_ID
AMLOGIC_KERNEL=$DCENT_MATERIALIZER_AMLOGIC_KERNEL
AMLOGIC_DTB=$DCENT_MATERIALIZER_AMLOGIC_DTB
AMLOGIC_FW_INFO=$DCENT_MATERIALIZER_AMLOGIC_FW_INFO
WORK_ROOT=$DCENT_MATERIALIZER_WORK_ROOT
OUTPUT_ROOT=$DCENT_MATERIALIZER_OUTPUT_ROOT
SELECTION_PATH=$DCENT_MATERIALIZER_SELECTION
POLICY_REL=DCENT_OS_Antminer/scripts/s19k_hermetic_dependencies.json
MATERIALIZER_REL=DCENT_OS_Antminer/scripts/s19k_hermetic_materialize_inner.sh
SNAPSHOT_HELPER_REL=DCENT_OS_Antminer/scripts/source_snapshot.py
POLICY=$SOURCE_ROOT/$POLICY_REL
SNAPSHOT_HELPER=$SOURCE_ROOT/$SNAPSHOT_HELPER_REL

# Validate the invocation, exact authenticated policy, lockfiles, held inputs,
# and all not-yet-created destinations before the first network operation.
python3 - "$0" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


EXPECTED_POLICY_SHA256 = "f7101ab4eff6fe2eb59a4080f0d3aef96d9e6ef525e0071c861298c4d4378fa1"
POLICY_REL = Path("DCENT_OS_Antminer/scripts/s19k_hermetic_dependencies.json")
MATERIALIZER_REL = Path("DCENT_OS_Antminer/scripts/s19k_hermetic_materialize_inner.sh")
SNAPSHOT_HELPER_REL = Path("DCENT_OS_Antminer/scripts/source_snapshot.py")
FULL_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:@/-]{0,255}\Z")
IMAGE = re.compile(
    r"(?:[a-z0-9._-]+(?::[0-9]+)?/)*[a-z0-9._-]+@sha256:[0-9a-f]{64}\Z"
)


def refuse(message: str) -> "NoReturn":
    raise SystemExit(f"S19K_HERMETIC_MATERIALIZER_REFUSED: {message}")


def env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or any(ord(character) < 32 or ord(character) == 127 for character in value):
        refuse(f"invalid environment value: {name}")
    return value


def directory(path: Path, label: str) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        refuse(f"{label} is unavailable: {error}")
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        refuse(f"{label} is not a non-link directory")


def regular(path: Path, label: str, maximum: int) -> bytes:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        refuse(f"{label} is unavailable: {error}")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > maximum
    ):
        refuse(f"{label} is not a bounded single-link regular file")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        refuse(f"{label} changed while it was read")
    return raw


def absolute_new_path(name: str) -> Path:
    value = Path(env(name))
    if not value.is_absolute() or value != Path(os.path.abspath(os.fspath(value))):
        refuse(f"{name} must be an absolute normalized path")
    if os.path.lexists(value):
        refuse(f"{name} already exists")
    directory(value.parent, f"{name} parent")
    return value


source_stage = Path(env("DCENT_MATERIALIZER_SOURCE_STAGE"))
directory(source_stage, "source snapshot stage")
directory(source_stage / "tree", "source snapshot tree")
source_root = (source_stage / "tree").resolve(strict=True)
policy_path = source_root / POLICY_REL
helper_path = source_root / SNAPSHOT_HELPER_REL
descriptor_path = source_stage / "snapshot.json"
policy_raw = regular(policy_path, "dependency policy", 1024 * 1024)
regular(helper_path, "source snapshot helper", 16 * 1024 * 1024)
regular(descriptor_path, "source snapshot descriptor", 16 * 1024 * 1024)

script_path = Path(sys.argv[1]).resolve(strict=True)
expected_script = (source_root / MATERIALIZER_REL).resolve(strict=True)
if not script_path.samefile(expected_script):
    refuse("materializer is not the script from the admitted source snapshot")
regular(expected_script, "materializer script", 16 * 1024 * 1024)

if hashlib.sha256(policy_raw).hexdigest() != EXPECTED_POLICY_SHA256:
    refuse("dependency policy digest is not the reviewed policy")
try:
    policy = json.loads(policy_raw)
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    refuse(f"dependency policy is not valid JSON: {error}")
canonical = (
    json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    + b"\n"
)
if policy_raw != canonical:
    refuse("dependency policy is not canonical JSON")
if set(policy) != {
    "amlogic_inputs",
    "authority",
    "builder",
    "buildroot",
    "cargo",
    "dashboard",
    "mandatory_selection_classes",
    "materialization",
    "schema",
    "selection_schema",
    "source_commit_binding",
    "toolchain",
}:
    refuse("dependency policy has an unexpected top-level shape")
if policy["schema"] != "dcentos.s19k-hermetic-dependency-policy/v1":
    refuse("dependency policy schema is unsupported")
if policy["selection_schema"] != "dcentos.s19k-hermetic-dependency-selection/v1":
    refuse("dependency selection schema is unsupported")
if policy["authority"] != "dependency-materialization-only-no-build-release-install-or-flash-authority":
    refuse("dependency policy overclaims authority")
if policy["source_commit_binding"] != {
    "policy_path": POLICY_REL.as_posix(),
    "verification": "admitted-immutable-snapshot-exact-tree-before-and-after",
}:
    refuse("dependency policy source binding changed")
if policy["materialization"] != {
    "builder_image_binding": "authenticated-policy-exact-name-at-sha256",
    "compiled_outputs_forbidden": True,
    "network_phase": "separate-source-fetch-only",
    "output": "source-only-exact-selection-for-later-host-sealing",
}:
    refuse("dependency materialization boundary changed")

source_commit = env("DCENT_MATERIALIZER_SOURCE_COMMIT")
builder_image = env("DCENT_MATERIALIZER_BUILDER_IMAGE")
toolchain_id = env("DCENT_MATERIALIZER_TOOLCHAIN_ID")
if not FULL_COMMIT.fullmatch(source_commit):
    refuse("selected source commit is not one full lowercase object id")
if not IMAGE.fullmatch(builder_image):
    refuse("builder image is not an exact name@sha256 reference")
if not TOKEN.fullmatch(toolchain_id):
    refuse("toolchain id is not a canonical exact token")
builder = policy["builder"]
if not isinstance(builder, dict) or set(builder) != {
    "dockerfile",
    "image",
    "linux_amd64_manifest_digest",
    "oci_config_digest",
    "oci_index_digest",
    "toolchain_id",
    "versions",
}:
    refuse("dependency policy builder shape changed")
if builder_image != builder["image"] or toolchain_id != builder["toolchain_id"]:
    refuse("selected builder/toolchain differs from authenticated policy")
dockerfile = builder["dockerfile"]
if not isinstance(dockerfile, dict) or set(dockerfile) != {"bytes", "path", "sha256"}:
    refuse("builder Dockerfile policy shape changed")
dockerfile_raw = regular(
    source_root / dockerfile["path"], "authenticated builder Dockerfile", 16 * 1024 * 1024
)
if (
    len(dockerfile_raw) != dockerfile["bytes"]
    or hashlib.sha256(dockerfile_raw).hexdigest() != dockerfile["sha256"]
):
    refuse("builder Dockerfile differs from authenticated policy")
if env("DCENT_MATERIALIZER_NETWORK_MODE") != "source-fetch-only":
    refuse("materializer network mode changed")

for section_name, expected_keys in (
    (
        "buildroot",
        {
            "commit",
            "downloads_destination",
            "source_archive_bytes",
            "source_archive_sha256",
            "source_destination",
            "url",
        },
    ),
    ("cargo", {"lock", "vendor_destination"}),
    ("dashboard", {"lock", "npm_cache_destination"}),
    ("toolchain", {"archive", "download_root", "sha256", "toolchain_id_binding", "url"}),
):
    section = policy[section_name]
    if not isinstance(section, dict) or set(section) != expected_keys:
        refuse(f"dependency policy {section_name} shape changed")
if policy["buildroot"] != {
    "commit": "7c8edc1b402efcd7bba2dabfe0b3be877adaed7a",
    "downloads_destination": "buildroot/dl",
    "source_archive_bytes": 35901440,
    "source_archive_sha256": "b9dc4163c397c67ad7cbe71499cfba7363413b021e8c49cca96892adb90acd19",
    "source_destination": "buildroot/source",
    "url": "https://github.com/buildroot/buildroot.git",
}:
    refuse("Buildroot source policy changed")
if policy["toolchain"] != {
    "archive": "gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu.tar.xz",
    "download_root": "buildroot/dl",
    "sha256": "20181f828e1075f1a493947ff91e82dd578ce9f8638fbdfc39e24b62857d8f8d",
    "toolchain_id_binding": "authenticated-policy-exact-token",
    "url": "https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/aarch64-linux-gnu/gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu.tar.xz",
}:
    refuse("AArch64 toolchain policy changed")

for section_name in ("cargo", "dashboard"):
    lock = policy[section_name]["lock"]
    if not isinstance(lock, dict) or set(lock) != {"bytes", "path", "sha256"}:
        refuse(f"{section_name} lock policy shape changed")
    lock_path = source_root / lock["path"]
    raw = regular(lock_path, f"{section_name} lockfile", 16 * 1024 * 1024)
    if len(raw) != lock["bytes"] or hashlib.sha256(raw).hexdigest() != lock["sha256"]:
        refuse(f"{section_name} lockfile differs from policy")

amlogic = policy["amlogic_inputs"]
if not isinstance(amlogic, list) or len(amlogic) != 3:
    refuse("Amlogic input policy is incomplete")
by_name = {item.get("name"): item for item in amlogic if isinstance(item, dict)}
if set(by_name) != {"vmlinux.bin", "devicetree.dtb", "fw-info"}:
    refuse("Amlogic input policy names changed")
for item in amlogic:
    if set(item) != {"bytes", "destination", "name", "sha256"}:
        refuse("Amlogic input policy shape changed")
for env_name, item_name in (
    ("DCENT_MATERIALIZER_AMLOGIC_KERNEL", "vmlinux.bin"),
    ("DCENT_MATERIALIZER_AMLOGIC_DTB", "devicetree.dtb"),
    ("DCENT_MATERIALIZER_AMLOGIC_FW_INFO", "fw-info"),
):
    raw = regular(Path(env(env_name)), f"held Amlogic {item_name}", 256 * 1024 * 1024)
    item = by_name[item_name]
    if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
        refuse(f"held Amlogic {item_name} differs from policy")

mandatory = policy["mandatory_selection_classes"]
if mandatory != [
    "amlogic-input",
    "buildroot-download",
    "buildroot-source",
    "cargo-source",
    "dashboard-dependency",
    "toolchain-archive",
]:
    refuse("mandatory dependency classes changed")
if policy["cargo"]["vendor_destination"] != "cargo/vendor":
    refuse("Cargo vendor destination changed")
if policy["dashboard"]["npm_cache_destination"] != "dashboard/npm-cache":
    refuse("dashboard cache destination changed")

work_root = absolute_new_path("DCENT_MATERIALIZER_WORK_ROOT")
output_root = absolute_new_path("DCENT_MATERIALIZER_OUTPUT_ROOT")
selection_path = absolute_new_path("DCENT_MATERIALIZER_SELECTION")
resolved_stage = source_stage.resolve(strict=True)


def within(candidate: Path, parent: Path) -> bool:
    return os.path.commonpath((os.fspath(candidate), os.fspath(parent))) == os.fspath(parent)


for new_root, label in ((work_root, "work root"), (output_root, "output root")):
    absolute = Path(os.path.abspath(os.fspath(new_root)))
    if within(absolute, resolved_stage):
        refuse(f"{label} is inside an authenticated read-only input")
if within(work_root, output_root) or within(output_root, work_root):
    refuse("work and output roots overlap")
if within(selection_path, work_root) or within(selection_path, output_root):
    refuse("selection path must be outside materialized and transient roots")
PY

mkdir "$WORK_ROOT" || fail "could not allocate the fresh private work root"
chmod 700 "$WORK_ROOT" || fail "could not restrict the private work root"

RESULT_ROOT=$WORK_ROOT/result
BUILDROOT_CHECKOUT=$WORK_ROOT/buildroot-checkout
BUILDROOT_OUTPUT=$WORK_ROOT/buildroot-output
BUILDROOT_EXTERNAL=$WORK_ROOT/br2-external
GIT_HOME=$WORK_ROOT/git-home
CARGO_HOME=$WORK_ROOT/cargo-home
DASHBOARD_WORK=$WORK_ROOT/dashboard-work
NPM_HOME=$WORK_ROOT/npm-home
MATERIALIZER_TMP=$WORK_ROOT/tmp
mkdir "$RESULT_ROOT" "$BUILDROOT_OUTPUT" "$BUILDROOT_EXTERNAL" \
    "$GIT_HOME" "$CARGO_HOME" "$DASHBOARD_WORK" "$NPM_HOME" \
    "$MATERIALIZER_TMP"

BUILDROOT_URL=https://github.com/buildroot/buildroot.git
BUILDROOT_COMMIT=7c8edc1b402efcd7bba2dabfe0b3be877adaed7a
TOOLCHAIN_ARCHIVE=gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu.tar.xz
TOOLCHAIN_SHA256=20181f828e1075f1a493947ff91e82dd578ce9f8638fbdfc39e24b62857d8f8d

python3 "$SNAPSHOT_HELPER" verify \
    --commit "$SOURCE_COMMIT" \
    "$SOURCE_DESCRIPTOR" >/dev/null ||
    fail "source snapshot failed its pre-materialization exact-tree verification"

# The Git wrapper ignores inherited user/system configuration. The reviewed
# HTTPS remote and exact object ID are the only admitted Buildroot source.
clean_git() {
    env -i \
        PATH="$PATH" \
        HOME="$GIT_HOME" \
        LC_ALL=C \
        GIT_CONFIG_NOSYSTEM=1 \
        git "$@"
}

clean_git init --quiet "$BUILDROOT_CHECKOUT"
clean_git -C "$BUILDROOT_CHECKOUT" remote add origin "$BUILDROOT_URL"
clean_git -C "$BUILDROOT_CHECKOUT" fetch --depth=1 --no-tags origin "$BUILDROOT_COMMIT"
clean_git -C "$BUILDROOT_CHECKOUT" checkout --quiet --detach FETCH_HEAD
OBSERVED_BUILDROOT_COMMIT=$(clean_git -C "$BUILDROOT_CHECKOUT" rev-parse --verify 'HEAD^{commit}')
[ "$OBSERVED_BUILDROOT_COMMIT" = "$BUILDROOT_COMMIT" ] ||
    fail "Buildroot checkout does not equal the reviewed commit"
clean_git -C "$BUILDROOT_CHECKOUT" fsck --full --strict >/dev/null
[ -z "$(clean_git -C "$BUILDROOT_CHECKOUT" status --porcelain=v1 --untracked-files=all)" ] ||
    fail "Buildroot checkout is not clean"

# Export the exact tracked Buildroot tree as one deterministic Git archive.
# Keeping the archive as a regular dependency file preserves tracked symlink
# entries without admitting live links into the host-sealed dependency stage.
mkdir -p "$RESULT_ROOT/buildroot/source" "$RESULT_ROOT/buildroot/dl"
clean_git -C "$BUILDROOT_CHECKOUT" archive \
    --format=tar \
    --output "$RESULT_ROOT/buildroot/source/buildroot-source.tar" \
    "$BUILDROOT_COMMIT"
python3 - "$RESULT_ROOT/buildroot/source/buildroot-source.tar" <<'PY'
import hashlib
from pathlib import Path
import sys

archive = Path(sys.argv[1])
raw = archive.read_bytes()
if len(raw) != 35901440:
    raise SystemExit("S19K_HERMETIC_MATERIALIZER_REFUSED: Buildroot archive byte count differs from policy")
if hashlib.sha256(raw).hexdigest() != "b9dc4163c397c67ad7cbe71499cfba7363413b021e8c49cca96892adb90acd19":
    raise SystemExit("S19K_HERMETIC_MATERIALIZER_REFUSED: Buildroot archive digest differs from policy")
PY

# Use a mutable copy of the authenticated BR2_EXTERNAL tree only to generate
# the composed defconfig. make source downloads and hash-checks package
# sources; it never invokes a target/host package build. Any transient Kconfig
# helper beneath the private O= tree is removed before successful publication.
(cd "$SOURCE_ROOT/DCENT_OS_Antminer/br2_external_dcentos" && tar -cf - .) |
    (cd "$BUILDROOT_EXTERNAL" && tar -xf -)
cat \
    "$BUILDROOT_EXTERNAL/configs/dcentos-common.fragment" \
    "$BUILDROOT_EXTERNAL/configs/dcentos_am3_aml_common.fragment" \
    "$BUILDROOT_EXTERNAL/configs/dcentos_am3_s19kpro_defconfig" \
    > "$BUILDROOT_EXTERNAL/configs/dcentos_am3_s19kpro_full_defconfig"
make -C "$BUILDROOT_CHECKOUT" \
    O="$BUILDROOT_OUTPUT" \
    BR2_EXTERNAL="$BUILDROOT_EXTERNAL" \
    BR2_DL_DIR="$RESULT_ROOT/buildroot/dl" \
    dcentos_am3_s19kpro_full_defconfig
make -C "$BUILDROOT_CHECKOUT" \
    O="$BUILDROOT_OUTPUT" \
    BR2_EXTERNAL="$BUILDROOT_EXTERNAL" \
    BR2_DL_DIR="$RESULT_ROOT/buildroot/dl" \
    source
[ -z "$(clean_git -C "$BUILDROOT_CHECKOUT" status --porcelain=v1 --untracked-files=all)" ] ||
    fail "Buildroot source checkout changed during source materialization"

# Cargo gets a fresh home, consumes the exact admitted lockfile, and emits only
# registry/Git package sources. It does not compile any crate.
mkdir -p "$RESULT_ROOT/cargo/vendor"
export CARGO_HOME
export CARGO_NET_OFFLINE=false
cargo vendor \
    --locked \
    --versioned-dirs \
    --manifest-path "$SOURCE_ROOT/DCENT_OS_Antminer/dcentrald/Cargo.toml" \
    "$RESULT_ROOT/cargo/vendor" \
    > "$WORK_ROOT/cargo-vendor-config.toml"

# Populate a fresh npm content cache from the exact lock. Lifecycle scripts are
# disabled, so no native addon, Cypress binary, dashboard bundle, or other
# generated output can be produced. node_modules remains transient and is
# removed before selection.
cp "$SOURCE_ROOT/DCENT_OS_Antminer/dashboard/package.json" "$DASHBOARD_WORK/package.json"
cp "$SOURCE_ROOT/DCENT_OS_Antminer/dashboard/package-lock.json" "$DASHBOARD_WORK/package-lock.json"
mkdir -p "$RESULT_ROOT/dashboard/npm-cache"
: > "$WORK_ROOT/empty-npmrc"
(cd "$DASHBOARD_WORK" && \
    HOME="$NPM_HOME" \
    npm_config_userconfig="$WORK_ROOT/empty-npmrc" \
    npm_config_registry=https://registry.npmjs.org/ \
    npm_config_cache="$RESULT_ROOT/dashboard/npm-cache" \
    npm_config_audit=false \
    npm_config_fund=false \
    npm_config_ignore_scripts=true \
    npm_config_update_notifier=false \
    npm ci --ignore-scripts --no-audit --no-fund)

python3 - "$WORK_ROOT" "$BUILDROOT_OUTPUT" "$DASHBOARD_WORK/node_modules" \
    "$RESULT_ROOT/dashboard/npm-cache/_logs" \
    "$RESULT_ROOT/dashboard/npm-cache/_update-notifier-last-checked" <<'PY'
from pathlib import Path
import os
import shutil
import sys

root = Path(sys.argv[1]).resolve(strict=True)
for raw in sys.argv[2:]:
    candidate = Path(raw)
    if not os.path.lexists(candidate):
        continue
    resolved_parent = candidate.parent.resolve(strict=True)
    if os.path.commonpath((str(resolved_parent), str(root))) != str(root):
        raise SystemExit("refused unsafe materializer cleanup target")
    if candidate.is_dir() and not candidate.is_symlink():
        shutil.rmtree(candidate)
    else:
        candidate.unlink()
PY

# Held boot inputs are admitted only by exact size+digest in the policy. These
# copies are build inputs, not generated firmware.
mkdir -p "$RESULT_ROOT/amlogic/s19kpro"
cp "$AMLOGIC_KERNEL" "$RESULT_ROOT/amlogic/s19kpro/vmlinux.bin"
cp "$AMLOGIC_DTB" "$RESULT_ROOT/amlogic/s19kpro/devicetree.dtb"
cp "$AMLOGIC_FW_INFO" "$RESULT_ROOT/amlogic/s19kpro/fw-info"

python3 "$SNAPSHOT_HELPER" verify \
    --commit "$SOURCE_COMMIT" \
    "$SOURCE_DESCRIPTOR" >/dev/null ||
    fail "source snapshot failed its post-materialization exact-tree verification"

# Generate and then independently replay the exact producer-compatible
# selection. This helper is transient under the private work root and is never
# part of the host-sealed dependency bundle.
cat > "$WORK_ROOT/finalize_selection.py" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


SELECTION_SCHEMA = "dcentos.s19k-hermetic-dependency-selection/v1"
EXPECTED_POLICY_SHA256 = "f7101ab4eff6fe2eb59a4080f0d3aef96d9e6ef525e0071c861298c4d4378fa1"
MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024
MAX_FILES = 1_000_000
MAX_TOTAL_BYTES = MAX_FILE_BYTES * 16
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
FORBIDDEN_DIRECTORIES = {"__pycache__", "node_modules", "output", "target"}
FORBIDDEN_BUILDROOT_COMPONENTS = {"build", "host", "images", "staging", "target"}
FORBIDDEN_SUFFIXES = (
    ".class", ".d", ".dll", ".dylib", ".ko", ".o", ".obj", ".pyc",
    ".pyo", ".rlib", ".rmeta", ".so",
)


def refuse(message: str) -> "NoReturn":
    raise SystemExit(f"S19K_HERMETIC_MATERIALIZER_REFUSED: {message}")


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + b"\n"
    )


def read_policy(path: Path) -> dict:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != EXPECTED_POLICY_SHA256:
        refuse("dependency policy digest changed after invocation admission")
    value = json.loads(raw)
    if raw != canonical(value):
        refuse("dependency policy changed or is noncanonical")
    return value


def safe_relative(value: str) -> PurePosixPath:
    pure = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or pure.is_absolute()
        or pure.as_posix() != value
        or any(part in ("", ".", "..") for part in pure.parts)
    ):
        refuse(f"unsafe dependency path: {value!r}")
    for part in pure.parts:
        if (
            any(ord(character) < 32 or ord(character) == 127 for character in part)
            or part.endswith((" ", "."))
            or ":" in part
        ):
            refuse(f"nonportable dependency path: {value!r}")
    return pure


def dependency_class(relative: str, policy: dict) -> str:
    toolchain = policy["toolchain"]
    toolchain_prefix = toolchain["download_root"] + "/"
    if (
        relative.startswith(toolchain_prefix)
        and PurePosixPath(relative).name == toolchain["archive"]
    ):
        return "toolchain-archive"
    if relative.startswith(policy["buildroot"]["source_destination"] + "/"):
        return "buildroot-source"
    if relative.startswith(policy["buildroot"]["downloads_destination"] + "/"):
        return "buildroot-download"
    if relative.startswith(policy["cargo"]["vendor_destination"] + "/"):
        return "cargo-source"
    if relative.startswith(policy["dashboard"]["npm_cache_destination"] + "/"):
        return "dashboard-dependency"
    admitted_amlogic = {item["destination"] for item in policy["amlogic_inputs"]}
    if relative in admitted_amlogic:
        return "amlogic-input"
    refuse(f"dependency output is outside every mandatory class: {relative}")


def validate_path(relative: str, dep_class: str) -> None:
    pure = safe_relative(relative)
    folded = tuple(part.casefold() for part in pure.parts)
    if set(folded) & FORBIDDEN_DIRECTORIES:
        refuse(f"dependency path contains mutable/compiled state: {relative}")
    if dep_class.startswith("buildroot-"):
        for index, component in enumerate(folded[:-1]):
            if (
                component == "buildroot"
                and index + 1 < len(folded)
                and folded[index + 1] in FORBIDDEN_BUILDROOT_COMPONENTS
            ):
                refuse(f"dependency path contains Buildroot output state: {relative}")
    if dep_class not in {"toolchain-archive", "amlogic-input"}:
        name = pure.name.casefold()
        if name.endswith(FORBIDDEN_SUFFIXES):
            refuse(f"dependency path looks compiled: {relative}")
        if name.startswith(("rootfs.", "uimage", "fit.itb")):
            refuse(f"dependency path looks like a generated image: {relative}")


def inventory(root: Path, policy: dict, normalize: bool) -> list[dict]:
    try:
        root_metadata = os.lstat(root)
    except OSError as error:
        refuse(f"dependency root is unavailable: {error}")
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        refuse("dependency root is not a non-link directory")
    records = []
    portable = set()
    total = 0
    for current_raw, names, leaves in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_raw)
        names.sort(key=lambda value: value.encode("utf-8"))
        leaves.sort(key=lambda value: value.encode("utf-8"))
        for name in names:
            path = current / name
            metadata = os.lstat(path)
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                refuse(f"dependency tree contains a linked/non-directory node: {path}")
            if normalize:
                os.chmod(path, 0o755)
        for name in leaves:
            path = current / name
            metadata = os.lstat(path)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > MAX_FILE_BYTES
            ):
                refuse(f"dependency is not a bounded single-link regular file: {path}")
            relative = path.relative_to(root).as_posix()
            dep_class = dependency_class(relative, policy)
            validate_path(relative, dep_class)
            folded = relative.casefold()
            if folded in portable:
                refuse(f"portable dependency path collision: {relative}")
            portable.add(folded)
            desired_mode = 0o755 if metadata.st_mode & 0o111 else 0o644
            if normalize:
                os.chmod(path, desired_mode)
                metadata = os.lstat(path)
            normalized_mode = 0o755 if stat.S_IMODE(metadata.st_mode) & 0o111 else 0o644
            if normalized_mode != desired_mode:
                refuse(f"dependency mode is not canonical: {relative}")
            digest = hashlib.sha256()
            size = 0
            with path.open("rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
            if size != metadata.st_size:
                refuse(f"dependency changed while hashing: {relative}")
            total += size
            if total > MAX_TOTAL_BYTES:
                refuse("dependency materialization exceeds the aggregate bound")
            records.append(
                {
                    "path": relative,
                    "class": dep_class,
                    "sha256": digest.hexdigest(),
                    "bytes": size,
                    "mode": desired_mode,
                }
            )
            if len(records) > MAX_FILES:
                refuse("dependency materialization exceeds the file-count bound")
    records.sort(key=lambda item: item["path"].encode("utf-8"))
    return records


mode, policy_raw, root_raw, selection_raw, source_commit, builder_image, toolchain_id = sys.argv[1:]
policy_path = Path(policy_raw)
root = Path(root_raw)
selection_path = Path(selection_raw)
policy = read_policy(policy_path)
if (
    builder_image != policy.get("builder", {}).get("image")
    or toolchain_id != policy.get("builder", {}).get("toolchain_id")
):
    refuse("selection builder/toolchain differs from authenticated policy")
records = inventory(root, policy, normalize=mode == "create")
observed_classes = sorted({item["class"] for item in records}, key=lambda value: value.encode("utf-8"))
if observed_classes != policy["mandatory_selection_classes"]:
    refuse(
        "mandatory dependency classes are incomplete: "
        f"expected={policy['mandatory_selection_classes']!r} observed={observed_classes!r}"
    )
by_path = {item["path"]: item for item in records}
toolchain = policy["toolchain"]
toolchain_records = [item for item in records if item["class"] == "toolchain-archive"]
if len(toolchain_records) != 1 or toolchain_records[0]["sha256"] != toolchain["sha256"]:
    refuse("downloaded AArch64 toolchain archive differs from policy")
source_records = [item for item in records if item["class"] == "buildroot-source"]
expected_source_archive = (
    policy["buildroot"]["source_destination"] + "/buildroot-source.tar"
)
if (
    len(source_records) != 1
    or source_records[0]["path"] != expected_source_archive
    or source_records[0]["sha256"] != policy["buildroot"]["source_archive_sha256"]
    or source_records[0]["bytes"] != policy["buildroot"]["source_archive_bytes"]
):
    refuse("Buildroot source must be the one exact deterministic Git archive")
for item in policy["amlogic_inputs"]:
    record = by_path.get(item["destination"])
    if (
        record is None
        or record["sha256"] != item["sha256"]
        or record["bytes"] != item["bytes"]
    ):
        refuse(f"materialized Amlogic input differs from policy: {item['name']}")

selection = {
    "schema": SELECTION_SCHEMA,
    "source_commit": source_commit,
    "builder_image": builder_image,
    "toolchain_id": toolchain_id,
    "inputs": records,
}
raw = canonical(selection)
if mode == "create":
    descriptor = os.open(
        selection_path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                refuse("short dependency selection write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
elif mode == "verify":
    retained = selection_path.read_bytes()
    if retained != raw:
        refuse("published dependency bytes differ from the exact selection")
else:
    refuse("unknown selection finalizer mode")
PY

# Source tools may leave cache scaffolding such as npm's empty `_cacache/tmp`.
# Empty directories are not selected dependencies and would make the host's
# exact directory ledger disagree. Prune them bottom-up before selection, while
# refusing links or unexpected removal errors.
python3 - "$RESULT_ROOT" <<'PY'
import errno
import os
from pathlib import Path
import stat
import sys

root = Path(os.path.abspath(sys.argv[1]))
root_metadata = os.lstat(root)
if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
    raise SystemExit("S19K_HERMETIC_MATERIALIZER_REFUSED: result root is not a real directory")
for current_raw, directories, _files in os.walk(root, topdown=False, followlinks=False):
    current = Path(current_raw)
    for name in directories:
        candidate = current / name
        metadata = os.lstat(candidate)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise SystemExit(
                "S19K_HERMETIC_MATERIALIZER_REFUSED: result tree contains a linked directory"
            )
        try:
            candidate.rmdir()
        except OSError as error:
            if error.errno not in (errno.ENOTEMPTY, errno.EEXIST):
                raise SystemExit(
                    "S19K_HERMETIC_MATERIALIZER_REFUSED: could not prune empty materializer output directory"
                ) from error
for current_raw, directories, files in os.walk(root, topdown=True, followlinks=False):
    if Path(current_raw) != root and not directories and not files:
        raise SystemExit(
            "S19K_HERMETIC_MATERIALIZER_REFUSED: empty materializer output directory remains"
        )
PY

WORK_SELECTION=$WORK_ROOT/selection.json
python3 "$WORK_ROOT/finalize_selection.py" \
    create "$POLICY" "$RESULT_ROOT" "$WORK_SELECTION" \
    "$SOURCE_COMMIT" "$BUILDER_IMAGE" "$TOOLCHAIN_ID"

# Publish to a caller-selected absent path. A failure can leave only an
# unsealed partial directory; the success selection is written last and with
# O_EXCL, so the host sealer can never mistake an interruption for completion.
mkdir "$OUTPUT_ROOT" || fail "could not allocate fresh materialized output root"
(cd "$RESULT_ROOT" && tar -cf - .) | (cd "$OUTPUT_ROOT" && tar -xf -)
python3 "$WORK_ROOT/finalize_selection.py" \
    verify "$POLICY" "$OUTPUT_ROOT" "$WORK_SELECTION" \
    "$SOURCE_COMMIT" "$BUILDER_IMAGE" "$TOOLCHAIN_ID"

python3 - "$WORK_SELECTION" "$SELECTION_PATH" <<'PY'
import os
from pathlib import Path
import stat
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
metadata = os.lstat(source)
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1:
    raise SystemExit("selection source is not a single-link regular file")
raw = source.read_bytes()
descriptor = os.open(
    destination,
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_BINARY", 0)
    | getattr(os, "O_NOFOLLOW", 0),
    0o600,
)
try:
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise SystemExit("short final selection write")
        view = view[written:]
    os.fsync(descriptor)
finally:
    os.close(descriptor)
parent_fd = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
PY

python3 "$WORK_ROOT/finalize_selection.py" \
    verify "$POLICY" "$OUTPUT_ROOT" "$SELECTION_PATH" \
    "$SOURCE_COMMIT" "$BUILDER_IMAGE" "$TOOLCHAIN_ID"
python3 "$SNAPSHOT_HELPER" verify \
    --commit "$SOURCE_COMMIT" \
    "$SOURCE_DESCRIPTOR" >/dev/null ||
    fail "source snapshot failed its final exact-tree verification"

echo "S19K_HERMETIC_DEPENDENCIES_MATERIALIZED"
echo "source_commit=$SOURCE_COMMIT"
echo "builder_image=$BUILDER_IMAGE"
echo "toolchain_id=$TOOLCHAIN_ID"
echo "materialized_root=$OUTPUT_ROOT"
echo "selection=$SELECTION_PATH"
echo "work_root_retained=$WORK_ROOT"
echo "release_authority=false"
echo "install_authority=false"
echo "flash_authority=false"
