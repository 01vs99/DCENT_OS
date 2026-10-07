#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
REPO_ROOT=$(CDPATH= cd -- "$PROJECT_DIR/../.." && pwd)
HELPER="$PROJECT_DIR/br2_external_dcentos/board/amlogic/require-exact-build-inputs.sh"
BUILD_DRIVER="$SCRIPT_DIR/build_in_docker.sh"
HELD_ASSETS=$(python3 "$SCRIPT_DIR/held_assets.py" --repo-root "$REPO_ROOT")
export DCENT_HELD_ASSETS="$HELD_ASSETS"

python3 - "$SCRIPT_DIR/source_closure.py" "$SCRIPT_DIR/build_inputs.manifest" "$REPO_ROOT" <<'PY'
import hashlib
import importlib.util
import json
import pathlib
import sys

source_closure_path = pathlib.Path(sys.argv[1]).resolve()
manifest_path = pathlib.Path(sys.argv[2]).resolve()
repo_root = pathlib.Path(sys.argv[3]).resolve()
sys.path.insert(0, str(source_closure_path.parent))
from held_assets import held_root
assets = held_root(repo_root)
spec = importlib.util.spec_from_file_location("source_closure", source_closure_path)
assert spec is not None and spec.loader is not None
source_closure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source_closure)

expected_models = {
    "am3-s19jpro-aml": "s19jpro",
    "am3-s19jproplus": "s19jpro-plus",
    "am3-s19jproa": "s19jpro-a",
    "am3-s19xp": "s19xp",
    "am3-s19jxp": "s19j-xp",
    "am3-s19kpro": "s19kpro",
    "am3-s21": "s21",
    "am3-s21pro": "s21pro",
    "am3-s21xp": "s21xp",
    "am3-t21": "t21",
}
expected_archive_sha256 = {
    "s19jpro": "cb2b1fcf49417296bd1a8aa280bd7a51fe7162f08819c4927994b0b87f38017d",
    "s19jpro-plus": "a2c6bad19a4376b410c79b49c5cfbef4a946684c765ab055a447057edcbf9ad3",
    "s19jpro-a": "6d3668d28b4eea49cd45f1ae640e4b08cd5e0e943fd189d54872b86470658580",
    "s19xp": "1c197fb3a7176cfdde45ba08b08eaaee9ce94f44dab8220104831c52eeec7b11",
    "s19j-xp": "0511e1a46ce10b25be83eda6c782f8704733fdc3467dacd265b54130539bce59",
    "s19kpro": "063a3f5128c3a12896124463ce4ca7e44005627cf6a48da85638675bec03c12a",
    "s21": "89784d30df48d3776fce3659cb354e27c809f41fed192e27d23611dd2e88053a",
    "s21pro": "b325ea491e4665fce20de1007218c8298fb01256917598b3e9302c38e24864fd",
    "s21xp": "29ff16ad122b4ae2e76ee42d7fbddc9e31b3bfff9b03f4b49db0d4a3d1e25bcb",
    "t21": "2398639097f937d3c7a4aa134e6f69d9c106de1fb1cae3b34c63ebcfe25862d1",
}
assert source_closure.AMLOGIC_EXACT_MODEL_BY_TARGET == {**expected_models, "am3-s19kpro-nopic": "s19kpro"}
assert set(expected_models).isdisjoint(source_closure.BLOCKED_BUILD_INPUT_TARGETS)
assert not ({"am3-s19", "am3-s21plus"} & set(source_closure.TARGET_BUILD_INPUTS))

_, manifest = source_closure.parse_build_input_manifest(repo_root, str(manifest_path))
kernel_hashes = set()
dtb_hashes = set()
fw_info_hashes = set()
for target, model in expected_models.items():
    inputs = source_closure.TARGET_BUILD_INPUTS[target]
    prefix = (
        f"knowledge-base/extractions/vnish-farm/{model}/"
        "vnishfarm-1.2.6-rc5-aml-nand-install/"
    )
    assert inputs == (
        prefix + "vmlinux.bin",
        prefix + "devicetree.dtb",
        prefix + "rootfs/etc/fw-info",
    )
    assert set(inputs) <= set(manifest)
    evidence = source_closure.build_input_evidence(repo_root, str(manifest_path), target, assets=assets)
    assert {item["path"] for item in evidence["files"]} == set(inputs)
    policy = source_closure.BUILD_TARGET_POLICIES[target]
    assert policy["arch"] == "aarch64-unknown-linux-musl"
    assert policy["configs"][1].endswith("dcentos_am3_aml_common.fragment")
    assert source_closure.PREBUILT_RUST_INPUTS_BY_TARGET[target] == (
        "dcentos-init",
        "dcentrald",
    )
    assert source_closure.PREBUILT_RUST_VARIANT_BY_TARGET[target] == "amlogic"

    kernel, dtb, fw_info = (assets / pathlib.PurePosixPath(name).relative_to("knowledge-base") for name in inputs)
    identity = json.loads(fw_info.read_text(encoding="utf-8"))
    assert identity["model"] == model
    assert identity["platform"] == "aml"
    assert identity["install_type"] == "nand"
    assert identity["build_name"] == "vnishfarm"
    assert identity["fw_version"] == "1.2.6-rc5"
    kernel_hashes.add(hashlib.sha256(kernel.read_bytes()).hexdigest())
    dtb_hashes.add(hashlib.sha256(dtb.read_bytes()).hexdigest())
    fw_info_hashes.add(hashlib.sha256(fw_info.read_bytes()).hexdigest())

    summary = json.loads((kernel.parent / "_summary.json").read_text(encoding="utf-8"))
    assert summary["model"] == model
    assert summary["container_type"] == "tar.gz"
    assert summary["source"] == (
        "knowledge-base/firmware-archive/vnish-farm-2026-05-01/antminer/"
        f"v1.2.6-rc5/{model}/vnishfarm-{model}-aml-nand-v1.2.6-rc5-install.tar.gz"
    )
    assert summary["source_sha256"] == expected_archive_sha256[model]
    source_archive = assets / pathlib.PurePosixPath(summary["source"]).relative_to("knowledge-base")
    assert source_archive.is_file()
    assert hashlib.sha256(source_archive.read_bytes()).hexdigest() == expected_archive_sha256[model]

assert kernel_hashes == {
    "d5013ac9f545df3b0792ea2cd8902b51e323bbb6f73ff0fea17bbee9f6157fe6"
}
assert dtb_hashes == {
    "540c1770543d9620e106ea4287c2a534f5efd85c912e97d6be6295930506b257"
}
assert len(fw_info_hashes) == len(expected_models)

# NoPic is a distinct 1.2.7 donor, not another 1.2.6-rc5 archive row. This
# extraction has no _summary.json; retain its three independently pinned
# inputs and exact fw-info identity rather than inventing summary provenance.
nopic = "am3-s19kpro-nopic"
prefix = "knowledge-base/extractions/re-armada/vnish-1.2.7-s19kpro-aml-nand-v1.2.7-install/"
inputs = tuple(prefix + name for name in ("vmlinux.bin", "devicetree.dtb", "rootfs/etc/fw-info"))
assert source_closure.TARGET_BUILD_INPUTS[nopic] == inputs
assert nopic not in source_closure.BLOCKED_BUILD_INPUT_TARGETS
evidence = source_closure.build_input_evidence(repo_root, str(manifest_path), nopic, assets=assets)
assert {item["path"] for item in evidence["files"]} == set(inputs)
expected = ("d5013ac9f545df3b0792ea2cd8902b51e323bbb6f73ff0fea17bbee9f6157fe6",
            "540c1770543d9620e106ea4287c2a534f5efd85c912e97d6be6295930506b257",
            "e9a976cef48abced73e240afbd70d7c15310f7fe65c1d83b9910d1545b0bec0a")
for name, digest in zip(inputs, expected):
    assert manifest[name] == digest
    assert hashlib.sha256((assets / pathlib.PurePosixPath(name).relative_to("knowledge-base")).read_bytes()).hexdigest() == digest
identity = json.loads((assets / pathlib.PurePosixPath(inputs[-1]).relative_to("knowledge-base")).read_text(encoding="utf-8"))
assert (identity["model"], identity["platform"], identity["install_type"], identity["fw_version"], identity["build_name"]) == (
    "s19kpro", "aml", "nand", "1.2.7", "vnishfirmwarecom")
assert source_closure.BUILD_TARGET_POLICIES[nopic]["configs"][-1].endswith("dcentos_am3_s19kpro_nopic_defconfig")
assert source_closure.PREBUILT_RUST_VARIANT_BY_TARGET[nopic] == "amlogic"
PY

# The build driver must supply all three read-only snapshot members, and every
# concrete post-image implementation must repeat the exact-identity gate.
grep -Fq 'DCENT_AM3_AML_KERNEL="${AMLOGIC_EXACT_CONTAINER_ROOT:+${AMLOGIC_EXACT_CONTAINER_ROOT}/vmlinux.bin}"' "$BUILD_DRIVER"
grep -Fq 'DCENT_AM3_AML_DTB="${AMLOGIC_EXACT_CONTAINER_ROOT:+${AMLOGIC_EXACT_CONTAINER_ROOT}/devicetree.dtb}"' "$BUILD_DRIVER"
grep -Fq 'DCENT_AM3_AML_FW_INFO="${AMLOGIC_EXACT_CONTAINER_ROOT:+${AMLOGIC_EXACT_CONTAINER_ROOT}/rootfs/etc/fw-info}"' "$BUILD_DRIVER"
grep -Fq 'dcent_require_exact_amlogic_build_inputs "$TARGET"' "$BUILD_DRIVER"

for board in am3-s19jpro-aml am3-s19kpro am3-s21 am3-s21pro am3-s21xp am3-t21; do
    post_image="$PROJECT_DIR/br2_external_dcentos/board/amlogic/$board/post-image.sh"
    case "$board" in
        am3-s21|am3-s21pro|am3-s21xp|am3-t21)
            grep -Fq 'post-image-family.sh" --board-target ' "$post_image"
            post_image="$PROJECT_DIR/br2_external_dcentos/board/amlogic/post-image-family.sh"
            ;;
    esac
    grep -Fq 'dcent_require_exact_amlogic_build_inputs "${TARGET:-}"' "$post_image"
    if grep -Eq 'extractions/(s19j-aml|s19k|s21|t21)/kernel_uimage\.bin' "$post_image"; then
        echo "ERROR: $board still contains a live or sibling-model kernel fallback" >&2
        exit 1
    fi
done

# Exercise the shell gate against every real held fixture, then prove a
# cross-model identity and an absent DTB are refused.
. "$HELPER"
for target in am3-s19jpro-aml am3-s19jproplus am3-s19jproa am3-s19xp am3-s19jxp am3-s19kpro am3-s19kpro-nopic am3-s21 am3-s21pro am3-s21xp am3-t21; do
    case "$target" in
        am3-s19jpro-aml) model=s19jpro ;;
        am3-s19jproplus) model=s19jpro-plus ;;
        am3-s19jproa) model=s19jpro-a ;;
        am3-s19xp) model=s19xp ;;
        am3-s19jxp) model=s19j-xp ;;
        am3-s19kpro|am3-s19kpro-nopic) model=s19kpro ;;
        am3-s21) model=s21 ;;
        am3-s21pro) model=s21pro ;;
        am3-s21xp) model=s21xp ;;
        am3-t21) model=t21 ;;
    esac
    fixture="$HELD_ASSETS/extractions/vnish-farm/$model/vnishfarm-1.2.6-rc5-aml-nand-install"
    if [ "$target" = am3-s19kpro-nopic ]; then
        fixture="$HELD_ASSETS/extractions/re-armada/vnish-1.2.7-s19kpro-aml-nand-v1.2.7-install"
    fi
    DCENT_AM3_AML_KERNEL="$fixture/vmlinux.bin"
    DCENT_AM3_AML_DTB="$fixture/devicetree.dtb"
    DCENT_AM3_AML_FW_INFO="$fixture/rootfs/etc/fw-info"
    dcent_require_exact_amlogic_build_inputs "$target" >/dev/null
done

s21_fixture="$HELD_ASSETS/extractions/vnish-farm/s21/vnishfarm-1.2.6-rc5-aml-nand-install"
s19xp_fixture="$HELD_ASSETS/extractions/vnish-farm/s19xp/vnishfarm-1.2.6-rc5-aml-nand-install"
if (
    fixture="$HELD_ASSETS/extractions/vnish-farm/s19kpro/vnishfarm-1.2.6-rc5-aml-nand-install"
    DCENT_AM3_AML_KERNEL="$fixture/vmlinux.bin"
    DCENT_AM3_AML_DTB="$fixture/devicetree.dtb"
    DCENT_AM3_AML_FW_INFO="$fixture/rootfs/etc/fw-info"
    dcent_require_exact_amlogic_build_inputs am3-s19kpro-nopic >/dev/null 2>&1
); then
    echo "ERROR: NoPic exact gate accepted the older 1.2.6 S19k donor" >&2
    exit 1
fi
if (
    DCENT_AM3_AML_KERNEL="$s21_fixture/vmlinux.bin"
    DCENT_AM3_AML_DTB="$s21_fixture/devicetree.dtb"
    DCENT_AM3_AML_FW_INFO="$s19xp_fixture/rootfs/etc/fw-info"
    dcent_require_exact_amlogic_build_inputs am3-s21 >/dev/null 2>&1
); then
    echo "ERROR: exact Amlogic gate accepted cross-model fw-info" >&2
    exit 1
fi
if (
    DCENT_AM3_AML_KERNEL="$s21_fixture/vmlinux.bin"
    DCENT_AM3_AML_DTB="$s21_fixture/missing-devicetree.dtb"
    DCENT_AM3_AML_FW_INFO="$s21_fixture/rootfs/etc/fw-info"
    dcent_require_exact_amlogic_build_inputs am3-s21 >/dev/null 2>&1
); then
    echo "ERROR: exact Amlogic gate accepted a missing DTB" >&2
    exit 1
fi

# Exercise the same private snapshot lifecycle used by build_in_docker.sh for
# one representative exact target. The policy/data checks above cover all
# eleven target selections; this covers their shared copy/verify/destroy path.
snapshot_path=""
snapshot_token=""
cleanup_snapshot() {
    if [ -n "$snapshot_path" ] && [ -n "$snapshot_token" ]; then
        python3 "$SCRIPT_DIR/build_input_snapshot.py" destroy \
            --token "$snapshot_token" "$snapshot_path" >/dev/null 2>&1 || true
    fi
}
trap cleanup_snapshot EXIT HUP INT TERM
snapshot_result=$(python3 "$SCRIPT_DIR/build_input_snapshot.py" create \
    --repo-root "$REPO_ROOT" \
    --held-assets "$HELD_ASSETS" \
    --build-input-manifest "$SCRIPT_DIR/build_inputs.manifest" \
    --target am3-s21)
snapshot_path=$(printf '%s\n' "$snapshot_result" \
    | python3 "$SCRIPT_DIR/build_input_snapshot.py" query-result --field snapshot)
snapshot_token=$(printf '%s\n' "$snapshot_result" \
    | python3 "$SCRIPT_DIR/build_input_snapshot.py" query-result --field destroy_token)
python3 "$SCRIPT_DIR/build_input_snapshot.py" verify \
    --target am3-s21 "$snapshot_path" >/dev/null
python3 "$SCRIPT_DIR/build_input_snapshot.py" destroy \
    --token "$snapshot_token" "$snapshot_path" >/dev/null
snapshot_path=""
snapshot_token=""
trap - EXIT HUP INT TERM

echo "Amlogic exact build inputs: PASS"
