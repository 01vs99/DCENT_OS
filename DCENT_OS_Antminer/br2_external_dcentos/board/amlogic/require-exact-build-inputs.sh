#!/bin/sh
# Fail-closed admission for model-bound A113D kernel/DTB packaging inputs.
# This validates only offline build inputs. It grants no device write authority.

dcent_amlogic_input_fail() {
    echo "ERROR: $*" >&2
    return 1
}

dcent_amlogic_require_regular_file() {
    dcent_input_path=$1
    dcent_input_label=$2
    if [ -z "$dcent_input_path" ] || [ ! -f "$dcent_input_path" ] || [ -L "$dcent_input_path" ]; then
        dcent_amlogic_input_fail \
            "$dcent_input_label must be a non-symlink regular file from the private build-input snapshot"
        return 1
    fi
}

dcent_amlogic_require_digest() {
    dcent_input_path=$1
    dcent_expected_size=$2
    dcent_expected_sha256=$3
    dcent_input_label=$4

    dcent_actual_size=$(stat -c%s "$dcent_input_path") || return 1
    if [ "$dcent_actual_size" != "$dcent_expected_size" ]; then
        dcent_amlogic_input_fail \
            "$dcent_input_label size mismatch: expected $dcent_expected_size, got $dcent_actual_size"
        return 1
    fi
    dcent_actual_sha256=$(sha256sum "$dcent_input_path" | awk '{print $1}') || return 1
    if [ "$dcent_actual_sha256" != "$dcent_expected_sha256" ]; then
        dcent_amlogic_input_fail \
            "$dcent_input_label SHA256 mismatch: expected $dcent_expected_sha256, got $dcent_actual_sha256"
        return 1
    fi
}

dcent_require_exact_amlogic_build_inputs() {
    dcent_build_target=$1
    # Reset per-call so a prior arm's donor generation cannot leak into a
    # later invocation within the same shell.
    unset dcent_expected_build_name dcent_expected_fw_version
    case "$dcent_build_target" in
        am3-s19jpro-aml)
            dcent_expected_model=s19jpro
            dcent_expected_fw_info_sha256=f1c495fb5d70e619602eefc1764aface200fd53c29e92f4b23ffd4b003eb018e
            dcent_expected_fw_info_size=278
            ;;
        am3-s19jproa)
            dcent_expected_model=s19jpro-a
            dcent_expected_fw_info_sha256=3625d6f454aa398e3d8855791e32a6adcddca5d986d3151865095cb9b19dbe92
            dcent_expected_fw_info_size=282
            ;;
        am3-s19jproplus)
            dcent_expected_model=s19jpro-plus
            dcent_expected_fw_info_sha256=853eab52798c2e564e6c8edb47967bbbafae54e83328a33d31ddd0ae0ff0ed15
            dcent_expected_fw_info_size=284
            ;;
        am3-s19xp)
            dcent_expected_model=s19xp
            dcent_expected_fw_info_sha256=d2b87592ccf14a7d934c61db4a214b519ed991088663ecaadc0e70b5e12c6c79
            dcent_expected_fw_info_size=274
            ;;
        am3-s19jxp)
            dcent_expected_model=s19j-xp
            dcent_expected_fw_info_sha256=656e892b34d6559f59bd7c4b8f64234d1931b337db38caa89353d936d746e92c
            dcent_expected_fw_info_size=277
            ;;
        am3-s19kpro)
            dcent_expected_model=s19kpro
            dcent_expected_fw_info_sha256=2c2aca134728f17e853701ad860956de933f96a0ada5b0eeae42d6e338af8710
            dcent_expected_fw_info_size=278
            ;;
        am3-s19kpro-nopic)
            # Exact S19k Pro NoPic image lane. Distinct vnish 1.2.7 NAND donor
            # identity (build_name vnishfirmwarecom); sibling-model and the
            # legacy vnishfarm 1.2.6-rc5 s19kpro identity are both refused.
            dcent_expected_model=s19kpro
            dcent_expected_fw_info_sha256=e9a976cef48abced73e240afbd70d7c15310f7fe65c1d83b9910d1545b0bec0a
            dcent_expected_fw_info_size=299
            dcent_expected_build_name=vnishfirmwarecom
            dcent_expected_fw_version=1.2.7
            ;;
        am3-s21)
            dcent_expected_model=s21
            dcent_expected_fw_info_sha256=bf32b8780802346d7ec433feeee82f7f24199f6b69505d4da46d4d7d68c7ef14
            dcent_expected_fw_info_size=269
            ;;
        am3-s21pro)
            dcent_expected_model=s21pro
            dcent_expected_fw_info_sha256=eb26f9b22fdfc806fd612b5e11284541b9c8bf6836d3fcdaa4d97e5d5791bba5
            dcent_expected_fw_info_size=276
            ;;
        am3-s21xp)
            dcent_expected_model=s21xp
            dcent_expected_fw_info_sha256=1555b13eeec9be880c0df19ad626308bbc45d8a2117738296b5122201c99ffce
            dcent_expected_fw_info_size=274
            ;;
        am3-t21)
            dcent_expected_model=t21
            dcent_expected_fw_info_sha256=24699f1a8a3b279d22853d173dd8803fdd93dd2dc1cf1f3a0ec403c717189ece
            dcent_expected_fw_info_size=269
            ;;
        *)
            dcent_amlogic_input_fail \
                "unadmitted Amlogic build target: ${dcent_build_target:-<missing>}"
            return 1
            ;;
    esac

    dcent_amlogic_require_regular_file \
        "${DCENT_AM3_AML_KERNEL:-}" "Amlogic kernel input" || return 1
    dcent_amlogic_require_regular_file \
        "${DCENT_AM3_AML_DTB:-}" "Amlogic DTB input" || return 1
    dcent_amlogic_require_regular_file \
        "${DCENT_AM3_AML_FW_INFO:-}" "Amlogic fw-info identity input" || return 1

    dcent_amlogic_require_digest \
        "$DCENT_AM3_AML_KERNEL" 14960648 \
        d5013ac9f545df3b0792ea2cd8902b51e323bbb6f73ff0fea17bbee9f6157fe6 \
        "Amlogic kernel input" || return 1
    dcent_amlogic_require_digest \
        "$DCENT_AM3_AML_DTB" 20945 \
        540c1770543d9620e106ea4287c2a534f5efd85c912e97d6be6295930506b257 \
        "Amlogic DTB input" || return 1
    dcent_amlogic_require_digest \
        "$DCENT_AM3_AML_FW_INFO" "$dcent_expected_fw_info_size" \
        "$dcent_expected_fw_info_sha256" "Amlogic fw-info identity input" || return 1

    # Arms may pin a distinct donor generation; the retained vnishfarm
    # 1.2.6-rc5 identity stays the default so earlier arms are unchanged.
    : "${dcent_expected_build_name:=vnishfarm}"
    : "${dcent_expected_fw_version:=1.2.6-rc5}"
    python3 - "$DCENT_AM3_AML_FW_INFO" "$dcent_expected_model" \
        "$dcent_expected_build_name" "$dcent_expected_fw_version" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected_model = sys.argv[2]
expected_build_name = sys.argv[3]
expected_fw_version = sys.argv[4]
try:
    identity = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"invalid exact Amlogic fw-info: {error}")

expected = {
    "build_name": expected_build_name,
    "fw_version": expected_fw_version,
    "install_type": "nand",
    "model": expected_model,
    "platform": "aml",
}
observed = {key: identity.get(key) for key in expected}
if observed != expected:
    raise SystemExit(
        f"exact Amlogic fw-info identity mismatch: expected {expected!r}, got {observed!r}"
    )
PY
    echo "Exact Amlogic build inputs: target=$dcent_build_target model=$dcent_expected_model platform=aml"
}
