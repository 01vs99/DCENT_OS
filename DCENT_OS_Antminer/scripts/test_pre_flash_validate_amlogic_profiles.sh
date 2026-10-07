#!/bin/sh
# Offline regression test for every Amlogic rootfs-window package profile.
# No SSH, target discovery, uploads, block devices, or hardware are used.

set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
VALIDATOR="$SCRIPT_DIR/pre_flash_validate.sh"
EXTRACTOR="$SCRIPT_DIR/build_amlogic_native_install.sh"
PYTHON3=${PYTHON3:-python3}
TMPDIR_T=$(mktemp -d 2>/dev/null || echo "/tmp/dcent-amlogic-profiles.$$")
rm -rf "$TMPDIR_T"
mkdir -p "$TMPDIR_T"
trap 'rm -rf "$TMPDIR_T"' EXIT HUP INT TERM

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

pass() {
    printf 'PASS: %s\n' "$*"
}

make_package() {
    board=$1
    tar_name=$2
    installable=${3:-true}
    if [ "$installable" = "false" ]; then
        toolbox_fields='"install_command": null, "update_command": null, "upload_endpoint": null, "board_target_header": null, "requires_inactive_slot": false, "install_mode": "package_only_denied", "target_side_sysupgrade": false'
    else
        toolbox_fields='"install_command": "dcent install <ip> -f <artifact> --artifact-dir <restore_verified_dir>", "update_command": "dcent ota update-fleet <ip> -f <artifact> --artifact-dir <restore_verified_dir>", "upload_endpoint": "/cgi-bin/upgrade.cgi", "board_target_header": "X-DCENT-Board-Target", "requires_inactive_slot": false, "install_mode": "target_sysupgrade", "target_side_sysupgrade": true'
    fi
    pkgdir="$TMPDIR_T/sysupgrade-$board"

    rm -rf "$pkgdir"
    mkdir -p "$pkgdir"
    # Donor Amlogic kernel shape: 56 header bytes then the arm64 Image
    # magic "ARM\x64" at 0x38 (the only kernel form am3 producers ship).
    dd if=/dev/zero of="$pkgdir/kernel" bs=1 count=56 2>/dev/null
    printf '\101\122\115\144kernel\n' >> "$pkgdir/kernel"
    printf '\047\005\031\126root\n' > "$pkgdir/root"
    printf 'board=%s\n' "$board" > "$pkgdir/METADATA"

    kernel_size=$(wc -c < "$pkgdir/kernel" | tr -d ' ')
    root_size=$(wc -c < "$pkgdir/root" | tr -d ' ')
    metadata_size=$(wc -c < "$pkgdir/METADATA" | tr -d ' ')
    kernel_sha=$(sha256sum "$pkgdir/kernel" | awk '{ print $1 }')
    root_sha=$(sha256sum "$pkgdir/root" | awk '{ print $1 }')
    metadata_sha=$(sha256sum "$pkgdir/METADATA" | awk '{ print $1 }')

    cat > "$pkgdir/MANIFEST.json" <<EOF
{
  "schema": 1,
  "manifest_profile": "dcentos.sysupgrade-unsigned-lab/v1",
  "product": "DCENT_OS",
  "package_type": "sysupgrade",
  "installable": $installable,
  "artifact_maturity": "experimental",
  "board": "$board",
  "board_target": "$board",
  "version": "0.0.0-test",
  "status": "lab_unsigned",
  "toolbox": { $toolbox_fields },
  "payloads": {
    "kernel": { "path": "sysupgrade-$board/kernel", "size": $kernel_size, "sha256": "$kernel_sha" },
    "rootfs": { "path": "sysupgrade-$board/root", "size": $root_size, "sha256": "$root_sha" },
    "metadata": { "path": "sysupgrade-$board/METADATA", "size": $metadata_size, "sha256": "$metadata_sha" }
  }
}
EOF
    (cd "$pkgdir" && sha256sum kernel root METADATA > SHA256SUMS)
    (cd "$TMPDIR_T" && tar cf "$tar_name" "sysupgrade-$board")
}

check_profile() {
    board=$1
    variant=$2
    tar_name=$3
    bin_name=$4

    make_package "$board" "$tar_name"
    DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 DCENT_PACKAGE_STATUS=lab_unsigned \
        sh "$VALIDATOR" --package-only "$TMPDIR_T/$tar_name" "$board" >/dev/null \
        || fail "$board package profile was rejected"
    pass "$board package profile validates offline"
    DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 DCENT_PACKAGE_STATUS=lab_unsigned \
        DCENT_REQUIRE_INSTALLABLE_PACKAGE=1 \
        sh "$VALIDATOR" --package-only "$TMPDIR_T/$tar_name" "$board" >/dev/null \
        || fail "$board installable package was rejected by the writer-authority gate"
    pass "$board installable package satisfies the writer-authority gate"

    DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 DCENT_PACKAGE_STATUS=lab_unsigned \
        bash "$EXTRACTOR" --variant "$variant" --output-dir "$TMPDIR_T" --lab-unsigned >/dev/null \
        || fail "$variant native-install extraction was rejected"
    [ -f "$TMPDIR_T/$bin_name" ] || fail "$variant extractor did not emit $bin_name"
    [ "$(od -An -N4 -tx1 "$TMPDIR_T/$bin_name" | tr -d ' \n')" = 27051956 ] \
        || fail "$variant extractor emitted a non-uImage root payload"
    pass "$variant extraction emits the expected rootfs-window image"
}

check_profile am3-s19k s19kpro dcentos-sysupgrade-am3-s19kpro.tar dcentos-amlogic-s19kpro.bin
check_profile am3-s21 s21 dcentos-sysupgrade-am3-s21.tar dcentos-amlogic-s21.bin
check_profile am3-s21pro s21pro dcentos-sysupgrade-am3-s21pro.tar dcentos-amlogic-s21pro.bin

# am3-s19jpro-aml, am3-s19jproplus, am3-s19jproa and the other A113D
# denied boards emit package_only_denied manifests (no persistent-writer
# authority; am3-s19jpro-aml unconditionally) — reconciled with
# PACKAGE_ONLY_DENIED_TARGETS after producer run drop1-20260918-xtleogkg;
# they validate like the other denied boards and refuse extraction.
make_package am3-t21 dcentos-sysupgrade-am3-t21.tar false
make_package am3-s21xp dcentos-sysupgrade-am3-s21xp.tar false
make_package am3-s19xp dcentos-sysupgrade-am3-s19xp.tar false
make_package am3-s19jxp dcentos-sysupgrade-am3-s19jxp.tar false
make_package am3-s19jproa dcentos-sysupgrade-am3-s19jproa.tar false
make_package am3-s19jproplus dcentos-sysupgrade-am3-s19jproplus.tar false
make_package am3-s19jpro-aml dcentos-sysupgrade-am3-s19jpro-aml.tar false
make_package am3-s19kpro dcentos-sysupgrade-am3-s19kpro-denied.tar false
printf '#!/bin/sh\nexit 97\n' > "$TMPDIR_T/poison-am3-geometry.sh"
for package_only_case in \
    'am3-s19xp:s19xp:dcentos-sysupgrade-am3-s19xp.tar' \
    'am3-s19jxp:s19jxp:dcentos-sysupgrade-am3-s19jxp.tar' \
    'am3-s21xp:s21xp:dcentos-sysupgrade-am3-s21xp.tar' \
    'am3-s19jproa:s19jproa:dcentos-sysupgrade-am3-s19jproa.tar' \
    'am3-s19jproplus:s19jproplus:dcentos-sysupgrade-am3-s19jproplus.tar' \
    'am3-s19jpro-aml:s19jpro-aml:dcentos-sysupgrade-am3-s19jpro-aml.tar' \
    'am3-s19kpro:s19kpro:dcentos-sysupgrade-am3-s19kpro-denied.tar'
do
    board=${package_only_case%%:*}
    remainder=${package_only_case#*:}
    variant=${remainder%%:*}
    tar_name=${remainder#*:}
    DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 DCENT_PACKAGE_STATUS=lab_unsigned \
        AM3_GEOMETRY_HELPER="$TMPDIR_T/poison-am3-geometry.sh" \
        sh "$VALIDATOR" --package-only "$TMPDIR_T/$tar_name" "$board" >/dev/null \
        || fail "$board package-only profile was rejected"
    pass "$board non-installable package structure validates without importing flash geometry"
    if bash "$EXTRACTOR" --variant "$variant" --output-dir "$TMPDIR_T" --lab-unsigned >/dev/null 2>&1; then
        fail "$variant native-install extraction was unexpectedly admitted"
    fi
    pass "$variant native-install extraction is refused"
done
DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 DCENT_PACKAGE_STATUS=lab_unsigned \
    AM3_GEOMETRY_HELPER="$TMPDIR_T/poison-am3-geometry.sh" \
    sh "$VALIDATOR" --package-only "$TMPDIR_T/dcentos-sysupgrade-am3-t21.tar" am3-t21 >/dev/null \
    || fail "am3-t21 package-only profile was rejected"
pass "am3-t21 non-installable package structure validates without importing flash geometry"
if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 DCENT_PACKAGE_STATUS=lab_unsigned \
    DCENT_REQUIRE_INSTALLABLE_PACKAGE=1 \
    sh "$VALIDATOR" --package-only "$TMPDIR_T/dcentos-sysupgrade-am3-t21.tar" am3-t21 >/dev/null 2>&1; then
    fail "am3-t21 inspection-only package was admitted as writer authority"
fi
pass "inspection-only package is refused when a writer requires installable=true"
if bash "$EXTRACTOR" --variant t21 --output-dir "$TMPDIR_T" --lab-unsigned >/dev/null 2>&1; then
    fail "t21 native-install extraction was unexpectedly admitted"
else
    pass "t21 remains package-validation-only with no native-install extraction"
fi

check_output_alias_refused() {
    alias_kind=$1
    alias_dir="$TMPDIR_T/alias-$alias_kind"
    mkdir -p "$alias_dir"
    cp "$TMPDIR_T/dcentos-sysupgrade-am3-s21.tar" "$alias_dir/"
    printf 'do-not-overwrite\n' > "$alias_dir/victim"
    case "$alias_kind" in
        symlink) ln -s "$alias_dir/victim" "$alias_dir/dcentos-amlogic-s21.bin" ;;
        hardlink) ln "$alias_dir/victim" "$alias_dir/dcentos-amlogic-s21.bin" ;;
        *) fail "unknown alias fixture: $alias_kind" ;;
    esac
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 DCENT_PACKAGE_STATUS=lab_unsigned \
        bash "$EXTRACTOR" --variant s21 --output-dir "$alias_dir" --lab-unsigned >/dev/null 2>&1; then
        fail "$alias_kind native-image destination was overwritten"
    fi
    [ "$(cat "$alias_dir/victim")" = "do-not-overwrite" ] \
        || fail "$alias_kind native-image refusal modified the aliased victim"
    pass "$alias_kind native-image output alias is refused without modifying its victim"
}

check_output_alias_refused symlink
check_output_alias_refused hardlink

make_package am3-s21 swapped-hashes.tar
"$PYTHON3" - "$TMPDIR_T/sysupgrade-am3-s21/MANIFEST.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
manifest = json.loads(path.read_text(encoding="utf-8"))
kernel = manifest["payloads"]["kernel"]
rootfs = manifest["payloads"]["rootfs"]
kernel_hash = kernel["sha256"]
rootfs_hash = rootfs["sha256"]
kernel["sha256"] = rootfs_hash
rootfs["sha256"] = kernel_hash
# These decoys made the old global grep checks pass even though each payload
# object named the wrong digest.
manifest["kernel_sha_decoy"] = kernel_hash
manifest["rootfs_sha_decoy"] = rootfs_hash
path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
PY
(cd "$TMPDIR_T" && tar cf swapped-hashes.tar sysupgrade-am3-s21)
if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 DCENT_PACKAGE_STATUS=lab_unsigned \
    sh "$VALIDATOR" --package-only "$TMPDIR_T/swapped-hashes.tar" am3-s21 >/dev/null 2>&1; then
    fail "swapped payload-object hashes passed through misleading global strings"
fi
pass "swapped payload-object hashes and misleading strings are rejected"

make_package am3-unknown dcentos-sysupgrade-am3-unknown.tar
if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 DCENT_PACKAGE_STATUS=lab_unsigned \
    sh "$VALIDATOR" --package-only "$TMPDIR_T/dcentos-sysupgrade-am3-unknown.tar" am3-unknown >/dev/null 2>&1; then
    fail "unknown Amlogic-like board bypassed the explicit payload-profile gate"
fi
pass "unknown board remains fail-closed"

printf 'All Amlogic package-profile tests passed.\n'
