#!/bin/sh
#
# Offline DCENT_OS CI gates. Checks use source and local fixtures; they do not
# contact miners, open SSH, upload packages, flash devices, or reboot hardware.

set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)

cd "$PROJECT_DIR"

STATIC_ONLY=0
FAIL_FAST=0
TIER=full
while [ "$#" -gt 0 ]; do
    case "$1" in
        --blocking|--nightly)
            if [ "$TIER" != full ]; then
                printf 'ERROR: choose only one gate tier.\n' >&2
                exit 2
            fi
            TIER=${1#--}
            ;;
        --static-only)
            STATIC_ONLY=1
            ;;
        --fail-fast)
            FAIL_FAST=1
            ;;
        -h|--help)
            printf 'Usage: %s [--blocking|--nightly|--static-only] [--fail-fast]\n' "$0"
            printf '  --blocking     Run local behavior, signing and storage safety tests.\n'
            printf '  --nightly      Run blocking tests, then all comprehensive gates.\n'
            printf '  --static-only  Keep legacy comprehensive checks without optional Cargo/cross probes.\n'
            printf '  --fail-fast    Exit immediately after the first failed gate.\n'
            exit 0
            ;;
        *)
            printf 'ERROR: unknown argument: %s\n' "$1" >&2
            exit 2
            ;;
    esac
    shift
done

if [ "$STATIC_ONLY" -eq 1 ] && [ "$TIER" != full ]; then
    printf 'ERROR: --static-only cannot be combined with a gate tier.\n' >&2
    exit 2
fi

# Keep the comprehensive path below intact. Literal shell delegation also lets
# the shell and Python ownership checkers follow every blocking test.
if [ "$TIER" = blocking ]; then
    exec sh scripts/test_blocking_gates.sh "$FAIL_FAST"
fi
if [ "$TIER" = nightly ]; then
    sh scripts/test_blocking_gates.sh "$FAIL_FAST"
    sh scripts/test_nightly_gates.sh "$FAIL_FAST"
fi

failures=0

pass() {
    printf 'PASS: %s\n' "$*"
}

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    failures=$((failures + 1))
    if [ "$FAIL_FAST" -eq 1 ]; then
        exit 1
    fi
}

require_file() {
    if [ -f "$1" ]; then
        pass "required file exists: $1"
    else
        fail "required file missing: $1"
    fi
}

require_pattern() {
    file=$1
    pattern=$2
    label=$3

    if [ ! -f "$file" ]; then
        fail "$label: missing file $file"
        return
    fi

    if grep -F -- "$pattern" "$file" >/dev/null 2>&1; then
        pass "$label"
    else
        fail "$label: missing pattern '$pattern' in $file"
    fi
}

require_line_regex() {
    file=$1
    pattern=$2
    label=$3

    if [ ! -f "$file" ]; then
        fail "$label: missing file $file"
        return
    fi

    if LC_ALL=C grep -E -- "$pattern" "$file" >/dev/null 2>&1; then
        pass "$label"
    else
        fail "$label: missing active anchored line matching '$pattern' in $file"
    fi
}

reject_pattern() {
    file=$1
    pattern=$2
    label=$3

    if [ ! -f "$file" ]; then
        fail "$label: missing file $file"
        return
    fi

    if grep -F -- "$pattern" "$file" >/dev/null 2>&1; then
        fail "$label: forbidden pattern '$pattern' in $file"
    else
        pass "$label"
    fi
}

am2_sysupgrade_environment_delegate_ok() {
    _am2_caller=$1
    _am2_helper=br2_external_dcentos/board/zynq/rootfs-overlay/usr/libexec/dcentos/am2-native-ota.sh
    [ -f "$_am2_caller" ] && [ -f "$_am2_helper" ] || return 1
    grep -Fxq 'AM2_OTA_HELPER="/usr/libexec/dcentos/am2-native-ota.sh"' "$_am2_caller" || return 1
    grep -Fxq '. "$AM2_OTA_HELPER"' "$_am2_caller" || return 1
    grep -Eq '^am2_ota_commit_script \|\| preflip_fail ' "$_am2_caller" || return 1
    grep -Fxq 'if ! am2_ota_apply_environment; then' "$_am2_caller" || return 1
    _am2_apply=$(sed -n '/^am2_ota_apply_environment()/,/^}/p' "$_am2_helper")
    printf '%s\n' "$_am2_apply" | grep -Fxq '    fw_setenv -c "$FW_ENV_CONFIG" --script "$FW_SETENV_SCRIPT" || AM2_OTA_ENV_WRITE_RC=$?' || return 1
    printf '%s\n' "$_am2_apply" | grep -Fxq '    fw_printenv -c "$FW_ENV_CONFIG" > "$_am2_readback" 2> "$_am2_errors" || return 1' || return 1
    printf '%s\n' "$_am2_apply" | grep -Fxq '    [ ! -s "$_am2_errors" ] || return 1' || return 1
    printf '%s\n' "$_am2_apply" | grep -Fxq '    if am2_ota_verify_snapshot after "$_am2_readback" 2> "$AM2_OTA_DIR/env.verify-after.errors"; then' || return 1
    printf '%s\n' "$_am2_apply" | grep -Fxq '    if am2_ota_verify_snapshot before "$_am2_readback" 2> "$AM2_OTA_DIR/env.verify-before.errors"; then'
}

sysupgrade_am2_variant_parity_check() {
    for file in \
        br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/usr/sbin/sysupgrade \
        br2_external_dcentos/board/zynq/am2-s19pro/rootfs-overlay/usr/sbin/sysupgrade \
        br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay/usr/sbin/sysupgrade
    do
        if [ ! -f "$file" ]; then
            fail "AM2 sysupgrade variant parity: missing $file"
            continue
        fi

        missing=0
        while IFS= read -r marker; do
            [ -n "$marker" ] || continue
            if ! grep -F -- "$marker" "$file" >/dev/null 2>&1; then
                fail "AM2 sysupgrade variant parity: $file missing '$marker'"
                missing=$((missing + 1))
            fi
        done <<'EOF'
WRONG_BOARD_EXIT=78
DCENT_SYSUPGRADE_OFFLINE_HARNESS
PACKAGE_SIG="$PACKAGE_SUBDIR/MANIFEST.sig"
PACKAGE_RELEASE_KEY="$PACKAGE_SUBDIR/release_ed25519.pub"
openssl pkeyutl -verify -rawin -pubin
verify_sha256 "$ROOTFS" "$ROOTFS_SHA"
verify_sha256 "$PACKAGE_KERNEL" "$KERNEL_SHA"
payload_fits_ubi_volume
EXPECTED_KERNEL_LEBS=23
EXPECTED_ROOTFS_LEBS=179
EXPECTED_ROOTFS_DATA_LEBS=210
. "$AM2_OTA_HELPER"
am2_ota_commit_script || preflip_fail
if ! am2_ota_apply_environment; then
upgrade_stage=0
REFUSING to fall back to raw dd/flash_erase/nandwrite
EOF

        if ! am2_sysupgrade_environment_delegate_ok "$file"; then
            fail "AM2 sysupgrade variant parity: $file lost the active complete-environment helper/writer/readback join"
            missing=$((missing + 1))
        fi
        if [ "$missing" -eq 0 ]; then
            pass "AM2 sysupgrade variant parity: $file keeps signing, hash, geometry, and env guards"
        fi
    done
}

make_release_verify_gate_check() {
    if [ ! -f Makefile ]; then
        fail "make release local verification gate: missing Makefile"
        return
    fi

    if awk '
        BEGIN { in_release = 0; verify_line = 0; capsule_line = 0; skip_line = 0 }
        /^release:/ { in_release = 1; next }
        in_release && /^[A-Za-z0-9_.-]+:/ { in_release = 0 }
        in_release && /\$\(MAKE\) verify/ { verify_line = NR }
        in_release && /scripts\/build_release_capsule\.sh/ { capsule_line = NR }
        in_release && /DCENT_SKIP_VERIFY/ { skip_line = NR }
        END {
            ok = verify_line > 0 && capsule_line > 0 && verify_line < capsule_line && skip_line == 0
            exit ok ? 0 : 1
        }
    ' Makefile; then
        pass "make release runs make verify before building release artifacts"
    else
        fail "make release must run make verify before the exact producer capsule driver and must not honor DCENT_SKIP_VERIFY"
    fi
}

precommit_skip_after_hygiene_check() {
    hook='scripts/git-hooks/pre-commit'

    if [ ! -f "$hook" ]; then
        fail "pre-commit skip ordering: missing $hook"
        return
    fi

    if awk '
        $0 == "reject_staged_repo_hygiene_violations" { hygiene_call = NR }
        index($0, "DCENT_SKIP_VERIFY:-0") { skip_line = NR }
        END { exit (hygiene_call > 0 && skip_line > 0 && hygiene_call < skip_line) ? 0 : 1 }
    ' "$hook"; then
        pass "pre-commit DCENT_SKIP_VERIFY bypass is after staged-path hygiene"
    else
        fail "pre-commit DCENT_SKIP_VERIFY bypass must remain after staged-path hygiene"
    fi
}

run_python_script() {
    script=$1
    shift

    if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys' >/dev/null 2>&1; then
        python3 "$script" "$@"
    elif command -v py >/dev/null 2>&1 && py -3 -c 'import sys' >/dev/null 2>&1; then
        py -3 "$script" "$@"
    elif command -v python >/dev/null 2>&1 && python -c 'import sys' >/dev/null 2>&1; then
        python "$script" "$@"
    else
        return 127
    fi
}

require_identical() {
    a=$1
    b=$2
    label=$3

    if [ ! -f "$a" ]; then
        fail "$label: missing file $a"
        return
    fi
    if [ ! -f "$b" ]; then
        fail "$label: missing file $b"
        return
    fi
    if cmp -s "$a" "$b"; then
        pass "$label"
    else
        fail "$label: $a and $b differ (must be byte-identical)"
    fi
}

check_no_cr() {
    file=$1

    if [ ! -f "$file" ]; then
        fail "line endings: missing file $file"
        return
    fi

    if LC_ALL=C grep "$(printf '\r')" "$file" >/dev/null 2>&1; then
        fail "line endings: CR byte found in $file"
    else
        pass "line endings: LF-only $file"
    fi
}

check_ascii() {
    file=$1

    if [ ! -f "$file" ]; then
        fail "ascii: missing file $file"
        return
    fi

    non_ascii_bytes=$(LC_ALL=C tr -d '\000-\177' < "$file" | wc -c | tr -d ' ')
    if [ "$non_ascii_bytes" != "0" ]; then
        fail "ascii: non-ASCII byte found in $file"
    else
        pass "ascii: ASCII-only $file"
    fi
}

syntax_shell() {
    file=$1
    first_line=$(sed -n '1p' "$file" 2>/dev/null || true)

    case "$first_line" in
        *bash*) printf '%s\n' bash ;;
        *) printf '%s\n' sh ;;
    esac
}

check_shell_syntax() {
    file=$1

    if [ ! -f "$file" ]; then
        fail "syntax: missing file $file"
        return
    fi

    shell_bin=$(syntax_shell "$file")
    if ! command -v "$shell_bin" >/dev/null 2>&1; then
        fail "syntax: $shell_bin is unavailable for $file"
        return
    fi

    if "$shell_bin" -n "$file"; then
        pass "syntax: $shell_bin -n $file"
    else
        fail "syntax: $shell_bin -n $file"
    fi
}

tracked_shell_files() {
    find scripts br2_external_dcentos \
        -type f \
        \( -name '*.sh' -o -path '*/etc/init.d/S*' \) \
        -print
}

tracked_lf_files() {
    for root in \
        scripts \
        br2_external_dcentos \
        ../dcentos-esp \
        ../dcentos-avalon \
        ../dcentaxe-avalon \
        ../dcentos-whatsminer \
        ../dcentos-innosilicon
    do
        [ -d "$root" ] || continue
        find "$root" \
            -type f \
            \( -name '*.sh' -o -path '*/rootfs-overlay/etc/init.d/S*' -o -name 'fw_env.config' \) \
            -print
    done | sort -u
}

pre_flash_package_only_selftest() {
    tmpdir=$(mktemp -d 2>/dev/null || echo "/tmp/dcentos-package-selftest.$$")
    rm -rf "$tmpdir"

    write_test_sysupgrade_package() {
        pkgdir=$1
        board=$2
        kernel_kind=$3
        root_kind=$4
        status=${5:-lab_unsigned}
        # AM1-A Drop-1 route-scoping fixtures: optional typed toolbox route
        # contract (empty = legacy manifest with no toolbox block) and an
        # optional truncated rootfs size (0 = tiny fitting root).
        route_install_mode=${6:-}
        route_root_size=${7:-0}

        if [ "$status" = "lab_unsigned" ]; then
            manifest_profile=dcentos.sysupgrade-unsigned-lab/v1
        else
            manifest_profile=dcentos.sysupgrade-authority/v1
        fi
        rm -rf "$pkgdir" || return 1
        mkdir -p "$pkgdir" || return 1

        case "$kernel_kind" in
            uimage) printf '\047\005\031\126kernel\n' > "$pkgdir/kernel" || return 1 ;;
            # Donor Amlogic kernel shape: 56 header bytes then the arm64
            # Image magic "ARM\x64" at 0x38 (what pre_flash_validate admits).
            arm64)
                dd if=/dev/zero of="$pkgdir/kernel" bs=1 count=56 2>/dev/null || return 1
                printf '\101\122\115\144kernel\n' >> "$pkgdir/kernel" || return 1
                ;;
            raw) printf 'raw-kernel\n' > "$pkgdir/kernel" || return 1 ;;
            *) return 1 ;;
        esac
        case "$root_kind" in
            uimage) printf '\047\005\031\126root\n' > "$pkgdir/root" || return 1 ;;
            squashfs) printf '\150\163\161\163root\n' > "$pkgdir/root" || return 1 ;;
            raw) printf 'raw-root\n' > "$pkgdir/root" || return 1 ;;
            *) return 1 ;;
        esac
        if [ "$route_root_size" -gt 4 ]; then
            if command -v truncate >/dev/null 2>&1; then
                truncate -s "$route_root_size" "$pkgdir/root" || return 1
            else
                dd if=/dev/zero of="$pkgdir/root" bs=1 count=1 seek=$((route_root_size - 1)) conv=notrunc >/dev/null 2>&1 || return 1
            fi
        fi
        printf 'board=%s\n' "$board" > "$pkgdir/METADATA" || return 1

        kernel_size=$(wc -c < "$pkgdir/kernel" | tr -d ' ') || return 1
        root_size=$(wc -c < "$pkgdir/root" | tr -d ' ') || return 1
        metadata_size=$(wc -c < "$pkgdir/METADATA" | tr -d ' ') || return 1
        kernel_sha=$(sha256sum "$pkgdir/kernel" | awk '{ print $1 }') || return 1
        root_sha=$(sha256sum "$pkgdir/root" | awk '{ print $1 }') || return 1
        metadata_sha=$(sha256sum "$pkgdir/METADATA" | awk '{ print $1 }') || return 1

        if [ "$route_install_mode" = "first_install_only" ]; then
            route_update_json=null
        elif [ -n "$route_install_mode" ]; then
            route_update_json='"dcent install <ip> -f dcentos-sysupgrade-118.tar"'
            route_install_mode=target_sysupgrade
        fi
        if [ -n "${route_install_mode:-}" ]; then
            toolbox_block=",
  \"toolbox\": {
    \"install_command\": \"dcent install <ip> -f dcentos-sysupgrade-118.tar\",
    \"update_command\": ${route_update_json:-null},
    \"upload_endpoint\": null,
    \"board_target_header\": null,
    \"requires_inactive_slot\": false,
    \"install_mode\": \"$route_install_mode\"
  }"
        else
            toolbox_block=""
        fi

        cat > "$pkgdir/MANIFEST.json" <<EOF || return 1
{
  "board": "$board",
  "schema": 1,
  "manifest_profile": "$manifest_profile",
  "product": "DCENT_OS",
  "package_type": "sysupgrade",
  "installable": true,
  "artifact_maturity": "experimental",
  "board_target": "$board",
  "status": "$status",
  "version": "test",
  "payloads": {
    "kernel": { "path": "sysupgrade-$board/kernel", "size": $kernel_size, "sha256": "$kernel_sha" },
    "rootfs": { "path": "sysupgrade-$board/root", "size": $root_size, "sha256": "$root_sha" },
    "metadata": { "path": "sysupgrade-$board/METADATA", "size": $metadata_size, "sha256": "$metadata_sha" }
  }$toolbox_block
}
EOF
        (cd "$pkgdir" && sha256sum kernel root METADATA > SHA256SUMS) || return 1
    }

    pkgdir="$tmpdir/sysupgrade-am3-s19k"
    write_test_sysupgrade_package "$pkgdir" am3-s19k arm64 uimage || return 1
    (cd "$tmpdir" && tar cf valid.tar sysupgrade-am3-s19k) || return 1

    if ! DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh --package-only "$tmpdir/valid.tar" am3-s19k >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    write_test_sysupgrade_package "$tmpdir/sysupgrade-am1-s9" am1-s9 uimage squashfs || return 1
    # write_test_sysupgrade_package assigns $pkgdir in POSIX-sh global scope, so the
    # am1-s9 build above clobbered the caller's am3-s19k pkgdir. Re-pin it before the
    # empty-version negative case (and the am3 rebuilds that follow) operate on am3.
    pkgdir="$tmpdir/sysupgrade-am3-s19k"
    sed 's/"version": "test"/"version": ""/' \
        "$pkgdir/MANIFEST.json" > "$pkgdir/MANIFEST.json.tmp" || return 1
    mv "$pkgdir/MANIFEST.json.tmp" "$pkgdir/MANIFEST.json" || return 1
    (cd "$tmpdir" && tar cf empty-version.tar sysupgrade-am3-s19k) || return 1
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh --package-only "$tmpdir/empty-version.tar" am3-s19k >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi
    write_test_sysupgrade_package "$pkgdir" am3-s19k arm64 uimage || return 1

    (cd "$tmpdir" && tar cf valid-s9.tar sysupgrade-am1-s9) || return 1
    if ! DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh --package-only "$tmpdir/valid-s9.tar" am1-s9 >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    # AM1-A Drop-1 route scoping (owner adjudication
    # AM1_S9_ROOTFS_WINDOW_ADJUDICATION Option A, 2026-09-15): an over-window
    # am1-s9 rootfs PASSES only with the typed first-install-only contract
    # (self-update explicitly denied); the same size CLAIMING the self-update
    # route fails closed at the geometry window.
    oversized_s9_root=$((134 * 124 * 1024 + 729088))
    write_test_sysupgrade_package "$tmpdir/sysupgrade-am1-s9" am1-s9 uimage squashfs \
        lab_unsigned first_install_only "$oversized_s9_root" || return 1
    (cd "$tmpdir" && tar cf fio-s9.tar sysupgrade-am1-s9) || return 1
    if ! DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh --package-only "$tmpdir/fio-s9.tar" am1-s9 >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi
    write_test_sysupgrade_package "$tmpdir/sysupgrade-am1-s9" am1-s9 uimage squashfs \
        lab_unsigned target_sysupgrade "$oversized_s9_root" || return 1
    (cd "$tmpdir" && tar cf tsu-s9.tar sysupgrade-am1-s9) || return 1
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh --package-only "$tmpdir/tsu-s9.tar" am1-s9 >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    # First-install capacity bound (merge-critic follow-up): the waiver is
    # bounded by the stock two-reboot transaction's HARD phase-2 volumes
    # (kernel -s 8MiB / rootfs -s 20MiB, stage1_builder.py:640/:642). A
    # first-install-only package past the 20 MiB rootfs volume must FAIL —
    # it has no installable route (mid-phase-2 abort otherwise).
    write_test_sysupgrade_package "$tmpdir/sysupgrade-am1-s9" am1-s9 uimage squashfs \
        lab_unsigned first_install_only $((20 * 1024 * 1024 + 1)) || return 1
    (cd "$tmpdir" && tar cf fio-cap-s9.tar sysupgrade-am1-s9) || return 1
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh --package-only "$tmpdir/fio-cap-s9.tar" am1-s9 >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    PY_TAR=
    PY_TAR_ARG=
    if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys' >/dev/null 2>&1; then
        PY_TAR=python3
    elif command -v py >/dev/null 2>&1 && py -3 -c 'import sys' >/dev/null 2>&1; then
        PY_TAR=py
        PY_TAR_ARG=-3
    elif command -v python >/dev/null 2>&1 && python -c 'import sys' >/dev/null 2>&1; then
        PY_TAR=python
    else
        rm -rf "$tmpdir"
        return 1
    fi
    "$PY_TAR" ${PY_TAR_ARG:-} - "$tmpdir/traversal.tar" <<'PY' || return 1
import pathlib
import sys
import tarfile

tar_path = pathlib.Path(sys.argv[1])
payload = b"evil\n"
info = tarfile.TarInfo("../evil")
info.size = len(payload)
with tarfile.open(tar_path, "w") as tf:
    import io
    tf.addfile(info, io.BytesIO(payload))
PY
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh --package-only "$tmpdir/traversal.tar" am3-s19k >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    "$PY_TAR" ${PY_TAR_ARG:-} - "$tmpdir/symlink.tar" <<'PY' || return 1
import pathlib
import sys
import tarfile

tar_path = pathlib.Path(sys.argv[1])
with tarfile.open(tar_path, "w") as tf:
    directory = tarfile.TarInfo("sysupgrade-am3-s19k/")
    directory.type = tarfile.DIRTYPE
    tf.addfile(directory)

    link = tarfile.TarInfo("sysupgrade-am3-s19k/link")
    link.type = tarfile.SYMTYPE
    link.linkname = "kernel"
    tf.addfile(link)
PY
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh --package-only "$tmpdir/symlink.tar" am3-s19k >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    write_test_sysupgrade_package "$tmpdir/sysupgrade-am3-s19k-badroot" am3-s19k arm64 squashfs || return 1
    rm -rf "$tmpdir/sysupgrade-am3-s19k" || return 1
    mv "$tmpdir/sysupgrade-am3-s19k-badroot" "$tmpdir/sysupgrade-am3-s19k" || return 1
    (cd "$tmpdir" && tar cf am3-squashfs-root.tar sysupgrade-am3-s19k) || return 1
    rm -rf "$tmpdir/sysupgrade-am3-s19k" || return 1
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh --package-only "$tmpdir/am3-squashfs-root.tar" am3-s19k >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    write_test_sysupgrade_package "$tmpdir/sysupgrade-am3-s21" am3-s21 arm64 uimage || return 1
    (cd "$tmpdir" && tar cf wrong-prefix.tar sysupgrade-am3-s21) || return 1
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh --package-only "$tmpdir/wrong-prefix.tar" am3-s19k >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    write_test_sysupgrade_package "$tmpdir/sysupgrade-am3-s19k" am3-s19k arm64 uimage || return 1
    root_size=$(wc -c < "$tmpdir/sysupgrade-am3-s19k/root" | tr -d ' ') || return 1
    sed 's/"size": '"$root_size"'/"size": 999999/' \
        "$tmpdir/sysupgrade-am3-s19k/MANIFEST.json" > "$tmpdir/sysupgrade-am3-s19k/MANIFEST.json.tmp" || return 1
    mv "$tmpdir/sysupgrade-am3-s19k/MANIFEST.json.tmp" "$tmpdir/sysupgrade-am3-s19k/MANIFEST.json" || return 1
    (cd "$tmpdir" && tar cf bad-manifest.tar sysupgrade-am3-s19k) || return 1
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh --package-only "$tmpdir/bad-manifest.tar" am3-s19k >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    if command -v openssl >/dev/null 2>&1; then
        openssl genpkey -algorithm Ed25519 -out "$tmpdir/release.key" >/dev/null 2>&1 || return 1
        openssl pkey -in "$tmpdir/release.key" -pubout -out "$tmpdir/release.pub" >/dev/null 2>&1 || return 1
        write_test_sysupgrade_package "$tmpdir/sysupgrade-am3-s19k" am3-s19k arm64 uimage || return 1
        kernel_size=$(wc -c < "$tmpdir/sysupgrade-am3-s19k/kernel" | tr -d ' ') || return 1
        root_size=$(wc -c < "$tmpdir/sysupgrade-am3-s19k/root" | tr -d ' ') || return 1
        metadata_size=$(wc -c < "$tmpdir/sysupgrade-am3-s19k/METADATA" | tr -d ' ') || return 1
        kernel_sha=$(sha256sum "$tmpdir/sysupgrade-am3-s19k/kernel" | awk '{ print $1 }') || return 1
        root_sha=$(sha256sum "$tmpdir/sysupgrade-am3-s19k/root" | awk '{ print $1 }') || return 1
        metadata_sha=$(sha256sum "$tmpdir/sysupgrade-am3-s19k/METADATA" | awk '{ print $1 }') || return 1
        cp -R "$pkgdir" "$tmpdir/sysupgrade-am3-s19k-signed" || return 1
        signed_dir="$tmpdir/sysupgrade-am3-s19k-signed"
        cp "$tmpdir/release.pub" "$signed_dir/release_ed25519.pub" || return 1
        pub_size=$(wc -c < "$signed_dir/release_ed25519.pub" | tr -d ' ') || return 1
        pub_sha=$(sha256sum "$signed_dir/release_ed25519.pub" | awk '{ print $1 }') || return 1
        cat > "$signed_dir/MANIFEST.json" <<EOF || return 1
{
  "product": "DCENT_OS",
  "schema": 1,
  "manifest_profile": "dcentos.sysupgrade-authority/v1",
  "package_type": "sysupgrade",
  "board": "am3-s19k",
  "installable": true,
  "artifact_maturity": "experimental",
  "board_target": "am3-s19k",
  "status": "release",
  "version": "test",
  "payloads": {
    "kernel": { "path": "sysupgrade-am3-s19k/kernel", "size": $kernel_size, "sha256": "$kernel_sha" },
    "rootfs": { "path": "sysupgrade-am3-s19k/root", "size": $root_size, "sha256": "$root_sha" },
    "metadata": { "path": "sysupgrade-am3-s19k/METADATA", "size": $metadata_size, "sha256": "$metadata_sha" },
    "verification_key": { "path": "sysupgrade-am3-s19k/release_ed25519.pub", "size": $pub_size, "sha256": "$pub_sha" }
  }
}
EOF
        (cd "$signed_dir" && sha256sum kernel root METADATA release_ed25519.pub > SHA256SUMS) || return 1
        openssl pkeyutl -sign -rawin -inkey "$tmpdir/release.key" -in "$signed_dir/MANIFEST.json" -out "$signed_dir/MANIFEST.sig" >/dev/null 2>&1 || return 1
        rm -rf "$tmpdir/sysupgrade-am3-s19k" || return 1
        mv "$signed_dir" "$tmpdir/sysupgrade-am3-s19k" || return 1
        (cd "$tmpdir" && tar cf signed.tar sysupgrade-am3-s19k) || return 1
        if ! DCENT_RELEASE_PUBKEY_FILE="$tmpdir/release.pub" sh scripts/pre_flash_validate.sh --package-only "$tmpdir/signed.tar" am3-s19k >/dev/null 2>&1; then
            rm -rf "$tmpdir"
            return 1
        fi
    fi

    rm -rf "$tmpdir"
    return 0
}

am3_geometry_static_selftest() {
    . scripts/lib/am3_geometry.sh || return 1
    [ "$DCENT_AM3_ROOTFS_MTD" = "/dev/mtd5" ] || return 1
    [ "$DCENT_AM3_ROOTFS_OFFSET_HEX" = "0x05100000" ] || return 1
    [ "$DCENT_AM3_ROOTFS_WINDOW_HEX" = "0x02800000" ] || return 1
    [ "$DCENT_AM3_ROOTFS_ERASE_COUNT" = "320" ] || return 1
    [ "$DCENT_AM3_ROOTFS_END_DEC" = "126877696" ] || return 1

    grep -F 'ROOTFS_OFFSET_HEX="$DCENT_AM3_ROOTFS_OFFSET_HEX"' scripts/install_amlogic_persistent.sh >/dev/null 2>&1 || return 1
    grep -F 'ROOTFS_WINDOW_HEX="$DCENT_AM3_ROOTFS_WINDOW_HEX"' scripts/install_amlogic_persistent.sh >/dev/null 2>&1 || return 1
    grep -F 'ROOTFS_OFFSET_HEX="$DCENT_AM3_ROOTFS_OFFSET_HEX"' scripts/amlogic_lab_rootfs.sh >/dev/null 2>&1 || return 1
    grep -F 'ROOTFS_WINDOW_HEX="$DCENT_AM3_ROOTFS_WINDOW_HEX"' scripts/amlogic_lab_rootfs.sh >/dev/null 2>&1 || return 1
    grep -F 'ROOTFS_OFFSET="$DCENT_AM3_ROOTFS_OFFSET_HEX"' scripts/revert_to_stock_am3_aml_s19k.sh >/dev/null 2>&1 || return 1
    grep -F 'ROOTFS_MTD="$DCENT_AM3_ROOTFS_MTD"' scripts/revert_to_stock_am3_aml_s19k.sh >/dev/null 2>&1 || return 1
    grep -F 'ROOTFS_OFFSET="$DCENT_AM3_ROOTFS_OFFSET_HEX"' scripts/revert_to_stock_am3_aml_s21.sh >/dev/null 2>&1 || return 1
    grep -F 'ROOTFS_MTD="$DCENT_AM3_ROOTFS_MTD"' scripts/revert_to_stock_am3_aml_s21.sh >/dev/null 2>&1 || return 1
    return 0
}

dcentrald_version_gate_selftest() {
    tmpdir=$(mktemp -d 2>/dev/null || echo "/tmp/dcentos-version-gate-selftest.$$")
    rm -rf "$tmpdir"
    mkdir -p "$tmpdir/target/etc" "$tmpdir/target/usr/local/bin" || return 1

    cat > "$tmpdir/Cargo.toml" <<EOF || return 1
[workspace.package]
version = "0.9.0"
EOF
    printf '0.9.0\n' > "$tmpdir/target/etc/dcentos-version" || return 1
    printf 'fixture dcentrald/0.9.0\n' > "$tmpdir/target/usr/local/bin/dcentrald" || return 1

    if ! sh -c '. scripts/lib/dcentrald_version_gate.sh; dcent_require_dcentrald_version_match "$1" "$2" selftest "$3"' sh "$tmpdir/target" "$tmpdir/target/usr/local/bin/dcentrald" "$tmpdir/Cargo.toml" >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    printf 'fixture dcentrald/0.5.0\n' > "$tmpdir/target/usr/local/bin/dcentrald" || return 1
    if sh -c '. scripts/lib/dcentrald_version_gate.sh; dcent_require_dcentrald_version_match "$1" "$2" selftest "$3"' sh "$tmpdir/target" "$tmpdir/target/usr/local/bin/dcentrald" "$tmpdir/Cargo.toml" >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi
    if ! DCENT_PACKAGE_STATUS=lab_stale_version DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 \
        sh -c '. scripts/lib/dcentrald_version_gate.sh; dcent_require_dcentrald_version_match "$1" "$2" selftest "$3"' sh "$tmpdir/target" "$tmpdir/target/usr/local/bin/dcentrald" "$tmpdir/Cargo.toml" >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    printf '0.5.0\n' > "$tmpdir/target/etc/dcentos-version" || return 1
    printf 'fixture dcentrald/0.9.0\n' > "$tmpdir/target/usr/local/bin/dcentrald" || return 1
    if sh -c '. scripts/lib/dcentrald_version_gate.sh; dcent_require_dcentrald_version_match "$1" "$2" selftest "$3"' sh "$tmpdir/target" "$tmpdir/target/usr/local/bin/dcentrald" "$tmpdir/Cargo.toml" >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    rm -rf "$tmpdir"
    return 0
}

toml_watchdog_disabled() {
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*\[/ {
            in_watchdog = ($0 ~ /^[[:space:]]*\[watchdog\][[:space:]]*(#.*)?$/)
            next
        }
        in_watchdog && $0 ~ /^[[:space:]]*enabled[[:space:]]*=[[:space:]]*false[[:space:]]*(#.*)?$/ {
            found = 1
        }
        END { exit(found ? 0 : 1) }
    ' "$1"
}

manifest_watchdog_disabled() {
    awk '
        /"watchdog(_enabled|\.enabled)"[[:space:]]*:[[:space:]]*false/ { found = 1 }
        /watchdog[.]enabled[[:space:]]*=[[:space:]]*false/ { found = 1 }
        /"watchdog"[[:space:]]*:/ { in_watchdog = 1 }
        in_watchdog && /"enabled"[[:space:]]*:[[:space:]]*false/ { found = 1 }
        in_watchdog && /}/ { in_watchdog = 0 }
        END { exit(found ? 0 : 1) }
    ' "$1"
}

watchdog_config_path_exempt() {
    case "$1" in
        br2_external_dcentos/board/beaglebone/am3-bb/*|br2_external_dcentos/board/beaglebone/am3-bb-s19jpro/*|*/br2_external_dcentos/board/beaglebone/am3-bb/*|*/br2_external_dcentos/board/beaglebone/am3-bb-s19jpro/*)
            return 0
            ;;
        br2_external_dcentos/board/amlogic/am3-s19xp/rootfs-overlay/etc/*|br2_external_dcentos/board/amlogic/am3-s19jxp/rootfs-overlay/etc/*|br2_external_dcentos/board/amlogic/am3-s21xp/rootfs-overlay/etc/*|*/br2_external_dcentos/board/amlogic/am3-s19xp/rootfs-overlay/etc/*|*/br2_external_dcentos/board/amlogic/am3-s19jxp/rootfs-overlay/etc/*|*/br2_external_dcentos/board/amlogic/am3-s21xp/rootfs-overlay/etc/*)
            policy_dir=${1%%/rootfs-overlay/etc/*}
            policy_file="$policy_dir/rootfs-overlay/etc/dcentos/mutation_policy"
            [ -f "$policy_file" ] || return 1
            [ "$(wc -l < "$policy_file" | tr -d '[:space:]')" = "1" ] || return 1
            grep -Fqx 'management-only' "$policy_file"
            return $?
            ;;
    esac
    return 1
}

watchdog_shipped_configs_ok() {
    root=$1
    offenders=$2
    found_configs=0
    : > "$offenders"

    for cfg in $(find "$root" -type f -path '*/rootfs-overlay/etc/*.toml' 2>/dev/null | sort); do
        found_configs=$((found_configs + 1))
        if watchdog_config_path_exempt "$cfg"; then
            continue
        fi
        if toml_watchdog_disabled "$cfg"; then
            printf '%s\n' "$cfg" >> "$offenders"
        fi
    done

    for manifest in $(find "$root" -type f \( -iname '*manifest*.json' -o -iname '*release*.json' -o -iname '*manifest*.toml' -o -iname '*release*.toml' \) 2>/dev/null | sort); do
        if watchdog_config_path_exempt "$manifest"; then
            continue
        fi
        case "$manifest" in
            *.toml)
                if toml_watchdog_disabled "$manifest"; then
                    printf '%s\n' "$manifest" >> "$offenders"
                fi
                ;;
            *)
                if manifest_watchdog_disabled "$manifest"; then
                    printf '%s\n' "$manifest" >> "$offenders"
                fi
                ;;
        esac
    done

    if [ "$found_configs" -eq 0 ]; then
        printf 'NO_SHIPPED_TOML_CONFIGS_FOUND\n' >> "$offenders"
        return 2
    fi
    [ ! -s "$offenders" ]
}

watchdog_shipped_config_gate_check() {
    tmpfile=$(mktemp 2>/dev/null || echo "/tmp/dcentos-watchdog-shipped-configs.$$")
    rm -f "$tmpfile"
    if watchdog_shipped_configs_ok "br2_external_dcentos" "$tmpfile"; then
        pass "SAF-3 shipped configs: watchdog enabled in release overlays (typed management-only lanes exempt)"
    else
        rc=$?
        if [ "$rc" -eq 2 ]; then
            fail "SAF-3 shipped configs: no rootfs-overlay/etc/*.toml configs found under br2_external_dcentos (path drift?)"
        else
            fail "SAF-3 shipped configs: watchdog disabled outside a typed management-only lane: $(tr '\n' ' ' < "$tmpfile")"
        fi
    fi
    rm -f "$tmpfile"
}

watchdog_shipped_config_gate_selftest() {
    tmpdir=$(mktemp -d 2>/dev/null || echo "/tmp/dcentos-watchdog-gate-selftest.$$")
    rm -rf "$tmpdir"
    root="$tmpdir/br2_external_dcentos"
    zynq_cfg="$root/board/zynq/rootfs-overlay/etc/dcentrald.toml"
    bb_cfg="$root/board/beaglebone/am3-bb/rootfs-overlay/etc/dcentrald.toml"
    aml_cfg="$root/board/amlogic/am3-s19xp/rootfs-overlay/etc/dcentrald.toml"
    aml_policy="$root/board/amlogic/am3-s19xp/rootfs-overlay/etc/dcentos/mutation_policy"
    manifest="$root/board/zynq/rootfs-overlay/etc/dcentos-release-manifest.json"
    offenders="$tmpdir/offenders.txt"

    mkdir -p "$(dirname "$zynq_cfg")" "$(dirname "$bb_cfg")" "$(dirname "$aml_cfg")" "$(dirname "$aml_policy")" || return 1

    cat > "$zynq_cfg" <<'EOF' || return 1
[watchdog]
enabled = false
EOF
    if watchdog_shipped_configs_ok "$root" "$offenders"; then
        rm -rf "$tmpdir"
        return 1
    fi

    cat > "$zynq_cfg" <<'EOF' || return 1
[watchdog]
enabled = true
EOF
    cat > "$bb_cfg" <<'EOF' || return 1
[watchdog]
enabled = false
EOF
    if ! watchdog_shipped_configs_ok "$root" "$offenders"; then
        rm -rf "$tmpdir"
        return 1
    fi

    cat > "$aml_cfg" <<'EOF' || return 1
[watchdog]
enabled = false
EOF
    printf 'management-only\n' > "$aml_policy" || return 1
    if ! watchdog_shipped_configs_ok "$root" "$offenders"; then
        rm -rf "$tmpdir"
        return 1
    fi
    rm -f "$aml_policy"
    if watchdog_shipped_configs_ok "$root" "$offenders"; then
        rm -rf "$tmpdir"
        return 1
    fi
    printf 'management-only\n' > "$aml_policy" || return 1

    cat > "$manifest" <<'EOF' || return 1
{ "release_image": true, "watchdog": { "enabled": false } }
EOF
    if watchdog_shipped_configs_ok "$root" "$offenders"; then
        rm -rf "$tmpdir"
        return 1
    fi

    rm -rf "$tmpdir"
    return 0
}

require_file '.gitattributes'
require_file 'scripts/package_sysupgrade.sh'
require_file 'scripts/pre_flash_validate.sh'
require_file 'scripts/lib/am3_geometry.sh'
require_file 'scripts/lib/amlogic_identity_guard.sh'
require_file 'scripts/lib/dcentrald_version_gate.sh'
require_file 'scripts/lib/sysupgrade_package_common.sh'
require_file 'scripts/run_wave_regressions.sh'
require_file 'dcentrald/dcentrald/tests/wave55i_phase0_full_ordering.rs'
require_file 'dcentrald/dcentrald/tests/i2c_eeprom_denylist_breadth.rs'
require_file 'scripts/validation_preflight.sh'
require_file 'scripts/validate_production_readiness.ps1'
require_file 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-build.sh'
require_file 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-image.sh'
require_file 'br2_external_dcentos/board/amlogic/am3-s21/post-build.sh'
require_file 'br2_external_dcentos/board/amlogic/am3-s21/post-image.sh'

require_pattern '.gitattributes' '*.sh text eol=lf' 'gitattributes keeps shell files LF-only'
require_pattern '.gitattributes' '/br2_external_dcentos/**/etc/init.d/* text eol=lf' 'gitattributes keeps init scripts LF-only'

for file in $(tracked_lf_files); do
    check_no_cr "$file"
done

for file in \
    scripts/pre_flash_validate.sh \
    scripts/lib/dcentrald_version_gate.sh \
    scripts/build_amlogic_native_install.sh \
    scripts/install_amlogic_persistent.sh \
    scripts/amlogic_lab_rootfs.sh
do
    check_ascii "$file"
done

for file in $(tracked_shell_files); do
    check_shell_syntax "$file"
done

if pre_flash_package_only_selftest; then
    pass "pre-flash package-only selftest accepts valid signed/lab packages and rejects malformed packages"
else
    fail "pre-flash package-only selftest failed"
fi

if am3_geometry_static_selftest; then
    pass "am3 geometry selftest proves install/lab/revert consume shared offsets"
else
    fail "am3 geometry selftest failed"
fi

if sh scripts/test_amlogic_identity_guard.sh; then
    pass "amlogic terminal identity guard rejects held unsupported sibling variants"
else
    fail "amlogic terminal identity guard selftest failed"
fi

if dcentrald_version_gate_selftest; then
    pass "dcentrald version gate selftest fails closed and accepts only explicit lab override"
else
    fail "dcentrald version gate selftest failed"
fi

if watchdog_shipped_config_gate_selftest; then
    pass "SAF-3 shipped configs selftest rejects untyped watchdog-off overlays/manifests and permits typed management-only lanes"
else
    fail "SAF-3 shipped configs selftest failed"
fi
watchdog_shipped_config_gate_check

require_pattern 'scripts/package_sysupgrade.sh' 'Refusing live upload of an unsigned package' 'package_sysupgrade refuses unsigned live upload'
reject_pattern 'scripts/package_sysupgrade.sh' 'DCENT_FORCE_AM2_UPLOAD' 'S9 package_sysupgrade exposes no AM2 live-upload override'
require_pattern 'scripts/package_sysupgrade.sh' 'S9_REQUIRES_INACTIVE_SLOT=true' 'dual-route package manifest declares the inactive-slot requirement (first-install-only scope sets it false)'
require_file 'scripts/lib/sd_image_signing_gate.sh'
require_file 'scripts/test_sd_signing_gate_static.sh'
if sh scripts/test_sd_signing_gate_static.sh >/dev/null 2>&1; then
    pass "SD image signing gate selftest rejects incomplete, unbound, and missing manifests"
else
    fail "SD image signing gate selftest failed"
fi
require_file 'scripts/sign_sd_image.sh'
require_file 'scripts/sign_sd_image.py'
require_file 'scripts/test_sign_sd_image.sh'
if sh scripts/test_sign_sd_image.sh >/dev/null 2>&1; then
    pass "SD image signer selftest validates exact manifest-bound publication"
else
    fail "SD image signer selftest failed"
fi
# AM2 SD artifact staging helper + static self-test (CE-410 residual prep).
# Anti-orphan requires the basename of every scripts/**/test_*.sh to appear here.
require_file 'scripts/stage_am2_sd_artifacts.sh'
require_file 'scripts/stage_am2_sd_artifacts.py'
require_file 'scripts/test_stage_am2_sd_artifacts_static.sh'
# bash required: the selftest uses BASH_SOURCE and Bash test helpers.
if bash scripts/test_stage_am2_sd_artifacts_static.sh >/dev/null 2>&1; then
    pass "AM2 SD artifact staging selftest validates the exact atomic lifecycle"
else
    fail "AM2 SD artifact staging selftest failed"
fi
# Install-path honesty + aggregate GO guard (cannot claim public install GO
# without CAPSTONE_EVIDENCE; never run silent).
require_file 'scripts/check_install_path_honesty.py'
require_file 'scripts/check_install_path_go_guard.py'
require_file 'scripts/test_sd_common_mbr_static.sh'
# Cross-compile matrix honesty: cargo check cells are cfg/type-check only
# (not object codegen/link/release). Continuous-audit residual 2026-07-29.
require_file 'scripts/check_cross_compile_matrix_honesty.py'
require_file 'scripts/test_check_cross_compile_matrix_honesty.py'
# Work-dispatch admission CI coverage: serial/hybrid/stock lifecycle tests +
# serial BIP320/hash_on_disconnect must-wire (2026-07-29 residual).
require_file 'scripts/check_work_dispatch_ci_coverage.py'
require_file 'scripts/test_check_work_dispatch_ci_coverage.py'
# Defconfig doc-reference honesty: every Buildroot defconfig named in an
# authoritative doc must exist on disk (2026-08-02 rank-11 phantom-CV1835 fix).
require_file 'scripts/check_defconfig_doc_references.py'
if command -v python3 >/dev/null 2>&1; then
    if python3 scripts/check_install_path_honesty.py >/dev/null 2>&1; then
        pass "install-path honesty check"
    else
        fail "install-path honesty check failed"
    fi
    if python3 scripts/check_install_path_go_guard.py >/dev/null 2>&1; then
        pass "install-path GO guard (aggregate GO stays NO without CAPSTONE)"
    else
        fail "install-path GO guard failed"
    fi
    if python3 scripts/check_cross_compile_matrix_honesty.py >/dev/null 2>&1; then
        pass "cross-compile matrix honesty (cargo check = cfg/type-check)"
    else
        fail "cross-compile matrix honesty check failed"
    fi
    if python3 scripts/test_check_cross_compile_matrix_honesty.py >/dev/null 2>&1; then
        pass "cross-compile matrix honesty unit selftest"
    else
        fail "cross-compile matrix honesty unit selftest failed"
    fi
    if python3 scripts/check_work_dispatch_ci_coverage.py >/dev/null 2>&1; then
        pass "work-dispatch CI coverage (lifecycle + serial must-wire)"
    else
        fail "work-dispatch CI coverage check failed"
    fi
    if python3 scripts/test_check_work_dispatch_ci_coverage.py >/dev/null 2>&1; then
        pass "work-dispatch CI coverage unit selftest"
    else
        fail "work-dispatch CI coverage unit selftest failed"
    fi
    if python3 scripts/check_defconfig_doc_references.py >/dev/null 2>&1; then
        pass "defconfig doc-reference honesty (every doc-named defconfig exists on disk)"
    else
        fail "defconfig doc-reference honesty check failed"
    fi
    if python3 scripts/check_defconfig_doc_references.py --self-test >/dev/null 2>&1; then
        pass "defconfig doc-reference parser selftest"
    else
        fail "defconfig doc-reference parser selftest failed"
    fi
elif command -v py >/dev/null 2>&1; then
    if py -3 scripts/check_install_path_honesty.py >/dev/null 2>&1; then
        pass "install-path honesty check"
    else
        fail "install-path honesty check failed"
    fi
    if py -3 scripts/check_install_path_go_guard.py >/dev/null 2>&1; then
        pass "install-path GO guard"
    else
        fail "install-path GO guard failed"
    fi
    if py -3 scripts/check_cross_compile_matrix_honesty.py >/dev/null 2>&1; then
        pass "cross-compile matrix honesty (cargo check = cfg/type-check)"
    else
        fail "cross-compile matrix honesty check failed"
    fi
    if py -3 scripts/test_check_cross_compile_matrix_honesty.py >/dev/null 2>&1; then
        pass "cross-compile matrix honesty unit selftest"
    else
        fail "cross-compile matrix honesty unit selftest failed"
    fi
    if py -3 scripts/check_work_dispatch_ci_coverage.py >/dev/null 2>&1; then
        pass "work-dispatch CI coverage (lifecycle + serial must-wire)"
    else
        fail "work-dispatch CI coverage check failed"
    fi
    if py -3 scripts/test_check_work_dispatch_ci_coverage.py >/dev/null 2>&1; then
        pass "work-dispatch CI coverage unit selftest"
    else
        fail "work-dispatch CI coverage unit selftest failed"
    fi
    if py -3 scripts/check_defconfig_doc_references.py >/dev/null 2>&1; then
        pass "defconfig doc-reference honesty (every doc-named defconfig exists on disk)"
    else
        fail "defconfig doc-reference honesty check failed"
    fi
    if py -3 scripts/check_defconfig_doc_references.py --self-test >/dev/null 2>&1; then
        pass "defconfig doc-reference parser selftest"
    else
        fail "defconfig doc-reference parser selftest failed"
    fi
else
    fail "python3/py required for install-path honesty/GO guards"
fi
if bash scripts/test_sd_common_mbr_static.sh >/dev/null 2>&1; then
    pass "sd_common pure-Python three-part MBR write selftest"
else
    fail "sd_common MBR selftest failed"
fi
require_pattern 'scripts/sign_sd_image.py' 'validate_manifest_binding' 'sign_sd_image binds completeness evidence to exact image bytes'
require_pattern 'scripts/sign_sd_image.py' 'trusted release public key is required' 'sign_sd_image fails closed without pinned public authority'
require_pattern 'scripts/sign_sd_image.py' 'sign_release_receipt' 'sign_sd_image reuses exact no-replace durable signing lifecycle'
require_pattern 'scripts/sign_sd_image.py' 'durable_input=True' 'sign_sd_image flushes pinned image bytes before signature commit'
reject_pattern 'scripts/sign_sd_image.py' 'dcentos.am3_bb_vnish_sd_image_manifest' 'sign_sd_image denies release authority to the open-gate VNish prototype'
require_pattern 'scripts/build_am2_s19jpro_sd_disk_image.sh' 'boot_artifacts_complete' 'am2 SD builder emits boot artifact completeness manifest'
require_pattern 'scripts/build_am2_s19jpro_sd_disk_image.sh' 'image_sha256' 'am2 SD manifest binds exact image digest'
require_pattern 'scripts/build_am2_s19jpro_sd_disk_image.sh' 'stale signature' 'am2 SD builder refuses stale sibling signatures before rewrite'
require_pattern 'scripts/build_am2_s19jpro_sd_disk_image.sh' '"BOOT.bin"' 'am2 SD manifest records BOOT.bin presence'
require_pattern 'scripts/build_am2_s19jpro_sd_disk_image.sh' '"uEnv.txt"' 'am2 SD manifest records uEnv presence'
require_pattern 'scripts/build_am3_bb_sd_vnish_bootbin_image.sh' 'not eligible for DCENT_OS release signing' 'VNish builder refuses release signing while vendor and RSA gates remain open'
reject_pattern 'scripts/build_am3_bb_sd_vnish_bootbin_image.sh' 'release_ed25519.pub' 'VNish builder does not reopen and copy a mutable public-key sidecar'
require_pattern 'scripts/build_in_docker.sh' 'dcent_sd_require_complete_manifest_for_signing' 'docker SD signing path requires complete AM2 manifest before signing'
require_pattern 'scripts/build_in_docker.sh' 'UNSIGNED-LAB-ROOTFS-ONLY' 'docker SD path relabels unsigned incomplete AM2 images'
require_pattern 'scripts/build_in_docker.sh' 'BOARD_POST_IMAGE" = "vnish-bootbin-sd"' 'docker SD path keeps VNish bootbin SD branch separate'
# CI-GATE-CE271-SIGNER-PUBKEY-MOUNT: the late Docker signer stages (Phase 8b
# am3-bb tarball, Phase 8c SD .img) must mount the trusted release pubkey into
# the signer container and pass the CONTAINER path, so verify-after-sign checks
# the PINNED trusted key rather than a pubkey self-derived from the signing key
# (which verifies any key). A raw host-path env leak makes the -f test always
# fail inside the container -> silent self-derived fallback (fail-open).
reject_pattern 'scripts/build_in_docker.sh' '-e DCENT_RELEASE_PUBKEY_FILE="${DCENT_RELEASE_PUBKEY_FILE:-}"' 'CE-271: signer containers must not receive a raw host pubkey path'
require_pattern 'scripts/sign_release_artifact.py' 'release artifact signing requires a trusted public key' 'CE-271: Phase 8b exact signer fails closed without a trusted pubkey'
require_pattern 'scripts/build_in_docker.sh' '--pubkey "${DCENT_RELEASE_PUBKEY_FILE}"' 'CE-271: Phase 8b passes the mounted trusted pubkey to the exact signer'
if [ "$(grep -cF -- 'PUBKEY_MOUNT_ARGS[@]' scripts/build_in_docker.sh)" -ge 3 ]; then
    pass "CE-271: Phase 8/8b/8c docker stages mount the trusted release pubkey"
else
    fail "CE-271: late Docker signer stages missing PUBKEY_MOUNT_ARGS pubkey mounts"
fi
require_pattern 'br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/S99upgrade' 'upgrade_stage' 'rollback init script still keys off upgrade_stage'
# W8 parity: the A/B commit gate must require a REAL health endpoint + a
# sustained boot-success window, not just a socket-bind probe (a daemon that
# binds then crash-loops must NOT be committed as good -> the auto-rollback the
# inactive-slot write armed stays effective). Brick-safe: stricter only.
require_pattern 'br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/S99upgrade' '/api/system/health' 'A/B commit gate checks the real health endpoint, not just socket bind'
require_pattern 'br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/S99upgrade' 'MIN_HEALTHY_UPTIME_S' 'A/B commit gate enforces a sustained boot-success window'
require_pattern 'br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/S99verify' 'report-only proof consumer' 'S99verify remains a non-mutating consumer of the S99upgrade boot-success decision'
require_pattern 'scripts/pre_flash_validate.sh' 'inactive NAND slot' 'pre-flash gate still validates inactive NAND slot'
require_pattern 'scripts/pre_flash_validate.sh' '--package-only' 'pre-flash validator keeps local package-only mode'
require_pattern 'scripts/pre_flash_validate.sh' 'tar entry paths are relative and traversal-free' 'pre-flash package-only mode rejects unsafe tar paths'
require_pattern 'scripts/pre_flash_validate.sh' 'tar entry types are regular files/directories only' 'pre-flash package-only mode rejects links/devices'
require_pattern 'scripts/pre_flash_validate.sh' 'MANIFEST.json board_target' 'pre-flash package-only mode validates manifest board_target'
require_pattern 'scripts/pre_flash_validate.sh' 'SHA256SUMS verifies kernel/root/METADATA' 'pre-flash package-only mode validates package hashes'
require_pattern 'scripts/pre_flash_validate.sh' 'MANIFEST.json payload paths/sizes/hashes match actual files' 'pre-flash package-only mode cross-checks manifest payloads'
require_pattern 'scripts/pre_flash_validate.sh' 'AM3 root uImage + kernel arm64 Image magic valid' 'pre-flash package-only mode validates AM3 root uImage and donor arm64 kernel header'
require_pattern 'scripts/pre_flash_validate.sh' 'squashfs-style root payload magic valid' 'pre-flash package-only mode validates squashfs-style root payloads'
require_pattern 'scripts/pre_flash_validate.sh' 'root payload fits am3 rootfs window' 'pre-flash package-only mode bounds am3 rootfs payload'
require_pattern 'scripts/pre_flash_validate.sh' 'assert_payload_fits_window "$board root" "$root_size" "$ZYNQ_ROOTFS_MAX_BYTES" "zynq rootfs window"' 'pre-flash package-only mode bounds zynq rootfs payloads'
require_pattern 'scripts/pre_flash_validate.sh' 'assert_payload_fits_window "$board kernel" "$kernel_size" "$ZYNQ_KERNEL_MAX_BYTES" "zynq kernel window"' 'pre-flash package-only mode bounds zynq kernel payloads'
# AM1-A Drop-1 route scoping (owner adjudication
# AM1_S9_ROOTFS_WINDOW_ADJUDICATION Option A, ratified 2026-09-15): the
# am1-s9 self-update window stays enforced for every self-update-claiming
# shape; only the typed first-install-only denial admits an over-window
# package (first-install route).
require_pattern 'scripts/pre_flash_validate.sh' 'query-install-mode' 'pre-flash package-only mode reads the route contract through the typed semantic helper'
require_pattern 'scripts/pre_flash_validate.sh' 'self-update window admission waived' 'pre-flash package-only mode records the first-install-only window waiver'
require_pattern 'scripts/package_sysupgrade.sh' 'AM1_S9_ROOTFS_WINDOW_ADJUDICATION.md' 'S9 packager cites the route-scoping owner adjudication'
require_pattern 'scripts/package_sysupgrade.sh' 'S9_TOOLBOX_INSTALL_MODE=first_install_only' 'S9 packager emits the typed first-install-only contract for over-window payloads'
require_pattern 'scripts/package_sysupgrade.sh' 'refusing to seal a self-update contract for an oversized package' 'S9 packager fails closed on a self-update claim with an over-window payload'
require_pattern 'scripts/package_sysupgrade.sh' 'Refusing --upload of a first-install-only package' 'S9 packager refuses the live-upload self-update rail for a first-install-only package'
# First-install capacity bound (merge-critic follow-up): defined once in the
# capacity helper with the stage1_builder.py:640/:642 citation, enforced at
# seal time and at pre-flash waiver time.
require_pattern 'scripts/lib/am1_s9_first_install_capacity.sh' 'AM1_S9_FIRST_INSTALL_ROOTFS_MAX_BYTES=$((20 * 1024 * 1024))' 'first-install capacity helper pins the 20MiB stock rootfs volume'
require_pattern 'scripts/package_sysupgrade.sh' 'dcent_am1_s9_require_first_install_capacity' 'S9 packager enforces the stock-transaction capacity at seal time'
require_pattern 'scripts/pre_flash_validate.sh' 'first-install-only waiver is bounded' 'pre-flash first-install-only waiver is bounded by the stock-transaction capacity'
require_pattern 'scripts/pre_flash_validate.sh' '[ "$board" = "am1-s9" ] && [ "$install_mode" = "first_install_only" ]' 'pre-flash waiver conjunct stays am1-s9 AND first_install_only only'
require_pattern 'scripts/lib/sysupgrade_manifest_json.py' 'first_install_only' 'semantic manifest helper admits the first-install-only route contract'
require_pattern 'scripts/lib/sysupgrade_package_common.sh' 'first-install-only metadata must not advertise an update command' 'shared typed-contract machinery refuses update metadata under the first-install-only denial'
require_pattern 'br2_external_dcentos/board/zynq/rootfs-overlay/usr/sbin/sysupgrade' 'payload_fits_ubi_volume' 'S9 sysupgrade checks payload byte fit before ubiupdatevol'
require_pattern 'br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/usr/sbin/sysupgrade' 'payload_fits_ubi_volume' 'am2-s19j sysupgrade checks payload byte fit before ubiupdatevol'
require_pattern 'br2_external_dcentos/board/zynq/am2-s19pro/rootfs-overlay/usr/sbin/sysupgrade' 'payload_fits_ubi_volume' 'am2-s19pro sysupgrade checks payload byte fit before ubiupdatevol'
require_pattern 'br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay/usr/sbin/sysupgrade' 'payload_fits_ubi_volume' 'am2-s17p sysupgrade checks payload byte fit before ubiupdatevol'
sysupgrade_am2_variant_parity_check
require_pattern 'scripts/pre_flash_validate.sh' 'DCENT_RELEASE_PUBKEY_FILE is required for authority-v1 package validation' 'pre-flash package-only mode requires trusted release key for signed authority'
require_pattern 'scripts/pre_flash_validate.sh' 'DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1' 'pre-flash package-only mode exposes explicit unsigned lab override'
require_pattern 'scripts/verify_sysupgrade_signature.sh' 'Public key is not a valid PEM public key' 'shell sysupgrade verifier rejects malformed placeholder public keys'
require_pattern 'scripts/pre_flash_validate.sh' 'dcentos.sysupgrade-unsigned-lab/v1)' 'pre-flash package-only mode recognizes the explicit unsigned lab profile'
require_pattern 'scripts/pre_flash_validate.sh' 'unsigned-lab/v1 requires exactly one status=lab_unsigned field' 'pre-flash package-only mode pins exact unsigned lab status'
require_pattern 'scripts/pre_flash_validate.sh' "exactly one 'status' authority field" 'pre-flash package-only mode requires one unambiguous status claim'
require_pattern 'scripts/pre_flash_validate.sh' 'status must not contain surrounding whitespace' 'pre-flash package-only mode rejects whitespace-padded status'
require_pattern 'scripts/pre_flash_validate.sh' 'version must not contain surrounding whitespace' 'pre-flash package-only mode rejects whitespace-padded version'
require_pattern 'scripts/pre_flash_validate.sh' 'unsigned-lab/v1 forbids MANIFEST.sig' 'pre-flash package-only mode rejects signatures in unsigned lab packages'
require_pattern 'scripts/build_in_docker.sh' 'release/verified builds fail closed on missing or mismatched toolchain' 'release docker builds make toolchain SHA verification mandatory'
require_file 'scripts/lib/sysupgrade_archive_admission.sh'
require_pattern 'scripts/lib/sysupgrade_archive_admission.sh' 'DCENT_SYSUPGRADE_ARCHIVE_MAX_MEMBERS=32' 'shell sysupgrade admission caps archive members before extraction'
require_pattern 'scripts/lib/sysupgrade_archive_admission.sh' 'unknown member leaf' 'shell sysupgrade admission rejects leaves outside the explicit package contract'
require_pattern 'scripts/verify_sysupgrade_signature.sh' 'dcent_sysupgrade_archive_admit "$PACKAGE" "$EXPECTED_BOARD" "$TMPDIR"' 'shell verifier runs shared archive admission before extraction/signature checks'
require_pattern 'scripts/verify_sysupgrade_signature.sh' 'for unsupported_chain_key in ota_intermediate_cert ota_revoked_intermediates' 'authority-v1 verifier restricts mutation authority to direct release-root signatures'
require_pattern 'scripts/verify_sysupgrade_signature.sh' 'certificate validity has no trusted-time authority on Zynq' 'authority-v1 verifier does not trust unauthenticated recovery wall time'
require_pattern 'scripts/verify_sysupgrade_signature.sh' 'Manifest authority-v1 forbids status=lab_unsigned' 'authority-v1 verifier rejects the signed/unsigned status contradiction'
require_pattern 'scripts/verify_sysupgrade_signature.sh' "exactly one 'status' field" 'authority-v1 verifier requires one unambiguous status claim'
require_pattern 'scripts/verify_sysupgrade_signature.sh' 'version must not contain surrounding whitespace' 'authority-v1 verifier rejects whitespace-padded version'
require_pattern 'scripts/build_in_docker.sh' 'ERROR (DEVOPS-002): no expected SHA256 pinned' 'release docker builds fail closed when no toolchain SHA pin exists'
require_file 'scripts/test_firmware_release_name.sh'
if sh scripts/test_firmware_release_name.sh >/dev/null 2>&1; then
    pass "firmware release-name helper self-test covers Antminer, ESP, H616, K230, and reject-unknown"
else
    fail "firmware release-name helper self-test failed"
fi
require_file 'scripts/check_stratum_contract_drift.py'
if run_python_script scripts/check_stratum_contract_drift.py >/dev/null 2>&1; then
    pass "stratum contract drift: current Whatsminer-first and Avalon-adapter assumptions are pinned"
else
    fail "stratum contract drift check failed"
fi
require_file 'scripts/check_family_docs_honesty.py'
if run_python_script scripts/check_family_docs_honesty.py >/dev/null 2>&1; then
    pass "family docs honesty: every support-matrix family has tier-boundary docs"
else
    fail "family docs honesty check failed"
fi
require_pattern 'Makefile' 'dcentrald-asic' 'make verify host tests execute dcentrald-asic behavioral safety tests'
require_pattern 'Makefile' 'dcentrald-thermal --no-default-features' 'make verify host tests execute dcentrald-thermal safety tests'
require_pattern '../../.github/workflows/dcentos-offline-gates.yml' 'cargo test -p dcentrald-asic --lib' 'offline workflow executes dcentrald-asic lib safety pins'
if grep -Eq 'dcentrald-hal --lib( --)? am2_' \
    '../../.github/workflows/dcentos-offline-gates.yml'; then
    pass 'offline workflow executes AM2 board-control UIO register-map pins'
else
    fail 'offline workflow is missing AM2 board-control UIO register-map pins'
fi
require_pattern '../../.github/workflows/dcentos-offline-gates.yml' 'cargo test -p dcentrald --test fan_safety_override_pin' 'offline workflow executes exact dcentrald fan safety override pin'
require_pattern 'Makefile' 'test-waves' 'make verify executes wave regression tests locally'
require_pattern 'Makefile' 'run_wave_regressions.sh' 'make test-waves delegates to the local wave regression runner'
require_pattern 'scripts/run_wave_regressions.sh' "name 'wave*.rs'" 'local wave regression runner discovers all dcentrald wave pins, including Wave-55i'
require_pattern 'dcentrald/dcentrald/tests/wave55i_phase0_full_ordering.rs' 'wave55i_phase0_full_ordering_rejects_swapped_phase0_markers' 'Wave-55i Phase-0 ordering pin carries a source-parse negative control'
require_pattern 'dcentrald/dcentrald/tests/i2c_eeprom_denylist_breadth.rs' 'am2_serial_pic_service' 'I2C EEPROM denylist breadth pin covers the AM2 serial PIC service'
require_pattern 'dcentrald/dcentrald/tests/i2c_eeprom_denylist_breadth.rs' 'denylist_breadth_helper_rejects_plain_i2c_service_constructor' 'I2C EEPROM denylist breadth pin carries a negative control'
require_pattern 'scripts/run_wave_regressions.sh' 'wave55l_loki_inter_txn_gap' 'local wave regression runner executes HAL wave55l Loki gap pin'
require_pattern 'scripts/run_wave_regressions.sh' 'watchdog::tests' 'local wave regression runner executes HAL watchdog Drop fail-closed pins'
require_pattern 'scripts/run_wave_regressions.sh' 'fan::tests' 'local wave regression runner executes HAL fan topology pins'
require_pattern 'scripts/run_wave_regressions.sh' 'xadc::tests' 'local wave regression runner executes HAL XADC non-finite fail-closed pins'
require_pattern 'scripts/run_wave_regressions.sh' 'safety_pwm_cap' 'local wave regression runner executes thermal safety_pwm_cap pin'
require_pattern 'dcentrald/dcentrald-asic/src/drivers/mod.rs' 'every_driver_core_count_matches_miner_profile_driver_semantics' 'ASIC driver core counts are pinned to MinerProfile driver-facing semantics'
require_pattern 'dcentrald/dcentrald-hal/src/fan.rs' 'fan_variant_topology_pins_physical_tach_and_pwm_channels' 'HAL fan variant topology pins physical/tach/PWM channel counts'
require_pattern 'dcentrald/dcentrald-thermal/src/supervisor.rs' 'hydro_configured_non_finite_inlet_fails_closed' 'thermal supervisor hydro NaN path fails closed'
require_pattern 'dcentrald/dcentrald-thermal/src/heater.rs' 'non_finite_power_never_yields_nan_or_boost' 'space-heater power loop rejects non-finite power'
require_pattern 'dcentrald/dcentrald-thermal/src/offgrid.rs' 'non_finite_power_and_current_do_not_poison_energy_or_telemetry' 'off-grid telemetry rejects non-finite current and power'
require_pattern 'dcentrald/dcentrald-thermal/src/curtailment.rs' 'sleep_controller_has_no_float_sensor_surface' 'curtailment sleep controller has no float sensor surface'
require_pattern 'dcentrald/dcentrald-hal/src/xadc.rs' 'iio_float_parser_rejects_non_finite_values' 'XADC parser rejects non-finite sysfs values'
require_file 'scripts/check_safety_clamp_manifest.py'
# BoardDesc install matrix (ADR-0011) — living product/lab/A/B SSOT for packaging.
require_file 'docs/architecture/install_matrix.tsv'
require_file 'docs/architecture/hardware_enablement_matrix.json'
require_file '../dcent-toolbox/src/dcent_toolbox/data/hardware_enablement_matrix.json'
require_file 'scripts/export_install_matrix.ps1'
require_file 'scripts/check_install_matrix_drift.ps1'
if awk -F '\t' '
    NR == 1 {
        for (i = 1; i <= NF; i++) {
            if ($i == "board_target") board_target_col = i
            if ($i == "install_authorization") install_authorization_col = i
            if ($i == "public_beta_install") public_beta_col = i
        }
        next
    }
    board_target_col && install_authorization_col && public_beta_col && \
        $install_authorization_col == "public_beta" && $public_beta_col == "1" {
        if ($board_target_col == "am1-s9") am1_s9 = 1
    }
    END {
        exit !(board_target_col && install_authorization_col && public_beta_col && \
            am1_s9)
    }
' docs/architecture/install_matrix.tsv; then
    pass 'install_matrix.tsv lists public-beta runtime board target am1-s9 (S9-only beta scope)'
else
    fail 'install_matrix.tsv missing public-beta runtime row am1-s9'
fi
if awk -F'\t' '
    NR == 1 {
        for (i = 1; i <= NF; i++) if ($i == "public_beta_install") public_beta_col = i
        next
    }
    public_beta_col && $public_beta_col == "1" { count++ }
    END { exit !(public_beta_col && count == 1) }
' docs/architecture/install_matrix.tsv; then
    pass 'install_matrix.tsv has exactly one public_beta_install=1 row (S9-only)'
else
    fail 'install_matrix.tsv public_beta_install=1 row count is not exactly 1'
fi
if cmp -s \
    docs/architecture/hardware_enablement_matrix.json \
    ../dcent-toolbox/src/dcent_toolbox/data/hardware_enablement_matrix.json; then
    pass 'Toolbox bundles the exact generated hardware enablement matrix'
else
    fail 'Toolbox hardware enablement matrix drifted from the Rust-generated canonical JSON'
fi
# C2 pleb-install lane: the toolbox's guided-install route catalog must be a
# faithful export of release_train.py TARGETS + the board_desc.rs rings.
if run_python_script scripts/export_install_route_catalog.py --check; then
    pass 'Toolbox install-route catalog matches release_train.py (C2 guided install)'
else
    fail 'Toolbox install-route catalog drifted from release_train.py — regenerate with export_install_route_catalog.py'
fi
if run_python_script scripts/check_safety_clamp_manifest.py --self-test; then
    pass "safety clamp manifest: classified thermal/voltage/frequency/PWM clamp set is pinned with negative control"
else
    fail "safety clamp manifest: classified clamp set drifted or negative control failed"
fi
# no-orphan power/PIC/thermal backend gate (hardware-enablement rank 36).
# Shipped 2026-08-03 as "not wired -- see W8-RANK-36-ORPHAN-GATE.md S6"; the
# coordinator wiring was never applied, so the gate that exists to catch
# unreachable code was itself unreachable for four days. Wired 2026-08-07
# (Round-16 B6). Deliberately WITHOUT >/dev/null so FAIL reasons reach CI logs.
require_file 'scripts/check_no_orphan_power_backends.py'
if run_python_script scripts/check_no_orphan_power_backends.py; then
    pass 'no-orphan power/PIC/thermal backend gate holds (35 pinned orphans, 0 new)'
else
    fail 'no-orphan backend gate: new orphan power/PIC/thermal backend, stale allowlist row, dead scope glob, or unreasoned allowlist entry (reasons printed above)'
fi
if run_python_script scripts/check_no_orphan_power_backends.py --self-test; then
    pass 'no-orphan backend gate self-test (orphan/live/dead-glob/allowlist-reason controls)'
else
    fail 'no-orphan backend gate self-test failed'
fi
require_pattern 'scripts/run_all_gates.sh' 'dcentrald-asic' 'run_all_gates host tests execute dcentrald-asic behavioral safety tests'
require_pattern 'scripts/run_all_gates.sh' 'dcentrald-thermal --no-default-features' 'run_all_gates host tests execute dcentrald-thermal safety tests'
require_pattern 'Makefile' 'test-clippy-input' 'make verify runs input-crate clippy deny gate'
require_pattern 'Makefile' 'clippy --no-deps -p dcentrald-stratum --lib -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic' 'stratum clippy deny command is pinned in make verify'
require_pattern 'Makefile' 'clippy --no-deps -p dcentrald-asic --lib -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic' 'asic clippy deny command is pinned in make verify'
make_release_verify_gate_check
precommit_skip_after_hygiene_check
require_pattern 'Makefile' 'hook-only emergency bypass' 'install-hooks documents DCENT_SKIP_VERIFY as hook-only'
require_pattern 'README.md' 'make install-hooks' 'source onboarding documents local hook installation'
require_pattern 'scripts/run_all_gates.sh' 'rust-input-clippy' 'run_all_gates runs input-crate clippy deny gate'
require_pattern 'dcentrald/dcentrald-thermal/src/controller.rs' 'safe_pwm_clamp' 'thermal controller uses adjacent safe PWM clamp helper'
require_pattern 'dcentrald/dcentrald/src/stock_mining.rs' 'spawn_watchdog_kicker' 'stock-fpga mining path arms the watchdog'
require_pattern 'dcentrald/dcentrald/src/main.rs' 'stock-fpga' 'watchdog source-pin list includes stock-fpga mining path'
require_pattern 'dcentrald/Cargo.toml' 'proptest = "1"' 'workspace declares proptest for untrusted-input property tests'
require_pattern 'dcentrald/dcentrald-stratum/src/v2/channel.rs' 'handle_frame_never_panics_on_bounded_payloads' 'SV2 channel handle_frame property coverage is present'
require_pattern 'dcentrald/dcentrald-stratum/src/v2/noise.rs' 'initiator_handshake_finish_never_panics_on_arbitrary_response' 'SV2 Noise handshake property coverage is present'
require_pattern 'dcentrald/dcentrald-stratum/src/v2/jd.rs' 'jd_message_decoders_never_panic_on_arbitrary_bytes' 'SV2 JD parser property coverage is present'
require_pattern 'dcentrald/fuzz/Cargo.toml' 'ota_sysupgrade_tar' 'cargo-fuzz OTA sysupgrade tar target is declared'
require_pattern 'dcentrald/fuzz/Cargo.toml' 'sv2_frame_decoder' 'cargo-fuzz SV2 frame decoder target is declared'
require_pattern 'dcentrald/fuzz/Cargo.toml' 'v1_pool_message_parser' 'cargo-fuzz V1 pool-message parser target is declared'
require_pattern '../../.github/workflows/dcentos-fuzz-smoke.yml' 'cargo fuzz run ota_sysupgrade_tar -- -runs=256' 'scheduled fuzz smoke runs OTA tar parser'
require_pattern '../../.github/workflows/dcentos-fuzz-smoke.yml' 'cargo fuzz run sv2_frame_decoder -- -runs=256' 'scheduled fuzz smoke runs SV2 frame decoder'
require_pattern '../../.github/workflows/dcentos-fuzz-smoke.yml' 'cargo fuzz run v1_pool_message_parser -- -runs=256' 'scheduled fuzz smoke runs V1 pool-message parser'
require_pattern '../../.github/workflows/dcentos-fuzz-smoke.yml' 'dcentos_receipt_parser_fuzz.c' 'scheduled fuzz smoke builds the compiled receipt ABI1 target'
require_pattern '../../.github/workflows/dcentos-fuzz-smoke.yml' 'dcentos-receipt-parser-fuzz' 'scheduled fuzz smoke runs compiled receipt ABI1 parsers'
require_pattern '../../.github/workflows/dcentos-fuzz-smoke.yml' 'dcentos_receipt_chain_fuzz.c' 'scheduled fuzz smoke builds the compiled receipt chain accumulator target'
require_pattern '../../.github/workflows/dcentos-fuzz-smoke.yml' 'dcentos-receipt-chain-fuzz' 'scheduled fuzz smoke runs compiled receipt chain accumulators'
require_pattern '../../.github/workflows/dcentos-fuzz-smoke.yml' 'scripts/fuzz/corpus/dcentos-receipt-chain' 'scheduled chain fuzz smoke uses the canonical valid-chain seed corpus'
require_pattern '../../.github/workflows/dcentos-fuzz-smoke.yml' 'dcentos_receipt_storage_fuzz.c' 'scheduled fuzz smoke builds the compiled receipt ABI2 storage target'
require_pattern '../../.github/workflows/dcentos-fuzz-smoke.yml' 'dcentos-receipt-storage-fuzz' 'scheduled fuzz smoke runs compiled receipt ABI2 storage validation'
require_pattern '../../.github/workflows/dcentos-fuzz-smoke.yml' 'scripts/fuzz/corpus/dcentos-receipt-storage' 'scheduled storage fuzz smoke uses the canonical valid-genesis seed corpus'
require_pattern '../../.github/workflows/dcentos-fuzz-smoke.yml' '-max_len=20498' 'scheduled storage fuzz smoke can reach the full framed ABI2 record boundary'
require_pattern 'scripts/test_dcentos_receipt_cross_compile.sh' 'receipt_projection.c' 'exact Zynq cross proof compiles the global receipt projection engine'
require_pattern 'scripts/test_dcentos_receipt_cross_compile.sh' 'projection=${projection_bytes}B' 'exact Zynq cross proof measures the stripped projection target'

# The entropy lifecycle is a boot-security boundary, not an implementation
# detail of one updater. Keep its host state-machine proof independent of the
# larger Experimental sysupgrade transaction. The full offline gate and the
# restricted-input image workflow own exact-target compilation; --static-only
# retains wiring checks without requiring the nonredistributable toolchain.
entropy_seed_lifecycle_check() {
    if [ ! -e br2_external_dcentos/board/zynq/rootfs-overlay/usr/sbin/seed-entropy ] && \
       [ -f br2_external_dcentos/packages/seed-entropy/src/seed-entropy.c ] && \
       grep -Fq 'BR2_PACKAGE_SEED_ENTROPY=y' \
           br2_external_dcentos/configs/dcentos-common.fragment; then
        pass 'entropy lifecycle: package source is enabled globally and has no overlay shadow'
    else
        fail 'entropy lifecycle: package wiring is absent or a legacy overlay implementation shadows the package binary'
    fi
    if [ "$STATIC_ONLY" -eq 0 ]; then
        if sh scripts/test_seed_entropy_lifecycle.sh >/dev/null 2>&1; then
            pass 'entropy lifecycle: native consume/mix/credit/rotation state machine passes'
        else
            fail 'entropy lifecycle: native state-machine suite failed'
        fi
        if sh scripts/test_seed_entropy_cross_compile.sh >/dev/null 2>&1; then
            pass 'entropy lifecycle: exact pinned Zynq ABI cross proof passes'
        else
            fail 'entropy lifecycle: exact pinned Zynq ABI cross proof failed or its restricted input is absent'
        fi
    fi
    if awk '
        /sh scripts\/provision_build_inputs.sh --check/ { provision = NR }
        /run: sh scripts\/test_seed_entropy_cross_compile.sh/ { proof = NR }
        /bash scripts\/build_release_capsule.sh/ { build = NR }
        END { exit !(provision && proof && build && provision < proof && proof < build) }
    ' ../../.github/workflows/dcentos-image-smoke.yml && \
       grep -Eq '^[[:space:]]*run:[[:space:]]+sh[[:space:]]+scripts/test_seed_entropy_cross_compile\.sh[[:space:]]*$' \
           ../../.github/workflows/dcentos-image-smoke.yml; then
        pass 'entropy lifecycle: exact Zynq proof is ordered after input admission and before image build'
    else
        fail 'entropy lifecycle: restricted-input image smoke lost the ordered exact Zynq proof'
    fi
}
entropy_seed_lifecycle_check

# Release-workflow admission anti-orphan. `build_in_docker.sh` and
# `build-dcentrald.sh` are capsule-internal drivers: a workflow calling either
# one directly can no longer satisfy receipt-v4 invocation ownership. S9 CI
# must consume the atomic public directory and verify it after private cleanup.
# Both workflows consume exact S9/AM2 producer results from the shared outer
# capsule. A package result grants no physical boot or first-install claim.
release_workflow_capsule_admission_check() {
    workflow_dir='../../.github/workflows'
    image_workflow="$workflow_dir/dcentos-image-smoke.yml"
    nandsim_workflow="$workflow_dir/dcentos-offline-nandsim.yml"

    require_file "$image_workflow"
    require_file "$nandsim_workflow"

    direct_call_pattern='(^|[[:space:]])(bash|sh)[[:space:]]+(\./)?scripts/(build_in_docker|build-dcentrald)\.sh([[:space:]\\]|$)'
    direct_calls=$(grep -REn -- "$direct_call_pattern" "$workflow_dir" 2>/dev/null || true)
    if [ -n "$direct_calls" ]; then
        fail "release workflows must not invoke capsule-internal build drivers directly: $direct_calls"
    else
        pass 'release workflows cannot orphan the outer capsule by invoking inner build drivers'
    fi

    for workflow in "$image_workflow" "$nandsim_workflow"; do
        require_pattern "$workflow" \
            'bash scripts/build_release_capsule.sh' \
            "$workflow uses the exact producer outer capsule"
        require_pattern "$workflow" \
            'python3 scripts/release_producer.py verify-cohort-result' \
            "$workflow verifies exact signed producer results after cleanup"
        require_pattern "$workflow" \
            'python3 scripts/release_producer_evidence.py verify-cohort' \
            "$workflow reauthenticates retained source closure after cleanup"
        require_pattern "$workflow" \
            'vars.DCENT_RUST_BUILDER_BASE' \
            "$workflow obtains the builder digest from repository/dispatch authority"
        require_pattern "$workflow" \
            "grep -Eq '^.+@sha256:[0-9a-f]{64}$'" \
            "$workflow rejects missing or mutable builder references"
        require_pattern "$workflow" \
            "DCENT_TOOLCHAIN_SHA256_VERIFIED: '1'" \
            "$workflow explicitly admits the ratified S9 toolchain checksum"
        require_pattern "$workflow" \
            'vars.DCENT_BUILD_INPUTS_DIR' \
            "$workflow obtains an explicit restricted-input channel authority"
        require_pattern "$workflow" \
            'runs-on: [self-hosted, linux, x64, dcentos-restricted-inputs' \
            "$workflow reserves capsule execution for an operator-managed restricted-input runner"
        require_pattern "$workflow" \
            'sh scripts/provision_build_inputs.sh --source "$INPUT_ROOT"' \
            "$workflow provisions restricted bytes only from the external authority"
        require_pattern "$workflow" \
            'sh scripts/provision_build_inputs.sh --check' \
            "$workflow hash-verifies every restricted input before build"
        require_pattern "$workflow" \
            'DCENT_BUILD_INPUTS_DIR must be outside the Actions checkout.' \
            "$workflow rejects a checkout-local pseudo-provisioning channel"
        require_pattern "$workflow" \
            '--producer s9 --producer am2-s19jpro' \
            "$workflow explicitly selects both admitted Zynq producers"
        require_pattern "$workflow" \
            '--result-json "$DCENT_CI_OUTPUT_ROOT/cohort-result.json"' \
            "$workflow binds the exact cohort result destination"
        reject_pattern "$workflow" \
            'DCENT_AM2_CAPSULE_STATUS: unavailable-fail-closed' \
            "$workflow does not retain the obsolete AM2 producer blocker"
        reject_pattern "$workflow" \
            '  push:' \
            "$workflow does not schedule an always-blocked hosted push build"
        reject_pattern "$workflow" \
            '  pull_request:' \
            "$workflow does not schedule an always-blocked hosted pull-request build"
    done

    require_pattern "$image_workflow" \
        '--test release_artifact_contract' \
        'image-smoke executes the public OTA artifact verifier on the capsule artifact'
    require_pattern "$image_workflow" \
        'built_release_artifact_passes_public_ota_contract' \
        'image-smoke invokes the ignored real-artifact contract test explicitly'
    reject_pattern "$image_workflow" \
        'target: am2-s19jpro' \
        'image-smoke uses the verified cohort rather than a mutable target matrix'
    reject_pattern "$image_workflow" \
        'target: cv1835-s19jpro' \
        'image-smoke does not advertise the unpinned CV1835 release lane'
    require_pattern "$nandsim_workflow" \
        '--target both' \
        'nandsim exercises both verified Zynq package producers'
    require_pattern "$nandsim_workflow" \
        '--s19jpro-package "$DCENT_AM2_NANDSIM_PACKAGE"' \
        'nandsim consumes the exact verified AM2 package path'
    reject_pattern "$nandsim_workflow" \
        'OFFLINE_FIRST_INSTALL_PROOF_OK target=am2-s19jpro' \
        'AM2 OTA rehearsal does not invent a first-install proof'
}
release_workflow_capsule_admission_check

require_pattern 'scripts/build_in_docker.sh' 'dcent_prepare_git_release_provenance' 'container build validates provenance against the source worktree'
require_pattern 'scripts/build_in_docker.sh' '-e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"' 'container build passes the canonical epoch into image packaging'
require_file 'scripts/release_envelope_archive.py'
require_file 'scripts/release_stage_boot.py'
require_file 'scripts/test_release_stage_boot.py'
require_file 'scripts/native_zynq_sd/current_release.py'
require_file 'scripts/test_current_bm1398_sd_profiles.py'
require_pattern 'scripts/release_envelope_archive.py' 'atomic_publish(' 'release envelope archive uses exact no-replace durable publication'
require_pattern 'scripts/release_envelope_archive.py' 'snapshot_without_mutation(root) != before' 'release envelope archive detects source mutation while tar reads'
reject_pattern 'scripts/lib/release_envelope.sh' 'rm -f --' 'release envelope library has no pathname-only deletion authority'
reject_pattern 'scripts/build_in_docker.sh' 'dcent_release_remove_publication' 'capsule inner driver never deletes unowned publication pathnames'
require_pattern 'scripts/lib/release_envelope.sh' 'DCENT_CAPSULE_PROVENANCE_VERIFIED' 'exact snapshot provenance requires verified capsule context'
require_pattern 'scripts/lib/release_envelope.sh' 'verify-against-git' 'exact snapshot provenance is reverified against mounted Git objects'
require_pattern 'scripts/lib/release_envelope.sh' 'release-root signing requires DCENT_RELEASE_IMAGE=1 hardening' 'release-root signing implies release-image hardening'
require_file 'scripts/sign_release_artifact.py'
require_file 'scripts/test_sign_release_artifact.sh'
if sh scripts/test_sign_release_artifact.sh >/dev/null 2>&1; then
    pass 'release artifact signer pins, verifies, and durably publishes exact bytes'
else
    fail 'release artifact signer selftest failed'
fi
require_pattern 'scripts/sign_release_artifact.py' 'durable_input=True' 'release artifact signer flushes exact artifact bytes before signature commit'
require_pattern 'scripts/build_in_docker.sh' 'sign_release_artifact.py' 'AM3 tar signing reuses the exact durable signing lifecycle'
require_pattern 'scripts/build_release_capsule.sh' 'sign_release_artifact.py" "$RELEASE_SET_STAGE/producer-result.json"' 'producer-result signing reuses the exact durable signing lifecycle'
require_pattern 'scripts/lib/sysupgrade_package_common.sh' 'sign_release_artifact.py' 'shared sysupgrade manifest signing reuses the exact durable signing lifecycle'
require_pattern 'scripts/package_sysupgrade.sh' 'sign_release_artifact.py' 'standalone sysupgrade manifest signing reuses the exact durable signing lifecycle'
reject_pattern 'scripts/lib/sysupgrade_package_common.sh' 'openssl pkeyutl -sign -rawin' 'shared sysupgrade manifest signing never truncates its signature output'
reject_pattern 'scripts/package_sysupgrade.sh' 'openssl pkeyutl -sign -rawin' 'standalone sysupgrade manifest signing never truncates its signature output'
require_file 'scripts/test_sign_stock_manifest.sh'
if sh scripts/test_sign_stock_manifest.sh >/dev/null 2>&1; then
    pass 'stock manifest signer produces a trusted no-replace candidate'
else
    fail 'stock manifest signer selftest failed'
fi
require_pattern 'scripts/sign_stock_manifest.sh' 'sign_release_artifact.py' 'stock manifest signing reuses the exact durable signing lifecycle'
require_pattern 'scripts/sign_stock_manifest.sh' 'DCENT_RELEASE_PUBKEY_FILE' 'stock manifest signing requires a trusted public key'
reject_pattern 'scripts/sign_stock_manifest.sh' 'pkeyutl -sign' 'stock manifest signing never truncates a tracked signature placeholder'
require_file 'scripts/test_sign_release_dry_run.sh'
if sh scripts/test_sign_release_dry_run.sh >/dev/null 2>&1; then
    pass 'release signing rehearsal exercises the exact signer end to end'
else
    fail 'release signing rehearsal selftest failed'
fi
require_pattern 'scripts/sign_release_dry_run.sh' 'sign_release_artifact.py' 'release signing rehearsal reuses the exact durable signing lifecycle'
reject_pattern 'scripts/sign_release_dry_run.sh' 'pkeyutl -sign' 'release signing rehearsal never truncates its signature output'
require_pattern 'scripts/verify_sysupgrade_signature.sh' 'select_manifest_python' 'host verifier probes a runnable Python interpreter'
require_pattern 'scripts/verify_sysupgrade_signature.sh' 'run_manifest_python "$MANIFEST_JSON_HELPER" validate' 'host verifier uses the probed Python interpreter for semantic admission'
reject_pattern 'scripts/build_in_docker.sh' 'openssl pkey -in /signkey -pubout' 'AM3 tar signing never derives its own trust root'
require_pattern 'scripts/package_sysupgrade.sh' 'dcent_create_deterministic_tar' 'S9 sysupgrade uses the deterministic envelope archiver'
require_pattern 'br2_external_dcentos/board/zynq/am2-s19jpro/post-image.sh' 'dcent_create_deterministic_tar' 'AM2 sysupgrade uses the deterministic envelope archiver'
if awk '
    /dcent_write_sysupgrade_manifest/ { rewrite = NR }
    /dcent_create_deterministic_tar/ { archive = NR }
    END { exit !(rewrite > 0 && archive > rewrite) }
' 'br2_external_dcentos/board/zynq/am2-s19jpro/post-image.sh'; then
    pass 'AM2 shared final-manifest rewrite occurs before deterministic packaging'
else
    fail 'AM2 must rewrite/sign the canonical shared manifest before deterministic packaging'
fi
require_pattern 'dcentrald/dcentrald-api/tests/release_artifact_contract.rs' 'verify_sysupgrade_bundle(&artifact, false, Some(&public_key))' 'real-artifact test calls the public fail-closed OTA verifier'
require_pattern 'dcentrald/dcentrald-stratum/src/v1/messages.rs' 'parse_pool_message_never_panics_on_arbitrary_or_malformed_input' 'V1 pool-message parser has malformed-input panic coverage'
require_pattern 'dcentrald/dcentrald-api/src/cgminer.rs' 'cgminer_shared_toolbox_contract_fixture_matches_dispatcher' 'cgminer dispatcher is pinned to shared toolbox contract fixture'
require_pattern '../dcent-toolbox/tests/test_cgminer_shape.py' 'test_dcentos_shared_cgminer_contract_fixture_parses_like_toolbox_expects' 'toolbox parses the shared dcentos cgminer contract fixture'
require_pattern 'dcentrald/dcentrald-api/tests/cgminer_luxos_routes.rs' 'api1_batch_with_mutation_is_invalid_even_loopback' 'cgminer API rejects mutating batch requests from loopback'
require_pattern 'dcentrald/dcentrald-api/tests/cgminer_luxos_routes.rs' 'api1_batch_restart_from_lan_peer_refused' 'cgminer API rejects mutating batch requests from LAN peers'
require_pattern 'dcentrald/dcentrald-stratum/src/v1/client.rs' 'fov6_config_drive_arm_advances_current_pool_index' 'failover simulation pins drive-mode arm transition'
require_pattern 'dcentrald/dcentrald-stratum/src/v1/client.rs' 'fov6_shadow_only_does_not_change_current_pool_index' 'failover simulation pins shadow-only no-op transition'
require_pattern 'dcentrald/dcentrald-stratum/src/v1/client.rs' 'fov6_production_triggers_do_not_advance_under_drive' 'failover simulation pins production-trigger guardrail under drive mode'
require_pattern 'dcentrald/dcentrald-common/src/wallet_mask.rs' 'wallet_mask_helpers_never_panic_on_arbitrary_text' 'wallet-mask helpers have arbitrary-text panic coverage'
require_pattern 'dcentrald/dcentrald-api/src/webhook.rs' 'redaction_is_applied_before_every_channel_render' 'webhook rendering applies redaction before every channel'
require_pattern 'dcentrald/dcentrald-api/src/websocket.rs' 'ws_stats_frame_masks_donation_url_and_worker' 'websocket stats frames mask donation URL and worker'
require_pattern 'dcentrald/dcentrald-stratum/src/v1/client.rs' 'failover_status_reports_active_pool_without_secrets' 'failover telemetry reports active pool without credentials'
require_pattern 'dcentrald/dcentrald/src/runtime/notifications.rs' 'mapping_then_redact_yields_clean_webhook_event' 'runtime notifications map then redact webhook events'
require_pattern 'dcentrald/dcentrald-asic/src/lib.rs' 'deterministic_mock_chain_mini_soak_covers_share_failover_and_ota_preflight' 'MockChain mini-soak executes in dcentrald-asic host tests'
require_pattern '../dcentos-esp/dcentaxe-hal/src/board.rs' 'board_version_deep_parity_pins_power_and_support_attributes' 'ESP board-version deep parity pins power/fan/temp/support attributes'
require_pattern '../dcentos-esp/dcentaxe-hal/src/board.rs' 'every_model_has_explicit_default_board_version' 'ESP every BitAxeModel has an explicit default board-version pin'
# Lucky Miner LVxx (EXPERIMENTAL, no live hardware). These EXTEND the two pins
# above; never replace them. The voltage-domain pin is the load-bearing one:
# the LVXX vendor fork deleted a live 3.6 V / 9-chip LV08 case, and
# `power.rs` derives the rail as per-chip mV x voltage_domains, so any Lucky
# row with voltage_domains > 1 would command a multiple of 1.2 V onto nine
# PARALLEL dies. The tach pin keeps LV07/LV08 fail-closed on fan proof without
# joining `is_hex()` (which would also mislabel them as 6-ASIC/3-domain).
require_pattern '../dcentos-esp/dcentaxe-hal/src/board.rs' 'lucky_voltage_domains_pinned_to_one_parallel_domain' 'ESP Lucky LVxx rows pin one parallel voltage domain (3.6 V trap guard)'
require_pattern '../dcentos-esp/dcentaxe-hal/src/board.rs' 'lucky_lv07_lv08_require_tach_proof_via_capability_not_is_hex' 'ESP Lucky multi-chip rows require tach proof by capability, not is_hex()'
# The Python mirror keys rows by board_version, so a duplicate key silently
# collapses two rows into one (and `find()` makes the second row unreachable
# dead code on the Rust side). The drift gate must fail loudly at the
# collision instead.
require_pattern '../dcent-toolbox/tests/test_board_catalog_consistency.py' 'duplicate board_version key(s) in BoardVersionProfile::ALL' 'toolbox ESP drift gate fails loudly on a duplicate board_version key'
require_pattern '../dcentos-esp/knowledge-base/upstream/esp-miner/fixture_manifest.json' 'last_synced_on' 'ESP-Miner fixture manifest records last sync date'
require_pattern '../dcentos-esp/knowledge-base/upstream/esp-miner/fixture_manifest.json' 'no_network_fetch_in_ci' 'ESP-Miner fixture drift gate stays source-only'
require_pattern '../dcentos-esp/docs/DCENT_AXE_OPERATOR_BENCH_RUNBOOK.md' 'ESP-9: ESP-Miner Fixture Sync Review' 'operator runbook carries ESP-Miner fixture sync checklist'
require_pattern '../../.github/workflows/bitaxe-build-matrix.yml' './scripts/build-matrix.sh' 'root bitaxe build workflow runs the ESP public build matrix'
require_pattern '../../.github/workflows/bitaxe-build-matrix.yml' 'WAVE9D7_XTENSA_ICE_QUARANTINE.md' 'root bitaxe build workflow points to xtensa ICE quarantine policy'
require_pattern '../../.github/workflows/dcentos-esp-release.yml' 'esp-rs/xtensa-toolchain@v1' 'ESP release workflow uses the xtensa toolchain for public releases'
require_pattern '../../.github/workflows/dcentos-esp-release.yml' 'xtensa-esp32s3-espidf' 'ESP release workflow pins xtensa target environment'
require_pattern '../dcentos-esp/docs/WAVE9D7_XTENSA_ICE_QUARANTINE.md' 'Wave 9D7' 'Wave 9D7 xtensa ICE quarantine policy is documented'
require_pattern '../dcentos-esp/docs/WAVE9D7_XTENSA_ICE_QUARANTINE.md' 'Public targets must not be silently skipped' 'xtensa quarantine policy forbids silent public-target skips'
require_pattern '../dcentos-esp/dcentaxe-hal/src/power_convert.rs' 'ds4432u_operator_bench_measurements_accept_meter_log' 'DS4432U ignored operator bench harness is present'
require_pattern '../dcentos-esp/docs/DCENT_AXE_OPERATOR_BENCH_RUNBOOK.md' 'DCENT_DS4432U_BENCH_MV_CSV' 'operator runbook documents the DS4432U bench harness input'
require_pattern '../dcent-toolbox/src/dcent_toolbox/core/install_package.py' 'def signature_status' 'toolbox install package exposes a central signature_status'
require_pattern '../dcent-toolbox/src/dcent_toolbox/core/install_package.py' 'board_identity_signed' 'toolbox install package tracks board-bound signature identity'
require_pattern '../dcent-toolbox/src/dcent_toolbox/core/installer.py' '_sig_status != "signed"' 'toolbox target-sysupgrade executor refuses unsigned packages by default'
require_pattern '../dcent-toolbox/src/dcent_toolbox/core/installer.py' 'allow_unsigned_lab=_allow_unsigned_lab' 'toolbox target-sysupgrade writer receives only explicit unsigned-lab override'
require_pattern '../dcent-toolbox/tests/test_install_signing_gate.py' 'test_unsigned_package_blocks_plan' 'toolbox planner signature gate blocks unsigned packages'
require_pattern '../dcent-toolbox/tests/test_install_signing_gate.py' 'test_unverifiable_package_blocks_plan' 'toolbox planner signature gate blocks unverifiable packages'
require_pattern '../dcent-toolbox/tests/test_install_inline_signature_board_binding.py' 'test_detached_manifest_sig_is_board_bound_and_relabel_invalidates' 'toolbox package signature tests pin detached manifest board binding'
require_pattern '../dcent-toolbox/tests/test_install_inline_signature_board_binding.py' 'test_unsigned_package_is_not_board_bound' 'toolbox package signature tests pin unsigned packages as unbound'
require_pattern '../dcent-toolbox/tests/test_install_w15_am2_persistent_lab.py' 'test_target_sysupgrade_refuses_unsigned_package_by_default' 'toolbox executor test refuses unsigned target sysupgrade packages'
require_pattern '../dcent-toolbox/tests/test_install_w15_am2_persistent_lab.py' 'writer must NOT be called for an unsigned package (Gate 8a)' 'toolbox executor test pins writer not called for unsigned packages'
require_pattern '../dcent-toolbox/tests/test_adv04_write_path_review.py' 'test_toolbox_target_sysupgrade_keeps_restore_signature_recovery_gates' 'toolbox source-order review pins signature gate before target-sysupgrade writer'
require_pattern '../dcent-toolbox/tests/test_sysupgrade_guard_execution.py' 'AM2_SYSUPGRADE_VARIANTS' 'toolbox sysupgrade guard tests enumerate AM2 variant overlays'
require_pattern '../dcent-toolbox/tests/test_sysupgrade_guard_execution.py' 'test_sysupgrade_t_executes_wrong_board_brick_guard' 'toolbox sysupgrade tests pin wrong-board refusal'
require_pattern '../dcent-toolbox/tests/test_sysupgrade_guard_execution.py' 'test_sysupgrade_t_refuses_shorter_board_near_miss_prefix' 'toolbox sysupgrade tests pin near-miss board prefix refusal'
require_pattern '../dcent-toolbox/tests/test_sysupgrade_guard_execution.py' 'test_sysupgrade_t_refuses_per_unit_board_variant_under_exact_pin' 'toolbox sysupgrade tests pin the per-unit board-variant refusal under the exact-target pin'
require_pattern '../dcent-toolbox/tests/test_am2_s17_route_promotion.py' 'test_am2_s17_route_promotion' 'toolbox 17-series stock targets resolve named evidence-gap routes'
require_pattern '../dcent-toolbox/tests/test_am2_s17_route_promotion.py' 'test_interpret_efuse_status_word_bit_0x400' 'toolbox pins the EFUSE_STATUS 0xF800D010 bit 0x400 boot-chain lock read'
require_pattern '../dcent-toolbox/tests/test_am2_s17_route_promotion.py' 'test_s17_family_install_routes_follow_the_efuse_bit' 'toolbox pins the SD/ramdisk-swap/NAND route cascade against the eFuse bit'
require_pattern 'docs/reviews/2026-07-05-wave7-uncovered-surfaces-audit.md' 'W7-R1: Narrow Pre-setup Recovery GET Exposure' 'Wave 7 audit records recovery pre-setup GET exposure follow-up'
require_pattern 'docs/reviews/2026-07-05-wave7-uncovered-surfaces-audit.md' 'W7-R2: Stock Restore Archive Trust Boundary' 'Wave 7 audit records stock restore archive trust-boundary follow-up'
require_pattern 'docs/reviews/2026-07-05-wave7-uncovered-surfaces-audit.md' 'W7-D1: Fsync Metrics CSV Exports' 'Wave 7 audit records metrics CSV persistence follow-up'
require_pattern 'docs/reviews/2026-07-05-wave7-uncovered-surfaces-audit.md' 'W7-D2: Fix Persistent Log Ring Cursor Commit' 'Wave 7 audit records persistent log ring cursor follow-up'
require_pattern 'docs/reviews/2026-07-05-wave7-uncovered-surfaces-audit.md' 'W7-D3: Fsync Auto-recovery Ladder State' 'Wave 7 audit records auto-recovery ladder persistence follow-up'
require_pattern 'docs/reviews/2026-07-05-wave7-uncovered-surfaces-audit.md' 'W7-L1: Constrain `/data/logrotate.conf`' 'Wave 7 audit records logrotate override bounds follow-up'
require_pattern 'docs/reviews/2026-07-05-wave7-uncovered-surfaces-audit.md' 'W7-L2: Keep Runtime State on tmpfs' 'Wave 7 audit records runtime tmpfs layout follow-up'
require_pattern 'dcentrald/dcentrald-api/src/rest.rs' 'mod late;' 'Wave 8 rest.rs decomposition keeps late route handlers in a child module'
require_pattern 'dcentrald/dcentrald-api/src/rest/late.rs' 'mounted_router_path_snapshot_is_explicit' 'Wave 8 route-table snapshot test is present'
require_pattern 'dcentrald/dcentrald-api/src/rest/route_paths_snapshot.txt' '/api/system/restore-to-stock/preflight-checks' 'Wave 8 route snapshot includes recovery routes'

rest_rs_decomposition_shape_check() {
    f='dcentrald/dcentrald-api/src/rest.rs'
    require_file "$f"
    [ -f "$f" ] || return
    _lines=$(wc -l < "$f" | tr -d '[:space:]')
    if [ "$_lines" -lt 10000 ]; then
        pass "Wave 8 rest.rs decomposition: $f is below 10000 lines ($_lines)"
    else
        fail "Wave 8 rest.rs decomposition: $f has $_lines lines (must stay below 10000)"
    fi
}
rest_rs_decomposition_shape_check

browser_sysupgrade_upload_signature_gate() {
    _rest='dcentrald/dcentrald-api/src/rest/late.rs'
    require_file "$_rest"
    _line=$(grep -n 'verify_sysupgrade_bundle(' "$_rest" 2>/dev/null | tail -n 1 | cut -d: -f1 || true)
    if [ -z "$_line" ]; then
        fail "browser sysupgrade upload path calls verify_sysupgrade_bundle"
        return
    fi
    _end=$((_line + 10))
    _call=$(sed -n "${_line},${_end}p" "$_rest")
    case "$_call" in
        *'false,'*'SYSTEM_UPGRADE_RELEASE_PUBKEY'*)
            pass "browser sysupgrade upload path hardcodes allow_unsigned=false and the on-disk release key"
            ;;
        *)
            fail "browser sysupgrade upload path must call verify_sysupgrade_bundle(..., false, Some(SYSTEM_UPGRADE_RELEASE_PUBKEY))"
            ;;
    esac
}
browser_sysupgrade_upload_signature_gate

# PH-1 (): /api/stratum/protocol prose must not re-introduce the SV2
# overclaim. The test-pinned firmware_stratum_matrix sets V1=Default, SV2=OptIn,
# and the pool config default is sv1 — so SV2 is an opt-in client, not the
# default, and there is no live SV2 accepted-share proof yet. Ban the two
# unambiguous overclaim phrases so a future edit can't silently re-add them.
reject_pattern 'dcentrald/dcentrald-api/src/rest.rs' 'only flavor defaulting to SV2' 'stratum protocol prose does not claim SV2 is the default (V1 is)'
reject_pattern 'dcentrald/dcentrald-api/src/rest.rs' 'supports Stratum V2 end-to-end' 'stratum protocol prose does not claim SV2 end-to-end (live proof pending)'
reject_pattern 'dcentrald/dcentrald/src/daemon.rs' 'Universal Hash Board Compatibility ACTIVE' 'daemon runtime strings do not advertise universal hash-board compatibility'
reject_pattern 'dcentrald/dcentrald/src/daemon.rs' 'any hash board generation' 'daemon runtime strings do not claim any-generation hash-board support'
reject_pattern 'dcentrald/dcentrald/src/daemon.rs' 'No competitor does this' 'daemon runtime strings do not carry competitor overclaims'
require_pattern 'dcentrald/dcentrald/src/daemon.rs' 'hash board auto-detected by ChipID (broad Zynq-era support)' 'daemon runtime strings keep the neutral ChipID support wording'
open_core_override_scope_check() {
    # bm1393.rs joined the allowlist 2026-09-12 (R03 wave-1 landing,
    # V01-confirmed): its send_open_core_work override is REFUSAL-ONLY — the
    # trait default silently returns Ok(0), which would skip BM1393's
    # mandatory 208-core open-core step on any future FpgaChain consumer; the
    # real open-core sequence is owned by the C43 fabric
    # (Bm1393Runtime::open_cores). No send path exists in the driver, so the
    # override cannot grant unproven send authority. BM1362/BM1366/BM1368/
    # BM1370 still inherit the default no-op.
    _hits=$(
        grep -RIn 'fn send_open_core_work' dcentrald/dcentrald-asic/src/drivers 2>/dev/null \
            | grep -Ev 'drivers/(mod|bm1387|bm1398|bm1393)\.rs:' || true
    )
    if [ -n "$_hits" ]; then
        echo "$_hits"
        fail "open-core override scope: only BM1387, BM1398 and the refusal-only bm1393 may override send_open_core_work without a bench-backed allowlist update"
    else
        pass "open-core override scope: BM1362/BM1366/BM1368/BM1370 inherit the default no-op; bm1393 override is refusal-only"
    fi
}
open_core_override_scope_check
require_pattern 'dcentrald/dcentrald-asic/src/drivers/bm1398.rs' 'bm139x_open_core_enable_value_matches_jig' 'BM1398 open-core value stays pinned to the BM1397 jig formula'
require_pattern 'dcentrald/dcentrald-asic/src/drivers/bm1398.rs' 'if !bm139x_open_core_enabled()' 'BM1398 open-core sweep remains default-off behind its env gate'
require_pattern 'dcentrald/dcentrald-api-types/src/lib.rs' 'pub mod api_error_codes' 'API REST error-code vocabulary is centralized and stable'
require_pattern 'dcentrald/dcentrald-api/src/rest/late.rs' 'api_error_mapper_wraps_bare_text_and_json_string_only' 'API error mapper pins machine-readable codes for legacy bodies'
require_pattern 'dcentrald/dcentrald-api/src/rest/late.rs' 'donation_config_route_rejects_bad_percent' 'config validation errors expose a stable CONFIG_VALIDATION code'
require_pattern 'dcentrald/dcentrald-api/src/rest/late.rs' 'config_update_validation_matrix_rejects_known_bad_inputs' 'config update validation matrix covers known bad inputs'
require_pattern 'dcentrald/dcentrald-api/src/rest/late.rs' 'config_update_merge_never_panics_on_bounded_json_patch' 'config update merge has bounded arbitrary-patch panic coverage'
require_pattern 'dcentrald/dcentrald-api/src/auth.rs' 'persisted_session_survives_daemon_restart_idle_map_reset' 'auth sessions survive daemon restart without reviving expired sessions'
require_pattern 'dcentrald/dcentrald/src/config.rs' 'http_bind = "miner.local"' 'api.http_bind validation rejects non-IP hostnames'
require_pattern 'dcentrald/dcentrald/src/config.rs' 'api_http_bind_defaults_to_existing_lan_visible_bind' 'api.http_bind default preserves LAN-visible dashboard bind'
require_pattern 'dcentrald/dcentrald-api/src/lib.rs' 'http_bind_addr_preserves_default_and_accepts_loopback_override' 'HTTP bind helper preserves default and loopback override contracts'
require_pattern 'dcentrald/dcentrald-api/src/lib.rs' 'state.config.websocket_tickets' 'API startup propagates the websocket ticket compatibility flag'
require_pattern 'dcentrald/dcentrald-api/src/rest.rs' '/api/auth/ws-ticket' 'one-time websocket ticket mint route is present'
require_pattern 'dcentrald/dcentrald-api/src/auth.rs' 'ws_ticket_flow_is_default_off_short_lived_and_one_time' 'websocket tickets are default-off, short-lived, and one-time'
require_pattern 'dcentrald/dcentrald-api/src/auth.rs' 'ticket=REDACTED' 'websocket ticket credentials are redacted from URI logs'
require_pattern 'scripts/lib/dcentrald_version_gate.sh' 'dcent_require_dcentrald_version_match' 'shared dcentrald version gate exposes fail-closed helper'
require_pattern 'scripts/lib/dcentrald_version_gate.sh' 'lab bypass requires non-release DCENT_PACKAGE_STATUS plus DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1' 'dcentrald version gate lab override is explicit'
require_pattern 'br2_external_dcentos/board/zynq/post-build.sh' 'dcent_require_dcentrald_version_match' 'zynq post-build enforces dcentrald version gate'
require_pattern 'br2_external_dcentos/board/zynq/am2-s19jpro/post-build.sh' 'dcent_require_dcentrald_version_match' 'am2 post-build enforces dcentrald version gate'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-build.sh' 'dcent_require_dcentrald_version_match' 'am3-s19k post-build enforces dcentrald version gate'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s21/post-build.sh' 'dcent_require_dcentrald_version_match' 'am3-s21 post-build enforces dcentrald version gate'
require_pattern 'br2_external_dcentos/board/beaglebone/am3-bb/post-build.sh' 'dcent_require_dcentrald_version_match' 'am3-bb post-build enforces dcentrald version gate'
require_pattern 'scripts/build_in_docker.sh' 'build_in_docker Phase 5' 'build_in_docker validates staged dcentrald version before Buildroot'
require_pattern 'scripts/build_in_docker.sh' 's9|am3-s19kpro|am3-s19kpro-nopic|am3-s19xp|am3-s19jxp|am3-s19jproa|am3-s19jproplus|am3-s21|am3-s21pro|am3-s21xp|am3-s19jpro-aml|am3-t21|am2-s19jpro|am2-s19pro)' 'build_in_docker applies package validation to every declared tar target'
require_pattern 'scripts/build_in_docker.sh' 'pre_flash_validate.sh --package-only' 'build_in_docker runs am3 package-only validation'
require_pattern 'scripts/build_amlogic_native_install.sh' 'pre_flash_validate.sh" --package-only' 'amlogic native image builder validates sysupgrade package before extraction'
require_pattern 'scripts/build_amlogic_native_install.sh' 'DCENT_REQUIRE_INSTALLABLE_PACKAGE=1' 'amlogic native image builder refuses inspection-only packages'
require_pattern 'scripts/build_amlogic_native_install.sh' 'OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"' 'amlogic native image builder canonicalizes output-dir before reuse'
require_pattern 'scripts/build_amlogic_native_install.sh' 'extracted rootfs exceeds Amlogic rootfs window' 'amlogic native image builder bounds extracted rootfs image'
require_pattern 'scripts/build_amlogic_native_install.sh' 'extracted rootfs is not a uImage payload' 'amlogic native image builder validates extracted rootfs magic'
require_pattern 'scripts/build_amlogic_native_install.sh' 'DCENT_AM3_ROOTFS_WINDOW_DEC' 'amlogic native image builder uses shared am3 rootfs window'
require_pattern 'scripts/install_amlogic_persistent.sh' 'Step 0/10: local package-only validation' 'amlogic persistent installer validates package before SSH'
require_pattern 'scripts/install_amlogic_persistent.sh' 'pre_flash_validate.sh" --package-only "$FIRMWARE" "$BOARD_PKG_NAME"' 'amlogic persistent installer reuses package-only validator'
require_pattern 'scripts/install_amlogic_persistent.sh' 'DCENT_REQUIRE_INSTALLABLE_PACKAGE=1' 'amlogic persistent installer refuses inspection-only packages before SSH/staging'
require_pattern 'scripts/install_amlogic_persistent.sh' '--variant s19jpro-aml|s19jproplus|s19kpro|s21|s21pro' 'amlogic persistent installer supports only admitted exact Amlogic variants'
require_pattern 'scripts/install_amlogic_persistent.sh' 'PACKAGE_PREFIX="sysupgrade-am3-s19jpro-aml"' 'amlogic persistent installer maps S19j Pro AML package prefix'
require_pattern 'scripts/install_amlogic_persistent.sh' 'PACKAGE_PREFIX="sysupgrade-am3-s19jproplus"' 'amlogic persistent installer maps S19j Pro+ package prefix'
require_pattern 'scripts/install_amlogic_persistent.sh' 'S19 XP is NOT-IMPLEMENTED and package-only; persistent install is refused' 'amlogic persistent installer refuses S19 XP writes'
require_pattern 'scripts/install_amlogic_persistent.sh' 'S19j XP is NOT-IMPLEMENTED and package-only; persistent install is refused' 'amlogic persistent installer refuses S19j XP writes'
require_pattern 'scripts/install_amlogic_persistent.sh' 'PACKAGE_PREFIX="sysupgrade-am3-s21"' 'amlogic persistent installer maps S21 package prefix'
require_pattern 'scripts/install_amlogic_persistent.sh' 'PACKAGE_PREFIX="sysupgrade-am3-s21pro"' 'amlogic persistent installer maps S21 Pro package prefix'
reject_pattern 'scripts/install_amlogic_persistent.sh' 'PACKAGE_PREFIX="sysupgrade-am3-s21xp"' 'amlogic persistent installer refuses S21 XP while its platform and flash contracts are unproven'
reject_pattern 'scripts/install_amlogic_persistent.sh' 'PACKAGE_PREFIX="sysupgrade-am3-t21"' 'amlogic persistent installer refuses T21 while its flash geometry is unproven'
reject_pattern 'scripts/build_amlogic_native_install.sh' 'BOARD_PKG_NAME="am3-s21xp"' 'amlogic native extractor does not label an S21 XP package as flashable'
reject_pattern 'scripts/build_amlogic_native_install.sh' 'BOARD_PKG_NAME="am3-t21"' 'amlogic native extractor does not label a T21 package as flashable'
require_pattern 'scripts/install_amlogic_persistent.sh' 'REMOTE_STAGE_DIR="/data/.dcentos-sysupgrade-$LOCAL_SHA"' 'amlogic persistent installer uses a content-bound no-clobber remote transaction'
require_pattern 'scripts/install_amlogic_persistent.sh' 'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"' 'amlogic persistent installer resolves validator path from script dir'
reject_pattern 'scripts/install_amlogic_persistent.sh' '/data/dcentos-sysupgrade.tar' 'amlogic persistent installer refuses a fixed remote bundle path'
reject_pattern 'scripts/install_amlogic_persistent.sh' 'rm -rf /data/sysupgrade' 'amlogic persistent installer never deletes a shared remote staging path'
require_pattern 'scripts/install_amlogic_persistent.sh' 'ROOTFS_END_DEC' 'amlogic persistent installer computes rootfs window end'
require_pattern 'scripts/install_amlogic_persistent.sh' 'mtd5 geometry OK' 'amlogic persistent installer validates target mtd5 geometry'
require_pattern 'scripts/install_amlogic_persistent.sh' 'root payload $ROOT_SIZE exceeds rootfs window' 'amlogic persistent installer bounds root payload size'
require_pattern 'scripts/install_amlogic_persistent.sh' 'fw_printenv backup is empty' 'amlogic persistent installer rejects empty fw_env backup'
require_pattern 'scripts/install_amlogic_persistent.sh' 'nand_env backup size $NAND_ENV_SIZE != 65536' 'amlogic persistent installer validates nand_env backup size'
require_pattern 'scripts/install_amlogic_persistent.sh' 'nand_env backup SHA mismatch' 'amlogic persistent installer verifies nand_env backup transfer'
require_pattern 'scripts/install_amlogic_persistent.sh' 'mtd5 backup SHA mismatch' 'amlogic persistent installer verifies mtd5 backup transfer'
require_pattern 'scripts/install_amlogic_persistent.sh' 'rootfs readback SHA mismatch' 'amlogic persistent installer verifies flashed rootfs readback'
require_pattern 'scripts/install_amlogic_persistent.sh' 'install_preflight_manifest.json' 'amlogic persistent installer writes recovery manifest'
require_pattern 'scripts/install_amlogic_persistent.sh' '"stage": "payload_verified"' 'amlogic persistent installer records recovery manifest stage'
require_pattern 'scripts/install_amlogic_persistent.sh' 'root_payload_sha256' 'amlogic persistent installer records root payload hash in manifest'
require_pattern 'scripts/install_amlogic_persistent.sh' 'remote_firmware_sha256' 'amlogic persistent installer records remote package hash in manifest'
require_pattern 'scripts/install_amlogic_persistent.sh' '"package_board": "$BOARD_PKG_NAME"' 'amlogic persistent installer records dynamic package board in manifest'
require_pattern 'scripts/install_amlogic_persistent.sh' 'root_write_readback.uimage' 'amlogic persistent installer preserves rootfs write readback artifact'
require_pattern 'scripts/install_amlogic_persistent.sh' 'refusing firstboot-only' 'amlogic persistent installer refuses firstboot-only install commit'
require_pattern 'scripts/revert_to_stock_am3_aml_s19k.sh' 'refusing firstboot-only' 'am3 s19k revert refuses firstboot-only commit'
require_pattern 'scripts/revert_to_stock_am3_aml_s19k.sh' 'REVERT_COMMIT_PLAN' 'am3 s19k revert writes REVERT_COMMIT_PLAN'
require_pattern 'scripts/revert_to_stock_am3_aml_s19k.sh' 'recover_env_source=nandrecovery_env.bin' 'am3 s19k revert names nandrecovery recover_env'
require_pattern 'scripts/revert_to_stock_am3_aml_s19k.sh' 'does NOT arm flag 0x02' 'am3 s19k revert does not mix flag 0x02'
require_pattern 'scripts/revert_to_stock_am3_aml_s19k.sh' '--dry-run' 'am3 s19k revert accepts --dry-run'
require_pattern 'scripts/revert_to_stock_am3_aml_s19k.sh' '[DRY RUN] writing REVERT_COMMIT_PLAN before GPIO/nandwrite' 'am3 s19k revert dry-run writes plan before NAND'
require_pattern 'scripts/revert_to_stock_am3_aml_s19k.sh' 'dry_run=true nandwrite=false gpio_write=false' 'am3 s19k revert dry-run emits plan field literals'
require_pattern 'scripts/revert_to_stock_am3_aml_s19k.sh' 'CLEAR_FOR_FLASH=false — refusing gpio437 SafeOff/nandwrite/fw_setenv' 'am3 s19k revert execute refuses NAND while FLASH-false'
require_pattern 'scripts/dcentrald_s19k_tmp_deploy.sh' '--dry-run' 's19k tmp deploy accepts --dry-run'
require_pattern 'scripts/dcentrald_s19k_tmp_deploy.sh' 'TMP_DEPLOY_PLAN' 's19k tmp deploy writes TMP_DEPLOY_PLAN'
require_pattern 'scripts/dcentrald_s19k_tmp_deploy.sh' 'musl_static=true' 's19k tmp deploy admits musl-static'
require_pattern 'scripts/dcentrald_s19k_tmp_deploy.sh' 'ld-linux' 's19k tmp deploy refuses glibc interp'
reject_pattern 'scripts/revert_to_stock_am3_aml_s19k.sh' 'fw_setenv firstboot 1' 'am3 s19k revert does not execute fw_setenv firstboot 1'
require_pattern 'scripts/install_amlogic_persistent.sh' 'INSTALL_COMMIT_PLAN.txt' 'amlogic persistent installer writes install-commit plan'
require_pattern 'scripts/install_amlogic_persistent.sh' 'write_install_commit_plan()' 'amlogic persistent installer emits rust InstallArm plan via helper'
require_pattern 'scripts/install_amlogic_persistent.sh' 'uboot_action=FirstBosThenSetFlag2' 'amlogic persistent installer commit plan names FirstBosThenSetFlag2'
require_pattern 'scripts/install_amlogic_persistent.sh' 'eraseblock_index=' 'amlogic persistent installer commit plan names eraseblock_index'
require_pattern 'scripts/install_amlogic_persistent.sh' 'RECOVER_TO_STOCK_PLAN.txt' 'amlogic persistent installer writes recover-to-stock plan'
require_pattern 'scripts/install_amlogic_persistent.sh' 'recover_amlogic_to_stock.sh' 'amlogic persistent installer names recover-to-stock runner'
require_pattern 'scripts/install_amlogic_persistent.sh' 'sh "$RECOVER_RUNNER" --artifact-dir "$ARTIFACT_DIR" --dry-run' 'amlogic persistent installer invokes recover --dry-run'
require_pattern 'scripts/install_amlogic_persistent.sh' 'recover-to-stock --dry-run failed; refusing successful backup' 'amlogic persistent installer refuses backup if recover walk fails'
require_pattern 'scripts/install_amlogic_persistent.sh' 'RECOVER_WALK.txt' 'amlogic persistent installer requires RECOVER_WALK after dry-run'
require_pattern 'scripts/lib/am3_geometry.sh' 'dcent_am3_extract_recovery_flag_eraseblock()' 'am3 geometry slices 128KiB recovery-flag eraseblock'
require_pattern 'scripts/install_amlogic_persistent.sh' 'dcent_am3_extract_recovery_flag_eraseblock' 'amlogic persistent installer slices recovery-flag eraseblock'
require_pattern 'scripts/install_amlogic_persistent.sh' 'sh "$FLAG_HELPER" --value 0x01' 'amlogic persistent installer walks 0x01 fixture'
require_pattern 'scripts/install_amlogic_persistent.sh' 'INSTALL_COMMIT_WALK.txt' 'amlogic persistent installer writes INSTALL_COMMIT_WALK'
require_pattern 'scripts/install_amlogic_persistent.sh' 'recovery-flag 0x01 fixture walk failed; refusing successful backup' 'amlogic persistent installer refuses backup if 0x01 fixture walk fails'
require_pattern 'scripts/install_amlogic_persistent.sh' '0x01 fixture-out length' 'amlogic persistent installer refuses wrong 0x01 fixture length'
require_pattern 'scripts/install_amlogic_persistent.sh' '0x01 fixture-out byte0=' 'amlogic persistent installer refuses wrong 0x01 fixture first byte'
require_pattern 'dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs' 'resolve_plug_gpio_global' 'amlogic HAL resolves plug GPIOs by name'
require_pattern 'dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs' '"CH0_PLUG"' 'amlogic HAL uses CH0_PLUG not integer-only 439'
require_pattern 'dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs' 'resolve_reset_gpio_global' 'amlogic HAL resolves HB reset GPIOs by name'
require_pattern 'dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs' '"HB0_RESET"' 'amlogic HAL uses HB0_RESET not integer-only 454'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'resolve_psu_gpio_global' 'Track-1 preflight resolves PWR_CONTROL before observe'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'resolve_plug_gpio_global' 'Track-1 preflight resolves CH*_PLUG before observe'
require_pattern 'dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs' 'resolve_fan_tach_gpio_global' 'amlogic HAL resolves fan tach GPIOs by name'
require_pattern 'dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs' '"FAN_FRONT_SPEED0"' 'amlogic HAL uses S21 FAN_FRONT_SPEED0 not integer-only 447'
require_pattern 'dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs' 'resolve_led_gpio_global' 'amlogic HAL resolves LED GPIOs by name'
require_pattern 'dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs' '"LED_RED"' 'amlogic HAL uses LED_RED not integer-only 438'
require_pattern 'dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs' 'resolve_pinmux_gpio_global' 'amlogic HAL resolves I2C pinmux GPIOs by name'
require_pattern 'dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs' '"I2C_SCL"' 'amlogic HAL uses I2C_SCL not integer-only 476'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'S19kRxExpectedAfter::FastUart28' 'Track-1 classifies FastUART 0x28 read'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'send_read_reg_broadcast_bm1397plus' 'Track-1 TX is broadcast 52 05 00 28'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 's19k_track1_should_retry_115200' 'Track-1 115200 retry is gated'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 's19k_track1_retry_restore_baud' 'Track-1 115200 retry restores 3M'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'impl Drop for Track1HostBaudRestore' 'Track-1 115200 retry restores 3M on Drop'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'refuse_work_tx_if_host_not_3m_after_restore' 'Track-1 refuses work TX if restore left host off 3M'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'classify_s19k_dual_baud_silence' 'Track-1 classifies 115200 retry against GPIO437'
require_pattern 'dcentrald/dcentrald-common/src/s19k_passthrough_preflight.rs' 'ChipHeardWhileRailsDisabled' 'dual-baud class distinguishes chip-heard from GPIO437 DISABLE'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'GetAddress115200Retry' 'Track-1 classifies 115200 retry separately from 3M GetAddress'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_uart_rx.rs' 'GetAddressSilenceAt115200' '115200 GetAddress silence is not ChipFastUartUnread'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'GetAddressSilenceAt115200' 'Track-1 maps 115200 GetAddress silence into dual-baud'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'FastUart28At115200' 'Track-1 probes FastUART 0x28 at 115200 after GetAddress silence'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'format_s19k_aml_factory_sd_plan' 'S19k AML factory SD planner exists'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_aml_factory_sd_as_nandrecovery_env' 'AML factory SD is not nandrecovery_env'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'parse_s19k_aml_upgrade_header' 'S19k AmlImagePack v2 header parser'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_aml_img_as_updateporc' 'S19k factory img is not updateporc'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'parse_s19k_aml_multi_dtb' 'S19k factory meson1 AML_ multi-DTB parser'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_uboot_gpioao3_as_gpio437' 'USB UBOOT GPIOAO_3 is not gpio437'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'parse_s19k_aml_dtb_gpio_controllers' 'S19k meson1 gpio-controller walker'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_dt_math_as_gpio437' 'DT cell math is not linux gpio437'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'parse_s19k_aml_verify_item' 'AmlImagePack VERIFY sha1sum parser'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_aml_dtb_alias_meson1_enc' 'item4 _aml_dtb aliases meson1_ENC'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'classify_s19k_aml_verify_hex' 'factory VERIFY sha1 classifier'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_aml_verify_pair' 'VERIFY sub and sha1 must agree'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_packed_gpio_word' 'USB UBOOT packed gpio word offset'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_bootloader_as_uboot_enc' 'item11 bootloader is not item7 UBOOT.ENC'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_uboot_packed_gpioao3_seq' 'USB/SDC share packed GPIOAO_3 sequence'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_sdc_usb_uboot_suffix' 'SDC UBOOT is USB plus 49664 BL2 prefix'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_i2c_mw_1f_as_gpio437' 'i2c mw 1f is PCA9557 ledring not gpio437'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'parse_s19k_bl2_storage_classes' 'BL2 storage class table parser'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_packed_setenv' 'USB UBOOT packed setenv boo pin'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_packed_logo' 'USB UBOOT packed logo=${display_layer}'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_bl2_rpmb_emmc_errors' 'BL2 eMMC RPMB error strings'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_packed_hardware' 'USB UBOOT packed hardware is Android cmdline'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_iogic_as_amlogic' 'packed Iogic is not contiguous amlogic'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_atf_plat_amlogic' 'USB UBOOT BL31 plat/amlogic ATF paths'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_bl2_scan_bbt_ecc' 'BL2 scan bbt ecc error is not live NAND ECC'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_packed_uild_expect' 'USB UBOOT packed uild.expect is Android remnant'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_packed_acmdlin' 'USB UBOOT packed acmdlin is Android cmdline remnant'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_bl2_ddr_saved_page' 'BL2 ddr saved page is DDR training not NAND'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_bl2_lock_check' 'BL2 lock check is not gpio437 SafeOff'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_bl2_cpu_clk_24mhz' 'BL2 CPU clk 24MHz is not hash clock or UART baud'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_bl2_pll_as_asic_pll' 'BL2 SYS/FIX PLL are not BM1366 ASIC PLL'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_bl2_saradc_sample_error' 'BL2 Get saradc sample Error is not miner ADC'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_bl2_saradc_as_miner_voltage_adc' 'BL2 SARADC is not INA260/dsPIC voltage'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_bl2_board_id' 'BL2 Board ID is not .78 chassis or BHB56'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_saradc_channel2' 'USB SARADC channel2 is not BL2 sample-error'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'parse_s19k_bl2_ddr_types' 'BL2 DDR3/DDR4/LPDDR table is not NAND geometry'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_bl2_ddr_table' 'BL2 rank/DDR table admit'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_bl2_ddr_as_78_nand' 'BL2 DRAM table is not .78 nandnormal'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_bl2_ddr_ssc_pll' 'BL2 DDR SSC/PLL is not BM1366 hash PLL'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_uart_rx.rs' 'admit_s19k_no_held_bm1366_job_nonce' 'no held S19k BM1366 job-nonce vector'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_uart_rx.rs' 'refuse_held_s21_job_as_s19k_bm1366_nonce' 'S21 BM1368 frame is not S19k nonce'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_uart_rx.rs' 'admit_constructed_fill_nonce_correlates' 'constructed fill nonce correlates with 21 36'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_uart_rx.rs' 'refuse_constructed_fill_body7_as_job_nonce' 'HAL body-7 cut of fill nonce is not JobNonce'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_bl2_bist_test' 'BL2 bist_test is DRAM BIST not NAND BIST'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_bl2_dram_chl_mhz' 'BL2 chl: MHz is DRAM channel not hash-chain'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'refuse_constructed_fill_hal_body7_wire_as_share' 'share-hunter refuses constructed fill HAL body-7 wire cut'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_bl2_ddr_reset' 'BL2 Reset after DDR init failed is not gpio437'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_production_hunt_uses_body9' 'production BM1366 hunt uses resp[..9] not HAL body 7'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_bl2_sdio_customer_id' 'BL2 sdio/Customer ID is not miner identity'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_production_sets_body_before_first_read' 'Track-1 set_response_len before first GetAddress'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'refuse_hal_default_body7_as_bm1366_first_read' 'HAL DEFAULT 7 is not BM1366 first-read'
require_pattern 'dcentrald/dcentrald-hal/src/serial_chain.rs' 'fn open_passthrough_bm1366' 'HAL BM1366 passthrough open sets body 9'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'open_passthrough_bm1366(i as u8, path)' 'Track-1 uses BM1366 fail-closed passthrough open'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_bl2_memdump_bl2z' 'BL2 @MEMDUMP/jump to BL2z is not nandrecovery'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_bl2_fip_usb_mode' 'BL2 USB mode/FIP CHK is not AML NAND install'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_bl2_fip_tmp_bl31' 'BL2 FIP TMP HDR/BL31 is not AML NAND install'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_bl2_err_sha_table' 'BL2 Err:sha* is FIP digest error not VERIFY sha1'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_bl2_never_be_here_skip_usb' 'BL2 NEVER BE HERE/Skip usb is USB-boot not AML NAND install'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_bl2_reg_dump' 'BL2 -W[0x]/DATA/ADDR dump is not hash UART or nandrecovery'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_txfifo_speed_enum' 'USB TxFIFO FULL/SPEED ENUM is USB controller not hash FIFO/enum'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_uart_rx.rs' 'admit_s19k_hal_extracts_bm1366_body9' 'HAL try_extract_frame at BM1366 body 9'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'refuse_constructed_fill_hal_body7_extract_as_share' 'HAL body-7 extract of fill nonce is not a share'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_cortex_exception' 'USB Cortex-M EXCEPTION dump is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'refuse_s19k_body7_two_frame_extract_as_shares' 'body-7 two-frame extract is not dual shares'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_ec_task_table' 'USB EC Task Ready/__wait_evt is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_uart_rx.rs' 'admit_s19k_body7_residue_then_body9_recovers_next' 'body-7 residue then body-9 recovers next frame'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_ec_mutex_svc' 'USB EC mutex_lock/svc_handler is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_uart_rx.rs' 'admit_s19k_hal_midstream_body7_then_body9' 'HAL RxBuffer mid-stream body-7 then body-9 recovery'
require_pattern 'dcentrald/dcentrald-hal/src/serial_chain.rs' 'rx_buffer_body7_then_body9_recovers_next' 'HAL RxBuffer body-7 then body-9 recovers next frame'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_ec_task_set_stack' 'USB EC task_set_event/Stack overflow is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_ec_idle' 'USB EC tasks_ready/<< idle >> is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_production_requires_body9_before_first_read' 'Track-1 require_bm1366_response_body before first read'
require_pattern 'dcentrald/dcentrald-hal/src/serial_chain.rs' 'fn require_bm1366_response_body' 'HAL require_bm1366_response_body fail-closes DEFAULT 7'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'require_bm1366_response_body' 'production Track-1 requires body 9 before drain/GetAddress'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_ec_hooks_timer' 'USB EC HOOKS/TIMERTASK is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_init_bm1366_requires_body9_before_flush' 'init_bm1366_chain require body 9 before flush'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'set_response_len(BM1366_UART_RESP_BODY_LEN)' 'init_bm1366_chain sets BM1366 body 9 not generic alias'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_ec_mailbox' 'USB EC LOWMAILBOX/HIGHMAILBOX is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_nopic_observation_refuses_bm1366' 'NoPic observation refuses BM1366 identity'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_ec_sec_userlow' 'USB EC SECMAILBOX/USERLOWTASK is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_am2_hybrid_reset_is_not_bm1366' 'AM2 hybrid reset is Zynq BM1362 not S19k first-read'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_am2_reset_baseline_is_not_bm1366' 'AM2 reset-baseline is BM1362 not S19k first-read'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_am3_bb_open_is_not_bm1366' 'am3-bb open is BeagleBone not S19k first-read'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_ec_user_high_secure' 'USB EC USERHIGHTASK/USERSECURETASK is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_init_bm1398_is_not_bm1366' 'init_bm1398_chain is BM1398 not S19k first-read'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_ec_timer_efuse' 'USB EC TIMERFORADCTASK/empty-chip efuse is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_empty_efuse_as_otp_decrypt' 'USB empty-chip efuse is not ENC-item decrypt'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_es_chip_dvfs' 'USB This is ES chip / is_set_dvfs_vol_first is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_am2_companion_open_is_not_bm1366' 'AM2 companion UART is Zynq BM1362 not S19k first-read'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_am2_phase3b1_relay_is_not_bm1366' 'AM2 Phase 3b1-relay is BM1362 not S19k first-read'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_dvfs_freq' 'USB get_init_dvfs/get_dvfs/freq_to_idx is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_freq_to_idx_as_hash_pll' 'USB freq_to_idx is not hash PLL'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_am2_probe_uart_is_not_bm1366' 'AM2 probe_uart_for_chips is BM1362 not S19k first-read'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_dvfs_sys_pll' 'USB set_dvfs_info/use_sys_pll is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_use_sys_pll_as_hash_pll' 'USB use_sys_pll is not hash PLL'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_am2_init_asic_open_is_not_bm1366' 'AM2 init_asic_chain primary open is BM1362 not S19k first-read'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_fix_clk_pll_lock' 'USB use_fix_clk / sys pll lock done is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_sys_pll_lock_as_hash_pll' 'USB sys pll lock done is not hash PLL'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_am2_passthrough0_is_not_bm1366' 'AM2 hybrid open_passthrough(0) is BM1362 not S19k first-read'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_dvfs_thermal' 'USB set_dvfs/cpu clk suspend/aml_thermal is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_aml_thermal_as_hash_thermal' 'USB aml_thermal is not hashboard thermal'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_cpu_clk_suspend_as_hash_pll' 'USB cpu clk suspend is not hash PLL'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_bl30_jtag_efuse' 'USB cpu clk resume / bl30:thermal / JTAG / efuse is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_bl30_thermal_as_hash_thermal' 'USB bl30:thermal is not hashboard thermal'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_efuse_pw_en_as_otp_decrypt' 'USB efuse_pw_en is not ENC decrypt'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_dvfstbl_jtag_trim' 'USB high_task_init_dvfstbl / disable M3 JTAG / efuse-disabled / bl30 thermal trim is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_efuse_bits_disabled_as_otp_decrypt' 'USB WARNING efuse bits is not ENC decrypt'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_bl30_thermal_trim_as_hash_thermal' 'USB bl30:thermal disable trim is not hashboard thermal'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_a53_gxl_thermal' 'USB disable A53 JTAG / Enable M3 JTAG / bl30:thermal_calib / GXL ES thermal is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_bl30_thermal_calib_as_hash_thermal' 'USB bl30:thermal_calib is not hashboard thermal'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_gxl_es_thermal_as_miner_identity' 'USB GXL ES thermal is not S19k identity'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_a53_ao_untrimmed' 'USB Enable A53 JTAG / to AO / bl30 ERROR thermal_calib / untrimmed thermal is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_bl30_thermal_calib_err_as_hash_thermal' 'USB bl30:ERROR thermal_calib is not hashboard thermal'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_bl30_untrimmed_as_hash_thermal' 'USB untrimmed thermal is not hashboard thermal'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_ee_pw_axg' 'USB to EE / Incorrect password / thermal_calibration_data / axg ver is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_incorrect_password_as_miner_auth' 'USB Incorrect password is not miner auth'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_bl30_axg_ver_as_miner_identity' 'USB bl30:axg ver is not S19k identity'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_invalid_try_thermal0' 'USB Invalid input / Please try again / axg thermal0 / thermal init err is not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_invalid_input_as_miner_auth' 'USB Invalid input is not miner auth'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_bl30_thermal_init_err_as_hash_thermal' 'USB bl30:thermal init err is not hashboard thermal'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_init_bm1368_is_not_bm1366' 'init_bm1368_chain is not S19k Track-1 first-read'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_init_bm1370_is_not_bm1366' 'init_bm1370_chain is not S19k Track-1 first-read'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_init_bm1362_is_not_bm1366' 'init_bm1362_chain is not S19k Track-1 first-read'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'S19K_FACTORY_BOOT_RAMDISK_SIZE' 'factory item 9 ramdisk is 0x686800 not 20231108 0x66A000'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_20231108_ramdisk_as_factory_boot' '20231108 ramdisk is not factory item 9'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_factory_android_second_layout' 'factory ANDROID second starts at 12875776'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_78_mtd3_is_ubi_stock_config' 'mtd3_stock_config.bin is UBI not updateporc'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_mtd3_as_updateporc_source' 'mtd3 has 0 updateporc bytes'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_mtd3_as_fileparser_source' 'mtd3 has 0 FileParser bytes'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_mtd3_as_uart_trans_source' 'mtd3 has 0 uart_trans bytes'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_20231108_miner_pem' '20231108 miner.pem is 451 B BEGIN PUBLIC KEY'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_held_root_does_not_verify_pem_sig' 'held bitmain.pub does not verify 20231108 miner.pem.sig'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_unverified_pem_sig_as_nand_grant' 'unverified pem.sig is not a nandwrite grant'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'HELD_FILEPARSER_SHA256_INIT' 'FileParser imports SHA256_Init'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 's19k_fill_lookup_tx' 'fill hunt identity-first then job|small_core overlay'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'S19K_CONSTRUCTED_FILL_WORK10_CORE2_BODY' 'constructed fill work 0x10 | core 2 fixture'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'refuse_s19k_fill_overlay_f8_as_fun_0091c0a0' 'fill overlay id&0xF8 is not FUN_0091c0a0'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 's19k_fill_lookup_tx_esp_overlay_experimental' 'ESP overlay fill lookup is experimental not production'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_init_bm1366_omits_esp_a4' 'init_bm1366_chain omits ESP 0xA4 VersionMask'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_production_bm1366_queue_covers_fill_slots' 'BM1366 UART hold queue is 2-4 not 256 drop-oldest'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'S19K_BM1366_HOLD_QUEUE_DEPTH' 'BM1366 UART hold is 4; outstanding stays 256'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'BM1366_SERIAL_WORK_QUEUE_DEPTH' 'S19k BM1366 work queue is hold-4 not fill-256'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'S19k Track-1 hold' 'BM1366 holds take_dispatch when UART queue is full'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_track1_thermal_handoff_unowned' 'Track-1 thermal is HandoffUnowned not Ready'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'ThermalSafetyState::HandoffUnowned' 'Track-1 sets HandoffUnowned'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'let tx_before_rx = is_bm1362 || is_bm1366' 'BM1366 TX-before-RX'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'DCENT_S19K_NATIVE_COLD_START' 'native S19k diagnostic request flag remains available'
require_pattern 'dcentrald/dcentrald-common/src/s19k_braiins_chain_discover.rs' 's19k_multi_send_work_tx_required' 'Multi send_work TX is required only on ttyS1+ttyS2'
require_pattern 'dcentrald/dcentrald-common/src/s19k_braiins_chain_discover.rs' 'refuse_s3_rx_as_fill_hunt' 'ttyS3 RX is observe-only not fill-hunt'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'admit_s19k_fill_hunt_on_tx_path' 'Track-1 fill hunt requires evidence-derived active TX path (ttyS3 only after promotion)'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 's19k_multi_send_work_tx_required' 'Track-1 Multi send_work skips discover/optional UARTs'
require_pattern 'dcentrald/dcentrald-common/src/s19k_passthrough_preflight.rs' 'refuse_chip_heard_at_115200_as_restored_3m_work_tx' 'ChipHeardAt115200 is not restored-3M work TX'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'admit_s19k_dual_baud_work_tx_for_path' 'dual-baud work-TX admit skips discover ttyS3'
require_pattern 'dcentrald/dcentrald-common/src/s19k_passthrough_preflight.rs' 'refuse_silence_at_both_bauds_as_chip_proof_3m_tx' 'SilenceAtBothBauds is handoff probe not chip-proof 3M TX'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'HandoffProbe is not ChipProofAt3M' 'Track-1 logs SilenceAtBothBauds as handoff probe'
require_pattern 'dcentrald/dcentrald-common/src/s19k_passthrough_preflight.rs' 'refuse_retry_not_run_or_inconclusive_as_chip_proof_3m_tx' 'RetryNotRun/Inconclusive is not chip-proof 3M TX'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'InconclusiveProbe is not ChipProofAt3M' 'Track-1 logs RetryNotRun as inconclusive probe'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_init_seq.rs' 'admit_s19k_stock_fastuart_28_write_as_leave_115200' 'only exact stock BM1366 0x3011 is admitted as the 115200-to-B3000000 transition'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_init_seq.rs' 'ESP_BM1366_MISCCTRL_DEFAULT_BAUD_VALUE' 'ESP default ~115200 is MiscCtrl 0x18 not FastUART 0x28'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'S19K_78_MTD2_ANDROID2_RAMDISK_SIZE' 'mtd2 second ANDROID ramdisk is 0x662000'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_mtd2_as_fileparser_source' 'mtd2 has 0 FileParser bytes'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'Mtd2Android1' 'mtd2 A1 AMLSECU 20211119 is not factory/20231108'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_78_mtd2_kernels_identical' 'mtd2 A1/A2 share one kernel'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_amlsecu_kind_matches_ramdisk' 'AMLSECU kind 2 ramdisk 0 / kind 3 ramdisk present'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_factory_recovery_as_mtd2_a1' 'factory recovery is not mtd2 A1'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_factory_recovery_item_as_78_bos_mtd3' 'factory recovery does not fit .78 BOS mtd3'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_factory_recovery_overflows_78_mtd3' 'factory recovery 6064640 overflows BOS mtd3 5242880'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_factory_pack_as_s30v_restock' 'factory SD is not a full s30v restock'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'S19K_FACTORY_RESTOCK_MISSING' 'factory pack missing config/misc/nvdata/tpl'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_factory_boot_item_as_78_mtd2_nandwrite' 'factory boot size-fit is not BOS mtd2 nandwrite'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_factory_boot_recovery_kernels_identical' 'factory boot/recovery share one kernel'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_factory_recovery_second_as_meson1_enc' 'factory recovery second is not meson1_ENC'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_78_mtd3_ubi_volume_name' 'mtd3 UBI volume is config_data'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_upgrade_cgi_as_updateporc_script' 'upgrade.cgi is not updateporc.sh'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_78_mtd3_vtbl_copies_identical' 'mtd3 UBI vtbl PEB3 and PEB4 copies are identical'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_upgrade_clear_as_updateporc_script' 'upgrade_clear.cgi is not updateporc.sh'
require_pattern 'dcentrald/dcentrald-common/src/s19k_nand_env.rs' 'admit_s19k_78_recover_erases_nvdata_after_recover_env' 'recover_to_stock recover_env before erase.part nvdata'
require_pattern 'dcentrald/dcentrald-common/src/s19k_nand_env.rs' 'refuse_s19k_erase_nvdata_before_recover_env' 'erase.part nvdata is not a BOS mtd name'
require_pattern 'dcentrald/dcentrald-common/src/s19k_nand_env.rs' 'admit_s19k_78_recover_env_default_before_import' 'recover_env default -a before import'
require_pattern 'dcentrald/dcentrald-common/src/s19k_nand_env.rs' 'refuse_s19k_env_default_a_as_recover_env' 'env default -a is not recover_env'
require_pattern 'dcentrald/dcentrald-common/src/s19k_nand_env.rs' 'admit_s19k_78_recover_env_import_flags' 'env import -d delete / -c CRC'
require_pattern 'dcentrald/dcentrald-common/src/s19k_nand_env.rs' 'refuse_s19k_dry_run_as_env_import_dash_d' 'DCENT dry-run is not U-Boot -d'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_gpio437.rs' 'admit_s19k_78_gpio_timeline_hb_reset_ganged_after_psu' 'HB reset 454/455/456 ganged after PSU'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_gpio437.rs' 'refuse_s19k_78_first_psu_engage_as_hb_reset_released' 'first GPIO437=0 is not reset released'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_uart_rx.rs' 'refuse_s19k_rxbuf_leftover_aa_plus_tx55_as_jobnonce' 'leftover AA + TX 55 AA is not JobNonce'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'flush leftover RX after empty GetAddress' 'Track-1 flush leftover after empty GetAddress'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'flush leftover RX after empty FastUART' 'Track-1 flush leftover after empty FastUART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_s97_nanddump_02_before_write_03' 'S97 nanddump-compare 0x02 before write 0x03'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_s99_header_names_recover_to_stock' 'S99 leftover 0x02 is recover_to_stock not mtd2'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_s99_wal_block_leaves_flag_02' 'S99 WAL-block leaves flag 0x02 recover_to_stock'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_s99_identity_wal_does_not_block_03' 'S19k WAL failure must not block 0x03'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s21_s97_identical_to_78' 'held S21 S97 matches .78 S97'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s21_held_s97_as_firstboot_bootcmd' 'S21 S97 is not firstboot bootcmd'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_uart_rx.rs' 'admit_s21_held_uart_chip_id_is_1368_not_1366' 'S21 UART capture is 0x1368 not 0x1366'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_uart_rx.rs' 'refuse_s21_held_uart_capture_as_s19k_jobnonce' 'S21 UART capture is not S19k JobNonce'
require_pattern 'br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S99upgrade' 's19k_firstboot_is_wal_companion_only' 'S19k firstboot WAL is companion-only'
require_pattern 'br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S99upgrade' 'next reboot is recover_to_stock' 'S99 WAL-block names recover_to_stock'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'flush leftover RX after empty 115200-retry GetAddress' 'Track-1 flush leftover after empty 115200-retry'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'flush leftover RX after empty FastUART-at-115200' 'Track-1 flush leftover after empty FastUART-at-115200'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_aml_upgrade_usb_ddr_item' 'S19k USB/DDR item 0 admit'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_aml_upgrade_usb_uboot_enc_item' 'S19k USB/UBOOT_ENC item 3 admit'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_encrypt_reg_as_otp_decrypt_key' 'Encrypt_reg 0xff800228 is not ENC decrypt key'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_ini_erase_bootloader_as_execute' 'embedded ini erase_bootloader is not --execute'
require_pattern 'dcentrald/dcentrald-hal/src/serial_chain.rs' 'rx_buffer_extracts_complete_bm1366_frame' 'HAL RxBuffer extracts 11-byte BM1366 wire at body 9'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'refuse_s19k_generic_passthrough0_as_track1' 'generic open_passthrough(0) is not S19k Track-1'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_share.rs' 'admit_s19k_production_refuses_generic_passthrough_for_bm1366' 'generic passthrough arm refuses BM1366 open_passthrough(0)'
require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'not generic open_passthrough(0)' 'S19k BM1366 cannot fall into generic passthrough(0)'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_gpioao3_offset' 'USB UBOOT GPIOAO_3 offset pin'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'admit_s19k_usb_uboot_scpi_ddr_gcm' 'USB post-45000 is BL30 SCPI/DDR/GCM not hash UART'
require_pattern 'dcentrald/dcentrald-common/src/s19k_aml_dtb.rs' 'refuse_s19k_usb_gcm_tag_as_android_decrypt' 'USB GCM Tag mismatch is not ANDROID decrypt'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_aml_upgrade_usb_uboot_item' 'S19k USB UBOOT item 2 admit'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_aml_upgrade_meson1_item' 'S19k meson1 gzip item 14 admit'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'parse_s19k_android_amlsecu_stamp_raw' 'S19k AMLSECU stamp raw parser'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_factory_android_recovery_header' 'S19k factory recovery ramdisk_size=0'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'admit_s19k_factory_android_ramdisk_not_gzip' 'S19k factory boot ramdisk is not gzip'
require_pattern 'dcentrald/dcentrald-common/src/s19k_am3_install.rs' 'refuse_s19k_factory_android_as_s30v_full_slot' 'factory ANDROID item is not full s30v slot'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_uart_rx.rs' 'FastUart28HeardAt115200' '115200 FastUART 0x28 reply is not ChipHeardAt115200'
require_pattern 'dcentrald/dcentrald-common/src/s19k_bm1366_wire_b.rs' 'pack_read_register_bcast_uart' 'broadcast read_register packer exists'
require_pattern 'scripts/recover_amlogic_to_stock.sh' '--dry-run' 'amlogic recover-to-stock accepts --dry-run'
require_pattern 'scripts/recover_amlogic_to_stock.sh' 'RECOVER_WALK.txt' 'amlogic recover-to-stock writes RECOVER_WALK'
require_pattern 'scripts/recover_amlogic_to_stock.sh' 's19k_nand_env_crc.py' 'amlogic recover-to-stock CRC-admits nandrecovery_env.bin'
require_pattern 'scripts/recover_amlogic_to_stock.sh' 'nand_env.bak is not recover_env' 'amlogic recover-to-stock refuses nand_env.bak as recover_env'
require_pattern 'scripts/recover_amlogic_to_stock.sh' 'CLEAR_FOR_FLASH=false — refusing gpio437 SafeOff/flash_erase/nandwrite' 'amlogic recover-to-stock execute refuses NAND while FLASH-false'
require_pattern 'scripts/recover_amlogic_to_stock.sh' 'missing live canonical platform/board_target pair' 'amlogic recover-to-stock execute refuses a missing canonical live identity pair'
require_pattern 'scripts/recover_amlogic_to_stock.sh' 'missing live /proc/mtd; refuse geometry-blind recover-to-stock' 'amlogic recover-to-stock execute refuses missing /proc/mtd'
reject_pattern 'scripts/recover_amlogic_to_stock.sh' 'fw_setenv firstboot 1' 'amlogic recover-to-stock does not execute fw_setenv firstboot 1'
require_pattern 'scripts/install_amlogic_persistent.sh' 'schema=dcentos.amlogic-recover-to-stock/v1' 'amlogic persistent installer uses rust recover-to-stock schema'
require_pattern 'scripts/install_amlogic_persistent.sh' 'RECOVER_EXECUTE_REFUSE.txt' 'amlogic persistent installer writes recover execute refuse'
require_pattern 'scripts/install_amlogic_persistent.sh' 'recovery-flag 0x01' 'amlogic persistent installer names flag 0x01 as install arm'
require_pattern 'scripts/install_amlogic_persistent.sh' 's19k_nand_env_crc.py' 'amlogic persistent installer CRC-admits nand_env blobs'
require_pattern 'scripts/s19k_nand_env_crc.py' 'S19K_NAND_ENV_CRC_OK' 'nand_env CRC helper prints admit sentinel'
require_pattern 'scripts/restore_amlogic_mtd5_from_backup.sh' 's19k_nand_env_crc.py' 'amlogic restore CRC-admits nandrecovery_env.bin'
require_pattern 'scripts/restore_amlogic_mtd5_from_backup.sh' 'CLEAR_FOR_FLASH=false — refusing gpio437 SafeOff/flash_erase/nandwrite' 'amlogic restore execute refuses NAND while FLASH-false'
require_pattern 'scripts/restore_amlogic_mtd5_from_backup.sh' 'missing live /proc/mtd; refuse geometry-blind restore' 'amlogic restore execute refuses missing /proc/mtd'
require_pattern 'scripts/restore_amlogic_mtd5_from_backup.sh' 'nandrecovery_env.bin CRC32 mismatch' 'amlogic restore refuses sidecar CRC mismatch'
require_pattern 'scripts/restore_amlogic_mtd5_from_backup.sh' 'recover_env_source=nandrecovery_env.bin' 'amlogic restore recover source is nandrecovery sidecar'
reject_pattern 'scripts/restore_amlogic_mtd5_from_backup.sh' 'recover_env_source=nand_env.bak' 'amlogic restore does not import nand_env.bak'
require_pattern 'scripts/restore_amlogic_mtd5_from_backup.sh' 'dcent_am3_extract_nandrecovery_env' 'amlogic restore slices nandrecovery_env from mtd5'
require_pattern 'scripts/restore_amlogic_mtd5_from_backup.sh' 'nandrecovery_env.bin does not match mtd5 slice' 'amlogic restore refuses bak-copied sidecar'
require_pattern 'scripts/restore_amlogic_mtd5_from_backup.sh' 'nandrecovery_env_matches_mtd5_slice=true' 'amlogic restore emits sidecar-slice match'
require_pattern 'scripts/restore_amlogic_mtd5_from_backup.sh' 'missing nandrecovery_env_sha256' 'amlogic restore refuses missing sidecar SHA'
require_pattern 'scripts/restore_amlogic_mtd5_from_backup.sh' 'nandrecovery_env.bin sha256 drift' 'amlogic restore refuses sidecar SHA drift'
require_pattern 'scripts/restore_amlogic_mtd5_from_backup.sh' 'nandrecovery_env_sha256_ok=true' 'amlogic restore emits sidecar SHA ok'
require_pattern 'scripts/install_amlogic_persistent.sh' 'INSTALL_PAYLOAD_PLAN.txt' 'amlogic persistent installer writes root-window-only payload plan'
require_pattern 'scripts/s19k_write_recovery_flag.sh' 'schema=dcentos.amlogic-install-commit/v1' 'recovery-flag helper emits 0x01 InstallArm rust commit schema'
require_pattern 'scripts/s19k_write_recovery_flag.sh' 'uboot_action=FirstBosThenSetFlag2' 'recovery-flag helper 0x01 names FirstBosThenSetFlag2'
require_pattern 'scripts/s19k_write_recovery_flag.sh' "printf '\\001'" 'recovery-flag helper fixture writes 0x01'
require_pattern 'scripts/s19k_write_recovery_flag.sh' 'recovery flag 0x01 execute is FLASH NOT_YET' 'recovery-flag helper refuses 0x01 NAND execute'
require_pattern 'scripts/s19k_write_recovery_flag.sh' 'rewrite_recovery_flag_fixture()' 'recovery-flag helper shares one fixture rewrite'
require_pattern 'scripts/s19k_write_recovery_flag.sh' 'schema=dcentos.amlogic-successful-flag/v1' 'recovery-flag helper emits 0x03 SuccessfulKeepBos plan'
require_pattern 'scripts/s19k_write_recovery_flag.sh' "printf '\\003'" 'recovery-flag helper fixture writes 0x03'
require_pattern 'scripts/s19k_write_recovery_flag.sh' 'fixture_value=0x03' 'recovery-flag helper tags 0x03 fixture rewrite'
require_pattern 'scripts/s19k_write_recovery_flag.sh' 'SuccessfulKeepBos plan/fixture only' 'recovery-flag helper refuses 0x03 NAND execute'
require_pattern 'scripts/s19k_write_recovery_flag.sh' 'SUCCESSFUL_FLAG_PLAN' 'recovery-flag helper names SUCCESSFUL_FLAG_PLAN'
require_pattern 'scripts/s19k_write_recovery_flag.sh' 'CLEAR_FOR_FLASH=false — refusing gpio437 SafeOff/flash_erase/nandwrite' 'recovery-flag execute refuses NAND while FLASH-false'
require_pattern 'scripts/s19k_write_recovery_flag.sh' 'missing exact live platform:target identity' 'recovery-flag execute refuses missing exact live identity pair'
require_pattern 'scripts/s19k_write_recovery_flag.sh' 'one_byte_execute_retired=true' 'recovery-flag helper retires destructive one-byte live execute'
require_pattern 'scripts/install_amlogic_persistent.sh' 'mining services were not stopped' 'amlogic persistent installer dry-run does not stop mining services'
require_pattern 'scripts/install_amlogic_persistent.sh' 'after confirmation, graceful TERM' 'amlogic persistent installer stops services only after confirmation'
require_pattern 'scripts/install_amlogic_persistent.sh' 'Step 8-9/10: content-bound root fd + flash_erase + nandwrite (${ROOTFS_ERASE_COUNT} erase blocks of ${ROOTFS_ERASESIZE_EXPECTED} bytes)' 'amlogic persistent installer reports content-bound variable-driven flash geometry'
reject_pattern 'scripts/install_amlogic_persistent.sh' 'flash_erase /dev/mtd5 0x05700000 320' 'amlogic persistent installer does not hardcode flash geometry in operator output'
require_pattern 'scripts/install_amlogic_persistent.sh' '. "$SCRIPT_DIR/lib/am3_geometry.sh"' 'amlogic persistent installer sources shared am3 geometry'
require_pattern 'scripts/install_amlogic_persistent.sh' '. "$SCRIPT_DIR/lib/amlogic_identity_guard.sh"' 'amlogic persistent installer sources exact sibling guard'
require_pattern 'scripts/install_amlogic_persistent.sh' 'dcent_amlogic_sibling_rejection "$variant" "$normalized" "$identity_lower"' 'amlogic persistent installer applies exact sibling guard before positive identity matching'
require_pattern 'scripts/install_amlogic_persistent.sh' 'dcent_amlogic_identity_record_admit "$variant" "$identity"' 'amlogic persistent installer requires the tested positive identity-record gate'
require_pattern 'scripts/lib/amlogic_identity_guard.sh' 'exact compatible PCB observation is missing' 'amlogic identity guard fails closed without direct compatible PCB evidence'
require_pattern 'scripts/amlogic_lab_rootfs.sh' '. "$SCRIPT_DIR/lib/am3_geometry.sh"' 'amlogic lab rootfs sources shared am3 geometry'
require_pattern 'scripts/revert_to_stock_am3_aml_s19k.sh' '. "$SCRIPT_DIR/lib/am3_geometry.sh"' 'am3 s19k revert sources shared am3 geometry'
require_pattern 'scripts/revert_to_stock_am3_aml_s21.sh' '. "$SCRIPT_DIR/lib/am3_geometry.sh"' 'am3 s21 revert sources shared am3 geometry'
require_pattern 'scripts/lib/am3_geometry.sh' 'DCENT_AM3_ROOTFS_OFFSET_HEX="${DCENT_AM3_ROOTFS_OFFSET_HEX:-0x05100000}"' 'shared am3 geometry pins rootfs offset'
require_pattern 'scripts/lib/am3_geometry.sh' 'DCENT_AM3_ROOTFS_WINDOW_HEX="${DCENT_AM3_ROOTFS_WINDOW_HEX:-0x02800000}"' 'shared am3 geometry pins rootfs window'
require_pattern 'dcentrald/dcentrald-api/src/routes/restore_to_stock.rs' '.arg(&post_dwell_fp.sha256)' 'restore route passes post-dwell SHA into revert helper'
require_pattern 'br2_external_dcentos/board/zynq/am2-s19jpro/post-build.sh' 'revert_to_stock_s19_am2.sh' 'am2 post-build ships profile revert helper'
require_pattern 'br2_external_dcentos/board/zynq/am2-s19jpro/post-build.sh' 'stock-bitmain-manifest.json' 'am2 post-build ships stock Bitmain manifest'
# R-F1: two copies of the stock-Bitmain manifest exist and serve DIFFERENT
# runtime roles — dcentrald-api/assets/stock-bitmain-manifest.json is BAKED into
# the binary (include_str!, the restore-to-stock fallback used when
# /etc/dcentos/stock-bitmain-manifest.json is missing), while the 13 buildroot
# post-build.sh scripts SHIP
# to the target rootfs (the primary on-disk copy). They MUST stay byte-identical,
# but nothing enforced it ("identical by luck"): editing one (e.g. to populate a
# restore SHA) would silently desync the baked fallback from the shipped copy.
# sign_stock_manifest.sh now emits a no-replace candidate; promotion must copy
# those reviewed bytes into BOTH tracked signature locations. Assert both pairs
# remain byte-identical.
require_identical \
    'dcentrald/dcentrald-api/assets/stock-bitmain-manifest.json' \
    '../../knowledge-base/firmware-archive/stock-bitmain-manifest.json' \
    'baked (assets) and shipped (firmware-archive) stock-bitmain manifests are byte-identical'
require_identical \
    'dcentrald/dcentrald-api/assets/stock-bitmain-manifest.json.sig' \
    '../../knowledge-base/firmware-archive/stock-bitmain-manifest.json.sig' \
    'baked and shipped stock-bitmain manifest signatures are byte-identical'
# R-F6: the legacy SSH flashers write ACTIVE firmware paths (brick risk) and are
# DISABLED with an early error+exit. Pin the disable guard in each so it cannot be
# silently removed, which would re-enable a latent-brick path (e.g. flash_vnish's
# raw_nand+NEEDS_KERNEL branch that leaves a no-UIO stock kernel under the DCENT
# rootfs). Round-2 recon F6.
require_pattern 'scripts/flash_vnish.sh' 'is disabled' 'legacy flash_vnish.sh keeps its active-write disable guard'
require_pattern 'scripts/flash_braiinsos.sh' 'is disabled' 'legacy flash_braiinsos.sh keeps its active-write disable guard'
require_pattern 'scripts/flash_universal.sh' 'flashing is disabled' 'flash_universal.sh keeps its unsafe-flash disable guards'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-build.sh' 'usr/sbin/lib/am3_geometry.sh' 'am3-s19k post-build ships AM3 geometry helper for revert'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s21/post-build.sh' 'usr/sbin/lib/am3_geometry.sh' 'am3-s21 post-build ships AM3 geometry helper for revert'
for revert_script in \
    scripts/revert_to_stock_s17.sh \
    scripts/revert_to_stock_am3_aml_s21.sh
do
    require_pattern "$revert_script" 'EXPECTED_SHA256=' "stock revert helper $(basename "$revert_script") accepts expected SHA"
    require_pattern "$revert_script" 'Firmware SHA-256 verified at extraction time.' "stock revert helper $(basename "$revert_script") re-hashes before extraction"
    require_pattern "$revert_script" 'MAX_EXTRACTED_KB' "stock revert helper $(basename "$revert_script") caps extracted size"
    require_pattern "$revert_script" 'firmware archive contains hard-linked files' "stock revert helper $(basename "$revert_script") rejects hard-linked files"
done
require_pattern 'scripts/revert_to_stock_am3_aml_s19k.sh' 'EXPECTED_SHA256=' 'stock revert helper revert_to_stock_am3_aml_s19k.sh accepts expected SHA'
require_pattern 'scripts/revert_to_stock_am3_aml_s19k.sh' 'Firmware SHA-256 verified on private immutable-for-this-process snapshot.' 'stock revert helper revert_to_stock_am3_aml_s19k.sh re-hashes its private snapshot before streaming'
require_pattern 'scripts/revert_to_stock_am3_aml_s19k.sh' 'MAX_UIMAGE_BYTES' 'stock revert helper revert_to_stock_am3_aml_s19k.sh caps its streamed candidate size'
require_pattern 'scripts/revert_to_stock_am3_aml_s19k.sh' 'firmware archive contains hard-linked files' 'stock revert helper revert_to_stock_am3_aml_s19k.sh rejects hard-linked files before streaming'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'ROOTFS_END_DEC' 'amlogic lab rootfs computes rootfs window end'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'mtd5 geometry OK' 'amlogic lab rootfs validates target mtd5 geometry'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'require_uimage_file' 'amlogic lab rootfs validates uImage payloads before write/restore'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'magic=$magic' 'amlogic lab rootfs reports invalid uImage magic'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'require_recovery_artifact' 'amlogic lab rootfs requires local recovery artifact before write'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'Recovery manifest lacks backup_sha256' 'amlogic lab rootfs verifies recovery manifest before write'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'Recovery backup SHA mismatch' 'amlogic lab rootfs verifies recovery manifest hash before write'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'Backup transfer SHA mismatch' 'amlogic lab rootfs verifies backup transfer'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'remote_backup_sha256' 'amlogic lab rootfs records backup manifest proof'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'Candidate upload SHA mismatch' 'amlogic lab rootfs verifies candidate upload before flash'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'Post-write readback SHA mismatch' 'amlogic lab rootfs verifies written image readback'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'write_readback.uimage' 'amlogic lab rootfs preserves write readback artifact'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'write_manifest.json' 'amlogic lab rootfs writes flash proof manifest'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'readback_manifest.json' 'amlogic lab rootfs writes standalone readback proof manifest'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'Restore upload SHA mismatch' 'amlogic lab rootfs verifies restore upload before flash'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'RESTORE_REMOTE_READBACK_SHA' 'amlogic lab rootfs verifies restore readback on target'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'restore_manifest.json' 'amlogic lab rootfs writes restore proof manifest'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'require_gpio437_safe_off_before_mutation' 'amlogic lab rootfs requires GPIO437 SafeOff before write/restore mutation'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'CLEAR_FOR_FLASH=false - refusing gpio437 SafeOff/flash_erase/nandwrite' 'amlogic lab rootfs refuses NAND while FLASH-false'
require_pattern 'scripts/amlogic_lab_rootfs.sh' '--lab-only is not a FLASH override' 'amlogic lab rootfs lab flags do not override FLASH'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'am3-s19k-active-low' 'amlogic lab rootfs SKU-scopes S19k GPIO437 SafeOff=1'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'GPIO437 PWR_EN SafeOff (polarity=' 'amlogic lab rootfs documents SKU-scoped GPIO437 SafeOff before NAND mutation'
require_pattern 'scripts/amlogic_lab_rootfs.sh' 'refusing NAND mutation' 'amlogic lab rootfs refuses NAND mutation when GPIO437 SafeOff fails'
reject_pattern 'scripts/build_rootfs_s21.sh' 'flash_erase /dev/mtd5' 'legacy S21 rootfs builder does not print raw mtd5 erase commands'
reject_pattern 'scripts/build_rootfs_s21.sh' 'nandwrite -p -s $ROOTFS_OFFSET_HEX /dev/mtd5' 'legacy S21 rootfs builder does not print raw mtd5 write commands'
reject_pattern 'scripts/build_rootfs_s21.sh' '0x5100000' 'legacy S21 rootfs builder does not carry stale am3 rootfs offset'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-build.sh' 'usr/bin/telnet' 'am3 post-build removes telnet client tooling'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-build.sh' 'usr/sbin/telnetd' 'am3 post-build removes telnet daemon'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-image.sh' 'Rootfs audit: witnessed access services present; unsigned S46 and telnet paths absent' 'am3 post-image runs rootfs service-surface audit'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-image.sh' 'DCENT_TOOLBOX_INSTALL_MODE=host_driven_rootfs_window_lab' 'am3-s19k package is host-driven and rootfs-window scoped'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-image.sh' 'DCENT_TARGET_SIDE_SYSUPGRADE=false' 'am3-s19k manifest disables target-side sysupgrade claim'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-image.sh' 'DCENT_PACKAGE_INSTALLABLE=true' 'am3-s19k package is structurally installable by the host-driven path'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-image.sh' 'DCENT_S19K_EXPECTED_RELEASE_KEY_SHA256' 'am3-s19k release key identity is externally pinned'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-image.sh' 's19k_persistent_image_verify.py' 'am3-s19k package runs the dependency-bound image contract verifier'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-image.sh' 'CLEAR_FOR_FLASH=false' 'am3-s19k package retains a disabled NAND writer'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-image.sh' 'dcent_write_sysupgrade_manifest' 'am3-s19k post-image uses shared manifest helper'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-image.sh' 'require_rootfs_path "etc/init.d/S50dropbear"' 'am3 rootfs audit requires Dropbear init'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-image.sh' 'require_rootfs_path "root/web/mcp_server.py"' 'am3 rootfs audit requires MCP server'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-image.sh' 'require_rootfs_path "uninstall.sh"' 'am3 rootfs audit requires uninstall hook'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-image.sh' 'reject_rootfs_pattern' 'am3 rootfs audit rejects forbidden paths'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s21/post-build.sh' 'usr/bin/telnet' 'am3-s21 post-build removes telnet client tooling'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s21/post-build.sh' 'usr/sbin/telnetd' 'am3-s21 post-build removes telnet daemon'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s21/post-image.sh' 'exec sh "$SCRIPT_DIR/../post-image-family.sh" --board-target from-target "$@"' 'am3-s21 delegates to the identity-checking shared post-image builder'
require_pattern 'br2_external_dcentos/board/amlogic/post-image-family.sh' 'Rootfs audit: access services present; telnet paths absent' 'am3-s21 post-image runs rootfs service-surface audit'
require_pattern 'br2_external_dcentos/board/amlogic/post-image-family.sh' 'host_driven_rootfs_window_lab' 'am3-s21 manifest marks host-driven install mode'
require_pattern 'br2_external_dcentos/board/amlogic/post-image-family.sh' 'DCENT_TARGET_SIDE_SYSUPGRADE=false' 'am3-s21 manifest disables target-side sysupgrade claim'
require_pattern 'br2_external_dcentos/board/amlogic/post-image-family.sh' 'dcent_write_sysupgrade_manifest' 'am3-s21 post-image uses shared manifest helper'
require_pattern 'br2_external_dcentos/board/amlogic/post-image-family.sh' 'require_rootfs_path "etc/init.d/S50dropbear"' 'am3-s21 rootfs audit requires Dropbear init'
require_pattern 'br2_external_dcentos/board/amlogic/post-image-family.sh' 'require_rootfs_path "root/web/mcp_server.py"' 'am3-s21 rootfs audit requires MCP server'
require_pattern 'br2_external_dcentos/board/amlogic/post-image-family.sh' 'require_rootfs_path "uninstall.sh"' 'am3-s21 rootfs audit requires uninstall hook'
require_pattern 'br2_external_dcentos/board/amlogic/post-image-family.sh' 'reject_rootfs_pattern' 'am3-s21 rootfs audit rejects forbidden paths'
require_pattern 'scripts/revert_to_stock_am335x_bb.sh' 'AM335x BB NAND revert is disabled' 'am3-bb revert refuses unvalidated NAND path by default'
require_pattern 'scripts/revert_to_stock_am335x_bb.sh' 'DCENT_AM3_BB_PROC_MTD_EVIDENCE' 'am3-bb revert requires live proc-mtd evidence before future override'
require_pattern 'scripts/revert_to_stock_am335x_bb.sh' 'DCENT_AM3_BB_ENABLE_NAND_REVERT is not accepted as a bypass' 'am3-bb revert has no env-only bypass'
require_pattern 'br2_external_dcentos/board/beaglebone/am3-bb/post-build.sh' 'echo "am3-bb" > "${TARGET_DIR}/etc/dcentos/board_family"' 'am3-bb post-build stamps unambiguous board_family'
reject_pattern 'scripts/revert_to_stock_am335x_bb.sh' 'flash_erase' 'am3-bb revert contains no erase path'
reject_pattern 'scripts/revert_to_stock_am335x_bb.sh' 'nandwrite' 'am3-bb revert contains no NAND write path'
reject_pattern 'scripts/revert_to_stock_am335x_bb.sh' 'fw_setenv' 'am3-bb revert contains no env write path'
require_pattern 'br2_external_dcentos/board/beaglebone/am3-bb/post-build.sh' 'management-bringup-sdcard-only' 'am3-bb rootfs marks management bring-up only status'
require_pattern 'br2_external_dcentos/board/beaglebone/am3-bb/post-image.sh' 'NAND install/revert is disabled until dated live /proc/mtd evidence exists.' 'am3-bb post-image documents NAND disabled status'

#
# W2.3 single-I2C-owner lockdown: refuse `I2cBus::open(...)` outside the HAL
# `platform/` modules and inside-HAL legitimate owners (psu/adc/i2c.rs).
#
# Normal out-of-HAL callers MUST go through `I2cServiceHandle`
# (spawn_i2c_service*) or the fixed secondary-bus miner-identity bootstrap
# helper. Arbitrary raw EEPROM access is recovery-feature-only. Recovery tools
# may opt in to `I2cBus::open_for_recovery`; additive Cargo feature unification
# means this source gate remains necessary even when manifests look isolated. See
# `dcentrald/dcentrald-hal/src/i2c.rs::I2cBus::open` for the contract.
#
# Build-log artifacts (build_output.txt, *.log) are excluded so a stale
# warning copy from cargo never trips the gate.
#
i2c_open_check_dirs="
dcentrald/dcentrald
dcentrald/dcentrald-asic
dcentrald/dcentrald-thermal
dcentrald/dcentrald-api
dcentrald/dcentrald-autotuner
dcentrald/dcentrald-diagnostics
"

i2c_open_hits=""
for dir in $i2c_open_check_dirs; do
    if [ ! -d "$dir" ]; then
        continue
    fi
    # Match the normal raw constructor exactly. Recovery and bootstrap APIs
    # have distinct names and are reviewed by separate feature/source gates.
    found=$(grep -rn 'I2cBus::open(' "$dir" --include='*.rs' 2>/dev/null | \
        awk -F: '{
            line=$0
            sub(/^[^:]+:[0-9]+:/, "", line)
            sub(/^[[:space:]]+/, "", line)
            if (line ~ /^\/\//) next
            if (line ~ /^\/\*/) next
            if (line ~ /^\*/) next
            print
        }' || true)
    if [ -n "$found" ]; then
        if [ -z "$i2c_open_hits" ]; then
            i2c_open_hits="$found"
        else
            i2c_open_hits="$i2c_open_hits
$found"
        fi
    fi
done

if [ -n "$i2c_open_hits" ]; then
    fail "single-I2C-owner: I2cBus::open(...) called outside dcentrald-hal/platform"
    printf '%s\n' "$i2c_open_hits" >&2
else
    pass "single-I2C-owner: no out-of-HAL I2cBus::open(...) callers"
fi

reject_pattern 'dcentrald/dcentrald/src/serial_mining.rs' 'libc::ioctl' \
    'single-I2C-owner: serial runtime has no direct ioctl transport'
reject_pattern 'dcentrald/dcentrald/src/serial_mining.rs' '\.open\("/dev/i2c-' \
    'single-I2C-owner: serial runtime has no literal direct /dev/i2c owner'

#
# Cross-process I2C fabric ownership. The process-local HAL registry remains
# responsible for allocation identity and quarantine, while this leaf crate is
# the one protocol shared by the daemon and standalone inspection tooling.
# These pins prevent a future refactor from quietly reverting to pidfile/TOCTOU
# ownership, releasing quarantine at token Drop, or bypassing a refused kernel
# adapter through GPIO bit-bang.
#
fabric_lease='dcentrald/dcentrald-fabric-lease/src/lib.rs'
require_file 'dcentrald/dcentrald-fabric-lease/Cargo.toml'
require_file "$fabric_lease"
require_pattern 'dcentrald/Cargo.toml' '"dcentrald-fabric-lease"' \
    'I2C fabric lease: shared leaf crate remains a workspace/default member'
require_pattern 'dcentrald/dcentrald-hal/Cargo.toml' 'dcentrald-fabric-lease = { path = "../dcentrald-fabric-lease" }' \
    'I2C fabric lease: HAL uses the shared cross-process protocol'
require_pattern 'dcentrald/pic-recovery/Cargo.toml' 'dcentrald-fabric-lease = { path = "../dcentrald-fabric-lease" }' \
    'I2C fabric lease: standalone inspection uses the shared protocol'
require_pattern "$fabric_lease" 'libc::LOCK_EX | libc::LOCK_NB' \
    'I2C fabric lease: ownership acquisition is exclusive and nonblocking'
require_pattern "$fabric_lease" 'libc::O_CLOEXEC | libc::O_NOFOLLOW' \
    'I2C fabric lease: opened paths are close-on-exec and do not follow symlinks'
require_pattern "$fabric_lease" 'stat.st_nlink != 1' \
    'I2C fabric lease: hard-linked lock targets fail closed'
require_pattern "$fabric_lease" 'exec_child_does_not_retain_parent_lease' \
    'I2C fabric lease: an actual exec child does not retain parent ownership'
require_pattern "$fabric_lease" 'copied_lease_state_rejects_a_different_process_identity' \
    'I2C fabric lease: copied fork-only state rejects a different process identity'
require_pattern "$fabric_lease" 'subprocess_contention_and_sigkill_release_are_kernel_proven' \
    'I2C fabric lease: subprocess exclusion and crash release execute in host tests'
require_pattern "$fabric_lease" 'pub mod topology' \
    'I2C fabric lease: topology-defined IDs have one canonical ABI ledger'
require_pattern "$fabric_lease" 'NAMED_PHYSICAL_I2C_FABRICS' \
    'I2C fabric lease: named topology IDs expose a collision-test registry'
reject_pattern "$fabric_lease" 'pub const fn topology_defined' \
    'I2C fabric lease: external crates cannot mint or relabel topology IDs'

fabric_lease_production=$(sed '/^#\[cfg.*test/,$d' "$fabric_lease")
if printf '%s\n' "$fabric_lease_production" | grep -Eq \
    'LOCK_UN|libc::unlink|std::fs::remove_file|std::fs::rename'; then
    fail 'I2C fabric lease: production code contains explicit unlock/unlink/rename'
else
    pass 'I2C fabric lease: production release is close-only and never replaces the stable inode'
fi

require_pattern 'dcentrald/dcentrald-hal/src/lib.rs' 'I2cFabricUnavailable' \
    'I2C fabric lease: ownership refusal has a typed non-transport HAL error'
require_pattern 'dcentrald/dcentrald-hal/src/i2c.rs' '_os_lease: Option<OsI2cFabricLease>' \
    'I2C fabric lease: registry entries retain OS ownership through quarantine'
require_pattern 'dcentrald/dcentrald-hal/src/i2c.rs' 'I2cServiceRegistryState::PreparingMutated' \
    'I2C fabric lease: preparation mutation has an explicit quarantine state'
require_pattern 'dcentrald/dcentrald-hal/src/i2c.rs' 'every_raw_wire_entry_revalidates_process_ownership' \
    'I2C fabric lease: raw kernel/devmem entry points pin fork-process validation'
require_pattern 'dcentrald/dcentrald-hal/src/i2c.rs' 'inherited_raw_handle_is_refused_before_simulated_wire_io' \
    'I2C fabric lease: inherited raw state is refused before executable wire behavior'
require_pattern 'dcentrald/dcentrald-hal/src/psu_gpio_i2c.rs' '_fabric_lease: I2cRawFabricLease' \
    'I2C fabric lease: GPIO bit-bang retains the canonical fabric reservation'
require_pattern 'dcentrald/dcentrald-hal/src/psu_gpio_i2c.rs' 'AM2_PSU_GPIO_I2C_FABRIC' \
    'I2C fabric lease: dedicated AM2 PSU wires use their named topology identity'
require_pattern 'dcentrald/dcentrald-hal/src/psu_gpio_i2c.rs' 'pub fn new_am2()' \
    'I2C fabric lease: fixed AM2 GPIO pins use a topology-specific constructor'
reject_pattern 'dcentrald/dcentrald-hal/src/psu_gpio_i2c.rs' 'pub fn new(' \
    'I2C fabric lease: arbitrary pins cannot be mislabeled as the AM2 PSU fabric'
reject_pattern 'dcentrald/dcentrald-hal/src/psu_gpio_i2c.rs' 'new_on_fabric' \
    'I2C fabric lease: fixed GPIO wires cannot be relabeled by a caller-selected bus'
require_pattern 'dcentrald/dcentrald-hal/src/i2c.rs' 'dedicated_am2_psu_fabric_coexists_with_bus_zero_but_self_conflicts' \
    'I2C fabric lease: dedicated PSU and adapter-zero coexistence/exclusion is pinned'
require_pattern 'dcentrald/dcentrald-hal/src/psu_gpio_i2c.rs' 'every_public_gpio_wire_entry_revalidates_process_ownership' \
    'I2C fabric lease: every GPIO/MMIO public wire entry pins fork validation'
gpio_process_checks=$(awk '/^#\[cfg\(test\)\]/{exit} {print}' \
    dcentrald/dcentrald-hal/src/psu_gpio_i2c.rs \
    | grep -c 'self\._fabric_lease\.validate_current_process()?;' || true)
if [ "$gpio_process_checks" -eq 6 ]; then
    pass 'I2C fabric lease: all six GPIO/MMIO wire entries validate process ownership'
else
    fail "I2C fabric lease: expected six GPIO/MMIO process guards, found $gpio_process_checks"
fi
require_pattern 'dcentrald/dcentrald-hal/src/psu.rs' 'kernel_i2c_absence_allows_gpio_fallback' \
    'I2C fabric lease: PSU GPIO fallback is limited to proven adapter absence'
require_pattern 'dcentrald/dcentrald-hal/src/psu.rs' 'Err(error @ HalError::I2cFabricUnavailable { .. }) => return Err(error)' \
    'I2C fabric lease: ownership refusal cannot fall through mmap-to-sysfs fallback'

require_pattern 'dcentrald/dcentrald-hal/src/i2c.rs' \
    'spawn_i2c_service_no_register_touch_with_denylist_and_reserved_preparation' \
    'I2C fabric lease: platform adapter preparation has a reserve-first factory'
require_pattern 'dcentrald/dcentrald-hal/src/i2c.rs' \
    'reserved_preparation_marks_mutated_before_callback_and_quarantines_error' \
    'I2C fabric lease: preparation callback ordering and failure quarantine execute'
hybrid='dcentrald/dcentrald/src/s19j_hybrid_mining.rs'
hybrid_reserve_line=$(grep -n '^[[:space:]]*spawn_i2c_service_no_register_touch_with_denylist_and_reserved_preparation(' "$hybrid" | head -n 1 | cut -d: -f1 || true)
hybrid_prepare_line=$(grep -n 'ensure_i2c0_kernel_bound().map_err' "$hybrid" | head -n 1 | cut -d: -f1 || true)
if [ -n "$hybrid_reserve_line" ] && [ -n "$hybrid_prepare_line" ] \
    && [ "$hybrid_reserve_line" -lt "$hybrid_prepare_line" ]; then
    pass 'I2C fabric lease: AM2 xiic bind/mknod callback is nested behind reservation'
else
    fail 'I2C fabric lease: AM2 xiic bind/mknod is not visibly behind reservation'
fi

pic_recovery='dcentrald/pic-recovery/src/main.rs'
lease_acquire_line=$(grep -n 'OsI2cFabricLease::acquire' "$pic_recovery" | head -n 1 | cut -d: -f1 || true)
device_open_line=$(grep -n 'let fd = unsafe { libc::open' "$pic_recovery" | head -n 1 | cut -d: -f1 || true)
if [ -n "$lease_acquire_line" ] && [ -n "$device_open_line" ] \
    && [ "$lease_acquire_line" -lt "$device_open_line" ]; then
    pass 'I2C fabric lease: pic-recovery acquires cross-process ownership before device open'
else
    fail 'I2C fabric lease: pic-recovery device open is not visibly preceded by shared ownership'
fi
pic_validate_line=$(grep -n '\.validate_current_process()' "$pic_recovery" | head -n 1 | cut -d: -f1 || true)
pic_ioctl_line=$(grep -n 'libc::ioctl' "$pic_recovery" | head -n 1 | cut -d: -f1 || true)
if [ -n "$pic_validate_line" ] && [ -n "$pic_ioctl_line" ] \
    && [ "$pic_validate_line" -lt "$pic_ioctl_line" ]; then
    pass 'I2C fabric lease: pic-recovery revalidates process identity before ioctl/read'
else
    fail 'I2C fabric lease: pic-recovery wire access lacks a visible process-identity guard'
fi

require_pattern 'scripts/run_all_gates.sh' 'dcentrald-fabric-lease' \
    'I2C fabric lease: comprehensive local gate executes subprocess ownership tests'
require_pattern 'scripts/run_all_gates.sh' 'test -p pic-recovery' \
    'I2C fabric lease: comprehensive local gate explicitly tests diagnostic boundary'
require_pattern 'scripts/run_all_gates.sh' 'test -p s19k-stage1-authorizer' \
    'S19k install: comprehensive local gate explicitly tests stage1 authorizer boundary'
require_pattern '../../.github/workflows/dcentos-offline-gates.yml' 'cargo test --locked -p dcentrald-fabric-lease --lib' \
    'I2C fabric lease: hosted CI executes subprocess ownership tests'
require_pattern '../../.github/workflows/dcentos-offline-gates.yml' 'cargo test -p pic-recovery' \
    'I2C fabric lease: hosted CI explicitly tests diagnostic boundary'
require_pattern '../../.github/workflows/dcentos-offline-gates.yml' 'cargo test --locked -p s19k-stage1-authorizer' \
    'S19k install: hosted CI explicitly tests stage1 authorizer boundary'

#
# W4.7 panic-discipline static gates (DCENT_DevOps + DCENT_QA, 2026-05-07).
#
# Three checks:
#   1. panic = "abort" must remain in [profile.release] (S9 squashfs gate;
#).
#   2. ASIC drivers must not regrow `.swap_bytes()` adjacent to `midstate`
#      tokens in non-comment Rust code (regression-pin for the 2026-03-17
#      first-accepted-shares fix in bm1387.rs:1460-1483; CE-agent analysis
#      that re-suggested this swap was wrong, all shares rejected
#      "Above target").
#   3. dev_deploy.sh must keep `kill -9` of bosminer platform-conditional —
#      Zynq paths must use SIGTERM + 10s wait (see
#      ). Only the amlogic warm-takeover
#      branch may SIGKILL.
#
# Counterpart CI workflow: .github/workflows/lint-gates.yml.
# Grandfather doc:
#

# 1. panic = "abort" presence
panic_abort_check() {
    cargo_toml='dcentrald/Cargo.toml'
    if [ ! -f "$cargo_toml" ]; then
        fail "panic-abort: missing $cargo_toml"
        return
    fi
    block=$(awk '
        /^\[profile\.release\]/ { in_block=1; next }
        /^\[/ && in_block { exit }
        in_block { print }
    ' "$cargo_toml")
    if [ -z "$block" ]; then
        fail "panic-abort: no [profile.release] section in $cargo_toml"
        return
    fi
    if printf '%s\n' "$block" | grep -Eq '^[[:space:]]*panic[[:space:]]*=[[:space:]]*"abort"'; then
        pass "panic-abort: panic = \"abort\" pinned in $cargo_toml [profile.release]"
    else
        fail "panic-abort: panic = \"abort\" missing from [profile.release] in $cargo_toml — see feedback_panic_abort_required_s9.md"
    fi
}
panic_abort_check

# 2. swap_bytes near midstate token ban (Protocol expert).
#    Look only in ASIC driver source files and in the work_dispatcher
#    midstate-encode hot path. The ban is on `.swap_bytes()` appearing on
#    the same line as a `midstate` identifier in actual code (not comments).
#    Existing files contain MANY guard comments saying "NO .swap_bytes()" /
#    "DO NOT ADD .swap_bytes()" — those are documentation, not violations.
#    We strip leading whitespace then skip any line whose first
#    non-whitespace char is `//`. Block comments are rare in this context;
#    we accept a tiny false-negative risk in exchange for simplicity.
#
#    W6.2 (2026-05-07, DCENT_QA + DCENT_Protocol): the scan list was
#    extended to also cover the Stratum V1 submit path
#    (`dcentrald-stratum/src/v1/client.rs`) and the work_dispatcher
#    `submit_share` neighborhood. The original 2026-03-17 bm1387.rs
#    regression was an ASIC-driver bug, but the same byte-order class of
#    mistake on the submit boundary would silently produce "Above target"
#    rejects rather than a hardware-side miscount, so the Protocol
#    expert wants the gate to refuse `.swap_bytes()` adjacent to
#    `midstate` in the submit-path crates too. Counterpart e2e:
#    `dcentrald-api/tests/share_submission_e2e.rs` (mock pool +
#    per-chip-family golden midstates).
#
#    DESK_NOW rank 10 (2026-08-19): also scan bm1396/bm1485/bm1489/bm1491/
#    bm1373 when those driver files exist. Missing files continue (skip).
swap_bytes_midstate_check() {
    targets='
        dcentrald/dcentrald-asic/src/drivers/bm1387.rs
        dcentrald/dcentrald-asic/src/drivers/bm1397.rs
        dcentrald/dcentrald-asic/src/drivers/bm1366.rs
        dcentrald/dcentrald-asic/src/drivers/bm1368.rs
        dcentrald/dcentrald-asic/src/drivers/bm1362.rs
        dcentrald/dcentrald-asic/src/drivers/bm1398.rs
        dcentrald/dcentrald-asic/src/drivers/bm1370.rs
        dcentrald/dcentrald-asic/src/drivers/bm1391.rs
        dcentrald/dcentrald-asic/src/drivers/bm1396.rs
        dcentrald/dcentrald-asic/src/drivers/bm1485.rs
        dcentrald/dcentrald-asic/src/drivers/bm1489.rs
        dcentrald/dcentrald-asic/src/drivers/bm1491.rs
        dcentrald/dcentrald-asic/src/drivers/bm1373.rs
        dcentrald/dcentrald/src/work_dispatcher.rs
        dcentrald/dcentrald/src/chain.rs
        dcentrald/dcentrald-stratum/src/v1/client.rs
    '
    hits=''
    for f in $targets; do
        if [ ! -f "$f" ]; then
            continue
        fi
        # Find lines that mention BOTH `midstate` and `.swap_bytes(`,
        # then drop comment-only lines. The work_dispatcher.rs file
        # has a known-good `swapped_nonce = nonce_result.nonce.swap_bytes()`
        # that has nothing to do with midstate encoding — that line
        # mentions `swapped_nonce` not `midstate`, so the dual-mention
        # filter excludes it correctly.
        # `grep -n` on a single file emits `LINENO:CONTENT` (no filename prefix).
        # Strip the leading `LINENO:` and any whitespace, then drop pure
        # comment lines. Print the original `LINENO:CONTENT` for offender output.
        candidate=$(grep -nE '\.swap_bytes\(' "$f" 2>/dev/null \
            | grep -E 'midstate' \
            | awk '{
                orig = $0
                # Strip leading "LINENO:" prefix added by grep -n.
                sub(/^[0-9]+:/, "", $0)
                # Strip leading whitespace.
                sub(/^[[:space:]]+/, "", $0)
                # Skip comment-only lines.
                if ($0 ~ /^\/\//) next
                if ($0 ~ /^\/\*/) next
                if ($0 ~ /^\*/) next
                print orig
            }' \
            || true)
        if [ -n "$candidate" ]; then
            if [ -z "$hits" ]; then
                hits=$candidate
            else
                hits="$hits
$candidate"
            fi
        fi
    done
    if [ -n "$hits" ]; then
        fail "swap_bytes-midstate: .swap_bytes() found adjacent to midstate token in non-comment code (regression of 2026-03-17 bm1387.rs first-accepted-shares fix)"
        printf '%s\n' "$hits" >&2
    else
        pass "swap_bytes-midstate: no non-comment .swap_bytes() near midstate identifiers in ASIC drivers"
    fi
}
swap_bytes_midstate_check

# DESK_NOW rank 2 (2026-08-19): PIC16 production GET_VERSION / READ_VOLTAGE
# must never use combined I2C_RDWR / write_read. Combined repeated-START
# wedges the PIC16F1704 MSSP parser (brick-class). Grep only those two
# function bodies in dcentrald-hal i2c.rs so EEPROM/PMBus write_read
# callers, test-only `fn write_read(` trait impls in pic16_runtime.rs,
# and I2cSimBackend cannot poison the contract. Comment-only mentions
# are ignored. The gate must fail while the production helpers still
# call write_read, and pass after the sibling rewrite to
# write-then-separate-read.
pic16_i2c_rdwr_ban_check() {
    f='dcentrald/dcentrald-hal/src/i2c.rs'
    if [ ! -f "$f" ]; then
        fail "PIC16 I2C_RDWR ban: missing $f"
        return
    fi

    hits=''
    missing=0
    for fn in pic_read_voltage pic_get_version; do
        body=$(awk -v fn="$fn" '
            BEGIN { in_fn = 0; depth = 0 }
            !in_fn {
                if ($0 ~ ("(^|[[:space:]])fn[[:space:]]+" fn "[[:space:]]*[(]")) {
                    in_fn = 1
                } else {
                    next
                }
            }
            {
                print
                line = $0
                sub(/\/\/.*/, "", line)
                for (i = 1; i <= length(line); i++) {
                    c = substr(line, i, 1)
                    if (c == "{") {
                        depth++
                    } else if (c == "}") {
                        depth--
                        if (depth <= 0) {
                            exit
                        }
                    }
                }
            }
        ' "$f")
        if [ -z "$body" ]; then
            fail "PIC16 I2C_RDWR ban: production fn $fn not found in $f"
            missing=$((missing + 1))
            continue
        fi
        offender=$(printf '%s\n' "$body" | awk '
            {
                orig = $0
                line = $0
                sub(/^[[:space:]]+/, "", line)
                if (line ~ /^\/\//) next
                if (line ~ /^\/\*/) next
                if (line ~ /^\*/) next
                sub(/\/\/.*/, "", line)
                if (line ~ /write_read\(/ || line ~ /write_read_at\(/ || line ~ /I2C_RDWR/) print orig
            }
        ' || true)
        if [ -n "$offender" ]; then
            if [ -z "$hits" ]; then
                hits="$fn:
$offender"
            else
                hits="$hits
$fn:
$offender"
            fi
        fi
    done

    if [ -n "$hits" ]; then
        fail "PIC16 I2C_RDWR ban: production pic_read_voltage/pic_get_version still call write_read/I2C_RDWR (must be write-then-separate-read):
$hits"
    elif [ "$missing" -eq 0 ]; then
        pass "PIC16 I2C_RDWR ban: production pic_read_voltage/pic_get_version do not call write_read/I2C_RDWR"
    fi
}
pic16_i2c_rdwr_ban_check

# DESK_NOW rank 2 (2026-08-19): operator helpers must not PRINT or invoke
# raw `flash_erase /dev/mtd4` or `nandwrite ... /dev/mtd4`. A prior pass
# rewrote apply-instructions to fw_setenv; NEVER/REFUSING warning strings
# that name the banned tokens are allowed so the gate stays green after
# that rewrite. Scope is DCENT_OS_Antminer/scripts/*.py plus the
# switch_firmware.sh twin operators actually run. Test files that assert
# the ban (`reject_pattern ... nandwrite`) and knowledge-base historical
# docs are out of scope. nandsim harnesses that program a simulator are
# not operator helpers.
mtd4_raw_nand_helper_ban_check() {
    bad=''
    scanned=0
    for f in scripts/*.py scripts/switch_firmware.sh scripts/fix_uboot_env.py; do
        [ -f "$f" ] || continue
        base=$(basename "$f")
        case "$base" in
            test_*|*_test.py|*_test.sh) continue ;;
        esac
        scanned=$((scanned + 1))
        offender=$(awk '
            {
                orig = $0
                line = $0
                sub(/^[[:space:]]+/, "", line)
                if (line ~ /^#/) next
                if (line ~ /NEVER|REFUSING|banned:|do not|must not|not-fw-setenv/) next
                is_print = (line ~ /print\(|echo[[:space:]]|printf[[:space:]]|sys\.stdout|os\.system|os\.popen|subprocess\.|check_call|check_output/)
                is_cmd = (line ~ /^(sudo[[:space:]]+)?(flash_erase|nandwrite)[[:space:]]/)
                if (!is_print && !is_cmd) next
                if (line ~ /flash_erase[[:space:]]+\/dev\/mtd4/) print orig
                else if (line ~ /nandwrite[[:space:]].*\/dev\/mtd4/) print orig
            }
        ' "$f" || true)
        if [ -n "$offender" ]; then
            bad="$bad
$f:
$offender"
        fi
    done
    if [ "$scanned" -eq 0 ]; then
        fail "mtd4 raw-NAND helper ban: no operator helper scripts found (path drift?)"
    elif [ -n "$bad" ]; then
        fail "mtd4 raw-NAND helper ban: helper still prints or invokes flash_erase/nandwrite /dev/mtd4:$bad"
    else
        pass "mtd4 raw-NAND helper ban: operator helpers do not print or invoke flash_erase/nandwrite mtd4 ($scanned scripts)"
    fi
}
mtd4_raw_nand_helper_ban_check

# DESK_NOW rank 10 (2026-08-19): S19k refuse_ms8 must run. GAP6 dropped the
# documented pre-existing failure; the offline-gates workflow must not
# resurrect `--skip` on that contract.
reject_pattern '../../.github/workflows/dcentos-offline-gates.yml' \
    '--skip s19k_braiins_job::tests::refuse_ms8_uart_fanout_and_pin_live_delta' \
    'S19k refuse_ms8 is not skipped in the offline-gates workflow'
require_pattern '../../.github/workflows/dcentos-offline-gates.yml' \
    'bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- s19k_' \
    'S19k common contract suite still runs the s19k_ filter'

# 3. dev_deploy.sh: kill -9 bosminer must be platform-conditional.
#    Walk the file looking for any line that calls SIGKILL on bosminer
#    (covers `kill -9 bosminer`, `kill -9 $BOSMINER_PID`, and the for-loop
#    pidof construct on amlogic). Each hit must be inside a context that
#    already gates on PLATFORM_FAMILY = "amlogic" within the surrounding
#    20-line window. The non-amlogic deploy path uses
#    `kill -TERM ...; sleep 10; kill -9 ... 2>/dev/null` which is allowed
#    because the SIGTERM precedes it with a 10-second drain — that is a
#    fallback after graceful shutdown attempt, not an unconditional SIGKILL.
kill9_bosminer_check() {
    f='scripts/dev_deploy.sh'
    if [ ! -f "$f" ]; then
        fail "kill9-bosminer: missing $f"
        return
    fi

    # Find every line that mentions `kill -9` AND `bosminer` (or a bosminer-pid
    # variable). For each hit, check whether the prior 20 lines contain either
    # `PLATFORM_FAMILY = "amlogic"` (amlogic warm-takeover branch) or
    # `kill -TERM` (graceful-shutdown fallback path).
    line_numbers=$(grep -nE 'kill[[:space:]]+-9' "$f" 2>/dev/null \
        | grep -E 'bosminer|BOSMINER' \
        | awk -F: '{ print $1 }' \
        || true)

    bad=''
    for ln in $line_numbers; do
        # Window: 20 lines before this hit.
        start=$((ln - 20))
        if [ "$start" -lt 1 ]; then
            start=1
        fi
        window=$(sed -n "${start},${ln}p" "$f")
        if printf '%s\n' "$window" | grep -qE 'PLATFORM_FAMILY"?[[:space:]]*=[[:space:]]*"amlogic"'; then
            continue
        fi
        if printf '%s\n' "$window" | grep -qE 'kill[[:space:]]+-TERM'; then
            continue
        fi
        # Neither gate found — this is a regression.
        if [ -z "$bad" ]; then
            bad="line $ln: $(sed -n "${ln}p" "$f")"
        else
            bad="$bad
line $ln: $(sed -n "${ln}p" "$f")"
        fi
    done

    if [ -n "$bad" ]; then
        fail "kill9-bosminer: unconditional kill -9 of bosminer in $f (must be amlogic-only or follow kill -TERM + 10s wait — see feedback_xiic_stuck_state_recovery.md)"
        printf '%s\n' "$bad" >&2
    else
        pass "kill9-bosminer: every kill -9 of bosminer in $f is platform-conditional or graceful-fallback"
    fi
}
kill9_bosminer_check

#
# W4.2 stale-tarball advisory gate (DCENT_DevOps).
#
# This is an INFORMATIONAL gate -- it warns but never fails. Goal: surface
# the case where someone edited a Buildroot defconfig (e.g. enabled a new
# package, bumped a kernel arg, swapped a board overlay path) but the
# matching `output/dcentos-*.tar` was last produced before that edit. A
# stale tarball is silent in build_in_docker.sh because the Docker volume
# happily picks up the new defconfig but the operator may flash the old
# tarball from `output/`.
#
# We deliberately stay non-fatal because:
#   1. `output/` is gitignored and may be empty on a fresh clone -- no
#      tarball at all is the common case, not a failure.
#   2. Defconfig edits frequently land before the next release rebuild
#      (commit -> rebuild -> commit pin). Failing CI here would block
#      every routine defconfig edit.
#   3. Non-S9 packaging has no authenticated outer capsule. The retained
#      `rebuild_all_non_s9.sh --list` inventory explains that blocked state;
#      a target-specific capsule is the fix.
#
# Mechanism (pure POSIX sh + git plumbing):
#   For each (target, defconfig, tarball) triple:
#     - skip if the tarball isn't present in output/
#     - read the last-commit unix-timestamp of the defconfig via
#       `git log -1 --format=%ct -- <path>`
#     - read the tarball's mtime via `stat -c %Y` (GNU coreutils, available
#       on every Buildroot/Docker host we run on; macOS dev shells are
#       not the CI target)
#     - warn if defconfig mtime > tarball mtime
#
stale_tarball_advisory_gate() {
    output_dir="$PROJECT_DIR/output"

    if [ ! -d "$output_dir" ]; then
        pass "stale-tarball advisory: no output/ directory yet (skipping; nothing to compare)"
        return 0
    fi

    if ! command -v git >/dev/null 2>&1; then
        pass "stale-tarball advisory: git unavailable (skipping; gate is informational only)"
        return 0
    fi

    if ! git -C "$PROJECT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        pass "stale-tarball advisory: not inside a git work tree (skipping)"
        return 0
    fi

    # Triples are space-separated: target|defconfig|tarball. Using `|` so
    # the inner `set` parser handles tokens with predictable boundaries.
    triples='
am2-s19jpro|br2_external_dcentos/configs/dcentos_am2_s19jpro_defconfig|output/dcentos-sysupgrade-am2-s19jpro.tar
am2-s19pro|br2_external_dcentos/configs/dcentos_am2_s19pro_defconfig|output/dcentos-sysupgrade-am2-s19pro.tar
am2-s17pro|br2_external_dcentos/configs/dcentos_am2_s17pro_zynq_defconfig|output/dcentos-sysupgrade-am2-s17pro.tar
am3-s19kpro|br2_external_dcentos/configs/dcentos_am3_s19kpro_defconfig|output/dcentos-sysupgrade-am3-s19kpro.tar
am3-s19xp|br2_external_dcentos/configs/dcentos_am3_s19xp_defconfig|output/dcentos-sysupgrade-am3-s19xp.tar
am3-s21|br2_external_dcentos/configs/dcentos_am3_s21_defconfig|output/dcentos-sysupgrade-am3-s21.tar
am3-s21pro|br2_external_dcentos/configs/dcentos_am3_s21pro_defconfig|output/dcentos-sysupgrade-am3-s21pro.tar
am3-s21xp|br2_external_dcentos/configs/dcentos_am3_s21xp_defconfig|output/dcentos-sysupgrade-am3-s21xp.tar
am3-s19jpro-aml|br2_external_dcentos/configs/dcentos_am3_s19jpro_aml_defconfig|output/dcentos-sysupgrade-am3-s19jpro-aml.tar
am3-t21|br2_external_dcentos/configs/dcentos_am3_t21_defconfig|output/dcentos-sysupgrade-am3-t21.tar
am3-bb|br2_external_dcentos/configs/dcentos_am3_bb_defconfig|output/dcentos-am3-bb-sdcard.tar
am3-bb-s19jpro|br2_external_dcentos/configs/dcentos_am3_bb_s19jpro_defconfig|output/dcentos-am3-bb-s19jpro-sdcard.tar
'

    # Per-target status accounting via a tempfile because `printf | while`
    # runs the loop body in a pipeline subshell (POSIX), so we cannot
    # mutate counter variables in place. Tempfile is read once after the
    # loop completes for the final pass/warn summary.
    tmp_status=$(mktemp 2>/dev/null || echo "/tmp/dcentos-stale-tarball.$$")
    : > "$tmp_status"

    printf '%s\n' "$triples" | while IFS='|' read -r target defconfig tarball; do
        [ -n "$target" ] || continue

        if [ ! -f "$PROJECT_DIR/$tarball" ]; then
            printf 'SKIP %s\n' "$target" >> "$tmp_status"
            continue
        fi

        if [ ! -f "$PROJECT_DIR/$defconfig" ]; then
            printf 'MISSING_DEFCONFIG %s %s\n' "$target" "$defconfig" >> "$tmp_status"
            continue
        fi

        defconfig_commit_ts=$(git -C "$PROJECT_DIR" log -1 --format=%ct -- "$defconfig" 2>/dev/null || echo "")
        if [ -z "$defconfig_commit_ts" ]; then
            # Defconfig is staged/untracked; no commit anchor to compare
            # against. Treat as informational skip rather than warning --
            # the operator already knows they have local changes.
            printf 'NO_COMMIT %s\n' "$target" >> "$tmp_status"
            continue
        fi

        tarball_mtime=$(stat -c %Y "$PROJECT_DIR/$tarball" 2>/dev/null || echo "")
        if [ -z "$tarball_mtime" ]; then
            printf 'NO_MTIME %s\n' "$target" >> "$tmp_status"
            continue
        fi

        if [ "$defconfig_commit_ts" -gt "$tarball_mtime" ]; then
            printf 'STALE %s %s %s\n' "$target" "$defconfig_commit_ts" "$tarball_mtime" >> "$tmp_status"
        else
            printf 'FRESH %s\n' "$target" >> "$tmp_status"
        fi
    done

    # `grep -c` with zero matches exits non-zero AND prints `0` -- the
    # naive `|| echo 0` then concatenates two `0`s into a multi-line value
    # that truncates the downstream `pass` line. Use `awk` for a robust
    # single-line count instead.
    stale_count=$(awk '/^STALE /{n++} END{print n+0}' "$tmp_status")
    fresh_count=$(awk '/^FRESH /{n++} END{print n+0}' "$tmp_status")
    skip_count=$(awk '/^SKIP /{n++} END{print n+0}' "$tmp_status")

    if [ "$stale_count" -gt 0 ]; then
        printf 'WARN: stale-tarball advisory: %s tarball(s) older than their defconfig commit\n' "$stale_count" >&2
        grep '^STALE ' "$tmp_status" | while read -r marker target def_ts tar_ts; do
            def_iso=$(date -u -d "@$def_ts" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "@$def_ts")
            tar_iso=$(date -u -d "@$tar_ts" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "@$tar_ts")
            printf '  WARN: %s tarball mtime=%s < defconfig commit=%s -- non-S9 rebuild unavailable; see scripts/rebuild_all_non_s9.sh --list\n' \
                "$target" "$tar_iso" "$def_iso" >&2
        done
    fi

    pass "stale-tarball advisory: stale=$stale_count fresh=$fresh_count skip=$skip_count (informational; never fails)"

    rm -f "$tmp_status"
    return 0
}

stale_tarball_advisory_gate

#
# W6.5 hardware-rule grep guards (DCENT_QA, 2026-05-07).
#
# Five static checks that pin memory-rule invariants into the build pipeline.
# Each gate is grep-only (no compilation, no live hardware); each cites the
# memory rule it backstops so a future regressor sees the link from CI fail
# to the durable rationale.
#
# 1. `set_enabled(false)` may only appear in comments/docstrings or inside
#    sanctioned cold-boot/passthrough init paths. The HAL exposes the
#    method (it is the literal CTRL_REG-zero primitive) but the daemon
#    must NEVER call it on a chain that has had UART traffic — see
#    . Today there are zero in-code
#    call sites; we pin that.
#
# 2. The 3-byte SHORT-form RESET `[0x55, 0xAA, 0x07]` byte literal is
#    banned from `dspic.rs` and from any `s19j_*` source file. It is the
#    proven non-bootloader-entry form on .139 fw=0x89 dsPICs (-4
#    synthesis 2026-04-27). Only the 6-byte FRAMED RESET
#    `[55 AA 04 07 00 0B]` is permitted, and only in the recovery-tool
#    binary..
#
# 3. `JUMP_TO_APP` (0x06) must always be preceded by a raw-byte check
#    that rejects 0x60 (already-in-app) — sending JUMP to an app-mode
#    PIC drops it back into bootloader and corrupts its state machine
#    (S9 stock PIC bug, 2026-03-12). We grep for `JUMP_TO_APP` /
#    `jump_to_app` call sites and require a prior `read_pic_raw` /
#    `i2c_read_byte` / `read_byte` within 20 lines OR the call must be
#    inside the recovery-tool binary (where bootloader-only invocation
#    is the explicit intent).
#
# 4. Each `set_voltage` call site outside the HAL primitive layer must
#    be inside a stable-heartbeat gate. The architectural pattern is a
#    `stable_heartbeat_ticks >= 5` (or `< 5` early-return) check in the
#    enclosing function, OR the call happens inside `stock_mining.rs`
#    cold-boot init OR inside `cold_boot_sequence` / `*_init_bypass`
#    paths..
#
# 5. The voltage-command channel architecture itself must remain wired:
#    `daemon.rs` must contain BOTH the `stable_heartbeat_ticks` counter
#    AND the `< 5` early-block branch. Removing either silently
#    bypasses the gate.
#

# Gate W6.5-1: set_enabled(false) must be comment-only or HAL-impl.
set_enabled_false_check() {
    targets='
        dcentrald/dcentrald
        dcentrald/dcentrald-asic
        dcentrald/dcentrald-thermal
        dcentrald/dcentrald-api
        dcentrald/dcentrald-autotuner
        dcentrald/dcentrald-diagnostics
    '
    hits=''
    for d in $targets; do
        [ -d "$d" ] || continue
        # Find lines with `.set_enabled(false)` or `set_enabled(false)`,
        # then drop comment-only lines (// ... or /// ...).
        candidate=$(grep -rnE '\.set_enabled\(false\)|fn set_enabled\(' "$d" --include='*.rs' 2>/dev/null \
            | awk -F: '{
                orig=$0
                line=$0
                # strip "FILE:LINENO:" prefix (two leading colon-fields)
                sub(/^[^:]+:[0-9]+:/, "", line)
                sub(/^[[:space:]]+/, "", line)
                # skip pure-comment lines
                if (line ~ /^\/\//) next
                if (line ~ /^\/\*/) next
                if (line ~ /^\*/) next
                # The HAL primitive itself (`pub fn set_enabled`) is allowed.
                if (line ~ /^pub fn set_enabled/) next
                if (line ~ /fn set_enabled\(/) next
                print orig
            }' \
            || true)
        # Filter the .set_enabled(false) hit list down to actual call sites.
        callers=$(printf '%s\n' "$candidate" | grep -F '.set_enabled(false)' || true)
        if [ -n "$callers" ]; then
            if [ -z "$hits" ]; then
                hits=$callers
            else
                hits="$hits
$callers"
            fi
        fi
    done
    if [ -n "$hits" ]; then
        fail "W6.5-1 set_enabled(false): forbidden call site detected (regression of feedback_never_set_enabled_false.md)"
        printf '%s\n' "$hits" >&2
    else
        pass "W6.5-1 set_enabled(false): zero non-comment call sites in daemon/asic/thermal/api/autotuner/diagnostics"
    fi
}
set_enabled_false_check

# Gate W6.5-2: 0x07 SHORT-form RESET banned from dspic.rs / dspic/*.rs / s19j_*.
#
#  W24-CI-2 (BD-1): the original `-name 'dspic.rs'` glob was BLIND to
# the entire `dspic/` directory module — the dsPIC sources moved from a flat
# `dspic.rs` into `dcentrald-asic/src/dspic/{mod,fw82,fw86,fw89,fw8a,
# recovery_fw86,bosminer_warmup}.rs`, so this gate (the tripwire for the
# `a lab unit`/`a lab unit` bare-RESET corruption class) was silently green and never
# inspected the dsPIC code at all. The find now also walks `*/dspic/*.rs`.
#
# `dspic/bosminer_warmup.rs` LEGITIMATELY contains the `[0x55, 0xAA, 0x07]`
# RESET literal (lines ~150, ~427), but there it is SAFE BY CONSTRUCTION: the
# wrapper always emits a 19-byte parser-flush transaction immediately BEFORE
# the RESET in the same `build_prelude_transactions()` call (the `a lab unit`
# corruption was a BARE RESET to a chip in unknown parser state — structurally
# impossible here). So `bosminer_warmup.rs` is allow-listed by name; to make
# sure that allow-list never masks a future genuinely-unsafe BARE RESET added
# to that file, the flush-before-RESET shape is independently PINNED below
# (`bosminer_warmup_flush_before_reset_pin`). A bare RESET added to any OTHER
# `dspic/*.rs` (mod/fw82/fw86/fw89/fw8a/recovery_fw86) still trips the gate.
short_form_reset_check() {
    targets=$(find dcentrald -type f \
        \( -path '*/dspic/*.rs' -o -name 'dspic.rs' -o -name 's19j_*.rs' \) \
        2>/dev/null)
    inspected_dspic_dir_files=0
    hits=''
    for f in $targets; do
        [ -f "$f" ] || continue
        case "$f" in
            */dspic/*) inspected_dspic_dir_files=$((inspected_dspic_dir_files + 1)) ;;
        esac
        # `dspic/bosminer_warmup.rs` is the sanctioned flush-prefixed RESET
        # site — allow-listed by name (its safe-by-construction shape is
        # separately pinned by bosminer_warmup_flush_before_reset_pin).
        case "$f" in
            */dspic/bosminer_warmup.rs) continue ;;
        esac
        # Match the 3-byte literal `[0x55, 0xAA, 0x07]` (with optional
        # whitespace + commas around the bytes). Skip comment lines.
        candidate=$(grep -nE '\[[[:space:]]*0x55[[:space:]]*,?[[:space:]]*0xAA[[:space:]]*,?[[:space:]]*0x07[[:space:]]*[,\]]' "$f" 2>/dev/null \
            | awk '{
                orig=$0
                line=$0
                sub(/^[0-9]+:/, "", line)
                sub(/^[[:space:]]+/, "", line)
                if (line ~ /^\/\//) next
                if (line ~ /^\/\*/) next
                if (line ~ /^\*/) next
                print FILENAME ":" orig
            }' FILENAME="$f" \
            || true)
        if [ -n "$candidate" ]; then
            if [ -z "$hits" ]; then
                hits=$candidate
            else
                hits="$hits
$candidate"
            fi
        fi
    done
    if [ -n "$hits" ]; then
        fail "W6.5-2 short-form-reset: 0x07 SHORT-form RESET literal [0x55,0xAA,0x07] found in dspic.rs / dspic/*.rs / s19j_* (regression of feedback_pic_no_reset_s19j.md — Wave 1-4 banned this form)"
        printf '%s\n' "$hits" >&2
    else
        pass "W6.5-2 short-form-reset: no [0x55,0xAA,0x07] literal in dspic.rs / dspic/*.rs (except sanctioned bosminer_warmup.rs) / s19j_* sources"
    fi
    # Self-test: the gate MUST actually inspect the dspic/ directory module.
    # If the find ever stops matching dspic/*.rs (path rename, build-tree
    # reshuffle), this catches the glob-hole that W24-CI-2 just closed instead
    # of silently going green again.
    if [ "$inspected_dspic_dir_files" -ge 1 ]; then
        pass "W6.5-2 short-form-reset selftest: gate inspected $inspected_dspic_dir_files file(s) under dspic/ directory module"
    else
        fail "W6.5-2 short-form-reset selftest: gate inspected ZERO files under */dspic/*.rs — the dsPIC module is unscanned (glob hole reopened; see W24-CI-2 / BD-1)"
    fi
}
short_form_reset_check

# Gate W6.5-2b: pin the flush-before-RESET shape in dspic/bosminer_warmup.rs.
#
# `bosminer_warmup.rs` is allow-listed in W6.5-2 because its RESET is
# safe-by-construction: the 19-byte parser flush (`[0x55, 0xAA, 0x00] + 16×00`)
# is emitted in the same call, immediately before the `[0x55, 0xAA, 0x07]`
# RESET. This gate makes that allow-list HONEST — it asserts the three
# structural invariants that keep the RESET safe, so a future edit that strips
# the flush (turning the sanctioned site into a bare RESET) FAILS CI here even
# though the file stays allow-listed in W6.5-2. Pins:
#   1. the 19-byte flush payload [0x55, 0xAA, 0x00, 0x00*16] exists,
#   2. the RESET frame [0x55, 0xAA, 0x07] exists,
#   3. the structural unit tests that order flush(tx0) -> reset(tx1) are present
#      (`step_0_is_per_byte_parser_flush` + `step_1_is_reset_opcode_*`).
bosminer_warmup_flush_before_reset_pin() {
    f=$(find dcentrald -type f -path '*/dspic/bosminer_warmup.rs' 2>/dev/null | head -n 1)
    if [ -z "$f" ] || [ ! -f "$f" ]; then
        # File absent => the W6.5-2 allow-list has nothing to mask. Not a
        # failure: a checkout without the bosminer warmup module simply has no
        # sanctioned flush-prefixed RESET site to protect.
        pass "W6.5-2b warmup-flush-pin: dspic/bosminer_warmup.rs not present (nothing to allow-list; skip)"
        return
    fi
    missing=''
    # 1. 19-byte parser-flush payload header [0x55, 0xAA, 0x00].
    if ! grep -qE 'bytes\.push\(0x55\)' "$f" || ! grep -qE 'bytes\.push\(0x00\)' "$f"; then
        missing="$missing parser-flush-payload"
    fi
    # 2. RESET frame literal must still be present (proves we are pinning the
    #    real site, not a renamed/empty file).
    if ! grep -qE '\[[[:space:]]*0x55[[:space:]]*,[[:space:]]*0xAA[[:space:]]*,[[:space:]]*0x07[[:space:]]*\]' "$f"; then
        missing="$missing reset-frame-literal"
    fi
    # 3. The structural ordering tests that prove flush(tx[0]) precedes
    #    reset(tx[1]) must remain.
    if ! grep -qE 'fn step_0_is_per_byte_parser_flush' "$f"; then
        missing="$missing flush-is-tx0-test"
    fi
    if ! grep -qE 'fn step_1_is_reset_opcode' "$f"; then
        missing="$missing reset-is-tx1-test"
    fi
    if [ -n "$missing" ]; then
        fail "W6.5-2b warmup-flush-pin: dspic/bosminer_warmup.rs lost flush-before-RESET invariant(s):$missing — the W6.5-2 allow-list for this file is no longer safe-by-construction (regression of feedback_pic_no_reset_s19j.md)"
    else
        pass "W6.5-2b warmup-flush-pin: dspic/bosminer_warmup.rs keeps the 19-byte flush before [0x55,0xAA,0x07] RESET (flush=tx0, reset=tx1 ordering tests present) — allow-list stays safe-by-construction"
    fi
}
bosminer_warmup_flush_before_reset_pin

# Gate W6.5-3: JUMP_TO_APP / jump_to_app must be preceded by a raw-byte check.
jump_to_app_check() {
    targets='
        dcentrald/dcentrald
        dcentrald/dcentrald-asic
        dcentrald/dcentrald-hal
    '
    hits=''
    for d in $targets; do
        [ -d "$d" ] || continue
        # Match call sites: `JUMP_TO_APP`, `JUMP_FROM_LOADER`, `jump_to_app(`.
        # Skip docstring/comment lines and skip `const`/`pub const` definitions.
        files=$(grep -rlE 'JUMP_TO_APP|JUMP_FROM_LOADER|jump_to_app\(' "$d" --include='*.rs' 2>/dev/null \
            | grep -vE 'pic-recovery|dspic_flash\.rs|dspic_frame\.rs|stock_fpga_iic\.rs|i2c\.rs|/pic/mod\.rs|/dspic/mod\.rs|/dspic/recovery_fw86\.rs|pic\.rs|dspic\.rs' \
            || true)
        # NOTE on the file-name exclusion list above:
        #   - pic.rs / dspic.rs both DEFINE the `jump_to_app` primitive AND
        #     contain its single sanctioned call site, which is gated by an
        #     extensive raw-byte (`raw_state == 0xCC`, `needs_jump`,
        #     `pre_detect_raw`) check chain that lives in a parent `if !needs_jump`
        #     block far outside the 20-line window. We trust those two files
        #     by-construction and audit any new call site OUTSIDE of them.
        #   - Their internal call site is independently locked down by the
        #     existing dspic.rs `jump_to_app banned` panic test (line ~2741)
        #     which W6.5-3 does not need to re-prove.
        for f in $files; do
            [ -f "$f" ] || continue
            # Find call-site line numbers (skip comments, skip const definitions).
            lines=$(grep -nE 'JUMP_TO_APP|JUMP_FROM_LOADER|jump_to_app\(' "$f" 2>/dev/null \
                | awk -F: '{
                    line=$0
                    ln=$1
                    sub(/^[0-9]+:/, "", line)
                    sub(/^[[:space:]]+/, "", line)
                    if (line ~ /^\/\//) next
                    if (line ~ /^\/\*/) next
                    if (line ~ /^\*/) next
                    if (line ~ /^pub const/) next
                    if (line ~ /^const/) next
                    if (line ~ /^use /) next
                    print ln
                }' \
                || true)
            for ln in $lines; do
                start=$((ln - 60))
                if [ "$start" -lt 1 ]; then start=1; fi
                window=$(sed -n "${start},${ln}p" "$f")
                # Acceptable preceding patterns: any raw-byte / version read
                # OR an explicit BootloaderOnly / cold-boot context.
                if printf '%s\n' "$window" | grep -qE 'read_pic_raw|read_raw_byte|i2c_read_byte|read_byte|pic_raw|raw_read|raw == 0xCC|== 0xCC|GET_VERSION|get_version|detect_firmware|in_bootloader|is_bootloader|BootloaderOnly|in_app_mode|needs_jump|pre_detect_raw|raw_state|cold_boot|cold-boot|COLD BOOT'; then
                    continue
                fi
                offender="$f:$ln: $(sed -n "${ln}p" "$f")"
                if [ -z "$hits" ]; then
                    hits=$offender
                else
                    hits="$hits
$offender"
                fi
            done
        done
    done
    if [ -n "$hits" ]; then
        fail "W6.5-3 jump_to_app: JUMP_TO_APP/jump_to_app call site without preceding raw-byte/version check within 20 lines (regression of feedback_pic_no_reset_s19j.md / S9 stock PIC 0xCC-vs-0x60 bug)"
        printf '%s\n' "$hits" >&2
    else
        pass "W6.5-3 jump_to_app: every JUMP_TO_APP / jump_to_app call site is preceded by a raw-byte / version check (or lives in the recovery-tool binary)"
    fi
}
jump_to_app_check

# Gate W6.5-4: set_voltage call sites must be heartbeat-stability-gated or
# inside cold-boot init / bypass paths.
set_voltage_gate_check() {
    # Sanctioned bypass paths: cold-boot init voltage, set_voltage_init_bypass,
    # set_voltage_min (panic-safe rail collapse), and HAL primitive impls.
    sanctioned_files='
        dcentrald/dcentrald-hal/src/psu.rs
        dcentrald/dcentrald-hal/src/i2c.rs
        dcentrald/dcentrald-asic/src/pic.rs
        dcentrald/dcentrald-asic/src/dspic.rs
        dcentrald/dcentrald-asic/src/dspic_flash.rs
        dcentrald/dcentrald-asic/src/i2c_service.rs
        dcentrald/dcentrald-asic/src/dspic_service.rs
        dcentrald/dcentrald-asic/src/pic0x89_service.rs
        dcentrald/pic-recovery/src/main.rs
    '
    # Files where set_voltage calls must each be inside a stability gate.
    callers='
        dcentrald/dcentrald/src/daemon.rs
        dcentrald/dcentrald/src/work_dispatcher.rs
        dcentrald/dcentrald/src/s19j_hybrid_mining.rs
        dcentrald/dcentrald/src/serial_mining.rs
        dcentrald/dcentrald/src/stock_mining.rs
        dcentrald/dcentrald-autotuner
    '
    hits=''
    for d in $callers; do
        [ -e "$d" ] || continue
        files=''
        if [ -d "$d" ]; then
            files=$(find "$d" -type f -name '*.rs' 2>/dev/null)
        else
            files="$d"
        fi
        for f in $files; do
            [ -f "$f" ] || continue
            # Find set_voltage call sites (skip definitions, comments, and
            # the panic-safe set_voltage_min rail-collapse path).
            lines=$(grep -nE '\.set_voltage\(' "$f" 2>/dev/null \
                | awk -F: '{
                    line=$0
                    ln=$1
                    sub(/^[0-9]+:/, "", line)
                    sub(/^[[:space:]]+/, "", line)
                    if (line ~ /^\/\//) next
                    if (line ~ /^\/\*/) next
                    if (line ~ /^\*/) next
                    if (line ~ /^pub fn set_voltage/) next
                    if (line ~ /^fn set_voltage/) next
                    # set_voltage_min/_init_bypass are sanctioned bypass paths
                    if (line ~ /\.set_voltage_min\(/) next
                    if (line ~ /\.set_voltage_init_bypass\(/) next
                    if (line ~ /\.set_voltage_max_safe\(/) next
                    print ln
                }' \
                || true)
            for ln in $lines; do
                start=$((ln - 60))
                if [ "$start" -lt 1 ]; then start=1; fi
                end=$((ln + 5))
                window=$(sed -n "${start},${end}p" "$f")
                # Acceptable enclosing patterns:
                #   - stable_heartbeat_ticks gate
                #   - cold_boot / cold-boot init context
                #   - INIT_VOLTAGE_DAC / DEFAULT_VOLTAGE_DAC (cold-boot init)
                #   - LAB-ONLY / TRUST-RAIL fallback
                #   - am2_safe_teardown_sequence (2026-05-19 reconciliation):
                #     the deferred-voltage-stability rule
                # protects
                #     the COLD-BOOT/STARTUP regime — a SET_VOLTAGE NACK before
                #     the PIC heartbeat is stable corrupts the MSSP parser.
                #     The orderly/fail-closed TEARDOWN coast-down (walk rail
                #     to floor so chips coast down before HBx_RESET drain) is
                #     the OPPOSITE phase: the PIC has heartbeated throughout
                #     the run, and on a fail-closed teardown you CANNOT and
                #     MUST NOT wait for "5 stable heartbeat ticks" (the PIC
                #     may already be dead — that's why teardown is
                #     best-effort, errors logged-not-propagated, with the
                #     run-scope hard-stop guard as the final net). This is a
                #     NARROW carve-out for the single named teardown function
                #     only — it cannot mask a cold-boot-init regression (a
                #     different function/context). NO firmware change; this
                #     reconciles the gate allowlist to the structurally-
                #     sanctioned teardown context (gate-vs-code drift since
                #     the teardown sequence landed ~2026-05-15).
                if printf '%s\n' "$window" | grep -qE 'stable_heartbeat_ticks|stable_heartbeats|heartbeat_stable|cold_boot|cold-boot|INIT_VOLTAGE_DAC|DEFAULT_VOLTAGE_DAC|init_voltage|init voltage|set_voltage_init_bypass|am2_safe_teardown_sequence|safe-teardown sequence|TRUST-RAIL|trust_rail|LAB-ONLY|voltage_stability|deferred_voltage|pending_voltage'; then
                    continue
                fi
                offender="$f:$ln: $(sed -n "${ln}p" "$f")"
                if [ -z "$hits" ]; then
                    hits=$offender
                else
                    hits="$hits
$offender"
                fi
            done
        done
    done
    if [ -n "$hits" ]; then
        fail "W6.5-4 set_voltage-gate: set_voltage call site without stable_heartbeat_ticks gate / cold-boot init context (regression of feedback_deferred_voltage_stability_gate.md)"
        printf '%s\n' "$hits" >&2
    else
        pass "W6.5-4 set_voltage-gate: every set_voltage call site is inside a stable_heartbeat_ticks gate or a sanctioned cold-boot init / bypass path"
    fi
    # Note: sanctioned_files list documents which files own the primitive
    # implementations. They are intentionally excluded from the caller scan.
    : "$sanctioned_files"
}
set_voltage_gate_check

# Gate W6.5-5: deferred-voltage architecture must remain wired in daemon.rs.
deferred_voltage_arch_check() {
    f='dcentrald/dcentrald/src/daemon.rs'
    if [ ! -f "$f" ]; then
        fail "W6.5-5 deferred-voltage-arch: missing $f"
        return
    fi
    if ! grep -q 'stable_heartbeat_ticks' "$f"; then
        fail "W6.5-5 deferred-voltage-arch: stable_heartbeat_ticks counter missing from $f"
        return
    fi
    if ! grep -qE 'stable_heartbeat_ticks[[:space:]]*<[[:space:]]*5' "$f"; then
        fail "W6.5-5 deferred-voltage-arch: '< 5' early-block branch missing from $f (regression of feedback_deferred_voltage_stability_gate.md)"
        return
    fi
    pass "W6.5-5 deferred-voltage-arch: stable_heartbeat_ticks counter + '< 5' early-block branch wired in daemon.rs"
}
deferred_voltage_arch_check

#
# Gate W6.5-6: BIP320 `version_bits_raw != 0` rejection-guard ban
# (DCENT_Protocol + DCENT_QA, 2026-05-15).
#
# The single most load-bearing mining-correctness contract on the
# BM1362-family chip-side BIP320 paths is that the share-submit loop must
# NEVER pre-filter parsed nonces with the form
#
#     if nr.version_bits_raw != 0 { continue; }
#
# That guard discarded ~95% of valid hashing work on AM2 XIL `a lab unit`
# (the 4655-RX-frames-0-nonces failure of 2026-05-15 morning) and cost
# the fifth-platform milestone an entire diagnostic session before it was
# deleted in the cross-platform Protocol fix sweep (post-`2b6d46f3`).
# `validate_full_header(header_with_rolled_version, share_target)` is the
# SOLE local gate; the rolled version is reconstructed via the shared
# `bm1362::bip320_reconstruct_rolled_version` helper. See memory rules
# ,
# ,
# and .
#
# Sibling W6.5 gates already grep-ban `.set_enabled(false)` and the
# 0x07 SHORT-form RESET literal; until now this contract was pinned only
# by the Rust `bip320_tests` module (a `cargo test -p dcentrald-asic`
# gate) plus prose regression-pins, with NO automated grep gate. This
# closes that gap.
#
# Scope: the four BM1362-family share-submit modules. The match is
# deliberately narrow — it fires on the actual *rejection guard*
# (a conditional on `version_bits_raw` being non-zero whose body is
# `continue`), in both the compact one-line form and the
# `if ... != 0 {` / `continue;` two-line form. It must NOT fire on:
#   * the obsolete-rejection PROSE block at
#     `s19j_hybrid_mining.rs` (a comment-only regression-pin that
#     legitimately quotes the banned pattern),
#   * the `bm1362::uart_transport` docstring that names
#     `version_bits_raw` + "rejection guard" in `///` comment lines,
#   * legitimate non-guard uses such as
#     `let distinct_midstates = ... version_bits_raw != 0;`
#     (a dedup boolean — no `continue`),
#   * test names / comments that mention the contract.
# Comment-only lines are stripped with the same awk pass the sibling
# W6.5 gates use.
#
bip320_rejection_guard_check() {
    if [ -n "${DCENT_BIP320_REJECTION_GUARD_TARGETS:-}" ]; then
        targets=$DCENT_BIP320_REJECTION_GUARD_TARGETS
    else
        targets='
            dcentrald/dcentrald/src/s19j_hybrid_mining.rs
            dcentrald/dcentrald/src/am3_bb_mining.rs
            dcentrald/dcentrald/src/serial_mining.rs
            dcentrald/dcentrald/src/work_dispatcher.rs
        '
    fi
    hits=''
    for f in $targets; do
        [ -f "$f" ] || continue

        # --- One-line compact form -------------------------------------
        # Matches `if <expr>version_bits_raw<expr> != 0 <expr> { ...
        # continue ... }` on a single line. The `[._a-zA-Z0-9 ]*`
        # tolerance around the identifier accepts `nr.version_bits_raw`,
        # `entry .version_bits_raw`, `version_bits_raw as u32`, etc.
        # Requires `continue` after the `{` so a non-guard boolean use
        # (`let x = ... version_bits_raw != 0;`) never matches.
        oneline=$(grep -nE \
            'if[[:space:]].*version_bits_raw[[:space:]._a-zA-Z0-9()]*!=[[:space:]]*0[^{]*\{[^}]*continue' \
            "$f" 2>/dev/null \
            | awk -v fn="$f" '{
                orig=$0
                line=$0
                sub(/^[0-9]+:/, "", line)
                sub(/^[[:space:]]+/, "", line)
                if (line ~ /^\/\//) next
                if (line ~ /^\/\*/) next
                if (line ~ /^\*/) next
                print fn ":" orig
            }' \
            || true)

        # --- Two-line form ---------------------------------------------
        # `if <...>version_bits_raw<...> != 0 <...> {` on one line, then
        # the very next non-blank source line is `continue;` (the
        # classic guard split across two lines). Use awk to carry the
        # candidate-open across lines, skipping comment-only lines so the
        # prose regression-pins do not match.
        twoline=$(awk '
            function strip(s) {
                sub(/^[[:space:]]+/, "", s)
                return s
            }
            {
                raw=$0
                code=strip($0)
                is_comment = (code ~ /^\/\//) || (code ~ /^\/\*/) || (code ~ /^\*/)
                if (is_comment) { next }
                if (code == "") { next }

                if (pending_open) {
                    if (code ~ /^continue[[:space:]]*;/) {
                        print FILENAME ":" open_lineno ": " open_text
                    }
                    pending_open = 0
                }

                if (code ~ /if[[:space:]].*version_bits_raw[[:space:]._a-zA-Z0-9()]*!=[[:space:]]*0[^{]*\{[[:space:]]*$/) {
                    pending_open = 1
                    open_lineno = FNR
                    open_text = code
                }
            }
        ' "$f" 2>/dev/null || true)

        for chunk in "$oneline" "$twoline"; do
            if [ -n "$chunk" ]; then
                if [ -z "$hits" ]; then
                    hits=$chunk
                else
                    hits="$hits
$chunk"
                fi
            fi
        done
    done
    if [ -n "$hits" ]; then
        fail "W6.5-6 bip320-rejection-guard: 'if ... version_bits_raw != 0 { continue }' rejection guard found in a BM1362 share-submit module (regression of feedback_am2_serial_dispatch_bip320_version_rolling_required.md — discards ~95% of valid AM2 hashing work; validate_full_header is the SOLE gate)"
        printf '%s\n' "$hits" >&2
    else
        pass "W6.5-6 bip320-rejection-guard: no version_bits_raw!=0 rejection guard in s19j_hybrid/am3_bb/serial_mining/work_dispatcher (rolled-version reconstruction + validate_full_header remain the only gate)"
    fi
}
bip320_rejection_guard_check

# W6.8 chip_geometry drift gate (DCENT_Perf, 2026-05-07).
#
# The legacy `chip_geometry::*_CORES` constants in
# `dcentrald-autotuner/src/lib.rs` drifted 30% out of sync with
# `dcentrald-asic::drivers::MinerProfile::cores_per_chip` (autotuner had
# 894 for BM1368 while MinerProfile carried the corrected 1280 from the
# S21 fixture RE). The autotuner now consumes
# `MinerProfile::nonce_attribution_cores` directly. This gate refuses any
# regression that reintroduces a per-chip `chip_geometry::BM*_CORES`
# constant — single source of truth lives in `dcentrald-asic`, not in
# the autotuner. See module docs in `dcentrald-asic/src/drivers/mod.rs`
# for the engine-vs-slot distinction.
#
chip_geometry_drift_check() {
    autotuner_dir='dcentrald/dcentrald-autotuner/src'
    if [ ! -d "$autotuner_dir" ]; then
        pass "chip_geometry-drift: autotuner dir not present (skipping)"
        return
    fi
    hits=$(grep -rEn 'chip_geometry::[A-Z0-9_]*_CORES' "$autotuner_dir" 2>/dev/null || true)
    if [ -n "$hits" ]; then
        fail "chip_geometry::*_CORES drift regression — autotuner must consume MinerProfile::nonce_attribution_cores"
        printf '%s\n' "$hits" >&2
    else
        pass "chip_geometry-drift: autotuner uses MinerProfile single-source-of-truth"
    fi
}
chip_geometry_drift_check

# Phase 4J regression slice (2026-05-15): offline log-replay of platform
# milestone runs. Catches schema drift / counter rename in `dcentrald`'s
# structured-log surface. Pure-text -- the script does NOT contact any
# miner, re-run the binary, or simulate hashing.
#
# Each platform replay asserts that the captured milestone log's
# `am2_serial_status` counters (`total_work`, `total_rx_frames`,
# `total_nonces`, `shares_submitted`) plus an independent count of
# "share accepted" lines still match the per-platform floor profile in
# `tools/replay_milestone_log.py` PLATFORM_PROFILES.
#
# Adding a new platform: drop the milestone log under
# , add a row below, add (or amend) the platform
# entry in PLATFORM_PROFILES. New platforms shipped without a milestone
# log emit an explicit SKIP line so the absence is documented rather than
# counted as a green proof.
regression_am2_xil_check() {
    if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
        pass "Phase 4J regression-am2-xil: python interpreter unavailable (skip)"
        return
    fi
    PY=python
    command -v python >/dev/null 2>&1 || PY=python3

    REPLAY_SCRIPT="$PROJECT_DIR/../../tools/replay_milestone_log.py"
    if [ ! -f "$REPLAY_SCRIPT" ]; then
        fail "Phase 4J regression-am2-xil: missing $REPLAY_SCRIPT"
        return
    fi

    # platform_short_name : milestone_log_relative_path
    set -- \
        "am2-xil:../../docs/dev/2026-05-14-xil-s19jpro-resume/logs/2026-05-15-dcentrald-xil-FIRST-ACCEPTED-SHARES.log" \
        "am3-bb:../../docs/dev/2026-05-13-am3-bb-blocker-fix/live-captures/dcentos-publicpool-share-79-20260513T2200Z.log"

    any_ran=0
    for entry in "$@"; do
        plat=$(printf '%s' "$entry" | cut -d: -f1)
        rel=$(printf '%s' "$entry" | cut -d: -f2-)
        log_path="$PROJECT_DIR/$rel"
        if [ ! -f "$log_path" ]; then
            # Not every checkout ships every milestone log. Emit SKIP, not PASS.
            printf 'SKIP: Phase 4J regression-%s: milestone log not present\n' "$plat"
            continue
        fi
        any_ran=1
        out=$("$PY" "$REPLAY_SCRIPT" --log "$log_path" --platform "$plat" 2>&1)
        rc=$?
        if [ "$rc" -eq 0 ]; then
            pass "Phase 4J regression-$plat: counters within floor for $log_path"
        else
            fail "Phase 4J regression-$plat: replay assertion failed for $log_path"
            printf '%s\n' "$out" >&2
        fi
    done

    if [ "$any_ran" -eq 0 ]; then
        # If NO milestone log was found, emit SKIP rather than a green PASS.
        printf 'SKIP: Phase 4J regression-am2-xil: no milestone logs found in this checkout\n'
    fi
}
regression_am2_xil_check

# Phase 4G regression slice (2026-05-15): cross-family mining-proof
# regression. Synthesizes s99verify-equivalent state.json + s99verify.json
# fixtures for five historical mining milestones (am1-s9, am2-s19pro,
# am2-XIL, am3-bb, am3-aml) and runs the current Phase 4H verifier
# (`dcent_toolbox.core.verifier`) offline against each.
#
# This complements the Phase 4J log-replay slice. Phase 4J catches
# schema drift in the running binary's structured log surface; Phase 4G
# catches regressions in the post-install verifier itself — the
# host-side classifier that gates whether "install completed" implies
# "install produces hashrate".
#
# The slice runs in two modes:
#   1. main slice — three admitted milestones must classify PROVEN and the
#                   historical S19 Pro/S21 fixtures must remain fail-closed
#                   UNVERIFIABLE under current first-install admission
#   2. self-test  — tamper the first milestone four ways (drop chain
#                   count, NULL first nonce, push share past budget,
#                   yield below floor) and verify each tamper flips
#                   the verifier verdict away from PROVEN
#
# Silent skip when Python is unavailable (same convention as Phase 4J).
regression_cross_family_check() {
    if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
        pass "Phase 4G regression-cross-family: python interpreter unavailable (skip)"
        return
    fi
    PY=python
    command -v python >/dev/null 2>&1 || PY=python3

    SLICE_SCRIPT="$PROJECT_DIR/../../tools/regression_cross_family.py"
    if [ ! -f "$SLICE_SCRIPT" ]; then
        fail "Phase 4G regression-cross-family: missing $SLICE_SCRIPT"
        return
    fi

    # Main slice — all five milestones must classify PROVEN.
    if out=$("$PY" "$SLICE_SCRIPT" 2>&1); then
        rc=0
    else
        rc=$?
    fi
    if [ "$rc" -eq 0 ]; then
        pass "Phase 4G regression-cross-family: 3 admitted + 2 policy-blocked milestone dispositions match"
        printf '%s\n' "$out" | sed -n 's/^OK    /  /p'
    else
        fail "Phase 4G regression-cross-family: a pinned milestone disposition drifted"
        printf '%s\n' "$out" >&2
        return
    fi

    # Self-test — tamper detection must fire.
    if out=$("$PY" "$SLICE_SCRIPT" --self-test 2>&1); then
        rc=0
    else
        rc=$?
    fi
    if [ "$rc" -eq 0 ]; then
        pass "Phase 4G regression-cross-family self-test: 4 of 4 tamper modes detected"
    else
        fail "Phase 4G regression-cross-family self-test: tamper detection regression"
        printf '%s\n' "$out" >&2
    fi
}
regression_cross_family_check

# =====================================================================
# DEVOPS/QA/SW/RE supply-chain + release + safety gates (2026-06-02).
# Static, offline, source-only. These close audit findings:
#   SW-05 / DEVOPS-003 / DEVOPS-004 — release-image hardening wiring
#   QA-004 / QA-009                 — workspace test gate wired into CI
#   QA-007                          — BIP320 rejection-guard ban-gate present
#   QA-006                          — devmem PWM writes <= 30 in all overlays
#   QA-002                          — BM1387 triple-write MiscCtrl count=3/5ms
#   RE-007                          — unconfirmed scaffold drivers fail-closed
# =====================================================================

#
# SW-05 / DEVOPS-003 / DEVOPS-004: release-image trust-boundary wiring.
#
# A PRODUCTION/RELEASE image (DCENT_RELEASE_IMAGE=1 at Buildroot time) MUST:
#   (a) have the release-image stamp hook wired into every board post-build.sh
#       (scripts/lib/release_image_provision.sh → dcent_provision_release_image)
#       so /etc/dcentos/release-image is stamped;
#   (b) gate the raw-HW MCP endpoint (S81mcp, port 3000) on that marker so it
#       does NOT auto-start on a release unit;
#   (c) have dcentrald-api::auth consume the marker (is_release_image →
#       password required, passwordless opt-out disabled).
# DEV-open (no marker, MCP localhost, root:dcentral) is intentional. The
# blocker this gate closes is a SHIPPED release image silently MISSING the
# marker/gate — which would leave REST/MCP/dashboard open with the shared
# root cred. This gate proves the wiring exists in source so a release build
# cannot regress to dev-open posture unnoticed.
#
nopic_post_build_release_delegate_ok() {
    _nopic_wrapper=$1
    [ -f "$_nopic_wrapper" ] && [ ! -L "$_nopic_wrapper" ] || return 1
    # Exact bounded prerequisite checks followed by the sole shared transaction.
    # This is a program contract, not a filename-only release exemption.
    # Each admitted wrapper's non-comment program text is pinned byte-exact.
    case "$_nopic_wrapper" in
        br2_external_dcentos/board/amlogic/am3-bm1362-nopic/post-build.sh)
            _nopic_expected=$(cat <<'DCENT_NOPIC_RELEASE_PROGRAM_BM1362'
set -eu
TARGET_DIR=$1
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
TARGET=$(cat "$TARGET_DIR/etc/dcentos/board_target")
case "$TARGET" in am3-s19jproa|am3-s19jproplus) ;; *) echo "ERROR: exact A126/Plus120 target required" >&2; exit 1 ;; esac
for required in etc/dcentos-early-init.sh etc/init.d/S45persistent \
    usr/libexec/dcentos/bm1362-nopic-storage.py usr/sbin/ubiattach; do
    [ -f "$TARGET_DIR/$required" ] && [ ! -L "$TARGET_DIR/$required" ] || {
        echo "ERROR: required A126/Plus120 startup file missing/indirect: $required" >&2
        exit 1
    }
    chmod 0755 "$TARGET_DIR/$required"
done
exec "$SCRIPT_DIR/../am3-s21/post-build.sh" "$@"
DCENT_NOPIC_RELEASE_PROGRAM_BM1362
)
            ;;
        br2_external_dcentos/board/amlogic/am3-s19kpro-nopic/post-build.sh)
            _nopic_expected=$(cat <<'DCENT_NOPIC_RELEASE_PROGRAM_S19KPRO'
set -eu
TARGET_DIR=$1
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
TARGET=$(cat "$TARGET_DIR/etc/dcentos/board_target")
case "$TARGET" in am3-s19kpro) ;; *) echo "ERROR: exact S19k Pro target required" >&2; exit 1 ;; esac
for required in etc/dcentos-early-init.sh etc/init.d/S45persistent \
    usr/libexec/dcentos/s19kpro-nopic-storage.py usr/sbin/ubiattach; do
    [ -f "$TARGET_DIR/$required" ] && [ ! -L "$TARGET_DIR/$required" ] || {
        echo "ERROR: required S19k Pro startup file missing/indirect: $required" >&2
        exit 1
    }
    chmod 0755 "$TARGET_DIR/$required"
done
exec "$SCRIPT_DIR/../am3-s21/post-build.sh" "$@"
DCENT_NOPIC_RELEASE_PROGRAM_S19KPRO
)
            ;;
        *)
            return 1
            ;;
    esac
    _nopic_actual=$(sed '/^[[:space:]]*#/d;/^[[:space:]]*$/d' "$_nopic_wrapper")
    [ "$_nopic_actual" = "$_nopic_expected" ] || return 1
    _nopic_delegate=br2_external_dcentos/board/amlogic/am3-s21/post-build.sh
    [ -f "$_nopic_delegate" ] && [ ! -L "$_nopic_delegate" ] || return 1
    grep -Fxq '. "${BR2_EXTERNAL_DCENTOS_PATH}/../scripts/lib/release_image_provision.sh"' "$_nopic_delegate" || return 1
    grep -Fxq 'dcent_provision_release_image "$TARGET_DIR" "$BOARD_NAME"' "$_nopic_delegate"
}

release_image_hardening_check() {
    # (a) the provisioning helper exists and stamps the marker.
    require_pattern \
        "scripts/lib/release_image_provision.sh" \
        "/etc/dcentos/release-image" \
        "SW-05a release-image: provision helper stamps /etc/dcentos/release-image"
    require_pattern \
        "scripts/lib/release_image_provision.sh" \
        "DCENT_RELEASE_IMAGE" \
        "SW-05a release-image: provision helper keys off DCENT_RELEASE_IMAGE"
    require_file 'scripts/test_release_image_provision.sh'
    if sh scripts/test_release_image_provision.sh >/dev/null 2>&1; then
        pass 'SW-05a release-image: adversarial provisioning lifecycle tests pass'
    else
        fail 'SW-05a release-image: adversarial provisioning lifecycle tests FAILED'
    fi

    # WS-A4 (2026-09-01): RELEASE is the DEFAULT image posture (operator
    # T-OP-7). Pin the flip itself: canonical resolver semantics, the
    # s19kpro-style refusal on explicit opt-out, driver wiring, and the
    # marker-keyed auth surfaces.
    require_file 'scripts/lib/release_posture.sh'
    require_pattern \
        'scripts/lib/release_posture.sh' \
        'DCENT_DEV_IMAGE' \
        'WS-A4 release-default: canonical resolver defines the DCENT_DEV_IMAGE opt-out'
    require_file 'scripts/test_release_posture_default.sh'
    if sh scripts/test_release_posture_default.sh >/dev/null 2>&1; then
        pass 'WS-A4 release-default: posture resolver, refusal, drivers, and marker-keyed auth surfaces pass'
    else
        fail 'WS-A4 release-default: release-default posture tests FAILED'
    fi

    require_file 'scripts/test_media_gate_delegates.py'
    if run_python_script scripts/test_media_gate_delegates.py >/dev/null 2>&1; then
        pass 'Media helper delegation gates reject missing, commented, redirected and early-success source paths'
    else
        fail 'Media helper delegation gate negative fixtures failed'
    fi

    # (a cont.) every activating board post-build.sh that ships a rootfs must
    # call the provisioning hook. A typed NOT_IMPLEMENTED compatibility hook
    # may be excluded only when its executable grammar is shell builtins that
    # print a refusal and terminate with EX_UNAVAILABLE (78).
    pb_missing=''
    pb_found=0
    pb_refused=0
    for pb in br2_external_dcentos/board/*/post-build.sh \
              br2_external_dcentos/board/*/*/post-build.sh; do
        [ -f "$pb" ] || continue
        pb_found=$((pb_found + 1))
        if grep -Fxq '# DCENT_BUILD_POLICY=not-implemented-refusal' "$pb"; then
            invalid_refusal=$(awk '
                /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
                $1 == "printf" { next }
                $0 == "exit 78" { exits++; next }
                { print NR ":" $0 }
                END { if (exits != 1) print "exit-count=" exits }
            ' "$pb")
            if [ -z "$invalid_refusal" ]; then
                pb_refused=$((pb_refused + 1))
                continue
            fi
            fail "SW-05a release-image: typed build refusal has activating or ambiguous grammar: $pb"
            printf '%s\n' "$invalid_refusal" >&2
            continue
        fi
        if grep -Eq -- '^[[:space:]]*dcent_provision_release_image([[:space:]]|$)' \
            "$pb" >/dev/null 2>&1; then
            continue
        fi

        # Product wrappers may delegate their entire post-build transaction to
        # one shared board hook. Admit only a single exact exec with untouched
        # argv, then resolve the repository-local target and prove that target
        # owns the release-image hook. Comments containing the hook name and
        # wrappers with any additional executable statement do not qualify.
        pb_delegate=$(sed -n \
            's|^exec "${BR2_EXTERNAL_DCENTOS_PATH}/\(board/[^"[:space:]]*/post-build\.sh\)" "$@"$|\1|p' \
            "$pb")
        pb_executable_lines=$(awk '
            /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
            { count++ }
            END { print count + 0 }
        ' "$pb")
        if [ -n "$pb_delegate" ] \
            && [ "$(printf '%s\n' "$pb_delegate" | wc -l | tr -d ' ')" -eq 1 ] \
            && [ "$pb_executable_lines" -eq 1 ] \
            && [ -f "br2_external_dcentos/$pb_delegate" ] \
            && grep -Eq -- '^[[:space:]]*dcent_provision_release_image([[:space:]]|$)' \
                "br2_external_dcentos/$pb_delegate" >/dev/null 2>&1; then
            continue
        fi
        if nopic_post_build_release_delegate_ok "$pb"; then
            continue
        fi
        pb_missing="$pb_missing $pb"
    done
    if [ "$pb_found" -eq 0 ]; then
        fail "SW-05a release-image: no board post-build.sh files found (path drift?)"
    elif [ -n "$pb_missing" ]; then
        fail "SW-05a release-image: board post-build.sh missing dcent_provision_release_image call:$pb_missing"
    else
        pb_active=$((pb_found - pb_refused))
        pass "SW-05a release-image: all $pb_active activating post-build hooks call dcent_provision_release_image; $pb_refused typed refusal hook(s) excluded"
    fi

    # (b) S81mcp gates on the marker (does NOT auto-start on a release image).
    mcp_missing=''
    mcp_found=0
    for mcp in br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/S81mcp \
               br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S81mcp; do
        [ -f "$mcp" ] || continue
        mcp_found=$((mcp_found + 1))
        if ! grep -F -- '/etc/dcentos/release-image' "$mcp" >/dev/null 2>&1; then
            mcp_missing="$mcp_missing $mcp"
        fi
    done
    if [ "$mcp_found" -eq 0 ]; then
        fail "SW-05b release-image: no S81mcp init scripts found (path drift?)"
    elif [ -n "$mcp_missing" ]; then
        fail "DEVOPS-004 S81mcp: raw-HW MCP endpoint NOT gated on the release-image marker in:$mcp_missing (a release image would auto-start an unauthenticated localhost raw-HW endpoint)"
    else
        pass "DEVOPS-004 S81mcp: raw-HW MCP endpoint gated on /etc/dcentos/release-image in all $mcp_found S81mcp scripts"
    fi

    # (c) dcentrald-api::auth consumes the marker.
    auth_rs='dcentrald/dcentrald-api/src/auth.rs'
    if [ -f "$auth_rs" ]; then
        require_pattern "$auth_rs" "/etc/dcentos/release-image" \
            "SW-05c release-image: dcentrald-api auth.rs consumes the release-image marker"
    else
        # auth.rs is owned by another group; absence here is path drift, not a
        # hard release-blocker for this gate — warn via a soft pass.
        pass "SW-05c release-image: auth.rs not present at expected path (skipping marker-consume check)"
    fi
}
release_image_hardening_check

# CE-183: a release-status sysupgrade package must not decouple from
# release-image hardening (root SSH lockdown + /etc/dcentos/release-image
# marker). Pins the producer-side coupling (packaging lib + docker + standalone
# packager) and the daemon accept-side rejection of unsigned release bundles.
release_status_hardening_coupling_check() {
    require_pattern \
        'scripts/lib/sysupgrade_package_common.sh' \
        'dcent_require_release_image_hardening' \
        'CE-183a: packaging lib defines the release-status->release-image coupling'

    # The manifest writer must call the coupling gate BEFORE writing the
    # MANIFEST.json (which carries the release status). Function-body pin in the
    # same style as make_release_verify_gate_check.
    if awk '
        BEGIN { in_fn = 0; gate_line = 0; manifest_line = 0 }
        /^dcent_write_sysupgrade_manifest\(\) \{/ { in_fn = 1; next }
        in_fn && /^\}/ { in_fn = 0 }
        in_fn && /dcent_require_release_image_hardening/ { if (gate_line == 0) gate_line = NR }
        in_fn && /MANIFEST\.json/ { if (manifest_line == 0) manifest_line = NR }
        END {
            ok = gate_line > 0 && manifest_line > 0 && gate_line < manifest_line
            exit ok ? 0 : 1
        }
    ' scripts/lib/sysupgrade_package_common.sh; then
        pass 'CE-183b: manifest writer calls the coupling gate before writing status'
    else
        fail 'CE-183b: dcent_write_sysupgrade_manifest must call dcent_require_release_image_hardening before the MANIFEST.json heredoc'
    fi

    require_pattern \
        'scripts/build_in_docker.sh' \
        'Release status must not decouple from release-image hardening' \
        'CE-183c: docker producer fails fast on release-status without DCENT_RELEASE_IMAGE=1'

    if [ "$(grep -c -- '-e DCENT_RELEASE_IMAGE=' scripts/build_in_docker.sh)" -ge 2 ]; then
        pass 'CE-183d: Phase 7 S9 packaging container receives DCENT_RELEASE_IMAGE'
    else
        fail 'CE-183d: Phase 7 S9 packaging container must pass -e DCENT_RELEASE_IMAGE'
    fi

    require_pattern \
        'scripts/package_sysupgrade.sh' \
        'requires DCENT_RELEASE_IMAGE=1' \
        'CE-183e: standalone S9 packager enforces the coupling'

    require_pattern \
        'dcentrald/dcentrald-api/src/ota_signature.rs' \
        'allow_unsigned lab override does not apply to release-status' \
        'CE-183f: daemon rejects unsigned release-status bundles even in lab mode'
}
release_status_hardening_coupling_check

#
# QA-004 / QA-009: the workspace test compile-gate (run_dcentrald_tests.sh,
# `cargo test --no-run` for the real musl target) must be REFERENCED by an
# actual CI workflow. The script existed but was orphaned — no workflow ran
# it — which is exactly how SB-3 (a test with a broken include_str! path)
# shipped uncompiled for weeks. This gate proves a workflow invokes it.
#
test_gate_wired_check() {
    script='scripts/run_dcentrald_tests.sh'
    require_file "$script"

    # Workflows live at repo root .github/workflows/ (PROJECT_DIR/../../).
    wf_dir='../../.github/workflows'
    if [ ! -d "$wf_dir" ]; then
        fail "QA-004 test-gate: workflows dir $wf_dir not found (path drift?)"
        return
    fi
    if grep -rF -- 'run_dcentrald_tests.sh' "$wf_dir" >/dev/null 2>&1; then
        ref=$(grep -rl -- 'run_dcentrald_tests.sh' "$wf_dir" 2>/dev/null | tr '\n' ' ')
        pass "QA-004 test-gate: run_dcentrald_tests.sh referenced by CI workflow(s): $ref"
    else
        fail "QA-004/QA-009 test-gate: run_dcentrald_tests.sh exists but is NOT referenced by any .github/workflows/* — the musl 'cargo test --no-run' compile-gate never runs in CI (this is how an uncompiled test silently shipped). Add a workflow step that calls it."
    fi
}
test_gate_wired_check

#
# MCP-PROFILE-DRIFT: author-once / emit-twice / VALIDATE durability self-presence.
#
# The Python `:3000` control server (board/{zynq,amlogic}/.../web/mcp_server.py)
# carries a HAND-MIRRORED minimal_profile() dict + WRITE_TOOLS set copied from the
# Rust source of truth dcent-schema::mcp::minimal_profile(). That hand-mirror can
# silently re-drift (the MCP analog of the stale theme.ts the token contract calls
# out). The DURABILITY MECHANISM that closes it is the drift test
# projects/dcent-schema/tests/python_overlay_drift.rs, which drives its assertions
# FROM the Rust registry against BOTH overlay files (token-contract §0,
# UIVIS-RENDER-1, step 3 "does each emission match the contract").
#
# This gate is the self-presence meta-check (same shape as the bip320 ban-gate +
# test_gate_wired self-presence assertions): it proves the drift mechanism itself
# is not silently deleted, that it still include_str!s BOTH overlays and drives
# from the registry, and that the overlays still carry the "MUST stay byte-aligned"
# comment the test makes enforceable. Offline + fail-soft on path drift.
#
mcp_profile_drift_gate_present_check() {
    drift='../dcent-schema/tests/python_overlay_drift.rs'
    if [ ! -f "$drift" ]; then
        # dcent-schema is a sibling crate owned in the same workspace tree;
        # absence here is path drift, not a hard release-blocker for THIS gate.
        pass "MCP-PROFILE-DRIFT: drift test not present at expected sibling path (skipping — sibling crate path drift, not a release blocker)"
        return
    fi
    require_pattern "$drift" 'minimal_profile' \
        'MCP-PROFILE-DRIFT: drift test drives assertions from the Rust minimal_profile() registry'
    require_pattern "$drift" 'board/zynq/rootfs-overlay/root/web/mcp_server.py' \
        'MCP-PROFILE-DRIFT: drift test include_str!s the zynq overlay'
    require_pattern "$drift" 'board/amlogic/rootfs-overlay/root/web/mcp_server.py' \
        'MCP-PROFILE-DRIFT: drift test include_str!s the amlogic overlay (both overlays guarded)'
    require_pattern "$drift" 'WRITE_TOOLS' \
        'MCP-PROFILE-DRIFT: drift test cross-checks the overlay WRITE_TOOLS auth set'

    # The two overlays must keep the byte-alignment comment that the drift test
    # makes enforceable (a removed comment is a sign someone hand-edited the
    # mirror without re-running the gate).
    for ov in br2_external_dcentos/board/zynq/rootfs-overlay/root/web/mcp_server.py \
              br2_external_dcentos/board/amlogic/rootfs-overlay/root/web/mcp_server.py; do
        if [ -f "$ov" ]; then
            require_pattern "$ov" 'byte-aligned with the Rust source of truth' \
                "MCP-PROFILE-DRIFT: overlay keeps the Rust-source-of-truth byte-alignment comment ($ov)"
        else
            pass "MCP-PROFILE-DRIFT: overlay not present at $ov (skipping comment check — path drift)"
        fi
    done
}
mcp_profile_drift_gate_present_check

#
# QA-007: BIP320 rejection-guard ban-gate self-presence assertion.
#
# The actual ban (W6.5-6 bip320_rejection_guard_check, above) greps the four
# BM1362-family share-submit modules for `if ... version_bits_raw != 0 {
# continue }`.  claims this guard is "banned" — this meta-gate makes
# sure the ban gate ITSELF is not silently deleted from this script (a removed
# gate is as bad as a missing one). It asserts the ban function exists and is
# invoked, and that it still keys off the load-bearing identifier + the
# adjacent continue/skip terminator.
#
bip320_bangate_present_check() {
    self="$0"
    [ -f "$self" ] || self="scripts/ci_offline_gates.sh"
    if [ ! -f "$self" ]; then
        fail "QA-007 bip320-bangate: cannot locate this script to self-verify the ban gate"
        return
    fi
    ok=1
    grep -F -- 'bip320_rejection_guard_check()' "$self" >/dev/null 2>&1 || ok=0
    # invoked (a call line that is not the definition)
    grep -E '^bip320_rejection_guard_check[[:space:]]*$' "$self" >/dev/null 2>&1 || ok=0
    # still keys off the banned identifier + a continue/skip terminator
    grep -F -- 'version_bits_raw' "$self" >/dev/null 2>&1 || ok=0
    grep -F -- 'continue' "$self" >/dev/null 2>&1 || ok=0
    if [ "$ok" -eq 1 ]; then
        pass "QA-007 bip320-bangate: the version_bits_raw!=0 rejection-guard ban gate is present + invoked (W6.5-6)"
    else
        fail "QA-007 bip320-bangate: the BIP320 rejection-guard ban gate (bip320_rejection_guard_check) is missing, not invoked, or no longer keys off 'version_bits_raw'/'continue' — restore it (load-bearing per feedback_am2_serial_dispatch_bip320_version_rolling_required.md)"
    fi
}
bip320_bangate_present_check

bip320_bangate_negative_control_check() {
    require_file 'scripts/test_bip320_bangate_negative_control.sh'
    if [ -f 'scripts/test_bip320_bangate_negative_control.sh' ]; then
        if sh 'scripts/test_bip320_bangate_negative_control.sh' >/dev/null 2>&1; then
            pass "QA-007 bip320-bangate: negative-control fixtures trip the real ban gate"
        else
            fail "QA-007 bip320-bangate: negative-control fixtures did NOT trip the real ban gate"
        fi
    fi
}
bip320_bangate_negative_control_check

#
# QA-006: home-safety fan cap. Every devmem PWM write in every S82dcentrald
# overlay (and any other init script that writes the FAN_BASE PWM registers
# 0x10 / 0x14) MUST command PWM <= 30. The form is:
#     devmem $((FAN_BASE + 0x10)) 32 <PWM>
# where `32` is the access width and <PWM> is the value. The PWM-30 home cap
# is a load-bearing safety contract (cut-hash-before-noise; never blast fans
# on a home/space-heater unit). This gate scans every overlay so a future
# edit can't reintroduce a 60-PWM transient spin-up via devmem.
#
fan_pwm_cap_check() {
    bad=''
    scanned=0
    # All init scripts in every board overlay (not just S82dcentrald — catch
    # any script that pokes the FAN_BASE PWM registers directly).
    for f in br2_external_dcentos/board/*/rootfs-overlay/etc/init.d/* \
             br2_external_dcentos/board/*/*/rootfs-overlay/etc/init.d/*; do
        [ -f "$f" ] || continue
        # Only consider files that write a FAN_BASE PWM register via devmem.
        grep -E 'devmem[[:space:]]+\$\(\(FAN_BASE[[:space:]]*\+[[:space:]]*0x1[04]\)\)[[:space:]]+32[[:space:]]+[0-9]+' \
            "$f" >/dev/null 2>&1 || continue
        scanned=$((scanned + 1))
        # Extract every PWM value written to 0x10/0x14 and check it is <= 30.
        # awk on the devmem line: the value is the field after the `32` width.
        offending=$(grep -E 'devmem[[:space:]]+\$\(\(FAN_BASE[[:space:]]*\+[[:space:]]*0x1[04]\)\)[[:space:]]+32[[:space:]]+[0-9]+' "$f" 2>/dev/null \
            | awk '{
                for (i = 1; i <= NF; i++) {
                    if ($i == "32" && (i + 1) <= NF && $(i+1) ~ /^[0-9]+$/) {
                        if ($(i+1) + 0 > 30) { print }
                    }
                }
            }')
        if [ -n "$offending" ]; then
            bad="$bad
$f:
$offending"
        fi
    done
    if [ "$scanned" -eq 0 ]; then
        fail "QA-006 fan-pwm-cap: no overlay init script writes the FAN_BASE PWM registers via devmem (path drift?)"
    elif [ -n "$bad" ]; then
        fail "QA-006 fan-pwm-cap: devmem PWM write > 30 found (regression of the PWM-30 home-safety cap; cut-hash-before-noise):$bad"
    else
        pass "QA-006 fan-pwm-cap: all devmem FAN_BASE PWM writes <= 30 across $scanned overlay init scripts"
    fi
}
fan_pwm_cap_check

# DESK_NOW rank 10 (2026-08-19): shipped overlay + example dcentrald*.toml
# under DCENT_OS_Antminer must keep home-quiet fan_max_pwm <= 30. Comment
# assignments are ignored. docs/dev live-session tomls and historical
# live448 capture tomls are out of scope (they live outside this tree or
# are path-excluded). Overlay-devmem PWM-30 (QA-006) does not catch a
# shipped TOML that sets fan_max_pwm = 127.
fan_max_pwm_toml_check() {
    bad=''
    scanned=0
    for root in br2_external_dcentos dcentrald configs etc; do
        [ -d "$root" ] || continue
        for f in $(find "$root" -type f -name 'dcentrald*.toml' \
            ! -path '*live448*' \
            ! -path '*/docs/*' \
            ! -path '*/target/*' \
            ! -path '*/target-*/*' \
            2>/dev/null | sort); do
            [ -f "$f" ] || continue
            scanned=$((scanned + 1))
            offender=$(awk '
                /^[[:space:]]*#/ { next }
                /^[[:space:]]*fan_max_pwm[[:space:]]*=/ {
                    n = $0
                    sub(/^[^=]*=[[:space:]]*/, "", n)
                    sub(/[^0-9].*/, "", n)
                    if (n == "" || n + 0 > 30) print
                }
            ' "$f" || true)
            if [ -n "$offender" ]; then
                bad="$bad
$f:
$offender"
            fi
        done
    done
    if [ "$scanned" -eq 0 ]; then
        fail "PWM TOML grep: no shipped overlay/example dcentrald*.toml found (path drift?)"
    elif [ -n "$bad" ]; then
        fail "PWM TOML grep: shipped overlay/example dcentrald*.toml has fan_max_pwm > 30 (home-quiet is PWM-30):$bad"
    else
        pass "PWM TOML grep: all $scanned shipped overlay/example dcentrald*.toml keep fan_max_pwm <= 30"
    fi
}
fan_max_pwm_toml_check

#
# QA-002: BM1387 MiscCtrl triple-write source-parse pin. After a temp read,
# `disable_i2c_on_chip0()` MUST write MiscCtrl 0x4020_0180 exactly 3 times
# with 5 ms delays — CMD-register readback is impossible on BM1387, so the
# triple-write is the ONLY reliable way to take chip 0 out of I2C-passthrough
# mode (root cause of the 75 s zero-nonce stall). This is a grep/parse gate
# (per RE-007/QA-002 scope: do NOT edit the Rust). It asserts the loop count
# (0..3) + the 5 ms delay + the constant are all still present.
#
bm1387_misc_ctrl_triple_write_check() {
    f='dcentrald/dcentrald-asic/src/drivers/bm1387.rs'
    pure='dcentrald/dcentrald-common/src/chain_transport.rs'
    if [ ! -f "$f" ]; then
        fail "QA-002 bm1387-triple-write: missing $f (path drift?)"
        return
    fi
    ok=1
    why=''
    # Preferred: pure cadence SSOT (plan_bm1387_misc_ctrl_i2c_off_chip0) + value/reg pins.
    if grep -E 'plan_bm1387_misc_ctrl_i2c_off_chip0' "$f" >/dev/null 2>&1 \
        && grep -E '0x4020[_]?0180' "$f" >/dev/null 2>&1 \
        && [ -f "$pure" ] \
        && grep -E 'MISC_CTRL_REG_BM1387|0x1[Cc]' "$pure" >/dev/null 2>&1 \
        && grep -E 'BM1387_MISC_CTRL_I2C_OFF_MINING|0x4020[_]?0180' "$pure" >/dev/null 2>&1 \
        && grep -E 'MISC_CTRL_TRIPLE_WRITE_COUNT|for _ in 0\.\.MISC_CTRL_TRIPLE_WRITE_COUNT' "$pure" >/dev/null 2>&1; then
        pass "QA-002 bm1387-triple-write: disable_i2c_on_chip0 consumes pure plan (0x4020_0180 @ 0x1C ×3 / 5ms SSOT)"
        return
    fi
    # Legacy open-coded loop (pre-pure-plan) still accepted.
    if ! grep -E 'for[[:space:]]+_[[:space:]]+in[[:space:]]+0\.\.3' "$f" >/dev/null 2>&1; then
        ok=0; why="$why [missing pure plan consume OR 'for _ in 0..3' triple-write loop]"
    fi
    if ! grep -E 'from_millis\([[:space:]]*5[[:space:]]*\)' "$f" >/dev/null 2>&1; then
        ok=0; why="$why [missing 5ms inter-write delay]"
    fi
    if ! grep -E '0x4020[_]?0180' "$f" >/dev/null 2>&1; then
        ok=0; why="$why [missing MiscCtrl 0x4020_0180 constant]"
    fi
    if [ "$ok" -eq 1 ]; then
        pass "QA-002 bm1387-triple-write: disable_i2c_on_chip0 still writes MiscCtrl 0x4020_0180 3x with 5ms delays"
    else
        fail "QA-002 bm1387-triple-write: BM1387 MiscCtrl triple-write contract regressed in $f:$why (CMD readback is impossible on BM1387; triple-write is the only safety net — root cause of the 75s zero-nonce stall)"
    fi
}
bm1387_misc_ctrl_triple_write_check

#
# RE-007 (safety): the BM1373 (S23) and BM1489 (L7/L9 scrypt) chip drivers are
# UNCONFIRMED, RE-inferred SCAFFOLDS — every register value is a projection
# from a sibling chip, NOT verified on live hardware. They MUST NOT silently
# run on a live unit. The intended runtime contract is a second confirmation
# gate (DCENT_CONFIRM_SCAFFOLD_ON_LIVE_HW) before any scaffold driver touches
# real hardware. This gate enforces the source-side invariant that backstops
# that contract: each scaffold driver's `init_chain` MUST fail closed (return
# an Err), so a scaffold can never bring up a chain without an explicit code
# change AND the operator's confirmation. It also records the required env-gate
# name so a future agent wiring the live path knows what to add.
#
# (Scope note: this is a CI/grep check per the RE-007 task framing. The Rust
# is owned by other groups; this gate documents + enforces the contract, it
# does not edit the drivers.)
#
scaffold_driver_fail_closed_check() {
    # Required runtime confirmation gate name (documented contract for the
    # future live-bring-up path — DO NOT remove without wiring it in Rust).
    required_gate='DCENT_CONFIRM_SCAFFOLD_ON_LIVE_HW'
    for f in dcentrald/dcentrald-asic/src/drivers/bm1373.rs \
             dcentrald/dcentrald-asic/src/drivers/bm1489.rs \
             dcentrald/dcentrald-asic/src/drivers/bm1491.rs; do
        if [ ! -f "$f" ]; then
            fail "RE-007 scaffold-fail-closed: missing $f (path drift?)"
            continue
        fi
        # The scaffold must (a) declare itself a SCAFFOLD and (b) its
        # init_chain must return an Err (fail-closed: it cannot bring up live
        # hardware). We assert the SCAFFOLD marker + the fail-closed Err
        # construction both exist in the file.
        if ! grep -F -- 'SCAFFOLD' "$f" >/dev/null 2>&1; then
            fail "RE-007 scaffold-fail-closed: $f no longer self-identifies as a SCAFFOLD (was it promoted without live verification?)"
            continue
        fi
        # Fail-closed evidence: an InvalidParameter Err that names the scaffold
        # refusal. Both drivers construct
        # `AsicError::InvalidParameter("... scaffold ...".into())` in init_chain.
        if grep -E 'InvalidParameter' "$f" >/dev/null 2>&1 \
            && grep -iE 'scaffold|cannot init|verified register' "$f" >/dev/null 2>&1; then
            pass "RE-007 scaffold-fail-closed: $(basename "$f") fails closed (scaffold init refuses to bring up live hardware)"
        else
            fail "RE-007 scaffold-fail-closed: $f scaffold no longer fails closed — its init_chain must return an Err so it cannot run on live hw without an explicit code change + the $required_gate operator confirmation"
        fi
    done
}
scaffold_driver_fail_closed_check

#
# CI-GATE-STALE-BINARY: build_in_docker.sh stages prebuilt Rust binaries and
# does not recompile them. Snapshot-consistency receipts, rather than mutable
# mtimes, detect local binary/source/context drift without claiming that the
# receipt attests a compiler execution. Phase 0 exports one detached private
# generation and Phase 5 must never reopen the mutable host target tree.
#
stale_binary_guard_check() {
    f='scripts/build_in_docker.sh'
    require_file "$f"
    require_pattern "$f" 'dcent_required_prebuilt_binaries' \
        'CI-GATE-STALE-BINARY: build_in_docker enumerates all required staged binaries'
    require_pattern "$f" 'export-snapshot-set' \
        'CI-GATE-STALE-BINARY: Phase 0 captures a private snapshot-consistent binary set'
    require_pattern "$f" 'query-export-snapshot-path' \
        'CI-GATE-STALE-BINARY: host resolves helper-verified canonical export paths'
    require_pattern "$f" '--field path-sha256' \
        'CI-GATE-STALE-BINARY: host atomically queries verified paths and digests for Phase 5'
    require_pattern "$f" 'destination digest mismatch' \
        'CI-GATE-STALE-BINARY: Phase 5 proves destination bytes equal the verified export'
    reject_pattern "$f" 'RECEIPT_HELPER=/build/dcentos/scripts/binary_build_receipt.py' \
        'CI-GATE-STALE-BINARY: Phase 5 does not trust the mutable recopied helper'
    require_pattern "$f" 'export-snapshot-capability-path' \
        'CI-GATE-STALE-BINARY: packaging retains the out-of-stage destruction capability'
    require_pattern "$f" 'destroy-export-snapshot-set' \
        'CI-GATE-STALE-BINARY: cleanup destroys the detached binary set'
    require_pattern "$f" '--capability "$BINARY_EXPORT_CAPABILITY"' \
        'CI-GATE-STALE-BINARY: detached-set cleanup is capability-authorized'
    require_pattern "$f" '-v "${DOCKER_BINARY_EXPORT_STAGE}:/dcent-binaries:ro"' \
        'CI-GATE-STALE-BINARY: Phase 5 receives the private export through a comma-safe read-only mount'
    require_pattern "$f" 'ALL_PREBUILT_BINARIES="dcentrald dcentos-init dcentos-discovery pic-recovery dspic-flash"' \
        'CI-GATE-STALE-BINARY: warm volume purges shipped and historical recovery binary generations'
    require_pattern "$f" 'unsafe persistent binary staging component' \
        'CI-GATE-STALE-BINARY: persistent release path rejects symlink components'
    require_pattern "$f" '"$BUILD_CONTAINER_ID" bash -c' \
        'CI-GATE-STALE-BINARY: post-inspection Docker work runs the immutable image ID'
    reject_pattern "$f" '${POSIX_PROJECT_DIR}/dcentrald/target:/target:ro' \
        'CI-GATE-STALE-BINARY: mutable host Rust target tree is not mounted for packaging'
    require_pattern "$f" 'check-override-policy' \
        'CI-GATE-STALE-BINARY: release-context stale override policy stays enforced'
    require_pattern 'scripts/build-dcentrald.sh' 'emit_build_receipts' \
        'CI-GATE-STALE-BINARY: Rust build emits receipts for staged binaries'
    require_pattern 'scripts/build-dcentrald.sh' '--binary "$receipt_release_dir/dcentrald"' \
        'CI-GATE-STALE-BINARY: dcentrald receipt is emitted'
    require_pattern 'scripts/build-dcentrald.sh' '--binary "$receipt_release_dir/dcentos-init"' \
        'CI-GATE-STALE-BINARY: dcentos-init receipt is emitted'
    require_pattern 'scripts/build-dcentrald.sh' '--binary "$receipt_release_dir/dcentos-discovery"' \
        'CI-GATE-STALE-BINARY: dcentos-discovery receipt is emitted'
    require_pattern 'scripts/build_cv1835_s19jpro.sh' 'exit 78' \
        'CI-GATE-STALE-BINARY: CV1835 standalone build entry point refuses before consuming binaries'
    require_pattern "$f" '--source-workspace DCENT_OS_Antminer/dcentrald' \
        'CI-GATE-STALE-BINARY: receipt inventory is rooted in the authenticated snapshot workspace'
    require_pattern 'scripts/binary_build_receipt.py' 'exact-git-object-snapshot' \
        'CI-GATE-STALE-BINARY: v4 receipts distinguish immutable source from live worktree state'
    if python3 - <<'PY'
import runpy

namespace = runpy.run_path("scripts/binary_build_receipt.py", run_name="ci_receipt_constants")
expected = (
    "declared-release-capsule-and-post-build-snapshot-consistency-"
    "not-build-causality-or-reproducibility-proof"
)
raise SystemExit(0 if namespace.get("RECEIPT_CLAIM_V4") == expected else 1)
PY
    then
        pass 'CI-GATE-STALE-BINARY: v4 capsule receipt claims neither build causality nor reproducibility proof'
    else
        fail 'CI-GATE-STALE-BINARY: v4 capsule receipt semantic claim regressed'
    fi
    require_pattern 'scripts/binary_build_receipt.py' 'is forbidden in release provenance/status/image mode' \
        'CI-GATE-STALE-BINARY: receipt bypass is categorically rejected for releases'
    require_pattern 'scripts/binary_build_receipt.py' 'it does not bypass snapshot/export validation' \
        'CI-GATE-STALE-BINARY: deprecated lab signal grants no immutable-boundary bypass'
    require_file 'scripts/test_binary_build_receipt.sh'
    require_file 'scripts/test_binary_export_phase5.sh'
    require_pattern 'br2_external_dcentos/board/zynq/post-build.sh' 'ERROR: dcentos-init not found' \
        'CI-GATE-STALE-BINARY: zynq post-build fails when dcentos-init is absent'
    require_pattern 'br2_external_dcentos/board/zynq/am2-s19jpro/post-build.sh' 'ERROR: dcentos-init not found' \
        'CI-GATE-STALE-BINARY: am2-s19jpro post-build fails when dcentos-init is absent'
    require_pattern 'br2_external_dcentos/board/zynq/post-build.sh' 'dcentos-init.sha256' \
        'CI-GATE-STALE-BINARY: zynq image stamps dcentos-init sha256'
    require_pattern 'br2_external_dcentos/board/zynq/am2-s19jpro/post-build.sh' 'dcentos-init.sha256' \
        'CI-GATE-STALE-BINARY: am2-s19jpro image stamps dcentos-init sha256'
    if sh scripts/test_binary_build_receipt.sh >/dev/null 2>&1; then
        pass "CI-GATE-STALE-BINARY: receipt suite rejects binary, source, context, and release-bypass drift"
    else
        fail "CI-GATE-STALE-BINARY: binary receipt adversarial suite failed"
    fi
    if bash scripts/test_binary_export_phase5.sh >/dev/null 2>&1; then
        pass "CI-GATE-STALE-BINARY: immutable Phase 0 to Phase 5 route and source pin hold"
    else
        fail "CI-GATE-STALE-BINARY: immutable Phase 5 binary export boundary failed"
    fi
}
stale_binary_guard_check

#
# CI-GATE-OTA-PRESERVE (RELIAB-1): the A/B self-update sysupgrade overlays MUST
# copy /data/dcent (dashboard auth.json password, onboarding.json,
# authorized_keys, .ssh-enabled) into the inactive slot. Before RELIAB-1 they
# synced /data/{keys,config,profiles,dcentrald.toml} but NOT /data/dcent, so
# every self-update wiped the operator's password/onboarding/SSH on the new slot
# (wizard re-triggered, SSH disabled). Both gating-platform (zynq) overlays must
# keep the `cp -a /data/dcent/.` preservation.
#
ota_preserve_data_dcent_check() {
    # The typed persistent-state architecture (2026-08 sysupgrade helper split)
    # preserves /data/dcent (dashboard auth.json, onboarding.json,
    # authorized_keys, .ssh-enabled) via `dcent_persist_stage`, not a literal
    # `cp -a /data/dcent/.` line. Keep the gate at operative-line strength:
    # the updater must make the operative stage call, and the shared helper's
    # staging list must include `dcent` (with its mode-admission branch).
    require_pattern \
        'br2_external_dcentos/board/zynq/rootfs-overlay/usr/sbin/sysupgrade' \
        'dcent_persist_stage "$PERSIST_SOURCE_ROOT" "$PERSIST_MOUNT_ROOT"' \
        'CI-GATE-OTA-PRESERVE (RELIAB-1): zynq base sysupgrade preserves /data/dcent (password/onboarding/SSH) across A/B self-update'
    require_pattern \
        'br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/usr/sbin/sysupgrade' \
        'dcent_persist_stage "$PERSIST_SOURCE_ROOT" "$PERSIST_MOUNT_ROOT"' \
        'CI-GATE-OTA-PRESERVE (RELIAB-1): zynq am2-s19jpro sysupgrade preserves /data/dcent (password/onboarding/SSH) across A/B self-update'
    require_pattern \
        'br2_external_dcentos/board/zynq/rootfs-overlay/usr/libexec/dcentos/sysupgrade-persistent-state.sh' \
        'for _dcent_name in config profiles dcent' \
        'CI-GATE-OTA-PRESERVE (RELIAB-1): typed persistent-state helper stages /data/dcent with the operator credential set'
    require_pattern \
        'br2_external_dcentos/board/zynq/rootfs-overlay/usr/libexec/dcentos/sysupgrade-persistent-state.sh' \
        'dcent_persist_require_mode "$_dcent_source/dcent" 700' \
        'CI-GATE-OTA-PRESERVE (RELIAB-1): typed persistent-state helper admits only a hardened /data/dcent source'
}
ota_preserve_data_dcent_check

#
# CI-GATE-CVITEK-S99UPGRADE-SHADOW: the unadmitted CV1835 scaffold historically
# inherited Amlogic NAND/environment behavior. Keep a same-name negative
# authority so direct assembly, a synthetic merge, or warm-build residue cannot
# reopen that brick vector. The supported build hooks refuse before assembly.
#
cvitek_retired_overlay_check() {
    f='br2_external_dcentos/board/cvitek/cv1835-s19jpro'
    if [ ! -e "$f" ] && [ ! -L "$f" ]; then
        pass 'CI-GATE-CVITEK-RETIRED: orphan board overlay is absent'
    else
        fail 'CI-GATE-CVITEK-RETIRED: orphan board overlay was reintroduced'
    fi
}
cvitek_retired_overlay_check

#
# CI-GATE-CVITEK-BRICK-VECTOR-RETIREMENT: held CV1835 U-Boot fingerprints use
# a built-in volatile environment, not a persistent MMC environment. The p2
# content marker is an observed selector, but no crash-safe transition or
# rollback contract has been reconstructed. Every historical build, update,
# recovery, and restore entry point must therefore fail closed.
#
cv1835_brick_vector_retirement_check() {
    tag='CI-GATE-CVITEK-BRICK-VECTOR-RETIREMENT'
    test_script='scripts/test_cv1835_brick_vector_retirement.sh'
    builder='scripts/build_cv1835_s19jpro.sh'
    consumer='scripts/safe_sysupgrade_cv_emmc.sh'
    revert='scripts/revert_to_stock_cv1835.sh'
    fw_env='br2_external_dcentos/board/cvitek/cv1835-s19jpro/rootfs-overlay/etc/fw_env.config'

    require_file "$test_script"
    require_file "$builder"
    require_file "$consumer"
    require_file "$revert"
    require_pattern "$builder" 'exit 78' \
        "$tag: standalone build entry point refuses every artifact lane"
    require_pattern "$consumer" 'exit 78' \
        "$tag: updater exits with an unconditional unavailable status"
    require_pattern "$revert" 'exit 78' \
        "$tag: stock-revert entrypoint exits with an unconditional unavailable status"
    require_pattern "$consumer" 'BuiltInVolatile/mutation-denied' \
        "$tag: updater records the evidenced environment backend"
    reject_pattern "$consumer" 'DCENT_ALLOW_UNSIGNED_SYSUPGRADE' \
        "$tag: updater has no override path"
    require_pattern 'scripts/build_in_docker.sh' \
        'cv1835-s19jpro has no firmware, sysupgrade, or supported artifact build lane' \
        "$tag: generic build driver refuses the evidence-only target"
    reject_pattern 'scripts/firmware_release_name.sh' \
        'cv1835-s19jpro.*stem=' \
        "$tag: firmware naming cannot mint a release-looking CV1835 alias"
    if [ ! -e "$fw_env" ] && [ ! -L "$fw_env" ]; then
        pass "$tag: guessed CV1835 fw_env.config remains absent"
    else
        fail "$tag: guessed CV1835 fw_env.config was reintroduced"
    fi

    if [ "$STATIC_ONLY" -eq 0 ]; then
        if sh "$test_script" >/dev/null 2>&1; then
            pass "$tag: executable retirement contract passed"
        else
            fail "$tag: executable retirement contract failed"
        fi
    fi
}
cv1835_brick_vector_retirement_check

#
# CI-GATE-AM3BB-SIGNED-SIDECARS (CE-204): the AM3-BB (BeagleBone) SD/package
# builds must emit the canonical Ed25519 sidecars (MANIFEST.json + MANIFEST.sig
# + release_ed25519.pub + SHA256SUMS) exactly like the zynq sysupgrade path — but
# as a deliberately NOT-NAND-installable "sdcard_payload" (nand_install:false), so
# the AM3-BB NAND-disabled honesty is preserved. Producer side: both am3-bb
# post-image.sh source the shared signing helper and run
# stage->write(sdcard_payload)->sign; both post-build.sh stage the pinned pubkey.
# Raw diagnostic/VNish prototype images remain outside release authority. The SD
# payload must NEVER call the sysupgrade manifest writer or self-set the unsigned
# lab escape.
#
am3_bb_signed_sidecars_check() {
    tag='CI-GATE-AM3BB-SIGNED-SIDECARS'
    lib='scripts/lib/sysupgrade_package_common.sh'
    pi_base='br2_external_dcentos/board/beaglebone/am3-bb/post-image.sh'
    pi_s19='br2_external_dcentos/board/beaglebone/am3-bb-s19jpro/post-image.sh'
    pb_base='br2_external_dcentos/board/beaglebone/am3-bb/post-build.sh'
    pb_s19='br2_external_dcentos/board/beaglebone/am3-bb-s19jpro/post-build.sh'
    disk_builder='scripts/build_am3_bb_sd_disk_image.sh'
    vnish_builder='scripts/build_am3_bb_sd_vnish_bootbin_image.sh'

    require_pattern "$lib" 'dcent_write_sdcard_payload_manifest' \
        "$tag LIB: shared helper defines the sdcard_payload manifest writer"
    require_pattern "$lib" '"package_type": "sdcard_payload"' \
        "$tag LIB: sdcard payload manifest is package_type sdcard_payload (not sysupgrade)"
    require_pattern "$lib" '"nand_install": false' \
        "$tag LIB: sdcard payload manifest declares nand_install false"

    for pi in "$pi_base" "$pi_s19"; do
        name=$(basename "$(dirname "$pi")")
        require_pattern "$pi" 'sysupgrade_package_common.sh' \
            "$tag PRODUCER [$name]: post-image sources the shared signing helper"
        require_pattern "$pi" 'dcent_stage_release_key' \
            "$tag PRODUCER [$name]: post-image stages release_ed25519.pub via the shared helper"
        require_pattern "$pi" 'dcent_write_sdcard_payload_manifest' \
            "$tag PRODUCER [$name]: post-image writes the sdcard_payload manifest"
        require_pattern "$pi" 'dcent_sign_sysupgrade_manifest' \
            "$tag PRODUCER [$name]: post-image signs MANIFEST.json (emits MANIFEST.sig)"
        require_pattern "$pi" 'sdcard_payload' \
            "$tag PRODUCER [$name]: post-image ties into the sdcard_payload schema"
        # NEGATIVE: the SD payload must never claim the sysupgrade/NAND schema and
        # the producer must never self-set the unsigned lab escape.
        reject_pattern "$pi" 'dcent_write_sysupgrade_manifest' \
            "$tag NEGATIVE [$name]: SD payload never claims the sysupgrade/NAND-installable schema"
        reject_pattern "$pi" 'DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1' \
            "$tag NEGATIVE [$name]: producer never self-sets the unsigned lab escape"
    done

    for pb in "$pb_base" "$pb_s19"; do
        name=$(basename "$(dirname "$pb")")
        require_pattern "$pb" 'etc/dcentos/release_ed25519.pub' \
            "$tag POST-BUILD [$name]: stages the pinned release_ed25519.pub into the rootfs"
        require_pattern "$pb" 'DCENT_RELEASE_PUBKEY_FILE' \
            "$tag POST-BUILD [$name]: embeds the trusted release pubkey from DCENT_RELEASE_PUBKEY_FILE"
    done

    require_pattern "$disk_builder" 'must never receive a release-authority signature' \
        "$tag BUILDER: bootloop diagnostic remains outside release authority"
    require_pattern "$vnish_builder" 'not eligible for DCENT_OS release signing' \
        "$tag BUILDER: open-gate VNish prototype remains outside release authority"
    require_pattern "$vnish_builder" 'mcopy readback failed; refusing an unverified image' \
        "$tag BUILDER: VNish completeness requires successful image readback"
    reject_pattern "$vnish_builder" 'release_ed25519.pub' \
        "$tag BUILDER: VNish prototype cannot ship a mutable pubkey sidecar"

    # FUNCTIONAL leg (mirrors the pre_flash Ed25519 gate; skipped gracefully
    # without openssl): stage->write->sign a fixture SD payload against a throwaway
    # keypair and assert MANIFEST.sig verifies against the staged pinned pubkey.
    if [ ! -f "$lib" ]; then
        return
    fi
    if command -v openssl >/dev/null 2>&1; then
        tmpdir=$(mktemp -d 2>/dev/null || echo "/tmp/dcentos-ce204-selftest.$$")
        rm -rf "$tmpdir"
        mkdir -p "$tmpdir/payload"
        if openssl genpkey -algorithm Ed25519 -out "$tmpdir/release.key" >/dev/null 2>&1 \
            && openssl pkey -in "$tmpdir/release.key" -pubout -out "$tmpdir/release.pub" >/dev/null 2>&1; then
            if [ "$(run_python_script -c 'import os; print(os.name)')" = nt ]; then
                run_python_script - "$SCRIPT_DIR" "$tmpdir/release.key" <<'PY'
from pathlib import Path
import sys

sys.path.insert(0, sys.argv[1])
import release_set_publication as release_io

release_io.set_windows_file_acl(
    Path(sys.argv[2]), release_io.WINDOWS_PRIVATE_FILE_SDDL
)
PY
            fi
            printf 'payload\n' > "$tmpdir/payload/uramdisk.image.gz"
            p_sha=$(sha256sum "$tmpdir/payload/uramdisk.image.gz" | awk '{print $1}')
            p_size=$(wc -c < "$tmpdir/payload/uramdisk.image.gz" | tr -d ' ')
            payload_block="
    \"uramdisk.image.gz\": {
      \"path\": \"dcentos-am3-bb-sdcard/uramdisk.image.gz\",
      \"size\": ${p_size},
      \"sha256\": \"${p_sha}\"
    }"
            # POSITIVE: a provenance-bound, release-image-hardened SD payload
            # may use release-root authority even though nand_install stays false.
            if (
                . "$lib"
                SUP_DIR="$tmpdir/payload"
                BOARD_NAME="am3-bb"
                BOARD_FAMILY="am3-bb"
                PACKAGE_VERSION="test"
                DCENT_SDCARD_TAR_PREFIX="dcentos-am3-bb-sdcard"
                DCENT_SDCARD_PAYLOAD_BLOCK="$payload_block"
                DCENT_PACKAGE_STATUS="release"
                DCENT_RELEASE_IMAGE=1
                DCENT_REQUIRE_RELEASE_PROVENANCE=1
                DCENT_RELEASE_SIGNING_KEY="$tmpdir/release.key"
                DCENT_RELEASE_PUBKEY_FILE="$tmpdir/release.pub"
                PROJECT_ROOT="$PROJECT_DIR"
                SOURCE_DATE_EPOCH=1700000000
                DCENT_SOURCE_COMMIT_EPOCH=1700000000
                DCENT_SOURCE_COMMIT="0123456789abcdef0123456789abcdef01234567"
                DCENT_SOURCE_TREE_STATE="clean"
                DCENT_BUILD_TARGET="am3-bb"
                DCENT_BUILD_ARCH="armv7"
                DCENT_TOOLCHAIN_ID="ci-fixture"
                dcent_stage_release_key
                dcent_write_sdcard_payload_manifest
                dcent_sign_sysupgrade_manifest
            ) >/dev/null 2>&1 \
                && [ -f "$tmpdir/payload/MANIFEST.sig" ] \
                && [ -f "$tmpdir/payload/release_ed25519.pub" ] \
                && openssl pkeyutl -verify -rawin -pubin \
                    -inkey "$tmpdir/payload/release_ed25519.pub" \
                    -sigfile "$tmpdir/payload/MANIFEST.sig" \
                    -in "$tmpdir/payload/MANIFEST.json" >/dev/null 2>&1; then
                pass "$tag FUNCTIONAL: stage->write->sign emits MANIFEST.sig that verifies against the staged pinned pubkey"
            else
                fail "$tag FUNCTIONAL: signed SD-payload sidecar generation/verification failed"
            fi

            # NEGATIVE A: no key + release status must fail closed.
            if (
                . "$lib"
                SUP_DIR="$tmpdir/neg-a"
                mkdir -p "$SUP_DIR"
                DCENT_PACKAGE_STATUS="release"
                dcent_stage_release_key
            ) >/dev/null 2>&1; then
                fail "$tag FUNCTIONAL NEGATIVE: unsigned release SD payload was NOT refused"
            else
                pass "$tag FUNCTIONAL NEGATIVE: unsigned release-status SD payload fails closed"
            fi

            # NEGATIVE B: no key + non-release status without the explicit lab
            # override must also fail closed.
            if (
                . "$lib"
                SUP_DIR="$tmpdir/neg-b"
                mkdir -p "$SUP_DIR"
                DCENT_PACKAGE_STATUS="management_bringup_sdcard_only"
                dcent_stage_release_key
            ) >/dev/null 2>&1; then
                fail "$tag FUNCTIONAL NEGATIVE: unsigned SD payload accepted without DCENT_ALLOW_UNSIGNED_SYSUPGRADE"
            else
                pass "$tag FUNCTIONAL NEGATIVE: unsigned lab SD payload requires explicit DCENT_ALLOW_UNSIGNED_SYSUPGRADE"
            fi
        else
            fail "$tag FUNCTIONAL: openssl Ed25519 keygen failed in the gate harness"
        fi
        rm -rf "$tmpdir"
    else
        pass "$tag FUNCTIONAL: openssl unavailable — signature legs skipped (pattern legs still enforced)"
    fi
}
am3_bb_signed_sidecars_check

#
# CI-GATE-COMMIT-AUTHORITY (CE-021): pin the already-normalized install/recovery
# COMMIT-AUTHORITY design so it cannot silently drift. Each platform's on-target
# commit mechanism is deliberate and per-platform live-tested; this gate is
# ENFORCEMENT-ONLY and changes NO boot behavior — it just fails closed if a
# future edit blurs the boundaries:
#
#   1. SHADOWS-STAY-NOOP   - the two beaglebone S99upgrade readiness shadows do
#      NO NAND/flash/env write (comment-stripped token scan; any non-comment hit
#      fails).
#   2. MARKER-PARITY       - the boot-success marker literal
#      /tmp/dcentos-upgrade-committed is present in BOTH the zynq S99upgrade (the
#      SOLE health-gated commit authority: bare-delete `fw_setenv upgrade_stage`)
#      and the zynq S99verify (which defers to that marker).
#   3. AMLOGIC-FAIL-CLOSED - amlogic S99upgrade keeps its platform-mandated raw-
#      NAND recovery-flag commit (commit_recovery_flag + the 0x03 readback-
#      mismatch fail path + replay_pending_env_clear WAL replay + the fw_setenv-
#      missing `return 1` in clear_uboot_env) and NEVER grows a zynq-style
#      upgrade_stage commit.
#   4. OTA-08-CONTAINMENT  - a command-position flash_erase/nandwrite appears in
#      NO etc/init.d/S99upgrade EXCEPT the amlogic copy (the documented OTA-08
#      raw-NAND exception); zynq stays fw_setenv-only. Command-position, NOT the
#      bare-token scan: the zynq S99upgrade carries a load-bearing
#      `echo "... DO NOT raw-nandwrite ..."` warning STRING that is documentation,
#      not a write — a bare-token comment-stripped scan would false-positive on it.
#   5. STAGING-NEVER-COMMITS - the 4 zynq sysupgrade overlays STAGE via
#      upgrade_stage=0 and NEVER bare-delete/commit upgrade_stage (that health-
#      gated commit is S99upgrade's sole authority).
#   6. HOST-ONLY-TRANSFORMERS - raw switch_firmware.{sh,py} environment-image
#      transformers remain available for offline forensics, refuse without an
#      explicit acknowledgement, and cannot land in a target overlay/rootfs.
#
commit_authority_normalization_check() {
    tag='CI-GATE-COMMIT-AUTHORITY'
    base='br2_external_dcentos/board'

    zynq_s99up="$base/zynq/rootfs-overlay/etc/init.d/S99upgrade"
    zynq_s99ver="$base/zynq/rootfs-overlay/etc/init.d/S99verify"
    aml_s99up="$base/amlogic/rootfs-overlay/etc/init.d/S99upgrade"
    bb_shadow_a="$base/beaglebone/am3-bb/rootfs-overlay/etc/init.d/S99upgrade"
    bb_shadow_b="$base/beaglebone/am3-bb-s19jpro/rootfs-overlay/etc/init.d/S99upgrade"
    sw_target_sh="$base/zynq/rootfs-overlay/usr/sbin/switch_firmware.sh"
    sw_target_py="$base/zynq/rootfs-overlay/usr/sbin/switch_firmware.py"
    sw_host_sh='scripts/switch_firmware.sh'
    sw_host_py='scripts/switch_firmware.py'
    runtime_prune="$base/common/prune-runtime-research-tools.sh"

    # Comment-stripped token scan (shared shell token-scan idiom):
    # strip grep's "N:" line-number prefix + leading whitespace, drop comment-only
    # lines, print any remaining match. $1=file, $2=ERE.
    _ca_noncomment_hits() {
        grep -nE "$2" "$1" 2>/dev/null \
            | awk '{
                line=$0
                sub(/^[0-9]+:/, "", line)
                sub(/^[[:space:]]+/, "", line)
                if (line ~ /^#/) next
                print
            }' || true
    }

    # 1. SHADOWS-STAY-NOOP — both beaglebone shadows must perform no NAND/flash/env
    #    write. Bare-token comment-stripped scan (the /dev/nand_env in the am3-bb
    #    header comment is stripped by the ^# skip).
    shadow_ok=1
    for f in "$bb_shadow_a" "$bb_shadow_b"; do
        require_file "$f"
        if [ ! -f "$f" ]; then
            shadow_ok=0
            continue
        fi
        hits=$(_ca_noncomment_hits "$f" 'flash_erase|nandwrite|fw_setenv|nanddump|/dev/mtd|/dev/nand_env')
        if [ -n "$hits" ]; then
            fail "$tag SHADOWS-STAY-NOOP: $f is a readiness shadow but contains a real NAND/flash/env write (must stay a no-op)"
            printf '%s\n' "$hits" >&2
            shadow_ok=0
        fi
    done
    if [ "$shadow_ok" -eq 1 ]; then
        pass "$tag SHADOWS-STAY-NOOP: both beaglebone S99upgrade shadows stay no-op (no flash_erase/nandwrite/fw_setenv/mtd/nand_env writes outside comments)"
    fi

    # 2. MARKER-PARITY — the same boot-success marker literal binds the zynq
    #    commit authority (S99upgrade) and the report-only S99verify.
    require_pattern "$zynq_s99up" '/tmp/dcentos-upgrade-committed' \
        "$tag MARKER-PARITY: zynq S99upgrade owns the /tmp/dcentos-upgrade-committed boot-success marker"
    require_pattern "$zynq_s99ver" '/tmp/dcentos-upgrade-committed' \
        "$tag MARKER-PARITY: zynq S99verify defers to the same /tmp/dcentos-upgrade-committed marker"

    # 3. AMLOGIC-FAIL-CLOSED — amlogic commits via the platform-mandated mtd5
    #    recovery-flag (0x02 -> 0x03) mechanism with 0x03 readback fail-closed,
    #    WAL replay, and a fw_setenv-missing return 1; it never touches
    #    upgrade_stage.
    require_file "$aml_s99up"
    require_pattern "$aml_s99up" 'commit_recovery_flag' \
        "$tag AMLOGIC-FAIL-CLOSED: amlogic S99upgrade keeps the mtd5 recovery-flag commit (commit_recovery_flag)"
    require_pattern "$aml_s99up" '!= "0x03"' \
        "$tag AMLOGIC-FAIL-CLOSED: amlogic S99upgrade fails closed on a 0x03 recovery-flag readback mismatch"
    require_pattern "$aml_s99up" 'require_amlogic_ota08_identity' \
        "$tag AMLOGIC-FAIL-CLOSED: amlogic S99upgrade scopes OTA-08 to sealed board_target"
    require_pattern "$aml_s99up" 'OLD=$(read_recovery_flag)' \
        "$tag AMLOGIC-FAIL-CLOSED: amlogic S99upgrade pre-reads 0x02 before flash_erase"
    require_pattern "$aml_s99up" 'ERROR: recovery flag readback' \
        "$tag AMLOGIC-FAIL-CLOSED: amlogic S99upgrade post-write mismatch is ERROR"
    require_pattern "$aml_s99up" 'ERROR: recovery flag = 0x01 (INSTALLED) leftover in userspace' \
        "$tag AMLOGIC-FAIL-CLOSED: amlogic S99upgrade leftover 0x01 is ERROR not WARN"
    require_pattern "$aml_s99up" 'ERROR: could not read recovery flag' \
        "$tag AMLOGIC-FAIL-CLOSED: amlogic S99upgrade unread flag is ERROR not WARN"
    require_pattern "$aml_s99up" 'ERROR: unexpected recovery flag value' \
        "$tag AMLOGIC-FAIL-CLOSED: amlogic S99upgrade unexpected flag is ERROR not WARN"
    require_pattern "$aml_s99up" 'replay_pending_env_clear' \
        "$tag AMLOGIC-FAIL-CLOSED: amlogic S99upgrade keeps the WAL replay_pending_env_clear path"
    # The fw_setenv-missing `return 1` must live INSIDE clear_uboot_env (scan from
    # its definition to the next top-level function definition).
    if [ -f "$aml_s99up" ] && awk '
        /clear_uboot_env\(\)/ { inb = 1; next }
        inb && /^[A-Za-z_][A-Za-z0-9_]*\(\)/ { inb = 0 }
        inb && /command -v fw_setenv/ { guard = 1 }
        inb && guard && /return 1/ { found = 1 }
        END { exit(found ? 0 : 1) }
    ' "$aml_s99up"; then
        pass "$tag AMLOGIC-FAIL-CLOSED: clear_uboot_env returns 1 when fw_setenv is missing (fails closed, never a silent skip)"
    else
        fail "$tag AMLOGIC-FAIL-CLOSED: clear_uboot_env lost its fw_setenv-missing return-1 fail-closed guard"
    fi
    reject_pattern "$aml_s99up" 'upgrade_stage' \
        "$tag AMLOGIC-FAIL-CLOSED: amlogic S99upgrade never grows a zynq-style upgrade_stage commit"

    # 4. OTA-08-CONTAINMENT — command-position flash_erase/nandwrite only in the
    #    amlogic OTA-08 exception; every other S99upgrade (incl. zynq) stays
    #    fw_setenv-only.
    ota_ok=1
    for f in $(find "$base" -path '*/etc/init.d/S99upgrade' 2>/dev/null | sort); do
        hits=$(_ca_noncomment_hits "$f" '(^|[[:space:]])(flash_erase|nandwrite)([[:space:]]|;|$)')
        if [ "$f" = "$aml_s99up" ]; then
            if [ -z "$hits" ]; then
                fail "$tag OTA-08-CONTAINMENT: amlogic S99upgrade lost its raw-NAND recovery-flag commit (flash_erase/nandwrite) — OTA-08 exception gutted"
                ota_ok=0
            fi
        else
            if [ -n "$hits" ]; then
                fail "$tag OTA-08-CONTAINMENT: $f has a raw-NAND flash_erase/nandwrite command (only the amlogic OTA-08 exception may; every other S99upgrade stays fw_setenv-only)"
                printf '%s\n' "$hits" >&2
                ota_ok=0
            fi
        fi
    done
    if [ "$ota_ok" -eq 1 ]; then
        pass "$tag OTA-08-CONTAINMENT: raw-NAND flash_erase/nandwrite is contained to the amlogic S99upgrade OTA-08 exception; all other S99upgrade copies stay fw_setenv-only"
    fi

    # 5. STAGING-NEVER-COMMITS — the 4 zynq sysupgrade overlays stage
    #    upgrade_stage=0 and must never issue a command-position bare-delete of
    #    upgrade_stage (that health-gated commit is S99upgrade's sole authority).
    stage_ok=1
    for f in \
        "$base/zynq/rootfs-overlay/usr/sbin/sysupgrade" \
        "$base/zynq/am2-s19jpro/rootfs-overlay/usr/sbin/sysupgrade" \
        "$base/zynq/am2-s19pro/rootfs-overlay/usr/sbin/sysupgrade" \
        "$base/zynq/am2-s17pro/rootfs-overlay/usr/sbin/sysupgrade"
    do
        require_file "$f"
        if [ ! -f "$f" ]; then
            stage_ok=0
            continue
        fi
        # Staging form present: the env-script `upgrade_stage=0` line or a direct
        # `fw_setenv upgrade_stage 0` (explicit 0 value).
        if grep -Fq 'upgrade_stage=0' "$f" 2>/dev/null \
            || grep -Eq '^[[:space:]]*fw_setenv[[:space:]]+upgrade_stage[[:space:]]+0([[:space:]]|;|$)' "$f" 2>/dev/null; then
            :
        else
            fail "$tag STAGING-NEVER-COMMITS: $f lost the staging form (fw_setenv upgrade_stage 0 / upgrade_stage=0)"
            stage_ok=0
        fi
        # No command-position bare-delete of upgrade_stage (no value argument).
        bare=$(_ca_noncomment_hits "$f" '^[[:space:]]*fw_setenv[[:space:]]+upgrade_stage[[:space:]]*($|2>|#|;)')
        if [ -n "$bare" ]; then
            fail "$tag STAGING-NEVER-COMMITS: $f bare-deletes/commits upgrade_stage (that health-gated commit belongs to S99upgrade only)"
            printf '%s\n' "$bare" >&2
            stage_ok=0
        fi
    done
    if [ "$stage_ok" -eq 1 ]; then
        pass "$tag STAGING-NEVER-COMMITS: all 4 zynq sysupgrade overlays stage upgrade_stage=0 and never bare-delete/commit upgrade_stage"
    fi

    # 6. HOST-ONLY-TRANSFORMERS — raw environment-image transformers stay
    #    available for offline forensics but never ship in a miner rootfs.
    host_only_ok=1
    for f in "$sw_target_sh" "$sw_target_py"; do
        if [ -e "$f" ] || [ -L "$f" ]; then
            fail "$tag HOST-ONLY-TRANSFORMERS: target overlay contains forbidden raw environment transformer: $f"
            host_only_ok=0
        fi
    done
    for f in "$sw_host_sh" "$sw_host_py"; do
        b=$(basename "$f")
        require_pattern "$f" '--i-understand-this-is-not-fw-setenv' \
            "$tag HOST-ONLY-TRANSFORMERS: host-only $b requires the explicit --i-understand-this-is-not-fw-setenv acknowledgement"
        require_pattern "$f" 'REFUSING' \
            "$tag HOST-ONLY-TRANSFORMERS: host-only $b prints a REFUSING message (deprecated, not fw_setenv)"
    done
    require_pattern "$runtime_prune" 'usr/sbin/switch_firmware.py' \
        "$tag HOST-ONLY-TRANSFORMERS: final rootfs prune removes stale switch_firmware.py"
    require_pattern "$runtime_prune" 'usr/sbin/switch_firmware.sh' \
        "$tag HOST-ONLY-TRANSFORMERS: final rootfs prune removes stale switch_firmware.sh"
    require_pattern "$runtime_prune" 'root usr usr/bin usr/sbin' \
        "$tag HOST-ONLY-TRANSFORMERS: final rootfs prune rejects a symlinked usr/sbin delete path"
    if [ "$host_only_ok" -eq 1 ]; then
        pass "$tag HOST-ONLY-TRANSFORMERS: raw environment transformers are absent from the target overlay"
    fi
}
commit_authority_normalization_check

#
# CI-GATE-S99VERIFY-DRIFT ( beta): the post-flash S99verify proof-matrix
# init script ships in Zynq, Amlogic and BeagleBone overlays. Require the
# shared V1..V14 schema and report-only behavior in all three. Amlogic and
# BeagleBone differ only in their architecture fallback. The incomplete
# CV1835 overlay was retired in L17 and has no parity exception.
#
s99verify_drift_check() {
    base='br2_external_dcentos/board'
    zynq="$base/zynq/rootfs-overlay/etc/init.d/S99verify"
    aml="$base/amlogic/rootfs-overlay/etc/init.d/S99verify"
    bb="$base/beaglebone/am3-bb-s19jpro/rootfs-overlay/etc/init.d/S99verify"

    all="$zynq $aml $bb"
    noncv_nonzynq="$aml $bb"

    # Presence — if any copy is missing the rest of the gate cannot reason about
    # drift, so bail after reporting the missing file(s).
    missing=0
    for f in $all; do
        if [ ! -f "$f" ]; then
            fail "CI-GATE-S99VERIFY-DRIFT: missing S99verify copy $f"
            missing=1
        fi
    done
    if [ "$missing" -ne 0 ]; then
        return
    fi

    # 1. Core-invariant markers present in all 4 copies.
    marker_ok=1
    for f in $all; do
        for marker in 'run_verify()' 'emit_check()' 'V1..V14 proof matrix' '"version": 2'; do
            if ! grep -F -- "$marker" "$f" >/dev/null 2>&1; then
                fail "CI-GATE-S99VERIFY-DRIFT: $f missing core-invariant marker '$marker' (proof-matrix contract gutted)"
                marker_ok=0
            fi
        done
    done
    if [ "$marker_ok" -eq 1 ]; then
        pass "CI-GATE-S99VERIFY-DRIFT: all 4 S99verify copies carry the shared V1..V14 proof-matrix markers"
    fi

    # 2. Every verifier is report-only. Ignore prose and reject only actual
    #    command-position durable mutation. Zynq additionally observes the
    #    marker written by its sole commit authority, S99upgrade.
    authority_ok=1
    for f in $all; do
        if ! grep -F -- 'report-only proof consumer' "$f" >/dev/null 2>&1; then
            fail "CI-GATE-S99VERIFY-DRIFT: $f lost the report-only ownership marker"
            authority_ok=0
        fi
        mutation_hits=$(grep -nE '^[[:space:]]*(fw_setenv|nandwrite|flash_erase)([[:space:]]|$)' "$f" 2>/dev/null || true)
        if [ -n "$mutation_hits" ]; then
            fail "CI-GATE-S99VERIFY-DRIFT: $f contains a durable boot-state mutation command"
            printf '%s\n' "$mutation_hits" >&2
            authority_ok=0
        fi
    done
    if ! grep -F -- 'UPGRADE_COMMIT_MARKER' "$zynq" >/dev/null 2>&1; then
        fail "CI-GATE-S99VERIFY-DRIFT: zynq S99verify lost the S99upgrade decision-marker observation"
        authority_ok=0
    fi
    if [ "$authority_ok" -eq 1 ]; then
        pass "CI-GATE-S99VERIFY-DRIFT: all S99verify copies are report-only and Zynq observes the sole commit authority's marker"
    fi

    # 3. The non-CV non-Zynq copies remain byte-identical modulo the sanctioned
    #    `uname -m` arch fallback (the two `armv7l|arm)` / `aarch64|arm64)`
    #    BOARD_FAMILY lines). Normalize by deleting exactly those lines, then
    #    compare sha256. CV is handled by the narrower contract below.
    arch_strip='^[[:space:]]*(armv7l\|arm|aarch64\|arm64)\)'
    norm_ok=1
    for f in $noncv_nonzynq; do
        # Self-test: the normalizer must still target exactly the 2 sanctioned
        # arch-fallback lines. If the arch-case shape ever changes, surface it
        # instead of silently normalizing the wrong thing.
        removed=$(grep -cE "$arch_strip" "$f" 2>/dev/null || true)
        if [ "${removed:-0}" -ne 2 ]; then
            fail "CI-GATE-S99VERIFY-DRIFT: $f has $removed sanctioned uname -m arch-fallback line(s) (expected 2) — the drift normalizer no longer targets the right block"
            norm_ok=0
        fi
    done
    if [ "$norm_ok" -eq 1 ]; then
        ref_hash=''
        for f in $noncv_nonzynq; do
            h=$(grep -vE "$arch_strip" "$f" | sha256sum | awk '{print $1}')
            if [ -z "$ref_hash" ]; then
                ref_hash="$h"
            elif [ "$h" != "$ref_hash" ]; then
                fail "CI-GATE-S99VERIFY-DRIFT: $f drifted from the other non-CV non-zynq S99verify copy OUTSIDE the sanctioned uname -m arch fallback (normalized sha256 $h != $ref_hash)"
                norm_ok=0
            fi
        done
        if [ "$norm_ok" -eq 1 ]; then
            pass "CI-GATE-S99VERIFY-DRIFT: amlogic/beaglebone S99verify are byte-identical apart from the sanctioned per-overlay uname -m arch fallback (normalized sha256 $ref_hash)"
        fi
    fi

    # CV1835 is retired. Its former verifier is absent; remaining overlay
    # parity is checked above and the retirement gate enforces its absence.

}
s99verify_drift_check

#
# S43logrotate ENOSPC-rotator parity gate (2026-06-29).
#
# S43logrotate is the copytruncate rotator that bounds /tmp/dcentrald.log +
# dashboard.log + mcp.log so a long-running home unit can't ENOSPC-brick its
# /tmp tmpfs. Every target that ships the S82dcentrald daemon (which writes
# those /tmp/*.log files) MUST therefore also ship S43logrotate.
#
# IMPORTANT — assembled-chain model, NOT per-overlay-dir parity:
# DCENT_OS overlays are LAYERED. Each defconfig's BR2_ROOTFS_OVERLAY chains a
# BASE overlay (board/zynq/rootfs-overlay OR board/amlogic/rootfs-overlay) FIRST,
# then a per-SKU VARIANT overlay (e.g. board/zynq/am2-s19jpro/rootfs-overlay).
# Both base overlays ship S43logrotate AND S82dcentrald; the variant overlays
# carry only the files that DIFFER from the base and inherit the rest. So the
# variant overlays (am2-s17pro / am2-s19jpro / am2-s19pro / am3-bb-s19jpro /
# cv1835-s19jpro) legitimately ship S82dcentrald with no sibling S43logrotate —
# the assembled rootfs still gets the rotator from the base overlay. A naive
# per-init.d-dir parity check would false-FAIL on all five and fight the overlay
# design. This gate instead validates the GUARANTEE THAT ACTUALLY MATTERS: for
# every defconfig, if the union of its overlay chain ships S82dcentrald, the same
# union must also ship S43logrotate. It also pins every committed S43logrotate to
# be byte-identical to the canonical zynq copy, so a drifted/edited rotator on any
# overlay is caught. Purely additive; weakens no existing gate.
#
s43logrotate_parity_check() {
    canonical='br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/S43logrotate'
    if [ ! -f "$canonical" ]; then
        fail "s43logrotate-parity: canonical rotator missing: $canonical"
        return
    fi
    canon_sha=$(sha256sum "$canonical" | awk '{ print $1 }')

    drift=0

    # 1. Every committed S43logrotate (any overlay) must match the canonical.
    for f in $(find br2_external_dcentos -path '*rootfs-overlay/etc/init.d/S43logrotate' 2>/dev/null); do
        sha=$(sha256sum "$f" | awk '{ print $1 }')
        if [ "$sha" != "$canon_sha" ]; then
            fail "s43logrotate-parity: $f drifts from canonical S43logrotate (sha256 $sha != $canon_sha)"
            drift=1
        fi
    done

    # 2. Every defconfig whose ASSEMBLED overlay chain ships S82dcentrald must
    #    also ship S43logrotate somewhere in the SAME chain.
    for cfg in br2_external_dcentos/configs/*_defconfig; do
        [ -f "$cfg" ] || continue
        # Extract the BR2_ROOTFS_OVERLAY value, strip quotes, and reduce the
        # $(BR2_EXTERNAL_DCENTOS_PATH)/ make-var prefix to repo-relative tokens
        # (so word-splitting is space-safe even though the checkout path has
        # spaces). Comment lines mentioning the var start with '#' and are
        # excluded by the '^BR2_ROOTFS_OVERLAY=' anchor.
        overlays=$(grep -E '^BR2_ROOTFS_OVERLAY=' "$cfg" | head -n1 \
            | sed -e 's/^BR2_ROOTFS_OVERLAY=//' -e 's/^"//' -e 's/"$//' \
                  -e 's#\$(BR2_EXTERNAL_DCENTOS_PATH)/##g')
        [ -n "$overlays" ] || continue
        has_daemon=0
        has_logrotate=0
        for ov in $overlays; do
            initd="br2_external_dcentos/$ov/etc/init.d"
            [ -f "$initd/S82dcentrald" ] && has_daemon=1
            [ -f "$initd/S43logrotate" ] && has_logrotate=1
        done
        if [ "$has_daemon" -eq 1 ] && [ "$has_logrotate" -eq 0 ]; then
            fail "s43logrotate-parity: $(basename "$cfg") ships S82dcentrald but its overlay chain has no S43logrotate (ENOSPC rotator) — /tmp tmpfs can fill over weeks"
            drift=1
        fi
    done

    if [ "$drift" -eq 0 ]; then
        pass "s43logrotate-parity: every S82dcentrald overlay chain ships a byte-identical S43logrotate ENOSPC rotator (canonical sha256 $canon_sha)"
    fi
}
s43logrotate_parity_check

data_growth_bounds_check() {
    require_file 'scripts/test_data_growth_bounds.sh'
    if [ -f 'scripts/test_data_growth_bounds.sh' ]; then
        if sh 'scripts/test_data_growth_bounds.sh' >/dev/null 2>&1; then
            pass "/data growth-bound audit: auth sessions, audit log, audit ring, and log rotation are capped"
        else
            fail "/data growth-bound audit: persistent storage growth controls regressed"
        fi
    fi
}
data_growth_bounds_check

time_posture_bounds_check() {
    require_file 'scripts/test_time_posture_bounds.sh'
    if [ -f 'scripts/test_time_posture_bounds.sh' ]; then
        if sh 'scripts/test_time_posture_bounds.sh' >/dev/null 2>&1; then
            pass "time/NTP posture audit: no-RTC restore, SNTP, auth timers, and schedule offsets are pinned"
        else
            fail "time/NTP posture audit: no-RTC/time contract regressed"
        fi
    fi
}
time_posture_bounds_check

auth_write_frequency_check() {
    require_file 'scripts/test_auth_write_frequency.sh'
    if [ -f 'scripts/test_auth_write_frequency.sh' ]; then
        if sh 'scripts/test_auth_write_frequency.sh' >/dev/null 2>&1; then
            pass "auth write-frequency audit: bearer-token hot path does not persist auth.json"
        else
            fail "auth write-frequency audit: auth.json hot-path write contract regressed"
        fi
    fi
}
auth_write_frequency_check

hardware_identification_confidence_check() {
    require_file 'scripts/test_hardware_identification_confidence.sh'
    if [ -f 'scripts/test_hardware_identification_confidence.sh' ]; then
        if sh 'scripts/test_hardware_identification_confidence.sh' >/dev/null 2>&1; then
            pass "hardware-identification confidence audit: identity confidence DTO, resolver, and JSON surfaces are pinned"
        else
            fail "hardware-identification confidence audit: structured identity confidence regressed"
        fi
    fi
}
hardware_identification_confidence_check

nonstandard_mining_identity_provenance_check() {
    require_file 'scripts/test_nonstandard_mining_identity_provenance.sh'
    if [ -f 'scripts/test_nonstandard_mining_identity_provenance.sh' ]; then
        if sh 'scripts/test_nonstandard_mining_identity_provenance.sh' >/dev/null 2>&1; then
            pass "non-standard mining engines remain non-Measured without retained enumeration receipts"
        else
            fail "non-standard mining identity provenance audit regressed"
        fi
    fi
}
nonstandard_mining_identity_provenance_check

asic_wire_crc5_check() {
    require_file 'scripts/test_asic_wire_crc5.sh'
    if [ -f 'scripts/test_asic_wire_crc5.sh' ]; then
        if sh 'scripts/test_asic_wire_crc5.sh' >/dev/null 2>&1; then
            pass "ASIC wire CRC5: captured command vectors, generated Python copies, and unverified response semantics are pinned"
        else
            fail "ASIC wire CRC5: command checksum or response-integrity boundary regressed"
        fi
    fi
}
asic_wire_crc5_check

offline_soak_harness_check() {
    require_file 'scripts/test_offline_soak_harness.sh'
    require_file 'scripts/offline_soak_harness.sh'
    if [ -f 'scripts/test_offline_soak_harness.sh' ]; then
        if sh 'scripts/test_offline_soak_harness.sh' >/dev/null 2>&1; then
            pass "offline soak harness: accelerated RSS/fd growth gate is pinned"
        else
            fail "offline soak harness: RSS/fd growth gate regressed"
        fi
    fi
}
offline_soak_harness_check

sim_vs_firmware_contract_check() {
    require_file 'scripts/test_sim_vs_firmware_contract.sh'
    if [ -f 'scripts/test_sim_vs_firmware_contract.sh' ]; then
        if sh 'scripts/test_sim_vs_firmware_contract.sh' >/dev/null 2>&1; then
            pass "sim-vs-firmware contract: simulator profiles match promoted firmware wire surfaces"
        else
            fail "sim-vs-firmware contract: simulator profiles drifted from firmware/API wire contracts"
        fi
    fi
}
sim_vs_firmware_contract_check

# hw-acceptance harness: the accepted-share PASS/FAIL parser is the load-bearing
# gate that decides whether a live miner passed acceptance. If its parse silently
# broke, the harness would rubber-stamp a dead unit. So (a) run the hardware-free
# parser unit test here, and (b) drift-guard that skus.conf still lists the
# expanded target SKU set (the harness's single source of truth for Antminer
# acceptance rows).
accept_harness_check() {
    base='scripts/hw-acceptance'
    require_file "$base/lib/accept_parse.sh"
    require_file "$base/dcent-accept.sh"
    require_file "$base/skus.conf"
    require_file "$base/test_accept_parse.sh"
    require_file "$base/test_accept_fuzz.sh"
    require_file "$base/test_skus_conf_valid.sh"
    require_file "$base/test_release_state_route.sh"
    require_file "$base/test_am3_bb_acceptance_route.sh"
    require_file 'scripts/test_dev_deploy_output_static.py'
    require_file 'scripts/test_dev_deploy_behavior.py'
    require_file 'scripts/test_dcentrald_deploy_recovery.sh'
    require_file 'scripts/test_dcentos_deploy_lock.sh'
    require_file 'scripts/test_dcentrald_deploy_upgrade_guard.sh'
    require_file 'scripts/dev_deploy_recovery_admin.sh'

    if python3 scripts/test_dev_deploy_output_static.py >/dev/null 2>&1; then
        pass 'dev-deploy: process identity, immutable config, atomic receipt, and failed-launch cleanup contracts are pinned'
    else
        fail 'dev-deploy: exact process/config/evidence cleanup contract regressed'
    fi
    if python3 scripts/test_dev_deploy_behavior.py >/dev/null 2>&1; then
        pass 'dev-deploy: fake transport proves explicit runtime config and receipt-failure exact cleanup behavior'
    else
        fail 'dev-deploy: behavioral fake-transport cleanup contract regressed'
    fi
    if sh scripts/test_dcentrald_deploy_recovery.sh >/dev/null 2>&1; then
        pass 'dev-deploy: boot resolver restores or commits one exact persistent binary/config generation'
    else
        fail 'dev-deploy: persistent binary/config boot recovery contract regressed'
    fi
    if sh scripts/test_dcentos_deploy_lock.sh >/dev/null 2>&1; then
        pass 'dev-deploy: kernel lock excludes admission and releases on owner death or explicit handoff'
    else
        fail 'dev-deploy: kernel-backed admission exclusion contract regressed'
    fi
    if sh scripts/test_dcentrald_deploy_upgrade_guard.sh >/dev/null 2>&1; then
        pass 'dev-deploy: slot transitions refuse active or split persistent generations'
    else
        fail 'dev-deploy: firmware transition guard regressed'
    fi

    if sh scripts/hw-acceptance/test_accept_parse.sh >/dev/null 2>&1; then
        pass 'hw-acceptance: test_accept_parse.sh green (accepted-share gate parser pinned)'
    else
        fail 'hw-acceptance: test_accept_parse.sh FAILED (accepted-share PASS/FAIL parser regressed)'
    fi
    if sh scripts/hw-acceptance/test_accept_fuzz.sh >/dev/null 2>&1; then
        pass 'hw-acceptance: test_accept_fuzz.sh green (accepted-share gate parser pinned)'
    else
        fail 'hw-acceptance: test_accept_fuzz.sh FAILED (accepted-share PASS/FAIL parser regressed)'
    fi
    if sh scripts/hw-acceptance/test_skus_conf_valid.sh >/dev/null 2>&1; then
        pass 'hw-acceptance: test_skus_conf_valid.sh green (accepted-share gate parser pinned)'
    else
        fail 'hw-acceptance: test_skus_conf_valid.sh FAILED (accepted-share PASS/FAIL parser regressed)'
    fi
    if sh scripts/hw-acceptance/test_release_state_route.sh >/dev/null 2>&1; then
        pass 'hw-acceptance: NOT-IMPLEMENTED rows refuse runnable phases before transport'
    else
        fail 'hw-acceptance: NOT-IMPLEMENTED route refusal or bootlog evidence path regressed'
    fi
if sh scripts/hw-acceptance/test_am3_bb_acceptance_route.sh >/dev/null 2>&1; then
    pass 'hw-acceptance: AM3-BB observers are route-bound/read-only and mutating phases refuse before transport'
else
    fail 'hw-acceptance: AM3-BB identity, enumeration, refusal, or no-install contract regressed'
fi
if run_python_script scripts/test_s9se_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'S9 SE ledger: all 19 offline contracts, current blockers, refusal spine, and CI execution stay converged'
else
    fail 'S9 SE ledger: source modules, blockers, fail-closed authority, or CI execution drifted'
fi
if run_python_script scripts/test_bm1385_s7_convergence.py -q >/dev/null 2>&1; then
    pass 'BM1385/S7 ledger: exact dual profiles, FIL return contract, refusals, and CI execution stay converged'
else
    fail 'BM1385/S7 ledger: profiles, wire contract, authority refusal, or CI execution drifted'
fi
if run_python_script scripts/test_bm1485_l3plus_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'BM1485/L3+ ledger: ten offline contracts, default/recovery isolation, refusals, and CI execution stay converged'
else
    fail 'BM1485/L3+ ledger: source modules, recovery isolation, fail-closed authority, or CI execution drifted'
fi
if run_python_script scripts/test_bm1489_l7_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'BM1489/L7 ledger: seven offline contracts, dual-scaffold boundaries, weaknesses, and CI execution stay converged'
else
    fail 'BM1489/L7 ledger: source modules, scaffold boundaries, fail-closed authority, or CI execution drifted'
fi
if run_python_script scripts/test_bm1491_l9_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'BM1491/L9 ledger: ten offline contracts, scaffold nuances, weaknesses, and CI execution stay converged'
else
    fail 'BM1491/L9 ledger: source modules, scaffold boundaries, fail-closed authority, or CI execution drifted'
fi
if run_python_script scripts/test_bm1396_x17_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'BM1396/X17 ledger: historical contracts, explicit native extension, recovery isolation, unregistered generic driver, and CI execution stay converged'
else
    fail 'BM1396/X17 ledger: source modules, recovery isolation, generic driver registration, or CI execution drifted'
fi
if run_python_script scripts/test_bm1391_s15_t15_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'BM1391/S15/T15 ledger: seven offline contracts, all-operation scaffold refusal, and CI execution stay converged'
else
    fail 'BM1391/S15/T15 ledger: source modules, scaffold/registry boundaries, fail-closed authority, or CI execution drifted'
fi
if run_python_script scripts/test_bm1397_s17_t17_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'BM1397/S17/T17 ledger: exact offline module, factory refusal, experimental registry boundary, and CI execution stay converged'
else
    fail 'BM1397/S17/T17 ledger: source module, factory/driver gating, fail-closed authority, or CI execution drifted'
fi
if run_python_script scripts/test_bm1398_s19_t19_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'BM1398/S19/T19 ledger: exact compatibility module, physical-identity refusal, experimental boundary, and CI execution stay converged'
else
    fail 'BM1398/S19/T19 ledger: source module, readiness/native refusal, experimental gating, or CI execution drifted'
fi
if run_python_script scripts/test_bm1366_s19k_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'BM1366/S19k ledger: all 17 offline contracts, native/Track-1 split authority, and CI execution stay converged'
else
    fail 'BM1366/S19k ledger: source modules, native/Track-1 boundaries, default-off safety, or CI execution drifted'
fi
if run_python_script scripts/test_s9_stock_dhash_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'stock-S9 DHASH ledger: five offline contracts, unminted live receipt, management-only route, and CI execution stay converged'
else
    fail 'stock-S9 DHASH ledger: source modules, live-authority refusal, teardown ownership, or CI execution drifted'
fi
if run_python_script scripts/test_aml_route_evidence_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'AML route evidence ledger: T21, X19, and S21 XP exact modules, action-authority refusal, and CI execution stay converged'
else
    fail 'AML route evidence ledger: module ownership, model-specific composition, evidence-only authority, or CI execution drifted'
fi
if run_python_script scripts/test_x17_amtc_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'X17 AMTC ledger: factory and recovery modules have exact nonduplicated ownership, closed authority, and CI execution'
else
    fail 'X17 AMTC ledger: factory/recovery ownership, evidence-only authority, held-corpus boundary, or CI execution drifted'
fi
if run_python_script scripts/test_foundational_registry_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'foundational registries: producer, BoardDesc, install matrix, and PLL model have exact ownership and fail-closed CI contracts'
else
    fail 'foundational registries: module ownership, registry authority ceiling, measured tests, or CI execution drifted'
fi
if run_python_script scripts/test_feature_policy_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'feature policies: cooling medium, diagnostic mode, and measurement provenance have exact ownership and non-authorizing CI contracts'
else
    fail 'feature policies: module ownership, fail-closed cooling/diagnostic semantics, provenance ceiling, or CI execution drifted'
fi
if run_python_script scripts/test_zynq_voltage_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'Zynq/voltage contracts: AM2 topology, desk isolation, readback freshness, and rail admission have exact ownership'
else
    fail 'Zynq/voltage contracts: module ownership, desk-only isolation, measurement provenance, rail refusal, or CI execution drifted'
fi
if run_python_script scripts/test_evidence_registry_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'evidence registries: dsPIC decode/heartbeat, factory-aging, and S21 ADC/VCO hold have exact non-authorizing ownership'
else
    fail 'evidence registries: module ownership, decoder/heartbeat refusal, factory execution ceiling, S21 hold, or CI execution drifted'
fi
if run_python_script scripts/test_hashboard_contract_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'hashboard contracts: protocol, transport, geometry, and cited interconnect modules have exact non-authorizing ownership'
else
    fail 'hashboard contracts: module ownership, physical-identity ceiling, transport/geometry refusal, connector evidence, or CI execution drifted'
fi
if run_python_script scripts/test_hashboard_work_contract_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'hashboard work contracts: serial bookkeeping/policy and ticket-mask modules extend the exact non-authorizing owner'
else
    fail 'hashboard work contracts: expanded ownership, stale-job/dedup boundaries, serial progress, ticket encoding, or CI execution drifted'
fi
if run_python_script scripts/test_dps_schedule_units_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'DPS schedule/units: night reductions, local-hour conversion, and typed hashrate units have exact bounded ownership'
else
    fail 'DPS schedule/units: module ownership, decrease-first caps, fresh-temperature restoration, time bounds, units, or CI execution drifted'
fi
if run_python_script scripts/test_cooling_custody_lockout_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'cooling custody/lockout: C52 home admission and durable source-matched thermal release extend exact cooling ownership'
else
    fail 'cooling custody/lockout: expanded ownership, C52 receipt, prearm, source release, persistence, or CI execution drifted'
fi
if run_python_script scripts/test_hashboard_lifecycle_safety_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'hashboard lifecycle: stagger, dispatch pillars, terminal revoke, and ordered safety actions extend exact ownership'
else
    fail 'hashboard lifecycle: expanded ownership, dispatch-before-inrush, burst/empty refusal, terminal revoke, cut ordering, or CI drifted'
fi
if run_python_script scripts/test_recovery_durability_privacy_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'recovery durability/privacy: atomic mutation journaling and diagnostic wallet masking close exact common-module ownership'
else
    fail 'recovery durability/privacy: module ownership, crash durability, mutation admission, mask limits, workflow ownership, or CI drifted'
fi
if run_python_script scripts/test_mutation_clearance_ledger_convergence.py -q >/dev/null 2>&1; then
    pass 'mutation clearance: opaque adjudication mints one-use exact-path journal removal authority'
else
    fail 'mutation clearance: opaque state, path binding, direct-clear exclusion, daemon consumers, integration owner, or ledger ceiling drifted'
fi
if run_python_script scripts/test_dcentrald_common_surface_registry.py -q >/dev/null 2>&1; then
    pass 'common crate registry: complete source, feature, consumer, effect, and test authority stays exact'
else
    fail 'common crate registry: source inventory, unsafe/effect boundary, recovery isolation, Bench-GO admission, test profile, workflow owner, or aggregate drifted'
fi
if run_python_script scripts/test_dcentrald_asic_module_registry.py -q >/dev/null 2>&1; then
    pass 'ASIC crate registry: every exported module has a source, measured suite, ledger scope, and non-authorizing ceiling'
else
    fail 'ASIC crate registry: export inventory, source path, test accounting, ledger scope, safety anchors, workflow owner, or aggregate drifted'
fi
if run_python_script scripts/test_dcentrald_hal_module_registry.py -q >/dev/null 2>&1; then
    pass 'HAL crate registry: every declared module has a source, compile profile, measured suite, ledger scope, and non-authorizing ceiling'
else
    fail 'HAL crate registry: export inventory, feature gate, source path, test accounting, ledger scope, safety anchors, workflow owner, or aggregate drifted'
fi
if run_python_script scripts/test_dcentrald_silicon_profiles_module_registry.py -q >/dev/null 2>&1; then
    pass 'silicon-profile crate registry: every declared module has a source, compile profile, measured suite, ledger scope, and non-authorizing ceiling'
else
    fail 'silicon-profile crate registry: export inventory, feature gates, source path, test accounting, ledger scope, safety anchors, workflow owner, or aggregate drifted'
fi
if run_python_script scripts/test_dcentrald_thermal_module_registry.py -q >/dev/null 2>&1; then
    pass 'thermal crate registry: every declared module has a source, HAL profile, measured suite, ledger scope, and non-authorizing ceiling'
else
    fail 'thermal crate registry: export inventory, HAL gate, source path, test accounting, ledger scope, safety anchors, workflow owner, or aggregate drifted'
fi
if run_python_script scripts/test_dcentrald_fabric_lease_surface_registry.py -q >/dev/null 2>&1; then
    pass 'fabric-lease surface: public module and root API have exact ownership, tests, ledger scope, and non-authorizing ceiling'
else
    fail 'fabric-lease surface: module/root API inventory, source path, test accounting, ledger scope, ownership anchors, workflow owner, or aggregate drifted'
fi
if run_python_script scripts/test_dcentrald_autotuner_module_registry.py -q >/dev/null 2>&1; then
    pass 'autotuner crate registry: every public module, private helper, root test, and feature-only method has exact non-authorizing ownership'
else
    fail 'autotuner crate registry: module/profile inventory, source path, test accounting, ledger scope, safety anchors, workflow owner, or aggregate drifted'
fi
if run_python_script scripts/test_dcentrald_diagnostics_module_registry.py -q >/dev/null 2>&1; then
    pass 'diagnostics crate registry: every public module and feature profile has exact test ownership and a source-bound authority ceiling'
else
    fail 'diagnostics crate registry: module/profile inventory, source path, test accounting, ledger scope, safety anchors, workflow owner, or aggregate drifted'
fi
if run_python_script scripts/test_dcentrald_chip_analysis_surface_registry.py -q >/dev/null 2>&1; then
    pass 'chip-analysis surface: root APIs, tests, dependency edge, bounded math, and non-authorizing ownership are exact'
else
    fail 'chip-analysis surface: root API, tests, dependency/consumer scope, numerical hardening, authority ceiling, workflow owner, or aggregate drifted'
fi
if run_python_script scripts/test_dcentrald_re_catalog_surface_registry.py -q >/dev/null 2>&1; then
    pass 'RE catalog surface: modules, rows, vectors, consumers, tests, and non-authorizing ownership are exact'
else
    fail 'RE catalog surface: modules/reexports, row census, vector hashes, dependency/consumer scope, authority ceiling, workflow owner, or aggregate drifted'
fi
if run_python_script scripts/test_dcentrald_bridge_surface_registry.py -q >/dev/null 2>&1; then
    pass 'bridge-client surface: modules, APIs, evidence hashes, side effects, tests, and authority boundaries are exact'
else
    fail 'bridge-client surface: API/test inventory, evidence hashes, dependency/consumer scope, network/OTA/thermal safety, workflow owner, or aggregate drifted'
fi
if run_python_script scripts/test_dcentrald_daemon_surface_registry.py -q >/dev/null 2>&1; then
    pass 'root daemon surface: binaries, modules, CLI, dispatch, effects, unsafe boundaries, tests, staging, and init consumers are exact'
else
    fail 'root daemon surface: package/module/API/test inventory, config/discovery safety, effect/unsafe census, workflow owner, aggregate, staging, or init scope drifted'
fi
if run_python_script scripts/test_dcentrald_api_surface_registry.py -q >/dev/null 2>&1; then
    pass 'primary API surface: modules, routes, CGMiner verbs, effects, auth admission, tests, and authority boundaries are exact'
else
    fail 'primary API surface: module/route/command/test inventory, feature/dependency/consumer scope, auth/CORS/persistence safety, workflow owner, or aggregate drifted'
fi
if run_python_script scripts/test_dcentrald_api_grpc_surface_registry.py -q >/dev/null 2>&1; then
    pass 'gRPC API surface: protobuf shape, auth/startup admission, effects, tests, and authority boundaries are exact'
else
    fail 'gRPC API surface: Rust/protobuf inventory, auth/startup admission, effect mapping, dependency/consumer scope, workflow owner, or aggregate drifted'
fi
if run_python_script scripts/test_dcentrald_api_types_module_registry.py -q >/dev/null 2>&1; then
    pass 'API-types crate registry: every host-safe module, root contract, test, consumer, invariant macro, and authority boundary is exact'
else
    fail 'API-types crate registry: module/source/API/test accounting, dependency/consumer scope, host-safe boundary, ledger scope, workflow owner, or aggregate drifted'
fi
if run_python_script scripts/test_dcentrald_stratum_module_registry.py -q >/dev/null 2>&1; then
    pass 'Stratum crate registry: every module, feature profile, test, consumer, and transport authority boundary is exact'
else
    fail 'Stratum crate registry: module/source/API/test accounting, feature/dependency/consumer scope, transport authority, ledger scope, workflow owner, or aggregate drifted'
fi
if run_python_script scripts/test_dcentos_init_surface_registry.py -q >/dev/null 2>&1; then
    pass 'PID-1 surface registry: private functions, unsafe actions, tests, staging consumers, and authority boundaries are exact'
else
    fail 'PID-1 surface registry: source/API/test accounting, unsafe/action census, boot/shutdown policy, staging scope, workflow owner, or aggregate drifted'
fi

if [ -f "$base/skus.conf" ]; then
        missing=''
        for want in S9 S9SE S15 T15 S17 S17Pro S17Plus T17 T17Plus S17e T17e S19 S19Pro S19jPro S19jProBB S19kPro T19 S19XP S19jXP S21 T21 S21Pro S21XP; do
            if ! grep -qE "^$want\|" "$base/skus.conf"; then
                missing="$missing $want"
            fi
        done
        if [ -n "$missing" ]; then
            fail "hw-acceptance: skus.conf is missing target SKU row(s):$missing (target-set drift)"
        else
            pass "hw-acceptance: skus.conf lists all 23 target SKU rows"
        fi
    fi
    require_pattern "$base/lib/accept_parse.sh" 'AM3_BB_ENUMERATION_RECEIPT schema=v1' \
        'hw-acceptance: AM3-BB enumeration requires an exact unique-population receipt'
    require_pattern "$base/lib/accept_parse.sh" 'AM3_ENUM_PENDING:no_unique_population_receipt' \
        'hw-acceptance: AM3-BB assignment-only evidence remains pending'
    require_pattern "$base/dcent-accept.sh" 'external-media/all|external-media/backup|external-media/firstlight|external-media/ota' \
        'hw-acceptance: AM3-BB generic deploy, backup, and OTA phases refuse before helpers'
    require_pattern 'dcentrald/dcentrald/src/am3_bb_mining.rs' 'AM3_BB_TOPOLOGY_CAPTURE_RECEIPT schema=v2' \
        'hw-acceptance: AM3-BB topology capture is explicitly non-admission evidence'
    require_pattern 'dcentrald/dcentrald/src/am3_bb_mining.rs' 'AM3_BB_ROUTE_ADMISSION_RECEIPT schema=v2' \
        'hw-acceptance: AM3-BB runtime emits a PID/topology-bound post-watchdog admission receipt'
    require_pattern "$base/lib/accept_parse.sh" 'ACCEPTANCE_SCOPE_PASS' \
        'hw-acceptance: matrix verdict is diagnostic completeness rather than release authority'
    require_pattern "$base/lib/accept_parse.sh" 'board_target_mismatch' \
        'hw-acceptance: matrix results are bound to the manifest board target'
    require_pattern "$base/lib/accept_parse.sh" '_mxpolicy_count' \
        'hw-acceptance: matrix results bind the one fixed policy identifier'
    reject_pattern "$base/dcent-accept.sh" 'DCENT_ACCEPT_CAPSTONE_N' \
        'hw-acceptance: ambient environment cannot weaken the capstone share threshold'
    reject_pattern "$base/dcent-accept.sh" 'DCENT_ACCEPT_CAPSTONE_T' \
        'hw-acceptance: ambient environment cannot weaken the capstone duration'
    reject_pattern "$base/dcent-accept.sh" 'DCENT_ACCEPT_TEMP_CEILING' \
        'hw-acceptance: ambient environment cannot weaken the thermal ceiling'
    reject_pattern "$base/dcent-accept.sh" 'RELEASE_GO' \
        'hw-acceptance: observer JSON cannot mint a positive release verdict'
    reject_pattern "$base/dcent-accept.sh" 'RELEASE_NOGO' \
        'hw-acceptance: observer JSON cannot mint a negative release verdict'
    require_pattern "$base/dcent-accept.sh" '--case-dir=/tmp/dcentos-am3-bb.<mktemp-suffix>' \
        'hw-acceptance: AM3-BB observers require a fresh witnessed case directory'
    require_pattern "$base/dcent-accept.sh" 'StrictHostKeyChecking=yes' \
        'hw-acceptance: live observation requires strict pinned SSH host authentication'
    require_pattern "$base/dcent-accept.sh" '--expected-mac=xx:xx:xx:xx:xx:xx' \
        'hw-acceptance: live observation binds independently recorded unit MAC identity'
    require_pattern "$base/dcent-accept.sh" '--output="$deploy_receipt"' \
        'hw-acceptance: first-light consumes the exact launched PID/start/executable receipt'
    require_pattern "$base/dcent-accept.sh" 'first-light producer transition was not exactly bound to the launched runtime' \
        'hw-acceptance: first-light rejects stale pre-launch or mismatched post-launch producers'
    require_pattern "$base/dcent-accept.sh" 'SOAK_MAX_SHARE_STALL=300' \
        'hw-acceptance: soak policy caps accepted-share progress stalls'
    require_pattern "$base/lib/accept_parse.sh" 'SOAK_FAIL:hashrate_unavailable' \
        'hw-acceptance: all-zero hashrate cannot satisfy retention'
    require_pattern 'scripts/dev_deploy.sh' 'DCENTRALD_UNVERIFIABLE' \
        'dev-deploy: recognized but uninspectable daemon owners fail closed'
    require_pattern 'scripts/dev_deploy.sh' 'stop_exact_launched_process' \
        'dev-deploy: launched processes are stopped only by revalidated PID/start/executable identity'
    require_pattern 'scripts/dev_deploy.sh' 'RUNTIME_CONFIG_DIR="/tmp/dcentrald-runtime.${CONFIG_BIND_SHA256}.${DEPLOY_START}.$$"' \
        'dev-deploy: explicit runtime configs use private run-unique content-addressed directories'
    require_pattern 'scripts/dev_deploy.sh' 'START_ERROR=explicit_config_hash_changed' \
        'dev-deploy: explicit runtime config bytes are rechecked at the launch boundary'
    reject_pattern "$base/dcent-accept.sh" 'ACCEPTANCE ALL-PASS' \
        'hw-acceptance: local diagnostic flow never emits release-looking all-pass authority'
    require_pattern 'dcentrald/dcentrald-api/src/auth.rs' 'observer_method_allowed' \
        'hw-acceptance: AM3-BB observer API refuses mutating HTTP methods before handlers'
    require_pattern 'dcentrald/dcentrald-api/src/cgminer.rs' 'observer_restricted_verb' \
        'hw-acceptance: AM3-BB observer API refuses CGMiner control and session mutation'
    require_pattern 'dcentrald/dcentrald-api/src/rest/late.rs' 'observer-only API forbids onboarding persistence' \
        'hw-acceptance: onboarding reads cannot migrate persistent state in observer mode'
    require_pattern 'dcentrald/dcentrald/src/runtime/api.rs' 'if observer_only {' \
        'hw-acceptance: observer runtime suppresses configured identity fallback and command sinks'
    require_pattern 'dcentrald/dcentrald/src/main.rs' 'let verify_bundle_publication = if am3_bb_mode || ephemeral_runtime {' \
        'hw-acceptance: external-media AM3-BB and every ephemeral runtime suppress persistent capability publication'
    require_pattern 'dcentrald/dcentrald/src/main.rs' 'skipping persistent verify-bundle capability publication for non-persistent runtime' \
        'hw-acceptance: capability suppression is explicitly observable'
    procedure='../../docs/dev/2026-07-02-antminer-production-readiness/hw-procedures/BP-AM3-BB-PSU65-WATCHDOG.md'
    require_file "$procedure"
    require_pattern "$procedure" 'AM3_BB_PSU65_WATCHDOG_ACCEPTANCE_OK' \
        'hw-acceptance: AM3-BB procedure defines the exact reviewed completion sentinel'
    require_pattern "$procedure" 'External media or `/tmp` runtime only' \
        'hw-acceptance: AM3-BB procedure keeps NAND and boot-environment writes out of scope'
    require_pattern "$procedure" 'env -i' \
        'hw-acceptance: AM3-BB canonical launch starts from an empty environment'
    require_pattern "$procedure" 'DCENTOS_AUDIT_LOG_PATH="$case_dir/dcentrald-audit.ndjson"' \
        'hw-acceptance: AM3-BB audit output is redirected below the fresh case directory'
    require_pattern "$procedure" 'persistent-mounts-read-only.proof' \
        'hw-acceptance: AM3-BB procedure records bounded read-only mount snapshots without claiming continuous observation'
    require_pattern "$procedure" 'cannot, from a normally booted stock system' \
        'hw-acceptance: AM3-BB procedure does not overclaim zero persistent-media mutation'
    require_pattern "$procedure" 'PT_INTERP' \
        'hw-acceptance: AM3-BB procedure binds a static executable image'
    require_pattern "$procedure" 'final UART stop bit' \
        'hw-acceptance: AM3-BB shutdown timing has a physically synchronized t0'
    require_pattern "$procedure" 'process.environ.raw' \
        'hw-acceptance: AM3-BB procedure hash-binds raw NUL-delimited process evidence'
    require_pattern "$procedure" 'acceptance_rc=0' \
        'hw-acceptance: AM3-BB procedure accumulates every acceptance phase failure'
    require_pattern "$procedure" 'sha256sum -c "$host_evidence_dir/acceptance-harness.sha256" || acceptance_rc=1' \
        'hw-acceptance: AM3-BB procedure rechecks the harness manifest after all phases'
    require_pattern "$procedure" 'acceptance-harness-manifest.sha256.tmp' \
        'hw-acceptance: nested acceptance manifest binding is published atomically'
    require_pattern "$procedure" 'configured address-assignment plan' \
        'hw-acceptance: AM3-BB procedure distinguishes assigned addresses from measured chips'
}
accept_harness_check

# Operator evidence manifest gate. BENCH-1..8, production key ceremony, public
# HTTPS publication, and product decisions are intentionally operator-run. This
# offline validator keeps the release closeout evidence fail-closed: every gate
# must be marked pass, operator-run, agent-no-live-action, and backed by retained
# files whose SHA-256/size match the manifest.
operator_bench_evidence_check() {
    require_file 'scripts/verify_operator_bench_evidence.py'
    require_file 'scripts/test_operator_bench_evidence.py'
    require_file 'scripts/test_operator_bench_evidence.sh'
    require_pattern 'scripts/verify_operator_bench_evidence.py' 'dcentos-public-beta-external-gates/v3' 'operator evidence manifest schema requires checklist binding'
    require_pattern 'scripts/verify_operator_bench_evidence.py' 'DEFAULT_CHECKLIST = "checklist.json"' 'operator evidence validator names checklist.json'
    require_pattern 'scripts/verify_operator_bench_evidence.py' '--grandfather-legacy-manifest' 'operator evidence validator has explicit legacy grandfather flag'
    require_pattern 'scripts/test_operator_bench_evidence.py' 'test_manifest_requires_hash_bound_checklist' 'operator evidence tests require hash-bound checklist'
    require_pattern 'scripts/test_operator_bench_evidence.py' 'test_legacy_v2_manifest_requires_grandfather_flag' 'operator evidence tests pin explicit legacy grandfather behavior'
    require_pattern 'docs/release/checklist.json' 'dcentos-public-beta-operator-checklist/v1' 'source-controlled operator checklist JSON is present'
    require_pattern 'docs/release/PUBLIC_BETA_OPERATOR_CLOSEOUT_CHECKLIST.md' 'OPERATOR_BENCH_EVIDENCE_OK' 'operator closeout checklist documents verifier success marker'
    require_pattern 'docs/release/reference_repo_staleness_manifest.json' 'advisory_no_network_fetch_in_ci' 'reference-repo staleness manifest is advisory and source-only'
    require_pattern 'docs/PUBLIC_BETA_READINESS_REPORT.md' 'dcentos-public-beta-external-gates/v3' 'public beta report names v3 operator evidence schema'
    if [ -f 'scripts/test_operator_bench_evidence.sh' ]; then
        if sh 'scripts/test_operator_bench_evidence.sh' >/dev/null 2>&1; then
            pass "operator evidence: BENCH/publication/key-ceremony manifest validator self-test green"
        else
            fail "operator evidence: manifest validator self-test FAILED"
        fi
    fi
}
operator_bench_evidence_check

# Public beta artifact marker gate. The release definition of done requires the
# shipped sysupgrade images to carry /etc/dcentos/release-image and
# metrics_require_auth = true. The publication verifier must inspect the
# embedded SquashFS root payloads, not just the outer tar manifest.
publication_artifact_marker_check() {
    f='scripts/verify_beta_xil_publication_packet.sh'
    require_file "$f"
    [ -f "$f" ] || return
    require_pattern "$f" 'unsquashfs' \
        'publication packet verifier inspects embedded SquashFS root payloads'
    require_pattern "$f" 'verify_rootfs_release_markers' \
        'publication packet verifier has a rootfs marker check'
    require_pattern "$f" 'etc/dcentos/release-image' \
        'publication packet verifier requires /etc/dcentos/release-image in rootfs'
    require_pattern "$f" 'metrics_require_auth' \
        'publication packet verifier requires metrics_require_auth=true in rootfs'
}
publication_artifact_marker_check

# No-secret-logs regression pin. post_config once logged the ENTIRE config request
# body at INFO (`"Config update request: {:?}", body`) — which carries a pool
# `password` and a `stratum+tcp://user:pass@host` URL, landing a plaintext
# credential on disk (/tmp/dcentrald.log + the persistent ring + support bundles).
# Fixed in 5c871dd6 to log only top-level key names. Ban the exact pre-fix leak
# marker so the class cannot silently return. (2026-07-03 secrets-in-logs sweep:
# this was the sole daemon log leak; the pool-credential path masks via mask_wallet.)
secret_log_ban_check() {
    f='dcentrald/dcentrald-api/src/rest.rs'
    if [ ! -f "$f" ]; then
        fail "no-secret-logs: missing $f"
        return
    fi
    if grep -F -- 'Config update request: {:?}' "$f" >/dev/null 2>&1; then
        fail "no-secret-logs: post_config raw-body INFO leak reintroduced ($f) — logs pool password on disk"
    else
        pass "no-secret-logs: post_config does not log the raw config body (pool-password-on-disk leak stays fixed)"
    fi
}
secret_log_ban_check

# Broaden the no-secret-logs gate from the single known post_config leak to the
# whole CLASS: any log macro that DEBUG-formats ({:?}) a credential-bearing
# variable (raw_body / *config / creds / password / secret) risks writing a pool
# password (or other credential) to the on-disk log. Scan the API + stratum
# sources; the codebase is clean today, so any hit is a NEW single-line
# reintroduction (the exact-string check above still covers the historical leak).
secret_debug_log_class_check() {
    # `|| true`: the whole grep pipeline exits non-zero when it finds nothing (the
    # clean case), which under this script's `set -e` would abort the gate on the
    # assignment. Force success so the empty result is handled below.
    _hits=$(grep -rnE '(info|warn|error|debug|trace)!\(' \
        dcentrald/dcentrald-api/src dcentrald/dcentrald-stratum/src 2>/dev/null \
        | grep -E '\{:\?\}' \
        | grep -iE '\b(raw_body|new_config|pool_config|full_config|creds|credential|password|passwd|secret)\b' \
        | grep -viE '//|redact|mask|password_set|has_password|no_password|_present|_configured|onboarding' \
        || true)
    if [ -n "$_hits" ]; then
        fail "no-secret-logs: a log statement debug-formats a credential-bearing variable (may leak a credential to the on-disk log): $(printf '%s' "$_hits" | head -1)"
    else
        pass "no-secret-logs: no log statement debug-formats a credential-bearing variable (API + stratum)"
    fi
}
secret_debug_log_class_check

# Key-ceremony tooling self-test. The production Ed25519 release key ceremony
# (generate_release_keypair.sh mints the key; verify_release_keypair.sh proves it
# round-trips + emits the exact firmware-baked public-key hex) is an air-gapped
# operator step. This proves the SCRIPTS themselves work end-to-end with THROWAWAY
# keys — a matched pair PASSES and emits a 64-char hex, a mismatched pair FAILS —
# so a broken ceremony script can't silently ship a firmware that fails to verify
# its own OTA (a bricked update path). The self-test skips cleanly if openssl/od
# are unavailable, so this stays green on a minimal host.
key_ceremony_selftest_check() {
    require_file 'scripts/release_host_tools.py'
    require_file 'scripts/test_release_host_tools.py'
    if python3 scripts/test_release_host_tools.py --host-platform >/dev/null 2>&1; then
        pass "release host tools: host-specific OpenSSL selection and path tests"
    else
        fail "release host tools: host-specific OpenSSL selection/path test failed"
    fi
    require_file 'scripts/generate_release_keypair.sh'
    require_file 'scripts/verify_release_keypair.sh'
    require_file 'scripts/test_verify_release_keypair.sh'
    if [ -f 'scripts/test_verify_release_keypair.sh' ]; then
        if bash 'scripts/test_verify_release_keypair.sh' >/dev/null 2>&1; then
            pass "key-ceremony: generate+verify tooling self-test green (or cleanly skipped)"
        else
            fail "key-ceremony: verify_release_keypair.sh self-test FAILED (ceremony tooling broken)"
        fi
    fi
}
key_ceremony_selftest_check

# Public SKU support matrix completeness. The public-facing SUPPORTED_HARDWARE.md
# must describe every SKU DCENT_OS targets — a drift means a user's miner is
# silently absent from the support statement (they'd have no honest read on their
# hardware's real state). Gate on each SKU's board_target token (unique per SKU)
# from the skus.conf source of truth, so the doc can't fall out of sync with the
# actual target set.
supported_hardware_doc_check() {
    doc='docs/SUPPORTED_HARDWARE.md'
    conf='scripts/hw-acceptance/skus.conf'
    require_file "$doc"
    require_file "$conf"
    [ -f "$doc" ] && [ -f "$conf" ] || return
    bts=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$conf" | cut -d'|' -f2)
    missing=''
    for bt in $bts; do
        [ -n "$bt" ] || continue
        grep -Fq "$bt" "$doc" || missing="$missing $bt"
    done
    if [ -n "$missing" ]; then
        fail "SUPPORTED_HARDWARE.md is missing SKU board_target(s):$missing (public support-doc drift)"
    else
        pass "SUPPORTED_HARDWARE.md covers every SKU in skus.conf (public support matrix in sync)"
    fi
    require_pattern "$doc" 'Failed-boot auto-revert is not guaranteed' 'SUPPORTED_HARDWARE.md states the beta rollback boundary'
    require_pattern "$doc" 'known-good SD recovery media or a verified full-NAND restore path' 'SUPPORTED_HARDWARE.md names required beta recovery equipment'
    require_pattern 'docs/PUBLIC_BETA_READINESS_REPORT.md' 'Failed-boot auto-revert is not guaranteed' 'public beta report states the rollback boundary'
    require_pattern 'docs/PUBLIC_BETA_READINESS_REPORT.md' 'serial console access plus known-good SD recovery media or a verified full-NAND restore path' 'public beta report names recovery equipment'
}
supported_hardware_doc_check

# A/B rollback health-verdict gate. daemon_real_health_verdict in the zynq
# S99upgrade is the commit-vs-revert decision for a fresh firmware slot. Its
# fail-safe classification is load-bearing: absence of proof (no wget / empty /
# unparseable body) must SOFT-PASS as "unknown" so a good unit is never needlessly
# reverted, while a reachable-but-zero-uptime daemon must be "unhealthy" so a broken
# slot is blocked from committing (the W8 "defeated by S99" bug class).
# The first functional test sources the REAL function and drives it with a
# mock wget; the second runs the REAL start path with host-side shims and
# asserts a zero-uptime daemon writes the blocked marker without calling
# fw_setenv. The third runs the REAL start path with SSH deliberately down
# and pins that only the documented first-boot/release-image policy states
# soft-pass; unmarked SSH-down still blocks the commit.
s99_health_verdict_check() {
    require_file 'scripts/test_s99_health_verdict.sh'
    if [ -f 'scripts/test_s99_health_verdict.sh' ]; then
        if sh 'scripts/test_s99_health_verdict.sh' >/dev/null 2>&1; then
            pass "A/B rollback: S99upgrade health-verdict fail-safe classification green"
        else
            fail "A/B rollback: S99upgrade daemon_real_health_verdict classification regressed"
        fi
    fi
    require_file 'scripts/test_s99upgrade_failed_health_no_commit.sh'
    if [ -f 'scripts/test_s99upgrade_failed_health_no_commit.sh' ]; then
        if sh 'scripts/test_s99upgrade_failed_health_no_commit.sh' >/dev/null 2>&1; then
            pass "A/B rollback: failed-health S99upgrade start path leaves slot uncommitted"
        else
            fail "A/B rollback: failed-health S99upgrade start path committed or regressed"
        fi
    fi
    require_file 'scripts/test_s99upgrade_commit_refusals.sh'
    if [ -f 'scripts/test_s99upgrade_commit_refusals.sh' ]; then
        if sh 'scripts/test_s99upgrade_commit_refusals.sh' >/dev/null 2>&1; then
            pass "A/B rollback: S99upgrade commit-refusal paths leave the slot blocked"
        else
            fail "A/B rollback: S99upgrade commit-refusal path committed or regressed"
        fi
    fi
    require_file 'scripts/test_s99upgrade_ssh_soft_pass.sh'
    if [ -f 'scripts/test_s99upgrade_ssh_soft_pass.sh' ]; then
        if sh 'scripts/test_s99upgrade_ssh_soft_pass.sh' >/dev/null 2>&1; then
            pass "A/B rollback: S99upgrade SSH soft-pass policy is pinned"
        else
            fail "A/B rollback: S99upgrade SSH soft-pass policy regressed"
        fi
    fi
}
s99_health_verdict_check

# S99verify platform-detection gate. detect_platform() classifies the running
# board (board_family stamp -> board_target fallback -> uname heuristic) and that
# classification routes the per-platform upgrade/rollback health checks — a
# mis-classified platform runs the wrong V-checks. Pins the classification for
# every target platform, incl. the canonical am2-s19jpro-zynq board_target in the
# fallback path (the routing-key class fixed across the resolver/harness/init).
s99_detect_platform_check() {
    require_file 'scripts/test_s99_detect_platform.sh'
    if [ -f 'scripts/test_s99_detect_platform.sh' ]; then
        if sh 'scripts/test_s99_detect_platform.sh' >/dev/null 2>&1; then
            pass "OTA: S99verify detect_platform classifies every target platform"
        else
            fail "OTA: S99verify detect_platform platform classification regressed"
        fi
    fi
}
s99_detect_platform_check

# The S9 stock-restore selector assumptions were invalidated by local U-Boot
# and live evidence. Keep both current and legacy CLI entry points fail-closed,
# prevent stale destructive recipes from surviving in source, and ensure the
# Buildroot legacy pathname is only an alias of the canonical containment file.
s9_restore_containment_check() {
    require_file 'scripts/test_s9_restore_containment.sh'
    if [ -f 'scripts/test_s9_restore_containment.sh' ]; then
        if sh 'scripts/test_s9_restore_containment.sh' >/dev/null 2>&1; then
            pass "S9 stock restore: invalidated selector path is contained"
        else
            fail "S9 stock restore: containment boundary regressed"
        fi
    fi
}
s9_restore_containment_check

# The common Amlogic overlay must retain the historical /uninstall.sh pathname
# without inheriting the captured LuxOS S19k environment-corruption/rootfs-wipe
# authority. Exercise the compatibility stub so a future packaging edit cannot
# silently re-enable raw /dev/nand_env mutation or a hard reboot.
amlogic_uninstall_containment_check() {
    require_file 'scripts/test_amlogic_uninstall_containment.sh'
    if [ -f 'scripts/test_amlogic_uninstall_containment.sh' ]; then
        if sh 'scripts/test_amlogic_uninstall_containment.sh' >/dev/null 2>&1; then
            pass "Amlogic uninstall: unproven LuxOS restore procedure is contained"
        else
            fail "Amlogic uninstall: zero-mutation compatibility boundary regressed"
        fi
    fi
}
amlogic_uninstall_containment_check

# The historical SD-to-NAND installer and Zynq AM2 S19 stock-revert path remain
# addressable for compatibility, but neither has an admitted shared-engine
# transaction. Exercise both refusal interfaces so legacy CLI arguments,
# hostile environment overrides, or target packaging cannot restore authority.
legacy_boot_env_writer_containment_check() {
    require_file 'scripts/test_legacy_boot_env_writer_containment.sh'
    if [ -f 'scripts/test_legacy_boot_env_writer_containment.sh' ]; then
        if sh 'scripts/test_legacy_boot_env_writer_containment.sh' >/dev/null 2>&1; then
            pass "legacy boot-environment writers: unproven install/restore paths are contained"
        else
            fail "legacy boot-environment writers: zero-mutation compatibility boundary regressed"
        fi
    fi
}
legacy_boot_env_writer_containment_check

# Sysupgrade / stock-revert packaging + NAND-safety static gate. This test bundles
# the load-bearing recovery-safety invariants — fw_setenv-only env flips, extract-
# before-erase ordering, extracted-size caps, hard-link rejection, S17 fail-closed
# on an unknown bootslot, and the Amlogic-never-flash_erase brick guard — but was
# ORPHANED (invoked by no CI workflow or gate). Run it here so those revert/recovery
# safety checks actually gate the release instead of silently rotting.
sysupgrade_packaging_static_check() {
    require_file 'scripts/test_sysupgrade_packaging_static.sh'
    if [ -f 'scripts/test_sysupgrade_packaging_static.sh' ]; then
        if sh 'scripts/test_sysupgrade_packaging_static.sh' >/dev/null 2>&1; then
            pass "sysupgrade/revert packaging + NAND-safety static checks green"
        else
            fail "sysupgrade/revert packaging + NAND-safety static checks regressed"
        fi
    fi
}
sysupgrade_packaging_static_check

# The signed sysupgrade envelope must be byte-identical when the same staged
# payloads are packaged in unrelated directories with different host mtimes,
# creation order and modes. The test also proves invalid/missing/dirty source
# provenance fails closed before signing.
release_envelope_reproducibility_check() {
    require_file 'scripts/test_release_envelope_reproducibility.sh'
    if [ -f 'scripts/test_release_envelope_reproducibility.sh' ]; then
        release_envelope_output=''
        if release_envelope_output=$(bash 'scripts/test_release_envelope_reproducibility.sh' 2>&1); then
            pass "release envelope is reproducible and provenance rejects invalid inputs"
        else
            printf '%s\n' "$release_envelope_output" >&2
            fail "release envelope reproducibility/provenance contract regressed"
        fi
    fi
}
release_envelope_reproducibility_check

release_publication_check() {
    require_file 'scripts/release_publication.py'
    require_file 'scripts/test_release_publication.py'
    require_file 'scripts/test_release_publication.sh'
    if sh 'scripts/test_release_publication.sh' >/dev/null 2>&1; then
        pass "each flat release compatibility file publishes atomically without replacement"
    else
        fail "release publication path/identity boundary regressed"
    fi
}
release_publication_check

# A release invocation is an identity/capability boundary, not cleanup authority
# over arbitrary Docker or output state. Source materialization and authoritative
# publication have separate exact-tree capabilities so each can fail closed.
release_capsule_primitives_check() {
    require_file 'scripts/release_invocation.py'
    require_file 'scripts/release_signing_authority.py'
    require_file 'scripts/test_release_signing_authority.py'
    require_file 'scripts/test_release_signing_authority.sh'
    require_file 'scripts/release_capsule_lineage.py'
    require_file 'scripts/test_release_invocation.py'
    require_file 'scripts/test_release_invocation.sh'
    require_file 'scripts/release_result_stage.py'
    require_file 'scripts/test_release_result_stage.py'
    require_file 'scripts/test_release_result_stage.sh'
    require_file 'scripts/release_docker_resources.py'
    require_file 'scripts/test_release_docker_resources.py'
    require_file 'scripts/test_release_docker_resources.sh'
    require_file 'scripts/build_s9_release_capsule.sh'
    require_file 'scripts/test_cargo_capsule_driver.sh'
    require_file 'scripts/test_s9_release_capsule_driver.sh'
    require_file 'scripts/release_capsule_target_policy.py'
    require_file 'scripts/test_release_capsule_target_policy.py'
    require_file 'scripts/test_release_capsule_target_policy.sh'
    require_file 'scripts/release_train.py'
    require_file 'scripts/test_release_train.py'
    require_file 'scripts/test_release_train.sh'
    require_file 'scripts/release_producer_evidence.py'
    require_file 'scripts/test_release_producer_evidence.py'
    if python3 scripts/test_release_producer_evidence.py; then
        pass "current producer exact-set audit rejects extra, missing, foreign, and unsealed members"
    else
        fail "current producer exact-set audit regressed"
    fi
    require_file 'scripts/portable_release_evidence.py'
    require_file 'scripts/test_portable_release_evidence.py'
    require_file 'scripts/test_portable_release_evidence.sh'
    require_file 'scripts/source_snapshot.py'
    require_file 'scripts/test_source_snapshot.py'
    require_file 'scripts/test_source_snapshot.sh'
    require_file 'scripts/release_set_publication.py'
    require_file 'scripts/test_release_set_publication.py'
    require_file 'scripts/test_release_set_publication.sh'
    require_file 'scripts/test_host_path_text.py'
    require_file 'scripts/test_host_path_text.sh'

    if sh 'scripts/test_host_path_text.sh' >/dev/null 2>&1; then
        pass "MSYS host-path normalization boundaries hold across all release tools"
    else
        fail "MSYS host-path normalization boundary behavior regressed"
    fi
    if sh 'scripts/test_release_invocation.sh' >/dev/null 2>&1; then
        pass "release invocation identities are unique, capability-owned, and explicitly GC-gated"
    else
        fail "release invocation identity/capability boundary regressed"
    fi
    if sh 'scripts/test_release_signing_authority.sh' >/dev/null 2>&1; then
        pass "release signing keys are stable, private, invocation-bound capabilities"
    else
        fail "release signing-authority snapshot/integrity boundary regressed"
    fi
    # The wrapper declares Bash and uses `set -o pipefail`; invoking it through
    # Ubuntu's `/bin/sh` (dash) exits before any result-stage test runs.
    if bash 'scripts/test_release_result_stage.sh' >/dev/null 2>&1; then
        pass "Cargo result handoff is invocation-bound, exact, and outside the live source tree"
    else
        fail "release result-stage isolation/integrity boundary regressed"
    fi
    if sh 'scripts/test_release_docker_resources.sh' >/dev/null 2>&1; then
        pass "Docker volume operations require exact invocation labels and cleanup authority"
    else
        fail "release Docker resource authority boundary regressed"
    fi
    if bash 'scripts/test_cargo_capsule_driver.sh' >/dev/null 2>&1; then
        pass "Cargo capsule consumes read-only snapshot source and isolated invocation results"
    else
        fail "Cargo capsule driver isolation/cleanup boundary regressed"
    fi
    if bash 'scripts/test_s9_release_capsule_driver.sh' >/dev/null 2>&1; then
        pass "S9 capsule preserves immutable source, private invocation state, cleanup, and no-replace publication"
    else
        fail "S9 release-capsule orchestration boundary regressed"
    fi
    if bash 'scripts/test_release_capsule_target_policy.sh' >/dev/null 2>&1; then
        pass "release-capsule targets use one exact fail-closed identity policy"
    else
        fail "release-capsule target admission policy regressed"
    fi
    if bash 'scripts/test_release_train.sh' >/dev/null 2>&1; then
        pass "release train composes frozen capsule policy with live admission rings and refuses Denied publishes"
    else
        fail "release-train admission/publish-posture boundary regressed"
    fi
    if sh 'scripts/test_source_snapshot.sh' >/dev/null 2>&1; then
        pass "source snapshots materialize exact Git-object bytes outside the live worktree"
    else
        fail "Git-object source snapshot integrity/cleanup boundary regressed"
    fi
    if bash 'scripts/test_portable_release_evidence.sh' >/dev/null 2>&1; then
        pass "published release sets remain target-bound and independently auditable after private-stage cleanup"
    else
        fail "portable signed release-evidence target boundary regressed"
    fi
    if sh 'scripts/test_release_set_publication.sh' >/dev/null 2>&1; then
        pass "authoritative release directories publish as one exact no-replace set"
    else
        fail "authoritative release-set sealing/publication boundary regressed"
    fi
}
release_capsule_primitives_check

# Partial source closure is a separate, deliberately narrower claim than
# envelope reproducibility. Bind immutable build definitions and actual output
# member digests while keeping unresolved Buildroot/container inputs explicit.
source_closure_check() {
    require_file 'scripts/source_closure.py'
    require_file 'scripts/test_source_closure.sh'
    require_file 'scripts/sign_release_receipt.sh'
    require_file 'scripts/sign_release_receipt.py'
    require_file 'scripts/test_sign_release_receipt.sh'
    if sh scripts/test_sign_release_receipt.sh >/dev/null 2>&1; then
        pass "release receipt signing pins exact inputs and durably publishes without replacement"
    else
        fail "release receipt signing lifecycle regressed"
    fi
    require_file 'scripts/test_build_input_preflight.sh'
    require_file 'scripts/build_input_snapshot.py'
    require_file 'scripts/test_build_input_snapshot.py'
    require_file 'scripts/test_build_input_snapshot.sh'
    require_file 'scripts/buildroot_local_source_digest.py'
    require_file 'scripts/test_buildroot_local_source_digest.py'
    if [ -f 'scripts/test_source_closure.sh' ]; then
        if bash 'scripts/test_source_closure.sh' >/dev/null 2>&1; then
            pass "partial source closure is deterministic and rejects missing/mutable inputs"
        else
            fail "partial source-closure generation/verification regressed"
        fi
    fi
    if [ -f 'scripts/test_build_input_preflight.sh' ]; then
        if bash 'scripts/test_build_input_preflight.sh' >/dev/null 2>&1; then
            pass "target-scoped out-of-band inputs fail closed before Cargo/Docker consumers"
        else
            fail "target-scoped build-input preflight regressed"
        fi
    fi
    if [ -f 'scripts/test_build_input_snapshot.sh' ]; then
        if sh 'scripts/test_build_input_snapshot.sh' >/dev/null 2>&1; then
            pass "manifest-pinned external bytes use exact-tree snapshots and consumer-side digest checks"
        else
            fail "build-input snapshot integrity/cleanup/consumption gate regressed"
        fi
    fi
    if run_python_script 'scripts/test_buildroot_local_source_digest.py' -q >/dev/null 2>&1; then
        pass "Buildroot warm-tree invalidation binds every staged BR2_EXTERNAL source byte, path, and mode"
    else
        fail "Buildroot local-source digest or warm-tree invalidation tests regressed"
    fi
    require_pattern 'scripts/source_closure.py' \
        'org.dcentral.dcentos.source-closure.v4' \
        'source closure v4 binds one authenticated invocation and Git-object snapshot'
    require_pattern 'scripts/source_closure.py' \
        'org.dcentral.dcentos.source-closure.v3' \
        'historical source closure v3 remains verification-only during migration'
    require_pattern 'scripts/source_closure.py' \
        'legacy source-closure v1 receipts lack required out-of-band input binding' \
        'source closure rejects unbound legacy v1 receipts by default'
    require_pattern 'scripts/source_closure.py' \
        'legacy source-closure v2 receipts lack retained prebuilt Rust input binding' \
        'source closure rejects v2 receipts that omit retained prebuilt Rust inputs'
    require_pattern 'scripts/source_closure.py' \
        'retained-packaging-input-snapshots-not-build-execution-attestation' \
        'retained prebuilt Rust evidence keeps its build-execution boundary explicit'
    require_pattern 'scripts/build_inputs.manifest' \
        'knowledge-base/extractions/s9/s9_devicetree.dtb' \
        'S9 FIT device tree is pinned as a consumed out-of-band build input'
    require_pattern 'scripts/build-dcentrald.sh' \
        '--target cargo-workspace' \
        'Cargo workspace snapshots its ignored embedded input before compilation'
    require_pattern 'scripts/build_in_docker.sh' \
        'build_input_snapshot.py" create' \
        'firmware packaging snapshots target inputs before Docker consumption'
    require_pattern 'scripts/build_in_docker.sh' \
        'buildroot_local_source_digest.py br2_external_dcentos' \
        'Buildroot warm target stamp digests the complete staged BR2_EXTERNAL tree'
    require_pattern 'scripts/build_in_docker.sh' \
        'br2_external_sha256=$BR2_EXTERNAL_SOURCE_SHA256' \
        'Buildroot warm target stamp invalidates cached local-package sources'
    require_pattern 'scripts/build_in_docker.sh' \
        'build_driver_sha256=$BUILD_DRIVER_SHA256' \
        'Buildroot warm target stamp invalidates build-driver semantic changes'
    require_pattern 'scripts/build_in_docker.sh' \
        'source_digest_tool_sha256=$SOURCE_DIGEST_TOOL_SHA256' \
        'Buildroot warm target stamp binds the digest implementation itself'
    reject_pattern 'scripts/build_in_docker.sh' \
        ':/kb:ro' \
        'supported packaging lanes cannot bypass snapshots through a live knowledge-base mount'
    reject_pattern 'scripts/build_in_docker.sh' \
        '/kb/extractions/' \
        'packaging contains no dormant live-extraction fallback path'
    if [ ! -e 'dcentrald/pic-recovery/build.rs' ]; then
        pass 'Cargo diagnostics contain no recovery-artifact build script'
    else
        fail 'Cargo diagnostics unexpectedly contain dcentrald/pic-recovery/build.rs'
    fi
    reject_pattern 'dcentrald/pic-recovery/src/main.rs' \
        'include_bytes!' \
        'controller diagnostics cannot embed a proprietary recovery artifact'
    reject_pattern 'dcentrald/pic-recovery/src/main.rs' \
        'include_str!' \
        'controller diagnostics cannot embed a textual recovery artifact'
    reject_pattern 'dcentrald/pic-recovery/src/dspic_flash_main.rs' \
        'include_bytes!' \
        'dsPIC status command cannot embed a proprietary recovery artifact'
    reject_pattern 'dcentrald/pic-recovery/src/dspic_flash_main.rs' \
        'include_str!' \
        'dsPIC status command cannot embed a textual recovery artifact'
    reject_pattern 'scripts/build-dcentrald.sh' \
        'DCENT_STOCK_FPGA' \
        'normal Cargo builds cannot carry retired stock-FPGA environment authority'
    reject_pattern 'scripts/build-dcentrald.sh' \
        'STAGED_STOCK_FPGA' \
        'normal Cargo builds cannot stage the retired stock-FPGA recovery input'
    reject_pattern 'scripts/build-dcentrald.sh' \
        '/dcent-inputs/stock_fpga' \
        'normal Cargo builds cannot mount the retired stock-FPGA recovery input'
    reject_pattern 'scripts/build_inputs.manifest' \
        'pic-recovery/firmware/stock_fpga_s9.bin' \
        'release input policy cannot retain the unconsumed stock FPGA blob'
    reject_pattern 'scripts/build_inputs.manifest' \
        'pic-recovery/firmware/stock_fpga_extracted.bin' \
        'release input policy cannot retain the unconsumed comparison blob'
    require_pattern 'scripts/source_closure.py' \
        'COMMON_CARGO_BUILD_INPUTS = ()' \
        'Cargo external-input evidence truthfully selects an empty file set'
    require_pattern 'scripts/build_in_docker.sh' \
        '--token "$BUILD_INPUT_DESTROY_TOKEN"' \
        'firmware packaging cleanup requires the out-of-band snapshot destruction capability'
    reject_pattern 'scripts/build-dcentrald.sh' \
        '$KNOWLEDGE_BASE_DIR":/knowledge-base:ro' \
        'cross Cargo cannot inspect the full live knowledge-base tree'
    require_pattern 'scripts/build-dcentrald.sh' \
        ':/knowledge-base/firmware-archive/stock-bitmain-manifest.json:ro' \
        'cross Cargo receives only the exact tracked stock manifest input'
    require_pattern 'scripts/build_in_docker.sh' \
        'git -C buildroot status --porcelain --untracked-files=normal' \
        'source closure rejects modified, staged, and untracked warm-volume Buildroot source'
    require_pattern 'scripts/build_in_docker.sh' \
        'source_closure.py" generate' \
        'all Docker image producers emit a source-closure receipt'
    require_pattern '../../.github/workflows/dcentos-image-smoke.yml' \
        'release_producer_evidence.py verify-cohort' \
        'S9 image smoke reauthenticates closure, receipts, inputs, and artifacts after capsule cleanup'
    require_pattern '../../.github/workflows/dcentos-image-smoke.yml' \
        'scripts/release_producer.py verify-cohort-result' \
        'Zynq image smoke authenticates each exact signed producer result'
    require_pattern 'scripts/release_producer_evidence.py' \
        'release_set_publication.DESCRIPTOR_NAME' \
        'producer evidence verifies the final sealed release-set descriptor'
    require_pattern '../../.github/workflows/dcentos-image-smoke.yml' \
        '${{ runner.temp }}/dcentos-image-smoke-${{ github.run_id }}-${{ github.run_attempt }}/releases/' \
        'S9 image smoke uploads the atomic published directory instead of a hand-picked flat sidecar subset'
    require_pattern '../../.github/workflows/dcentos-image-smoke.yml' \
        '--producer s9 --producer am2-s19jpro' \
        'AM2 source-closure audit consumes its exact selected producer result'
}
source_closure_check

# Buildroot package file lists are path claims, not final-content ownership.
# Keep the bounded final-rootfs ledger's deterministic classifier and negative
# controls live in CI without pretending that a fixture proves production image
# attribution or a complete SPDX/CycloneDX SBOM.
rootfs_ownership_ledger_check() {
    require_file 'scripts/rootfs_ownership_ledger.py'
    require_file 'scripts/test_rootfs_ownership_ledger.sh'
    if [ -f 'scripts/test_rootfs_ownership_ledger.sh' ]; then
        if bash 'scripts/test_rootfs_ownership_ledger.sh' >/dev/null 2>&1; then
            pass "final-rootfs ownership ledger is deterministic and keeps ambiguous/unattributed evidence explicit"
        else
            fail "final-rootfs ownership ledger fixture or negative controls regressed"
        fi
    fi
    require_pattern 'scripts/rootfs_ownership_ledger.py' \
        '"is_sbom": False' \
        'rootfs ownership ledger does not overclaim complete SBOM coverage'
    require_pattern 'scripts/rootfs_ownership_ledger.py' \
        'single-buildroot-path-claim;final-content-origin-not-proven' \
        'unique Buildroot package attribution remains explicitly path-claim-only'
}
rootfs_ownership_ledger_check

# Buildroot's own legal-info output is hash-enumerated as a bounded release
# evidence slice. It is artifact-bound and source/license aware, but remains a
# custom partial inventory rather than an SBOM or a license-compliance claim.
buildroot_legal_inventory_check() {
    require_file 'scripts/buildroot_legal_inventory.py'
    require_file 'scripts/test_buildroot_legal_inventory.sh'
    if [ -f 'scripts/test_buildroot_legal_inventory.sh' ]; then
        if bash 'scripts/test_buildroot_legal_inventory.sh' >/dev/null 2>&1; then
            pass "artifact-bound Buildroot legal-info inventory is deterministic and fail-closed"
        else
            fail "Buildroot legal-info inventory fixture or negative controls regressed"
        fi
    fi
    require_pattern 'scripts/buildroot_legal_inventory.py' \
        '"is_sbom": False' \
        'Buildroot legal inventory does not overclaim complete SBOM coverage'
    require_pattern 'scripts/buildroot_legal_inventory.py' \
        '"license_compliance": "not_assessed"' \
        'Buildroot legal inventory does not overclaim license compliance'
    require_pattern 'scripts/buildroot_legal_inventory.py' \
        '"vulnerability_analysis": "not_performed"' \
        'Buildroot legal inventory keeps advisory analysis explicitly unresolved'
    require_pattern 'scripts/build_in_docker.sh' \
        'buildroot_legal_inventory.py generate' \
        'release image producers emit the Buildroot legal-info inventory'
    require_pattern 'scripts/build_in_docker.sh' \
        '--artifact "$BUILDROOT_LEGAL_INVENTORY_PATH"' \
        'signed source-closure receipts bind the Buildroot legal-info inventory'
}
buildroot_legal_inventory_check

# Rust packages are the first dependency-inventory vertical slice. Keep the
# custom schema honest: it is artifact-bound and locked/offline, but does not
# pretend to be a complete SPDX/CycloneDX SBOM for Buildroot firmware.
rust_dependency_inventory_check() {
    require_file 'scripts/rust_dependency_inventory.py'
    require_file 'scripts/test_rust_dependency_inventory.sh'
    if [ -f 'scripts/test_rust_dependency_inventory.sh' ]; then
        if bash 'scripts/test_rust_dependency_inventory.sh' >/dev/null 2>&1; then
            pass "artifact-bound Rust dependency inventory is deterministic and locked offline"
        else
            fail "Rust dependency inventory generation/verification regressed"
        fi
    fi
    require_pattern 'scripts/rust_dependency_inventory.py' \
        '"spdx_conformance": "not_claimed"' \
        'Rust inventory does not overclaim SPDX conformance'
    require_pattern 'scripts/rust_dependency_inventory.py' \
        '"cyclonedx_conformance": "not_claimed"' \
        'Rust inventory does not overclaim CycloneDX conformance'
    require_pattern 'scripts/build_in_docker.sh' \
        'rust_dependency_inventory.py" generate' \
        'release image producers emit the Rust dependency inventory'
    require_pattern 'scripts/build-dcentrald.sh' \
        'cargo metadata --locked --offline --filter-platform' \
        'Rust inventory metadata is emitted locked/offline for the release target'
    require_pattern 'scripts/build-dcentrald.sh' \
        'FROM ${RUST_BUILDER_BASE}' \
        'Rust inventory metadata shares the selected builder base'
    require_pattern 'scripts/build-dcentrald.sh' \
        'builder_image_id=$DCENT_BUILDER_IMAGE_ID' \
        'Rust inventory receipt context binds the inspected builder image ID'
    require_pattern 'scripts/build-dcentrald.sh' \
        '"$DOCKER_IMAGE_ID" \' \
        'Rust inventory build executes the inspected immutable builder image ID'
    require_pattern 'scripts/build_in_docker.sh' \
        '--artifact "$RUST_INVENTORY_PATH"' \
        'source-closure receipt binds the Rust dependency inventory'
    require_pattern '../../.github/workflows/dcentos-image-smoke.yml' \
        'release_producer_evidence.py verify-cohort' \
        'S9 image smoke verifies the closure-bound Rust inventory through retained producer source evidence'
    require_pattern '../../.github/workflows/dcentos-image-smoke.yml' \
        '--producer s9 --producer am2-s19jpro' \
        'AM2 closure-bound Rust inventory is audited with its selected producer result'
}
rust_dependency_inventory_check

# Amlogic first boot uses /data/.firstboot-pending as a write-ahead marker
# before the raw recovery-flag transition. Keep the crash-injection harness in
# the aggregate gate so the marker cannot regress to unchecked truncate/sync or
# a fail-open continuation into flash/env mutation.
amlogic_firstboot_wal_durability_check() {
    require_file 'scripts/test_amlogic_s99upgrade_wal_durability.sh'
    if [ -f 'scripts/test_amlogic_s99upgrade_wal_durability.sh' ]; then
        if bash 'scripts/test_amlogic_s99upgrade_wal_durability.sh' >/dev/null 2>&1; then
            pass "Amlogic firstboot WAL is durable before recovery authority mutation"
        else
            fail "Amlogic firstboot WAL durability/fail-closed harness regressed"
        fi
    fi
    require_pattern \
        'br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S99upgrade' \
        'refusing recovery-flag commit' \
        'Amlogic S99upgrade refuses recovery authority when WAL durability is unproven'
}
amlogic_firstboot_wal_durability_check

# OTA downgrade-floor monotonicity gate. The signed-package shell path must
# never treat an older release version as installable, even when the operator's
# lab downgrade override is present. This host-only test extracts the comparator
# and floor functions from every shipped Zynq sysupgrade overlay and drives a
# local fixture matrix without touching hardware or flash.
ota_version_monotonicity_check() {
    require_file 'scripts/test_ota_version_monotonicity.sh'
    if [ -f 'scripts/test_ota_version_monotonicity.sh' ]; then
        if sh 'scripts/test_ota_version_monotonicity.sh' >/dev/null 2>&1; then
            pass "OTA: sysupgrade version monotonicity matrix green"
        else
            fail "OTA: sysupgrade version monotonicity matrix regressed"
        fi
    fi
}
ota_version_monotonicity_check

# Overlay board_target recognition gate (structural fix for the S19j-Pro-class
# mis-route found 2026-07-03: the canonical `am2-s19jpro-zynq` board_target was
# declared/used but the ZynqVariant resolver did NOT recognize it, silently
# routing a BM1362 board to the S9 fail-safe — wrong chain init at first-light).
# Every Buildroot overlay that stamps /etc/dcentos/board_target MUST have that
# exact string recognized by the daemon: either the zynq ZynqVariant resolver
# (matches the dashed form) OR model.rs board_target_chip_label (matches the
# dash-stripped/normalized form). A newly-added SKU overlay that stamps an
# unrecognized target fails HERE instead of mis-routing on live hardware.
overlay_board_target_recognized_check() {
    _zynq='dcentrald/dcentrald-hal/src/platform/zynq.rs'
    _model='dcentrald/dcentrald/src/model.rs'
    for _f in $(find br2_external_dcentos -path '*/etc/dcentos/board_target' 2>/dev/null | sort); do
        _bt=$(tr -d ' \t\r\n' < "$_f")
        [ -n "$_bt" ] || continue
        _norm=$(printf '%s' "$_bt" | tr -d '-')
        if grep -Fq "\"$_bt\"" "$_zynq" 2>/dev/null || grep -Fq "\"$_norm\"" "$_model" 2>/dev/null; then
            pass "overlay board_target '$_bt' is recognized by the daemon resolver"
        else
            fail "overlay board_target '$_bt' (${_f#br2_external_dcentos/board/}) is NOT recognized by the ZynqVariant resolver or board_target_chip_label — a flashed unit would mis-route to the fail-safe variant"
        fi
    done
}
overlay_board_target_recognized_check

# Controller mutation is not a shipped software capability. Keep this proof in
# one executable semantic test so Cargo membership, dependencies, syscalls,
# dashboard ownership, and stale-binary cleanup cannot drift independently.
controller_diagnostic_boundary_check() {
    require_file 'scripts/test_controller_diagnostic_boundary.py'
    require_file 'dcentrald/dcentrald-api-types/src/dspic_frame.rs'
    require_file 'dcentrald/dcentrald-hal/src/stock_fpga_iic.rs'
    require_pattern 'dcentrald/dcentrald-api-types/src/dspic_frame.rs' \
        'SET_HOST_MAC_ADDRESS_OPCODE: u8 = 0x14' \
        'CONTROLLER-DIAGNOSTICS: canonical API catalog pins 0x14 as SET_HOST_MAC_ADDRESS'
    require_pattern 'dcentrald/dcentrald-hal/src/stock_fpga_iic.rs' \
        'SET_HOST_MAC_ADDRESS: u8 = 0x14' \
        'CONTROLLER-DIAGNOSTICS: HAL catalog independently pins 0x14 as SET_HOST_MAC_ADDRESS'
    local diagnostic_output
    if diagnostic_output="$(python3 'scripts/test_controller_diagnostic_boundary.py' 2>&1)"; then
        pass 'CONTROLLER-DIAGNOSTICS: standalone tools are opt-in and structurally read-only'
    else
        printf '%s\n' "$diagnostic_output" \
            | sed 's/^/ERROR: CONTROLLER-DIAGNOSTICS: /' >&2
        fail 'CONTROLLER-DIAGNOSTICS: standalone diagnostic-only boundary regressed'
    fi
}
controller_diagnostic_boundary_check

# Normal-runtime hardware ownership is process-exclusive. Web adapters and
# post-boot checks consume daemon snapshots; normal REST handlers never open a
# second transport; raw research executors are pruned after every product
# overlay. S99verify observes boot-commit state but never owns its mutation.
runtime_hardware_ownership_check() {
    require_file 'scripts/test_runtime_hardware_ownership.py'
    require_file 'scripts/test_s99verify_commit_authority.sh'
    require_file 'br2_external_dcentos/board/common/prune-runtime-research-tools.sh'
    if python3 'scripts/test_runtime_hardware_ownership.py' >/dev/null 2>&1; then
        pass 'HARDWARE-OWNERSHIP: runtime adapters are snapshot-only and research executors are absent from product rootfs images'
    else
        fail 'HARDWARE-OWNERSHIP: parallel runtime hardware access or release-composition pruning regressed'
    fi
    if sh 'scripts/test_s99verify_commit_authority.sh' >/dev/null 2>&1; then
        pass 'HARDWARE-OWNERSHIP: S99verify observes committed/blocked boot state without durable mutation authority'
    else
        fail 'HARDWARE-OWNERSHIP: S99verify boot-commit authority contract regressed'
    fi
}
runtime_hardware_ownership_check

# Image-content leak gate (2026-10-06): release rootfs images must not carry
# internal lab/workspace details. The common post-build prune runs the scanner
# over every RELEASE TARGET_DIR; this host check keeps the scanner, its
# planted-leak fixtures, and the shipped source overlays themselves clean.
image_content_leak_gate_check() {
    require_file 'scripts/image_content_leak_scan.py'
    require_file 'scripts/test_image_content_leak_scan.py'
    require_pattern 'br2_external_dcentos/board/common/prune-runtime-research-tools.sh' 'image_content_leak_scan.py' 'common release prune runs the image-content leak scanner'
    if python3 'scripts/test_image_content_leak_scan.py' >/dev/null 2>&1; then
        pass 'IMAGE-LEAK: scanner fails planted leaks, passes clean rootfs, and shipped overlays are leak-free'
    else
        fail 'IMAGE-LEAK: image-content leak scanner or shipped overlay cleanliness regressed'
    fi
}
image_content_leak_gate_check

# Recovery-feature manifest/source gate (guarantee #2 from the .74/.139 incident).
# Historical protocol research remains feature-gated inside library crates.
# Cargo features are additive across a resolved graph, so this proves only that
# shipped package manifests do not directly request the feature; source/API
# visibility gates carry the stronger runtime boundary.
recovery_tool_not_in_daemon_check() {
    _dc='dcentrald/dcentrald/Cargo.toml'
    _controller='dcentrald/pic-recovery/Cargo.toml'
    require_file "$_dc"
    require_file "$_controller"
    _hits=$(grep -nE 'recovery-tool' "$_dc" "$_controller" 2>/dev/null | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' || true)
    if [ -z "$_hits" ]; then
        pass "EEPROM/PIC: shipped daemon/controller manifests do not directly enable recovery-tool"
    else
        fail "EEPROM/PIC: a shipped package enables recovery-tool. Offending line(s): $_hits"
    fi
}
recovery_tool_not_in_daemon_check

# Credential-URL log-redaction gate. Caught 5 real leaks 2026-07-03: the Telegram/
# Discord webhook token (x3 sites), the donation pool URL, the bitcoind RPC URL,
# and the MQTT broker URL. A log field whose VALUE is a known credential-bearing
# URL — any `*_rpc_url` (embeds rpcuser:rpcpassword@host), a webhook URL (embeds a
# bot token in the path), or a `.broker` (mqtt://user:pass@host) — must pass
# through a redactor (sanitize_pool_url / sanitize_webhook_url / redact_rpc_url)
# before it reaches the daemon log / support bundle / dashboard log-tail. A
# redactor is a no-op for a credential-free URL, so a new RAW log of one fails
# HERE instead of shipping the secret. (`.broker` matches the raw field access,
# not a pre-sanitized `broker_display` variable.)
credential_url_log_redaction_check() {
    _hits=$(grep -rnE '= %[A-Za-z0-9_:&.()]*(rpc_url|webhook[A-Za-z0-9_.]*url|\.broker\b)' \
        dcentrald/dcentrald/src dcentrald/dcentrald-api/src dcentrald/dcentrald-stratum/src 2>/dev/null \
        | grep -viE 'sanitize_pool_url|sanitize_webhook_url|redact_rpc_url|redact|mask|//|test' || true)
    if [ -z "$_hits" ]; then
        pass "logging: every credential-bearing URL (rpc_url / webhook url) is run through a redactor before logging"
    else
        fail "logging: a credential-bearing URL is logged RAW — leaks rpcuser:rpcpassword@ or a webhook token to logs/support-bundles. Wrap it in sanitize_pool_url / sanitize_webhook_url. Offending: $_hits"
    fi
}
credential_url_log_redaction_check

# Wallet/PII log-masking gate. On Stratum V1 the `worker` field IS the operator's
# Bitcoin wallet/payout address (likewise fallback_worker + coinbase_output_
# address) — logging it raw leaks the operator's address into the daemon log /
# support bundle / dashboard log-tail. Every such field must pass through
# dcentrald_common::wallet_mask::mask_wallet (the load-bearing W1.4 rule). This
# gate caught a raw `worker = %self.config.pool.worker` in stock_mining.rs
# 2026-07-03. mask_wallet is a no-op on an empty value, so a new raw log fails
# HERE instead of shipping the operator's address. (`.worker` matches the raw
# field access, not worker_count / worker_name / a pre-masked variable.)
wallet_log_masking_check() {
    _hits=$(grep -rnE '= %[A-Za-z0-9_:&.()]*(\.worker\b|coinbase_output_address|fallback_worker|payout_address)' \
        dcentrald/dcentrald/src dcentrald/dcentrald-api/src dcentrald/dcentrald-stratum/src 2>/dev/null \
        | grep -viE 'mask_wallet|mask|redact|sanitize|//|test' || true)
    if [ -z "$_hits" ]; then
        pass "logging: every worker/wallet/coinbase-address log field is masked (mask_wallet)"
    else
        fail "logging: an operator wallet/payout address (worker / coinbase_output_address) is logged RAW — leaks the operator's Bitcoin address to logs/support-bundles. Wrap it in dcentrald_common::wallet_mask::mask_wallet. Offending: $_hits"
    fi
}
wallet_log_masking_check

# CI-GATE-CE026 (reverse A/B + AM2 vendor first-install evidence boundary).
# The AM2 sysupgrade harness proves the already-running-DCENT_OS A/B writer in
# both directions. The separate stage1 first-install harness is S9-only: AM2
# has no authenticated source-runtime capsule or persistent-state migration,
# so injecting virtme host tools must never emit a vendor first-install proof.
ce026_reverse_ab_and_am2_first_install_boundary_check() {
    tag='CI-GATE-CE026'
    harness='scripts/sysupgrade_offline_nandsim_harness.sh'
    stage1='scripts/stage1_first_install_offline_nandsim_harness.sh'
    runner='scripts/sysupgrade_offline_virtme_nandsim_runner.sh'
    workflow='../../.github/workflows/dcentos-offline-nandsim.yml'
    capsule_contract='../dcent-toolbox/docs/AM2_FIRST_INSTALL_CAPSULE.md'

    require_file "$harness"
    require_file "$stage1"
    require_file "$runner"
    require_file "$workflow"
    require_file "$capsule_contract"
    if [ ! -f "$harness" ] || [ ! -f "$stage1" ] || [ ! -f "$runner" ] \
        || [ ! -f "$workflow" ] || [ ! -f "$capsule_contract" ]; then
        return
    fi

    # (1) REVERSE A/B in the sysupgrade harness: the --current-fw selector, the
    #     reverse both-slots nandsim layout, and the DISTINCT reverse sentinel.
    #     The default forward path (current-fw=2) stays byte-identical.
    require_pattern "$harness" '--current-fw' \
        "$tag REVERSE: sysupgrade harness exposes the --current-fw {1,2} selector"
    require_pattern "$harness" 'NANDSIM_PARTS_REVERSE' \
        "$tag REVERSE: sysupgrade harness defines the reverse both-slots layout"
    # 2026-08 nandsim profile split: the both-slots S9 emulator tuple moved from
    # a harness literal into the evidence-derived profile authority in
    # scripts/lib/zynq_nandsim_geometry.sh (which the Zynq nandsim geometry gate
    # below pins as subordinate to package authority). Keep requiring the exact
    # reverse-capable tuple at its operative source.
    require_pattern 'scripts/lib/zynq_nandsim_geometry.sh' '1,1,1,1,4,1,1,900,900' \
        "$tag REVERSE: reverse layout provisions BOTH slots (mtd7 + mtd8, 128KiB eraseblocks)"
    require_pattern "$harness" 'OFFLINE_NANDSIM_PROOF_OK target=$TARGET direction=reverse current_fw=1 inactive_mtd=8' \
        "$tag REVERSE: sysupgrade harness emits the distinct reverse sentinel (current_fw=1 inactive_mtd=8)"

    # (2) AM2 FIRST-INSTALL BOUNDARY: the S9 stage1 harness cannot accept an
    #     AM2 target/package or emit an AM2 first-install proof. The missing
    #     capsule remains explicit in the architecture contract.
    require_pattern "$stage1" 'This harness is intentionally S9-only' \
        "$tag AM2-FIRST-INSTALL: stage1 harness declares its S9-only authority"
    reject_pattern "$stage1" 'am2-s19jpro' \
        "$tag AM2-FIRST-INSTALL: stage1 harness has no AM2 target"
    reject_pattern "$stage1" '--am2-package' \
        "$tag AM2-FIRST-INSTALL: stage1 harness has no AM2 package input"
    reject_pattern "$stage1" 'OFFLINE_FIRST_INSTALL_PROOF_OK target=am2' \
        "$tag AM2-FIRST-INSTALL: stage1 harness cannot emit an AM2 proof sentinel"
    require_line_regex "$capsule_contract" '^Status: architecture contract; not implemented$' \
        "$tag AM2-FIRST-INSTALL: capsule contract remains explicitly unimplemented"
    require_pattern "$capsule_contract" 'must refuse before package upload or target mutation' \
        "$tag AM2-FIRST-INSTALL: capsule contract refuses vendor-source mutation"

    # (3) RUNNER COVERAGE + HONEST CI WIRING: the reusable runner retains AM2
    #     DCENT_OS A/B coverage but cannot invoke a vendor first-install path.
    #     The workflow asserts only capsule-backed S9 first-install sentinels
    #     and carries an explicit AM2 blocked disposition.
    require_pattern "$runner" '--current-fw 1 --target am1-s9' \
        "$tag CI-WIRING: runner invokes the am1-s9 reverse-direction guest proof"
    require_pattern "$runner" '--current-fw 1 --target am2-s19jpro' \
        "$tag CI-WIRING: runner invokes the am2-s19jpro reverse-direction guest proof"
    reject_pattern "$runner" '--target am2-s19jpro --am2-package' \
        "$tag CI-WIRING: runner has no synthetic AM2 first-install invocation"
    reject_pattern "$runner" '/tmp/dcent-first-install-proof-am2' \
        "$tag CI-WIRING: runner has no AM2 first-install proof workspace"
    require_pattern "$workflow" "grep -q 'OFFLINE_NANDSIM_PROOF_OK target=am1-s9 direction=reverse'" \
        "$tag CI-WIRING: workflow asserts the am1-s9 reverse sentinel"
    require_pattern "$workflow" "grep -q 'OFFLINE_FIRST_INSTALL_PROOF_OK target=am1-s9'" \
        "$tag CI-WIRING: workflow asserts the am1-s9 first-install sentinel"
    require_pattern "$workflow" '--producer s9 --producer am2-s19jpro' \
        "$tag CI-WIRING: workflow builds the exact S9 and AM2 producer cohort"
    require_pattern "$workflow" '--s19jpro-package "$DCENT_AM2_NANDSIM_PACKAGE"' \
        "$tag CI-WIRING: workflow consumes the exact verified AM2 artifact"
    require_pattern "$workflow" "grep -q 'OFFLINE_NANDSIM_PROOF_OK target=am2-s19jpro direction=reverse'" \
        "$tag CI-WIRING: workflow requires the actual AM2 reverse proof"
    reject_pattern "$workflow" "grep -q 'OFFLINE_FIRST_INSTALL_PROOF_OK target=am2-s19jpro'" \
        "$tag CI-WIRING: workflow does not assert an AM2 first-install proof it cannot build"
}
ce026_reverse_ab_and_am2_first_install_boundary_check

# CE-114: release-image proxy-nonce weak-entropy fail-closed (defense-in-depth).
# (a) every board S80dashboard that keeps the weak date+pid+uptime fallback must
#     release-gate it (reference '/etc/dcentos/release-image' in generate_proxy_nonce
#     so the weak fallback is refused on a release image).
# (b) the dcentrald-api backend refuses to trust a non-64-hex proxy nonce on a
#     release image (auth.rs is_strong_proxy_nonce).
ce114_proxy_nonce_weak_entropy_check() {
    s80_found=0
    s80_missing=''
    for s80 in br2_external_dcentos/board/*/rootfs-overlay/etc/init.d/S80dashboard; do
        [ -f "$s80" ] || continue
        s80_found=$((s80_found + 1))
        if grep -F -- 'date +%s%N' "$s80" >/dev/null 2>&1 \
           && ! grep -F -- '/etc/dcentos/release-image' "$s80" >/dev/null 2>&1; then
            s80_missing="$s80_missing $s80"
        fi
    done
    if [ "$s80_found" -eq 0 ]; then
        fail "CE-114: no board S80dashboard init scripts found (path drift?)"
    elif [ -n "$s80_missing" ]; then
        fail "CE-114 S80dashboard: weak date+pid+uptime proxy-nonce fallback NOT release-gated in:$s80_missing"
    else
        pass "CE-114 S80dashboard: weak proxy-nonce fallback release-gated in all $s80_found scripts"
    fi
    ce114_auth='dcentrald/dcentrald-api/src/auth.rs'
    if [ -f "$ce114_auth" ]; then
        require_pattern "$ce114_auth" 'fn is_strong_proxy_nonce' \
            "CE-114 auth: strong-entropy proxy-nonce validator present"
        require_pattern "$ce114_auth" 'nonce.map(is_strong_proxy_nonce)' \
            "CE-114 auth: release trust path requires a strong-entropy nonce"
    else
        fail "CE-114: dcentrald-api/src/auth.rs not found (path drift?)"
    fi
}
ce114_proxy_nonce_weak_entropy_check

# SIM-HAL: host simulator must remain impossible to reference from a default
# build and absent from every firmware/Buildroot profile. The compile probe is
# a real downstream crate (not a source grep): it imports SimPlatform without
# enabling the feature and MUST fail to compile.
sim_hal_nonshipping_gate() {
    hal_manifest='dcentrald/dcentrald-hal/Cargo.toml'
    platform_mod='dcentrald/dcentrald-hal/src/platform/mod.rs'
    require_pattern "$hal_manifest" 'sim-hal = [' \
        'SIM-HAL: opt-in Cargo feature exists'
    require_pattern 'dcentrald/dcentrald-hal/src/lib.rs' \
        'sim-hal is host-only and must never be compiled into ARM Linux firmware artifacts' \
        'SIM-HAL: ARM Linux firmware compile guard is present'
    require_pattern "$platform_mod" '#[cfg(feature = "sim-hal")]' \
        'SIM-HAL: module export is compile-time gated'

    if grep -R -n --include='*defconfig' --include='*.mk' --include='Config.in' \
        'sim-hal' br2_external_dcentos >/dev/null 2>&1; then
        fail 'SIM-HAL: a Buildroot/release profile enables the host simulator feature'
    else
        pass 'SIM-HAL: no Buildroot/release profile enables the host simulator feature'
    fi

    [ "$STATIC_ONLY" -eq 0 ] || return 0
    sim_rust_toolchain="${DCENT_RUST_TOOLCHAIN:-1.90.0}"
    sim_rustup="$(command -v rustup 2>/dev/null || true)"
    if [ -z "$sim_rustup" ] && [ -x "${HOME:-}/.cargo/bin/rustup" ]; then
        sim_rustup="${HOME}/.cargo/bin/rustup"
    fi
    if [ -z "$sim_rustup" ]; then
        fail 'SIM-HAL compile-fail probe: rustup is unavailable for the pinned toolchain'
        return
    fi
    if ! "$sim_rustup" run "$sim_rust_toolchain" cargo --version >/dev/null 2>&1; then
        fail "SIM-HAL compile-fail probe: pinned Rust toolchain is unavailable: $sim_rust_toolchain"
        return
    fi

    sim_probe_dir=$(mktemp -d "${TMPDIR:-/tmp}/dcent-sim-hal-negative.XXXXXX")
    mkdir -p "$sim_probe_dir/src"
    cat >"$sim_probe_dir/Cargo.toml" <<EOF
[package]
name = "dcent-sim-hal-negative-probe"
version = "0.0.0"
edition = "2021"

[workspace]

[dependencies]
dcentrald-hal = { path = "$PROJECT_DIR/dcentrald/dcentrald-hal" }
EOF
    cat >"$sim_probe_dir/src/main.rs" <<'EOF'
use dcentrald_hal::platform::sim::SimPlatform;

fn main() {
    let _ = std::mem::size_of::<SimPlatform>();
}
EOF
    if "$sim_rustup" run "$sim_rust_toolchain" cargo check --quiet \
        --manifest-path "$sim_probe_dir/Cargo.toml" \
        >"$sim_probe_dir/stdout" 2>"$sim_probe_dir/stderr"; then
        fail 'SIM-HAL compile-fail probe: SimPlatform was linkable without --features sim-hal'
    elif grep -E 'could not find `sim`|unresolved import.*platform::sim' \
        "$sim_probe_dir/stderr" >/dev/null 2>&1; then
        pass 'SIM-HAL compile-fail probe: default dependency cannot reference SimPlatform'
    else
        fail 'SIM-HAL compile-fail probe failed for an unexpected reason (not the feature gate)'
        sed -n '1,80p' "$sim_probe_dir/stderr" >&2
    fi
    rm -rf -- "$sim_probe_dir"
}
sim_hal_nonshipping_gate

# SIM-HAL evidence/contract meta-gates. These are static and host-safe: they
# neither contact a pool nor touch a device. The full VM/nandsim proof remains
# a separate, artifact-bearing CI job because it needs a compatible kernel.
sim_hal_evidence_contract_gates() {
    for script in \
        scripts/sim/bringup_ladder.sh \
        scripts/sim/full_offline_model_proof.sh \
        scripts/sim/virtme_sim_hal_runner.sh \
        scripts/sim/wsl_namespace_sim_hal_runner.sh \
        scripts/sim/wsl_all_model_proof.sh; do
        if bash -n "$script"; then
            pass "SIM-HAL: shell syntax valid for $script"
        else
            fail "SIM-HAL: shell syntax invalid for $script"
        fi
    done
    if python3 scripts/sim/check_sim_tier_honesty.py; then
        pass 'SIM-HAL: S9-S23 declared tiers do not exceed checked evidence'
    else
        fail 'SIM-HAL: tier-honesty matrix failed'
    fi
    if python3 scripts/sim/check_esp_contract_parity.py; then
        pass 'ESP convergence: donation/onboarding contract parity gate passed'
    else
        fail 'ESP convergence: donation/onboarding contract parity gate failed'
    fi

    # A simulator that only runs on a developer workstation is not a release
    # gate.  Pin the executable model proofs to the workflow so they cannot
    # become another orphaned safety suite during CI refactors.
    sim_workflow='../../.github/workflows/dcentos-offline-gates.yml'
    exact_test_runner='scripts/run_exact_cargo_test.sh'
    require_file "$exact_test_runner"
    require_pattern "$exact_test_runner" 'cargo test "$@" "$exact_test" -- --list' \
        'CI exact-test runner inventories the fully qualified contract before execution'
    require_pattern "$exact_test_runner" 'if [ "$match_count" -ne 1 ]; then' \
        'CI exact-test runner rejects missing or ambiguous contracts'
    require_pattern "$exact_test_runner" 'cargo test "$@" "$exact_test" -- --exact --include-ignored' \
        'CI exact-test runner executes the inventoried contract even when it is ignored'
    if sh scripts/test_run_exact_cargo_test.sh; then
        pass 'CI exact-test runner rejects zero/duplicate inventories, includes ignored tests, and propagates Cargo failures'
    else
        fail 'CI exact-test runner behavioral contract failed'
    fi
    reject_pattern "$sim_workflow" ' -- --exact' \
        'CI workflow routes every exact load-bearing Rust contract through the inventory runner'
    require_pattern "$sim_workflow" 'sim-hal-contract:' \
        'SIM-HAL CI: independent executable contract job is present'
    require_pattern "$sim_workflow" \
        'cargo test -p dcentrald-asic --features sim-hal --test golden_init_trace' \
        'SIM-HAL CI: provenance-backed golden initialization traces execute'
    require_pattern "$sim_workflow" \
        'cargo test -p dcentrald --features sim-hal --test sim_s19pro_t2' \
        'SIM-HAL CI: ten-model T2 enumeration/init/share proof executes'
    require_pattern "$sim_workflow" \
        'i2c_service_deadline_tests' \
        'SIM-HAL CI: deadline-aware serialized I2C regression executes'
    require_pattern "$sim_workflow" \
        'cargo test -p dcentrald-hal --features sim-hal --test pic16_admission' \
        'SIM-HAL CI: worker-owned PIC16 batch admission and receipt integration executes'
    require_pattern "$sim_workflow" \
        'cargo test -p dcentrald-asic --features sim-hal --test sim_pic16_runtime' \
        'SIM-HAL CI: PIC16 cold-boot runtime grammar and admission regression executes'
    require_pattern "$sim_workflow" \
        'bash ../scripts/run_filtered_cargo_test.sh -p dcentrald --features sim-hal --bin dcentrald -- hardware_preflight_policy_tests' \
        'SIM-HAL CI: daemon PIC16 controller-admission regression executes'
    require_pattern "$sim_workflow" \
        'bash ../scripts/run_filtered_cargo_test.sh -p dcentrald --features sim-hal --bin dcentrald -- initialized_pic_addrs_tests' \
        'SIM-HAL CI: PIC16 heartbeat membership remains deduplicated'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh i2c::i2c_service_deadline_tests::caller_supplied_privileged_intent_surface_stays_crate_private --locked -p dcentrald-hal --features sim-hal --lib' \
        'SIM-HAL CI: I2C privileged-intent visibility regression executes'
    require_pattern "$sim_workflow" \
        'cargo test -p dcentrald-hal --doc' \
        'SIM-HAL CI: I2C privileged-intent compile-fail contract executes'
    require_pattern "$sim_workflow" \
        'init_heartbeat_ownership_tests' \
        'SIM-HAL CI: initialization-heartbeat ownership regression executes'
    require_pattern "$sim_workflow" \
        'bash ../scripts/run_filtered_cargo_test.sh -p dcentrald --features sim-hal --bin dcentrald -- voltage_mailbox::tests' \
        'SIM-HAL CI: prioritized voltage mailbox lifecycle regressions execute'
    require_pattern "$sim_workflow" \
        'psu_apw12_smbus::tests::power_off' \
        'SIM-HAL CI: PSU safe-off failure and compensation regression executes'
    require_pattern "$sim_workflow" \
        'psu_apw12_smbus::tests::cold_boot' \
        'SIM-HAL CI: partial cold-boot rollback regression executes'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_am2_management_fabric_latch_is_unique_and_rejects_stale_clones --locked -p dcentrald --features sim-hal --bin dcentrald' \
        'SIM-HAL CI: exact AM2 terminal management-fabric latch regression executes'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_am2_guard_retries_real_negative_i2c_barrier_before_any_safe_off_leg --locked -p dcentrald --features sim-hal --bin dcentrald' \
        'SIM-HAL CI: exact AM2 guard retries a real negative terminal barrier before final legs'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::production_apw_state_machine_retains_failed_owner_and_never_replays_receipt --locked -p dcentrald --features sim-hal --bin dcentrald' \
        'SIM-HAL CI: production AM2 APW owner-retention state machine executes'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::joined_actor_panic_is_reported_after_safe_shutdown_without_hiding_primary_error --locked -p dcentrald --bin dcentrald' \
        'CI: joined hardware-actor panic remains a terminal operator-visible error'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh execution_fence::tests::revocation_is_nonblocking_and_rejects_late_commit_before_wait_finishes --locked -p dcentrald --bin dcentrald' \
        'CI: queued terminal writer cannot block a late closed-generation rejection'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh execution_fence::tests::revoked_try_wait_is_pending_without_spawning_and_completes_after_release --locked -p dcentrald --bin dcentrald' \
        'CI: revoked serial execution exposes one-shot nonblocking quiescence evidence'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh execution_fence::tests::panicked_commit_marks_the_quiescent_fence_receipt_dirty --locked -p dcentrald --bin dcentrald' \
        'CI: generic execution records explicit dirty evidence when a commit unwinds'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am2_failure_and_operator_stop_verify_power_off_before_waiting_on_serial_commit_fence --locked -p dcentrald --bin dcentrald' \
        'CI: exact AM2 first-stage cutoff and nonblocking serial revocation ordering executes'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_am2_closeouts_revoke_serial_and_bound_watchdog_before_gpio_cut --locked -p dcentrald --bin dcentrald' \
        'CI: exact AM2 closeouts revoke UART admission and bound watchdog feeds before GPIO I/O'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_route_domain_phase_matrix_is_owner_issued --locked -p dcentrald --bin dcentrald' \
        'CI: exact serial route lifecycle distinguishes never-opened from owner-closed domains'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_route_domain_closeouts_reject_cross_run_pairing_and_duplicate_claims --locked -p dcentrald --bin dcentrald' \
        'CI: exact serial route domains reject duplicate claims and cross-run evidence pairing'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::dropping_opened_route_domains_revokes_uart_and_api_admission --locked -p dcentrald --bin dcentrald' \
        'CI: dropping an opened exact route owner synchronously revokes UART and API admission'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am2_persistent_cut_failure_revokes_serial_before_immediate_retries_and_fence_wait --locked -p dcentrald --bin dcentrald' \
        'CI: exact AM2 persistent GPIO failure cannot delay serial revocation'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am2_serial_fence_timeout_drops_revoked_owner_without_blocking_waiter --locked -p dcentrald --bin dcentrald' \
        'CI: timed-out AM2 serial fence observation retains no detached blocking waiter'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am2_serial_fence_timeout_allows_runtime_drop_before_commit_release --locked -p dcentrald --bin dcentrald' \
        'CI: timed-out AM2 serial fence observation cannot stall Tokio runtime destruction'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am2_serial_fence_never_probes_after_absolute_deadline --locked -p dcentrald --bin dcentrald' \
        'CI: AM2 serial closeout never probes or accepts quiescence after the absolute deadline'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::nopic_and_legacy_shutdown_revoke_before_watchdog_and_cut_before_uart_wait --locked -p dcentrald --bin dcentrald' \
        'CI: NoPic and legacy UART shutdown revoke before waits and cut power before polling'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::nopic_emergency_cut_cannot_be_reused_as_terminal_safeoff_evidence --locked -p dcentrald --bin dcentrald' \
        'CI: NoPic pre-fence emergency cut cannot substitute for terminal checked safe-off evidence'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am2_out_of_band_hard_stop_clears_every_terminal_ownership_flag --locked -p dcentrald --bin dcentrald' \
        'CI: AM2 hard-stop consumes terminal ownership without recursive Drop re-entry'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am2_out_of_band_hard_stop_cannot_drop_assign_or_early_return_live_ownership --locked -p dcentrald --bin dcentrald' \
        'CI: AM2 hard-stop has no drop-assignment, early-return, or live-owner redispatch path'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_dspic_heartbeat_is_bounded_observable_and_terminally_consumed --locked -p dcentrald --bin dcentrald' \
        'CI: exact AM2 BM1362 dsPIC heartbeat failure is bounded and consumed as terminal safe-off intent'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::legacy_serial_topology_refuses_pic_heartbeat_before_spawn --locked -p dcentrald --bin dcentrald' \
        'CI: legacy serial topology cannot mint a PIC-heartbeat actor'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::runtime_thread_join_budget_exceeds_service_heartbeat_call_bound --locked -p dcentrald --bin dcentrald' \
        'CI: serial actor join budget strictly exceeds the service heartbeat call bound'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::cancellation_interrupts_wait_for_runtime_owner_lock --locked -p dcentrald --bin dcentrald' \
        'CI: APW heartbeat cancellation cannot block behind the retained PSU mutex'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh i2c::i2c_service_deadline_tests::published_heartbeat_call_bound_covers_internal_service_deadline --locked -p dcentrald-hal --lib' \
        'CI: HAL public heartbeat call bound covers its internal queue and execution deadline'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh psu::tests::cancellable_heartbeat_stops_during_retry_flush_before_second_read --locked -p dcentrald-hal --lib' \
        'CI: APW heartbeat cancellation stops a retry flush before its second service read'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1398_native_route_consumes_exact_admission_before_generic_hardware --locked -p dcentrald --bin dcentrald' \
        'CI: BM1398 native route fails closed before optional EEPROM observation without exact physical identity'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am2_bm1362_serial_admission::tests::exact_am2_zynq_bm1362_direct_serial_composition_is_admitted --locked -p dcentrald --bin dcentrald' \
        'CI: direct-serial AM2 admission consumes the detector canonical control-board identity'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_admission::tests::exact_am2_zynq_bm1362_hybrid_composition_is_admitted --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid AM2 admission consumes the detector canonical control-board identity'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_execution_fence_rejects_panicked_commit_as_clean_shutdown_evidence --locked -p dcentrald --bin dcentrald' \
        'CI: serial commit panic cannot authorize clean watchdog disarm'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_terminal_physical_io_uses_blocking_workers --locked -p dcentrald --bin dcentrald' \
        'CI: serial terminal PSU, controller, GPIO, and fan I/O cannot park Tokio workers'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh terminal_io_owner::tests::destructor_work_runs_on_the_single_blocking_owner_in_submission_order --locked -p dcentrald --bin dcentrald' \
        'CI: destructor terminal I/O executes FIFO on the dedicated blocking owner'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_guard_destructors_transfer_terminal_io_to_the_blocking_owner --locked -p dcentrald --bin dcentrald' \
        'CI: NoPic and AM2 serial guard Drops cannot perform terminal I/O on Tokio workers'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_run_scope_drop_transfers_io_but_clean_retirement_is_awaited --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid async Drop transfers I/O while clean retirement remains awaited'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::early_cutoff_start_is_recorded_at_the_physical_value_write_boundary --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid cutoff timing starts at the physical sysfs value write boundary'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh platform::am2_controller::tests::am2_s19pro_is_not_admitted_without_independent_physical_identity --locked -p dcentrald-hal --lib' \
        'CI: S19 Pro controller authority is refused without independent physical identity'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh dspic::pic0x89_tests::observed_dspic_endpoint_session_rejects_unknown_and_unmodeled_firmware --locked -p dcentrald-asic --lib' \
        'CI: observed dsPIC session rejects unknown and unmodeled firmware'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh dspic::pic0x89_tests::observed_dspic_endpoint_session_preserves_bound_address_and_firmware_for_all_views --locked -p dcentrald-asic --lib' \
        'CI: observed dsPIC session preserves its exact address and firmware authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh platform::hardware_mutation_gate_tests::terminal_fence_orders_an_entered_commit_before_safe_off_and_rejects_later_commit --locked -p dcentrald-hal --lib' \
        'CI: HAL mutation fence nonblocking probe orders an entered commit before safe-off'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh platform::hardware_mutation_gate_tests::preparatory_lease_timeout_can_still_prove_commit_fence_quiescence --locked -p dcentrald-hal --lib' \
        'CI: HAL distinguishes stale preparatory leases from active final commits'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh platform::hardware_mutation_gate_tests::revocation_rejects_a_waiting_stale_commit_before_the_entered_commit_returns --locked -p dcentrald-hal --lib' \
        'CI: a stale HAL commit rejects immediately after lock-independent revocation'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh platform::hardware_mutation_gate_tests::panicked_commit_mints_dirty_quiescence_evidence_and_rejects_late_mutation --locked -p dcentrald-hal --lib' \
        'CI: HAL commit panic produces dirty quiescence evidence and closes admission'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh platform::hardware_mutation_gate_tests::only_zero_timeout_allows_an_initial_quiescent_observation_at_its_deadline --locked -p dcentrald-hal --lib' \
        'CI: only an initial zero-time quiescent probe may mint evidence at its deadline'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh hardware_mutation_fence::tests::bounded_hardware_mutation_fence_timeout_allows_runtime_drop_before_commit_release --locked -p dcentrald --bin dcentrald' \
        'CI: HAL commit-fence timeout cannot retain Tokio runtime destruction'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh hardware_mutation_fence::tests::hardware_mutation_fence_never_probes_after_absolute_deadline --locked -p dcentrald --bin dcentrald' \
        'CI: HAL commit-fence observer never probes after its absolute deadline'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh hardware_mutation_fence::tests::poisoned_commit_fence_is_negative_clean_shutdown_evidence --locked -p dcentrald --bin dcentrald' \
        'CI: a poisoned HAL fence cannot authorize clean watchdog disarm'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh bounded_nonblocking_probe::tests::immediate_completion_preserves_value_and_strict_timestamp --locked -p dcentrald --bin dcentrald' \
        'CI: shared nonblocking probe accepts an exact timely completion timestamp'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh bounded_nonblocking_probe::tests::completion_at_deadline_is_not_timely --locked -p dcentrald --bin dcentrald' \
        'CI: shared nonblocking probe classifies equality with the deadline as late'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh bounded_nonblocking_probe::tests::pending_state_is_returned_and_never_probed_after_deadline --locked -p dcentrald --bin dcentrald' \
        'CI: shared nonblocking probe retains pending authority without post-deadline probes'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh asic_identity_publication::tests::held_commit_denies_replacement_until_bounded_revocation_retry_succeeds --locked -p dcentrald --bin dcentrald' \
        'CI: unresolved measured composition denies replacement until a bounded retry proves quiescence'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh asic_identity_publication::tests::fast_invalidation_retains_the_exact_token_and_denies_reopening --locked -p dcentrald --bin dcentrald' \
        'CI: fast composition invalidation retains its exact token and closed activation authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh asic_identity_publication::tests::revocation_epoch_exhaustion_still_reclaims_execution_and_identity --locked -p dcentrald --bin dcentrald' \
        'CI: revocation epoch exhaustion remains fail-closed while reclaiming execution and measured identity'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh asic_identity_publication::tests::active_session_drop_with_held_commit_is_nonblocking --locked -p dcentrald --bin dcentrald' \
        'CI: measured composition session Drop never waits for a held physical commit'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh asic_identity_publication::tests::composition_revocation_timeout_allows_runtime_drop_before_commit_release --locked -p dcentrald --bin dcentrald' \
        'CI: bounded composition revocation cannot retain Tokio runtime destruction'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh asic_identity_publication::tests::composition_authority_source_has_no_production_blocking_fence_or_drop_wait --locked -p dcentrald --bin dcentrald' \
        'CI: composition authority and Drop expose no production blocking fence path'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh asic_identity_publication::tests::contended_authority_mutex_respects_deadline_and_runtime_drop --locked -p dcentrald --bin dcentrald' \
        'CI: composition authority mutex contention respects deadline and Tokio runtime destruction'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh asic_identity_publication::tests::cancelled_bounded_revocation_while_authority_busy_closes_commit_generation --locked -p dcentrald --bin dcentrald' \
        'CI: cancellation during authority contention leaves current composition admission closed'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh asic_identity_publication::tests::cancelled_bounded_revocation_after_pending_retains_exclusive_retry_state --locked -p dcentrald --bin dcentrald' \
        'CI: cancellation after pending composition revocation retains exclusive retry state'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh asic_identity_publication::tests::panicked_execution_commit_is_not_clean_composition_revocation_evidence --locked -p dcentrald --bin dcentrald' \
        'CI: measured-runtime commit panic cannot authorize replacement or clean shutdown'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh asic_identity_publication::tests::cancelled_bounded_invalidation_cannot_be_overwritten_by_activation_publish --locked -p dcentrald --bin dcentrald' \
        'CI: cancelled lock-independent composition invalidation cannot be overwritten by activation publication'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh asic_identity_publication::tests::identity_clear_after_deadline_is_not_attributed_to_early_execution_fence --locked -p dcentrald --bin dcentrald' \
        'CI: late identity clearance cannot borrow an earlier execution-fence timestamp'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh daemon::td003_destructive_write_guard_tests::shutdown_fences_internal_execution_before_identity_revocation_and_safe_off --locked -p dcentrald --bin dcentrald' \
        'CI: daemon revokes execution before awaits and fences after task reclamation before safe-off'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh daemon::watchdog_interval_tests::standard_watchdog_disarm_is_owner_admitted_only_inside_teardown_deadline --locked -p dcentrald --bin dcentrald' \
        'CI: standard watchdog owner rejects Disarm outside its admitted teardown deadline'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::thread_guard::tests::completion_first_observed_at_the_deadline_is_not_positive_evidence --locked -p dcentrald --bin dcentrald' \
        'CI: blocking worker completion first observed at the deadline is negative evidence'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::thread_guard::tests::absolute_join_never_rebases_an_expired_deadline --locked -p dcentrald --bin dcentrald' \
        'CI: blocking worker cleanup cannot rebase an already-expired caller deadline'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::thread_guard::tests::fixed_roster_issuance_rejects_duplicate_slots_and_names --locked -p dcentrald --bin dcentrald' \
        'CI: fixed thread-roster issuance rejects duplicate slots and diagnostic identities'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::thread_guard::tests::fixed_roster_conditional_slot_requires_explicit_non_applicability --locked -p dcentrald --bin dcentrald' \
        'CI: conditional thread slots require explicit owner-issued non-applicability'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::thread_guard::tests::fixed_roster_conditional_resolution_matches_discovered_topology --locked -p dcentrald --bin dcentrald' \
        'CI: conditional thread slots must agree with the discovered hardware topology'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::thread_guard::tests::fixed_roster_reservation_drop_and_duplicate_are_terminal_failures --locked -p dcentrald --bin dcentrald' \
        'CI: dropped or duplicate pre-spawn slot reservation permanently denies roster authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::thread_guard::tests::fixed_roster_panic_and_timeout_are_diagnostic_only --locked -p dcentrald --bin dcentrald' \
        'CI: fixed-roster panic and timeout remain diagnostic-only'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::thread_guard::tests::fixed_roster_distinguishes_topology_absence_from_pre_runtime_closeout --locked -p dcentrald --bin dcentrald' \
        'CI: fixed roster distinguishes topology absence from pre-runtime closeout'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::thread_guard::tests::fixed_roster_pre_runtime_closeout_is_issuer_bound --locked -p dcentrald --bin dcentrald' \
        'CI: pre-runtime thread closeout authority remains issuer-bound'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::thread_guard::tests::fixed_roster_runtime_seal_closes_registration_permanently --locked -p dcentrald --bin dcentrald' \
        'CI: exact runtime roster seal permanently closes thread registration'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::thread_guard::tests::fixed_roster_start_failure_cannot_be_reclassified_as_not_admitted --locked -p dcentrald --bin dcentrald' \
        'CI: failed exact actor start cannot be reclassified as pre-runtime absence'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::task_guard::tests::completion_first_observed_at_the_deadline_is_not_positive_evidence --locked -p dcentrald --bin dcentrald' \
        'CI: async task completion first observed at the deadline is negative evidence'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::task_guard::tests::absolute_task_join_never_rebases_an_expired_deadline --locked -p dcentrald --bin dcentrald' \
        'CI: async task cleanup cannot rebase an already-expired caller deadline'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::task_guard::tests::mining_hardware_tasks_are_owned_and_quiesced_before_hardware_teardown --locked -p dcentrald --bin dcentrald' \
        'CI: standard mining hardware tasks are owned and quiesced before hardware teardown'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::teardown_budget::tests::absolute_schedule_is_strict_ordered_checked_and_nonextending --locked -p dcentrald --bin dcentrald' \
        'CI: teardown deadline schedule is strict, checked, and nonextending'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::teardown_budget::tests::budget_is_one_shot_run_and_issuer_bound --locked -p dcentrald --bin dcentrald' \
        'CI: teardown budget is one-shot and watchdog run/issuer bound'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::teardown_budget::tests::sequential_stages_share_one_cleanup_deadline --locked -p dcentrald --bin dcentrald' \
        'CI: sequential teardown stages cannot refresh the cleanup deadline'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::teardown_budget::tests::every_stage_boundary_is_strict --locked -p dcentrald --bin dcentrald' \
        'CI: teardown stage completion exactly at a deadline remains negative evidence'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::teardown_budget::tests::disarm_command_and_completion_reject_pre_budget_timestamps --locked -p dcentrald --bin dcentrald' \
        'CI: teardown stages reject timestamps forged before the shared budget start'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh daemon::td003_destructive_write_guard_tests::terminal_sync_transport_and_fan_io_runs_on_blocking_workers --locked -p dcentrald --bin dcentrald' \
        'CI: synchronous daemon controller, GPIO, and fan shutdown I/O cannot park a Tokio worker'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh tests::legacy_watchdog_cancellation_never_magic_closes_before_safeoff --locked -p dcentrald --bin dcentrald' \
        'CI: legacy watchdog cancellation stops feeds without premature magic close'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh daemon::watchdog_interval_tests::watchdog_selects_prioritize_terminal_control_before_kick_ticks --locked -p dcentrald --bin dcentrald' \
        'CI: watchdog terminal control wins a coincident kick tick'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::watchdog_feed_gate::tests::terminal_close_and_physical_kick_share_one_linearization_boundary --locked -p dcentrald --bin dcentrald' \
        'CI: terminal watchdog closure and physical kicks share one serialized boundary'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::watchdog_feed_gate::tests::physical_deadline_time_is_sampled_only_after_gate_lock_acquisition --locked -p dcentrald --bin dcentrald' \
        'CI: physical watchdog deadline time is sampled inside the serialized kick boundary'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::watchdog_feed_gate::tests::deadline_publication_never_waits_for_a_blocked_physical_kick --locked -p dcentrald --bin dcentrald' \
        'CI: watchdog teardown deadline publication cannot wait behind a blocked physical kick'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::watchdog_feed_gate::tests::lock_free_stop_signal_withholds_every_later_feed_admission --locked -p dcentrald --bin dcentrald' \
        'CI: lock-free crash signal terminally suppresses later watchdog feed admission'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::watchdog_closeout_orders_barriers_quiescence_and_safeoff_before_disarm --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB uses nonblocking final-commit evidence before safe-off and Disarm'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::gpio59_cutoff_receipt_precedes_dspic_and_reset_defense_in_depth --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB checked GPIO59 cutoff precedes shared-controller and reset defense-in-depth work'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::retained_gpio59_cutoff_set_prepares_glitch_free_off_and_owns_the_only_on_transition --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB preconfigures GPIO59 OFF before retaining the sole one-shot ON authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::every_retained_gpio59_lane_can_cut_with_an_independent_file_offset --locked -p dcentrald --bin dcentrald' \
        'CI: every AM3-BB GPIO59 cutoff lane owns an independent file offset'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::retained_gpio59_cutoff_uses_open_inode_after_ordinary_unlink_fixture --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB ordinary-file fixture proves retained GPIO59 cutoff does not reopen a pathname without claiming sysfs-unexport survival'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::emergency_gpio59_cut_before_energization_permanently_revokes_on_authority --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB terminal cutoff publication permanently revokes board-enable assertion authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::panic_gpio59_cut_serializes_with_published_on_writer_and_finishes_low --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB panic cutoff serializes with the sole published ON writer and finishes physically LOW'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::panic_cutoff_iteration_budget_exhausts_when_a_foreign_on_writer_never_retires --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB panic cutoff exhausts its completed-iteration budget fail-closed when a foreign ON writer never retires'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::polarity_drift_is_cut_physically_low_but_refuses_a_checked_receipt --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB raw direction cutoff survives polarity drift without minting false checked evidence'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::raw_cutoff_descriptor_failure_still_revokes_on_authority --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB raw cutoff failure still terminally revokes ON authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::landed_on_write_with_failed_readback_is_immediately_recut --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB landed HIGH is immediately re-cut when checked ON readback fails'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::heartbeat_terminal_error_cuts_gpio59_before_returning_failure --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB heartbeat terminal failure cuts GPIO59 before returning to its caller'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::post_energization_cancellation_never_reports_clean_shutdown --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB post-energization cancellation remains reset-pending and cannot claim clean shutdown'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::stratum_guard_owns_cancellation_before_first_spawn --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB Stratum cancellation and publisher gate are owned before the first spawn can fail'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::stratum_and_cleanup_deadlines_are_strictly_capped --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB Stratum, API, and heartbeat cleanup stages stay under fixed absolute caps'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::mining_loop_top_level_error_is_structurally_pre_spawn --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB top-level errors are structurally limited to the pre-spawn boundary'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::stratum_abort_never_waits_beyond_the_original_absolute_deadline --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB non-cooperative Stratum abort never adds an untimed follow-up join'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::stratum_partial_roster_error_retains_and_aborts_all_owned_tasks --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB partial Stratum rosters retain every task handle until Drop aborts them'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime_policy::tests::ephemeral_policy_requires_the_exact_explicit_value --locked -p dcentrald --bin dcentrald' \
        'CI: ephemeral runtime policy accepts only the exact explicit value 1'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh minimal_app_state_tests::ephemeral_policy_overrides_persistent_audit_sink_and_writes_only_tmpfs --locked -p dcentrald-api --lib' \
        'CI: ephemeral API audit output cannot inherit a persistent sink override'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh tests::f1_only_fully_owned_closeout_arms_use_management_only_on_err --locked -p dcentrald --bin dcentrald' \
        'CI: only routes with complete closeout evidence may enter stable management-only after error'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::concurrent_gpio_export_error_is_accepted_only_after_node_materializes --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB accepts a competing GPIO exporter only after observing its materialized node'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::delayed_gpio_attributes_are_boundedly_observed_after_export --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB bounds delayed sysfs GPIO attribute materialization'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::non_active_high_gpio59_topology_is_refused_before_any_gpio_mutation --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB refuses unsupported GPIO59 polarity before any GPIO mutation'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::retained_gpio59_authority_is_preopened_once_and_panic_cut_runs_first --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB preopens independent cutoff lanes and panic teardown cuts GPIO59 before reset sysfs work'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh platform::beaglebone_cold_boot::tests::cold_boot_v2_refuses_mismatched_prepared_board_enable_before_io --locked -p dcentrald-hal --lib' \
        'CI: AM3-BB cold boot refuses mismatched prepared board-enable authority before hardware I/O'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh platform::hardware_mutation_gate_tests::absolute_mutation_drain_never_rebases_an_expired_deadline --locked -p dcentrald-hal --lib' \
        'CI: hardware-mutation drain closes admission without rebasing an expired deadline'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::admitted_platform_topology_is_captured_once_and_moved_into_the_engine --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB captures admitted platform topology once and moves it into the engine'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::stratum_task_guard_joins_publishers_before_terminal_state --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB joins Stratum router and status publishers before publishing terminal state'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh am3_bb_mining::tests::heartbeat_roster_is_watchdog_issued_reserved_before_spawn_and_manifest_typed --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB reserves its watchdog-issued heartbeat slot before spawn and passes only typed actor authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::normal_shutdown_retires_every_hardware_owner_before_watchdog_disarm --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid shutdown uses bounded API final-commit evidence before safe-off and Disarm'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::hybrid_terminal_safe_off_marker_consumes_watchdog_closeout_receipt --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid management-safe disposition consumes positive watchdog closeout evidence'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::serial_dispatch_rejoins_normal_shutdown_with_retained_pic0x89_session --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid serial-dispatch routes rejoin the sole API/actor/safe-off watchdog closeout pipeline'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::heartbeat_roster_is_watchdog_issued_reserved_before_spawn_and_manifest_typed --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid reserves watchdog-issued PSU/PIC heartbeat slots before spawn and passes only typed actor authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::am2_power_shutdown_evidence_tests::applicable_but_missing_psu_leg_cannot_be_reported_as_graceful --locked -p dcentrald --bin dcentrald' \
        'CI: applicable AM2 shutdown legs cannot be omitted as NotApplicable'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_serial_failure_disposition_requires_positive_watchdog_closeout --locked -p dcentrald --bin dcentrald' \
        'CI: exact serial management-safe disposition requires a positive watchdog closeout receipt'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::local_teardown_request_bounds_feeds_without_actor_acknowledgement --locked -p dcentrald --bin dcentrald' \
        'CI: watchdog teardown deadline is locally visible before actor acknowledgement'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::admission_distinguishes_pre_open_from_post_open_failures --locked -p dcentrald --bin dcentrald' \
        'CI: watchdog admission distinguishes no-open failures from reset-pending post-open outcomes'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::only_opened_or_unknown_admission_carries_reset_pending_marker --locked -p dcentrald --bin dcentrald' \
        'CI: only opened-or-unknown watchdog admission carries the reset-pending marker through error chains'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::watchdog_teardown_request_and_actor_acknowledgement_are_separate_boundaries --locked -p dcentrald --bin dcentrald' \
        'CI: watchdog Teardown publication is synchronous and actor acknowledgement is a separate boundary'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::watchdog_teardown_receipt_timestamp_cannot_launder_late_admission --locked -p dcentrald --bin dcentrald' \
        'CI: watchdog worker timestamp prevents late teardown admission from being laundered by host receipt timing'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::watchdog_teardown_admission_wait_uses_the_original_absolute_deadline --locked -p dcentrald --bin dcentrald' \
        'CI: watchdog teardown admission wait uses the original absolute cutoff-start deadline'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::locally_latched_deadline_accepts_only_its_matching_actor_command --locked -p dcentrald --bin dcentrald' \
        'CI: watchdog locally latched teardown accepts only the identical actor deadline'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::absolute_budget_disarm_uses_the_watchdog_issued_schedule --locked -p dcentrald --bin dcentrald' \
        'CI: watchdog Disarm consumes its own run-bound absolute teardown schedule'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::worker_rejects_disarm_after_absolute_start_deadline_even_before_feed_deadline --locked -p dcentrald --bin dcentrald' \
        'CI: exact watchdog worker revalidates DisarmStart at the physical magic-close boundary'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::disarm_permit_from_another_watchdog_run_is_rejected --locked -p dcentrald --bin dcentrald' \
        'CI: watchdog disarm rejects a complete permit from another run scope'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::same_run_permit_from_another_composition_is_rejected --locked -p dcentrald --bin dcentrald' \
        'CI: watchdog disarm rejects a same-run permit from another hardware composition'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::watchdog_composition_binding_is_single_use --locked -p dcentrald --bin dcentrald' \
        'CI: watchdog hardware-composition binding is one-shot'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::nopic_serial_actor_roster_is_watchdog_issued_and_issuer_bound --locked -p dcentrald --bin dcentrald' \
        'CI: NoPic serial actor roster is watchdog-issued and issuer-bound'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::am2_serial_actor_roster_records_bypass_topology_and_issuer_binding --locked -p dcentrald --bin dcentrald' \
        'CI: AM2 serial actor roster records conditional topology and issuer binding'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::serial_watchdog_admission_cannot_change_composition_after_claim --locked -p dcentrald --bin dcentrald' \
        'CI: exact serial watchdog admission cannot change composition after claim'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::exact_serial_compositions_reject_untyped_mining_admission --locked -p dcentrald --bin dcentrald' \
        'CI: exact serial watchdog Mining rejects admission without typed runtime-actor authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::hybrid_actor_roster_owner_is_single_claim_and_issuer_bound --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid actor roster owner is one-shot and issuer-bound to its route scope'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::am3_actor_roster_owner_is_single_claim_and_issuer_bound --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB actor roster owner is one-shot and issuer-bound to its route scope'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::never_energized_evidence_from_another_run_is_rejected --locked -p dcentrald --bin dcentrald' \
        'CI: AM2 pre-energization close authority rejects another watchdog run'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::task_guard::tests::standard_roster_rejects_every_slot_never_started --locked -p dcentrald --bin dcentrald' \
        'CI: standard mining roster cannot authorize a run that never owned its required dispatcher'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::task_guard::tests::standard_roster_receipt_is_run_and_issuer_bound --locked -p dcentrald --bin dcentrald' \
        'CI: standard mining actor receipt is run- and issuer-bound'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::task_guard::tests::standard_roster_terminalization_is_one_shot_and_closes_spawn_admission --locked -p dcentrald --bin dcentrald' \
        'CI: standard mining actor terminalization is one-shot and closes spawn admission'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::task_guard::tests::standard_roster_timeout_returns_diagnostics_without_authority --locked -p dcentrald --bin dcentrald' \
        'CI: standard mining actor timeout remains diagnostic-only'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::task_guard::tests::standard_roster_panic_is_quiescent_but_not_clean_disarm_authority --locked -p dcentrald --bin dcentrald' \
        'CI: standard mining actor panic is quiescent but cannot authorize clean watchdog Disarm'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::standard_disarm_permit_uses_watchdog_issued_actor_authority --locked -p dcentrald --bin dcentrald' \
        'CI: standard watchdog terminal authority is bound to its watchdog-issued actor and unit-closeout identities'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh daemon::standard_closeout_tests::standard_unit_closeout_receipts_are_one_shot_run_and_issuer_bound --locked -p dcentrald --bin dcentrald' \
        'CI: standard unit closeout receipts are one-shot and watchdog run/issuer bound'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh daemon::standard_closeout_tests::standard_unit_closeout_rejects_cross_run_and_mixed_issuer_receipts --locked -p dcentrald --bin dcentrald' \
        'CI: standard unit closeout rejects mixed issuers and cross-run receipt substitution'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh daemon::standard_closeout_tests::standard_shutdown_source_has_no_remintable_unit_closeout_markers --locked -p dcentrald --bin dcentrald' \
        'CI: standard shutdown contains no remintable zero-sized closeout markers'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh runtime::safety_watchdog::tests::production_watchdog_disarm_uses_only_move_only_exact_route_manifests --locked -p dcentrald --bin dcentrald' \
        'CI: every nonstandard production watchdog route consumes an exact move-only evidence manifest'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1362_apw_heartbeat_retries_only_wire_exhaustion_and_fails_typed_authority --locked -p dcentrald --bin dcentrald' \
        'CI: BM1362 direct APW heartbeat retries only typed ordinary-wire exhaustion'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1362_apw_heartbeat_threshold_retries_terminates_and_recovers --locked -p dcentrald --bin dcentrald' \
        'CI: BM1362 direct APW ordinary-wire retry budget is bounded and recoverable'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am2_apw_stabilization_observes_terminal_exit_before_hardware_bringup_continues --locked -p dcentrald --bin dcentrald' \
        'CI: APW terminal receipt cancels exact BM1362 hardware bring-up during stabilization'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am2_checked_teardown_retains_failed_leg_owners_and_retries_composite_evidence --locked -p dcentrald --bin dcentrald' \
        'CI: AM2 teardown cuts retained dsPIC endpoints independently of aggregate APW evidence'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am2_apw_stabilization_closed_channel_preserves_ordinary_shutdown --locked -p dcentrald --bin dcentrald' \
        'CI: closed APW exit channel preserves an already-active ordinary shutdown diagnosis'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am2_apw_stabilization_timer_boundary_preserves_shutdown_attribution --locked -p dcentrald --bin dcentrald' \
        'CI: APW stabilization timer boundary preserves ordinary shutdown attribution'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am2_apw_actor_unexpected_exit_cancels_lifecycle_and_publishes_reason --locked -p dcentrald --bin dcentrald' \
        'CI: unexpected APW heartbeat actor loss cancels lifecycle and remains diagnosable'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh daemon_lifecycle::tests::safe_off_error_forbids_the_management_plane --locked -p dcentrald --bin dcentrald' \
        'CI: safe-off failure forbids management-only lifecycle recovery'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am2_apw_terminal_publication_does_not_relabel_ordinary_shutdown --locked -p dcentrald --bin dcentrald' \
        'CI: in-flight APW failure cannot relabel an already-active ordinary shutdown'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_serial_actor_topology_rejects_controller_conflicts_before_route_use --locked -p dcentrald --bin dcentrald' \
        'CI: exact serial actor topology rejects contradictory controller evidence before route use'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_serial_io_rejects_alternate_actor_before_spawn_closure --locked -p dcentrald --bin dcentrald' \
        'CI: exact serial roster rejects an alternate actor before its spawn closure runs'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_serial_actor_rosters_reserve_before_spawn_and_feed_typed_manifests --locked -p dcentrald --bin dcentrald' \
        'CI: exact serial actors reserve before spawn and feed typed watchdog manifests'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_serial_pre_runtime_closeout_classifies_only_untouched_actor_slots --locked -p dcentrald --bin dcentrald' \
        'CI: exact serial pre-runtime closeout classifies only untouched conditional actor slots'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_serial_actor_closeout_requires_matching_route_domain_authority --locked -p dcentrald --bin dcentrald' \
        'CI: exact serial actor closeout requires matching route-domain authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_serial_runtime_actor_admission_requires_promoted_execution_and_same_roster --locked -p dcentrald --bin dcentrald' \
        'CI: exact serial runtime actors require promoted execution and their issuing roster'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_serial_runtime_actor_admission_closes_as_joined_after_typed_mining_permit --locked -p dcentrald --bin dcentrald' \
        'CI: exact serial Mining permit closes runtime actors as joined evidence'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_am2_actor_topology_is_power_bound_and_failed_start_stays_negative --locked -p dcentrald --bin dcentrald' \
        'CI: exact AM2 actor topology is power-bound and failed starts remain negative evidence'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_am2_reset_closeout_distinguishes_never_attempted_from_serial_barrier --locked -p dcentrald --bin dcentrald' \
        'CI: exact AM2 reset closeout distinguishes never-attempted from serial-barrier evidence'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_am2_reset_mutation_is_route_bound_read_back_and_manifested --locked -p dcentrald --bin dcentrald' \
        'CI: exact AM2 reset mutation is route-bound, read back, and terminally manifested'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_am2_dspic_safeoff_distinguishes_never_armed_from_lost_armed_owner --locked -p dcentrald --bin dcentrald' \
        'CI: exact AM2 dsPIC safe-off distinguishes never armed from lost armed authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh board_control::tests::exact_am2_reset_receipt_requires_assert_and_release_register_readback --locked -p dcentrald-hal --lib' \
        'CI: exact AM2 reset receipt requires asserted and released register readback'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_serial_invariant_failures_preserve_ordered_safety_legs --locked -p dcentrald --bin dcentrald' \
        'CI: exact serial invariant failures preserve every independent terminal safety leg'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_serial_session_closeout_distinguishes_pending_observing_and_executing --locked -p dcentrald --bin dcentrald' \
        'CI: exact serial session closeout distinguishes never-observed, observation-only, and executing phases'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_serial_session_promotion_mismatch_restores_observation_and_revokes_late_work --locked -p dcentrald --bin dcentrald' \
        'CI: failed exact serial promotion restores observation authority for ordered revocation'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_serial_session_rejects_cross_session_observation_facade --locked -p dcentrald --bin dcentrald' \
        'CI: exact serial observation facade is issuer-bound and cannot cross sessions'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_serial_raw_observation_is_restricted_and_promoted_without_reopen --locked -p dcentrald --bin dcentrald' \
        'CI: exact raw UART observation remains restricted to one promotable session'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_actor_publishes_ownership_only_after_physical_send --locked -p dcentrald --bin dcentrald' \
        'CI: S19k actor publishes ownership only after physical UART commit'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_actor_orders_physical_commit_before_following_rx --locked -p dcentrald --bin dcentrald' \
        'CI: S19k actor orders physical UART commit before subsequent receive'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_actor_does_not_publish_failed_tx_and_receipts_partial_commit --locked -p dcentrald --bin dcentrald' \
        'CI: S19k actor refuses failed TX ownership publication and records partial commit'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_job_attribution_variants_preserve_retry_order_and_identity --locked -p dcentrald --bin dcentrald' \
        'CI: S19k job attribution preserves retry ordering and job identity'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::track1_watchdog_liveness_requires_fresh_complete_thermal_and_tach_proof --locked -p dcentrald --bin dcentrald' \
        'CI: Track-1 watchdog liveness requires fresh complete thermal and tach proof'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::track1_watchdog_sla_requires_exact_30_30_5 --locked -p dcentrald --bin dcentrald' \
        'CI: Track-1 watchdog SLA remains exact at 30s thermal, 30s tach, and 5s confirmation'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::nopic_panic_fans_coast_only_after_checked_cut --locked -p dcentrald --bin dcentrald' \
        'CI: NoPic panic fans coast only after checked power cut'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_clean_gate_uses_header_resolved_attribution --locked -p dcentrald --bin dcentrald' \
        'CI: S19k clean gate uses header-resolved attribution'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_partial_receipt_cannot_publish_global_ownership --locked -p dcentrald --bin dcentrald' \
        'CI: S19k partial receipt cannot publish global ownership'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_runtime_drains_actor_events_before_terminal_exit --locked -p dcentrald --bin dcentrald' \
        'CI: S19k runtime drains actor events before terminal exit'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::track1_closeout_source_fences_panic_planned_stop_and_question_mark_exits --locked -p dcentrald --bin dcentrald' \
        'CI: Track-1 closeout source fences panic, planned stop, and question-mark exits'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::track1_watchdog_accepts_only_positive_armed_admission --locked -p dcentrald --bin dcentrald' \
        'CI: Track-1 watchdog accepts only positive armed admission'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::track1_bosminer_identity_binds_pid_start_comm_and_executable --locked -p dcentrald --bin dcentrald' \
        'CI: Track-1 bosminer identity binds PID start time, comm, and executable'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_endpoint_observability_keeps_raw_frame_and_valid_nonce_clocks_distinct --locked -p dcentrald --bin dcentrald' \
        'CI: S19k endpoint observability keeps raw-frame and admitted-nonce clocks distinct'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_multi_uart_actor_io_is_bound_to_exact_execution_fence --locked -p dcentrald --bin dcentrald' \
        'CI: S19k multi-UART actor I/O remains bound to one exact execution fence'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_share_result_sidecar_bounds_history_and_counts_eviction --locked -p dcentrald --bin dcentrald' \
        'CI: S19k share-result sidecar bounds history and counts eviction'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_share_result_sidecar_consumes_exact_payload_once --locked -p dcentrald --bin dcentrald' \
        'CI: S19k share-result sidecar consumes each exact payload once'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_track1_route_is_distinct_fenced_and_api_denied --locked -p dcentrald --bin dcentrald' \
        'CI: S19k Track-1 route remains distinct, fenced, and API-denied'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_watchdog_requires_recent_history_admitted_nonce_on_every_active_tx_path --locked -p dcentrald --bin dcentrald' \
        'CI: S19k watchdog requires recent admitted nonce history on every active TX path'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_wrap_epoch_advances_only_in_physical_commit_consumer --locked -p dcentrald --bin dcentrald' \
        'CI: S19k wrap epoch advances only in the physical-commit consumer'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_stale_epoch_commit_retires_under_present_authority --locked -p dcentrald --bin dcentrald' \
        'CI: S19k stale-epoch commit retires under present authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::track1_live_identity_command_is_bounded_and_reaps_a_hung_probe --locked -p dcentrald --bin dcentrald' \
        'CI: Track-1 live-identity command is bounded and reaps a hung probe'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::track1_live_identity_parsers_pin_cpu_mtd_and_profile_aware_v2_transcripts --locked -p dcentrald --bin dcentrald' \
        'CI: Track-1 live-identity parsers pin CPU, MTD, two profiles, and v2 transcript evidence'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::track1_live_identity_reader_refuses_symlink_and_oversize_file --locked -p dcentrald --bin dcentrald' \
        'CI: Track-1 live-identity reader refuses symlink and oversized inputs'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::track1_live_model_accepts_902_903_mix_and_refuses_invalid_shapes --locked -p dcentrald --bin dcentrald' \
        'CI: Track-1 live model refuses mixed SKU, count, address, and alias identity shapes'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::track1_live_profiles_refuse_all_non_exact_eeprom_populations --locked -p dcentrald --bin dcentrald' \
        'CI: Track-1 live profiles refuse all non-exact EEPROM populations'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1366_native_cold_executor_is_exact_multi_uart_and_owner_gated --locked -p dcentrald --bin dcentrald' \
        'CI: native BM1366 cold executor is exact multi-UART and owner-gated'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1366_native_post_baud_admission_requires_exact_host_pair_and_fresh_geometry --locked -p dcentrald --bin dcentrald' \
        'CI: native BM1366 post-baud admission requires the exact host pair and fresh geometry'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1366_native_route_requires_configured_request_then_evidence_joined --locked -p dcentrald --bin dcentrald' \
        'CI: native BM1366 route is configured and evidence-joined'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_native_cold_start_opt_in_is_strict_and_never_the_token_issuer --locked -p dcentrald --bin dcentrald' \
        'CI: S19k native cold-start opt-in is strict and cannot issue authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_native_configured_dispatch_needs_no_extra_environment_flag --locked -p dcentrald --bin dcentrald' \
        'CI: S19k native identity s19k_native_configured_dispatch_needs_no_extra_environment_flag'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::s19k_native_identity::tests::native_identity_decodes_held_page_for_every_nonempty_population --locked -p dcentrald --bin dcentrald' \
        'CI: S19k native identity native_identity_decodes_held_page_for_every_nonempty_population'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::s19k_native_identity::tests::native_identity_decodes_every_mixed_and_homogeneous_supported_slot_map --locked -p dcentrald --bin dcentrald' \
        'CI: S19k native identity native_identity_decodes_every_mixed_and_homogeneous_supported_slot_map'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::s19k_native_identity::tests::native_identity_refuses_wrong_controller_population_and_corrupt_pages --locked -p dcentrald --bin dcentrald' \
        'CI: S19k native identity native_identity_refuses_wrong_controller_population_and_corrupt_pages'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::s19k_native_identity::tests::same_header_bm1366_xp_is_not_an_s19k_board --locked -p dcentrald --bin dcentrald' \
        'CI: S19k native identity same_header_bm1366_xp_is_not_an_s19k_board'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_native_cooling_pins_all_four_channels_at_2000_rpm --locked -p dcentrald --bin dcentrald' \
        'CI: S19k native cooling pins four channels at the 2000 RPM floor'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_native_mapping_and_panic_closeout_are_not_generic_nopic --locked -p dcentrald --bin dcentrald' \
        'CI: S19k native mapping and panic closeout remain isolated from generic NoPic'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_native_owner_timeline_rejects_stale_pre_and_post_evidence --locked -p dcentrald --bin dcentrald' \
        'CI: S19k native owner timeline rejects stale pre- and post-evidence'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_native_route_requires_an_exact_ordered_population_subset --locked -p dcentrald --bin dcentrald' \
        'CI: S19k native route requires an exact ordered population subset'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_bounded_work_cli_must_match_the_immutable_runtime_binding --locked -p dcentrald --bin dcentrald' \
        'CI: S19k bounded-work CLI is bound to immutable runtime authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_bounded_work_completion_requires_every_required_uart --locked -p dcentrald --bin dcentrald' \
        'CI: S19k bounded-work completion requires every required UART'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_bounded_work_incomplete_closeout_is_a_terminal_error --locked -p dcentrald --bin dcentrald' \
        'CI: S19k incomplete bounded-work closeout is terminal'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_bounded_work_rx_evidence_reconstructs_the_complete_wire_frame --locked -p dcentrald --bin dcentrald' \
        'CI: S19k bounded-work RX evidence reconstructs the complete wire frame'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_endurance_segments_use_interval_not_lifetime_hashrate --locked -p dcentrald --bin dcentrald' \
        'CI: S19k endurance segments use interval rather than lifetime hashrate'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_endurance_work_cli_must_match_the_immutable_runtime_binding --locked -p dcentrald --bin dcentrald' \
        'CI: S19k endurance CLI is bound to immutable runtime authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_guarded_unlink_durable_replace_is_ordered_and_crash_resumable --locked -p dcentrald --bin dcentrald' \
        'CI: S19k durable guarded replacement is ordered and crash-resumable'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_guarded_unlink_is_inode_bound_and_crash_resumable --locked -p dcentrald --bin dcentrald' \
        'CI: S19k guarded unlink is inode-bound and crash-resumable'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_guarded_unlink_rejects_symlink_type_mode_and_owner --locked -p dcentrald --bin dcentrald' \
        'CI: S19k guarded unlink rejects symlink, type, mode, and owner drift'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_no_work_actor_refuses_any_queued_uart_transmit --locked -p dcentrald --bin dcentrald' \
        'CI: S19k no-work actor refuses every queued UART transmit'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_no_work_cli_must_match_the_immutable_runtime_binding --locked -p dcentrald --bin dcentrald' \
        'CI: S19k no-work CLI is bound to immutable runtime authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_production_endurance_never_grants_itself_bounded_bench_completion --locked -p dcentrald --bin dcentrald' \
        'CI: S19k production endurance cannot grant bounded-bench completion'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_bounded_proof_credits_duplicate_rx_paths_on_pool_accept --locked -p dcentrald --bin dcentrald' \
        'CI: S19k bounded proof credits duplicate RX paths only on pool accept'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_coverage_denial_detail_renders_duplicate_and_off_plan_addresses --locked -p dcentrald --bin dcentrald' \
        'CI: S19k coverage denial renders duplicate and off-plan addresses'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_missing_plan_addresses_diffs_and_refuses_off_plan_windows --locked -p dcentrald --bin dcentrald' \
        'CI: S19k missing plan addresses diff refuses off-plan windows'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_salvage_plan_prefix_window_accepts_exact_plan_with_unparseable_tail --locked -p dcentrald --bin dcentrald' \
        'CI: S19k salvage prefix window accepts exact plan with unparseable tail'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_salvage_plan_prefix_window_never_hides_a_parseable_tail_frame --locked -p dcentrald --bin dcentrald' \
        'CI: S19k salvage prefix window never hides a parseable tail frame'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_salvage_plan_prefix_window_refuses_bad_frame_inside_the_plan --locked -p dcentrald --bin dcentrald' \
        'CI: S19k salvage prefix window refuses bad frame inside the plan'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_salvage_plan_prefix_window_refuses_non_rejected_error_kinds --locked -p dcentrald --bin dcentrald' \
        'CI: S19k salvage prefix window refuses non-rejected error kinds'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_salvage_plan_prefix_window_replays_attempt9_tty_s1_coverage_windows --locked -p dcentrald --bin dcentrald' \
        'CI: S19k salvage prefix window replays attempt-9 ttyS1 coverage windows'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_track1_address_ladder_paces_each_set_address_step_like_the_stock_jig --locked -p dcentrald --bin dcentrald' \
        'CI: S19k Track-1 ladder paces each SetAddress like the stock jig'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_track1_coverage_retry_reenrolls_unclaimed_plan_addresses_before_next_probe --locked -p dcentrald --bin dcentrald' \
        'CI: S19k Track-1 coverage retry re-enrolls unclaimed plan addresses'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_track1_duplicate_rx_share_credit_requires_submitted_or_accepted_share --locked -p dcentrald --bin dcentrald' \
        'CI: S19k Track-1 duplicate RX share credit requires a submitted share'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_track1_wrap_retired_no_clean_submit_allows_only_never_cleaned_sessions --locked -p dcentrald --bin dcentrald' \
        'CI: S19k Track-1 wrap-retired no-clean allows only never-cleaned sessions'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::track1_reenrollment_and_coverage_back_onto_the_shared_serial_chain_contract --locked -p dcentrald --bin dcentrald' \
        'CI: Track-1 re-enrollment and coverage stay rebased onto the shared serial-chain contract'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::track1_ladder_cadence_is_representable_in_the_shared_paced_policy --locked -p dcentrald --bin dcentrald' \
        'CI: Track-1 ladder cadence stays representable in the shared paced-enumeration policy'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::track1_inherited_unread_voltage_is_published_as_unknown --locked -p dcentrald --bin dcentrald' \
        'CI: Track-1 inherited unread voltage remains explicitly unknown'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::track1_j3_is_exact_kernel_all_thread_authority --locked -p dcentrald --bin dcentrald' \
        'CI: Track-1 J3 is exact kernel all-thread authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_hybrid_zero_celsius_is_classified_missing --locked -p dcentrald --features sim-hal --bin dcentrald' \
        'CI: AM2 hybrid zero Celsius remains missing rather than fabricated telemetry'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::hybrid_run_wires_mining_alert_monitor --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid runtime wires the mining-alert monitor'
    # Work-dispatch admission lifecycle + serial safety must-wire (2026-07-29).
    # Sibling work_dispatch_admission_tests modules (not under tests::) + BIP320 /
    # hash_on_disconnect honesty. Pin kept in check_work_dispatch_ci_coverage.py.
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::work_dispatch_admission_tests::serial_watchdog_state_maps_ownership --locked -p dcentrald --bin dcentrald' \
        'CI: serial work-dispatch maps watchdog ownership states'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::work_dispatch_admission_tests::serial_heartbeat_nopic_and_passthrough_require_none --locked -p dcentrald --bin dcentrald' \
        'CI: serial NoPic/passthrough heartbeat requirement is none'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::work_dispatch_admission_tests::serial_admit_green_succeeds --locked -p dcentrald --bin dcentrald' \
        'CI: serial admit succeeds when watchdog+HB+thermal green'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::work_dispatch_admission_tests::serial_admit_refuses_failed_dspic_heartbeat --locked -p dcentrald --bin dcentrald' \
        'CI: serial admit refuses failed dsPIC heartbeat'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::work_dispatch_admission_tests::serial_admit_refuses_watchdog_unavailable --locked -p dcentrald --bin dcentrald' \
        'CI: serial admit refuses unavailable watchdog'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::work_dispatch_admission_tests::serial_terminal_revoke_blocks_re_admit_until_teardown --locked -p dcentrald --bin dcentrald' \
        'CI: serial terminal revoke blocks re-admit until teardown'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::work_dispatch_admission_tests::serial_run_owns_lifecycle_and_calls_shipped_adapters --locked -p dcentrald --bin dcentrald' \
        'CI: serial run owns WorkDispatchLifecycle and shipped adapters'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::work_dispatch_admission_tests::hybrid_watchdog_state_maps_config_and_mining_enter --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid work-dispatch maps watchdog ownership states'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::work_dispatch_admission_tests::hybrid_heartbeat_passthrough_requires_none --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid passthrough heartbeat requirement is none'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::work_dispatch_admission_tests::hybrid_admit_green_succeeds --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid admit succeeds when pillars green'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::work_dispatch_admission_tests::hybrid_admit_refuses_failed_pic_heartbeat --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid admit refuses failed PIC heartbeat'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::work_dispatch_admission_tests::hybrid_admit_refuses_thermal_not_ready --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid admit refuses thermal not-ready'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::work_dispatch_admission_tests::hybrid_terminal_revoke_blocks_re_admit_until_teardown --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid terminal revoke blocks re-admit until teardown'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::work_dispatch_admission_tests::hybrid_run_owns_lifecycle_and_calls_shipped_adapters --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid run owns WorkDispatchLifecycle and shipped adapters'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh stock_mining::work_dispatch_admission_tests::stock_nonce2_beta_gate_is_explicit_and_fail_closed --locked -p dcentrald --bin dcentrald' \
        'CI: stock nonce2 beta gate is explicit and fail-closed'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh stock_mining::work_dispatch_admission_tests::stock_nonce2_beta_refusal_precedes_all_device_access --locked -p dcentrald --bin dcentrald' \
        'CI: stock nonce2 beta refusal precedes all device access'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh stock_mining::work_dispatch_admission_tests::stock_nonce2_beta_suppresses_every_uncorrelated_pool_submission --locked -p dcentrald --bin dcentrald' \
        'CI: stock nonce2 beta suppresses every uncorrelated pool submission'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh stock_mining::work_dispatch_admission_tests::stock_pool_route_and_job_domain_refuse_sv2_standard_before_work --locked -p dcentrald --bin dcentrald' \
        'CI: stock pool route and job domain refuse SV2 standard before work'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh stock_mining::work_dispatch_admission_tests::stock_v1_route_refusal_precedes_all_device_access --locked -p dcentrald --bin dcentrald' \
        'CI: stock V1 route refusal precedes all device access'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh stock_mining::work_dispatch_admission_tests::retained_live_receipt_is_revalidated_before_any_device_access --locked -p dcentrald --bin dcentrald' \
        'CI: stock retained live receipt is revalidated before any device access'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh stock_mining::work_dispatch_admission_tests::stock_watchdog_state_maps_config_and_kicker_presence --locked -p dcentrald --bin dcentrald' \
        'CI: stock work-dispatch maps watchdog/kicker states'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh stock_mining::work_dispatch_admission_tests::admit_before_work_dispatch_succeeds_when_pillars_green --locked -p dcentrald --bin dcentrald' \
        'CI: stock admit succeeds when pillars green'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh stock_mining::work_dispatch_admission_tests::admit_refuses_failed_initial_pic_heartbeat --locked -p dcentrald --bin dcentrald' \
        'CI: stock admit refuses failed initial PIC heartbeat'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh stock_mining::work_dispatch_admission_tests::admit_refuses_when_soc_watchdog_enabled_but_kicker_missing --locked -p dcentrald --bin dcentrald' \
        'CI: stock admit refuses missing kicker when SoC WDT enabled'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh stock_mining::work_dispatch_admission_tests::terminal_revoke_on_heartbeat_failure_blocks_re_admit_and_cuts_hash_first --locked -p dcentrald --bin dcentrald' \
        'CI: stock terminal revoke cuts hash first and blocks re-admit'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh stock_mining::work_dispatch_admission_tests::operator_shutdown_revoke_also_stops_feed_and_parks_fans --locked -p dcentrald --bin dcentrald' \
        'CI: stock operator shutdown stops feed and parks fans'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh stock_mining::work_dispatch_admission_tests::stock_run_owns_lifecycle_and_calls_shipped_admit_revoke_adapters --locked -p dcentrald --bin dcentrald' \
        'CI: stock run owns WorkDispatchLifecycle and shipped adapters'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh daemon::work_dispatch_admission_tests::daemon_watchdog_state_maps_config_and_feed_owner --locked -p dcentrald --bin dcentrald' \
        'CI: daemon work-dispatch maps watchdog/feed-owner states'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh daemon::work_dispatch_admission_tests::daemon_admit_green_succeeds_with_initialized_pics --locked -p dcentrald --bin dcentrald' \
        'CI: daemon admit succeeds when pillars green'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh daemon::work_dispatch_admission_tests::daemon_nopic_empty_controllers_uses_none_required --locked -p dcentrald --bin dcentrald' \
        'CI: daemon NoPic empty controllers use NoneRequired heartbeat'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh daemon::work_dispatch_admission_tests::daemon_admit_refuses_failed_pic_heartbeat --locked -p dcentrald --bin dcentrald' \
        'CI: daemon admit refuses failed PIC heartbeat'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh daemon::work_dispatch_admission_tests::daemon_admit_refuses_when_soc_watchdog_enabled_but_feed_owner_missing --locked -p dcentrald --bin dcentrald' \
        'CI: daemon admit refuses missing feed owner when SoC WDT enabled'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh daemon::work_dispatch_admission_tests::daemon_admit_refuses_thermal_emergency --locked -p dcentrald --bin dcentrald' \
        'CI: daemon admit refuses thermal emergency'
    # Work-domain refactor admission coverage (registered 2026-08-02). These four
    # tests shipped in stock_mining.rs / daemon.rs on 2026-07-30 but were never
    # wired into the workflow or this inventory, which is what the work-dispatch
    # coverage gate was reporting. Registered only after the bin crate was made
    # to compile and all four were OBSERVED passing.
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh daemon::work_dispatch_admission_tests::daemon_thermal_requires_measured_startup_and_latch_dominates --locked -p dcentrald --bin dcentrald' \
        'CI: daemon thermal requires measured startup and latch dominates'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh daemon::work_dispatch_admission_tests::daemon_terminal_revoke_blocks_re_admit_and_cuts_hash_first --locked -p dcentrald --bin dcentrald' \
        'CI: daemon terminal revoke cuts hash first and blocks re-admit'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh daemon::work_dispatch_admission_tests::daemon_run_owns_lifecycle_and_admits_before_work_dispatcher --locked -p dcentrald --bin dcentrald' \
        'CI: daemon run owns WorkDispatchLifecycle and admits before WorkDispatcher'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_job_id_steps_and_wrap_match_each_supported_family --locked -p dcentrald --bin dcentrald' \
        'CI: L08 serial_job_id_steps_and_wrap_match_each_supported_family'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_job_id_rejects_unknown_chips_and_mismatched_xp_dialect --locked -p dcentrald --bin dcentrald' \
        'CI: L08 serial_job_id_rejects_unknown_chips_and_mismatched_xp_dialect'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1370_job_id_dispatch_cycle_round_trips_all_small_cores --locked -p dcentrald --bin dcentrald' \
        'CI: L08 bm1370_job_id_dispatch_cycle_round_trips_all_small_cores'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_rolled_version_reconstructs_when_pool_did_not_negotiate_mask --locked -p dcentrald --bin dcentrald' \
        'CI: serial BIP320 rolled version reconstructs without negotiated mask'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_rolled_version_retains_full_field_for_later_pool_admission --locked -p dcentrald --bin dcentrald' \
        'CI: serial BIP320 retains full field for separate pool admission'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1362_aml_cold_parser_keeps_short_identity_separate_from_assigned_coverage --locked -p dcentrald --bin dcentrald' \
        'CI: native serial exact contract bm1362_aml_cold_parser_keeps_short_identity_separate_from_assigned_coverage'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1362_aml_native_actual_init_work_and_known_nonce_on_a_and_plus_ptys --locked -p dcentrald --bin dcentrald' \
        'CI: native serial exact contract bm1362_aml_native_actual_init_work_and_known_nonce_on_a_and_plus_ptys'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1362_aml_runtime_clock_and_hcn_share_all_three_uart_fences --locked -p dcentrald --bin dcentrald' \
        'CI: native serial exact contract bm1362_aml_runtime_clock_and_hcn_share_all_three_uart_fences'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1366_xp_native_actual_init_work_and_known_nonce_on_xp_and_jxp_ptys --locked -p dcentrald --bin dcentrald' \
        'CI: native serial exact contract bm1366_xp_native_actual_init_work_and_known_nonce_on_xp_and_jxp_ptys'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1370_native_actual_init_work_and_known_nonce_on_pro_and_xp_ptys --locked -p dcentrald --bin dcentrald' \
        'CI: native serial exact contract bm1370_native_actual_init_work_and_known_nonce_on_pro_and_xp_ptys'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s21_native_selected_uart_work_and_genesis_nonce_round_trip --locked -p dcentrald --bin dcentrald' \
        'CI: native serial exact contract s21_native_selected_uart_work_and_genesis_nonce_round_trip'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_pool_version_checks_both_set_and_cleared_base_bits --locked -p dcentrald --bin dcentrald' \
        'CI: native serial exact contract serial_pool_version_checks_both_set_and_cleared_base_bits'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_pool_version_genesis_matches_the_actual_v1_wire_header --locked -p dcentrald --bin dcentrald' \
        'CI: native serial exact contract serial_pool_version_genesis_matches_the_actual_v1_wire_header'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_pool_version_leaves_bm1398_and_s19k_reconstruction_unchanged --locked -p dcentrald --bin dcentrald' \
        'CI: native serial exact contract serial_pool_version_leaves_bm1398_and_s19k_reconstruction_unchanged'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_am2_source_clears_stale_work_when_hash_on_disconnect_is_false --locked -p dcentrald --bin dcentrald' \
        'CI: serial clears stale work when hash_on_disconnect does not cut hash'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::work_dispatch_admission_tests::multi_pic_voltage_enable_uses_production_powerup_planner --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid multi-PIC enable uses production power-up planner (P1-5)'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1362_heartbeat_terminal_limit_precedes_short_watchdog_reset_windows --locked -p dcentrald --bin dcentrald' \
        'CI: BM1362 heartbeat terminal limit precedes short WDT reset windows'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1362_heartbeat_requires_supported_observed_dspic_firmware --locked -p dcentrald --bin dcentrald' \
        'CI: BM1362 heartbeat requires supported observed dsPIC firmware'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1362_heartbeat_failure_budget_is_bounded_and_success_resets_it --locked -p dcentrald --bin dcentrald' \
        'CI: BM1362 heartbeat failure budget is bounded and success resets it'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::nopic_fan_loop_disposition_is_terminal_for_every_revoked_state --locked -p dcentrald --bin dcentrald' \
        'CI: NoPic fan loop disposition is terminal for every revoked state'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::terminal_barrier_failure_consumes_no_safe_off_leg_before_retry --locked -p dcentrald --bin dcentrald' \
        'CI: terminal barrier failure consumes no safe-off leg before retry'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am2_never_energized_closeout_is_not_terminal_safe_off_evidence --locked -p dcentrald --bin dcentrald' \
        'CI: AM2 never-energized closeout is not terminal safe-off evidence'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_am2_bm1362_refuses_unmonitored_uart_trans_routes --locked -p dcentrald --bin dcentrald' \
        'CI: AM2 BM1362 refuses unmonitored UART-trans routes'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::validated_serial_admission_binds_exact_route_family_and_separate_geometry --locked -p dcentrald --bin dcentrald' \
        'CI: validated serial admission binds exact route family and geometry'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::ambiguous_nopic_count_refuses_instead_of_guessing_a_pic_driver --locked -p dcentrald --bin dcentrald' \
        'CI: ambiguous NoPic count refuses instead of guessing PIC driver'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::native_serial_voltage_identity_rejects_impossible_model_chip_pairs --locked -p dcentrald --bin dcentrald' \
        'CI: native serial voltage identity rejects impossible model/chip pairs'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::preenergize_airflow_envelope_reports_low_point_and_restore_failures_together --locked -p dcentrald --bin dcentrald' \
        'CI: preenergize airflow reports low-point and restore failures together'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::preenergize_airflow_envelope_refuses_low_point_and_restores_maximum --locked -p dcentrald --bin dcentrald' \
        'CI: preenergize airflow refuses low point and restores maximum'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::preenergize_airflow_envelope_proves_max_then_min_then_restores_max --locked -p dcentrald --bin dcentrald' \
        'CI: preenergize airflow proves max then min then restores max'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1362_nonce_safety_distinguishes_startup_midrun_and_disabled --locked -p dcentrald --bin dcentrald' \
        'CI: BM1362 nonce safety distinguishes startup midrun and disabled'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_actor_receiver_loss_and_three_read_errors_are_terminal --locked -p dcentrald --bin dcentrald' \
        'CI: serial actor receiver loss and three read errors are terminal'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::native_serial_identity_never_comes_from_default_or_explicit_geometry --locked -p dcentrald --bin dcentrald' \
        'CI: native serial identity never comes from default or explicit geometry alone'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am2_apw_stabilization_requires_live_actor_and_successful_progress --locked -p dcentrald --bin dcentrald' \
        'CI: AM2 APW stabilization requires live actor and successful progress'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_execution_terminal_rejects_late_physical_commit --locked -p dcentrald --bin dcentrald' \
        'CI: serial execution terminal rejects late physical commit'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_rearm_write_failure_is_terminal_not_best_effort --locked -p dcentrald --bin dcentrald' \
        'CI: S19k rearm write failure is terminal, not best effort'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::retained_single_owner_safe_off_legs_execute_all_pending_work_and_never_replay_success --locked -p dcentrald --bin dcentrald' \
        'CI: retained single-owner safe-off legs execute all pending work without success replay'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_serial_actor_freshness_rejects_queued_or_disconnected_required_exits --locked -p dcentrald --bin dcentrald' \
        'CI: exact serial actor freshness rejects queued or disconnected required exits'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am2_bringup_wait_is_immediately_cancellation_aware --locked -p dcentrald --bin dcentrald' \
        'CI: AM2 bringup wait is immediately cancellation-aware'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am2_cancellation_refuses_every_subsequent_validated_serial_commit --locked -p dcentrald --bin dcentrald' \
        'CI: AM2 cancellation refuses every subsequent validated serial commit'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_am2_bringup_validates_before_consuming_power_boundary_authority --locked -p dcentrald --bin dcentrald' \
        'CI: exact AM2 bringup validates before consuming power-boundary authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1362_pool_disconnect_requires_announced_authority_and_uart_commit --locked -p dcentrald --bin dcentrald' \
        'CI: BM1362 pool disconnect requires announced authority and UART commit'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_pool_disconnect_requires_prior_authority_and_physical_commit --locked -p dcentrald --bin dcentrald' \
        'CI: S19k pool disconnect requires prior authority and physical commit'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::validated_serial_admission_rejects_family_cross_use_and_impossible_frame_envelope --locked -p dcentrald --bin dcentrald' \
        'CI: validated serial admission rejects family cross-use and impossible frame envelope'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::assigned_serial_geometry_requires_exact_unique_configured_address_coverage --locked -p dcentrald --bin dcentrald' \
        'CI: assigned serial geometry requires exact unique configured address coverage'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::native_serial_geometry_requires_catalog_evidence_or_explicit_override --locked -p dcentrald --bin dcentrald' \
        'CI: native serial geometry requires catalog evidence or explicit override'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::native_serial_difficulty_requires_a_registered_profile --locked -p dcentrald --bin dcentrald' \
        'CI: native serial difficulty requires a registered profile'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_runtime_has_no_unbrokered_kernel_i2c_fd_or_ioctl_path --locked -p dcentrald --bin dcentrald' \
        'CI: serial runtime has no unbrokered kernel i2c fd or ioctl path'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::unique_owner_installation_never_replaces_live_or_completed_custody --locked -p dcentrald --bin dcentrald' \
        'CI: unique owner installation never replaces live or completed custody'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am3_bb_uart_trans_chain_parser_accepts_deduped_ttyo_list --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB uart-trans parser accepts deduped ttyO list'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am3_bb_uart_trans_chain_parser_accepts_single_ttyo_path --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB uart-trans parser accepts single ttyO path'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::am3_bb_uart_trans_chain_parser_rejects_unknown_or_empty_paths --locked -p dcentrald --bin dcentrald' \
        'CI: AM3-BB uart-trans parser rejects unknown or empty paths'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::apw_bypass_and_unclassified_state_transitions_are_explicit --locked -p dcentrald --bin dcentrald' \
        'CI: APW bypass and unclassified state transitions are explicit'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1368_fixture_interval_agrees_with_the_general_ladder --locked -p dcentrald --bin dcentrald' \
        'CI: BM1368 fixture interval agrees with general ladder'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1370_and_bm1368_chip_ids_are_distinct_in_discriminator --locked -p dcentrald --bin dcentrald' \
        'CI: BM1370 and BM1368 chip ids are distinct in discriminator'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1370_serial_execution_requires_exact_experimental_chip_authority --locked -p dcentrald --bin dcentrald' \
        'CI: BM1370 serial execution requires exact experimental chip authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1398_fixture_validates_full_header_with_rolled_midstate --locked -p dcentrald --bin dcentrald' \
        'CI: BM1398 fixture validates full header with rolled midstate'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1398_rejects_out_of_range_midstate_even_without_rolling --locked -p dcentrald --bin dcentrald' \
        'CI: BM1398 rejects out-of-range midstate even without rolling'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::bm1398_work_id_wraps_on_seven_bit_job_ring --locked -p dcentrald --bin dcentrald' \
        'CI: BM1398 work id wraps on seven-bit job ring'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_am2_apw_applicability_is_explicit_and_unclassified_state_cannot_close --locked -p dcentrald --bin dcentrald' \
        'CI: exact AM2 APW applicability is explicit; unclassified state cannot close'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_am2_bm1362_init_uses_constructor_plan_and_retained_observations --locked -p dcentrald --bin dcentrald' \
        'CI: exact AM2 BM1362 init uses constructor plan and retained observations'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_am2_power_boundary_remains_crossed_when_gpio_assertion_is_unknown --locked -p dcentrald --bin dcentrald' \
        'CI: exact AM2 power boundary remains crossed when GPIO assertion is unknown'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::exact_route_api_lifecycle_distinguishes_never_opened_from_opened_and_closed --locked -p dcentrald --bin dcentrald' \
        'CI: exact route API lifecycle distinguishes never-opened from opened and closed'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::native_amlogic_serial_source_has_one_validated_write_and_shutdown_path --locked -p dcentrald --bin dcentrald' \
        'CI: native Amlogic serial source has one validated write and shutdown path'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::nopic_family_classifier_matches_profile_table --locked -p dcentrald --bin dcentrald' \
        'CI: NoPic family classifier matches profile table'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::pic_enable_cmd_vnish_byte_exact --locked -p dcentrald --bin dcentrald' \
        'CI: PIC enable cmd Vnish byte-exact'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::pic_family_default_path_is_unchanged_for_non_nopic_units --locked -p dcentrald --bin dcentrald' \
        'CI: PIC family default path is unchanged for non-NoPic units'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::pinned_bm1370_model_wins_over_misleading_chip_count --locked -p dcentrald --bin dcentrald' \
        'CI: pinned BM1370 model wins over misleading chip count'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::retired_bhb56_dspic_route_has_no_runtime_capability_surface --locked -p dcentrald --bin dcentrald' \
        'CI: retired BHB56 dsPIC route has no runtime capability surface'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s21pro_family_models_resolve_to_bm1370_not_bm1368 --locked -p dcentrald --bin dcentrald' \
        'CI: S21 Pro family models resolve to BM1370 not BM1368'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_actor_distinguishes_empty_poll_liveness_from_committed_work --locked -p dcentrald --bin dcentrald' \
        'CI: serial actor distinguishes empty poll liveness from committed work'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_actor_mints_commit_evidence_only_after_successful_tx --locked -p dcentrald --bin dcentrald' \
        'CI: serial actor mints commit evidence only after successful tx'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_address_ladder_is_unchanged_for_shipped_populations_and_safe_at_one_chip --locked -p dcentrald --bin dcentrald' \
        'CI: serial address ladder is unchanged for shipped populations and safe at one chip'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_share_fixture_keeps_target_and_achieved_difficulty_separate --locked -p dcentrald --bin dcentrald' \
        'CI: serial share fixture keeps target and achieved difficulty separate'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::industrial_serial_pll_policy_is_exact_route_bound_and_fail_closed --locked -p dcentrald --bin dcentrald' \
        'CI: industrial serial PLL policy is exact-route-bound and fail-closed'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::industrial_serial_pll_searches_enforce_vendor_vco_envelope --locked -p dcentrald --bin dcentrald' \
        'CI: industrial serial PLL searches enforce vendor VCO envelope'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_braiins_bm1366_passthrough_opens_both_ttys --locked -p dcentrald --bin dcentrald' \
        'CI: S19k Braiins BM1366 passthrough opens both ttys'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_braiins_bm1366_passthrough_uses_closed_21_36_builder --locked -p dcentrald --bin dcentrald' \
        'CI: S19k Braiins BM1366 passthrough uses closed 21 36 builder'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_track1_coverage_probe_reads_immediately_and_retries_exact_plan --locked -p dcentrald --bin dcentrald' \
        'CI: S19k Track-1 coverage probe reads immediately and retries the exact plan'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_track1_exact_route_assigns_and_publishes_coverage_before_multi_handover --locked -p dcentrald --bin dcentrald' \
        'CI: S19k Track-1 exact route assigns and publishes coverage before multi handover'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_j0_wrapper_live_admits_reparented_wrapper_and_refuses_identity_drift --locked -p dcentrald --bin dcentrald' \
        'CI: S19k J0 wrapper-live admits reparented wrapper and refuses identity drift'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::live407_uart_vbits_hash_is_ticket_valid_not_434faee1 --locked -p dcentrald --bin dcentrald' \
        'CI: live407 UART vbits hash is ticket-valid not 434faee1'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::wave425_post_clean_chain_inactive_sentinel_dispatches_before_work --locked -p dcentrald --bin dcentrald' \
        'CI: Wave-425 post-clean chain-inactive sentinel dispatches before work'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_night_fan_apply_caps_home_and_safety --locked -p dcentrald --bin dcentrald' \
        'CI: serial night fan helper caps home requests at the thermal safety envelope'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_night_fan_path_publishes_watch_and_applies_helper --locked -p dcentrald --bin dcentrald' \
        'CI: serial night fan path publishes its watch and applies the shared helper'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_night_frequency_init_uses_shared_helper --locked -p dcentrald --bin dcentrald' \
        'CI: serial night initial frequency uses the shared bounded helper'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::serial_night_frequency_midrun_enqueues_pll0_write --locked -p dcentrald --bin dcentrald' \
        'CI: serial night mid-run frequency transition enqueues the bounded PLL0 write'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::active_capacity_frequency_requires_completed_serial_pll_write --locked -p dcentrald --bin dcentrald' \
        'CI: active capacity changes only after completed serial PLL writes'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::install_custody_is_a_pre_uart_gpio437_only_terminal_composition --locked -p dcentrald --bin dcentrald' \
        'CI: S19k install custody is a pre-UART GPIO437-only terminal composition'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::install_custody_panic_and_receipt_contracts_remain_cut_only --locked -p dcentrald --bin dcentrald' \
        'CI: S19k install custody panic and receipt contracts remain cut-only'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::install_custody_receipt_contract_rejects_both_mode_mismatches --locked -p dcentrald --bin dcentrald' \
        'CI: S19k install custody receipt contract rejects both mode mismatches'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::s19k_install_custody_cli_must_match_the_immutable_runtime_binding --locked -p dcentrald --bin dcentrald' \
        'CI: S19k install custody CLI must match the immutable runtime binding'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_thermal_selection_preserves_effective_source_provenance --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 thermal selection preserves effective source provenance'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::open_core_rail_plan_is_atomic_and_fail_closed --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid open core rail plan is atomic and fail closed'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::elevated_rail_has_one_asic_init_attempt_without_a_dwell_budget --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid elevated rail has one asic init attempt without a dwell budget'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_endpoint_migration_reuses_existing_eeprom_and_version_observations --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 endpoint migration reuses existing eeprom and version observations'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::selected_pic0x89_owner_has_no_raw_model_address_fallback --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid selected pic0x89 owner has no raw model address fallback'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::normal_shutdown_exact_pic0x89_owner_cannot_reconstruct_raw_authority --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid normal shutdown exact pic0x89 owner cannot reconstruct raw authority'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::normal_shutdown_requests_feeder_stop_before_cutoff_ack_and_later_join --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid normal shutdown requests feeder stop before cutoff ack and later join'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::post_enable_uart_gate_failure_reuses_retained_pic0x89_controller --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid post enable uart gate failure reuses retained pic0x89 controller'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::selected_pic0x89_heartbeat_owner_is_issued_by_retained_endpoint_session --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid selected pic0x89 heartbeat owner is issued by retained endpoint session'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::selected_pic0x89_thermal_owner_is_issued_by_retained_endpoint_session --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid selected pic0x89 thermal owner is issued by retained endpoint session'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::re018_pll_hex_envelope_accepts_proven_and_refuses_unsafe --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid re018 pll hex envelope accepts proven and refuses unsafe'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::at3_chain_id_for_pic_addr_maps_canonical_dspic_addrs_to_slots --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid at3 chain id for pic addr maps canonical dspic addrs to slots'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::at3_rail_read_gate_defaults_off_and_opts_in_via_config --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid at3 rail read gate defaults off and opts in via config'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::at3_rail_read_interval_defaults_30_and_clamps --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid at3 rail read interval defaults 30 and clamps'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_bus_prime_order_primes_non_selected_ascending --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 bus prime order primes non selected ascending'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_hybrid_bip320_reconstruction_matches_shared_bm1362_helper --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 hybrid bip320 reconstruction matches shared bm1362 helper'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_phase1_multi_serial_devices_selects_first_chain_only --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 phase1 multi serial devices selects first chain only'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_phase1_dual_plan_is_logged_but_execution_selector_stays_first_only --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 phase1 dual plan is logged but execution selector stays first only'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_dual_chain_gate_is_default_off --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 dual chain gate is default off'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_dual_chain_second_uart_default_and_override --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 dual chain second uart default and override'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_serial_chain_state_attributes_and_dedups --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 serial chain state attributes and dedups'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_dual_chain_attributes_nonces_to_the_producing_chain_only --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 dual chain attributes nonces to the producing chain only'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_dual_chain_bip320_reconstruction_is_per_chain_correct --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 dual chain bip320 reconstruction is per chain correct'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_teardown_params_global_set_then_read_round_trip --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 teardown params global set then read round trip'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_fastuart_settle_ms_default_override_and_clamp --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 fastuart settle ms default override and clamp'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_env_flag_off_only_true_for_falsey_values --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 env flag off only true for falsey values'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_safe_teardown_default_on_opt_out --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 safe teardown default on opt out'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::board_control_uio_falls_back_to_17_on_host --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid board control uio falls back to 17 on host'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::s19_dspic_addrs_cover_all_three_controllers --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid s19 dspic addrs cover all three controllers'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::psu_override_active_truth_table --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid psu override active truth table'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::chip_rail_target_ignores_psu_override_voltage --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid chip rail target ignores psu override voltage'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_uart_fallback_candidates_exclude_ps_console_uart --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 uart fallback candidates exclude ps console uart'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::gpio_number_spec_parser_accepts_numeric_and_pwr_control_label_specs --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid gpio number spec parser accepts numeric and pwr control label specs'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::proc_comm_matcher_requires_exact_bosminer_name --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid proc comm matcher requires exact bosminer name'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::xil_pic_get_version_framed_reply_parser_accepts_fw89 --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid xil pic get version framed reply parser accepts fw89'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::xil_pic_get_version_transaction_uses_bytewise_write_and_single_byte_read --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid xil pic get version transaction uses bytewise write and single byte read'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::pic_get_version_retry_budget_is_bosminer_faithful --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid pic get version retry budget is bosminer faithful'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::pic_get_version_helper_can_still_prepend_flush_when_asked --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid pic get version helper can still prepend flush when asked'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::parse_ablation_fields_extracts_canonical_summary_shape --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid parse ablation fields extracts canonical summary shape'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::parse_ablation_fields_captures_126_to_28_collapse_signature --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid parse ablation fields captures 126 to 28 collapse signature'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::wave42_env_gate_name_is_dcent_am2_dspic_bosminer_faithful --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid wave42 env gate name is dcent am2 dspic bosminer faithful'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::wave28b_parse_recognizes_strace_4byte_response_with_fw_at_index_1 --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid wave28b parse recognizes strace 4byte response with fw at index 1'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::wave28b_parse_handles_all_known_fw_bytes_in_4byte_shape --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid wave28b parse handles all known fw bytes in 4byte shape'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::daemon_side_fw86_refuses_voltage_without_lab_override --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid daemon side fw86 refuses voltage without lab override'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::wave28b_parse_does_not_false_positive_on_older_3byte_shape --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid wave28b parse does not false positive on older 3byte shape'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::wave28b_parse_does_not_false_positive_on_vnish_5byte_shape --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid wave28b parse does not false positive on vnish 5byte shape'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::wave28b_parse_rejects_strace_shape_with_garbage_status_byte --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid wave28b parse rejects strace shape with garbage status byte'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::wave28b_parse_rejects_strace_shape_with_garbage_fw_byte --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid wave28b parse rejects strace shape with garbage fw byte'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::wave28b_parse_handles_1_byte_read_without_false_4byte_match --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid wave28b parse handles 1 byte read without false 4byte match'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::parse_ablation_fields_tolerates_missing_or_error_summaries --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid parse ablation fields tolerates missing or error summaries'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::freq_only_default_off_is_byte_identical_gate --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid freq only default off is byte identical gate'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::freq_only_opt_in_via_config_key --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid freq only opt in via config key'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::applied_pll_band_is_proven_table_intersection_400_545 --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid applied pll band is proven table intersection 400 545'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::built_config_hard_pins_voltage_and_dvfs_off_and_clamps_band --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid built config hard pins voltage and dvfs off and clamps band'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::quiet_home_efficiency_is_the_default_objective_for_dot25 --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid quiet home efficiency is the default objective for dot25'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::explicit_operator_hashrate_target_is_preserved_not_silently_quieted --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid explicit operator hashrate target is preserved not silently quieted'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::hacker_mode_opts_back_into_hashrate_but_voltage_stays_off --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid hacker mode opts back into hashrate but voltage stays off'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::chain_stats_snapshot_is_chip_count_aware_and_resets_window --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid chain stats snapshot is chip count aware and resets window'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::quiet_idle_pwm_default_home_path --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid quiet idle pwm default home path'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::quiet_idle_pwm_clamps_down_to_fan_max --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid quiet idle pwm clamps down to fan max'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::quiet_idle_pwm_never_exceeds_safety_max --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid quiet idle pwm never exceeds safety max'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::quiet_idle_pwm_zero_is_preserved --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid quiet idle pwm zero is preserved'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::re018_decoded_register_values_are_byte_exact --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid re018 decoded register values are byte exact'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::re018_hashrate_fix_constants_are_byte_exact --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid re018 hashrate fix constants are byte exact'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::re018_nonce_space_base_matches_traced_values --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid re018 nonce space base matches traced values'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::re018_gate_is_off_by_default --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid re018 gate is off by default'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_mid_run_stall_timeout_default_override_and_disable --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 mid run stall timeout default override and disable'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_mid_run_stall_fires_only_after_generous_timeout --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 mid run stall fires only after generous timeout'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_nonce_recently_active_is_conservative --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 nonce recently active is conservative'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_recent_window_hashrate_drops_when_activity_stops --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 recent window hashrate drops when activity stops'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_rolling_window_hashrate_stable_on_sparse_eco_cadence --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 rolling window hashrate stable on sparse eco cadence'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_fan_fault_step_requires_sustained_confident_zero_rpm --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 fan fault step requires sustained confident zero rpm'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_graded_throttle_steps_down_only_above_hot --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 graded throttle steps down only above hot'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::hybrid_route_admission_is_consumed_at_first_run_entry --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid hybrid route admission is consumed at first run entry'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_chain_state_status_reverts_to_stalled_when_inactive --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 chain state status reverts to stalled when inactive'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::am2_publish_status_downgrades_to_stalled_on_inactivity --locked -p dcentrald --bin dcentrald' \
        'CI: hybrid am2 publish status downgrades to stalled on inactivity'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::smart_apw_lenience_excludes_typed_controller_and_safety_failures --locked -p dcentrald --bin dcentrald' \
        'CI: opportunistic smart APW lenience excludes typed controller and safety failures'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::smart_apw_lenient_service_terminal_refusal_returns_error_without_heartbeat --locked -p dcentrald --features sim-hal --bin dcentrald' \
        'SIM-HAL CI: smart APW bring-up returns a terminal service refusal before heartbeat spawn'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh s19j_hybrid_mining::tests::smart_apw_heartbeat_typed_refusal_cancels_hybrid_run --locked -p dcentrald --features sim-hal --bin dcentrald' \
        'SIM-HAL CI: smart APW heartbeat authority loss cancels the hybrid lifecycle'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh psu::tests::serialized_apw_service_rejects_positive_short_frame_before_later_boot_verbs --locked -p dcentrald-hal --features sim-hal --lib' \
        'SIM-HAL CI: serialized APW exact-write completion regression executes'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh psu::tests::terminally_superseded_apw_service_mutation_has_zero_retry_or_buffer_drain --locked -p dcentrald-hal --features sim-hal --lib' \
        'SIM-HAL CI: terminally superseded APW mutation remains non-retryable'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh psu::tests::terminally_superseded_apw_heartbeat_has_no_opcode_fallback_retry_or_state_change --locked -p dcentrald-hal --features sim-hal --lib' \
        'SIM-HAL CI: terminally superseded APW heartbeat cannot fall back or mutate state'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh psu::tests::dual_ordinary_wire_heartbeat_exhaustion_has_a_dedicated_retryable_type --locked -p dcentrald-hal --features sim-hal --lib' \
        'SIM-HAL CI: dual ordinary-wire heartbeat failure constructs the dedicated retryable type'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh psu::tests::apw_error_classification_preserves_fabric_ownership_and_defers_only_wire_exhaustion --locked -p dcentrald-hal --features sim-hal --lib' \
        'SIM-HAL CI: APW preserves typed fabric ownership failures and defers only wire exhaustion'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh psu::tests::every_raw_apw_observation_and_loki_cold_wake_path_preserves_typed_errors --locked -p dcentrald-hal --features sim-hal --lib' \
        'SIM-HAL CI: raw APW observations and standalone Loki cold-wake preserve typed ownership failures'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh psu::tests::legacy_cold_boot_returns_typed_probe_error_without_outer_retry_or_reflush --locked -p dcentrald-hal --features sim-hal --lib' \
        'SIM-HAL CI: legacy APW cold boot returns typed probe refusal without retry or flush'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh psu::tests::cached_legacy_cold_boot_returns_typed_disable_error_after_only_wire_probe_retries --locked -p dcentrald-hal --features sim-hal --lib' \
        'SIM-HAL CI: cached legacy APW cold boot returns typed Disable refusal immediately'
    require_pattern "$sim_workflow" \
        'sh ../scripts/run_exact_cargo_test.sh psu::tests::higher_level_apw_boot_wrappers_defer_only_ordinary_wire_failures --locked -p dcentrald-hal --features sim-hal --lib' \
        'SIM-HAL CI: higher APW boot wrappers defer only ordinary wire failures'
    require_pattern "$sim_workflow" \
        'runtime::thread_guard::tests' \
        'SIM-HAL CI: bounded runtime-thread ownership regression executes'
    require_pattern "$sim_workflow" \
        'am2_power_shutdown_evidence_tests' \
        'SIM-HAL CI: AM2 shutdown evidence regression executes'
}
sim_hal_evidence_contract_gates

# Native NoPic safety-watchdog evidence must remain executable in hosted CI.
# Source invariants complement (not replace) the fake-device behavioral tests:
# every API PSU mutator is admitted through the shared gate, serial teardown
# drains that gate before safe-off, and fan liveness uses checked actuation.
nopic_watchdog_evidence_contract_gates() {
    workflow='../../.github/workflows/dcentos-offline-gates.yml'
    require_pattern "$workflow" \
        'bash ../scripts/run_filtered_cargo_test.sh -p dcentrald --bin dcentrald -- runtime::safety_watchdog::tests' \
        'NoPic watchdog CI: fail-closed worker state-machine tests execute'
    require_pattern "$workflow" \
        'sh ../scripts/run_exact_cargo_test.sh serial_mining::tests::nopic_watchdog_and_safeoff_order_is_fail_closed --locked -p dcentrald --bin dcentrald' \
        'NoPic watchdog CI: engine teardown source-order contract executes'
    require_pattern "$workflow" \
        'sh ../scripts/run_exact_cargo_test.sh tests::watchdog_armed_on_all_mining_entry_paths --locked -p dcentrald --bin dcentrald' \
        'NoPic watchdog CI: mining entry-path admission contract executes'
    require_pattern "$workflow" \
        'bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-hal --lib -- hardware_mutation_gate_tests' \
        'NoPic watchdog CI: control-plane mutation drain contract executes'
    require_pattern "$workflow" \
        'sh ../scripts/run_exact_cargo_test.sh platform::amlogic::tests::checked_fan_command_surfaces_partial_two_channel_write --locked -p dcentrald-hal --lib' \
        'NoPic watchdog CI: partial two-channel fan failure executes'
    require_pattern "$workflow" \
        'sh ../scripts/run_exact_cargo_test.sh platform::amlogic::tests::checked_psu_gpio_parser_never_converts_unknown_data_to_off --locked -p dcentrald-hal --lib' \
        'NoPic watchdog CI: unknown GPIO readback remains fail-closed'
    require_pattern 'dcentrald/dcentrald-api/src/rest/late.rs' \
        'state.hardware_mutation_gate.try_acquire()' \
        'NoPic watchdog: API PSU mutations acquire teardown-drain admission'
    require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' \
        '.close_and_drain(RUNTIME_THREAD_STOP_TIMEOUT)' \
        'NoPic watchdog: serial teardown closes and drains API mutations'
    require_pattern 'dcentrald/dcentrald/src/serial_mining.rs' \
        'fan.set_speed_checked' \
        'NoPic watchdog: thermal safety liveness uses checked fan actuation'
}
nopic_watchdog_evidence_contract_gates

# A watchdog-disarm followed by a voltage-minimum command removes the PSU's
# independent cutoff before the safe-direction command is known to have
# completed. Runtime code must use Apw121215a::safe_shutdown_to_min(), whose
# ordering is minimum first and disarm second.
if grep -R -n --include='*.rs' '\.watchdog(false)' dcentrald/dcentrald/src >/tmp/dcentos-naked-psu-disarm.$$ 2>/dev/null; then
    fail 'PSU safe-off ordering: naked watchdog(false) remains in daemon runtime code'
    cat /tmp/dcentos-naked-psu-disarm.$$ >&2
else
    pass 'PSU safe-off ordering: daemon runtime uses the minimum-then-disarm coordinator'
fi
rm -f /tmp/dcentos-naked-psu-disarm.$$
require_pattern 'dcentrald/dcentrald-hal/src/psu.rs' \
    'pub fn safe_shutdown_to_min' \
    'PSU safe-off ordering: typed minimum-then-disarm coordinator exists'

# Raw public I2C operations are conservatively terminal-fenced mutations;
# privileged intent is HAL-internal. Production protocol modules use typed
# plans or audit-only mutation labels instead of the compatibility transaction.
require_file 'scripts/check_i2c_transaction_labeling.py'
if _dcent_i2c_labeling_output=$(python3 scripts/check_i2c_transaction_labeling.py --self-test 2>&1); then
    pass 'I2C mutation labeling: raw public operations are conservatively fenced; production compound transactions use typed plans or audit labels'
else
    printf '%s\n' "$_dcent_i2c_labeling_output" >&2
    fail 'I2C mutation labeling: compatibility transaction call remains in production modules'
fi

# Application crates must never regain the ability to select the HAL's
# authorizing intent or invoke an intent-bearing executor. Keep the scan on
# production source roots so compile-fail documentation and HAL unit tests do
# not become false positives.
if grep -R -n --include='*.rs' -E 'I2cOperationIntent|_with_intent' \
    dcentrald/dcentrald-asic/src \
    dcentrald/dcentrald/src \
    >/tmp/dcentos-external-i2c-intent.$$ 2>/dev/null; then
    fail 'I2C privilege boundary: application crate references HAL-internal intent authority'
    cat /tmp/dcentos-external-i2c-intent.$$ >&2
else
    pass 'I2C privilege boundary: privileged intent and intent-bearing executors remain HAL-internal'
fi
rm -f /tmp/dcentos-external-i2c-intent.$$

# AM3-BB carrier contract: keep the active `a lab unit` board-target, HAL constants,
# safe boot/shutdown GPIO directions, UART topology, DTB admission gates, and
# the quarantined legacy BBCtrl/S70 DTS from silently converging into one
# misleading product definition.  Both commands are host-only Python checks.
if run_python_script scripts/test_am3_bb_hardware_contract.py; then
    pass 'AM3-BB hardware contract: negative fixtures reject unsafe drift'
else
    fail 'AM3-BB hardware contract: negative-fixture suite failed'
fi
if run_python_script scripts/check_am3_bb_hardware_contract.py --root "$PROJECT_DIR"; then
    pass 'AM3-BB hardware contract: catalog and all offline consumers agree'
else
    fail 'AM3-BB hardware contract: board/DTS/build consistency gate failed'
fi

# Safety regressions must be executable from this canonical gate, not only from
# a workflow step or a developer-local command.
if sh scripts/test_run_wave_regressions_driver.sh >/dev/null 2>&1; then
    pass 'wave regression driver: dependency-lock and exact-index command contract is pinned'
else
    fail 'wave regression driver: dependency-lock or command contract regressed'
fi
if sh scripts/test_sysupgrade_resource_ledger.sh >/dev/null 2>&1; then
    pass 'sysupgrade resource ledger: durable ownership and reconciliation contract is pinned'
else
    fail 'sysupgrade resource ledger: ownership or reconciliation contract regressed'
fi
if sh scripts/test_verify_sysupgrade_signature.sh >/dev/null 2>&1; then
    pass 'sysupgrade signature verifier: executable signed-envelope contract is pinned'
else
    fail 'sysupgrade signature verifier: signed-envelope contract regressed'
fi

# A release panic aborts without running Rust Drop cleanup. Until the durable
# hardware-disposition journal and startup resolver are active, a fresh daemon
# must not be admitted automatically after an abnormal exit. Check every board
# overlay dynamically so new product supervisors inherit the same fail-closed
# policy instead of reintroducing a bounded-but-unsafe crash loop.
# The aggregate policy directly executes the three component behavioral suites;
# require each transitive dependency and pin the active delegations below so
# comments cannot counterfeit either existence or execution ownership.
require_file 'scripts/test_dcentrald_process_identity.sh'
require_file 'scripts/test_am3_bb_emergency_safeoff.sh'
require_file 'scripts/test_zynq_terminal_safety.sh'
require_line_regex 'scripts/test_dcentrald_crash_restart_policy.sh' \
    '^[[:space:]]*IDENTITY_TEST="\$SCRIPT_DIR/test_dcentrald_process_identity\.sh"[[:space:]]*$' \
    'dcentrald crash policy: exact-process identity component is delegated'
require_line_regex 'scripts/test_dcentrald_crash_restart_policy.sh' \
    '^[[:space:]]*elif[[:space:]]+sh[[:space:]]+"\$IDENTITY_TEST";[[:space:]]+then[[:space:]]*$' \
    'dcentrald crash policy: exact-process identity component is executed'
require_line_regex 'scripts/test_dcentrald_crash_restart_policy.sh' \
    '^[[:space:]]*AM3_BB_SAFEOFF_TEST="\$SCRIPT_DIR/test_am3_bb_emergency_safeoff\.sh"[[:space:]]*$' \
    'dcentrald crash policy: AM3-BB safe-off component is delegated'
require_line_regex 'scripts/test_dcentrald_crash_restart_policy.sh' \
    '^[[:space:]]*elif[[:space:]]+sh[[:space:]]+"\$AM3_BB_SAFEOFF_TEST";[[:space:]]+then[[:space:]]*$' \
    'dcentrald crash policy: AM3-BB safe-off component is executed'
require_line_regex 'scripts/test_dcentrald_crash_restart_policy.sh' \
    '^[[:space:]]*ZYNQ_SAFEOFF_TEST="\$SCRIPT_DIR/test_zynq_terminal_safety\.sh"[[:space:]]*$' \
    'dcentrald crash policy: Zynq safe-off component is delegated'
require_line_regex 'scripts/test_dcentrald_crash_restart_policy.sh' \
    '^[[:space:]]*elif[[:space:]]+sh[[:space:]]+"\$ZYNQ_SAFEOFF_TEST";[[:space:]]+then[[:space:]]*$' \
    'dcentrald crash policy: Zynq safe-off component is executed'
if sh scripts/test_dcentrald_crash_restart_policy.sh; then
    pass 'dcentrald crash policy: every shipped supervisor refuses automatic readmission'
else
    fail 'dcentrald crash policy: a shipped supervisor can automatically readmit after an abnormal exit'
fi

# Durable mutation-disposition journal (defense-in-depth UNDER the supervisor
# session latch pinned above): the daemon must adjudicate the durable journal
# at startup BEFORE hardware admission and refuse fail-closed on any
# unresolved/foreign-boot/unreadable record, and must journal Mutated/
# Quarantined fabric dispositions at the controlled teardown points. The
# journal never relaxes the no-auto-restart policy: restart.rs keeps
# returning false because a clean journal is not a typed SafeOff receipt.
require_pattern 'dcentrald/dcentrald/src/daemon.rs' 'load_and_adjudicate_mutation_disposition(' 'mutation journal: daemon adjudicates the durable journal at startup'
require_pattern 'dcentrald/dcentrald/src/daemon.rs' 'mutation-disposition journal refuses hardware admission' 'mutation journal: unresolved journal refuses hardware admission fail-closed'
require_pattern 'dcentrald/dcentrald/src/daemon.rs' 'fn persist_unresolved_mutation_dispositions(' 'mutation journal: controlled teardown journals unresolved fabric dispositions'
require_pattern 'dcentrald/dcentrald/src/daemon.rs' 'fn terminal_mutation_disposition_path(' 'mutation journal: durable path goes through the runtime_policy persistence seam'
require_pattern 'dcentrald/dcentrald/src/restart.rs' 'Automatic daemon restart refused: no typed hardware disposition receipt is available' 'mutation journal: automatic restart stays refused despite the journal'

# Single-chokepoint arm coverage (2026-08-16): the Daemon::init gate above only
# covers the standard/S9 passthrough path. The PRIMARY hardware-energizing arms
# (run_am3_bb_mining, S19jHybridMiner, SerialMiner) are launched directly from
# run_main and never enter Daemon::init, so main.rs must adjudicate the durable
# journal ONCE, immediately before the runtime-arm dispatch branch (covering
# every current and future arm structurally), and must journal unresolved
# Mutated/Quarantined fabric dispositions at each arm's controlled run-return
# seam. These pins grep main.rs (a different file from this gate script) for
# the exact load-bearing literals per the source-contract self-match-trap rule.
require_pattern 'dcentrald/dcentrald/src/main.rs' 'fn adjudicate_mutation_disposition_before_runtime_arm_dispatch()' 'mutation journal: single-chokepoint gate is defined in main.rs'
require_pattern 'dcentrald/dcentrald/src/main.rs' 'adjudicate_mutation_disposition_before_runtime_arm_dispatch()?;' 'mutation journal: chokepoint gate is invoked fail-closed on the dispatch path'
require_pattern 'dcentrald/dcentrald/src/main.rs' 'mutation-disposition journal refuses hardware admission before runtime-arm dispatch' 'mutation journal: chokepoint refusal is typed and precedes every mining arm'
require_pattern 'dcentrald/dcentrald/src/main.rs' 'let am3_bb_run_result = am3_bb_mining::run_am3_bb_mining(' 'mutation journal: am3-bb arm binds its run result for controlled-teardown journaling'
require_pattern 'dcentrald/dcentrald/src/main.rs' 'let hybrid_run_result = miner.run().await;' 'mutation journal: s19j-hybrid arm binds its run result for controlled-teardown journaling'
require_pattern 'dcentrald/dcentrald/src/main.rs' 'let serial_run_result = miner.run().await;' 'mutation journal: serial arm binds its run result for controlled-teardown journaling'
require_pattern 'dcentrald/dcentrald/src/main.rs' 'crate::daemon::persist_unresolved_mutation_dispositions(' 'mutation journal: run_main arms journal unresolved dispositions at controlled teardown'
mutation_gate_line=$(grep -nF 'adjudicate_mutation_disposition_before_runtime_arm_dispatch()?;' dcentrald/dcentrald/src/main.rs | head -n 1 | cut -d: -f1)
mutation_dispatch_line=$(grep -nF 'if am3_bb_mode {' dcentrald/dcentrald/src/main.rs | head -n 1 | cut -d: -f1)
if [ -n "$mutation_gate_line" ] && [ -n "$mutation_dispatch_line" ] && [ "$mutation_gate_line" -lt "$mutation_dispatch_line" ]; then
    pass 'mutation journal: chokepoint gate precedes the runtime-arm dispatch branch'
else
    fail 'mutation journal: chokepoint gate does not precede the runtime-arm dispatch branch'
fi

if sh scripts/test_amlogic_boot_safe_state.sh; then
    pass 'Amlogic lifecycle: boot baseline, runtime handoff, crash cut, and PID1 ordering are pinned'
else
    fail 'Amlogic lifecycle: boot/runtime/crash safe-state contract regressed'
fi
if run_python_script scripts/test_s19k_aml_install_safety.py -q; then
    pass 'S19k AML install safety: explicit mutation authority, authenticated post-install boundary, exact NAND map, and offset-preserving backup are pinned'
else
    fail 'S19k AML install safety: mutation authority, post-install boundary, NAND map, backup representation, or flash refusal regressed'
fi
if bash scripts/test_s19k_aarch64_compile_check.sh && \
   "$PY" -m py_compile \
       scripts/s19k_phase12_normalize.py \
       scripts/s19k_phase12_capture_verify.py \
       scripts/s19k_no_work_verify.py \
       scripts/s19k_no_work_prepare.py \
       scripts/test_s19k_phase12_normalize.py \
       scripts/test_s19k_phase12_capture_verify.py \
       scripts/test_s19k_no_work_verify.py \
       scripts/test_s19k_no_work_prepare.py && \
   run_python_script scripts/test_s19k_phase12_normalize.py -q && \
   run_python_script scripts/test_s19k_phase12_capture_verify.py -q && \
   run_python_script scripts/test_s19k_no_work_verify.py -q && \
   run_python_script scripts/test_s19k_no_work_prepare.py -q; then
    pass 'S19k joined Phase 1+2: per-channel raw blocks, normalization, deterministic bundle preparation, and no-work physical-evidence admission remain content-bound'
else
    fail 'S19k joined Phase 1+2: normalization replay, bundle preparation, target transcript, or independent physical-evidence admission regressed'
fi
if "$PY" -m py_compile scripts/test_s19k_gauntlet_runbook_convergence.py && \
   run_python_script scripts/test_s19k_gauntlet_runbook_convergence.py -q; then
    pass 'S19k Gauntlet operator path: historical plans remain non-executable and current v12 commands, artifacts, and evidence tools converge'
else
    fail 'S19k Gauntlet operator path: stale command authority, artifact selection, or evidence-tool drift detected'
fi
if "$PY" -m py_compile \
       scripts/s19k_bounded_transcript_verify.py \
       scripts/s19k_endurance_collect.py \
       scripts/s19k_endurance_verify.py \
       scripts/s19k_phase3_physical_verify.py \
       scripts/s19k_tmp_build_artifact.py \
       scripts/s19k_host_verify.py \
       scripts/test_s19k_bounded_transcript_verify.py \
       scripts/test_s19k_endurance.py \
       scripts/test_s19k_phase3_physical_verify.py \
       scripts/test_s19k_tmp_build_artifact.py && \
   run_python_script scripts/test_s19k_bounded_transcript_verify.py -q && \
   run_python_script scripts/test_s19k_phase3_physical_verify.py -q && \
   run_python_script scripts/test_s19k_endurance.py -q && \
   run_python_script scripts/test_s19k_tmp_build_artifact.py -q && \
   run_python_script scripts/s19k_host_verify.py; then
    pass 'S19k bounded-work/endurance/build/host contracts: verifier, evidence, artifact, and board-safety regressions remain fail-closed'
else
    fail 'S19k bounded-work/endurance/build/host contracts: verifier, evidence, artifact, or board-safety regression detected'
fi
if "$PY" -m py_compile \
       ../../tools/ghidra/amlogic_lz4c.py \
       ../../tools/ghidra/test_amlogic_lz4c.py \
       ../../tools/ghidra/wrap_raw_elf.py \
       ../../tools/ghidra/test_wrap_raw_elf.py \
       ../../tools/vnish_aml_boot_package/vnish_aml_boot_package.py \
       ../../tools/vnish_aml_boot_package/test_vnish_aml_boot_package.py \
       scripts/s19k_native_re_verify.py \
       scripts/test_s19k_native_re_verify.py \
       scripts/s19k_shared_bhb5690x_interface_verify.py \
       scripts/test_s19k_shared_bhb5690x_interface_verify.py \
       scripts/s19k_native_hardware_verify.py \
       scripts/test_s19k_native_hardware_verify.py \
       scripts/s19k_native_build_verify.py \
       scripts/test_s19k_native_build_verify.py \
       scripts/s19k_native_owner_verify.py \
       scripts/test_s19k_native_owner_verify.py \
       scripts/s19k_native_population_coverage_verify.py \
       scripts/test_s19k_native_population_coverage_verify.py \
       scripts/s19k_native_live_common.py \
       scripts/s19k_native_phase12_verify.py \
       scripts/s19k_native_bounded_verify.py \
       scripts/s19k_native_endurance_verify.py \
       scripts/test_s19k_native_live_verifiers.py \
       scripts/s19k_persistent_recovery_verify.py \
       scripts/test_s19k_persistent_recovery_verify.py \
       scripts/s19k_persistent_recovery_prepare.py \
       scripts/test_s19k_persistent_recovery_prepare.py \
       scripts/s19k_persistent_image_verify.py \
       scripts/test_s19k_persistent_image_verify.py \
       scripts/s19k_persistent_install_verify.py \
       scripts/s19k_persistent_acceptance_verify.py \
       scripts/test_s19k_persistent_transaction_verifiers.py \
       scripts/s19k_board_population_matrix_verify.py \
       scripts/test_s19k_board_population_matrix_verify.py \
       scripts/s19k_gauntlet_workflow.py \
       scripts/test_s19k_gauntlet_workflow.py && \
   "$PY" -m pytest -q \
       ../../tools/ghidra/test_amlogic_lz4c.py \
       ../../tools/ghidra/test_wrap_raw_elf.py && \
   run_python_script ../../tools/vnish_aml_boot_package/test_vnish_aml_boot_package.py -q && \
   run_python_script scripts/test_s19k_native_re_verify.py -q && \
   run_python_script scripts/s19k_shared_bhb5690x_interface_verify.py audit && \
   run_python_script scripts/test_s19k_shared_bhb5690x_interface_verify.py -q && \
   run_python_script scripts/test_s19k_native_hardware_verify.py -q && \
   run_python_script scripts/test_s19k_native_build_verify.py -q && \
   run_python_script scripts/s19k_native_owner_verify.py audit && \
   run_python_script scripts/test_s19k_native_owner_verify.py -q && \
   run_python_script scripts/test_s19k_native_population_coverage_verify.py -q && \
   run_python_script scripts/test_s19k_native_live_verifiers.py -q && \
   run_python_script scripts/test_s19k_persistent_recovery_verify.py -q && \
   run_python_script scripts/test_s19k_persistent_recovery_prepare.py -q && \
   run_python_script scripts/s19k_persistent_image_verify.py audit-source && \
   run_python_script scripts/test_s19k_persistent_image_verify.py -q && \
   run_python_script scripts/test_s19k_persistent_transaction_verifiers.py -q && \
   run_python_script scripts/test_s19k_board_population_matrix_verify.py -q && \
   run_python_script scripts/test_s19k_gauntlet_workflow.py -q && \
   sh scripts/test_s19k_workflow_checkout.sh; then
    pass 'S19k dynamic workflow: secure-firmware classification, evidence-derived adopted/native/persistent DAG, and bounded expert wave remain fail-closed'
else
    fail 'S19k dynamic workflow: secure-firmware evidence, campaign DAG, evidence derivation, expert wave, or terminal refusal regressed'
fi
if "$PY" -m py_compile scripts/s19k_aml_stock_recovery_plan.py scripts/test_s19k_aml_stock_recovery_plan.py && \
   run_python_script scripts/test_s19k_aml_stock_recovery_plan.py -q; then
    pass 'S19k AML factory recovery: exact encrypted media, full-erasure classification, and six-MTD preburn backup remain plan-only'
else
    fail 'S19k AML factory recovery: archive/member/INI/TOC pin, preburn backup, or no-execute boundary regressed'
fi
if run_python_script scripts/test_s19k_current_recovered_stock_closeout.py -q; then
    pass 'S19k recovered-stock closeout: immutable one-use evidence and no-effect retirement remain pinned'
else
    fail 'S19k recovered-stock closeout: exact transaction evidence or no-effect retirement boundary regressed'
fi
if run_python_script scripts/test_s19k_stock_restart_from_safeoff.py -q; then
    pass 'S19k stock restart: terminal SafeOff evidence, at-most-once claim, and exact stock-tree proof remain pinned'
else
    fail 'S19k stock restart: SafeOff admission, at-most-once claim, or exact stock-tree proof regressed'
fi
if sh scripts/test_s19k_braiins_supervisor_custody.sh; then
    pass 'S19k Braiins custody: exact stock supervisor/child process-tree evidence remains read-only and fail-closed'
else
    fail 'S19k Braiins custody: supervisor/child identity, topology, or read-only boundary regressed'
fi
if run_python_script scripts/test_s19k_persistent_elf_contract.py -q; then
    pass 'S19k persistent image: staged init and daemon are runnable static AArch64 ELF artifacts'
else
    fail 'S19k persistent image: AArch64 executable/static ABI contract regressed'
fi

if sh scripts/test_dcentos_receipt_core.sh; then
    pass 'compiled receipt foundation: SHA-256 and complete resource/claim transitions are pinned'
else
    fail 'compiled receipt foundation: hash or state-machine boundary regressed'
fi
if sh scripts/test_dcentos_receipt_parser.sh; then
    pass 'compiled receipt ABI1: canonical byte parsers and semantic chains are pinned'
else
    fail 'compiled receipt ABI1: parser or semantic-chain boundary regressed'
fi
if sh scripts/test_dcentos_receipt_store.sh; then
    pass 'compiled receipt storage: descriptor-only topology and race boundary is pinned'
else
    fail 'compiled receipt storage: descriptor, metadata, topology, or race boundary regressed'
fi
if sh scripts/test_dcentos_receipt_storage.sh; then
    pass 'compiled receipt ABI2 storage: seal/head grammar and composite manifest-pair validation are pinned'
else
    fail 'compiled receipt ABI2 storage: parser, parity, linkage, or delta boundary regressed'
fi
if sh scripts/test_dcentos_receipt_fuzz_corpus.sh; then
    pass 'compiled receipt ABI2 fuzz corpus: every structured seed is a real valid manifest pair'
else
    fail 'compiled receipt ABI2 fuzz corpus: framed seed or pair validity regressed'
fi
if sh scripts/test_dcentos_receipt_projection.sh; then
    pass 'compiled receipt ABI2 projection: complete bounded chronology and surviving-head projections are pinned'
else
    fail 'compiled receipt ABI2 projection: chronology, authority, prefix, or manifest boundary regressed'
fi
if sh scripts/test_dcentos_receipt_quality.sh; then
    pass 'compiled receipt quality: sanitizer, analyzer, and projection stack budgets are durable'
else
    fail 'compiled receipt quality: sanitizer, analyzer, or projection stack boundary regressed'
fi
if grep -Eq '^[[:space:]]*run:[[:space:]]+sh[[:space:]]+scripts/test_dcentos_receipt_cross_compile\.sh[[:space:]]*$' \
    ../../.github/workflows/dcentos-image-smoke.yml; then
    pass 'compiled receipt foundation: exact Zynq cross proof runs only after restricted-input provisioning'
else
    fail 'compiled receipt foundation: restricted-input image smoke no longer invokes the exact Zynq cross proof'
fi

if sh scripts/test_sysupgrade_mount_identity.sh >/dev/null 2>&1 &&
   sh scripts/test_sysupgrade_ubi_volume_plan.sh >/dev/null 2>&1; then
    pass 'Zynq state observers: mount and UBI identities are admitted without mutation'
else
    fail 'Zynq state observers: mount or UBI identity admission regressed'
fi

# Typed sysupgrade helper contract suites (2026-08 helper split). Each suite
# adversarially pins one libexec helper consumed by the four Zynq sysupgrade
# overlays; the anti-orphan reachability checker requires these active
# invocations to stay on single interpreter lines.
if sh scripts/test_sysupgrade_package_input.sh >/dev/null 2>&1; then
    pass 'sysupgrade package input: stable package admission and read-window integrity are pinned'
else
    fail 'sysupgrade package input: admission or read-window integrity regressed'
fi
if sh scripts/test_sysupgrade_persistent_state.sh >/dev/null 2>&1; then
    pass 'sysupgrade persistent state: staged /data preservation and entropy rotation are pinned'
else
    fail 'sysupgrade persistent state: staged preservation or entropy rotation regressed'
fi
if sh scripts/test_sysupgrade_transaction_lock.sh >/dev/null 2>&1; then
    pass 'sysupgrade transaction lock: boot-bound ownership and phase admission are pinned'
else
    fail 'sysupgrade transaction lock: ownership, phase, or cleanup admission regressed'
fi
if sh scripts/test_sysupgrade_transaction_workspace.sh >/dev/null 2>&1; then
    pass 'sysupgrade transaction workspace: owned mounts and retirement paths are pinned'
else
    fail 'sysupgrade transaction workspace: ownership or retirement regressed'
fi
if sh scripts/test_sysupgrade_ubi_identity.sh >/dev/null 2>&1; then
    pass 'sysupgrade UBI identity: semantic attachment identity admission is pinned'
else
    fail 'sysupgrade UBI identity: semantic identity admission regressed'
fi
if sh scripts/test_sysupgrade_ubi_node.sh >/dev/null 2>&1; then
    pass 'sysupgrade UBI node: exact root-only device-node admission is pinned'
else
    fail 'sysupgrade UBI node: device-node admission or refusal regressed'
fi
if sh scripts/test_sysupgrade_uboot_env_admission.sh >/dev/null 2>&1; then
    pass 'sysupgrade U-Boot env admission: redundant-copy geometry admission is pinned'
else
    fail 'sysupgrade U-Boot env admission: geometry or authority admission regressed'
fi
if sh scripts/test_sysupgrade_signal_exit.sh >/dev/null 2>&1; then
    pass 'sysupgrade signal exit: every updater terminates through one cleanup path'
else
    fail 'sysupgrade signal exit: single-cleanup-path termination regressed'
fi
if sh scripts/test_boot_artifact_auditor.sh >/dev/null 2>&1; then
    pass 'boot-artifact auditor: parser fixtures and the declared local catalog stay policy-valid'
else
    fail 'boot-artifact auditor: parser or declared-catalog policy regressed'
fi
if sh scripts/virtme/am2-ubi/test_manifest_verifier.sh >/dev/null 2>&1; then
    pass 'virtme am2-ubi manifest verifier: bundle-manifest admission contract is pinned'
else
    fail 'virtme am2-ubi manifest verifier: bundle-manifest admission regressed'
fi

if sh scripts/test_zynq_nandsim_geometry.sh >/dev/null 2>&1; then
    pass 'Zynq nandsim geometry: evidence-derived emulator tuple remains subordinate to package authority'
else
    fail 'Zynq nandsim geometry: emulator tuple or package cross-contract regressed'
fi

if sh scripts/test_zynq_sysupgrade_geometry.sh >/dev/null 2>&1 &&
   sh scripts/test_zynq_payload_geometry_integration.sh >/dev/null 2>&1; then
    pass 'Zynq payload geometry: canonical boundaries and producer/consumer wiring are enforced'
else
    fail 'Zynq payload geometry: canonical boundaries or producer/consumer wiring regressed'
fi

require_file 'scripts/test_am2_xilinx_legacy_ramdisk.py'
require_file 'scripts/test_am2_xilinx_preinit_safety.py'
require_file 'scripts/test_am2_s19jpro_sd_builder_hardening.py'
require_file 'scripts/test_am2_s17_post_image.sh'
require_file 'scripts/test_am2_s17_ramdisk_swap.py'
require_file 'scripts/test_amlogic_exact_build_inputs.sh'
require_file 'scripts/test_amlogic_native_package_targets.py'
require_file 'scripts/test_pre_flash_validate_amlogic_profiles.sh'
require_file 'scripts/test_bcb100_offline_boot_inputs.py'
require_file 'scripts/test_sd_boot_media_manifest.py'
require_file 'scripts/test_sd_common_output_safety.py'
require_file 'scripts/test_zynq_external_media_ephemeral_policy.sh'
if run_python_script scripts/test_am2_xilinx_legacy_ramdisk.py -q >/dev/null 2>&1; then
    pass 'AM2 external media: deterministic ramdisk, init filtering, and output containment are pinned'
else
    fail 'AM2 external media: ramdisk producer or init-surface containment regressed'
fi
if run_python_script scripts/test_am2_xilinx_preinit_safety.py -q >/dev/null 2>&1; then
    pass 'AM2 external pre-init: exact donor handoff and resident-chain blockers are pinned'
else
    fail 'AM2 external pre-init: donor handoff or resident-chain safety analysis regressed'
fi
if run_python_script scripts/test_am2_s19jpro_sd_builder_hardening.py -q >/dev/null 2>&1; then
    pass 'AM2 S19j Pro media: target-bound staging, input admission, and fresh-output semantics are pinned'
else
    fail 'AM2 S19j Pro media: builder input or output hardening regressed'
fi
if sh scripts/test_am2_s17_post_image.sh >/dev/null 2>&1; then
    pass 'AM2 S17 package-only media: exact held donor identity and model-bound FIT are pinned'
else
    fail 'AM2 S17 package-only media: donor identity or model-bound FIT contract regressed'
fi
if run_python_script scripts/test_am2_s17_ramdisk_swap.py -q >/dev/null 2>&1; then
    pass 'AM2 17-family ramdisk-swap: fail-closed window, mtd1/mtd4-only write map, and mtd0 never-touch stay pinned'
else
    fail 'AM2 17-family ramdisk-swap: plan-only boundary or boot-chain never-touch contract regressed'
fi
if sh scripts/test_amlogic_exact_build_inputs.sh >/dev/null 2>&1; then
    pass 'Amlogic build inputs: exact model-bound kernel, DTB, and firmware identity are pinned'
else
    fail 'Amlogic build inputs: model-bound source closure or consumer routing regressed'
fi
if sh scripts/test_pre_flash_validate_amlogic_profiles.sh >/dev/null 2>&1; then
    pass 'Amlogic package profiles: every native target validates and extracts under its exact package identity'
else
    fail 'Amlogic package profiles: validation, extraction, or unknown-target refusal regressed'
fi
if run_python_script scripts/test_amlogic_native_package_targets.py -q >/dev/null 2>&1; then
    pass 'Amlogic native targets: package identities and exact extractor variants are pinned'
else
    fail 'Amlogic native targets: package identity or extractor routing regressed'
fi
if run_python_script scripts/test_bcb100_offline_boot_inputs.py -q >/dev/null 2>&1; then
    pass 'BCB100 offline boot inputs: held declarations, absent dependencies, and denied write authority are pinned'
else
    fail 'BCB100 offline boot inputs: evidence identity or denied-authority contract regressed'
fi
if run_python_script scripts/test_sd_boot_media_manifest.py -q >/dev/null 2>&1; then
    pass 'SD media manifest: target binding, source identity, and output-collision guards are pinned'
else
    fail 'SD media manifest: identity or source-survival guarantees regressed'
fi
if run_python_script scripts/test_sd_common_output_safety.py -q >/dev/null 2>&1; then
    pass 'SD output safety: namespace, alias, and exclusive-publication guards are pinned'
else
    fail 'SD output safety: namespace or collision containment regressed'
fi
if sh scripts/test_zynq_external_media_ephemeral_policy.sh >/dev/null 2>&1; then
    pass 'AM2 external runtime: identity, volatile root, and hardware-write suppression are pinned'
else
    fail 'AM2 external runtime: ephemeral or hardware-write policy regressed'
fi

# Anti-orphan meta-gate. Raw basename grep is forbidden: comments,
# `require_pattern` arguments, and `sh -n` syntax checks are not execution.
# The reachability checker lexes active shell commands, follows variable-bound
# aggregate delegation, and admits exact workflow `run:` commands for tests
# whose restricted inputs intentionally exist only in those jobs.
require_file 'scripts/check_test_gate_reachability.py'
require_file 'scripts/test_dcentrald_hw_unresolved_env.sh'
if sh scripts/test_dcentrald_hw_unresolved_env.sh >/dev/null 2>&1; then
    pass 'dcentrald unresolved-hardware environment helper remains host-safe and mtd4-write-free'
else
    fail 'dcentrald unresolved-hardware environment helper contract regressed'
fi
require_file 'scripts/test_public_artifact_release_gate.sh'
if sh scripts/test_public_artifact_release_gate.sh >/dev/null 2>&1; then
    pass 'public artifact release gate refuses customer-facing output without release-image admission'
else
    fail 'public artifact release-image admission contract regressed'
fi
require_file 'scripts/test_s99verify_v6_board_target.sh'
if sh scripts/test_s99verify_v6_board_target.sh >/dev/null 2>&1; then
    pass 'S99verify V6 is board_target-scoped (not all am3-aml = TAS5782M)'
else
    fail 'S99verify V6 board_target-scoping contract regressed'
fi
require_file 'scripts/test_s19kpro_beta_capsule_lane.sh'
if bash scripts/test_s19kpro_beta_capsule_lane.sh >/dev/null 2>&1; then
    pass 'S19k Pro beta capsule lane: build-lane target/artifact/signing/DACL invariants are pinned'
else
    fail 'S19k Pro beta capsule lane invariants regressed'
fi
if python3 scripts/check_test_gate_reachability.py --self-test >/dev/null 2>&1 &&
   python3 scripts/check_test_gate_reachability.py; then
    pass 'anti-orphan: every shell safety suite has an active gate path'
else
    fail 'anti-orphan: a shell safety suite is mentioned but not actively reachable'
fi

require_file 'scripts/check_exact_selector_parity.py'
require_file 'scripts/run_filtered_cargo_test.sh'
require_file 'scripts/check_direct_cargo_filters.py'
if [ "$STATIC_ONLY" -eq 1 ]; then
    if python3 scripts/check_exact_selector_parity.py --inventory-only; then
        pass 'exact selectors: workflow and static inventories are equal (Cargo resolution skipped by --static-only)'
    else
        fail 'exact selectors: workflow/static inventory parity regressed'
    fi
elif python3 scripts/check_exact_selector_parity.py; then
    pass 'exact selectors: workflow and static inventories are equal and source-resolvable'
else
    fail 'exact selectors: workflow/static parity or source resolution regressed'
fi
if python3 scripts/check_direct_cargo_filters.py; then
    pass 'direct cargo filters: no zero-match false-green risk in scoped workflows'
else
    fail 'direct cargo filters: bare cargo test FILTER still present in scoped workflows'
fi

if [ "$failures" -ne 0 ]; then
    printf '\nDCENT_OS offline gates failed: %s failure(s)\n' "$failures" >&2
    exit 1
fi

printf '\nDCENT_OS offline gates passed.\n'
