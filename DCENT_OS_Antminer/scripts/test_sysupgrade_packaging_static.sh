#!/bin/sh
#
# Static regression checks for sysupgrade packaging/verifier safety.
# This script is offline only: no SSH, uploads, flashing, or live target access.

set -eu

TIER=full
case "${1:-}" in
    '') [ "$#" -eq 0 ] || exit 2 ;;
    --blocking) [ "$#" -eq 1 ] || exit 2; TIER=blocking ;;
    *) printf 'Usage: %s [--blocking]\n' "$0" >&2; exit 2 ;;
esac

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)

cd "$PROJECT_DIR"

failures=0

pass() {
    printf 'PASS: %s\n' "$*"
}

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    failures=$((failures + 1))
}

require_pattern() {
    file=$1
    pattern=$2
    label=$3

    if grep -F -- "$pattern" "$file" >/dev/null 2>&1; then
        pass "$label"
    else
        fail "$label: missing pattern '$pattern' in $file"
    fi
}

require_exact_line() {
    file=$1
    line=$2
    label=$3

    if grep -Fqx -- "$line" "$file" >/dev/null 2>&1; then
        pass "$label"
    else
        fail "$label: missing exact line '$line' in $file"
    fi
}

require_ordered_patterns() {
    file=$1
    first=$2
    second=$3
    label=$4

    if awk -v first="$first" -v second="$second" '
        first_line == 0 && index($0, first) { first_line = NR }
        first_line > 0 && index($0, second) { second_line = NR; exit }
        END { exit (first_line > 0 && second_line > first_line) ? 0 : 1 }
    ' "$file"; then
        pass "$label"
    else
        fail "$label: '$first' must precede '$second' in $file"
    fi
}

reject_pattern() {
    file=$1
    pattern=$2
    label=$3

    if grep -F -- "$pattern" "$file" >/dev/null 2>&1; then
        fail "$label: forbidden pattern '$pattern' in $file"
    else
        pass "$label"
    fi
}

# Like reject_pattern, but only inspects EXECUTABLE shell lines: comment
# lines (leading-whitespace then '#') and `echo`/`printf` recovery-hint
# lines are stripped first. This lets a sysupgrade script keep a documented
# recovery hint that NAMES the banned raw-env path in prose without the
# guard false-positiving on the comment/echo text — while still catching a
# genuine `flash_erase /dev/mtd4` / `nandwrite -p /dev/mtd4` invocation.
reject_executable_pattern() {
    file=$1
    pattern=$2
    label=$3

    if grep -Ev '^[[:space:]]*#' "$file" \
        | grep -Ev '^[[:space:]]*(echo|printf)[[:space:]]' \
        | grep -F -- "$pattern" >/dev/null 2>&1; then
        fail "$label: forbidden EXECUTABLE pattern '$pattern' in $file"
    else
        pass "$label"
    fi
}

make_test_sysupgrade_package() {
    pkgdir=$1
    status=$2
    if [ "$status" = "lab_unsigned" ]; then
        manifest_profile=dcentos.sysupgrade-unsigned-lab/v1
    else
        manifest_profile=dcentos.sysupgrade-authority/v1
    fi

    mkdir -p "$pkgdir"
    # Donor Amlogic kernel shape: 56 header bytes then the arm64 Image
    # magic "ARM\x64" at 0x38 — the only kernel form every am3 producer
    # ships (donor vmlinux.bin, sha-pinned by require-exact-build-inputs).
    dd if=/dev/zero of="$pkgdir/kernel" bs=1 count=56 2>/dev/null
    printf '\101\122\115\144kernel\n' >> "$pkgdir/kernel"
    printf '\047\005\031\126root\n' > "$pkgdir/root"
    printf 'board=am3-s19k\n' > "$pkgdir/METADATA"

    kernel_size=$(wc -c < "$pkgdir/kernel" | tr -d ' ')
    root_size=$(wc -c < "$pkgdir/root" | tr -d ' ')
    metadata_size=$(wc -c < "$pkgdir/METADATA" | tr -d ' ')
    kernel_sha=$(sha256sum "$pkgdir/kernel" | awk '{ print $1 }')
    root_sha=$(sha256sum "$pkgdir/root" | awk '{ print $1 }')
    metadata_sha=$(sha256sum "$pkgdir/METADATA" | awk '{ print $1 }')

    cat > "$pkgdir/MANIFEST.json" <<EOF
{
  "schema": 1,
  "manifest_profile": "$manifest_profile",
  "product": "DCENT_OS",
  "package_type": "sysupgrade",
  "installable": true,
  "artifact_maturity": "experimental",
  "board": "am3-s19k",
  "board_target": "am3-s19k",
  "version": "test",
  "status": "$status",
  "payloads": {
    "kernel": { "path": "sysupgrade-am3-s19k/kernel", "size": $kernel_size, "sha256": "$kernel_sha" },
    "rootfs": { "path": "sysupgrade-am3-s19k/root", "size": $root_size, "sha256": "$root_sha" },
    "metadata": { "path": "sysupgrade-am3-s19k/METADATA", "size": $metadata_size, "sha256": "$metadata_sha" }
  }
}
EOF
    (cd "$pkgdir" && sha256sum kernel root METADATA > SHA256SUMS)
}

make_test_oversized_zynq_package() {
    pkgdir=$1
    board=$2
    root_size=$3

    mkdir -p "$pkgdir"
    printf '\320\015\376\355kernel\n' > "$pkgdir/kernel"
    printf 'hsqs' > "$pkgdir/root"
    if command -v truncate >/dev/null 2>&1; then
        truncate -s "$root_size" "$pkgdir/root"
    else
        dd if=/dev/zero of="$pkgdir/root" bs=1 count=1 seek=$((root_size - 1)) conv=notrunc >/dev/null 2>&1
    fi
    printf 'board=%s\n' "$board" > "$pkgdir/METADATA"

    kernel_size=$(wc -c < "$pkgdir/kernel" | tr -d ' ')
    actual_root_size=$(wc -c < "$pkgdir/root" | tr -d ' ')
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
  "installable": true,
  "artifact_maturity": "experimental",
  "board": "$board",
  "board_target": "$board",
  "version": "test",
  "status": "lab_unsigned",
  "payloads": {
    "kernel": { "path": "sysupgrade-$board/kernel", "size": $kernel_size, "sha256": "$kernel_sha" },
    "rootfs": { "path": "sysupgrade-$board/root", "size": $actual_root_size, "sha256": "$root_sha" },
    "metadata": { "path": "sysupgrade-$board/METADATA", "size": $metadata_size, "sha256": "$metadata_sha" }
  }
}
EOF
    (cd "$pkgdir" && sha256sum kernel root METADATA > SHA256SUMS)
}

make_test_s9_package() {
    pkgdir=$1
    manifest_board=$2
    kernel_kind=$3
    requested_kernel_size=$4
    package_prefix=$(basename "$pkgdir")

    mkdir -p "$pkgdir"
    case "$kernel_kind" in
        fit)
            printf '\320\015\376\355kernel\n' > "$pkgdir/kernel"
            ;;
        bare-zimage)
            printf '\000\000\240\341kernel\n' > "$pkgdir/kernel"
            ;;
        *)
            return 1
            ;;
    esac
    current_kernel_size=$(wc -c < "$pkgdir/kernel" | tr -d ' ')
    [ "$requested_kernel_size" -ge "$current_kernel_size" ] || return 1
    if command -v truncate >/dev/null 2>&1; then
        truncate -s "$requested_kernel_size" "$pkgdir/kernel"
    else
        dd if=/dev/zero of="$pkgdir/kernel" bs=1 count=1 seek=$((requested_kernel_size - 1)) conv=notrunc >/dev/null 2>&1
    fi
    printf 'hsqs' > "$pkgdir/root"
    printf 'board=%s\n' "$manifest_board" > "$pkgdir/METADATA"

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
  "installable": true,
  "artifact_maturity": "experimental",
  "board": "$manifest_board",
  "board_target": "$manifest_board",
  "version": "test",
  "status": "lab_unsigned",
  "payloads": {
    "kernel": { "path": "$package_prefix/kernel", "size": $kernel_size, "sha256": "$kernel_sha" },
    "rootfs": { "path": "$package_prefix/root", "size": $root_size, "sha256": "$root_sha" },
    "metadata": { "path": "$package_prefix/METADATA", "size": $metadata_size, "sha256": "$metadata_sha" }
  }
}
EOF
    (cd "$pkgdir" && sha256sum kernel root METADATA > SHA256SUMS)
}

s9_expect_package_rejection() {
    package_archive=$1
    expected_reason=$2
    rejection_output=$3

    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh \
        --package-only "$package_archive" am1-s9 >"$rejection_output" 2>&1; then
        return 1
    fi
    grep -F -- "$expected_reason" "$rejection_output" >/dev/null 2>&1
}

s9_export_validation_selftest() {
    tmpdir=$(mktemp -d 2>/dev/null || echo "/tmp/dcentos-s9-export-selftest.$$")
    rm -rf "$tmpdir"
    mkdir -p "$tmpdir"

    valid_case="$tmpdir/valid"
    make_test_s9_package "$valid_case/sysupgrade-am1-s9" am1-s9 fit 16 || {
        rm -rf "$tmpdir"
        return 1
    }
    (cd "$valid_case" && tar cf s9.tar sysupgrade-am1-s9)
    if ! DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh \
        --package-only "$valid_case/s9.tar" am1-s9 >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    wrong_prefix_case="$tmpdir/wrong-prefix"
    make_test_s9_package "$wrong_prefix_case/sysupgrade-am2-s19j" am2-s19j fit 16 || {
        rm -rf "$tmpdir"
        return 1
    }
    (cd "$wrong_prefix_case" && tar cf wrong-prefix.tar sysupgrade-am2-s19j)
    s9_expect_package_rejection \
        "$wrong_prefix_case/wrong-prefix.tar" \
        "wrong package for this validation" \
        "$wrong_prefix_case/rejection.out" || {
        rm -rf "$tmpdir"
        return 1
    }

    wrong_board_case="$tmpdir/wrong-board"
    make_test_s9_package "$wrong_board_case/sysupgrade-am1-s9" am2-s19j fit 16 || {
        rm -rf "$tmpdir"
        return 1
    }
    (cd "$wrong_board_case" && tar cf wrong-board.tar sysupgrade-am1-s9)
    s9_expect_package_rejection \
        "$wrong_board_case/wrong-board.tar" \
        "MANIFEST.json package authority is inconsistent with am1-s9" \
        "$wrong_board_case/rejection.out" || {
        rm -rf "$tmpdir"
        return 1
    }

    bare_kernel_case="$tmpdir/bare-kernel"
    make_test_s9_package "$bare_kernel_case/sysupgrade-am1-s9" am1-s9 bare-zimage 16 || {
        rm -rf "$tmpdir"
        return 1
    }
    (cd "$bare_kernel_case" && tar cf bare-kernel.tar sysupgrade-am1-s9)
    s9_expect_package_rejection \
        "$bare_kernel_case/bare-kernel.tar" \
        "a bare zImage will brick the unit" \
        "$bare_kernel_case/rejection.out" || {
        rm -rf "$tmpdir"
        return 1
    }

    bad_binding_case="$tmpdir/bad-binding"
    make_test_s9_package "$bad_binding_case/sysupgrade-am1-s9" am1-s9 fit 16 || {
        rm -rf "$tmpdir"
        return 1
    }
    bound_kernel_sha=$(sha256sum "$bad_binding_case/sysupgrade-am1-s9/kernel" | awk '{ print $1 }')
    zero_sha=0000000000000000000000000000000000000000000000000000000000000000
    sed "s/$bound_kernel_sha/$zero_sha/" \
        "$bad_binding_case/sysupgrade-am1-s9/MANIFEST.json" \
        > "$bad_binding_case/sysupgrade-am1-s9/MANIFEST.json.tmp"
    mv "$bad_binding_case/sysupgrade-am1-s9/MANIFEST.json.tmp" \
        "$bad_binding_case/sysupgrade-am1-s9/MANIFEST.json"
    (cd "$bad_binding_case" && tar cf bad-binding.tar sysupgrade-am1-s9)
    s9_expect_package_rejection \
        "$bad_binding_case/bad-binding.tar" \
        "MANIFEST.json kernel payload object does not match the exact file" \
        "$bad_binding_case/rejection.out" || {
        rm -rf "$tmpdir"
        return 1
    }

    oversized_kernel_case="$tmpdir/oversized-kernel"
    make_test_s9_package \
        "$oversized_kernel_case/sysupgrade-am1-s9" am1-s9 fit 4063233 || {
        rm -rf "$tmpdir"
        return 1
    }
    (cd "$oversized_kernel_case" && tar cf oversized-kernel.tar sysupgrade-am1-s9)
    s9_expect_package_rejection \
        "$oversized_kernel_case/oversized-kernel.tar" \
        "am1-s9 kernel payload exceeds zynq kernel window (4063233B > 4063232B)" \
        "$oversized_kernel_case/rejection.out" || {
        rm -rf "$tmpdir"
        return 1
    }

    rm -rf "$tmpdir"
    return 0
}

signing_policy_selftest() {
    tmpdir=$(mktemp -d 2>/dev/null || echo "/tmp/dcentos-signing-selftest.$$")
    rm -rf "$tmpdir"
    mkdir -p "$tmpdir"

    make_test_sysupgrade_package "$tmpdir/sysupgrade-am3-s19k" release
    (cd "$tmpdir" && tar cf unsigned-release.tar sysupgrade-am3-s19k)
    if sh scripts/pre_flash_validate.sh --package-only "$tmpdir/unsigned-release.tar" am3-s19k >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh --package-only "$tmpdir/unsigned-release.tar" am3-s19k >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    rm -rf "$tmpdir/sysupgrade-am3-s19k"
    make_test_sysupgrade_package "$tmpdir/sysupgrade-am3-s19k" lab_unsigned
    (cd "$tmpdir" && tar cf unsigned-lab.tar sysupgrade-am3-s19k)
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh --package-only "$tmpdir/unsigned-lab.tar" am3-s19k >/dev/null 2>&1; then
        :
    else
        rm -rf "$tmpdir"
        return 1
    fi

    if SUP_DIR="$tmpdir/stage-release" DCENT_PACKAGE_STATUS=release sh -c '. scripts/lib/sysupgrade_package_common.sh; dcent_stage_release_key' >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi
    if SUP_DIR="$tmpdir/stage-lab" DCENT_PACKAGE_STATUS=lab_unsigned DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh -c '. scripts/lib/sysupgrade_package_common.sh; dcent_stage_release_key' >/dev/null 2>&1; then
        :
    else
        rm -rf "$tmpdir"
        return 1
    fi

    if command -v openssl >/dev/null 2>&1; then
        mkdir -p "$tmpdir/stage-generated"
        : > "$tmpdir/stage-generated/SHA256SUMS"
        openssl genpkey -algorithm Ed25519 -out "$tmpdir/generated.key" >/dev/null 2>&1 || {
            rm -rf "$tmpdir"
            return 1
        }
        if SUP_DIR="$tmpdir/stage-generated" DCENT_RELEASE_SIGNING_KEY="$tmpdir/generated.key" DCENT_PACKAGE_STATUS=release sh -c '. scripts/lib/sysupgrade_package_common.sh; dcent_stage_release_key' >/dev/null 2>&1; then
            rm -rf "$tmpdir"
            return 1
        fi
        if SUP_DIR="$tmpdir/stage-generated" DCENT_RELEASE_SIGNING_KEY="$tmpdir/generated.key" DCENT_PACKAGE_STATUS=lab_generated_key DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh -c '. scripts/lib/sysupgrade_package_common.sh; dcent_stage_release_key' >/dev/null 2>&1; then
            rm -rf "$tmpdir"
            return 1
        fi
    fi

    rm -rf "$tmpdir"
    return 0
}

zynq_payload_window_selftest() {
    tmpdir=$(mktemp -d 2>/dev/null || echo "/tmp/dcentos-zynq-window-selftest.$$")
    rm -rf "$tmpdir"
    mkdir -p "$tmpdir"

    oversized_root=$((134 * 124 * 1024 + 1))
    make_test_oversized_zynq_package "$tmpdir/sysupgrade-am1-s9" am1-s9 "$oversized_root"
    (cd "$tmpdir" && tar cf oversized-zynq.tar sysupgrade-am1-s9)
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh --package-only "$tmpdir/oversized-zynq.tar" am1-s9 >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    rm -rf "$tmpdir"
    return 0
}

# make_test_route_scoped_s9_package <pkgdir> <board> <root_size> <kernel_size> <install_mode> <update_command_json>
# AM1-A Drop-1 route scoping fixtures: a lab package whose MANIFEST carries
# an explicit typed toolbox route contract. install_mode "" emits a legacy
# manifest with NO toolbox block (the pre-scoping shape). The kernel is
# bootable FIT magic + truncate to kernel_size (0 = tiny); the root is
# squashfs magic + truncate to root_size (0 = tiny fitting root).
make_test_route_scoped_s9_package() {
    pkgdir=$1
    board=$2
    requested_root_size=$3
    requested_kernel_size=$4
    route_install_mode=$5
    route_update_json=$6
    route_installable=${7:-true}
    package_prefix="sysupgrade-$board"

    mkdir -p "$pkgdir"
    printf '\320\015\376\355kernel\n' > "$pkgdir/kernel"
    printf 'hsqs' > "$pkgdir/root"
    if [ "$requested_kernel_size" -gt 14 ]; then
        if command -v truncate >/dev/null 2>&1; then
            truncate -s "$requested_kernel_size" "$pkgdir/kernel"
        else
            dd if=/dev/zero of="$pkgdir/kernel" bs=1 count=1 seek=$((requested_kernel_size - 1)) conv=notrunc >/dev/null 2>&1
        fi
    fi
    if [ "$requested_root_size" -gt 4 ]; then
        if command -v truncate >/dev/null 2>&1; then
            truncate -s "$requested_root_size" "$pkgdir/root"
        else
            dd if=/dev/zero of="$pkgdir/root" bs=1 count=1 seek=$((requested_root_size - 1)) conv=notrunc >/dev/null 2>&1
        fi
    fi
    printf 'board=%s\n' "$board" > "$pkgdir/METADATA"

    kernel_size=$(wc -c < "$pkgdir/kernel" | tr -d ' ')
    root_size=$(wc -c < "$pkgdir/root" | tr -d ' ')
    metadata_size=$(wc -c < "$pkgdir/METADATA" | tr -d ' ')
    kernel_sha=$(sha256sum "$pkgdir/kernel" | awk '{ print $1 }')
    root_sha=$(sha256sum "$pkgdir/root" | awk '{ print $1 }')
    metadata_sha=$(sha256sum "$pkgdir/METADATA" | awk '{ print $1 }')

    if [ -n "$route_install_mode" ]; then
        toolbox_block=",
  \"toolbox\": {
    \"install_command\": \"dcent install <ip> -f dcentos-sysupgrade-118.tar\",
    \"update_command\": $route_update_json,
    \"upload_endpoint\": null,
    \"board_target_header\": null,
    \"requires_inactive_slot\": false,
    \"install_mode\": \"$route_install_mode\"
  }"
    else
        toolbox_block=""
    fi

    cat > "$pkgdir/MANIFEST.json" <<EOF
{
  "schema": 1,
  "manifest_profile": "dcentos.sysupgrade-unsigned-lab/v1",
  "product": "DCENT_OS",
  "package_type": "sysupgrade",
  "installable": $route_installable,
  "artifact_maturity": "experimental",
  "board": "$board",
  "board_target": "$board",
  "version": "test",
  "status": "lab_unsigned",
  "payloads": {
    "kernel": { "path": "$package_prefix/kernel", "size": $kernel_size, "sha256": "$kernel_sha" },
    "rootfs": { "path": "$package_prefix/root", "size": $root_size, "sha256": "$root_sha" },
    "metadata": { "path": "$package_prefix/METADATA", "size": $metadata_size, "sha256": "$metadata_sha" }
  }$toolbox_block
}
EOF
    (cd "$pkgdir" && sha256sum kernel root METADATA > SHA256SUMS)
}

# AM1-A Drop-1 route-scoped window admission (owner adjudication
#
# Option A, ratified 2026-09-15). The live-sysupgrade window stays enforced
# for every self-update-claiming shape; only the explicit first-install-only
# denial contract admits an over-window package (first-install route), and
# that waiver is itself bounded by the stock phase-2 hard volumes
# (scripts/lib/am1_s9_first_install_capacity.sh).
make_test_denied_am3_package() {
    pkgdir=$1
    board=$2
    route_installable=$3
    package_prefix="sysupgrade-$board"

    mkdir -p "$pkgdir"
    # Donor Amlogic kernel shape: 56 header bytes then the arm64 Image
    # magic "ARM\x64" at 0x38 (every am3 producer's only kernel form).
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
  "installable": $route_installable,
  "artifact_maturity": "experimental",
  "board": "$board",
  "board_target": "$board",
  "version": "test",
  "status": "lab_unsigned",
  "payloads": {
    "kernel": { "path": "$package_prefix/kernel", "size": $kernel_size, "sha256": "$kernel_sha" },
    "rootfs": { "path": "$package_prefix/root", "size": $root_size, "sha256": "$root_sha" },
    "metadata": { "path": "$package_prefix/METADATA", "size": $metadata_size, "sha256": "$metadata_sha" }
  },
  "toolbox": {
    "install_command": null,
    "update_command": null,
    "upload_endpoint": null,
    "board_target_header": null,
    "requires_inactive_slot": false,
    "install_mode": "package_only_denied",
    "target_side_sysupgrade": false
  }
}
EOF
    (cd "$pkgdir" && sha256sum kernel root METADATA > SHA256SUMS)
}

s9_route_scoped_window_selftest() {
    tmpdir=$(mktemp -d 2>/dev/null || echo "/tmp/dcentos-s9-route-selftest.$$")
    rm -rf "$tmpdir"
    mkdir -p "$tmpdir"

    # The canonical measured fact: 17,743,872 B rootfs vs 17,014,784 B window.
    oversized_root=$((134 * 124 * 1024 + 729088))
    # First-install stock-transaction capacities (stage1_builder.py:640/:642).
    fi_kernel_max=$((8 * 1024 * 1024))
    fi_rootfs_max=$((20 * 1024 * 1024))

    # (a) OVER-WINDOW rootfs (the exact measured size, 3,227,648 B under the
    # 20 MiB first-install capacity) + typed first-install-only contract -> PASS.
    make_test_route_scoped_s9_package \
        "$tmpdir/fio-pkg/sysupgrade-am1-s9" am1-s9 "$oversized_root" 0 \
        first_install_only null || { rm -rf "$tmpdir"; return 1; }
    (cd "$tmpdir/fio-pkg" && tar cf fio.tar sysupgrade-am1-s9) || { rm -rf "$tmpdir"; return 1; }
    if ! DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh \
        --package-only "$tmpdir/fio-pkg/fio.tar" am1-s9 \
        >"$tmpdir/fio.out" 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi
    grep -F 'self-update window admission waived' "$tmpdir/fio.out" >/dev/null 2>&1 || {
        rm -rf "$tmpdir"
        return 1
    }

    # (b) same OVER-WINDOW rootfs CLAIMING the self-update route -> FAIL.
    make_test_route_scoped_s9_package \
        "$tmpdir/tsu-pkg/sysupgrade-am1-s9" am1-s9 "$oversized_root" 0 \
        target_sysupgrade '"dcent install <ip> -f dcentos-sysupgrade-118.tar"' \
        || { rm -rf "$tmpdir"; return 1; }
    (cd "$tmpdir/tsu-pkg" && tar cf tsu.tar sysupgrade-am1-s9) || { rm -rf "$tmpdir"; return 1; }
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh \
        --package-only "$tmpdir/tsu-pkg/tsu.tar" am1-s9 \
        >"$tmpdir/tsu.out" 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi
    grep -F 'exceeds zynq rootfs window' "$tmpdir/tsu.out" >/dev/null 2>&1 || {
        rm -rf "$tmpdir"
        return 1
    }

    # (b2) OVER-WINDOW rootfs with a tampered denial (update_command not
    # null) -> FAIL: the denial must be machine-checkable, not decorative.
    make_test_route_scoped_s9_package \
        "$tmpdir/fio-upd-pkg/sysupgrade-am1-s9" am1-s9 "$oversized_root" 0 \
        first_install_only '"dcent install <ip> -f dcentos-sysupgrade-118.tar"' \
        || { rm -rf "$tmpdir"; return 1; }
    (cd "$tmpdir/fio-upd-pkg" && tar cf fio-upd.tar sysupgrade-am1-s9) || { rm -rf "$tmpdir"; return 1; }
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh \
        --package-only "$tmpdir/fio-upd-pkg/fio-upd.tar" am1-s9 \
        >"$tmpdir/fio-upd.out" 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi
    grep -F 'package authority is inconsistent' "$tmpdir/fio-upd.out" >/dev/null 2>&1 || {
        rm -rf "$tmpdir"
        return 1
    }

    # (b3) OVER-WINDOW rootfs with an unadmitted route value -> FAIL.
    make_test_route_scoped_s9_package \
        "$tmpdir/weird-pkg/sysupgrade-am1-s9" am1-s9 "$oversized_root" 0 \
        self_update_forced null || { rm -rf "$tmpdir"; return 1; }
    (cd "$tmpdir/weird-pkg" && tar cf weird.tar sysupgrade-am1-s9) || { rm -rf "$tmpdir"; return 1; }
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh \
        --package-only "$tmpdir/weird-pkg/weird.tar" am1-s9 >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    # (b4) inspection-only denial (the am3-s19xp shape from run
    # drop1-20260918-xtleogkg: package_only_denied + installable=false)
    # -> PASS: denial is a typed contract here, not a contradiction.
    make_test_denied_am3_package "$tmpdir/denied-pkg/sysupgrade-am3-s19xp" am3-s19xp false \
        || { rm -rf "$tmpdir"; return 1; }
    (cd "$tmpdir/denied-pkg" && tar cf denied.tar sysupgrade-am3-s19xp) || { rm -rf "$tmpdir"; return 1; }
    if ! DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh \
        --package-only "$tmpdir/denied-pkg/denied.tar" am3-s19xp \
        >"$tmpdir/denied.out" 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi
    grep -F 'toolbox route contract admitted (install_mode=package_only_denied)' "$tmpdir/denied.out" >/dev/null 2>&1 || {
        rm -rf "$tmpdir"
        return 1
    }

    # (b5) denial contradicting installable=true -> FAIL at the authority
    # layer (the semantic helper refuses the contradiction).
    make_test_denied_am3_package "$tmpdir/denied-true-pkg/sysupgrade-am3-s19xp" am3-s19xp true \
        || { rm -rf "$tmpdir"; return 1; }
    (cd "$tmpdir/denied-true-pkg" && tar cf denied-true.tar sysupgrade-am3-s19xp) || { rm -rf "$tmpdir"; return 1; }
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh \
        --package-only "$tmpdir/denied-true-pkg/denied-true.tar" am3-s19xp \
        >"$tmpdir/denied-true.out" 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi
    grep -F 'package authority is inconsistent' "$tmpdir/denied-true.out" >/dev/null 2>&1 || {
        rm -rf "$tmpdir"
        return 1
    }

    # (c) FITTING rootfs + explicit dual-route contract -> PASS (unchanged
    # behavior; the contract makes the self-update claim machine-checkable).
    make_test_route_scoped_s9_package \
        "$tmpdir/fit-tsu-pkg/sysupgrade-am1-s9" am1-s9 0 0 \
        target_sysupgrade '"dcent install <ip> -f dcentos-sysupgrade-118.tar"' \
        || { rm -rf "$tmpdir"; return 1; }
    (cd "$tmpdir/fit-tsu-pkg" && tar cf fit-tsu.tar sysupgrade-am1-s9) || { rm -rf "$tmpdir"; return 1; }
    if ! DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh \
        --package-only "$tmpdir/fit-tsu-pkg/fit-tsu.tar" am1-s9 >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    # (d) FITTING rootfs + first-install-only contract -> PASS (denying MORE
    # than required is a legal restrictive posture, never a safety hazard).
    make_test_route_scoped_s9_package \
        "$tmpdir/fit-fio-pkg/sysupgrade-am1-s9" am1-s9 0 0 first_install_only null \
        || { rm -rf "$tmpdir"; return 1; }
    (cd "$tmpdir/fit-fio-pkg" && tar cf fit-fio.tar sysupgrade-am1-s9) || { rm -rf "$tmpdir"; return 1; }
    if ! DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh \
        --package-only "$tmpdir/fit-fio-pkg/fit-fio.tar" am1-s9 >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    # (e) OVER-CAPACITY rootfs (past the stock phase-2 20 MiB hard volume)
    # + first-install-only contract -> FAIL: the waiver is bounded; such a
    # payload would abort the two-reboot transaction mid-phase-2 (both
    # merge critics' follow-up).
    make_test_route_scoped_s9_package \
        "$tmpdir/fio-cap-pkg/sysupgrade-am1-s9" am1-s9 $((fi_rootfs_max + 1)) 0 \
        first_install_only null || { rm -rf "$tmpdir"; return 1; }
    (cd "$tmpdir/fio-cap-pkg" && tar cf fio-cap.tar sysupgrade-am1-s9) || { rm -rf "$tmpdir"; return 1; }
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh \
        --package-only "$tmpdir/fio-cap-pkg/fio-cap.tar" am1-s9 \
        >"$tmpdir/fio-cap.out" 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi
    grep -F 'first-install rootfs payload exceeds the stock phase-2 hard volume' \
        "$tmpdir/fio-cap.out" >/dev/null 2>&1 || {
        rm -rf "$tmpdir"
        return 1
    }

    # (f) OVER-CAPACITY kernel (past the stock phase-2 8 MiB hard volume)
    # + first-install-only contract -> FAIL. The kernel is also over the
    # self-update kernel window, so this shape is first-install-only AND
    # has no installable route.
    make_test_route_scoped_s9_package \
        "$tmpdir/fio-kcap-pkg/sysupgrade-am1-s9" am1-s9 0 $((fi_kernel_max + 1)) \
        first_install_only null || { rm -rf "$tmpdir"; return 1; }
    (cd "$tmpdir/fio-kcap-pkg" && tar cf fio-kcap.tar sysupgrade-am1-s9) || { rm -rf "$tmpdir"; return 1; }
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh \
        --package-only "$tmpdir/fio-kcap-pkg/fio-kcap.tar" am1-s9 \
        >"$tmpdir/fio-kcap.out" 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi
    grep -F 'first-install kernel payload exceeds the stock phase-2 hard volume' \
        "$tmpdir/fio-kcap.out" >/dev/null 2>&1 || {
        rm -rf "$tmpdir"
        return 1
    }

    # (g) BOARD-SCOPE pin (merge-critic follow-up): a first_install_only
    # contract on am2-s19j gets NO waiver — the waiver conjunct is
    # am1-s9-only. Over-window for am2 = 179 LEBs x 126,976 B + 1. The
    # failure reason must be the am2 WINDOW refusal: deleting the am1-s9
    # board conjunct would route this package into the (bounded) waiver and
    # change the refusal to the capacity message, breaking this suite.
    am2_oversized_root=$((179 * 124 * 1024 + 1))
    make_test_route_scoped_s9_package \
        "$tmpdir/am2-fio-pkg/sysupgrade-am2-s19j" am2-s19j "$am2_oversized_root" 0 \
        first_install_only null || { rm -rf "$tmpdir"; return 1; }
    (cd "$tmpdir/am2-fio-pkg" && tar cf am2-fio.tar sysupgrade-am2-s19j) || { rm -rf "$tmpdir"; return 1; }
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh \
        --package-only "$tmpdir/am2-fio-pkg/am2-fio.tar" am2-s19j \
        >"$tmpdir/am2-fio.out" 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi
    grep -F 'am2-s19j root payload exceeds zynq rootfs window' \
        "$tmpdir/am2-fio.out" >/dev/null 2>&1 || {
        rm -rf "$tmpdir"
        return 1
    }

    # (h) MODE-SCOPE pin (merge-critic follow-up): host_driven_rootfs_window_lab
    # claimed on an OVER-WINDOW am1-s9 package -> FAIL — only
    # first_install_only earns the waiver. Deleting the install_mode
    # conjunct (any-mode waives) would admit this package (it is under the
    # 20 MiB capacity), breaking this suite.
    make_test_route_scoped_s9_package \
        "$tmpdir/hdr-pkg/sysupgrade-am1-s9" am1-s9 "$oversized_root" 0 \
        host_driven_rootfs_window_lab null \
        || { rm -rf "$tmpdir"; return 1; }
    (cd "$tmpdir/hdr-pkg" && tar cf hdr.tar sysupgrade-am1-s9) || { rm -rf "$tmpdir"; return 1; }
    if DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 sh scripts/pre_flash_validate.sh \
        --package-only "$tmpdir/hdr-pkg/hdr.tar" am1-s9 \
        >"$tmpdir/hdr.out" 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi
    grep -F 'am1-s9 root payload exceeds zynq rootfs window' \
        "$tmpdir/hdr.out" >/dev/null 2>&1 || {
        rm -rf "$tmpdir"
        return 1
    }

    rm -rf "$tmpdir"
    return 0
}

run_zynq_target_payload_authority() {
    authority_target_script=$1
    authority_fixture_root=$2
    {
        sed -n '/^verify_sha256() {/,/^validate_sysupgrade_tar_members() {/p' "$authority_target_script" | sed '$d'
        cat <<'SELFTEST'
validate_extracted_package_leaves &&
validate_manifest_payload_binding kernel kernel "$PACKAGE_KERNEL" &&
validate_manifest_payload_binding rootfs root "$ROOTFS" &&
validate_manifest_payload_binding metadata METADATA "$PACKAGE_SUBDIR/METADATA" &&
validate_manifest_payload_binding verification_key release_ed25519.pub "$PACKAGE_RELEASE_KEY"
SELFTEST
    } | PACKAGE_SUBDIR="$authority_fixture_root/sysupgrade-test" \
        PACKAGE_SUBDIR_NAME=sysupgrade-test \
        PACKAGE_MANIFEST="$authority_fixture_root/sysupgrade-test/MANIFEST.json" \
        PACKAGE_KERNEL="$authority_fixture_root/sysupgrade-test/kernel" \
        ROOTFS="$authority_fixture_root/sysupgrade-test/root" \
        PACKAGE_RELEASE_KEY="$authority_fixture_root/sysupgrade-test/release_ed25519.pub" \
        sh
}

write_zynq_target_authority_manifest() {
    authority_manifest_dir=$1
    authority_kernel_path=$2
    authority_kernel_size_value=$3
    authority_kernel_sha_value=$4
    authority_root_size=$(wc -c < "$authority_manifest_dir/root" | tr -d '[:space:]')
    authority_metadata_size=$(wc -c < "$authority_manifest_dir/METADATA" | tr -d '[:space:]')
    authority_key_size=$(wc -c < "$authority_manifest_dir/release_ed25519.pub" | tr -d '[:space:]')
    authority_root_sha=$(sha256sum "$authority_manifest_dir/root" | awk '{print $1}')
    authority_metadata_sha=$(sha256sum "$authority_manifest_dir/METADATA" | awk '{print $1}')
    authority_key_sha=$(sha256sum "$authority_manifest_dir/release_ed25519.pub" | awk '{print $1}')
    cat > "$authority_manifest_dir/MANIFEST.json" <<EOF
{
  "payloads": {
    "kernel": { "path": "$authority_kernel_path", "size": $authority_kernel_size_value, "sha256": "$authority_kernel_sha_value" },
    "rootfs": { "path": "sysupgrade-test/root", "size": $authority_root_size, "sha256": "$authority_root_sha" },
    "metadata": { "path": "sysupgrade-test/METADATA", "size": $authority_metadata_size, "sha256": "$authority_metadata_sha" },
    "verification_key": { "path": "sysupgrade-test/release_ed25519.pub", "size": $authority_key_size, "sha256": "$authority_key_sha" }
  }
}
EOF
}

zynq_target_payload_authority_selftest() {
    tmpdir=$(mktemp -d 2>/dev/null || echo "/tmp/dcentos-zynq-authority-selftest.$$")
    rm -rf "$tmpdir"
    fixture_dir="$tmpdir/sysupgrade-test"
    mkdir -p "$fixture_dir"
    printf 'kernel-bytes' > "$fixture_dir/kernel"
    printf 'rootfs-bytes' > "$fixture_dir/root"
    printf 'board=test\n' > "$fixture_dir/METADATA"
    printf 'test-release-key' > "$fixture_dir/release_ed25519.pub"
    kernel_size=$(wc -c < "$fixture_dir/kernel" | tr -d '[:space:]')
    kernel_sha=$(sha256sum "$fixture_dir/kernel" | awk '{print $1}')
    write_zynq_target_authority_manifest "$fixture_dir" sysupgrade-test/kernel "$kernel_size" "$kernel_sha"

    for target_script in \
        br2_external_dcentos/board/zynq/rootfs-overlay/usr/sbin/sysupgrade \
        br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/usr/sbin/sysupgrade \
        br2_external_dcentos/board/zynq/am2-s19pro/rootfs-overlay/usr/sbin/sysupgrade \
        br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay/usr/sbin/sysupgrade; do
        run_zynq_target_payload_authority "$target_script" "$tmpdir" >/dev/null 2>&1 || {
            rm -rf "$tmpdir"
            return 1
        }
    done

    printf 'unknown' > "$fixture_dir/unknown.bin"
    if run_zynq_target_payload_authority \
        br2_external_dcentos/board/zynq/rootfs-overlay/usr/sbin/sysupgrade \
        "$tmpdir" >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi
    rm -f "$fixture_dir/unknown.bin"

    mkdir -p "$fixture_dir/nested"
    printf 'nested' > "$fixture_dir/nested/payload"
    if run_zynq_target_payload_authority \
        br2_external_dcentos/board/zynq/rootfs-overlay/usr/sbin/sysupgrade \
        "$tmpdir" >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi
    rm -rf "$fixture_dir/nested"

    for invalid_case in path string-size zero-size uppercase-sha wrong-sha; do
        case "$invalid_case" in
            path)
                write_zynq_target_authority_manifest "$fixture_dir" sysupgrade-test/root "$kernel_size" "$kernel_sha"
                ;;
            string-size)
                write_zynq_target_authority_manifest "$fixture_dir" sysupgrade-test/kernel '"'"$kernel_size"'"' "$kernel_sha"
                ;;
            zero-size)
                write_zynq_target_authority_manifest "$fixture_dir" sysupgrade-test/kernel 0 "$kernel_sha"
                ;;
            uppercase-sha)
                uppercase_sha=$(printf '%s' "$kernel_sha" | tr 'a-f' 'A-F')
                write_zynq_target_authority_manifest "$fixture_dir" sysupgrade-test/kernel "$kernel_size" "$uppercase_sha"
                ;;
            wrong-sha)
                write_zynq_target_authority_manifest "$fixture_dir" sysupgrade-test/kernel "$kernel_size" '0000000000000000000000000000000000000000000000000000000000000000'
                ;;
        esac
        if run_zynq_target_payload_authority \
            br2_external_dcentos/board/zynq/rootfs-overlay/usr/sbin/sysupgrade \
            "$tmpdir" >/dev/null 2>&1; then
            rm -rf "$tmpdir"
            return 1
        fi
    done

    rm -rf "$tmpdir"
    return 0
}

# CE-183: prove dcent_require_release_image_hardening fails closed for
# release-status packages that lack DCENT_RELEASE_IMAGE=1 / the rootfs marker,
# and is a no-op for non-release lab packages.
release_image_hardening_coupling_selftest() {
    tmpdir=$(mktemp -d 2>/dev/null || echo "/tmp/dcentos-relimg-selftest.$$")
    rm -rf "$tmpdir"
    mkdir -p "$tmpdir"

    # 1) release status + DCENT_RELEASE_IMAGE=0 -> must fail closed.
    if DCENT_PACKAGE_STATUS=release DCENT_RELEASE_IMAGE=0 \
        sh -c '. scripts/lib/sysupgrade_package_common.sh; dcent_require_release_image_hardening' >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    # 2) release status + DCENT_RELEASE_IMAGE=1 + TARGET_DIR without marker -> fail.
    mkdir -p "$tmpdir/rootfs-nomarker/etc/dcentos"
    if DCENT_PACKAGE_STATUS=release DCENT_RELEASE_IMAGE=1 TARGET_DIR="$tmpdir/rootfs-nomarker" \
        sh -c '. scripts/lib/sysupgrade_package_common.sh; dcent_require_release_image_hardening' >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        return 1
    fi

    # 3) release status + DCENT_RELEASE_IMAGE=1 + TARGET_DIR WITH marker -> ok.
    mkdir -p "$tmpdir/rootfs-ok/etc/dcentos"
    : > "$tmpdir/rootfs-ok/etc/dcentos/release-image"
    if DCENT_PACKAGE_STATUS=release DCENT_RELEASE_IMAGE=1 TARGET_DIR="$tmpdir/rootfs-ok" \
        sh -c '. scripts/lib/sysupgrade_package_common.sh; dcent_require_release_image_hardening' >/dev/null 2>&1; then
        :
    else
        rm -rf "$tmpdir"
        return 1
    fi

    # 4) non-release lab status -> no-op even without DCENT_RELEASE_IMAGE.
    if DCENT_PACKAGE_STATUS=lab_unsigned DCENT_RELEASE_IMAGE=0 \
        sh -c '. scripts/lib/sysupgrade_package_common.sh; dcent_require_release_image_hardening' >/dev/null 2>&1; then
        :
    else
        rm -rf "$tmpdir"
        return 1
    fi

    rm -rf "$tmpdir"
    return 0
}

toolbox_install_contract_selftest() {
    helper='scripts/lib/sysupgrade_package_common.sh'

    if ! BOARD_NAME=am1-s9 sh -c \
        '. "$1"; dcent_require_toolbox_install_contract "$2" "$3"' \
        sh "$helper" \
        'dcent install <ip> -f dcentos-sysupgrade-118.tar' \
        target_sysupgrade >/dev/null 2>&1; then
        return 1
    fi
    if ! BOARD_NAME=am2-s19j sh -c \
        '. "$1"; dcent_require_toolbox_install_contract "$2" "$3"' \
        sh "$helper" \
        'dcent install <ip> -f dcentos-sysupgrade-am2-s19jpro.tar --artifact-dir <restore_verified_dir> --accept-am2-persistent-lab --i-have-recovery' \
        target_sysupgrade >/dev/null 2>&1; then
        return 1
    fi
    if ! BOARD_NAME=am3-s21 sh -c \
        '. "$1"; dcent_require_toolbox_install_contract "$2" "$3"' \
        sh "$helper" \
        'dcent install <ip> -f dcentos-sysupgrade-am3-s21.tar --artifact-dir <restore_verified_dir>' \
        host_driven_rootfs_window_lab >/dev/null 2>&1; then
        return 1
    fi

    for bad_command in \
        'dcent install <ip> -f dcentos-sysupgrade-am3-s21.tar' \
        'dcent install <ip> -f dcentos-sysupgrade-am3-s21.tar --artifact-dir <restore_verified_dir> --yes' \
        'dcent install <ip> -f dcentos-sysupgrade-am3-s21.tar --artifact-dir <restore_verified_dir> --accept-vnish-aml-rootfs-window'
    do
        if BOARD_NAME=am3-s21 sh -c \
            '. "$1"; dcent_require_toolbox_install_contract "$2" "$3"' \
            sh "$helper" "$bad_command" \
            host_driven_rootfs_window_lab >/dev/null 2>&1; then
            return 1
        fi
    done

    for bad_command in \
        'dcent install <ip> -f dcentos-sysupgrade-am2-s19jpro.tar --accept-am2-persistent-lab --i-have-recovery' \
        'dcent install <ip> -f dcentos-sysupgrade-am2-s19jpro.tar --artifact-dir <restore_verified_dir> --i-have-recovery' \
        'dcent install <ip> -f dcentos-sysupgrade-am2-s19jpro.tar --artifact-dir <restore_verified_dir> --accept-am2-persistent-lab'
    do
        if BOARD_NAME=am2-s19j sh -c \
            '. "$1"; dcent_require_toolbox_install_contract "$2" "$3"' \
            sh "$helper" "$bad_command" target_sysupgrade >/dev/null 2>&1; then
            return 1
        fi
    done

    return 0
}

# 2026-08-15: update_command metadata may advertise the fleet OTA rail
# (`dcent ota update-fleet`, toolbox S21 rootfs-window acceptance) as the
# update form of the SAME guarded route. The install contract stays strict
# (install_command must remain `dcent install ...`); the update contract
# accepts either form with identical safety-gate requirements.
toolbox_update_contract_selftest() {
    helper='scripts/lib/sysupgrade_package_common.sh'

    # Accepted: fleet OTA form with the restore-verified artifact gate.
    if ! BOARD_NAME=am3-s21 sh -c \
        '. "$1"; dcent_require_toolbox_update_contract "$2" "$3"' \
        sh "$helper" \
        'dcent ota update-fleet <ip> -f dcentos-sysupgrade-am3-s21.tar --artifact-dir <restore_verified_dir>' \
        host_driven_rootfs_window_lab >/dev/null 2>&1; then
        return 1
    fi
    # Accepted: legacy single-unit install form as update (back-compat).
    if ! BOARD_NAME=am3-s21 sh -c \
        '. "$1"; dcent_require_toolbox_update_contract "$2" "$3"' \
        sh "$helper" \
        'dcent install <ip> -f dcentos-sysupgrade-am3-s21.tar --artifact-dir <restore_verified_dir>' \
        host_driven_rootfs_window_lab >/dev/null 2>&1; then
        return 1
    fi

    for bad_command in \
        'dcent ota update-fleet <ip> -f dcentos-sysupgrade-am3-s21.tar' \
        'dcent ota update-fleet <ip> -f dcentos-sysupgrade-am3-s21.tar --artifact-dir <restore_verified_dir> --yes' \
        'dcent ota update-fleet <ip> -f dcentos-sysupgrade-am3-s21.tar --artifact-dir <restore_verified_dir> --accept-vnish-aml-rootfs-window' \
        'dcent flash <ip> -f dcentos-sysupgrade-am3-s21.tar --artifact-dir <restore_verified_dir>'
    do
        if BOARD_NAME=am3-s21 sh -c \
            '. "$1"; dcent_require_toolbox_update_contract "$2" "$3"' \
            sh "$helper" "$bad_command" \
            host_driven_rootfs_window_lab >/dev/null 2>&1; then
            return 1
        fi
    done

    # The strict INSTALL contract must still refuse the OTA-only form:
    # install_command metadata remains single-unit `dcent install`.
    if BOARD_NAME=am3-s21 sh -c \
        '. "$1"; dcent_require_toolbox_install_contract "$2" "$3"' \
        sh "$helper" \
        'dcent ota update-fleet <ip> -f dcentos-sysupgrade-am3-s21.tar --artifact-dir <restore_verified_dir>' \
        host_driven_rootfs_window_lab >/dev/null 2>&1; then
        return 1
    fi

    return 0
}

# CE-374: exercise AM2's strict plan validator here. AM1's stricter Python
# evidence suite is wired into the Python safety gate and Zynq integration gate.
nand_backup_identity_selftest() {
    python_bin=$(command -v python3 || command -v python || true)
    [ -n "$python_bin" ] || return 0
    "$python_bin" scripts/validate_am2_nand_backup_plan.py --self-test >/dev/null
}

require_no_active_fw_env_lines() {
    file=$1
    label=$2

    if grep -Ev '^[[:space:]]*(#|$)' "$file" >/dev/null 2>&1; then
        fail "$label: fw_env.config has active device lines"
    else
        pass "$label"
    fi
}

# Assert a one-line board identity file (etc/dcentos/<name>) exists and its
# sole non-empty line is exactly the expected canonical string. Buildroot
# overlay identity files are authored as a single value + trailing newline,
# so this rejects both a missing file and a drifted value.
require_identity_file() {
    file=$1
    expected=$2
    label=$3

    if [ ! -f "$file" ]; then
        fail "$label: missing identity file $file"
        return
    fi

    actual=$(tr -d '\r' < "$file" | sed -n '/[^[:space:]]/{p;q;}' | sed 's/[[:space:]]*$//')
    if [ "$actual" = "$expected" ]; then
        pass "$label"
    else
        fail "$label: $file = '$actual', expected '$expected'"
    fi
}

BB_S99='br2_external_dcentos/board/beaglebone/am3-bb/rootfs-overlay/etc/init.d/S99upgrade'
BB_FW_ENV='br2_external_dcentos/board/beaglebone/am3-bb/rootfs-overlay/etc/fw_env.config'
VERIFY='scripts/verify_sysupgrade_signature.sh'
PACKAGE='scripts/package_sysupgrade.sh'
PRE_FLASH='scripts/pre_flash_validate.sh'
VERSION_GATE='scripts/lib/dcentrald_version_gate.sh'
ARCHIVE_ADMISSION='scripts/lib/sysupgrade_archive_admission.sh'
ZYNQ_GEOMETRY_HELPER='scripts/lib/sysupgrade_zynq_geometry.sh'
MANIFEST_JSON='scripts/lib/sysupgrade_manifest_json.py'
AM2_POST_IMAGE='br2_external_dcentos/board/zynq/am2-s19jpro/post-image.sh'
AM3_S19K_POST_IMAGE='br2_external_dcentos/board/amlogic/am3-s19kpro/post-image.sh'
AM3_S21_POST_IMAGE='br2_external_dcentos/board/amlogic/post-image-family.sh'
AM3_S19XP_MUTATION_POLICY='br2_external_dcentos/board/amlogic/am3-s19xp/rootfs-overlay/etc/dcentos/mutation_policy'
AM3_S19JXP_MUTATION_POLICY='br2_external_dcentos/board/amlogic/am3-s19jxp/rootfs-overlay/etc/dcentos/mutation_policy'
AM3_S21PRO_POST_IMAGE='br2_external_dcentos/board/amlogic/post-image-family.sh'
AM3_S21XP_POST_IMAGE='br2_external_dcentos/board/amlogic/post-image-family.sh'
AM3_S21XP_MUTATION_POLICY='br2_external_dcentos/board/amlogic/am3-s21xp/rootfs-overlay/etc/dcentos/mutation_policy'
AM3_T21_POST_IMAGE='br2_external_dcentos/board/amlogic/post-image-family.sh'
AM3_T21_POST_BUILD='br2_external_dcentos/board/amlogic/am3-t21/post-build.sh'
AM3_T21_MUTATION_POLICY='br2_external_dcentos/board/amlogic/am3-t21/rootfs-overlay/etc/dcentos/mutation_policy'
AMLOGIC_S46POST_INSTALL='br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S46post-install'
AM3_S19JPRO_AML_POST_IMAGE='br2_external_dcentos/board/amlogic/am3-s19jpro-aml/post-image.sh'
AMLOGIC_S37BOARD_SETUP='br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S37board_setup'
AMLOGIC_S82DCENTRALD='br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S82dcentrald'
AMLOGIC_S99UPGRADE='br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S99upgrade'
AM3_GEOMETRY='scripts/lib/am3_geometry.sh'
SYSUPGRADE_COMMON='scripts/lib/sysupgrade_package_common.sh'
AM3_BB_REVERT='scripts/revert_to_stock_am335x_bb.sh'
S9_REVERT='scripts/revert_to_stock_s9.sh'
S17_REVERT='scripts/revert_to_stock_s17.sh'
S19_AM2_REVERT='scripts/revert_to_stock_s19_am2.sh'
AM3_S19K_REVERT='scripts/revert_to_stock_am3_aml_s19k.sh'
AM3_S21_REVERT='scripts/revert_to_stock_am3_aml_s21.sh'
BUILD_DOCKER='scripts/build_in_docker.sh'
BUILD_WSL='scripts/build_in_wsl.sh'
BUILD_AMLOGIC_NATIVE='scripts/build_amlogic_native_install.sh'
S9_SYSUPGRADE='br2_external_dcentos/board/zynq/rootfs-overlay/usr/sbin/sysupgrade'
AM2_SYSUPGRADE='br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/usr/sbin/sysupgrade'
AM2_S19PRO_SYSUPGRADE='br2_external_dcentos/board/zynq/am2-s19pro/rootfs-overlay/usr/sbin/sysupgrade'
AM2_S17PRO_SYSUPGRADE='br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay/usr/sbin/sysupgrade'
S9_POST_BUILD='br2_external_dcentos/board/zynq/post-build.sh'
AM2_POST_BUILD='br2_external_dcentos/board/zynq/am2-s19jpro/post-build.sh'
AM2_S19PRO_POST_BUILD='br2_external_dcentos/board/zynq/am2-s19pro/post-build.sh'
AM2_S17PRO_POST_BUILD='br2_external_dcentos/board/zynq/am2-s17pro/post-build.sh'
RESTORE_ROUTE='dcentrald/dcentrald-api/src/routes/restore_to_stock.rs'
CI_BETA_XIL_RELEASE_GATES='scripts/ci_beta_xil_release_gates.sh'
BETA_XIL_RELEASE_NAMES='scripts/verify_beta_xil_release_names.sh'
FIRMWARE_RELEASE_NAME='scripts/firmware_release_name.sh'

require_pattern "$BB_S99" 'no NAND recovery flag or fw_env commit' 'am3-bb S99upgrade declares no NAND/fw_env commit'
require_pattern "$BB_S99" 'dcentrald API management endpoint is reachable' 'am3-bb S99upgrade uses management-readiness wording'
reject_pattern "$BB_S99" 'fw_setenv' 'am3-bb S99upgrade does not call fw_setenv'
reject_pattern "$BB_S99" 'flash_erase' 'am3-bb S99upgrade does not erase NAND'
reject_pattern "$BB_S99" 'nandwrite' 'am3-bb S99upgrade does not write NAND'
reject_pattern "$BB_S99" 'RECOVERY_FLAG_OFFSET' 'am3-bb S99upgrade does not inherit Amlogic recovery offsets'
require_no_active_fw_env_lines "$BB_FW_ENV" 'am3-bb fw_env.config masks Amlogic env layout'

require_pattern "$VERIFY" '#!/bin/sh' 'verifier is POSIX/BusyBox shell'
require_pattern "$VERIFY" 'validate_payload_hash "$SUBDIR_NAME/kernel" "kernel"' 'verifier checks kernel payload hash'
require_pattern "$VERIFY" 'validate_payload_hash "$SUBDIR_NAME/root" "rootfs"' 'verifier checks rootfs payload hash'
require_pattern "$VERIFY" 'validate_payload_hash "$SUBDIR_NAME/METADATA" "metadata"' 'verifier checks metadata payload hash'
require_pattern "$VERIFY" 'validate_payload_hash "$SUBDIR_NAME/release_ed25519.pub" "verification_key"' 'verifier checks embedded verification key hash'
require_pattern "$VERIFY" 'Manifest board_target' 'verifier checks manifest board_target'
require_pattern "$VERIFY" 'Manifest product' 'verifier checks manifest product'
require_pattern "$VERIFY" 'Public key is not a valid PEM public key' 'verifier rejects malformed placeholder public keys'
require_pattern "$VERIFY" 'Package manifest and signature validated' 'verifier uses manifest/signature validated wording'
reject_pattern "$VERIFY" 'Signature verified:' 'verifier no longer reports signature-only proof'

require_pattern "$ARCHIVE_ADMISSION" 'DCENT_SYSUPGRADE_ARCHIVE_MAX_MEMBERS=32' 'archive admission caps sysupgrade envelopes at 32 members'
require_pattern "$ARCHIVE_ADMISSION" 'duplicate archive member' 'archive admission rejects duplicate exact members'
require_pattern "$ARCHIVE_ADMISSION" 'duplicate logical archive member' 'archive admission rejects duplicate logical members'
require_pattern "$ARCHIVE_ADMISSION" 'expected exactly one canonical %s/ directory member' 'archive admission requires one exact target prefix directory'
require_pattern "$ARCHIVE_ADMISSION" 'nested or empty member path' 'archive admission rejects nested member paths'
require_pattern "$ARCHIVE_ADMISSION" 'unsafe type %s for member %s' 'archive admission rejects symlink, hardlink, and special members'
require_pattern "$ARCHIVE_ADMISSION" 'unknown member leaf' 'archive admission uses an explicit leaf allowlist'
require_pattern "$ARCHIVE_ADMISSION" 'archive payload is not declared exactly once in MANIFEST.json' 'archive admission rejects unmanifested optional payload leaves'
require_pattern "$ARCHIVE_ADMISSION" 'fpga_bitstream.bit' 'archive admission preserves the manifest-bound optional FPGA bitstream'
require_pattern "$ARCHIVE_ADMISSION" "grep -F '\\'" 'archive admission rejects all JSON escape aliases before byte-oriented authority readers'
require_pattern "$MANIFEST_JSON" 'object_pairs_hook=_unique_object' 'semantic manifest admission rejects decoded duplicate keys at every object depth'
require_pattern "$MANIFEST_JSON" 'compare-version' 'semantic manifest authority exposes the deterministic version comparator'
require_pattern "$MANIFEST_JSON" 'require_payload_binding' 'semantic manifest authority binds path, size, and digest inside one exact payload object'
require_pattern "$PRE_FLASH" 'verify-payload "$MANIFEST" kernel' 'package-only validator uses typed kernel payload-object binding'
require_pattern "$PRE_FLASH" 'verify-payload "$MANIFEST" rootfs' 'package-only validator uses typed rootfs payload-object binding'
reject_pattern "$PRE_FLASH" 'manifest_payload_block()' 'package-only validator removes substring-based JSON object splitting'

require_pattern "$PACKAGE" 'infer_package_version' 'packager infers package version'
require_pattern "$PACKAGE" 'Package version is required for fail-closed release manifests' 'packager fails closed if version cannot be set'
require_pattern "$PACKAGE" '"version": "$PACKAGE_VERSION"' 'packager writes a non-null manifest version'
reject_pattern "$PACKAGE" '"version": null' 'packager does not emit null manifest version'
require_pattern "$PRE_FLASH" 'AM3 root uImage + kernel arm64 Image magic valid' 'package-only validator has explicit AM3 uImage-root/arm64-kernel profile'
require_pattern "$PRE_FLASH" 'AM3 root payload fits am3 rootfs window' 'package-only validator keeps AM3 rootfs window gate'
require_pattern "$PRE_FLASH" 'squashfs-style root payload magic valid' 'package-only validator has squashfs-style board profile'
require_pattern "$PRE_FLASH" 'AM3 uImage/rootfs-window checks skipped for squashfs-style' 'package-only validator does not label S9/am2 packages as AM3 uImage'
require_pattern "$PRE_FLASH" 'sysupgrade_zynq_geometry.sh' 'package-only validator sources canonical real-target Zynq geometry'
require_pattern "$ZYNQ_GEOMETRY_HELPER" 'ZYNQ_UBI_LEB_SIZE_BYTES=126976' 'canonical geometry pins captured Xilinx UBI LEB bytes'
require_pattern "$ZYNQ_GEOMETRY_HELPER" 'AM2_ZYNQ_KERNEL_PACKAGE_LEBS=23' 'canonical geometry separates package fit from runtime layout tolerance'
require_pattern "$ZYNQ_GEOMETRY_HELPER" 'AM2_ZYNQ_ROOTFS_PACKAGE_LEBS=179' 'canonical geometry pins the live AM2 rootfs window'
require_pattern "$ZYNQ_GEOMETRY_HELPER" 'AM2_ZYNQ_KERNEL_TAR_BOUND_BYTES=' 'canonical geometry exposes a separate pre-extraction bound'
require_pattern "$PRE_FLASH" 'assert_payload_fits_window "$board kernel" "$kernel_size" "$ZYNQ_KERNEL_MAX_BYTES" "zynq kernel window"' 'package-only validator rejects oversized Zynq kernels'
require_pattern "$PRE_FLASH" 'assert_payload_fits_window "$board root" "$root_size" "$ZYNQ_ROOTFS_MAX_BYTES" "zynq rootfs window"' 'package-only validator rejects oversized Zynq rootfs payloads'
# --- AM1-A Drop-1 route-scoped geometry admission (adjudication Option A) -----
# The am1-s9 package windows are the live-sysupgrade (self-update) volume
# plan (owner adjudication
#
# Option A, ratified 2026-09-15). An over-window package may serve the
# FIRST-INSTALL route only when its manifest carries the typed
# self-update denial; every self-update-claiming shape still fails closed.
require_pattern "$PACKAGE" 'AM1_S9_ROOTFS_WINDOW_ADJUDICATION.md' 'packager cites the route-scoping owner adjudication'
require_pattern "$PACKAGE" 'AM1_S9_SELF_UPDATE_FITS=0' 'packager derives the self-update route claim from payload fit'
require_pattern "$PACKAGE" 'S9_TOOLBOX_INSTALL_MODE=first_install_only' 'packager emits the typed first-install-only contract for over-window payloads'
require_pattern "$PACKAGE" 'S9_TOOLBOX_UPDATE_COMMAND_JSON=null' 'packager denies self-update explicitly (null update_command) for over-window payloads'
require_pattern "$PACKAGE" 'refusing to seal a self-update contract for an oversized package' 'packager fails closed on a self-update claim with an over-window payload'
require_pattern "$PACKAGE" 'dcent_require_toolbox_install_contract "$S9_TOOLBOX_INSTALL_COMMAND" "$S9_TOOLBOX_INSTALL_MODE"' 'packager validates its emitted contract through the shared typed-contract machinery'
require_pattern "$PACKAGE" 'dcent_require_toolbox_update_contract "$S9_TOOLBOX_UPDATE_COMMAND_PLAIN" "$S9_TOOLBOX_INSTALL_MODE"' 'packager validates the update-command denial through the shared typed-contract machinery'
require_pattern "$PACKAGE" 'Drop-1 FIRST-INSTALL-ONLY package' 'packager summary honestly marks a first-install-only artifact'
require_pattern "$PACKAGE" 'Refusing --upload of a first-install-only package' 'packager refuses the live-upload self-update rail for a first-install-only package'
require_pattern "$PRE_FLASH" 'query-install-mode' 'package-only validator reads the route contract through the typed semantic helper'
require_pattern "$PRE_FLASH" 'self-update window admission waived' 'package-only validator records the first-install-only window waiver'
require_pattern "$PRE_FLASH" 'is not an admitted route contract' 'package-only validator rejects unadmitted toolbox route values'
require_pattern "$MANIFEST_JSON" 'first_install_only' 'semantic manifest helper knows the first-install-only route contract'
require_pattern "$MANIFEST_JSON" 'require_install_mode_contract' 'semantic manifest helper exposes the typed route-contract admission'
require_pattern "$SYSUPGRADE_COMMON" 'first_install_only)' 'shared typed-contract machinery admits the first_install_only install mode'
require_pattern "$SYSUPGRADE_COMMON" 'first-install-only metadata must not advertise an update command' 'shared typed-contract machinery refuses an update command under the first-install-only denial'
# First-install capacity admission (merge-critic follow-up, both critics):
# the waiver is bounded by the stock two-reboot transaction's HARD phase-2
# volumes — kernel -s 8MiB / rootfs -s 20MiB
# (dcent-toolbox/src/dcent_toolbox/core/stage1_builder.py:640/:642). Defined
# ONCE in scripts/lib/am1_s9_first_install_capacity.sh and enforced at both
# seal time (packager) and pre-flash waiver time.
AM1_S9_FI_CAPACITY='scripts/lib/am1_s9_first_install_capacity.sh'
require_pattern "$AM1_S9_FI_CAPACITY" 'AM1_S9_FIRST_INSTALL_KERNEL_MAX_BYTES=$((8 * 1024 * 1024))' 'first-install capacity helper pins the 8MiB stock kernel volume'
require_pattern "$AM1_S9_FI_CAPACITY" 'AM1_S9_FIRST_INSTALL_ROOTFS_MAX_BYTES=$((20 * 1024 * 1024))' 'first-install capacity helper pins the 20MiB stock rootfs volume'
require_pattern "$AM1_S9_FI_CAPACITY" 'stage1_builder.py:640' 'first-install capacity helper cites the hard kernel volume site'
require_pattern "$AM1_S9_FI_CAPACITY" 'stage1_builder.py:642' 'first-install capacity helper cites the hard rootfs volume site'
require_pattern "$AM1_S9_FI_CAPACITY" 'dcent_am1_s9_require_first_install_capacity' 'first-install capacity helper exposes the admission proof'
require_pattern "$PACKAGE" 'dcent_am1_s9_require_first_install_capacity "$KERNEL_SIZE" "$ROOTFS_SIZE"' 'packager refuses to seal a first-install-only package beyond the stock-transaction capacity'
require_pattern "$PACKAGE" 'no installable route; refusing to seal' 'packager names the both-windows-and-capacity refusal'
require_pattern "$PRE_FLASH" 'am1-s9 first-install-only waiver is bounded' 'pre-flash waiver is bounded by the stock-transaction capacity'
require_pattern "$PRE_FLASH" 'am1_s9_first_install_capacity.sh' 'pre-flash validator sources the canonical first-install capacity helper'
require_pattern "$PRE_FLASH" '[ "$board" = "am1-s9" ] && [ "$install_mode" = "first_install_only" ]' 'pre-flash waiver conjunct is am1-s9 AND first_install_only only (board and mode scope pinned textually)'
# --- end AM1-A route-scoped admission coverage ---------------------------------
require_pattern "$PRE_FLASH" 'am1-s9|am2-s19j|am2-s19jpro|am2-s19pro|am2-s17p)' 'package-only validator covers all admitted Zynq board identities'
require_pattern "$PRE_FLASH" 'validate_package_only "$TARBALL" "am1-s9"' 'am1-s9 live pre-flash validates the package before declaring backup-floor success (CE-352)'
require_pattern "$BUILD_DOCKER" 'BOARD_PKG_NAME="am1-s9"' 'S9 build target retains exact am1-s9 package identity'
require_exact_line "$BUILD_DOCKER" '            s9|am3-s19kpro|am3-s19kpro-nopic|am3-s19xp|am3-s19jxp|am3-s19jproa|am3-s19jproplus|am3-s21|am3-s21pro|am3-s21xp|am3-s19jpro-aml|am3-t21|am2-s19jpro|am2-s19pro)' 'build_in_docker structurally validates its remaining sysupgrade tar recipes'
require_pattern "$BUILD_DOCKER" 'if [ "$BOARD_POST_IMAGE" != native-sd ]; then' 'native SD outputs select their actual media validator outside the tar branch'
require_pattern "$BUILD_DOCKER" 'python3 "$SCRIPT_DIR/release_producer.py" verify-native-media' 'native SD export invokes the independent current-media reader'
require_ordered_patterns "$BUILD_DOCKER" '-sigfile "$OUTPUT_DIR/$TARBALL_NAME.sig" -in "$OUTPUT_DIR/$TARBALL_NAME"' 'python3 "$SCRIPT_DIR/release_producer.py" verify-native-media' 'native media validation follows actual outer artifact signing and verification'
require_exact_line "$BUILD_DOCKER" '            am3-bb|am3-bb-s19jpro|am3-bb-s19jpro-payload)' 'build_in_docker keeps BB payload targets on their distinct SD-card payload validation branch'
require_pattern "$BUILD_DOCKER" 'SD-card payload validation:' 'BB export validation remains SD-card-specific, not sysupgrade package validation'
require_pattern "$BUILD_DOCKER" 'Package-only non-installable validation:' 'build_in_docker gives am2-s17pro a distinct non-installable validation lane'
require_pattern "$BUILD_DOCKER" 'find buildroot/output/build -mindepth 2 -maxdepth 2 -name .applied_patches_list' 'evidence sweep removes unrecoverable half-patched package state before legal-info'
require_pattern "$BUILD_DOCKER" '[ ! -e "$package_dir/.stamp_patched" ]' 'evidence sweep removes dirs whose patch stamp is missing'
require_pattern "$BUILD_DOCKER" '.stamp_patched" -ot "$package_dir/.stamp_extracted"' 'evidence sweep also heals patch stamps older than their extract prerequisite'
require_pattern "$BUILD_DOCKER" 'rm -rf "$package_dir"' 'evidence sweep completes the package-dir removal its detection prescribes'
require_pattern "$BUILD_DOCKER" 'echo "fund_url=https://d-central.tech/fund/"' 'release metadata carries the fund link the train publication gate scans for'
require_pattern "$BUILD_DOCKER" 'trap "rm -rf -- \"$PACKAGE_ONLY_TMP\"" EXIT HUP INT TERM' 'am2-s17pro package validator cleanup stays inside the container-script quoting boundary'
require_pattern "$BUILD_DOCKER" 'S17 package-only manifest must declare installable=false' 'am2-s17pro wrapper preserves package-only denial'
require_pattern "$BUILD_DOCKER" 'extract_am2_s17_kernel.py verify-fit' 'am2-s17pro wrapper re-admits the exact model-bound FIT after export'
require_pattern "$SYSUPGRADE_COMMON" 'dcent_require_toolbox_install_contract "$install_command" "$install_mode"' 'manifest writer validates its operator install command'
require_pattern "$SYSUPGRADE_COMMON" 'must preserve interactive confirmation' 'package metadata never pre-acknowledges --yes'
require_pattern "$SYSUPGRADE_COMMON" 'must not pre-acknowledge the VNish-source safety gate' 'generic Amlogic package metadata does not pre-acknowledge a source-specific route'
require_pattern "$BUILD_DOCKER" '--artifact-dir <restore_verified_dir> --plan' 'Amlogic build handoff supplies the restore-verified artifact directory'
require_pattern "$BUILD_AMLOGIC_NATIVE" 'ln "$STAGED_ROOT" "$BIN_PATH"' 'Amlogic native extractor publishes without replacing an existing alias'
require_pattern "$S9_SYSUPGRADE" 'payload_fits_ubi_volume' 'S9 sysupgrade validates payload byte fit before UBI writes'
require_pattern "$AM2_SYSUPGRADE" 'payload_fits_ubi_volume' 'am2-s19j sysupgrade validates payload byte fit before UBI writes'
require_pattern "$AM2_S19PRO_SYSUPGRADE" 'payload_fits_ubi_volume' 'am2-s19pro sysupgrade validates payload byte fit before UBI writes'
require_pattern "$AM2_S17PRO_SYSUPGRADE" 'payload_fits_ubi_volume' 'am2-s17p sysupgrade validates payload byte fit before UBI writes'
require_pattern "$S9_SYSUPGRADE" 'validate_sysupgrade_tar_preextract "$ROOTFS"' 'S9 sysupgrade bounds package tar size before extraction'
require_pattern "$AM2_SYSUPGRADE" 'validate_sysupgrade_tar_preextract "$ROOTFS"' 'am2-s19j sysupgrade bounds package tar size before extraction'
require_pattern "$AM2_S19PRO_SYSUPGRADE" 'validate_sysupgrade_tar_preextract "$ROOTFS"' 'am2-s19pro sysupgrade bounds package tar size before extraction'
require_pattern "$AM2_S17PRO_SYSUPGRADE" 'validate_sysupgrade_tar_preextract "$ROOTFS"' 'am2-s17p sysupgrade bounds package tar size before extraction'
require_pattern "$S9_SYSUPGRADE" 'Refusing before tar extraction' 'S9 sysupgrade reports pre-extraction package refusal'
require_pattern "$AM2_SYSUPGRADE" 'Refusing before tar extraction' 'am2-s19j sysupgrade reports pre-extraction package refusal'
require_pattern "$AM2_S19PRO_SYSUPGRADE" 'Refusing before tar extraction' 'am2-s19pro sysupgrade reports pre-extraction package refusal'
require_pattern "$AM2_S17PRO_SYSUPGRADE" 'Refusing before tar extraction' 'am2-s17p sysupgrade reports pre-extraction package refusal'
require_pattern "$S9_SYSUPGRADE" 'Refusing before ubiupdatevol' 'S9 sysupgrade names the pre-write oversized-payload refusal'
require_pattern "$AM2_SYSUPGRADE" 'Refusing before ubiupdatevol' 'am2-s19j sysupgrade names the pre-write oversized-payload refusal'
require_pattern "$AM2_S19PRO_SYSUPGRADE" 'Refusing before ubiupdatevol' 'am2-s19pro sysupgrade names the pre-write oversized-payload refusal'
require_pattern "$AM2_S17PRO_SYSUPGRADE" 'Refusing before ubiupdatevol' 'am2-s17p sysupgrade names the pre-write oversized-payload refusal'
for zynq_sysupgrade in "$S9_SYSUPGRADE" "$AM2_SYSUPGRADE" "$AM2_S19PRO_SYSUPGRADE" "$AM2_S17PRO_SYSUPGRADE"; do
    require_exact_line "$zynq_sysupgrade" 'manifest_key_count() {' "Zynq sysupgrade $(basename "$zynq_sysupgrade") defines the manifest cardinality helper under its callable name"
    require_pattern "$zynq_sysupgrade" 'dcentos.sysupgrade-authority/v1' "Zynq sysupgrade $(basename "$zynq_sysupgrade") requires the versioned mutation-authority profile"
    require_pattern "$zynq_sysupgrade" 'dcentos.sysupgrade-unsigned-lab/v1)' "Zynq sysupgrade $(basename "$zynq_sysupgrade") recognizes the explicit unsigned lab profile"
    require_pattern "$zynq_sysupgrade" 'Package authority-v1 forbids status=lab_unsigned' "Zynq sysupgrade $(basename "$zynq_sysupgrade") rejects the signed/unsigned status contradiction"
    require_pattern "$zynq_sysupgrade" "exactly one 'status' authority field" "Zynq sysupgrade $(basename "$zynq_sysupgrade") requires one unambiguous status claim"
    require_pattern "$zynq_sysupgrade" 'status must not contain surrounding whitespace' "Zynq sysupgrade $(basename "$zynq_sysupgrade") rejects whitespace-padded status"
    require_pattern "$zynq_sysupgrade" 'version must not contain surrounding whitespace' "Zynq sysupgrade $(basename "$zynq_sysupgrade") rejects whitespace-padded version"
    require_pattern "$zynq_sysupgrade" 'Package unsigned-lab/v1 requires exactly one status=lab_unsigned field' "Zynq sysupgrade $(basename "$zynq_sysupgrade") pins exact unsigned lab status"
    require_pattern "$zynq_sysupgrade" 'Package unsigned-lab/v1 forbids MANIFEST.sig' "Zynq sysupgrade $(basename "$zynq_sysupgrade") rejects signatures in the unsigned lab profile"
    require_pattern "$zynq_sysupgrade" 'Package unsigned-lab/v1 forbids release_ed25519.pub' "Zynq sysupgrade $(basename "$zynq_sysupgrade") rejects release keys in the unsigned lab profile"
    require_pattern "$zynq_sysupgrade" 'Package unsigned-lab/v1 forbids a verification_key payload' "Zynq sysupgrade $(basename "$zynq_sysupgrade") rejects verification authority in the unsigned lab profile"
    require_pattern "$zynq_sysupgrade" 'for payload_key in kernel rootfs metadata' "Zynq sysupgrade $(basename "$zynq_sysupgrade") bounds named payload duplicates"
    require_pattern "$zynq_sysupgrade" 'validate_extracted_package_leaves || exit 1' "Zynq sysupgrade $(basename "$zynq_sysupgrade") revalidates the extracted flat leaf envelope"
    require_pattern "$zynq_sysupgrade" 'Extracted package contains nested payload entry' "Zynq sysupgrade $(basename "$zynq_sysupgrade") rejects post-extraction nested entries"
    require_pattern "$zynq_sysupgrade" 'Extracted package contains unknown payload leaf' "Zynq sysupgrade $(basename "$zynq_sysupgrade") rejects post-extraction unknown leaves"
    require_pattern "$zynq_sysupgrade" "for _payload_field in path size sha256" "Zynq sysupgrade $(basename "$zynq_sysupgrade") requires one complete payload declaration tuple"
    require_pattern "$zynq_sysupgrade" "payload path must be exactly" "Zynq sysupgrade $(basename "$zynq_sysupgrade") binds payload kinds to canonical paths"
    require_pattern "$zynq_sysupgrade" 'payload size must be a positive JSON integer' "Zynq sysupgrade $(basename "$zynq_sysupgrade") requires typed positive payload sizes"
    require_pattern "$zynq_sysupgrade" 'payload size does not match signed manifest' "Zynq sysupgrade $(basename "$zynq_sysupgrade") binds signed payload sizes to regular files"
    require_pattern "$zynq_sysupgrade" 'sha256 must be exactly 64 lowercase hexadecimal characters' "Zynq sysupgrade $(basename "$zynq_sysupgrade") requires canonical signed payload digests"
    require_pattern "$zynq_sysupgrade" 'payload bytes do not match signed sha256' "Zynq sysupgrade $(basename "$zynq_sysupgrade") hashes the actual extracted payload bytes"
    require_pattern "$zynq_sysupgrade" 'contains fpga_bitstream.bit without exactly one signed bitstream declaration' "Zynq sysupgrade $(basename "$zynq_sysupgrade") rejects an undeclared optional FPGA payload"
    require_pattern "$zynq_sysupgrade" 'manifest declares bitstream but fpga_bitstream.bit is absent' "Zynq sysupgrade $(basename "$zynq_sysupgrade") rejects an absent declared FPGA payload"
    require_pattern "$zynq_sysupgrade" 'validate_manifest_payload_binding verification_key release_ed25519.pub' "Zynq sysupgrade $(basename "$zynq_sysupgrade") binds the signed verification key payload"
    require_pattern "$zynq_sysupgrade" 'validate_manifest_payload_binding bitstream fpga_bitstream.bit' "Zynq sysupgrade $(basename "$zynq_sysupgrade") binds the optional FPGA payload when declared"
    require_pattern "$zynq_sysupgrade" 'manifest_boolean_field "$PACKAGE_MANIFEST" installable' "Zynq sysupgrade $(basename "$zynq_sysupgrade") distinguishes JSON boolean installability from strings"
    require_pattern "$zynq_sysupgrade" 'Package manifest must explicitly declare installable=true' "Zynq sysupgrade $(basename "$zynq_sysupgrade") requires signed install authorization"
    require_pattern "$zynq_sysupgrade" 'Package manifest artifact_maturity must match this target' "Zynq sysupgrade $(basename "$zynq_sysupgrade") requires policy-aligned artifact maturity"
    require_pattern "$zynq_sysupgrade" 'Package manifest board and board_target must be present and identical' "Zynq sysupgrade $(basename "$zynq_sysupgrade") binds signed target aliases"
    require_pattern "$zynq_sysupgrade" 'does not match signed target' "Zynq sysupgrade $(basename "$zynq_sysupgrade") binds package directory to signed target"
    require_pattern "$zynq_sysupgrade" 'for unsupported_chain_key in ota_intermediate_cert ota_revoked_intermediates' "Zynq sysupgrade $(basename "$zynq_sysupgrade") restricts authority-v1 to direct release-root signatures"
    require_pattern "$zynq_sysupgrade" 'certificate validity has no trusted-time authority on Zynq' "Zynq sysupgrade $(basename "$zynq_sysupgrade") does not trust an unauthenticated recovery clock"
    require_pattern "$zynq_sysupgrade" 'enforce_sysupgrade_version_floor || exit 1' "Zynq sysupgrade $(basename "$zynq_sysupgrade") enforces downgrade floor before payload writes"
    require_pattern "$zynq_sysupgrade" 'DCENT_SYSUPGRADE_VERSION_PATH' "Zynq sysupgrade $(basename "$zynq_sysupgrade") exposes offline version-file seam"
    require_pattern "$zynq_sysupgrade" 'DCENT_ALLOW_DOWNGRADE' "Zynq sysupgrade $(basename "$zynq_sysupgrade") requires explicit downgrade override"
    require_pattern "$zynq_sysupgrade" '[ "$ALLOW_DOWNGRADE" = "1" ] && ! is_release_status "$PACKAGE_STATUS"' "Zynq sysupgrade $(basename "$zynq_sysupgrade") allows downgrade override only for non-release packages"
    require_pattern "$zynq_sysupgrade" 'Downgrade refused: package version' "Zynq sysupgrade $(basename "$zynq_sysupgrade") reports signed-package downgrade refusal"
    require_pattern "$zynq_sysupgrade" 'command -v jsonfilter' "Zynq sysupgrade $(basename "$zynq_sysupgrade") prefers jsonfilter for manifest parsing"
    require_pattern "$zynq_sysupgrade" 'command -v python3' "Zynq sysupgrade $(basename "$zynq_sysupgrade") checks python3 before manifest parsing"
    require_pattern "$zynq_sysupgrade" 'Error: manifest_field needs jsonfilter or python3' "Zynq sysupgrade $(basename "$zynq_sysupgrade") fails clearly when manifest parser is unavailable"
    require_pattern "$zynq_sysupgrade" 'ARCHIVE_ADMISSION_HELPER="/usr/libexec/dcentos/sysupgrade-archive-admission.sh"' "Zynq sysupgrade $(basename "$zynq_sysupgrade") binds the installed archive-admission helper"
    require_pattern "$zynq_sysupgrade" 'MANIFEST_JSON_HELPER="/usr/libexec/dcentos/sysupgrade-manifest-json.py"' "Zynq sysupgrade $(basename "$zynq_sysupgrade") binds semantic manifest/version admission"
    require_pattern "$zynq_sysupgrade" '. "$ARCHIVE_ADMISSION_HELPER"' "Zynq sysupgrade $(basename "$zynq_sysupgrade") sources canonical archive admission"
    require_pattern "$zynq_sysupgrade" 'python3 "$MANIFEST_JSON_HELPER" validate "$PACKAGE_MANIFEST"' "Zynq sysupgrade $(basename "$zynq_sysupgrade") semantically admits JSON before authority reads"
    require_pattern "$zynq_sysupgrade" 'python3 "$MANIFEST_JSON_HELPER" compare-version "$1" "$2"' "Zynq sysupgrade $(basename "$zynq_sysupgrade") compares versions without awk numeric coercion"
    require_pattern "$zynq_sysupgrade" 'python3 "$MANIFEST_JSON_HELPER" read-version-file "$VERSION_PATH"' "Zynq sysupgrade $(basename "$zynq_sysupgrade") requires one canonical current-version line"
    require_pattern "$zynq_sysupgrade" '"${DCENT_SYSUPGRADE_WORKSPACE:-${TMPDIR:-/tmp}}"' "Zynq sysupgrade $(basename "$zynq_sysupgrade") admits the exact board archive with transaction-private scratch when available and a standalone target fallback"
    require_ordered_patterns "$zynq_sysupgrade" \
        'validate_sysupgrade_tar_preextract "$ROOTFS"' \
        'validate_sysupgrade_tar_members "$ROOTFS"' \
        "Zynq sysupgrade $(basename "$zynq_sysupgrade") bounds then admits the archive before extraction"
done
for zynq_post_build in "$S9_POST_BUILD" "$AM2_POST_BUILD" "$AM2_S19PRO_POST_BUILD" "$AM2_S17PRO_POST_BUILD"; do
    require_pattern "$zynq_post_build" 'scripts/lib/sysupgrade_archive_admission.sh' "Zynq post-build $(basename "$(dirname "$zynq_post_build")") installs the canonical archive-admission source"
    require_pattern "$zynq_post_build" 'sysupgrade-archive-admission.sh' "Zynq post-build $(basename "$(dirname "$zynq_post_build")") stages the target helper path"
    require_pattern "$zynq_post_build" 'sysupgrade-manifest-json.py' "Zynq post-build $(basename "$(dirname "$zynq_post_build")") installs semantic manifest/version admission"
done
require_pattern "$BUILD_DOCKER" 'release/verified builds fail closed on missing or mismatched toolchain' 'docker release builds document mandatory toolchain SHA gate'
require_pattern "$BUILD_DOCKER" 'ERROR (DEVOPS-002): no expected SHA256 pinned' 'docker release build fails closed when no toolchain SHA is pinned'
require_pattern "$BUILD_DOCKER" 'TOOLCHAIN_SHA256_MANDATORY=1' 'docker release build makes toolchain SHA mismatch mandatory'
require_pattern "$CI_BETA_XIL_RELEASE_GATES" 'verify_beta_xil_release_names.sh' 'Xilinx beta release gate verifies release-name/packet consistency before artifact checks'
require_pattern "$BETA_XIL_RELEASE_NAMES" 'firmware_release_name.sh' 'Xilinx beta release-name verifier derives names from the canonical helper'
require_pattern "$FIRMWARE_RELEASE_NAME" 'am2-t17e)              stem="DCENTOS_XIL2_T17e"' 'BM1396 ext2 lane t17e has its canonical publication name (drop1-20260922 latent: missing arm would exit the capsule at the provenance gate)'
require_pattern "$FIRMWARE_RELEASE_NAME" 'am2-s17e)              stem="DCENTOS_XIL2_S17e"' 'BM1396 ext2 lane s17e has its canonical publication name'
require_pattern "$FIRMWARE_RELEASE_NAME" 'am2-s19a)              stem="DCENTOS_XIL3_S19a"' 'BM1398 lane s19a has its canonical publication name (second half of the drop1-20260922 name sweep)'
require_pattern "$FIRMWARE_RELEASE_NAME" 'am2-s19plus)           stem="DCENTOS_XIL3_S19Plus"' 'BM1398 lane s19plus has its canonical publication name'
require_pattern 'br2_external_dcentos/configs/dcentos_am3_bb_s19jpro_defconfig' 'BR2_TOOLCHAIN_EXTERNAL_FORTRAN=y' 'BB producer defconfig declares the Linaro toolchain Fortran capability (drop1-20260922 run-25 lane 20 latent: available-but-unselected is a hard toolchain check error)'
require_pattern 'br2_external_dcentos/configs/dcentos_am3_bb_s19jpro_defconfig' 'BR2_TOOLCHAIN_EXTERNAL_OPENMP=y' 'BB producer defconfig declares the Linaro toolchain OpenMP capability'
require_pattern 'br2_external_dcentos/configs/dcentos_am3_bb_defconfig' 'BR2_TOOLCHAIN_EXTERNAL_FORTRAN=y' 'BB base defconfig declares the Linaro toolchain Fortran capability'
require_pattern 'br2_external_dcentos/configs/dcentos_am3_bb_defconfig' 'BR2_TOOLCHAIN_EXTERNAL_OPENMP=y' 'BB base defconfig declares the Linaro toolchain OpenMP capability'
reject_pattern "$BUILD_DOCKER" 'grep -qx "etc/dcentos/rescue_ssh_enabled"' 'BB payload validation follows release posture: the rescue marker is stripped from release images and must not be demanded'
if [ "$TIER" = blocking ]; then
    printf 'NIGHTLY: committed Xilinx publication packet/checksum metadata\n'
elif sh "$BETA_XIL_RELEASE_NAMES" >/dev/null; then
    pass "Xilinx beta release-name verifier passes on committed packet/checksum metadata"
else
    fail "Xilinx beta release-name verifier failed"
fi

# --- BUG 1 (build): Zynq sysupgrade kernel must be a bootable FIT/uImage ------
# The S9/Zynq NAND boot path uses U-Boot `bootm`, which boots ONLY a FIT
# (d00dfeed) or a legacy uImage (27051956). The BraiinsOS-extracted kernel.bin
# is a BARE ARM zImage (magic 0x016f2818 at offset 0x24) — copying it straight
# into sysupgrade-<board>/kernel bricked .135. These guards pin (a) the
# packager wraps the bare zImage into a NAND FIT, and (b) the pre-flash
# validator REJECTS a bare-zImage kernel for the zynq boards.
require_pattern "$PACKAGE" 'build_nand_kernel_fit' 'packager defines the bare-zImage -> NAND FIT wrapper'
require_pattern "$PACKAGE" 'kernel_is_bootm_ready' 'packager classifies the kernel container (FIT/uImage vs bare zImage)'
require_pattern "$PACKAGE" 'is a bare zImage' 'packager logs when it wraps a bare zImage into a FIT'
require_pattern "$PACKAGE" 'no ramdisk' 'packager NAND FIT mirrors the SD .its minus the ramdisk node'
require_pattern "$PACKAGE" 'Staged sysupgrade kernel is not bootm-ready' 'packager fails closed if the staged kernel is not bootm-ready'
require_pattern "$PACKAGE" 'load = <0x00008000>' 'packager NAND FIT loads the kernel at 0x8000'
require_pattern "$PRE_FLASH" 'is NOT a bootm-ready FIT/uImage' 'pre-flash validator rejects a bare-zImage zynq kernel'
require_pattern "$PRE_FLASH" 'kernel payload is a bootable FIT' 'pre-flash validator accepts a FIT zynq kernel'
# --- end BUG 1 Zynq FIT-kernel coverage --------------------------------------

# --- BUG 3: DCENT_OS DHCP client must keep a stable MAC-based identity --------
# On the BraiinsOS->DCENT_OS swap, DCENT_OS pulled a NEW lease (.135 -> .100)
# because its udhcpc sent a different client-identifier than BraiinsOS. The fix
# makes S40network send RFC 2132 option 61 (client-identifier) = "01"+MAC, the
# same form stock/Braiins firmware use, so the lease (and IP) survive the swap.
S40NETWORK='br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/S40network'
require_pattern "$S40NETWORK" '/sys/class/net/$INTERFACE/address' 'S40network reads the interface MAC for the DHCP client-id'
require_pattern "$S40NETWORK" '0x3d:$CLIENTID_HEX' 'S40network sends udhcpc raw option 61 (client-identifier)'
require_pattern "$S40NETWORK" 'CLIENTID_HEX="01' 'S40network builds the option-61 client-id as Ethernet-type "01" + MAC'
# --- end BUG 3 DHCP stable-identity coverage ---------------------------------
require_pattern 'br2_external_dcentos/board/zynq/post-image-ramdisk.sh' 'MAX_UBI_SIZE=$((134 * 124 * 1024))' 'S9 post-image warning threshold uses live 2026-06-05 rootfs volume capacity'
require_pattern 'br2_external_dcentos/board/zynq/post-image-ramdisk.sh' 'exceeds live S9 UBI rootfs volume' 'S9 post-image warning names live UBI rootfs fit blocker'
reject_pattern 'br2_external_dcentos/board/zynq/post-image-ramdisk.sh' '166 * 124 * 1024' 'S9 post-image no longer uses stale 166-LEB capacity'
reject_pattern 'br2_external_dcentos/board/zynq/post-image-ramdisk.sh' 'within observed S9 volume' 'S9 post-image no longer reports stale observed-volume OK wording'
require_pattern "$VERSION_GATE" 'dcent_require_dcentrald_version_match' 'shared dcentrald version gate helper exists'
require_pattern "$VERSION_GATE" 'binary string $actual_string != expected $expected_string' 'dcentrald version gate compares binary user-agent version to staged metadata'
require_pattern "$VERSION_GATE" 'staged version $staged_version from $staged_source != Cargo workspace version $cargo_version' 'dcentrald version gate compares staged metadata to Cargo workspace version'
require_pattern "$VERSION_GATE" 'DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1' 'dcentrald version gate uses existing explicit lab override pattern'
require_pattern "$PACKAGE" 'dcent_require_dcentrald_version_match' 'standalone packager gates staged dcentrald version when target dir is present'
require_pattern 'scripts/build_in_docker.sh' 'phase5_stage_binaries.sh' 'docker build wires the file-delivered Phase 5 staging script'
require_pattern 'scripts/phase5_stage_binaries.sh' 'build_in_docker Phase 5' 'docker build validates staged ARM dcentrald before Buildroot'
require_pattern "$BUILD_DOCKER" '--lab-unsigned' 'docker build requires explicit lab unsigned flag'
require_pattern "$BUILD_DOCKER" 'release sysupgrade builds require DCENT_RELEASE_SIGNING_KEY' 'docker build fails closed for unsigned release sysupgrade builds'
reject_pattern "$BUILD_DOCKER" 'DCENT_ALLOW_UNSIGNED_SYSUPGRADE="${DCENT_ALLOW_UNSIGNED_SYSUPGRADE:-1}"' 'docker build does not default to unsigned lab override'
reject_pattern "$BUILD_DOCKER" '-e DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1' 'docker build does not hardcode unsigned lab override into container'
require_pattern "$BUILD_WSL" 'release sysupgrade packaging requires DCENT_RELEASE_SIGNING_KEY' 'WSL build fails closed for unsigned release sysupgrade builds'
reject_pattern "$BUILD_WSL" 'export DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1' 'WSL build does not auto-enable unsigned lab override'
require_pattern "$BUILD_AMLOGIC_NATIVE" '--lab-unsigned' 'amlogic native extractor accepts explicit lab unsigned validation'
require_pattern "$BUILD_AMLOGIC_NATIVE" 'expected existing tarball missing' 'amlogic native extractor requires an existing package'
require_pattern "$BUILD_AMLOGIC_NATIVE" 'does not invoke the disabled non-S9 packaging lane' 'amlogic native extractor does not claim build authority'
reject_pattern "$BUILD_AMLOGIC_NATIVE" 'DCENT_ALLOW_UNSIGNED_SYSUPGRADE="${DCENT_ALLOW_UNSIGNED_SYSUPGRADE:-1}"' 'amlogic native extractor does not default to unsigned lab override'
require_pattern 'br2_external_dcentos/board/zynq/post-build.sh' 'dcent_require_dcentrald_version_match' 'S9 post-build gates staged dcentrald version'
require_pattern 'br2_external_dcentos/board/zynq/am2-s19jpro/post-build.sh' 'dcent_require_dcentrald_version_match' 'am2 post-build gates staged dcentrald version'
require_pattern 'br2_external_dcentos/board/zynq/am2-s19jpro/post-build.sh' 'revert_to_stock_s19_am2.sh' 'am2 post-build ships profile revert helper'
require_pattern 'br2_external_dcentos/board/zynq/am2-s19jpro/post-build.sh' 'stock-bitmain-manifest.json' 'am2 post-build ships stock Bitmain manifest'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-build.sh' 'dcent_require_dcentrald_version_match' 'am3-s19k post-build gates staged dcentrald version'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s19kpro/post-build.sh' 'usr/sbin/lib/am3_geometry.sh' 'am3-s19k post-build ships AM3 geometry helper for revert'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s21/post-build.sh' 'dcent_require_dcentrald_version_match' 'am3-s21 post-build gates staged dcentrald version'
require_pattern 'br2_external_dcentos/board/amlogic/am3-s21/post-build.sh' 'usr/sbin/lib/am3_geometry.sh' 'am3-s21 post-build ships AM3 geometry helper for revert'
require_pattern 'br2_external_dcentos/board/beaglebone/am3-bb/post-build.sh' 'dcent_require_dcentrald_version_match' 'am3-bb post-build gates staged dcentrald version'
require_pattern "$AM2_POST_IMAGE" '"version": "${PACKAGE_VERSION}"' 'am2 post-image writes a non-null manifest version'
require_pattern "$AM3_S19K_POST_IMAGE" 'PACKAGE_VERSION=$(infer_package_version || true)' 'am3-s19k post-image resolves a non-null manifest version before the shared writer'
require_pattern "$AM3_S21_POST_IMAGE" '"version": "${PACKAGE_VERSION}"' 'am3-s21 post-image writes a non-null manifest version'
require_pattern "$AM2_POST_IMAGE" 'dcent_write_sysupgrade_manifest' 'am2 post-image uses shared AM2/AM3 manifest writer'
require_pattern "$AM3_S19K_POST_IMAGE" 'dcent_write_sysupgrade_manifest' 'am3-s19k post-image uses shared AM2/AM3 manifest writer'
require_pattern "$AM3_S21_POST_IMAGE" 'dcent_write_sysupgrade_manifest' 'am3-s21 post-image uses shared AM2/AM3 manifest writer'
require_pattern "$SYSUPGRADE_COMMON" 'dcent_stage_release_key' 'shared manifest helper stages release key'
require_pattern "$SYSUPGRADE_COMMON" 'dcent_sign_sysupgrade_manifest' 'shared manifest helper signs and verifies manifest'
require_pattern "$SYSUPGRADE_COMMON" 'production release package requires trusted release keys/signatures' 'shared signing helper fails closed for production release mode'
require_pattern "$SYSUPGRADE_COMMON" 'package must never derive its trust root from the signing key' 'shared signing helper forbids self-derived generated-key trust'
require_pattern "$PACKAGE" 'Release-root signing requires --verify-pubkey or DCENT_RELEASE_PUBKEY_FILE' 'standalone packager requires trusted public key for release-root signing'
require_pattern "$PACKAGE" 'unsigned package generation' 'standalone packager gates unsigned package generation'
require_pattern "$AM3_S19K_POST_IMAGE" 'DCENT_TARGET_SIDE_SYSUPGRADE=false' 'am3-s19k metadata disables target-side sysupgrade'
require_pattern "$AM3_S21_POST_IMAGE" 'DCENT_TARGET_SIDE_SYSUPGRADE=false' 'am3-s21 metadata disables target-side sysupgrade'
require_pattern "$AM3_S19K_POST_IMAGE" 'DCENT_TOOLBOX_INSTALL_MODE=host_driven_rootfs_window_lab' 'am3-s19k metadata admits only the host-driven guarded rootfs window'
require_pattern "$AM3_S19K_POST_IMAGE" 'DCENT_PACKAGE_INSTALLABLE=true' 'am3-s19k package is structurally installable after its release prerequisites pass'
require_pattern "$AM3_S19K_POST_IMAGE" 'DCENT_TOOLBOX_INSTALL_COMMAND="dcent install <ip>' 'am3-s19k metadata emits the guarded host install command'
require_pattern "$AM3_S19K_POST_IMAGE" 'DCENT_TOOLBOX_UPDATE_COMMAND="$DCENT_TOOLBOX_INSTALL_COMMAND"' 'am3-s19k update remains the same guarded host transaction'
require_pattern 'scripts/s19k_hermetic_image_producer.py' 'DCENT_S19K_EXPECTED_RELEASE_KEY_SHA256' 'am3-s19k build requires an externally pinned release key'
require_pattern 'scripts/s19k_hermetic_image_producer.py' 's19k_persistent_image_verify.py' 'am3-s19k build runs the dependency-bound image contract verifier'
require_pattern 'scripts/s19k_persistent_image_verify.py' 'CLEAR_FOR_FLASH=false' 'am3-s19k packaged writer remains disabled'
reject_pattern "$AM3_S19K_POST_IMAGE" 'dcent ota update-fleet <ip>' 'am3-s19k build artifacts do not advertise fleet OTA'
require_pattern "$AM3_S21_POST_IMAGE" 'host_driven_rootfs_window_lab' 'am3-s21 metadata marks host-driven lab install'
# 2026-08-15: every manifest-bearing Amlogic package advertises the fleet OTA
# update command for the same guarded rootfs-window rail (the packaging-side
# update contract selftest above enforces the safety shape of this string).
require_pattern "$AM3_S21_POST_IMAGE" 'DCENT_TOOLBOX_UPDATE_COMMAND="dcent ota update-fleet <ip> -f ${OUTPUT_BASENAME} --artifact-dir <restore_verified_dir>"' 'am3-s21 metadata advertises the fleet OTA update command'
require_pattern "$AM3_S21PRO_POST_IMAGE" 'DCENT_TOOLBOX_UPDATE_COMMAND="dcent ota update-fleet <ip> -f ${OUTPUT_BASENAME} --artifact-dir <restore_verified_dir>"' 'am3-s21pro metadata advertises the fleet OTA update command'
require_pattern "$AM3_S21_POST_IMAGE" 'am3-s19xp)' 'shared A113D packager has an exact S19 XP package-only branch'
require_pattern "$AM3_S21_POST_IMAGE" 'am3-s19jxp)' 'shared A113D packager has an exact S19j XP package-only branch'
require_pattern "$AM3_S21_POST_IMAGE" 'PACKAGE_STORAGE_AUTHORIZED=0' 'X19 AML package branches deny storage geometry'
require_pattern "$AM3_S21_POST_IMAGE" 'DCENT_TOOLBOX_INSTALL_MODE=package_only_denied' 'shared A113D metadata can deny X19 AML installation'
require_pattern "$AM3_S21_POST_IMAGE" 'DCENT_PACKAGE_INSTALLABLE=false' 'shared A113D package-only branches are explicitly non-installable'
require_exact_line "$AM3_S19XP_MUTATION_POLICY" 'hardware-enabled' 'am3-s19xp runtime policy enables its admitted native owner; package storage/install guards remain separate'
require_exact_line "$AM3_S19JXP_MUTATION_POLICY" 'hardware-enabled' 'am3-s19jxp runtime policy enables its admitted native owner; package storage/install guards remain separate'
require_pattern "$AM3_S21XP_POST_IMAGE" 'DCENT_TOOLBOX_INSTALL_MODE=package_only_denied' 'am3-s21xp metadata denies installation while its platform/storage contracts remain unproven'
require_pattern "$AM3_S21XP_POST_IMAGE" 'DCENT_PACKAGE_INSTALLABLE=false' 'am3-s21xp package-validation artifact is explicitly non-installable'
require_pattern "$AM3_S21XP_POST_IMAGE" 'DCENT_TOOLBOX_UPDATE_COMMAND=""' 'am3-s21xp metadata emits no fleet OTA command'
require_exact_line "$AM3_S21XP_MUTATION_POLICY" 'hardware-enabled' 'am3-s21xp runtime policy enables its admitted native owner; package storage/install guards remain separate'
require_pattern "$AM3_T21_POST_IMAGE" 'DCENT_TOOLBOX_INSTALL_MODE=package_only_denied' 'am3-t21 metadata denies installation while storage geometry remains unproven'
require_pattern "$AM3_T21_POST_IMAGE" 'DCENT_PACKAGE_INSTALLABLE=false' 'am3-t21 package-validation artifact is explicitly non-installable'
require_pattern "$AM3_T21_POST_IMAGE" 'DCENT_TOOLBOX_UPDATE_COMMAND=""' 'am3-t21 metadata emits no fleet OTA command'
require_exact_line "$AM3_T21_MUTATION_POLICY" 'management-only' 'am3-t21 rootfs carries an immutable management-only mutation policy'
require_ordered_patterns "$AMLOGIC_S37BOARD_SETUP" 'require_mutation_authority || return 1' 'force_psu_safe_low' 'am3 shared board init checks target policy before the first PSU GPIO write'
require_ordered_patterns "$AMLOGIC_S46POST_INSTALL" 'require_post_install_authority || return 1' '. /lib/functions/dcentos-defaults.sh' 'am3 post-install hook checks target policy before loading generic NAND geometry'
require_ordered_patterns "$AMLOGIC_S46POST_INSTALL" 'require_post_install_authority || return 1' 'nanddump -q' 'am3 post-install hook checks target policy before reading or erasing NAND'
require_pattern "$AMLOGIC_S82DCENTRALD" 'require_runtime_authority || exit 1' 'am3 daemon lifecycle refuses management-only targets before launch or safety actions'
reject_pattern "$AMLOGIC_S99UPGRADE" 'am3-s19jpro-aml|am3-s21|am3-s21pro|am3-s21xp' 'am3-s21xp is excluded from the raw-NAND OTA-08 identity gate'
reject_pattern "$AMLOGIC_S99UPGRADE" 'am3-s19jpro-aml|am3-s21|am3-s21pro|am3-t21' 'am3-t21 is excluded from the raw-NAND OTA-08 identity gate'
require_ordered_patterns "$AMLOGIC_S99UPGRADE" 'require_ota_mutation_policy || exit 1' 'replay_pending_env_clear' 'am3 OTA policy gate precedes WAL replay and fw_setenv mutation'
reject_pattern "$AM3_T21_POST_BUILD" 'cp "$REVERT_T21_SRC"' 'am3-t21 rootfs does not stage an unproven revert helper'
require_pattern "$AM3_T21_POST_IMAGE" 'if [ "$PACKAGE_STORAGE_AUTHORIZED" = "1" ]; then' 'shared recipe imports flash geometry only inside the authorized storage branch'
reject_pattern 'br2_external_dcentos/board/amlogic/am3-s21xp/post-build.sh' 'cp "$REVERT_S21_SRC"' 'am3-s21xp rootfs does not stage an inherited base-S21 revert helper'
require_pattern "$AM3_S21XP_POST_IMAGE" 'am3-s21xp|am3-t21)' 'shared recipe binds S21XP and T21 to the denied storage branch'
require_pattern "$AM3_S19K_POST_IMAGE" 'structurally installable for the host extractor, but it grants no writer' 'am3-s19k unsigned A/B package distinguishes structural installability from mutation authority'
# L12 posture (2026-09-15): Classic (am3-s19jpro-aml) has no compatible
# persistent writer (mtd5=config, mtd6=nvdata; six-MTD writer incompatible),
# so its metadata must advertise NO fleet OTA update command — pin the refusal.
require_pattern "$AM3_S19JPRO_AML_POST_IMAGE" 'DCENT_TOOLBOX_UPDATE_COMMAND=""' 'am3-s19jpro-aml metadata advertises no fleet OTA command (six-MTD writer incompatible)'
require_pattern "$AM3_GEOMETRY" 'DCENT_AM3_ROOTFS_OFFSET_HEX="${DCENT_AM3_ROOTFS_OFFSET_HEX:-0x05100000}"' 'am3 geometry centralizes rootfs offset'
require_pattern "$AM3_GEOMETRY" 'DCENT_AM3_ROOTFS_WINDOW_HEX="${DCENT_AM3_ROOTFS_WINDOW_HEX:-0x02800000}"' 'am3 geometry centralizes rootfs window'
require_pattern "$AM3_S21_REVERT" 'ROOTFS_OFFSET="$DCENT_AM3_ROOTFS_OFFSET_HEX"' 'am3-s21 revert uses shared rootfs offset'
require_pattern "$RESTORE_ROUTE" '.arg(&post_dwell_fp.sha256)' 'restore route passes post-dwell SHA into revert helper'
require_pattern "$S9_REVERT" 'exec python3 -m dcent_toolbox.cli.stock_revert "$@" --require-board-target am1-s9' 'S9 owner-host restore delegates to the exact saved-source transaction'
reject_executable_pattern "$S9_REVERT" 'EXPECTED_SHA256=' 'contained S9 helper does not inspect an image'
for revert_script in "$S17_REVERT" "$AM3_S21_REVERT"; do
    require_pattern "$revert_script" 'EXPECTED_SHA256=' "stock revert helper $(basename "$revert_script") accepts expected SHA"
    require_pattern "$revert_script" 'Firmware SHA-256 verified at extraction time.' "stock revert helper $(basename "$revert_script") verifies SHA before extract"
    require_pattern "$revert_script" 'MAX_EXTRACTED_KB' "stock revert helper $(basename "$revert_script") caps extracted size"
    require_pattern "$revert_script" 'firmware archive contains hard-linked files' "stock revert helper $(basename "$revert_script") rejects hard-linked files"
done
require_pattern "$AM3_S19K_REVERT" 'EXPECTED_SHA256=' 'S19k evidence classifier accepts an exact expected archive SHA'
require_pattern "$AM3_S19K_REVERT" 'Firmware SHA-256 verified on private immutable-for-this-process snapshot.' 'S19k evidence classifier snapshots and authenticates the archive before inspection'
require_pattern "$AM3_S19K_REVERT" '(ulimit -f 2048 && tar -tzf "$PRIVATE_FW" > "$TOC")' 'S19k evidence classifier bounds the archive TOC'
require_pattern "$AM3_S19K_REVERT" 'firmware archive must contain exactly one uImage-like candidate' 'S19k evidence classifier rejects ambiguous payload candidates'
require_pattern "$AM3_S19K_REVERT" '(ulimit -f 81920 && tar -xOzf "$PRIVATE_FW" -- "$UIMAGE_MEMBER" > "$UIMAGE_REAL")' 'S19k evidence classifier streams one option-delimited candidate into a bounded private file'
require_pattern "$AM3_S19K_REVERT" 'avoids materializing' 'S19k evidence classifier never materializes archive paths, links, devices, or sibling files'
require_pattern "$AM3_S19K_REVERT" 'private firmware snapshot changed during classification' 'S19k evidence classifier rehashes its private archive after streaming'
require_pattern "$AM3_S19K_REVERT" 'classifier limits: CRC and stock payload identity are unverified; NAND mutation remains refused' 'S19k evidence classifier states its missing proof and mutation refusal'

# NAND-safety for the AMLOGIC reverts. Amlogic (A113D) writes the stock rootfs
# into a uImage window with `nandwrite -p` PAGE writes and must NEVER call
# `flash_erase` (partition-erase = the weak-ECC brick / corruption class of the
# .74/.139 incident; the s21 script documents this in prose). This is
# Amlogic-only: the Zynq reverts legitimately `flash_erase` the INACTIVE firmware
# SLOT (never the env — that flips via fw_setenv, already checked below). The
# guard is comment-aware so the scripts that DOCUMENT the ban don't self-trip.
AM3_S19JPRO_REVERT='scripts/revert_to_stock_am3_aml_s19jpro.sh'
AM3_T21_REVERT='scripts/revert_to_stock_am3_aml_t21.sh'
for aml_revert in "$AM3_S19K_REVERT" "$AM3_S21_REVERT" "$AM3_S19JPRO_REVERT"; do
    reject_executable_pattern "$aml_revert" 'flash_erase' "amlogic revert helper $(basename "$aml_revert") never flash_erases a partition (nandwrite page-writes only; brick op)"
done
require_pattern "$AM3_T21_REVERT" 'T21 stock revert is unavailable' 'T21 compatibility revert entrypoint always refuses while storage geometry is unproven'
reject_executable_pattern "$AM3_T21_REVERT" 'nandwrite|nanddump|flash_erase|fw_setenv|revert_ssh_preflight|ssh|scp' 'T21 compatibility revert entrypoint contains no transport or storage writer'
require_pattern "$S17_REVERT" 'command -v fw_printenv' 'S17 stock revert requires fw_printenv before destructive work'
require_pattern "$S17_REVERT" 'command -v fw_setenv' 'S17 stock revert requires fw_setenv before destructive work'
require_pattern "$S17_REVERT" "Refusing to infer active slot" 'S17 stock revert fails closed on unknown bootslot'
reject_executable_pattern "$S17_REVERT" 'fw_printenv -n bootslot 2>/dev/null || echo "a"' 'S17 stock revert no longer defaults unknown bootslot to slot a'
require_pattern "$S17_REVERT" 'fw_setenv --script "$FW_SETENV_SCRIPT"' 'S17 stock revert applies boot env flip through fw_setenv script'
require_pattern "$S17_REVERT" 'POST_FLIP_SLOT=$(fw_printenv -n bootslot' 'S17 stock revert verifies post-flip bootslot through fw_printenv'
require_pattern "$S17_REVERT" 'Post-flip boot slot verified via fw_printenv' 'S17 stock revert reports success only after env readback'
require_pattern "$AM3_BB_REVERT" 'AM335x BB NAND revert is disabled' 'am3-bb NAND revert disabled pending evidence'
require_pattern "$AM3_BB_REVERT" 'DCENT_AM3_BB_PROC_MTD_EVIDENCE' 'am3-bb NAND revert requires proc-mtd evidence before override'
require_pattern "$AM3_BB_REVERT" 'DCENT_AM3_BB_ENABLE_NAND_REVERT is not accepted as a bypass' 'am3-bb NAND revert has no env-only bypass'
require_pattern 'br2_external_dcentos/board/beaglebone/am3-bb/post-build.sh' 'echo "am3-bb" > "${TARGET_DIR}/etc/dcentos/board_family"' 'am3-bb post-build stamps unambiguous board_family'

# --- Phase 2D / 2E Buildroot variant identity coverage (QA-F002) -------------
# Phases 2D (am2-s19pro-zynq) and 2E (am2-s17pro-zynq) shipped ~4000 LOC of
# Buildroot variant with ZERO static/CI coverage. Regression-pin the per-variant
# board-identity overlay files so the Phase 4A S99verify V1-V14 multi-family
# port (which consumes these etc/dcentos/* files) and the per-variant
# sysupgrade writer cannot silently drift. Canonical strings VERIFIED from the
# on-disk overlay files, not guessed.
AM2_S19PRO_OVL='br2_external_dcentos/board/zynq/am2-s19pro/rootfs-overlay/etc/dcentos'
AM2_S17PRO_OVL='br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay/etc/dcentos'

require_identity_file "$AM2_S19PRO_OVL/platform" 'zynq-bm3-am2' 'am2-s19pro overlay stamps platform=zynq-bm3-am2'
require_identity_file "$AM2_S19PRO_OVL/board_family" 'am2' 'am2-s19pro overlay stamps board_family=am2'
require_identity_file "$AM2_S19PRO_OVL/board_target" 'am2-s19pro' 'am2-s19pro overlay stamps board_target=am2-s19pro'

require_identity_file "$AM2_S17PRO_OVL/platform" 'zynq-bm3-am2' 'am2-s17pro overlay stamps platform=zynq-bm3-am2'
require_identity_file "$AM2_S17PRO_OVL/board_family" 'am2' 'am2-s17pro overlay stamps board_family=am2'
require_identity_file "$AM2_S17PRO_OVL/board_target" 'am2-s17p' 'am2-s17pro overlay stamps board_target=am2-s17p'
# --- end Phase 2D / 2E variant identity coverage -----------------------------

# --- AM3-BB cold-boot management-only gate (matrix §7 #4) --------------------
# Productionization sweep (2026-05-21) QA CRITICAL-3 + Thermal CRITICAL +
# DevOps WARNING-3: the AM3-BB install image baked `[mining] enabled = true` +
# a real Public Pool and S82dcentrald unconditionally passed --am3-bb-mining on
# the beaglebone platform, so a cold-boot install image auto-energized the PSU
# and drove the ASIC chains while SD-first/thermal/restore proof remained
# blocked. The fix gates the cold-boot mining start behind a proof marker
# (mirrors the /etc/dcentos/release-image trust-boundary pattern): absent the
# marker the daemon comes up management-only (no --am3-bb-mining + a
# management-only config whose empty pool + `[mining].enabled=false` makes
# dcentrald's `mining_start_enabled()` gate keep the hardware off). These
# guards pin that the install image does NOT auto-mine without the proof
# marker, and that the management-only fail-closed config ships.
BB_S82='br2_external_dcentos/board/beaglebone/am3-bb-s19jpro/rootfs-overlay/etc/init.d/S82dcentrald'
BB_MGMT_CFG='br2_external_dcentos/board/beaglebone/am3-bb-s19jpro/rootfs-overlay/etc/dcentrald.management-only.toml'
BB_S19JPRO_POSTBUILD='br2_external_dcentos/board/beaglebone/am3-bb-s19jpro/post-build.sh'

require_pattern "$BB_S82" 'AM3_BB_COLDBOOT_PROOF_MARKER="/data/dcentos/am3-bb-coldboot-proven"' 'am3-bb-s19jpro S82dcentrald defines the cold-boot proof marker'
require_pattern "$BB_S82" '[ -e "$AM3_BB_COLDBOOT_PROOF_MARKER" ] && AM3_BB_MINING_REQUESTED=1' 'am3-bb-s19jpro S82dcentrald snapshots the proof marker before safety admission'
require_pattern "$BB_S82" 'if [ "$AM3_BB_MINING_REQUESTED" -eq 1 ]; then' 'am3-bb-s19jpro S82dcentrald gates mining start on the immutable posture snapshot'
require_pattern "$BB_S82" 'MANAGEMENT-ONLY until cold-boot proof' 'am3-bb-s19jpro S82dcentrald logs management-only posture when unproven'
require_pattern "$BB_S82" 'AM3_BB_MGMT_ONLY_CONFIG="/etc/dcentrald.management-only.toml"' 'am3-bb-s19jpro S82dcentrald points at the management-only config'
# The ONLY --am3-bb-mining invocation must be inside the snapshotted
# marker-present branch; a marker appearing during safe-off cannot upgrade the
# current invocation from management-only into mining.
# There must be exactly one --am3-bb-mining ARGS assignment and it must follow
# the marker test. Assert the marker test precedes the --am3-bb-mining ARGS.
if awk '
    /if \[ "\$AM3_BB_MINING_REQUESTED" -eq 1 \]; then/ { seen_marker = 1 }
    /ARGS="--am3-bb-mining \$ARGS"/ { if (!seen_marker) { bad = 1 } }
    END { exit (bad ? 1 : 0) }
' "$BB_S82"; then
    pass 'am3-bb-s19jpro S82dcentrald: --am3-bb-mining ARGS only set inside the proof-marker branch'
else
    fail 'am3-bb-s19jpro S82dcentrald: --am3-bb-mining ARGS set OUTSIDE the proof-marker branch (would auto-mine on cold boot)'
fi
require_pattern "$BB_MGMT_CFG" 'enabled = false' 'am3-bb-s19jpro management-only config disables mining'
require_identity_file "$BB_MGMT_CFG" '# DCENT_OS Mining Daemon Configuration - Antminer S19j Pro AM335x BB' 'am3-bb-s19jpro management-only config ships with the expected header'
# The management-only config must have an EMPTY pool url (defense in depth: a
# blank pool alone makes mining_start_enabled() false even if `enabled` drifts).
require_pattern "$BB_MGMT_CFG" 'url = ""' 'am3-bb-s19jpro management-only config has an empty pool url'
require_pattern "$BB_S19JPRO_POSTBUILD" '/etc/dcentrald.management-only.toml missing from rootfs' 'am3-bb-s19jpro post-build verifies the management-only config ships'
# --- end AM3-BB cold-boot management-only gate -------------------------------

reject_pattern "$AM3_BB_REVERT" 'flash_erase' 'am3-bb NAND revert script contains no erase path'
reject_pattern "$AM3_BB_REVERT" 'nandwrite' 'am3-bb NAND revert script contains no write path'
reject_pattern "$AM3_BB_REVERT" 'fw_setenv' 'am3-bb NAND revert script contains no env write path'
require_pattern "$S9_SYSUPGRADE" 'PACKAGE_STATUS=$(manifest_string_field "$PACKAGE_MANIFEST" status' 'S9 target sysupgrade reads typed manifest package status'
require_pattern "$S9_SYSUPGRADE" 'Package authority-v1 is missing MANIFEST.sig' 'S9 target sysupgrade rejects unsigned authority packages even with lab override'
require_pattern "$S9_SYSUPGRADE" 'DCENT_PACKAGE_STATUS to be a non-release lab value' 'S9 target raw lab sysupgrade requires non-release status'
require_pattern "$AM2_SYSUPGRADE" 'PACKAGE_STATUS=$(manifest_string_field "$PACKAGE_MANIFEST" status' 'am2 target sysupgrade reads typed manifest package status'
require_pattern "$AM2_SYSUPGRADE" 'Package authority-v1 is missing MANIFEST.sig' 'am2 target sysupgrade rejects unsigned authority packages even with lab override'
require_pattern "$AM2_SYSUPGRADE" 'DCENT_PACKAGE_STATUS to be a non-release lab value' 'am2 target raw lab sysupgrade requires non-release status'
require_pattern "$AM2_SYSUPGRADE" 'DCENT_ALLOW_AM2_S19J_AMBIGUOUS_BOS_PLATFORM' 'am2-s19j sysupgrade requires guided override for ambiguous generic AM2 platform'
require_pattern "$AM2_SYSUPGRADE" 'ambiguous AM2 platform marker' 'am2-s19j sysupgrade explains zynq-bm3-am2 ambiguity'
require_pattern "$AM2_SYSUPGRADE" 'Wrong AM2 image = brick' 'am2-s19j sysupgrade treats ambiguous first-flash as a brick guard'
reject_executable_pattern "$AM2_SYSUPGRADE" 'zynq-bm3-am2) DETECTED_BOARD="am2-s19j"' 'am2-s19j sysupgrade never unconditionally maps generic AM2 platform to S19j'

# --- AM2 U-Boot env-flip must use fw_setenv, NEVER raw mtd4 writes ----------
# Production-readiness matrix §7 #6/#8 + load-bearing rule
# : the AM2 control board's
# pl35x-nand env partition (mtd4) is weak-ECC and was bricked TWICE by the
# raw dd/flash_erase/nandwrite env-flip. The .139-proven am2-s19jpro variant
# is the canonical fw_setenv model; the am2-s19pro + am2-s17pro siblings must
# match it. These guards prevent the raw-env-write path from ever returning
# to ANY am2 sysupgrade variant (the rootfs A/B writes use ubiupdatevol, not
# nandwrite, so a literal flash_erase/nandwrite token in these scripts can
# only be a regression to the banned env-flip method).
for am2_sup in "$AM2_SYSUPGRADE" "$AM2_S19PRO_SYSUPGRADE" "$AM2_S17PRO_SYSUPGRADE"; do
    am2_name=$(echo "$am2_sup" | sed 's#.*/zynq/##; s#/rootfs-overlay.*##')
    require_pattern "$am2_sup" 'fw_setenv' "am2 sysupgrade [$am2_name] flips boot-selector via fw_setenv"
    require_pattern "$am2_sup" 'fw_printenv' "am2 sysupgrade [$am2_name] verifies env flip via fw_printenv"
    require_pattern "$am2_sup" 'WRONG_BOARD_EXIT=78' "am2 sysupgrade [$am2_name] uses a distinct wrong-board exit"
    require_pattern "$am2_sup" 'exit "$WRONG_BOARD_EXIT"' "am2 sysupgrade [$am2_name] exits non-zero on wrong board even in test/dry-run"
    reject_pattern "$am2_sup" 'dry-run permissive, continuing' "am2 sysupgrade [$am2_name] never green-lights wrong-board dry-runs"
    # Executable-only: the proven am2-s19jpro variant keeps a recovery-hint
    # comment that NAMES the banned raw path in prose; only an actual
    # invocation is a regression.
    reject_executable_pattern "$am2_sup" 'flash_erase /dev/mtd4' "am2 sysupgrade [$am2_name] never erases the mtd4 env partition"
    reject_executable_pattern "$am2_sup" 'nandwrite -p /dev/mtd4' "am2 sysupgrade [$am2_name] never nandwrites the mtd4 env partition"
    reject_executable_pattern "$am2_sup" 'switch_firmware.py' "am2 sysupgrade [$am2_name] does not invoke the raw-env switch_firmware.py helper"
done

require_pattern "$AM2_S19PRO_SYSUPGRADE" 'PACKAGE_STATUS=$(manifest_string_field "$PACKAGE_MANIFEST" status' 'am2-s19pro sysupgrade reads typed manifest package status'
require_pattern "$AM2_S17PRO_SYSUPGRADE" 'PACKAGE_STATUS=$(manifest_string_field "$PACKAGE_MANIFEST" status' 'am2-s17pro sysupgrade reads typed manifest package status'
require_pattern "$AM2_S19PRO_SYSUPGRADE" 'DCENT_ALLOW_AM2_S19PRO_AMBIGUOUS_BOS_PLATFORM' 'am2-s19pro sysupgrade requires explicit lab override for ambiguous generic AM2 platform'
require_pattern "$AM2_S19PRO_SYSUPGRADE" 'ambiguous AM2 platform marker' 'am2-s19pro sysupgrade explains zynq-bm3-am2 ambiguity'
require_pattern "$AM2_S19PRO_SYSUPGRADE" 'Wrong AM2 image = brick' 'am2-s19pro sysupgrade treats ambiguous first-flash as a brick guard'
reject_executable_pattern "$AM2_S19PRO_SYSUPGRADE" 'zynq-bm3-am2) DETECTED_BOARD="am2-s19pro"' 'am2-s19pro sysupgrade never unconditionally maps generic AM2 platform to S19 Pro'
require_pattern "$AM2_S17PRO_SYSUPGRADE" 'DCENT_ALLOW_AM2_S17P_AMBIGUOUS_BOS_PLATFORM' 'am2-s17pro sysupgrade requires explicit lab override for ambiguous generic AM2 platform'
require_pattern "$AM2_S17PRO_SYSUPGRADE" 'ambiguous AM2 platform marker' 'am2-s17pro sysupgrade explains zynq-bm3-am2 ambiguity'
require_pattern "$AM2_S17PRO_SYSUPGRADE" 'Wrong AM2 image = brick' 'am2-s17pro sysupgrade treats ambiguous first-flash as a brick guard'
reject_executable_pattern "$AM2_S17PRO_SYSUPGRADE" 'zynq-bm3-am2) DETECTED_BOARD="am2-s17p"' 'am2-s17pro sysupgrade never unconditionally maps generic AM2 platform to S17'
# --- end AM2 env-flip fw_setenv coverage ------------------------------------

# --- BASE zynq sysupgrade is am1-s9-ONLY; AM2 reachability is overlay-fenced -
# Productionization sweep (2026-05-21) DevOps CRITICAL-1 / Security CRITICAL-5
# claimed the BASE board/zynq/rootfs-overlay/usr/sbin/sysupgrade raw mtd4
# env-flip is AM2-reachable. It is NOT: Buildroot applies BR2_ROOTFS_OVERLAY
# left-to-right (later overlays overwrite earlier files), so every AM2 product
# defconfig that lists the base overlay ALSO appends its own product overlay
# that REPLACES usr/sbin/sysupgrade with the fw_setenv writer. The base raw
# script therefore ships ONLY in the am1-s9 image. These guards pin that
# invariant so a future defconfig/overlay change cannot silently expose the
# raw env-flip to an AM2 weak-ECC target.
#
# (1) The base script has NO AM2 board-detection branch — it resolves only
#     am1-s9 / unknown. (A regression that taught it to self-detect AM2 would
#     make the raw mtd4 path AM2-reachable.)
# Executable-only: the scope-documenting comment block legitimately NAMES the
# am2 platform/board strings in prose; only an actual executable reference
# (e.g. a DETECTED_BOARD="am2-*" assignment or a `zynq-bm3-am2` case branch)
# would make the raw mtd4 path AM2-reachable.
reject_executable_pattern "$S9_SYSUPGRADE" 'zynq-bm3-am2' 'base zynq sysupgrade has no executable am2 platform branch'
reject_executable_pattern "$S9_SYSUPGRADE" 'DETECTED_BOARD="am2' 'base zynq sysupgrade never resolves an am2 board target'
require_pattern "$S9_SYSUPGRADE" 'DETECTED_BOARD="am1-s9"' 'base zynq sysupgrade only ever resolves am1-s9'
require_pattern "$S9_SYSUPGRADE" 'ships ONLY in the am1-s9 image' 'base zynq sysupgrade documents its am1-only scope + AM2 overlay-replace'

# (2) Overlay-precedence invariant: every defconfig that lists the BASE zynq
#     overlay AND targets AM2 (platform zynq-bm3-am2) MUST also append a
#     product overlay with its own fw_setenv sysupgrade. We assert each known
#     AM2 zynq defconfig chains base + a product overlay dir on its
#     BR2_ROOTFS_OVERLAY line; and that the matching product sysupgrade exists
#     and uses fw_setenv (already covered above). am1-s9 chains the base only.
CONFIGS='br2_external_dcentos/configs'
for am2_cfg in dcentos_am2_s19jpro_defconfig dcentos_am2_s19pro_defconfig dcentos_am2_s17pro_zynq_defconfig; do
    cfg_path="$CONFIGS/$am2_cfg"
    if [ ! -f "$cfg_path" ]; then
        fail "AM2 overlay-precedence [$am2_cfg]: defconfig missing"
        continue
    fi
    ovl_line=$(grep '^BR2_ROOTFS_OVERLAY=' "$cfg_path" || echo '')
    case "$ovl_line" in
        *board/zynq/rootfs-overlay*board/zynq/am2-*/rootfs-overlay*)
            pass "AM2 overlay-precedence [$am2_cfg]: base overlay precedes an am2 product overlay (product fw_setenv sysupgrade wins)" ;;
        *)
            fail "AM2 overlay-precedence [$am2_cfg]: BR2_ROOTFS_OVERLAY must chain base zynq overlay THEN an am2-*/rootfs-overlay product override (else the raw-mtd4 base sysupgrade would ship on AM2)" ;;
    esac
done

# (3) The am1-s9 defconfig chains the BASE overlay only (so the raw-mtd4 base
#     sysupgrade is the intended am1-s9 healthy-NAND writer, not a leak).
S9_DEFCONFIG="$CONFIGS/dcentos_s9_defconfig"
s9_ovl_line=$(grep '^BR2_ROOTFS_OVERLAY=' "$S9_DEFCONFIG" || echo '')
case "$s9_ovl_line" in
    *board/zynq/am2-*) fail "am1-s9 defconfig must NOT chain an am2 product overlay" ;;
    *board/zynq/rootfs-overlay*) pass "am1-s9 defconfig chains the base zynq overlay only (raw mtd4 is the intended healthy-NAND path)" ;;
    *) fail "am1-s9 defconfig BR2_ROOTFS_OVERLAY does not reference the base zynq overlay" ;;
esac
# --- end base-sysupgrade am1-only overlay-precedence coverage ----------------

# --- Legacy SD-to-NAND compatibility path has no mutation authority ---------
SD_NAND_INSTALL='scripts/sd_nand_install.sh'
require_pattern "$SD_NAND_INSTALL" 'NOT IMPLEMENTED (mutation denied)' 'sd_nand_install declares its zero-mutation compatibility boundary'
require_pattern "$SD_NAND_INSTALL" 'exit 78' 'sd_nand_install refuses legacy mutation-shaped calls with EX_CONFIG'
for forbidden_writer in fw_setenv fw_printenv flash_erase nandwrite nanddump ubiattach ubiformat ubiupdatevol; do
    reject_executable_pattern "$SD_NAND_INSTALL" "$forbidden_writer" "sd_nand_install excludes writer: $forbidden_writer"
done
# --- end legacy SD-to-NAND containment --------------------------------------
require_pattern "$AM3_S19K_POST_IMAGE" 'rootfs uImage exceeds Amlogic rootfs window' 'am3-s19k post-image fails if rootfs exceeds rootfs window'
require_pattern "$AM3_S21_POST_IMAGE" 'PACKAGE_SIZE_LABEL="Amlogic rootfs window"' 'am3-s21 admitted targets label the guarded rootfs window'
require_pattern "$AM3_S21_POST_IMAGE" 'rootfs uImage exceeds ${PACKAGE_SIZE_LABEL}' 'am3-s21 shared packager fails against the selected authorized or package-only ceiling'
reject_pattern "$AM2_POST_IMAGE" '"version": null' 'am2 post-image does not emit null manifest version'
reject_pattern "$AM3_S19K_POST_IMAGE" '"version": null' 'am3-s19k post-image does not emit null manifest version'
reject_pattern "$AM3_S21_POST_IMAGE" '"version": null' 'am3-s21 post-image does not emit null manifest version'

# --- Amlogic S99upgrade raw-NAND exception is named and readback-verified ----
# am3-aml deliberately writes one recovery-state byte in mtd5 after health
# checks pass. That exception must stay explicit, Amlogic-only, immediately
# verified with read_recovery_flag(), and separate from the fw_setenv-only
# firstboot env clear.
require_pattern "$AMLOGIC_S99UPGRADE" 'AMLOGIC_RAW_NAND_RECOVERY_FLAG_EXCEPTION' 'amlogic S99upgrade names its only raw-NAND recovery-flag exception'
require_pattern "$AMLOGIC_S99UPGRADE" 'NEW=$(read_recovery_flag)' 'amlogic S99upgrade reads back the recovery flag after nandwrite'
require_pattern "$AMLOGIC_S99UPGRADE" '[ "$NEW" != "0x03" ]' 'amlogic S99upgrade fails when recovery-flag readback is not 0x03'
require_pattern "$AMLOGIC_S99UPGRADE" 'recovery flag readback = $NEW (expected 0x03)' 'amlogic S99upgrade reports the exact recovery-flag readback mismatch'
require_pattern "$AMLOGIC_S99UPGRADE" 'require_amlogic_ota08_identity' 'amlogic S99upgrade scopes OTA-08 to sealed board_target'
require_pattern "$AMLOGIC_S99UPGRADE" 'missing live $BOARD_TARGET_FILE' 'amlogic S99upgrade refuses missing live board_target'
require_pattern "$AMLOGIC_S99UPGRADE" 'OLD=$(read_recovery_flag)' 'amlogic S99upgrade pre-reads 0x02 before flash_erase'
require_pattern "$AMLOGIC_S99UPGRADE" 'ERROR: recovery flag readback' 'amlogic S99upgrade post-write mismatch is ERROR not WARN'
require_pattern "$AMLOGIC_S99UPGRADE" 'ERROR: recovery flag = 0x01 (INSTALLED) leftover in userspace' 'amlogic S99upgrade leftover 0x01 is ERROR not WARN'
reject_pattern "$AMLOGIC_S99UPGRADE" '[WARN] recovery flag = 0x01' 'amlogic S99upgrade leftover 0x01 is not WARN'
require_pattern "$AMLOGIC_S99UPGRADE" 'ERROR: could not read recovery flag' 'amlogic S99upgrade unread flag is ERROR not WARN'
require_pattern "$AMLOGIC_S99UPGRADE" 'ERROR: unexpected recovery flag value' 'amlogic S99upgrade unexpected flag is ERROR not WARN'
reject_pattern "$AMLOGIC_S99UPGRADE" '[WARN] could not read recovery flag' 'amlogic S99upgrade unread flag is not WARN'
reject_pattern "$AMLOGIC_S99UPGRADE" '[WARN] unexpected recovery flag value:' 'amlogic S99upgrade unexpected flag is not WARN'
require_pattern "$AMLOGIC_S99UPGRADE" 'fw_setenv firstboot 0' 'amlogic S99upgrade keeps firstboot env clearing on fw_setenv, not raw NAND'
# --- end amlogic S99upgrade raw-NAND exception -------------------------------

# --- Zynq A/B boot-success contract (W8 parity: auto-rollback not defeated) --
# W8 PARITY-SIGNOFF flagged the A/B auto-rollback as "⚠️ defeated by S99": the
# zynq S99upgrade committed a fresh slot (cleared upgrade_stage) the instant the
# daemon bound its API socket — a daemon that binds /api/status then crash-loops
# (or never reaches a steady state) was committed as good, defeating the U-Boot
# auto-revert the inactive-slot write had armed. The fix adds (a) a REAL health
# check (/api/system/health must parse + report positive daemon.uptime_s) and
# (b) a sustained BOOT-SUCCESS WINDOW (the same dcentrald PID must survive
# MIN_HEALTHY_UPTIME_S). These guards pin the contract so it cannot silently
# regress to the bind-then-commit hole. Brick-safety: the new gates only ever
# make the commit STRICTER (a needless non-commit reverts to the known-good old
# slot; this is the lower-risk failure), and absent health evidence soft-passes rather than
# falsely reverting a good unit.
ZYNQ_S99UPGRADE='br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/S99upgrade'
ZYNQ_S99VERIFY='br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/S99verify'

require_pattern "$ZYNQ_S99UPGRADE" 'BOOT-SUCCESS CONTRACT' 'zynq S99upgrade documents the boot-success contract'
require_pattern "$ZYNQ_S99UPGRADE" '/api/system/health' 'zynq S99upgrade gates commit on the real health endpoint, not just a socket bind'
require_pattern "$ZYNQ_S99UPGRADE" 'daemon_real_health_verdict' 'zynq S99upgrade evaluates a three-state real-health verdict'
require_pattern "$ZYNQ_S99UPGRADE" 'MIN_HEALTHY_UPTIME_S' 'zynq S99upgrade enforces a sustained boot-success window'
require_pattern "$ZYNQ_S99UPGRADE" 'boot-success window' 'zynq S99upgrade re-confirms the daemon survives the window'
require_pattern "$ZYNQ_S99UPGRADE" 'died inside the boot-success window' 'zynq S99upgrade fails closed on a crash-loop inside the window'
require_pattern "$ZYNQ_S99UPGRADE" 'UPGRADE_COMMIT_MARKER' 'zynq S99upgrade records its commit decision for S99verify'
# Brick-safety: the unknown/absent-health path must SOFT-PASS, not revert a
# good unit. Pin that the three-state verdict keeps an explicit soft-pass arm.
require_pattern "$ZYNQ_S99UPGRADE" 'not blocking commit on its absence' 'zynq S99upgrade soft-passes when health evidence is merely absent (brick-safe)'
# The real-health gate must default-safe: window default present and tunable.
require_pattern "$ZYNQ_S99UPGRADE" 'DCENTOS_BOOT_SUCCESS_WINDOW_S' 'zynq S99upgrade boot-success window is tunable with a safe default'

# S99verify is a report-only consumer of S99upgrade's decision (single commit
# authority) and must never re-commit a slot the upgrader blocked.
require_pattern "$ZYNQ_S99VERIFY" 'UPGRADE_COMMIT_MARKER' 'zynq S99verify observes the S99upgrade commit-decision marker'
require_pattern "$ZYNQ_S99VERIFY" 'report-only proof consumer' 'zynq S99verify documents its non-mutating proof role'
require_pattern "$ZYNQ_S99VERIFY" 'S99upgrade blocked commit' 'zynq S99verify preserves upgrade_stage when S99upgrade blocked the slot'

# Both init scripts must stay POSIX/BusyBox-ash safe (no bashisms).
require_pattern "$ZYNQ_S99UPGRADE" '#!/bin/sh' 'zynq S99upgrade is POSIX/BusyBox shell'
require_pattern "$ZYNQ_S99VERIFY" '#!/bin/sh' 'zynq S99verify is POSIX/BusyBox shell'
reject_pattern "$ZYNQ_S99UPGRADE" '[[ ' 'zynq S99upgrade has no bash [[ ]] test'
# --- end zynq boot-success contract coverage ---------------------------------

# --- Zynq upgrade_stage CLEAR must be reliable on weak-ECC mtd4 (BUG 2) -------
# Live S9 (.100, 2026-06-05): S99upgrade logged "OK: firmware committed via
# fw_setenv" THEN "WARN: upgrade_stage still present after fw_setenv" — the clear
# silently failed, so a power-cycle auto-reverted the unit to BraiinsOS (install
# NOT permanent). Root cause was the WRITE/VERIFY logic, not the env geometry
# (offsets 0x0/0x20000 + ENV_SIZE 0x20000 are CRC-verified against a real mtd4
# dump). The old code ran TWO separate fw_setenv calls + a single readback; on
# weak-ECC pl35x-nand a first-call copy that reads back CRC-bad makes the SECOND
# call re-read the stale copy and re-persist upgrade_stage. The fix mirrors the
# proven sysupgrade write path: one ATOMIC `fw_setenv --script -` transaction
# clearing BOTH vars, RETRIED with a per-attempt fw_printenv verify, failing
# loudly (blocked marker -> U-Boot reverts to the known-good slot) if all
# attempts fail. NEVER raw nandwrite mtd4 (load-bearing
# ).
require_pattern "$ZYNQ_S99UPGRADE" 'fw_setenv -c "$FW_ENV_CONFIG" --script -' 'zynq S99upgrade clears upgrade_stage via a single atomic fw_setenv --script transaction'
require_pattern "$ZYNQ_S99UPGRADE" 'FW_COMMIT_RETRIES' 'zynq S99upgrade retries the upgrade_stage clear (weak-ECC mtd4 resilience)'
require_pattern "$ZYNQ_S99UPGRADE" 'DCENTOS_FW_COMMIT_RETRIES' 'zynq S99upgrade retry count is tunable with a safe default'
require_pattern "$ZYNQ_S99UPGRADE" 'exact old environment still present' 'zynq S99upgrade verifies upgrade_stage is actually gone after each attempt'
require_pattern "$ZYNQ_S99UPGRADE" 'could NOT be cleared after' 'zynq S99upgrade fails loudly when every clear attempt fails'
# The clear must remain fw_setenv-only — never a raw NAND write on weak mtd4.
# (Match an actual command targeting the device, not the word in prose/warnings:
# the script legitimately documents "DO NOT raw-nandwrite" in comments.)
reject_pattern "$ZYNQ_S99UPGRADE" 'nandwrite /dev/mtd' 'zynq S99upgrade never raw-nandwrites mtd4'
reject_pattern "$ZYNQ_S99UPGRADE" 'flash_erase /dev/mtd' 'zynq S99upgrade never flash_erases mtd4'
# A blocked (unconfirmed) clear must NOT advertise a committed slot to S99verify.
require_pattern "$ZYNQ_S99UPGRADE" 'echo "blocked" > "$UPGRADE_COMMIT_MARKER"' 'zynq S99upgrade marks the slot blocked when the clear is unconfirmed (fail-safe)'
# fw_env.config geometry must stay the CRC-verified redundant pair. The
# installed file is the exact 72-byte parser input (two single-space records,
# no comment header): sysupgrade-uboot-env-admission.sh admits ONLY that
# byte-exact content before any fw_setenv mutation, so this documentation
# lives in tests, not in the parser input. Geometry was verified against a
# real mtd4 dump (2026-06-05, output/nand-backup-135-20260605, 524288 B):
# copy A @ 0x00000, copy B @ 0x20000, ENV_SIZE 0x20000 (CRC32 over
# data[5:0x20000] matches BOTH copies). Do NOT "fix" this by shrinking
# ENV_SIZE or by raw nandwrite (load-bearing
# ).
ZYNQ_FW_ENV='br2_external_dcentos/board/zynq/rootfs-overlay/etc/fw_env.config'
require_exact_line "$ZYNQ_FW_ENV" '/dev/mtd4 0x00000 0x20000 0x20000 1' 'zynq fw_env.config copy A geometry (CRC-verified, admission byte-exact)'
require_exact_line "$ZYNQ_FW_ENV" '/dev/mtd4 0x20000 0x20000 0x20000 1' 'zynq fw_env.config copy B geometry (CRC-verified, admission byte-exact)'
if [ "$(wc -c <"$ZYNQ_FW_ENV" | tr -d '[:space:]')" = 72 ]; then
    pass 'zynq fw_env.config is the exact 72-byte two-record parser input'
else
    fail 'zynq fw_env.config must be the exact 72-byte two-record parser input (no comments)'
fi
# --- end zynq upgrade_stage-clear reliability coverage -----------------------

# --- CV1835 brick-vector retirement -----------------------------------------
# Held FIP/U-Boot evidence disproves the old persistent-environment premise.
# No artifact producer is admitted until exact-toolchain and final-rootfs
# containment closure are proven. Every historical build/update entry point
# must therefore remain an unconditional refusal.
CV1835_SAFE_SU='scripts/safe_sysupgrade_cv_emmc.sh'
CV1835_REVERT='scripts/revert_to_stock_cv1835.sh'
CV1835_BUILD='scripts/build_cv1835_s19jpro.sh'
CV1835_POST_IMAGE='br2_external_dcentos/board/cvitek/cv1835-s19jpro/post-image.sh'
CV1835_POST_BUILD='br2_external_dcentos/board/cvitek/cv1835-s19jpro/post-build.sh'
CV1835_FW_ENV='br2_external_dcentos/board/cvitek/cv1835-s19jpro/rootfs-overlay/etc/fw_env.config'

require_pattern "$CV1835_SAFE_SU" 'exit 78' 'cv1835 updater exits with unconditional unavailable status'
require_pattern "$CV1835_REVERT" 'exit 78' 'cv1835 stock-revert exits with unconditional unavailable status'
require_pattern "$CV1835_BUILD" 'exit 78' 'cv1835 standalone build entry point refuses every artifact lane'
require_pattern "$CV1835_SAFE_SU" 'BuiltInVolatile/mutation-denied' 'cv1835 updater records the evidenced volatile environment backend'
reject_pattern "$CV1835_SAFE_SU" 'DCENT_ALLOW_UNSIGNED_SYSUPGRADE' 'cv1835 updater has no proof or unsigned-package override'
if [ ! -e "$CV1835_FW_ENV" ] && [ ! -L "$CV1835_FW_ENV" ]; then
    pass 'cv1835 guessed fw_env.config remains absent'
else
    fail 'cv1835 guessed fw_env.config was reintroduced'
fi
if [ ! -e 'br2_external_dcentos/board/cvitek/cv1835-s19jpro' ]; then
    pass 'cv1835 orphan board overlay remains deleted'
else
    fail 'cv1835 orphan board overlay was reintroduced'
fi
# --- end CV1835 brick-vector retirement -------------------------------------

# =============================================================================
# Bucket-A P0 blocker coverage (CE-105 / CE-056 / CE-153 / CE-408 / CE-341 /
# CE-126 / CE-374 / CE-382). Additive, fail-closed pins so the new guards
# cannot silently rot. All files are already offline/static-checkable here.
# =============================================================================

# --- CE-105 successor: inactive-slot work is denied until the shared engine --
require_pattern "$SD_NAND_INSTALL" 'no exact admitted hardware/update descriptor' 'sd_nand_install requires typed hardware/update admission before implementation'
require_pattern "$SD_NAND_INSTALL" 'legacy install-shaped arguments cannot authorize' 'sd_nand_install rejects legacy argument-based write authority'

# The standalone packager owns only the S9 lane. AM2 artifacts come from their
# dedicated target post-image scripts, so an S9 DTB can never be relabelled AM2.
reject_pattern "$PACKAGE" 'DCENT_ALLOW_AM2_S9_PLACEHOLDER' 'S9 packager has no AM2 placeholder override'
reject_pattern "$PACKAGE" 'DCENT_FORCE_AM2_UPLOAD' 'S9 packager has no AM2 live-upload override'
reject_pattern "$PACKAGE" 'am2-s19j)' 'S9 packager cannot dispatch an AM2 package lane'
require_pattern "$PACKAGE" 'accepted: am1-s9' 'S9 packager declares its single accepted board'
if retired_output=$(bash "$PACKAGE" \
    --board am2-s19j \
    --version 0.9.0 \
    --images-dir /dcentos-am2-retired-lane-must-not-be-read \
    --output /dcentos-am2-retired-lane-must-not-be-written.tar 2>&1); then
    fail "S9 packager accepted the retired AM2 package lane"
else
    case "$retired_output" in
        *"Unsupported board: am2-s19j (accepted: am1-s9)"*)
            pass "S9 packager refuses AM2 before reading build inputs"
            ;;
        *)
            fail "S9 packager AM2 refusal was not the canonical early board gate"
            ;;
    esac
fi

# --- CE-153: raw environment transformers are guarded host-only tools --------
HOST_SWITCH_FW='scripts/switch_firmware.py'
HOST_SWITCH_FW_SH='scripts/switch_firmware.sh'
TARGET_SWITCH_FW='br2_external_dcentos/board/zynq/rootfs-overlay/usr/sbin/switch_firmware.py'
TARGET_SWITCH_FW_SH='br2_external_dcentos/board/zynq/rootfs-overlay/usr/sbin/switch_firmware.sh'
RUNTIME_PRUNE='br2_external_dcentos/board/common/prune-runtime-research-tools.sh'
require_pattern "$HOST_SWITCH_FW" '--i-understand-this-is-not-fw-setenv' 'host switch_firmware.py requires the not-fw-setenv acknowledgement'
require_pattern "$HOST_SWITCH_FW" 'REFUSING: switch_firmware.py is DEPRECATED' 'host switch_firmware.py refuses to run without the ack'
require_pattern "$HOST_SWITCH_FW" 'DEPRECATED FOR THE OTA/SYSUPGRADE WRITE PATH' 'host switch_firmware.py carries the deprecation banner'
require_pattern "$HOST_SWITCH_FW" 'distinct flags' 'host switch_firmware.py writes redundant env copies with distinct flags'
require_pattern "$HOST_SWITCH_FW_SH" '--i-understand-this-is-not-fw-setenv' 'host switch_firmware.sh requires the not-fw-setenv acknowledgement'
require_pattern "$HOST_SWITCH_FW_SH" 'REFUSING: switch_firmware.sh is DEPRECATED' 'host switch_firmware.sh refuses to run without the ack'
for target_switch_fw in "$TARGET_SWITCH_FW" "$TARGET_SWITCH_FW_SH"; do
    if [ ! -e "$target_switch_fw" ] && [ ! -L "$target_switch_fw" ]; then
        pass "target overlay excludes host-only transformer: $target_switch_fw"
    else
        fail "target overlay contains forbidden raw environment transformer: $target_switch_fw"
    fi
done
require_pattern "$RUNTIME_PRUNE" 'usr/sbin/switch_firmware.py' 'final rootfs prune removes stale switch_firmware.py'
require_pattern "$RUNTIME_PRUNE" 'usr/sbin/switch_firmware.sh' 'final rootfs prune removes stale switch_firmware.sh'

# --- CE-408 successor: unverified S19 AM2 restore is fully contained ---------
require_pattern "$S19_AM2_REVERT" 'NOT IMPLEMENTED (mutation denied)' 'revert_to_stock_s19_am2 declares its zero-mutation compatibility boundary'
require_pattern "$S19_AM2_REVERT" 'exit 78' 'revert_to_stock_s19_am2 refuses legacy mutation-shaped calls with EX_CONFIG'
for forbidden_writer in fw_setenv fw_printenv flash_erase nandwrite nanddump wget curl; do
    reject_executable_pattern "$S19_AM2_REVERT" "$forbidden_writer" "revert_to_stock_s19_am2 excludes writer: $forbidden_writer"
done

# --- CE-341: build_in_docker labels/gates the canonical release alias ---------
require_pattern "$BUILD_DOCKER" 'LAB-UNSIGNED-NOT-FOR-RELEASE' 'build_in_docker labels a non-release-grade canonical alias as lab-unsigned'
require_pattern "$BUILD_DOCKER" 'signature_trust=' 'build_in_docker records signature_trust in the release sidecar'
require_pattern "$BUILD_DOCKER" 'proof_scope=' 'build_in_docker records proof_scope in the release sidecar'
require_pattern "$BUILD_DOCKER" 'RELEASE_GRADE=1' 'build_in_docker computes a release-grade verdict for the canonical alias'

# --- CE-126: legacy web-installer quarantine + no world-open CGMiner API ------
# Pin the SOURCE copy (the RC baseline). The public-releases/ mirror is a
# regenerated artifact (tools/public-release/refresh-all.sh) — it inherits this
# fix at publish time and must NOT be hand-edited here (the plan excludes
# public-releases from the RC cut).
WEB_INSTALLER='scripts/build_web_installer.sh'
for web_inst in "$WEB_INSTALLER"; do
    if [ -f "$web_inst" ]; then
        require_pattern "$web_inst" 'DCENT_ALLOW_LEGACY_WEB_INSTALLER' "web-installer [$web_inst] is quarantined behind an explicit opt-in"
        require_pattern "$web_inst" 'quarantined unsafe research tool' "web-installer [$web_inst] refuses to run by default"
        reject_pattern "$web_inst" 'W:0/0' "web-installer [$web_inst] emits no world-open CGMiner api-allow"
        reject_pattern "$web_inst" 'W:0\/0' "web-installer [$web_inst] emits no world-open CGMiner api-allow (sed-escaped form)"
    else
        pass "web-installer copy not present in this tree (skipped): $web_inst"
    fi
done

# --- CE-374: NAND backup planners bind restore-proof to the exact unit --------
AM1_NAND_PLAN=scripts/am1_nand_backup_plan.py
AM1_NAND_PLAN_WRAPPER=scripts/am1_nand_backup_plan.sh
require_pattern "$AM1_NAND_PLAN_WRAPPER" 'am1_nand_backup_plan.py' 'AM1 planner wrapper delegates to the strict Python implementation'
require_pattern "$AM1_NAND_PLAN" '"--restore-artifact"' 'AM1 planner requires the physical restore artifact bytes'
require_pattern "$AM1_NAND_PLAN" '"--expect-host-key-sha256"' 'AM1 planner binds the pinned SSH host key'
require_pattern "$AM1_NAND_PLAN" 'args.expect_target != AUTHORIZED_BOARD_TARGET' 'AM1 planner rejects an operator-selected board class'
require_ordered_patterns "$AM1_NAND_PLAN" \
    'atomic_publish(args.output, markdown)' \
    'atomic_publish(args.json_template, encoded)' \
    'AM1 planner publishes its executable validated JSON last'

for nand_plan in scripts/am2_nand_backup_plan.sh; do
    require_pattern "$nand_plan" '--expect-mac' "$(basename "$nand_plan") accepts an --expect-mac identity arg"
    require_pattern "$nand_plan" '--expect-hwid' "$(basename "$nand_plan") accepts an --expect-hwid identity arg"
    require_pattern "$nand_plan" 'restore_verified_identity_matched' "$(basename "$nand_plan") sets restore-proof OK only on identity match"
    require_pattern "$nand_plan" 'restore_matched_mac' "$(basename "$nand_plan") emits the matched MAC in JSON"
    require_pattern "$nand_plan" 'identity_mismatch' "$(basename "$nand_plan") fails closed on identity mismatch"
    require_pattern "$nand_plan" 'advisory, not identity-bound' "$(basename "$nand_plan") downgrades marker-only proof wording"
done
if nand_backup_identity_selftest; then
    pass "CE-374 NAND backup planners bind restore-proof to the exact unit (identity match required for plan_ready)"
else
    fail "CE-374 NAND backup planner identity-binding selftest failed"
fi

# --- CE-382: SD writer fails closed on a post-write verify failure ------------
WRITE_SD='scripts/write_sd_card.sh'
require_pattern "$WRITE_SD" 'VERIFY_FAILED=1' 'write_sd_card marks a post-write verification failure'
require_pattern "$WRITE_SD" 'Post-write verification FAILED' 'write_sd_card refuses to declare the card ready after a failed verify'
require_pattern "$WRITE_SD" 'BOOT.BIN: NOT FOUND ON CARD' 'write_sd_card fails closed when a copied BOOT.BIN is absent on the card'
# The fail-closed guard (error/exit) MUST sit BEFORE the success banner so the
# "=== SD Card Ready ===" line can never print on a failed verify.
if awk '
    /Post-write verification FAILED/ { seen_guard = 1 }
    /=== SD Card Ready ===/ { if (!seen_guard) { bad = 1 } }
    END { exit (bad ? 1 : 0) }
' "$WRITE_SD"; then
    pass 'write_sd_card: fail-closed verify guard precedes the SD Card Ready banner'
else
    fail 'write_sd_card: SD Card Ready banner can print before the fail-closed verify guard'
fi

if signing_policy_selftest; then
    pass "signing policy selftest fails closed for release and accepts explicit lab override"
else
    fail "signing policy selftest failed"
fi
if zynq_payload_window_selftest; then
    pass "zynq package-only selftest rejects oversized rootfs payloads"
else
    fail "zynq package-only selftest failed"
fi
if s9_route_scoped_window_selftest; then
    pass "S9 route-scoped admission: over-window first-install-only package passes within the stock-transaction capacity bounds; over-capacity rootfs/kernel, self-update-claiming, legacy, tampered, wrong-board, and wrong-mode shapes all fail closed; fitting dual-route unchanged"
else
    fail "S9 route-scoped window admission behavioral selftest failed"
fi
if s9_export_validation_selftest; then
    pass "S9 export validation accepts a bound package and rejects wrong prefix/board, bare zImage, bad binding, and oversized kernel"
else
    fail "S9 export validation behavioral selftest failed"
fi
if zynq_target_payload_authority_selftest; then
    pass "Zynq target payload authority validates canonical bindings and rejects malformed paths, sizes, hashes, and extracted leaves"
else
    fail "Zynq target payload authority behavioral selftest failed"
fi
if python3 scripts/test_sysupgrade_manifest_json.py >/dev/null; then
    pass "semantic manifest JSON and deterministic version contracts pass"
else
    fail "semantic manifest JSON/version contract test failed"
fi

# --- Interpreter pinning for in-recipe host python (run
# --- drop1-20260918-xtleogkg): Buildroot's make puts its minimal host
# --- python3 first on PATH; release_native_sd.py and the bm1396 media
# --- scripts need the container system python's python3-cryptography.
# --- Static pins so a reverted pin fails offline instead of at the next
# --- producer run.
NATIVE_SD_POST_BUILD='scripts/release_native_sd_post_build.sh'
NATIVE_SD_POST_IMAGE='scripts/release_native_sd_post_image.sh'
BM1396_SD='scripts/build_sd_bm1396.sh'
POST_IMAGE_17F='br2_external_dcentos/board/zynq/post-image-17-family.sh'
for dcent_pinned_script in "$NATIVE_SD_POST_BUILD" "$NATIVE_SD_POST_IMAGE" "$BM1396_SD" "$POST_IMAGE_17F"; do
    [ -f "$dcent_pinned_script" ] || fail "interpreter-pinned script missing: $dcent_pinned_script"
done
require_pattern "$NATIVE_SD_POST_BUILD" 'exec /usr/bin/python3 "$here/release_native_sd.py"' 'native-SD post-build pins the system python'
require_pattern "$NATIVE_SD_POST_IMAGE" 'exec /usr/bin/python3 "$here/release_native_sd.py"' 'native-SD post-image pins the system python'
require_pattern "$BM1396_SD" '/usr/bin/python3 "$dcent_script_dir/prepare_bm1396_sd_image.py" assemble' 'BM1396 media assembly pins the system python'
require_pattern "$BM1396_SD" '/usr/bin/python3 "$dcent_script_dir/prepare_bm1396_sd_image.py" data-uuid' 'BM1396 data-uuid stage pins the system python'
require_pattern "$BM1396_SD" '/usr/bin/python3 "$dcent_script_dir/prepare_bm1396_sd_image.py" root' 'BM1396 root stage pins the system python'
require_pattern "$BM1396_SD" '/usr/bin/python3 "$dcent_script_dir/prepare_bm1396_sd_boot.py"' 'BM1396 boot stage pins the system python'
require_pattern "$POST_IMAGE_17F" '/usr/bin/python3 "$PROJECT_ROOT/scripts/release_native_sd.py"' '17-family native SD assembly pins the system python'
# Filesystem tools: Buildroot's host e2fsprogs 1.47.x shadows the container
# system 1.46.x inside make recipes; the pristine ext4 schema is pinned to
# the system tool bytes (run drop1-20260919-yomed_3s).
NATIVE_SD_PY='scripts/release_native_sd.py'
[ -f "$NATIVE_SD_PY" ] || fail "interpreter-pinned script missing: $NATIVE_SD_PY"
require_pattern "$NATIVE_SD_PY" 'command("/usr/sbin/mke2fs"' 'native-SD ext4 creation pins the system mke2fs'
require_pattern "$NATIVE_SD_PY" 'arguments = ["/usr/sbin/mke2fs"' 'native-SD new_filesystem pins the system mke2fs'
require_pattern "$NATIVE_SD_PY" 'command("/usr/sbin/e2fsck"' 'native-SD ext4 check pins the system e2fsck'
require_pattern "$NATIVE_SD_PY" 'command("/usr/sbin/debugfs"' 'native-SD fallocate pins the system debugfs'
require_pattern "$NATIVE_SD_PY" 'command("/usr/sbin/mkfs.fat"' 'native-SD FAT creation pins the system mkfs.fat'
require_pattern "$NATIVE_SD_PY" 'command("/usr/bin/mcopy"' 'native-SD FAT copy pins the system mcopy'
require_pattern "$NATIVE_SD_PY" 'command("/usr/bin/mtype"' 'native-SD FAT readback pins the system mtype'
require_pattern "$NATIVE_SD_PY" 'command("/usr/bin/mksquashfs"' 'native-SD squashfs pins the system mksquashfs'
require_pattern "$NATIVE_SD_PY" '*(["-Xbcj", "arm"] if selected["board_family"] != "am1" else [])' 'native-SD am2 squashfs carries the ARM BCJ filter, am1 excluded (179-LEB window)'
require_pattern "$NATIVE_SD_PY" 'remove_flat_tree(root, "etc/dcentos/xil25-seed")' 'native-SD strips the XIL .25 NAND-bake seed from removable media'
require_pattern "$NATIVE_SD_PY" 'if source_board == "am2-s19j":' 'native-SD seed strip applies only to the s19j base that stages it'
require_pattern "$NATIVE_SD_PY" 'remove(root, "usr/local/bin/dcentrald_standalone_boot.sh")' 'native-SD strips the .25 auto-pinned launcher'
require_pattern "$NATIVE_SD_PY" 'unexpected XIL .25 seed staging in base:' 'native-SD refuses the seed on any base that does not stage it'
require_pattern "$NATIVE_SD_PY" '"etc/dcentos/psu_config", "etc/dcentos/rail_gpio",' 'native-SD strips the am2 XIL-bake PSU/rail declarations'
require_pattern "$NATIVE_SD_PY" '"etc/dcentos/partial_yield_floor", "etc/dcentos/fan_max_pwm",' 'native-SD strips the am2 yield/fan tuning declarations'
# The toolbox validator is the second wall: a strip regression must fail
# release verification, not ship. The suite imports this package, so the
# sibling repo is already a hard prerequisite here.
TOOLBOX_NATIVE_VALIDATOR='../dcent-toolbox/src/dcent_toolbox/core/current_native_release.py'
require_pattern "$TOOLBOX_NATIVE_VALIDATOR" '"etc/dcentos/psu_config", "etc/dcentos/rail_gpio", "etc/dcentos/partial_yield_floor",' 'toolbox native validator forbids the PSU/rail declarations'
require_pattern "$TOOLBOX_NATIVE_VALIDATOR" '"etc/dcentos/fan_max_pwm", "etc/init.d/S81dcentos-xil25-seed",' 'toolbox native validator forbids the fan tuning file and the XIL seed service'
require_pattern "$BM1396_SD" '/usr/sbin/mke2fs -q -F -t ext2' 'BM1396 rootfs pins the system mke2fs'
require_pattern "$BM1396_SD" '/usr/sbin/mke2fs -q -F -t ext4' 'BM1396 data pins the system mke2fs'
require_pattern "$BM1396_SD" '/usr/sbin/e2fsck -f -n' 'BM1396 checks pin the system e2fsck'
require_pattern "$BM1396_SD" '/usr/sbin/mkfs.vfat -F 32' 'BM1396 boot pins the system mkfs.vfat'
require_pattern "$BM1396_SD" '/usr/bin/unsquashfs -processors' 'BM1396 rootfs unpack pins the system unsquashfs'
require_pattern "$PRE_FLASH" '--package-only-noninstallable' 'denied-contract packages verify signatures in the non-installable mode'
if release_image_hardening_coupling_selftest; then
    pass "CE-183 release-status packaging fails closed without release-image hardening and no-ops for lab status"
else
    fail "CE-183 release-status hardening coupling selftest failed"
fi
if toolbox_install_contract_selftest; then
    pass "toolbox install metadata accepts complete contracts and rejects missing or pre-acknowledged gates"
else
    fail "toolbox install metadata contract selftest failed"
fi
if toolbox_update_contract_selftest; then
    pass "toolbox update metadata accepts the fleet OTA form with identical gates; install metadata stays single-unit"
else
    fail "toolbox update metadata contract selftest failed"
fi

for phrase in \
    'Package + upload + flash' \
    'Upload and flash' \
    'Ready to flash' \
    'during flash' \
    'Upload verified.' \
    'Refusing to flash' \
    '=== SUCCESS ===' \
    'DCENTos is running on'
do
    reject_pattern "$PACKAGE" "$phrase" "package_sysupgrade avoids overclaim phrase: $phrase"
done

if [ "$failures" -ne 0 ]; then
    printf '\nSysupgrade packaging static checks failed: %s failure(s)\n' "$failures" >&2
    exit 1
fi

printf '\nSysupgrade packaging static checks passed.\n'
