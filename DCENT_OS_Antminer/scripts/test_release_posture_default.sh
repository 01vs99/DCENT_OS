#!/bin/sh
#
# WS-A4 (2026-09-01) — RELEASE-default image posture tests.
#
# Operator decision T-OP-7 ("ship RELEASE by default", 2026-09-01 campaign
# prompt) closes the 2026-08-19 Security  "the customer image is still
# DEV-credentialed". This suite pins the flip:
#
#   (a) the canonical resolver (scripts/lib/release_posture.sh):
#       unset => RELEASE, DCENT_DEV_IMAGE=1 => DEV, explicit
#       DCENT_RELEASE_IMAGE wins either way (stricter posture wins).
#   (b) the am3-s19kpro post-image refusal still fires — but only on an
#       explicit DEV/LAB opt-out, never on the (now RELEASE) default.
#   (c) the build drivers resolve the canonical posture (docker driver
#       materializes the effective DCENT_RELEASE_IMAGE; --lab-unsigned opts
#       out; the WSL dev driver self-declares DEV; build-dcentrald.sh keys
#       its release context on the resolver).
#   (d) every runtime auth surface stays keyed on the
#       /etc/dcentos/release-image MARKER (never on the env var), so the
#       default flip hardens the shipped image without forking daemon
#       behavior on build-time environment.
#
# POSIX sh only; runs on the host (no Buildroot, no Docker, no hardware).

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
BR2_DIR="$PROJECT_DIR/br2_external_dcentos"

fail_test() {
    echo "release posture default test failed: $*" >&2
    exit 1
}

pass() {
    echo "ok - $1"
}

# --- (a) canonical resolver semantics ---------------------------------------
. "$SCRIPT_DIR/lib/release_posture.sh"

if (unset DCENT_RELEASE_IMAGE DCENT_DEV_IMAGE; dcent_release_posture_is_release); then
    pass "resolver: unset posture env => RELEASE (the shipped default)"
else
    fail_test "resolver: unset posture env did not resolve to RELEASE"
fi

if (unset DCENT_RELEASE_IMAGE; DCENT_DEV_IMAGE=1 dcent_release_posture_is_release); then
    fail_test "resolver: DCENT_DEV_IMAGE=1 did not select the DEV/LAB posture"
else
    pass "resolver: DCENT_DEV_IMAGE=1 (canonical opt-out) => DEV"
fi

if (unset DCENT_RELEASE_IMAGE; DCENT_DEV_IMAGE=true dcent_release_posture_is_release); then
    fail_test "resolver: DCENT_DEV_IMAGE=true not accepted as truthy opt-out"
else
    pass "resolver: DCENT_DEV_IMAGE truthy spellings accepted"
fi

if (unset DCENT_DEV_IMAGE; DCENT_RELEASE_IMAGE=0 dcent_release_posture_is_release); then
    fail_test "resolver: explicit DCENT_RELEASE_IMAGE=0 did not select DEV"
else
    pass "resolver: explicit DCENT_RELEASE_IMAGE=0 => DEV (direct opt-out spelling)"
fi

if (DCENT_RELEASE_IMAGE=1 DCENT_DEV_IMAGE=1 dcent_release_posture_is_release); then
    pass "resolver: explicit DCENT_RELEASE_IMAGE=1 beats the DCENT_DEV_IMAGE alias"
else
    fail_test "resolver: explicit RELEASE value lost to the lab alias (must fail-safe to the stricter posture)"
fi

if (DCENT_RELEASE_IMAGE=0 DCENT_DEV_IMAGE=1 dcent_release_posture_is_release); then
    fail_test "resolver: explicit 0 + dev alias did not resolve to DEV"
else
    pass "resolver: explicit 0 + dev alias => DEV (consistent opt-outs)"
fi

# An exported-but-EMPTY DCENT_RELEASE_IMAGE must not silently mean DEV.
if (DCENT_RELEASE_IMAGE= dcent_release_posture_is_release); then
    pass "resolver: empty DCENT_RELEASE_IMAGE falls through to the RELEASE default"
else
    fail_test "resolver: empty DCENT_RELEASE_IMAGE selected DEV (drivers materialize empty values)"
fi

[ "$(unset DCENT_RELEASE_IMAGE DCENT_DEV_IMAGE; dcent_release_posture_value)" = 1 ] \
    || fail_test "resolver: posture value is not 1 on the default"
[ "$(DCENT_DEV_IMAGE=1 dcent_release_posture_value)" = 0 ] \
    || fail_test "resolver: posture value is not 0 on the dev opt-out"

# --- (b) s19kpro post-image refusal: default RELEASE, opt-out refuses -------
S19KPRO_POST_IMAGE="$BR2_DIR/board/amlogic/am3-s19kpro/post-image.sh"
[ -f "$S19KPRO_POST_IMAGE" ] || fail_test "missing $S19KPRO_POST_IMAGE"

# The refusal must fire on the explicit DEV opt-out...
(
    unset DCENT_RELEASE_IMAGE
    export DCENT_DEV_IMAGE=1
    export BR2_EXTERNAL_DCENTOS_PATH="$BR2_DIR"
    set +e
    sh "$S19KPRO_POST_IMAGE" >/dev/null 2>"${TMPDIR:-/tmp}/dcent-wsa4-s19kpro-refusal.err"
    _rc=$?
    set -e
    [ "$_rc" -ne 0 ] || exit 10
    grep -q 'requires DCENT_RELEASE_IMAGE=1' "${TMPDIR:-/tmp}/dcent-wsa4-s19kpro-refusal.err" || exit 11
    exit 0
) || fail_test "s19kpro post-image: DCENT_DEV_IMAGE=1 did NOT hit the RELEASE refusal"
pass "s19kpro post-image: explicit DEV opt-out still refused (exit + exact message)"

# ...and must NOT fire on the default posture (the run proceeds past the
# posture gate and stops at a LATER gate instead).
(
    unset DCENT_RELEASE_IMAGE DCENT_DEV_IMAGE
    export BR2_EXTERNAL_DCENTOS_PATH="$BR2_DIR"
    set +e
    sh "$S19KPRO_POST_IMAGE" >/dev/null 2>"${TMPDIR:-/tmp}/dcent-wsa4-s19kpro-default.err"
    _rc=$?
    set -e
    [ "$_rc" -ne 0 ] || exit 20
    if grep -q 'requires DCENT_RELEASE_IMAGE=1' "${TMPDIR:-/tmp}/dcent-wsa4-s19kpro-default.err"; then
        exit 21
    fi
    exit 0
) || fail_test "s19kpro post-image: the DEFAULT posture was refused by the release gate"
pass "s19kpro post-image: default posture passes the release gate (fails later on the signing-key gate, as designed)"

# --- (c) build drivers resolve the canonical posture ------------------------
DOCKER_DRIVER="$SCRIPT_DIR/build_in_docker.sh"
grep -q 'lib/release_posture.sh' "$DOCKER_DRIVER" \
    || fail_test "build_in_docker.sh does not source the canonical posture resolver"
grep -q 'DCENT_RELEASE_IMAGE="\$(dcent_release_posture_value)"' "$DOCKER_DRIVER" \
    || fail_test "build_in_docker.sh does not materialize the effective posture"
# The resolution must happen before the CE-183 gate reads the variable.
_ce183_line=$(grep -n 'is_release_status "\$DCENT_PACKAGE_STATUS" && ! is_truthy' "$DOCKER_DRIVER" | head -1 | cut -d: -f1)
_resolve_line=$(grep -n 'DCENT_RELEASE_IMAGE="\$(dcent_release_posture_value)"' "$DOCKER_DRIVER" | head -1 | cut -d: -f1)
[ -n "$_ce183_line" ] && [ -n "$_resolve_line" ] && [ "$_resolve_line" -lt "$_ce183_line" ] \
    || fail_test "build_in_docker.sh posture resolution does not precede the CE-183 gate"
grep -q -- '--lab-unsigned)' "$DOCKER_DRIVER" \
    && grep -A6 -- '--lab-unsigned)' "$DOCKER_DRIVER" | grep -q 'DCENT_DEV_IMAGE' \
    || fail_test "build_in_docker.sh --lab-unsigned does not set the canonical DEV opt-out"
pass "build_in_docker.sh: canonical resolution before first read; --lab-unsigned opts out"

WSL_DRIVER="$SCRIPT_DIR/build_in_wsl.sh"
grep -q 'DCENT_DEV_IMAGE="\${DCENT_DEV_IMAGE:-1}"' "$WSL_DRIVER" \
    || fail_test "build_in_wsl.sh does not self-declare the DEV opt-out"
grep -q 'does not implement release-image hardening' "$WSL_DRIVER" \
    || fail_test "build_in_wsl.sh lost its explicit-release refusal"
pass "build_in_wsl.sh: self-declared DEV driver; explicit RELEASE request still refused"

DCENTRALD_DRIVER="$SCRIPT_DIR/build-dcentrald.sh"
grep -q 'dcent_release_posture_is_release' "$DCENTRALD_DRIVER" \
    || fail_test "build-dcentrald.sh does not resolve the canonical posture"
grep -q 'DCENT_DEV_IMAGE=1' "$DCENTRALD_DRIVER" \
    || fail_test "build-dcentrald.sh error text does not teach the DEV opt-out"
pass "build-dcentrald.sh: release context keyed on the canonical resolver"

PACKAGER="$SCRIPT_DIR/package_sysupgrade.sh"
grep -q 'DCENT_RELEASE_IMAGE="\$(dcent_release_posture_value)"' "$PACKAGER" \
    || fail_test "package_sysupgrade.sh does not materialize the effective posture"
pass "package_sysupgrade.sh: canonical resolution before the CE-183/public gates"

# DEV-default read pattern must not return in the posture-critical surfaces.
for _file in \
    "$SCRIPT_DIR/lib/release_image_provision.sh" \
    "$BR2_DIR/board/common/prune-runtime-research-tools.sh" \
    "$BR2_DIR/board/amlogic/am3-s19kpro/post-image.sh" \
    "$BR2_DIR/board/beaglebone/am3-bb-s19jpro/post-build.sh" \
    "$SCRIPT_DIR/lib/sysupgrade_package_common.sh" \
    "$SCRIPT_DIR/lib/release_envelope.sh" \
    "$SCRIPT_DIR/lib/public_artifact_release_gate.sh"
do
    if grep -n 'DCENT_RELEASE_IMAGE:-0' "$_file" >/dev/null; then
        fail_test "DEV-default read pattern \${DCENT_RELEASE_IMAGE:-0} returned in $_file"
    fi
done
pass "no \${DCENT_RELEASE_IMAGE:-0} DEV-default reads remain in posture-critical surfaces"

# --- (d) auth surfaces stay MARKER-keyed (never env-keyed) -------------------
# The marker file the post-build stamps is the single runtime switch for the
# RELEASE≠DEV auth split; daemons must not read the build-time env var.
grep -q 'RELEASE_IMAGE_MARKER = "/etc/dcentos/release-image"' \
    "$BR2_DIR/board/zynq/rootfs-overlay/root/web/server.py" \
    || fail_test "zynq :80 server.py lost the marker constant"
grep -q 'RELEASE_IMAGE_MARKER = "/etc/dcentos/release-image"' \
    "$BR2_DIR/board/amlogic/rootfs-overlay/root/web/server.py" \
    || fail_test "amlogic :80 server.py lost the marker constant"
# L27 (2026-09-13) replaced the presence-only bearer check with the shared
# local-control gate: validated bearer (dcentrald first, then constant-time
# auth-file fallback), fail-closed on an unreadable auth file, TLS-only on
# release. Adjudicated TEST-STALE by DCENT_Security
#.
grep -q 'if not release_image() and not password_state_exists()' \
    "$BR2_DIR/board/zynq/rootfs-overlay/root/web/server.py" \
    || fail_test "zynq server.py lost the marker-keyed dev-open posture"
if [ "$(grep -c 'if not local_control_authorized(self.headers)' \
        "$BR2_DIR/board/zynq/rootfs-overlay/root/web/server.py")" -lt 4 ]; then
    fail_test "zynq server.py control endpoints drifted off local_control_authorized"
fi
grep -q 'return bearer_authorized_by_auth_file(auth_header)' \
    "$BR2_DIR/board/zynq/rootfs-overlay/root/web/server.py" \
    || fail_test "zynq server.py bearer fallback lost the validated auth-file gate"
grep -q 'if not local_control_authorized' \
    "$BR2_DIR/board/zynq/rootfs-overlay/root/web/server.py" \
    || fail_test "zynq server.py dashboard-local POST auth gate drifted"
grep -q 'RELEASE_MARKER="/etc/dcentos/release-image"' \
    "$BR2_DIR/board/zynq/rootfs-overlay/etc/init.d/S81mcp" \
    || fail_test "zynq S81mcp lost the marker gate (MCP autostart)"
grep -q 'RELEASE_MARKER="/etc/dcentos/release-image"' \
    "$BR2_DIR/board/amlogic/rootfs-overlay/etc/init.d/S81mcp" \
    || fail_test "amlogic S81mcp lost the marker gate (MCP autostart)"
grep -q 'RELEASE_IMAGE_MARKER' "$PROJECT_DIR/dcentrald/dcentrald-api/src/auth.rs" \
    || fail_test "dcentrald-api auth.rs lost the marker constant"
grep -q 'fn is_release_image' "$PROJECT_DIR/dcentrald/dcentrald-api/src/auth.rs" \
    || fail_test "dcentrald-api auth.rs lost is_release_image"
grep -q 'release-image' "$PROJECT_DIR/dcentrald/dcentrald-api-grpc/src/lib.rs" \
    || fail_test "dcentrald-api-grpc lost the marker read (MCP/gRPC write fail-closed)"
pass "auth surfaces (dashboard log/probe, dashboard-local POSTs, MCP autostart, daemon auth, gRPC) stay keyed on /etc/dcentos/release-image"

echo "release posture default tests passed"
