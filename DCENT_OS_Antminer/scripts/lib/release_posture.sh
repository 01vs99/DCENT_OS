#!/bin/sh
#
# release_posture.sh — canonical DCENT_OS image-posture resolution (WS-A4).
#
# D-Central Technologies, 2026.
#
# History: DCENT_RELEASE_IMAGE used to default to 0 (DEV) and release builds
# opted IN with DCENT_RELEASE_IMAGE=1. The 2026-08-19 Security review made
# DEV-default packaging a binding : the image that shipped by default
# carried root/dcentral, skip-password, MCP autostart, and unauthenticated
# dashboard-local surfaces. Per the operator's 2026-09-01 decision (T-OP-7,
# "ship RELEASE by default"), RELEASE is now the DEFAULT image posture:
#
#   * DCENT_RELEASE_IMAGE, when explicitly set to a non-empty value, ALWAYS
#     wins: a truthy spelling selects RELEASE, anything else selects DEV.
#     An explicit value can never be overridden by the lab alias below, so a
#     release driver can never be silently downgraded by a leaked lab
#     variable (the stricter posture wins on conflict).
#   * Otherwise DCENT_DEV_IMAGE=1 (truthy) selects the DEV/LAB posture.
#     DCENT_DEV_IMAGE=1 is the ONE canonical opt-out for dev/lab/bench
#     flows. (An explicit DCENT_RELEASE_IMAGE=0 remains a direct spelling of
#     the same opt-out.)
#   * Otherwise — nothing set — the posture is RELEASE (the shipped default).
#
# Every build-time reader of the image posture must resolve through these
# helpers (or a byte-identical inline copy — pinned by
# scripts/test_release_posture_default.sh) so the default cannot drift
# between the provision lib, prune hooks, packagers, and build drivers.
#
# Runtime daemons must NOT fork on these variables: they key off the
# /etc/dcentos/release-image marker stamped by release_image_provision.sh.
#
# POSIX sh only (BusyBox ash / Buildroot host sh). No bashisms.

dcent_release_posture_is_release() {
    if [ -n "${DCENT_RELEASE_IMAGE:-}" ]; then
        case "$DCENT_RELEASE_IMAGE" in
            1|true|TRUE|yes|YES|y|Y) return 0 ;;
            *) return 1 ;;
        esac
    fi
    case "${DCENT_DEV_IMAGE:-}" in
        1|true|TRUE|yes|YES|y|Y) return 1 ;;
    esac
    return 0
}

dcent_release_posture_value() {
    if dcent_release_posture_is_release; then
        echo 1
    else
        echo 0
    fi
}
