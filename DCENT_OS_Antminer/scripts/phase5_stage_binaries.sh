#!/usr/bin/env bash
# Phase 5: stage pre-built binaries into the Buildroot volume.
# Extracted verbatim from build_in_docker.sh (2026-09-14): delivered as a
# volume file so the multiline script never crosses the Windows
# docker.exe argv quoting seam.

        set -eu
        case "$BUILD_ARCH" in
            armv7-unknown-linux-musleabihf|aarch64-unknown-linux-musl) ;;
            *) echo "ERROR: unsafe BUILD_ARCH for binary staging: $BUILD_ARCH" >&2; exit 1 ;;
        esac
        release_dir=/build
        [ -d "$release_dir" ] && [ ! -L "$release_dir" ] || {
            echo "ERROR: Docker volume root is not a real directory" >&2
            exit 1
        }
        for component in projects dcentos dcentrald target "$BUILD_ARCH" release; do
            next="$release_dir/$component"
            [ -d "$next" ] && [ ! -L "$next" ] || {
                echo "ERROR: unsafe persistent binary staging component: $next" >&2
                exit 1
            }
            release_dir="$next"
        done
        for binary_name in $REQUIRED_BINARIES; do
            case "$binary_name" in
                dcentrald)
                    relative_path="$DCENTRALD_EXPORT_PATH"
                    expected_sha256="$DCENTRALD_EXPORT_SHA256"
                    ;;
                dcentos-init)
                    relative_path="$INIT_EXPORT_PATH"
                    expected_sha256="$INIT_EXPORT_SHA256"
                    ;;
                dcentos-discovery)
                    relative_path="$DISCOVERY_EXPORT_PATH"
                    expected_sha256="$DISCOVERY_EXPORT_SHA256"
                    ;;
                *) echo "ERROR: unsafe required binary name: $binary_name" >&2; exit 1 ;;
            esac
            case "$relative_path" in
                artifacts/[0-9][0-9][0-9][0-9]/"$binary_name") ;;
                *) echo "ERROR: unsafe exported path for $binary_name" >&2; exit 1 ;;
            esac
            case "$expected_sha256" in
                *[!0-9a-f]*|'') echo "ERROR: malformed SHA256 for $binary_name" >&2; exit 1 ;;
            esac
            [ "${#expected_sha256}" -eq 64 ] || {
                echo "ERROR: non-64-byte SHA256 for $binary_name" >&2
                exit 1
            }
            source_path="/dcent-binaries/$relative_path"
            destination="$release_dir/$binary_name"
            [ -f "$source_path" ] && [ ! -L "$source_path" ] || {
                echo "ERROR: exported source is missing or linked: $source_path" >&2
                exit 1
            }
            [ ! -e "$destination" ] && [ ! -L "$destination" ] || {
                echo "ERROR: binary destination unexpectedly exists: $destination" >&2
                exit 1
            }
            source_sha256="$(sha256sum "$source_path" | cut -d" " -f1)"
            [ "$source_sha256" = "$expected_sha256" ] || {
                echo "ERROR: exported source digest mismatch for $binary_name" >&2
                exit 1
            }
            install -m 0755 "$source_path" "$destination"
            destination_sha256="$(sha256sum "$destination" | cut -d" " -f1)"
            [ "$destination_sha256" = "$expected_sha256" ] || {
                echo "ERROR: installed destination digest mismatch for $binary_name" >&2
                exit 1
            }
            file "$destination"
            ls -lh "$destination"
        done
        # W1.2 (2026-05-07): when a manifest pubkey was pinned, prove it is
        # actually embedded in the prebuilt binary. dcentrald-api uses
        # `option_env!("DCENT_MANIFEST_PUBLIC_KEY_HEX")` which only embeds
        # the hex string when the env var was set during `cargo build`. If
        # the build host did not export the same hex used here, the binary
        # silently falls back to fail-open. `strings | grep` catches that.
        if [ -n "${DCENT_MANIFEST_PUBLIC_KEY_HEX:-}" ]; then
            BIN_PATH="/build/DCENT_OS_Antminer/dcentrald/target/$BUILD_ARCH/release/dcentrald"
            if strings "$BIN_PATH" | grep -qF "$DCENT_MANIFEST_PUBLIC_KEY_HEX"; then
                echo "  manifest pubkey pin embedded in dcentrald binary (verified via strings)"
            else
                echo "ERROR: DCENT_MANIFEST_PUBLIC_KEY_HEX is set in this build environment" >&2
                echo "       but the prebuilt dcentrald binary does NOT contain that hex" >&2
                echo "       string — the binary was likely cargo-built without the env" >&2
                echo "       var exported. Re-run cargo build with the pin set:" >&2
                echo "       export DCENT_MANIFEST_PUBLIC_KEY_HEX=<hex64>" >&2
                echo "       cargo build --release --target $BUILD_ARCH" >&2
                exit 1
            fi
        fi
        # W13.C4: variant TARGET arms (W10) need version-stamp dispatch.
        # Without these, dcentrald version stamp is silently skipped on
        # these variants (the wildcard `*)` falls through to "" and the
        # `dcent_require_dcentrald_version_match` call below is bypassed),
        # so a stale binary in the variant overlay would ship to
        # sysupgrade tarballs unnoticed.
        case "$TARGET" in
            s9|am1-s9i|am1-s9j|am1-s15|am1-t15|am2-t17e|am2-s17e) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/rootfs-overlay" ;;
            # DEVOPS-011 (2026-06-02): am2-s19jpro-sd reuses the am2-s19jpro
            # defconfig + rootfs-overlay (only the post-image differs — it emits
            # a flashable .img instead of a sysupgrade .tar). Without this arm it
            # fell through to the wildcard "" and the dcentrald version-match
            # gate was silently skipped, so a stale binary in the shared
            # am2-s19jpro overlay could ship in the SD image unnoticed (same
            # W13.C4 hazard the other variants close). Point it at the same
            # overlay the SD build actually stages from.
            am2-s19jpro|am2-s19jpro-sd|am2-s19|am2-t19|am2-s19a|am2-s19plus) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay" ;;
            # Added by Phase 2K — without these am2-s19pro / am2-s17pro fall
            # through to the wildcard "" and the version-match gate is
            # silently skipped, shipping a stale binary in the variant
            # overlay unnoticed (same W13.C4 hazard as the am3 variants).
            am2-s19pro) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-s19pro/rootfs-overlay" ;;
            am2-s17pro) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay" ;;
            am2-s17plus) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-s17plus/rootfs-overlay" ;;
            am2-t17) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-t17/rootfs-overlay" ;;
            am1-s9se) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am1-s9se/rootfs-overlay" ;;
            am1-s9k) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am1-s9k/rootfs-overlay" ;;
            am2-t17plus) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-t17plus/rootfs-overlay" ;;
            # End Phase 2K
            am3-s19kpro) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19kpro/rootfs-overlay" ;;
            am3-s19kpro-nopic) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19kpro-nopic/rootfs-overlay" ;;
            am3-s19xp) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19xp/rootfs-overlay" ;;
            am3-s19jxp) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19jxp/rootfs-overlay" ;;
            am3-s19jproa) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19jproa/rootfs-overlay" ;;
            am3-s19jproplus) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19jproplus/rootfs-overlay" ;;
            am3-s21) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s21/rootfs-overlay" ;;
            am3-s21pro) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s21pro/rootfs-overlay" ;;
            am3-s21xp) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s21xp/rootfs-overlay" ;;
            # Added by Phase 4B
            am3-s19jpro-aml) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19jpro-aml/rootfs-overlay" ;;
            am3-t21) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-t21/rootfs-overlay" ;;
            # End Phase 4B
            am3-bb) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/beaglebone/am3-bb/rootfs-overlay" ;;
            am3-bb-s19jpro|am3-bb-s19jpro-payload|am3-bb-s19jpro-vnish) VERSION_TARGET_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/board/beaglebone/am3-bb-s19jpro/rootfs-overlay" ;;
            *) VERSION_TARGET_DIR="" ;;
        esac
        if [ -n "$VERSION_TARGET_DIR" ]; then
            . /build/DCENT_OS_Antminer/scripts/lib/dcentrald_version_gate.sh
            dcent_require_dcentrald_version_match \
                "$VERSION_TARGET_DIR" \
                "/build/DCENT_OS_Antminer/dcentrald/target/$BUILD_ARCH/release/dcentrald" \
                "build_in_docker Phase 5 ($TARGET)" \
                "/build/DCENT_OS_Antminer/dcentrald/Cargo.toml"
        fi

