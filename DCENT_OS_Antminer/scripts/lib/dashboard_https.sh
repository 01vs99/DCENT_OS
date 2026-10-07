#!/bin/sh
# Stage the shared HTTPS frontend on the two AM335x images. The Amlogic
# frontend's manual-restart response preserves the existing BB service owner.
dcent_stage_bb_dashboard_https() {
    dcent_dashboard_target=$1
    dcent_dashboard_source="${BR2_EXTERNAL_DCENTOS_PATH}/board/amlogic/rootfs-overlay"
    for dcent_dashboard_path in root/web root/web/static etc/init.d; do
        mkdir -p "$dcent_dashboard_target/$dcent_dashboard_path"
    done
    for dcent_dashboard_file in root/web/server.py etc/init.d/S80dashboard; do
        install -m 0755 "$dcent_dashboard_source/$dcent_dashboard_file" \
            "$dcent_dashboard_target/$dcent_dashboard_file"
    done
    for dcent_dashboard_file in recovery.html diagnostic.html diagnostic-banner.js; do
        install -m 0644 "$dcent_dashboard_source/root/web/static/$dcent_dashboard_file" \
            "$dcent_dashboard_target/root/web/static/$dcent_dashboard_file"
    done
}
