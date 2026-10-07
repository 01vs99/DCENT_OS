#!/bin/sh
set -eu
cd "$(dirname "$0")"
flock /tmp/dcent-heavy.lock python3 -m unittest -q test_amlogic_seven_mtd_package test_classic_aml_signed_entry test_classic_aml_sd_fit test_vnish_bm1362_voltage
bash -n ../br2_external_dcentos/board/amlogic/am3-bm1362-nopic/post-image.sh
bash -n ../br2_external_dcentos/board/amlogic/am3-s19jpro-aml/post-image.sh
