#!/bin/sh
# Nightly process integration: compile once, then exercise only isolated views.
# Caller serializes this command with other heavy jobs through the shared lock.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR/.."

cargo +1.90.0 build --offline --locked -j2 --manifest-path dcentrald/Cargo.toml -p dcentrald --bin dcentrald
target_dir=$(cargo +1.90.0 metadata --offline --locked --no-deps --format-version 1 --manifest-path dcentrald/Cargo.toml | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')
if [ "$(id -u)" -eq 0 ]; then
    python3 scripts/test_software_closeout_integration.py --daemon "$target_dir/debug/dcentrald"
else
    # The private user namespace supplies fixture-local root ownership and
    # mount capability without elevating the invoking user on the host.
    unshare --user --map-root-user -- python3 scripts/test_software_closeout_integration.py --daemon "$target_dir/debug/dcentrald"
fi
