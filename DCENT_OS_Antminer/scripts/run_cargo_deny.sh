#!/bin/sh
# Canonical local/CI daemon supply-chain gate; exact tools and --locked graph.
# Python 3.9/3.10: install scripts/requirements-supply-chain.txt first.
# To install reviewed Rust tools: run_cargo_deny.sh --install-tools
set -eu
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
exec python3 "$SCRIPT_DIR/daemon_supply_chain.py" "$@"
