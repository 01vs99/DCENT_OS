#!/bin/sh
# Exercise the installed Toolbox feed consumer against real signed fixtures.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 -m pytest -q "$SCRIPT_DIR/../../dcent-toolbox/tests/test_channel_feed.py"
