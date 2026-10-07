#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Host launcher for the toolbox's pinned-unit, resumable SSH stock restore.

This file never opens local hardware. The toolbox orchestrator checks its exact
SHA-256 and executes a private snapshot with the current Python interpreter.
"""
from dcent_toolbox.cli.stock_revert import main

if __name__ == "__main__":
    raise SystemExit(main())
