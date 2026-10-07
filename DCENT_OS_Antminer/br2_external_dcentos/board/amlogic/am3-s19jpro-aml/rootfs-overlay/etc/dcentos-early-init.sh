#!/bin/sh
# Mandatory classic AML early gate. A failure leaves custom PID1 console-only.
# Mount only the existing qualified nvdata UBIFS; no format or repair fallback.
set -eu
exec /usr/bin/python3 -I /usr/libexec/dcentos/classic-aml-storage.py early
