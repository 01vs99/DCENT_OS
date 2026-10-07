#!/bin/sh
# Mandatory A126/Plus120 AML early gate. A failure leaves custom PID1 console-only.
# Mount only the existing qualified nvdata UBIFS; no format or repair fallback.
set -eu
exec /usr/bin/python3 -I /usr/libexec/dcentos/bm1362-nopic-storage.py early
