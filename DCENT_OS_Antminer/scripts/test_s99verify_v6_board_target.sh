#!/bin/sh
# Execute V6's board-target classification without opening hardware.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
python3 - "$root" <<'PY'
from pathlib import Path
import subprocess
import sys
root = Path(sys.argv[1])
for board in ("amlogic", "zynq", "beaglebone/am3-bb-s19jpro"):
    path = root / f"br2_external_dcentos/board/{board}/rootfs-overlay/etc/init.d/S99verify"
    source = path.read_text(encoding="utf-8")
    begin = source.index("check_pic_fw() {")
    body = source[begin:source.index("\n}", begin) + 2]
    for target, admitted in (("am3-s19k", True), ("am3-s21", True), ("am3-s19xp", True), ("am3-s19jproa", True), ("am3-unknown", False), ("am3-s19jpro-aml", False)):
        script = body + "\nPLATFORM=am3-aml\nboard_target=" + target + "\n" + """
python3() { return 1; }
emit_check() { printf '%s|%s|%s\\n' "$1" "$2" "$3"; }
gpio437_polarity_scope() { echo forbidden-polarity-inference; exit 97; }
check_pic_fw
"""
        result = subprocess.run(["sh"], input=script, text=True, capture_output=True, timeout=5)
        want = "V6|true|" if admitted else "V6|false|"
        assert result.returncode == 0 and result.stdout.startswith(want), (board, target, result)
print("PASS: all shipped V6 copies keep exact route classification separate from GPIO437 and require classic owner proof")
PY
