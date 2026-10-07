"""Run real R06 boot identity/S12 flow with a recording daemon and fake files."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

OVERLAY = Path(__file__).resolve().parents[1] / "br2_external_dcentos/board/zynq/bm1396/rootfs-overlay"
BOOT = "12345678-1234-1234-1234-123456789abc"
SHA = "39109da8ab92a08842141bd960d70987a47f368c9529c124540dce71c4098195"


@unittest.skipUnless(shutil.which("sh"), "POSIX shell required")
class BootStartupTests(unittest.TestCase):
    def execute(self, root, target, *, failed_load=False, cut_exit=0):
        def put(relative, value):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value, encoding="utf-8")
            return path

        put("etc/dcentos/board_target", target + "\n")
        put("etc/dcentos/bm1396-bitstream.sha256", SHA + "\n")
        put("proc/sys/kernel/random/boot_id", BOOT + "\n")
        put("proc/cmdline", f"dcent.bm1396_target={target} dcent.bm1396_sha256={SHA} "
                            f"dcent.bm1396_load_completed={0 if failed_load else 1}\n")
        put("sys/class/xdevcfg/xdevcfg/device/prog_done", "1\n")
        put("run/dcentos/bm1396-boot-cut-ready", "stale prior boot\n")
        helper = "usr/libexec/dcentos/bm1396-fabric-identity.sh"
        put(helper, (OVERLAY / helper).read_text(encoding="utf-8"))
        daemon = put("usr/bin/dcentrald", '''#!/bin/sh
set -eu
[ "$#" = 1 ] && [ "$1" = --bm1396-boot-cut-only ]
[ -s "$TEST_RUNTIME/bm1396-fabric.json" ]
[ ! -e "$TEST_RUNTIME/bm1396-boot-cut-ready" ]
printf '%s\n' "$1" > "$TEST_RUNTIME/cut-invoked"
exit "$TEST_CUT_EXIT"
''')
        daemon.chmod(0o755)
        text = (OVERLAY / "etc/init.d/S12fpga_identity").read_text(encoding="utf-8")
        text = re.sub(r"(?<![A-Za-z0-9_])/(?:etc|usr|run|proc|sys)(?=/)",
                      lambda match: str(root) + match.group(), text)
        script = put("start.sh", text)
        return subprocess.run(["sh", str(script), "start"], capture_output=True, text=True,
            env=dict(os.environ, TEST_RUNTIME=str(root / "run/dcentos"), TEST_CUT_EXIT=str(cut_exit)), timeout=5)

    def test_both_exact_targets_publish_current_boot_only_after_cut_command(self):
        for target in ("am2-s17e", "am2-t17e"):
            with self.subTest(target=target), tempfile.TemporaryDirectory(prefix="r06-start-") as temp:
                root = Path(temp)
                result = self.execute(root, target)
                self.assertEqual(result.returncode, 0, result.stderr)
                runtime = root / "run/dcentos"
                receipt = json.loads((runtime / "bm1396-fabric.json").read_text())
                self.assertEqual(receipt["board_target"], target)
                self.assertEqual(receipt["boot_id"], BOOT)
                self.assertEqual((runtime / "cut-invoked").read_text().strip(), "--bm1396-boot-cut-only")
                self.assertEqual((runtime / "bm1396-boot-cut-ready").read_text().strip(), BOOT)

    def test_failed_fabric_or_cut_cannot_retain_stale_ready_marker(self):
        for arguments in ({"failed_load": True}, {"cut_exit": 42}):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory(prefix="r06-start-") as temp:
                root = Path(temp)
                result = self.execute(root, "am2-s17e", **arguments)
                self.assertNotEqual(result.returncode, 0)
                runtime = root / "run/dcentos"
                self.assertFalse((runtime / "bm1396-boot-cut-ready").exists())
                self.assertEqual((runtime / "cut-invoked").exists(), "cut_exit" in arguments)


if __name__ == "__main__":
    unittest.main()
