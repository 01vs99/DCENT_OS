#!/usr/bin/env python3
"""Run the actual S99 script against disposable paths and inert NAND tools."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S99upgrade"


class ClassicUpgradeGate(unittest.TestCase):
    def test_inherited_pending_marker_cannot_authorize_legacy_env_or_nand_access(self):
        with tempfile.TemporaryDirectory(prefix="classic-upgrade-gate-") as temporary:
            root = Path(temporary)
            binaries = root / "bin"
            binaries.mkdir()
            for command in ("fw_printenv", "fw_setenv", "nanddump", "nandwrite", "flash_erase"):
                tool = binaries / command
                tool.write_text('#!/bin/sh\nprintf "%s %s\\n" "${0##*/}" "$*" >> "$CALLS"\nexit 1\n')
                tool.chmod(0o755)
            # mtd5 exists only as an inert regular fixture; none of the command
            # doubles opens it. Real NAND helpers are never invoked.
            (root / "mtd5").touch()
            (root / "pending").touch()
            (root / "target").write_text("am3-s19jpro-aml\n")
            (root / "platform").write_text("am3-aml-s19jpro\n")
            script = SCRIPT.read_text(encoding="utf-8").replace(
                "/lib/functions/system.sh", str(root / "absent-system.sh"))
            environment = dict(os.environ, PATH=str(binaries) + ":/usr/bin:/bin",
                               CALLS=str(root / "calls"),
                               DCENTOS_SYSTEM_MTD=str(root / "mtd5"),
                               DCENTOS_LOCAL_RECOVERY_FLAGS_OFFSET="0x0",
                               DCENTOS_BOARD_TARGET_FILE=str(root / "target"),
                               DCENTOS_PLATFORM_FILE=str(root / "platform"),
                               DCENTOS_MUTATION_POLICY_FILE=str(root / "absent-policy"),
                               DCENTOS_FIRSTBOOT_PENDING_FILE=str(root / "pending"))
            result = subprocess.run(["/bin/sh", "-c", script, "S99upgrade", "start"],
                                    env=environment, capture_output=True, text=True, timeout=5)
            calls = (root / "calls").read_text() if (root / "calls").exists() else ""
            self.assertEqual(calls, "", result.stdout + result.stderr + calls)
            self.assertEqual(result.returncode, 1)
            self.assertTrue((root / "pending").exists(), "unsupported legacy intent must not be consumed")
            self.assertIn("Classic AML", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
