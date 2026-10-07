#!/usr/bin/env python3
"""Execute C43 early-init control flow against bounded fake sysfs/mount owners.

The shell script is unchanged except absolute paths are redirected into a
temporary fixture. mount/mknod/ip are recording shims; no real devices/mounts
are touched. Real shell, dd/hexdump, UUID and read-only-root checks execute.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid

OVERLAY = Path(__file__).resolve().parents[1] / "br2_external_dcentos/board/zynq/c43/rootfs-overlay"
ROOT_UUID = "d362a466-39dc-4208-b7fd-203de7d7ad4a"
DATA_UUID = "cc62df83-522e-43c1-89ac-ed13c4edc30a"


@unittest.skipUnless(shutil.which("sh") and shutil.which("hexdump"), "POSIX shell/hexdump unavailable")
class C43EarlyInitTests(unittest.TestCase):
    def execute(self, root, *, wrong_uuid=False, fail_mount=False, writable_root=False):
        for relative in ("etc/dcentos", "dev", "proc/sys/kernel/random", "sys/class/tty/ttyPS0",
                         "sys/class/watchdog/watchdog0", "tmp", "run", "data", "root", "bin"):
            (root / relative).mkdir(parents=True, exist_ok=True)
        (root / "etc/dcentos/board_target").write_text("am1-s9se\n")
        (root / "etc/hostname").write_text("dcentos-s9se\n")
        (root / "etc/dcentos/c43-root-uuid").write_text(ROOT_UUID + "\n")
        (root / "etc/dcentos/c43-data-uuid").write_text(DATA_UUID + "\n")
        (root / "proc/mounts").write_text(f"/dev/mmcblk0p2 / ext2 {'rw' if writable_root else 'ro'},relatime 0 0\n")
        (root / "sys/class/tty/ttyPS0/dev").write_text("253:0\n")
        (root / "sys/class/watchdog/watchdog0/dev").write_text("250:0\n")
        for index in range(4):
            name = "mmcblk0" + (f"p{index}" if index else "")
            path = root / "sys/class/block" / name
            path.mkdir(parents=True)
            (path / "dev").write_text(f"179:{index}\n")
            block = bytearray(4096)
            block[1080:1082] = b"\x53\xef"
            if index in (2, 3):
                block[1128:1144] = uuid.UUID(ROOT_UUID if index == 2 else DATA_UUID).bytes
                if wrong_uuid and index == 3:
                    block[1128] ^= 1
            (root / "dev" / name).write_bytes(block)
        shims = {
            "mknod": '#!/bin/sh\nprintf "mknod %s\\n" "$*" >> "$TEST_TRACE"\n'
                      '# Preserve the preloaded block fixtures; chars are plain files.\n'
                      '[ "$4" = b ] || : > "$3"\n',
            "mount": '#!/bin/sh\nprintf "mount %s\\n" "$*" >> "$TEST_TRACE"\n'
                     'case "$*" in *mmcblk0p3*) [ "$TEST_FAIL_MOUNT" != 1 ] || exit 1 ;; esac\nexit 0\n',
            "ip": '#!/bin/sh\nprintf "ip %s\\n" "$*" >> "$TEST_TRACE"\nexit 0\n',
            "hostname": '#!/bin/sh\nprintf "hostname %s\\n" "$*" >> "$TEST_TRACE"\nexit 0\n',
        }
        for name, text in shims.items():
            path = root / "bin" / name
            path.write_text(text)
            path.chmod(0o755)
        source = (OVERLAY / "etc/dcentos-early-init.sh").read_text()
        # Longest/specific paths first; each replacement introduces only a
        # temporary prefix, so it cannot match another listed absolute prefix.
        import re
        source = re.sub(r"(?<![A-Za-z0-9_])/(?:etc|dev|proc|sys|tmp|run|data|root|usr)(?=/|\s|\"|$)",
                        lambda match: str(root) + match.group(), source)
        script = root / "early-init.sh"
        script.write_text(source)
        env = dict(os.environ, PATH=str(root / "bin") + os.pathsep + os.environ["PATH"],
                   TEST_TRACE=str(root / "trace"), TEST_FAIL_MOUNT="1" if fail_mount else "0")
        result = subprocess.run(["sh", str(script)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        trace = (root / "trace").read_text()
        return result, trace

    def test_actual_shell_starts_only_with_exact_sd_uuids_and_readonly_root(self):
        with tempfile.TemporaryDirectory(prefix="c43-init-") as temp:
            root = Path(temp)
            result, trace = self.execute(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "run/dcentos/c43-sd-data-ready").read_text().strip(), DATA_UUID)
            self.assertIn("mmcblk0p3", trace)
            self.assertIn("mount --bind", trace)
            self.assertIn(f"mknod -m 666 {root}/dev/ptmx c 5 2", trace)
            self.assertIn("hostname dcentos-s9se", trace)
            self.assertNotIn("mtd", trace)
            self.assertNotIn("ubi", trace)
            self.assertNotIn("i2c", trace)
            self.assertTrue((root / "data/dcent").is_dir())

    def test_wrong_uuid_or_writable_root_never_mounts_persistent_data(self):
        for parameters in ({"wrong_uuid": True}, {"writable_root": True}):
            with self.subTest(parameters=parameters), tempfile.TemporaryDirectory(prefix="c43-init-") as temp:
                root = Path(temp)
                result, trace = self.execute(root, **parameters)
                self.assertEqual(result.returncode, 81, result.stderr)
                self.assertNotIn("mount -t ext4", trace)
                self.assertFalse((root / "run/dcentos/c43-sd-data-ready").exists())

    def test_data_mount_failure_has_no_ready_receipt_or_volatile_data_fallback(self):
        with tempfile.TemporaryDirectory(prefix="c43-init-") as temp:
            root = Path(temp)
            result, trace = self.execute(root, fail_mount=True)
            self.assertEqual(result.returncode, 82, result.stderr)
            self.assertNotIn("mount --bind", trace)
            self.assertFalse((root / "run/dcentos/c43-sd-data-ready").exists())
            self.assertFalse((root / "data/dcent").exists())


if __name__ == "__main__":
    unittest.main()
