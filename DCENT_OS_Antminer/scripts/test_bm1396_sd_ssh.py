#!/usr/bin/env python3
"""Execute SD key provisioning and the actual shared SSH gate without a server."""
from __future__ import annotations

import base64
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ZYNQ = Path(__file__).resolve().parents[1] / "br2_external_dcentos/board/zynq"
OVERLAY = ZYNQ / "bm1396/rootfs-overlay"
DATA_UUID = "cc62df83-522e-43c1-89ac-ed13c4edc30a"
# A public-key wire record, not a credential/private signing key.
KEY = "ssh-ed25519 " + base64.b64encode(bytes.fromhex("0000000b") + b"ssh-ed25519" + bytes.fromhex("00000020") + bytes(range(32))).decode()


@unittest.skipUnless(shutil.which("sh"), "POSIX shell unavailable")
class Bm1396SshTests(unittest.TestCase):
    TARGET = "am2-s17e"

    def fixture(self, root):
        for relative in ("etc/dcentos", "etc/default", "etc/dropbear", "run/dcentos", "run/bm1396-boot", "data/dcent", "root", "var/run", "bin"):
            (root / relative).mkdir(parents=True, exist_ok=True)
        (root / "etc/dcentos/board_target").write_text(self.TARGET + "\n")
        (root / "etc/dcentos/bm1396-data-uuid").write_text(DATA_UUID + "\n")
        (root / "run/dcentos/bm1396-sd-data-ready").write_text(DATA_UUID + "\n")
        (root / "etc/dcentos/release-image").write_text("release_image=1\n")
        (root / "etc/default/dropbear").write_text('DROPBEAR_ARGS="-s"\n')
        for name in ("mount", "umount", "sync", "logger"):
            path = root / "bin" / name
            path.write_text('#!/bin/sh\nprintf "%s %s\\n" "${0##*/}" "$*" >> "$TEST_TRACE"\nexit 0\n')
            path.chmod(0o755)

    def execute(self, root, source, argument="start"):
        text = source.read_text(encoding="utf-8")
        text = re.sub(r"(?<![A-Za-z0-9_])/(?:etc|dev|proc|sys|tmp|run|data|root|usr|var)(?=/|\s|\"|$)",
                      lambda match: str(root) + match.group(), text)
        script = root / source.name
        script.write_text(text)
        env = dict(os.environ, PATH=str(root / "bin") + os.pathsep + os.environ["PATH"], TEST_TRACE=str(root / "trace"))
        return subprocess.run(["sh", str(script), argument], env=env, capture_output=True, text=True, timeout=5)

    def provision(self, root):
        result = self.execute(root, OVERLAY / "etc/init.d/S46bm1396_ssh")
        self.assertEqual(result.returncode, 0, result.stderr)

    def gate(self, root):
        result = self.execute(root, ZYNQ / "rootfs-overlay/etc/init.d/S50dropbear", "status")
        self.assertEqual(result.returncode, 3, result.stderr)
        return result.stdout

    def test_public_key_is_persisted_and_dropbear_reads_it_across_reboots(self):
        with tempfile.TemporaryDirectory(prefix="bm1396-ssh-") as temp:
            root = Path(temp)
            self.fixture(root)
            (root / "run/bm1396-boot/DCENT_SSH_KEY.pub").write_text(KEY + " tester@example\r\n")
            self.provision(root)
            self.assertEqual((root / "data/dcent/authorized_keys").read_text(), KEY + "\n")
            self.assertEqual((root / "root/.ssh/authorized_keys").read_text(), KEY + "\n")
            self.assertEqual((root / "data/dcent/authorized_keys").stat().st_mode & 0o777, 0o600)
            self.assertIn("enabled-by-keys", self.gate(root))
            trace = (root / "trace").read_text()
            self.assertIn("mount -t vfat -o ro,nodev,nosuid,noexec", trace)
            self.assertNotIn("nand", trace)
            # A new boot gets fresh /root; changing the FAT key does not replace
            # the already provisioned operator identity in persistent SD data.
            shutil.rmtree(root / "root/.ssh")
            (root / "run/bm1396-boot/DCENT_SSH_KEY.pub").write_text("untrusted replacement\n")
            self.provision(root)
            self.assertEqual((root / "root/.ssh/authorized_keys").read_text(), KEY + "\n")

    def test_missing_malformed_or_option_prefixed_key_does_not_open_ssh(self):
        for content in (None, "invalid\n", 'command="id" ' + KEY, KEY.replace("AAAAC3", "BAAAC3"), KEY + "\ninvalid\n"):
            with self.subTest(content=content), tempfile.TemporaryDirectory(prefix="bm1396-ssh-") as temp:
                root = Path(temp)
                self.fixture(root)
                if content is not None:
                    (root / "run/bm1396-boot/DCENT_SSH_KEY.pub").write_text(content)
                self.provision(root)
                self.assertFalse((root / "data/dcent/authorized_keys").exists())
                self.assertFalse((root / "data/dcent/.ssh-enabled").exists())
                self.assertIn("locked-release-image", self.gate(root))

    def test_data_ownership_and_explicit_operator_disable_are_preserved(self):
        with tempfile.TemporaryDirectory(prefix="bm1396-ssh-") as temp:
            root = Path(temp)
            self.fixture(root)
            (root / "run/bm1396-boot/DCENT_SSH_KEY.pub").write_text(KEY)
            (root / "run/dcentos/bm1396-sd-data-ready").write_text("wrong-owner")
            result = self.execute(root, OVERLAY / "etc/init.d/S46bm1396_ssh")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "data/dcent/authorized_keys").exists())
            (root / "run/dcentos/bm1396-sd-data-ready").write_text(DATA_UUID)
            (root / "data/dcent/.ssh-disabled").touch()
            self.provision(root)
            self.assertIn("disabled-by-opt-out", self.gate(root))


class Bm1396SshT17eTests(Bm1396SshTests):
    TARGET = "am2-t17e"


if __name__ == "__main__":
    unittest.main()
