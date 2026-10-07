#!/usr/bin/env python3
"""Run exact image admission/hooks with inert destinations and held donors."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
ROOT = PROJECT.parents[1]
BOARD = PROJECT / "br2_external_dcentos/board/amlogic"
PROFILES = {"am3-s19jproa": "s19jpro-a", "am3-s19jproplus": "s19jpro-plus"}


class ImageRecipes(unittest.TestCase):
    def test_new_directly_executed_hooks_have_linux_line_endings(self):
        for relative in ("am3-bm1362-nopic/post-build.sh", "am3-bm1362-nopic/post-image.sh",
                         "am3-s19jproa/post-image.sh", "am3-s19jproplus/post-image.sh",
                         "require-exact-build-inputs.sh"):
            data = (BOARD / relative).read_bytes()
            self.assertTrue(data.startswith(b"#!/bin/sh\n"), relative)
            self.assertNotIn(b"\r\n", data, relative)

    def test_actual_exact_donor_gate_accepts_only_its_model(self):
        gate = BOARD / "require-exact-build-inputs.sh"
        for target, model in PROFILES.items():
            donor = ROOT / "" / model / "vnishfarm-1.2.6-rc5-aml-nand-install"
            env = dict(os.environ, DCENT_AM3_AML_KERNEL=str(donor / "vmlinux.bin"),
                       DCENT_AM3_AML_DTB=str(donor / "devicetree.dtb"),
                       DCENT_AM3_AML_FW_INFO=str(donor / "rootfs/etc/fw-info"))
            command = ["/bin/sh", "-c", '. "$1"; dcent_require_exact_amlogic_build_inputs "$2"', "fixture", str(gate)]
            with self.subTest(target=target):
                result = subprocess.run(command + [target], env=env, text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("target=" + target + " model=" + model, result.stdout)
                wrong = next(other for other in PROFILES if other != target)
                result = subprocess.run(command + [wrong], env=env, text=True, capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("fw-info identity input", result.stderr)

    def test_post_build_requires_real_startup_files_before_delegating(self):
        source = BOARD / "am3-bm1362-nopic/post-build.sh"
        required = ("etc/dcentos-early-init.sh", "etc/init.d/S45persistent",
                    "usr/libexec/dcentos/bm1362-nopic-storage.py", "usr/sbin/ubiattach")
        for target in PROFILES:
            for omitted in (*required, None):
                with self.subTest(target=target, omitted=omitted), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    own = root / "board/am3-bm1362-nopic"
                    own.mkdir(parents=True)
                    shutil.copy2(source, own / "post-build.sh")
                    sibling = root / "board/am3-s21"
                    sibling.mkdir()
                    delegate = sibling / "post-build.sh"
                    delegate.write_text('#!/bin/sh\necho admitted > "$1/delegated"\n')
                    delegate.chmod(0o755)
                    destination = root / "target"
                    (destination / "etc/dcentos").mkdir(parents=True)
                    (destination / "etc/dcentos/board_target").write_text(target)
                    for name in required:
                        if name != omitted:
                            p = destination / name
                            p.parent.mkdir(parents=True, exist_ok=True)
                            p.write_text("#!/bin/sh\nexit 0\n")
                    result = subprocess.run(["/bin/sh", str(own / "post-build.sh"), str(destination)],
                                            text=True, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 0 if omitted is None else 1, result.stderr)
                    self.assertEqual((destination / "delegated").exists(), omitted is None)
                    if omitted is None:
                        self.assertTrue(all((destination / name).stat().st_mode & 0o777 == 0o755 for name in required))

    def test_recipe_layers_preserve_exact_product_and_boot_owner(self):
        for target in PROFILES:
            config = (PROJECT / "br2_external_dcentos/configs" / ("dcentos_" + target.replace("-", "_") + "_defconfig")).read_text()
            overlay = next(line for line in config.splitlines() if line.startswith("BR2_ROOTFS_OVERLAY="))
            self.assertLess(overlay.index("/am3-bm1362-nopic/"), overlay.index("/" + target + "/"))
            self.assertIn("BR2_PACKAGE_MTD_UBIATTACH=y", config)
            self.assertIn("/am3-bm1362-nopic/post-build.sh", config)
            self.assertIn("/" + target + "/post-image.sh", config)
            self.assertNotIn("am3-s19jpro-aml", config)

    def test_post_image_rejects_foreign_identity_before_tool_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "etc/dcentos").mkdir(parents=True)
            for target in ("am3-s21", "am3-s19jpro-aml", "am3-s19jproa-extra"):
                (root / "etc/dcentos/board_target").write_text(target)
                result = subprocess.run(["/bin/sh", str(BOARD / "am3-bm1362-nopic/post-image.sh")],
                                        env=dict(os.environ, TARGET_DIR=str(root), BINARIES_DIR=str(root / "absent")),
                                        text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 1)
                self.assertIn("exact A126/Plus120 post-image target required", result.stderr)
                self.assertFalse((root / "absent").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
