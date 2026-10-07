#!/usr/bin/env python3
"""Run exact S19k Pro image admission/hooks with inert destinations and held donors."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
ROOT = PROJECT.parents[1]
BOARD = PROJECT / "br2_external_dcentos/board/amlogic"
TARGET = "am3-s19kpro-nopic"
DONOR = ROOT / (""
                "vnish-1.2.7-s19kpro-aml-nand-v1.2.7-install")
LEGACY_DONOR = (ROOT / ""
                "vnishfarm-1.2.6-rc5-aml-nand-install")


class ImageRecipes(unittest.TestCase):
    def test_new_directly_executed_hooks_have_linux_line_endings(self):
        for relative in ("am3-s19kpro-nopic/post-build.sh", "am3-s19kpro-nopic/post-image.sh",
                         "am3-s19kpro-nopic/rootfs-overlay/etc/dcentos-early-init.sh",
                         "am3-s19kpro-nopic/rootfs-overlay/etc/init.d/S45persistent",
                         "require-exact-build-inputs.sh"):
            data = (BOARD / relative).read_bytes()
            self.assertTrue(data.startswith(b"#!/bin/sh\n"), relative)
            self.assertNotIn(b"\r\n", data, relative)

    def test_actual_exact_donor_gate_accepts_only_the_s19k_127_donor(self):
        gate = BOARD / "require-exact-build-inputs.sh"
        command = ["/bin/sh", "-c", '. "$1"; dcent_require_exact_amlogic_build_inputs "$2"',
                   "fixture", str(gate)]
        for donor, target, expected in (
                (DONOR, TARGET, True),
                (LEGACY_DONOR, TARGET, False),
                # The legacy vnishfarm 1.2.6-rc5 s19kpro arm keeps its own
                # identity; the vnish 1.2.7 donor cannot feed it.
                (DONOR, "am3-s19kpro", False),
                (DONOR, "am3-s19jproa", False)):
            with self.subTest(donor=donor.name, target=target, expected=expected):
                env = dict(os.environ, DCENT_AM3_AML_KERNEL=str(donor / "vmlinux.bin"),
                           DCENT_AM3_AML_DTB=str(donor / "devicetree.dtb"),
                           DCENT_AM3_AML_FW_INFO=str(donor / "rootfs/etc/fw-info"))
                result = subprocess.run(command + [target], env=env, text=True,
                                        capture_output=True, timeout=10)
                if expected:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("target=" + target + " model=s19kpro", result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("fw-info identity input", result.stderr + result.stdout)

    def test_donor_kernel_dtb_and_nvdata_scripts_match_the_reviewed_aml_bytes(self):
        import hashlib
        pinned = {
            "vmlinux.bin": "d5013ac9f545df3b0792ea2cd8902b51e323bbb6f73ff0fea17bbee9f6157fe6",
            "devicetree.dtb": "540c1770543d9620e106ea4287c2a534f5efd85c912e97d6be6295930506b257",
            "rootfs/etc/inittab": "24b024463df9bfee34f768e6322552fed79fc83e204ee7870cbe04e343314dc6",
            "rootfs/etc/init.d/S03mount": "adf7c86a79ee28f908f39e1739f2bd90cbbddcaad9bd94a464571055820a0fb9",
            "rootfs/etc/fw-info": "e9a976cef48abced73e240afbd70d7c15310f7fe65c1d83b9910d1545b0bec0a",
        }
        for name, expected in pinned.items():
            digest = hashlib.sha256((DONOR / name).read_bytes()).hexdigest()
            self.assertEqual(digest, expected, name)

    def test_post_build_requires_real_startup_files_before_delegating(self):
        source = BOARD / "am3-s19kpro-nopic/post-build.sh"
        required = ("etc/dcentos-early-init.sh", "etc/init.d/S45persistent",
                    "usr/libexec/dcentos/s19kpro-nopic-storage.py", "usr/sbin/ubiattach")
        for omitted in (*required, None):
            with self.subTest(omitted=omitted), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                own = root / "board/am3-s19kpro-nopic"
                own.mkdir(parents=True)
                shutil.copy2(source, own / "post-build.sh")
                sibling = root / "board/am3-s21"
                sibling.mkdir()
                delegate = sibling / "post-build.sh"
                delegate.write_text('#!/bin/sh\necho admitted > "$1/delegated"\n')
                delegate.chmod(0o755)
                destination = root / "target"
                (destination / "etc/dcentos").mkdir(parents=True)
                (destination / "etc/dcentos/board_target").write_text("am3-s19kpro")
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
                    self.assertTrue(all((destination / name).stat().st_mode & 0o777 == 0o755
                                        for name in required))

    def test_post_build_refuses_foreign_identity_before_delegating(self):
        source = BOARD / "am3-s19kpro-nopic/post-build.sh"
        for target in ("am3-s19k", "am3-s19jproa", "am3-s19jproplus", "am3-s19kpro-extra"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                own = root / "board/am3-s19kpro-nopic"
                own.mkdir(parents=True)
                shutil.copy2(source, own / "post-build.sh")
                destination = root / "target"
                (destination / "etc/dcentos").mkdir(parents=True)
                (destination / "etc/dcentos/board_target").write_text(target)
                result = subprocess.run(["/bin/sh", str(own / "post-build.sh"), str(destination)],
                                        text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 1)
                self.assertIn("exact S19k Pro target required", result.stderr)

    def test_recipe_layers_preserve_exact_product_and_boot_owner(self):
        config = (PROJECT / "br2_external_dcentos/configs"
                  / "dcentos_am3_s19kpro_nopic_defconfig").read_text()
        overlay = next(line for line in config.splitlines() if line.startswith("BR2_ROOTFS_OVERLAY="))
        # Product identity comes last; the S19k NoPIC boot owner is the
        # separate am3-s19kpro-nopic dir, not the A126/Plus120 shared one.
        self.assertLess(overlay.index("/board/common/rootfs-overlay"), overlay.index("/board/amlogic/rootfs-overlay"))
        self.assertLess(overlay.index("/board/amlogic/rootfs-overlay"), overlay.index("/am3-s19kpro-nopic/"))
        self.assertNotIn("am3-bm1362-nopic", config)
        self.assertIn("BR2_PACKAGE_MTD_UBIATTACH=y", config)
        self.assertIn("/am3-s19kpro-nopic/post-build.sh", config)
        self.assertIn("/am3-s19kpro-nopic/post-image.sh", config)
        # The legacy am3-s19k runtime overlay lane stays out of this image.
        self.assertNotIn("am3-s19kpro/rootfs-overlay", config)
        self.assertNotIn("am3-s19jpro-aml", config)

    def test_identity_markers_are_the_exact_s19k_nopic_pair(self):
        overlay = BOARD / "am3-s19kpro-nopic/rootfs-overlay"
        self.assertEqual((overlay / "etc/dcentos/board_target").read_text().strip(), "am3-s19kpro")
        for name in ("etc/dcentos-platform", "etc/dcentos/board_family"):
            self.assertEqual((overlay / name).read_text().strip(), "am3-aml-s19kpro", name)
        self.assertEqual((overlay / "etc/dcentos/rail_gpio").read_text().strip(), "437")
        policy = (overlay / "etc/dcentos/mutation_policy").read_text().splitlines()
        self.assertIn("boot-safeoff", policy)
        self.assertIn("daemon-hardware", policy)
        self.assertNotIn("ota-storage", policy)
        self.assertEqual((overlay / "etc/dcentos-version").read_text().strip(), "0.9.0")

    def test_post_image_rejects_foreign_identity_before_tool_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "etc/dcentos").mkdir(parents=True)
            for target in ("am3-s21", "am3-s19jpro-aml", "am3-s19jproa",
                           "am3-s19k", "am3-s19kpro-extra"):
                (root / "etc/dcentos/board_target").write_text(target)
                result = subprocess.run(["/bin/sh", str(BOARD / "am3-s19kpro-nopic/post-image.sh")],
                                        env=dict(os.environ, TARGET_DIR=str(root), BINARIES_DIR=str(root / "absent")),
                                        text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 1)
                self.assertIn("exact S19k Pro post-image target required", result.stderr)
                self.assertFalse((root / "absent").exists())

    def test_storage_owner_readiness_path_is_s19k_distinct(self):
        helper = (BOARD / "am3-s19kpro-nopic/rootfs-overlay/usr/libexec/dcentos/"
                  "s19kpro-nopic-storage.py").read_text(encoding="utf-8")
        self.assertIn('READY = "/run/dcentos/s19kpro-nopic-storage-ready.json"', helper)
        self.assertIn('profiles = {"am3-s19kpro": "am3-aml-s19kpro"}', helper)
        self.assertNotIn("am3-s19jproa", helper)


if __name__ == "__main__":
    unittest.main(verbosity=2)
