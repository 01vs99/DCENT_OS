#!/usr/bin/env python3
"""Execute exact wrappers through their real shared target-selection branches."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parent.parent
BOARDS = PROJECT / "br2_external_dcentos/board"


class SharedPostImageTests(unittest.TestCase):
    def invoke(self, wrapper, board, *, native=False):
        with tempfile.TemporaryDirectory(prefix="post-image-target-") as temporary:
            root = Path(temporary)
            (root / "target/etc/dcentos").mkdir(parents=True)
            (root / "target/etc/dcentos/board_target").write_text(board + "\n", encoding="ascii")
            (root / "images").mkdir()
            env = {**os.environ, "TARGET_DIR": str(root / "target"), "BINARIES_DIR": str(root / "images"),
                   "BASE_DIR": str(root), "BR2_EXTERNAL_DCENTOS_PATH": str(PROJECT / "br2_external_dcentos")}
            env.pop("DCENT_NATIVE_SD_BOOT_INPUTS", None)
            if native:
                env["DCENT_NATIVE_SD_BOOT_INPUTS"] = str(root / "missing-pinned-inputs")
            shell = shutil.which("sh")
            if not shell:
                raise RuntimeError("POSIX shell is required for actual post-image wrappers")
            return subprocess.run([shell, "-x", str(BOARDS / wrapper / "post-image.sh")],
                                  env=env, capture_output=True, text=True, timeout=30)

    def test_amlogic_wrappers_dispatch_shared_builder(self):
        for board in ("am3-s21", "am3-s21pro", "am3-s21xp", "am3-t21"):
            with self.subTest(board=board):
                text = (BOARDS / "amlogic" / board / "post-image.sh").read_text()
                self.assertIn('exec sh "$SCRIPT_DIR/../post-image-family.sh" --board-target ', text)
                self.assertNotIn("mkimage", text)
                result = self.invoke("amlogic/" + board, board)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("rootfs.cpio.gz not found", result.stderr)
                self.assertNotIn("unadmitted or missing", result.stderr)

    def test_bound_amlogic_wrapper_refuses_foreign_root_before_payload(self):
        for wrapper in ("am3-s21pro", "am3-s21xp", "am3-t21"):
            with self.subTest(wrapper=wrapper):
                result = self.invoke("amlogic/" + wrapper, "am3-s21")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("differs from rootfs identity", result.stderr)
                self.assertNotIn("rootfs.cpio.gz not found", result.stderr)

    def test_unknown_amlogic_root_refused_by_existing_family_wrapper(self):
        result = self.invoke("amlogic/am3-s21", "am3-unknown")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unadmitted or missing", result.stderr)

    def test_exact_17_family_wrapper_roots_and_shared_geometry(self):
        for build, board in (("am2-s17pro", "am2-s17p"), ("am2-s17plus", "am2-s17plus"),
                             ("am2-t17", "am2-t17"), ("am2-t17plus", "am2-t17plus")):
            with self.subTest(board=board):
                text = (BOARDS / "zynq" / build / "post-image.sh").read_text()
                self.assertIn('post-image-17-family.sh" --board-target ' + board, text)
                self.assertNotIn("dcent_zynq_geometry_require_payload_fit", text)
        shared = (BOARDS / "zynq/post-image-17-family.sh").read_text()
        self.assertIn('dcent_zynq_geometry_require_payload_fit "$BOARD_NAME" rootfs "$ROOTFS_SIZE"', shared)
        self.assertIn('dcent_zynq_geometry_require_payload_fit "$BOARD_NAME" kernel "$KERNEL_SIZE"', shared)
        self.assertIn('DCENT_AM2_S17_BRAIINS_SD_IMAGE', shared)

    def test_already_stripped_runtime_excluded_from_buildroot_final_strip(self):
        fragment = (PROJECT / "br2_external_dcentos/configs/dcentos-common.fragment").read_text()
        self.assertIn('BR2_STRIP_EXCLUDE_FILES="dcentrald dcentos-init dcentos-discovery init"', fragment)


if __name__ == "__main__":
    unittest.main()
