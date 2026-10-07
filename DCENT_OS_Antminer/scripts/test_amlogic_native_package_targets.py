#!/usr/bin/env python3
"""Offline evidence and fail-closed contract tests for new A113D packages."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest


PROJECT = Path(__file__).resolve().parents[1]
REPO = PROJECT.parents[1]
VNISH = REPO / "knowledge-base" / "extractions" / "vnish-farm"

TARGETS = {
    "s19jpro-plus": (
        "Antminer S19j Pro+",
        "am3-s19jproplus",
        "dcentos_am3_s19jproplus_defconfig",
        "s19jproplus",
    ),
    "s19xp": (
        "Antminer S19 XP",
        "am3-s19xp",
        "dcentos_am3_s19xp_defconfig",
        "s19xp",
    ),
    "s19j-xp": (
        "Antminer S19j XP",
        "am3-s19jxp",
        "dcentos_am3_s19jxp_defconfig",
        "s19jxp",
    ),
}

SHARED_VMLINUX_SHA256 = (
    "d5013ac9f545df3b0792ea2cd8902b51e323bbb6f73ff0fea17bbee9f6157fe6"
)
SHARED_DTB_SHA256 = (
    "540c1770543d9620e106ea4287c2a534f5efd85c912e97d6be6295930506b257"
)
SHARED_S11BOARD_SHA256 = (
    "bbc25a2137fd35ff97d6aa545992d21e4d7d35303fe5650b1b226fdd94b249c4"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class AmlogicNativePackageTargetsTest(unittest.TestCase):
    def test_exact_vendor_identity_and_shared_a113d_runtime(self) -> None:
        for model, (miner, _board, _defconfig, _daemon_model) in TARGETS.items():
            with self.subTest(model=model):
                package = VNISH / model / "vnishfarm-1.2.6-rc5-aml-nand-install"
                fw_info = json.loads(
                    (package / "rootfs" / "etc" / "fw-info").read_text(encoding="utf-8")
                )
                self.assertEqual(fw_info["model"], model)
                self.assertEqual(fw_info["miner"], miner)
                self.assertEqual(fw_info["platform"], "aml")
                self.assertEqual(fw_info["install_type"], "nand")
                self.assertEqual(sha256(package / "vmlinux.bin"), SHARED_VMLINUX_SHA256)
                self.assertEqual(sha256(package / "devicetree.dtb"), SHARED_DTB_SHA256)
                self.assertEqual(
                    sha256(package / "rootfs" / "etc" / "init.d" / "S11board"),
                    SHARED_S11BOARD_SHA256,
                )

    def test_each_product_has_exact_overlay_and_shared_capability_builder(self) -> None:
        configs = PROJECT / "br2_external_dcentos" / "configs"
        boards = PROJECT / "br2_external_dcentos" / "board" / "amlogic"
        for model, (_miner, board, defconfig, daemon_model) in TARGETS.items():
            with self.subTest(model=model):
                config = (configs / defconfig).read_text(encoding="utf-8")
                self.assertIn(f"/{board}/rootfs-overlay", config)
                if board == "am3-s19jproplus":
                    self.assertIn("/am3-bm1362-nopic/post-build.sh", config)
                    wrapper = (boards / "am3-bm1362-nopic/post-build.sh").read_text(encoding="utf-8")
                    self.assertIn('case "$TARGET" in am3-s19jproa|am3-s19jproplus)', wrapper)
                    self.assertIn('exec "$SCRIPT_DIR/../am3-s21/post-build.sh" "$@"', wrapper)
                else:
                    self.assertIn("/am3-s21/post-build.sh", config)
                if board in {"am3-s19jxp", "am3-s19jproplus"}:
                    self.assertIn(f"/{board}/post-image.sh", config)
                    wrapper = (boards / board / "post-image.sh").read_text(encoding="utf-8")
                    if board == "am3-s19jproplus":
                        self.assertIn('exec "$SCRIPT_DIR/../am3-bm1362-nopic/post-image.sh" "$@"', wrapper)
                        dedicated = (boards / "am3-bm1362-nopic/post-image.sh").read_text(encoding="utf-8")
                        self.assertIn('am3-s19jproplus) PRODUCT_LABEL="S19j Pro+ 120"', dedicated)
                        self.assertIn('*) echo "ERROR: exact A126/Plus120 post-image target required" >&2; exit 1', dedicated)
                        self.assertIn('dcent_require_exact_amlogic_build_inputs "${TARGET:-}"', dedicated)
                        self.assertIn("PACKAGE_INSTALL_AUTHORIZED=0", dedicated)
                        self.assertIn("PACKAGE_STORAGE_AUTHORIZED=0", dedicated)
                        self.assertIn("DCENT_PACKAGE_INSTALLABLE=false", dedicated)
                        self.assertIn("DCENT_TOOLBOX_INSTALL_MODE=package_only_denied", dedicated)
                    else:
                        self.assertIn("/am3-s21/post-image.sh", wrapper)
                else:
                    self.assertIn("/am3-s21/post-image.sh", config)
                overlay = boards / board / "rootfs-overlay" / "etc"
                self.assertEqual(
                    (overlay / "dcentos" / "board_target").read_text(encoding="utf-8").strip(),
                    board,
                )
                daemon = (overlay / "dcentrald.toml").read_text(encoding="utf-8")
                self.assertIn("enabled = false", daemon)
                self.assertIn(f'model = "{daemon_model}"', daemon)

    def test_package_metadata_is_experimental_and_identity_gated(self) -> None:
        post_image = (
            PROJECT
            / "br2_external_dcentos"
            / "board"
            / "amlogic"
            / "post-image-family.sh"
        ).read_text(encoding="utf-8")
        helper = (PROJECT / "scripts" / "lib" / "sysupgrade_package_common.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("am3-s19xp)", post_image)
        self.assertIn("am3-s19jxp)", post_image)
        self.assertIn("am3-s19jproplus)", post_image)
        self.assertGreaterEqual(post_image.count("PACKAGE_INSTALL_AUTHORIZED=0"), 2)
        self.assertIn("DCENT_TOOLBOX_INSTALL_MODE=package_only_denied", post_image)
        self.assertIn("DCENT_PACKAGE_INSTALLABLE=false", post_image)
        self.assertIn('PACKAGE_POSTURE="exact-runtime Experimental host rootfs-window target"', post_image)
        self.assertIn("DCENT_TOOLBOX_INSTALL_MODE=host_driven_rootfs_window_lab", post_image)
        self.assertIn("DCENT_PACKAGE_INSTALLABLE=true", post_image)
        self.assertIn("exact observed PCB, lock epoch, geometry, MAC, backup, and restore proof", post_image)
        self.assertNotIn("DCENT_PACKAGE_STATUS=package_only_install_denied", post_image)
        self.assertIn('"installable": ${installable}', helper)
        self.assertIn('install_command_json="\\"${install_command}\\""', helper)

    def test_native_rootfs_extractor_refuses_x19xp_package_only_targets(self) -> None:
        extractor = (PROJECT / "scripts" / "build_amlogic_native_install.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("s19xp|s19jxp|s19j-xp)", extractor)
        self.assertIn("NOT-IMPLEMENTED package-only targets; native install extraction is refused", extractor)
        self.assertIn("DCENT_REQUIRE_INSTALLABLE_PACKAGE=1", extractor)
        self.assertNotIn('BOARD_PKG_NAME="am3-s19xp"', extractor)
        self.assertNotIn('BOARD_PKG_NAME="am3-s19jxp"', extractor)
        self.assertNotIn('BIN_NAME="dcentos-amlogic-s19xp.bin"', extractor)
        self.assertNotIn('BIN_NAME="dcentos-amlogic-s19jxp.bin"', extractor)

    def test_s19xp_exact_asic_model_and_td003_gate_are_registered(self) -> None:
        model_source = (
            PROJECT / "dcentrald" / "dcentrald" / "src" / "model.rs"
        ).read_text(encoding="utf-8")
        self.assertIn('"s19xp" => ModelSpec {', model_source)
        self.assertIn('family_key: "bm1366"', model_source)
        self.assertIn('"am3s19xp"', model_source)

        master_models = (
            REPO / "knowledge-base" / "research" / "models" / ""
        ).read_text(encoding="utf-8")
        exact_catalog = (
            PROJECT
            / "dcentrald"
            / "dcentrald-re-catalog"
            / "src"
            / "model_catalog.rs"
        ).read_text(encoding="utf-8")
        self.assertNotIn("Antminer S19 XP | BHB42801/803/811/821 | BM1366", master_models)
        self.assertIn("historical BHB428 attribution retracted", master_models)
        self.assertIn('model!("s19xp", 0x1366, 3, Some(110)', exact_catalog)
        self.assertIn('model!("s19jxp", 0x1366, 3, Some(110)', exact_catalog)

    def test_plain_s19_redesign_asic_conflict_remains_unpackaged(self) -> None:
        amlogic_re = (
            REPO
            / "knowledge-base"
            / "research"
            / "vnish"
            / "VNISH_FIRMWARE_RE_AMLOGIC_EXTENDED.md"
        ).read_text(encoding="utf-8")
        hashboard_catalog = (
            PROJECT
            / "dcentrald"
            / "dcentrald-silicon-profiles"
            / "src"
            / "hashboard_catalog.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("Antminer S19 (88) | s19-88 | BM1398", amlogic_re)
        self.assertIn("Antminer S19 (126) | s19-126 | BM1398", amlogic_re)
        self.assertIn('(\"BHB42801\", \"BM1362\", 88, None, 1, true)', hashboard_catalog)
        self.assertNotIn('Some(\"Antminer S19 (88)\")', hashboard_catalog)
        self.assertNotIn('Some(\"Antminer S19 (126)\")', hashboard_catalog)
        configs = PROJECT / "br2_external_dcentos" / "configs"
        self.assertFalse((configs / "dcentos_am3_s19_88_defconfig").exists())
        self.assertFalse((configs / "dcentos_am3_s19_126_defconfig").exists())

    def test_s21plus_asic_conflict_remains_explicitly_unpackaged(self) -> None:
        intake = (
            REPO
            / "knowledge-base"
            / "research"
            / "mining-bible-v1"
            / "0-firmware-intake"
            / "binary-hash-map.md"
        ).read_text(encoding="utf-8")
        power_synthesis = (
            REPO
            / "knowledge-base"
            / "research"
            / "re-armada-2026-04-25"
            / "power-synthesis.md"
        ).read_text(encoding="utf-8")
        self.assertIn("s21plus-aml | S21+ | Amlogic | BM1368", intake)
        self.assertIn("aml | Antminer S21+ | BM1370", power_synthesis)
        self.assertFalse(
            (PROJECT / "br2_external_dcentos" / "configs" / "dcentos_am3_s21plus_defconfig").exists()
        )

    def test_s19pro_and_s19j_have_no_held_model_exact_aml_package(self) -> None:
        for model in ("s19pro", "s19j"):
            with self.subTest(model=model):
                entries = [path.name.lower() for path in (VNISH / model).iterdir()]
                self.assertFalse(any("aml" in entry for entry in entries))


if __name__ == "__main__":
    unittest.main()
