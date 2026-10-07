#!/usr/bin/env python3
"""Tests for the release image-content leak gate.

Planted-leak fixtures must fail, clean fixtures must pass, known false
positives stay quiet, and the shipped source overlays themselves must be clean
(except the lab-only seeder that the am2-s19jpro post-build removes). Host-only;
no build, network, or hardware.
"""
from __future__ import annotations

import gzip
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
PROJECT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

import image_content_leak_scan as scan  # noqa: E402

BOARD = PROJECT / "br2_external_dcentos" / "board"
PRUNE = BOARD / "common" / "prune-runtime-research-tools.sh"
S19JPRO_POST_BUILD = BOARD / "zynq" / "am2-s19jpro" / "post-build.sh"

# Assembled from parts so this test file never matches the scanner itself.
MAC = "32:30:41:27" + ":f6:ab"
LEAKS = {
    "lab-unit-mac": f'KNOWN_MAC="{MAC}"\n',
    "xil-home-unit": "worker = bc1qexample.s19jpro-xil" + "25\n",
    "workspace-path": "built from D:/DCENT " + "Projects/projects\n",
    "wsl-workspace-mount": "cd /mnt/d/" + "build\n",
    "windows-user-path": "C:/Users" + "/someone/repo\n",
    "operator-account": "owner=" + "Kry" + "pt\n",
    "lab-ip-192.168.101": "# example: ssh root@192.168." + "101.133\n",
    "lab-ip-10.0.1": 'pool_host = "10.0.' + '1.109"\n',
    "memory-rule-slug": "# see feed" + "back_fan_never_blast.md\n",
    "internal-doc-path": "# docs/" + "dev/2026-06-14-notes/RUNBOOK.md\n",
    "knowledge-base-path": '"source": "knowledge' + '-base/extractions/x.md"\n',
    "claude-md": "# policy lives in CLAUDE" + ".md\n",
}


def make_rootfs(base: Path) -> Path:
    root = base / "rootfs"
    for directory in ("etc/init.d", "bin", "usr/bin", "usr/lib/python3.11", "root/web"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "etc/init.d/S82dcentrald").write_text("#!/bin/sh\necho start\n")
    (root / "etc/dcentrald.toml").write_text('[pool]\nurl = "stratum+tcp://pool.example:3333"\n')
    (root / "root/web/index.html").write_text("<html>DCENT_OS</html>\n")
    return root


class ScannerUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.root = make_rootfs(self.base)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def rules(self) -> set[str]:
        return {finding.rule for finding in scan.scan_tree(self.root)}

    def test_clean_fixture_passes(self) -> None:
        self.assertEqual(scan.scan_tree(self.root), [])
        self.assertEqual(scan.main([str(self.root)]), 0)

    def test_every_planted_leak_fails(self) -> None:
        for rule, text in LEAKS.items():
            with self.subTest(rule=rule):
                target = self.root / "etc/init.d/S99planted"
                target.write_text("#!/bin/sh\n" + text)
                self.assertIn(rule, self.rules())
                self.assertEqual(scan.main([str(self.root)]), 1)
                target.unlink()

    def test_strong_patterns_apply_in_vendor_trees_owned_patterns_do_not(self) -> None:
        vendor = self.root / "usr/lib/python3.11/example.py"
        vendor.write_text("HOST = '203.0.113.7'\nREF = 'reference_alpha_beta_gamma'\n")
        self.assertEqual(self.rules(), set())
        vendor.write_text(f"MAC = '{MAC}'\n")
        self.assertEqual(self.rules(), {"lab-unit-mac"})

    def test_binary_files_are_skipped_and_gzip_text_is_scanned(self) -> None:
        (self.root / "usr/bin/dcentrald").write_bytes(b"\x7fELF\x01\x01\x01" + MAC.encode())
        self.assertEqual(self.rules(), set())
        with gzip.open(self.root / "root/web/index.html.gz", "wb") as handle:
            handle.write(("<p>see docs/" + "reviews/x.md</p>").encode())
        self.assertEqual(self.rules(), {"internal-doc-path"})

    def test_known_false_positives_stay_quiet(self) -> None:
        (self.root / "root/web/app.js").write_text(
            'pools=[{name:"Kryp' + 'tex"}];x.reference_wall_watts;y.rpm_feedback_available;'
            'net="10.0.10.5";other="1203.0.113.5";ip="192.168.1011.2"\n'
        )
        self.assertEqual(self.rules(), set())

    def test_symlinks_are_not_followed(self) -> None:
        outside = self.base / "outside.txt"
        outside.write_text(f"{MAC}\n")
        try:
            os.symlink(outside, self.root / "etc/link")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        self.assertEqual(self.rules(), set())

    def test_pinned_line_exception_is_exact(self) -> None:
        pinned = "# feed" + "back_fan_never_blast."
        target = self.root / "etc/init.d/S82dcentrald"
        target.write_text("#!/bin/sh\n    " + pinned + "\n")
        self.assertEqual(self.rules(), set())
        target.write_text("#!/bin/sh\n" + pinned + " (edited)\n")
        self.assertEqual(self.rules(), {"memory-rule-slug"})
        other = self.root / "etc/init.d/S99other"
        other.write_text("#!/bin/sh\n" + pinned + "\n")
        self.assertIn("memory-rule-slug", self.rules())

    def test_usage_error_for_missing_directory(self) -> None:
        self.assertEqual(scan.main([str(self.base / "missing")]), 2)


class ShippedSourceTests(unittest.TestCase):
    """The overlays and image-staged sources must already be leak-free."""

    LAB_ONLY_REMOVED_BY_POST_BUILD = {"etc/init.d/S81dcentos-xil-seed"}
    # revert_to_stock_* scripts that board post-build hooks copy into images.
    STAGED_REVERT_SCRIPTS = (
        "revert_to_stock_am3_aml_s19jpro.sh",
        "revert_to_stock_am3_aml_s19k.sh",
        "revert_to_stock_am3_aml_s21.sh",
        "revert_to_stock_am335x_bb.sh",
        "revert_to_stock_am335x_bb_s19jpro.sh",
        "revert_to_stock_s17.sh",
        "revert_to_stock_s19_am2.sh",
        "revert_to_stock_s9.sh",
    )
    STAGED_SOURCES = {
        "usr/sbin/lib/am3_geometry.sh": "scripts/lib/am3_geometry.sh",
        "usr/libexec/dcentos/sysupgrade-zynq-geometry.sh": "scripts/lib/sysupgrade_zynq_geometry.sh",
        "usr/libexec/dcentos/sysupgrade-archive-admission.sh": "scripts/lib/sysupgrade_archive_admission.sh",
        "usr/libexec/dcentos/sysupgrade_manifest_json.py": "scripts/lib/sysupgrade_manifest_json.py",
        "etc/dcentrald.toml#s17pro": "dcentrald/configs/dcentrald_s17pro_am2_baked_default.toml",
        "etc/dcentrald.toml#s19jpro": "dcentrald/configs/dcentrald_s19jpro_am2_baked_default.toml",
        "etc/dcentrald.toml#xil": "dcentrald/configs/dcentrald_s19jpro_xil_baked_default.toml",
        "etc/dcentrald/xil_override.toml": "dcentrald/configs/dcentrald_s19jpro_xil_override.toml",
        "etc/dcentrald.toml#s19pro": "dcentrald/configs/dcentrald_s19pro_am2_baked_default.toml",
        "etc/dcentos/s19k_install_custody.toml": "dcentrald/dcentrald_s19k_install_custody.toml",
        "root/web/index.html": "dashboard/dist/index.html",
    }

    def test_rootfs_overlays_are_clean(self) -> None:
        findings = []
        for overlay in sorted(BOARD.rglob("rootfs-overlay")):
            if not overlay.is_dir():
                continue
            for path in sorted(overlay.rglob("*")):
                if path.is_symlink() or not path.is_file():
                    continue
                rel = path.relative_to(overlay).as_posix()
                if rel.startswith("root/tools/") or rel in self.LAB_ONLY_REMOVED_BY_POST_BUILD:
                    continue
                text = scan._read_text(path)  # noqa: SLF001
                if text is not None:
                    findings.extend(
                        f"{path.relative_to(PROJECT).as_posix()}: {finding.render()}"
                        for finding in scan.scan_text(rel, text)
                    )
        self.assertEqual(findings, [])

    def test_image_staged_sources_are_clean(self) -> None:
        sources = dict(self.STAGED_SOURCES)
        for name in self.STAGED_REVERT_SCRIPTS:
            sources[f"usr/sbin/{name}"] = f"scripts/{name}"
        findings = []
        for rel, source in sources.items():
            path = PROJECT / source
            if not path.is_file():
                continue
            text = scan._read_text(path)  # noqa: SLF001
            if text is not None:
                findings.extend(f"{source}: {f.render()}" for f in scan.scan_text(rel.split("#")[0], text))
        self.assertEqual(findings, [])


class BuildGlueTests(unittest.TestCase):
    def test_s19jpro_post_build_stages_xil25_seed_only_behind_lab_opt_in(self) -> None:
        text = S19JPRO_POST_BUILD.read_text(encoding="utf-8")
        self.assertIn('case "${DCENT_LAB_XIL25_SEED:-0}" in', text)
        self.assertIn("dcent_release_posture_is_release || [ \"${DCENT_REQUIRE_RELEASE_KEY:-0}\" = \"1\" ]", text)
        self.assertIn('rm -f "${TARGET_DIR}/etc/init.d/S81dcentos-xil-seed"', text)
        self.assertIn('rm -rf "${TARGET_DIR}/etc/dcentos/xil-seed"', text)
        opt_out = text.index('if [ "$XIL25_LAB_OPT_IN" != "1" ]; then')
        staging = text.index('mkdir -p "$XIL25_SEED_DIR"')
        self.assertLess(opt_out, staging, "seed staging must sit behind the lab opt-in branch")

    def test_common_prune_runs_the_scanner_on_release_rootfs(self) -> None:
        text = PRUNE.read_text(encoding="utf-8")
        gate = text.index("image_content_leak_scan.py")
        self.assertGreaterEqual(text.rfind("if dcent_release_posture_is_release; then", 0, gate), 0)
        self.assertIn('python3 "$_dcent_leak_scan" "$TARGET_DIR"', text)
        self.assertNotIn(b"\r", PRUNE.read_bytes())
        self.assertNotIn(b"\r", S19JPRO_POST_BUILD.read_bytes())

    @unittest.skipUnless(os.name == "posix" and shutil.which("sh") and shutil.which("python3"), "requires POSIX sh")
    def test_release_prune_fails_on_planted_leak_and_dev_prune_does_not(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_rootfs(Path(tmp))
            (root / "usr/sbin").mkdir(parents=True, exist_ok=True)
            env = {k: v for k, v in os.environ.items() if k not in {"DCENT_RELEASE_IMAGE", "DCENT_DEV_IMAGE"}}
            env["BR2_EXTERNAL_DCENTOS_PATH"] = str(PROJECT / "br2_external_dcentos")
            (root / "etc/dcentos").mkdir(parents=True, exist_ok=True)
            unread_manifest = root / "etc/dcentos/stock-bitmain-manifest.json"
            unread_manifest.write_text(LEAKS["knowledge-base-path"])
            clean = subprocess.run(["sh", str(PRUNE), str(root)], env=env, capture_output=True, text=True)
            self.assertEqual(clean.returncode, 0, clean.stderr)
            self.assertFalse(unread_manifest.exists(), "release prune must drop the unread lab manifest copy")
            (root / "etc/init.d/S99planted").write_text("#!/bin/sh\n" + LEAKS["lab-unit-mac"])
            leaked = subprocess.run(["sh", str(PRUNE), str(root)], env=env, capture_output=True, text=True)
            self.assertNotEqual(leaked.returncode, 0)
            self.assertIn("lab-unit-mac", leaked.stderr)
            dev = subprocess.run(
                ["sh", str(PRUNE), str(root)], env={**env, "DCENT_DEV_IMAGE": "1"}, capture_output=True, text=True
            )
            self.assertEqual(dev.returncode, 0, dev.stderr)


if __name__ == "__main__":
    unittest.main()
