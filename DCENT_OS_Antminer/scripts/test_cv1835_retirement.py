#!/usr/bin/env python3
"""Offline acceptance for L17's CV1835 deletion and retained research inputs.

No compiler, firmware build, hardware endpoint, or historical campaign document
is opened. The old desktop refusal wrappers are deliberately outside shipped
overlays. Identifiers in negative tests and research are not runtime references.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path

import check_defconfig_doc_references as defconfig_docs


PROJECT = Path(__file__).resolve().parents[1]
REPO = PROJECT.parents[1]
EXTERNAL = PROJECT / "br2_external_dcentos"
HAL = PROJECT / "dcentrald/dcentrald-hal/src"
STOCK = EXTERNAL / "board/cvitek/r16-stock-evidence"
RETIRED_MODULES = ("cvitek", "cvitek_cold_boot", "cvitek_pinmux")


class Cv1835RetirementTests(unittest.TestCase):
    def test_no_cv_product_directory_or_defconfig_remains(self) -> None:
        self.assertEqual(
            {p.name for p in (EXTERNAL / "board/cvitek").iterdir()},
            {"r16-stock-evidence"},
        )
        self.assertFalse(list((EXTERNAL / "configs").glob("*cv1835*defconfig")))
        for name in RETIRED_MODULES:
            self.assertFalse((HAL / "platform" / f"{name}.rs").exists(), name)

    def test_no_cv_exit_78_wrapper_is_shipped_or_staged(self) -> None:
        retired = re.compile(
            r"safe_sysupgrade_cv_emmc|revert_to_stock_cv1835|"
            r"build_cv1835_s19jpro|cv1835_overlay_plan|board/cvitek/"
        )
        paths = list((EXTERNAL / "configs").glob("*defconfig"))
        paths += list((EXTERNAL / "board").rglob("post-*.sh"))
        paths += [
            p for p in (EXTERNAL / "board").rglob("*")
            if p.is_file() and "rootfs-overlay" in p.parts
        ]
        self.assertGreater(len(paths), 100)
        for path in paths:
            with self.subTest(path=str(path.relative_to(PROJECT))):
                self.assertIsNone(retired.search(path.read_text(encoding="utf-8", errors="replace")))

    def test_factory_has_no_retired_module_or_constructor(self) -> None:
        source = (HAL / "platform/mod.rs").read_text(encoding="utf-8")
        for name in RETIRED_MODULES:
            self.assertNotRegex(source, rf"\bmod\s+{name}\s*;")
        self.assertNotIn("CViTekPlatform::new", source)
        self.assertRegex(source, r"#\[cfg\(test\)\]\s*mod cvitek_stock_evidence;")

    def test_no_rust_code_references_retired_cv_modules(self) -> None:
        result = subprocess.run(
            ["git", "ls-files", "-z", "--", "DCENT_OS_Antminer/dcentrald/*/src/*.rs"],
            cwd=REPO, capture_output=True, check=True,
        )
        paths = [REPO / path for path in result.stdout.decode("utf-8").split("\0") if path]
        self.assertGreater(len(paths), 100)
        retired = re.compile(r"\b(?:cvitek|cvitek_cold_boot|cvitek_pinmux)::")
        for path in paths:
            for line in path.read_text(encoding="utf-8").splitlines():
                # Historical comments are retained RE context, not imports.
                if not line.lstrip().startswith("//"):
                    self.assertIsNone(retired.search(line), f"{path}: {line}")

    def test_cv_rust_includes_and_registry_evidence_resolve(self) -> None:
        paths = [HAL / "platform/cvitek_stock_evidence.rs", HAL / "platform/cv1835_retirement.rs"]
        for path in paths:
            source = path.read_text(encoding="utf-8")
            for relative in re.findall(r'include_(?:bytes|str)!\(\s*"([^"]+)"', source):
                self.assertTrue((path.parent / relative).is_file(), relative)
        registry = (PROJECT / "dcentrald/dcentrald-common/src/board_desc.rs").read_text(encoding="utf-8")
        rows = re.search(r"const CV1835_RETAINED_EVIDENCE:.*?= &\[(.*?)\];", registry, re.S)
        self.assertIsNotNone(rows)
        for relative in re.findall(r'"([^"]+)"', rows[1]):
            self.assertTrue((PROJECT / "dcentrald" / relative).is_file(), relative)

    def test_retained_fixtures_survive_a_clean_checkout(self) -> None:
        manifest = json.loads((STOCK / "FIXTURES_MANIFEST.json").read_text(encoding="utf-8"))
        result = subprocess.run(
            ["git", "ls-files", "-z", "--", STOCK.relative_to(REPO).as_posix()],
            cwd=REPO, capture_output=True, check=True,
        )
        tracked = set(result.stdout.decode("utf-8").split("\0"))
        for name, expected in manifest["fixtures"].items():
            path = STOCK / "fixtures" / name
            with self.subTest(fixture=name):
                self.assertTrue(path.relative_to(REPO).as_posix() in tracked, f"untracked fixture: {name}")
                self.assertEqual(path.stat().st_size, expected["bytes"])
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected["sha256"])

    def test_current_defconfig_audit_uses_retirement_decision(self) -> None:
        decision = PROJECT / "docs/CV1835_STATUS.md"
        self.assertIn(decision, defconfig_docs.AUTHORITATIVE_DOCS)
        for path in defconfig_docs.AUTHORITATIVE_DOCS:
            self.assertTrue(path.is_file(), str(path))
        self.assertEqual(defconfig_docs.collect_claims(decision.read_text(encoding="utf-8")), [])

    def test_current_decision_links_resolve_without_opening_history(self) -> None:
        decision = PROJECT / "docs/CV1835_STATUS.md"
        for target in re.findall(r"\]\(([^)]+)\)", decision.read_text(encoding="utf-8")):
            self.assertTrue((decision.parent / target).is_file(), target)
        matrix = (REPO / "SUPPORT_MATRIX.md").read_text(encoding="utf-8")
        self.assertIn("L17 selected removal", matrix)
        self.assertIn("DCENT_OS_Antminer/docs/CV1835_STATUS.md", matrix)


if __name__ == "__main__":
    unittest.main()
