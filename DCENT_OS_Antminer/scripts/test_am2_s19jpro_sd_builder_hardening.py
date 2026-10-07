#!/usr/bin/env python3
"""Host-only admission tests for the AM2 S19j-Pro SD image builder."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
BUILDER = SCRIPT_DIR / "build_am2_s19jpro_sd_disk_image.sh"
BAKED_CONFIG = (
    SCRIPT_DIR.parent / "dcentrald/configs/dcentrald_s19jpro_xil_baked_default.toml"
)


class Am2S19jproSdBuilderHardeningTests(unittest.TestCase):
    def bash(self) -> str:
        if os.name == "nt":
            candidate = Path(
                os.environ.get("ProgramFiles", r"C:\Program Files")
            ) / "Git/bin/bash.exe"
            if candidate.is_file():
                return str(candidate)
        shell = shutil.which("bash") or shutil.which("sh")
        if shell:
            return shell
        self.skipTest("POSIX shell unavailable")

    def stage_payload(self, root: Path) -> Path:
        payload = root / "payload" / "sysupgrade-am2-s19j"
        payload.mkdir(parents=True)
        rootfs = payload / "root"
        with rootfs.open("wb") as handle:
            handle.write(b"hsqs")
            handle.seek(8 * 1024 * 1024 - 1)
            handle.write(b"\0")
        root_hash = hashlib.sha256(rootfs.read_bytes()).hexdigest()
        manifest = {
            "schema": 1,
            "product": "DCENT_OS",
            "package_type": "sysupgrade",
            "board": "am2-s19j",
            "board_target": "am2-s19j",
            "payloads": {
                "rootfs": {
                    "path": "sysupgrade-am2-s19j/root",
                    "size": rootfs.stat().st_size,
                    "sha256": root_hash,
                }
            },
        }
        (payload / "MANIFEST.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        (payload / "SHA256SUMS").write_text(
            f"{root_hash}  root\n", encoding="ascii", newline="\n"
        )
        return payload.parent

    def stage_artifacts(self, root: Path, *, board_target: str = "am2-s19j") -> Path:
        artifacts = root / "artifacts"
        artifacts.mkdir()
        values = {
            "BOOT.bin": b"B" * 20_000,
            "uImage": b"\x27\x05\x19\x56" + b"K" * 65_532,
            "devicetree.dtb": b"\xd0\x0d\xfe\xed" + b"D" * 60,
            "system.bit": b"isolated-bitstream-input-fixture",
        }
        records: dict[str, object] = {}
        for name, value in values.items():
            (artifacts / name).write_bytes(value)
            records[name] = {
                "bytes": len(value),
                "present": True,
                "sha256": hashlib.sha256(value).hexdigest(),
                "source_name": name,
            }
        document = {
            "schema": "dcentos.am2_sd_artifacts_stage.v2",
            "board_target": board_target,
            "control_board_family": "zynq-bm3-am2",
            "media_target": "am2-s19jpro-sd",
            "provenance_scope": "local-snapshot-integrity-only",
            "ready_for_complete_build": True,
            "artifacts": records,
        }
        (artifacts / "artifacts.manifest.json").write_text(
            json.dumps(document), encoding="utf-8"
        )
        return artifacts

    def run_preflight(
        self,
        root: Path,
        payload: Path,
        artifacts: Path,
        *extra: str,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["BUILDROOT_OUTPUT"] = (root / "output").as_posix()
        return subprocess.run(
            [
                self.bash(),
                BUILDER.as_posix(),
                "--payload-dir",
                payload.as_posix(),
                "--artifacts",
                artifacts.as_posix(),
                "--bitstream",
                (artifacts / "system.bit").as_posix(),
                *extra,
                "--validate-inputs-only",
            ],
            capture_output=True,
            check=False,
            env=environment,
            text=True,
        )

    def test_exact_target_bound_inputs_pass_without_creating_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = self.stage_payload(root)
            artifacts = self.stage_artifacts(root)

            result = self.run_preflight(root, payload, artifacts)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("AM2_S19JPRO_SD_INPUTS_READY", result.stdout)
            self.assertFalse(
                (root / "output/sd_card_am2_s19jpro/dcentos-am2-s19jpro.img").exists()
            )

    def test_wrong_target_artifact_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = self.stage_payload(root)
            artifacts = self.stage_artifacts(root, board_target="am2-s19pro")

            result = self.run_preflight(root, payload, artifacts)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("board_target mismatch", result.stderr)
            self.assertFalse(
                (root / "output/sd_card_am2_s19jpro/dcentos-am2-s19jpro.img").exists()
            )

    def test_active_mining_config_is_rejected_before_image_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = self.stage_payload(root)
            artifacts = self.stage_artifacts(root)
            unsafe = root / "unsafe.toml"
            unsafe.write_text(
                "[pool]\nurl = \"stratum+tcp://example\"\nworker = \"x\"\n"
                "[mining]\nenabled = true\n",
                encoding="utf-8",
            )

            result = self.run_preflight(
                root, payload, artifacts, "--xil-config", unsafe.as_posix()
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("[mining] enabled='true'", result.stderr)
            self.assertFalse(
                (root / "output/sd_card_am2_s19jpro/dcentos-am2-s19jpro.img").exists()
            )

    def test_declared_origin_consistency_preserves_legacy_and_handoff(self) -> None:
        baked = BAKED_CONFIG.read_text(encoding="utf-8")
        mining_section = "[mining]\n"
        passthrough_line = "passthrough = false\n"
        self.assertNotIn('am2_boot_origin =', baked)
        self.assertEqual(baked.count(mining_section), 1)
        self.assertEqual(baked.count(passthrough_line), 1)
        cases = (
            ("native", '"native_cold"', "false", True),
            ("native_literal_string", "'native_cold'", "false", True),
            ("native_default_passthrough", '"native_cold"', None, True),
            ("native_passthrough_conflict", '"native_cold"', "true", False),
            ("native_invalid_passthrough_type", '"native_cold"', '"false"', False),
            ("unknown_origin", '"stock_warm"', "false", False),
            ("unknown_origin_with_embedded_space", '"native_ cold"', "false", False),
            ("invalid_origin_type", "false", "false", False),
            ("empty_declared_origin", '""', "false", False),
            ("absent_legacy_origin", None, "true", True),
            ("fresh_generic_origin", None, "false", True),
            ("explicit_handoff", '"inherited_handoff"', "true", True),
            ("handoff_rail_selection_remains_runtime_owned", '"inherited_handoff"', "false", True),
        )
        for label, origin, passthrough, admitted in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                payload = self.stage_payload(root)
                artifacts = self.stage_artifacts(root)
                config = root / "selected.toml"
                text = baked.replace(
                    mining_section, mining_section + ("" if origin is None else f"am2_boot_origin = {origin}\n")
                ).replace(
                    passthrough_line,
                    "" if passthrough is None else f"passthrough = {passthrough}\n",
                )
                config.write_text(text, encoding="utf-8", newline="\n")

                result = self.run_preflight(
                    root, payload, artifacts, "--xil-config", config.as_posix()
                )

                if admitted:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("AM2_S19JPRO_SD_INPUTS_READY", result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("am2_boot_origin", result.stderr)
                    self.assertNotIn("AM2_S19JPRO_SD_INPUTS_READY", result.stdout)
                self.assertFalse(
                    (root / "output/sd_card_am2_s19jpro/dcentos-am2-s19jpro.img").exists()
                )

    def test_manifest_retains_authority_and_provenance_contract(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        for required in (
            '"board_target": "am2-s19j"',
            '"control_board_family": "zynq-bm3-am2"',
            '"install_scope": "external_media_boot"',
            '"persistent_install_authorized": false',
            '"nand_mutation_authorized": false',
            '"build_invocation_token": "$TOOLBOX_BUILD_TOKEN"',
            '"trust_scope": "local-input-integrity-only"',
            '"boot_artifact_manifest"',
            '"rootfs_source_manifest"',
            'assert_idle_first_config "$XIL_CONFIG_SRC"',
        ):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
