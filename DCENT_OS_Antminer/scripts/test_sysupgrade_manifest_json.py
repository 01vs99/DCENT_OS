#!/usr/bin/env python3
"""Offline contracts for semantic manifest and version admission."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

LIB_DIR = Path(__file__).resolve().parent / "lib"
sys.path.insert(0, str(LIB_DIR))

from sysupgrade_manifest_json import (  # noqa: E402
    AdmissionError,
    admit_manifest,
    compare_versions,
    read_version_file,
    require_install_mode_contract,
    require_package_authority,
    require_payload_binding,
)


class ManifestAdmissionTests(unittest.TestCase):
    def write_manifest(self, directory: Path, text: str) -> Path:
        path = directory / "MANIFEST.json"
        path.write_text(text, encoding="utf-8")
        return path

    def test_accepts_escape_free_unique_object(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            path = self.write_manifest(
                Path(raw_dir),
                json.dumps(
                    {
                        "schema": 1,
                        "version": "0.9.0",
                        "payloads": {
                            "kernel": {
                                "path": "sysupgrade-am1-s9/kernel",
                                "size": 6,
                                "sha256": "0" * 64,
                            }
                        },
                    },
                    indent=2,
                ),
            )
            self.assertEqual(admit_manifest(path)["version"], "0.9.0")

    def test_rejects_literal_decoded_duplicate_at_any_depth(self) -> None:
        fixtures = (
            '{"schema":1,"schema":2}',
            '{"payloads":{"kernel":{"size":6,"size":999}}}',
        )
        with tempfile.TemporaryDirectory() as raw_dir:
            directory = Path(raw_dir)
            for index, fixture in enumerate(fixtures):
                with self.subTest(index=index):
                    path = self.write_manifest(directory, fixture)
                    with self.assertRaisesRegex(AdmissionError, "duplicate decoded"):
                        admit_manifest(path)

    def test_rejects_escaped_keys_and_values(self) -> None:
        fixtures = (
            r'{"schema":1,"sche\u006da":2}',
            r'{"status":"rele\u0061se"}',
            r'{"payloads":{"kernel":{"sha\u003256":"00"}}}',
        )
        with tempfile.TemporaryDirectory() as raw_dir:
            directory = Path(raw_dir)
            for index, fixture in enumerate(fixtures):
                with self.subTest(index=index):
                    path = self.write_manifest(directory, fixture)
                    with self.assertRaisesRegex(AdmissionError, "escape sequences"):
                        admit_manifest(path)

    def test_rejects_noncanonical_or_oversized_structure(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            directory = Path(raw_dir)
            noncanonical = self.write_manifest(directory, '{"bad key":1}')
            with self.assertRaisesRegex(AdmissionError, "canonical ASCII grammar"):
                admit_manifest(noncanonical)

            nested: object = 0
            for _ in range(34):
                nested = {"node": nested}
            too_deep = self.write_manifest(directory, json.dumps(nested))
            with self.assertRaisesRegex(AdmissionError, "nesting exceeds"):
                admit_manifest(too_deep)

    def test_payload_binding_rejects_swapped_hashes_and_decoy_strings(self) -> None:
        kernel_sha = "1" * 64
        root_sha = "2" * 64
        manifest = {
            "payloads": {
                "kernel": {
                    "path": "sysupgrade-am3-s21/kernel",
                    "size": 10,
                    "sha256": root_sha,
                    "note": kernel_sha,
                },
                "rootfs": {
                    "path": "sysupgrade-am3-s21/root",
                    "size": 20,
                    "sha256": kernel_sha,
                    "note": root_sha,
                },
            }
        }
        with self.assertRaisesRegex(AdmissionError, "kernel.sha256"):
            require_payload_binding(
                manifest,
                "kernel",
                "sysupgrade-am3-s21/kernel",
                10,
                kernel_sha,
            )
        with self.assertRaisesRegex(AdmissionError, "rootfs.sha256"):
            require_payload_binding(
                manifest,
                "rootfs",
                "sysupgrade-am3-s21/root",
                20,
                root_sha,
            )

    def test_payload_binding_requires_exact_types(self) -> None:
        manifest = {
            "payloads": {
                "kernel": {
                    "path": "sysupgrade-am3-s21/kernel",
                    "size": "10",
                    "sha256": "1" * 64,
                }
            }
        }
        with self.assertRaisesRegex(AdmissionError, "kernel.size"):
            require_payload_binding(
                manifest,
                "kernel",
                "sysupgrade-am3-s21/kernel",
                10,
                "1" * 64,
            )

    def test_installable_package_authority_requires_exact_boolean(self) -> None:
        manifest = {
            "board": "am3-s21",
            "board_target": "am3-s21",
            "installable": True,
            "toolbox": {"install_mode": "target_sysupgrade"},
        }
        require_package_authority(manifest, "am3-s21")
        manifest["installable"] = "true"
        with self.assertRaisesRegex(AdmissionError, "JSON boolean"):
            require_package_authority(manifest, "am3-s21")

    def test_amlogic_package_only_denial_is_exact_and_non_dispatching(self) -> None:
        toolbox = {
            "install_command": None,
            "update_command": None,
            "upload_endpoint": None,
            "board_target_header": None,
            "requires_inactive_slot": False,
            "install_mode": "package_only_denied",
            "target_side_sysupgrade": False,
        }
        for board in ("am3-s19xp", "am3-s19jxp", "am3-s21xp", "am3-t21"):
            manifest = {
                "board": board,
                "board_target": board,
                "installable": False,
                "toolbox": toolbox,
            }
            require_package_authority(manifest, board)

            for field, bad_value in (
                ("install_command", f"dcent install 192.0.2.1 -f {board}.tar"),
                ("update_command", f"dcent ota update-fleet 192.0.2.1 -f {board}.tar"),
                ("upload_endpoint", "/cgi-bin/upgrade.cgi"),
                ("board_target_header", "X-DCENT-Board-Target"),
                ("requires_inactive_slot", True),
                ("install_mode", "host_driven_rootfs_window_lab"),
                ("target_side_sysupgrade", True),
            ):
                with self.subTest(board=board, field=field):
                    tampered = {**manifest, "toolbox": {**toolbox, field: bad_value}}
                    with self.assertRaisesRegex(AdmissionError, f"toolbox.{field}"):
                        require_package_authority(tampered, board)

    def test_noninstallable_package_is_not_a_generic_authority_lane(self) -> None:
        manifest = {
            "board": "am3-s21",
            "board_target": "am3-s21",
            "installable": False,
            "toolbox": {"install_mode": "package_only_denied"},
        }
        with self.assertRaisesRegex(AdmissionError, "not admitted"):
            require_package_authority(manifest, "am3-s21")

    def test_first_install_only_contract_is_explicit_and_non_updating(self) -> None:
        # AM1-A Drop-1 route scoping (owner adjudication
        # AM1_S9_ROOTFS_WINDOW_ADJUDICATION Option A, ratified 2026-09-15):
        # an installable first-install-only package carries the typed
        # self-update denial — update_command must be JSON null and the
        # install_command stays the target-bound dcent install rail.
        toolbox = {
            "install_command": "dcent install <ip> -f dcentos-unit.tar",
            "update_command": None,
            "upload_endpoint": None,
            "board_target_header": None,
            "requires_inactive_slot": False,
            "install_mode": "first_install_only",
            "target_side_sysupgrade": False,
        }
        manifest = {
            "board": "am1-s9",
            "board_target": "am1-s9",
            "installable": True,
            "toolbox": toolbox,
        }
        require_package_authority(manifest, "am1-s9")
        self.assertEqual(
            require_install_mode_contract(manifest), "first_install_only"
        )

        for field, bad_value in (
            (
                "update_command",
                "dcent install <ip> -f dcentos-unit.tar",
            ),
            (
                "update_command",
                "dcent ota update-fleet <ip> -f dcentos-unit.tar",
            ),
            ("install_command", "dcent flash <ip> -f dcentos-unit.tar"),
            ("install_mode", "weird_route"),
            ("install_mode", ""),
        ):
            with self.subTest(field=field, bad_value=bad_value):
                tampered = {**manifest, "toolbox": {**toolbox, field: bad_value}}
                with self.assertRaises(AdmissionError):
                    require_package_authority(tampered, "am1-s9")

    def test_install_mode_query_admits_known_values_and_absence(self) -> None:
        base = {"board": "am1-s9", "board_target": "am1-s9", "installable": True}
        # No toolbox block at all: legacy manifests stay inspectable and
        # resolve to None (printed as "absent" by query-install-mode).
        self.assertIsNone(require_install_mode_contract(dict(base)))
        mode_toolboxes = {
            "target_sysupgrade": {},
            "host_driven_rootfs_window_lab": {},
            "first_install_only": {
                "install_command": "dcent install <ip> -f dcentos-unit.tar",
                "update_command": None,
            },
        }
        for mode, extra in mode_toolboxes.items():
            manifest = {**base, "toolbox": {"install_mode": mode, **extra}}
            self.assertEqual(require_install_mode_contract(manifest), mode)
        # package_only_denied on an installable manifest stays a contradiction.
        with self.assertRaisesRegex(AdmissionError, "contradicts"):
            require_package_authority(
                {
                    **base,
                    "toolbox": {
                        "install_command": "dcent install <ip> -f x.tar",
                        "install_mode": "package_only_denied",
                    },
                },
                "am1-s9",
            )


class VersionAdmissionTests(unittest.TestCase):
    def test_comparison_vectors(self) -> None:
        cases = (
            ("1.2", "1.2.0", 0),
            ("v1.2.0+build7", "1.2.0", 0),
            ("1.2.0", "1.2.0-rc1", 1),
            ("1.2.0-rc1", "1.2.0-rc2", -1),
            ("1.2.0-rc10", "1.2.0-rc2", -1),
            ("1.2.0-rc.10", "1.2.0-rc.2", 1),
            ("1.2.0-alpha", "1.2.0-alpha.0", -1),
            ("1.2.0-1", "1.2.0-alpha", -1),
            ("1.2.0-ab", "1.2.0-ba", -1),
            ("9007199254740993.0", "9007199254740992.0", 1),
            ("18446744073709551616.0", "18446744073709551615.0", 1),
            (
                "100000000000000000000000000000000.0",
                "99999999999999999999999999999999.999",
                1,
            ),
            ("1.2.0+build-7", "1.2.0+other", 0),
        )
        for candidate, current, expected in cases:
            with self.subTest(candidate=candidate, current=current):
                self.assertEqual(compare_versions(candidate, current), expected)
                self.assertEqual(compare_versions(current, candidate), -expected)

    def test_rejects_noncanonical_versions(self) -> None:
        invalid = (
            "1",
            "1.2.3.4",
            "01.2.0",
            "1.02.0",
            "1.2.0-",
            "1.2.0-alpha..1",
            "1.2.0-alpha.01",
            "1.2.0+",
            "1.2.0_bad",
            "1.2.0:bad",
            " 1.2.0",
            "1.2.0 ",
            "1.2.0-" + ("a" * 33),
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(AdmissionError):
                    compare_versions(value, "1.2.0")

    def test_version_file_has_exactly_one_canonical_line(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            path = Path(raw_dir) / "dcentos-version"
            path.write_bytes(b"0.9.0\n")
            self.assertEqual(read_version_file(path), "0.9.0")
            for invalid in (b"0.9.0\r\n", b"0.9.0\n1.0.0\n", b"\n", b" 0.9.0\n"):
                with self.subTest(invalid=invalid):
                    path.write_bytes(invalid)
                    with self.assertRaises(AdmissionError):
                        read_version_file(path)


if __name__ == "__main__":
    unittest.main()
