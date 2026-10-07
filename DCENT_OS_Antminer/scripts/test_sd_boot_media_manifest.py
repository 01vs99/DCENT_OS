#!/usr/bin/env python3
"""Host-only tests for typed SD boot-media manifest generation."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
WRITER = SCRIPT_DIR / "write_sd_boot_media_manifest.py"
BUILDER = SCRIPT_DIR / "build_sd_s19pro.sh"
DONOR_SIZE = 112_197_632
DONOR_SHA256 = "b0444ad2a5e9b9e2b021ec756a40cb1448128545a42c77bdabb4363617d03579"


class BootMediaManifestTests(unittest.TestCase):
    def bash_shell(self) -> str:
        # build_sd_s19pro.sh deliberately uses Bash (`pipefail` and arrays),
        # so invoking it through `/bin/sh` tests the wrong interpreter and can
        # fail before the donor-preservation boundary under dash.
        if os.name == "nt":
            program_files = Path(
                os.environ.get("ProgramFiles", r"C:\Program Files")
            )
            git_bash = program_files / "Git/bin/bash.exe"
            if git_bash.is_file():
                return str(git_bash)
            self.skipTest("Git Bash unavailable on Windows")
        shell = shutil.which("bash")
        if shell:
            return shell
        self.skipTest("POSIX shell unavailable")

    def run_writer(
        self, image: Path, donor: Path, manifest: Path
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(WRITER),
                "--image",
                str(image),
                "--manifest",
                str(manifest),
                "--target",
                "am2-s19pro-sd",
                "--board-target",
                "am2-s19pro",
                "--control-board-family",
                "zynq-bm3-am2",
                "--native-runtime-support",
                "management_only",
                "--donor",
                str(donor),
            ],
            capture_output=True,
            check=False,
            text=True,
        )

    def test_hash_bound_am2_management_only_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "dcentos-s19pro-sd.img"
            donor = root / "braiins-os_am2-s17_sd.img"
            runtime = root / "dcentrald"
            image.write_bytes(b"synthetic DCENT_OS SD image")
            donor.write_bytes(b"synthetic held AM2 donor")
            runtime.write_bytes(b"synthetic current runtime")

            result = subprocess.run(
                [
                    sys.executable,
                    str(WRITER),
                    "--image",
                    str(image),
                    "--target",
                    "am2-s19pro-sd",
                    "--board-target",
                    "am2-s19pro",
                    "--control-board-family",
                    "zynq-bm3-am2",
                    "--native-runtime-support",
                    "management_only",
                    "--donor",
                    str(donor),
                    "--runtime",
                    str(runtime),
                    "--complete-zynq-boot-set",
                ],
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            manifest = json.loads(Path(f"{image}.manifest.json").read_text("utf-8"))
            self.assertEqual(manifest["schema"], "dcentos.sd_boot_media_manifest.v1")
            self.assertEqual(manifest["board_target"], "am2-s19pro")
            self.assertEqual(manifest["control_board_family"], "zynq-bm3-am2")
            self.assertEqual(manifest["install_scope"], "external_media_boot")
            self.assertEqual(manifest["native_runtime_support"], "management_only")
            self.assertFalse(manifest["persistent_install_authorized"])
            self.assertFalse(manifest["nand_mutation_authorized"])
            self.assertTrue(manifest["requires_sd_present"])
            self.assertTrue(manifest["boot_artifacts_complete"])
            self.assertTrue(all(manifest["artifacts"].values()))
            self.assertEqual(
                manifest["image_sha256"], hashlib.sha256(image.read_bytes()).hexdigest()
            )
            self.assertEqual(
                manifest["boot_chain_evidence"]["sha256"],
                hashlib.sha256(donor.read_bytes()).hexdigest(),
            )
            self.assertEqual(
                manifest["runtime_provenance"]["sha256"],
                hashlib.sha256(runtime.read_bytes()).hexdigest(),
            )
            self.assertTrue(manifest["runtime_provenance"]["required_current_build"])

    def test_rejects_noncanonical_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "image.img"
            image.write_bytes(b"image")
            result = subprocess.run(
                [
                    sys.executable,
                    str(WRITER),
                    "--image",
                    str(image),
                    "--target",
                    "../am2-s19pro",
                    "--board-target",
                    "am2-s19pro",
                    "--control-board-family",
                    "zynq-bm3-am2",
                    "--native-runtime-support",
                    "management_only",
                ],
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(Path(f"{image}.manifest.json").exists())

    def test_refuses_direct_and_resolved_source_collisions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "image.img"
            donor = root / "donor.img"
            image_bytes = b"image bytes must survive"
            donor_bytes = b"donor bytes must survive"
            image.write_bytes(image_bytes)
            donor.write_bytes(donor_bytes)
            (root / "alias-parent").mkdir()

            collisions = (
                image,
                donor,
                root / "alias-parent" / ".." / image.name,
                root / "alias-parent" / ".." / donor.name,
            )
            for manifest in collisions:
                with self.subTest(manifest=manifest):
                    result = self.run_writer(image, donor, manifest)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("must not overwrite or alias", result.stderr)
                    self.assertEqual(image.read_bytes(), image_bytes)
                    self.assertEqual(donor.read_bytes(), donor_bytes)

    def test_refuses_existing_hardlinks_to_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "image.img"
            donor = root / "donor.img"
            image_bytes = b"image bytes must survive"
            donor_bytes = b"donor bytes must survive"
            image.write_bytes(image_bytes)
            donor.write_bytes(donor_bytes)

            for source in (image, donor):
                manifest = root / f"{source.name}.hardlink.json"
                os.link(source, manifest)
                with self.subTest(source=source):
                    result = self.run_writer(image, donor, manifest)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("must not overwrite or alias", result.stderr)
                    self.assertEqual(image.read_bytes(), image_bytes)
                    self.assertEqual(donor.read_bytes(), donor_bytes)

    def test_refuses_existing_symlinks_to_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "image.img"
            donor = root / "donor.img"
            image_bytes = b"image bytes must survive"
            donor_bytes = b"donor bytes must survive"
            image.write_bytes(image_bytes)
            donor.write_bytes(donor_bytes)

            links: list[Path] = []
            try:
                for source in (image, donor):
                    link = root / f"{source.name}.symlink.json"
                    link.symlink_to(source)
                    links.append(link)
            except (NotImplementedError, OSError) as error:
                self.skipTest(f"host cannot create file symlinks: {error}")

            for manifest in links:
                with self.subTest(manifest=manifest):
                    result = self.run_writer(image, donor, manifest)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("must not be a symlink", result.stderr)
                    self.assertEqual(image.read_bytes(), image_bytes)
                    self.assertEqual(donor.read_bytes(), donor_bytes)

    def test_legacy_am2_builder_exposes_both_typed_targets(self) -> None:
        builder = BUILDER.read_text(encoding="utf-8")
        for required in (
            'BOARD_TARGET="am2-s19pro"',
            'ARTIFACT_TARGET="am2-s19pro-sd"',
            'BOARD_TARGET="am2-s17p"',
            'ARTIFACT_TARGET="am2-s17p-sd"',
            'CONFIG_NAME="dcentrald_s19pro_am2_baked_default.toml"',
            'CONFIG_NAME="dcentrald_s17pro_am2_baked_default.toml"',
            '--native-runtime-support experimental',
            f"BRAIINS_IMG_SIZE={DONOR_SIZE}",
            f"BRAIINS_IMG_SHA256={DONOR_SHA256}",
            "validate_braiins_donor",
            "regular non-symlink file",
            '--runtime "$NEW_BINARY"',
            "current regular non-symlink armv7 dcentrald is required",
        ):
            self.assertIn(required, builder)
        self.assertNotIn('dcentrald/dcentrald-s19pro.toml', builder)
        self.assertNotIn("Keeping the shared base rootfs's EXISTING dcentrald", builder)
        self.assertLess(
            builder.index("current regular non-symlink armv7 dcentrald is required"),
            builder.index('WORKDIR="$(mktemp -d '),
        )
        self.assertNotIn('WORKDIR="${WORKDIR:-', builder)
        self.assertIn('WORKDIR="$(mktemp -d ', builder)
        self.assertIn(".dcentos-private-am2-workdir", builder)
        self.assertIn("trap cleanup_private_workdir EXIT", builder)
        self.assertIn(
            "DCENT_OS lab SD boot for AM2 Zynq S17 Pro / S19 Pro control boards",
            builder,
        )

    def test_builder_rejects_bad_donor_before_clearing_workdir(self) -> None:
        bash = self.bash_shell()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            donor = root / "wrong-size.img"
            donor.write_bytes(b"not the held donor")
            workdir = root / "workdir"
            workdir.mkdir()
            sentinel = workdir / "must-survive"
            sentinel.write_bytes(b"preserved")
            environment = os.environ.copy()
            environment["BRAIINS_IMG"] = donor.as_posix()
            environment["WORKDIR"] = workdir.as_posix()
            result = subprocess.run(
                [bash, BUILDER.as_posix(), "--variant", "s19pro"],
                capture_output=True,
                check=False,
                env=environment,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("donor size mismatch", result.stderr)
            self.assertEqual(sentinel.read_bytes(), b"preserved")

    def test_builder_rejects_exact_size_wrong_hash_before_clearing_workdir(self) -> None:
        bash = self.bash_shell()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            donor = root / "wrong-hash.img"
            with donor.open("wb") as handle:
                handle.seek(DONOR_SIZE - 1)
                handle.write(b"\0")
            workdir = root / "workdir"
            workdir.mkdir()
            sentinel = workdir / "must-survive"
            sentinel.write_bytes(b"preserved")
            environment = os.environ.copy()
            environment["BRAIINS_IMG"] = donor.as_posix()
            environment["WORKDIR"] = workdir.as_posix()
            result = subprocess.run(
                [bash, BUILDER.as_posix(), "--verify-donor-only"],
                capture_output=True,
                check=False,
                env=environment,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("donor SHA256 mismatch", result.stderr)
            self.assertEqual(sentinel.read_bytes(), b"preserved")

    def test_caller_workdir_is_never_a_recursive_cleanup_target(self) -> None:
        builder = BUILDER.read_text(encoding="utf-8")
        self.assertNotIn('WORKDIR="${WORKDIR:-', builder)
        self.assertNotIn('$SUDO rm -rf "$WORKDIR"', builder)
        self.assertIn('$SUDO rm -rf -- "$WORKDIR"', builder)
        self.assertLess(
            builder.index('[ -f "${WORKDIR_SENTINEL:-}" ]'),
            builder.index('$SUDO rm -rf -- "$WORKDIR"'),
        )


if __name__ == "__main__":
    unittest.main()
