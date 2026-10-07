#!/usr/bin/env python3
"""Actual signed ELF, exact held boot and distinct S17e/T17e image readback.

Run in WSL under the outer heavy lock. Keys are throwaway fixtures, and the
builder only creates regular files in a temporary directory.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import prepare_bm1396_sd_image as image
import runtime_image_manifest as runtime
import held_assets
from test_runtime_image_manifest import fixture as elf_fixture

WORKSPACE = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(WORKSPACE / "projects/dcent-toolbox/src"))
from dcent_toolbox.core import bm1396_sd_media as reader


@unittest.skipUnless(os.name == "posix", "real ARM ELF and filesystem tools require WSL")
class NativeT17eTests(unittest.TestCase):
    target = "am2-t17e"

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix=cls.target + "-image-tests-")
        cls.base = Path(cls.temporary.name)
        cls.key, cls.pubkey, cls.daemon = elf_fixture(cls.base / "elf")
        # Compile the actual supervisor programs, including their real dynamic
        # loader dependency. No target program is executed by this fixture.
        compiler = shutil.which("arm-linux-gnueabihf-gcc")
        if compiler is None:
            raise RuntimeError("ARM cross-compiler required for supervisor fixture")
        cls.supervisor_helpers = {}
        for name in ("dcentos-deploy-lock", "dcentos-deploy-path"):
            source = image.PROJECT / "br2_external_dcentos/packages" / name / "src" / (name + ".c")
            output = cls.base / name
            subprocess.run([compiler, "-Os", "-s", "-Wl,-z,max-page-size=4096", str(source),
                            "-o", str(output)], check=True, capture_output=True, timeout=60)
            cls.supervisor_helpers[name] = output
        cls.supervisor_libraries = {}
        for name in ("libc.so.6", "ld-linux-armhf.so.3"):
            source = Path(subprocess.check_output([compiler, "-print-file-name=" + name], text=True).strip())
            if not source.is_file():
                raise RuntimeError("actual ARM supervisor library unavailable: " + name)
            cls.supervisor_libraries[name] = source
        cls.donor = held_assets.held_root(WORKSPACE, os.environ.get("DCENT_HELD_ROOT")) / (
            "extractions/asicminingsupplies/" + cls.target.removeprefix("am2-") + "-om-20210108/fw")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=self.base)
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root, self.binaries = self.directory / "root", self.directory / "binaries"
        self.binaries.mkdir()
        for name in ("dcentrald", "dcentos-init", "dcentos-discovery"):
            shutil.copyfile(self.daemon, self.binaries / name)
        for name in ("etc/dcentos", "etc/init.d", "usr/local/bin", "usr/bin", "sbin", "data", "root",
                     "usr/share/dcentos-dashboard", "etc/default", "etc/dcentrald", "usr/sbin", "usr/libexec/dcentos"):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        (self.root / "etc/dcentos/board_target").write_text("am2-s19j\n")
        (self.root / "etc/dcentos/platform").write_text("zynq-bm3-am2\n")
        (self.root / "etc/dcentos-version").write_text("1.2.3\n")
        (self.root / "etc/shadow").write_text("root:!:0:0:99999:7:::\n")
        shutil.copyfile(self.daemon, self.root / runtime.DAEMON)
        for name, source in self.supervisor_helpers.items():
            destination = self.root / "usr/libexec/dcentos" / name
            shutil.copyfile(source, destination)
            destination.chmod(0o755)
        (self.root / "lib").mkdir()
        for name, source in self.supervisor_libraries.items():
            destination = self.root / "lib" / ("libc-fixture.so" if name == "libc.so.6" else name)
            shutil.copyfile(source, destination)
            destination.chmod(0o755)
        (self.root / "lib/libc.so.6").symlink_to("libc-fixture.so")
        for name in ("rcS", "rcK", "S16foreign_gpio", "S15pic_boot", "S37board_setup", "S99upgrade", "S99verify"):
            (self.root / "etc/init.d" / name).write_text("#!/bin/sh\nexit 0\n")
        html = b"<html>temporary signed dashboard fixture</html>\n" * 4096
        self.dashboard = self.directory / "dashboard"
        self.dashboard.mkdir()
        for name, content in (("index.html", html), ("index.html.gz", gzip.compress(html)),
                              ("index.html.sha256", hashlib.sha256(html).hexdigest().encode() + b"\n")):
            (self.dashboard / name).write_bytes(content)
        runtime.prepare(self.root, "am2-s19j", "beta", "1.2.3", self.key, self.pubkey)
        self.environment = patch.dict(os.environ, {"DCENT_RELEASE_SIGNING_KEY": str(self.key),
            "DCENT_RELEASE_PUBKEY_FILE": str(self.pubkey), "DCENT_RELEASE_CHANNEL": "beta",
            "DCENT_RELEASE_DASHBOARD_DIR": str(self.dashboard)})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def prepare(self, target=None):
        target = self.target if target is None else target
        return image.prepare_root(self.root, target, self.binaries,
            "bcab06bb-4bda-5925-b107-1803a28f1a31", image.DATA_UUIDS[target])

    def test_fresh_root_binds_exact_model_and_both_daemon_consumers(self):
        self.prepare()
        self.assertTrue((self.root / runtime.DAEMON).samefile(self.root / "usr/bin/dcentrald"))
        self.assertEqual((self.root / runtime.DAEMON).stat().st_nlink, 2)
        document = runtime.verify(self.root, self.target, "beta", "1.2.3", self.pubkey)
        self.assertEqual(document["board_target"], self.target)
        config = reader.tomllib.loads((self.root / "etc/dcentrald.toml").read_text())
        self.assertEqual(config["mining"]["model"], self.target.removeprefix("am2-"))
        self.assertEqual(config["mining"]["serial_chip_count"], 135 if self.target == "am2-s17e" else 78)
        self.assertEqual(config["mining"]["frequency_mhz"], 530 if self.target == "am2-s17e" else 300)
        self.assertFalse(config["mining"]["enabled"])
        self.assertEqual((self.root / "etc/dcentos/mutation_policy").read_bytes(), b"boot-safeoff\ndaemon-hardware\n")
        for name in ("S16foreign_gpio", "S15pic_boot", "S37board_setup", "S99upgrade", "S99verify"):
            self.assertFalse((self.root / "etc/init.d" / name).exists())
        self.assertEqual({p.name for p in (self.root / "etc/init.d").iterdir()},
                         set(image.CURRENT_SERVICES) | set(image.OWN_SERVICES))
        self.assertEqual((self.root / "root/web/server.py").read_bytes(),
                         (image.ZYNQ_OVERLAY / "root/web/server.py").read_bytes())
        self.assertIn("--bm1396-boot-cut-only", (self.root / "etc/init.d/S12fpga_identity").read_text())
        self.assertIn('DAEMON="/usr/local/bin/dcentrald"', (self.root / "etc/init.d/S82dcentrald").read_text())
        supervisor = (self.root / "etc/init.d/S82dcentrald").read_text()
        self.assertIn('case "$BOARD_TARGET" in am2-t17e|am2-s17e)', supervisor)

    def test_sibling_data_identity_and_legacy_s17_alias_are_refused(self):
        sibling = "am2-s17e" if self.target == "am2-t17e" else "am2-t17e"
        with self.assertRaisesRegex(ValueError, "exact target/layout data UUID"):
            image.prepare_root(self.root, self.target, self.binaries,
                "bcab06bb-4bda-5925-b107-1803a28f1a31", image.DATA_UUIDS[sibling])
        with self.assertRaisesRegex(ValueError, "exact S17e or T17e"):
            reader.native_contents(b"", "am2-s17")
        self.prepare()
        # The fresh carrier exception is deliberately not a sibling converter.
        with self.assertRaisesRegex(ValueError, "selected BM1396"):
            self.prepare(sibling)

    def verify_producer_handoff(self, artifact):
        from test_release_native_sd import NativeReleaseTests
        return NativeReleaseTests.verify_producer_handoff(self, artifact, self.target)

    def test_missing_supervisor_program_or_dynamic_dependency_refuses_before_mutation(self):
        marker = (self.root / "etc/dcentos/board_target").read_bytes()
        for name in ("usr/libexec/dcentos/dcentos-deploy-lock",
                     "usr/libexec/dcentos/dcentos-deploy-path",
                     "lib/ld-linux-armhf.so.3", "lib/libc-fixture.so"):
            with self.subTest(name=name):
                path = self.root / name
                saved = path.read_bytes()
                path.unlink()
                with self.assertRaisesRegex(ValueError, "missing|dependency"):
                    self.prepare()
                self.assertEqual((self.root / "etc/dcentos/board_target").read_bytes(), marker)
                path.write_bytes(saved)
                path.chmod(0o755)

    def test_unsigned_changed_or_personal_carrier_is_refused(self):
        marker = (self.root / "etc/dcentos/board_target").read_bytes()
        (self.root / runtime.DAEMON).write_bytes(self.daemon.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "digest/size"):
            self.prepare()
        self.assertEqual((self.root / "etc/dcentos/board_target").read_bytes(), marker)
        shutil.copyfile(self.daemon, self.root / runtime.DAEMON)
        (self.root / "data/dcentrald.toml").write_text("[mining]\nenabled=true\n")
        with self.assertRaisesRegex(ValueError, "persistent/image override"):
            self.prepare()

    def test_missing_key_and_lab_identity_refused_before_composition(self):
        with patch.dict(os.environ, {"DCENT_RELEASE_SIGNING_KEY": ""}):
            with self.assertRaisesRegex(ValueError, "explicit signing key"):
                self.prepare()
        _, _, lab = elf_fixture(self.directory / "lab", lab=True, key_hex=runtime.public_key_bytes(self.pubkey).hex())
        shutil.copyfile(lab, self.binaries / "dcentrald")
        with self.assertRaisesRegex(ValueError, "lab|sim|recovery"):
            self.prepare()

    def test_real_file_image_independent_reader_and_authenticated_negatives(self):
        carrier = self.directory / "carrier.squashfs"
        subprocess.run(["mksquashfs", str(self.root), str(carrier), "-noappend", "-comp", "gzip",
                        "-processors", "2", "-no-progress", "-all-root"], check=True, capture_output=True)
        output = self.directory / "output"
        result = subprocess.run(["sh", str(Path(__file__).with_name("build_sd_bm1396.sh")), self.target,
            str(self.donor), str(carrier), str(self.binaries), str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout[-6000:] + result.stderr[-6000:])
        artifact = output / "dcentos-sd.img"
        signature = Path(str(artifact) + ".sig")
        runtime.openssl("pkeyutl", "-sign", "-rawin", "-inkey", self.key, "-in", artifact, "-out", signature)
        def validate(**overrides):
            options = dict(version="1.2.3", channel="beta", pubkey=self.pubkey)
            options.update(overrides)
            return reader.validate_bm1396_image(artifact, self.target, **options)
        observed = validate()
        # L04 ordinary SD install uses the same authenticated current reader,
        # including the distinct T17e producer. No historical schema fallback.
        from dcent_toolbox.core.sd_first_install import plan_sd_first_install
        with patch.dict(os.environ, {"DCENT_RELEASE_PUBKEY_FILE": str(self.pubkey),
                                     "DCENT_RELEASE_PUBKEY_HEX": ""}):
            plan = plan_sd_first_install("am2-t17e", artifact, dry_run=True,
                                         release_version="1.2.3")
            self.assertEqual(plan["sd_first_state"], "dry_run_ready", plan)
            self.assertEqual(plan["proof_scope"], "signed_image_and_exact_boot_root_identity")
            self.assertTrue(plan["build_plan"]["release_authentication_verified"])
            refused = plan_sd_first_install("am2-t17e", artifact, dry_run=True,
                                            release_version="1.2.4")
            self.assertEqual(refused["sd_first_state"], "payload_invalid", refused)
        # Exercise the real source-bound signed producer-result boundary, not
        # just the family reader. This uses the separate T17e reader dispatch.
        from test_release_native_sd import NativeReleaseTests
        def handoff():
            return NativeReleaseTests.verify_producer_handoff(self, artifact, "am2-t17e")
        handoff()
        self.assertTrue(observed["qualified_full_candidate"])
        self.assertTrue(observed["release_authentication_verified"])
        self.assertFalse(observed["nand_writes"])
        self.assertEqual(observed["physical_qualification"], "pending")
        self.verify_producer_handoff(artifact)
        self.assertIn(self.target.removeprefix("am2-").upper().replace("E", "e"),
                      (output / "TESTER_README.txt").read_text())
        with self.assertRaises(ValueError):
            validate(version="1.2.4")
        with self.assertRaises(ValueError):
            validate(channel="unsupported")
        saved = signature.read_bytes()
        signature.write_bytes(bytes([saved[0] ^ 1]) + saved[1:])
        with self.assertRaisesRegex(ValueError, "signature"):
            validate()
        signature.write_bytes(saved)
        pair = Path(str(artifact) + ".runtime-image.json")
        saved = pair.read_bytes()
        sibling = "am2-s17e" if self.target == "am2-t17e" else "am2-t17e"
        pair.write_bytes(saved.replace(self.target.encode(), sibling.encode()))
        with self.assertRaisesRegex(ValueError, "exported runtime"):
            validate()
        pair.write_bytes(saved)
        # Even a newly signed card must retain the real executable supervisor.
        # Rebuild only the ext2 bytes after deleting a helper, then sign the
        # actual altered image. The independent reader must reject its root.
        original_image = artifact.read_bytes()
        original_manifest = Path(str(artifact) + ".manifest.json").read_bytes()
        original_signature = signature.read_bytes()
        root_start, root_count, _ = reader.PARTITIONS[1]
        damaged_root = self.directory / "missing-supervisor.ext2"
        damaged_root.write_bytes(original_image[root_start * 512:(root_start + root_count) * 512])
        subprocess.run(["debugfs", "-w", "-R", "rm /usr/libexec/dcentos/dcentos-deploy-lock",
                        str(damaged_root)], check=True, capture_output=True)
        damaged_image = bytearray(original_image)
        damaged_image[root_start * 512:(root_start + root_count) * 512] = damaged_root.read_bytes()
        artifact.write_bytes(damaged_image)
        manifest_path = Path(str(artifact) + ".manifest.json")
        document = json.loads(original_manifest)
        document["image_sha256"] = hashlib.sha256(damaged_image).hexdigest()
        manifest_path.write_text(json.dumps(document))
        runtime.openssl("pkeyutl", "-sign", "-rawin", "-inkey", self.key, "-in", artifact, "-out", signature)
        with self.assertRaisesRegex(ValueError, "dcentos-deploy-lock"):
            validate()
        with self.assertRaisesRegex(ValueError, "dcentos-deploy-lock"):
            self.verify_producer_handoff(artifact)
        artifact.write_bytes(original_image)
        manifest_path.write_bytes(original_manifest)
        signature.write_bytes(original_signature)
        # A valid release signature cannot admit sibling configuration into a
        # root with this target's signed daemon identity and boot commands.
        damaged_root.write_bytes(original_image[root_start * 512:(root_start + root_count) * 512])
        wrong_config = self.directory / "sibling.toml"
        wrong_config.write_bytes((image.PROJECT / "dcentrald/configs/beta" /
                                  (sibling + "-baked-default.toml")).read_bytes())
        for command in ("rm /etc/dcentrald.toml", "write " + str(wrong_config) + " /etc/dcentrald.toml"):
            subprocess.run(["debugfs", "-w", "-R", command, str(damaged_root)],
                           check=True, capture_output=True)
        damaged_image = bytearray(original_image)
        damaged_image[root_start * 512:(root_start + root_count) * 512] = damaged_root.read_bytes()
        artifact.write_bytes(damaged_image)
        document = json.loads(original_manifest)
        document["image_sha256"] = hashlib.sha256(damaged_image).hexdigest()
        manifest_path.write_text(json.dumps(document))
        runtime.openssl("pkeyutl", "-sign", "-rawin", "-inkey", self.key, "-in", artifact, "-out", signature)
        with self.assertRaisesRegex(ValueError, "exact BM1396 model"):
            validate()
        artifact.write_bytes(original_image)
        manifest_path.write_bytes(original_manifest)
        signature.write_bytes(original_signature)
        # The manifest is only a parser hint. Even with the valid original
        # image signature, it cannot retarget the exact boot command line.
        document = json.loads(original_manifest)
        document.update(board_target=sibling, target=sibling + "-sd-standalone")
        manifest_path.write_text(json.dumps(document))
        with self.assertRaisesRegex(ValueError, "target-specific BM1396 SD boot"):
            reader.validate_bm1396_image(artifact, sibling, version="1.2.3", channel="beta", pubkey=self.pubkey)
        manifest_path.write_bytes(original_manifest)
        # A trusted signature cannot substitute a sibling FPGA payload.
        raw = bytearray(artifact.read_bytes())
        boot = (output / "BOOT.BIN").read_bytes()
        at = raw.find(boot)
        self.assertGreater(at, 0)
        raw[at + 100] ^= 1
        artifact.write_bytes(raw)
        manifest = Path(str(artifact) + ".manifest.json")
        document = json.loads(manifest.read_text())
        document["image_sha256"] = hashlib.sha256(raw).hexdigest()
        manifest.write_text(json.dumps(document))
        runtime.openssl("pkeyutl", "-sign", "-rawin", "-inkey", self.key, "-in", artifact, "-out", signature)
        with self.assertRaisesRegex(ValueError, "boot input"):
            validate()
        with self.assertRaisesRegex(ValueError, "boot input"):
            self.verify_producer_handoff(artifact)


class NativeS17eTests(NativeT17eTests):
    target = "am2-s17e"


if __name__ == "__main__":
    unittest.main()
