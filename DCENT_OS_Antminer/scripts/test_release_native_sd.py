#!/usr/bin/env python3
"""Fresh signed root composition and real pinned native SD media readback.

Run under the outer heavy lock on Linux. Temporary roots use real production
ELF identity and throwaway signing keys. No service or firmware is executed.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from held_assets import held_root
import prepare_release_am2_boot
import release_native_sd as native
import release_producer
import release_runtime_exports as exports
import runtime_image_manifest as runtime
from dcent_toolbox.core.current_native_release import validate_current_native_release
from dcent_toolbox.core import bm1391_sd_media, c43_native_image, current_native_release as current, zynq_native_sd_card
from dcent_toolbox.core.squashfs_files import SquashfsFiles
from test_runtime_image_manifest import fixture as elf_fixture
from test_release_am2_boot_reproduction import pinned_mkimage


def supervisor_helpers_fixture(directory: Path) -> dict[str, Path]:
    """Compile the actual two production C helpers for ARM, without executing them."""
    compiler = shutil.which("arm-linux-gnueabihf-gcc")
    if compiler is None:
        raise RuntimeError("ARM cross-compiler required for real native supervisor fixture")
    directory.mkdir()
    result = {}
    for name in ("dcentos-deploy-lock", "dcentos-deploy-path"):
        source = native.PROJECT / "br2_external_dcentos/packages" / name / "src" / (name + ".c")
        output = directory / name
        completed = subprocess.run([compiler, "-Os", "-s", "-Wl,-z,max-page-size=4096",
                                    str(source), "-o", str(output)], capture_output=True, timeout=60)
        if completed.returncode:
            raise RuntimeError("ARM supervisor fixture compile failed: " + completed.stderr.decode(errors="replace"))
        result[name] = output
    return result


class NativeReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="native-release-test-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.base = Path(cls.temporary.name)
        cls.key, cls.pubkey, cls.daemon = elf_fixture(cls.base / "elf")
        cls.supervisor_helpers = supervisor_helpers_fixture(cls.base / "supervisor")
        # This fixture validates packaging, never dispatches a C43 command. The
        # historical import preflight checks this CLI spelling in addition to
        # the real production identity retained in the ELF.
        cls.daemon.write_bytes(cls.daemon.read_bytes() + b"--c43-boot-cut-only")
        cls.assets = held_root(native.WORKSPACE)

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
        (self.root / "etc/dcentos/board_target").write_text("am1-s9\n")
        (self.root / "etc/dcentos-version").write_text("1.2.3\n")
        (self.root / "etc/shadow").write_text("root:!:0:0:99999:7:::\n")
        shutil.copyfile(self.daemon, self.root / runtime.DAEMON)
        for name, source in self.supervisor_helpers.items():
            destination = self.root / "usr/libexec/dcentos" / name
            shutil.copyfile(source, destination)
            destination.chmod(0o755)
        # The actual ARM C helpers use glibc. Copy their real cross-toolchain
        # loader/libc into this private carrier, with the usual in-root alias.
        (self.root / "lib").mkdir()
        compiler = shutil.which("arm-linux-gnueabihf-gcc")
        for name in ("libc.so.6", "ld-linux-armhf.so.3"):
            source = subprocess.check_output([compiler, "-print-file-name=" + name], text=True).strip()
            if not Path(source).is_file():
                raise RuntimeError("real ARM fixture library missing: " + name)
            shutil.copyfile(source, self.root / "lib" / ("libc-fixture.so" if name == "libc.so.6" else name))
            (self.root / "lib" / ("libc-fixture.so" if name == "libc.so.6" else name)).chmod(0o755)
        os.symlink("libc-fixture.so", self.root / "lib/libc.so.6")
        for name in ("rcS", "rcK", *native.assets.BASE_SERVICES, *native.assets.SOURCE_SERVICES, *native.assets.OWN_SERVICES,
                     "S15pic_boot", "S37board_setup", "S99upgrade", "S99verify"):
            (self.root / "etc/init.d" / name).write_text("#!/bin/sh\nexit 0\n")
        html = b"<html>temporary dashboard fixture</html>\n" * 4096
        for name, content in (("index.html", html), ("index.html.gz", gzip.compress(html)),
                              ("index.html.sha256", hashlib.sha256(html).hexdigest().encode() + b"\n")):
            (self.root / "usr/share/dcentos-dashboard" / name).write_bytes(content)
        runtime.prepare(self.root, "am1-s9", "beta", "1.2.3", self.key, self.pubkey)
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {"DCENT_RELEASE_SIGNING_KEY": str(self.key), "DCENT_RELEASE_PUBKEY_FILE": str(self.pubkey),
                                "DCENT_RELEASE_CHANNEL": "beta", "DCENT_RELEASE_HARDWARE_RECIPE": "board-default"}).start()

    def prepare(self, board):
        self.base_for(self.root, board)
        return native.prepare_root(self.root, board, self.binaries)

    def test_directory_preflight_requires_program_closure_before_shell_install(self):
        root = current.DirectoryRoot(self.root)
        observed = current.supervisor_dependencies(root, require_scripts=False)
        self.assertEqual(set(observed), {*current.SUPERVISOR_PROGRAMS,
                                        "lib/libc-fixture.so", "lib/ld-linux-armhf.so.3"})
        with self.assertRaises(ValueError):
            current.supervisor_dependencies(root)
        # The initial carrier may lack source-owned scripts that prepare_root
        # installs later, but that flag never permits absent C/runtime bytes.
        for name in (*current.SUPERVISOR_PROGRAMS, "lib/libc-fixture.so", "lib/ld-linux-armhf.so.3"):
            path = self.root / name
            raw, mode = path.read_bytes(), path.stat().st_mode & 0o7777
            path.unlink()
            try:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    current.supervisor_dependencies(root, require_scripts=False)
            finally:
                path.write_bytes(raw)
                path.chmod(mode)

    def base_for(self, root, board):
        if board.startswith("am2-"):
            (root / "etc/dcentos/board_target").write_text("am2-s19j\n")
            (root / "etc/dcentos/platform").write_text("zynq-bm3-am2\n")
            runtime.prepare(root, "am2-s19j", "beta", "1.2.3", self.key, self.pubkey)

    def boot(self, board):
        output = self.directory / "boot-inputs"
        producer = exports.producer_for(board)
        if producer.runtime_root == "partition2-squashfs":
            # Same pinned tool as the producer and blocking gate #70 — never a
            # PATH lookup, so this suite cannot diverge from the capsule again.
            prepare_release_am2_boot.prepare(self.assets / "firmware-archive/braiins-os_am2-s17_sd.img", output,
                                             mkimage=str(pinned_mkimage()))
        elif producer.runtime_root == "fat-ramdisk":
            output.mkdir()
            for name, source in (("BOOT.BIN", "sd_recovery_BOOT.BIN"), ("devicetree.dtb", "s9_devicetree.dtb"),
                                 ("kernel.bin", "kernel.bin"), ("mtd2_fpga1.bin", "mtd2_fpga1.bin")):
                shutil.copyfile(self.assets / "extractions/s9" / source, output / name)
        else:
            source = "extractions/s9se/inner" if board in ("am1-s9se", "am1-s9k") else "extractions/mskminers/s15-1.2.2-sd/bin"
            output.mkdir()
            for name in ("BOOT.bin", "uImage", "devicetree.dtb"):
                shutil.copyfile(self.assets / source / name, output / name)
        return output

    def sign_and_validate(self, artifact, board):
        native.command("openssl", "pkeyutl", "-sign", "-rawin", "-inkey", self.key,
                       "-in", artifact, "-out", Path(str(artifact) + ".sig"))
        return validate_current_native_release(artifact, board, version="1.2.3", channel="beta", pubkey=self.pubkey)

    def verify_producer_handoff(self, artifact, board):
        producer = exports.producer_for(board)
        source_commit = "a" * 40
        document = release_producer.create_result(
            artifact.parent, producer, source_commit, "1.2.3", "beta", artifact.name,
            [artifact.name + ".manifest.json", "TESTER_README.txt"])
        attestation = artifact.parent / "producer-result.json"
        attestation.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
        native.command("openssl", "pkeyutl", "-sign", "-rawin", "-inkey", self.key,
                       "-in", attestation, "-out", Path(str(attestation) + ".sig"))
        for name in ("producer-result.json", "producer-result.json.sig"):
            document["ancillary"].append(release_producer.file_record(artifact.parent, name))
        return release_producer.verify_result(document, artifact.parent, producer,
                                              source_commit, "1.2.3", "beta", self.pubkey)

    def test_all_current_roots_keep_exact_identity_and_alias(self):
        for row in release_producer.list_producers():
            if row.board_target not in current.TARGETS:
                continue
            with self.subTest(board=row.board_target), tempfile.TemporaryDirectory(dir=self.directory) as temporary:
                root = Path(temporary) / "root"
                shutil.copytree(self.root, root, symlinks=True)
                self.base_for(root, row.board_target)
                native.prepare_root(root, row.board_target, self.binaries)
                self.assertEqual(runtime.verify(root, row.board_target, "beta", "1.2.3", self.pubkey)["board_target"], row.board_target)
                self.assertTrue((root / runtime.DAEMON).samefile(root / "usr/bin/dcentrald"))
                self.assertEqual((root / runtime.DAEMON).stat().st_nlink, 2)
                self.assertFalse((root / "etc/init.d/S99upgrade").exists())
                self.assertEqual((root / "etc/dcentos/mutation_policy").read_bytes(), b"boot-safeoff\ndaemon-hardware\n")
                config = (root / "etc/dcentrald.toml").read_text()
                mining = re.findall(r"(?ms)^\[mining\]\s*\n(.*?)(?=^\[|\Z)", config)
                self.assertEqual(len(mining), 1)
                self.assertEqual(re.findall(r"(?m)^enabled\s*=\s*(\w+)\s*$", mining[0]), ["false"])

    def test_unsigned_or_changed_carrier_refused_before_native_mutation(self):
        (self.root / runtime.DAEMON).write_bytes(self.daemon.read_bytes() + b"changed")
        before = (self.root / "etc/dcentos/board_target").read_bytes()
        with self.assertRaisesRegex(ValueError, "digest/size"):
            self.prepare("am1-s9i")
        self.assertEqual((self.root / "etc/dcentos/board_target").read_bytes(), before)

    def test_persistent_personal_override_refused(self):
        (self.root / "data/dcentrald.toml").write_text("[mining]\nenabled = true\n")
        with self.assertRaisesRegex(ValueError, "persistent/personal"):
            self.prepare("am2-s17p")

    def test_xil25_nand_bake_seed_is_stripped_from_removable_media(self):
        # The s19jpro-base post-build stages the operator's XIL .25 seed for
        # the s19jpro first-install flow; BM1398 native siblings build from
        # that base and must never ship it on removable media (run
        # drop1-20260921-l16b8n18: the release validator refused the seed).
        seed = self.root / "etc/dcentos/xil-seed"
        seed.mkdir(parents=True)
        # The four entries the s19jpro post-build actually stages: the
        # SHA-pinned launcher copy plus the three seed payload files.
        (seed / "dcentrald_standalone_boot.sh").write_text("#!/bin/sh\nexit 0\n")
        (seed / "dcentrald.toml").write_text("[mining]\nenabled = true\n")
        (seed / "dcentrald.toml.mgmt-bak").write_text("[mining]\nenabled = false\n")
        (seed / "dcentrald-env").write_text("DCENT_XIL25=1\n")
        (self.root / "usr/local/bin/dcentrald_standalone_boot.sh").write_text(
            "#!/bin/sh\nEXPECTED_DCENTRALD_SHA256=\"fixture\"\n")
        (self.root / "etc/init.d/S81dcentos-xil-seed").write_text("#!/bin/sh\nexit 0\n")
        # The XIL-bake declarations the s19j overlay/post-build stamps: the
        # psu_config G5 hint plus the tuning files (critic H, run-23 follow-up).
        (self.root / "etc/dcentos/psu_config").write_text("override\n")
        (self.root / "etc/dcentos/rail_gpio").write_text("MIO44\n")
        (self.root / "etc/dcentos/partial_yield_floor").write_text("22\n")
        (self.root / "etc/dcentos/fan_max_pwm").write_text("30\n")
        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            directory = Path(temporary)
            root = directory / "root"
            shutil.copytree(self.root, root, symlinks=True)
            self.base_for(root, "am2-s19")
            native.prepare_root(root, "am2-s19", self.binaries)
            for removed in ("etc/dcentos/xil-seed", "usr/local/bin/dcentrald_standalone_boot.sh",
                            "etc/init.d/S81dcentos-xil-seed", "etc/dcentos/psu_config",
                            "etc/dcentos/rail_gpio", "etc/dcentos/partial_yield_floor",
                            "etc/dcentos/fan_max_pwm"):
                self.assertFalse((root / removed).exists(), removed)
            inputs = self.boot("am2-s19")
            artifact = native.assemble(root, directory / "images", "am2-s19", inputs)
            candidate = self.sign_and_validate(artifact, "am2-s19")
            self.assertEqual(candidate["board_target"], "am2-s19")
            self.assertEqual(self.verify_producer_handoff(artifact, "am2-s19")["board_target"], "am2-s19")

    def test_xil25_seed_on_any_other_base_refused_as_contamination(self):
        # Only the s19j base stages the seed; on any other base its presence
        # means a mis-wired post-build and must fail the build instead of
        # being silently cleaned (critics G+H on the run-23 strip fix).
        (self.root / "etc/dcentos/xil-seed").mkdir(parents=True)
        (self.root / "etc/dcentos/xil-seed/dcentrald.toml").write_text("[mining]\nenabled = true\n")
        with self.assertRaisesRegex(ValueError, "unexpected XIL .25 seed staging"):
            self.prepare("am1-s9i")

    def test_foreign_psu_declaration_refused_by_release_validator(self):
        # Emulates a strip regression: a stale psu_config="override" riding a
        # finished artifact must fail release validation (toolbox forbidden
        # list), never ship to a BETA card where preflight would report it.
        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            directory = Path(temporary)
            root = directory / "root"
            shutil.copytree(self.root, root, symlinks=True)
            self.base_for(root, "am2-s19")
            native.prepare_root(root, "am2-s19", self.binaries)
            (root / "etc/dcentos/psu_config").write_text("override\n")
            inputs = self.boot("am2-s19")
            artifact = native.assemble(root, directory / "images", "am2-s19", inputs)
            with self.assertRaisesRegex(ValueError, "persistent/foreign/NAND override: etc/dcentos/psu_config"):
                self.sign_and_validate(artifact, "am2-s19")

    def test_foreign_standalone_boot_launcher_refused_by_release_validator(self):
        # Second-wall coverage for the XIL .25 seed launcher: prepare strips
        # it on the am2-s19j base and refuses it on every other base; a
        # replanted copy riding a finished artifact must also fail the
        # toolbox validator (critics M+N fold, run-24 cycle).
        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            directory = Path(temporary)
            root = directory / "root"
            shutil.copytree(self.root, root, symlinks=True)
            self.base_for(root, "am2-s19")
            native.prepare_root(root, "am2-s19", self.binaries)
            (root / "usr/local/bin/dcentrald_standalone_boot.sh").write_text("#!/bin/sh\nexit 0\n")
            inputs = self.boot("am2-s19")
            artifact = native.assemble(root, directory / "images", "am2-s19", inputs)
            with self.assertRaisesRegex(
                    ValueError, "persistent/foreign/NAND override: usr/local/bin/dcentrald_standalone_boot.sh"):
                self.sign_and_validate(artifact, "am2-s19")

    def test_real_media_composition_uses_all_four_exact_native_layouts(self):
        for board in ("am1-s9i", "am2-s17p", "am1-s9se", "am1-s15"):
            with self.subTest(board=board), tempfile.TemporaryDirectory(dir=self.directory) as temporary:
                directory = Path(temporary)
                root = directory / "root"
                shutil.copytree(self.root, root, symlinks=True)
                self.base_for(root, board)
                native.prepare_root(root, board, self.binaries)
                inputs = self.boot(board)
                try:
                    artifact = native.assemble(root, directory / "images", board, inputs)
                    document = exports.verify_artifact_runtime(artifact, Path(str(artifact) + ".runtime-image.json"),
                                  Path(str(artifact) + ".runtime-image.sig"), self.pubkey, board, "beta", "1.2.3", "board-default")
                    self.assertEqual(document["daemon_sha256"], hashlib.sha256(self.daemon.read_bytes()).hexdigest())
                    self.assertTrue(Path(str(artifact) + ".manifest.json").is_file())
                    self.assertIn("not a NAND installer", (artifact.parent / "TESTER_README.txt").read_text())
                    candidate = self.sign_and_validate(artifact, board)
                    self.assertTrue(candidate["qualified_full_candidate"])
                    self.assertTrue(candidate["release_authentication_verified"])
                    self.assertEqual(candidate["physical_qualification"], "pending")
                    # Exercise the ordinary Toolbox install consumer against
                    # these actual producer bytes, including its trust join.
                    from dcent_toolbox.core.sd_first_install import plan_sd_first_install
                    with patch.dict(os.environ, {"DCENT_RELEASE_PUBKEY_FILE": str(self.pubkey),
                                                 "DCENT_RELEASE_PUBKEY_HEX": ""}):
                        plan = plan_sd_first_install(board, artifact, dry_run=True,
                                                     release_version="1.2.3")
                        self.assertEqual(plan["sd_first_state"], "dry_run_ready", plan)
                        self.assertEqual(plan["proof_scope"], "signed_image_and_exact_boot_root_identity")
                        self.assertTrue(plan["build_plan"]["release_authentication_verified"])
                        refused = plan_sd_first_install(board, artifact, dry_run=True,
                                                        release_version="1.2.4")
                        self.assertEqual(refused["sd_first_state"], "payload_invalid", refused)
                    self.assertEqual(self.verify_producer_handoff(artifact, board)["board_target"], board)
                    # The old checkpoint entry points cannot accept the new
                    # schema even though this current image verifies above.
                    old = (c43_native_image.validate_native_c43_image if board == "am1-s9se" else
                           bm1391_sd_media.validate_bm1391_image if board == "am1-s15" else
                           zynq_native_sd_card.validate_zynq_native_card)
                    with self.assertRaises(ValueError):
                        old(artifact, board)
                    with self.assertRaises(ValueError):
                        validate_current_native_release(artifact, board, version="1.2.4", channel="beta", pubkey=self.pubkey)
                    signature = Path(str(artifact) + ".sig")
                    saved = signature.read_bytes()
                    signature.write_bytes(bytes([saved[0] ^ 1]) + saved[1:])
                    with self.assertRaisesRegex(ValueError, "signature"):
                        validate_current_native_release(artifact, board, version="1.2.3", channel="beta", pubkey=self.pubkey)
                    signature.write_bytes(saved)
                    with self.assertRaisesRegex(ValueError, "preserve prior"):
                        native.assemble(root, directory / "images", board, inputs)
                finally:
                    shutil.rmtree(inputs)

    def test_five_bm1398_profiles_roundtrip_exact_defaults_and_signed_producer_handoff(self):
        expected = (
            ("am2-s19pro", "s19pro", 114, 500, 12800),
            ("am2-s19", "s19", 76, 650, 13800),
            ("am2-t19", "t19", 76, 550, 14200),
            ("am2-s19a", "s19a", 72, 660, 12800),
            ("am2-s19plus", "s19plus", 80, 645, 14000),
        )
        for board, model, chips, frequency, voltage in expected:
            with self.subTest(board=board), tempfile.TemporaryDirectory(dir=self.directory) as temporary:
                directory = Path(temporary)
                root = directory / "root"
                shutil.copytree(self.root, root, symlinks=True)
                self.base_for(root, board)
                native.prepare_root(root, board, self.binaries)
                inputs = self.boot(board)
                try:
                    artifact = native.assemble(root, directory / "images", board, inputs)
                    self.assertEqual(artifact.name, release_producer.get_producer(board).primary_artifact)
                    candidate = self.sign_and_validate(artifact, board)
                    self.assertEqual(candidate["board_target"], board)
                    self.assertTrue(candidate["release_authentication_verified"])
                    self.assertEqual(candidate["physical_qualification"], "pending")
                    self.assertFalse(candidate["nand_writes"])
                    self.assertEqual(self.verify_producer_handoff(artifact, board)["board_target"], board)
                    decoded, _, artifacts, _, _ = current.native_contents(artifact.read_bytes(), board)
                    config = current.tomllib.loads(decoded.read("etc/dcentrald.toml", 65536).decode())
                    self.assertEqual(tuple(config["mining"][key] for key in
                                           ("model", "serial_chip_count", "frequency_mhz", "voltage_mv")),
                                     (model, chips, frequency, voltage))
                    self.assertIs(config["mining"]["enabled"], False)
                    self.assertIs(config["api"]["cgminer_bind_lan"], True)
                    self.assertIs(config["api"]["cgminer_lan_writes"], False)
                    self.assertLessEqual(len(artifacts["rootfs.squashfs"]), 179 * 126976)
                    # A signed image for one exact SKU cannot be selected as a sibling.
                    sibling = "am2-s19" if board != "am2-s19" else "am2-t19"
                    with self.assertRaises(ValueError):
                        validate_current_native_release(artifact, sibling, version="1.2.3",
                                                        channel="beta", pubkey=self.pubkey)
                finally:
                    # boot() creates an ordinary directory in this test's own
                    # private root; no mount or host /data participates.
                    shutil.rmtree(inputs)

    def test_bm1398_oversized_root_refused_by_producer_and_independent_reader(self):
        board = "am2-s19plus"
        self.prepare(board)
        # Deterministic incompressible fixture exceeds 179 LEB while still
        # fitting the removable-media partition. This is not a release build.
        ballast = self.root / "usr/share/rootfs-budget-fixture.bin"
        ballast.write_bytes(hashlib.shake_256(b"BM1398 rootfs overflow fixture").digest(179 * 126976))
        inputs = self.boot(board)
        images = self.directory / "images"
        with self.assertRaisesRegex(ValueError, "179-LEB"):
            native.assemble(self.root, images, board, inputs)
        self.assertFalse(any(images.glob("*.img")))
        # Only bypass the producer budget check to manufacture a validly
        # signed oversized candidate for the separate consumer to reject.
        with patch.object(native.current_release, "check_rootfs_size"):
            artifact = native.assemble(self.root, images, board, inputs)
        with self.assertRaisesRegex(ValueError, "179-LEB"):
            self.sign_and_validate(artifact, board)

    def test_missing_or_foreign_boot_input_never_emits_complete_media(self):
        self.prepare("am2-s17p")
        inputs = self.directory / "empty-boot"
        inputs.mkdir()
        output = self.directory / "images"
        with self.assertRaises((ValueError, OSError)):
            native.assemble(self.root, output, "am2-s17p", inputs)
        self.assertFalse(any(output.glob("*.img")))
        self.assertFalse(any(output.glob("*.manifest.json")))

    def test_toolbox_refuses_newly_signed_foreign_boot_bytes(self):
        board = "am1-s15"
        self.prepare(board)
        artifact = native.assemble(self.root, self.directory / "images", board, self.boot(board))
        raw = bytearray(artifact.read_bytes())
        boot = bm1391_sd_media.fat32_files(bytes(raw[2048 * 512:133120 * 512]))["BOOT.BIN"]
        at = raw.find(boot)
        self.assertGreater(at, 0)
        raw[at + 100] ^= 1
        artifact.write_bytes(raw)
        manifest = Path(str(artifact) + ".manifest.json")
        document = json.loads(manifest.read_text())
        document["image_sha256"] = hashlib.sha256(raw).hexdigest()
        manifest.write_text(json.dumps(document))
        with self.assertRaisesRegex(ValueError, "boot input|boot component"):
            self.sign_and_validate(artifact, board)
        # A valid outer signature and unchanged in-image daemon pair cannot
        # bypass independent boot validation through the publication contract.
        with self.assertRaisesRegex(ValueError, "boot input|boot component"):
            self.verify_producer_handoff(artifact, board)

    def test_toolbox_refuses_signed_storage_grant_or_enabled_mining(self):
        board = "am2-s19pro"
        self.prepare(board)
        inputs = self.boot(board)
        config_mutations = {
            "mining": ("[mining]\nenabled = false", "[mining]\nenabled = true"),
            "protocol": ('serial_chip_type = "BM1398"', 'serial_chip_type = "BM1362"'),
            "frequency": ("frequency_mhz = 500", "frequency_mhz = 650"),
            "voltage": ("voltage_mv = 12800", "voltage_mv = 13800"),
            "psu_watchdog": ("watchdog_enabled = true", "watchdog_enabled = false"),
            "watchdog": ("[watchdog]\nenabled = true", "[watchdog]\nenabled = false"),
            "supervisor": ("[thermal.supervisor]\nenabled = true", "[thermal.supervisor]\nenabled = false"),
        }
        for kind in ("storage", *config_mutations, "mode"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=self.directory) as temporary:
                directory = Path(temporary)
                root = directory / "root"
                # Preserve the deliberate daemon hardlink while copying.
                shutil.copytree(self.root, root, symlinks=True)
                (root / "usr/bin/dcentrald").unlink()
                os.link(root / runtime.DAEMON, root / "usr/bin/dcentrald")
                if kind == "storage":
                    (root / "etc/dcentos/mutation_policy").write_bytes(b"boot-safeoff\ndaemon-hardware\nota-storage\n")
                elif kind in config_mutations:
                    config = root / "etc/dcentrald.toml"
                    before, after = config_mutations[kind]
                    text = config.read_text()
                    self.assertEqual(text.count(before), 1)
                    config.write_text(text.replace(before, after, 1))
                else:
                    (root / runtime.DAEMON).chmod(0o644)
                # The producer now rejects modified BM1398 defaults too. Bypass
                # only that check in this adversarial fixture to construct a
                # newly signed bad image and exercise the independent reader.
                if kind in config_mutations:
                    with self.assertRaisesRegex(ValueError, "BM1398.*default differs"):
                        native.assemble(root, directory / "images", board, inputs)
                with patch.object(native.current_release, "validate_bm1398_config"):
                    artifact = native.assemble(root, directory / "images", board, inputs)
                with self.assertRaisesRegex(ValueError, "OTA writer|mining disabled|execute permission|BM1398.*config differs"):
                    self.sign_and_validate(artifact, board)

    def test_supervisor_dependencies_are_checked_in_actual_root_filesystem(self):
        board = "am2-s19pro"
        self.prepare(board)

        def inspect(root, directory):
            squash = directory / "root.squashfs"
            native.command("mksquashfs", root, squash, "-noappend", "-comp", "xz", "-processors", "1", "-quiet")
            fs = SquashfsFiles(squash.read_bytes())
            fs.inventory()
            return current.root_policy(current.Root(fs, squash=True), board, "1.2.3",
                                       {"board_family": "am2", "platform": "zynq-bm3-am2"})

        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            self.assertIn("dcentrald", inspect(self.root, Path(temporary)))
        mutations = [(path, "absent") for path in (*current.SUPERVISOR_SCRIPTS, *current.SUPERVISOR_PROGRAMS)]
        mutations += [(path, kind) for path in current.SUPERVISOR_PROGRAMS for kind in ("non-executable", "shell-stub", "mode")]
        mutations += [(current.SUPERVISOR_SCRIPTS[0], "non-executable")]
        mutations += [(path, kind) for path in ("lib/libc-fixture.so", "lib/ld-linux-armhf.so.3")
                      for kind in ("absent", "shell-stub")]
        mutations += [("lib/libc.so.6", kind) for kind in ("escape", "cycle")]
        for path, kind in mutations:
            with self.subTest(path=path, kind=kind), tempfile.TemporaryDirectory(dir=self.directory) as temporary:
                directory = Path(temporary)
                root = directory / "root"
                shutil.copytree(self.root, root, symlinks=True)
                (root / "usr/bin/dcentrald").unlink()
                os.link(root / runtime.DAEMON, root / "usr/bin/dcentrald")
                destination = root / path
                if kind == "absent":
                    destination.unlink()
                elif kind == "shell-stub":
                    destination.write_bytes(b"#!/bin/sh\nexit 0\n")
                elif kind in ("escape", "cycle"):
                    destination.unlink()
                    os.symlink("../../host-libc.so" if kind == "escape" else "libc.so.6", destination)
                else:
                    destination.chmod(0o644 if kind == "non-executable" else 0o750)
                with self.assertRaises(ValueError):
                    inspect(root, directory)

    def test_signed_complete_media_without_deploy_lock_is_not_qualified(self):
        board = "am2-s19pro"
        self.prepare(board)
        (self.root / "usr/libexec/dcentos/dcentos-deploy-lock").unlink()
        artifact = native.assemble(self.root, self.directory / "images", board, self.boot(board))
        # The actual final root still has a valid signed daemon pair, and the
        # outer image is newly signed. Missing owner supervision must refuse it.
        with self.assertRaisesRegex(ValueError, "dcentos-deploy-lock"):
            self.sign_and_validate(artifact, board)
        with self.assertRaisesRegex(ValueError, "dcentos-deploy-lock"):
            self.verify_producer_handoff(artifact, board)


if __name__ == "__main__":
    unittest.main()
