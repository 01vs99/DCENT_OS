#!/usr/bin/env python3
"""Real ELF + throwaway Ed25519 tests for the production runtime image helper."""
import argparse
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

import runtime_image_manifest as runtime

SCRIPT_DIR = Path(__file__).resolve().parent
IDENTITY = SCRIPT_DIR.parent / "dcentrald/dcentrald/src/build_identity.rs"


def fixture(directory: Path, lab=False, sim=False, key_hex=None, machine="armv7-unknown-linux-musleabihf"):
    """Compile the actual production module into a real ELF, with test-only keys."""
    directory.mkdir(parents=True, exist_ok=True)
    key, pubkey = directory / "test-key.pem", directory / "test-pub.pem"
    if not key.exists():
        runtime.openssl("genpkey", "-algorithm", "ED25519", "-out", key)
        runtime.openssl("pkey", "-in", key, "-pubout", "-out", pubkey)
    public = runtime.public_key_bytes(pubkey).hex() if key_hex is None else key_hex
    source = directory / "identity_fixture.rs"
    source.write_text('extern crate self as dcentrald_common;\n'
                      'pub mod lab_env { pub const fn compiled() -> bool { ' + str(lab).lower() + ' } }\n'
                      '#[path = ' + json.dumps(str(IDENTITY)) + '] mod build_identity;\n'
                      'fn main() { build_identity::retain(); }\n', encoding="utf-8")
    env = dict(os.environ, CARGO_PKG_VERSION="1.2.3")
    if public == "missing":
        env.pop("DCENT_OTA_PUBLIC_KEY_HEX", None)
    else:
        env["DCENT_OTA_PUBLIC_KEY_HEX"] = public
    rustc = subprocess.check_output(["rustup", "which", "--toolchain", "1.90.0", "rustc"], text=True).strip()
    linker = Path(rustc).parent.parent / "lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
    command = [rustc, "--edition", "2021", str(source), "--target", machine,
               "-C", "opt-level=2", "-C", "lto=yes", "-C", "strip=symbols", "-C", "linker=" + str(linker), "-o", str(directory / "daemon")]
    if sim:
        command += ["--cfg", 'feature="sim-hal"']
    subprocess.run(command, env=env, check=True, capture_output=True, timeout=180)
    return key, pubkey, directory / "daemon"


@unittest.skipUnless(os.name == "posix", "real cross ELF fixture uses WSL Rust toolchain")
class RuntimeManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="runtime-manifest-test-")
        cls.base = Path(cls.temporary.name)
        cls.key, cls.pubkey, cls.daemon = fixture(cls.base / "fixture")
        cls.arm64_key, cls.arm64_pubkey, cls.arm64_daemon = fixture(cls.base / "arm64", machine="aarch64-unknown-linux-musl")
        cls.rejected = [fixture(cls.base / name, **settings)[2] for name, settings in (
            ("lab", {"lab": True}), ("sim", {"sim": True}),
            ("missing", {"key_hex": "missing"}), ("bad-key", {"key_hex": "bad"}))]

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(dir=self.base)
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        (self.root / "etc/dcentos").mkdir(parents=True)
        (self.root / "usr/local/bin").mkdir(parents=True)
        shutil.copyfile(self.daemon, self.root / runtime.DAEMON)

    def prepare(self, **overrides):
        args = dict(rootfs=self.root, board="am1-s9", channel="beta", version="1.2.3", key=self.key, pubkey=self.pubkey)
        args.update(overrides)
        return runtime.prepare(**args)

    def verify(self, **overrides):
        args = dict(rootfs=self.root, board="am1-s9", channel="beta", version="1.2.3", pubkey=self.pubkey)
        args.update(overrides)
        return runtime.verify(**args)

    def test_actual_stripped_elf_production_identity_roundtrip(self):
        document = self.prepare()
        self.assertEqual(document, self.verify())
        self.assertEqual(len((self.root / runtime.SIGNATURE).read_bytes()), 64)
        self.assertEqual(set(document), runtime.FIELDS | {"hardware_recipe"})
        self.assertEqual(document["hardware_recipe"], "board-default")

    def test_optional_signed_reset_default_rejects_changed_or_mining_on_default(self):
        self.assertNotIn("settings_default_sha256", self.prepare())
        default = self.root / runtime.SETTINGS_DEFAULT
        default.parent.mkdir(parents=True)
        default.write_text("[mining]\nenabled=false\n")
        self.assertIn("settings_default_sha256", self.prepare())
        self.verify()
        default.write_text("[mining]\nenabled=true\n")
        with self.assertRaisesRegex(runtime.ManifestError, "default digest"):
            self.verify()
        with self.assertRaisesRegex(runtime.ManifestError, "disable mining"):
            self.prepare()

    def test_actual_stripped_aarch64_production_identity_roundtrip(self):
        shutil.copyfile(self.arm64_daemon, self.root / runtime.DAEMON)
        document = self.prepare(board="am3-s21", key=self.arm64_key, pubkey=self.arm64_pubkey)
        self.assertEqual(document, self.verify(board="am3-s21", pubkey=self.arm64_pubkey))
        self.assertEqual(runtime.build_identity(self.arm64_daemon.read_bytes())["machine"], 183)

    def test_unsigned_tamper_and_daemon_change_fail(self):
        self.prepare()
        signature = self.root / runtime.SIGNATURE
        raw = signature.read_bytes()
        signature.unlink()
        with self.assertRaises(OSError):
            self.verify()
        signature.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        with self.assertRaises(runtime.ManifestError):
            self.verify()
        signature.write_bytes(raw)
        with (self.root / runtime.DAEMON).open("ab") as handle:
            handle.write(b"changed")
        with self.assertRaisesRegex(runtime.ManifestError, "digest/size"):
            self.verify()

    def test_wrong_board_channel_version_architecture_key_refused(self):
        self.prepare()
        for overrides in ({"board": "am1-s9i"}, {"channel": "stable"}, {"channel": "lab"},
                          {"board": "am3-s19kpro"}, {"version": "1.2.4"}):
            with self.subTest(overrides=overrides), self.assertRaises(runtime.ManifestError):
                self.verify(**overrides)
        with self.assertRaisesRegex(runtime.ManifestError, "architecture"):
            self.prepare(board="am3-s21")
        other_pub = self.base / "lab/test-pub.pem"
        with self.assertRaisesRegex(runtime.ManifestError, "version/key"):
            self.prepare(pubkey=other_pub)

    def test_compiled_lab_sim_missing_and_invalid_key_refused(self):
        for executable in self.rejected:
            with self.subTest(executable=executable):
                shutil.copyfile(executable, self.root / runtime.DAEMON)
                with self.assertRaisesRegex(runtime.ManifestError, "ineligible"):
                    self.prepare()

    def test_missing_unbound_or_writable_identity_refused(self):
        original = self.daemon.read_bytes()
        missing = original.replace(b".dcent.runtime\0", b".absent.dataxx\0")
        with self.assertRaises(runtime.ManifestError):
            runtime.build_identity(missing)
        # Change the real ELF section header, preserving the production bytes.
        shoff = struct.unpack_from("<I", original, 32)[0]
        shsize, shnum = struct.unpack_from("<HH", original, 46)
        for i in range(shnum):
            at = shoff + i * shsize
            section_offset, section_size = struct.unpack_from("<II", original, at + 16)
            if section_size == 196 and original[section_offset:section_offset + 32] == runtime.BUILD_PROFILE:
                for relative, value in ((8, 3), (12, 0)):
                    changed = bytearray(original)
                    struct.pack_into("<I", changed, at + relative, value)
                    with self.assertRaises(runtime.ManifestError):
                        runtime.build_identity(bytes(changed))
                return
        self.fail("production identity section absent")

    def test_strict_duplicate_unknown_and_bounded_metadata(self):
        document = self.prepare()
        raw = json.dumps(document)
        for mutated in (raw[:-1] + ',"channel":"beta"}', raw[:-1] + ',"chann\\u0065l":"beta"}',
                        raw[:-1] + ',"lab":false}', " " * 4097,
                        json.dumps(dict(document, daemon_size=True)), json.dumps(dict(document, channel="unsupported"))):
            with self.subTest(mutated=mutated[:80]), self.assertRaises((runtime.ManifestError, ValueError)):
                runtime.manifest_document(mutated.encode())

    def test_symlink_daemon_refused(self):
        (self.root / runtime.DAEMON).unlink()
        (self.root / runtime.DAEMON).symlink_to(self.daemon)
        with self.assertRaises(runtime.ManifestError):
            self.prepare()

    def test_signed_hardware_recipe_exact_row_and_legacy_default(self):
        document = self.prepare(board="am2-s19j", hardware_recipe="am2-s19j-xil-loki")
        self.assertEqual(self.verify(board="am2-s19j"), document)
        for board, recipe in (("am1-s9", "am2-s19j-xil-loki"), ("am2-s19j", "unknown")):
            with self.assertRaises(runtime.ManifestError):
                self.prepare(board=board, hardware_recipe=recipe)
        document.pop("hardware_recipe")
        runtime.manifest_document(json.dumps(document).encode())

    def test_deliberate_daemon_alias_preserves_byte_binding(self):
        os.link(self.root / runtime.DAEMON, self.root / "alias")
        self.assertEqual(self.prepare(), self.verify())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--fixture-dir", type=Path)
    args, remaining = parser.parse_known_args()
    if args.fixture_dir:
        fixture(args.fixture_dir)
    else:
        unittest.main(argv=[__file__, *remaining])
