#!/usr/bin/env python3
"""Actual compiled ELF/trusted-key/compile-observation join for releases."""
import os
from pathlib import Path
import tempfile
import unittest

import release_build_identity as binding
import runtime_image_manifest as runtime
from test_runtime_image_manifest import fixture


@unittest.skipUnless(os.name == "posix", "real cross ELF fixture uses WSL Rust toolchain")
class BuildIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temporary.name)
        _, cls.pubkey, cls.binary = fixture(cls.base / "production")
        cls.key = runtime.public_key_bytes(cls.pubkey).hex()

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def observation(self, text=None):
        path = self.base / "compile-env.txt"
        path.write_text(text if text is not None else f"DCENT_OTA_PUBLIC_KEY_HEX={self.key}\n")
        return path

    def test_actual_compiled_key_version_and_observation_agree(self):
        binding.verify(self.binary, self.observation(), self.pubkey, "1.2.3")

    def test_missing_or_duplicate_compile_observation_refuses(self):
        for text in ("CARGO_BUILD_PROFILE=release\n", f"DCENT_OTA_PUBLIC_KEY_HEX={self.key}\n" * 2,
                     "DCENT_OTA_PUBLIC_KEY_HEX=" + "00" * 32 + "\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                binding.verify(self.binary, self.observation(text), self.pubkey, "1.2.3")

    def test_independently_trusted_key_disagrees_with_caller(self):
        self.assertEqual(binding.key_hex(self.pubkey, self.key), self.key)
        for text in ("", "ff" * 32, "not-hex"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                binding.key_hex(self.pubkey, text)

    def test_real_elf_version_mismatch_refuses(self):
        with self.assertRaisesRegex(ValueError, "actual daemon ELF"):
            binding.verify(self.binary, self.observation(), self.pubkey, "9.9.9")

    def test_different_trusted_key_refuses_even_with_matching_compile_text(self):
        key, pubkey = self.base / "different-key.pem", self.base / "different-public.pem"
        runtime.openssl("genpkey", "-algorithm", "ED25519", "-out", key)
        runtime.openssl("pkey", "-in", key, "-pubout", "-out", pubkey)
        text = "DCENT_OTA_PUBLIC_KEY_HEX=" + runtime.public_key_bytes(pubkey).hex() + "\n"
        with self.assertRaisesRegex(ValueError, "actual daemon ELF"):
            binding.verify(self.binary, self.observation(text), pubkey, "1.2.3")


if __name__ == "__main__":
    unittest.main()
