#!/usr/bin/env python3
"""Actual Windows long-path ceremony and durable artifact signing regression."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import atomic_publish_directory as atomic
import release_host_tools as host
import runtime_image_manifest as runtime
import sign_release_artifact as signer


class ReleaseHostToolsTests(unittest.TestCase):
    def test_host_selection_preserves_linux_or_selects_actual_msys(self):
        with patch.dict(os.environ):
            original = os.environ.get("PATH", "")
            selected = host.prepare_openssl_environment()
            if os.name == "nt":
                self.assertTrue(selected)
                self.assertEqual(Path(shutil.which("openssl")).parent, Path(selected))
            else:
                self.assertIsNone(selected)
                self.assertEqual(os.environ.get("PATH", ""), original)

    @unittest.skipUnless(os.name == "nt", "actual Windows MSYS/native path regression")
    def test_long_path_ceremony_signing_and_tamper_refusal(self):
        # Exercise the checkout's actual volume, where short-name generation
        # may be disabled even if the system temporary volume has 8.3 names.
        with patch.dict(os.environ), tempfile.TemporaryDirectory(
            prefix=".dcent-long-key-", dir=Path(__file__).resolve().parent
        ) as temporary:
            root = Path(temporary)
            selected = host.prepare_openssl_environment()
            openssl = str(Path(selected) / "openssl.exe")
            short_key = root / "key.pem"
            short_pub = root / "pub.pem"
            subprocess.run([openssl, "genpkey", "-algorithm", "ED25519", "-out", str(short_key)],
                           check=True, capture_output=True, timeout=10)
            subprocess.run([openssl, "pkey", "-in", str(short_key), "-pubout", "-out", str(short_pub)],
                           check=True, capture_output=True, timeout=10)
            parent = root / ("stage-" + "a" * 110) / ("authority-" + "b" * 110) / "keys"
            parent.mkdir(parents=True)
            key, pub = parent / "private.pem", parent / "public.pem"
            short_key.rename(key)
            short_pub.rename(pub)
            atomic.set_windows_file_acl(key, atomic.WINDOWS_PRIVATE_FILE_SDDL)
            self.assertGreater(len(str(key)), 300)
            public = runtime.public_key_bytes(pub)
            bash = str(Path(selected) / "bash.exe")
            ceremony = Path(__file__).with_name("verify_release_keypair.sh")
            for expected, code in ((public.hex(), 0), ("00" * 32, 1)):
                result = subprocess.run([bash, str(ceremony), str(key), str(pub), expected],
                                        cwd=root, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, code, result.stderr.decode(errors="replace"))
            artifact = parent / "artifact.bin"
            signature = parent / "artifact.bin.sig"
            artifact.write_bytes(b"actual long-path release-signing fixture\n")
            signer.sign_artifact(argparse.Namespace(artifact=str(artifact), output_sig=str(signature),
                                                   key=str(key), pubkey=str(pub)))
            runtime.verify_signature(artifact, signature, pub)
            artifact.write_bytes(b"tampered long-path release-signing fixture\n")
            with self.assertRaises(runtime.ManifestError):
                runtime.verify_signature(artifact, signature, pub)


if __name__ == "__main__":
    if sys.argv[1:] == ["--host-platform"]:
        names = ["test_host_selection_preserves_linux_or_selects_actual_msys"]
        if os.name == "nt":
            names.append("test_long_path_ceremony_signing_and_tamper_refusal")
        result = unittest.TextTestRunner().run(unittest.TestSuite(
            ReleaseHostToolsTests(name) for name in names
        ))
        raise SystemExit(0 if result.wasSuccessful() and not result.skipped else 1)
    unittest.main()
