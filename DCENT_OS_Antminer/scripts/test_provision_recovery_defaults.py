#!/usr/bin/env python3
import json
from pathlib import Path
import tempfile
import unittest
from provision_recovery_defaults import provision


class DefaultsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "etc").mkdir()
        self.config = self.root / "etc/dcentrald.toml"
        self.config.write_text('[mining]\nenabled=false\n')

    def test_exact_final_default_and_source_metadata_are_staged(self):
        provision(self.root, git_sha="a" * 40, drop="1")
        self.assertEqual((self.root / "usr/share/dcentos/default-dcentrald.toml").read_bytes(), self.config.read_bytes())
        self.assertEqual(json.loads((self.root / "etc/dcentos/build-info.json").read_text()),
                         {"git_sha": "a" * 40, "drop": "1"})

    def test_enabled_or_implicit_mining_default_is_never_staged(self):
        for config in ('[mining]\nenabled=true\n', '[mining]\nenabled="false"\n', '[pool]\nurl=""\n'):
            self.config.write_text(config)
            with self.assertRaises(ValueError):
                provision(self.root)
            self.assertFalse((self.root / "usr/share/dcentos/default-dcentrald.toml").exists())

    def test_bad_source_revision_is_refused(self):
        with self.assertRaises(ValueError):
            provision(self.root, git_sha="unknown")
        with self.assertRaises(ValueError):
            provision(self.root, drop="debug")

    def test_symlink_output_cannot_overwrite_other_file(self):
        target = self.root / "vendor"
        target.write_bytes(b"preserve")
        directory = self.root / "usr/share/dcentos"
        directory.mkdir(parents=True)
        (directory / "default-dcentrald.toml").symlink_to(target)
        with self.assertRaises(ValueError):
            provision(self.root)
        self.assertEqual(target.read_bytes(), b"preserve")


if __name__ == '__main__':
    unittest.main()
