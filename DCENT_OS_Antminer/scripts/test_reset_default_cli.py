#!/usr/bin/env python3
"""Exercise the actual daemon's read-only reset CLI before custody bootstrap."""
import argparse
import os
from pathlib import Path
import subprocess
import unittest


class ResetDefaultCliTests(unittest.TestCase):
    daemon = None

    def invoke(self, role, arguments):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("DCENT_")}
        environment["DCENT_S19K_STARTUP_BOOTSTRAP"] = role
        result = subprocess.run([str(self.daemon), *arguments], env=environment,
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("bootstrap", result.stderr.lower())
        self.assertNotIn("DCENT_S19K_STARTUP_WRAPPER", result.stderr)
        return result.stderr

    def test_read_only_default_inspection_precedes_all_inherited_custody_roles(self):
        self.assertFalse(Path("/etc/dcentos/board_target").exists(),
                         "Run this offline acceptance on the host, never on a miner")
        for role in ("publisher-v1", "daemon-v1", "invalid-role"):
            with self.subTest(role=role):
                self.assertIn("reset: exact installed board identity unavailable",
                              self.invoke(role, ["--check-reset-default"]))

    def test_mixed_mutating_and_read_only_arguments_are_refused_before_bootstrap(self):
        for arguments in (
            ["--check-reset-default", "--s19k-track1-journal-source", "/nonexistent"],
            ["--check-reset-default", "--check-reset-default"],
            ["--stock-fpga", "--check-reset-default"],
        ):
            with self.subTest(arguments=arguments):
                self.assertIn("usage: dcentrald --check-reset-default",
                              self.invoke("publisher-v1", arguments))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", type=Path, required=True)
    args, remaining = parser.parse_known_args()
    ResetDefaultCliTests.daemon = args.daemon.resolve(strict=True)
    unittest.main(argv=[__file__, *remaining])
