#!/usr/bin/env python3
"""Exercise persistent job/boot joins on disposable Linux directories."""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

from lib import am2_ota_boot as ota
import test_am2_native_ota as fixtures

sys.modules["am2_ota_boot"] = ota
HELPER = (
    Path(__file__).resolve().parents[1]
    / "br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentos-update-observer.py"
)
SPEC = importlib.util.spec_from_file_location("update_observer", HELPER)
OBSERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVER)


@unittest.skipUnless(
    sys.platform == "linux", "Linux persistent file ownership contract"
)
class UpdateObserverTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.jobs = self.root / "jobs"
        self.receipts = self.root / "receipts"
        self.jobs.mkdir(mode=0o700)
        self.receipts.mkdir(mode=0o700)
        self.fixture = fixtures.PreparedJobBindingTests()
        self.receipt, self.environment, self.cmdline = self.fixture.prepared()
        self.job = self.jobs / self.fixture.JOB
        self.job.mkdir(mode=0o700)
        self.status = self.job / "status.json"
        self.write(
            self.status,
            {
                "schema": 1,
                "job_id": self.fixture.JOB,
                "package_sha256": self.fixture.PACKAGE,
                "source_boot_id": self.fixture.BEFORE,
                "state": "running",
                "boot_verified": False,
            },
        )
        self.receipt_dir = self.receipts / "exact-transaction"
        self.receipt_dir.mkdir(mode=0o700)
        self.write(self.receipt_dir / "receipt.json", self.receipt)

    @staticmethod
    def write(path, record):
        path.write_text(json.dumps(record))
        path.chmod(0o600)

    def observe(self):
        return OBSERVER.observe(
            self.environment,
            self.cmdline,
            self.fixture.AFTER,
            journal_root=self.jobs,
            receipt_root=self.receipts,
        )

    def test_exact_join_publishes_private_observation_without_rewriting_worker(self):
        before = self.status.read_bytes()
        results = self.observe()
        self.assertEqual(len(results), 1)
        path = self.job / "boot-observation.json"
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(path.read_text())["job_id"], self.fixture.JOB)
        self.assertFalse(results[0]["physical_hashing_verified"])
        self.assertEqual(self.status.read_bytes(), before)
        self.assertFalse(list(self.job.glob(".boot-observation-*")))

    def test_pending_commit_and_foreign_job_never_publish(self):
        self.environment["upgrade_stage"] = "1"
        self.assertEqual(self.observe(), [])
        del self.environment["upgrade_stage"]
        status = json.loads(self.status.read_text())
        status["package_sha256"] = "f" * 64
        self.write(self.status, status)
        self.assertEqual(self.observe(), [])
        self.assertFalse((self.job / "boot-observation.json").exists())

    def test_duplicate_receipt_custody_is_ambiguous(self):
        duplicate = self.receipts / "duplicate"
        duplicate.mkdir(mode=0o700)
        self.write(duplicate / "receipt.json", self.receipt)
        self.assertEqual(self.observe(), [])

    def test_symlink_and_mutable_status_cannot_supply_job_authority(self):
        saved = self.job / "saved.json"
        self.status.rename(saved)
        self.status.symlink_to(saved)
        self.assertEqual(self.observe(), [])
        self.status.unlink()
        saved.rename(self.status)
        self.status.chmod(0o666)
        self.assertEqual(self.observe(), [])

    def test_missing_roots_and_foreign_receipt_do_not_promote(self):
        self.assertEqual(
            OBSERVER.observe(
                {},
                "",
                self.fixture.AFTER,
                journal_root=self.root / "absent",
                receipt_root=self.receipts,
            ),
            [],
        )
        self.receipt["after"]["dcent_native_transaction"] = "e" * 64
        self.write(self.receipt_dir / "receipt.json", self.receipt)
        self.assertEqual(self.observe(), [])

    def test_evidence_root_permissions_are_checked(self):
        self.receipts.chmod(0o777)
        with self.assertRaises(ValueError):
            self.observe()


if __name__ == "__main__":
    unittest.main(verbosity=2)
