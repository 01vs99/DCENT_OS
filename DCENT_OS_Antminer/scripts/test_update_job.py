#!/usr/bin/env python3
"""Execute update custody using harmless child commands on Linux."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

HELPER = Path(__file__).resolve().parents[1] / "br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentos-update-job.py"
SPEC = importlib.util.spec_from_file_location("update_job", HELPER)
JOB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(JOB)


@unittest.skipUnless(sys.platform == "linux", "Linux detached process contract")
class UpdateJobTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.stage = self.base / "stages"
        self.upload = self.stage / "upload"
        self.upload.mkdir(parents=True)
        self.package = self.upload / "image.tar"
        self.package.write_bytes(b"harmless fixture, never passed to real sysupgrade")
        self.digest = hashlib.sha256(self.package.read_bytes()).hexdigest()
        self.journal = self.base / "journal"
        self.work = self.base / "work"
        self.job_id = str(uuid.uuid4())

    def arguments(self, command):
        return dict(stage_root=self.stage, journal_root=self.journal,
                    work_root=self.work, command=command, delay=0.01)

    def read_terminal(self):
        status = self.journal / self.job_id / "status.json"
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if status.exists():
                record = json.loads(status.read_text())
                if record["state"] in {"command_completed", "command_failed", "worker_failed"}:
                    return record
            time.sleep(0.02)
        self.fail("detached update worker did not reach terminal journal")

    def test_worker_survives_launcher_exit_with_file_output_and_same_reserved_inode(self):
        original = self.package.stat()
        command = [sys.executable, "-c", "import time;time.sleep(.2);print('child finished')"]
        script = (
            "import importlib.util,json;from pathlib import Path;"
            f"s=importlib.util.spec_from_file_location('job',{str(HELPER)!r});"
            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
            f"r=m.launch_job(Path({str(self.package)!r}),{self.digest!r},{self.job_id!r},"
            f"stage_root=Path({str(self.stage)!r}),journal_root=Path({str(self.journal)!r}),"
            f"work_root=Path({str(self.work)!r}),command={command!r},delay=.01);print(json.dumps(r))"
        )
        launcher = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=5)
        self.assertEqual(launcher.returncode, 0, launcher.stderr)
        receipt = json.loads(launcher.stdout)
        self.assertEqual(receipt["job_id"], self.job_id)
        result = self.read_terminal()
        self.assertEqual(result["state"], "command_completed", result)
        self.assertFalse(result["boot_verified"])
        self.assertEqual(result["source_boot_id"], Path("/proc/sys/kernel/random/boot_id").read_text().strip())
        for key in ("schema", "job_id", "package_sha256", "source_boot_id", "scheduled_at"):
            self.assertEqual(receipt[key], result[key], key)
        self.assertEqual(receipt["state"], "scheduled")
        self.assertFalse(receipt["boot_verified"])
        self.assertIn("child finished", (self.journal / self.job_id / "output.log").read_text())
        pinned = Path(result["package_path"])
        self.assertEqual(pinned.stat().st_ino, original.st_ino)
        self.assertFalse(self.package.exists())
        self.assertFalse((self.journal / self.job_id / "package.tar").exists())

    def test_command_failure_remains_failure_and_does_not_claim_boot(self):
        launch = JOB.launch_job(self.package, self.digest, self.job_id,
                               **self.arguments([sys.executable, "-c", "raise SystemExit(7)"]))
        os.waitpid(launch["pid"], 0)
        result = self.read_terminal()
        self.assertEqual(result["state"], "command_failed")
        self.assertEqual(result["exit_code"], 7)
        self.assertFalse(result["boot_verified"])
        self.assertEqual(result["source_boot_id"], Path("/proc/sys/kernel/random/boot_id").read_text().strip())

    def test_child_receives_exact_job_package_and_source_boot_binding(self):
        command = [sys.executable, "-c", "import json,os;print(json.dumps({k:v for k,v in os.environ.items() if k.startswith('DCENT_UPDATE_JOB_')}))"]
        launch = JOB.launch_job(self.package, self.digest, self.job_id,
                               **self.arguments(command))
        os.waitpid(launch["pid"], 0)
        self.assertEqual(self.read_terminal()["state"], "command_completed")
        binding = json.loads((self.journal / self.job_id / "output.log").read_text())
        self.assertEqual(binding, {
            "DCENT_UPDATE_JOB_ID": self.job_id,
            "DCENT_UPDATE_JOB_PACKAGE_SHA256": self.digest,
            "DCENT_UPDATE_JOB_SOURCE_BOOT_ID": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        })

    def test_digest_mismatch_keeps_upload_and_never_forks(self):
        with self.assertRaisesRegex(ValueError, "digest"):
            JOB.launch_job(self.package, "0" * 64, self.job_id,
                           **self.arguments(["must-not-run"]))
        self.assertTrue(self.package.exists())
        result = json.loads((self.journal / self.job_id / "status.json").read_text())
        self.assertEqual(result["state"], "failed_before_start")
        self.assertNotIn("worker_pid", result)

    def test_symlink_upload_and_foreign_stage_are_refused(self):
        alternate = self.upload / "alternate.tar"
        alternate.symlink_to(self.package)
        with self.assertRaisesRegex(ValueError, "unsafe update file"):
            JOB.launch_job(alternate, self.digest, self.job_id, **self.arguments(["must-not-run"]))
        with self.assertRaisesRegex(ValueError, "immediate file"):
            JOB.launch_job(self.base / "foreign.tar", self.digest, self.job_id,
                           **self.arguments(["must-not-run"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
