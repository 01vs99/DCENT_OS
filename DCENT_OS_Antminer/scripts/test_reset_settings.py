#!/usr/bin/env python3
"""Real ordinary-file reset operations and subprocess outcomes, no devices."""
import importlib.util
import hashlib
import json
import os
import signal
import sys
import time
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentos-reset-settings.py"
spec = importlib.util.spec_from_file_location("reset_settings", SOURCE)
reset = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reset)


class ResetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ("data/dcent", "usr/share/dcentos", "run", "vendor"):
            (self.root / directory).mkdir(parents=True, mode=0o700)
        self.default = self.root / "usr/share/dcentos/default-dcentrald.toml"
        self.default.write_text('[mining]\nenabled = false\n[pool]\nurl = ""\n')
        self.config = self.root / "data/dcentrald.toml"
        self.config.write_text('[mining]\nenabled = true\n[pool]\npassword = "secret"\n')
        for name in reset.SETTINGS:
            (self.root / name).write_text("private settings")
        (self.root / "data/dcent/auth.json.corrupt.123").write_text("bad-auth")
        self.vendor = self.root / "vendor/factory-eeprom"
        self.vendor.write_bytes(b"VENDOR MUST SURVIVE")
        self.journal = self.root / "data/dcent/mutation-disposition.json"
        self.journal.write_text("retained historical proof")
        self.events = self.root / "events"
        self.stop = self.command("stop", f"echo stop >> '{self.events}'\n")
        self.status = self.command("status", "echo clear\n")
        self.reboot = self.command("reboot", f"echo reboot >> '{self.events}'\n")
        proof = json.dumps({"settings_default_sha256": hashlib.sha256(self.default.read_bytes()).hexdigest(),
                            "bytes": self.default.stat().st_size})
        self.verify = self.command("verify", f"echo '{proof}'\n")

    def command(self, name, body):
        path = self.root / name
        path.write_text("#!/bin/sh\nset -e\n" + body)
        path.chmod(0o700)
        return [str(path)]

    def execute(self, **kwargs):
        reset.reset(self.root, self.stop, self.status, self.reboot, verify=self.verify, **kwargs)

    def test_actual_reset_preserves_vendor_and_journal_after_checked_stop(self):
        # The stop command observes secrets still present before removal.
        self.stop = self.command("stop", f"test -f '{self.root}/data/dcent/auth.json'\necho stop >> '{self.events}'\n")
        self.execute()
        self.assertEqual(self.config.read_bytes(), self.default.read_bytes())
        self.assertTrue(all(not (self.root / p).exists() for p in reset.SETTINGS))
        self.assertFalse((self.root / "data/dcent/auth.json.corrupt.123").exists())
        self.assertEqual(self.vendor.read_bytes(), b"VENDOR MUST SURVIVE")
        self.assertEqual(self.journal.read_text(), "retained historical proof")
        self.assertEqual(self.events.read_text(), "stop\nreboot\n")
        self.assertTrue((self.root / "run/dcentos-deploy-maintenance").exists())
        self.assertEqual(json.loads((self.root / "data/dcent/reset-settings-status.json").read_text())["phase"], "settings_reset")

    def test_failed_stop_keeps_all_settings_and_bars_reboot(self):
        self.stop = self.command("stop", "exit 1\n")
        before = self.config.read_bytes()
        with self.assertRaises(subprocess.CalledProcessError):
            self.execute()
        self.assertEqual(self.config.read_bytes(), before)
        self.assertTrue((self.root / "data/dcent/auth.json").exists())
        self.assertFalse(self.events.exists())
        self.assertEqual((self.root / reset.MARKER).read_bytes(), reset.CONFIRMATION)
        self.assertEqual(json.loads((self.root / "data/dcent/reset-settings-status.json").read_text())["phase"], "failed")

    def test_false_success_with_unresolved_session_does_not_remove_auth(self):
        self.status = self.command("status", "echo unresolved\n")
        with self.assertRaises(ValueError):
            self.execute()
        self.assertTrue((self.root / "data/dcent/auth.json").exists())
        self.assertNotIn("reboot", self.events.read_text())

    def test_symlink_cannot_reset_vendor_file(self):
        self.config.unlink()
        self.config.symlink_to(self.vendor)
        with self.assertRaises(ValueError):
            self.execute()
        self.assertEqual(self.vendor.read_bytes(), b"VENDOR MUST SURVIVE")
        self.assertFalse(self.events.exists())

    def test_mining_enabled_default_is_refused_before_stop(self):
        self.default.write_text("[mining]\nenabled=true\n")
        with self.assertRaises(ValueError):
            self.execute()
        self.assertFalse(self.events.exists())

    def test_boot_marker_is_consumed_without_reboot_and_defaults_are_off(self):
        marker = self.root / reset.MARKER
        marker.write_bytes(reset.CONFIRMATION)
        reset.reset(self.root, self.stop, self.status, verify=self.verify, boot=True)
        self.assertFalse(marker.exists())
        self.assertFalse((self.root / "run/dcentos-deploy-maintenance").exists())
        self.assertEqual(self.events.read_text(), "stop\n")
        self.assertEqual(self.config.read_bytes(), self.default.read_bytes())

    def test_wrong_boot_marker_preserves_credentials(self):
        (self.root / reset.MARKER).write_text("reset")
        with self.assertRaises(ValueError):
            reset.reset(self.root, self.stop, self.status, verify=self.verify, boot=True)
        self.assertTrue((self.root / "data/dcent/auth.json").exists())
        self.assertFalse(self.events.exists())

    def test_unsigned_default_refused_before_stop(self):
        self.verify = self.command("verify", "exit 1\n")
        with self.assertRaises(subprocess.CalledProcessError):
            self.execute()
        self.assertFalse(self.events.exists())
        self.assertTrue((self.root / "data/dcent/auth.json").exists())

    def test_changed_default_after_stop_preserves_credentials(self):
        self.stop = self.command("stop", f"echo corrupt > '{self.default}'\n")
        with self.assertRaises(ValueError):
            self.execute()
        self.assertTrue((self.root / "data/dcent/auth.json").exists())

    def test_failed_reboot_keeps_fence_and_deliberate_retry_is_idempotent(self):
        self.reboot = self.command("reboot", "exit 1\n")
        with self.assertRaises(subprocess.CalledProcessError):
            self.execute()
        self.assertTrue((self.root / "run/dcentos-deploy-maintenance").exists())
        self.reboot = self.command("reboot", f"echo reboot >> '{self.events}'\n")
        self.execute()
        self.assertEqual(self.config.read_bytes(), self.default.read_bytes())
        self.assertEqual(self.vendor.read_bytes(), b"VENDOR MUST SURVIVE")

    def test_killed_worker_after_stop_retains_durable_intent_and_original_settings(self):
        reached = self.root / "stopped"
        self.status = self.command("status", f"touch '{reached}'\nsleep 30\necho clear\n")
        driver = self.root / "driver.py"
        driver.write_text(
            "import importlib.util\nfrom pathlib import Path\n"
            + f"spec=importlib.util.spec_from_file_location('worker', {str(SOURCE)!r})\n"
            + "m=importlib.util.module_from_spec(spec)\nspec.loader.exec_module(m)\n"
            + f"m.reset(Path({str(self.root)!r}), {self.stop!r}, {self.status!r}, {self.reboot!r}, verify={self.verify!r})\n")
        child = subprocess.Popen([sys.executable, str(driver)], start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while not reached.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(reached.exists(), "actual stop subprocess did not reach its witness")
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)
            self.assertEqual((self.root / reset.MARKER).read_bytes(), reset.CONFIRMATION)
            self.assertTrue((self.root / "run/dcentos-deploy-maintenance").exists())
            self.assertTrue((self.root / "data/dcent/auth.json").exists())
            self.assertIn("enabled = true", self.config.read_text())
            self.assertEqual(self.vendor.read_bytes(), b"VENDOR MUST SURVIVE")
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)

    def test_pending_firstlight_restore_bars_reset_before_intent_or_stop(self):
        firstlight = self.root / "data/.dcent-firstlight"
        firstlight.mkdir(mode=0o700)
        for name in ["current", "retired-" + "a" * 32, "unknown"]:
            entry = firstlight / name
            entry.mkdir()
            with self.assertRaisesRegex(ValueError, "firstlight"):
                self.execute()
            self.assertFalse((self.root / reset.MARKER).exists())
            self.assertFalse(self.events.exists())
            entry.rmdir()
        self.execute()  # Empty retained parent is a completed lifecycle.

    def test_pending_deploy_cannot_restore_pre_reset_settings_on_next_start(self):
        recovery = self.root / "data/.dcent-deploy-recovery"
        recovery.mkdir(mode=0o700)
        lease = recovery / ".deploy-lease"
        lease.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, "deploy lease"):
            self.execute()
        self.assertFalse((self.root / reset.MARKER).exists())
        lease.rmdir()
        run = recovery / ("a" * 32)
        run.mkdir(mode=0o700)
        pending = run / "persistent-transaction.state"
        pending.symlink_to("missing")
        with self.assertRaisesRegex(ValueError, "deploy state"):
            self.execute()
        self.assertFalse(self.events.exists())
        pending.unlink()
        (run / "persistent-transaction.committed").write_text("historical audit")
        self.execute()  # Completed transaction cannot be replayed by S82.

    def test_unrelated_maintenance_refused_without_creating_reset_intent(self):
        fence = self.root / "run/dcentos-deploy-maintenance"
        fence.write_text("another-owner\n")
        with self.assertRaisesRegex(ValueError, "another maintenance"):
            self.execute()
        self.assertEqual(fence.read_text(), "another-owner\n")
        self.assertFalse((self.root / reset.MARKER).exists())
        self.assertFalse(self.events.exists())

    def test_changed_intent_after_stop_cannot_remove_settings(self):
        marker = self.root / reset.MARKER
        self.stop = self.command("stop", f"echo invalid > '{marker}'\n")
        with self.assertRaisesRegex(ValueError, "intent changed"):
            self.execute()
        self.assertTrue((self.root / "data/dcent/auth.json").exists())
        self.assertEqual(marker.read_text(), "invalid\n")


if __name__ == "__main__":
    unittest.main()
