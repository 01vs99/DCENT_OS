#!/usr/bin/env python3
"""Run the host's emitted stage shell and protected metadata helper on real files."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "dcent-toolbox/src"))
from dcent_toolbox.core import firstlight_executor as executor
from dcent_toolbox.core.firstlight import FirstlightError
import test_firstlight_restore as restore_fixture


class FirstlightStagingTests(unittest.TestCase):
    def setUp(self):
        self.cut_at = None
        self.fixture = restore_fixture.FirstlightRestoreTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.stage = self.fixture.root, self.fixture.stage
        binding = self.fixture.binding
        self.context = {key: binding.fields[key] for key in
                        ("board", "boot", "daemon_path", "daemon", "original_path", "original")}
        for name in ("census.toml", "work.toml", "session"):
            (self.stage / name).unlink()
        self.stage.rmdir()
        (self.root / "run").mkdir()

    def stage_inputs(self, directory, files):
        target = self.root / directory.lstrip("/")
        target.mkdir(parents=True, mode=0o700)
        for name, raw in files.items():
            path = target / name
            path.write_bytes(raw)
            path.chmod(0o600)

    def run_remote(self, command, timeout):
        arguments = shlex.split(command)
        self.assertEqual(arguments[:4], [executor.LOCK, "--", "sh", "-c"])
        body = arguments[4]
        body = body.replace(executor.BINDING, str(self.fixture.binding.helper))
        body = body.replace(executor.LATCH, str(self.fixture.latch))
        body = body.replace("/etc/dcentos/board_target", str(self.root / "etc/dcentos/board_target"))
        body = body.replace("/data", str(self.root / "data"))
        body = body.replace("/run/dcentos-sysupgrade.lock", str(self.root / "run/dcentos-sysupgrade.lock"))
        body = body.replace("/tmp/dcent-firstlight-" + restore_fixture.TOKEN, str(self.root / ("tmp/dcent-firstlight-" + restore_fixture.TOKEN)))
        # These are the explicit external owner/fsync boundaries. The whole
        # emitted body and all metadata/digest/refusal logic execute unchanged.
        body = ("pidof() { return 1; }\nmv() { busybox mv \"$@\"; }\nsync_count=0\n"
                "sync() { sync_count=$((sync_count + 1)); "
                f"[ \"$sync_count\" != {shlex.quote(str(self.cut_at))} ] || kill -KILL $$; }}\n" + body)
        result = subprocess.run(["sh", "-x", "-c", body], capture_output=True, text=True, timeout=timeout)
        self.diagnostics = result.stdout + result.stderr
        return result.returncode, self.diagnostics

    def prepare(self):
        executor._prepare_remote(SimpleNamespace(stage=self.stage_inputs, run=self.run_remote), self.context, restore_fixture.TOKEN,
                                 b"[mining]\nenabled=false\n", b"[mining]\nenabled=false\n# work\n")

    def recover_preparation(self):
        executor._recover_remote_preparation(SimpleNamespace(run=self.run_remote), self.context, restore_fixture.TOKEN)

    def test_actual_emitted_stage_preserves_original_and_binds_both_phase_files(self):
        original = self.fixture.binding.original.read_bytes()
        try:
            self.prepare()
        except FirstlightError:
            self.fail(self.diagnostics)
        self.assertEqual(self.fixture.binding.original.read_bytes(), original)
        record = dict(line.split("=", 1) for line in (self.stage / "session").read_text().splitlines())
        self.assertEqual(record["token"], restore_fixture.TOKEN)
        for phase in ("census", "work"):
            self.assertEqual(record[phase], self.fixture.binding.identity(self.stage / (phase + ".toml")))
        self.assertFalse((self.root / "tmp" / ("dcent-firstlight-" + restore_fixture.TOKEN)).exists())

    def test_pending_update_or_reset_refuses_before_current_creation(self):
        for name in ("run/dcentos-sysupgrade.lock", "data/dcent/reset-settings"):
            with self.subTest(path=name):
                path = self.root / name
                path.write_bytes(b"pending")
                with self.assertRaises(FirstlightError): self.prepare()
                self.assertFalse(self.stage.exists())
                path.unlink()
                source = self.root / "tmp" / ("dcent-firstlight-" + restore_fixture.TOKEN)
                for child in source.iterdir(): child.unlink()
                source.rmdir()

    def test_retired_foreign_or_unknown_context_cannot_be_overwritten(self):
        foreign = self.stage.parent / ("retired-" + "f" * 32)
        foreign.mkdir()
        with self.assertRaises(FirstlightError): self.prepare()
        self.assertTrue(foreign.is_dir())
        self.assertFalse(self.stage.exists())

    def test_original_drift_before_actual_stage_refuses(self):
        self.fixture.binding.original.write_bytes(b"[mining]\nenabled=true\n")
        with self.assertRaises(FirstlightError): self.prepare()
        self.assertFalse(self.stage.exists())

    def test_actual_kill_at_each_preparation_barrier_never_exposes_partial_current(self):
        for cut in range(1, 6):
            with self.subTest(cut=cut):
                if cut > 1:
                    self.setUp()
                self.cut_at = cut
                with self.assertRaises(FirstlightError):
                    self.prepare()
                prepared = self.stage.parent / ("prepared-" + restore_fixture.TOKEN)
                self.assertEqual(self.fixture.binding.original.read_bytes(), self.fixture.original)
                self.cut_at = None
                if cut < 4:
                    self.assertTrue(prepared.is_dir())
                    self.assertFalse(self.stage.exists())
                    retained = {path.name: path.read_bytes() for path in prepared.iterdir()}
                    with self.assertRaises(FirstlightError):
                        self.recover_preparation()
                    self.assertEqual({path.name: path.read_bytes() for path in prepared.iterdir()}, retained)
                    self.assertFalse(self.stage.exists())
                else:
                    self.recover_preparation()
                    self.assertTrue(self.stage.is_dir())
                    self.assertFalse(prepared.exists())
                    self.fixture.assert_success(self.fixture.invoke())

    def test_prepared_recovery_refuses_foreign_context_links_and_unknown_contents(self):
        for change in ("foreign", "unknown", "symlink", "current", "original"):
            with self.subTest(change=change):
                if change != "foreign":
                    self.setUp()
                self.cut_at = 4
                with self.assertRaises(FirstlightError):
                    self.prepare()
                self.cut_at = None
                prepared = self.stage.parent / ("prepared-" + restore_fixture.TOKEN)
                if change == "foreign":
                    session = prepared / "session"
                    session.write_text(session.read_text().replace(restore_fixture.TOKEN, "f"*32))
                elif change == "unknown":
                    (prepared / "foreign-data").write_bytes(b"retain")
                elif change == "symlink":
                    phase = prepared / "work.toml"
                    phase.unlink()
                    phase.symlink_to(self.fixture.binding.original)
                elif change == "current":
                    self.stage.mkdir()
                    (self.stage / "foreign-data").write_bytes(b"retain")
                else:
                    self.fixture.binding.original.write_bytes(b"[mining]\nenabled=true\n")
                with self.assertRaises(FirstlightError):
                    self.recover_preparation()
                self.assertTrue(prepared.is_dir())
                if change == "current":
                    self.assertEqual((self.stage / "foreign-data").read_bytes(), b"retain")
                else:
                    self.assertFalse(self.stage.exists())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--s82", type=Path)
    args, remaining = parser.parse_known_args()
    if args.s82:
        restore_fixture.S82 = args.s82.resolve(strict=True)
    unittest.main(argv=[__file__, *remaining])
