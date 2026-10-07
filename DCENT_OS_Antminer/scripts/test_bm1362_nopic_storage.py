#!/usr/bin/env python3
"""Exact A126/Plus120 storage and startup regressions, using inert devices."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_classic_aml_storage as baseline


BOARD = baseline.BOARD
OVERLAY = BOARD / "am3-bm1362-nopic/rootfs-overlay"
SPEC = importlib.util.spec_from_file_location(
    "nopic_storage", OVERLAY / "usr/libexec/dcentos/bm1362-nopic-storage.py")
storage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(storage)
OriginalFixture = baseline.Fixture
TARGETS = ("am3-s19jproa", "am3-s19jproplus")


class Fixture(OriginalFixture):
    def __init__(self, root, target="am3-s19jproplus"):
        super().__init__(root)
        self.select(target)

    def select(self, target):
        self.write("/etc/dcentos/board_target", target)
        platform = "am3-aml-" + target.removeprefix("am3-")
        self.write("/etc/dcentos/platform", platform)
        self.write("/etc/dcentos-platform", platform)


class ExistingStorage(baseline.ExistingStorage):
    """Run the established destructive-failure and custody fixtures on this owner."""
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(baseline, "storage", storage).start()
        patch.object(baseline, "Fixture", Fixture).start()
        super().setUp()

    def test_both_exact_profiles_bind_readiness_and_refuse_cross_model_rebind(self):
        for target in TARGETS:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                f = Fixture(Path(temporary), target)
                f.owner.early()
                f.owner.check()
                self.assertEqual(json.loads(f.path(storage.READY).read_text())["board_target"], target)
                f.select(next(other for other in TARGETS if other != target))
                with self.assertRaisesRegex(storage.Refused, "identity changed"):
                    f.owner.check()
                # A new process with a different exact model cannot consume
                # the first model's current-boot mount receipt either.
                with self.assertRaises(storage.Refused):
                    storage.Storage(f.root, f.run).check()

    def test_classic_pic_and_unadmitted_variants_refuse_before_any_command(self):
        for target in ("am3-s19jpro-aml", "am3-s21", "am3-s19k", "am3-s19jproa-plus"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                f = Fixture(Path(temporary), target)
                with self.assertRaises(storage.Refused):
                    f.owner.early()
                self.assertEqual(f.calls, [])

    def test_actual_s37_control_flow_before_failed_storage(self):
        # Same actual script/control-flow fixture, with both NoPIC identities.
        for target in TARGETS:
            with self.subTest(target=target), patch.object(
                    baseline, "Fixture", lambda root: Fixture(root, target)):
                baseline.StartupScripts.test_early_invokes_actual_s37_policy_cut_fan_and_reset_control_flow(self)


class StartupScripts(unittest.TestCase):
    def test_both_profiles_refuse_legacy_post_install_before_loading_helpers(self):
        source = (BOARD / "rootfs-overlay/etc/init.d/S46post-install").read_text(encoding="utf-8")
        for target in TARGETS:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                identity = root / "etc/dcentos"
                identity.mkdir(parents=True)
                (identity / "board_target").write_text(target)
                script = source.replace("/etc/", str(root / "etc") + "/")
                script = script.replace("/lib/functions/", str(root / "forbidden-helpers") + "/")
                result = subprocess.run(["/bin/sh", "-c", script, "S46post-install", "start"],
                                        text=True, capture_output=True, timeout=5)
                # This optional one-shot hook remains an idempotent no-op;
                # refusing its payload must not stop the later boot services.
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("A126/Plus120 legacy unsigned NAND", result.stdout)
                self.assertNotIn("forbidden-helpers", result.stderr)

    def test_pending_intent_and_single_marker_cannot_trigger_legacy_nand_or_env(self):
        source = (BOARD / "rootfs-overlay/etc/init.d/S99upgrade").read_text(encoding="utf-8")
        for target in TARGETS:
            for marker in ("both", "target", "platform"):
                with self.subTest(target=target, marker=marker), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    binaries = root / "bin"
                    binaries.mkdir()
                    for command in ("fw_printenv", "fw_setenv", "nanddump", "nandwrite", "flash_erase"):
                        p = binaries / command
                        p.write_text('#!/bin/sh\necho unexpected >> "$CALLS"\nexit 1\n')
                        p.chmod(0o755)
                    (root / "pending").touch()
                    (root / "mtd5").touch()
                    if marker != "platform":
                        (root / "target").write_text(target)
                    if marker != "target":
                        (root / "platform").write_text("am3-aml-" + target.removeprefix("am3-"))
                    env = dict(os.environ, PATH=str(binaries) + ":/usr/bin:/bin",
                               CALLS=str(root / "calls"),
                               DCENTOS_SYSTEM_MTD=str(root / "mtd5"),
                               DCENTOS_LOCAL_RECOVERY_FLAGS_OFFSET="0x0",
                               DCENTOS_BOARD_TARGET_FILE=str(root / "target"),
                               DCENTOS_PLATFORM_FILE=str(root / "platform"),
                               DCENTOS_MUTATION_POLICY_FILE=str(root / "absent-policy"),
                               DCENTOS_FIRSTBOOT_PENDING_FILE=str(root / "pending"))
                    script = source.replace("/lib/functions/system.sh", str(root / "absent-system.sh"))
                    result = subprocess.run(["/bin/sh", "-c", script, "S99upgrade", "start"],
                                            env=env, text=True, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn("A126/Plus120", result.stdout)
                    self.assertFalse((root / "calls").exists(), result.stdout + result.stderr)
                    self.assertTrue((root / "pending").exists())

    def test_daemon_requires_storage_before_operation_lock_for_both_profiles(self):
        source = (BOARD / "rootfs-overlay/etc/init.d/S82dcentrald").read_text(encoding="utf-8")
        for target in TARGETS:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                identity = root / "etc/dcentos"
                identity.mkdir(parents=True)
                (identity / "board_target").write_text(target)
                (root / "refuse.py").write_text("raise SystemExit(21)\n")
                script = source.replace("/etc/", str(root / "etc") + "/")
                script = script.replace("/run/", str(root / "run") + "/")
                script = script.replace("/usr/libexec/dcentos/bm1362-nopic-storage.py", str(root / "refuse.py"))
                result = subprocess.run(["/bin/sh", "-c", script, "S82dcentrald", "start"],
                                        text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 1)
                self.assertIn("persistent namespace is not ready", result.stdout)
                self.assertFalse((root / "run").exists())

    def test_early_and_s45_propagate_helper_failure(self):
        for name, args in (("etc/dcentos-early-init.sh", []), ("etc/init.d/S45persistent", ["start"])):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                helper = Path(temporary) / "refuse.py"
                helper.write_text("raise SystemExit(23)\n")
                script = (OVERLAY / name).read_text().replace("/usr/libexec/dcentos/bm1362-nopic-storage.py", str(helper))
                result = subprocess.run(["/bin/sh", "-c", script, name, *args], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 23)


if __name__ == "__main__":
    unittest.main(verbosity=2)
