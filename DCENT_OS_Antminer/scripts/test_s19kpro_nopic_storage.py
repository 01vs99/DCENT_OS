#!/usr/bin/env python3
"""Exact S19k Pro NoPic storage and startup regressions, using inert devices."""
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
OVERLAY = BOARD / "am3-s19kpro-nopic/rootfs-overlay"
SPEC = importlib.util.spec_from_file_location(
    "s19kpro_nopic_storage", OVERLAY / "usr/libexec/dcentos/s19kpro-nopic-storage.py")
storage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(storage)
nopic_spec = importlib.util.spec_from_file_location(
    "bm1362_nopic_storage_cross",
    BOARD / "am3-bm1362-nopic/rootfs-overlay/usr/libexec/dcentos/bm1362-nopic-storage.py")
sibling_storage = importlib.util.module_from_spec(nopic_spec)
nopic_spec.loader.exec_module(sibling_storage)
OriginalFixture = baseline.Fixture
TARGET = "am3-s19kpro"
PLATFORM = "am3-aml-s19kpro"


class Fixture(OriginalFixture):
    def __init__(self, root, target=TARGET):
        super().__init__(root)
        self.select(target)

    def select(self, target):
        platform = "am3-aml-" + target.removeprefix("am3-")
        self.write("/etc/dcentos/board_target", target)
        self.write("/etc/dcentos/platform", platform)
        self.write("/etc/dcentos-platform", platform)


class ExistingStorage(baseline.ExistingStorage):
    """Run the established destructive-failure and custody fixtures on this owner."""
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(baseline, "storage", storage).start()
        patch.object(baseline, "Fixture", Fixture).start()
        super().setUp()

    def test_exact_profile_binds_readiness_and_refuses_cross_model_rebind(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = Fixture(Path(temporary), TARGET)
            f.owner.early()
            f.owner.check()
            self.assertEqual(json.loads(f.path(storage.READY).read_text())["board_target"], TARGET)
            # The retained S19k owner refuses the A126/Plus120 identities and
            # the legacy am3-s19k runtime marker on a later rebind...
            for other in ("am3-s19jproa", "am3-s19jproplus", "am3-s19k"):
                with self.subTest(other=other):
                    f.select(other)
                    with self.assertRaises(storage.Refused):
                        f.owner.check()
            # ...and a new process with a different exact model cannot consume
            # this model's current-boot mount receipt either.
            for other, platform in (("am3-s19jproa", "am3-aml-s19jproa"),
                                    ("am3-s19jproplus", "am3-aml-s19jproplus")):
                with self.subTest(other=other), tempfile.TemporaryDirectory() as second:
                    g = Fixture(Path(second), other)
                    g.write(storage.READY, f.path(storage.READY).read_bytes())
                    with self.assertRaises(storage.Refused):
                        storage.Storage(g.root, g.run).check()

    def test_sibling_owners_refuse_s19k_identity_in_both_directions(self):
        # The retained A126/Plus120 owner refuses the S19k Pro identity...
        with tempfile.TemporaryDirectory() as temporary:
            f = Fixture(Path(temporary), TARGET)
            with self.assertRaises(sibling_storage.Refused):
                sibling_storage.Storage(f.root, f.run).controller_identity()
        # ...and the S19k Pro owner refuses both A126/Plus120 identities.
        for target, platform in (("am3-s19jproa", "am3-aml-s19jproa"),
                                 ("am3-s19jproplus", "am3-aml-s19jproplus")):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                f = Fixture(Path(temporary), target)
                with self.assertRaises(storage.Refused):
                    storage.Storage(f.root, f.run).controller_identity()

    def test_classic_pic_and_unadmitted_variants_refuse_before_any_command(self):
        for target in ("am3-s19jpro-aml", "am3-s21", "am3-s19k", "am3-s19jproa",
                       "am3-s19jproplus", "am3-s19kpro-extra"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                f = Fixture(Path(temporary), target)
                with self.assertRaises(storage.Refused):
                    f.owner.early()
                self.assertEqual(f.calls, [])

    def test_actual_s37_control_flow_uses_s19k_capability_route_before_failed_storage(self):
        # Exact S37 script; only electrical/sysfs leaves and receipt
        # publication are replaced with observable functions. The S19k Pro
        # identity takes the mutation-policy capability route, so the helper
        # must be present and grant boot-safeoff before any electrical leaf.
        source = (BOARD / "rootfs-overlay/etc/init.d/S37board_setup").read_text(encoding="utf-8")
        definitions, dispatch = source.split('case "${1:-start}" in', 1)
        scenarios = (
            ("present", "boot-safeoff", 0, 0, ["cut", "fans:30000/100000", "resets", "receipt"]),
            ("present", "boot-safeoff\ndaemon-hardware", 1, 0, ["cut", "fans:30000/100000"]),
            ("absent", "boot-safeoff", 0, 0, []),
            ("present", "daemon-hardware", 0, 0, []),
        )
        for helper, policy, power, fans, expected in scenarios:
            with self.subTest(helper=helper, policy=policy), tempfile.TemporaryDirectory() as temporary:
                f = Fixture(Path(temporary))
                f.write("/etc/dcentos/mutation_policy", policy)
                helper_path = f.path("/mutation-helper.sh")
                if helper == "present":
                    helper_path.write_text(
                        'dcent_mutation_policy_has() { grep -F -x "$2" "$1" >/dev/null 2>&1; }\n')
                    helper_value = str(helper_path)
                else:
                    helper_value = str(f.path("/absent-mutation-helper.sh"))
                trace = f.root / "electrical-fixture-trace"
                harness = definitions + f'''
IDENTITY_ROOT='{f.path("/etc/dcentos")}'
MUTATION_POLICY_FILE=$IDENTITY_ROOT/mutation_policy
MUTATION_POLICY_HELPER='{helper_value}'
force_psu_safe_low() {{ echo cut >> '{trace}'; return {power}; }}
configure_fans_checked() {{ echo "fans:$FAN_BOOT_DUTY_NS/$FAN_PERIOD_NS" >> '{trace}'; return {fans}; }}
pinmux_init() {{ echo resets >> '{trace}'; }}
write_receipt() {{ echo receipt >> '{trace}'; }}
case "${{1:-start}}" in''' + dispatch
                f.write(storage.BASELINE, harness)
                f.path(storage.BASELINE).chmod(0o755)
                f.write("/proc/mtd", "deliberately unavailable storage")
                def run_actual_baseline(argv):
                    f.run(argv)
                    if argv[0] == storage.BASELINE:
                        subprocess.run(["/bin/sh", str(f.path(storage.BASELINE)), "start"],
                                       check=True, capture_output=True, timeout=5)
                f.owner.runner = run_actual_baseline
                with self.assertRaises((storage.Refused, subprocess.CalledProcessError)):
                    f.owner.early()
                self.assertEqual(trace.read_text().splitlines() if trace.exists() else [], expected)
                self.assertFalse(any("ubifs" in call or "--bind" in call for call in f.calls))
                self.assertFalse(f.path(storage.READY).exists())


class StartupScripts(unittest.TestCase):
    def test_s19k_markers_refuse_legacy_post_install_before_loading_helpers(self):
        source = (BOARD / "rootfs-overlay/etc/init.d/S46post-install").read_text(encoding="utf-8")
        for marker in ("both", "target", "platform"):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                identity = root / "etc/dcentos"
                identity.mkdir(parents=True)
                if marker != "platform":
                    (identity / "board_target").write_text(TARGET)
                if marker != "target":
                    (root / "etc/dcentos-platform").write_text(PLATFORM)
                script = source.replace("/etc/", str(root / "etc") + "/")
                script = script.replace("/lib/functions/", str(root / "forbidden-helpers") + "/")
                result = subprocess.run(["/bin/sh", "-c", script, "S46post-install", "start"],
                                        text=True, capture_output=True, timeout=5)
                # This optional one-shot hook remains an idempotent no-op;
                # refusing its payload must not stop the later boot services.
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("unsigned S19k NAND post-install payloads are disabled", result.stdout)
                self.assertNotIn("forbidden-helpers", result.stderr)

    def test_s19k_target_cannot_trigger_legacy_nand_or_env_without_ota_capability(self):
        source = (BOARD / "rootfs-overlay/etc/init.d/S99upgrade").read_text(encoding="utf-8")
        for marker in ("both", "target", "platform"):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as temporary:
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
                    (root / "target").write_text(TARGET)
                if marker != "target":
                    (root / "platform").write_text(PLATFORM)
                env = dict(os.environ, PATH=str(binaries) + ":/usr/bin:/bin",
                           CALLS=str(root / "calls"),
                           DCENTOS_SYSTEM_MTD=str(root / "mtd5"),
                           DCENTOS_LOCAL_RECOVERY_FLAGS_OFFSET="0x0",
                           DCENTOS_BOARD_TARGET_FILE=str(root / "target"),
                           DCENTOS_PLATFORM_FILE=str(root / "platform"),
                           DCENTOS_MUTATION_POLICY_FILE=str(root / "absent-policy"),
                           DCENTOS_MUTATION_POLICY_HELPER=str(root / "absent-helper.sh"),
                           DCENTOS_FIRSTBOOT_PENDING_FILE=str(root / "pending"))
                script = source.replace("/lib/functions/system.sh", str(root / "absent-system.sh"))
                result = subprocess.run(["/bin/sh", "-c", script, "S99upgrade", "start"],
                                        env=env, text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 1)
                # Missing exact capabilities fail before the identity gate on
                # every target; no case may reach a NAND/environment tool.
                self.assertIn("refuse OTA/recovery mutation", result.stdout)
                self.assertFalse((root / "calls").exists(), result.stdout + result.stderr)
                self.assertTrue((root / "pending").exists())

    def test_daemon_requires_storage_before_operation_lock_for_s19k(self):
        source = (BOARD / "rootfs-overlay/etc/init.d/S82dcentrald").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = root / "etc/dcentos"
            identity.mkdir(parents=True)
            (identity / "board_target").write_text(TARGET)
            # The exact S19k daemon-hardware capability arm passes so the flow
            # reaches the storage-proof gate under test.
            (identity / "mutation_policy").write_text("boot-safeoff\ndaemon-hardware\n")
            (root / "policy-helper.sh").write_text(
                'dcent_mutation_policy_has() { grep -F -x "$2" "$1" >/dev/null 2>&1; }\n')
            (root / "refuse.py").write_text("raise SystemExit(21)\n")
            script = source.replace("/etc/", str(root / "etc") + "/")
            script = script.replace("/run/", str(root / "run") + "/")
            script = script.replace("/usr/libexec/dcentos/mutation-policy.sh", str(root / "policy-helper.sh"))
            script = script.replace("/usr/libexec/dcentos/s19kpro-nopic-storage.py", str(root / "refuse.py"))
            result = subprocess.run(["/bin/sh", "-c", script, "S82dcentrald", "start"],
                                    text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertIn("S19k Pro persistent namespace is not ready", result.stdout)
            self.assertFalse((root / "run").exists())

    def test_daemon_storage_proof_names_the_exact_s19k_owner(self):
        source = (BOARD / "rootfs-overlay/etc/init.d/S82dcentrald").read_text(encoding="utf-8")
        self.assertIn("am3-s19kpro)", source)
        self.assertIn("/usr/libexec/dcentos/s19kpro-nopic-storage.py check", source)
        # The A126/Plus120 arm stays distinct; neither model composes the
        # other's storage owner.
        self.assertIn("/usr/libexec/dcentos/bm1362-nopic-storage.py check", source)
        self.assertNotIn("s19kpro-nopic-storage.py check || {\n                    echo \"  [FAIL] A126/Plus120", source)

    def test_early_and_s45_propagate_helper_failure(self):
        for name, args in (("etc/dcentos-early-init.sh", []), ("etc/init.d/S45persistent", ["start"])):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                helper = Path(temporary) / "refuse.py"
                helper.write_text("raise SystemExit(23)\n")
                script = (OVERLAY / name).read_text().replace("/usr/libexec/dcentos/s19kpro-nopic-storage.py", str(helper))
                result = subprocess.run(["/bin/sh", "-c", script, name, *args], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 23)

    def test_s37_seals_exact_s19k_identity_pair_before_mutation(self):
        source = (BOARD / "rootfs-overlay/etc/init.d/S37board_setup").read_text(encoding="utf-8")
        self.assertIn("am3-aml-s19kpro:am3-s19kpro", source)
        body = source.split("read_identity() {", 1)[1]
        body = body[:body.index("\n}\n")]
        for platform, target, sealed in (
                (PLATFORM, TARGET, True),
                (PLATFORM, "am3-s19jproa", False),
                ("am3-aml-s19jproa", TARGET, False),
                ("am3-aml-s19k", TARGET, False),
                (PLATFORM, "am3-s19k", False)):
            with self.subTest(platform=platform, target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                identity = root / "etc/dcentos"
                identity.mkdir(parents=True)
                (identity / "board_target").write_text(target)
                (identity / "platform").write_text(platform)
                (identity / "rail_gpio").write_text("437")
                harness = (
                    "log_error() { echo \"ERR:$*\" >&2; return 1; }\n"
                    "read_trimmed() { [ -r \"$1\" ] || return 1; VALUE=$(cat \"$1\") || return 1; printf '%s' \"$VALUE\"; }\n"
                    "PWR_GPIO=437\n"
                    "IDENTITY_ROOT=" + str(identity) + "\n"
                    "read_identity() {" + body + "\n}\n"
                    "if read_identity; then echo SEALED; else echo REFUSED; fi\n")
                result = subprocess.run(["/bin/sh", "-c", harness], text=True, capture_output=True, timeout=5)
                self.assertIn("SEALED" if sealed else "REFUSED", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
