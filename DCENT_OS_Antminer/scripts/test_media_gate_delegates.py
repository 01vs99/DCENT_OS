#!/usr/bin/env python3
"""Small ordinary-file negative fixtures for exact media helper call paths."""
import argparse
import configparser
from pathlib import Path
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
CI = PROJECT / "scripts/ci_offline_gates.sh"
S21XP_CONFIG = PROJECT / "br2_external_dcentos/board/amlogic/am3-s21xp/rootfs-overlay/etc/dcentrald.toml"
HELPER = Path("br2_external_dcentos/board/zynq/rootfs-overlay/usr/libexec/dcentos/am2-native-ota.sh")
NOPIC = Path("br2_external_dcentos/board/amlogic/am3-bm1362-nopic/post-build.sh")
DELEGATE = Path("br2_external_dcentos/board/amlogic/am3-s21/post-build.sh")


def function(name):
    source = CI.read_text(encoding="utf-8")
    begin = source.index(name + "() {\n")
    end = source.index("\n}\n", begin) + 3
    return source[begin:end]


def write(root, relative, source):
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")


def invoke(root, name, relative):
    # Execute only the named source-check function; never a post-build or updater.
    source = function(name) + '\n' + name + ' "$1"\n'
    return subprocess.run(["/bin/sh", "-c", source, "fixture", relative.as_posix()],
                          cwd=root, text=True, capture_output=True, timeout=5)


class MediaDelegateContracts(unittest.TestCase):
    def test_all_three_actual_am2_callers_join_the_canonical_environment_writer(self):
        for variant in ("am2-s19jpro", "am2-s19pro", "am2-s17pro"):
            caller = Path("br2_external_dcentos/board/zynq") / variant / "rootfs-overlay/usr/sbin/sysupgrade"
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write(root, caller, (PROJECT / caller).read_text(encoding="utf-8"))
                write(root, HELPER, (PROJECT / HELPER).read_text(encoding="utf-8"))
                result = invoke(root, "am2_sysupgrade_environment_delegate_ok", caller)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_am2_missing_commented_redirected_calls_and_incomplete_readback_refuse(self):
        caller = Path("br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/usr/sbin/sysupgrade")
        original = (PROJECT / caller).read_text(encoding="utf-8")
        helper = (PROJECT / HELPER).read_text(encoding="utf-8")
        cases = [
            (original.replace('AM2_OTA_HELPER="/usr/libexec/dcentos/am2-native-ota.sh"', '# AM2_OTA_HELPER="/usr/libexec/dcentos/am2-native-ota.sh"', 1), helper),
            (original.replace('AM2_OTA_HELPER="/usr/libexec/dcentos/am2-native-ota.sh"', 'AM2_OTA_HELPER="/tmp/foreign.sh"', 1), helper),
            (original.replace('\n. "$AM2_OTA_HELPER"', '\n# . "$AM2_OTA_HELPER"', 1), helper),
            (original.replace('\nam2_ota_commit_script ||', '\n# am2_ota_commit_script ||', 1), helper),
            (original.replace('if ! am2_ota_apply_environment; then', 'if ! true; then', 1), helper),
            (original, helper.replace('    fw_setenv -c "$FW_ENV_CONFIG" --script', '    # fw_setenv -c "$FW_ENV_CONFIG" --script', 1)),
            (original, helper.replace('    fw_printenv -c "$FW_ENV_CONFIG" > "$_am2_readback"', '    # fw_printenv -c "$FW_ENV_CONFIG" > "$_am2_readback"', 1)),
            (original, helper.replace('    [ ! -s "$_am2_errors" ] || return 1', '    : # warning readback ignored', 1)),
            (original, helper.replace('    if am2_ota_verify_snapshot after ', '    if true; then # ', 1)),
            (original, helper.replace('    if am2_ota_verify_snapshot before ', '    if true; then # ', 1)),
            (original, None),
        ]
        for index, (actual_caller, actual_helper) in enumerate(cases):
            with self.subTest(case=index), tempfile.TemporaryDirectory() as temporary:
                self.assertTrue(actual_caller != original or actual_helper != helper)
                root = Path(temporary)
                write(root, caller, actual_caller)
                if actual_helper is not None:
                    write(root, HELPER, actual_helper)
                self.assertNotEqual(invoke(root, "am2_sysupgrade_environment_delegate_ok", caller).returncode, 0)

    def test_actual_nopic_preflight_reaches_only_the_shared_provisioning_transaction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write(root, NOPIC, (PROJECT / NOPIC).read_text(encoding="utf-8"))
            write(root, DELEGATE, (PROJECT / DELEGATE).read_text(encoding="utf-8"))
            result = invoke(root, "nopic_post_build_release_delegate_ok", NOPIC)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_nopic_early_success_fake_or_redirected_delegate_and_missing_provision_refuse(self):
        original = (PROJECT / NOPIC).read_text(encoding="utf-8")
        target = (PROJECT / DELEGATE).read_text(encoding="utf-8")
        line = 'exec "$SCRIPT_DIR/../am3-s21/post-build.sh" "$@"'
        cases = [
            (original.replace(line, '# ' + line), target),
            (original.replace(line, 'exec /tmp/foreign "$@"'), target),
            (original.replace(line, 'exit 0\n' + line), target),
            (original.replace('        exit 1', '        exit 0'), target),
            (original.replace('am3-s19jproa|am3-s19jproplus', 'am3-s19jproa|am3-s19jproplus|am3-foreign'), target),
            (original.replace('usr/libexec/dcentos/bm1362-nopic-storage.py ', ''), target),
            (original + '\ntrue\n', target),
            (original, target.replace('\ndcent_provision_release_image "$TARGET_DIR" "$BOARD_NAME"', '\n# dcent_provision_release_image "$TARGET_DIR" "$BOARD_NAME"')),
            (original, target.replace('. "${BR2_EXTERNAL_DCENTOS_PATH}/../scripts/lib/release_image_provision.sh"', '# . "${BR2_EXTERNAL_DCENTOS_PATH}/../scripts/lib/release_image_provision.sh"')),
            (original, None),
        ]
        for index, (wrapper, delegate) in enumerate(cases):
            with self.subTest(case=index), tempfile.TemporaryDirectory() as temporary:
                self.assertTrue(wrapper != original or delegate != target)
                root = Path(temporary)
                write(root, NOPIC, wrapper)
                if delegate is not None:
                    write(root, DELEGATE, delegate)
                self.assertNotEqual(invoke(root, "nopic_post_build_release_delegate_ok", NOPIC).returncode, 0)

    def test_s21xp_hardware_enabled_config_requires_watchdog_while_booting_idle(self):
        source = S21XP_CONFIG.read_text(encoding="utf-8")
        config = configparser.ConfigParser(inline_comment_prefixes=("#",))
        config.read_string(source)
        self.assertTrue(config.getboolean("watchdog", "enabled"))
        self.assertEqual(config.getint("watchdog", "timeout_s"), 30)
        self.assertEqual(config.getint("watchdog", "kick_interval_s"), 5)
        self.assertFalse(config.getboolean("mining", "enabled"))
        self.assertEqual(config["platform"]["target"], '"am3-aml-s21xp"')
        policy = PROJECT / "br2_external_dcentos/board/amlogic/am3-s21xp/rootfs-overlay/etc/dcentos/mutation_policy"
        self.assertEqual(policy.read_text(encoding="utf-8"), "hardware-enabled\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=PROJECT)
    parser.add_argument("--candidate-ci", type=Path)
    parser.add_argument("--s21xp-config", type=Path)
    args = parser.parse_args()
    PROJECT = args.project.resolve()
    CI = args.candidate_ci or PROJECT / "scripts/ci_offline_gates.sh"
    S21XP_CONFIG = args.s21xp_config or PROJECT / "br2_external_dcentos/board/amlogic/am3-s21xp/rootfs-overlay/etc/dcentrald.toml"
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(MediaDelegateContracts))
    raise SystemExit(0 if result.wasSuccessful() else 1)
