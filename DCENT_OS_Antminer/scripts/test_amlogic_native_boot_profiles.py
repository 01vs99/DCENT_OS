#!/usr/bin/env python3
"""Execute exact native AML boot identity/polarity logic on disposable files.

Only sysfs direction readback is emulated: writing high/low reads back out.
The production shell performs identity, policy, raw-polarity and value checks.
No real GPIO, miner, NAND or network access occurs.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

import generate_amlogic_gpio437 as gpio_policy

PROJECT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT / "br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S37board_setup"


@unittest.skipUnless(os.name == "posix", "actual POSIX shell execution")
class NativeBootProfiles(unittest.TestCase):
    def execute(self, target, platform=None, policy="boot-safeoff", wrong_readback=False, incomplete_evidence=False):
        with tempfile.TemporaryDirectory(prefix="dcent-native-boot-") as directory:
            root = Path(directory)
            identity = root / "identity"
            identity.mkdir()
            for name, value in {"board_target": target, "platform": platform or target.replace("am3-", "am3-aml-", 1), "rail_gpio": "437", "mutation_policy": policy}.items():
                (identity / name).write_text(value + "\n")
            gpio = root / "gpio/gpio437"
            gpio.mkdir(parents=True)
            for name, value in {"active_low": "1", "direction": "in", "value": "inherited"}.items():
                (gpio / name).write_text(value + "\n")
            source = SOURCE.read_text(encoding="utf-8")
            source = source[:source.index('case "${1:-start}" in')]
            harness = source + r'''
GPIO_ROOT=$1/gpio
IDENTITY_ROOT=$1/identity
MUTATION_POLICY_FILE=$IDENTITY_ROOT/mutation_policy
MUTATION_POLICY_HELPER=$3
GPIO437_POLICY_HELPER=$4
# Emulate only the documented sysfs readback shape; retain real shell writes.
read_trimmed() {
    [ -r "$1" ] || return 1
    value=$(cat "$1") || return 1
    case "$1" in
        */direction) case "$value" in high|low) value=out ;; esac ;;
        */value) [ "$2" != bad ] 2>/dev/null || value=0 ;;
    esac
    printf '%s' "$value"
}
require_mutation_authority || exit 21
force_psu_safe_low || exit 22
'''
            if wrong_readback:
                harness = harness.replace('[ "$2" != bad ] 2>/dev/null || value=0', 'value=0')
            helper = SOURCE.parents[2] / "usr/share/dcentos/amlogic-gpio437.sh"
            if incomplete_evidence:
                fixture = gpio_policy.load_policy()
                row = next(row for row in fixture["profiles"] if row["board_target"] == target)
                row["evidence"] = [item for item in row["evidence"] if fixture["sources"][item["source"]]["vendor"] != "epic"]
                helper = root / "incomplete-policy.sh"
                helper.write_text(gpio_policy.shell_text(fixture))
            script = root / "execute.sh"
            script.write_text(harness)
            result = subprocess.run(["sh", str(script), str(root), "unused", str(SOURCE.parents[2] / "usr/libexec/dcentos/mutation-policy.sh"), str(helper)], capture_output=True, text=True, timeout=5)
            state = {name: (gpio / name).read_text().strip() for name in ("active_low", "direction", "value")}
            return result, state

    QUALIFIED_TARGETS = ("am3-s19k", "am3-s19kpro", "am3-s21", "am3-s21pro", "am3-s21xp", "am3-s19xp", "am3-s19jxp", "am3-s19jproa", "am3-s19jproplus", "am3-s19jpro-aml")
    INCOMPLETE_FIXTURE_TARGETS = ("am3-s19jpro-aml",)

    def test_qualified_profiles_command_high_before_checked_off(self):
        for target in self.QUALIFIED_TARGETS:
            with self.subTest(target=target):
                result, state = self.execute(target, platform="am3-aml-s19jpro" if target == "am3-s19jpro-aml" else None)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(state, {"active_low": "0", "direction": "high", "value": "1"})

    def test_incomplete_evidence_fixture_leaves_the_rail_pin_undriven(self):
        for target in self.INCOMPLETE_FIXTURE_TARGETS:
            platform = "am3-aml-s19jpro" if target == "am3-s19jpro-aml" else None
            with self.subTest(target=target):
                result, state = self.execute(target, platform=platform, incomplete_evidence=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                # Input direction, and the value file is never written: an
                # undriven pin has no commanded level to claim.
                self.assertEqual(
                    state, {"active_low": "0", "direction": "in", "value": "inherited"}
                )
                self.assertIn("left undriven", result.stderr)

    def test_cross_paired_xp_identity_refuses_before_first_gpio_write(self):
        result, state = self.execute("am3-s19xp", platform="am3-aml-s19jxp")
        self.assertEqual(result.returncode, 21)
        self.assertEqual(state, {"active_low": "1", "direction": "in", "value": "inherited"})

    def test_classic_aml_uses_proved_off_and_rejects_opposite_readback(self):
        result, state = self.execute("am3-s19jpro-aml", platform="am3-aml-s19jpro")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(state, {"active_low": "0", "direction": "high", "value": "1"})
        result, state = self.execute("am3-s19jpro-aml", platform="am3-aml-s19jpro", wrong_readback=True)
        self.assertEqual(result.returncode, 22, result.stderr)
        self.assertIn("readback=0 expected=1", result.stderr)
        self.assertNotIn("safeoff", result.stdout.lower())

    def test_verifier_polarity_scope_matches_the_boot_writer_class(self):
        """S99verify's report must never out-claim S37's polarity evidence class."""
        for board in ("amlogic", "zynq"):
            verify = (PROJECT / f"br2_external_dcentos/board/{board}/rootfs-overlay/etc/init.d/S99verify").read_text()
            begin = verify.index("gpio437_polarity_scope() {")
            end = verify.index("\n}", begin) + 2
            scope = verify[begin:end]
            for target, expected in (
                ("am3-s21", "qualified-software"),
                ("am3-s19k", "qualified-software"),
                ("am3-s19jpro-aml", "qualified-software"),
                ("am3-s19xp", "qualified-software"),
                ("am3-s19jxp", "qualified-software"),
                ("am3-s19jproa", "qualified-software"),
                ("am3-s19jproplus", "qualified-software"),
            ):
                with self.subTest(board=board, target=target):
                    result = subprocess.run(
                        ["sh", "-c", scope + f"\nGPIO437_POLICY_HELPER=\"{SOURCE.parents[2] / 'usr/share/dcentos/amlogic-gpio437.sh'}\"\ngpio437_polarity_scope {target}"],
                        capture_output=True, text=True, timeout=5,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), expected)

    def test_classic_pic_v6_requires_owner_proof_and_never_skips_as_no_pic(self):
        for board in ("amlogic", "zynq"):
            verify = (PROJECT / f"br2_external_dcentos/board/{board}/rootfs-overlay/etc/init.d/S99verify").read_text()
            begin = verify.index("check_pic_fw() {")
            end = verify.index("\n}", begin) + 2
            for status in (0, 1, 127):
                with self.subTest(board=board, status=status):
                    # Execute the actual V6 function, replacing only its external
                    # proof process with a success/failure/missing-tool fixture.
                    harness = verify[begin:end] + f"""
PLATFORM=am3-aml
board_target=am3-s19jpro-aml
python3() {{
    [ "$1" = /usr/libexec/dcentos/verify-classic-aml-proof.py ] || return 98
    echo retained-owner-observation
    return {status}
}}
emit_check() {{ printf '%s|%s|%s\\n' "$1" "$2" "$3"; }}
gpio437_polarity_scope() {{ echo unexpected-NoPic-inheritance; exit 99; }}
check_pic_fw
"""
                    result = subprocess.run(["sh", "-c", harness], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(result.stdout.startswith("V6|true|" if status == 0 else "V6|false|"), result.stdout)
                    self.assertNotIn("skipped", result.stdout)

    def test_bm1362_no_pic_and_classic_identity_pairs_cannot_be_substituted(self):
        for target, platform in (("am3-s19jproa", "am3-aml-s19jproplus"),
                                 ("am3-s19jproplus", "am3-aml-s19jpro"),
                                 ("am3-s19jpro-aml", "am3-aml-s19jproa")):
            with self.subTest(target=target, platform=platform):
                result, state = self.execute(target, platform=platform)
                self.assertEqual(result.returncode, 21)
                self.assertEqual(state["value"], "inherited")

    def test_management_policy_refuses_before_first_gpio_write(self):
        result, state = self.execute("am3-s19jxp", policy="management-only")
        self.assertEqual(result.returncode, 21)
        self.assertEqual(state["value"], "inherited")

    def test_unregistered_xp_revision_refuses_before_first_gpio_write(self):
        result, state = self.execute("am3-s19jxp-extra")
        self.assertEqual(result.returncode, 21)
        self.assertEqual(state["direction"], "in")

    def test_wrong_gpio_readback_never_reports_safe_off(self):
        # A qualified output still requires matching raw readback.
        result, _ = self.execute("am3-s21", wrong_readback=True)
        self.assertEqual(result.returncode, 22)
        self.assertIn("readback=0 expected=1", result.stderr)


if __name__ == "__main__":
    unittest.main()
