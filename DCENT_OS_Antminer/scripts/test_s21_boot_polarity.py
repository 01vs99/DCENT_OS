#!/usr/bin/env python3
"""Execute the real S37/S99 polarity branches against isolated sysfs fixtures."""

import pathlib
import shlex
import subprocess
import tempfile
import unittest

import generate_amlogic_gpio437 as gpio_policy


PROJECT = pathlib.Path(__file__).resolve().parents[1]
BOARD = PROJECT / "br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d"
POLICY = BOARD.parents[1] / "usr/share/dcentos/amlogic-gpio437.sh"
SOURCE = (BOARD / "S37board_setup").read_text().split('\ncase "${1:-start}" in')[0]

PLATFORM_BY_TARGET = {
    # Two-vendor software evidence; no measurement claim.
    "am3-s21": "am3-aml-s21",
    "am3-s19k": "am3-aml-s19k",
    "am3-s21pro": "am3-aml-s21pro",
    "am3-s21xp": "am3-aml-s21xp",
    # Exact model composition is qualified independently in the table.
    "am3-s19xp": "am3-aml-s19xp",
    "am3-s19jxp": "am3-aml-s19jxp",
    "am3-s19jproa": "am3-aml-s19jproa",
    "am3-s19jproplus": "am3-aml-s19jproplus",
    "am3-s19jpro-aml": "am3-aml-s19jpro",
}

INCOMPLETE_FIXTURE_TARGETS = ("am3-s19jpro-aml",)


class S21BootPolarityTests(unittest.TestCase):
    def execute(self, target, value, *, corrupt_receipt=False, reject_direction=False,
                receipt_state="boot-safe", restart_case=None):
        with tempfile.TemporaryDirectory(prefix="dcent-s21-boot-") as temporary:
            root = pathlib.Path(temporary)
            for gpio in (437, 454, 455, 456):
                directory = root / "gpio" / f"gpio{gpio}"
                directory.mkdir(parents=True)
                for name, text in {"active_low": "0", "direction": "out", "value": "0"}.items():
                    (directory / name).write_text(text + "\n")
            for fan in (0, 1):
                directory = root / "pwm" / f"pwm{fan}"
                directory.mkdir(parents=True)
                for name, text in {"period": "100000", "duty_cycle": "30000", "enable": "1"}.items():
                    (directory / name).write_text(text + "\n")
            identity = root / "identity"
            identity.mkdir()
            platform = PLATFORM_BY_TARGET[target]
            for name, text in {"platform": platform, "board_target": target, "rail_gpio": "437"}.items():
                (identity / name).write_text(text + "\n")
            # Linux sysfs changes 'high'/'low' into direction 'out'; emulate
            # only this kernel ABI boundary. Everything else is real shell,
            # ordinary file readback, receipt production and revalidation.
            script = SOURCE + f"""
GPIO437_POLICY_HELPER={shlex.quote(str(POLICY))}
GPIO_ROOT={shlex.quote(str(root / 'gpio'))}
PWM_ROOT={shlex.quote(str(root / 'pwm'))}
IDENTITY_ROOT={shlex.quote(str(identity))}
RECEIPT_DIR={shlex.quote(str(root / 'run'))}
RECEIPT=$RECEIPT_DIR/receipt
set_gpio_direction_checked() {{
    [ {int(reject_direction)} = 0 ] || return 1
    [ "$2" = {('high' if value else 'low')} ] || return 1
    printf 'out\\n' > "$GPIO_ROOT/gpio$1/direction"
}}
read_identity || exit 20
force_psu_safe_low || exit 21
[ "$(cat "$GPIO_ROOT/gpio437/value")" = {value} ] || exit 22
write_receipt {receipt_state} || exit 23
receipt_field_is commanded_value {value} || exit 24
receipt_field_is readback_value {value} || exit 25
"""
            if corrupt_receipt:
                script += "sed -i 's/commanded_value=1/commanded_value=0/; s/readback_value=1/readback_value=0/' \"$RECEIPT\"\n"
            if restart_case is None:
                script += "verify_boot_safe_receipt || exit 26\n"
            else:
                # Execute full S82 start/restart and the actual S37 verifier,
                # runtime handoff, and persistent session prepare functions.
                # Only kernel sysfs ABI and daemon spawning are simulated.
                settings = script[len(SOURCE):].split("set_gpio_direction_checked()", 1)[0]
                policy_helper = BOARD.parents[1] / "usr/libexec/dcentos/mutation-policy.sh"
                (identity / "mutation_policy").write_text("boot-safeoff\ndaemon-hardware\n")
                (identity / "mutation_policy").chmod(0o600)
                settings += f"MUTATION_POLICY_FILE={shlex.quote(str(identity / 'mutation_policy'))}\nMUTATION_POLICY_HELPER={shlex.quote(str(policy_helper))}\n"
                board_setup = root / "board-setup"
                dispatch = '\ncase "${1:-start}" in' + (BOARD / "S37board_setup").read_text().split('\ncase "${1:-start}" in', 1)[1]
                kernel_abi = '''
set_gpio_direction_checked() {
    case "$2" in
        high) printf 'out\\n' > "$GPIO_ROOT/gpio$1/direction"; printf '1\\n' > "$GPIO_ROOT/gpio$1/value" ;;
        low) printf 'out\\n' > "$GPIO_ROOT/gpio$1/direction"; printf '0\\n' > "$GPIO_ROOT/gpio$1/value" ;;
        in|out) printf '%s\\n' "$2" > "$GPIO_ROOT/gpio$1/direction" ;;
        *) return 1 ;;
    esac
}
'''
                board_setup.write_text(SOURCE + settings + kernel_abi + dispatch)
                board_setup.chmod(0o700)
                s82 = (BOARD / "S82dcentrald").read_text()
                supervisor = root / "supervisor"
                helper = PROJECT / "br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-session-latch.sh"
                state = root / "data/dcent"
                state.mkdir(parents=True)
                unresolved = state / "dcentrald-hardware-session.unresolved"
                crash = state / "dcentrald-hardware-session.crash-latched"
                if restart_case == "dirty":
                    crash.write_text("crash-latched\n")
                if restart_case == "unresolved":
                    unresolved.write_text("previous-session-unresolved\n")
                latch = root / "latch"
                mounts = root / "mounts"
                mounts.write_text(f"/dev/fixture {root / 'data'} ext4 rw 0 0\n")
                helper_source = helper.read_text().replace("/data", str(root / "data")).replace("/run/dcentos-sysupgrade.lock", str(root / "update-lock"))
                helper_source = helper_source.replace("MOUNTS_FILE=/proc/mounts", f"MOUNTS_FILE={shlex.quote(str(mounts))}")
                latch.write_text(helper_source)
                daemon = root / "daemon"
                daemon.write_text("#!/bin/sh\nexit 99\n")
                daemon.chmod(0o700)
                config = root / "config"
                config.write_text("[api]\nport = 8080\n")
                launched = root / "launched"
                commands = root / "commands"
                commands.mkdir()
                spawn = commands / "start-stop-daemon"
                spawn.write_text(f'''#!/bin/sh
[ -f {shlex.quote(str(unresolved))} ] || exit 91
grep -qx state=runtime-handoff {shlex.quote(str(root / 'run/receipt'))} || exit 92
touch {shlex.quote(str(launched))}
echo READMISSION_STARTED
''')
                spawn.chmod(0o700)
                overrides = f'''
PATH={shlex.quote(str(commands))}:$PATH
DAEMON={shlex.quote(str(daemon))}
CONFIG={shlex.quote(str(config))}
BOARD_SETUP={shlex.quote(str(board_setup))}
SESSION_LATCH_HELPER={shlex.quote(str(latch))}
MUTATION_POLICY_HELPER={shlex.quote(str(policy_helper))}
LOGFILE={shlex.quote(str(root / 'log'))}
PIDFILE={shlex.quote(str(root / 'pid'))}
CHILD_PIDFILE={shlex.quote(str(root / 'child-pid'))}
EXPECTFILE={shlex.quote(str(root / 'expected'))}
sleep() {{ :; }}
pidof() {{ [ -e {shlex.quote(str(launched))} ] && printf '424242\\n'; }}
'''
                s82 = s82.replace("/data", str(root / "data")).replace("/etc/dcentos", str(identity)).replace("/run/dcentos", str(root / "run")).replace("/sys/class/pwm/pwmchip0", str(root / "pwm"))
                s82 = s82.replace('\ncase "$1" in', overrides + '\ncase "$1" in', 1)
                supervisor.write_text(s82)
                supervisor.chmod(0o700)
                if receipt_state == "terminal-safe":
                    script += "if verify_boot_safe_receipt; then exit 27; fi\n"
                if restart_case == "changed-pin":
                    script += 'printf "0\\n" > "$GPIO_ROOT/gpio437/value"\n'
                # Invalid start baselines must fail directly. Restart's real
                # stop path may legitimately establish a fresh safe baseline.
                action = "restart" if restart_case in ("restart", "dirty", "unresolved") else "start"
                script += f"\n{shlex.quote(str(supervisor))} {action}\n"
            return subprocess.run(["sh"], input=script, text=True, capture_output=True)

    def test_terminal_receipt_allows_checked_s82_restart(self):
        for action in ("clean", "restart"):
            with self.subTest(action=action):
                result = self.execute("am3-s21", 1, receipt_state="terminal-safe", restart_case=action)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("READMISSION_STARTED", result.stdout)

    def test_boot_receipt_remains_a_valid_start_baseline(self):
        result = self.execute("am3-s21", 1, restart_case="clean")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_terminal_receipt_cannot_override_dirty_session_or_live_pin_change(self):
        for case in ("dirty", "unresolved", "changed-pin"):
            with self.subTest(case=case):
                result = self.execute("am3-s21", 1, receipt_state="terminal-safe", restart_case=case)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("READMISSION_STARTED", result.stdout)

    def test_handoff_or_corrupt_receipt_cannot_admit_s82_restart(self):
        for state, corrupt in (("runtime-handoff", False), ("terminal-safe", True)):
            with self.subTest(state=state, corrupt=corrupt):
                result = self.execute("am3-s21", 1, receipt_state=state,
                                      corrupt_receipt=corrupt, restart_case="clean")
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("READMISSION_STARTED", result.stdout)

    def test_s21_high_off_command_receipt_and_readback(self):
        result = self.execute("am3-s21", 1)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_s19k_high_off_is_preserved(self):
        result = self.execute("am3-s19k", 1)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_s21pro_production_profile_high_off(self):
        result = self.execute("am3-s21pro", 1)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_s21xp_production_profile_high_off(self):
        result = self.execute("am3-s21xp", 1)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_old_base_s21_low_off_receipt_is_rejected(self):
        self.assertEqual(self.execute("am3-s21", 1, corrupt_receipt=True).returncode, 26)

    def test_failed_s21_direction_write_cannot_produce_receipt(self):
        self.assertEqual(self.execute("am3-s21", 1, reject_direction=True).returncode, 21)

    def execute_undriven(self, target):
        """Remove vendor2 in a fixture, then run the real S37 writer and receipt."""
        with tempfile.TemporaryDirectory(prefix="dcent-s21-undriven-") as temporary:
            root = pathlib.Path(temporary)
            for gpio in (437, 454, 455, 456):
                directory = root / "gpio" / f"gpio{gpio}"
                directory.mkdir(parents=True)
                for name, text in {"active_low": "0", "direction": "out", "value": "0"}.items():
                    (directory / name).write_text(text + "\n")
            for fan in (0, 1):
                directory = root / "pwm" / f"pwm{fan}"
                directory.mkdir(parents=True)
                for name, text in {"period": "100000", "duty_cycle": "30000", "enable": "1"}.items():
                    (directory / name).write_text(text + "\n")
            identity = root / "identity"
            identity.mkdir()
            for name, text in {
                "platform": PLATFORM_BY_TARGET[target],
                "board_target": target,
                "rail_gpio": "437",
            }.items():
                (identity / name).write_text(text + "\n")
            fixture = gpio_policy.load_policy()
            row = next(row for row in fixture["profiles"] if row["board_target"] == target)
            row["evidence"] = [item for item in row["evidence"] if fixture["sources"][item["source"]]["vendor"] != "epic"]
            helper = root / "incomplete-policy.sh"
            helper.write_text(gpio_policy.shell_text(fixture))
            script = SOURCE + f"""
GPIO437_POLICY_HELPER={shlex.quote(str(helper))}
GPIO_ROOT={shlex.quote(str(root / 'gpio'))}
PWM_ROOT={shlex.quote(str(root / 'pwm'))}
IDENTITY_ROOT={shlex.quote(str(identity))}
RECEIPT_DIR={shlex.quote(str(root / 'run'))}
RECEIPT=$RECEIPT_DIR/receipt
set_gpio_direction_checked() {{
    [ "$2" = "$3" ] || return 1
    printf '%s\\n' "$2" > "$GPIO_ROOT/gpio$1/direction"
}}
read_identity || exit 20
[ "$(psu_polarity_class "$BOARD_TARGET")" = undriven ] || exit 27
force_psu_safe_low || exit 21
# The pin must be an input: boot never drives an unproven rail polarity.
[ "$(cat "$GPIO_ROOT/gpio437/direction")" = in ] || exit 22
write_receipt boot-safe || exit 23
receipt_field_is gpio_direction in || exit 24
receipt_field_is commanded_value undriven || exit 25
receipt_field_is psu_polarity_class undriven || exit 28
verify_boot_safe_receipt || exit 26
"""
            return subprocess.run(["sh"], input=script, text=True, capture_output=True)

    def test_missing_vendor_fixture_stays_undriven_at_boot(self):
        for target in INCOMPLETE_FIXTURE_TARGETS:
            with self.subTest(target=target):
                result = self.execute_undriven(target)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_table_membership_is_exact_and_unknown_targets_emit_nothing(self):
        script = SOURCE + f"\nGPIO437_POLICY_HELPER={shlex.quote(str(POLICY))}\n" + """
for t in am3-s19k am3-s19kpro am3-aml-s19kpro am3-s21 am3-s21pro am3-s21xp am3-s19xp am3-s19jxp am3-s19jproa am3-s19jproplus am3-s19jpro-aml; do
    [ "$(psu_polarity_class "$t")" = qualified-software ] || exit 40
done
for t in '' am3-bb am3-t21 amlogic-s21plus am3-s21-unknown; do
    psu_polarity_class "$t" && exit 42
done
exit 0
"""
        result = subprocess.run(["sh"], input=script, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_newly_qualified_exact_models_command_off(self):
        for target in ("am3-s19xp", "am3-s19jxp", "am3-s19jproa", "am3-s19jproplus", "am3-s19jpro-aml"):
            result = self.execute(target, 1)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_all_shipped_s99_copies_report_exact_polarity(self):
        for source in (PROJECT / "br2_external_dcentos").rglob("S99verify"):
            text = source.read_text()
            if "gpio437_polarity_scope()" not in text:
                continue
            functions = text.split("gpio437_polarity_scope()", 1)[1].split("# Report-only software SafeOff-on-stop.", 1)[0]
            script = f"GPIO437_POLICY_HELPER={shlex.quote(str(POLICY))}\n" + "gpio437_polarity_scope()" + functions + """
[ "$(gpio437_software_state am3-s21 1 out 0)" = safeoff ] || exit 30
[ "$(gpio437_software_state am3-s21 0 out 0)" = engaged ] || exit 31
[ "$(gpio437_software_state am3-s19k 1 out 0)" = safeoff ] || exit 32
[ "$(gpio437_software_state am3-s21pro 1 out 0)" = safeoff ] || exit 33
[ "$(gpio437_software_state am3-s21xp 1 out 0)" = safeoff ] || exit 35
[ "$(gpio437_software_state am3-s21xp 0 out 0)" = engaged ] || exit 36
[ "$(gpio437_software_state am3-s21-unknown 0 out 0)" = unknown ] || exit 34
# Input and inversion cannot mint an ON/OFF observation.
[ "$(gpio437_software_state am3-s21 1 in 0)" = undriven ] || exit 43
[ "$(gpio437_software_state am3-s21 1 out 1)" = unknown ] || exit 44
[ "$(gpio437_software_state am3-s21 1 out)" = unknown ] || exit 45
for t in am3-s19xp am3-s19jxp am3-s19jproa am3-s19jproplus am3-s19jpro-aml; do
    [ "$(gpio437_software_state "$t" 1 out 0)" = safeoff ] || exit 46
done
# Classic's proved level remains distinct from undriven input or inversion.
[ "$(gpio437_software_state am3-s19jpro-aml 0 out 0)" = engaged ] || exit 37
[ "$(gpio437_software_state am3-s19jpro-aml 1 in 0)" = undriven ] || exit 38
[ "$(gpio437_software_state am3-s19jpro-aml 1 out 1)" = unknown ] || exit 39
"""
            result = subprocess.run(["sh"], input=script, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, f"{source}: {result.stderr}")


if __name__ == "__main__":
    unittest.main()
