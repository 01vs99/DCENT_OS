#!/usr/bin/env python3
"""Execute existing production safety guards without the comprehensive campaign."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
GATE = PROJECT / "scripts/ci_offline_gates.sh"
# These functions own source safety checks, not docs or a frozen registry.
GUARDS = (
    "panic_abort_check",
    "swap_bytes_midstate_check",
    "pic16_i2c_rdwr_ban_check",
    "mtd4_raw_nand_helper_ban_check",
    "set_enabled_false_check",
    "short_form_reset_check",
    "jump_to_app_check",
    "set_voltage_gate_check",
    "deferred_voltage_arch_check",
    "bip320_rejection_guard_check",
    "fan_pwm_cap_check",
    "fan_max_pwm_toml_check",
    "recovery_tool_not_in_daemon_check",
)


def guard_source(source, name):
    # Each existing guard has a top-level definition followed by its literal
    # call. Reuse both; missing/renamed calls are failures, not empty tests.
    match = re.search(
        rf"(?ms)^{re.escape(name)}\(\) \{{\n.*?^\}}\n{re.escape(name)}[ \t]*$",
        source,
    )
    if match is None:
        raise ValueError(f"missing complete production guard and call: {name}")
    return match.group(0)


PROLOGUE = r'''set -eu
failures=0
pass() { :; }
fail() { printf 'FAIL: %s\n' "$*" >&2; failures=$((failures + 1)); }
require_file() { [ -f "$1" ] || fail "missing file: $1"; }
require_pattern() { if ! grep -F -- "$2" "$1" >/dev/null; then fail "$3"; fi; }
reject_pattern() { if [ ! -f "$1" ] || grep -F -- "$2" "$1" >/dev/null; then fail "$3"; fi; }
'''


class BlockingSourceGuards(unittest.TestCase):
    def test_amlogic_literal_restart_requires_consumed_closeout(self):
        source = (PROJECT / "br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S82dcentrald").read_text(encoding="utf-8")
        function = re.search(r"(?ms)^restart_after_software_closeout\(\) \{\n.*?^\}", source).group(0)
        self.assertRegex(source, r"restart\)\s+restart_after_software_closeout\s+exit \$\?")
        for shell in (["sh"], ["busybox", "ash"]):
            for kind, stop_exit, start_exit, expected in (
                ("clear", 0, 0, 0), ("delayed-clear", 0, 0, 0),
                ("missing-proof", 0, 0, 1), ("crash-latched", 0, 0, 1),
                ("invalid-status", 0, 0, 1), ("failed-clear", 0, 0, 1),
                ("clear", 7, 0, 7), ("clear", 0, 8, 8),
            ):
                with self.subTest(shell=shell, kind=kind, stop=stop_exit, start=start_exit), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    supervisor = root / "supervisor"
                    supervisor.write_text("#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$TRACE\"\n"
                                          "case \"$1\" in stop) exit \"$STOP_EXIT\";; start) exit \"$START_EXIT\";; *) exit 99;; esac\n",
                                          encoding="utf-8")
                    supervisor.chmod(0o700)
                    latch = root / "latch"
                    latch.write_text("#!/bin/sh\n[ \"$1\" = status ] || exit 99\nprintf 'status\\n' >> \"$TRACE\"\n"
                                     "case \"$KIND\" in\nclear) echo clear; exit 0;;\n"
                                     "delayed-clear) if [ -e \"$ONCE\" ]; then echo clear; exit 0; fi; : > \"$ONCE\"; echo unresolved; exit 1;;\n"
                                     "missing-proof) echo unresolved; exit 1;;\ncrash-latched) echo crash-latched; exit 2;;\n"
                                     "invalid-status) echo unknown; exit 0;;\nfailed-clear) echo clear; exit 1;;\nesac\n",
                                     encoding="utf-8")
                    trace = root / "trace"
                    result = subprocess.run(shell + ["-c", function + "\nsleep() { :; }\nrestart_after_software_closeout\n"],
                                            env={**os.environ, "SCRIPT": str(supervisor), "SESSION_LATCH_HELPER": str(latch),
                                                 "TRACE": str(trace), "ONCE": str(root / "once"), "KIND": kind,
                                                 "STOP_EXIT": str(stop_exit), "START_EXIT": str(start_exit)},
                                            capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    events = trace.read_text(encoding="utf-8").splitlines()
                    self.assertEqual(events[0], "stop")
                    if stop_exit:
                        self.assertEqual(events, ["stop"])
                    elif kind in ("clear", "delayed-clear"):
                        self.assertEqual(events[-1], "start")
                        self.assertIn("status", events[1:-1])
                    else:
                        self.assertNotIn("start", events)

    def test_orderly_restart_publishers_require_real_terminal_receipts(self):
        rust = PROJECT / "dcentrald/dcentrald/src"
        daemon = (rust / "daemon.rs").read_text(encoding="utf-8")
        helper = daemon.split("pub(crate) fn publish_orderly_software_closeout(", 1)[1]
        helper = helper.split("/// Capture and durably journal", 1)[0]
        self.assertIn("&crate::runtime::safety_watchdog::WatchdogCloseoutReceipt", helper)
        self.assertIn("&unresolved_mutation_journal_entries()", helper)
        self.assertNotIn("remove_file", helper)

        serial = (rust / "serial_mining.rs").read_text(encoding="utf-8")
        classifier = serial.split("fn classify_serial_terminal_result(", 1)[1]
        classifier = classifier.split("async fn failure_with_exact_serial_closeout(", 1)[0]
        self.assertRegex(classifier, r"\(true, None, Some\(closeout\)\) => \{\s*"
                         r"crate::daemon::publish_orderly_software_closeout\(software_closeout_run, &closeout\)")
        self.assertEqual(classifier.count("publish_orderly_software_closeout("), 1)
        self.assertIn("(true, None, None) => Err(watchdog_reset_pending_error(", classifier)
        self.assertIn("(true, Some(error), Some(closeout)) => Err(terminal_safe_off_error(error, closeout))", classifier)
        self.assertIn("(false, None, _) => Ok(())", classifier)
        self.assertIn("terminal_watchdog_closeout,\n            software_closeout_run,", serial)

        # These real owner functions possess the opaque closeout only after
        # disarm-and-join. Each error arm retains its existing typed error;
        # only the successful mining result may publish restart authority.
        for name, entry, arm, receipt in (
            ("s19j_hybrid_mining.rs", "pub async fn run(&mut self)", "None", "closeout"),
            ("s17_native_runtime.rs", "pub(super) async fn run(", "Ok(())", "closeout"),
            ("s19_bm1398_native_mining.rs", "pub(crate) async fn run(", "Ok(())", "receipt"),
            ("serial_mining/classic_aml_runtime.rs", "pub(super) async fn run(", "Ok(())", "receipt"),
            ("bm1391_mining.rs", "pub(crate) async fn run(", "Ok(())", "receipt"),
            ("c43_bm1393_mining.rs", "pub(crate) async fn run(", "Ok(())", "receipt"),
            ("bm1396_mining.rs", "pub(crate) async fn run(", "Ok(())", "actual_receipt"),
        ):
            with self.subTest(owner=name):
                source = (rust / name).read_text(encoding="utf-8").split(entry, 1)[1]
                call = f"{arm} => crate::daemon::publish_orderly_software_closeout(software_closeout_run, &{receipt})"
                compact = re.sub(r"\s+", "", source)
                compact_call = re.sub(r"\s+", "", call)
                compact = compact.replace(f"&{receipt},)", f"&{receipt})")
                self.assertIn(compact_call, compact)
                self.assertEqual(source.count("publish_orderly_software_closeout("), 1)
                self.assertLess(source.index("capture_software_closeout_run("), source.index("disarm_and_join("))
                self.assertLess(compact.index("disarm_and_join("), compact.index(compact_call))

        am3_bb = (rust / "am3_bb_mining.rs").read_text(encoding="utf-8")
        am3_bb = am3_bb.split("fn run_am3_bb_blocking(", 1)[1]
        self.assertLess(am3_bb.index("disarm_and_join("), am3_bb.index("let terminal_closeout ="))
        self.assertLess(am3_bb.index("if let Err(mining_error) = mining_result"),
                        am3_bb.index("publish_orderly_software_closeout("))
        self.assertRegex(am3_bb, r"publish_orderly_software_closeout\(\s*software_closeout_run,\s*"
                         r"&terminal_closeout\._watchdog,")
        bm1396 = (rust / "bm1396_mining.rs").read_text(encoding="utf-8")
        outer, owned = bm1396.split("async fn run_owned<H: Hardware>(", 1)
        self.assertIn("started,\n        software_closeout_run,", outer)
        self.assertIn("software_closeout_run: std::result::Result<", owned)
        self.assertNotIn("capture_software_closeout_run(", owned)

    def test_cold_idle_proof_is_confined_to_cancelled_initial_owner(self):
        rust = PROJECT / "dcentrald/dcentrald/src"
        cold = (rust / "runtime/cold_activation.rs").read_text(encoding="utf-8").split("#[cfg(test)]", 1)[0]
        self.assertEqual(cold.count("Ok(ColdIdleCloseout { run })"), 1)
        issuer = cold.split("async fn close_initial_idle(", 1)[1].split("pub(crate) fn eligible(", 1)[0]
        self.assertLess(issuer.index("shutdown.is_cancelled()"), issuer.index("api.0.abort()"))
        self.assertLess(issuer.index("api.1.abort()"), issuer.index("timeout_at(deadline, task)"))
        self.assertLess(issuer.index("timeout_at(deadline, task)"), issuer.index("Ok(ColdIdleCloseout { run })"))
        run = cold.split("pub(crate) async fn run(", 1)[1]
        self.assertEqual(run.count("capture_software_closeout_run("), 1)
        self.assertEqual(run.count("close_initial_idle("), 2)
        exec_failure = run.split("let error = replace_current_process(&arguments);", 1)[1]
        self.assertNotIn("close_initial_idle(", exec_failure)
        self.assertNotIn("publish_", exec_failure)
        main = (rust / "main.rs").read_text(encoding="utf-8")
        parking = main.split("async fn enter_management_only_idle(", 1)[1].split("/// F1", 1)[0]
        self.assertNotIn("publish_", parking)
        daemon = (rust / "daemon.rs").read_text(encoding="utf-8")
        publisher = daemon.split("pub(crate) fn publish_never_started_software_closeout(", 1)[1].split("fn persist_clean_software_closeout(", 1)[0]
        self.assertIn("closeout: crate::runtime::cold_activation::ColdIdleCloseout", publisher)
        self.assertIn("persist_clean_software_closeout(closeout.into_run())", publisher)

    def test_production_safety_guards(self):
        source = GATE.read_text(encoding="utf-8")
        for name in GUARDS:
            with self.subTest(guard=name):
                script = PROLOGUE + guard_source(source, name) + '\n[ "$failures" -eq 0 ]\n'
                result = subprocess.run(
                    ["sh", "-c", script], cwd=PROJECT, text=True,
                    capture_output=True, timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_or_comment_only_guard_call_is_not_execution(self):
        source = "example() {\n    fail broken\n}\nexample\n"
        self.assertIn("fail broken", guard_source(source, "example"))
        for candidate in ("", source.replace("\nexample\n", "\n# example\n")):
            with self.assertRaises(ValueError):
                guard_source(candidate, "example")

    def test_a_guard_failure_cannot_be_hidden_by_a_later_success(self):
        source = "example() {\n    fail broken\n    pass later\n}\nexample\n"
        script = PROLOGUE + guard_source(source, "example") + '\n[ "$failures" -eq 0 ]\n'
        result = subprocess.run(["sh", "-c", script], capture_output=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
