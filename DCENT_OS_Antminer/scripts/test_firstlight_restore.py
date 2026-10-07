#!/usr/bin/env python3
"""Execute S82's restore transaction on real private files at interruption points.

The deployment handoff, fsync and Rust idle parser are explicit process-boundary
fixtures; no hardware or physical power-loss proof is inferred from these tests.
The real session helper still decides whether a dirty hardware latch is clear.
"""
import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import unittest

import test_firstlight_config_binding as config_binding
TOKEN = config_binding.TOKEN
from test_firstlight_census_supervisor import LATCH, S82, function


class FirstlightRestoreTests(unittest.TestCase):
    def setUp(self):
        self.binding = config_binding.FirstlightConfigTests()
        self.binding.setUp()
        self.addCleanup(self.binding.doCleanups)
        self.root = self.binding.root
        self.stage = self.binding.stage
        self.retired = self.stage.parent / ("retired-" + TOKEN)
        q = lambda path: shlex.quote(str(path))
        daemon = self.binding.daemon
        daemon.write_text(f'''#!/bin/sh
[ "$#" -eq 2 ] && [ "$1" = --check-firstlight-idle-config ] || exit 10
printf parser\\n >> {q(self.root / 'events')}
case "${{PARSER_MODE:-ok}}" in
    refuse) exit 11 ;;
    replace) cp "$2" "$2.replaced" && mv "$2.replaced" "$2" ;;
    mutate) printf '# changed after parser\\n' >> "$2" ;;
esac
exit 0
''')
        daemon.chmod(0o755)
        self.binding.fields["daemon"] = self.binding.identity(daemon)
        self.binding.record()
        state = self.root / "data/dcent"
        state.mkdir()
        source = LATCH.read_text()
        marker = 'case "${1:-}" in'
        prefix, dispatch = source.rsplit(marker, 1)
        self.latch = self.root / "latch"
        self.latch.write_text(prefix + f'''
PERSISTENCE_PATH={q(self.root / 'data')}
STATE_DIR={q(state)}
UNRESOLVED_FILE=$STATE_DIR/dcentrald-hardware-session.unresolved
CRASH_LATCH_FILE=$STATE_DIR/dcentrald-hardware-session.crash-latched
LOCK_DIR=$STATE_DIR/.dcentrald-session-latch.lock
backing_store_is_persistent() {{ return 0; }}
sync_state() {{ return 0; }}
''' + marker + dispatch)
        source = S82.read_text()
        # Execute the actual start fence after restore's exec, including exact
        # recognized retirement recovery. Other startup owners stay explicit
        # fixtures; this suite neither energizes hardware nor claims rail proof.
        match = re.search(r"^        for firstlight_prepared in .*?^        done\n", source, re.M | re.S)
        self.assertIsNotNone(match, "actual S82 must fence unresolved firstlight preparation/retirement")
        startup_fence = match.group().replace("/data/", str(self.root / "data") + "/")
        actual = function(source, "validate_firstlight_request") + function(source, "firstlight_restore_locked")
        actual = actual.replace("/etc/dcentos/board_target", str(self.root / "etc/dcentos/board_target"))
        actual = actual.replace("/run/dcentos-sysupgrade.lock", str(self.root / "update-lock"))
        actual = actual.replace("/data/dcent/reset-settings", str(state / "reset-settings"))
        self.script = self.root / "S82"
        self.script.write_text(f'''#!/bin/sh
DAEMON={q(daemon)}
CONFIG={q(self.binding.original)}
SESSION_LATCH_HELPER={q(self.latch)}
FIRSTLIGHT_CONFIG_HELPER={q(self.binding.helper)}
DEPLOY_MAINTENANCE_MARKER={q(self.root / 'maintenance')}
dcent_validate_deploy_lock_handoff() {{ [ "${{HANDOFF:-ok}}" = ok ]; }}
resolve_interrupted_persistent_deploy() {{ return 0; }}
select_dcentrald_paths() {{ return 0; }}
dcent_verify_resolved_deploy_selection() {{ return 0; }}
dcent_verify_resolved_deploy_generation() {{ [ "${{GENERATION:-ok}}" = ok ]; }}
pidof() {{ [ "${{LIVE_PID:-no}}" = no ] || printf '1234\\n'; }}
sync_count=0
sync() {{
    sync_count=$((sync_count + 1))
    [ "$sync_count" != "${{KILL_SYNC:-none}}" ] || kill -KILL $$
}}
rm() {{
    command rm "$@" || return 1
    case "$*" in
        */session) [ "${{KILL_AFTER_RECORD:-no}}" = no ] || kill -KILL $$ ;;
    esac
}}
{actual}
case "$1" in
    restore) firstlight_restore_locked "$2" ;;
    start-locked)
{startup_fence}
        [ "$(sh "$SESSION_LATCH_HELPER" status)" = clear ] || exit 12
        [ ! -e {q(self.stage)} ] && [ ! -L {q(self.stage)} ] || exit 13
        printf '%s\\n' "$CONFIG" > {q(self.root / 'restart')}
        ;;
    *) exit 64 ;;
esac
''')
        self.script.chmod(0o700)
        self.original = self.binding.original.read_bytes()

    def invoke(self, token=TOKEN, **environment):
        result = subprocess.run([str(self.script), "restore", token], env={**os.environ, **environment},
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(self.binding.original.read_bytes(), self.original)
        return result

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.stage.exists())
        self.assertFalse(self.retired.exists())
        self.assertEqual((self.root / "restart").read_text().strip(), str(self.binding.original))

    def test_checked_restore_retains_original_and_refuses_second_consume(self):
        self.assert_success(self.invoke())
        (self.root / "restart").unlink()
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertFalse((self.root / "restart").exists())

    def test_interrupt_after_retirement_can_retry_from_bound_record(self):
        result = self.invoke(KILL_SYNC="1")
        self.assertEqual(result.returncode, -9)
        self.assertFalse(self.stage.exists())
        self.assertTrue((self.retired / "session").is_file())
        self.assertFalse((self.root / "restart").exists())
        self.assert_success(self.invoke())

    def test_interrupt_during_phase_cleanup_can_retry_remaining_bound_record(self):
        result = self.invoke(KILL_SYNC="2")
        self.assertEqual(result.returncode, -9)
        self.assertFalse((self.retired / "census.toml").exists())
        self.assertTrue((self.retired / "work.toml").is_file())
        self.assert_success(self.invoke())

    def test_record_unlink_interruption_cannot_turn_empty_directory_into_authority(self):
        self.assertEqual(self.invoke(KILL_AFTER_RECORD="yes").returncode, -9)
        self.assertTrue(self.retired.is_dir())
        self.assertEqual(list(self.retired.iterdir()), [])
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertFalse((self.root / "restart").exists())

    def test_foreign_destination_and_unknown_contents_remain_untouched(self):
        self.retired.symlink_to(self.root / "absent", target_is_directory=True)
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertTrue(self.retired.is_symlink())
        self.retired.unlink()
        unknown = self.stage / "foreign"
        unknown.write_bytes(b"retain this")
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertEqual(unknown.read_bytes(), b"retain this")
        self.assertFalse((self.root / "restart").exists())

    def test_retired_foreign_token_or_incomplete_record_refuses_untouched(self):
        self.stage.rename(self.retired)
        original_record = (self.retired / "session").read_bytes()
        for bad_record in (
            original_record.replace(TOKEN.encode(), b"f" * 32),
            b"schema=dcentos.firstlight-config.v1\ntoken=" + TOKEN.encode() + b"\n",
        ):
            with self.subTest(record=bad_record):
                (self.retired / "session").write_bytes(bad_record)
                before = {path.name: path.read_bytes() for path in self.retired.iterdir()}
                self.assertNotEqual(self.invoke().returncode, 0)
                self.assertEqual({path.name: path.read_bytes() for path in self.retired.iterdir()}, before)
                self.assertFalse((self.root / "restart").exists())

    def test_other_retired_session_cannot_be_removed_or_bypassed_by_restore(self):
        foreign = self.stage.parent / ("retired-" + "f" * 32)
        foreign.mkdir()
        (foreign / "retain").write_bytes(b"unrelated session")
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertEqual((foreign / "retain").read_bytes(), b"unrelated session")
        self.assertFalse((self.root / "restart").exists())

    def test_failed_generation_handoff_parser_or_live_daemon_cannot_retire(self):
        for values in ({"HANDOFF": "bad"}, {"GENERATION": "bad"}, {"PARSER_MODE": "refuse"}, {"LIVE_PID": "yes"}):
            with self.subTest(values=values):
                self.assertNotEqual(self.invoke(**values).returncode, 0)
                self.assertTrue((self.stage / "session").is_file())
                self.assertFalse((self.root / "restart").exists())

    def test_update_reset_and_maintenance_markers_refuse_before_retirement(self):
        for path in (self.root / "update-lock", self.root / "maintenance", self.root / "data/dcent/reset-settings"):
            with self.subTest(marker=path.name):
                path.symlink_to(self.root / "absent")
                self.assertNotEqual(self.invoke().returncode, 0)
                self.assertTrue((self.stage / "session").is_file())
                self.assertFalse((self.root / "restart").exists())
                path.unlink()

    def test_real_dirty_latch_cannot_retire(self):
        prepare = subprocess.run(["sh", str(self.latch), "prepare"], capture_output=True, text=True, timeout=5)
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertTrue((self.stage / "session").is_file())
        self.assertFalse((self.root / "restart").exists())

    def test_config_inode_replacement_after_parser_refuses_retirement(self):
        self.assertNotEqual(self.invoke(PARSER_MODE="replace").returncode, 0)
        self.assertTrue((self.stage / "session").is_file())
        self.assertFalse((self.root / "restart").exists())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--s82", type=Path)
    args, remaining = parser.parse_known_args()
    if args.s82:
        S82 = args.s82
    unittest.main(argv=[__file__, *remaining])
