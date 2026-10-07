#!/usr/bin/env python3
"""Actual census shell fork/wait and latch tests with explicit boundary fixtures.

The private fixtures replace persistence sync, hardware safety and the opaque
Rust validator. These are protocol tests, not physical SafeOff or Rust receipt
acceptance; the separate real process suite covers the latter.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
LATCH = PROJECT / "br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-session-latch.sh"
S82 = PROJECT / "br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/S82dcentrald"
CONFIG_HELPER = PROJECT / "br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-firstlight-config.sh"
TOKEN = "0123456789abcdef0123456789abcdef"


def write(path, content):
    path.write_text(content, encoding="utf-8", newline="\n")
    path.chmod(0o700)
    return path


def function(source, name):
    match = re.search(r"^" + name + r"\(\) \{\n.*?^\}\n", source, re.M | re.S)
    assert match, name
    return match.group()


class CensusSupervisorTests(unittest.TestCase):
    def fixture(self, directory, mode, s82=False, work=False, target="am1-s9",
                pending_kind="directory", pending_prefix="prepared"):
        root = Path(directory)
        q = lambda name: shlex.quote(str(root / name))
        (root / "data/dcent").mkdir(parents=True)
        child = "#!/bin/sh\n"
        child += f"printf '%s\\n' \"$@\" > {q('argv')}\n"
        if mode != "immediate":
            child += f"""
attempt=0
while [ ! -s {q('child')} ]; do
    attempt=$((attempt + 1)); [ "$attempt" -lt 100 ] || exit 90
    sleep 0.01
done
cp {q('child')} {q('observed')} || exit 91
"""
        if mode == "foreign":
            child += f"printf '999999999 requested-stop\\n' > {q('expected')}\n"
        if mode == "forced":
            child += f"printf '%s forced-stop-timeout\\n' $$ > {q('expected')}\n"
        child += {"signal": "kill -TERM $$\n", "nonzero": "exit 7\n"}.get(mode, "exit 0\n")
        write(root / "daemon", child).chmod(0o755)
        write(root / "validator", f"""#!/bin/sh
printf 'validator\\n' >> {q('events')}
[ "$#" -eq 5 ] && [ "$1" = --check-software-closeout ] || exit 10
read pid start session boot < {q('observed')} || exit 11
[ "$2:$3:$4:$5" = "$pid:$start:$boot:$session" ] || exit 12
[ ! -e {q('consumed')} ] || exit 13
[ {int(mode != 'missing-proof')} -eq 1 ] || exit 14
: > {q('consumed')}
""")
        write(root / "safety", f"""#!/bin/sh
[ "$1" = safety ] || exit 80
printf 'safety\\n' >> {q('events')}
[ ! -d {q('fan.ready.lock')} ] || exit 81
exit {82 if mode == 'failed-safety' else 0}
""")
        source = LATCH.read_text(encoding="utf-8").replace("/usr/local/bin/dcentrald", str(root / "daemon"))
        dispatch_marker = 'case "' + '$' + '{1:-}" in'
        prefix, dispatch = source.rsplit(dispatch_marker, 1)
        overrides = f"""
PERSISTENCE_PATH={q('data')}
STATE_DIR={q('data/dcent')}
UNRESOLVED_FILE=$STATE_DIR/dcentrald-hardware-session.unresolved
CRASH_LATCH_FILE=$STATE_DIR/dcentrald-hardware-session.crash-latched
LOCK_DIR=$STATE_DIR/.dcentrald-session-latch.lock
UPDATE_LOCK_DIR={q('update-lock')}
PARENT_DEATH_HELPER={q('missing-pdeath') if mode == 'launch-failure' else ''}
CLOSEOUT_VALIDATOR={q('validator')}
backing_store_is_persistent() {{ return 0; }}
sync_state() {{ return 0; }}
"""
        latch = write(root / "latch", prefix + overrides + dispatch_marker + dispatch)

        def shell(*arguments):
            result = subprocess.run(["sh", *map(str, arguments)], capture_output=True, text=True, timeout=10)
            result.diagnostics = result.stdout + result.stderr + ((root / "log").read_text() if (root / "log").exists() else "")
            return result

        if s82:
            source = S82.read_text(encoding="utf-8")
            functions = "".join(function(source, name) for name in (
                "dcent_release_fan_transition_lock", "dcent_acquire_fan_transition_lock",
                "validate_firstlight_request", "validate_firstlight_seconds"))
            write(root / "board", target + "\n")
            write(root / "config", "[mining]\nenabled=false\n").chmod(0o600)
            functions = functions.replace("/etc/dcentos/board_target", str(root / "board"))
            dispatch = '\ncase "$1" in' + source.split('\ncase "$1" in', 1)[1]
            dispatch = dispatch.replace("/data/", str(root / "data") + "/")
            fixture = f"""#!/bin/sh
{functions}
FIRSTLIGHT_CENSUS_TOKEN=
FIRSTLIGHT_WORK_SECONDS=
FAN_TRANSITION_LOCK_HELD=0
FAN_CUSTODY_AVAILABLE=1
PROCESS_IDENTITY_AVAILABLE=1
IS_AM2=0
DAEMON={q('daemon')}
CONFIG={q('config')}
PIDFILE={q('wrapper')}
CHILD_PIDFILE={q('child')}
EXPECTFILE={q('expected')}
LOGFILE={q('log')}
SCRIPT={q('safety')}
SESSION_LATCH_HELPER={q('latch')}
FIRSTLIGHT_CONFIG_HELPER={q('config-helper')}
DEPLOY_MAINTENANCE_MARKER={q('maintenance')}
FANHOLD_READYFILE={q('fan.ready')}
dcent_fan_lock_acquire() {{ mkdir "$1"; }}
dcent_fan_lock_release() {{ rmdir "$1"; }}
dcent_validate_deploy_lock_handoff() {{ return 0; }}
resolve_interrupted_persistent_deploy() {{ return 0; }}
select_dcentrald_paths() {{ return 0; }}
dcent_verify_resolved_deploy_selection() {{ return 0; }}
dcent_verify_resolved_deploy_generation() {{ return 0; }}
pidof() {{ return 1; }}
bosminer_pic_bootstrap_enabled() {{ return 1; }}
migrate_legacy_api_port() {{ return 0; }}
fan_safety_override() {{ return 0; }}
"""
            if "dcent_firstlight_capture_config" in source:
                stage = root / "data/.dcent-firstlight/current"
                stage.mkdir(parents=True)
                stage.chmod(0o700)
                stage.parent.chmod(0o700)
                for phase in ("census", "work"):
                    write(stage / (phase + ".toml"), phase + "\n").chmod(0o600)

                def identity(path):
                    observed = path.stat()
                    fields = [observed.st_dev, observed.st_ino, observed.st_uid, observed.st_gid,
                              format(observed.st_mode & 0o777, "o"), observed.st_nlink,
                              observed.st_size, int(observed.st_mtime)]
                    return ":".join(map(str, fields)) + ":" + hashlib.sha256(path.read_bytes()).hexdigest()

                fields = {
                    "schema": "dcentos.firstlight-config.v1", "token": TOKEN, "board": target,
                    "boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                    "daemon_path": str(root / "daemon"), "daemon": identity(root / "daemon"),
                    "original_path": str(root / "config"), "original": identity(root / "config"),
                    "census": identity(stage / "census.toml"), "work": identity(stage / "work.toml"),
                }
                if mode == "stage-token":
                    fields["token"] = "f" * 32
                write(stage / "session", "".join(key + "=" + value + "\n" for key, value in fields.items())).chmod(0o600)
                helper = CONFIG_HELPER.read_text().replace("/usr/local/bin/dcentrald", str(root / "daemon"))
                helper = helper.replace("/etc/dcentrald.toml", str(root / "config"))
                helper = helper.replace("/etc/dcentos/board_target", str(root / "board"))
                helper = helper.replace("/data", str(root / "data"))
                write(root / "config-helper", helper)
                if mode == "stage-missing":
                    (stage / "session").unlink()
                if mode == "stage-phase-drift":
                    (stage / "work.toml").write_text("changed\n")
                if mode == "stage-original-drift":
                    (root / "config").write_text("changed\n")
                if mode.startswith("pending-"):
                    pending = stage.parent / (pending_prefix + "-" + TOKEN)
                    if mode == "pending-normal":
                        stage.rename(root / "saved-current")
                    if pending_kind == "symlink":
                        pending.symlink_to(root / "absent")
                    else:
                        pending.mkdir()
            if mode == "missing-binary":
                (root / "daemon").unlink()
            if mode == "admission-drift":
                fixture += f"migrate_legacy_api_port() {{ printf x >> {q('data/.dcent-firstlight/current/work.toml')}; }}\n"
            script = write(root / "S82", fixture + dispatch)
            arguments = [] if mode in ("normal-with-stage", "pending-normal") else [
                "firstlight-work" if work else "firstlight-census", TOKEN, *(["30"] if work else [])]
            result = shell(script, "start-locked", *arguments)
            self.assertFalse((root / "fan.ready.lock").exists(), result.diagnostics)
        else:
            prepare = shell(latch, "prepare")
            self.assertEqual(prepare.returncode, 0, prepare.diagnostics)
            result = shell(latch, "supervise-firstlight-work" if work else "supervise-census",
                           prepare.stdout.strip(), root / "safety",
                           root / "log", root / "child", root / "expected", root / "daemon",
                           "--config", root / "config", "--firstlight-work" if work else "--firstlight-census",
                           "A" * 32 if mode == "invalid-token" else TOKEN,
                           *(["--firstlight-seconds", "301" if mode == "invalid-seconds" else "30"] if work else []),
                           *(["--serial-mining"] if mode == "extra-flag" else []))
        unresolved = root / "data/dcent/dcentrald-hardware-session.unresolved"
        crash = root / "data/dcent/dcentrald-hardware-session.crash-latched"
        if mode == "ok":
            self.assertEqual(result.returncode, 0, result.diagnostics)
            self.assertFalse(unresolved.exists())
            self.assertFalse(crash.exists())
            self.assertEqual(shell(latch, "status").stdout.strip(), "clear")
            self.assertEqual((root / "events").read_text().splitlines(), ["safety", "validator"])
            if s82 and "dcent_firstlight_capture_config" in source:
                observed_argv = (root / "argv").read_text().splitlines()
                self.assertEqual(observed_argv[:2], ["--config", str(stage / ("work.toml" if work else "census.toml"))])
                self.assertEqual((root / "config").read_text(), "[mining]\nenabled=false\n")
            pid, start, session, boot = (root / "observed").read_text().split()
            replay = shell(root / "validator", "--check-software-closeout", pid, start, boot, session)
            self.assertNotEqual(replay.returncode, 0)
        else:
            self.assertNotEqual(result.returncode, 0, result.diagnostics)
            self.assertFalse((root / "consumed").exists(), result.diagnostics)
            if not mode.startswith("pending-") and mode not in ("missing-binary", "stage-token", "stage-missing", "stage-phase-drift", "stage-original-drift", "normal-with-stage", "unsupported-board"):
                self.assertTrue(unresolved.exists() or crash.exists(), result.diagnostics)
            if mode in ("foreign", "forced", "signal", "nonzero", "failed-safety"):
                self.assertEqual((root / "events").read_text().splitlines(), ["safety"])
            if mode in ("invalid-token", "extra-flag", "invalid-seconds", "missing-binary",
                        "stage-token", "stage-missing", "stage-phase-drift", "stage-original-drift",
                        "normal-with-stage", "admission-drift", "unsupported-board", "pending-normal"):
                self.assertFalse((root / "observed").exists())
            if mode.startswith("pending-"):
                self.assertIn("firstlight session before startup", result.diagnostics)
                self.assertFalse((root / "observed").exists())
                pending = root / "data/.dcent-firstlight" / (pending_prefix + "-" + TOKEN)
                self.assertTrue(pending.is_symlink() if pending_kind == "symlink" else pending.is_dir())
                if pending_kind == "symlink":
                    self.assertEqual(pending.readlink(), root / "absent")
                else:
                    self.assertEqual(list(pending.iterdir()), [])

    def setUp(self):
        self.assertEqual(os.name, "posix", "Linux owns this fixture")
        self.assertEqual(os.geteuid(), 0, "use a private user-root namespace when unprivileged")

    def test_supervisor_actual_process_outcomes(self):
        for mode in ("ok", "missing-proof", "foreign", "forced", "failed-safety",
                     "signal", "nonzero", "invalid-token", "extra-flag"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="dcent-census-shell-") as directory:
                self.fixture(directory, mode)

    def test_s82_wait_and_fan_lock_lifecycle(self):
        for mode in ("ok", "missing-proof", "launch-failure", "missing-binary", "immediate"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="dcent-census-shell-") as directory:
                self.fixture(directory, mode, s82=True)

    def test_work_supervisor_actual_process_outcomes(self):
        for mode in ("ok", "missing-proof", "foreign", "forced", "failed-safety",
                     "signal", "nonzero", "invalid-token", "extra-flag", "invalid-seconds"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="dcent-work-shell-") as directory:
                self.fixture(directory, mode, work=True)

    def test_work_s82_wait_and_fan_lock_lifecycle(self):
        for mode in ("ok", "missing-proof", "launch-failure", "missing-binary", "immediate"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="dcent-work-shell-") as directory:
                self.fixture(directory, mode, s82=True, work=True)

    def test_s82_firstlight_stage_is_required_and_session_bound(self):
        for mode in ("stage-token", "stage-missing", "stage-phase-drift", "stage-original-drift",
                     "normal-with-stage", "admission-drift"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="dcent-stage-shell-") as directory:
                self.fixture(directory, mode, s82=True, work=True)

    def test_s19j_exact_board_runs_both_phases_and_siblings_refuse_before_launch(self):
        for work in (False, True):
            for target in ("am2-s19j", "am2-s19jpro", "am2-s19pro"):
                with self.subTest(work=work, target=target), tempfile.TemporaryDirectory(prefix="dcent-s19j-shell-") as directory:
                    self.fixture(directory, "ok" if target == "am2-s19j" else "unsupported-board",
                                 s82=True, work=work, target=target)

    def test_every_start_refuses_foreign_prepared_or_retired_directory_or_symlink(self):
        for prefix in ("prepared", "retired"):
            for route in ("normal", "census", "work"):
                for kind in ("directory", "symlink"):
                    with self.subTest(prefix=prefix, route=route, kind=kind), tempfile.TemporaryDirectory(prefix="dcent-pending-shell-") as directory:
                        self.fixture(directory, "pending-" + route, s82=True, work=route == "work",
                                     pending_kind=kind, pending_prefix=prefix)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-latch", type=Path)
    parser.add_argument("--candidate-s82", type=Path)
    args, remaining = parser.parse_known_args()
    if args.candidate_latch:
        LATCH = args.candidate_latch.resolve(strict=True)
    if args.candidate_s82:
        S82 = args.candidate_s82.resolve(strict=True)
    unittest.main(argv=[__file__, *remaining])
