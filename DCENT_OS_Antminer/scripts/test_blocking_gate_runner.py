#!/usr/bin/env python3
"""Behavioral fixtures for gate selection, failure propagation and Git hooks."""
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parent
GATE = (SCRIPTS / "ci_offline_gates.sh").read_text(encoding="utf-8")
RUNNER = (SCRIPTS / "test_blocking_gates.sh").read_text(encoding="utf-8")
CALLS = re.findall(r"(?m)^if suite_output=\$\(((?:sh|bash|python3(?: -m pytest -q)?) scripts/[^;\n]+?|cargo [^;\n]+?) 2>&1\); then$", RUNNER)


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    path.chmod(0o755)


class HostSigningSelectionTests(unittest.TestCase):
    def test_host_selection_owns_every_test_once_and_refuses_unclassified_tests(self):
        import test_release_signing_authority as signing
        portable = set(signing.PORTABLE_TESTS)
        posix = {test._testMethodName for test in signing.host_platform_suite("posix")}
        windows = {test._testMethodName for test in signing.host_platform_suite("nt")}
        self.assertEqual(posix & windows, portable)
        self.assertEqual(posix - portable, set(signing.POSIX_TESTS))
        self.assertEqual(windows - portable, set(signing.WINDOWS_TESTS))
        with self.assertRaises(ValueError):
            signing.host_platform_suite("unknown")
        with mock.patch.object(signing.ReleaseSigningAuthorityTests, "test_unclassified", lambda self: None, create=True):
            with self.assertRaises(ValueError):
                signing.host_platform_suite("posix")
        with mock.patch.object(signing, "POSIX_TESTS", signing.POSIX_TESTS + (signing.PORTABLE_TESTS[0],)):
            with self.assertRaises(ValueError):
                signing.host_platform_suite("nt")


class FixtureBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dcent-blocking-gates-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "DCENT_OS_Antminer"
        self.scripts = self.project / "scripts"
        self.trace = self.root / "calls"
        self.env = {**os.environ, "TRACE": str(self.trace)}

    def invoke(self, source, *args, env=None):
        path = self.scripts / "ci_offline_gates.sh"
        write(path, source)
        return subprocess.run(
            ["sh", str(path), *args], text=True, capture_output=True,
            env=env or self.env, timeout=20,
        )

    def calls(self):
        return self.trace.read_text().splitlines() if self.trace.exists() else []

class GateFixtures(FixtureBase):
    def dispatcher(self):
        write(self.scripts / "test_blocking_gates.sh", '#!/bin/sh\nprintf "blocking:%s\\n" "$*" >> "$TRACE"\nexit "${BLOCKING_STATUS:-0}"\n')
        write(self.scripts / "test_nightly_gates.sh", '#!/bin/sh\nprintf "nightly:%s\\n" "$*" >> "$TRACE"\nexit "${NIGHTLY_STATUS:-0}"\n')
        return GATE.split("\nfailures=0\n", 1)[0] + '\nprintf "legacy:%s\\n" "$STATIC_ONLY" >> "$TRACE"\nexit "${LEGACY_STATUS:-0}"\n'

    def test_default_and_static_preserve_legacy_selection(self):
        for args, expected in (((), "legacy:0"), (("--static-only",), "legacy:1")):
            with self.subTest(args=args):
                self.trace.unlink(missing_ok=True)
                result = self.invoke(self.dispatcher(), *args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.calls(), [expected])

    def test_blocking_dispatch_excludes_legacy_and_forwards_fail_fast(self):
        result = self.invoke(self.dispatcher(), "--blocking", "--fail-fast")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), ["blocking:1"])

    def test_nightly_runs_blocking_before_comprehensive(self):
        result = self.invoke(self.dispatcher(), "--nightly")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), ["blocking:0", "nightly:0", "legacy:0"])

    def test_child_failure_propagates_in_both_tiers(self):
        for tier in ("--blocking", "--nightly"):
            with self.subTest(tier=tier):
                self.trace.unlink(missing_ok=True)
                result = self.invoke(self.dispatcher(), tier, env={**self.env, "BLOCKING_STATUS": "7"})
                self.assertEqual(result.returncode, 7)
                self.assertEqual(self.calls(), ["blocking:0"])
        self.trace.unlink()
        result = self.invoke(self.dispatcher(), "--nightly", env={**self.env, "LEGACY_STATUS": "9"})
        self.assertEqual(result.returncode, 9)
        self.trace.unlink()
        result = self.invoke(self.dispatcher(), "--nightly", env={**self.env, "NIGHTLY_STATUS": "8"})
        self.assertEqual(result.returncode, 8)
        self.assertEqual(self.calls(), ["blocking:0", "nightly:0"])

    def test_invalid_or_conflicting_options_do_not_execute_tests(self):
        for args in (("--blocking", "--nightly"), ("--static-only", "--blocking"),
                     ("--nightly", "--static-only"), ("--unknown",)):
            with self.subTest(args=args):
                result = self.invoke(self.dispatcher(), *args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(self.calls(), [])

    def runner_environment(self):
        # Minimal ordinary-file fixtures: shell/Python suites become recording
        # stubs, so testing dispatch never recursively executes the real gate.
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        for tool in ("sh", "bash", "cc", "cargo", "rustup", "flock", "openssl", "busybox", "fw_setenv", "fw_printenv",
                     "git", "awk", "sed", "grep", "tar", "sha256sum", "od", "tail", "dirname"):
            actual = shutil.which(tool)
            if tool in ("sh", "bash", "dirname", "grep"):
                (bin_dir / tool).symlink_to(actual)
            else:
                write(bin_dir / tool, "#!/bin/sh\nexit 0\n")
        write(bin_dir / "uname", "#!/bin/sh\necho Linux\n")
        write(bin_dir / "cargo", '#!/bin/sh\necho cargo >> "$TRACE"\nexit 0\n')
        write(bin_dir / "python3", '#!/bin/sh\n[ "$1" != -c ] || exit 0\nif [ "$1" = -m ]; then shift 3; fi\nexec /bin/sh "$@"\n')
        write(bin_dir / "date", '#!/bin/sh\nif [ -f "$CLOCK_STATE" ]; then echo "${ELAPSED:-0}"; else : > "$CLOCK_STATE"; echo 0; fi\n')
        for call in CALLS:
            if call.startswith("cargo "):
                continue
            script = next(arg for arg in shlex.split(call) if arg.startswith("scripts/"))
            write(self.project / script, f'#!/bin/sh\necho {shlex.quote(script)} >> "$TRACE"\nexit 0\n')
        return {**self.env, "PATH": str(bin_dir), "CLOCK_STATE": str(self.root / "clock")}

    def test_roster_runs_and_failed_suite_is_not_counted_as_pass(self):
        env = self.runner_environment()
        self.assertGreater(len(CALLS), 30)
        first = shlex.split(CALLS[0])[1]
        write(self.project / first, '#!/bin/sh\necho failure >> "$TRACE"\nexit 77\n')
        result = self.invoke(RUNNER, env=env)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("1 failed", result.stdout)
        self.assertEqual(len(self.calls()), len(CALLS))
        self.assertIn("BLOCKING FAIL:", result.stderr)

    def test_runner_fail_fast_stops_at_first_failure(self):
        env = self.runner_environment()
        first = shlex.split(CALLS[0])[1]
        write(self.project / first, '#!/bin/sh\necho failure >> "$TRACE"\nexit 1\n')
        result = self.invoke(RUNNER, "1", env=env)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.calls(), ["failure"])

    def test_skipped_or_zero_tests_are_not_counted_as_pass(self):
        env = self.runner_environment()
        first = shlex.split(CALLS[0])[1]
        for diagnostic in ("SKIP: utility missing", "OK (skipped=1)",
                           "2 passed, 1 skipped in 0.01s", "Ran 0 tests in 0.000s"):
            with self.subTest(diagnostic=diagnostic):
                self.trace.unlink(missing_ok=True)
                (self.root / "clock").unlink(missing_ok=True)
                write(self.project / first,
                      f'#!/bin/sh\necho ran >> "$TRACE"\necho {shlex.quote(diagnostic)}\nexit 0\n')
                result = self.invoke(RUNNER, env=env)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("1 failed", result.stdout)
                self.assertIn("did not execute all selected tests", result.stderr)
                self.assertEqual(len(self.calls()), len(CALLS))

    def test_missing_fw_setenv_fails_before_any_suite(self):
        env = self.runner_environment()
        (self.root / "bin/fw_setenv").unlink()
        result = self.invoke(RUNNER, env=env)
        self.assertEqual(result.returncode, 1)
        self.assertIn("prerequisite is missing: fw_setenv", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_ten_minute_overrun_is_not_reported_as_success(self):
        env = {**self.runner_environment(), "ELAPSED": "600"}
        result = self.invoke(RUNNER, env=env)
        self.assertEqual(result.returncode, 1)
        self.assertIn("ten-minute budget", result.stderr)


class HookFixtures(FixtureBase):
    # Git itself supplies the effective hook path; emulate its response so the
    # fixture never registers a real worktree or changes the user's Git config.
    def mock_git(self):
        bin_dir = self.root / "git-bin"
        bin_dir.mkdir()
        write(bin_dir / "git", r'''#!/bin/sh
case "$*" in
    *--show-toplevel*) printf '%s\n' "$REPO_FIXTURE" ;;
    *--local-env-vars*) echo GIT_DIR ;;
    *--git-path*) printf '%s\n' "$HOOK_FIXTURE" ;;
    *diff*) printf '%s\n' "${STAGED_FIXTURE:-}" ;;
    *) exit 2 ;;
esac
''')
        write(bin_dir / "flock", '#!/bin/sh\n[ "$1" = --close ] || exit 90\nshift\n[ "$1" = /tmp/dcent-heavy.lock ] || exit 91\nshift\nexec "$@"\n')
        return {**self.env, "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                "REPO_FIXTURE": str(self.root), "HOOK_FIXTURE": str(self.root / "shared/hooks")}

    def test_hook_runs_only_blocking_and_propagates_failure(self):
        env = self.mock_git()
        hook = self.scripts / "git-hooks/pre-commit"
        write(hook, (SCRIPTS / "git-hooks/pre-commit").read_text())
        write(self.scripts / "ci_offline_gates.sh", '#!/bin/sh\nprintf "%s\\n" "$*" >> "$TRACE"\nexit 7\n')
        result = subprocess.run(["bash", str(hook)], env=env, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(self.calls(), ["--blocking"])

    def test_hygiene_cannot_be_bypassed(self):
        env = {**self.mock_git(), "DCENT_SKIP_VERIFY": "1", "STAGED_FIXTURE": "tmp/garbage"}
        hook = self.scripts / "git-hooks/pre-commit"
        write(hook, (SCRIPTS / "git-hooks/pre-commit").read_text())
        write(self.scripts / "ci_offline_gates.sh", '#!/bin/sh\necho ran >> "$TRACE"\n')
        result = subprocess.run(["bash", str(hook)], env=env, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.calls(), [])
        env["STAGED_FIXTURE"] = "DCENT_OS_Antminer/safe.txt"
        result = subprocess.run(["bash", str(hook)], env=env, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_installer_uses_git_effective_path_with_dot_git_file(self):
        env = self.mock_git()
        write(self.root / ".git", "gitdir: shared/worktrees/lane\n")
        for name in ("pre-commit", "pre-push"):
            write(self.scripts / "git-hooks" / name, "#!/bin/sh\nexit 0\n")
        helper = self.scripts / "install_git_hooks.sh"
        write(helper, (SCRIPTS / "install_git_hooks.sh").read_text())
        result = subprocess.run(["sh", str(helper)], env=env, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("pre-commit", "pre-push"):
            target = Path(env["HOOK_FIXTURE"]) / name
            self.assertEqual(target.read_bytes(), (self.scripts / "git-hooks" / name).read_bytes())
            self.assertTrue(os.access(target, os.X_OK))


if __name__ == "__main__":
    unittest.main()
