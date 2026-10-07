#!/usr/bin/env python3
"""Exercise the real shell runner with fake Cargo; never build or start a miner."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parent
CARGO = r'''#!/usr/bin/python3
import json, os, sys
args = sys.argv[1:]
listing = "--list" in args
marker = args[args.index("--") - 1]
with open(os.environ["CALLS"], "a") as output:
    output.write(json.dumps({"listing": listing, "marker": marker, "args": args}) + "\n")
assert args[0] == "test" and "--locked" in args and "-j2" in args
assert "sim-hal" in args and os.environ["CARGO_NET_OFFLINE"] == "true"
assert os.environ["RUSTUP_TOOLCHAIN"] == "1.90.0"
mode = os.environ.get("FIXTURE_MODE", "good")
if listing:
    if mode == "list-error": sys.exit(41)
    if mode == "empty-suite": sys.exit(0)
    if mode == "missing-row" and "am3_s21pro_" in marker: sys.exit(0)
    count = {"platform::sim::chain::tests": 8, "beta_spine_inventory": 2,
             "host_sim_cli": 4, "host_sim_refusals": 4, "sim_s19pro_t2": 11}.get(marker, 1)
    if mode == "duplicate-row" and "am3_s21pro_" in marker: count = 2
    for index in range(count):
        name = marker if count == 1 or "am3_s21pro_" in marker else marker + "::case_" + str(index)
        print(name + ": test")
else:
    assert "--include-ignored" in args
    if mode == "run-error": sys.exit(42)
    print("test result: ok. 1 passed; 0 failed; 0 ignored")
'''
TIMEOUT = r'''#!/usr/bin/python3
import json, os, subprocess, sys
with open(os.environ["BOUND"], "w") as output:
    json.dump(sys.argv[1:4], output)
assert sys.argv[1:4] == ["--signal=TERM", "--kill-after=30s", "2400s"]
if os.environ.get("FIXTURE_MODE") == "timeout": sys.exit(124)
sys.exit(subprocess.call(sys.argv[4:]))
'''
FLOCK = r'''#!/usr/bin/python3
import os, subprocess, sys
assert sys.argv[1:3] == ["--close", os.environ["HOME"] + "/.cache/dcent-beta/heavy.lock"]
with open(os.environ["LOCK"], "w") as output:
    output.write(sys.argv[2])
sys.exit(subprocess.call(sys.argv[3:]))
'''


class NativeRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dcent-native-runner-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        (self.root / "dcentrald").mkdir()
        for name in ("run_native_spine_tests.sh", "run_exact_cargo_test.sh", "run_filtered_cargo_test.sh"):
            shutil.copyfile(SCRIPTS / name, self.scripts / name)
        bins = self.root / "bin"
        bins.mkdir()
        for name, source in (("cargo", CARGO), ("timeout", TIMEOUT), ("flock", FLOCK)):
            path = bins / name
            path.write_text(source, encoding="utf-8", newline="\n")
            path.chmod(0o755)
        self.calls = self.root / "calls"
        self.bound = self.root / "bound"
        self.lock = self.root / "lock"
        self.env = {**os.environ, "PATH": str(bins) + os.pathsep + os.environ["PATH"],
                    "HOME": str(self.root), "XDG_CACHE_HOME": str(self.root / "cache"),
                    "CALLS": str(self.calls), "BOUND": str(self.bound), "LOCK": str(self.lock)}

    def invoke(self, mode="good", *args):
        return subprocess.run(["sh", str(self.scripts / "run_native_spine_tests.sh"), *args],
                              env={**self.env, "FIXTURE_MODE": mode}, text=True,
                              capture_output=True, timeout=30)

    def trace(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def test_executes_all_named_rows_with_the_canonical_shared_build_lock(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("NATIVE ROW:"), 29)
        self.assertIn("Every registered Beta row passed", result.stdout)
        calls = self.trace()
        self.assertEqual(len(calls), 100)
        for listed, run in zip(calls[::2], calls[1::2]):
            self.assertTrue(listed["listing"])
            self.assertFalse(run["listing"])
            self.assertEqual(listed["marker"], run["marker"])
        self.assertEqual(json.loads(self.bound.read_text()), ["--signal=TERM", "--kill-after=30s", "2400s"])
        self.assertEqual(self.lock.read_text(), str(self.root / ".cache/dcent-beta/heavy.lock"))

    def test_empty_suite_refuses_before_execution(self):
        result = self.invoke("empty-suite")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertTrue(all(call["listing"] for call in self.trace()))

    def test_missing_row_refuses_before_any_later_row(self):
        result = self.invoke("missing-row")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("expected exactly one", result.stderr)
        self.assertNotIn("NATIVE ROW: am3-s21xp", result.stdout)
        self.assertTrue(self.trace()[-1]["listing"])

    def test_duplicate_exact_row_refuses(self):
        result = self.invoke("duplicate-row")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("found 2", result.stderr)
        self.assertTrue(self.trace()[-1]["listing"])

    def test_inventory_error_propagates(self):
        self.assertEqual(self.invoke("list-error").returncode, 41)
        self.assertEqual(len(self.trace()), 1)

    def test_runtime_failure_stops_the_spine(self):
        self.assertEqual(self.invoke("run-error").returncode, 42)
        self.assertEqual(len(self.trace()), 2)

    def test_outer_deadline_failure_cannot_be_reported_as_success(self):
        self.assertEqual(self.invoke("timeout").returncode, 124)
        self.assertEqual(self.trace(), [])

    def test_unknown_arguments_refuse_before_tools(self):
        self.assertEqual(self.invoke("good", "--skip").returncode, 2)
        self.assertEqual(self.trace(), [])
        self.assertFalse(self.bound.exists())


if __name__ == "__main__":
    unittest.main()
