"""Behavioral tests for the registry age boundary and explicit emergency path."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import check_dependency_age as gate


NOW = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
CHECKSUM = "a" * 64
PACKAGE = gate.Package("example", "1.2.3", gate.CRATES_IO, CHECKSUM)


def lock_text(version="1.2.3", checksum=CHECKSUM, source=gate.CRATES_IO):
    return (f'version = 4\n[[package]]\nname = "example"\nversion = "{version}"\n'
            f'source = "{source}"\nchecksum = "{checksum}"\n')


def metadata(age=gate.MINIMUM_AGE):
    return {"version": {"crate": "example", "num": "1.2.3", "checksum": CHECKSUM,
                        "created_at": (NOW - age).isoformat(), "yanked": False}}


def exception():
    return {"name": "example", "version": "1.2.3", "checksum": CHECKSUM,
            "issued_at": NOW.isoformat(), "expires_at": (NOW + timedelta(days=1)).isoformat(),
            "reason": "Emergency fix for a documented remotely reachable vulnerability.",
            "reference": "https://rustsec.org/advisories/TEST.html"}


class DependencyAgeTests(unittest.TestCase):
    def test_exact_seven_day_boundary(self):
        self.assertEqual(gate.evaluate(PACKAGE, metadata(), NOW, {})["status"], "mature")
        with self.assertRaisesRegex(gate.GateError, "younger"):
            gate.evaluate(PACKAGE, metadata(gate.MINIMUM_AGE - timedelta(microseconds=1)), NOW, {})

    def test_timestamp_must_be_zoned_and_not_future(self):
        with self.assertRaises(gate.GateError):
            gate.utc_timestamp("2026-09-01T00:00:00")
        with self.assertRaisesRegex(gate.GateError, "future publication"):
            gate.evaluate(PACKAGE, metadata(timedelta(seconds=-1)), NOW, {})
        self.assertEqual(gate.utc_timestamp("2026-09-07T08:00:00-04:00"), NOW)

    def test_metadata_identity_checksum_yank_and_schema_fail_closed(self):
        for field, value in [("crate", "different"), ("num", "1.2.4"),
                             ("checksum", "b" * 64), ("yanked", True),
                             ("yanked", None), ("created_at", None)]:
            with self.subTest(field=field, value=value):
                data = metadata()
                data["version"][field] = value
                with self.assertRaises(gate.GateError):
                    gate.evaluate(PACKAGE, data, NOW, {})
        with self.assertRaises(gate.GateError):
            gate.evaluate(PACKAGE, {}, NOW, {})

    def test_changed_version_or_checksum_cannot_hide_behind_existing_name(self):
        previous = gate.read_packages(lock_text(), set())
        for changed in [lock_text("1.2.4"), lock_text(checksum="b" * 64)]:
            self.assertEqual(len(gate.read_packages(changed, set()) - previous), 1)
        self.assertFalse(gate.read_packages(lock_text(), set()) - previous)

    def test_workspace_and_explicit_git_are_separate_from_registry_age(self):
        local = 'version=4\n[[package]]\nname="local"\nversion="0.1.0"\n'
        self.assertEqual(gate.read_packages(local, set()), set())
        git_source = "git+https://github.com/example/repo?rev=reviewed#" + "a" * 40
        text = local + '[[package]]\nname="git-crate"\nversion="1.2.3"\nsource="' + git_source + '"\n'
        with self.assertRaisesRegex(gate.GateError, "unapproved source"):
            gate.read_packages(text, set())
        self.assertEqual(gate.read_packages(text, {git_source}), set())

    def test_unknown_source_malformed_or_duplicate_lock_refused(self):
        cases = [lock_text(source="registry+https://evil.invalid"), lock_text(checksum=""),
                 lock_text().replace('"example"', '"../example"'),
                 lock_text() + lock_text().split("\n", 1)[1], 'version=4\n', 'not toml']
        for text in cases:
            with self.subTest(text=text), self.assertRaises(gate.GateError):
                gate.read_packages(text, set())

    def load_exceptions(self, rows):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "exceptions.json"
            path.write_text(json.dumps({"schema_version": 1, "exceptions": rows}), encoding="utf-8")
            return gate.load_exceptions(path, NOW)

    def test_explicit_exception_waives_age_only_and_is_reported(self):
        exceptions = self.load_exceptions([exception()])
        result = gate.evaluate(PACKAGE, metadata(timedelta(hours=1)), NOW, exceptions)
        self.assertEqual(result["status"], "emergency-exception")
        self.assertIn("Emergency fix", result["exception"]["reason"])
        for field, value in [("checksum", "b" * 64), ("yanked", True), ("crate", "other")]:
            data = metadata(timedelta(hours=1))
            data["version"][field] = value
            with self.assertRaises(gate.GateError):
                gate.evaluate(PACKAGE, data, NOW, exceptions)

    def test_exception_does_not_cover_a_different_version_or_checksum(self):
        row = exception()
        row["version"] = "1.2.2"
        with self.assertRaisesRegex(gate.GateError, "younger"):
            gate.evaluate(PACKAGE, metadata(timedelta(hours=1)), NOW, self.load_exceptions([row]))

    def test_expired_future_overlong_or_underspecified_exception_refused(self):
        for field, value in [("expires_at", NOW.isoformat()),
                             ("issued_at", (NOW + timedelta(seconds=1)).isoformat()),
                             ("expires_at", (NOW + timedelta(days=8)).isoformat()),
                             ("reason", "just because"), ("reference", "http://example.com"),
                             ("checksum", "*")]:
            row = exception()
            row[field] = value
            with self.subTest(field=field), self.assertRaises(gate.GateError):
                self.load_exceptions([row])
        with self.assertRaises(gate.GateError):
            self.load_exceptions([exception(), exception()])

    def test_registry_outage_is_bounded_and_never_waived(self):
        with patch.object(gate, "urlopen", side_effect=TimeoutError), patch.object(gate.time, "sleep") as sleep:
            with self.assertRaisesRegex(gate.GateError, "registry request failed"):
                gate.registry_version(PACKAGE)
            self.assertEqual(sleep.call_count, 2)
        with patch.object(gate, "urlopen", side_effect=HTTPError("url", 404, "missing", {}, None)) as request:
            with self.assertRaises(gate.GateError):
                gate.registry_version(PACKAGE)
            self.assertEqual(request.call_count, 1)

    def test_git_base_new_lock_bad_ref_and_unchanged_pr(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for args in [("init", "-q"), ("config", "user.email", "fixture@example.invalid"),
                         ("config", "user.name", "Fixture")]:
                subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)
            path = root / "Cargo.lock"
            path.write_text(lock_text(), encoding="utf-8")
            (root / "exceptions.json").write_text('{"schema_version":1,"exceptions":[]}', encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True, capture_output=True)
            self.assertEqual(gate.base_lock(root, "new/Cargo.lock", "HEAD")[1], None)
            self.assertEqual(gate.base_lock(root, "Cargo.lock", "0" * 40)[1], None)
            with self.assertRaises(gate.GateError):
                gate.base_lock(root, "Cargo.lock", "missing-ref")
            with patch.object(gate, "registry_version", side_effect=AssertionError("unexpected network")):
                self.assertEqual(gate.main(["--lock", str(path), "--base-ref", "HEAD",
                                            "--exceptions", str(root / "exceptions.json")]), 0)


if __name__ == "__main__":
    unittest.main()
