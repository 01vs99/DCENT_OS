#!/usr/bin/env python3
"""Verify dashboard input/output binding and the private npm work directory."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release_dashboard as dashboard


def assets(root):
    root.mkdir()
    html = b'<html><body>application<script src="/static/diagnostic-banner.js" defer></script></body></html>'
    (root / "index.html").write_bytes(html)
    (root / "index.html.gz").write_bytes(gzip.compress(html, mtime=0))
    (root / "index.html.sha256").write_bytes((hashlib.sha256(html).hexdigest() + "\n").encode())
    (root / "font.woff2").write_bytes(b"fixture-font")


class DashboardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.source = self.base / "dashboard"
        self.source.mkdir()
        for name in ("package.json", "package-lock.json"):
            (self.source / name).write_text("{}\n")
        self.output = self.base / "result"

    def observed(self):
        assets(self.output)
        receipt = {"manifest_profile": dashboard.PROFILE, "node": "v22.0.0", "npm": "10.0.0",
                   "source": dashboard.inventory(self.source, source=True),
                   "assets": dashboard.verify_assets(self.output)}
        (self.output / dashboard.RECEIPT).write_bytes(dashboard.canonical(receipt))
        return receipt

    def test_exact_source_and_all_assets_verify(self):
        receipt = self.observed()
        self.assertEqual(dashboard.verify(self.source, self.output), receipt)
        self.assertEqual(len(receipt["assets"]), 4)

    def test_changed_lockfile_refuses(self):
        self.observed()
        (self.source / "package-lock.json").write_text('{"changed":true}\n')
        with self.assertRaisesRegex(ValueError, "source/output differs"):
            dashboard.verify(self.source, self.output)

    def test_changed_font_refuses(self):
        self.observed()
        (self.output / "font.woff2").write_bytes(b"other-font")
        with self.assertRaisesRegex(ValueError, "source/output differs"):
            dashboard.verify(self.source, self.output)

    def test_concatenated_gzip_refuses(self):
        self.observed()
        path = self.output / "index.html.gz"
        path.write_bytes(path.read_bytes() + gzip.compress(b"trailing-member"))
        with self.assertRaisesRegex(ValueError, "HTML/gzip/digest disagree"):
            dashboard.verify(self.source, self.output)

    def test_duplicate_observation_key_refuses(self):
        self.observed()
        path = self.output / dashboard.RECEIPT
        path.write_bytes(b'{"node":"spoof",' + path.read_bytes()[1:])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            dashboard.verify(self.source, self.output)

    def test_missing_sidecar_refuses(self):
        self.observed()
        (self.output / "index.html.sha256").unlink()
        with self.assertRaises((OSError, ValueError, dashboard.ReceiptError)):
            dashboard.verify(self.source, self.output)

    def test_symlink_asset_refuses(self):
        self.observed()
        try:
            (self.output / "linked").symlink_to(self.source / "package.json")
        except OSError:
            self.skipTest("host does not permit unprivileged symlinks")
        with self.assertRaises((ValueError, dashboard.ReceiptError)):
            dashboard.verify(self.source, self.output)

    def test_npm_build_uses_disposable_copy_and_seals_complete_output(self):
        # Exercise the real copy/build/publication path with a deterministic npm
        # process fixture. No dependency downloads occur in this focused test.
        npm_directory = self.base / "tools"
        npm_cli = npm_directory / "node_modules/npm/bin/npm-cli.js"
        npm_cli.parent.mkdir(parents=True)
        npm_cli.write_text("// npm process fixture")
        calls = []
        def run(command, *, cwd, env, check):
            self.assertNotEqual(cwd, self.source)
            self.assertEqual((cwd / "package-lock.json").read_bytes(), (self.source / "package-lock.json").read_bytes())
            calls.append(command)
            if command[-2:] == ["run", "build"]:
                assets(cwd / "dist")
            return subprocess.CompletedProcess(command, 0)
        with patch.object(dashboard.shutil, "which", side_effect=lambda name: str(npm_directory / name)), \
                patch.object(dashboard.subprocess, "check_output", return_value="22.0.0\n"), \
                patch.object(dashboard.subprocess, "run", side_effect=run):
            receipt = dashboard.build(self.source, self.output)
        self.assertTrue(any("ci" in command for command in calls))
        self.assertEqual(len(calls), 2)
        self.assertFalse((self.source / "dist").exists())
        self.assertEqual(dashboard.verify(self.source, self.output), receipt)
        self.assertFalse(list(self.base.glob("dashboard-build-*")))

    def test_actual_npm_build_publishes_into_long_capsule_path(self):
        # No dependencies or downloads: execute the installed Node/npm pair
        # against a tiny real package through the production build function.
        # Use the checkout's volume (NTFS short aliases can be disabled there).
        with tempfile.TemporaryDirectory(prefix=".dashboard-long-", dir=Path(__file__).parent) as temporary:
            base = Path(temporary).absolute()
            source = base / "input"
            source.mkdir()
            package = {"name": "dashboard-process-fixture", "version": "1.0.0",
                       "scripts": {"build": "node build.cjs"}}
            (source / "package.json").write_bytes(json.dumps(package).encode())
            (source / "package-lock.json").write_bytes(json.dumps({
                "name": package["name"], "version": "1.0.0", "lockfileVersion": 3,
                "requires": True, "packages": {"": {
                    "name": package["name"], "version": "1.0.0"}}
            }).encode())
            (source / "build.cjs").write_bytes(b'''
const fs = require('node:fs');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const html = Buffer.from('<html><script src="/static/diagnostic-banner.js"></script></html>');
fs.mkdirSync('dist');
fs.writeFileSync('dist/index.html', html);
fs.writeFileSync('dist/index.html.gz', zlib.gzipSync(html));
fs.writeFileSync('dist/index.html.sha256', crypto.createHash('sha256').update(html).digest('hex') + '\\n');
''')
            parent = base / ("result-" + "a" * 110) / ("snapshot-" + "b" * 110) / "results"
            parent.mkdir(parents=True)
            output = parent / "dashboard"
            self.assertGreater(len(str(parent)), 300)
            scratch = dashboard.scratch_parent(output)
            before = set(scratch.glob("dashboard-build-*"))
            receipt = dashboard.build(source, output)
            self.assertEqual(dashboard.verify(source, output), receipt)
            self.assertFalse((source / "dist").exists())
            self.assertEqual(set(scratch.glob("dashboard-build-*")), before)
            with self.assertRaisesRegex(ValueError, "must be absent"):
                dashboard.build(source, output)
            (output / "index.html.sha256").write_bytes(b"tampered\n")
            with self.assertRaisesRegex(ValueError, "HTML/gzip/digest disagree"):
                dashboard.verify(source, output)


# Host-owned selection (the signing-authority pattern): the blocking tier
# refuses suites that skip at runtime, so the Windows-only regression is
# deselected by the host instead of skipped inside a posix run.
WINDOWS_ONLY_TESTS = frozenset({
    "test_actual_npm_build_publishes_into_long_capsule_path",
})


if __name__ == "__main__":
    selected = unittest.defaultTestLoader.getTestCaseNames(DashboardTests)
    suite = unittest.TestSuite(
        DashboardTests(name)
        for name in selected
        if os.name == "nt" or name not in WINDOWS_ONLY_TESTS
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
