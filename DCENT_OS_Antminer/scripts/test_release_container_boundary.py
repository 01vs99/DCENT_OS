#!/usr/bin/env python3
"""Exercise real Docker mounts, source authority and staged native dependencies."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import source_snapshot as snapshot
import release_dashboard as dashboard
from release_source_git import read_source
from test_release_dashboard import assets

SCRIPTS = Path(__file__).resolve().parent
PROJECT = SCRIPTS.parent
TOOLBOX = PROJECT.parent / "dcent-toolbox"


class ContainerBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = os.environ.get("DCENT_TEST_RELEASE_CONTAINER_IMAGE", "")
        if not cls.image.startswith("sha256:"):
            raise RuntimeError("run test_release_container_boundary.sh with its inspected immutable builder")

    def run_container(self, arguments, *command, expect=0):
        run = subprocess.run(["docker", "run", "--rm", "--network=none",
                              "-e", "PYTHONDONTWRITEBYTECODE=1", *arguments,
                              self.image, *command], capture_output=True, text=True)
        if expect == 0:
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        else:
            self.assertNotEqual(run.returncode, 0, run.stdout + run.stderr)
        return run

    def test_linked_source_common_objects_and_tamper_refusal(self):
        with tempfile.TemporaryDirectory(prefix="dcent-container-authority-") as name:
            base = Path(name)
            repo, linked = base / "repo", base / "linked"
            repo.mkdir()
            def git(*arguments):
                return subprocess.run(["git", "-C", str(repo), *arguments], check=True,
                                      capture_output=True, text=True).stdout.strip()
            git("init", "-q")
            git("config", "user.name", "Container Fixture")
            git("config", "user.email", "container@example.invalid")
            (repo / "authority.txt").write_bytes(b"exact committed source\n")
            git("add", "authority.txt")
            git("commit", "-qm", "fixture")
            commit = git("rev-parse", "HEAD")
            git("worktree", "add", "--detach", str(linked), commit)
            created = snapshot.create_snapshot(linked, commit, base)
            try:
                common = read_source(linked, "git-common-dir")
                mounts = ["-v", f"{SCRIPTS}:/scripts:ro",
                          "-v", f"{created.snapshot.parent}:/dcentos-source-snapshot-release:ro"]
                command = ["python3", "/scripts/source_snapshot.py", "verify-against-git",
                           "--repo-root", "/dcent-git-object-repo", "--commit", commit,
                           "/dcentos-source-snapshot-release/snapshot.json"]
                # The old mount cannot follow a host-only linked-worktree .git.
                old_git = self.run_container([*mounts, "-v", f"{linked}:/dcent-git-object-repo:ro"],
                                             *command, expect=1)
                self.assertIn("Git plumbing failed", old_git.stderr)
                projection = [*mounts, "-v", f"{common}:/dcent-git-object-repo/.git:ro",
                              "-e", "GIT_CONFIG_COUNT=1", "-e", "GIT_CONFIG_KEY_0=safe.directory",
                              "-e", "GIT_CONFIG_VALUE_0=/dcent-git-object-repo"]
                good = self.run_container(projection, *command)
                self.assertEqual(json.loads(good.stdout)["commit_oid"], commit)
                descriptor_only = self.run_container(
                    [*projection, "-v", f"{created.snapshot}:/dcent-capsule-source:ro"],
                    *command[:-1], "/dcent-capsule-source", expect=1)
                self.assertIn("owned source-snapshot stage", descriptor_only.stderr)
                wrong = command.copy()
                wrong[-2] = "0" * len(commit)
                self.run_container(projection, *wrong, expect=1)
                changed = base / "changed-snapshot"
                shutil.copytree(created.snapshot.parent, changed)
                descriptor = changed / snapshot.SNAPSHOT_NAME
                descriptor.chmod(0o644)
                descriptor.write_bytes(descriptor.read_bytes().replace(b"authority.txt", b"different.txt"))
                self.run_container([*projection, "-v", f"{changed}:/dcentos-source-snapshot-changed:ro"],
                                   *command[:-1], "/dcentos-source-snapshot-changed/snapshot.json", expect=1)
            finally:
                snapshot.destroy_snapshot(created.snapshot, created.destroy_token)

    def test_git_different_owner_requires_only_exact_scoped_exception(self):
        code = r'''
import os, pathlib, subprocess, sys
sys.path.insert(0, '/scripts')
import source_snapshot as source
repo = pathlib.Path('/dcent-git-object-repo'); repo.mkdir()
def git(*args):
    return subprocess.check_output(['git', '-C', str(repo), *args]).decode().strip()
git('init', '-q'); git('config', 'user.name', 'Owner Fixture')
git('config', 'user.email', 'owner@example.invalid')
(repo / 'source').write_text('committed\n')
git('add', 'source'); git('commit', '-qm', 'fixture')
commit = git('rev-parse', 'HEAD')
created = source.create_snapshot(repo, commit, pathlib.Path('/tmp'))
for parent, dirs, files in os.walk(repo):
    os.chown(parent, 1001, 1001)
    for name in files: os.chown(os.path.join(parent, name), 1001, 1001)
try:
    source.verify_against_git(repo, commit, created.snapshot)
except source.SnapshotError as error:
    assert 'dubious ownership' in str(error), str(error)
else:
    raise AssertionError('foreign owner unexpectedly admitted without explicit scope')
os.environ.update(GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='safe.directory',
                  GIT_CONFIG_VALUE_0='/dcent-git-object-repo')
source.verify_against_git(repo, commit, created.snapshot)
source.destroy_snapshot(created.snapshot, created.destroy_token)
'''
        self.run_container(["-v", f"{SCRIPTS}:/scripts:ro"], "python3", "-c", code)

    def test_actual_staged_aliases_render_all_native_profiles_and_refuse_reuse(self):
        code = r'''
set -eu
mkdir /build-fixture
bash /src/scripts/release_container_stage.sh /src /toolbox /build-fixture armv7-unknown-linux-musleabihf
test "$(readlink -f /build-fixture/dcentos)" = /build-fixture/DCENT_OS_Antminer
test "$(readlink -f /build-fixture/dcent-toolbox)" = /build-fixture/projects/dcent-toolbox
test -d /build-fixture/DCENT_OS_Antminer/dcentrald/target/armv7-unknown-linux-musleabihf/release
test ! -L /build-fixture/DCENT_OS_Antminer/dcentrald/target
if python3 /build-fixture/dcentos/scripts/release_dashboard.py stage --source /src/dashboard --output /dashboard-result --destination /build-fixture/dcentos/dashboard/dist; then
    echo 'symlink ancestor unexpectedly admitted' >&2
    exit 1
fi
python3 /build-fixture/DCENT_OS_Antminer/scripts/release_dashboard.py stage --source /src/dashboard --output /dashboard-result --destination /build-fixture/DCENT_OS_Antminer/dashboard/dist
if bash /src/scripts/release_container_stage.sh /src /toolbox /build-fixture armv7-unknown-linux-musleabihf; then
    echo 'stale staging unexpectedly admitted' >&2
    exit 1
fi
'''
        with tempfile.TemporaryDirectory(prefix="dcent-container-dashboard-") as name:
            output = Path(name) / "result"
            assets(output)
            receipt = {"manifest_profile": dashboard.PROFILE, "node": "fixture", "npm": "fixture",
                       "source": dashboard.inventory(PROJECT / "dashboard", source=True),
                       "assets": dashboard.verify_assets(output)}
            (output / dashboard.RECEIPT).write_bytes(dashboard.canonical(receipt))
            result = self.run_container(["-v", f"{PROJECT}:/src:ro", "-v", f"{TOOLBOX}:/toolbox:ro",
                                         "-v", f"{output}:/dashboard-result:ro"], "bash", "-c", code)
        self.assertIn("seven exact source profiles verified", result.stdout)
        self.assertIn("verified dashboard: 4 assets", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
