#!/usr/bin/env python3
"""Real filesystem tests for the read-only S82 firstlight binding helper."""
import hashlib
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
HELPER = PROJECT / "br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-firstlight-config.sh"
TOKEN = "0123456789abcdef0123456789abcdef"


class FirstlightConfigTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.name, "posix", "Linux owns protected metadata tests")
        self.assertEqual(os.geteuid(), 0, "use private user-root namespace when unprivileged")
        temporary = tempfile.TemporaryDirectory(prefix="dcent-firstlight-config-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stage = self.root / "data/.dcent-firstlight/current"
        self.stage.mkdir(parents=True)
        self.stage.chmod(0o700)
        self.stage.parent.chmod(0o700)
        self.daemon = self.root / "usr/local/bin/dcentrald"
        self.original = self.root / "etc/dcentrald.toml"
        self.daemon.parent.mkdir(parents=True)
        (self.root / "etc/dcentos").mkdir(parents=True)
        self.daemon.write_bytes(b"fixture executable bytes")
        self.daemon.chmod(0o755)
        self.original.write_bytes(b"[mining]\nenabled=false\n")
        self.original.chmod(0o644)
        (self.root / "etc/dcentos/board_target").write_text("am1-s9\n")
        for phase in ("census", "work"):
            path = self.stage / (phase + ".toml")
            path.write_bytes((phase + "\n").encode())
            path.chmod(0o600)
        self.fields = {
            "schema": "dcentos.firstlight-config.v1", "token": TOKEN, "board": "am1-s9",
            "boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "daemon_path": str(self.daemon), "daemon": self.identity(self.daemon),
            "original_path": str(self.original), "original": self.identity(self.original),
            "census": self.identity(self.stage / "census.toml"),
            "work": self.identity(self.stage / "work.toml"),
        }
        self.record()
        # Only relocate fixed paths in a disposable copy. All metadata/digest
        # validation is the real shipped implementation, without stubbed guards.
        source = HELPER.read_text().replace("/data", str(self.root / "data"))
        source = source.replace("/etc", str(self.root / "etc")).replace(
            "/usr/local", str(self.root / "usr/local"))
        self.helper = self.root / "helper"
        self.helper.write_text(source)

    @staticmethod
    def identity(path):
        st = path.stat()
        values = [st.st_dev, st.st_ino, st.st_uid, st.st_gid,
                  format(stat.S_IMODE(st.st_mode), "o"), st.st_nlink, st.st_size, int(st.st_mtime)]
        return ":".join(map(str, values)) + ":" + hashlib.sha256(path.read_bytes()).hexdigest()

    def record(self):
        path = self.stage / "session"
        path.write_text("".join(key + "=" + value + "\n" for key, value in self.fields.items()))
        path.chmod(0o600)

    def run_helper(self, mutation="", session=TOKEN, phase="census"):
        q = shlex.quote
        code = f". {q(str(self.helper))}\n" + (
            f"dcent_firstlight_capture_config {q(session)} {q(phase)} {q(str(self.daemon))} {q(str(self.original))} || exit 11\n"
        )
        code += mutation + "\n"
        code += f"dcent_firstlight_verify_config {q(str(self.daemon))} {q(str(self.original))}\n"
        return subprocess.run(["sh", "-c", code], capture_output=True, text=True, timeout=5)

    def test_exact_both_phases_capture_and_revalidate(self):
        for phase in ("census", "work"):
            with self.subTest(phase=phase):
                result = self.run_helper(phase=phase)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_foreign_context_and_empty_missing_identity_are_refused(self):
        for key, value in (("token", "f" * 32), ("board", "am1-s9i"), ("boot", "foreign"),
                           ("daemon", ""), ("original", ""), ("work", "foreign")):
            with self.subTest(field=key):
                before = self.fields[key]
                self.fields[key] = value
                self.record()
                result = self.run_helper(phase="work")
                self.assertNotEqual(result.returncode, 0)
                self.fields[key] = before
        self.record()
        self.assertNotEqual(self.run_helper(session="f" * 32).returncode, 0)

    def test_mutated_bytes_original_or_phase_cannot_revalidate(self):
        for name in ("census.toml", "session"):
            with self.subTest(name=name):
                self.fields["census"] = self.identity(self.stage / "census.toml")
                self.record()
                self.assertEqual(self.run_helper().returncode, 0)
                path = self.stage / name
                saved = path.read_bytes()
                result = self.run_helper(f"printf x >> {shlex.quote(str(path))}")
                self.assertNotEqual(result.returncode, 0)
                path.write_bytes(saved)
        # A separate direct mutation of the original config is checked even
        # when the phase and session record are untouched.
        self.record()
        self.assertEqual(self.run_helper().returncode, 0)
        result = self.run_helper(f"printf x >> {shlex.quote(str(self.original))}")
        self.assertNotEqual(result.returncode, 0)

    def test_byte_identical_inode_replacement_is_refused(self):
        path = self.stage / "census.toml"
        replacement = self.stage / "replacement"
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o600)
        result = self.run_helper(f"mv {shlex.quote(str(replacement))} {shlex.quote(str(path))}")
        self.assertNotEqual(result.returncode, 0)

    def test_phase_hardlink_and_symlink_are_refused(self):
        path = self.stage / "census.toml"
        other = self.stage / "other"
        os.link(path, other)
        self.assertNotEqual(self.run_helper().returncode, 0)
        other.unlink()
        path.rename(other)
        path.symlink_to(other)
        self.assertNotEqual(self.run_helper().returncode, 0)

    def test_weak_stage_or_file_permissions_are_refused(self):
        for path in (self.stage, self.stage / "session", self.stage / "census.toml", self.original):
            with self.subTest(path=path.name):
                mode = path.stat().st_mode & 0o777
                path.chmod(0o777)
                self.assertNotEqual(self.run_helper().returncode, 0)
                path.chmod(mode)

    def test_duplicate_unknown_or_partial_record_is_refused(self):
        path = self.stage / "session"
        before = path.read_text()
        for text in (before + "token=" + TOKEN + "\n", before + "unknown=value\n", before[:-8]):
            with self.subTest(record=text[-40:]):
                path.write_text(text)
                self.assertNotEqual(self.run_helper().returncode, 0)


if __name__ == "__main__":
    unittest.main()
