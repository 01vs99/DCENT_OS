#!/usr/bin/env python3
"""Execute the S19k boot scripts with inert paths and the real storage checker.

No network service, miner endpoint, block device or media mount is contacted.
The existing storage fixture supplies synthetic proc/sysfs files explicitly to
the actual checker; only Dropbear/key generation are recording shell doubles.
"""
from __future__ import annotations
import os
from pathlib import Path
import re
import subprocess
import unittest
import tempfile

from test_s19k_data_mount_owner import BOARD, HELPER, MountFixture


@unittest.skipUnless(os.name == "posix", "boot shell acceptance runs in WSL")
class S19kOperatorSshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dcent-s19k-ssh-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.mount = MountFixture(self.root)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls = self.root / "service-calls"
        self.key_calls = self.root / "key-calls"
        self.data = self.root / "data/dcent"
        self.data.mkdir()
        self.auth = self.data / "auth.json"
        self.keys = self.data / "authorized_keys"
        self.hosts = self.data / "dropbear"
        self.root_ssh = self.root / "root/.ssh"
        self.helper = self.bin / "data-owner"
        self.helper.write_bytes(HELPER.read_bytes())
        self.helper.chmod(0o755)
        self.env = dict(os.environ, **self.mount.environment())
        self.env.update(PATH=str(self.bin) + ":" + os.environ["PATH"],
                        SERVICE_CALLS=str(self.calls), KEY_CALLS=str(self.key_calls))
        self.write_executable("start-stop-daemon",
            '#!/bin/sh\nprintf "%s\\n" "$*" >> "$SERVICE_CALLS"\n')
        self.dropbearkey = self.write_executable("dropbearkey",
            '#!/bin/sh\n[ "${FAIL_KEYGEN:-0}" != 1 ] || exit 1\n'
            'case "$1" in\n'
            ' -t) printf "generate\\n" >> "$KEY_CALLS"; printf "inert-key\\n" > "$4" ;;\n'
            ' -y) [ -s "$3" ] ;;\n'
            ' *) exit 1 ;;\nesac\n')
        self.s50 = self.root / "S50dropbear"
        self.s49 = self.root / "S49s19k-postinstall-witness"
        replacements = {
            "DAEMON": self.bin / "never-executed-dropbear", "PIDFILE": self.root / "dropbear.pid",
            "DROPBEAR_DEFAULTS": self.root / "absent-defaults",
            "RELEASE_MARKER": self.mount.release_marker, "SSH_DISABLED": self.data / ".ssh-disabled",
            "AUTH_FILE": self.auth, "AUTHORIZED_KEYS": self.keys, "DATA_HELPER": self.helper,
            "PERSISTENT_DIR": self.data, "HOST_KEY_DIR": self.hosts, "ROOT_SSH_DIR": self.root_ssh,
            "DROPBEARKEY": self.dropbearkey,
        }
        self.materialize("S50dropbear", self.s50, replacements)
        self.materialize("S49s19k-postinstall-witness", self.s49,
            {key: value for key, value in replacements.items() if key in {"RELEASE_MARKER", "DATA_HELPER"}}
            | {"SSH_INIT": self.s50})

    def write_executable(self, name, source):
        path = self.bin / name
        path.write_text(source)
        path.chmod(0o755)
        return path

    def materialize(self, name, destination, paths):
        source = (BOARD / "rootfs-overlay/etc/init.d" / name).read_text()
        for name, path in paths.items():
            source, count = re.subn(r"^" + name + r"=.*$", lambda _: name + "='" + str(path) + "'",
                                    source, flags=re.MULTILINE)
            self.assertEqual(count, 1, name)
        destination.write_text(source)
        destination.chmod(0o755)

    def run_script(self, script, action="start"):
        return subprocess.run(["sh", str(script), action], env=self.env,
                              capture_output=True, text=True, timeout=10)

    def boot(self):
        result = self.run_script(self.s49)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_fresh_release_prepares_namespace_without_witness_or_ssh(self):
        self.boot()
        self.assertEqual((self.root_ssh / "authorized_keys").readlink(), self.keys)
        self.assertTrue(self.hosts.is_dir())
        self.assertFalse((self.data / "s19k-postinstall-witness").exists())
        result = self.run_script(self.s50)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("locked-release-image", result.stdout)
        self.assertFalse(self.calls.exists())
        self.assertFalse(self.key_calls.exists())

    def test_operator_keys_enable_key_only_ssh_and_reuse_persistent_host_key(self):
        self.boot()
        self.keys.write_text("ssh-ed25519 inert-operator-key\n")
        self.keys.chmod(0o600)
        for _ in range(2):
            result = self.run_script(self.s50)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("enabled-by-keys", result.stdout)
        calls = self.calls.read_text().splitlines()
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(" -- -s -r " in line and " -R" not in line for line in calls))
        self.assertEqual(self.key_calls.read_text(), "generate\n")
        self.assertEqual((self.root_ssh / "authorized_keys").read_text(), self.keys.read_text())

    def test_wizard_service_admission_never_changes_a_system_password(self):
        self.boot()
        self.auth.write_text('{"password_hash":"fixture-argon2id"}\n')
        shadow = self.root / "etc/shadow"
        shadow.write_text("root:!:0:0:99999:7:::\n")
        result = self.run_script(self.s50)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("enabled-by-wizard", result.stdout)
        self.assertEqual(shadow.read_text(), "root:!:0:0:99999:7:::\n")

    def test_opt_out_beats_uploaded_credentials_including_dangling_marker(self):
        self.boot()
        self.keys.write_text("ssh-ed25519 inert-operator-key\n")
        marker = self.data / ".ssh-disabled"
        marker.symlink_to(self.root / "absent-opt-out-target")
        result = self.run_script(self.s50)
        self.assertIn("disabled-by-opt-out", result.stdout)
        self.assertFalse(self.calls.exists())
        self.assertFalse(self.key_calls.exists())

    def test_real_storage_checker_refuses_foreign_layout_before_service_or_key_generation(self):
        self.boot()
        self.keys.write_text("ssh-ed25519 inert-operator-key\n")
        self.mount.proc_mtd.write_text(self.mount.proc_mtd.read_text().replace(
            'mtd4: 02000000 00020000 "overlay"', 'mtd4: 04000000 00020000 "overlay"'))
        self.assertNotEqual(self.run_script(self.s49).returncode, 0)
        result = self.run_script(self.s50)
        self.assertIn("locked-data-owner", result.stdout)
        self.assertFalse(self.calls.exists())
        self.assertFalse(self.key_calls.exists())

    def test_indirect_credentials_do_not_open_release_service(self):
        self.boot()
        foreign = self.root / "foreign-keys"
        foreign.write_text("ssh-ed25519 inert-operator-key\n")
        self.keys.symlink_to(foreign)
        result = self.run_script(self.s50)
        self.assertIn("locked-release-image", result.stdout)
        self.assertFalse(self.calls.exists())

    def test_foreign_root_key_view_and_keygen_failure_refuse(self):
        self.boot()
        self.keys.write_text("ssh-ed25519 inert-operator-key\n")
        view = self.root_ssh / "authorized_keys"
        view.unlink()
        view.symlink_to(self.root / "foreign-keys")
        self.assertNotEqual(self.run_script(self.s50).returncode, 0)
        self.assertFalse(self.calls.exists())
        view.unlink()
        view.symlink_to(self.keys)
        self.env["FAIL_KEYGEN"] = "1"
        self.assertNotEqual(self.run_script(self.s50).returncode, 0)
        self.assertFalse(self.calls.exists())


if __name__ == "__main__":
    unittest.main()
