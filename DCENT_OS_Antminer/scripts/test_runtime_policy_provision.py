#!/usr/bin/env python3
"""Registry-derived image permissions and actual shell capability boundaries."""
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

import provision_runtime_policy as policy


class RuntimePolicyProvisionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="runtime-policy-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "etc/dcentos").mkdir(parents=True)

    def board(self, name):
        (self.root / "etc/dcentos/board_target").write_bytes((name + "\n").encode())

    def test_all_registered_rows_install_exact_independent_capabilities(self):
        rows = policy.load_policy()
        self.assertEqual(len(rows), 40)
        self.assertEqual(sum(row["daemon_hardware"] for row in rows.values()), 29)
        for board in ("am2-s19pro", "am2-s19", "am2-t19", "am2-s19a", "am2-s19plus"):
            with self.subTest(bm1398=board):
                self.assertEqual(rows[board]["release_channel"], "beta")
                self.assertTrue(rows[board]["boot_safeoff"])
                self.assertTrue(rows[board]["daemon_hardware"])
        s17e = rows["am2-s17e"]
        self.assertTrue(s17e["daemon_hardware"] and s17e["boot_safeoff"])
        self.assertFalse(s17e["ota_storage"])
        for board, row in rows.items():
            with self.subTest(board=board):
                self.board(board)
                self.assertEqual(policy.provision(self.root), row)
                self.assertEqual(policy.provision(self.root, check=True), row)
                raw = (self.root / "etc/dcentos/mutation_policy").read_text()
                self.assertNotIn("hardware-enabled", raw)
                for key, token in policy.CAPABILITIES.items():
                    self.assertEqual(token in raw.splitlines(), row[key])
        nopic = rows["am3-s19kpro"]
        self.assertTrue(nopic["boot_safeoff"])
        self.assertFalse(nopic["daemon_hardware"] or nopic["ota_storage"])
        guarded = rows["am3-s19k"]
        self.assertTrue(guarded["boot_safeoff"] and guarded["daemon_hardware"])
        self.assertFalse(guarded["ota_storage"])

    def test_unknown_alias_and_malformed_policy_fail_closed(self):
        self.board("am1-s9")
        with self.assertRaises(ValueError):
            policy.provision(self.root, check=True)
        self.assertFalse((self.root / "usr").exists())
        for board in ("unknown", "am3-aml-s19k", "am2-s19jpro", "am1-s9\nextra"):
            self.board(board)
            with self.assertRaises(ValueError):
                policy.provision(self.root)
        self.board("am1-s9")
        original = json.loads(policy.POLICY.read_text())
        fixture = self.root / "policy.json"
        for change in ("unknown", "duplicate", "unsupported", "bool", "field"):
            document = json.loads(json.dumps(original))
            if change == "unknown":
                document["targets"][0]["release_channel"] = "lab"
            elif change == "duplicate":
                document["targets"].append(document["targets"][0])
            elif change == "unsupported":
                document["targets"][0]["release_channel"] = "unsupported"
            elif change == "bool":
                document["targets"][0]["ota_storage"] = 1
            else:
                document["targets"][0]["wildcard"] = True
            fixture.write_text(json.dumps(document))
            with self.subTest(change=change), self.assertRaises(ValueError):
                policy.provision(self.root, policy=fixture)
        fixture.write_text('{"schema":"x","schema":"y","targets":[]}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            policy.load_policy(fixture)

    @unittest.skipUnless(os.name == "posix", "POSIX filesystem semantics")
    def test_symlink_parent_refused_and_output_alias_cannot_modify_victim(self):
        self.board("am1-s9")
        victim = self.root / "victim"
        victim.write_text("preserve")
        output = self.root / "etc/dcentos/mutation_policy"
        output.symlink_to(victim)
        policy.provision(self.root)
        self.assertEqual(victim.read_text(), "preserve")
        self.assertFalse(output.is_symlink())
        output.write_text("hardware-enabled\n")
        with self.assertRaisesRegex(ValueError, "differs"):
            policy.provision(self.root, check=True)
        (self.root / "usr/libexec/dcentos/mutation-policy.sh").unlink()
        (self.root / "usr/libexec/dcentos").rmdir()
        (self.root / "usr/libexec/dcentos").symlink_to(self.root / "etc/dcentos")
        with self.assertRaisesRegex(ValueError, "real directory"):
            policy.provision(self.root)

    @unittest.skipUnless(os.name == "posix", "actual POSIX policy reader")
    def test_actual_reader_has_no_hardware_or_missing_policy_wildcard(self):
        if os.geteuid() != 0:
            self.skipTest("root-owned policy reader acceptance requires root fixture owner")
        path = self.root / "policy"
        def allows(capability):
            return subprocess.run(["sh", "-c", '. "$1"; dcent_mutation_policy_has "$2" "$3"',
                                   "test", str(policy.HELPER), str(path), capability], capture_output=True).returncode == 0
        self.assertFalse(allows("ota-storage"))
        for raw, allowed in (("hardware-enabled\n", set()), ("boot-safeoff\n", {"boot-safeoff"}),
                             ("boot-safeoff\ndaemon-hardware\n", {"boot-safeoff", "daemon-hardware"}),
                             ("ota-storage\n", {"ota-storage"}),
                             ("boot-safeoff\nhardware-enabled\n", set()),
                             ("boot-safeoff\nboot-safeoff\n", set())):
            path.write_text(raw)
            path.chmod(0o644)
            for capability in (*policy.CAPABILITIES.values(), "unknown"):
                with self.subTest(raw=raw, capability=capability):
                    self.assertEqual(allows(capability), capability in allowed)
        path.write_text("ota-storage\n")
        path.chmod(0o666)
        self.assertFalse(allows("ota-storage"))
        path.chmod(0o644)
        os.link(path, self.root / "alias")
        self.assertFalse(allows("ota-storage"))

    def test_each_executable_buildroot_hook_generates_before_policy_checks(self):
        base = policy.PROJECT / "br2_external_dcentos/board"
        covered = 0
        for path in base.rglob("post-build.sh"):
            source = path.read_text(encoding="utf-8")
            if os.name == "posix":
                subprocess.run(["sh", "-n", str(path)], capture_output=True, check=True)
            if "dcent_provision_release_image" in source:
                covered += 1
                hook = source.index("provision_runtime_policy.py")
                self.assertLess(hook, source.index("dcent_provision_release_image"), str(path))
                if "MUTATION_POLICY=" in source:
                    self.assertLess(hook, source.index("MUTATION_POLICY="), str(path))
            else:
                self.assertTrue("exec " in source or "exit 78" in source, str(path))
        self.assertEqual(covered, 15)
        if os.name == "posix":
            for name in ("S37board_setup", "S82dcentrald", "S46post-install", "S99upgrade"):
                path = base / "amlogic/rootfs-overlay/etc/init.d" / name
                subprocess.run(["sh", "-n", str(path)], capture_output=True, check=True)
            subprocess.run(["sh", "-n", str(policy.HELPER)], capture_output=True, check=True)


if __name__ == "__main__":
    unittest.main()
