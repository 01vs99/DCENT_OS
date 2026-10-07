#!/usr/bin/env python3
"""Exercise the boot network parser without touching the host network."""
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / "br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/S40network").read_text().split('\ncase "$1" in')[0]


class PersistedNetworkTests(unittest.TestCase):
    def run_parser(self, persisted, baked=None, render_dns=False):
        with tempfile.TemporaryDirectory(prefix="dcent-network-") as directory:
            root = Path(directory)
            for name, value in (("persisted", persisted), ("baked", baked)):
                if value is not None:
                    (root / name).write_text(value)
            script = SOURCE + f"\nPERSISTED_STATIC_CONF={shlex.quote(str(root / 'persisted'))}\nSTATIC_CONF={shlex.quote(str(root / 'baked'))}\n" + '''
select_static_config || exit 42
printf '%s|%s|%s|%s\\n' "$IP" "$PREFIX" "$GW" "$DNS"
'''
            if render_dns:
                script += '\nwrite_dns_config ./resolv.conf\ncat ./resolv.conf\n'
            result = subprocess.run(["sh"], input=script, text=True, capture_output=True, cwd=root)
            self.assertFalse((root / "injected").exists())
            return result

    def test_persisted_static_precedes_image_default(self):
        result = self.run_parser("IP=10.5.3.8\nMASK=255.255.255.0\nGW=10.5.3.1\nDNS=1.1.1.1\n", "IP=203.0.113.9\nMASK=16\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "10.5.3.8|24|10.5.3.1|1.1.1.1")

    def test_multiple_dns_are_preserved_as_distinct_resolvers(self):
        for servers in ["1.1.1.1 8.8.8.8", "1.1.1.1 8.8.8.8 9.9.9.9"]:
            result = self.run_parser("IP=10.5.3.8\nMASK=24\nDNS=" + servers + "\n", render_dns=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines()[1:], ["nameserver " + ip for ip in servers.split()])
        self.assertEqual(self.run_parser("IP=10.5.3.8\nMASK=24\nDNS=1.1.1.1 8.8.8.8 9.9.9.9 4.4.4.4\n").returncode, 42)

    def test_missing_config_preserves_dhcp(self):
        self.assertEqual(self.run_parser(None).returncode, 42)

    def test_explicit_persisted_dhcp_overrides_baked_static(self):
        self.assertEqual(self.run_parser("", "IP=203.0.113.9\nMASK=16\n").returncode, 42)

    def test_optional_gateway_dns_and_prefix(self):
        result = self.run_parser("IP=192.168.5.7\nMASK=22\nGW=\nDNS=\n")
        self.assertEqual(result.stdout.strip(), "192.168.5.7|22||")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_persisted_falls_back_to_valid_image_config(self):
        result = self.run_parser("IP=invalid\nMASK=24\n", "IP=203.0.113.9\nMASK=16\n")
        self.assertEqual(result.stdout.strip(), "203.0.113.9|16||")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_injections_duplicates_and_invalid_addresses_never_reach_commands(self):
        invalid = ["IP=$(touch injected)\nMASK=24\n", "IP=1.2.3.4;touch injected\nMASK=24\n", "IP=1.2.3.4\nMASK=33\n", "IP=1.2.3.4\nMASK=255.0.255.0\n", "IP=1.2.3.4\nMASK=24\nDNS=8.8.8.999\n", "IP=1.2.3.4\nMASK=24\nGW=1.2.3.4\nGW=1.2.3.5\n", "IP=01.2.3.4\nMASK=24\n", "IP=1.2.3.4\nMASK=24\nOTHER=1\n"]
        for config in invalid:
            with self.subTest(config=config):
                self.assertEqual(self.run_parser(config).returncode, 42)


if __name__ == "__main__":
    unittest.main()
