#!/usr/bin/env python3
"""Every shipped default explicitly separates LAN monitoring from control."""
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BetaCgminerDefaults(unittest.TestCase):
    def test_all_beta_overlays_and_baked_defaults_are_explicit_read_only(self):
        overlays = list((ROOT / "br2_external_dcentos/board").glob("**/rootfs-overlay/etc/dcentrald.toml"))
        baked = list((ROOT / "dcentrald/configs").glob("**/*baked*default.toml"))
        self.assertGreaterEqual(len(overlays), 14)
        self.assertGreaterEqual(len(baked), 12)
        for path in overlays + baked:
            with self.subTest(path=path.relative_to(ROOT)):
                raw = path.read_bytes()
                config = tomllib.loads(raw.decode())
                unsupported = any(part in {"am3-t21", "am3-s19kpro-nopic"} for part in path.parts)
                self.assertIs(config["api"]["cgminer_bind_lan"], not unsupported)
                self.assertIs(config["api"]["cgminer_lan_writes"], False)
                self.assertIs(config["mining"]["enabled"], False)
                self.assertNotIn(b"\r", raw)


if __name__ == "__main__":
    unittest.main()
