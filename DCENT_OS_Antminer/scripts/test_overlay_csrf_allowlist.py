#!/usr/bin/env python3
"""WS-F6: overlay :80 CSRF allowlist parity with dcentrald-api csrf_allowlist.rs."""

from __future__ import annotations

import pathlib
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
OVERLAYS = [
    ROOT
    / "br2_external_dcentos"
    / "board"
    / "amlogic"
    / "rootfs-overlay"
    / "root"
    / "web"
    / "server.py",
    ROOT
    / "br2_external_dcentos"
    / "board"
    / "zynq"
    / "rootfs-overlay"
    / "root"
    / "web"
    / "server.py",
]


def load_overlay_csrf(path: pathlib.Path) -> types.ModuleType:
    source = path.read_text(encoding="utf-8")
    start = source.index("def _strip_host_port")
    end = source.index("def cors_allow_origin_value")
    origin_start = source.index("def same_origin(")
    origin_end = source.index("def cookie_bearer(")
    snippet = "import os\n" + source[origin_start:origin_end] + source[start:end]
    module = types.ModuleType(path.name)
    exec(snippet, module.__dict__)  # noqa: S102 — extracted overlay helpers only
    return module


class OverlayCsrfAllowlistTests(unittest.TestCase):
    def setUp(self) -> None:
        self.modules = [load_overlay_csrf(path) for path in OVERLAYS]

    def test_helpers_exist_in_both_overlays(self) -> None:
        for path in OVERLAYS:
            text = path.read_text(encoding="utf-8")
            self.assertIn("host_header_is_allowed", text)
            self.assertIn("Origin==Host is not enough", text)
            self.assertIn("Default :80 must match a bare host", text)
            self.assertNotRegex(
                text,
                r"if origin_host\.lower\(\) == host\.strip\(\)\.lower\(\)",
            )

    def test_port_80_matches_bare_host(self) -> None:
        for mod in self.modules:
            self.assertTrue(
                mod.cors_origin_allowed("http://203.0.113.50:80", "203.0.113.50")
            )
            self.assertTrue(
                mod.cors_origin_allowed("http://203.0.113.50", "203.0.113.50:80")
            )
            self.assertTrue(
                mod.cors_origin_allowed("http://dcentos.local:80", "dcentos.local")
            )

    def test_dns_rebind_hostname_is_rejected(self) -> None:
        for mod in self.modules:
            self.assertFalse(
                mod.cors_origin_allowed("http://evil.example", "evil.example")
            )
            self.assertFalse(
                mod.cors_origin_allowed("http://evil.example:80", "evil.example")
            )


if __name__ == "__main__":
    unittest.main()
