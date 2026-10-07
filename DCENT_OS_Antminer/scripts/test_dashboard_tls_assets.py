#!/usr/bin/env python3
"""Run actual BB frontend staging and check all release frontend inputs."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]


class TlsImageAssets(unittest.TestCase):
    def test_actual_bb_staging_includes_service_and_frontend_without_keys(self):
        bash = "C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else "/bin/sh"
        helper = PROJECT / "scripts/lib/dashboard_https.sh"
        external = PROJECT / "br2_external_dcentos"
        with tempfile.TemporaryDirectory(prefix="dcent-https-image-") as temporary:
            target = Path(temporary)
            result = subprocess.run([bash, "-c", '. "$1"; dcent_stage_bb_dashboard_https "$2"',
                                     "dashboard-stage", helper.as_posix(), target.as_posix()],
                                    env=dict(os.environ, BR2_EXTERNAL_DCENTOS_PATH=external.as_posix()),
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("root/web/server.py", "etc/init.d/S80dashboard",
                         "root/web/static/recovery.html", "root/web/static/diagnostic.html",
                         "root/web/static/diagnostic-banner.js"):
                source = external / "board/amlogic/rootfs-overlay" / name
                self.assertEqual((target / name).read_bytes(), source.read_bytes())
            self.assertFalse((target / "data/dcent/tls").exists())
        for variant in ("am3-bb", "am3-bb-s19jpro"):
            hook = (external / f"board/beaglebone/{variant}/post-build.sh").read_text()
            self.assertIn('dcent_stage_bb_dashboard_https "$TARGET_DIR"', hook)
        self.assertIn("BR2_PACKAGE_PYTHON3_SSL=y", (external / "configs/dcentos-common.fragment").read_text())


if __name__ == "__main__":
    unittest.main()
