#!/usr/bin/env python3
"""Exercise the real AM2 builder's target selection and beta-policy install."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parents[2]
BUILDER = SCRIPT_DIR / "build_sd_s19pro.sh"


class Am2BetaPolicyTests(unittest.TestCase):
    def test_selected_image_installs_exact_policy_without_mutating_pool_config(self):
        if os.name == "nt":
            bash = str(
                Path(os.environ.get("ProgramFiles", "C:/Program Files"))
                / "Git/bin/bash.exe"
            )
            if not Path(bash).is_file():
                self.skipTest("Git Bash unavailable")
        else:
            bash = shutil.which("bash")
            if not bash:
                self.skipTest("Bash unavailable")
        source = BUILDER.read_text(encoding="utf-8")
        selection = (
            'case "$VARIANT" in'
            + source.split('case "$VARIANT" in', 1)[1].split("\nesac", 1)[0]
            + "\nesac\n"
        )
        assignment = next(
            line
            for line in source.splitlines()
            if line.startswith("DCENTOS_BETA_POLICY=")
        )
        install = (
            "# This is an explicitly selected hardware beta image."
            + source.split("# This is an explicitly selected hardware beta image.", 1)[
                1
            ].split("# Fix dropbear", 1)[0]
        )
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            etc = work / "rootfs_new/etc"
            etc.mkdir(parents=True)
            config = etc / "dcentrald.toml"
            idle_config = b'[pool]\nurl = ""\nworker = ""\n[mining]\nenabled = false\n'
            config.write_bytes(idle_config)
            runner = work / "policy.sh"
            runner.write_text(
                "set -eu\n" + selection + assignment + "\n" + install,
                encoding="utf-8",
                newline="\n",
            )
            for variant, target in [
                ("s17p", "am2-s17p"),
                ("s17plus", "am2-s17plus"),
                ("t17", "am2-t17"),
                ("t17plus", "am2-t17plus"),
                ("s19pro", "am2-s19pro"),
                ("s17", "am2-s17p"),
            ]:
                with self.subTest(variant=variant):
                    environment = dict(
                        os.environ,
                        VARIANT=variant,
                        PROJ=ROOT.as_posix(),
                        WORKDIR=work.as_posix(),
                        SUDO="",
                    )
                    result = subprocess.run(
                        [bash, runner.as_posix()],
                        env=environment,
                        text=True,
                        capture_output=True,
                        timeout=15,
                    )
                    self.assertEqual(
                        result.returncode, 0, result.stdout + result.stderr
                    )
                    expected = (
                        ROOT
                        / f"DCENT_OS_Antminer/dcentrald/configs/beta/{target}-experimental.toml"
                    )
                    self.assertEqual(
                        (etc / "dcentrald-experimental.toml").read_bytes(),
                        expected.read_bytes(),
                    )
                    self.assertEqual(config.read_bytes(), idle_config)
            before = (etc / "dcentrald-experimental.toml").read_bytes()
            environment["VARIANT"] = "s17e"
            result = subprocess.run(
                [bash, runner.as_posix()],
                env=environment,
                text=True,
                capture_output=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual((etc / "dcentrald-experimental.toml").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
