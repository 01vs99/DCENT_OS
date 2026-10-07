#!/usr/bin/env python3
"""Actual XP/JXP shared package signing with held inputs and inert rootfs ELF."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import unittest

import test_s19k_single_signer as s19k_fixture
from test_s19k_persistent_elf_contract import synthetic_elf64, synthetic_newc

PROJECT, HELD = s19k_fixture.PROJECT, s19k_fixture.HELD
HOOK = PROJECT / "br2_external_dcentos/board/amlogic/post-image-family.sh"
sys.path.insert(0, str(PROJECT / "scripts/lib"))
from sysupgrade_manifest_json import admit_manifest, require_package_authority, require_payload_binding


@unittest.skipUnless(os.name == "posix", "actual package hook needs POSIX tools")
class XpFamilySingleSignerTests(unittest.TestCase):
    def setUp(self):
        # Reuse only fixture preparation, not the S19k-specific assertions.
        s19k_fixture.S19kSingleSignerTests.setUp(self)
        (self.target / "etc/dcentos").mkdir(parents=True, exist_ok=True)

    provision_target = s19k_fixture.S19kSingleSignerTests.provision_target

    def make_cpio(self):
        names = set(re.findall(r'^require_rootfs_path "([^"]+)"$', HOOK.read_text(), re.MULTILINE))
        names.update(path.relative_to(self.target).as_posix() for path in self.target.rglob("*") if path.is_file())
        entries = [(name, 0o100000 | ((self.target / name).stat().st_mode & 0o7777),
                    (self.target / name).read_bytes()) if (self.target / name).is_file()
                   else (name, 0o100755, b"inert fixture\n") for name in sorted(names)]
        (self.images / "rootfs.cpio.gz").write_bytes(synthetic_newc(entries))

    def run_hook(self, target, model, status="release", **overrides):
        self.provision_target(target)
        self.make_cpio()
        donor = HELD / "extractions/vnish-farm" / model / "vnishfarm-1.2.6-rc5-aml-nand-install"
        env = dict(self.env, TARGET=target, DCENT_PACKAGE_STATUS=status,
                   DCENT_AM3_AML_KERNEL=str(donor / "vmlinux.bin"),
                   DCENT_AM3_AML_DTB=str(donor / "devicetree.dtb"),
                   DCENT_AM3_AML_FW_INFO=str(donor / "rootfs/etc/fw-info"),
                   DCENT_BUILD_TARGET="dcentos_" + target.replace("-", "_") + "_defconfig")
        env.update(overrides)
        return subprocess.run(["sh", str(HOOK), "--board-target", target],
                              env=env, text=True, capture_output=True, timeout=45)

    def test_actual_xp_pair_signing_preserves_release_status_without_install_authority(self):
        for target, model in [("am3-s19xp", "s19xp"), ("am3-s19jxp", "s19j-xp")]:
            for status in ["release", "stable"]:
                with self.subTest(target=target, status=status):
                    result = self.run_hook(target, model, status)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    artifact = self.images / ("dcentos-sysupgrade-" + target + ".tar")
                    with tarfile.open(artifact) as archive:
                        files = {entry.name: archive.extractfile(entry).read()
                                 for entry in archive if entry.isfile()}
                    prefix = "sysupgrade-" + target + "/"
                    manifest_path = self.root / "manifest.json"
                    manifest_path.write_bytes(files[prefix + "MANIFEST.json"])
                    manifest = admit_manifest(manifest_path)
                    self.assertEqual(manifest["status"], status)
                    self.assertFalse(manifest["installable"])
                    self.assertEqual(manifest["toolbox"]["install_mode"], "package_only_denied")
                    require_package_authority(manifest, target)
                    for key, payload in manifest["payloads"].items():
                        data = files[payload["path"]]
                        require_payload_binding(manifest, key, payload["path"],
                                                len(data), hashlib.sha256(data).hexdigest())
                    signature = self.root / "manifest.sig"
                    signature.write_bytes(files[prefix + "MANIFEST.sig"])
                    verified = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin",
                        "-inkey", str(self.pub), "-rawin", "-in", str(manifest_path),
                        "-sigfile", str(signature)], capture_output=True)
                    self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_xp_cannot_borrow_sibling_identity_or_unsigned_status(self):
        result = self.run_hook("am3-s19xp", "s19j-xp")
        self.assertNotEqual(result.returncode, 0)
        result = self.run_hook("am3-s19xp", "s19xp", status="lab_unsigned")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
