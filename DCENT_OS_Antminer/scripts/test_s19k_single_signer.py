#!/usr/bin/env python3
"""Run the real S19k post-image hook with fixture ELF/CPIO and throwaway keys.

These fixture packages test the signing/build boundary; they are not daemon
builds or installable releases. Kernel/DTB/fw-info admission uses held bytes.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest

from test_s19k_persistent_elf_contract import synthetic_elf64, synthetic_newc
from test_runtime_image_manifest import fixture as identity_fixture

PROJECT = Path(__file__).resolve().parents[1]
BOARD = PROJECT / "br2_external_dcentos/board/amlogic/am3-s19kpro"
HOOK = BOARD / "post-image.sh"
HELD = Path(os.environ.get("DCENT_HELD_ASSETS", PROJECT.parents[1] / "knowledge-base"))
DONOR = HELD / "extractions/vnish-farm/s19kpro/vnishfarm-1.2.6-rc5-aml-nand-install"


@unittest.skipUnless(os.name == "posix", "post-image requires POSIX build tools")
class S19kSingleSignerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dcent-s19k-signer-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.images = self.root / "images"
        self.images.mkdir()
        self.target = self.root / "target"
        self.target.mkdir()
        for command in ["openssl", "mkimage", "cpio", "gzip"]:
            self.assertIsNotNone(shutil.which(command), f"missing required build tool {command}")
        self.key, self.pub, self.daemon = identity_fixture(
            self.root / "identity", machine="aarch64-unknown-linux-musl")
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith("DCENT_") and key != "SOURCE_DATE_EPOCH"}
        self.env.update({
            "BR2_EXTERNAL_DCENTOS_PATH": str(PROJECT / "br2_external_dcentos"),
            "BINARIES_DIR": str(self.images), "TARGET_DIR": str(self.target),
            "HOST_DIR": str(self.root / "host"), "TARGET": "am3-s19kpro",
            "DCENT_PACKAGE_STATUS": "release", "DCENT_RELEASE_IMAGE": "1",
            "DCENT_REQUIRE_RELEASE_KEY": "1", "DCENT_REQUIRE_RELEASE_PROVENANCE": "1",
            "DCENT_RELEASE_SIGNING_KEY": str(self.key), "DCENT_RELEASE_PUBKEY_FILE": str(self.pub),
            "DCENT_SOURCE_COMMIT": "1" * 40, "SOURCE_DATE_EPOCH": "1700000000",
            "DCENT_SOURCE_COMMIT_EPOCH": "1700000000", "DCENT_SOURCE_TREE_STATE": "clean",
            "DCENT_BUILD_TARGET": "dcentos_am3_s19kpro_defconfig", "DCENT_BUILD_ARCH": "aarch64",
            "DCENT_TOOLCHAIN_ID": "test-production-identity-module-no-daemon-build", "DCENT_PACKAGE_VERSION": "1.2.3",
            "DCENT_AM3_AML_KERNEL": str(DONOR / "vmlinux.bin"),
            "DCENT_AM3_AML_DTB": str(DONOR / "devicetree.dtb"),
            "DCENT_AM3_AML_FW_INFO": str(DONOR / "rootfs/etc/fw-info"),
        })
        self.provision_target("am3-s19k")
        self.make_cpio()

    def provision_target(self, board):
        (self.target / "etc/dcentos").mkdir(parents=True, exist_ok=True)
        (self.target / "usr/local/bin").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.daemon, self.target / "usr/local/bin/dcentrald")
        (self.target / "usr/local/bin/dcentrald").chmod(0o755)
        (self.target / "etc/dcentos/board_target").write_text(board + "\n")
        (self.target / "etc/dcentos-version").write_text("1.2.3\n")
        (self.target / "etc/dcentrald.toml").write_text("[mining]\nenabled = false\n")
        (self.target / "etc/shadow").write_text("root:!:20000:0:99999:7:::\n")
        (self.target / "etc/shadow").chmod(0o600)
        provision = subprocess.run(["sh", "-c",
            '. "$1"; dcent_provision_release_image "$2" fixture', "fixture",
            str(PROJECT / "scripts/lib/release_image_provision.sh"), str(self.target)],
            env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(provision.returncode, 0, provision.stdout + provision.stderr)

    def make_cpio(self, *, elf=None, omit=None):
        names = set(re.findall(r'^require_rootfs_path "([^"]+)"$', HOOK.read_text(), re.MULTILINE))
        names.update(path.relative_to(self.target).as_posix() for path in self.target.rglob("*") if path.is_file())
        entries = []
        for name in sorted(names - {omit}):
            staged = self.target / name
            data = staged.read_bytes() if staged.is_file() else b"fixture\n"
            mode = 0o100000 | (staged.stat().st_mode & 0o7777) if staged.is_file() else 0o100755
            if name == "usr/local/bin/dcentrald" and elf is not None:
                data = elf
            entries.append((name, mode, data))
        (self.images / "rootfs.cpio.gz").write_bytes(synthetic_newc(entries))

    def run_hook(self, **changes):
        env = dict(self.env)
        for key, value in changes.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
        return subprocess.run(["sh", str(HOOK)], env=env, text=True, capture_output=True, timeout=45)

    def test_real_hook_emits_signed_final_package_without_custody_receipts(self):
        result = self.run_hook()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        artifact = self.images / "dcentos-sysupgrade-am3-s19kpro.tar"
        self.assertTrue(artifact.is_file())
        self.assertFalse((self.images / "dcentos-sysupgrade-am3-s19kpro.unsigned.tar").exists())
        with tarfile.open(artifact) as archive:
            members = {member.name: archive.extractfile(member).read()
                       for member in archive if member.isfile()}
        prefix = "sysupgrade-am3-s19k/"
        self.assertEqual(set(members), {prefix + leaf for leaf in ["kernel", "root", "METADATA", "SHA256SUMS",
                          "MANIFEST.json", "MANIFEST.sig", "release_ed25519.pub"]})
        manifest = json.loads(members[prefix + "MANIFEST.json"])
        self.assertEqual(manifest["board_target"], "am3-s19k")
        for payload in manifest["payloads"].values():
            data = members[payload["path"]]
            self.assertEqual(len(data), payload["size"])
            self.assertEqual(hashlib.sha256(data).hexdigest(), payload["sha256"])
        manifest_file, signature = self.root / "manifest.json", self.root / "manifest.sig"
        manifest_file.write_bytes(members[prefix + "MANIFEST.json"])
        signature.write_bytes(members[prefix + "MANIFEST.sig"])
        verify = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(self.pub),
            "-rawin", "-in", str(manifest_file), "-sigfile", str(signature)], capture_output=True)
        self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_missing_mismatched_or_unsigned_signing_posture_refuses(self):
        other = self.root / "wrong-private.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(other)], check=True, capture_output=True)
        for changes in [{"DCENT_RELEASE_SIGNING_KEY": None}, {"DCENT_RELEASE_PUBKEY_FILE": None},
                        {"DCENT_S19K_UNSIGNED_INTERMEDIATE": "1"}, {"DCENT_ALLOW_UNSIGNED_SYSUPGRADE": "1"},
                        {"DCENT_RELEASE_SIGNING_KEY": str(other)}, {"DCENT_RELEASE_IMAGE": "0"}]:
            with self.subTest(changes=changes):
                result = self.run_hook(**changes)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((self.images / "dcentos-sysupgrade-am3-s19kpro.tar").exists())

    def test_elf_service_identity_and_physical_geometry_checks_remain_load_bearing(self):
        self.make_cpio(elf=synthetic_elf64(machine=40))
        result = self.run_hook()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("EM_AARCH64", result.stderr)
        self.make_cpio(omit="etc/init.d/S82dcentrald")
        result = self.run_hook()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing required path", result.stderr)
        self.make_cpio()
        for changes in [{"DCENT_AM3_ROOTFS_WINDOW_HEX": "0x04000000"},
                        {"DCENT_AM3_OFFSET_FROM_END_MTD0_TO_MTD1": "0"},
                        {"DCENT_AM3_AML_FW_INFO": str(DONOR.parent.parent / "s19xp/vnishfarm-1.2.6-rc5-aml-nand-install/rootfs/etc/fw-info")}]:
            result = self.run_hook(**changes)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((self.images / "dcentos-sysupgrade-am3-s19kpro.tar").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
