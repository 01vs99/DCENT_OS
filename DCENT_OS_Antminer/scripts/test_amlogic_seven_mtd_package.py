"""Actual Classic/A126/Plus120 package assembly with structural rootfs fixtures.

Runs real cpio/mkimage, exact donor admission, manifest helper and signer. The
throwaway test key and synthetic source-provenance fixture are never a release.
No runtime executable, miner boot or device write is tested here.
"""

from __future__ import annotations

import gzip
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT.parent / 'dcent-toolbox/src'))
from dcent_toolbox.core.artifact_contract import inspect_archive_contract_bytes, install_rejection  # noqa: E402
from dcent_toolbox.core.install_package import verify_detached_release_signature  # noqa: E402

BOARDS = PROJECT / 'br2_external_dcentos/board/amlogic'
DONORS = Path(os.environ.get('DCENT_HELD_ASSETS', str(Path(__file__).resolve().parents[3] / 'knowledge-base'))) / 'extractions/vnish-farm'
REQUIRED = (
    'etc/init.d/S50dropbear', 'etc/init.d/S70ip_reporter', 'etc/init.d/S80dashboard',
    'etc/init.d/S81mcp', 'etc/init.d/S82dcentrald', 'usr/sbin/dropbear',
    'usr/local/bin/dcentrald', 'sbin/init', 'etc/init.d/S37board_setup',
    'etc/init.d/S99verify', 'usr/libexec/dcentos/verify-classic-aml-proof.py',
    'root/web/server.py', 'root/web/mcp_server.py', 'root/web/ip_reporter.py',
    'uninstall.sh', 'etc/dcentos-platform', 'etc/fw_env.config',
)


def cpio_fixture(extra=None):
    result = bytearray()
    entries = dict.fromkeys(REQUIRED, b'package test fixture\n')
    entries.update(extra or {})
    entries['TRAILER!!!'] = b''
    for index, (name, payload) in enumerate(entries.items()):
        encoded = name.encode() + b'\0'
        fields = (index, 0o100644, 0, 0, 1, 0, len(payload), 0, 0, 0, 0, len(encoded), 0)
        result.extend(b'070701' + b''.join(f'{field:08x}'.encode() for field in fields))
        result.extend(encoded)
        result.extend(b'\0' * (-len(result) % 4))
        result.extend(payload)
        result.extend(b'\0' * (-len(result) % 4))
    return gzip.compress(bytes(result), mtime=0)


class SevenMtdPackageTest(unittest.TestCase):
    def build(self, target, model, *, signed=True, rootfs=None, inspect=None):
        with tempfile.TemporaryDirectory(prefix='dcent-l12-package-') as directory:
            root = Path(directory)
            images = root / 'images'
            images.mkdir()
            marker = root / 'target/etc/dcentos'
            marker.mkdir(parents=True)
            (marker / 'board_target').write_text(target + '\n')
            (marker / 'release-image').write_text('fixture\n')
            (images / 'rootfs.cpio.gz').write_bytes(cpio_fixture() if rootfs is None else rootfs)
            donor = DONORS / model / 'vnishfarm-1.2.6-rc5-aml-nand-install'
            key = Ed25519PrivateKey.generate()
            private = root / 'test-key.pem'
            with os.fdopen(os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
                stream.write(key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            public = root / 'test-key.pub'
            public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                            serialization.PublicFormat.SubjectPublicKeyInfo))
            env = {name: value for name, value in os.environ.items()
                   if not name.startswith('DCENT_') and name != 'SOURCE_DATE_EPOCH'}
            env.update({
                'TARGET': target, 'TARGET_DIR': str(root / 'target'),
                'BASE_DIR': str(root), 'BINARIES_DIR': str(images), 'HOST_DIR': '/usr/local',
                'BR2_EXTERNAL_DCENTOS_PATH': str(PROJECT / 'br2_external_dcentos'),
                'DCENT_AM3_AML_KERNEL': str(donor / 'vmlinux.bin'),
                'DCENT_AM3_AML_DTB': str(donor / 'devicetree.dtb'),
                'DCENT_AM3_AML_FW_INFO': str(donor / 'rootfs/etc/fw-info'),
                'DCENT_PACKAGE_VERSION': 'test-fixture',
                'DCENT_PACKAGE_STATUS': 'release' if signed else 'lab_unsigned',
                'SOURCE_DATE_EPOCH': '1', 'DCENT_SOURCE_COMMIT_EPOCH': '1',
                'DCENT_SOURCE_COMMIT': '1' * 40, 'DCENT_SOURCE_TREE_STATE': 'clean',
                'DCENT_BUILD_TARGET': target, 'DCENT_BUILD_ARCH': 'aarch64-unknown-linux-musl',
                'DCENT_TOOLCHAIN_ID': 'test-fixture',
            })
            if signed:
                env.update(DCENT_RELEASE_SIGNING_KEY=str(private), DCENT_RELEASE_PUBKEY_FILE=str(public),
                           DCENT_REQUIRE_RELEASE_PROVENANCE='1', DCENT_RELEASE_IMAGE='1')
            else:
                env.update(DCENT_ALLOW_UNSIGNED_SYSUPGRADE='1', DCENT_DEV_IMAGE='1')
            recipe = BOARDS / target / 'post-image.sh'
            run = subprocess.run(['sh', str(recipe)], env=env, text=True, capture_output=True, timeout=180)
            self.assertEqual(run.returncode, 0, run.stdout[-3000:] + run.stderr[-3000:])
            with tarfile.open(images / f'dcentos-sysupgrade-{target}.tar') as archive:
                prefix = f'sysupgrade-{target}/'
                raw = archive.extractfile(prefix + 'MANIFEST.json').read()
                manifest = json.loads(raw)
                self.assertEqual(manifest['board_target'], target)
                self.assertFalse(manifest['installable'])
                self.assertEqual(manifest['toolbox']['install_mode'], 'package_only_denied')
                self.assertIsNone(manifest['toolbox']['install_command'])
                self.assertIsNone(manifest['toolbox']['update_command'])
                self.assertFalse(manifest['target_side_sysupgrade'])
                if signed:
                    signature = archive.extractfile(prefix + 'MANIFEST.sig').read()
                    key.public_key().verify(signature, raw)
                    with patch.dict(os.environ, {'DCENT_RELEASE_PUBKEY_HEX': '',
                                                 'DCENT_RELEASE_PUBKEY_FILE': str(public)}):
                        embedded = archive.extractfile(prefix + 'release_ed25519.pub').read()
                        self.assertIsNone(verify_detached_release_signature(
                            manifest_bytes=raw, signature=signature, embedded_pubkey=embedded))
                        self.assertIsNotNone(verify_detached_release_signature(
                            manifest_bytes=raw + b' ', signature=signature, embedded_pubkey=embedded))
                    self.assertEqual(manifest['status'], 'release')
                else:
                    self.assertNotIn(prefix + 'MANIFEST.sig', archive.getnames())
                    self.assertEqual(manifest['status'], 'lab_unsigned')
            # The actual Toolbox consumer parses the resulting archive and
            # refuses persistent installation independently of its signature.
            contract = inspect_archive_contract_bytes(
                (images / f'dcentos-sysupgrade-{target}.tar').read_bytes())
            self.assertIsNotNone(contract)
            self.assertEqual(contract.board_target, target)
            self.assertFalse(contract.installable)
            self.assertIn('installable', install_rejection(contract))
            if inspect is not None:
                inspect(images / f'dcentos-sysupgrade-{target}.tar', public, donor, key)
            return manifest

    def test_classic_signed_package_does_not_advertise_six_mtd_writer(self):
        self.build('am3-s19jpro-aml', 's19jpro')

    def test_a126_signed_package_keeps_signing_posture_separate_from_install_authority(self):
        self.build('am3-s19jproa', 's19jpro-a')

    def test_plus120_signed_package_keeps_signing_posture_separate_from_install_authority(self):
        self.build('am3-s19jproplus', 's19jpro-plus')

    def test_explicit_local_unsigned_lab_package_remains_noninstallable(self):
        self.build('am3-s19jpro-aml', 's19jpro', signed=False)


if __name__ == '__main__':
    unittest.main()
