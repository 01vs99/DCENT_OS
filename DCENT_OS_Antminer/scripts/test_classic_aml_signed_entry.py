"""Current signed recipe -> real Classic C/ASM build, with refusal coverage.

Uses exact held read-only kernel/DTB/BL33 and fresh throwaway signatures. The
rootfs contents are structural fixtures, never a runtime or physical boot test.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zlib
import lz4.block

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from classic_aml_entry import prepare_signed as entry
import test_amlogic_seven_mtd_package as package_fixture


def startup(*, target=entry.TARGET, enabled=False):
    return f'[mining]\nenabled = {str(enabled).lower()}\n[platform]\nboard_target = "{target}"\n'.encode()


def rootfs_entries():
    return {'etc/dcentos/board_target': entry.TARGET.encode() + b'\n',
            'etc/dcentos/release-image': b'structural-test-only\n',
            'etc/dcentrald.toml': startup()}


def archive_bytes(members, extra=()):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, body in (*members.items(), *extra):
            member = tarfile.TarInfo(entry.PREFIX + name)
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
    return stream.getvalue()


class SignedClassicEntryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        def retain(package, public, donor, key):
            cls.package = package.read_bytes()
            cls.public = public.read_bytes()
            cls.dtb = (donor / 'devicetree.dtb').read_bytes()
            cls.key = key
        package_fixture.SevenMtdPackageTest().build(
            entry.TARGET, 's19jpro', rootfs=package_fixture.cpio_fixture(rootfs_entries()), inspect=retain)
        held = Path(os.environ.get('DCENT_HELD_ASSETS', str(Path(__file__).resolve().parents[3] / 'knowledge-base')))
        sd = (held / 'extractions/vnish-farm/s19jpro/vnishfarm-1.2.6-rc5-aml-sd-install'
              / 'aml_upgrade_package_enc.img').read_bytes()
        # Decode the exact held container directly; no campaign research output.
        offset = 0x5d990
        assert sd[offset:offset + 4] == b'LZ4C'
        cls.resident = lz4.block.decompress(sd[offset + 128:offset + 128 + 494727],
                                          uncompressed_size=entry.RESIDENT_BYTES)
        cls.members = entry.package_members(cls.package)
        cls.manifest = json.loads(cls.members['MANIFEST.json'])

    def signed(self, changes=None, manifest_change=None):
        members = dict(self.members)
        members.update(changes or {})
        manifest = json.loads(self.members['MANIFEST.json'])
        for row in manifest['payloads'].values():
            name = row['path'].removeprefix(entry.PREFIX)
            row.update(size=len(members[name]), sha256=entry.digest(members[name]))
        members['SHA256SUMS'] = ''.join(
            f"{row['sha256']}  {row['path'].removeprefix(entry.PREFIX)}\n"
            for row in manifest['payloads'].values()).encode()
        if manifest_change:
            manifest_change(manifest)
        members['MANIFEST.json'] = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
        members['MANIFEST.sig'] = self.key.sign(members['MANIFEST.json'])
        return archive_bytes(members)

    def with_rootfs(self, entries=None, compressed=None, arch=22):
        compressed = package_fixture.cpio_fixture(entries) if compressed is None else compressed
        header = bytearray(self.members['root'][:64])
        struct.pack_into('>I', header, 12, len(compressed))
        struct.pack_into('>I', header, 24, zlib.crc32(compressed))
        header[29] = arch
        struct.pack_into('>I', header, 4, 0)
        struct.pack_into('>I', header, 4, zlib.crc32(header))
        return self.signed({'root': bytes(header) + compressed})

    def compose(self, package=None, public=None, dtb=None, resident=None, target=entry.TARGET):
        return entry.compose(self.package if package is None else package,
                             self.public if public is None else public, target,
                             self.dtb if dtb is None else dtb,
                             self.resident if resident is None else resident)

    def test_actual_signed_recipe_compiles_current_profile_and_c_checks_descriptor(self):
        with tempfile.TemporaryDirectory(prefix='dcent-l12-entry-') as directory:
            root = Path(directory)
            inputs = [root / name for name in ('current.tar', 'caller.pub', 'donor.dtb', 'resident.bin')]
            for path, raw in zip(inputs, (self.package, self.public, self.dtb, self.resident)):
                path.write_bytes(raw)
            output = root / 'entry'
            zig = Path(os.environ.get('DCENT_TEST_ZIG', '/opt/zig-0.13.0/zig'))
            run_command = subprocess.run
            compiler_caches = []
            def compile_command(command, **kwargs):
                env = kwargs['env']
                local = Path(env['ZIG_LOCAL_CACHE_DIR'])
                global_cache = Path(env['ZIG_GLOBAL_CACHE_DIR'])
                self.assertEqual(local.parent, global_cache.parent)
                self.assertEqual(local.parent.parent, root)
                compiler_caches.append(local.parent)
                return run_command(command, **kwargs)
            with patch.object(entry.subprocess, 'run', side_effect=compile_command):
                version = entry.prepare(inputs[0], inputs[1], entry.TARGET, inputs[2], inputs[3], output, zig)
            self.assertEqual(len(compiler_caches), 2)
            self.assertTrue(all(not path.exists() for path in compiler_caches))
            self.assertEqual(version, 'test-fixture')
            self.assertEqual({path.name for path in output.iterdir()},
                             {'Image', 'initrd.gz', 'final.dtb', 'descriptor.bin', 'entry-profile.h',
                              'classic-entry.elf', 'classic-entry.bin'})
            descriptor = (output / 'descriptor.bin').read_bytes()
            self.assertEqual(descriptor[208:240], hashlib.sha256(self.package).digest())
            self.assertIn(hashlib.sha256(descriptor).digest(), (output / 'classic-entry.bin').read_bytes())
            self.assertFalse(self.manifest['installable'])
            # Execute the existing real C contract against the generated profile,
            # and prove a post-generation mutation is refused by that contract.
            harness = root / 'contract-check.c'
            harness.write_bytes(b'''#include <stdio.h>
#include "entry-profile.h"
int main(int argc, char **argv) {
  struct dcent_descriptor descriptor;
  if (argc != 2) return 1;
  FILE *stream = fopen(argv[1], "rb");
  if (!stream || fread(&descriptor, 1, sizeof(descriptor), stream) != sizeof(descriptor)) return 2;
  if (fclose(stream)) return 3;
  if (dcent_descriptor_check(&descriptor, profile.descriptor_sha)) return 4;
  descriptor.candidate_sha[0] ^= 1;
  return dcent_descriptor_check(&descriptor, profile.descriptor_sha) == DCENT_BAD_DESCRIPTOR ? 0 : 5;
}
''')
            binary = root / 'contract-check'
            compiled = subprocess.run(['cc', '-O2', '-I', str(entry.HERE), '-I', str(output),
                                       str(harness), '-o', str(binary)], capture_output=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stderr.decode())
            checked = subprocess.run([str(binary), str(output / 'descriptor.bin')], timeout=30)
            self.assertEqual(checked.returncode, 0)
            with self.assertRaisesRegex(ValueError, 'fresh directory'):
                entry.prepare(inputs[0], inputs[1], entry.TARGET, inputs[2], inputs[3], output, zig)

    def test_exact_profile_is_recomputed_and_changes_with_current_package(self):
        files, _ = self.compose()
        changed = self.signed(manifest_change=lambda item: item.update(version='next-test-fixture'))
        next_files, _ = self.compose(changed)
        self.assertNotEqual(files['descriptor.bin'], next_files['descriptor.bin'])
        self.assertNotEqual(files['entry-profile.h'], next_files['entry-profile.h'])
        self.assertIn(b'{0x130,0x1002b4cULL}', files['entry-profile.h'])
        self.assertIn(b'{0x26000,0x10988b8ULL}', files['entry-profile.h'])

    def test_wrong_caller_key_signature_and_unsigned_package_refused(self):
        wrong = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        with self.assertRaisesRegex(ValueError, 'caller-pinned'):
            self.compose(public=wrong)
        members = dict(self.members, **{'MANIFEST.json': self.members['MANIFEST.json'] + b' '})
        with self.assertRaisesRegex(ValueError, 'signature'):
            self.compose(archive_bytes(members))
        del members['MANIFEST.sig']
        with self.assertRaisesRegex(ValueError, 'complete signed'):
            self.compose(archive_bytes(members))

    def test_exact_target_and_signed_provenance_refused(self):
        for field, value in (('board_target', 'am3-s19jproa'), ('board', 'am3-s19jproplus'),
                             ('schema', True), ('status', 'lab_unsigned')):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.compose(self.signed(manifest_change=lambda item: item.update({field: value})))
        with self.assertRaisesRegex(ValueError, 'only exact Classic'):
            self.compose(target='am3-s19jproa')
        with self.assertRaisesRegex(ValueError, 'provenance'):
            self.compose(self.signed(manifest_change=lambda item: item['provenance'].update(source_tree_state='dirty')))

    def test_payload_tamper_and_signed_wrong_kernel_refused(self):
        members = dict(self.members, kernel=b'wrong')
        with self.assertRaisesRegex(ValueError, 'signed payload'):
            self.compose(archive_bytes(members))
        with self.assertRaisesRegex(ValueError, 'exact held Classic kernel'):
            self.compose(self.signed({'kernel': b'wrong'}))

    def test_wrong_donor_and_resident_refused(self):
        with self.assertRaisesRegex(ValueError, 'kernel DTB'):
            self.compose(dtb=self.dtb[:-1] + bytes([self.dtb[-1] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'Classic BL33'):
            self.compose(resident=self.resident[:-1] + bytes([self.resident[-1] ^ 1]))

    def test_signed_wrong_uimage_crc_architecture_and_concatenated_gzip_refused(self):
        root = self.members['root']
        with self.assertRaisesRegex(ValueError, 'uImage'):
            self.compose(self.signed({'root': root[:-1] + bytes([root[-1] ^ 1])}))
        with self.assertRaisesRegex(ValueError, 'uImage'):
            self.compose(self.with_rootfs(rootfs_entries(), arch=2))
        with self.assertRaisesRegex(ValueError, 'concatenated'):
            self.compose(self.with_rootfs(compressed=root[64:] + root[64:]))

    def test_signed_wrong_rootfs_markers_and_mining_enabled_refused(self):
        for field, content in (('etc/dcentos/board_target', b'am3-s19jproa\n'),
                               ('etc/dcentos/release-image', b''),
                               ('etc/dcentrald.toml', startup(enabled=True)),
                               ('etc/dcentrald.toml', startup(target='am3-s19jproplus')),
                               ('etc/dcentrald.toml', b'mining = false\nplatform = "x"\n')):
            entries = rootfs_entries()
            entries[field] = content
            with self.subTest(field=field, content=content), self.assertRaises(ValueError):
                self.compose(self.with_rootfs(entries))

    def test_buildroot_dot_prefix_accepted_but_alias_and_parent_overwrite_refused(self):
        entries = {'./' + name: content for name, content in rootfs_entries().items()}
        self.compose(self.with_rootfs(entries))
        entries['etc/dcentrald.toml'] = startup(enabled=True)
        with self.assertRaisesRegex(ValueError, 'aliased'):
            self.compose(self.with_rootfs(entries))
        entries = rootfs_entries()
        entries['etc'] = b'not a directory'
        with self.assertRaisesRegex(ValueError, 'parent'):
            self.compose(self.with_rootfs(entries))

    def test_tar_duplicates_traversal_and_trailing_archive_refused(self):
        for name in ('root', '../root'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.compose(archive_bytes(self.members, ((name, b'extra'),)))
        with self.assertRaisesRegex(ValueError, 'padding|concatenated'):
            self.compose(self.package + b'foreign appended data')


if __name__ == '__main__':
    unittest.main()
