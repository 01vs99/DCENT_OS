#!/usr/bin/env python3
"""Offline preparation-contract fixtures; no fixture is a physical image claim."""
import gzip
import importlib.util
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zlib

SOURCE = Path(__file__).with_name('prepare_classic_aml_private_beta.py')
spec = importlib.util.spec_from_file_location('classic_beta', SOURCE)
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)
WORKSPACE = Path(__file__).resolve().parents[3]
audit_spec = importlib.util.spec_from_file_location('classic_terminal', SOURCE.with_name('audit_classic_aml_build_terminal.py'))
terminal_audit = importlib.util.module_from_spec(audit_spec)
audit_spec.loader.exec_module(terminal_audit)


def uimage(body, arch=22):
    header = struct.pack('>7I4B32s', 0x27051956, 0, 0, len(body), 0, 0,
                         zlib.crc32(body), 5, arch, 3, 1, b'fixture')
    return header[:4] + struct.pack('>I', zlib.crc32(header)) + header[8:] + body


class PrivatePreparation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='classic-private-beta-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.native_manifest = self.write('native-source.json', {'fixture': True})
        native_hash = producer.sha(self.native_manifest)
        native = self.write('native-build.json', dict(exit_code=0, source_snapshot_manifest_sha256=native_hash))
        files = [{'path': producer.DONOR_ROOT + relative, 'sha256': sha}
                 for relative, sha in producer.DONORS.values()]
        self.image = self.write('image.json', dict(source=str(WORKSPACE), files=files, fixture=True))
        configured = self.write('configure.json', dict(step='configure', exit_code=0,
            sources_unchanged=True, validation_error=None, input_receipt_sha256=producer.sha(self.image),
            resolved_config_sha256='c' * 64))
        compressed = gzip.compress(b'fixture-only-not-an-image')
        artifacts = []
        for name, data in [('rootfs.cpio.gz', compressed), ('uImage_rootfs.bin', uimage(compressed)),
                           ('rootfs.ext4', b'fixture-only-not-a-filesystem')]:
            path = self.root / name
            path.write_bytes(data)
            artifacts.append(dict(path=str(path), bytes=len(data), sha256=producer.sha(path)))
        self.build_data = dict(step='build', make_exit_code=2, sources_unchanged=True, validation_error=None,
            resolved_aarch64=True, resolved_root_locked=True, resolved_config_sha256='c' * 64,
            native=dict(receipt=str(native), receipt_sha256=producer.sha(native), source_manifest_sha256=native_hash),
            input_receipt=str(self.image), input_receipt_sha256=producer.sha(self.image),
            configuration=dict(receipt=str(configured), receipt_sha256=producer.sha(configured), resolved_config_sha256='c' * 64),
            artifacts=artifacts)
        self.log = self.root / 'build.log'
        self.log.write_text('\n'.join(terminal_audit.MARKERS) + '\n' + terminal_audit.PACKAGE_REFUSAL
                            + '\nmake: *** [Makefile:824: target-post-image] Error 1\n', encoding='utf-8')
        self.build_data['log'] = str(self.log)
        self.build = self.write('build.json', self.build_data)
        self.terminal = self.root / 'terminal.json'
        terminal_audit.audit(self.build, self.terminal)
        critical = ['sbin/init', 'usr/local/bin/dcentrald', 'etc/init.d/S37board_setup',
                    'etc/init.d/S82dcentrald', 'etc/init.d/S99verify',
                    'usr/libexec/dcentos/verify-classic-aml-proof.py']
        self.inspection_data = dict(claim='actual_userspace_archive_and_read_only_fs_cli_checks_not_physical_or_package_admission',
            fixture=True, build_receipt_sha256=producer.sha(self.build), native_source_manifest_sha256=native_hash,
            image_input_receipt_sha256=producer.sha(self.image), resolved_config_sha256='c' * 64,
            configure_receipt_sha256=producer.sha(configured), root_locked=True, hardware_contact=False,
            publication=False, cpio_executable_metadata={name: {} for name in critical},
            ext4_read_only_cpio_equivalence=dict(critical_members=critical))
        self.inspection = self.write('inspection.json', self.inspection_data)

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding='utf-8')
        return path

    def check(self):
        return producer.checked_inputs(self.build, self.inspection, self.native_manifest, self.terminal)

    def test_local_bundle_keeps_distinct_sources_unsigned_scope_and_all_checksums(self):
        result = producer.prepare(self.build, self.inspection, self.native_manifest, self.terminal, self.root / 'prepared')
        manifest = json.loads((self.root / 'prepared/PRIVATE_BETA.json').read_text(encoding='utf-8'))
        self.assertFalse(manifest['persistent_install_authorized'])
        self.assertFalse(manifest['authenticated_git_release_provenance'])
        self.assertFalse(manifest['publication'])
        self.assertIsNone(manifest['signature'])
        self.assertEqual(manifest['userspace_make_exit_code'], 2)
        self.assertNotEqual(manifest['native_source_manifest_sha256'], manifest['image_input_receipt_sha256'])
        with tarfile.open(result['archive']) as archive:
            for name, row in manifest['artifacts'].items():
                member = archive.getmember('classic-aml-private-beta/' + name)
                self.assertTrue(member.isfile())
                self.assertEqual((member.mode, member.uid, member.gid), (0o644, 0, 0))
                self.assertEqual(producer.hashlib.sha256(archive.extractfile(member).read()).hexdigest(), row['sha256'])
        with self.assertRaisesRegex(ValueError, 'preserve existing'):
            producer.prepare(self.build, self.inspection, self.native_manifest, self.terminal, self.root / 'prepared')

    def test_changed_payload_and_foreign_inspection_refuse(self):
        self.inspection_data['build_receipt_sha256'] = '0' * 64
        self.write('inspection.json', self.inspection_data)
        with self.assertRaisesRegex(ValueError, 'different userspace'):
            self.check()
        self.inspection_data['build_receipt_sha256'] = producer.sha(self.build)
        self.write('inspection.json', self.inspection_data)
        (self.root / 'rootfs.ext4').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'filesystem artifact differs'):
            self.check()

    def test_stale_source_receipt_or_missing_mode_inspection_refuses(self):
        self.inspection_data['cpio_executable_metadata'].pop('sbin/init')
        self.write('inspection.json', self.inspection_data)
        with self.assertRaisesRegex(ValueError, 'executable checks missing'):
            self.check()
        self.native_manifest.write_text('{}', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'receipt digest differs'):
            self.check()

    def test_header_crc_payload_crc_wrong_architecture_and_different_cpio_refuse(self):
        compressed = gzip.compress(b'fixture')
        valid = uimage(compressed)
        producer.validate_uimage(valid, compressed)
        for damaged in (valid[:8] + bytes([valid[8] ^ 1]) + valid[9:],
                        valid[:-1] + bytes([valid[-1] ^ 1]), uimage(compressed, arch=2), valid + b'x'):
            with self.subTest(header=damaged[:12]):
                with self.assertRaises(ValueError):
                    producer.validate_uimage(damaged, compressed)
        with self.assertRaisesRegex(ValueError, 'inspected gzip'):
            producer.validate_uimage(valid, gzip.compress(b'other'))

    def test_early_failure_leftovers_wrong_tail_and_changed_log_refuse(self):
        valid = self.log.read_text(encoding='utf-8')
        for exit_code, text in ((2, terminal_audit.PACKAGE_REFUSAL),
                                (2, valid.replace(terminal_audit.PACKAGE_REFUSAL, 'ERROR: filesystem generation failed')),
                                (2, valid + 'ERROR: unrelated failure\n'), (1, valid), (0, valid)):
            with self.subTest(exit_code=exit_code, text=text[-80:]):
                with self.assertRaises(ValueError):
                    terminal_audit.classify(exit_code, text)
        self.assertEqual(terminal_audit.classify(0, '\n'.join(terminal_audit.MARKERS) + '\nSysupgrade tarball:\n')[0],
                         'completed_standard_make')
        self.log.write_text(valid + 'changed after audit\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'audited build log differs'):
            self.check()

    def test_same_length_mutation_after_staging_is_rejected_from_completed_archive(self):
        output = self.root / 'race-prepared'
        original = tarfile.TarFile.addfile

        def mutate_then_add(bundle, entry, fileobj=None):
            if entry.name.endswith('/payloads/rootfs.ext4'):
                path = output / 'payloads/rootfs.ext4'
                path.write_bytes(b'x' * path.stat().st_size)
            return original(bundle, entry, fileobj)

        with patch.object(tarfile.TarFile, 'addfile', mutate_then_add):
            with self.assertRaisesRegex(ValueError, 'archive member digest differs'):
                producer.prepare(self.build, self.inspection, self.native_manifest, self.terminal, output)


if __name__ == '__main__':
    unittest.main()
