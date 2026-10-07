#!/usr/bin/env python3
"""Prepare an unsigned local Classic AML image bundle from checked build receipts.

This creates no release signature, authenticated Git provenance, device access,
or persistent-install authority. Runtime and image inputs remain distinct.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import tarfile
import zlib

TARGET = 'am3-s19jpro-aml'
SCHEMA = 'dcentos.classic_aml_private_beta.v1'
WINDOW_BYTES = 0x02800000
DONOR_ROOT = ''
DONORS = {
    'kernel': ('vmlinux.bin', 'd5013ac9f545df3b0792ea2cd8902b51e323bbb6f73ff0fea17bbee9f6157fe6'),
    'devicetree.dtb': ('devicetree.dtb', '540c1770543d9620e106ea4287c2a534f5efd85c912e97d6be6295930506b257'),
    'fw-info': ('rootfs/etc/fw-info', 'f1c495fb5d70e619602eefc1764aface200fd53c29e92f4b23ffd4b003eb018e'),
}
FILESYSTEMS = ('uImage_rootfs.bin', 'rootfs.cpio.gz', 'rootfs.ext4')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def receipt(path, expected=None):
    require(path.is_file() and not path.is_symlink(), 'receipt must be regular: ' + str(path))
    require(path.stat().st_size <= 4 * 1024 * 1024, 'receipt exceeds size bound')
    if expected:
        require(sha(path) == expected, 'receipt digest differs: ' + str(path))
    value = json.loads(path.read_text(encoding='utf-8'))
    require(isinstance(value, dict), 'receipt is not an object')
    return value


def validate_uimage(data, compressed):
    require(64 < len(data) <= WINDOW_BYTES, 'rootfs does not fit the AM3 window')
    fields = struct.unpack('>7I4B32s', data[:64])
    magic, header_crc, _, length, load, entry, body_crc, os_id, arch, kind, compression, _ = fields
    require(magic == 0x27051956, 'rootfs lacks uImage magic')
    header = data[:4] + b'\0' * 4 + data[8:64]
    require(zlib.crc32(header) == header_crc, 'uImage header CRC differs')
    require(length == len(data) - 64 and zlib.crc32(data[64:]) == body_crc,
            'uImage payload length or CRC differs')
    require((os_id, arch, kind, compression, load, entry) == (5, 22, 3, 1, 0, 0),
            'uImage is not the exact Linux AArch64 gzip ramdisk shape')
    require(data[64:] == compressed and compressed[:2] == b'\x1f\x8b',
            'uImage does not wrap the inspected gzip CPIO')
    return {'bytes': len(data), 'payload_bytes': length, 'header_crc32': header_crc,
            'payload_crc32': body_crc, 'window_bytes': WINDOW_BYTES}


def verify_archive(archive, expected):
    """Check completed TAR bytes, including files changed after staging checks."""
    seen = set()
    with tarfile.open(archive, 'r:') as bundle:
        for member in bundle:
            prefix = 'classic-aml-private-beta/'
            require(member.name.startswith(prefix), 'unexpected archive prefix')
            name = member.name[len(prefix):]
            require(name in expected and name not in seen, 'unexpected or duplicate archive member')
            require(member.isfile() and (member.mode, member.uid, member.gid, member.mtime) == (0o644, 0, 0, 0),
                    'archive member metadata differs: ' + name)
            require(member.size == expected[name]['bytes'], 'archive member size differs: ' + name)
            seen.add(name)
            stream = bundle.extractfile(member)
            result = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                result.update(chunk)
            require(result.hexdigest() == expected[name]['sha256'], 'archive member digest differs: ' + name)
    require(seen == set(expected), 'archive member set is incomplete')


def checked_inputs(build_path, inspection_path, native_manifest_path, terminal_path):
    build = receipt(build_path)
    require(build.get('step') == 'build' and build.get('sources_unchanged') is True
            and build.get('validation_error') is None, 'userspace build input validation did not pass')
    require(build.get('resolved_aarch64') is True and build.get('resolved_root_locked') is True,
            'userspace must be AArch64 with locked root')
    terminal = receipt(terminal_path)
    allowed = {(0, 'completed_standard_make'), (2, 'final_unsigned_package_gate_refusal')}
    require(terminal.get('schema') == 'dcentos.classic_aml_build_terminal.v1'
            and terminal.get('eligible_for_private_preparation') is True
            and terminal.get('build_receipt_sha256') == sha(build_path)
            and terminal.get('make_exit_code') == build['make_exit_code']
            and (build['make_exit_code'], terminal.get('terminal_stage')) in allowed,
            'make did not end at an eligible audited terminal stage')
    build_log = Path(build['log'])
    require(str(build_log) == terminal['log'] and build_log.stat().st_size == terminal['log_bytes']
            and sha(build_log) == terminal['log_sha256'], 'audited build log differs')
    native = build['native']
    require(isinstance(native, dict), 'native artifact binding missing')
    native_path = Path(native['receipt'])
    native_build = receipt(native_path, native['receipt_sha256'])
    require(native_build['exit_code'] == 0, 'native compilation did not pass')
    receipt(native_manifest_path, native['source_manifest_sha256'])
    require(native_build['source_snapshot_manifest_sha256'] == native['source_manifest_sha256'],
            'native source identities differ')
    image_path = Path(build['input_receipt'])
    image = receipt(image_path, build['input_receipt_sha256'])
    configured_path = Path(build['configuration']['receipt'])
    configured = receipt(configured_path, build['configuration']['receipt_sha256'])
    require(configured.get('step') == 'configure' and configured['exit_code'] == 0
            and configured.get('sources_unchanged') is True and configured.get('validation_error') is None,
            'configure did not pass')
    require(configured['input_receipt_sha256'] == build['input_receipt_sha256']
            and configured['resolved_config_sha256'] == build['resolved_config_sha256']
            == build['configuration']['resolved_config_sha256'], 'configuration binding differs')
    inspection = receipt(inspection_path)
    require(inspection.get('claim') == 'actual_userspace_archive_and_read_only_fs_cli_checks_not_physical_or_package_admission'
            and inspection['build_receipt_sha256'] == sha(build_path), 'inspection belongs to different userspace')
    require(inspection['native_source_manifest_sha256'] == native['source_manifest_sha256']
            and inspection['image_input_receipt_sha256'] == build['input_receipt_sha256']
            and inspection['resolved_config_sha256'] == build['resolved_config_sha256']
            and inspection['configure_receipt_sha256'] == build['configuration']['receipt_sha256'],
            'inspection source/configuration binding differs')
    require(inspection['root_locked'] is True and inspection['hardware_contact'] is False
            and inspection['publication'] is False, 'inspection scope differs')
    critical = {'sbin/init', 'usr/local/bin/dcentrald', 'etc/init.d/S37board_setup',
                'etc/init.d/S82dcentrald', 'etc/init.d/S99verify',
                'usr/libexec/dcentos/verify-classic-aml-proof.py'}
    require(critical <= set(inspection['cpio_executable_metadata'])
            and critical <= set(inspection['ext4_read_only_cpio_equivalence']['critical_members']),
            'required CPIO/ext4 executable checks missing')
    artifacts = {Path(row['path']).name: row for row in build['artifacts']}
    selected = {}
    for name in FILESYSTEMS:
        row = artifacts[name]
        path = Path(row['path'])
        require(path.is_file() and path.stat().st_size == row['bytes'] and sha(path) == row['sha256'],
                'filesystem artifact differs: ' + name)
        selected['payloads/' + name] = (path, row['sha256'])
    rows = {row['path']: row for row in image['files']}
    for name, (relative, expected) in DONORS.items():
        source_name = DONOR_ROOT + relative
        require(rows[source_name]['sha256'] == expected, 'held boot identity differs: ' + name)
        path = Path(image['source']) / source_name
        require(sha(path) == expected, 'held boot bytes differ: ' + name)
        selected['boot/' + name] = (path, expected)
    for name, path in (
        ('userspace-build.json', build_path), ('userspace-inspection.json', inspection_path),
        ('native-build.json', native_path), ('native-source-snapshot.json', native_manifest_path),
        ('image-inputs.json', image_path), ('configure.json', configured_path),
        ('build-terminal.json', terminal_path), ('userspace-build.log', build_log),
    ):
        selected['receipts/' + name] = (path, sha(path))
    uimage = validate_uimage(Path(artifacts['uImage_rootfs.bin']['path']).read_bytes(),
                            Path(artifacts['rootfs.cpio.gz']['path']).read_bytes())
    return build, inspection, selected, uimage


def prepare(build_path, inspection_path, native_manifest_path, terminal_path, output):
    archive = output.with_name(output.name + '.tar')
    require(not output.exists() and not archive.exists(), 'preserve existing preparation')
    build, inspection, selected, uimage = checked_inputs(build_path, inspection_path, native_manifest_path, terminal_path)
    output.mkdir(parents=True)
    artifacts = {}
    for name, (source, expected) in sorted(selected.items()):
        copied = output / name
        copied.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, copied)
        copied.chmod(0o644)
        require(sha(copied) == expected, 'input changed while copying: ' + name)
        artifacts[name] = {'bytes': copied.stat().st_size, 'sha256': expected}
    manifest = {
        'schema': SCHEMA, 'board_target': TARGET, 'product': 'DCENT_OS',
        'status': 'private_beta_unsigned_unpublished', 'runtime_lane': 'ClassicAmlNativeSerial',
        'admitted_application_firmware': '0x89', 'asic': 'BM1362', 'chips_per_populated_chain': 126,
        'factory_models': ['BHB42601', 'BHB42621', 'BHB42641'],
        'scope': 'local_artifact_preparation', 'persistent_install_authorized': False,
        'authenticated_git_release_provenance': False, 'physical_runtime_validation': False,
        'hardware_contact': False, 'publication': False, 'signature': None,
        'image_input_receipt_sha256': build['input_receipt_sha256'],
        'native_source_manifest_sha256': build['native']['source_manifest_sha256'],
        'native_build_receipt_sha256': build['native']['receipt_sha256'],
        'resolved_config_sha256': build['resolved_config_sha256'],
        'userspace_make_exit_code': build['make_exit_code'],
        'build_terminal_receipt_sha256': sha(terminal_path),
        'uimage': uimage, 'artifacts': artifacts,
        'producer': {'file': Path(__file__).name, 'sha256': sha(Path(__file__))},
        'next_install_requirements': 'separate exact-unit route, root access, restore-verified backup, package admission and live-operation authorization',
    }
    manifest_path = output / 'PRIVATE_BETA.json'
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    checksums = dict(artifacts)
    checksums['PRIVATE_BETA.json'] = {'sha256': sha(manifest_path), 'bytes': manifest_path.stat().st_size}
    sums_path = output / 'SHA256SUMS'
    sums_path.write_text(''.join(row['sha256'] + '  ' + name + '\n'
                                for name, row in sorted(checksums.items())), encoding='utf-8')
    archive_members = dict(checksums, SHA256SUMS={'sha256': sha(sums_path), 'bytes': sums_path.stat().st_size})
    with tarfile.open(archive, 'x', format=tarfile.USTAR_FORMAT) as bundle:
        for path in sorted(p for p in output.rglob('*') if p.is_file()):
            name = path.relative_to(output).as_posix()
            entry = tarfile.TarInfo('classic-aml-private-beta/' + name)
            entry.size = path.stat().st_size
            entry.mode = 0o644
            entry.uid = entry.gid = entry.mtime = 0
            with path.open('rb') as stream:
                bundle.addfile(entry, stream)
    verify_archive(archive, archive_members)
    return {'directory': str(output), 'archive': str(archive), 'archive_bytes': archive.stat().st_size,
            'archive_sha256': sha(archive), 'manifest_sha256': sha(manifest_path),
            'schema': SCHEMA, 'persistent_install_authorized': False, 'publication': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-receipt', required=True, type=Path)
    parser.add_argument('--inspection-receipt', required=True, type=Path)
    parser.add_argument('--native-source-manifest', required=True, type=Path)
    parser.add_argument('--terminal-receipt', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.build_receipt, args.inspection_receipt,
                             args.native_source_manifest, args.terminal_receipt, args.output_dir), indent=2))


if __name__ == '__main__':
    main()
