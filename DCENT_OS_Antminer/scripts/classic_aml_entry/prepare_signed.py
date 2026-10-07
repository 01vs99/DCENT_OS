#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only
"""Build local Classic entry files from a caller-authenticated current package.

No device transport, boot script, persistent writer or production signer runs.
Cold-entry lineage and complete hardware/actor custody remain separate work.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
import zlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:
    import tomllib
except ImportError:
    import tomli as tomllib

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from classic_aml_entry import prepare as layout  # noqa: E402

TARGET = 'am3-s19jpro-aml'
PREFIX = f'sysupgrade-{TARGET}/'
MAX_PACKAGE = 64 * 1024 * 1024
MAX_INITRD = 32 * 1024 * 1024
MAX_CPIO = 256 * 1024 * 1024
MEMBERS = {'kernel', 'root', 'METADATA', 'MANIFEST.json', 'MANIFEST.sig',
           'release_ed25519.pub', 'SHA256SUMS'}
# Independently recomputed from the exact held Classic SD ZIP's upgrade image:
# LZ4C at 383376, 494960 bytes -> authenticated 923584-byte BL33. These are source
# identities, never an observation of the loader currently running on a miner.
RESIDENT_BYTES = 923584
RESIDENT_SHA = '103c64d90f72fffeb1a79d0133c656a31eecff959fd1502e0c302adc66f6711e'
RESIDENT_PREFIX_BYTES = 0x94000
RESIDENT_PREFIX_SHA = '83042e6fc1c14955ba0a3ed621379798e4c865637619e7645bcec0561776c183'
SOURCE_NAMES = ('runtime_bootstrap.S', 'runtime.c', 'mmio.S', 'cache.S', 'handoff.S', 'finish.S')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def public_key(raw):
    try:
        if raw.startswith(b'-----BEGIN PUBLIC KEY-----'):
            key = serialization.load_pem_public_key(raw)
            require(isinstance(key, Ed25519PublicKey), 'Ed25519 public key required')
            return key
        text = raw.decode('ascii').strip()
        require(re.fullmatch(r'[0-9a-f]{64}', text), 'public key must be PEM or lowercase raw hex')
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(text))
    except (UnicodeError, TypeError) as error:
        raise ValueError('invalid caller public key') from error


def package_members(raw):
    require(0 < len(raw) <= MAX_PACKAGE, 'package size exceeds Classic bound')
    members = {}
    directories = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            for member in archive:
                require(member.name.startswith(PREFIX) or member.name == PREFIX[:-1],
                        'package has a foreign or unsafe member path')
                require(not member.pax_headers, 'extended tar member metadata refused')
                if member.isdir():
                    require(member.name.rstrip('/') == PREFIX[:-1]
                            and member.name.rstrip('/') not in directories,
                            'unexpected or duplicate package directory')
                    directories.add(member.name.rstrip('/'))
                    continue
                name = member.name[len(PREFIX):]
                require(member.isfile() and name in MEMBERS and name not in members,
                        'package member is unexpected, duplicated or indirect')
                limit = MAX_PACKAGE if name in ('kernel', 'root') else 65536
                require(0 < member.size <= limit, 'package member size exceeds bound')
                body = archive.extractfile(member).read(limit + 1)
                require(len(body) == member.size, 'short package member')
                members[name] = body
            require(len(raw) >= archive.offset + 1024 and not any(raw[archive.offset:]),
                    'nonzero/short tar padding or concatenated archive')
    except tarfile.TarError as error:
        raise ValueError('plain sysupgrade tar required') from error
    require(set(members) == MEMBERS, 'complete signed Classic package required')
    return members


def authenticated_package(raw, caller_public_key, target):
    require(target == TARGET, 'only exact Classic am3-s19jpro-aml is supported')
    members = package_members(raw)
    key = public_key(caller_public_key)
    embedded = public_key(members['release_ed25519.pub'])
    encoding = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    require(key.public_bytes(*encoding) == embedded.public_bytes(*encoding),
            'embedded key differs from caller-pinned key')
    try:
        key.verify(members['MANIFEST.sig'], members['MANIFEST.json'])
    except (InvalidSignature, ValueError) as error:
        raise ValueError('current package signature is invalid') from error
    manifest = layout.reader.object_json(members['MANIFEST.json'])
    for field, expected in {
        'schema': 1, 'manifest_profile': 'dcentos.sysupgrade-authority/v1',
        'product': 'DCENT_OS', 'family': 'antminer', 'package_type': 'sysupgrade',
        'board_family': 'am3', 'board': TARGET, 'board_target': TARGET,
    }.items():
        require(type(manifest.get(field)) is type(expected) and manifest[field] == expected,
                f'signed package {field} differs')
    require(manifest.get('status') in ('release', 'production', 'stable'),
            'signed release posture required')
    require(type(manifest.get('installable')) is bool, 'explicit package installation status required')
    require(isinstance(manifest.get('version'), str) and manifest['version'].strip(),
            'package version required')
    provenance = manifest.get('provenance')
    require(isinstance(provenance, dict) and provenance.get('build_target') == TARGET,
            'exact source build target required')
    require(re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', str(provenance.get('source_commit', '')))
            and provenance.get('source_tree_state') in ('clean', 'exact_git_object_snapshot'),
            'authenticated source provenance required')
    require(type(provenance.get('source_date_epoch')) is int
            and provenance['source_date_epoch'] >= 0
            and type(provenance.get('source_commit_epoch')) is int
            and provenance['source_commit_epoch'] == provenance['source_date_epoch'],
            'source epoch provenance differs')
    payloads = manifest.get('payloads')
    names = {'kernel': 'kernel', 'rootfs': 'root', 'metadata': 'METADATA',
             'verification_key': 'release_ed25519.pub'}
    require(isinstance(payloads, dict) and set(payloads) == set(names), 'exact signed payload roster required')
    for role, name in names.items():
        row = payloads[role]
        require(isinstance(row, dict) and set(row) == {'path', 'size', 'sha256'}
                and row['path'] == PREFIX + name and type(row['size']) is int
                and row['size'] == len(members[name]) and row['sha256'] == digest(members[name]),
                f'signed payload differs: {role}')
    sums = {}
    for line in members['SHA256SUMS'].decode('ascii').splitlines():
        parts = line.split('  ')
        require(len(parts) == 2 and parts[1] in names.values() and parts[1] not in sums,
                'invalid package checksum roster')
        sums[parts[1]] = parts[0]
    require(sums == {name: digest(members[name]) for name in names.values()},
            'package checksum roster differs')
    require(digest(members['kernel']) == layout.KERNEL_SHA, 'exact held Classic kernel required')
    return members, manifest


def initrd_from_uimage(raw):
    require(64 < len(raw) <= MAX_INITRD + 64, 'rootfs uImage exceeds entry bound')
    fields = struct.unpack('>7I4B32s', raw[:64])
    body = raw[64:]
    require(fields[0] == 0x27051956
            and fields[1] == zlib.crc32(raw[:4] + bytes(4) + raw[8:64])
            and fields[3] == len(body) and fields[6] == zlib.crc32(body)
            and (fields[4], fields[5], *fields[7:11]) == (0, 0, 5, 22, 3, 1),
            'rootfs uImage header, CRC, architecture or ramdisk type differs')
    entries = {}
    for name, entry in layout.reader.cpio_entries(layout.reader.gunzip(body, MAX_CPIO)).items():
        # Buildroot newc producers may use a leading './'. Normalize that one
        # spelling only, refusing aliases that could overwrite checked markers.
        name = name[2:] if name.startswith('./') else name
        if name in ('', '.') and entry[0][1] & 0o170000 == 0o040000:
            continue
        require(all(part not in ('', '.', '..') for part in name.split('/'))
                and name not in entries, 'aliased rootfs path')
        entries[name] = entry
    def regular(name):
        require(name in entries and entries[name][0][1] & 0o170000 == 0o100000
                and entries[name][0][4] == 1 and entries[name][0][2:4] == [0, 0],
                f'regular rootfs marker required: {name}')
        for parent in Path(name).parents:
            parent = parent.as_posix()
            require(parent not in entries or entries[parent][0][1] & 0o170000 == 0o040000,
                    'rootfs marker parent is not a directory')
        return entries[name][1]
    require(regular('etc/dcentos/board_target').strip() == TARGET.encode(),
            'rootfs board target differs from authenticated package')
    require(regular('etc/dcentos/release-image').strip(), 'release image marker required')
    try:
        config = tomllib.loads(regular('etc/dcentrald.toml').decode('utf-8'))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError('invalid signed startup config') from error
    mining, platform = config.get('mining'), config.get('platform')
    require(isinstance(mining, dict) and mining.get('enabled') is False,
            'entry image must boot with mining disabled')
    require(isinstance(platform, dict) and platform.get('board_target') == TARGET,
            'startup config target differs')
    return body


def resident_profile(raw, descriptor):
    require(len(raw) == RESIDENT_BYTES and digest(raw) == RESIDENT_SHA,
            'exact held decompressed Classic BL33 required')
    relocations = []
    for position in range(0, len(raw) - 23, 8):
        address, kind, addend = struct.unpack_from('<QQQ', raw, position)
        if kind == 1027 and 0x01000000 <= address < 0x01000000 + RESIDENT_PREFIX_BYTES:
            relocations.append((address - 0x01000000, addend))
    relocations.sort()
    require(len(relocations) == 9 and len({row[0] for row in relocations}) == 9,
            'resident RELATIVE relocation roster differs')
    prefix = bytearray(raw[:RESIDENT_PREFIX_BYTES])
    for offset, addend in relocations:
        require(offset % 8 == 0 and offset + 8 <= len(prefix)
                and struct.unpack_from('<Q', raw, offset)[0] == addend,
                'resident source relocation differs')
        struct.pack_into('<Q', prefix, offset, addend)
    require(digest(prefix) == RESIDENT_PREFIX_SHA, 'canonical resident prefix differs')
    def initializer(value):
        return '{' + ','.join(f'0x{byte:02x}' for byte in value) + '}'
    rows = ','.join(f'{{0x{offset:x},0x{addend:x}ULL}}' for offset, addend in relocations)
    return ('/* Current authenticated Classic package; independently derived held BL33. */\n'
            '#include "admission.h"\nstatic const struct dcent_admission_profile profile={\n'
            + initializer(hashlib.sha256(descriptor).digest()) + ',\n'
            + initializer(hashlib.sha256(prefix).digest()) + ',\n{' + rows + '}\n};\n').encode()


def compose(package, key, target, dtb, resident):
    members, manifest = authenticated_package(package, key, target)
    require(digest(dtb) == layout.FDT_SHA, 'exact held Classic kernel DTB required')
    kernel = members['kernel']
    require(len(kernel) == 14960648 and struct.unpack_from('<QQQ', kernel, 8)
            == (layout.KERNEL_ADDRESS, 0xF2B000, 0xA) and kernel[56:60] == b'ARM\x64',
            'Classic kernel effective extent differs')
    initrd = initrd_from_uimage(members['root'])
    start = (layout.INITRD_HIGH - len(initrd)) & ~4095
    final_dtb = layout.final_dtb(dtb, start, start + len(initrd))
    require(layout.FDT_ADDRESS + len(final_dtb) <= start and len(final_dtb) <= 0x9000,
            'entry payloads overlap')
    descriptor = struct.pack('<8sII8Q', b'DCE2CL01', 1, 256, layout.KERNEL_ADDRESS,
        len(kernel), 0xF2B000, start, len(initrd), layout.FDT_ADDRESS, len(final_dtb), 0x10000000)
    descriptor += b''.join(hashlib.sha256(value).digest() for value in
                          (kernel, initrd, final_dtb, layout.BOOTARGS, package)) + bytes(16)
    files = {'Image': kernel, 'initrd.gz': initrd, 'final.dtb': final_dtb,
             'descriptor.bin': descriptor, 'entry-profile.h': resident_profile(resident, descriptor)}
    return files, manifest


def build_entry(output, zig):
    # Existing tracked C/ASM leaves are compiled with a fresh descriptor profile;
    # no legacy candidate, build receipt, private output or generated header is read.
    inputs = [HERE / name for name in SOURCE_NAMES]
    elf, binary = output / 'classic-entry.elf', output / 'classic-entry.bin'
    commands = (
        [str(zig), 'cc', '-target', 'aarch64-freestanding-none',
         '-mcpu=generic+el3+reserve_x18-neon-fp_armv8', '-O2', '-ffreestanding', '-nostdlib',
         '-fno-builtin', '-fno-stack-protector', '-fno-pic', '-ffixed-x18', '-mgeneral-regs-only',
         '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-I', str(HERE), '-I', str(output),
         '-Wl,-T,' + str(HERE / 'entry.ld'), '-Wl,--build-id=none',
         *map(str, inputs), '-o', str(elf)],
        [str(zig), 'objcopy', '-O', 'binary', str(elf), str(binary)],
    )
    # Keep compiler scratch with this operation and remove it afterward, rather
    # than writing into a shared global Zig cache outside the worktree.
    with tempfile.TemporaryDirectory(prefix='dcent-classic-compile-', dir=output.parent) as cache:
        env = dict(os.environ, ZIG_LOCAL_CACHE_DIR=str(Path(cache) / 'local'),
                   ZIG_GLOBAL_CACHE_DIR=str(Path(cache) / 'global'))
        for command in commands:
            result = subprocess.run(command, env=env, capture_output=True, timeout=120)
            require(result.returncode == 0, 'entry compilation failed: ' + result.stderr[-4000:].decode(errors='replace'))
    header = layout.reader.regular_bytes(elf, 2 * 1024 * 1024)
    require(header[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', header, 18)[0] == 183
            and struct.unpack_from('<Q', header, 24)[0] == 0x07800000,
            'compiled entry architecture/address differs')
    raw = layout.reader.regular_bytes(binary, 65536)
    require(hashlib.sha256((output / 'descriptor.bin').read_bytes()).digest() in raw,
            'compiled entry is not bound to current descriptor')


def prepare(package, key, target, dtb, resident, output, zig):
    inputs = [(package, MAX_PACKAGE), (key, 4096), (dtb, 65536), (resident, 2 * 1024 * 1024)]
    originals = [layout.reader.regular_bytes(path, limit) for path, limit in inputs]
    files, manifest = compose(originals[0], originals[1], target, originals[2], originals[3])
    output = layout.reader._plain_path(output)
    require(not output.exists(), 'entry output must be a fresh directory')
    output.mkdir(mode=0o700)
    for name, raw in files.items():
        layout.reader._write_new(output / name, raw)
        require(layout.reader.regular_bytes(output / name) == raw, f'entry readback differs: {name}')
    build_entry(output, zig)
    require(all(layout.reader.regular_bytes(path, limit) == raw
                for (path, limit), raw in zip(inputs, originals)), 'input changed during preparation')
    layout.reader._sync_directory(output)
    layout.reader._sync_directory(output.parent)
    return manifest['version']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('package', 'public-key', 'donor-dtb', 'resident-bl33', 'output', 'zig'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--target', required=True, choices=(TARGET,))
    args = parser.parse_args()
    try:
        version = prepare(args.package, args.public_key, args.target, args.donor_dtb,
                          args.resident_bl33, args.output, args.zig)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(f'Prepared {TARGET} {version} with a compiled current descriptor profile.')
    print('Local files only. Cold entry, boot selection and persistent install/restore remain unfinished.')


if __name__ == '__main__':
    main()
