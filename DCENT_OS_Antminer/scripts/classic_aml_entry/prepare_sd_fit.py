#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare a Classic SD-FIT from a release package authenticated by the caller.

The removable-media path uses U-Boot's normal Linux handoff. It does not use
the six-MTD writer, change a boot selector or format the existing nvdata UBI.
Run locally on Linux with mkimage and dtc installed.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from classic_aml_entry import prepare_signed as signed

FIT_ADDRESS = 0x08000000
MAX_FIT = 0x04000000
TARGET = signed.TARGET


def compose(package: bytes, key: bytes, dtb: bytes) -> dict[str, bytes]:
    members, _ = signed.authenticated_package(package, key, TARGET)
    signed.require(signed.digest(dtb) == signed.layout.FDT_SHA, 'exact Classic seven-MTD DTB required')
    initrd = signed.initrd_from_uimage(members['root'])
    start = (signed.layout.INITRD_HIGH - len(initrd)) & ~4095
    final_dtb = signed.layout.final_dtb(dtb, start, start + len(initrd))
    # Explicit load locations keep the kernel effective extent and both output
    # buffers below the FIT input, above secure memory, and below ramoops.
    signed.require(start >= signed.layout.FDT_ADDRESS + len(final_dtb), 'SD-FIT payload overlap')
    its = f'''/dts-v1/;
/ {{
    description = "DCENT_OS Classic seven-MTD SD boot";
    #address-cells = <1>;
    images {{
        kernel {{
            description = "Classic A113D Linux";
            data = /incbin/("Image");
            type = "kernel"; arch = "arm64"; os = "linux"; compression = "none";
            load = <0x{signed.layout.KERNEL_ADDRESS:x}>;
            entry = <0x{signed.layout.KERNEL_ADDRESS:x}>;
            hash-1 {{ algo = "sha256"; }};
        }};
        fdt {{
            description = "Classic seven-MTD device tree";
            data = /incbin/("final.dtb");
            type = "flat_dt"; arch = "arm64"; compression = "none";
            load = <0x{signed.layout.FDT_ADDRESS:x}>;
            hash-1 {{ algo = "sha256"; }};
        }};
        ramdisk {{
            description = "Authenticated DCENT_OS initramfs";
            data = /incbin/("initrd.gz");
            type = "ramdisk"; arch = "arm64"; os = "linux"; compression = "none";
            load = <0x{start:x}>;
            hash-1 {{ algo = "sha256"; }};
        }};
    }};
    configurations {{
        default = "classic";
        classic {{ kernel = "kernel"; fdt = "fdt"; ramdisk = "ramdisk"; }};
    }};
}};
'''.encode()
    # The gzip bytes are loaded as-is; Linux unpacks them. Setting ramdisk
    # compression=gzip would ask U-Boot to inflate into a compressed-size span.
    return {'Image': members['kernel'], 'initrd.gz': initrd, 'final.dtb': final_dtb,
            'boot.its': its, 'release.tar': package}


def boot_command(fit_size: int, fit_sha: str) -> bytes:
    signed.require(0 < fit_size <= MAX_FIT, 'SD-FIT exceeds input memory span')
    signed.require(len(fit_sha) == 64 and all(c in '0123456789abcdef' for c in fit_sha),
                   'invalid SD-FIT digest')
    # No saveenv: these environment variables are RAM-only. The script is
    # explicitly loaded by the owner from FAT partition mmc 0:1 at the console.
    # Hash verification is required; a loader missing that command fails closed.
    return f'''if fatload mmc 0:1 0x{FIT_ADDRESS:x} /dcentos/boot.itb 0x{MAX_FIT + 1:x}; then
    if test "${{filesize}}" = "{fit_size:x}"; then
        if hash sha256 0x{FIT_ADDRESS:x} 0x{fit_size:x} dcent_fit_sha; then
            if test "${{dcent_fit_sha}}" = "{fit_sha}"; then
                if setenv bootargs 'console=ttyAML0,115200n8 rdinit=/init' &&
                   setenv fdt_high ffffffffffffffff &&
                   setenv initrd_high ffffffffffffffff; then
                    bootm 0x{FIT_ADDRESS:x}#classic
                fi
            fi
        fi
    fi
fi
echo 'DCENT_OS SD boot stopped; original NAND boot selection is unchanged'
false
'''.encode()


def prepare(package: Path, public_key: Path, dtb: Path, output: Path, mkimage: str = 'mkimage'):
    reader = signed.layout.reader
    inputs = [(package, signed.MAX_PACKAGE), (public_key, 4096), (dtb, 65536)]
    raw = [reader.regular_bytes(path, limit) for path, limit in inputs]
    files = compose(*raw)
    output = reader._plain_path(output)
    signed.require(not output.exists(), 'SD-FIT output must be a fresh directory')
    output.mkdir(mode=0o700)
    for name, body in files.items():
        reader._write_new(output / name, body)
    result = subprocess.run([mkimage, '-f', 'boot.its', 'boot.itb'], cwd=output,
                            capture_output=True, timeout=60)
    signed.require(result.returncode == 0, 'SD-FIT build failed: ' + result.stderr[-2000:].decode(errors='replace'))
    fit = reader.regular_bytes(output / 'boot.itb', MAX_FIT)
    verify_fit(fit, files)
    script = boot_command(len(fit), hashlib.sha256(fit).hexdigest())
    reader._write_new(output / 'boot.cmd', script)
    result = subprocess.run([mkimage, '-A', 'arm64', '-O', 'linux', '-T', 'script',
                             '-C', 'none', '-n', 'DCENT_OS Classic SD', '-d', 'boot.cmd', 'boot.scr'],
                            cwd=output, capture_output=True, timeout=60)
    signed.require(result.returncode == 0, 'SD script build failed: ' + result.stderr[-2000:].decode(errors='replace'))
    signed.require(all(reader.regular_bytes(path, limit) == original
                       for (path, limit), original in zip(inputs, raw)), 'SD-FIT input changed')
    signed.require(all(reader.regular_bytes(output / name) == body for name, body in files.items()),
                   'SD-FIT input readback differs')
    reader._sync_directory(output)
    reader._sync_directory(output.parent)


def verify_fit(fit: bytes, files: dict[str, bytes]):
    """Check the compiled image contents, selection, addresses and all hashes."""
    # dtc/mkimage allow zero padding after the FDT; the existing strict parser
    # expects the serialized tree's exact byte length.
    signed.require(len(fit) >= 40, 'short SD-FIT')
    total = struct.unpack_from('>I', fit, 4)[0]
    signed.require(total <= len(fit) and not any(fit[total:]), 'SD-FIT padding differs')
    nodes, _ = signed.layout.reader.parse_fdt(fit[:total])
    signed.require(nodes['/configurations']['default'] == b'classic\0' and
                   nodes['/configurations/classic'] ==
                   {'kernel': b'kernel\0', 'fdt': b'fdt\0', 'ramdisk': b'ramdisk\0'},
                   'SD-FIT boot selection differs')
    start = (signed.layout.INITRD_HIGH - len(files['initrd.gz'])) & ~4095
    for name, filename, address in (('kernel', 'Image', signed.layout.KERNEL_ADDRESS),
                                   ('fdt', 'final.dtb', signed.layout.FDT_ADDRESS),
                                   ('ramdisk', 'initrd.gz', start)):
        node = nodes['/images/' + name]
        signed.require(node['data'] == files[filename] and node['arch'] == b'arm64\0'
                       and node['load'] == struct.pack('>I', address)
                       and node['compression'] == b'none\0', 'SD-FIT payload differs: ' + name)
        checksum = nodes['/images/' + name + '/hash-1']
        signed.require(checksum['algo'] == b'sha256\0' and checksum['value'] ==
                       hashlib.sha256(files[filename]).digest(), 'SD-FIT hash differs: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('package', 'public-key', 'donor-dtb', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--mkimage', default='mkimage')
    args = parser.parse_args()
    try:
        prepare(args.package, args.public_key, args.donor_dtb, args.output, args.mkimage)
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print('Prepared Classic SD-FIT and console boot script from the authenticated release package.')


if __name__ == '__main__':
    main()
