#!/usr/bin/env python3
"""Reproduce native S15/T15 SD boot files from the exact held stock components.

Both MSKMINERS 1.2.2 SD ZIPs supply these pins in bin/. Their top-level
BOOT.bin has a different FPGA and is deliberately not an interchangeable
input. Source receipts live in the R04 campaign evidence directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import zlib

# These two helpers operate on Zynq PS device-tree properties and regular
# pinned files. S15/T15 and C43 supply byte-identical Linux DTBs and kernels;
# no C43 PL register layout, FPGA payload or mining recipe is imported.
from prepare_c43_sd_image import add_native_watchdog, checked_input, fdt_properties

TARGETS = ("am1-s15", "am1-t15")
PINS = {
    "BOOT.bin": (2735664, "e6b85d66e226856203588794afb56da458716129852848c2c6069cb0ba84ab32"),
    "uImage": (4006832, "85f7da5f8205a684acb057ce7268d2e395bc4f39e5ae4c088bbf4ede1fcb638f"),
    "devicetree.dtb": (7650, "10a0199be8a638c4bf319a623362a89b6bee38f732ab00204df499a2f25ad2ea"),
}
BITSTREAM_OFFSET = 104256
BITSTREAM_SIZE = 2083744
BITSTREAM_SHA256 = "75e0b98b73822da3e195bb8ebd9235dfa3fb98c658838fe01c7accbe6a581dcd"
DMA_BASE = 0x0f000000
DMA_BYTES = 0x01000000
DMA_NODE = "/reserved-memory/bm1391-dma@f000000"


def reserve_native_dma(dtb: Path, fdtput: str = "fdtput") -> None:
    """Reserve the held 256-MiB profile's complete last 16 MiB before Linux.

    Stock cgminer startup and its launcher select this region for the small
    RAM branch. The pinned kernel enables CONFIG_OF_RESERVED_MEM; no-map keeps
    this region out of normal Linux mappings. This is a native reservation,
    not evidence that the stock module reserved memory safely.
    """
    original = fdt_properties(dtb.read_bytes())
    if (original.get(("/memory@0", "reg")) != struct.pack(">II", 0, 0x10000000)
            or original.get(("", "#address-cells")) != struct.pack(">I", 1)
            or original.get(("", "#size-cells")) != struct.pack(">I", 1)):
        raise ValueError("BM1391 DMA reservation requires the exact 256-MiB DT memory geometry")
    if any(path.startswith("/reserved-memory") for path, _ in original):
        raise ValueError("unexpected pre-existing reserved memory in BM1391 donor")
    subprocess.run([fdtput, "-c", str(dtb), "/reserved-memory"], check=True)
    subprocess.run([fdtput, "-c", str(dtb), DMA_NODE], check=True)
    entries = {
        ("/reserved-memory", "#address-cells"): ("x", ["1"]),
        ("/reserved-memory", "#size-cells"): ("x", ["1"]),
        ("/reserved-memory", "ranges"): ("x", []),
        (DMA_NODE, "reg"): ("x", [f"{DMA_BASE:x}", f"{DMA_BYTES:x}"]),
        (DMA_NODE, "compatible"): ("s", ["dcent,bm1391-stock-fpga-dma"]),
        (DMA_NODE, "no-map"): ("x", []),
    }
    for (node, name), (kind, values) in entries.items():
        subprocess.run([fdtput, "-t", kind, str(dtb), node, name, *values], check=True)
    changed = fdt_properties(dtb.read_bytes())
    if (any(changed.get(key) != value for key, value in original.items())
            or changed.keys() - original.keys() != entries.keys()
            or changed[(DMA_NODE, "reg")] != struct.pack(">II", DMA_BASE, DMA_BYTES)
            or changed[(DMA_NODE, "no-map")] != b""):
        raise ValueError("BM1391 reserved-memory edit changed unrelated properties")


def extract_fpga(boot: bytes) -> bytes:
    size, digest = PINS["BOOT.bin"]
    if len(boot) != size or hashlib.sha256(boot).hexdigest() != digest:
        raise ValueError("exact S15/T15 resident BOOT image required")
    pointer = struct.unpack_from("<I", boot, 0x9c)[0]
    header = struct.unpack_from("<16I", boot, pointer + 64)
    if (sum(header) & 0xffffffff != 0xffffffff
            or header[5] * 4 != BITSTREAM_OFFSET or header[0] * 4 != BITSTREAM_SIZE):
        raise ValueError("BM1391 BOOT FPGA partition header mismatch")
    payload = boot[BITSTREAM_OFFSET:BITSTREAM_OFFSET + BITSTREAM_SIZE]
    if hashlib.sha256(payload).hexdigest() != BITSTREAM_SHA256:
        raise ValueError("BM1391 raw FPGA payload mismatch")
    return payload


def verify_kernel(kernel: bytes) -> None:
    header = bytearray(kernel[:64])
    magic, crc, _, length, load, entry, data_crc = struct.unpack_from(">7I", header)
    header[4:8] = b"\0" * 4
    if (magic != 0x27051956 or zlib.crc32(header) != crc or len(kernel) != length + 64
            or zlib.crc32(kernel[64:]) != data_crc or load != 0x8000 or entry != 0x8000):
        raise ValueError("BM1391 kernel legacy header/CRC mismatch")


def boot_environment(target: str) -> dict[str, str]:
    if target not in TARGETS:
        raise ValueError("exact S15/T15 board target required")
    digest = bytes.fromhex(BITSTREAM_SHA256)
    writes = " && ".join(
        f"mw.l 0x{0x7f0000 + offset:x} 0x{int.from_bytes(digest[offset:offset+4], 'little'):08x} 1"
        for offset in range(0, 32, 4))
    return {
        "dcent_fpga_hash_pin": writes,
        "dcent_fpga_load": (
            "setenv verify yes && load mmc 0 0x00800000 bm1391-fabric.itb"
            " && fdt addr 0x00800000"
            " && fdt get value dcent_hash_algo /images/bm1391-raw/hash-1 algo"
            " && test x${dcent_hash_algo} = xsha256"
            " && fdt get size dcent_hash_size /images/bm1391-raw/hash-1 value"
            " && itest ${dcent_hash_size} == 0x20"
            " && fdt get addr dcent_hash_addr /images/bm1391-raw/hash-1 value"
            " && run dcent_fpga_hash_pin && cmp.b ${dcent_hash_addr} 0x007f0000 0x20"
            " && imxtract 0x00800000 bm1391-raw 0x01200000"
            f" && itest ${{filesize}} == 0x{BITSTREAM_SIZE:x}"
            " && fpga load 0 0x01200000 ${filesize}"
        ),
        "dcent_sd_load": "load mmc 0 0x02000000 uImage && load mmc 0 0x03000000 devicetree.dtb",
        "dcent_bootargs": (
            "setenv bootargs console=ttyPS0,115200 root=/dev/mmcblk0p2 ro rootwait rootfstype=ext2"
            " dcent.bm1391_load_completed=${dcent_bm1391_load_completed}"
            f" dcent.bm1391_sha256={BITSTREAM_SHA256} dcent.bm1391_target={target}"
        ),
        "uenvcmd": (
            "setenv dcent_bm1391_load_completed 0; if run dcent_fpga_load;"
            " then setenv dcent_bm1391_load_completed 1; else echo BM1391 FPGA load failed; fi;"
            " run dcent_sd_load && run dcent_bootargs && bootm 0x02000000 - 0x03000000"
        ),
    }


def prepare_boot(output: Path, donor: Path, target: str,
                 mkimage: str = "mkimage", fdtput: str = "fdtput") -> dict:
    environment = boot_environment(target)
    if output.is_symlink() or not output.is_dir() or any(output.iterdir()):
        raise ValueError("empty regular boot staging directory required")
    if donor.is_symlink() or not donor.is_dir():
        raise ValueError("regular donor directory required")
    held = {name: checked_input(donor / name, *pin) for name, pin in PINS.items()}
    payload = extract_fpga(held["BOOT.bin"])
    verify_kernel(held["uImage"])
    for name, data in held.items():
        (output / ("BOOT.BIN" if name == "BOOT.bin" else name)).write_bytes(data)
    (output / "devicetree-stock.dtb").write_bytes(held["devicetree.dtb"])
    add_native_watchdog(output / "devicetree.dtb", fdtput)
    reserve_native_dma(output / "devicetree.dtb", fdtput)
    (output / "bm1391-system.bin").write_bytes(payload)
    (output / "bm1391-fabric.its").write_text(
        '/dts-v1/;\n/ { description = "DCENT exact S15/T15 FPGA"; #address-cells = <1>;\n'
        ' images { bm1391-raw { description = "S15/T15 resident raw configuration";\n'
        ' data = /incbin/("bm1391-system.bin"); type = "firmware"; arch = "arm";\n'
        ' compression = "none"; hash-1 { algo = "sha256"; }; }; }; };\n', encoding="utf-8")
    # Use the pinned kernel's legacy image timestamp so repeated builds with
    # the same toolchain do not embed the operator's current wall-clock time.
    environment_vars = dict(os.environ, SOURCE_DATE_EPOCH=str(struct.unpack_from(">I", held["uImage"], 8)[0]))
    subprocess.run([mkimage, "-f", "bm1391-fabric.its", "bm1391-fabric.itb"],
                   cwd=output, env=environment_vars, check=True)
    fit = fdt_properties((output / "bm1391-fabric.itb").read_bytes())
    if (fit.get(("/images/bm1391-raw", "data")) != payload
            or fit.get(("/images/bm1391-raw/hash-1", "algo")) != b"sha256\0"
            or fit.get(("/images/bm1391-raw/hash-1", "value")) != bytes.fromhex(BITSTREAM_SHA256)):
        raise ValueError("generated BM1391 FIT failed independent payload/hash verification")
    (output / "uEnv.txt").write_text(
        "\n".join(f"{key}={value}" for key, value in environment.items()) + "\n", encoding="utf-8")
    manifest = {
        "schema": 1, "board_target": target, "kind": "native-sd-boot-components",
        "bitstream_sha256": BITSTREAM_SHA256,
        "dma_reservation": {"physical_base": DMA_BASE, "bytes": DMA_BYTES,
                            "device_tree_node": DMA_NODE, "no_map": True},
        "root_filesystem": {"device": "/dev/mmcblk0p2", "type": "ext2", "read_only": True},
        "inputs": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                   for name, data in held.items()},
        "files": {path.name: {"bytes": path.stat().st_size,
                              "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                  for path in sorted(output.iterdir())},
    }
    (output / "boot-components.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=TARGETS)
    parser.add_argument("--donor", required=True, type=Path, help="directory containing the pinned resident BOOT/kernel/DTB")
    parser.add_argument("--output", required=True, type=Path, help="new private directory to create")
    parser.add_argument("--mkimage", default="mkimage")
    parser.add_argument("--fdtput", default="fdtput")
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    manifest = prepare_boot(args.output, args.donor, args.target, args.mkimage, args.fdtput)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
