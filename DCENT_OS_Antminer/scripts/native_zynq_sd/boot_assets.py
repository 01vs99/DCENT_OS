"""Pure source-pinned boot composition for native AM1/AM2 SD images.

These functions neither read files nor execute boot commands. AM1 retains its
2014.01 legacy bootm K/R/D flow; AM2 retains the separately source-bound 2016.03
SPL/U-Boot/FIT-fabric tuple. Complete root/data and image review is separate.
"""

from __future__ import annotations

import gzip
import hashlib
import struct
import zlib

from .profiles import profile

EPOCH = 1700000000
S9_INPUTS = {
    "BOOT.BIN": (
        2559264,
        "4004015bba6ff3d64c7626d3be2e24bf4486fe4bad1261be7b880ca6ef693e1c",
    ),
    "devicetree.dtb": (
        16384,
        "c500204acdf9bc53b0062276f9bc25b5ccd6d568d032419979af89426a11fea7",
    ),
    "kernel.bin": (
        2825904,
        "e3d6cb69890118e75b34cf069ee9fd32d0671e192535f6cf83775e69935ea35c",
    ),
    "mtd2_fpga1.bin": (
        2097152,
        "496a1e8a505ee929c7a5fdb3260d83c73396387deaf2ebb919faa02ee0d49a01",
    ),
}
S9_FPGA = (2083858, "980532de5eb666508dafb111466f30169a70b8b6ea662bdda61e17dbd55a4421")
# Exact ten boot files observed by seven-fat32-probe-v1.json. They remain a
# component input, never approval of the older intermediate card's root.
AM2_BOOT_PINS = {
    "am2-fabric.itb": (
        2084351,
        "21268da09d64ea193d492eef216cc81fb4de746bb13823918356c70f370afe98",
    ),
    "boot.bin": (
        78039,
        "60a60746f4c92d5493bfb6af36c02e3ac9574c46d5718bcb70106563b8e6c654",
    ),
    "u-boot.img": (
        572780,
        "af8a04e7b108f545eb029f97fb810296e05257425dae93657e5c9d6fa5868f6d",
    ),
    "system.bit.gz": (
        259234,
        "7102a9f204a4be3edfbf2096f68e6a9b24b1a2845c8257e29563ce459a597c8b",
    ),
    "system_bm.bit.gz": (
        365657,
        "e2454a146c196b15bd59b59a1321a289109afefc80f7e7e587ef0e6c96ff5897",
    ),
    "miner.btm": (
        2048,
        "a5443fbfebd548332e31e23576bdd62e5c6607724ed344d9b36d76a0e0a017ce",
    ),
    "miner.btm.sig": (
        256,
        "4e81c666b82a0096fff729b32e0bb93a47efc3d21cbc3bf6e3162ecd313d0533",
    ),
    "uImage": (
        2827808,
        "1e33ef5177c93e62d50c965dd69552906c81ccc99e8a6e2ef489e59093d28b60",
    ),
    "devicetree.dtb": (
        16454,
        "51f4d224271b0e2bd4c1bf4f62f88373f50caaa5f184571817f32fa30841ff3b",
    ),
    "uEnv.txt": (
        4375,
        "c88bd40cdb0bab27f68f927aa9a2a2e51c2c749321f1d98b15ed94ebd053f335",
    ),
}


def _check(raw: bytes, expected: tuple[int, str], name: str) -> None:
    if (
        type(raw) is not bytes
        or (len(raw), hashlib.sha256(raw).hexdigest()) != expected
    ):
        raise ValueError("exact held boot component required: " + name)


def _legacy(
    payload: bytes, kind: int, compression: int, load: int, name: bytes
) -> bytes:
    header = bytearray(
        struct.pack(
            ">7I4B32s",
            0x27051956,
            0,
            EPOCH,
            len(payload),
            load,
            load,
            zlib.crc32(payload),
            5,
            2,
            kind,
            compression,
            name,
        )
    )
    struct.pack_into(">I", header, 4, zlib.crc32(header))
    return bytes(header) + payload


def s9_static_assets(target: str, inputs: dict[str, bytes]) -> dict[str, bytes]:
    """Return five exact S9 legacy assets; the current root ramdisk is separate."""
    if profile(target)["board_family"] != "am1" or set(inputs) != set(S9_INPUTS):
        raise ValueError("exact S9i/S9j boot input set required")
    for name, expected in S9_INPUTS.items():
        _check(inputs[name], expected, name)
    decoder = zlib.decompressobj(31)
    bitstream = decoder.decompress(inputs["mtd2_fpga1.bin"], S9_FPGA[0] + 1)
    if (
        not decoder.eof
        or decoder.unconsumed_tail
        or not decoder.unused_data
        or decoder.unused_data.strip(b"\xff")
    ):
        raise ValueError("exact single S9 gzip member with NAND padding required")
    _check(bitstream, S9_FPGA, "raw system.bit")
    bit_size = f"0x{len(bitstream):X}"
    sequence = (
        "dcache off && run fpgacmd && fatload mmc 0 0x2000000 uImage"
        " && fatload mmc 0 0x3000000 devicetree.dtb"
        " && fatload mmc 0 0x4000000 uramdisk.image.gz"
        " && bootm 0x2000000 0x4000000 0x3000000"
    )
    environment = (
        "bootargs=console=ttyPS0,115200 ramdisk_size=67108864 root=/dev/ram0 rootfstype=squashfs ro earlyprintk\n"
        f"fpgacmd=fatload mmc 0 0x2000000 system.bit {bit_size} && fpga load 0 0x2000000 {bit_size}\n"
        f"uenvcmd={sequence}\nsd_uenvcmd={sequence}\n"
    )
    return {
        "BOOT.BIN": inputs["BOOT.BIN"],
        "devicetree.dtb": inputs["devicetree.dtb"],
        "system.bit": bitstream,
        "uImage": _legacy(inputs["kernel.bin"], 2, 0, 0x8000, b"DCENT_OS Linux 4.4.92"),
        "uEnv.txt": environment.encode("ascii"),
    }


def s9_ramdisk(root: bytes) -> bytes:
    """Wrap a separately qualified gzip-SquashFS root in exactly one gzip layer."""
    if (
        type(root) is not bytes
        or not 96 <= len(root) < 48 * 1024 * 1024
        or root[:4] != b"hsqs"
    ):
        raise ValueError("bounded raw SquashFS root required")
    # This is header preflight only. The caller must independently inspect the
    # entire root and join its approved source/runtime inventory before use.
    if struct.unpack_from("<H", root, 20)[0] != 1:
        raise ValueError("AM1 kernel requires the selected gzip SquashFS format")
    payload = gzip.compress(root, compresslevel=9, mtime=0)
    # Python versions differ in gzip's informational OS byte; pin portable output.
    payload = payload[:9] + b"\xff" + payload[10:]
    if len(payload) + 64 > 48 * 1024 * 1024:
        raise ValueError("AM1 ramdisk exceeds its checked FAT/RAM input bound")
    return _legacy(payload, 3, 1, 0, b"DCENT_OS rootfs")


def am2_boot_assets(target: str, inputs: dict[str, bytes]) -> dict[str, bytes]:
    """Admit exact retained AM2 boot bytes without promoting its older root."""
    if profile(target)["board_family"] != "am2" or set(inputs) != set(AM2_BOOT_PINS):
        raise ValueError("exact five-route AM2 boot input set required")
    return _checked_am2_inputs(inputs)


def _checked_am2_inputs(inputs: dict[str, bytes]) -> dict[str, bytes]:
    if set(inputs) != set(AM2_BOOT_PINS):
        raise ValueError("exact AM2 boot input set required")
    for name, expected in AM2_BOOT_PINS.items():
        _check(inputs[name], expected, name)
    return dict(inputs)
