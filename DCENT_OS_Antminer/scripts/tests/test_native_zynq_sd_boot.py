"""Boot-only composition from actual held donors and an actual SquashFS fixture."""

import hashlib
import os
from pathlib import Path
import struct
import sys
import zlib

import pytest

ROOT = Path(__file__).resolve().parents[4]
sys.path[:0] = [
    str(ROOT / "DCENT_OS_Antminer/scripts"),
    str(ROOT / "projects/dcent-toolbox/src"),
]
from native_zynq_sd import boot_assets as boot  # noqa: E402
from dcent_toolbox.core.uboot_legacy_image import parse_uboot_legacy_image  # noqa: E402
from dcent_toolbox.core.squashfs_files import SquashfsFiles  # noqa: E402


@pytest.fixture(scope="module")
def s9_inputs():
    names = {
        "BOOT.BIN": "sd_recovery_BOOT.BIN",
        "devicetree.dtb": "s9_devicetree.dtb",
        "kernel.bin": "kernel.bin",
        "mtd2_fpga1.bin": "mtd2_fpga1.bin",
    }
    return {
        name: (ROOT / "" / path).read_bytes()
        for name, path in names.items()
    }


@pytest.fixture(scope="module")
def am2_inputs():
    directory = Path("/root/dcent-seven-boot-source-v2/am2-boot")
    if os.name != "posix" or not directory.is_dir():
        pytest.skip("requires actual independently joined AM2 donor component fixture")
    return {name: (directory / name).read_bytes() for name in boot.AM2_BOOT_PINS}


@pytest.mark.parametrize("target", ("am1-s9i", "am1-s9j"))
def test_actual_s9_legacy_kernel_and_raw_fpga(target, s9_inputs):
    files = boot.s9_static_assets(target, s9_inputs)
    kernel = parse_uboot_legacy_image(files["uImage"])
    assert kernel.payload == s9_inputs["kernel.bin"]
    assert (kernel.architecture_id, kernel.image_type_id, kernel.compression_id) == (
        2,
        2,
        0,
    )
    assert kernel.load_address == kernel.entry_address == 0x8000
    assert (
        len(files["system.bit"]),
        hashlib.sha256(files["system.bit"]).hexdigest(),
    ) == boot.S9_FPGA
    env = dict(line.split("=", 1) for line in files["uEnv.txt"].decode().splitlines())
    assert (
        env["bootargs"]
        == "console=ttyPS0,115200 ramdisk_size=67108864 root=/dev/ram0 rootfstype=squashfs ro earlyprintk"
    )
    assert env["uenvcmd"] == env["sd_uenvcmd"]
    assert env["uenvcmd"].endswith("bootm 0x2000000 0x4000000 0x3000000")
    assert "unzip" not in env["fpgacmd"] and "fpga load " in env["fpgacmd"]


@pytest.mark.parametrize("name", sorted(boot.S9_INPUTS))
def test_actual_s9_changed_component_refused(name, s9_inputs):
    changed = dict(s9_inputs)
    raw = bytearray(changed[name])
    raw[len(raw) // 2] ^= 1
    changed[name] = bytes(raw)
    with pytest.raises(ValueError, match="exact held boot"):
        boot.s9_static_assets("am1-s9i", changed)


@pytest.mark.parametrize(
    "target", ("am2-s17p", "am2-s17plus", "am2-t17", "am2-t17plus", "am2-s19pro")
)
def test_actual_am2_held_boot_components(target, am2_inputs):
    assert boot.am2_boot_assets(target, am2_inputs) == am2_inputs


@pytest.mark.parametrize("name", sorted(boot.AM2_BOOT_PINS))
def test_actual_am2_changed_component_refused(name, am2_inputs):
    changed = dict(am2_inputs)
    changed[name] = changed[name][:-1] + bytes([changed[name][-1] ^ 1])
    with pytest.raises(ValueError, match="exact held boot"):
        boot.am2_boot_assets("am2-s17p", changed)


@pytest.mark.parametrize("target", ("am1-s9", "am1-s9i\n", "am2-s17pro", "am2-s19jpro"))
def test_neighbour_routes_refused(target, s9_inputs):
    with pytest.raises(ValueError):
        boot.s9_static_assets(target, s9_inputs)
    with pytest.raises(ValueError):
        boot.am2_boot_assets(target, {})


@pytest.mark.parametrize("extra", (False, True))
def test_missing_or_extra_boot_file_refused(extra, s9_inputs, am2_inputs):
    for compose, target, inputs in (
        (boot.s9_static_assets, "am1-s9i", s9_inputs),
        (boot.am2_boot_assets, "am2-s17p", am2_inputs),
    ):
        changed = dict(inputs)
        if extra:
            changed["retained.conf"] = b"do not carry retained material"
        else:
            changed.pop(next(iter(changed)))
        with pytest.raises(ValueError):
            compose(target, changed)


def test_actual_squashfs_ramdisk_single_gzip_and_complete_inventory():
    raw = (
        ROOT / "DCENT_OS_Antminer/output/i02-seven-squashfs-fixtures-v1/gzip.squashfs"
    ).read_bytes()
    expected = SquashfsFiles(raw).inventory()
    wrapped = boot.s9_ramdisk(raw)
    parsed = parse_uboot_legacy_image(wrapped)
    assert (parsed.architecture_id, parsed.image_type_id, parsed.compression_id) == (
        2,
        3,
        1,
    )
    assert parsed.load_address == parsed.entry_address == 0
    decoder = zlib.decompressobj(31)
    decoded = decoder.decompress(parsed.payload, len(raw) + 1)
    assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
    assert decoded == raw and SquashfsFiles(decoded).inventory() == expected
    assert len(expected) == 508
    assert boot.s9_ramdisk(raw) == wrapped


@pytest.mark.parametrize(
    "mutation", ("empty", "truncated", "wrong_magic", "xz", "oversized", "mutable")
)
def test_ramdisk_obvious_wrong_root_refused(mutation):
    raw = bytearray(
        (
            ROOT
            / "DCENT_OS_Antminer/output/i02-seven-squashfs-fixtures-v1/gzip.squashfs"
        ).read_bytes()
    )
    if mutation == "empty":
        raw = b""
    elif mutation == "truncated":
        raw = raw[:95]
    elif mutation == "wrong_magic":
        raw[:4] = b"sqsh"
    elif mutation == "xz":
        struct.pack_into("<H", raw, 20, 4)
    elif mutation == "oversized":
        raw.extend(b"\0" * (48 * 1024 * 1024 - len(raw)))
    candidate = raw if mutation == "mutable" else bytes(raw)
    with pytest.raises(ValueError):
        boot.s9_ramdisk(candidate)
