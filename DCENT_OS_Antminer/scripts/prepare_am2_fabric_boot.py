#!/usr/bin/env python3
"""Prepare the held AM2 FPGA payload and a hash-checked U-Boot load sequence."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

BITSTREAM_SHA256 = "4e2f7a0bb5d65b8f7ad43bea1290c8646c5f7b49321c768418bdfdc9e04afe22"
BITSTREAM_SIZE = 2_083_859
HASH_ADDRESS = 0x01F00000


def boot_environment() -> dict[str, str]:
    digest = bytes.fromhex(BITSTREAM_SHA256)
    writes = " && ".join(
        f"mw.l 0x{HASH_ADDRESS + offset:x} 0x{int.from_bytes(digest[offset:offset + 4], 'little'):08x} 1"
        for offset in range(0, 32, 4)
    )
    return {
        # fdt get addr returns the address of the property, not an interpreted
        # integer. Compare all 32 bytes against the admitted digest in RAM.
        "dcent_fpga_hash_pin": writes,
        "bm_load_bitstream": (
            "setenv verify yes && load mmc 0 ${bm_bitstream_load_addr} am2-fabric.itb"
            " && fdt addr ${bm_bitstream_load_addr}"
            " && fdt get value dcent_hash_algo /images/system-bit/hash-1 algo"
            " && test x${dcent_hash_algo} = xsha256"
            " && fdt get size dcent_hash_size /images/system-bit/hash-1 value"
            " && itest ${dcent_hash_size} == 0x20"
            " && fdt get addr dcent_hash_addr /images/system-bit/hash-1 value"
            " && run dcent_fpga_hash_pin"
            " && cmp.b ${dcent_hash_addr} 0x1f00000 0x20"
            # imxtract performs fit_image_verify with verify=yes before copying.
            " && imxtract ${bm_bitstream_load_addr} system-bit ${bm_bitstream_addr}"
            f" && itest ${{filesize}} == 0x{BITSTREAM_SIZE:x}"
            " && fpga loadb 0 ${bm_bitstream_addr} ${filesize}"
        ),
        "bm_set_bootargs": (
            "setenv bootargs mem=228M console=ttyPS0,115200 root=/dev/mmcblk0p2"
            " rootfstype=squashfs ro rootwait earlyprintk"
            " dcent.fpga_load_completed=${dcent_fpga_load_completed}"
            f" dcent.fpga_sha256={BITSTREAM_SHA256}"
        ),
        "sd_uenvcmd": (
            "setenv dcent_fpga_load_completed 0;"
            " if run bm_load_bitstream; then setenv dcent_fpga_load_completed 1;"
            " echo Exact AM2 FPGA programmed; else echo AM2 FPGA load failed; fi;"
            " run bm_load_sd_images && run bm_set_bootargs"
            " && bootm ${bm_kernel_addr} - ${bm_devicetree_addr}"
        ),
    }


# Exact held AM2 dual-UBI geometry, independent of the selected firmware slot.
NAND_MTDPARTS = (
    "mtdparts=pl35x-nand:8m(boot),12m(boot-failover),2m(fpga1),2m(fpga2),"
    "512k(uboot_env),512k(miner_cfg),87m(recovery),57m(firmware1),"
    "57m(firmware2),30m(factory)"
)


def nand_boot_environment(firmware: int, vendor_nandboot: str) -> dict[str, str]:
    """Produce the boot tuple committed with an inactive-slot FPGA FIT.

    The caller preserves and verifies every changed/deleted environment key,
    the exact firmware/FPGA partition pair and the original NAND boot command.
    This function never reads a device or changes a boot environment. The
    commands use the held AM2 v2016.03 U-Boot ABI. The three FCLK writes are
    the exact existing cold-boot sequence in s19j-am2-139/uboot_env.txt.
    """
    if type(firmware) is not int or firmware not in (1, 2):
        raise ValueError("NAND firmware must be exact slot 1 or 2")
    if (not vendor_nandboot or len(vendor_nandboot) > 8192
            or any(c in vendor_nandboot for c in "\r\n\0")
            or "dcent_" in vendor_nandboot):
        raise ValueError("original vendor NAND boot command required; no nested transition")
    env = boot_environment()
    load = env["bm_load_bitstream"].replace(
        "load mmc 0 ${bm_bitstream_load_addr} am2-fabric.itb",
        f"nand read 0x01000000 fpga{firmware} 0x200000",
    ).replace("${bm_bitstream_load_addr}", "0x01000000").replace(
        "${bm_bitstream_addr}", "0x01800000"
    )
    previous = 3 - firmware
    mtd = 6 + firmware
    return {
        "dcent_native_slot": str(firmware),
        "dcent_vendor_nandboot": vendor_nandboot,
        "dcent_fpga_hash_pin": env["dcent_fpga_hash_pin"],
        "dcent_fpga_load": load,
        "dcent_nand_fallback": (
            f"setenv firmware {previous} && setenv upgrade_stage && setenv first_boot"
            " && saveenv && run dcent_vendor_nandboot"
        ),
        "dcent_nandboot": (
            # A prior failed kernel boot invokes the existing auto_recovery
            # before another native boot. FPGA/kernel load failure falls back
            # immediately to the preserved active vendor image.
            "run auto_recovery;"
            f" if test x${{firmware}} = x{firmware}"
            " && mw.l 0xF8000008 0x0000DF0D"
            " && mw.l 0xF8000170 0x00400400"
            " && mw.l 0xF8000004 0x0000767B"
            " && run dcent_fpga_load"
            f' && setenv bootargs "console=ttyPS0,115200 noinitrd ubi.mtd={mtd}'
            " ubi.block=0,1 root=/dev/ubiblock0_1 ro rootfstype=squashfs rootwait"
            f" {NAND_MTDPARTS} earlyprintk dcent.fpga_load_completed=1"
            f' dcent.fpga_sha256={BITSTREAM_SHA256}"'
            f" && ubi part firmware{firmware} && ubi read 0x02000000 kernel;"
            " then bootm 0x02000000; fi; run dcent_nand_fallback"
        ),
        "nandboot": (
            f"if test x${{firmware}} = x{firmware}; then run dcent_nandboot;"
            " else run dcent_vendor_nandboot; fi"
        ),
    }


def prepare(bitstream_gzip: Path, output_dir: Path, uenv: Path, mkimage: str) -> Path:
    # Compression and mkimage are host packaging dependencies. The installed
    # native OTA consumer imports only the pure boot-command producers.
    import gzip
    import subprocess

    with gzip.open(bitstream_gzip, "rb") as source:
        bitstream = source.read(BITSTREAM_SIZE + 1)
    if len(bitstream) != BITSTREAM_SIZE or hashlib.sha256(bitstream).hexdigest() != BITSTREAM_SHA256:
        raise ValueError("AM2 FPGA payload does not match the admitted uncompressed donor")
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "am2-system.bit").write_bytes(bitstream)
    its = output_dir / "am2-fabric.its"
    its.write_text(
        '/dts-v1/;\n/ { description = "DCENT AM2 exact FPGA"; #address-cells = <1>;\n'
        ' images { system-bit { description = "Braiins AM2 S17 fabric";\n'
        ' data = /incbin/("am2-system.bit"); type = "firmware"; arch = "arm";\n'
        ' compression = "none"; hash-1 { algo = "sha256"; }; }; }; };\n',
        encoding="utf-8",
    )
    fit = output_dir / "am2-fabric.itb"
    subprocess.run([mkimage, "-f", its.name, fit.name], cwd=output_dir, check=True)
    env = boot_environment()
    original = uenv.read_text(encoding="utf-8").splitlines()
    for name in ("bm_load_bitstream", "bm_set_bootargs", "sd_uenvcmd"):
        if sum(line.startswith(name + "=") for line in original) != 1:
            raise ValueError(f"expected exactly one {name} in the AM2 boot environment")
    # Replace named entries and append the new digest materialization command.
    updated = []
    for line in original:
        name = line.split("=", 1)[0]
        updated.append(name + "=" + env.pop(name) if name in env else line)
    updated.extend(name + "=" + value for name, value in env.items())
    uenv.write_text("\n".join(updated) + "\n", encoding="utf-8", newline="\n")
    return fit


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitstream-gzip", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--uenv", type=Path, required=True)
    parser.add_argument("--mkimage", default="mkimage")
    args = parser.parse_args()
    prepare(args.bitstream_gzip, args.output_dir, args.uenv, args.mkimage)


if __name__ == "__main__":
    main()
