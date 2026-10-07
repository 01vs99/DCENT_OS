"""Exact local image contracts for two AM1 and five AM2 native SD routes.

These are new image layouts, not authority for existing intermediate cards,
NAND layouts, or physical boot qualification. The kernel/FPGA input sets remain
separate; the shared data size does not transfer a board or writer identity.
"""

from __future__ import annotations

import uuid

SECTOR = 512
MIB = 1024 * 1024
DATA_BYTES = 64 * MIB
BOOT_BYTES = 96 * MIB
ROOT_BYTES = 48 * MIB
NATIVE_CHECKPOINT = 28
NATIVE = {
    "dcentrald": (
        26650304,
        "5c94f411da636c92f8cbbac3a6069644e9baab862e98d29b85a2c0c2e0c82cec",
    ),
    "dcentos-discovery": (
        1011180,
        "955367c0f9d5bc3921c22e0f34f28936d2b781d320a33c8c824d47c5988e259c",
    ),
    "dcentos-init": (
        469652,
        "f855560ea150d6de26e7d588d15c9ca5815982f1d5cb8aa35dc32122e82b4e92",
    ),
}
TARGETS = {
    "am1-s9i": ("Antminer S9i", "am1", 63, "s9i"),
    "am1-s9j": ("Antminer S9j", "am1", 63, "s9j"),
    "am2-s17p": ("Antminer S17 / S17 Pro", "am2", 48, "s17pro"),
    "am2-s17plus": ("Antminer S17+", "am2", 65, "s17plus"),
    "am2-t17": ("Antminer T17", "am2", 30, "t17"),
    "am2-t17plus": ("Antminer T17+", "am2", 44, "t17plus"),
    "am2-s19pro": ("Antminer S19 Pro", "am2", 114, "s19pro"),
}


def profile(target: str) -> dict:
    if target not in TARGETS:
        raise ValueError("exact seven-route native SD target required")
    label, family, chips, model = TARGETS[target]
    boot = (MIB // SECTOR, BOOT_BYTES // SECTOR, 0x0C)
    # AM1 retains the legacy gzip SquashFS ramdisk. AM2 keeps raw SquashFS
    # partition 2. Data is a distinct partition in both layouts.
    parts = [boot]
    if family == "am2":
        parts.append(((MIB + BOOT_BYTES) // SECTOR, ROOT_BYTES // SECTOR, 0x83))
    data_start = MIB + BOOT_BYTES + (ROOT_BYTES if family == "am2" else 0)
    parts.append((data_start // SECTOR, DATA_BYTES // SECTOR, 0x83))
    return {
        "schema": "dcentos.native_zynq_sd_profile.v1",
        "board_target": target,
        "label": label,
        "board_family": family,
        "platform": "zynq-am1" if family == "am1" else "zynq-bm3-am2",
        "model": model,
        "chips_per_chain": chips,
        "chain_count": 3,
        "root_source": "/dev/ram0" if family == "am1" else "/dev/mmcblk0p2",
        "root_fstype": "squashfs",
        "data_device": "/dev/mmcblk0p2" if family == "am1" else "/dev/mmcblk0p3",
        "data_uuid": str(
            uuid.uuid5(
                uuid.NAMESPACE_URL, "https://d-cent.local/native-sd/v1/" + target
            )
        ),
        "data_bytes": DATA_BYTES,
        "data_label": "DCENT_SD_DATA",
        "partitions": parts,
        "image_bytes": data_start + DATA_BYTES,
        "native_checkpoint": NATIVE_CHECKPOINT,
        "physical_qualification": "pending",
        "nand_writes": False,
    }
