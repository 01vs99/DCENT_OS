import importlib.util
from pathlib import Path
import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

SOURCE = Path(__file__).with_name("build_am3_bb_nand_recovery_media.py")
spec = importlib.util.spec_from_file_location("bb_media_producer", SOURCE)
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


def arm_elf(*, dynamic=False, entry=0x8000, filesz=84):
    header = struct.pack("<16sHHIIIIIHHHHHH", b"\x7fELF\x01\x01\x01"+bytes(9), 2, 40, 1,
                         entry, 52, 0, 0x05000000, 52, 32, 1, 0, 0, 0)
    return header+struct.pack("<8I", 3 if dynamic else 1, 0, 0x8000, 0x8000, filesz, 84, 5, 4096)


def test_helper_requires_static_arm_executable_and_bounded_load_segments():
    producer.static_arm_helper(arm_elf())
    for data in (arm_elf(dynamic=True), arm_elf(entry=0x9000), arm_elf(filesz=85), arm_elf()[:-1], b"#!/bin/sh\n"):
        with pytest.raises(ValueError):
            producer.static_arm_helper(data)


def test_media_geometry_preserves_resident_loader_and_allocates_backup_capacity():
    result = producer.mbr(1024)
    assert result[:446] == bytes(446)
    assert result[510:] == b"\x55\xaa"
    first = struct.unpack("<B3sB3sII", result[446:462])
    second = struct.unpack("<B3sB3sII", result[462:478])
    assert (first[0], first[2], first[4], first[5]) == (0x80, 0x0c, 1, 262143)
    assert (second[0], second[2], second[4], second[5]) == (0, 0x83, 262144, 1835008)
    for size in (512, 1023, 8193, 1024.0, True):
        with pytest.raises(ValueError):
            producer.mbr(size)


def test_first_recovery_entry_uses_modern_safe_memory_windows_only():
    text = producer.uenv("ttyS0").decode()
    assert "bootm 0x80200000 0x85000000 0x84000000" in text
    assert "root=/dev/ram0 rw rdinit=/init" in text
    assert all(command not in text for command in ("nand erase", "nand write", "saveenv", "run update"))
    with pytest.raises(ValueError):
        producer.uenv("ttyO0")


def test_plan_retains_public_transport_identity_and_no_key_material(tmp_path, monkeypatch):
    from dcent_toolbox.core.am3_bb_recovery_keys import create_transport_keys
    directory = tmp_path/"keys"
    identity = create_transport_keys(directory)
    capsule = tmp_path/"capsule.tar.gz"
    capsule.write_bytes(b"mock capsule inputs are independently validated in coordinator tests")
    bundle = {"capsule_sha256": "a"*64, "plan": {"console": "ttyS0", "bootloader_image_sha256": "b"*64}}
    monkeypatch.setattr(producer, "inputs", lambda *_, **__: (bundle, {name: b"bounded-fixture" for name in producer.RECOVERY_FILES}, arm_elf()))
    receipt = producer.build(capsule, tmp_path, tmp_path/"card.img", operator_key=directory/"operator.pub",
                             host_key=directory/"ssh_host_ed25519_key", plan_only=True)
    assert receipt["transport"]["host_key_sha256"] == identity["host_key_sha256"]
    assert receipt["persistent_install_ready"] is False
    assert receipt["device_contact"] == "none"
    assert not (tmp_path/"card.img").exists()
    assert "private" not in repr(receipt["transport"])
