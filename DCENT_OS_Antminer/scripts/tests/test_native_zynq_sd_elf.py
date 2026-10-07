"""Actual retained ARM ELF comparisons and immutable image-path fault cases."""

import hashlib
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[4]
sys.path[:0] = [
    str(ROOT / "DCENT_OS_Antminer/scripts"),
    str(ROOT / "projects/dcent-toolbox/src"),
]
from dcent_toolbox.core.arm_elf_dependencies import arm_elf_dependencies  # noqa: E402
from dcent_toolbox.core.squashfs_files import SquashfsFiles  # noqa: E402
from native_zynq_sd.inspect_base import resolve  # noqa: E402


@pytest.fixture(scope="module")
def actual_root():
    if os.name != "posix":
        pytest.skip("actual retained Linux root component fixture")
    raw = Path(
        "/root/dcent-beta-am2-20260907/buildroot-output/images/rootfs.squashfs"
    ).read_bytes()
    assert (
        len(raw) == 21491712
        and hashlib.sha256(raw).hexdigest()
        == "a1e75595367eab046a194ad241890ef3b2a6e2bada53029981f63f8dbd398aed"
    )
    fs = SquashfsFiles(raw)
    fs.inventory()
    return fs


@pytest.mark.parametrize(
    "name",
    (
        "bin/busybox",
        "usr/sbin/dropbear",
        "usr/bin/python3.13",
        "usr/lib/libreadline.so.8.3",
        "lib/libc-2.25.so",
        "lib/ld-2.25.so",
    ),
)
def test_actual_loader_requirements_match_gnu_readelf(actual_root, tmp_path, name):
    # Resolve fixture versioned names from its actual image inventory, not host
    # libraries; no target executable is run by this test.
    inventory = actual_root.inventory()
    if name.startswith("usr/bin/python"):
        name = resolve(inventory, "usr/bin/python3")
    elif name.startswith("lib/libc-"):
        name = resolve(inventory, "lib/libc.so.6")
    elif name.startswith("lib/ld-"):
        name = resolve(inventory, "lib/ld-linux-armhf.so.3")
    elif name == "usr/sbin/dropbear":
        name = resolve(inventory, name)
    raw = actual_root.read(name)
    parsed = arm_elf_dependencies(raw)
    output = tmp_path / "actual-arm.elf"
    output.write_bytes(raw)
    result = subprocess.run(
        ["/usr/bin/readelf", "-W", "-l", "-d", str(output)],
        capture_output=True,
        check=True,
        env={**os.environ, "LC_ALL": "C"},
    )
    text = result.stdout.decode()
    assert re.findall(r"\(NEEDED\).*?\[([^]]+)\]", text) == parsed["needed"]
    assert re.findall(r"Requesting program interpreter: ([^]]+)\]", text) == (
        [parsed["interpreter"]] if parsed["interpreter"] else []
    )
    assert re.findall(r"\(SONAME\).*?\[([^]]+)\]", text) == (
        [parsed["soname"]] if parsed["soname"] else []
    )
    assert [
        (kind.lower(), value)
        for kind, value in re.findall(r"\((RPATH|RUNPATH)\).*?\[([^]]*)\]", text)
    ] == parsed["search_paths"]
    assert output.read_bytes() == raw


@pytest.mark.parametrize(
    "mutation",
    (
        "short",
        "mutable",
        "aarch64",
        "big_endian",
        "header_size",
        "ph_count",
        "ph_offset",
        "segment_extent",
        "load_memory",
        "dynamic_unterminated",
    ),
)
def test_actual_elf_malformed_loader_fields_refuse(actual_root, mutation):
    raw = bytearray(actual_root.read("bin/busybox"))
    phoff = struct.unpack_from("<I", raw, 28)[0]
    count = struct.unpack_from("<H", raw, 44)[0]
    headers = [
        (index, struct.unpack_from("<8I", raw, phoff + index * 32))
        for index in range(count)
    ]
    if mutation == "short":
        raw = raw[:51]
    elif mutation == "aarch64":
        struct.pack_into("<H", raw, 18, 183)
    elif mutation == "big_endian":
        raw[5] = 2
    elif mutation == "header_size":
        struct.pack_into("<H", raw, 40, 64)
    elif mutation == "ph_count":
        struct.pack_into("<H", raw, 44, 257)
    elif mutation == "ph_offset":
        struct.pack_into("<I", raw, 28, len(raw))
    elif mutation == "segment_extent":
        struct.pack_into("<I", raw, phoff + 16, len(raw) + 1)
    elif mutation == "load_memory":
        index, _header = next(row for row in headers if row[1][0] == 1)
        struct.pack_into("<I", raw, phoff + index * 32 + 20, 0)
    elif mutation == "dynamic_unterminated":
        _index, header = next(row for row in headers if row[1][0] == 2)
        for offset in range(header[1], header[1] + header[4], 8):
            if struct.unpack_from("<I", raw, offset)[0] == 0:
                struct.pack_into("<I", raw, offset, 1)
    candidate = raw if mutation == "mutable" else bytes(raw)
    with pytest.raises(ValueError):
        arm_elf_dependencies(candidate)


@pytest.mark.parametrize("target", ("../../outside", "/missing", "cycle", "file/child"))
def test_image_dependency_cannot_escape_loop_or_traverse_file(target):
    inventory = {
        "lib": {"kind": 1},
        "lib/file": {"kind": 2},
        "lib/link": {"kind": 3, "target_hex": target.encode().hex()},
        "lib/cycle": {"kind": 3, "target_hex": b"link".hex()},
    }
    with pytest.raises(ValueError):
        resolve(inventory, "/lib/link")


def test_image_dependency_absolute_and_relative_links_remain_in_image():
    inventory = {
        "usr": {"kind": 1},
        "usr/lib": {"kind": 1},
        "usr/lib/lib.so": {"kind": 2},
        "lib": {"kind": 3, "target_hex": b"/usr/lib".hex()},
        "loader": {"kind": 3, "target_hex": b"usr/lib/lib.so".hex()},
    }
    assert resolve(inventory, "/lib/lib.so") == "usr/lib/lib.so"
    assert resolve(inventory, "/loader") == "usr/lib/lib.so"
