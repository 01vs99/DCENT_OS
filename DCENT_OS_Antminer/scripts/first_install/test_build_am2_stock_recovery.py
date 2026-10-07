# SPDX-License-Identifier: GPL-3.0-only
import hashlib
import importlib.util
from pathlib import Path
import struct
import tarfile
import zlib

import pytest

SCRIPT = Path(__file__).with_name("build_am2_stock_recovery.py")
SPEC = importlib.util.spec_from_file_location("i01_stock_recovery_builder", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
ARCHIVE = SCRIPT.parents[4] / ""


@pytest.mark.skipif(not ARCHIVE.is_file(), reason="held stock8 donor archive is unavailable")
def test_repack_keeps_exact_uboot_kernel_dtb_and_rehashes_modified_ramdisk():
    with tarfile.open(ARCHIVE) as tar:
        raw = tar.extractfile("firmware/uImage.itb").read()
    _, before, prefix, _, original = MODULE.transition_parts(raw)
    # This test isolates FIT composition; the builder separately runs the real
    # SquashFS tools against the held tree and canonical recovery scripts.
    replacement = original + b"fixed recovery handler fixture"
    result = MODULE.repack_fit(raw, replacement)
    outer = MODULE.parse_fdt(result, limits=MODULE.FIT_LIMITS)
    payload = outer.require_property("/images/kernel", "data")
    assert payload[:1048576] == prefix
    assert outer.require_property("/images/kernel/hash", "value") == struct.pack(">I", zlib.crc32(payload))
    inner = MODULE.parse_fdt(payload[1048576:], limits=MODULE.FIT_LIMITS)
    for name in ("kernel@1", "fdt@1"):
        assert inner.require_property("/images/" + name, "data") == before.require_property("/images/" + name, "data")
    assert inner.require_property("/images/ramdisk@1", "data") == replacement
    assert inner.require_property("/images/ramdisk@1/hash@2", "value") == hashlib.sha1(replacement).digest()
    assert len(result) < 8388608


def test_recovery_repack_refuses_unpinned_bootloader():
    with pytest.raises(ValueError, match="pinned stock8 donor"):
        MODULE.repack_fit(b"arbitrary bootloader", b"hsqs")
