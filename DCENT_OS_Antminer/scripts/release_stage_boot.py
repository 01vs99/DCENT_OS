#!/usr/bin/env python3
"""Stage only the selected producer's already-snapshotted native boot inputs."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

from binary_build_receipt import assert_no_symlink_components
from release_producer import get_producer
from source_closure import AM1_S9_NATIVE_INPUTS, AM2_S17_DONOR_RELATIVE_PATH, BM1391_NATIVE_INPUTS, BM1396_NATIVE_INPUTS, BM1396_S17E_NATIVE_INPUTS, C43_NATIVE_INPUTS


def stage(producer: str, snapshot_files: Path, output: Path) -> None:
    row = get_producer(producer)
    if row.artifact_kind != "native-sd-image":
        raise ValueError("native media producer required for boot input staging")
    if output.exists() or output.is_symlink():
        raise ValueError("native boot input destination must be absent")
    assert_no_symlink_components(snapshot_files, "verified snapshot files")
    if row.runtime_root == "partition2-squashfs":
        donor = snapshot_files / AM2_S17_DONOR_RELATIVE_PATH
        assert_no_symlink_components(donor, "native AM2 donor snapshot")
        # The AM2 fabric FIT pin is mkimage-build-specific: a bare PATH lookup
        # in the capsule container resolved apt u-boot-tools and emitted bytes
        # that differ from the hardware-validated pin (drop1-20260919-4f5h9mgl).
        # Fail closed instead of ever falling back to PATH.
        mkimage = os.environ.get("DCENT_MKIMAGE", "").strip()
        if not mkimage:
            raise ValueError(
                "DCENT_MKIMAGE (toolchain-cache/u-boot-2026.04-mkimage/mkimage, "
                "mounted read-only by the producer from DCENT_TOOLCHAIN_LOCAL_DIR; "
                "provision with scripts/provision_build_inputs.sh) is required "
                "for native AM2 boot reproduction"
            )
        subprocess.run([sys.executable, str(Path(__file__).with_name("prepare_release_am2_boot.py")),
                        "--donor", str(donor), "--output", str(output),
                        "--mkimage", mkimage], check=True)
        return
    if row.board_target in ("am1-s9i", "am1-s9j"):
        inputs = zip(AM1_S9_NATIVE_INPUTS, ("BOOT.BIN", "devicetree.dtb", "kernel.bin", "mtd2_fpga1.bin"))
    elif row.board_target in ("am1-s9se", "am1-s9k"):
        inputs = ((name, Path(name).name) for name in C43_NATIVE_INPUTS)
    elif row.board_target in ("am1-s15", "am1-t15"):
        inputs = ((name, Path(name).name) for name in BM1391_NATIVE_INPUTS)
    elif row.board_target == "am2-t17e":
        inputs = ((name, Path(name).name) for name in BM1396_NATIVE_INPUTS)
    elif row.board_target == "am2-s17e":
        inputs = ((name, Path(name).name) for name in BM1396_S17E_NATIVE_INPUTS)
    else:
        raise ValueError("native producer has no exact boot staging policy")
    output.mkdir()
    for relative, name in inputs:
        source = assert_no_symlink_components(snapshot_files / relative, "native boot snapshot input")
        shutil.copyfile(source, output / name)
    # The media composer independently enforces the component size/hash pins.


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer", required=True)
    parser.add_argument("--snapshot-files", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    stage(args.producer, args.snapshot_files, args.output)


if __name__ == "__main__":
    main()
