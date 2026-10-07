#!/usr/bin/env python3
"""Apply current producer hooks only to a disposable merged Buildroot config."""
from __future__ import annotations

import argparse
from pathlib import Path
import re

from release_producer import get_producer


def configure(text: str, producer: str) -> str:
    row = get_producer(producer)
    if row.artifact_kind != "native-sd-image":
        return text
    hooks = re.findall(r'^BR2_ROOTFS_POST_BUILD_SCRIPT="([^"\r\n]*)"$', text, re.M)
    if not hooks or not hooks[-1].strip():
        raise ValueError("native release requires its existing base post-build signing hook")
    native = "$(BR2_EXTERNAL_DCENTOS_PATH)/../scripts/release_native_sd_post_build.sh"
    post_image = "$(BR2_EXTERNAL_DCENTOS_PATH)/../scripts/release_native_sd_post_image.sh"
    if native in hooks[-1].split() or "# Current native producer:" in text:
        raise ValueError("native producer hooks already configured")
    if row.board_target in ("am2-t17e", "am2-s17e"):
        # Its own composer consumes the current signed SquashFS carrier and
        # builds the exact selected BM1396 ext2 layout. Never route it through native7.
        return (text.rstrip() + "\n# Current native producer: " + row.producer + "\n"
                + 'BR2_ROOTFS_POST_IMAGE_SCRIPT="$(BR2_EXTERNAL_DCENTOS_PATH)/../scripts/release_bm1396_post_image.sh"\n')
    return (text.rstrip() + "\n# Current native producer: " + row.producer + "\n"
            + 'BR2_ROOTFS_POST_BUILD_SCRIPT="' + hooks[-1] + " " + native + '"\n'
            + 'BR2_ROOTFS_POST_IMAGE_SCRIPT="' + post_image + '"\n')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer", required=True)
    parser.add_argument("--defconfig", type=Path, required=True)
    args = parser.parse_args()
    if args.defconfig.is_symlink() or not args.defconfig.is_file():
        parser.exit(2, "ERROR: generated defconfig must be a regular file\n")
    try:
        args.defconfig.write_text(configure(args.defconfig.read_text(encoding="utf-8"), args.producer),
                                 encoding="utf-8", newline="\n")
    except ValueError as error:
        parser.exit(2, f"ERROR: {error}\n")


if __name__ == "__main__":
    main()
