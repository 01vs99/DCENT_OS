#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare exact recovery-only signing bytes or attach an approved detached signature."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/"dcent-toolbox/src"))
from dcent_toolbox.core.am3_bb_recovery_bundle import (  # noqa: E402
    HELPER_MEMBER, RECOVERY_FILES, archive_bytes, load_bundle, manifest_bytes, read_bundle, signing_request,
)
from dcent_toolbox.core.am3_bb_nand_transaction import _create  # noqa: E402


def prepare(recovery_root: Path, helper: Path, output: Path, bootloader: str) -> dict:
    if output.exists() or output.is_symlink() or output.parent.resolve() != output.parent.absolute():
        raise ValueError("new direct signing-preparation directory required")
    files = {}
    for name, path in [(name, recovery_root/name) for name in RECOVERY_FILES]+[(HELPER_MEMBER, helper)]:
        if path.is_symlink() or path.resolve() != path.absolute() or not path.is_file() or not 0 < path.stat().st_size <= 64*1024*1024:
            raise ValueError("bounded direct recovery input required")
        files[name] = path.read_bytes()
    manifest = manifest_bytes(files, bootloader)
    request = signing_request(manifest)
    output.mkdir(mode=0o700)
    _create(output/"manifest.json", manifest)
    _create(output/"signing-request.json", (json.dumps(request, indent=2)+"\n").encode())
    _create(output/"recovery.unsigned.tar.gz", archive_bytes(dict(files, **{"manifest.json": manifest})))
    return request


def attach(unsigned: Path, signature: Path, output: Path) -> dict:
    load_bundle(unsigned, signing_preparation=True)
    files, _digest = read_bundle(unsigned)
    if "manifest.sig" in files:
        raise ValueError("unsigned signing preparation required")
    if signature.is_symlink() or not signature.is_file() or signature.stat().st_size != 64:
        raise ValueError("64-byte detached Ed25519 signature required")
    files["manifest.sig"] = signature.read_bytes()
    # Authenticate before publishing the completed artifact.
    from dcent_toolbox.core.install_package import verify_detached_release_signature
    error = verify_detached_release_signature(manifest_bytes=files["manifest.json"], signature=files["manifest.sig"], embedded_pubkey=None)
    if error:
        raise ValueError(error)
    _create(output, archive_bytes(files))
    result = load_bundle(output)
    return {key: value for key, value in result.items() if key != "files"}


def main():
    parser = argparse.ArgumentParser(description=__doc__, epilog="Support DCENT development: https://d-central.tech/fund/")
    sub = parser.add_subparsers(dest="action", required=True)
    first = sub.add_parser("prepare")
    first.add_argument("--recovery-root", type=Path, required=True)
    first.add_argument("--helper", type=Path, required=True)
    first.add_argument("--output", type=Path, required=True)
    first.add_argument("--bootloader-image-sha256", required=True)
    final = sub.add_parser("attach-signature")
    final.add_argument("--unsigned", type=Path, required=True)
    final.add_argument("--signature", type=Path, required=True)
    final.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "prepare":
        result = prepare(args.recovery_root, args.helper, args.output, args.bootloader_image_sha256)
    else:
        result = attach(args.unsigned, args.signature, args.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
