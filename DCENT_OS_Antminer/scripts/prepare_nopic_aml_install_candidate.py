#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only
"""Compact a retained exact-target NoPIC private image into a local host artifact."""
from __future__ import annotations

import argparse
import gzip
import io
import json
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "projects/dcent-toolbox/src"))
from dcent_toolbox.core import nopic_aml_candidate as reader


def compressed_kernel(raw):
    # GzipFile writes the stable OS=255 header on Python 3.9+; gzip.compress's
    # mtime=0 fast path instead inherited different host OS bytes in 3.11/3.12.
    stream = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=stream, compresslevel=9, mtime=0) as compressor:
        compressor.write(raw)
    return stream.getvalue()


def compose(source_raw, target):
    reader.require(target in reader.PROFILES, "exact NoPIC target required")
    reader.require(reader.pin(source_raw) == reader.PROFILES[target]["source_archive"], "retained source archive pin differs")
    source = {}
    prefix = target + "-private-beta/"
    with tarfile.open(fileobj=io.BytesIO(source_raw), mode="r:") as archive:
        for item in archive:
            reader.require(item.name.startswith(prefix) and item.isfile() and not item.pax_headers,
                           "source member contract differs")
            name = item.name[len(prefix):]
            reader.require(name in reader.SOURCE_MEMBERS and name not in source, "source member set differs")
            source[name] = archive.extractfile(item).read()
    reader.require(set(source) == reader.SOURCE_MEMBERS, "incomplete source")
    reader.require(source["uImage_rootfs.bin"][64:] == source["rootfs.cpio.gz"], "source rootfs duplication differs")
    blobs = {"SOURCE_PRIVATE_BETA.json": source["PRIVATE_BETA.json"], "SOURCE_SHA256SUMS": source["SHA256SUMS"],
             "payloads/kernel.gz": compressed_kernel(source["kernel"]),
             "payloads/devicetree.dtb": source["devicetree.dtb"], "payloads/fw-info": source["fw-info"],
             "payloads/uImage_rootfs.bin": source["uImage_rootfs.bin"]}
    blobs.update({"receipts/" + name: source["evidence/" + name] for name in reader.RECEIPTS})
    manifest = {"schema": reader.SCHEMA, "board_target": target, "platform": reader.PROFILES[target]["platform"],
                "source_archive": reader.pin(source_raw), "members": {name: reader.pin(body) for name, body in blobs.items()},
                "boundaries": reader.BOUNDARIES, "format": reader.FORMAT}
    blobs["CANDIDATE.json"] = reader.canonical(manifest)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:", format=tarfile.USTAR_FORMAT) as archive:
        for name, body in sorted(blobs.items()):
            item = tarfile.TarInfo(reader.PREFIX + name)
            item.size, item.mode = len(body), 0o644
            archive.addfile(item, io.BytesIO(body))
    raw = stream.getvalue()
    report = reader.inspect_bytes(raw, expected_target=target)
    return raw, report


def prepare(source, output, target):
    source_raw = reader.regular_bytes(source, reader.MAX_SOURCE)
    raw, report = compose(source_raw, target)
    reader._write_new(output, raw)
    reader.require(reader.regular_bytes(output) == raw, "candidate complete readback differs")
    reader._sync_directory(Path(output).absolute().parent)
    reader.require(reader.regular_bytes(source, reader.MAX_SOURCE) == source_raw, "source changed during preparation")
    return {"status": "local_nopic_candidate_created", "output": str(output), "inspection": report,
            "source_unchanged": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=tuple(reader.PROFILES), required=True)
    parser.add_argument("--source-private-tar", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = prepare(args.source_private_tar, args.output, args.target)
    except (ValueError, OSError, tarfile.TarError) as error:
        parser.error(str(error))
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
