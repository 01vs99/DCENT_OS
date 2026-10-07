#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only
"""Compose a compact unsigned Classic AML FIT container from a checked local BETA.

The exact held loader and Classic padding are preserved. This is host artifact
preparation; it emits no boot script, device writer, signing key or signature.
Support this project: https://d-central.tech/fund/
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[3]
CODEC = "tools/vnish_aml_boot_package/vnish_aml_boot_package.py"
CODEC_SHA = "794875f6a8a703d3c2009b11af4ecb3bf3dd41d43f01fcebfb2446164e312324"
DONOR = ""
DONOR_SHA = "7888c97c08fa34aa83bbc0c36b01b84940ef4897462f1ac7c5e30e77dd1bb252"
PACKAGE_SHA = "da95e907334bc620bf8559d939cceb431f4dd23a86b661aee2ed923799e34d9b"
PREFIX = "classic-aml-private-beta/"
MAX_SOURCE = 384 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(raw):
    return {"bytes": len(raw), "sha256": sha(raw)}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def reader():
    sys.path.insert(0, str(ROOT / "projects/dcent-toolbox/src"))
    from dcent_toolbox.core import classic_aml_candidate
    return classic_aml_candidate


def load_source(path, expected_sha256):
    consumer = reader()
    raw = consumer.regular_bytes(path, MAX_SOURCE)
    require(sha(raw) == expected_sha256, "source archive SHA256 differs")
    blobs = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as source:
        for member in source:
            require(member.name.startswith(PREFIX), "source archive prefix differs")
            name = member.name[len(PREFIX):]
            require(name not in blobs and member.isfile() and not member.pax_headers and
                    (member.mode, member.uid, member.gid, member.mtime) == (0o644, 0, 0, 0),
                    "source archive metadata/duplicate differs")
            require(0 < member.size <= 256 * 1024 * 1024 and len(blobs) < 20, "source member bound")
            blobs[name] = source.extractfile(member).read()
            require(len(blobs[name]) == member.size, "source member truncated")
    manifest = consumer.object_json(blobs["PRIVATE_BETA.json"])
    require(set(blobs) == set(manifest["artifacts"]) | {"PRIVATE_BETA.json", "SHA256SUMS"}, "source member set differs")
    for name, row in manifest["artifacts"].items():
        require(pin(blobs[name]) == row, "source digest differs: " + name)
    sums = {}
    for line in blobs["SHA256SUMS"].decode("ascii").splitlines():
        digest, name = line.split("  ", 1)
        require(name not in sums and name in blobs and sha(blobs[name]) == digest, "source checksum differs")
        sums[name] = digest
    require(set(sums) == set(blobs) - {"SHA256SUMS"}, "source checksum set differs")
    require(blobs["payloads/uImage_rootfs.bin"][64:] == blobs["payloads/rootfs.cpio.gz"], "source gzip/uImage differ")
    # Validate the omitted build log now. Its immutable digest remains in the
    # source manifest/terminal receipt; the compact archive need not copy it.
    terminal = consumer.object_json(blobs["receipts/build-terminal.json"])
    log = blobs["receipts/userspace-build.log"]
    require(pin(log) == {"bytes": terminal["log_bytes"], "sha256": terminal["log_sha256"]}, "terminal log differs")
    require(terminal["reason"].encode() in log, "terminal reason absent from checked log")
    return blobs, pin(raw)


def codec_and_donor():
    consumer = reader()
    codec_raw = consumer.regular_bytes(ROOT / CODEC, 1024 * 1024)
    require(sha(codec_raw) == CODEC_SHA, "held codec source changed")
    spec = importlib.util.spec_from_file_location("classic_held_transform_primitives", ROOT / CODEC)
    codec = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(codec)
    donor_raw = consumer.regular_bytes(ROOT / DONOR)
    require(sha(donor_raw) == DONOR_SHA, "held Classic SD source changed")
    with zipfile.ZipFile(io.BytesIO(donor_raw)) as archive:
        require(archive.namelist().count("aml_boot_package.enc") == 1, "duplicate donor package")
        package = archive.read("aml_boot_package.enc")
    require(sha(package) == PACKAGE_SHA, "Classic source package differs")
    decoded = bytearray(package)
    for stage in codec.STAGES:
        offset, polynomial, address, length, _ = stage
        codec.xor_control_struct(decoded, offset)
        codec._validate_stage(codec._control_words(decoded, offset), stage)
        start = address - codec.IMAGE_BASE
        decoded[start:start + length] = codec.contiguous_transform(decoded[start:start + length], polynomial, False)
    codec.xor_control_struct(decoded, codec.FINAL_HEADER_OFFSET)
    final = codec._control_words(decoded, codec.FINAL_HEADER_OFFSET)
    require(final == (0, 0, 0, 0, 0x6b8b4567, 0x02300000, 0x01151438,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x02203000, 4096, 0), "Classic final control differs")
    codec.sparse_transform(decoded, codec.FIT_OFFSET, final[6], final[4], False)
    require(consumer.decode_container(package) == decoded, "independent original decode differs")
    return codec, bytes(decoded)


def compose(codec, original, ramdisk):
    fit = original[codec.FIT_OFFSET:]
    header, nodes = codec.parse_fdt(fit)
    previous, offset = nodes["/images/ramdisk"]["data"]
    require(header["total_size"] == len(fit), "source FIT length differs")
    old_padded, new_padded = (len(previous) + 3) & ~3, (len(ramdisk) + 3) & ~3
    delta = new_padded - old_padded
    replacement = ramdisk + b"\0" * (new_padded - len(ramdisk))
    new_fit = bytearray(fit[:offset] + replacement + fit[offset + old_padded:])
    # Offset points to data following token, property length and name offset.
    struct.pack_into(">I", new_fit, offset - 8, len(ramdisk))
    for at, value in ((4, len(new_fit)), (12, header["strings_offset"] + delta),
                      (36, header["structure_size"] + delta)):
        struct.pack_into(">I", new_fit, at, value)
    parsed_header, parsed_nodes = codec.parse_fdt(bytes(new_fit))
    require(parsed_header["total_size"] == len(new_fit) and
            parsed_nodes["/images/ramdisk"]["data"][0] == ramdisk, "replacement FIT parse differs")
    for path, properties in nodes.items():
        for name, (body, _) in properties.items():
            if (path, name) != ("/images/ramdisk", "data"):
                require(parsed_nodes[path][name][0] == body, "unrelated FIT property changed")
    decoded = bytearray(original[:codec.FIT_OFFSET] + new_fit)
    require(len(decoded) <= reader().MAX_PACKAGE, "candidate overlaps reserved secmon memory")
    struct.pack_into("<I", decoded, 0x4028, len(new_fit))
    encoded = bytearray(decoded)
    codec.sparse_transform(encoded, codec.FIT_OFFSET, len(new_fit), 0x6b8b4567, True)
    codec.xor_control_struct(encoded, codec.FINAL_HEADER_OFFSET)
    for offset, polynomial, address, length, _ in reversed(codec.STAGES):
        start = address - codec.IMAGE_BASE
        encoded[start:start + length] = codec.contiguous_transform(encoded[start:start + length], polynomial, True)
        codec.xor_control_struct(encoded, offset)
    require(reader().decode_container(bytes(encoded)) == decoded, "independent candidate roundtrip differs")
    return bytes(encoded), len(reader().gunzip(nodes["/images/kernel"]["data"][0], 16 * 1024 * 1024))


def prepare(source, expected_source_sha256, output):
    consumer = reader()
    output = consumer._plain_path(output)
    require(not output.exists(), "preserve existing candidate")
    source_blobs, source_pin = load_source(source, expected_source_sha256)
    codec, original = codec_and_donor()
    package, kernel_bytes = compose(codec, original, source_blobs["payloads/rootfs.cpio.gz"])
    blobs = {"aml_boot_package.enc": package, "SOURCE_PRIVATE_BETA.json": source_blobs["PRIVATE_BETA.json"]}
    for name in consumer.RECEIPTS:
        blobs["receipts/" + name] = source_blobs["receipts/" + name]
    manifest = {"schema": consumer.SCHEMA, "board_target": consumer.TARGET,
                "source_archive": source_pin, "source_boot_package_sha256": PACKAGE_SHA,
                "source_uimage_header_hex": source_blobs["payloads/uImage_rootfs.bin"][:64].hex(),
                "boundaries": consumer.BOUNDARIES, "persistence": consumer.PERSISTENCE,
                "members": {name: pin(body) for name, body in blobs.items()},
                "known_memory_spans": {"kernel": [0x01080000, 0x01080000 + kernel_bytes],
                    "loader": [0x02200000, 0x02300000], "fit": [0x02300000, 0x02200000 + len(package)],
                    "secmon": [0x05000000, 0x05400000], "ramoops": [0x07400000, 0x07500000]},
                "unresolved_entry_contract": ["resident load/verify/go failure behavior", "resident bootm acceptance",
                                              "resident DRAM fixups and initrd relocation", "exact-unit external-entry witness"],
                "producer": {"path": Path(__file__).name, **pin(Path(__file__).read_bytes())}}
    blobs["CANDIDATE.json"] = canonical(manifest)
    blobs["SIGNING_REQUEST.json"] = canonical({"schema": "dcentos.detached_signing_request.v1",
        "artifact": "CANDIDATE.json", "artifact_pin": pin(blobs["CANDIDATE.json"]), "algorithm": "Ed25519",
        "signature": None, "release_key": "externally_pinned_dcentral_release_key_required",
        "authenticated_git_release_provenance": False, "install_admission": False})
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, body in sorted(blobs.items()):
            member = tarfile.TarInfo(consumer.PREFIX + name)
            member.size, member.mode = len(body), 0o644
            member.uid = member.gid = member.mtime = 0
            archive.addfile(member, io.BytesIO(body))
    result = consumer.inspect_bytes(buffer.getvalue())
    consumer._write_new(output, buffer.getvalue())
    require(consumer.inspect_candidate(output) == result, "published candidate readback differs")
    return {"output": str(output), **result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--expected-source-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.source, args.expected_source_sha256, args.output), indent=2))
    except (ValueError, OSError, KeyError, tarfile.TarError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
