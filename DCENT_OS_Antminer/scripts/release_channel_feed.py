#!/usr/bin/env python3
"""Emit ChannelFeed from one authenticated, complete cumulative release drop."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import sys
import tempfile

SCRIPT = Path(__file__).resolve().parent
TOOLBOX = SCRIPT.parents[1] / "dcent-toolbox/src"
sys.path.insert(0, str(TOOLBOX))
from dcent_toolbox.core import channel_feed as feed
import runtime_image_manifest as runtime
from release_producer import get_producer
import sign_release_artifact

DROP_FIELDS = {"manifest_profile", "drop", "source_commit", "release_channel",
               "complete_selected_beta", "fund_url", "targets"}
ROW_FIELDS = {"producer", "board_target", "release_channel", "version", "source_commit",
              "hardware_recipe", "install_route", "reproducibility", "files"}


def payload_from_drop(document: dict, minimum_version: str) -> dict:
    from release_train import load_admissions
    feed.version(minimum_version)  # Explicit compatibility floor, never inferred.
    if (not isinstance(document, dict) or document.keys() != DROP_FIELDS
            or document["manifest_profile"] != "dcentos-release-train-drop-manifest/v2"
            or type(document["drop"]) is not int or document["drop"] not in (1, 2, 3)
            or document["release_channel"] != "beta" or document["complete_selected_beta"] is not True
            or not isinstance(document["targets"], list)):
        raise feed.FeedError("channel feed requires a complete signed cumulative v2 Beta drop")
    targets, seen = [], set()
    for row in document["targets"]:
        if not isinstance(row, dict) or row.keys() != ROW_FIELDS:
            raise feed.FeedError("malformed cumulative target")
        producer = get_producer(row["producer"])
        if (row["board_target"] != producer.board_target or row["install_route"] != producer.install_route
                or row["release_channel"] != "beta" or row["source_commit"] != document["source_commit"]
                or row["board_target"] in seen):
            raise feed.FeedError("cumulative row differs from its exact producer/source/channel")
        runtime.registry_channel(producer.board_target, "beta")
        seen.add(producer.board_target)
        if not isinstance(row["files"], list) or not 4 <= len(row["files"]) <= 68:
            raise feed.FeedError("cumulative target has no bounded complete artifact file set")
        names = {}
        for record in row["files"]:
            if not isinstance(record, dict) or record.keys() != {"path", "size", "sha256", "url"}:
                raise feed.FeedError("malformed published file record")
            if not isinstance(record["path"], str):
                raise feed.FeedError("published file path must be text")
            path = PurePosixPath(record["path"])
            if path.is_absolute() or any(part in (".", "..") for part in record["path"].split("/")):
                raise feed.FeedError("published file path is not relative")
            name = path.name
            if name in names:
                raise feed.FeedError("duplicate published artifact basename")
            feed.https_url(record["url"])
            from urllib.parse import unquote, urlsplit
            if unquote(urlsplit(record["url"]).path).rsplit("/", 1)[-1] != name:
                raise feed.FeedError("published URL does not name the authenticated file")
            names[name] = record
        name = producer.primary_artifact
        if not {name, name + ".sig", name + ".runtime-image.json", name + ".runtime-image.sig"} <= names.keys():
            raise feed.FeedError("published primary or signature/runtime companion is absent")
        primary = names[name]
        targets.append({"board_target": producer.board_target, "version": row["version"],
            "minimum_version": minimum_version, "release_channel": "beta",
            "artifact_kind": producer.artifact_kind, "install_route": producer.install_route,
            "hardware_recipe": row["hardware_recipe"], "sha256": primary["sha256"],
            "url": primary["url"], "size": primary["size"]})
    expected = {board for board, channel in load_admissions().items() if channel == "Beta"}
    if seen != expected:
        raise feed.FeedError("channel feed must include every registered Beta row exactly once")
    return feed.validate_payload({"schema": 1, "product": "DCENT_OS", "release_channel": "beta",
        "source_commit": document["source_commit"], "targets": sorted(targets, key=lambda row: row["board_target"])}, "beta")


def emit(manifest: Path, output: Path, key: Path, pubkey: Path, minimum_version: str) -> dict:
    raw = feed.read_bounded(manifest, feed.MAX_FEED_BYTES)
    # Signature covers the exact bytes parsed below; no reread race through a
    # helper that authenticates one pathname but returns a different document.
    signature = feed.read_bounded(Path(str(manifest) + ".sig"), 64)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    trusted = feed.public_key(pubkey)
    try:
        Ed25519PublicKey.from_public_bytes(trusted).verify(signature, raw)
    except (ValueError, InvalidSignature) as error:
        raise feed.FeedError("cumulative drop signature verification failed") from error
    payload = payload_from_drop(feed.strict_json(raw), minimum_version)
    signed_bytes = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with tempfile.TemporaryDirectory(prefix=".channel-sign-", dir=output.parent) as temporary:
        source = Path(temporary) / "payload.json"
        signed = Path(temporary) / "payload.sig"
        source.write_bytes(signed_bytes)
        sign_release_artifact.sign_artifact(argparse.Namespace(artifact=str(source), output_sig=str(signed),
                                                               key=str(key), pubkey=str(pubkey)))
        envelope = {"profile": feed.PROFILE, "payload": signed_bytes.decode("utf-8"),
                    "signature": signed.read_bytes().hex()}
        encoded = (json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n").encode()
        feed.verify(encoded, trusted, "beta")
        with output.open("xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    return envelope


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--drop-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--pubkey", type=Path, required=True)
    parser.add_argument("--minimum-version", required=True)
    args = parser.parse_args()
    try:
        emit(args.drop_manifest, args.output, args.key, args.pubkey, args.minimum_version)
        return 0
    except (ValueError, OSError) as error:
        parser.exit(1, f"channel feed refused: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
