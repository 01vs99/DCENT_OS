#!/usr/bin/env python3
"""Authenticated cumulative-drop projection; synthetic release records only."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import release_channel_feed as emitter
from release_producer import list_producers


def fixture(directory):
    key = Ed25519PrivateKey.from_private_bytes(bytes([17]) * 32)
    private, public = directory / "private.pem", directory / "public.pem"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    private.chmod(0o600)
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    rows = []
    commit = "a" * 40
    for producer in list_producers():
        files = []
        for suffix, size in (("", 1024), (".sig", 64), (".runtime-image.json", 512), (".runtime-image.sig", 64)):
            path = f"beta/{producer.board_target}/{'b' * 64}/{producer.primary_artifact}{suffix}"
            files.append({"path": path, "url": "https://releases.example.invalid/" + path,
                          "sha256": "c" * 64, "size": size})
        rows.append({"producer": producer.producer, "board_target": producer.board_target,
            "release_channel": "beta", "version": "1.2.3", "source_commit": commit,
            "hardware_recipe": producer.hardware_recipe, "install_route": producer.install_route,
            "reproducibility": {"compared": True, "identical": True}, "files": files})
    document = {"manifest_profile": "dcentos-release-train-drop-manifest/v2", "drop": 1,
        "source_commit": commit, "release_channel": "beta", "complete_selected_beta": True,
        "fund_url": "https://d-central.tech/dcentos/", "targets": rows}
    manifest = directory / "drop.json"
    def save(value):
        raw = (json.dumps(value, sort_keys=True) + "\n").encode()
        manifest.write_bytes(raw)
        Path(str(manifest) + ".sig").write_bytes(key.sign(raw))
    save(document)
    return document, save, manifest, private, public


class FeedEmitterTests(unittest.TestCase):
    def test_actual_signer_roundtrip_all_beta_and_manual_route_retention(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            document, _, manifest, key, pubkey = fixture(directory)
            output = directory / "beta.json"
            emitter.emit(manifest, output, key, pubkey, "0.9.0")
            payload, _ = emitter.feed.load(output, pubkey, "beta")
            self.assertEqual(len(payload["targets"]), len(document["targets"]))
            by_board = {row["board_target"]: row for row in payload["targets"]}
            self.assertEqual(by_board["am2-s17e"]["install_route"], "sd_trial_boot_only")
            self.assertEqual(by_board["am3-bb-s19jpro"]["artifact_kind"], "sd-payload-tar")
            self.assertEqual(by_board["am3-s21xp"]["install_route"], "operator_staged")
            with self.assertRaises(FileExistsError):
                emitter.emit(manifest, output, key, pubkey, "0.9.0")

    def test_unsigned_or_modified_drop_never_creates_feed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            _, _, manifest, key, pubkey = fixture(directory)
            manifest.write_bytes(manifest.read_bytes() + b" ")
            output = directory / "beta.json"
            with self.assertRaises(emitter.feed.FeedError):
                emitter.emit(manifest, output, key, pubkey, "0.9.0")
            self.assertFalse(output.exists())

    def test_signed_incomplete_foreign_or_missing_primary_never_creates_feed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            original, save, manifest, key, pubkey = fixture(directory)
            changes = [
                lambda value: value.update(complete_selected_beta=False),
                lambda value: value["targets"].pop(),
                lambda value: value["targets"][0].update(board_target="am2-s19"),
                lambda value: value["targets"][0].update(release_channel="unsupported"),
                lambda value: value["targets"][0]["files"].pop(0),
                lambda value: value["targets"][0]["files"][0].update(url="http://example.invalid/unsigned.tar"),
            ]
            for change in changes:
                value = json.loads(json.dumps(original))
                change(value)
                save(value)
                output = directory / "beta.json"
                with self.assertRaises(ValueError):
                    emitter.emit(manifest, output, key, pubkey, "0.9.0")
                self.assertFalse(output.exists())

    def test_explicit_minimum_version_must_be_valid_and_not_newer_than_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            document, *_ = fixture(Path(temporary))
            for value in ("", "0", "v0.9.0", "1.2.4"):
                with self.assertRaises(ValueError):
                    emitter.payload_from_drop(document, value)


if __name__ == "__main__":
    if sys.argv[1:] == ["--schema-fixture"]:
        # Used by the Rust schema integration test: actual production emitter
        # and signer, with the same public throwaway fixture key as the schema.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            _, _, manifest, key, pubkey = fixture(directory)
            output = directory / "beta.json"
            with contextlib.redirect_stdout(io.StringIO()):
                emitter.emit(manifest, output, key, pubkey, "0.9.0")
            sys.stdout.buffer.write(output.read_bytes())
    else:
        unittest.main()
