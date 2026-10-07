#!/usr/bin/env python3
"""Prepare/verify signed runtime metadata after the daemon's final placement/strip.

Trust comes from an explicitly supplied release public key and the immutable
compiler-emitted ELF identity, never from rootfs metadata or strings output.
This helper does not generate keys. Its runtime manifest deliberately excludes
the enclosing rootfs digest, avoiding a self-referential image hash.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

# The installed Toolbox owns the pure signed-byte parser. Publication policy
# stays here; neither the package parser nor its key input can grant admission.
_TOOLBOX = Path(__file__).resolve().parents[2] / "dcent-toolbox/src"
if _TOOLBOX.is_dir() and str(_TOOLBOX) not in sys.path:
    sys.path.insert(0, str(_TOOLBOX))
from dcent_toolbox.core import signed_runtime_image as signed_runtime
from dcent_toolbox.core.signed_runtime_image import (
    PROFILE, MANIFEST, SIGNATURE, DAEMON, SETTINGS_DEFAULT, BUILD_PROFILE,
    MAX_DAEMON, FIELDS, OPTIONAL_FIELDS, ManifestError, build_identity,
    validate_hardware_recipe,
)


def regular_bytes(path: Path, maximum: int, *, single_link: bool = True) -> bytes:
    """Bound reads and refuse symlinks, devices and multi-link mutable inputs."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or (single_link and before.st_nlink != 1):
        raise ManifestError(f"expected single-link regular file: {path}")
    with os.fdopen(os.open(path, flags), "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ManifestError(f"input changed while opening: {path}")
        if not 0 < opened.st_size <= maximum:
            raise ManifestError(f"input size outside bounds: {path}")
        data = handle.read(maximum + 1)
        after = os.fstat(handle.fileno())
    identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if identity(opened) != identity(after) or len(data) != opened.st_size:
        raise ManifestError(f"input changed while reading: {path}")
    return data


def openssl(*arguments: str) -> bytes:
    # The MSYS openssl on the release host cannot open \\?\-prefixed NT long
    # paths (recorded by the signing-authority stage). Strip the prefix and
    # hand it the plain native path; MSYS resolves the drive itself.
    normalized = tuple(
        argument.replace("\\\\?\\", "") for argument in map(str, arguments)
    )
    result = subprocess.run(["openssl", *normalized], capture_output=True, check=False, timeout=30)
    if result.returncode:
        raise ManifestError("OpenSSL rejected key/signature: " + result.stderr.decode(errors="replace").strip())
    return result.stdout


def public_key_bytes(path: Path) -> bytes:
    regular_bytes(path, 16384)
    der = openssl("pkey", "-pubin", "-in", path, "-outform", "DER")
    if len(der) != 44 or der[:12] != bytes.fromhex("302a300506032b6570032100"):
        raise ManifestError("trusted public key must be Ed25519")
    return der[12:]


def registry_channel(board: str, channel: str) -> None:
    # Keep the parser shared with the release train/exporter.
    from release_train import load_admissions
    if channel not in ("beta", "stable") or load_admissions().get(board) != channel.title():
        raise ManifestError(f"board/channel is not publishable: {board}/{channel}")


def manifest_document(raw: bytes) -> dict:
    document = signed_runtime.manifest_document(raw)
    registry_channel(document["board_target"], document["channel"])
    return document


def verify_signature(subject: Path, signature: Path, pubkey: Path) -> None:
    public_key_bytes(pubkey)
    if len(regular_bytes(signature, 64)) != 64:
        raise ManifestError("detached Ed25519 signature must be raw 64 bytes")
    openssl("pkeyutl", "-verify", "-pubin", "-inkey", pubkey, "-rawin", "-in", subject, "-sigfile", signature)


def verify(rootfs: Path, board: str, channel: str, version: str, pubkey: Path, hardware_recipe: str = None) -> dict:
    registry_channel(board, channel)
    manifest = regular_bytes(rootfs / MANIFEST, 4096)
    manifest_document(manifest)
    files = {name: manifest if name == MANIFEST else regular_bytes(rootfs / name, maximum, single_link=name != DAEMON)
             for name, maximum in signed_runtime.required_files(manifest).items()}
    return signed_runtime.verify_files(files, public_key_bytes(pubkey), board, channel, version, hardware_recipe)


def prepare(rootfs: Path, board: str, channel: str, version: str, key: Path, pubkey: Path, hardware_recipe: str = "board-default") -> dict:
    registry_channel(board, channel)
    validate_hardware_recipe(board, hardware_recipe)
    daemon = regular_bytes(rootfs / DAEMON, MAX_DAEMON, single_link=False)
    identity = build_identity(daemon)
    expected_machine = 183 if board.startswith("am3-") and not board.startswith("am3-bb") else 40
    if identity["machine"] != expected_machine:
        raise ManifestError("daemon architecture does not match exact board target")
    if identity["version"] != version or identity["public_key"] != public_key_bytes(pubkey):
        raise ManifestError("compiled daemon version/key mismatch")
    document = dict(manifest_profile=PROFILE, board_target=board, channel=channel, version=version,
                    daemon_sha256=hashlib.sha256(daemon).hexdigest(), daemon_size=len(daemon), hardware_recipe=hardware_recipe)
    if (rootfs / SETTINGS_DEFAULT).exists() or (rootfs / SETTINGS_DEFAULT).is_symlink():
        content = regular_bytes(rootfs / SETTINGS_DEFAULT, signed_runtime.MAX_SETTINGS)
        document["settings_default_sha256"] = signed_runtime.settings_default_digest(content)
    directory = rootfs / "etc/dcentos"
    if not directory.is_dir() or directory.is_symlink():
        raise ManifestError("runtime metadata directory must be a real directory")
    # Verify in an isolated directory first; no failed preparation leaves a
    # partially trusted pair. The existing durable signer owns key handling.
    import sign_release_artifact
    with tempfile.TemporaryDirectory(prefix=".runtime-image-", dir=directory) as temporary:
        staged = Path(temporary)
        payload = staged / "runtime-image.json"
        signature = staged / "runtime-image.sig"
        payload.write_bytes((json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode())
        sign_release_artifact.sign_artifact(argparse.Namespace(artifact=str(payload), output_sig=str(signature), key=str(key), pubkey=str(pubkey)))
        verify_signature(payload, signature, pubkey)
        # Refuse a daemon changed between inspection and publication.
        if regular_bytes(rootfs / DAEMON, MAX_DAEMON, single_link=False) != daemon:
            raise ManifestError("daemon changed during manifest preparation")
        for source, destination in ((payload, rootfs / MANIFEST), (signature, rootfs / SIGNATURE)):
            os.chmod(source, 0o644)
            os.replace(source, destination)
    try:
        return verify(rootfs, board, channel, version, pubkey)
    except Exception:
        (rootfs / MANIFEST).unlink(missing_ok=True)
        (rootfs / SIGNATURE).unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "verify"))
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--board-target", required=True)
    parser.add_argument("--channel", required=True, choices=("beta", "stable"))
    parser.add_argument("--version", required=True)
    parser.add_argument("--hardware-recipe", choices=("board-default", "am2-s19j-xil-loki"))
    parser.add_argument("--pubkey", default=os.environ.get("DCENT_RELEASE_PUBKEY_FILE"), type=Path)
    parser.add_argument("--key", default=os.environ.get("DCENT_RELEASE_SIGNING_KEY"), type=Path)
    args = parser.parse_args()
    try:
        if not args.pubkey or (args.action == "prepare" and not args.key):
            raise ManifestError("explicit signing key and trusted public key are required for release preparation")
        arguments = (args.rootfs, args.board_target, args.channel, args.version)
        document = prepare(*arguments, args.key, args.pubkey, args.hardware_recipe or "board-default") if args.action == "prepare" else verify(*arguments, args.pubkey, args.hardware_recipe)
        print(json.dumps(document, sort_keys=True))
        return 0
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"ERROR: runtime image: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
