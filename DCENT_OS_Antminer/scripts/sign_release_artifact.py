#!/usr/bin/env python3
"""Sign one exact release artifact through the durable no-replace signer."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys


SCRIPT_DIR = Path(__file__).resolve().parent
if os.fspath(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, os.fspath(SCRIPT_DIR))

import release_set_publication as release_io  # noqa: E402
import sign_release_receipt as exact_signer  # noqa: E402


MAX_RELEASE_ARTIFACT_BYTES = 64 * 1024 * 1024 * 1024


def fail(message: str) -> None:
    raise exact_signer.SigningError(message)


def host_path_text(value: str) -> str:
    """Rewrite Git-Bash (MSYS) drive paths (/d/dir) and long-path prefixes.

    MSYS automatic argument conversion is per-argument and inconsistent on
    long release command lines (producer runs drop1-20260916-cyg3sjwi and
    drop1-20260917-gnscaudk; the same fix landed in rust_dependency_inventory
    commit b1ae659fa and source_closure commit 4fd3d8b0e). Key paths are also
    read from DCENT_RELEASE_SIGNING_KEY / DCENT_RELEASE_PUBKEY_FILE, and MSYS
    never converts environment values at all, so normalization happens at
    this single resolution point for argv and environment alike. POSIX and
    native inputs are returned unchanged; on non-Windows hosts this is the
    identity.
    """
    if os.name != "nt" or not isinstance(value, str):
        return value
    text = value
    if text.startswith("\\\\?\\UNC\\"):
        text = "\\\\" + text[8:]
    elif text.startswith("//?/UNC/"):
        text = "//" + text[8:]
    else:
        for prefix in ("\\\\?\\", "//?/"):
            if text.startswith(prefix):
                text = text[len(prefix) :]
                break
    if (
        len(text) >= 2
        and text[0] == "/"
        and text[1].isascii()
        and text[1].isalpha()
        and (len(text) == 2 or text[2] == "/")
    ):
        return text[1].upper() + ":/" + text[3:]
    return text



def sign_artifact(args: argparse.Namespace) -> None:
    artifact = Path(host_path_text(args.artifact)).expanduser().absolute()
    output = Path(
        host_path_text(args.output_sig or f"{artifact}.sig")
    ).expanduser().absolute()
    private_key = host_path_text(
        args.key or os.environ.get("DCENT_RELEASE_SIGNING_KEY", "")
    )
    public_key = host_path_text(
        args.pubkey or os.environ.get("DCENT_RELEASE_PUBKEY_FILE", "")
    )
    if not private_key:
        fail(
            "release artifact signing requires a private key; set "
            "DCENT_RELEASE_SIGNING_KEY or pass --key"
        )
    if not public_key:
        fail(
            "release artifact signing requires a trusted public key; set "
            "DCENT_RELEASE_PUBKEY_FILE or pass --pubkey"
        )

    exact_signer.sign_receipt(
        argparse.Namespace(
            receipt=os.fspath(artifact),
            private_key=os.fspath(Path(private_key).expanduser().absolute()),
            public_key=os.fspath(Path(public_key).expanduser().absolute()),
            signature=os.fspath(output),
            subject="release artifact",
            staged_output=bool(getattr(args, "staged_output", False)),
            maximum_input_bytes=MAX_RELEASE_ARTIFACT_BYTES,
            durable_input=True,
            control_prefix="dcentos-release-artifact-signing-",
            success_message=f"Signed release artifact: {artifact} -> {output}",
        )
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("artifact")
    result.add_argument("--key")
    result.add_argument("--pubkey")
    result.add_argument("--output-sig")
    result.add_argument(
        "--staged-output",
        action="store_true",
        help="sign into a private release-set stage member (Windows private DACL)",
    )
    return result


def main() -> int:
    os.umask(0o077)
    try:
        sign_artifact(parser().parse_args())
        return 0
    except (
        exact_signer.SigningError,
        OSError,
        ValueError,
        release_io.ReleaseSetError,
        release_io.DirectoryPublishError,
        release_io.PublishError,
    ) as error:
        print(f"ERROR: release artifact signing: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
