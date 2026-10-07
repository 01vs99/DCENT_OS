#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only

"""Build a DCENT AM2/Xilinx FIRST-INSTALL capsule (Wave 3, firmware side).

Packages operator-reviewed transition inputs into the typed capsule
contract enforced by ``dcent am2-first-install inspect`` (toolbox
``core/am2_xil_first_install.py`` â€” the single source of truth for the
contract). This script is the packager ONLY: it never invents payload
content, never contacts a miner, and never authorizes an install. Trust
comes exclusively from the release signature:

* the manifest is signed with the EXACT release signer
  (``sign_release_artifact.py`` â†’ ``sign_release_receipt.py`` â€” the same
  durable no-replace ceremony as sysupgrade packages);
* the trusted public key must be supplied explicitly (``--pubkey`` or
  ``DCENT_RELEASE_PUBKEY_FILE``) â€” trust is never derived from the
  signing key;
* output is no-replace: an existing capsule path is an error.

Determinism: identical inputs produce a byte-identical capsule (sorted
members, mtime-0 tar, mtime-0 gzip, sorted manifest keys).

The transition mechanism is DERIVED from the source layout (single-slot
sources â†’ boot_chain_repartition + mandatory ``transition/stage1.sh``;
dual-UBI sources â†’ inactive_slot_write) â€” there is no ``--mechanism``
flag to get wrong.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

SCRIPT_DIR = Path(__file__).resolve().parent
WORKSPACE_ROOT = SCRIPT_DIR.parents[2]
TOOLBOX_SOURCE = WORKSPACE_ROOT / "projects" / "dcent-toolbox" / "src"
if str(TOOLBOX_SOURCE) not in sys.path:
    sys.path.insert(0, str(TOOLBOX_SOURCE))

from dcent_toolbox.core.am2_xil_first_install import (  # noqa: E402
    CAPSULE_PACKAGE_TYPE,
    CAPSULE_SCHEMA,
    FIRST_INSTALL_TARGETS,
    MECHANISM_BOOT_CHAIN_REPARTITION,
    MANIFEST_MEMBER,
    SIGNATURE_MEMBER,
    STAGE1_MEMBER,
    canonical_first_install_source,
    canonical_first_install_target,
    first_install_source_facts,
)

MAX_STAGE1_BYTES = 4 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_PAYLOAD_BYTES = 256 * 1024 * 1024
_RESERVED_MEMBER_NAMES = {MANIFEST_MEMBER, SIGNATURE_MEMBER}
_VERSION_CHARS = re.compile(r"^[A-Za-z0-9._+:-]+$")


class CapsuleBuildError(ValueError):
    """Raised when capsule inputs violate the contract or cannot be packaged."""


def _fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise CapsuleBuildError(message)


def _member_bytes(path: Path, maximum: int = MAX_MEMBER_BYTES) -> bytes:
    # Reuse the established bounded no-follow/single-link snapshot. Validate
    # the exact retained bytes rather than reopening a caller-controlled path.
    from runtime_image_manifest import regular_bytes
    return regular_bytes(path, maximum)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(_member_bytes(path)).hexdigest()


def _validate_member_name(name: str) -> str:
    if (
        not name
        or name != name.strip()
        or name.startswith("/")
        or name.startswith("\\")
        or "\\" in name
        or ":" in name.split("/")[0]
        or any(part in ("", ".", "..") for part in name.split("/"))
        or "//" in name
    ):
        raise ValueError(f"unsafe member name: {name!r}")
    if name in _RESERVED_MEMBER_NAMES:
        raise ValueError(f"member name is reserved: {name!r}")
    if Path(name).is_absolute():
        raise ValueError(f"member name must be relative: {name!r}")
    return name


def _parse_member(spec: str) -> tuple[str, Path]:
    if "=" not in spec:
        raise ValueError(f"--member expects NAME=PATH, got {spec!r}")
    name, _, raw_path = spec.partition("=")
    return _validate_member_name(name.strip()), Path(raw_path.strip()).expanduser()


def _deterministic_tar(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name in sorted(files):
            data = files[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(buf.getvalue(), compresslevel=9, mtime=0)


def _default_output_name(board_target: str, version: str) -> str:
    pattern = FIRST_INSTALL_TARGETS[board_target].capsule_name_pattern
    return pattern.replace("<version>", version)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Build a contract-conforming DCENT AM2/XIL first-install "
            "capsule (packager only; signed with the exact release signer)."
        )
    )
    result.add_argument("--board-target", required=True,
                        help="am2-s19pro | am2-s19jpro-zynq | am2-s17p | am2-s17plus | am2-t17 | am2-t17plus (aliases accepted)")
    result.add_argument("--source-layout", required=True,
                        help="one source storage dialect (see `dcent am2-first-install contract`)")
    result.add_argument("--version", required=True,
                        help="capsule version string ([A-Za-z0-9._+:-])")
    result.add_argument("--post-install-artifact", required=True,
                        help="DCENT sysupgrade artifact ID the capsule converges to")
    result.add_argument("--migration-scope", required=True,
                        help="declared persistent-state migration (explicit 'none' allowed)")
    result.add_argument("--stage1", type=Path,
                        help="on-target transition script (required for executable capsules); packaged as "
                             + STAGE1_MEMBER)
    result.add_argument("--dual-ubi-kernel", type=Path,
                        help="embed kernel and canonical dual-UBI stage1; requires --dual-ubi-rootfs")
    result.add_argument("--dual-ubi-rootfs", type=Path,
                        help="embed rootfs for the executable dual-UBI first-install capsule")
    result.add_argument("--dual-ubi-fpga", type=Path,
                        help="exact am2-fabric.itb for the inactive 2 MiB FPGA partition")
    result.add_argument("--dual-ubi-writer", type=Path,
                        help="static ARM am2-nand-window helper built from the canonical source")
    for name in ("kernel", "rootfs", "fpga", "writer", "transition", "receipt", "recovery-fpga", "closure-dir"):
        result.add_argument("--stock8-" + name, type=Path,
                            help="exact stock8 executable capsule input: " + name)
    result.add_argument("--member", action="append", default=[], metavar="NAME=PATH",
                        help="additional payload member (repeatable; NAME is the in-capsule path)")
    result.add_argument("--key", default=os.environ.get("DCENT_RELEASE_SIGNING_KEY", ""),
                        help="Ed25519 private key PEM (default $DCENT_RELEASE_SIGNING_KEY)")
    result.add_argument("--pubkey", default=os.environ.get("DCENT_RELEASE_PUBKEY_FILE", ""),
                        help="trusted release public key (default $DCENT_RELEASE_PUBKEY_FILE); "
                             "trust is never derived from the signing key")
    result.add_argument("--output", type=Path,
                        help="output capsule path (default: the contract naming pattern)")
    result.add_argument("--plan", action="store_true",
                        help="print the exact manifest and member table; write nothing")
    result.add_argument("--json", action="store_true", help="emit JSON to stdout")
    return result


def build(args: argparse.Namespace) -> int:
    # --- validate against the toolbox contract (single source of truth) ---
    try:
        board_target = canonical_first_install_target(args.board_target)
    except ValueError as exc:
        raise _fail(str(exc))
    try:
        source = canonical_first_install_source(args.source_layout)
    except ValueError as exc:
        raise _fail(str(exc))
    facts = first_install_source_facts(source)
    mechanism = facts["transition_mechanism"]
    needs_stage1 = mechanism == MECHANISM_BOOT_CHAIN_REPARTITION

    if not 0 < len(args.version) <= 128 or not _VERSION_CHARS.fullmatch(args.version):
        raise _fail(f"version contains characters outside [A-Za-z0-9._+:-]: {args.version!r}")
    if not args.post_install_artifact or "/" in args.post_install_artifact or "\\" in args.post_install_artifact:
        raise _fail("post-install artifact must be a bare artifact ID (no path separators)")
    if not args.migration_scope.strip():
        raise _fail("migration scope must be declared (explicit 'none' allowed, never empty)")

    members: dict[str, Path] = {}
    generated: dict[str, bytes] = {}
    kernel = getattr(args, "dual_ubi_kernel", None)
    rootfs = getattr(args, "dual_ubi_rootfs", None)
    fpga = getattr(args, "dual_ubi_fpga", None)
    writer = getattr(args, "dual_ubi_writer", None)
    stock_names = ("kernel", "rootfs", "fpga", "writer", "transition", "receipt", "recovery_fpga", "closure_dir")
    stock = {name: getattr(args, "stock8_" + name, None) for name in stock_names}
    if any(stock.values()):
        from dcent_toolbox.core.am2_stock8_executor import (
            STAGE1_PATH as STOCK_STAGE1, HELD_CLOSURE, SOURCE as STOCK_SOURCE,
        )
        from dcent_toolbox.core.am2_first_install_executor import (
            validate_kernel_image, validate_rootfs_image, validate_fpga_image,
            validate_static_arm_writer, VENDOR_BOOT_PLACEHOLDER,
        )
        from prepare_am2_fabric_boot import nand_boot_environment
        if (not all(stock.values()) or source != STOCK_SOURCE or args.stage1 is not None
                or any((kernel, rootfs, fpga, writer))):
            raise _fail("stock8 requires all eight stock8 inputs, the exact stock8 source and no other stage1 override")
        validate_kernel_image(_member_bytes(stock["kernel"], 2920448), board_target)
        validate_rootfs_image(_member_bytes(stock["rootfs"], 22728704))
        validate_fpga_image(_member_bytes(stock["fpga"], 2097152))
        validate_static_arm_writer(_member_bytes(stock["writer"], 4 * 1024**2))
        for name, expected in HELD_CLOSURE.items():
            path = stock["closure_dir"] / name
            if not path.is_file() or path.is_symlink() or _sha256_file(path) != expected:
                raise _fail("stock8 executable closure differs from the exercised held donor")
            members["tools/" + name] = path
        firmware_dir = SCRIPT_DIR / "first_install"
        members.update({STAGE1_MEMBER: STOCK_STAGE1,
                        "payload/kernel": stock["kernel"], "payload/rootfs": stock["rootfs"],
                        "payload/am2-fabric.itb": stock["fpga"],
                        "tools/am2-nand-window-armv7": stock["writer"],
                        "payload/stock8-transition.itb": stock["transition"],
                        "payload/stock8-template.json": stock["receipt"],
                        "payload/system.bit.gz": stock["recovery_fpga"],
                        "payload/stock8-boot-defaults.env": firmware_dir / "stock8-boot-defaults.env",
                        "transition/stock8-stage2.sh": firmware_dir / "am2_stock_stage2.sh",
                        "transition/stock8-bootstrap.sh": firmware_dir / "am2_stock_bootstrap.sh"})
        generated["payload/bootenv1.json"] = (json.dumps(
            nand_boot_environment(1, VENDOR_BOOT_PLACEHOLDER), sort_keys=True, indent=2) + "\n").encode()
        # The source is still a boot-chain transition; this only satisfies its
        # canonical stage1 requirement instead of accepting a caller override.
        needs_stage1 = False
    if kernel or rootfs or fpga or writer:
        from dcent_toolbox.core.am2_first_install_executor import (
            STAGE1_PATH, validate_kernel_image, validate_rootfs_image,
            FPGA_MEMBER, WRITER_MEMBER, VENDOR_BOOT_PLACEHOLDER,
            validate_fpga_image, validate_static_arm_writer,
        )
        from prepare_am2_fabric_boot import nand_boot_environment
        if not all((kernel, rootfs, fpga, writer)) or needs_stage1 or args.stage1 is not None:
            raise _fail("dual-UBI requires kernel/rootfs/FPGA/static writer, a dual-UBI source and no --stage1 override")
        members.update({STAGE1_MEMBER: STAGE1_PATH, "payload/kernel": kernel,
                        "payload/rootfs": rootfs, FPGA_MEMBER: fpga, WRITER_MEMBER: writer})
        for path, ceiling in ((kernel, 2920448), (rootfs, 22728704)):
            if not path.is_file() or not 0 < path.stat().st_size <= ceiling:
                raise _fail("dual-UBI payload exceeds exact AM2 geometry")
        validate_kernel_image(_member_bytes(kernel, 2920448), board_target)
        validate_rootfs_image(_member_bytes(rootfs, 22728704))
        validate_fpga_image(_member_bytes(fpga, 2097152))
        validate_static_arm_writer(_member_bytes(writer, 4 * 1024**2))
        for firmware in (1, 2):
            generated[f"payload/bootenv{firmware}.json"] = (
                json.dumps(nand_boot_environment(firmware, VENDOR_BOOT_PLACEHOLDER),
                           sort_keys=True, indent=2) + "\n").encode()
    if needs_stage1:
        if args.stage1 is None:
            raise _fail(
                f"source {source} requires the on-target transition script "
                f"(--stage1 PATH; packaged as {STAGE1_MEMBER})"
            )
        members[STAGE1_MEMBER] = args.stage1.expanduser()
    elif args.stage1 is not None:
        raise _fail(
            f"--stage1 applies only to {MECHANISM_BOOT_CHAIN_REPARTITION} "
            f"capsules; use --dual-ubi-kernel/--dual-ubi-rootfs for canonical dual-UBI execution"
        )
    try:
        for spec in args.member:
            name, path = _parse_member(spec)
            if name in members or name in generated:
                raise ValueError(f"duplicate member name: {name!r}")
            members[name] = path
    except ValueError as exc:
        raise _fail(str(exc))

    checksums: dict[str, str] = {}
    payloads = dict(generated)
    total = 0
    for name in sorted(members):
        path = members[name]
        if not path.is_file():
            raise _fail(f"member file is missing or not a regular file: {path}")
        if path.is_symlink():
            raise _fail(f"member file is a symlink (refused): {path}")
        limit = MAX_STAGE1_BYTES if name == STAGE1_MEMBER else MAX_MEMBER_BYTES
        size = path.stat().st_size
        if size <= 0:
            raise _fail(f"member file is empty: {path}")
        if size > limit:
            raise _fail(f"member exceeds its {limit}-byte bound: {name} ({size} bytes)")
        total += size
        payloads[name] = _member_bytes(path, limit)
        checksums[name] = hashlib.sha256(payloads[name]).hexdigest()
    for name, data in generated.items():
        checksums[name] = hashlib.sha256(data).hexdigest()
        total += len(data)
    if total > MAX_TOTAL_PAYLOAD_BYTES:
        raise _fail(f"total payload exceeds {MAX_TOTAL_PAYLOAD_BYTES} bytes")
    if any(stock.values()):
        from dcent_toolbox.core.am2_stock8_executor import MEMBERS, validate_stock8_files
        validate_stock8_files({name: payloads[member] for name, member in MEMBERS.items()}, board_target)
    elif kernel:
        # Admit the retained bytes that will actually be signed. A path may
        # have changed since the preliminary input checks above.
        validate_kernel_image(payloads["payload/kernel"], board_target)
        validate_rootfs_image(payloads["payload/rootfs"])
        validate_fpga_image(payloads[FPGA_MEMBER])
        validate_static_arm_writer(payloads[WRITER_MEMBER])
    if "payload/rootfs" in payloads:
        if not args.pubkey:
            raise _fail("executable capsule requires an explicit trusted runtime public key, including --plan")
        import runtime_image_manifest as runtime
        from dcent_toolbox.core.am2_first_install_executor import runtime_board_target
        board = runtime_board_target(board_target)
        runtime.registry_channel(board, "beta")
        runtime.signed_runtime.verify_files(
            runtime.signed_runtime.squashfs_files(payloads["payload/rootfs"]),
            runtime.public_key_bytes(Path(args.pubkey).expanduser()), board, "beta", args.version, "board-default")

    manifest = {
        "schema": CAPSULE_SCHEMA,
        "package_type": CAPSULE_PACKAGE_TYPE,
        "version": args.version,
        "board_target": board_target,
        "accepted_source_layouts": [source],
        "transition_mechanism": mechanism,
        "post_install_artifact": args.post_install_artifact,
        "migration_scope": args.migration_scope.strip(),
        "checksums": checksums,
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
    output = (args.output or Path(_default_output_name(board_target, args.version))).expanduser()

    if args.plan:
        plan = {
            "mode": "plan",
            "output": str(output),
            "board_target": board_target,
            "source_layout": source,
            "transition_mechanism": mechanism,
            "dialect_proven": facts["dialect_proven"],
            "members": [
                {"name": name, "bytes": len(payloads[name]), "sha256": checksums[name]}
                for name in sorted(payloads)
            ],
            "manifest": manifest,
            "signing": {
                "key": str(Path(args.key).expanduser()) if args.key else "(not configured)",
                "trusted_pubkey": str(Path(args.pubkey).expanduser()) if args.pubkey else "(not configured)",
                "signer": str(SCRIPT_DIR / "sign_release_artifact.py"),
            },
        }
        print(json.dumps(plan, indent=2) if args.json else json.dumps(plan, indent=2))
        return 0

    if output.exists() or output.is_symlink():
        raise _fail(f"output already exists (no-replace): {output}")
    if not args.key or not args.pubkey:
        raise _fail(
            "signing requires --key (or $DCENT_RELEASE_SIGNING_KEY) AND "
            "--pubkey (or $DCENT_RELEASE_PUBKEY_FILE); trust is never "
            "derived from the signing key"
        )

    key_path = Path(args.key).expanduser()
    pubkey_path = Path(args.pubkey).expanduser()
    for label, path in (("signing key", key_path), ("trusted public key", pubkey_path)):
        if not path.is_file():
            raise _fail(f"{label} is not a file: {path}")

    signer = SCRIPT_DIR / "sign_release_artifact.py"
    if not signer.is_file():
        raise _fail(f"exact release signer is missing: {signer}")

    with tempfile.TemporaryDirectory(prefix="am2-first-install-") as staging_raw:
        staging = Path(staging_raw)
        manifest_path = staging / MANIFEST_MEMBER
        manifest_path.write_bytes(manifest_bytes)
        signature_path = staging / SIGNATURE_MEMBER
        run = subprocess.run(
            [
                sys.executable, str(signer), str(manifest_path),
                "--key", str(key_path),
                "--pubkey", str(pubkey_path),
                "--output-sig", str(signature_path),
            ],
            capture_output=True,
            text=True,
        )
        if run.returncode != 0:
            print(run.stdout, file=sys.stderr)
            print(run.stderr, file=sys.stderr)
            raise _fail("exact release signer failed (see signer output above)")
        signature = signature_path.read_bytes()
        if len(signature) != 64:
            raise _fail(f"signer produced a {len(signature)}-byte signature (expected 64)")

        files: dict[str, bytes] = {MANIFEST_MEMBER: manifest_bytes, SIGNATURE_MEMBER: signature}
        files.update(payloads)
        capsule_bytes = _deterministic_tar(files)

        # write no-replace: create exclusively, then fsync
        try:
            descriptor = os.open(str(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o644)
        except FileExistsError:
            raise _fail(f"output appeared during build (no-replace): {output}")
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(capsule_bytes)
            handle.flush()
            os.fsync(handle.fileno())

    payload = {
        "mode": "built",
        "capsule": str(output),
        "bytes": len(capsule_bytes),
        "sha256": hashlib.sha256(capsule_bytes).hexdigest(),
        "board_target": board_target,
        "source_layout": source,
        "transition_mechanism": mechanism,
        "version": args.version,
        "members": sorted(payloads),
        "verify_command": f"dcent am2-first-install inspect --capsule {output}",
    }
    print(json.dumps(payload, indent=2) if args.json else (
        f"Built capsule: {output}\n"
        f"  board: {board_target} | source: {source} | mechanism: {mechanism}\n"
        f"  version: {args.version} | members: {', '.join(sorted(payloads)) or '(manifest-only)'}\n"
        f"  size: {len(capsule_bytes)} bytes | sha256: {payload['sha256']}\n"
        f"  verify: dcent am2-first-install inspect --capsule {output}"
    ))
    return 0


def main(argv: list[str] | None = None) -> int:
    if shutil.which("openssl") is None:
        print(
            "WARNING: openssl not found on PATH; the exact release signer "
            "requires it.",
            file=sys.stderr,
        )
    try:
        return build(parser().parse_args(argv))
    except CapsuleBuildError:
        return 2
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"ERROR: capsule input validation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
