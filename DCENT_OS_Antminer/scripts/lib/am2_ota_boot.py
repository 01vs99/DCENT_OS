#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Canonical two-native-slot AM2 NAND boot tuple and exact FPGA FIT envelope."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import struct
import sys
import uuid

try:
    import prepare_am2_fabric_boot as fabric
except ModuleNotFoundError as error:
    if error.name != "prepare_am2_fabric_boot":
        raise
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import prepare_am2_fabric_boot as fabric

LEGACY_KEYS = {
    "nandboot",
    "dcent_native_slot",
    "dcent_vendor_nandboot",
    "dcent_fpga_hash_pin",
    "dcent_fpga_load",
    "dcent_nand_fallback",
    "dcent_nandboot",
}
# These variables are produced by the pinned U-Boot load commands. A fallback
# saveenv can persist their current values; rollback restores their old values.
BOOT_SCRATCH_KEYS = {
    "bootargs",
    "verify",
    "filesize",
    "fileaddr",
    "dcent_hash_algo",
    "dcent_hash_size",
    "dcent_hash_addr",
    "dcent_fpga_load_completed",
}


def native_environment(previous: int, transaction: str) -> dict[str, str]:
    """Both native slots load their own exact FPGA before kernel/I2C ownership.

    The previous slot is attempted at most once after a failed new boot. There
    is no recursive vendor command stack and no Linux FPGA reprogramming.
    """
    if type(previous) is not int or previous not in (1, 2):
        raise ValueError("previous native firmware must be exact slot1 or slot2")
    if not re.fullmatch(r"[0-9a-f]{64}", transaction):
        raise ValueError("native transaction identity must be a SHA256-sized nonce")
    result = {
        "nandboot": "run dcent_native_dispatch",
        "dcent_native_previous": str(previous),
        "dcent_native_transaction": transaction,
        "dcent_fpga_hash_pin": fabric.boot_environment()["dcent_fpga_hash_pin"],
    }
    for slot in (1, 2):
        result[f"dcent_fpga_load{slot}"] = fabric.nand_boot_environment(
            slot, "run nandboot_recovery"
        )["dcent_fpga_load"]
        result[f"dcent_native_boot{slot}"] = (
            "setenv dcent_fpga_load_completed 0;"
            " if mw.l 0xF8000008 0x0000DF0D && mw.l 0xF8000170 0x00400400"
            f" && mw.l 0xF8000004 0x0000767B && run dcent_fpga_load{slot}"
            f' && setenv bootargs "console=ttyPS0,115200 noinitrd ubi.mtd={6 + slot}'
            " ubi.block=0,1 root=/dev/ubiblock0_1 ro rootfstype=squashfs rootwait"
            f" {fabric.NAND_MTDPARTS} earlyprintk dcent.fpga_load_completed=1"
            f' dcent.fpga_sha256={fabric.BITSTREAM_SHA256}"'
            f" && ubi part firmware{slot} && ubi read 0x02000000 kernel;"
            " then bootm 0x02000000; fi; false"
        )
    result["dcent_native_fallback"] = (
        "if test x${firmware} = x${dcent_native_previous};"
        " then echo Previous native firmware also failed; false;"
        " else setenv firmware ${dcent_native_previous} && setenv upgrade_stage"
        " && setenv first_boot && saveenv"
        " && if test x${firmware} = x1; then run dcent_native_boot1;"
        " else run dcent_native_boot2; fi; fi"
    )
    result["dcent_native_dispatch"] = (
        "if test x${upgrade_stage} = x1; then run dcent_native_fallback;"
        " else if test x${upgrade_stage} = x0;"
        " then setenv upgrade_stage 1 && saveenv || exit; fi;"
        " if test x${firmware} = x1; then run dcent_native_boot1;"
        " elif test x${firmware} = x2; then run dcent_native_boot2;"
        " else echo Invalid native firmware selector; exit; fi;"
        " run dcent_native_fallback; fi"
    )
    return result


def parse_environment(raw: bytes) -> dict[str, str]:
    if len(raw) > 131072 or b"\0" in raw or b"\r" in raw:
        raise ValueError("environment encoding/size differs")
    result = {}
    for line in raw.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z0-9_]+", key) or key in result:
            raise ValueError("environment duplicate/invalid key")
        result[key] = value
    return result


def admitted_fabric_bytes(raw: bytes) -> bytes:
    """Accept the ratified s19j container form of the held AM2 fabric.

    W8-BITSTREAM-PROVENANCE §4.2 F-2: 
    fpga_bitstream.bit is a padded 2 MiB partition read whose first bytes
    are a GZIP member (stored name system.bit). The admitted AM2 fabric is
    the INFLATED member; inflate the container so the admission pins the
    payload, not the container bytes. Trailing bytes after the member are
    ignored (the partition-read form pads with 0xff). Inflation is bounded by the admitted size (deflate
    amplification cannot exhaust memory before the size pin refuses), and
    a member truncated before its CRC32/ISIZE trailer is refused. A bare
    (already inflated) payload passes through.
    """
    if raw[:3] != b"\x1f\x8b\x08":
        return raw
    import zlib

    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        inflated = inflater.decompress(raw, fabric.BITSTREAM_SIZE + 1)
    except zlib.error as error:
        raise ValueError(f"AM2 fabric container is corrupt: {error}") from error
    if not inflater.eof or len(inflated) > fabric.BITSTREAM_SIZE:
        raise ValueError("AM2 fabric container is truncated or oversized")
    return inflated


def fit_from_raw(raw: bytes) -> bytes:
    raw = admitted_fabric_bytes(raw)
    if (
        len(raw) != fabric.BITSTREAM_SIZE
        or hashlib.sha256(raw).hexdigest() != fabric.BITSTREAM_SHA256
    ):
        raise ValueError("signed FPGA payload is not the admitted AM2 fabric")
    strings = bytearray()
    structure = bytearray()
    offsets = {}

    def word(value):
        structure.extend(struct.pack(">I", value))

    def aligned(data):
        structure.extend(data)
        structure.extend(b"\0" * (-len(data) % 4))

    def begin(name):
        word(1)
        aligned(name.encode() + b"\0")

    def prop(name, data):
        if name not in offsets:
            offsets[name] = len(strings)
            strings.extend(name.encode() + b"\0")
        word(3)
        word(len(data))
        word(offsets[name])
        aligned(data)

    begin("")
    prop("description", b"DCENT AM2 exact FPGA\0")
    # U-Boot FIT format admission requires the root timestamp property. Fixed
    # epoch keeps this locally wrapped, signed raw payload reproducible.
    prop("timestamp", struct.pack(">I", 0))
    prop("#address-cells", struct.pack(">I", 1))
    begin("images")
    begin("system-bit")
    for key, data in (
        ("description", b"DCENT AM2 fabric\0"),
        ("data", raw),
        ("type", b"firmware\0"),
        ("arch", b"arm\0"),
        ("compression", b"none\0"),
    ):
        prop(key, data)
    begin("hash-1")
    prop("algo", b"sha256\0")
    prop("value", hashlib.sha256(raw).digest())
    word(2)
    word(2)
    word(2)
    word(2)
    word(9)
    start = 56
    header = struct.pack(
        ">10I",
        0xD00DFEED,
        start + len(structure) + len(strings),
        start,
        start + len(structure),
        40,
        17,
        16,
        0,
        len(strings),
        len(structure),
    )
    result = header + bytes(16) + structure + strings
    validate_fit(result)
    return result


def validate_fit(raw: bytes) -> None:
    if not 40 <= len(raw) <= 2097152:
        raise ValueError("FPGA FIT exceeds its exact2MiB partition")
    magic, total, off, strings_off, _, version, compatible, _, strings_size, size = (
        struct.unpack_from(">10I", raw)
    )
    if (
        magic != 0xD00DFEED
        or version != 17
        or compatible > 17
        or not 40 <= total <= len(raw)
        or off < 40
        or off + size > total
        or strings_off < off + size
        or strings_off + strings_size > total
        or any(byte != 255 for byte in raw[total:])
    ):
        raise ValueError("FPGA FIT header/extent differs")
    names = raw[strings_off : strings_off + strings_size]
    cursor, end = off, off + size
    stack, props, nodes = [], {}, set()

    def string(data, at):
        stop = data.find(b"\0", at)
        if stop < 0:
            raise ValueError("unterminated FDT string")
        return data[at:stop].decode("ascii"), stop + 1

    finished = False
    while cursor + 4 <= end:
        token = struct.unpack_from(">I", raw, cursor)[0]
        cursor += 4
        if token == 1:
            name, cursor = string(raw[:end], cursor)
            cursor = (cursor + 3) & ~3
            stack.append(name)
            path = "/" + "/".join(stack[1:])
            if path in nodes or (len(stack) == 1 and name):
                raise ValueError("duplicate/root FDT node")
            nodes.add(path)
        elif token == 2:
            if not stack:
                raise ValueError("unbalanced FDT node")
            stack.pop()
        elif token == 3:
            if not stack or cursor + 8 > end:
                raise ValueError("FDT property header")
            length, nameoff = struct.unpack_from(">II", raw, cursor)
            cursor += 8
            if nameoff >= len(names) or cursor + length > end:
                raise ValueError("FDT property extent")
            name, _ = string(names, nameoff)
            key = ("/" + "/".join(stack[1:]), name)
            if key in props:
                raise ValueError("duplicate FDT property")
            props[key] = raw[cursor : cursor + length]
            cursor = (cursor + length + 3) & ~3
        elif token == 4:
            continue
        elif token == 9:
            if stack:
                raise ValueError("unfinished FDT tree")
            finished = True
            break
        else:
            raise ValueError("unknown FDT token")
    if not finished or nodes != {
        "/",
        "/images",
        "/images/system-bit",
        "/images/system-bit/hash-1",
    }:
        raise ValueError("unexpected FPGA FIT image inventory")
    if len(props.get(("/", "timestamp"), b"")) != 4:
        raise ValueError("FPGA FIT lacks the U-Boot timestamp property")
    path = "/images/system-bit"
    for key, value in (
        ("type", b"firmware\0"),
        ("arch", b"arm\0"),
        ("compression", b"none\0"),
    ):
        if props.get((path, key)) != value:
            raise ValueError("FPGA FIT payload dialect differs")
    data = props.get((path, "data"), b"")
    digest = bytes.fromhex(fabric.BITSTREAM_SHA256)
    if (
        len(data) != fabric.BITSTREAM_SIZE
        or hashlib.sha256(data).digest() != digest
        or props.get((path + "/hash-1", "algo")) != b"sha256\0"
        or props.get((path + "/hash-1", "value")) != digest
    ):
        raise ValueError("FPGA FIT payload or verified hash differs")


def transition(
    before: dict[str, str], current: int, transaction_id: str | None = None
) -> tuple[dict, bytes, bytes]:
    if current not in (1, 2) or before.get("firmware") != str(current):
        raise ValueError("native source selector does not match running slot")
    if before.get("upgrade_stage") or before.get("first_boot"):
        raise ValueError("current native slot must complete its boot commit before OTA")
    if before.get("nandboot") == "run dcent_native_dispatch":
        previous = int(before.get("dcent_native_previous", "0"))
        expected = native_environment(
            previous, before.get("dcent_native_transaction", "")
        )
    else:
        expected = fabric.nand_boot_environment(
            current, before.get("dcent_vendor_nandboot", "")
        )
    if any(before.get(key) != value for key, value in expected.items()):
        raise ValueError("source native boot tuple differs from its canonical producer")
    updated = native_environment(current, transaction_id or secrets.token_hex(32))
    changed = (
        LEGACY_KEYS
        | BOOT_SCRATCH_KEYS
        | updated.keys()
        | {"firmware", "first_boot", "upgrade_stage"}
    )
    desired = {
        **updated,
        "firmware": str(3 - current),
        "first_boot": "yes",
        "upgrade_stage": "0",
    }
    forward = "".join(
        f"{key}={desired.get(key, '')}\n" for key in sorted(changed)
    ).encode()
    rollback = "".join(
        f"{key}={before.get(key, '')}\n" for key in sorted(changed)
    ).encode()
    receipt = {
        "schema": "dcentos.am2-native-ota-boot.v1",
        "previous_firmware": current,
        "destination_firmware": 3 - current,
        "before": {key: before.get(key) for key in sorted(changed)},
        "after": {key: desired.get(key) for key in sorted(changed)},
        "unchanged": {
            key: value for key, value in before.items() if key not in changed
        },
    }
    return receipt, forward, rollback


def validate_receipt(receipt: dict) -> None:
    """Treat retained JSON as data; regenerate every executable boot command."""
    if receipt.get("schema") != "dcentos.am2-native-ota-boot.v1":
        raise ValueError("native OTA receipt schema differs")
    before = receipt.get("before", {})
    unchanged = receipt.get("unchanged", {})
    if (
        not isinstance(before, dict)
        or not isinstance(unchanged, dict)
        or set(before) & set(unchanged)
        or any(
            not isinstance(k, str)
            or not re.fullmatch(r"[A-Za-z0-9_]+", k)
            or not isinstance(v, str)
            or any(c in v for c in "\0\r\n")
            for k, v in unchanged.items()
        )
    ):
        raise ValueError("invalid unchanged environment inventory")
    full = {**unchanged, **{k: v for k, v in before.items() if v is not None}}
    canonical, _, _ = transition(
        full,
        receipt["previous_firmware"],
        receipt.get("after", {}).get("dcent_native_transaction", ""),
    )
    if any(receipt.get(key) != value for key, value in canonical.items()):
        raise ValueError(
            "receipt contains noncanonical boot commands or selector history"
        )
    validate_preparation_binding(receipt)


JOB_ENV_KEYS = (
    "DCENT_UPDATE_JOB_ID",
    "DCENT_UPDATE_JOB_PACKAGE_SHA256",
    "DCENT_UPDATE_JOB_SOURCE_BOOT_ID",
)
JOB_BINDING_SCHEMA = "dcentos.am2-update-job-binding.v1"


def canonical_uuid(value: str) -> str:
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("a canonical UUID is required")
    return value


def canonical_sha256(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("a lowercase SHA256 is required")
    return value


def validate_preparation_binding(receipt: dict) -> None:
    # Old receipts remain usable for rollback. Newly prepared transactions
    # always include both measured package identity and actual source boot.
    present = [key in receipt for key in ("package_sha256", "source_boot_id")]
    if any(present) and not all(present):
        raise ValueError("incomplete package/source boot binding")
    if all(present):
        canonical_sha256(receipt["package_sha256"])
        canonical_uuid(receipt["source_boot_id"])
    if "job_binding" not in receipt:
        return
    job = receipt["job_binding"]
    if (
        not all(present)
        or not isinstance(job, dict)
        or set(job)
        != {
            "schema",
            "job_id",
            "package_sha256",
            "source_boot_id",
            "native_transaction",
        }
    ):
        raise ValueError("native update job binding inventory differs")
    canonical_uuid(job["job_id"])
    if (
        job["schema"] != JOB_BINDING_SCHEMA
        or job["package_sha256"] != receipt["package_sha256"]
        or job["source_boot_id"] != receipt["source_boot_id"]
        or job["native_transaction"] != receipt["after"]["dcent_native_transaction"]
    ):
        raise ValueError("native update job binding differs from this transaction")


def bind_preparation(
    receipt: dict, package_sha256: str, source_boot_id: str, environment: dict[str, str]
) -> dict:
    """Bind a newly prepared boot transaction to the measured updater input."""
    if any(
        key in receipt for key in ("package_sha256", "source_boot_id", "job_binding")
    ):
        raise ValueError("an existing native preparation cannot be rebound")
    canonical_sha256(package_sha256)
    canonical_uuid(source_boot_id)
    result = {
        **receipt,
        "package_sha256": package_sha256,
        "source_boot_id": source_boot_id,
    }
    present = [key in environment for key in JOB_ENV_KEYS]
    if any(present):
        if not all(present):
            raise ValueError("all three update job identity fields are required")
        job_id, expected_package, expected_boot = (
            environment[key] for key in JOB_ENV_KEYS
        )
        canonical_uuid(job_id)
        if expected_package != package_sha256 or expected_boot != source_boot_id:
            raise ValueError(
                "update job does not own this measured package/source boot"
            )
        result["job_binding"] = {
            "schema": JOB_BINDING_SCHEMA,
            "job_id": job_id,
            "package_sha256": package_sha256,
            "source_boot_id": source_boot_id,
            "native_transaction": receipt["after"]["dcent_native_transaction"],
        }
    validate_receipt(result)
    return result


def verify_committed(
    receipt: dict,
    actual: dict[str, str],
    cmdline: str,
    boot_id: str,
    *,
    expected_job_id: str | None = None,
    expected_package_sha256: str | None = None,
    expected_source_boot_id: str | None = None,
) -> dict:
    """Verify a later native boot's committed environment, never ASIC hashing."""
    validate_receipt(receipt)
    canonical_uuid(boot_id)
    if "source_boot_id" not in receipt or "package_sha256" not in receipt:
        raise ValueError("receipt has no measured package/source boot binding")
    if receipt["source_boot_id"] == boot_id:
        raise ValueError("the source boot cannot prove the new boot committed")
    current = receipt["destination_firmware"]
    validate_cmdline(cmdline, current)
    if "first_boot" in actual or "upgrade_stage" in actual:
        raise ValueError("new native boot has not cleared both commit flags")
    expected = {
        **receipt["unchanged"],
        **{k: v for k, v in receipt["after"].items() if v is not None},
    }
    for key in BOOT_SCRATCH_KEYS | {"first_boot", "upgrade_stage"}:
        expected.pop(key, None)
    observed = {k: v for k, v in actual.items() if k not in BOOT_SCRATCH_KEYS}
    if observed != expected:
        raise ValueError(
            "committed native environment differs from the complete transaction"
        )
    expectations = (expected_job_id, expected_package_sha256, expected_source_boot_id)
    if any(value is not None for value in expectations):
        if not all(value is not None for value in expectations):
            raise ValueError(
                "expected job identity requires job, package and source boot"
            )
        canonical_uuid(expected_job_id)
        canonical_sha256(expected_package_sha256)
        canonical_uuid(expected_source_boot_id)
        job = receipt.get("job_binding", {})
        if (
            job.get("job_id"),
            job.get("package_sha256"),
            job.get("source_boot_id"),
        ) != expectations:
            raise ValueError(
                "committed native transaction does not belong to the expected update job"
            )
    return {
        "schema": "dcentos.am2-native-boot-commit-observation.v1",
        "package_sha256": receipt["package_sha256"],
        "source_boot_id": receipt["source_boot_id"],
        "observed_boot_id": boot_id,
        "firmware": current,
        "native_transaction": receipt["after"]["dcent_native_transaction"],
        "job_id": receipt.get("job_binding", {}).get("job_id"),
        "boot_environment_committed": True,
        "physical_hashing_verified": False,
    }


def verify_environment(receipt: dict, actual: dict[str, str], state: str) -> None:
    validate_receipt(receipt)
    expected = {
        **receipt["unchanged"],
        **{k: v for k, v in receipt[state].items() if v is not None},
    }
    if actual != expected:
        raise ValueError("complete native OTA environment differs")


def rollback_script(receipt: dict, actual: dict[str, str], current: int) -> bytes:
    validate_receipt(receipt)
    # S99 may have committed the new boot; U-Boot may have fallen back once.
    # Every helper and the transaction nonce must still belong to this update.
    if current not in (receipt["previous_firmware"], receipt["destination_firmware"]):
        raise ValueError("rollback running slot differs")
    if actual.get("firmware") != str(current):
        raise ValueError("rollback cannot race an already pending selector change")
    expected = {
        **receipt["unchanged"],
        **{k: v for k, v in receipt["after"].items() if v is not None},
    }
    ignored = {"firmware", "first_boot", "upgrade_stage"} | BOOT_SCRATCH_KEYS
    for key in ignored:
        expected.pop(key, None)
    comparable = {k: v for k, v in actual.items() if k not in ignored}
    if (
        comparable != expected
        or actual.get("upgrade_stage") not in (None, "0", "1")
        or actual.get("first_boot") not in (None, "yes")
    ):
        raise ValueError(
            "rollback receipt does not own the complete live native transaction"
        )
    return "".join(
        f"{key}={value or ''}\n" for key, value in sorted(receipt["before"].items())
    ).encode("ascii")


def validate_cmdline(raw: str, current: int) -> None:
    for key, expected in (
        ("ubi.mtd", str(6 + current)),
        ("dcent.fpga_load_completed", "1"),
        ("dcent.fpga_sha256", fabric.BITSTREAM_SHA256),
    ):
        values = re.findall(r"(?:^|\s)" + re.escape(key) + r"=([^\s]+)", raw)
        if values != [expected]:
            raise ValueError(
                "current native boot does not attest the exact FPGA/slot pair"
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    prepare = subs.add_parser("prepare")
    for name in ("bitstream", "active-fpga", "environment", "output", "cmdline"):
        prepare.add_argument("--" + name, type=Path, required=True)
    prepare.add_argument("--current", type=int, choices=(1, 2), required=True)
    prepare.add_argument("--package-sha256", required=True)
    verify = subs.add_parser("verify-environment")
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--environment", type=Path, required=True)
    verify.add_argument("--state", choices=("before", "after"), required=True)
    committed = subs.add_parser("verify-committed")
    for name in ("receipt", "environment"):
        committed.add_argument("--" + name, type=Path, required=True)
    committed.add_argument("--cmdline", type=Path, default=Path("/proc/cmdline"))
    committed.add_argument(
        "--boot-id", type=Path, default=Path("/proc/sys/kernel/random/boot_id")
    )
    for name in (
        "expected-job-id",
        "expected-package-sha256",
        "expected-source-boot-id",
    ):
        committed.add_argument("--" + name)
    payload = subs.add_parser("verify-payload")
    payload.add_argument("bitstream", type=Path)
    rollback = subs.add_parser("rollback-script")
    for name in ("receipt", "environment", "previous-fpga", "cmdline", "output"):
        rollback.add_argument("--" + name, type=Path, required=True)
    rollback.add_argument("--current", type=int, choices=(1, 2), required=True)
    previous_slot = subs.add_parser("previous-slot")
    previous_slot.add_argument("--receipt", type=Path, required=True)
    running_slot = subs.add_parser("running-slot")
    running_slot.add_argument("--cmdline", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "previous-slot":
        receipt = json.loads(args.receipt.read_text())
        validate_receipt(receipt)
        print(receipt["previous_firmware"])
        return
    if args.command == "running-slot":
        raw = args.cmdline.read_text()
        matches = re.findall(r"(?:^|\s)ubi.mtd=([78])(?:\s|$)", raw)
        if len(matches) != 1:
            raise ValueError("one native running firmware is required")
        current = int(matches[0]) - 6
        validate_cmdline(raw, current)
        print(current)
        return
    if args.command == "verify-payload":
        fit_from_raw(args.bitstream.read_bytes())
        return
    if args.command == "verify-environment":
        verify_environment(
            json.loads(args.receipt.read_text()),
            parse_environment(args.environment.read_bytes()),
            args.state,
        )
        return
    if args.command == "verify-committed":
        observed = verify_committed(
            json.loads(args.receipt.read_text()),
            parse_environment(args.environment.read_bytes()),
            args.cmdline.read_text(),
            args.boot_id.read_text().strip(),
            expected_job_id=args.expected_job_id,
            expected_package_sha256=args.expected_package_sha256,
            expected_source_boot_id=args.expected_source_boot_id,
        )
        print(json.dumps(observed, sort_keys=True))
        return
    if args.command == "rollback-script":
        receipt = json.loads(args.receipt.read_text())
        validate_cmdline(args.cmdline.read_text(), args.current)
        with args.previous_fpga.open("rb") as handle:
            previous = handle.read(2097153)
        validate_fit(previous)
        if hashlib.sha256(previous).hexdigest() != receipt.get("active_fpga_sha256"):
            raise ValueError(
                "previous native FPGA partition changed since OTA preparation"
            )
        result = rollback_script(
            receipt, parse_environment(args.environment.read_bytes()), args.current
        )
        with args.output.open("xb") as handle:
            handle.write(result)
        return
    with args.active_fpga.open("rb") as handle:
        active = handle.read(2097153)
    validate_fit(active)
    validate_cmdline(args.cmdline.read_text(), args.current)
    incoming = fit_from_raw(args.bitstream.read_bytes())
    before = parse_environment(args.environment.read_bytes())
    receipt, forward, rollback = transition(before, args.current)
    receipt = bind_preparation(
        receipt,
        args.package_sha256,
        Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        os.environ,
    )
    args.output.mkdir(mode=0o700)
    for name, data in (
        ("am2-fabric.itb", incoming),
        ("env.change", forward),
        ("env.rollback", rollback),
    ):
        with (args.output / name).open("xb") as handle:
            handle.write(data)
    receipt.update(
        fpga_sha256=hashlib.sha256(incoming).hexdigest(),
        active_fpga_sha256=hashlib.sha256(active).hexdigest(),
    )
    with (args.output / "receipt.json").open("x") as handle:
        json.dump(receipt, handle, sort_keys=True, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    main()
