#!/usr/bin/env python3
"""Current release producers and their strict, path-bounded result contract.

This contract is independent of frozen portable-evidence v1/v2. A producer
declares an artifact route, never first-install or physical qualification.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from types import MappingProxyType


PROFILE = "dcentos-release-producer-result/v1"
COHORT_PROFILE = "dcentos-release-producer-cohort/v1"
MAX_ARTIFACT = 64 * 1024**3
MAX_RESULT = 1024**2
ROLES = ("primary", "primary_signature", "runtime_manifest", "runtime_signature")


class ProducerError(ValueError):
    pass


@dataclass(frozen=True)
class Producer:
    producer: str
    board_target: str
    build_target: str
    cargo_variant: str
    artifact_kind: str
    primary_artifact: str
    release_stem: str
    install_route: str
    input_profile: str
    reproducible: bool = False
    hardware_recipe: str = "board-default"
    runtime_root: str = "sysupgrade-root"


def _table() -> dict[str, Producer]:
    rows = [
        Producer("s9", "am1-s9", "s9", "zynq", "sysupgrade-tar",
                 "dcentos-unit.tar", "DCENTOS_XIL1_S9",
                 "first_install_and_self_update", "s9", True),
        Producer("am2-s19jpro", "am2-s19j", "am2-s19jpro", "zynq", "sysupgrade-tar",
                 "dcentos-sysupgrade-am2-s19jpro.tar", "DCENTOS_XIL3_S19jPro",
                 "self_update_only", "am2-s19jpro", True),
    ]
    for model, stem in (("s9i", "S9i"), ("s9j", "S9j"), ("s9se", "S9SE"),
                        ("s9k", "S9k"), ("s15", "S15"), ("t15", "T15")):
        board = "am1-" + model
        rows.append(Producer(board, board, board, "zynq", "native-sd-image",
                             "dcentos-sd.img", "DCENTOS_XIL1_" + stem,
                             "sd_trial_boot_only", board,
                             runtime_root="fat-ramdisk" if model in ("s9i", "s9j") else "partition2-ext2"))
    for board, build, basename, stem in (
        ("am2-s17p", "am2-s17pro", "s17pro", "DCENTOS_XIL2_S17"),
        ("am2-s17plus", "am2-s17plus", "s17plus", "DCENTOS_XIL2_S17Plus"),
        ("am2-t17", "am2-t17", "t17", "DCENTOS_XIL2_T17"),
        ("am2-t17plus", "am2-t17plus", "t17plus", "DCENTOS_XIL2_T17Plus"),
        ("am2-s19pro", "am2-s19pro", "s19pro", "DCENTOS_XIL3_S19Pro"),
        ("am2-s19", "am2-s19", "s19", "DCENTOS_XIL3_S19"),
        ("am2-t19", "am2-t19", "t19", "DCENTOS_XIL3_T19"),
        ("am2-s19a", "am2-s19a", "s19a", "DCENTOS_XIL3_S19a"),
        ("am2-s19plus", "am2-s19plus", "s19plus", "DCENTOS_XIL3_S19Plus"),
    ):
        rows.append(Producer(board, board, build, "zynq", "native-sd-image",
                             f"dcentos-{basename}-sd.img", stem,
                             "sd_trial_boot_only", build, runtime_root="partition2-squashfs"))
    for model, stem in (("t17e", "T17e"), ("s17e", "S17e")):
        board = "am2-" + model
        rows.append(Producer(board, board, board, "zynq", "native-sd-image",
                             "dcentos-sd.img", "DCENTOS_XIL2_" + stem, "sd_trial_boot_only", board,
                             runtime_root="partition2-ext2"))
    for board, build, stem in (
        ("am3-s19k", "am3-s19kpro", "S19kPro"),
        ("am3-s19xp", "am3-s19xp", "S19XP"),
        ("am3-s19jxp", "am3-s19jxp", "S19jXP"),
        ("am3-s19jproa", "am3-s19jproa", "S19jProA"),
        ("am3-s19jproplus", "am3-s19jproplus", "S19jProPlus"),
        ("am3-s19jpro-aml", "am3-s19jpro-aml", "S19jPro"),
        ("am3-s21", "am3-s21", "S21"),
        ("am3-s21pro", "am3-s21pro", "S21Pro"),
        ("am3-s21xp", "am3-s21xp", "S21XP"),
    ):
        rows.append(Producer(board, board, build, "amlogic", "sysupgrade-tar",
                             f"dcentos-sysupgrade-{build}.tar", "DCENTOS_AML3_" + stem,
                             "operator_staged" if board in ("am3-s19xp", "am3-s19jxp", "am3-s19jproa", "am3-s21xp") else "self_update_only", build))
    rows.append(Producer("am3-bb-s19jpro", "am3-bb-s19jpro", "am3-bb-s19jpro-payload",
                         "zynq", "sd-payload-tar", "dcentos-am3-bb-s19jpro-sdcard.tar",
                         "DCENTOS_BB3_S19jPro", "operator_staged", "am3-bb-s19jpro-payload",
                         runtime_root="bb-ramdisk"))
    if len({row.producer for row in rows}) != len(rows) or len({row.board_target for row in rows}) != len(rows):
        raise ProducerError("duplicate producer or board identity")
    return {row.producer: row for row in rows}


PRODUCERS = MappingProxyType(_table())
MISSING_PRODUCERS = MappingProxyType({})


def get_producer(producer: str) -> Producer:
    if not isinstance(producer, str):
        raise ProducerError("exact producer identifier required")
    if producer in MISSING_PRODUCERS:
        raise ProducerError(MISSING_PRODUCERS[producer])
    try:
        return PRODUCERS[producer]
    except (KeyError, TypeError) as error:
        raise ProducerError(f"unknown release producer: {producer!r}") from error


def list_producers() -> tuple[Producer, ...]:
    return tuple(PRODUCERS.values())


def cohort(producers: list[str]) -> tuple[Producer, ...]:
    if (not isinstance(producers, (list, tuple)) or not producers
            or len(producers) > len(PRODUCERS) or any(not isinstance(name, str) for name in producers)
            or len(set(producers)) != len(producers)):
        raise ProducerError("cohort requires unique declared producers")
    rows = tuple(get_producer(name) for name in producers)
    if len({row.cargo_variant for row in rows}) != 1:
        raise ProducerError("one cohort must use exactly one Cargo variant")
    return rows


def release_name(producer: Producer, channel: str, date: str) -> str:
    if channel not in ("beta", "stable") or not re.fullmatch(r"[0-9]{8}", date):
        raise ProducerError("publishable channel and YYYYMMDD date required")
    try:
        dt.datetime.strptime(date, "%Y%m%d")
    except ValueError as error:
        raise ProducerError("invalid release date") from error
    return f"{producer.release_stem}_{channel}{date}"


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ProducerError(f"duplicate result field: {key}")
        value[key] = item
    return value


def _keys(value: object, fields: set[str], subject: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise ProducerError(f"invalid {subject} fields")
    return value


def regular_path(root: Path, relative: str) -> Path:
    """Reject traversal, ambiguous separators and symlinks at every level."""
    if not isinstance(relative, str) or not relative or len(relative) > 1024:
        raise ProducerError("bounded relative file path required")
    parts = PurePosixPath(relative).parts
    if (PurePosixPath(relative).is_absolute() or ":" in relative or "\\" in relative
            or any(part in ("", ".", "..") for part in relative.split("/"))
            or any(ord(char) < 0x20 for char in relative)):
        raise ProducerError("noncanonical result path")
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
    if len(parts) > 16 or any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,200}", part)
                              or part.endswith(".") or part.split(".")[0].lower() in reserved for part in parts):
        raise ProducerError("nonportable result path")
    root = Path(root).absolute()
    if root.is_symlink() or not root.is_dir():
        raise ProducerError("regular result root directory required")
    current = root
    for part in parts:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ProducerError("result path contains a symlink")
    info = current.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ProducerError("single-link regular result file required")
    return current


def file_record(root: Path, relative: str) -> dict:
    path = regular_path(root, relative)
    before = path.stat()
    if not 0 < before.st_size <= MAX_ARTIFACT:
        raise ProducerError("result file outside size bounds")
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        for chunk in iter(lambda: stream.read(1024**2), b""):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    def identity(item):
        return (item.st_dev, item.st_ino, item.st_mode, item.st_nlink,
                item.st_size, item.st_mtime_ns)
    final = path.stat()
    # Python on Windows reports different ctime semantics through stat/fstat.
    # Compare that timestamp within each API, and the file identity across both.
    if (identity(before) != identity(opened) or identity(opened) != identity(after)
            or identity(after) != identity(final) or before.st_ctime_ns != final.st_ctime_ns
            or opened.st_ctime_ns != after.st_ctime_ns):
        raise ProducerError("result file changed while hashing")
    return {"path": relative, "size": before.st_size, "sha256": digest.hexdigest()}


def _identity(producer: Producer, source_commit: str, version: str, channel: str,
              hardware_recipe: str) -> dict:
    import runtime_image_manifest as runtime
    if not isinstance(source_commit, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", source_commit):
        raise ProducerError("full Git source commit required")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.+-]+)?", version):
        raise ProducerError("exact build version required")
    runtime.registry_channel(producer.board_target, channel)
    runtime.validate_hardware_recipe(producer.board_target, hardware_recipe)
    return {"manifest_profile": PROFILE, "producer": producer.producer,
            "board_target": producer.board_target, "build_target": producer.build_target,
            "cargo_variant": producer.cargo_variant, "artifact_kind": producer.artifact_kind,
            "runtime_root": producer.runtime_root,
            "source_commit": source_commit, "version": version, "channel": channel,
            "hardware_recipe": hardware_recipe}


def create_result(root: Path, producer: Producer, source_commit: str, version: str,
                  channel: str, primary: str, ancillary: list[str],
                  hardware_recipe: str = "board-default") -> dict:
    document = _identity(producer, source_commit, version, channel, hardware_recipe)
    names = (primary, primary + ".sig", primary + ".runtime-image.json", primary + ".runtime-image.sig")
    document["files"] = {role: file_record(root, name) for role, name in zip(ROLES, names)}
    document["ancillary"] = [file_record(root, name) for name in ancillary]
    return document


def verify_native_media(artifact: Path, producer: Producer, version: str, channel: str,
                        pubkey: Path, hardware_recipe: str = "board-default") -> dict:
    if producer.artifact_kind != "native-sd-image":
        raise ProducerError("complete native SD producer required")
    toolbox = Path(__file__).resolve().parents[2] / "dcent-toolbox/src"
    if str(toolbox) not in sys.path:
        sys.path.insert(0, str(toolbox))
    if producer.board_target in ("am2-t17e", "am2-s17e"):
        if hardware_recipe != "board-default":
            raise ProducerError("T17e media requires its exact board-default recipe")
        from dcent_toolbox.core.bm1396_sd_media import validate_bm1396_image
        return validate_bm1396_image(artifact, producer.board_target, version=version,
                                    channel=channel, pubkey=pubkey)
    from dcent_toolbox.core.current_native_release import validate_current_native_release
    return validate_current_native_release(artifact, producer.board_target, version=version,
                                           channel=channel, pubkey=pubkey,
                                           hardware_recipe=hardware_recipe)


def _verify_result_payload(document: dict, root: Path, producer: Producer, source_commit: str,
                  version: str, channel: str, pubkey: Path,
                  hardware_recipe: str = "board-default") -> dict:
    """Rejoin expected identity, exact bytes, signatures and packaged runtime."""
    import runtime_image_manifest as runtime
    identity = _identity(producer, source_commit, version, channel, hardware_recipe)
    _keys(document, set(identity) | {"files", "ancillary"}, "producer result")
    if any(document[key] != value for key, value in identity.items()):
        raise ProducerError("producer result identity mismatch")
    files = _keys(document["files"], set(ROLES), "result file roles")
    ancillary = document["ancillary"]
    if not isinstance(ancillary, list) or len(ancillary) > 64:
        raise ProducerError("bounded ancillary file list required")
    seen = set()
    for record in [*files.values(), *ancillary]:
        _keys(record, {"path", "size", "sha256"}, "file record")
        if (type(record["size"]) is not int or not isinstance(record["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])):
            raise ProducerError("invalid result size/digest")
        regular_path(root, record["path"])
        if record["path"].casefold() in seen:
            raise ProducerError("duplicate result file path")
        seen.add(record["path"].casefold())
        if file_record(root, record["path"]) != record:
            raise ProducerError("result file size/digest mismatch")
    primary = files["primary"]["path"]
    if PurePosixPath(primary).name != producer.primary_artifact:
        raise ProducerError("primary artifact does not match producer basename")
    if producer.artifact_kind == "native-sd-image":
        required = {primary + ".manifest.json", str(PurePosixPath(primary).parent / "TESTER_README.txt")}
        if not required <= {record["path"] for record in ancillary}:
            raise ProducerError("native SD media manifest and tester instructions required")
    for role, suffix in (("primary_signature", ".sig"), ("runtime_manifest", ".runtime-image.json"),
                         ("runtime_signature", ".runtime-image.sig")):
        if files[role]["path"] != primary + suffix:
            raise ProducerError("runtime/signature companion path mismatch")
    artifact = regular_path(root, primary)
    runtime.verify_signature(artifact, regular_path(root, files["primary_signature"]["path"]), pubkey)
    # The image/package parser independently verifies the actual in-image pair
    # and executable; a signed sidecar alone is insufficient for publication.
    from release_runtime_exports import verify_artifact_runtime
    verify_artifact_runtime(
        artifact, regular_path(root, files["runtime_manifest"]["path"]),
        regular_path(root, files["runtime_signature"]["path"]), pubkey,
        producer.board_target, channel, version, hardware_recipe)
    if producer.artifact_kind == "native-sd-image":
        verify_native_media(artifact, producer, version, channel, pubkey, hardware_recipe)
    return document


def load_result(path: Path) -> dict:
    import runtime_image_manifest as runtime
    return json.loads(runtime.regular_bytes(path, MAX_RESULT), object_pairs_hook=_unique)


def verify_signed_result(document: dict, root: Path, pubkey: Path) -> None:
    """Bind the external handoff to the signed, in-directory producer result.

    Runtime signatures bind executable identity; this signature additionally
    binds the source commit, producer route and ancillary files. Paths differ
    only by the release-directory prefix in the external handoff.
    """
    import runtime_image_manifest as runtime
    directory = PurePosixPath(document["files"]["primary"]["path"]).parent
    result_path = str(directory / "producer-result.json")
    signature_path = result_path + ".sig"
    authority = {result_path, signature_path}
    if not authority <= {record["path"] for record in document["ancillary"]}:
        raise ProducerError("signed producer result and signature required for publication")
    subject = regular_path(root, result_path)
    runtime.verify_signature(subject, regular_path(root, signature_path), pubkey)
    def relative(record):
        path = PurePosixPath(record["path"])
        if path.parent != directory:
            raise ProducerError("producer result members must share one release directory")
        return {**record, "path": path.name}
    expected = {key: value for key, value in document.items() if key not in ("files", "ancillary")}
    expected["files"] = {role: relative(record) for role, record in document["files"].items()}
    expected["ancillary"] = [relative(record) for record in document["ancillary"] if record["path"] not in authority]
    if load_result(subject) != expected:
        raise ProducerError("external result differs from signed producer identity or files")


def verify_result(document: dict, root: Path, producer: Producer, source_commit: str,
                  version: str, channel: str, pubkey: Path,
                  hardware_recipe: str = "board-default") -> dict:
    """Verify publishable bytes and the signed source/producer result binding."""
    _verify_result_payload(document, root, producer, source_commit, version, channel, pubkey, hardware_recipe)
    verify_signed_result(document, root, pubkey)
    return document


def verify_cohort(document: dict, root: Path, producers: list[str], source_commit: str,
                  version: str, channel: str, pubkey: Path,
                  hardware_recipe: str = "board-default") -> dict:
    rows = cohort(producers)
    _keys(document, {"manifest_profile", "cargo_variant", "source_commit", "version", "channel", "results"}, "producer cohort")
    if (document["manifest_profile"], document["cargo_variant"], document["source_commit"], document["version"], document["channel"]) != (
            COHORT_PROFILE, rows[0].cargo_variant, source_commit, version, channel):
        raise ProducerError("cohort identity mismatch")
    results = document["results"]
    if not isinstance(results, list) or len(results) != len(rows):
        raise ProducerError("cohort must contain every selected producer exactly once")
    for row, result in zip(rows, results):
        verify_result(result, root, row, source_commit, version, channel, pubkey, hardware_recipe)
    return document


def host_path_text(value: str) -> str:
    """Rewrite Git-Bash (MSYS) drive paths (/d/dir) and long-path prefixes.

    MSYS automatic argument conversion is per-argument and inconsistent on
    long release command lines (producer runs drop1-20260916-cyg3sjwi and
    drop1-20260917-gnscaudk; the same fix landed in rust_dependency_inventory
    commit b1ae659fa and source_closure commit 4fd3d8b0e). Producer result
    paths arrive as argparse ``type=Path`` values whose spelling is already
    consumed, so normalization happens in the type converter at the parse
    layer, making the shell conversion behavior irrelevant. POSIX and native
    inputs are returned unchanged; on non-Windows hosts this is the identity.
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



def host_path(value: str) -> Path:
    """argparse Path type normalized through host_path_text."""
    return Path(host_path_text(value))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("list")
    query = actions.add_parser("query")
    query.add_argument("producer")
    query.add_argument("field", choices=tuple(Producer.__dataclass_fields__))
    native = actions.add_parser("verify-native-media")
    for option in ("producer", "version", "channel"):
        native.add_argument("--" + option, required=True)
    for option in ("artifact", "pubkey"):
        native.add_argument("--" + option, type=host_path, required=True)
    native.add_argument("--hardware-recipe", default="board-default")
    for action in ("create-cohort-result", "verify-cohort-result"):
        grouped = actions.add_parser(action)
        grouped.add_argument("--producer", action="append", required=True)
        if action == "create-cohort-result":
            grouped.add_argument("--member-result", type=host_path, action="append", required=True)
        for option in ("source-commit", "version", "channel"):
            grouped.add_argument("--" + option, required=True)
        for option in ("root", "result-json", "pubkey"):
            grouped.add_argument("--" + option, type=host_path, required=True)
        grouped.add_argument("--hardware-recipe", default="board-default")
    for action in ("create-result", "verify-result"):
        sub = actions.add_parser(action)
        for option in ("producer", "source-commit", "version", "channel"):
            sub.add_argument("--" + option, required=True)
        sub.add_argument("--root", type=host_path, required=True)
        sub.add_argument("--result-json", type=host_path, required=True)
        sub.add_argument("--pubkey", type=host_path, required=True)
        sub.add_argument("--hardware-recipe", default="board-default")
        if action == "create-result":
            sub.add_argument("--primary", required=True)
            sub.add_argument("--ancillary", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        if args.action == "list":
            print(json.dumps({"producers": [asdict(row) for row in list_producers()],
                              "missing_producers": dict(MISSING_PRODUCERS)}, sort_keys=True, indent=2))
        elif args.action == "query":
            value = getattr(get_producer(args.producer), args.field)
            print(str(value).lower() if isinstance(value, bool) else value)
        elif args.action == "verify-native-media":
            result = verify_native_media(args.artifact, get_producer(args.producer),
                                         args.version, args.channel, args.pubkey, args.hardware_recipe)
            print(json.dumps(result, sort_keys=True))
        elif args.action in ("create-cohort-result", "verify-cohort-result"):
            rows = cohort(args.producer)
            if args.action == "create-cohort-result":
                document = {"manifest_profile": COHORT_PROFILE, "cargo_variant": rows[0].cargo_variant,
                            "source_commit": args.source_commit, "version": args.version, "channel": args.channel,
                            "results": [load_result(path) for path in args.member_result]}
            else:
                document = load_result(args.result_json)
            verify_cohort(document, args.root, args.producer, args.source_commit, args.version,
                          args.channel, args.pubkey, args.hardware_recipe)
            if args.action == "create-cohort-result":
                with args.result_json.open("x", encoding="utf-8", newline="\n") as stream:
                    stream.write(json.dumps(document, sort_keys=True, indent=2) + "\n")
            print(json.dumps(document, sort_keys=True))
        else:
            producer = get_producer(args.producer)
            if args.action == "create-result":
                document = create_result(args.root, producer, args.source_commit, args.version,
                                         args.channel, args.primary, args.ancillary, args.hardware_recipe)
            else:
                document = load_result(args.result_json)
            verifier = _verify_result_payload if args.action == "create-result" else verify_result
            verifier(document, args.root, producer, args.source_commit, args.version,
                     args.channel, args.pubkey, args.hardware_recipe)
            if args.action == "create-result":
                with args.result_json.open("x", encoding="utf-8", newline="\n") as stream:
                    stream.write(json.dumps(document, sort_keys=True, indent=2) + "\n")
            print(json.dumps(document, sort_keys=True))
        return 0
    except (ValueError, OSError) as error:
        print("ERROR: release producer: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
