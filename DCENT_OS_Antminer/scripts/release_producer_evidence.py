#!/usr/bin/env python3
"""Retain and audit current producer source evidence after private cleanup.

The signed producer result owns the exact file set. These projections establish
consistency with trusted Git and signed build receipts, not build causality,
reproducibility, physical qualification, or surviving private authority.
Historical portable-evidence v1/v2 contracts remain independent.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import sys

import binary_build_receipt
import build_input_snapshot
import portable_release_evidence as projections
import release_capsule_lineage
import release_invocation
import release_producer as producer
import release_result_stage
import release_set_publication
import source_closure
import source_snapshot


PROJECTION_NAMES = (projections.SOURCE_NAME, projections.INVOCATION_NAME,
                    projections.CARGO_INPUT_NAME, projections.RESULT_NAME)


def retain_live(args: argparse.Namespace) -> None:
    """Copy only canonical audit descriptors while their live owners exist."""
    directory, _ = release_set_publication.safe_directory(args.artifact_dir, "producer stage")
    source_snapshot.verify_against_git(Path(args.repo_root), args.source_commit,
                                       Path(args.source_snapshot))
    invocation = release_invocation.verify_invocation(Path(args.release_invocation))
    cargo = build_input_snapshot.verify_snapshot(Path(args.cargo_input_snapshot), "cargo-workspace")
    if cargo.get("schema") != build_input_snapshot.SPLIT_AUTHORITY_SCHEMA:
        raise ValueError("split-authority Cargo input snapshot required")
    result = release_result_stage.verify_result_stage(Path(args.result_stage),
                                                     Path(args.release_invocation))
    if result.descriptor["state"] != "sealed":
        raise ValueError("sealed Cargo result required before audit retention")
    values = (
        projections.read_canonical(Path(args.source_snapshot), "source snapshot",
                                   source_snapshot.MAX_DESCRIPTOR_BYTES),
        invocation.descriptor, cargo, release_result_stage.audit_projection(result),
    )
    for name, value in zip(PROJECTION_NAMES, values):
        projections.write_exclusive(directory / name, projections.canonical_bytes(value))


def verify_exact_set(document: dict, root: Path, row: producer.Producer) -> Path:
    """Rejoin the sealed directory to every member of the signed result."""
    parent = PurePosixPath(document["files"]["primary"]["path"]).parent
    directory = producer.regular_path(root, document["files"]["primary"]["path"]).parent
    if directory.name != producer.release_name(row, document["channel"], directory.name[-8:]):
        raise ValueError("published directory does not match producer/channel/date")
    expected = []
    for record in [*document["files"].values(), *document["ancillary"]]:
        path = PurePosixPath(record["path"])
        if path.parent != parent:
            raise ValueError("producer evidence must remain in its exact release directory")
        expected.append({"name": path.name, "size": record["size"], "sha256": record["sha256"]})
    expected.sort(key=lambda record: record["name"])
    descriptor = projections.read_canonical(directory / release_set_publication.DESCRIPTOR_NAME,
                                            "sealed producer set", release_set_publication.MAX_JSON_BYTES)
    if (set(descriptor) != {"schema", "state", "stage_id", "capability_sha256", "output_name", "files"}
            or descriptor["schema"] != release_set_publication.STAGE_SCHEMA
            or descriptor["state"] != "sealed" or descriptor["output_name"] != directory.name):
        raise ValueError("invalid sealed producer descriptor")
    try:
        release_set_publication.validate_hex(descriptor["stage_id"], "producer stage ID", 32)
        release_set_publication.validate_hex(descriptor["capability_sha256"], "producer capability digest", 64)
        declared = release_set_publication.validate_file_entries(descriptor["files"], "producer set")
    except release_set_publication.ReleaseSetError as error:
        raise ValueError(str(error)) from error
    if declared != expected:
        raise ValueError("sealed producer set differs from signed result members")
    names = {record["name"] for record in expected} | {release_set_publication.DESCRIPTOR_NAME}
    if {path.name for path in directory.iterdir()} != names:
        raise ValueError("published producer directory has missing or extra members")
    for name in names:
        producer.regular_path(root, str(parent / name))
    return directory


def verify_retained_result_pair(result: dict, entry: dict, receipt: dict) -> None:
    """Join a source-authenticated retained pair to its sealed Cargo paths."""
    binary_path = f"target/{entry['target_triple']}/{entry['profile']}/{entry['name']}"
    if receipt["binary"]["path"] != binary_path:
        raise ValueError("retained Cargo receipt has a noncanonical binary path")
    records = {record["path"]: record for record in result["manifest"]["files"]}
    for role, path in (("binary", binary_path),
                       ("receipt", binary_path + binary_build_receipt.RECEIPT_SUFFIX)):
        actual = records.get(path)
        if actual is None or any(actual[field] != entry[role][field] for field in ("size", "sha256")):
            raise ValueError("sealed Cargo result differs from retained " + role + ": " + entry["name"])


def verify_installed_daemon(directory: Path, row: producer.Producer, closure: dict,
                            pubkey: Path, version: str, channel: str,
                            hardware_recipe: str = "board-default") -> None:
    """Independently parse the package and compare its daemon to retained Cargo."""
    from release_runtime_exports import verify_artifact_runtime
    artifact = directory / row.primary_artifact
    runtime = verify_artifact_runtime(artifact, Path(str(artifact) + ".runtime-image.json"),
        Path(str(artifact) + ".runtime-image.sig"), pubkey, row.board_target,
        channel, version, hardware_recipe)
    entries = [entry for entry in closure["prebuilt_rust_inputs"]["entries"]
               if entry["name"] == "dcentrald"]
    if len(entries) != 1 or any(runtime["daemon_" + field] != entries[0]["binary"][field]
                                for field in ("size", "sha256")):
        raise ValueError("actual packaged daemon differs from retained Cargo daemon")


def verify_compiled_feed_base(receipt: dict, expected: str | None) -> None:
    """Join explicit build selection to the authenticated compile inventory."""
    entries = receipt.get("compile_environment", {}).get("entries")
    if not isinstance(entries, dict):
        raise ValueError("retained compile environment is absent")
    if expected is not None:
        from release_channel_feed import feed
        feed.https_url(expected)
    if ((expected is None and "DCENT_UPDATE_FEED_BASE_URL" in entries)
            or entries.get("DCENT_UPDATE_FEED_BASE_URL") != expected):
        raise ValueError("compiled channel base differs from the explicit release selection")


def verify_audit_contents(directory: Path, row: producer.Producer, source_commit: str,
                          logical_name: str, repo_root: Path, pubkey: Path,
                          expected_feed_base_url: str | None = None) -> dict:
    """Validate retained source/build lineage; caller authenticates the set."""
    closure_path = directory / (row.primary_artifact + ".source-closure.json")
    closure = source_closure.validate_receipt_schema(
        projections.read_canonical(closure_path, "producer source closure"))
    if (closure.get("schema") != source_closure.SCHEMA
            or closure["source"]["commit"] != source_commit
            or closure["build"]["target"] != row.build_target
            or closure["prebuilt_rust_inputs"]["packaging_artifact"] != row.primary_artifact):
        raise ValueError("producer source closure identity mismatch")
    invocation = release_invocation.verify_audit_descriptor(directory / projections.INVOCATION_NAME)
    if invocation["logical_name"] != logical_name:
        raise ValueError("producer invocation differs from selected cohort owner")
    cargo = build_input_snapshot.verify_audit_descriptor(directory / projections.CARGO_INPUT_NAME,
                                                         "cargo-workspace")
    packaging = build_input_snapshot.verify_audit_descriptor(directory / projections.PACKAGING_INPUT_NAME,
                                                             row.build_target)
    if any(value.get("schema") != build_input_snapshot.SPLIT_AUTHORITY_SCHEMA for value in (cargo, packaging)):
        raise ValueError("split-authority input projections required")
    result = projections.read_canonical(directory / projections.RESULT_NAME, "Cargo result projection")
    release_result_stage.verify_audit_projection(result, invocation)
    snapshot = projections.read_canonical(directory / projections.SOURCE_NAME, "source projection",
                                          source_snapshot.MAX_DESCRIPTOR_BYTES)
    capsule = release_capsule_lineage.validate_release_capsule({
        "schema": release_capsule_lineage.SCHEMA,
        "release_invocation_descriptor_sha256": release_invocation.sha256_bytes(
            release_invocation.canonical_bytes(invocation)),
        "release_invocation_id": invocation["invocation_id"],
        "source_snapshot_id": snapshot["snapshot_id"],
        "source_snapshot_descriptor_sha256": source_snapshot.sha256_bytes(source_snapshot.canonical_bytes(snapshot)),
    })
    if capsule != closure["release_capsule"]:
        raise ValueError("producer audit projections differ from signed source capsule")
    source_closure.verify_portable_manifest(argparse.Namespace(
        repo_root=str(repo_root), artifact_dir=str(directory),
        source_snapshot_projection=str(directory / projections.SOURCE_NAME),
        release_invocation_projection=str(directory / projections.INVOCATION_NAME),
        build_input_projection=str(directory / projections.PACKAGING_INPUT_NAME),
        signature=str(closure_path) + ".sig", public_key=str(pubkey), manifest=str(closure_path)))
    cargo_evidence = build_input_snapshot.snapshot_evidence(cargo)
    for entry in closure["prebuilt_rust_inputs"]["entries"]:
        receipt = projections.read_canonical(directory / entry["receipt"]["path"], "retained Cargo receipt")
        if receipt.get("build_inputs", {}).get("evidence") != cargo_evidence:
            raise ValueError("retained build receipt differs from Cargo input projection")
        verify_retained_result_pair(result, entry, receipt)
        verify_compiled_feed_base(receipt, expected_feed_base_url)
    return closure


def verify_cohort_evidence(document: dict, root: Path, names: list[str], source_commit: str,
                           version: str, channel: str, pubkey: Path, repo_root: Path,
                           hardware_recipe: str = "board-default", expected_feed_base_url: str | None = None) -> None:
    producer.verify_cohort(document, root, names, source_commit, version, channel, pubkey, hardware_recipe)
    rows = producer.cohort(names)
    for row, member in zip(rows, document["results"]):
        directory = verify_exact_set(member, root, row)
        closure = verify_audit_contents(directory, row, source_commit, rows[0].build_target, repo_root, pubkey, expected_feed_base_url)
        verify_installed_daemon(directory, row, closure, pubkey, version, channel, hardware_recipe)


def host_path_text(value: str) -> str:
    """Rewrite Git-Bash (MSYS) drive paths (/d/dir) and long-path prefixes.

    MSYS automatic argument conversion is per-argument and inconsistent on
    long release command lines (producer runs drop1-20260916-cyg3sjwi and
    drop1-20260917-gnscaudk; the same fix landed in rust_dependency_inventory
    commit b1ae659fa and source_closure commit 4fd3d8b0e). Evidence paths are
    fed directly into the strict stage/snapshot verifiers, so the raw
    strings are normalized here at the parse layer before any pathlib
    conversion. POSIX and native inputs are returned unchanged; on
    non-Windows hosts this is the identity.
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


def normalize_host_path_args(args: argparse.Namespace) -> argparse.Namespace:
    # retain-live fields only; the verify-cohort path options are normalized
    # at their argparse type layer (host_path) in main(). ``source_commit``,
    # ``version`` and ``channel`` are non-path scalars.
    for field in (
        "repo_root",
        "source_snapshot",
        "release_invocation",
        "cargo_input_snapshot",
        "result_stage",
        "artifact_dir",
    ):
        value = getattr(args, field, None)
        if isinstance(value, str):
            setattr(args, field, host_path_text(value))
    return args


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    retain = commands.add_parser("retain-live")
    for name in ("repo-root", "source-commit", "source-snapshot", "release-invocation",
                 "cargo-input-snapshot", "result-stage", "artifact-dir"):
        retain.add_argument("--" + name, required=True)
    audit = commands.add_parser("verify-cohort")
    audit.add_argument("--producer", action="append", required=True)
    for name in ("source-commit", "version", "channel"):
        audit.add_argument("--" + name, required=True)
    for name in ("repo-root", "root", "result-json", "pubkey"):
        audit.add_argument("--" + name, type=host_path, required=True)
    audit.add_argument("--hardware-recipe", default="board-default")
    audit.add_argument("--feed-base-url", help="explicit expected compiled channel base; omission requires absence")
    args = normalize_host_path_args(parser.parse_args())
    try:
        if args.command == "retain-live":
            retain_live(args)
        else:
            verify_cohort_evidence(producer.load_result(args.result_json), args.root, args.producer,
                args.source_commit, args.version, args.channel, args.pubkey, args.repo_root, args.hardware_recipe, args.feed_base_url)
            print("Verified current producer source evidence after private cleanup")
        return 0
    except (ValueError, OSError, KeyError, TypeError, source_snapshot.SnapshotError,
            release_set_publication.ReleaseSetError) as error:
        print("ERROR: producer evidence: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
