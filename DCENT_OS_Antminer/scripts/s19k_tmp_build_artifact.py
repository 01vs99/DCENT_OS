#!/usr/bin/env python3
"""Create source receipts and admit S19k /tmp armv7 build artifacts.

This helper is host-only.  It performs no deployment and grants no persistent
install authority.  A single admitted build is not reproducibility proof;
``compare-receipts`` only compares distinct observation identifiers and
input-equivalent receipt contents. It cannot prove that two compilers were
independently executed, so that claim requires separate clean-build custody.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import subprocess
import sys
import tempfile
from typing import Iterable


SOURCE_SCHEMA = "org.dcentral.dcentos.s19k-tmp-source.v1"
BUILD_SCHEMA = "org.dcentral.dcentos.s19k-tmp-build.v1"
TARGET_SELECTOR = "s19k-tmp"
TARGET_TRIPLE = "armv7-unknown-linux-musleabihf"
EXPECTED_ARTIFACT = f"target/s19k-tmp/{TARGET_TRIPLE}/release/dcentrald"
EXPECTED_INVENTORY = "target/s19k-tmp/release-inventory"
EXPECTED_TARGET_DIRECTORY = "/src/target/s19k-tmp"
EXPECTED_CAPSULE_TARGET_DIRECTORY = "/cargo-target"
EXPECTED_TARGET_DIRECTORIES = (
    EXPECTED_TARGET_DIRECTORY,
    EXPECTED_CAPSULE_TARGET_DIRECTORY,
)
# Order is load-bearing: rustc applies the last matching remap, so the normal
# target path must follow the broader /src source mapping.
EXPECTED_REMAP_FLAGS = (
    "--remap-path-prefix=/src=/dcent-source",
    "--remap-path-prefix=/src/target/s19k-tmp=/dcent-build",
    "--remap-path-prefix=/cargo-target=/dcent-build",
)
EXPECTED_RUSTFLAGS = " ".join(
    ("-C", "link-arg=-s", "-C", "target-feature=+crt-static", *EXPECTED_REMAP_FLAGS)
)
EXPECTED_RUST_RELEASE = "1.90.0"
EXPECTED_ZIG_VERSION = "0.13.0"
EXPECTED_ZIG_SHA256 = "d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea"
EXPECTED_PACKAGE_RESOLUTION = "official-zig-0.13.0-sha256-d45312e6"
SOURCE_CLAIM = "content-bound working-tree inputs observed at one S19k /tmp build endpoint"
SOURCE_NON_CLAIMS = [
    "immutable-source-snapshot",
    "protection-from-transient-same-uid-mutation",
    "dependency-or-container-closure",
    "reproducibility-proof",
    "production-release-authority",
]
BUILD_CLAIM = (
    "one offline S19k temporary-handoff artifact passed endpoint-stable source, "
    "toolchain, target-isolation, canonical path-remap, and ELF admission"
)
BUILD_NON_CLAIMS = [
    "two-build-reproducibility-proof",
    "clean-room-independent-rebuild-proof",
    "production-release-or-persistent-install-authority",
    "live-device-execution-or-accepted-share-proof",
    "protection-from-transient-same-uid-source-mutation",
]
HEX64 = re.compile(r"^[0-9a-f]{64}$")
DIGEST_REFERENCE = re.compile(r"^(?:[^/@]+/)*[^/@]+@sha256:[0-9a-f]{64}$")
CACHE_DIRECTORY_SIGNATURE = b"Signature: 8a477f597d28d172789f06886806bc55"
REQUIRED_SOURCE_PATHS = {
    "",
    "",
    "projects/dcent-schema/Cargo.toml",
    "DCENT_OS_Antminer/dcentrald/.cargo/config.toml",
    "DCENT_OS_Antminer/dcentrald/Cargo.lock",
    "DCENT_OS_Antminer/dcentrald/Cargo.toml",
    "DCENT_OS_Antminer/scripts/build-dcentrald.sh",
    "DCENT_OS_Antminer/scripts/s19k_tmp_build_artifact.py",
}


class BuildArtifactError(ValueError):
    """An input cannot support the claimed S19k build receipt."""


def fail(message: str) -> None:
    raise BuildArtifactError(message)


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_reparse(metadata: os.stat_result) -> bool:
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and getattr(metadata, "st_file_attributes", 0) & flag)


def _require_directory(path: Path, label: str) -> os.stat_result:
    metadata = os.lstat(path)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        fail(f"{label} must be a real non-link directory: {path}")
    return metadata


def _stable_regular_bytes(path: Path, label: str) -> tuple[bytes, os.stat_result]:
    before = os.lstat(path)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse(before)
    ):
        fail(f"{label} must be a regular non-link file: {path}")
    if before.st_nlink != 1:
        fail(f"{label} must have exactly one hard link: {path}")
    data = path.read_bytes()
    after = os.lstat(path)
    observed_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_mode,
    )
    observed_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_mode,
    )
    if observed_before != observed_after or len(data) != before.st_size:
        fail(f"{label} changed while it was read: {path}")
    return data, before


def _within(root: Path, path: Path, label: str) -> None:
    try:
        path.relative_to(root)
    except ValueError:
        fail(f"{label} is outside repository root: {path}")


def _entry(logical_path: str, path: Path) -> dict[str, object]:
    data, metadata = _stable_regular_bytes(path, logical_path)
    return {
        "path": logical_path,
        "bytes": len(data),
        "executable": bool(stat.S_IMODE(metadata.st_mode) & 0o111),
        "sha256": sha256_bytes(data),
    }


def _tree_entries(label: str, root: Path) -> Iterable[dict[str, object]]:
    _require_directory(root, label)
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        kept: list[str] = []
        for name in sorted(directories):
            candidate = current_path / name
            relative = candidate.relative_to(root)
            # Cargo output is never a source byte. Besides the conventional
            # `target`, local gates use named Cargo target directories such as
            # `target-topology-api`; exclude one only when Cargo's standard
            # cache-directory signature proves that it is a cache root. A
            # legitimate source directory with a `target-*` name remains in.
            cache_tag = candidate / "CACHEDIR.TAG"
            cargo_cache = False
            if cache_tag.exists() and not cache_tag.is_symlink():
                tag, _ = _stable_regular_bytes(cache_tag, f"{label}/{relative.as_posix()}/CACHEDIR.TAG")
                cargo_cache = tag.startswith(CACHE_DIRECTORY_SIGNATURE)
            if name == "target" or cargo_cache:
                continue
            metadata = os.lstat(candidate)
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
                fail(f"source tree contains a link/reparse directory: {label}/{relative.as_posix()}")
            if not stat.S_ISDIR(metadata.st_mode):
                fail(f"source tree contains a non-directory traversal entry: {candidate}")
            kept.append(name)
        directories[:] = kept
        for name in sorted(files):
            candidate = current_path / name
            relative = candidate.relative_to(root).as_posix()
            yield _entry(f"{label}/{relative}", candidate)


def _git_head(repo_root: Path) -> str:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
        }
    )
    completed = subprocess.run(
        ("git", "-C", os.fspath(repo_root), "rev-parse", "--verify", "HEAD^{commit}"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=environment,
    )
    if completed.returncode:
        fail(f"cannot resolve Git HEAD: {completed.stderr.decode('utf-8', 'replace').strip()}")
    head = completed.stdout.decode("ascii", "strict").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head):
        fail("Git HEAD is not a canonical object id")
    return head


def source_snapshot(args: argparse.Namespace) -> dict[str, object]:
    repo_root = Path(args.repo_root).resolve(strict=True)
    _require_directory(repo_root, "repository root")
    roots = (
        ("DCENT_OS_Antminer/dcentrald", Path(args.dcentrald_root).resolve(strict=True)),
        ("projects/dcent-schema", Path(args.dcent_schema_root).resolve(strict=True)),
    )
    explicit = (
        ("", Path(args.stock_manifest).resolve(strict=True)),
        ("", Path(args.stock_signature).resolve(strict=True)),
        ("DCENT_OS_Antminer/scripts/build-dcentrald.sh", Path(args.build_script).resolve(strict=True)),
        ("DCENT_OS_Antminer/scripts/s19k_tmp_build_artifact.py", Path(args.verifier).resolve(strict=True)),
    )
    entries: list[dict[str, object]] = []
    for label, root in roots:
        _within(repo_root, root, label)
        if root != (repo_root / label).resolve(strict=True):
            fail(f"{label} input is not the canonical repository path: {root}")
        entries.extend(_tree_entries(label, root))
    for label, path in explicit:
        _within(repo_root, path, label)
        if path != (repo_root / label).resolve(strict=True):
            fail(f"{label} input is not the canonical repository path: {path}")
        entries.append(_entry(label, path))
    entries.sort(key=lambda item: str(item["path"]))
    paths = [str(item["path"]) for item in entries]
    if len(paths) != len(set(paths)):
        fail("source snapshot has duplicate logical paths")
    body: dict[str, object] = {
        "schema": SOURCE_SCHEMA,
        "claim": SOURCE_CLAIM,
        "non_claims": SOURCE_NON_CLAIMS,
        "git_head": _git_head(repo_root),
        "files": entries,
        "file_count": len(entries),
        "total_bytes": sum(int(item["bytes"]) for item in entries),
    }
    descriptor = dict(body)
    descriptor["snapshot_id"] = sha256_bytes(canonical_bytes(body))
    return descriptor


def _validate_source_descriptor(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        fail("source descriptor must be a JSON object")
    expected = {
        "schema",
        "claim",
        "non_claims",
        "git_head",
        "files",
        "file_count",
        "total_bytes",
        "snapshot_id",
    }
    if (
        set(value) != expected
        or value.get("schema") != SOURCE_SCHEMA
        or value.get("claim") != SOURCE_CLAIM
        or value.get("non_claims") != SOURCE_NON_CLAIMS
    ):
        fail("source descriptor schema/fields are invalid")
    snapshot_id = value.get("snapshot_id")
    if not isinstance(snapshot_id, str) or not HEX64.fullmatch(snapshot_id):
        fail("source descriptor snapshot_id is invalid")
    body = dict(value)
    body.pop("snapshot_id")
    if sha256_bytes(canonical_bytes(body)) != snapshot_id:
        fail("source descriptor snapshot_id does not authenticate its body")
    files = value.get("files")
    git_head = value.get("git_head")
    if not isinstance(git_head, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", git_head):
        fail("source descriptor Git HEAD is invalid")
    file_count = value.get("file_count")
    total_bytes = value.get("total_bytes")
    if (
        not isinstance(file_count, int)
        or isinstance(file_count, bool)
        or file_count < 0
        or not isinstance(total_bytes, int)
        or isinstance(total_bytes, bool)
        or total_bytes < 0
        or not isinstance(files, list)
        or len(files) != file_count
    ):
        fail("source descriptor file count is invalid")
    previous = ""
    total = 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "bytes", "executable", "sha256"}:
            fail("source descriptor contains an invalid file entry")
        path = item["path"]
        digest = item["sha256"]
        size = item["bytes"]
        if (
            not isinstance(path, str)
            or not path
            or path <= previous
            or "\\" in path
            or path.startswith("/")
            or "//" in path
            or any(component in ("", ".", "..") for component in path.split("/"))
        ):
            fail("source descriptor paths are not strictly sorted canonical paths")
        if not isinstance(digest, str) or not HEX64.fullmatch(digest):
            fail(f"source descriptor digest is invalid: {path}")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            fail(f"source descriptor byte count is invalid: {path}")
        if not isinstance(item["executable"], bool):
            fail(f"source descriptor executable bit is invalid: {path}")
        previous = path
        total += size
    if total != total_bytes:
        fail("source descriptor total byte count is invalid")
    missing = sorted(REQUIRED_SOURCE_PATHS.difference(str(item["path"]) for item in files))
    if missing:
        fail(f"source descriptor omits required build inputs: {', '.join(missing)}")
    return value


def _load_json_file(path: Path, label: str) -> tuple[object, bytes]:
    data, _ = _stable_regular_bytes(path, label)
    try:
        return json.loads(data.decode("utf-8")), data
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid UTF-8 JSON: {error}")


def _atomic_write(path: Path, data: bytes) -> None:
    parent = path.parent
    _require_directory(parent, "output parent")
    if path.exists() or path.is_symlink():
        metadata = os.lstat(path)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
            fail(f"refusing to replace non-regular output: {path}")
    descriptor = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if "temporary_name" in locals() and os.path.exists(temporary_name):
            os.unlink(temporary_name)


def verify_armv7_artifact(blob: bytes) -> dict[str, object]:
    if len(blob) < 52 or blob[:4] != b"\x7fELF":
        fail("artifact is not a complete ELF32 header")
    if blob[4:7] != b"\x01\x01\x01":
        fail("artifact must be ELF32 little-endian EV_CURRENT")
    elf_type, machine = struct.unpack_from("<HH", blob, 16)
    if elf_type not in (2, 3):
        fail("artifact must be ET_EXEC or static ET_DYN")
    if machine != 40:
        fail(f"artifact e_machine={machine}, expected EM_ARM=40")
    if struct.unpack_from("<I", blob, 20)[0] != 1:
        fail("artifact ELF header version is not EV_CURRENT")
    entry, phoff = struct.unpack_from("<II", blob, 24)
    flags = struct.unpack_from("<I", blob, 36)[0]
    ehsize, phentsize, phnum = struct.unpack_from("<HHH", blob, 40)
    if entry == 0:
        fail("artifact entry point is zero")
    if flags & 0xFF00_0000 != 0x0500_0000:
        fail("artifact is not ARM EABI5")
    if not flags & 0x400 or flags & 0x200:
        fail("artifact must set hard-float and must not set soft-float ABI flags")
    if ehsize != 52 or phentsize != 32 or phnum in (0, 0xFFFF):
        fail("artifact has invalid ELF32/program-header geometry")
    if phoff < 52 or phoff + phentsize * phnum > len(blob):
        fail("artifact program-header table is outside the file")
    executable_entry = False
    executable_loads = 0
    dynamic_ranges: list[tuple[int, int, int]] = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_flags, _align = struct.unpack_from(
            "<IIIIIIII", blob, offset
        )
        if p_type == 3:
            fail("artifact contains PT_INTERP; static musl output is required")
        if p_type == 2:
            if p_offset > len(blob) or p_filesz > len(blob) - p_offset or p_filesz % 8:
                fail(f"artifact PT_DYNAMIC[{index}] is outside the file or misaligned")
            dynamic_ranges.append((index, p_offset, p_filesz))
        if p_type != 1:
            continue
        if p_filesz > p_memsz or p_offset > len(blob) or p_filesz > len(blob) - p_offset:
            fail(f"artifact PT_LOAD[{index}] is outside the file")
        if p_vaddr + p_memsz > 0x1_0000_0000:
            fail(f"artifact PT_LOAD[{index}] virtual range wraps ELF32 address space")
        if p_flags & 1 and p_filesz:
            executable_loads += 1
            if p_vaddr <= entry < p_vaddr + p_filesz:
                executable_entry = True
    if not executable_loads or not executable_entry:
        fail("artifact entry point is not in a file-backed executable PT_LOAD")
    for index, offset, size in dynamic_ranges:
        terminated = False
        for cursor in range(offset, offset + size, 8):
            tag, _value = struct.unpack_from("<II", blob, cursor)
            if tag == 0:
                terminated = True
                break
            if tag == 1:
                fail(f"artifact PT_DYNAMIC[{index}] contains DT_NEEDED; static output is required")
        if not terminated:
            fail(f"artifact PT_DYNAMIC[{index}] has no in-bounds DT_NULL terminator")
    return {
        "class": "ELF32",
        "endianness": "little",
        "machine": "EM_ARM",
        "arm_eabi": 5,
        "float_abi": "hard",
        "pt_interp": False,
        "dt_needed": False,
        "elf_type": elf_type,
        "entry": entry,
        "executable_loads": executable_loads,
        "bytes": len(blob),
        "sha256": sha256_bytes(blob),
    }


def _parse_lines(data: bytes, label: str) -> tuple[list[str], dict[str, str]]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        fail(f"{label} is not UTF-8: {error}")
    values: dict[str, str] = {}
    for line in lines:
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in values:
            fail(f"{label} contains duplicate key {key}")
        values[key] = value
    return lines, values


def _require_env(values: dict[str, str], key: str, expected: str) -> None:
    if values.get(key) != expected:
        fail(f"compile environment {key}={values.get(key)!r}, expected {expected!r}")


JOURNAL_ADMISSION_SOURCE = Path("dcentrald-common") / "src" / "s19k_braiins_tmp_deploy.rs"
JOURNAL_ADMISSION_MARKER = "pub const S19K_EPHEMERAL_JOURNAL_TRIAL_DESTINATIONS: &[&str] = &["
JOURNAL_REFUSAL = b"S19k journal destination is not an admitted startup authority path"
RUNNER_SCRIPT = Path("scripts") / "dcentrald_s19k_tmp_remote_run.sh"


def daemon_journal_destinations(dcentrald_root: Path) -> list[str]:
    """The single publisher-v1 admission set, read from dcentrald-common."""
    source, _ = _stable_regular_bytes(
        dcentrald_root / JOURNAL_ADMISSION_SOURCE, "S19k journal admission source"
    )
    text = source.decode("utf-8")
    start = text.find(JOURNAL_ADMISSION_MARKER)
    if start < 0:
        fail("S19k journal admission set is missing from dcentrald-common")
    end = text.find("];", start)
    names = re.findall(r'"([a-z0-9_]+)"', text[start:end])
    if len(names) < 12 or len(set(names)) != len(names):
        fail("S19k journal admission set is malformed")
    return names


def runner_journal_destinations(dcentrald_root: Path) -> list[str]:
    """Trial basenames the Track-1 runner hands to the daemon publisher."""
    runner_path = dcentrald_root.parent / RUNNER_SCRIPT
    runner, _ = _stable_regular_bytes(runner_path, "S19k Track-1 runner")
    text = runner.decode("utf-8")
    names: list[str] = []
    for source_var, destination_var in re.findall(
        r'^\s*publish_no_clobber_journal(?:_keep_source)? "\$([A-Z0-9_]+)" "\$([A-Z0-9_]+)"',
        text,
        flags=re.M,
    ):
        if (source_var, destination_var) == ("JOURNAL_SOURCE", "JOURNAL_DESTINATION"):
            continue
        if destination_var in ("RUNTIME_LOCK_OWNER", "ENDURANCE_ACK"):
            continue
        match = re.search(
            rf'^\s*{re.escape(destination_var)}="\$TRIAL_DIR/([A-Za-z0-9_.-]+)"$',
            text,
            flags=re.M,
        )
        if match is None:
            fail(f"runner journal destination {destination_var} is not a fixed trial basename")
        names.append(match.group(1))
    if not names:
        fail("runner publishes no trial journals")
    return names


def verify_journal_destinations(blob: bytes, dcentrald_root: Path) -> dict[str, object]:
    """Refuse to seal a daemon whose publisher cannot bind every receipt the
    runner publishes. 2026-09-01: the sealed receipt-fix-v7 bytes carried none
    of the five post-SafeOff receipt names, so the live bounded-work proof
    mined and SafeOff'd cleanly and then failed at the transcript seal."""
    admitted = daemon_journal_destinations(dcentrald_root)
    published = runner_journal_destinations(dcentrald_root)
    unadmitted = sorted(set(published) - set(admitted))
    if unadmitted:
        fail(
            "runner publishes journal destinations the daemon source does not admit: "
            f"{unadmitted}"
        )
    absent = [name for name in admitted if blob.find(name.encode("ascii")) < 0]
    if absent:
        fail(
            f"artifact bytes lack admitted journal destination strings {absent}; "
            "the sealed daemon would refuse those receipts on the bench"
        )
    if blob.find(JOURNAL_REFUSAL) < 0:
        fail("artifact lacks the publisher-v1 refusal string; journal publication is not compiled in")
    return {"admitted": admitted, "published": published}


def verify_build(args: argparse.Namespace) -> dict[str, object]:
    if not isinstance(args.build_observation_id, str) or not HEX64.fullmatch(
        args.build_observation_id
    ):
        fail("build observation id must be 32 random bytes encoded as lowercase hex")
    workspace_root = Path(args.dcentrald_root).resolve(strict=True)
    _require_directory(workspace_root, "dcentrald workspace")
    artifact_root_argument = getattr(args, "artifact_root", None)
    artifact_root = Path(artifact_root_argument or args.dcentrald_root).resolve(strict=True)
    _require_directory(artifact_root, "S19k build artifact root")
    binary_path = Path(args.binary).resolve(strict=True)
    expected_binary = artifact_root / EXPECTED_ARTIFACT
    if binary_path != expected_binary.resolve(strict=True):
        fail(f"artifact path={binary_path}, expected canonical output {expected_binary}")
    binary, _ = _stable_regular_bytes(binary_path, "S19k /tmp binary")
    elf = verify_armv7_artifact(binary)
    verify_journal_destinations(binary, workspace_root)

    source_value, source_data = _load_json_file(Path(args.source_snapshot), "source snapshot")
    source = _validate_source_descriptor(source_value)
    post_source_value, _ = _load_json_file(
        Path(args.post_source_snapshot), "post-build source snapshot"
    )
    post_source = _validate_source_descriptor(post_source_value)
    if canonical_bytes(source) != canonical_bytes(post_source):
        fail("source inputs changed between the pre-build and post-build endpoints")

    inventory = artifact_root / EXPECTED_INVENTORY
    expected_inputs = {
        "source snapshot": inventory / "s19k-tmp.source.json",
        "Cargo metadata": inventory / f"{TARGET_TRIPLE}.metadata.json",
        "toolchain context": inventory / f"{TARGET_TRIPLE}.toolchain.txt",
        "compile environment": inventory / f"{TARGET_TRIPLE}.compile-env.txt",
        "build receipt": inventory / "s19k-tmp.build.json",
    }
    supplied_inputs = {
        "source snapshot": Path(args.source_snapshot),
        "Cargo metadata": Path(args.metadata),
        "toolchain context": Path(args.toolchain_context),
        "compile environment": Path(args.compile_environment),
        "build receipt": Path(args.receipt),
    }
    for label, expected_path in expected_inputs.items():
        supplied = supplied_inputs[label].resolve(strict=False)
        expected = expected_path.resolve(strict=False)
        if supplied != expected:
            fail(f"{label} path={supplied}, expected canonical output {expected}")

    metadata_value, metadata_data = _load_json_file(Path(args.metadata), "Cargo metadata")
    if not isinstance(metadata_value, dict):
        fail("Cargo metadata must be a JSON object")
    target_directory = str(metadata_value.get("target_directory", "")).replace("\\", "/").rstrip("/")
    if target_directory not in EXPECTED_TARGET_DIRECTORIES:
        fail(
            f"Cargo metadata target_directory={target_directory!r}, expected one of "
            f"the isolated S19k roots {EXPECTED_TARGET_DIRECTORIES!r}"
        )

    toolchain_data, _ = _stable_regular_bytes(Path(args.toolchain_context), "toolchain context")
    toolchain_lines, toolchain = _parse_lines(toolchain_data, "toolchain context")
    releases = [line.split(":", 1)[1].strip() for line in toolchain_lines if line.startswith("release:")]
    if releases != [EXPECTED_RUST_RELEASE]:
        fail(f"rustc release pin mismatch: {releases!r}")
    cargo_versions = [line for line in toolchain_lines if line.startswith("cargo ")]
    if len(cargo_versions) != 1 or not cargo_versions[0].startswith(f"cargo {EXPECTED_RUST_RELEASE} "):
        fail(f"Cargo release pin mismatch: {cargo_versions!r}")
    builder_base = toolchain.get("builder_base_reference", "")
    if not DIGEST_REFERENCE.fullmatch(builder_base) or builder_base != args.expected_builder_base:
        fail("builder base is not the exact expected sha256 digest reference")
    builder_image = toolchain.get("builder_image_id", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", builder_image):
        fail("builder image id is not an immutable sha256 identity")
    if toolchain.get("builder_package_resolution") != EXPECTED_PACKAGE_RESOLUTION:
        fail("builder package-resolution evidence is not the pinned Zig policy")
    if toolchain.get("zig_version") != EXPECTED_ZIG_VERSION:
        fail("Zig version evidence is absent or wrong")
    if toolchain.get("zig_archive_sha256") != EXPECTED_ZIG_SHA256:
        fail("Zig archive digest evidence is absent or wrong")

    environment_data, _ = _stable_regular_bytes(Path(args.compile_environment), "compile environment")
    _environment_lines, environment = _parse_lines(environment_data, "compile environment")
    suffix = TARGET_TRIPLE.replace("-", "_")
    upper = TARGET_TRIPLE.replace("-", "_").upper()
    _require_env(environment, "CARGO_BUILD_PROFILE", "release")
    _require_env(environment, "CARGO_TARGET_DIR", target_directory)
    _require_env(environment, f"CC_{suffix}", "/usr/local/bin/zig-cc-target-musl")
    _require_env(environment, f"AR_{suffix}", "/usr/local/bin/zig-ar")
    _require_env(environment, f"CARGO_TARGET_{upper}_LINKER", "rust-lld")
    _require_env(environment, f"CARGO_TARGET_{upper}_RUSTFLAGS", "-C linker=rust-lld")
    if "CARGO_ENCODED_RUSTFLAGS" in environment:
        fail("compile environment must not contain higher-priority CARGO_ENCODED_RUSTFLAGS")
    _require_env(environment, "RUSTFLAGS", EXPECTED_RUSTFLAGS)
    _require_env(environment, "DCENT_BUILDER_BASE_REFERENCE", builder_base)
    _require_env(environment, "DCENT_BUILDER_IMAGE_ID", builder_image)
    _require_env(environment, "DCENT_BUILDER_PACKAGE_RESOLUTION", EXPECTED_PACKAGE_RESOLUTION)

    body: dict[str, object] = {
        "schema": BUILD_SCHEMA,
        "claim": BUILD_CLAIM,
        "non_claims": BUILD_NON_CLAIMS,
        "target_selector": TARGET_SELECTOR,
        "target_triple": TARGET_TRIPLE,
        "build_observation_id": args.build_observation_id,
        "artifact_path": EXPECTED_ARTIFACT,
        "artifact": elf,
        "source_snapshot_id": source["snapshot_id"],
        "source_endpoints_identical": True,
        "source_descriptor_sha256": sha256_bytes(source_data),
        "cargo_metadata_sha256": sha256_bytes(metadata_data),
        "toolchain_context_sha256": sha256_bytes(toolchain_data),
        "compile_environment_sha256": sha256_bytes(environment_data),
        "rust_release": EXPECTED_RUST_RELEASE,
        "cargo_version": cargo_versions[0],
        "builder_base_reference": builder_base,
        "builder_image_id": builder_image,
        "zig_version": EXPECTED_ZIG_VERSION,
        "zig_archive_sha256": EXPECTED_ZIG_SHA256,
    }
    receipt = dict(body)
    receipt["receipt_id"] = sha256_bytes(canonical_bytes(body))
    return receipt


def _validate_build_receipt(value: object) -> dict[str, object]:
    expected = {
        "schema",
        "claim",
        "non_claims",
        "target_selector",
        "target_triple",
        "build_observation_id",
        "artifact_path",
        "artifact",
        "source_snapshot_id",
        "source_endpoints_identical",
        "source_descriptor_sha256",
        "cargo_metadata_sha256",
        "toolchain_context_sha256",
        "compile_environment_sha256",
        "rust_release",
        "cargo_version",
        "builder_base_reference",
        "builder_image_id",
        "zig_version",
        "zig_archive_sha256",
        "receipt_id",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("schema") != BUILD_SCHEMA
        or value.get("claim") != BUILD_CLAIM
        or value.get("non_claims") != BUILD_NON_CLAIMS
        or value.get("target_selector") != TARGET_SELECTOR
        or value.get("target_triple") != TARGET_TRIPLE
        or value.get("artifact_path") != EXPECTED_ARTIFACT
        or value.get("source_endpoints_identical") is not True
        or value.get("rust_release") != EXPECTED_RUST_RELEASE
        or value.get("zig_version") != EXPECTED_ZIG_VERSION
        or value.get("zig_archive_sha256") != EXPECTED_ZIG_SHA256
    ):
        fail("build receipt schema is invalid")
    observation_id = value.get("build_observation_id")
    if not isinstance(observation_id, str) or not HEX64.fullmatch(observation_id):
        fail("build receipt observation id is invalid")
    receipt_id = value.get("receipt_id")
    if not isinstance(receipt_id, str) or not HEX64.fullmatch(receipt_id):
        fail("build receipt id is invalid")
    body = dict(value)
    body.pop("receipt_id", None)
    if sha256_bytes(canonical_bytes(body)) != receipt_id:
        fail("build receipt id does not authenticate its body")
    for field in (
        "source_snapshot_id",
        "source_descriptor_sha256",
        "cargo_metadata_sha256",
        "toolchain_context_sha256",
        "compile_environment_sha256",
    ):
        item = value.get(field)
        if not isinstance(item, str) or not HEX64.fullmatch(item):
            fail(f"build receipt {field} is invalid")
    artifact = value.get("artifact")
    if not isinstance(artifact, dict) or set(artifact) != {
        "class",
        "endianness",
        "machine",
        "arm_eabi",
        "float_abi",
        "pt_interp",
        "dt_needed",
        "elf_type",
        "entry",
        "executable_loads",
        "bytes",
        "sha256",
    }:
        fail("build receipt artifact facts are invalid")
    if (
        artifact.get("class") != "ELF32"
        or artifact.get("endianness") != "little"
        or artifact.get("machine") != "EM_ARM"
        or artifact.get("arm_eabi") != 5
        or artifact.get("float_abi") != "hard"
        or artifact.get("pt_interp") is not False
        or artifact.get("dt_needed") is not False
        or artifact.get("elf_type") not in (2, 3)
        or not isinstance(artifact.get("entry"), int)
        or isinstance(artifact.get("entry"), bool)
        or not isinstance(artifact.get("executable_loads"), int)
        or isinstance(artifact.get("executable_loads"), bool)
        or artifact.get("executable_loads", 0) < 1
        or not isinstance(artifact.get("bytes"), int)
        or isinstance(artifact.get("bytes"), bool)
        or artifact.get("bytes", 0) < 52
        or not isinstance(artifact.get("sha256"), str)
        or not HEX64.fullmatch(str(artifact.get("sha256")))
    ):
        fail("build receipt artifact admission facts are invalid")
    if not DIGEST_REFERENCE.fullmatch(str(value.get("builder_base_reference", ""))):
        fail("build receipt builder base is not digest-pinned")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(value.get("builder_image_id", ""))):
        fail("build receipt builder image id is invalid")
    cargo_version = value.get("cargo_version")
    if not isinstance(cargo_version, str) or not cargo_version.startswith(
        f"cargo {EXPECTED_RUST_RELEASE} "
    ):
        fail("build receipt Cargo version is invalid")
    return value


def compare_receipts(first: dict[str, object], second: dict[str, object]) -> None:
    if first.get("build_observation_id") == second.get("build_observation_id"):
        fail("receipts are from the same build observation; a copied receipt is not reproducibility evidence")
    compared = (
        "target_selector",
        "target_triple",
        "artifact_path",
        "artifact",
        "source_snapshot_id",
        "source_endpoints_identical",
        "source_descriptor_sha256",
        "cargo_metadata_sha256",
        "toolchain_context_sha256",
        "compile_environment_sha256",
        "rust_release",
        "cargo_version",
        "builder_base_reference",
        "builder_image_id",
        "zig_version",
        "zig_archive_sha256",
    )
    changed = [field for field in compared if first.get(field) != second.get(field)]
    if changed:
        fail(f"receipts do not prove input-equivalent byte reproducibility; changed: {', '.join(changed)}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("new-observation")
    verify_elf = commands.add_parser("verify-elf")
    verify_elf.add_argument("binary")
    verify_elf.add_argument(
        "--dcentrald-root",
        help="also require every runner journal destination admitted by this source tree to be present in the ELF",
    )
    source = commands.add_parser("source-snapshot")
    source.add_argument("--repo-root", required=True)
    source.add_argument("--dcentrald-root", required=True)
    source.add_argument("--dcent-schema-root", required=True)
    source.add_argument("--stock-manifest", required=True)
    source.add_argument("--stock-signature", required=True)
    source.add_argument("--build-script", required=True)
    source.add_argument("--verifier", required=True)
    source.add_argument("--output", required=True)

    compare_source = commands.add_parser("compare-source-snapshots")
    compare_source.add_argument("first")
    compare_source.add_argument("second")

    verify = commands.add_parser("verify")
    verify.add_argument("--dcentrald-root", required=True)
    verify.add_argument(
        "--artifact-root",
        help="result root; defaults to --dcentrald-root for an ordinary build",
    )
    verify.add_argument("--binary", required=True)
    verify.add_argument("--source-snapshot", required=True)
    verify.add_argument("--post-source-snapshot", required=True)
    verify.add_argument("--metadata", required=True)
    verify.add_argument("--toolchain-context", required=True)
    verify.add_argument("--compile-environment", required=True)
    verify.add_argument("--expected-builder-base", required=True)
    verify.add_argument("--build-observation-id", required=True)
    verify.add_argument("--receipt", required=True)

    compare = commands.add_parser("compare-receipts")
    compare.add_argument("first")
    compare.add_argument("second")
    return parser


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv[1:])
    try:
        if args.command == "new-observation":
            print(secrets.token_hex(32))
        elif args.command == "verify-elf":
            binary, _ = _stable_regular_bytes(Path(args.binary), "S19k /tmp binary")
            artifact = verify_armv7_artifact(binary)
            if args.dcentrald_root:
                journals = verify_journal_destinations(
                    binary, Path(args.dcentrald_root).resolve(strict=True)
                )
                print(
                    "JOURNAL_DESTINATIONS="
                    f"{len(journals['admitted'])} admitted, "
                    f"{len(journals['published'])} runner-published, all present"
                )
            print(f"SHA256={artifact['sha256']}")
            print(f"BYTES={artifact['bytes']}")
            print(
                "ELF32 ARM musl-static admitted "
                "(class=1 machine=40 arm_eabi=5 hard_float=1 "
                "soft_float=0 pt_interp=none dt_needed=none)"
            )
        elif args.command == "source-snapshot":
            descriptor = source_snapshot(args)
            _atomic_write(Path(args.output), canonical_bytes(descriptor))
            print(
                f"S19K_TMP_SOURCE_SNAPSHOT id={descriptor['snapshot_id']} "
                f"files={descriptor['file_count']} bytes={descriptor['total_bytes']}"
            )
        elif args.command == "compare-source-snapshots":
            first_value, _ = _load_json_file(Path(args.first), "first source snapshot")
            second_value, _ = _load_json_file(Path(args.second), "second source snapshot")
            first = _validate_source_descriptor(first_value)
            second = _validate_source_descriptor(second_value)
            if canonical_bytes(first) != canonical_bytes(second):
                fail("source inputs changed during the S19k /tmp build")
            print(f"S19K_TMP_SOURCE_STABLE id={first['snapshot_id']}")
        elif args.command == "verify":
            receipt = verify_build(args)
            _atomic_write(Path(args.receipt), canonical_bytes(receipt))
            artifact = receipt["artifact"]
            assert isinstance(artifact, dict)
            print(
                f"S19K_TMP_BUILD_ADMITTED receipt={receipt['receipt_id']} "
                f"sha256={artifact['sha256']} bytes={artifact['bytes']}"
            )
        elif args.command == "compare-receipts":
            first_value, _ = _load_json_file(Path(args.first), "first build receipt")
            second_value, _ = _load_json_file(Path(args.second), "second build receipt")
            first = _validate_build_receipt(first_value)
            second = _validate_build_receipt(second_value)
            compare_receipts(first, second)
            print(
                "S19K_TMP_TWO_BUILD_OBSERVATIONS_MATCH "
                f"first={first['receipt_id']} second={second['receipt_id']}"
            )
        else:  # pragma: no cover
            fail("unknown command")
    except (OSError, BuildArtifactError) as error:
        print(f"ERROR: S19k /tmp build artifact refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
