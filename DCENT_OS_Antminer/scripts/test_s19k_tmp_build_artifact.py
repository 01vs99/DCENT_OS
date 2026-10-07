#!/usr/bin/env python3
"""Host-only regression tests for the S19k temporary build admission helper."""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import re
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
HELPER_PATH = SCRIPT_DIR / "s19k_tmp_build_artifact.py"
SPEC = importlib.util.spec_from_file_location("s19k_tmp_build_artifact", HELPER_PATH)
assert SPEC is not None and SPEC.loader is not None
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


def synthetic_arm_elf(*, flags: int = 0x0500_0400, machine: int = 40) -> bytes:
    blob = bytearray(100)
    blob[:16] = b"\x7fELF\x01\x01\x01" + (b"\x00" * 9)
    struct.pack_into(
        "<HHIIIIIHHHHHH",
        blob,
        16,
        2,  # ET_EXEC
        machine,
        1,  # EV_CURRENT
        0x1000,
        52,
        0,
        flags,
        52,
        32,
        1,
        40,
        0,
        0,
    )
    struct.pack_into(
        "<IIIIIIII",
        blob,
        52,
        1,  # PT_LOAD
        84,
        0x1000,
        0x1000,
        16,
        16,
        5,  # PF_R | PF_X
        4,
    )
    blob[84:] = bytes(range(16))
    return bytes(blob)


REAL_ADMISSION_SOURCE = (
    Path(__file__).resolve().parents[1]
    / "dcentrald"
    / helper.JOURNAL_ADMISSION_SOURCE
)
REAL_RUNNER = Path(__file__).resolve().parent / "dcentrald_s19k_tmp_remote_run.sh"


def admission_source_text() -> str:
    """The real S19K_EPHEMERAL_JOURNAL_TRIAL_DESTINATIONS block, so the fixture
    tracks the daemon's admission set instead of a stale copy."""
    text = REAL_ADMISSION_SOURCE.read_text(encoding="utf-8")
    start = text.index(helper.JOURNAL_ADMISSION_MARKER)
    end = text.index("];", start) + 2
    return text[start:end] + "\n"


def admitted_journal_names() -> list[str]:
    return re.findall(r'"([a-z0-9_]+)"', admission_source_text())


def journal_string_payload(names: list[str] | None = None) -> bytes:
    names = admitted_journal_names() if names is None else names
    return b"\0".join(name.encode("ascii") for name in names) + b"\0" + helper.JOURNAL_REFUSAL + b"\0"


def synthetic_sealed_elf(names: list[str] | None = None) -> bytes:
    """A synthetic ARM ELF whose trailing bytes carry the publisher strings."""
    return synthetic_arm_elf() + journal_string_payload(names)


def install_journal_sources(dcentrald_root: Path) -> None:
    source = dcentrald_root / helper.JOURNAL_ADMISSION_SOURCE
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(admission_source_text(), encoding="utf-8")
    runner = dcentrald_root.parent / helper.RUNNER_SCRIPT
    runner.parent.mkdir(parents=True, exist_ok=True)
    runner.write_bytes(REAL_RUNNER.read_bytes())


def source_descriptor() -> dict[str, object]:
    files = [
        {"path": path, "bytes": 0, "executable": False, "sha256": "0" * 64}
        for path in sorted(helper.REQUIRED_SOURCE_PATHS)
    ]
    body: dict[str, object] = {
        "schema": helper.SOURCE_SCHEMA,
        "claim": helper.SOURCE_CLAIM,
        "non_claims": helper.SOURCE_NON_CLAIMS,
        "git_head": "a" * 40,
        "files": files,
        "file_count": len(files),
        "total_bytes": 0,
    }
    value = dict(body)
    value["snapshot_id"] = helper.sha256_bytes(helper.canonical_bytes(body))
    return value


class ElfAdmissionTests(unittest.TestCase):
    def test_admits_elf32_arm_eabi5_hard_float_static(self) -> None:
        facts = helper.verify_armv7_artifact(synthetic_arm_elf())
        self.assertEqual(facts["machine"], "EM_ARM")
        self.assertEqual(facts["arm_eabi"], 5)
        self.assertEqual(facts["float_abi"], "hard")
        self.assertFalse(facts["pt_interp"])

    def test_rejects_wrong_machine(self) -> None:
        with self.assertRaisesRegex(helper.BuildArtifactError, "EM_ARM"):
            helper.verify_armv7_artifact(synthetic_arm_elf(machine=183))

    def test_rejects_wrong_eabi_or_float_abi(self) -> None:
        for flags in (0x0400_0400, 0x0500_0000, 0x0500_0600):
            with self.subTest(flags=hex(flags)), self.assertRaises(helper.BuildArtifactError):
                helper.verify_armv7_artifact(synthetic_arm_elf(flags=flags))

    def test_rejects_pt_interp(self) -> None:
        blob = bytearray(synthetic_arm_elf())
        struct.pack_into("<I", blob, 52, 3)
        with self.assertRaisesRegex(helper.BuildArtifactError, "PT_INTERP"):
            helper.verify_armv7_artifact(bytes(blob))

    def test_rejects_dt_needed_even_without_interpreter(self) -> None:
        original = synthetic_arm_elf()
        blob = bytearray(148)
        blob[:52] = original[:52]
        struct.pack_into("<H", blob, 44, 2)  # e_phnum
        struct.pack_into(
            "<IIIIIIII", blob, 52, 1, 116, 0x1000, 0x1000, 16, 16, 5, 4
        )
        struct.pack_into(
            "<IIIIIIII", blob, 84, 2, 132, 0x2000, 0x2000, 16, 16, 4, 4
        )
        blob[116:132] = bytes(range(16))
        struct.pack_into("<IIII", blob, 132, 1, 7, 0, 0)  # DT_NEEDED, then DT_NULL
        with self.assertRaisesRegex(helper.BuildArtifactError, "DT_NEEDED"):
            helper.verify_armv7_artifact(bytes(blob))

    def test_rejects_entry_outside_executable_file_bytes(self) -> None:
        blob = bytearray(synthetic_arm_elf())
        struct.pack_into("<I", blob, 24, 0x1010)
        with self.assertRaisesRegex(helper.BuildArtifactError, "entry point"):
            helper.verify_armv7_artifact(bytes(blob))

    def test_rejects_wrapping_load_segment(self) -> None:
        blob = bytearray(synthetic_arm_elf())
        struct.pack_into("<I", blob, 60, 0xFFFF_FFF8)  # p_vaddr
        with self.assertRaisesRegex(helper.BuildArtifactError, "wraps"):
            helper.verify_armv7_artifact(bytes(blob))

    def test_verify_elf_cli_routes_through_canonical_admission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "dcentrald"
            binary.write_bytes(synthetic_arm_elf())
            admitted = subprocess.run(
                [sys.executable, str(HELPER_PATH), "verify-elf", str(binary)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(admitted.returncode, 0, admitted.stderr)
            self.assertIn("SHA256=", admitted.stdout)
            self.assertIn("soft_float=0", admitted.stdout)
            self.assertIn("dt_needed=none", admitted.stdout)

            # Both flags set is not hard-float proof.  This mutation was accepted
            # by the deployer's historical embedded parser before verify-elf was
            # made the authoritative admission boundary.
            binary.write_bytes(synthetic_arm_elf(flags=0x0500_0600))
            refused = subprocess.run(
                [sys.executable, str(HELPER_PATH), "verify-elf", str(binary)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("float ABI", refused.stderr)


class SourceSelectionTests(unittest.TestCase):
    def test_excludes_proven_cargo_cache_but_keeps_target_named_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "target-topology-api" / "src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text("pub fn topology() {}\n", encoding="utf-8")
            cache = root / "target-generated"
            cache.mkdir()
            (cache / "CACHEDIR.TAG").write_bytes(
                helper.CACHE_DIRECTORY_SIGNATURE + b"\n# Cargo cache\n"
            )
            (cache / "artifact").write_bytes(b"not-source")
            ruff_cache = root / ".ruff_cache"
            ruff_cache.mkdir()
            # Ruff emits the standard signature without a trailing newline.
            (ruff_cache / "CACHEDIR.TAG").write_bytes(helper.CACHE_DIRECTORY_SIGNATURE)
            (ruff_cache / ".gitignore").write_bytes(b"*")
            paths = [item["path"] for item in helper._tree_entries("workspace", root)]
            self.assertEqual(paths, ["workspace/target-topology-api/src/lib.rs"])


class BuildReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name) / "dcentrald"
        self.inventory = self.workspace / helper.EXPECTED_INVENTORY
        self.binary = self.workspace / helper.EXPECTED_ARTIFACT
        self.inventory.mkdir(parents=True)
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(synthetic_sealed_elf())
        install_journal_sources(self.workspace)

        source = source_descriptor()
        self.source = self.inventory / "s19k-tmp.source.json"
        self.post_source = Path(self.temporary.name) / "post.json"
        self.source.write_bytes(helper.canonical_bytes(source))
        self.post_source.write_bytes(helper.canonical_bytes(source))

        self.metadata = self.inventory / f"{helper.TARGET_TRIPLE}.metadata.json"
        self.metadata.write_text(
            json.dumps({"target_directory": helper.EXPECTED_TARGET_DIRECTORY}),
            encoding="utf-8",
        )
        self.base = "rust@sha256:" + ("b" * 64)
        self.image = "sha256:" + ("c" * 64)
        self.toolchain = self.inventory / f"{helper.TARGET_TRIPLE}.toolchain.txt"
        self.toolchain.write_text(
            "\n".join(
                (
                    "rustc 1.90.0 (1159e78c4 2025-09-14)",
                    "binary: rustc",
                    "commit-hash: 1159e78c4747b02ef996e55082b704c09b970588",
                    "release: 1.90.0",
                    "host: x86_64-unknown-linux-gnu",
                    "LLVM version: 20.1.7",
                    "cargo 1.90.0 (840b83a10 2025-07-30)",
                    f"builder_base_reference={self.base}",
                    f"builder_image_id={self.image}",
                    f"builder_package_resolution={helper.EXPECTED_PACKAGE_RESOLUTION}",
                    f"zig_version={helper.EXPECTED_ZIG_VERSION}",
                    f"zig_archive_sha256={helper.EXPECTED_ZIG_SHA256}",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        suffix = helper.TARGET_TRIPLE.replace("-", "_")
        upper = suffix.upper()
        self.environment = self.inventory / f"{helper.TARGET_TRIPLE}.compile-env.txt"
        self.environment.write_text(
            "\n".join(
                (
                    f"AR_{suffix}=/usr/local/bin/zig-ar",
                    "CARGO_BUILD_PROFILE=release",
                    f"CARGO_TARGET_DIR={helper.EXPECTED_TARGET_DIRECTORY}",
                    f"CARGO_TARGET_{upper}_LINKER=rust-lld",
                    f"CARGO_TARGET_{upper}_RUSTFLAGS=-C linker=rust-lld",
                    f"CC_{suffix}=/usr/local/bin/zig-cc-target-musl",
                    f"DCENT_BUILDER_BASE_REFERENCE={self.base}",
                    f"DCENT_BUILDER_IMAGE_ID={self.image}",
                    f"DCENT_BUILDER_PACKAGE_RESOLUTION={helper.EXPECTED_PACKAGE_RESOLUTION}",
                    f"RUSTFLAGS={helper.EXPECTED_RUSTFLAGS}",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        self.receipt = self.inventory / "s19k-tmp.build.json"

    def args(self) -> argparse.Namespace:
        return argparse.Namespace(
            dcentrald_root=str(self.workspace),
            binary=str(self.binary),
            source_snapshot=str(self.source),
            post_source_snapshot=str(self.post_source),
            metadata=str(self.metadata),
            toolchain_context=str(self.toolchain),
            compile_environment=str(self.environment),
            expected_builder_base=self.base,
            build_observation_id="f" * 64,
            receipt=str(self.receipt),
        )

    def test_verifies_canonical_output_and_emits_content_bound_receipt(self) -> None:
        receipt = helper.verify_build(self.args())
        helper._validate_build_receipt(receipt)
        self.assertTrue(receipt["source_endpoints_identical"])
        self.assertEqual(receipt["artifact_path"], helper.EXPECTED_ARTIFACT)
        self.assertEqual(receipt["artifact"]["sha256"], helper.sha256_bytes(self.binary.read_bytes()))

    def test_rejects_artifact_missing_a_runner_journal_destination(self) -> None:
        # The 2026-09-01 receipt-fix-v7 shape: the daemon bytes lack the
        # post-SafeOff receipt names the runner publishes.
        names = admitted_journal_names()
        self.assertIn("runtime_bounded_work_transcript", names)
        self.binary.write_bytes(
            synthetic_sealed_elf(
                [name for name in names if name != "runtime_bounded_work_transcript"]
            )
        )
        with self.assertRaises(helper.BuildArtifactError) as raised:
            helper.verify_build(self.args())
        self.assertIn("runtime_bounded_work_transcript", str(raised.exception))
        self.assertIn("would refuse those receipts on the bench", str(raised.exception))

    def test_rejects_runner_destination_outside_the_daemon_set(self) -> None:
        runner = self.workspace.parent / helper.RUNNER_SCRIPT
        text = runner.read_text(encoding="utf-8")
        mutated = text.replace(
            'BOUNDED_TRANSCRIPT_RECEIPT="$TRIAL_DIR/runtime_bounded_work_transcript"',
            'BOUNDED_TRANSCRIPT_RECEIPT="$TRIAL_DIR/runtime_bounded_work_transcript_v2"',
        )
        self.assertNotEqual(mutated, text)
        runner.write_text(mutated, encoding="utf-8", newline="\n")
        with self.assertRaises(helper.BuildArtifactError) as raised:
            helper.verify_build(self.args())
        self.assertIn("runtime_bounded_work_transcript_v2", str(raised.exception))

    def test_rejects_artifact_without_publisher_refusal_string(self) -> None:
        self.binary.write_bytes(
            synthetic_arm_elf() + b"\0".join(n.encode() for n in admitted_journal_names()) + b"\0"
        )
        with self.assertRaises(helper.BuildArtifactError) as raised:
            helper.verify_build(self.args())
        self.assertIn("refusal string", str(raised.exception))

    def test_rejects_changed_source_endpoint(self) -> None:
        changed = source_descriptor()
        changed["git_head"] = "d" * 40
        body = dict(changed)
        body.pop("snapshot_id")
        changed["snapshot_id"] = helper.sha256_bytes(helper.canonical_bytes(body))
        self.post_source.write_bytes(helper.canonical_bytes(changed))
        with self.assertRaisesRegex(helper.BuildArtifactError, "source inputs changed"):
            helper.verify_build(self.args())

    def test_rejects_nonisolated_cargo_target(self) -> None:
        self.metadata.write_text(json.dumps({"target_directory": "/src/target"}), encoding="utf-8")
        with self.assertRaisesRegex(helper.BuildArtifactError, "isolated S19k roots"):
            helper.verify_build(self.args())

    def test_capsule_result_root_and_isolated_cargo_target_are_admitted(self) -> None:
        capsule_root = Path(self.temporary.name) / "capsule-result"
        capsule_inventory = capsule_root / helper.EXPECTED_INVENTORY
        capsule_binary = capsule_root / helper.EXPECTED_ARTIFACT
        capsule_inventory.mkdir(parents=True)
        capsule_binary.parent.mkdir(parents=True)
        capsule_binary.write_bytes(self.binary.read_bytes())

        capsule_source = capsule_inventory / self.source.name
        capsule_metadata = capsule_inventory / self.metadata.name
        capsule_toolchain = capsule_inventory / self.toolchain.name
        capsule_environment = capsule_inventory / self.environment.name
        capsule_receipt = capsule_inventory / self.receipt.name
        capsule_source.write_bytes(self.source.read_bytes())
        capsule_metadata.write_text(
            json.dumps({"target_directory": helper.EXPECTED_CAPSULE_TARGET_DIRECTORY}),
            encoding="utf-8",
        )
        capsule_toolchain.write_bytes(self.toolchain.read_bytes())
        capsule_environment.write_text(
            self.environment.read_text(encoding="utf-8").replace(
                f"CARGO_TARGET_DIR={helper.EXPECTED_TARGET_DIRECTORY}",
                f"CARGO_TARGET_DIR={helper.EXPECTED_CAPSULE_TARGET_DIRECTORY}",
            ),
            encoding="utf-8",
        )
        args = self.args()
        args.artifact_root = str(capsule_root)
        args.binary = str(capsule_binary)
        args.source_snapshot = str(capsule_source)
        args.metadata = str(capsule_metadata)
        args.toolchain_context = str(capsule_toolchain)
        args.compile_environment = str(capsule_environment)
        args.receipt = str(capsule_receipt)
        receipt = helper.verify_build(args)
        helper._validate_build_receipt(receipt)
        self.assertEqual(receipt["artifact"]["sha256"], helper.sha256_bytes(capsule_binary.read_bytes()))

    def test_refuses_metadata_and_compile_target_directory_disagreement(self) -> None:
        self.metadata.write_text(
            json.dumps({"target_directory": helper.EXPECTED_CAPSULE_TARGET_DIRECTORY}),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(helper.BuildArtifactError, "CARGO_TARGET_DIR"):
            helper.verify_build(self.args())

    def test_rejects_missing_or_wrong_path_remap_evidence(self) -> None:
        original = self.environment.read_text(encoding="utf-8")
        mutations = {
            "missing source remap": helper.EXPECTED_RUSTFLAGS.replace(
                f" {helper.EXPECTED_REMAP_FLAGS[0]}", ""
            ),
            "missing normal-target remap": helper.EXPECTED_RUSTFLAGS.replace(
                f" {helper.EXPECTED_REMAP_FLAGS[1]}", ""
            ),
            "missing capsule-target remap": helper.EXPECTED_RUSTFLAGS.replace(
                f" {helper.EXPECTED_REMAP_FLAGS[2]}", ""
            ),
            "wrong stable build prefix": helper.EXPECTED_RUSTFLAGS.replace(
                "/src/target/s19k-tmp=/dcent-build",
                "/src/target/s19k-tmp=/dcent-source/target/s19k-tmp",
            ),
            "extra late conflicting remap": (
                f"{helper.EXPECTED_RUSTFLAGS} --remap-path-prefix=/src=/wrong"
            ),
            "wrong precedence order": " ".join(
                (
                    "-C",
                    "link-arg=-s",
                    "-C",
                    "target-feature=+crt-static",
                    helper.EXPECTED_REMAP_FLAGS[1],
                    helper.EXPECTED_REMAP_FLAGS[0],
                    helper.EXPECTED_REMAP_FLAGS[2],
                )
            ),
        }
        for label, rustflags in mutations.items():
            with self.subTest(label=label):
                try:
                    self.environment.write_text(
                        original.replace(
                            f"RUSTFLAGS={helper.EXPECTED_RUSTFLAGS}",
                            f"RUSTFLAGS={rustflags}",
                        ),
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(
                        helper.BuildArtifactError, "compile environment RUSTFLAGS"
                    ):
                        helper.verify_build(self.args())
                finally:
                    self.environment.write_text(original, encoding="utf-8")

    def test_rejects_higher_priority_encoded_rustflags(self) -> None:
        with self.environment.open("a", encoding="utf-8") as stream:
            stream.write(
                "CARGO_ENCODED_RUSTFLAGS="
                "--remap-path-prefix=/src/target/s19k-tmp=/wrong\n"
            )
        with self.assertRaisesRegex(helper.BuildArtifactError, "higher-priority"):
            helper.verify_build(self.args())

    def test_rejects_mutable_or_different_builder(self) -> None:
        args = self.args()
        args.expected_builder_base = "rust:1.90"
        with self.assertRaisesRegex(helper.BuildArtifactError, "exact expected"):
            helper.verify_build(args)

    def test_rejects_artifact_outside_canonical_output(self) -> None:
        other = Path(self.temporary.name) / "other"
        other.write_bytes(self.binary.read_bytes())
        args = self.args()
        args.binary = str(other)
        with self.assertRaisesRegex(helper.BuildArtifactError, "canonical output"):
            helper.verify_build(args)

    def test_compare_requires_identical_artifact_and_inputs(self) -> None:
        first = helper.verify_build(self.args())
        with self.assertRaisesRegex(helper.BuildArtifactError, "copied receipt"):
            helper.compare_receipts(first, copy.deepcopy(first))
        changed = copy.deepcopy(first)
        changed["build_observation_id"] = "1" * 64
        changed["artifact"]["sha256"] = "e" * 64
        body = dict(changed)
        body.pop("receipt_id")
        changed["receipt_id"] = helper.sha256_bytes(helper.canonical_bytes(body))
        helper._validate_build_receipt(changed)
        with self.assertRaisesRegex(helper.BuildArtifactError, "changed: artifact"):
            helper.compare_receipts(first, changed)

    def test_compare_accepts_distinct_matching_build_observations(self) -> None:
        first = helper.verify_build(self.args())
        second = copy.deepcopy(first)
        second["build_observation_id"] = "2" * 64
        body = dict(second)
        body.pop("receipt_id")
        second["receipt_id"] = helper.sha256_bytes(helper.canonical_bytes(body))
        helper._validate_build_receipt(second)
        helper.compare_receipts(first, second)


class BuildScriptContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = (SCRIPT_DIR / "build-dcentrald.sh").read_text(encoding="utf-8")

    def test_s19k_uses_isolated_canonical_output(self) -> None:
        self.assertIn('TARGET_OUTPUT_PREFIX="target/s19k-tmp"', self.script)
        self.assertIn('-e "CARGO_TARGET_DIR=/src/$TARGET_OUTPUT_PREFIX"', self.script)
        self.assertIn(
            'BINARY="$BUILD_RESULT_ROOT/$TARGET_OUTPUT_PREFIX/$TRIPLE/release/dcentrald"',
            self.script,
        )
        self.assertIn(
            'DOCKER_ENV_ARGS+=( -e "DCENT_TARGET_OUTPUT_PREFIX=${TARGET_OUTPUT_PREFIX}" )',
            self.script,
        )
        self.assertIn(
            'release_dir="/results/${DCENT_TARGET_OUTPUT_PREFIX}/${DCENT_METADATA_TARGET}/release"',
            self.script,
        )
        self.assertIn(
            'inventory_dir="/results/${DCENT_TARGET_OUTPUT_PREFIX}/release-inventory"',
            self.script,
        )
        self.assertIn('--artifact-root "$S19K_ARTIFACT_ROOT"', self.script)

    def test_normal_s19k_cargo_hardlink_is_snapshotted_before_receipt(self) -> None:
        snapshot = self.script.index(
            'install -m 0755 "$s19k_binary" "$s19k_snapshot"'
        )
        publish = self.script.index('mv -f "$s19k_snapshot" "$s19k_binary"')
        admission = self.script.index('"$S19K_TMP_BUILD_VERIFIER" verify')
        self.assertLess(snapshot, publish)
        self.assertLess(publish, admission)

    def test_s19k_uses_one_ordered_normal_and_capsule_path_remap_contract(self) -> None:
        expected = " ".join(helper.EXPECTED_REMAP_FLAGS)
        self.assertIn(f'S19K_TMP_PATH_REMAP_FLAGS="{expected}"', self.script)
        self.assertIn('PATH_REMAP_FLAGS="$S19K_TMP_PATH_REMAP_FLAGS"', self.script)
        self.assertIn('BUILD_RUSTFLAGS="-C link-arg=-s ${ARCH_FLAGS}"', self.script)
        self.assertIn('BUILD_RUSTFLAGS="$BUILD_RUSTFLAGS $PATH_REMAP_FLAGS"', self.script)
        self.assertIn('-e "RUSTFLAGS=${BUILD_RUSTFLAGS}"', self.script)
        unset_encoded = self.script.index("unset CARGO_ENCODED_RUSTFLAGS")
        cargo_build = self.script.index("cargo build --release --locked --offline")
        self.assertLess(unset_encoded, cargo_build)
        self.assertLess(expected.index("/src=/dcent-source"), expected.index("/src/target/s19k-tmp"))

    def test_immutable_toolchain_and_elf_admission_precede_success(self) -> None:
        immutable = self.script.index('if [ "$TARGET" = "s19k-tmp" ] \\')
        self.assertIn("s19k-tmp requires DCENT_RUST_BUILDER_BASE", self.script[immutable:])
        docker_build = self.script.index('"$DOCKER_BIN" build')
        provenance_disabled = self.script.index("--provenance=false", docker_build)
        admission = self.script.index('"$S19K_TMP_BUILD_VERIFIER" verify')
        success = self.script.index("S19k /tmp artifact admitted for experimental ephemeral handoff")
        self.assertLess(immutable, docker_build)
        self.assertLess(provenance_disabled, admission)
        self.assertLess(admission, success)

    def test_source_endpoints_surround_cross_compile(self) -> None:
        snapshot_calls = []
        start = 0
        needle = '"$S19K_TMP_BUILD_VERIFIER" source-snapshot'
        while True:
            found = self.script.find(needle, start)
            if found < 0:
                break
            snapshot_calls.append(found)
            start = found + len(needle)
        self.assertEqual(len(snapshot_calls), 2)
        docker_run = self.script.index('MSYS_NO_PATHCONV=1 "$DOCKER_BIN" run --rm')
        comparison = self.script.index('"$S19K_TMP_BUILD_VERIFIER" compare-source-snapshots')
        self.assertLess(snapshot_calls[0], docker_run)
        self.assertLess(docker_run, snapshot_calls[1])
        self.assertLess(snapshot_calls[1], comparison)

    def test_success_text_keeps_experimental_nonclaims(self) -> None:
        self.assertIn("Production readiness and two-build reproducibility are NOT proven.", self.script)
        self.assertIn("compare-receipts <first-build-receipt> <second-build-receipt>", self.script)


if __name__ == "__main__":
    unittest.main()
