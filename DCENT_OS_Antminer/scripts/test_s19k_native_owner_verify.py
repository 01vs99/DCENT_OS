#!/usr/bin/env python3
"""Adversarial tests for the host-only S19k native-owner verifier."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest

from test_s19k_native_build_verify import CapsuleFixture


SCRIPT_PATH = Path(__file__).with_name("s19k_native_owner_verify.py")
SPEC = importlib.util.spec_from_file_location("s19k_native_owner_verify", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
owner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(owner)


def canonical(value: object) -> bytes:
    return owner.canonical_json(value)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def with_verification_id(value: dict[str, object]) -> dict[str, object]:
    result = dict(value)
    result["verification_id"] = digest(canonical(result))
    return result


def aarch64_elf() -> bytes:
    result = bytearray(128)
    result[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", result, 16, 3, 183)
    result[24:48] = b"joined-native-owner-test"
    return bytes(result)


class EvidenceFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.phase = root / "native-cold-start-owner"
        self.phase.mkdir()

        native_re = {
            "schema": owner.NATIVE_RE_SCHEMA,
            "classification": "runtime-secure-sram-key-boundary",
            "plaintext_recovered": False,
            "live_contact_authorized": False,
        }
        re_bytes = canonical(native_re)
        re_dir = root / "native-secure-firmware-re"
        re_dir.mkdir()
        (re_dir / "verification.json").write_bytes(re_bytes)

        hardware = with_verification_id(
            {
                "schema": owner.NATIVE_HARDWARE_SCHEMA,
                "claim": "reviewed-common-clock-native-hardware-contract",
                "authority_granted": False,
                "tty_to_physical_address": {"/dev/ttyS1": 3, "/dev/ttyS2": 2},
                "reset_gpio_to_tty": {"455": "/dev/ttyS2", "456": "/dev/ttyS1"},
                "gpio437_raw_energized": 0,
                "gpio437_raw_safeoff": 1,
            }
        )
        hardware_dir = root / "native-hardware-contract"
        hardware_dir.mkdir()
        (hardware_dir / "verification.json").write_bytes(canonical(hardware))

        endurance = (
            f"schema={owner.ENDURANCE_SCHEMA}\n"
            "outcome=pass\n"
            "terminal_safeoff=verified\n"
        ).encode("ascii")
        endurance_dir = root / "adopted-endurance" / "evidence"
        endurance_dir.mkdir(parents=True)
        (endurance_dir / "HOST_ENDURANCE_VERIFICATION.kv").write_bytes(endurance)

        capsule_fixture = CapsuleFixture(
            root / "capsule-build",
            semantic_source_bytes=owner.load_source_corpus(),
        )
        self.repo_root = capsule_fixture.repo
        self.artifact = capsule_fixture.artifact.read_bytes()
        (self.phase / owner.ARTIFACT_NAME).write_bytes(self.artifact)
        source = owner.audit_source_tree(self.repo_root)
        self.build_receipt = capsule_fixture.receipt
        (self.phase / owner.BUILD_RECEIPT_NAME).write_bytes(
            owner.native_build.canonical_json(self.build_receipt)
        )
        current_invocation_id = self.build_receipt["capsule_build_receipt"][
            "release_capsule"
        ]["release_invocation_id"]
        other_invocation_id = "8" * 64
        if other_invocation_id == current_invocation_id:
            other_invocation_id = "9" * 64
        self.reproducibility = with_verification_id(
            {
                "schema": owner.REPRODUCIBILITY_SCHEMA,
                "classification": "two-distinct-sealed-capsule-results-byte-identical",
                "source": {
                    "commit_oid": self.build_receipt["capsule_build_receipt"][
                        "git"
                    ]["commit"],
                    "source_snapshot_id": self.build_receipt[
                        "capsule_build_receipt"
                    ]["release_capsule"]["source_snapshot_id"],
                },
                "input_contract": {
                    "manifest_public_key_hex": self.build_receipt[
                        "manifest_public_key_hex"
                    ],
                    "manifest_public_key_sha256": self.build_receipt[
                        "manifest_public_key_sha256"
                    ],
                },
                "artifact": {
                    "path": "dcentrald",
                    "sha256": digest(self.artifact),
                    "bytes": len(self.artifact),
                    "elf_class": 64,
                    "machine": 183,
                },
                "observations": [
                    {
                        "release_invocation_id": current_invocation_id,
                        "native_build_verification_id": self.build_receipt[
                            "verification_id"
                        ],
                    },
                    {
                        "release_invocation_id": other_invocation_id,
                        "native_build_verification_id": "e" * 64,
                    },
                ],
                "equality": {
                    "exact_source_snapshot": True,
                    "exact_build_input_snapshot": True,
                    "exact_builder_image": True,
                    "byte_identical_artifact": True,
                },
                "two_capsule_byte_reproducibility_observed": True,
                "build_causality_proven": False,
                "independent_compiler_execution_proven": False,
                "release_authority_granted": False,
                "installation_authority_granted": False,
                "live_hardware_contacted": False,
                "persistent_mutation_authority_granted": False,
            }
        )
        reproducibility_dir = root / "native-build-reproducibility"
        reproducibility_dir.mkdir()
        (reproducibility_dir / "verification.json").write_bytes(
            canonical(self.reproducibility)
        )
        self.ids = {
            "native-secure-firmware-re": digest(re_bytes),
            "native-hardware-contract": hardware["verification_id"],
            "adopted-endurance": digest(endurance),
            "native-build-reproducibility": self.reproducibility[
                "verification_id"
            ],
        }
        self.inputs = {
            "schema": owner.INPUT_SCHEMA,
            "prerequisite_verification_ids": self.ids,
            "native_owner_artifact": {
                "path": owner.ARTIFACT_NAME,
                "sha256": digest(self.artifact),
                "bytes": len(self.artifact),
                "target_triple": "aarch64-unknown-linux-musl",
                "cargo_profile": "release",
                "artifact_role": "native-cold-start-owner",
                "source_files_sha256": digest(canonical(source["source_files"])),
                "compile_contract_sha256": digest(
                    canonical(source["aarch64_compile_contract"])
                ),
                "native_build_verification_id": self.build_receipt[
                    "verification_id"
                ],
                "capsule_build_receipt_sha256": self.build_receipt[
                    "capsule_build_receipt_sha256"
                ],
                "source_commit": self.build_receipt["capsule_build_receipt"][
                    "git"
                ]["commit"],
                "source_snapshot_id": self.build_receipt[
                    "capsule_build_receipt"
                ]["release_capsule"]["source_snapshot_id"],
                "release_invocation_id": self.build_receipt[
                    "capsule_build_receipt"
                ]["release_capsule"]["release_invocation_id"],
                "cargo_metadata_sha256": self.build_receipt[
                    "local_dependency_closure"
                ]["cargo_metadata_sha256"],
                "manifest_public_key_hex": self.build_receipt[
                    "manifest_public_key_hex"
                ],
                "manifest_public_key_sha256": self.build_receipt[
                    "manifest_public_key_sha256"
                ],
                "native_reproducibility_verification_id": self.reproducibility[
                    "verification_id"
                ],
                "observed_native_build_verification_ids": sorted(
                    item["native_build_verification_id"]
                    for item in self.reproducibility["observations"]
                ),
                "observed_release_invocation_ids": sorted(
                    item["release_invocation_id"]
                    for item in self.reproducibility["observations"]
                ),
            },
        }
        (self.phase / owner.INPUT_NAME).write_bytes(canonical(self.inputs))

    def stage(self) -> dict[str, object]:
        return owner.stage_implementation_receipt(
            self.phase, repo_root=self.repo_root
        )


class NativeOwnerVerifierTests(unittest.TestCase):
    def _changed_source(self, needle: bytes, replacement: bytes, path: str) -> None:
        corpus = owner.load_source_corpus()
        self.assertIn(needle, corpus[path])
        changed = dict(corpus)
        changed[path] = corpus[path].replace(needle, replacement, 1)
        with self.assertRaises(owner.NativeOwnerError):
            owner.audit_source_corpus(changed)

    def test_current_tree_has_exact_ready_joined_owner(self) -> None:
        result = owner.audit_source_tree()
        self.assertEqual(result["classification"], "ready")
        self.assertTrue(result["production_owner_present"])
        self.assertFalse(result["authority_minted"])
        self.assertTrue(result["host_only_source_audit"])
        self.assertFalse(result["live_hardware_contacted"])
        self.assertEqual(
            tuple(result["must_join_before_authority"]),
            owner.REQUIRED_OWNER_CAPABILITIES,
        )
        self.assertEqual(
            set(result["capability_inventory"]), set(owner.REQUIRED_OWNER_CAPABILITIES)
        )
        self.assertTrue(
            all(
                item["status"] == "joined" and item["evidence"]
                for item in result["capability_inventory"].values()
            )
        )
        self.assertEqual(
            [item["path"] for item in result["source_files"]], list(owner.SOURCE_PATHS)
        )

    def test_public_or_duplicable_token_is_rejected(self) -> None:
        self._changed_source(
            b"    struct S19kNativePreSerialAdmission {",
            b"    pub struct S19kNativePreSerialAdmission {",
            owner.SERIAL_SOURCE,
        )
        self._changed_source(
            b"    struct S19kNativePreSerialAdmission {",
            b"    #[derive(Clone)]\n    struct S19kNativePreSerialAdmission {",
            owner.SERIAL_SOURCE,
        )

    def test_mapping_uart_and_77_geometry_drift_are_rejected(self) -> None:
        self._changed_source(
            b'logical_chain: 0,\n        logical_board_address: 1,\n        uart: "/dev/ttyS3",',
            b'logical_chain: 0,\n        logical_board_address: 1,\n        uart: "/dev/ttyS4",',
            owner.HAL_SOURCE,
        )
        self._changed_source(
            b"SerialChainBackend::open(route.logical_chain, path, 115_200)",
            b"SerialChainBackend::open(index as u8, path, 115_200)",
            owner.SERIAL_SOURCE,
        )
        self._changed_source(
            b"first.observed_chip_count == geometry.observed_chip_count",
            b"true /* count ignored */",
            owner.SERIAL_SOURCE,
        )

    def test_cooling_freshness_and_generation_drift_are_rejected(self) -> None:
        self._changed_source(
            b"const S19K_NATIVE_MIN_FAN_RPM: u32 = 2_000;",
            b"const S19K_NATIVE_MIN_FAN_RPM: u32 = 300;",
            owner.SERIAL_SOURCE,
        )
        self._changed_source(
            b"const S19K_NATIVE_OWNER_EVIDENCE_MAX_AGE: Duration = Duration::from_secs(5);",
            b"const S19K_NATIVE_OWNER_EVIDENCE_MAX_AGE: Duration = Duration::MAX;",
            owner.SERIAL_SOURCE,
        )
        self._changed_source(
            b"s19k_native_four_fan_rpm_admitted(&readings)",
            b"true /* exact channel admission bypassed */",
            owner.SERIAL_SOURCE,
        )
        self._changed_source(
            b"if *slot || rpm < S19K_NATIVE_MIN_FAN_RPM",
            b"if rpm < S19K_NATIVE_MIN_FAN_RPM /* duplicate channel accepted */",
            owner.SERIAL_SOURCE,
        )
        self._changed_source(
            b"Arc::ptr_eq(power_generation, &self.generation)",
            b"true /* foreign receipt accepted */",
            owner.HAL_SOURCE,
        )

    def test_table_driven_platform_and_geometry_must_remain_bound(self) -> None:
        # The owner now consults the dispatch-admitted common profile. An
        # obsolete literal must not reject that implementation, but removing
        # either target equality or its independent HAL geometry check must.
        for needle in (
            b"bm1366_dispatch_admitted_serial_platform(",
            b"dispatch.board_target() == platform.board_target()",
            b"dispatch.board_target() == platform_profile.board_target",
            b"== dcentrald_hal::platform::amlogic::S19K_NATIVE_EXPECTED_CHIPS_PER_UART",
        ):
            self._changed_source(needle, b"REMOVED_REQUIRED_PLATFORM_BINDING", owner.SERIAL_SOURCE)

    def test_native_identity_requires_full_decode_crc_and_slot_binding(self) -> None:
        for needle in (
            b"names[slot] = Some(decode_deployed_eeprom(page)?.board_name)",
            b"platform.bind_population_polarity(service, names.each_ref().map(|name| name.as_deref()))?",
            b"let identity = decode_deployed_eeprom(page)",
            b"identity.region_1_crc5 == Crc5Check::Match",
            b"S19kNativeBoardModel::parse(&identity.board_name)",
            b"page.is_some() == populated[slot]",
        ):
            self._changed_source(needle, b"REMOVED_REQUIRED_IDENTITY_CHECK", owner.NATIVE_IDENTITY_SOURCE)

    def test_reset_safeoff_and_post_init_cancellation_drift_are_rejected(self) -> None:
        self._changed_source(
            b"for chain in 0..3u8",
            b"for chain in 1..3u8",
            owner.HAL_SOURCE,
        )
        self._changed_source(
            b"dcentrald_hal::platform::amlogic::disable_s19k_track1_psu_checked().is_ok()",
            b"dcentrald_hal::platform::amlogic::disable_psu_checked().is_ok()",
            owner.SERIAL_SOURCE,
        )
        self._changed_source(
            b"shutdown arrived during native S19k population cold init",
            b"native cold init completed",
            owner.SERIAL_SOURCE,
        )
        self._changed_source(
            b"if is_bm1366 && !passthrough && self.shutdown.is_cancelled()",
            b"if false /* native cancellation ignored */",
            owner.SERIAL_SOURCE,
        )

    def test_only_native_join_can_mint_exact_work_mapping(self) -> None:
        self._changed_source(
            b"native_exact_mapping: false,",
            b"native_exact_mapping: true,",
            owner.SERIAL_SOURCE,
        )

    def test_aarch64_compile_contract_drift_is_rejected(self) -> None:
        self._changed_source(
            b"export CARGO_NET_OFFLINE=true",
            b"export CARGO_NET_OFFLINE=false",
            owner.AARCH64_CHECK_SOURCE,
        )
        self._changed_source(
            b"exec \"$zig_bin\" cc -target aarch64-linux-musl -mcpu=cortex_a53",
            b"exec \"$zig_bin\" cc -target x86_64-linux-musl",
            owner.ZIG_CC_SOURCE,
        )

    def test_exact_bundle_stages_and_verifies_without_minting_authority(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = EvidenceFixture(Path(raw))
            result = fixture.stage()
            self.assertEqual(result["classification"], "verified")
            self.assertEqual(result["source_readiness_classification"], "ready")
            self.assertTrue(result["production_owner_present"])
            self.assertTrue(result["dependency_evidence_bound"])
            self.assertFalse(result["authority_minted"])
            self.assertFalse(result["live_hardware_contacted"])
            self.assertEqual(
                result["aarch64_compile_contract"],
                owner.native_build.AARCH64_COMPILE_CONTRACT,
            )
            self.assertEqual(result["prerequisite_verification_ids"], fixture.ids)
            self.assertEqual(
                result["native_owner_artifact"],
                {
                    "path": "usr/local/bin/dcentrald",
                    "sha256": digest(fixture.artifact),
                    "bytes": len(fixture.artifact),
                },
            )
            self.assertEqual(
                result["native_owner_build_binding"],
                {
                    "target_triple": "aarch64-unknown-linux-musl",
                    "cargo_profile": "release",
                    "artifact_role": "native-cold-start-owner",
                    "source_files_sha256": digest(
                        canonical(result["source_files"])
                    ),
                    "compile_contract_sha256": digest(
                        canonical(result["aarch64_compile_contract"])
                    ),
                    "adopted_artifact_reused": False,
                    "native_build_verification_id": fixture.build_receipt[
                        "verification_id"
                    ],
                    "capsule_build_receipt_sha256": fixture.build_receipt[
                        "capsule_build_receipt_sha256"
                    ],
                    "source_commit": fixture.build_receipt[
                        "capsule_build_receipt"
                    ]["git"]["commit"],
                    "source_snapshot_id": fixture.build_receipt[
                        "capsule_build_receipt"
                    ]["release_capsule"]["source_snapshot_id"],
                    "release_invocation_id": fixture.build_receipt[
                        "capsule_build_receipt"
                    ]["release_capsule"]["release_invocation_id"],
                    "cargo_metadata_sha256": fixture.build_receipt[
                        "local_dependency_closure"
                    ]["cargo_metadata_sha256"],
                    "manifest_public_key_hex": fixture.build_receipt[
                        "manifest_public_key_hex"
                    ],
                    "manifest_public_key_sha256": fixture.build_receipt[
                        "manifest_public_key_sha256"
                    ],
                    "native_reproducibility_verification_id": fixture.reproducibility[
                        "verification_id"
                    ],
                    "observed_native_build_verification_ids": sorted(
                        item["native_build_verification_id"]
                        for item in fixture.reproducibility["observations"]
                    ),
                    "observed_release_invocation_ids": sorted(
                        item["release_invocation_id"]
                        for item in fixture.reproducibility["observations"]
                    ),
                },
            )
            self.assertEqual(result["native_build_receipt"], fixture.build_receipt)
            projected = dict(result)
            verification_id = projected.pop("verification_id")
            self.assertEqual(verification_id, digest(canonical(projected)))
            self.assertEqual(
                owner.verify_implementation_receipt(
                    fixture.phase, repo_root=fixture.repo_root
                ),
                result,
            )
            self.assertEqual(
                set(item.name for item in fixture.phase.iterdir()), set(owner.PHASE_FILES)
            )

    def test_asserted_prerequisite_id_cannot_override_sibling_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = EvidenceFixture(Path(raw))
            fixture.inputs["prerequisite_verification_ids"][
                "native-hardware-contract"
            ] = "f" * 64
            (fixture.phase / owner.INPUT_NAME).write_bytes(canonical(fixture.inputs))
            with self.assertRaises(owner.NativeOwnerError):
                fixture.stage()

    def test_prepare_inputs_derives_exact_binding_and_refuses_stale_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = EvidenceFixture(Path(raw))
            path = fixture.phase / owner.INPUT_NAME
            path.unlink()
            prepared = owner.prepare_inputs(
                fixture.phase, repo_root=fixture.repo_root
            )
            self.assertEqual(prepared, fixture.inputs)
            self.assertEqual(path.read_bytes(), canonical(fixture.inputs))

            path.write_bytes(b"{}\n")
            with self.assertRaisesRegex(owner.NativeOwnerError, "refusing to overwrite"):
                owner.prepare_inputs(fixture.phase, repo_root=fixture.repo_root)

    def test_artifact_build_binding_and_adopted_binary_reuse_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = EvidenceFixture(Path(raw))
            fixture.inputs["native_owner_artifact"]["cargo_profile"] = "debug"
            (fixture.phase / owner.INPUT_NAME).write_bytes(canonical(fixture.inputs))
            with self.assertRaisesRegex(
                owner.NativeOwnerError, "exact source-built dcentrald artifact"
            ):
                fixture.stage()

        with tempfile.TemporaryDirectory() as raw:
            fixture = EvidenceFixture(Path(raw))
            original = owner.ADOPTED_ROUTE_ARTIFACT_SHA256S
            owner.ADOPTED_ROUTE_ARTIFACT_SHA256S = {digest(fixture.artifact)}
            try:
                with self.assertRaisesRegex(
                    owner.NativeOwnerError, "older adopted-route binary"
                ):
                    fixture.stage()
            finally:
                owner.ADOPTED_ROUTE_ARTIFACT_SHA256S = original

    def test_wrong_mapping_in_sibling_hardware_receipt_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = EvidenceFixture(Path(raw))
            path = Path(raw) / "native-hardware-contract" / "verification.json"
            value = json.loads(path.read_text(encoding="ascii"))
            value.pop("verification_id")
            value["tty_to_physical_address"] = {"/dev/ttyS1": 2, "/dev/ttyS2": 3}
            path.write_bytes(canonical(with_verification_id(value)))
            with self.assertRaises(owner.NativeOwnerError):
                fixture.stage()

    def test_non_aarch64_or_symlink_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = EvidenceFixture(Path(raw))
            artifact = bytearray(fixture.artifact)
            struct.pack_into("<H", artifact, 18, 62)
            (fixture.phase / owner.ARTIFACT_NAME).write_bytes(artifact)
            record = dict(fixture.inputs["native_owner_artifact"])
            record.update(
                {
                    "path": owner.ARTIFACT_NAME,
                    "sha256": digest(bytes(artifact)),
                    "bytes": len(artifact),
                }
            )
            fixture.inputs["native_owner_artifact"] = record
            (fixture.phase / owner.INPUT_NAME).write_bytes(canonical(fixture.inputs))
            with self.assertRaises(owner.NativeOwnerError):
                fixture.stage()

        with tempfile.TemporaryDirectory() as raw:
            fixture = EvidenceFixture(Path(raw))
            artifact = fixture.phase / owner.ARTIFACT_NAME
            target = fixture.phase / "real-daemon"
            artifact.rename(target)
            try:
                os.symlink(target.name, artifact)
            except OSError:
                self.skipTest("symlink creation is unavailable")
            with self.assertRaises(owner.NativeOwnerError):
                fixture.stage()

    def test_noncanonical_inputs_stale_receipt_and_extra_file_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = EvidenceFixture(Path(raw))
            (fixture.phase / owner.INPUT_NAME).write_text(
                json.dumps(fixture.inputs, indent=2) + "\n", encoding="ascii"
            )
            with self.assertRaises(owner.NativeOwnerError):
                fixture.stage()

        with tempfile.TemporaryDirectory() as raw:
            fixture = EvidenceFixture(Path(raw))
            fixture.stage()
            (fixture.phase / owner.RECEIPT_NAME).write_bytes(b"{}\n")
            with self.assertRaises(owner.NativeOwnerError):
                owner.verify_implementation_receipt(
                    fixture.phase, repo_root=fixture.repo_root
                )

        with tempfile.TemporaryDirectory() as raw:
            fixture = EvidenceFixture(Path(raw))
            fixture.stage()
            (fixture.phase / "extra").write_bytes(b"x")
            with self.assertRaises(owner.NativeOwnerError):
                owner.verify_implementation_receipt(
                    fixture.phase, repo_root=fixture.repo_root
                )


if __name__ == "__main__":
    unittest.main()
