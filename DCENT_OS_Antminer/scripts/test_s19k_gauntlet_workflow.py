#!/usr/bin/env python3
"""Adversarial tests for the offline S19k complete-enablement controller."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPT_PATH = SCRIPT_DIR / "s19k_gauntlet_workflow.py"
SPEC = importlib.util.spec_from_file_location("s19k_gauntlet_workflow", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
workflow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(workflow)


class S19kGauntletWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest, cls.manifest_sha = workflow.load_manifest(
            workflow.DEFAULT_MANIFEST
        )

    def manifest_with_repo_fixture(self) -> tuple[dict, str]:
        """Exercise the DAG with a verifiable fixture, not a moving checkout.

        The historical campaign seals exact source inventories. New runtime
        implementation correctly makes that old seal refuse the working tree;
        a graph test must not require rewriting those historical identities.
        The real repository verifier still reads and hashes this fixture.
        """
        manifest = copy.deepcopy(self.manifest)
        path = Path(__file__).resolve()
        relative = path.relative_to(workflow.REPO_ROOT).as_posix()
        raw = path.read_bytes()
        verifier = next(
            phase for phase in manifest["phases"]
            if phase["id"] == workflow.ADOPTED_REPO_PHASE_ID
        )["verifier"]
        verifier["required_paths"] = [relative]
        verifier["required_identities"] = {
            relative: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        }
        return manifest, hashlib.sha256(workflow.canonical_json(manifest)).hexdigest()

    def test_manifest_spans_adopted_native_persistent_and_terminal_routes(self) -> None:
        phase_ids = [phase["id"] for phase in self.manifest["phases"]]
        for required in (
            "adopted-phase12",
            "adopted-bounded-work",
            "adopted-endurance",
            "native-secure-firmware-re",
            "static-bhb5690x-controller-interface",
            "native-cold-start-owner",
            "native-phase12",
            "native-bounded-work",
            "native-endurance",
            "persistent-recovery-rehearsal",
            "persistent-image",
            "persistent-install",
            "persistent-acceptance",
            "persistent-board-population-matrix",
            "complete-dcentos-enablement",
        ):
            self.assertIn(required, phase_ids)
        terminal = self.manifest["phases"][-1]
        self.assertEqual(terminal["kind"], "terminal")
        self.assertEqual(
            set(terminal["depends_on"]),
            {
                "adopted-endurance",
                "native-endurance",
                "native-population-coverage",
                "persistent-acceptance",
                "persistent-board-population-matrix",
            },
        )

    def test_manifest_is_fail_closed_and_controller_contains_no_contact_primitive(self) -> None:
        policy = self.manifest["contact_policy"]
        self.assertTrue(policy["controller_is_offline_only"])
        self.assertTrue(policy["live_contact_requires_fresh_operator_authorization"])
        self.assertTrue(policy["nand_write_requires_separate_explicit_authorization"])
        self.assertFalse(policy["controller_may_grant_authority"])
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "import socket",
            "import requests",
            "import paramiko",
            "subprocess",
            "ssh ",
            "scp ",
            "/sys/class/gpio",
            "flash_erase",
            "nandwrite",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_verified_repo_frontier_is_derived_and_terminal_remains_denied(self) -> None:
        manifest, manifest_sha = self.manifest_with_repo_fixture()
        with tempfile.TemporaryDirectory() as raw_temp:
            report = workflow.evaluate(
                manifest,
                manifest_sha,
                Path(raw_temp) / "evidence",
                None,
            )
        states = {phase["id"]: phase["state"] for phase in report["phases"]}
        self.assertEqual(states["offline-repo-contract"], "verified")
        self.assertEqual(states["portable-artifact-custody"], "awaiting_operator")
        self.assertEqual(states["native-build-reproducibility"], "ready")
        self.assertEqual(states["native-secure-firmware-re"], "ready")
        self.assertEqual(
            states["static-bhb5690x-controller-interface"], "ready"
        )
        self.assertEqual(states["complete-dcentos-enablement"], "waiting")
        self.assertFalse(report["complete"])
        self.assertEqual(
            set(report["frontier"]),
            {
                "portable-artifact-custody",
                "native-build-reproducibility",
                "native-secure-firmware-re",
                "static-bhb5690x-controller-interface",
            },
        )

    def test_agent_wave_has_bounded_owner_review_and_separate_operator_gate(self) -> None:
        manifest, manifest_sha = self.manifest_with_repo_fixture()
        with tempfile.TemporaryDirectory() as raw_temp:
            report = workflow.evaluate(
                manifest,
                manifest_sha,
                Path(raw_temp) / "evidence",
                None,
            )
        wave = workflow.emit_agent_tasks(manifest, report)
        self.assertEqual(wave["max_parallel_agents"], 3)
        self.assertEqual(len(wave["tasks"]), 6)
        self.assertEqual(wave["tasks"][0]["expert"], "DCENT_Release")
        self.assertEqual(wave["tasks"][1]["role"], "independent-review")
        self.assertEqual(wave["tasks"][2]["expert"], "DCENT_RE")
        self.assertEqual(wave["tasks"][3]["role"], "independent-review")
        self.assertEqual(wave["tasks"][4]["expert"], "DCENT_RE")
        self.assertEqual(wave["tasks"][5]["role"], "independent-review")
        self.assertEqual(
            [gate["phase_id"] for gate in wave["operator_gates"]],
            ["portable-artifact-custody"],
        )
        self.assertIn("controller grants none", wave["operator_gates"][0]["authorization"])

    def test_stale_repository_identity_refuses_without_resealing_the_campaign(self) -> None:
        manifest, _ = self.manifest_with_repo_fixture()
        phase = next(p for p in manifest["phases"] if p["id"] == workflow.ADOPTED_REPO_PHASE_ID)
        self.assertEqual(workflow.verify_repo_phase(phase)["required_file_count"], 1)
        identity = next(iter(phase["verifier"]["required_identities"].values()))
        identity["sha256"] = "0" * 64
        with self.assertRaisesRegex(workflow.WorkflowError, "file identity mismatch"):
            workflow.verify_repo_phase(phase)
        with tempfile.TemporaryDirectory() as raw_temp:
            report = workflow.evaluate(manifest, "0" * 64, Path(raw_temp), None)
        states = {p["id"]: p["state"] for p in report["phases"]}
        self.assertEqual(states[workflow.ADOPTED_REPO_PHASE_ID], "refused")
        self.assertFalse(report["complete"])

    def test_waiting_desk_readiness_is_visible_without_bypassing_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            report = workflow.evaluate(
                self.manifest,
                self.manifest_sha,
                Path(raw_temp) / "evidence",
                None,
            )
        blockers = {
            item["phase_id"]: item["classification"]
            for item in report["latent_tooling_blockers"]
        }
        self.assertEqual(blockers, {})
        states = {phase["id"]: phase["state"] for phase in report["phases"]}
        self.assertEqual(states["native-cold-start-owner"], "waiting")
        self.assertEqual(states["persistent-image"], "waiting")
        readiness = {
            phase["id"]: phase.get("tooling_readiness", {}).get("classification")
            for phase in report["phases"]
            if phase["id"] in {"native-cold-start-owner", "persistent-image"}
        }
        self.assertEqual(
            readiness,
            {"native-cold-start-owner": "ready", "persistent-image": "ready"},
        )

    def test_artifact_custody_requires_exact_local_and_portable_bytes(self) -> None:
        payload_a = b"phase-a"
        payload_b = b"phase-bb"
        manifest = copy.deepcopy(self.manifest)
        for artifact, payload in zip(manifest["artifacts"], (payload_a, payload_b)):
            artifact["sha256"] = hashlib.sha256(payload).hexdigest()
            artifact["bytes"] = len(payload)
            artifact["portable_path"] = f"sha256/{artifact['sha256']}/dcentrald"
        original_root = workflow.REPO_ROOT
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            local_root = temp / "repo"
            portable_root = temp / "portable"
            for artifact, payload in zip(manifest["artifacts"], (payload_a, payload_b)):
                local = local_root / artifact["local_path"]
                portable = portable_root.joinpath(
                    *Path(artifact["portable_path"]).parts
                )
                local.parent.mkdir(parents=True, exist_ok=True)
                portable.parent.mkdir(parents=True, exist_ok=True)
                local.write_bytes(payload)
                portable.write_bytes(payload)
            try:
                workflow.REPO_ROOT = local_root
                facts = workflow.verify_artifacts(manifest, portable_root)
                self.assertEqual(len(facts["artifacts"]), 2)
                portable = portable_root.joinpath(
                    *Path(manifest["artifacts"][0]["portable_path"]).parts
                )
                portable.write_bytes(b"tamper")
                with self.assertRaises(workflow.WorkflowError):
                    workflow.verify_artifacts(manifest, portable_root)
            finally:
                workflow.REPO_ROOT = original_root

    def test_manifest_rejects_cycle_bad_portable_path_and_weakened_policy(self) -> None:
        mutations = []
        cycle = copy.deepcopy(self.manifest)
        cycle["phases"][0]["depends_on"] = [cycle["phases"][-1]["id"]]
        mutations.append(cycle)
        portable = copy.deepcopy(self.manifest)
        portable["artifacts"][0]["portable_path"] = "latest/dcentrald"
        mutations.append(portable)
        policy = copy.deepcopy(self.manifest)
        policy["contact_policy"]["controller_may_grant_authority"] = True
        mutations.append(policy)
        with tempfile.TemporaryDirectory() as raw_temp:
            for index, document in enumerate(mutations):
                with self.subTest(index=index):
                    path = Path(raw_temp) / f"manifest-{index}.json"
                    path.write_text(json.dumps(document), encoding="utf-8")
                    with self.assertRaises(workflow.WorkflowError):
                        workflow.load_manifest(path)

    def test_module_phase_cannot_complete_from_receipt_without_evidence(self) -> None:
        phase = next(
            phase
            for phase in self.manifest["phases"]
            if phase["id"] == "native-secure-firmware-re"
        )
        with tempfile.TemporaryDirectory() as raw_temp:
            phase_dir = Path(raw_temp)
            (phase_dir / "verification.json").write_text("{}\n", encoding="ascii")
            with self.assertRaisesRegex(Exception, "required evidence|evidence directory"):
                workflow.verify_generic_module(phase, phase_dir)

    def test_bounded_campaign_phase_requires_separate_physical_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            phase_dir = Path(raw_temp)
            (phase_dir / "plan.kv").write_text("plan\n", encoding="ascii")
            (phase_dir / "trial").mkdir()
            (phase_dir / "verification.json").write_text("{}\n", encoding="ascii")
            with self.assertRaisesRegex(FileNotFoundError, "physical"):
                workflow.verify_bounded(phase_dir, self.manifest)

    def test_adopted_plan_must_bind_campaign_artifact_and_repo_inputs(self) -> None:
        self.assertEqual(
            dict(workflow.COMMON_ADOPTED_PLAN_REPO_BINDINGS)["config"],
            workflow.ADOPTED_LIVE_CONFIG_REPO_PATH,
        )
        self.assertNotEqual(
            workflow.ADOPTED_LIVE_CONFIG_REPO_PATH,
            "DCENT_OS_Antminer/dcentrald/dcentrald_s19k.toml",
        )
        manifest = copy.deepcopy(self.manifest)
        repo = next(
            phase for phase in manifest["phases"] if phase["verifier"]["kind"] == "repo"
        )["verifier"]
        plan: dict[str, str] = {}
        artifact = next(
            item
            for item in manifest["artifacts"]
            if item["id"] == workflow.ADOPTED_PHASE12_ARTIFACT_ID
        )
        plan.update(
            sha256=artifact["sha256"],
            bytes=str(artifact["bytes"]),
            expected_artifact_sha256=artifact["sha256"],
            expected_artifact_bytes=str(artifact["bytes"]),
        )
        for index, (prefix, path) in enumerate(
            workflow.COMMON_ADOPTED_PLAN_REPO_BINDINGS, 1
        ):
            identity = {
                "sha256": hashlib.sha256(path.encode("ascii")).hexdigest(),
                "bytes": index,
            }
            if path not in repo["required_paths"]:
                repo["required_paths"].append(path)
            repo["required_identities"][path] = identity
            plan[f"{prefix}_sha256"] = identity["sha256"]
            plan[f"{prefix}_bytes"] = str(identity["bytes"])

        binding = workflow._verify_adopted_plan_binding(
            plan,
            manifest,
            workflow.ADOPTED_PHASE12_ARTIFACT_ID,
            workflow.COMMON_ADOPTED_PLAN_REPO_BINDINGS,
        )
        self.assertEqual(
            binding["scope"], "controller-derived-transient-status-only"
        )
        self.assertEqual(binding["artifact"]["id"], "phase0-3")
        self.assertEqual(
            len(binding["repository_inputs"]),
            len(workflow.COMMON_ADOPTED_PLAN_REPO_BINDINGS),
        )

        retired = dict(plan)
        retired.update(
            sha256="fbd730e5c189cc69d5a191fd3bffdba3f2401e171d24e36e3d86b0d38dc0967b",
            bytes="24065480",
            expected_artifact_sha256="fbd730e5c189cc69d5a191fd3bffdba3f2401e171d24e36e3d86b0d38dc0967b",
            expected_artifact_bytes="24065480",
        )
        with self.assertRaisesRegex(
            workflow.WorkflowError,
            "does not match campaign artifact phase0-3",
        ):
            workflow._verify_adopted_plan_binding(
                retired,
                manifest,
                workflow.ADOPTED_PHASE12_ARTIFACT_ID,
                workflow.COMMON_ADOPTED_PLAN_REPO_BINDINGS,
            )

        stale_runner = dict(plan)
        stale_runner["runner_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            workflow.WorkflowError,
            "plan input runner does not match campaign repository identity",
        ):
            workflow._verify_adopted_plan_binding(
                stale_runner,
                manifest,
                workflow.ADOPTED_PHASE12_ARTIFACT_ID,
                workflow.COMMON_ADOPTED_PLAN_REPO_BINDINGS,
            )

        missing_input = copy.deepcopy(manifest)
        missing_repo = next(
            phase
            for phase in missing_input["phases"]
            if phase["verifier"]["kind"] == "repo"
        )["verifier"]
        custody_path = dict(workflow.COMMON_ADOPTED_PLAN_REPO_BINDINGS)[
            "custody_observer"
        ]
        missing_repo["required_paths"].remove(custody_path)
        del missing_repo["required_identities"][custody_path]
        with self.assertRaisesRegex(
            workflow.WorkflowError,
            "repository seal does not bind adopted plan input custody_observer",
        ):
            workflow._verify_adopted_plan_binding(
                plan,
                missing_input,
                workflow.ADOPTED_PHASE12_ARTIFACT_ID,
                workflow.COMMON_ADOPTED_PLAN_REPO_BINDINGS,
            )

    def test_blocked_operator_tooling_emits_implementation_wave_before_gate(self) -> None:
        phase = next(
            item
            for item in self.manifest["phases"]
            if item["id"] == "native-hardware-contract"
        )
        self.assertEqual(
            set(phase["depends_on"]),
            {
                "adopted-phase12",
                "static-bhb5690x-controller-interface",
                "native-population-coverage",
            },
        )
        report = {
            "campaign_id": self.manifest["campaign_id"],
            "manifest_sha256": self.manifest_sha,
            "frontier": [phase["id"]],
            "phases": [
                {
                    "id": phase["id"],
                    "state": "blocked_tooling",
                    "reason": "offline verifier missing",
                }
            ],
        }
        wave = workflow.emit_agent_tasks(self.manifest, report)
        self.assertEqual(wave["operator_gates"], [])
        self.assertEqual(wave["tasks"][0]["role"], "verifier-owner")
        self.assertEqual(
            wave["tasks"][0]["owns"],
            ["DCENT_OS_Antminer/scripts/s19k_native_hardware_verify.py"],
        )

    def test_verify_exit_requires_completion_or_exact_expected_frontier(self) -> None:
        report = {
            "complete": False,
            "frontier": [
                "portable-artifact-custody",
                "native-secure-firmware-re",
                "static-bhb5690x-controller-interface",
            ],
            "phases": [
                {"state": "awaiting_operator"},
                {"state": "ready"},
            ],
        }
        self.assertEqual(workflow.verify_exit_code(report, None), 1)
        self.assertEqual(
            workflow.verify_exit_code(
                report,
                "portable-artifact-custody,native-secure-firmware-re,"
                "static-bhb5690x-controller-interface",
            ),
            0,
        )
        self.assertEqual(
            workflow.verify_exit_code(report, "portable-artifact-custody"), 1
        )
        report["phases"].append({"state": "blocked_tooling"})
        self.assertEqual(
            workflow.verify_exit_code(
                report,
                "portable-artifact-custody,native-secure-firmware-re,"
                "static-bhb5690x-controller-interface",
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()
