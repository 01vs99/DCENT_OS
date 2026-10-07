#!/usr/bin/env python3
"""Drift gates for the one authoritative S19k Gauntlet operator path."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
WORKSPACE_ROOT = PROJECT_ROOT.parent.parent
CURRENT_DIR = WORKSPACE_ROOT / ""
HISTORICAL_DIR = (
    WORKSPACE_ROOT / ""
)
LEGACY_BENCH = PROJECT_ROOT / ""
LEGACY_OPERATOR_DOCS = (
    LEGACY_BENCH,
    PROJECT_ROOT
    / "",
    PROJECT_ROOT
    / "",
    WORKSPACE_ROOT / "",
    WORKSPACE_ROOT
    / "",
    PROJECT_ROOT
    / "",
    PROJECT_ROOT
    / "",
    PROJECT_ROOT
    / "",
)

PHASE03_SHA = "fbd730e5c189cc69d5a191fd3bffdba3f2401e171d24e36e3d86b0d38dc0967b"
PHASE03_BYTES = "24065480"
ENDURANCE_SHA = "9570a9fcd8e8a2cff6f3d21902f6354666c5b337b7b260641e5b0baf9260b4d6"
ENDURANCE_BYTES = "24146528"
HOST_KEY_SHA = "SHA256:tvXAsrOvqpcajFIKHLOrpOgJAKl4RcK5YDTD01/OIWg"
RUNNER_PATH = SCRIPT_DIR / "dcentrald_s19k_tmp_remote_run.sh"
RUNNER_SHA = hashlib.sha256(RUNNER_PATH.read_bytes()).hexdigest()
RUNNER_BYTES = str(RUNNER_PATH.stat().st_size)
DEPLOYER_PATH = SCRIPT_DIR / "dcentrald_s19k_tmp_deploy.sh"
DEPLOYER_SHA = hashlib.sha256(DEPLOYER_PATH.read_bytes()).hexdigest()
DEPLOYER_BYTES = str(DEPLOYER_PATH.stat().st_size)
PINNED_DRY_RUN_PLAN = "TMP_DEPLOY_PLAN.20260823153500.1473482.oDbtYk"
PINNED_DRY_RUN_SHA = "fe96be80feabaa3e88ee020a1a2665fb1a523f43dbc1c509f1830b79112fb3e9"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def shell_blocks(markdown: str) -> list[str]:
    return re.findall(r"(?ms)^```sh\n(.*?)\n```$", markdown)


def code_blocks(markdown: str) -> list[str]:
    return re.findall(r"(?ms)^```[^\n]*\n(.*?)^```$", markdown)


class S19kGauntletRunbookConvergenceTests(unittest.TestCase):
    def test_current_card_has_exactly_three_pinned_deploy_commands(self) -> None:
        card = read(CURRENT_DIR / "NEXT_OFFICE_RUNBOOK.md")
        self.assertIn("sole current executable S19k Gauntlet card", card)
        self.assertIn("BENCH_PLAN.md", card)
        deploy_blocks = [
            block
            for block in shell_blocks(card)
            if "dcentrald_s19k_tmp_deploy.sh" in block
        ]
        self.assertEqual(len(deploy_blocks), 3)
        self.assertEqual(
            sum("--handoff-no-work" in block for block in deploy_blocks), 1
        )
        self.assertEqual(
            sum("--bounded-work-proof" in block for block in deploy_blocks), 1
        )
        self.assertEqual(
            sum("--endurance-work-proof" in block for block in deploy_blocks), 1
        )
        for block in deploy_blocks:
            self.assertIn("--expected-artifact-sha256", block)
            self.assertIn("--expected-artifact-bytes", block)
            self.assertIn("--known-hosts <KNOWN_HOSTS>", block)
            self.assertIn(f"--expected-host-key-sha256 {HOST_KEY_SHA}", block)
            self.assertNotIn("target/s19k-tmp", block)
            self.assertNotRegex(block, r"s19k-tmp-deploy/v(?:9|10|11)")

        phase03 = [block for block in deploy_blocks if "phase0-3/dcentrald" in block]
        self.assertEqual(len(phase03), 2)
        for block in phase03:
            self.assertIn(f"--expected-artifact-sha256 {PHASE03_SHA}", block)
            self.assertIn(f"--expected-artifact-bytes {PHASE03_BYTES}", block)

        endurance = [block for block in deploy_blocks if "endurance/dcentrald" in block]
        self.assertEqual(len(endurance), 1)
        self.assertIn(f"--expected-artifact-sha256 {ENDURANCE_SHA}", endurance[0])
        self.assertIn(f"--expected-artifact-bytes {ENDURANCE_BYTES}", endurance[0])

    def test_historical_bench_plan_is_non_executable_and_points_forward(self) -> None:
        bench = read(HISTORICAL_DIR / "BENCH_PLAN.md")
        self.assertIn("is **not an executable runbook**", bench)
        self.assertIn("The sole current command authority is", bench)
        self.assertIn("2026-08-21-s19k-office-gauntlet/NEXT_OFFICE_RUNBOOK.md", bench)
        self.assertIn("Never reconstruct a live command from this plan", bench)
        self.assertEqual(shell_blocks(bench), [])
        self.assertNotIn("dcentrald_s19k_tmp_deploy.sh", bench)
        self.assertNotIn("target/s19k-tmp/armv7-unknown-linux-musleabihf", bench)
        self.assertNotIn("schema=dcentos.s19k-tmp-deploy/v9", bench)

    def test_legacy_bench_pack_is_non_executable_and_points_forward(self) -> None:
        bench = read(LEGACY_BENCH)
        self.assertRegex(bench, r"not an\s+executable runbook")
        self.assertIn("sole current executable S19k Gauntlet card", bench)
        self.assertIn(
            "",
            bench,
        )
        self.assertIn("Never reconstruct a command", bench)
        self.assertNotIn("```", bench)
        self.assertNotIn("dcentrald_s19k_tmp_deploy.sh", bench)
        self.assertNotIn("cargo build", bench)
        self.assertNotIn("target/armv7-unknown-linux-musleabihf", bench)
        self.assertNotIn("S99bosminer", bench)
        self.assertNotIn("<MINER_IP>", bench)

    def test_all_legacy_s19k_operator_docs_are_superseded_and_non_executable(
        self,
    ) -> None:
        forbidden_in_code = (
            "ssh ",
            "scp ",
            "sftp_put",
            "dcentrald_s19k_tmp",
            "s19k_braiins_wire_try",
            "S99bosminer",
            "install_amlogic_persistent",
            "flash_erase",
            "nandwrite",
            "fw_setenv",
            "cargo build",
            "<MINER_IP>",
        )
        for path in LEGACY_OPERATOR_DOCS:
            with self.subTest(path=path.relative_to(WORKSPACE_ROOT)):
                document = read(path)
                self.assertRegex(
                    document,
                    r"sole current(?:\s|>\s)*executable S19k(?:\s|>\s)*Gauntlet card",
                )
                executable_looking = "\n".join(code_blocks(document))
                for forbidden in forbidden_in_code:
                    self.assertNotIn(forbidden, executable_looking)
        ralph = read(
            WORKSPACE_ROOT / ""
            "0d-cvitek-s19k-pro-78.md"
        )
        self.assertNotIn("203.0.113.78", ralph)
        self.assertNotIn("root@", ralph)

    def test_historical_handoff_documents_point_to_current_card(self) -> None:
        for filename in (
            "ARTIFACT_RECEIPT.md",
            "BENCH_PLAN.md",
            "CONTEXT.md",
            "FINAL_REPORT.md",
            "OFFLINE_EXHAUSTION.md",
            "PLAN.md",
            "TASKS.md",
        ):
            with self.subTest(filename=filename):
                document = read(HISTORICAL_DIR / filename)
                self.assertIn("2026-08-21-s19k-office-gauntlet", document)
                self.assertIn("NEXT_OFFICE_RUNBOOK.md", document)

    def test_phase12_tool_pins_match_current_files(self) -> None:
        gate = read(CURRENT_DIR / "PHASE12_NO_WORK_GATE.md")
        for filename in (
            "s19k_phase12_normalize.py",
            "test_s19k_phase12_normalize.py",
            "s19k_phase12_capture_verify.py",
            "test_s19k_phase12_capture_verify.py",
            "s19k_no_work_prepare.py",
            "s19k_no_work_verify.py",
            "test_s19k_no_work_prepare.py",
            "test_s19k_no_work_verify.py",
        ):
            path = SCRIPT_DIR / filename
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertIn(digest, gate, filename)
            self.assertIn(f"{path.stat().st_size:,}", gate, filename)

    def test_endurance_and_deployer_pins_match_current_files(self) -> None:
        gate = read(CURRENT_DIR / "ENDURANCE_GATE.md")
        card = read(CURRENT_DIR / "NEXT_OFFICE_RUNBOOK.md")
        inputs = (
            SCRIPT_DIR / "dcentrald_s19k_tmp_deploy.sh",
            SCRIPT_DIR / "s19k_endurance_collect.py",
            SCRIPT_DIR / "s19k_endurance_verify.py",
            SCRIPT_DIR / "s19k_endurance_baseline.py",
            SCRIPT_DIR / "s19k_bounded_transcript_verify.py",
            SCRIPT_DIR / "s19k_tmp_build_artifact.py",
            PROJECT_ROOT / "dcentrald/dcentrald_s19k_braiins_ckpool.toml",
        )
        for path in inputs:
            with self.subTest(path=path.name):
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                self.assertIn(digest, gate)
                self.assertIn(f"{path.stat().st_size:,}", gate)
        deployer = inputs[0]
        self.assertIn(hashlib.sha256(deployer.read_bytes()).hexdigest(), card)
        self.assertIn(str(deployer.stat().st_size), card)

    def test_current_card_requires_sealed_phase12_and_external_reverification(
        self,
    ) -> None:
        card = read(CURRENT_DIR / "NEXT_OFFICE_RUNBOOK.md")
        self.assertIn("before energization", card)
        self.assertIn("Never attach, remove or reposition", card)
        self.assertIn("do not instrument it or invoke the joined `Run:`", card)
        self.assertIn("while AC was disconnected and verified absent", card)
        self.assertIn("complete `INSTRUMENTATION_PREFLIGHT.md`", card)
        self.assertIn("GPIO437, GPIO454/455/456", card)
        self.assertIn("Every named GPIO channel is required", card)
        self.assertIn("do not invoke `Run:`", card)
        self.assertNotIn("if safe test points exist, GPIO437/reset capture", card)
        self.assertIn("python3 scripts/s19k_phase12_normalize.py", card)
        self.assertIn("python3 scripts/s19k_phase12_capture_verify.py stage", card)
        self.assertIn("python3 scripts/s19k_no_work_prepare.py", card)
        self.assertIn("S19K_PHASE12_BUNDLE_OK", card)
        self.assertIn("python3 scripts/s19k_no_work_verify.py", card)
        self.assertIn("<NEW_EXTERNAL_PHASE12_REVERIFICATION_JSON>", card)
        self.assertIn("exact thirteen-file bundle", card)
        self.assertIn("--preflight <REVIEWED_INSTRUMENTATION_PREFLIGHT_KV>", card)

    def test_phase3_requires_instrumentation_decay_and_stock_restoration(self) -> None:
        card = read(CURRENT_DIR / "NEXT_OFFICE_RUNBOOK.md")
        annex = read(CURRENT_DIR / "INSTRUMENTATION_PREFLIGHT.md")
        self.assertIn("complete `INSTRUMENTATION_PREFLIGHT.md`", card)
        self.assertIn("preserve capture continuously through terminal", card)
        self.assertIn("exact staged stock-restart helper", card)
        self.assertIn("Do not guess a hashboard rail test point", annex)
        self.assertIn("earth-referenced oscilloscope probe is forbidden", annex)
        self.assertIn("no gap over five seconds", annex)
        self.assertIn("instrumentation-preflight/v3", annex)
        self.assertIn("the 1 Hz slow-monitor cadence is not edge", annex)
        self.assertIn("gpio_edge_sample_rate_hz=<CANONICAL_DECIMAL_AT_LEAST_100000>", annex)
        self.assertIn("uart_sample_rate_hz=<CANONICAL_DECIMAL_AT_LEAST_25000000>", annex)
        self.assertIn("fan_harness_status=untouched-fans-remain-connected", annex)
        self.assertIn("slots2-and3-only-populated-hashboard-feeds", annex)
        self.assertIn("AC input, a PSU input lead, a controller/fan feed", annex)
        self.assertIn("at least two milliseconds", annex)

    def test_obsolete_artifacts_never_appear_in_executable_blocks(self) -> None:
        documents = "\n".join(read(path) for path in CURRENT_DIR.glob("*.md"))
        executable = "\n".join(shell_blocks(documents))
        for forbidden in (
            "037ce6b9473d090437604998d75d3ee345f95e341b59de57786d3c43860311ac",
            "72427970",
            "e0fb5ab7",
            "target/s19k-tmp",
        ):
            self.assertNotIn(forbidden, executable)

    def test_host_key_pinned_dry_run_remains_explicitly_non_authorizing(self) -> None:
        card = read(CURRENT_DIR / "NEXT_OFFICE_RUNBOOK.md")
        self.assertIn(PINNED_DRY_RUN_PLAN, card)
        self.assertIn(PINNED_DRY_RUN_SHA, card)
        self.assertIn("dry_run=true", card)
        self.assertIn("ssh_host_key_admission=exact-operator-pin", card)
        self.assertIn("no SSH, SCP, chmod or target write", card)
        self.assertIn("cannot authorize contact or physical", card)
        self.assertIn(f"Runner SHA-256 / bytes | `{RUNNER_SHA}` / `{RUNNER_BYTES}`", card)
        self.assertIn(f"Deployer SHA-256 / bytes | `{DEPLOYER_SHA}` / `{DEPLOYER_BYTES}`", card)
        self.assertIn("predates the current deployer", card)

    def test_dynamic_controller_precedes_live_command_authority(self) -> None:
        card = read(CURRENT_DIR / "NEXT_OFFICE_RUNBOOK.md")
        admission = card.index("## Dynamic campaign admission")
        first_deploy = card.index("./scripts/dcentrald_s19k_tmp_deploy.sh")
        self.assertLess(admission, first_deploy)
        self.assertIn("--artifact-root <PORTABLE_ARTIFACT_ROOT> verify", card)
        self.assertIn("--expect-frontier adopted-phase12", card)
        self.assertIn("portable-artifact-custody: verified", card)
        self.assertIn("adopted-phase12` must then be the live", card)
        self.assertIn("They grant no contact, mining, power, GPIO", card)

    def test_power_on_is_explicitly_non_authorizing(self) -> None:
        card = read(CURRENT_DIR / "NEXT_OFFICE_RUNBOOK.md")
        normalized = " ".join(card.split())
        self.assertIn(
            "Powering on the unit, stating that it will be powered on", normalized
        )
        self.assertIn(
            "None of those actions or statements authorizes SSH, staging", normalized
        )
        self.assertIn("process signaling, GPIO access", normalized)
        self.assertIn("reboot, or persistent mutation", normalized)

    def test_ci_runs_this_convergence_suite(self) -> None:
        ci = read(PROJECT_ROOT / "scripts/ci_offline_gates.sh")
        workflow = read(WORKSPACE_ROOT / ".github/workflows/dcentos-offline-gates.yml")
        marker = "test_s19k_gauntlet_runbook_convergence.py"
        self.assertIn(marker, ci)
        self.assertIn(marker, workflow)
        for required in (
            "test_s19k_bounded_transcript_verify.py",
            "test_s19k_endurance.py",
            "test_s19k_tmp_build_artifact.py",
            "s19k_host_verify.py",
            "test_amlogic_lz4c.py",
            "test_wrap_raw_elf.py",
            "test_s19k_native_re_verify.py",
            "test_s19k_gauntlet_workflow.py",
            "test_s19k_workflow_checkout.sh",
        ):
            with self.subTest(required=required):
                self.assertTrue(required in ci, f"offline gate does not execute {required}")
                self.assertTrue(required in workflow, f"workflow does not execute {required}")
        checkout = read(PROJECT_ROOT / "scripts/test_s19k_workflow_checkout.sh")
        self.assertIn('mktemp -d', checkout)
        self.assertIn('"$SCRIPT_DIR/s19k_gauntlet_workflow.py"', checkout)
        self.assertIn('--evidence-root "$DCENT_S19K_CHECKOUT_TMP" verify', checkout)
        self.assertIn('--expect-frontier portable-artifact-custody,native-build-reproducibility,native-secure-firmware-re,static-bhb5690x-controller-interface', checkout)
        self.assertIn(
            "**", workflow
        )
        self.assertIn("**", workflow)
        self.assertIn("**", workflow)
        self.assertIn("tools/ghidra/amlogic_lz4c.py", workflow)
        self.assertIn("tools/ghidra/wrap_raw_elf.py", workflow)
        self.assertIn(
            "",
            workflow,
        )

    def test_project_context_keeps_gpio437_polarity_board_target_scoped(self) -> None:
        context = read(PROJECT_ROOT / "")
        self.assertIn("GPIO437 is **not universal across Amlogic targets**", context)
        self.assertIn("**raw 0 = ON, raw 1 = OFF**", context)
        self.assertIn("Exact S21 Pro/XP independently use the same AM3", context)
        self.assertIn("0=ON,1=OFF mapping", context)
        self.assertIn("This does not generalize to S21+/hydro/immersion variants.", context)
        self.assertIn("is not an electrical rail measurement.", context)
        self.assertNotIn("**raw 1 = ON, raw 0 = SafeOff**", context)
        self.assertNotIn("PWR_EN polarity confirmed active-HIGH", context)
        self.assertNotIn(
            "Both stock-Bitmain bmminer and VNish cgminer use the same active-HIGH",
            context,
        )


if __name__ == "__main__":
    unittest.main()
