#!/usr/bin/env python3
"""Pin the BM1366/S19k source, ledger, authority, and CI contract."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
DCENTRALD_ROOT = DCENTOS_ROOT / "dcentrald"
COMMON_SRC = DCENTRALD_ROOT / "dcentrald-common" / "src"
ASIC_DRIVERS = DCENTRALD_ROOT / "dcentrald-asic" / "src" / "drivers"
SILICON_SRC = DCENTRALD_ROOT / "dcentrald-silicon-profiles" / "src"
DAEMON_SRC = DCENTRALD_ROOT / "dcentrald" / "src"
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

EXPECTED_MODULES = {
    "s19k_am3_gpio437",
    "s19k_am3_install",
    "s19k_aml_dtb",
    "s19k_apw121215f_stock",
    "s19k_bm1366_amtc_pattern",
    "s19k_bm1366_braiins_nonce",
    "s19k_bm1366_init_seq",
    "s19k_bm1366_nopic_beta",
    "s19k_bm1366_share",
    "s19k_bm1366_uart_rx",
    "s19k_bm1366_wire_b",
    "s19k_bmu_payload_evidence",
    "s19k_bosminer_enum",
    "s19k_bosminer_t1_pack",
    "s19k_braiins_chain_discover",
    "s19k_braiins_job",
    "s19k_braiins_tmp_deploy",
    "s19k_braiins_wire_try",
    "s19k_midrun_flush_evidence",
    "s19k_nand_env",
    "s19k_passthrough_preflight",
    "s19k_stock_bmu_toc",
    "s19k_uart_trans_job",
}

COMMON_COMMAND = (
    "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- s19k_"
)

EXPECTED_TESTS = {
    "uv run --with pytest pytest -q test_x19_aml_production_route_evidence.py --rootdir=. from tools/ (21/21)",
    "cargo +1.90.0 test -p dcentrald-common x19_aml_production_route --lib (5/5)",
    f"Linux: {COMMON_COMMAND}",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-asic --lib -- drivers::bm1366 (7/7)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-silicon-profiles --lib -- bm1366 (42/42)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald --bin dcentrald -- s19k_ (70/70 as of 2026-08-29; includes paced-ladder, straggler-re-enroll, coverage-probe, salvage-window, and shared-contract rebasing)",
    "python DCENT_OS_Antminer/scripts/test_bm1366_s19k_ledger_convergence.py -q (6/6)",
}


class Bm1366S19kLedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        matches = [entry for entry in ledger["entries"] if entry["id"] == "asic.bm1366"]
        if len(matches) != 1:
            raise AssertionError(
                f"expected one asic.bm1366 entry, found {len(matches)}"
            )
        cls.entry = matches[0]

    def test_ledger_tracks_every_s19k_contract_module_exactly(self) -> None:
        source_modules = {path.stem for path in COMMON_SRC.glob("s19k_*.rs")}
        self.assertEqual(source_modules, EXPECTED_MODULES)
        self.assertEqual(set(self.entry["offline_contract_modules"]), EXPECTED_MODULES)

        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        anchor = self.entry["dcentos_anchor"]
        for module in EXPECTED_MODULES:
            self.assertIn(f"pub mod {module};", lib_rs)
            self.assertIn(f"{module}.rs", anchor)

    def test_row_records_current_depth_and_split_authority(self) -> None:
        self.assertEqual(self.entry["status"], "experimental")
        self.assertEqual(self.entry["acceptance_chip_labels"], ["BM1366"])
        self.assertEqual(set(self.entry["tests"]), EXPECTED_TESTS)
        self.assertGreaterEqual(len(self.entry["safety"]), 10)
        self.assertGreaterEqual(len(self.entry["instrumentation"]), 9)
        row = json.dumps(self.entry, sort_keys=True)
        for needle in (
            "generic BM1366 driver",
            "native non-passthrough",
            "no mining transport",
            "Track-1",
            "mining-disabled",
            "BHB5690x",
            "GPIO437",
            "accepted-share",
            "persistent-write",
            "no --skip",
        ):
            self.assertIn(needle, row)

    def test_generic_driver_and_exact_native_route_stay_distinct(self) -> None:
        driver = (ASIC_DRIVERS / "bm1366.rs").read_text(encoding="utf-8")
        registry = (ASIC_DRIVERS / "mod.rs").read_text(encoding="utf-8")
        admission = (SILICON_SRC / "s19k_nopic_admission.rs").read_text(
            encoding="utf-8"
        )
        serial = (DAEMON_SRC / "serial_mining.rs").read_text(encoding="utf-8")

        self.assertIn("impl ChipDriver for Bm1366Driver", driver)
        self.assertIn(
            "registry.register(Box::new(bm1366::Bm1366Driver::new()));", registry
        )
        self.assertIn("pub const S19K_NATIVE_MINING_REFUSAL", admission)
        self.assertIn("S19kMiningDisposition::NotImplemented", admission)
        self.assertIn(
            "if is_bm1366 && !passthrough && !self.s19k_native_cold_start_requested()",
            serial,
        )
        self.assertIn(
            "native BM1366 requires an admitted am3-s19k serial configuration",
            serial,
        )
        self.assertIn(".promote_s19k_native_cold_start(&mut cold_owner)", serial)
        self.assertIn("fresh 77-chip-per-selected-route cold init failed", serial)

    def test_track1_route_is_explicit_and_defaults_remain_off(self) -> None:
        serial = (DAEMON_SRC / "serial_mining.rs").read_text(encoding="utf-8")
        host_config = (DCENTRALD_ROOT / "dcentrald_s19k.toml").read_text(
            encoding="utf-8"
        )
        overlay_config = (
            DCENTOS_ROOT
            / "br2_external_dcentos"
            / "board"
            / "amlogic"
            / "am3-s19kpro"
            / "rootfs-overlay"
            / "etc"
            / "dcentrald.toml"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "let braiins_bm1366_passthrough_handoff = passthrough && is_bm1366",
            serial,
        )
        self.assertIn("let serial = if braiins_bm1366_passthrough_handoff", serial)
        self.assertIn("admit_braiins_mining_on_ports(&opened)", serial)
        self.assertIn("admit_s19k_passthrough_work_tx(silence_class, gpio437)", serial)
        self.assertIn("admit_s19k_track1_thermal_ready(", serial)
        self.assertIn("Track-1 SoC watchdog", serial)
        for config in (host_config, overlay_config):
            self.assertIn("enabled = false", config)
            self.assertIn('model = "s19k"', config)
            self.assertIn("passthrough = false", config)

    def test_workflow_owns_all_focused_suites_and_skip_is_fail_closed(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        for command in (
            COMMON_COMMAND,
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-asic --lib -- drivers::bm1366",
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-silicon-profiles --lib -- bm1366",
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald --bin dcentrald -- s19k_",
        ):
            self.assertIn(command, workflow)

        runner = (DCENTOS_ROOT / "scripts" / "run_filtered_cargo_test.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('filter="${args[$((sep + 1))]}"', runner)
        self.assertIn('harness_args=("${args[@]:sep+2}")', runner)
        self.assertIn('"$filter" -- --list "${harness_args[@]}"', runner)
        self.assertIn('"$filter" -- "${harness_args[@]}"', runner)

    def test_aggregate_gate_executes_this_convergence_suite(self) -> None:
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/test_bm1366_s19k_ledger_convergence.py -q", aggregate)


if __name__ == "__main__":
    unittest.main()
