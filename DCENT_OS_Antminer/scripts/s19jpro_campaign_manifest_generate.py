#!/usr/bin/env python3
"""One-shot generator for the S19j Pro complete-enablement campaign manifest.

Regenerating overwrites the tracked manifest; any phase identity change must
be re-pinned in tests. Run from the repository root.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
OUT = (
    REPO
    / ""
    "S19J_PRO_ENABLEMENT_CAMPAIGN.json"
)
MODULE_PATH = "DCENT_OS_Antminer/scripts/s19jpro_lane_verify.py"


def ident(rel: str) -> dict[str, object]:
    data = (REPO / rel).read_bytes()
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


PINNED = [
    "DCENT_OS_Antminer/scripts/s19jpro_enablement_workflow.py",
    "DCENT_OS_Antminer/scripts/s19jpro_lane_verify.py",
    "DCENT_OS_Antminer/scripts/test_s19jpro_enablement_workflow.py",
    "DCENT_OS_Antminer/scripts/test_s19jpro_lane_verify.py",
]


def phase(
    pid: str,
    title: str,
    kind: str,
    expert: str,
    deps: list[str],
    mission: str,
    owns: list[str] | None = None,
    verifier: dict[str, object] | None = None,
) -> dict[str, object]:
    if verifier is None:
        verifier = {"kind": "module", "path": MODULE_PATH}
    return {
        "id": pid,
        "title": title,
        "kind": kind,
        "expert": expert,
        "depends_on": deps,
        "owns": owns or [],
        "mission": mission,
        "verifier": verifier,
    }


PHASES: list[dict[str, object]] = [
    phase(
        "offline-repo-contract",
        "Offline controller and lane verifier toolchain",
        "desk",
        "DCENT_QA",
        [],
        "Keep the offline controller, shared lane verifier, and their adversarial tests byte-pinned so every later phase builds on an unmodified toolchain.",
        owns=PINNED,
        verifier={
            "kind": "repo",
            "required_paths": PINNED,
            "required_identities": {p: ident(p) for p in PINNED},
        },
    ),
    phase(
        "variant-matrix-closure",
        "Canonical S19j Pro version matrix + first-class SKU rows",
        "desk",
        "DCENT_RE",
        ["offline-repo-contract"],
        "Close the canonical S19j Pro version matrix (control board x model x hashboard x PIC/NoPic x firmware state) and add the missing am3-s19jpro-aml and am3-s19jproplus first-class skus.conf rows.",
        owns=[
            "DCENT_OS_Antminer/scripts/hw-acceptance/skus.conf",
            "DCENT_OS_Antminer/scripts/hw-acceptance/test_skus_conf_valid.sh",
            "SUPPORT_MATRIX.md",
            "scripts/check_support_matrix_drift.py",
            "",
        ],
    ),
    phase(
        "hashboard-revision-atlas",
        "Read-only BHB hashboard revision atlas",
        "desk",
        "DCENT_EE",
        ["variant-matrix-closure"],
        "Extend the read-only hashboard EEPROM atlas with every S19j Pro BHB class (BHB42601..BHB42612) and the PIC-versus-NoPic roster; EEPROM writes to 0x50-0x57 stay forbidden on am2/am3 lanes.",
        owns=[""],
    ),
    phase(
        "unlock-surface-closure",
        "Complete unlock ladder for every entry firmware state",
        "desk",
        "DCENT_Security",
        ["offline-repo-contract", "variant-matrix-closure"],
        "Audit and document the complete unlock ladder for every S19j Pro entry firmware state (locked stock, BraiinsOS, LuxOS, VNish) across XIL/BB/AML boards: signature-bypass web package, SSH-enabler cascade, Amlogic USB-OTG downgrade, bitmain_bb_access.",
        owns=[
            "projects/dcent-toolbox/src/dcent_toolbox/cli/commands/unlock.py",
            "projects/dcent-toolbox/src/dcent_toolbox/cli/commands/amlogic_unlock.py",
            "DCENT_OS_Antminer/web_packages/",
        ],
    ),
    phase(
        "xil-full-chain-init",
        "XIL full-roster chain enumeration fix",
        "desk",
        "DCENT_CE",
        ["offline-repo-contract"],
        "Fix XIL chain enumeration so init sees the full per-board chip roster (historical standalone runs enumerated only 28 of 126) and pin it with the s19jpro_full_chain_init acceptance test.",
        owns=[
            "DCENT_OS_Antminer/dcentrald/dcentrald/tests/s19jpro_full_chain_init.rs",
            "DCENT_OS_Antminer/dcentrald/dcentrald/src/serial_mining.rs",
        ],
    ),
    phase(
        "xil-stock-first-install-plan",
        "XIL stock-to-DCENT_OS first-install bench card",
        "desk",
        "DCENT_DevOps",
        ["unlock-surface-closure"],
        "Produce the sole-executable XIL stock-to-DCENT_OS first-install operator bench card (Wave 3 am2_first_install ladder), modeled on the S19k OPERATOR_BENCH_CARD pattern; the card is the pinned deliverable.",
        owns=[
            ""
        ],
    ),
    phase(
        "xil-stock-unlock-live",
        "Live stock-XIL unlock cascade proof",
        "operator",
        "DCENT_Security",
        ["xil-stock-first-install-plan"],
        "Under fresh operator authorization, run the stock unlock cascade (signature-bypass web package / SSH enabler) on a locked stock XIL unit and capture proof; this controller grants no authority.",
    ),
    phase(
        "xil-no-work-safeoff",
        "XIL no-work/SafeOff physical gate",
        "operator",
        "DCENT_EE",
        ["xil-stock-unlock-live"],
        "Under fresh operator authorization, collect the XIL no-work/SafeOff gate evidence (rail/GPIO/reset/cooling) with the unit producing no hash work.",
    ),
    phase(
        "xil-bounded-work",
        "XIL bounded staged mining with accepted shares",
        "operator",
        "DCENT_Protocol",
        ["xil-no-work-safeoff"],
        "Under fresh operator authorization, run the bounded staged-mining trial from the running firmware and capture the accepted-share transcript.",
    ),
    phase(
        "xil-endurance",
        "XIL quiet-home endurance soak",
        "operator",
        "DCENT_Thermal",
        ["xil-bounded-work"],
        "Under fresh operator authorization, run the quiet-home-profile endurance soak with wall-power evidence and thermal custody.",
    ),
    phase(
        "xil-persistent-install",
        "XIL witnessed A/B NAND install",
        "operator",
        "DCENT_CE",
        ["xil-endurance", "xil-full-chain-init"],
        "Under fresh, separate, explicit authorization, perform the witnessed A/B NAND sysupgrade install on the XIL target and seal the installed artifact under artifacts/s19jpro-enablement/.",
    ),
    phase(
        "xil-acceptance",
        "XIL persistent acceptance",
        "operator",
        "DCENT_QA",
        ["xil-persistent-install"],
        "Under fresh operator authorization, verify cold boot, manageability (SSH/MCP/dashboard), rollback drill, and accepted shares on the persistently installed XIL unit.",
    ),
    phase(
        "bb-sd-coldboot-diagnosis",
        "BB SD boot-loop root cause via UART capture",
        "operator",
        "DCENT_CE",
        ["offline-repo-contract"],
        "Under fresh operator authorization, capture UART serial-console evidence of the BB SD boot loop (per the .79 deferral rule: a different physical SD card OR serial capture) and identify the root cause.",
    ),
    phase(
        "bb-sd-first-boot",
        "BB SD-first cold boot proof",
        "operator",
        "DCENT_DevOps",
        ["bb-sd-coldboot-diagnosis"],
        "Under fresh operator authorization, boot DCENT_OS from SD on the BB unit cold and seal the exact SD image artifact.",
    ),
    phase(
        "bb-safety-bench",
        "BB PSU65/watchdog safety bench",
        "operator",
        "DCENT_EE",
        ["offline-repo-contract"],
        "Under fresh operator authorization, run the BP-AM3-BB-PSU65-WATCHDOG safety bench (runtime-bound checked-LOW GPIO65 owner, complete EEPROM identity, watchdog teardown) on the BB unit.",
    ),
    phase(
        "bb-stock-ssh-unlock-live",
        "Live stock-BB SSH unlock proof",
        "operator",
        "DCENT_Security",
        ["unlock-surface-closure"],
        "Under fresh operator authorization, run the stock BB SSH-enable unlock (bitmain_bb_access) on a stock BB unit and capture proof.",
    ),
    phase(
        "bb-bounded-work",
        "BB bounded staged mining with accepted shares",
        "operator",
        "DCENT_Protocol",
        ["bb-safety-bench"],
        "Under fresh operator authorization, run the bounded staged-mining trial on the BB unit and capture the accepted-share transcript.",
    ),
    phase(
        "bb-endurance",
        "BB endurance soak",
        "operator",
        "DCENT_Thermal",
        ["bb-bounded-work"],
        "Under fresh operator authorization, run the BB endurance soak with wall-power and thermal evidence.",
    ),
    phase(
        "bb-nand-first-install",
        "BB NAND first-install capstone",
        "operator",
        "DCENT_CE",
        ["bb-sd-first-boot", "bb-endurance", "bb-stock-ssh-unlock-live"],
        "Under fresh, separate, explicit authorization, complete the BB NAND first-install ladder (backup round-trip, dry-run, witnessed capstone) and seal the artifact.",
    ),
    phase(
        "bb-acceptance",
        "BB persistent acceptance",
        "operator",
        "DCENT_QA",
        ["bb-nand-first-install"],
        "Under fresh operator authorization, verify cold boot, manageability, rollback, and accepted shares on the persistently installed BB unit.",
    ),
    phase(
        "aml-unit-custody",
        "Amlogic S19j Pro unit custody",
        "operator",
        "DCENT_EE",
        ["variant-matrix-closure"],
        "Take custody of an Amlogic S19j Pro unit (.133 replacement or equivalent), record its read-only board fingerprint, and hold it for the AML gauntlet; no VNish-unit contact without fresh authorization.",
    ),
    phase(
        "aml-otg-unlock-live",
        "Amlogic USB-OTG downgrade-unlock live proof",
        "operator",
        "DCENT_Security",
        ["aml-unit-custody", "unlock-surface-closure"],
        "Under fresh operator authorization, run the USB-OTG downgrade-unlock (amlogic_unlock / aml_burn_tool pre-lock eMMC image) on the AML S19j Pro unit.",
    ),
    phase(
        "aml-rootfs-window-bounded",
        "AML rootfs-window bounded mining",
        "operator",
        "DCENT_Protocol",
        ["aml-otg-unlock-live"],
        "Under fresh operator authorization, run the bounded rootfs-window staged-mining trial within the AMLCTRL boundary rules and capture accepted shares.",
    ),
    phase(
        "aml-endurance",
        "AML endurance soak",
        "operator",
        "DCENT_Thermal",
        ["aml-rootfs-window-bounded"],
        "Under fresh operator authorization, run the AML endurance soak with wall-power and thermal evidence.",
    ),
    phase(
        "aml-persistent-install",
        "AML guarded rootfs-window persistent install",
        "operator",
        "DCENT_CE",
        ["aml-endurance"],
        "Under fresh, separate, explicit authorization, perform the guarded rootfs-window persistent install (restore-verified backup, package-family match, physical recovery plan) and seal the artifact.",
    ),
    phase(
        "aml-acceptance",
        "AML persistent acceptance",
        "operator",
        "DCENT_QA",
        ["aml-persistent-install"],
        "Under fresh operator authorization, verify cold boot, manageability, restore path, and accepted shares on the persistent AML unit.",
    ),
    phase(
        "s19jproplus-td003-promotion",
        "S19j Pro+ TD-003 promotion gates",
        "desk",
        "DCENT_CE",
        ["offline-repo-contract", "variant-matrix-closure"],
        "Complete the TD-003 promotion gates for S19j Pro+ (exact BHB42612 identity, BM1362 protocol admission, safety lifecycle) and lift the management-only intercept in model.rs with ADR-backed evidence.",
        owns=[
            "DCENT_OS_Antminer/dcentrald/dcentrald/src/model.rs",
            "DCENT_OS_Antminer/docs/ARCHITECTURE_DECISION_LOG.md",
            "",
        ],
    ),
    phase(
        "s19jproplus-unit-custody",
        "S19j Pro+ unit custody",
        "operator",
        "DCENT_EE",
        ["variant-matrix-closure"],
        "Take custody of an S19j Pro+ (BHB42612, 3x120) unit and record its read-only fingerprint.",
    ),
    phase(
        "s19jproplus-no-work-safeoff",
        "S19j Pro+ no-work/SafeOff physical gate",
        "operator",
        "DCENT_EE",
        ["s19jproplus-td003-promotion", "s19jproplus-unit-custody"],
        "Under fresh operator authorization, collect the S19j Pro+ no-work/SafeOff gate evidence before any hash work.",
    ),
    phase(
        "s19jproplus-bounded-work",
        "S19j Pro+ bounded staged mining",
        "operator",
        "DCENT_Protocol",
        ["s19jproplus-no-work-safeoff"],
        "Under fresh operator authorization, run the bounded staged-mining trial with accepted-share transcript on S19j Pro+.",
    ),
    phase(
        "s19jproplus-endurance",
        "S19j Pro+ endurance soak",
        "operator",
        "DCENT_Thermal",
        ["s19jproplus-bounded-work"],
        "Under fresh operator authorization, run the S19j Pro+ endurance soak with wall-power and thermal evidence.",
    ),
    phase(
        "s19jproplus-persistent-install",
        "S19j Pro+ persistent install",
        "operator",
        "DCENT_CE",
        ["s19jproplus-endurance"],
        "Under fresh, separate, explicit authorization, perform the persistent install on S19j Pro+ and seal the artifact.",
    ),
    phase(
        "s19jproplus-acceptance",
        "S19j Pro+ persistent acceptance",
        "operator",
        "DCENT_QA",
        ["s19jproplus-persistent-install"],
        "Under fresh operator authorization, verify cold boot, manageability, rollback, and accepted shares on S19j Pro+.",
    ),
    phase(
        "cv-unit-acquisition",
        "CV1835 S19j Pro bench unit acquisition",
        "operator",
        "DCENT_EE",
        ["variant-matrix-closure"],
        "Acquire a CV1835 S19j Pro bench unit and record custody plus read-only fingerprint; the CV lane is acquisition-gated by design.",
    ),
    phase(
        "cv-emmc-recovery-plan",
        "CV1835 eMMC recovery plan",
        "desk",
        "DCENT_CE",
        ["cv-unit-acquisition"],
        "Write the CV1835 eMMC recovery plan backed by the acquired unit's captured eMMC map; the plan document is the pinned deliverable.",
        owns=[
            ""
        ],
    ),
    phase(
        "support-tier-promotion",
        "Evidence-backed support-tier promotion for all five lanes",
        "desk",
        "DCENT_QA",
        [
            "hashboard-revision-atlas",
            "xil-acceptance",
            "bb-acceptance",
            "aml-acceptance",
            "s19jproplus-acceptance",
        ],
        "Promote all five S19j Pro family rows in SUPPORT_MATRIX.md and skus.conf to their evidence-backed tiers, each with a named artifact path per the support-matrix guardrails.",
        owns=["SUPPORT_MATRIX.md", "DCENT_OS_Antminer/scripts/hw-acceptance/skus.conf"],
    ),
    phase(
        "complete-s19jpro-enablement",
        "Terminal claim: complete S19j Pro enablement",
        "terminal",
        "DCENT_QA",
        ["support-tier-promotion", "cv-emmc-recovery-plan"],
        "Terminal claim issues only when every dependency is independently verified.",
        verifier={"kind": "terminal"},
    ),
]


def main() -> None:
    manifest = {
        "schema": "dcentos.s19jpro-enablement-campaign/v1",
        "campaign_id": "s19j-pro-complete-enablement-20260826",
        "target": (
            "Antminer S19j Pro family - XIL (am2-s19jpro-zynq), BB "
            "(am3-bb-s19jpro), Amlogic (am3-s19jpro-aml), S19j Pro+ "
            "(am3-s19jproplus), CV1835 (cv1835-s19jpro) - BM1362"
        ),
        "terminal_claim": (
            "Every S19j Pro control-board family (XIL, BB, Amlogic, S19j Pro+, "
            "CV1835) has an independently verified unlock-to-persistent-DCENT_OS "
            "path with fresh operator-authorized evidence receipts"
        ),
        "contact_policy": {
            "controller_is_offline_only": True,
            "live_contact_requires_fresh_operator_authorization": True,
            "nand_or_emmc_write_requires_separate_explicit_authorization": True,
            "controller_may_grant_authority": False,
        },
        "artifacts": [],
        "phases": PHASES,
    }
    OUT.write_text(
        json.dumps(manifest, indent=1, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    canonical = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    print("wrote", OUT)
    print("phases:", len(PHASES))
    print("manifest canonical sha256:", hashlib.sha256(canonical).hexdigest())


if __name__ == "__main__":
    main()
