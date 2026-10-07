#!/usr/bin/env python3
"""Offline regression tests for the bounded S19k Amlogic install-safety wave."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AML_INIT = ROOT / "br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d"
INSTALL = ROOT / "scripts/install_amlogic_persistent.sh"
RESTORE = ROOT / "scripts/restore_amlogic_mtd5_from_backup.sh"
RECOVER = ROOT / "scripts/recover_amlogic_to_stock.sh"
IDENTITY_GUARD = ROOT / "scripts/lib/amlogic_identity_guard.sh"
AM3_GEOMETRY = ROOT / "scripts/lib/am3_geometry.sh"
FLAG_HELPER = ROOT / "scripts/s19k_write_recovery_flag.sh"
LEGACY_REVERT = ROOT / "scripts/revert_to_stock_am3_aml_s19k.sh"
S99 = AML_INIT / "S99upgrade"
S37 = AML_INIT / "S37board_setup"
POLICY_HELPER = AML_INIT.parents[1] / "usr/libexec/dcentos/mutation-policy.sh"
S19K_POLICY = (
    ROOT
    / "br2_external_dcentos/board/amlogic/am3-s19kpro/rootfs-overlay/etc/dcentos/mutation_policy"
)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="strict")


def function_body(source: str, name: str) -> str:
    marker = f"{name}() {{"
    start = source.index(marker)
    end = source.index("\n}", start)
    return source[start:end]


def shell_path(path: Path) -> str:
    if os.name != "nt":
        return str(path)
    resolved = path.resolve()
    drive = resolved.drive.rstrip(":").lower()
    relative = resolved.relative_to(resolved.anchor).as_posix()
    return f"/mnt/{drive}/{relative}"


class S19kAmlInstallSafetyTests(unittest.TestCase):
    def make_recover_fixture(self, artifact: Path, *, duplicate_flag: bool = False) -> None:
        artifact.mkdir()
        body = b"recover=1\0\0" + b"\0" * (65536 - 4 - len(b"recover=1\0\0"))
        env = zlib.crc32(body).to_bytes(4, "little") + body
        (artifact / "nandrecovery_env.bin").write_bytes(env)
        env_sha = hashlib.sha256(env).hexdigest()
        identity = (
            "BOARD_TARGET=\n"
            "MODEL=Antminer S19k Pro\n"
            "HWID=S19k Pro C81\n"
            "PCB=C81\n"
            'BOS_MODEL=model = "Antminer S19K Pro NoPic"\n'
            "DT_MODEL=Bitmain A113D C81\n"
            "DT_COMPATIBLE=amlogic,meson-axg\n"
            "CPU_SYSTEM=AArch64 Processor rev 4\n"
        )
        identity_bytes = identity.encode("ascii")
        (artifact / "identity_tuple_pre.txt").write_bytes(identity_bytes)
        identity_sha = hashlib.sha256(identity_bytes).hexdigest()
        identity_receipt = (
            "model/SoC/PCB tuple admitted: variant=s19kpro pcb=c81 soc=A113D/AXG"
        )
        flag_lines = "flag_local=0x04D00000\n"
        if duplicate_flag:
            flag_lines += "flag_local=0x04D00000\n"
        (artifact / "RECOVER_TO_STOCK_PLAN.txt").write_text(
            "schema=dcentos.amlogic-recover-to-stock/v1\n"
            "intent=UbootStockRevert\n"
            "flag_value=0x02\n"
            + flag_lines
            + "nandrecovery_env_local=0x04900000\n"
            "recover_env_source=nandrecovery_env.bin\n"
            "step0=ImportNandrecoveryEnv\n"
            "step1=EraseNvdata\n"
            "step2=Reset\n"
            "nand_erase_part=nvdata\n"
            "bootm_mtd2=false\n"
            "clear_for_flash=false\n",
            encoding="ascii",
        )
        (artifact / "BACKUP_LEDGER.txt").write_text(
            "schema=dcentos.amlogic-backup/v1\n"
            "clear_for_flash=false\n"
            "nandrecovery_env_local=0x04900000\n"
            f"nandrecovery_env_sha256={env_sha}\n"
            "board_target=\n"
            "board_target_source=package\n"
            "board_target_package=am3-s19k\n"
            "identity_proof_schema=dcentos.amlogic-identity-tuple/v1\n"
            "identity_proof_variant=s19kpro\n"
            "identity_proof_file=identity_tuple_pre.txt\n"
            f"identity_proof_sha256={identity_sha}\n"
            f"identity_proof_receipt={identity_receipt}\n",
            encoding="ascii",
        )

    def test_recovery_identity_gate_refuses_every_mixed_pair_before_gpio(self) -> None:
        exact_pairs = (
            ("am3-aml-s19k", "am3-s19k"),
            ("am3-aml-s21", "am3-s21"),
            ("am3-aml-s21pro", "am3-s21pro"),
        )
        refused_pairs = [
            (platform, target)
            for platform, _ in exact_pairs
            for _, target in exact_pairs
            if (platform, target) != ("am3-aml-s19k", "am3-s19k")
        ]
        refused_pairs.extend(
            (
                ("am3-aml-s19k", "am3-s19kpro"),
                ("am3-aml-s19kpro", "am3-s19k"),
                ("unknown-platform", "am3-s19k"),
                ("am3-aml-s19k", "unknown-target"),
            )
        )

        with tempfile.TemporaryDirectory() as raw_temp:
            root = Path(raw_temp)
            identity_root = root / "identity"
            identity_root.mkdir()
            sentinels = {
                root / "gpio_export": b"NO_EXPORT\n",
                root / "gpio_active_low": b"NO_ACTIVE_LOW\n",
                root / "gpio_direction": b"NO_DIRECTION\n",
                root / "gpio_value": b"NO_VALUE\n",
            }
            for path, value in sentinels.items():
                path.write_bytes(value)

            for production in (RESTORE, RECOVER):
                source = read(production)
                gate = function_body(source, "require_exact_live_s19k_identity")
                harness = root / f"{production.stem}-identity-gate.sh"
                harness.write_bytes(
                    (
                        "#!/bin/sh\nset -eu\n"
                        + gate
                        + '\n}\nrequire_exact_live_s19k_identity "$1"\n'
                    ).encode("utf-8")
                )
                call = source.index("require_exact_live_s19k_identity /etc/dcentos")
                first_gpio = source.index('echo "$PWR_GPIO" > "$SYS/export"')
                self.assertLess(call, first_gpio)

                for platform, target in refused_pairs:
                    with self.subTest(script=production.name, platform=platform, target=target):
                        (identity_root / "platform").write_text(platform + "\n", encoding="ascii")
                        (identity_root / "board_target").write_text(target + "\n", encoding="ascii")
                        before = {path: path.read_bytes() for path in sentinels}
                        command = (
                            ["wsl.exe", "sh", shell_path(harness), shell_path(identity_root)]
                            if os.name == "nt"
                            else ["sh", str(harness), str(identity_root)]
                        )
                        result = subprocess.run(command, text=True, capture_output=True, check=False)
                        self.assertNotEqual(0, result.returncode)
                        self.assertIn("exact am3-aml-s19k:am3-s19k", result.stderr)
                        self.assertEqual(before, {path: path.read_bytes() for path in sentinels})

                (identity_root / "platform").write_text("am3-aml-s19k\n", encoding="ascii")
                (identity_root / "board_target").write_text("am3-s19k\n", encoding="ascii")
                result = subprocess.run(command, text=True, capture_output=True, check=False)
                self.assertEqual(0, result.returncode, result.stderr)

    def test_s19k_capabilities_are_split_and_fail_closed(self) -> None:
        cases = {
            "S37board_setup": (
                "require_mutation_authority",
                "boot-safeoff",
                "boot-safeoff capability is missing or insecure",
            ),
            "S82dcentrald": (
                "require_runtime_authority",
                "daemon-hardware",
                "daemon-hardware capability is missing or insecure",
            ),
            "S99upgrade": (
                "require_ota_mutation_policy",
                "ota-storage",
                "ota-storage capability is missing or insecure",
            ),
        }
        for filename, (function, capability, refusal) in cases.items():
            with self.subTest(filename=filename):
                body = function_body(read(AML_INIT / filename), function)
                self.assertIn("dcent_mutation_policy_has", body)
                self.assertIn(capability, body)
                self.assertIn(refusal, body)

    def test_backup_only_never_writes_a_fixed_remote_nand_env_temp(self) -> None:
        install = read(INSTALL)
        self.assertNotIn("/tmp/nand_env_pre.bin", install)
        self.assertNotIn("dd if=/dev/nand_env of=", install)
        self.assertNotIn("scp_get()", install)
        self.assertNotIn("/tmp/dcentos_root_readback.uimage", install)
        self.assertIn(
            'ssh_stream_get "dd if=/dev/nand_env bs=64K count=1 2>/dev/null"',
            install,
        )
        self.assertEqual(
            2,
            install.count(
                'ssh_stream_get "dd if=/dev/nand_env bs=64K count=1 2>/dev/null"'
            ),
        )
        self.assertIn("duplicate host-streamed nand_env backup SHA mismatch", install)
        self.assertIn('rm -f "$NAND_ENV_RECHECK"', install)
        self.assertIn("host-streamed rootfs readback failed", install)

    def test_installer_board_target_normalization_is_busybox_safe(self) -> None:
        install = read(INSTALL)
        self.assertIn('head -1 | tr -d " \\\\t\\\\r\\\\n"', install)

        if os.name == "nt":
            command = [
                "wsl.exe",
                "/usr/bin/busybox",
                "tr",
                "-d",
                r" \t\r\n",
            ]
        else:
            busybox = shutil.which("busybox")
            if busybox is None:
                self.skipTest("busybox is required for the target tr regression")
            command = [busybox, "tr", "-d", r" \t\r\n"]
        result = subprocess.run(
            command,
            input=" am3-s19k \r\n",
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("am3-s19k", result.stdout)

    def test_evidence_only_staging_is_content_bound_and_no_clobber(self) -> None:
        install = read(INSTALL)
        for stale_path in (
            "/data/dcentos-sysupgrade.tar",
            "/data/sysupgrade",
            "/data/.dcent_stage_check",
        ):
            self.assertNotIn(stale_path, install)
        self.assertIn(
            'REMOTE_STAGE_DIR="/data/.dcentos-sysupgrade-$LOCAL_SHA"', install
        )
        self.assertIn('[ ! -e \'$REMOTE_STAGE_DIR\' ]', install)
        self.assertIn('[ ! -L \'$REMOTE_STAGE_DIR\' ]', install)
        self.assertIn("mkdir '$REMOTE_STAGE_DIR'", install)
        self.assertIn('REMOTE_BUNDLE="$REMOTE_STAGE_DIR/bundle.tar"', install)
        self.assertIn('REMOTE_EXTRACT="$REMOTE_STAGE_DIR/extracted"', install)
        self.assertIn("[ ! -e '$REMOTE_EXTRACT' ]", install)
        self.assertIn("tar xf '$REMOTE_BUNDLE' -C '$REMOTE_EXTRACT'", install)

    def test_exact_s19k_tuple_rejects_held_s19k_pro_plus_miner_type(self) -> None:
        guard = read(IDENTITY_GUARD)
        self.assertIn("*s19kproplus*", guard)
        self.assertIn("*s19k\\ pro+*", guard)
        evidence = read(
            ROOT
            / ""
        )
        self.assertIn('"Antminer S19k Pro+"', evidence)
        self.assertIn("bmminer_1e47f3a45f6ff37c.dec/sub_42B0C@42B0C.c", evidence)

        with tempfile.TemporaryDirectory() as raw_temp:
            harness = Path(raw_temp) / "identity-guard.sh"
            harness.write_bytes(
                (
                    "#!/bin/sh\nset -eu\n"
                    f". '{shell_path(IDENTITY_GUARD)}'\n"
                    'dcent_amlogic_exact_tuple_admit s19kpro "" "$1" a113d c81 "$2"\n'
                ).encode("utf-8")
            )

            cases = (
                ("antminers19kproplus", "model=antminer s19k pro+"),
                ("antminers19kpro", "model=antminer s19k pro+"),
                ("antminers19kpro", "model=antminer s19kpro+"),
                ("antminers19kpro", "model=antminer s19k pro plus"),
            )
            for normalized, raw in cases:
                with self.subTest(normalized=normalized, raw=raw):
                    command = (
                        ["wsl.exe", "sh", shell_path(harness), normalized, raw]
                        if os.name == "nt"
                        else ["sh", str(harness), normalized, raw]
                    )
                    result = subprocess.run(command, text=True, capture_output=True, check=False)
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn("S19k", result.stdout)

            command = (
                [
                    "wsl.exe",
                    "sh",
                    shell_path(harness),
                    "antminers19kpro",
                    "model=antminer s19k pro",
                ]
                if os.name == "nt"
                else [
                    "sh",
                    str(harness),
                    "antminers19kpro",
                    "model=antminer s19k pro",
                ]
            )
            result = subprocess.run(command, text=True, capture_output=True, check=False)
            self.assertEqual(0, result.returncode, result.stderr)

    # --- Braiins model+SoC identity dialect (2026-08-30) --------------------

    LIVE_88_BRAIINS_RECORD = (
        "BOARD_TARGET=\n"
        "MODEL=\n"
        "HWID=\n"
        "PCB=\n"
        'BOS_MODEL=model = "Antminer S19K Pro NoPic"\n'
        "DT_MODEL=Amlogic\n"
        "DT_COMPATIBLE=amlogic, axg\n"
        "CPU_SYSTEM=Amlogic\n"
        "PCB_OBSERVATION=unavailable-braiins\n"
        "HASHBOARD_EEPROM=0x50=absent,0x51=05:11,0x52=05:11\n"
    )
    STOCK_DIRECT_RECORD = (
        "BOARD_TARGET=\n"
        "MODEL=Antminer S19k Pro\n"
        "HWID=S19k Pro C81\n"
        "PCB=C81\n"
        'BOS_MODEL=model = "Antminer S19K Pro NoPic"\n'
        "DT_MODEL=Bitmain A113D C81\n"
        "DT_COMPATIBLE=amlogic,meson-axg\n"
        "CPU_SYSTEM=AArch64 Processor rev 4\n"
        "PCB_OBSERVATION=direct\n"
        "HASHBOARD_EEPROM=reader-unavailable\n"
    )
    STOCK_RECEIPT = "model/SoC/PCB tuple admitted: variant=s19kpro pcb=c81 soc=A113D/AXG"
    BRAIINS_RECEIPT = (
        "model/SoC tuple admitted (braiins dialect, operator override): "
        "variant=s19kpro pcb_observation=unavailable-braiins soc=A113D/AXG"
    )

    def _run_record_admit(self, record: str, variant: str = "s19kpro"):
        raw_dir = tempfile.TemporaryDirectory()
        self.addCleanup(raw_dir.cleanup)
        base = Path(raw_dir.name)
        harness = base / "record-guard.sh"
        harness.write_bytes(
            (
                "#!/bin/sh\nset -eu\n"
                f". '{shell_path(IDENTITY_GUARD)}'\n"
                'dcent_amlogic_identity_record_admit "$1" "$(cat "$2")"\n'
            ).encode("utf-8")
        )
        record_file = base / "record.txt"
        record_file.write_text(record, encoding="ascii", newline="\n")
        command = (
            ["wsl.exe", "sh", shell_path(harness), variant, shell_path(record_file)]
            if os.name == "nt"
            else ["sh", str(harness), variant, str(record_file)]
        )
        return subprocess.run(command, text=True, capture_output=True, check=False)

    def test_braiins_dialect_admission_requires_explicit_operator_marker(self) -> None:
        # Exact live .88 refusal shape + operator marker + held 05:11 hashboard
        # evidence admits with an honest pcb_observation=unavailable-braiins
        # receipt.
        result = self._run_record_admit(self.LIVE_88_BRAIINS_RECORD)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(self.BRAIINS_RECEIPT, result.stdout.strip())

        # Same physical unit WITHOUT the dialect marker keeps the historical
        # fail-closed refusal (the stock gate is not weakened).
        unmarked = self.LIVE_88_BRAIINS_RECORD.replace(
            "PCB_OBSERVATION=unavailable-braiins", "PCB_OBSERVATION=direct"
        )
        result = self._run_record_admit(unmarked)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("exact compatible PCB observation is missing", result.stdout)

        # The dialect is held S19k Pro evidence only.
        result = self._run_record_admit(self.LIVE_88_BRAIINS_RECORD, variant="s21")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("not held evidence for variant s21", result.stdout)

        # A reader-unavailable Braiins unit still admits honestly (model+SoC+
        # override), and the missing reader is recorded, never invented.
        readerless = self.LIVE_88_BRAIINS_RECORD.replace(
            "HASHBOARD_EEPROM=0x50=absent,0x51=05:11,0x52=05:11",
            "HASHBOARD_EEPROM=reader-unavailable",
        )
        result = self._run_record_admit(readerless)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_braiins_dialect_neverweakens_stock_or_legacy_transcripts(self) -> None:
        # The stock-source branch is byte-identical: a direct C81 observation
        # admits with the historical receipt.
        result = self._run_record_admit(self.STOCK_DIRECT_RECORD)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(self.STOCK_RECEIPT, result.stdout.strip())

        # Historical eight-field transcripts (retained artifact dirs) still
        # re-admit so recover_amlogic_to_stock.sh keeps working on them.
        legacy = "\n".join(
            line
            for line in self.STOCK_DIRECT_RECORD.splitlines()
            if not line.startswith(("PCB_OBSERVATION=", "HASHBOARD_EEPROM="))
        ) + "\n"
        result = self._run_record_admit(legacy)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(self.STOCK_RECEIPT, result.stdout.strip())

        # A legacy-shape Braiins record (no marker) cannot ride the dialect.
        legacy_braiins = "\n".join(
            line
            for line in self.LIVE_88_BRAIINS_RECORD.splitlines()
            if not line.startswith(("PCB_OBSERVATION=", "HASHBOARD_EEPROM="))
        ) + "\n"
        result = self._run_record_admit(legacy_braiins)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("exact compatible PCB observation is missing", result.stdout)

        # Mixed/partial schema extensions are refused.
        nine_field = "\n".join(
            line
            for line in self.LIVE_88_BRAIINS_RECORD.splitlines()
            if not line.startswith("HASHBOARD_EEPROM=")
        ) + "\n"
        result = self._run_record_admit(nine_field)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("ten-field schema", result.stdout)

    def test_braiins_dialect_refuses_ambiguous_sibling_and_foreign_evidence(self) -> None:
        cases = (
            # Sibling S19k Pro+ model signal anywhere in the record.
            (
                self.LIVE_88_BRAIINS_RECORD.replace(
                    'BOS_MODEL=model = "Antminer S19K Pro NoPic"',
                    'BOS_MODEL=model = "Antminer S19k Pro+"',
                ),
                "S19k Pro+ is a distinct miner type",
            ),
            # Ambiguous/conflicting model observations.
            (
                self.LIVE_88_BRAIINS_RECORD.replace("MODEL=\n", "MODEL=Antminer S19j Pro\n"),
                "unknown or conflicting model observation",
            ),
            # Foreign hashboard family preamble (S19j/BHB42-class 04:11).
            (
                self.LIVE_88_BRAIINS_RECORD.replace(
                    "0x51=05:11", "0x51=foreign:0x04:0x11"
                ),
                "refuses a foreign or partial hashboard EEPROM preamble",
            ),
            # Partial/unreliable populated-slot read.
            (
                self.LIVE_88_BRAIINS_RECORD.replace("0x52=05:11", "0x52=partial:0x05"),
                "refuses a foreign or partial hashboard EEPROM preamble",
            ),
            # A present-but-conflicting carrier PCB token can never be
            # relabelled by the operator override.
            (
                self.LIVE_88_BRAIINS_RECORD.replace(
                    "DT_MODEL=Amlogic", "DT_MODEL=Bitmain A113D C76"
                ),
                "conflicts with s19kpro",
            ),
            # The model proof must come from the Braiins BOS_MODEL source.
            (
                self.LIVE_88_BRAIINS_RECORD.replace(
                    'BOS_MODEL=model = "Antminer S19K Pro NoPic"', "BOS_MODEL="
                ),
                "requires an exact BOS_MODEL",
            ),
            # The dialect marker can never coexist with the evidence it says
            # is missing.
            (
                self.LIVE_88_BRAIINS_RECORD.replace("PCB=\n", "PCB=C81\n"),
                "contradicts an observed compatible PCB token",
            ),
        )
        for record, expected in cases:
            with self.subTest(expected=expected):
                result = self._run_record_admit(record)
                self.assertNotEqual(0, result.returncode, result.stdout)
                self.assertIn(expected, result.stdout)

    def test_braiins_override_is_operator_scoped_and_recorded_honestly(self) -> None:
        install = read(INSTALL)
        guard = read(IDENTITY_GUARD)
        recover = read(RECOVER)
        restore = read(RESTORE)

        # Explicit CLI flag, S19k-scoped, default off.
        self.assertIn("--accept-braiins-model-soc-identity", install)
        self.assertIn("BRAIINS_MODEL_SOC_IDENTITY=false", install)
        self.assertIn(
            "--accept-braiins-model-soc-identity is held S19k Pro evidence only",
            install,
        )

        # The observation block records the dialect placeholder plus the
        # Track-1-proven chain-bus hashboard EEPROM probe.
        self.assertIn('printf "PCB_OBSERVATION=%s\\n" "pending"', install)
        self.assertIn('printf "HASHBOARD_EEPROM=%s\\n"', install)
        self.assertIn("/usr/sbin/i2cget", install)
        self.assertIn('"$hb_reader" -y 1 0x$hb_addr 0 b', install)
        self.assertIn('"$hb_b0:$hb_b1" = "0x05:0x11"', install)

        # The dialect marker is only minted when every stock PCB channel is
        # empty AND the operator flag is present.
        self.assertIn("pcb_observation=direct", install)
        self.assertIn("pcb_observation=unavailable-braiins", install)
        self.assertIn("EXACT_AMLOGIC_IDENTITY_DIALECT=$pcb_observation", install)

        # The full-rescue ledger records the dialect disposition honestly.
        self.assertIn(
            "identity_disposition=tuple-proven-$EXACT_AMLOGIC_IDENTITY_VARIANT-braiins-model-soc",
            install,
        )

        # The guard carries the ten-field schema and both new keys.
        self.assertIn("PCB_OBSERVATION HASHBOARD_EEPROM", guard)
        self.assertIn("pcb_observation=unavailable-braiins", guard)
        self.assertIn("braiins dialect requires an exact BOS_MODEL", guard)

        # Recovery/restore accept the new observation fields (absent or once).
        for script in (recover, restore):
            self.assertIn("PCB_OBSERVATION HASHBOARD_EEPROM", script)
            self.assertIn("|PCB_OBSERVATION|HASHBOARD_EEPROM)=", script)

    def test_s37_refuses_every_mixed_identity_before_any_gpio_write(self) -> None:
        source = read(S37)
        authority = function_body(source, "require_mutation_authority")
        self.assertLess(
            authority.index("read_identity ||"),
            authority.index("dcent_mutation_policy_has"),
        )
        identity = function_body(source, "read_identity")
        self.assertIn("am3-aml-s19k:am3-s19k|", identity)
        self.assertIn("am3-aml-s19kpro:am3-s19kpro|", identity)
        for broad in ("am3-aml-s19k:*", "*:am3-s19k", "*:am3-s19kpro"):
            self.assertNotIn(broad, authority)

        exact_pairs = (
            ("am3-aml-s19jpro", "am3-s19jpro-aml"),
            ("am3-aml-s19k", "am3-s19k"),
            ("am3-aml-s19kpro", "am3-s19kpro"),
            ("am3-aml-s21", "am3-s21"),
            ("am3-aml-s21pro", "am3-s21pro"),
            ("am3-aml-s21xp", "am3-s21xp"),
        )
        refused_pairs = [
            (platform, target)
            for platform, _ in exact_pairs
            for _, target in exact_pairs
            if (platform, target) not in exact_pairs
        ]
        refused_pairs.extend(
            (
                ("am3-aml-s19k", "am3-s19kpro"),
                ("am3-aml-s19k", "am3-aml-s19kpro"),
                ("am3-aml-s19kpro", "am3-s19k"),
                ("unknown-platform", "am3-s19k"),
                ("am3-aml-s19k", "unknown-target"),
            )
        )

        with tempfile.TemporaryDirectory() as raw_temp:
            root = Path(raw_temp)
            gpio = root / "gpio"
            pwm = root / "pwm"
            identity = root / "identity"
            receipt = root / "run"
            gpio437 = gpio / "gpio437"
            gpio437.mkdir(parents=True)
            pwm.mkdir()
            identity.mkdir()
            receipt.mkdir()
            instrumented = (
                source.replace("GPIO_ROOT=/sys/class/gpio", f"GPIO_ROOT={shell_path(gpio)}")
                .replace("PWM_ROOT=/sys/class/pwm/pwmchip0", f"PWM_ROOT={shell_path(pwm)}")
                .replace("IDENTITY_ROOT=/etc/dcentos", f"IDENTITY_ROOT={shell_path(identity)}")
                .replace("RECEIPT_DIR=/run/dcentos", f"RECEIPT_DIR={shell_path(receipt)}")
            )
            script = root / "S37board_setup"
            script.write_bytes(instrumented.encode("utf-8"))

            sentinels = {
                gpio / "export": b"NO_EXPORT\n",
                gpio437 / "active_low": b"NO_ACTIVE_LOW\n",
                gpio437 / "direction": b"NO_DIRECTION\n",
                gpio437 / "value": b"NO_VALUE\n",
                pwm / "export": b"NO_PWM_EXPORT\n",
            }
            for path, value in sentinels.items():
                path.write_bytes(value)

            command = (
                ["wsl.exe", "sh", shell_path(script), "start"]
                if os.name == "nt"
                else ["sh", str(script), "start"]
            )
            for platform, target in refused_pairs:
                with self.subTest(platform=platform, target=target):
                    (identity / "platform").write_text(platform + "\n", encoding="ascii")
                    (identity / "board_target").write_text(target + "\n", encoding="ascii")
                    (identity / "rail_gpio").write_text("437\n", encoding="ascii")
                    for path, value in sentinels.items():
                        path.write_bytes(value)
                    result = subprocess.run(command, text=True, capture_output=True, check=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("exact Amlogic platform:target:rail identity", result.stderr)
                    self.assertEqual(
                        {path: path.read_bytes() for path in sentinels},
                        sentinels,
                        "identity refusal must precede every GPIO/PWM write",
                    )

            (identity / "platform").write_text("am3-aml-s19k\n", encoding="ascii")
            (identity / "board_target").write_text("am3-s19k\n", encoding="ascii")
            (identity / "rail_gpio").write_text("438\n", encoding="ascii")
            result = subprocess.run(command, text=True, capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual({path: path.read_bytes() for path in sentinels}, sentinels)

    def test_s19k_image_grants_boot_safeoff_and_daemon_without_persistent_writes(self) -> None:
        self.assertEqual("boot-safeoff\ndaemon-hardware\n", read(S19K_POLICY))
        helper = read(POLICY_HELPER)
        self.assertIn('[ ! -L "$policy_file" ]', helper)
        self.assertIn("stat -c '%u'", helper)
        self.assertIn("400|440|444|600|640|644", helper)
        self.assertIn('grep -F -x "$capability"', helper)

    def test_s19k_unsigned_post_install_is_disabled_before_nand_access(self) -> None:
        source = read(AML_INIT / "S46post-install")
        body = function_body(source, "require_post_install_authority")
        refusal = "unsigned S19k NAND post-install payloads are disabled"
        self.assertIn("am3-aml-s19k", body)
        self.assertIn(refusal, body)
        self.assertIn("return 1", body[body.index(refusal) :])
        gate = source.index("require_post_install_authority || return 1")
        self.assertLess(gate, source.index(". /lib/functions/dcentos-defaults.sh"))
        self.assertLess(gate, source.index("nanddump -q", gate))
        self.assertLess(gate, source.index("flash_erase -q", gate))

    def test_backup_is_host_streamed_padbad_omitoob_and_double_read(self) -> None:
        source = read(INSTALL)
        command = "nanddump --bb=padbad --omitoob '$ROOTFS_MTD'"
        self.assertEqual(2, source.count(command))
        self.assertIn("ssh_stream_get()", source)
        self.assertNotIn("/tmp/mtd5_pre.bin", source)
        self.assertNotIn("nanddump --bb=skipbad -f /tmp/mtd5_pre.bin", source)
        self.assertIn('[ "$MTD5_BACKUP_SIZE" -eq "$MTD5_SIZE" ]', source)
        self.assertIn('[ "$MTD5_RECHECK_SIZE" -eq "$MTD5_SIZE" ]', source)
        self.assertIn('[ "$MTD5_LOCAL_SHA" = "$MTD5_RECHECK_SHA" ]', source)
        self.assertIn("mtd5_dump_bad_blocks=padbad", source)
        self.assertIn("mtd5_dump_oob=omitted", source)
        self.assertIn("mtd5_duplicate_read=true", source)
        self.assertIn(
            "mtd5_bad_block_count_before=$MTD5_BAD_BLOCKS_BEFORE", source
        )
        self.assertIn("mtd5_bad_block_count_after=$MTD5_BAD_BLOCKS_AFTER", source)
        self.assertIn(
            "mtd5_restore_bad_block_policy=$MTD5_RESTORE_BAD_BLOCK_POLICY",
            source,
        )
        self.assertIn("/sys/class/mtd/mtd5/bad_blocks", source)
        self.assertIn("identity_proof_schema=dcentos.amlogic-identity-tuple/v1", source)
        self.assertIn("identity_proof_file=$IDENTITY_PROOF_FILE", source)
        self.assertIn("identity_proof_sha256=$IDENTITY_PROOF_SHA", source)
        self.assertIn("EXACT_AMLOGIC_IDENTITY_RECORD=$identity", source)
        self.assertIn(
            'LIVE_BT=$(printf \'%s\' "${EXACT_AMLOGIC_OBSERVED_BOARD_TARGET:-}"',
            source,
        )

    def test_uboot_one_byte_flag_rewrite_requires_erased_tail(self) -> None:
        source = read(INSTALL)
        geometry = read(AM3_GEOMETRY)
        self.assertIn("dcent_am3_admit_recovery_flag_eraseblock_exclusive", geometry)
        self.assertRegex(
            source,
            r'dcent_am3_admit_recovery_flag_eraseblock_exclusive \\\n\s+"\$ARTIFACT_DIR/recovery_flag_eb\.bin"',
        )
        self.assertIn("recovery_flag_eraseblock_exclusive=$FLAG_EB_EXCLUSIVE", source)
        self.assertIn("complete_stock_byte_restore=false", source)
        self.assertIn("full_logical_six_mtd_capture=$FULL_RESCUE_CAPTURE", source)
        self.assertIn("factory_full_erase_capture_complete=false", source)
        self.assertIn("factory_full_erase_backup_ready=false", source)
        self.assertIn(
            "factory_full_erase_backup_ready_blockers="
            "logical-oob-omitted-capture-not-physical-replay+"
            "bad-block-positions-unproven+encrypted-offhost-copy+"
            "unit-state-restore-live-unproven",
            source,
        )
        self.assertNotIn("factory_full_erase_capture_complete=$FULL_RESCUE_CAPTURE", source)
        self.assertNotIn("factory_full_erase_backup_ready=$FULL_RESCUE_CAPTURE", source)

        with tempfile.TemporaryDirectory() as raw_temp:
            root = Path(raw_temp)
            good = root / "good.bin"
            sentinel = root / "sentinel.bin"
            good_bytes = b"\x02" + b"\xff" * 131071
            bad_bytes = bytearray(good_bytes)
            bad_bytes[4096] = 0x5A
            good.write_bytes(good_bytes)
            sentinel.write_bytes(bad_bytes)
            harness = root / "flag-exclusive.sh"
            harness.write_bytes(
                (
                    "#!/bin/sh\nset -eu\n"
                    f". '{shell_path(AM3_GEOMETRY)}'\n"
                    'dcent_am3_admit_recovery_flag_eraseblock_exclusive "$1"\n'
                ).encode("ascii")
            )

            def admit(path: Path) -> subprocess.CompletedProcess[str]:
                command = (
                    ["wsl.exe", "sh", shell_path(harness), shell_path(path)]
                    if os.name == "nt"
                    else ["sh", str(harness), str(path)]
                )
                return subprocess.run(command, text=True, capture_output=True, check=False)

            accepted = admit(good)
            self.assertEqual(0, accepted.returncode, accepted.stderr)
            refused = admit(sentinel)
            self.assertNotEqual(0, refused.returncode)

    def test_backup_only_produces_private_duplicate_six_mtd_logical_rescue(self) -> None:
        source = read(INSTALL)
        self.assertIn("Current executable behavior is backup, validation,", source)
        self.assertIn("no current write authority", source)
        self.assertIn("schema=dcentos.s19k-aml-full-logical-rescue/v1", source)
        self.assertIn("partition_count=6", source)
        self.assertIn("bad_block_counts=stable-per-partition", source)
        self.assertIn("bad_block_positions=not-proven-by-count-only-sysfs", source)
        self.assertIn("nand_boot_dmesg=nand_boot_dmesg.txt", source)
        self.assertIn("raw_linux_restore=false", source)
        self.assertIn("padbad_nandwrite_replay=false", source)
        self.assertIn("physical_full_device_replay=false", source)
        self.assertIn("unit_specific_config_included=true", source)
        self.assertIn("sensitive_unit_data=true", source)
        self.assertIn("offhost_encrypted_copy_required=true", source)
        self.assertIn("platform_observation=$PLATFORM", source)
        self.assertIn("identity_disposition=tuple-proven-$EXACT_AMLOGIC_IDENTITY_VARIANT", source)
        self.assertNotIn('echo "platform=am3-aml-s19k"', source)
        self.assertIn('chmod 0700 "$ARTIFACT_DIR"', source)
        self.assertIn('chmod 0600 "$ARTIFACT_DIR"/*.bin "$ARTIFACT_DIR"/*.txt', source)
        self.assertIn("for MTD_INDEX in 0 1 2 3 4", source)
        self.assertEqual(
            2,
            source.count('ssh_stream_get "nanddump --bb=padbad --omitoob \'$MTD_DEV\'"'),
        )
        # 2026-08-31 r7 (99e32c650, live .80 six-MTD backup) appended a
        # locked_pages field to every rescue row (the Amlogic boot partition
        # carries factory-locked pages; mtd5's rootfs has none). Assert the exact
        # current row including that field.
        self.assertIn(
            '"mtd5=system,$MTD5_BACKUP_SIZE,$MTD5_LOCAL_SHA,padbad,omitoob,duplicate-match,badblocks=$MTD5_BAD_BLOCKS_AFTER,locked_pages=none"',
            source,
        )
        self.assertNotIn("badmap-empty", source)
        exact_map = source.index(
            'dcent_am3_require_exact_s19k_mtd_map_file "$ARTIFACT_DIR/proc_mtd.txt"'
        )
        full_capture = source.index("for MTD_INDEX in 0 1 2 3 4")
        backup_exit = source.index('if [ "$BACKUP_ONLY" = true ]; then', full_capture)
        self.assertLess(exact_map, full_capture)
        self.assertLess(full_capture, backup_exit)

    def test_dormant_flag_and_revert_paths_refuse_mixed_identity_without_mutation(self) -> None:
        flag_source = read(FLAG_HELPER)
        revert_source = read(LEGACY_REVERT)
        self.assertNotIn("CODE-COMPLETE but NOT live-tested", revert_source)
        self.assertIn("this is not a code-complete revert", revert_source)
        exact_pair = "am3-aml-s19k:am3-s19k"
        for source in (flag_source, revert_source):
            self.assertIn(exact_pair, source)
            self.assertIn("DCENTOS_PLATFORM_FILE", source)
            self.assertIn("DCENTOS_BOARD_TARGET_FILE", source)
        self.assertIn("one_byte_execute_retired=true", flag_source)
        self.assertIn("candidate_required=full-0x20000-byte-eraseblock", flag_source)
        self.assertIn("candidate_source=host-fixture-only", flag_source)
        self.assertIn("write_command=false", flag_source)
        self.assertIn("EB_OFF=$((LOCAL_DEC % ERASESIZE))", flag_source)
        self.assertIn('seek="$EB_OFF"', flag_source)
        self.assertNotIn("byte_in_block must be 0", flag_source)
        self.assertIn(
            "readback_required=full-0x20000-byte-sha256-and-byte-compare",
            flag_source,
        )
        self.assertNotIn("dry_flash_erase=", flag_source)
        self.assertNotIn("dry_nandwrite=", flag_source)
        self.assertNotIn("printf '\\\\x01' | nandwrite", flag_source)
        self.assertNotIn("printf '\\\\x02' | nandwrite", flag_source)
        self.assertNotIn("printf '\\\\x03' | nandwrite", flag_source)
        self.assertNotIn("mode=execute-eraseblock-rewrite", flag_source)
        self.assertNotIn("nand=erased+programmed", flag_source)

        with tempfile.TemporaryDirectory() as raw_temp:
            root = Path(raw_temp)
            platform = root / "platform"
            target = root / "board_target"
            platform.write_text("am3-aml-s21\n", encoding="ascii")
            target.write_text("am3-s19k\n", encoding="ascii")
            dummy = root / "stock.tar.gz"
            dummy.write_bytes(b"not reached")
            shim = root / "shim"
            shim.mkdir()
            mutation_log = root / "mutation.log"
            mutation_log.write_bytes(b"")
            for name in ("flash_erase", "nandwrite", "fw_setenv"):
                tool = shim / name
                tool.write_text(
                    "#!/bin/sh\nprintf '%s\\n' \"$0 $*\" >> \"$AML_MUTATION_LOG\"\nexit 99\n",
                    encoding="ascii",
                )
                tool.chmod(0o755)

            env_pairs = {
                "DCENTOS_PLATFORM_FILE": shell_path(platform),
                "DCENTOS_BOARD_TARGET_FILE": shell_path(target),
                "DCENT_S19K_RECOVERY_FLAG_EXECUTE": "1",
                "AML_MUTATION_LOG": shell_path(mutation_log),
            }
            if os.name == "nt":
                prefix = ["wsl.exe", "env", f"PATH={shell_path(shim)}:/usr/bin:/bin"]
                prefix.extend(f"{key}={value}" for key, value in env_pairs.items())
                flag_command = prefix + ["sh", shell_path(FLAG_HELPER), "--value", "0x02", "--execute"]
                revert_command = prefix + [
                    "sh",
                    shell_path(LEGACY_REVERT),
                    shell_path(dummy),
                    "0" * 64,
                ]
            else:
                env = os.environ.copy()
                env.update(env_pairs)
                env["PATH"] = f"{shim}:/usr/bin:/bin"
                flag_command = ["sh", str(FLAG_HELPER), "--value", "0x02", "--execute"]
                revert_command = ["sh", str(LEGACY_REVERT), str(dummy), "0" * 64]

            for command in (flag_command, revert_command):
                result = subprocess.run(
                    command,
                    text=True,
                    capture_output=True,
                    check=False,
                    env=None if os.name == "nt" else env,
                )
                self.assertNotEqual(0, result.returncode)
                self.assertIn("platform:target='am3-aml-s21:am3-s19k'", result.stderr)
                self.assertEqual(b"", mutation_log.read_bytes())

    def test_exact_s19k_map_is_checked_before_backup_stream(self) -> None:
        source = read(INSTALL)
        geometry = read(AM3_GEOMETRY)
        restore = read(RESTORE)
        expected_rows = (
            "mtd0: 00200000 00020000 bootloader",
            "mtd1: 00800000 00020000 tpl",
            "mtd2: 03200000 00020000 stock_system",
            "mtd3: 00500000 00020000 stock_config",
            "mtd4: 02000000 00020000 overlay",
            "mtd5: 09900000 00020000 system",
        )
        for row in expected_rows:
            self.assertIn(row, geometry)
        geometry_gate = source.index(
            'dcent_am3_require_exact_s19k_mtd_map_file "$ARTIFACT_DIR/proc_mtd.txt"'
        )
        first_stream = source.index(
            'ssh_stream_get "nanddump --bb=padbad --omitoob'
        )
        self.assertLess(geometry_gate, first_stream)
        self.assertIn('[ "$MTD5_NAME" != system ]', source)
        self.assertIn('S19K_MTD5_SIZE_EXPECTED=$((0x09900000))', source)

        ledger_gate = restore.index(
            'dcent_am3_require_exact_s19k_mtd_map_file "$PROC_TMP"'
        )
        self.assertLess(ledger_gate, restore.index("RECOMPUTED="))
        live_gate = restore.index(
            "dcent_am3_require_exact_s19k_mtd_map_file /proc/mtd"
        )
        self.assertLess(live_gate, restore.index("require_exact_live_s19k_identity /etc/dcentos"))
        self.assertLess(live_gate, restore.index('echo "$PWR_GPIO" > "$SYS/export"'))

    def test_exact_s19k_map_rejects_equal_sum_foreign_layouts(self) -> None:
        exact_rows = [
            'mtd0: 00200000 00020000 "bootloader"',
            'mtd1: 00800000 00020000 "tpl"',
            'mtd2: 03200000 00020000 "stock_system"',
            'mtd3: 00500000 00020000 "stock_config"',
            'mtd4: 02000000 00020000 "overlay"',
            'mtd5: 09900000 00020000 "system"',
        ]

        with tempfile.TemporaryDirectory() as raw_temp:
            root = Path(raw_temp)
            harness = root / "geometry-admit.sh"
            harness.write_bytes(
                (
                    "#!/bin/sh\nset -eu\n"
                    f". '{shell_path(AM3_GEOMETRY)}'\n"
                    'dcent_am3_require_exact_s19k_mtd_map_file "$1"\n'
                ).encode("utf-8")
            )

            def admit(rows: list[str]) -> subprocess.CompletedProcess[str]:
                proc_mtd = root / "proc_mtd.txt"
                proc_mtd.write_bytes(
                    ("dev:    size   erasesize  name\n" + "\n".join(rows) + "\n").encode(
                        "ascii"
                    )
                )
                command = (
                    ["wsl.exe", "sh", shell_path(harness), shell_path(proc_mtd)]
                    if os.name == "nt"
                    else ["sh", str(harness), str(proc_mtd)]
                )
                return subprocess.run(command, text=True, capture_output=True, check=False)

            result = admit(exact_rows)
            self.assertEqual(0, result.returncode, result.stderr)

            foreign_maps = {
                # mtd0..4 retain the exact same aggregate size, so the old
                # sum-only base parser could not distinguish this layout.
                "equal-sum-layout": [
                    row.replace("03200000", "03100000") if row.startswith("mtd2:")
                    else row.replace("02000000", "02100000") if row.startswith("mtd4:")
                    else row
                    for row in exact_rows
                ],
                "name": [
                    row.replace('"system"', '"rootfs"') if row.startswith("mtd5:") else row
                    for row in exact_rows
                ],
                "erasesize": [
                    row.replace("00020000", "00040000") if row.startswith("mtd3:") else row
                    for row in exact_rows
                ],
                "mtd5-size": [
                    row.replace("09900000", "09800000") if row.startswith("mtd5:") else row
                    for row in exact_rows
                ],
                "extra-row": exact_rows + ['mtd6: 00100000 00020000 "foreign"'],
                "missing-row": exact_rows[:-1],
            }
            for mutation, rows in foreign_maps.items():
                with self.subTest(mutation=mutation):
                    result = admit(rows)
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn("exact six-part .78 map", result.stderr)

    def test_padbad_preserves_offsets_that_skipbad_compaction_loses(self) -> None:
        erase = 4
        blocks = (b"A" * erase, b"B" * erase, b"C" * erase)
        compact_skipbad = blocks[0] + blocks[2]
        offset_preserving_padbad = blocks[0] + (b"\xff" * erase) + blocks[2]
        third_block_offset = erase * 2
        self.assertEqual(b"C" * erase, offset_preserving_padbad[third_block_offset:])
        self.assertEqual(b"", compact_skipbad[third_block_offset:])

        # The held mtd-utils source proves that default skip-bad nandwrite
        # advances the physical offset before its next input read. A padbad
        # 0xFF placeholder is therefore replayed onto the next good eraseblock;
        # it is not consumed for the skipped physical block. Admit only the
        # unambiguous zero-bad-block case.
        def zero_only_restore(
            before: int | None, after: int | None, live: int | None
        ) -> bool:
            return before == after == live == 0

        self.assertTrue(zero_only_restore(0, 0, 0))
        self.assertFalse(zero_only_restore(1, 1, 1))
        self.assertFalse(zero_only_restore(0, 1, 1))
        self.assertFalse(zero_only_restore(None, None, None))

        restore = read(RESTORE)
        backup_gate = restore.index(
            "full padbad restore is admitted only for a stable zero-bad-block backup"
        )
        live_gate = restore.index("live mtd5 bad-block count is unavailable")
        gpio = restore.index("gpio437 SafeOff (am3-s19k-active-low, value=1)")
        writer = restore.index('nandwrite -p "$ROOTFS_MTD"')
        self.assertLess(backup_gate, writer)
        self.assertLess(live_gate, gpio)
        self.assertLess(live_gate, writer)
        self.assertIn("no proven padbad-to-skipbad replay transform exists", restore)
        self.assertIn(
            'nanddump --bb=padbad --omitoob -f "$RESTORE_TMP/mtd5_restore_readback.bin"',
            restore,
        )
        self.assertNotIn("/tmp/mtd5_restore_readback.bin", restore)
        self.assertNotIn(
            'nanddump --bb=skipbad -f "$RESTORE_TMP/mtd5_restore_readback.bin"',
            restore,
        )

    def test_dormant_stock_revert_uses_only_a_private_tmp_transaction(self) -> None:
        source = read(LEGACY_REVERT)
        self.assertIn(
            'REVERT_TMP=$(mktemp -d "${TMPDIR:-/tmp}/dcent-s19k-stock-revert.XXXXXX")',
            source,
        )
        self.assertIn('REVERT_PLAN="$REVERT_TMP/REVERT_COMMIT_PLAN.txt"', source)
        self.assertIn('PRIVATE_FW="$REVERT_TMP/stock-candidate.tar.gz"', source)
        self.assertIn('trap cleanup_revert_tmp EXIT', source)
        self.assertIn('cat "$REVERT_PLAN"', source)
        self.assertIn('tar -tzf "$PRIVATE_FW" > "$TOC"', source)
        self.assertIn('tar -xOzf "$PRIVATE_FW" -- "$UIMAGE_MEMBER"', source)
        self.assertIn('/*|-*|*/-*|..|../*|*/..|*/../*)', source)
        self.assertIn('MAX_ARCHIVE_BYTES=67108864', source)
        self.assertIn('(ulimit -f 2048 && tar -tzf', source)
        self.assertIn('(ulimit -f 81920 && tar -xOzf', source)
        self.assertIn('archive must contain exactly one uImage-like candidate', source)
        self.assertIn('POST_EXTRACT_SHA256=$(sha256sum "$PRIVATE_FW"', source)
        self.assertIn('exactly equal 64+ih_size', source)
        self.assertIn('uimage_crc_verified=false', source)
        self.assertIn('stock_payload_identity_verified=false', source)
        self.assertIn('vendor_factory_sd_is_only_evidence_bound_stock_route=true', source)
        self.assertNotIn('/tmp/stock_extract', source)
        self.assertNotIn('/tmp/REVERT_COMMIT_PLAN.txt', source)
        self.assertNotIn('/tmp/stock_firmware_am3_aml_s19k', source)

    def test_dormant_stock_revert_binds_one_private_uimage_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            root = Path(raw_temp)
            platform = root / "platform"
            target = root / "board_target"
            platform.write_text("am3-aml-s19k\n", encoding="ascii")
            target.write_text("am3-s19k\n", encoding="ascii")
            transaction_root = root / "tmp"
            transaction_root.mkdir()

            uimage = bytearray(80)
            uimage[0:4] = bytes.fromhex("27051956")
            uimage[12:16] = (16).to_bytes(4, "big")
            uimage[29] = 22  # IH_ARCH_ARM64
            payload = root / "rootfs_uImage.bin"
            payload.write_bytes(uimage)

            def make_archive(path: Path, members: tuple[str, ...]) -> str:
                with tarfile.open(path, mode="w:gz") as archive:
                    for member in members:
                        archive.add(payload, arcname=member)
                return hashlib.sha256(path.read_bytes()).hexdigest()

            one = root / "one.tar.gz"
            one_sha = make_archive(one, ("payload/rootfs_uImage.bin",))
            two = root / "two.tar.gz"
            two_sha = make_archive(
                two,
                ("payload/rootfs_uImage.bin", "payload/alternate_uImage.bin"),
            )

            env_pairs = {
                "DCENTOS_PLATFORM_FILE": shell_path(platform),
                "DCENTOS_BOARD_TARGET_FILE": shell_path(target),
                "TMPDIR": shell_path(transaction_root),
            }

            def invoke(archive: Path, digest: str) -> subprocess.CompletedProcess[str]:
                if os.name == "nt":
                    command = ["wsl.exe", "env"]
                    command.extend(f"{key}={value}" for key, value in env_pairs.items())
                    command.extend(
                        [
                            "sh",
                            shell_path(LEGACY_REVERT),
                            "--dry-run",
                            shell_path(archive),
                            digest,
                        ]
                    )
                    return subprocess.run(command, text=True, capture_output=True, check=False)
                env = os.environ.copy()
                env.update(env_pairs)
                return subprocess.run(
                    ["sh", str(LEGACY_REVERT), "--dry-run", str(archive), digest],
                    text=True,
                    capture_output=True,
                    check=False,
                    env=env,
                )

            admitted = invoke(one, one_sha)
            self.assertEqual(0, admitted.returncode, admitted.stderr)
            self.assertIn("exact_header_length=80 classified", admitted.stdout)
            self.assertIn("uimage_crc_verified=false", admitted.stdout)
            self.assertIn("stock_payload_identity_verified=false", admitted.stdout)
            self.assertEqual([], list(transaction_root.iterdir()))

            ambiguous = invoke(two, two_sha)
            self.assertNotEqual(0, ambiguous.returncode)
            self.assertIn("exactly one uImage-like candidate", ambiguous.stderr)
            self.assertEqual([], list(transaction_root.iterdir()))

            dash = root / "dash.tar.gz"
            dash_sha = make_archive(dash, ("-malicious_uImage.bin",))
            option_like = invoke(dash, dash_sha)
            self.assertNotEqual(0, option_like.returncode)
            self.assertIn("archive member escapes its root", option_like.stderr)
            self.assertEqual([], list(transaction_root.iterdir()))

    def test_held_mtd_utils_proves_padbad_nandwrite_mismatch(self) -> None:
        archive = ROOT / "buildroot/dl/mtd/mtd-utils-2.2.1.tar.bz2"
        self.assertEqual(
            hashlib.sha256(archive.read_bytes()).hexdigest(),
            "f7ae20b2eb79ee83441468f0b99d897024cd96ff853eea59106fb1952065c803",
        )
        with tarfile.open(archive, mode="r:bz2") as held:
            nandwrite_member = held.extractfile(
                "mtd-utils-2.2.1/nand-utils/nandwrite.c"
            )
            nanddump_member = held.extractfile(
                "mtd-utils-2.2.1/nand-utils/nanddump.c"
            )
            self.assertIsNotNone(nandwrite_member)
            self.assertIsNotNone(nanddump_member)
            nandwrite = nandwrite_member.read().decode("utf-8")
            nanddump = nanddump_member.read().decode("utf-8")

        loop = nandwrite.index("while (blockstart != (mtdoffset & (~ebsize_aligned + 1)))")
        skip = nandwrite.index("mtdoffset = blockstart + ebsize_aligned;", loop)
        next_input_read = nandwrite.index(
            "/* Read more data from the input if there isn't enough in the buffer */",
            skip,
        )
        self.assertLess(skip, next_input_read)
        self.assertIn(
            "padbad:  dump flash data, substituting 0xFF for any bad blocks",
            nanddump,
        )

    def test_held_78_bad_blocks_intersect_the_planned_root_window(self) -> None:
        dmesg = read(
            ROOT.parents[1]
            / ""
        )
        global_blocks = sorted(
            {
                int(value, 16)
                for value in re.findall(
                    r"NAND bbt detect factory Bad block at ([0-9a-f]+)", dmesg
                )
            }
        )
        self.assertEqual(
            global_blocks,
            [0x0C000000, 0x0C020000, 0x0FE60000, 0x0FEA0000],
        )
        mtd5_base = 0x06700000
        local_blocks = [address - mtd5_base for address in global_blocks]
        self.assertEqual(
            local_blocks,
            [0x05900000, 0x05920000, 0x09760000, 0x097A0000],
        )
        root_start, root_end = 0x05100000, 0x07900000
        self.assertEqual(
            [address for address in local_blocks if root_start <= address < root_end],
            [0x05900000, 0x05920000],
        )
        self.assertIn("Number of bad blocks: 4", dmesg)
        self.assertIn("ECC failed: 0", dmesg)
        self.assertIn("ECC corrected: 0", dmesg)

    def test_future_writer_revalidates_each_mutation_boundary_and_stays_zero_bad_only(self) -> None:
        source = read(INSTALL)
        policy_gate = source.index(
            'if [ "$MTD5_RESTORE_BAD_BLOCK_POLICY" != zero-only-admitted ]; then'
        )
        clearance = source.index("CLEAR_FOR_FLASH=false", policy_gate)
        pre_stop = source.index("\ncapture_pre_mutation_evidence pre_stop", clearance)
        stock_signal = source.index("kill -TERM", pre_stop)
        pre_gpio = source.index("\ncapture_pre_mutation_evidence pre_gpio", stock_signal)
        gpio_write = source.index('ssh_run "PWR_GPIO=437', pre_gpio)
        pre_nand = source.index("\ncapture_pre_mutation_evidence pre_nand", gpio_write)
        flash = source.index("flash_erase $ROOTFS_MTD", pre_nand)
        self.assertLess(policy_gate, clearance)
        self.assertLess(pre_stop, stock_signal)
        self.assertLess(stock_signal, pre_gpio)
        self.assertLess(pre_gpio, gpio_write)
        self.assertLess(gpio_write, pre_nand)
        self.assertLess(pre_nand, flash)
        self.assertIn("schema=dcentos.amlogic-pre-mutation-evidence/v1", source)
        self.assertIn('cmp -s "$ARTIFACT_DIR/proc_mtd.txt" "$proc_mtd_file"', source)
        self.assertIn('[ "$current_identity_sha" = "$IDENTITY_PROOF_SHA" ]', source)
        self.assertIn('[ "$current_bad_blocks" = 0 ]', source)
        self.assertIn('[ ! -L \'$REMOTE_PREFIX/root\' ]', source)
        target_guard_start = source.index('ssh_run "\n', pre_nand)
        target_guard_end = source.index("\n    flash_erase $ROOTFS_MTD", target_guard_start)
        target_guard = source[target_guard_start:target_guard_end]
        self.assertIn("/sys/class/mtd/mtd5/bad_blocks", target_guard)
        self.assertIn("/sys/class/gpio/gpio437/value", target_guard)
        self.assertIn("'0'", target_guard)
        open_fd = source.index("exec 3< '$REMOTE_PREFIX/root'", target_guard_start)
        hash_fd = source.index("sha256sum /proc/self/fd/3", open_fd)
        erase_actual = source.index("\n    flash_erase $ROOTFS_MTD", hash_fd)
        write_fd = source.index(
            "nandwrite -p -s $ROOTFS_OFFSET_HEX $ROOTFS_MTD /proc/self/fd/3",
            erase_actual,
        )
        self.assertLess(open_fd, hash_fd)
        self.assertLess(hash_fd, erase_actual)
        self.assertLess(erase_actual, write_fd)
        self.assertNotIn(
            "nandwrite -p -s $ROOTFS_OFFSET_HEX $ROOTFS_MTD '$REMOTE_PREFIX/root'",
            source,
        )

    def test_flash_execution_gate_remains_false_and_precedes_writer(self) -> None:
        source = read(INSTALL)
        self.assertNotIn("CLEAR_FOR_FLASH=true", source)
        gate = source.index("CLEAR_FOR_FLASH=false")
        writer = source.index("flash_erase $ROOTFS_MTD $ROOTFS_OFFSET_HEX $ROOTFS_ERASE_COUNT", gate)
        self.assertLess(gate, writer)

    def test_persistent_installer_pins_host_key_and_refuses_artifact_clobber(self) -> None:
        source = read(INSTALL)
        self.assertIn("StrictHostKeyChecking=yes", source)
        self.assertNotIn("StrictHostKeyChecking=no", source)
        self.assertIn("UserKnownHostsFile=$KNOWN_HOSTS", source)
        self.assertIn('--artifact-dir must not already exist (no-clobber backup transaction)', source)
        self.assertNotIn('mkdir -p "$ARTIFACT_DIR"', source)

    def test_persistent_installer_verifies_authority_without_claiming_full_apply(self) -> None:
        source = read(INSTALL)
        validator = source.index('DCENT_ALLOW_UNSIGNED_SYSUPGRADE=0')
        installable_gate = source.index("DCENT_REQUIRE_INSTALLABLE_PACKAGE=1")
        staging = source.index('scp_put "$FIRMWARE"')
        self.assertLess(validator, staging)
        self.assertLess(installable_gate, staging)
        package_validator = read(ROOT / "scripts/pre_flash_validate.sh")
        self.assertIn('manifest_boolean_field installable "$MANIFEST"', package_validator)
        self.assertIn(
            "caller requires installable=true; inspection-only package is not install authority",
            package_validator,
        )
        self.assertIn(
            '"manifest_profile":"dcentos.sysupgrade-authority/v1"', source
        )
        self.assertIn('"installable":true', source)
        self.assertIn("persistent install requires verified authority-v1 manifest", source)
        self.assertIn("persistent install requires verified installable=true manifest", source)
        self.assertIn('"package_authority": "release_ed25519_authority_v1"', source)
        self.assertIn('"package_manifest_verified": true', source)
        self.assertIn('"package_manifest_applied": false', source)
        self.assertIn('"compatibility_projection": "rootfs_only_stock_kernel"', source)
        self.assertIn('"kernel_payload_applied": false', source)
        self.assertNotIn('"package_manifest_applied": true', source)

    def test_restore_refuses_legacy_skipbad_or_untyped_backup(self) -> None:
        source = read(RESTORE)
        self.assertIn("--execute            refused", source)
        self.assertIn("current 0x05100000", source)
        self.assertIn("stale 0x05700000 is size-sum geometry", source)
        gate = source.index('[ "$LEDGER_BAD_BLOCKS" = "padbad" ]')
        slice_use = source.index('dcent_am3_extract_nandrecovery_env "$MTD5"')
        self.assertLess(gate, slice_use)
        self.assertIn('[ "$LEDGER_OOB" = "omitted" ]', source)
        self.assertIn('[ "$LEDGER_DUPLICATE" = "true" ]', source)
        self.assertIn("legacy skipbad or untyped mtd5 backups are non-restorable", source)
        self.assertIn("mtd5_bad_block_count_before", source)
        self.assertIn("mtd5_bad_block_count_after", source)
        self.assertIn("mtd5_restore_bad_block_policy", source)
        self.assertIn("BACKUP_LEDGER repeats authority field(s)", source)

    def test_restore_verification_never_writes_scratch_into_backup(self) -> None:
        source = read(RESTORE)
        self.assertIn('[ ! -L "$ARTIFACT_DIR" ]', source)
        for artifact in ("$LEDGER", "$NAND_ENV", "$MTD5", "$NANDRECOVERY_ENV"):
            self.assertIn(f'[ ! -L "{artifact}" ]', source)
        self.assertIn('RESTORE_TMP=$(mktemp -d', source)
        self.assertIn('PROC_TMP="$RESTORE_TMP/proc_mtd.txt"', source)
        self.assertIn('SLICE="$RESTORE_TMP/nandrecovery_env.slice"', source)
        self.assertNotIn('"$ARTIFACT_DIR/.restore_proc_mtd.txt"', source)
        self.assertNotIn('"$ARTIFACT_DIR/.restore_nandrecovery_env.slice"', source)

    def test_stock_recovery_binds_plan_and_sidecar_to_backup_ledger(self) -> None:
        source = read(RECOVER)
        self.assertIn('LEDGER="$ARTIFACT_DIR/BACKUP_LEDGER.txt"', source)
        self.assertIn('field_get_exact "$PLAN" flag_local recover-plan', source)
        self.assertIn('field_get_exact "$LEDGER" nandrecovery_env_sha256 backup-ledger', source)
        self.assertIn('[ "$FLAG_LOCAL" = "0x04D00000" ]', source)
        self.assertIn('[ "$ENV_LOCAL" = "0x04900000" ]', source)
        self.assertIn('[ "$NANDRECOVERY_ENV_SHA" = "$LEDGER_ENV_SHA" ]', source)
        self.assertIn("nandrecovery_env_sha256_ok=true", source)

    def test_stock_recovery_outputs_are_private_atomic_transactions(self) -> None:
        source = read(RECOVER)
        self.assertIn('[ -d "$ARTIFACT_DIR" ] && [ ! -L "$ARTIFACT_DIR" ]', source)
        self.assertIn('[ -f "$REQUIRED_INPUT" ] && [ ! -L "$REQUIRED_INPUT" ]', source)
        self.assertIn('mktemp "$ARTIFACT_DIR/.RECOVER_WALK.txt.tmp.XXXXXX"', source)
        self.assertIn('mktemp "$ARTIFACT_DIR/.RECOVER_EXECUTE_REFUSE.txt.tmp.XXXXXX"', source)
        self.assertIn('mv -f "$WALK_TMP" "$WALK"', source)
        self.assertIn('mv -f "$REFUSE_TMP" "$REFUSE"', source)

    def test_stock_recovery_fixture_walk_and_duplicate_authority_refusal(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            base = Path(temp)
            good = base / "good"
            self.make_recover_fixture(good)
            good_rel = good.relative_to(ROOT).as_posix()
            result = subprocess.run(
                ["bash", "scripts/recover_amlogic_to_stock.sh", "--artifact-dir", good_rel, "--dry-run"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            walk = (good / "RECOVER_WALK.txt").read_text(encoding="ascii")
            self.assertIn("nandrecovery_env_sha256_ok=true", walk)
            self.assertIn("identity_proof_schema=dcentos.amlogic-identity-tuple/v1", walk)
            self.assertIn("identity_proof_variant=s19kpro", walk)
            self.assertIn("clear_for_flash=false", walk)

            tampered = base / "tampered"
            self.make_recover_fixture(tampered)
            proof = tampered / "identity_tuple_pre.txt"
            proof.write_text(
                proof.read_text(encoding="ascii").replace("S19k Pro", "S21 Pro", 1),
                encoding="ascii",
            )
            tampered_rel = tampered.relative_to(ROOT).as_posix()
            result = subprocess.run(
                ["bash", "scripts/recover_amlogic_to_stock.sh", "--artifact-dir", tampered_rel, "--dry-run"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("identity_tuple_pre.txt sha256", result.stderr)

            duplicate = base / "duplicate"
            self.make_recover_fixture(duplicate, duplicate_flag=True)
            duplicate_rel = duplicate.relative_to(ROOT).as_posix()
            result = subprocess.run(
                ["bash", "scripts/recover_amlogic_to_stock.sh", "--artifact-dir", duplicate_rel, "--dry-run"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("exactly one flag_local=", result.stderr)

    def test_s99_preserves_and_verifies_complete_flag_eraseblock(self) -> None:
        source = read(S99)
        body = function_body(source, "commit_recovery_flag")
        self.assertIn("eraseblock.before-duplicate.bin", body)
        self.assertIn("nanddump --bb=padbad --omitoob", body)
        self.assertIn('cmp -s "$FLAG_BEFORE" "$FLAG_BEFORE_2"', body)
        self.assertIn("printf '\\003'", body)
        self.assertIn(
            'nandwrite -p -s "$ERASEBLOCK_START" "$RECOVERY_MTD" "$FLAG_EXPECTED"',
            body,
        )
        self.assertIn('cmp -s "$FLAG_EXPECTED" "$FLAG_READBACK"', body)
        self.assertIn("preserved pre-write eraseblock transaction", body)
        self.assertNotIn(
            'printf \'\\x3\' | nandwrite -p -s "$RECOVERY_FLAG_OFFSET"', body
        )


if __name__ == "__main__":
    unittest.main()
