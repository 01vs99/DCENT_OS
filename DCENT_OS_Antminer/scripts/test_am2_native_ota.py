#!/usr/bin/env python3
"""AM2 exact FPGA envelope, complete environment transaction and boot execution."""

import gzip
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import struct
import sys
import tarfile
import tempfile
import unittest
import zlib

from lib import am2_ota_boot as ota

WORKSPACE = Path(__file__).resolve().parents[3]
NONCE = "a" * 64


def source(slot=1):
    return {
        **ota.fabric.nand_boot_environment(slot, "run nandboot_recovery"),
        "firmware": str(slot),
        "miner_hwid": "retained-unit",
        "ethaddr": "02:00:00:00:00:01",
    }


def full(receipt, state):
    return {
        **receipt["unchanged"],
        **{k: v for k, v in receipt[state].items() if v is not None},
    }


class NativeTransactionTests(unittest.TestCase):
    def test_complete_forward_and_rollback_preserve_unrelated_keys_and_absence(self):
        for current in (1, 2):
            receipt, forward, rollback = ota.transition(source(current), current, NONCE)
            self.assertIn(b"dcent_native_slot=\n", forward)
            self.assertIn(b"dcent_fpga_load2=", forward)
            self.assertEqual(len(forward.splitlines()), len(receipt["after"]))
            self.assertIn(b"dcent_native_transaction=\n", rollback)
            ota.verify_environment(receipt, full(receipt, "after"), "after")
            ota.verify_environment(receipt, source(current), "before")
            for key in receipt["after"]:
                altered = full(receipt, "after")
                altered[key] = "changed"
                with self.assertRaises(ValueError, msg=key):
                    ota.verify_environment(receipt, altered, "after")
            altered = full(receipt, "after")
            altered["miner_hwid"] = "other-unit"
            with self.assertRaises(ValueError):
                ota.verify_environment(receipt, altered, "after")

    def test_rollback_after_pending_committed_and_automatic_fallback(self):
        receipt, _, expected = ota.transition(source(), 1, NONCE)
        for current, stage in ((2, "0"), (2, "1"), (2, None), (1, None)):
            actual = full(receipt, "after")
            actual["firmware"] = str(current)
            if stage is None:
                del actual["first_boot"], actual["upgrade_stage"]
            else:
                actual["upgrade_stage"] = stage
            self.assertEqual(ota.rollback_script(receipt, actual, current), expected)

    def test_rollback_cannot_replay_an_older_update_or_inject_commands(self):
        receipt, _, _ = ota.transition(source(), 1, NONCE)
        actual = full(receipt, "after")
        actual["dcent_native_transaction"] = "b" * 64
        with self.assertRaises(ValueError):
            ota.rollback_script(receipt, actual, 2)
        malicious = json.loads(json.dumps(receipt))
        malicious["before"]["dcent_nandboot"] = "nand erase.chip"
        with self.assertRaises(ValueError):
            ota.validate_receipt(malicious)

    def test_fallback_scratch_variables_are_restored_without_relaxing_factory_identity(
        self,
    ):
        original = source()
        original["bootargs"] = "old boot arguments"
        receipt, _, expected = ota.transition(original, 1, NONCE)
        actual = full(receipt, "after")
        actual["firmware"] = "1"
        del actual["first_boot"], actual["upgrade_stage"]
        actual.update(
            bootargs="failed native kernel arguments", filesize="0x1fcc13", verify="yes"
        )
        self.assertEqual(ota.rollback_script(receipt, actual, 1), expected)
        self.assertIn(b"bootargs=old boot arguments\n", expected)
        actual["miner_hwid"] = "different unit"
        with self.assertRaises(ValueError):
            ota.rollback_script(receipt, actual, 1)

    def test_subsequent_update_has_a_distinct_generation_and_complete_rollback(self):
        first, _, _ = ota.transition(source(), 1, NONCE)
        committed = full(first, "after")
        del committed["first_boot"], committed["upgrade_stage"]
        second, _, _ = ota.transition(committed, 2, "b" * 64)
        ota.verify_environment(second, committed, "before")
        self.assertEqual(second["destination_firmware"], 1)
        self.assertNotEqual(
            second["after"]["dcent_native_transaction"],
            first["after"]["dcent_native_transaction"],
        )

    def test_no_duplicate_or_wrong_completion_selector(self):
        good = f"ubi.mtd=7 dcent.fpga_load_completed=1 dcent.fpga_sha256={ota.fabric.BITSTREAM_SHA256}"
        ota.validate_cmdline(good, 1)
        for bad in (
            good + " ubi.mtd=7",
            good.replace("completed=1", "completed=0"),
            good.replace("ubi.mtd=7", "ubi.mtd=8"),
        ):
            with self.assertRaises(ValueError):
                ota.validate_cmdline(bad, 1)
        with self.assertRaises(ValueError):
            ota.parse_environment(b"firmware=1\nfirmware=2\n")


class PreparedJobBindingTests(unittest.TestCase):
    BEFORE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    AFTER = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    JOB = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    PACKAGE = "d" * 64

    def prepared(self, current=1, job=True):
        receipt, _, _ = ota.transition(source(current), current, NONCE)
        environment = (
            dict(zip(ota.JOB_ENV_KEYS, (self.JOB, self.PACKAGE, self.BEFORE)))
            if job
            else {}
        )
        receipt = ota.bind_preparation(receipt, self.PACKAGE, self.BEFORE, environment)
        actual = full(receipt, "after")
        del actual["first_boot"], actual["upgrade_stage"]
        cmdline = f"ubi.mtd={receipt['destination_firmware'] + 6} dcent.fpga_load_completed=1 dcent.fpga_sha256={ota.fabric.BITSTREAM_SHA256}"
        return receipt, actual, cmdline

    def test_exact_both_slot_transactions_join_the_measured_job_after_commit(self):
        for current in (1, 2):
            receipt, actual, cmdline = self.prepared(current)
            observed = ota.verify_committed(
                receipt,
                actual,
                cmdline,
                self.AFTER,
                expected_job_id=self.JOB,
                expected_package_sha256=self.PACKAGE,
                expected_source_boot_id=self.BEFORE,
            )
            self.assertTrue(observed["boot_environment_committed"])
            self.assertFalse(observed["physical_hashing_verified"])
            self.assertEqual(observed["job_id"], self.JOB)
            self.assertEqual(observed["firmware"], 3 - current)
            self.assertEqual(observed["native_transaction"], NONCE)

    def test_partial_or_foreign_worker_bindings_cannot_own_the_preparation(self):
        receipt, _, _ = ota.transition(source(), 1, NONCE)
        good = dict(zip(ota.JOB_ENV_KEYS, (self.JOB, self.PACKAGE, self.BEFORE)))
        for key in ota.JOB_ENV_KEYS:
            for value in (None, "", "foreign"):
                altered = dict(good)
                if value is None:
                    del altered[key]
                else:
                    altered[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    ota.bind_preparation(receipt, self.PACKAGE, self.BEFORE, altered)
        bound = ota.bind_preparation(receipt, self.PACKAGE, self.BEFORE, good)
        with self.assertRaises(ValueError):
            ota.bind_preparation(bound, self.PACKAGE, self.BEFORE, good)

    def test_copied_or_modified_receipt_cannot_claim_a_different_job(self):
        receipt, actual, cmdline = self.prepared()
        for key in receipt["job_binding"]:
            altered = json.loads(json.dumps(receipt))
            altered["job_binding"][key] = "other"
            with self.subTest(key=key), self.assertRaises(ValueError):
                ota.verify_committed(altered, actual, cmdline, self.AFTER)
        with self.assertRaises(ValueError):
            ota.verify_committed(
                receipt,
                actual,
                cmdline,
                self.AFTER,
                expected_job_id=self.AFTER,
                expected_package_sha256=self.PACKAGE,
                expected_source_boot_id=self.BEFORE,
            )
        with self.assertRaises(ValueError):
            ota.verify_committed(
                receipt, actual, cmdline, self.AFTER, expected_job_id=self.JOB
            )

    def test_pending_wrong_slot_same_boot_and_foreign_environment_never_commit(self):
        receipt, actual, cmdline = self.prepared()
        for key, value in (
            ("first_boot", ""),
            ("upgrade_stage", "1"),
            ("firmware", "1"),
            ("dcent_native_transaction", "b" * 64),
            ("miner_hwid", "other-unit"),
            ("new_factory_key", "unexpected"),
        ):
            altered = {**actual, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                ota.verify_committed(receipt, altered, cmdline, self.AFTER)
        with self.assertRaises(ValueError):
            ota.verify_committed(receipt, actual, cmdline, self.BEFORE)
        for altered in (
            cmdline.replace("ubi.mtd=8", "ubi.mtd=7"),
            cmdline.replace("completed=1", "completed=0"),
            cmdline + " ubi.mtd=8",
        ):
            with self.assertRaises(ValueError):
                ota.verify_committed(receipt, actual, altered, self.AFTER)

    def test_cli_updates_and_old_rollback_receipts_keep_distinct_evidence(self):
        receipt, actual, cmdline = self.prepared(job=False)
        self.assertIsNone(
            ota.verify_committed(receipt, actual, cmdline, self.AFTER)["job_id"]
        )
        legacy, _, rollback = ota.transition(source(), 1, NONCE)
        self.assertEqual(ota.rollback_script(legacy, actual, 2), rollback)
        with self.assertRaises(ValueError):
            ota.verify_committed(legacy, actual, cmdline, self.AFTER)

    def test_actual_cli_consumes_exact_environment_and_expected_job(self):
        receipt, actual, cmdline = self.prepared()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "receipt.json").write_text(json.dumps(receipt))
            (root / "environment").write_text(
                "".join(f"{k}={v}\n" for k, v in actual.items())
            )
            (root / "cmdline").write_text(cmdline)
            (root / "boot-id").write_text(self.AFTER)
            command = [
                sys.executable,
                str(Path(ota.__file__)),
                "verify-committed",
                "--receipt",
                str(root / "receipt.json"),
                "--environment",
                str(root / "environment"),
                "--cmdline",
                str(root / "cmdline"),
                "--boot-id",
                str(root / "boot-id"),
                "--expected-job-id",
                self.JOB,
                "--expected-package-sha256",
                self.PACKAGE,
                "--expected-source-boot-id",
                self.BEFORE,
            ]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["job_id"], self.JOB)
            (root / "boot-id").write_text(self.BEFORE)
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)


@unittest.skipUnless(
    sys.platform == "linux"
    and shutil.which("fw_setenv")
    and shutil.which("fw_printenv"),
    "Linux libubootenv ordinary-file transaction fixtures",
)
class ExecutedEnvironmentCommitTests(unittest.TestCase):
    def invoke(self, failure):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = source()
            receipt, forward, _ = ota.transition(before, 1, NONCE)
            (root / "receipt.json").write_text(json.dumps(receipt))
            (root / "env.change").write_bytes(forward)
            raw = b"".join(f"{k}={v}\0".encode() for k, v in before.items()) + b"\0"
            raw = raw.ljust(131072 - 5, b"\0")
            record = struct.pack("<IB", zlib.crc32(raw), 1) + raw
            (root / "env").write_bytes(record * 2)
            config = root / "fw_env.config"
            config.write_text(
                f"{root / 'env'} 0x0 0x20000 0x20000\n"
                f"{root / 'env'} 0x20000 0x20000 0x20000\n"
            )
            participant = WORKSPACE / (
                "DCENT_OS_Antminer/br2_external_dcentos/board/zynq/"
                "rootfs-overlay/usr/libexec/dcentos/am2-native-ota.sh"
            )
            script = r"""
set -eu
. "$PARTICIPANT"
fw_setenv() {
    case "$FAILURE" in
        unchanged) return 9 ;;
        partial) "$REAL_SETENV" -c "$FW_ENV_CONFIG" firmware 2; return 9 ;;
    esac
    "$REAL_SETENV" "$@" || return $?
    case "$FAILURE" in
        late-error) return 9 ;;
        foreign-key) "$REAL_SETENV" -c "$FW_ENV_CONFIG" miner_hwid altered ;;
    esac
}
fw_printenv() {
    [ "$FAILURE" != read-error ] || return 9
    "$REAL_PRINTENV" "$@" || return $?
    if [ "$FAILURE" = read-warning ]; then echo warning >&2; fi
}
if am2_ota_apply_environment; then result=0; else result=$?; fi
printf 'RESULT=%s:%s\n' "$result" "$AM2_OTA_ENV_RESULT"
"""
            result = subprocess.run(
                ["sh", "-c", script],
                env={
                    **os.environ,
                    "PARTICIPANT": str(participant),
                    "FAILURE": failure,
                    "REAL_SETENV": shutil.which("fw_setenv"),
                    "REAL_PRINTENV": shutil.which("fw_printenv"),
                    "AM2_OTA_TOOL": str(Path(ota.__file__)),
                    "AM2_OTA_DIR": str(root),
                    "FW_ENV_CONFIG": str(config),
                    "FW_SETENV_SCRIPT": str(root / "env.change"),
                },
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout, result.stderr

    def test_real_redundant_commit_and_late_error_both_prove_complete_success(self):
        for failure in ("none", "late-error"):
            with self.subTest(failure=failure):
                output, errors = self.invoke(failure)
                self.assertIn("RESULT=0:committed", output, errors)
                if failure == "late-error":
                    self.assertIn("complete CRC-valid readback", errors)

    def test_unchanged_environment_is_distinguished_from_partial_or_foreign_change(
        self,
    ):
        for failure, expected in (
            ("unchanged", "unchanged"),
            ("partial", "indeterminate"),
            ("foreign-key", "indeterminate"),
        ):
            with self.subTest(failure=failure):
                output, errors = self.invoke(failure)
                self.assertIn(f"RESULT=1:{expected}", output, errors)

    def test_failed_or_warning_readback_never_establishes_committed_state(self):
        for failure in ("read-error", "read-warning"):
            with self.subTest(failure=failure):
                output, errors = self.invoke(failure)
                self.assertIn("RESULT=1:indeterminate", output, errors)


class ExactFitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        archive = (
            WORKSPACE
            / ""
        )
        with tarfile.open(archive) as handle:
            member = next(
                item
                for item in handle.getmembers()
                if item.name.endswith("firmware/system.bit.gz")
            )
            cls.raw = gzip.decompress(handle.extractfile(member).read())

    def test_constructed_exact_payload_fits_partition_and_accepts_erased_tail(self):
        fit = ota.fit_from_raw(self.raw)
        self.assertLess(len(fit), 2097152)
        ota.validate_fit(fit)
        ota.validate_fit(fit + b"\xff" * (2097152 - len(fit)))
        self.assertIn(hashlib.sha256(self.raw).digest(), fit)

    def test_container_form_inflates_to_the_same_admitted_fit(self):
        # The s19j knowledge-base extraction is a padded 2 MiB partition read
        # whose first bytes are the gzip member (W8-BITSTREAM-PROVENANCE
        # 4.2 F-2); the producer delivers that container byte-for-byte via
        # DCENT_AM2_S19J_BITSTREAM. The admission pins the INFLATED member.
        container = gzip.compress(self.raw, mtime=0) + b"\xff" * 512
        self.assertEqual(ota.fit_from_raw(container), ota.fit_from_raw(self.raw))
        with self.assertRaises(ValueError):
            ota.fit_from_raw(
                gzip.compress(self.raw[:-1] + bytes([self.raw[-1] ^ 1]), mtime=0)
            )
        # A member truncated before its CRC32/ISIZE trailer inflates to a
        # silent partial payload; the admission must refuse it.
        truncated = gzip.compress(self.raw, mtime=0)[:-8] + b"\xff" * 512
        with self.assertRaises(ValueError):
            ota.fit_from_raw(truncated)
        # Oversized members are cut off at the admitted size bound and
        # refused (deflate-amplification bombs cannot exhaust memory).
        with self.assertRaises(ValueError):
            ota.fit_from_raw(
                gzip.compress(b"\x00" * (ota.fabric.BITSTREAM_SIZE + 1), mtime=0)
            )

    @unittest.skipUnless(
        sys.platform == "linux" and shutil.which("mkimage") and shutil.which("fdtget"),
        "Linux U-Boot tools",
    )
    def test_actual_first_install_producer_fit_is_accepted_by_native_ota(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compressed = root / "system.bit.gz"
            compressed.write_bytes(gzip.compress(self.raw, mtime=0))
            uenv = root / "uEnv.txt"
            uenv.write_text(
                "bm_load_bitstream=fixture\nbm_set_bootargs=fixture\nsd_uenvcmd=fixture\n"
            )
            fit = ota.fabric.prepare(
                compressed, root / "fabric", uenv, shutil.which("mkimage")
            )
            data = fit.read_bytes()
            ota.validate_fit(data + b"\xff" * (2097152 - len(data)))

    @unittest.skipUnless(
        sys.platform == "linux" and shutil.which("mkimage") and shutil.which("fdtget"),
        "Linux U-Boot tools",
    )
    def test_real_uboot_tools_parse_the_generated_fit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fabric.itb"
            path.write_bytes(ota.fit_from_raw(self.raw))
            result = subprocess.run(
                ["mkimage", "-l", str(path)], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("system-bit", result.stdout)
            digest = subprocess.check_output(
                ["fdtget", "-t", "bx", str(path), "/images/system-bit/hash-1", "value"],
                text=True,
            )
            self.assertEqual(
                bytes(int(word, 16) for word in digest.split()).hex(),
                ota.fabric.BITSTREAM_SHA256,
            )

    def test_wrong_payload_hash_header_and_non_erased_tail_refuse(self):
        fit = ota.fit_from_raw(self.raw)
        for bad in (
            b"bad",
            fit[:-1],
            fit + b"\0",
            fit.replace(b"system-bit\0", b"system-bat\0", 1),
        ):
            with self.assertRaises(ValueError):
                ota.validate_fit(bad)
        with self.assertRaises(ValueError):
            ota.fit_from_raw(self.raw[:-1] + bytes([self.raw[-1] ^ 1]))


@unittest.skipUnless(sys.platform == "linux", "Linux transparent command adapter")
class ExecutedNativeBootTests(unittest.TestCase):
    def invoke(self, previous, stage="0", failure="", selected=None):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace"
            env = ota.native_environment(previous, NONCE)
            env.update(
                firmware=str(selected or 3 - previous),
                upgrade_stage=stage,
                first_boot="yes",
            )
            assignments = "\n".join(
                f"{key}={shlex.quote(value)}" for key, value in env.items()
            )
            script = (
                r"""set -u
TRACE=$1
FAILURE=$2
PREVIOUS=$3
setenv() { local key=$1; shift; printf -v "$key" '%s' "$*"; }
run() { local key=$1; eval "${!key}"; }
mw.l() { echo "MW $*" >> "$TRACE"; }
nand() { echo "NAND $*" >> "$TRACE"; [ "$FAILURE" != all ] && { [ "$firmware" = "$PREVIOUS" ] || [ "$FAILURE" != nand ]; }; }
fdt() { case "${3:-}" in dcent_hash_algo) dcent_hash_algo=sha256 ;; dcent_hash_size) dcent_hash_size=0x20 ;; dcent_hash_addr) dcent_hash_addr=0x011ffff0 ;; esac; }
itest() { [ "$1" = "$3" ]; }
cmp.b() { [ "$firmware" = "$PREVIOUS" ] || [ "$FAILURE" != digest ]; }
imxtract() { echo EXTRACT >> "$TRACE"; filesize=0x1fcc13; [ "$firmware" = "$PREVIOUS" ] || [ "$FAILURE" != extract ]; }
fpga() { echo FPGA >> "$TRACE"; [ "$firmware" = "$PREVIOUS" ] || [ "$FAILURE" != fpga ]; }
ubi() { echo "UBI $*" >> "$TRACE"; [ "$firmware" = "$PREVIOUS" ] || [ "$FAILURE" != kernel ]; }
bootm() { echo "BOOT $bootargs" >> "$TRACE"; if [ "$firmware" != "$PREVIOUS" ] && [ "$FAILURE" = returned ]; then return 0; fi; exit 0; }
saveenv() { echo "SAVE firmware=$firmware stage=$upgrade_stage first=$first_boot" >> "$TRACE"; [ "$FAILURE" != save ]; }
"""
                + assignments
                + "\nrun nandboot\n"
            )
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    script,
                    "native-boot",
                    str(trace),
                    failure,
                    str(previous),
                ],
                capture_output=True,
                text=True,
            )
            return result.returncode, trace.read_text(), result.stderr

    def test_both_slots_program_before_kernel_and_arm_once(self):
        for previous in (1, 2):
            rc, trace, error = self.invoke(previous)
            self.assertEqual(rc, 0, error)
            self.assertIn(f"SAVE firmware={3 - previous} stage=1 first=yes", trace)
            self.assertIn(f"NAND read 0x01000000 fpga{3 - previous} 0x200000", trace)
            self.assertLess(trace.index("FPGA"), trace.index("UBI"))
            self.assertIn(f"ubi.mtd={9 - previous}", trace)
            self.assertIn("dcent.fpga_load_completed=1", trace)

    def test_every_failed_new_boot_tries_previous_native_once(self):
        for previous in (1, 2):
            for failure in ("nand", "digest", "extract", "fpga", "kernel", "returned"):
                with self.subTest(previous=previous, failure=failure):
                    rc, trace, error = self.invoke(previous, failure=failure)
                    self.assertEqual(rc, 0, error)
                    self.assertIn(f"SAVE firmware={previous} stage= first=", trace)
                    self.assertIn(f"ubi.mtd={6 + previous}", trace)
                    self.assertEqual(
                        trace.count(f"NAND read 0x01000000 fpga{previous} "), 1
                    )

    def test_second_boot_goes_directly_to_previous_and_double_failure_terminates(self):
        for previous in (1, 2):
            rc, trace, error = self.invoke(previous, stage="1")
            self.assertEqual(rc, 0, error)
            self.assertNotIn(f"fpga{3 - previous} ", trace)
            rc, trace, _ = self.invoke(previous, failure="all")
            self.assertNotEqual(rc, 0)
            self.assertEqual(trace.count("NAND read"), 2)

    def test_failed_stage_save_never_reads_flash_and_committed_boot_never_saves(self):
        rc, trace, _ = self.invoke(1, failure="save")
        self.assertNotEqual(rc, 0)
        self.assertNotIn("NAND", trace)
        rc, trace, error = self.invoke(1, stage="")
        self.assertEqual(rc, 0, error)
        self.assertNotIn("SAVE", trace)


if __name__ == "__main__":
    unittest.main()
