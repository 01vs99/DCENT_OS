#!/usr/bin/env python3
"""Exercise AM2 FPGA packaging and the actual early-boot receipt helper."""

import gzip
import hashlib
import json
from pathlib import Path
import shutil
import shlex
import sys
import subprocess
import tempfile
import unittest

import prepare_am2_fabric_boot as fabric

PROJECT = Path(__file__).resolve().parents[1]
WORKSPACE = PROJECT.parents[1]
HELPER = PROJECT / "br2_external_dcentos/board/zynq/rootfs-overlay/usr/libexec/dcentos/am2-fabric-identity.sh"


class FabricPackagingTests(unittest.TestCase):
    def test_uboot_hash_pin_materializes_all_expected_digest_bytes(self):
        env = fabric.boot_environment()
        materialized = bytearray(32)
        for command in env["dcent_fpga_hash_pin"].split(" && "):
            _, address, value, count = command.split()
            self.assertEqual(count, "1")
            offset = int(address, 16) - fabric.HASH_ADDRESS
            materialized[offset:offset + 4] = int(value, 16).to_bytes(4, "little")
        self.assertEqual(materialized.hex(), fabric.BITSTREAM_SHA256)
        command = env["bm_load_bitstream"]
        self.assertLess(command.index("cmp.b"), command.index("imxtract"))
        self.assertLess(command.index("imxtract"), command.index("fpga loadb"))
        self.assertIn("setenv verify yes", command)

    def test_modified_payload_never_invokes_mkimage_or_changes_boot_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            donor = root / "bad.gz"
            donor.write_bytes(gzip.compress(b"wrong fabric"))
            uenv = root / "uEnv.txt"
            uenv.write_text("unchanged\n")
            with self.assertRaises(ValueError):
                fabric.prepare(donor, root, uenv, "must-not-be-invoked")
            self.assertEqual(uenv.read_text(), "unchanged\n")

    @unittest.skipUnless(shutil.which("mkimage") and shutil.which("fdtget"), "Linux FIT tools required")
    def test_actual_fit_contains_exact_payload_and_independent_sha256(self):
        donor = WORKSPACE / "tmp/antminer17-armada/bos_s17/system.bit.gz"
        self.assertTrue(donor.is_file(), "exact held donor extraction is required")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            uenv = root / "uEnv.txt"
            uenv.write_text("bm_load_bitstream=old\nbm_set_bootargs=old\nsd_uenvcmd=old\n")
            fit = fabric.prepare(donor, root, uenv, "mkimage")
            raw = (root / "am2-system.bit").read_bytes()
            digest = subprocess.check_output(["fdtget", "-t", "bx", str(fit), "/images/system-bit/hash-1", "value"], text=True)
            decoded = bytes(int(word, 16) for word in digest.split())
            self.assertEqual(decoded, hashlib.sha256(raw).digest())
            self.assertEqual(decoded.hex(), fabric.BITSTREAM_SHA256)
            self.assertEqual(len(raw), fabric.BITSTREAM_SIZE)
            self.assertLessEqual(fit.stat().st_size, 2 * 1024**2, "NAND FPGA partition must hold entire FIT")
            self.assertIn("dcent.fpga_load_completed=${dcent_fpga_load_completed}", uenv.read_text())


@unittest.skipUnless(sys.platform == "linux" and shutil.which("bash"), "Linux shell execution required")
class NandBootEnvironmentTests(unittest.TestCase):
    def invoke(self, slot, *, selected=None, failure=""):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "boot.trace"
            env = fabric.nand_boot_environment(slot, 'echo VENDOR >> "$TRACE"; exit 0')
            env.update(firmware=str(selected or slot), auto_recovery="true")
            assignments = "\n".join(f"{key}={shlex.quote(value)}" for key, value in env.items())
            # Execute generated boot commands with a transparent command adapter.
            # This validates composition/fallback; it is not a U-Boot hardware run.
            script = r'''set -eu
TRACE=$1
FAILURE=$2
setenv() { local key=$1; shift; printf -v "$key" '%s' "$*"; }
run() { local key=$1; eval "${!key}"; }
mw.l() { :; }
nand() { echo "NAND $*" >> "$TRACE"; [ "$FAILURE" != nand ]; }
fdt() {
  case "${3:-}" in
    dcent_hash_algo) dcent_hash_algo=sha256 ;;
    dcent_hash_size) dcent_hash_size=0x20 ;;
    dcent_hash_addr) dcent_hash_addr=0x011ffff0 ;;
  esac
}
itest() { [ "$1" = "$3" ]; }
cmp.b() { [ "$FAILURE" != digest ]; }
imxtract() { echo "EXTRACT $*" >> "$TRACE"; filesize=0x1fcc13; [ "$FAILURE" != payload ]; }
fpga() { echo "FPGA $*" >> "$TRACE"; [ "$FAILURE" != fpga ]; }
ubi() { echo "UBI $*" >> "$TRACE"; [ "$FAILURE" != kernel ]; }
bootm() { echo "BOOT $bootargs" >> "$TRACE"; exit 0; }
saveenv() { echo "SAVE firmware=$firmware upgrade_stage=$upgrade_stage first_boot=$first_boot" >> "$TRACE"; }
''' + assignments + "\nrun nandboot\n"
            result = subprocess.run(["bash", "-c", script, "boot-model", str(trace), failure], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return trace.read_text()

    def test_both_slots_program_exact_pair_before_kernel_and_completion(self):
        for slot in (1, 2):
            with self.subTest(slot=slot):
                trace = self.invoke(slot)
                self.assertIn(f"NAND read 0x01000000 fpga{slot} 0x200000", trace)
                self.assertIn("EXTRACT 0x01000000 system-bit 0x01800000", trace)
                self.assertIn("FPGA loadb 0 0x01800000 0x1fcc13", trace)
                self.assertLess(trace.index("FPGA"), trace.index("UBI"))
                self.assertIn(f"ubi.mtd={6 + slot}", trace)
                self.assertIn("dcent.fpga_load_completed=1", trace)
                self.assertIn(fabric.BITSTREAM_SHA256, trace)
                self.assertNotIn("VENDOR", trace)
                self.assertNotIn("SAVE", trace)

    def test_load_failure_restores_previous_boot_without_native_completion(self):
        for slot in (1, 2):
            for failure in ("nand", "digest", "payload", "fpga", "kernel"):
                with self.subTest(slot=slot, failure=failure):
                    trace = self.invoke(slot, failure=failure)
                    self.assertIn(f"SAVE firmware={3 - slot} upgrade_stage= first_boot=", trace)
                    self.assertIn("VENDOR", trace)
                    self.assertNotIn("BOOT ", trace)

    def test_rollback_selects_preserved_vendor_without_touching_fpga(self):
        self.assertEqual(self.invoke(2, selected=1), "VENDOR\n")

    def test_invalid_slot_or_nested_transition_refuses(self):
        for slot in (0, 3, True, "2"):
            with self.assertRaises(ValueError):
                fabric.nand_boot_environment(slot, "run vendor")
        for old in ("", "run dcent_nandboot", "run vendor\nsaveenv"):
            with self.assertRaises(ValueError):
                fabric.nand_boot_environment(2, old)


@unittest.skipUnless(sys.platform == "linux" and shutil.which("sh"), "Linux POSIX shell required")
class BootObserverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.paths = [self.root / name for name in ("board", "cmdline", "boot", "prog_done", "fclk_export", "rate", "run")]
        values = ["am2-s17p", f"console=ttyPS0 dcent.fpga_load_completed=1 dcent.fpga_sha256={fabric.BITSTREAM_SHA256}", "12345678-1234-1234-1234-123456789abc", "1", "", "100000000"]
        for path, value in zip(self.paths, values):
            path.write_text(value + "\n")

    def invoke(self):
        return subprocess.run(["sh", "-c", '. "$1"; shift; dcent_am2_fabric_identity "$@"', "observer", str(HELPER), *map(str, self.paths)], capture_output=True, text=True)

    def test_success_records_current_boot_and_actual_programming(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads((self.paths[-1] / "s17-fabric.json").read_text())
        self.assertEqual(receipt, {"schema": 1, "boot_id": self.paths[2].read_text().strip(), "bitstream_sha256": fabric.BITSTREAM_SHA256, "load_completed": True, "prog_done": 1})
        self.assertEqual(self.paths[4].read_text(), "\n")
        self.assertEqual(self.paths[5].read_text(), "100000000\n")

    def test_failed_or_ambiguous_boot_removes_old_receipt(self):
        original = self.paths[1].read_text()
        for command_line in [original.replace("completed=1", "completed=0"), original.replace(fabric.BITSTREAM_SHA256, "0" * 64), original + " dcent.fpga_load_completed=1", "console=ttyPS0"]:
            with self.subTest(command_line=command_line):
                self.paths[-1].mkdir(exist_ok=True)
                stale = self.paths[-1] / "s17-fabric.json"
                stale.write_text("stale")
                self.paths[1].write_text(command_line)
                self.assertNotEqual(self.invoke().returncode, 0)
                self.assertFalse(stale.exists())

    def test_missing_hardware_program_done_refuses_receipt(self):
        self.paths[3].write_text("0\n")
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertFalse((self.paths[-1] / "s17-fabric.json").exists())

    def test_bm1398_receipt_uses_its_distinct_runtime_path(self):
        self.paths[0].write_text("am2-s19pro\n")
        self.assertEqual(self.invoke().returncode, 0)
        self.assertTrue((self.paths[-1] / "bm1398-fabric.json").is_file())
        self.assertFalse((self.paths[-1] / "s17-fabric.json").exists())


if __name__ == "__main__":
    unittest.main()
