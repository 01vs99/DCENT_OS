"""Exercise real FIT/DTB tools and the image's BusyBox receipt producer."""
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

import prepare_bm1396_sd_boot as IMAGE

WORKSPACE = Path(__file__).resolve().parents[3]
DONOR = WORKSPACE / "tmp/bm1396-exact-signed-root-re-20260810/s17e/inner"
HELPER = Path(__file__).resolve().parents[1] / "br2_external_dcentos/board/zynq/bm1396/rootfs-overlay/usr/libexec/dcentos/bm1396-fabric-identity.sh"
BOOT_ID = "12345678-1234-1234-1234-123456789abc"


class BootComponents(unittest.TestCase):
    def test_both_real_boot_packages_preserve_inputs_and_reserve_dma_with_ps_watchdog(self):
        original = IMAGE.fdt_properties((DONOR / "devicetree.dtb").read_bytes())
        with tempfile.TemporaryDirectory() as temporary:
            for target in IMAGE.TARGETS:
                output = Path(temporary) / target
                output.mkdir()
                manifest = IMAGE.prepare_boot(output, DONOR, target)
                self.assertEqual(manifest["board_target"], target)
                for name in ("BOOT.bin", "uImage"):
                    staged = output / ("BOOT.BIN" if name == "BOOT.bin" else name)
                    self.assertEqual(staged.read_bytes(), (DONOR / name).read_bytes())
                changed = IMAGE.fdt_properties((output / "devicetree.dtb").read_bytes())
                self.assertEqual({key: changed[key] for key in original}, original)
                added = changed.keys() - original.keys()
                self.assertEqual(len(added), 13)
                self.assertEqual({path for path, _ in added}, {
                    "/amba@0/watchdog@f8005000", "/reserved-memory", IMAGE.DMA_NODE})
                self.assertEqual(changed[("/amba@0/watchdog@f8005000", "reset-on-timeout")], b"")
                self.assertEqual(changed[(IMAGE.DMA_NODE, "reg")], struct.pack(">II", 0x0f000000, 0x01000000))
                self.assertEqual(changed[(IMAGE.DMA_NODE, "no-map")], b"")
                self.assertEqual(changed[("/reserved-memory", "ranges")], b"")
                self.assertEqual(manifest["dma_reservation"]["physical_base"], 0x0f000000)
                fit = IMAGE.fdt_properties((output / "bm1396-fabric.itb").read_bytes())
                payload = fit[("/images/bm1396-raw", "data")]
                self.assertEqual(len(payload), IMAGE.BITSTREAM_SIZE)
                self.assertEqual(hashlib.sha256(payload).hexdigest(), IMAGE.BITSTREAM_SHA256)
                self.assertEqual(payload, (DONOR / "BOOT.bin").read_bytes()[104256:2188000])
                subprocess.run(["dumpimage", "-l", str(output / "bm1396-fabric.itb")], check=True, capture_output=True)
                self.assertEqual(json.loads((output / "boot-components.json").read_text()), manifest)
                # A completed staging directory cannot be reused or overwritten.
                with self.assertRaisesRegex(ValueError, "empty regular"):
                    IMAGE.prepare_boot(output, DONOR, target)
                repeated = Path(temporary) / (target + "-repeat")
                repeated.mkdir()
                IMAGE.prepare_boot(repeated, DONOR, target)
                self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()},
                                 {p.name: p.read_bytes() for p in repeated.iterdir()})

    def test_dma_reservation_rejects_conflicting_or_different_memory_geometry(self):
        with tempfile.TemporaryDirectory() as temporary:
            dtb = Path(temporary) / "test.dtb"
            for kind in ("existing", "different-size"):
                dtb.write_bytes((DONOR / "devicetree.dtb").read_bytes())
                if kind == "existing":
                    subprocess.run(["fdtput", "-c", str(dtb), "/reserved-memory"], check=True)
                    subprocess.run(["fdtput", "-t", "x", str(dtb), "/reserved-memory", "#address-cells", "1"], check=True)
                else:
                    subprocess.run(["fdtput", "-t", "x", str(dtb), "/memory@0", "reg", "0", "20000000"], check=True)
                before = dtb.read_bytes()
                with self.assertRaises(ValueError):
                    IMAGE.reserve_native_dma(dtb)
                self.assertEqual(dtb.read_bytes(), before)

    def test_s15_boot_with_different_fpga_is_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            donor = Path(temporary) / "donor"
            output = Path(temporary) / "out"
            donor.mkdir()
            output.mkdir()
            for name in IMAGE.PINS:
                shutil.copyfile(DONOR / name, donor / name)
            shutil.copyfile(WORKSPACE / "tmp/bm1391-evidence/s15-msk-sd/bin/BOOT.bin", donor / "BOOT.bin")
            with self.assertRaisesRegex(ValueError, "donor SHA256 mismatch"):
                IMAGE.prepare_boot(output, donor, "am2-s17e")
            self.assertEqual(list(output.iterdir()), [])

    def test_kernel_header_and_payload_corruption_are_rejected(self):
        kernel = (DONOR / "uImage").read_bytes()
        IMAGE.verify_kernel(kernel)
        for offset in (0, 4, 16, 1000, len(kernel) - 1):
            damaged = bytearray(kernel)
            damaged[offset] ^= 1
            with self.assertRaisesRegex(ValueError, "legacy header/CRC"):
                IMAGE.verify_kernel(damaged)


class FabricIdentity(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.files = [self.root / name for name in ("board", "pin", "cmdline", "boot_id", "prog_done")]
        self.output = self.root / "run"
        self.output.mkdir()
        self.reset("am2-s17e")

    def reset(self, target):
        # Exercise the actual generated bootargs, expanded as U-Boot would
        # after a successful load. This does not model a physical U-Boot run.
        arguments = IMAGE.boot_environment(target)["dcent_bootargs"]
        arguments = arguments.removeprefix("setenv bootargs ").replace("${dcent_bm1396_load_completed}", "1")
        for path, value in zip(self.files, (target, IMAGE.BITSTREAM_SHA256, arguments, BOOT_ID, "1")):
            if path.is_symlink():
                path.unlink()
            path.write_text(value + "\n")

    def invoke(self):
        command = ["busybox", "sh", "-c", '. "$1"; shift; dcent_bm1396_fabric_identity "$@"',
                   "test", str(HELPER), *map(str, self.files), str(self.output)]
        return subprocess.run(command, capture_output=True, text=True)

    def test_both_targets_produce_exact_native_receipt(self):
        for target in IMAGE.TARGETS:
            self.reset(target)
            result = self.invoke()
            self.assertEqual(result.returncode, 0, result.stderr)
            path = self.output / "bm1396-fabric.json"
            self.assertEqual(json.loads(path.read_text()), {
                "schema": 1, "boot_id": BOOT_ID, "board_target": target,
                "bitstream_sha256": IMAGE.BITSTREAM_SHA256, "load_completed": True, "prog_done": True,
            })
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
            self.assertEqual(len(list(self.output.iterdir())), 1)

    def test_bad_or_ambiguous_observations_remove_stale_receipt(self):
        cases = [(0, "am1-s9se"), (1, "0" * 64), (3, "bad-boot-id"), (4, "0")]
        good = self.files[2].read_text()
        cases += [(2, good.replace("load_completed=1", "load_completed=0")),
                  (2, good.replace(IMAGE.BITSTREAM_SHA256, "f" * 64)),
                  (2, good.replace("target=am2-s17e", "target=am2-t17e"))]
        cases += [(2, good + " " + argument) for argument in (
            "dcent.bm1396_load_completed=1", "dcent.bm1396_sha256=" + IMAGE.BITSTREAM_SHA256,
            "dcent.bm1396_target=am2-s17e")]
        cases += [(2, " ".join(item for item in good.split() if not item.startswith(prefix)))
                  for prefix in ("dcent.bm1396_load_completed=", "dcent.bm1396_sha256=", "dcent.bm1396_target=")]
        for index, value in cases:
            with self.subTest(index=index, value=value):
                self.reset("am2-s17e")
                self.assertEqual(self.invoke().returncode, 0)
                self.files[index].write_text(value)
                self.assertNotEqual(self.invoke().returncode, 0)
                self.assertFalse((self.output / "bm1396-fabric.json").exists())

    def test_symlink_observation_and_output_are_rejected(self):
        for index in range(5):
            self.reset("am2-s17e")
            saved = self.root / "saved"
            saved.write_text(self.files[index].read_text())
            self.files[index].unlink()
            self.files[index].symlink_to(saved)
            self.assertNotEqual(self.invoke().returncode, 0)
        self.reset("am2-s17e")
        self.output.rmdir()
        actual = self.root / "actual"
        actual.mkdir()
        marker = actual / "bm1396-fabric.json"
        marker.write_text("untouched")
        self.output.symlink_to(actual, target_is_directory=True)
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertEqual(marker.read_text(), "untouched")


if __name__ == "__main__":
    unittest.main()
