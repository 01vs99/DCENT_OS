"""Offline native SD composition, boot rejoin and startup-marker behavior."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import prepare_bm1391_sd_image as image

ROOT_UUID = "d362a466-39dc-4208-b7fd-203de7d7ad4a"
DATA_UUID = "cc62df83-522e-43c1-89ac-ed13c4edc30a"
BOOT_ID = "12345678-1234-1234-1234-123456789abc"
DONOR = Path(__file__).resolve().parents[3] / "tmp/bm1391-evidence/s15-msk-sd/bin"


def fixture(directory):
    root, binaries = directory / "root", directory / "binaries"
    for relative in ("etc/dcentos", "etc/init.d", "usr/bin", "usr/local/bin", "sbin", "data", "root"):
        (root / relative).mkdir(parents=True, exist_ok=True)
    (root / "etc/dcentos/board_target").write_text("am2-s19j\n")
    (root / "etc/dcentos/platform").write_text("zynq-bm3-am2\n")
    # Exact audited base has a regular older binary here, which S82 selects.
    (root / "usr/local/bin/dcentrald").write_bytes(b"old AM2 supervisor binary")
    for name in ("S10modules", "S11modules", "S15pic_boot", "S37board_setup", "S99upgrade", "S99verify"):
        (root / "etc/init.d" / name).write_text("foreign hardware script\n")
    binaries.mkdir()
    # Header-only fixtures establish producer input typing; they are never
    # invoked and do not constitute current ARM runtime build evidence.
    elf = bytearray(64)
    elf[:6] = b"\x7fELF\x01\x01"
    struct.pack_into("<H", elf, 18, 40)
    for name in ("dcentrald", "dcentos-init", "dcentos-discovery"):
        (binaries / name).write_bytes(elf)
    return root, binaries


class ImageTests(unittest.TestCase):
    def test_exact_two_roots_use_own_fabric_boot_cut_and_sd_storage(self):
        for target, count in (("am1-s15", 72), ("am1-t15", 60)):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temp:
                root, binaries = fixture(Path(temp))
                image.prepare_root(root, target, binaries, ROOT_UUID, image.DATA_UUIDS[target], image.ADMITTED_AM2_BASE_SHA256)
                self.assertEqual((root / "etc/dcentos/board_target").read_text().strip(), target)
                self.assertEqual((root / "etc/dcentos/platform").read_text().strip(), "zynq-bm1391-stock")
                self.assertEqual((root / "etc/dcentos/bm1391-bitstream.sha256").read_text().strip(), image.BITSTREAM_SHA256)
                for name in ("S10modules", "S11modules", "S15pic_boot", "S37board_setup", "S99upgrade", "S99verify"):
                    self.assertFalse((root / "etc/init.d" / name).exists())
                config = (root / "etc/dcentrald.toml").read_text()
                for setting in (f'serial_chip_count = {count}', 'frequency_mhz = 100', 'voltage_mv = 18000', 'enabled = false'):
                    self.assertIn(setting, config)
                initial = (root / "etc/init.d/S12fpga_identity").read_text()
                self.assertLess(initial.index('dcent_bm1391_fabric_identity'), initial.index('--bm1391-boot-cut-only'))
                self.assertLess(initial.index('--bm1391-boot-cut-only'), initial.index('cat /proc/sys/kernel/random/boot_id'))
                supervisor = (root / "etc/init.d/S82dcentrald").read_text()
                self.assertIn('dcent_bm1391_sd_ready', supervisor)
                # Execute the actual produced selector against an executable
                # preserved data override. It must still select the baked binary.
                selector = supervisor.split('select_dcentrald_paths() {', 1)[1].split('\n}', 1)[0]
                data = root / 'data'
                (data / 'dcentrald').write_text('#!/bin/sh\nexit 99\n')
                (data / 'dcentrald').chmod(0o755)
                (data / 'dcentrald.toml').write_text('preserved operator config\n')
                command = ['sh', '-c', 'select_dcentrald_paths() {' + selector.replace('/data/', str(data)+'/')
                    + '\n}\nselect_dcentrald_paths\nprintf "%s\\n%s\\n" "$DAEMON" "$CONFIG"']
                selected = subprocess.run(command, capture_output=True, text=True, check=True).stdout.splitlines()
                self.assertEqual(selected, ['/usr/local/bin/dcentrald', str(data / 'dcentrald.toml')])
                fallback = supervisor.split('fan_safety_override() {', 1)[1]
                self.assertLess(fallback.index('am1-s15|am1-t15'), fallback.index('FAN_BASE + 0x10'))
                self.assertTrue((root / "etc/init.d/S46bm1391_ssh").is_file())
                self.assertEqual(len(json.loads((root / "etc/dcentos/bm1391-runtime-inputs.json").read_text())), 3)
                self.assertTrue((root / "usr/local/bin/dcentrald").samefile(root / "usr/bin/dcentrald"))
                self.assertEqual((root / "usr/local/bin/dcentrald").read_bytes(), (binaries / "dcentrald").read_bytes())
                for name, data in image.current_dashboard().items():
                    self.assertEqual((root / "usr/share/dcentos-dashboard" / name).read_bytes(), data)

    def test_mismatched_current_dashboard_fails_before_native_identity_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            root, binaries = fixture(directory)
            dashboard = directory / 'dashboard'
            dashboard.mkdir()
            for name, data in image.current_dashboard().items():
                (dashboard / name).write_bytes(data)
            (dashboard / 'index.html.sha256').write_text('0'*64+'\n')
            with patch.object(image, 'DASHBOARD', dashboard), self.assertRaisesRegex(ValueError, 'do not match'):
                image.prepare_root(root, 'am1-s15', binaries, ROOT_UUID,
                    image.DATA_UUIDS['am1-s15'], image.ADMITTED_AM2_BASE_SHA256)
            self.assertEqual((root / 'etc/dcentos/board_target').read_text(), 'am2-s19j\n')

    def test_unlisted_base_binary_and_foreign_target_fail_before_identity_changes(self):
        for defect in ('base', 'binary', 'target'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as temp:
                root, binaries = fixture(Path(temp))
                if defect == 'binary':
                    (binaries / 'dcentrald').write_bytes(b'old or foreign executable')
                with self.assertRaises(ValueError):
                    image.prepare_root(root, 'am1-s9se' if defect == 'target' else 'am1-s15',
                        binaries, ROOT_UUID, image.DATA_UUIDS['am1-s15'], '0'*64 if defect == 'base' else image.ADMITTED_AM2_BASE_SHA256)
                self.assertEqual((root / 'etc/dcentos/board_target').read_text(), 'am2-s19j\n')

    def test_final_boot_rejoin_refuses_target_swap_and_rehashed_dma_corruption(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            image.boot_source.prepare_boot(output, DONOR, 'am1-s15')
            image.verify_boot_files(output, 'am1-s15')
            with self.assertRaises(ValueError):
                image.verify_boot_files(output, 'am1-t15')
            dtb = output / 'devicetree.dtb'
            subprocess.run(['fdtput', '-t', 'x', str(dtb), image.boot_source.DMA_NODE, 'reg', 'f000000', '200000'], check=True)
            # Even a matching updated file digest cannot bless a weakened DMA
            # reservation: assembly independently compares native properties.
            receipt = json.loads((output / 'boot-components.json').read_text())
            receipt['files']['devicetree.dtb'] = {'bytes':dtb.stat().st_size, 'sha256':hashlib.sha256(dtb.read_bytes()).hexdigest()}
            (output / 'boot-components.json').write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, 'DTB differs'):
                image.verify_boot_files(output, 'am1-s15')

    def test_actual_shell_start_gate_rejects_stale_missing_foreign_and_oversized_markers(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            identity, runtime = root / 'identity', root / 'runtime'
            identity.mkdir()
            runtime.mkdir()
            (identity / 'board_target').write_text('am1-s15\n')
            (identity / 'bm1391-data-uuid').write_text(DATA_UUID+'\n')
            (runtime / 'bm1391-sd-data-ready').write_text(DATA_UUID+'\n')
            (runtime / 'bm1391-boot-cut-ready').write_text(BOOT_ID+'\n')
            (runtime / 'bm1391-boot-cut.json').write_text('{}\n')
            (runtime / 'bm1391-fabric.json').write_text('{}\n')
            (root / 'boot').write_text(BOOT_ID+'\n')
            helper = image.OVERLAY / 'usr/libexec/dcentos/bm1391-sd-ready.sh'
            command = ['sh', '-c', '. "$1"; dcent_bm1391_sd_ready "$2" "$3" "$4"', 'fixture', str(helper), str(identity), str(runtime), str(root/'boot')]
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            for path, value in ((runtime/'bm1391-boot-cut-ready', ROOT_UUID+'\n'),
                                (runtime/'bm1391-sd-data-ready', ROOT_UUID+'\n'),
                                (identity/'board_target', 'am1-s9se\n'),
                                (runtime/'bm1391-fabric.json', 'x'*1025)):
                saved = path.read_bytes()
                path.write_text(value)
                self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
                path.write_bytes(saved)
            (runtime/'bm1391-boot-cut-ready').unlink()
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)


if __name__ == '__main__':
    unittest.main()
