"""Exercise the real signed package -> mkimage SD-FIT path, entirely offline."""
from pathlib import Path
import hashlib
import subprocess
import tempfile
import unittest

from classic_aml_entry import prepare_sd_fit as sd
from test_classic_aml_signed_entry import rootfs_entries
import test_amlogic_seven_mtd_package as fixture


class ClassicSdFitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        def retain(package, public, donor, key):
            cls.package = package.read_bytes()
            cls.public = public.read_bytes()
            cls.dtb = (donor / 'devicetree.dtb').read_bytes()
        fixture.SevenMtdPackageTest().build(sd.TARGET, 's19jpro',
            rootfs=fixture.cpio_fixture(rootfs_entries()), inspect=retain)

    def test_current_signed_package_builds_seven_mtd_sd_fit(self):
        with tempfile.TemporaryDirectory(prefix='dcent-l12-sd-') as directory:
            root = Path(directory)
            inputs = [root / name for name in ('release.tar', 'trusted.pub', 'donor.dtb')]
            for path, raw in zip(inputs, (self.package, self.public, self.dtb)):
                path.write_bytes(raw)
            output = root / 'dcentos'
            sd.prepare(*inputs, output)
            files = sd.compose(self.package, self.public, self.dtb)
            fit = (output / 'boot.itb').read_bytes()
            sd.verify_fit(fit, files)
            self.assertEqual((output / 'release.tar').read_bytes(), self.package)
            self.assertTrue((output / 'boot.scr').read_bytes().startswith(bytes.fromhex('27051956')))
            listing = subprocess.run(['mkimage', '-l', str(output / 'boot.itb')],
                                      capture_output=True, text=True, timeout=15)
            self.assertEqual(listing.returncode, 0, listing.stderr)
            self.assertIn('Default Configuration: \'classic\'', listing.stdout)
            self.assertIn(b'nvdata\0', files['final.dtb'])
            self.assertIn(b'config\0', files['final.dtb'])
            tampered = dict(files, Image=b'wrong kernel')
            with self.assertRaisesRegex(ValueError, 'payload differs'):
                sd.verify_fit(fit, tampered)
            with self.assertRaisesRegex(ValueError, 'fresh directory'):
                sd.prepare(*inputs, output)

    def test_unsigned_wrong_key_and_wrong_geometry_are_refused_before_output(self):
        with self.assertRaisesRegex(ValueError, 'DTB'):
            sd.compose(self.package, self.public, b'six-MTD S19k DTB')
        with self.assertRaises(ValueError):
            sd.compose(self.package, b'0' * 64, self.dtb)
        with self.assertRaises(ValueError):
            sd.compose(b'unsigned image', self.public, self.dtb)

    def test_sd_boot_only_after_load_size_and_digest_success(self):
        expected = hashlib.sha256(b'fixture FIT').hexdigest()
        command = sd.boot_command(11, expected).decode()
        # U-Boot's hush syntax is executed in sh with hardware commands modeled.
        # No devices, sockets or child firmware processes are used.
        for load, size, hashing, digest, setting, allowed in (
                (0, 'b', 0, expected, 0, True), (1, 'b', 0, expected, 0, False),
                (0, 'a', 0, expected, 0, False), (0, 'b', 1, expected, 0, False),
                (0, 'b', 0, '0' * 64, 0, False), (0, 'b', 0, expected, 1, False)):
            with self.subTest(load=load, size=size, hashing=hashing, digest=digest):
                shim = f'''fatload() {{ filesize={size}; return {load}; }}
hash() {{ dcent_fit_sha={digest}; return {hashing}; }}
setenv() {{ return {setting}; }}
bootm() {{ echo BOOT_CALLED; }}
'''
                run = subprocess.run(['sh', '-s'], input=shim + command,
                                     text=True, capture_output=True, timeout=15)
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertEqual('BOOT_CALLED' in run.stdout, allowed)
        for forbidden in ('nandwrite', 'flash_erase', 'saveenv', 'fw_setenv', 'gpio', 'i2c'):
            self.assertNotIn(forbidden, command)


if __name__ == '__main__':
    unittest.main()
