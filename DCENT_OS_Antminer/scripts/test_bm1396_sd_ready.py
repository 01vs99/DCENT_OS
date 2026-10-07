"""Read-only R06 SD startup gate with real shell and current-boot markers."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

OVERLAY = Path(__file__).resolve().parents[1] / "br2_external_dcentos/board/zynq/bm1396/rootfs-overlay"
UUID = "cc62df83-522e-43c1-89ac-ed13c4edc30a"
BOOT = "12345678-1234-1234-1234-123456789abc"


@unittest.skipUnless(shutil.which("sh"), "POSIX shell unavailable")
class ReadyTests(unittest.TestCase):
    def fixture(self, root, target):
        identity, runtime = root / "identity", root / "runtime"
        identity.mkdir()
        runtime.mkdir()
        for path, value in ((identity / "board_target", target),
                            (identity / "bm1396-data-uuid", UUID),
                            (runtime / "bm1396-sd-data-ready", UUID),
                            (runtime / "bm1396-boot-cut-ready", BOOT),
                            (runtime / "bm1396-boot-cut.json", "{}"),
                            (runtime / "bm1396-fabric.json", "{}"),
                            (root / "boot", BOOT)):
            path.write_text(value + "\n")
        # JSON existence/size is a diagnostic prerequisite. A successful actual
        # boot-cut command creates the separate current-boot shell marker.
        return ["sh", "-c", '. "$1"; dcent_bm1396_sd_ready "$2" "$3" "$4"',
                "fixture", str(OVERLAY / "usr/libexec/dcentos/bm1396-sd-ready.sh"),
                str(identity), str(runtime), str(root / "boot")]

    def test_both_targets_require_their_own_current_boot_and_data_markers(self):
        for target in ("am2-s17e", "am2-t17e"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                command = self.fixture(root, target)
                self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
                for name, value in (("identity/board_target", "am1-s15"),
                                    ("runtime/bm1396-boot-cut-ready", UUID),
                                    ("runtime/bm1396-sd-data-ready", BOOT),
                                    ("runtime/bm1396-fabric.json", "x" * 1025),
                                    ("boot", "malformed")):
                    path = root / name
                    saved = path.read_bytes()
                    path.write_text(value)
                    self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
                    path.write_bytes(saved)

    def test_missing_or_symlinked_observation_does_not_open_the_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            command = self.fixture(root, "am2-s17e")
            path = root / "runtime/bm1396-boot-cut.json"
            path.unlink()
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            path.symlink_to(root / "runtime/bm1396-fabric.json")
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)


if __name__ == "__main__":
    unittest.main()
