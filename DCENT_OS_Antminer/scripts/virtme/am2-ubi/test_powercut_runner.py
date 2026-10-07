"""Pure runner/guest correlation checks; no QEMU or character-device writes."""
from copy import deepcopy
import argparse
from pathlib import Path
import shlex
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from nandsim_snapshot import SnapshotError
from powercut_runner import check_events, validate_binding, vm_command, launch
from guest_powercut import verify_transaction


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.schema = SimpleNamespace(kernel_sha256="1"*64, module_sha256="2"*64,
                                      base_btf_sha256="3"*64, module_btf_sha256="4"*64, symbol_offset=24)
        self.binding = {"token": "5"*64, "kernel_release": "5.15.0-181-generic",
                        "kernel_sha256": "1"*64, "module_sha256": "2"*64,
                        "base_btf_sha256": "3"*64, "module_btf_sha256": "4"*64,
                        "symbol_address": 0xffff888000000018, "bss_address": 0xffff888000000000,
                        "bad_blocks": [2047]}

    def test_symbol_belongs_to_exact_loaded_module_and_btf(self):
        validate_binding(self.schema, self.binding, "5"*64)
        for field, changed in (("symbol_address", 0xffff888000000028), ("token", "6"*64),
                               ("base_btf_sha256", "7"*64), ("module_sha256", "8"*64),
                               ("bad_blocks", [2048]), ("bad_blocks", [2, 1])):
            with self.subTest(field=field):
                binding = deepcopy(self.binding)
                binding[field] = changed
                with self.assertRaises(SnapshotError):
                    validate_binding(self.schema, binding, "5"*64)

    def test_unknown_or_missing_binding_fields_refuse(self):
        for value in ({**self.binding, "authority": "forged"}, {key: val for key, val in self.binding.items() if key != "token"}):
            with self.assertRaises(SnapshotError):
                validate_binding(self.schema, value, "5"*64)

    def test_boundary_census_must_be_bounded_and_explicit(self):
        event = {"operation": "fw_setenv:syscall-18", "writes": 1, "roles": ["device:mtd4"]}
        check_events([event])
        for bad in ([], [event]*513, [{**event, "writes": True}], [{"result": "pass"}]):
            with self.assertRaises(SnapshotError):
                check_events(bad)

    def test_transaction_verification_cannot_open_host_paths_before_guest_admission(self):
        with mock.patch("guest_powercut.guard", side_effect=SnapshotError("not admitted")), \
                mock.patch("guest_powercut.regular") as read:
            with self.assertRaisesRegex(SnapshotError, "not admitted"):
                verify_transaction(SimpleNamespace(token="5"*64))
            read.assert_not_called()

    def test_actual_vm_argv_preserves_leading_qemu_switch_and_socket_paths(self):
        directory = Path("/private fixture/vm")
        args = SimpleNamespace(kernel=Path("/boot/kernel"), bundle=Path("/bundle"),
                               writer=Path("/tools/am2-nand-window"), layout="canonical")
        command = vm_command(args, directory, Path("/private fixture/control"), "5"*64, cut=0)
        self.assertIn("--verbose", command)  # Preserve boot diagnostics on failed launches.
        # Exercise argparse's real leading-dash handling, the failure that
        # previously prevented the owned QEMU process from being launched.
        parser = argparse.ArgumentParser()
        parser.add_argument("--qemu-opts", required=True)
        parser.add_argument("--append", action="append", default=[])
        parsed, _ = parser.parse_known_args(command[1:])
        self.assertEqual(parsed.append, ["nopti", "no5lvl"])
        options = shlex.split(parsed.qemu_opts)
        self.assertEqual(options[:2], ["-qmp", f"unix:{directory}/qmp.sock,server=on,wait=off"])
        self.assertEqual(options[2:4], ["-gdb", f"unix:{directory}/gdb.sock,server=on,wait=off"])
        self.assertEqual(options[4:6], ["-pidfile", str(directory / "qemu.pid")])

    def test_explicit_acceleration_preserves_snapshot_abi_and_never_falls_back(self):
        args = SimpleNamespace(kernel=Path("/boot/kernel"), bundle=Path("/bundle"),
                               writer=Path("/tools/am2-nand-window"), layout="canonical")
        for acceleration in ("tcg", "kvm"):
            args.accel = acceleration
            command = vm_command(args, Path("/private/vm"), Path("/private/control"), "5"*64, cut=0)
            options = shlex.split(next(value.split("=", 1)[1] for value in command if value.startswith("--qemu-opts=")))
            self.assertEqual(options[-2:], ["-machine", "accel=" + acceleration])
            self.assertNotIn("-accel", options)  # vng already uses -machine accel=.
            self.assertEqual("--disable-kvm" in command, acceleration == "tcg")
            self.assertIn("no5lvl", command)
            self.assertIn("--force-9p", command)
            self.assertNotIn("--network", command)
        args.accel = "auto"
        with self.assertRaisesRegex(SnapshotError, "explicit"):
            vm_command(args, Path("/private/vm"), Path("/private/control"), "5"*64, cut=0)

    def test_qemu_exit_during_cleanup_preserves_original_failure(self):
        launcher = mock.Mock()
        launcher.poll.return_value = None
        owner = mock.Mock(pid=123)
        owner.discard.side_effect = FileNotFoundError("process exited")
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch("powercut_runner.vm_command", return_value=["unused"]), \
                mock.patch("powercut_runner.subprocess.Popen", return_value=launcher), \
                mock.patch("powercut_runner.OwnedQemu", return_value=owner):
            with self.assertRaisesRegex(SnapshotError, "original guest failure"):
                with launch(None, Path(temporary) / "vm", Path(temporary), "5"*64):
                    raise SnapshotError("original guest failure")
        launcher.wait.assert_called_once_with(timeout=15)


if __name__ == "__main__":
    unittest.main()
