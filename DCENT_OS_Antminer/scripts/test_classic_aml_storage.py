#!/usr/bin/env python3
"""Offline real storage-owner and startup-script regressions; no device IO."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


PROJECT = Path(__file__).resolve().parents[1]
BOARD = PROJECT / "br2_external_dcentos/board/amlogic"
OVERLAY = BOARD / "am3-s19jpro-aml/rootfs-overlay"
HELPER = OVERLAY / "usr/libexec/dcentos/classic-aml-storage.py"
SPEC = importlib.util.spec_from_file_location("classic_storage", HELPER)
storage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(storage)


class Fixture:
    def __init__(self, root):
        self.root = root
        self.calls = []
        self.mounts = []
        self.owner = storage.Storage(root, self.run)
        for name, value in {
            "/etc/dcentos/board_target": "am3-s19jpro-aml\n",
            "/etc/dcentos-platform": "am3-aml-s19jpro\n",
            "/etc/dcentos/platform": "am3-aml-s19jpro\n",
            "/etc/dcentos/rail_gpio": "437\n",
            "/etc/hostname": "dcentos-s19jpro-aml\n",
            "/proc/sys/kernel/osrelease": "4.9.113\n",
            "/proc/sys/kernel/random/boot_id": "f5921430-47ab-466b-a4a6-a197e090ee51\n",
            "/proc/mtd": "dev:    size   erasesize  name\n" + "".join(
                f'mtd{i}: {size:08x} 00020000 "{name}"\n'
                for i, (name, size) in enumerate(storage.MTD)),
            storage.DT + "/compatible": b"amlogic, axg\0",
            storage.DT + "/amlogic-dt-id": b"axg_s400_v03sbr\0",
            storage.NAND + "/compatible": b"amlogic, aml_mtd_nand\0",
            storage.NAND + "/status": b"okay\0",
            storage.NAND + "/nand_partition/nvdata/offset": b"\xff" * 8,
            storage.NAND + "/nand_partition/nvdata/size": b"\0" * 8,
        }.items():
            self.write(name, value)
        for index, (name, size) in enumerate(storage.MTD):
            prefix = f"/sys/class/mtd/mtd{index}/"
            for key, value in {"name": name, "size": size, "erasesize": 131072,
                               "writesize": 2048, "type": "nand"}.items():
                self.write(prefix + key, str(value))
            if 2 <= index < 6:
                self.write(storage.NAND + "/nand_partition/" + name + "/size",
                           size.to_bytes(8, "big"))
        self.write(storage.BASELINE, "#!/bin/sh\nexit 0\n")
        self.path(storage.BASELINE).chmod(0o755)
        self.ubi()
        self.flush_mounts()
        self.directory("/etc/dropbear")

    def path(self, name):
        return self.root / name.lstrip("/")

    def directory(self, name):
        self.path(name).mkdir(parents=True, exist_ok=True, mode=0o755)

    def write(self, name, value):
        self.directory(str(Path(name).parent))
        self.path(name).write_bytes(value if isinstance(value, bytes) else value.encode())

    def ubi(self):
        for prefix, values in {
            "/sys/class/ubi/ubi0/": {"mtd_num": 6, "volumes_count": 1, "ro_mode": 0,
                                   "min_io_size": 2048, "eraseblock_size": 126976},
            "/sys/class/ubi/ubi0_0/": {"name": "nvdada_log", "type": "dynamic",
                                     "corrupted": 0, "upd_marker": 0,
                                     "usable_eb_size": 126976, "reserved_ebs": 1424},
        }.items():
            for key, value in values.items():
                self.write(prefix + key, str(value))

    def flush_mounts(self):
        self.write("/proc/self/mountinfo", "\n".join(self.mounts) + "\n")

    def mount(self, target, root="/", filesystem="ubifs", source="ubi0_0", options="rw,nosuid,nodev,noexec"):
        self.mounts.append(f"{40 + len(self.mounts)} 1 0:22 {root} {target} {options} - {filesystem} {source} rw")
        self.flush_mounts()

    def run(self, argv):
        self.calls.append(argv)
        if argv == [storage.BASELINE, "start"]:
            pass  # Offline stand-in; actual S37 behavior has its own fixtures.
        elif argv[0] == "/usr/sbin/ubiattach":
            self.ubi()
        elif argv[:2] == ["/bin/mount", "--bind"]:
            _, _, source, target = argv
            if target == "/data":
                # Offline namespace emulation only. No actual host mount.
                shutil.copytree(self.path(source), self.path(target), dirs_exist_ok=True, symlinks=True)
                self.mount(target, storage.DATA_ROOT)
            elif target == "/etc/dropbear":
                self.mount(target, storage.DATA_ROOT + "/keys/dropbear")
            else:
                raise AssertionError(argv)
        elif argv[:3] == ["/bin/mount", "-t", "ubifs"]:
            self.mount(storage.VOLUME)
        elif argv[:2] == ["/bin/mount", "-t"]:
            self.mount(argv[-1], filesystem=argv[2], source=argv[-2], options="rw," + argv[4])
        elif argv[:3] == ["/bin/mount", "-o", "remount,bind,rw,nosuid,nodev,noexec"]:
            pass
        elif argv == ["/sbin/ip", "link", "set", "lo", "up"]:
            pass
        elif argv == ["/bin/hostname", "dcentos-s19jpro-aml"]:
            pass
        else:
            raise AssertionError(argv)


class ExistingStorage(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="classic-storage-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Fixture(Path(self.temporary.name))

    def test_early_baseline_precedes_storage_geometry_failure(self):
        faults = {
            storage.NAND + "/compatible": b"foreign\0",
            "/proc/mtd": "no supported partitions\n",
            "/sys/class/mtd/mtd6/size": "1",
            "/sys/class/ubi/ubi0_0/corrupted": "1",
        }
        for name, value in faults.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                f = Fixture(Path(temporary))
                f.write(name, value)
                real_identity = f.owner.identity
                def geometry_after_baseline():
                    self.assertIn([storage.BASELINE, "start"], f.calls)
                    real_identity()
                with patch.object(f.owner, "identity", side_effect=geometry_after_baseline):
                    with self.assertRaises(storage.Refused):
                        f.owner.early()
                self.assertEqual([call[-1] for call in f.calls[:3]], ["/dev", "/run", "start"])
                self.assertFalse(any(call[0] == "/usr/sbin/ubiattach"
                                     or "ubifs" in call or "--bind" in call for call in f.calls))
                self.assertFalse(f.path(storage.READY).exists())

    def test_early_baseline_failure_prevents_all_storage_checks_and_mounts(self):
        f = self.fixture
        def failed_baseline(argv):
            f.run(argv)
            if argv[0] == storage.BASELINE:
                raise subprocess.CalledProcessError(1, argv)
        f.owner.runner = failed_baseline
        with patch.object(f.owner, "identity", side_effect=AssertionError("storage checked before baseline")):
            with self.assertRaises(subprocess.CalledProcessError):
                f.owner.early()
        self.assertEqual([call[-1] for call in f.calls], ["/dev", "/run", "start"])
        self.assertFalse(f.path(storage.READY).exists())

    def test_early_controller_mismatch_refuses_before_baseline_or_mount(self):
        for name, value in {
            "/etc/dcentos/board_target": "am3-s19jproa",
            "/etc/dcentos/platform": "am3-aml-s19jproa",
            "/etc/dcentos/rail_gpio": "438",
            storage.DT + "/amlogic-dt-id": b"foreign\0",
        }.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                f = Fixture(Path(temporary))
                f.write(name, value)
                with self.assertRaises(storage.Refused):
                    f.owner.early()
                self.assertEqual(f.calls, [])

    def test_early_cold_ramdisk_replaces_pid1_dev_then_baseline_then_storage(self):
        f = self.fixture
        f.mount("/dev", filesystem="tmpfs", source="tmpfs", options="rw")
        f.owner.early()
        f.owner.check()
        self.assertEqual([call[-1] for call in f.calls[:3]], ["/dev", "/run", "start"])
        self.assertEqual(sum(call == [storage.BASELINE, "start"] for call in f.calls), 1)
        baseline = f.calls.index([storage.BASELINE, "start"])
        self.assertTrue(all(index > baseline for index, call in enumerate(f.calls)
                            if "ubifs" in call or "--bind" in call))
        self.assertEqual(len(f.owner.at("/dev")), 2)

    def test_exact_existing_volume_persists_isolated_namespace_and_rechecks_boot(self):
        f = self.fixture
        f.write(storage.VOLUME + "/anthillos/data/keep", "third-party data remains")
        f.owner.start_storage()
        f.owner.check()
        self.assertEqual(f.path(storage.VOLUME + "/anthillos/data/keep").read_text(), "third-party data remains")
        self.assertEqual(len(f.calls), 5)
        self.assertEqual(f.calls[0], ["/bin/mount", "-t", "ubifs", "-o",
                                    "rw,nosuid,nodev,noexec", "ubi0_0", storage.VOLUME])
        self.assertEqual(f.path(storage.READY).stat().st_mode & 0o777, 0o600)
        self.assertEqual(f.path("/data/dcent").stat().st_mode & 0o777, 0o700)
        f.write("/proc/sys/kernel/random/boot_id", "another-boot")
        with self.assertRaisesRegex(storage.Refused, "stale"):
            f.owner.check()

    def test_identity_and_geometry_faults_precede_every_mount(self):
        changes = {
            "/etc/dcentos/board_target": "am3-s19jproa",
            "/proc/sys/kernel/osrelease": "4.9.114",
            storage.DT + "/compatible": b"amlogic, other\0",
            storage.NAND + "/nand_partition/nvdata/offset": b"\0" * 8,
            "/proc/mtd": 'dev: size erasesize name\nmtd6: 0b900000 00020000 "system"\n',
            "/sys/class/mtd/mtd6/name": "overlay",
            "/sys/class/mtd/mtd6/size": "194117631",
            "/sys/class/mtd/mtd6/erasesize": "65536",
            "/sys/class/mtd/mtd6/writesize": "4096",
        }
        for path, value in changes.items():
            with self.subTest(path=path), tempfile.TemporaryDirectory() as temp:
                f = Fixture(Path(temp))
                f.write(path, value)
                with self.assertRaises(storage.Refused):
                    f.owner.start_storage()
                self.assertEqual(f.calls, [])

    def test_existing_volume_faults_never_repair_or_mount(self):
        for key, value in {"ubi0/mtd_num": "5", "ubi0/volumes_count": "2", "ubi0/ro_mode": "1",
                           "ubi0_0/name": "rootfs_data", "ubi0_0/type": "static",
                           "ubi0_0/corrupted": "1", "ubi0_0/upd_marker": "1",
                           "ubi0_0/reserved_ebs": "999999"}.items():
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temp:
                f = Fixture(Path(temp))
                f.write("/sys/class/ubi/" + key, value)
                with self.assertRaises(storage.Refused):
                    f.owner.start_storage()
                self.assertEqual(f.calls, [])

    def test_attach_uses_only_exact_existing_mtd_and_does_not_create_volume(self):
        f = self.fixture
        shutil.rmtree(f.path("/sys/class/ubi/ubi0"))
        shutil.rmtree(f.path("/sys/class/ubi/ubi0_0"))
        with patch.object(f.owner, "character") as character:
            f.owner.start_storage()
        self.assertEqual(character.call_count, 2)
        self.assertEqual(f.calls[0], ["/usr/sbin/ubiattach", "/dev/ubi_ctrl", "-d", "0", "-m", "6"])
        self.assertEqual(len(f.calls), 6)

    def test_foreign_attach_and_mount_are_not_adopted(self):
        f = self.fixture
        shutil.rmtree(f.path("/sys/class/ubi/ubi0"))
        f.write("/sys/class/ubi/ubi2/mtd_num", "6")
        with self.assertRaisesRegex(storage.Refused, "different UBI"):
            f.owner.start_storage()
        self.assertEqual(f.calls, [])
        f.ubi()
        f.mount("/foreign")
        with self.assertRaisesRegex(storage.Refused, "another owner"):
            f.owner.start_storage()
        self.assertEqual(f.calls, [])

    def test_symlink_and_writable_namespace_rejected_without_bind(self):
        for mode in ("symlink", 0o777, 0o775):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                f = Fixture(Path(temp))
                f.directory(storage.VOLUME)
                namespace = f.path(storage.VOLUME + "/dcentos")
                if mode == "symlink":
                    namespace.symlink_to(f.path("/etc"))
                else:
                    namespace.mkdir()
                    namespace.chmod(mode)
                with self.assertRaisesRegex(storage.Refused, "unsafe directory"):
                    f.owner.start_storage()
                self.assertEqual(len(f.calls), 1)  # Volume mounted; no data mutation or bind.
                self.assertFalse(f.path(storage.READY).exists())

    def test_failure_at_each_mount_command_publishes_no_readiness(self):
        for position in range(5):
            with self.subTest(position=position), tempfile.TemporaryDirectory() as temp:
                f = Fixture(Path(temp))
                def failure(argv):
                    if len(f.calls) == position:
                        raise subprocess.CalledProcessError(1, argv)
                    f.run(argv)
                f.owner.runner = failure
                with self.assertRaises(subprocess.CalledProcessError):
                    f.owner.start_storage()
                self.assertFalse(f.path(storage.READY).exists())

    def test_mount_namespace_or_readonly_substitution_invalidates_readiness(self):
        for replacement in ("/foreign/data", "/dcentos/data"):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as temp:
                f = Fixture(Path(temp))
                f.owner.start_storage()
                if replacement == "/foreign/data":
                    f.mounts[1] = f.mounts[1].replace("/dcentos/data", replacement)
                else:
                    f.mounts[1] = f.mounts[1].replace("rw,nosuid", "ro,nosuid")
                f.flush_mounts()
                with self.assertRaises(storage.Refused):
                    f.owner.check()

    def test_fake_marker_or_symlink_cannot_replace_actual_mount_proof(self):
        f = self.fixture
        f.directory("/run/dcentos")
        f.write(storage.READY, json.dumps({"schema": 1}))
        with self.assertRaises(storage.Refused):
            f.owner.check()
        f.path(storage.READY).unlink()
        f.owner.start_storage()
        f.path(storage.READY).unlink()
        f.path(storage.READY).symlink_to(f.path("/etc/dcentos/board_target"))
        with self.assertRaises((OSError, storage.Refused)):
            f.owner.check()

    def test_devtmpfs_replaces_pid1_tmpfs_using_kernel_nodes_not_guessed_uart_numbers(self):
        f = self.fixture
        f.directory("/tmp")
        f.path("/tmp").chmod(0o1777)
        f.mount("/dev", filesystem="tmpfs", source="tmpfs", options="rw")
        f.owner.virtual_fs()
        self.assertEqual(f.calls[0], ["/bin/mount", "-t", "devtmpfs", "-o",
                                    "mode=0755,nosuid", "devtmpfs", "/dev"])
        self.assertEqual(f.calls[-2], ["/sbin/ip", "link", "set", "lo", "up"])
        self.assertEqual(f.calls[-1], ["/bin/hostname", "dcentos-s19jpro-aml"])
        self.assertFalse(any("mknod" in argument for call in f.calls for argument in call))

    def test_operator_login_key_survives_fresh_ramdisk_root_without_creating_credentials(self):
        f = self.fixture
        f.owner.start_storage()
        self.assertFalse(f.path("/data/dcent/authorized_keys").exists())
        self.assertEqual(f.path("/root/.ssh/authorized_keys").readlink(), Path("/data/dcent/authorized_keys"))
        f.write(storage.VOLUME + storage.DATA_ROOT + "/dcent/authorized_keys", "ssh-ed25519 fixture-operator-key\n")
        f.path(storage.VOLUME + storage.DATA_ROOT + "/dcent/authorized_keys").chmod(0o600)
        with tempfile.TemporaryDirectory() as second_root:
            second = Fixture(Path(second_root))
            second.write("/proc/sys/kernel/random/boot_id", "next-boot")
            second.directory(storage.VOLUME)
            shutil.copytree(f.path(storage.VOLUME + "/dcentos"), second.path(storage.VOLUME + "/dcentos"))
            second.owner.start_storage()
            second.owner.check()
            self.assertEqual(second.path("/data/dcent/authorized_keys").read_text(), "ssh-ed25519 fixture-operator-key\n")
            self.assertEqual(second.path("/root/.ssh/authorized_keys").readlink(), Path("/data/dcent/authorized_keys"))
            self.assertEqual(second.path("/root/.ssh").stat().st_mode & 0o777, 0o700)

    def test_foreign_root_key_file_or_link_and_unsafe_persistent_keys_refuse(self):
        for kind in ("root-file", "foreign-link", "persistent-symlink", "persistent-world-writable"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                f = Fixture(Path(temporary))
                f.directory("/root/.ssh")
                root_key = f.path("/root/.ssh/authorized_keys")
                if kind == "root-file":
                    root_key.write_text("foreign")
                elif kind == "foreign-link":
                    root_key.symlink_to("/etc/shadow")
                else:
                    f.directory(storage.VOLUME + storage.DATA_ROOT + "/dcent")
                    key = f.path(storage.VOLUME + storage.DATA_ROOT + "/dcent/authorized_keys")
                    if kind == "persistent-symlink":
                        # Namespace emulation retains symlinks as real bind does.
                        key.symlink_to(f.path("/etc/hostname"))
                    else:
                        key.write_text("foreign")
                        key.chmod(0o666)
                with self.assertRaises((storage.Refused, OSError)):
                    f.owner.start_storage()
                self.assertFalse(f.path(storage.READY).exists())

    def test_character_node_wrong_gid_or_writable_permissions_are_rejected(self):
        f = self.fixture
        f.write("/sys/class/mtd/mtd6/dev", "90:12")
        for gid, mode in ((0, 0o600), (1, 0o600), (0, 0o666), (0, 0o620)):
            metadata = SimpleNamespace(st_mode=stat.S_IFCHR | mode, st_uid=0,
                                       st_gid=gid, st_rdev=os.makedev(90, 12))
            with self.subTest(gid=gid, mode=mode), patch.object(Path, "lstat", return_value=metadata):
                if gid == 0 and mode == 0o600:
                    f.owner.character("/dev/mtd6", "/sys/class/mtd/mtd6/dev")
                else:
                    with self.assertRaises(storage.Refused):
                        f.owner.character("/dev/mtd6", "/sys/class/mtd/mtd6/dev")

    def test_fifo_credentials_and_readiness_are_rejected_before_open(self):
        f = self.fixture
        f.owner.start_storage()
        for name in ("/data/dcent/authorized_keys", storage.READY):
            if f.path(name).exists():
                f.path(name).unlink()
            os.mkfifo(f.path(name), 0o600)
            with self.subTest(name=name), patch.object(storage.os, "open", side_effect=AssertionError("FIFO was opened")):
                with self.assertRaisesRegex(storage.Refused, "unsafe file"):
                    f.owner.regular_descriptor(name)
            f.path(name).unlink()

    def test_existing_virtual_mount_wrong_root_options_source_or_count_refuses(self):
        for target in ("/dev", "/run"):
            for kind in ("root", "readonly", "flags", "source", "duplicate"):
                with self.subTest(target=target, kind=kind), tempfile.TemporaryDirectory() as temporary:
                    f = Fixture(Path(temporary))
                    fs = "devtmpfs" if target == "/dev" else "tmpfs"
                    f.mount(target, filesystem=fs, source=fs,
                            options="rw,nosuid" + (",nodev" if target == "/run" else ""))
                    if kind == "root":
                        f.mounts[0] = f.mounts[0].replace("0:22 / ", "0:22 /foreign ")
                    elif kind == "readonly":
                        f.mounts[0] = f.mounts[0].replace("rw,nosuid", "ro,nosuid")
                    elif kind == "flags":
                        f.mounts[0] = f.mounts[0].replace("rw,nosuid", "rw")
                    elif kind == "source":
                        f.mounts[0] = f.mounts[0].replace(f"- {fs} {fs}", f"- {fs} foreign")
                    else:
                        f.mount(target, filesystem=fs, source=fs)
                    f.flush_mounts()
                    with self.assertRaises(storage.Refused):
                        f.owner.virtual_fs()
                    self.assertFalse(any(call[0] == "/bin/hostname" for call in f.calls))

    def test_new_virtual_mount_malformed_readback_refuses(self):
        for kind in ("wrong-root", "duplicate", "readonly", "missing-nodev"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                f = Fixture(Path(temporary))
                def bad_readback(argv):
                    f.run(argv)
                    if argv[-1] == "/run":
                        if kind == "wrong-root":
                            f.mounts[-1] = f.mounts[-1].replace("0:22 / ", "0:22 /foreign ")
                        elif kind == "duplicate":
                            f.mount("/run", filesystem="tmpfs", source="tmpfs")
                        elif kind == "readonly":
                            f.mounts[-1] = f.mounts[-1].replace("rw,mode", "ro,mode")
                        else:
                            f.mounts[-1] = f.mounts[-1].replace(",nodev", "")
                        f.flush_mounts()
                f.owner.runner = bad_readback
                with self.assertRaises(storage.Refused):
                    f.owner.virtual_fs()
                self.assertFalse(f.path(storage.READY).exists())


class StartupScripts(unittest.TestCase):
    def test_early_invokes_actual_s37_policy_cut_fan_and_reset_control_flow(self):
        source = (BOARD / "rootfs-overlay/etc/init.d/S37board_setup").read_text(encoding="utf-8")
        definitions, dispatch = source.split('case "${1:-start}" in', 1)
        for power, fans, policy, expected in (
            (0, 0, "boot-safeoff", ["cut", "fans:30000/100000", "resets", "receipt"]),
            (1, 0, "boot-safeoff", ["cut", "fans:30000/100000"]),
            (0, 1, "boot-safeoff", ["cut", "fans:30000/100000"]),
            (0, 0, "management-only", []),
            (0, 0, "hardware-enabled", []),
        ):
            with self.subTest(power=power, fans=fans, policy=policy), tempfile.TemporaryDirectory() as temporary:
                f = Fixture(Path(temporary))
                f.write("/etc/dcentos/mutation_policy", policy)
                # Execute the production dispatch/identity/policy/start_board.
                # Only electrical/sysfs leaves and receipt publication are
                # replaced with observable functions inside a disposable shell.
                trace = f.root / "electrical-fixture-trace"
                harness = definitions + f'''
IDENTITY_ROOT='{f.path("/etc/dcentos")}'
MUTATION_POLICY_FILE=$IDENTITY_ROOT/mutation_policy
MUTATION_POLICY_HELPER='{BOARD / "rootfs-overlay/usr/libexec/dcentos/mutation-policy.sh"}'
force_psu_safe_low() {{ echo cut >> '{trace}'; return {power}; }}
configure_fans_checked() {{ echo "fans:$FAN_BOOT_DUTY_NS/$FAN_PERIOD_NS" >> '{trace}'; return {fans}; }}
pinmux_init() {{ echo resets >> '{trace}'; }}
write_receipt() {{ echo receipt >> '{trace}'; }}
case "${{1:-start}}" in''' + dispatch
                f.write(storage.BASELINE, harness)
                f.path(storage.BASELINE).chmod(0o755)
                f.write("/proc/mtd", "deliberately unavailable storage")
                def run_actual_baseline(argv):
                    f.run(argv)
                    if argv[0] == storage.BASELINE:
                        subprocess.run(["/bin/sh", str(f.path(storage.BASELINE)), "start"],
                                       check=True, capture_output=True, timeout=5)
                f.owner.runner = run_actual_baseline
                with self.assertRaises((storage.Refused, subprocess.CalledProcessError)):
                    f.owner.early()
                self.assertEqual(trace.read_text().splitlines() if trace.exists() else [], expected)
                self.assertFalse(any("ubifs" in call or "--bind" in call for call in f.calls))
                self.assertFalse(f.path(storage.READY).exists())

    def test_classic_legacy_post_install_refuses_before_loading_nand_helpers(self):
        script = (BOARD / "rootfs-overlay/etc/init.d/S46post-install").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = root / "etc/dcentos"
            identity.mkdir(parents=True)
            (identity / "board_target").write_text("am3-s19jpro-aml")
            (root / "etc/dcentos-platform").write_text("am3-aml-s19jpro")
            # Exact script body and shell; redirect only filesystem roots into
            # the disposable fixture. Missing policy cannot authorize NAND.
            script = script.replace("/etc/", str(root / "etc") + "/")
            script = script.replace("/lib/functions/", str(root / "absent") + "/")
            result = subprocess.run(["/bin/sh", "-c", script, "S46post-install", "start"],
                                    text=True, capture_output=True)
            self.assertIn("classic AML legacy unsigned NAND post-install payloads are disabled", result.stdout)
            self.assertNotIn("cannot open", result.stderr)
            self.assertNotIn("nanddump", result.stderr)

    def test_daemon_start_stops_at_storage_refusal_before_lock_or_hardware(self):
        script = (BOARD / "rootfs-overlay/etc/init.d/S82dcentrald").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = root / "etc/dcentos"
            identity.mkdir(parents=True)
            (identity / "board_target").write_text("am3-s19jpro-aml")
            (root / "refuse.py").write_text("raise SystemExit(21)\n")
            (identity / "mutation_policy").write_text("daemon-hardware\n")
            script = script.replace("/usr/libexec/dcentos/mutation-policy.sh", str(BOARD / "rootfs-overlay/usr/libexec/dcentos/mutation-policy.sh"))
            script = script.replace("/etc/", str(root / "etc") + "/")
            script = script.replace("/run/", str(root / "run") + "/")
            script = script.replace("/usr/libexec/dcentos/classic-aml-storage.py", str(root / "refuse.py"))
            result = subprocess.run(["/bin/sh", "-c", script, "S82dcentrald", "start"],
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("persistent namespace is not ready", result.stdout)
            self.assertFalse((root / "run").exists())

    def test_early_and_s45_propagate_helper_failure(self):
        for name, arguments in (("etc/dcentos-early-init.sh", []), ("etc/init.d/S45persistent", ["start"])):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                helper = Path(temporary) / "refuse.py"
                helper.write_text("raise SystemExit(23)\n")
                script = (OVERLAY / name).read_text().replace("/usr/libexec/dcentos/classic-aml-storage.py", str(helper))
                result = subprocess.run(["/bin/sh", "-c", script, name, *arguments], capture_output=True)
                self.assertEqual(result.returncode, 23)


if __name__ == "__main__":
    unittest.main(verbosity=2)
