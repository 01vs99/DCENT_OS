"""Linux-only real ptrace/process cases over private ordinary files.

Filesystem classification is explicit here: no NAND or kernel-power-loss
acceptance is inferred from these ordinary-file process tests.
"""
import ctypes
import os
from pathlib import Path
import shlex
import sys
import tempfile
import unittest

from nandsim_snapshot import SnapshotError
from trace_boundaries import trace, syscall_role, ioctl_mutates


class TraceTests(unittest.TestCase):
    def setUp(self):
        if os.name != "posix" or os.uname().machine != "x86_64":
            raise RuntimeError("this process suite requires its declared Linux x86-64 runner")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.events = []

    def classifier(self, pid, regs):
        def role(path):
            return "modeled-file:" + Path(path).name if str(path).startswith(str(self.root) + "/") else None
        def fd(pid, descriptor):
            try:
                return role(os.readlink(f"/proc/{pid}/fd/{descriptor}"))
            except FileNotFoundError:
                return None
        def path(pid, value, directory=-100):
            if not value.startswith("/"):
                value = os.readlink(f"/proc/{pid}/cwd" if directory == -100 else f"/proc/{pid}/fd/{directory}") + "/" + value
            return role(value)
        return syscall_role(pid, regs, fd_classifier=fd, path_classifier=path)

    def test_actual_shell_and_forked_utility_writes_are_both_observed(self):
        source, destination, state = self.root / "source", self.root / "copy", self.root / "state"
        source.write_bytes(b"real process fixture\n" * 5000)
        command = f"cp {shlex.quote(str(source))} {shlex.quote(str(destination))}; printf done > {shlex.quote(str(state))}"
        trace(["/bin/sh", "-c", command], self.events.append, classifier=self.classifier)
        self.assertEqual(source.read_bytes(), destination.read_bytes())
        self.assertEqual(state.read_bytes(), b"done")
        self.assertTrue(any(row["operation"] == "cp:completed" and row["writes"] > 0 for row in self.events), self.events)
        self.assertTrue(any(row["operation"].startswith("shell:") for row in self.events), self.events)

    def test_failed_real_child_cannot_be_reported_as_a_successful_boundary_census(self):
        with self.assertRaisesRegex(SnapshotError, "transaction failed"):
            trace(["/bin/sh", "-c", "exit 17"], self.events.append, classifier=self.classifier)

    def test_rename_from_volatile_source_observes_persistent_destination(self):
        with tempfile.TemporaryDirectory(dir=self.root.parent) as outside:
            source, destination = Path(outside) / "volatile", self.root / "installed"
            source.write_bytes(b"actual rename without a destination write syscall")
            trace(["/bin/mv", str(source), str(destination)], self.events.append, classifier=self.classifier)
            self.assertFalse(source.exists())
            self.assertEqual(destination.read_bytes(), b"actual rename without a destination write syscall")
            self.assertTrue(any(row["operation"] == "mv:completed" and
                                "modeled-file:installed" in row["roles"] for row in self.events), self.events)

    def test_unknown_persistent_writer_is_not_silently_omitted(self):
        output = self.root / "foreign"
        command = f"printf x | tee {shlex.quote(str(output))} >/dev/null"
        with self.assertRaisesRegex(SnapshotError, "unclassified persistent executable: tee"):
            trace(["/bin/sh", "-c", command], self.events.append, classifier=self.classifier)

    def test_actual_mtd_abi_read_queries_are_not_classified_by_argument_direction(self):
        self.assertFalse(ioctl_mutates(0x40084D0B))  # MEMGETBADBLOCK.
        self.assertFalse(ioctl_mutates(0xC0104D04))  # MEMREADOOB.
        self.assertTrue(ioctl_mutates(0x800C4D10))   # OTPLOCK despite _IOR.
        self.assertTrue(ioctl_mutates(0x40084D02))   # MEMERASE.
        self.assertTrue(ioctl_mutates(0x40304D18))   # MEMWRITE.
        with self.assertRaisesRegex(SnapshotError, "unclassified MTD"):
            ioctl_mutates(0x40084D7F)

    def test_successful_environment_ioctl_is_a_separate_cut_before_its_later_write(self):
        # This is explicitly a syscall-boundary fixture, not a NAND utility:
        # an interpreter alias performs a real AF_UNIX FIONBIO ioctl and a
        # later ordinary-file write. Only that ioctl's storage classification
        # is modeled; ptrace must stop it before it observes the next write.
        executable = self.root / "fw_setenv"
        executable.symlink_to(sys.executable)
        output = self.root / "environment-model"
        script = ("import fcntl, os, socket, struct; "
                  "a,b=socket.socketpair(); fcntl.ioctl(a, 0x5421, struct.pack('i', 1)); "
                  "fd=os.open(" + repr(str(output)) + ", os.O_WRONLY|os.O_CREAT, 0o600); "
                  "os.write(fd, b'complete'); os.close(fd)")

        def classify(pid, regs):
            if regs.orig_rax == 16 and regs.rsi == 0x5421:
                return "modeled-env:erase-ioctl"
            return self.classifier(pid, regs)

        trace([str(executable), "-c", script], self.events.append, classifier=classify)
        self.assertEqual(output.read_bytes(), b"complete")
        operations = [event["operation"] for event in self.events]
        self.assertIn("fw_setenv:syscall-16", operations)
        self.assertLess(operations.index("fw_setenv:syscall-16"), operations.index("fw_setenv:syscall-1"))


if __name__ == "__main__":
    unittest.main()
