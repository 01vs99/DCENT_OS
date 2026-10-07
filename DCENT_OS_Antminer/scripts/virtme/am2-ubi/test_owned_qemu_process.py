"""Real Linux PID/exec/Unix-peer negatives; these do not start QEMU."""
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest

from nandsim_snapshot import SnapshotError
from owned_qemu import OwnedQemu, process_identity


class OwnerProcessTests(unittest.TestCase):
    def setUp(self):
        if os.name != "posix" or not hasattr(socket, "SO_PEERCRED"):
            raise RuntimeError("this suite requires its declared Linux process runner")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def process(self, argv, **kwargs):
        child = subprocess.Popen(argv, start_new_session=True, **kwargs)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
        self.addCleanup(cleanup)
        return child

    def test_plain_process_cannot_bind_as_the_runner_qemu(self):
        child = self.process(["/bin/sleep", "60"])
        (self.directory / "qemu.pid").write_text(str(child.pid))
        owner = OwnedQemu(child, self.directory)
        with self.assertRaisesRegex(SnapshotError, "QEMU command"):
            owner.bind(timeout=1)
        self.assertIsNone(owner.pid)

    def test_empty_pidfile_waits_for_publication_without_admitting_foreign_process(self):
        child = self.process(["/bin/sleep", "60"])
        pidfile = self.directory / "qemu.pid"
        pidfile.write_bytes(b"")
        def publish():
            time.sleep(.1)
            pidfile.write_text(str(child.pid))
        publisher = threading.Thread(target=publish)
        publisher.start()
        try:
            owner = OwnedQemu(child, self.directory)
            with self.assertRaisesRegex(SnapshotError, "QEMU command"):
                owner.bind(timeout=2)
            self.assertIsNone(owner.pid)
        finally:
            publisher.join(timeout=2)

    def test_real_socket_peer_must_be_the_retained_process(self):
        child = self.process(["/bin/sleep", "60"])
        owner = OwnedQemu(child, self.directory)
        owner.pid, owner.identity = child.pid, process_identity(child.pid)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(owner.qmp_path))
            server.listen(1)
            with self.assertRaisesRegex(SnapshotError, "foreign process"):
                owner.connect(owner.qmp_path)

    def test_same_pid_exec_cannot_keep_old_executable_binding(self):
        child = self.process(["/bin/sh", "-c", "read value; exec /bin/sleep 60"], stdin=subprocess.PIPE)
        self.addCleanup(child.stdin.close)
        owner = OwnedQemu(child, self.directory)
        owner.pid, owner.identity = child.pid, process_identity(child.pid)
        child.stdin.write(b"continue\n")
        child.stdin.flush()
        deadline = time.monotonic() + 3
        while process_identity(child.pid) == owner.identity and time.monotonic() < deadline:
            time.sleep(.01)
        with self.assertRaisesRegex(SnapshotError, "exited, execed or reused"):
            owner.check()

    def test_exited_process_is_refused_without_signalling_another_pid(self):
        child = self.process(["/bin/sleep", "60"])
        owner = OwnedQemu(child, self.directory)
        owner.pid, owner.identity = child.pid, process_identity(child.pid)
        child.kill()
        child.wait(timeout=5)
        with self.assertRaises((OSError, SnapshotError)):
            owner.discard()


if __name__ == "__main__":
    unittest.main()
