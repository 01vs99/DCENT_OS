"""Real private mount/chroot path classification; tmpfs is a declared model.

This test does not substitute NAND utilities or claim a power-cut result. It
checks that the observer resolves the real child's mount and descriptor paths.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import trace_boundaries as tracing


def mount_inventory():
    """Use the kernel inventory: ismount misses same-filesystem bind mounts."""
    result = {}
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        target = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[4])
        result.setdefault(target, []).append(int(fields[0]))
    return result


def retire_mount(target, identity):
    if mount_inventory().get(str(target)) != [identity]:
        raise RuntimeError("private mount identity changed; retaining fixture")
    subprocess.run(["umount", str(target)], check=True)
    if str(target) in mount_inventory():
        raise RuntimeError("private mount remains; retaining fixture")


def fixture():
    temporary = Path(tempfile.mkdtemp(prefix="dcent-trace-chroot-"))
    root = temporary / "root"
    root.mkdir()
    mounts = []

    def mount(target, arguments):
        if str(target) in mount_inventory():
            raise RuntimeError("unexpected existing fixture mount")
        subprocess.run(["mount", *arguments, str(target)], check=True)
        identities = mount_inventory().get(str(target), [])
        if len(identities) != 1:
            raise RuntimeError("private mount was not identified; retaining fixture")
        mounts.append((target, identities[0]))

    try:
        # Never expose a writable host tree inside the chroot. Only the shell
        # runtime directories are visible, and every bind is read-only before
        # launching the child. All fixture mutations live on private tmpfs.
        mount(root, ["-t", "tmpfs", "-o", "mode=0755", "none"])
        for name in ("usr", "bin", "lib", "lib64"):
            source, target = Path("/") / name, root / name
            if source.is_symlink():
                target.symlink_to(os.readlink(source))
            elif source.is_dir():
                target.mkdir()
                mount(target, ["--bind", str(source)])
                subprocess.run(["mount", "-o", "remount,bind,ro", str(target)], check=True)
        mounted = root / "fixture"
        mounted.mkdir()
        mount(mounted, ["-t", "tmpfs", "none"])
        filesystem = tracing._filesystem
        def modeled_filesystem(pid, path):
            kind, mount = filesystem(pid, path)
            # Only this actual private tmpfs stands in for the filesystem kind.
            # The original production mountinfo/path matching is still used.
            if kind == "tmpfs" and mount == str(mounted):
                return "ubifs", mount
            return kind, mount
        events = []
        script = "printf actual-chroot-write > /fixture/config"
        with mock.patch.object(tracing, "_filesystem", modeled_filesystem):
            tracing.trace([shutil.which("chroot"), str(root), "/bin/sh", "-c", script], events.append)
        assert (mounted / "config").read_bytes() == b"actual-chroot-write"
        writes = [row for row in events if row["operation"] == "shell:syscall-1"]
        assert writes and writes[0]["roles"] == ["ubifs:config"], events
        # A regular file named mtd0 and the real /dev/null are not raw NAND.
        with (mounted / "mtd0").open("wb") as regular, open("/dev/null", "rb") as null:
            assert tracing.fd_role(os.getpid(), regular.fileno()) is None
            assert tracing.fd_role(os.getpid(), null.fileno()) is None
    finally:
        for target, identity in reversed(mounts):
            retire_mount(target, identity)
        if any(path == str(root) or path.startswith(str(root) + "/") for path in mount_inventory()):
            raise RuntimeError("unrecognized private mount remains; retaining fixture")
        # Nonrecursive even on setup failure: an unexpected file or a mount
        # fails closed. There is no traversal of a mounted or foreign tree.
        root.rmdir()
        temporary.rmdir()


class ChrootClassificationTests(unittest.TestCase):
    def test_real_chroot_fd_write_is_seen_in_observers_mount_inventory(self):
        if os.name != "posix":
            raise RuntimeError("this suite requires its declared Linux mount-namespace runner")
        command = ["unshare", "--mount", "--propagation", "private"]
        if os.geteuid() != 0:
            command += ["--user", "--map-root-user"]
        command += ["--", sys.executable, str(Path(__file__).resolve()), "--fixture"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    if sys.argv[1:] == ["--fixture"]:
        fixture()
    else:
        unittest.main()
