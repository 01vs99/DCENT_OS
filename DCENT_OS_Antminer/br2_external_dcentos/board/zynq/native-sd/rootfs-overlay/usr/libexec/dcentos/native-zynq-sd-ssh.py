#!/usr/bin/env python3
"""Prepare the exact native SD SSH namespace after data and volatile binds.

Storage admission runs separately before and after this helper. It never reads
hardware, generates credentials, opens an SSH service or changes root password.
Only direct owned paths are accepted; the early-boot caller owns this namespace
without competing writers. Persistent key files remain on the admitted SD.
"""

import os
from pathlib import Path
import stat
import subprocess

TARGETS = {
    b"am1-s9i\n",
    b"am1-s9j\n",
    b"am2-s17p\n",
    b"am2-s17plus\n",
    b"am2-t17\n",
    b"am2-t17plus\n",
    b"am2-s19pro\n",
    b"am2-s19\n",
    b"am2-t19\n",
    b"am2-s19a\n",
    b"am2-s19plus\n",
}
HOST_KEYS = {
    "dropbear_rsa_host_key",
    "dropbear_ecdsa_host_key",
    "dropbear_ed25519_host_key",
}


def direct_directory(root, relative, *, create=False, mode=None):
    current = root
    for part in relative.split("/"):
        if part in {"", ".", ".."}:
            raise ValueError("canonical namespace path required")
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if not create:
                raise
            current.mkdir(mode=0o700)
            info = current.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise ValueError("direct protected root-owned namespace required")
    if mode is not None:
        current.chmod(mode)
        if stat.S_IMODE(current.lstat().st_mode) != mode:
            raise ValueError("namespace directory mode readback differs")
    return current


def bounded_file(path, *, mode, limit):
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != 0
        or before.st_gid != 0
        or stat.S_IMODE(before.st_mode) != mode
        or not 0 < before.st_size <= limit
    ):
        raise ValueError(
            "bounded direct root-owned credential or identity file required"
        )
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if (
        not os.path.samestat(before, opened)
        or not os.path.samestat(after, path.lstat())
        or len(raw) != before.st_size
        or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    ):
        raise ValueError("credential or identity file changed during read")
    return raw


def directory_mount_id(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        rows = Path("/proc/self/fdinfo/" + str(descriptor)).read_text().splitlines()
        identities = [line.split()[1] for line in rows if line.startswith("mnt_id:\t")]
        if len(identities) != 1 or not identities[0].isdigit():
            raise ValueError("one kernel descriptor mount ID required")
        return identities[0]
    finally:
        os.close(descriptor)


def prepare(root=Path("/"), *, bind=None):
    identity = direct_directory(root, "etc/dcentos") / "board_target"
    target = bounded_file(identity, mode=0o644, limit=64)
    if target not in TARGETS:
        raise ValueError("exact native Zynq SD target required")
    volume = direct_directory(root, "data")
    application = direct_directory(root, "data/dcent", create=True, mode=0o700)
    direct_directory(root, "data/keys", create=True, mode=0o700)
    persistent = direct_directory(root, "data/keys/dropbear", create=True, mode=0o700)
    hostkeys = direct_directory(root, "etc/dropbear", create=True, mode=0o700)
    ssh = direct_directory(root, "root/.ssh", create=True, mode=0o700)
    if not (
        directory_mount_id(volume)
        == directory_mount_id(application)
        == directory_mount_id(persistent)
    ):
        raise ValueError(
            "application and persistent keys must share admitted data mount"
        )
    for path in persistent.iterdir():
        if path.name not in HOST_KEYS:
            raise ValueError("unexpected persistent host-key entry")
        bounded_file(path, mode=0o600, limit=16384)
    link = ssh / "authorized_keys"
    try:
        metadata = link.lstat()
    except FileNotFoundError:
        link.symlink_to("/data/dcent/authorized_keys")
        metadata = link.lstat()
    if (
        not stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or os.readlink(link) != "/data/dcent/authorized_keys"
    ):
        raise ValueError("fixed persistent authorized_keys link required")
    if not os.path.samestat(persistent.stat(), hostkeys.stat()):
        if any(hostkeys.iterdir()):
            raise ValueError("volatile host-key directory must be empty before bind")
        if bind is None:
            subprocess.run(
                ["/bin/mount", "--bind", str(persistent), str(hostkeys)],
                check=True,
                timeout=20,
            )
        else:
            bind(persistent, hostkeys)
    if (
        not os.path.samestat(persistent.stat(), hostkeys.stat())
        or bounded_file(identity, mode=0o644, limit=64) != target
    ):
        raise ValueError("persistent SSH bind or target readback differs")
    return {
        "target": target.decode().strip(),
        "persistent_keys": "/data/keys/dropbear",
        "operator_keys": "/data/dcent/authorized_keys",
        "ssh_started": False,
    }


if __name__ == "__main__":
    prepare()
