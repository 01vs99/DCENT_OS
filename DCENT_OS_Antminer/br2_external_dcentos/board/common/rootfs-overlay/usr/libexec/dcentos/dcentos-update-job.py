#!/usr/bin/env python3
"""Keep a validated update and its journal alive across daemon shutdown."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import uuid


def regular_owned(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_mode & 0o022:
        raise ValueError(f"unsafe update file: {path}")
    return before


def private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError(f"unsafe update directory: {path}")


def publish(directory, record):
    temporary = directory / (".status-" + uuid.uuid4().hex)
    with temporary.open("x", encoding="utf-8") as stream:
        os.chmod(temporary, 0o600)
        json.dump(record, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, directory / "status.json")
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def launch_job(package, digest, job_id, *, stage_root=Path("/tmp/dcentos-upgrade"),
               journal_root=Path("/data/dcent/update-jobs"),
               work_root=Path("/tmp/dcentos-update-jobs"),
               command=("/usr/sbin/sysupgrade", "--stop-miner", "-f"), delay=2.0):
    """Fork a worker after its verified package is reserved and journal is durable.

    The worker owns ordinary file output, no daemon pipes, no inherited network
    listeners and no parent-death signal. The updater still owns transaction,
    signature, target, hardware-session, flash and boot-environment checks.
    """
    os.umask(0o077)
    if str(uuid.UUID(job_id)) != job_id:
        raise ValueError("invalid update job UUID")
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("invalid update package digest")
    package = Path(package)
    stage_root = Path(stage_root)
    if not package.is_absolute() or package.parent.parent != stage_root:
        raise ValueError("update must be an immediate file in a staged upload directory")
    for directory in (stage_root, package.parent):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError("unsafe staged upload directory")
    source_info = regular_owned(package)
    private_directory(journal_root)
    directory = journal_root / job_id
    directory.mkdir(mode=0o700)
    source_boot_id = str(uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip()))
    record = {"schema": 1, "job_id": job_id, "package_sha256": digest,
              "source_boot_id": source_boot_id,
              "state": "preparing", "boot_verified": False, "physical_hashing_verified": False}
    publish(directory, record)
    private_directory(work_root)
    work_directory = work_root / job_id
    work_directory.mkdir(mode=0o700)
    pinned = work_directory / "package.tar"
    measured = hashlib.sha256()
    try:
        with os.fdopen(os.open(package, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
            opened = os.fstat(source.fileno())
            if (source_info.st_dev, source_info.st_ino, source_info.st_size) != (opened.st_dev, opened.st_ino, opened.st_size):
                raise ValueError("staged update changed before copying")
            while chunk := source.read(1024 * 1024):
                measured.update(chunk)
            after = os.fstat(source.fileno())
            if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError("staged update changed while copying")
        if measured.hexdigest() != digest:
            raise ValueError("staged update no longer matches verified package digest")
        # Keep the large package in RAM; NAND data volumes cannot hold another
        # firmware archive. Same-filesystem rename reserves the staged inode
        # without an additional RAM copy. Sysupgrade authenticates it again.
        os.rename(package, pinned)
        reserved = regular_owned(pinned)
        if (reserved.st_dev, reserved.st_ino, reserved.st_size) != (opened.st_dev, opened.st_ino, opened.st_size):
            raise ValueError("staged update changed before reservation")
        record.update(state="scheduled", scheduled_at=int(time.time()), package_path=str(pinned))
        publish(directory, record)
        pid = os.fork()
    except BaseException as error:
        record.update(state="failed_before_start", error=str(error))
        publish(directory, record)
        raise
    if pid:
        return {"schema": 1, "job_id": job_id, "pid": pid, "state": "scheduled",
                "package_sha256": digest, "source_boot_id": source_boot_id,
                "scheduled_at": record["scheduled_at"], "boot_verified": False,
                "physical_hashing_verified": False,
                "status_path": str(directory / "status.json")}
    try:
        os.setsid()
        # Close every inherited descriptor, including daemon sockets and the
        # launcher's stdout pipe, before waiting for the HTTP response window.
        for name in os.listdir("/proc/self/fd"):
            descriptor = int(name)
            if descriptor > 2:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        input_fd = os.open(os.devnull, os.O_RDONLY)
        log_fd = os.open(directory / "output.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.dup2(input_fd, 0)
        os.dup2(log_fd, 1)
        os.dup2(log_fd, 2)
        os.close(input_fd)
        os.close(log_fd)
        time.sleep(delay)
        record.update(state="running", started_at=int(time.time()), worker_pid=os.getpid())
        publish(directory, record)
        environment = dict(os.environ)
        # Sysupgrade measures its input again and validates these three fields
        # as a single optional binding to its own native transaction nonce.
        environment.update(DCENT_UPDATE_JOB_ID=job_id,
                           DCENT_UPDATE_JOB_PACKAGE_SHA256=digest,
                           DCENT_UPDATE_JOB_SOURCE_BOOT_ID=source_boot_id)
        result = subprocess.run([*command, str(pinned)], check=False, close_fds=True,
                                env=environment)
        record.update(state="command_completed" if result.returncode == 0 else "command_failed",
                      exit_code=result.returncode, finished_at=int(time.time()))
        publish(directory, record)
        # The updater's return code does not establish successful boot/rollback.
        os._exit(0 if result.returncode == 0 else 1)
    except BaseException as error:
        try:
            record.update(state="worker_failed", error=str(error))
            publish(directory, record)
        finally:
            os._exit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("sha256")
    parser.add_argument("job_id")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("image update jobs require root")
    print(json.dumps(launch_job(args.package, args.sha256, args.job_id)), flush=True)


if __name__ == "__main__":
    main()
