#!/usr/bin/env python3
"""Join a checked native boot commit to its exact saved browser update job."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

from am2_ota_boot import parse_environment, verify_committed


def private_directory(path):
    info = path.lstat()
    return (
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid()
        and not info.st_mode & 0o077
    )


def read_owned(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o022
            or info.st_size > limit
        ):
            raise ValueError("unsafe or oversized update evidence")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("update evidence exceeded its bound")
        return data


def publish(directory, observation):
    temporary = directory / (".boot-observation-" + uuid.uuid4().hex)
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            os.chmod(temporary, 0o600)
            json.dump(observation, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, directory / "boot-observation.json")
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def observe(
    environment,
    cmdline,
    boot_id,
    *,
    journal_root=Path("/data/dcent/update-jobs"),
    receipt_root=Path("/data/dcent/ota-native"),
):
    """Consume S99's CRC-valid complete readback without writing boot state."""
    if not journal_root.exists() or not receipt_root.exists():
        return []
    if not private_directory(journal_root) or not private_directory(receipt_root):
        raise ValueError("update evidence roots must remain private directories")
    receipts = []
    for index, directory in enumerate(receipt_root.iterdir()):
        if index >= 256:
            break
        try:
            if not private_directory(directory):
                continue
            data = read_owned(directory / "receipt.json", 131072)
            receipt = json.loads(data)
            if isinstance(receipt.get("job_binding"), dict):
                receipts.append((receipt, hashlib.sha256(data).hexdigest()))
        except (OSError, ValueError, AttributeError):
            continue
    observations = []
    for index, directory in enumerate(journal_root.iterdir()):
        if index >= 256:
            break
        try:
            if str(
                uuid.UUID(directory.name)
            ) != directory.name or not private_directory(directory):
                continue
            job = json.loads(read_owned(directory / "status.json", 8192))
            if job.get("schema") != 1 or job.get("job_id") != directory.name:
                continue
            matches = []
            for receipt, digest in receipts:
                try:
                    observation = verify_committed(
                        receipt,
                        environment,
                        cmdline,
                        boot_id,
                        expected_job_id=directory.name,
                        expected_package_sha256=job["package_sha256"],
                        expected_source_boot_id=job["source_boot_id"],
                    )
                    observation["receipt_sha256"] = digest
                    matches.append(observation)
                except (ValueError, KeyError, TypeError):
                    continue
            # Duplicate custody is ambiguous even if the copied bytes agree.
            if len(matches) == 1:
                publish(directory, matches[0])
                observations.append(matches[0])
        except (OSError, ValueError, AttributeError):
            continue
    return observations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("boot observations require root")
    environment = parse_environment(read_owned(args.environment, 131072))
    observations = observe(
        environment,
        Path("/proc/cmdline").read_text(),
        Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    )
    print(json.dumps({"observed_update_jobs": len(observations)}))


if __name__ == "__main__":
    main()
