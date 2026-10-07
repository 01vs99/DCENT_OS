#!/usr/bin/env python3
"""Read-only S99 observation of the retained classic AML fw89 application.

This record grants neither hardware mutation nor watchdog disarm authority.
No raw I2C operation is performed. Alternate roots exist for offline fixtures.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import sys
import time


class StaleObservation(ValueError):
    """A previous complete record can be replaced by the in-flight scan."""


def require(condition, message):
    if not condition:
        raise ValueError(message)


def process_identity(proc_root, pid):
    root = proc_root / str(pid)
    # comm may contain spaces and parentheses; fields after the final ')' start
    # at field 3. starttime is field 22, in current-boot kernel clock ticks.
    fields = (root / "stat").read_text().rsplit(")", 1)[1].split()
    require(fields[0] not in ("Z", "X", "x"), "producer is not running")
    start = int(fields[19])
    executable = os.readlink(root / "exe").removesuffix(" (deleted)")
    require(Path(executable).name == "dcentrald", "producer executable mismatch")
    return start


def verify(proof_path, proc_root, gpio_root):
    directory = proof_path.parent.lstat()
    require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0
            and directory.st_mode & 0o022 == 0, "unprotected proof directory")
    descriptor = os.open(proof_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as proof_file:
        metadata = os.fstat(proof_file.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
                and stat.S_IMODE(metadata.st_mode) == 0o600,
                "proof must be a root-owned mode-0600 regular file")
        raw = proof_file.read(16385)
    require(len(raw) <= 16384, "proof exceeds size bound")
    proof = json.loads(raw)
    require(isinstance(proof, dict), "proof is not an object")
    require(type(proof.get("schema")) is int and proof["schema"] == 1
            and proof.get("producer") == "classic_aml_native"
            and proof.get("board_target") == "am3-s19jpro-aml"
            and proof.get("admitted_application_fw") == "0x89",
            "wrong application proof identity")
    boot_id = (proc_root / "sys/kernel/random/boot_id").read_text().strip()
    require(bool(boot_id) and proof.get("boot_id") == boot_id, "different boot")
    pid, start = proof.get("producer_pid"), proof.get("producer_start_ticks")
    require(type(pid) is int and pid > 0 and type(start) is int and start > 0,
            "invalid producer identity")
    require(process_identity(proc_root, pid) == start, "producer PID was reused")
    chains = proof.get("physical_chains")
    require(isinstance(chains, list) and 1 <= len(chains) <= 3
            and all(type(chain) is int and 1 <= chain <= 3 for chain in chains)
            and chains == sorted(set(chains)), "invalid physical population")
    present = []
    for chain in range(1, 4):
        # Exact source provider: GPIO439..441 are active-high plug inputs.
        gpio = gpio_root / f"gpio{438 + chain}"
        require((gpio / "direction").read_text().strip() == "in",
                "plug GPIO is not an input")
        value = (gpio / "value").read_text().strip()
        require(value in ("0", "1"), "invalid plug GPIO observation")
        if value == "1":
            present.append(chain)
    require(chains == present, "current physical population differs")
    # Recheck the same live process after all observations. A reusable PID alone
    # is insufficient, even if its executable happens to have the same name.
    require(process_identity(proc_root, pid) == start, "producer changed during read")
    observed = proof.get("observed_monotonic_ms")
    require(type(observed) is int and observed >= 0, "invalid monotonic observation")
    age = time.monotonic_ns() // 1_000_000 - observed
    require(age >= 0, "application observation is from the future")
    if age >= 5000:
        raise StaleObservation("application observation is stale")
    return f"Classic AML fw89 owner: current health, chains={chains}, age_ms={age}"


def wait_for_fresh(proof_path, proc_root, gpio_root, timeout=5.0):
    # A full source-paced three-board scan takes at least3.35s. Its original
    # observation is never backdated. Catch its next fresh atomic publication
    # within one bounded refresh, while refusing other contradictions at once.
    deadline = time.monotonic() + timeout
    while True:
        try:
            return verify(proof_path, proc_root, gpio_root)
        except StaleObservation:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise
            time.sleep(min(0.1, remaining))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof", type=Path, default=Path("/run/dcentos/classic-aml-application.json"))
    parser.add_argument("--proc-root", type=Path, default=Path("/proc"))
    parser.add_argument("--gpio-root", type=Path, default=Path("/sys/class/gpio"))
    args = parser.parse_args()
    try:
        print(wait_for_fresh(args.proof, args.proc_root, args.gpio_root))
    except (OSError, ValueError, IndexError, KeyError, TypeError) as error:
        print(f"Classic AML proof unavailable: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
