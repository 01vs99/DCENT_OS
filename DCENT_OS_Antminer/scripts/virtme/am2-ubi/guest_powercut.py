#!/usr/bin/env python3
"""Disposable-guest half of the actual AM2 logical-boundary crash rehearsal."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from guest_nand import guard, replay, runtime_binding
from nandsim_snapshot import SnapshotError, regular, sha
from trace_boundaries import trace


def publish(directory: Path, name: str, value):
    raw = json.dumps(value, sort_keys=True).encode() + b"\n"
    if len(raw) > 1024*1024:
        raise SnapshotError("guest control message exceeds bound")
    pending = directory / (name + ".next")
    with pending.open("xb") as stream:
        stream.write(raw)
    pending.rename(directory / name)
    # This is host-side correlation over a private shared control directory.
    # Never issue sync/fsync here: that would change the simulated cut state.


def hold():
    # Only the owning host may release this state, by discarding the VM. A
    # timeout is failure; it must not resume the transaction to manufacture a
    # successful receipt or flush its pending UBI/UBIFS buffers.
    time.sleep(1800)
    raise SnapshotError("host did not discard the stopped logical-boundary guest")


def trace_install(args):
    guard(args.token)
    transaction = args.root / "tmp/transaction"
    expected = args.control / "expected"
    expected.mkdir(mode=0o700)
    paths = {name: transaction / name for name in (
        "kernel", "rootfs", "dcentrald.toml", "am2-fabric.itb", "ssh-host-ed25519", "ssh-authorized_keys")}
    paths.update({"env.before": args.work / "env.before",
                  "pools.conf": args.root / "overlay/pools.conf"})
    manifest = {}
    for name, path in paths.items():
        raw = regular(path, 4*1024**2)
        (expected / name).write_bytes(raw)
        manifest[name] = {"size": len(raw), "sha256": sha(raw)}
    protected = {name: regular(args.work / (name + ".before"), 128).decode().split()[0]
                 for name in ("active", "factory", "fpga-active")}
    publish(args.control, "expected.json", {"files": manifest, "protected": protected})
    events = []
    def checkpoint(row):
        events.append(row)
        if len(events) > 512:
            raise SnapshotError("logical write census exceeds bound")
        if args.cut == len(events)-1:
            publish(args.control, "cut.json", {"binding": runtime_binding(args.token), "events": events})
            hold()
    checkpoint({"operation": "install:before-first-write", "writes": 0, "roles": []})
    trace([shutil.which("chroot"), str(args.root), "/bin/sh", "/tmp/transaction/stage1.sh",
           "install", "/tmp/transaction", args.request_sha], checkpoint)
    if args.cut >= 0:
        raise SnapshotError("requested cut was not reached by the real transaction")
    publish(args.control, "trace-complete.json", {"binding": runtime_binding(args.token), "events": events})


def run(*arguments, **kwargs):
    result = subprocess.run(arguments, capture_output=True, timeout=120, **kwargs)
    if result.returncode:
        raise SnapshotError("fresh guest readback command failed: " + result.stderr.decode(errors="replace")[-2048:])
    return result.stdout


def verify_transaction(args):
    """Check flash selection after raw replay, before declaring this cut safe."""
    guard(args.token)
    expected = json.loads(regular(args.control / "expected.json", 16384))
    retained = {}
    for name, record in expected["files"].items():
        if name not in {"kernel", "rootfs", "dcentrald.toml", "am2-fabric.itb", "ssh-host-ed25519",
                        "ssh-authorized_keys", "env.before", "pools.conf"}:
            raise SnapshotError("unexpected retained transaction fixture")
        raw = regular(args.control / "expected" / name, 4*1024**2)
        if record != {"size": len(raw), "sha256": sha(raw)}:
            raise SnapshotError("retained transaction fixture differs")
        retained[name] = raw
    for name, index in (("active", 7), ("factory", 9), ("fpga-active", 2)):
        raw = run("nanddump", "-q", "--omitoob", "--bb=padbad", f"/dev/mtd{index}")
        if sha(raw) != expected["protected"][name]:
            raise SnapshotError("power cut altered protected " + name)
    env_config = Path("/tmp/dcent-replay-fw-env.config")
    env_config.write_text("/dev/mtd4 0x00000 0x20000 0x20000\n/dev/mtd4 0x20000 0x20000 0x20000\n")
    environment = run("fw_printenv", "-c", str(env_config))
    def fields(raw):
        rows = raw.decode().splitlines()
        result = {}
        for row in rows:
            key, separator, value = row.partition("=")
            if not separator or key in result:
                raise SnapshotError("complete unique environment readback required")
            result[key] = value
        return result
    current, previous = fields(environment), fields(retained["env.before"])
    if current == previous:
        return {"selection": "original-complete-environment", "protected_partitions": "unchanged"}
    # A changed selector is acceptable only if the real environment is the
    # complete intended commit and the newly selected files all read back.
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from prepare_am2_fabric_boot import nand_boot_environment
    wanted = dict(previous)
    wanted.update(nand_boot_environment(2, previous["nandboot"]))
    wanted.update(firmware="2", upgrade_stage="0", first_boot="yes")
    if current != wanted:
        raise SnapshotError("torn, partial or foreign persistent boot environment")
    with Path("/dev/mtd3").open("rb", buffering=0) as stream:
        if stream.read(len(retained["am2-fabric.itb"])) != retained["am2-fabric.itb"]:
            raise SnapshotError("new selector precedes complete FPGA readback")
    run("ubiattach", "-m", "8", "-d", "1", "-O", "2048", "--max-beb-per1024=20")
    for name, index in (("kernel", 0), ("rootfs", 1)):
        with Path(f"/dev/ubi1_{index}").open("rb", buffering=0) as stream:
            if stream.read(len(retained[name])) != retained[name]:
                raise SnapshotError("new selector precedes complete " + name)
        if Path(f"/sys/class/ubi/ubi1_{index}/corrupted").read_text().strip() != "0":
            raise SnapshotError("selected UBI update is incomplete")
    destination = Path("/tmp/dcent-replay-verify")
    destination.mkdir(mode=0o700)
    run("mount", "-t", "ubifs", "-o", "ro", "ubi1:rootfs_data", str(destination))
    for name, relative in (("dcentrald.toml", "dcentrald.toml"), ("env.before", "vendor-first-install/env.before"),
                           ("ssh-host-ed25519", "keys/dropbear/dropbear_ed25519_host_key"),
                           ("ssh-authorized_keys", "dcent/authorized_keys")):
        if regular(destination / relative, 4*1024**2) != retained[name]:
            raise SnapshotError("new selector precedes complete protected data: " + name)
    if not (destination / "dcent/.ssh-enabled").is_file():
        raise SnapshotError("new selector precedes SSH enablement state")
    if run("tar", "-xOf", str(destination / "vendor-first-install/overlay.tar"), "./pools.conf") != retained["pools.conf"]:
        raise SnapshotError("new selector lost original vendor configuration")
    return {"selection": "new-complete-environment-and-payload", "protected_partitions": "unchanged"}


def replay_guest(args):
    report = replay(args.snapshot, args.token)
    publish(args.control, "replayed.json", {"binding": runtime_binding(args.token), "report": report})
    # Host independently compares the new simulator's allocation map and BBT
    # before allowing a UBI attachment to touch the restored flash.
    deadline = time.monotonic() + 600
    while not (args.control / "verify-request.json").exists():
        if time.monotonic() >= deadline:
            raise SnapshotError("host did not authenticate the fresh raw memory replay")
        time.sleep(.05)
    request = json.loads(regular(args.control / "verify-request.json", 256))
    if request != {"token": args.token, "action": "verify-transaction"}:
        raise SnapshotError("foreign fresh-guest verification request")
    report.update(verify_transaction(args))
    publish(args.control, "verified.json", report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("trace", "replay"))
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--request-sha")
    parser.add_argument("--cut", type=int, default=-1)
    parser.add_argument("--snapshot", type=Path)
    args = parser.parse_args()
    try:
        (trace_install if args.mode == "trace" else replay_guest)(args)
    except (SnapshotError, OSError, ValueError) as error:
        publish(args.control, "failed.json", {"error": str(error)})
        raise


if __name__ == "__main__":
    main()
