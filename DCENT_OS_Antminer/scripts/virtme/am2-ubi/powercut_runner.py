#!/usr/bin/env python3
"""Run actual AM2 logical-write cuts by retaining only owned QEMU NAND state.

Caller must hold the campaign heavy lock. No miners, network, kernel rebuild,
host MTD device or production installation authority is used by this runner.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import signal
import subprocess
import tempfile
import time

from guest_nand import KERNEL_SHA, MODULE, MODULE_SHA, RELEASE
from nandsim_snapshot import Schema, SnapshotError, pointer, regular, sha, snapshot
from owned_qemu import Debugger, OwnedQemu, Qmp


HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parents[1]
STAGE1 = SCRIPTS.parent.parent / "dcent-toolbox/src/dcent_toolbox/_am2_first_install/stage1.sh"


def checked(*args, timeout=60):
    result = subprocess.run([str(value) for value in args], capture_output=True, timeout=timeout)
    if result.returncode:
        raise SnapshotError("prerequisite check failed: " + result.stderr.decode(errors="replace")[-4096:])
    return result.stdout


def preflight(args):
    if os.name != "posix" or os.geteuid() != 0 or os.uname().machine != "x86_64":
        raise SnapshotError("native root Linux host required for disposable virtme rehearsal")
    for tool in ("vng", "qemu-system-x86_64", "modinfo", "nandwrite", "nanddump", "python3"):
        if shutil.which(tool) is None:
            raise SnapshotError("required local test dependency absent: " + tool)
    lock = HERE / "inputs.lock.json"
    if regular(lock, 65536) != regular(args.bundle / "inputs.lock.json", 65536):
        raise SnapshotError("module bundle uses a different input lock")
    checked("python3", HERE / "verify_manifest.py", "verify-bundle", "--manifest", args.bundle / "manifest.json",
            "--lock", lock, "--bundle-dir", args.bundle)
    checked("python3", HERE / "verify_manifest.py", "verify-kernel", "--lock", lock, "--kernel", args.kernel)
    checked("python3", SCRIPTS / "first_install/build_am2_stock_window.py", "verify", "--output-dir", args.writer.parent)
    if args.writer.name != "am2-nand-window":
        raise SnapshotError("exact verified native window writer required")
    if sha(regular(args.kernel, 16*1024**2)) != KERNEL_SHA:
        raise SnapshotError("snapshot decoder kernel authority differs")
    module = regular(MODULE, 4*1024**2)
    extractor = Path("/usr/src/linux-headers-5.15.0-181/scripts/extract-vmlinux")
    image = checked("sh", extractor, args.kernel, timeout=30)
    schema = Schema.decode(image, module, kernel_sha256=KERNEL_SHA, expected_module_sha256=MODULE_SHA)
    if schema.symbol_section != ".bss":
        raise SnapshotError("loaded module binding has an unexpected symbol section")
    return schema


def validate_binding(schema, binding, token):
    expected = {"token": token, "kernel_release": RELEASE, "kernel_sha256": schema.kernel_sha256,
                "module_sha256": schema.module_sha256, "base_btf_sha256": schema.base_btf_sha256,
                "module_btf_sha256": schema.module_btf_sha256}
    if not isinstance(binding, dict) or set(binding) != set(expected) | {"symbol_address", "bss_address", "bad_blocks"}:
        raise SnapshotError("guest kernel binding fields differ")
    if any(binding[key] != value for key, value in expected.items()):
        raise SnapshotError("guest runtime kernel/module/BTF differs from admitted bytes")
    if (type(binding["symbol_address"]) is not int or type(binding["bss_address"]) is not int
            or binding["symbol_address"] != binding["bss_address"] + schema.symbol_offset):
        raise SnapshotError("guest nsmtd symbol does not belong to the verified loaded module")
    pointer(binding["symbol_address"])
    pointer(binding["bss_address"])
    bad = binding["bad_blocks"]
    if (not isinstance(bad, list) or any(type(value) is not int or not 0 <= value < 2048 for value in bad)
            or sorted(set(bad)) != bad):
        raise SnapshotError("guest bad-block census differs")


def wait_message(owner, control, name, *, timeout=1200):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        failed = control / "failed.json"
        if failed.exists():
            raise SnapshotError("actual guest refused: " + regular(failed, 65536).decode())
        path = control / name
        if path.exists():
            return json.loads(regular(path, 1024*1024))
        if owner.launcher.poll() is not None:
            raise SnapshotError("guest exited before " + name)
        owner.check()
        time.sleep(.05)
    raise SnapshotError("actual guest deadline expired before " + name)


def guest_command(args, control, token, *, cut=None, replay_path=None):
    quote = shlex.quote
    commands = ["set -eu", "export DCENT_DISPOSABLE_VIRTME=am2-first-install-v1",
                "modprobe mtd", "insmod " + quote(str(args.bundle / "ubi-nofastmap.ko")),
                "insmod " + quote(str(args.bundle / "ubifs-nofastmap.ko"))]
    if replay_path is None:
        commands += ["export DCENT_AM2_NANDSIM_LAYOUT=" + quote(args.layout),
                     "export DCENT_AM2_POWERCUT_CONTROL=" + quote(str(control)),
                     "export DCENT_AM2_POWERCUT_TOKEN=" + quote(token),
                     "export DCENT_AM2_POWERCUT_INDEX=" + str(cut),
                     shlex.join(["bash", str(SCRIPTS / "am2_first_install_offline_nandsim_harness.sh"),
                                 "/tmp/dcent-am2-nandsim-" + token[:16], str(STAGE1), str(args.writer)])]
    else:
        commands += ["modprobe nandsim id_bytes=0x20,0xaa,0x00,0x15 overridesize=11 parts=64,96,16,16,4,4,696,456,456",
                     "for node in /sys/class/mtd/mtd[0-9]*; do "
                     "[ -f \"$node/dev\" ] || continue; name=${node##*/}; "
                     "IFS=: read -r major minor < \"$node/dev\"; "
                     "[ -c /dev/$name ] || mknod /dev/$name c \"$major\" \"$minor\"; done",
                     shlex.join(["python3", str(HERE / "guest_powercut.py"), "replay", "--control", str(control),
                                 "--token", token, "--snapshot", str(replay_path)])]
    return "; ".join(commands)


def vm_command(args, directory, control, token, *, cut=None, replay_path=None):
    acceleration = getattr(args, "accel", "tcg")
    if acceleration not in ("tcg", "kvm"):
        raise SnapshotError("explicit tcg or kvm acceleration required")
    qemu_options = shlex.join(["-qmp", f"unix:{directory}/qmp.sock,server=on,wait=off",
                               "-gdb", f"unix:{directory}/gdb.sock,server=on,wait=off",
                               "-pidfile", str(directory / "qemu.pid"),
                               "-smbios", "type=1,serial=DCENT-NANDSIM-" + token,
                               "-machine", "accel=" + acceleration])
    # The value starts with -qmp. Attach it to the option so argparse cannot
    # mistake the QEMU switches for vng switches before QEMU even starts.
    return ["vng", "--run", str(args.kernel), "--memory", "2048M", "--cpus", "2",
            *(["--disable-kvm"] if acceleration == "tcg" else []),
            # The snapshot schema admits four-level canonical kernel pointers.
            # QEMU's max CPU and this pinned Ubuntu kernel both support LA57;
            # allowing their default would select a different direct-map ABI.
            "--disable-microvm", "--disable-monitor", "--force-9p", "--verbose", "--append", "nopti", "--append", "no5lvl", "--rwdir", str(control),
            "--qemu-opts=" + qemu_options,
            "--exec", guest_command(args, control, token, cut=cut, replay_path=replay_path)]


@contextmanager
def launch(args, directory, control, token, *, cut=None, replay_path=None):
    directory.mkdir(mode=0o700)
    command = vm_command(args, directory, control, token, cut=cut, replay_path=replay_path)
    log = (directory / "guest.log").open("xb")
    launcher = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    owner = OwnedQemu(launcher, directory)
    try:
        owner.bind()
        yield owner
    except BaseException:
        log.flush()
        print((directory / "guest.log").read_bytes()[-12000:].decode(errors="replace"), flush=True)
        raise
    finally:
        if launcher.poll() is None:
            if owner.pid is not None:
                try:
                    owner.discard()
                except (ProcessLookupError, FileNotFoundError):
                    launcher.wait(timeout=15)
            else:
                # The still-running session leader is our retained Popen,
                # therefore this group belongs to this failed launch only.
                os.killpg(launcher.pid, signal.SIGKILL)
                launcher.wait(timeout=15)
        log.close()


def capture(schema, owner, binding, token, output, boundary):
    validate_binding(schema, binding, token)
    qmp = Qmp(owner)
    debugger = None
    try:
        qmp.stop()
        debugger = Debugger(owner)
        result = snapshot(schema, debugger.read, nsmtd_address=binding["symbol_address"], output=output,
                          boundary=boundary, bad_blocks=tuple(binding["bad_blocks"]))
        owner.check()
        if qmp.call("query-status").get("running") is not False:
            raise SnapshotError("QEMU resumed while its flash was being captured")
        return result, qmp, debugger
    except BaseException:
        if debugger is not None:
            debugger.close()
        qmp.close()
        raise


def check_events(events):
    if not isinstance(events, list) or not 1 <= len(events) <= 512:
        raise SnapshotError("bounded actual logical write census required")
    for event in events:
        if (not isinstance(event, dict) or set(event) != {"operation", "writes", "roles"}
                or not isinstance(event["operation"], str) or len(event["operation"]) > 80
                or type(event["writes"]) is not int or not 0 <= event["writes"] <= 100000
                or not isinstance(event["roles"], list)
                or any(not isinstance(role, str) or len(role) > 512 for role in event["roles"])):
            raise SnapshotError("actual write event shape differs")


def rehearse(args, schema, temporary):
    baseline = temporary / "baseline"
    baseline.mkdir(mode=0o700)
    token = secrets.token_hex(32)
    with launch(args, temporary / "baseline-vm", baseline, token, cut=-1) as owner:
        result = wait_message(owner, baseline, "trace-complete.json")
        validate_binding(schema, result["binding"], token)
        check_events(result["events"])
        if owner.launcher.wait(timeout=120) != 0:
            raise SnapshotError("actual baseline install/readback/rollback failed")
    events = result["events"]
    cuts = list(range(len(events))) if args.cuts == "all" else [int(value) for value in args.cuts.split(",")]
    if not cuts or sorted(set(cuts)) != cuts or any(not 0 <= value < len(events) for value in cuts):
        raise SnapshotError("requested cuts are outside the actual ordered census")
    print(json.dumps({"layout": args.layout, "logical_boundaries": events, "selected_cuts": cuts}), flush=True)
    for number in cuts:
        with tempfile.TemporaryDirectory(prefix=f"cut-{number}-", dir=temporary) as cut_dir:
            case = Path(cut_dir)
            control = case / "control"
            control.mkdir(mode=0o700)
            token = secrets.token_hex(32)
            boundary = f"{args.layout}:{number}:{events[number]['operation']}"
            with launch(args, case / "source-vm", control, token, cut=number) as owner:
                result = wait_message(owner, control, "cut.json")
                if result["events"] != events[:number+1]:
                    raise SnapshotError("real cut transaction differs from its baseline prefix")
                expected = json.loads(regular(control / "expected.json", 16384))
                baseline_expected = json.loads(regular(baseline / "expected.json", 16384))
                # Fresh ubiformat seeds may differ in image sequence. Protected
                # flash is compared with this cut guest's own pre-install hash.
                if expected["files"] != baseline_expected["files"]:
                    raise SnapshotError("cut guest uses different transaction payload bytes")
                original, qmp, debugger = capture(schema, owner, result["binding"], token, control / "flash", boundary)
                try:
                    owner.discard()  # Actual cut: kernel RAM is never resumed or saved.
                finally:
                    debugger.close()
                    qmp.close()
            replay_token = secrets.token_hex(32)
            with launch(args, case / "replay-vm", control, replay_token, replay_path=control / "flash") as owner:
                replayed = wait_message(owner, control, "replayed.json")
                restored, qmp, debugger = capture(schema, owner, replayed["binding"], replay_token,
                                                  control / "replayed-flash", boundary)
                try:
                    if restored != original:
                        raise SnapshotError("fresh raw owner replay changed allocation, OOB, bad blocks or BBT")
                    (control / "verify-request.json").write_text(json.dumps(
                        {"token": replay_token, "action": "verify-transaction"}) + "\n")
                    qmp.call("cont")
                finally:
                    debugger.close()
                    qmp.close()
                verified = wait_message(owner, control, "verified.json")
                if owner.launcher.wait(timeout=120) != 0:
                    raise SnapshotError("fresh guest transaction-state verification failed")
            print(json.dumps({"cut": number, "boundary": boundary, "result": verified}), flush=True)
    return len(events), len(cuts)


def main():
    def interrupted(number, frame):
        # An external deadline must unwind the owned-launch context so its
        # private QEMU cannot survive a terminated wrapper holding no lock.
        raise SystemExit(128 + number)
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--writer", type=Path, required=True)
    parser.add_argument("--layout", choices=("canonical", "blank", "vendor"), default="canonical")
    parser.add_argument("--accel", choices=("tcg", "kvm"), default="tcg",
                        help="explicit local QEMU accelerator; unavailable KVM fails without fallback")
    parser.add_argument("--cuts", default="all", help="all, or ascending comma-separated census indices for focused diagnosis")
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    for name in ("bundle", "kernel", "writer"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    schema = preflight(args)
    if args.preflight_only:
        print("Exact kernel/module/BTF/window-writer prerequisites verified; no VM started")
        return
    with tempfile.TemporaryDirectory(prefix="dcent-am2-cut-") as temporary:
        total, checked_cuts = rehearse(args, schema, Path(temporary))
    print(f"AM2_LOGICAL_POWERCUT_OK layout={args.layout} verified={checked_cuts} census={total}")


if __name__ == "__main__":
    main()
