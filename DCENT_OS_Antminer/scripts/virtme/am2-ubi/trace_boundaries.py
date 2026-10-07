#!/usr/bin/env python3
"""Observe logical writes by the actual native x86-64 guest transaction.

Utilities retain their real syscalls. Ptrace pauses the child at a syscall or
exit boundary; the host then stops all QEMU CPUs and saves only simulated NAND.
No target script hooks, fake successful tools, or physical power claim exists.
"""
from __future__ import annotations

import ctypes
import errno
import json
import os
from pathlib import Path
import signal
import stat
import struct
import time

from nandsim_snapshot import SnapshotError


TRACEME, PEEKDATA, SYSCALL, GETREGS, SETOPTIONS, GETEVENTMSG = 0, 2, 24, 12, 0x4200, 0x4201
GET_SYSCALL_INFO = 0x420E
OPTIONS = 1 | 2 | 4 | 8 | 16 | 64 | 0x100000  # syscall, fork/vfork/clone/exec/exit, EXITKILL
REG_NAMES = "r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs".split()


class Registers(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in REG_NAMES]


def ptrace(operation, pid, address=0, value=0):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    ctypes.set_errno(0)
    result = libc.ptrace(ctypes.c_uint(operation), ctypes.c_uint(pid), ctypes.c_void_p(address),
                        value if not isinstance(value, int) else ctypes.c_void_p(value))
    failure = ctypes.get_errno()
    if result == -1 and failure:
        raise OSError(failure, os.strerror(failure))
    return result


def string(pid, address):
    raw = bytearray()
    while len(raw) < 4096:
        word = struct.pack("<Q", ptrace(PEEKDATA, pid, address + len(raw)) & 0xffffffffffffffff)
        raw.extend(word)
        if b"\0" in word:
            return bytes(raw).split(b"\0", 1)[0].decode("utf-8", errors="strict")
    raise SnapshotError("trace path exceeds bound")


def _unescape(value):
    for escape, character in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\")):
        value = value.replace(escape, character)
    return value


def _filesystem(pid, path):
    matches = []
    for line in Path(f"/proc/{pid}/mountinfo").read_text().splitlines():
        left, separator, right = line.partition(" - ")
        if not separator:
            raise SnapshotError("malformed trace mount inventory")
        mount = _unescape(left.split()[4])
        if path == mount or path.startswith(mount.rstrip("/") + "/"):
            matches.append((len(mount), right.split()[0], mount))
    return max(matches, default=(0, "", ""))[1:]


def fd_role(pid, descriptor):
    try:
        descriptor_path = f"/proc/{pid}/fd/{descriptor}"
        path = os.readlink(descriptor_path)
        info = os.stat(descriptor_path)
    except FileNotFoundError:
        return None
    if stat.S_ISCHR(info.st_mode):
        # The real FD may name a bind-mounted chroot /dev. Bind the kernel's
        # character-device name, not a textual /dev prefix or caller alias.
        event = Path(f"/sys/dev/char/{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}/uevent")
        if event.exists():
            names = [line[8:] for line in event.read_text().splitlines() if line.startswith("DEVNAME=")]
            if len(names) == 1:
                name = names[0]
                if (name == "ubi_ctrl" or name.startswith("mtd") and name[3:].isdigit()
                        or name.startswith("ubi") and all(part.isdigit() for part in name[3:].split("_"))):
                    return "device:" + name
        return None
    # proc fd links are rendered relative to the observer's root. A tracee
    # chroot shortens its own mountinfo paths, so comparing this host-visible
    # link against that inventory would silently miss its UBIFS writes.
    kind, mount = _filesystem(os.getpid(), path)
    if kind == "ubifs":
        return "ubifs:" + path[len(mount):].lstrip("/")
    return None


def path_role(pid, path, directory=-100):
    if path.startswith("/"):
        resolved = os.path.normpath(os.readlink(f"/proc/{pid}/root") + "/" + path.lstrip("/"))
    else:
        base = os.readlink(f"/proc/{pid}/cwd" if directory == -100 else f"/proc/{pid}/fd/{directory}")
        resolved = os.path.normpath(base + "/" + path)
    kind, mount = _filesystem(os.getpid(), resolved)
    if kind == "ubifs":
        return "ubifs:" + resolved[len(mount):].lstrip("/")
    return None


# The census records one completed logical utility operation, including its
# number of actual write syscalls. Unknown persistent writers fail the census.
WRITERS = frozenset(("ubiformat", "ubirmvol", "ubimkvol", "ubiupdatevol", "am2-nand-window",
                    "fw_setenv", "cp", "mv", "rm", "mkdir", "rmdir", "chmod", "tar"))
BARRIERS = frozenset(("sync", "mount", "umount", "ubiattach", "ubidetach", "ubiblock"))


def ioctl_mutates(command):
    # Direction means userspace argument transfer, not flash mutation. In
    # particular MEMGETBADBLOCK is _IOW and MEMREADOOB is _IOWR. Conversely
    # OTPLOCK is _IOR. These are the actual Linux MTD/UBI UAPI operation IDs.
    group, number = command >> 8 & 255, command & 255
    if group == ord("M"):
        if number in (2, 3, 5, 6, 12, 16, 20, 21, 24, 25):
            return True
        if number in (1, 4, 7, 8, 10, 11, 13, 14, 15, 17, 18, 19, 22, 23, 26):
            return False
        raise SnapshotError("unclassified MTD ioctl")
    if group == ord("o"):
        if number in (0, 1, 2, 3, 4, 5, 64, 65):
            return True
        raise SnapshotError("unclassified UBI device ioctl")
    if group == ord("O"):
        if number in (0, 1, 2, 3, 4, 6, 7, 8):
            return True
        if number == 5:
            return False
        raise SnapshotError("unclassified UBI volume ioctl")
    return bool(command & 0x40000000)


def syscall_role(pid, regs, *, fd_classifier=fd_role, path_classifier=path_role):
    number = regs.orig_rax
    args = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9]
    # Direct writes, vectored writes, splice/copy destinations, truncate and
    # fsync. Pwrite on mtd4 exposes the redundant environment's actual edges.
    fd_argument = {1: 0, 18: 0, 20: 0, 40: 0, 74: 0, 75: 0, 77: 0, 91: 0,
                   275: 2, 285: 0, 296: 0, 306: 0, 326: 2, 328: 0}.get(number)
    if fd_argument is not None:
        return fd_classifier(pid, ctypes.c_int(args[fd_argument]).value)
    if number == 16:
        role = fd_classifier(pid, ctypes.c_int(args[0]).value)
        return role if role and ioctl_mutates(args[1]) else None
    if number == 9 and args[2] & 2 and args[3] & 1:  # Writable MAP_SHARED.
        if fd_classifier(pid, ctypes.c_int(args[4]).value):
            raise SnapshotError("persistent writable mmap has no admitted syscall cut boundary")
    # Renaming a volatile source into UBIFS mutates the destination even when
    # no persistent source descriptor was opened. Check both sides, including
    # renameat2 exchange; hard links likewise alter the destination namespace.
    pairs = {82: ((0, None), (1, None)), 86: ((0, None), (1, None)),
             264: ((1, 0), (3, 2)), 265: ((1, 0), (3, 2)), 316: ((1, 0), (3, 2))}
    if number in pairs:
        roles = []
        for index, directory in pairs[number]:
            role = path_classifier(pid, string(pid, args[index]),
                                   -100 if directory is None else ctypes.c_int(args[directory]).value)
            if role and role not in roles:
                roles.append(role)
        return " -> ".join(roles) or None
    paths = {76: (0, None), 83: (0, None), 84: (0, None), 87: (0, None), 88: (1, None),
             90: (0, None), 92: (0, None), 94: (0, None), 132: (0, None), 133: (0, None),
             258: (1, 0), 259: (1, 0), 260: (1, 0), 263: (1, 0), 266: (2, 1),
             268: (1, 0), 280: (1, 0)}
    if number in paths:
        index, directory = paths[number]
        return path_classifier(pid, string(pid, args[index]),
                               -100 if directory is None else ctypes.c_int(args[directory]).value)
    if number == 2 and args[1] & (os.O_CREAT | os.O_TRUNC):
        return path_classifier(pid, string(pid, args[0]))
    if number == 257 and args[2] & (os.O_CREAT | os.O_TRUNC):
        return path_classifier(pid, string(pid, args[1]), ctypes.c_int(args[0]).value)
    return None


def trace(argv, checkpoint, *, classifier=syscall_role):
    """Run the real child; checkpoint executes while that tracee is stopped."""
    if os.name != "posix" or os.uname().machine != "x86_64":
        raise SnapshotError("native x86-64 disposable Linux guest required")
    child = os.fork()
    if child == 0:
        try:
            ptrace(TRACEME, 0)
            os.kill(os.getpid(), signal.SIGSTOP)
            os.execv(argv[0], argv)
        finally:
            os._exit(127)
    tasks = {child: {"program": "sh", "pending": None, "writes": 0, "roles": set()}}
    completed = None
    try:
        while tasks:
            pid, status = os.waitpid(-1, 0x40000000)  # __WALL includes traced clone threads.
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                if pid == child:
                    completed = os.waitstatus_to_exitcode(status)
                tasks.pop(pid, None)
                continue
            if not os.WIFSTOPPED(status):
                raise SnapshotError("unexpected trace wait state")
            item = tasks.setdefault(pid, {"program": "sh", "pending": None, "writes": 0, "roles": set()})
            stopped, event = os.WSTOPSIG(status), status >> 16
            deliver = 0
            if stopped == signal.SIGSTOP:
                ptrace(SETOPTIONS, pid, 0, OPTIONS)
            elif event in (1, 2, 3):
                other = ctypes.c_ulong()
                ptrace(GETEVENTMSG, pid, 0, ctypes.byref(other))
                tasks[other.value] = {"program": item["program"], "pending": None, "writes": 0, "roles": set()}
            elif event == 4:
                command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
                item["program"] = Path(os.fsdecode(command[0])).name
            elif event == 6:
                if item["writes"] or item["program"] in BARRIERS:
                    if item["program"] not in WRITERS | BARRIERS:
                        raise SnapshotError("unclassified persistent executable: " + item["program"])
                    checkpoint({"operation": item["program"] + ":completed", "writes": item["writes"],
                                "roles": sorted(item["roles"])})
            elif stopped == signal.SIGTRAP | 0x80:
                information = ctypes.create_string_buffer(128)
                ptrace(GET_SYSCALL_INFO, pid, 128, ctypes.byref(information))
                operation = information.raw[0]
                regs = Registers()
                ptrace(GETREGS, pid, 0, ctypes.byref(regs))
                if operation == 1:
                    item["pending"] = (regs.orig_rax, classifier(pid, regs))
                elif operation == 2 and item["pending"] and ctypes.c_longlong(regs.rax).value >= 0:
                    number, role = item["pending"]
                    if role:
                        item["writes"] += 1
                        item["roles"].add(role)
                        if item["program"] in ("sh", "dash", "bash"):
                            checkpoint({"operation": f"shell:syscall-{number}", "writes": 1, "roles": [role]})
                            item["writes"] = 0
                            item["roles"].clear()
                        elif item["program"] == "fw_setenv" and number in (1, 16, 18):
                            # A successful mutating MTD ioctl includes erasing
                            # the inactive redundant environment record. Cut
                            # there too, before its later write can hide the
                            # erased-record recovery boundary. Read-only ioctls
                            # have already been excluded by syscall_role().
                            checkpoint({"operation": f"fw_setenv:syscall-{number}", "writes": 1, "roles": [role]})
                elif operation not in (1, 2):
                    raise SnapshotError("expected a kernel-reported syscall entry or exit")
            elif stopped not in (signal.SIGTRAP,):
                deliver = stopped
            ptrace(SYSCALL, pid, 0, deliver)
        if completed != 0:
            raise SnapshotError(f"actual transaction failed during boundary census: {completed}")
    finally:
        for pid in tasks:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                ptrace(7, pid, 0, signal.SIGKILL)  # Resume an EXIT event stop to reap it.
            except OSError:
                pass
        deadline = time.monotonic() + 5
        while tasks and time.monotonic() < deadline:
            try:
                pid, status = os.waitpid(-1, 0x40000000 | os.WNOHANG)
            except ChildProcessError:
                break
            if not pid:
                time.sleep(0.01)
                continue
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                tasks.pop(pid, None)
            elif os.WIFSTOPPED(status) and pid in tasks:
                try:
                    ptrace(7, pid, 0, signal.SIGKILL)
                except OSError:
                    pass
        if tasks:
            raise SnapshotError("owned tracees did not retire within the teardown bound")
