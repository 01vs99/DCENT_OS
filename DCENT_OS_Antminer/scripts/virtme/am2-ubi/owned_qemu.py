"""Local test-only control of the QEMU descendant started by this runner.

Only AF_UNIX sockets inside a private runner directory are supported. Both
socket peer PID and the retained process start time/executable must match.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import subprocess
import time

from nandsim_snapshot import SnapshotError, regular


def process_identity(pid: int):
    if type(pid) is not int or pid <= 1:
        raise SnapshotError("ordinary owned QEMU PID required")
    raw = Path(f"/proc/{pid}/stat").read_text()
    end = raw.rfind(")")
    if end < 0 or raw[:raw.find("(")].strip() != str(pid):
        raise SnapshotError("process stat identity differs")
    fields = raw[end+2:].split()
    if len(fields) < 20 or fields[0] in ("Z", "X"):
        raise SnapshotError("QEMU process has exited")
    executable = Path(f"/proc/{pid}/exe").stat()
    return int(fields[19]), int(fields[2]), (executable.st_dev, executable.st_ino, executable.st_size)


class OwnedQemu:
    def __init__(self, launcher, directory: Path):
        self.launcher = launcher
        self.directory = directory
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise SnapshotError("private runner-owned QEMU directory required")
        self.qmp_path, self.gdb_path = directory / "qmp.sock", directory / "gdb.sock"
        self.pid, self.identity = None, None

    def bind(self, *, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.launcher.poll() is not None:
                raise SnapshotError("QEMU launcher exited before binding")
            pidfile = self.directory / "qemu.pid"
            if pidfile.exists():
                raw = regular(pidfile, 32).strip()
                if not raw:
                    # QEMU creates the file before publishing its PID. The
                    # private empty file grants no process authority yet.
                    time.sleep(0.05)
                    continue
                if not raw.isdigit():
                    raise SnapshotError("invalid owned QEMU PID file")
                pid = int(raw)
                identity = process_identity(pid)
                if identity[1] != self.launcher.pid:
                    raise SnapshotError("QEMU is outside the owned launch process group")
                command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
                executable = os.readlink(f"/proc/{pid}/exe")
                if (not Path(executable).name.startswith("qemu-system-")
                        or not any(str(self.qmp_path).encode() in value for value in command)
                        or not any(str(self.gdb_path).encode() in value for value in command)
                        or str(pidfile).encode() not in command):
                    raise SnapshotError("QEMU command is not this runner's private instance")
                self.pid, self.identity = pid, identity
                return
            time.sleep(0.05)
        raise SnapshotError("owned QEMU binding deadline expired")

    def check(self):
        if self.pid is None or process_identity(self.pid) != self.identity:
            raise SnapshotError("QEMU exited, execed or reused its PID")

    def connect(self, path: Path):
        self.check()
        info = path.lstat()
        if path.parent != self.directory or not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
            raise SnapshotError("runner-owned local debugger socket required")
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(10)
        try:
            client.connect(str(path))
            peer, uid, _ = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if peer != self.pid or uid != os.getuid():
                raise SnapshotError("local debugger socket belongs to a foreign process")
            self.check()
            return client
        except BaseException:
            client.close()
            raise

    def discard(self):
        """Power loss: no QMP quit, guest sync, filesystem unmount or resume."""
        self.check()
        os.kill(self.pid, signal.SIGKILL)
        try:
            self.launcher.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.launcher.terminate()
            self.launcher.wait(timeout=15)


class Qmp:
    def __init__(self, owner: OwnedQemu):
        self.owner = owner
        self.socket = owner.connect(owner.qmp_path)
        self.file = self.socket.makefile("rb")
        self.counter = 0
        if "QMP" not in self._read():
            raise SnapshotError("QMP greeting absent")
        self.call("qmp_capabilities")

    def _read(self):
        line = self.file.readline(65537)
        if not line.endswith(b"\n") or len(line) > 65536:
            raise SnapshotError("bounded complete QMP response required")
        value = json.loads(line)
        if not isinstance(value, dict):
            raise SnapshotError("QMP object required")
        return value

    def call(self, command, arguments=None):
        self.owner.check()
        self.counter += 1
        message = {"execute": command, "id": self.counter}
        if arguments is not None:
            message["arguments"] = arguments
        self.socket.sendall(json.dumps(message).encode() + b"\n")
        for _ in range(100):
            value = self._read()
            if "event" in value:
                continue
            if value.get("id") != self.counter or "return" not in value or "error" in value:
                raise SnapshotError("QMP operation failed or response binding differs")
            self.owner.check()
            return value["return"]
        raise SnapshotError("QMP event bound exceeded")

    def stop(self):
        self.call("stop")
        status = self.call("query-status")
        if status.get("running") is not False or status.get("status") != "paused":
            raise SnapshotError("all QEMU CPUs must be paused before flash capture")

    def close(self):
        self.file.close()
        self.socket.close()


class Debugger:
    def __init__(self, owner: OwnedQemu):
        self.owner = owner
        self.socket = owner.connect(owner.gdb_path)
        self._pending = b""
        self._position = 0

    def _byte(self):
        if self._position == len(self._pending):
            self._pending = self.socket.recv(4096)
            self._position = 0
            if not self._pending:
                raise SnapshotError("local debugger disconnected")
        raw = self._pending[self._position:self._position + 1]
        self._position += 1
        return raw

    def request(self, body: bytes) -> bytes:
        self.owner.check()
        self.socket.sendall(b"$" + body + b"#" + f"{sum(body)&255:02x}".encode())
        if self._byte() != b"+" or self._byte() != b"$":
            raise SnapshotError("debugger packet acknowledgement differs")
        data = bytearray()
        while len(data) <= 8192:
            byte = self._byte()
            if byte == b"#":
                checksum = self._byte() + self._byte()
                if checksum != f"{sum(data)&255:02x}".encode():
                    raise SnapshotError("debugger packet checksum differs")
                self.socket.sendall(b"+")
                self.owner.check()
                decoded = bytearray()
                position = 0
                while position < len(data):
                    value = data[position]
                    position += 1
                    if value == ord("}"):
                        if position == len(data):
                            raise SnapshotError("incomplete debugger escape")
                        decoded.append(data[position] ^ 0x20)
                        position += 1
                    elif value == ord("*"):
                        if not decoded or position == len(data) or not 3 <= data[position] - 29 <= 97:
                            raise SnapshotError("invalid debugger repeat encoding")
                        decoded.extend(bytes([decoded[-1]]) * (data[position] - 29))
                        position += 1
                    else:
                        decoded.append(value)
                    if len(decoded) > 8192:
                        raise SnapshotError("decoded debugger reply exceeds bound")
                return bytes(decoded)
            data.extend(byte)
        raise SnapshotError("debugger reply exceeds bound")

    def read(self, address: int, size: int) -> bytes:
        result = bytearray()
        while len(result) < size:
            count = min(2048, size - len(result))
            raw = self.request(f"m{address+len(result):x},{count:x}".encode())
            if len(raw) != count * 2 or any(c not in b"0123456789abcdefABCDEF" for c in raw):
                raise SnapshotError("debugger did not return exact guest memory bytes")
            result.extend(bytes.fromhex(raw.decode()))
        return bytes(result)

    def close(self):
        self.socket.close()
