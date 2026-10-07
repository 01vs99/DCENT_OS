#!/usr/bin/env python3
"""Real cold-idle shutdown -> fixed CLI consumer -> supervisor latch clearance.

Requires Linux root, unshare/mount, cc, strip, and an already built daemon.
The caller holds the shared heavy lock. Only a disposable copy is stripped.
The child has private mount, PID and network namespaces, with no hardware
devices or external networking. Production helper and validator code is unchanged.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

PROJECT = Path(__file__).resolve().parents[1]
HELPER = PROJECT / "br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-session-latch.sh"
PDEATH_SOURCE = PROJECT / "br2_external_dcentos/packages/dcentos-deploy-lock/src/dcentos-deploy-lock.c"
DAEMON = Path("/usr/local/bin/dcentrald")
LATCH = Path("/usr/libexec/dcentos/dcentrald-session-latch.sh")
UNRESOLVED = Path("/data/dcent/dcentrald-hardware-session.unresolved")
RECEIPT = Path("/data/dcent/dcentrald-software-closeout-v1")
JOURNAL = Path("/data/dcent/dcentrald-mutation-disposition-v1")
CRASH = Path("/data/dcent/dcentrald-hardware-session.crash-latched")
LOG = Path("/run/closeout.log")


def run(*arguments, **kwargs):
    result = subprocess.run(list(map(str, arguments)), capture_output=True,
                            text=True, timeout=30, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{arguments!r} exited {result.returncode}: "
                           + result.stdout[-4000:] + result.stderr[-4000:])
    return result


def write(path: Path, content: str, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    path.chmod(mode)


def inside(root: Path, parent_mount: int):
    # Refuse before mounting unless unshare actually created the requested
    # namespace. PID 1's exit tears down all fixture children on any failure.
    assert os.geteuid() == 0 and os.getpid() == 1
    assert os.stat("/proc/self/ns/mnt").st_ino != parent_mount
    root = root.resolve(strict=True)
    assert root.parent == Path("/var/tmp") and root.name.startswith("dcent-closeout-")
    # A private root provides every fixed production mountpoint even when the
    # host has no /data or /usr/libexec. Never mkdir a mountpoint on the host.
    # The self-bind makes / a real, persistent root mount for the actual slot
    # and persistence validators after chroot.
    run("mount", "--bind", root, root)
    for source in ("/bin", "/sbin", "/lib", "/lib64", "/usr/bin", "/usr/sbin",
                   "/usr/lib", "/usr/lib64"):
        if Path(source).is_dir():
            destination = root / source.lstrip("/")
            destination.mkdir(parents=True, exist_ok=True)
            # A user namespace cannot discard locked child mounts (WSL's
            # /usr/lib/wsl is one example). Preserve them, then protect every
            # member of this copied mount tree before entering the root.
            run("mount", "--rbind", source, destination)
            mounts = [line.split()[4] for line in Path("/proc/self/mountinfo").read_text().splitlines()]
            for mounted in sorted((path for path in mounts if path == str(destination)
                                   or path.startswith(str(destination) + "/")),
                                  key=len, reverse=True):
                run("mount", "-o", "remount,bind,ro", mounted)
    run("mount", "--rbind", "/proc", root / "proc")

    # Only generic kernel devices are exposed in the private root.
    for name in ("null", "zero", "random", "urandom"):
        destination = root / "dev" / name
        destination.touch()
        run("mount", "--bind", "/dev/" + name, destination)
    for name, target in (("fd", "/proc/self/fd"), ("stdin", "/proc/self/fd/0"),
                         ("stdout", "/proc/self/fd/1"), ("stderr", "/proc/self/fd/2")):
        (root / "dev" / name).symlink_to(target)
    os.chroot(root)
    os.chdir("/")
    assert not Path("/dev/i2c-0").exists() and not Path("/dev/uio0").exists()
    assert not Path("/sys/class/gpio").exists()
    # The network namespace starts with only a down loopback device. Binding
    # API listeners needs no interface activation and cannot reach any pool.
    assert len(Path("/proc/net/dev").read_text().splitlines()) == 3
    assert not any(path.exists() for path in (UNRESOLVED, RECEIPT, JOURNAL, CRASH))

    version = Path("/etc/dcentos-version").read_text().strip()
    assert version in run(DAEMON, "--version").stdout
    token = run("sh", LATCH, "prepare").stdout.strip()
    marker = UNRESOLVED.read_bytes()
    assert f"session_token={token}\n".encode() in marker
    supervisor = subprocess.Popen(
        ["sh", str(LATCH), "supervise", token, "/run/closeout-safety", str(LOG),
         "/run/closeout-child", "/run/closeout-expected", str(DAEMON),
         "--serial-mining", "--config", "/etc/dcentrald.toml"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            log = LOG.read_text(errors="replace") if LOG.exists() else ""
            if "Initial idle: save a pool and enable mining" in log and Path("/run/closeout-child").is_file():
                break
            assert supervisor.poll() is None, "supervisor ended before real cold idle: " + log[-8000:]
            time.sleep(0.05)
        else:
            raise AssertionError("real cold idle readiness timed out: " + log[-8000:])
        fields = Path("/run/closeout-child").read_text().split()
        assert len(fields) == 4 and fields[2] == token
        pid, start, session, boot = fields
        child_exe = Path(f"/proc/{pid}/exe").stat()
        installed = DAEMON.stat()
        assert (child_exe.st_dev, child_exe.st_ino) == (installed.st_dev, installed.st_ino)
        assert not RECEIPT.exists(), "a running idle process must not prepublish closeout"

        # Same expected-stop wire format as S82: verified PID followed by TERM.
        write(Path("/run/closeout-expected"), pid + "\n")
        os.kill(int(pid), signal.SIGTERM)
        stdout, stderr = supervisor.communicate(timeout=30)
        log = LOG.read_text(errors="replace")
        assert supervisor.returncode == 0, stdout + stderr + log[-8000:]
        assert "Recorded exact-session orderly software closeout" in log, log[-8000:]
        assert "exact-session orderly software closeout admitted restart" in log, log[-8000:]
        assert not any(path.exists() for path in (UNRESOLVED, RECEIPT, JOURNAL, CRASH))
        assert run("sh", LATCH, "status").stdout.strip() == "clear"

        # Restore only the identical fixture marker so replay reaches the
        # actual missing-receipt check, not an unrelated missing-session check.
        UNRESOLVED.write_bytes(marker)
        UNRESOLVED.chmod(0o600)
        replay = subprocess.run([str(DAEMON), "--check-software-closeout", pid, start, boot, session],
                                capture_output=True, text=True, timeout=10)
        assert replay.returncode != 0, "consumed software closeout was reusable"
        assert "No such file" in replay.stderr, replay.stderr
        assert UNRESOLVED.read_bytes() == marker and not RECEIPT.exists()
        assert not JOURNAL.exists() and not CRASH.exists()
        print("Real cold-idle publisher, fixed CLI consumer, helper clearance and one-use refusal passed.")
    finally:
        if supervisor.poll() is None:
            os.killpg(supervisor.pid, signal.SIGKILL)
            supervisor.communicate(timeout=5)


class SoftwareCloseoutIntegration(unittest.TestCase):
    daemon_path: Path

    def test_real_cold_idle_closeout_clears_once(self):
        self.assertEqual(sys.platform, "linux", "fixture requires Linux namespaces")
        self.assertEqual(os.geteuid(), 0, "fixture requires root in the isolated Linux test environment")
        for tool in ("unshare", "mount", "cc", "strip"):
            self.assertIsNotNone(shutil.which(tool), f"missing mandatory fixture tool: {tool}")
        original = self.daemon_path.resolve(strict=True)
        before = original.stat()
        with tempfile.TemporaryDirectory(prefix="dcent-closeout-", dir="/var/tmp") as temporary:
            root = Path(temporary)
            for name in ("etc", "data", "run", "tmp", "usr/local/bin", "usr/libexec/dcentos", "sys", "dev", "proc"):
                (root / name).mkdir(parents=True)
            # Debian's /usr/bin/awk resolves through /etc/alternatives. Keep
            # that executable link available after hiding the host /etc.
            (root / "etc/alternatives").mkdir()
            (root / "etc/alternatives/awk").symlink_to(Path("/usr/bin/awk").resolve(strict=True))
            daemon = root / "usr/local/bin/dcentrald"
            shutil.copyfile(original, daemon)
            daemon.chmod(0o700)
            run("strip", "--strip-all", daemon)
            self.assertLessEqual(daemon.stat().st_size, 256 * 1024 * 1024)
            shutil.copyfile(HELPER, root / "usr/libexec/dcentos/dcentrald-session-latch.sh")
            run("cc", "-O2", "-std=c11", PDEATH_SOURCE, "-o", root / "usr/libexec/dcentos/dcentos-deploy-lock")
            workspace = (PROJECT / "dcentrald/Cargo.toml").read_text()
            version = re.search(r'^version = "([^"]+)"$', workspace, re.MULTILINE).group(1)
            for name, value in (("board_target", "am3-s21"), ("platform", "am3-aml-s21"), ("rail_gpio", "437")):
                write(root / "etc/dcentos" / name, value + "\n", 0o644)
            write(root / "etc/dcentos-version", version + "\n", 0o644)
            write(root / "etc/dcentrald.toml", '''[general]
log_level = "info"
[pool]
url = ""
worker = ""
password = "x"
[mining]
enabled = false
passthrough = false
model = "s21"
serial_chip_type = "BM1368"
[api]
http_bind = "127.0.0.1"
http_port = 0
cgminer_port = 0
cgminer_bind_lan = false
''')
            # Cold idle owns no hardware. This fixture supplies only the
            # supervisor's successful containment boundary; it cannot create
            # the daemon receipt or make the real validator accept one.
            write(root / "run/closeout-safety", '''#!/bin/sh
[ "$1" = safety ] && [ ! -e /dev/i2c-0 ] && [ ! -e /dev/uio0 ] && [ ! -e /sys/class/gpio ]
''', 0o700)
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith(("DCENT", "S19K", "RUST_LOG"))}
            environment.update(TMPDIR="/tmp", LC_ALL="C")
            command = ["unshare", "--mount", "--net", "--pid", "--fork", "--mount-proc",
                       "--kill-child=KILL", "--propagation", "private", sys.executable,
                       str(Path(__file__).resolve()), "--inside", str(root),
                       "--parent-mount", str(os.stat("/proc/self/ns/mnt").st_ino)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=90, env=environment)
            self.assertEqual(result.returncode, 0, result.stdout[-8000:] + result.stderr[-8000:])
            self.assertIn("one-use refusal passed", result.stdout)
        after = original.stat()
        self.assertEqual((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
                         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", type=Path)
    parser.add_argument("--inside", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--parent-mount", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inside is not None:
        inside(args.inside, args.parent_mount)
    else:
        if args.daemon is None:
            parser.error("--daemon must name an already built production daemon")
        SoftwareCloseoutIntegration.daemon_path = args.daemon
        result = unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(SoftwareCloseoutIntegration))
        raise SystemExit(0 if result.wasSuccessful() else 1)
