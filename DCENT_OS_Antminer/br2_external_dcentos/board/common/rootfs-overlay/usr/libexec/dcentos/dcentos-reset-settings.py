#!/usr/bin/python3
"""Reset DCENT settings after checked owner shutdown; never a firmware flasher.

Production paths are fixed. Tests import the private operation with a private
root and real fixture commands; the CLI has no path or command overrides.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 host fixtures; images use Python 3.12+.
    import tomli as tomllib

HERE = "/usr/libexec/dcentos/"
SELF = HERE + "dcentos-reset-settings.py"
CONFIRMATION = b"RESET DCENT_OS SETTINGS\n"
MARKER = "data/dcent/reset-settings"
SETTINGS = (
    "data/dcent/auth.json", "data/dcent/authorized_keys",
    "data/dcent/setup.json", "data/dcent/onboarding.json",
    "data/dcent/safety_ack.json", "data/dcent/install_intent.json",
    "data/dcentos-compat",
)


def protected(path, *, directory=False):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (not kind(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022
            or (not directory and info.st_nlink != 1)):
        raise ValueError(f"unsafe reset path: {path}")
    return info


def checked_path(root, relative, *, missing=False):
    path = root
    parts = Path(relative).parts
    for component in parts[:-1]:
        path /= component
        protected(path, directory=True)
    path /= parts[-1]
    try:
        protected(path)
    except FileNotFoundError:
        if not missing:
            raise
    return path


def atomic(path, data):
    temporary = path.with_name(path.name + f".reset-{os.getpid()}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        temporary.unlink(missing_ok=True)


def require_no_pending_restore(root):
    firstlight = root / "data/.dcent-firstlight"
    if firstlight.exists() or firstlight.is_symlink():
        protected(firstlight, directory=True)
        if any(firstlight.iterdir()):
            raise ValueError("pending or ambiguous firstlight restore bars settings reset")
    recovery = root / "data/.dcent-deploy-recovery"
    if recovery.exists() or recovery.is_symlink():
        protected(recovery, directory=True)
        for entry in recovery.iterdir():
            # S82's deploy resolver can restore config from any pending state,
            # or synthesize one from a retained lease. Completed audit runs
            # without either are historical and do not block settings reset.
            if entry.name == ".deploy-lease":
                raise ValueError("pending persistent deploy lease bars settings reset")
            protected(entry, directory=True)
            pending = entry / "persistent-transaction.state"
            if pending.exists() or pending.is_symlink():
                raise ValueError("pending persistent deploy state bars settings reset")


def reset(root, stop, status, reboot=None, *, verify, boot=False):
    """Caller holds the deploy lock. A failed stop cannot reach any removal."""
    require_no_pending_restore(root)
    default = checked_path(root, "usr/share/dcentos/default-dcentrald.toml")
    if default.stat().st_size > 1024 * 1024:
        raise ValueError("oversized immutable default")
    content = default.read_bytes()
    config = tomllib.loads(content.decode("utf-8"))
    if config.get("mining", {}).get("enabled") is not False:
        raise ValueError("image default must explicitly disable mining")
    def verify_default():
        result = subprocess.run(verify, check=True, capture_output=True, timeout=20)
        proof = json.loads(result.stdout)
        if (proof.get("settings_default_sha256") != hashlib.sha256(content).hexdigest()
                or proof.get("bytes") != len(content)):
            raise ValueError("default bytes differ from compiled-key signed image verification")
        checked_path(root, "usr/share/dcentos/default-dcentrald.toml")
        if default.read_bytes() != content:
            raise ValueError("default changed during reset")
    verify_default()
    destination = checked_path(root, "data/dcentrald.toml", missing=True)
    state = root / "data/dcent"
    protected(state, directory=True)
    marker = checked_path(root, MARKER, missing=not boot)
    if marker.exists():
        if marker.stat().st_size != len(CONFIRMATION) or marker.read_bytes() != CONFIRMATION:
            raise ValueError("invalid reset intent marker")
    selected = [checked_path(root, name, missing=True) for name in SETTINGS]
    # Quarantined auth can otherwise keep the release image configured forever.
    for path in state.glob("auth.json.corrupt.*"):
        selected.append(checked_path(root, str(path.relative_to(root))))
    # Profiles are DCENT operator settings. No recursive directory deletion:
    # refuse unexpected entries, links and subdirectories before stopping.
    profiles = state / "profiles"
    if profiles.exists() or profiles.is_symlink():
        protected(profiles, directory=True)
        for path in profiles.iterdir():
            if path.suffix != ".json":
                raise ValueError(f"unexpected settings profile: {path}")
            selected.append(checked_path(root, str(path.relative_to(root))))
    maintenance = root / "run/dcentos-deploy-maintenance"
    protected(maintenance.parent, directory=True)
    if maintenance.exists() or maintenance.is_symlink():
        protected(maintenance)
        if maintenance.stat().st_size != 15 or maintenance.read_bytes() != b"reset-settings\n":
            raise ValueError("another maintenance operation owns the start fence")
        # Deliberate operator retry, under a newly acquired kernel lock. Never
        # erase or bypass an unrelated maintenance or hardware-session marker.
    status_path = checked_path(root, "data/dcent/reset-settings-status.json", missing=True)
    # Durable intent precedes stop and settings mutation. S82 refuses any such
    # marker, even after a reboot clears /run or a worker dies mid-operation.
    if not marker.exists():
        atomic(marker, CONFIRMATION)
    def progress(phase, error=None):
        atomic(status_path, (json.dumps({"phase": phase, "unix_seconds": int(time.time()),
                                        "error": error}) + "\n").encode())
    progress("pending_shutdown")
    if not maintenance.exists():
        fd = os.open(maintenance, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write("reset-settings\n")
    try:
        subprocess.run(stop, check=True, timeout=95)
        observed = subprocess.run(status, check=True, capture_output=True, text=True, timeout=5)
        if observed.stdout.strip() != "clear":
            raise ValueError("checked shutdown did not clear the exact hardware session")
        progress("stopped")
        verify_default()
        require_no_pending_restore(root)
        checked_path(root, MARKER)
        if marker.stat().st_size != len(CONFIRMATION) or marker.read_bytes() != CONFIRMATION:
            raise ValueError("reset intent changed during checked shutdown")
        checked_path(root, "data/dcentrald.toml", missing=True)
        for path in selected:
            checked_path(root, str(path.relative_to(root)), missing=True)
        # Session/disposition journals, firmware, vendor partitions, EEPROM,
        # entropy and host keys are deliberately outside this exact allowlist.
        atomic(destination, content)
        for path in selected:
            path.unlink(missing_ok=True)
        for parent in {path.parent for path in selected}:
            directory = os.open(parent, os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        marker.unlink(missing_ok=True)
        directory = os.open(state, os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        progress("settings_reset")
        if reboot is not None:
            subprocess.run(reboot, check=True, timeout=10)
        elif not boot:
            raise ValueError("normal reset requires reboot handoff")
    except Exception as error:
        # Remain fenced on any failure, including partial removal or a refused
        # reboot. Never restart mining to hide a failed reset.
        try:
            progress("failed", str(error)[:1024])
        except OSError:
            pass
        raise
    else:
        if boot:
            maintenance.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("schedule", "run", "boot", "boot-locked"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError("settings reset requires root")
    if args.action == "schedule":
        # The retained helper owns the operation after S82 stops the API process.
        # Detach every inherited daemon descriptor, including stdout pipes.
        pid = os.fork()
        if pid:
            print(json.dumps({"status": "scheduled", "operation": "reset_settings"}))
            return
        os.setsid()
        devnull = os.open("/dev/null", os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(devnull, fd)
        os.closerange(3, 65536)
        time.sleep(2)
        os.execv(HERE + "dcentos-deploy-lock", ["dcentos-deploy-lock", "--",
                 "/usr/bin/python3", SELF, "run"])
    if args.action == "boot":
        marker = Path("/") / MARKER
        if not marker.exists() and not marker.is_symlink():
            return
        os.execv(HERE + "dcentos-deploy-lock", ["dcentos-deploy-lock", "--",
                 "/usr/bin/python3", SELF, "boot-locked"])
    # Require an actual inherited lock descriptor, not an environment claim.
    info = protected(Path("/run/dcentos-deploy-admission.lock"))
    admitted = False
    for name in os.listdir("/proc/self/fd"):
        try:
            fd = int(name)
            candidate = os.fstat(fd)
            if (candidate.st_dev, candidate.st_ino) == (info.st_dev, info.st_ino):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                admitted = True
                break
        except (OSError, ValueError):
            continue
    if not admitted:
        raise ValueError("reset requires the retained deploy-admission lock")
    reset(Path("/"), ["/etc/init.d/S82dcentrald", "stop"],
          [HERE + "dcentrald-session-latch.sh", "status"],
          None if args.action == "boot-locked" else ["/sbin/reboot"],
          verify=["/usr/local/bin/dcentrald", "--check-reset-default"],
          boot=args.action == "boot-locked")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"DCENT settings reset refused: {error}", file=sys.stderr)
        sys.exit(1)
