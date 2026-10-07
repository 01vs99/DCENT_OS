"""Execute S70's real shell flow with inert verification/process commands."""

import hashlib
import os
from pathlib import Path
import re
import subprocess

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "br2_external_dcentos/board/zynq/native-sd/rootfs-overlay/etc/init.d/S70dcentos-discovery"
)
pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="POSIX shell process-admission fixture"
)


def write_exec(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o755)


@pytest.mark.parametrize(
    "fault",
    [
        "none",
        "storage",
        "missing_binary",
        "binary_symlink",
        "nonexecutable",
        "wrong_hash",
        "missing_hash",
        "launch_failure",
        "missing_log_parent",
    ],
)
def test_start_requires_storage_and_exact_executable_before_dispatch(tmp_path, fault):
    root = tmp_path / "root"
    for name in ("usr/bin", "etc/dcentos", "tmp", "run"):
        (root / name).mkdir(parents=True)
    commands = tmp_path / "commands"
    events = tmp_path / "events"
    events.write_text("")
    write_exec(
        root / "usr/bin/python3",
        b'#!/bin/sh\nprintf "verify:%s\\n" "$*" >> "$EVENTS"\n[ "$FAIL_STORAGE" != 1 ]\n',
    )
    write_exec(
        commands / "start-stop-daemon",
        b'#!/bin/sh\nprintf "dispatch:%s\\n" "$*" >> "$EVENTS"\n[ "$FAIL_LAUNCH" != 1 ]\n',
    )
    executable = root / "usr/bin/dcentos-discovery"
    write_exec(executable, b"inert native byte fixture; never executed\n")
    digest = root / "etc/dcentos/dcentos-discovery.sha256"
    digest.write_text(hashlib.sha256(executable.read_bytes()).hexdigest() + "\n")
    if fault == "missing_binary":
        executable.unlink()
    elif fault == "binary_symlink":
        held = root / "held"
        executable.rename(held)
        executable.symlink_to(held)
    elif fault == "nonexecutable":
        executable.chmod(0o644)
    elif fault == "wrong_hash":
        digest.write_text("0" * 64 + "\n")
    elif fault == "missing_hash":
        digest.unlink()
    elif fault == "missing_log_parent":
        (root / "tmp").rmdir()
    text = re.sub(
        r"(?<![A-Za-z0-9_./-])/(?:usr|etc|tmp|run)(?=/|\b)",
        lambda m: str(root) + m.group(),
        SCRIPT.read_text(),
    )
    observed = tmp_path / "observed.sh"
    write_exec(observed, text.encode())
    env = {
        **os.environ,
        "PATH": str(commands) + ":/usr/bin:/bin",
        "EVENTS": str(events),
        "FAIL_STORAGE": str(int(fault == "storage")),
        "FAIL_LAUNCH": str(int(fault == "launch_failure")),
    }
    result = subprocess.run(
        ["/bin/sh", str(observed), "start"],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    rows = events.read_text().splitlines()
    assert rows[0].startswith("verify:") and rows[0].endswith(" --verify")
    assert (result.returncode == 0) == (fault == "none")
    if fault in {"none", "launch_failure"}:
        assert (
            len(rows) == 2
            and rows[1]
            == f"dispatch:-S -b -m -p {root}/run/dcentos-discovery.pid --exec {executable} -- --interval-seconds 60 --api-port 8080"
        )
    else:
        assert len(rows) == 1


@pytest.mark.parametrize("action", ["", "inspect", "--gpio-button"])
def test_unknown_actions_never_call_absolute_helpers(tmp_path, action):
    # This branch reaches no absolute path, so execute the original script.
    result = subprocess.run(
        ["/bin/sh", str(SCRIPT), action], capture_output=True, text=True, timeout=5
    )
    assert result.returncode == 1 and result.stdout == "" and result.stderr == ""
