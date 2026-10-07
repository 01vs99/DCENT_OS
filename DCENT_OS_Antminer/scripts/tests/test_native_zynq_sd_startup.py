"""Execute exact shell control flow in a path-rebased, stubbed host namespace.

The kernel and privileged commands are explicit fixtures. This exercises
failure propagation and readiness ordering, not mounts or physical hardware.
"""

import os
from pathlib import Path
import re
import subprocess

import pytest

OVERLAY = (
    Path(__file__).resolve().parents[2]
    / "br2_external_dcentos/board/zynq/native-sd/rootfs-overlay"
)
TARGETS = (
    "am1-s9i",
    "am1-s9j",
    "am2-s17p",
    "am2-s17plus",
    "am2-t17",
    "am2-t17plus",
    "am2-s19pro",
)
pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="actual POSIX shell namespace fixture"
)


def executable(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def namespace(tmp_path, source):
    root = tmp_path / "root"
    root.mkdir()
    commands = tmp_path / "commands"
    commands.mkdir()
    events = tmp_path / "events"
    events.write_text("")
    count = tmp_path / "mount-count"
    helper_count = tmp_path / "helper-count"
    for path in (
        "etc/dcentos",
        "dev",
        "proc/sys/kernel/random",
        "sys/class",
        "run",
        "tmp",
        "data",
        "root",
        "usr/bin",
    ):
        (root / path).mkdir(parents=True, exist_ok=True)
    (root / "etc/hostname").write_text("dcentos-test\n")
    (root / "proc/sys/kernel/random/boot_id").write_text(
        "943abf27-74a5-4cfa-8eab-bfedec7f268e\n"
    )
    for name in ("mount", "mknod", "ln", "chmod", "hostname", "ip", "sync"):
        executable(
            commands / name,
            "#!/bin/sh\n"
            'printf "%s\\n" "'
            + name
            + ':$*" >> "$EVENTS"\n'
            + (
                'n=0; [ ! -f "$COUNT" ] || n=$(cat "$COUNT"); n=$((n+1)); echo "$n" > "$COUNT"\n'
                '[ "$n" != "$FAIL_MOUNT" ] || exit 77\n'
                if name == "mount"
                else ""
            )
            + "exit 0\n",
        )
    executable(
        root / "usr/bin/python3",
        "#!/bin/sh\n"
        'printf "%s\\n" "helper:$*" >> "$EVENTS"\n'
        'n=0; [ ! -f "$HELPER_COUNT" ] || n=$(cat "$HELPER_COUNT"); n=$((n+1)); echo "$n" > "$HELPER_COUNT"\n'
        '[ "$n" != "$FAIL_HELPER" ] || exit 78\n',
    )
    original = source.read_text(encoding="utf-8")
    # Rebase every fixed absolute path prefix. The product has no test-root
    # environment option and remains unchanged by this observer.
    rewritten = re.sub(
        r"(?<![A-Za-z0-9_./-])/(?:etc|proc|sys|dev|tmp|run|data|root|usr)(?=/|\b)",
        lambda match: str(root) + match.group(),
        original,
    )
    script = tmp_path / "observed.sh"
    executable(script, rewritten)
    assert str(root) + "/proc/sys/kernel/random/boot_id" in rewritten
    assert "/proc" + str(root) not in rewritten
    env = {
        **os.environ,
        "PATH": str(commands) + ":/usr/bin:/bin",
        "EVENTS": str(events),
        "COUNT": str(count),
        "HELPER_COUNT": str(helper_count),
        "FAIL_MOUNT": "-1",
        "FAIL_HELPER": "-1",
    }
    return root, script, env, events


@pytest.mark.parametrize("target", TARGETS)
def test_complete_startup_orders_storage_before_readiness(tmp_path, target):
    root, script, env, events = namespace(
        tmp_path, OVERLAY / "etc/dcentos-early-init.sh"
    )
    (root / "etc/dcentos/board_target").write_text(target + "\n")
    result = subprocess.run(
        ["/bin/sh", str(script)], env=env, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    rows = events.read_text().splitlines()
    helper = [i for i, row in enumerate(rows) if row.startswith("helper:")]
    binds = [i for i, row in enumerate(rows) if row.startswith("mount:--bind")]
    assert len(helper) == 3 and len(binds) == 2
    assert helper[0] < binds[0] < binds[1] < helper[1] < helper[2]
    assert rows[helper[1]].endswith("/native-zynq-sd-ssh.py")
    assert rows[helper[2]].endswith(" --verify")
    assert (root / "run/dcentos/native-zynq-sd-ready").read_bytes() == (
        root / "proc/sys/kernel/random/boot_id"
    ).read_bytes()
    assert not any(
        word in events.read_text()
        for word in ("nand", "ubi", "fw_setenv", "devmem", "fpga load")
    )


@pytest.mark.parametrize(
    "fault",
    [
        "foreign",
        "ephemeral",
        "ephemeral_symlink",
        "helper1",
        "helper2",
        "helper3",
        "mount3",
        "mount4",
        "mount5",
        "mount6",
        "mount7",
        "mount8",
    ],
)
def test_startup_failure_never_publishes_ready(tmp_path, fault):
    root, script, env, events = namespace(
        tmp_path, OVERLAY / "etc/dcentos-early-init.sh"
    )
    (root / "etc/dcentos/board_target").write_text(
        "am1-s9se\n" if fault == "foreign" else "am2-s17p\n"
    )
    marker = root / "etc/dcentos/external-media-ephemeral-root"
    if fault == "ephemeral":
        marker.write_text("1\n")
    if fault == "ephemeral_symlink":
        marker.symlink_to(root / "missing")
    if fault.startswith("helper"):
        env["FAIL_HELPER"] = fault[-1]
    if fault.startswith("mount"):
        env["FAIL_MOUNT"] = fault[-1]
    result = subprocess.run(
        ["/bin/sh", str(script)], env=env, capture_output=True, text=True
    )
    assert result.returncode != 0
    assert not (root / "run/dcentos/native-zynq-sd-ready").exists()
    if fault in {"foreign", "ephemeral", "ephemeral_symlink"}:
        assert events.read_text() == ""


@pytest.mark.parametrize(
    "fault", ["none", "missing", "old_boot", "symlink", "verification"]
)
def test_persistent_service_requires_current_boot_and_actual_storage(tmp_path, fault):
    root, script, env, events = namespace(
        tmp_path, OVERLAY / "etc/init.d/S45persistent"
    )
    ready = root / "run/dcentos/native-zynq-sd-ready"
    ready.parent.mkdir(exist_ok=True)
    boot = root / "proc/sys/kernel/random/boot_id"
    if fault == "symlink":
        ready.symlink_to(boot)
    elif fault != "missing":
        ready.write_text("prior-boot\n" if fault == "old_boot" else boot.read_text())
    if fault == "verification":
        env["FAIL_HELPER"] = "1"
    result = subprocess.run(
        ["/bin/sh", str(script), "start"], env=env, capture_output=True, text=True
    )
    assert (result.returncode == 0) == (fault == "none")
    if fault in {"missing", "old_boot", "symlink"}:
        assert events.read_text() == ""
    if fault == "none":
        assert events.read_text().strip().endswith(" --verify")
