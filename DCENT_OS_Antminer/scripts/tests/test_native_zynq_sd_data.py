"""Data producer path custody and retained failure behavior; no device I/O."""

from pathlib import Path
import importlib
import os
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "DCENT_OS_Antminer/scripts"))
producer = importlib.import_module("native_zynq_sd.prepare_data")
pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="Linux private mkfs producer"
)


def test_existing_output_preserved(tmp_path, monkeypatch):
    job = tmp_path / "job"
    job.mkdir()
    original = job / "data.ext4"
    original.write_bytes(b"retained evidence")
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: pytest.fail("process launched")
    )
    with pytest.raises(ValueError, match="preserve"):
        producer.prepare_data(job, "am1-s9i")
    assert original.read_bytes() == b"retained evidence"


def test_symlink_output_refused(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    job = tmp_path / "job"
    job.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: pytest.fail("process launched")
    )
    with pytest.raises(ValueError, match="preserve"):
        producer.prepare_data(job, "am1-s9i")
    assert list(outside.iterdir()) == []


def test_symlink_parent_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="direct existing"):
        producer.prepare_data(alias / "job", "am1-s9i")
    assert list(outside.iterdir()) == []


def test_shared_writable_parent_refused(tmp_path):
    tmp_path.chmod(0o777)
    try:
        with pytest.raises(ValueError, match="non-writable-by-others"):
            producer.prepare_data(tmp_path / "job", "am1-s9i")
        assert list(tmp_path.iterdir()) == []
    finally:
        tmp_path.chmod(0o700)


@pytest.mark.parametrize(
    "target", ["am1-s9", "am1-s9i-extra", "am2-s17", "am2-t17plus-extra"]
)
def test_nearby_target_never_creates_job(tmp_path, target):
    with pytest.raises(ValueError, match="exact seven-route"):
        producer.prepare_data(tmp_path / "job", target)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "fault", ["mkfs-fails", "fsck-fails", "fsck-modifies", "fsck-replaces", "timeout"]
)
def test_failed_commands_retain_logs_and_no_success_receipt(
    tmp_path, monkeypatch, fault
):
    job = tmp_path / "job"
    calls = []

    def observed_run(command, **kwargs):
        calls.append(command)
        image = Path(command[-1])
        kwargs["stdout"].write(b"injected command observation\n")
        if fault == "timeout":
            raise subprocess.TimeoutExpired(command, 60)
        exit_code = 0
        if len(calls) == 1:
            if fault == "mkfs-fails":
                exit_code = 2
        elif fault == "fsck-fails":
            exit_code = 4
        elif fault == "fsck-modifies":
            with image.open("r+b") as stream:
                stream.seek(-1, os.SEEK_END)
                stream.write(b"X")
        elif fault == "fsck-replaces":
            image.rename(job / "original-data.ext4")
            with image.open("xb") as stream:
                stream.truncate(producer.DATA_BYTES)
        return subprocess.CompletedProcess(command, exit_code)

    monkeypatch.setattr(subprocess, "run", observed_run)
    with pytest.raises((ValueError, subprocess.TimeoutExpired)):
        producer.prepare_data(job, "am1-s9i")
    assert (job / "failed.json").is_file()
    assert (job / "command-0.log").read_bytes() == b"injected command observation\n"
    assert (job / "data.ext4").is_file()
    assert not (job / "data-inputs.json").exists()
    assert len(calls) == (1 if fault in {"mkfs-fails", "timeout"} else 2)
