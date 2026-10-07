"""Private host-root finalization and refusal controls; inert fixture contents."""

from pathlib import Path
import hashlib
import importlib
import json
import os
import sys
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "DCENT_OS_Antminer/scripts"))
finalizer = importlib.import_module("native_zynq_sd.finalize_root")
pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="Linux Buildroot-only file finalizer"
)

_runtime_daemon = None


@pytest.fixture(scope="module", autouse=True)
def signed_runtime_fixture(tmp_path_factory):
    from test_runtime_image_manifest import fixture
    global _runtime_daemon
    key, pubkey, daemon = fixture(tmp_path_factory.mktemp("native-runtime-identity"))
    _runtime_daemon = daemon.read_bytes()
    with patch.dict(os.environ, DCENT_RELEASE_SIGNING_KEY=str(key), DCENT_RELEASE_PUBKEY_FILE=str(pubkey), DCENT_RELEASE_CHANNEL="beta", DCENT_RELEASE_HARDWARE_RECIPE="board-default"):
        yield


def pinned(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "mode": 0o755}


def fresh(tmp_path, target="am2-s17p"):
    job = tmp_path / "job"
    root = job / "buildroot-output/target"
    root.mkdir(parents=True)
    for name in (
        "etc/init.d",
        "etc/dcentos",
        "data",
        "usr/bin",
        "usr/sbin",
        "usr/local/bin",
        "usr/libexec/dcentos",
        "bin",
    ):
        (root / name).mkdir(parents=True)
    services = finalizer.COMMON_SERVICES | (
        {"S12fpga_identity"} if target.startswith("am2-") else set()
    )
    overlay = {"usr/local/bin/dcentrald": pinned(_runtime_daemon)}
    (root / "usr/local/bin/dcentrald").write_bytes(_runtime_daemon)
    (root / "etc/dcentos-version").write_text("1.2.3\n")
    (root / "etc/dcentos/board_target").write_text(target + "\n")
    for name in services | {"rcS", "rcK", "S99upgrade", "S50telnet"}:
        raw = ("inert " + name).encode()
        (root / "etc/init.d" / name).write_bytes(raw)
        (root / "etc/init.d" / name).chmod(0o755)
        if name in services and name not in {
            "S01syslogd",
            "S02klogd",
            "S02sysctl",
            "S10udevd",
        }:
            overlay["etc/init.d/" + name] = pinned(raw)
    for name in (
        "usr/libexec/dcentos/dcentos-deploy-lock",
        "usr/libexec/dcentos/dcentos-deploy-path",
        "usr/sbin/seed-entropy",
        "bin/busybox",
    ):
        path = root / name
        path.write_bytes(b"\x7fELFinert dependency; not executable content")
        path.chmod(0o755)
    (root / "etc/shadow").write_text("root:*:1:0:99999:7:::\n")
    manifest = {
        "schema": "dcentos.native_zynq_sd_build_inputs.v1",
        "board_target": target,
        "job_root": str(job),
        "target_dir": str(root),
        "services": sorted(services),
        "overlay": overlay,
    }
    path = job / "inputs.json"
    path.write_text(json.dumps(manifest))
    return job, root, path, manifest


@pytest.mark.parametrize("target", ["am1-s9i", "am2-s17p"])
def test_private_target_finalization_binds_alias_and_exact_services(tmp_path, target):
    job, root, path, manifest = fresh(tmp_path, target)
    result = finalizer.finalize(root, path)
    left, right = (
        (root / "usr/local/bin/dcentrald").stat(),
        (root / "usr/bin/dcentrald").stat(),
    )
    assert (left.st_dev, left.st_ino, left.st_nlink) == (right.st_dev, right.st_ino, 2)
    assert set(result["services"]) == set(manifest["services"]) | {"rcS", "rcK"}
    assert result["removed_generated_services"] == ["S50telnet", "S99upgrade"]
    assert json.loads((job / "root-finalization.json").read_text()) == result
    with pytest.raises(ValueError, match="previous root finalization"):
        finalizer.finalize(root, path)


@pytest.mark.parametrize(
    "fault",
    [
        "foreign_target",
        "extra_service",
        "missing_service",
        "wrong_root",
        "unlocked_password",
        "duplicate_root",
        "changed_overlay",
        "overlay_symlink",
        "overlay_hardlink",
        "missing_helper",
        "nonexec_helper",
        "helper_symlink",
        "nonfile_startup",
        "persistent_override",
        "nand_control",
        "old_ephemeral",
        "old_alias",
        "shadow_hardlink",
        "shadow_symlink",
        "short_shadow",
        "generated_symlink",
        "generated_hardlink",
        "generated_directory",
        "generated_nonexec",
        "missing_rcK",
        "generated_fifo",
    ],
)
def test_preflight_faults_preserve_existing_root_and_never_commit(tmp_path, fault):
    job, root, path, manifest = fresh(tmp_path)
    daemon = root / "usr/local/bin/dcentrald"
    if fault == "foreign_target":
        manifest["board_target"] = "am1-s9se"
    elif fault == "extra_service":
        manifest["services"].append("S99upgrade")
    elif fault == "missing_service":
        (root / "etc/init.d/S80dashboard").unlink()
    elif fault == "wrong_root":
        manifest["target_dir"] = str(job)
    elif fault == "unlocked_password":
        (root / "etc/shadow").write_text("root:dcentral:1:0:99999:7:::\n")
    elif fault == "duplicate_root":
        (root / "etc/shadow").write_text("root:*:1:0:99999:7:::\n" * 2)
    elif fault == "changed_overlay":
        daemon.write_bytes(b"different")
    elif fault == "overlay_symlink":
        held = root / "held"
        daemon.rename(held)
        daemon.symlink_to(held)
    elif fault == "overlay_hardlink":
        os.link(daemon, root / "held")
    elif fault == "missing_helper":
        (root / "usr/sbin/seed-entropy").unlink()
    elif fault == "nonexec_helper":
        (root / "usr/sbin/seed-entropy").chmod(0o644)
    elif fault == "helper_symlink":
        helper = root / "usr/sbin/seed-entropy"
        helper.unlink()
        helper.symlink_to(root / "bin/busybox")
    elif fault == "nonfile_startup":
        (root / "etc/init.d/unknown-directory").mkdir()
    elif fault == "persistent_override":
        (root / "data/dcentrald.toml").write_bytes(b"unbound config")
    elif fault == "nand_control":
        (root / "usr/sbin/sysupgrade").write_bytes(b"unadmitted writer")
    elif fault == "old_ephemeral":
        (root / "etc/dcentos/external-media-ephemeral-root").write_bytes(b"old")
    elif fault == "old_alias":
        (root / "usr/bin/dcentrald").write_bytes(b"old alias")
    elif fault == "shadow_hardlink":
        os.link(root / "etc/shadow", tmp_path / "outside-shadow")
    elif fault == "shadow_symlink":
        shadow = root / "etc/shadow"
        outside = tmp_path / "outside-shadow"
        shadow.rename(outside)
        shadow.symlink_to(outside)
    elif fault == "short_shadow":
        (root / "etc/shadow").write_bytes(b"root:*\n")
    elif fault == "generated_symlink":
        script = root / "etc/init.d/S01syslogd"
        outside = tmp_path / "outside-script"
        script.rename(outside)
        script.symlink_to(outside)
    elif fault == "generated_hardlink":
        os.link(root / "etc/init.d/rcS", tmp_path / "outside-script")
    elif fault == "generated_directory":
        script = root / "etc/init.d/rcK"
        script.unlink()
        script.mkdir()
    elif fault == "generated_nonexec":
        (root / "etc/init.d/S02sysctl").chmod(0o644)
    elif fault == "missing_rcK":
        (root / "etc/init.d/rcK").unlink()
    elif fault == "generated_fifo":
        script = root / "etc/init.d/rcS"
        script.unlink()
        os.mkfifo(script)
    path.write_text(json.dumps(manifest))
    before = (root / "etc/init.d/S99upgrade").read_bytes()
    with pytest.raises((ValueError, FileNotFoundError)):
        finalizer.finalize(root, path)
    assert not (job / "root-finalization.json").exists()
    assert (root / "etc/init.d/S99upgrade").read_bytes() == before
    if fault in {"shadow_hardlink", "shadow_symlink"}:
        assert (tmp_path / "outside-shadow").stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize("fault", ["hardlink", "symlink", "fifo", "oversize"])
def test_manifest_file_kind_refuses_before_read(tmp_path, fault):
    job, root, path, _manifest = fresh(tmp_path)
    if fault == "hardlink":
        os.link(path, tmp_path / "outside-manifest")
    elif fault == "symlink":
        outside = tmp_path / "outside-manifest"
        path.rename(outside)
        path.symlink_to(outside)
    elif fault == "fifo":
        path.unlink()
        os.mkfifo(path)
    else:
        path.write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(ValueError):
        finalizer.finalize(root, path)
    assert not (job / "root-finalization.json").exists()


@pytest.mark.parametrize(
    "fault",
    [
        "manifest",
        "overlay",
        "new_service",
        "lost_mode",
        "lost_shadow_mode",
        "shadow_bytes",
        "shadow_identity",
        "generated_bytes",
        "generated_symlink",
        "generated_mode",
    ],
)
def test_late_mutation_refuses_final_receipt(tmp_path, monkeypatch, fault):
    job, root, path, manifest = fresh(tmp_path)
    original = finalizer.os.link

    def linked(source, destination):
        original(source, destination)
        if fault == "manifest":
            path.write_text(json.dumps(dict(manifest, unexpected=True)))
        elif fault == "overlay":
            (root / "etc/init.d/S80dashboard").write_bytes(b"late change")
        elif fault == "new_service":
            (root / "etc/init.d/S99upgrade").write_bytes(b"late startup")
        elif fault == "shadow_bytes":
            (root / "etc/shadow").write_bytes(b"root:changed:1:0:99999:7:::\n")
        elif fault == "shadow_identity":
            shadow = root / "etc/shadow"
            raw = shadow.read_bytes()
            shadow.rename(root / "old-shadow")
            shadow.write_bytes(raw)
        elif fault == "generated_bytes":
            (root / "etc/init.d/rcS").write_bytes(b"changed generated script")
        elif fault == "generated_symlink":
            script = root / "etc/init.d/S01syslogd"
            outside = tmp_path / "outside-script"
            script.rename(outside)
            script.symlink_to(outside)
        elif fault == "generated_mode":
            (root / "etc/init.d/rcK").chmod(0o644)

    monkeypatch.setattr(finalizer.os, "link", linked)
    if fault in {"lost_mode", "lost_shadow_mode"}:
        omitted = root / (
            "etc/init.d/S80dashboard" if fault == "lost_mode" else "etc/shadow"
        )
        omitted.chmod(0o644)
        original_chmod = Path.chmod

        def dropped(path, mode, **kwargs):
            if path == omitted:
                return None
            return original_chmod(path, mode, **kwargs)

        monkeypatch.setattr(Path, "chmod", dropped)
    with pytest.raises(ValueError):
        finalizer.finalize(root, path)
    assert not (job / "root-finalization.json").exists()
