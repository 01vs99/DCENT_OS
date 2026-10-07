"""Actual project-source composition and bounded source-file fault cases."""

from pathlib import Path
import hashlib
import importlib.util
import os
import sys

import pytest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "DCENT_OS_Antminer/scripts"))
assets = importlib.import_module("native_zynq_sd.assets")
TARGETS = importlib.import_module("native_zynq_sd.profiles").TARGETS

HELPER = ROOT / (assets.OWN + "usr/libexec/dcentos/native-zynq-sd-storage.py")
spec = importlib.util.spec_from_file_location("native_sd_storage_asset_test", HELPER)
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)


@pytest.mark.parametrize("target", TARGETS)
def test_actual_source_plan_and_independent_storage_parser(target):
    plan = assets.source_assets(ROOT, target)
    assert storage.profile_from_bytes(
        plan["etc/dcentos/native-zynq-sd.json"].content
    ) == storage.expected_profile(target)
    assert plan["etc/dcentos/board_target"].content == (target + "\n").encode()
    config = assets.tomllib.loads(plan["etc/dcentrald.toml"].content.decode())
    assert config["mining"]["enabled"] is False and config["pool"]["url"] == ""
    assert config["api"]["http_port"] == 8080
    assert config["api"]["cgminer_bind_lan"] is True
    assert config["api"]["cgminer_lan_writes"] is False
    assert all(b"\r" not in value.content for value in plan.values())
    for key, asset in plan.items():
        assert not key.startswith("/") and ".." not in Path(key).parts
        if asset.source:
            raw = (ROOT / asset.source).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == asset.source_sha256
            if key not in {"etc/dcentrald.toml", "etc/init.d/S82dcentrald"}:
                assert asset.content == raw.replace(b"\r\n", b"\n")
            elif key == "etc/init.d/S82dcentrald":
                source = raw.replace(b"\r\n", b"\n")
                before = source.index(b"    if [ -x /data/dcentrald ]; then\n")
                after = source.index(b"    if [ -f /data/dcentrald.toml ]; then\n")
                new_after = asset.content.index(
                    b"    if [ -f /data/dcentrald.toml ]; then\n"
                )
                assert source[:before] == asset.content[:before]
                assert source[after:] == asset.content[new_after:]
                assert (
                    b'DAEMON="/usr/local/bin/dcentrald"\n'
                    in asset.content[before:new_after]
                )
                assert (
                    b'DAEMON="/data/dcentrald"' not in asset.content[before:new_after]
                )
    actual_services = {
        Path(name).name for name in plan if name.startswith("etc/init.d/")
    }
    assert actual_services == set(assets.SOURCE_SERVICES + assets.OWN_SERVICES) | (
        {"S12fpga_identity"} if target.startswith("am2-") else set()
    )
    assert not actual_services & {
        "S99upgrade",
        "S99verify",
        "S15pic_boot",
        "S10modules",
        "S70ip_reporter",
        "S81mcp",
        "S81dcentos-xil-seed",
        "S50telnet",
    }


@pytest.mark.parametrize(
    "mutation", ["mining_enabled", "pool", "model", "chip_count", "api", "cgminer", "lan_writes", "missing_writes"]
)
def test_qualified_default_mutations_refuse(tmp_path, mutation):
    name = assets.CONFIGS + "dcentrald_s17pro_am2_baked_default.toml"
    text = (ROOT / name).read_text()
    old, new = {
        "mining_enabled": ("[mining]\nenabled = false", "[mining]\nenabled = true"),
        "pool": ('url = ""', 'url = "stratum+tcp://changed.example:3333"'),
        "model": ('model = "s17pro"', 'model = "t17"'),
        "chip_count": ("serial_chip_count = 48", "serial_chip_count = 65"),
        "api": ("http_port = 8080", "http_port = 80"),
        "cgminer": ("cgminer_bind_lan = true", "cgminer_bind_lan = false"),
        "lan_writes": ("cgminer_lan_writes = false", "cgminer_lan_writes = true"),
        "missing_writes": ("cgminer_lan_writes = false", "# missing LAN write policy"),
    }[mutation]
    assert text.count(old) == 1
    source = tmp_path / name
    source.parent.mkdir(parents=True)
    source.write_text(text.replace(old, new))
    with pytest.raises(ValueError):
        assets.render_config(tmp_path, "am2-s17p")


@pytest.mark.parametrize(
    "fault", ["empty", "oversized", "directory", "symlink", "hardlink"]
)
def test_direct_unique_regular_source(tmp_path, fault):
    path = tmp_path / "input"
    if fault == "directory":
        path.mkdir()
    else:
        path.write_bytes(b"" if fault == "empty" else b"source")
        if fault == "symlink":
            link = tmp_path / "link"
            try:
                link.symlink_to(path)
            except OSError:
                pytest.skip("host symlink privilege unavailable")
            path = link
        elif fault == "hardlink":
            os.link(path, tmp_path / "alias")
    with pytest.raises(ValueError):
        assets.read_source(path, 3 if fault == "oversized" else 1024)


def test_source_replaced_between_lstat_and_open(tmp_path, monkeypatch):
    path = tmp_path / "source"
    path.write_bytes(b"accepted")
    candidate = tmp_path / "replacement"
    candidate.write_bytes(b"changed!")
    original = assets.os.open

    def opened(name, flags):
        os.replace(candidate, path)
        return original(name, flags)

    monkeypatch.setattr(assets.os, "open", opened)
    with pytest.raises(ValueError, match="replaced"):
        assets.read_source(path)


def test_actual_native28_artifacts_remain_exact():
    name = (
        "/root/dcent-beta-native-checkpoint28-artifacts/armv7-unknown-linux-musleabihf"
    )
    directory = (
        Path(r"\\wsl.localhost\Ubuntu-22.04" + name.replace("/", "\\"))
        if os.name == "nt"
        else Path(name)
    )
    if not directory.is_dir():
        pytest.skip("actual native28 inputs unavailable")
    result = assets.native_assets(directory)
    assert len(result) == 6
    for name in ("dcentrald", "dcentos-discovery", "dcentos-init"):
        assert (
            result["etc/dcentos/" + name + ".sha256"].content
            == (assets.NATIVE[name][1] + "\n").encode()
        )


def test_foreign_native_bytes_refuse_before_other_inputs(tmp_path):
    (tmp_path / "dcentrald").write_bytes(b"\x7fELFforeign")
    with pytest.raises(ValueError, match="native28"):
        assets.native_assets(tmp_path)


@pytest.mark.parametrize(
    "target", ["am1-s9", "am1-s9se", "am2-t17e", "am3-s19pro", "am2-s19j"]
)
def test_foreign_target_refuses_before_source_read(target, monkeypatch):
    def deny(*args):
        raise AssertionError("foreign target read a source")

    monkeypatch.setattr(assets, "read_source", deny)
    with pytest.raises(ValueError):
        assets.source_assets(ROOT, target)


@pytest.mark.parametrize("mutation", ["changed", "duplicate"])
def test_supervisor_source_selector_drift_refuses(tmp_path, mutation):
    name = assets.ZYNQ + "etc/init.d/S82dcentrald"
    original = (ROOT / name).read_text()
    if mutation == "changed":
        original = original.replace(
            'DAEMON="/data/dcentrald"', 'DAEMON="/data/changed"'
        )
    else:
        original += "\n" + original
    source = tmp_path / name
    source.parent.mkdir(parents=True)
    source.write_text(original)
    with pytest.raises(ValueError, match="single current supervisor"):
        assets.render_supervisor(tmp_path, "am1-s9i")
