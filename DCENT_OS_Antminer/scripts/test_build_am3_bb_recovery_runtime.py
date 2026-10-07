import importlib.util
from pathlib import Path
import sys

import pytest

SOURCE = Path(__file__).with_name("build_am3_bb_recovery_runtime.py")
spec = importlib.util.spec_from_file_location("bb_runtime_producer", SOURCE)
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


def test_runtime_closure_contains_signature_and_modern_boot_verifiers_without_cli():
    modules = producer.module_closure("dcent_toolbox.core.am3_bb_recovery_service")
    for name in ("am3_bb_nand_transaction", "am3_bb_recovery_ramdisk", "am3_bb_modern_boot", "am3_bb_bootenv"):
        assert "dcent_toolbox/core/"+name+".py" in modules
    assert not any("/cli/" in name or "/tui/" in name or "fleet" in name for name in modules)
    assert len(modules) < 25


def test_rootfs_wrapper_refuses_stock_autoflash_archive():
    import gzip
    with pytest.raises(ValueError):
        producer.legacy_ramdisk(gzip.compress(b"070701"+bytes(512)))


def test_overlay_retains_only_fixed_recovery_startup(tmp_path):
    package = tmp_path/"source/package/python3"
    package.mkdir(parents=True)
    (package/"python3.mk").write_text("PYTHON3_VERSION_MAJOR = 3.13\n")
    receipt = producer.populate_overlay(tmp_path)
    overlay = tmp_path/"overlay"
    assert (overlay/"etc/inittab").read_text().startswith("# Recovery PID1 only reaps children")
    assert not (overlay/"etc/init.d").exists()
    assert b"--start-transport" in (overlay/"init").read_bytes()
    assert b"execute_transaction" not in (overlay/"init").read_bytes()
    assert "dcent_toolbox/core/am3_bb_recovery_ramdisk.py" in " ".join(receipt["files"])
    for name, digest in receipt["files"].items():
        assert producer.file_sha(overlay/name.lstrip("/")) == digest
    config = (tmp_path/"recovery_defconfig").read_text()
    assert "BR2_PACKAGE_PYTHON3_XZ=y" in config
    assert "BR2_JLEVEL=2" in config


def test_eager_import_closure_ignores_unexecuted_ui_import(tmp_path, monkeypatch):
    package = tmp_path/"dcent_toolbox/core"
    package.mkdir(parents=True)
    (tmp_path/"dcent_toolbox/__init__.py").write_text("")
    (package/"__init__.py").write_text("")
    (package/"entry.py").write_text("from dcent_toolbox.core import needed\ndef unrelated():\n    import dcent_toolbox.tui.unavailable\n")
    (package/"needed.py").write_text("VALUE = 1\n")
    monkeypatch.setattr(producer, "TOOLBOX", tmp_path)
    modules = producer.module_closure("dcent_toolbox.core.entry")
    assert set(modules) == {"dcent_toolbox/__init__.py", "dcent_toolbox/core/__init__.py",
                            "dcent_toolbox/core/entry.py", "dcent_toolbox/core/needed.py"}
