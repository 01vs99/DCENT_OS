# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only

"""Offline tests for the AM2/XIL first-install capsule builder.

Validation tests are pure; signing tests exercise the exact release
signer (openssl + sign_release_artifact.py) and are skipped when openssl
is unavailable. The closing assertion of every signing test is the
TOOLBOX contract verdict: `capsule_ready`.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCRIPT = Path(__file__).with_name("build_am2_first_install_capsule.py")
SPEC = importlib.util.spec_from_file_location("build_am2_first_install_capsule", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

TOOLBOX_SOURCE = MODULE.TOOLBOX_SOURCE
if str(TOOLBOX_SOURCE) not in sys.path:
    sys.path.insert(0, str(TOOLBOX_SOURCE))

from dcent_toolbox.core.am2_xil_first_install import (  # noqa: E402
    SOURCE_STOCK_3PART,
    inspect_am2_first_install_capsule,
)

HAS_OPENSSL = shutil.which("openssl") is not None


@pytest.fixture(scope="module")
def actual_runtime_root(tmp_path_factory):
    from test_runtime_image_manifest import fixture
    import runtime_image_manifest as runtime
    directory = tmp_path_factory.mktemp("first-install-runtime")
    key, public, daemon = fixture(directory / "identity")
    root = directory / "root"
    for name in ("etc/dcentos", "usr/local/bin", "usr/share/dcentos"):
        (root / name).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(daemon, root / runtime.DAEMON)
    (root / runtime.SETTINGS_DEFAULT).write_bytes(b"[mining]\nenabled=false\n")
    runtime.prepare(root, "am2-s19j", "beta", "1.2.3", key, public)
    squashfs = directory / "rootfs"
    result = subprocess.run(["mksquashfs", str(root), str(squashfs), "-noappend", "-all-root",
        "-no-xattrs", "-no-exports", "-comp", "xz", "-processors", "1", "-mkfs-time", "0"],
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    return key, public, squashfs


@pytest.mark.skipif(not HAS_OPENSSL, reason="exact release signer requires openssl")
def test_dual_payload_pair_embeds_callable_canonical_executor(tmp_path, capsys, actual_runtime_root, monkeypatch):
    from dcent_toolbox.core import am2_first_install_executor as executor
    from dcent_toolbox.core.am2_first_install_executor import executable_capsule_members, STAGE1_PATH
    key_pem, pub_pem, actual_rootfs = actual_runtime_root
    data = b"fixture ARM Linux kernel"
    header = bytearray(struct.pack(">7I4B32s", 0x27051956, 0, 0, len(data),
                                  0x8000, 0x8000, zlib.crc32(data), 5, 2, 2, 0, b"fixture"))
    struct.pack_into(">I", header, 4, zlib.crc32(header))
    kernel = tmp_path / "kernel"
    kernel.write_bytes(bytes(header) + data)
    rootfs = tmp_path / "rootfs"
    rootfs.write_bytes(actual_rootfs.read_bytes())
    # This case closes signer/packager/consumer composition; the consumer's
    # independent FIT tests bind real structural validation and donor digest.
    fpga = tmp_path / "am2-fabric.itb"
    fpga.write_bytes(b"test-only admitted FPGA")
    def admit_fixture(raw):
        assert raw == fpga.read_bytes()
    monkeypatch.setattr(executor, "validate_fpga_image", admit_fixture)
    writer = tmp_path / "am2-nand-window-armv7"
    elf = bytearray(84)
    elf[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<HH", elf, 16, 2, 40)
    struct.pack_into("<I", elf, 28, 52)
    struct.pack_into("<HH", elf, 42, 32, 1)
    struct.pack_into("<I", elf, 52, 1)
    writer.write_bytes(elf)
    output = tmp_path / "dual.tar.gz"
    source = "braiins-dual-ubi-mtd7-mtd8"
    args = ["--board-target", "am2-s19jpro-zynq", "--source-layout", source,
            "--version", "1.2.3", "--post-install-artifact", "X.tar",
            "--migration-scope", "vendor archive and explicit mining config",
            "--dual-ubi-kernel", str(kernel), "--dual-ubi-rootfs", str(rootfs),
            "--dual-ubi-fpga", str(fpga), "--dual-ubi-writer", str(writer),
            "--key", str(key_pem), "--pubkey", str(pub_pem), "--output", str(output), "--json"]
    assert MODULE.main(args) == 0
    capsys.readouterr()
    monkeypatch.setenv("DCENT_RELEASE_PUBKEY_FILE", str(pub_pem))
    members, _ = executable_capsule_members(output, "am2-s19jpro-zynq", source)
    assert members["stage1.sh"] == STAGE1_PATH.read_bytes()
    assert members["kernel"] == kernel.read_bytes()
    assert members["rootfs"] == rootfs.read_bytes()
    assert members["am2-fabric.itb"] == fpga.read_bytes()
    assert json.loads(members["bootenv2.json"])["dcent_native_slot"] == "2"
    # Even a valid outer signing key cannot qualify plausible header-only
    # root bytes; the builder executes the same actual runtime parser first.
    invalid_output = tmp_path / "header-only.tar.gz"
    args[args.index("--output") + 1] = str(invalid_output)
    rootfs.write_bytes(struct.pack("<5I6H8Q", 0x73717368, 1, 0, 131072, 0,
                                  4, 17, 0, 1, 4, 0, 0, 100, *([0] * 6)) + bytes(4))
    assert MODULE.main(args) == 2
    assert not invalid_output.exists()


@pytest.fixture()
def dev_authority(tmp_path: Path):
    key = Ed25519PrivateKey.generate()
    key_pem = tmp_path / "key.pem"
    descriptor = os.open(key_pem, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        if os.name == "nt":
            from dcent_toolbox.cli.commands._secret_output import _harden_windows_secret_acl
            _harden_windows_secret_acl(key_pem)
        handle.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    pub_pem = tmp_path / "pub.pem"
    pub_pem.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return key_pem, pub_pem


def _stage1(tmp_path: Path) -> Path:
    stage1 = tmp_path / "stage1.sh"
    stage1.write_bytes(b"#!/bin/sh\nset -e\n# transition (test)\n")
    return stage1


def _base_args(tmp_path: Path, stage1: Path) -> list[str]:
    return [
        "--board-target", "am2-s19pro",
        "--source-layout", SOURCE_STOCK_3PART,
        "--version", "v0.1.0-test",
        "--post-install-artifact", "DCENTOS_XIL3_S19Pro_20260814.tar",
        "--migration-scope", "serial-number-only",
        "--stage1", str(stage1),
    ]


def test_plan_derives_mechanism_and_writes_nothing(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    output = tmp_path / "capsule.tar.gz"
    rc = MODULE.main(
        _base_args(tmp_path, stage1) + ["--plan", "--output", str(output)]
    )
    assert rc == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["transition_mechanism"] == "boot_chain_repartition"
    assert plan["board_target"] == "am2-s19pro"
    assert [m["name"] for m in plan["members"]] == ["transition/stage1.sh"]
    assert not output.exists()


def test_single_slot_source_requires_stage1(tmp_path, capsys):
    rc = MODULE.main(
        [
            "--board-target", "am2-s19pro",
            "--source-layout", SOURCE_STOCK_3PART,
            "--version", "v0.1.0-test",
            "--post-install-artifact", "X.tar",
            "--migration-scope", "none",
            "--plan",
        ]
    )
    assert rc == 2
    assert "--stage1" in capsys.readouterr().err


def test_dual_ubi_source_refuses_stage1(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    rc = MODULE.main(
        [
            "--board-target", "am2-s19jpro-zynq",
            "--source-layout", "braiins-dual-ubi-mtd7-mtd8",
            "--version", "v0.1.0-test",
            "--post-install-artifact", "X.tar",
            "--migration-scope", "none",
            "--stage1", str(stage1),
            "--plan",
        ]
    )
    assert rc == 2
    assert "applies only to" in capsys.readouterr().err


def test_already_dcent_source_refused(tmp_path, capsys):
    rc = MODULE.main(
        [
            "--board-target", "am2-s19pro",
            "--source-layout", "dcent-dual-ubi-mtd7-mtd8",
            "--version", "v0.1.0-test",
            "--post-install-artifact", "X.tar",
            "--migration-scope", "none",
            "--plan",
        ]
    )
    assert rc == 2
    assert "already DCENT_OS" in capsys.readouterr().err


def test_unsafe_member_names_rejected(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"data")
    rc = MODULE.main(
        _base_args(tmp_path, stage1)
        + ["--member", f"../evil={payload}", "--plan"]
    )
    assert rc == 2
    assert "unsafe member name" in capsys.readouterr().err


def test_reserved_member_names_rejected(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    payload = tmp_path / "manifest.json"
    payload.write_bytes(b"{}")
    rc = MODULE.main(
        _base_args(tmp_path, stage1) + ["--member", f"manifest.json={payload}", "--plan"]
    )
    assert rc == 2
    assert "reserved" in capsys.readouterr().err


def test_real_build_requires_signing_material(tmp_path, capsys, monkeypatch):
    stage1 = _stage1(tmp_path)
    monkeypatch.delenv("DCENT_RELEASE_SIGNING_KEY", raising=False)
    monkeypatch.delenv("DCENT_RELEASE_PUBKEY_FILE", raising=False)
    rc = MODULE.main(
        _base_args(tmp_path, stage1)
        + ["--output", str(tmp_path / "capsule.tar.gz")]
    )
    assert rc == 2
    assert "signing requires" in capsys.readouterr().err


def test_version_charset_enforced(tmp_path, capsys):
    stage1 = _stage1(tmp_path)
    args = [
        "--board-target", "am2-s19pro",
        "--source-layout", SOURCE_STOCK_3PART,
        "--version", "bad version!",
        "--post-install-artifact", "X.tar",
        "--migration-scope", "none",
        "--stage1", str(stage1),
        "--plan",
    ]
    assert MODULE.main(args) == 2
    assert "version" in capsys.readouterr().err


@pytest.mark.skipif(not HAS_OPENSSL, reason="exact release signer requires openssl")
def test_built_capsule_reaches_toolbox_capsule_ready(tmp_path, capsys, dev_authority):
    key_pem, pub_pem = dev_authority
    stage1 = _stage1(tmp_path)
    boot = tmp_path / "boot.bin"
    boot.write_bytes(b"AM2-BOOTCHAIN-TEST" * 4)
    output = tmp_path / "capsule.tar.gz"
    rc = MODULE.main(
        _base_args(tmp_path, stage1)
        + [
            "--member", f"boot/boot.bin={boot}",
            "--output", str(output),
            "--key", str(key_pem),
            "--pubkey", str(pub_pem),
            "--json",
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["sha256"]
    # THE loop-closing assertion: the toolbox contract admits the product
    import os

    old = os.environ.get("DCENT_RELEASE_PUBKEY_FILE")
    os.environ["DCENT_RELEASE_PUBKEY_FILE"] = str(pub_pem)
    try:
        report = inspect_am2_first_install_capsule(output)
    finally:
        if old is None:
            os.environ.pop("DCENT_RELEASE_PUBKEY_FILE", None)
        else:
            os.environ["DCENT_RELEASE_PUBKEY_FILE"] = old
    assert report.verdict == "capsule_ready"
    assert report.board_target == "am2-s19pro"
    assert "transition/stage1.sh" in report.members
    assert "boot/boot.bin" in report.members


@pytest.mark.skipif(not HAS_OPENSSL, reason="exact release signer requires openssl")
def test_build_is_deterministic_and_no_replace(tmp_path, capsys, dev_authority):
    key_pem, pub_pem = dev_authority
    stage1 = _stage1(tmp_path)
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    common = _base_args(tmp_path, stage1) + [
        "--key", str(key_pem), "--pubkey", str(pub_pem), "--json",
    ]
    assert MODULE.main(common + ["--output", str(first)]) == 0
    digest_a = json.loads(capsys.readouterr().out)["sha256"]
    assert MODULE.main(common + ["--output", str(second)]) == 0
    digest_b = json.loads(capsys.readouterr().out)["sha256"]
    assert digest_a == digest_b
    # no-replace: rebuilding over the same path is refused
    assert MODULE.main(common + ["--output", str(first)]) == 2
    assert "no-replace" in capsys.readouterr().err
