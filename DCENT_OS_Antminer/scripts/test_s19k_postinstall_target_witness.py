#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only
"""Adversarial host tests for the S19k image-side postinstall witness."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Optional, Sequence

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]
TOOLBOX_SRC = WORKSPACE / "projects" / "dcent-toolbox" / "src"
sys.path.insert(0, str(TOOLBOX_SRC))

from dcent_toolbox.core import s19k_postinstall_witness as host_witness  # noqa: E402


TARGET_SOURCE = (
    ROOT
    / "br2_external_dcentos"
    / "board"
    / "amlogic"
    / "am3-s19kpro"
    / "rootfs-overlay"
    / "usr"
    / "sbin"
    / "dcent-s19k-postinstall-witness.py"
)
target_witness = ModuleType("s19k_target_witness")
target_witness.__file__ = str(TARGET_SOURCE)
sys.modules[target_witness.__name__] = target_witness
# Compile the exact source bytes directly so a desk test can never leave a
# generated __pycache__ inside the Buildroot rootfs overlay. Such a cache could
# otherwise become an unintended image member if a build follows the test.
exec(
    compile(TARGET_SOURCE.read_bytes(), str(TARGET_SOURCE), "exec"),
    target_witness.__dict__,
)

NOW_TEXT = "2026-08-30T16:00:00Z"
NOW = datetime(2026, 8, 30, 16, 0, 0, tzinfo=timezone.utc)
EXPIRES = "2026-08-30T17:00:00Z"
BOOT_ID = "12345678-1234-4abc-8def-1234567890ab"


@pytest.fixture(autouse=True)
def _emulate_posix_modes_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the Linux metadata checks exercised on a Windows test host.

    Windows only reports writable/read-only permission classes, so it cannot
    represent the target's 0700/0600/0644 split.  Map directories and regular
    files to their restrictive fixture modes while retaining every ownership,
    symlink, hard-link, pinning, and byte check in the target helper.
    """
    if os.name != "nt":
        return

    original_read_regular = target_witness._read_regular

    def fixture_mode(observed: os.stat_result) -> int:
        return 0o700 if stat.S_ISDIR(observed.st_mode) else 0o600

    def fixture_read_regular(
        path: Path,
        *,
        label: str,
        max_bytes: int,
        expected_uid: Optional[int],
        allowed_modes: tuple[int, ...],
    ) -> bytes:
        if allowed_modes == (0o444, 0o644):
            allowed_modes = (0o600,)
        return original_read_regular(
            path,
            label=label,
            max_bytes=max_bytes,
            expected_uid=expected_uid,
            allowed_modes=allowed_modes,
        )

    monkeypatch.setattr(target_witness, "_mode", fixture_mode)
    monkeypatch.setattr(target_witness, "_read_regular", fixture_read_regular)


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _public_der(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _public_pem(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _private_pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _sha(char: str) -> str:
    return char * 64


def _write(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(mode)


def _ssh_public_line(public: bytes) -> bytes:
    return target_witness._authorized_keys_line(public.hex()).split(b" dcent-", 1)[0] + b"\n"


class FakeRunner:
    def __init__(
        self,
        *,
        release_key: Ed25519PrivateKey,
        witness_key: Ed25519PrivateKey,
        host_public: bytes,
    ) -> None:
        self.release_key = release_key
        self.witness_key = witness_key
        self.host_public = host_public
        self.sign_calls = 0
        self.host_generation_calls = 0
        self.data_mount_verify_calls = 0
        self.refuse_data_mount = False
        self.fail_after_sign = False

    def __call__(self, args: Sequence[str], input_data: Optional[bytes]) -> bytes:
        command = list(args)
        if command == [target_witness.DATA_MOUNT_HELPER, "verify"]:
            self.data_mount_verify_calls += 1
            if self.refuse_data_mount:
                raise target_witness.TargetWitnessError(
                    "fixture persistent data mount refused"
                )
            return b""
        if command[:2] == ["openssl", "pkey"]:
            is_release = "-pubin" in command
            key = self.release_key if is_release else self.witness_key
            return _public_der(key) if "DER" in command else _public_pem(key)
        if command[:2] == ["openssl", "pkeyutl"] and "-verify" in command:
            assert input_data is not None
            signature_path = Path(command[command.index("-sigfile") + 1])
            signature = signature_path.read_bytes()
            key_path = Path(command[command.index("-inkey") + 1])
            key = self.release_key if key_path.name == "release_ed25519.pub" else self.witness_key
            try:
                key.public_key().verify(signature, input_data)
            except InvalidSignature as exc:
                raise target_witness.TargetWitnessError("fixture signature rejected") from exc
            return b""
        if command[:2] == ["openssl", "pkeyutl"] and "-sign" in command:
            assert input_data is not None
            self.sign_calls += 1
            signature = self.witness_key.sign(input_data)
            if self.fail_after_sign:
                raise target_witness.TargetWitnessError("fixture crash after private-key operation")
            return signature
        if command[:2] == ["dropbearkey", "-t"]:
            key_path = Path(command[command.index("-f") + 1])
            self.host_generation_calls += 1
            _write(key_path, b"fixture-dropbear-ed25519-private", 0o600)
            return b"Generating key, this may take a while...\n"
        if command[:2] == ["dropbearkey", "-y"]:
            key_path = Path(command[command.index("-f") + 1])
            assert key_path.read_bytes() == b"fixture-dropbear-ed25519-private"
            return b"Public key portion is:\n" + _ssh_public_line(self.host_public)
        raise AssertionError(f"unexpected target command: {command!r}")


class Fixture:
    def __init__(self, root: Path, *, host_public: Optional[bytes] = None) -> None:
        self.root = root
        self.release_key = Ed25519PrivateKey.generate()
        self.witness_key = Ed25519PrivateKey.generate()
        self.client_key = Ed25519PrivateKey.generate()
        self.host_key = Ed25519PrivateKey.generate()
        self.host_public = host_public or _raw_public(self.host_key)

        dcent_dir = root / "data" / "dcent"
        state_root = dcent_dir / "s19k-postinstall-witness"
        inbox = state_root / "inbox"
        root_ssh = root / "root" / ".ssh"
        for directory in (dcent_dir, state_root, inbox, root / "root"):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)
        self.paths = target_witness.TargetPaths(
            state_root=state_root,
            release_marker=root / "etc" / "dcentos" / "release-image",
            board_target=root / "etc" / "dcentos" / "board_target",
            platform=root / "etc" / "dcentos" / "platform",
            release_public_key=root / "etc" / "dcentos" / "release_ed25519.pub",
            boot_id=root / "proc" / "sys" / "kernel" / "random" / "boot_id",
            dcent_dir=dcent_dir,
            root_ssh_dir=root_ssh,
        )
        _write(self.paths.release_marker, b"release_image=1\n", 0o644)
        _write(self.paths.board_target, b"am3-s19k\n", 0o644)
        _write(self.paths.platform, b"am3-aml-s19k\n", 0o644)
        _write(self.paths.release_public_key, _public_pem(self.release_key), 0o644)
        _write(self.paths.boot_id, (BOOT_ID + "\n").encode(), 0o644)

        self.scope_raw = host_witness.build_witness_scope(
            capsule_sha256=_sha("1"),
            rootfs_sha256=_sha("2"),
            unit_identity_sha256=_sha("3"),
            preinstall_host_key_sha256=_sha("4"),
            install_scope_id=_sha("5"),
            install_request_sha256=_sha("6"),
            witness_public_key_hex=_raw_public(self.witness_key).hex(),
            authorized_client_public_key_hex=_raw_public(self.client_key).hex(),
            authorized_utc=NOW_TEXT,
            expires_utc=EXPIRES,
        )
        scope = json.loads(self.scope_raw)
        scope_signature = self.release_key.sign(self.scope_raw)
        admission = host_witness.admit_witness_scope(
            self.scope_raw,
            scope_signature,
            now_utc=NOW_TEXT,
            expected_release_public_key_hex=_raw_public(self.release_key).hex(),
            allow_nonproduction_test_key=True,
        )
        challenge_state = root / "host-challenge-state"
        challenge_state.mkdir(mode=0o700)
        challenge = host_witness.issue_witness_challenge(
            admission,
            challenge_state,
            observer_id="office-independent-observer",
            now_utc=NOW_TEXT,
            ttl_seconds=300,
            nonce_hex="ab" * 32,
        )
        self.challenge_raw = challenge.raw
        self.stage1_receipt = {
            "schema": "dcentos.s19k-stage1-receipt/v1",
            "board_target": "am3-s19kpro",
            "source_layout": "braiins-aml-s19k",
            "scope_id": scope["install_scope_id"],
            "request_sha256": scope["install_request_sha256"],
            "capsule_sha256": scope["capsule_sha256"],
            "rootfs_sha256": scope["rootfs_sha256"],
            "rootfs_readback_sha256": scope["rootfs_sha256"],
            "rootfs_bytes": 4096,
            "rootfs_readback_bytes": 4096,
            "identity_record_sha256": scope["unit_identity_sha256"],
            "state": "installed_commit_verified_no_reboot",
            "terminal": True,
            "simulation": False,
            "clear_for_flash_internal": True,
            "clear_for_flash_request": True,
            "writes_authorized": True,
            "authorization_verified": True,
            "stage1_authorizer_verified": True,
            "stage1_authorizer_target_kat_verified": True,
            "transferred_inputs_verified": True,
            "identity_verified": True,
            "geometry_verified": True,
            "zero_bad_blocks_verified": True,
            "safeoff_verified": True,
            "mutation_started": True,
            "nand_erase_performed": True,
            "nand_write_performed": True,
            "install_commit_verified": True,
            "postboot_proof_required": True,
            "restore_required": False,
            "recovery_flag_readback": 1,
        }
        self.receipt_raw = _canonical(self.stage1_receipt)
        _write(inbox / "scope.json", self.scope_raw, 0o600)
        _write(inbox / "scope.sig", scope_signature, 0o600)
        _write(inbox / "challenge.json", self.challenge_raw, 0o600)
        _write(inbox / "witness-private.pem", _private_pem(self.witness_key), 0o600)
        _write(inbox / "stage1-install-receipt.json", self.receipt_raw, 0o600)
        self.runner = FakeRunner(
            release_key=self.release_key,
            witness_key=self.witness_key,
            host_public=self.host_public,
        )

    def run(self) -> dict[str, object]:
        return target_witness.run_firstboot(
            self.paths,
            runner=self.runner,
            now=NOW,
            expected_uid=None,
        )


def test_target_contract_is_candidate_only_and_cannot_authorize_release() -> None:
    contract = target_witness.contract()
    assert contract["candidate_implemented"] is True
    assert contract["production_approved"] is False
    assert contract["stage1_envelope_transport_implemented"] is False
    assert contract["toolbox_executor_integration_complete"] is False
    assert contract["release_gate_integration_complete"] is False
    assert contract["clear_for_flash"] is False
    assert contract["production_execution_ready"] is False
    assert contract["persistent_data_mount_owner_implemented"] is True
    assert contract["persistent_data_mount_live_verified"] is False
    assert "cold-boot" in contract["missing_persistent_data_proof"]
    assert contract["authorizes_install"] is False
    assert contract["authorizes_nand_write"] is False
    assert contract["authorizes_reboot"] is False


def test_valid_target_response_is_byte_exact_host_contract_and_one_use(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    admission = fixture.run()
    response = (fixture.paths.outbox / "response.json").read_bytes()
    expected = host_witness.build_witness_response_payload(
        fixture.challenge_raw,
        first_boot_host_key_public_hex=fixture.host_public.hex(),
        boot_id_sha256=hashlib.sha256(BOOT_ID.encode()).hexdigest(),
        stage1_install_receipt_sha256=hashlib.sha256(fixture.receipt_raw).hexdigest(),
    )
    assert response == expected
    fixture.witness_key.public_key().verify(
        (fixture.paths.outbox / "response.sig").read_bytes(), response
    )
    assert admission["target_response_signed_once"] is True
    assert admission["release_ready"] is False
    assert fixture.runner.sign_calls == 1
    assert fixture.runner.host_generation_calls == 1
    assert fixture.runner.data_mount_verify_calls == 1
    assert fixture.paths.host_key.is_file()
    assert target_witness._mode(fixture.paths.host_key.stat()) == 0o600
    assert b"-postinstall\n" in fixture.paths.root_authorized_keys.read_bytes()

    replay = fixture.run()
    assert replay == admission
    assert fixture.runner.sign_calls == 1
    assert fixture.runner.host_generation_calls == 1
    # Replay checks the mount before even looking for the admission and again
    # inside the independently callable retained-admission verifier.
    assert fixture.runner.data_mount_verify_calls == 3


def test_unverified_data_mount_fails_before_any_persistent_state_access(
    tmp_path: Path,
) -> None:
    fixture = Fixture(tmp_path)
    fixture.runner.refuse_data_mount = True
    with pytest.raises(target_witness.TargetWitnessError, match="data mount refused"):
        fixture.run()
    assert fixture.runner.data_mount_verify_calls == 1
    assert fixture.runner.host_generation_calls == 0
    assert fixture.runner.sign_calls == 0
    assert not fixture.paths.host_key_claim.exists()
    assert not fixture.paths.signing_claim.exists()
    assert not fixture.paths.admission.exists()


def test_missing_envelope_leaves_ssh_unadmitted(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    (fixture.paths.inbox / "challenge.json").unlink()
    with pytest.raises(target_witness.TargetWitnessError, match="member set"):
        fixture.run()
    assert not fixture.paths.admission.exists()
    assert not fixture.paths.ssh_enabled.exists()
    assert not fixture.paths.root_authorized_keys.exists()
    assert fixture.runner.sign_calls == 0


def test_bad_release_signature_fails_before_host_key_or_signing(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    _write(fixture.paths.inbox / "scope.sig", b"x" * 64, 0o600)
    with pytest.raises(target_witness.TargetWitnessError, match="signature rejected"):
        fixture.run()
    assert not fixture.paths.host_key.exists()
    assert not fixture.paths.signing_claim.exists()
    assert fixture.runner.sign_calls == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("simulation", True),
        ("clear_for_flash_internal", False),
        ("install_commit_verified", False),
        ("postboot_proof_required", False),
        ("state", "preflight_passed_no_mutation"),
    ],
)
def test_nonterminal_stage1_receipt_never_reaches_private_key(
    tmp_path: Path, field: str, value: object
) -> None:
    fixture = Fixture(tmp_path)
    receipt = dict(fixture.stage1_receipt)
    receipt[field] = value
    _write(
        fixture.paths.inbox / "stage1-install-receipt.json",
        _canonical(receipt),
        0o600,
    )
    with pytest.raises(target_witness.TargetWitnessError, match=field):
        fixture.run()
    assert fixture.runner.sign_calls == 0
    assert not fixture.paths.host_key.exists()


@pytest.mark.parametrize("reuse", ["witness", "client"])
def test_firstboot_host_key_role_reuse_is_refused(
    tmp_path: Path, reuse: str
) -> None:
    fixture = Fixture(tmp_path)
    fixture.runner.host_public = (
        _raw_public(fixture.witness_key)
        if reuse == "witness"
        else _raw_public(fixture.client_key)
    )
    with pytest.raises(target_witness.TargetWitnessError, match="reuses witness/client"):
        fixture.run()
    assert fixture.runner.sign_calls == 0
    assert not fixture.paths.admission.exists()


def test_crash_after_private_key_operation_is_terminal_no_resign(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    fixture.runner.fail_after_sign = True
    with pytest.raises(target_witness.TargetWitnessError, match="crash"):
        fixture.run()
    assert fixture.runner.sign_calls == 1
    assert fixture.paths.signing_claim.is_file()
    fixture.runner.fail_after_sign = False
    with pytest.raises(target_witness.TargetWitnessError, match="already exists"):
        fixture.run()
    assert fixture.runner.sign_calls == 1
    assert not fixture.paths.admission.exists()


def test_response_tamper_locks_gate_without_resigning(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    fixture.run()
    response_path = fixture.paths.outbox / "response.json"
    response = json.loads(response_path.read_bytes())
    response["release_ready"] = True
    _write(response_path, _canonical(response), 0o600)
    with pytest.raises(target_witness.TargetWitnessError, match="key set/schema"):
        target_witness.verify_ssh_gate(
            fixture.paths,
            runner=fixture.runner,
            expected_uid=None,
        )
    assert fixture.runner.sign_calls == 1


def test_symlinked_private_key_is_refused(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    private_path = fixture.paths.inbox / "witness-private.pem"
    real_path = tmp_path / "outside-private.pem"
    private_path.replace(real_path)
    try:
        private_path.symlink_to(real_path)
    except OSError:
        pytest.skip("file symlinks unavailable")
    with pytest.raises(target_witness.TargetWitnessError, match="direct single-link"):
        fixture.run()
    assert fixture.runner.sign_calls == 0


def test_image_wires_persistent_owner_and_operator_ssh_without_historical_witness() -> None:
    board = (
        ROOT
        / "br2_external_dcentos"
        / "board"
        / "amlogic"
        / "am3-s19kpro"
    )
    s49 = (board / "rootfs-overlay/etc/init.d/S49s19k-postinstall-witness").read_text()
    s38 = (board / "rootfs-overlay/etc/init.d/S38s19k-data").read_text()
    s50 = (board / "rootfs-overlay/etc/init.d/S50dropbear").read_text()
    post_build = (board / "post-build.sh").read_text()
    post_image = (board / "post-image.sh").read_text()
    assert "dcent-s19k-data-mount" in s38
    assert "dcent-s19k-data-mount" in s49
    assert "dcent-s19k-data-mount" in s50
    assert "S38s19k-data" in post_image
    assert "S49s19k-postinstall-witness" in post_image
    assert "dcent-s19k-postinstall-witness.py" in post_image
    assert "verify-ssh-gate" not in s50
    assert "dcent-s19k-postinstall-witness.py" not in s49 + s50
    assert "enabled-by-keys" in s50 and "enabled-by-wizard" in s50
    assert "locked-release-image" in s50 and "locked-data-owner" in s50
    assert 'rm -f "${TARGET_DIR}/usr/sbin/dcent-s19k-postinstall-witness.py"' in post_build
    assert "reject_rootfs_pattern '(^|/)dcent-s19k-postinstall-witness.py$'" in post_image
    assert 'rm -f "${TARGET_DIR}/etc/init.d/S46post-install"' in post_build
    assert "reject_rootfs_pattern '(^|/)S46post-install$'" in post_image


def test_target_source_has_no_network_reboot_hardware_or_install_primitive() -> None:
    source = TARGET_SOURCE.read_text(encoding="utf-8")
    forbidden = (
        "socket.",
        "requests.",
        "paramiko",
        "subprocess.*ssh",
        "nandwrite",
        "flash_erase",
        "fw_setenv",
        "/sys/class/gpio",
        "/dev/mtd",
        "os.reboot",
        "systemctl reboot",
    )
    for token in forbidden:
        assert token not in source
