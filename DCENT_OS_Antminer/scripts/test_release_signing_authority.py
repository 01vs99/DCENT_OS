#!/usr/bin/env python3
"""Adversarial tests for release_signing_authority.py."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("release_signing_authority.py")
SPEC = importlib.util.spec_from_file_location("release_signing_authority", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
authority = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(authority)
invocation = authority.release_invocation


class ReleaseSigningAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.invocation_parent = self.root / "invocations"
        self.authority_parent = self.root / "authorities"
        self.keys = self.root / "keys"
        for path in (self.invocation_parent, self.authority_parent, self.keys):
            path.mkdir()
        self.private = self.keys / "private.pem"
        self.public = self.keys / "public.pem"
        self.private.write_bytes(b"PRIVATE-ED25519-TEST-AUTHORITY\n")
        self.public.write_bytes(b"PUBLIC-ED25519-TEST-AUTHORITY\n")
        if os.name == "posix":
            os.chmod(self.private, 0o600)
        elif os.name == "nt":
            authority.atomic_publish_directory.set_windows_file_acl(
                self.private,
                authority.atomic_publish_directory.WINDOWS_PRIVATE_FILE_SDDL,
            )
        self.release_invocation = invocation.create_invocation(
            self.invocation_parent, "s9"
        )

    def tearDown(self) -> None:
        for root, directories, files in os.walk(
            self.temporary.name, topdown=False, followlinks=False
        ):
            for name in files:
                path = Path(root) / name
                try:
                    if not path.is_symlink():
                        os.chmod(path, 0o600)
                except OSError:
                    pass
            for name in directories:
                path = Path(root) / name
                try:
                    if not path.is_symlink():
                        os.chmod(path, 0o700)
                except OSError:
                    pass
        self.temporary.cleanup()

    def create(self):
        return authority.create_authority(
            self.authority_parent,
            self.release_invocation.stage,
            self.private,
            self.public,
        )

    def test_driver_result_parent_preparation_allows_actual_durable_authority(self) -> None:
        parent = self.root / "driver-control"
        parent.mkdir(mode=0o755)
        sentinel = parent / "existing-public-source.txt"
        sentinel.write_bytes(b"source bytes remain unchanged\n")
        result = self.run_cli("prepare-result-parent", str(parent))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sentinel.read_bytes(), b"source bytes remain unchanged\n")
        authority._check_directory(parent.lstat(), "prepared driver parent", private=True)
        authority._require_private_windows_path(parent, "prepared driver parent")
        created = authority.create_authority(
            self.authority_parent, self.release_invocation.stage, self.private,
            self.public, result_output=parent / "signing-result.json")
        value = json.loads((parent / "signing-result.json").read_bytes())
        self.assertEqual(value["authority_id"], created.authority_id)
        authority.destroy_authority(created.stage, created.capability)
        self.assertFalse(created.stage.exists())
        self.assertNotEqual(self.run_cli("prepare-result-parent", str(sentinel)).returncode, 0)

    @unittest.skipUnless(os.name == "nt", "actual Git Bash/Windows DACL integration")
    def test_capsule_directory_preparation_admits_actual_release_set_stage(self) -> None:
        # Execute the actual driver's directory setup, without a compiler or key.
        # Both siblings start with an inherited DACL, as Git Bash mkdir creates.
        git = shutil.which("git")
        self.assertIsNotNone(git, "Windows release acceptance requires Git Bash")
        bash = next((parent / "usr/bin/bash.exe" for parent in Path(git).resolve().parents
                     if (parent / "usr/bin/bash.exe").is_file()), None)
        self.assertIsNotNone(bash, "active Git installation must contain Bash")
        source = SCRIPT.with_name("build_release_capsule.sh").read_text(encoding="utf-8")
        start = source.index('\nWORK_PARENT="$PUBLIC_OUTPUT_ROOT/.dcent-release-capsules"') + 1
        end = source.index('\nINVOCATION_STAGE=""', start)
        output = self.root / "actual capsule parents"
        output.mkdir()
        script = (
            "set -euo pipefail\numask 077\nexport PATH=/usr/bin:/bin:$PATH\n"
            f"PUBLIC_OUTPUT_ROOT={shlex.quote(output.as_posix())}\n"
            f"SCRIPT_DIR={shlex.quote(SCRIPT.parent.as_posix())}\n"
            f"python3() {{ {shlex.quote(Path(sys.executable).as_posix())} \"$@\"; }}\n"
            + source[start:end] + "\n"
        )
        result = subprocess.run([str(bash), "-c", script], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in (".dcent-release-capsules", ".release-set-stages"):
            authority._require_private_windows_path(output / name, "actual capsule parent")
        publication = SCRIPT.with_name("release_set_publication.py")
        capability = output / ".dcent-release-capsules" / "stage-capability.json"
        created = subprocess.run([
            sys.executable, str(publication), "create-stage", "--parent",
            str(output / ".release-set-stages"), "--capability-output", str(capability)
        ], capture_output=True, text=True, timeout=30)
        self.assertEqual(created.returncode, 0, created.stderr)
        self.assertTrue(capability.is_file())
        destroyed = subprocess.run([
            sys.executable, str(publication), "destroy-stage", "--capability-file", str(capability)
        ], capture_output=True, text=True, timeout=30)
        self.assertEqual(destroyed.returncode, 0, destroyed.stderr)
        self.assertEqual(list((output / ".release-set-stages").iterdir()), [])

    def run_cli(
        self, *arguments: str, stdin: bytes = b""
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *arguments],
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_create_is_private_exact_invocation_bound_and_path_free(self) -> None:
        created = self.create()
        verified = authority.verify_authority(
            created.stage, self.release_invocation.stage
        )
        self.assertEqual(created.private_key.read_bytes(), self.private.read_bytes())
        self.assertEqual(created.public_key.read_bytes(), self.public.read_bytes())
        self.assertEqual(
            set(path.name for path in created.stage.iterdir()),
            {
                authority.DESCRIPTOR_NAME,
                authority.PRIVATE_KEY_NAME,
                authority.PUBLIC_KEY_NAME,
            },
        )
        self.assertEqual(
            verified.descriptor["invocation"]["invocation_id"],
            self.release_invocation.invocation_id,
        )
        descriptor_raw = created.descriptor.read_bytes()
        capability_raw = created.capability.read_bytes()
        self.assertNotIn(self.private.read_bytes(), descriptor_raw)
        self.assertNotIn(self.private.read_bytes(), capability_raw)
        self.assertNotIn(str(self.private).encode(), descriptor_raw)
        self.assertNotIn(str(self.public).encode(), descriptor_raw)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(created.stage.stat().st_mode), 0o700)
            for path in (*created.stage.iterdir(), created.capability):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
        elif os.name == "nt":
            authority._require_private_windows_path(
                created.stage, "created signing authority stage"
            )
            authority._require_private_windows_path(
                created.capability, "created signing authority capability"
            )
            for path in created.stage.iterdir():
                authority._require_private_windows_path(
                    path, f"created signing authority {path.name}"
                )

    @unittest.skipUnless(os.name == "nt", "Windows ACL proof is Windows-only")
    def test_windows_rejects_public_private_key_acl(self) -> None:
        authority.atomic_publish_directory.set_windows_file_acl(
            self.private,
            authority.atomic_publish_directory.WINDOWS_PUBLIC_FILE_SDDL,
        )
        with self.assertRaisesRegex(
            authority.SigningAuthorityError, "Everyone|untrusted SID"
        ):
            self.create()

    @unittest.skipUnless(os.name == "nt", "Windows ACL proof is Windows-only")
    def test_windows_normalizes_existing_capability_directory_acl(self) -> None:
        capability_directory = (
            self.authority_parent / authority.CAPABILITY_DIRECTORY
        )
        capability_directory.mkdir()
        authority.atomic_publish_directory.set_windows_directory_acl(
            capability_directory,
            authority.atomic_publish_directory.WINDOWS_PUBLIC_DIRECTORY_SDDL,
        )

        created = self.create()

        authority._require_private_windows_path(
            capability_directory, "existing capability directory"
        )
        authority._require_private_windows_path(
            created.capability, "created capability"
        )

    def test_query_result_and_cli_lifecycle_are_strict(self) -> None:
        result = self.run_cli(
            "create",
            "--stage-parent",
            str(self.authority_parent),
            "--invocation-stage",
            str(self.release_invocation.stage),
            "--private-key",
            str(self.private),
            "--public-key",
            str(self.public),
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        created = json.loads(result.stdout)
        for field in authority.QUERY_FIELDS:
            queried = self.run_cli(
                "query-result", "--field", field, stdin=result.stdout
            )
            self.assertEqual(queried.returncode, 0, queried.stderr.decode())
            self.assertEqual(queried.stdout.decode().strip(), created[field])
        checked = self.run_cli(
            "verify",
            "--invocation-stage",
            str(self.release_invocation.stage),
            created["stage"],
        )
        self.assertEqual(checked.returncode, 0, checked.stderr.decode())
        destroyed = self.run_cli(
            "destroy",
            "--capability",
            created["capability"],
            created["stage"],
        )
        self.assertEqual(destroyed.returncode, 0, destroyed.stderr.decode())
        self.assertFalse(Path(created["stage"]).exists())
        self.assertFalse(Path(created["capability"]).exists())

        noncanonical = json.dumps(created).encode("ascii")
        rejected = self.run_cli("query-result", "--field", "stage", stdin=noncanonical)
        self.assertNotEqual(rejected.returncode, 0)

    def test_create_is_idempotent_and_repairs_authenticated_partial_files(self) -> None:
        created = self.create()
        capability_raw = created.capability.read_bytes()
        created.public_key.unlink()
        if os.name == "posix":
            os.chmod(created.private_key, 0o600)
        created.private_key.write_bytes(b"PARTIAL")
        if os.name == "posix":
            os.chmod(created.private_key, 0o400)

        recovered = self.create()

        self.assertEqual(recovered, created)
        self.assertEqual(recovered.capability.read_bytes(), capability_raw)
        self.assertEqual(recovered.private_key.read_bytes(), self.private.read_bytes())
        self.assertEqual(recovered.public_key.read_bytes(), self.public.read_bytes())
        authority.verify_authority(recovered.stage, self.release_invocation.stage)

    def test_create_failure_after_capability_is_resumable(self) -> None:
        original = authority._ensure_stage_file
        calls = 0

        def fail_after_descriptor(path: Path, raw: bytes) -> None:
            nonlocal calls
            calls += 1
            original(path, raw)
            if calls == 1:
                raise OSError("injected interruption after descriptor publication")

        with mock.patch.object(
            authority, "_ensure_stage_file", side_effect=fail_after_descriptor
        ):
            with self.assertRaisesRegex(OSError, "injected interruption"):
                self.create()

        stages = [
            path
            for path in self.authority_parent.iterdir()
            if path.name.startswith(authority.STAGE_PREFIX)
        ]
        self.assertEqual(len(stages), 1)
        capability = authority.capability_path(stages[0])
        self.assertTrue(capability.is_file())
        recovered = self.create()
        authority.verify_authority(recovered.stage, self.release_invocation.stage)

    def test_durable_result_precedes_key_copy_and_is_idempotent(self) -> None:
        result_parent = self.root / "private-results"
        result_parent.mkdir()
        authority._set_private_directory(result_parent)
        result_output = result_parent / "signing-authority.result.json"
        original = authority._ensure_stage_file

        def interrupt_first_copy(path: Path, raw: bytes) -> None:
            original(path, raw)
            raise OSError("injected interruption after durable result")

        with mock.patch.object(
            authority, "_ensure_stage_file", side_effect=interrupt_first_copy
        ):
            with self.assertRaisesRegex(OSError, "durable result"):
                authority.create_authority(
                    self.authority_parent,
                    self.release_invocation.stage,
                    self.private,
                    self.public,
                    result_output=result_output,
                )

        result_raw = result_output.read_bytes()
        result = json.loads(result_raw)
        self.assertTrue(Path(result["capability"]).is_file())
        self.assertTrue(Path(result["stage"]).is_dir())
        synced: list[Path] = []
        original_sync = authority._fsync_directory

        def record_sync(path: Path) -> None:
            original_sync(path)
            synced.append(path)

        with mock.patch.object(
            authority, "_fsync_directory", side_effect=record_sync
        ):
            recovered = authority.create_authority(
                self.authority_parent,
                self.release_invocation.stage,
                self.private,
                self.public,
                result_output=result_output,
            )
        self.assertEqual(result_output.read_bytes(), result_raw)
        self.assertEqual(Path(result["stage"]), recovered.stage)
        self.assertIn(result_parent, synced)

    def test_create_recovers_linked_capability_publication_boundary(self) -> None:
        original = authority._unlink_verified
        interrupted = False

        def interrupt_pending(path: Path, metadata, label: str) -> None:
            nonlocal interrupted
            if label.startswith("published release signing authority") and not interrupted:
                interrupted = True
                raise OSError("injected interruption after capability link")
            original(path, metadata, label)

        with mock.patch.object(
            authority, "_unlink_verified", side_effect=interrupt_pending
        ):
            with self.assertRaisesRegex(OSError, "injected interruption"):
                self.create()

        stages = [
            path
            for path in self.authority_parent.iterdir()
            if path.name.startswith(authority.STAGE_PREFIX)
        ]
        self.assertEqual(len(stages), 1)
        capability = authority.capability_path(stages[0])
        pending = capability.with_name(f"{capability.name}.pending")
        self.assertTrue(capability.is_file())
        self.assertTrue(pending.is_file())
        recovered = self.create()
        self.assertFalse(pending.exists())
        authority.verify_capability(recovered.stage, recovered.capability)

    def test_create_rebinds_durable_capability_after_empty_stage_loss(self) -> None:
        created = self.create()
        before = json.loads(created.capability.read_bytes())
        for path in created.stage.iterdir():
            authority._unlink_verified(
                path, os.lstat(path), f"simulated lost stage {path.name}"
            )
        authority._fsync_directory(created.stage)
        authority._rmdir_verified(
            created.stage,
            os.lstat(created.stage),
            "simulated lost signing authority stage",
        )
        authority._fsync_directory(created.stage.parent)

        recovered = self.create()

        after = json.loads(recovered.capability.read_bytes())
        metadata = os.lstat(recovered.stage)
        self.assertEqual(after["token"], before["token"])
        self.assertEqual((after["stage_dev"], after["stage_ino"]), (
            metadata.st_dev,
            metadata.st_ino,
        ))
        authority.verify_authority(recovered.stage, self.release_invocation.stage)

    def test_descriptor_directory_barrier_precedes_every_key_copy(self) -> None:
        events: list[tuple[str, str]] = []
        original_ensure = authority._ensure_stage_file
        original_sync = authority._fsync_directory

        def record_ensure(path: Path, raw: bytes) -> None:
            original_ensure(path, raw)
            events.append(("file", path.name))

        def record_sync(path: Path) -> None:
            original_sync(path)
            events.append(("sync", path.name))

        with mock.patch.object(
            authority, "_ensure_stage_file", side_effect=record_ensure
        ), mock.patch.object(authority, "_fsync_directory", side_effect=record_sync):
            created = self.create()

        descriptor = events.index(("file", authority.DESCRIPTOR_NAME))
        private_key = events.index(("file", authority.PRIVATE_KEY_NAME))
        public_key = events.index(("file", authority.PUBLIC_KEY_NAME))
        stage_syncs = [
            index
            for index, event in enumerate(events)
            if event == ("sync", created.stage.name)
        ]
        self.assertTrue(any(descriptor < index < private_key for index in stage_syncs))
        self.assertTrue(any(private_key < index < public_key for index in stage_syncs))

    def test_destroy_retries_after_partial_key_removal(self) -> None:
        created = self.create()
        original = authority._unlink_verified
        failed = False

        def interrupt_public(path: Path, metadata, label: str) -> None:
            nonlocal failed
            if path.name == authority.PUBLIC_KEY_NAME and not failed:
                failed = True
                raise OSError("injected interruption during key removal")
            original(path, metadata, label)

        with mock.patch.object(
            authority, "_unlink_verified", side_effect=interrupt_public
        ):
            with self.assertRaisesRegex(OSError, "injected interruption"):
                authority.destroy_authority(created.stage, created.capability)

        self.assertFalse(created.private_key.exists())
        self.assertTrue(created.descriptor.exists())
        authority.destroy_authority(created.stage, created.capability)
        self.assertFalse(created.stage.exists())
        self.assertFalse(created.capability.exists())

    def test_destroy_retries_after_stage_removal(self) -> None:
        created = self.create()
        original = authority._unlink_verified
        failed = False

        def interrupt_capability(path: Path, metadata, label: str) -> None:
            nonlocal failed
            if path == created.capability and not failed:
                failed = True
                raise OSError("injected interruption after stage removal")
            original(path, metadata, label)

        with mock.patch.object(
            authority, "_unlink_verified", side_effect=interrupt_capability
        ):
            with self.assertRaisesRegex(OSError, "injected interruption"):
                authority.destroy_authority(created.stage, created.capability)

        self.assertFalse(created.stage.exists())
        self.assertTrue(created.capability.exists())
        authority.destroy_authority(created.stage, created.capability)
        self.assertFalse(created.capability.exists())
        synced: list[Path] = []
        original_sync = authority._fsync_directory

        def record_sync(path: Path) -> None:
            original_sync(path)
            synced.append(path)

        with mock.patch.object(
            authority, "_fsync_directory", side_effect=record_sync
        ):
            authority.destroy_authority(created.stage, created.capability)
        self.assertIn(created.stage.parent, synced)

    def test_destroy_upgrades_legacy_capability_before_mutation(self) -> None:
        created = self.create()
        current = json.loads(created.capability.read_bytes())
        legacy = {
            "authority_id": current["authority_id"],
            "invocation_id": current["invocation_id"],
            "schema": authority.LEGACY_CAPABILITY_SCHEMA,
            "stage_name": current["stage_name"],
            "token": current["token"],
        }
        if os.name == "posix":
            os.chmod(created.capability, 0o600)
        created.capability.write_bytes(authority.canonical_bytes(legacy))
        if os.name == "posix":
            os.chmod(created.capability, 0o400)

        authority.destroy_authority(created.stage, created.capability)

        self.assertFalse(created.stage.exists())
        self.assertFalse(created.capability.exists())

    @unittest.skipUnless(
        os.name == "posix" and Path("/proc/self/fd").is_dir(),
        "file-descriptor accounting requires procfs",
    )
    def test_exclusive_write_closes_descriptor_when_fdopen_fails(self) -> None:
        output = self.root / "fdopen-failure"
        before = len(list(Path("/proc/self/fd").iterdir()))
        with mock.patch.object(authority.os, "fdopen", side_effect=OSError("fdopen")):
            with self.assertRaisesRegex(OSError, "fdopen"):
                authority._write_exclusive(output, b"bounded\n")
        after = len(list(Path("/proc/self/fd").iterdir()))
        self.assertEqual(after, before)
        self.assertFalse(output.exists())

    def test_wrong_capability_and_invocation_cannot_authorize(self) -> None:
        first = self.create()
        other_invocation = invocation.create_invocation(self.invocation_parent, "other")
        second = authority.create_authority(
            self.authority_parent, other_invocation.stage, self.private, self.public
        )
        with self.assertRaises(authority.SigningAuthorityError):
            authority.verify_authority(first.stage, other_invocation.stage)
        with self.assertRaises(authority.SigningAuthorityError):
            authority.destroy_authority(first.stage, second.capability)
        self.assertTrue(first.stage.is_dir())
        self.assertTrue(second.stage.is_dir())

    def test_symlink_source_is_rejected(self) -> None:
        symlink = self.keys / "private-link.pem"
        try:
            symlink.symlink_to(self.private)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlinks unavailable: {error}")
        with self.assertRaises(authority.SigningAuthorityError):
            authority.create_authority(
                self.authority_parent,
                self.release_invocation.stage,
                symlink,
                self.public,
            )

    def test_hardlink_fifo_and_loose_private_mode_are_rejected(self) -> None:
        hardlink = self.keys / "private-hardlink.pem"
        try:
            os.link(self.private, hardlink)
        except OSError as error:
            self.skipTest(f"hardlinks unavailable: {error}")
        with self.assertRaisesRegex(
            authority.SigningAuthorityError, "exactly one filesystem link"
        ):
            self.create()
        hardlink.unlink()

        if os.name == "posix":
            fifo = self.keys / "private-fifo.pem"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(
                authority.SigningAuthorityError, "regular file"
            ):
                authority.create_authority(
                    self.authority_parent,
                    self.release_invocation.stage,
                    fifo,
                    self.public,
                )
            os.chmod(self.private, 0o644)
            with self.assertRaisesRegex(
                authority.SigningAuthorityError, "group or other"
            ):
                self.create()

    @unittest.skipUnless(os.name == "posix", "pathname replacement proof is POSIX-only")
    def test_open_handle_rejects_pathname_rotation(self) -> None:
        replacement = self.keys / "replacement.pem"
        replacement.write_bytes(b"ROTATED-PRIVATE-KEY\n")
        os.chmod(replacement, 0o600)

        def rotate() -> None:
            os.replace(replacement, self.private)

        with self.assertRaisesRegex(
            authority.SigningAuthorityError,
            "pathname was replaced|exactly one filesystem link",
        ):
            authority._read_source_file(
                self.private,
                "release private key",
                private=True,
                after_open=rotate,
            )

    @unittest.skipUnless(os.name == "posix", "FIFO race proof is POSIX-only")
    def test_raced_fifo_open_never_blocks_before_handle_revalidation(self) -> None:
        code = r"""import importlib.util, os, pathlib, sys
script=pathlib.Path(sys.argv[1]); target=pathlib.Path(sys.argv[2])
sys.path.insert(0, str(script.parent))
spec=importlib.util.spec_from_file_location("rsa_fifo_child", script)
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
real_open=module.os.open; raced=False
def replace_then_open(path, flags, *args, **kwargs):
    global raced
    if not raced and pathlib.Path(path) == target:
        raced=True; target.unlink(); os.mkfifo(target)
    return real_open(path, flags, *args, **kwargs)
module.os.open=replace_then_open
try:
    module._read_source_file(target, "raced private key", private=True)
except module.SigningAuthorityError:
    raise SystemExit(0)
raise SystemExit("raced FIFO unexpectedly admitted")
"""
        completed = subprocess.run(
            [sys.executable, "-c", code, str(SCRIPT), str(self.private)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())

    def test_stage_tampering_and_cleanup_escape_are_rejected(self) -> None:
        created = self.create()
        if os.name == "posix":
            os.chmod(created.private_key, 0o600)
        created.private_key.write_bytes(b"TAMPERED\n")
        if os.name == "posix":
            os.chmod(created.private_key, 0o400)
        with self.assertRaises(authority.SigningAuthorityError):
            authority.verify_authority(created.stage, self.release_invocation.stage)

        other_root = self.root / "must-survive"
        other_root.mkdir()
        marker = other_root / "marker"
        marker.write_text("retained", encoding="ascii")
        alias = self.authority_parent / "authority-alias"
        try:
            alias.symlink_to(other_root, target_is_directory=True)
        except (OSError, NotImplementedError):
            alias = None
        if alias is not None:
            with self.assertRaises(authority.SigningAuthorityError):
                authority.destroy_authority(alias, created.capability)
        self.assertEqual(marker.read_text(encoding="ascii"), "retained")

    @unittest.skipUnless(os.name == "nt", "junction rejection is Windows-only")
    def test_windows_junction_source_component_is_rejected(self) -> None:
        target = self.root / "junction-target"
        target.mkdir()
        private = target / "private.pem"
        private.write_bytes(b"PRIVATE-JUNCTION\n")
        junction = self.root / "junction"
        made = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(target)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if made.returncode != 0:
            self.skipTest(f"junction creation unavailable: {made.stderr}")
        try:
            with self.assertRaisesRegex(
                authority.SigningAuthorityError, "reparse-point"
            ):
                authority.create_authority(
                    self.authority_parent,
                    self.release_invocation.stage,
                    junction / "private.pem",
                    self.public,
                )
        finally:
            os.rmdir(junction)
        self.assertEqual(private.read_bytes(), b"PRIVATE-JUNCTION\n")


# Explicit platform ownership keeps mandatory tests executing without turning
# decorator skips into a passing blocking gate. New test methods must be owned.
PORTABLE_TESTS = (
    "test_driver_result_parent_preparation_allows_actual_durable_authority",
    "test_create_is_private_exact_invocation_bound_and_path_free",
    "test_query_result_and_cli_lifecycle_are_strict",
    "test_create_is_idempotent_and_repairs_authenticated_partial_files",
    "test_create_failure_after_capability_is_resumable",
    "test_durable_result_precedes_key_copy_and_is_idempotent",
    "test_create_recovers_linked_capability_publication_boundary",
    "test_create_rebinds_durable_capability_after_empty_stage_loss",
    "test_descriptor_directory_barrier_precedes_every_key_copy",
    "test_destroy_retries_after_partial_key_removal",
    "test_destroy_retries_after_stage_removal",
    "test_destroy_upgrades_legacy_capability_before_mutation",
    "test_wrong_capability_and_invocation_cannot_authorize",
    "test_hardlink_fifo_and_loose_private_mode_are_rejected",
    "test_stage_tampering_and_cleanup_escape_are_rejected",
)
POSIX_TESTS = (
    # Creating symlinks on Windows requires privileges; its reparse-point
    # rejection is exercised by the mandatory Windows junction fixture.
    "test_symlink_source_is_rejected",
    "test_exclusive_write_closes_descriptor_when_fdopen_fails",
    "test_open_handle_rejects_pathname_rotation",
    "test_raced_fifo_open_never_blocks_before_handle_revalidation",
)
WINDOWS_TESTS = (
    "test_windows_rejects_public_private_key_acl",
    "test_windows_normalizes_existing_capability_directory_acl",
    "test_windows_junction_source_component_is_rejected",
    "test_capsule_directory_preparation_admits_actual_release_set_stage",
)


def host_platform_suite(host: str) -> unittest.TestSuite:
    owned = PORTABLE_TESTS + POSIX_TESTS + WINDOWS_TESTS
    discovered = unittest.defaultTestLoader.getTestCaseNames(ReleaseSigningAuthorityTests)
    if len(owned) != len(set(owned)) or set(owned) != set(discovered):
        raise ValueError("signing authority test platform ownership is incomplete or duplicated")
    if host == "posix":
        selected = PORTABLE_TESTS + POSIX_TESTS
    elif host == "nt":
        selected = PORTABLE_TESTS + WINDOWS_TESTS
    else:
        raise ValueError(f"unsupported signing test host: {host}")
    return unittest.TestSuite(ReleaseSigningAuthorityTests(name) for name in selected)


if __name__ == "__main__":
    if sys.argv[1:] == ["--host-platform"]:
        result = unittest.TextTestRunner(verbosity=2).run(host_platform_suite(os.name))
        raise SystemExit(0 if result.wasSuccessful() and not result.skipped else 1)
    unittest.main(verbosity=2)
