#!/usr/bin/env python3
"""Offline contract tests for the S19k hermetic dependency materializer."""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("s19k_hermetic_materialize_inner.sh")
POLICY = Path(__file__).with_name("s19k_hermetic_dependencies.json")
PROJECT = SCRIPT.parent.parent
REPO_ROOT = PROJECT.parent.parent
SELECTION_SCHEMA = "dcentos.s19k-hermetic-dependency-selection/v1"
POLICY_SHA256 = "f7101ab4eff6fe2eb59a4080f0d3aef96d9e6ef525e0071c861298c4d4378fa1"
BUILDROOT_COMMIT = "7c8edc1b402efcd7bba2dabfe0b3be877adaed7a"
BUILDROOT_ARCHIVE_SHA256 = "b9dc4163c397c67ad7cbe71499cfba7363413b021e8c49cca96892adb90acd19"
BUILDROOT_ARCHIVE_BYTES = 35_901_440
TOOLCHAIN_SHA256 = "20181f828e1075f1a493947ff91e82dd578ce9f8638fbdfc39e24b62857d8f8d"
MANDATORY_CLASSES = [
    "amlogic-input",
    "buildroot-download",
    "buildroot-source",
    "cargo-source",
    "dashboard-dependency",
    "toolchain-archive",
]


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + b"\n"
    )


def write(root: Path, relative: str, raw: bytes, executable: bool = False) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o755 if executable else 0o644)
    return path


class HermeticMaterializerPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy_raw = POLICY.read_bytes()
        cls.policy = json.loads(cls.policy_raw)
        cls.script = SCRIPT.read_text(encoding="utf-8")

    def test_policy_is_canonical_and_review_digest_is_pinned(self) -> None:
        self.assertEqual(self.policy_raw, canonical(self.policy))
        self.assertEqual(digest(self.policy_raw), POLICY_SHA256)
        self.assertIn(POLICY_SHA256, self.script)
        self.assertEqual(self.policy["schema"], "dcentos.s19k-hermetic-dependency-policy/v1")
        self.assertEqual(self.policy["selection_schema"], SELECTION_SCHEMA)
        self.assertEqual(
            self.policy["authority"],
            "dependency-materialization-only-no-build-release-install-or-flash-authority",
        )

    def test_policy_pins_every_mandatory_source_class(self) -> None:
        self.assertEqual(self.policy["mandatory_selection_classes"], MANDATORY_CLASSES)
        self.assertEqual(
            self.policy["buildroot"],
            {
                "commit": BUILDROOT_COMMIT,
                "downloads_destination": "buildroot/dl",
                "source_archive_bytes": BUILDROOT_ARCHIVE_BYTES,
                "source_archive_sha256": BUILDROOT_ARCHIVE_SHA256,
                "source_destination": "buildroot/source",
                "url": "https://github.com/buildroot/buildroot.git",
            },
        )
        self.assertEqual(self.policy["cargo"]["vendor_destination"], "cargo/vendor")
        self.assertEqual(
            self.policy["dashboard"]["npm_cache_destination"], "dashboard/npm-cache"
        )
        self.assertEqual(self.policy["toolchain"]["sha256"], TOOLCHAIN_SHA256)
        self.assertEqual(
            self.policy["toolchain"]["download_root"],
            "buildroot/dl",
        )

    def test_policy_matches_current_authenticated_lockfile_bytes(self) -> None:
        for section in ("cargo", "dashboard"):
            lock = self.policy[section]["lock"]
            path = REPO_ROOT / lock["path"]
            raw = path.read_bytes()
            self.assertEqual(len(raw), lock["bytes"], section)
            self.assertEqual(digest(raw), lock["sha256"], section)
        self.assertEqual(
            self.policy["cargo"]["lock"]["sha256"],
            "1b0f9ccade4f175dee81c38851607f1378734faef98b7d518e6551624b764663",
        )
        self.assertEqual(
            self.policy["dashboard"]["lock"]["sha256"],
            "b3108c123893b70f413c0a3cf4d054a8532f1d1290a87b8c3bf3441a94d8e739",
        )

    def test_policy_pins_exact_s19k_amlogic_inputs(self) -> None:
        observed = {item["name"]: item for item in self.policy["amlogic_inputs"]}
        self.assertEqual(set(observed), {"vmlinux.bin", "devicetree.dtb", "fw-info"})
        self.assertEqual(
            (observed["vmlinux.bin"]["sha256"], observed["vmlinux.bin"]["bytes"]),
            (
                "d5013ac9f545df3b0792ea2cd8902b51e323bbb6f73ff0fea17bbee9f6157fe6",
                14_960_648,
            ),
        )
        self.assertEqual(
            (observed["devicetree.dtb"]["sha256"], observed["devicetree.dtb"]["bytes"]),
            (
                "540c1770543d9620e106ea4287c2a534f5efd85c912e97d6be6295930506b257",
                20_945,
            ),
        )
        self.assertEqual(
            (observed["fw-info"]["sha256"], observed["fw-info"]["bytes"]),
            (
                "2c2aca134728f17e853701ad860956de933f96a0ada5b0eeae42d6e338af8710",
                278,
            ),
        )

    def test_source_and_builder_bindings_are_exact_without_self_reference(self) -> None:
        self.assertEqual(
            self.policy["source_commit_binding"],
            {
                "policy_path": "DCENT_OS_Antminer/scripts/s19k_hermetic_dependencies.json",
                "verification": "admitted-immutable-snapshot-exact-tree-before-and-after",
            },
        )
        self.assertEqual(
            self.policy["materialization"]["builder_image_binding"],
            "authenticated-policy-exact-name-at-sha256",
        )
        self.assertEqual(
            self.policy["builder"]["image"],
            "dcentos-s19k-hermetic-builder@sha256:"
            "b977715aacf5d50ea987a4486e2e038139a1d3dcbfeec156d30f552888a2545b",
        )
        self.assertEqual(
            self.policy["builder"]["dockerfile"],
            {
                "bytes": 3309,
                "path": "DCENT_OS_Antminer/scripts/docker/Dockerfile.s19k-hermetic",
                "sha256": "3a0905958eddd353958b4f969f5c859746562f6dc88c3ad3aeeeea16dad436bf",
            },
        )
        self.assertEqual(
            self.policy["builder"]["versions"]["rust_target"],
            "aarch64-unknown-linux-musl",
        )
        # A source-controlled file cannot truthfully contain the hash of the
        # commit that contains itself. The selection receives the runtime exact
        # commit only after the complete snapshot is Git-object verified.
        self.assertNotIn("source_commit", self.policy)
        self.assertNotIn("source_commit", self.policy["builder"])
        self.assertIn('IMAGE = re.compile(', self.script)
        self.assertIn('builder_image != builder["image"]', self.script)
        self.assertIn('"source_commit": source_commit', self.script)
        self.assertIn('"builder_image": builder_image', self.script)

    def test_materializer_has_separate_network_source_only_workflow(self) -> None:
        required = (
            "DCENT_MATERIALIZER_NETWORK_MODE",
            "source-fetch-only",
            "fetch --depth=1 --no-tags origin \"$BUILDROOT_COMMIT\"",
            "--output \"$RESULT_ROOT/buildroot/source/buildroot-source.tar\"",
            "dcentos_am3_s19kpro_full_defconfig",
            "    source\n",
            "cargo vendor",
            "    --locked",
            "    --versioned-dirs",
            "npm ci --ignore-scripts --no-audit --no-fund",
            "s19k_hermetic_image_producer.py exact-set",
            "release_authority=false",
            "install_authority=false",
            "flash_authority=false",
        )
        for value in required:
            self.assertIn(value, self.script)
        self.assertGreaterEqual(self.script.count('"$SNAPSHOT_HELPER" verify'), 2)
        self.assertNotIn("verify-against-git", self.script)
        self.assertNotIn("GIT_OBJECT_REPO", self.script)
        self.assertIn(BUILDROOT_COMMIT, self.script)
        self.assertIn(BUILDROOT_ARCHIVE_SHA256, self.script)
        self.assertIn(TOOLCHAIN_SHA256, self.script)

    def test_materializer_contains_no_build_install_flash_or_miner_executor(self) -> None:
        active = "\n".join(
            line for line in self.script.splitlines() if not line.lstrip().startswith("#")
        )
        forbidden_patterns = (
            r"\bcargo\s+build\b",
            r"\bnpm\s+run\s+build\b",
            r"\bdocker\s+(?:build|run|create)\b",
            r"\b(?:ssh|scp|sftp)\b",
            r"\b(?:nandwrite|nanddump|flash_erase|fw_setenv|sysupgrade|reboot)\b",
            r"\b(?:curl|wget)\b.*(?:miner|firmware)",
        )
        for pattern in forbidden_patterns:
            self.assertIsNone(re.search(pattern, active), pattern)
        self.assertNotIn("DCENT_REQUIRE_RELEASE_KEY", active)
        self.assertNotIn("CLEAR_FOR_FLASH=true", active)

    def test_shell_is_posix_sh_and_embedded_python_parses_as_python39(self) -> None:
        self.assertTrue(self.script.startswith("#!/bin/sh\n"))
        self.assertIn("set -eu\n", self.script)
        for bashism in ("[[", "]]", "function ", "<(", "${BASH_", "#!/bin/bash"):
            self.assertNotIn(bashism, self.script)
        snippets = re.findall(r"<<'PY'\n(.*?)\nPY(?:\n|\Z)", self.script, flags=re.DOTALL)
        self.assertGreaterEqual(len(snippets), 4)
        for index, snippet in enumerate(snippets):
            try:
                ast.parse(snippet, filename=f"embedded-materializer-{index}.py", feature_version=(3, 9))
            except SyntaxError as error:  # pragma: no cover - assertion detail
                self.fail(f"embedded Python {index} is not Python 3.9 syntax: {error}")

    @unittest.skipUnless(shutil.which("bash"), "bash is unavailable for shell syntax validation")
    def test_shell_parses_with_bash_posix_frontend(self) -> None:
        result = subprocess.run(
            [shutil.which("bash") or "bash", "-n", SCRIPT.name],
            cwd=SCRIPT.parent,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which("bash"), "bash is unavailable for fail-closed smoke test")
    def test_missing_invocation_contract_fails_before_network(self) -> None:
        clean_env = dict(os.environ)
        for name in tuple(clean_env):
            if name.startswith("DCENT_MATERIALIZER_"):
                clean_env.pop(name)
        result = subprocess.run(
            [shutil.which("bash") or "bash", SCRIPT.name],
            cwd=SCRIPT.parent,
            env=clean_env,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing required environment", result.stderr)
        self.assertNotIn("github.com", result.stdout)


class MaterializerSelectionBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        script = SCRIPT.read_text(encoding="utf-8")
        snippets = re.findall(r"<<'PY'\n(.*?)\nPY(?:\n|\Z)", script, flags=re.DOTALL)
        cls.finalizer = next(
            snippet for snippet in snippets if "def dependency_class" in snippet
        )
        cls.empty_directory_pruner = next(
            snippet
            for snippet in snippets
            if "empty materializer output directory remains" in snippet
        )

    def make_fixture(self, root: Path) -> tuple[Path, Path]:
        toolchain = write(
            root,
            "buildroot/dl/toolchain-external-custom/toolchain.tar.xz",
            b"toolchain-source",
        )
        write(root, "buildroot/dl/busybox.tar.bz2", b"buildroot-download")
        buildroot_archive = write(
            root, "buildroot/source/buildroot-source.tar", b"fixture Git archive"
        )
        write(root, "cargo/vendor/example-1.0.0/src/lib.rs", b"pub fn fixture() {}\n")
        write(root, "dashboard/npm-cache/_cacache/content-v2/sha512/aa/blob", b"npm-tarball")
        kernel = write(root, "amlogic/s19kpro/vmlinux.bin", b"kernel")
        dtb = write(root, "amlogic/s19kpro/devicetree.dtb", b"dtb")
        fw_info = write(root, "amlogic/s19kpro/fw-info", b"model=s19kpro\n")
        policy = {
            "builder": {
                "image": "registry.invalid/s19k-builder@sha256:" + "b" * 64,
                "toolchain_id": "fixture-toolchain-v1",
            },
            "buildroot": {
                "source_destination": "buildroot/source",
                "downloads_destination": "buildroot/dl",
                "source_archive_bytes": buildroot_archive.stat().st_size,
                "source_archive_sha256": digest(buildroot_archive.read_bytes()),
            },
            "cargo": {"vendor_destination": "cargo/vendor"},
            "dashboard": {"npm_cache_destination": "dashboard/npm-cache"},
            "mandatory_selection_classes": MANDATORY_CLASSES,
            "toolchain": {
                "archive": "toolchain.tar.xz",
                "download_root": "buildroot/dl",
                "sha256": digest(toolchain.read_bytes()),
            },
            "amlogic_inputs": [
                {
                    "name": "vmlinux.bin",
                    "destination": "amlogic/s19kpro/vmlinux.bin",
                    "sha256": digest(kernel.read_bytes()),
                    "bytes": kernel.stat().st_size,
                },
                {
                    "name": "devicetree.dtb",
                    "destination": "amlogic/s19kpro/devicetree.dtb",
                    "sha256": digest(dtb.read_bytes()),
                    "bytes": dtb.stat().st_size,
                },
                {
                    "name": "fw-info",
                    "destination": "amlogic/s19kpro/fw-info",
                    "sha256": digest(fw_info.read_bytes()),
                    "bytes": fw_info.stat().st_size,
                },
            ],
        }
        policy_path = root.parent / "fixture-policy.json"
        policy_raw = canonical(policy)
        policy_path.write_bytes(policy_raw)
        finalizer_path = root.parent / "finalizer.py"
        fixture_finalizer = self.finalizer.replace(POLICY_SHA256, digest(policy_raw))
        finalizer_path.write_text(fixture_finalizer, encoding="utf-8", newline="\n")
        return policy_path, finalizer_path

    def invoke(
        self,
        finalizer: Path,
        mode: str,
        policy: Path,
        root: Path,
        selection: Path,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(finalizer),
                mode,
                str(policy),
                str(root),
                str(selection),
                "a" * 40,
                "registry.invalid/s19k-builder@sha256:" + "b" * 64,
                "fixture-toolchain-v1",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def prune_empty_directories(self, root: Path) -> subprocess.CompletedProcess[str]:
        pruner = root.parent / "prune-empty-directories.py"
        pruner.write_text(self.empty_directory_pruner, encoding="utf-8", newline="\n")
        return subprocess.run(
            [sys.executable, str(pruner), str(root)],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_empty_cache_scaffolding_is_pruned_before_exact_selection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "inputs"
            root.mkdir()
            policy, finalizer = self.make_fixture(root)
            (root / "dashboard/npm-cache/_cacache/tmp/nested").mkdir(parents=True)
            (root / "cargo/vendor/empty/scaffolding").mkdir(parents=True)
            pruned = self.prune_empty_directories(root)
            self.assertEqual(pruned.returncode, 0, pruned.stderr)
            self.assertFalse((root / "dashboard/npm-cache/_cacache/tmp").exists())
            self.assertFalse((root / "cargo/vendor/empty").exists())
            selection = base / "selection.json"
            created = self.invoke(finalizer, "create", policy, root, selection)
            self.assertEqual(created.returncode, 0, created.stderr)
            replay = self.invoke(finalizer, "verify", policy, root, selection)
            self.assertEqual(replay.returncode, 0, replay.stderr)

    def test_finalizer_emits_exact_canonical_producer_selection_and_replays(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "inputs"
            root.mkdir()
            policy, finalizer = self.make_fixture(root)
            selection = base / "selection.json"
            created = self.invoke(finalizer, "create", policy, root, selection)
            self.assertEqual(created.returncode, 0, created.stderr)
            raw = selection.read_bytes()
            value = json.loads(raw)
            self.assertEqual(raw, canonical(value))
            self.assertEqual(value["schema"], SELECTION_SCHEMA)
            self.assertEqual(
                sorted({item["class"] for item in value["inputs"]}), MANDATORY_CLASSES
            )
            paths = [item["path"] for item in value["inputs"]]
            self.assertEqual(paths, sorted(paths, key=lambda item: item.encode("utf-8")))
            replay = self.invoke(finalizer, "verify", policy, root, selection)
            self.assertEqual(replay.returncode, 0, replay.stderr)

    def test_finalizer_refuses_compiled_or_mutable_dependency_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "inputs"
            root.mkdir()
            policy, finalizer = self.make_fixture(root)
            write(root, "cargo/vendor/example-1.0.0/target/object.o", b"compiled")
            result = self.invoke(finalizer, "create", policy, root, base / "selection.json")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("mutable/compiled state", result.stderr)

    def test_finalizer_refuses_missing_mandatory_class(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "inputs"
            root.mkdir()
            policy, finalizer = self.make_fixture(root)
            (root / "buildroot/dl/busybox.tar.bz2").unlink()
            result = self.invoke(finalizer, "create", policy, root, base / "selection.json")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("mandatory dependency classes are incomplete", result.stderr)


if __name__ == "__main__":
    unittest.main()
