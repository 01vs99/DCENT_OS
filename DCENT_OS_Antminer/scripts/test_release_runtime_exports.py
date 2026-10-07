#!/usr/bin/env python3
"""Actual release-container fixtures, production ELF identity and throwaway keys.

The caller holds the shared heavy lock for the real cross-ELF setup. Importing
this module never builds anything; publication tests may reuse package_fixture.
"""
from __future__ import annotations

import argparse
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import unittest
import zlib

import release_runtime_exports as exports
import runtime_image_manifest as runtime
import sign_release_artifact


def command(*args, **kwargs):
    result = subprocess.run(list(map(str, args)), capture_output=True, timeout=180, **kwargs)
    if result.returncode:
        raise RuntimeError(f"fixture command {args[0]} failed: {result.stderr.decode(errors='replace')}")
    return result.stdout


def newc(entries):
    """Byte-format negative fixture helper; successful packages use real cpio."""
    output = bytearray()
    for ino, (name, mode, payload, links) in enumerate([*entries, ("TRAILER!!!", 0, b"", 1)], 1):
        encoded = name.encode() + b"\0"
        fields = (ino, mode, 0, 0, links, 0, len(payload), 0, 0, 0, 0, len(encoded), 0)
        output.extend(b"070701" + b"".join(f"{value:08x}".encode() for value in fields) + encoded)
        output.extend(b"\0" * (-len(output) % 4))
        output.extend(payload)
        output.extend(b"\0" * (-len(output) % 4))
    return bytes(output)


def wrap_ramdisk(root: bytes, *, arm64=False):
    packed = gzip.compress(root, mtime=0)
    header = bytearray(struct.pack(">7I4B32s", 0x27051956, 0, 0, len(packed), 0, 0, zlib.crc32(packed), 5, 22 if arm64 else 2, 3, 1, b"test-only rootfs"))
    struct.pack_into(">I", header, 4, zlib.crc32(header))
    return bytes(header) + packed


def root_payload(root: Path, kind: str, directory: Path) -> bytes:
    if kind == "cpio":
        names = [".", *sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))]
        return command("cpio", "-o", "--format=newc", "--quiet", cwd=root,
                       input=("\n".join(names) + "\n").encode())
    if kind == "squashfs":
        output = directory / "root.squashfs"
        command("mksquashfs", root, output, "-noappend", "-no-xattrs", "-comp", "gzip", "-processors", "1", "-quiet")
        return output.read_bytes()
    if kind == "ext2":
        output = directory / "root.ext2"
        with output.open("wb") as stream:
            stream.truncate(128 * 1024**2)
        board = json.loads((root / runtime.MANIFEST).read_text())["board_target"]
        label = "DCENT_BM1391_RT" if board in ("am1-s15", "am1-t15") else "DCENT_C43_ROOT"
        command("mke2fs", "-q", "-F", "-t", "ext2", "-b", "4096", "-L", label,
                "-O", "none,ext_attr,resize_inode,dir_index,filetype,sparse_super,large_file", "-d", root, output)
        last = ((root / runtime.DAEMON).stat().st_size - 1) // 4096
        command("debugfs", "-w", "-R", f"fallocate /{runtime.DAEMON} 0 {last}", output)
        command("e2fsck", "-f", "-n", output)
        return output.read_bytes()
    raise ValueError(kind)


def write_tar(path: Path, files: dict[str, bytes]):
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


def write_card(path: Path, payload: bytes, *, fat=False):
    start = 2048
    if not fat:
        start += 2048  # The runtime reader requires root partition 2.
    size = (len(payload) + 511) // 512
    mbr = bytearray(512)
    if not fat:
        struct.pack_into("<B3sB3sII", mbr, 446, 128, bytes(3), 0x0C, bytes(3), 2048, 2048)
    struct.pack_into("<B3sB3sII", mbr, 446 + (0 if fat else 16), 128 if fat else 0, bytes(3), 0x0C if fat else 0x83, bytes(3), start, size)
    mbr[510:] = b"\x55\xaa"
    with path.open("wb") as stream:
        stream.truncate((start + size) * 512)
        stream.write(mbr)
        stream.seek(start * 512)
        stream.write(payload)


def package_fixture(directory: Path, *, board="am1-s9", key=None, pubkey=None, daemon=None,
                    hardware_recipe="board-default") -> dict:
    """Create one signed real package; boot fixture bytes grant no media claim."""
    directory.mkdir(parents=True, exist_ok=True)
    producer = exports.producer_for(board)
    if daemon is None:
        from test_runtime_image_manifest import fixture
        key, pubkey, daemon = fixture(directory / "elf", machine="aarch64-unknown-linux-musl" if producer.cargo_variant == "amlogic" else "armv7-unknown-linux-musleabihf")
    if key is None or pubkey is None:
        raise ValueError("fixture daemon needs its matching throwaway key pair")
    root = directory / "rootfs"
    (root / "etc/dcentos").mkdir(parents=True)
    (root / "usr/local/bin").mkdir(parents=True)
    (root / "usr/bin").mkdir(parents=True)
    shutil.copyfile(daemon, root / runtime.DAEMON)
    os.link(root / runtime.DAEMON, root / "usr/bin/dcentrald")
    runtime.prepare(root, board, "beta", "1.2.3", key, pubkey, hardware_recipe)
    artifact = directory / producer.primary_artifact
    if producer.runtime_root == "sysupgrade-root":
        if producer.cargo_variant == "amlogic":
            payload = wrap_ramdisk(root_payload(root, "cpio", directory), arm64=True)
        else:
            payload = root_payload(root, "squashfs", directory)
        write_tar(artifact, {f"sysupgrade-{board}/root": payload})
    elif producer.runtime_root == "bb-ramdisk":
        raw = root_payload(root, "cpio", directory)
        write_tar(artifact, {f"dcentos-{board}-sdcard/ramdisk.gz": wrap_ramdisk(raw),
                             f"dcentos-{board}-sdcard/uramdisk.image.gz": gzip.compress(raw, mtime=0)})
    elif producer.runtime_root in ("partition2-squashfs", "partition2-ext2"):
        write_card(artifact, root_payload(root, producer.runtime_root.split("-", 1)[1], directory))
    elif producer.runtime_root == "fat-ramdisk":
        filesystem = directory / "boot.vfat"
        with filesystem.open("wb") as stream:
            stream.truncate(96 * 1024**2)
        command("mkfs.vfat", "-F", "32", "-n", "DCENTOS", filesystem)
        for name in ("BOOT.BIN", "devicetree.dtb", "system.bit", "uImage", "uEnv.txt", "uramdisk.image.gz"):
            path = directory / name
            path.write_bytes(wrap_ramdisk(root_payload(root, "squashfs", directory)) if name == "uramdisk.image.gz" else b"fixture boot bytes; not boot-input qualification\n")
            command("mcopy", "-i", filesystem, path, "::" + name)
        write_card(artifact, filesystem.read_bytes(), fat=True)
    else:
        raise ValueError("unsupported test producer")
    manifest, signature = Path(str(artifact) + ".runtime-image.json"), Path(str(artifact) + ".runtime-image.sig")
    # Export through production: publication fixtures cannot be signed plausible
    # JSON beside arbitrary text. The actual embedded ELF/pair must already pass.
    exports.export_artifact_runtime(artifact, pubkey, board, "beta", "1.2.3", hardware_recipe)
    sign_release_artifact.sign_artifact(argparse.Namespace(artifact=str(artifact), output_sig=str(artifact) + ".sig", key=str(key), pubkey=str(pubkey)))
    return dict(artifact=artifact, manifest=manifest, signature=signature, key=key, pubkey=pubkey, daemon=daemon, rootfs=root)


class ContainerStructureTests(unittest.TestCase):
    def cpio_fixture(self, *, signed_default=False):
        # This tests container structure, not executable/signature admission.
        # The manifest must still describe the runtime member inventory.
        manifest = dict(manifest_profile=runtime.PROFILE, board_target="am1-s9",
                        channel="beta", version="1.2.3", daemon_sha256="0" * 64,
                        daemon_size=5)
        directories = ["etc", "etc/dcentos", "usr", "usr/local", "usr/local/bin"]
        files = {name: b"value" for name in exports.LIMITS}
        if signed_default:
            default = b"[mining]\nenabled=false\n"
            manifest["settings_default_sha256"] = runtime.signed_runtime.settings_default_digest(default)
            directories += ["usr/share", "usr/share/dcentos"]
            files[runtime.SETTINGS_DEFAULT] = default
        files[runtime.MANIFEST] = json.dumps(manifest).encode()
        return ([(name, stat.S_IFDIR | 0o755, b"", 1) for name in directories]
                + [(name, stat.S_IFREG | 0o644, value, 1) for name, value in files.items()])

    def test_public_verifier_normalizes_malformed_container(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.tar"
            path.write_bytes(b"signed arbitrary text is not a release container")
            with self.assertRaisesRegex(ValueError, "malformed release container"):
                exports.verify_artifact_runtime(path, path, path, path, "am1-s9", "beta", "1.2.3", "board-default")

    def test_cpio_duplicate_traversal_and_symlink_parents_refused(self):
        base = self.cpio_fixture()
        self.assertEqual(set(exports.cpio_files(newc(base))), set(exports.LIMITS))
        for entries in (base + [base[-1]], base + [("../escape", stat.S_IFREG, b"x", 1)],
                        [(name, stat.S_IFLNK if name == "usr" else mode, data, links) for name, mode, data, links in base]):
            with self.subTest(entries=entries[-1][0]), self.assertRaises(ValueError):
                exports.cpio_files(newc(entries))

    def test_cpio_signed_default_is_extracted_and_cannot_be_missing_or_linked(self):
        base = self.cpio_fixture(signed_default=True)
        observed = exports.cpio_files(newc(base))
        self.assertEqual(set(observed), set(exports.LIMITS) | {runtime.SETTINGS_DEFAULT})
        self.assertEqual(observed[runtime.SETTINGS_DEFAULT], b"[mining]\nenabled=false\n")
        missing = [entry for entry in base if entry[0] != runtime.SETTINGS_DEFAULT]
        linked = [(name, stat.S_IFLNK if name == runtime.SETTINGS_DEFAULT else mode, data, links)
                  for name, mode, data, links in base]
        for entries in (missing, linked):
            with self.subTest(entries=len(entries)), self.assertRaises(ValueError):
                exports.cpio_files(newc(entries))

    def test_ramdisk_crc_architecture_and_trailing_gzip_refused(self):
        raw = wrap_ramdisk(b"cpio bytes", arm64=True)
        self.assertEqual(exports.ramdisk(raw, arm64=True), b"cpio bytes")
        for candidate, arm64 in ((raw, False), (raw[:-1] + bytes([raw[-1] ^ 1]), True), (raw + b"tail", True)):
            with self.subTest(arm64=arm64), self.assertRaises(ValueError):
                exports.ramdisk(candidate, arm64=arm64)
        with self.assertRaises(ValueError):
            exports.gunzip(gzip.compress(b"one") + gzip.compress(b"two"))

    def test_tar_duplicate_link_and_foreign_prefix_refused(self):
        for mode in ("duplicate", "symlink", "foreign", "traversal"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "package.tar"
                with tarfile.open(path, "w") as archive:
                    entry = tarfile.TarInfo("sysupgrade-am1-s9/root" if mode != "foreign" else "sysupgrade-am2-s19j/root")
                    entry.size = 1
                    if mode == "symlink":
                        entry.type, entry.linkname, entry.size = tarfile.SYMTYPE, "/etc/passwd", 0
                    if mode == "traversal":
                        entry.name = "../root"
                    archive.addfile(entry, io.BytesIO(b"x"))
                    if mode == "duplicate":
                        archive.addfile(entry, io.BytesIO(b"x"))
                with path.open("rb") as stream, self.assertRaises(ValueError):
                    exports.tar_payloads(stream, {"sysupgrade-am1-s9/root": 16})

    def test_overlapping_partition_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "image.img"
            write_card(path, b"x" * 512)
            with path.open("r+b") as stream:
                stream.seek(446 + 16 + 8)
                stream.write(struct.pack("<I", 2048))
            with exports.artifact_reader(path) as (stream, total), self.assertRaises(ValueError):
                exports.partition(stream, total, 1)


class PackagedRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.name != "posix":
            raise RuntimeError("actual package/ELF tests require the explicit POSIX build host")
        from test_runtime_image_manifest import fixture
        cls.temporary = tempfile.TemporaryDirectory(prefix="packaged-runtime-test-")
        cls.base = Path(cls.temporary.name)
        cls.arm = fixture(cls.base / "arm")
        cls.arm64 = fixture(cls.base / "arm64", machine="aarch64-unknown-linux-musl")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def fixture(self, board="am1-s9", **kwargs):
        scratch = tempfile.TemporaryDirectory(dir=self.base)
        self.addCleanup(scratch.cleanup)
        key, pubkey, daemon = self.arm64 if exports.producer_for(board).cargo_variant == "amlogic" else self.arm
        return package_fixture(Path(scratch.name), board=board, key=key, pubkey=pubkey, daemon=daemon, **kwargs)

    def verify(self, value, board="am1-s9", **kwargs):
        settings = dict(board=board, channel="beta", version="1.2.3", hardware_recipe="board-default")
        settings.update(kwargs)
        return exports.verify_artifact_runtime(*(value[name] for name in ("artifact", "manifest", "signature", "pubkey")), **settings)

    def test_real_all_runtime_container_formats_roundtrip(self):
        for board in ("am1-s9", "am3-s21", "am3-bb-s19jpro", "am2-s17p", "am1-s9se", "am1-s9i"):
            with self.subTest(board=board):
                self.assertEqual(self.verify(self.fixture(board), board)["board_target"], board)

    def test_signed_package_must_match_retained_cargo_daemon(self):
        import hashlib
        import release_producer_evidence as evidence
        value = self.fixture()
        row = exports.producer_for("am1-s9")
        daemon = (value["rootfs"] / runtime.DAEMON).read_bytes()
        closure = {"prebuilt_rust_inputs": {"entries": [{"name": "dcentrald", "binary": {
            "size": len(daemon), "sha256": hashlib.sha256(daemon).hexdigest()}}]}}
        evidence.verify_installed_daemon(value["artifact"].parent, row, closure,
            value["pubkey"], "1.2.3", "beta")
        # Package B contains a different, still valid ELF signed by the same
        # throwaway authority. It passes the actual runtime reader, yet cannot
        # borrow package A's retained Cargo lineage.
        changed_daemon = value["artifact"].parent / "other-daemon"
        changed_daemon.write_bytes(daemon + b"distinct fixture payload")
        other = package_fixture(value["artifact"].parent / "other-package", key=value["key"],
            pubkey=value["pubkey"], daemon=changed_daemon)
        self.verify(other)
        with self.assertRaisesRegex(ValueError, "actual packaged daemon differs"):
            evidence.verify_installed_daemon(other["artifact"].parent, row, closure,
                value["pubkey"], "1.2.3", "beta")

    def test_signed_plausible_sidecars_cannot_qualify_arbitrary_artifact(self):
        value = self.fixture()
        value["artifact"].write_bytes(b"plausible but not a rootfs container")
        with self.assertRaises((ValueError, tarfile.TarError)):
            self.verify(value)

    def test_exported_pair_must_match_actual_embedded_bytes(self):
        value = self.fixture()
        for name in ("manifest", "signature"):
            original = value[name].read_bytes()
            value[name].write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
            with self.assertRaisesRegex(ValueError, "differs from actual packaged"):
                self.verify(value)
            value[name].write_bytes(original)

    def test_actual_packaged_daemon_tamper_refused_even_with_old_signed_pair(self):
        value = self.fixture("am3-s21")
        daemon = value["rootfs"] / runtime.DAEMON
        daemon.write_bytes(daemon.read_bytes() + b"changed")
        payload = wrap_ramdisk(root_payload(value["rootfs"], "cpio", value["artifact"].parent), arm64=True)
        write_tar(value["artifact"], {"sysupgrade-am3-s21/root": payload})
        with self.assertRaisesRegex(ValueError, "digest/size"):
            self.verify(value, "am3-s21")

    def test_requested_target_version_recipe_and_key_are_independent(self):
        value = self.fixture("am2-s19j", hardware_recipe="am2-s19j-xil-loki")
        self.assertEqual(self.verify(value, "am2-s19j", hardware_recipe="am2-s19j-xil-loki")["hardware_recipe"], "am2-s19j-xil-loki")
        for settings in ({"version": "1.2.4"}, {"channel": "stable"}, {"hardware_recipe": "board-default"}):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                self.verify(value, "am2-s19j", **settings)
        value["pubkey"] = self.arm64[1]
        with self.assertRaises(ValueError):
            self.verify(value, "am2-s19j", hardware_recipe="am2-s19j-xil-loki")

    def test_bb_inspection_copy_cannot_differ_from_booted_ramdisk(self):
        value = self.fixture("am3-bb-s19jpro")
        root = root_payload(value["rootfs"], "cpio", value["artifact"].parent)
        prefix = "dcentos-am3-bb-s19jpro-sdcard/"
        write_tar(value["artifact"], {prefix + "ramdisk.gz": wrap_ramdisk(root), prefix + "uramdisk.image.gz": gzip.compress(root + b"x")})
        with self.assertRaisesRegex(ValueError, "ramdisks disagree"):
            self.verify(value, "am3-bb-s19jpro")


if __name__ == "__main__":
    unittest.main()
