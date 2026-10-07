#!/usr/bin/env python3
"""Compose current signed native SD releases from fresh Buildroot userspace.

Reuses the existing exact boot pins, board startup and partition layouts. No
old root image, daemon checkpoint, block device or mount is an input. Only a
new private directory is formatted; the final image is read back before its
embedded runtime pair is exported. Outer release signing is a separate step.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import uuid

import provision_runtime_policy
import release_runtime_exports as exports
import runtime_image_manifest as runtime

PROJECT = Path(__file__).resolve().parent.parent
WORKSPACE = PROJECT.parents[1]
sys.path.insert(0, str(WORKSPACE / "projects/dcent-toolbox/src"))
from native_zynq_sd import assets, boot_assets, current_release
from native_zynq_sd.current_release import profile
from native_zynq_sd.prepare_data import MKFS_CONFIG
from dcent_toolbox.core.flat_fat32 import read_flat_fat32
from dcent_toolbox.core.pristine_ext4 import inspect_pristine_ext4


def settings():
    key, pubkey = os.environ.get("DCENT_RELEASE_SIGNING_KEY"), os.environ.get("DCENT_RELEASE_PUBKEY_FILE")
    if not key or not pubkey:
        raise ValueError("native release requires explicit signing key and trusted public key")
    channel = os.environ.get("DCENT_RELEASE_CHANNEL", "beta")
    recipe = os.environ.get("DCENT_RELEASE_HARDWARE_RECIPE", "board-default")
    return Path(key), Path(pubkey), channel, recipe


def direct(root: Path, name: str, *, create=False) -> Path:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("real root directory required")
    name = exports.canonical(name)
    current = root
    for part in name.split("/")[:-1]:
        current /= part
        if create and not current.exists() and not current.is_symlink():
            current.mkdir()
        if not stat.S_ISDIR(current.lstat().st_mode):
            raise ValueError("native root path traverses a non-directory")
    return current / name.split("/")[-1]


def install(root: Path, name: str, data: bytes, mode=0o644):
    path = direct(root, name, create=True)
    if path.exists() or path.is_symlink():
        if not path.is_symlink() and not path.is_file():
            raise ValueError("native overlay may replace only a file: " + name)
        path.unlink()
    path.write_bytes(data)
    path.chmod(mode)


def remove(root: Path, name: str):
    path = direct(root, name, create=True)
    if path.exists() or path.is_symlink():
        if not path.is_symlink() and not path.is_file():
            raise ValueError("unexpected non-file native override: " + name)
        path.unlink()


def remove_flat_tree(root: Path, name: str, limit: int = 64):
    """Remove a shallow all-regular-file directory, refusing surprises.

    Used for staged payload directories (the XIL .25 seed) whose shape the
    composer knows exactly: a symlinked directory, nested directories, or
    more than `limit` entries are refused rather than silently torn out.
    """
    path = direct(root, name, create=True)
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or not path.is_dir():
        raise ValueError("unexpected non-directory staged payload: " + name)
    entries = sorted(path.iterdir())
    if len(entries) > limit:
        raise ValueError(f"staged payload exceeds {limit} entries: " + name)
    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            raise ValueError("unexpected nested staged payload: " + name + "/" + entry.name)
        entry.unlink()
    path.rmdir()


def root_uuid(board: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "https://d-cent.local/native-release-root/v1/" + board))


def prepare_root(root: Path, board: str, binaries: Path) -> dict:
    producer = exports.producer_for(board)
    if producer.artifact_kind != "native-sd-image":
        raise ValueError("canonical native SD producer required")
    if board in ("am2-t17e", "am2-s17e"):
        raise ValueError("S17e/T17e requires its distinct BM1396 ext2 media composer")
    key, pubkey, channel, recipe = settings()
    runtime.registry_channel(board, channel)
    version = runtime.regular_bytes(direct(root, "etc/dcentos-version"), 128).decode().strip()
    # Prove the fresh carrier's existing signed daemon before any composition.
    # Same-version metadata or an old checkpoint alone cannot admit a daemon.
    source_board = runtime.regular_bytes(direct(root, "etc/dcentos/board_target"), 128).decode().strip()
    runtime.verify(root, source_board, channel, version, pubkey)
    if producer.runtime_root != "partition2-ext2":
        base_boards = ({"am1-s9", board} if board.startswith("am1-") else {"am2-s19j", board})
        if source_board not in base_boards:
            raise ValueError("native release requires its exact target or corresponding fresh architecture base")
    shadow = runtime.regular_bytes(direct(root, "etc/shadow"), 16384).decode().splitlines()
    roots = [row.split(":") for row in shadow if row.startswith("root:")]
    if len(roots) != 1 or len(roots[0]) != 9 or not roots[0][1].startswith(("!", "*")):
        raise ValueError("native release requires locked root credentials")
    for name in ("data/dcentrald", "data/dcentrald.toml", "data/dcentrald-experimental.toml",
                 "data/dcent/auth.json", "data/dcent/authorized_keys", "root/.ssh/authorized_keys",
                 "etc/dcentos/first-boot-authorized_keys", "etc/dcentos/external-media-ephemeral-root"):
        candidate = direct(root, name, create=True)
        if candidate.exists() or candidate.is_symlink():
            raise ValueError("native release contains persistent/personal override: " + name)
    if producer.runtime_root == "partition2-ext2":
        import prepare_c43_sd_image as c43
        import prepare_bm1391_sd_image as bm1391
        owner = c43 if board in c43.TARGETS else bm1391
        # The old import utility keeps its strict historical input contract.
        # This entry independently verifies a current same-target/base release.
        owner.prepare_root(root, board, binaries, root_uuid(board), owner.DATA_UUIDS[board],
                           fresh_release=True)
    else:
        selected = profile(board)
        for name, asset in current_release.source_assets(WORKSPACE, board).items():
            install(root, name, asset.content, asset.mode)
        for name, destination in (("dcentrald", runtime.DAEMON), ("dcentos-init", "sbin/init"),
                                  ("dcentos-discovery", "usr/bin/dcentos-discovery")):
            data = runtime.regular_bytes(binaries / name, runtime.MAX_DAEMON)
            if len(data) < 64 or data[:6] != b"\x7fELF\x01\x01" or struct.unpack_from("<H", data, 18)[0] != 40:
                raise ValueError("current ARMv7 native executable required: " + name)
            if name == "dcentrald":
                identity = runtime.build_identity(data)
                if identity["version"] != version or identity["public_key"] != runtime.public_key_bytes(pubkey):
                    raise ValueError("native executable version/key differs")
            install(root, destination, data, 0o755)
            install(root, "etc/dcentos/" + name + ".sha256", hashlib.sha256(data).hexdigest().encode() + b"\n")
        remove(root, "usr/bin/dcentrald")
        os.link(root / runtime.DAEMON, root / "usr/bin/dcentrald")
        allowed = set(assets.BASE_SERVICES) | set(assets.SOURCE_SERVICES) | set(assets.OWN_SERVICES) | {"rcS", "rcK"}
        if selected["board_family"] == "am2":
            allowed.add("S12fpga_identity")
        init = direct(root, "etc/init.d/rcS").parent
        if not allowed <= {path.name for path in init.iterdir()}:
            raise ValueError("native release startup dependency missing")
        for path in init.iterdir():
            if path.name not in allowed:
                remove(root, "etc/init.d/" + path.name)
        install(root, "etc/dcentos/board_family", (selected["board_family"] + "\n").encode())
        # The s19jpro-base post-build stages the operator's XIL .25 NAND-bake
        # seed (authorized 2026-06-14, s19jpro first-install flow only); the
        # BM1398 native siblings build from that base, where the seed is
        # expected and stripped — removable trial media must never carry
        # persistent board-specific overrides, and the release validator
        # refuses them (drop1-20260921-l16b8n18). On any other base the seed
        # or its launcher is contamination and fails the build, mirroring the
        # BM1396/1391/C43 ext2 preparers' reject-when-unexpected rule.
        if source_board == "am2-s19j":
            remove_flat_tree(root, "etc/dcentos/xil-seed")
            remove(root, "usr/local/bin/dcentrald_standalone_boot.sh")
        else:
            for name in ("etc/dcentos/xil-seed", "usr/local/bin/dcentrald_standalone_boot.sh"):
                candidate = direct(root, name, create=True)
                if candidate.exists() or candidate.is_symlink():
                    raise ValueError("unexpected XIL .25 seed staging in base: " + name)
        # Every am2 zynq board overlay plants rail_gpio/partial_yield_floor/
        # fan_max_pwm, and the s19j post-build stamps psu_config="override"
        # (the XIL-bake G5 hint). No code on removable trial media reads any
        # of them; the toolbox native composers strip the same class as
        # foreign (bm1391_sd_media, c43_native_image, prepare_bm1396), and
        # toolbox preflight would otherwise report a stale PSU mode off the
        # card (critics H+I, run-23 follow-up).
        for name in ("etc/default/dcentrald-am2-xil-env", "etc/dcentos/xil_override.toml",
                     "etc/dcentos/psu_config", "etc/dcentos/rail_gpio",
                     "etc/dcentos/partial_yield_floor", "etc/dcentos/fan_max_pwm",
                     "etc/dcentos/first-boot-grace", "usr/sbin/sysupgrade", "usr/sbin/fw_setenv", "usr/sbin/nandwrite"):
            remove(root, name)
    # Restore the final release identity after native overlays. This is the
    # last daemon mutation; Buildroot excludes pre-stripped Rust executables.
    provision_runtime_policy.provision(root)
    # The removable-media composition is stricter than the board's global
    # storage capability: this image never installs an on-target NAND writer.
    install(root, "etc/dcentos/mutation_policy", b"boot-safeoff\ndaemon-hardware\n")
    for name in ("usr/sbin/sysupgrade", "usr/sbin/fw_setenv", "usr/sbin/nandwrite"):
        remove(root, name)
    return runtime.prepare(root, board, channel, version, key, pubkey, recipe)


def command(*arguments, **kwargs):
    result = subprocess.run([str(value) for value in arguments], capture_output=True, timeout=180, **kwargs)
    if result.returncode:
        raise ValueError(f"native filesystem tool {arguments[0]} failed: " + result.stderr.decode(errors="replace").strip())
    return result.stdout


def pin(path: Path) -> dict:
    data = runtime.regular_bytes(path, exports.MAX_ARTIFACT)
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def new_filesystem(path: Path, size: int, kind: str, identity: str, label: str, *, root=None):
    with path.open("xb") as stream:
        stream.truncate(size)
    features = ("none,ext_attr,resize_inode,dir_index,filetype,sparse_super,large_file" if kind == "ext2" else
                "none,has_journal,ext_attr,resize_inode,dir_index,filetype,extent,flex_bg,sparse_super,large_file,uninit_bg,dir_nlink,extra_isize")
    arguments = ["/usr/sbin/mke2fs", "-q", "-F", "-t", kind, "-b", "4096", "-U", identity, "-L", label, "-O", features]
    if root is not None:
        arguments += ["-d", str(root)]
    else:
        arguments += ["-E", "lazy_itable_init=0,lazy_journal_init=0"]
    command(*arguments, path)
    if root is not None:
        # mke2fs -d sparsifies zero-filled ELF pages. The independent native
        # readers require allocated protected executables; allocate those holes
        # in this new regular image without changing any executable bytes.
        for name in (runtime.DAEMON, "sbin/init", "usr/bin/dcentos-discovery"):
            size = len(runtime.regular_bytes(direct(root, name), runtime.MAX_DAEMON, single_link=False))
            command("/usr/sbin/debugfs", "-w", "-R", f"fallocate /{name} 0 {(size - 1) // 4096}", path)
    command("/usr/sbin/e2fsck", "-f", "-n", path)


def fat_image(directory: Path, files: dict[str, bytes], size: int, label="DCENTOS") -> Path:
    fat = directory / "boot.vfat"
    with fat.open("xb") as stream:
        stream.truncate(size)
    command("/usr/sbin/mkfs.fat", "--invariant", "-F", "32", "-s", "1", "-n", label, fat)
    sources = directory / "fat-inputs"
    sources.mkdir()
    for name, data in sorted(files.items()):
        if "/" in exports.canonical(name):
            raise ValueError("flat native boot file required")
        source = sources / name
        source.write_bytes(data)
        os.utime(source, (boot_assets.EPOCH, boot_assets.EPOCH))
        command("/usr/bin/mcopy", "-m", "-i", fat, source, "::" + name)
    if size == 96 * 1024**2:
        if read_flat_fat32(fat.read_bytes(), label="DCENTOS", limits={name: len(data) for name, data in files.items()}) != files:
            raise ValueError("native FAT runtime/boot readback differs")
    else:
        # The C43/BM1391 layout uses 64-MiB FAT32. Decode actual file contents
        # with mtools; no loop device, mount or block-device path is used.
        for name, data in files.items():
            if command("/usr/bin/mtype", "-i", fat, "::" + name) != data:
                raise ValueError("native FAT boot readback differs: " + name)
    return fat


def assemble(root: Path, images: Path, board: str, boot_inputs: Path) -> Path:
    producer = exports.producer_for(board)
    if producer.artifact_kind != "native-sd-image" or boot_inputs.is_symlink() or not boot_inputs.is_dir():
        raise ValueError("native producer and staged exact boot-input directory required")
    _, pubkey, channel, recipe = settings()
    version = runtime.regular_bytes(direct(root, "etc/dcentos-version"), 128).decode().strip()
    runtime.verify(root, board, channel, version, pubkey, recipe)
    if board in current_release.BM1398_DEFAULTS:
        current_release.validate_bm1398_config(
            board, runtime.regular_bytes(direct(root, "etc/dcentrald.toml"), 65536))
    images.mkdir(parents=True, exist_ok=True)
    if images.is_symlink() or not images.is_dir():
        raise ValueError("real Buildroot images directory required")
    destination = images / producer.primary_artifact
    if destination.exists() or destination.is_symlink():
        raise ValueError("preserve prior native release image; use a clean images directory")
    with tempfile.TemporaryDirectory(prefix=".native-release-", dir=images) as temporary:
        stage = Path(temporary)
        if producer.runtime_root == "partition2-ext2":
            import prepare_c43_sd_image as c43
            import prepare_bm1391_sd_image as bm1391
            import prepare_bm1391_sd_boot as bm1391_boot
            owner = c43 if board in c43.TARGETS else bm1391
            if owner is c43:
                c43.prepare_boot(stage, boot_inputs)
                names = ("BOOT.BIN", "uImage", "devicetree.dtb", "c43-system.bin", "c43-fabric.itb", "uEnv.txt")
            else:
                bm1391_boot.prepare_boot(stage, boot_inputs, board)
                names = ("BOOT.BIN", "uImage", "devicetree.dtb", "bm1391-system.bin", "bm1391-fabric.itb", "uEnv.txt")
            fat_image(stage, {name: runtime.regular_bytes(stage / name, 16 * 1024**2) for name in names}, 64 * 1024**2,
                      "DCENT_C43" if owner is c43 else "DCENT1391")
            new_filesystem(stage / "rootfs.ext2", 128 * 1024**2, "ext2", root_uuid(board),
                           "DCENT_C43_ROOT" if owner is c43 else "DCENT_BM1391_RT", root=root)
            new_filesystem(stage / "data.ext4", 64 * 1024**2, "ext4", owner.DATA_UUIDS[board],
                           "DCENT_C43_DATA" if owner is c43 else "DCENT_BM1391_DT")
            image = owner.assemble(stage, board)
            layout = ((2048, 131072, 0x0C), (133120, 262144, 0x83), (395264, 131072, 0x83))
            ids = {"root_uuid": root_uuid(board), "data_uuid": owner.DATA_UUIDS[board]}
        else:
            selected = profile(board)
            source_pins = boot_assets.S9_INPUTS if selected["board_family"] == "am1" else boot_assets.AM2_BOOT_PINS
            supplied = {name: runtime.regular_bytes(boot_inputs / name, 16 * 1024**2) for name in source_pins}
            boot = boot_assets.s9_static_assets(board, supplied) if selected["board_family"] == "am1" else current_release.am2_boot_assets(board, supplied)
            squash = stage / "rootfs.squashfs"
            # am2/BM1398 xz payload carries the ARM BCJ filter: the family
            # rootfs otherwise misses the operator-ratified 179-LEB NAND
            # window by ~0.7% (drop1-20260920-nu4xg06g: 22,880,256 vs
            # 22,728,704; with BCJ 22,237,184 — 491,520 under). The stock
            # Braiins zynq-bm3-am2 production firmware itself ships two-
            # filter (BCJ+LZMA2) xz streams (203 validated streams in
            # firmware_2026-08-20-0-33fea20e-26.08.1-plus), and the pinned
            # donor vmlinux exports the kernel xz decoder symbols
            # (xz_dec_run: CONFIG_XZ_DEC=y), so the donor kernel lineage
            # decompresses BCJ squashfs; failure would be a recoverable
            # SD-card no-boot (nand_writes stays False).
            command("/usr/bin/mksquashfs", root, squash, "-noappend", "-no-xattrs",
                    "-comp", "gzip" if selected["board_family"] == "am1" else "xz",
                    "-b", "1048576", "-processors", "1", "-quiet",
                    *(["-Xbcj", "arm"] if selected["board_family"] != "am1" else []))
            root_bytes = runtime.regular_bytes(squash, 48 * 1024**2)
            current_release.check_rootfs_size(board, len(root_bytes))
            exports.verify_files(exports.squashfs_files(root_bytes), board, channel, version, pubkey, recipe)
            if selected["board_family"] == "am1":
                boot["uramdisk.image.gz"] = boot_assets.s9_ramdisk(root_bytes)
            fat = fat_image(stage, boot, 96 * 1024**2)
            configuration = stage / "mke2fs.conf"
            configuration.write_bytes(MKFS_CONFIG)
            with (stage / "data.ext4").open("xb") as stream:
                stream.truncate(selected["data_bytes"])
            # Buildroot builds host e2fsprogs (1.47.x) whose output/host/bin
            # shadows the container system tools inside the make recipe, and
            # >=1.47 gives SOURCE_DATE_EPOCH precedence over
            # E2FSPROGS_FAKE_TIME while Buildroot exports SOURCE_DATE_EPOCH
            # into recipes. Pin the system tool AND the epoch under both
            # names so the pristine schema below holds on any base image.
            command("/usr/sbin/mke2fs", "-q", "-F", "-t", "ext4", "-b", "4096", "-I", "256", "-N", "4096", "-m", "0",
                    "-U", selected["data_uuid"], "-L", "DCENT_SD_DATA",
                    "-O", "none,has_journal,extent,filetype,sparse_super,large_file,extra_isize",
                    "-E", "lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0,nodiscard,hash_seed=" + selected["data_uuid"], stage / "data.ext4",
                    env={**os.environ, "MKE2FS_CONFIG": str(configuration),
                         "E2FSPROGS_FAKE_TIME": str(boot_assets.EPOCH),
                         "SOURCE_DATE_EPOCH": str(boot_assets.EPOCH), "LC_ALL": "C"})
            command("/usr/sbin/e2fsck", "-f", "-n", stage / "data.ext4")
            inspect_pristine_ext4((stage / "data.ext4").read_bytes(), expected_uuid=selected["data_uuid"])
            image = stage / "dcentos-sd.img"
            mbr = bytearray(512)
            parts = [fat] + ([squash] if selected["board_family"] == "am2" else []) + [stage / "data.ext4"]
            with image.open("xb") as stream:
                stream.truncate(selected["image_bytes"])
                for index, ((start, count, kind), part) in enumerate(zip(selected["partitions"], parts)):
                    if part.stat().st_size > count * 512:
                        raise ValueError("native partition payload exceeds exact layout")
                    struct.pack_into("<B3sB3sII", mbr, 446 + index * 16, 128 if index == 0 else 0, b"\xfe\xff\xff", kind, b"\xfe\xff\xff", start, count)
                    stream.seek(start * 512)
                    with part.open("rb") as source:
                        shutil.copyfileobj(source, stream)
                mbr[510:] = b"\x55\xaa"
                stream.seek(0)
                stream.write(mbr)
            # Every partition is read back, including zero tail and pristine data.
            with image.open("rb") as stream:
                for (start, count, _), part in zip(selected["partitions"], parts):
                    stream.seek(start * 512)
                    actual = stream.read(count * 512)
                    expected = part.read_bytes()
                    if actual[:len(expected)] != expected or any(actual[len(expected):]):
                        raise ValueError("native image partition readback differs")
            document = {"schema": "dcentos.native-release-media/v1", "target": board,
                        "board_target": board, "image": producer.primary_artifact,
                        "image_size_bytes": image.stat().st_size, "image_sha256": pin(image)["sha256"],
                        "boot_artifacts_complete": True, "requires_sd_present": True,
                        "nand_writes": False, "physical_qualification": "pending",
                        "partitions": selected["partitions"],
                        "artifacts": {**{name: {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()} for name, value in boot.items()},
                                      "rootfs.squashfs": pin(squash), "data.ext4": pin(stage / "data.ext4")}}
            Path(str(image) + ".manifest.json").write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
            layout, ids = selected["partitions"], {"data_uuid": selected["data_uuid"]}
        manifest = Path(str(image) + ".manifest.json")
        document = json.loads(manifest.read_text(encoding="utf-8"))
        document.update(schema="dcentos.native-release-media/v1", target=board, board_target=board,
                        image=producer.primary_artifact, version=version, channel=channel, hardware_recipe=recipe,
                        install_scope="external_media_boot", partitions=layout, **ids)
        document["artifacts"]["boot.vfat"] = pin(stage / "boot.vfat")
        manifest.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
        exports.export_artifact_runtime(image, pubkey, board, channel, version, recipe)
        for suffix in (".manifest.json", ".runtime-image.json", ".runtime-image.sig", ""):
            os.replace(Path(str(image) + suffix), Path(str(destination) + suffix))
        readme = images / "TESTER_README.txt"
        if readme.is_symlink() or (readme.exists() and not readme.is_file()):
            raise ValueError("native media README destination must be a regular path")
        readme.write_text(
            f"DCENT_OS {board} signed native SD trial media\n\n"
            "Write the complete .img to removable SD media. The SD must remain inserted.\n"
            "This is not a NAND installer or an authorization to change U-Boot environment.\n"
            "Mining starts disabled; configure the miner and press Start.\n"
            "Boot, rail polarity, thermals and hashrate still require the exact board bench check.\n"
            "Verify the artifact signature and runtime companions before use.\n\n"
            "Fund DCENT_OS development: https://d-central.tech/fund/\n",
            encoding="utf-8", newline="\n")
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preflight", "prepare-root", "assemble"))
    parser.add_argument("--rootfs", type=Path)
    parser.add_argument("--board-target")
    parser.add_argument("--binaries", type=Path)
    parser.add_argument("--images", type=Path)
    parser.add_argument("--boot-inputs", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "preflight":
            # Import the independent reader now, before any expensive compiler
            # step, including its cryptography and Python 3.10 TOML dependency.
            from dcent_toolbox.core.current_native_release import validate_current_native_release
            from native_zynq_sd.current_release import TARGETS
            if PROJECT != WORKSPACE / "DCENT_OS_Antminer":
                raise ValueError("native source requires canonical DCENT_OS_Antminer workspace ancestry")
            for board in TARGETS:
                current_release.source_assets(WORKSPACE, board)
            assert callable(validate_current_native_release)
            print(f"Native dependencies and {len(TARGETS)} exact current source profiles verified")
            return 0
        if args.rootfs is None or args.board_target is None:
            raise ValueError("--rootfs and --board-target required for native composition")
        if args.action == "prepare-root":
            if args.binaries is None:
                raise ValueError("--binaries required for native root preparation")
            print(json.dumps(prepare_root(args.rootfs, args.board_target, args.binaries), sort_keys=True))
        else:
            if args.images is None or args.boot_inputs is None:
                raise ValueError("--images and --boot-inputs required for native assembly")
            print(assemble(args.rootfs, args.images, args.board_target, args.boot_inputs))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"ERROR: native SD release: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
