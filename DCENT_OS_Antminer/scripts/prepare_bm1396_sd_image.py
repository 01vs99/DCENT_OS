#!/usr/bin/env python3
"""Compose exact native S17e/T17e SD userspace and regular-file card images.

Uses our PS-only storage layout; all FPGA identity comes from the independently
pinned BM1396 boot producer and its own overlay. No miner or device access.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import uuid
import sys

from prepare_c43_sd_image import checked_path, ADMITTED_AM2_BASE_SHA256
from prepare_bm1396_sd_boot import BITSTREAM_SHA256
import runtime_image_manifest as runtime
import provision_runtime_policy

# Shared boot bytes do not grant sibling identity: each target has its own
# signed runtime, baked geometry, boot command line and persistent data UUID.
TARGETS = ("am2-t17e", "am2-s17e")
import prepare_bm1396_sd_boot as boot_source

PROJECT = Path(__file__).resolve().parents[1]
DASHBOARD = PROJECT / "dashboard/dist"
OVERLAY = PROJECT / "br2_external_dcentos/board/zynq/bm1396/rootfs-overlay"
COMMON_OVERLAY = PROJECT / "br2_external_dcentos/board/common/rootfs-overlay"
ZYNQ_OVERLAY = PROJECT / "br2_external_dcentos/board/zynq/rootfs-overlay"
CURRENT_SERVICES = ("rcS", "rcK", "S40network", "S41ntp", "S43logrotate", "S50dropbear", "S80dashboard", "S82dcentrald")
BASE_SERVICES = ("S01syslogd", "S02klogd", "S02sysctl")
OWN_SERVICES = ("S12fpga_identity", "S45persistent", "S46bm1396_ssh", "S70dcentos-discovery")
# Stable within each exact target/layout so a reviewed root update can retain
# the complete prior /data partition. UUIDs identify filesystems, not units or
# authorization. Root UUIDs remain fresh for each produced root artifact.
DATA_UUIDS = {"am2-t17e": "05a12990-c502-55c4-9c41-55bb24a23de8",
              "am2-s17e": "2be50b10-0f74-508a-b439-faf6885c2478"}


def release_settings():
    key, public = os.environ.get("DCENT_RELEASE_SIGNING_KEY"), os.environ.get("DCENT_RELEASE_PUBKEY_FILE")
    if not key or not public:
        raise ValueError("BM1396 release requires an explicit signing key and trusted public key")
    return Path(key), Path(public), os.environ.get("DCENT_RELEASE_CHANNEL", "beta")



def current_dashboard() -> dict[str, bytes]:
    directory = Path(os.environ.get("DCENT_RELEASE_DASHBOARD_DIR", str(DASHBOARD)))
    files = {name: checked_path(directory, name).read_bytes()
             for name in ("index.html", "index.html.gz", "index.html.sha256")}
    html = files["index.html"]
    if not 100_000 <= len(html) <= 16 * 1024 * 1024:
        raise ValueError("current dashboard HTML has an invalid size")
    try:
        uncompressed = gzip.decompress(files["index.html.gz"])
    except (OSError, EOFError) as exc:
        raise ValueError("current dashboard gzip is invalid") from exc
    if (uncompressed != html or files["index.html.sha256"].strip()
            != hashlib.sha256(html).hexdigest().encode("ascii")):
        raise ValueError("current dashboard HTML/gzip/hash do not match")
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError("dashboard asset symlink refused")
        if path.is_file():
            relative = path.relative_to(directory).as_posix()
            if path.stat().st_size > 16 * 1024 * 1024:
                raise ValueError("dashboard asset exceeds bound")
            files[relative] = path.read_bytes()
    return files


def verify_boot_files(output: Path, target: str) -> None:
    """Rejoin boot bytes at final card assembly, including native-only DT edits."""
    receipt = json.loads(checked_path(output, "boot-components.json").read_text())
    if (receipt.get("schema") != 1 or receipt.get("board_target") != target
            or receipt.get("kind") != "native-sd-boot-components"
            or receipt.get("bitstream_sha256") != BITSTREAM_SHA256):
        raise ValueError("BM1396 boot receipt does not bind the selected target")
    for name in ("BOOT.BIN", "uImage", "devicetree.dtb", "devicetree-stock.dtb",
                 "bm1396-system.bin", "bm1396-fabric.itb", "uEnv.txt"):
        path = checked_path(output, name)
        data = path.read_bytes()
        if receipt.get("files", {}).get(name) != {
                "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}:
            raise ValueError("BM1396 boot bytes changed after production: " + name)
    for name, source_name in (("BOOT.BIN", "BOOT.bin"), ("uImage", "uImage"),
                              ("devicetree-stock.dtb", "devicetree.dtb")):
        boot_source.checked_input(checked_path(output, name), *boot_source.PINS[source_name])
    payload = (output / "bm1396-system.bin").read_bytes()
    if payload != boot_source.extract_fpga((output / "BOOT.BIN").read_bytes()):
        raise ValueError("BM1396 native FPGA differs from the resident source")
    fit = boot_source.fdt_properties((output / "bm1396-fabric.itb").read_bytes())
    if (fit.get(("/images/bm1396-raw", "data")) != payload
            or fit.get(("/images/bm1396-raw/hash-1", "algo")) != b"sha256\0"
            or fit.get(("/images/bm1396-raw/hash-1", "value")) != bytes.fromhex(BITSTREAM_SHA256)):
        raise ValueError("BM1396 boot FIT payload/hash differs")
    properties = boot_source.fdt_properties((output / "devicetree-stock.dtb").read_bytes())
    node = "/amba@0/watchdog@f8005000"
    def cells(*values):
        return struct.pack(">" + "I" * len(values), *values)
    properties.update({(node, "compatible"): b"cdns,wdt-r1p2\0",
        (node, "clocks"): cells(2, 45), (node, "interrupt-parent"): cells(3),
        (node, "interrupts"): cells(0, 9, 1), (node, "reg"): cells(0xf8005000, 0x1000),
        (node, "timeout-sec"): cells(60), (node, "reset-on-timeout"): b"",
        ("/reserved-memory", "#address-cells"): cells(1),
        ("/reserved-memory", "#size-cells"): cells(1), ("/reserved-memory", "ranges"): b"",
        (boot_source.DMA_NODE, "reg"): cells(boot_source.DMA_BASE, boot_source.DMA_BYTES),
        (boot_source.DMA_NODE, "compatible"): b"dcent,bm1396-stock-fpga-dma\0",
        (boot_source.DMA_NODE, "no-map"): b""})
    if boot_source.fdt_properties((output / "devicetree.dtb").read_bytes()) != properties:
        raise ValueError("BM1396 DTB differs from exact PS watchdog and reserved DMA edits")
    expected_env = "\n".join(f"{key}={value}" for key, value in boot_source.boot_environment(target).items()) + "\n"
    if (output / "uEnv.txt").read_text() != expected_env:
        raise ValueError("BM1396 boot environment differs from exact selected SD source")

def prepare_root(root: Path, target: str, binaries: Path, root_uuid: str, data_uuid: str,
                 base_sha256: str | None = None) -> None:
    if target not in TARGETS or root.is_symlink() or not root.is_dir():
        raise ValueError("exact BM1396 target and private root staging directory required")
    for value in (root_uuid, data_uuid):
        if str(uuid.UUID(value)) != value:
            raise ValueError("canonical root/data UUID required")
    if data_uuid != DATA_UUIDS[target] or root_uuid == data_uuid:
        raise ValueError("exact target/layout data UUID and distinct root UUID required")
    key, public, channel = release_settings()
    runtime.registry_channel(target, channel)
    marker = checked_path(root, "etc/dcentos/board_target")
    source_target = marker.read_text().strip()
    version = runtime.regular_bytes(root / "etc/dcentos-version", 128).decode("ascii").strip()
    if source_target not in ("am1-s9", "am2-s19j", target):
        raise ValueError("fresh exact selected BM1396 target or signed ARM userspace carrier required")
    runtime.verify(root, source_target, channel, version, public)
    sys.path.insert(0, str(PROJECT.parents[1] / "projects/dcent-toolbox/src"))
    from dcent_toolbox.core.current_native_release import DirectoryRoot, supervisor_dependencies
    # Buildroot supplies these C programs and their runtime loader/libraries.
    # Validate their complete protected closure before changing the carrier.
    # Source-owned shell helpers are installed below and rechecked afterward.
    supervisor_dependencies(DirectoryRoot(root), require_scripts=False)
    shadow = runtime.regular_bytes(root / "etc/shadow", 16384).decode().splitlines()
    roots = [line.split(":") for line in shadow if line.startswith("root:")]
    if len(roots) != 1 or len(roots[0]) != 9 or not roots[0][1].startswith(("!", "*")):
        raise ValueError("release root credentials must be locked")
    for name in ("data/dcentrald.toml", "data/dcentrald", "data/dcentrald-experimental.toml", "etc/dcentos/external-media-ephemeral-root",
                 "data/dcent/auth.json", "data/dcent/authorized_keys", "root/.ssh/authorized_keys", "etc/dcentos/first-boot-authorized_keys"):
        if checked_path(root, name).exists():
            raise ValueError(f"input contains incompatible persistent/image override: {name}")
    inputs = {}
    for name in ("dcentrald", "dcentos-init", "dcentos-discovery"):
        path = binaries / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"current regular ARM binary required: {name}")
        data = path.read_bytes()
        if len(data) < 64 or data[:6] != b"\x7fELF\x01\x01" or struct.unpack_from("<H", data, 18)[0] != 40:
            raise ValueError(f"current ARMv7 ELF required: {name}")
        if name == "dcentrald":
            identity = runtime.build_identity(data)
            if identity["version"] != version or identity["public_key"] != runtime.public_key_bytes(public):
                raise ValueError("replacement daemon compiled key/version differs")
        inputs[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    dashboard = current_dashboard()
    destinations = [(name, "sbin/init" if name == "dcentos-init" else f"usr/bin/{name}") for name in inputs]
    for _, relative in destinations:
        checked_path(root, relative)
    for name, relative in destinations:
        destination = checked_path(root, relative)
        shutil.copyfile(binaries / name, destination)
        destination.chmod(0o755)
    # Bind the early boot-cut CLI and supervisor to this one current executable;
    # mke2fs -d preserves the hardlink without duplicating the binary payload.
    supervisor_binary = checked_path(root, "usr/local/bin/dcentrald")
    supervisor_binary.parent.mkdir(parents=True, exist_ok=True)
    if supervisor_binary.exists():
        if not supervisor_binary.is_file():
            raise ValueError("supervisor daemon path must be a regular file")
        supervisor_binary.unlink()
    os.link(checked_path(root, "usr/bin/dcentrald"), supervisor_binary)
    for name, data in dashboard.items():
        destination = checked_path(root, "usr/share/dcentos-dashboard/" + name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        destination.chmod(0o644)
    for source in OVERLAY.rglob("*"):
        if source.is_file():
            if source.is_symlink():
                raise ValueError("BM1396 source overlay symlink")
            relative = str(source.relative_to(OVERLAY))
            destination = checked_path(root, relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            destination.chmod(0o755)
    # Install every source-owned service and its current web proxy, not scripts
    # retained from the carrier image. Buildroot owns the three inert PS services.
    for source in [*(ZYNQ_OVERLAY / "etc/init.d" / name for name in CURRENT_SERVICES),
                   ZYNQ_OVERLAY / "usr/sbin/dcent-enable-ssh",
                   *sorted((COMMON_OVERLAY / "usr/libexec/dcentos").glob("dcentrald-*.sh"))]:
        if source.name in CURRENT_SERVICES:
            relative = "etc/init.d/" + source.name
        elif source.name == "dcent-enable-ssh":
            relative = "usr/sbin/" + source.name
        else:
            relative = "usr/libexec/dcentos/" + source.name
        destination = checked_path(root, relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o755)
    for relative in ("root/web/server.py", "root/web/static/recovery.html", "root/web/static/diagnostic.html", "root/web/static/diagnostic-banner.js"):
        destination = checked_path(root, relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ZYNQ_OVERLAY / relative, destination)
        destination.chmod(0o755 if relative.endswith(".py") else 0o644)
    supervisor_dependencies(DirectoryRoot(root))
    allowed = set(BASE_SERVICES) | set(CURRENT_SERVICES) | set(OWN_SERVICES)
    for service in checked_path(root, "etc/init.d").iterdir():
        if service.name not in allowed:
            if service.is_symlink() or not service.is_file():
                raise ValueError("unknown non-file service in native carrier")
            service.unlink()
    configs = PROJECT / "dcentrald/configs/beta"
    for source, destination in ((f"{target}-baked-default.toml", "etc/dcentrald.toml"),):
        shutil.copyfile(configs / source, checked_path(root, destination))
    identities = {"board_target": target, "board_family": "am2", "platform": "zynq-bm1396-stock",
                  "bm1396-bitstream.sha256": BITSTREAM_SHA256, "bm1396-root-uuid": root_uuid, "bm1396-data-uuid": data_uuid}
    for name, value in identities.items():
        checked_path(root, "etc/dcentos/" + name).write_text(value + "\n", encoding="utf-8")
    # Beta cards start through dashboard setup and operator SSH keys.
    checked_path(root, "etc/dcentos/release-image").write_text("release_image=1\n", encoding="utf-8")
    # These SD candidates have no automatic NAND upgrade/commit lifecycle.
    for name in ("S10udevd", "S10modules", "S11modules", "S15pic_boot", "S37board_setup",
                 "S37bitmainer_setup", "S50telnet", "S81dcentos-xil-seed", "S99upgrade", "S99verify", "S12fpga_load"):
        path = checked_path(root, "etc/init.d/" + name)
        if path.exists():
            path.unlink()
    foreign_files = ("etc/default/dcentrald-am2-xil-env", "etc/dcentrald/xil_override.toml",
                     "etc/dcentos/rail_gpio", "etc/dcentos/psu_config", "etc/dcentos/partial_yield_floor",
                     "usr/libexec/dcentos/am2-fabric-identity.sh", "usr/libexec/dcentos/am2-native-ota.sh",
                     "etc/dcentrald-experimental.toml", "etc/dcentos/first-boot-grace",
                     "usr/sbin/sysupgrade", "usr/sbin/fw_setenv", "usr/sbin/nandwrite")
    for relative in foreign_files:
        path = checked_path(root, relative)
        if path.exists():
            if not path.is_file():
                raise ValueError("foreign image override is not a regular file")
            path.unlink()
    # The audited base has no active XIL seed directory. Reject one rather than
    # permitting an unknown baked payload to affect this image composition.
    if checked_path(root, "etc/dcentos/xil-seed").exists():
        raise ValueError("unexpected persistent XIL seed in base userspace")
    checked_path(root, "etc/hostname").write_text("dcentos-" + target.removeprefix("am2-") + "\n", encoding="utf-8")
    checked_path(root, "etc/dcentrald-target.conf").write_text(
        f"BOARD_FAMILY=am2\nBOARD_TARGET={target}\nPLATFORM=zynq-bm1396-stock\nSOC=zynq-7000\nARCH=armv7\nVARIANT={target.removeprefix('am2-')}\n", encoding="utf-8")
    for name in ("dcentrald", "dcentos-init", "dcentos-discovery"):
        checked_path(root, f"etc/dcentos/{name}.sha256").write_text(inputs[name]["sha256"] + "\n", encoding="utf-8")
    checked_path(root, "etc/dcentos/dcentrald.md5").write_text(hashlib.md5((binaries / "dcentrald").read_bytes(), usedforsecurity=False).hexdigest() + "\n", encoding="utf-8")
    supervisor = checked_path(root, "etc/init.d/S82dcentrald")
    text = supervisor.read_text(encoding="utf-8")
    selector = ('    if [ -x /data/dcentrald ]; then\n'
                '        DAEMON="/data/dcentrald"\n'
                '    else\n        DAEMON="/usr/local/bin/dcentrald"\n    fi\n')
    if text.count(selector) != 1:
        raise ValueError("exact supervisor binary selection required")
    text = text.replace(selector,
        '    # This SD image owns its native runtime; retained /data binaries\n'
        '    # are preserved as data and cannot replace the reviewed executable.\n'
        '    DAEMON="/usr/local/bin/dcentrald"\n', 1)
    anchor = "fan_safety_override() {\n"
    if text.count(anchor) != 1:
        raise ValueError("exact native supervisor fallback function required")
    text = text.replace(anchor, anchor + '    case "$BOARD_TARGET" in am2-t17e|am2-s17e)\n'
                        '        echo "BM1396 hardware disposition remains with its retained native watchdog owner" >&2\n'
                        '        return 1 ;; esac\n', 1)
    # A failed early-init must not enter the S9 fallback or start with volatile
    # /data. Keep the normal persistent session-latch supervisor after this gate.
    anchor = 'case "$1" in\n'
    at = text.index(anchor)
    text = text[:at] + ('if [ "${1:-}" = start ]; then\n'
                        '    . /usr/libexec/dcentos/bm1396-sd-ready.sh\n'
                        '    if ! dcent_bm1396_sd_ready /etc/dcentos /run/dcentos /proc/sys/kernel/random/boot_id; then\n'
                        '        echo "BM1396 SD data or boot source observation unavailable; daemon startup refused" >&2\n'
                        '        exit 1\n    fi\nfi\n') + text[at:]
    supervisor.write_text(text, encoding="utf-8", newline="\n")
    provision_runtime_policy.provision(root)
    # This removable card carries no NAND writer, irrespective of other media.
    if (root / "etc/dcentos/mutation_policy").read_text() != "boot-safeoff\ndaemon-hardware\n":
        raise ValueError("BM1396 native card requires only boot cut and daemon capabilities")
    runtime.prepare(root, target, channel, version, key, public, "board-default")
    (root / "etc/dcentos/bm1396-runtime-inputs.json").write_text(json.dumps(inputs, indent=2) + "\n", encoding="utf-8")
    (root / "etc/dcentos/bm1396-userspace-source.json").write_text(json.dumps({"source_target": source_target,
        "source_image_sha256": base_sha256, "composition": "bm1396-native-sd-v1", "runtime_version": version}, indent=2) + "\n", encoding="utf-8")


def assemble(output: Path, target: str, version: str) -> Path:
    if target not in TARGETS or output.is_symlink() or not output.is_dir():
        raise ValueError("exact BM1396 target and private image output required")
    verify_boot_files(output, target)
    parts = (("boot.vfat", 2048, 131072, 0x0C),
             ("rootfs.ext2", 133120, 262144, 0x83),
             ("data.ext4", 395264, 131072, 0x83))
    for name, _, sectors, _ in parts:
        path = output / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != sectors * 512:
            raise ValueError(f"partition {name} has wrong exact size")
    filesystem_ids = {}
    for name in ("rootfs.ext2", "data.ext4"):
        with (output / name).open("rb") as stream:
            stream.seek(1024)
            superblock = stream.read(120)
        if superblock[56:58] != b"\x53\xef":
            raise ValueError("native SD partition lacks its ext filesystem: " + name)
        filesystem_ids[name] = str(uuid.UUID(bytes=superblock[104:120]))
    if (filesystem_ids["data.ext4"] != DATA_UUIDS[target]
            or filesystem_ids["rootfs.ext2"] == DATA_UUIDS[target]):
        raise ValueError("native SD filesystem UUIDs do not bind this target/layout")
    image = output / "dcentos-sd.img"
    mbr = bytearray(512)
    for index, (_, start, sectors, kind) in enumerate(parts):
        struct.pack_into("<B3sB3sII", mbr, 446 + index * 16, 0x80 if index == 0 else 0,
                         b"\xfe\xff\xff", kind, b"\xfe\xff\xff", start, sectors)
    mbr[510:] = b"\x55\xaa"
    with image.open("xb") as stream:
        stream.truncate(526336 * 512)
        stream.write(mbr)
        for name, start, _, _ in parts:
            stream.seek(start * 512)
            with (output / name).open("rb") as part:
                shutil.copyfileobj(part, stream, 1024 * 1024)
    sys.path.insert(0, str(PROJECT.parents[1] / "projects/dcent-toolbox/src"))
    from cryptography.hazmat.primitives import serialization
    from dcent_toolbox.core import bm1396_sd_media as reader
    _, public, channel = release_settings()
    raw = image.read_bytes()
    key = serialization.load_pem_public_key(runtime.regular_bytes(public, 16384))
    _, _, runtime_json, runtime_sig = reader.inspect_embedded_runtime(raw, target,
        version=version, channel=channel, key=key)
    Path(str(image) + ".runtime-image.json").write_bytes(runtime_json)
    Path(str(image) + ".runtime-image.sig").write_bytes(runtime_sig)
    digest = hashlib.sha256()
    with image.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    artifacts = {}
    for name in ("BOOT.BIN", "uImage", "devicetree.dtb", "bm1396-system.bin", "bm1396-fabric.itb", "uEnv.txt", "rootfs.ext2", "data.ext4"):
        path = output / name
        artifacts[name] = {"bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    manifest = {"schema": "dcentos.bm1396_sd_image_manifest.v1", "target": target + "-sd-standalone",
                "board_target": target, "install_scope": "external_media_boot", "requires_sd_present": True,
                "root_uuid":filesystem_ids["rootfs.ext2"], "data_uuid":DATA_UUIDS[target],
                "image": image.name, "image_size_bytes": image.stat().st_size, "image_sha256": digest.hexdigest(),
                "boot_artifacts_complete": True, "artifacts": artifacts,
                "partitions": [{"index": index + 1, "start_sector": start, "sectors": sectors, "type": kind}
                               for index, (_, start, sectors, kind) in enumerate(parts)],
                "nand_writes": False, "physical_qualification": "pending"}
    image.with_suffix(image.suffix + ".manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return image


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    data_uuid = actions.add_parser("data-uuid")
    data_uuid.add_argument("--target", choices=TARGETS, required=True)
    root = actions.add_parser("root")
    root.add_argument("--root", type=Path, required=True)
    root.add_argument("--target", choices=TARGETS, required=True)
    root.add_argument("--binaries", type=Path, required=True)
    root.add_argument("--root-uuid", required=True)
    root.add_argument("--data-uuid", required=True)
    root.add_argument("--base-sha256")
    image = actions.add_parser("assemble")
    image.add_argument("--output", type=Path, required=True)
    image.add_argument("--target", choices=TARGETS, required=True)
    image.add_argument("--version", required=True)
    args = parser.parse_args()
    if args.action == "data-uuid":
        print(DATA_UUIDS[args.target])
    elif args.action == "root":
        prepare_root(args.root, args.target, args.binaries, args.root_uuid, args.data_uuid, args.base_sha256)
    else:
        print(assemble(args.output, args.target, args.version))


if __name__ == "__main__":
    main()
