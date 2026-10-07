#!/usr/bin/env python3
"""Stage exact stock C43 boot components and native S9SE/S9k SD userspace."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import uuid
import zlib

PROJECT = Path(__file__).resolve().parents[1]
DASHBOARD = PROJECT / "dashboard/dist"
WORKSPACE = PROJECT.parents[1]
DONOR = WORKSPACE / ""
OVERLAY = PROJECT / "br2_external_dcentos/board/zynq/c43/rootfs-overlay"
TARGETS = ("am1-s9se", "am1-s9k")
# Stable target/layout identifiers allow reviewed root updates to preserve the
# entire existing data filesystem. These identify filesystems, not operators.
DATA_UUIDS = {
    "am1-s9se": "a970508d-8427-5998-a732-08c4de3afe1a",
    "am1-s9k": "98a814e9-3a2f-58a9-bd93-f6b9cc1fd4a6",
}
PINS = {
    "BOOT.bin": (2752048, "e7353cb4a4b06434f3fc36b203fb0c794c54dc70491d319c23b0df3bfdaab222"),
    "uImage": (4006832, "85f7da5f8205a684acb057ce7268d2e395bc4f39e5ae4c088bbf4ede1fcb638f"),
    "devicetree.dtb": (7650, "10a0199be8a638c4bf319a623362a89b6bee38f732ab00204df499a2f25ad2ea"),
}
BITSTREAM_SHA256 = "1681558e124de9a3721bf4fe4b885ba9a122d2a9f2a4d7e0f560824d95cdd6cc"
BITSTREAM_OFFSET = 0x1D740
BITSTREAM_SIZE = 2083744
ADMITTED_AM2_BASE_SHA256 = "a1e75595367eab046a194ad241890ef3b2a6e2bada53029981f63f8dbd398aed"
COMMON_OVERLAY = PROJECT / "br2_external_dcentos/board/common/rootfs-overlay"
ZYNQ_OVERLAY = PROJECT / "br2_external_dcentos/board/zynq/rootfs-overlay"


def current_dashboard(directory: Path | None = None) -> dict[str, bytes]:
    if directory is None:
        directory = DASHBOARD
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
    return files


def fdt_properties(data: bytes) -> dict[tuple[str, str], bytes]:
    """Read property bytes for semantic verification of one bounded native edit."""
    header = struct.unpack(">10I", data[:40])
    if header[0] != 0xD00DFEED or header[1] != len(data):
        raise ValueError("bounded FDT required")
    offset = header[2]
    names = data[header[3]:header[3] + header[8]]
    nodes, properties = [], {}
    while offset < len(data):
        token = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        if token == 1:
            end = data.index(0, offset)
            nodes.append(data[offset:end].decode())
            offset = (end + 4) & ~3
        elif token == 2:
            nodes.pop()
        elif token == 3:
            size, key = struct.unpack_from(">2I", data, offset)
            offset += 8
            value = data[offset:offset + size]
            offset = (offset + size + 3) & ~3
            name = names[key:names.index(0, key)].decode()
            properties[("/".join(nodes), name)] = value
        elif token == 9:
            return properties
        elif token != 4:
            raise ValueError("unknown FDT token")
    raise ValueError("FDT end token missing")


def add_native_watchdog(dtb: Path, fdtput: str = "fdtput") -> None:
    # The held kernel has CONFIG_CADENCE_WATCHDOG=y, but its donor DTB has
    # only an obsolete SCU watchdog node. Xilinx2016.4 zynq-7000.dtsi supplies
    # this exact fixed PS watchdog tuple; reset-on-timeout is mandatory in
    # the compiled driver's own probe/start logic. No PL topology is changed.
    original = fdt_properties(dtb.read_bytes())
    clock_path = "/amba@0/ps7-slcr@f8000000/clkc@100"
    intc_path = "/amba@0/ps7-scugic@f8f01000"
    if original.get((clock_path, "phandle")) != struct.pack(">I", 2) or original.get((intc_path, "phandle")) != struct.pack(">I", 3):
        raise ValueError("C43 clock/GIC donor handles mismatch")
    node = "/amba@0/watchdog@f8005000"
    if any(path == node for path, _ in original):
        raise ValueError("unexpected pre-existing native watchdog node")
    subprocess.run([fdtput, "-c", str(dtb), node], check=True)
    entries = {"compatible": ("s", ["cdns,wdt-r1p2"]), "clocks": ("x", ["2", "2d"]),
               "interrupt-parent": ("x", ["3"]), "interrupts": ("x", ["0", "9", "1"]),
               "reg": ("x", ["f8005000", "1000"]), "timeout-sec": ("x", ["3c"]),
               "reset-on-timeout": ("x", [])}
    for name, (kind, values) in entries.items():
        subprocess.run([fdtput, "-t", kind, str(dtb), node, name, *values], check=True)
    changed = fdt_properties(dtb.read_bytes())
    if any(changed.get(key) != value for key, value in original.items()) or any(path != node for path, name in changed.keys() - original.keys()):
        raise ValueError("native watchdog patch changed unrelated donor properties")


def checked_path(root: Path, relative: str) -> Path:
    current = root
    for part in Path(relative).parts:
        if part in ("..", "."):
            raise ValueError("unsafe relative path")
        current /= part
        if current.is_symlink():
            raise ValueError(f"staging path is symlink: {relative}")
    return current


def checked_input(path: Path, size: int, digest: str) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size != size:
        raise ValueError(f"exact regular donor required: {path}")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"donor SHA256 mismatch: {path}")
    return data


def extract_fpga(boot: bytes) -> bytes:
    size, digest = PINS["BOOT.bin"]
    if len(boot) != size or hashlib.sha256(boot).hexdigest() != digest:
        raise ValueError("exact XC7Z007S C43 BOOT image required")
    pointer = struct.unpack_from("<I", boot, 0x9C)[0]
    header = struct.unpack_from("<16I", boot, pointer + 64)
    if sum(header) & 0xFFFFFFFF != 0xFFFFFFFF or header[5] * 4 != BITSTREAM_OFFSET:
        raise ValueError("C43 BOOT partition header mismatch")
    payload = boot[BITSTREAM_OFFSET:BITSTREAM_OFFSET + BITSTREAM_SIZE]
    if hashlib.sha256(payload).hexdigest() != BITSTREAM_SHA256:
        raise ValueError("C43 raw FPGA payload mismatch")
    return payload


def boot_environment() -> dict[str, str]:
    digest = bytes.fromhex(BITSTREAM_SHA256)
    writes = " && ".join(f"mw.l 0x{0x7F0000 + offset:x} 0x{int.from_bytes(digest[offset:offset+4], 'little'):08x} 1"
                         for offset in range(0, 32, 4))
    return {
        "dcent_fpga_hash_pin": writes,
        "dcent_fpga_load": (
            "setenv verify yes && load mmc 0 0x00800000 c43-fabric.itb"
            " && fdt addr 0x00800000"
            " && fdt get value dcent_hash_algo /images/c43-raw/hash-1 algo"
            " && test x${dcent_hash_algo} = xsha256"
            " && fdt get size dcent_hash_size /images/c43-raw/hash-1 value"
            " && itest ${dcent_hash_size} == 0x20"
            " && fdt get addr dcent_hash_addr /images/c43-raw/hash-1 value"
            " && run dcent_fpga_hash_pin && cmp.b ${dcent_hash_addr} 0x007f0000 0x20"
            " && imxtract 0x00800000 c43-raw 0x01200000"
            f" && itest ${{filesize}} == 0x{BITSTREAM_SIZE:x}"
            # Actual stock mmc_loadbit uses fpga load for this raw format.
            " && fpga load 0 0x01200000 ${filesize}"
        ),
        "dcent_sd_load": "load mmc 0 0x02000000 uImage && load mmc 0 0x03000000 devicetree.dtb",
        "dcent_bootargs": (
            "setenv bootargs console=ttyPS0,115200 root=/dev/mmcblk0p2 ro rootwait rootfstype=ext2"
            " dcent.c43_load_completed=${dcent_c43_load_completed}"
            f" dcent.c43_sha256={BITSTREAM_SHA256}"
        ),
        "uenvcmd": (
            "setenv dcent_c43_load_completed 0; if run dcent_fpga_load;"
            " then setenv dcent_c43_load_completed 1; else echo C43 FPGA load failed; fi;"
            " run dcent_sd_load && run dcent_bootargs && bootm 0x02000000 - 0x03000000"
        ),
    }


def prepare_boot(output: Path, donor: Path = DONOR, mkimage: str = "mkimage") -> None:
    if output.is_symlink() or not output.is_dir():
        raise ValueError("private regular boot staging directory required")
    held = {name: checked_input(donor / name, *pin) for name, pin in PINS.items()}
    payload = extract_fpga(held["BOOT.bin"])
    kernel = held["uImage"]
    header = bytearray(kernel[:64])
    magic, crc, _, length, load, entry, data_crc = struct.unpack_from(">7I", header)
    header[4:8] = b"\0" * 4
    if (magic != 0x27051956 or zlib.crc32(header) != crc or len(kernel) != length + 64
            or zlib.crc32(kernel[64:]) != data_crc or load != 0x8000 or entry != 0x8000):
        raise ValueError("held C43 kernel legacy header/CRC mismatch")
    for name, data in held.items():
        (output / ("BOOT.BIN" if name == "BOOT.bin" else name)).write_bytes(data)
    (output / "devicetree-stock.dtb").write_bytes(held["devicetree.dtb"])
    add_native_watchdog(output / "devicetree.dtb")
    (output / "c43-system.bin").write_bytes(payload)
    its = output / "c43-fabric.its"
    its.write_text('/dts-v1/;\n/ { description = "DCENT exact C43 FPGA"; #address-cells = <1>;\n'
                   ' images { c43-raw { description = "C43 XC7Z007S raw configuration";\n'
                   ' data = /incbin/("c43-system.bin"); type = "firmware"; arch = "arm";\n'
                   ' compression = "none"; hash-1 { algo = "sha256"; }; }; }; };\n', encoding="utf-8")
    subprocess.run([mkimage, "-f", its.name, "c43-fabric.itb"], cwd=output, check=True)
    (output / "uEnv.txt").write_text("\n".join(f"{key}={value}" for key, value in boot_environment().items()) + "\n", encoding="utf-8")


def prepare_root(root: Path, target: str, binaries: Path, root_uuid: str, data_uuid: str,
                 base_sha256: str | None = None, *, fresh_release: bool = False) -> None:
    if target not in TARGETS or root.is_symlink() or not root.is_dir():
        raise ValueError("exact C43 target and private root staging directory required")
    for value in (root_uuid, data_uuid):
        if str(uuid.UUID(value)) != value:
            raise ValueError("canonical root/data UUID required")
    if data_uuid != DATA_UUIDS[target] or root_uuid == data_uuid:
        raise ValueError("exact target/layout data UUID and distinct root UUID required")
    marker = checked_path(root, "etc/dcentos/board_target")
    source_target = marker.read_text().strip()
    if fresh_release:
        if source_target not in ("am1-s9", target):
            raise ValueError("fresh native release requires its exact target or S9 build base")
        from runtime_image_manifest import verify
        public_key = os.environ.get("DCENT_RELEASE_PUBKEY_FILE")
        if not public_key:
            raise ValueError("fresh native release requires its trusted public key")
        verify(root, source_target, os.environ.get("DCENT_RELEASE_CHANNEL", "beta"),
               checked_path(root, "etc/dcentos-version").read_text().strip(), Path(public_key))
    elif source_target == "am2-s19j":
        if base_sha256 != ADMITTED_AM2_BASE_SHA256:
            raise ValueError("only the exact audited fresh AM2 userspace base is admitted")
        if checked_path(root, "etc/dcentos/platform").read_text().strip() != "zynq-bm3-am2":
            raise ValueError("AM2 input platform does not match audited source")
    elif source_target != "am1-s9":
        raise ValueError("current S9 or exact audited AM2 ARMv7 userspace input required")
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
        if name == "dcentrald" and b"--c43-boot-cut-only" not in data:
            raise ValueError("C43 native daemon predates the required idle-boot cutoff command")
        inputs[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    dashboard = current_dashboard(root / "usr/share/dcentos-dashboard") if fresh_release else current_dashboard()
    destinations = [(name, "sbin/init" if name == "dcentos-init" else f"usr/bin/{name}") for name in inputs]
    for _, relative in destinations:
        checked_path(root, relative)
    for name, relative in destinations:
        destination = checked_path(root, relative)
        shutil.copyfile(binaries / name, destination)
        destination.chmod(0o755)
    # The audited AM2 base has a different old daemon at the path S82 executes.
    # Bind both canonical paths to the supplied binary; mke2fs preserves links.
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
                raise ValueError("C43 source overlay symlink")
            relative = str(source.relative_to(OVERLAY))
            destination = checked_path(root, relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            destination.chmod(0o755)
    # Install the current generic supervisor, not AM2's environment/override
    # loader, and its current common ownership helpers. Native C43 retains the
    # same session-latch discipline without inheriting any AM2 hardware recipe.
    for source in [ZYNQ_OVERLAY / "etc/init.d/S82dcentrald", ZYNQ_OVERLAY / "etc/init.d/S50dropbear",
                   ZYNQ_OVERLAY / "usr/sbin/dcent-enable-ssh",
                   *sorted((COMMON_OVERLAY / "usr/libexec/dcentos").glob("dcentrald-*.sh"))]:
        if source.name in ("S82dcentrald", "S50dropbear"):
            relative = "etc/init.d/" + source.name
        elif source.name == "dcent-enable-ssh":
            relative = "usr/sbin/" + source.name
        else:
            relative = "usr/libexec/dcentos/" + source.name
        destination = checked_path(root, relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o755)
    configs = PROJECT / "dcentrald/configs/beta"
    for source, destination in ((f"{target}-baked-default.toml", "etc/dcentrald.toml"),):
        shutil.copyfile(configs / source, checked_path(root, destination))
    identities = {"board_target": target, "board_family": "am1", "platform": "zynq-c43",
                  "c43-bitstream.sha256": BITSTREAM_SHA256, "c43-root-uuid": root_uuid, "c43-data-uuid": data_uuid}
    for name, value in identities.items():
        checked_path(root, "etc/dcentos/" + name).write_text(value + "\n", encoding="utf-8")
    # Beta cards start through dashboard setup and operator SSH keys, even
    # when an otherwise compatible lab S9 userspace was the input carrier.
    checked_path(root, "etc/dcentos/release-image").write_text("release_image=1\n", encoding="utf-8")
    # These SD candidates have no automatic NAND upgrade/commit lifecycle.
    for name in ("S10udevd", "S10modules", "S11modules", "S15pic_boot", "S37board_setup",
                 "S37bitmainer_setup", "S50telnet", "S81dcentos-xil-seed", "S99upgrade", "S99verify"):
        path = checked_path(root, "etc/init.d/" + name)
        if path.exists():
            path.unlink()
    foreign_files = ("etc/default/dcentrald-am2-xil-env", "etc/dcentrald/xil_override.toml",
                     "etc/dcentos/rail_gpio", "etc/dcentos/psu_config", "etc/dcentos/partial_yield_floor",
                     "usr/libexec/dcentos/am2-fabric-identity.sh", "usr/libexec/dcentos/am2-native-ota.sh")
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
    checked_path(root, "etc/hostname").write_text("dcentos-" + target.removeprefix("am1-") + "\n", encoding="utf-8")
    checked_path(root, "etc/dcentrald-target.conf").write_text(
        f"BOARD_FAMILY=am1\nBOARD_TARGET={target}\nPLATFORM=zynq-c43\nSOC=zynq-7000\nARCH=armv7\nVARIANT={target.removeprefix('am1-')}\n", encoding="utf-8")
    for name in ("dcentrald", "dcentos-init"):
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
        '    # This SD image owns its runtime; retained data executables do not\n'
        '    # replace the reviewed baked daemon after an image update.\n'
        '    DAEMON="/usr/local/bin/dcentrald"\n', 1)
    anchor = "fan_safety_override() {\n"
    if text.count(anchor) != 1:
        raise ValueError("exact native supervisor fallback function required")
    text = text.replace(anchor, anchor + '    case "$BOARD_TARGET" in am1-s9se|am1-s9k)\n'
                        '        echo "C43 hardware disposition remains with its retained native watchdog owner" >&2\n'
                        '        return 1 ;; esac\n', 1)
    # A failed early-init must not enter the S9 fallback or start with volatile
    # /data. Keep the normal persistent session-latch supervisor after this gate.
    anchor = 'case "$1" in\n'
    at = text.index(anchor)
    text = text[:at] + ('if [ "${1:-}" = start ]; then\n'
                        '    . /usr/libexec/dcentos/c43-sd-ready.sh\n'
                        '    if ! dcent_c43_sd_ready /etc/dcentos /run/dcentos /proc/sys/kernel/random/boot_id; then\n'
                        '        echo "C43 SD data ownership unavailable or current-boot cutoff incomplete; daemon startup refused" >&2\n'
                        '        exit 1\n    fi\nfi\n') + text[at:]
    supervisor.write_text(text, encoding="utf-8", newline="\n")
    (root / "etc/dcentos/c43-runtime-inputs.json").write_text(json.dumps(inputs, indent=2) + "\n", encoding="utf-8")
    (root / "etc/dcentos/c43-userspace-source.json").write_text(json.dumps({"source_target": source_target,
        "source_image_sha256": base_sha256, "composition": "c43-native-sd-v1"}, indent=2) + "\n", encoding="utf-8")


def assemble(output: Path, target: str) -> Path:
    if target not in TARGETS or output.is_symlink() or not output.is_dir():
        raise ValueError("exact C43 target and private image output required")
    parts = (("boot.vfat", 2048, 131072, 0x0C),
             ("rootfs.ext2", 133120, 262144, 0x83),
             ("data.ext4", 395264, 131072, 0x83))
    for name, _, sectors, _ in parts:
        path = output / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != sectors * 512:
            raise ValueError(f"partition {name} has wrong exact size")
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
    digest = hashlib.sha256()
    with image.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    artifacts = {}
    for name in ("BOOT.BIN", "uImage", "devicetree.dtb", "c43-system.bin", "c43-fabric.itb", "uEnv.txt", "rootfs.ext2", "data.ext4"):
        path = output / name
        artifacts[name] = {"bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    manifest = {"schema": "dcentos.c43_sd_image_manifest.v1", "target": target + "-sd-standalone",
                "board_target": target, "install_scope": "external_media_boot", "requires_sd_present": True,
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
    boot = actions.add_parser("boot")
    boot.add_argument("--output", type=Path, required=True)
    boot.add_argument("--donor", type=Path, default=DONOR)
    boot.add_argument("--mkimage", default="mkimage")
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
    args = parser.parse_args()
    if args.action == "data-uuid":
        print(DATA_UUIDS[args.target])
    elif args.action == "boot":
        prepare_boot(args.output, args.donor, args.mkimage)
    elif args.action == "root":
        prepare_root(args.root, args.target, args.binaries, args.root_uuid, args.data_uuid, args.base_sha256)
    else:
        print(assemble(args.output, args.target))


if __name__ == "__main__":
    main()
