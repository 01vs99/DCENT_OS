#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Compile and source-compare the distinct BBCtrl NAND RAM recovery DTB."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import sys
import tarfile
import zipfile

from build_am3_bb_recovery_kernel import SOURCE_SHA256, VERSION

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1]/"dcent-toolbox/src"))
from dcent_toolbox.core.flattened_device_tree import parse_fdt  # noqa: E402

DONOR_SHA256 = "03926d8f61f8b1af900131fd799c8b21635cc4f84bf4020fefed54a4b6232361"
MODEL = "DCENT BBCtrl S19j NAND RAM recovery"
PROFILE = "bbctrl-s19j-20210622-ram-recovery/v1"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def nodes(data):
    return {node.path: {prop.name: prop.value for prop in node.properties} for node in parse_fdt(data).nodes}


def physical_address(tree: dict, path: str) -> int:
    """Translate the actual OF reg through each explicit parent ranges map."""
    def count(node, key, default):
        raw = tree[node].get(key, struct.pack(">I", default))
        value, = struct.unpack(">I", raw)
        if not 1 <= value <= 2:
            raise ValueError("unsupported recovery peripheral address cell count")
        return value

    parent = path.rsplit("/", 1)[0] or "/"
    address = int.from_bytes(tree[path]["reg"][:count(parent, "#address-cells", 2)*4], "big")
    while parent != "/":
        grandparent = parent.rsplit("/", 1)[0] or "/"
        ranges = tree[parent].get("ranges")
        if ranges is None:
            raise ValueError("recovery peripheral lacks explicit parent address translation")
        if ranges:
            child_bytes = count(parent, "#address-cells", 2)*4
            parent_bytes = count(grandparent, "#address-cells", 2)*4
            size_bytes = count(parent, "#size-cells", 1)*4
            stride = child_bytes+parent_bytes+size_bytes
            if len(ranges) % stride:
                raise ValueError("recovery peripheral has malformed parent ranges")
            matches = []
            for start in range(0, len(ranges), stride):
                fields = ranges[start:start+stride]
                child = int.from_bytes(fields[:child_bytes], "big")
                translated = int.from_bytes(fields[child_bytes:child_bytes+parent_bytes], "big")
                size = int.from_bytes(fields[-size_bytes:], "big")
                if child <= address < child+size:
                    matches.append(translated+address-child)
            if len(matches) != 1:
                raise ValueError("recovery peripheral address has no unique parent range")
            address = matches[0]
        parent = grandparent
    return address


def compare(donor: bytes, recovery: bytes) -> dict:
    if sha(donor) != DONOR_SHA256:
        raise ValueError("exact held BBCtrl DTB source digest required")
    source, result = nodes(donor), nodes(recovery)
    if (result["/"].get("model") != MODEL.encode()+b"\0" or
            result["/"].get("compatible") != source["/"].get("compatible")):
        raise ValueError("dedicated recovery identity differs")
    gpmc = "/ocp/gpmc@50000000"
    nand = gpmc+"/nand@0,0"
    changes = []
    if result[gpmc].get("status") != b"okay\0" or result[nand].get("compatible") != b"ti,omap2-nand\0":
        raise ValueError("recovery NAND controller/driver disabled or mismatched")
    for key in ("compatible", "reg", "ranges", "#address-cells", "#size-cells"):
        if source[gpmc][key] != result[gpmc].get(key):
            raise ValueError("recovery GPMC source property differs: "+key)
    bools = {"gpmc,wait-on-read", "gpmc,wait-on-write", "gpmc,cycle2cycle-samecsen"}
    for key, value in source[nand].items():
        if key in ("ti,elm-id", "phandle", "linux,phandle"):
            continue
        expected = b"" if key in bools else value
        if result[nand].get(key) != expected:
            raise ValueError("recovery NAND source property differs: "+key)
        if value != expected:
            changes.append({"property": nand+":"+key, "before": value.hex(), "after": expected.hex(),
                            "reason": "normalize presence-only boolean for current DT binding"})
    old_parts = {props["label"]: props for path, props in source.items()
                 if path.startswith(nand+"/") and "label" in props}
    new_parts = {props["label"]: props for path, props in result.items()
                 if path.startswith(nand+"/") and "label" in props}
    if len(old_parts) != 12 or set(old_parts) != set(new_parts):
        raise ValueError("exact twelve original partition labels required")
    for label, old in old_parts.items():
        new = new_parts[label]
        if old["reg"] != new["reg"] or ("read-only" in new) != (label not in (b"bootenv\0", b"nvdata\0")):
            raise ValueError("recovery partition range/protection differs")
    nand_pins = next(props for path, props in result.items() if path.endswith("/bb-recovery-nand"))
    if source["/pinmux@44e10800/nandflash_pins_s0"]["pinctrl-single,pins"] != nand_pins["pinctrl-single,pins"]:
        raise ValueError("NAND pad source differs")
    phandles = {props["phandle"]: (path, props) for path, props in result.items() if "phandle" in props}
    if phandles[result[gpmc]["pinctrl-0"]][1] != nand_pins:
        raise ValueError("GPMC NAND pin group is not linked")
    elm = phandles[result[nand]["ti,elm-id"]][1]
    if b"ti,am3352-elm\0" not in elm.get("compatible", b"") or elm.get("status") != b"okay\0":
        raise ValueError("NAND BCH8 ELM is not linked")
    aliases = result["/aliases"]
    mmc_path = aliases["mmc0"].rstrip(b"\0").decode()
    mmc = result[mmc_path]
    if (physical_address(result, mmc_path) != 0x48060000 or mmc.get("status") != b"okay\0" or
            mmc.get("compatible") != b"ti,am335-sdhci\0" or mmc.get("bus-width") != struct.pack(">I", 4) or
            mmc.get("cd-gpios", b"")[4:] != struct.pack(">II", 6, 0) or "cd-inverted" not in mmc):
        raise ValueError("donor SD MMC/card-detect route differs")
    gpio_path, _gpio = phandles[mmc["cd-gpios"][:4]]
    if physical_address(result, gpio_path) != 0x44e07000:
        raise ValueError("donor SD card-detect GPIO controller differs")
    mmc_pins = phandles[mmc["pinctrl-0"]][1].get("pinctrl-single,pins")
    expected_mmc = struct.pack(">14I", 0x160, 0x2f, 0xfc, 0x30, 0xf8, 0x30,
                               0xf4, 0x30, 0xf0, 0x30, 0x104, 0x30, 0x100, 0x30)
    if mmc_pins != expected_mmc:
        raise ValueError("donor SD/native MMC0 pad routing differs")
    supply = phandles[mmc["vmmc-supply"]][1]
    for key in ("regulator-min-microvolt", "regulator-max-microvolt"):
        if supply.get(key) != source["/fixedregulator@0"][key]:
            raise ValueError("donor SD regulator differs")
    console_path = aliases["serial0"].rstrip(b"\0").decode()
    console = result[console_path]
    if console.get("status") != b"okay\0" or physical_address(result, console_path) != 0x44e09000:
        raise ValueError("recovery UART0 console is disabled")
    if phandles[console["pinctrl-0"]][1].get("pinctrl-single,pins") != struct.pack(">4I", 0x170, 0x30, 0x174, 0):
        raise ValueError("native UART0 console pad routing differs")
    for number in range(1, 6):
        alias = aliases.get(f"serial{number}")
        if alias and result[alias.rstrip(b"\0").decode()].get("status") != b"disabled\0":
            raise ValueError("recovery must not activate hashboard UARTs")
    if any(props.get("compatible") in (b"gpio-leds\0", b"gpio-rctrl\0") for props in result.values()):
        raise ValueError("recovery must not inherit donor GPIO LED/reset clients")
    changes.extend([
        {"property": "model", "before": source["/"]["model"].decode().rstrip("\0"), "after": MODEL,
         "reason": "distinct recovery identity; no claim of LuxOS mining DTB equivalence"},
        {"property": "clock/interrupt/controller ancestry", "reason": "Linux5.4 AM33xx SoC includes replace Linux3.8 hwmod-only binding"},
        {"property": nand+":compatible", "after": "ti,omap2-nand", "reason": "Linux5.4 OMAP NAND OF driver match"},
        {"property": nand+":ti,elm-id", "reason": "rebind to Linux5.4 AM3352 ELM node"},
        {"property": gpmc+":pinctrl-0", "before": source[gpmc]["pinctrl-0"].hex(),
         "reason": "replace stale donor numeric phandle with its verbatim NAND pad group"},
        {"property": "MMC0/UART0/MII pads", "reason": "explicit AM335x native pads from Linux5.4 bone-common bindings; donor SD GPIO0_6,3.3V and PHY0 retained"},
        {"property": "partition:read-only", "reason": "kernel protects all ten preserved windows; only bootenv/nvdata writable"},
        {"property": "donor GPIO LED/reset/mining peripherals", "reason": "omitted from independent RAM recovery"},
    ])
    return {"schema": "dcentos.bbctrl-recovery-dtb/v1", "profile": PROFILE, "model": MODEL,
            "donor_sha256": sha(donor), "dtb_sha256": sha(recovery), "dtb_bytes": len(recovery),
            "physical_boot_validated": False, "mining_carrier_equivalence": False,
            "source_comparison": "verified", "changes": changes}


def verify_linux_sources(archive: Path, linux_tree: Path, dependencies: list[Path]) -> dict:
    digest = hashlib.sha256()
    with archive.open("rb") as source:
        for chunk in iter(lambda: source.read(1024*1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != SOURCE_SHA256:
        raise ValueError("pinned kernel.org Linux source archive required")
    pins = {}
    with tarfile.open(archive, "r:xz") as source:
        for path in dependencies:
            relative = path.resolve().relative_to(linux_tree.resolve()).as_posix()
            member = source.extractfile("linux-"+VERSION+"/"+relative)
            if member is None or member.read() != path.read_bytes():
                raise ValueError("Linux DT dependency differs from pinned source: "+relative)
            pins[relative] = sha(path.read_bytes())
    return pins


def build(archive: Path, linux_archive: Path, linux_tree: Path, output: Path) -> dict:
    if os.name != "posix":
        raise ValueError("Linux host with cpp/dtc required")
    if output.exists() or output.is_symlink():
        raise ValueError("new recovery DTB output directory required")
    with zipfile.ZipFile(archive) as original:
        donor = original.read("devicetree.dtb")
    if sha(donor) != DONOR_SHA256:
        raise ValueError("exact held BBCtrl donor required")
    dts = SCRIPT_DIR/"first_install/am3_bbctrl_recovery.dts"
    command = ["cpp", "-nostdinc", "-undef", "-D__DTS__", "-x", "assembler-with-cpp",
               "-I", str(linux_tree/"include"), "-I", str(linux_tree/"arch/arm/boot/dts"), str(dts)]
    dependencies = subprocess.run(command[:1]+["-M", "-MT", "dtb"]+command[1:], capture_output=True, check=True)
    paths = shlex.split(dependencies.stdout.decode().replace("\\\n", "").split(":", 1)[1])
    pins = {path: sha(Path(path).read_bytes()) for path in paths}
    # The native MMC/UART/MII pad choices are copied from this upstream board
    # include, so retain its pin even though it is not included wholesale.
    linux_dependencies = [Path(path) for path in paths if Path(path).resolve() != dts.resolve()]
    linux_dependencies.append(linux_tree/"arch/arm/boot/dts/am335x-bone-common.dtsi")
    source_pins = verify_linux_sources(linux_archive, linux_tree, linux_dependencies)
    preprocessed = subprocess.run(command, capture_output=True, check=True)
    compiled = subprocess.run(["dtc", "-I", "dts", "-O", "dtb"], input=preprocessed.stdout,
                              capture_output=True, check=True)
    receipt = compare(donor, compiled.stdout)
    if any(sha(Path(path).read_bytes()) != digest for path, digest in pins.items()):
        raise ValueError("DTB source dependency changed during compilation")
    receipt["source_dependencies"] = pins
    receipt["linux_source_archive_sha256"] = SOURCE_SHA256
    receipt["linux_source_dependencies"] = source_pins
    output.mkdir(mode=0o700)
    for name, data in (("devicetree.dtb", compiled.stdout), ("source.preprocessed.dts", preprocessed.stdout),
                       ("dtc.log", compiled.stderr), ("dtb-receipt.json", (json.dumps(receipt, indent=2)+"\n").encode())):
        with (output/name).open("xb") as destination:
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock-archive", type=Path, required=True)
    parser.add_argument("--linux-tree", type=Path, required=True)
    parser.add_argument("--linux-archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.stock_archive.absolute(), args.linux_archive.absolute(),
                           args.linux_tree.absolute(), args.output.absolute()), indent=2))
