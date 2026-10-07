#!/usr/bin/env python3
"""Build a disposable ARM NAND guest around the real native updater and rollback."""

import argparse
import gzip
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

from prepare_am2_arm_guest import HERE, WORKSPACE, base_guest, pack_guest
from build_am2_stock_window import verify as verify_writer_bundle
from dcent_toolbox.core.am2_first_install_executor import EXPECTED_PARTITIONS, _sha
from lib import am2_ota_boot as ota
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def preflight_package(guest):
    """Execute the unchanged updater's package-only path on the Linux host."""
    script = guest / "i01/sysupgrade"
    env = dict(os.environ)
    env.update(
        DCENT_SYSUPGRADE_OFFLINE_HARNESS="1",
        DCENT_SYSUPGRADE_OFFLINE_MARKER=str(guest / "i01/offline-marker"),
        DCENT_SYSUPGRADE_PROC_CMDLINE_PATH=str(guest / "i01/cmdline-native1"),
        DCENT_SYSUPGRADE_BOARD_TARGET_PATH=str(guest / "etc/dcentos/board_target"),
        DCENT_SYSUPGRADE_VERSION_PATH=str(guest / "etc/dcentos-version"),
        DCENT_SYSUPGRADE_RELEASE_PUBKEY=str(guest / "etc/dcentos/release_ed25519.pub"),
        DCENT_SYSUPGRADE_AM2_OTA_TOOL=str(
            guest / "usr/libexec/dcentos/am2_ota_boot.py"
        ),
        DCENT_SYSUPGRADE_LOCK_DIR=str(guest / "i01/host-package-test-lock"),
    )
    for name, path in re.findall(
        r'^([A-Z0-9_]+_HELPER)="(/usr/libexec/dcentos/[^"\n]+)"',
        script.read_text(),
        re.M,
    ):
        env["DCENT_SYSUPGRADE_" + name] = str(guest / path.lstrip("/"))
    result = subprocess.run(
        ["sh", str(script), "-T", "--stop-miner", str(guest / "i01/native-ota.tar")],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    (guest / "i01/host-package-test.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise ValueError(
            "fixture package preflight failed: "
            + result.stdout[-3000:]
            + result.stderr[-1000:]
        )
    return result.stdout


def refresh_sources(guest, tools):
    if (
        not guest.is_absolute()
        or guest.is_symlink()
        or guest.parent != Path("/root/dcent-beta-i01-arm-guest")
        or not guest.name.startswith("guest-ota-v")
        or (guest / "i01/FIXTURE").read_text().strip()
        != "dcent-i01-arm-kernel-ordinary-identity-v1"
        or guest.with_name(guest.name + ".cpio.gz").exists()
    ):
        raise ValueError("only an unpacked disposable OTA guest may be refreshed")
    verify_writer_bundle(tools)
    project = HERE.parent.parent
    overlay = project / "br2_external_dcentos/board/zynq/rootfs-overlay"
    copies = [
        (
            tools / "am2-nand-window-armv7",
            guest / "usr/libexec/dcentos/am2-nand-window",
        ),
        (HERE / "am2_native_ota_arm_guest.sh", guest / "init"),
        (overlay / "etc/init.d/S40network", guest / "etc/init.d/S40network"),
        (overlay / "etc/init.d/S99upgrade", guest / "etc/init.d/S99upgrade"),
        (
            project / "br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentos-update-observer.py",
            guest / "usr/libexec/dcentos/dcentos-update-observer.py",
        ),
        (
            HERE.parent / "lib/am2_ota_boot.py",
            guest / "usr/libexec/dcentos/am2_ota_boot.py",
        ),
        (
            HERE.parent / "prepare_am2_fabric_boot.py",
            guest / "usr/libexec/dcentos/prepare_am2_fabric_boot.py",
        ),
        (
            overlay / "usr/libexec/dcentos/am2-native-ota.sh",
            guest / "usr/libexec/dcentos/am2-native-ota.sh",
        ),
        (
            overlay / "usr/sbin/dcent-am2-ota-rollback",
            guest / "usr/sbin/dcent-am2-ota-rollback",
        ),
        (
            project
            / "br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/usr/sbin/sysupgrade",
            guest / "i01/sysupgrade",
        ),
    ]
    for path in (HERE.parent / "lib").glob("sysupgrade_*"):
        if path.is_file() and path.suffix in {".sh", ".py"}:
            copies.append(
                (path, guest / "usr/libexec/dcentos" / path.name.replace("_", "-"))
            )
    for source, destination in copies:
        shutil.copyfile(source, destination)
        destination.chmod(0o755)
    with tarfile.open(guest / "i01/native-ota.tar") as tar:
        raw = tar.extractfile("sysupgrade-am2-s19j/fpga_bitstream.bit").read()
    (guest / "i01/am2-fabric.itb").write_bytes(ota.fit_from_raw(raw))
    (guest / "i01/fpga_bitstream.bit").write_bytes(raw)
    # Match am2-s19jpro/post-build.sh's shebang normalization. Directly copying
    # a Windows checkout over a post-built donor must not resurrect CRLF.
    for path in (guest / "usr/libexec/dcentos").iterdir():
        if path.is_file() and not path.is_symlink():
            raw = path.read_bytes()
            if raw.startswith(b"#!") and b"\r\n" in raw:
                path.write_bytes(raw.replace(b"\r\n", b"\n"))
            if path.suffix == ".sh":
                subprocess.run(["sh", "-n", str(path)], check=True, capture_output=True)
    return {
        "refreshed": {
            str(destination.relative_to(guest)): _sha(destination.read_bytes())
            for _, destination in copies
        }
    }


def build(guest, donor, kernel, tools, rootfs):
    proc = (
        "dev:    size   erasesize  name\n"
        + "".join(
            f'mtd{i}: {size:08x} 00020000 "{name}"\n'
            for i, (name, size) in enumerate(EXPECTED_PARTITIONS)
        )
    ).encode()
    inputs = base_guest(
        guest, donor, kernel, "am2_native_ota_arm_guest.sh", EXPECTED_PARTITIONS, proc
    )
    identity = inputs.parent
    archive = (
        WORKSPACE
        / ""
    )
    with tarfile.open(archive) as tar:
        raw = gzip.decompress(tar.extractfile("firmware/system.bit.gz").read())
    (identity / "am2-fabric.itb").write_bytes(ota.fit_from_raw(raw))
    held = (
        WORKSPACE
        / "DCENT_OS_Antminer/output/beta-xil-20260617/DCENTOS_XIL3_S19jPro_beta20260617.tar"
    )
    with tarfile.open(held) as tar:
        kernel_raw = tar.extractfile("sysupgrade-am2-s19j/kernel").read()
    (identity / "kernel").write_bytes(kernel_raw)
    (identity / "rootfs").write_bytes(rootfs.read_bytes())
    env = {
        **ota.fabric.nand_boot_environment(1, "run nandboot_recovery"),
        "firmware": "1",
        "miner_hwid": "fixture123",
        "ethaddr": "02:00:00:00:00:01",
    }
    (identity / "env.defaults").write_text(
        "".join(f"{k}={v}\n" for k, v in sorted(env.items()))
    )
    for slot in (1, 2):
        (identity / f"cmdline-native{slot}").write_text(
            f"console=ttyAMA0 ubi.mtd={6 + slot} dcent.fpga_load_completed=1 dcent.fpga_sha256={ota.fabric.BITSTREAM_SHA256}\n"
        )
    project = HERE.parent.parent
    overlay = project / "br2_external_dcentos/board/zynq/rootfs-overlay"
    common = project / "br2_external_dcentos/board/common/rootfs-overlay"
    # Copy current updater participants explicitly; donor target is only the
    # real ARM executable/DSO closure, not a claim of final-image freshness.
    for parent in (overlay / "usr/libexec/dcentos", common / "usr/libexec/dcentos"):
        for source in parent.iterdir():
            if source.is_file():
                destination = guest / "usr/libexec/dcentos" / source.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
                destination.chmod(0o755)
    copies = [
        (HERE.parent / "lib/am2_ota_boot.py", "usr/libexec/dcentos/am2_ota_boot.py"),
        (
            HERE.parent / "prepare_am2_fabric_boot.py",
            "usr/libexec/dcentos/prepare_am2_fabric_boot.py",
        ),
        (tools / "am2-nand-window-armv7", "usr/libexec/dcentos/am2-nand-window"),
        (
            overlay / "usr/sbin/dcent-am2-ota-rollback",
            "usr/sbin/dcent-am2-ota-rollback",
        ),
        (
            project
            / "br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/usr/sbin/sysupgrade",
            "i01/sysupgrade",
        ),
    ]
    for source, target in copies:
        destination = guest / target
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o755)
    for leaf in ("sysupgrade_archive_admission.sh", "sysupgrade_manifest_json.py"):
        target = leaf.replace("_", "-")
        shutil.copyfile(
            HERE.parent / "lib" / leaf, guest / "usr/libexec/dcentos" / target
        )
    (identity / "bin").mkdir()
    (identity / "bin/reboot").write_text(
        "#!/bin/sh\necho DCENT_FIXTURE_REBOOT_REQUESTED\n"
    )
    (identity / "bin/reboot").chmod(0o755)
    (identity / "offline-marker").write_text(
        "dcent-sysupgrade-offline-nandsim-harness-v1\n"
    )
    (guest / "etc/dcentos/board_target").write_text("am2-s19j\n")
    (guest / "etc/dcentos-version").write_text("1.1.0\n")
    key = (
        Ed25519PrivateKey.generate()
    )  # disposable fixture key; private bytes never enter guest
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    (guest / "etc/dcentos/release_ed25519.pub").write_bytes(public)
    payloads = {
        "kernel": kernel_raw,
        "root": rootfs.read_bytes(),
        "fpga_bitstream.bit": raw,
        "release_ed25519.pub": public,
        "METADATA": b'{"board":"am2-s19j"}\n',
    }
    prefix = "sysupgrade-am2-s19j"
    manifest = {
        "schema": 1,
        "product": "DCENT_OS",
        "family": "antminer",
        "package_type": "sysupgrade",
        "installable": True,
        "artifact_maturity": "experimental",
        "board_family": "am2",
        "board": "am2-s19j",
        "board_target": "am2-s19j",
        "version": "1.1.0",
        "status": "experimental",
        "manifest_profile": "dcentos.sysupgrade-authority/v1",
        "payloads": {
            name: {
                "path": f"{prefix}/{leaf}",
                "size": len(payloads[leaf]),
                "sha256": _sha(payloads[leaf]),
            }
            for name, leaf in (
                ("kernel", "kernel"),
                ("rootfs", "root"),
                ("bitstream", "fpga_bitstream.bit"),
                ("verification_key", "release_ed25519.pub"),
                ("metadata", "METADATA"),
            )
        },
    }
    payloads["MANIFEST.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    payloads["MANIFEST.sig"] = key.sign(payloads["MANIFEST.json"])
    payloads["SHA256SUMS"] = "".join(
        f"{_sha(data)}  {name}\n"
        for name, data in payloads.items()
        if name not in {"MANIFEST.json", "MANIFEST.sig"}
    ).encode()
    with tarfile.open(
        identity / "native-ota.tar", "w", format=tarfile.USTAR_FORMAT
    ) as tar:
        directory = tarfile.TarInfo(prefix + "/")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        tar.addfile(directory)
        for name, data in payloads.items():
            info = tarfile.TarInfo(f"{prefix}/{name}")
            info.size = len(data)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
    (identity / "native-ota.tar").chmod(0o600)
    files = [
        "init",
        "i01/sysupgrade",
        "i01/native-ota.tar",
        "usr/bin/python3.13",
        "usr/bin/fw_setenv",
        "usr/libexec/dcentos/am2-nand-window",
        "usr/libexec/dcentos/am2-native-ota.sh",
        "usr/libexec/dcentos/am2_ota_boot.py",
        "usr/sbin/dcent-am2-ota-rollback",
    ]
    report = {
        "scope": "real ARM native OTA transaction fixture; boot transition simulated; not final candidate image",
        "files": {name: _sha((guest / name).read_bytes()) for name in files},
    }
    report.update(refresh_sources(guest, tools))
    report["host_package_test"] = preflight_package(guest)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("guest", "donor", "kernel", "tools", "rootfs"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--pack", action="store_true")
    parser.add_argument("--refresh", action="store_true")
    args = parser.parse_args()
    report = (
        refresh_sources(args.guest, args.tools)
        if args.refresh
        else build(args.guest, args.donor, args.kernel, args.tools, args.rootfs)
    )
    if args.refresh:
        report["host_package_test"] = preflight_package(args.guest)
    if args.pack:
        report.update(pack_guest(args.guest))
    print(json.dumps(report, indent=2))
