"""Prepare one create-only native28 Zynq SD base build; never run make.

Run as a module under Linux. Separate AM1/S9i and AM2/S17 Pro base roots retain
their architecture/config lineage. Their remaining exact variants are composed
only after the fresh base and complete root reader have passed actual checks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from .assets import (
    Asset,
    BASE_SERVICES,
    OWN_SERVICES,
    SOURCE_SERVICES,
    native_assets,
    read_source,
    source_assets,
)

BUILDROOT = Path("/root/dcentos-build/buildroot")
BUILDROOT_COMMIT = "7c8edc1b402efcd7bba2dabfe0b3be877adaed7a"
BUILDROOT_PATCH = "75dcb00abfe832a2f459394e59b90f74bc8cd83604affd0930cf7d0ea3fd6a8a"
NCURSES_SHA = "056704515d1a812fe4d91b9fecf401adbc90e830a64615bd63310c75e89d64d0"
TOOLCHAIN_NAME = "gcc-linaro-7.2.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz"
TOOLCHAIN_SHA = "cee0087b1f1205b73996651b99acd3a926d136e71047048f1758ffcec69b1ca2"


def pin(raw: bytes) -> dict:
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def write_new(path: Path, raw: bytes, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(mode)


def render_defconfig(base: str, family: str, job: Path, toolchain: Path) -> str:
    """Append the isolated SD-only overrides to the selected source config."""
    if family not in {"am1", "am2"}:
        raise ValueError("exact AM1 or AM2 build family required")
    for path in (job, toolchain):
        if not path.is_absolute() or any(c in str(path) for c in '\n\r"\\'):
            raise ValueError("absolute unquoted Linux build path required")
    target = "am1-s9i" if family == "am1" else "am2-s17p"
    hook = job / "source/DCENT_OS_Antminer/scripts/native_zynq_sd/post_build.sh"
    overrides = [
        'BR2_TOOLCHAIN_EXTERNAL_URL="file://' + str(toolchain) + '"',
        'BR2_ROOTFS_OVERLAY="' + str(job / "overlay") + '"',
        'BR2_ROOTFS_POST_BUILD_SCRIPT="' + str(hook) + '"',
        'BR2_ROOTFS_POST_SCRIPT_ARGS="' + str(job / "inputs.json") + '"',
        'BR2_ROOTFS_POST_IMAGE_SCRIPT=""',
        'BR2_PACKAGE_BUSYBOX_CONFIG="$(BR2_EXTERNAL_DCENTOS_PATH)/board/zynq/native-sd/busybox.config"',
        'BR2_TARGET_GENERIC_ROOT_PASSWD="*"',
        "# BR2_TARGET_ENABLE_ROOT_LOGIN is not set",
        'BR2_TARGET_GENERIC_HOSTNAME="dcentos-' + target.split("-", 1)[1] + '"',
        'BR2_TARGET_GENERIC_ISSUE="DCENT_OS native28 private SD beta"',
        "BR2_JLEVEL=2",
        "BR2_REPRODUCIBLE=y",
        "# BR2_PACKAGE_DCENTOS_TOOLS is not set",
        "# BR2_PACKAGE_AM2_NAND_WINDOW is not set",
        "# BR2_PACKAGE_MTD is not set",
        "# BR2_PACKAGE_MTD_UBIFS_UTILS is not set",
        "# BR2_PACKAGE_LIBUBOOTENV is not set",
        "# BR2_PACKAGE_LIBUBOOTENV_TOOLS is not set",
        "# BR2_PACKAGE_STRACE is not set",
        "# BR2_TARGET_ROOTFS_EXT2 is not set",
        "BR2_TARGET_ROOTFS_SQUASHFS=y",
        "BR2_TARGET_ROOTFS_SQUASHFS_BS_1024K=y",
    ]
    if family == "am1":
        overrides += [
            "# BR2_TARGET_ROOTFS_SQUASHFS4_XZ is not set",
            "BR2_TARGET_ROOTFS_SQUASHFS4_GZIP=y",
        ]
    else:
        overrides += [
            "# BR2_TARGET_ROOTFS_SQUASHFS4_GZIP is not set",
            "BR2_TARGET_ROOTFS_SQUASHFS4_XZ=y",
        ]
    return (
        base
        + "\n# Exact seven-route SD overrides; no legacy root overlay or post-image writer.\n"
        + "\n".join(overrides)
        + "\n"
    )


def prepare(workspace: Path, family: str, version: str) -> dict:
    if (
        os.name != "posix"
        or family not in {"am1", "am2"}
        or not re.fullmatch(r"[a-z0-9]+", version)
    ):
        raise ValueError("Linux exact AM1/AM2 family and simple version required")
    workspace = workspace.resolve(strict=True)
    target = "am1-s9i" if family == "am1" else "am2-s17p"
    job = Path(f"/root/dcent-beta-native-zynq-sd-{family}-{version}")
    evidence = workspace / ""
    receipt = evidence / f"seven-sd-{family}-build-inputs-{version}.json"
    if job.exists() or job.is_symlink() or receipt.exists():
        raise ValueError("preserve prior image inputs and build output")

    def git(*args):
        return subprocess.check_output(["git", "-C", str(BUILDROOT), *args])

    if git("rev-parse", "HEAD").decode().strip() != BUILDROOT_COMMIT:
        raise ValueError("held Buildroot commit differs")
    if git("diff", "HEAD", "--name-only").decode().splitlines() != [
        "package/ncurses/ncurses.mk"
    ]:
        raise ValueError("unreviewed held Buildroot change")
    patch = git("diff", "--binary", "HEAD")
    if (
        pin(patch)["sha256"] != BUILDROOT_PATCH
        or pin((BUILDROOT / "package/ncurses/ncurses.mk").read_bytes())["sha256"]
        != NCURSES_SHA
    ):
        raise ValueError("held ncurses repair differs")
    toolchain = (
        workspace
        / "DCENT_OS_Antminer/output/beta-enablement-20260907/build-inputs"
        / TOOLCHAIN_NAME
    )
    toolchain_raw = read_source(toolchain, 128 * 1024 * 1024)
    if pin(toolchain_raw)["sha256"] != TOOLCHAIN_SHA:
        raise ValueError("held ARM Linaro archive differs")
    cached_toolchain = BUILDROOT / "dl/toolchain-external-custom" / TOOLCHAIN_NAME
    if read_source(cached_toolchain, 128 * 1024 * 1024) != toolchain_raw:
        raise ValueError("existing Linux compiler cache must equal retained archive")
    assets = source_assets(workspace, target)
    runtime_directory = Path(
        "/root/dcent-beta-native-checkpoint28-artifacts/armv7-unknown-linux-musleabihf"
    )
    assets.update(native_assets(runtime_directory))
    dashboard_receipt = evidence / "seven-dashboard-build-v1.json"
    dashboard_bytes = read_source(dashboard_receipt)
    dashboard = json.loads(dashboard_bytes)
    if (
        not dashboard["success"]
        or not dashboard["source_unchanged"]
        or not dashboard["dependencies_unchanged"]
    ):
        raise ValueError("successful separately source-bound dashboard build required")
    dashboard_dir = (
        workspace / "DCENT_OS_Antminer/output/i02-seven-dashboard-v1/source/dist"
    )
    for name, expected in dashboard["artifacts"].items():
        raw = read_source(dashboard_dir / name)
        if pin(raw) != expected:
            raise ValueError("actual isolated dashboard artifact differs")
        assets["usr/share/dcentos-dashboard/" + name] = Asset(raw, 0o644)
    assets["etc/dcentos-version"] = Asset(b"0.9.0\n", 0o644)
    native_join = evidence / "seven-runtime-dashboard-join-v1.json"
    native_join_bytes = read_source(native_join)
    joined = json.loads(native_join_bytes)
    if not joined["passed"] or joined["runtime_checkpoint"] != 28:
        raise ValueError("explicit actual native28 source/artifact join required")
    native_source_rows = []
    for row in joined["selected_frozen_sources"]:
        relative = Path(row["manifest_path"])
        actual = read_source(workspace / relative)
        if pin(actual) != {k: row[k] for k in ("bytes", "sha256")}:
            raise ValueError(
                "selected current startup/runtime source differs from native28"
            )
        native_source_rows.append({"path": relative.as_posix(), **pin(actual)})
    relative_external = Path("DCENT_OS_Antminer/br2_external_dcentos")
    inputs = {
        Path(asset.source)
        for asset in assets.values()
        if asset.source and asset.source.startswith("projects/")
    }
    inputs.update(
        relative_external / name
        for name in ("external.desc", "external.mk", "Config.in")
    )
    for path in (workspace / relative_external / "packages").rglob("*"):
        if path.is_file() and not set(path.parts) & {
            "__pycache__",
            ".pytest_cache",
            ".ruff_cache",
        }:
            inputs.add(path.relative_to(workspace))
    defconfig = (
        "dcentos_s9_defconfig"
        if family == "am1"
        else "dcentos_am2_s17pro_zynq_defconfig"
    )
    inputs.update(
        relative_external / "configs" / name
        for name in ("dcentos-common.fragment", defconfig)
    )
    inputs.add(relative_external / "board/zynq/busybox.config")
    inputs.add(relative_external / "board/zynq/native-sd/busybox.config")
    inputs.update(
        Path("DCENT_OS_Antminer/scripts/native_zynq_sd") / name
        for name in (
            "profiles.py",
            "assets.py",
            "prepare_build.py",
            "finalize_root.py",
            "post_build.sh",
        )
    )
    inputs.add(
        Path(
            "DCENT_OS_Antminer/br2_external_dcentos/board/zynq/rootfs-overlay/etc/dcentos-version"
        )
    )
    source_bytes = {}
    for relative in sorted(inputs):
        path = workspace / relative
        source_bytes[relative] = read_source(path)
    if (
        source_bytes[
            Path(
                "DCENT_OS_Antminer/br2_external_dcentos/board/zynq/rootfs-overlay/etc/dcentos-version"
            )
        ].strip()
        != b"0.9.0"
    ):
        raise ValueError("source version must remain exact native28 0.9.0")
    job.mkdir()
    source = job / "source"
    rows = []
    for relative, original in source_bytes.items():
        staged = original.replace(b"\r\n", b"\n")
        executable = staged.startswith(b"#!")
        write_new(source / relative, staged, 0o755 if executable else 0o644)
        rows.append(
            {
                "path": relative.as_posix(),
                "source": pin(original),
                "staged": pin(staged),
                "mode": 0o755 if executable else 0o644,
                "normalization": "crlf_to_lf" if original != staged else "unchanged",
            }
        )
    overlay = job / "overlay"
    overlay_rows = {}
    for name, asset in assets.items():
        write_new(overlay / name, asset.content, asset.mode)
        overlay_rows[name] = {
            **pin(asset.content),
            "mode": asset.mode,
            "source": asset.source,
            "original_source_sha256": asset.source_sha256,
        }
    for name in (
        "data",
        "root",
        "run",
        "tmp",
        "proc",
        "sys",
        "dev",
        "usr/bin",
        "usr/sbin",
    ):
        (overlay / name).mkdir(parents=True, exist_ok=True)
    external = source / relative_external
    config = "\n".join(
        (external / "configs" / name).read_text()
        for name in ("dcentos-common.fragment", defconfig)
    )
    manifest_path = job / "inputs.json"
    config = render_defconfig(config, family, job, cached_toolchain)
    config_path = job / "native-sd.defconfig"
    write_new(config_path, config.encode())
    output = job / "buildroot-output"
    make = [
        "make",
        "-C",
        str(BUILDROOT),
        "O=" + str(output),
        "BR2_EXTERNAL=" + str(external),
    ]
    services = sorted(
        set(BASE_SERVICES + SOURCE_SERVICES + OWN_SERVICES)
        | ({"S12fpga_identity"} if family == "am2" else set())
    )
    result = {
        "schema": "dcentos.native_zynq_sd_build_inputs.v1",
        "board_target": target,
        "family": family,
        "job_root": str(job),
        "target_dir": str(output / "target"),
        "source": str(source),
        "buildroot": {
            "path": str(BUILDROOT),
            "commit": BUILDROOT_COMMIT,
            "patch_sha256": BUILDROOT_PATCH,
            "ncurses_sha256": NCURSES_SHA,
        },
        "toolchain": {"path": str(toolchain), **pin(toolchain_raw)},
        "actual_local_toolchain": {"path": str(cached_toolchain), **pin(toolchain_raw)},
        "source_inputs": rows,
        "overlay": overlay_rows,
        "services": services,
        "defconfig": {"path": str(config_path), **pin(config.encode())},
        "native_checkpoint": 28,
        "native_dashboard_join": pin(native_join_bytes),
        "selected_native28_current_sources": native_source_rows,
        "dashboard_build": pin(dashboard_bytes),
        "configure_command": make + ["BR2_DEFCONFIG=" + str(config_path), "defconfig"],
        "build_command": make + ["-j2"],
        "build_environment": {"SOURCE_DATE_EPOCH": "1700000000"},
        "claim": "fresh private host userspace build preparation; separate source-bound boot/data/image qualification still required",
        "make_launched": False,
        "hardware_contact": False,
        "signing": False,
        "publication": False,
    }
    for relative, raw in source_bytes.items():
        if read_source(workspace / relative) != raw:
            raise ValueError(
                "source changed during build preparation: " + str(relative)
            )
    for name, row in overlay_rows.items():
        path = overlay / name
        if (
            pin(read_source(path)) != {k: row[k] for k in ("bytes", "sha256")}
            or stat.S_IMODE(path.stat().st_mode) != row["mode"]
        ):
            raise ValueError("prepared overlay changed")
    for row in rows:
        path = source / row["path"]
        if (
            pin(read_source(path)) != row["staged"]
            or stat.S_IMODE(path.stat().st_mode) != row["mode"]
        ):
            raise ValueError("prepared source changed")
    if git("diff", "--binary", "HEAD") != patch:
        raise ValueError("held Buildroot source changed during preparation")
    for row in native_source_rows:
        if pin(read_source(workspace / row["path"])) != {
            k: row[k] for k in ("bytes", "sha256")
        }:
            raise ValueError("native28 current-source join changed during preparation")
    if (
        read_source(native_join) != native_join_bytes
        or read_source(dashboard_receipt) != dashboard_bytes
        or read_source(cached_toolchain, 128 * 1024 * 1024) != toolchain_raw
    ):
        raise ValueError(
            "runtime/dashboard/compiler evidence changed during preparation"
        )
    raw = (json.dumps(result, indent=2) + "\n").encode()
    write_new(job / "held-buildroot.patch", patch)
    write_new(manifest_path, raw)
    write_new(receipt, raw)
    if read_source(manifest_path) != raw or read_source(receipt) != raw:
        raise ValueError("prepared input receipt readback differs")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--family", choices=("am1", "am2"), required=True)
    parser.add_argument("--version", required=True)
    arguments = parser.parse_args()
    prepared = prepare(arguments.workspace, arguments.family, arguments.version)
    print(
        json.dumps(
            {
                key: prepared[key]
                for key in (
                    "board_target",
                    "job_root",
                    "configure_command",
                    "build_command",
                    "make_launched",
                )
            },
            indent=2,
        )
    )
