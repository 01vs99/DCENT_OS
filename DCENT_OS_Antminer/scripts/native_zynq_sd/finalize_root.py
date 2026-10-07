"""Finalize only the manifest-owned fresh Buildroot target before SquashFS.

The separate preparation step must already freeze every overlay input and
identify the exact root directory. No physical device, service or boot command
is executed. Native and dashboard bytes are verified before and after changes.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys

TARGETS = {
    "am1-s9i",
    "am1-s9j",
    "am2-s17p",
    "am2-s17plus",
    "am2-t17",
    "am2-t17plus",
    "am2-s19pro",
}
COMMON_SERVICES = {
    "S01syslogd",
    "S02klogd",
    "S02sysctl",
    "S10udevd",
    "S40network",
    "S41ntp",
    "S43logrotate",
    "S45persistent",
    "S50dropbear",
    "S70dcentos-discovery",
    "S80dashboard",
    "S82dcentrald",
}


def digest(path: Path) -> dict:
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def member(root: Path, name: str) -> Path:
    if name.startswith("/") or any(part in ("", ".", "..") for part in name.split("/")):
        raise ValueError("canonical root-relative member required")
    current = root
    for part in name.split("/")[:-1]:
        current = current / part
        if not stat.S_ISDIR(current.lstat().st_mode):
            raise ValueError("direct directory parents required: " + name)
    return current / name.split("/")[-1]


def verify_overlay(root: Path, manifest: dict, *, final: bool = False) -> None:
    for name, expected in manifest["overlay"].items():
        path = member(root, name)
        info = path.lstat()
        links = 2 if final and name == "usr/local/bin/dcentrald" else 1
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != links
            or (final and stat.S_IMODE(info.st_mode) != expected["mode"])
            or digest(path) != {k: expected[k] for k in ("bytes", "sha256")}
        ):
            raise ValueError("actual source-bound overlay member differs: " + name)


def startup_snapshot(root: Path, allowed: set, overlay: dict) -> dict:
    """Require owned files for every admitted startup name, including rcS/rcK."""
    generated = {}
    for name in sorted(allowed):
        relative = "etc/init.d/" + name
        path = member(root, relative)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("direct unique startup file required: " + name)
        if relative not in overlay:
            if stat.S_IMODE(info.st_mode) != 0o755:
                raise ValueError("generated startup executable mode differs: " + name)
            generated[name] = {
                "device": info.st_dev,
                "inode": info.st_ino,
                "mode": stat.S_IMODE(info.st_mode),
                **digest(path),
            }
    return generated


def finalize(root: Path, manifest_path: Path) -> dict:
    if os.name != "posix":
        raise ValueError("Linux Buildroot target required")
    if root.is_symlink() or manifest_path.is_symlink():
        raise ValueError("direct Buildroot root and manifest required")
    root, manifest_path = root.resolve(strict=True), manifest_path.resolve(strict=True)
    manifest_info = manifest_path.lstat()
    if (
        not stat.S_ISDIR(root.lstat().st_mode)
        or not stat.S_ISREG(manifest_info.st_mode)
        or manifest_info.st_nlink != 1
        or not 0 < manifest_info.st_size <= 1024 * 1024
    ):
        raise ValueError("direct target directory and bounded unique manifest required")
    original = manifest_path.read_bytes()
    manifest = json.loads(original)
    if (
        manifest.get("schema") != "dcentos.native_zynq_sd_build_inputs.v1"
        or manifest.get("board_target") not in TARGETS
        or root != Path(manifest["target_dir"])
        or manifest_path.parent != Path(manifest["job_root"])
    ):
        raise ValueError("exact manifest-owned fresh target required")
    expected_services = COMMON_SERVICES | (
        {"S12fpga_identity"} if manifest["board_target"].startswith("am2-") else set()
    )
    if set(manifest["services"]) != expected_services or len(
        manifest["services"]
    ) != len(expected_services):
        raise ValueError("exact native target service contract required")
    if (
        root.parent != manifest_path.parent / "buildroot-output"
        or root.name != "target"
    ):
        raise ValueError("target must remain inside the selected private build output")
    receipt = manifest_path.parent / "root-finalization.json"
    if receipt.exists() or receipt.is_symlink():
        raise ValueError("preserve previous root finalization; prepare a new build")
    verify_overlay(root, manifest)
    init_dir = member(root, "etc/init.d")
    if not stat.S_ISDIR(init_dir.lstat().st_mode):
        raise ValueError("direct init directory required")
    allowed = set(manifest["services"]) | {"rcS", "rcK"}
    present = {path.name: path for path in init_dir.iterdir()}
    if not allowed <= set(present):
        raise ValueError("required complete native service set is absent")
    generated_startup = startup_snapshot(root, allowed, manifest["overlay"])
    removals = []
    for name, path in present.items():
        if name not in allowed:
            if not stat.S_ISREG(path.lstat().st_mode) and not path.is_symlink():
                raise ValueError("unexpected non-file startup entry")
            removals.append(path)
    daemon = member(root, "usr/local/bin/dcentrald")
    alias = member(root, "usr/bin/dcentrald")
    if alias.exists() or alias.is_symlink():
        raise ValueError("unexpected pre-existing daemon alias in fresh base")
    shadow = member(root, "etc/shadow")
    shadow_info = shadow.lstat()
    if (
        not stat.S_ISREG(shadow_info.st_mode)
        or shadow_info.st_nlink != 1
        or not 0 < shadow_info.st_size <= 16384
    ):
        raise ValueError("direct unique root credential file required")
    shadow_raw = shadow.read_bytes()
    if not 0 < len(shadow_raw) <= 16384:
        raise ValueError("bounded root credential file required")
    rows = [
        line.split(":")
        for line in shadow_raw.decode().splitlines()
        if line.startswith("root:")
    ]
    if len(rows) != 1 or len(rows[0]) != 9 or rows[0][1] not in ("*", "!", "!*", "!!"):
        raise ValueError(
            "root password must already be locked by Buildroot configuration"
        )
    for name in (
        "usr/libexec/dcentos/dcentos-deploy-lock",
        "usr/libexec/dcentos/dcentos-deploy-path",
        "usr/sbin/seed-entropy",
        "bin/busybox",
    ):
        path = member(root, name)
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or not info.st_mode & 0o111
            or path.read_bytes()[:4] != b"\x7fELF"
        ):
            raise ValueError("required compiled startup dependency absent: " + name)
    for name in (
        "data/dcentrald",
        "data/dcentrald.toml",
        "data/dcentrald-experimental.toml",
        "etc/dcentos/external-media-ephemeral-root",
        "etc/dcentos/first-boot-grace",
        "usr/sbin/sysupgrade",
        "usr/sbin/fw_setenv",
        "usr/sbin/nandwrite",
    ):
        path = member(root, name)
        if path.exists() or path.is_symlink():
            raise ValueError(
                "foreign persistent or NAND control in fresh native SD root: " + name
            )
    if manifest_path.read_bytes() != original:
        raise ValueError("build input manifest changed before root finalization")
    for path in removals:
        path.unlink()
    for name, expected in manifest["overlay"].items():
        member(root, name).chmod(expected["mode"])
    os.link(daemon, alias)
    shadow.chmod(0o600)
    verify_overlay(root, manifest, final=True)
    if startup_snapshot(root, allowed, manifest["overlay"]) != generated_startup:
        raise ValueError("generated startup files changed during finalization")
    final_shadow = shadow.lstat()
    if (
        not stat.S_ISREG(final_shadow.st_mode)
        or final_shadow.st_nlink != 1
        or (final_shadow.st_dev, final_shadow.st_ino)
        != (shadow_info.st_dev, shadow_info.st_ino)
        or stat.S_IMODE(final_shadow.st_mode) != 0o600
        or shadow.read_bytes() != shadow_raw
    ):
        raise ValueError("root credential final identity/content/mode differs")
    left, right = daemon.stat(), alias.stat()
    if (left.st_dev, left.st_ino, left.st_nlink) != (right.st_dev, right.st_ino, 2):
        raise ValueError("canonical daemon paths must share exactly two links")
    if {
        p.name for p in init_dir.iterdir()
    } != allowed or manifest_path.read_bytes() != original:
        raise ValueError("final startup or input manifest readback differs")
    # Final executable bytes are now fixed (including the deliberate two-name
    # hardlink). Bind them before Buildroot creates the rootfs archive.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from runtime_image_manifest import prepare
    from provision_runtime_policy import provision
    provision(root)
    signing_key = os.environ.get("DCENT_RELEASE_SIGNING_KEY")
    public_key = os.environ.get("DCENT_RELEASE_PUBKEY_FILE")
    if not signing_key or not public_key:
        raise ValueError("native beta root requires signing key and trusted public key")
    prepare(root, manifest["board_target"], os.environ.get("DCENT_RELEASE_CHANNEL", "beta"),
            member(root, "etc/dcentos-version").read_text().strip(), Path(signing_key), Path(public_key),
            os.environ.get("DCENT_RELEASE_HARDWARE_RECIPE", "board-default"))
    result = {
        "schema": "dcentos.native_zynq_sd_root_finalization.v1",
        "board_target": manifest["board_target"],
        "target_dir": str(root),
        "input_manifest_sha256": hashlib.sha256(original).hexdigest(),
        "overlay": manifest["overlay"],
        "services": sorted(allowed),
        "removed_generated_services": sorted(p.name for p in removals),
        "daemon_links": 2,
        "root_password_locked": True,
        "root_credential_sha256": hashlib.sha256(shadow_raw).hexdigest(),
        "generated_startup": generated_startup,
        "scope": "fresh host root files only; image/content/boot validation remains separate",
    }
    with receipt.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(
        json.dumps(
            {
                "board_target": manifest["board_target"],
                "verified_overlay_members": len(manifest["overlay"]),
                "services": len(allowed),
            }
        )
    )
    return result


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: finalize_root.py TARGET INPUT_MANIFEST")
    finalize(Path(sys.argv[1]), Path(sys.argv[2]))
