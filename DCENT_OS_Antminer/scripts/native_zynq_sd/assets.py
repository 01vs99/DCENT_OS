"""Source-bound assets for the exact seven native28 Zynq SD compositions.

This builds regular-file data in memory. It does not mount, start a service,
change a base root, or grant NAND or physical boot authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat

try:
    import tomllib
except ImportError:
    import tomli as tomllib

from .profiles import NATIVE, profile

ZYNQ = "DCENT_OS_Antminer/br2_external_dcentos/board/zynq/rootfs-overlay/"
COMMON = "DCENT_OS_Antminer/br2_external_dcentos/board/common/rootfs-overlay/"
OWN = "DCENT_OS_Antminer/br2_external_dcentos/board/zynq/native-sd/rootfs-overlay/"
CONFIGS = "DCENT_OS_Antminer/dcentrald/configs/"

# Buildroot produces these four scripts. The completed base receipt must bind
# their exact bytes and every interpreter/library they require separately.
BASE_SERVICES = ("S01syslogd", "S02klogd", "S02sysctl", "S10udevd")
SOURCE_SERVICES = (
    "S40network",
    "S41ntp",
    "S43logrotate",
    "S50dropbear",
    "S80dashboard",
    "S82dcentrald",
)
OWN_SERVICES = ("S45persistent", "S70dcentos-discovery")
COMMON_HELPERS = (
    "dcentrald-session-latch.sh",
    "dcentrald-process-identity.sh",
    "dcentrald-fan-custody.sh",
    "dcentrald-deploy-recovery.sh",
    "dcentrald-firstlight-config.sh",
)


@dataclass(frozen=True)
class Asset:
    content: bytes
    mode: int
    source: str | None = None
    source_sha256: str | None = None


def read_source(path: Path, limit: int = 32 * 1024 * 1024) -> bytes:
    """Read a direct unique regular file with before/open/after identity joins."""
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or not 0 < before.st_size <= limit
    ):
        raise ValueError("bounded direct unique regular source required: " + str(path))
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)

        def identity(value, include_ctime=True):
            return (
                value.st_dev,
                value.st_ino,
                value.st_mode,
                value.st_nlink,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns if include_ctime else None,
            )

        # Windows Python can expose creation time through path.stat while
        # fstat reports another ctime value. Compare common identity across
        # interfaces and retain each interface's own ctime through the read.
        if identity(opened, False) != identity(before, False):
            raise ValueError("source replaced before read")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        if (
            len(raw) != before.st_size
            or identity(os.fstat(fd)) != identity(opened)
            or identity(path.lstat()) != identity(before)
        ):
            raise ValueError("source changed during read")
        return raw
    finally:
        os.close(fd)


def normalized_asset(root: Path, name: str, mode: int) -> Asset:
    raw = read_source(root / name)
    normalized = raw.replace(b"\r\n", b"\n")
    if b"\r" in normalized or b"\0" in normalized:
        raise ValueError("source text contains unsupported carriage return or NUL")
    normalized.decode("utf-8")
    return Asset(normalized, mode, name, hashlib.sha256(raw).hexdigest())


def render_config(root: Path, target: str) -> Asset:
    selected = profile(target)
    if selected["board_family"] == "am1":
        source = CONFIGS + "beta/" + target + "-baked-default.toml"
    elif target == "am2-s19pro":
        source = CONFIGS + "dcentrald_s19pro_am2_baked_default.toml"
    else:
        source = CONFIGS + "dcentrald_s17pro_am2_baked_default.toml"
    return _render_config(root, target, selected, source)


def _render_config(root: Path, target: str, selected: dict, source: str) -> Asset:
    """Render a caller-admitted exact source profile; no target selection here."""
    asset = normalized_asset(root, source, 0o644)
    text = asset.content.decode()
    # Preserve the qualified base policy; only exact variant identity changes.
    if target in {"am2-s17plus", "am2-t17", "am2-t17plus"}:
        model = {"am2-s17plus": "s17+", "am2-t17": "t17", "am2-t17plus": "t17+"}[target]
        section = ""
        counts = {"model": 0, "serial_chip_count": 0}
        rows = []
        for row in text.splitlines():
            if row.strip().startswith("["):
                section = row.strip()
            if section == "[mining]" and "=" in row:
                key = row.split("=", 1)[0].strip()
                if key in counts:
                    counts[key] += 1
                    row = (
                        f'model = "{model}"'
                        if key == "model"
                        else f"serial_chip_count = {selected['chips_per_chain']}"
                    )
            rows.append(row)
        if set(counts.values()) != {1}:
            raise ValueError(
                "exact single qualified model and chip-count fields required"
            )
        text = "\n".join(rows) + "\n"
    decoded = tomllib.loads(text)
    mining = decoded["mining"]
    expected_model = {"am2-s17plus": "s17+", "am2-t17plus": "t17+"}.get(
        target, selected["model"]
    )
    if (
        mining["enabled"] is not False
        or mining["model"] != expected_model
        or decoded["pool"]["url"]
    ):
        raise ValueError("exact idle-first native model and empty pool required")
    if selected["board_family"] == "am2" and (
        type(mining["serial_chip_count"]) is not int
        or mining["serial_chip_count"] != selected["chips_per_chain"]
    ):
        raise ValueError("exact native chip geometry required")
    if (
        decoded["api"]["http_port"] != 8080
        or decoded["api"].get("cgminer_bind_lan") is not True
        or decoded["api"].get("cgminer_lan_writes") is not False
    ):
        raise ValueError("qualified read-only LAN API binding required")
    return Asset(text.encode(), asset.mode, asset.source, asset.source_sha256)


def render_supervisor(root: Path, target: str) -> Asset:
    """Keep the reviewed image daemon when a previous data snapshot is retained."""
    profile(target)
    return _render_supervisor(root)


def _render_supervisor(root: Path) -> Asset:
    asset = normalized_asset(root, ZYNQ + "etc/init.d/S82dcentrald", 0o755)
    old = (
        "    if [ -x /data/dcentrald ]; then\n"
        '        DAEMON="/data/dcentrald"\n'
        "    else\n"
        '        DAEMON="/usr/local/bin/dcentrald"\n'
        "    fi\n"
    )
    text = asset.content.decode()
    if text.count(old) != 1:
        raise ValueError("exact single current supervisor runtime selector required")
    replacement = (
        "    # The SD root owns the reviewed native runtime across image updates.\n"
        "    # Retained operator configuration still uses the selection below.\n"
        '    DAEMON="/usr/local/bin/dcentrald"\n'
    )
    return Asset(
        text.replace(old, replacement, 1).encode(),
        asset.mode,
        asset.source,
        asset.source_sha256,
    )


def source_assets(root: Path, target: str) -> dict[str, Asset]:
    selected = profile(target)
    return _source_assets(root, target, selected, render_config(root, target))


def _source_assets(root: Path, target: str, selected: dict, config: Asset) -> dict[str, Asset]:
    """Common file rendering after an entry point has admitted its target."""
    assets = {"etc/dcentrald.toml": config}
    for service in SOURCE_SERVICES:
        name = "etc/init.d/" + service
        assets[name] = (
            _render_supervisor(root)
            if service == "S82dcentrald"
            else normalized_asset(root, ZYNQ + name, 0o755)
        )
    for service in OWN_SERVICES:
        name = "etc/init.d/" + service
        assets[name] = normalized_asset(root, OWN + name, 0o755)
    for name in (
        "etc/dcentos-early-init.sh",
        "usr/libexec/dcentos/native-zynq-sd-storage.py",
        "usr/libexec/dcentos/native-zynq-sd-ssh.py",
    ):
        assets[name] = normalized_asset(root, OWN + name, 0o755)
    for helper in COMMON_HELPERS:
        name = "usr/libexec/dcentos/" + helper
        assets[name] = normalized_asset(root, COMMON + name, 0o755)
    for name in (
        "root/web/server.py",
        "root/web/ip_reporter.py",
        "usr/sbin/dcent-enable-ssh",
    ):
        assets[name] = normalized_asset(root, ZYNQ + name, 0o755)
    for name in ("etc/default/dropbear", "etc/default/dcentos-compat"):
        assets[name] = normalized_asset(root, ZYNQ + name, 0o644)
    if selected["board_family"] == "am2":
        for name in (
            "etc/init.d/S12fpga_identity",
            "usr/libexec/dcentos/am2-fabric-identity.sh",
        ):
            assets[name] = normalized_asset(root, ZYNQ + name, 0o755)
    storage = {
        "schema": "dcentos.native_zynq_sd_storage.v1",
        **{
            name: selected[name]
            for name in (
                "board_target",
                "board_family",
                "platform",
                "root_source",
                "root_fstype",
                "data_device",
                "data_uuid",
                "data_bytes",
                "data_label",
            )
        },
        "data_start_sector": selected["partitions"][-1][0],
    }
    assets["etc/dcentos/native-zynq-sd.json"] = Asset(
        (json.dumps(storage, sort_keys=True, indent=2) + "\n").encode(), 0o644
    )
    for name, value in {
        "board_target": target,
        "platform": selected["platform"],
        "release-image": "1",
    }.items():
        assets["etc/dcentos/" + name] = Asset((value + "\n").encode(), 0o644)
    assets["etc/hostname"] = Asset(
        ("dcentos-" + target.split("-", 1)[1] + "\n").encode(), 0o644
    )
    return assets


def native_assets(directory: Path) -> dict[str, Asset]:
    result = {}
    for name, (size, digest) in NATIVE.items():
        raw = read_source(directory / name)
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("exact retained native28 executable required: " + name)
        destination = (
            "sbin/init"
            if name == "dcentos-init"
            else "usr/local/bin/dcentrald"
            if name == "dcentrald"
            else "usr/bin/dcentos-discovery"
        )
        result[destination] = Asset(raw, 0o755, name, digest)
        result["etc/dcentos/" + name + ".sha256"] = Asset(
            (digest + "\n").encode(), 0o644
        )
    # The producer must create usr/bin/dcentrald as a hard link to the canonical
    # local-bin inode, then the independent root decoder must prove exactly two.
    return result
