"""Current signed SD compositions; historical native28 admission stays frozen.

The four additional BM1398 profiles use the qualified AM2 controller boot
inputs and independent exact idle defaults from L07. This declares removable
media layout only; it grants neither NAND writes nor physical qualification.
"""
from pathlib import Path
from types import MappingProxyType
import uuid

from . import assets, boot_assets
from .profiles import TARGETS as HISTORICAL_TARGETS, profile as historical_profile

BM1398_TARGETS = MappingProxyType({
    "am2-s19": ("Antminer S19", "s19", 76),
    "am2-t19": ("Antminer T19", "t19", 76),
    "am2-s19a": ("Antminer S19a", "s19a", 72),
    "am2-s19plus": ("Antminer S19+", "s19plus", 80),
})
TARGETS = frozenset(HISTORICAL_TARGETS) | frozenset(BM1398_TARGETS)
# Captured AM2 payload ceiling, canonical scripts/lib/sysupgrade_zynq_geometry.sh.
# A size comparison does not grant a NAND route or inherit its physical geometry.
BM1398_ROOTFS_MAX_BYTES = 179 * 126976

# Exact shipped native owner defaults, not a range of operator tuning values.
# Tuple: model, chips, native MHz, native rail mV, generic PSU metadata mV.
# S19 Pro's generic PSU field remains 15200; its native PIC owner uses 12800.
BM1398_DEFAULTS = MappingProxyType({
    "am2-s19pro": ("s19pro", 114, 500, 12800, 15200),
    "am2-s19": ("s19", 76, 650, 13800, 13800),
    "am2-t19": ("t19", 76, 550, 14200, 14200),
    "am2-s19a": ("s19a", 72, 660, 12800, 12800),
    "am2-s19plus": ("s19plus", 80, 645, 14000, 14000),
})


def validate_bm1398_config(target: str, raw: bytes) -> None:
    """Require exact idle defaults before composing or assembling current media."""
    if target not in BM1398_DEFAULTS:
        raise ValueError("exact current BM1398 config target required")
    model, chips, mhz, rail, psu_metadata = BM1398_DEFAULTS[target]
    config = assets.tomllib.loads(raw.decode("utf-8"))
    expected = {
        "mining.model": model, "mining.serial_chip_type": "BM1398",
        "mining.serial_chip_count": chips, "mining.frequency_mhz": mhz,
        "mining.voltage_mv": rail, "mining.enabled": False,
        "mining.passthrough": False, "mining.am2_pll_ramp": False,
        "mining.am2_no_nonce_timeout_s": 90, "mining.skip_fifo_reset": False,
        "mining.skip_board_temp": False, "mining.version_rolling": False,
        "mining.serial_device": "/dev/ttyS1", "mining.fpga_chain_base": "0x43C00000",
        "mining.fpga_chain_id": 1, "pool.url": "", "pool.worker": "",
        "pool.protocol": "sv1", "power.psu_bypass": False,
        "power.psu_override.enabled": False, "psu.voltage_mv": psu_metadata,
        "psu.watchdog_enabled": True, "psu.heartbeat_hz": 1,
        "psu.i2c_address": 16, "psu.transport": "gpio_bitbang",
        "psu.pwr_control_gpio": "gpio:907", "watchdog.enabled": True,
        "watchdog.kick_interval_s": 5, "thermal.target_temp_c": 60,
        "thermal.hot_temp_c": 70, "thermal.dangerous_temp_c": 80,
        "thermal.fan_min_pwm": 10, "thermal.fan_max_pwm": 30,
        "thermal.supervisor.enabled": True, "thermal.supervisor.min_fans": 3,
        "autotuner.enabled": False, "hash_on_disconnect.enabled": False,
        "mode.active": "standard", "api.http_port": 8080,
        "api.cgminer_bind_lan": True, "api.cgminer_lan_writes": False,
        "api.metrics_require_auth": True,
    }
    for field, wanted in expected.items():
        value = config
        for key in field.split("."):
            value = value.get(key) if isinstance(value, dict) else None
        if type(value) is not type(wanted) or value != wanted:
            raise ValueError(f"exact BM1398 {target} default differs: {field}")


def check_rootfs_size(target: str, size: int) -> None:
    profile(target)
    if type(size) is not int or size <= 0:
        raise ValueError("positive exact native rootfs byte count required")
    if target in BM1398_TARGETS or target == "am2-s19pro":
        if size > BM1398_ROOTFS_MAX_BYTES:
            raise ValueError(f"BM1398 rootfs {size} bytes exceeds the 179-LEB AM2 payload ceiling ({BM1398_ROOTFS_MAX_BYTES} bytes)")


def profile(target: str) -> dict:
    if target not in BM1398_TARGETS:
        return historical_profile(target)
    label, model, chips = BM1398_TARGETS[target]
    return {
        "schema": "dcentos.native_zynq_release_profile.v1",
        "board_target": target, "label": label, "model": model,
        "board_family": "am2", "platform": "zynq-bm3-am2",
        "chips_per_chain": chips, "chain_count": 3,
        "root_source": "/dev/mmcblk0p2", "root_fstype": "squashfs",
        "data_device": "/dev/mmcblk0p3",
        "data_uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, "https://d-cent.local/native-sd/v1/" + target)),
        "data_bytes": 64 * 1024**2, "data_label": "DCENT_SD_DATA",
        "partitions": [(2048, 196608, 0x0c), (198656, 98304, 0x83), (296960, 131072, 0x83)],
        "image_bytes": 209 * 1024**2,
        "physical_qualification": "pending", "nand_writes": False,
    }


def source_assets(root: Path, target: str) -> dict[str, assets.Asset]:
    selected = profile(target)
    if target not in BM1398_TARGETS:
        plan = assets.source_assets(root, target)
        if target in BM1398_DEFAULTS:
            validate_bm1398_config(target, plan["etc/dcentrald.toml"].content)
        return plan
    source = assets.CONFIGS + "dcentrald_" + selected["model"] + "_am2_baked_default.toml"
    config = assets._render_config(root, target, selected, source)
    validate_bm1398_config(target, config.content)
    return assets._source_assets(root, target, selected, config)


def am2_boot_assets(target: str, inputs: dict[str, bytes]) -> dict[str, bytes]:
    if profile(target)["board_family"] != "am2":
        raise ValueError("exact current AM2 native release target required")
    return boot_assets._checked_am2_inputs(inputs)
