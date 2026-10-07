#!/usr/bin/env python3
"""Current-only BM1398 composition and independent consumer layout contracts."""
from pathlib import Path
import copy
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
SOURCE_ROOT = Path(os.environ.get("DCENT_CURRENT_SD_SOURCE_ROOT", ROOT))
sys.path.insert(0, str(ROOT / "projects/dcent-toolbox/src"))
from native_zynq_sd import assets, boot_assets, current_release, profiles  # noqa: E402
from dcent_toolbox.core import current_am2_sd_layout, current_native_release, zynq_native_sd_card  # noqa: E402
from release_producer import get_producer  # noqa: E402
import source_closure  # noqa: E402
import release_native_sd  # noqa: E402

spec = importlib.util.spec_from_file_location("current_storage", ROOT / (assets.OWN + "usr/libexec/dcentos/native-zynq-sd-storage.py"))
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)

# Review-owned mutation roster, independent of either policy implementation.
CONFIG_FIELDS = (
    "mining.model mining.serial_chip_type mining.serial_chip_count mining.frequency_mhz "
    "mining.voltage_mv mining.enabled mining.passthrough mining.am2_pll_ramp "
    "mining.am2_no_nonce_timeout_s mining.skip_fifo_reset mining.skip_board_temp "
    "mining.version_rolling mining.serial_device mining.fpga_chain_base mining.fpga_chain_id "
    "pool.url pool.worker pool.protocol power.psu_bypass power.psu_override.enabled "
    "psu.voltage_mv psu.watchdog_enabled psu.heartbeat_hz psu.i2c_address psu.transport "
    "psu.pwr_control_gpio watchdog.enabled watchdog.kick_interval_s thermal.target_temp_c "
    "thermal.hot_temp_c thermal.dangerous_temp_c thermal.fan_min_pwm thermal.fan_max_pwm "
    "thermal.supervisor.enabled thermal.supervisor.min_fans autotuner.enabled "
    "hash_on_disconnect.enabled mode.active api.http_port api.cgminer_bind_lan api.cgminer_lan_writes "
    "api.metrics_require_auth"
).split()
EXACT_DEFAULTS = (
    ("am2-s19pro", "s19pro", 114, 500, 12800, 15200),
    ("am2-s19", "s19", 76, 650, 13800, 13800),
    ("am2-t19", "t19", 76, 550, 14200, 14200),
    ("am2-s19a", "s19a", 72, 660, 12800, 12800),
    ("am2-s19plus", "s19plus", 80, 645, 14000, 14000),
)


def config_source(model):
    return (SOURCE_ROOT / assets.CONFIGS / ("dcentrald_" + model + "_am2_baked_default.toml")).read_text(encoding="utf-8")


def mutate_field(source, path, replacement):
    section, key = path.rsplit(".", 1)
    pattern = rf"(?m)(^\[{re.escape(section)}\]\s*\n)(.*?)(?=^\[|\Z)"
    matches = list(re.finditer(pattern, source, re.S))
    if len(matches) != 1:
        raise AssertionError("fixture section is not unique: " + section)
    match = matches[0]
    changed, count = re.subn(rf"(?m)^{re.escape(key)} = .*\n", replacement, match[2])
    if count != 1:
        raise AssertionError("fixture field is not unique: " + path)
    return source[:match.start(2)] + changed + source[match.end(2):]


class RemainingRootChecks(Exception):
    pass


class ConfigRoot:
    """The real reader's root-policy boundary, stopping before unrelated ELF I/O."""
    def __init__(self, target, raw):
        self.values = {
            "etc/dcentos/board_target": (target + "\n").encode(),
            "etc/dcentos/board_family": b"am2\n",
            "etc/dcentos/platform": b"zynq-bm3-am2\n",
            "etc/dcentos-version": b"test\n", "etc/dcentos/release-image": b"1\n",
            "etc/dcentos/mutation_policy": b"boot-safeoff\ndaemon-hardware\n",
            "etc/dcentrald.toml": raw,
        }

    def read(self, name, _limit):
        if name == "etc/shadow":
            raise RemainingRootChecks
        return self.values[name]


def reader_config_boundary(target, raw):
    return current_native_release._root_policy(
        ConfigRoot(target, raw), target, "test",
        {"board_family": "am2", "platform": "zynq-bm3-am2"}, required_startup=())


class CurrentBm1398Tests(unittest.TestCase):
    def test_five_real_defaults_reach_both_current_policies(self):
        for target, model, chips, mhz, native_mv, generic_mv in EXACT_DEFAULTS:
            with self.subTest(target=target):
                raw = config_source(model).encode()
                decoded = assets.tomllib.loads(raw.decode())
                self.assertEqual(
                    tuple(decoded["mining"][name] for name in ("model", "serial_chip_count", "frequency_mhz", "voltage_mv")),
                    (model, chips, mhz, native_mv))
                self.assertEqual(decoded["psu"]["voltage_mv"], generic_mv)
                current_release.validate_bm1398_config(target, raw)
                current_am2_sd_layout.validate_bm1398_config(target, decoded)
                with self.assertRaises(RemainingRootChecks):
                    reader_config_boundary(target, raw)
                plan = current_release.source_assets(SOURCE_ROOT, target)
                self.assertEqual(plan["etc/dcentrald.toml"].content, raw)

    def test_each_required_default_refuses_changed_missing_and_wrong_toml_type(self):
        self.assertEqual(len(CONFIG_FIELDS), 42)
        for target, model, *_ in EXACT_DEFAULTS:
            source = config_source(model)
            decoded = assets.tomllib.loads(source)
            for path in CONFIG_FIELDS:
                section = decoded
                for key in path.split("."):
                    section = section[key]
                key = path.rsplit(".", 1)[1]
                changed = ("false" if section else "true") if type(section) is bool else (
                    str(section + 1) if type(section) is int else '"foreign-profile"')
                wrong_type = '"wrong-type"' if type(section) is not str else "123"
                for kind, line in (("changed", f"{key} = {changed}\n"),
                                   ("missing", ""), ("type", f"{key} = {wrong_type}\n")):
                    with self.subTest(target=target, field=path, mutation=kind):
                        raw = mutate_field(source, path, line).encode()
                        with self.assertRaises(ValueError):
                            current_release.validate_bm1398_config(target, raw)
                        with self.assertRaises(ValueError):
                            reader_config_boundary(target, raw)

    def test_sibling_configs_and_boolean_integer_aliases_are_not_exact_defaults(self):
        for target, model, *_ in EXACT_DEFAULTS:
            for other, sibling, *_ in EXACT_DEFAULTS:
                if target == other:
                    continue
                with self.subTest(target=target, sibling=other):
                    raw = config_source(sibling).encode()
                    with self.assertRaises(ValueError):
                        current_release.validate_bm1398_config(target, raw)
                    with self.assertRaises(ValueError):
                        reader_config_boundary(target, raw)
            raw = mutate_field(config_source(model), "psu.heartbeat_hz", "heartbeat_hz = true\n").encode()
            with self.assertRaises(ValueError):
                current_release.validate_bm1398_config(target, raw)
            with self.assertRaises(ValueError):
                reader_config_boundary(target, raw)
            malformed = copy.deepcopy(assets.tomllib.loads(config_source(model)))
            malformed["thermal"]["supervisor"] = True
            with self.assertRaises(ValueError):
                current_am2_sd_layout.validate_bm1398_config(target, malformed)
        for alias in ("am2-s19+", "s19pro", "am2-s19j", "am2-s19i"):
            with self.assertRaises(ValueError):
                current_release.validate_bm1398_config(alias, b"")
            with self.assertRaises(ValueError):
                current_am2_sd_layout.validate_bm1398_config(alias, {})

    def test_current_composer_and_assembler_recheck_config_before_output(self):
        original = assets.normalized_asset
        for target, model, *_ in EXACT_DEFAULTS:
            for field in ("mining.serial_chip_type", "thermal.supervisor.enabled"):
                key = field.rsplit(".", 1)[1]
                value = '"BM1362"' if field.startswith("mining") else "false"
                raw = mutate_field(config_source(model), field, f"{key} = {value}\n").encode()
                def source(root, name, mode):
                    asset = original(root, name, mode)
                    return assets.Asset(raw, mode, name, asset.source_sha256) if name.endswith(model + "_am2_baked_default.toml") else asset
                with self.subTest(target=target, field=field):
                    with patch.object(assets, "normalized_asset", side_effect=source):
                        with self.assertRaises(ValueError):
                            current_release.source_assets(SOURCE_ROOT, target)
                    with tempfile.TemporaryDirectory() as temporary:
                        base = Path(temporary)
                        root, images, boot = base / "root", base / "images", base / "boot"
                        (root / "etc").mkdir(parents=True)
                        boot.mkdir()
                        (root / "etc/dcentos-version").write_text("test\n")
                        (root / "etc/dcentrald.toml").write_bytes(raw)
                        # No signature or image qualification claimed here: isolate
                        # the real final-stage check after its existing verifier.
                        with patch.object(release_native_sd, "settings", return_value=(base / "key", base / "pub", "beta", "board-default")), patch.object(release_native_sd.runtime, "verify") as verified:
                            with self.assertRaises(ValueError):
                                release_native_sd.assemble(root, images, target, boot)
                            verified.assert_called_once()
                        self.assertFalse(images.exists())

    def test_exact_rootfs_budget_matches_captured_geometry_and_refuses_overflow(self):
        source = (ROOT / "DCENT_OS_Antminer/scripts/lib/sysupgrade_zynq_geometry.sh").read_text(encoding="utf-8")
        leb = int(re.search(r"(?m)^ZYNQ_UBI_LEB_SIZE_BYTES=(\d+)$", source)[1])
        count = int(re.search(r"(?m)^AM2_ZYNQ_ROOTFS_PACKAGE_LEBS=(\d+)$", source)[1])
        maximum = leb * count
        self.assertEqual((leb, count), (126976, 179))
        self.assertEqual(current_release.BM1398_ROOTFS_MAX_BYTES, maximum)
        self.assertEqual(current_am2_sd_layout.BM1398_ROOTFS_MAX_BYTES, maximum)
        for target in (*current_am2_sd_layout.TARGETS, "am2-s19pro"):
            current_release.check_rootfs_size(target, maximum)
            with self.assertRaisesRegex(ValueError, "179-LEB"):
                current_release.check_rootfs_size(target, maximum + 1)
        for invalid in (0, -1, True, "22728704"):
            with self.assertRaises(ValueError):
                current_release.check_rootfs_size("am2-s19a", invalid)

    def test_actual_new_model_configs_and_source_assets_match_runtime_storage_reader(self):
        for target in current_am2_sd_layout.TARGETS:
            with self.subTest(target=target):
                plan = current_release.source_assets(SOURCE_ROOT, target)
                observed = storage.profile_from_bytes(plan["etc/dcentos/native-zynq-sd.json"].content)
                self.assertEqual(observed["board_target"], target)
                self.assertEqual(plan["etc/dcentos/board_target"].content, (target + "\n").encode())
                config = assets.tomllib.loads(plan["etc/dcentrald.toml"].content.decode())
                self.assertEqual(config["mining"]["model"], current_release.profile(target)["model"])
                self.assertEqual(config["mining"]["serial_chip_type"], "BM1398")
                self.assertFalse(config["mining"]["enabled"])
                self.assertEqual(config["pool"]["url"], "")
                self.assertIn("etc/init.d/S12fpga_identity", plan)
                self.assertEqual(source_closure.TARGET_BUILD_INPUTS[target], (source_closure.AM2_S17_DONOR_RELATIVE_PATH,))
                self.assertEqual(source_closure.PREBUILT_RUST_INPUTS_BY_TARGET[target], ("dcentos-init", "dcentrald", "dcentos-discovery"))
                self.assertEqual(source_closure.PREBUILT_RUST_VARIANT_BY_TARGET[target], "zynq")

    def test_wrong_model_geometry_and_enabled_work_refused_before_other_assets(self):
        target = "am2-s19a"
        name = assets.CONFIGS + "dcentrald_s19a_am2_baked_default.toml"
        source = (SOURCE_ROOT / name).read_text(encoding="utf-8")
        for before, after in [('model = "s19a"', 'model = "s19"'), ('serial_chip_count = 72', 'serial_chip_count = 76'), ('[mining]\nenabled = false', '[mining]\nenabled = true')]:
            self.assertEqual(source.count(before), 1)
            with self.subTest(mutation=before), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                path = root / name
                path.parent.mkdir(parents=True)
                path.write_text(source.replace(before, after), encoding="utf-8")
                with self.assertRaises(ValueError):
                    current_release.source_assets(root, target)

    def test_all_four_exact_layouts_join_independent_current_reader(self):
        seen = set()
        for target, chips in (("am2-s19", 76), ("am2-t19", 76), ("am2-s19a", 72), ("am2-s19plus", 80)):
            with self.subTest(target=target):
                producer = get_producer(target)
                selected = current_release.profile(target)
                reader = current_am2_sd_layout.geometry(target)
                self.assertEqual(producer.board_target, target)
                self.assertEqual(producer.runtime_root, "partition2-squashfs")
                self.assertEqual(producer.install_route, "sd_trial_boot_only")
                self.assertEqual(selected["chips_per_chain"], chips)
                self.assertEqual(selected["chain_count"], 3)
                self.assertNotIn("native_checkpoint", selected)
                self.assertFalse(selected["nand_writes"])
                self.assertEqual(selected["physical_qualification"], "pending")
                for field in ("partitions", "data_uuid", "image_bytes"):
                    self.assertEqual(selected[field], reader[field])
                self.assertEqual(reader["data_offset"], selected["partitions"][-1][0] * 512)
                self.assertEqual(reader["image_bytes"], sum(selected["partitions"][-1][:2]) * 512)
                self.assertIn(target, current_native_release.TARGETS)
                seen.add(reader["data_uuid"])
        self.assertEqual(len(seen), 4)

    def test_historical_checkpoint_producers_and_readers_still_refuse_new_models(self):
        self.assertEqual(len(profiles.TARGETS), 7)
        self.assertEqual(len(zynq_native_sd_card.ROOTS), 7)
        for target in current_am2_sd_layout.TARGETS:
            for call in (profiles.profile, zynq_native_sd_card.geometry):
                with self.assertRaises(ValueError):
                    call(target)
            # Both gates must refuse before consuming any source or boot bytes.
            with self.assertRaises(ValueError):
                assets.source_assets(ROOT / "absent", target)
            with self.assertRaises(ValueError):
                boot_assets.am2_boot_assets(target, {})

    def test_current_entry_points_refuse_aliases_missing_boot_and_unsupported_models(self):
        for target in ("am2-s19+", "am2-s19-plus", "am2-s19i", "am2-s19a-prototype", "AM2-S19", "s19"):
            with self.assertRaises(ValueError):
                current_release.profile(target)
            with self.assertRaises(ValueError):
                current_am2_sd_layout.geometry(target)
        for target in current_am2_sd_layout.TARGETS:
            with self.assertRaisesRegex(ValueError, "exact AM2 boot input set"):
                current_release.am2_boot_assets(target, {})
            corrupted = {name: b"wrong input" for name in boot_assets.AM2_BOOT_PINS}
            with self.assertRaises(ValueError):
                current_release.am2_boot_assets(target, corrupted)


if __name__ == "__main__":
    unittest.main()
