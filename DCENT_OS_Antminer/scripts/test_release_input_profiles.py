#!/usr/bin/env python3
"""Current producers require exact packaging inputs and native hook ordering."""
from pathlib import Path
import tempfile
import unittest

import held_assets
import release_build_config
import release_producer
import source_closure


class InputProfilesTests(unittest.TestCase):
    def test_every_current_producer_has_an_explicit_complete_recipe(self):
        project = Path(__file__).resolve().parents[3]
        for row in release_producer.list_producers():
            with self.subTest(producer=row.producer):
                self.assertEqual(row.input_profile, row.build_target)
                self.assertIn(row.build_target, source_closure.TARGET_BUILD_INPUTS)
                self.assertNotIn(row.build_target, source_closure.BLOCKED_BUILD_INPUT_TARGETS)
                self.assertEqual(source_closure.PREBUILT_RUST_VARIANT_BY_TARGET[row.build_target], row.cargo_variant)
                for config in source_closure.BUILD_TARGET_POLICIES[row.build_target]["configs"]:
                    self.assertTrue((project / config).is_file(), config)
                binaries = source_closure.PREBUILT_RUST_INPUTS_BY_TARGET[row.build_target]
                self.assertIn("dcentrald", binaries)
                if row.artifact_kind == "native-sd-image":
                    self.assertEqual(set(binaries), {"dcentrald", "dcentos-init", "dcentos-discovery"})

    def test_bb_payload_does_not_unblock_historical_boot_media(self):
        row = release_producer.get_producer("am3-bb-s19jpro")
        self.assertEqual(row.artifact_kind, "sd-payload-tar")
        self.assertEqual(row.install_route, "operator_staged")
        self.assertEqual(source_closure.TARGET_BUILD_INPUTS[row.build_target], ())
        for target in ("am3-bb", "am3-bb-s19jpro", "am3-bb-s19jpro-vnish"):
            self.assertIn(target, source_closure.BLOCKED_BUILD_INPUT_TARGETS)

    def test_nopic_recipe_cannot_substitute_older_donor_or_become_beta(self):
        inputs = source_closure.TARGET_BUILD_INPUTS["am3-s19kpro-nopic"]
        self.assertTrue(all("vnish-1.2.7-s19kpro-aml" in path for path in inputs))
        self.assertNotIn("am3-s19kpro-nopic", {row.board_target for row in release_producer.list_producers()})

    def test_native_hooks_follow_existing_base_and_replace_image_hook(self):
        text = ('BR2_ROOTFS_POST_BUILD_SCRIPT="base-sign.sh"\n'
                'BR2_ROOTFS_POST_IMAGE_SCRIPT="old-sysupgrade.sh"\n')
        result = release_build_config.configure(text, "am1-s9i")
        self.assertIn('BR2_ROOTFS_POST_BUILD_SCRIPT="base-sign.sh $(BR2_EXTERNAL_DCENTOS_PATH)/../scripts/release_native_sd_post_build.sh"', result)
        self.assertTrue(result.endswith('BR2_ROOTFS_POST_IMAGE_SCRIPT="$(BR2_EXTERNAL_DCENTOS_PATH)/../scripts/release_native_sd_post_image.sh"\n'))
        with self.assertRaises(ValueError):
            release_build_config.configure(result, "am1-s9i")

    def test_native_requires_existing_base_post_build(self):
        with self.assertRaises(ValueError):
            release_build_config.configure("BR2_arm=y\n", "am1-s15")
        self.assertEqual(release_build_config.configure("BR2_arm=y\n", "s9"), "BR2_arm=y\n")

    def test_t17e_retains_signed_carrier_and_uses_its_own_ext2_composer(self):
        text = 'BR2_ROOTFS_POST_BUILD_SCRIPT="base-sign.sh"\n'
        result = release_build_config.configure(text, "am2-t17e")
        self.assertIn(text, result)
        self.assertIn("release_bm1396_post_image.sh", result)
        self.assertNotIn("release_native_sd_post_build.sh", result)
        self.assertNotIn("release_native_sd_post_image.sh", result)
        self.assertEqual(source_closure.TARGET_BUILD_INPUTS["am2-t17e"], source_closure.BM1396_NATIVE_INPUTS)
        self.assertNotIn(source_closure.AM2_S17_DONOR_RELATIVE_PATH, source_closure.BM1396_NATIVE_INPUTS)
        with self.assertRaises(ValueError):
            release_build_config.configure(result, "am2-t17e")

    def test_s17e_has_its_own_exact_source_profile_and_composer(self):
        text = 'BR2_ROOTFS_POST_BUILD_SCRIPT="base-sign.sh"\n'
        result = release_build_config.configure(text, "am2-s17e")
        self.assertIn(text, result)
        self.assertIn("release_bm1396_post_image.sh", result)
        self.assertNotIn("release_native_sd_post_build.sh", result)
        selected = source_closure.TARGET_BUILD_INPUTS["am2-s17e"]
        self.assertEqual(selected, source_closure.BM1396_S17E_NATIVE_INPUTS)
        self.assertEqual(len(selected), 3)
        self.assertTrue(all("/s17e-om-20210108/fw/" in path for path in selected))
        self.assertTrue(set(selected).isdisjoint(source_closure.BM1396_NATIVE_INPUTS))
        row = release_producer.get_producer("am2-s17e")
        sibling = release_producer.get_producer("am2-t17e")
        self.assertEqual(row.runtime_root, "partition2-ext2")
        self.assertNotEqual(row.release_stem, sibling.release_stem)
        for target in ("am2-s17e-other", "am2-S17e", "s17e"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                release_build_config.configure(text, target)

    def test_held_override_requires_absolute_existing_directory(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.assertEqual(held_assets.held_root(root, str(root)), root)
            for value in ("relative", str(root / "missing")):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    held_assets.held_root(root, value)

    def test_input_mapping_cannot_escape_explicit_asset_root(self):
        for path in ("../outside", "", "/outside", "", "D:/x"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                held_assets.input_location(Path("repo"), path, Path("held"))
        self.assertEqual(held_assets.input_location(Path("repo"), "", Path("held")),
                         (Path("held"), "extractions/x"))


if __name__ == "__main__":
    unittest.main()
