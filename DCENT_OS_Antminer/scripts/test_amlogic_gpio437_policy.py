#!/usr/bin/env python3
"""Offline tests for the exact-target GPIO437 authority and generated helper."""

import copy
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import generate_amlogic_gpio437 as policy


def fixture(vendors=("braiins", "vnish"), levels=((0, 1), (0, 1))):
    sources = {}
    evidence = []
    for index, (vendor, pair) in enumerate(zip(vendors, levels)):
        source = f"source-{index}"
        sources[source] = {
            "vendor": vendor,
            "artifact": f"synthetic-fixture-{index}",
            "sha256": f"{index:064x}",
        }
        evidence.append({
            "board_target": "am3-test-exact",
            "hashboard_names": ["TEST01"],
            "source": source,
            "kind": "complete-model-trace",
            "on_raw": pair[0],
            "off_raw": pair[1],
            "model_join": "synthetic exact model/controller binding",
            "trace": "synthetic complete enable and disable paths",
        })
    return {
        "schema": "dcentos.amlogic-gpio437/v1",
        "gpio": 437,
        "sources": sources,
        "profiles": [{"board_target": "am3-test-exact", "hashboard_names": ["TEST01"], "note": "Synthetic only", "evidence": evidence}],
    }


def decide(value):
    policy.validate(value)
    return policy.decision(value["profiles"][0], value["sources"])


class PolicyTests(unittest.TestCase):
    def test_generated_artifacts_are_current_and_lf(self):
        value = policy.load_policy()
        for path, expected in ((policy.RUST, policy.rust_text(value)), (policy.SHELL, policy.shell_text(value)), (policy.SHELL_COMMON, policy.shell_text(value))):
            self.assertEqual(path.read_bytes(), expected.encode("utf-8"))
            self.assertNotIn(b"\r", path.read_bytes())

    def test_distinct_complete_vendors_qualify_both_polarities(self):
        for pair in ((0, 1), (1, 0)):
            with self.subTest(pair=pair):
                self.assertEqual(decide(fixture(levels=(pair, pair))), ("qualified", 2, pair))

    def test_one_vendor_and_repackaged_same_vendor_refuse(self):
        self.assertEqual(decide(fixture(("braiins",), ((0, 1),))), ("insufficient-independent-vendors", 1, None))
        self.assertEqual(decide(fixture(("vnish", "vnish"))), ("insufficient-independent-vendors", 1, None))

    def test_startup_backend_and_recorded_observations_do_not_qualify(self):
        for kind in ("startup-only", "shared-backend-only", "recorded-model-observation"):
            with self.subTest(kind=kind):
                value = fixture()
                value["profiles"][0]["evidence"][1]["kind"] = kind
                self.assertEqual(decide(value), ("insufficient-independent-vendors", 1, None))

    def test_complete_conflict_refuses_including_after_two_agree(self):
        self.assertEqual(decide(fixture(levels=((0, 1), (1, 0)))), ("conflicting-complete-traces", 2, None))
        value = fixture(("braiins", "vnish", "epic"), ((0, 1), (0, 1), (1, 0)))
        self.assertEqual(decide(value), ("conflicting-complete-traces", 3, None))
        value = fixture(("braiins", "braiins"), ((0, 1), (1, 0)))
        self.assertEqual(decide(value), ("conflicting-complete-traces", 1, None))

    def test_identical_artifact_cannot_be_relabeled_as_second_vendor(self):
        value = fixture()
        value["sources"]["source-1"]["sha256"] = value["sources"]["source-0"]["sha256"]
        with self.assertRaisesRegex(ValueError, "relabeled"):
            policy.validate(value)

    def test_malformed_evidence_and_wrong_target_are_rejected(self):
        for name, replacement in (
            ("board_target", "am3-test-sibling"), ("on_raw", 2),
            ("on_raw", True), ("off_raw", 0), ("off_raw", None),
            ("kind", "measured"), ("source", "absent"), ("model_join", ""),
        ):
            with self.subTest(name=name, replacement=replacement):
                value = fixture()
                value["profiles"][0]["evidence"][1][name] = replacement
                with self.assertRaises(ValueError):
                    policy.validate(value)

    def test_duplicate_targets_and_shell_metacharacters_are_rejected(self):
        value = fixture()
        value["profiles"].append(copy.deepcopy(value["profiles"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate target"):
            policy.validate(value)
        for target in ("am3-test-exact\n", "am3-test-$(touch forbidden)", "am2-s19j", "AM3-S21"):
            value = fixture()
            value["profiles"][0]["board_target"] = target
            with self.assertRaises(ValueError):
                policy.validate(value)

    def test_current_source_has_no_implicit_grandfathering(self):
        value = policy.load_policy()
        counts = {
            row["board_target"]: policy.decision(row, value["sources"])
            for row in value["profiles"]
        }
        self.assertEqual(len(counts), 11)
        for target in ("am3-s19xp", "am3-s19jxp", "am3-s19jproa", "am3-s19jproplus", "am3-s19k", "am3-s19kpro", "am3-aml-s19kpro", "am3-s21", "am3-s21pro", "am3-s21xp", "am3-s19jpro-aml"):
            self.assertEqual(counts[target], ("qualified", 2, (0, 1)))

    def test_classic_requires_both_exact_vendor_coverages(self):
        value = policy.load_policy()
        row = next(row for row in value["profiles"] if row["board_target"] == "am3-s19jpro-aml")
        self.assertEqual(row["hashboard_names"], ["BHB42601", "BHB42621", "BHB42641"])
        complete = [item for item in row["evidence"] if item["kind"] == "complete-model-trace"]
        self.assertEqual({value["sources"][item["source"]]["vendor"] for item in complete}, {"braiins", "epic"})
        for missing_vendor in ("braiins", "epic"):
            missing = copy.deepcopy(row)
            missing["evidence"] = [item for item in missing["evidence"] if value["sources"][item["source"]]["vendor"] != missing_vendor]
            self.assertEqual(policy.decision(missing, value["sources"]), ("insufficient-independent-vendors", 1, None))
            for name in row["hashboard_names"]:
                self.assertEqual(policy.decision(missing, value["sources"], name), ("insufficient-independent-vendors", 1, None))
        partial = copy.deepcopy(row)
        next(item for item in partial["evidence"] if item["source"] == "epic-amlogic-production-1-22-0")["hashboard_names"].remove("BHB42641")
        self.assertEqual(policy.decision(partial, value["sources"]), ("insufficient-independent-vendors", 1, None))
        self.assertEqual(policy.decision(partial, value["sources"], "BHB42641"), ("insufficient-independent-vendors", 1, None))
        self.assertEqual(policy.decision(partial, value["sources"], "BHB42601"), ("qualified", 2, (0, 1)))
        for name in ("BHB42612", "BHB42699", "BHB426", "bhb42641"):
            self.assertEqual(policy.decision(row, value["sources"], name), ("unknown-hashboard", 0, None))

    def test_partial_revision_proof_only_qualifies_exact_runtime_identity(self):
        value = fixture()
        row = value["profiles"][0]
        row["hashboard_names"].append("TEST02")
        row["evidence"][0]["hashboard_names"].append("TEST02")
        policy.validate(value)
        self.assertEqual(policy.decision(row, value["sources"]), ("insufficient-independent-vendors", 1, None))
        self.assertEqual(policy.decision(row, value["sources"], "TEST01"), ("qualified", 2, (0, 1)))
        self.assertEqual(policy.decision(row, value["sources"], "TEST02"), ("insufficient-independent-vendors", 1, None))
        self.assertEqual(policy.decision(row, value["sources"], "TEST03"), ("unknown-hashboard", 0, None))

    def test_revision_scope_cannot_name_unknown_or_duplicate_hardware(self):
        for names in ([], ["TEST03"], ["TEST01", "TEST01"]):
            value = fixture()
            value["profiles"][0]["evidence"][1]["hashboard_names"] = names
            with self.assertRaises(ValueError):
                policy.validate(value)


@unittest.skipUnless(shutil.which("sh"), "POSIX shell required; run this suite under WSL")
class ShellTests(unittest.TestCase):
    def invoke(self, value, target, function="dcent_gpio437_drive_levels"):
        policy.validate(value)
        env = dict(os.environ)
        env.update(DCENT_PSU_ACTIVE_LOW="1", DCENT_BOARD_TARGET="am3-test-exact")
        with tempfile.TemporaryDirectory(prefix="dcent-gpio437-policy-") as directory:
            helper = Path(directory) / "policy.sh"
            helper.write_bytes(policy.shell_text(value).encode("utf-8"))
            result = subprocess.run(
                ["sh", "-c", '. "$1"; "$2" "$3"', "test", str(helper), function, target],
                check=False, capture_output=True, text=True, env=env,
            )
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()), ["policy.sh"])
        self.assertEqual(result.stderr, "")
        return result.returncode, result.stdout

    def test_positive_fixture_and_opposite_polarity(self):
        self.assertEqual(self.invoke(fixture(), "am3-test-exact"), (0, "0 1 high\n"))
        self.assertEqual(self.invoke(fixture(levels=((1, 0), (1, 0))), "am3-test-exact"), (0, "1 0 low\n"))

    def test_known_unqualified_and_conflicting_rows_emit_no_drive_level(self):
        for value in (
            fixture(("braiins", "braiins")),
            fixture(("braiins", "vnish", "epic"), ((0, 1), (0, 1), (1, 0))),
        ):
            self.assertEqual(self.invoke(value, "am3-test-exact"), (1, ""))
            self.assertEqual(self.invoke(value, "am3-test-exact", "dcent_gpio437_policy_state"), (0, "undriven\n"))

    def test_unknown_target_never_emits_state_or_drive_levels(self):
        for target in ("", "am3-test-exact ", "am3-test-sibling", "am2-s19j", "$(touch forbidden)"):
            for function in ("dcent_gpio437_drive_levels", "dcent_gpio437_policy_state"):
                self.assertEqual(self.invoke(fixture(), target, function), (2, ""))

    def test_real_table_drives_only_fully_qualified_rows(self):
        value = policy.load_policy()
        for row in value["profiles"]:
            with self.subTest(target=row["board_target"]):
                _, _, levels = policy.decision(row, value["sources"])
                if levels is None:
                    self.assertEqual(self.invoke(value, row["board_target"]), (1, ""))
                    self.assertEqual(self.invoke(value, row["board_target"], "dcent_gpio437_policy_state"), (0, "undriven\n"))
                else:
                    self.assertEqual(self.invoke(value, row["board_target"]), (0, "0 1 high\n"))
                    self.assertEqual(self.invoke(value, row["board_target"], "dcent_gpio437_policy_state"), (0, "qualified-software\n"))


if __name__ == "__main__":
    unittest.main()
