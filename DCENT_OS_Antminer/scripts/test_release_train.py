#!/usr/bin/env python3
"""Tests for release_train.py (campaign Phase 0.7).

Run: py -3 -m pytest scripts/test_release_train.py -q   (from DCENT_OS_Antminer)

The suite never executes a real lane: run-mode behavior is exercised through
monkeypatched execution against temporary fixtures.
"""

from __future__ import annotations

import json
import importlib.util
import io
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from dataclasses import replace
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import release_train as train  # noqa: E402
import release_capsule_target_policy as capsule_policy  # noqa: E402
import runtime_image_manifest as runtime
import export_install_route_catalog as catalog


def toolbox_consumer():
    """Load the actual wheel consumer, not a permissive test-local imitation."""
    path = Path(train.DCENTOS_DIR).parent / "dcent-toolbox/src/dcent_toolbox/core/dcentos_install_matrix.py"
    spec = importlib.util.spec_from_file_location("train_test_toolbox_matrix", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BOARD_DESC_FIXTURE = '''
pub enum ReleaseChannel { Beta, Stable, Unsupported }

impl BoardDesc {
    pub const fn am1_s9() -> Self {
        Self {
            board_target: "am1-s9",
            enablement: AM1_S9_PUBLIC_UPDATE_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            mining_default_enabled: false,
        }
    }

    pub const fn am2_s17() -> Self {
        Self {
            board_target: "am2-s17p",
            enablement: ZYNQ_RUNTIME_ONLY_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            mining_default_enabled: false,
        }
    }

    pub const fn am2_s19jpro() -> Self {
        Self {
            board_target: "am2-s19j",
            enablement: AM2_PUBLIC_UPDATE_ENABLEMENT,
            release_channel: ReleaseChannel::Unsupported,
            mining_default_enabled: false,
        }
    }
}
'''


@unittest.skipUnless(os.name == "posix", "real shell adapter runs under Linux")
class NativeBm1391AdapterTests(unittest.TestCase):
    def run_adapter(self, target, donor=True):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shim = root / "sh"
            shim.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                "pathlib.Path(os.environ['DCENT_TEST_ARGV']).write_text(json.dumps(sys.argv[1:]))\n"
                "pathlib.Path(sys.argv[-1]).mkdir()\n",
                encoding="utf-8",
            )
            shim.chmod(0o755)
            captured = root / "argv.json"
            output = root / "image output"
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       DCENT_NATIVE_SD_ROOTFS="current root.squashfs",
                       DCENT_NATIVE_SD_BINARIES="current ARM binaries",
                       DCENT_TEST_ARGV=str(captured))
            env.pop("DCENT_BM1391_SD_DONOR", None)
            if donor:
                env["DCENT_BM1391_SD_DONOR"] = "exact " + target + " boot"
            result = subprocess.run(
                ["/bin/sh", str(Path(train.SCRIPT_DIR) / "build_native_am1_sd_beta.sh"),
                 target, str(output)], env=env, capture_output=True, text=True,
            )
            argv = json.loads(captured.read_text()) if captured.exists() else None
            guide = output / "TESTER_README.txt"
            return result, argv, guide.read_bytes() if guide.exists() else None

    def test_exact_bm1391_models_keep_explicit_inputs_and_canonical_guide(self):
        guide = Path(train.DCENTOS_DIR).parent / "dcent-toolbox/docs/BM1391_SD.md"
        for target in ("am1-s15", "am1-t15"):
            with self.subTest(target=target):
                result, argv, readme = self.run_adapter(target)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(Path(argv[0]).name, "build_sd_bm1391.sh")
                self.assertEqual(argv[1:5], [target, "exact " + target + " boot",
                                           "current root.squashfs", "current ARM binaries"])
                self.assertEqual(readme, guide.read_bytes())

    def test_missing_exact_donor_never_calls_an_image_builder(self):
        result, argv, guide = self.run_adapter("am1-s15", donor=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(argv)
        self.assertIsNone(guide)

    def test_unregistered_target_never_calls_an_image_builder(self):
        result, argv, guide = self.run_adapter("am1-s15-other")
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(argv)
        self.assertIsNone(guide)


class AdmissionParserTests(unittest.TestCase):
    def test_parses_rings_per_board_target(self):
        table = train.parse_install_admissions(BOARD_DESC_FIXTURE)
        self.assertEqual(
            table,
            {
                "am1-s9": "Beta",
                "am2-s17p": "Beta",
                "am2-s19j": "Unsupported",
            },
        )

    def test_real_board_desc_parses_and_matches_expected_rings(self):
        dcentos_dir = train.DCENTOS_DIR
        table = train.load_admissions(dcentos_dir)
        self.assertGreater(len(table), 20)
        self.assertEqual(table.get("am1-s9"), "Beta")
        self.assertEqual(table.get("am2-s17p"), "Beta")
        self.assertEqual(table.get("am2-s19j"), "Beta")

    def test_empty_source_refuses(self):
        with self.assertRaises(train.TrainError):
            train.parse_install_admissions("")

    def test_unknown_missing_and_duplicate_registry_channels_refuse(self):
        for source in (BOARD_DESC_FIXTURE.replace("ReleaseChannel::Beta", "ReleaseChannel::Lab"),
                       BOARD_DESC_FIXTURE.replace("release_channel:", "absent_channel:"),
                       BOARD_DESC_FIXTURE + BOARD_DESC_FIXTURE):
            with self.assertRaises(train.TrainError):
                train.parse_install_admissions(source)


class CatalogChannelTests(unittest.TestCase):
    def test_export_joins_channel_to_registry_preserving_media_routes(self):
        document = catalog.build_catalog()
        channels = train.load_admissions()
        self.assertEqual(len(document["routes"]), 30)
        for row in document["routes"]:
            self.assertEqual(row["channel"], channels[row["board_target"]].lower())

    @unittest.skipUnless(os.name == "posix", "WSL read-only Git fallback")
    def test_windows_linked_worktree_uses_windows_git_readonly(self):
        failure = subprocess.CalledProcessError(128, ["git"])
        success = subprocess.CompletedProcess(["git.exe"], 0, "a" * 40 + "\n", "")
        with patch.object(catalog.shutil, "which", return_value="git.exe"), patch.object(catalog.subprocess, "run", side_effect=[failure, success, failure, success, failure, success]) as run:
            self.assertEqual(catalog._source_git_head(train.DCENTOS_DIR), "a" * 40)
        self.assertEqual([call.args[0][0] for call in run.call_args_list], ["git", "git.exe", "git", "git.exe", "git", "git.exe"])


class TargetTableTests(unittest.TestCase):
    def setUp(self):
        self.admissions = train.load_admissions()

    def test_every_target_resolves_a_known_ring(self):
        for target in train.TARGETS:
            self.assertIn(
                target.board_target,
                self.admissions,
                f"{target.name}: board_target {target.board_target} not in registry",
            )

    def test_all_beta_rows_have_truthful_plan_slots(self):
        slots = train.drop_targets(1)
        beta = {board for board, channel in self.admissions.items() if channel == "Beta"}
        self.assertEqual(len(beta), 29)
        self.assertEqual({slot.board_target for slot in slots if self.admissions[slot.board_target] == "Beta"}, beta)
        executable = [slot for slot in slots if self.admissions[slot.board_target] == "Beta" and train.plan_target(slot, self.admissions).executable]
        self.assertEqual(len(executable), 29)
        missing = [slot for slot in slots if self.admissions[slot.board_target] == "Beta" and not slot.lane_command]
        self.assertEqual(missing, [])
        t17e = next(slot for slot in slots if slot.board_target == "am2-t17e")
        self.assertEqual(t17e.install_route, train.ROUTE_SD_TRIAL)
        self.assertEqual(t17e.lane_command[3], "am2-t17e")
        native = next(slot for slot in slots if slot.name == "am3-s19k")
        self.assertEqual(native.board_target, "am3-s19k")
        self.assertEqual(native.producer, "am3-s19k")
        self.assertEqual(native.lane_command[3], "am3-s19k")

    def test_route_ring_consistency_all_targets(self):
        for target in train.TARGETS:
            planned = train.plan_target(target, self.admissions)
            self.assertEqual(
                planned.issues,
                [],
                f"{target.name}: {planned.issues}",
            )

    def test_policy_targets_resolve_and_match_board(self):
        aliases = train.load_aliases()
        for target in train.TARGETS:
            if not target.policy_target:
                continue
            record = capsule_policy.policy_for(target.policy_target)
            canonical = train.canonical_board_target(record.package_board, aliases)
            self.assertEqual(
                canonical,
                target.board_target,
                f"{target.name}: policy package_board {record.package_board!r} "
                f"does not canonicalize to {target.board_target!r}",
            )

    def test_am3_s19kpro_slot_is_its_own_denied_row_never_published(self):
        # 2026-09-12 drift-13/R10 adjudication: the deployed S19k Pro NoPic
        # identity is a REGISTERED board_desc.rs row, not an alias fold onto
        # the guarded PIC-era `am3-s19k` key.  The train slot must resolve
        # through that exact Unsupported row and stay fail-closed: operator-staged
        # only, never a first-install/SD-trial publish slot, and its capsule
        # policy must never admit an outer publication lifecycle.
        slot = next(t for t in train.TARGETS if t.name == "am3-s19kpro")
        self.assertEqual(slot.board_target, "am3-s19kpro")
        self.assertNotIn(
            ("am3-s19kpro", "am3-s19k"),
            train.load_aliases().items(),
            "alias would shadow the registered am3-s19kpro row",
        )
        admissions = train.load_admissions()
        self.assertEqual(admissions.get(slot.board_target), "Unsupported")
        self.assertEqual(slot.install_route, train.ROUTE_OPERATOR_STAGED)
        self.assertNotIn(
            slot.install_route,
            (train.ROUTE_FIRST_INSTALL, train.ROUTE_SD_TRIAL),
        )
        record = capsule_policy.policy_for(slot.policy_target)
        self.assertEqual(record.package_board, "am3-s19kpro")
        self.assertFalse(record.publication_admitted)
        with self.assertRaises(capsule_policy.TargetPolicyError):
            capsule_policy.policy_for(slot.policy_target, require_publication=True)

    def test_first_install_route_requires_public_beta_ring(self):
        denied = replace(
            next(t for t in train.TARGETS if t.name == "s9"),
            board_target="am2-s19j",
        )
        planned = train.plan_target(denied, self.admissions)
        self.assertTrue(planned.hard_violation)

    def test_sd_trial_route_requires_publishable_channel(self):
        wrong_ring = replace(
            next(t for t in train.TARGETS if t.name == "s17-s17pro"),
            board_target="am3-s19kpro",
        )
        planned = train.plan_target(wrong_ring, self.admissions)
        self.assertTrue(planned.hard_violation)

    def test_denied_ring_never_occupies_a_publish_route(self):
        # A Unsupported ring may only sit on operator-staged or self-update-only
        # slots (both are kept out of the public publish tree).  A Unsupported
        # ring on a first-install or SD-trial slot is a hard violation.
        for target in train.TARGETS:
            if target.install_route not in (
                train.ROUTE_FIRST_INSTALL,
                train.ROUTE_SD_TRIAL,
            ):
                continue
            ring = self.admissions[target.board_target]
            self.assertNotEqual(
                ring,
                "Unsupported",
                f"{target.name} occupies a publish route with a Unsupported ring",
            )

    def test_pending_route_requires_blocked_reason(self):
        unblocked = replace(
            next(t for t in train.TARGETS if t.name == "am2-t17e"),
            install_route=train.ROUTE_PENDING, lane_command=(), producer=None, blocked_reason="",
        )
        planned = train.plan_target(unblocked, self.admissions)
        self.assertTrue(planned.hard_violation)

    def test_am2_lane_selects_its_release_target(self):
        am2 = next(t for t in train.TARGETS if t.name == "am2-s19jpro")
        self.assertEqual(am2.lane_command[2:4], ("--producer", "am2-s19jpro"))
        self.assertFalse(am2.blocked_reason, "am2 lane parameterization landed")

    def test_capsule_names_validate_through_frozen_policy(self):
        from release_train import _today

        for target in train.TARGETS:
            if not target.policy_target:
                continue
            name = train.validate_capsule_name(target.policy_target, _today())
            stem = capsule_policy.policy_for(target.policy_target).release_stem
            self.assertTrue(name.startswith(stem + "_beta"))

    def test_expected_artifact_globs_resolve(self):
        date = "20260901"
        for target in train.TARGETS:
            if not target.expected_artifact:
                continue
            glob = train.expected_artifact_glob(target, date)
            self.assertNotIn("{", glob, f"{target.name}: unresolved placeholder in {glob}")


class FundLinkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _write(self, name, text):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def test_tar_member_fund_link_found(self):
        tar_path = os.path.join(self.tmp, "capsule.tar")
        member = os.path.join(self.tmp, "README.md")
        self._write("README.md", "docs at https://d-central.tech/fund/ thanks")
        with tarfile.open(tar_path, "w") as tar:
            tar.add(member, arcname="README.md")
        ok, where = train.scan_fund_link(tar_path)
        self.assertTrue(ok)
        self.assertIn("README.md", where)

    def test_missing_fund_link_fails(self):
        tar_path = os.path.join(self.tmp, "capsule.tar")
        member = self._write("README.md", "no link here")
        with tarfile.open(tar_path, "w") as tar:
            tar.add(member, arcname="README.md")
        ok, _ = train.scan_fund_link(tar_path)
        self.assertFalse(ok)

    def test_sidecar_readme_satisfies_gate(self):
        img = self._write("image.img", "\0" * 64)
        self._write(
            "TESTER_README.txt",
            "DCENT_OS SD trial media.\nFund development: https://d-central.tech/fund/\n",
        )
        ok, where = train.scan_fund_link(img)
        self.assertTrue(ok)
        self.assertEqual(where, "sidecar TESTER_README.txt")

    def test_authenticated_release_metadata_ancillary_satisfies_bound_gate(self):
        # Shape documentation for the emitter fix: the fund URL inside the
        # signed .release.txt ancillary recorded in the result document
        # (drop1-20260922 latent: no emitter carried it, so the publication
        # gate failed all 12 tar lanes deterministically). The scanner here is
        # unchanged; the emitter-side guard is the static pin on the writer.
        self._write("capsule.tar", "\0" * 64)
        metadata = ("release_name=DCENTOS_S9_BETA_20260922\n"
                    "fund_url=https://d-central.tech/fund/\n")
        self._write("DCENTOS_S9_BETA_20260922.release.txt", metadata)
        document = {"files": {"primary": {"path": "capsule.tar"}},
                    "ancillary": [{"path": "DCENTOS_S9_BETA_20260922.release.txt",
                                   "size": len(metadata.encode())}]}
        ok, where = train.scan_result_fund_link(document, self.tmp)
        self.assertTrue(ok)
        self.assertEqual(where, "result ancillary DCENTOS_S9_BETA_20260922.release.txt")


class PublishStagingTests(unittest.TestCase):
    """Real signed packages and actual packaged-ELF verifier, never text stand-ins.

    The runner must hold the shared heavy lock for the one production ELF
    compilation in setUpClass. Every test reuses those immutable fixture bytes.
    """
    @classmethod
    def setUpClass(cls):
        from test_release_runtime_exports import package_fixture
        cls.shared_temporary = tempfile.TemporaryDirectory(prefix="dcent-train-package-")
        cls.addClassCleanup(cls.shared_temporary.cleanup)
        cls.fixture = package_fixture(Path(cls.shared_temporary.name) / "base")

    def setUp(self):
        import release_producer
        self.temporary = tempfile.TemporaryDirectory(prefix="dcent-train-publish-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.publish, self.staging = str(self.root / "publish"), str(self.root / "staging")
        self.output = self.root / "producer"
        self.output.mkdir()
        self.row = release_producer.get_producer("s9")
        self.artifact = self.output / self.row.primary_artifact
        for suffix in ("", ".sig", ".runtime-image.json", ".runtime-image.sig"):
            shutil.copyfile(str(self.fixture["artifact"]) + suffix, str(self.artifact) + suffix)
        (self.output / "TESTER_README.txt").write_text(train.FUND_URL + "\n", encoding="utf-8")
        self.key, self.pubkey = self.fixture["key"], self.fixture["pubkey"]
        environment = patch.dict(os.environ, DCENT_RELEASE_PUBKEY_FILE=str(self.pubkey), DCENT_RELEASE_SIGNING_KEY=str(self.key))
        environment.start()
        self.addCleanup(environment.stop)
        self.result = {"name": "s9", "board_target": "am1-s9", "channel": "beta", "version": "1.2.3",
                       "source_commit": "a" * 40, "hardware_recipe": "board-default",
                       "install_route": train.ROUTE_FIRST_INSTALL, "status": "built",
                       "fund_link": {"ok": True}, "producer_output_root": str(self.output),
                       "reproducibility": {"compared": True, "identical": True}}
        self.refresh()

    def refresh(self, ancillary=None):
        import release_producer
        ancillary = ["TESTER_README.txt"] if ancillary is None else ancillary
        signed = release_producer.create_result(
            self.output, self.row, "a" * 40, "1.2.3", "beta", self.artifact.name,
            ancillary)
        subject = self.output / "producer-result.json"
        subject.write_text(json.dumps(signed), encoding="utf-8")
        runtime.openssl("pkeyutl", "-sign", "-inkey", self.key, "-rawin", "-in", subject,
                        "-out", str(subject) + ".sig")
        self.result["producer_result"] = release_producer.create_result(
            self.output, self.row, "a" * 40, "1.2.3", "beta", self.artifact.name,
            ancillary + ["producer-result.json", "producer-result.json.sig"])
        record = self.result["producer_result"]["files"]["primary"]
        self.result["artifact"] = {"path": os.path.relpath(self.artifact, train.DCENTOS_DIR),
                                   "sha256": record["sha256"], "bytes": record["size"]}

    def publish_result(self):
        return train.stage_publish(self.result, self.publish, self.staging)

    def test_signed_actual_package_stages_every_bound_member_at_immutable_address(self):
        outcome = self.publish_result()
        self.assertTrue(outcome["staged"], outcome)
        destination = Path(train.DCENTOS_DIR) / outcome["path"]
        self.assertRegex(destination.parent.name, r"^[a-f0-9]{64}$")
        for record in outcome["files"]:
            self.assertEqual((Path(self.publish) / record["path"]).read_bytes(),
                             (self.output / Path(record["path"]).name).read_bytes())
        # Segment resume re-stages the same content address: complete staged
        # bytes are re-verified in place and reused unchanged.
        again = self.publish_result()
        self.assertTrue(again["staged"], again)
        self.assertEqual(again["files"], outcome["files"])
        # A tampered or partial staged directory is derived output, never
        # evidence: staging regenerates it from the still-verified capsule
        # originals and the healed bytes re-verify against the signed record.
        staged_member = Path(self.publish) / outcome["files"][0]["path"]
        original_member = staged_member.read_bytes()
        staged_member.write_bytes(original_member + b"tamper")
        healed = self.publish_result()
        self.assertTrue(healed["staged"], healed)
        self.assertEqual(staged_member.read_bytes(), original_member)
        staged_member.unlink()
        partial = self.publish_result()
        self.assertTrue(partial["staged"], partial)
        self.assertEqual(staged_member.read_bytes(), original_member)

    def test_only_bound_fund_link_members_count(self):
        self.refresh(ancillary=[])
        outcome = self.publish_result()
        self.assertFalse(outcome["staged"])
        self.assertIn("fund", outcome["reason"])

    def test_bm1391_board_publication_consults_native_media_gate(self):
        self.result["board_target"] = "am1-s15"
        self.result["producer_result"]["producer"] = "am1-s15"
        with patch.object(train, "verify_publication"), \
                patch.object(train, "validate_native_media_candidate", return_value={}) as gate:
            outcome = self.publish_result()
        self.assertTrue(outcome["staged"], outcome)
        gate.assert_called_once()
        self.assertEqual(gate.call_args[0][1].board_target, "am1-s15")

    def test_unsupported_or_wrong_board_and_wrong_route_are_refused(self):
        for field, value in (("board_target", "am3-s19kpro"), ("board_target", "am1-s9i"),
                             ("channel", "unsupported"), ("install_route", train.ROUTE_SD_TRIAL)):
            original = self.result[field]
            with self.subTest(field=field, value=value):
                self.result[field] = value
                self.assertFalse(self.publish_result()["staged"])
                self.result[field] = original

    def test_missing_each_signature_or_runtime_companion_is_refused(self):
        for suffix in (".sig", ".runtime-image.json", ".runtime-image.sig"):
            path = Path(str(self.artifact) + suffix)
            data = path.read_bytes()
            with self.subTest(suffix=suffix):
                path.unlink()
                self.assertFalse(self.publish_result()["staged"])
                path.write_bytes(data)

    def test_signed_arbitrary_payload_cannot_pass_as_a_runtime_image(self):
        self.artifact.write_bytes(b"arbitrary signed bytes with plausible sidecar")
        runtime.openssl("pkeyutl", "-sign", "-inkey", self.key, "-rawin", "-in", self.artifact,
                        "-out", str(self.artifact) + ".sig")
        self.refresh()
        self.assertFalse(self.publish_result()["staged"])

    def test_tampered_outer_signature_fails_even_with_refreshed_result_digest(self):
        Path(str(self.artifact) + ".sig").write_bytes(b"x" * 64)
        self.refresh()
        self.assertFalse(self.publish_result()["staged"])

    def test_changed_artifact_never_uses_earlier_verification(self):
        with self.artifact.open("ab") as stream:
            stream.write(b"changed")
        self.assertFalse(self.publish_result()["staged"])

    def test_result_cannot_select_another_file(self):
        self.result["artifact"]["path"] = str(self.output / "other.tar")
        self.assertFalse(self.publish_result()["staged"])

    def test_external_result_cannot_claim_a_different_source_commit(self):
        self.result["source_commit"] = "b" * 40
        self.result["producer_result"]["source_commit"] = "b" * 40
        outcome = self.publish_result()
        self.assertFalse(outcome["staged"])
        self.assertIn("signed producer identity", outcome["reason"])

    def test_unbuilt_target_cannot_stage(self):
        self.result["status"] = "blocked"
        self.assertFalse(self.publish_result()["staged"])

    def test_cohort_cli_verifies_exact_signed_members_and_refuses_different_selection(self):
        import release_producer
        document = dict(manifest_profile=release_producer.COHORT_PROFILE, cargo_variant="zynq",
                        source_commit="a" * 40, version="1.2.3", channel="beta",
                        results=[self.result["producer_result"]])
        path = self.root / "cohort.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        command = [sys.executable, str(Path(train.SCRIPT_DIR) / "release_producer.py"),
                   "verify-cohort-result", "--producer", "s9", "--source-commit", "a" * 40,
                   "--version", "1.2.3", "--channel", "beta", "--root", str(self.output),
                   "--result-json", str(path), "--pubkey", str(self.pubkey)]
        outcome = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertEqual(json.loads(outcome.stdout), document)
        command[command.index("s9")] = "am2-s19jpro"
        outcome = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(outcome.returncode, 0)
        self.assertEqual(outcome.stdout, "")

    def test_cumulative_manifest_has_verified_signature_and_immutable_member_urls(self):
        self.result["publish"] = self.publish_result()
        self.assertTrue(self.result["publish"]["staged"])
        target = next(target for target in train.TARGETS if target.name == "s9")
        path = self.root / "MANIFEST_DROP1.json"
        with patch.object(train, "load_admissions", return_value={"am1-s9": "Beta"}):
            train.write_manifest(str(path), 1, [self.result], "a" * 40, targets=[target],
                                 base_url="https://releases.example.test/dcentos", publish_root=self.publish)
        runtime.verify_signature(path, Path(str(path) + ".sig"), self.pubkey)
        document = json.loads(path.read_text())
        self.assertTrue(document["complete_selected_beta"])
        self.assertEqual(document["targets"][0]["release_channel"], "beta")
        for record in document["targets"][0]["files"]:
            self.assertIn("/beta/am1-s9/", record["url"])
            self.assertIn(record["path"], record["url"])
        path.write_bytes(path.read_bytes() + b"tamper")
        with self.assertRaises(ValueError):
            runtime.verify_signature(path, Path(str(path) + ".sig"), self.pubkey)

    def test_successful_second_process_without_result_cannot_reuse_first_artifact(self):
        import release_producer
        calls = []
        target = next(target for target in train.TARGETS if target.name == "s9")
        planned = train.plan_target(target, train.load_admissions())
        def execute(_target, _date, _scratch, _log, extra_args=()):
            calls.append(extra_args)
            if len(calls) == 1:
                root = Path(extra_args[extra_args.index("--output-root") + 1])
                root.mkdir(parents=True)
                for path in self.output.iterdir():
                    shutil.copyfile(path, root / path.name)
                result = release_producer.create_result(root, self.row, "a" * 40, "1.2.3", "beta",
                                                        self.artifact.name, ["TESTER_README.txt", "producer-result.json", "producer-result.json.sig"])
                group = dict(manifest_profile=release_producer.COHORT_PROFILE, cargo_variant="zynq",
                             source_commit="a" * 40, version="1.2.3", channel="beta", results=[result])
                Path(extra_args[extra_args.index("--result-json") + 1]).write_text(json.dumps(group), encoding="utf-8")
            return 0, "test-process.log"
        with patch.object(train, "_execute_lane", side_effect=execute), patch.object(train, "_git_head", return_value="a" * 40), patch.object(train, "workspace_version", return_value="1.2.3"):
            outcome = train.run_lane(planned, "20260913", str(self.root / "repro"), set(), with_repro=True)
        self.assertEqual(len(calls), 2)
        self.assertEqual(outcome["status"], "repro-mismatch")
        self.assertFalse(outcome["reproducibility"]["identical"])


class SegmentResumeTests(PublishStagingTests):
    """Segmented drops: sealed lanes persist, re-verify from disk, and only
    the missing lanes rebuild — with exactly one endgame over the merged set.
    """

    def _verifiable_result(self, scratch: str):
        """setUp's s9 result with the on-disk evidence a sealed lane owes:
        run-dir-contained capsule output plus byte-identical pass-2 proof."""
        import release_producer
        output = Path(scratch) / "out-s9"
        output.mkdir(parents=True, exist_ok=True)
        row = release_producer.get_producer("s9")
        artifact = output / row.primary_artifact
        for suffix in ("", ".sig", ".runtime-image.json", ".runtime-image.sig"):
            shutil.copyfile(str(self.fixture["artifact"]) + suffix, str(artifact) + suffix)
        (output / "TESTER_README.txt").write_text(train.FUND_URL + "\n", encoding="utf-8")
        first = release_producer.create_result(output, row, "a" * 40, "1.2.3", "beta",
                                               artifact.name, ["TESTER_README.txt"])
        subject = output / "producer-result.json"
        subject.write_text(json.dumps(first), encoding="utf-8")
        runtime.openssl("pkeyutl", "-sign", "-inkey", self.key, "-rawin", "-in", subject,
                        "-out", str(subject) + ".sig")
        document = release_producer.create_result(
            output, row, "a" * 40, "1.2.3", "beta", artifact.name,
            ["TESTER_README.txt", "producer-result.json", "producer-result.json.sig"])
        record = document["files"]["primary"]
        # Pass-2 proof in the repro cohort tree with its full signed members.
        pass2_root = Path(scratch) / "cohort-zynq-repro" / "capsule" / "pass2-s9"
        pass2_root.mkdir(parents=True, exist_ok=True)
        for member in [*document["files"].values(), *document["ancillary"]]:
            shutil.copyfile(output / Path(member["path"]).name, pass2_root / Path(member["path"]).name)
        result = dict(self.result)
        result.update(producer_output_root=str(output), producer_result=document,
                      artifact={"path": os.path.relpath(artifact, train.DCENTOS_DIR),
                                "sha256": record["sha256"], "bytes": record["size"]},
                      reproducibility={"compared": True, "identical": True, "pass2_log": "pass2.log",
                                       "pass2_root": str(pass2_root), "pass2_document": document,
                                       "pass2_primary": {"path": artifact.name,
                                                         "sha256": record["sha256"]}})
        return result

    def test_sealed_result_rejects_tampering_and_removal(self):
        import release_producer
        import release_producer_evidence

        # The cohort-evidence layer needs a real capsule tree the plain
        # fixture lacks, so it is replaced by a SHAPE-ASSERTING stand-in: a
        # member document passed where a cohort group belongs must fail here
        # (round-2 critic U caught exactly that regression class).
        def evidence_contract(document, _root, producers, *_rest):
            self.assertEqual(document.get("manifest_profile"), release_producer.COHORT_PROFILE)
            self.assertEqual(document.get("source_commit"), "a" * 40)
            self.assertEqual(len(document["results"]), len(producers))
            # The evidence verifier derives the expected cohort owner from
            # rows[0]; members must arrive in invocation order, never as
            # per-member singletons (live refusal, Oct 1 2026).
            self.assertEqual([member["producer"] for member in document["results"]], producers)

        scratch = str(self.root / "run")
        result = self._verifiable_result(scratch)
        train.persist_segment_result(scratch, result)
        sealed = train.load_segment_results(scratch)
        self.assertEqual(list(sealed), ["s9"])
        with patch.object(release_producer_evidence, "verify_cohort_evidence", side_effect=evidence_contract):
            train.verify_sealed_segment_result(sealed["s9"], scratch, None)  # fixture bytes verify
            artifact_path = Path(sealed["s9"]["producer_output_root"]) / Path(sealed["s9"]["artifact"]["path"]).name
            original = artifact_path.read_bytes()
            artifact_path.write_bytes(original + b"tamper")
            with self.assertRaises((train.TrainError, ValueError)):
                train.verify_sealed_segment_result(sealed["s9"], scratch, None)
            artifact_path.write_bytes(original)
            # Forged reproducibility without signed pass-2 evidence, with
            # tampered pass-2 bytes, or aliasing the pass-1 capsule output
            # as its own pass-2, is refused outright.
            forged = json.loads(json.dumps(sealed["s9"]))
            forged["reproducibility"] = {"compared": True, "identical": True}
            with self.assertRaises((train.TrainError, ValueError)):
                train.verify_sealed_segment_result(forged, scratch, None)
            mismatched = json.loads(json.dumps(sealed["s9"]))
            pass2_artifact = Path(mismatched["reproducibility"]["pass2_root"]) / "dcentos-unit.tar"
            pass2_artifact.write_bytes(b"different rebuild")
            with self.assertRaises((train.TrainError, ValueError)):
                train.verify_sealed_segment_result(mismatched, scratch, None)
            pass2_artifact.write_bytes(original)
            aliased = json.loads(json.dumps(sealed["s9"]))
            aliased["reproducibility"]["pass2_root"] = aliased["producer_output_root"]
            with self.assertRaises((train.TrainError, ValueError)):
                train.verify_sealed_segment_result(aliased, scratch, None)
            outside = json.loads(json.dumps(sealed["s9"]))
            outside["reproducibility"]["pass2_root"] = str(self.root / "pass2-elsewhere")
            with self.assertRaises((train.TrainError, ValueError)):
                train.verify_sealed_segment_result(outside, scratch, None)
            # Capsule output outside the run directory is a graft, not a seal.
            grafted = json.loads(json.dumps(sealed["s9"]))
            grafted["producer_output_root"] = str(self.root / "elsewhere")
            with self.assertRaises(train.TrainError):
                train.verify_sealed_segment_result(grafted, scratch, None)
            os.remove(artifact_path)
            with self.assertRaises((train.TrainError, ValueError, OSError)):
                train.verify_sealed_segment_result(sealed["s9"], scratch, None)

    def test_sealed_invocations_reverify_as_ordered_cohort_groups(self):
        """Live refusal, Oct 1 2026: every member of one capsule invocation
        carries the FIRST member's build target as its stamped cohort owner,
        so members must re-verify together and in planned order — verifying
        any member against a singleton list computes a different owner and
        refuses honest evidence. Grouping is by the shared invocation log."""
        import release_producer
        import release_producer_evidence

        run = self.root / "run"
        capsule = run / "cohort-zynq" / "capsule"
        capsule.mkdir(parents=True, exist_ok=True)

        def lane(name: str, log: str) -> Dict:
            return {"name": name, "status": "built", "lane_log": log,
                    "producer_result": {"producer": name},
                    "producer_output_root": str(capsule),
                    "artifact": {"path": "scripts/release_train.py", "sha256": "0" * 64, "bytes": 1},
                    "source_commit": "a" * 40, "version": "1.2.3", "channel": "beta",
                    "hardware_recipe": "board-default"}

        shared = str(run / "cohort-zynq" / "cohort-seg1.log")
        resealed = str(run / "cohort-zynq" / "cohort-seg2.log")
        sealed = {
            "am1-s9i": lane("am1-s9i", shared),   # planned third of the invocation
            "am1-s9j": lane("am1-s9j", shared),   # planned second
            "s9": lane("s9", shared),             # planned first — the stamped owner
            "am1-s15": lane("am1-s15", resealed),  # a later partial-invocation seal
        }
        seen: List[List[str]] = []

        def evidence_contract(document, _root, producers, *_rest):
            seen.append(list(producers))
            self.assertEqual(document.get("manifest_profile"), release_producer.COHORT_PROFILE)
            self.assertEqual([member["producer"] for member in document["results"]], producers)

        with patch.object(train, "verify_publication"), \
             patch.object(train, "scan_result_fund_link", return_value=(True, "TESTER_README.txt")), \
             patch.object(release_producer, "verify_cohort"), \
             patch.object(release_producer_evidence, "verify_cohort_evidence", side_effect=evidence_contract):
            train.verify_sealed_segment_results(sealed, str(run), None,
                                                ["s9", "am1-s9j", "am1-s9i", "am1-s15"])
        # One evidence call per invocation; the shared-log invocation arrives
        # in planned order with the owner first — never per-member singletons.
        self.assertEqual(seen, [["s9", "am1-s9j", "am1-s9i"], ["am1-s15"]])

        # A sealed lane outside the planned drop is refused outright.
        with patch.object(train, "verify_publication"), \
             patch.object(train, "scan_result_fund_link", return_value=(True, "TESTER_README.txt")):
            with self.assertRaises(train.TrainError):
                train.verify_sealed_segment_results(sealed, str(run), None,
                                                    ["s9", "am1-s9j", "am1-s9i"])

    def test_segment_state_requires_known_schema(self):
        with self.assertRaises(train.TrainError):
            train.load_segment_state(str(self.root / "missing"))
        bad = self.root / "run2"
        (bad / "segments").mkdir(parents=True)
        (bad / "segments" / "state.json").write_text(json.dumps({"schema": "other"}), encoding="utf-8")
        with self.assertRaises(train.TrainError):
            train.load_segment_state(str(bad))

    def test_cohort_session_files_never_collide_or_truncate(self):
        target = replace(next(t for t in train.TARGETS if t.name == "s9"), lane_command=("bash", "x"))
        planned = train.plan_target(target, {"am1-s9": "Beta"})
        seen = []

        def execute(_target, _date, _scratch, log, extra_args=()):
            seen.append((_scratch + "/" + log, extra_args[extra_args.index("--result-json") + 1]))
            return 1, "failed.log"  # rc!=0 skips result parsing; naming is the subject

        with patch.object(train, "_execute_lane", side_effect=execute):
            for session in ("seg1", "seg2"):
                train._execute_cohort([planned], "20260924", str(self.root / "run"), session=session)
        self.assertNotEqual(seen[0][0], seen[1][0])
        self.assertNotEqual(seen[0][1], seen[1][1])
        self.assertTrue(seen[0][0].endswith("cohort-seg1.log"))
        self.assertTrue(seen[1][0].endswith("cohort-seg2.log"))
        self.assertTrue(seen[1][1].endswith("cohort-result-seg2.json"))

    def test_session_number_skips_artifacts_of_a_dead_unrecorded_session(self):
        """A crash between the first per-lane seals and the segment-record
        write leaves seg1 artifacts on disk with an empty segments list; the
        naive counter would reuse seg1, merging two invocations into one
        resume group (critic W RISK-1, Oct 2026)."""
        run = self.root / "run"
        cohort = run / "cohort-zynq"
        cohort.mkdir(parents=True, exist_ok=True)
        (cohort / "cohort-seg1.log").write_text("dead session log\n", encoding="utf-8")
        state = {"segments": []}
        self.assertEqual(train.next_segment_session(str(run), state), "seg2")
        (cohort / "cohort-result-seg2.json").write_text("{}", encoding="utf-8")
        self.assertEqual(train.next_segment_session(str(run), state), "seg3")
        state = {"segments": [{"session": "seg3"}]}
        self.assertEqual(train.next_segment_session(str(run), state), "seg4")
        # A clean run directory numbers from one.
        clean = self.root / "clean"
        clean.mkdir()
        self.assertEqual(train.next_segment_session(str(clean), {"segments": []}), "seg1")

    def test_stale_release_output_cleared_for_rebuilt_lanes_only(self):
        from release_producer import get_producer
        scratch = self.root / "run"
        target = next(t for t in train.TARGETS if t.name == "s9")
        planned = train.plan_target(target, {"am1-s9": "Beta"})
        variant = get_producer(target.producer).cargo_variant
        for tree in ("cohort-" + variant, "cohort-" + variant + "-repro"):
            releases = scratch / tree / "capsule" / "releases"
            releases.mkdir(parents=True)
            (releases / "DCENTOS_XIL1_S9_beta20260901").mkdir()
            (releases / "DCENTOS_XIL1_S9k_beta20260901").mkdir()
        with patch.object(train, "canonical_release_name", return_value="DCENTOS_XIL1_S9_beta20260901"):
            train.clear_stale_release_output(str(scratch), [planned], "20260901")
        for tree in ("cohort-" + variant, "cohort-" + variant + "-repro"):
            self.assertFalse((scratch / tree / "capsule" / "releases" / "DCENTOS_XIL1_S9_beta20260901").exists())
            self.assertTrue((scratch / tree / "capsule" / "releases" / "DCENTOS_XIL1_S9k_beta20260901").exists())

    def test_resume_refuses_a_dirty_working_tree(self):
        from subprocess import CompletedProcess
        real_run = subprocess.run

        def git_dirty(command, *args, **kwargs):
            if command[:3] == ["git", "status", "--porcelain"]:
                return CompletedProcess(command, 0, stdout=" M DCENT_OS_Antminer/scripts/release_train.py\n", stderr="")
            return real_run(command, *args, **kwargs)

        with patch.object(train.subprocess, "run", side_effect=git_dirty):
            with self.assertRaises(train.TrainError):
                train.require_clean_worktree("resume")
        clean = CompletedProcess(["git", "status", "--porcelain"], 0, stdout="", stderr="")
        with patch.object(train.subprocess, "run", return_value=clean):
            train.require_clean_worktree("resume")  # clean tree passes
        broken = CompletedProcess(["git", "status", "--porcelain"], 128, stdout="", stderr="not a repo")
        with patch.object(train.subprocess, "run", return_value=broken),                 redirect_stdout(io.StringIO()):
            train.require_clean_worktree("resume")  # git failure is loud but non-fatal

    @classmethod
    def board_fixture(cls, board: str) -> dict:
        """Board-matched signed package (inner tar members are board-named);
        reuses the class fixture's ELF and keys, so only repackaging runs."""
        cached = getattr(cls, "_board_fixtures", None)
        if cached is None:
            cached = cls._board_fixtures = {}
        if board not in cached:
            from test_release_runtime_exports import package_fixture
            cached[board] = package_fixture(
                Path(cls.shared_temporary.name) / ("fixture-" + board), board=board,
                key=cls.fixture["key"], pubkey=cls.fixture["pubkey"],
                daemon=cls.fixture["daemon"])
        return cached[board]

    def _canned_result(self, name, producer, base=None):
        """Fixture-backed built result for a second lane, mirroring refresh().

        `base` anchors the capsule output (and the byte-identical pass-2
        copy) inside a specific tree — segment resume requires capsule output
        contained in the run directory.
        """
        import release_producer
        root = base or self.root
        output = root / ("out-" + name)
        output.mkdir()
        row = release_producer.get_producer(producer)
        source = self.fixture if row.board_target == "am1-s9" else self.board_fixture(row.board_target)
        artifact = output / row.primary_artifact
        for suffix in ("", ".sig", ".runtime-image.json", ".runtime-image.sig"):
            shutil.copyfile(str(source["artifact"]) + suffix, str(artifact) + suffix)
        (output / "TESTER_README.txt").write_text(train.FUND_URL + "\n", encoding="utf-8")
        first = release_producer.create_result(output, row, "a" * 40, "1.2.3", "beta", artifact.name,
                                               ["TESTER_README.txt"])
        subject = output / "producer-result.json"
        subject.write_text(json.dumps(first), encoding="utf-8")
        runtime.openssl("pkeyutl", "-sign", "-inkey", self.key, "-rawin", "-in", subject,
                        "-out", str(subject) + ".sig")
        document = release_producer.create_result(
            output, row, "a" * 40, "1.2.3", "beta", artifact.name,
            ["TESTER_README.txt", "producer-result.json", "producer-result.json.sig"])
        record = document["files"]["primary"]
        # The pass-2 proof lives in the repro cohort tree with its full
        # signed member set, exactly as a real second-build capsule output.
        pass2_root = root / ("cohort-" + row.cargo_variant + "-repro") / "capsule" / ("pass2-" + name)
        pass2_root.mkdir(parents=True)
        for member in [*document["files"].values(), *document["ancillary"]]:
            shutil.copyfile(output / Path(member["path"]).name, pass2_root / Path(member["path"]).name)
        return {"name": name, "board_target": row.board_target, "ring": "Beta", "channel": "beta",
                "version": "1.2.3", "source_commit": "a" * 40, "hardware_recipe": "board-default",
                "install_route": row.install_route, "status": "built",
                "fund_link": {"ok": True, "where": "result ancillary TESTER_README.txt"},
                "producer_output_root": str(output), "producer_result": document,
                # Faithful lane_log: segment resume attributes sealed lanes to
                # their invocation (and its stamped cohort owner) by this log.
                "lane_log": str(root / f"canned-{name}-invocation.log"),
                "reproducibility": {"compared": True, "identical": True, "pass2_log": "pass2.log",
                                    "pass2_root": str(pass2_root), "pass2_document": document,
                                    "pass2_primary": {"path": artifact.name, "sha256": record["sha256"]}},
                "artifact": {"path": os.path.relpath(artifact, train.DCENTOS_DIR),
                             "sha256": record["sha256"], "bytes": record["size"]}}

    def test_cmd_run_segments_resume_and_finish_one_drop(self):
        import release_channel_feed
        targets = [next(t for t in train.TARGETS if t.name == name) for name in ("s9", "am2-s19jpro")]
        admissions = {"am1-s9": "Beta", "am2-s19j": "Beta"}
        home = self.root / "train-home"
        (home / "output" / ".release-train").mkdir(parents=True)
        real_dcentos = os.path.dirname(train.SCRIPT_DIR)
        matrix_destination = home / "docs" / "architecture"
        matrix_destination.mkdir(parents=True)
        shutil.copyfile(os.path.join(real_dcentos, "docs", "architecture", "hardware_enablement_matrix.json"),
                        str(matrix_destination / "hardware_enablement_matrix.json"))
        # load_aliases binds DCENTOS_DIR as a definition-time default argument,
        # so the real board registry file must exist under the patched root.
        board_destination = home / "dcentrald" / "dcentrald-common" / "src"
        board_destination.mkdir(parents=True)
        shutil.copyfile(os.path.join(real_dcentos, "dcentrald", "dcentrald-common", "src", "board_desc.rs"),
                        str(board_destination / "board_desc.rs"))
        # plan_target stats the lane script relative to the patched root.
        (home / "scripts").mkdir()
        shutil.copyfile(os.path.join(real_dcentos, "scripts", "build_release_capsule.sh"),
                        str(home / "scripts" / "build_release_capsule.sh"))
        builds: list = []
        dates: list = []
        canned: dict = {}
        producers = {"s9": "s9", "am2-s19jpro": "am2-s19jpro"}

        def fake_cohorts(planned, date, scratch, _skip, with_repro=False,
                         channel_base_url=None, session=None, on_result=None, recovered=None,
                         recovered_comparison=None, protect=None):
            names = [item.target.name for item in planned]
            builds.extend(names)
            dates.append(date)
            # Capsule output is created inside the run directory, exactly as
            # production cohort capsule trees live under the run root.
            for name in names:
                if name not in canned:
                    canned[name] = self._canned_result(name, producers[name], base=Path(scratch))
            outcomes = [json.loads(json.dumps(canned[name])) for name in names]
            if on_result is not None:
                for outcome in outcomes:
                    on_result(outcome)
            return outcomes

        def fake_emit(manifest, channel, _key, _pubkey, _minimum):
            channel.write_bytes(b"signed-feed")

        environment = patch.dict(os.environ, DCENT_RELEASE_BASE_URL="https://releases.example.test/dcentos/")
        environment.start()
        self.addCleanup(environment.stop)
        base_argv = ["--run", "--drop", "1", "--repro", "--minimum-version", "0.9.0",
                     "--channel-base-url", "https://releases.example.test/dcentos/channel/"]
        import release_producer
        import release_producer_evidence

        # Cohort-evidence stands in with a shape contract: the verifier must
        # receive a cohort GROUP document (regression guard for the
        # member-vs-group round-2 finding).
        def evidence_contract(document, _root, producers, *_rest):
            assert document.get("manifest_profile") == release_producer.COHORT_PROFILE
            assert len(document["results"]) == len(producers)

        patches = [
            patch.object(train, "DCENTOS_DIR", str(home)),
            patch.object(train, "drop_targets", return_value=targets),
            patch.object(train, "load_admissions", return_value=admissions),
            patch.object(train, "run_selected_cohorts", side_effect=fake_cohorts),
            patch.object(train, "_git_head", return_value="a" * 40),
            patch.object(train, "workspace_version", return_value="1.2.3"),
            patch.object(release_channel_feed, "emit", side_effect=fake_emit),
            patch.object(release_producer_evidence, "verify_cohort_evidence", side_effect=evidence_contract),
        ]
        for active in patches:
            active.start()
            self.addCleanup(active.stop)
        # Lane results are materialized lazily inside the fake cohort runner,
        # under the run directory the train created (capsule containment).

        # Segment 1 (pinned calendar date D1): one lane budget, clean exit.
        with patch.object(train, "_today", return_value="20260901"), \
                redirect_stdout(io.StringIO()) as captured:
            rc = train.main(base_argv + ["--stop-after-lanes", "1"])
        self.assertEqual(rc, 0, captured.getvalue())
        self.assertIn("SEGMENT_COMPLETE", captured.getvalue())
        self.assertIn("sealed=1/2 remaining=1 next=am2-s19jpro", captured.getvalue())
        self.assertEqual(builds, ["s9"])
        run_dirs = [p for p in (home / "output" / ".release-train").iterdir() if p.is_dir()]
        self.assertEqual(len(run_dirs), 1)
        run_dir = run_dirs[0]
        self.assertIn(f"run={run_dir.name}", captured.getvalue())
        self.assertTrue((run_dir / "segments" / "results" / "s9.json").is_file())
        state = json.loads((run_dir / "segments" / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["drop"], 1)
        self.assertEqual(state["drop_date"], "20260901")
        self.assertEqual(len(state["segments"]), 1)
        self.assertEqual(state["segments"][0]["built"], ["s9"])
        status = json.loads((run_dir / "RUN_STATUS.json").read_text(encoding="utf-8"))
        self.assertFalse(status["complete_selected_beta"])
        self.assertEqual(status["deferred"], ["am2-s19jpro"])

        # A tampered sealed lane is refused before any new lane is built.
        tampered_artifact = Path(canned["s9"]["producer_output_root"]) / Path(canned["s9"]["artifact"]["path"]).name
        original_bytes = tampered_artifact.read_bytes()
        tampered_artifact.write_bytes(original_bytes + b"tamper")
        with redirect_stdout(io.StringIO()):
            rc = train.main(base_argv + ["--resume", run_dir.name])
        self.assertNotEqual(rc, 0)
        self.assertEqual(builds, ["s9"], "no lane may build after a sealed lane fails re-verification")
        tampered_artifact.write_bytes(original_bytes)

        # A corrupted pinned drop date is refused before anything builds.
        state_path = run_dir / "segments" / "state.json"
        state_document = json.loads(state_path.read_text(encoding="utf-8"))
        state_document["drop_date"] = "2099-13-99"
        state_path.write_text(json.dumps(state_document), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            rc = train.main(base_argv + ["--resume", run_dir.name])
        self.assertNotEqual(rc, 0)
        self.assertEqual(builds, ["s9"])
        state_document["drop_date"] = "20260901"
        state_path.write_text(json.dumps(state_document), encoding="utf-8")

        # Segment 2 (a DIFFERENT calendar date): the pinned drop date drives
        # the remaining lanes and the manifest name; build, resume, endgame.
        with patch.object(train, "_today", return_value="20260902"), \
                redirect_stdout(io.StringIO()) as captured:
            rc = train.main(base_argv + ["--resume", run_dir.name])
        self.assertEqual(rc, 0, captured.getvalue())
        self.assertEqual(builds, ["s9", "am2-s19jpro"])
        self.assertEqual(dates, ["20260901", "20260901"], "resume must build at the pinned drop date")
        manifests = list(run_dir.glob("MANIFEST_DROP1_*.json"))
        self.assertEqual(len(manifests), 1)
        self.assertIn("20260901", manifests[0].name)
        document = json.loads(manifests[0].read_text(encoding="utf-8"))
        self.assertEqual(sorted(row["board_target"] for row in document["targets"]), ["am1-s9", "am2-s19j"])
        self.assertTrue((run_dir / "beta.json").is_file())
        state = json.loads((run_dir / "segments" / "state.json").read_text(encoding="utf-8"))
        self.assertTrue(state["completed"])
        status = json.loads((run_dir / "RUN_STATUS.json").read_text(encoding="utf-8"))
        self.assertTrue(status["complete_selected_beta"])
        self.assertEqual(status["deferred"], [])

        # A completed drop is final: resuming it again is refused outright.
        with redirect_stdout(io.StringIO()):
            rc = train.main(base_argv + ["--resume", run_dir.name])
        self.assertNotEqual(rc, 0)

        # HEAD drift after any segment is an unrecoverable mismatch.
        with patch.object(train, "_git_head", return_value="b" * 40), \
                redirect_stdout(io.StringIO()):
            rc = train.main(base_argv + ["--resume", run_dir.name])
        self.assertNotEqual(rc, 0)

    def _orphaned_run(self, home, run_name="drop1-20260901-orphan", tampered=False):
        """A crashed session-1 run dir: capsule invocation complete, no state,
        no seals. Returns (run_dir, cohort capsule root, canned document)."""
        import release_producer
        run_dir = home / "output" / ".release-train" / run_name
        cohort = run_dir / "cohort-zynq"
        capsule = cohort / "capsule"
        capsule.mkdir(parents=True)
        result = self._canned_result("s9", "s9", base=capsule.parent)
        # The capsule root carries the invocation's member files.
        for member in [*result["producer_result"]["files"].values(), *result["producer_result"]["ancillary"]]:
            shutil.copyfile(Path(result["producer_output_root"]) / Path(member["path"]).name,
                            capsule / Path(member["path"]).name)
        group = {"manifest_profile": release_producer.COHORT_PROFILE, "cargo_variant": "zynq",
                 "source_commit": "a" * 40, "version": "1.2.3", "channel": "beta",
                 "results": [result["producer_result"]]}
        if tampered:
            group["results"][0]["files"]["primary"]["sha256"] = "0" * 64
        (cohort / "cohort-result-seg1.json").write_text(json.dumps(group), encoding="utf-8")
        return run_dir, capsule, result

    def test_orphaned_run_recovers_completed_invocation_without_rebuild(self):
        import release_channel_feed
        import release_producer
        import release_producer_evidence

        def evidence_contract(document, _root, producers, *_rest):
            assert document.get("manifest_profile") == release_producer.COHORT_PROFILE
            assert len(document["results"]) == len(producers)

        targets = [next(t for t in train.TARGETS if t.name == "s9")]
        admissions = {"am1-s9": "Beta"}
        home = self.root / "train-home"
        (home / "output" / ".release-train").mkdir(parents=True)
        real_dcentos = os.path.dirname(train.SCRIPT_DIR)
        for relative in ("docs/architecture/hardware_enablement_matrix.json",
                         "dcentrald/dcentrald-common/src/board_desc.rs",
                         "scripts/build_release_capsule.sh"):
            destination = home / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(os.path.join(real_dcentos, *relative.split("/")), str(destination))
        run_dir, capsule, canned = self._orphaned_run(home)

        calls = []

        def fake_execute_cohort(planned, _date, scratch, channel_base_url=None, session=None, protect=None):
            calls.append(scratch)
            # Only the repro pass may build: a byte-identical second result
            # in the repro cohort tree (members copied in place).
            repro_root = Path(scratch) / "capsule"
            repro_root.mkdir(parents=True, exist_ok=True)
            for member in [*canned["producer_result"]["files"].values(), *canned["producer_result"]["ancillary"]]:
                shutil.copyfile(capsule / Path(member["path"]).name, repro_root / Path(member["path"]).name)
            return {canned["producer_result"]["producer"]:
                    {"status": "built", "root": str(repro_root), "rc": 0,
                     "source_commit": "a" * 40, "log": "repro.log",
                     "document": canned["producer_result"]}}

        environment = patch.dict(os.environ, DCENT_RELEASE_BASE_URL="https://releases.example.test/dcentos/")
        environment.start()
        self.addCleanup(environment.stop)
        argv = ["--run", "--drop", "1", "--repro", "--minimum-version", "0.9.0",
                "--channel-base-url", "https://releases.example.test/dcentos/channel/",
                "--resume", run_dir.name]
        with patch.object(train, "DCENTOS_DIR", str(home)), \
                patch.object(train, "drop_targets", return_value=targets), \
                patch.object(train, "load_admissions", return_value=admissions), \
                patch.object(train, "_git_head", return_value="a" * 40), \
                patch.object(train, "workspace_version", return_value="1.2.3"), \
                patch.object(train, "_today", return_value="20260902"), \
                patch.object(release_channel_feed, "emit",
                             side_effect=lambda m, c, k, p, mv: c.write_bytes(b"feed")), \
                patch.object(release_producer_evidence, "verify_cohort_evidence",
                             side_effect=evidence_contract), \
                patch.object(train, "_execute_cohort", side_effect=fake_execute_cohort), \
                redirect_stdout(io.StringIO()) as captured:
            rc = train.main(argv)
        self.assertEqual(rc, 0, captured.getvalue())
        # The completed invocation recovered: NO first-pass cohort build ran,
        # only the repro pass (in the -repro tree) rebuilt for comparison.
        self.assertEqual([os.path.basename(c) for c in calls], ["cohort-zynq-repro"])
        # Bootstrap derived the pins from the orphaned directory itself.
        state = json.loads((run_dir / "segments" / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["git_head"], "a" * 40)
        self.assertEqual(state["drop_date"], "20260901")
        self.assertTrue(state["orphan_adopted"])
        self.assertEqual(state["segments"][-1]["recovered"], ["s9"])
        self.assertTrue((run_dir / "segments" / "results" / "s9.json").is_file())
        self.assertTrue(list(run_dir.glob("MANIFEST_DROP1_20260901.json")))

    def test_orphaned_run_with_tampered_invocation_falls_back_to_rebuild(self):
        import release_producer_evidence
        home = self.root / "train-home2"
        (home / "output" / ".release-train").mkdir(parents=True)
        run_dir, _capsule, _canned = self._orphaned_run(home, tampered=True)
        planned = train.plan_target(next(t for t in train.TARGETS if t.name == "s9"),
                                    {"am1-s9": "Beta"})
        with patch.object(release_producer_evidence, "verify_cohort_evidence"):
            recovered, adopted = train.recover_completed_invocations(str(run_dir), [planned], None)
        self.assertEqual(recovered, {}, "a tampered invocation must not be adopted")
        self.assertEqual(adopted, set())

    def test_bootstrap_refuses_inconsistent_or_undated_orphans(self):
        home = self.root / "train-home3"
        (home / "output" / ".release-train").mkdir(parents=True)
        empty = home / "output" / ".release-train" / "drop1-20260901-empty"
        empty.mkdir()
        with self.assertRaises(train.TrainError):
            train.bootstrap_orphaned_segment_state(str(empty), 1, False)
        mixed = home / "output" / ".release-train" / "drop1-20260901-mixed"
        (mixed / "cohort-zynq").mkdir(parents=True)
        for commit in ("a" * 40, "b" * 40):
            (mixed / "cohort-zynq" / f"cohort-result-{commit[:4]}.json").write_text(
                json.dumps({"source_commit": commit}), encoding="utf-8")
        with self.assertRaises(train.TrainError):
            train.bootstrap_orphaned_segment_state(str(mixed), 1, False)


class MediaQualificationTests(unittest.TestCase):
    def test_native_media_gate_rejects_placeholder_bytes(self):
        import release_producer
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dcentos-sd.img"
            path.write_bytes(b"placeholder")
            key = Path(directory) / "pub.pem"
            # A real key keeps the failure on the image side (missing media
            # constructs), not on key deserialization.
            subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519",
                            "-out", str(key)], check=True, capture_output=True)
            with self.assertRaises((ValueError, OSError)):
                train.validate_native_media_candidate(
                    str(path), release_producer.get_producer("am1-s15"),
                    "1.2.3", "beta", str(key), "board-default")

    def test_native_media_gate_delegates_to_the_capsule_reader(self):
        import release_producer
        row = release_producer.get_producer("am1-t15")
        sentinel = {"validated": True}
        with patch.object(release_producer, "verify_native_media", return_value=sentinel) as router:
            outcome = train.validate_native_media_candidate(
                "media.img", row, "1.2.3", "beta", "pub.pem", "board-default")
        self.assertIs(outcome, sentinel)
        args, kwargs = router.call_args
        self.assertEqual(args, (Path("media.img"), row, "1.2.3", "beta", Path("pub.pem")))
        self.assertEqual(kwargs, {"hardware_recipe": "board-default"})


class ProducerPublicationNameTests(unittest.TestCase):
    def test_every_producer_target_resolves_its_canonical_stem(self):
        # drop1-20260922 latents: t17e/s17e and s19a/s19plus lacked
        # firmware_release_name.sh arms; the capsule exits at the provenance
        # gate only ~15 h in. Sweep the whole matrix so the class is closed.
        import release_producer
        name_script = Path(train.DCENTOS_DIR) / "scripts" / "firmware_release_name.sh"
        for row in release_producer.list_producers():
            with self.subTest(producer=row.producer):
                completed = subprocess.run(
                    ["sh", str(name_script), row.build_target, "beta", "20260922"],
                    capture_output=True, text=True)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout.strip().rsplit("_beta", 1)[0],
                                 row.release_stem)

    def test_every_linaro_defconfig_declares_its_toolchain_features(self):
        # drop1-20260922 run-25 lane 20 latent: the BB defconfigs used the
        # Linaro 7.2.1 toolchain without declaring FORTRAN/OPENMP, and the
        # external-toolchain check hard-errors on available-but-unselected
        # capabilities (buildroot/toolchain/helpers.mk). Sweep EVERY file
        # carrying that toolchain — zynq defconfigs, the amlogic fragment,
        # and the first-install recovery defconfig — so the class stays
        # closed (critics Q+R fold: fragment/recovery are the same hazard).
        configs = Path(train.DCENTOS_DIR) / "br2_external_dcentos" / "configs"
        candidates = [*configs.glob("*_defconfig"), *configs.glob("*.fragment"),
                      *(Path(train.DCENTOS_DIR) / "scripts" / "first_install").glob("*_defconfig")]
        users = [p for p in sorted(candidates)
                 if not p.name.endswith("_full_defconfig")
                 and "gcc-linaro-7.2.1" in p.read_text(encoding="utf-8", errors="replace")]
        self.assertGreaterEqual(len(users), 10, "expected the known Linaro toolchain family")
        for path in users:
            with self.subTest(file=path.name):
                lines = [line.strip() for line in
                         path.read_text(encoding="utf-8", errors="replace").splitlines()]
                self.assertIn("BR2_TOOLCHAIN_EXTERNAL_FORTRAN=y", lines)
                self.assertIn("BR2_TOOLCHAIN_EXTERNAL_OPENMP=y", lines)


class RunModeTests(unittest.TestCase):
    """run_lane against a fake lane executable — never a real build."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.scratch = os.path.join(self.tmp, "scratch")
        os.makedirs(self.scratch)

    def _fake_lane(self, body):
        program = os.path.join(self.tmp, "fake_lane.cmd")
        with open(program, "w", encoding="utf-8") as handle:
            handle.write("@echo off\n" + body if os.name == "nt" else "#!/bin/sh\n" + body)
        os.chmod(program, 0o755 if os.name != "nt" else stat.S_IWRITE)
        return program

    def _target(self, program, artifact_name):
        return train.TrainTarget(
            name="fake",
            drops=(1,),
            board_target="am1-s9",
            policy_target="s9",
            lane_kind="s9_release_capsule",
            lane_command=("true",),  # replaced below by monkeypatched exec
            expected_artifact=artifact_name,
            install_route=train.ROUTE_FIRST_INSTALL,
            reproducible=False,
        )

    def test_blocked_target_is_recorded_not_run(self):
        target = replace(
            next(t for t in train.TARGETS if t.name == "am3-s19kpro"),
            blocked_reason="test",
        )
        planned = train.plan_target(target, train.load_admissions())
        result = train.run_lane(planned, "20260901", self.scratch, set())
        self.assertEqual(result["status"], "blocked")

    def test_lane_failure_recorded_with_rc(self):
        target = replace(
            next(t for t in train.TARGETS if t.name == "s9"),
            lane_command=(sys.executable, "-c", "import sys; sys.exit(3)"),
        )
        planned = train.plan_target(target, train.load_admissions())
        result = train.run_lane(planned, "20260901", self.scratch, set())
        self.assertEqual(result["status"], "lane-failed")
        self.assertEqual(result["lane_rc"], 3)

    def test_skip_short_circuits(self):
        target = next(t for t in train.TARGETS if t.name == "s9")
        planned = train.plan_target(target, train.load_admissions())
        result = train.run_lane(planned, "20260901", self.scratch, {"s9"})
        self.assertEqual(result["status"], "skipped")

    def test_incomplete_run_cannot_create_a_signed_manifest(self):
        target = next(target for target in train.TARGETS if target.name == "s9")
        path = os.path.join(self.tmp, "MANIFEST.json")
        with self.assertRaisesRegex(train.TrainError, "incomplete"):
            train.write_manifest(path, 1, [{"name": "s9", "status": "blocked"}], "a" * 40,
                                 targets=[target], base_url="https://release.example.test/", publish_root=self.tmp)
        self.assertFalse(Path(path).exists())

    def test_toolbox_row_matches_matrix_schema_fields(self):
        row = train.emit_toolbox_row(
            {
                "board_target": "am2-s17p",
                "ring": "Beta",
                "install_route": train.ROUTE_SD_TRIAL,
                "channel": train.CHANNEL_EXPBETA,
                "artifact": None,
            }
        )
        consumer = toolbox_consumer()
        self.assertEqual(set(row), consumer._ROW_FIELDS)
        path = Path(self.scratch) / "strict-policy.json"
        path.write_text(json.dumps({"schema": 4, "targets": [row]}), encoding="utf-8")
        loaded = consumer.load_enablement_matrix(path)
        self.assertEqual(loaded[0].board_target, "am2-s17p")
        self.assertNotIn("experimental_acknowledgment_required", row)
        self.assertFalse(row["public_beta_install"])

    def test_every_train_target_exports_a_strictly_loadable_policy_matrix(self):
        document = train.emit_toolbox_matrix([
            {"board_target": target.board_target} for target in train.TARGETS
        ])
        path = Path(self.scratch) / "all-targets.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        loaded = toolbox_consumer().load_enablement_matrix(path)
        self.assertEqual({row.board_target for row in loaded}, {target.board_target for target in train.TARGETS})

    def test_release_metadata_cannot_mint_policy_or_duplicate_targets(self):
        result = {"board_target": "am3-s19k", "install_route": train.ROUTE_FIRST_INSTALL,
                  "public_beta_install": True, "ring": "Beta", "artifact_sha256": "a" * 64}
        document = train.emit_toolbox_matrix([result, result])
        self.assertEqual(len(document["targets"]), 1)
        row = document["targets"][0]
        self.assertFalse(row["public_beta_install"])
        self.assertEqual(row, train.load_toolbox_policy()["am3-s19k"])
        self.assertNotIn("artifact_sha256", row)

    def test_unknown_or_malformed_policy_never_produces_a_fallback_row(self):
        with self.assertRaises(train.TrainError):
            train.emit_toolbox_row({"board_target": "future-miner"})
        with self.assertRaises(train.TrainError):
            train.emit_toolbox_matrix([])
        path = Path(self.scratch) / "bad-policy.json"
        for document in (
            {"schema": 3, "targets": [{"board_target": "am1-s9"}]},
            {"schema": 4, "targets": [{"board_target": "am1-s9"}] * 2},
            {"schema": 4, "targets": []},
        ):
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(train.TrainError):
                train.load_toolbox_policy(str(path))

    def test_skipped_debug_target_fails_without_signing_a_manifest(self):
        target = next(target for target in train.TARGETS if target.name == "s9")
        planned = train.plan_target(target, train.load_admissions())
        policy = train.load_toolbox_policy()
        admissions = train.load_admissions()
        with (patch.object(train, "DCENTOS_DIR", self.scratch),
              patch.object(train, "load_admissions", return_value=admissions),
              patch.object(train, "workspace_version", return_value="1.2.3"),
              patch.object(train, "plan_target", return_value=planned),
              patch.object(train, "load_toolbox_policy", return_value=policy),
              patch.dict(os.environ, DCENT_RELEASE_SIGNING_KEY="unused-test", DCENT_RELEASE_PUBKEY_FILE="unused-test"),
              redirect_stdout(io.StringIO())):
            code = train.main(["--run", "--debug-subset", "--target", "s9", "--skip", "s9"])
        self.assertEqual(code, 1)
        statuses = list(Path(self.scratch).glob("output/.release-train/*/RUN_STATUS.json"))
        self.assertEqual(len(statuses), 1)
        self.assertFalse(json.loads(statuses[0].read_text())["complete_selected_beta"])
        self.assertEqual(list(statuses[0].parent.glob("MANIFEST*")), [])

    def test_repro_not_requested_is_honest(self):
        target = replace(
            next(t for t in train.TARGETS if t.name == "s9"),
            lane_command=(sys.executable, "-c", "print('ok')"),
        )
        planned = train.plan_target(target, train.load_admissions())
        result = train.run_lane(planned, "20260901", self.scratch, set())
        # the lane "succeeds" but produces no capsule artifact
        self.assertIn(result["status"], ("artifact-unqualified", "lane-failed"))
        self.assertIsNone(result["reproducibility"])


class BoundedLaneOutputTests(unittest.TestCase):
    def test_lane_uses_resolved_bash_and_retains_environment(self):
        shell = (Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe"
                 if os.name == "nt" else Path(shutil.which("bash") or ""))
        self.assertTrue(shell.is_file(), "Bash is required for release acceptance")
        target = replace(next(target for target in train.TARGETS if target.name == "s9"),
            lane_command=("bash", "-c", 'printf "%s:%s" "$OSTYPE" "$DCENT_TEST_RELEASE_INHERIT"'))
        with tempfile.TemporaryDirectory() as directory, patch.object(train.shutil, "which", return_value=str(shell)), patch.dict(os.environ, DCENT_TEST_RELEASE_INHERIT="nonsecret-fixture"):
            status, path = train._execute_lane(target, "20260913", directory, "shell.log")
            self.assertEqual(status, 0)
            output = Path(path).read_text()
            self.assertTrue(output.endswith(":nonsecret-fixture"))
            self.assertTrue(output.split(":", 1)[0])
            if os.name == "nt":
                self.assertEqual(output, "msys:nonsecret-fixture")

    def test_missing_shell_refuses_before_a_lane_process_is_created(self):
        target = next(target for target in train.TARGETS if target.name == "s9")
        with tempfile.TemporaryDirectory() as directory, patch.object(train.shutil, "which", return_value=None), patch.object(train.subprocess, "Popen") as process:
            with self.assertRaisesRegex(train.TrainError, "Git Bash"):
                train._execute_lane(target, "20260913", directory, "shell.log")
            process.assert_not_called()

    def test_long_failed_build_preserves_exit_and_recent_diagnostics_within_limit(self):
        target = next(target for target in train.TARGETS if target.name == "s9")
        target = replace(target, lane_command=(sys.executable, "-c",
            "import sys; sys.stdout.write('x'*(6*1024**2)); print('FINAL_FAILURE_MARKER'); sys.exit(7)"))
        with tempfile.TemporaryDirectory() as directory:
            status, path = train._execute_lane(target, "20260913", directory, "build.log")
            self.assertEqual(status, 7)
            self.assertLessEqual(Path(path).stat().st_size, 5_000_000)
            self.assertTrue(Path(path).read_bytes().rstrip(b"\r\n").endswith(b"FINAL_FAILURE_MARKER"))

    def test_subchunk_output_reaches_the_log_before_lane_exit(self):
        # A plain read(64 KiB) withholds output until a full chunk or EOF, so
        # silent link phases read as a hung producer; read1 must surface each
        # fragment as it arrives.
        import threading
        import time
        target = replace(next(target for target in train.TARGETS if target.name == "s9"),
            lane_command=(sys.executable, "-c",
                "print('EARLY_OUTPUT_MARKER', flush=True); import time; time.sleep(5)"))
        with tempfile.TemporaryDirectory() as directory:
            outcome = {}
            worker = threading.Thread(target=lambda: outcome.update(
                zip(("status", "path"), train._execute_lane(target, "20260913", directory, "stream.log"))))
            worker.start()
            log_path = Path(directory) / "stream.log"
            deadline = time.monotonic() + 2.0
            seen = False
            while time.monotonic() < deadline:
                if log_path.exists() and b"EARLY_OUTPUT_MARKER" in log_path.read_bytes():
                    seen = True
                    break
                time.sleep(0.05)
            worker.join()
            self.assertTrue(seen, "sub-chunk output must reach the lane log before the lane exits")
            self.assertEqual(outcome["status"], 0)


class CompleteBetaTests(unittest.TestCase):
    def setUp(self):
        self.target = next(target for target in train.TARGETS if target.name == "s9")
        self.good = {"name": "s9", "board_target": "am1-s9", "channel": "beta", "status": "built",
                     "publish": {"staged": True}, "fund_link": {"ok": True},
                     "reproducibility": {"compared": True, "identical": True}}

    def test_every_incomplete_status_fails_including_old_false_success_cases(self):
        self.assertTrue(train.complete_selected_beta([self.target], [self.good]))
        for status in ("blocked", "skipped", "no-lane", "lane-failed", "artifact-unqualified",
                       "artifact-missing", "package-failed", "fund-link-failed", "repro-mismatch", None):
            with self.subTest(status=status):
                self.assertFalse(train.complete_selected_beta([self.target], [{**self.good, "status": status}]))
        for field, value in (("publish", {"staged": False}), ("publish", None),
                             ("fund_link", {"ok": False}), ("channel", "unsupported"),
                             ("board_target", "am3-s19kpro"), ("reproducibility", {"compared": False}),
                             ("reproducibility", {"compared": True, "identical": False})):
            with self.subTest(field=field, value=value):
                self.assertFalse(train.complete_selected_beta([self.target], [{**self.good, field: value}]))

    def test_missing_duplicate_or_unselected_results_fail(self):
        for results in ([], [self.good, self.good], [{**self.good, "name": "unselected"}]):
            self.assertFalse(train.complete_selected_beta([self.target], results))
        self.assertFalse(train.complete_selected_beta([], []))

    def test_cumulative_drop_selection_preserves_every_earlier_beta_row(self):
        expected = {target.board_target for target in train.drop_targets(1)}
        self.assertEqual(len(expected), 29)
        for drop in (2, 3):
            self.assertEqual({target.board_target for target in train.drop_targets(drop)}, expected)
        self.assertNotIn("am3-s19kpro", expected)

    def test_unavailable_producer_preflight_fails_before_build_or_sign(self):
        unavailable = [replace(target, lane_command=(), blocked_reason="fixture producer unavailable")
                       if target.board_target == "am2-t17e" else target for target in train.TARGETS]
        with patch.object(train, "TARGETS", unavailable), patch.object(train, "_execute_cohort", side_effect=AssertionError("must not build")), patch.object(train, "write_manifest", side_effect=AssertionError("must not sign")):
            self.assertEqual(train.main(["--run", "--drop", "1", "--minimum-version", "0.9.0", "--channel-base-url", "https://releases.example.invalid/channels"]), 1)

    def test_new_beta_registry_row_cannot_be_silently_omitted(self):
        admissions = {**train.load_admissions(), "future-beta-board": "Beta"}
        with patch.object(train, "load_admissions", return_value=admissions), patch.object(train, "_execute_cohort", side_effect=AssertionError("must not build")):
            self.assertEqual(train.main(["--run", "--drop", "1", "--minimum-version", "0.9.0", "--channel-base-url", "https://releases.example.invalid/channels"]), 2)

    def test_partial_selected_list_cannot_be_signed_as_a_numbered_drop(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(train.TrainError, "every registered Beta"):
            train.write_manifest(str(Path(directory) / "MANIFEST.json"), 1, [self.good], "a" * 40,
                                 targets=[self.target], base_url="https://releases.example.test", publish_root=directory)

    def test_numbered_drop_cannot_skip_or_silently_select_a_subset(self):
        for args in (["--drop", "1", "--skip", "s9"], ["--target", "s9"],
                     ["--drop", "1", "--debug-subset", "--target", "s9"]):
            self.assertEqual(train.main(["--run", "--minimum-version", "0.9.0", "--channel-base-url", "https://releases.example.invalid/channels", *args]), 2)

    def test_missing_or_noncanonical_minimum_refuses_before_any_materialization(self):
        for minimum in (None, "", "unsupported", "v1.2.3", "1.2", "01.2.3", "1.0.0-"):
            args = ["--run", "--drop", "1"]
            if minimum is not None:
                args.extend(["--minimum-version", minimum])
            with (patch.object(train.os, "makedirs", side_effect=AssertionError("must not materialize")),
                  patch.object(train, "run_selected_cohorts", side_effect=AssertionError("must not build")),
                  patch.object(train, "write_manifest", side_effect=AssertionError("must not sign"))):
                self.assertEqual(train.main(args), 2, minimum)

    def test_complete_run_emits_authenticated_feed_after_signed_cumulative_manifest(self):
        from test_release_channel_feed import fixture
        from release_channel_feed import feed
        from contextlib import ExitStack
        policy = train.load_toolbox_policy()
        admissions = train.load_admissions()
        planned = {target.name:train.plan_target(target,admissions) for target in train.TARGETS}
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            directory = Path(temporary)
            document, _, source, key, public = fixture(directory)
            results = [{"name": target.name, "board_target": target.board_target, "channel":"beta",
                        "status":"built", "fund_link":{"ok":True},
                        "reproducibility":{"compared":True,"identical":True}} for target in train.drop_targets(1)]
            def signed_manifest(path, *_args, **_kwargs):
                Path(path).write_bytes(source.read_bytes())
                Path(path + ".sig").write_bytes(Path(str(source) + ".sig").read_bytes())
            # This exercises orchestration against authenticated synthetic drop
            # records. Existing result/manifest tests own real package validation.
            for owner, name, replacement in (
                (train,"DCENTOS_DIR",str(directory)), (train,"_git_head",lambda:"a"*40),
                (train,"load_admissions",lambda:admissions),
                (train,"plan_target",lambda target,_admissions:planned[target.name]),
                (train,"load_toolbox_policy",lambda:policy),
                (train,"run_selected_cohorts",lambda *_args,**_kwargs:results),
                (train,"stage_publish",lambda *_args:{"staged":True}),
                (train,"write_manifest",signed_manifest)):
                stack.enter_context(patch.object(owner,name,replacement))
            stack.enter_context(patch.dict(os.environ, DCENT_RELEASE_SIGNING_KEY=str(key), DCENT_RELEASE_PUBKEY_FILE=str(public)))
            self.assertEqual(train.main(["--run","--drop","1","--minimum-version","0.9.0","--base-url","https://releases.example.invalid", "--channel-base-url","https://releases.example.invalid/channels"]),0)
            outputs = list(directory.glob("output/.release-train/*/beta.json"))
            self.assertEqual(len(outputs),1)
            payload,_ = feed.load(outputs[0],public,"beta")
            self.assertEqual({row["board_target"] for row in payload["targets"]},
                             {row["board_target"] for row in document["targets"]})

    def test_missing_or_unsafe_channel_base_refuses_before_materialization(self):
        for base in (None,"","http://example.invalid","https://user:password@example.invalid", "https://example.invalid/?token=x"):
            args=["--run","--drop","1","--minimum-version","0.9.0"]
            if base is not None: args.extend(["--channel-base-url",base])
            with patch.object(train.os,"makedirs",side_effect=AssertionError("must not materialize")):
                self.assertEqual(train.main(args),2,base)

    def test_selected_producers_build_once_per_architecture_cohort(self):
        targets = [target for target in train.TARGETS if target.producer]
        planned = [train.plan_target(target, train.load_admissions()) for target in targets]
        calls = []
        def failed_build(members, _date, scratch, channel_base_url=None, session=None, protect=None):
            calls.append([member.target.producer for member in members])
            return {member.target.producer: {"status": "lane-failed", "root": scratch,
                                            "source_commit": "a" * 40, "rc": 3} for member in members}
        with tempfile.TemporaryDirectory() as directory, patch.object(train, "_execute_cohort", side_effect=failed_build):
            results = train.run_selected_cohorts(planned, "20260913", directory, set(), with_repro=True)
        self.assertEqual(len(calls), 2)
        self.assertEqual(sorted(sum(calls, [])), sorted(target.producer for target in targets))
        self.assertEqual(len(results), 29)
        self.assertTrue(all(result["status"] == "lane-failed" for result in results))


class CliTests(unittest.TestCase):
    def test_admission_dump_runs(self):
        rc = train.main(["--admission"])
        self.assertEqual(rc, 0)

    def test_plan_drop1_is_clean_on_real_tree(self):
        rc = train.main(["--plan", "--drop", "1"])
        self.assertEqual(rc, 0, "drop-1 plan must have zero hard violations")

    def test_plan_without_drop_or_target_fails_closed(self):
        # resolve_targets refuses, and main() converts that to rc=2.
        self.assertRaises(train.TrainError, train.resolve_targets, None, None)
        self.assertEqual(train.main(["--plan"]), 2)

    def test_unknown_target_rejected(self):
        with self.assertRaises(train.TrainError):
            train.resolve_targets(None, ["no-such-target"])


if __name__ == "__main__":
    unittest.main()
