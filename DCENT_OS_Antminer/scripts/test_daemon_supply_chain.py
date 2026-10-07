"""Adversarial checks for the narrow MQTT dormant-code advisory boundary."""

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import tempfile
import unittest

import daemon_supply_chain as gate
from check_dependency_age import CRATES_IO, GateError


class DormantSourcePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name)
        source = self.workspace / "registry/rumqttc"
        (source / "src").mkdir(parents=True)
        (source / "src/tls.rs").write_text("enum Error { Legacy(webpki::Error) }\n")
        (source / "Cargo.toml").write_text('[package]\nname="rumqttc"\nversion="0.25.1"\n')
        adapter = self.workspace / "dcentrald-api/src/mqtt.rs"
        adapter.parent.mkdir(parents=True)
        adapter.write_text("/// Apply TLS transport when the broker URL requests it.\n"
                           "fn tls() { modern_verified_transport(); }\n"
                           "pub fn mqtt_command_token_is_present() {}\n")
        self.source = source
        self.adapter = adapter
        self.package_pins = [{"name": name, "version": version, "source": CRATES_IO, "checksum": "a" * 64}
                             for name, version in [("rumqttc", "0.25.1"),
                                                   ("rustls-webpki", "0.102.8"),
                                                   ("rustls-pemfile", "2.2.0")]]
        self.lock = {"package": deepcopy(self.package_pins)}
        self.metadata = {
            "packages": [{"id": p["name"], **p, "manifest_path": str(source / "Cargo.toml"),
                          "targets": [{"kind": ["lib"]}]} for p in self.package_pins] +
                        [{"id": "rustls", "name": "rustls", "version": "0.23.41"}],
            "resolve": {"nodes": [{"id": "rumqttc", "features": ["use-rustls-no-provider"],
                                    "dependencies": ["rustls-webpki", "rustls-pemfile"]},
                                   {"id": "rustls-webpki", "features": [], "dependencies": []},
                                   {"id": "rustls-pemfile", "features": [], "dependencies": []}]}}
        self.policy = {"schema_version": 1, "expires_at": "2026-12-07T00:00:00Z",
                       "packages": deepcopy(self.package_pins),
                       "rumqttc_source_sha256": gate.source_digest(source),
                       "rumqttc_manifest_sha256": hashlib.sha256((source / "Cargo.toml").read_bytes()).hexdigest(),
                       "dcent_mqtt_adapter_sha256": gate.mqtt_adapter_digest(adapter),
                       "findings": [{"advisory": "RUSTSEC-2026-0098", "package": "rustls-webpki", "version": "0.102.8"}]}
        self.now = datetime(2026, 9, 7, tzinfo=timezone.utc)

    def run_guard(self):
        return gate.guard_dormant_findings(self.policy, self.lock, self.metadata,
                                          self.now, workspace=self.workspace)

    def test_exact_reviewed_source_and_graph_admitted(self):
        self.assertEqual(self.run_guard(), {("RUSTSEC-2026-0098", "rustls-webpki", "0.102.8")})

    def test_changed_or_new_runtime_source_refuses_exception(self):
        (self.source / "src/verification.rs").write_text("fn verify() { webpki::verify(); }")
        with self.assertRaisesRegex(GateError, "runtime callers"):
            self.run_guard()

    def test_changed_manifest_cannot_repurpose_a_dependency(self):
        with (self.source / "Cargo.toml").open("a") as file:
            file.write('[features]\ndefault=["use-rustls"]\n')
        with self.assertRaisesRegex(GateError, "manifest changed"):
            self.run_guard()

    def test_another_old_verifier_consumer_refuses_exception(self):
        self.metadata["resolve"]["nodes"].append({"id": "another-client", "dependencies": ["rustls-webpki"]})
        with self.assertRaisesRegex(GateError, "gained a caller"):
            self.run_guard()

    def test_older_rustls_or_changed_provider_refuses_exception(self):
        self.metadata["packages"][-1]["version"] = "0.22.4"
        with self.assertRaisesRegex(GateError, "older active rustls"):
            self.run_guard()
        self.metadata["packages"][-1]["version"] = "0.23.41"
        self.metadata["resolve"]["nodes"][0]["features"].append("use-rustls")
        with self.assertRaisesRegex(GateError, "provider policy"):
            self.run_guard()

    def test_tls_adapter_change_requires_fresh_review(self):
        self.adapter.write_text(self.adapter.read_text().replace("modern_verified_transport", "legacy_pem_branch"))
        with self.assertRaisesRegex(GateError, "adapter changed"):
            self.run_guard()

    def test_expiry_checksum_or_source_change_refuses_exception(self):
        self.now = datetime(2026, 12, 7, tzinfo=timezone.utc)
        with self.assertRaisesRegex(GateError, "expired"):
            self.run_guard()
        self.now = datetime(2026, 9, 7, tzinfo=timezone.utc)
        self.lock["package"][0]["checksum"] = "b" * 64
        with self.assertRaisesRegex(GateError, "package pin"):
            self.run_guard()

    def test_new_advisory_yank_and_other_version_are_never_hidden(self):
        def row(advisory, version="0.102.8"):
            return {"advisory": {"id": advisory}, "package": {"name": "rustls-webpki", "version": version}}
        accepted = row("RUSTSEC-2026-0098")
        new_advisory = row("RUSTSEC-2026-9999")
        new_version = row("RUSTSEC-2026-0098", "0.103.1")
        yank = {"kind": "yanked", "package": {"name": "rustls-webpki", "version": "0.102.8"}}
        audit = {"database": {}, "vulnerabilities": {"list": [accepted, new_advisory, new_version]},
                 "warnings": {"yanked": [yank]}}
        blocked, dormant = gate.classify_audit(audit, self.run_guard())
        self.assertEqual(dormant, [accepted])
        self.assertEqual(blocked, [new_advisory, new_version, yank])

    def test_incomplete_audit_does_not_pass(self):
        with self.assertRaises(GateError):
            gate.classify_audit({"error": "could not fetch advisory database"}, set())

    def test_policy_file_cannot_add_a_broader_ignore_or_omit_package_pins(self):
        self.policy["findings"].append({"advisory": "RUSTSEC-2026-9999", "package": "other", "version": "1.0.0"})
        with self.assertRaisesRegex(GateError, "outside the reviewed"):
            self.run_guard()
        self.policy["findings"].pop()
        self.policy["packages"].pop()
        with self.assertRaisesRegex(GateError, "every reviewed package"):
            self.run_guard()


if __name__ == "__main__":
    unittest.main()
