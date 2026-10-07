#!/usr/bin/env python3
"""Exact published producer-set adversaries; full signed audit lives in source-closure suite."""
import copy
from pathlib import Path
import tempfile
import unittest

import release_producer as producer
import release_producer_evidence as evidence
import release_set_publication as publication


class ExactProducerSet(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.row = producer.get_producer("s9")
        self.relative = "releases/" + producer.release_name(self.row, "beta", "20260913")
        self.directory = self.root / self.relative
        self.directory.mkdir(parents=True)
        names = [self.row.primary_artifact + suffix for suffix in
                 ("", ".sig", ".runtime-image.json", ".runtime-image.sig")]
        names += ["producer-result.json", "producer-result.json.sig"]
        for name in names:
            (self.directory / name).write_bytes(b"exact-set fixture; no runtime/source qualification")
        records = [producer.file_record(self.root, self.relative + "/" + name) for name in names]
        self.document = {"channel": "beta", "files": dict(zip(producer.ROLES, records[:4])),
                         "ancillary": records[4:]}
        self.descriptor = {"schema": publication.STAGE_SCHEMA, "state": "sealed",
                           "stage_id": "a" * 32, "capability_sha256": "b" * 64,
                           "output_name": self.directory.name,
                           "files": sorted([{"name": Path(r["path"]).name, "size": r["size"],
                                              "sha256": r["sha256"]} for r in records], key=lambda r: r["name"])}
        self.write_descriptor()

    def write_descriptor(self):
        (self.directory / publication.DESCRIPTOR_NAME).write_bytes(publication.canonical_json(self.descriptor))

    def verify(self):
        return evidence.verify_exact_set(self.document, self.root, self.row)

    def test_exact_signed_members_rejoin_sealed_directory(self):
        self.assertEqual(self.verify(), self.directory)

    def test_unlisted_extra_member_refused(self):
        (self.directory / "unsigned-extra").write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "extra"):
            self.verify()

    def test_missing_member_refused(self):
        (self.directory / "producer-result.json.sig").unlink()
        with self.assertRaises((ValueError, OSError)):
            self.verify()

    def test_descriptor_cannot_remove_signed_member(self):
        self.descriptor["files"].pop()
        self.write_descriptor()
        with self.assertRaisesRegex(ValueError, "differs"):
            self.verify()

    def test_malformed_seal_or_renamed_output_refused(self):
        original = copy.deepcopy(self.descriptor)
        for key, value in (("state", "open"), ("stage_id", "x" * 32),
                           ("capability_sha256", "b" * 63), ("output_name", "other")):
            with self.subTest(key=key):
                self.descriptor = {**original, key: value}
                self.write_descriptor()
                with self.assertRaises(ValueError):
                    self.verify()

    def test_foreign_directory_ancillary_refused(self):
        self.document["ancillary"][0]["path"] = "another/producer-result.json"
        with self.assertRaisesRegex(ValueError, "exact release directory"):
            self.verify()


class RetainedCargoJoin(unittest.TestCase):
    def setUp(self):
        self.path = "target/armv7-unknown-linux-musleabihf/release/dcentrald"
        self.entry = {"name": "dcentrald", "target_triple": "armv7-unknown-linux-musleabihf",
                      "profile": "release", "binary": {"size": 1024, "sha256": "a" * 64},
                      "receipt": {"size": 2048, "sha256": "b" * 64}}
        self.receipt = {"binary": {"path": self.path}}
        self.result = {"manifest": {"files": [
            {"path": self.path, **self.entry["binary"]},
            {"path": self.path + ".build-receipt.json", **self.entry["receipt"]}]}}

    def test_retained_pair_matches_its_sealed_paths(self):
        evidence.verify_retained_result_pair(self.result, self.entry, self.receipt)

    def test_foreign_binary_or_receipt_digest_size_and_path_refused(self):
        for index in (0, 1):
            for field, value in (("size", 4), ("sha256", "c" * 64), ("path", "foreign/output")):
                with self.subTest(index=index, field=field):
                    changed = copy.deepcopy(self.result)
                    changed["manifest"]["files"][index][field] = value
                    with self.assertRaisesRegex(ValueError, "sealed Cargo result differs"):
                        evidence.verify_retained_result_pair(changed, self.entry, self.receipt)

    def test_empty_result_and_noncanonical_receipt_binary_path_refused(self):
        with self.assertRaisesRegex(ValueError, "sealed Cargo result differs"):
            evidence.verify_retained_result_pair({"manifest": {"files": []}}, self.entry, self.receipt)
        for path in ("other/dcentrald", self.path.replace("armv7", "aarch64")):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "noncanonical binary path"):
                evidence.verify_retained_result_pair(self.result, self.entry, {"binary": {"path": path}})


class SnapshotDescriptorBound(unittest.TestCase):
    """The live source descriptor scales with the workspace file count.

    Producer run drop1-20260917-ffsk3xe6 built the first complete signed
    artifact, then retain-live rejected its own 29 MiB snapshot descriptor
    because read_canonical's canonical-index default bound is 4 MiB. The
    snapshot authority's MAX_DESCRIPTOR_BYTES is the bound for that file.
    """

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_descriptor_beyond_index_bound_passes_with_authority_bound(self):
        import portable_release_evidence as projections
        import source_snapshot
        document = {"schema": "bound-fixture",
                    "files": [{"p": "d/%06d" % index, "s": 1} for index in range(200000)]}
        raw = projections.canonical_bytes(document)
        self.assertGreater(len(raw), projections.MAX_INDEX_BYTES)
        path = self.root / "snapshot.json"
        projections.write_exclusive(path, raw)
        with self.assertRaises(projections.PortableEvidenceError):
            projections.read_canonical(path, "source snapshot")
        self.assertEqual(
            projections.read_canonical(path, "source snapshot",
                                       source_snapshot.MAX_DESCRIPTOR_BYTES),
            document)

    def test_retain_and_audit_sites_pass_the_authority_bound(self):
        import inspect

        import portable_release_evidence as projections

        for function in (evidence.retain_live, evidence.verify_audit_contents,
                         projections.create_live_with_key):
            with self.subTest(function=function.__name__):
                self.assertIn("MAX_DESCRIPTOR_BYTES", inspect.getsource(function))


if __name__ == "__main__":
    unittest.main()
