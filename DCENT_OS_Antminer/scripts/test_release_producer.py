#!/usr/bin/env python3
"""Producer identity and strict result parser tests; no build or device access."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

import release_producer as producer
import release_train


class Producers(unittest.TestCase):
    def test_all_current_beta_rows_have_an_exact_producer(self):
        beta = {board for board, channel in release_train.load_admissions().items() if channel == "Beta"}
        rows = producer.list_producers()
        self.assertEqual(len(rows), 29)
        self.assertEqual(beta, {row.board_target for row in rows} | set(producer.MISSING_PRODUCERS))
        self.assertEqual(set(producer.MISSING_PRODUCERS), set())
        for row in rows:
            self.assertNotEqual(release_train.load_admissions()[row.board_target], "Unsupported")

    def test_s19k_build_spelling_does_not_alias_unsupported_board(self):
        row = producer.get_producer("am3-s19k")
        self.assertEqual((row.build_target, row.board_target), ("am3-s19kpro", "am3-s19k"))
        with self.assertRaises(producer.ProducerError):
            producer.get_producer("am3-s19kpro")

    def test_declared_routes_preserve_storage_facets(self):
        rows = producer.list_producers()
        self.assertEqual([row.producer for row in rows if row.install_route == "first_install_and_self_update"], ["s9"])
        self.assertEqual(sum(row.artifact_kind == "native-sd-image" for row in rows), 17)
        self.assertEqual(producer.get_producer("am2-t17e").runtime_root, "partition2-ext2")
        self.assertEqual(producer.get_producer("am3-bb-s19jpro").artifact_kind, "sd-payload-tar")
        self.assertEqual(producer.get_producer("am2-s19jpro").install_route, "self_update_only")
        for board in ("am3-s19xp", "am3-s19jxp", "am3-s19jproa", "am3-s21xp"):
            self.assertEqual(producer.get_producer(board).install_route, "operator_staged")

    def test_cohorts_require_unique_producers_of_one_architecture(self):
        self.assertEqual(len(producer.cohort(["s9", "am2-s19jpro"])), 2)
        self.assertEqual(len(producer.cohort(["am2-t17e", "s9"])), 2)
        for names in ([], ["s9", "s9"], ["s9", "am3-s21"], ["am2-s17e-other"], "s9", [None], [["s9"]]):
            with self.subTest(names=names), self.assertRaises(producer.ProducerError):
                producer.cohort(names)

    def test_invalid_channels_dates_and_unknown_producers_refused(self):
        for name in ("am2-s17e-other", "s19k", "", "../s9", None, ["s9"]):
            with self.subTest(name=name), self.assertRaises(producer.ProducerError):
                producer.get_producer(name)
        for channel, date in (("lab", "20260913"), ("beta", "20260230"), ("beta", "2026-09-13")):
            with self.subTest(channel=channel, date=date), self.assertRaises(producer.ProducerError):
                producer.release_name(producer.get_producer("s9"), channel, date)


class ResultRefusals(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.row = producer.get_producer("s9")
        self.primary = self.row.primary_artifact
        for suffix in ("", ".sig", ".runtime-image.json", ".runtime-image.sig"):
            (self.root / (self.primary + suffix)).write_bytes(b"fixture; intentionally not a signed artifact")
        self.document = producer.create_result(self.root, self.row, "a" * 40, "0.1.0", "beta", self.primary, [])

    def reject(self, document):
        with self.assertRaises((ValueError, OSError)):
            producer.verify_result(document, self.root, self.row, "a" * 40, "0.1.0", "beta", self.root / "missing-trust-key")

    def test_every_identity_field_must_match_callers_expectation(self):
        for key in set(self.document) - {"files", "ancillary"}:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.document)
                changed[key] = "wrong"
                self.reject(changed)

    def test_unknown_and_missing_fields_refused(self):
        for key in self.document:
            changed = copy.deepcopy(self.document)
            del changed[key]
            self.reject(changed)
        changed = copy.deepcopy(self.document)
        changed["verified"] = True
        self.reject(changed)

    def test_duplicate_json_fields_refused(self):
        path = self.root / "result.json"
        path.write_text('{"producer":"s9","producer":"am3-s21"}', encoding="utf-8")
        with self.assertRaisesRegex(producer.ProducerError, "duplicate"):
            producer.load_result(path)

    def test_changed_files_and_boolean_size_refused(self):
        changed = copy.deepcopy(self.document)
        changed["files"]["primary"]["size"] = True
        self.reject(changed)
        (self.root / self.primary).write_bytes(b"tampered")
        self.reject(self.document)

    def test_path_traversal_and_ambiguous_paths_refused_before_open(self):
        for path in ("../outside", "/absolute", "a/../x", "./x", "a//b", "a\\b", "C:/x", "a\nfile"):
            with self.subTest(path=path), self.assertRaises(producer.ProducerError):
                producer.regular_path(self.root, path)

    def test_hardlink_and_symlink_files_refused(self):
        linked = self.root / "linked"
        os.link(self.root / self.primary, linked)
        with self.assertRaisesRegex(producer.ProducerError, "single-link"):
            producer.file_record(self.root, "linked")
        if os.name == "posix":
            linked.unlink()
            linked.symlink_to(self.root / self.primary)
            with self.assertRaisesRegex(producer.ProducerError, "symlink"):
                producer.file_record(self.root, "linked")


if __name__ == "__main__":
    unittest.main()
