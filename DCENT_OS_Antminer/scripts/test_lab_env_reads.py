#!/usr/bin/env python3
"""Behavioral checks for the focused production environment-reader inventory."""

from pathlib import Path
import tempfile
import subprocess
import sys
import unittest

from check_lab_env_reads import is_allowed, readers_in_source, scan_tree


class ProductionEnvironmentReaders(unittest.TestCase):
    def readers(self, source, path="dcentrald-hal/src/example.rs"):
        return readers_in_source(path, source)

    def test_register_and_presence_overrides_are_detected(self):
        rows = self.readers('''
            fn route() {
                let clock = std :: env :: var ("DCENT_S21_FAST_UART_VALUE");
                let degraded = std::env::var_os("DCENT_AM2_ACCEPT_DEGRADED_HARDWARE");
            }
        ''')
        self.assertEqual([r.api for r in rows], ["var", "var_os"])
        self.assertEqual([r.function for r in rows], ["route", "route"])
        self.assertTrue(all(not is_allowed(row) for row in rows))

    def test_comments_and_all_literal_forms_are_opaque(self):
        rows = self.readers(r'''
            // std::env::var("DCENT_FAKE")
            /* outer /* nested */ std::env::var("DCENT_FAKE") */
            const DOC: &str = r###"std::env::var("DCENT_FAKE") #[cfg(test)]"###;
            fn route<'a>() {
                let text = "escaped \" std::env::var(\"DCENT_FAKE\")";
                let bytes = br#"std::env::var("DCENT_FAKE")"#;
                let brace = '}';
                std::env::var("DCENT_REAL")
            }
        ''')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].argument, '"DCENT_REAL"')
        self.assertEqual(rows[0].function, "route")

    def test_test_items_are_excluded_but_shared_test_feature_code_is_scanned(self):
        rows = self.readers('''
            #[cfg(test)] #[allow(dead_code)]
            mod tests { fn fixture() { std::env::var("DCENT_FIXTURE"); } }
            #[cfg(all(test, feature = "lab"))]
            fn child() { std::env::var("DCENT_CHILD"); }
            #[cfg(any(test, feature = "hardware"))]
            fn live() { std::env::var("DCENT_REAL"); }
        ''')
        self.assertEqual([r.function for r in rows], ["live"])

    def test_test_field_does_not_swallow_the_next_production_function(self):
        rows = self.readers('''
            struct S { #[cfg(test)] fixture: bool, }
            fn live() { std::env::var("DCENT_REAL"); }
            fn other() { let s = S { #[cfg(test)] fixture: true, }; }
        ''')
        self.assertEqual([r.function for r in rows], ["live"])

    def test_aliased_raw_imports_cannot_hide_reads(self):
        for source in (
            'use std::env as runtime; fn f() { runtime::var("DCENT_REAL"); }',
            'use std::env::{var as override_var};',
            'use std::{env};',
            'use std::env::*;',
            'use std::env::{self as runtime};',
        ):
            with self.subTest(source=source):
                rows = self.readers(source)
                self.assertTrue(any(r.api == "raw-env-import" for r in rows))
        self.assertFalse(self.readers('use std::env::VarError;'))

    def test_env_module_reader_and_dynamic_enumeration_are_detected(self):
        rows = self.readers('fn f(name: &str) { env::var(name); std::env::vars_os(); }')
        self.assertEqual([(r.api, r.argument) for r in rows], [("var", "name"), ("vars_os", "")])

    def test_function_reference_cannot_hide_raw_reader(self):
        rows = self.readers('fn f() { let read = std::env::var; read("DCENT_REAL"); }')
        self.assertEqual([(r.api, r.argument) for r in rows], [("var", "<function reference>")])

    def test_shared_lab_accessors_are_accepted_without_raw_exceptions(self):
        self.assertFalse(self.readers('''
            fn f() { dcentrald_common::lab_env::var("DCENT_REAL");
                     crate::lab_env::var_os("DCENT_OTHER"); }
        '''))

    def test_operational_exception_cannot_hide_new_grant_in_same_file(self):
        rows = self.readers('''
            fn init_logging() {
                std::env::var("RUST_LOG");
                std::env::var("DCENT_AM2_TRUST_DEGRADED_FW");
            }
        ''', "dcentrald/src/logging.rs")
        self.assertEqual([is_allowed(row) for row in rows], [True, False])

    def test_test_module_files_are_excluded_by_declaration_not_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            source = workspace / "dcentrald/src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text('''
                #[cfg(test)] #[path = "fixture.rs"] mod tests;
                mod suspicious_tests;
            ''')
            (source / "fixture.rs").write_text('fn f() { std::env::var("DCENT_TEST_CHILD"); }')
            (source / "suspicious_tests.rs").write_text('fn f() { std::env::var("DCENT_REAL"); }')
            rows = scan_tree(workspace)
            self.assertEqual([r.path for r in rows], ["dcentrald/src/suspicious_tests.rs"])

    def test_inner_test_cfg_excludes_entire_file(self):
        self.assertFalse(self.readers('#![cfg(test)] fn f() { std::env::var("DCENT_TEST"); }'))

    def test_cli_refuses_missing_source_tree_instead_of_empty_success(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("check_lab_env_reads.py")),
                 "--workspace", directory], capture_output=True, text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source inventory is incomplete", result.stderr)


if __name__ == "__main__":
    unittest.main()
