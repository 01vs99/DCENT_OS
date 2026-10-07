#!/usr/bin/env python3
"""Explicit channel compile selection; ordinary files and local shell only."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release_train as train
import release_producer_evidence as evidence
import binary_build_receipt as receipts

SCRIPT = Path(__file__).resolve().parent
BASE = "https://releases.example.invalid/channels"


class ChannelBuildConfig(unittest.TestCase):
    def test_real_make_beta_forwards_explicit_parameters_as_literal_arguments(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            scripts=root/"scripts"; scripts.mkdir()
            (scripts/"release_train.py").write_text("import json,sys\nprint(json.dumps(sys.argv[1:]))\n")
            # Actual make target, harmless private argument sink. No producer
            # is invoked. Shell-looking bytes remain data for train validation.
            value="1.2.3`touch should-not-exist`"
            result=subprocess.run([shutil.which("make"),"--no-print-directory","-f",str(SCRIPT.parent/"Makefile"),
                "beta","CURDIR="+str(root),"DROP=2","MINIMUM_VERSION="+value,"CHANNEL_BASE_URL="+BASE],
                cwd=root,capture_output=True,text=True,timeout=10,check=True)
            arguments=json.loads(result.stdout)
            self.assertEqual(arguments,["--run","--drop","2","--repro","--minimum-version",value,"--channel-base-url",BASE])
            self.assertFalse((root/"should-not-exist").exists())

    def test_capsule_rejects_plaintext_empty_and_duplicate_urls_before_setup(self):
        for arguments in (("--feed-base-url", "http://example.invalid"),
                          ("--feed-base-url", ""),
                          ("--feed-base-url", BASE, "--feed-base-url", BASE + "/other"),
                          ("--feed-base-url", BASE, "--feed-base-url", BASE)):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "must-not-exist"
                process = subprocess.run([shutil.which("bash"), str(SCRIPT / "build_release_capsule.sh"),
                    *arguments, "--output-root", str(output)], cwd=temporary,
                    env={**os.environ, "DCENT_UPDATE_FEED_BASE_URL": BASE + "/ambient"},
                    capture_output=True, text=True, timeout=10)
                self.assertNotEqual(process.returncode,0)
                self.assertFalse(output.exists())

    def test_actual_capsule_preflight_clears_ambient_and_keeps_explicit_value(self):
        # Execute the unmodified production argument/URL preflight, stopping
        # immediately before producer/source selection. No Docker or Git action
        # is reachable in this prefix; no fake release result is constructed.
        source = (SCRIPT / "build_release_capsule.sh").read_text()
        prefix = source.split('case "$RELEASE_CHANNEL" in',1)[0]
        prefix = prefix.replace('SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
                                "SCRIPT_DIR=" + shlex.quote(str(SCRIPT)))
        with tempfile.TemporaryDirectory() as temporary:
            runner = Path(temporary) / "preflight.sh"
            runner.write_text(prefix + '\nprintf "selected=%s\\n" "${DCENT_UPDATE_FEED_BASE_URL-ABSENT}"\n')
            for arguments, expected in (([], "ABSENT"), (["--feed-base-url",BASE],BASE)):
                result = subprocess.run([shutil.which("bash"),str(runner),*arguments],
                    env={**os.environ,"DCENT_UPDATE_FEED_BASE_URL":BASE + "/ambient"},
                    capture_output=True,text=True,timeout=10,check=True)
                self.assertEqual(result.stdout.strip(),"selected=" + expected)

    def test_both_real_cohort_and_repro_receive_the_exact_explicit_url(self):
        target = next(target for target in train.TARGETS if target.name == "s9")
        planned = train.plan_target(target,train.load_admissions())
        observed = []
        def cohort(members,date,scratch,*,channel_base_url=None,session=None,on_result=None,protect=None,recovered=None,recovered_comparison=None):
            observed.append(channel_base_url)
            return {target.producer:{"status":"built"}}
        with tempfile.TemporaryDirectory() as temporary, patch.object(train,"_execute_cohort",side_effect=cohort), patch.object(train,"run_lane",return_value={}):
            train.run_selected_cohorts([planned],"20260913",temporary,set(),True,BASE)
        self.assertEqual(observed,[BASE,BASE])
        captured = []
        def execute(target,*_args,**_kwargs):
            captured.append(target.lane_command)
            return 1,"fixture-refusal-before-any-build"
        with tempfile.TemporaryDirectory() as temporary, patch.object(train,"_execute_lane",side_effect=execute), patch.object(train,"_git_head",return_value="a"*40):
            train._execute_cohort([planned],"20260913",temporary,BASE)
        self.assertIn(("--feed-base-url",BASE),list(zip(captured[0],captured[0][1:])))

    def test_compile_inventory_parser_and_expected_selection_join(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            path=root/"compile-env.txt"
            path.write_text("CARGO_BUILD_PROFILE=release\nDCENT_UPDATE_FEED_BASE_URL=" + BASE + "\n")
            record={"compile_environment":receipts.compile_environment_file(path,root)}
            evidence.verify_compiled_feed_base(record,BASE)
            for expected in (None,BASE + "/other","http://example.invalid"):
                with self.assertRaises(ValueError):
                    evidence.verify_compiled_feed_base(record,expected)
            absent={"compile_environment":{"entries":{}}}
            evidence.verify_compiled_feed_base(absent,None)
            with self.assertRaises(ValueError): evidence.verify_compiled_feed_base(absent,BASE)
            for malformed in ({}, {"compile_environment":{}},
                              {"compile_environment":{"entries":{"DCENT_UPDATE_FEED_BASE_URL":None}}}):
                with self.assertRaises(ValueError): evidence.verify_compiled_feed_base(malformed,None)


if __name__ == "__main__":
    unittest.main()
