#!/usr/bin/env python3
"""Pin the host_path_text boundary contract shared by the release tools.

Every host-side release tool carries a byte-identical host_path_text copy
(lineage b1ae659fa, 4fd3d8b0e, 054e5ce96, fbcf2ddc8). This test pins the
full boundary matrix under a simulated Windows host and the identity
contract on the current host, for every copy at once, so the seventeen
implementations cannot drift apart again.
"""

import os
import pathlib
import sys
import unittest
from unittest import mock

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import binary_build_receipt  # noqa: E402
import build_input_snapshot  # noqa: E402
import release_dashboard  # noqa: E402
import release_docker_resources  # noqa: E402
import release_invocation  # noqa: E402
import release_producer  # noqa: E402
import release_producer_evidence  # noqa: E402
import release_publication  # noqa: E402
import release_result_stage  # noqa: E402
import release_runtime_exports  # noqa: E402
import release_set_publication  # noqa: E402
import release_signing_authority  # noqa: E402
import release_source_git  # noqa: E402
import rust_dependency_inventory  # noqa: E402
import sign_release_artifact  # noqa: E402
import source_closure  # noqa: E402
import source_snapshot  # noqa: E402

MODULES = (
    binary_build_receipt,
    build_input_snapshot,
    release_dashboard,
    release_docker_resources,
    release_invocation,
    release_producer,
    release_producer_evidence,
    release_publication,
    release_result_stage,
    release_runtime_exports,
    release_set_publication,
    release_signing_authority,
    release_source_git,
    rust_dependency_inventory,
    sign_release_artifact,
    source_closure,
    source_snapshot,
)

B = chr(92)

# (input, expected-on-nt) pairs. Identity-expected inputs list themselves.
CASES = (
    # MSYS drive forms rewrite, including the bare drive roots that
    # otherwise resolve drive-relative into the cwd drive's shadow tree.
    ("/d/Example Projects/x", "D:/Example Projects/x"),
    ("/d/x", "D:/x"),
    ("/D/Dir", "D:/Dir"),
    ("/d/", "D:/"),
    ("/d", "D:/"),
    # Long-path prefixes strip; UNC long paths keep their UNC meaning.
    (B * 2 + "?" + B + "UNC" + B + "srv" + B + "share" + B + "k.pem",
     B * 2 + "srv" + B + "share" + B + "k.pem"),
    ("//?/UNC/srv/share/k", "//srv/share/k"),
    (B * 2 + "?" + B + "D:" + B + "x", "D:" + B + "x"),
    ("//?/D:/x", "D:/x"),
    # Native, container, POSIX, and non-drive spellings pass through.
    ("D:/native", "D:/native"),
    ("D:" + B + "native", "D:" + B + "native"),
    ("/mnt/d/x", "/mnt/d/x"),
    ("/dev/null", "/dev/null"),
    ("/usr/bin", "/usr/bin"),
    ("/out/x", "/out/x"),
    ("/project/scripts/x", "/project/scripts/x"),
    ("/src/main.rs", "/src/main.rs"),
    ("/ä/foo", "/ä/foo"),
    ("/ab/foo", "/ab/foo"),
    ("relative/path", "relative/path"),
    ("", ""),
    (b"/d/x", b"/d/x"),
)


class HostPathTextBoundaries(unittest.TestCase):
    def test_every_copy_agrees_under_windows(self):
        for module in MODULES:
            with mock.patch.object(os, "name", "nt"):
                for value, expected in CASES:
                    with self.subTest(module=module.__name__, value=value):
                        self.assertEqual(module.host_path_text(value), expected)

    def test_every_copy_is_identity_on_the_current_host(self):
        if os.name == "nt":
            self.skipTest("identity contract is exercised via the nt matrix")
        for module in MODULES:
            for value, _ in CASES:
                with self.subTest(module=module.__name__, value=value):
                    self.assertEqual(module.host_path_text(value), value)


if __name__ == "__main__":
    unittest.main()
