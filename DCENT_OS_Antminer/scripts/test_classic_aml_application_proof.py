#!/usr/bin/env python3
"""Execute the shipped read-only proof verifier on disposable process/GPIO files."""
import importlib.util
import itertools
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest

PROJECT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT / "br2_external_dcentos/board/amlogic/rootfs-overlay/usr/libexec/dcentos/verify-classic-aml-proof.py"
spec = importlib.util.spec_from_file_location("classic_proof_verifier", SOURCE)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


@unittest.skipUnless(os.name == "posix" and os.geteuid() == 0, "Linux root-owned file fixtures")
class ApplicationProof(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="classic-application-proof-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.proc = self.root / "proc"
        self.gpio = self.root / "gpio"
        self.proof = self.root / "proof.json"
        boot = self.proc / "sys/kernel/random/boot_id"
        boot.parent.mkdir(parents=True)
        boot.write_text("current-boot\n")
        process = self.proc / "123"
        process.mkdir()
        # Deliberately awkward comm exercises the real /proc stat parser.
        (process / "stat").write_text("123 (dcentrald ) actor) " + " ".join(["S"] + ["0"] * 18 + ["456"]) + "\n")
        (process / "exe").symlink_to("/usr/bin/dcentrald")
        for chain in range(1, 4):
            pin = self.gpio / f"gpio{438 + chain}"
            pin.mkdir(parents=True)
            (pin / "direction").write_text("in\n")
            (pin / "value").write_text("1\n")
        self.record = dict(schema=1, producer="classic_aml_native",
                           board_target="am3-s19jpro-aml", admitted_application_fw="0x89",
                           boot_id="current-boot", producer_pid=123, producer_start_ticks=456,
                           physical_chains=[1, 2, 3], observed_monotonic_ms=time.monotonic_ns() // 1_000_000)
        self.write()

    def write(self):
        self.proof.write_text(json.dumps(self.record))
        self.proof.chmod(0o600)

    def verify(self):
        return verifier.verify(self.proof, self.proc, self.gpio)

    def test_all_seven_exact_live_populations(self):
        for count in range(1, 4):
            for chains in itertools.combinations(range(1, 4), count):
                with self.subTest(chains=chains):
                    self.record["physical_chains"] = list(chains)
                    for chain in range(1, 4):
                        (self.gpio / f"gpio{438 + chain}/value").write_text(str(int(chain in chains)))
                    self.write()
                    self.assertIn("Classic AML fw89 owner", self.verify())

    def test_identity_freshness_and_population_refusals(self):
        for key, bad_values in {
            "schema": [True, 2], "producer": ["generic"],
            "board_target": ["am3-s19jproa"], "admitted_application_fw": ["0x86", "0x82"],
            "boot_id": ["previous-boot"], "producer_pid": [True, 0, 999],
            "producer_start_ticks": [457, True],
            "physical_chains": [[], [1], [1, 1, 2], [3, 2, 1], [1, 2, True], [1, 2, 4]],
            "observed_monotonic_ms": [True, -1, time.monotonic_ns() // 1_000_000 - 6000,
                                      time.monotonic_ns() // 1_000_000 + 10000],
        }.items():
            original = self.record[key]
            for value in bad_values:
                with self.subTest(key=key, value=value):
                    self.record[key] = value
                    self.write()
                    with self.assertRaises((ValueError, OSError)):
                        self.verify()
            self.record[key] = original

    def test_source_paced_three_board_age_is_fresh_without_backdating(self):
        self.record["observed_monotonic_ms"] = time.monotonic_ns() // 1_000_000 - 3500
        self.write()
        age = int(self.verify().rsplit("age_ms=", 1)[1])
        self.assertGreaterEqual(age, 3500)
        self.assertLess(age, 5000)

    def test_stale_record_waits_for_next_atomic_observation_but_contradictions_refuse(self):
        self.record["observed_monotonic_ms"] = time.monotonic_ns() // 1_000_000 - 6000
        self.write()
        with self.assertRaises(verifier.StaleObservation):
            self.verify()
        with self.assertRaises(verifier.StaleObservation):
            verifier.wait_for_fresh(self.proof, self.proc, self.gpio, 0.02)

        def refresh():
            time.sleep(0.03)
            record = dict(self.record, observed_monotonic_ms=time.monotonic_ns() // 1_000_000 - 3500)
            pending = self.root / "pending"
            pending.write_text(json.dumps(record))
            pending.chmod(0o600)
            pending.replace(self.proof)

        worker = threading.Thread(target=refresh)
        worker.start()
        try:
            self.assertIn("Classic AML fw89 owner", verifier.wait_for_fresh(self.proof, self.proc, self.gpio, 0.5))
        finally:
            worker.join()
        self.record["admitted_application_fw"] = "0x86"
        self.write()
        started = time.monotonic()
        with self.assertRaisesRegex(ValueError, "identity"):
            verifier.wait_for_fresh(self.proof, self.proc, self.gpio, 0.5)
        self.assertLess(time.monotonic() - started, 0.2)

    def test_file_safety_and_malformed_content_refusals(self):
        for raw in ("{", "[]", "null", "x" * 16385):
            self.proof.write_text(raw)
            with self.assertRaises(ValueError):
                self.verify()
        self.write()
        self.proof.chmod(0o644)
        with self.assertRaises(ValueError):
            self.verify()
        self.proof.unlink()
        self.proof.symlink_to(self.root / "missing")
        with self.assertRaises(OSError):
            self.verify()

    def test_wrong_process_executable_dead_process_and_gpio_refused(self):
        executable = self.proc / "123/exe"
        executable.unlink()
        executable.symlink_to("/usr/bin/other")
        with self.assertRaises(ValueError):
            self.verify()
        executable.unlink()
        executable.symlink_to("/usr/bin/dcentrald")
        process_stat = self.proc / "123/stat"
        saved = process_stat.read_text()
        process_stat.write_text(saved.replace(") S ", ") Z "))
        with self.assertRaises(ValueError):
            self.verify()
        process_stat.write_text(saved)
        for name, value in (("direction", "out"), ("value", "unknown")):
            path = self.gpio / "gpio439" / name
            saved = path.read_text()
            path.write_text(value)
            with self.assertRaises(ValueError):
                self.verify()
            path.write_text(saved)


if __name__ == "__main__":
    unittest.main()
