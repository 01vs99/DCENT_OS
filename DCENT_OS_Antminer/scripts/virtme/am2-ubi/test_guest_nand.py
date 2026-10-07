"""Pure raw replay planning tests; character devices are never substituted."""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import guest_nand as guest
from nandsim_snapshot import SnapshotError


def records(values):
    allocation = bytearray(16384)
    pages = bytearray()
    for number, raw in sorted(values.items()):
        allocation[number//8] |= 1 << (number%8)
        pages.extend(raw)
    return allocation, bytes(pages)


class ReplayPlanTests(unittest.TestCase):
    def test_holes_partition_edges_oob_and_allocated_erased_page_survive(self):
        last = guest.PART_BLOCKS[0] * 64 - 1
        allocation, pages = records({0: guest.ERASED, 2: b"A"*2048+b"O"*64,
                                    last: b"B"*2112, last+1: b"C"*2112})
        self.assertEqual(list(guest.replay_runs(allocation, pages)), [
            (0, 0, guest.ERASED), (0, 4096, b"A"*2048+b"O"*64),
            (0, last*2048, b"B"*2112), (1, 0, b"C"*2112)])

    def test_contiguous_runs_are_bounded_to_one_eraseblock_of_raw_data(self):
        allocation, pages = records({n: bytes([n])*2112 for n in range(65)})
        runs = list(guest.replay_runs(allocation, pages))
        self.assertEqual([(row[0], row[1], len(row[2])) for row in runs],
                         [(0, 0, 64*2112), (0, 64*2048, 2112)])
        self.assertEqual(b"".join(row[2] for row in runs), pages)

    def test_readback_checks_unallocated_pages_and_oob_not_only_payload(self):
        allocation, pages = records({1: b"A"*2048+b"O"*64})
        def raw(device, blocks):
            for number in range(131072):
                yield pages if number == 1 else guest.ERASED
        with mock.patch.object(guest, "raw_pages", raw):
            observed = guest.compare_raw(((Path("pure-model"), 2048),), allocation, pages)
        self.assertEqual(len(observed), 64)
        for damaged_page, value in ((0, b"x"+guest.ERASED[1:]), (1, b"A"*2048+b"X"*64)):
            def damaged(device, blocks):
                for number, original in enumerate(raw(device, blocks)):
                    yield value if number == damaged_page else original
            with mock.patch.object(guest, "raw_pages", damaged):
                with self.assertRaisesRegex(SnapshotError, "NAND/OOB replay differs"):
                    guest.compare_raw(((Path("pure-model"), 2048),), allocation, pages)

    def test_host_context_refuses_before_any_device_open(self):
        with mock.patch.dict(guest.os.environ, {}, clear=True), mock.patch.object(guest.os, "open") as opened:
            with self.assertRaisesRegex(SnapshotError, "exact disposable"):
                guest.guard("a"*64)
            opened.assert_not_called()

    def test_guest_without_explicit_four_level_mapping_refuses_before_device_open(self):
        for command_line in ("quiet nopti", "quiet no5lvl", "quiet"):
            with self.subTest(command_line=command_line), \
                    mock.patch.object(guest.os, "name", "posix"), \
                    mock.patch.object(guest.os, "geteuid", return_value=0), \
                    mock.patch.object(guest.os, "uname", return_value=SimpleNamespace(release=guest.RELEASE)), \
                    mock.patch.dict(guest.os.environ, {"DCENT_DISPOSABLE_VIRTME": "am2-first-install-v1"}), \
                    mock.patch.object(Path, "read_text", return_value=command_line), \
                    mock.patch.object(guest.os, "open") as opened:
                with self.assertRaisesRegex(SnapshotError, "four-level"):
                    guest.guard("a" * 64)
                opened.assert_not_called()


if __name__ == "__main__":
    unittest.main()
