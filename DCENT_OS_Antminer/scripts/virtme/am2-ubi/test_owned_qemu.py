"""Bounded local protocol decoding; actual QEMU belongs to the VM acceptance."""
import io
import json
import unittest

from nandsim_snapshot import SnapshotError
from owned_qemu import Debugger, Qmp


class Wire:
    def __init__(self, data):
        self.data = io.BytesIO(data)
        self.sent = bytearray()
        self.read_calls = 0
    def recv(self, size):
        self.read_calls += 1
        return self.data.read(size)
    def sendall(self, data): self.sent.extend(data)
    def makefile(self, mode): return self.data
    def close(self): pass


class Owner:
    qmp_path = "only-modeled-socket"
    def __init__(self, wire): self.wire = wire
    def check(self): pass
    def connect(self, path):
        assert path == self.qmp_path
        return self.wire


def packet(data):
    return b"+$" + data + b"#" + f"{sum(data)&255:02x}".encode()


class ProtocolTests(unittest.TestCase):
    def debugger(self, data):
        debug = Debugger.__new__(Debugger)
        debug.socket = Wire(data)
        debug.owner = Owner(debug.socket)
        debug._pending, debug._position = b"", 0
        return debug

    def test_exact_memory_and_packet_acknowledgement(self):
        debug = self.debugger(packet(b"00a1ff"))
        self.assertEqual(debug.read(0xffff888000000000, 3), b"\0\xa1\xff")
        self.assertTrue(debug.socket.sent.endswith(b"+"))

    def test_qemu_run_length_encoded_hex_is_decoded_with_wire_checksum(self):
        debug = self.debugger(packet(b"0* "))  # Three extra zero digits.
        self.assertEqual(debug.read(0xffff888000000000, 2), b"\0\0")

    def test_memory_packet_is_buffered_without_losing_following_reply(self):
        debug = self.debugger(packet(b"ab" * 2048) + packet(b"00ff"))
        self.assertEqual(debug.read(0xffff888000000000, 2048), b"\xab" * 2048)
        self.assertEqual(debug.read(0xffff888000001000, 2), b"\0\xff")
        self.assertEqual(debug.socket.read_calls, 2)

    def test_fragmented_buffer_still_checks_each_packet_checksum(self):
        debug = self.debugger(packet(b"00ff") + b"+$abcd#00")
        read = debug.socket.recv
        debug.socket.recv = lambda size: read(min(size, 3))
        self.assertEqual(debug.read(0xffff888000000000, 2), b"\0\xff")
        with self.assertRaisesRegex(SnapshotError, "checksum"):
            debug.read(0xffff888000001000, 2)

    def test_checksum_bad_length_disconnect_and_error_reply_refuse(self):
        for raw in (b"+$00#00", packet(b"00"), packet(b"E14"), b"", packet(b"* ")):
            with self.subTest(raw=raw), self.assertRaises(SnapshotError):
                self.debugger(raw).read(0xffff888000000000, 2)

    def qmp(self, replies):
        wire = Wire(b"".join(json.dumps(value).encode() + b"\n" for value in replies))
        return Qmp(Owner(wire))

    def test_stop_requires_actual_paused_status_after_bound_reply(self):
        qmp = self.qmp([{"QMP": {}}, {"return": {}, "id": 1}, {"event": "STOP"},
            {"return": {}, "id": 2}, {"return": {"running": False, "status": "paused"}, "id": 3}])
        qmp.stop()

    def test_successful_stop_command_with_running_cpu_status_still_refuses(self):
        qmp = self.qmp([{"QMP": {}}, {"return": {}, "id": 1}, {"return": {}, "id": 2},
            {"return": {"running": True, "status": "running"}, "id": 3}])
        with self.assertRaisesRegex(SnapshotError, "paused"):
            qmp.stop()

    def test_unbound_or_error_qmp_response_refuses(self):
        for reply in ({"return": {}, "id": 99}, {"error": {"desc": "refused"}, "id": 1}):
            with self.subTest(reply=reply), self.assertRaises(SnapshotError):
                self.qmp([{"QMP": {}}, reply])


if __name__ == "__main__":
    unittest.main()
