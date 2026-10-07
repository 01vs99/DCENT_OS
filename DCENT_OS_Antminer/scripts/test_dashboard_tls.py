#!/usr/bin/env python3
"""Actual local TLS/proxy/pin acceptance; no hardware or external network."""
from __future__ import annotations

import hashlib
import base64
import http.client
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import sys
import tempfile
import threading
import time
import types
import stat
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT.parents[1] / "projects/dcent-toolbox/src"))
from dcent_toolbox.core.dashboard_tls import inspect_dashboard_tls

TOKEN = "a" * 64


class Backend(BaseHTTPRequestHandler):
    calls = []

    def do_GET(self):
        self.handle_api()

    do_POST = do_GET
    do_DELETE = do_GET

    def handle_api(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.calls.append((self.command, self.path, dict(self.headers), body))
        if self.path.startswith("/ws"):
            if self.headers.get("Authorization") != "Bearer " + TOKEN:
                self.send_error(401)
                return
            key = self.headers["Sec-WebSocket-Key"]
            accept = base64.b64encode(hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            self.wfile.write(b"\x81\x02hi")
            raw = self.rfile.read(10)
            self.server.ws_frame = raw
            if raw == b"\x81\x84\x01\x02\x03\x04qkmc":
                self.wfile.write(b"\x81\x04pong")
            self.close_connection = True
            return
        if self.path in ("/api/auth/session", "/api/auth/setup"):
            payload = {"status": "ok", "session_token": TOKEN}
        elif self.path == "/api/info":
            payload = {"model": "test-only"}
        elif self.headers.get("Authorization") != "Bearer " + TOKEN:
            self.send_error(401)
            return
        else:
            payload = {"status": "ok"}
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class DashboardTlsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dcent-tls-")
        self.root = Path(self.temp.name)
        self.servers = []
        self.threads = []
        self.patches = []

    def tearDown(self):
        for server in reversed(self.servers):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def start(self, server):
        self.servers.append(server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        self.threads.append(thread)
        thread.start()
        return server.server_port

    def overlay(self, family):
        path = PROJECT / f"br2_external_dcentos/board/{family}/rootfs-overlay/root/web/server.py"
        spec = importlib.util.spec_from_file_location("dashboard_" + family, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # Only the filesystem owner is inert; generation and TLS transport are real.
        original_load = module.load_device_tls
        module.load_device_tls = lambda path, **kw: original_load(
            path, verify_storage=kw.get("verify_storage", lambda _path: "inert-owner"))
        module.AUTH_FILE = str(self.root / "auth.json")
        module.RELEASE_IMAGE_MARKER = str(self.root / "release-image")
        return module

    def servers_for(self, family):
        module = self.overlay(family)
        backend = ThreadingHTTPServer(("127.0.0.1", 0), Backend)
        backend.calls = []
        module.DCENTRALD_PORT = self.start(backend)
        context, info = module.load_device_tls(self.root / family)
        secure = module.create_tls_server(("127.0.0.1", 0), context, info)
        tls_port = self.start(secure)
        plain = module.ThreadedHTTPServer(("127.0.0.1", 0), module.DCENTosHandler)
        plain.tls_port = tls_port
        http_port = self.start(plain)
        return module, backend, tls_port, http_port, info

    def request(self, port, method, path, *, headers=None, body=None, tls=True):
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=3)
        else:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        try:
            connection.request(method, path, headers=headers or {}, body=body)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_real_tls_cookie_logout_and_api_pin_for_both_overlays(self):
        for family in ("amlogic", "zynq"):
            with self.subTest(family=family):
                module, backend, port, _, info = self.servers_for(family)
                status, headers, body = self.request(port, "POST", "/api/auth/session", body=b'{}')
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body)["session_token"], TOKEN)
                cookie = headers["Set-Cookie"]
                for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/"):
                    self.assertIn(flag, cookie)
                self.assertIn("no-store", headers["Cache-Control"])
                supplied = {"Cookie": cookie.split(";", 1)[0]}
                self.assertEqual(self.request(port, "GET", "/api/private", headers=supplied)[0], 200)
                self.assertEqual(backend.calls[-1][2]["X-Forwarded-Proto"], "https")
                self.assertNotIn(module.DASHBOARD_PROXY_HEADER, backend.calls[-1][2])
                before = len(backend.calls)
                self.assertEqual(self.request(port, "DELETE", "/api/auth/session/current", headers=supplied)[0], 403)
                supplied["Origin"] = "https://127.0.0.1:" + str(port)
                status, headers, _ = self.request(port, "DELETE", "/api/auth/session/current", headers=supplied)
                self.assertEqual(status, 200)
                self.assertIn("Max-Age=0", headers["Set-Cookie"])
                self.assertEqual(len(backend.calls), before + 1)
                observed = inspect_dashboard_tls("127.0.0.1", port=port, expected_pin=info["certificate_sha256"])
                self.assertTrue(observed["pin_verified"])
                self.assertTrue(observed["api_matches_certificate"])
                self.assertEqual(json.loads(self.request(port, "GET", "/api/info")[2])["tls"], info)
                before = len(backend.calls)
                with self.assertRaisesRegex(ValueError, "supplied pin"):
                    inspect_dashboard_tls("127.0.0.1", port=port, expected_pin="f" * 64)
                self.assertEqual(len(backend.calls), before)
                secure = self.servers[-2]
                secure.tls_info = dict(info, certificate_sha256="f" * 64)
                with self.assertRaisesRegex(ValueError, "does not match"):
                    inspect_dashboard_tls("127.0.0.1", port=port, expected_pin=info["certificate_sha256"])

    def test_http_closes_on_release_or_auth_state_and_rejects_cross_origin(self):
        module, backend, port, plain, _ = self.servers_for("amlogic")
        self.assertEqual(self.request(plain, "GET", "/api/info", tls=False)[0], 200)
        self.assertEqual(self.request(plain, "POST", "/api/auth/setup", body=b'{}', tls=False)[0], 308)
        for marker in (module.RELEASE_IMAGE_MARKER, module.AUTH_FILE):
            Path(marker).write_text("corrupt still closes HTTP")
            status, headers, _ = self.request(plain, "POST", "/api/private", body=b"secret", tls=False)
            self.assertEqual(status, 308)
            self.assertEqual(headers["Location"], f"https://127.0.0.1:{port}/api/private")
            self.assertNotIn("Set-Cookie", headers)
            Path(marker).unlink()
        for origin in ("https://other.local", "http://127.0.0.1:" + str(port), "https://127.0.0.1:1", "null"):
            before = len(backend.calls)
            self.assertEqual(self.request(port, "POST", "/api/auth/setup", headers={"Origin": origin}, body=b'{}')[0], 403)
            self.assertEqual(len(backend.calls), before)
        self.assertEqual(self.request(port, "GET", "/api/info", headers={"Host": "evil.example"})[0], 403)
        self.assertEqual(self.request(plain, "GET", "/api/private", headers={"Cookie": module.SESSION_COOKIE + "=" + TOKEN}, tls=False)[0], 401)

    def test_persistent_distinct_device_keys_and_corrupt_private_state_refuses(self):
        module = self.overlay("amlogic")
        _, first = module.load_device_tls(self.root / "one")
        before = (self.root / "one/dashboard.pem").read_bytes()
        _, repeated = module.load_device_tls(self.root / "one")
        _, other = module.load_device_tls(self.root / "two")
        self.assertEqual(first, repeated)
        self.assertEqual(before, (self.root / "one/dashboard.pem").read_bytes())
        self.assertNotEqual(first, other)
        bundle = self.root / "one/dashboard.pem"
        bundle.write_text("broken")
        with self.assertRaises(ssl.SSLError):
            module.load_device_tls(self.root / "one")
        self.assertEqual(bundle.read_text(), "broken")
        if os.name == "posix":
            directory = self.root / "two"
            directory.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "private"):
                module.load_device_tls(directory)
            directory.chmod(0o700)

    def test_actual_websocket_tls_tunnel_preserves_frames_and_backend_auth(self):
        for family in ("amlogic", "zynq"):
            module, backend, port, _, _ = self.servers_for(family)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
                with context.wrap_socket(raw, server_hostname="localhost") as client:
                    client.sendall((f"GET /ws HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                                    "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                    "Sec-WebSocket-Version: 13\r\n"
                                    f"Cookie: {module.SESSION_COOKIE}={TOKEN}\r\n\r\n").encode())
                    received = bytearray()
                    while b"\r\n\r\n" not in received:
                        received.extend(client.recv(4096))
                    head, frames = bytes(received).split(b"\r\n\r\n", 1)
                    self.assertTrue(head.startswith(b"HTTP/1.1 101"), head)
                    while len(frames) < 4:
                        frames += client.recv(4096)
                    self.assertEqual(frames, b"\x81\x02hi")
                    client.sendall(b"\x81\x84\x01\x02\x03\x04qkmc")
                    reply = bytearray()
                    while len(reply) < 6:
                        data = client.recv(4096)
                        self.assertTrue(data)
                        reply.extend(data)
                    self.assertEqual(reply, b"\x81\x04pong")
                    self.assertEqual(backend.ws_frame, b"\x81\x84\x01\x02\x03\x04qkmc")
            status, _, _ = self.request(port, "GET", "/ws", headers={
                "Upgrade": "websocket", "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Version": "13"})
            self.assertEqual(status, 401)

    def test_slow_handshakes_are_bounded_and_admission_recovers(self):
        module = self.overlay("amlogic")
        context, info = module.load_device_tls(self.root / "bounded")
        with patch.object(module.ThreadedHTTPServer, "max_connections", 2):
            server = module.create_tls_server(("127.0.0.1", 0), context, info)
        port = self.start(server)
        clients = [socket.create_connection(("127.0.0.1", port), timeout=2) for _ in range(2)]
        try:
            deadline = time.monotonic() + 2
            while server.connection_slots._value != 0 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(server.connection_slots._value, 0)
            with socket.create_connection(("127.0.0.1", port), timeout=2) as extra:
                try:
                    self.assertEqual(extra.recv(1), b"")
                except ConnectionResetError:
                    pass
            self.assertEqual(server.connection_slots._value, 0)
        finally:
            for client in clients:
                client.close()
        deadline = time.monotonic() + 2
        while server.connection_slots._value != 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(server.connection_slots._value, 2)
        self.assertEqual(self.request(port, "GET", "/api/tls/info")[0], 200)

    def test_storage_owner_refusal_and_change_never_publish_a_device_key(self):
        module = self.overlay("amlogic")
        def refuse(_path):
            raise RuntimeError("persistent owner absent")
        with self.assertRaisesRegex(RuntimeError, "persistent owner absent"):
            module.load_device_tls(self.root / "absent", verify_storage=refuse)
        self.assertFalse((self.root / "absent").exists())
        states = iter(("first mount", "replacement mount"))
        with self.assertRaisesRegex(RuntimeError, "owner changed"):
            module.load_device_tls(self.root / "changed", verify_storage=lambda _path: next(states))
        self.assertFalse((self.root / "changed/dashboard.pem").exists())
        self.assertEqual(list((self.root / "changed").iterdir()), [])

    def test_slow_body_cannot_extend_deadline_and_connection_admission_recovers(self):
        for family in ("amlogic", "zynq"):
            with self.subTest(family=family):
                module = self.overlay(family)
                context, info = module.load_device_tls(self.root / (family + "-slow-body"))
                with patch.object(module.ThreadedHTTPServer, "max_connections", 1):
                    server = module.create_tls_server(("127.0.0.1", 0), context, info)
                port = self.start(server)
                client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                client_context.check_hostname = False
                client_context.verify_mode = ssl.CERT_NONE
                with patch.object(module.DCENTosHandler, "request_body_timeout", 0.3):
                    with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
                        with client_context.wrap_socket(raw, server_hostname="localhost") as client:
                            client.sendall((
                                "POST /api/private HTTP/1.1\r\n"
                                f"Host: 127.0.0.1:{port}\r\n"
                                "Content-Length: 65536\r\n\r\nx"
                            ).encode("ascii"))
                            started = time.monotonic()
                            self.assertEqual(server.connection_slots._value, 0)
                            # Keep the socket active well inside its idle timeout,
                            # but never finish the first 64 KiB buffered read.
                            sent = 1
                            send_failed = False
                            while (server.connection_slots._value == 0
                                   and time.monotonic() - started < 1.5):
                                time.sleep(0.04)
                                if not send_failed:
                                    try:
                                        client.sendall(b"x")
                                        sent += 1
                                    except OSError:
                                        send_failed = True
                            self.assertGreater(sent, 2)
                            self.assertEqual(server.connection_slots._value, 1,
                                             "slow body retained the only connection slot")
                            # Recovery is observed before closing the original
                            # client, through another real TLS handshake/request.
                            self.assertEqual(self.request(port, "GET", "/api/tls/info")[0], 200)

    def test_body_admission_precedes_read_and_authenticated_upload_streams(self):
        module, backend, port, _, _ = self.servers_for("amlogic")
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            before = len(backend.calls)
            self.assertEqual(self.request(port, method, "/api/private", headers={
                "Content-Length": str(2 * 1024 * 1024 + 1)})[0], 413)
            self.assertEqual(len(backend.calls), before)
        self.assertEqual(self.request(port, "POST", "/api/system/upgrade", headers={
            "Content-Length": str(128 * 1024 * 1024 + 1)})[0], 413)
        self.assertEqual(self.request(port, "POST", "/api/system/upgrade", headers={
            "Content-Length": "3000000"})[0], 401)
        self.assertEqual(self.request(port, "POST", "/api/private", headers={
            "Content-Length": "5", "Transfer-Encoding": "chunked"})[0], 400)
        # Real backend receives a payload larger than the buffered JSON bound.
        # Production's admitted upload iterator supplies bounded chunks to
        # HTTPConnection rather than retaining this whole body in the proxy.
        body = b"bounded-stream-" * 160000
        chunk_sizes = []
        original = module.DCENTosHandler._body_chunks
        def observed(handler):
            for chunk in original(handler):
                chunk_sizes.append(len(chunk))
                yield chunk
        with patch.object(module.DCENTosHandler, "_body_chunks", observed):
            status, _, _ = self.request(port, "POST", "/api/system/upgrade", body=body,
                                        headers={"Authorization": "Bearer " + TOKEN})
        self.assertEqual(status, 200)
        self.assertGreater(len(chunk_sizes), 1)
        self.assertLessEqual(max(chunk_sizes), 65536)
        self.assertEqual(sum(chunk_sizes), len(body))
        self.assertEqual(backend.calls[-1][3], body)
        self.assertNotIn("Transfer-Encoding", backend.calls[-1][2])
        self.assertEqual(int(backend.calls[-1][2]["Content-Length"]), len(body))

    @unittest.skipUnless(os.name == "posix", "Linux device numbers and mountinfo")
    def test_actual_mount_verifier_refuses_volatile_readonly_and_nested_mounts(self):
        module = self.overlay("amlogic")
        meta = types.SimpleNamespace(st_dev=os.makedev(179, 2), st_ino=11, st_mode=stat.S_IFDIR | 0o700)
        persistent = "31 1 179:2 / / rw - ext4 /dev/mmcblk0p2 rw\n"
        accepted = module.persistent_data_mount(persistent, meta)
        self.assertEqual(accepted[-2:], ("ext4", "/dev/mmcblk0p2"))
        for text in (
            "31 1 0:20 / / rw - tmpfs tmpfs rw\n",
            persistent.replace(" rw", " ro"),
            persistent.replace("179:2", "179:3"),
            persistent + "42 31 0:20 / /data/dcent rw - tmpfs tmpfs rw\n",
            persistent + "43 31 0:21 / /data/dcent/tls rw - tmpfs tmpfs rw\n",
        ):
            with self.assertRaises(RuntimeError):
                module.persistent_data_mount(text, meta)


if __name__ == "__main__":
    if not shutil.which("openssl"):
        raise SystemExit("Real OpenSSL is required for TLS acceptance")
    unittest.main()
