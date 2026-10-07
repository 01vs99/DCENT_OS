#!/usr/bin/env python3
"""Loopback-only HTTPS fixture for actual channel transport tests."""
import argparse
import datetime
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import ssl
import time
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def certificate(root):
    key = ec.generate_private_key(ec.SECP256R1())
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DCENT loopback fixture CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(ca_key, hashes.SHA256()))
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(ca_name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).sign(ca_key, hashes.SHA256()))
    (root / "tls-ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (root / "tls-cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (root / "tls-key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (root / "tls-key.pem").chmod(0o600)


class Handler(BaseHTTPRequestHandler):
    def __init__(self, *args, root, **kwargs):
        self.root = root
        super().__init__(*args, **kwargs)

    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1/plaintext")
            self.end_headers()
            return
        if self.path == "/slow":
            time.sleep(1)
        name = "feed.json" if self.path == "/feed.json" else "package.tar"
        if self.path not in ("/feed.json", "/package.tar", "/too-long", "/truncated", "/slow"):
            self.send_error(404)
            return
        raw = (self.root / name).read_bytes()
        self.send_response(200)
        if self.path != "/too-long":
            self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if self.path == "/too-long":
            raw += b"unexpected-tail"
        elif self.path == "/truncated":
            raw = raw[:-1]
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ssl.SSLEOFError):
            pass  # The client deliberately cancels rejected/slow responses.


def serve(root, ready):
    certificate(root)
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, root=root))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / "tls-cert.pem", root / "tls-key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    ready.write_text(json.dumps({"url": f"https://127.0.0.1:{server.server_port}"}), encoding="utf-8")
    server.serve_forever(poll_interval=0.05)


class FixtureTests(unittest.TestCase):
    def test_certificate_has_only_loopback_names(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate(root)
            cert = x509.load_pem_x509_certificate((root / "tls-cert.pem").read_bytes())
            names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            self.assertEqual(names.get_values_for_type(x509.DNSName), ["localhost"])
            self.assertEqual(names.get_values_for_type(x509.IPAddress), [ipaddress.ip_address("127.0.0.1")])


if __name__ == "__main__":
    import sys
    if "--serve" in sys.argv:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--serve", action="store_true")
        parser.add_argument("--root", type=Path, required=True)
        parser.add_argument("--ready", type=Path, required=True)
        args = parser.parse_args()
        serve(args.root, args.ready)
    else:
        unittest.main()
