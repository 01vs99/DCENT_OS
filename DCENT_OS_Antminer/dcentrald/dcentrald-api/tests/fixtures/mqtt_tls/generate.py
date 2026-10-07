"""Regenerate public, self-authored TLS test credentials; never use for a service."""

from pathlib import Path
import subprocess
import tempfile


def main():
    destination = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="dcent-mqtt-test-certs-") as directory:
        work = Path(directory)

        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=work, check=True, capture_output=True)

        for name in ["ca", "untrusted-ca"]:
            openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.pem", "-days", "3650",
                    "-subj", f"/CN=DCENT MQTT TEST ONLY {name}", "-addext", "basicConstraints=critical,CA:TRUE")
            openssl("x509", "-in", f"{name}.pem", "-outform", "DER", "-out", str(destination / f"{name}.der"))
        openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", "server.key", "-out", "server.csr", "-subj", "/CN=broker.example")
        (work / "extensions.cnf").write_text(
            "subjectAltName=DNS:broker.example\nbasicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n", encoding="ascii")
        openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-CAcreateserial", "-out", "server.pem", "-days", "3650", "-extfile", "extensions.cnf")
        openssl("x509", "-in", "server.pem", "-outform", "DER", "-out", str(destination / "server.der"))
        openssl("pkcs8", "-topk8", "-nocrypt", "-in", "server.key", "-outform", "DER",
                "-out", str(destination / "server-key.der"))
    print("Generated TEST-ONLY credentials for broker.example; CA private keys discarded.")


if __name__ == "__main__":
    main()
