#!/usr/bin/env python3
"""
DCENTos Web Dashboard — Lightweight HTTP Server + API
D-Central Technologies, 2026

Serves the web dashboard and provides JSON API endpoints for system status,
fan control, FPGA monitoring, and hardware diagnostics.

Serves HTTPS on port 443 and redirects HTTP on release/password-protected images.
Uses ThreadingMixIn for non-blocking request handling.

API Endpoints:
  GET  /api/status    — Full system status (JSON)
  GET  /api/health    — Simple alive check
  GET  /api/fan       — Fan status (PWM + RPM)
  POST /api/fan       — Set fan speed (AM2 home cap 0-30, legacy S9 fallback 0-127)
  GET  /              — Dashboard HTML page
  GET  /static/*      — Static assets

Future: CGMiner-compatible API on port 4028 for pyasic compatibility.
"""

import http.server
import http.client
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
import socket
import ssl
import argparse
from http.server import HTTPServer
from socketserver import ThreadingMixIn
from pathlib import Path

# dcentrald reverse proxy target
DCENTRALD_HOST = "127.0.0.1"
DCENTRALD_PORT = 8080
DASHBOARD_PROXY_HEADER = "X-Dcentos-Dashboard-Proxy"
RELEASE_IMAGE_MARKER = "/etc/dcentos/release-image"
AUTH_CHECK_PATH = "/api/debug/log?lines=1"
AUTH_FILE = "/data/dcent/auth.json"

# SEC-W24-1: per-boot dashboard-proxy trust nonce.
#
# The daemon (auth.rs) treats a loopback request carrying this header as a
# trusted same-host proxy and bypasses bearer auth. The header VALUE used to be
# the static string "1", which is forgeable by any LAN client (we have no auth
# of our own on :80). S80dashboard now mints a random per-boot secret into a
# root-only tmpfs file before launching us; we read it and send it as the
# header value. On a PRODUCTION/release image the daemon rejects anything that
# isn't this exact nonce. On a DEV/LAB image (no release marker) the daemon
# still accepts the legacy "1", so when the file is unreadable we fall back to
# "1" and dev behaviour is byte-identical to before.
PROXY_NONCE_FILE = "/run/dcentos/proxy_nonce"
_PROXY_NONCE_CACHE = {"value": None, "loaded": False}


def proxy_header_value():
    """Return the dashboard-proxy header value to forward to dcentrald.

    Reads the per-boot nonce minted by S80dashboard. Cached for the process
    lifetime (the file is stable for the boot). Falls back to the legacy
    static "1" if the file is missing/unreadable so DEV images keep working
    byte-identically — on a release image the daemon rejects "1" anyway.
    """
    if not _PROXY_NONCE_CACHE["loaded"]:
        value = "1"
        try:
            with open(PROXY_NONCE_FILE, "r") as fh:
                nonce = fh.read().strip()
            if nonce:
                value = nonce
        except OSError:
            pass
        _PROXY_NONCE_CACHE["value"] = value
        _PROXY_NONCE_CACHE["loaded"] = True
    return _PROXY_NONCE_CACHE["value"]


def release_image():
    """Return true for production/release images."""
    return os.path.exists(RELEASE_IMAGE_MARKER)


TLS_DIR = Path("/data/dcent/tls")
SESSION_COOKIE = "__Host-dcent_session"


def password_state_exists():
    """Any credential state closes plain HTTP, including corrupt/symlink state."""
    try:
        os.lstat(AUTH_FILE)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return True


def _private_path(path, directory=False):
    import stat
    info = path.lstat()
    kind_ok = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not kind_ok or (not directory and info.st_nlink != 1):
        raise RuntimeError("TLS material must use private, direct filesystem paths")
    if os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
        raise RuntimeError("TLS material must be owned by the service user and private")


def verify_persistent_tls_storage(tls_dir):
    """Observe the current data owner and writable persistent backing before key I/O."""
    data = Path("/data")
    if Path(tls_dir) != TLS_DIR or data.is_symlink() or not data.is_dir():
        raise RuntimeError("Device TLS requires the canonical persistent data directory")
    target = Path("/etc/dcentos/board_target").read_text(encoding="ascii").strip()
    helpers = {
        "am3-s19jpro-aml": ("/usr/libexec/dcentos/classic-aml-storage.py", "check"),
        "am3-s19jproa": ("/usr/libexec/dcentos/bm1362-nopic-storage.py", "check"),
        "am3-s19jproplus": ("/usr/libexec/dcentos/bm1362-nopic-storage.py", "check"),
        "am3-s19k": ("/usr/sbin/dcent-s19k-data-mount", "verify"),
        "am3-s19kpro": ("/usr/sbin/dcent-s19k-data-mount", "verify"),
        "am3-aml-s19kpro": ("/usr/sbin/dcent-s19k-data-mount", "verify"),
    }
    native = Path("/usr/libexec/dcentos/native-zynq-sd-storage.py")
    command = helpers.get(target)
    if native.exists():
        command = (str(native), "--verify")
    if command is not None:
        helper = Path(command[0])
        if helper.is_symlink() or not helper.is_file():
            raise RuntimeError("Persistent data owner is unavailable")
        subprocess.run(list(command), check=True, timeout=15,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    actual = next(path for path in (Path(tls_dir), Path(tls_dir).parent, data) if path.exists())
    return persistent_data_mount(Path("/proc/self/mountinfo").read_text(), data.stat(), actual.stat())


def persistent_data_mount(text, data_stat, target_stat=None):
    """Join /data's actual filesystem device with its longest visible mount."""
    import stat
    target_stat = target_stat or data_stat
    candidates = []
    for line in text.splitlines():
        fields = line.split()
        try:
            sep = fields.index("-")
            point = fields[4]
            if point not in ("/", "/data", "/data/dcent", "/data/dcent/tls"):
                continue
            candidates.append((len(point), fields, sep))
        except (ValueError, IndexError):
            raise RuntimeError("Malformed persistent storage mount information")
    if not candidates:
        raise RuntimeError("Persistent /data mount is absent")
    _, fields, sep = max(candidates, key=lambda item: (item[0], int(item[1][0])))
    filesystem, source = fields[sep + 1:sep + 3]
    if (filesystem not in ("ext2", "ext3", "ext4", "f2fs", "xfs", "btrfs", "jffs2", "ubifs")
            or "rw" not in fields[5].split(",") or "rw" not in fields[sep + 3].split(",")):
        raise RuntimeError("TLS requires writable persistent storage, not volatile/root-image backing")
    major, minor = (int(value) for value in fields[2].split(":"))
    if (os.major(target_stat.st_dev), os.minor(target_stat.st_dev)) != (major, minor):
        raise RuntimeError("Persistent /data device does not match its current mount")
    if not stat.S_ISDIR(data_stat.st_mode):
        raise RuntimeError("Persistent /data is not a directory")
    if not (source.startswith("/dev/") or re.fullmatch(r"ubi[0-9]+:[A-Za-z0-9_-]+", source)):
        raise RuntimeError("Persistent data mount has no recognized device owner")
    return (data_stat.st_dev, data_stat.st_ino, fields[0], fields[2], fields[3], filesystem, source)


def load_device_tls(tls_dir=TLS_DIR, verify_storage=verify_persistent_tls_storage):
    """Create one private atomic key/cert bundle at first boot; never rotate silently."""
    import secrets
    import tempfile
    tls_dir = Path(tls_dir).absolute()
    storage_owner = verify_storage(tls_dir)
    # Reject indirect ancestors before creating or opening any private material.
    for parent in reversed((tls_dir,) + tuple(tls_dir.parents)):
        if parent.is_symlink():
            raise RuntimeError("TLS directory cannot traverse a symbolic link")
    tls_dir.parent.mkdir(mode=0o700, exist_ok=True)
    _private_path(tls_dir.parent, directory=True)
    tls_dir.mkdir(mode=0o700, exist_ok=True)
    _private_path(tls_dir, directory=True)
    bundle = tls_dir / "dashboard.pem"
    if not os.path.lexists(bundle):
        # Exclusive generation directory and atomic publication prevent partial
        # key/cert pairs after a reboot. No firmware image contains this key.
        draft = Path(tempfile.mkdtemp(prefix=".generate-", dir=tls_dir))
        key, cert, config = (draft / name for name in ("key.pem", "cert.pem", "openssl.cnf"))
        try:
            name = "dcentos-" + secrets.token_hex(8)
            hostname = socket.gethostname().rstrip(".")
            names = [name + ".local", "localhost"]
            if re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}", hostname):
                names.append(hostname)
                if "." not in hostname:
                    names.append(hostname + ".local")
            config.write_text(
                "[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n"
                "[dn]\nCN=" + name + "\n[ext]\nsubjectAltName="
                + ",".join("DNS:" + n for n in names) + ",IP:127.0.0.1,IP:::1\n"
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\n", encoding="ascii")
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-sha256", "-days", "3650", "-config", str(config),
                "-keyout", str(key), "-out", str(cert),
            ], check=True, timeout=45, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            pem = key.read_bytes() + cert.read_bytes()
            staged = draft / "dashboard.pem"
            fd = os.open(str(staged), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(pem)
                output.flush()
                os.fsync(output.fileno())
            # Validate before publishing. Corrupt existing material is never replaced.
            probe = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            probe.load_cert_chain(str(staged))
            # Hard-link publication is exclusive: concurrent starts cannot rotate a
            # certificate that another process has already begun serving.
            if verify_storage(tls_dir) != storage_owner:
                raise RuntimeError("Persistent data owner changed during TLS generation")
            try:
                os.link(staged, bundle)
            except FileExistsError:
                pass
            staged.unlink()
            if os.name == "posix":
                fd = os.open(str(tls_dir), os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        finally:
            # Only known files created in this private directory; never recurse.
            for name in ("key.pem", "cert.pem", "openssl.cnf", "dashboard.pem"):
                (draft / name).unlink(missing_ok=True)
            draft.rmdir()
    if verify_storage(tls_dir) != storage_owner:
        raise RuntimeError("Persistent data owner changed before TLS load")
    _private_path(bundle)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(bundle))
    pem = bundle.read_text(encoding="ascii")
    match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
    if not match:
        raise RuntimeError("TLS bundle has no certificate")
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(match.group(0))).hexdigest()
    return context, {"enabled": True, "certificate_sha256": fingerprint, "algorithm": "sha256"}


def tls_session_cookie(token):
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,256}", token):
        raise ValueError("Invalid session token")
    return SESSION_COOKIE + "=" + token + "; Path=/; Secure; HttpOnly; SameSite=Strict"


def same_origin(origin, host, scheme="https"):
    from urllib.parse import urlsplit
    try:
        source, target = urlsplit(origin), urlsplit(scheme + "://" + host)
        default = 443 if scheme == "https" else 80
        return (source.scheme == scheme and source.hostname == target.hostname
                and (source.port or default) == (target.port or default)
                and not source.username and not source.password
                and source.path in ("", "/") and not source.query and not source.fragment
                and host_header_is_allowed(host))
    except ValueError:
        return False


def cookie_bearer(headers):
    from http.cookies import SimpleCookie, CookieError
    try:
        cookies = SimpleCookie()
        cookies.load(headers.get("Cookie", ""))
        item = cookies.get(SESSION_COOKIE)
        if item and re.fullmatch(r"[A-Za-z0-9_-]{20,256}", item.value):
            return "Bearer " + item.value
    except CookieError:
        pass
    return None


def _strip_host_port(host):
    """Strip :port from Host / Origin host. Default :80 must match a bare host."""
    host = (host or "").strip().rstrip(".")
    if host.startswith("["):
        end = host.find("]")
        if end != -1:
            return host[1:end]
    if ":" in host and host.count(":") == 1:
        name, port = host.rsplit(":", 1)
        if name and port.isdigit():
            return name
    return host


def _is_loopback_or_literal_ip(host):
    if host.lower() == "localhost":
        return True
    try:
        import ipaddress
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_mdns_local(host):
    labels = host.rsplit(".", 1)
    return bool(labels) and labels[-1].lower() == "local"


def _extra_csrf_hosts():
    raw = os.environ.get("DCENT_CSRF_ALLOWED_HOSTS", "")
    return [part.strip() for part in raw.split(",") if part.strip()]


def host_header_is_allowed(host):
    """Parity with dcentrald-api csrf_allowlist.rs. Origin==Host is not enough."""
    from urllib.parse import urlsplit
    try:
        parsed = urlsplit("https://" + (host or ""))
        if (parsed.path or parsed.query or parsed.fragment or parsed.username
                or parsed.password or not parsed.hostname or any(c.isspace() for c in host)):
            return False
        _ = parsed.port  # Validate range and syntax even though the allowlist is host-only.
        host = parsed.hostname
    except ValueError:
        return False
    if _is_loopback_or_literal_ip(host) or _is_mdns_local(host):
        return True
    bare = host.lower()
    return any(_strip_host_port(extra).lower() == bare for extra in _extra_csrf_hosts())


def cors_origin_allowed(origin, host):
    """Only a matching HTTP(S) authority can receive browser CORS headers."""
    if not origin or not host:
        return False
    scheme = "https" if origin.startswith("https://") else "http"
    return same_origin(origin, host, scheme)


def cors_allow_origin_value(headers):
    origin = headers.get("Origin") if headers else None
    host = headers.get("Host") if headers else None
    if cors_origin_allowed(origin, host):
        return origin
    return None


_WALLET_RE = re.compile(r"\b(bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")


def mask_wallet_lines(lines):
    """Redact bech32/base58 payout-shaped strings in local dashboard logs."""
    out = []
    for line in lines:
        out.append(_WALLET_RE.sub(lambda m: m.group(0)[:6] + "…" + m.group(0)[-4:], line))
    return out


def bearer_auth_header(headers):
    """Extract a Bearer Authorization header from an HTTP header mapping."""
    value = headers.get("Authorization")
    if not value or not value.startswith("Bearer "):
        return None
    return value


def build_dcentrald_proxy_headers(headers, client_ip, encrypted=False):
    """Build headers for the dcentrald reverse proxy.

    Do not stamp DASHBOARD_PROXY_HEADER here. server.py is LAN-facing and has no
    auth database of its own; adding the root-only loopback nonce to every
    proxied request turns the dashboard into a confused deputy. Normal browser
    traffic must authenticate with the real Bearer token, which is forwarded
    below when present.
    """
    out = {}
    for name in ("Authorization", "Accept", "Content-Type", "Origin", "Referer", "Sec-Fetch-Site"):
        value = headers.get(name)
        if value:
            out[name] = value
    host = headers.get("Host")
    if host:
        out["Host"] = host
        out["X-Forwarded-Host"] = host
    out["X-Forwarded-For"] = client_ip
    out["X-Forwarded-Proto"] = "https" if encrypted else "http"
    return out


def validate_bearer_with_dcentrald(auth_header):
    """Check a Bearer token against a protected read-only daemon endpoint."""
    conn = None
    try:
        conn = http.client.HTTPConnection(DCENTRALD_HOST, DCENTRALD_PORT, timeout=3)
        conn.request(
            "GET",
            AUTH_CHECK_PATH,
            headers={"Authorization": auth_header, "Accept": "application/json"},
        )
        resp = conn.getresponse()
        resp.read()
        return 200 <= resp.status < 300
    except Exception:
        return None
    finally:
        if conn is not None:
            conn.close()


def bearer_token(auth_header):
    """Extract the token string from a Bearer Authorization value."""
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header[len("Bearer "):].strip()
    return token or None


def _session_unexpired(session):
    expires_at = str(session.get("expires_at") or "").strip()
    if not expires_at:
        return True
    try:
        return int(expires_at) > int(time.time())
    except ValueError:
        return False


def bearer_authorized_by_auth_file(auth_header):
    """Fallback token check for local controls when dcentrald is down."""
    token = bearer_token(auth_header)
    if not token:
        return False
    try:
        with open(AUTH_FILE, "r", encoding="utf-8") as f:
            auth = json.load(f)
    except Exception:
        return False

    legacy = str(auth.get("api_token") or "")
    if legacy and hmac.compare_digest(token, legacy):
        return True

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    for session in auth.get("sessions") or []:
        if not isinstance(session, dict):
            continue
        if str(session.get("revoked_at") or "").strip():
            continue
        if str(session.get("role") or "admin") != "admin":
            continue
        if not _session_unexpired(session):
            continue
        if hmac.compare_digest(str(session.get("token_hash") or ""), token_hash):
            return True
    return False


def local_control_authorized(headers):
    """Authorize server.py's local POST controls."""
    if not release_image() and not password_state_exists():
        return True
    auth_header = bearer_auth_header(headers)
    if not auth_header:
        return False
    daemon_verdict = validate_bearer_with_dcentrald(auth_header)
    if daemon_verdict is not None:
        return daemon_verdict
    return bearer_authorized_by_auth_file(auth_header)

VERSION_FILE = Path("/etc/dcentos-version")
VERSION = VERSION_FILE.read_text().strip() if VERSION_FILE.exists() else "dev"
WEB_DIR = Path(__file__).parent
STATIC_DIR = WEB_DIR / "static"
# W5.1 (2026-05-07): canonical dashboard SPA install path. The Buildroot
# post-build hook copies DCENT_OS_Antminer/dashboard/dist/index.html here
# instead of into the daemon binary (`include_str!` was retired). Falls
# back to STATIC_DIR / index.html so partial upgrades still serve a UI.
DASHBOARD_DIR = Path("/usr/share/dcentos-dashboard")
DASHBOARD_INDEX = DASHBOARD_DIR / "index.html"
DASHBOARD_BANNER_TAG = b'<script src="/static/diagnostic-banner.js" defer></script>'
DASHBOARD_LEGACY_BANNER_TAG = b'<script src="/static/diagnostic-banner.js"></script>'
START_TIME = time.time()

# dcentrald log file (used by /api/dashboard/health to surface tail to the UI)
DCENTRALD_LOG = "/tmp/dcentrald.log"
DCENTRALD_PIDFILE = "/var/run/dcentrald.pid"
DCENTRALD_CHILD_PIDFILE = "/var/run/dcentrald-child.pid"

def _dashboard_sidecar(path, suffix):
    return Path(str(path) + suffix)


def _accepts_gzip(header_value):
    for part in str(header_value or "").split(","):
        bits = [item.strip() for item in part.split(";")]
        token = bits[0].lower()
        if token not in ("gzip", "*"):
            continue
        q = 1.0
        for param in bits[1:]:
            if not param.lower().startswith("q="):
                continue
            try:
                q = float(param.split("=", 1)[1])
            except ValueError:
                q = 0.0
        if q > 0:
            return True
    return False


def _dashboard_sha256(path):
    try:
        raw = _dashboard_sidecar(path, ".sha256").read_text().strip().split()[0]
    except (FileNotFoundError, IndexError, OSError):
        return None
    if re.fullmatch(r"[0-9a-fA-F]{64}", raw):
        return raw.lower()
    return None


def _etag_matches(header_value, etag):
    for item in str(header_value or "").split(","):
        token = item.strip()
        if token == "*" or token == etag:
            return True
    return False

def run_cmd(cmd, timeout=3):
    """Run a shell command and return stdout, or empty string on failure."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except Exception:
        return ""
















def read_sysfs(path):
    """Read a sysfs file, return stripped text or empty string."""
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except Exception:
        return ""














def get_dcentrald_pid():
    """Return dcentrald PID if running, else None.

    Tries the child pidfile first (the actual binary, not the wrapper shell),
    then the wrapper pidfile, then falls back to `pidof`.
    """
    for pidfile in (DCENTRALD_CHILD_PIDFILE, DCENTRALD_PIDFILE):
        try:
            with open(pidfile, "r") as f:
                pid = int(f.read().strip())
            if pid > 0:
                # /proc check — confirms the pid is actually alive
                if os.path.isdir(f"/proc/{pid}"):
                    # Sanity: only count it if cmdline contains "dcentrald".
                    try:
                        with open(f"/proc/{pid}/cmdline", "rb") as cf:
                            cmdline = cf.read().decode("utf-8", "replace")
                        if "dcentrald" in cmdline:
                            return pid
                    except Exception:
                        return pid  # cmdline unreadable — trust the pidfile
        except Exception:
            pass

    # Fallback: pidof
    raw = run_cmd("pidof dcentrald", timeout=2)
    if raw:
        try:
            # pidof can return multiple — take first
            return int(raw.split()[0])
        except (ValueError, IndexError):
            return None
    return None


def get_dcentrald_uptime(pid):
    """Best-effort dcentrald uptime in seconds, derived from /proc/<pid>/stat."""
    if not pid:
        return None
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            fields = f.read().split()
        # field 22 (1-indexed) = starttime in clock ticks since boot
        starttime_ticks = int(fields[21])
        clk_tck_raw = run_cmd("getconf CLK_TCK 2>/dev/null", timeout=1)
        try:
            clk_tck = int(clk_tck_raw) if clk_tck_raw else 100
        except ValueError:
            clk_tck = 100
        with open("/proc/uptime", "r") as f:
            sys_uptime = float(f.read().split()[0])
        proc_uptime = sys_uptime - (starttime_ticks / clk_tck)
        return max(0, int(proc_uptime))
    except Exception:
        return None


def tail_log(path, lines=20):
    """Cheap log tail. Returns list of last N lines (empty list on failure)."""
    try:
        out = run_cmd(f"tail -n {int(lines)} {path} 2>/dev/null", timeout=2)
        if not out:
            return []
        return [ln for ln in out.split("\n") if ln]
    except Exception:
        return []


def _probe_dcentrald_api():
    """Quick TCP probe of dcentrald HTTP API on DCENTRALD_HOST:DCENTRALD_PORT.

    Returns True only if a TCP connection succeeds within 500ms. The dashboard
    needs the proxy to actually be reachable; a process that's alive but never
    bound :8080 (e.g. S19j hybrid mode short-circuits daemon.rs::run()) should
    NOT be reported as alive — otherwise the React app stops showing the
    graceful-degrade banner and races against /api/* 503 responses.
    """
    try:
        with socket.create_connection((DCENTRALD_HOST, DCENTRALD_PORT), timeout=0.5):
            return True
    except (OSError, socket.timeout):
        return False


def _last_error_line(log_lines):
    """Return the last line containing 'ERROR' or 'error=' from log tail."""
    for ln in reversed(log_lines):
        if "ERROR" in ln or "error=" in ln:
            return ln
    return None


def get_braiins_glitch_mirror():
    """Report unavailable until dcentrald publishes this FPGA snapshot."""
    return {
        "status": "unavailable",
        "source": "dcentrald snapshot",
        "hardware_access_attempted": False,
        "reason": "Braiins glitch-mirror registers are not published by the runtime owner.",
    }


def get_slot_info():
    """U-Boot env: which firmware slot is active + upgrade_stage."""
    out = {}
    for var in ("firmware", "upgrade_stage"):
        v = run_cmd(f"fw_printenv -n {var} 2>/dev/null", timeout=1)
        out[var] = v if v else None
    return out


def get_network_info():
    """Hostname + first non-loopback IPv4 + MAC."""
    hostname = run_cmd("hostname 2>/dev/null", timeout=1) or "unknown"
    ip_out = run_cmd("ip -4 -o addr show eth0 2>/dev/null", timeout=1)
    ip = None
    if ip_out:
        parts = ip_out.split()
        if len(parts) >= 4:
            ip = parts[3].split("/")[0]
    mac = read_sysfs("/sys/class/net/eth0/address").upper() or None
    return {"hostname": hostname, "ip": ip, "mac": mac}


_VERSION_CACHE = {"text": None, "ts": 0}
_VERSION_CACHE_TTL = 30


def get_dcentrald_version():
    """Cached `dcentrald --version` head (refreshes every 30s)."""
    now = time.time()
    if _VERSION_CACHE["text"] and (now - _VERSION_CACHE["ts"]) < _VERSION_CACHE_TTL:
        return _VERSION_CACHE["text"]
    raw = run_cmd("/usr/local/bin/dcentrald --version 2>&1 | head -3", timeout=2)
    if not raw:
        # Try /tmp/dcentrald.new (developer overlay binary)
        raw = run_cmd("/tmp/dcentrald.new --version 2>&1 | head -3", timeout=2)
    _VERSION_CACHE["text"] = raw or None
    _VERSION_CACHE["ts"] = now
    return _VERSION_CACHE["text"]


def get_dashboard_health():
    """Return the daemon-health JSON used by the React banner.

    This endpoint is served by server.py directly (not proxied), so it works
    even when dcentrald is dead — which is exactly when the dashboard needs it.
    Health = (process is up) AND (REST API actually bound and accepting TCP).

    Diagnostic surface (added 2026-04-29 per .74 fw=0x86 live test): when
    dcentrald is dead, the dashboard relies on these fields to show what
    state the unit is in without requiring SSH.
    """
    pid = get_dcentrald_pid()
    uptime_s = get_dcentrald_uptime(pid)
    api_bound = _probe_dcentrald_api() if pid is not None else False
    log_lines = tail_log(DCENTRALD_LOG, lines=50)
    if pid is None:
        dcentrald_status = "dead"
    elif api_bound:
        dcentrald_status = "alive"
    else:
        dcentrald_status = "starting"
    return {
        "alive": pid is not None and api_bound,
        "pid": pid,
        "uptime_s": uptime_s,
        "api_bound": api_bound,
        "dcentrald_status": dcentrald_status,
        "last_log_lines": log_lines,  # legacy field, kept for compat
        "dcentrald_log_tail": log_lines,
        "dcentrald_last_error": _last_error_line(log_lines),
        "slot": get_slot_info(),
        "network": get_network_info(),
        "braiins_glitch_mirror": get_braiins_glitch_mirror(),
        "dcentrald_version": get_dcentrald_version(),
        "last_health_probe_ts": int(time.time()),
        "version": VERSION,
    }


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread — prevents blocking on slow probes."""
    daemon_threads = True
    max_connections = 16

    def __init__(self, *args, **kwargs):
        import threading
        self.connection_slots = threading.BoundedSemaphore(self.max_connections)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.connection_slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.connection_slots.release()
            request.close()
            raise

    def process_request_thread(self, request, client_address):
        # TLS handshakes run in the request worker with a deadline; one client
        # that never sends ClientHello cannot stall the listening socket.
        try:
            request.settimeout(15)
            context = getattr(self, "tls_context", None)
            if context is not None:
                request = context.wrap_socket(request, server_side=True)
            super().process_request_thread(request, client_address)
        except (OSError, ssl.SSLError):
            request.close()
        finally:
            self.connection_slots.release()


def create_tls_server(address, context, info):
    server = ThreadedHTTPServer(address, DCENTosHandler)
    server.tls_context = context
    server.tls_info = info
    return server


class DCENTosHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP request handler with API endpoints + reverse proxy to dcentrald."""
    protocol_version = "HTTP/1.1"
    request_body_timeout = 120

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def parse_request(self):
        if not super().parse_request():
            return False
        host = self.headers.get("Host", "")
        if not host_header_is_allowed(host) or len(self.headers.get_all("Host", [])) != 1:
            self.send_error(403, "Invalid dashboard Host")
            return False
        encrypted = isinstance(self.connection, ssl.SSLSocket)
        if not encrypted and (release_image() or password_state_exists()
                              or not self.path.startswith("/api/")
                              or self.path.split("?", 1)[0].startswith("/api/auth/")):
            from urllib.parse import urlsplit
            hostname = urlsplit("http://" + host).hostname
            if not hostname:
                self.send_error(403)
                return False
            authority = "[" + hostname + "]" if ":" in hostname else hostname
            tls_port = getattr(self.server, "tls_port", 443)
            if tls_port != 443:
                authority += ":" + str(tls_port)
            self.send_response(308)
            # A path cannot replace the explicitly constructed authority.
            self.send_header("Location", "https://" + authority + "/" + self.path.lstrip("/"))
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return False
        origin = self.headers.get("Origin")
        scheme = "https" if encrypted else "http"
        if origin and not same_origin(origin, host, scheme):
            self.send_error(403, "Cross-origin dashboard request refused")
            return False
        if encrypted and not self.headers.get("Authorization"):
            authorization = cookie_bearer(self.headers)
            if authorization:
                # Cookies are ambient credentials. Unsafe methods require an
                # explicit same-origin browser proof; Bearer clients are unchanged.
                if self.command not in ("GET", "HEAD", "OPTIONS") and not origin:
                    self.send_error(403, "Cookie writes require same-origin Origin")
                    return False
                self.headers["Authorization"] = authorization
        if self.command in ("POST", "PUT", "PATCH", "DELETE"):
            self.request_body_length = self._body_length()
            if self.request_body_length is None:
                return False
        if getattr(self, "_expect_continue", False):
            self.send_response_only(100)
            super().end_headers()
            self._expect_continue = False
        return True

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        if isinstance(self.connection, ssl.SSLSocket):
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        if self.path.startswith("/api/auth/") or self.path == "/api/tls/info":
            self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def handle_expect_100(self):
        # BaseHTTPRequestHandler calls this before our transport/Origin checks.
        # Delay Continue until those checks and body admission have succeeded.
        self._expect_continue = True
        return True

    def _body_length(self):
        fields = self.headers.get_all("Content-Length", [])
        if (len(fields) > 1 or self.headers.get("Transfer-Encoding")
                or (fields and not re.fullmatch(r"[0-9]{1,10}", fields[0]))):
            self.send_error(400, "Ambiguous or unsupported request framing")
            self.close_connection = True
            return None
        length = int(fields[0]) if fields else 0
        self.stream_upload = self.command == "POST" and self.path.split("?", 1)[0] in (
            "/api/system/upgrade", "/api/v1/system/upgrade", "/api/v1/firmware/update")
        limit = 128 * 1024 * 1024 if self.stream_upload else 2 * 1024 * 1024
        if length > limit:
            self.send_error(413, "Request body exceeds endpoint limit")
            self.close_connection = True
            return None
        if self.stream_upload:
            bearer = bearer_auth_header(self.headers)
            if not bearer or validate_bearer_with_dcentrald(bearer) is not True:
                self.send_error(401, "Firmware upload requires an authenticated session")
                self.close_connection = True
                return None
        return length

    def _body_chunks(self):
        remaining = self.request_body_length
        deadline = time.monotonic() + self.request_body_timeout
        while remaining:
            budget = deadline - time.monotonic()
            if budget <= 0:
                raise TimeoutError("Request body deadline exceeded")
            self.connection.settimeout(min(15, budget))
            # read() may repeat raw reads until this whole chunk is filled,
            # allowing a slow sender to renew the socket timeout indefinitely.
            # read1() preserves buffered bytes but performs at most one raw read
            # before returning to the absolute deadline check.
            chunk = self.rfile.read1(min(65536, remaining))
            if not chunk:
                raise ConnectionError("Request body ended early")
            remaining -= len(chunk)
            yield chunk

    def _forward_mutation(self):
        body = b"".join(self._body_chunks())
        if self.path.startswith("/api/"):
            if not self._proxy_to_dcentrald(self.command, body):
                self._send_disconnect_json("dcentrald not reachable on 127.0.0.1:8080")
        else:
            self.send_error(404)

    do_DELETE = _forward_mutation
    do_PUT = _forward_mutation
    do_PATCH = _forward_mutation

    def _proxy_websocket(self):
        """Relay authenticated WebSocket bytes through the same TLS endpoint."""
        import base64
        import select
        if self.headers.get("Upgrade", "").lower() != "websocket":
            self.send_error(400, "WebSocket upgrade required")
            return
        key = self.headers.get("Sec-WebSocket-Key", "")
        try:
            if len(base64.b64decode(key, validate=True)) != 16:
                raise ValueError("invalid key")
        except ValueError:
            self.send_error(400, "Invalid WebSocket key")
            return
        upstream = None
        upgraded = False
        try:
            headers = build_dcentrald_proxy_headers(
                self.headers, self.client_address[0], isinstance(self.connection, ssl.SSLSocket))
            for name in ("Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Protocol"):
                if self.headers.get(name):
                    headers[name] = self.headers[name]
            headers.update({"Upgrade": "websocket", "Connection": "Upgrade"})
            if any("\r" in value or "\n" in value for value in headers.values()):
                self.send_error(400)
                return
            request = "GET " + self.path + " HTTP/1.1\r\n" + "".join(
                name + ": " + value + "\r\n" for name, value in headers.items()) + "\r\n"
            upstream = socket.create_connection((DCENTRALD_HOST, DCENTRALD_PORT), timeout=10)
            upstream.sendall(request.encode("latin-1"))
            received = bytearray()
            while b"\r\n\r\n" not in received:
                data = upstream.recv(4096)
                if not data or len(received) + len(data) > 65536:
                    raise ValueError("Invalid upstream WebSocket response")
                received.extend(data)
            head, tail = bytes(received).split(b"\r\n\r\n", 1)
            lines = head.decode("latin-1").split("\r\n")
            status = int(lines[0].split()[1])
            fields = {}
            for line in lines[1:]:
                name, value = line.split(":", 1)
                fields[name.lower()] = value.strip()
            if status != 101:
                self.send_error(status if status in (400, 401, 403, 429) else 502)
                return
            expected = base64.b64encode(hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()).decode("ascii")
            if (fields.get("sec-websocket-accept") != expected
                    or fields.get("upgrade", "").lower() != "websocket"):
                raise ValueError("Invalid upstream WebSocket handshake")
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", expected)
            if fields.get("sec-websocket-protocol"):
                self.send_header("Sec-WebSocket-Protocol", fields["sec-websocket-protocol"])
            self.end_headers()
            upgraded = True
            if tail:
                self.connection.sendall(tail)
            # Single worker owns both directions of the SSL object. Its
            # decrypted pending bytes must be drained before waiting on select.
            while True:
                pending = isinstance(self.connection, ssl.SSLSocket) and self.connection.pending()
                ready = [self.connection] if pending else select.select(
                    [self.connection, upstream], [], [], 60)[0]
                if not ready:
                    break
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    (upstream if source is self.connection else self.connection).sendall(data)
        except (OSError, ValueError, IndexError, UnicodeError):
            if not upgraded:
                self.send_error(502, "WebSocket backend unavailable")
        finally:
            if upstream is not None:
                upstream.close()
            self.close_connection = True

    def _proxy_to_dcentrald(self, method="GET", body=None):
        """Forward request to dcentrald on port 8080.

        Returns:
            True  — proxy succeeded, response already written.
            False — could not connect (handled by caller as graceful fallback).

        On unrecoverable proxy errors (read timeout, malformed response after
        connecting), we still return a 200 with `{_disconnected: true,
        _error: ...}` so the React client can detect the daemon-down state
        without throwing.
        """
        try:
            conn = http.client.HTTPConnection(DCENTRALD_HOST, DCENTRALD_PORT, timeout=10)
            headers = build_dcentrald_proxy_headers(
                self.headers, self.client_address[0], isinstance(self.connection, ssl.SSLSocket))
            if getattr(self, "stream_upload", False) and method == "POST":
                headers["Content-Length"] = str(self.request_body_length)
            conn.request(method, self.path, body=body, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read()

            encrypted = isinstance(self.connection, ssl.SSLSocket)
            cookie = None
            route = self.path.split("?", 1)[0]
            if encrypted and 200 <= resp.status < 300:
                if method == "POST" and route in ("/api/auth/setup", "/api/auth/session"):
                    try:
                        token = json.loads(resp_body).get("session_token")
                        if token:
                            cookie = tls_session_cookie(token)
                    except (ValueError, TypeError, AttributeError):
                        pass
                elif method == "DELETE" and route == "/api/auth/session/current":
                    cookie = SESSION_COOKIE + "=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"
            if route in ("/api/info", "/api/system/info") and resp.status == 200:
                try:
                    info = json.loads(resp_body)
                    if isinstance(info, dict):
                        info["tls"] = getattr(self.server, "tls_info", {"enabled": False})
                        resp_body = json.dumps(info).encode("utf-8")
                except (ValueError, TypeError):
                    pass
            self.send_response(resp.status)
            if cookie:
                self.send_header("Set-Cookie", cookie)
            if resp.getheader("Cache-Control"):
                self.send_header("Cache-Control", resp.getheader("Cache-Control"))
            self.send_header("Content-Type", resp.getheader("Content-Type", "application/json"))
            self.send_header("Content-Length", len(resp_body))
            self.end_headers()
            self.wfile.write(resp_body)
            conn.close()
            return True
        except (ConnectionRefusedError, ConnectionResetError, socket.timeout, OSError):
            # dcentrald not listening or hung — let caller handle fallback.
            return False
        except Exception:
            return False

    def _send_disconnect_json(self, reason):
        """Return a 503 with a JSON disconnect marker the React client recognises."""
        body = {
            "_disconnected": True,
            "_error": reason,
            "_path": self.path,
            "_ts": int(time.time()),
        }
        self.send_json(body, status=503)

    def do_GET(self):
        if self.path.split("?", 1)[0] == "/ws":
            self._proxy_websocket()
            return
        if self.path == "/api/tls/info":
            self.send_json(getattr(self.server, "tls_info", {"enabled": False}))
            return
        if self.path.startswith("/api/"):
            # ALWAYS-LOCAL endpoints — must work even when dcentrald is dead.
            # That's the whole point of the diagnostic dashboard.
            if self.path == "/api/dashboard/health":
                self.send_json(get_dashboard_health())
                return
            if self.path.startswith("/api/dashboard/log"):
                # /api/dashboard/log?lines=N (default 100, max 1000)
                if not local_control_authorized(self.headers):
                    self.send_json({"error": "unauthorized"}, status=401)
                    return
                lines = 100
                if "?" in self.path:
                    qs = self.path.split("?", 1)[1]
                    for kv in qs.split("&"):
                        if kv.startswith("lines="):
                            try:
                                lines = max(1, min(1000, int(kv.split("=", 1)[1])))
                            except ValueError:
                                pass
                self.send_json({
                    "lines": mask_wallet_lines(tail_log(DCENTRALD_LOG, lines=lines)),
                    "path": DCENTRALD_LOG,
                    "ts": int(time.time()),
                })
                return
            if self.path == "/api/dashboard/probe":
                if not local_control_authorized(self.headers):
                    self.send_json({"error": "unauthorized"}, status=401)
                    return
                # Full diagnostic snapshot — same data as health but explicit
                self.send_json({
                    "braiins_glitch_mirror": get_braiins_glitch_mirror(),
                    "slot": get_slot_info(),
                    "network": get_network_info(),
                    "dcentrald_version": get_dcentrald_version(),
                    "ts": int(time.time()),
                })
                return
            # Try forwarding to dcentrald first; fall back to local handlers
            if self._proxy_to_dcentrald("GET"):
                return
            # Fallback: ALL /api/* return a structured disconnect marker.
            # Don't substitute server.py's own /api/status here — its schema
            # (chains as dict, no hashrate, no pool) doesn't match what the
            # dashboard expects from dcentrald (chains as array). The dashboard's
            # graceful-degrade client recognises `_disconnected: true` and
            # renders the DEAD banner; receiving a 200 with the wrong shape
            # causes a TypeError ("chains.find is not a function") that crashes
            # the React tree before the banner can mount.
            if self.path == "/api/health":
                # Cheap liveness check the operator can hit from curl —
                # server.py is up even when dcentrald isn't.
                self.send_json({"status": "alive", "version": VERSION})
            else:
                self._send_disconnect_json("dcentrald not reachable on 127.0.0.1:8080")
        elif self.path == "/" or self.path == "/index.html":
            # W5.1: prefer the canonical /usr/share/dcentos-dashboard/index.html
            # produced by Buildroot post-build (copy of dashboard/dist/index.html).
            # Fall back to the legacy STATIC_DIR copy so a partial overlay
            # (server.py refreshed but no dashboard rebuild yet) still serves
            # a UI rather than 404.
            if DASHBOARD_INDEX.exists():
                self.serve_file(DASHBOARD_INDEX, "text/html")
            else:
                self.serve_file(STATIC_DIR / "index.html", "text/html")
        elif self.path == "/diagnostic" or self.path == "/diagnostic.html":
            self.serve_file(STATIC_DIR / "diagnostic.html", "text/html")
        elif self.path == "/recovery" or self.path == "/recovery.html":
            # GROUP B: static daemon-down recovery page. Served directly by
            # server.py (no dcentrald dependency) so an operator hitting the web
            # port when the daemon is dead gets a self-contained recovery page
            # with SSH/restart/log/rollback guidance instead of a dead
            # connection. The default static handler (rooted at STATIC_DIR) also
            # serves the raw file at /recovery.html, so this route is a clean
            # alias. Mirrors how LuxOS/BraiinsOS serve a static fallback. The
            # banner-injection in serve_file() is skipped for this page (it
            # already shows the daemon-down state statically, no JS required).
            self.serve_file(STATIC_DIR / "recovery.html", "text/html")
        else:
            super().do_GET()

    def do_POST(self):
        if self.stream_upload:
            if not self._proxy_to_dcentrald("POST", self._body_chunks()):
                self._send_disconnect_json("Authenticated upload backend unavailable")
            return
        body = b"".join(self._body_chunks())

        if self.path.startswith("/api/"):
            # ALWAYS-LOCAL endpoints — work even when dcentrald is dead.
            if self.path == "/api/dashboard/restart-dcentrald":
                if not local_control_authorized(self.headers):
                    self.send_json({
                        "status": "unauthorized",
                        "error": "release image requires a valid Bearer token for dashboard-local control endpoints",
                    }, status=401)
                    return
                self.send_json({
                    "status": "manual_resolution_required",
                    "error": "automatic Amlogic restart is disabled; resolve electrical disposition through /recovery before a guarded start",
                }, status=409)
                return
            if self.path == "/api/dashboard/report-ip":
                if not local_control_authorized(self.headers):
                    self.send_json({
                        "status": "unauthorized",
                        "error": "release image requires a valid Bearer token for dashboard-local control endpoints",
                    }, status=401)
                    return
                # Trigger ip_reporter daemon (SIGUSR1) OR fall back to
                # one-shot subprocess if daemon isn't running.
                pid = None
                try:
                    with open("/var/run/ip_reporter.pid", "r") as f:
                        pid = int(f.read().strip())
                    os.kill(pid, 10)  # SIGUSR1
                    self.send_json({
                        "status": "broadcasting",
                        "method": "signal",
                        "pid": pid,
                        "ts": int(time.time()),
                    })
                    return
                except (FileNotFoundError, ProcessLookupError, ValueError, PermissionError) as e:
                    # Fall back to one-shot
                    try:
                        subprocess.Popen(
                            ["/usr/bin/python3", "/root/web/ip_reporter.py", "--once"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            start_new_session=True,
                        )
                        self.send_json({
                            "status": "broadcasting",
                            "method": "one-shot",
                            "fallback_reason": str(e),
                            "ts": int(time.time()),
                        })
                        return
                    except Exception as e2:
                        self.send_json({
                            "status": "error",
                            "error": str(e2),
                            "ts": int(time.time()),
                        }, status=500)
                        return
            # Try forwarding to dcentrald first
            if self._proxy_to_dcentrald("POST", body):
                return
            self._send_disconnect_json("dcentrald not reachable on 127.0.0.1:8080")
        else:
            self.send_error(404)

    def do_OPTIONS(self):
        """Handle CORS preflight for all paths."""
        self.send_response(200)
        self.send_header("Content-Length", "0")
        allow = cors_allow_origin_value(self.headers)
        if allow:
            self.send_header("Access-Control-Allow-Origin", allow)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def send_json(self, data, status=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        allow = cors_allow_origin_value(self.headers)
        if allow:
            self.send_header("Access-Control-Allow-Origin", allow)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)

    def serve_file(self, path, content_type):
        try:
            content = path.read_bytes()
            is_dashboard_html = content_type == "text/html" and path.name == "index.html"
            banner_baked = (not is_dashboard_html) or DASHBOARD_BANNER_TAG in content
            if is_dashboard_html and not banner_baked:
                if DASHBOARD_LEGACY_BANNER_TAG in content:
                    content = content.replace(DASHBOARD_LEGACY_BANNER_TAG, DASHBOARD_BANNER_TAG, 1)
                elif b'</body>' in content:
                    content = content.replace(b'</body>', DASHBOARD_BANNER_TAG + b'</body>', 1)
                else:
                    content = content + DASHBOARD_BANNER_TAG

            etag = None
            if is_dashboard_html and banner_baked:
                sha256 = _dashboard_sha256(path)
                if sha256:
                    gzip_path = _dashboard_sidecar(path, ".gz")
                    gzip_fresh = (
                        gzip_path.exists()
                        and gzip_path.stat().st_mtime >= path.stat().st_mtime
                    )
                    if (
                        gzip_fresh
                        and _accepts_gzip(self.headers.get("Accept-Encoding", ""))
                    ):
                        etag = '"' + sha256[:16] + '-gz"'
                        if _etag_matches(self.headers.get("If-None-Match", ""), etag):
                            self.send_response(304)
                            self.send_header("ETag", etag)
                            self.send_header("Cache-Control", "no-cache")
                            self.send_header("Vary", "Accept-Encoding")
                            self.end_headers()
                            return
                        content = gzip_path.read_bytes()
                        self.send_response(200)
                        self.send_header("Content-Type", content_type)
                        self.send_header("Content-Encoding", "gzip")
                        self.send_header("Content-Length", len(content))
                        self.send_header("ETag", etag)
                        self.send_header("Cache-Control", "no-cache")
                        self.send_header("Vary", "Accept-Encoding")
                        self.end_headers()
                        self.wfile.write(content)
                        return

                    etag = '"' + sha256[:16] + '"'
                    if _etag_matches(self.headers.get("If-None-Match", ""), etag):
                        self.send_response(304)
                        self.send_header("ETag", etag)
                        self.send_header("Cache-Control", "no-cache")
                        self.send_header("Vary", "Accept-Encoding")
                        self.end_headers()
                        return

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", len(content))
            if is_dashboard_html:
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Vary", "Accept-Encoding")
                if etag:
                    self.send_header("ETag", etag)
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(404)

    def log_message(self, format, *args):
        """Suppress default logging to stderr."""
        pass


def main():
    import threading
    parser = argparse.ArgumentParser(description="DCENTos HTTPS Dashboard")
    parser.add_argument("--port", type=int, default=80, help="HTTP redirect port (default: 80)")
    parser.add_argument("--tls-port", type=int, default=443, help="HTTPS port (default: 443)")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    args = parser.parse_args()

    # Establish a valid persistent device identity before opening either listener.
    context, info = load_device_tls()
    server = create_tls_server((args.bind, args.tls_port), context, info)
    redirect = None
    worker = None
    try:
        redirect = ThreadedHTTPServer((args.bind, args.port), DCENTosHandler)
        redirect.tls_port = args.tls_port
        worker = threading.Thread(target=redirect.serve_forever, daemon=True)
        worker.start()
        print("DCENTos Dashboard v{} â€” HTTPS :{}, HTTP redirect :{}".format(
            VERSION, args.tls_port, args.port), flush=True)
        print("  Certificate SHA-256: " + info["certificate_sha256"], flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if redirect is not None:
            if worker is not None:
                redirect.shutdown()
                worker.join(timeout=5)
            redirect.server_close()


if __name__ == "__main__":
    main()
