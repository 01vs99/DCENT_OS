"""Localhost Stratum V1 stub pool for the DCENT_OS emulation twin (emu-twin).

Serves mining.subscribe / mining.authorize / mining.notify /
mining.set_difficulty / mining.submit over newline-delimited JSON on TCP
(localhost only), tracks every job it issued, and validates every submitted
share by RECOMPUTING double-SHA256 of the reconstructed 80-byte header with
the stdlib ``hashlib`` — never by trusting the miner's claim.

Wire truth is mirrored from the production client this stub must fool:
``DCENT_OS_Antminer/dcentrald/dcentrald-stratum/src/v1/`` (codec.rs line
framing, messages.rs request/response shapes, mock_pool.rs handshake order,
difficulty.rs target math) and ``dcentrald-stratum/src/work.rs``
(header construction: coinbase -> merkle fold -> word-reversed prevhash ->
little-endian u32 fields).

Divergence from the production client (intentional, documented): the daemon's
``difficulty_to_target`` clamps any difficulty <= 1.0 to the pdiff-1 target
(2^224 - 1); this stub honors sub-1.0 difficulties with a proportionally
wider target so host-side scenario tests can find shares in milliseconds
with real sha256d work ("difficulty configurable down to trivially-low").
Difficulty seen by the real daemon inside QEMU must stay >= 1.0.

Standard-library only (Python 3.9+). Run directly for a standalone pool::

    py -3 stratum_stub.py --port 17001 --difficulty 0.0001
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import socket
import socketserver
import struct
import sys
import threading
import time
from typing import Dict, List, Optional, Sequence, Tuple

__version__ = "0.1.0"

# ---------------------------------------------------------------------------
# Constants mirrored from the production stratum crate
# ---------------------------------------------------------------------------

#: Mirror of ``dcentrald-stratum/src/v1/codec.rs`` MAX_LINE_LENGTH.
MAX_LINE_LENGTH = 16 * 1024

#: pdiff-1 target (pool difficulty 1) = 2^224 - 1, as a big integer.
#: Mirror of ``dcentrald-stratum/src/v1/difficulty.rs`` PDIFF1_TARGET.
PDIFF1_TARGET_INT = (1 << 224) - 1

#: BIP320 version-rolling mask the stub advertises via mining.configure.
DEFAULT_VERSION_MASK = 0x1FFFE000

#: Extranonce2 size the stub requests (production DEFAULT_V1_EXTRANONCE2_SIZE).
DEFAULT_EXTRANONCE2_SIZE = 4


# ---------------------------------------------------------------------------
# sha256d + share math (mirrors dcentrald-stratum/src/v1/job.rs + work.rs)
# ---------------------------------------------------------------------------


def sha256d(data: bytes) -> bytes:
    """Double SHA-256 (the Bitcoin work hash)."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def reverse_words_per_4(buf: bytes) -> bytes:
    """Byte-swap each consecutive 4-byte word.

    The production work builder applies this to the notify prev_hash before
    placing it into the block header (``work.rs`` ``reverse_endianness_per_word``).
    """
    if len(buf) % 4 != 0:
        raise ValueError("length must be a multiple of 4")
    out = bytearray(len(buf))
    for i in range(0, len(buf), 4):
        out[i : i + 4] = buf[i : i + 4][::-1]
    return bytes(out)


def build_coinbase(coinbase1: bytes, extranonce1: bytes, extranonce2: bytes, coinbase2: bytes) -> bytes:
    """coinbase = coinbase1 || extranonce1 || extranonce2 || coinbase2."""
    return coinbase1 + extranonce1 + extranonce2 + coinbase2


def merkle_root(coinbase_hash: bytes, branches: Sequence[bytes]) -> bytes:
    """Fold the coinbase hash with merkle branches (``job.rs`` semantics).

    Each step: current = sha256d(current || branch). No endianness games —
    the daemon folds raw 32-byte values exactly like this.
    """
    current = coinbase_hash
    for branch in branches:
        current = sha256d(current + branch)
    return current


def build_header(
    version: int,
    prev_hash_notify: bytes,
    merkle: bytes,
    ntime: int,
    nbits: int,
    nonce: int,
) -> bytes:
    """Build the 80-byte header exactly as the daemon's work builder does.

    version/ntime/nbits/nonce are u32s packed little-endian; prev_hash is the
    notify payload with each 4-byte word byte-reversed; merkle root is raw.
    """
    return (
        struct.pack("<I", version & 0xFFFFFFFF)
        + reverse_words_per_4(prev_hash_notify)
        + merkle
        + struct.pack("<III", ntime & 0xFFFFFFFF, nbits & 0xFFFFFFFF, nonce & 0xFFFFFFFF)
    )


def difficulty_to_target_int(difficulty: float) -> int:
    """Convert pool difficulty to a 256-bit share target integer.

    Mirrors ``difficulty.rs`` fail-closed semantics for malformed input
    (non-finite -> hardest target 0; <= 0 -> accept-all sentinel), but unlike
    the production clamp at difficulty <= 1.0 this stub keeps scaling below
    1.0 (see module docstring).
    """
    if difficulty != difficulty or difficulty in (float("inf"), float("-inf")):
        return 0  # fail closed: nothing can meet target 0
    if difficulty <= 0.0:
        return (1 << 256) - 1  # accept-all sentinel
    if difficulty == 1.0:
        return PDIFF1_TARGET_INT  # exact (float(PDIFF1)/1.0 would round to 2^224)
    if difficulty < 1.0:
        # production clamps to pdiff1 here; the stub scales instead
        # (see module docstring).
        scaled = float(PDIFF1_TARGET_INT) / difficulty
        return min(int(scaled), (1 << 256) - 1)
    if difficulty > float(2 ** 63):
        return int(float(PDIFF1_TARGET_INT) / difficulty)
    return PDIFF1_TARGET_INT // int(difficulty)


def target_int_to_bytes(target: int) -> bytes:
    """32-byte big-endian representation of a target integer."""
    return target.to_bytes(32, "big")


def meets_target(hash32: bytes, target: bytes) -> bool:
    """hash <= target compared as big-endian 256-bit integers."""
    return hash32 <= target


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------


class Job:
    """A mining.notify job issued by the stub, kept for share validation."""

    def __init__(
        self,
        job_id: str,
        prev_hash_hex: str,
        coinbase1_hex: str,
        coinbase2_hex: str,
        merkle_branches_hex: Sequence[str],
        version_hex: str,
        nbits_hex: str,
        ntime_hex: str,
        clean_jobs: bool,
    ) -> None:
        self.job_id = job_id
        self.prev_hash_hex = prev_hash_hex
        self.coinbase1_hex = coinbase1_hex
        self.coinbase2_hex = coinbase2_hex
        self.merkle_branches_hex = list(merkle_branches_hex)
        self.version_hex = version_hex
        self.nbits_hex = nbits_hex
        self.ntime_hex = ntime_hex
        self.clean_jobs = clean_jobs
        self.issued_at = time.time()

    # -- lazy byte decodes (validated once) --------------------------------
    @property
    def prev_hash(self) -> bytes:
        return bytes.fromhex(self.prev_hash_hex)

    @property
    def coinbase1(self) -> bytes:
        return bytes.fromhex(self.coinbase1_hex)

    @property
    def coinbase2(self) -> bytes:
        return bytes.fromhex(self.coinbase2_hex)

    @property
    def merkle_branches(self) -> List[bytes]:
        return [bytes.fromhex(h) for h in self.merkle_branches_hex]

    @property
    def version(self) -> int:
        return int(self.version_hex, 16)

    @property
    def nbits(self) -> int:
        return int(self.nbits_hex, 16)

    @property
    def ntime(self) -> int:
        return int(self.ntime_hex, 16)

    def notify_params(self) -> List[object]:
        return [
            self.job_id,
            self.prev_hash_hex,
            self.coinbase1_hex,
            self.coinbase2_hex,
            self.merkle_branches_hex,
            self.version_hex,
            self.nbits_hex,
            self.ntime_hex,
            self.clean_jobs,
        ]

    def describe(self) -> Dict[str, object]:
        return {
            "job_id": self.job_id,
            "prev_hash": self.prev_hash_hex,
            "coinbase1": self.coinbase1_hex,
            "coinbase2": self.coinbase2_hex,
            "merkle_branches": list(self.merkle_branches_hex),
            "version": self.version_hex,
            "nbits": self.nbits_hex,
            "ntime": self.ntime_hex,
            "clean_jobs": self.clean_jobs,
            "issued_at": self.issued_at,
        }


def make_job(
    index: int,
    ntime: Optional[int] = None,
    job_id_prefix: str = "tw",
    with_merkle_branch: bool = True,
) -> Job:
    """Deterministically derive job ``index`` (reproducible evidence)."""
    digest = lambda label: hashlib.sha256(f"emu-twin-{label}-{index}".encode()).digest()
    prev_hash = digest("prev").hex()
    branches = [digest("branch").hex()] if with_merkle_branch else []
    return Job(
        job_id=f"{job_id_prefix}{index:02x}",
        prev_hash_hex=prev_hash,
        # Coinbase parts shaped like dcentrald's mock_pool fixtures.
        coinbase1_hex="0100000001" + "00" * 32 + "ffffffff08",
        coinbase2_hex="ffffffff010000000000000000015100000000",
        merkle_branches_hex=branches,
        version_hex="20000000",
        nbits_hex="1d00ffff",
        ntime_hex=f"{(ntime if ntime is not None else 0x66112233) & 0xFFFFFFFF:08x}",
        clean_jobs=True,
    )


# ---------------------------------------------------------------------------
# Share search helper (host-side twin tooling; real sha256d, subsampled)
# ---------------------------------------------------------------------------


def find_share(
    job: Job,
    extranonce1: bytes,
    difficulty: float,
    start_nonce: int = 0,
    max_attempts: int = 5_000_000,
    extranonce2_size: int = DEFAULT_EXTRANONCE2_SIZE,
    timeout_secs: float = 120.0,
    version_bits: int = 0,
) -> Optional[Dict[str, object]]:
    """Search for a nonce whose sha256d(header) meets the stub target.

    Uses REAL double-SHA256 from ``hashlib`` (no shortcut, no synthetic
    nonces — the twin's honesty rule). Varies nonce and, every 2**16 attempts,
    increments extranonce2 for a fresh merkle root. Returns None when the
    bounded window is exhausted (we need valid shares, not terahash).
    """
    target = target_int_to_bytes(difficulty_to_target_int(difficulty))
    version = job.version
    if version_bits:
        version = (version & ~DEFAULT_VERSION_MASK) | (version_bits & DEFAULT_VERSION_MASK)
    deadline = time.monotonic() + timeout_secs
    nonce = start_nonce & 0xFFFFFFFF
    en2_counter = 0
    attempts = 0
    while attempts < max_attempts:
        extranonce2 = en2_counter.to_bytes(extranonce2_size, "big")
        coinbase = build_coinbase(job.coinbase1, extranonce1, extranonce2, job.coinbase2)
        merkle = merkle_root(sha256d(coinbase), job.merkle_branches)
        prefix = build_header(version, job.prev_hash, merkle, job.ntime, job.nbits, 0)[:76]
        for _ in range(1 << 16):
            if attempts >= max_attempts:
                break
            header = prefix + struct.pack("<I", nonce)
            h = sha256d(header)
            if meets_target(h, target):
                return {
                    "job_id": job.job_id,
                    "extranonce2_hex": extranonce2.hex(),
                    "ntime_hex": job.ntime_hex,
                    "nonce_hex": f"{nonce:08x}",
                    "version_bits_hex": f"{version_bits:08x}" if version_bits else None,
                    "hash_hex": h.hex(),
                    "attempts": attempts,
                }
            nonce = (nonce + 1) & 0xFFFFFFFF
            attempts += 1
            if attempts % 4096 == 0 and time.monotonic() > deadline:
                return None
        en2_counter += 1
    return None


# ---------------------------------------------------------------------------
# The stub pool
# ---------------------------------------------------------------------------


class StratumStub:
    """Threaded localhost Stratum V1 pool that genuinely validates shares."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        difficulty: float = 1.0,
        extranonce2_size: int = DEFAULT_EXTRANONCE2_SIZE,
        version_mask: int = DEFAULT_VERSION_MASK,
        job_ttl_secs: Optional[float] = None,
        require_authorize: bool = True,
        seed: Optional[int] = None,
    ) -> None:
        if not (difficulty > 0) or difficulty == float("inf"):
            raise ValueError("difficulty must be finite and positive")
        self.host = host
        self._requested_port = port
        self.difficulty = difficulty
        self.extranonce2_size = extranonce2_size
        self.version_mask = version_mask
        self.job_ttl_secs = job_ttl_secs
        self.require_authorize = require_authorize
        self._rng = random.Random(seed if seed is not None else 0xD_CE21)

        self._lock = threading.Lock()
        self._jobs: Dict[str, Job] = {}
        self._job_counter = 0
        self._sessions: Dict[int, "_Session"] = {}
        self._server: Optional[socketserver.ThreadingTCPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._port: Optional[int] = None

        # stats (mirror of the daemon mock-pool handle plus latency tracking)
        self.accepted = 0
        self.rejected = 0
        self.jobs_issued = 0
        self.submits_seen = 0
        self.latencies_ms: List[float] = []
        self.share_log: List[Dict[str, object]] = []
        self.request_log: List[str] = []

    # -- lifecycle ----------------------------------------------------------
    def start(self) -> "StratumStub":
        if self._server is not None:
            return self
        self._server = _StubServer((self.host, self._requested_port), self)
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="stratum-stub", daemon=True
        )
        self._thread.start()
        self._port = self._server.server_address[1]
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        self._thread = None
        self._port = None

    @property
    def port(self) -> int:
        if self._port is None:
            raise RuntimeError("stub not started")
        return self._port

    @property
    def url(self) -> str:
        return f"stratum+tcp://{self.host}:{self.port}"

    # -- job management -----------------------------------------------------
    def issue_job(self, job: Optional[Job] = None, ntime: Optional[int] = None) -> Job:
        """Create (or accept) a job, track it, and push it to live sessions."""
        with self._lock:
            if job is None:
                job = make_job(self._job_counter, ntime=ntime)
            if job.job_id in self._jobs:
                raise ValueError(f"duplicate job_id {job.job_id!r}")
            self._job_counter += 1
            self._jobs[job.job_id] = job
            self.jobs_issued += 1
            sessions = list(self._sessions.values())
        for session in sessions:
            session.push_notify(job)
        return job

    def get_job(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    # -- session registry (called from handler threads) ----------------------
    def _register_session(self, session: "_Session") -> None:
        with self._lock:
            self._sessions[id(session)] = session

    def _unregister_session(self, session: "_Session") -> None:
        with self._lock:
            self._sessions.pop(id(session), None)

    def _next_extranonce1(self) -> bytes:
        return self._rng.getrandbits(32).to_bytes(4, "big")

    # -- share validation (the heart of the stub) ----------------------------
    def validate_share(
        self,
        session: "_Session",
        worker: str,
        job_id: str,
        extranonce2_hex: str,
        ntime_hex: str,
        nonce_hex: str,
        version_bits_hex: Optional[str],
    ) -> Tuple[bool, Optional[str], Optional[Dict[str, object]]]:
        """Recompute the share from first principles; never trust the miner.

        Returns (accepted, reject_reason, evidence_record).
        """
        job = self.get_job(job_id)
        if job is None:
            return False, "unknown-job", None
        if self.job_ttl_secs is not None and time.time() - job.issued_at > self.job_ttl_secs:
            return False, "job-expired", None
        if self.require_authorize and not session.authorized:
            return False, "not-authorized", None

        def _u32(hexstr: str, field: str) -> int:
            if len(hexstr) != 8:
                raise ValueError(f"{field} must be 8 hex chars")
            return int(hexstr, 16)

        try:
            ntime = _u32(ntime_hex, "ntime")
            nonce = _u32(nonce_hex, "nonce")
            vbits = _u32(version_bits_hex, "version_bits") if version_bits_hex else 0
            extranonce2 = bytes.fromhex(extranonce2_hex)
            if len(extranonce2) != self.extranonce2_size:
                raise ValueError(
                    f"extranonce2 must be {self.extranonce2_size} bytes, got {len(extranonce2)}"
                )
        except ValueError as exc:
            return False, f"bad-params: {exc}", None

        version = job.version
        if vbits:
            version = (version & ~self.version_mask) | (vbits & self.version_mask)

        coinbase = build_coinbase(job.coinbase1, session.extranonce1, extranonce2, job.coinbase2)
        merkle = merkle_root(sha256d(coinbase), job.merkle_branches)
        header = build_header(version, job.prev_hash, merkle, ntime, job.nbits, nonce)
        share_hash = sha256d(header)
        target = target_int_to_bytes(difficulty_to_target_int(self.difficulty))
        ok = meets_target(share_hash, target)

        record = {
            "worker": worker,
            "job_id": job_id,
            "extranonce2": extranonce2_hex,
            "ntime": ntime_hex,
            "nonce": nonce_hex,
            "version_bits": version_bits_hex,
            "header_hex": header.hex(),
            "share_hash": share_hash.hex(),
            "target": target.hex(),
            "difficulty": self.difficulty,
            "meets_target": ok,
            "ts": time.time(),
        }
        return ok, (None if ok else "share-hash-above-target"), record

    # -- stats ---------------------------------------------------------------
    def stats(self) -> Dict[str, object]:
        with self._lock:
            return {
                "url": self.url if self._port else None,
                "difficulty": self.difficulty,
                "jobs_issued": self.jobs_issued,
                "accepted": self.accepted,
                "rejected": self.rejected,
                "submits_seen": self.submits_seen,
                "sessions": len(self._sessions),
                "latency_ms": {
                    "last": self.latencies_ms[-1] if self.latencies_ms else None,
                    "avg": (
                        sum(self.latencies_ms) / len(self.latencies_ms)
                        if self.latencies_ms
                        else None
                    ),
                    "max": max(self.latencies_ms) if self.latencies_ms else None,
                },
                "shares": list(self.share_log),
            }


class _Session:
    """Per-connection protocol state."""

    def __init__(self, stub: StratumStub, wfile) -> None:
        self.stub = stub
        self._wfile = wfile
        self._wlock = threading.Lock()
        self.subscribed = False
        self.authorized = False
        self.worker: Optional[str] = None
        self.extranonce1 = b""
        self.subscription_id = "0"

    def send(self, payload: Dict[str, object]) -> None:
        line = json.dumps(payload, separators=(",", ":")) + "\n"
        with self._wlock:
            self._wfile.write(line.encode("utf-8"))
            self._wfile.flush()

    def send_response(self, id_value: object, result: object, error: object = None) -> None:
        self.send({"id": id_value, "result": result, "error": error})

    def send_difficulty(self) -> None:
        self.send(
            {
                "id": None,
                "method": "mining.set_difficulty",
                "params": [self.stub.difficulty],
            }
        )

    def push_notify(self, job: Job) -> None:
        if not (self.subscribed or self.authorized):
            return
        self.send(
            {
                "id": None,
                "method": "mining.notify",
                "params": job.notify_params(),
            }
        )


class _StubServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, stub: StratumStub) -> None:
        self.stub = stub
        super().__init__(address, _StubHandler)


class _StubHandler(socketserver.StreamRequestHandler):
    """One JSON-lines Stratum connection."""

    def handle(self) -> None:
        stub: StratumStub = self.server.stub  # type: ignore[attr-defined]
        session = _Session(stub, self.wfile)
        stub._register_session(session)
        try:
            while True:
                line = self.rfile.readline(MAX_LINE_LENGTH + 1)
                if not line:
                    break
                if len(line) > MAX_LINE_LENGTH:
                    continue  # oversize: drop (codec.rs buffer-bomb protection)
                text = line.decode("utf-8", errors="replace").strip()
                if not text:
                    continue
                self._dispatch(stub, session, text)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            stub._unregister_session(session)

    # -- request dispatch ----------------------------------------------------
    def _dispatch(self, stub: StratumStub, session: _Session, text: str) -> None:
        try:
            message = json.loads(text)
        except json.JSONDecodeError:
            return  # mock_pool precedent: silently ignore non-JSON lines
        if not isinstance(message, dict):
            return
        with stub._lock:
            stub.request_log.append(text)
            if len(stub.request_log) > 1000:
                del stub.request_log[:500]
        id_value = message.get("id")
        method = message.get("method", "")
        params = message.get("params", [])

        if method == "mining.subscribe":
            session.extranonce1 = stub._next_extranonce1()
            session.subscription_id = f"sub{len(stub.request_log):04x}"
            session.subscribed = True
            session.send_response(
                id_value,
                [
                    [
                        ["mining.set_difficulty", session.subscription_id],
                        ["mining.notify", session.subscription_id],
                    ],
                    session.extranonce1.hex(),
                    stub.extranonce2_size,
                ],
            )
        elif method == "mining.authorize":
            worker = params[0] if isinstance(params, list) and params else ""
            session.worker = worker
            session.authorized = True
            session.send_response(id_value, True)
            # mock_pool handshake order: difficulty then first job.
            session.send_difficulty()
            with stub._lock:
                has_job = bool(stub._jobs)
            if not has_job:
                stub.issue_job()
            else:
                with stub._lock:
                    last_job = next(reversed(stub._jobs.values()))
                session.push_notify(last_job)
        elif method == "mining.configure":
            session.send_response(
                id_value,
                {
                    "version-rolling": True,
                    "version-rolling.mask": f"{stub.version_mask:08x}",
                    "subscribe-extranonce": True,
                },
            )
        elif method == "mining.extranonce.subscribe":
            session.send_response(id_value, True)
        elif method == "mining.suggest_difficulty":
            session.send_response(id_value, True)
            session.send_difficulty()
        elif method == "mining.submit":
            self._handle_submit(stub, session, id_value, params)
        elif method == "mining.ping":
            session.send_response(id_value, None)
        elif method == "client.get_version":
            session.send_response(id_value, f"emu-twin-stratum-stub/{__version__}")
        else:
            if id_value is not None:
                session.send_response(id_value, True)

    def _handle_submit(self, stub: StratumStub, session: _Session, id_value, params) -> None:
        started = time.perf_counter()
        stub.submits_seen += 1
        if not isinstance(params, list) or len(params) < 5:
            stub.rejected += 1
            session.send_response(id_value, False, [24, "bad-params: need >= 5", None])
            return
        worker, job_id, extranonce2_hex, ntime_hex, nonce_hex = (
            str(params[0]),
            str(params[1]),
            str(params[2]),
            str(params[3]),
            str(params[4]),
        )
        version_bits_hex = str(params[5]) if len(params) > 5 and params[5] is not None else None
        accepted, reason, record = stub.validate_share(
            session, worker, job_id, extranonce2_hex, ntime_hex, nonce_hex, version_bits_hex
        )
        latency_ms = (time.perf_counter() - started) * 1000.0
        with stub._lock:
            stub.latencies_ms.append(latency_ms)
            if accepted:
                stub.accepted += 1
            else:
                stub.rejected += 1
            if record is not None:
                record["latency_ms"] = latency_ms
                stub.share_log.append(record)
                if len(stub.share_log) > 256:
                    del stub.share_log[:128]
        if accepted:
            session.send_response(id_value, True)
        else:
            session.send_response(id_value, False, [23, reason or "rejected", None])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="emu-twin localhost Stratum V1 stub pool (real sha256d share validation)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="bind host (localhost only)")
    parser.add_argument("--port", type=int, default=17001, help="bind port (0 = ephemeral)")
    parser.add_argument("--difficulty", type=float, default=1.0,
                        help="share difficulty (values < 1.0 are stub-easier; see module docs)")
    parser.add_argument("--job-every", type=float, default=0.0, metavar="SECS",
                        help="issue a fresh deterministic job every SECS (0 = on authorize only)")
    args = parser.parse_args(argv)

    stub = StratumStub(host=args.host, port=args.port, difficulty=args.difficulty).start()
    print(f"stratum stub listening on {stub.url} difficulty={args.difficulty}")
    try:
        if args.job_every > 0:
            i = 0
            while True:
                time.sleep(args.job_every)
                job = stub.issue_job(ntime=int(time.time()) & 0xFFFFFFFF)
                i += 1
                print(f"issued job {job.job_id} (#{i})")
        else:
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        stats = stub.stats()
        print(json.dumps({k: v for k, v in stats.items() if k != "shares"}, indent=2))
        stub.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
