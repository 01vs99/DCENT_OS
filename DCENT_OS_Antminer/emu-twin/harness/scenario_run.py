"""End-to-end scenario runner for the DCENT_OS emulation twin (emu-twin).

Scripted timeline (the seed of the campaign Phase-A exit test — "the twin
returns a genuinely valid share")::

    stratum stub issues job
      -> job reaches the chain backend (I1 chain_server, or the built-in
         chain stub over TCP)
      -> nonce found with REAL double-SHA256 (stdlib hashlib; never a
         synthesized nonce)
      -> mining.submit reaches the stratum stub
      -> the stub RECOMPUTES the share hash and target-checks it
      -> harness independently recomputes the hash a second time
      -> PASS/FAIL verdict + JSON evidence (timestamps, hashes, targets,
         latencies) written under harness/evidence/ (gitignored).

Sibling-module discipline: I1 owns ``chain_server``/``nonce_engine`` and may
land after this file. Both are imported lazily and defensively — if absent or
if their signatures have not frozen yet, the built-in backend runs and the
evidence file records exactly which backend/engine served the run. No test
hard-requires I1 modules.

Builtin chain-stub wire protocol ("emu-twin builtin chain v1", TCP, localhost):
    request:  4-byte big-endian length, then JSON:
        {"v":1, "type":"job", "job_id":str, "header_hex":<80 bytes>,
         "target_hex":<32 bytes>, "start_nonce":int, "max_attempts":int,
         "timeout_secs":float}
    response: 4-byte big-endian length, then JSON:
        {"v":1, "type":"share", "found":bool, "nonce_hex":str|null,
         "hash_hex":str|null, "attempts":int, "engine":str}

Standard library only. CLI::

    py -3 harness/scenario_run.py --difficulty 0.0001
"""

from __future__ import annotations

import argparse
import importlib
import json
import socket
import socketserver
import struct
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

# Make sibling emu-twin modules importable both as a script and via -m.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import stratum_stub  # noqa: E402  (sibling module, I2-owned)
from stratum_stub import (  # noqa: E402
    Job,
    StratumStub,
    build_coinbase,
    build_header,
    difficulty_to_target_int,
    merkle_root,
    sha256d,
    target_int_to_bytes,
)

SCHEMA = "emu-twin/scenario-evidence/1"
#: Honesty tier label (a2 report §F rule 3): a host-side scenario is T1;
#: T2 requires the unmodified capsule binary inside QEMU.
MODEL_TIER = "t1-host-scenario"

DEFAULT_EVIDENCE_DIR = _ROOT / "harness" / "evidence"


# ---------------------------------------------------------------------------
# Lazy sibling-module loading (I1 modules may land later)
# ---------------------------------------------------------------------------


def load_optional_module(name: str):
    """Import a sibling module if present; never raise (I1 may land later)."""
    try:
        return importlib.import_module(name)
    except ImportError:
        return None
    except Exception as exc:  # half-written sibling file mid-landing
        print(f"warning: module {name} present but failed to import: {exc}", file=sys.stderr)
        return None


class EngineProbe:
    """Adapter around I1's ``nonce_engine`` with verified fallback.

    I1's engine (landed 2026-10-05) exposes::

        MidstateJob.from_header_prefix(header_prefix76, target:int, job_id, version_bits)
        search(job, start_nonce=0, max_nonces=1<<20, nonce_stride=1) -> FoundShare|None

    CONVENTION NOTE (resolved 2026-10-05): nonce_engine now compares targets
    as BIG-ENDIAN bignums (``hash_to_uint_be``), matching the daemon's share
    gate (dcentrald-stratum difficulty.rs ``meets_target``) and this stub.
    The adapter still re-verifies every engine digest against the big-endian
    target before using it (defense in depth) and falls back to the builtin
    hashlib search on any mismatch or error. Whichever engine serves the run
    is recorded in the evidence file.
    """

    def __init__(self) -> None:
        self.module = load_optional_module("nonce_engine")
        self.engine_name = "builtin-hashlib"
        self.skip_reason = ""
        if self.module is not None and hasattr(self.module, "MidstateJob"):
            self.engine_name = "nonce_engine(i1)"

    def search(
        self,
        header80: bytes,
        target: bytes,
        start_nonce: int,
        max_attempts: int,
        timeout_secs: float,
    ) -> Optional[Tuple[int, bytes]]:
        """Return (nonce, digest_be) meeting the BIG-ENDIAN target, or None."""
        if self.module is not None and self.engine_name.startswith("nonce_engine"):
            result = self._search_via_module(header80, target, start_nonce, max_attempts)
            if result is not None:
                return result
        return find_nonce_for_header(header80, target, start_nonce, max_attempts, timeout_secs)

    def _search_via_module(
        self, header80: bytes, target: bytes, start_nonce: int, max_attempts: int
    ) -> Optional[Tuple[int, bytes]]:
        try:
            job_cls = self.module.MidstateJob
            job = job_cls.from_header_prefix(
                header80[:76],
                int.from_bytes(target, "big"),
                job_id=0,
            )
            found = self.module.search(job, start_nonce=start_nonce, max_nonces=max_attempts)
        except Exception as exc:  # any adapter mismatch -> builtin, never fail the run
            self.skip_reason = f"nonce_engine adapter error: {exc}"
            self.engine_name = "builtin-hashlib (nonce_engine present, adapter error)"
            return None
        if found is None:
            return None
        nonce = int(found.nonce)
        digest = bytes(found.digest)
        # BE re-verification: the stub and the daemon compare big-endian.
        rebuilt = sha256d(header80[:76] + struct.pack("<I", nonce))
        if rebuilt != digest or rebuilt > target:
            self.skip_reason = (
                "nonce_engine digest failed big-endian target verification "
                "(LE-bignum convention mismatch — reported to orchestrator)"
            )
            self.engine_name = "builtin-hashlib (nonce_engine LE/BE mismatch)"
            return None
        return nonce, digest


def find_nonce_for_header(
    header80: bytes,
    target: bytes,
    start_nonce: int = 0,
    max_attempts: int = 2_000_000,
    timeout_secs: float = 60.0,
) -> Optional[Tuple[int, bytes]]:
    """Builtin REAL sha256d nonce search over the last 4 header bytes."""
    if len(header80) != 80:
        raise ValueError("header must be exactly 80 bytes")
    prefix = header80[:76]
    deadline = time.monotonic() + timeout_secs
    nonce = start_nonce & 0xFFFFFFFF
    check_every = 4096
    for attempt in range(max_attempts):
        digest = sha256d(prefix + struct.pack("<I", nonce))
        if digest <= target:
            return nonce, digest
        nonce = (nonce + 1) & 0xFFFFFFFF
        if attempt % check_every == 0 and time.monotonic() > deadline:
            return None
    return None


# ---------------------------------------------------------------------------
# Built-in chain stub (TCP transport the "daemon" dispatches jobs onto)
# ---------------------------------------------------------------------------


class _ChainJobHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            raw_len = self._recv_exact(4)
            if raw_len is None:
                return
            (length,) = struct.unpack(">I", raw_len)
            if length > 1 << 20:
                return
            payload = self._recv_exact(length)
            if payload is None:
                return
            try:
                request = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send({"v": 1, "type": "error", "error": "invalid JSON"})
                continue
            if request.get("type") != "job":
                self._send({"v": 1, "type": "error", "error": "expected type=job"})
                continue
            header = bytes.fromhex(str(request["header_hex"]))
            target = bytes.fromhex(str(request["target_hex"]))
            engine: EngineProbe = self.server.engine  # type: ignore[attr-defined]
            result = engine.search(
                header,
                target,
                int(request.get("start_nonce", 0)),
                int(request.get("max_attempts", 1_000_000)),
                float(request.get("timeout_secs", 30.0)),
            )
            if result is None:
                self._send(
                    {
                        "v": 1,
                        "type": "share",
                        "found": False,
                        "job_id": request.get("job_id"),
                        "attempts": int(request.get("max_attempts", 0)),
                        "engine": engine.engine_name,
                    }
                )
            else:
                nonce, digest = result
                self._send(
                    {
                        "v": 1,
                        "type": "share",
                        "found": True,
                        "job_id": request.get("job_id"),
                        "nonce_hex": f"{nonce:08x}",
                        "hash_hex": digest.hex(),
                        "engine": engine.engine_name,
                    }
                )

    def _recv_exact(self, n: int) -> Optional[bytes]:
        chunks = bytearray()
        while len(chunks) < n:
            try:
                chunk = self.request.recv(n - len(chunks))
            except OSError:
                return None
            if not chunk:
                return None
            chunks.extend(chunk)
        return bytes(chunks)

    def _send(self, payload: Dict[str, object]) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        try:
            self.request.sendall(struct.pack(">I", len(data)) + data)
        except OSError:
            pass


class ChainStubServer:
    """Length-prefixed TCP job dispatch endpoint (builtin chain stand-in)."""

    PROTOCOL = "emu-twin builtin chain v1"

    def __init__(self, engine: Optional[EngineProbe] = None) -> None:
        self.engine = engine or EngineProbe()
        self.jobs_received: List[Dict[str, object]] = []
        self.last_response: Optional[Dict[str, object]] = None
        self._server: Optional[socketserver.ThreadingTCPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._port: Optional[int] = None

    def start(self) -> "ChainStubServer":
        outer = self

        class _Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
            engine = outer.engine

        self._server = _Server(("127.0.0.1", 0), _ChainJobHandler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="chain-stub", daemon=True
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
            raise RuntimeError("chain stub not started")
        return self._port

    def dispatch_job(
        self,
        job_id: str,
        header: bytes,
        target: bytes,
        start_nonce: int = 0,
        max_attempts: int = 1_000_000,
        timeout_secs: float = 30.0,
    ) -> Dict[str, object]:
        """Send one job to the chain and return the share response."""
        request = {
            "v": 1,
            "type": "job",
            "job_id": job_id,
            "header_hex": header.hex(),
            "target_hex": target.hex(),
            "start_nonce": start_nonce,
            "max_attempts": max_attempts,
            "timeout_secs": timeout_secs,
        }
        record = {"ts": time.time(), "job_id": job_id, "header_hex": header.hex()}
        self.jobs_received.append(record)
        payload = json.dumps(request, separators=(",", ":")).encode("utf-8")
        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout_secs + 30) as sock:
            sock.sendall(struct.pack(">I", len(payload)) + payload)
            response = self._read_response(sock)
        self.last_response = response
        return response

    @staticmethod
    def _read_response(sock: socket.socket) -> Dict[str, object]:
        header = ChainStubServer._recv_exact(sock, 4)
        if header is None:
            raise ConnectionError("chain closed before response length")
        (length,) = struct.unpack(">I", header)
        body = ChainStubServer._recv_exact(sock, length)
        if body is None:
            raise ConnectionError("chain closed mid-response")
        return json.loads(body.decode("utf-8"))

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
        chunks = bytearray()
        while len(chunks) < n:
            chunk = sock.recv(n - len(chunks))
            if not chunk:
                return None
            chunks.extend(chunk)
        return bytes(chunks)


# ---------------------------------------------------------------------------
# Chain backend resolution (I1 chain_server if usable, else builtin stub)
# ---------------------------------------------------------------------------


def resolve_chain_backend(preference: str = "auto") -> Tuple[str, Dict[str, object]]:
    """Decide which chain backend serves the run.

    Returns (backend_name, info). I1's chain_server is only used when its
    module is importable AND exposes an obviously-usable dispatch surface;
    otherwise the builtin stub runs. The evidence file records the decision.
    """
    info: Dict[str, object] = {"chain_server_module_present": False}
    if preference == "builtin":
        return "builtin-chain-stub", info
    module = load_optional_module("chain_server")
    if module is None:
        return "builtin-chain-stub", info
    info["chain_server_module_present"] = True
    # Signature freeze pending: no adapter yet. Record availability honestly.
    info["note"] = "chain_server importable; transport adapter pending I1 signature freeze"
    return "builtin-chain-stub (chain_server present, adapter pending)", info


# ---------------------------------------------------------------------------
# Miner client (plays the dcentrald role until the QEMU PoC runs the real one)
# ---------------------------------------------------------------------------


class MinerClient:
    """Minimal Stratum V1 client used to drive the stub through the flow."""

    def __init__(self, host: str, port: int, worker: str = "twin.0", timeout: float = 30.0) -> None:
        self.worker = worker
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self._buf = bytearray()
        self._next_id = 1
        self.extranonce1 = b""
        self.extranonce2_size = 4
        self.version_mask = 0
        self.difficulty: Optional[float] = None

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def _send(self, payload: Dict[str, object]) -> int:
        request_id = self._next_id
        self._next_id += 1
        payload["id"] = payload.get("id", request_id)
        self.sock.sendall((json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8"))
        return int(payload["id"])

    def _read_message(self) -> Dict[str, object]:
        while True:
            if b"\n" in self._buf:
                line, _, rest = self._buf.partition(b"\n")
                self._buf = bytearray(rest)
                text = line.decode("utf-8", errors="replace").strip()
                if text:
                    message = json.loads(text)
                    if isinstance(message, dict):
                        return message
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("stratum stub closed the connection")
            self._buf.extend(chunk)

    def _request(self, method: str, params: List[object]) -> Dict[str, object]:
        request_id = self._send({"method": method, "params": params})
        while True:
            message = self._read_message()
            if message.get("id") == request_id:
                return message

    def configure(self) -> None:
        response = self._request(
            "mining.configure", [[], {}]
        )
        result = response.get("result") or {}
        if isinstance(result, dict):
            mask = result.get("version-rolling.mask")
            if isinstance(mask, str) and mask:
                self.version_mask = int(mask, 16)

    def subscribe(self) -> None:
        response = self._request("mining.subscribe", ["emu-twin-harness/0.1"])
        result = response.get("result")
        if not isinstance(result, list) or len(result) < 3:
            raise ValueError(f"bad subscribe result: {result!r}")
        self.extranonce1 = bytes.fromhex(str(result[1]))
        self.extranonce2_size = int(result[2])

    def authorize(self, password: str = "x") -> None:
        response = self._request("mining.authorize", [self.worker, password])
        if response.get("result") is not True:
            raise ValueError(f"authorize refused: {response!r}")

    def read_until_notify(self) -> Dict[str, object]:
        """Consume notifications; returns the first mining.notify params."""
        while True:
            message = self._read_message()
            method = message.get("method")
            if method == "mining.set_difficulty":
                params = message.get("params") or []
                if params:
                    self.difficulty = float(params[0])
                continue
            if method == "mining.notify":
                return message

    def submit(
        self,
        job_id: str,
        extranonce2_hex: str,
        ntime_hex: str,
        nonce_hex: str,
        version_bits_hex: Optional[str] = None,
    ) -> Dict[str, object]:
        params: List[object] = [self.worker, job_id, extranonce2_hex, ntime_hex, nonce_hex]
        if version_bits_hex:
            params.append(version_bits_hex)
        return self._request("mining.submit", params)


# ---------------------------------------------------------------------------
# The scenario
# ---------------------------------------------------------------------------


def build_work_header(
    job: Job, extranonce1: bytes, extranonce2: bytes, nonce: int = 0, ntime: Optional[int] = None
) -> bytes:
    """Header built exactly as the daemon's work builder would (work.rs)."""
    coinbase = build_coinbase(job.coinbase1, extranonce1, extranonce2, job.coinbase2)
    root = merkle_root(sha256d(coinbase), job.merkle_branches)
    return build_header(
        job.version, job.prev_hash, root,
        job.ntime if ntime is None else ntime, job.nbits, nonce,
    )


def run_scenario(
    name: str = "default-e2e",
    difficulty: float = 0.0001,
    evidence_dir: Optional[Path] = None,
    max_chain_attempts: int = 1_000_000,
    chain_timeout_secs: float = 60.0,
    extranonce2_tries: int = 8,
    chain_preference: str = "auto",
    quiet: bool = False,
) -> Dict[str, object]:
    """Run the full job->chain->nonce->share->verdict timeline.

    Returns the evidence dict (also written as JSON into evidence_dir).
    """
    steps: List[Dict[str, object]] = []

    def step(label: str, detail: object = "") -> None:
        steps.append({"step": label, "ts": time.time(), "detail": detail})
        if not quiet:
            print(f"[scenario] {label}" + (f": {detail}" if detail else ""))

    stub = StratumStub(host="127.0.0.1", port=0, difficulty=difficulty, seed=0x5EED_0001).start()
    engine = EngineProbe()
    chain = ChainStubServer(engine=engine).start()
    backend_name, backend_info = resolve_chain_backend(chain_preference)
    miner: Optional[MinerClient] = None
    evidence: Dict[str, object] = {}
    try:
        step("stratum-stub-start", stub.url)
        step("chain-backend", backend_name)
        step("nonce-engine", engine.engine_name)

        miner = MinerClient("127.0.0.1", stub.port)
        miner.configure()
        miner.subscribe()
        step("subscribed", f"extranonce1={miner.extranonce1.hex()} en2_size={miner.extranonce2_size}")
        miner.authorize()
        step("authorized", miner.worker)

        notify = miner.read_until_notify()
        params = notify.get("params") or []
        job_id = str(params[0])
        job = stub.get_job(job_id)
        if job is None:
            raise RuntimeError(f"stub did not track issued job {job_id!r}")
        if miner.difficulty is None:
            raise RuntimeError("stub did not send mining.set_difficulty before notify")
        step("job-received", job_id)

        target = target_int_to_bytes(difficulty_to_target_int(difficulty))
        share_response: Optional[Dict[str, object]] = None
        dispatched_header_hex = ""
        used_extranonce2_hex = ""
        for try_index in range(extranonce2_tries):
            extranonce2 = try_index.to_bytes(miner.extranonce2_size, "big")
            header = build_work_header(job, miner.extranonce1, extranonce2)
            dispatched_header_hex = header.hex()
            response = chain.dispatch_job(
                job_id=job_id,
                header=header,
                target=target,
                start_nonce=try_index * 1_000_000,
                max_attempts=max_chain_attempts,
                timeout_secs=chain_timeout_secs,
            )
            step(
                "chain-dispatch",
                {"try": try_index, "found": response.get("found"),
                 "engine": response.get("engine"), "job_id": job_id},
            )
            if response.get("found"):
                nonce_hex = str(response["nonce_hex"])
                used_extranonce2_hex = extranonce2.hex()
                share_response = miner.submit(
                    job_id, used_extranonce2_hex, job.ntime_hex, nonce_hex
                )
                step("share-submitted", {"nonce": nonce_hex, "hash": response.get("hash_hex")})
                break
        if share_response is None:
            raise RuntimeError("chain never found a nonce inside the bounded window")

        accepted = share_response.get("result") is True
        step("share-verdict", "accepted" if accepted else f"rejected: {share_response.get('error')}")

        stats = stub.stats()
        share_record = stats["shares"][-1] if stats["shares"] else None
        independent_ok = False
        independent_hash = ""
        if isinstance(share_record, dict):
            header_hex = str(share_record["header_hex"])
            recomputed = sha256d(bytes.fromhex(header_hex))
            independent_hash = recomputed.hex()
            independent_ok = (
                recomputed.hex() == share_record["share_hash"]
                and recomputed <= bytes.fromhex(str(share_record["target"]))
            )
            step("independent-recompute", {"matches_stub": independent_ok})

        verdict = "PASS" if (accepted and independent_ok) else "FAIL"
        evidence = {
            "schema": SCHEMA,
            "model_tier": MODEL_TIER,
            "scenario": name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "verdict": verdict,
            "reason": (
                "share accepted and independently recomputed"
                if verdict == "PASS"
                else f"accepted={accepted} independent_ok={independent_ok}"
            ),
            "chain_backend": backend_name,
            "chain_backend_info": backend_info,
            "chain_protocol": ChainStubServer.PROTOCOL,
            "nonce_engine": engine.engine_name,
            "nonce_engine_skip_reason": engine.skip_reason,
            "chain_jobs": chain.jobs_received,
            "chain_response": chain.last_response,
            "dispatched_header_hex": dispatched_header_hex,
            "extranonce2": used_extranonce2_hex,
            "stratum": {
                "url": stub.url,
                "difficulty": difficulty,
                "target_hex": target.hex(),
                "jobs_issued": stats["jobs_issued"],
                "accepted": stats["accepted"],
                "rejected": stats["rejected"],
                "latency_ms": stats["latency_ms"],
            },
            "job": job.describe(),
            "share": share_record,
            "independent_check": {
                "recomputed_hash": independent_hash,
                "matches_stub": independent_ok,
            },
            "steps": steps,
        }
    finally:
        if miner is not None:
            miner.close()
        chain.stop()
        stub.stop()
        step("teardown", "stopped")

    evidence_dir = Path(evidence_dir) if evidence_dir is not None else DEFAULT_EVIDENCE_DIR
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence_path = evidence_dir / f"scenario-{name}-{stamp}.json"
    evidence_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    evidence["evidence_path"] = str(evidence_path)
    if not quiet:
        print(f"[scenario] verdict={verdict} evidence={evidence_path}")
    return evidence


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="emu-twin end-to-end scenario: job -> chain -> real sha256d nonce -> valid share",
    )
    parser.add_argument("--name", default="default-e2e", help="scenario name (evidence file stem)")
    parser.add_argument(
        "--difficulty", type=float, default=0.0001,
        help="stub share difficulty (<1.0 is stub-easier; use >=1.0 for daemon-parity pdiff)",
    )
    parser.add_argument("--evidence-dir", default=str(DEFAULT_EVIDENCE_DIR))
    parser.add_argument("--chain-backend", choices=("auto", "builtin"), default="auto")
    parser.add_argument("--max-chain-attempts", type=int, default=1_000_000)
    parser.add_argument("--chain-timeout", type=float, default=60.0)
    parser.add_argument("--extranonce2-tries", type=int, default=8)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    try:
        evidence = run_scenario(
            name=args.name,
            difficulty=args.difficulty,
            evidence_dir=Path(args.evidence_dir),
            max_chain_attempts=args.max_chain_attempts,
            chain_timeout_secs=args.chain_timeout,
            extranonce2_tries=args.extranonce2_tries,
            chain_preference=args.chain_backend,
            quiet=args.quiet,
        )
    except Exception as exc:  # scenario failure IS the signal, not a traceback
        print(f"scenario error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"verdict": evidence["verdict"], "evidence": evidence.get("evidence_path")}))
    return 0 if evidence["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
