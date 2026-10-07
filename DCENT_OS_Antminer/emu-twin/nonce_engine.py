"""Real double-SHA256 nonce search for the emu-twin chain emulator.

This is a GENUINE proof-of-work search: every reported nonce is found by
computing sha256(sha256(header)) and comparing the little-endian interpreted
hash against a target.  No synthesized "valid" nonces, ever.

Two job forms are supported, matching what the BM1362-class wire protocol
implies for dispatch (`dcentrald-api-types::asic_protocol_spec` selects
`UartFullHeader` for BM1362/BM1366/BM1368/BM1370 — the chip receives full
header material and computes its own midstates):

  1. Full-header form (`from_header_prefix`, the BM1362 wire reality): a
     76-byte header prefix.  The engine precomputes the inner SHA-256
     object over the first 64 bytes once per job — a true midstate — and
     each nonce costs only `base.copy()` + 20 bytes via hashlib (fast path).
  2. Midstate-digest + tail form (`from_midstate`): a caller-supplied
     32-byte inner state plus the 12-byte tail.  `hashlib` cannot be
     re-seeded from a digest, so this form runs a small pure-Python SHA-256
     compression seeded with the midstate words (correct, ~100x slower —
     provided for interface parity with midstate-first dispatch paths, not
     for throughput).

Subsampling: the engine searches only as fast as needed to produce the
configured found-share rate — `max_nonces` bounds the per-job scan window.
We need valid shares, not terahash; hashrate numbers reported by the twin
MUST come from `physics.py` models, never from this engine's Python search
rate (tier honesty: T1 sim / T2 twin evidence only; model outputs, not
silicon truth).

BIP320 version rolling is honored: jobs carry a version base; callers may
roll version bits (mask 0x1FFFE000, positions 13..28) exactly like the
am2 BM1362 law (: never re-introduce the rejection guard).

Stdlib only.  Optional multiprocess pool (`search_parallel`) via
`concurrent.futures`; default is single-process for deterministic tests.

License: GPL-3.0 (DCENT_OS emu-twin).
Fund: https://d-central.tech/fund/
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# Bitcoin difficulty-1 target (bignum) for `target_from_difficulty`.
# [BITCOIN-CONSENSUS] constant, not vendor data.
DIFFICULTY_1_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------


def sha256d(header: bytes) -> bytes:
    """Double SHA-256 of a full 80-byte header."""
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()


def hash_to_uint_le(hash32: bytes) -> int:
    """Interpret a 32-byte hash as a little-endian unsigned integer
    (Bitcoin-Core-internal uint256 storage convention). NOT the daemon's
    share-gate convention — see hash_to_uint_be."""
    return int.from_bytes(hash32, "little")


def hash_to_uint_be(hash32: bytes) -> int:
    """Interpret a 32-byte hash as a big-endian unsigned integer.

    This is the DAEMON's share-target convention: dcentrald-stratum
    difficulty.rs::meets_target compares hash bytes MSB-to-LSB, and the
    targets from target_from_difficulty/target_from_nbits are big-endian
    bignums. Share scanning MUST use this, not the Core-internal LE view.
    """
    return int.from_bytes(hash32, "big")


def target_from_difficulty(difficulty: float) -> int:
    """Share target for a (possibly fractional) difficulty.

    Uses exact rational arithmetic (`fractions`) — float division silently
    loses every digit past 53 bits, and targets are ~1e72 bignums.
    """
    from fractions import Fraction

    if difficulty <= 0:
        raise ValueError("difficulty must be > 0")
    return int(DIFFICULTY_1_TARGET / Fraction(difficulty))


def target_from_nbits(nbits: int) -> int:
    """Decode an nbits compact target (consensus decode)."""
    exponent = (nbits >> 24) & 0xFF
    mantissa = nbits & 0x00FFFFFF
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


# ---------------------------------------------------------------------------
# Pure-Python SHA-256 compression, seedable from a midstate digest
# ---------------------------------------------------------------------------

# [FIPS-180-4] initial hash values — public specification.
_SHA256_H0 = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)

# [FIPS-180-4] round constants — public specification.
_SHA256_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _sha256_compress(state: List[int], block: bytes) -> List[int]:
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        big_s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (h + big_s1 + ch + _SHA256_K[i] + w[i]) & 0xFFFFFFFF
        big_s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (big_s0 + maj) & 0xFFFFFFFF
        h, g, f, e, d, c, b, a = (
            g, f, e, (d + t1) & 0xFFFFFFFF, c, b, a, (t1 + t2) & 0xFFFFFFFF,
        )
    return [(x + y) & 0xFFFFFFFF for x, y in zip(state, (a, b, c, d, e, f, g, h))]


def true_midstate(first_block64: bytes) -> bytes:
    """The REAL mining midstate: the SHA-256 state after compressing exactly
    64 message bytes (no padding), i.e. the state a chip/engine resumes from.

    NOTE: this is NOT `hashlib.sha256(block).digest()` — that is the final
    digest of block+padding (two extra padding blocks), a different state.
    `hashlib` cannot expose interior state, so this is one pure-Python
    compression from the FIPS initial values (cheap: once per job).
    """
    if len(first_block64) != 64:
        raise ValueError("midstate block must be exactly 64 bytes")
    state = _sha256_compress(list(_SHA256_H0), first_block64)
    return struct.pack(">8I", *state)


def sha256_from_midstate(midstate: bytes, data: bytes, bits_already: int = 512) -> bytes:
    """Continue SHA-256 from a TRUE midstate (see `true_midstate`) over
    `data`; equivalent to sha256(first_block + data).
    """
    state = list(struct.unpack(">8I", midstate))
    total_bits = bits_already + 8 * len(data)
    msg = data + b"\x80"
    msg += b"\x00" * ((56 - len(msg)) % 64)
    msg += struct.pack(">Q", total_bits)
    for i in range(0, len(msg), 64):
        state = _sha256_compress(state, msg[i : i + 64])
    return struct.pack(">8I", *state)


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MidstateJob:
    """A search job: TRUE inner SHA-256 state after the first 64 header
    bytes, the 12-byte tail (header bytes 64:76), and the share target."""

    midstate: bytes        # 32 B — TRUE midstate (see true_midstate)
    tail: bytes            # 12 B — header[64:76] (the nonce is bytes 76:80)
    target: int            # share target as a big-endian bignum (daemon convention)
    job_id: int = 0
    version_bits: int = 0  # raw BIP320 vbits rolled into the version
    header_prefix: Optional[bytes] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if len(self.midstate) != 32:
            raise ValueError("midstate must be 32 bytes")
        if len(self.tail) != 12:
            raise ValueError("tail must be 12 bytes (header bytes 64:76)")
        if self.target <= 0:
            raise ValueError("target must be positive")

    @classmethod
    def from_header_prefix(
        cls,
        header_prefix76: bytes,
        target: int,
        job_id: int = 0,
        version_bits: int = 0,
    ) -> "MidstateJob":
        """Build a job from the 76-byte header prefix (no nonce).

        The midstate is the TRUE state after the first 64 bytes (one raw
        compression — hashlib's digest of 64 bytes is NOT that state); the
        tail is bytes 64:76 (header bytes 76:80 are the nonce).
        `header_prefix76` is exactly `protocol.JobFields.header_prefix()`.
        """
        if len(header_prefix76) != 76:
            raise ValueError("header prefix must be 76 bytes")
        return cls(
            midstate=true_midstate(header_prefix76[:64]),
            tail=header_prefix76[64:76],
            target=target,
            job_id=job_id,
            version_bits=version_bits,
            header_prefix=bytes(header_prefix76),
        )

    @classmethod
    def from_midstate(
        cls,
        midstate: bytes,
        tail: bytes,
        target: int,
        job_id: int = 0,
        version_bits: int = 0,
    ) -> "MidstateJob":
        """Build a job from a caller-supplied TRUE midstate + 12-byte tail
        (no header prefix available; search uses the seeded pure-Python
        compression — slower, same results)."""
        return cls(
            midstate=midstate,
            tail=tail,
            target=target,
            job_id=job_id,
            version_bits=version_bits,
            header_prefix=None,
        )

    def header(self, nonce: int) -> bytes:
        """Reconstruct the full 80-byte header for a candidate nonce.

        Requires the prefix form (the midstate alone is not invertible).
        """
        if self.header_prefix is None:
            raise NotImplementedError(
                "header reconstruction requires the prefix form; "
                "midstate-form jobs carry no header bytes"
            )
        return self.header_prefix + struct.pack("<I", nonce & 0xFFFFFFFF)

    def inner_digest(self, nonce: int) -> bytes:
        """Inner sha256(header) for a candidate nonce."""
        if self.header_prefix is not None:
            base = hashlib.sha256(self.header_prefix[:64])
            inner = base.copy()
            inner.update(self.header_prefix[64:] + struct.pack("<I", nonce & 0xFFFFFFFF))
            return inner.digest()
        return sha256_from_midstate(
            self.midstate,
            self.tail + struct.pack("<I", nonce & 0xFFFFFFFF),
        )

    def digest(self, nonce: int) -> bytes:
        """Full double-SHA256 digest for a candidate nonce."""
        return hashlib.sha256(self.inner_digest(nonce)).digest()


@dataclass(frozen=True)
class FoundShare:
    """A REAL share: nonce + the double-SHA256 digest that met the target."""

    nonce: int
    digest_uint: int     # int.from_bytes(sha256d, "big") — daemon share-gate convention
    digest: bytes         # raw 32-byte sha256d output
    job_id: int
    version_bits: int
    hashes_computed: int  # nonce candidates examined before this hit


def _scan(
    job: MidstateJob,
    start_nonce: int,
    max_nonces: int,
    nonce_stride: int,
    want: int,
) -> List[FoundShare]:
    """Scan up to `max_nonces` candidates; collect up to `want` real shares."""
    found: List[FoundShare] = []
    target = job.target
    prefix = job.header_prefix
    nonce = start_nonce
    for i in range(max_nonces):
        if prefix is not None:
            base = _PREFIX_BASE_CACHE.get(prefix)
            if base is None:
                base = hashlib.sha256(prefix[:64])
                _PREFIX_BASE_CACHE[prefix] = base
            inner = base.copy()
            inner.update(prefix[64:] + struct.pack("<I", nonce & 0xFFFFFFFF))
            inner_digest = inner.digest()
        else:
            inner_digest = sha256_from_midstate(
                job.midstate, job.tail + struct.pack("<I", nonce & 0xFFFFFFFF)
            )
        digest = hashlib.sha256(inner_digest).digest()
        if int.from_bytes(digest, "big") <= target:
            found.append(
                FoundShare(
                    nonce=nonce & 0xFFFFFFFF,
                    digest_uint=int.from_bytes(digest, "big"),
                    digest=digest,
                    job_id=job.job_id,
                    version_bits=job.version_bits,
                    hashes_computed=i + 1,
                )
            )
            if len(found) >= want:
                break
        nonce += nonce_stride
    return found


# One base sha256 object per distinct header prefix (keyed by the immutable
# prefix bytes — never by object identity, which can be reused after GC).
# Cleared explicitly by clear_job_cache(); bounded by the caller's distinct
# job count.  hashlib objects support neither weakrefs nor use as dict keys,
# so a plain dict keyed on the bytes is the safe shape.
_PREFIX_BASE_CACHE: "dict[bytes, 'hashlib._Hash']" = {}


def clear_job_cache() -> None:
    """Drop cached per-job base sha256 objects (test hygiene)."""
    _PREFIX_BASE_CACHE.clear()


def search(
    job: MidstateJob,
    start_nonce: int = 0,
    max_nonces: int = 1 << 20,
    nonce_stride: int = 1,
) -> Optional[FoundShare]:
    """Search a nonce window for one real share.

    `nonce_stride` models per-chip nonce-range distribution
    (HASH_COUNTING_NUMBER / core interleaving): each simulated searching
    core walks its own stride through the 32-bit nonce space.
    """
    if max_nonces <= 0:
        raise ValueError("max_nonces must be positive")
    hits = _scan(job, start_nonce, max_nonces, nonce_stride, want=1)
    return hits[0] if hits else None


def search_many(
    job: MidstateJob,
    start_nonce: int,
    max_nonces: int,
    want: int,
    nonce_stride: int = 1,
) -> List[FoundShare]:
    """Collect up to `want` real shares from one window (bounded work)."""
    if max_nonces <= 0:
        raise ValueError("max_nonces must be positive")
    return _scan(job, start_nonce, max_nonces, nonce_stride, want)


# ---------------------------------------------------------------------------
# Multiprocess worker pool (optional; stdlib concurrent.futures)
# ---------------------------------------------------------------------------

_WORKER_JOB: Optional[MidstateJob] = None


def _pool_init(job: MidstateJob) -> None:
    global _WORKER_JOB
    _WORKER_JOB = job


def _pool_search(chunk: Tuple[int, int, int]) -> Optional[FoundShare]:
    assert _WORKER_JOB is not None
    hits = _scan(_WORKER_JOB, chunk[0], chunk[1], chunk[2], want=1)
    return hits[0] if hits else None


def search_parallel(
    job: MidstateJob,
    start_nonce: int = 0,
    max_nonces: int = 1 << 20,
    workers: int = 4,
    nonce_stride: int = 1,
) -> Optional[FoundShare]:
    """Optional multiprocess search: splits the window into per-worker nonce
    sub-ranges.  Stdlib only (`concurrent.futures`).  Windows note: uses the
    spawn start method (default); requires this module to be importable."""
    import concurrent.futures as cf

    if workers <= 1:
        return search(job, start_nonce, max_nonces, nonce_stride)
    clear_job_cache()
    chunk = max(1, max_nonces // workers)
    chunks: List[Tuple[int, int, int]] = []
    off = start_nonce
    remaining = max_nonces
    while remaining > 0:
        n = min(chunk, remaining)
        chunks.append((off, n, nonce_stride))
        off += n * nonce_stride
        remaining -= n
    with cf.ProcessPoolExecutor(
        max_workers=workers, initializer=_pool_init, initargs=(job,)
    ) as ex:
        for res in ex.map(_pool_search, chunks):
            if res is not None:
                return res
    return None


__all__ = [
    "DIFFICULTY_1_TARGET",
    "sha256d",
    "hash_to_uint_le",
    "hash_to_uint_be",
    "target_from_difficulty",
    "target_from_nbits",
    "true_midstate",
    "sha256_from_midstate",
    "MidstateJob",
    "FoundShare",
    "search",
    "search_many",
    "search_parallel",
    "clear_job_cache",
]
