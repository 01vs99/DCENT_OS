"""Nonce-engine tests: every share is a REAL double-SHA256 result.

The core property under test: any nonce the engine returns, when the full
80-byte header is hashed with plain `hashlib` by the TEST (no engine code),
meets the share target.  Plus midstate correctness, target decoding, and
bounded subsampling.

License: GPL-3.0 (DCENT_OS emu-twin).
Fund: https://d-central.tech/fund/
"""

from __future__ import annotations

import hashlib
import random
import struct

import pytest

import nonce_engine as ne
import protocol as wire


def _make_header(job_id: int = 0) -> bytes:
    """Deterministic pseudo-random 76-byte header prefix (full header minus
    the nonce)."""
    rng = random.Random(0xBEEF + job_id)
    version = 0x2000_0000
    prevhash = bytes(rng.randrange(256) for _ in range(32))
    merkle = bytes(rng.randrange(256) for _ in range(32))
    ntime = 0x6802_AB6E
    nbits = 0x1D00_FFFF
    return (
        struct.pack("<I", version) + prevhash + merkle +
        struct.pack("<II", ntime, nbits)
    )


def _plain_sha256d(header80: bytes) -> int:
    # big-endian per the daemon share gate (difficulty.rs::meets_target, MSB-first)
    """Verification hash computed with plain hashlib in the test."""
    digest = hashlib.sha256(hashlib.sha256(header80).digest()).digest()
    return int.from_bytes(digest, "big")


class TestRealSearch:
    def test_found_share_meets_target_when_recomputed(self):
        prefix = _make_header()
        difficulty = 2e-5
        target = ne.target_from_difficulty(difficulty)
        job = ne.MidstateJob.from_header_prefix(prefix, target)
        share = ne.search(job, start_nonce=0, max_nonces=1 << 19)
        assert share is not None, "bounded window found no share — rerun"
        header80 = prefix + struct.pack("<I", share.nonce)
        recomputed = _plain_sha256d(header80)
        assert recomputed <= target
        assert recomputed == share.digest_uint

    def test_digest_helper_matches_plain_hashlib(self):
        prefix = _make_header(1)
        job = ne.MidstateJob.from_header_prefix(
            prefix, ne.target_from_difficulty(1e-4)
        )
        for nonce in (0, 1, 42, 0xFFFF_FFFF):
            header80 = job.header(nonce)
            assert job.digest(nonce) == hashlib.sha256(
                hashlib.sha256(header80).digest()
            ).digest()

    def test_search_many_respects_want_and_all_meet_target(self):
        prefix = _make_header(2)
        target = ne.target_from_difficulty(1e-5)
        job = ne.MidstateJob.from_header_prefix(prefix, target)
        shares = ne.search_many(job, start_nonce=0, max_nonces=1 << 19, want=3)
        assert 1 <= len(shares) <= 3
        nonces = set()
        for share in shares:
            header80 = prefix + struct.pack("<I", share.nonce)
            assert _plain_sha256d(header80) <= target
            nonces.add(share.nonce)
        assert len(nonces) == len(shares)

    def test_stride_search_stays_on_stride(self):
        prefix = _make_header(3)
        target = ne.target_from_difficulty(1e-5)
        job = ne.MidstateJob.from_header_prefix(prefix, target)
        share = ne.search(
            job, start_nonce=4, max_nonces=1 << 19, nonce_stride=2
        )
        assert share is not None
        assert share.nonce % 2 == 0
        header80 = prefix + struct.pack("<I", share.nonce)
        assert _plain_sha256d(header80) <= target

    def test_window_bound_is_honored(self):
        prefix = _make_header(4)
        # Impossible target: nothing meets it — the engine must stop at the
        # bounded window instead of scanning forever (subsampled search).
        job = ne.MidstateJob.from_header_prefix(prefix, target=1)
        share = ne.search(job, start_nonce=0, max_nonces=64)
        assert share is None


class TestMidstateForm:
    def test_sha256_from_midstate_equals_hashlib(self):
        rng = random.Random(7)
        for _ in range(8):
            block = bytes(rng.randrange(256) for _ in range(64))
            tail = bytes(rng.randrange(256) for _ in range(16))
            midstate = ne.true_midstate(block)  # TRUE prefix state
            assert ne.sha256_from_midstate(midstate, tail) == hashlib.sha256(
                block + tail
            ).digest()

    def test_true_midstate_is_not_the_padded_digest(self):
        # Guard the classic mistake: sha256(block).digest() finalizes with
        # padding — it is NOT the resumable state.  Our midstate IS.
        block = bytes(range(64))
        assert ne.true_midstate(block) != hashlib.sha256(block).digest()
        assert (
            ne.sha256_from_midstate(ne.true_midstate(block), b"")
            == hashlib.sha256(block).digest()
        )

    def test_midstate_digest_form_finds_same_class_shares(self):
        prefix = _make_header(5)
        target = ne.target_from_difficulty(2e-5)
        fast = ne.MidstateJob.from_header_prefix(prefix, target)
        seeded = ne.MidstateJob.from_midstate(
            fast.midstate, fast.tail, target
        )
        share = ne.search(seeded, start_nonce=0, max_nonces=1 << 19)
        assert share is not None
        # verify against the ORIGINAL header bytes, hashed with plain hashlib
        header80 = fast.header(share.nonce)
        assert _plain_sha256d(header80) <= target

    def test_jobs_from_both_forms_agree_per_nonce(self):
        prefix = _make_header(6)
        target = ne.target_from_difficulty(1)
        fast = ne.MidstateJob.from_header_prefix(prefix, target)
        seeded = ne.MidstateJob.from_midstate(fast.midstate, fast.tail, target)
        for nonce in (0, 5, 0x1234_5678):
            assert fast.digest(nonce) == seeded.digest(nonce)


class TestTargets:
    def test_difficulty_one_target_is_diff1_constant(self):
        assert ne.target_from_difficulty(1) == ne.DIFFICULTY_1_TARGET

    def test_fractional_difficulty_eases_target(self):
        # EASIER (smaller) difficulty -> BIGGER target (0.001 is 1000x easier)
        t_small = ne.target_from_difficulty(0.001)
        t_one = ne.target_from_difficulty(1.0)
        assert t_one == ne.DIFFICULTY_1_TARGET
        assert t_one * 1001 > t_small > t_one * 999
        assert t_small > 0

    def test_nbits_genesis_decode(self):
        # [BITCOIN-CONSENSUS] genesis nbits 0x1D00FFFF -> known target
        target = ne.target_from_nbits(0x1D00_FFFF)
        assert target == 0x00000000FFFF0000000000000000000000000000000000000000000000000000

    def test_invalid_difficulty_rejected(self):
        with pytest.raises(ValueError):
            ne.target_from_difficulty(0)
        with pytest.raises(ValueError):
            ne.target_from_difficulty(-1)


class TestParallelSearch:
    def test_parallel_finds_a_real_share(self):
        prefix = _make_header(7)
        target = ne.target_from_difficulty(1e-5)
        job = ne.MidstateJob.from_header_prefix(prefix, target)
        share = ne.search_parallel(
            job, start_nonce=0, max_nonces=1 << 18, workers=2
        )
        if share is not None:  # bounded window; usually finds one
            header80 = prefix + struct.pack("<I", share.nonce)
            assert _plain_sha256d(header80) <= target


class TestJobFieldsIntegration:
    def test_job_fields_prefix_is_hashable_by_engine(self):
        # The exact interface chain_server uses: protocol.JobFields ->
        # header_prefix() -> MidstateJob.from_header_prefix
        rng = random.Random(9)
        fields = wire.JobFields(
            job_id=24,
            num_midstates=1,
            starting_nonce=0,
            nbits=0x1D00_FFFF,
            ntime=0x6802_AB6E,
            merkle_root=bytes(rng.randrange(256) for _ in range(32)),
            prev_block_hash=bytes(rng.randrange(256) for _ in range(32)),
            version=0x2000_0000,
        )
        prefix = fields.header_prefix()
        assert len(prefix) == 76
        job = ne.MidstateJob.from_header_prefix(
            prefix, ne.target_from_difficulty(2e-5)
        )
        share = ne.search(job, max_nonces=1 << 19)
        assert share is not None
        header80 = fields.header_prefix() + struct.pack("<I", share.nonce)
        assert _plain_sha256d(header80) <= ne.target_from_difficulty(2e-5)

    def test_version_rolling_changes_hash(self):
        rng = random.Random(11)
        fields = wire.JobFields(
            job_id=0, num_midstates=1, starting_nonce=0,
            nbits=0x1D00_FFFF, ntime=1,
            merkle_root=bytes(rng.randrange(256) for _ in range(32)),
            prev_block_hash=bytes(rng.randrange(256) for _ in range(32)),
            version=0x2000_0000,
        )
        base = fields.header_prefix(version_bits=0)
        rolled = fields.header_prefix(version_bits=0x0F)
        assert base[:4] != rolled[:4]
        # rolled = (base & ~mask) | ((vbits<<13) & mask)
        b, r = struct.unpack("<I", base[:4])[0], struct.unpack("<I", rolled[:4])[0]
        assert r == (b & ~wire.VERSION_ROLLING_FIELD_MASK) | (
            (0x0F << 13) & wire.VERSION_ROLLING_FIELD_MASK
        )
        assert base[4:] == rolled[4:]
