"""Hashing, entropy and wipe-detection primitives."""

from __future__ import annotations

import hashlib
import io
import os

import pytest

from sanctum.core import hashing


# -- digests ---------------------------------------------------------------

def test_hash_bytes_matches_hashlib():
    data = b"sanctum" * 1000
    digests = hashing.hash_bytes(data)
    assert digests["sha256"] == hashlib.sha256(data).hexdigest()
    assert digests["md5"] == hashlib.md5(data).hexdigest()
    assert digests["sha1"] == hashlib.sha1(data).hexdigest()


def test_hash_file_matches_hash_bytes(tmp_path):
    data = os.urandom(300_000)
    path = tmp_path / "blob.bin"
    path.write_bytes(data)
    assert hashing.hash_file(path) == hashing.hash_bytes(data)


def test_streamed_digest_is_chunk_boundary_independent(tmp_path):
    """
    A streamed digest must not depend on where the chunk boundaries fell.

    This is the property that lets a multi-terabyte image be hashed in 1 MiB
    chunks and still produce the digest a single-shot hash would.
    """
    data = os.urandom(5 * 1024 * 1024 + 12345)
    path = tmp_path / "big.bin"
    path.write_bytes(data)

    streamed = hashing.hash_file(path, chunk_size=64 * 1024)
    assert streamed["sha256"] == hashlib.sha256(data).hexdigest()


def test_iter_chunks_reads_a_window(tmp_path):
    data = bytes(range(256)) * 40  # 10240 bytes
    stream = io.BytesIO(data)
    pieces = list(hashing.iter_chunks(stream, 1024, offset=512, limit=2048))
    assert len(pieces) == 2
    assert b"".join(pieces) == data[512 : 512 + 2048]


def test_iter_chunks_yields_full_input_once():
    data = os.urandom(2500)
    pieces = list(hashing.iter_chunks(io.BytesIO(data), 1024))
    assert b"".join(pieces) == data


# -- content characterisation ---------------------------------------------

def test_entropy_of_constant_data_is_zero():
    assert hashing.shannon_entropy(b"\x00" * 4096) == pytest.approx(0.0, abs=1e-9)


def test_entropy_of_uniform_random_is_near_eight():
    value = hashing.shannon_entropy(os.urandom(65536))
    assert 7.8 < value <= 8.0


def test_entropy_of_empty_input_is_zero():
    assert hashing.shannon_entropy(b"") == 0.0


def test_entropy_profile_separates_constant_from_random():
    data = b"\x00" * 8192 + os.urandom(8192)
    profile = hashing.entropy_profile(data, block=4096)
    assert len(profile) == 4
    assert profile[0] == pytest.approx(0.0, abs=1e-9)
    assert profile[1] == pytest.approx(0.0, abs=1e-9)
    assert profile[-1] > 7.0


def test_constant_byte_detects_uniform_fill():
    assert hashing.constant_byte(b"\xaa" * 1024) == 0xAA
    assert hashing.constant_byte(os.urandom(1024)) is None
    assert hashing.constant_byte(b"") is None


def test_is_probably_wiped_accepts_zero_fill():
    assert hashing.is_probably_wiped(b"\x00" * 4096)


def test_is_probably_wiped_rejects_random_data():
    assert not hashing.is_probably_wiped(os.urandom(4096))


# -- comparison ------------------------------------------------------------

def test_compare_digests_reports_differing_algorithms():
    expected = {"sha256": "aa", "md5": "bb"}
    actual = {"sha256": "aa", "md5": "cc"}
    matched, differing = hashing.compare_digests(expected, actual)
    assert not matched
    assert differing == ["md5"]


def test_compare_digests_ignores_algorithms_absent_from_one_side():
    """
    A report generated with a wider algorithm set must not be judged mismatched
    against one computed with fewer - only the shared algorithms count.
    """
    matched, differing = hashing.compare_digests(
        {"sha256": "aa"}, {"sha256": "aa", "md5": "bb", "sha1": "cc"}
    )
    assert matched
    assert differing == []


def test_compare_digests_is_case_insensitive():
    matched, _ = hashing.compare_digests({"sha256": "AABB"}, {"sha256": "aabb"})
    assert matched


# -- formatting ------------------------------------------------------------

@pytest.mark.parametrize(
    "value,expected",
    [
        (0, "0 B"),
        (512, "512 B"),
        (1024, "1.00 KB"),
        (1024 * 1024, "1.00 MB"),
        (1024 ** 3, "1.00 GB"),
        (1024 ** 4, "1.00 TB"),
    ],
)
def test_human_bytes(value, expected):
    assert hashing.human_bytes(value) == expected
