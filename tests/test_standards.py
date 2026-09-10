"""
Overwrite-standard library tests.

The standards are data, so what needs testing is that the data is right - the
pass counts and patterns that a compliance claim rests on. A Gutmann standard
that silently declares 34 passes instead of 35 would make every report citing it
wrong.
"""

from __future__ import annotations

import pytest

from sanctum.core.standards import (
    GUTMANN_PASSES,
    STANDARDS,
    STANDARDS_BY_ID,
    EraseStandard,
    PassSpec,
    PatternKind,
    get_standard,
)


# -- registry --------------------------------------------------------------

def test_standard_ids_are_unique():
    ids = [s.id for s in STANDARDS]
    assert len(ids) == len(set(ids))


def test_registry_lookup_matches_the_tuple():
    for standard in STANDARDS:
        assert STANDARDS_BY_ID[standard.id] is standard
        assert get_standard(standard.id) is standard


def test_unknown_standard_id_raises():
    with pytest.raises(KeyError):
        get_standard("no-such-standard")


def test_every_standard_declares_at_least_one_pass():
    for standard in STANDARDS:
        assert standard.pass_count >= 1, standard.id


def test_every_standard_has_a_description_and_compliance_note():
    for standard in STANDARDS:
        assert standard.description, standard.id
        assert standard.name, standard.id


# -- pass counts -----------------------------------------------------------

@pytest.mark.parametrize(
    "standard_id,expected",
    [
        ("zero1", 1),
        ("random1", 1),
        ("nist_purge", 3),
        ("dod3", 3),
        ("dod7", 7),
        ("schneier7", 7),
        ("vsitr", 7),
        ("hmg_enhanced", 3),
        ("gutmann", 35),
    ],
)
def test_declared_pass_counts(standard_id, expected):
    assert get_standard(standard_id).pass_count == expected


def test_every_registry_entry_is_covered_by_the_pass_count_table():
    """
    Guards the table above against drift: a standard added to the registry
    without a declared pass count would otherwise go unchecked, and the pass
    count is what the compliance claim rests on.
    """
    declared = {
        "zero1", "random1", "nist_purge", "dod3", "dod7",
        "schneier7", "vsitr", "hmg_enhanced", "gutmann",
    }
    assert declared == {s.id for s in STANDARDS}


def test_gutmann_table_has_thirty_five_passes():
    """
    The published Gutmann scheme is 35 passes: 4 random, 27 targeted patterns,
    4 random. Counting this wrong would invalidate the compliance claim.
    """
    standard = get_standard("gutmann")
    assert len(GUTMANN_PASSES) == 35

    random_passes = [p for p in GUTMANN_PASSES if p.kind is PatternKind.RANDOM]
    assert len(random_passes) == 8  # four at each end

    # The first four and last four are random.
    assert all(p.kind is PatternKind.RANDOM for p in GUTMANN_PASSES[:4])
    assert all(p.kind is PatternKind.RANDOM for p in GUTMANN_PASSES[-4:])
    assert standard.pass_count == 35


def test_gutmann_includes_the_characteristic_patterns():
    """
    Spot-check the documented Gutmann sequences.

    0x92, 0x49 and 0x24 appear in the scheme *only* as the three 3-byte cycles
    (and, for the first two, again later), never as single-byte passes. The
    single-byte sweep is the 16-step 0x00, 0x11 ... 0xFF progression. Asserting
    those three bytes against the single-byte set asks the implementation to
    cover a byte with a pass Gutmann never specified, so the two claims are
    checked separately - which is also what makes this test able to fail.
    """
    sequences = {
        tuple(p.sequence) for p in GUTMANN_PASSES if p.kind is PatternKind.CYCLE and p.sequence
    }
    assert (0x92, 0x49, 0x24) in sequences
    assert (0x49, 0x24, 0x92) in sequences
    assert (0x24, 0x92, 0x49) in sequences

    singles = [p.byte for p in GUTMANN_PASSES if p.kind is PatternKind.BYTE]
    # Two opening byte passes, then the 16-step progression, then the three
    # trailing bytes - in the order the method specifies them.
    assert singles[:2] == [0x55, 0xAA]
    assert singles[2:18] == [0x11 * step for step in range(16)]
    assert singles[18:] == [0x6D, 0xB6, 0xDB]

    # Every byte the scheme writes, from either kind of pass.
    covered = set(singles)
    for sequence in sequences:
        covered.update(sequence)
    assert {0x55, 0xAA, 0x92, 0x49, 0x24, 0x6D, 0xB6, 0xDB} <= covered


def test_dod_ece_is_the_three_pass_scheme_run_then_repeated_with_random():
    standard = get_standard("dod7")
    kinds = [p.kind for p in standard.passes]
    assert PatternKind.RANDOM in kinds
    assert standard.pass_count == 7


# -- pass semantics --------------------------------------------------------

def test_zero_pass_builds_a_zero_buffer():
    spec = PassSpec(PatternKind.ZERO)
    assert spec.build_buffer(16) == b"\x00" * 16


def test_one_pass_builds_a_ff_buffer():
    assert PassSpec(PatternKind.ONE).build_buffer(16) == b"\xff" * 16


def test_byte_pass_builds_a_repeated_byte():
    assert PassSpec(PatternKind.BYTE, byte=0x5A).build_buffer(8) == b"\x5a" * 8


def test_cycle_pass_tiles_the_sequence():
    spec = PassSpec(PatternKind.CYCLE, sequence=b"\x92\x49\x24")
    assert spec.build_buffer(7) == b"\x92\x49\x24\x92\x49\x24\x92"


def test_random_pass_produces_different_buffers():
    """
    A random pass that returned the same bytes twice would defeat its own
    purpose - each pass must write fresh data.
    """
    spec = PassSpec(PatternKind.RANDOM)
    first = spec.build_buffer(4096)
    second = spec.build_buffer(4096)
    assert len(first) == 4096
    assert first != second


def test_random_pass_has_high_entropy():
    from sanctum.core.hashing import shannon_entropy

    assert shannon_entropy(PassSpec(PatternKind.RANDOM).build_buffer(65536)) > 7.5


def test_build_buffer_respects_the_requested_size():
    for kind in (PatternKind.ZERO, PatternKind.ONE, PatternKind.RANDOM):
        assert len(PassSpec(kind).build_buffer(1000)) == 1000


def test_cycle_pass_requires_a_sequence():
    with pytest.raises(ValueError):
        PassSpec(PatternKind.CYCLE, sequence=b"").build_buffer(16)


def test_describe_reads_humanly():
    assert PassSpec(PatternKind.ZERO).describe() == "0x00"
    assert PassSpec(PatternKind.ONE).describe() == "0xFF"
    assert PassSpec(PatternKind.RANDOM).describe() == "random"
    assert PassSpec(PatternKind.BYTE, byte=0x6D).describe() == "0x6D"
    assert PassSpec(PatternKind.CYCLE, sequence=b"\x92\x49\x24").describe() == "0x92 0x49 0x24"
    assert PassSpec(PatternKind.ZERO, label="custom").describe() == "custom"


# -- verification policy ---------------------------------------------------

def test_effective_passes_can_force_verification_on():
    standard = get_standard("dod3")
    forced = standard.effective_passes(True)
    assert all(p.verify for p in forced)
    # Forcing verification must not change which passes run.
    assert [p.kind for p in forced] == [p.kind for p in standard.passes]


def test_effective_passes_can_force_verification_off():
    standard = get_standard("dod7")
    assert not any(p.verify for p in standard.effective_passes(False))


def test_effective_passes_defaults_to_the_standard_policy():
    standard = get_standard("zero1")
    assert standard.effective_passes(None) == standard.passes


# -- pattern phase ---------------------------------------------------------

def test_single_byte_patterns_have_a_period_of_one():
    for kind in (PatternKind.ZERO, PatternKind.ONE, PatternKind.RANDOM):
        assert PassSpec(kind).period == 1
    assert PassSpec(PatternKind.BYTE, byte=0x55).period == 1


def test_cycle_period_is_the_sequence_length():
    assert PassSpec(PatternKind.CYCLE, sequence=b"\x92\x49\x24").period == 3


def test_aligned_size_rounds_down_to_whole_periods():
    spec = PassSpec(PatternKind.CYCLE, sequence=b"\x92\x49\x24")
    assert spec.aligned_size(1024) == 1023      # 1024 % 3 == 1
    assert spec.aligned_size(1023) == 1023
    assert spec.aligned_size(1048576) == 1048575  # CHUNK_SIZE is not a multiple of 3


def test_aligned_size_never_returns_zero():
    """A buffer shorter than one period must still hold a whole period."""
    spec = PassSpec(PatternKind.CYCLE, sequence=b"\x92\x49\x24")
    assert spec.aligned_size(2) == 3
    assert spec.aligned_size(0) == 3


def test_aligned_size_leaves_period_one_patterns_alone():
    assert PassSpec(PatternKind.ZERO).aligned_size(1048576) == 1048576


def test_tiling_an_aligned_buffer_is_phase_continuous():
    """
    The bug this guards against.

    The real CHUNK_SIZE is 1 MiB, which is not a multiple of 3, so a naive
    implementation writes the sequence 0x92 0x49 0x24 from the start of every
    chunk. Past the first megabyte the media no longer holds the pattern the
    standard specifies - and the report would still claim it did.
    """
    spec = PassSpec(PatternKind.CYCLE, sequence=b"\x92\x49\x24")
    chunk = spec.aligned_size(1048576)
    buffer = spec.build_buffer(chunk)

    # Tiling the chunk must equal one continuous run of the sequence.
    tiled = buffer + buffer
    continuous = spec.build_buffer(len(tiled))
    assert tiled == continuous


def test_unaligned_tiling_would_break_phase():
    """Confirms the guard above is testing something real."""
    spec = PassSpec(PatternKind.CYCLE, sequence=b"\x92\x49\x24")
    unaligned = spec.build_buffer(1048576)
    assert (unaligned + unaligned) != spec.build_buffer(len(unaligned) * 2)


def test_expected_at_shifts_the_phase_with_the_offset():
    spec = PassSpec(PatternKind.CYCLE, sequence=b"\x92\x49\x24")
    assert spec.expected_at(0, 3) == b"\x92\x49\x24"
    assert spec.expected_at(1, 3) == b"\x49\x24\x92"
    assert spec.expected_at(2, 3) == b"\x24\x92\x49"


def test_expected_at_matches_a_continuous_write_at_any_offset():
    """Verification windows fall where they fall; the comparison must hold."""
    spec = PassSpec(PatternKind.CYCLE, sequence=b"\x92\x49\x24")
    written = spec.build_buffer(99)
    for offset in (0, 1, 2, 3, 17, 33):
        assert spec.expected_at(offset, 5) == written[offset : offset + 5]


def test_expected_at_is_trivial_for_period_one_patterns():
    assert PassSpec(PatternKind.BYTE, byte=0x55).expected_at(12345, 4) == b"\x55" * 4
