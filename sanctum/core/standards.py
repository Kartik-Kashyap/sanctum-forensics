"""
Overwrite standards library.

Each standard is declared as an ordered list of write passes plus a verification
policy. The erasure engine is generic: it walks whatever pass list a standard
declares, so adding a new regulatory scheme is a data change, not a code change.

A note on honesty in the UI: overwrite-based sanitization is genuinely effective
on magnetic media (HDD), where writes are physical and addressable. It is *not*
a reliable purge for SSDs, SMR drives or anything with wear-levelling, because
the controller remaps logical blocks and may retain the old physical pages. For
those devices the correct answer is the drive's own firmware sanitize command
(ATA SANITIZE / SECURITY ERASE UNIT, NVMe Format / Sanitize, or TCG Opal crypto
erase). SANCTUM says so plainly rather than implying an overwrite is a purge -
that distinction is exactly the kind of thing an audit is supposed to catch.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence


class PatternKind(str, Enum):
    """The shape of a single overwrite pass."""

    ZERO = "ZERO"          # all 0x00
    ONE = "ONE"            # all 0xFF
    RANDOM = "RANDOM"      # cryptographically random
    BYTE = "BYTE"          # one byte value repeated
    CYCLE = "CYCLE"        # short byte sequence tiled across the region


@dataclass(frozen=True)
class PassSpec:
    """One overwrite pass."""

    kind: PatternKind
    byte: int | None = None
    sequence: bytes | None = None
    label: str = ""
    verify: bool = False

    def describe(self) -> str:
        if self.label:
            return self.label
        if self.kind is PatternKind.ZERO:
            return "0x00"
        if self.kind is PatternKind.ONE:
            return "0xFF"
        if self.kind is PatternKind.RANDOM:
            return "random"
        if self.kind is PatternKind.BYTE and self.byte is not None:
            return f"0x{self.byte:02X}"
        if self.kind is PatternKind.CYCLE and self.sequence:
            return " ".join(f"0x{b:02X}" for b in self.sequence)
        return self.kind.value

    def build_buffer(self, size: int) -> bytes:
        """Materialise one buffer of this pattern. Callers tile it as needed."""
        if self.kind is PatternKind.ZERO:
            return bytes(size)
        if self.kind is PatternKind.ONE:
            return b"\xff" * size
        if self.kind is PatternKind.RANDOM:
            return os.urandom(size)
        if self.kind is PatternKind.BYTE:
            value = 0x00 if self.byte is None else self.byte
            return bytes([value]) * size
        if self.kind is PatternKind.CYCLE:
            if not self.sequence:
                raise ValueError(
                    "A CYCLE pass needs a byte sequence to tile; without one "
                    "there is no pattern to write and no pattern to verify "
                    "against. Substituting zeros here would produce a pass that "
                    "claims to be Gutmann's 0x92/0x49/0x24 cycle and is "
                    "indistinguishable, in the report, from a zeros pass."
                )
            repeats = (size // len(self.sequence)) + 1
            return (self.sequence * repeats)[:size]
        raise ValueError(f"Unsupported pattern kind: {self.kind}")

    @property
    def period(self) -> int:
        """Length in bytes of the pattern's repeating unit."""
        if self.kind is PatternKind.CYCLE and self.sequence:
            return len(self.sequence)
        return 1

    def aligned_size(self, requested: int) -> int:
        """
        Largest whole number of pattern periods that fits in ``requested``.

        A repeating pattern must be written in whole periods. Tiling a 3-byte
        Gutmann sequence in 1 MiB chunks shifts its phase after the first
        megabyte - the write would still be a valid-looking fill, but it would
        no longer be the sequence the standard specifies, and the compliance
        claim in the report would be false. Callers size their write buffer with
        this so the phase stays continuous across the whole target.
        """
        period = self.period
        if requested <= period:
            return period
        return requested - (requested % period)

    def expected_at(self, offset: int, length: int) -> bytes:
        """
        The bytes this pattern should hold at absolute ``offset``.

        Verification reads windows at arbitrary offsets, so it cannot assume the
        window starts on a pattern boundary.
        """
        period = self.period
        if period == 1:
            return self.build_buffer(length)
        phase = offset % period
        return self.build_buffer(length + period)[phase : phase + length]


def _zero(label: str = "", verify: bool = False) -> PassSpec:
    return PassSpec(PatternKind.ZERO, label=label, verify=verify)


def _one(label: str = "", verify: bool = False) -> PassSpec:
    return PassSpec(PatternKind.ONE, label=label, verify=verify)


def _random(label: str = "", verify: bool = False) -> PassSpec:
    return PassSpec(PatternKind.RANDOM, label=label, verify=verify)


def _byte(value: int, label: str = "", verify: bool = False) -> PassSpec:
    return PassSpec(PatternKind.BYTE, byte=value, label=label or f"0x{value:02X}", verify=verify)


def _cycle(sequence: bytes, label: str = "", verify: bool = False) -> PassSpec:
    return PassSpec(PatternKind.CYCLE, sequence=sequence, label=label, verify=verify)


@dataclass(frozen=True)
class EraseStandard:
    """A named sanitization scheme."""

    id: str
    name: str
    description: str
    passes: tuple[PassSpec, ...]
    compliance: tuple[str, ...] = ()
    verify_default: bool = True
    recommended_for: str = "HDD"
    notes: str = ""

    @property
    def pass_count(self) -> int:
        return len(self.passes)

    def effective_passes(self, verify: bool | None = None) -> tuple[PassSpec, ...]:
        """
        The pass list to execute, optionally forcing verification on/off.

        When verification is requested, any pass not already marked for
        verification is upgraded, so the operator gets the check they asked for
        without having to know which standards build it in.
        """
        if verify is None:
            verify = self.verify_default
        if not verify:
            return tuple(
                PassSpec(p.kind, p.byte, p.sequence, p.label, False) for p in self.passes
            )
        return tuple(
            PassSpec(p.kind, p.byte, p.sequence, p.label, True) for p in self.passes
        )


# --------------------------------------------------------------------------
# Standard definitions
# --------------------------------------------------------------------------

GUTMANN_PASSES: tuple[PassSpec, ...] = (
    _random(), _random(), _random(), _random(),
    _byte(0x55), _byte(0xAA),
    _cycle(b"\x92\x49\x24"), _cycle(b"\x49\x24\x92"), _cycle(b"\x24\x92\x49"),
    _byte(0x00), _byte(0x11), _byte(0x22), _byte(0x33), _byte(0x44),
    _byte(0x55), _byte(0x66), _byte(0x77), _byte(0x88), _byte(0x99),
    _byte(0xAA), _byte(0xBB), _byte(0xCC), _byte(0xDD), _byte(0xEE),
    _byte(0xFF),
    _cycle(b"\x92\x49\x24"), _cycle(b"\x49\x24\x92"), _cycle(b"\x24\x92\x49"),
    _byte(0x6D), _byte(0xB6), _byte(0xDB),
    _random(), _random(), _random(), _random(),
)

DOD_5220_22_M: tuple[PassSpec, ...] = (_zero(), _one(), _random(verify=True))

DOD_5220_22_M_ECE: tuple[PassSpec, ...] = (
    _zero(verify=True), _one(verify=True), _random(verify=True),
    _one(), _zero(), _one(), _random(verify=True),
)

SCHNEIER: tuple[PassSpec, ...] = (
    _one(), _zero(),
    _random(), _random(), _random(), _random(), _random(verify=True),
)

VSITR: tuple[PassSpec, ...] = (
    _zero(), _one(), _zero(), _one(), _zero(), _one(), _byte(0xAA, verify=True),
)

HMG_BASELINE: tuple[PassSpec, ...] = (_random(verify=True),)

HMG_ENHANCED: tuple[PassSpec, ...] = (_random(), _random(), _random(verify=True))


STANDARDS: tuple[EraseStandard, ...] = (
    EraseStandard(
        id="zero1",
        name="Single Pass Zeros",
        description="One pass of 0x00 across the entire region, then verify.",
        passes=(_zero(verify=True),),
        compliance=("NIST SP 800-88 Rev.1 - Clear (logical overwrite)",),
        recommended_for="HDD",
        notes="Fastest option. Acceptable for clearing non-sensitive media or "
              "for rapid re-provisioning where confidentiality risk is low.",
    ),
    EraseStandard(
        id="random1",
        name="Single Pass Random",
        description="One pass of cryptographically random data, then verify.",
        passes=(_random(verify=True),),
        compliance=(
            "NIST SP 800-88 Rev.1 - Clear (logical overwrite)",
            "HMG Infosec Standard 5 - Baseline",
        ),
        recommended_for="HDD",
        notes="Preferred over zeros when the final media state should not be "
              "trivially distinguishable from live data.",
    ),
    EraseStandard(
        id="nist_purge",
        name="NIST SP 800-88 Purge (overwrite profile)",
        description="Three-pass overwrite with full verification.",
        passes=(_random(), _random(), _random(verify=True)),
        compliance=("NIST SP 800-88 Rev.1 - Purge (software profile)",),
        recommended_for="HDD",
        notes="On magnetic media this satisfies a software-overwrite purge. On "
              "SSD/NVMe use the firmware sanitize command instead - see the "
              "device guidance panel.",
    ),
    EraseStandard(
        id="dod3",
        name="DoD 5220.22-M (3-pass)",
        description="Zeros, ones, random with verification on the final pass.",
        passes=DOD_5220_22_M,
        compliance=("DoD 5220.22-M", "NIST SP 800-88 Rev.1 - Clear"),
        recommended_for="HDD",
    ),
    EraseStandard(
        id="dod7",
        name="DoD 5220.22-M ECE (7-pass)",
        description="Extended DoD scheme: zeros, ones, random, then a "
                    "ones/zeros/ones/random sweep.",
        passes=DOD_5220_22_M_ECE,
        compliance=("DoD 5220.22-M ECE",),
        recommended_for="HDD",
        notes="Considerably slower than the 3-pass variant for a marginal "
              "increase in confidence against laboratory recovery.",
    ),
    EraseStandard(
        id="schneier7",
        name="Schneier (7-pass)",
        description="0xFF, 0x00, then five random passes with verification.",
        passes=SCHNEIER,
        compliance=("Schneier Algorithm",),
        recommended_for="HDD",
    ),
    EraseStandard(
        id="vsitr",
        name="VSITR (7-pass)",
        description="German VSITR scheme: alternating zeros/ones ending in 0xAA.",
        passes=VSITR,
        compliance=("VSITR (Germany)",),
        recommended_for="HDD",
    ),
    EraseStandard(
        id="hmg_enhanced",
        name="HMG Infosec Standard 5 - Enhanced",
        description="Three random passes with verification.",
        passes=HMG_ENHANCED,
        compliance=("HMG Infosec Standard 5 - Enhanced",),
        recommended_for="HDD",
    ),
    EraseStandard(
        id="gutmann",
        name="Gutmann (35-pass)",
        description="Peter Gutmann's 1996 scheme: 4 random passes, 27 targeted "
                    "patterns exploiting historical encoding artefacts, then 4 "
                    "more random passes.",
        passes=GUTMANN_PASSES,
        compliance=("Gutmann Method",),
        recommended_for="HDD",
        notes="Historically significant and useful for demonstrating rigour, but "
              "Gutmann himself has stated it is unnecessary for any drive made "
              "after roughly 2001. Expect a 35x runtime cost.",
    ),
)

STANDARDS_BY_ID: dict[str, EraseStandard] = {s.id: s for s in STANDARDS}


def get_standard(standard_id: str) -> EraseStandard:
    """Look up a standard by id, with a helpful error for typos."""
    try:
        return STANDARDS_BY_ID[standard_id]
    except KeyError:
        valid = ", ".join(sorted(STANDARDS_BY_ID))
        raise KeyError(f"Unknown erase standard '{standard_id}'. Available: {valid}") from None
