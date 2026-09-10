"""
Automatic classification and confidence scoring for recovered artefacts.

A carving tool that reports "1,842 files recovered" without qualification is
close to useless in a forensic context: the number is dominated by false
positives unless something filters them. This module assigns each artefact a
0-100 confidence score built from independent signals, so an investigator can
triage by score and cite the reasoning behind every number.

The score is additive over named factors, and every factor is retained in the
report. That means a reviewer can disagree with our weighting and recompute -
which is the point. An opaque score would be unauditable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sanctum.core.hashing import shannon_entropy
from sanctum.recover.signatures import (
    CATEGORY_AUDIO,
    CATEGORY_IMAGE,
    CATEGORY_VIDEO,
    FileSignature,
)

#: Formats whose content is normally compressed or encoded, so high entropy is
#: expected rather than suspicious.
_HIGH_ENTROPY_CATEGORIES = {
    CATEGORY_IMAGE, CATEGORY_VIDEO, CATEGORY_AUDIO, "Archive",
}

LABEL_HIGH = "High"
LABEL_MEDIUM = "Medium"
LABEL_LOW = "Low"

HIGH_THRESHOLD = 80.0
MEDIUM_THRESHOLD = 55.0


@dataclass
class ConfidenceFactor:
    """One contribution to a score, retained for auditability."""

    name: str
    weight: float
    detail: str = ""

    def as_dict(self) -> dict:
        return {"factor": self.name, "weight": self.weight, "detail": self.detail}


@dataclass
class Classification:
    """The scored verdict for one artefact."""

    category: str
    signature_id: str
    label: str
    confidence: float
    factors: list[ConfidenceFactor] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def explain(self) -> str:
        lines = [f"{self.label} confidence ({self.confidence:.0f}/100) - {self.category}"]
        for factor in self.factors:
            sign = "+" if factor.weight >= 0 else ""
            lines.append(f"  {sign}{factor.weight:g}  {factor.name}: {factor.detail}")
        for warning in self.warnings:
            lines.append(f"  !  {warning}")
        return "\n".join(lines)

    def as_dict(self) -> dict:
        return {
            "category": self.category,
            "signature_id": self.signature_id,
            "label": self.label,
            "confidence": round(self.confidence, 2),
            "factors": [f.as_dict() for f in self.factors],
            "warnings": self.warnings,
        }


def label_for(score: float) -> str:
    if score >= HIGH_THRESHOLD:
        return LABEL_HIGH
    if score >= MEDIUM_THRESHOLD:
        return LABEL_MEDIUM
    return LABEL_LOW


def score_artifact(
    signature: FileSignature,
    probe: bytes,
    *,
    validated: bool,
    footer_found: bool,
    truncated: bool,
    recovered_length: int,
) -> Classification:
    """
    Score one recovered artefact.

    Signals are deliberately independent: a structural parse, a terminating
    marker, a plausible length and a sane entropy profile are four different
    reasons to believe a find is real, and agreement between them is what
    justifies a high score.
    """
    factors: list[ConfidenceFactor] = []
    warnings: list[str] = []

    # 1. Structural validation - the strongest single signal.
    if validated:
        factors.append(
            ConfidenceFactor(
                "structural validation",
                45.0,
                f"parsed successfully as {signature.name}",
            )
        )
    else:
        factors.append(
            ConfidenceFactor(
                "structural validation",
                -15.0,
                "header matched but the format could not be parsed",
            )
        )
        warnings.append("Failed structural validation - likely a coincidental header match")

    # 2. Terminating marker.
    if footer_found:
        factors.append(
            ConfidenceFactor("terminator found", 25.0, "closing marker present")
        )
    elif signature.footers:
        factors.append(
            ConfidenceFactor(
                "terminator found",
                -10.0,
                f"no closing marker within {signature.max_size} bytes",
            )
        )
        warnings.append("No terminator: file may be fragmented or truncated")
    else:
        factors.append(
            ConfidenceFactor("terminator found", 5.0, "format has no terminator")
        )

    # 3. Length plausibility.
    if recovered_length < signature.min_size:
        factors.append(
            ConfidenceFactor(
                "length plausibility",
                -20.0,
                f"{recovered_length} bytes is below the {signature.min_size}-byte minimum",
            )
        )
        warnings.append("Recovered length below the format's minimum size")
    elif recovered_length >= signature.max_size:
        factors.append(
            ConfidenceFactor(
                "length plausibility",
                -5.0,
                f"hit the {signature.max_size}-byte search ceiling",
            )
        )
    else:
        factors.append(
            ConfidenceFactor(
                "length plausibility",
                15.0,
                f"{recovered_length} bytes is within the expected range",
            )
        )

    # 4. Entropy sanity - catches zero-filled or random regions that happen to
    #    start with a valid header.
    entropy = shannon_entropy(probe[: min(len(probe), 65536)])
    if entropy < 0.5:
        # Near-constant content: essentially every byte in the window is the
        # same. How damning that is depends on the format.
        #
        # For a compressed format it is close to conclusive. A JPEG, PNG, ZIP or
        # MP3 cannot be 99% one byte value; what this shape actually is, is the
        # stale header of a file that has since been overwritten, sitting at the
        # front of a wiped region. The penalty has to be large enough to keep
        # such a find out of Medium on structure alone, because structure is
        # exactly what survives a wipe - the header is intact and the payload
        # behind it is gone. A -25 penalty left the case below at 60 and
        # labelled it Medium: the tool would have called overwritten data a
        # recovered file and put a Medium badge on it.
        #
        # Uncompressed formats are a real exception. A solid-colour BMP or a
        # silent WAV is legitimately one byte value repeated for the whole
        # payload, and penalising it as hard would discard genuine finds. So the
        # category decides, and the warning is raised either way.
        penalty = -45.0 if signature.category in _HIGH_ENTROPY_CATEGORIES else -25.0
        factors.append(
            ConfidenceFactor(
                "entropy profile",
                penalty,
                f"{entropy:.2f} bits/byte (near-constant data)",
            )
        )
        warnings.append("Content is near-constant - likely wiped or padding, not a real file")
    elif signature.category in _HIGH_ENTROPY_CATEGORIES and entropy < 2.0:
        factors.append(
            ConfidenceFactor(
                "entropy profile",
                -8.0,
                f"{entropy:.2f} bits/byte is low for {signature.category} data",
            )
        )
    elif 2.0 <= entropy <= 8.0:
        factors.append(
            ConfidenceFactor("entropy profile", 10.0, f"{entropy:.2f} bits/byte")
        )
    else:
        factors.append(
            ConfidenceFactor("entropy profile", 0.0, f"{entropy:.2f} bits/byte")
        )

    # 5. Truncation penalty.
    if truncated:
        factors.append(
            ConfidenceFactor("completeness", -12.0, "recovery stopped at the size ceiling")
        )
        warnings.append("Truncated - the artefact was recovered only in part")

    total = max(0.0, min(100.0, sum(f.weight for f in factors)))

    return Classification(
        category=signature.category,
        signature_id=signature.id,
        label=label_for(total),
        confidence=total,
        factors=factors,
        warnings=warnings,
    )


def refine_category(
    signature: FileSignature, probe: bytes, fallback: Classification
) -> Classification:
    """
    Ambiguity resolution for container formats.

    If a generic ZIP was carved but the payload actually contains an Office
    marker, we still report ZIP rather than guessing - the specific OOXML
    signatures run at higher priority and will have claimed it already. This
    hook exists so future heuristics (file-command style probing, ML
    classification) can be added without touching the carver.
    """
    return fallback


def summarize_artifacts(classifications: list[Classification]) -> dict:
    """Aggregate counts for the dashboard and report header."""
    by_category: dict[str, int] = {}
    by_label: dict[str, int] = {"High": 0, "Medium": 0, "Low": 0}
    total_confidence = 0.0

    for item in classifications:
        by_category[item.category] = by_category.get(item.category, 0) + 1
        by_label[item.label] = by_label.get(item.label, 0) + 1
        total_confidence += item.confidence

    count = len(classifications) or 1
    return {
        "total": len(classifications),
        "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
        "by_confidence": by_label,
        "mean_confidence": round(total_confidence / count, 2),
    }
