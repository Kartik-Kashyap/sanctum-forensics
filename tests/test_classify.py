"""
Confidence scoring tests.

The score exists so an examiner can triage thousands of carved artefacts, and it
is only defensible if the number can be explained. The central test here is that
the reported score is exactly the sum of the named factors that were retained -
if that ever stops holding, the score becomes an opaque number that no reviewer
can check.
"""

from __future__ import annotations

import os

import pytest

from tools.sample_files import make_jpeg

from sanctum.recover.classify import (
    HIGH_THRESHOLD,
    LABEL_HIGH,
    LABEL_LOW,
    LABEL_MEDIUM,
    MEDIUM_THRESHOLD,
    Classification,
    ConfidenceFactor,
    label_for,
    score_artifact,
    summarize_artifacts,
)
from sanctum.recover.signatures import get_signature


@pytest.fixture
def signature():
    return get_signature("jpeg")


@pytest.fixture
def probe():
    return make_jpeg(64, 64)


def _perfect(signature, probe):
    return score_artifact(
        signature, probe, validated=True, footer_found=True,
        truncated=False, recovered_length=len(probe),
    )


# -- thresholds ------------------------------------------------------------

@pytest.mark.parametrize(
    "score,expected",
    [
        (100.0, LABEL_HIGH),
        (HIGH_THRESHOLD, LABEL_HIGH),
        (HIGH_THRESHOLD - 0.1, LABEL_MEDIUM),
        (MEDIUM_THRESHOLD, LABEL_MEDIUM),
        (MEDIUM_THRESHOLD - 0.1, LABEL_LOW),
        (0.0, LABEL_LOW),
    ],
)
def test_label_thresholds(score, expected):
    assert label_for(score) == expected


# -- the auditability invariant -------------------------------------------

def test_the_score_is_exactly_the_sum_of_its_factors(signature, probe):
    """
    The property that makes the score reviewable.

    A reviewer who disagrees with a weighting can recompute the total from the
    retained factors - but only if the total really is their sum.
    """
    cases = [
        dict(validated=True, footer_found=True, truncated=False, recovered_length=len(probe)),
        dict(validated=False, footer_found=False, truncated=True, recovered_length=10),
        dict(validated=True, footer_found=False, truncated=False, recovered_length=len(probe)),
    ]
    for case in cases:
        result = score_artifact(signature, probe, **case)
        assert result.confidence == max(0.0, min(100.0, sum(f.weight for f in result.factors)))


def test_every_factor_is_named_and_explained(signature, probe):
    result = _perfect(signature, probe)
    assert result.factors
    for factor in result.factors:
        assert factor.name
        assert factor.detail


def test_the_score_stays_within_bounds(signature, probe):
    worst = score_artifact(signature, b"\x00" * 4096, validated=False,
                           footer_found=False, truncated=True, recovered_length=1)
    assert 0.0 <= worst.confidence <= 100.0


# -- individual signals ----------------------------------------------------

def test_a_structurally_valid_file_with_a_terminator_scores_high(signature, probe):
    result = _perfect(signature, probe)

    assert result.confidence >= HIGH_THRESHOLD
    assert result.label == LABEL_HIGH
    assert result.category == signature.category
    assert result.signature_id == signature.id


def test_failing_structural_validation_costs_and_warns(signature, probe):
    """
    A header match with nothing behind it is the classic false positive, so
    this is the heaviest single penalty.
    """
    result = score_artifact(signature, probe, validated=False, footer_found=True,
                            truncated=False, recovered_length=len(probe))

    assert result.confidence < HIGH_THRESHOLD
    assert any("structural validation" in f.name for f in result.factors)
    assert any("coincidental" in w for w in result.warnings)


def test_a_missing_terminator_costs_and_warns(signature, probe):
    result = score_artifact(signature, probe, validated=True, footer_found=False,
                            truncated=False, recovered_length=len(probe))

    assert result.confidence < _perfect(signature, probe).confidence
    assert any("terminator" in w.lower() or "fragment" in w.lower() for w in result.warnings)


def test_a_format_without_a_terminator_is_not_penalised_for_lacking_one():
    """
    Penalising a format for the absence of a footer it never had would be a
    systematic bias against those formats.
    """
    signature = get_signature("sqlite")
    result = score_artifact(signature, b"SQLite format 3\x00" + b"\x00" * 4096,
                            validated=True, footer_found=False, truncated=False,
                            recovered_length=4112)

    terminator = next(f for f in result.factors if "terminator" in f.name)
    assert terminator.weight > 0
    assert not any("fragment" in w.lower() for w in result.warnings)


def test_a_file_below_the_format_minimum_is_penalised(signature):
    result = score_artifact(signature, b"\xff\xd8\xff", validated=False, footer_found=False,
                            truncated=False, recovered_length=3)

    assert any("minimum" in w for w in result.warnings)
    assert result.confidence < MEDIUM_THRESHOLD


def test_hitting_the_size_ceiling_is_flagged(signature, probe):
    result = score_artifact(signature, probe, validated=True, footer_found=True,
                            truncated=False, recovered_length=signature.max_size)

    assert any("ceiling" in f.detail for f in result.factors)


def test_near_constant_content_is_heavily_penalised(signature):
    """
    A header followed by zeros is the signature of a wiped region that happens
    to contain a stale header - the most common false positive there is.
    """
    zeros = b"\xff\xd8\xff\xe0" + b"\x00" * 65532
    result = score_artifact(signature, zeros, validated=True, footer_found=True,
                            truncated=False, recovered_length=len(zeros))

    assert result.confidence < MEDIUM_THRESHOLD
    assert any("wiped or padding" in w for w in result.warnings)


def test_truncation_is_penalised_and_warned(signature, probe):
    result = score_artifact(signature, probe, validated=True, footer_found=False,
                            truncated=True, recovered_length=len(probe))

    assert any("Truncated" in w for w in result.warnings)
    assert any("completeness" in f.name for f in result.factors)


def test_high_entropy_data_scores_better_than_low_entropy_for_media_formats():
    """
    Image and video data is compressed, so high entropy is expected rather than
    suspicious. The scoring must not invert that.
    """
    signature = get_signature("jpeg")
    compressed = make_jpeg(96, 96)
    flat = b"\xff\xd8\xff\xe0" + b"\x00\x01" * 30000

    rich = score_artifact(signature, compressed, validated=True, footer_found=True,
                          truncated=False, recovered_length=len(compressed))
    poor = score_artifact(signature, flat, validated=True, footer_found=True,
                          truncated=False, recovered_length=len(flat))

    assert rich.confidence > poor.confidence


# -- reporting shapes ------------------------------------------------------

def test_explain_lists_every_factor(signature, probe):
    result = _perfect(signature, probe)
    text = result.explain()

    for factor in result.factors:
        assert factor.name in text
    assert result.label in text


def test_explain_includes_warnings(signature):
    result = score_artifact(signature, b"\x00" * 4096, validated=False,
                            footer_found=False, truncated=False, recovered_length=4096)
    assert "!" in result.explain()


def test_as_dict_is_json_serialisable(signature, probe):
    import json

    payload = json.loads(json.dumps(_perfect(signature, probe).as_dict()))
    assert payload["label"] == LABEL_HIGH
    assert payload["factors"][0]["factor"]
    assert set(payload["factors"][0]) == {"factor", "weight", "detail"}


def test_confidence_factor_as_dict_shape():
    assert ConfidenceFactor("test", 5.0, "because").as_dict() == {
        "factor": "test", "weight": 5.0, "detail": "because"
    }


# -- aggregation -----------------------------------------------------------

def test_summarize_counts_by_category_and_label():
    items = [
        Classification(category="Image", signature_id="jpeg", label=LABEL_HIGH, confidence=90.0),
        Classification(category="Image", signature_id="png", label=LABEL_MEDIUM, confidence=60.0),
        Classification(category="Document", signature_id="pdf", label=LABEL_LOW, confidence=20.0),
    ]
    summary = summarize_artifacts(items)

    assert summary["total"] == 3
    assert summary["by_category"] == {"Image": 2, "Document": 1}
    assert summary["by_confidence"] == {"High": 1, "Medium": 1, "Low": 1}
    assert summary["mean_confidence"] == pytest.approx(56.67, abs=0.01)


def test_summarize_handles_an_empty_run_without_dividing_by_zero():
    summary = summarize_artifacts([])
    assert summary["total"] == 0
    assert summary["mean_confidence"] == 0.0
    assert summary["by_confidence"] == {"High": 0, "Medium": 0, "Low": 0}
