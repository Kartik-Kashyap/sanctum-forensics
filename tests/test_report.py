"""
Report and audit-management tests.

The report is the artefact that leaves the tool, so the properties that matter
are: it says what was actually done, it states the limits of what was done, it
never presents an unverified or broken audit chain as sound, and it cannot be
made to emit operator-supplied text as markup.
"""

from __future__ import annotations

import json

import pytest

from sanctum.core.audit import AuditCategory, AuditChain
from sanctum.report.builder import (
    LIMITATION_AUDIT,
    LIMITATION_CARVING,
    LIMITATION_CONFIDENCE,
    LIMITATION_JOURNAL,
    LIMITATION_OVERWRITE,
    ReportBuilder,
    ReportContext,
)


DRIVE_OP = {
    "operation": "drive_erase",
    "headline": "Completed and verified",
    "success": True,
    "verified": True,
    "bytes_total": 1024 * 1024,
    "elapsed_seconds": 1.5,
    "throughput_mbps": 0.7,
    "target": {"path": "evidence/scratch.img", "media_type": "Image"},
    "standard": {"id": "dod3", "name": "DoD 5220.22-M (3-pass)",
                 "compliance": ["DoD 5220.22-M"]},
    "passes": [
        {"pass": 1, "pattern": "0x00", "bytes_written": 1024 * 1024,
         "duration_seconds": 0.5, "verified": True},
    ],
    "warnings": [],
}

CARVE_OP = {
    "operation": "file_carving",
    "source": "evidence/deleted_files.img",
    "source_size": 16 * 1024 * 1024,
    "bytes_scanned": 16 * 1024 * 1024,
    "regions_scanned": 1,
    "signatures_used": 35,
    "recovered_count": 2,
    "recovered_bytes": 4096,
    "high_confidence": 1,
    "elapsed_seconds": 2.0,
    "by_category": {"Image": 2},
    "summary": {"mean_confidence": 88.5},
    "artifacts": [
        {"name": "carved_0001.jpg", "category": "Image", "signature_id": "jpeg",
         "offset": 4096, "end_offset": 8192, "length": 4096, "confidence": 92.0,
         "confidence_label": "High", "sha256": "a" * 64, "md5": "b" * 32,
         "validated": True, "footer_found": True, "truncated": False,
         "output_path": "out/carved_0001.jpg"},
        {"name": "carved_0002.png", "category": "Image", "signature_id": "png",
         "offset": 16384, "end_offset": 18432, "length": 2048, "confidence": 40.0,
         "confidence_label": "Low", "sha256": "c" * 64, "md5": "d" * 32,
         "validated": False, "footer_found": False, "truncated": True,
         "output_path": "out/carved_0002.png"},
    ],
    "warnings": [],
}


@pytest.fixture
def chain(tmp_path):
    return AuditChain(tmp_path / "audit.jsonl")


# -- operation intake ------------------------------------------------------

def test_add_operation_accepts_a_dict():
    builder = ReportBuilder()
    builder.add_operation(DRIVE_OP)
    assert builder.context.operations == [DRIVE_OP]


def test_add_operation_accepts_anything_with_as_dict():
    class Result:
        def as_dict(self):
            return {"operation": "drive_erase"}

    builder = ReportBuilder()
    builder.add_operation(Result())
    assert builder.context.operations[0]["operation"] == "drive_erase"


def test_add_operation_rejects_an_unusable_object():
    with pytest.raises(TypeError):
        ReportBuilder().add_operation(object())


def test_add_evidence_accepts_a_dict_and_is_optional():
    builder = ReportBuilder()
    builder.add_evidence({"path": "evidence/usb.img", "sha256": "e" * 64})
    assert len(builder.context.evidence) == 1


# -- conditional limitations ----------------------------------------------

def test_a_drive_erasure_report_carries_the_overwrite_limitation():
    builder = ReportBuilder()
    builder.add_operation(DRIVE_OP)
    assert LIMITATION_OVERWRITE in builder.limitations()


def test_a_carving_report_carries_the_carving_and_confidence_limitations():
    builder = ReportBuilder()
    builder.add_operation(CARVE_OP)
    limits = builder.limitations()
    assert LIMITATION_CARVING in limits
    assert LIMITATION_CONFIDENCE in limits
    assert LIMITATION_OVERWRITE not in limits


def test_a_file_deletion_report_carries_the_journal_limitation():
    builder = ReportBuilder()
    builder.add_operation({"operation": "file_erase", "results": []})
    assert LIMITATION_JOURNAL in builder.limitations()


def test_the_audit_limitation_is_always_stated():
    """
    Even a report with no operations must state that tamper-evidence is not
    tamper-proofing.
    """
    assert LIMITATION_AUDIT in ReportBuilder().limitations()


def test_limitations_are_specific_to_what_was_actually_done():
    """
    A report should not pad itself with caveats about work it never performed -
    that dilutes the ones that matter.
    """
    builder = ReportBuilder()
    builder.add_operation(CARVE_OP)
    limits = builder.limitations()
    assert LIMITATION_OVERWRITE not in limits
    assert LIMITATION_JOURNAL not in limits


def test_reassembly_limitation_appears_only_when_reassembly_was_used():
    plain = ReportBuilder()
    plain.add_operation(CARVE_OP)
    assert not any("extents are in their" in note for note in plain.limitations())

    reassembled = ReportBuilder()
    reassembled.add_operation({**CARVE_OP, "reassembled": True})
    assert any("extents are in their" in note for note in reassembled.limitations())


# -- HTML ------------------------------------------------------------------

def test_html_contains_the_expected_sections():
    builder = ReportBuilder(ReportContext(case_name="Operation Falcon", examiner="A. Examiner"))
    builder.add_operation(DRIVE_OP)
    builder.add_operation(CARVE_OP)
    html = builder.to_html()

    for section in ("Integrity verification", "Examination environment",
                    "Operations performed", "Recovered artefact inventory",
                    "Limitations and caveats"):
        assert section in html, section
    assert "Operation Falcon" in html
    assert "A. Examiner" in html


def test_html_does_not_claim_integrity_when_no_chain_was_attached():
    """The single most important honesty check in the report."""
    builder = ReportBuilder()
    builder.add_operation(DRIVE_OP)
    html = builder.to_html()

    assert "Audit chain not attached" in html
    assert "unverified" in html.lower()
    assert "Audit chain intact" not in html


def test_html_reports_an_intact_chain(tmp_path, chain):
    chain.log(AuditCategory.ERASE, "drive_erase_started")
    chain.log(AuditCategory.ERASE, "drive_erase_finished")

    builder = ReportBuilder()
    builder.add_operation(DRIVE_OP)
    verification = builder.attach_audit(chain)

    assert verification.ok
    assert "Audit chain intact" in builder.to_html()


def test_html_reports_a_broken_chain_and_names_where(tmp_path, chain):
    """
    A tampered log must not produce a report that looks normal. The report has
    to say the results cannot be relied upon, and say where integrity failed.
    """
    import json as json_module

    for index in range(4):
        chain.log(AuditCategory.ERASE, f"action_{index}")

    lines = [json_module.loads(line) for line in
             chain.path.read_text(encoding="utf-8").splitlines() if line.strip()]
    lines[2]["action"] = "tampered"
    chain.path.write_text(
        "\n".join(json_module.dumps(line, sort_keys=True) for line in lines) + "\n",
        encoding="utf-8",
    )

    builder = ReportBuilder()
    builder.add_operation(DRIVE_OP)
    verification = builder.attach_audit(chain)

    assert not verification.ok
    html = builder.to_html()
    assert "Audit chain BROKEN" in html
    assert "cannot be relied upon" in html
    assert str(verification.broken_at) in html


def test_operator_supplied_text_cannot_inject_markup():
    """
    Case names, examiner names and file paths come from the operator and from
    the media being examined. An examiner opening a report about a suspect's
    drive should not be running the suspect's script.
    """
    payload = '<script>alert("xss")</script>'
    builder = ReportBuilder(
        ReportContext(case_name=payload, examiner=payload, description=payload)
    )
    builder.add_operation({
        "operation": "file_erase",
        "results": [{"path": payload, "headline": payload, "size_bytes": 1}],
    })
    builder.context.extra_notes.append(payload)

    html = builder.to_html()

    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_html_shows_the_pass_table_for_a_drive_erasure():
    builder = ReportBuilder()
    builder.add_operation(DRIVE_OP)
    html = builder.to_html()

    assert "Bytes written" in html
    assert "0x00" in html


def test_html_shows_the_artefact_inventory_sorted_by_confidence():
    builder = ReportBuilder()
    builder.add_operation(CARVE_OP)
    html = builder.to_html()

    assert "carved_0001.jpg" in html
    assert html.index("carved_0001.jpg") < html.index("carved_0002.png")


def test_html_marks_a_failed_verification_as_failed():
    builder = ReportBuilder()
    builder.add_operation({
        **DRIVE_OP,
        "success": False,
        "verified": False,
        "headline": "Completed with VERIFICATION FAILURES",
    })
    html = builder.to_html()

    assert "VERIFICATION FAILURES" in html


def test_html_with_no_operations_still_renders():
    html = ReportBuilder().to_html()
    assert "No operations were recorded" in html


# -- JSON ------------------------------------------------------------------

def test_json_round_trips_and_includes_the_audit_block(tmp_path, chain):
    chain.log(AuditCategory.ERASE, "one")

    builder = ReportBuilder(ReportContext(case_name="Case", case_id="CASE-1"))
    builder.add_operation(CARVE_OP)
    builder.attach_audit(chain)

    payload = json.loads(builder.to_json())

    assert payload["case"]["id"] == "CASE-1"
    assert payload["audit"]["verified"] is True
    assert payload["audit"]["entries"] == 1
    assert payload["audit"]["broken_at"] is None
    assert payload["operations"][0]["operation"] == "file_carving"
    assert LIMITATION_CARVING in payload["limitations"]


def test_json_reports_an_unverified_chain_as_null_not_true():
    payload = json.loads(ReportBuilder().to_json())
    assert payload["audit"]["verified"] is None


def test_json_states_a_broken_chain_with_its_reason(tmp_path, chain):
    import json as json_module

    chain.log(AuditCategory.ERASE, "one")
    lines = [json_module.loads(line) for line in
             chain.path.read_text(encoding="utf-8").splitlines() if line.strip()]
    lines[0]["action"] = "tampered"
    chain.path.write_text(
        "\n".join(json_module.dumps(line, sort_keys=True) for line in lines) + "\n",
        encoding="utf-8",
    )

    builder = ReportBuilder()
    builder.attach_audit(chain)
    payload = json.loads(builder.to_json())

    assert payload["audit"]["verified"] is False
    assert payload["audit"]["broken_at"] == 1
    assert payload["audit"]["reason"]


# -- CSV -------------------------------------------------------------------

def test_csv_lists_every_recovered_artefact():
    import csv as csv_module
    import io

    builder = ReportBuilder()
    builder.add_operation(CARVE_OP)
    rows = list(csv_module.DictReader(io.StringIO(builder.to_csv())))

    assert len(rows) == 2
    assert rows[0]["name"] == "carved_0001.jpg"
    assert rows[0]["sha256"] == "a" * 64
    assert rows[0]["confidence_label"] == "High"


def test_csv_has_a_header_even_with_nothing_recovered():
    import csv as csv_module
    import io

    rows = list(csv_module.DictReader(io.StringIO(ReportBuilder().to_csv())))
    assert rows == []


# -- writing ---------------------------------------------------------------

def test_write_produces_each_requested_format(tmp_path):
    builder = ReportBuilder(ReportContext(case_name="Case"))
    builder.add_operation(CARVE_OP)

    written = builder.write(tmp_path / "reports", stem="falcon",
                            formats=("html", "json", "csv"))

    assert set(written) == {"html", "json", "csv"}
    assert written["html"].name == "falcon.html"
    assert written["json"].name == "falcon.json"
    assert written["csv"].name == "falcon_artifacts.csv"
    for path in written.values():
        assert path.exists() and path.stat().st_size > 0


def test_write_defaults_to_html_and_json(tmp_path):
    written = ReportBuilder().write(tmp_path / "reports")
    assert set(written) == {"html", "json"}


def test_write_creates_the_destination_directory(tmp_path):
    destination = tmp_path / "deep" / "nested" / "reports"
    ReportBuilder().write(destination)
    assert destination.is_dir()
