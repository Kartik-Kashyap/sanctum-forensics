"""
Report and audit management.

Builds the deliverable that leaves the tool: a report an investigator can hand
to a reviewer, a court, or an auditor. It covers the operation performed, the
exact parameters, the evidence handled, the results, the integrity state of the
audit chain, and - importantly - the limitations of what was done.

That last section is not boilerplate. A report that quietly omits "an overwrite
is not a guaranteed purge on SSD media" or "the carver cannot prove contiguity
for reassembled fragments" is misleading precisely where it matters most, and
it is the first thing a competent reviewer will attack. Stating limits plainly
is what makes the rest of the report credible.

Formats:

``html``
    Self-contained and print-ready. "Export to PDF" is the browser's print
    dialog, which keeps the tool dependency-free.
``json``
    Full structured output for machine consumption and re-analysis.
``csv``
    Recovered-artefact inventory, for import into a case-management system.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from sanctum import __product_name__, __tagline__, __version__
from sanctum.config import AppInfo
from sanctum.core.audit import AuditChain, VerifyReport
from sanctum.core.hashing import human_bytes
from sanctum.report import templates as t

#: Statements about what the tool does *not* guarantee. Attached to every
#: report that includes the corresponding operation.
LIMITATION_OVERWRITE = (
    "Overwrite-based sanitization is effective on magnetic (HDD) media. On SSDs, "
    "NVMe devices, USB flash and SD cards, wear-levelling and block remapping mean "
    "the controller may retain previous physical pages: an overwrite is not a "
    "guaranteed purge. Use the device's firmware sanitize command (ATA SANITIZE / "
    "SECURITY ERASE UNIT, NVMe Format/Sanitize, TCG Opal crypto erase) for those."
)

LIMITATION_JOURNAL = (
    "Selective file deletion removes file content and cleanses the directory entry, "
    "but filesystem journals and table records (NTFS $UsnJrnl, $LogFile, MFT; ext3/4 "
    "journal) may retain filename and timestamp fragments beyond user-space reach."
)

LIMITATION_CARVING = (
    "Content-based carving recovers byte sequences that match known file structures. "
    "It does not recover original filenames, timestamps or directory structure - those "
    "live in filesystem metadata, which is present only when the native backend is "
    "available. Every recovered file's digest is recorded so its content can be "
    "verified independently."
)

LIMITATION_REASSEMBLY = (
    "Reassembled fragmented files are validated structurally (for JPEG, by walking the "
    "marker chain), but structural validity does not prove that the extents are in their "
    "original order. Treat reassembled artefacts as provisional and verify visually."
)

LIMITATION_CONFIDENCE = (
    "Confidence scores are heuristic and are provided to prioritise review, not to "
    "establish authenticity. Every contributing factor is listed so the weighting can "
    "be independently assessed and recomputed."
)

LIMITATION_AUDIT = (
    "The audit chain provides tamper-evidence, not tamper-proofing: it detects any "
    "modification, reordering or deletion of records, but an actor holding the HMAC key "
    "and write access to the chain file could re-forge it."
)


@dataclass
class ReportContext:
    """Everything a report needs, gathered in one place."""

    case_name: str = "Ad-hoc session"
    case_id: str = ""
    examiner: str = ""
    description: str = ""
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    environment: AppInfo = field(default_factory=AppInfo)
    operations: list[dict] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    audit_verification: VerifyReport | None = None
    audit_entry_count: int = 0
    extra_notes: list[str] = field(default_factory=list)


class ReportBuilder:
    """
    Assemble a report from recorded operations.

    Example - report on a carving run::

        builder = ReportBuilder(ReportContext(case_name="Operation Falcon"))
        builder.add_operation(carve_result.as_dict())
        builder.write("reports", formats=("html", "json"))
    """

    def __init__(self, context: ReportContext | None = None) -> None:
        self.context = context or ReportContext()

    # -- input -------------------------------------------------------------

    def add_operation(self, result: dict | object) -> None:
        """Record an operation result (anything exposing ``as_dict``)."""
        if hasattr(result, "as_dict"):
            self.context.operations.append(result.as_dict())  # type: ignore[union-attr]
        elif isinstance(result, dict):
            self.context.operations.append(result)
        else:
            raise TypeError("Expected a dict or an object with as_dict()")

    def add_evidence(self, item: dict | object) -> None:
        if hasattr(item, "as_dict"):
            self.context.evidence.append(item.as_dict())  # type: ignore[union-attr]
        elif isinstance(item, dict):
            self.context.evidence.append(item)

    def attach_audit(self, chain: AuditChain) -> VerifyReport:
        """Bind the case's audit chain and verify it as part of the report."""
        verification = chain.verify()
        self.context.audit_verification = verification
        self.context.audit_entry_count = verification.entries
        return verification

    # -- derived -----------------------------------------------------------

    def limitations(self) -> list[str]:
        """
        The limitations that apply to the operations actually recorded.

        Public because the UI shows them *before* the report is written - an
        operator should never be surprised by what their own report says about
        the work they just did.
        """
        return self._limitations()

    def _limitations(self) -> list[str]:
        """Only the limitations that apply to the operations actually performed."""
        kinds = {op.get("operation") for op in self.context.operations}
        notes: list[str] = []
        if "drive_erase" in kinds:
            notes.append(LIMITATION_OVERWRITE)
        if "file_erase" in kinds or "free_space_wipe" in kinds:
            notes.append(LIMITATION_JOURNAL)
        if "file_carving" in kinds:
            notes.append(LIMITATION_CARVING)
        if any(op.get("reassembled") for op in self.context.operations):
            notes.append(LIMITATION_REASSEMBLY)
            notes.append(LIMITATION_CONFIDENCE)
        elif "file_carving" in kinds:
            notes.append(LIMITATION_CONFIDENCE)
        notes.append(LIMITATION_AUDIT)
        return notes

    def _all_artifacts(self) -> list[dict]:
        collected: list[dict] = []
        for op in self.context.operations:
            for artifact in op.get("artifacts", []) or []:
                collected.append(artifact)
        return collected

    def _totals(self) -> dict:
        return {
            "operations": len(self.context.operations),
            "artifacts": len(self._all_artifacts()),
            "bytes_recovered": sum(a.get("length", 0) for a in self._all_artifacts()),
            "evidence_items": len(self.context.evidence),
        }

    # -- HTML --------------------------------------------------------------

    def to_html(self) -> str:
        c = self.context
        parts: list[str] = []

        # Summary
        totals = self._totals()
        parts.append(
            t.meta_grid(
                {
                    "Case": c.case_name,
                    "Case ID": c.case_id or "n/a",
                    "Examiner": c.examiner or "not recorded",
                    "Generated": c.generated_at,
                    "Operations": totals["operations"],
                    "Artefacts recovered": totals["artifacts"],
                    "Data recovered": human_bytes(totals["bytes_recovered"]),
                    "Evidence items": totals["evidence_items"],
                }
            )
        )

        if c.description:
            parts.append(t.callout("Case description", t.html_escape(c.description)))

        # Integrity - the first thing a reviewer looks for
        parts.append("<h2>Integrity verification</h2>")
        verification = c.audit_verification
        if verification is None:
            parts.append(
                t.callout(
                    "Audit chain not attached",
                    "No audit chain was bound to this report, so integrity could not be "
                    "verified. Treat the contents as unverified.",
                    "warn",
                )
            )
        elif verification.ok:
            parts.append(
                t.callout(
                    "Audit chain intact",
                    f"All {verification.entries} audit record(s) verified: every entry's "
                    "digest and back-link are consistent and the HMAC is valid. No "
                    "modification, reordering or deletion of records was detected.",
                    "ok",
                )
            )
        else:
            parts.append(
                t.callout(
                    "Audit chain BROKEN",
                    f"Integrity verification failed at record {verification.broken_at}: "
                    f"{t.html_escape(verification.reason)}. The audit log has been altered "
                    "and the results below cannot be relied upon.",
                    "bad",
                )
            )
        parts.append(
            f'<p class="sub">{t.html_escape(LIMITATION_AUDIT)}</p>'
        )

        # Environment
        parts.append("<h2>Examination environment</h2>")
        parts.append(
            t.meta_grid(
                {
                    "Platform": c.environment.platform,
                    "Machine": c.environment.machine,
                    "Python": c.environment.python,
                    "SANCTUM version": __version__,
                }
            )
        )

        # Evidence register
        if c.evidence:
            parts.append("<h2>Evidence register</h2>")
            rows = [
                [
                    t.html_escape(item.get("path", "")),
                    t.html_escape(item.get("description", "")),
                    f'{item.get("size_bytes", 0):,}',
                    f'<span class="hash">{t.html_escape(item.get("sha256", ""))}</span>',
                    t.html_escape(item.get("registered_at", "")),
                ]
                for item in c.evidence
            ]
            parts.append(
                t.table(
                    ["Path", "Description", "Bytes", "SHA-256", "Registered"],
                    rows,
                    numeric_columns={2},
                )
            )

        # Operations
        parts.append("<h2>Operations performed</h2>")
        if not c.operations:
            parts.append("<p>No operations were recorded in this report.</p>")
        for index, op in enumerate(c.operations, start=1):
            parts.append(self._render_operation(index, op))

        # Artefact inventory
        artifacts = self._all_artifacts()
        if artifacts:
            parts.append("<h2>Recovered artefact inventory</h2>")
            parts.append(self._render_artifacts_table(artifacts))

        # Limitations
        parts.append("<h2>Limitations and caveats</h2>")
        items = "".join(f"<li>{t.html_escape(note)}</li>" for note in self._limitations())
        parts.append(f'<ul class="limits">{items}</ul>')

        if c.extra_notes:
            parts.append("<h2>Examiner notes</h2>")
            parts.extend(f"<p>{t.html_escape(note)}</p>" for note in c.extra_notes)

        body = "\n".join(parts)
        footer = (
            f"{__product_name__} v{__version__} &middot; {t.html_escape(__tagline__)} "
            f"&middot; Case {t.html_escape(c.case_id or 'n/a')}"
        )
        return t.document(
            f"{__product_name__} Forensic Report",
            body,
            subtitle=f"{c.case_name} · generated {c.generated_at}",
            footer=footer,
        )

    def _render_operation(self, index: int, op: dict) -> str:
        kind = op.get("operation", "unknown")
        titles = {
            "drive_erase": "Secure drive erasure",
            "file_erase": "Secure file/folder deletion",
            "free_space_wipe": "Free-space sanitization",
            "file_carving": "File carving and recovery",
        }
        title = titles.get(kind, kind.replace("_", " ").title())
        out = [f"<h3>{index}. {t.html_escape(title)}</h3>"]

        if kind == "drive_erase":
            success = op.get("success")
            tone = "ok" if success and op.get("verified") is not False else "bad" if not success else "warn"
            out.append(f'<p>{t.pill(op.get("headline", ""), tone)}</p>')
            out.append(
                t.meta_grid(
                    {
                        "Target": op.get("target", {}).get("path", ""),
                        "Media type": op.get("target", {}).get("media_type", ""),
                        "Size": human_bytes(op.get("bytes_total", 0)),
                        "Standard": op.get("standard", {}).get("name", ""),
                        "Passes executed": op.get("passes", []) and len(op["passes"]) or 0,
                        "Verified": "yes" if op.get("verified") else ("no" if op.get("verified") is False else "not requested"),
                        "Elapsed": f'{op.get("elapsed_seconds", 0):.1f}s',
                        "Throughput": f'{op.get("throughput_mbps", 0):.1f} MB/s',
                    }
                )
            )
            compliance = op.get("standard", {}).get("compliance") or []
            if compliance:
                out.append(
                    "<p><strong>Standards addressed:</strong> "
                    + t.html_escape("; ".join(compliance))
                    + "</p>"
                )
            rows = [
                [
                    str(p.get("pass", "")),
                    t.html_escape(p.get("pattern", "")),
                    f'{p.get("bytes_written", 0):,}',
                    f'{p.get("duration_seconds", 0):.2f}s',
                    self._verified_cell(p.get("verified")),
                ]
                for p in op.get("passes", [])
            ]
            if rows:
                out.append(
                    t.table(
                        ["Pass", "Pattern", "Bytes written", "Duration", "Verification"],
                        rows,
                        numeric_columns={2, 3},
                    )
                )
            for warning in op.get("warnings", []) or []:
                out.append(t.callout("Warning", t.html_escape(warning), "warn"))

        elif kind == "file_erase":
            out.append(
                t.meta_grid(
                    {
                        "Paths processed": op.get("total", 0),
                        "Succeeded": op.get("succeeded", 0),
                        "Failed": op.get("failed", 0),
                        "Bytes overwritten": human_bytes(op.get("total_bytes_overwritten", 0)),
                    }
                )
            )
            rows = [
                [
                    t.html_escape(r.get("path", "")),
                    t.html_escape(r.get("headline", "")),
                    f'{r.get("size_bytes", 0):,}',
                    str(r.get("passes_executed", "")),
                    self._verified_cell(r.get("verified")),
                ]
                for r in op.get("results", [])
            ]
            if rows:
                out.append(
                    t.table(
                        ["Path", "Outcome", "Bytes", "Passes", "Removed"],
                        rows,
                        numeric_columns={2, 3},
                    )
                )

        elif kind == "file_carving":
            out.append(f'<p>{t.pill(op.get("headline", "Carving complete"), "info")}</p>')
            summary = op.get("summary", {})
            out.append(
                t.meta_grid(
                    {
                        "Source": op.get("source", ""),
                        "Source size": human_bytes(op.get("source_size", 0)),
                        "Bytes scanned": human_bytes(op.get("bytes_scanned", 0)),
                        "Regions scanned": op.get("regions_scanned", 0),
                        "Signatures used": op.get("signatures_used", 0),
                        "Artefacts found": op.get("recovered_count", 0),
                        "High confidence": op.get("high_confidence", 0),
                        "Mean confidence": f'{summary.get("mean_confidence", 0):.1f}/100',
                        "Elapsed": f'{op.get("elapsed_seconds", 0):.1f}s',
                    }
                )
            )
            by_category = op.get("by_category") or {}
            if by_category:
                rows = [[t.html_escape(k), str(v)] for k, v in by_category.items()]
                out.append(t.table(["Category", "Count"], rows, numeric_columns={1}))
            for warning in op.get("warnings", []) or []:
                out.append(t.callout("Note", t.html_escape(warning), "warn"))

        else:
            out.append(f"<pre class='mono'>{t.html_escape(json.dumps(op, indent=2)[:4000])}</pre>")

        return "\n".join(out)

    @staticmethod
    def _verified_cell(value) -> str:
        if value is True:
            return t.pill("verified", "ok")
        if value is False:
            return t.pill("FAILED", "bad")
        return t.pill("not requested", "info")

    def _render_artifacts_table(self, artifacts: list[dict]) -> str:
        rows = []
        for artifact in sorted(artifacts, key=lambda a: -a.get("confidence", 0)):
            tone = {"High": "ok", "Medium": "warn", "Low": "bad"}.get(
                artifact.get("confidence_label", ""), "info"
            )
            rows.append(
                [
                    t.html_escape(artifact.get("name", "")),
                    t.html_escape(artifact.get("category", "")),
                    f'0x{artifact.get("offset", 0):X}',
                    f'{artifact.get("length", 0):,}',
                    t.pill(f'{artifact.get("confidence", 0):.0f} {artifact.get("confidence_label", "")}', tone),
                    f'<span class="hash">{t.html_escape(artifact.get("sha256", ""))}</span>',
                ]
            )
        return t.table(
            ["File", "Category", "Offset", "Bytes", "Confidence", "SHA-256"],
            rows,
            numeric_columns={3},
        )

    # -- JSON / CSV --------------------------------------------------------

    def to_json(self) -> str:
        payload = {
            "product": __product_name__,
            "version": __version__,
            "generated_at": self.context.generated_at,
            "case": {
                "id": self.context.case_id,
                "name": self.context.case_name,
                "examiner": self.context.examiner,
                "description": self.context.description,
            },
            "environment": self.context.environment.as_dict(),
            "evidence": self.context.evidence,
            "operations": self.context.operations,
            "limitations": self._limitations(),
            "audit": {
                "entries": self.context.audit_entry_count,
                "verified": (
                    self.context.audit_verification.ok
                    if self.context.audit_verification
                    else None
                ),
                "broken_at": (
                    self.context.audit_verification.broken_at
                    if self.context.audit_verification
                    else None
                ),
                "reason": (
                    self.context.audit_verification.reason
                    if self.context.audit_verification
                    else ""
                ),
            },
        }
        return json.dumps(payload, indent=2, default=str)

    def to_csv(self) -> str:
        """Recovered-artefact inventory as CSV."""
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                "name", "category", "signature", "offset", "end_offset", "length",
                "confidence", "confidence_label", "sha256", "md5", "validated",
                "footer_found", "truncated", "output_path",
            ]
        )
        for artifact in self._all_artifacts():
            writer.writerow(
                [
                    artifact.get("name", ""),
                    artifact.get("category", ""),
                    artifact.get("signature_id", ""),
                    artifact.get("offset", ""),
                    artifact.get("end_offset", ""),
                    artifact.get("length", ""),
                    artifact.get("confidence", ""),
                    artifact.get("confidence_label", ""),
                    artifact.get("sha256", ""),
                    artifact.get("md5", ""),
                    artifact.get("validated", ""),
                    artifact.get("footer_found", ""),
                    artifact.get("truncated", ""),
                    artifact.get("output_path", ""),
                ]
            )
        return buffer.getvalue()

    # -- output ------------------------------------------------------------

    def write(
        self,
        destination: str | Path,
        *,
        stem: str = "sanctum_report",
        formats: tuple[str, ...] = ("html", "json"),
    ) -> dict[str, Path]:
        """Write the report in each requested format; returns the paths written."""
        directory = Path(destination)
        directory.mkdir(parents=True, exist_ok=True)
        written: dict[str, Path] = {}

        if "html" in formats:
            path = directory / f"{stem}.html"
            path.write_text(self.to_html(), encoding="utf-8")
            written["html"] = path
        if "json" in formats:
            path = directory / f"{stem}.json"
            path.write_text(self.to_json(), encoding="utf-8")
            written["json"] = path
        if "csv" in formats:
            path = directory / f"{stem}_artifacts.csv"
            path.write_text(self.to_csv(), encoding="utf-8")
            written["csv"] = path

        return written
