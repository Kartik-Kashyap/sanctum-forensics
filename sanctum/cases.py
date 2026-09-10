"""
Case management.

A forensic tool's output has to be defensible months later, by someone who was
not present when the work was done. That requires every operation to land
inside a named case with its own audit chain, its own evidence register and its
own report directory - so "what did we do, to what, and when" has an answer
that does not depend on anyone's memory.

The layout::

    <cases dir>/<case-id>/
        case.json        case metadata and evidence register
        audit.jsonl      the tamper-evident chain for this case
        artifacts/       files recovered by the carver
        reports/         generated reports
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from sanctum.config import CASES_DIR, ensure_layout
from sanctum.core import hashing
from sanctum.core.audit import AuditCategory, AuditChain, AuditOutcome

_ID_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _slugify(value: str, limit: int = 40) -> str:
    cleaned = _ID_SAFE.sub("-", value.strip()).strip("-")
    return (cleaned[:limit] or "case").lower()


@dataclass
class EvidenceItem:
    """One item registered into a case."""

    path: str
    description: str = ""
    size_bytes: int = 0
    sha256: str = ""
    md5: str = ""
    registered_at: str = field(default_factory=_now)
    source: str = ""
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Case:
    """A unit of investigative work."""

    case_id: str
    name: str
    examiner: str = ""
    description: str = ""
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    root: str = ""
    evidence: list[EvidenceItem] = field(default_factory=list)
    operations: list[dict] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    notes: str = ""

    # -- derived paths -----------------------------------------------------

    @property
    def path(self) -> Path:
        return Path(self.root)

    @property
    def audit_path(self) -> Path:
        return self.path / "audit.jsonl"

    @property
    def artifacts_dir(self) -> Path:
        return self.path / "artifacts"

    @property
    def reports_dir(self) -> Path:
        return self.path / "reports"

    @property
    def meta_path(self) -> Path:
        return self.path / "case.json"

    # -- behaviour ---------------------------------------------------------

    def ensure_layout(self) -> None:
        for directory in (self.path, self.artifacts_dir, self.reports_dir):
            directory.mkdir(parents=True, exist_ok=True)

    def audit(self, actor: str | None = None) -> AuditChain:
        """The case's audit chain, created on first use."""
        self.ensure_layout()
        return AuditChain(self.audit_path, actor=actor or self.examiner or "operator")

    def register_evidence(
        self,
        path: str | Path,
        description: str = "",
        *,
        compute_hash: bool = True,
        source: str = "",
    ) -> EvidenceItem:
        """
        Register an evidence item, hashing it at intake.

        Hashing on registration is what makes the chain-of-custody claim
        meaningful: the digest recorded here is the one a later report can be
        checked against to show the item was not altered in the interim.
        """
        target = Path(path)
        digests: dict[str, str] = {}
        size = 0
        if target.exists() and target.is_file():
            size = target.stat().st_size
            if compute_hash:
                try:
                    digests = hashing.hash_file(target)
                except OSError:
                    digests = {}

        item = EvidenceItem(
            path=str(target),
            description=description,
            size_bytes=size,
            sha256=digests.get("sha256", ""),
            md5=digests.get("md5", ""),
            source=source,
        )
        self.evidence.append(item)
        self.touch()
        return item

    def record_operation(self, kind: str, summary: str, details: dict | None = None) -> dict:
        """Attach an operation summary to the case record."""
        entry = {
            "kind": kind,
            "summary": summary,
            "at": _now(),
            "details": details or {},
        }
        self.operations.append(entry)
        self.touch()
        return entry

    def touch(self) -> None:
        self.updated_at = _now()

    def save(self) -> Path:
        self.ensure_layout()
        self.touch()
        payload = asdict(self)
        self.meta_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return self.meta_path

    @classmethod
    def load(cls, path: str | Path) -> "Case":
        """Load a case from its directory or its case.json."""
        target = Path(path)
        meta = target / "case.json" if target.is_dir() else target
        payload = json.loads(meta.read_text(encoding="utf-8"))
        evidence = [EvidenceItem(**item) for item in payload.pop("evidence", [])]
        case = cls(**payload)
        case.evidence = evidence
        case.root = str(meta.parent)
        return case

    def summary(self) -> dict:
        return {
            "case_id": self.case_id,
            "name": self.name,
            "examiner": self.examiner,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "evidence_count": len(self.evidence),
            "operation_count": len(self.operations),
            "root": self.root,
        }


class CaseManager:
    """Create, list and open cases under the configured cases directory."""

    def __init__(self, base_dir: str | Path | None = None) -> None:
        ensure_layout()
        self.base_dir = Path(base_dir) if base_dir else CASES_DIR
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def list_cases(self) -> list[dict]:
        """Summarise every case on disk, newest first."""
        summaries: list[dict] = []
        for meta in self.base_dir.glob("*/case.json"):
            try:
                summaries.append(Case.load(meta).summary())
            except (OSError, json.JSONDecodeError, TypeError):
                continue
        return sorted(summaries, key=lambda s: s.get("updated_at", ""), reverse=True)

    def create(
        self,
        name: str,
        examiner: str = "",
        description: str = "",
        tags: list[str] | None = None,
    ) -> Case:
        """Create a new case directory with an initialised audit chain."""
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        short = uuid.uuid4().hex[:6]
        case_id = f"{stamp}-{_slugify(name, 24)}-{short}"
        case = Case(
            case_id=case_id,
            name=name,
            examiner=examiner,
            description=description,
            tags=tags or [],
            root=str(self.base_dir / case_id),
        )
        case.ensure_layout()
        chain = case.audit()
        chain.log(
            AuditCategory.CASE,
            "case_created",
            outcome=AuditOutcome.SUCCESS,
            target=case_id,
            details={"name": name, "examiner": examiner, "description": description},
        )
        case.save()
        return case

    def open(self, case_id: str) -> Case:
        """Open an existing case by id or by path."""
        candidate = Path(case_id)
        if candidate.is_dir() and (candidate / "case.json").exists():
            return Case.load(candidate)
        target = self.base_dir / case_id
        if not (target / "case.json").exists():
            raise FileNotFoundError(f"No such case: {case_id}")
        return Case.load(target)

    def delete(self, case_id: str) -> None:
        """
        Remove a case directory.

        Deliberately shallow and explicit: no recursive wildcards, and the id
        must resolve to a directory directly under the cases root.
        """
        import shutil

        target = (self.base_dir / case_id).resolve()
        if target.parent != self.base_dir.resolve():
            raise ValueError("Refusing to delete outside the cases directory")
        if not target.is_dir():
            raise FileNotFoundError(f"No such case: {case_id}")
        shutil.rmtree(target)
