"""
Tamper-evident audit chain.

The problem statement asks for "audit logging, tamper-resistant reporting".
A plain log file satisfies neither: anyone who can write to it can also edit
history, and a report that merely *quotes* a mutable log proves nothing.

SANCTUM therefore stores audit records in a hash chain. Each entry commits to
the digest of its predecessor, and carries an HMAC over its own canonical
payload. Editing, reordering, deleting or injecting any record breaks the chain
at a verifiable point. :func:`AuditChain.verify` walks the whole file and
reports the exact sequence number where integrity first fails.

The guarantee is tamper-*evidence*, not tamper-*proof*: an attacker with the
HMAC key and full file access could re-forge the chain. That is the correct
and honest claim to make, and it is what the compliance world expects - the
point is that silent modification is impossible.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

from sanctum.config import AUDIT_HMAC_KEY

#: Genesis link - the prev_hash of the first entry in any chain.
GENESIS_HASH = "0" * 64


class AuditCategory(str, Enum):
    """Coarse grouping, used for filtering in the audit viewer."""

    SYSTEM = "SYSTEM"
    CASE = "CASE"
    SAFETY = "SAFETY"
    ERASE = "ERASE"
    RECOVER = "RECOVER"
    REPORT = "REPORT"
    INTEGRITY = "INTEGRITY"


class AuditOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"
    INFO = "INFO"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class AuditEntry:
    """One immutable record in the chain."""

    seq: int
    timestamp: str
    category: str
    action: str
    outcome: str
    actor: str = "operator"
    target: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = GENESIS_HASH
    entry_hash: str = ""
    hmac: str = ""

    def payload(self) -> dict[str, Any]:
        """
        The portion of the entry covered by the digests.

        ``entry_hash`` and ``hmac`` are excluded - they are derived from this
        payload, so including them would be circular.
        """
        data = asdict(self)
        data.pop("entry_hash", None)
        data.pop("hmac", None)
        return data

    def canonical(self) -> bytes:
        """Deterministic serialisation - key order and separators are pinned."""
        return json.dumps(
            self.payload(), sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8")

    def compute_hash(self) -> str:
        """SHA-256 over the previous link concatenated with this entry's payload."""
        digest = hashlib.sha256()
        digest.update(self.prev_hash.encode("utf-8"))
        digest.update(self.canonical())
        return digest.hexdigest()

    def compute_hmac(self) -> str:
        """HMAC-SHA-256 keyed by the installation's audit secret."""
        return hmac.new(AUDIT_HMAC_KEY, self.entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()

    def seal(self) -> "AuditEntry":
        """Finalise the derived fields. Mutates and returns self for chaining."""
        self.entry_hash = self.compute_hash()
        self.hmac = self.compute_hmac()
        return self

    def is_sealed_correctly(self) -> bool:
        return (
            self.entry_hash == self.compute_hash()
            and hmac.compare_digest(self.hmac, self.compute_hmac())
        )

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, default=str)


@dataclass
class VerifyReport:
    """Outcome of :meth:`AuditChain.verify`."""

    ok: bool
    entries: int
    broken_at: int | None = None
    reason: str = ""

    def summary(self) -> str:
        if self.ok:
            return f"Audit chain intact across {self.entries} entries."
        return f"Audit chain BROKEN at entry {self.broken_at}: {self.reason}"


class AuditChain:
    """
    Append-only, hash-chained audit log persisted as JSON Lines.

    Thread-safe: the GUI runs erasure and recovery on worker threads that all
    write here, and a torn write would corrupt the chain.
    """

    def __init__(self, path: str | Path, actor: str = "operator") -> None:
        self.path = Path(path)
        self.actor = actor
        self._lock = threading.RLock()
        self._seq = 0
        self._last_hash = GENESIS_HASH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._resume()

    # -- chain state -------------------------------------------------------

    def _resume(self) -> None:
        """Continue an existing chain rather than starting a second one."""
        if not self.path.exists():
            return
        last: AuditEntry | None = None
        count = 0
        for entry in self._read_entries():
            last = entry
            count += 1
        if last is not None:
            self._seq = last.seq
            self._last_hash = last.entry_hash

    def _read_entries(self) -> Iterator[AuditEntry]:
        # A chain that has not been written to yet has no file. Yielding nothing
        # is the honest answer, and it is what ``verify`` already reports, so
        # ``len(audit)``, ``entries()`` and ``verify()`` agree on a fresh case
        # instead of two of the three raising FileNotFoundError at the operator.
        if not self.path.exists():
            return
        with open(self.path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield AuditEntry(**json.loads(line))
                except (json.JSONDecodeError, TypeError):
                    # A malformed line is itself evidence of tampering; the
                    # verifier reports it. Skipping here keeps the tool usable.
                    continue

    # -- writing -----------------------------------------------------------

    def log(
        self,
        category: AuditCategory | str,
        action: str,
        *,
        outcome: AuditOutcome | str = AuditOutcome.INFO,
        target: str = "",
        details: dict[str, Any] | None = None,
        actor: str | None = None,
    ) -> AuditEntry:
        """Append a sealed entry and return it."""
        with self._lock:
            entry = AuditEntry(
                seq=self._seq + 1,
                timestamp=_utc_now(),
                category=str(getattr(category, "value", category)),
                action=action,
                outcome=str(getattr(outcome, "value", outcome)),
                actor=actor or self.actor,
                target=str(target),
                details=details or {},
                prev_hash=self._last_hash,
            ).seal()

            # newline="\n" is not cosmetic. Without it Python translates the
            # terminator to the platform convention on write, so the same chain
            # has different bytes on Windows and on Linux - and an exported copy
            # then differs from the original on the machine that produced it,
            # which is exactly the comparison an evidence bundle is checked
            # with. The chain's bytes must depend on its content alone.
            with open(self.path, "a", encoding="utf-8", newline="\n") as handle:
                handle.write(entry.to_json() + "\n")
                handle.flush()
                os.fsync(handle.fileno())  # survive a crash mid-investigation

            self._seq = entry.seq
            self._last_hash = entry.entry_hash
            return entry

    # -- reading -----------------------------------------------------------

    def entries(self) -> list[AuditEntry]:
        with self._lock:
            return list(self._read_entries())

    def __bool__(self) -> bool:
        """
        Always true. A chain is a valid audit sink whether or not it is empty.

        Without this, ``__len__`` below makes a freshly created chain falsy, and
        every ``if not self.audit: return`` guard in the engines then skips
        logging on exactly the chain that has recorded nothing yet - silently
        dropping the first entry of a new case, the refusal that blocked a
        dangerous operation, and the opening record of a wipe. The engines now
        test ``is None`` explicitly; this exists so that the same mistake cannot
        be made again by writing the natural-looking ``if not chain``.
        """
        return True

    def __len__(self) -> int:
        with self._lock:
            return sum(1 for _ in self._read_entries())

    def tail(self, count: int = 50) -> list[AuditEntry]:
        return self.entries()[-count:]

    # -- verification ------------------------------------------------------

    def verify(self) -> VerifyReport:
        """
        Re-derive the whole chain and report the first integrity failure.

        Detects: modified payloads, broken back-links, re-sequenced entries,
        forged HMACs and unparseable lines.

        ``broken_at`` is the 1-based position of the offending record *in the
        file*, not the ``seq`` it claims. That distinction matters: in exactly
        the cases being detected, ``seq`` is written by whoever tampered with
        the chain, so reporting it would be repeating the attacker's account of
        where the records are. The physical position is a fact about the
        artefact. The claimed sequence is still named in the reason, where it is
        useful context rather than the answer.
        """
        with self._lock:
            if not self.path.exists():
                return VerifyReport(ok=True, entries=0, reason="no audit records yet")

            expected_prev = GENESIS_HASH
            expected_seq = 1
            count = 0

            with open(self.path, "r", encoding="utf-8") as handle:
                for lineno, line in enumerate(handle, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw = json.loads(line)
                        entry = AuditEntry(**raw)
                    except (json.JSONDecodeError, TypeError) as exc:
                        return VerifyReport(
                            ok=False,
                            entries=count,
                            broken_at=lineno,
                            reason=f"unparseable record: {exc}",
                        )

                    if entry.seq != expected_seq:
                        return VerifyReport(
                            ok=False,
                            entries=count,
                            broken_at=lineno,
                            reason=f"sequence gap (expected {expected_seq}, found {entry.seq})",
                        )
                    if entry.prev_hash != expected_prev:
                        return VerifyReport(
                            ok=False,
                            entries=count,
                            broken_at=lineno,
                            reason=(
                                "broken back-link to previous entry "
                                f"(record claims sequence {entry.seq})"
                            ),
                        )
                    if not entry.is_sealed_correctly():
                        return VerifyReport(
                            ok=False,
                            entries=count,
                            broken_at=lineno,
                            reason=(
                                "payload modified or HMAC invalid "
                                f"(record claims sequence {entry.seq})"
                            ),
                        )

                    expected_prev = entry.entry_hash
                    expected_seq += 1
                    count += 1

            return VerifyReport(ok=True, entries=count)

    # -- export ------------------------------------------------------------

    def export_json(self, destination: str | Path) -> Path:
        """
        Copy the raw chain to an evidence bundle, preserving byte content.

        A byte copy rather than a decode-and-rewrite: the point of an export is
        that it is the same artefact, and anything that round-trips through text
        can quietly change it. The test that pins this compares the bytes.
        """
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.path, destination)
        return destination
