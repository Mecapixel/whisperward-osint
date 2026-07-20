"""
core/evidence.py
WhisperWard Core — Evidence Model
Pixora Inc. | Roadmap Phase 2, Milestone 1

Promotes the Evidence contract (core/contracts.py) from a marker to a real
model. No artifact exists in a Phase 2 evidence view without an identifier,
a SHA-256 digest, a UTC timestamp, a source, and a collector. The model
wraps the existing artifacts table rather than replacing it, so every
already-collected artifact gains the contract retroactively and nothing in
the collection pipeline changes.

The chain-of-custody manifest assembles, per case: every artifact's
identity and digest, every custody event recorded against it in the
evidence log, and the tamper-evidence verification status of the hash
chain itself. The manifest is what a reviewer reads to answer "what is
this artifact, where did it come from, who touched it, and can I trust
the record" without opening the database.
"""

from __future__ import annotations

import sqlite3
import uuid as uuid_module
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from core.case_log import ChainOfCustodyLog


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EvidenceRecord:
    """The canonical implementation of the Evidence contract.

    Every field the contract promises is mandatory at construction:
    evidence_id (UUID string), sha256, collected_at (UTC ISO), source,
    and collector. artifact_id links back to the artifacts table when the
    record wraps a stored artifact; it is None for records created ahead
    of persistence.
    """

    sha256: str
    source: str
    collector: str
    artifact_type: str = "unknown"
    collected_at: str = field(default_factory=_utc_now_iso)
    evidence_id: str = field(default_factory=lambda: str(uuid_module.uuid4()))
    artifact_id: Optional[int] = None
    case_id: Optional[str] = None
    target_id: Optional[int] = None

    def __post_init__(self):
        if not self.sha256 or not isinstance(self.sha256, str):
            raise ValueError("EvidenceRecord requires a non-empty sha256")
        if len(self.sha256) != 64 or any(
            c not in "0123456789abcdefABCDEF" for c in self.sha256
        ):
            raise ValueError("sha256 must be a 64-character hex digest")
        if not self.source:
            raise ValueError("EvidenceRecord requires a source")
        if not self.collector:
            raise ValueError("EvidenceRecord requires a collector")

    def to_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "artifact_id": self.artifact_id,
            "case_id": self.case_id,
            "target_id": self.target_id,
            "artifact_type": self.artifact_type,
            "sha256": self.sha256,
            "collected_at": self.collected_at,
            "source": self.source,
            "collector": self.collector,
        }

    @classmethod
    def from_artifact_row(cls, row: dict, case_id: Optional[str] = None) -> "EvidenceRecord":
        """Build an EvidenceRecord from a row of the artifacts table.

        The artifacts table predates this model, so two contract fields are
        derived: source comes from the module that collected the artifact,
        and the deterministic UUID is derived from the artifact's own
        identity (id + sha256) so repeated manifest builds assign the same
        evidence_id to the same artifact instead of minting a new one.
        """
        artifact_id = row["artifact_id"]
        sha256 = row["sha256"]
        stable = uuid_module.uuid5(
            uuid_module.NAMESPACE_URL,
            f"whisperward:artifact:{artifact_id}:{sha256}",
        )
        return cls(
            sha256=sha256,
            source=row.get("module_name", "unknown"),
            collector=row.get("module_name", "unknown"),
            artifact_type=row.get("artifact_type", "unknown"),
            collected_at=str(row.get("collected_at") or _utc_now_iso()),
            evidence_id=str(stable),
            artifact_id=artifact_id,
            case_id=case_id,
            target_id=row.get("target_id"),
        )


def _rows_as_dicts(cursor) -> list[dict]:
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, r)) for r in cursor.fetchall()]


def build_custody_manifest(
    case_id: str,
    connection: sqlite3.Connection,
    db_path: Optional[str] = None,
) -> dict:
    """Assemble the chain-of-custody manifest for a case.

    Contents, in order: the case identity and build timestamp; one entry per
    artifact carrying the full EvidenceRecord plus every custody event
    recorded against that artifact in the evidence log; custody events
    recorded at case level (no artifact reference); and the verification
    status of the tamper-evident hash chain, so the manifest itself states
    whether the record it summarizes withstood verification.
    """
    cur = connection.cursor()
    cur.execute(
        """
        SELECT a.artifact_id, a.target_id, a.module_name, a.artifact_type,
               a.sha256, a.collected_at
        FROM artifacts a
        JOIN targets t ON a.target_id = t.target_id
        WHERE t.case_id = ?
        ORDER BY a.artifact_id
        """,
        (case_id,),
    )
    artifact_rows = _rows_as_dicts(cur)

    cur.execute(
        """
        SELECT log_id, timestamp, action, artifact_id, target_id, analyst,
               sha256, notes
        FROM evidence_log
        WHERE artifact_id IN (
            SELECT a.artifact_id FROM artifacts a
            JOIN targets t ON a.target_id = t.target_id
            WHERE t.case_id = ?
        )
        ORDER BY log_id
        """,
        (case_id,),
    )
    events = _rows_as_dicts(cur)
    events_by_artifact: dict[int, list[dict]] = {}
    for e in events:
        events_by_artifact.setdefault(e["artifact_id"], []).append(e)

    entries = []
    for row in artifact_rows:
        record = EvidenceRecord.from_artifact_row(row, case_id=case_id)
        entries.append(
            {
                "evidence": record.to_dict(),
                "custody_events": [
                    {
                        "timestamp": str(e["timestamp"]),
                        "action": e["action"],
                        "analyst": e.get("analyst"),
                        "notes": e.get("notes"),
                    }
                    for e in events_by_artifact.get(row["artifact_id"], [])
                ],
            }
        )

    chain_status: dict = {"available": False}
    try:
        log = ChainOfCustodyLog(connection=connection) if db_path is None else ChainOfCustodyLog(db_path=db_path)
        try:
            chain_status = dict(log.verify())
            chain_status["available"] = True
        finally:
            if db_path is not None:
                log.close()
    except Exception as exc:  # chain table absent or unreadable: say so, honestly
        chain_status = {"available": False, "error": str(exc)}

    # Phase 2 M4: analyst notes travel with the case. The table is created
    # on demand, so cases predating the notes layer produce an empty list.
    try:
        note_rows = connection.execute(
            "SELECT note_id, target_id, finding_ref, analyst, note, created_at"
            " FROM analyst_notes WHERE case_id = ? ORDER BY note_id",
            (case_id,),
        ).fetchall()
        notes = [
            {
                "note_id": r[0],
                "target_id": r[1],
                "finding_ref": r[2],
                "analyst": r[3],
                "note": r[4],
                "created_at": str(r[5]),
            }
            for r in note_rows
        ]
    except sqlite3.OperationalError:
        notes = []

    return {
        "manifest_type": "chain_of_custody",
        "manifest_version": 1,
        "case_id": case_id,
        "built_at": _utc_now_iso(),
        "artifact_count": len(entries),
        "artifacts": entries,
        "analyst_notes": notes,
        "hash_chain_verification": chain_status,
    }
