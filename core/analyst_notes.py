"""
core/analyst_notes.py
WhisperWard Core — Analyst Notes
Pixora Inc. | Roadmap Phase 2, Milestone 4

Human annotations as first-class case data. A note attaches to a case, and
optionally to a target and to a specific finding (a risk-engine component
name or an ExplanationObject's source_component), and it travels with the
case: notes appear in the chain-of-custody manifest that ships inside
every evidence package, and every note written lands in the tamper-evident
custody hash chain, so the record of human judgment is as protected as the
record of collected evidence.

Notes are append-only by design. Corrections are new notes that say what
they correct; nothing is silently rewritten. That is the same principle
the evidence log follows, applied to the analyst's own words.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Optional

from core.case_log import ChainOfCustodyLog

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analyst_notes (
    note_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT    NOT NULL,
    target_id   INTEGER,
    finding_ref TEXT,
    analyst     TEXT    NOT NULL,
    note        TEXT    NOT NULL,
    created_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyst_notes_case
    ON analyst_notes (case_id, note_id);
"""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AnalystNotes:
    """Append-only analyst annotations for a case, chained into custody."""

    def __init__(self, db_path: Optional[str] = None,
                 connection: Optional[sqlite3.Connection] = None):
        if connection is not None:
            self._conn = connection
            self._owns_connection = False
        elif db_path is not None:
            self._conn = sqlite3.connect(db_path)
            self._owns_connection = True
        else:
            raise ValueError("Provide either a db_path or an existing connection.")
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def add(self, case_id: str, analyst: str, note: str,
            target_id: Optional[int] = None,
            finding_ref: Optional[str] = None) -> int:
        """Record a note and append the event to the custody hash chain."""
        if not case_id:
            raise ValueError("A note requires a case_id")
        if not analyst:
            raise ValueError("A note requires an analyst")
        if not note or not note.strip():
            raise ValueError("A note requires content")

        created_at = _utc_now_iso()
        cur = self._conn.execute(
            "INSERT INTO analyst_notes"
            " (case_id, target_id, finding_ref, analyst, note, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (case_id, target_id, finding_ref, analyst, note.strip(), created_at),
        )
        note_id = cur.lastrowid
        self._conn.commit()

        chain = ChainOfCustodyLog(connection=self._conn)
        chain.append(
            "analyst_note_added",
            case_id=case_id,
            analyst=analyst,
            notes=(
                f"note {note_id}"
                + (f" on finding {finding_ref}" if finding_ref else "")
                + (f" (target {target_id})" if target_id is not None else "")
            ),
        )
        return note_id

    def for_case(self, case_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT note_id, case_id, target_id, finding_ref, analyst, note,"
            " created_at FROM analyst_notes WHERE case_id = ? ORDER BY note_id",
            (case_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def for_finding(self, case_id: str, finding_ref: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT note_id, case_id, target_id, finding_ref, analyst, note,"
            " created_at FROM analyst_notes"
            " WHERE case_id = ? AND finding_ref = ? ORDER BY note_id",
            (case_id, finding_ref),
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self):
        if self._owns_connection:
            self._conn.close()
