"""
WhisperWard — Investigation Timeline
Platform Phase 3, Milestone 3
Pixora Inc.

The database already records everything that happens to a case: when it was
opened, when targets were added, when artifacts were collected, when analyses
ran, what the custody chain logged, and what analysts wrote in their notes.
What it lacked was a single ordered view. This module assembles that view.

The timeline is strictly reconstructive. It reports what the record shows,
sourced row by row, and never infers events that are not in the record. Every
event names the table it came from and the row it references, so any entry on
the timeline can be walked back to its underlying evidence. Timestamps are
normalized to UTC; rows whose timestamps carry no timezone (SQLite's
CURRENT_TIMESTAMP is UTC by definition) are labeled as UTC rather than
guessed at.

Because the timeline travels inside evidence packages, its serialization is
deterministic: stable ordering (timestamp, then source, then reference id)
and stable key order.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def _normalize_utc(value: Optional[str]) -> str:
    """Best-effort normalization of stored timestamps to ISO-8601 UTC.
    SQLite CURRENT_TIMESTAMP produces naive 'YYYY-MM-DD HH:MM:SS' in UTC;
    application code writes timezone-aware ISO strings. Unparseable input is
    returned unchanged rather than dropped, because losing a malformed
    timestamp would silently drop the event it belongs to."""
    if not value:
        return ""
    text = str(value).strip()
    try:
        candidate = text.replace(" ", "T", 1)
        parsed = datetime.fromisoformat(candidate)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except ValueError:
        return text


@dataclass
class TimelineEvent:
    timestamp: str
    kind: str
    description: str
    source_table: str
    source_ref: str
    analyst: str = ""
    target_id: Optional[int] = None
    sha256: str = ""
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "kind": self.kind,
            "description": self.description,
            "source_table": self.source_table,
            "source_ref": self.source_ref,
            "analyst": self.analyst,
            "target_id": self.target_id,
            "sha256": self.sha256,
            "detail": dict(self.detail),
        }


class InvestigationTimeline:
    """Builds the ordered event stream for one case from the database."""

    def __init__(self, case_id: str, events: list[TimelineEvent]):
        self.case_id = case_id
        self.events = sorted(
            events, key=lambda e: (e.timestamp, e.source_table, e.source_ref))

    # ------------------------------------------------------------- build

    @classmethod
    def build(cls, database, case_id: str) -> "InvestigationTimeline":
        conn = database.get_connection()
        events: list[TimelineEvent] = []

        case = conn.execute(
            "SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        if case is not None:
            events.append(TimelineEvent(
                timestamp=_normalize_utc(case["created_at"]),
                kind="case_opened",
                description="Case '" + (case["case_name"] or case_id) + "' opened",
                source_table="cases", source_ref=case_id,
                analyst=case["analyst_name"] or ""))

        target_ids: list[int] = []
        for t in conn.execute(
                "SELECT * FROM targets WHERE case_id = ? ORDER BY target_id",
                (case_id,)).fetchall():
            target_ids.append(t["target_id"])
            events.append(TimelineEvent(
                timestamp=_normalize_utc(t["added_at"]),
                kind="target_added",
                description=("Target " + t["platform"] + ":" + t["username"]
                             + " added to case"),
                source_table="targets", source_ref=str(t["target_id"]),
                target_id=t["target_id"]))

        if target_ids:
            marks = ",".join("?" for _ in target_ids)
            for a in conn.execute(
                    "SELECT artifact_id, target_id, module_name, artifact_type, "
                    "sha256, collected_at FROM artifacts WHERE target_id IN ("
                    + marks + ") ORDER BY artifact_id", target_ids).fetchall():
                events.append(TimelineEvent(
                    timestamp=_normalize_utc(a["collected_at"]),
                    kind="artifact_collected",
                    description=(a["module_name"] + " collected "
                                 + a["artifact_type"] + " artifact"),
                    source_table="artifacts", source_ref=str(a["artifact_id"]),
                    target_id=a["target_id"], sha256=a["sha256"] or ""))

            for r in conn.execute(
                    "SELECT result_id, target_id, analysis_type, risk_score, "
                    "analyzed_at FROM analysis_results WHERE target_id IN ("
                    + marks + ") ORDER BY result_id", target_ids).fetchall():
                detail = {}
                if r["risk_score"] is not None:
                    detail["risk_score"] = round(float(r["risk_score"]), 2)
                events.append(TimelineEvent(
                    timestamp=_normalize_utc(r["analyzed_at"]),
                    kind="analysis_recorded",
                    description=r["analysis_type"] + " analysis recorded",
                    source_table="analysis_results",
                    source_ref=str(r["result_id"]),
                    target_id=r["target_id"], detail=detail))

        events.extend(cls._custody_events(conn, case_id, set(target_ids)))
        events.extend(cls._note_events(conn, case_id))
        events.extend(cls._entity_events(conn, case_id))
        return cls(case_id, events)

    @staticmethod
    def _custody_events(conn, case_id: str, target_ids: set) -> list[TimelineEvent]:
        events = []
        try:
            rows = conn.execute(
                "SELECT log_id, timestamp, action, case_id, target_id, "
                "analyst, sha256, notes FROM evidence_log "
                "ORDER BY log_id").fetchall()
        except Exception:
            return events
        for row in rows:
            keys = row.keys()
            row_case = row["case_id"] if "case_id" in keys else None
            row_target = row["target_id"] if "target_id" in keys else None
            in_case = (row_case == case_id) or (
                row_case is None and row_target in target_ids)
            if not in_case:
                continue
            events.append(TimelineEvent(
                timestamp=_normalize_utc(row["timestamp"]),
                kind="custody_" + (row["action"] or "entry"),
                description=(row["notes"] or row["action"] or "custody entry"),
                source_table="evidence_log", source_ref=str(row["log_id"]),
                analyst=row["analyst"] or "", target_id=row_target,
                sha256=row["sha256"] or ""))
        return events

    @staticmethod
    def _note_events(conn, case_id: str) -> list[TimelineEvent]:
        events = []
        try:
            rows = conn.execute(
                "SELECT note_id, case_id, analyst, note, finding_ref, "
                "created_at FROM analyst_notes WHERE case_id = ? "
                "ORDER BY note_id", (case_id,)).fetchall()
        except Exception:
            return events
        for row in rows:
            detail = {}
            if row["finding_ref"]:
                detail["finding_ref"] = row["finding_ref"]
            events.append(TimelineEvent(
                timestamp=_normalize_utc(row["created_at"]),
                kind="analyst_note",
                description=row["note"] or "",
                source_table="analyst_notes", source_ref=str(row["note_id"]),
                analyst=row["analyst"] or "", detail=detail))
        return events

    @staticmethod
    def _entity_events(conn, case_id: str) -> list[TimelineEvent]:
        events = []
        try:
            rows = conn.execute(
                "SELECT entity_id, canonical_handle, promoted_by, promoted_at "
                "FROM entities WHERE case_id = ? ORDER BY promoted_at",
                (case_id,)).fetchall()
        except Exception:
            return events
        for row in rows:
            events.append(TimelineEvent(
                timestamp=_normalize_utc(row["promoted_at"]),
                kind="entity_promoted",
                description=("Entity " + row["entity_id"] + " ('"
                             + row["canonical_handle"]
                             + "') resolved by analyst decision"),
                source_table="entities", source_ref=row["entity_id"],
                analyst=row["promoted_by"] or ""))
        return events

    # ------------------------------------------------------------ queries

    def filter(self, kind: Optional[str] = None,
               target_id: Optional[int] = None) -> list[TimelineEvent]:
        selected = self.events
        if kind is not None:
            selected = [e for e in selected if e.kind == kind
                        or e.kind.startswith(kind)]
        if target_id is not None:
            selected = [e for e in selected if e.target_id == target_id]
        return list(selected)

    # ------------------------------------------------------ serialization

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "event_count": len(self.events),
            "events": [e.to_dict() for e in self.events],
            "provenance": (
                "Reconstructed from the case record only. Every event names "
                "its source table and row; no event is inferred."
            ),
        }

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True,
                          separators=(",", ":"))
