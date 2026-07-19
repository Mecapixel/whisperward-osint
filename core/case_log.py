"""
WhisperWard OSINT — Chain of Custody Log
Phase 4, Milestone 5
Pixora Inc.

This module turns the chain of custody log into a tamper evident record. The
existing evidence_log table records who did what and when, but as an ordinary
table a row could be edited or deleted with nothing to show for it. A forensic
log must be append only and tamper evident, so that any alteration of a past
entry is detectable after the fact.

The mechanism is a hash chain. Every entry stores its own SHA-256 digest, and
that digest is computed over the entry's own content together with the digest of
the entry immediately before it. The first entry chains from a fixed genesis
value. Because each entry seals the one before it, changing any past entry
changes that entry's digest, which breaks the link every later entry depends on.
A single edit therefore invalidates the entire remainder of the chain, and
verification pinpoints exactly where the break occurs.

All timestamps are recorded in UTC with an explicit timezone, because a chain of
custody timestamp without a timezone is ambiguous and that ambiguity is the kind
of thing challenged in court.

This module manages its own connection through a supplied path or connection so
it can be tested in isolation, and it is written to coexist with the existing
evidence_log table by adding the chain columns if they are not already present.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional


# The fixed value the first entry chains from. Any constant works as long as it
# is stable, because its only job is to give entry one a defined predecessor.
GENESIS_PREVIOUS_HASH = "0" * 64


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_entry_bytes(timestamp: str, action: str, case_id: Optional[str],
                           artifact_id: Optional[int], target_id: Optional[int],
                           analyst: Optional[str], sha256: Optional[str],
                           notes: Optional[str], previous_hash: str) -> bytes:
    """Serializes the fields that the entry digest is computed over, in a fixed
    key order so the digest is reproducible. The previous entry's hash is
    included, which is what links each entry to its predecessor. Any change to any
    field changes these bytes and therefore the digest."""
    payload = {
        "timestamp": timestamp,
        "action": action,
        "case_id": case_id,
        "artifact_id": artifact_id,
        "target_id": target_id,
        "analyst": analyst,
        "sha256": sha256,
        "notes": notes,
        "previous_hash": previous_hash,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _entry_hash(*args) -> str:
    return hashlib.sha256(_canonical_entry_bytes(*args)).hexdigest()


class ChainOfCustodyLog:
    """A tamper evident append only log backed by the evidence_log table. Pass a
    database path or an open connection. The chain columns are created on first
    use if they are not already present, so this works against the existing
    schema without a migration step."""

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
        self._ensure_schema()

    def _ensure_schema(self):
        """Creates the evidence_log table if absent and adds the chain columns if
        they are not already present. Existing deployments keep their data and
        simply gain the entry_hash and previous_hash columns."""
        cur = self._conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_log (
                log_id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     TEXT,
                action        TEXT NOT NULL,
                case_id       TEXT,
                artifact_id   INTEGER,
                target_id     INTEGER,
                analyst       TEXT,
                sha256        TEXT,
                notes         TEXT,
                entry_hash    TEXT,
                previous_hash TEXT
            )
            """
        )
        existing = {row["name"] for row in cur.execute("PRAGMA table_info(evidence_log)")}
        if "entry_hash" not in existing:
            cur.execute("ALTER TABLE evidence_log ADD COLUMN entry_hash TEXT")
        if "previous_hash" not in existing:
            cur.execute("ALTER TABLE evidence_log ADD COLUMN previous_hash TEXT")
        if "case_id" not in existing:
            cur.execute("ALTER TABLE evidence_log ADD COLUMN case_id TEXT")
        self._conn.commit()

    def _last_entry_hash(self) -> str:
        """Returns the hash of the most recent chained entry, or the genesis value
        if the chain is empty. Only rows that carry an entry_hash participate in
        the chain, so pre existing unchained rows do not interfere."""
        cur = self._conn.cursor()
        row = cur.execute(
            "SELECT entry_hash FROM evidence_log "
            "WHERE entry_hash IS NOT NULL ORDER BY log_id DESC LIMIT 1"
        ).fetchone()
        if row is None or row["entry_hash"] is None:
            return GENESIS_PREVIOUS_HASH
        return row["entry_hash"]

    def append(self, action: str, case_id: Optional[str] = None,
               artifact_id: Optional[int] = None, target_id: Optional[int] = None,
               analyst: Optional[str] = None, sha256: Optional[str] = None,
               notes: Optional[str] = None) -> dict:
        """Appends a new entry sealing the previous one and returns the stored
        entry as a dictionary. The action describes what happened, for example
        artifact_collected, package_created, redaction_applied, or case_purged.
        The timestamp is recorded in UTC."""
        if not action:
            raise ValueError("An action is required for a chain of custody entry.")
        timestamp = _utc_now_iso()
        previous_hash = self._last_entry_hash()
        entry_hash = _entry_hash(timestamp, action, case_id, artifact_id,
                                 target_id, analyst, sha256, notes, previous_hash)
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO evidence_log
                (timestamp, action, case_id, artifact_id, target_id, analyst,
                 sha256, notes, entry_hash, previous_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (timestamp, action, case_id, artifact_id, target_id, analyst,
             sha256, notes, entry_hash, previous_hash),
        )
        self._conn.commit()
        return {
            "log_id": cur.lastrowid,
            "timestamp": timestamp,
            "action": action,
            "case_id": case_id,
            "artifact_id": artifact_id,
            "target_id": target_id,
            "analyst": analyst,
            "sha256": sha256,
            "notes": notes,
            "entry_hash": entry_hash,
            "previous_hash": previous_hash,
        }

    def entries(self, case_id: Optional[str] = None) -> list:
        """Returns the chained entries in order. When a case_id is given, only
        that case's entries are returned, though verification should be run over
        the full chain because the chain links across cases."""
        cur = self._conn.cursor()
        if case_id is not None:
            rows = cur.execute(
                "SELECT * FROM evidence_log WHERE entry_hash IS NOT NULL AND case_id = ? "
                "ORDER BY log_id ASC", (case_id,)
            ).fetchall()
        else:
            rows = cur.execute(
                "SELECT * FROM evidence_log WHERE entry_hash IS NOT NULL ORDER BY log_id ASC"
            ).fetchall()
        return [dict(row) for row in rows]

    def verify(self) -> dict:
        """Recomputes the chain from the beginning and confirms every entry seals
        the previous one. Returns a result describing whether the chain is intact,
        how many entries were checked, and the first entry where a break was found
        if any. A break means a past entry was altered or removed after the fact."""
        cur = self._conn.cursor()
        rows = cur.execute(
            "SELECT * FROM evidence_log WHERE entry_hash IS NOT NULL ORDER BY log_id ASC"
        ).fetchall()

        expected_previous = GENESIS_PREVIOUS_HASH
        checked = 0
        for row in rows:
            recomputed = _entry_hash(
                row["timestamp"], row["action"], row["case_id"], row["artifact_id"],
                row["target_id"], row["analyst"], row["sha256"], row["notes"],
                row["previous_hash"],
            )
            if row["previous_hash"] != expected_previous:
                return {
                    "intact": False,
                    "entries_checked": checked,
                    "broken_at_log_id": row["log_id"],
                    "reason": "previous_hash does not match the prior entry, the chain link is broken.",
                }
            if recomputed != row["entry_hash"]:
                return {
                    "intact": False,
                    "entries_checked": checked,
                    "broken_at_log_id": row["log_id"],
                    "reason": "stored entry_hash does not match recomputed hash, the entry content was altered.",
                }
            expected_previous = row["entry_hash"]
            checked += 1

        return {
            "intact": True,
            "entries_checked": checked,
            "broken_at_log_id": None,
            "reason": "All entries verified, the chain is intact.",
        }

    def close(self):
        if self._owns_connection:
            self._conn.close()