"""
tests/test_analyst_notes.py
WhisperWard — Phase 2 Milestone 4 tests

Analyst notes attach to cases, targets, and findings; every note lands in
the tamper-evident custody chain; notes travel inside the chain-of-custody
manifest; and the layer is append-only with validated inputs.
"""

import sqlite3
from pathlib import Path

import pytest

from core.analyst_notes import AnalystNotes
from core.case_log import ChainOfCustodyLog
from core.evidence import build_custody_manifest

VALID_SHA = "c" * 64


def _case_conn():
    conn = sqlite3.connect(":memory:")
    conn.executescript(Path("database/schema.sql").read_text())
    conn.execute(
        "INSERT INTO cases (case_id, case_name, status) VALUES (?, ?, ?)",
        ("CASE-NOTES01", "Notes test", "open"),
    )
    conn.execute(
        "INSERT INTO targets (case_id, platform, username) VALUES (?, ?, ?)",
        ("CASE-NOTES01", "roblox", "synthetic_user"),
    )
    target_id = conn.execute("SELECT target_id FROM targets").fetchone()[0]
    conn.execute(
        "INSERT INTO artifacts (target_id, module_name, artifact_type, sha256)"
        " VALUES (?, ?, ?, ?)",
        (target_id, "roblox_osint", "profile", VALID_SHA),
    )
    conn.commit()
    return conn, target_id


class TestAnalystNotes:
    def test_add_and_read_case_notes(self):
        conn, target_id = _case_conn()
        notes = AnalystNotes(connection=conn)
        note_id = notes.add(
            "CASE-NOTES01", "test_analyst",
            "Reviewed grooming component; escalation justified by message 4.",
            target_id=target_id, finding_ref="grooming_classifier",
        )
        assert note_id == 1
        stored = notes.for_case("CASE-NOTES01")
        assert len(stored) == 1
        assert stored[0]["finding_ref"] == "grooming_classifier"
        assert stored[0]["analyst"] == "test_analyst"

    def test_notes_filterable_by_finding(self):
        conn, _ = _case_conn()
        notes = AnalystNotes(connection=conn)
        notes.add("CASE-NOTES01", "a1", "on grooming", finding_ref="grooming_classifier")
        notes.add("CASE-NOTES01", "a1", "on correlation", finding_ref="cross_platform_correlation")
        grooming = notes.for_finding("CASE-NOTES01", "grooming_classifier")
        assert len(grooming) == 1 and grooming[0]["note"] == "on grooming"

    def test_every_note_lands_in_custody_chain(self):
        conn, _ = _case_conn()
        notes = AnalystNotes(connection=conn)
        notes.add("CASE-NOTES01", "test_analyst", "chained note",
                  finding_ref="overall_assessment")
        chain = ChainOfCustodyLog(connection=conn)
        actions = [e["action"] for e in chain.entries(case_id="CASE-NOTES01")]
        assert "analyst_note_added" in actions
        assert chain.verify().get("ok", chain.verify().get("valid", True))

    def test_notes_travel_in_custody_manifest(self):
        conn, target_id = _case_conn()
        notes = AnalystNotes(connection=conn)
        notes.add("CASE-NOTES01", "test_analyst", "manifest-borne note",
                  target_id=target_id)
        manifest = build_custody_manifest("CASE-NOTES01", conn)
        assert len(manifest["analyst_notes"]) == 1
        assert manifest["analyst_notes"][0]["note"] == "manifest-borne note"

    def test_manifest_without_notes_table_is_empty_not_error(self):
        conn, _ = _case_conn()
        manifest = build_custody_manifest("CASE-NOTES01", conn)
        assert manifest["analyst_notes"] == []

    def test_rejects_empty_inputs(self):
        conn, _ = _case_conn()
        notes = AnalystNotes(connection=conn)
        with pytest.raises(ValueError):
            notes.add("", "analyst", "note")
        with pytest.raises(ValueError):
            notes.add("CASE-NOTES01", "", "note")
        with pytest.raises(ValueError):
            notes.add("CASE-NOTES01", "analyst", "   ")
