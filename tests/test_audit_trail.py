"""
tests/test_audit_trail.py
WhisperWard — Phase 2 Milestone 5 tests

Audit trail hardening: every state change in a case's life — creation,
target addition, artifact collection, analysis, analyst note, evidence
packaging — lands in the tamper-evident custody chain, the chain verifies
intact across the full lifecycle, and tampering with history is detected.
"""

import sqlite3

import pytest

from core.analyst_notes import AnalystNotes
from core.case_log import ChainOfCustodyLog
from core.evidence_packager import create_evidence_package
from database.db_manager import DatabaseManager


@pytest.fixture()
def db(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # DatabaseManager.init reads database/schema.sql relative to cwd
    import shutil
    from pathlib import Path
    src = Path(__file__).resolve().parent.parent / "database" / "schema.sql"
    (tmp_path / "database").mkdir()
    shutil.copy(src, tmp_path / "database" / "schema.sql")
    manager = DatabaseManager(db_path=str(tmp_path / "audit.db"))
    manager.init()
    yield manager
    manager.close()


class TestLifecycleAuditTrail:
    def test_every_lifecycle_action_lands_in_chain(self, db, tmp_path):
        case_id = db.create_case("Audit lifecycle", analyst="test_analyst")
        db.add_target(case_id, "roblox", "synthetic_user")
        target_id = db.get_case_targets(case_id)[0]["target_id"]
        db.save_artifact(target_id, "roblox_osint", "profile",
                         raw_data={"username": "synthetic_user"})
        db.save_analysis(target_id, {"analysis_type": "behavioral",
                                     "risk_score": 3.2})
        AnalystNotes(connection=db.get_connection()).add(
            case_id, "test_analyst", "lifecycle audit note")
        create_evidence_package(case_id, export_dir=str(tmp_path),
                                connection=db.get_connection(),
                                analyst="test_analyst")

        chain = ChainOfCustodyLog(connection=db.get_connection())
        actions = [e["action"] for e in chain.entries()]
        for expected in ("case_created", "target_added", "artifact_saved",
                         "analysis_saved", "analyst_note_added"):
            assert expected in actions, f"lifecycle action {expected} missing from chain"
        assert any("package" in a for a in actions), "packaging event missing from chain"

    def test_chain_verifies_intact_after_full_lifecycle(self, db):
        case_id = db.create_case("Audit verify", analyst="test_analyst")
        db.add_target(case_id, "roblox", "synthetic_user")
        target_id = db.get_case_targets(case_id)[0]["target_id"]
        db.save_artifact(target_id, "roblox_osint", "profile",
                         raw_data={"k": "v"})
        chain = ChainOfCustodyLog(connection=db.get_connection())
        result = chain.verify()
        assert result.get("intact", result.get("ok", result.get("valid"))), result
        assert result.get("entries_checked", result.get("checked", 0)) >= 3

    def test_tampering_with_history_is_detected(self, db):
        case_id = db.create_case("Audit tamper", analyst="test_analyst")
        db.add_target(case_id, "roblox", "synthetic_user")
        conn = db.get_connection()
        conn.execute(
            "UPDATE evidence_log SET action = 'nothing_happened'"
            " WHERE action = 'target_added'")
        conn.commit()
        chain = ChainOfCustodyLog(connection=conn)
        result = chain.verify()
        assert not result.get("intact", result.get("ok", result.get("valid", True))), (
            "altered history must fail verification")

    def test_chain_failure_never_blocks_primary_operation(self, db, capsys):
        # Dropping the chain's own columns simulates a broken chain layer;
        # the case operation must still succeed with a warning, because an
        # investigator's work is never held hostage by audit plumbing.
        conn = db.get_connection()
        conn.execute("DROP TABLE evidence_log")
        conn.commit()
        case_id = db.create_case("Resilience", analyst="test_analyst")
        assert case_id.startswith("CASE-")
