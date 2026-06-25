"""
WhisperWard OSINT — Test suite for the Chain of Custody Log
Phase 4, Milestone 5
Pixora Inc.

These tests lock in the tamper evident behavior of the chain of custody log. The
central guarantees are that a clean chain verifies, that editing any past entry is
detected at the exact entry, that deleting an entry breaks the chain, that the log
coexists with a pre existing evidence_log table without losing data, and that
timestamps are recorded in UTC.
"""

import os
import sqlite3
import tempfile

import pytest

from modules.case_log import ChainOfCustodyLog, GENESIS_PREVIOUS_HASH


@pytest.fixture
def db_path():
    directory = tempfile.mkdtemp()
    yield os.path.join(directory, "test.db")


class TestChainConstruction:
    def test_empty_chain_verifies(self, db_path):
        log = ChainOfCustodyLog(db_path=db_path)
        result = log.verify()
        assert result["intact"] is True
        assert result["entries_checked"] == 0

    def test_single_entry_chains_from_genesis(self, db_path):
        log = ChainOfCustodyLog(db_path=db_path)
        entry = log.append(action="case_created", case_id="CASE-1")
        assert entry["previous_hash"] == GENESIS_PREVIOUS_HASH
        assert entry["entry_hash"]

    def test_each_entry_seals_the_previous(self, db_path):
        log = ChainOfCustodyLog(db_path=db_path)
        first = log.append(action="a", case_id="C")
        second = log.append(action="b", case_id="C")
        assert second["previous_hash"] == first["entry_hash"]

    def test_multi_entry_chain_verifies(self, db_path):
        log = ChainOfCustodyLog(db_path=db_path)
        for action in ["created", "collected", "analyzed", "packaged", "signed"]:
            log.append(action=action, case_id="CASE-1", analyst="Meca")
        result = log.verify()
        assert result["intact"] is True
        assert result["entries_checked"] == 5

    def test_append_requires_action(self, db_path):
        log = ChainOfCustodyLog(db_path=db_path)
        with pytest.raises(ValueError):
            log.append(action="")


class TestTamperDetection:
    def test_edited_entry_is_detected(self, db_path):
        log = ChainOfCustodyLog(db_path=db_path)
        for action in ["a", "b", "c", "d"]:
            log.append(action=action, case_id="C")
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE evidence_log SET notes='ALTERED' WHERE log_id=2")
        conn.commit()
        conn.close()
        result = log.verify()
        assert result["intact"] is False
        assert result["broken_at_log_id"] == 2

    def test_deleted_entry_breaks_chain(self, db_path):
        log = ChainOfCustodyLog(db_path=db_path)
        for action in ["a", "b", "c", "d"]:
            log.append(action=action, case_id="C")
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM evidence_log WHERE log_id=2")
        conn.commit()
        conn.close()
        result = log.verify()
        assert result["intact"] is False

    def test_altered_action_field_detected(self, db_path):
        log = ChainOfCustodyLog(db_path=db_path)
        log.append(action="case_created", case_id="C")
        log.append(action="case_purged", case_id="C")
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE evidence_log SET action='case_created' WHERE log_id=2")
        conn.commit()
        conn.close()
        result = log.verify()
        assert result["intact"] is False

    def test_intact_after_legitimate_appends(self, db_path):
        log = ChainOfCustodyLog(db_path=db_path)
        log.append(action="a", case_id="C")
        log.append(action="b", case_id="C")
        assert log.verify()["intact"] is True
        log.append(action="c", case_id="C")
        assert log.verify()["intact"] is True


class TestSchemaCoexistence:
    def test_adds_chain_columns_to_existing_table(self, db_path):
        # Create the legacy evidence_log table without chain columns first.
        conn = sqlite3.connect(db_path)
        conn.execute(
            "CREATE TABLE evidence_log (log_id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp DATETIME, action TEXT NOT NULL, artifact_id INTEGER, "
            "target_id INTEGER, analyst TEXT, sha256 TEXT, notes TEXT)"
        )
        conn.execute("INSERT INTO evidence_log (action, notes) VALUES ('legacy_row', 'old')")
        conn.commit()
        conn.close()

        # Opening the log should add chain columns without losing the legacy row.
        log = ChainOfCustodyLog(db_path=db_path)
        conn = sqlite3.connect(db_path)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(evidence_log)")}
        assert "entry_hash" in cols
        assert "previous_hash" in cols
        legacy = conn.execute("SELECT COUNT(*) FROM evidence_log WHERE action='legacy_row'").fetchone()[0]
        conn.close()
        assert legacy == 1

    def test_legacy_rows_excluded_from_chain(self, db_path):
        conn = sqlite3.connect(db_path)
        conn.execute(
            "CREATE TABLE evidence_log (log_id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp DATETIME, action TEXT NOT NULL, artifact_id INTEGER, "
            "target_id INTEGER, analyst TEXT, sha256 TEXT, notes TEXT)"
        )
        conn.execute("INSERT INTO evidence_log (action) VALUES ('legacy_unchained')")
        conn.commit()
        conn.close()
        log = ChainOfCustodyLog(db_path=db_path)
        log.append(action="chained_entry", case_id="C")
        # The legacy unchained row must not participate in or break the chain.
        result = log.verify()
        assert result["intact"] is True
        assert result["entries_checked"] == 1


class TestEntriesAndTimestamps:
    def test_entries_filtered_by_case(self, db_path):
        log = ChainOfCustodyLog(db_path=db_path)
        log.append(action="a", case_id="CASE-A")
        log.append(action="b", case_id="CASE-B")
        log.append(action="c", case_id="CASE-A")
        assert len(log.entries(case_id="CASE-A")) == 2
        assert len(log.entries(case_id="CASE-B")) == 1

    def test_timestamp_is_utc(self, db_path):
        log = ChainOfCustodyLog(db_path=db_path)
        entry = log.append(action="a", case_id="C")
        # An ISO UTC timestamp ends with +00:00 offset.
        assert entry["timestamp"].endswith("+00:00")

    def test_entries_in_order(self, db_path):
        log = ChainOfCustodyLog(db_path=db_path)
        for action in ["first", "second", "third"]:
            log.append(action=action, case_id="C")
        actions = [e["action"] for e in log.entries()]
        assert actions == ["first", "second", "third"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))