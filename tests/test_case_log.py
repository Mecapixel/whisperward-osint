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

from core.case_log import ChainOfCustodyLog, GENESIS_PREVIOUS_HASH


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


class TestConnectionAndOwnership:
    def test_shared_connection_not_closed_by_log(self, db_path):
        # When a connection is supplied, the log does not own it and must not
        # close it. This is the mode the packager uses.
        shared = sqlite3.connect(db_path)
        log = ChainOfCustodyLog(connection=shared)
        log.append(action="a", case_id="C")
        log.close()
        # The shared connection should still be usable after the log closes.
        shared.execute("SELECT 1").fetchone()
        shared.close()

    def test_owned_connection_path_works(self, db_path):
        # When only a db_path is supplied the log owns and manages its own
        # connection. This exercises the ownership branch end to end.
        log = ChainOfCustodyLog(db_path=db_path)
        log.append(action="a", case_id="C")
        assert log.verify()["intact"] is True
        log.close()

    def test_requires_path_or_connection(self):
        with pytest.raises(ValueError):
            ChainOfCustodyLog()

    def test_two_logs_share_one_connection(self, db_path):
        # The packager opens its own ChainOfCustodyLog on a connection the caller
        # also uses. Appends from either must extend the same intact chain.
        shared = sqlite3.connect(db_path)
        log_a = ChainOfCustodyLog(connection=shared)
        log_a.append(action="first", case_id="C")
        log_b = ChainOfCustodyLog(connection=shared)
        log_b.append(action="second", case_id="C")
        assert log_b.verify()["intact"] is True
        assert log_b.verify()["entries_checked"] == 2
        shared.close()


class TestNullFieldTampering:
    def test_filling_a_null_field_is_detected(self, db_path):
        # An entry written with no analyst stores NULL. Changing that NULL to a
        # value after the fact must break the chain, because the digest covered
        # the null.
        log = ChainOfCustodyLog(db_path=db_path)
        log.append(action="a", case_id="C")  # analyst is None
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE evidence_log SET analyst='InsertedName' WHERE log_id=1")
        conn.commit()
        conn.close()
        assert log.verify()["intact"] is False

    def test_analyst_none_flows_through(self, db_path):
        log = ChainOfCustodyLog(db_path=db_path)
        entry = log.append(action="a", case_id="C", analyst=None)
        assert entry["analyst"] is None
        assert log.verify()["intact"] is True


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))