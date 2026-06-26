"""
WhisperWard OSINT — Test suite for the Retention Enforcer
Phase 4, Milestone 5
Pixora Inc.

These tests lock in the retention behavior. The guarantees are that the default is
a dry run that changes nothing, that a confirmed purge deletes the eligible case's
database rows and export files, that cases inside the retention window are never
touched, that the chain of custody entries for a purged case are preserved and the
chain still verifies, that a case_purged entry is written, and that timestamp
parsing handles the forms the database produces while erring toward keeping data
when a timestamp cannot be parsed.
"""

import os
import sqlite3
from datetime import datetime, timezone, timedelta

import pytest

from modules.retention_enforcer import (enforce_retention, print_report,
                                        _parse_timestamp, DEFAULT_RETENTION_DAYS)
from modules.case_log import ChainOfCustodyLog


def iso_days_ago(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def seed(directory):
    db = os.path.join(directory, "w.db")
    exports = os.path.join(directory, "exports")
    os.makedirs(exports, exist_ok=True)
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE cases (case_id TEXT PRIMARY KEY, case_name TEXT,
            description TEXT, created_at TEXT, analyst_name TEXT, status TEXT);
        CREATE TABLE targets (target_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT, platform TEXT, username TEXT);
        CREATE TABLE artifacts (artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER, module_name TEXT, artifact_type TEXT,
            file_path TEXT, sha256 TEXT);
        CREATE TABLE analysis_results (result_id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER, analysis_type TEXT, risk_score REAL, analyzed_at TEXT);
        """
    )
    old = iso_days_ago(120)
    recent = iso_days_ago(10)
    conn.execute("INSERT INTO cases VALUES ('CASE-OLD','old','d',?,'Meca','open')", (old,))
    conn.execute("INSERT INTO targets (case_id, platform, username) VALUES ('CASE-OLD','roblox','s1')")
    conn.execute("INSERT INTO artifacts (target_id, module_name, artifact_type, sha256) "
                 "VALUES (1,'roblox','profile','h')")
    conn.execute("INSERT INTO analysis_results (target_id, analysis_type, risk_score, analyzed_at) "
                 "VALUES (1,'behavioral',5.0,?)", (old,))
    conn.execute("INSERT INTO cases VALUES ('CASE-NEW','new','d',?,'Meca','open')", (recent,))
    conn.execute("INSERT INTO targets (case_id, platform, username) VALUES ('CASE-NEW','roblox','s2')")
    conn.commit()

    for name in ["CASE-OLD_evidence_package.zip", "CASE-OLD_referral_redacted.json",
                 "CASE-NEW_evidence_package.zip"]:
        with open(os.path.join(exports, name), "w", encoding="utf-8") as handle:
            handle.write("x")

    log = ChainOfCustodyLog(connection=conn)
    log.append(action="case_created", case_id="CASE-OLD", analyst="Meca")
    conn.commit()
    return conn, exports


@pytest.fixture
def env(tmp_path):
    conn, exports = seed(str(tmp_path))
    yield {"dir": str(tmp_path), "conn": conn, "exports": exports}
    conn.close()


class TestDryRunSafety:
    def test_default_is_dry_run(self, env):
        rep = enforce_retention(connection=env["conn"], export_dir=env["exports"])
        assert rep["mode"] == "dry_run"

    def test_dry_run_changes_nothing(self, env):
        enforce_retention(connection=env["conn"], export_dir=env["exports"])
        rows = env["conn"].execute("SELECT COUNT(*) FROM cases WHERE case_id='CASE-OLD'").fetchone()[0]
        assert rows == 1
        assert os.path.exists(os.path.join(env["exports"], "CASE-OLD_evidence_package.zip"))

    def test_dry_run_identifies_eligible(self, env):
        rep = enforce_retention(connection=env["conn"], export_dir=env["exports"])
        assert rep["eligible_count"] == 1
        assert rep["cases"][0]["case_id"] == "CASE-OLD"

    def test_dry_run_lists_files_that_would_go(self, env):
        rep = enforce_retention(connection=env["conn"], export_dir=env["exports"])
        files = rep["cases"][0]["would_delete_files"]
        assert "CASE-OLD_evidence_package.zip" in files
        assert "CASE-OLD_referral_redacted.json" in files


class TestPurge:
    def test_purge_deletes_old_case_rows(self, env):
        enforce_retention(connection=env["conn"], export_dir=env["exports"],
                          confirm=True, analyst="Meca")
        c = env["conn"]
        assert c.execute("SELECT COUNT(*) FROM cases WHERE case_id='CASE-OLD'").fetchone()[0] == 0
        assert c.execute("SELECT COUNT(*) FROM targets WHERE case_id='CASE-OLD'").fetchone()[0] == 0

    def test_purge_deletes_old_case_files(self, env):
        enforce_retention(connection=env["conn"], export_dir=env["exports"],
                          confirm=True, analyst="Meca")
        assert not os.path.exists(os.path.join(env["exports"], "CASE-OLD_evidence_package.zip"))
        assert not os.path.exists(os.path.join(env["exports"], "CASE-OLD_referral_redacted.json"))

    def test_recent_case_survives_rows(self, env):
        enforce_retention(connection=env["conn"], export_dir=env["exports"], confirm=True)
        assert env["conn"].execute(
            "SELECT COUNT(*) FROM cases WHERE case_id='CASE-NEW'").fetchone()[0] == 1

    def test_recent_case_file_survives(self, env):
        enforce_retention(connection=env["conn"], export_dir=env["exports"], confirm=True)
        assert os.path.exists(os.path.join(env["exports"], "CASE-NEW_evidence_package.zip"))

    def test_purge_reports_counts(self, env):
        rep = enforce_retention(connection=env["conn"], export_dir=env["exports"], confirm=True)
        case = rep["cases"][0]
        assert case["purged"] is True
        assert case["rows_deleted"]["targets"] == 1
        assert case["rows_deleted"]["artifacts"] == 1
        assert case["rows_deleted"]["analyses"] == 1


class TestChainPreserved:
    def test_chain_entries_survive_purge(self, env):
        enforce_retention(connection=env["conn"], export_dir=env["exports"],
                          confirm=True, analyst="Meca")
        log = ChainOfCustodyLog(connection=env["conn"])
        actions = [e["action"] for e in log.entries("CASE-OLD")]
        assert "case_created" in actions
        assert "case_purged" in actions

    def test_chain_intact_after_purge(self, env):
        enforce_retention(connection=env["conn"], export_dir=env["exports"], confirm=True)
        log = ChainOfCustodyLog(connection=env["conn"])
        assert log.verify()["intact"] is True


class TestTimestampParsing:
    def test_iso_with_offset(self):
        dt = _parse_timestamp("2026-06-01T01:00:00+00:00")
        assert dt is not None and dt.tzinfo is not None

    def test_iso_without_offset_assumed_utc(self):
        dt = _parse_timestamp("2026-06-01T01:00:00")
        assert dt is not None and dt.tzinfo == timezone.utc

    def test_sqlite_default_form(self):
        dt = _parse_timestamp("2026-06-01 01:00:00")
        assert dt is not None

    def test_trailing_z(self):
        dt = _parse_timestamp("2026-06-01T01:00:00Z")
        assert dt is not None and dt.tzinfo is not None

    def test_unparseable_returns_none(self):
        assert _parse_timestamp("not a date") is None
        assert _parse_timestamp(None) is None

    def test_unparseable_case_kept(self, env):
        # A case with a garbage created_at must not be purged, erring toward
        # keeping data over deleting on a parse error.
        env["conn"].execute("INSERT INTO cases VALUES ('CASE-BAD','b','d','garbage','Meca','open')")
        env["conn"].commit()
        rep = enforce_retention(connection=env["conn"], export_dir=env["exports"], confirm=True)
        assert env["conn"].execute(
            "SELECT COUNT(*) FROM cases WHERE case_id='CASE-BAD'").fetchone()[0] == 1


class TestGuardsAndReport:
    def test_no_db_returns_not_ok(self):
        rep = enforce_retention()
        assert rep["ok"] is False

    def test_print_report_returns_zero_on_success(self, env):
        rep = enforce_retention(connection=env["conn"], export_dir=env["exports"])
        assert print_report(rep) == 0

    def test_print_report_returns_two_on_failure(self):
        assert print_report({"ok": False, "reason": "x"}) == 2

    def test_configurable_window(self, env):
        # With a 5 day window, the 10 day old recent case also becomes eligible.
        rep = enforce_retention(retention_days=5, connection=env["conn"],
                                export_dir=env["exports"])
        ids = {c["case_id"] for c in rep["cases"]}
        assert "CASE-NEW" in ids and "CASE-OLD" in ids


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))