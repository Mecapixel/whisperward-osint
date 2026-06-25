"""
WhisperWard OSINT — Test suite for the Redaction Engine
Phase 4, Milestone 5
Pixora Inc.

These tests lock in the redaction behavior. The guarantees are that structurally
identifiable PII is masked, that analyst tagged protected values are masked
wherever they appear, that suspect focused evidence is preserved, that the policy
selection changes the protected placeholder, that a redaction_applied entry is
written to the chain, that the derived export is a separate file and the source is
untouched, and that the IPv6 detector does not false match clock or timestamp
strings.

The timestamp regression test exists because an earlier IPv6 pattern matched the
HH:MM:SS portion of timestamps, which would have corrupted every timestamp in an
export and inflated redaction counts. That must never return.
"""

import json
import os
import sqlite3
import tempfile

import pytest

from modules.redaction_engine import (redact_case, _IPV6_RE, _IPV4_RE,
                                       _EMAIL_RE, _PHONE_RE, _SSN_RE,
                                       PII_PLACEHOLDER, MINOR_PLACEHOLDER)
from modules.case_log import ChainOfCustodyLog


def seed(directory, target_notes=None):
    db = os.path.join(directory, "w.db")
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE cases (case_id TEXT PRIMARY KEY, case_name TEXT,
            description TEXT, created_at TEXT, analyst_name TEXT, status TEXT);
        CREATE TABLE targets (target_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT, platform TEXT, username TEXT, notes TEXT);
        CREATE TABLE artifacts (artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER, module_name TEXT, artifact_type TEXT,
            file_path TEXT, sha256 TEXT, collected_at TEXT);
        CREATE TABLE analysis_results (result_id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER, analysis_type TEXT, risk_score REAL,
            analyst_notes TEXT, analyzed_at TEXT);
        """
    )
    conn.execute("INSERT INTO cases VALUES ('CASE-R1','Test',"
                 "'Reporter: jane.doe@gmail.com or 201-555-0142',"
                 "'2026-06-01T00:00:00+00:00','Meca','open')")
    notes = target_notes if target_notes is not None else (
        "protected: littlekid_victim\n"
        "Suspect contacted victim from 192.168.5.44 at 2026-06-01T01:00:00+00:00")
    conn.execute("INSERT INTO targets (case_id, platform, username, notes) "
                 "VALUES ('CASE-R1','roblox','suspect_predator99',?)", (notes,))
    conn.execute("INSERT INTO analysis_results (target_id, analysis_type, risk_score, "
                 "analyst_notes, analyzed_at) VALUES (1,'behavioral',8.5,"
                 "'Suspect messaged littlekid_victim. Victim email child@school.edu.',"
                 "'2026-06-01T01:00:00+00:00')")
    conn.commit()
    log = ChainOfCustodyLog(connection=conn)
    log.append(action="case_created", case_id="CASE-R1", analyst="Meca")
    conn.commit()
    return conn


@pytest.fixture
def env(tmp_path):
    conn = seed(str(tmp_path))
    yield {"dir": str(tmp_path), "conn": conn}
    conn.close()


class TestPatternMasking:
    def test_emails_masked(self, env):
        r = redact_case("CASE-R1", connection=env["conn"], output_dir=env["dir"])
        blob = json.dumps(r["data"])
        assert "jane.doe@gmail.com" not in blob
        assert "child@school.edu" not in blob
        assert r["counts"]["email"] == 2

    def test_phone_masked(self, env):
        r = redact_case("CASE-R1", connection=env["conn"], output_dir=env["dir"])
        assert "201-555-0142" not in json.dumps(r["data"])
        assert r["counts"]["phone"] == 1

    def test_ip_masked(self, env):
        r = redact_case("CASE-R1", connection=env["conn"], output_dir=env["dir"])
        assert "192.168.5.44" not in json.dumps(r["data"])
        assert r["counts"]["ip"] == 1

    def test_timestamp_not_false_matched(self, env):
        # Regression: the timestamp HH:MM:SS must survive intact and must not be
        # counted as an IP. This guards against the old IPv6 over-match.
        r = redact_case("CASE-R1", connection=env["conn"], output_dir=env["dir"])
        assert "2026-06-01T01:00:00" in json.dumps(r["data"])
        assert r["counts"]["ip"] == 1


class TestProtectedTags:
    def test_protected_handle_masked_everywhere(self, env):
        r = redact_case("CASE-R1", connection=env["conn"], output_dir=env["dir"])
        assert "littlekid_victim" not in json.dumps(r["data"])
        # appears in both target notes and analyst notes, so at least two hits
        assert r["counts"]["protected"] >= 2

    def test_no_protected_tag_means_no_protected_redactions(self, tmp_path):
        conn = seed(str(tmp_path), target_notes="No tags here, just plain notes.")
        r = redact_case("CASE-R1", connection=conn, output_dir=str(tmp_path))
        assert r["counts"]["protected"] == 0
        conn.close()


class TestEvidencePreserved:
    def test_suspect_username_preserved(self, env):
        r = redact_case("CASE-R1", connection=env["conn"], output_dir=env["dir"])
        assert "suspect_predator99" in json.dumps(r["data"])

    def test_risk_score_preserved(self, env):
        r = redact_case("CASE-R1", connection=env["conn"], output_dir=env["dir"])
        assert "8.5" in json.dumps(r["data"])


class TestPolicies:
    def test_minor_policy_uses_minor_placeholder(self, env):
        r = redact_case("CASE-R1", connection=env["conn"], output_dir=env["dir"],
                        policy="minor_involved")
        assert MINOR_PLACEHOLDER in json.dumps(r["data"])

    def test_standard_policy_uses_pii_placeholder(self, env):
        r = redact_case("CASE-R1", connection=env["conn"], output_dir=env["dir"],
                        policy="standard")
        assert PII_PLACEHOLDER in json.dumps(r["data"])

    def test_unknown_policy_declines(self, env):
        assert redact_case("CASE-R1", connection=env["conn"], policy="nonsense") is None


class TestChainAndOutput:
    def test_redaction_logged_to_chain(self, env):
        redact_case("CASE-R1", connection=env["conn"], output_dir=env["dir"], analyst="Meca")
        log = ChainOfCustodyLog(connection=env["conn"])
        assert "redaction_applied" in [e["action"] for e in log.entries("CASE-R1")]

    def test_chain_intact_after_redaction(self, env):
        redact_case("CASE-R1", connection=env["conn"], output_dir=env["dir"])
        log = ChainOfCustodyLog(connection=env["conn"])
        assert log.verify()["intact"] is True

    def test_output_file_written(self, env):
        r = redact_case("CASE-R1", connection=env["conn"], output_dir=env["dir"])
        assert os.path.exists(r["output_path"])
        with open(r["output_path"], encoding="utf-8") as handle:
            data = json.load(handle)
        assert "redaction" in data

    def test_no_file_when_write_disabled(self, env):
        r = redact_case("CASE-R1", connection=env["conn"], output_dir=env["dir"],
                        write_file=False)
        assert r["output_path"] is None

    def test_redaction_metadata_present(self, env):
        r = redact_case("CASE-R1", connection=env["conn"], output_dir=env["dir"],
                        analyst="Meca", reason="ncmec_referral")
        meta = r["data"]["redaction"]
        assert meta["reason"] == "ncmec_referral"
        assert meta["analyst"] == "Meca"
        assert meta["total_redactions"] == r["total_redactions"]

    def test_no_db_declines(self):
        assert redact_case("CASE-R1") is None


class TestRegexUnit:
    def test_ipv6_matches_real_addresses(self):
        for addr in ["2001:db8::1", "fe80::a00:27ff:fe4e:66a1",
                     "2001:0db8:0000:0000:0000:ff00:0042:8329"]:
            assert _IPV6_RE.findall(addr), addr

    def test_ipv6_ignores_time_strings(self):
        for s in ["01:00:00", "12:34:56", "2026-06-01T01:00:00+00:00", "1:2:3"]:
            assert not _IPV6_RE.findall(s), s

    def test_ssn_pattern(self):
        assert _SSN_RE.findall("123-45-6789")
        assert not _SSN_RE.findall("12-345-6789")

    def test_email_pattern(self):
        assert _EMAIL_RE.findall("a.b@example.co.uk")
        assert not _EMAIL_RE.findall("not an email")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))