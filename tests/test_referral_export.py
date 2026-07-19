"""
WhisperWard OSINT — Test suite for the Structured Referral Export
Phase 4, Milestone 5
Pixora Inc.

These tests lock in the referral export behavior. The guarantees are that the
referral carries the expected structure, that it is redacted by default and masks
reporter and protected information, that the unredacted internal view is only
produced on an explicit opt out and is named so a reader knows it is internal,
that suspect focused evidence and artifact hashes are preserved, that the
representative notice is always present, that a referral_exported entry is written
to the chain, and that a sealed package is referenced by its real hash when one
exists.
"""

import json
import os
import sqlite3
import zipfile

import pytest

from modules.child_safety.referral_export import export_referral, REFERRAL_FORMAT_VERSION
from core.case_log import ChainOfCustodyLog
from core.evidence_packager import create_evidence_package


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
            case_id TEXT, platform TEXT, username TEXT, platform_user_id TEXT, notes TEXT);
        CREATE TABLE artifacts (artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER, module_name TEXT, artifact_type TEXT,
            file_path TEXT, sha256 TEXT, collected_at TEXT);
        CREATE TABLE analysis_results (result_id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER, analysis_type TEXT, risk_score REAL,
            analyst_notes TEXT, analyzed_at TEXT);
        """
    )
    conn.execute("INSERT INTO cases VALUES ('CASE-X1','Burner',"
                 "'Concern: littlekid_victim contacted by suspect. Reporter "
                 "jane@gmail.com 201-555-0142.','2026-06-01T00:00:00+00:00','Meca','open')")
    conn.execute("INSERT INTO targets (case_id, platform, username, platform_user_id, notes) "
                 "VALUES ('CASE-X1','roblox','suspect_99','rblx_88812','protected: littlekid_victim')")
    conn.execute("INSERT INTO analysis_results (target_id, analysis_type, risk_score, "
                 "analyst_notes, analyzed_at) VALUES (1,'behavioral',8.5,'note','2026-06-01T01:00:00+00:00')")
    for mod, typ, h in [("roblox", "profile", "abc123"), ("sherlock", "username_match", "def456")]:
        conn.execute("INSERT INTO artifacts (target_id, module_name, artifact_type, sha256, "
                     "collected_at) VALUES (1,?,?,?,'2026-06-01T00:30:00+00:00')", (mod, typ, h))
    conn.commit()
    log = ChainOfCustodyLog(connection=conn)
    log.append(action="case_created", case_id="CASE-X1", analyst="Meca")
    conn.commit()
    return conn, exports


@pytest.fixture
def env(tmp_path):
    conn, exports = seed(str(tmp_path))
    yield {"dir": str(tmp_path), "conn": conn, "exports": exports}
    conn.close()


class TestStructure:
    def test_has_expected_sections(self, env):
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"])
        data = r["data"]
        for section in ["reporting", "incident", "subjects", "supporting_evidence",
                        "provenance", "representative_notice"]:
            assert section in data

    def test_format_version_present(self, env):
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"])
        assert r["data"]["format_version"] == REFERRAL_FORMAT_VERSION

    def test_representative_notice_present(self, env):
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"])
        assert "representative referral" in json.dumps(r["data"]).lower()

    def test_referral_id_format(self, env):
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"])
        assert r["referral_id"].startswith("REF-")


class TestRedactionDefault:
    def test_redacted_by_default(self, env):
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"])
        assert r["redacted"] is True

    def test_reporter_pii_masked(self, env):
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"])
        blob = json.dumps(r["data"])
        assert "jane@gmail.com" not in blob
        assert "201-555-0142" not in blob

    def test_protected_party_masked(self, env):
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"])
        assert "littlekid_victim" not in json.dumps(r["data"])

    def test_redacted_filename(self, env):
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"])
        assert "redacted" in os.path.basename(r["output_path"])


class TestInternalOptOut:
    def test_internal_keeps_pii(self, env):
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"],
                            redact=False)
        assert r["redacted"] is False
        assert "jane@gmail.com" in json.dumps(r["data"])

    def test_internal_filename(self, env):
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"],
                            redact=False)
        assert "internal" in os.path.basename(r["output_path"])

    def test_internal_view_warns_in_metadata(self, env):
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"],
                            redact=False)
        assert "internal" in r["data"]["redaction"]["note"].lower()


class TestEvidencePreserved:
    def test_suspect_username_preserved(self, env):
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"])
        assert "suspect_99" in json.dumps(r["data"])

    def test_artifact_hashes_preserved(self, env):
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"])
        blob = json.dumps(r["data"])
        assert "abc123" in blob and "def456" in blob

    def test_artifact_count_correct(self, env):
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"])
        assert r["data"]["supporting_evidence"]["artifact_count"] == 2

    def test_highest_risk_score_carried(self, env):
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"])
        assert r["data"]["incident"]["highest_risk_score"] == 8.5


class TestPackageReference:
    def test_references_package_when_present(self, env):
        create_evidence_package("CASE-X1", export_dir=env["exports"], connection=env["conn"])
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"])
        prov = r["data"]["provenance"]["sealed_evidence_package"]
        assert isinstance(prov, dict)
        assert prov["manifest_sha256"]

    def test_notes_absence_when_no_package(self, env):
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"])
        prov = r["data"]["provenance"]["sealed_evidence_package"]
        assert isinstance(prov, str)

    def test_zip_without_seal_handled(self, env):
        # A package ZIP that lacks a seal file must degrade to no reference rather
        # than crash or claim a hash it does not have.
        pkg = os.path.join(env["exports"], "CASE-X1_evidence_package.zip")
        with zipfile.ZipFile(pkg, "w") as archive:
            archive.writestr("CASE-X1_manifest.json", "{}")  # manifest but no seal
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"])
        prov = r["data"]["provenance"]["sealed_evidence_package"]
        assert isinstance(prov, str)

    def test_malformed_seal_handled(self, env):
        pkg = os.path.join(env["exports"], "CASE-X1_evidence_package.zip")
        with zipfile.ZipFile(pkg, "w") as archive:
            archive.writestr("CASE-X1_manifest.seal.json", "not valid json {{{")
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"])
        prov = r["data"]["provenance"]["sealed_evidence_package"]
        assert isinstance(prov, str)


class TestChainAndGuards:
    def test_referral_logged_to_chain(self, env):
        export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"], analyst="Meca")
        log = ChainOfCustodyLog(connection=env["conn"])
        assert "referral_exported" in [e["action"] for e in log.entries("CASE-X1")]

    def test_chain_intact_after_export(self, env):
        export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"])
        log = ChainOfCustodyLog(connection=env["conn"])
        assert log.verify()["intact"] is True

    def test_no_db_declines(self):
        assert export_referral("CASE-X1") is None

    def test_no_file_when_write_disabled(self, env):
        r = export_referral("CASE-X1", connection=env["conn"], output_dir=env["exports"],
                            write_file=False)
        assert r["output_path"] is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))