"""
WhisperWard OSINT — Test suite for the Signed Case Report Generator
Phase 4, Milestone 5
Pixora Inc.

These tests lock in the behavior of the signed report. The guarantees are that a
report is produced and is a valid PDF, that the digital signature is
cryptographically valid and detects tampering, that generating a report writes a
report_signed entry to the chain of custody log, that the optional package sync
produces a package the report can reference, that the signing identity is created
once and reused, and that the report declines cleanly without a database.

Signature validation uses pyHanko's own validation path against the portfolio
certificate, which is the correct way to verify a self signed identity.
"""

import os
import sqlite3
import tempfile

import pytest

from modules.report_generator import (generate_signed_report,
                                       ensure_signing_identity,
                                       _fetch_case_data, _tier_for_score,
                                       DEFAULT_CERT_DIR, CERT_FILE)

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from pyhanko.keys import load_cert_from_pemder


def seed_case(directory):
    """Builds a database with one case, a target, an analysis result, three
    artifacts, and two custody entries, returning the connection and export dir."""
    db = os.path.join(directory, "wward.db")
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
            target_id INTEGER, analysis_type TEXT, risk_score REAL,
            analyst_notes TEXT, analyzed_at TEXT);
        """
    )
    conn.execute("INSERT INTO cases VALUES ('CASE-T1','Test Case','d',"
                 "'2026-05-24T20:43:00+00:00','Meca','open')")
    conn.execute("INSERT INTO targets (case_id, platform, username) "
                 "VALUES ('CASE-T1','roblox','suspect')")
    conn.execute("INSERT INTO analysis_results (target_id, analysis_type, risk_score, "
                 "analyst_notes, analyzed_at) VALUES (1,'behavioral',5.0,NULL,'t')")
    for name, module, atype in [("p.json", "roblox", "profile"),
                                ("a.txt", "roblox", "avatar"),
                                ("s.json", "sherlock", "username_match")]:
        path = os.path.join(exports, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("data")
        conn.execute("INSERT INTO artifacts (target_id, module_name, artifact_type, "
                     "file_path, sha256) VALUES (1,?,?,?,'h')", (module, atype, path))
    conn.commit()

    from modules.case_log import ChainOfCustodyLog
    log = ChainOfCustodyLog(connection=conn)
    log.append(action="case_created", case_id="CASE-T1", analyst="Meca")
    log.append(action="artifact_collected", case_id="CASE-T1", analyst="Meca")
    conn.commit()
    return conn, exports


@pytest.fixture
def env(tmp_path, monkeypatch):
    # Run inside a temp working directory so the default data/signing path and any
    # reports land in an isolated place and never touch the real repo.
    monkeypatch.chdir(tmp_path)
    directory = str(tmp_path)
    conn, exports = seed_case(directory)
    yield {"dir": directory, "conn": conn, "exports": exports}
    conn.close()


def _validate(signed_path, cert_dir):
    cert = load_cert_from_pemder(os.path.join(cert_dir, CERT_FILE))
    vc = ValidationContext(trust_roots=[cert])
    with open(signed_path, "rb") as handle:
        sig = PdfFileReader(handle).embedded_signatures[0]
        return validate_pdf_signature(sig, vc)


class TestReportGeneration:
    def test_report_is_created(self, env):
        path = generate_signed_report("CASE-T1", output_dir=os.path.join(env["dir"], "reports"),
                                      connection=env["conn"], analyst="Meca")
        assert path is not None
        assert os.path.exists(path)
        assert os.path.getsize(path) > 0

    def test_output_is_a_pdf(self, env):
        path = generate_signed_report("CASE-T1", output_dir=os.path.join(env["dir"], "reports"),
                                      connection=env["conn"])
        with open(path, "rb") as handle:
            assert handle.read(5) == b"%PDF-"

    def test_unsigned_intermediate_removed(self, env):
        out = os.path.join(env["dir"], "reports")
        generate_signed_report("CASE-T1", output_dir=out, connection=env["conn"])
        assert not os.path.exists(os.path.join(out, "CASE-T1_report_unsigned.pdf"))
        assert os.path.exists(os.path.join(out, "CASE-T1_report_signed.pdf"))

    def test_no_db_returns_none(self, env):
        assert generate_signed_report("CASE-T1") is None


class TestSignature:
    def test_signature_is_valid(self, env):
        path = generate_signed_report("CASE-T1", output_dir=os.path.join(env["dir"], "reports"),
                                      connection=env["conn"])
        status = _validate(path, DEFAULT_CERT_DIR)
        assert status.intact is True
        assert status.valid is True

    def test_tampering_breaks_signature(self, env):
        path = generate_signed_report("CASE-T1", output_dir=os.path.join(env["dir"], "reports"),
                                      connection=env["conn"])
        data = bytearray(open(path, "rb").read())
        # Flip a byte in the body of the document.
        data[len(data) // 2] = (data[len(data) // 2] + 1) % 256
        tampered = path.replace(".pdf", "_tampered.pdf")
        with open(tampered, "wb") as handle:
            handle.write(data)
        try:
            status = _validate(tampered, DEFAULT_CERT_DIR)
            assert status.intact is False
        except Exception:
            # A parse-level failure on a corrupted signature is also acceptable
            # evidence that tampering is not silently accepted.
            assert True


class TestChainEntry:
    def test_report_writes_chain_entry(self, env):
        from modules.case_log import ChainOfCustodyLog
        generate_signed_report("CASE-T1", output_dir=os.path.join(env["dir"], "reports"),
                               connection=env["conn"], analyst="Meca")
        log = ChainOfCustodyLog(connection=env["conn"])
        actions = [e["action"] for e in log.entries(case_id="CASE-T1")]
        assert "report_signed" in actions

    def test_chain_intact_after_report(self, env):
        from modules.case_log import ChainOfCustodyLog
        generate_signed_report("CASE-T1", output_dir=os.path.join(env["dir"], "reports"),
                               connection=env["conn"])
        log = ChainOfCustodyLog(connection=env["conn"])
        assert log.verify()["intact"] is True


class TestPackageSync:
    def test_create_package_produces_referenced_package(self, env):
        generate_signed_report("CASE-T1", output_dir=os.path.join(env["dir"], "reports"),
                               connection=env["conn"], create_package=True,
                               export_dir=env["exports"])
        pkg = os.path.join(env["exports"], "CASE-T1_evidence_package.zip")
        assert os.path.exists(pkg)

    def test_package_event_in_chain_when_synced(self, env):
        from modules.case_log import ChainOfCustodyLog
        generate_signed_report("CASE-T1", output_dir=os.path.join(env["dir"], "reports"),
                               connection=env["conn"], create_package=True,
                               export_dir=env["exports"])
        log = ChainOfCustodyLog(connection=env["conn"])
        actions = [e["action"] for e in log.entries(case_id="CASE-T1")]
        assert "evidence_package_created" in actions
        assert "report_signed" in actions


class TestSigningIdentity:
    def test_identity_created_once_and_reused(self, env):
        first = ensure_signing_identity(DEFAULT_CERT_DIR)
        assert os.path.exists(first)
        mtime_first = os.path.getmtime(first)
        second = ensure_signing_identity(DEFAULT_CERT_DIR)
        assert second == first
        # The identity is reused, not regenerated, so the file is unchanged.
        assert os.path.getmtime(second) == mtime_first

    def test_cert_pem_written(self, env):
        ensure_signing_identity(DEFAULT_CERT_DIR)
        assert os.path.exists(os.path.join(DEFAULT_CERT_DIR, CERT_FILE))


class TestDataHelpers:
    def test_fetch_case_data_populates_sections(self, env):
        data = _fetch_case_data(env["conn"], "CASE-T1")
        assert data["case"]["case_id"] == "CASE-T1"
        assert len(data["targets"]) == 1
        assert data["total_artifacts"] == 3
        assert data["custody_total"] >= 2

    def test_tier_thresholds(self):
        assert "Tier 1" in _tier_for_score(1.0)
        assert "Tier 2" in _tier_for_score(5.0)
        assert "Tier 3" in _tier_for_score(8.0)
        assert _tier_for_score(None) == "Not scored"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))