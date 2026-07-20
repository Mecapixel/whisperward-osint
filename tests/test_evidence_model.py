"""
tests/test_evidence_model.py
WhisperWard — Phase 2 Milestone 1 tests

Covers the EvidenceRecord contract (mandatory identity, digest, timestamp,
source, collector), deterministic identity for stored artifacts, and the
chain-of-custody manifest: per-artifact evidence records, custody events,
and hash-chain verification status embedded in the manifest itself.
"""

import json
import sqlite3
import zipfile
from pathlib import Path

import pytest

from core.case_log import ChainOfCustodyLog
from core.evidence import EvidenceRecord, build_custody_manifest
from core.evidence_packager import create_evidence_package

VALID_SHA = "a" * 64


def _make_case_db(tmp_path) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    schema = Path("database/schema.sql").read_text()
    conn.executescript(schema)
    conn.execute(
        "INSERT INTO cases (case_id, case_name, status) VALUES (?, ?, ?)",
        ("CASE-TEST01", "Evidence model test", "open"),
    )
    conn.execute(
        "INSERT INTO targets (case_id, platform, username) VALUES (?, ?, ?)",
        ("CASE-TEST01", "roblox", "synthetic_user"),
    )
    target_id = conn.execute("SELECT target_id FROM targets").fetchone()[0]
    conn.execute(
        "INSERT INTO artifacts (target_id, module_name, artifact_type, sha256)"
        " VALUES (?, ?, ?, ?)",
        (target_id, "roblox_osint", "profile", VALID_SHA),
    )
    artifact_id = conn.execute("SELECT artifact_id FROM artifacts").fetchone()[0]
    conn.execute(
        "INSERT INTO evidence_log (action, artifact_id, target_id, analyst, sha256)"
        " VALUES (?, ?, ?, ?, ?)",
        ("collected", artifact_id, target_id, "test_analyst", VALID_SHA),
    )
    conn.commit()
    return conn


class TestEvidenceRecordContract:
    def test_minimal_record_carries_full_contract(self):
        rec = EvidenceRecord(sha256=VALID_SHA, source="roblox_osint", collector="roblox_osint")
        d = rec.to_dict()
        for key in ("evidence_id", "sha256", "collected_at", "source", "collector"):
            assert d[key], f"contract field {key} must be present and non-empty"

    def test_rejects_missing_sha256(self):
        with pytest.raises(ValueError):
            EvidenceRecord(sha256="", source="s", collector="c")

    def test_rejects_malformed_sha256(self):
        with pytest.raises(ValueError):
            EvidenceRecord(sha256="not-a-digest", source="s", collector="c")

    def test_rejects_missing_source_and_collector(self):
        with pytest.raises(ValueError):
            EvidenceRecord(sha256=VALID_SHA, source="", collector="c")
        with pytest.raises(ValueError):
            EvidenceRecord(sha256=VALID_SHA, source="s", collector="")

    def test_from_artifact_row_identity_is_deterministic(self):
        row = {
            "artifact_id": 7,
            "target_id": 1,
            "module_name": "roblox_osint",
            "artifact_type": "profile",
            "sha256": VALID_SHA,
            "collected_at": "2026-07-19T00:00:00+00:00",
        }
        a = EvidenceRecord.from_artifact_row(row, case_id="CASE-X")
        b = EvidenceRecord.from_artifact_row(row, case_id="CASE-X")
        assert a.evidence_id == b.evidence_id
        assert a.artifact_id == 7 and a.case_id == "CASE-X"


class TestCustodyManifest:
    def test_manifest_contains_artifact_and_custody_events(self, tmp_path):
        conn = _make_case_db(tmp_path)
        manifest = build_custody_manifest("CASE-TEST01", conn)
        assert manifest["case_id"] == "CASE-TEST01"
        assert manifest["artifact_count"] == 1
        entry = manifest["artifacts"][0]
        assert entry["evidence"]["sha256"] == VALID_SHA
        assert entry["evidence"]["source"] == "roblox_osint"
        actions = [e["action"] for e in entry["custody_events"]]
        assert "collected" in actions

    def test_manifest_reports_hash_chain_verification(self, tmp_path):
        conn = _make_case_db(tmp_path)
        log = ChainOfCustodyLog(connection=conn)
        log.append("case_opened", case_id="CASE-TEST01", analyst="test_analyst")
        manifest = build_custody_manifest("CASE-TEST01", conn)
        status = manifest["hash_chain_verification"]
        assert status["available"] is True

    def test_evidence_package_includes_custody_manifest(self, tmp_path):
        db_path = tmp_path / "case.db"
        conn = sqlite3.connect(db_path)
        schema = Path("database/schema.sql").read_text()
        conn.executescript(schema)
        conn.execute(
            "INSERT INTO cases (case_id, case_name, status) VALUES (?, ?, ?)",
            ("CASE-TEST02", "Package test", "open"),
        )
        conn.execute(
            "INSERT INTO targets (case_id, platform, username) VALUES (?, ?, ?)",
            ("CASE-TEST02", "roblox", "synthetic_user"),
        )
        target_id = conn.execute("SELECT target_id FROM targets").fetchone()[0]
        conn.execute(
            "INSERT INTO artifacts (target_id, module_name, artifact_type, sha256)"
            " VALUES (?, ?, ?, ?)",
            (target_id, "roblox_osint", "profile", VALID_SHA),
        )
        conn.commit()
        conn.close()

        package = create_evidence_package(
            "CASE-TEST02", export_dir=str(tmp_path), db_path=str(db_path),
            analyst="test_analyst",
        )
        assert package is not None
        with zipfile.ZipFile(package) as z:
            names = z.namelist()
            custody_name = "CASE-TEST02_custody_manifest.json"
            assert custody_name in names
            custody = json.loads(z.read(custody_name))
            assert custody["manifest_type"] == "chain_of_custody"
            assert custody["artifact_count"] == 1
            package_manifest = json.loads(z.read("CASE-TEST02_manifest.json"))
            assert custody_name in package_manifest["sha256_manifest"]
