"""
Platform Phase 4 — CLI surfacing for STIX export and ATT&CK mapping.

All data is synthetic. The contract under test: the stix command writes a
byte-stable bundle and seals the export into the evidence store; the
attack-map command maps only fired signals from a real stored analysis and
always states its scope; both refuse cleanly when the record is empty.
"""

import json

import pytest
from typer.testing import CliRunner

from database.db_manager import DatabaseManager
from whisperward import app

runner = CliRunner()


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    database = DatabaseManager(db_path=str(tmp_path / "phase4_test.db"))
    database.init()
    import whisperward
    monkeypatch.setattr(whisperward, "db", database)
    return database


def _seed_case(database):
    case_id = database.create_case("SYNTHETIC phase4", "synthetic", "pytest")
    database.add_target(case_id, "roblox", "synthetic_shadowfox")
    database.add_target(case_id, "discord", "synthetic_shadow_fox")
    targets = database.get_case_targets(case_id)
    a = "roblox:synthetic_shadowfox"
    b = "discord:synthetic_shadow_fox"
    database.save_artifact(
        target_id=targets[0]["target_id"],
        module_name="CorrelationEngine",
        artifact_type="identity_correlation",
        raw_data={"case_id": case_id, "pairwise": [{
            "profile_a": a, "profile_b": b,
            "correlation_strength": 0.85, "is_lead": True,
            "contradiction_note": "", "rationale": ["near-identical handles"],
            "signals": [],
        }], "cluster": {"groups": [[a, b]]}},
    )
    return case_id, targets


class TestStixCommand:
    def test_exports_and_seals(self, test_db, tmp_path):
        case_id, _ = _seed_case(test_db)
        out = tmp_path / "bundle.json"
        result = runner.invoke(app, ["stix", "--case", case_id,
                                     "--out", str(out)])
        assert result.exit_code == 0
        flattened = " ".join(result.output.split())
        assert "STIX 2.1 bundle" in flattened
        assert "sealed as artifact" in flattened

        body = json.loads(out.read_text())
        types = {o["type"] for o in body["objects"]}
        assert "user-account" in types and "grouping" in types
        assert types.isdisjoint({"threat-actor", "malware", "indicator"})

        row = test_db.get_connection().execute(
            "SELECT raw_data FROM artifacts WHERE artifact_type = "
            "'stix_bundle' ORDER BY artifact_id DESC LIMIT 1").fetchone()
        assert row is not None
        assert json.loads(row["raw_data"])["object_count"] == len(body["objects"])

    def test_refuses_empty_case(self, test_db):
        case_id = test_db.create_case("SYNTHETIC empty", "synthetic", "pytest")
        result = runner.invoke(app, ["stix", "--case", case_id])
        assert result.exit_code == 0
        assert "no targets" in result.output.lower()


class TestAttackMapCommand:
    def test_requires_structured_analysis(self, test_db):
        case_id, _ = _seed_case(test_db)
        result = runner.invoke(app, ["attack-map", "--case", case_id])
        assert result.exit_code == 0
        assert "No structured risk analysis" in result.output

    def test_maps_real_stored_analysis(self, test_db):
        from core.risk_scoring import score_target
        case_id, targets = _seed_case(test_db)
        target_id = targets[0]["target_id"]
        test_db.save_analysis(target_id, score_target(
            test_db.get_connection(), target_id))
        result = runner.invoke(app, ["attack-map", "--case", case_id])
        assert result.exit_code == 0
        flattened = " ".join(result.output.split())
        assert "technical observations only" in flattened
