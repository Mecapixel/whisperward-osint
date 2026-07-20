"""
Platform Phase 3, Milestone 5 — CLI and API surfacing.

All data is synthetic. The contract under test: the entity workflow runs
propose → analyst promote → list, entirely from sealed evidence; the graph and
timeline commands and routes report only what the record holds; and promotion
without correlation or without proposals refuses cleanly instead of inventing
state.
"""

import json

import pytest
from typer.testing import CliRunner

from database.db_manager import DatabaseManager
from whisperward import app

runner = CliRunner()


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    database = DatabaseManager(db_path=str(tmp_path / "phase3_test.db"))
    database.init()
    import whisperward
    monkeypatch.setattr(whisperward, "db", database)
    return database


def _seed_correlated_case(database):
    """A case with two synthetic Roblox targets whose sealed correlation
    artifact links them at lead strength with no contradiction."""
    case_id = database.create_case("SYNTHETIC phase3 test", "synthetic", "pytest")
    for username in ("synthetic_xX_shadow_Xx", "synthetic_xX_shad0w_Xx"):
        database.add_target(case_id, "roblox", username)
    targets = database.get_case_targets(case_id)
    a = "roblox:synthetic_xX_shadow_Xx"
    b = "roblox:synthetic_xX_shad0w_Xx"
    payload = {
        "case_id": case_id,
        "pairwise": [{
            "profile_a": a, "profile_b": b,
            "correlation_strength": 0.86, "is_lead": True,
            "contradiction_note": "",
            "scored_at": "2026-07-20T00:00:00+00:00",
            "rationale": ["near-identical handles"],
            "signals": [{"name": "username", "raw_score": 0.9,
                         "confidence": 0.9, "rationale": "handle similarity"}],
        }],
        "cluster": {"groups": [[a, b]]},
        "semantic_enabled": False,
    }
    database.save_artifact(
        target_id=targets[0]["target_id"],
        module_name="CorrelationEngine",
        artifact_type="identity_correlation",
        raw_data=payload,
    )
    return case_id, targets


def _candidate_id_from_store(database, case_id):
    conn = database.get_connection()
    row = conn.execute(
        "SELECT raw_data FROM artifacts WHERE artifact_type = 'entity_candidates' "
        "ORDER BY artifact_id DESC LIMIT 1").fetchone()
    payload = json.loads(row["raw_data"])
    return payload["candidates"][0]["candidate_id"]


class TestEntityWorkflow:
    def test_propose_requires_sealed_correlation(self, test_db):
        case_id = test_db.create_case("SYNTHETIC empty", "synthetic", "pytest")
        result = runner.invoke(app, ["propose-entities", "--case", case_id])
        assert result.exit_code == 0
        assert "No sealed correlation" in result.output

    def test_propose_seals_candidates(self, test_db):
        case_id, _ = _seed_correlated_case(test_db)
        result = runner.invoke(app, ["propose-entities", "--case", case_id])
        assert result.exit_code == 0
        assert "Candidate ENT-CAND-" in result.output
        assert "Proposals sealed as artifact" in result.output
        assert "explicit analyst decision" in result.output

    def test_promote_requires_proposals(self, test_db):
        case_id, _ = _seed_correlated_case(test_db)
        result = runner.invoke(app, [
            "promote-entity", "--case", case_id,
            "--candidate", "ENT-CAND-MISSING", "--analyst", "M. Dismukes"])
        assert result.exit_code == 0
        assert "No sealed entity proposals" in result.output

    def test_promote_records_analyst_decision(self, test_db):
        case_id, _ = _seed_correlated_case(test_db)
        runner.invoke(app, ["propose-entities", "--case", case_id])
        candidate_id = _candidate_id_from_store(test_db, case_id)
        result = runner.invoke(app, [
            "promote-entity", "--case", case_id,
            "--candidate", candidate_id, "--analyst", "M. Dismukes",
            "--note", "synthetic promotion for tests"])
        assert result.exit_code == 0
        assert "resolved by M. Dismukes" in result.output

        stored = test_db.get_case_entities(case_id)
        assert len(stored) == 1
        assert stored[0]["entity"]["promoted_by"] == "M. Dismukes"
        assert len(stored[0]["members"]) == 2

        # The promotion must land in the custody chain.
        row = test_db.get_connection().execute(
            "SELECT notes FROM evidence_log WHERE action = 'entity_promoted' "
            "ORDER BY log_id DESC LIMIT 1").fetchone()
        assert row is not None and "resolved over accounts" in row["notes"]

    def test_entities_lists_promotion(self, test_db):
        case_id, _ = _seed_correlated_case(test_db)
        runner.invoke(app, ["propose-entities", "--case", case_id])
        candidate_id = _candidate_id_from_store(test_db, case_id)
        runner.invoke(app, [
            "promote-entity", "--case", case_id,
            "--candidate", candidate_id, "--analyst", "M. Dismukes"])
        result = runner.invoke(app, ["entities", "--case", case_id])
        assert result.exit_code == 0
        assert "promoted by M. Dismukes" in result.output


class TestGraphAndTimelineCommands:
    def test_identity_graph_reports_corroboration(self, test_db):
        case_id, _ = _seed_correlated_case(test_db)
        result = runner.invoke(app, ["identity-graph", "--case", case_id])
        assert result.exit_code == 0
        assert "nodes: 2" in result.output
        assert "contradiction-free lead edges: 1" in result.output
        flattened = " ".join(result.output.split())
        assert "not assertions of shared identity" in flattened

    def test_identity_graph_requires_sealed_correlation(self, test_db):
        case_id = test_db.create_case("SYNTHETIC empty", "synthetic", "pytest")
        result = runner.invoke(app, ["identity-graph", "--case", case_id])
        assert result.exit_code == 0
        assert "No sealed correlation" in result.output

    def test_timeline_reconstructs_case_record(self, test_db):
        case_id, _ = _seed_correlated_case(test_db)
        result = runner.invoke(app, ["timeline", "--case", case_id])
        assert result.exit_code == 0
        assert "case_opened" in result.output
        assert "target_added" in result.output
        assert "reconstructed from the case" in result.output.lower()


class TestPhase3ApiRoutes:
    @pytest.fixture
    def client(self, test_db, monkeypatch):
        import sqlite3
        from fastapi.testclient import TestClient
        import webapp.api_routes as api_routes
        # TestClient serves requests off the main thread; the routes get their
        # own connection to the same on-disk test database with the same-thread
        # check disabled, mirroring how a served deployment holds its own
        # connection separate from the CLI's.
        route_db = DatabaseManager(db_path=test_db.db_path)
        route_db.conn = sqlite3.connect(test_db.db_path, check_same_thread=False)
        route_db.conn.row_factory = sqlite3.Row
        monkeypatch.setattr(api_routes, "_db", route_db)
        from fastapi import FastAPI
        application = FastAPI()
        application.include_router(api_routes.router)
        return TestClient(application)

    def test_entities_route_empty_case(self, client, test_db):
        case_id = test_db.create_case("SYNTHETIC empty", "synthetic", "pytest")
        body = client.get(f"/api/case/{case_id}/entities").json()
        assert body["count"] == 0 and body["entities"] == []

    def test_identity_graph_route_without_correlation(self, client, test_db):
        case_id = test_db.create_case("SYNTHETIC empty", "synthetic", "pytest")
        body = client.get(f"/api/case/{case_id}/identity-graph").json()
        assert body["found"] is False

    def test_identity_graph_route_with_correlation(self, client, test_db):
        case_id, _ = _seed_correlated_case(test_db)
        body = client.get(f"/api/case/{case_id}/identity-graph").json()
        assert body["found"] is True
        assert body["node_count"] == 2 and body["edge_count"] == 1
        assert body["edges"][0]["justification"]["is_lead"] is True
        assert body["risk_inputs"]["graph_lead_edge_count"] == 1

    def test_timeline_route_names_sources(self, client, test_db):
        case_id, _ = _seed_correlated_case(test_db)
        body = client.get(f"/api/case/{case_id}/investigation-timeline").json()
        assert body["event_count"] >= 3
        assert all(e["source_table"] for e in body["events"])

    def test_entities_route_after_promotion(self, client, test_db):
        case_id, _ = _seed_correlated_case(test_db)
        runner.invoke(app, ["propose-entities", "--case", case_id])
        candidate_id = _candidate_id_from_store(test_db, case_id)
        runner.invoke(app, [
            "promote-entity", "--case", case_id,
            "--candidate", candidate_id, "--analyst", "M. Dismukes"])
        body = client.get(f"/api/case/{case_id}/entities").json()
        assert body["count"] == 1
        member = body["entities"][0]["members"][0]
        assert member["justification"]["supporting_edges"]
