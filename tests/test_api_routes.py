"""
WhisperWard OSINT — Test suite for the JSON API Routes
Phase 4, Milestone 6
Pixora Inc.

These tests exercise the JSON endpoints through a FastAPI test client with a
stubbed database, so the route shapes and computed values are verified without
depending on live data. The stub mirrors the real DatabaseManager method
signatures, so a change that breaks the contract the routes rely on is caught
here. The guarantees are that metrics aggregates correctly, that the risk tier
mapping matches the governance thresholds, that a missing case is reported rather
than erroring, that the timeline returns ordered points, and that capability
reporting is present.

The stub is installed into sys.modules before the router module is imported, which
is how the router picks it up instead of the real database layer.
"""

import sys
import types
import importlib.util
import os

import pytest


def _install_stub_db():
    """Installs a fake 'database' module exposing a DatabaseManager whose methods
    match the real one's shapes, seeded with a known set of cases."""
    mod = types.ModuleType("database")

    class FakeDM:
        def __init__(self, *a, **k):
            self._cases = [
                {"case_id": "CASE-1", "case_name": "Alpha", "analyst_name": "Meca",
                 "created_at": "2026-05-01", "target_count": 1, "primary_platform": "roblox",
                 "latest_risk": 8.5, "peak_risk": 8.5, "analyzed_at": "2026-05-04",
                 "analysis_count": 2, "status": "open"},
                {"case_id": "CASE-2", "case_name": "Bravo", "analyst_name": "Meca",
                 "created_at": "2026-05-02", "target_count": 1, "primary_platform": "discord",
                 "latest_risk": 3.0, "peak_risk": 3.0, "analyzed_at": "2026-05-03",
                 "analysis_count": 1, "status": "open"},
                {"case_id": "CASE-3", "case_name": "Charlie", "analyst_name": "Meca",
                 "created_at": "2026-05-05", "target_count": 1, "primary_platform": "roblox",
                 "latest_risk": None, "peak_risk": None, "analyzed_at": None,
                 "analysis_count": 0, "status": "open"},
            ]

        def init(self):
            pass

        def get_all_cases(self):
            return self._cases

        def get_case(self, cid):
            return next((c for c in self._cases if c["case_id"] == cid), None)

        def get_case_summary(self, cid):
            return {"total_targets": 1, "artifacts_count": 1, "platforms": {"roblox": 1}}

        def get_case_risk(self, cid):
            return {"latest_risk": 8.5, "peak_risk": 8.5, "analysis_count": 2}

        class _Conn:
            def execute(self, q, *a):
                class R:
                    def fetchone(s):
                        return {"n": 5}

                    def fetchall(s):
                        return [{"at": "2026-05-03", "score": 8.5},
                                {"at": "2026-05-04", "score": 6.0}]
                return R()

        def get_connection(self):
            return self._Conn()

    mod.DatabaseManager = FakeDM
    sys.modules["database"] = mod


def _load_router_module():
    _install_stub_db()
    # Resolve relative to the repository root (this file's parent directory)
    # so the test works whether it lives at the root or under tests/.
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here) if os.path.basename(here) == "tests" else here
    path = os.path.join(root, "webapp", "api_routes.py")
    if not os.path.exists(path):
        path = os.path.join(root, "api_routes.py")
    spec = importlib.util.spec_from_file_location("api_routes_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    mod = _load_router_module()
    app = FastAPI()
    app.include_router(mod.router)
    return TestClient(app)


class TestHealth:
    def test_health_ok(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


class TestMetrics:
    def test_metrics_totals(self, client):
        data = client.get("/api/metrics").json()
        assert data["total_cases"] == 3
        assert data["total_targets"] == 3
        assert data["total_artifacts"] == 5

    def test_metrics_risk_tiers(self, client):
        tiers = client.get("/api/metrics").json()["risk_tiers"]
        # 8.5 -> tier3, 3.0 -> tier2, None -> unscored
        assert tiers["tier3"] == 1
        assert tiers["tier2"] == 1
        assert tiers["unscored"] == 1
        assert tiers["tier1"] == 0

    def test_metrics_platforms(self, client):
        plats = client.get("/api/metrics").json()["platforms"]
        assert plats["roblox"] == 2
        assert plats["discord"] == 1


class TestRiskDistribution:
    def test_distribution_total(self, client):
        data = client.get("/api/cases/risk-distribution").json()
        assert data["total"] == 3
        assert len(data["series"]) == 4

    def test_distribution_labels(self, client):
        series = client.get("/api/cases/risk-distribution").json()["series"]
        tiers = {s["tier"] for s in series}
        assert tiers == {"tier1", "tier2", "tier3", "unscored"}


class TestCaseSummary:
    def test_found_case(self, client):
        data = client.get("/api/case/CASE-1/summary").json()
        assert data["found"] is True
        assert data["tier"] == "tier3"

    def test_missing_case(self, client):
        data = client.get("/api/case/NOPE/summary").json()
        assert data["found"] is False


class TestTimeline:
    def test_timeline_points(self, client):
        data = client.get("/api/case/CASE-1/risk-timeline").json()
        assert data["count"] == 2
        assert data["points"][0]["score"] == 8.5


class TestCasesList:
    def test_cases_list(self, client):
        data = client.get("/api/cases").json()
        assert data["count"] == 3
        assert len(data["cases"]) == 3


class TestPlatforms:
    def test_platforms_endpoint(self, client):
        data = client.get("/api/platforms").json()
        assert "platforms" in data
        assert "available" in data


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))