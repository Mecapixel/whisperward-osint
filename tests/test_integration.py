"""
test_integration.py
WhisperWard OSINT — Integration Tests
Pixora Inc. | Phase 4 Milestone 1

Full pipeline tests from case creation to evidence package.
Uses in-memory/temp SQLite — no real API calls, no real Ollama, no real user data.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from database.db_manager import DatabaseManager
from modules.behavioral import analyze_text
from modules.evidence_packager import create_evidence_package


@pytest.fixture
def test_db(tmp_path):
    """Creates a real SQLite database in a temp directory for each test."""
    db_path = str(tmp_path / "test_whisperward.db")
    db = DatabaseManager(db_path=db_path)

    # Load schema
    schema_path = Path("database/schema.sql")
    if schema_path.exists():
        conn = db.get_connection()
        with open(schema_path, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
        conn.commit()
    return db


class TestDatabaseIntegration:
    def test_create_case_returns_case_id(self, test_db):
        case_id = test_db.create_case("Synthetic Test Case", "Integration test", "Test Analyst")
        assert case_id.startswith("CASE-")
        assert len(case_id) == 13

    def test_add_target_and_retrieve(self, test_db):
        case_id = test_db.create_case("Synthetic Test Case")
        test_db.add_target(case_id, "roblox", "synthetic_test_user_001")
        targets = test_db.get_case_targets(case_id)
        assert len(targets) == 1
        assert targets[0]["username"] == "synthetic_test_user_001"

    def test_save_analysis_and_retrieve_risk(self, test_db):
        case_id = test_db.create_case("Synthetic Test Case")
        test_db.add_target(case_id, "roblox", "synthetic_test_user_001")
        targets = test_db.get_case_targets(case_id)
        target_id = targets[0]["target_id"]

        test_db.save_analysis(target_id, {
            "analysis_type": "ai_rag_behavioral",
            "risk_score": 7.5,
            "findings": {"summary": "synthetic test finding"},
        })

        risk = test_db.get_case_risk(case_id)
        assert risk["peak_risk"] == 7.5


class TestFullPipeline:
    def test_case_creation_to_analysis_pipeline(self, test_db):
        case_id = test_db.create_case(
            "Synthetic Pipeline Test",
            "Full integration test with synthetic data",
            "Test Analyst",
        )
        test_db.add_target(case_id, "roblox", "synthetic_pipeline_user_001")
        targets = test_db.get_case_targets(case_id)
        target_id = targets[0]["target_id"]

        test_db.save_artifact(
            target_id=target_id,
            module_name="RobloxOSINT",
            artifact_type="profile",
            raw_data={"username": "synthetic_pipeline_user_001", "platform": "roblox"},
        )

        # Milestone 8 contract: the persisted score comes from the structured
        # RiskEngine reading the target's collected artifacts. The AI is run for
        # qualitative context only; its number (deliberately absurd here) must
        # never become the score. The profile description below is the synthetic
        # grooming text the classifier scans in this path, paired with a brand
        # new account, so the engine has real signals to score.
        test_db.save_artifact(
            target_id=target_id,
            module_name="RobloxOSINT",
            artifact_type="profile",
            raw_data={
                "username": "synthetic_pipeline_user_001",
                "platform": "roblox",
                "description": "let's keep this just between us, don't tell your parents",
                "friend_count": 250,
                "created": datetime.now(timezone.utc).isoformat(),
            },
        )

        with patch("modules.behavioral.AIEngine") as mock_ai_class:
            mock_ai = MagicMock()
            mock_ai.analyze_behavior.return_value = {
                "analysis_type": "ai_rag_behavioral",
                "risk_score": 99.9,
                "findings": {"summary": "synthetic pipeline test"},
            }
            mock_ai_class.return_value = mock_ai

            result = analyze_text(
                "synthetic test content",
                use_ai=True,
                case_id=case_id,
                target_id=target_id,
                db=test_db,
            )

        # The score is the engine's, never the AI's.
        assert result["analysis_type"] == "risk_engine_v1"
        assert result["risk_score"] != 99.9
        assert 0.0 < result["risk_score"] <= 10.0

        # The AI context is preserved for the analyst, not folded into the number.
        assert result["findings"].get("ai_context") == {"summary": "synthetic pipeline test"}

        # The persisted case risk matches what the engine returned.
        risk = test_db.get_case_risk(case_id)
        assert risk["peak_risk"] == result["risk_score"]

    @pytest.mark.asyncio
    async def test_roblox_collect_integrates_with_db(self, test_db):
        from modules.roblox_osint import RobloxOSINT

        case_id = test_db.create_case("Synthetic Roblox Integration Test")
        test_db.add_target(case_id, "roblox", "synthetic_roblox_user_001")
        targets = test_db.get_case_targets(case_id)
        target_id = targets[0]["target_id"]

        roblox = RobloxOSINT()
        with patch.object(roblox, "_get_with_retry", new=AsyncMock(return_value=None)):
            await roblox.collect(
                username="synthetic_roblox_user_001",
                case_id=case_id,
                db=test_db,
                target_id=target_id,
            )

        summary = test_db.get_case_summary(case_id)
        assert summary["artifacts_count"] >= 1


# Additional tests can be added here as more modules stabilize.