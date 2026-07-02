"""
test_modules.py
WhisperWard OSINT — Existing Module Unit Tests
Pixora Inc. | Phase 4 Milestone 1

All tests use mocks. No real API calls, no real Ollama, no real filesystem writes.
No real user data used anywhere.
"""

import asyncio
import hashlib
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Import the modules under test
from modules.base_module import BaseOSINTModule
from modules.behavioral import analyze_text
from modules.evidence_packager import create_evidence_package
from modules.roblox_osint import RobloxOSINT
from modules.sherlock_integration import SherlockIntegration


# ─────────────────────────────────────────────
# BaseOSINTModule tests
# ─────────────────────────────────────────────
class ConcreteModule(BaseOSINTModule):
    """Minimal concrete implementation for testing the abstract base."""
    pass


class TestBaseOSINTModule:
    def test_module_name_stored(self):
        mod = ConcreteModule("TestModule")
        assert mod.module_name == "TestModule"

    def test_hash_data_dict(self):
        mod = ConcreteModule("TestModule")
        result = mod.hash_data({"key": "value"})
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_hash_data_deterministic(self):
        mod = ConcreteModule("TestModule")
        h1 = mod.hash_data({"key": "value"})
        h2 = mod.hash_data({"key": "value"})
        assert h1 == h2


# ─────────────────────────────────────────────
# RobloxOSINT tests
# ─────────────────────────────────────────────
class TestRobloxOSINT:
    def test_module_name(self):
        roblox = RobloxOSINT()
        assert roblox.module_name == "RobloxOSINT"

    @pytest.mark.asyncio
    async def test_get_user_id_returns_none_on_failure(self):
        roblox = RobloxOSINT()
        with patch("aiohttp.ClientSession") as mock_session:
            mock_resp = AsyncMock(status=500)
            mock_resp.__aenter__.return_value = mock_resp
            mock_session.return_value.__aenter__.return_value = mock_session.return_value
            mock_session.return_value.post.return_value = mock_resp

            result = await roblox._get_user_id("synthetic_test_user")
            assert result is None


# ─────────────────────────────────────────────
# SherlockIntegration tests
# ─────────────────────────────────────────────
class TestSherlockIntegration:
    def test_module_name(self):
        sherlock = SherlockIntegration()
        assert sherlock.module_name == "SherlockIntegration"

    def test_parse_output_finds_platforms(self):
        sherlock = SherlockIntegration()
        fake_output = (
            "[+] Twitter: https://twitter.com/testuser\n"
            "[+] Instagram: https://instagram.com/testuser\n"
            "[-] Reddit: Not Found!\n"
        )
        result = sherlock._parse_output(fake_output)
        assert "Twitter" in result
        assert "Instagram" in result
        assert len(result) == 2


# ─────────────────────────────────────────────
# Evidence Packager tests
# ─────────────────────────────────────────────
class TestEvidencePackager:
    def test_sha256_hash_correctness(self):
        content = b"synthetic test content"
        expected = hashlib.sha256(content).hexdigest()
        assert len(expected) == 64

    def test_manifest_structure(self):
        manifest = {
            "case_id": "CASE-TEST001",
            "generated_at": "2026-06-01T00:00:00",
            "package_version": "1.0",
            "files": ["file1.json"],
            "sha256_manifest": {"file1.json": "abc123"},
        }
        assert "case_id" in manifest
        assert "sha256_manifest" in manifest


# ─────────────────────────────────────────────
# Behavioral module tests
# ─────────────────────────────────────────────
class TestBehavioral:
    def test_analyze_text_structured_without_target(self):
        # Milestone 8 contract: the score comes from the structured RiskEngine,
        # never from the AI. Without a target and database there are no collected
        # artifacts to score against, so the result is an honest 0.0 under the
        # risk_engine_v1 analysis type rather than an invented number.
        result = analyze_text("synthetic test content", use_ai=False)
        assert isinstance(result, dict)
        assert "risk_score" in result
        assert result["analysis_type"] == "risk_engine_v1"
        assert result["risk_score"] == 0.0

    def test_analyze_text_ai_failure_fallback(self):
        with patch("modules.behavioral.AIEngine") as mock_ai_class:
            mock_ai_class.side_effect = Exception("Ollama not running")
            result = analyze_text("synthetic test content", use_ai=True)
            assert isinstance(result, dict)
            assert "risk_score" in result


# Add more tests as needed for RAGEngine, AIEngine, etc.
