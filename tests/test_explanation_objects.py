"""
tests/test_explanation_objects.py
WhisperWard — Phase 2 Milestone 3 tests

Every component of a scored result becomes an ExplanationObject carrying
finding, reasoning, confidence, and evidence references; the overall
assessment gets its own explanation; and absent evidence is stated
honestly rather than silently omitted.
"""

import sqlite3
from pathlib import Path

from core.evidence import build_custody_manifest
from core.explanation import ExplanationObject, build_explanations
from core.risk_engine import RiskEngine, RiskSignals

VALID_SHA = "b" * 64


def _scored_result():
    signals = RiskSignals(
        chat_messages=["hi there"] * 12,
        platform_count=2,
        account_age_days=200,
        friend_count=50,
    )
    return RiskEngine().score(signals)


def _case_manifest():
    conn = sqlite3.connect(":memory:")
    conn.executescript(Path("database/schema.sql").read_text())
    conn.execute(
        "INSERT INTO cases (case_id, case_name, status) VALUES (?, ?, ?)",
        ("CASE-EXPL01", "Explanation test", "open"),
    )
    conn.execute(
        "INSERT INTO targets (case_id, platform, username) VALUES (?, ?, ?)",
        ("CASE-EXPL01", "roblox", "synthetic_user"),
    )
    target_id = conn.execute("SELECT target_id FROM targets").fetchone()[0]
    conn.execute(
        "INSERT INTO artifacts (target_id, module_name, artifact_type, sha256)"
        " VALUES (?, ?, ?, ?)",
        (target_id, "roblox_osint", "profile", VALID_SHA),
    )
    conn.commit()
    return build_custody_manifest("CASE-EXPL01", conn)


class TestExplanationObjects:
    def test_one_explanation_per_component_plus_summary(self):
        result = _scored_result()
        explanations = build_explanations(result)
        assert len(explanations) == len(result.components) + 1
        assert explanations[-1].source_component == "overall_assessment"

    def test_explanations_carry_reasoning_and_confidence(self):
        for e in build_explanations(_scored_result()):
            assert isinstance(e, ExplanationObject)
            assert e.finding
            assert e.reasoning, f"{e.source_component} must carry reasoning"
            assert e.confidence in ("high", "medium", "low")

    def test_explanations_link_to_case_evidence(self):
        manifest = _case_manifest()
        explanations = build_explanations(_scored_result(), custody_manifest=manifest)
        expected_ids = [a["evidence"]["evidence_id"] for a in manifest["artifacts"]]
        assert expected_ids
        for e in explanations:
            assert e.evidence_refs == expected_ids

    def test_absent_evidence_is_stated_not_silent(self):
        explanations = build_explanations(_scored_result())
        for e in explanations:
            assert e.evidence_refs == []
            assert any("no stored artifacts" in r for r in e.reasoning)

    def test_to_dict_round_trip_fields(self):
        e = build_explanations(_scored_result())[0].to_dict()
        for key in ("finding", "source_component", "reasoning", "confidence",
                    "evidence_refs", "created_at"):
            assert key in e
