"""
Platform Phase 3, Milestone 4 — Graph-aware risk.

The contract under test: graph inputs refine the cross-platform component and
only that component; without graph inputs, the engine behaves exactly as
before; contradictions cap confidence and never alter a score; explanations
enumerate the corroboration the score relied on.
"""

import pytest

from core.identity_graph import IdentityGraph
from core.risk_engine import RiskEngine, RiskSignals


def pair(a, b, strength, is_lead, contradiction=""):
    return {
        "profile_a": a, "profile_b": b,
        "correlation_strength": strength, "is_lead": is_lead,
        "contradiction_note": contradiction,
        "scored_at": "2026-07-20T00:00:00+00:00",
        "rationale": [f"{a} and {b} share signal evidence"],
        "signals": [{"name": "username", "raw_score": strength,
                     "confidence": 0.9, "rationale": "handle similarity"}],
    }


@pytest.fixture()
def engine():
    return RiskEngine()


@pytest.fixture()
def corroborated_graph():
    pairs = [
        pair("roblox:shadowfox", "discord:shadow_fox", 0.85, True),
        pair("discord:shadow_fox", "steam:sfox", 0.72, True),
    ]
    return IdentityGraph.from_correlation("CASE-M4", pairs)


@pytest.fixture()
def contradicted_graph():
    pairs = [
        pair("roblox:shadowfox", "discord:shadow_fox", 0.85, True),
        pair("discord:shadow_fox", "steam:sfox", 0.68, True,
             contradiction="disjoint active hours observed simultaneously"),
    ]
    return IdentityGraph.from_correlation("CASE-M4C", pairs)


@pytest.fixture()
def uncorroborated_graph():
    pairs = [pair("roblox:shadowfox", "roblox:brightowl", 0.20, False)]
    return IdentityGraph.from_correlation("CASE-M4U", pairs)


def cross_component(result):
    return next(c for c in result.components
                if c.name == "cross_platform_correlation")


class TestRiskInputsAdapter:
    def test_keys_match_risksignals_fields(self, corroborated_graph):
        inputs = corroborated_graph.risk_inputs()
        signals = RiskSignals(**inputs)
        assert signals.graph_lead_platforms == 3
        assert signals.graph_lead_edge_count == 2
        assert signals.graph_max_lead_strength == pytest.approx(0.85)
        assert signals.graph_has_contradictions is False

    def test_contradicted_edge_excluded_from_corroboration(self, contradicted_graph):
        inputs = contradicted_graph.risk_inputs()
        assert inputs["graph_lead_edge_count"] == 1
        assert inputs["graph_lead_platforms"] == 2
        assert inputs["graph_has_contradictions"] is True

    def test_no_leads_means_no_corroboration(self, uncorroborated_graph):
        inputs = uncorroborated_graph.risk_inputs()
        assert inputs["graph_lead_platforms"] == 0
        assert inputs["graph_lead_edge_count"] == 0
        assert inputs["graph_max_lead_strength"] == 0.0


class TestScoring:
    def test_without_graph_inputs_behavior_unchanged(self, engine):
        flat = engine._score_cross_platform(RiskSignals(platform_count=3))
        assert flat == pytest.approx(0.7)

    def test_graph_platforms_drive_score_when_present(self, engine):
        signals = RiskSignals(platform_count=1, graph_lead_platforms=3)
        assert engine._score_cross_platform(signals) == pytest.approx(0.7)

    def test_graph_can_lower_an_overclaimed_flat_count(self, engine):
        # Observed on four platforms, but the graph justifies none of the
        # links: the score follows the evidence, not the observation count.
        signals = RiskSignals(platform_count=4, graph_lead_platforms=0)
        assert engine._score_cross_platform(signals) == 0.0

    def test_contradiction_flag_never_changes_score(self, engine):
        clean = RiskSignals(graph_lead_platforms=2, graph_lead_edge_count=1,
                            graph_has_contradictions=False)
        flagged = RiskSignals(graph_lead_platforms=2, graph_lead_edge_count=1,
                              graph_has_contradictions=True)
        assert (engine._score_cross_platform(clean)
                == engine._score_cross_platform(flagged))

    def test_only_cross_platform_component_consumes_graph_inputs(self, engine):
        base = RiskSignals(is_tor=True, prior_case_flags=1,
                           account_age_days=10, friend_count=5)
        with_graph = RiskSignals(is_tor=True, prior_case_flags=1,
                                 account_age_days=10, friend_count=5,
                                 graph_lead_platforms=3,
                                 graph_lead_edge_count=2,
                                 graph_max_lead_strength=0.85)
        r_base = engine.score(base)
        r_graph = engine.score(with_graph)
        for name in ("grooming_classifier", "anonymization_ip",
                     "behavioral_velocity", "historical_signals"):
            c_base = next(c for c in r_base.components if c.name == name)
            c_graph = next(c for c in r_graph.components if c.name == name)
            assert c_base.raw_score == c_graph.raw_score


class TestExplanationAndConfidence:
    def test_explanation_enumerates_corroboration(self, engine, corroborated_graph):
        signals = RiskSignals(**corroborated_graph.risk_inputs())
        result = engine.score(signals)
        component = cross_component(result)
        assert "identity graph corroborates 3 platforms" in component.explanation
        assert "2 contradiction-free lead edge(s)" in component.explanation
        assert "0.85" in component.explanation

    def test_explanation_honest_when_uncorroborated(self, engine, uncorroborated_graph):
        signals = RiskSignals(platform_count=2,
                              **uncorroborated_graph.risk_inputs())
        result = engine.score(signals)
        component = cross_component(result)
        assert "not" in component.explanation
        assert "corroborated" in component.explanation
        assert component.raw_score == 0.0

    def test_contradiction_caps_confidence_at_medium(self, engine, contradicted_graph):
        signals = RiskSignals(**contradicted_graph.risk_inputs())
        result = engine.score(signals)
        component = cross_component(result)
        assert component.confidence == "medium"
        assert any("contradicted" in r for r in component.confidence_reasons)

    def test_clean_corroboration_earns_high_confidence(self, engine, corroborated_graph):
        signals = RiskSignals(**corroborated_graph.risk_inputs())
        result = engine.score(signals)
        component = cross_component(result)
        assert component.confidence == "high"
        assert any("justified correlation" in r
                   for r in component.confidence_reasons)

    def test_flat_path_confidence_reasons_unchanged(self, engine):
        result = engine.score(RiskSignals(platform_count=2))
        component = cross_component(result)
        assert any("directly observed" in r
                   for r in component.confidence_reasons)


class TestEndToEnd:
    def test_graph_to_score_pipeline(self, engine, corroborated_graph):
        signals = RiskSignals(
            chat_messages=[], is_vpn=True,
            **corroborated_graph.risk_inputs())
        result = engine.score(signals)
        component = cross_component(result)
        assert component.raw_score == pytest.approx(0.7)
        assert result.risk_score > 0.0
        payload = result.to_dict()
        exported = next(c for c in payload["components"]
                        if c["name"] == "cross_platform_correlation")
        assert exported["confidence"] == "high"
