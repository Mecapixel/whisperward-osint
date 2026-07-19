import json
import pytest

from core.risk_engine import (
    RiskEngine,
    RiskSignals,
    RiskResult,
    Tier,
    score_to_tier,
)


SAFE_SIGNALS = RiskSignals(
    chat_messages=[
        "hey wanna play together?",
        "nice game!",
        "gg everyone",
        "what server are you on?",
    ],
    platform_count=1,
    is_tor=False,
    is_vpn=False,
    account_age_days=365,
    friend_count=50,
    late_night_activity=False,
    game_history_flags=0,
    prior_case_flags=0,
)

THREAT_SIGNALS = RiskSignals(
    chat_messages=[
        "don't tell your parents about this",
        "how old are you?",
        "add me on discord it's more private",
        "i'll give you robux if you keep talking to me",
        "keep this just between us okay?",
        "let's talk somewhere private",
        "you seem really mature for your age",
    ],
    platform_count=4,
    is_tor=True,
    is_vpn=True,
    account_age_days=5,
    friend_count=300,
    late_night_activity=True,
    game_history_flags=3,
    prior_case_flags=2,
)

EDGE_SIGNALS = RiskSignals(
    chat_messages=[
        "how old are you?",
        "add me on discord it's more private",
        "don't tell your parents",
        "gg everyone",
    ],
    platform_count=3,
    is_tor=False,
    is_vpn=True,
    account_age_days=20,
    friend_count=200,
    late_night_activity=True,
    game_history_flags=2,
    prior_case_flags=1,
)


class TestRiskEngine:
    def test_safe_signals_low_score(self):
        engine = RiskEngine()
        result = engine.score(SAFE_SIGNALS)
        assert result.risk_score < 2.0
        assert result.tier == Tier.TIER_1

    def test_threat_signals_high_score(self):
        engine = RiskEngine()
        result = engine.score(THREAT_SIGNALS)
        assert result.risk_score >= 7.0
        assert result.tier in {Tier.TIER_2, Tier.TIER_3}
        assert len(result.components) == 5

    def test_edge_signals_tier_2(self):
        engine = RiskEngine()
        result = engine.score(EDGE_SIGNALS)
        assert 2.0 <= result.risk_score < 7.0
        assert result.tier == Tier.TIER_2

    def test_tier_mapping(self):
        assert score_to_tier(0.0) == Tier.TIER_1
        assert score_to_tier(1.9) == Tier.TIER_1
        assert score_to_tier(2.0) == Tier.TIER_2
        assert score_to_tier(6.9) == Tier.TIER_2
        assert score_to_tier(7.0) == Tier.TIER_3
        assert score_to_tier(10.0) == Tier.TIER_3

    def test_result_has_top_signals(self):
        engine = RiskEngine()
        result = engine.score(THREAT_SIGNALS)
        assert isinstance(result.top_signals, list)
        assert len(result.top_signals) > 0

    def test_result_has_components(self):
        engine = RiskEngine()
        result = engine.score(THREAT_SIGNALS)
        assert isinstance(result.components, list)
        assert len(result.components) == 5

    def test_components_are_explanatory(self):
        engine = RiskEngine()
        result = engine.score(THREAT_SIGNALS)
        assert all(c.explanation for c in result.components)

    def test_to_dict_serializable(self):
        engine = RiskEngine()
        result = engine.score(THREAT_SIGNALS)
        json.dumps(result.to_dict())

    def test_score_is_normalized_0_to_10(self):
        engine = RiskEngine()
        result = engine.score(THREAT_SIGNALS)
        assert 0.0 <= result.risk_score <= 10.0

    def test_result_is_dataclass(self):
        engine = RiskEngine()
        result = engine.score(SAFE_SIGNALS)
        assert isinstance(result, RiskResult)

    def test_build_explanation_contains_tier_context(self):
        engine = RiskEngine()
        result = engine.score(THREAT_SIGNALS)
        assert "risk" in result.explanation.lower()

    def test_classifier_result_pass_through(self):
        engine = RiskEngine()
        result = engine.score(THREAT_SIGNALS)
        assert result.classifier_result is not None

    def test_cross_platform_score_changes_with_platform_count(self):
        engine = RiskEngine()
        low = engine._score_cross_platform(RiskSignals(platform_count=1))
        high = engine._score_cross_platform(RiskSignals(platform_count=4))
        assert high > low

    def test_anonymization_score_changes(self):
        engine = RiskEngine()
        low = engine._score_anonymization(RiskSignals(is_tor=False, is_vpn=False))
        high = engine._score_anonymization(RiskSignals(is_tor=True, is_vpn=True))
        assert high > low

    def test_velocity_score_changes(self):
        engine = RiskEngine()
        low = engine._score_velocity(RiskSignals(account_age_days=365, friend_count=1))
        high = engine._score_velocity(
            RiskSignals(account_age_days=5, friend_count=300, late_night_activity=True)
        )
        assert high > low

    def test_historical_score_changes(self):
        engine = RiskEngine()
        low = engine._score_historical(RiskSignals(prior_case_flags=0))
        high = engine._score_historical(RiskSignals(prior_case_flags=3))
        assert high > low