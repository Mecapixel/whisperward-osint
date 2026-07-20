"""
tests/test_confidence_engine.py
WhisperWard — Phase 2 Milestone 2 tests

The confidence engine's guarantees: every score component and every overall
result carries a confidence level with enumerated reasons; confidence
reflects data availability; and confidence never changes the score itself.
"""

from core.risk_engine import RiskEngine, RiskSignals


def _rich_signals() -> RiskSignals:
    return RiskSignals(
        chat_messages=["hey how old are you"] * 25,
        platform_count=3,
        is_tor=True,
        account_age_days=12,
        friend_count=4,
        late_night_activity=True,
    )


def _sparse_signals() -> RiskSignals:
    return RiskSignals(chat_messages=[], platform_count=1)


class TestConfidencePresence:
    def test_every_component_carries_confidence_and_reasons(self):
        result = RiskEngine().score(_rich_signals())
        assert result.components, "expected scored components"
        for c in result.components:
            assert c.confidence in ("high", "medium", "low")
            assert c.confidence_reasons, f"{c.name} must enumerate confidence reasons"

    def test_result_carries_overall_confidence_and_reasons(self):
        result = RiskEngine().score(_rich_signals())
        assert result.confidence in ("high", "medium", "low")
        assert result.confidence_reasons

    def test_to_dict_never_emits_bare_scores(self):
        d = RiskEngine().score(_rich_signals()).to_dict()
        assert d["confidence"] in ("high", "medium", "low")
        assert isinstance(d["confidence_reasons"], list) and d["confidence_reasons"]
        for c in d["components"]:
            assert c["confidence"] in ("high", "medium", "low")
            assert isinstance(c["confidence_reasons"], list) and c["confidence_reasons"]


class TestConfidenceReflectsData:
    def test_rich_data_yields_high_grooming_confidence(self):
        result = RiskEngine().score(_rich_signals())
        grooming = next(c for c in result.components if c.name == "grooming_classifier")
        assert grooming.confidence == "high"
        assert any("25 messages" in r for r in grooming.confidence_reasons)

    def test_no_chat_yields_low_grooming_confidence(self):
        result = RiskEngine().score(_sparse_signals())
        grooming = next(c for c in result.components if c.name == "grooming_classifier")
        assert grooming.confidence == "low"
        assert any("no chat content" in r for r in grooming.confidence_reasons)

    def test_sparse_data_lowers_overall_confidence(self):
        result = RiskEngine().score(_sparse_signals())
        assert result.confidence == "low"

    def test_multi_platform_yields_high_correlation_confidence(self):
        result = RiskEngine().score(_rich_signals())
        cross = next(c for c in result.components if c.name == "cross_platform_correlation")
        assert cross.confidence == "high"
        assert any("3 platform" in r for r in cross.confidence_reasons)

    def test_missing_account_metadata_yields_low_velocity_confidence(self):
        result = RiskEngine().score(_sparse_signals())
        velocity = next(c for c in result.components if c.name == "behavioral_velocity")
        assert velocity.confidence == "low"


class TestConfidenceNeverAltersScore:
    def test_scores_identical_with_and_without_confidence_read(self):
        a = RiskEngine().score(_rich_signals())
        b = RiskEngine().score(_rich_signals())
        assert a.risk_score == b.risk_score
        assert [c.weighted_score for c in a.components] == [
            c.weighted_score for c in b.components
        ]
