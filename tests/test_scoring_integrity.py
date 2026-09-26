"""
Tests for three scoring changes that make the engine do what its documentation
says it does.

Grooming measures language only. Account age and friend rate are scored once,
in the velocity component. They previously also raised the grooming score
through the classifier's behavior boost, counting the same evidence twice.

Escalation requires corroboration. Tier 3 needs cross-platform presence or
prior history as an explicit rule, because a single-platform subject with no
history can otherwise reach the 7.0 threshold exactly.

Synergy is itemized. The interaction term carries its reasons, so the displayed
components plus synergy always sum to the score.
"""

import pytest

import modules.child_safety  # noqa: F401  registers the classifier
from core.risk_engine import RiskEngine, RiskSignals, Tier, SYNERGY_CAP
from modules.child_safety.eval import methodology as m


def _grooming(result):
    return next(c.raw_score for c in result.components if c.name == "grooming_classifier")


class TestGroomingMeasuresLanguageOnly:
    def test_account_behavior_no_longer_moves_the_grooming_component(self):
        engine = RiskEngine()
        base = dict(chat_messages=m.DIRECT_GROOMING, platform_count=2)
        new_busy = engine.score(RiskSignals(account_age_days=5, friend_count=300, **base))
        old_quiet = engine.score(RiskSignals(account_age_days=400, friend_count=20, **base))
        assert _grooming(new_busy) == _grooming(old_quiet)

    def test_account_behavior_is_still_scored_once_in_velocity(self):
        engine = RiskEngine()
        base = dict(chat_messages=m.DIRECT_GROOMING, platform_count=2)
        new_busy = engine.score(RiskSignals(account_age_days=5, friend_count=300, **base))
        old_quiet = engine.score(RiskSignals(account_age_days=400, friend_count=20, **base))
        velocity = lambda r: next(c.raw_score for c in r.components if c.name == "behavioral_velocity")
        assert velocity(new_busy) > velocity(old_quiet)
        assert new_busy.risk_score > old_quiet.risk_score

    def test_classifier_boost_remains_available_standalone(self):
        """The classifier used on its own, outside the engine, keeps its boost."""
        from core.registry import get_classifier
        c = get_classifier()
        boosted = c.classify_profile(m.DIRECT_GROOMING, account_age_days=5,
                                     friend_count=300, is_new_account=True)
        plain = c.classify_profile(m.DIRECT_GROOMING)
        assert boosted.grooming_score > plain.grooming_score


class TestEscalationRequiresCorroboration:
    def test_uncorroborated_single_platform_is_held_at_tier2(self):
        r = RiskEngine().score(m.maximal_signals(platform_count=1, prior_case_flags=0))
        assert r.risk_score >= 7.0
        assert r.tier == Tier.TIER_2
        assert r.tier_hold_reason
        assert "Held at Tier 2" in r.explanation

    def test_hold_never_changes_the_score(self):
        engine = RiskEngine()
        held = engine.score(m.maximal_signals(platform_count=1, prior_case_flags=0))
        components = sum(c.weighted_score for c in held.components) + held.synergy_bonus
        assert held.risk_score == round(min(10.0, components * 10), 2)

    @pytest.mark.parametrize("platforms,flags", [(2, 0), (1, 1), (4, 3)])
    def test_corroborated_subjects_escalate(self, platforms, flags):
        r = RiskEngine().score(m.maximal_signals(platform_count=platforms, prior_case_flags=flags))
        assert r.tier == Tier.TIER_3
        assert r.tier_hold_reason is None

    def test_graph_corroboration_counts(self):
        s = m.maximal_signals(platform_count=1, prior_case_flags=0)
        s.graph_lead_platforms = 2
        assert RiskEngine().score(s).tier == Tier.TIER_3

    def test_hold_is_serialized(self):
        d = RiskEngine().score(m.maximal_signals(1, 0)).to_dict()
        assert d["tier"] == 2 and d["tier_hold_reason"]


class TestSynergyIsItemized:
    def test_components_plus_synergy_equal_the_score(self, ):
        for s in m.factorial_grid()[::37]:
            r = RiskEngine().score(s)
            total = sum(c.weighted_score for c in r.components) + r.synergy_bonus
            assert r.risk_score == round(min(10.0, total * 10), 2)

    def test_each_synergy_reason_is_reported(self):
        r = RiskEngine().score(m.maximal_signals(platform_count=3, prior_case_flags=0))
        assert r.synergy_bonus == pytest.approx(SYNERGY_CAP)
        assert len(r.synergy_reasons) == 3

    def test_no_synergy_no_reasons(self):
        r = RiskEngine().score(RiskSignals(platform_count=1))
        assert r.synergy_bonus == 0 and r.synergy_reasons == []

    def test_synergy_serialized(self):
        d = RiskEngine().score(m.maximal_signals(3, 0)).to_dict()
        assert d["synergy_bonus"] == pytest.approx(SYNERGY_CAP)
        assert len(d["synergy_reasons"]) == 3
