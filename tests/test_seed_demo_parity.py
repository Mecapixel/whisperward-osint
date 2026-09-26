"""
The public demo shows pre-computed scores, written at startup so the free host
never runs the engine on a cold start. These tests keep those numbers honest:
every seeded case is rescored by the real engine on each run, and any
difference fails the build. A demo that can drift from its engine would let
the site display results the engine would not produce.
"""

import pytest

import modules.child_safety  # noqa: F401  registers the classifier
import seed_demo
from core.risk_engine import RiskEngine, RiskSignals


def _rescore(variant):
    messages = [line for line in variant["description"].splitlines() if line.strip()]
    return RiskEngine().score(RiskSignals(
        chat_messages=messages,
        platform_count=variant["platforms_found"],
        account_age_days=variant["account_age_days"],
        friend_count=variant["friend_count"],
    )).to_dict()


@pytest.mark.parametrize("variant", seed_demo.DEMO_VARIANTS, ids=lambda v: v["username"])
class TestSeedParity:
    def test_seeded_score_matches_engine(self, variant):
        assert variant["risk_score"] == _rescore(variant)["risk_score"]

    def test_seeded_findings_match_engine(self, variant):
        live = _rescore(variant)
        seeded = variant["findings"]
        for key in ("tier", "tier_label", "components", "top_signals", "explanation",
                    "confidence", "confidence_reasons", "synergy_bonus",
                    "synergy_reasons", "tier_hold_reason"):
            assert seeded[key] == live[key], key

    def test_displayed_parts_sum_to_the_score(self, variant):
        """The breakdown panel shows each component and the synergy term. Their
        sum must equal the displayed score, or the explanation does not explain."""
        f = variant["findings"]
        parts = sum(c["weighted_score"] for c in f["components"]) + f["synergy_bonus"]
        assert round(parts * 10, 1) == round(variant["risk_score"], 1)


def test_demo_spans_both_review_tiers():
    tiers = sorted(v["findings"]["tier"] for v in seed_demo.DEMO_VARIANTS)
    assert tiers == [2, 3]
