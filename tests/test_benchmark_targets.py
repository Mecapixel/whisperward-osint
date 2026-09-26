"""
Benchmark targets, enforced against the real engine.

The synthetic evaluation set (seed 42: 50 safe, 50 threat, 10 edge profiles)
is scored end to end through RiskEngine, and the documented targets in
PERFORMANCE_BENCHMARK.md are asserted here, so the benchmark table cannot
claim anything the engine does not deliver.

These profiles are drawn from message lists authored alongside the classifier,
so the figures measure internal consistency, not real-world detection. See
docs/METHODOLOGY.md for what they do and do not establish.
"""

import pytest

import modules.child_safety  # noqa: F401  registers the classifier
from core.risk_engine import RiskEngine, RiskSignals
from modules.child_safety.eval.synthetic_profile_generator import SyntheticProfileGenerator

LATE_HOURS = {22, 23, 0, 1, 2, 3}


def _signals(profile) -> RiskSignals:
    late = sum(1 for t in profile.activity_timing if int(t[11:13]) in LATE_HOURS)
    return RiskSignals(
        chat_messages=[m.content for m in profile.chat_history],
        platform_count=1,
        is_tor=profile.is_tor,
        is_vpn=profile.is_vpn,
        account_age_days=profile.account_age_days,
        friend_count=profile.friend_count,
        late_night_activity=late > len(profile.activity_timing) / 2,
    )


@pytest.fixture(scope="module")
def outcomes():
    engine = RiskEngine()
    dataset = SyntheticProfileGenerator(seed=42).generate_balanced_dataset()
    rows = []
    for p in dataset.all_profiles:
        flagged = engine.score(_signals(p)).tier.value >= 2
        rows.append((p.profile_type, p.expected_tier >= 2, flagged))
    return rows


def _rate(rows, profile_type):
    subset = [r for r in rows if r[0] == profile_type]
    return sum(1 for r in subset if r[2]) / len(subset)


def test_no_safe_profile_is_flagged(outcomes):
    assert _rate(outcomes, "safe") == 0.0


def test_threat_profile_recall(outcomes):
    assert _rate(outcomes, "threat") >= 0.85


def test_precision_and_f1(outcomes):
    tp = sum(1 for _, pos, hit in outcomes if pos and hit)
    fp = sum(1 for _, pos, hit in outcomes if not pos and hit)
    fn = sum(1 for _, pos, hit in outcomes if pos and not hit)
    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    assert precision >= 0.75
    assert 2 * precision * recall / (precision + recall) >= 0.70


def test_edge_cases_are_mostly_left_below_review(outcomes):
    """Edge profiles are ambiguous by construction. The engine flags few of
    them, which is recorded as a known limitation rather than hidden: a
    stricter engine would catch more edges only by also raising the false
    positive rate on safe profiles, which is held at zero."""
    assert _rate(outcomes, "edge_case") <= 0.5
