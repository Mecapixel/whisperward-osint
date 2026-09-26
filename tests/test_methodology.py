"""
Methodology and robustness tests for the risk engine.

These tests interrogate the scoring function rather than its accuracy, so none
of them depends on labeled ground truth. Three kinds of assertion appear here:

    Properties the engine must always hold, such as monotonicity and the
    weight total, which guard against regressions.

    Robustness bounds, such as the tier flip rate under a ten percent weight
    change, which turn a methodology claim into a checked number.

    Resolved findings. Where analysis showed the engine behaving differently
    from its documentation, the engine was corrected and the corrected
    behavior is asserted here, so a regression fails the build.
"""

import pytest

import modules.child_safety  # noqa: F401  registers the classifier
from core.risk_engine import RiskEngine, RiskSignals, Tier, score_to_tier
from modules.child_safety.eval import methodology as m


@pytest.fixture(scope="module")
def grid():
    return m.factorial_grid()


@pytest.fixture(scope="module")
def evasion():
    return {r.name: r for r in m.run_evasion()}


# ─────────────────────────────────────────────
# Harness correctness
# ─────────────────────────────────────────────
class TestHarness:
    def test_grid_is_full_factorial(self, grid):
        assert len(grid) == 6 * 4 * 4 * 4 * 4 == 1536

    def test_tier_for_matches_the_engine_exactly(self, grid):
        engine = RiskEngine()
        for s in grid:
            r = engine.score(s)
            assert m.tier_for(r.risk_score, corroborated=RiskEngine._has_corroboration(s)) == r.tier

    def test_perturbed_weights_preserve_total(self):
        for component in m.COMPONENTS:
            for fraction in (-0.25, -0.10, 0.10, 0.25):
                weights = m.perturbed_weights(RiskEngine.WEIGHTS, component, fraction)
                assert sum(weights.values()) == pytest.approx(1.0)

    def test_perturbation_moves_target_and_rescales_others_proportionally(self):
        base = RiskEngine.WEIGHTS
        w = m.perturbed_weights(base, "grooming", 0.25)
        assert w["grooming"] == pytest.approx(0.50)
        # the other four keep their ratios to each other
        assert w["cross_platform"] / w["anonymization"] == pytest.approx(
            base["cross_platform"] / base["anonymization"])

    def test_perturbation_outside_unit_interval_is_refused(self):
        with pytest.raises(ValueError):
            m.perturbed_weights(RiskEngine.WEIGHTS, "grooming", 2.0)

    def test_unknown_component_is_refused(self):
        with pytest.raises(KeyError):
            m.perturbed_weights(RiskEngine.WEIGHTS, "vibes", 0.1)

    def test_analysis_never_mutates_the_engine_constant(self, grid):
        before = dict(RiskEngine.WEIGHTS)
        m.weight_sensitivity(grid[:50])
        assert RiskEngine.WEIGHTS == before

    def test_zero_perturbation_flips_nothing(self, grid):
        rows = m.weight_sensitivity(grid, fractions=(0.0,))
        assert all(r.flips == 0 for r in rows)


# ─────────────────────────────────────────────
# Properties the engine must always hold
# ─────────────────────────────────────────────
class TestEngineProperties:
    def test_weights_sum_to_one(self):
        assert sum(RiskEngine.WEIGHTS.values()) == pytest.approx(1.0)

    def test_scores_stay_in_range(self, grid):
        assert all(0.0 <= s <= 10.0 for s in m.score_all(grid))

    @pytest.mark.parametrize("field,levels", [
        ("platform_count", m.PLATFORM_LEVELS),
        ("prior_case_flags", m.PRIOR_FLAG_LEVELS),
    ])
    def test_raising_evidence_never_lowers_the_score(self, field, levels):
        """Monotonicity: more evidence on any one axis, all else fixed, must not
        reduce risk. A violation would mean a subject could lower their score by
        doing more of what the engine is looking for."""
        engine = RiskEngine()
        for g in m.GROOMING_LEVELS:
            scores = []
            for level in levels:
                s = RiskSignals(
                    classifier_result=m._classifier_result(g) if g else None,
                    is_vpn=True, account_age_days=20,
                    **{field: level},
                )
                scores.append(engine.score(s).risk_score)
            assert scores == sorted(scores), (field, g, scores)

    @pytest.mark.parametrize("axis", ["anonymization", "velocity"])
    def test_ordered_levels_never_lower_the_score(self, axis):
        engine = RiskEngine()
        levels = m.ANONYMIZATION_LEVELS if axis == "anonymization" else m.VELOCITY_LEVELS
        for g in m.GROOMING_LEVELS:
            scores = []
            for level in levels:
                fields = dict(classifier_result=m._classifier_result(g) if g else None,
                              platform_count=2)
                if axis == "anonymization":
                    fields.update(is_tor=level[0], is_vpn=level[1])
                else:
                    fields.update(account_age_days=level[0], friend_count=level[1],
                                  late_night_activity=level[2])
                scores.append(engine.score(RiskSignals(**fields)).risk_score)
            assert scores == sorted(scores), (axis, g, scores)

    def test_grid_reaches_every_component_extreme(self, grid):
        """The sensitivity rates are only as honest as the population is wide.
        Every component must reach both zero and its maximum somewhere in the grid."""
        engine = RiskEngine()
        seen = {}
        for s in grid:
            for c in engine.score(s).components:
                lo, hi = seen.get(c.name, (1.0, 0.0))
                seen[c.name] = (min(lo, c.raw_score), max(hi, c.raw_score))
        for name, (lo, hi) in seen.items():
            assert lo == 0.0 and hi == pytest.approx(1.0), (name, lo, hi)

    def test_grooming_level_is_monotone(self):
        engine = RiskEngine()
        scores = [
            engine.score(RiskSignals(classifier_result=m._classifier_result(g) if g else None,
                                     platform_count=2)).risk_score
            for g in m.GROOMING_LEVELS
        ]
        assert scores == sorted(scores)


# ─────────────────────────────────────────────
# Robustness bounds
# ─────────────────────────────────────────────
class TestRobustnessBounds:
    def test_ten_percent_weight_change_moves_few_profiles(self, grid):
        """A ten percent reallocation of any single weight changes the tier of
        under five percent of the full input space. Hand-set weights are
        defensible to the extent tier output is insensitive to their exact
        values; this is the number that makes that claim checkable."""
        rows = m.weight_sensitivity(grid, fractions=(-0.10, 0.10))
        assert max(r.flip_rate for r in rows) < 0.05

    def test_twenty_five_percent_change_stays_bounded(self, grid):
        rows = m.weight_sensitivity(grid, fractions=(-0.25, 0.25))
        assert max(r.flip_rate for r in rows) < 0.10
        # a quarter-sized reallocation never moves any score more than one point
        assert max(r.max_score_shift for r in rows) <= 1.0 + 1e-9

    def test_grooming_weight_is_the_most_influential(self, grid):
        rows = m.weight_sensitivity(grid, fractions=(0.25,))
        worst = max(rows, key=lambda r: r.flips)
        assert worst.component == "grooming"

    def test_tier3_boundary_is_more_sensitive_than_tier2(self, grid):
        """More of the input space sits near 7.0 than near 2.0, so the Tier 3
        threshold is where calibration carries the most weight."""
        density = m.boundary_density(grid)
        assert density["near_tier3"] > density["near_tier2"]
        rows = {(r.boundary, r.shift): r.reassigned for r in m.threshold_sensitivity(grid)}
        assert rows[("tier3", 0.5)] > rows[("tier2", 0.5)]


# ─────────────────────────────────────────────
# Adversarial evasion
# ─────────────────────────────────────────────
class TestEvasion:
    def test_reference_subject_escalates(self, evasion):
        assert evasion["reference"].tier == Tier.TIER_3

    def test_dilution_does_not_help_the_subject(self, evasion):
        """Category hits are counted, not averaged against message volume, so
        burying grooming in benign chat leaves the score unchanged."""
        assert evasion["dilution"].score == evasion["reference"].score

    @pytest.mark.parametrize("name", ["clean_network", "slow_burn", "aged_account"])
    def test_single_evasions_still_reach_human_review(self, evasion, name):
        """Dropping anonymization, spacing tactics out, or using an established
        account each lowers the score below escalation, but none drops the
        subject to monitor-only. A human reviewer still sees the case."""
        assert evasion[name].tier == Tier.TIER_2
        assert evasion[name].score >= 6.0

    def test_paraphrase_defeats_the_lexical_classifier(self, evasion):
        """Known limitation: the classifier matches phrasing, not intent. The
        same tactics reworded lose most of the grooming signal."""
        assert evasion["paraphrase"].grooming_raw < 0.25 * evasion["reference"].grooming_raw
        assert evasion["paraphrase"].tier < Tier.TIER_3

    def test_unlinked_accounts_avoid_escalation(self, evasion):
        """Known limitation: without correlation linking the accounts, a
        subject confined to one platform per account stays below Tier 3."""
        assert evasion["account_split"].tier < Tier.TIER_3

    def test_combined_evasion_is_not_caught(self, evasion):
        """Known limitation, stated plainly: a subject who paraphrases, stays on
        one platform, uses an established account and a clean network is not
        detected. The engine is a triage aid for patterns it models, not a
        detector of adversaries who understand it."""
        assert evasion["full_evasion"].tier == Tier.TIER_1


# ─────────────────────────────────────────────
# Resolved findings
# ─────────────────────────────────────────────
class TestResolvedFindings:
    """Two findings from the first methodology pass, each now resolved in the
    engine. These tests assert the corrected behavior, so a regression to the
    original behavior fails here."""

    def test_single_platform_ceiling_is_held_below_escalation(self):
        """FINDING 1, resolved: a single-platform subject with no history can
        still reach a score of exactly 7.0, but escalation now requires
        corroboration as an explicit rule, so the tier is held at Tier 2."""
        assert m.ceiling(platform_count=1, prior_case_flags=0) == 7.0
        r = RiskEngine().score(m.maximal_signals(1, 0))
        assert r.tier == Tier.TIER_2 and r.tier_hold_reason

    def test_uncorroborated_escalation_is_held_through_real_chat(self):
        from modules.child_safety.eval.synthetic_profile_generator import GROOMING_CHAT_MESSAGES
        result = RiskEngine().score(RiskSignals(
            chat_messages=GROOMING_CHAT_MESSAGES * 4, platform_count=1,
            is_tor=True, is_vpn=True, account_age_days=3, friend_count=100,
            late_night_activity=True, prior_case_flags=0,
        ))
        assert result.tier == Tier.TIER_2
        assert result.tier_hold_reason

    def test_ceilings_rise_with_corroboration(self):
        assert m.ceiling(1, 0) < m.ceiling(2, 0) < m.ceiling(4, 3)
        assert m.ceiling(4, 3) == 10.0

    def test_account_age_is_counted_once(self):
        """FINDING 2, resolved: inside the engine, account age and friend rate
        no longer raise the grooming component. They are scored in velocity only."""
        engine = RiskEngine()
        young = engine.score(RiskSignals(chat_messages=m.DIRECT_GROOMING, platform_count=2,
                                         account_age_days=5, friend_count=150))
        old = engine.score(RiskSignals(chat_messages=m.DIRECT_GROOMING, platform_count=2,
                                       account_age_days=400, friend_count=80))
        g = lambda r: next(c.raw_score for c in r.components if c.name == "grooming_classifier")
        assert g(young) == g(old)
