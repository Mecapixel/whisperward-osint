"""
methodology.py
WhisperWard OSINT — Methodology and robustness analysis for the risk engine.

The precision/recall reporter answers how the engine performs on synthetic
profiles. Those profiles are drawn from message lists authored alongside the
classifier's patterns, so their recall measures self-consistency rather than
detection ability. This module answers a different set of questions, none of
which requires labeled ground truth, because each interrogates the scoring
function itself rather than the world:

    Analytic ceilings    What is the highest score reachable under a stated
                         constraint, such as a single platform with no history?
                         Design claims about tier reachability are checked
                         against the real engine, not asserted.

    Weight sensitivity   If a component weight moves by a stated fraction,
                         with the others rescaled to keep the total at 1.0,
                         how many profiles change tier?

    Threshold            If a tier boundary moves by a stated number of points,
    sensitivity          how many profiles change tier?

    Adversarial evasion  How does a subject score when deliberately shaped to
                         avoid each signal the engine relies on?

The profile population for the sensitivity analyses is a full factorial grid
over every component's reachable levels, not a sample from the synthetic
generator. A generated population clusters wherever the generator puts its
mass, often far from tier boundaries, which makes flip rates look smaller than
they are. The grid places profiles across the whole input space, including at
the boundaries, so the reported sensitivity is the honest one.

Nothing here alters the engine. Weights are overridden on a private engine
instance for the duration of one analysis.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Iterable, Optional

from core.contracts import Decision
from core.risk_engine import RiskEngine, RiskSignals, Tier

# Grooming levels injected directly as classifier output, so the grid covers
# the component's full range independent of which phrases happen to match.
GROOMING_LEVELS = (0.0, 0.2, 0.4, 0.6, 0.8, 1.0)
PLATFORM_LEVELS = (1, 2, 3, 4)
ANONYMIZATION_LEVELS = ((False, False), (False, True), (True, False), (True, True))  # (tor, vpn)
# Velocity profiles as (account_age_days, friend_count, late_night_activity),
# chosen to reach raw velocity 0.0, 0.1, 0.5 and 1.0. Account age alone tops
# out at 0.5, so friend rate and late-night activity are set explicitly to
# carry the component across its whole range.
VELOCITY_LEVELS = ((None, None, False), (60, 60, False), (20, 250, False), (3, 100, True))
PRIOR_FLAG_LEVELS = (0, 1, 2, 3)

COMPONENTS = ("grooming", "cross_platform", "anonymization", "velocity", "historical")


def _classifier_result(grooming_score: float):
    """A classifier result carrying only a score, for driving the engine at a
    chosen grooming level. Imported lazily so the core stays specialization-free
    at import time."""
    from modules.child_safety.behavioral_classifier import ClassifierResult
    return ClassifierResult(
        grooming_score=grooming_score,
        detected_patterns=[],
        category_scores={},
        top_signals=[],
        message_count=10 if grooming_score > 0 else 0,
        flagged_message_count=0,
        decision=Decision.ALLOW,
    )


def tier_for(score: float, tier2: float = 2.0, tier3: float = 7.0,
             corroborated: bool = True) -> Tier:
    """Tier assignment with movable boundaries, applying the engine's
    corroboration rule for escalation. Matches the engine's own tier exactly
    at the default boundaries, so sensitivity is measured against the real
    rule rather than the score alone."""
    if score >= tier3:
        return Tier.TIER_3 if corroborated else Tier.TIER_2
    if score >= tier2:
        return Tier.TIER_2
    return Tier.TIER_1


# ─────────────────────────────────────────────
# Profile population
# ─────────────────────────────────────────────
def factorial_grid() -> list[RiskSignals]:
    """Every combination of component levels: 6 × 4 × 4 × 4 × 4 = 1,536 profiles.

    Grooming is injected as classifier output rather than produced from chat,
    so this grid measures the scoring layer. It does not include the
    classifier's own account-age boost, which is examined separately."""
    grid = []
    for g, p, (tor, vpn), (age, friends, late), flags in itertools.product(
        GROOMING_LEVELS, PLATFORM_LEVELS, ANONYMIZATION_LEVELS,
        VELOCITY_LEVELS, PRIOR_FLAG_LEVELS,
    ):
        grid.append(RiskSignals(
            classifier_result=_classifier_result(g) if g > 0 else None,
            platform_count=p,
            is_tor=tor,
            is_vpn=vpn,
            account_age_days=age,
            friend_count=friends,
            late_night_activity=late,
            prior_case_flags=flags,
        ))
    return grid


def _engine_with(weights: Optional[dict] = None) -> RiskEngine:
    engine = RiskEngine()
    if weights is not None:
        engine.WEIGHTS = dict(weights)  # instance override; class constant untouched
    return engine


def score_all(profiles: Iterable[RiskSignals], weights: Optional[dict] = None) -> list[float]:
    engine = _engine_with(weights)
    return [engine.score(s).risk_score for s in profiles]


def corroboration(profiles: Iterable[RiskSignals]) -> list[bool]:
    """Whether each profile meets the engine's corroboration rule for escalation."""
    return [RiskEngine._has_corroboration(s) for s in profiles]


# ─────────────────────────────────────────────
# Analytic ceilings
# ─────────────────────────────────────────────
def maximal_signals(platform_count: int = 1, prior_case_flags: int = 0) -> RiskSignals:
    """Every signal the engine reads, pushed to its maximum, under the stated
    platform and history constraints."""
    return RiskSignals(
        classifier_result=_classifier_result(1.0),
        platform_count=platform_count,
        is_tor=True,
        is_vpn=True,
        account_age_days=3,
        friend_count=100,           # 33 friends per day, the top velocity band
        late_night_activity=True,
        game_history_flags=2,
        prior_case_flags=prior_case_flags,
    )


def ceiling(platform_count: int = 1, prior_case_flags: int = 0) -> float:
    return RiskEngine().score(maximal_signals(platform_count, prior_case_flags)).risk_score


# ─────────────────────────────────────────────
# Weight sensitivity
# ─────────────────────────────────────────────
def perturbed_weights(base: dict, component: str, fraction: float) -> dict:
    """Scale one weight by (1 + fraction) and rescale the rest proportionally so
    the total stays exactly 1.0. Holding the sum fixed isolates the effect of
    reallocating emphasis from the effect of inflating every score."""
    if component not in base:
        raise KeyError(component)
    new_target = base[component] * (1.0 + fraction)
    if not 0.0 < new_target < 1.0:
        raise ValueError("perturbation drives the weight outside (0, 1)")
    others_total = sum(v for k, v in base.items() if k != component)
    scale = (1.0 - new_target) / others_total
    return {k: (new_target if k == component else v * scale) for k, v in base.items()}


@dataclass
class SensitivityRow:
    component: str
    fraction: float
    flips: int
    total: int
    max_score_shift: float
    mean_score_shift: float
    escalations: int = 0      # profiles moved to a higher tier
    de_escalations: int = 0   # profiles moved to a lower tier

    @property
    def flip_rate(self) -> float:
        return self.flips / self.total if self.total else 0.0


def weight_sensitivity(
    profiles: list[RiskSignals],
    fractions: Iterable[float] = (-0.25, -0.10, 0.10, 0.25),
) -> list[SensitivityRow]:
    base = dict(RiskEngine.WEIGHTS)
    baseline = score_all(profiles)
    corr = corroboration(profiles)
    base_tiers = [tier_for(s, corroborated=c) for s, c in zip(baseline, corr)]
    rows = []
    for component in COMPONENTS:
        for fraction in fractions:
            scores = score_all(profiles, perturbed_weights(base, component, fraction))
            shifts = [abs(a - b) for a, b in zip(scores, baseline)]
            new_tiers = [tier_for(s, corroborated=c) for s, c in zip(scores, corr)]
            up = sum(1 for a, b in zip(new_tiers, base_tiers) if a > b)
            down = sum(1 for a, b in zip(new_tiers, base_tiers) if a < b)
            rows.append(SensitivityRow(
                component=component, fraction=fraction, flips=up + down,
                total=len(profiles), max_score_shift=max(shifts),
                mean_score_shift=sum(shifts) / len(shifts),
                escalations=up, de_escalations=down,
            ))
    return rows


# ─────────────────────────────────────────────
# Threshold sensitivity
# ─────────────────────────────────────────────
@dataclass
class ThresholdRow:
    boundary: str
    shift: float
    reassigned: int
    total: int

    @property
    def reassign_rate(self) -> float:
        return self.reassigned / self.total if self.total else 0.0


def threshold_sensitivity(
    profiles: list[RiskSignals],
    shifts: Iterable[float] = (-0.5, -0.25, 0.25, 0.5),
) -> list[ThresholdRow]:
    scores = score_all(profiles)
    corr = corroboration(profiles)
    base = [tier_for(s, corroborated=c) for s, c in zip(scores, corr)]
    rows = []
    for shift in shifts:
        t2 = [tier_for(s, tier2=2.0 + shift, corroborated=c) for s, c in zip(scores, corr)]
        t3 = [tier_for(s, tier3=7.0 + shift, corroborated=c) for s, c in zip(scores, corr)]
        rows.append(ThresholdRow("tier2", shift, sum(a != b for a, b in zip(t2, base)), len(scores)))
        rows.append(ThresholdRow("tier3", shift, sum(a != b for a, b in zip(t3, base)), len(scores)))
    return rows


def boundary_density(profiles: list[RiskSignals], margin: float = 0.5) -> dict:
    """How many profiles sit within `margin` points of a tier boundary. Those
    are the cases whose tier depends on calibration rather than on evidence."""
    scores = score_all(profiles)
    near2 = sum(1 for s in scores if abs(s - 2.0) < margin)
    near3 = sum(1 for s in scores if abs(s - 7.0) < margin)
    return {"total": len(scores), "near_tier2": near2, "near_tier3": near3, "margin": margin}


# ─────────────────────────────────────────────
# Adversarial evasion
# ─────────────────────────────────────────────
# A reference subject exhibiting the behavior the engine is built to catch,
# expressed in phrasing the classifier's patterns recognize.
DIRECT_GROOMING = [
    "how old are you",
    "you're so mature for your age",
    "don't tell your parents about us",
    "this is just between us okay",
    "add me on snapchat",
    "let's talk on discord instead",
    "your parents don't understand you like i do",
    "i'll send you robux if you keep this secret",
    "what grade are you in",
    "you can trust me more than anyone",
]

# The same intent, phrased to avoid the literal constructions the regexes key on.
PARAPHRASED_GROOMING = [
    "wait which year of school did you say",
    "honestly you seem older than kids your year",
    "probably best we keep our chats to ourselves",
    "no need to mention me at home",
    "this app is laggy, got another one we could use",
    "i'm the only one who really gets you",
    "i could sort you out with some credits",
    "you can always come to me first",
    "the adults around you just wouldn't get it",
    "whose phone do you use mostly",
]

BENIGN_FILLER = [
    "gg that was a good round", "did you see the new update", "lol nice build",
    "want to try the obby next", "brb getting food", "that boss was hard",
    "my wifi is slow today", "nice skin", "who won the last match", "see you tomorrow",
]


@dataclass
class EvasionResult:
    name: str
    technique: str
    score: float
    tier: Tier
    grooming_raw: float
    note: str = ""


@dataclass
class EvasionScenario:
    name: str
    technique: str
    signals: RiskSignals
    note: str = ""


def _baseline_subject(**overrides) -> RiskSignals:
    """The reference subject: direct grooming language across three platforms,
    a new high-velocity account, behind a VPN."""
    fields = dict(
        chat_messages=list(DIRECT_GROOMING),
        platform_count=3,
        is_vpn=True,
        account_age_days=5,
        friend_count=150,
        late_night_activity=True,
    )
    fields.update(overrides)
    return RiskSignals(**fields)


def evasion_scenarios() -> list[EvasionScenario]:
    return [
        EvasionScenario("reference", "none — direct grooming, three platforms, new account, VPN",
                        _baseline_subject()),
        EvasionScenario("paraphrase", "same intent in phrasing the patterns do not match",
                        _baseline_subject(chat_messages=list(PARAPHRASED_GROOMING))),
        EvasionScenario("dilution", "grooming messages buried in eight times as much benign chat",
                        _baseline_subject(chat_messages=list(DIRECT_GROOMING) + BENIGN_FILLER * 8)),
        EvasionScenario("slow_burn", "one message per tactic, never repeating",
                        _baseline_subject(chat_messages=DIRECT_GROOMING[::2])),
        EvasionScenario("account_split", "each account kept on one platform and never linked",
                        _baseline_subject(platform_count=1)),
        EvasionScenario("aged_account", "an old account with a normal friend rate, active in daytime",
                        _baseline_subject(account_age_days=400, friend_count=80, late_night_activity=False)),
        EvasionScenario("clean_network", "no VPN or Tor",
                        _baseline_subject(is_vpn=False)),
        EvasionScenario("full_evasion", "paraphrase, single platform, aged account, clean network",
                        _baseline_subject(chat_messages=list(PARAPHRASED_GROOMING), platform_count=1,
                                          account_age_days=400, friend_count=80,
                                          late_night_activity=False, is_vpn=False)),
    ]


def run_evasion() -> list[EvasionResult]:
    engine = RiskEngine()
    results = []
    for sc in evasion_scenarios():
        r = engine.score(sc.signals)
        grooming = next(c.raw_score for c in r.components if c.name.startswith("grooming"))
        results.append(EvasionResult(sc.name, sc.technique, r.risk_score, r.tier, grooming, sc.note))
    return results


# ─────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────
def full_report() -> dict:
    grid = factorial_grid()
    baseline = score_all(grid)
    corr = corroboration(grid)
    tiers = [tier_for(s, corroborated=c) for s, c in zip(baseline, corr)]
    tier_counts = {t.name: tiers.count(t) for t in Tier}
    return {
        "population": {"profiles": len(grid), "tier_counts": tier_counts},
        "ceilings": {
            "single_platform_no_history": ceiling(1, 0),
            "single_platform_max_history": ceiling(1, 3),
            "two_platforms_no_history": ceiling(2, 0),
            "four_platforms_max_history": ceiling(4, 3),
        },
        "weight_sensitivity": [
            {**r.__dict__, "flip_rate": round(r.flip_rate, 4)} for r in weight_sensitivity(grid)
        ],
        "threshold_sensitivity": [
            {**r.__dict__, "reassign_rate": round(r.reassign_rate, 4)} for r in threshold_sensitivity(grid)
        ],
        "boundary_density": boundary_density(grid),
        "evasion": [
            {"name": e.name, "technique": e.technique, "score": e.score,
             "tier": e.tier.value, "grooming_raw": round(e.grooming_raw, 4)}
            for e in run_evasion()
        ],
    }


if __name__ == "__main__":
    import json
    print(json.dumps(full_report(), indent=2, default=str))
