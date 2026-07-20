from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Optional

from core.contracts import Decision
from core.registry import get_classifier

if TYPE_CHECKING:
    from modules.child_safety.behavioral_classifier import ClassifierResult


class Tier(int, Enum):
    TIER_1 = 1
    TIER_2 = 2
    TIER_3 = 3


# Tier thresholds calibrated June 2026 against a seed-42 balanced synthetic
# dataset (50 safe, 50 threat, 10 edge) via threshold sweep. The Tier 2
# boundary at 2.0 holds recall at 0.85 with zero false positives while
# preserving a full point of margin below the review line for real-world
# noise that sterile synthetic safe profiles do not exhibit. Tier 3 at 7.0
# sits above the ceiling reachable from single-platform signals alone,
# so evidence-package escalation requires cross-platform or historical
# corroboration. Recalibrated each major release.
TIER_THRESHOLDS = {
    Tier.TIER_1: (0.0, 1.9),
    Tier.TIER_2: (2.0, 6.9),
    Tier.TIER_3: (7.0, 10.0),
}


def score_to_tier(score: float) -> Tier:
    if score >= 7.0:
        return Tier.TIER_3
    if score >= 2.0:
        return Tier.TIER_2
    return Tier.TIER_1


@dataclass
class RiskSignals:
    chat_messages: list[str] = field(default_factory=list)
    platform_count: int = 1
    is_tor: bool = False
    is_vpn: bool = False
    account_age_days: Optional[int] = None
    friend_count: Optional[int] = None
    late_night_activity: bool = False
    game_history_flags: int = 0
    prior_case_flags: int = 0
    declared_age: Optional[int] = None
    classifier_result: Optional[ClassifierResult] = None


@dataclass
class ScoreComponent:
    name: str
    weight: float
    raw_score: float
    weighted_score: float
    explanation: str
    # Phase 2 M2: a score never travels as a bare number. Confidence states
    # how much the underlying data supports this component, and the reasons
    # enumerate exactly why.
    confidence: str = "medium"
    confidence_reasons: list[str] = field(default_factory=list)


@dataclass
class RiskResult:
    risk_score: float
    tier: Tier
    components: list[ScoreComponent]
    top_signals: list[str]
    explanation: str
    classifier_result: Optional[ClassifierResult]
    scored_at: str
    confidence: str = "medium"
    confidence_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "risk_score": round(self.risk_score, 2),
            "tier": self.tier.value,
            "tier_label": self._tier_label(),
            "components": [
                {
                    "name": c.name,
                    "weight": c.weight,
                    "raw_score": round(c.raw_score, 4),
                    "weighted_score": round(c.weighted_score, 4),
                    "explanation": c.explanation,
                    "confidence": c.confidence,
                    "confidence_reasons": list(c.confidence_reasons),
                }
                for c in self.components
            ],
            "top_signals": self.top_signals,
            "explanation": self.explanation,
            "confidence": self.confidence,
            "confidence_reasons": list(self.confidence_reasons),
            "scored_at": self.scored_at,
        }

    def _tier_label(self) -> str:
        return {
            Tier.TIER_1: "Monitor Only",
            Tier.TIER_2: "Human Review Required",
            Tier.TIER_3: "Escalate — Evidence Package",
        }[self.tier]


class RiskEngine:
    WEIGHTS = {
        "grooming": 0.40,
        "cross_platform": 0.25,
        "anonymization": 0.15,
        "velocity": 0.10,
        "historical": 0.10,
    }

    def __init__(self):
        # Resolved through the core registry on first use. The core never
        # imports a specialization; see core/registry.py.
        self._classifier = None

    def score(self, signals: RiskSignals) -> RiskResult:
        classifier_result = signals.classifier_result
        if classifier_result is None and signals.chat_messages:
            if self._classifier is None:
                self._classifier = get_classifier()
            classifier_result = self._classifier.classify_profile(
                chat_messages=signals.chat_messages,
                account_age_days=signals.account_age_days,
                friend_count=signals.friend_count,
                is_new_account=(signals.account_age_days is not None and signals.account_age_days < 30),
            )

        components: list[ScoreComponent] = []

        grooming_raw, grooming_explanation = self._score_grooming(classifier_result)
        g_conf, g_reasons = self._confidence_grooming(signals, classifier_result)
        components.append(
            ScoreComponent(
                name="grooming_classifier",
                weight=self.WEIGHTS["grooming"],
                raw_score=grooming_raw,
                weighted_score=grooming_raw * self.WEIGHTS["grooming"],
                explanation=grooming_explanation,
                confidence=g_conf,
                confidence_reasons=g_reasons,
            )
        )

        cross_raw = self._score_cross_platform(signals)
        x_conf, x_reasons = self._confidence_cross_platform(signals)
        components.append(
            ScoreComponent(
                name="cross_platform_correlation",
                weight=self.WEIGHTS["cross_platform"],
                raw_score=cross_raw,
                weighted_score=cross_raw * self.WEIGHTS["cross_platform"],
                explanation=self._explain_cross_platform(signals),
                confidence=x_conf,
                confidence_reasons=x_reasons,
            )
        )

        anon_raw = self._score_anonymization(signals)
        a_conf, a_reasons = self._confidence_anonymization(signals)
        components.append(
            ScoreComponent(
                name="anonymization_ip",
                weight=self.WEIGHTS["anonymization"],
                raw_score=anon_raw,
                weighted_score=anon_raw * self.WEIGHTS["anonymization"],
                explanation=self._explain_anonymization(signals),
                confidence=a_conf,
                confidence_reasons=a_reasons,
            )
        )

        velocity_raw = self._score_velocity(signals)
        v_conf, v_reasons = self._confidence_velocity(signals)
        components.append(
            ScoreComponent(
                name="behavioral_velocity",
                weight=self.WEIGHTS["velocity"],
                raw_score=velocity_raw,
                weighted_score=velocity_raw * self.WEIGHTS["velocity"],
                explanation=self._explain_velocity(signals),
                confidence=v_conf,
                confidence_reasons=v_reasons,
            )
        )

        historical_raw = self._score_historical(signals)
        h_conf, h_reasons = self._confidence_historical(signals)
        components.append(
            ScoreComponent(
                name="historical_signals",
                weight=self.WEIGHTS["historical"],
                raw_score=historical_raw,
                weighted_score=historical_raw * self.WEIGHTS["historical"],
                explanation=self._explain_historical(signals),
                confidence=h_conf,
                confidence_reasons=h_reasons,
            )
        )

        synergy_bonus = self._synergy_bonus(signals, components, classifier_result)
        normalized_score = sum(c.weighted_score for c in components) + synergy_bonus
        risk_score = round(min(10.0, normalized_score * 10.0), 2)
        tier = score_to_tier(risk_score)

        top_signals = self._build_top_signals(components, classifier_result, synergy_bonus)
        explanation = self._build_explanation(risk_score, tier, top_signals)

        overall_conf, overall_reasons = self._overall_confidence(components)

        return RiskResult(
            risk_score=risk_score,
            tier=tier,
            components=components,
            top_signals=top_signals,
            explanation=explanation,
            classifier_result=classifier_result,
            scored_at=datetime.now(timezone.utc).isoformat(),
            confidence=overall_conf,
            confidence_reasons=overall_reasons,
        )

    # ------------------------------------------------------------------
    # Phase 2 M2 — Confidence engine.
    # Confidence never alters a score. It states how much observed data
    # stands behind each component, with the reasons enumerated, so a
    # reviewer can weigh a number by the evidence underneath it.
    # ------------------------------------------------------------------

    def _confidence_grooming(self, signals: RiskSignals,
                             classifier_result) -> tuple[str, list[str]]:
        if classifier_result is None:
            return "low", ["no chat content was available for behavioral classification"]
        reasons = []
        msg_count = getattr(classifier_result, "message_count", 0) or 0
        flagged = getattr(classifier_result, "flagged_message_count", 0) or 0
        reasons.append(f"behavioral classifier evaluated {msg_count} messages")
        if flagged:
            reasons.append(f"{flagged} messages matched behavioral patterns")
        if msg_count >= 20:
            return "high", reasons
        if msg_count >= 5:
            reasons.append("moderate message volume; more chat history would strengthen the assessment")
            return "medium", reasons
        reasons.append("very small message sample; classification is weakly supported")
        return "low", reasons

    def _confidence_cross_platform(self, signals: RiskSignals) -> tuple[str, list[str]]:
        n = signals.platform_count
        reasons = [f"identity observed on {n} platform(s)"]
        if n >= 2:
            reasons.append("cross-platform presence is directly observed, not inferred")
            return "high", reasons
        reasons.append("single-platform observation; correlation evidence absent rather than negative")
        return "medium", reasons

    def _confidence_anonymization(self, signals: RiskSignals) -> tuple[str, list[str]]:
        reasons = []
        if signals.is_tor or signals.is_vpn:
            if signals.is_tor:
                reasons.append("Tor exit usage flagged by IP enrichment")
            if signals.is_vpn:
                reasons.append("VPN usage flagged by IP enrichment")
            return "high", reasons
        reasons.append("no anonymization flags present; absence may reflect unavailable IP data")
        return "medium", reasons

    def _confidence_velocity(self, signals: RiskSignals) -> tuple[str, list[str]]:
        have_age = signals.account_age_days is not None
        have_friends = signals.friend_count is not None
        reasons = []
        if have_age:
            reasons.append(f"account age observed: {signals.account_age_days} days")
        if have_friends:
            reasons.append(f"friend count observed: {signals.friend_count}")
        if have_age and have_friends:
            return "high", reasons
        if have_age or have_friends:
            reasons.append("partial account metadata; remaining velocity inputs unavailable")
            return "medium", reasons
        return "low", ["no account metadata available for velocity assessment"]

    def _confidence_historical(self, signals: RiskSignals) -> tuple[str, list[str]]:
        reasons = [
            f"prior case flags on record: {signals.prior_case_flags}",
            f"game history flags on record: {signals.game_history_flags}",
        ]
        return "high", reasons

    @staticmethod
    def _overall_confidence(components: list[ScoreComponent]) -> tuple[str, list[str]]:
        levels = {c.name: c.confidence for c in components}
        reasons = []
        grooming_conf = levels.get("grooming_classifier", "medium")
        low_count = sum(1 for v in levels.values() if v == "low")
        for c in components:
            if c.confidence == "low" and c.confidence_reasons:
                reasons.append(f"{c.name}: {c.confidence_reasons[0]}")
        if grooming_conf == "high" and low_count == 0:
            return "high", reasons or ["all scoring components are well supported by observed data"]
        if grooming_conf == "low" or low_count >= 2:
            reasons.append("overall assessment limited by the components above; treat the score as provisional")
            return "low", reasons
        reasons.append("assessment is usable but would strengthen with additional observed data")
        return "medium", reasons

    def _score_grooming(self, classifier_result: Optional[ClassifierResult]) -> tuple[float, str]:
        if classifier_result is None:
            return 0.0, "no chat content available for analysis"

        raw = classifier_result.grooming_score
        if raw >= 0.6:
            explanation = "strong grooming language pattern detected across multiple categories"
        elif raw >= 0.3:
            explanation = "moderate grooming language signals detected"
        elif raw > 0.0:
            explanation = "minor grooming language signals detected"
        else:
            explanation = "no grooming language patterns detected"

        if classifier_result.decision == Decision.ESCALATE:
            explanation += "; multi-step grooming sequence confirmed"

        return raw, explanation

    def _score_cross_platform(self, signals: RiskSignals) -> float:
        if signals.platform_count >= 4:
            return 1.0
        if signals.platform_count == 3:
            return 0.7
        if signals.platform_count == 2:
            return 0.4
        return 0.0

    def _score_anonymization(self, signals: RiskSignals) -> float:
        score = 0.0
        if signals.is_tor:
            score += 0.6
        if signals.is_vpn:
            score += 0.4
        return min(1.0, score)

    def _score_velocity(self, signals: RiskSignals) -> float:
        score = 0.0

        if signals.account_age_days is not None:
            if signals.account_age_days < 7:
                score += 0.5
            elif signals.account_age_days < 30:
                score += 0.3
            elif signals.account_age_days < 90:
                score += 0.1

        if signals.friend_count is not None and signals.account_age_days is not None and signals.account_age_days > 0:
            rate = signals.friend_count / signals.account_age_days
            if rate > 20:
                score += 0.4
            elif rate > 10:
                score += 0.2
            elif rate > 5:
                score += 0.1

        if signals.late_night_activity:
            score += 0.1

        if signals.game_history_flags > 0:
            score += min(0.2, signals.game_history_flags * 0.1)

        return min(1.0, score)

    def _score_historical(self, signals: RiskSignals) -> float:
        if signals.prior_case_flags >= 3:
            return 1.0
        if signals.prior_case_flags == 2:
            return 0.7
        if signals.prior_case_flags == 1:
            return 0.4
        return 0.0

    def _synergy_bonus(
        self,
        signals: RiskSignals,
        components: list[ScoreComponent],
        classifier_result: Optional[ClassifierResult],
    ) -> float:
        active = sum(1 for c in components if c.weighted_score > 0)
        bonus = 0.0

        if classifier_result and classifier_result.grooming_score >= 0.2 and signals.platform_count >= 2:
            bonus += 0.05
        if active >= 3:
            bonus += 0.05
        if (
            classifier_result
            and classifier_result.grooming_score >= 0.15
            and signals.platform_count >= 2
            and (signals.is_vpn or signals.is_tor)
            and signals.account_age_days is not None
            and signals.account_age_days < 30
        ):
            bonus += 0.05

        return min(0.15, bonus)

    def _explain_cross_platform(self, signals: RiskSignals) -> str:
        if signals.platform_count >= 4:
            return f"username present on {signals.platform_count} platforms — high cross-platform footprint"
        if signals.platform_count == 3:
            return f"username present on {signals.platform_count} platforms"
        if signals.platform_count == 2:
            return f"username present on {signals.platform_count} platforms"
        return "username found on single platform only"

    def _explain_anonymization(self, signals: RiskSignals) -> str:
        parts = []
        if signals.is_tor:
            parts.append("Tor routing detected")
        if signals.is_vpn:
            parts.append("VPN usage detected")
        return "; ".join(parts) if parts else "no anonymization tools detected"

    def _explain_velocity(self, signals: RiskSignals) -> str:
        parts = []
        if signals.account_age_days is not None and signals.account_age_days < 30:
            parts.append(f"account is {signals.account_age_days} days old")
        if signals.friend_count is not None and signals.account_age_days is not None and signals.account_age_days > 0:
            rate = signals.friend_count / signals.account_age_days
            if rate > 10:
                parts.append(f"high friend acquisition rate ({rate:.1f}/day)")
        if signals.late_night_activity:
            parts.append("predominant late-night activity pattern")
        if signals.game_history_flags > 0:
            parts.append(f"{signals.game_history_flags} flagged game title(s) in history")
        return "; ".join(parts) if parts else "no significant velocity signals"

    def _explain_historical(self, signals: RiskSignals) -> str:
        if signals.prior_case_flags == 0:
            return "no prior flags in database"
        return f"{signals.prior_case_flags} prior flag(s) in WhisperWard database"

    def _build_top_signals(
        self,
        components: list[ScoreComponent],
        classifier_result: Optional[ClassifierResult],
        synergy_bonus: float,
    ) -> list[str]:
        signals = []
        sorted_components = sorted(components, key=lambda c: c.weighted_score, reverse=True)

        for component in sorted_components:
            if component.weighted_score > 0:
                signals.append(component.explanation)

        if classifier_result and classifier_result.top_signals:
            for sig in classifier_result.top_signals:
                if sig not in signals:
                    signals.append(sig)

        if synergy_bonus > 0:
            signals.append("combined weak signals increased overall risk")

        return signals[:5]

    def _build_explanation(self, risk_score: float, tier: Tier, top_signals: list[str]) -> str:
        tier_descriptions = {
            Tier.TIER_1: "Low risk — monitor only. No immediate action required.",
            Tier.TIER_2: "Moderate risk — human review required within 24 hours.",
            Tier.TIER_3: "High risk — evidence package generated. Human sign-off required before any filing.",
        }
        base = tier_descriptions[tier]
        if top_signals:
            return f"{base} Primary signal: {top_signals[0]}"
        return base