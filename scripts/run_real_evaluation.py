"""
run_real_evaluation.py
WhisperWard OSINT — Real Risk Engine Evaluation
Pixora Inc. | Phase 4

Runs the actual RiskEngine against a balanced synthetic dataset and
produces a real precision, recall, and F1 report through the
PrecisionRecallReporter. This replaces stub-detector numbers with a
genuine measurement of how the production scoring pipeline performs.

All profiles are synthetic. No real user data.

Run:
    python run_real_evaluation.py
"""

from modules.child_safety.eval.precision_recall_reporter import PrecisionRecallReporter
from core.risk_engine import RiskEngine, RiskSignals
from modules.child_safety.eval.synthetic_profile_generator import (
    SyntheticProfile,
    SyntheticProfileGenerator,
)


THREAT_GAME_MARKERS = (
    "condo", "18plus", "adult", "private_rp", "secretmeet",
    "nokids", "mature", "hidden",
)


def profile_to_signals(profile: SyntheticProfile) -> RiskSignals:
    """
    Convert a SyntheticProfile into the RiskSignals shape the risk
    engine expects. This is the same mapping the live pipeline will use,
    so the evaluation measures the real scoring path.
    """
    messages = [m.content for m in profile.chat_history]

    late_night = False
    for ts in profile.activity_timing:
        hour_part = ts.split("T")[1][:2] if "T" in ts else "12"
        try:
            hour = int(hour_part)
        except ValueError:
            hour = 12
        if hour in (22, 23, 0, 1, 2, 3):
            late_night = True
            break

    game_flags = 0
    for game in profile.game_history:
        lowered = game.lower()
        if any(marker in lowered for marker in THREAT_GAME_MARKERS):
            game_flags += 1

    return RiskSignals(
        chat_messages=messages,
        platform_count=1,
        is_tor=profile.is_tor,
        is_vpn=profile.is_vpn,
        account_age_days=profile.account_age_days,
        friend_count=profile.friend_count,
        late_night_activity=late_night,
        game_history_flags=game_flags,
        prior_case_flags=0,
        declared_age=profile.declared_age,
    )


def main():
    engine = RiskEngine()

    def real_detector(profile: SyntheticProfile) -> int:
        signals = profile_to_signals(profile)
        result = engine.score(signals)
        return result.tier.value

    generator = SyntheticProfileGenerator(seed=42)
    reporter = PrecisionRecallReporter()

    print("Running real RiskEngine evaluation on balanced synthetic dataset...")
    print("Profiles: 50 safe, 50 threat, 10 edge. Seed 42 for reproducibility.\n")

    result = reporter.run_evaluation(
        generator,
        real_detector,
        safe_count=50,
        threat_count=50,
        edge_count=10,
    )

    reporter.print_report(result)
    reporter.save_report(result, "reports/real_engine_metrics_v4.json")


if __name__ == "__main__":
    main()