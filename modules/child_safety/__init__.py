# modules/child_safety/__init__.py
# The child-safety specialization: WhisperWard's first module on the
# reusable investigation core. It declares its capabilities to the core
# through the registry; the core never imports this package directly.

from core.registry import register_classifier, register_signals


def _make_classifier():
    from modules.child_safety.behavioral_classifier import GroomingClassifier
    return GroomingClassifier()


register_classifier("child_safety", _make_classifier)

register_signals(
    "child_safety",
    {
        # Mirrors PatternCategory in behavioral_classifier.py exactly.
        "behavioral_indicators": [
            "isolation_language",
            "secrecy_solicitation",
            "compliment_escalation",
            "age_probing",
            "gift_incentive",
            "platform_migration",
            "identity_probing",
            "trust_building",
        ],
        "purpose": (
            "Indicators associated with online grooming, surfaced for human "
            "review. Indicators are never verdicts; every consequential "
            "decision belongs to a human reviewer."
        ),
    },
)
