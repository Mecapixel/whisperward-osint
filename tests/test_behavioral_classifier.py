import json
import pytest
from modules.child_safety.behavioral_classifier import (
    ClassifierResult,
    GroomingClassifier,
    PatternCategory,
    PATTERN_WEIGHTS,
    Decision,
)


CLEAN_MESSAGES = [
    "hey wanna play together?",
    "nice game!",
    "gg everyone",
    "what server are you on?",
    "this game is so fun",
    "anyone wanna trade?",
]

SECRECY_MESSAGES = [
    "don't tell your parents about this",
    "keep this just between us okay?",
    "this is our little secret",
]

AGE_PROBE_MESSAGES = [
    "how old are you?",
    "you don't seem like you're 13",
    "what grade are you in?",
]

PLATFORM_MIGRATION_MESSAGES = [
    "add me on discord it's more private",
    "let's move to snapchat",
    "my discord is user#1234",
]

GIFT_MESSAGES = [
    "i'll give you robux if you keep talking to me",
    "free robux for you",
    "i can buy you a gift card",
]

ISOLATION_MESSAGES = [
    "let's talk somewhere private just the two of us",
    "nobody needs to know about this",
    "away from everyone else",
]

MIXED_THREAT_MESSAGES = (
    SECRECY_MESSAGES
    + AGE_PROBE_MESSAGES
    + PLATFORM_MIGRATION_MESSAGES
    + GIFT_MESSAGES
)


class TestGroomingClassifier:
    def test_clean_messages_low_score(self):
        clf = GroomingClassifier()
        result = clf.classify_messages(CLEAN_MESSAGES)
        assert result.grooming_score < 0.2
        assert result.flagged_message_count == 0
        assert result.decision == Decision.ALLOW

    def test_secrecy_messages_detected(self):
        clf = GroomingClassifier()
        result = clf.classify_messages(SECRECY_MESSAGES)
        assert result.grooming_score > 0.1
        categories = [p.category for p in result.detected_patterns]
        assert PatternCategory.SECRECY_SOLICITATION in categories

    def test_age_probe_messages_detected(self):
        clf = GroomingClassifier()
        result = clf.classify_messages(AGE_PROBE_MESSAGES)
        categories = [p.category for p in result.detected_patterns]
        assert PatternCategory.AGE_PROBING in categories

    def test_platform_migration_detected(self):
        clf = GroomingClassifier()
        result = clf.classify_messages(PLATFORM_MIGRATION_MESSAGES)
        categories = [p.category for p in result.detected_patterns]
        assert PatternCategory.PLATFORM_MIGRATION in categories

    def test_gift_incentive_detected(self):
        clf = GroomingClassifier()
        result = clf.classify_messages(GIFT_MESSAGES)
        categories = [p.category for p in result.detected_patterns]
        assert PatternCategory.GIFT_INCENTIVE in categories

    def test_isolation_language_detected(self):
        clf = GroomingClassifier()
        result = clf.classify_messages(ISOLATION_MESSAGES)
        categories = [p.category for p in result.detected_patterns]
        assert PatternCategory.ISOLATION_LANGUAGE in categories

    def test_mixed_threat_messages_high_score(self):
        clf = GroomingClassifier()
        result = clf.classify_messages(MIXED_THREAT_MESSAGES)
        assert result.grooming_score > 0.4
        assert result.flagged_message_count > 0

    def test_score_is_normalized_0_to_1(self):
        clf = GroomingClassifier()
        result = clf.classify_messages(list(MIXED_THREAT_MESSAGES) * 10)
        assert 0.0 <= result.grooming_score <= 1.0

    def test_result_has_top_signals(self):
        clf = GroomingClassifier()
        result = clf.classify_messages(MIXED_THREAT_MESSAGES)
        assert isinstance(result.top_signals, list)
        assert len(result.top_signals) > 0

    def test_result_has_category_scores(self):
        clf = GroomingClassifier()
        result = clf.classify_messages(MIXED_THREAT_MESSAGES)
        assert isinstance(result.category_scores, dict)
        assert len(result.category_scores) > 0

    def test_empty_messages_returns_zero_score(self):
        clf = GroomingClassifier()
        result = clf.classify_messages([])
        assert result.grooming_score == 0.0
        assert result.flagged_message_count == 0
        assert result.decision == Decision.ALLOW

    def test_classify_text_single_string(self):
        clf = GroomingClassifier()
        result = clf.classify_text("don't tell your parents about this")
        assert result.grooming_score > 0.0
        assert result.decision in {Decision.REVIEW, Decision.ESCALATE, Decision.ALLOW}

    def test_message_count_tracked(self):
        clf = GroomingClassifier()
        result = clf.classify_messages(CLEAN_MESSAGES)
        assert result.message_count == len(CLEAN_MESSAGES)

    def test_to_dict_serializable(self):
        clf = GroomingClassifier()
        result = clf.classify_messages(MIXED_THREAT_MESSAGES)
        json.dumps(result.to_dict())

    def test_clean_vs_threat_score_ordering(self):
        clf = GroomingClassifier()
        clean_result = clf.classify_messages(CLEAN_MESSAGES)
        threat_result = clf.classify_messages(MIXED_THREAT_MESSAGES)
        assert threat_result.grooming_score > clean_result.grooming_score

    def test_velocity_boost_applied_for_new_account(self):
        clf = GroomingClassifier()
        base_result = clf.classify_profile(
            SECRECY_MESSAGES,
            account_age_days=60,
            friend_count=10,
        )
        boosted_result = clf.classify_profile(
            SECRECY_MESSAGES,
            account_age_days=5,
            friend_count=300,
        )
        assert boosted_result.grooming_score >= base_result.grooming_score

    def test_pattern_weights_sum_to_one(self):
        total = sum(PATTERN_WEIGHTS.values())
        assert abs(total - 1.0) < 0.001

    def test_result_is_dataclass(self):
        clf = GroomingClassifier()
        result = clf.classify_messages(CLEAN_MESSAGES)
        assert isinstance(result, ClassifierResult)

    def test_decision_escalates_for_strong_multi_signal_case(self):
        clf = GroomingClassifier()
        result = clf.classify_messages(list(MIXED_THREAT_MESSAGES) * 2)
        assert result.decision in {Decision.REVIEW, Decision.ESCALATE}

    def test_negated_context_is_ignored(self):
        clf = GroomingClassifier()
        result = clf.classify_text("This is an educational example about grooming detection.")
        assert result.grooming_score == 0.0
        assert result.flagged_message_count == 0