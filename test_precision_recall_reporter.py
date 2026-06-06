"""
test_precision_recall_reporter.py
WhisperWard OSINT — Precision/Recall/F1 Reporter Tests
Pixora Inc. | Phase 4 Milestone 1

All tests use synthetic profiles only.
"""

import json

import pytest

from precision_recall_reporter import (
    EvaluationResult,
    PrecisionRecallReporter,
)
from synthetic_profile_generator import SyntheticProfileGenerator


# Detector stubs for testing
def perfect_detector(profile) -> int:
    """Always returns the correct expected tier."""
    return profile.expected_tier


def always_tier1_detector(profile) -> int:
    """Always predicts tier 1 — misses all threats."""
    return 1


def always_tier3_detector(profile) -> int:
    """Always predicts tier 3 — high false positives."""
    return 3


class TestPrecisionRecallReporter:
    def test_perfect_detector_has_perfect_metrics(self):
        gen = SyntheticProfileGenerator(seed=42)
        reporter = PrecisionRecallReporter()
        result = reporter.run_evaluation(
            gen, perfect_detector,
            safe_count=10, threat_count=10, edge_count=5
        )
        assert result.precision == 1.0
        assert result.recall == 1.0
        assert result.f1_score == 1.0
        assert result.false_positive_rate == 0.0
        assert result.false_negative_rate == 0.0

    def test_always_tier1_has_zero_recall(self):
        gen = SyntheticProfileGenerator(seed=42)
        reporter = PrecisionRecallReporter()
        result = reporter.run_evaluation(
            gen, always_tier1_detector,
            safe_count=10, threat_count=10, edge_count=5
        )
        assert result.recall == 0.0
        assert result.false_negative_rate == 1.0

    def test_always_tier3_has_high_false_positive_rate(self):
        gen = SyntheticProfileGenerator(seed=42)
        reporter = PrecisionRecallReporter()
        result = reporter.run_evaluation(
            gen, always_tier3_detector,
            safe_count=10, threat_count=10, edge_count=5
        )
        assert result.false_positive_rate == 1.0

    def test_result_has_correct_total_count(self):
        gen = SyntheticProfileGenerator(seed=42)
        reporter = PrecisionRecallReporter()
        result = reporter.run_evaluation(
            gen, perfect_detector,
            safe_count=10, threat_count=10, edge_count=5
        )
        assert result.total_profiles == 25
        assert result.profile_counts["safe"] == 10
        assert result.profile_counts["threat"] == 10
        assert result.profile_counts["edge"] == 5

    def test_targets_met_all_true_for_perfect_detector(self):
        gen = SyntheticProfileGenerator(seed=42)
        reporter = PrecisionRecallReporter()
        result = reporter.run_evaluation(
            gen, perfect_detector,
            safe_count=10, threat_count=10, edge_count=5
        )
        assert all(result.targets_met.values())

    def test_to_dict_is_json_serializable(self):
        gen = SyntheticProfileGenerator(seed=42)
        reporter = PrecisionRecallReporter()
        result = reporter.run_evaluation(
            gen, perfect_detector,
            safe_count=5, threat_count=5, edge_count=2
        )
        data = result.to_dict()
        json.dumps(data)  # should not raise

    def test_save_report_creates_file(self, tmp_path):
        gen = SyntheticProfileGenerator(seed=42)
        reporter = PrecisionRecallReporter()
        result = reporter.run_evaluation(
            gen, perfect_detector,
            safe_count=5, threat_count=5, edge_count=2
        )
        path = str(tmp_path / "test_metrics.json")
        reporter.save_report(result, path)

        with open(path) as f:
            loaded = json.load(f)
        assert loaded["seed"] == 42
        assert "metrics" in loaded
        assert "confusion_matrix" in loaded

    def test_confusion_matrix_sums_to_total(self):
        gen = SyntheticProfileGenerator(seed=42)
        reporter = PrecisionRecallReporter()
        result = reporter.run_evaluation(
            gen, perfect_detector,
            safe_count=10, threat_count=10, edge_count=5
        )
        total = (
            result.true_positives +
            result.false_positives +
            result.true_negatives +
            result.false_negatives
        )
        assert total == result.total_profiles

    def test_run_id_is_unique(self):
        gen = SyntheticProfileGenerator(seed=42)
        reporter = PrecisionRecallReporter()
        r1 = reporter.run_evaluation(gen, perfect_detector, safe_count=3, threat_count=3, edge_count=1)
        r2 = reporter.run_evaluation(gen, perfect_detector, safe_count=3, threat_count=3, edge_count=1)
        assert r1.run_id != r2.run_id