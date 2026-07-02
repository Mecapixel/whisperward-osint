"""
test_synthetic_profile_generator.py
WhisperWard OSINT — Synthetic Data Pipeline Tests
Pixora Inc. | Phase 4 Milestone 1

All tests use entirely fabricated synthetic data only.
No real user data is ever used in any test.
"""

import json

import pytest

from synthetic_profile_generator import (
    SyntheticDataset,
    SyntheticProfileGenerator,
)


class TestSyntheticProfileGenerator:
    def test_generates_correct_count_safe(self):
        gen = SyntheticProfileGenerator(seed=42)
        profiles = gen.generate("safe", count=10)
        assert len(profiles) == 10

    def test_generates_correct_count_threat(self):
        gen = SyntheticProfileGenerator(seed=42)
        profiles = gen.generate("threat", count=5)
        assert len(profiles) == 5

    def test_generates_correct_count_edge(self):
        gen = SyntheticProfileGenerator(seed=42)
        profiles = gen.generate("edge_case", count=3)
        assert len(profiles) == 3

    def test_invalid_profile_type_raises(self):
        gen = SyntheticProfileGenerator(seed=42)
        with pytest.raises(ValueError):
            gen.generate("invalid_type", count=1)

    def test_safe_profile_type_label(self):
        gen = SyntheticProfileGenerator(seed=42)
        profiles = gen.generate("safe", count=3)
        for p in profiles:
            assert p.profile_type == "safe"

    def test_threat_profile_type_label(self):
        gen = SyntheticProfileGenerator(seed=42)
        profiles = gen.generate("threat", count=3)
        for p in profiles:
            assert p.profile_type == "threat"

    def test_edge_profile_type_label(self):
        gen = SyntheticProfileGenerator(seed=42)
        profiles = gen.generate("edge_case", count=3)
        for p in profiles:
            assert p.profile_type == "edge_case"

    def test_safe_profiles_expected_tier_1(self):
        gen = SyntheticProfileGenerator(seed=42)
        profiles = gen.generate("safe", count=5)
        for p in profiles:
            assert p.expected_tier == 1

    def test_threat_profiles_expected_tier_3(self):
        gen = SyntheticProfileGenerator(seed=42)
        profiles = gen.generate("threat", count=5)
        for p in profiles:
            assert p.expected_tier == 3

    def test_edge_profiles_expected_tier_2(self):
        gen = SyntheticProfileGenerator(seed=42)
        profiles = gen.generate("edge_case", count=5)
        for p in profiles:
            assert p.expected_tier == 2

    def test_reproducible_with_same_seed(self):
        gen1 = SyntheticProfileGenerator(seed=99)
        gen2 = SyntheticProfileGenerator(seed=99)
        profiles1 = gen1.generate("safe", count=3)
        profiles2 = gen2.generate("safe", count=3)
        for p1, p2 in zip(profiles1, profiles2):
            assert p1.username == p2.username
            assert p1.profile_id == p2.profile_id

    def test_different_seeds_produce_different_profiles(self):
        gen1 = SyntheticProfileGenerator(seed=1)
        gen2 = SyntheticProfileGenerator(seed=2)
        p1 = gen1.generate("safe", count=1)[0]
        p2 = gen2.generate("safe", count=1)[0]
        assert p1.username != p2.username

    def test_ip_stubs_are_non_routable(self):
        gen = SyntheticProfileGenerator(seed=42)
        profiles = gen.generate("safe", count=10)
        valid_prefixes = ("192.0.2.", "198.51.100.", "203.0.113.")
        for p in profiles:
            assert any(p.ip_stub.startswith(prefix) for prefix in valid_prefixes)

    def test_no_real_user_data_in_profiles(self):
        gen = SyntheticProfileGenerator(seed=42)
        profiles = gen.generate("threat", count=5)
        for p in profiles:
            assert "SYNTH-THREAT" in p.profile_id

    def test_chat_history_not_empty(self):
        gen = SyntheticProfileGenerator(seed=42)
        profiles = gen.generate("safe", count=3)
        for p in profiles:
            assert len(p.chat_history) > 0

    def test_to_dict_serializable(self):
        gen = SyntheticProfileGenerator(seed=42)
        profile = gen.generate("safe", count=1)[0]
        data = profile.to_dict()
        json.dumps(data)  # should not raise

    def test_activity_timing_sorted(self):
        gen = SyntheticProfileGenerator(seed=42)
        profiles = gen.generate("safe", count=5)
        for p in profiles:
            assert p.activity_timing == sorted(p.activity_timing)


class TestSyntheticDataset:
    def test_balanced_dataset_counts(self):
        gen = SyntheticProfileGenerator(seed=42)
        dataset = gen.generate_balanced_dataset(
            safe_count=10, threat_count=10, edge_count=5
        )
        assert len(dataset.safe_profiles) == 10
        assert len(dataset.threat_profiles) == 10
        assert len(dataset.edge_profiles) == 5
        assert dataset.total_count == 25

    def test_all_profiles_property(self):
        gen = SyntheticProfileGenerator(seed=42)
        dataset = gen.generate_balanced_dataset(
            safe_count=5, threat_count=5, edge_count=2
        )
        assert len(dataset.all_profiles) == 12

    def test_dataset_has_seed(self):
        gen = SyntheticProfileGenerator(seed=77)
        dataset = gen.generate_balanced_dataset(safe_count=2, threat_count=2, edge_count=1)
        assert dataset.seed == 77

    def test_dataset_to_dict_serializable(self):
        gen = SyntheticProfileGenerator(seed=42)
        dataset = gen.generate_balanced_dataset(safe_count=2, threat_count=2, edge_count=1)
        json.dumps(dataset.to_dict())

    def test_dataset_save_and_load(self, tmp_path):
        gen = SyntheticProfileGenerator(seed=42)
        dataset = gen.generate_balanced_dataset(safe_count=2, threat_count=2, edge_count=1)
        path = tmp_path / "test_dataset.json"
        dataset.save(str(path))

        with open(path) as f:
            loaded = json.load(f)
        assert loaded["seed"] == 42
        assert loaded["total_count"] == 5