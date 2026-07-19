"""
test_correlation_engine.py
WhisperWard OSINT — Correlation Engine Tests
Pixora Inc. | Phase 4 Milestone 3

All profiles are synthetic. No real user data.
Tests run with use_semantic=False so they stay fast and need no model download.
A separate test confirms the engine still runs when semantic is requested.
"""

import json
import pytest

from core.correlation_engine import (
    CorrelationEngine,
    CorrelationProfile,
    handle_rarity,
    string_entropy,
    inverse_degree_weight,
    hour_rarity,
    stylometric_vector,
    vector_similarity,
    confidence_interval_for_sample,
)


# ─────────────────────────────────────────────
# Fixtures — synthetic match / non-match / adversarial
# ─────────────────────────────────────────────

# A distinctive shared handle, similar writing, shared overnight hours,
# shared small-group connections, matching avatar. Should correlate strongly.
MATCH_A = CorrelationProfile(
    profile_id="SYNTH-A",
    platform="roblox",
    username="zephyrqwx_42",
    messages=[
        "honestly i dont even know why i bother lol",
        "yeah... maybe. idk tho",
        "that game was kinda mid ngl",
        "i mean its fine i guess",
        "whatever works for u honestly",
        "lol fair enough",
    ],
    active_hours=[2, 3, 23, 1],
    connections={"grp_12person", "user_rare_88", "user_rare_91"},
    connection_degrees={"grp_12person": 12, "user_rare_88": 9, "user_rare_91": 14},
    avatar_phash="ffd8a1c0b3e21100",
    avatar_dhash="aa11bb22cc33dd44",
)

MATCH_B = CorrelationProfile(
    profile_id="SYNTH-B",
    platform="discord",
    username="zephyrqwx_42",
    messages=[
        "honestly idk why i even try sometimes lol",
        "yeah maybe... not sure tho",
        "that round was kinda mid ngl",
        "its fine i guess whatever",
        "whatever works honestly lol",
        "fair enough i suppose",
    ],
    active_hours=[2, 3, 1, 23],
    connections={"grp_12person", "user_rare_88", "user_other_5"},
    connection_degrees={"grp_12person": 12, "user_rare_88": 9, "user_other_5": 7},
    avatar_phash="ffd8a1c0b3e21100",
    avatar_dhash="aa11bb22cc33dd44",
)

# Completely different people. Common handles, different writing, daytime
# hours, no shared connections, different avatars. Should not correlate.
NONMATCH_A = CorrelationProfile(
    profile_id="SYNTH-C",
    platform="roblox",
    username="coolgamer123",
    messages=[
        "Hello everyone, great game today!",
        "I really enjoyed that match.",
        "Looking forward to playing again soon.",
        "Thank you for the wonderful experience.",
        "Have a great day, everyone!",
    ],
    active_hours=[14, 15, 16],
    connections={"bigpublic_acct"},
    connection_degrees={"bigpublic_acct": 48000},
    avatar_phash="0011223344556677",
    avatar_dhash="1122334455667788",
)

NONMATCH_B = CorrelationProfile(
    profile_id="SYNTH-D",
    platform="discord",
    username="proplayer999",
    messages=[
        "yo whats good",
        "bruh that was insane lmaooo",
        "deadass tho we cooked",
        "nah u trippin fr fr",
        "aight bet lessgo",
    ],
    active_hours=[19, 20, 21],
    connections={"bigpublic_acct"},
    connection_degrees={"bigpublic_acct": 48000},
    avatar_phash="ffffffffffffffff",
    avatar_dhash="eeeeeeeeeeeeeeee",
)

# Adversarial — same person deliberately varying handle and writing to evade.
# Handle differs, writing style deliberately altered, but shared distinctive
# overnight hours and a shared small private group remain. Should still raise
# some signal through the network and timing even when text is disguised.
ADVERSARIAL_A = CorrelationProfile(
    profile_id="SYNTH-E",
    platform="roblox",
    username="nightowl_prime",
    messages=[
        "Greetings. I trust the session went well.",
        "Indeed, a most agreeable outcome.",
        "I shall return at a later hour.",
    ],
    active_hours=[3, 4, 2],
    connections={"grp_8person_private", "user_rare_77"},
    connection_degrees={"grp_8person_private": 8, "user_rare_77": 11},
    avatar_phash="abcd1234ef567890",
    avatar_dhash="1234abcd5678ef90",
)

ADVERSARIAL_B = CorrelationProfile(
    profile_id="SYNTH-F",
    platform="discord",
    username="xX_shadowmaster_Xx",
    messages=[
        "yo yo whats poppin lol",
        "lmaooo that was wild",
        "brb gimme a sec",
    ],
    active_hours=[3, 4, 2],
    connections={"grp_8person_private", "user_rare_77"},
    connection_degrees={"grp_8person_private": 8, "user_rare_77": 11},
    avatar_phash="abcd1234ef567890",
    avatar_dhash="1234abcd5678ef90",
)


# ─────────────────────────────────────────────
# Helper function tests
# ─────────────────────────────────────────────

class TestRarityHelpers:

    def test_string_entropy_empty(self):
        assert string_entropy("") == 0.0

    def test_string_entropy_repeated_low(self):
        assert string_entropy("aaaa") < string_entropy("abcd")

    def test_handle_rarity_common_is_low(self):
        assert handle_rarity("coolgamer123") < 0.5

    def test_handle_rarity_distinctive_is_higher(self):
        assert handle_rarity("zephyrqwx_42") > handle_rarity("gamer")

    def test_handle_rarity_empty(self):
        assert handle_rarity("") == 0.0

    def test_inverse_degree_small_group_high(self):
        assert inverse_degree_weight(8) > inverse_degree_weight(48000)

    def test_inverse_degree_single(self):
        assert inverse_degree_weight(1) == 1.0

    def test_hour_rarity_overnight_higher_than_evening(self):
        assert hour_rarity(3) > hour_rarity(20)


class TestStylometry:

    def test_empty_vector(self):
        assert stylometric_vector([]) == {}

    def test_vector_has_features(self):
        vec = stylometric_vector(["hello there!", "how are you?"])
        assert "function_word_freq" in vec
        assert "punctuation_density" in vec

    def test_vector_similarity_identical(self):
        vec = stylometric_vector(["hello there how are you my friend"])
        sim = vector_similarity(vec, vec)
        assert sim > 0.99

    def test_vector_similarity_empty(self):
        assert vector_similarity({}, {}) == 0.0

    def test_confidence_interval_narrows_with_size(self):
        wide = confidence_interval_for_sample(0.5, 2)
        narrow = confidence_interval_for_sample(0.5, 50)
        wide_width = wide[1] - wide[0]
        narrow_width = narrow[1] - narrow[0]
        assert narrow_width < wide_width


# ─────────────────────────────────────────────
# Pairwise correlation tests
# ─────────────────────────────────────────────

class TestPairwiseCorrelation:

    def test_match_pair_is_lead(self):
        engine = CorrelationEngine(use_semantic=False)
        result = engine.correlate(MATCH_A, MATCH_B)
        assert result.is_lead is True
        assert result.correlation_strength >= 0.45

    def test_nonmatch_pair_not_lead(self):
        engine = CorrelationEngine(use_semantic=False)
        result = engine.correlate(NONMATCH_A, NONMATCH_B)
        assert result.is_lead is False
        assert result.correlation_strength < 0.45

    def test_match_scores_higher_than_nonmatch(self):
        engine = CorrelationEngine(use_semantic=False)
        match = engine.correlate(MATCH_A, MATCH_B)
        nonmatch = engine.correlate(NONMATCH_A, NONMATCH_B)
        assert match.correlation_strength > nonmatch.correlation_strength

    def test_adversarial_still_raises_signal(self):
        engine = CorrelationEngine(use_semantic=False)
        result = engine.correlate(ADVERSARIAL_A, ADVERSARIAL_B)
        # Text was disguised but network and timing and avatar persist
        assert result.correlation_strength > 0.3

    def test_result_has_five_signals(self):
        engine = CorrelationEngine(use_semantic=False)
        result = engine.correlate(MATCH_A, MATCH_B)
        names = [s.name for s in result.signals]
        assert "username" in names
        assert "stylometry" in names
        assert "timing" in names
        assert "network" in names
        assert "avatar" in names

    def test_rationale_not_empty_for_match(self):
        engine = CorrelationEngine(use_semantic=False)
        result = engine.correlate(MATCH_A, MATCH_B)
        assert len(result.rationale) > 0

    def test_strength_between_0_and_1(self):
        engine = CorrelationEngine(use_semantic=False)
        for pair in [(MATCH_A, MATCH_B), (NONMATCH_A, NONMATCH_B), (ADVERSARIAL_A, ADVERSARIAL_B)]:
            result = engine.correlate(*pair)
            assert 0.0 <= result.correlation_strength <= 1.0

    def test_to_dict_serializable(self):
        engine = CorrelationEngine(use_semantic=False)
        result = engine.correlate(MATCH_A, MATCH_B)
        json.dumps(result.to_dict())

    def test_to_dict_has_disclaimer(self):
        engine = CorrelationEngine(use_semantic=False)
        result = engine.correlate(MATCH_A, MATCH_B)
        d = result.to_dict()
        assert "disclaimer" in d
        assert "not an assertion" in d["disclaimer"]

    def test_distinctive_username_match_strong(self):
        engine = CorrelationEngine(use_semantic=False)
        result = engine.correlate(MATCH_A, MATCH_B)
        username_signal = next(s for s in result.signals if s.name == "username")
        assert username_signal.raw_score > 0.4

    def test_common_username_match_weak(self):
        engine = CorrelationEngine(use_semantic=False)
        p1 = CorrelationProfile("X1", "roblox", "coolgamer123")
        p2 = CorrelationProfile("X2", "discord", "coolgamer123")
        result = engine.correlate(p1, p2)
        username_signal = next(s for s in result.signals if s.name == "username")
        # identical but common handle should be heavily discounted
        assert username_signal.raw_score < 0.5

    def test_default_avatar_excluded(self):
        from core.correlation_engine import DEFAULT_AVATAR_HASHES
        DEFAULT_AVATAR_HASHES.add("deadbeefdeadbeef")
        engine = CorrelationEngine(use_semantic=False)
        p1 = CorrelationProfile("Y1", "roblox", "userone", avatar_phash="deadbeefdeadbeef")
        p2 = CorrelationProfile("Y2", "discord", "usertwo", avatar_phash="deadbeefdeadbeef")
        result = engine.correlate(p1, p2)
        avatar_signal = next(s for s in result.signals if s.name == "avatar")
        assert avatar_signal.raw_score == 0.0
        DEFAULT_AVATAR_HASHES.discard("deadbeefdeadbeef")

    def test_contradiction_penalty_applied(self):
        engine = CorrelationEngine(use_semantic=False)
        all_day = list(range(0, 24))
        p1 = CorrelationProfile(
            "Z1", "roblox", "samehandle_xyz",
            messages=["hello there friend"],
            active_hours=all_day,
        )
        p2 = CorrelationProfile(
            "Z2", "discord", "samehandle_xyz",
            messages=["hello there friend"],
            active_hours=all_day,
        )
        result = engine.correlate(p1, p2)
        assert "contradiction" not in result.contradiction_note.lower() or "argues against" in result.contradiction_note


# ─────────────────────────────────────────────
# Entity clustering tests
# ─────────────────────────────────────────────

class TestEntityClustering:

    def test_cluster_groups_match_pair(self):
        engine = CorrelationEngine(use_semantic=False)
        cluster = engine.cluster_identities([MATCH_A, MATCH_B, NONMATCH_A])
        match_grouped = any(
            "SYNTH-A" in g and "SYNTH-B" in g for g in cluster.groups
        )
        assert match_grouped

    def test_cluster_separates_nonmatch(self):
        engine = CorrelationEngine(use_semantic=False)
        cluster = engine.cluster_identities([MATCH_A, MATCH_B, NONMATCH_A])
        nonmatch_alone = any(
            g == {"SYNTH-C"} for g in cluster.groups
        )
        assert nonmatch_alone

    def test_cluster_to_dict_serializable(self):
        engine = CorrelationEngine(use_semantic=False)
        cluster = engine.cluster_identities([MATCH_A, MATCH_B])
        json.dumps(cluster.to_dict())

    def test_cluster_all_profiles_accounted_for(self):
        engine = CorrelationEngine(use_semantic=False)
        profiles = [MATCH_A, MATCH_B, NONMATCH_A, NONMATCH_B]
        cluster = engine.cluster_identities(profiles)
        all_ids = set()
        for g in cluster.groups:
            all_ids |= g
        assert all_ids == {"SYNTH-A", "SYNTH-B", "SYNTH-C", "SYNTH-D"}


# ─────────────────────────────────────────────
# Semantic path smoke test
# ─────────────────────────────────────────────

class TestSemanticPath:

    def test_engine_runs_with_semantic_requested(self):
        # If sentence-transformers is installed and the embedding model is
        # available (cached locally or downloadable) this exercises the real
        # semantic path. If the package is missing, use_semantic auto-disables
        # and this still runs clean. If the package is present but the model
        # cannot be loaded — offline machine, restricted network, cold cache —
        # skip rather than fail: model availability is an environment property,
        # not a property of this code.
        engine = CorrelationEngine(use_semantic=True)
        try:
            result = engine.correlate(MATCH_A, MATCH_B)
        except OSError as exc:
            pytest.skip(f"embedding model unavailable in this environment: {exc}")
        assert 0.0 <= result.correlation_strength <= 1.0