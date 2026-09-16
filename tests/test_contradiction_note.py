"""
tests/test_contradiction_note.py
WhisperWard OSINT — Regression tests for the clean-pair contradiction sentinel

Defect: CorrelationEngine emitted the sentence "no contradictions detected"
for a clean pair. Every consumer truth-tests contradiction_note, so every
clean pair read as contradicted: lead_edge_count was 0, has_contradictions
was True, graph-aware confidence was capped at medium, the entity resolver
never saw a clean lead, and STIX relationships carried a false
"Contradiction observed" clause. The existing suite passed because its
fixtures hand-built pairs with "" rather than running engine output through
the consumers.

These tests run real engine output through each consumer, and feed the
legacy sentence form to confirm sealed pre-fix records are still read as
clean.
"""

import pytest

from core.contradiction_note import (is_clean_contradiction_note,
                                     normalize_contradiction_note)
from core.correlation_engine import CorrelationEngine, CorrelationProfile
from core.entity import EntityResolver
from core.identity_graph import IdentityGraph
from core.persistence_graph import _has_contradiction

LEGACY = "no contradictions detected"


def clean_engine_pair():
    """A real engine result for a pair with no contradiction evidence."""
    engine = CorrelationEngine(use_semantic=False)
    a = CorrelationProfile("R-1", "roblox", "zephyrqwx_42",
                           messages=["honestly i dont even know why i bother lol"],
                           active_hours=[1, 2, 3])
    b = CorrelationProfile("D-1", "discord", "zephyrqwx_42",
                           messages=["honestly i dont even know why i bother lol"],
                           active_hours=[1, 2, 3])
    return engine.correlate(a, b)


def pair_dict(a, b, strength, is_lead, note):
    return {
        "profile_a": a, "profile_b": b,
        "correlation_strength": strength, "is_lead": is_lead,
        "contradiction_note": note,
        "signals": [{"name": "username", "raw_score": strength,
                     "confidence": 0.9, "rationale": "handles identical"}],
        "rationale": ["username: handles identical"],
    }


class TestNormalizer:
    @pytest.mark.parametrize("note", ["", None, LEGACY, "  No Contradictions Detected  ", "none"])
    def test_clean_spellings(self, note):
        assert is_clean_contradiction_note(note) is True
        assert normalize_contradiction_note(note) == ""

    def test_real_contradiction_survives(self):
        note = "both profiles show sustained near-identical all-day activity"
        assert is_clean_contradiction_note(note) is False
        assert normalize_contradiction_note(note) == note


class TestEngineEmitsEmptyForClean:
    def test_clean_pair_note_is_empty(self):
        result = clean_engine_pair()
        assert result.contradiction_note == ""
        assert not result.contradiction_note

    def test_contradicted_pair_note_is_nonempty(self):
        engine = CorrelationEngine(use_semantic=False)
        all_day = list(range(24))
        a = CorrelationProfile("Z1", "roblox", "h", messages=["x"], active_hours=all_day)
        b = CorrelationProfile("Z2", "discord", "h", messages=["x"], active_hours=all_day)
        result = engine.correlate(a, b)
        assert result.contradiction_note
        assert "argues against" in result.contradiction_note


class TestIdentityGraphReadsCleanPairs:
    def test_real_engine_output_is_not_contradicted(self):
        result = clean_engine_pair()
        graph = IdentityGraph.from_correlation("CASE-CN000001", [result.to_dict()])
        assert graph.has_contradictions() is False
        if result.is_lead:
            assert graph.lead_edge_count(contradiction_free=True) == 1

    def test_legacy_sentence_is_read_as_clean(self):
        graph = IdentityGraph.from_correlation(
            "CASE-CN000002",
            [pair_dict("roblox:a", "discord:a", 0.85, True, LEGACY)])
        assert graph.has_contradictions() is False
        assert graph.lead_edge_count(contradiction_free=True) == 1
        assert graph.platforms_connected_by_leads() == {"roblox", "discord"}
        inputs = graph.risk_inputs()
        assert inputs["graph_has_contradictions"] is False
        assert inputs["graph_lead_edge_count"] == 1


class TestEntityResolverReadsCleanPairs:
    def test_legacy_sentence_yields_clean_lead_candidate(self):
        resolver = EntityResolver()
        pairs = [pair_dict("roblox:a", "discord:a", 0.85, True, LEGACY)]
        groups = [{"roblox:a", "discord:a"}]
        candidates = resolver.propose("CASE-CN000003", groups, pairs)
        assert len(candidates) == 1
        cand = candidates[0]
        assert len(cand.members) == 2
        for member in cand.members:
            for edge in member.justification.supporting_edges:
                assert edge["contradiction_note"] == ""


class TestPersistenceGraphSharesDefinition:
    def test_legacy_sentence_is_clean(self):
        assert _has_contradiction(LEGACY) is False
        assert _has_contradiction("") is False
        assert _has_contradiction("timezone conflict") is True
