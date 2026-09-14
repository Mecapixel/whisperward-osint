"""
tests/test_persistence_graph.py

Covers the persistence layer: succession recording, evidence refusal, cycle
refusal, inference from correlation output, chain assembly, interval math, and
both export views.
"""

import pytest

from core.identity_graph import EdgeJustification
from core.persistence_graph import (
    AccountState,
    AccountStatus,
    HANDED_OFF_TO,
    PersistenceError,
    PersistenceGraph,
    SUCCEEDED_BY,
    _parse_ts,
)


def justification(strength=0.9, rationale=None, is_lead=True, contradiction=""):
    return EdgeJustification(
        strength=strength,
        is_lead=is_lead,
        signals=[{"name": "username", "score": strength}],
        rationale=rationale if rationale is not None else ["handle pattern reused"],
        contradiction_note=contradiction,
        scored_at="2026-05-01T00:00:00+00:00",
    )


def account(profile_id, status=AccountStatus.UNKNOWN, created="", removed=""):
    return AccountState(
        profile_id=profile_id,
        status=status,
        created_at=created,
        removed_at=removed,
    )


@pytest.fixture
def chain_graph():
    """Three Roblox accounts forming a two link succession chain."""
    graph = PersistenceGraph("WW-TEST-001")
    graph.upsert_account(account("roblox:alpha1", AccountStatus.REMOVED,
                                 created="2026-01-01T00:00:00+00:00",
                                 removed="2026-01-10T00:00:00+00:00"))
    graph.upsert_account(account("roblox:alpha2", AccountStatus.REMOVED,
                                 created="2026-01-10T04:00:00+00:00",
                                 removed="2026-01-20T00:00:00+00:00"))
    graph.upsert_account(account("roblox:alpha3", AccountStatus.ACTIVE,
                                 created="2026-01-20T02:00:00+00:00"))
    graph.add_succession("roblox:alpha1", "roblox:alpha2", justification())
    graph.add_succession("roblox:alpha2", "roblox:alpha3", justification())
    return graph


class TestAccountState:
    def test_profile_id_splits_into_platform_and_username(self):
        state = account("discord:handle_77")
        assert state.platform == "discord"
        assert state.username == "handle_77"

    def test_profile_id_without_separator_is_unknown_platform(self):
        state = account("bare-identifier")
        assert state.platform == "unknown"
        assert state.username == "bare-identifier"

    def test_upsert_merges_rather_than_replaces(self):
        graph = PersistenceGraph("WW-TEST-002")
        graph.upsert_account(account("roblox:a", created="2026-01-01T00:00:00+00:00"))
        graph.upsert_account(account("roblox:a", AccountStatus.REMOVED,
                                     removed="2026-02-01T00:00:00+00:00"))
        merged = graph.states["roblox:a"]
        assert merged.created_at == "2026-01-01T00:00:00+00:00"
        assert merged.removed_at == "2026-02-01T00:00:00+00:00"
        assert merged.status is AccountStatus.REMOVED


class TestTimestampParsing:
    def test_parses_zulu_suffix(self):
        assert _parse_ts("2026-01-01T00:00:00Z") is not None

    def test_unparseable_returns_none_rather_than_raising(self):
        assert _parse_ts("not a timestamp") is None
        assert _parse_ts("") is None
        assert _parse_ts(None) is None

    def test_naive_timestamp_is_treated_as_utc(self):
        parsed = _parse_ts("2026-01-01T00:00:00")
        assert parsed is not None and parsed.tzinfo is not None


class TestEvidenceDiscipline:
    def test_succession_without_rationale_is_refused(self):
        graph = PersistenceGraph("WW-TEST-003")
        with pytest.raises(PersistenceError, match="rationale"):
            graph.add_succession("roblox:a", "roblox:b", justification(rationale=[]))

    def test_succession_without_justification_is_refused(self):
        graph = PersistenceGraph("WW-TEST-003")
        with pytest.raises(PersistenceError, match="EdgeJustification"):
            graph.add_succession("roblox:a", "roblox:b", None)

    def test_self_succession_is_refused(self):
        graph = PersistenceGraph("WW-TEST-003")
        with pytest.raises(PersistenceError, match="cannot succeed itself"):
            graph.add_succession("roblox:a", "roblox:a", justification())

    def test_cycle_is_refused(self, chain_graph):
        with pytest.raises(PersistenceError, match="cycle"):
            chain_graph.add_succession("roblox:alpha3", "roblox:alpha1", justification())


class TestHandoff:
    def test_cross_platform_handoff_is_recorded(self):
        graph = PersistenceGraph("WW-TEST-004")
        link = graph.add_handoff("roblox:alpha3", "discord:privatechan", justification())
        assert link.source == "roblox:alpha3"
        assert graph.graph.edges["roblox:alpha3", "discord:privatechan"]["relation"] == HANDED_OFF_TO

    def test_same_platform_movement_is_refused(self):
        graph = PersistenceGraph("WW-TEST-004")
        with pytest.raises(PersistenceError, match="same platform"):
            graph.add_handoff("roblox:a", "roblox:b", justification())

    def test_handoff_reports_platform_pair(self):
        graph = PersistenceGraph("WW-TEST-004")
        graph.add_handoff("roblox:alpha3", "telegram:chan9", justification())
        assert graph.cross_platform_handoffs() == [
            {"from_platform": "roblox", "to_platform": "telegram",
             "observed_at": graph.handoff_edges()[0].observed_at}
        ]


class TestChains:
    def test_chain_is_assembled_in_order(self, chain_graph):
        assert chain_graph.longest_chain() == [
            "roblox:alpha1", "roblox:alpha2", "roblox:alpha3"
        ]

    def test_chain_count_and_length_in_summary(self, chain_graph):
        summary = chain_graph.persistence_summary()
        assert summary["succession_links"] == 2
        assert summary["longest_chain_length"] == 3
        assert summary["removed_accounts"] == 2
        assert summary["platforms_spanned"] == ["roblox"]

    def test_graph_with_no_successions_has_no_chains(self):
        graph = PersistenceGraph("WW-TEST-005")
        graph.upsert_account(account("roblox:lonely", AccountStatus.ACTIVE))
        assert graph.reconstitution_chains() == []
        assert graph.longest_chain() == []
        assert graph.persistence_summary()["longest_chain_length"] == 0

    def test_branching_produces_multiple_chains(self):
        graph = PersistenceGraph("WW-TEST-006")
        for pid in ("roblox:r0", "roblox:r1", "roblox:r2"):
            graph.upsert_account(account(pid))
        graph.add_succession("roblox:r0", "roblox:r1", justification())
        graph.add_succession("roblox:r0", "roblox:r2", justification())
        assert len(graph.reconstitution_chains()) == 2


class TestIntervals:
    def test_gap_is_computed_from_removal_and_creation(self, chain_graph):
        intervals = chain_graph.reconstitution_intervals()
        assert [row["gap_hours"] for row in intervals] == [2.0, 4.0]

    def test_median_gap(self, chain_graph):
        assert chain_graph.median_gap_hours() == 3.0

    def test_missing_timestamps_yield_no_interval(self):
        graph = PersistenceGraph("WW-TEST-007")
        graph.add_succession("roblox:x", "roblox:y", justification())
        assert graph.reconstitution_intervals() == []
        assert graph.median_gap_hours() is None


class TestInference:
    def _pair(self, a, b, strength=0.9, contradiction="", is_lead=True):
        return {
            "profile_a": a,
            "profile_b": b,
            "correlation_strength": strength,
            "is_lead": is_lead,
            "signals": [{"name": "username", "score": strength}],
            "rationale": ["handle rarity high"],
            "contradiction_note": contradiction,
            "scored_at": "2026-05-01T00:00:00+00:00",
        }

    def _seeded(self):
        graph = PersistenceGraph("WW-TEST-008")
        graph.upsert_account(account("roblox:beta1", AccountStatus.REMOVED,
                                     removed="2026-03-01T00:00:00+00:00"))
        graph.upsert_account(account("roblox:beta2", AccountStatus.ACTIVE,
                                     created="2026-03-01T06:00:00+00:00"))
        return graph

    def test_direction_comes_from_timestamps_not_argument_order(self):
        graph = self._seeded()
        links = graph.infer_successions([self._pair("roblox:beta2", "roblox:beta1")])
        assert len(links) == 1
        assert links[0].predecessor == "roblox:beta1"
        assert links[0].successor == "roblox:beta2"

    def test_inferred_links_are_flagged_and_annotated(self):
        graph = self._seeded()
        link = graph.infer_successions([self._pair("roblox:beta1", "roblox:beta2")])[0]
        assert link.inferred is True
        assert any("inferred succession" in line for line in link.justification.rationale)
        assert graph.persistence_summary()["inferred_links"] == 1

    def test_weak_correlation_is_skipped(self):
        graph = self._seeded()
        assert graph.infer_successions(
            [self._pair("roblox:beta1", "roblox:beta2", strength=0.2)]
        ) == []

    def test_contradiction_is_skipped(self):
        graph = self._seeded()
        assert graph.infer_successions(
            [self._pair("roblox:beta1", "roblox:beta2", contradiction="timezone conflict")]
        ) == []

    def test_require_lead_filters_non_leads(self):
        graph = self._seeded()
        pair = self._pair("roblox:beta1", "roblox:beta2", is_lead=False)
        assert graph.infer_successions([pair], require_lead=True) == []
        assert len(graph.infer_successions([pair], require_lead=False)) == 1

    def test_creation_outside_window_is_skipped(self):
        graph = PersistenceGraph("WW-TEST-009")
        graph.upsert_account(account("roblox:g1", AccountStatus.REMOVED,
                                     removed="2026-01-01T00:00:00+00:00"))
        graph.upsert_account(account("roblox:g2", AccountStatus.ACTIVE,
                                     created="2026-06-01T00:00:00+00:00"))
        assert graph.infer_successions([self._pair("roblox:g1", "roblox:g2")]) == []

    def test_missing_timestamps_produce_no_inference(self):
        graph = PersistenceGraph("WW-TEST-010")
        assert graph.infer_successions([self._pair("roblox:h1", "roblox:h2")]) == []

    def test_accepts_objects_exposing_to_dict(self):
        class Result:
            def __init__(self, payload):
                self._payload = payload

            def to_dict(self):
                return self._payload

        graph = self._seeded()
        wrapped = Result(self._pair("roblox:beta1", "roblox:beta2"))
        assert len(graph.infer_successions([wrapped])) == 1


class TestExports:
    def test_referral_view_retains_identifiers(self, chain_graph):
        payload = chain_graph.to_dict()
        assert payload["view"] == "referral"
        assert any(a["profile_id"] == "roblox:alpha1" for a in payload["accounts"])
        assert payload["reconstitution_chains"][0][0] == "roblox:alpha1"

    def test_platform_view_withholds_identifiers(self, chain_graph):
        payload = chain_graph.to_redacted_view()
        serialized = str(payload)
        assert payload["view"] == "platform"
        for identifier in ("alpha1", "alpha2", "alpha3"):
            assert identifier not in serialized

    def test_platform_view_preserves_structure(self, chain_graph):
        payload = chain_graph.to_redacted_view()
        assert payload["chains"][0]["length"] == 3
        assert payload["chains"][0]["positions"] == ["CH1-P1", "CH1-P2", "CH1-P3"]
        assert len(payload["reconstitution_intervals"]) == 2
        assert payload["summary"]["median_gap_hours"] == 3.0

    def test_platform_view_carries_attribution_disclaimer(self, chain_graph):
        note = chain_graph.to_redacted_view()["note"]
        assert "not identifications of natural persons" in note
        assert "not legal conclusions" in note

    def test_unchained_accounts_receive_labels(self):
        graph = PersistenceGraph("WW-TEST-011")
        graph.upsert_account(account("discord:solo"))
        payload = graph.to_redacted_view()
        assert payload["chains"] == []
        assert "solo" not in str(payload)


class TestEdgeRelations:
    def test_succession_and_handoff_are_distinguishable(self):
        graph = PersistenceGraph("WW-TEST-012")
        graph.add_succession("roblox:a", "roblox:b", justification())
        graph.add_handoff("roblox:b", "discord:c", justification())
        assert len(graph.succession_edges()) == 1
        assert len(graph.handoff_edges()) == 1
        assert graph.graph.edges["roblox:a", "roblox:b"]["relation"] == SUCCEEDED_BY

    def test_handoffs_do_not_appear_in_chains(self):
        graph = PersistenceGraph("WW-TEST-013")
        graph.add_succession("roblox:a", "roblox:b", justification())
        graph.add_handoff("roblox:b", "discord:c", justification())
        assert graph.longest_chain() == ["roblox:a", "roblox:b"]