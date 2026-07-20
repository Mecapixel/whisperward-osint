"""
Platform Phase 3, Milestone 1 — Unified entity model and resolver.

The contract under test: the resolver proposes, humans decide. Candidates
carry full per-membership justification, contradictions block automatic
candidacy, promotion demands an analyst name, and every promotion lands in
the tamper-evident custody chain.
"""

import json
import os
import tempfile

import pytest

from core.entity import (EntityCandidate, EntityMember, EntityResolver,
                         MembershipJustification, ResolvedEntity,
                         entity_from_row)


def make_pair(a, b, strength, is_lead, contradiction=""):
    return {
        "profile_a": a,
        "profile_b": b,
        "correlation_strength": strength,
        "is_lead": is_lead,
        "contradiction_note": contradiction,
        "signals": [
            {"name": "username", "raw_score": strength, "confidence": 0.9,
             "rationale": "handles are near-identical"},
            {"name": "avatar", "raw_score": strength * 0.8, "confidence": 0.7,
             "rationale": "avatar hashes within hamming threshold"},
        ],
    }


class TestProposal:
    def test_lead_pair_produces_candidate(self):
        resolver = EntityResolver()
        pairs = [make_pair("roblox:shadowfox", "discord:shadow_fox", 0.82, True)]
        groups = [{"roblox:shadowfox", "discord:shadow_fox"}]
        candidates = resolver.propose("CASE-TEST0001", groups, pairs)
        assert len(candidates) == 1
        cand = candidates[0]
        assert len(cand.members) == 2
        assert cand.case_id == "CASE-TEST0001"
        assert cand.mean_strength == pytest.approx(0.82)

    def test_standalone_group_is_not_a_candidate(self):
        resolver = EntityResolver()
        candidates = resolver.propose("CASE-X", [{"roblox:lonely"}], [])
        assert candidates == []

    def test_membership_carries_justification_edges(self):
        resolver = EntityResolver()
        pairs = [make_pair("roblox:a", "discord:b", 0.75, True)]
        cand = resolver.propose("CASE-X", [{"roblox:a", "discord:b"}], pairs)[0]
        member = cand.members[0]
        edges = member.justification.supporting_edges
        assert len(edges) == 1
        assert edges[0]["strength"] == pytest.approx(0.75)
        assert edges[0]["is_lead"] is True
        assert edges[0]["top_signals"], "justification must name its signals"

    def test_contradicted_account_is_excluded_with_reason(self):
        resolver = EntityResolver()
        pairs = [
            make_pair("roblox:a", "discord:b", 0.80, True),
            make_pair("roblox:a", "roblox:c", 0.65, True,
                      contradiction="simultaneous activity in disjoint hours"),
            make_pair("discord:b", "roblox:c", 0.30, False),
        ]
        groups = [{"roblox:a", "discord:b", "roblox:c"}]
        cand = resolver.propose("CASE-X", groups, pairs)[0]
        member_ids = {m.profile_id for m in cand.members}
        assert member_ids == {"roblox:a", "discord:b"}
        assert len(cand.excluded) == 1
        assert cand.excluded[0]["profile_id"] == "roblox:c"
        assert "contradiction" in cand.excluded[0]["reason"] or \
               "lead-strength" in cand.excluded[0]["reason"]

    def test_group_with_no_clean_lead_yields_no_candidate(self):
        resolver = EntityResolver()
        pairs = [make_pair("roblox:a", "discord:b", 0.55, False)]
        cand = resolver.propose("CASE-X", [{"roblox:a", "discord:b"}], pairs)
        assert cand == []

    def test_accepts_live_correlation_result_objects(self):
        from core.correlation_engine import CorrelationResult, SignalResult
        result = CorrelationResult(
            profile_a="roblox:a", profile_b="discord:b",
            correlation_strength=0.9, is_lead=True,
            signals=[SignalResult(name="username", raw_score=0.9,
                                  confidence=0.9, rationale="near-identical")],
            rationale=["near-identical"], contradiction_note="",
            scored_at="2026-07-20T00:00:00+00:00")
        resolver = EntityResolver()
        cand = resolver.propose("CASE-X", [{"roblox:a", "discord:b"}], [result])
        assert len(cand) == 1

    def test_candidate_dict_carries_disclaimer(self):
        resolver = EntityResolver()
        pairs = [make_pair("roblox:a", "discord:b", 0.8, True)]
        cand = resolver.propose("CASE-X", [{"roblox:a", "discord:b"}], pairs)[0]
        payload = cand.to_dict()
        assert "not an identity determination" in payload["disclaimer"]


class TestPromotion:
    def _candidate(self):
        resolver = EntityResolver()
        pairs = [make_pair("roblox:a", "discord:b", 0.8, True)]
        return resolver.propose("CASE-X", [{"roblox:a", "discord:b"}], pairs)[0]

    def test_promotion_requires_analyst_name(self):
        resolver = EntityResolver()
        with pytest.raises(ValueError):
            resolver.promote(self._candidate(), analyst="")
        with pytest.raises(ValueError):
            resolver.promote(self._candidate(), analyst="   ")

    def test_promotion_produces_attributed_entity(self):
        resolver = EntityResolver()
        entity = resolver.promote(self._candidate(), analyst="M. Dismukes",
                                  analyst_note="confirmed on avatar + handle")
        assert entity.entity_id.startswith("ENT-")
        assert entity.promoted_by == "M. Dismukes"
        assert entity.analyst_note == "confirmed on avatar + handle"
        assert len(entity.members) == 2
        assert entity.source_candidate_id == self._candidate().candidate_id[:0] or \
               entity.source_candidate_id.startswith("ENT-CAND-")

    def test_canonical_handle_defaults_to_first_member(self):
        resolver = EntityResolver()
        cand = self._candidate()
        entity = resolver.promote(cand, analyst="M. Dismukes")
        assert entity.canonical_handle == cand.members[0].username

    def test_single_member_candidate_cannot_be_promoted(self):
        resolver = EntityResolver()
        lone = EntityCandidate(
            candidate_id="ENT-CAND-XX", case_id="CASE-X",
            members=[EntityMember("roblox:a", "roblox", "a")],
            excluded=[], mean_strength=0.0, proposed_at="now")
        with pytest.raises(ValueError):
            resolver.promote(lone, analyst="M. Dismukes")


class TestPersistence:
    @pytest.fixture()
    def database(self, tmp_path, monkeypatch):
        from database.db_manager import DatabaseManager
        monkeypatch.chdir(os.path.dirname(os.path.dirname(__file__)))
        db = DatabaseManager(db_path=str(tmp_path / "phase3.db"))
        db.init()
        yield db
        db.close()

    def _entity(self, case_id):
        resolver = EntityResolver()
        pairs = [make_pair("roblox:a", "discord:b", 0.8, True)]
        cand = resolver.propose(case_id, [{"roblox:a", "discord:b"}], pairs)[0]
        return resolver.promote(cand, analyst="M. Dismukes")

    def test_save_and_reload_round_trip(self, database):
        case_id = database.create_case("phase3 case", analyst="M. Dismukes")
        entity = self._entity(case_id)
        database.save_entity(entity)
        stored = database.get_case_entities(case_id)
        assert len(stored) == 1
        rebuilt = entity_from_row(stored[0]["entity"], stored[0]["members"])
        assert rebuilt.entity_id == entity.entity_id
        assert {m.profile_id for m in rebuilt.members} == \
               {m.profile_id for m in entity.members}
        assert rebuilt.members[0].justification.supporting_edges

    def test_promotion_lands_in_custody_chain(self, database):
        from core.case_log import ChainOfCustodyLog
        case_id = database.create_case("phase3 chain", analyst="M. Dismukes")
        entity = self._entity(case_id)
        database.save_entity(entity)
        conn = database.get_connection()
        rows = conn.execute(
            "SELECT action, analyst, notes FROM evidence_log "
            "WHERE action = 'entity_promoted'").fetchall()
        assert len(rows) == 1
        assert rows[0]["analyst"] == "M. Dismukes"
        assert entity.entity_id in rows[0]["notes"]
        verdict = ChainOfCustodyLog(connection=conn).verify()
        assert verdict["intact"], (
            "custody chain must verify intact, broke at "
            + str(verdict["broken_at_log_id"]))

    def test_entities_scoped_to_their_case(self, database):
        case_a = database.create_case("case a", analyst="M. Dismukes")
        case_b = database.create_case("case b", analyst="M. Dismukes")
        database.save_entity(self._entity(case_a))
        assert len(database.get_case_entities(case_a)) == 1
        assert database.get_case_entities(case_b) == []
