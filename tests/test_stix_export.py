"""
Platform Phase 4, Milestone 1 — STIX 2.1 export.

The contract under test: the bundle carries only what the case record holds
(accounts, justified correlation relationships, analyst-resolved entities, one
investigation grouping); it never emits adversary-assertion object types;
confidence maps from correlation strength; contradictions travel verbatim;
and identical case content serializes to identical bytes.
"""

import json

import pytest

from core.stix_export import (StixExporter, canonical_bundle_json,
                              _confidence_from_strength)
from database.db_manager import DatabaseManager

AS_OF = "2026-07-20T12:00:00Z"

FORBIDDEN_TYPES = {"threat-actor", "malware", "attack-pattern", "indicator",
                   "intrusion-set", "campaign", "tool"}


@pytest.fixture
def seeded_db(tmp_path):
    database = DatabaseManager(db_path=str(tmp_path / "stix_test.db"))
    database.init()
    case_id = database.create_case("SYNTHETIC stix test", "synthetic", "pytest")
    database.add_target(case_id, "roblox", "synthetic_shadowfox")
    database.add_target(case_id, "discord", "synthetic_shadow_fox")
    targets = database.get_case_targets(case_id)
    a = "roblox:synthetic_shadowfox"
    b = "discord:synthetic_shadow_fox"
    payload = {
        "case_id": case_id,
        "pairwise": [{
            "profile_a": a, "profile_b": b,
            "correlation_strength": 0.85, "is_lead": True,
            "contradiction_note": "",
            "scored_at": "2026-07-20T00:00:00+00:00",
            "rationale": ["near-identical handles", "matching avatar hash"],
            "signals": [{"name": "username", "raw_score": 0.9,
                         "confidence": 0.9, "rationale": "handle similarity"}],
        }],
        "cluster": {"groups": [[a, b]]},
    }
    database.save_artifact(
        target_id=targets[0]["target_id"],
        module_name="CorrelationEngine",
        artifact_type="identity_correlation",
        raw_data=payload,
    )
    return database, case_id


def _promote_entity(database, case_id):
    from core.entity import EntityResolver
    payload = json.loads(database.get_connection().execute(
        "SELECT raw_data FROM artifacts WHERE artifact_type = "
        "'identity_correlation' ORDER BY artifact_id DESC LIMIT 1"
    ).fetchone()["raw_data"])
    resolver = EntityResolver()
    groups = [set(g) for g in payload["cluster"]["groups"]]
    candidates = resolver.propose(case_id, groups, payload["pairwise"])
    entity = resolver.promote(candidates[0], analyst="M. Dismukes",
                              analyst_note="synthetic promotion")
    database.save_entity(entity)
    return entity


def _objects_by_type(bundle_dict):
    grouped = {}
    for obj in bundle_dict["objects"]:
        grouped.setdefault(obj["type"], []).append(obj)
    return grouped


class TestBundleContent:
    def test_accounts_and_correlation_present(self, seeded_db):
        database, case_id = seeded_db
        bundle = StixExporter(as_of=AS_OF).bundle_for_case(database, case_id)
        grouped = _objects_by_type(json.loads(bundle.serialize()))
        assert len(grouped["user-account"]) == 2
        rels = grouped["relationship"]
        assert len(rels) == 1
        assert rels[0]["relationship_type"] == "related-to"
        assert rels[0]["confidence"] == 85
        assert "near-identical handles" in rels[0]["description"]

    def test_grouping_is_suspicious_activity_investigation(self, seeded_db):
        database, case_id = seeded_db
        bundle = StixExporter(as_of=AS_OF).bundle_for_case(database, case_id)
        grouped = _objects_by_type(json.loads(bundle.serialize()))
        grouping = grouped["grouping"][0]
        assert grouping["context"] == "suspicious-activity"
        # The grouping must reference every other object in the bundle.
        all_ids = {o["id"] for objs in grouped.values() for o in objs
                   if o["type"] != "grouping"}
        assert set(grouping["object_refs"]) == all_ids

    def test_never_emits_adversary_assertions(self, seeded_db):
        database, case_id = seeded_db
        _promote_entity(database, case_id)
        bundle = StixExporter(as_of=AS_OF).bundle_for_case(database, case_id)
        types = {o["type"] for o in json.loads(bundle.serialize())["objects"]}
        assert types.isdisjoint(FORBIDDEN_TYPES)

    def test_scope_statement_travels_with_the_bundle(self, seeded_db):
        database, case_id = seeded_db
        bundle = StixExporter(as_of=AS_OF).bundle_for_case(database, case_id)
        grouped = _objects_by_type(json.loads(bundle.serialize()))
        description = grouped["grouping"][0]["description"]
        assert "not assertions of shared identity" in description
        assert "No adversary" in description


class TestResolvedEntities:
    def test_entity_identity_records_analyst_decision(self, seeded_db):
        database, case_id = seeded_db
        entity = _promote_entity(database, case_id)
        bundle = StixExporter(as_of=AS_OF).bundle_for_case(database, case_id)
        grouped = _objects_by_type(json.loads(bundle.serialize()))
        identities = [i for i in grouped["identity"]
                      if i["identity_class"] == "unknown"]
        assert len(identities) == 1
        assert entity.entity_id in identities[0]["description"]
        assert "M. Dismukes" in identities[0]["description"]
        assert "does not assert a real-world identity" in identities[0]["description"]

    def test_membership_relationships_link_entity_to_accounts(self, seeded_db):
        database, case_id = seeded_db
        _promote_entity(database, case_id)
        bundle = StixExporter(as_of=AS_OF).bundle_for_case(database, case_id)
        grouped = _objects_by_type(json.loads(bundle.serialize()))
        memberships = [r for r in grouped["relationship"]
                       if "membership" in r["description"].lower()
                       or "Analyst-confirmed" in r["description"]]
        assert len(memberships) == 2


class TestDeterminism:
    def test_identical_content_identical_bytes(self, seeded_db):
        database, case_id = seeded_db
        one = canonical_bundle_json(
            StixExporter(as_of=AS_OF).bundle_for_case(database, case_id))
        two = canonical_bundle_json(
            StixExporter(as_of=AS_OF).bundle_for_case(database, case_id))
        assert one == two

    def test_contradiction_note_travels_verbatim(self, seeded_db, tmp_path):
        database, case_id = seeded_db
        targets = database.get_case_targets(case_id)
        note = "disjoint active hours observed simultaneously"
        database.save_artifact(
            target_id=targets[0]["target_id"],
            module_name="CorrelationEngine",
            artifact_type="identity_correlation",
            raw_data={"case_id": case_id, "pairwise": [{
                "profile_a": "roblox:synthetic_shadowfox",
                "profile_b": "discord:synthetic_shadow_fox",
                "correlation_strength": 0.6, "is_lead": True,
                "contradiction_note": note, "rationale": [], "signals": [],
            }], "cluster": {"groups": []}},
        )
        bundle = StixExporter(as_of=AS_OF).bundle_for_case(database, case_id)
        grouped = _objects_by_type(json.loads(bundle.serialize()))
        assert note in grouped["relationship"][0]["description"]

    def test_confidence_scale_clamped(self):
        assert _confidence_from_strength(0.85) == 85
        assert _confidence_from_strength(0.0) == 0
        assert _confidence_from_strength(1.7) == 100
        assert _confidence_from_strength(-0.2) == 0


class TestEmptyCase:
    def test_case_without_correlation_still_exports(self, tmp_path):
        database = DatabaseManager(db_path=str(tmp_path / "empty.db"))
        database.init()
        case_id = database.create_case("SYNTHETIC empty", "synthetic", "pytest")
        database.add_target(case_id, "roblox", "synthetic_solo")
        bundle = StixExporter(as_of=AS_OF).bundle_for_case(database, case_id)
        grouped = _objects_by_type(json.loads(bundle.serialize()))
        assert len(grouped["user-account"]) == 1
        assert "relationship" not in grouped
