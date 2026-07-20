"""
Platform Phase 3, Milestone 3 — Auto-built investigation timeline.

The contract under test: the timeline is reconstructive, ordered, sourced row
by row, and never invents events. Case lifecycle, artifacts, analyses,
custody entries, analyst notes, and entity promotions all appear.
"""

import os

import pytest

from core.timeline import InvestigationTimeline, _normalize_utc


@pytest.fixture()
def database(tmp_path, monkeypatch):
    from database.db_manager import DatabaseManager
    monkeypatch.chdir(os.path.dirname(os.path.dirname(__file__)))
    db = DatabaseManager(db_path=str(tmp_path / "timeline.db"))
    db.init()
    yield db
    db.close()


@pytest.fixture()
def populated_case(database):
    case_id = database.create_case("timeline case", analyst="M. Dismukes")
    database.add_target(case_id, "roblox", "shadowfox")
    targets = database.get_case_targets(case_id)
    target_id = targets[0]["target_id"]
    database.save_artifact(target_id=target_id, module_name="RobloxOSINT",
                           artifact_type="profile",
                           raw_data={"description": "hello"})
    database.save_analysis(target_id, {"analysis_type": "behavioral",
                                       "findings": {}, "risk_score": 4.2})
    from core.analyst_notes import AnalystNotes
    notes = AnalystNotes(connection=database.get_connection())
    notes.add(case_id, analyst="M. Dismukes",
              note="reviewed profile description", finding_ref="overall_assessment")
    return case_id, target_id


class TestNormalization:
    def test_naive_sqlite_timestamp_labeled_utc(self):
        out = _normalize_utc("2026-07-20 01:02:03")
        assert out.endswith("+00:00")
        assert out.startswith("2026-07-20T01:02:03")

    def test_aware_timestamp_converted_to_utc(self):
        out = _normalize_utc("2026-07-20T01:02:03-04:00")
        assert out == "2026-07-20T05:02:03+00:00"

    def test_unparseable_timestamp_survives(self):
        assert _normalize_utc("not a time") == "not a time"

    def test_empty_timestamp(self):
        assert _normalize_utc(None) == ""


class TestReconstruction:
    def test_lifecycle_events_present(self, database, populated_case):
        case_id, target_id = populated_case
        timeline = InvestigationTimeline.build(database, case_id)
        kinds = {e.kind for e in timeline.events}
        assert "case_opened" in kinds
        assert "target_added" in kinds
        assert "artifact_collected" in kinds
        assert "analysis_recorded" in kinds
        assert "analyst_note" in kinds
        assert any(k.startswith("custody_") for k in kinds)

    def test_events_are_ordered(self, database, populated_case):
        case_id, _ = populated_case
        timeline = InvestigationTimeline.build(database, case_id)
        stamps = [e.timestamp for e in timeline.events]
        assert stamps == sorted(stamps)

    def test_every_event_names_its_source_row(self, database, populated_case):
        case_id, _ = populated_case
        timeline = InvestigationTimeline.build(database, case_id)
        for event in timeline.events:
            assert event.source_table
            assert event.source_ref

    def test_analysis_event_carries_risk_score(self, database, populated_case):
        case_id, _ = populated_case
        timeline = InvestigationTimeline.build(database, case_id)
        analyses = timeline.filter(kind="analysis_recorded")
        assert len(analyses) == 1
        assert analyses[0].detail["risk_score"] == pytest.approx(4.2)

    def test_entity_promotion_appears(self, database, populated_case):
        case_id, _ = populated_case
        from core.entity import EntityResolver
        from tests.test_entity_resolution import make_pair
        resolver = EntityResolver()
        pairs = [make_pair("roblox:a", "discord:b", 0.8, True)]
        cand = resolver.propose(case_id, [{"roblox:a", "discord:b"}], pairs)[0]
        database.save_entity(resolver.promote(cand, analyst="M. Dismukes"))
        timeline = InvestigationTimeline.build(database, case_id)
        promotions = timeline.filter(kind="entity_promoted")
        assert len(promotions) >= 1
        assert promotions[0].analyst == "M. Dismukes"

    def test_other_cases_do_not_leak_in(self, database, populated_case):
        case_id, _ = populated_case
        other = database.create_case("unrelated", analyst="M. Dismukes")
        database.add_target(other, "roblox", "unrelated_user")
        timeline = InvestigationTimeline.build(database, case_id)
        for event in timeline.events:
            assert "unrelated_user" not in event.description

    def test_filter_by_target(self, database, populated_case):
        case_id, target_id = populated_case
        timeline = InvestigationTimeline.build(database, case_id)
        scoped = timeline.filter(target_id=target_id)
        assert scoped
        assert all(e.target_id == target_id for e in scoped)


class TestSerialization:
    def test_to_dict_declares_provenance(self, database, populated_case):
        case_id, _ = populated_case
        payload = InvestigationTimeline.build(database, case_id).to_dict()
        assert payload["event_count"] == len(payload["events"])
        assert "no event is inferred" in payload["provenance"]

    def test_canonical_json_stable_for_same_content(self, database, populated_case):
        case_id, _ = populated_case
        t1 = InvestigationTimeline.build(database, case_id)
        t2 = InvestigationTimeline.build(database, case_id)
        assert t1.to_canonical_json() == t2.to_canonical_json()
