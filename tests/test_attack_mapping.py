"""
Platform Phase 4, Milestone 2 — Honest MITRE ATT&CK mapping.

The contract under test: only signals that actually fired are mapped; grooming
findings are never mapped and always carry an explicit out-of-scope statement
pointing to the behavioral taxonomy; analogue mappings say they are analogues;
and an empty result maps to nothing.
"""

import pytest

from core.attack_mapping import (map_risk_result, taxonomy_reference,
                                 SCOPE_STATEMENT)
from core.risk_engine import RiskEngine, RiskSignals


def result_dict(**signal_kwargs):
    return RiskEngine().score(RiskSignals(**signal_kwargs)).to_dict()


class TestMappingHonesty:
    def test_grooming_is_never_mapped(self):
        result = result_dict(prior_case_flags=1, platform_count=3, is_tor=True)
        mapping = map_risk_result(result, is_tor=True)
        assert all(m["signal"] != "grooming_classifier"
                   for m in mapping["mapped"])

    def test_nothing_fires_nothing_maps(self):
        mapping = map_risk_result(result_dict())
        assert mapping["mapped"] == []

    def test_scope_statement_always_present(self):
        mapping = map_risk_result(result_dict())
        assert mapping["scope_statement"] == SCOPE_STATEMENT
        assert "outside ATT&CK's scope" in mapping["scope_statement"]

    def test_analogue_mappings_declare_themselves(self):
        result = result_dict(is_tor=True, is_vpn=True)
        mapping = map_risk_result(result, is_tor=True, is_vpn=True)
        anonymization = [m for m in mapping["mapped"]
                        if m["signal"].startswith("anonymization")]
        assert len(anonymization) == 2
        assert all(m["applicability"] == "analogue" for m in anonymization)
        assert all("closest standard vocabulary" in m["justification"]
                   for m in anonymization)

    def test_tor_and_vpn_distinguished(self):
        result = result_dict(is_tor=True)
        mapping = map_risk_result(result, is_tor=True, is_vpn=False)
        ids = {m["technique_id"] for m in mapping["mapped"]}
        assert "T1090.003" in ids
        assert "T1090" not in {m["technique_id"] for m in mapping["mapped"]
                               if m["signal"] == "anonymization_vpn"}


class TestSignalGating:
    def test_cross_platform_maps_to_establish_accounts(self):
        mapping = map_risk_result(result_dict(platform_count=3))
        techniques = {m["technique_id"]: m for m in mapping["mapped"]}
        assert techniques["T1585.001"]["applicability"] == "direct"

    def test_graph_uncorroborated_cross_platform_does_not_map(self):
        # The graph found no justified link: the component scores zero and the
        # ATT&CK mapping must follow the evidence the same way the score does.
        result = result_dict(platform_count=4, graph_lead_platforms=0)
        mapping = map_risk_result(result)
        assert all(m["signal"] != "cross_platform_personas"
                   for m in mapping["mapped"])

    def test_velocity_maps_only_when_scored(self):
        with_velocity = map_risk_result(
            result_dict(account_age_days=5, friend_count=0))
        assert any(m["signal"] == "new_account_velocity"
                   for m in with_velocity["mapped"])
        without = map_risk_result(result_dict(account_age_days=2000))
        assert all(m["signal"] != "new_account_velocity"
                   for m in without["mapped"])

    def test_historical_flags_explicitly_unmapped(self):
        mapping = map_risk_result(result_dict(prior_case_flags=2))
        unmapped = {u["signal"]: u for u in mapping["unmapped"]}
        assert "historical_signals" in unmapped
        assert "no ATT&CK technique" in unmapped["historical_signals"]["reason"]


class TestGroomingOutOfScope:
    def test_grooming_finding_points_to_taxonomy(self):
        from core.contracts import Decision

        class FakeClassifierResult:
            grooming_score = 0.5
            message_count = 10
            flagged_message_count = 3
            decision = Decision.REVIEW
            detected_patterns = []
            category_scores = {}
            top_signals = ["secrecy_solicitation"]
            analysis_notes = ""

            def to_dict(self):
                return {}

        result = RiskEngine().score(
            RiskSignals(classifier_result=FakeClassifierResult())).to_dict()
        mapping = map_risk_result(result)
        unmapped = {u["signal"]: u for u in mapping["unmapped"]}
        assert "grooming_classifier" in unmapped
        assert unmapped["grooming_classifier"]["documented_in"] == \
            "docs/BEHAVIORAL_INDICATORS.md"
        assert "outside ATT&CK" in unmapped["grooming_classifier"]["reason"] \
            or "no technique for this conduct" in \
            unmapped["grooming_classifier"]["reason"]


class TestReferenceTable:
    def test_reference_covers_both_sides(self):
        reference = taxonomy_reference()
        assert len(reference["mappable"]) == 4
        assert len(reference["out_of_scope"]) == 2
        assert any(u["signal"] == "grooming_classifier"
                   for u in reference["out_of_scope"])

    def test_reference_matches_doc_location(self):
        reference = taxonomy_reference()
        grooming = next(u for u in reference["out_of_scope"]
                        if u["signal"] == "grooming_classifier")
        assert grooming["documented_in"] == "docs/BEHAVIORAL_INDICATORS.md"
