"""
Platform Phase 3, Milestone 2 — Identity graph with justified edges.

The contract under test: no unexplained edges, deterministic serialization,
and queries whose answers are evidence trails rather than bare structure.
"""

import pytest

from core.identity_graph import IdentityGraph


def pair(a, b, strength, is_lead, contradiction=""):
    return {
        "profile_a": a, "profile_b": b,
        "correlation_strength": strength, "is_lead": is_lead,
        "contradiction_note": contradiction,
        "scored_at": "2026-07-20T00:00:00+00:00",
        "rationale": [f"{a} and {b} share signal evidence"],
        "signals": [{"name": "username", "raw_score": strength,
                     "confidence": 0.9, "rationale": "handle similarity"}],
    }


@pytest.fixture()
def graph():
    pairs = [
        pair("roblox:shadowfox", "discord:shadow_fox", 0.85, True),
        pair("discord:shadow_fox", "steam:sfox", 0.72, True),
        pair("roblox:shadowfox", "roblox:brightowl", 0.20, False),
        pair("steam:sfox", "roblox:brightowl", 0.68, True,
             contradiction="disjoint active hours observed simultaneously"),
    ]
    return IdentityGraph.from_correlation("CASE-G1", pairs)


class TestStructure:
    def test_nodes_and_edges_present(self, graph):
        assert len(graph.nodes()) == 4
        assert graph.graph.number_of_edges() == 4

    def test_every_edge_carries_justification(self, graph):
        for u, v, data in graph.graph.edges(data=True):
            j = data["justification"]
            assert j.signals, f"edge {u}-{v} has no signals"
            assert 0.0 <= j.strength <= 1.0

    def test_edge_justification_lookup_is_order_independent(self, graph):
        a = graph.edge_justification("roblox:shadowfox", "discord:shadow_fox")
        b = graph.edge_justification("discord:shadow_fox", "roblox:shadowfox")
        assert a is b
        assert a.strength == pytest.approx(0.85)

    def test_missing_edge_returns_none(self, graph):
        assert graph.edge_justification("roblox:shadowfox", "steam:sfox") is None

    def test_neighbors_sorted(self, graph):
        n = graph.neighbors("discord:shadow_fox")
        assert n == sorted(n)
        assert "roblox:shadowfox" in n and "steam:sfox" in n


class TestQueries:
    def test_path_carries_evidence_per_hop(self, graph):
        path = graph.path_with_evidence("roblox:shadowfox", "steam:sfox")
        assert path is not None
        assert len(path["hops"]) >= 1
        for hop in path["hops"]:
            assert hop["justification"]["signals"]

    def test_leads_only_path_excludes_weak_edges(self, graph):
        # roblox:brightowl connects to shadowfox only via a non-lead edge and
        # to sfox via a contradicted lead; with leads_only the contradicted
        # edge still counts as a lead edge structurally, but the weak 0.20
        # edge must never appear on a leads-only path.
        path = graph.path_with_evidence("roblox:shadowfox", "roblox:brightowl",
                                        leads_only=True)
        if path is not None:
            for hop in path["hops"]:
                assert hop["justification"]["is_lead"]

    def test_lead_edge_count_excludes_contradicted_by_default(self, graph):
        assert graph.lead_edge_count() == 2
        assert graph.lead_edge_count(contradiction_free=False) == 3

    def test_has_contradictions(self, graph):
        assert graph.has_contradictions() is True

    def test_platforms_connected_by_leads(self, graph):
        platforms = graph.platforms_connected_by_leads()
        assert platforms == {"roblox", "discord", "steam"}

    def test_max_lead_strength_ignores_contradicted(self, graph):
        assert graph.max_lead_strength() == pytest.approx(0.85)


class TestEntities:
    def test_attach_entity_labels_members(self, graph):
        graph.attach_entity({
            "entity_id": "ENT-AAAA0001",
            "canonical_handle": "shadowfox",
            "members": [{"profile_id": "roblox:shadowfox"},
                        {"profile_id": "discord:shadow_fox"}],
        })
        sub = graph.entity_subgraph("ENT-AAAA0001")
        assert sub["members"] == ["discord:shadow_fox", "roblox:shadowfox"]
        assert len(sub["edges"]) == 1
        assert sub["edges"][0]["justification"]["strength"] == pytest.approx(0.85)

    def test_unlabeled_nodes_have_no_entity(self, graph):
        payload = graph.to_dict()
        assert all(n["entity_id"] is None for n in payload["nodes"])


class TestSerialization:
    def test_to_dict_is_sorted_and_disclaimed(self, graph):
        payload = graph.to_dict()
        node_ids = [n["id"] for n in payload["nodes"]]
        assert node_ids == sorted(node_ids)
        edge_keys = [(e["from"], e["to"]) for e in payload["edges"]]
        assert edge_keys == sorted(edge_keys)
        assert "not" in payload["disclaimer"]

    def test_canonical_json_is_byte_stable(self):
        pairs = [pair("roblox:a", "discord:b", 0.8, True)]
        g1 = IdentityGraph.from_correlation("CASE-G2", pairs)
        g2 = IdentityGraph.from_correlation("CASE-G2", list(reversed(pairs)))
        assert g1.to_canonical_json() == g2.to_canonical_json()

    def test_d3_export_shape(self, graph):
        d3 = graph.to_d3()
        assert set(d3.keys()) == {"nodes", "links"}
        assert all({"id", "platform", "username", "entity"} <= set(n.keys())
                   for n in d3["nodes"])
        contradicted = [l for l in d3["links"] if l["contradicted"]]
        assert len(contradicted) == 1
