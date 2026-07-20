"""
WhisperWard — Identity Graph
Platform Phase 3, Milestone 2
Pixora Inc.

The correlation engine produces pairwise judgments; the identity graph makes
the whole web of those judgments a first-class, queryable structure. Nodes are
platform accounts. Edges exist only where the correlation engine actually
scored a pair, and every edge carries its complete justification: the fused
strength, the lead flag, each contributing signal with its confidence and
rationale, and any contradiction note. There is no such thing as an
unexplained edge in this graph. Asking "why are these two accounts connected"
is a lookup, not an investigation.

Resolved entities from the analyst layer decorate the graph rather than
rewrite it. When an entity is attached, member nodes are labeled with its
entity_id, so the graph always distinguishes what the machine correlated from
what a human confirmed.

Serialization is deterministic (sorted nodes, sorted edges, stable key order)
because graph exports travel inside evidence packages, and evidence artifacts
must hash identically when their content is identical. A D3-shaped export is
provided for the dashboard.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import networkx as nx


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _edge_key(a: str, b: str) -> tuple[str, str]:
    """Undirected edges are stored under a sorted key so the same pair always
    lands on the same edge regardless of argument order."""
    return (a, b) if a <= b else (b, a)


@dataclass
class EdgeJustification:
    """Everything the graph knows about why two accounts are connected."""
    strength: float
    is_lead: bool
    signals: list[dict] = field(default_factory=list)
    rationale: list[str] = field(default_factory=list)
    contradiction_note: str = ""
    scored_at: str = ""

    def to_dict(self) -> dict:
        return {
            "strength": round(float(self.strength), 4),
            "is_lead": bool(self.is_lead),
            "signals": [dict(s) for s in self.signals],
            "rationale": list(self.rationale),
            "contradiction_note": self.contradiction_note,
            "scored_at": self.scored_at,
        }


class IdentityGraph:
    """A justified identity graph over one case's correlation output.

    Build it from pairwise correlation results (live CorrelationResult objects
    or their sealed to_dict() forms), optionally attach resolved entities, then
    query it: neighbors, edge justification, evidence-bearing paths between any
    two accounts, and the subgraph a single entity occupies.
    """

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.graph = nx.Graph()
        self.built_at = _utc_now_iso()

    # ------------------------------------------------------------- build

    @classmethod
    def from_correlation(cls, case_id: str, pairwise: list,
                         entities: Optional[list] = None) -> "IdentityGraph":
        graph = cls(case_id)
        for pair in pairwise:
            graph.add_correlation(pair)
        for entity in entities or []:
            graph.attach_entity(entity)
        return graph

    def add_correlation(self, pair) -> None:
        if hasattr(pair, "to_dict"):
            pair = pair.to_dict()
        a, b = pair["profile_a"], pair["profile_b"]
        for node in (a, b):
            self._ensure_node(node)
        justification = EdgeJustification(
            strength=float(pair.get("correlation_strength", 0.0)),
            is_lead=bool(pair.get("is_lead", False)),
            signals=[dict(s) for s in pair.get("signals", []) or []],
            rationale=list(pair.get("rationale", []) or []),
            contradiction_note=pair.get("contradiction_note", "") or "",
            scored_at=pair.get("scored_at", "") or "",
        )
        u, v = _edge_key(a, b)
        self.graph.add_edge(u, v, justification=justification)

    def attach_entity(self, entity) -> None:
        """Label member nodes with an analyst-resolved entity. Accepts a
        ResolvedEntity or its to_dict() form. Nodes that don't exist yet are
        created, since an entity may reference accounts the current pairwise
        set didn't cover."""
        if hasattr(entity, "to_dict"):
            entity = entity.to_dict()
        entity_id = entity["entity_id"]
        for member in entity.get("members", []):
            node = member["profile_id"]
            self._ensure_node(node)
            self.graph.nodes[node]["entity_id"] = entity_id
            self.graph.nodes[node]["canonical_handle"] = entity.get(
                "canonical_handle", "")

    def _ensure_node(self, profile_id: str) -> None:
        if profile_id not in self.graph:
            platform = profile_id.split(":", 1)[0] if ":" in profile_id else "unknown"
            username = profile_id.split(":", 1)[1] if ":" in profile_id else profile_id
            self.graph.add_node(profile_id, platform=platform,
                                username=username, entity_id=None,
                                canonical_handle="")

    # ------------------------------------------------------------ queries

    def nodes(self) -> list[str]:
        return sorted(self.graph.nodes)

    def neighbors(self, profile_id: str) -> list[str]:
        if profile_id not in self.graph:
            return []
        return sorted(self.graph.neighbors(profile_id))

    def edge_justification(self, a: str, b: str) -> Optional[EdgeJustification]:
        u, v = _edge_key(a, b)
        if self.graph.has_edge(u, v):
            return self.graph.edges[u, v]["justification"]
        return None

    def path_with_evidence(self, a: str, b: str,
                           leads_only: bool = False) -> Optional[dict]:
        """Shortest path between two accounts, returned with the justification
        of every edge along it, so a path is itself an evidence trail. With
        leads_only, the path may only traverse lead-strength edges — the
        difference between 'these accounts are loosely reachable' and 'these
        accounts are connected by analyst-attention correlations'."""
        if a not in self.graph or b not in self.graph:
            return None
        working = self.graph
        if leads_only:
            working = nx.Graph()
            working.add_nodes_from(self.graph.nodes(data=True))
            for u, v, data in self.graph.edges(data=True):
                if data["justification"].is_lead:
                    working.add_edge(u, v, justification=data["justification"])
        try:
            node_path = nx.shortest_path(working, a, b)
        except nx.NetworkXNoPath:
            return None
        hops = []
        for u, v in zip(node_path, node_path[1:]):
            hops.append({
                "from": u, "to": v,
                "justification": working.edges[_edge_key(u, v)]["justification"].to_dict(),
            })
        return {"nodes": node_path, "hops": hops, "leads_only": leads_only}

    def entity_subgraph(self, entity_id: str) -> dict:
        members = sorted(n for n, d in self.graph.nodes(data=True)
                         if d.get("entity_id") == entity_id)
        edges = []
        for u, v, data in self.graph.edges(data=True):
            if u in members and v in members:
                u2, v2 = _edge_key(u, v)
                edges.append({"from": u2, "to": v2,
                              "justification": data["justification"].to_dict()})
        edges.sort(key=lambda e: (e["from"], e["to"]))
        return {"entity_id": entity_id, "members": members, "edges": edges}

    def lead_edge_count(self, contradiction_free: bool = True) -> int:
        count = 0
        for _, _, data in self.graph.edges(data=True):
            j = data["justification"]
            if j.is_lead and (not contradiction_free or not j.contradiction_note):
                count += 1
        return count

    def has_contradictions(self) -> bool:
        return any(data["justification"].contradiction_note
                   for _, _, data in self.graph.edges(data=True))

    def platforms_connected_by_leads(self) -> set[str]:
        """The set of platforms reachable through contradiction-free lead
        edges — the graph-derived counterpart to the risk engine's flat
        platform_count, used by graph-aware risk in Milestone 4."""
        platforms: set[str] = set()
        for u, v, data in self.graph.edges(data=True):
            j = data["justification"]
            if j.is_lead and not j.contradiction_note:
                platforms.add(self.graph.nodes[u]["platform"])
                platforms.add(self.graph.nodes[v]["platform"])
        return platforms

    def max_lead_strength(self) -> float:
        strengths = [data["justification"].strength
                     for _, _, data in self.graph.edges(data=True)
                     if data["justification"].is_lead
                     and not data["justification"].contradiction_note]
        return max(strengths) if strengths else 0.0

    def risk_inputs(self) -> dict:
        """Platform Phase 3 M4: the graph-derived inputs the risk engine's
        cross-platform component reasons over. Keys match the graph_* fields
        on RiskSignals, so wiring is a dict-unpack:

            signals = RiskSignals(..., **graph.risk_inputs())

        Only contradiction-free lead edges count toward corroboration;
        contradicted edges are reported separately so the engine can cap
        confidence without ever letting a contradiction change a score."""
        return {
            "graph_lead_platforms": len(self.platforms_connected_by_leads()),
            "graph_lead_edge_count": self.lead_edge_count(contradiction_free=True),
            "graph_max_lead_strength": self.max_lead_strength(),
            "graph_has_contradictions": self.has_contradictions(),
        }

    # ------------------------------------------------------ serialization

    def to_dict(self) -> dict:
        nodes = []
        for node in sorted(self.graph.nodes):
            data = self.graph.nodes[node]
            nodes.append({
                "id": node,
                "platform": data.get("platform", "unknown"),
                "username": data.get("username", node),
                "entity_id": data.get("entity_id"),
                "canonical_handle": data.get("canonical_handle", ""),
            })
        edges = []
        for u, v, data in self.graph.edges(data=True):
            u2, v2 = _edge_key(u, v)
            edges.append({"from": u2, "to": v2,
                          "justification": data["justification"].to_dict()})
        edges.sort(key=lambda e: (e["from"], e["to"]))
        return {
            "case_id": self.case_id,
            "built_at": self.built_at,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": nodes,
            "edges": edges,
            "disclaimer": (
                "Edges are correlation leads with supporting evidence, not "
                "assertions of shared identity. Entity labels record explicit "
                "analyst decisions."
            ),
        }

    def to_canonical_json(self) -> str:
        """Byte-stable serialization for evidence packaging: identical graph
        content always produces identical bytes and therefore an identical
        SHA-256."""
        payload = self.to_dict()
        payload = dict(payload)
        payload.pop("built_at", None)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def to_d3(self) -> dict:
        """The shape the dashboard's D3 force layout consumes."""
        payload = self.to_dict()
        return {
            "nodes": [
                {"id": n["id"], "platform": n["platform"],
                 "username": n["username"], "entity": n["entity_id"]}
                for n in payload["nodes"]
            ],
            "links": [
                {"source": e["from"], "target": e["to"],
                 "strength": e["justification"]["strength"],
                 "lead": e["justification"]["is_lead"],
                 "contradicted": bool(e["justification"]["contradiction_note"])}
                for e in payload["edges"]
            ],
        }
