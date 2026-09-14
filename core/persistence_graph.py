"""
core/persistence_graph.py

The persistence layer that account level enforcement does not touch.

IdentityGraph answers whether two accounts belong to the same operator. It is
built on an undirected graph, so it deliberately discards direction: the edge
between two correlated profiles is the same edge regardless of which came first.
That is correct for correlation and wrong for persistence.

This module answers a different question. When an account is removed and the
operator returns, which account replaced which, how quickly, and across which
platforms. Those relationships are directed and temporally ordered, so they live
in a DiGraph here rather than being forced into the correlation graph.

Why it matters. A single removed account is an enforcement success on paper. A
chain of six accounts, each created within hours of the previous removal, is
evidence that enforcement failed and that the operation was never disrupted.
The chain is the artifact that changes a platform's response, and it is the
artifact a referral needs in order to show an ongoing course of conduct rather
than an isolated incident.

Evidence discipline. Succession and handoff edges reuse EdgeJustification from
core.identity_graph rather than inventing a parallel evidence model. An edge
without a rationale is refused at construction. Inference from correlation
output is held to a configurable strength floor and every inferred edge records
that it was inferred, so an analyst can separate observed successions from
suggested ones.

Correlation is not attribution. A chain in this module describes accounts
believed to be operated in coordination. It does not identify a natural person
and no method here accepts a legal name.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable, Optional

import networkx as nx

from core.identity_graph import EdgeJustification


SUCCEEDED_BY = "succeeded_by"
HANDED_OFF_TO = "handed_off_to"

DEFAULT_INFERENCE_FLOOR = 0.65
DEFAULT_RECONSTITUTION_WINDOW_DAYS = 30


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_ts(value) -> Optional[datetime]:
    """Parse an ISO timestamp into an aware UTC datetime. Returns None on
    anything unparseable, because a missing timestamp is a normal condition in
    open source collection and must not raise."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class AccountStatus(str, Enum):
    """Observed state of an account at last check. UNKNOWN is the honest default
    for an account whose status was never confirmed."""

    ACTIVE = "active"
    DORMANT = "dormant"
    SUSPENDED = "suspended"
    REMOVED = "removed"
    UNKNOWN = "unknown"


class PersistenceError(ValueError):
    """Raised when an edge would violate an evidence or ordering rule."""


@dataclass
class AccountState:
    """
    Temporal state for one profile. profile_id follows the same
    platform:username convention IdentityGraph uses, so nodes align across both
    graphs without translation.
    """

    profile_id: str
    status: AccountStatus = AccountStatus.UNKNOWN
    first_observed: str = ""
    created_at: str = ""
    removed_at: str = ""
    last_observed: str = ""

    @property
    def platform(self) -> str:
        return self.profile_id.split(":", 1)[0] if ":" in self.profile_id else "unknown"

    @property
    def username(self) -> str:
        return self.profile_id.split(":", 1)[1] if ":" in self.profile_id else self.profile_id

    def to_dict(self) -> dict:
        return {
            "profile_id": self.profile_id,
            "platform": self.platform,
            "username": self.username,
            "status": self.status.value,
            "first_observed": self.first_observed,
            "created_at": self.created_at,
            "removed_at": self.removed_at,
            "last_observed": self.last_observed,
        }


@dataclass
class SuccessionLink:
    """One directed link from a predecessor account to the account that replaced
    it. gap_seconds is the interval between the predecessor's removal and the
    successor's creation, and is None when either timestamp is unavailable."""

    predecessor: str
    successor: str
    justification: EdgeJustification
    inferred: bool = False
    gap_seconds: Optional[float] = None
    recorded_at: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> dict:
        return {
            "predecessor": self.predecessor,
            "successor": self.successor,
            "inferred": self.inferred,
            "gap_seconds": self.gap_seconds,
            "gap_hours": round(self.gap_seconds / 3600.0, 2) if self.gap_seconds is not None else None,
            "recorded_at": self.recorded_at,
            "justification": self.justification.to_dict(),
        }


@dataclass
class HandoffLink:
    """A contact migrating from one platform surface to another. Same platform
    moves are not handoffs and are refused, because the pattern of interest is
    movement off a moderated surface."""

    source: str
    destination: str
    justification: EdgeJustification
    observed_at: str = ""
    recorded_at: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "destination": self.destination,
            "observed_at": self.observed_at,
            "recorded_at": self.recorded_at,
            "justification": self.justification.to_dict(),
        }


def _require_justification(justification: EdgeJustification, label: str) -> None:
    if justification is None:
        raise PersistenceError(f"{label} requires an EdgeJustification")
    if not justification.rationale:
        raise PersistenceError(
            f"{label} requires a non-empty rationale; unsupported edges are not permitted"
        )


class PersistenceGraph:
    """
    A directed graph of succession and handoff relationships for one case.

    Build it from observed links, or infer succession from correlation output
    with infer_successions. Query it for reconstitution chains, the interval
    between removal and return, and cross platform migration.
    """

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.graph = nx.DiGraph()
        self.states: dict[str, AccountState] = {}
        self.built_at = _utc_now_iso()

    # ------------------------------------------------------------- build

    def upsert_account(self, state: AccountState) -> AccountState:
        """Register or update an account's temporal state and ensure its node."""
        existing = self.states.get(state.profile_id)
        if existing:
            for attribute in ("status", "first_observed", "created_at", "removed_at", "last_observed"):
                value = getattr(state, attribute)
                if value not in ("", None, AccountStatus.UNKNOWN):
                    setattr(existing, attribute, value)
            state = existing
        else:
            self.states[state.profile_id] = state
        self.graph.add_node(
            state.profile_id,
            platform=state.platform,
            username=state.username,
            status=state.status.value,
            removed_at=state.removed_at,
            created_at=state.created_at,
        )
        return state

    def _ensure_node(self, profile_id: str) -> AccountState:
        if profile_id not in self.states:
            return self.upsert_account(AccountState(profile_id=profile_id))
        return self.states[profile_id]

    def _gap_seconds(self, predecessor: str, successor: str) -> Optional[float]:
        removed = _parse_ts(self.states.get(predecessor, AccountState(predecessor)).removed_at)
        created = _parse_ts(self.states.get(successor, AccountState(successor)).created_at)
        if removed is None or created is None:
            return None
        return (created - removed).total_seconds()

    def add_succession(self, predecessor: str, successor: str,
                       justification: EdgeJustification,
                       inferred: bool = False) -> SuccessionLink:
        """
        Record that successor replaced predecessor.

        Refuses a self edge, refuses an edge lacking a rationale, and refuses any
        edge that would create a cycle, since a succession chain is temporally
        ordered and a cycle means the ordering is wrong.
        """
        if predecessor == successor:
            raise PersistenceError("an account cannot succeed itself")
        _require_justification(justification, "succession")
        self._ensure_node(predecessor)
        self._ensure_node(successor)

        if self.graph.has_node(successor) and nx.has_path(self.graph, successor, predecessor):
            raise PersistenceError(
                f"succession {predecessor} -> {successor} would create a cycle; "
                "review the ordering of removal and creation timestamps"
            )

        link = SuccessionLink(
            predecessor=predecessor,
            successor=successor,
            justification=justification,
            inferred=inferred,
            gap_seconds=self._gap_seconds(predecessor, successor),
        )
        self.graph.add_edge(predecessor, successor, relation=SUCCEEDED_BY, link=link)
        return link

    def add_handoff(self, source: str, destination: str,
                    justification: EdgeJustification,
                    observed_at: str = "") -> HandoffLink:
        """Record a contact moving from one platform surface to another."""
        if source == destination:
            raise PersistenceError("a handoff requires two distinct endpoints")
        _require_justification(justification, "handoff")
        source_state = self._ensure_node(source)
        destination_state = self._ensure_node(destination)
        if source_state.platform == destination_state.platform:
            raise PersistenceError(
                "same platform movement is not a handoff; the pattern of interest "
                "is migration off a moderated surface"
            )
        link = HandoffLink(
            source=source,
            destination=destination,
            justification=justification,
            observed_at=observed_at or _utc_now_iso(),
        )
        self.graph.add_edge(source, destination, relation=HANDED_OFF_TO, link=link)
        return link

    def infer_successions(self, pairwise: Iterable,
                          strength_floor: float = DEFAULT_INFERENCE_FLOOR,
                          window_days: int = DEFAULT_RECONSTITUTION_WINDOW_DAYS,
                          require_lead: bool = False) -> list[SuccessionLink]:
        """
        Derive succession links from correlation output.

        A pair becomes a candidate when the two accounts correlate at or above
        the strength floor, one of them was removed, and the other was created
        after that removal and within the window. Direction comes from the
        timestamps rather than from the correlation, which has none. Every link
        produced is marked inferred so an analyst can tell it apart from an
        observed succession. Pairs carrying a contradiction note are skipped.
        """
        produced: list[SuccessionLink] = []
        window_seconds = window_days * 86400

        for pair in pairwise:
            if hasattr(pair, "to_dict"):
                pair = pair.to_dict()
            if pair.get("contradiction_note"):
                continue
            strength = float(pair.get("correlation_strength", 0.0))
            if strength < strength_floor:
                continue
            if require_lead and not pair.get("is_lead", False):
                continue

            a, b = pair["profile_a"], pair["profile_b"]
            self._ensure_node(a)
            self._ensure_node(b)

            ordered = self._order_by_timestamps(a, b, window_seconds)
            if ordered is None:
                continue
            predecessor, successor = ordered

            rationale = list(pair.get("rationale", []) or [])
            rationale.append(
                f"inferred succession: {predecessor} removed before {successor} "
                f"was created, within {window_days} day window"
            )
            justification = EdgeJustification(
                strength=strength,
                is_lead=bool(pair.get("is_lead", False)),
                signals=[dict(s) for s in pair.get("signals", []) or []],
                rationale=rationale,
                contradiction_note="",
                scored_at=pair.get("scored_at", "") or "",
            )
            try:
                produced.append(self.add_succession(predecessor, successor,
                                                    justification, inferred=True))
            except PersistenceError:
                continue
        return produced

    def _order_by_timestamps(self, a: str, b: str,
                             window_seconds: float) -> Optional[tuple[str, str]]:
        """Return the pair ordered predecessor first, or None when the timestamps
        do not support a succession reading."""
        for predecessor, successor in ((a, b), (b, a)):
            removed = _parse_ts(self.states[predecessor].removed_at)
            created = _parse_ts(self.states[successor].created_at)
            if removed is None or created is None:
                continue
            gap = (created - removed).total_seconds()
            if 0 <= gap <= window_seconds:
                return predecessor, successor
        return None

    # ------------------------------------------------------------ queries

    def succession_edges(self) -> list[SuccessionLink]:
        return [data["link"] for _, _, data in self.graph.edges(data=True)
                if data.get("relation") == SUCCEEDED_BY]

    def handoff_edges(self) -> list[HandoffLink]:
        return [data["link"] for _, _, data in self.graph.edges(data=True)
                if data.get("relation") == HANDED_OFF_TO]

    def _succession_subgraph(self) -> nx.DiGraph:
        keep = [(u, v) for u, v, d in self.graph.edges(data=True)
                if d.get("relation") == SUCCEEDED_BY]
        subgraph = nx.DiGraph()
        subgraph.add_nodes_from(self.graph.nodes(data=True))
        for u, v in keep:
            subgraph.add_edge(u, v, **self.graph.edges[u, v])
        return subgraph

    def reconstitution_chains(self) -> list[list[str]]:
        """
        Every maximal succession path, longest first. A chain of length two is a
        single reappearance. A long chain is the demonstration that repeated
        enforcement did not disrupt the operation.
        """
        subgraph = self._succession_subgraph()
        roots = [n for n in subgraph if subgraph.in_degree(n) == 0 and subgraph.out_degree(n) > 0]
        leaves = [n for n in subgraph if subgraph.out_degree(n) == 0 and subgraph.in_degree(n) > 0]
        chains: list[list[str]] = []
        for root in roots:
            for leaf in leaves:
                for path in nx.all_simple_paths(subgraph, root, leaf):
                    chains.append(list(path))
        return sorted(chains, key=len, reverse=True)

    def longest_chain(self) -> list[str]:
        chains = self.reconstitution_chains()
        return chains[0] if chains else []

    def reconstitution_intervals(self) -> list[dict]:
        """Per link intervals between removal and return, fastest first. This is
        the number that makes the pattern legible to a platform: a return
        measured in hours is not a coincidence."""
        rows = [
            {
                "predecessor": link.predecessor,
                "successor": link.successor,
                "gap_hours": round(link.gap_seconds / 3600.0, 2),
                "inferred": link.inferred,
            }
            for link in self.succession_edges()
            if link.gap_seconds is not None
        ]
        return sorted(rows, key=lambda r: r["gap_hours"])

    def median_gap_hours(self) -> Optional[float]:
        gaps = sorted(r["gap_hours"] for r in self.reconstitution_intervals())
        if not gaps:
            return None
        middle = len(gaps) // 2
        if len(gaps) % 2:
            return gaps[middle]
        return round((gaps[middle - 1] + gaps[middle]) / 2.0, 2)

    def cross_platform_handoffs(self) -> list[dict]:
        return [
            {
                "from_platform": self.states[link.source].platform,
                "to_platform": self.states[link.destination].platform,
                "observed_at": link.observed_at,
            }
            for link in self.handoff_edges()
        ]

    def platforms_spanned(self) -> set[str]:
        return {state.platform for state in self.states.values()}

    def persistence_summary(self) -> dict:
        """The headline numbers for a report cover page."""
        chains = self.reconstitution_chains()
        successions = self.succession_edges()
        return {
            "case_id": self.case_id,
            "accounts_tracked": len(self.states),
            "removed_accounts": sum(
                1 for s in self.states.values() if s.status is AccountStatus.REMOVED
            ),
            "succession_links": len(successions),
            "inferred_links": sum(1 for link in successions if link.inferred),
            "chain_count": len(chains),
            "longest_chain_length": len(chains[0]) if chains else 0,
            "median_gap_hours": self.median_gap_hours(),
            "platforms_spanned": sorted(self.platforms_spanned()),
            "cross_platform_handoffs": len(self.handoff_edges()),
        }

    # ------------------------------------------------------------- export

    def to_dict(self) -> dict:
        """Full fidelity export for the referral path. Retains profile
        identifiers and every justification."""
        return {
            "case_id": self.case_id,
            "built_at": self.built_at,
            "view": "referral",
            "accounts": [state.to_dict() for state in self.states.values()],
            "successions": [link.to_dict() for link in self.succession_edges()],
            "handoffs": [link.to_dict() for link in self.handoff_edges()],
            "reconstitution_chains": self.reconstitution_chains(),
            "summary": self.persistence_summary(),
        }

    def to_redacted_view(self) -> dict:
        """
        Platform facing export. Profile identifiers are replaced with opaque
        chain and position labels. What survives is the shape of the persistence
        problem, which is the part with analytic value and the part that carries
        no attribution exposure.
        """
        chains = self.reconstitution_chains()
        label_of: dict[str, str] = {}
        for chain_index, chain in enumerate(chains, start=1):
            for position, node in enumerate(chain, start=1):
                label_of.setdefault(node, f"CH{chain_index}-P{position}")
        for index, node in enumerate(sorted(n for n in self.states if n not in label_of), start=1):
            label_of[node] = f"U-{index}"

        return {
            "case_id": self.case_id,
            "built_at": self.built_at,
            "view": "platform",
            "note": (
                "Account identifiers are withheld. Chains describe accounts believed "
                "to be operated in coordination and are not identifications of "
                "natural persons. Intervals describe observed timing and are not "
                "legal conclusions."
            ),
            "chains": [
                {
                    "chain": f"CH{index}",
                    "length": len(chain),
                    "platforms": sorted({self.states[n].platform for n in chain}),
                    "positions": [label_of[n] for n in chain],
                }
                for index, chain in enumerate(chains, start=1)
            ],
            "reconstitution_intervals": [
                {
                    "from_position": label_of.get(row["predecessor"], "unlabeled"),
                    "to_position": label_of.get(row["successor"], "unlabeled"),
                    "gap_hours": row["gap_hours"],
                    "inferred": row["inferred"],
                }
                for row in self.reconstitution_intervals()
            ],
            "cross_platform_handoffs": self.cross_platform_handoffs(),
            "summary": {
                key: value for key, value in self.persistence_summary().items()
                if key != "case_id"
            },
        }