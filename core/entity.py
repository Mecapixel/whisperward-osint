"""
WhisperWard — Unified Entity Model and Resolver
Platform Phase 3, Milestone 1
Pixora Inc.

This module promotes the Entity contract in core/contracts.py to a real data
model. Until now the correlation engine produced pairwise leads and clusters of
profile identifiers, but nothing in the system represented a resolved identity:
one actor holding several platform accounts, with the reasons for believing so
attached to the record itself.

The design follows the same discipline as every other analytical layer in
WhisperWard. The resolver never asserts identity on its own. It proposes entity
candidates from correlation output, each membership carrying its full
justification: which pairwise edges support it, at what strength, with which
signals, and whether any contradiction was observed. Promotion of a candidate to
a resolved entity is an explicit analyst action. It requires an analyst name,
and the promotion is recorded in the tamper-evident chain of custody exactly
like any other consequential case action. A cluster the machine grouped is a
lead. An entity is a human decision with the machine's evidence attached.

A contradiction observed on any supporting edge blocks automatic candidacy of
that pairing. The contradicted account is excluded from the candidate and the
exclusion is recorded, because silently averaging away conflicting evidence is
exactly the failure mode the correlation engine's contradiction detector exists
to prevent.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _split_profile_id(profile_id: str) -> tuple[str, str]:
    """Profile identifiers follow the platform:username convention used by the
    correlation pipeline. A malformed identifier degrades to an unknown
    platform rather than failing, since the identifier itself remains the
    stable key either way."""
    if ":" in profile_id:
        platform, username = profile_id.split(":", 1)
        return platform or "unknown", username
    return "unknown", profile_id


@dataclass
class MembershipJustification:
    """The evidence trail for one account's membership in an entity. Every
    supporting edge names the paired account, the fused correlation strength,
    whether the pair cleared the lead threshold, the top contributing signals,
    and any contradiction note. Nothing here is a bare number."""
    supporting_edges: list[dict] = field(default_factory=list)

    def add_edge(self, other_profile: str, strength: float, is_lead: bool,
                 top_signals: list[str], contradiction_note: str = "") -> None:
        self.supporting_edges.append({
            "with": other_profile,
            "strength": round(float(strength), 4),
            "is_lead": bool(is_lead),
            "top_signals": list(top_signals),
            "contradiction_note": contradiction_note or "",
        })

    def to_dict(self) -> dict:
        return {"supporting_edges": [dict(e) for e in self.supporting_edges]}


@dataclass
class EntityMember:
    """A single platform account inside an entity, with its justification."""
    profile_id: str
    platform: str
    username: str
    justification: MembershipJustification = field(
        default_factory=MembershipJustification)

    def to_dict(self) -> dict:
        return {
            "profile_id": self.profile_id,
            "platform": self.platform,
            "username": self.username,
            "justification": self.justification.to_dict(),
        }


@dataclass
class EntityCandidate:
    """A machine-proposed grouping awaiting human judgment. Excluded accounts
    are those a contradiction removed from the grouping, kept on the record so
    the analyst sees what the machine declined to link and why."""
    candidate_id: str
    case_id: str
    members: list[EntityMember]
    excluded: list[dict]
    mean_strength: float
    proposed_at: str

    def to_dict(self) -> dict:
        return {
            "candidate_id": self.candidate_id,
            "case_id": self.case_id,
            "members": [m.to_dict() for m in self.members],
            "excluded": [dict(e) for e in self.excluded],
            "mean_strength": round(self.mean_strength, 4),
            "proposed_at": self.proposed_at,
            "disclaimer": (
                "This is a machine-proposed grouping of correlation leads. "
                "It is not an identity determination. Promotion to a resolved "
                "entity is an explicit analyst decision recorded in the chain "
                "of custody."
            ),
        }


@dataclass
class ResolvedEntity:
    """An analyst-confirmed identity holding one or more platform accounts.
    The record keeps the machine's justification and the human decision
    together: who promoted it, when, and on what evidence."""
    entity_id: str
    case_id: str
    canonical_handle: str
    members: list[EntityMember]
    promoted_by: str
    promoted_at: str
    source_candidate_id: Optional[str] = None
    analyst_note: str = ""

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "case_id": self.case_id,
            "canonical_handle": self.canonical_handle,
            "members": [m.to_dict() for m in self.members],
            "promoted_by": self.promoted_by,
            "promoted_at": self.promoted_at,
            "source_candidate_id": self.source_candidate_id,
            "analyst_note": self.analyst_note,
        }


class EntityResolver:
    """Builds entity candidates from correlation output and promotes them to
    resolved entities on explicit analyst instruction.

    propose() consumes the cluster groups and the pairwise results that
    produced them. Only groups of two or more accounts become candidates,
    since a standalone account needs no resolution. Within a group, an account
    is included only if at least one of its supporting edges is a lead-strength
    correlation free of contradiction; an account whose every path into the
    group is contradicted is excluded and the exclusion is recorded.

    promote() converts a candidate into a ResolvedEntity. It refuses to run
    without an analyst name, because entity resolution is a human decision and
    an unattributed decision is not defensible.
    """

    def __init__(self, lead_threshold: float = 0.0):
        # A non-zero threshold lets a caller demand stronger evidence than the
        # engine's own is_lead flag. Zero defers entirely to the engine.
        self.lead_threshold = float(lead_threshold)

    # ---------------------------------------------------------- proposal

    def propose(self, case_id: str, groups: list, pairwise: list) -> list[EntityCandidate]:
        """groups: list of sets/lists of profile ids (ClusterResult.groups or
        the equivalent from a sealed correlation artifact). pairwise: list of
        CorrelationResult objects or their to_dict() forms."""
        edges = [self._normalize_pair(p) for p in pairwise]
        candidates: list[EntityCandidate] = []

        for group in groups:
            members_ids = sorted(group)
            if len(members_ids) < 2:
                continue
            included: list[EntityMember] = []
            excluded: list[dict] = []
            strengths: list[float] = []

            for pid in members_ids:
                justification = MembershipJustification()
                has_clean_lead = False
                contradiction_reasons: list[str] = []

                for edge in edges:
                    if pid not in (edge["profile_a"], edge["profile_b"]):
                        continue
                    other = edge["profile_b"] if edge["profile_a"] == pid else edge["profile_a"]
                    if other not in members_ids:
                        continue
                    justification.add_edge(
                        other_profile=other,
                        strength=edge["correlation_strength"],
                        is_lead=edge["is_lead"],
                        top_signals=edge["top_signals"],
                        contradiction_note=edge["contradiction_note"],
                    )
                    if edge["contradiction_note"]:
                        contradiction_reasons.append(
                            pid + " ↔ " + other + ": " + edge["contradiction_note"])
                    elif edge["is_lead"] and edge["correlation_strength"] >= self.lead_threshold:
                        has_clean_lead = True
                        strengths.append(edge["correlation_strength"])

                if has_clean_lead:
                    platform, username = _split_profile_id(pid)
                    included.append(EntityMember(
                        profile_id=pid, platform=platform, username=username,
                        justification=justification))
                else:
                    reason = ("every supporting correlation carries a "
                              "contradiction" if contradiction_reasons else
                              "no uncontradicted lead-strength correlation "
                              "supports this membership")
                    excluded.append({
                        "profile_id": pid,
                        "reason": reason,
                        "details": contradiction_reasons,
                    })

            if len(included) >= 2:
                candidates.append(EntityCandidate(
                    candidate_id="ENT-CAND-" + uuid.uuid4().hex[:8].upper(),
                    case_id=case_id,
                    members=included,
                    excluded=excluded,
                    mean_strength=(sum(strengths) / len(strengths)) if strengths else 0.0,
                    proposed_at=_utc_now_iso(),
                ))
        return candidates

    # ---------------------------------------------------------- promotion

    def promote(self, candidate: EntityCandidate, analyst: str,
                canonical_handle: Optional[str] = None,
                analyst_note: str = "") -> ResolvedEntity:
        if not analyst or not str(analyst).strip():
            raise ValueError(
                "Entity promotion requires an analyst name. Resolution is a "
                "human decision and must be attributable.")
        if len(candidate.members) < 2:
            raise ValueError(
                "A resolved entity requires at least two member accounts.")
        handle = canonical_handle or candidate.members[0].username
        return ResolvedEntity(
            entity_id="ENT-" + uuid.uuid4().hex[:8].upper(),
            case_id=candidate.case_id,
            canonical_handle=handle,
            members=list(candidate.members),
            promoted_by=str(analyst).strip(),
            promoted_at=_utc_now_iso(),
            source_candidate_id=candidate.candidate_id,
            analyst_note=analyst_note or "",
        )

    # ---------------------------------------------------------- helpers

    @staticmethod
    def _normalize_pair(pair) -> dict:
        """Accepts a CorrelationResult or its to_dict() form and returns the
        fields candidacy reasons over, so the resolver works equally from live
        engine output and from a sealed correlation artifact."""
        if hasattr(pair, "to_dict"):
            pair = pair.to_dict()
        signals = pair.get("signals", []) or []
        ranked = sorted(
            signals,
            key=lambda s: float(s.get("raw_score", 0.0)) * float(s.get("confidence", 0.0)),
            reverse=True,
        )
        top_signals = [s.get("rationale", s.get("name", "")) for s in ranked[:2]]
        return {
            "profile_a": pair["profile_a"],
            "profile_b": pair["profile_b"],
            "correlation_strength": float(pair.get("correlation_strength", 0.0)),
            "is_lead": bool(pair.get("is_lead", False)),
            "contradiction_note": pair.get("contradiction_note", "") or "",
            "top_signals": top_signals,
        }


def candidate_from_dict(payload: dict) -> EntityCandidate:
    """Rebuild an EntityCandidate from its to_dict() form, so a candidate the
    resolver sealed into the evidence store can be promoted later by the
    analyst without re-running correlation. The justification travels back
    verbatim; the disclaimer is presentation and is not restored as data."""
    members = []
    for m in payload.get("members", []):
        justification = MembershipJustification()
        justification.supporting_edges = list(
            (m.get("justification") or {}).get("supporting_edges", []))
        members.append(EntityMember(
            profile_id=m["profile_id"],
            platform=m.get("platform", "unknown"),
            username=m.get("username", m["profile_id"]),
            justification=justification))
    return EntityCandidate(
        candidate_id=payload["candidate_id"],
        case_id=payload["case_id"],
        members=members,
        excluded=[dict(e) for e in payload.get("excluded", [])],
        mean_strength=float(payload.get("mean_strength", 0.0)),
        proposed_at=payload.get("proposed_at", ""))


def entity_from_row(row: dict, members_rows: list[dict]) -> ResolvedEntity:
    """Rebuild a ResolvedEntity from database rows. Justifications are stored
    as JSON on the member rows and restored verbatim."""
    members = []
    for m in members_rows:
        justification = MembershipJustification()
        try:
            payload = json.loads(m.get("justification") or "{}")
            justification.supporting_edges = list(payload.get("supporting_edges", []))
        except (ValueError, TypeError):
            pass
        members.append(EntityMember(
            profile_id=m["profile_id"], platform=m["platform"],
            username=m["username"], justification=justification))
    return ResolvedEntity(
        entity_id=row["entity_id"], case_id=row["case_id"],
        canonical_handle=row["canonical_handle"], members=members,
        promoted_by=row["promoted_by"], promoted_at=row["promoted_at"],
        source_candidate_id=row.get("source_candidate_id"),
        analyst_note=row.get("analyst_note") or "")
