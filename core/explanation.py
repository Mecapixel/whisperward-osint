"""
core/explanation.py
WhisperWard Core — Explanation Objects
Pixora Inc. | Roadmap Phase 2, Milestone 3

Promotes the Explanation contract (core/contracts.py) from a marker to a
real model. A finding stops being a string and becomes an object that
carries its reasoning, its confidence, the score component that produced
it, and references to the exact evidence records behind it — so "why" is
queryable data, not prose a reviewer must trust.

The builder links a scored RiskResult to a case's evidence through the
Phase 2 M1 custody manifest. The risk engine itself stays evidence-store
agnostic: explanations are assembled at the reporting layer, where the
case database is available.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ExplanationObject:
    """The canonical implementation of the Explanation contract.

    finding: the human-readable conclusion being explained.
    source_component: the risk-engine component (or engine stage) that
        produced the finding.
    reasoning: the enumerated reasons behind the finding, in order.
    confidence: the confidence level attached to the source component.
    evidence_refs: evidence_id values (Phase 2 M1 EvidenceRecord UUIDs)
        for the artifacts this finding rests on. Empty means the finding
        derives from computed signals rather than stored artifacts, and
        the reasoning must say so.
    """

    finding: str
    source_component: str
    reasoning: list[str] = field(default_factory=list)
    confidence: str = "medium"
    evidence_refs: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> dict:
        return {
            "finding": self.finding,
            "source_component": self.source_component,
            "reasoning": list(self.reasoning),
            "confidence": self.confidence,
            "evidence_refs": list(self.evidence_refs),
            "created_at": self.created_at,
        }


def _evidence_ids_from_manifest(custody_manifest: Optional[dict]) -> list[str]:
    if not custody_manifest:
        return []
    return [
        entry["evidence"]["evidence_id"]
        for entry in custody_manifest.get("artifacts", [])
        if entry.get("evidence", {}).get("evidence_id")
    ]


def build_explanations(
    risk_result,
    custody_manifest: Optional[dict] = None,
) -> list[ExplanationObject]:
    """Assemble ExplanationObjects for every component of a RiskResult.

    Each score component becomes one explanation: its finding is the
    component's explanation string, its reasoning is the component's
    enumerated confidence reasons, and its evidence references are the
    case's evidence records from the custody manifest. A final summary
    explanation captures the overall assessment and overall confidence.
    When no manifest is supplied, evidence_refs are empty and the
    reasoning records that the finding derives from computed signals.
    """
    evidence_ids = _evidence_ids_from_manifest(custody_manifest)
    no_store_note = (
        "derived from computed signals; no stored artifacts were linked "
        "at explanation time"
    )

    explanations: list[ExplanationObject] = []
    for component in risk_result.components:
        reasoning = list(component.confidence_reasons)
        if not evidence_ids:
            reasoning.append(no_store_note)
        explanations.append(
            ExplanationObject(
                finding=component.explanation,
                source_component=component.name,
                reasoning=reasoning,
                confidence=component.confidence,
                evidence_refs=list(evidence_ids),
            )
        )

    summary_reasoning = list(risk_result.confidence_reasons)
    if not evidence_ids:
        summary_reasoning.append(no_store_note)
    explanations.append(
        ExplanationObject(
            finding=risk_result.explanation,
            source_component="overall_assessment",
            reasoning=summary_reasoning,
            confidence=risk_result.confidence,
            evidence_refs=list(evidence_ids),
        )
    )
    return explanations
