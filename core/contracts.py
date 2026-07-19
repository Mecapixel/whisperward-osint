"""
core/contracts.py
WhisperWard Core — Stable Contracts
Pixora Inc. | Roadmap Phase 1

This module defines the interfaces that every specialization module depends
on. The contracts formalize shapes that already exist in the codebase; they
do not invent new fields. Where a contract's canonical implementation lives
elsewhere, the docstring says exactly where, so a reviewer can trace every
contract to running code.

The dependency rule these contracts enforce: core never imports a
specialization. A specialization imports core, implements these contracts,
and registers its capabilities through core.registry.
"""

from __future__ import annotations

from enum import Enum
from typing import Iterable, Optional, Protocol, runtime_checkable


class Decision(str, Enum):
    """Triage outcome of any behavioral classification.

    Moved here from the child-safety behavioral classifier because the
    allow / review / escalate triad is a platform-wide concept, not a
    child-safety one. Every classifier a specialization registers must
    express its verdict in these terms, which is what keeps risk scoring,
    reporting, and the human-review workflow uniform across modules.
    """

    ALLOW = "allow"
    REVIEW = "review"
    ESCALATE = "escalate"


@runtime_checkable
class ClassifierVerdict(Protocol):
    """The result shape the core risk engine consumes from any classifier.

    Canonical implementation today: ClassifierResult in
    modules/child_safety/behavioral_classifier.py. The core engine reads
    exactly these members and nothing else; a specialization may attach any
    additional fields it needs for its own reporting.
    """

    grooming_score: float  # naming note: generalizes to behavioral_score in Phase 2
    top_signals: list
    decision: Decision


@runtime_checkable
class BehavioralClassifier(Protocol):
    """A specialization-provided classifier the risk engine can invoke.

    Canonical implementation today: GroomingClassifier in
    modules/child_safety/behavioral_classifier.py, registered through
    core.registry at specialization import time and resolvable lazily by
    dotted path as a fallback (see core/registry.py).
    """

    def classify_profile(
        self,
        chat_messages: Iterable[str],
        account_age_days: Optional[int] = None,
        friend_count: Optional[int] = None,
        is_new_account: bool = False,
    ) -> ClassifierVerdict: ...


class Evidence:
    """Contract marker for evidence artifacts.

    Canonical implementation today: the evidence records produced by
    core/evidence_packager.py and persisted through database/db_manager.py
    (evidence_log table), hash-chained by core/case_log.py. Every artifact
    carries an identifier, a SHA-256 digest, a timestamp, and a source.
    Phase 2 promotes this marker to a full dataclass with a chain-of-custody
    manifest; Phase 1 records the contract without changing behavior.
    """


class Entity:
    """Contract marker for resolved identities.

    Canonical implementation today: correlation targets consumed by
    core/correlation_engine.py (username, platform accounts, avatar hash,
    writing samples, timing data). Phase 3 promotes this to a unified
    entity model with an identity graph; Phase 1 records the contract.
    """


class Case:
    """Contract marker for investigation cases.

    Canonical implementation today: the case records managed by
    database/db_manager.py and the case lifecycle in whisperward.py and
    webapp/. A case owns targets, evidence, findings, scores, and its
    chain-of-custody log.
    """


class RiskSignal:
    """Contract marker for scored risk inputs.

    Canonical implementation today: RiskSignals and ScoreComponent in
    core/risk_engine.py — every component carries its weight, its raw and
    weighted values, and a human-readable explanation string.
    """


class Explanation:
    """Contract marker for finding-level reasoning.

    Canonical implementation today: the explanation strings attached to
    every ScoreComponent in core/risk_engine.py and the rationale entries
    produced by core/correlation_engine.py. Phase 2 promotes explanations
    to first-class queryable objects linking findings to evidence.
    """
