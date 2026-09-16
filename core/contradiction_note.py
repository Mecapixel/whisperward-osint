"""
core/contradiction_note.py
WhisperWard OSINT — Contradiction note normalization

A contradiction note is the CorrelationEngine's record of evidence that
argues AGAINST two profiles sharing an operator. Every downstream consumer
(identity graph, entity resolver, persistence graph, STIX export, CLI
rendering) tests the field for truthiness: a non-empty note means the pair
is contradicted and is excluded from corroboration.

The engine historically emitted the sentence "no contradictions detected"
for a clean pair, which is truthy, so every clean pair read as contradicted.
This module is the single place that defines what "clean" looks like, so the
engine can emit an empty string and every consumer can still ingest sealed
correlation records written before the fix.
"""

from __future__ import annotations

# Every spelling a clean pair has ever carried. Sealed correlation output
# from cases scored before the fix still holds the sentence form.
CLEAN_CONTRADICTION_NOTES: frozenset[str] = frozenset({
    "",
    "no contradictions detected",
    "no contradiction detected",
    "none",
})


def is_clean_contradiction_note(note) -> bool:
    """True when the note records no contradiction."""
    if not note:
        return True
    return str(note).strip().lower() in CLEAN_CONTRADICTION_NOTES


def normalize_contradiction_note(note) -> str:
    """Return "" for a clean note, otherwise the stripped note text.

    Consumers call this at ingest so a truthiness test on the result is a
    correct contradiction test regardless of which spelling was sealed.
    """
    if is_clean_contradiction_note(note):
        return ""
    return str(note).strip()
