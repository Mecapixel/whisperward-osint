# modules/risk_scoring.py
"""
WhisperWard OSINT — Risk Scoring Bridge
Phase 4, Milestone 8
Pixora Inc.

This module connects the structured RiskEngine to the live analysis pipeline.

Before this bridge, the analyze command persisted whatever numeric score the
local AI happened to emit, defaulting to a fixed value when the model returned
none. That produced scores that did not reflect the data actually collected
about a target. This module replaces that path. It reads the artifacts a scan
has already gathered, assembles them into the RiskSignals structure the
RiskEngine consumes, runs the engine, and returns an explainable RiskResult
whose every point can be traced to a weighted, documented component.

The AI analysis is preserved, but as qualitative context rather than as the
score. The numeric risk score now comes entirely from the RiskEngine, so a
reviewer can account for it. The AI summary is carried alongside in the stored
findings for the analyst to read, never silently folded into the number.

The platform specific review-only leads that the Roblox plugin emits — group
and game names that match terms worth a human's attention — are surfaced as
notes attached to the result. They are leads for review, not determinations,
so they are shown to the analyst but never added into the numeric score.

Data sources, all from artifacts a scan already persisted:
    platform_count     Sherlock username_correlation artifact, platforms_found
    friend_count       RobloxOSINT profile artifact, friend_count
    account_age_days    computed from the RobloxOSINT profile created timestamp
    game_history_flags  count of Roblox games/groups whose names match the
                        plugin's conservative review terms
    chat text           the profile description, the only public text collected;
                        scanned by the grooming classifier as a single message
    is_tor / is_vpn     not present in this path yet, left False
    prior_case_flags    not cross-referenced yet, left 0

Anything absent degrades to a neutral value rather than failing, so a sparse
profile scores low and honestly rather than erroring.
"""

import json
from datetime import datetime, timezone
from typing import Optional

# RiskEngine and the classifier live at the repository root, not under modules/.
try:
    from core.risk_engine import RiskEngine, RiskSignals
except Exception:  # pragma: no cover - import shim for alternate layouts
    from ..risk_engine import RiskEngine, RiskSignals  # type: ignore


# Conservative review terms, kept in sync with the plugin's review-only leads.
# A match surfaces a group or game name for human review. It is never a
# determination about the space, only a reason for an analyst to look.
REVIEW_TERMS = ["condo", "scented con", "vibe", "18+", "nsfw"]


def _parse_created(created) -> Optional[int]:
    """Return account age in days from a Roblox created timestamp, or None.
    Roblox returns an ISO 8601 string such as 2008-05-24T18:00:00Z. A value that
    cannot be parsed yields None, which the engine treats as unknown rather than
    new."""
    if not created or not isinstance(created, str):
        return None
    text = created.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        # Fall back to a plain date if present.
        try:
            dt = datetime.fromisoformat(text[:10])
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - dt
    return max(0, delta.days)


def _count_review_leads(profile: dict) -> tuple[int, list[str]]:
    """Count and collect group and game names that match the review terms. The
    count feeds the engine's game_history_flags input; the names are surfaced as
    notes for the analyst. Both are review leads, not determinations."""
    leads: list[str] = []
    for collection_key, name_key in (("groups", "name"), ("games", "name")):
        for item in (profile.get(collection_key) or []):
            name = (item.get(name_key) or "")
            lowered = name.lower()
            if any(term in lowered for term in REVIEW_TERMS):
                leads.append(name)
    return len(leads), leads


def _load_target_artifacts(connection, target_id: int) -> dict:
    """Read a target's artifacts and return the Roblox profile dict and the
    Sherlock platform count. Tolerates missing artifacts by returning neutral
    defaults."""
    profile: dict = {}
    platform_count = 1

    cur = connection.execute(
        "SELECT module_name, artifact_type, raw_data FROM artifacts WHERE target_id = ?",
        (target_id,),
    )
    for row in cur.fetchall():
        module_name = row["module_name"] if "module_name" in row.keys() else row[0]
        raw_data = row["raw_data"] if "raw_data" in row.keys() else row[2]
        try:
            data = json.loads(raw_data) if isinstance(raw_data, str) else (raw_data or {})
        except (ValueError, TypeError):
            continue
        if not isinstance(data, dict):
            continue

        if module_name == "RobloxOSINT":
            # Latest profile wins; artifacts are returned in insertion order so a
            # re-scan's newer profile naturally overwrites the older one here.
            profile = data
        elif module_name == "SherlockIntegration":
            found = data.get("platforms_found")
            if isinstance(found, int) and found > platform_count:
                platform_count = found

    return {"profile": profile, "platform_count": platform_count}


def build_signals(connection, target_id: int) -> tuple[RiskSignals, list[str]]:
    """Assemble a RiskSignals object for a target from its collected artifacts.
    Returns the signals and the list of review-only lead names to surface as
    notes."""
    loaded = _load_target_artifacts(connection, target_id)
    profile = loaded["profile"]
    platform_count = loaded["platform_count"]

    friend_count = profile.get("friend_count")
    if not isinstance(friend_count, int):
        friend_count = None

    account_age_days = _parse_created(profile.get("created"))

    flag_count, lead_names = _count_review_leads(profile)

    # The only public text WhisperWard collects on Roblox is the profile
    # description. Feed it to the classifier as a single message when present.
    description = profile.get("description") or ""
    chat_messages = [description] if description.strip() else []

    signals = RiskSignals(
        chat_messages=chat_messages,
        platform_count=platform_count,
        is_tor=False,
        is_vpn=False,
        account_age_days=account_age_days,
        friend_count=friend_count,
        late_night_activity=False,
        game_history_flags=flag_count,
        prior_case_flags=0,
    )
    return signals, lead_names


def score_target(connection, target_id: int, ai_findings: Optional[dict] = None) -> dict:
    """Score a single target with the structured RiskEngine and return a result
    dict in the shape DatabaseManager.save_analysis expects.

    ai_findings, when provided, is the qualitative output of the AI engine. It is
    preserved in the stored findings as analyst context and never folded into the
    numeric score, which comes entirely from the RiskEngine so it stays
    explainable.
    """
    signals, lead_names = build_signals(connection, target_id)

    engine = RiskEngine()
    result = engine.score(signals)
    result_dict = result.to_dict()

    findings = {
        "engine": "RiskEngine",
        "tier": result_dict["tier"],
        "tier_label": result_dict["tier_label"],
        "components": result_dict["components"],
        "top_signals": result_dict["top_signals"],
        "explanation": result_dict["explanation"],
        "scored_at": result_dict["scored_at"],
    }

    notes_parts = [result_dict["explanation"]]

    if lead_names:
        preview = ", ".join(n for n in lead_names[:5] if n)
        findings["review_leads"] = lead_names
        notes_parts.append(
            "Review leads surfaced for human attention (not determinations): "
            f"{preview}."
        )

    if ai_findings:
        # Keep the AI's qualitative read as context only.
        findings["ai_context"] = ai_findings

    return {
        "analysis_type": "risk_engine_v1",
        "risk_score": result_dict["risk_score"],
        "findings": findings,
        "notes": " ".join(notes_parts),
    }