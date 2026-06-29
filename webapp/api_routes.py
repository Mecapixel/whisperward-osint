"""
WhisperWard OSINT — JSON API Routes
Phase 4, Milestone 6
Pixora Inc.

This module defines the JSON endpoints that the redesigned front end consumes.
The existing page routes return rendered HTML, which is right for full pages, but
the D3 visualizations and any live widgets need data as JSON to render on the
client. These routes provide that data, read from the same DatabaseManager the
pages use, so the numbers on a chart and the numbers on a page always agree.

The routes are grouped on an APIRouter and mounted by the main application with a
single include call, which keeps the working main module almost unchanged. Every
route returns real data from the database. When the database is empty the routes
return empty structures rather than inventing values, so a chart on an empty
deployment shows nothing rather than something false.

The risk tiers used here match the governance framework. Tier one is below two,
tier two is from two up to seven, and tier three is seven and above. Keeping the
same thresholds the rest of the system uses means the dashboard tells the same
story as the reports.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from fastapi import APIRouter

try:
    from database import DatabaseManager
except Exception:  # pragma: no cover - import shape depends on run context
    from ..database import DatabaseManager

try:
    from modules.platform_plugin import default_registry
    _REGISTRY_AVAILABLE = True
except Exception:  # pragma: no cover
    default_registry = None
    _REGISTRY_AVAILABLE = False


router = APIRouter(prefix="/api", tags=["api"])

# A single shared manager for the API routes. The pages construct their own; this
# mirrors that pattern so the API is self contained.
_db = DatabaseManager()
try:
    _db.init()
except Exception:
    pass


def _tier_for_score(score) -> str:
    """Maps a risk score to its governance tier label. None means not scored."""
    if score is None:
        return "unscored"
    if score < 2.0:
        return "tier1"
    if score < 7.0:
        return "tier2"
    return "tier3"


def _all_cases() -> List[Dict[str, Any]]:
    try:
        return _db.get_all_cases()
    except Exception:
        return []


@router.get("/health")
async def health() -> Dict[str, Any]:
    """A simple liveness check for the deployment. Reports that the service is up
    and whether the database is reachable."""
    db_ok = True
    try:
        _db.get_all_cases()
    except Exception:
        db_ok = False
    return {"status": "ok", "database_reachable": db_ok}


@router.get("/metrics")
async def metrics() -> Dict[str, Any]:
    """Returns aggregate statistics across all cases. Real counts only. Powers the
    dashboard summary and the demo script's headline numbers."""
    cases = _all_cases()

    total_cases = len(cases)
    total_targets = sum(int(c.get("target_count") or 0) for c in cases)

    # Risk tier distribution across cases that have a latest risk.
    tiers = {"tier1": 0, "tier2": 0, "tier3": 0, "unscored": 0}
    for c in cases:
        tiers[_tier_for_score(c.get("latest_risk"))] += 1

    # Platform breakdown by each case's primary platform.
    platforms: Dict[str, int] = {}
    for c in cases:
        plat = (c.get("primary_platform") or "unknown")
        platforms[plat] = platforms.get(plat, 0) + 1

    # Artifact total, counted directly from the database for accuracy.
    total_artifacts = 0
    try:
        conn = _db.get_connection()
        row = conn.execute("SELECT COUNT(*) AS n FROM artifacts").fetchone()
        total_artifacts = int(row["n"]) if row else 0
    except Exception:
        total_artifacts = 0

    capabilities = {}
    if _REGISTRY_AVAILABLE:
        try:
            capabilities = default_registry().capabilities()
        except Exception:
            capabilities = {}

    return {
        "total_cases": total_cases,
        "total_targets": total_targets,
        "total_artifacts": total_artifacts,
        "risk_tiers": tiers,
        "platforms": platforms,
        "plugin_capabilities": capabilities,
    }


@router.get("/cases/risk-distribution")
async def risk_distribution() -> Dict[str, Any]:
    """Returns the risk tier counts in a shape ready for a bar or donut chart. The
    labels carry the human readable tier names so the chart needs no extra lookup."""
    cases = _all_cases()
    counts = {"tier1": 0, "tier2": 0, "tier3": 0, "unscored": 0}
    for c in cases:
        counts[_tier_for_score(c.get("latest_risk"))] += 1
    labels = {
        "tier1": "Tier 1 — monitor",
        "tier2": "Tier 2 — review",
        "tier3": "Tier 3 — escalate",
        "unscored": "Not scored",
    }
    return {
        "series": [
            {"tier": key, "label": labels[key], "count": counts[key]}
            for key in ["tier1", "tier2", "tier3", "unscored"]
        ],
        "total": sum(counts.values()),
    }


@router.get("/cases")
async def cases_list() -> Dict[str, Any]:
    """Returns the case list as JSON, the same data the dashboard renders, for any
    client side table or live refresh."""
    cases = _all_cases()
    return {"count": len(cases), "cases": cases}


@router.get("/case/{case_id}/summary")
async def case_summary(case_id: str) -> Dict[str, Any]:
    """Returns a single case's summary as JSON, including target count, artifact
    count, platform breakdown, and risk. Returns a not_found marker rather than an
    error body when the case does not exist, so the client can handle it cleanly."""
    case = None
    try:
        case = _db.get_case(case_id)
    except Exception:
        case = None
    if not case:
        return {"found": False, "case_id": case_id}

    try:
        summary = _db.get_case_summary(case_id)
    except Exception:
        summary = {}
    try:
        risk = _db.get_case_risk(case_id)
    except Exception:
        risk = {"latest_risk": None, "peak_risk": None, "analysis_count": 0}

    return {
        "found": True,
        "case_id": case_id,
        "case_name": case.get("case_name"),
        "status": case.get("status"),
        "summary": summary,
        "risk": risk,
        "tier": _tier_for_score(risk.get("latest_risk")),
    }


@router.get("/case/{case_id}/risk-timeline")
async def case_risk_timeline(case_id: str) -> Dict[str, Any]:
    """Returns the sequence of risk scores recorded for a case over time, ordered
    oldest to newest, for a D3 line chart. Each point carries the timestamp and the
    score. Empty when the case has no analyses, so the chart shows nothing rather
    than a fabricated trend."""
    points: List[Dict[str, Any]] = []
    try:
        conn = _db.get_connection()
        rows = conn.execute(
            """
            SELECT ar.risk_score AS score, ar.analyzed_at AS at
            FROM targets t
            JOIN analysis_results ar ON ar.target_id = t.target_id
            WHERE t.case_id = ? AND ar.risk_score IS NOT NULL
            ORDER BY ar.analyzed_at ASC
            """,
            (case_id,)
        ).fetchall()
        for row in rows:
            points.append({"at": row["at"], "score": row["score"]})
    except Exception:
        points = []
    return {"case_id": case_id, "points": points, "count": len(points)}


@router.get("/case/{case_id}/signals")
async def case_signals(case_id: str) -> Dict[str, Any]:
    """Returns the explainable breakdown of the case's most recent structured
    analysis: the weighted score components, the tier, the top signals, and the
    review-only leads. This is what lets the case page show why a score is what it
    is, rather than only the number. Reads the findings the risk engine persisted.

    When the latest analysis predates the structured engine, or carries no
    component breakdown, the route returns found True with empty components and an
    explanatory note, so the page can show a clean 'no structured breakdown'
    state rather than an error."""
    result: Dict[str, Any] = {
        "case_id": case_id,
        "found": False,
        "risk_score": None,
        "tier_label": None,
        "components": [],
        "top_signals": [],
        "review_leads": [],
        "explanation": None,
        "analysis_type": None,
    }

    try:
        conn = _db.get_connection()
        row = conn.execute(
            """
            SELECT ar.risk_score AS score, ar.findings AS findings,
                   ar.analysis_type AS analysis_type
            FROM targets t
            JOIN analysis_results ar ON ar.target_id = t.target_id
            WHERE t.case_id = ?
            ORDER BY ar.result_id DESC
            LIMIT 1
            """,
            (case_id,)
        ).fetchone()
    except Exception:
        row = None

    if not row:
        return result

    result["found"] = True
    result["risk_score"] = row["score"]
    result["analysis_type"] = row["analysis_type"]

    findings_raw = row["findings"]
    findings: Dict[str, Any] = {}
    if findings_raw:
        try:
            parsed = json.loads(findings_raw)
            if isinstance(parsed, dict):
                findings = parsed
        except (ValueError, TypeError):
            findings = {}

    # The structured engine stores these keys. An older AI-only analysis will not
    # have them, which the page treats as a no-breakdown state.
    result["tier_label"] = findings.get("tier_label")
    result["explanation"] = findings.get("explanation")
    result["top_signals"] = findings.get("top_signals", []) or []
    result["review_leads"] = findings.get("review_leads", []) or []

    components = findings.get("components", []) or []
    cleaned: List[Dict[str, Any]] = []
    for c in components:
        if not isinstance(c, dict):
            continue
        cleaned.append({
            "name": c.get("name"),
            "weight": c.get("weight"),
            "raw_score": c.get("raw_score"),
            "weighted_score": c.get("weighted_score"),
            "explanation": c.get("explanation"),
        })
    result["components"] = cleaned

    return result


@router.get("/platforms")
async def platforms() -> Dict[str, Any]:
    """Returns the registered platforms and whether each is currently available,
    so the UI can show honest capability rather than offering a platform that is
    not implemented."""
    if not _REGISTRY_AVAILABLE:
        return {"platforms": {}, "available": []}
    try:
        reg = default_registry()
        return {"platforms": reg.capabilities(), "available": reg.available_platforms()}
    except Exception:
        return {"platforms": {}, "available": []}