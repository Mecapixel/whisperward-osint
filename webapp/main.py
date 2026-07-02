# webapp/main.py
import hashlib
import hmac
import json
import os
import secrets
import sys
from datetime import datetime, timezone

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import DatabaseManager
from webapp.api_routes import router as api_router

app = FastAPI(title="WhisperWard OSINT")
templates = Jinja2Templates(directory="webapp/templates")
app.mount("/static", StaticFiles(directory="webapp/static"), name="static")

db = DatabaseManager()
db.init()

# On a stateless deployment (for example the free Render tier) the database is
# empty on every start. Seed clearly labeled synthetic demo cases so the public
# demo shows the real scoring and visualizations rather than an empty registry.
# The seeder guards itself and does nothing when any case already exists, so it
# never disturbs a real working database.
try:
    from seed_demo import seed_if_empty
    seed_if_empty(db)
except Exception as _seed_exc:
    print(f"[main] demo seeding skipped: {_seed_exc}")

app.include_router(api_router)


# ── Operator session ─────────────────────────────────────────────────────────
# Chain of custody starts with operator identity, so the web layer enforces it
# rather than merely displaying it: the auth step issues an HMAC-signed session
# cookie carrying the operator name, and the dashboard and case pages verify
# that signature before rendering. Set WHISPERWARD_SESSION_SECRET in the
# environment for sessions that survive restarts; without it a fresh secret is
# generated per boot, which simply means operators re-authenticate after a
# restart. This is deliberately session-layer identity for the demonstration
# interface, not credential verification — the authoritative operator record
# lives in the chain-of-custody log.

_SESSION_SECRET = (os.getenv("WHISPERWARD_SESSION_SECRET") or secrets.token_hex(32)).encode()
_SESSION_COOKIE = "ww_session"


def _sign(value: str) -> str:
    return hmac.new(_SESSION_SECRET, value.encode(), hashlib.sha256).hexdigest()


def _make_session(operator: str) -> str:
    operator = (operator or "OPERATOR").strip().upper()[:32] or "OPERATOR"
    return f"{operator}|{_sign(operator)}"


def _read_session(request: Request):
    """Return the operator name from a validly signed session cookie, else None."""
    raw = request.cookies.get(_SESSION_COOKIE, "")
    if "|" not in raw:
        return None
    operator, signature = raw.rsplit("|", 1)
    if hmac.compare_digest(_sign(operator), signature):
        return operator
    return None


def _session_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y.%m.%d")


DEMO_CASES = [
    {"case_id": "CASE-DEMO0001", "case_name": "Demo: BuilderMan",
     "analyst_name": "MECAPIXEL", "created_at": "2026-05-18 10:00:00",
     "target_count": 1, "primary_platform": "roblox",
     "latest_risk": 5.0, "peak_risk": 7.2, "analyzed_at": "2026-05-20 14:00:00",
     "analysis_count": 2},
    {"case_id": "CASE-DEMO0002", "case_name": "Demo: Skylar Trace",
     "analyst_name": "MECAPIXEL", "created_at": "2026-05-20 09:00:00",
     "target_count": 2, "primary_platform": "discord",
     "latest_risk": 4.7, "peak_risk": 4.7, "analyzed_at": "2026-05-20 10:30:00",
     "analysis_count": 1},
    {"case_id": "CASE-DEMO0003", "case_name": "Demo: Ravensong",
     "analyst_name": "MECAPIXEL", "created_at": "2026-05-15 11:00:00",
     "target_count": 1, "primary_platform": "roblox",
     "latest_risk": 3.2, "peak_risk": 3.2, "analyzed_at": "2026-05-15 12:00:00",
     "analysis_count": 1},
    {"case_id": "CASE-DEMO0004", "case_name": "Demo: KJ Strider",
     "analyst_name": "MECAPIXEL", "created_at": "2026-05-11 09:00:00",
     "target_count": 1, "primary_platform": "discord",
     "latest_risk": 2.8, "peak_risk": 2.8, "analyzed_at": "2026-05-11 10:00:00",
     "analysis_count": 1},
    {"case_id": "CASE-DEMO0005", "case_name": "Demo: Mossfire",
     "analyst_name": "MECAPIXEL", "created_at": "2026-05-08 08:00:00",
     "target_count": 1, "primary_platform": "roblox",
     "latest_risk": None, "peak_risk": None, "analyzed_at": None,
     "analysis_count": 0},
]


def get_avatar_for_case(case_id: str):
    """Pull the Roblox avatar URL from artifacts for the first target in a case."""
    try:
        conn = db.get_connection()
        row = conn.execute(
            """SELECT a.raw_data
               FROM artifacts a
               JOIN targets t ON t.target_id = a.target_id
               WHERE t.case_id = ? AND a.module_name = 'RobloxOSINT'
               LIMIT 1""",
            (case_id,)
        ).fetchone()
        if row:
            data = json.loads(row['raw_data'])
            return data.get('avatar_url')
    except Exception as e:
        print(f"[get_avatar_for_case] error: {e}")
    return None


@app.get("/", response_class=HTMLResponse)
async def boot(request: Request):
    try:
        case_count = len(db.get_all_cases())
    except Exception as e:
        print(f"[boot] get_all_cases failed: {e}")
        case_count = 0
    return templates.TemplateResponse(request, "boot.html", {"case_count": case_count})


@app.get("/landing", response_class=HTMLResponse)
async def landing(request: Request):
    return templates.TemplateResponse(request, "landing.html")


@app.post("/auth")
async def auth(operator: str = Form(...), auth_key: str = Form(...)):
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        key=_SESSION_COOKIE,
        value=_make_session(operator),
        httponly=True,
        samesite="lax",
    )
    return response


@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/landing", status_code=303)
    response.delete_cookie(_SESSION_COOKIE)
    return response


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    operator = _read_session(request)
    if operator is None:
        return RedirectResponse(url="/landing", status_code=303)

    try:
        real_cases = db.get_all_cases()
    except Exception as e:
        print(f"[dashboard] get_all_cases failed: {e}")
        real_cases = []

    if not real_cases:
        cases = DEMO_CASES
        demo_mode = True
    else:
        cases = real_cases
        demo_mode = False

    return templates.TemplateResponse(request, "dashboard.html", {
        "cases": cases,
        "demo_mode": demo_mode,
        "operator": operator,
        "session_date": _session_date(),
    })


@app.get("/case/{case_id}", response_class=HTMLResponse)
async def case_detail(request: Request, case_id: str):
    operator = _read_session(request)
    if operator is None:
        return RedirectResponse(url="/landing", status_code=303)

    case_data = db.get_case(case_id)
    targets = db.get_case_targets(case_id) if case_data else []
    summary = db.get_case_summary(case_id) if case_data else {}

    risk_data = db.get_case_risk(case_id) if case_data else None
    latest_risk = risk_data["latest_risk"] if risk_data else None
    peak_risk = risk_data["peak_risk"] if risk_data else None
    analysis_count = risk_data["analysis_count"] if risk_data else 0

    avatar_url = get_avatar_for_case(case_id) if case_data else None

    return templates.TemplateResponse(request, "case_detail.html", {
        "case": case_data,
        "targets": targets,
        "summary": summary,
        "latest_risk": latest_risk,
        "peak_risk": peak_risk,
        "analysis_count": analysis_count,
        "avatar_url": avatar_url,
        "operator": operator,
    })


if __name__ == "__main__":
    uvicorn.run("webapp.main:app", host="0.0.0.0", port=8003, reload=True)
