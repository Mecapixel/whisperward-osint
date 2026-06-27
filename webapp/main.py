# webapp/main.py
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import DatabaseManager
from webapp.api_routes import router as api_router

app = FastAPI(title="WhisperWard OSINT")
templates = Jinja2Templates(directory="webapp/templates")
app.mount("/static", StaticFiles(directory="webapp/static"), name="static")

db = DatabaseManager()
db.init()

app.include_router(api_router)


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
    return RedirectResponse(url="/dashboard", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
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
        "operator": "MECAPIXEL",
        "session_date": "2026.05.24",
    })


@app.get("/case/{case_id}", response_class=HTMLResponse)
async def case_detail(request: Request, case_id: str):
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
    })


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8003)