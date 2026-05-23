# webapp/main.py
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import DatabaseManager

app = FastAPI(title="WhisperWard OSINT")
templates = Jinja2Templates(directory="webapp/templates")
app.mount("/static", StaticFiles(directory="webapp/static"), name="static")

db = DatabaseManager()
db.init()


# Demo data — shown only when DB is empty (fresh clone, portfolio reviewer)
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


# Root → boot screen (auto-redirects to /landing after 4.5s)
@app.get("/", response_class=HTMLResponse)
async def boot(request: Request):
    return templates.TemplateResponse(request, "boot.html")


# Landing / login screen
@app.get("/landing", response_class=HTMLResponse)
async def landing(request: Request):
    return templates.TemplateResponse(request, "landing.html")


# Auth stub — any submit goes to dashboard (real auth is Phase 6)
@app.post("/auth")
async def auth(operator: str = Form(...), auth_key: str = Form(...)):
    return RedirectResponse(url="/dashboard", status_code=303)


# Dashboard — live cases with empty-state demo fallback
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
        "session_date": "2026.05.22",
    })


@app.get("/case/{case_id}", response_class=HTMLResponse)
async def case_detail(request: Request, case_id: str):
    case_data = db.get_case(case_id)
    targets = db.get_case_targets(case_id) if case_data else []
    summary = db.get_case_summary(case_id) if case_data else {}
    return templates.TemplateResponse(request, "case_detail.html", {
        "case": case_data,
        "targets": targets,
        "summary": summary
    })


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8003)