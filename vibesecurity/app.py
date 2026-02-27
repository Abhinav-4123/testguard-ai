"""
VibeSecurity - AI-Powered Security Analysis Platform
Clean FastAPI application with modular architecture.
"""
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import auth
import database as db
import scanner
from config import (
    HOST, PORT, RATE_LIMIT_LOGIN, RATE_LIMIT_SIGNUP,
    RATE_LIMIT_SCAN, RATE_LIMIT_API,
    CONTACT_EMAIL, ENTERPRISE_EMAIL,
)
from validators import validate_scan_target, sanitize_for_html

# ── Logging ──

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("vibesecurity")

# ── App Setup ──

app = FastAPI(title="VibeSecurity", version="2.0.0")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Templates ──

TEMPLATE_DIR = Path(__file__).parent / "templates"


def load_template(name: str) -> str:
    return (TEMPLATE_DIR / name).read_text(encoding="utf-8")


# ── Startup ──

@app.on_event("startup")
async def startup():
    await db.init_db()
    logger.info("VibeSecurity started")


# ── Helper: Get authenticated user from session cookie ──

async def get_session_user(request: Request):
    session_token = request.cookies.get("session")
    return await auth.get_user_from_session(session_token)


def verify_csrf(request_token: str, session_csrf: str):
    if not request_token or request_token != session_csrf:
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


# ── Landing Page ──

@app.get("/", response_class=HTMLResponse)
async def landing_page(request: Request):
    stats = await db.get_stats()
    html = load_template("landing.html")
    html = html.replace("{{total_users}}", str(stats["total_users"]))
    html = html.replace("{{total_scans}}", str(stats["total_scans"]))
    html = html.replace("{{contact_email}}", CONTACT_EMAIL)
    html = html.replace("{{enterprise_email}}", ENTERPRISE_EMAIL)
    return html


# ── Auth Routes ──

@app.post("/api/signup")
@limiter.limit(RATE_LIMIT_SIGNUP)
async def signup(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    company: str = Form(""),
):
    result = await auth.signup(email, password, name, company)
    if result["success"]:
        login_result = await auth.login(email, password)
        if login_result["success"]:
            response = RedirectResponse(url="/dashboard", status_code=303)
            response.set_cookie(
                "session", login_result["session_token"],
                httponly=True, secure=True, samesite="lax", max_age=7 * 24 * 3600,
            )
            return response
        return RedirectResponse(url="/dashboard", status_code=303)
    error = quote(result["error"])
    return RedirectResponse(url=f"/?error={error}&form=signup", status_code=303)


@app.post("/api/login")
@limiter.limit(RATE_LIMIT_LOGIN)
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
):
    result = await auth.login(email, password)
    if result["success"]:
        response = RedirectResponse(url="/dashboard", status_code=303)
        response.set_cookie(
            "session", result["session_token"],
            httponly=True, secure=True, samesite="lax", max_age=7 * 24 * 3600,
        )
        return response
    error = quote(result["error"])
    return RedirectResponse(url=f"/?error={error}&form=login", status_code=303)


@app.get("/api/logout")
async def logout(request: Request):
    session_token = request.cookies.get("session")
    if session_token:
        await auth.logout(session_token)
    response = RedirectResponse(url="/")
    response.delete_cookie("session")
    return response


# ── Dashboard ──

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    user = await get_session_user(request)
    if not user:
        return RedirectResponse(url="/")

    api_keys = await db.get_user_api_keys(user["id"])
    stats = await db.get_stats()
    usage = await db.get_user_usage(user["id"])
    recent_scans = await db.get_user_scans(user["id"], limit=10)

    # Build API keys HTML
    if api_keys:
        keys_html = "".join(
            f'<div class="api-key"><code>{sanitize_for_html(k["key"])}</code>'
            f'<span style="color:#666;">{sanitize_for_html(k["name"])} | '
            f'Last used: {k["last_used"] or "Never"}</span></div>'
            for k in api_keys
        )
    else:
        keys_html = '<p style="color:#666;">No API keys yet</p>'

    # Build scan history HTML
    if recent_scans:
        scans_html = ""
        for s in recent_scans:
            status_class = f"badge-{s['status']}"
            scans_html += (
                f'<div class="scan-row">'
                f'<code>{sanitize_for_html(s["target"][:50])}</code>'
                f'<div style="display:flex;gap:12px;align-items:center;">'
                f'<span class="badge {status_class}">{s["status"].upper()}</span>'
                f'<a href="/scan/{s["id"]}" style="color:#00ff88;font-size:13px;">View</a>'
                f'</div></div>'
            )
    else:
        scans_html = '<p style="color:#666;">No scans yet. Start your first scan above.</p>'

    html = load_template("dashboard.html")
    html = html.replace("{{user_email}}", sanitize_for_html(user["email"]))
    html = html.replace("{{user_display_name}}", sanitize_for_html(user["name"] or user["email"].split("@")[0]))
    html = html.replace("{{user_plan}}", sanitize_for_html(user["plan"].upper()))
    html = html.replace("{{scan_count}}", str(usage["scans"]))
    html = html.replace("{{api_call_count}}", str(usage["api_calls"]))
    html = html.replace("{{total_users}}", str(stats["total_users"]))
    html = html.replace("{{total_scans}}", str(stats["total_scans"]))
    html = html.replace("{{api_keys_html}}", keys_html)
    html = html.replace("{{scan_history_html}}", scans_html)
    html = html.replace("{{csrf_token}}", sanitize_for_html(user.get("csrf_token", "")))
    return html


# ── API Key Management ──

@app.post("/api/keys/generate")
async def generate_key(request: Request, csrf_token: str = Form(...)):
    user = await get_session_user(request)
    if not user:
        return RedirectResponse(url="/")
    verify_csrf(csrf_token, user.get("csrf_token", ""))

    await auth.generate_api_key(user["id"], f"Key-{datetime.now().strftime('%Y%m%d')}")
    return RedirectResponse(url="/dashboard", status_code=303)


# ── Public Stats ──

@app.get("/api/stats")
async def get_stats():
    return await db.get_stats()


# ── Scan Endpoints ──

class ScanRequest(BaseModel):
    target_url: str


@app.post("/api/scan")
@limiter.limit(RATE_LIMIT_SCAN)
async def start_scan_form(request: Request, target_url: str = Form(...), csrf_token: str = Form(...)):
    user = await get_session_user(request)
    if not user:
        return RedirectResponse(url="/")
    verify_csrf(csrf_token, user.get("csrf_token", ""))

    # Validate target URL
    valid, error = validate_scan_target(target_url)
    if not valid:
        error_msg = quote(error)
        return RedirectResponse(url=f"/dashboard?error={error_msg}", status_code=303)

    # Check plan limits
    allowed, limit_msg = await auth.check_plan_limit(user["id"], user["plan"])
    if not allowed:
        error_msg = quote(limit_msg)
        return RedirectResponse(url=f"/dashboard?error={error_msg}", status_code=303)

    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{id(request) % 10000}"
    await db.create_scan(scan_id, target_url, user["id"], datetime.now().isoformat())
    await db.increment_scan_usage(user["id"])

    asyncio.create_task(scanner.run_quick_scan(scan_id, target_url, user["id"]))

    return RedirectResponse(url=f"/scan/{scan_id}", status_code=303)


@app.post("/api/v1/scan")
@limiter.limit(RATE_LIMIT_API)
async def start_scan_api(request: Request, scan: ScanRequest):
    api_key = request.headers.get("X-API-Key") or request.headers.get("Authorization", "").replace("Bearer ", "")
    user_info = await auth.validate_api_key(api_key)
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    valid, error = validate_scan_target(scan.target_url)
    if not valid:
        raise HTTPException(status_code=400, detail=error)

    allowed, limit_msg = await auth.check_plan_limit(user_info["user_id"], user_info["plan"])
    if not allowed:
        raise HTTPException(status_code=429, detail=limit_msg)

    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{id(request) % 10000}"
    await db.create_scan(scan_id, scan.target_url, user_info["user_id"], datetime.now().isoformat())
    await db.increment_scan_usage(user_info["user_id"])

    asyncio.create_task(scanner.run_quick_scan(scan_id, scan.target_url, user_info["user_id"]))

    return {
        "status": "queued",
        "scan_id": scan_id,
        "target": scan.target_url,
        "message": f"Scan started. Poll /api/v1/scan/{scan_id} for results.",
    }


@app.get("/api/v1/scan/{scan_id}")
async def get_scan_api(scan_id: str, request: Request):
    api_key = request.headers.get("X-API-Key") or request.headers.get("Authorization", "").replace("Bearer ", "")
    user_info = await auth.validate_api_key(api_key)
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    scan_data = await db.get_scan(scan_id)
    if not scan_data or scan_data.get("user_id") != user_info["user_id"]:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan_data


# ── Scan Results Page ──

@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_results_page(scan_id: str, request: Request):
    user = await get_session_user(request)
    if not user:
        return RedirectResponse(url="/")

    scan_data = await db.get_scan(scan_id)
    if not scan_data or scan_data.get("user_id") != user["id"]:
        return RedirectResponse(url="/dashboard")

    status_colors = {"queued": "#888", "running": "#ffcc00", "completed": "#00ff88", "failed": "#ff4444"}
    sev_colors = {"critical": "#ff0000", "high": "#ff4444", "medium": "#ffcc00", "low": "#00ccff", "info": "#888"}

    status_color = status_colors.get(scan_data["status"], "#888")

    # Build vulnerabilities HTML
    vulns_html = ""
    for v in scan_data.get("vulnerabilities", []):
        sev = v.get("severity", "info")
        sev_color = sev_colors.get(sev, "#888")
        vulns_html += (
            f'<div class="vuln" style="border-left:3px solid {sev_color};">'
            f'<div class="vuln-header">'
            f'<h4>{sanitize_for_html(v.get("title", "Unknown"))}</h4>'
            f'<span class="badge" style="background:{sev_color};">{sev.upper()}</span>'
            f'</div>'
            f'<p style="color:#888;font-size:13px;margin-top:8px;">{sanitize_for_html(v.get("description", ""))}</p>'
            f'<p style="color:#666;font-size:11px;margin-top:4px;">Category: {sanitize_for_html(v.get("category", "Unknown"))} | Framework: {sanitize_for_html(v.get("framework", "N/A"))}</p>'
            f'</div>'
        )

    if not vulns_html:
        if scan_data["status"] != "completed":
            vulns_html = '<div style="text-align:center;padding:40px;color:#666;">Scan in progress...</div>'
        else:
            vulns_html = '<div style="text-align:center;padding:40px;color:#00ff88;">No vulnerabilities found!</div>'

    is_running = scan_data["status"] in ["queued", "running"]
    summary = scan_data.get("summary", {})

    html = load_template("scan_result.html")
    html = html.replace("{{auto_refresh}}", '<meta http-equiv="refresh" content="5">' if is_running else "")
    html = html.replace("{{scan_target}}", sanitize_for_html(scan_data["target"]))
    html = html.replace("{{scan_status}}", scan_data["status"].upper())
    html = html.replace("{{status_color}}", status_color)
    html = html.replace("{{spinner_html}}", f'<div class="spinner" style="border-color:{status_color};border-top-color:transparent;"></div>' if is_running else "")
    html = html.replace("{{total}}", str(summary.get("total", 0)))
    html = html.replace("{{critical}}", str(summary.get("critical", 0)))
    html = html.replace("{{high}}", str(summary.get("high", 0)))
    html = html.replace("{{medium}}", str(summary.get("medium", 0)))
    html = html.replace("{{low}}", str(summary.get("low", 0)))
    html = html.replace("{{vulns_html}}", vulns_html)
    return html


# ── Run Server ──

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)
