"""
QA Testing Agent API
Autonomous QA testing for SaaS applications
With integrated Security Framework Scanning
"""
import os
import uuid
import secrets
import logging
import ipaddress
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / ".env"
load_dotenv(env_path)

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Security, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import asyncio

from .alerts import AlertManager
from .billing import router as billing_router
from .security_scanner import SecurityScanner, generate_security_report, Framework
from . import database as db

# ── Logging ──

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("testguard")

# ── App Setup ──

ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "https://vibesecurity.in,https://app.vibesecurity.in"
).split(",")

app = FastAPI(
    title="TestGuard AI",
    description="AI-powered autonomous QA testing with security framework scanning",
    version="2.0.0"
)

# CORS - restricted origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Include billing routes
app.include_router(billing_router)

# Initialize alert manager
alert_manager = AlertManager()


# ── API Key Authentication ──

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Security(api_key_header)):
    """Verify API key for protected endpoints."""
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key. Include X-API-Key header.")
    valid = await db.validate_api_key(api_key)
    if not valid:
        raise HTTPException(status_code=403, detail="Invalid or inactive API key")
    return api_key


# ── SSRF Protection ──

BLOCKED_HOSTS = {"localhost", "0.0.0.0", "metadata.google.internal"}


def validate_url(url: str) -> tuple[bool, str]:
    """Validate a URL is safe to access."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL format"
    if parsed.scheme not in ("http", "https"):
        return False, "Only HTTP and HTTPS URLs are allowed"
    hostname = parsed.hostname
    if not hostname:
        return False, "URL must include a hostname"
    if hostname in BLOCKED_HOSTS:
        return False, "This host is not allowed"
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
            return False, "Private or reserved IP addresses are not allowed"
    except ValueError:
        pass  # Hostname, not IP - that's fine
    return True, ""


# ── Startup ──

@app.on_event("startup")
async def startup():
    await db.init_db()
    logger.info("TestGuard AI started")


# ── Models ──

class Credentials(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    login_url: Optional[str] = None


class TestRequest(BaseModel):
    url: HttpUrl
    objective: str
    credentials: Optional[Credentials] = None
    steps: Optional[List[str]] = None
    webhook_url: Optional[HttpUrl] = None


class SecurityScanRequest(BaseModel):
    url: HttpUrl
    frameworks: Optional[List[str]] = None


# ── Public Endpoints (no auth) ──

@app.get("/")
async def root():
    return {
        "service": "QA Testing Agent",
        "status": "operational",
        "endpoints": {
            "POST /test": "Start a new test",
            "GET /test/{test_id}": "Get test status/results",
            "GET /tests": "List all tests"
        }
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


# ── Key Management ──

@app.post("/api/keys/generate")
async def generate_api_key():
    """Generate a new API key. Protect this endpoint in production with admin auth."""
    key = f"tg_live_{secrets.token_urlsafe(32)}"
    await db.create_api_key(key)
    return {"key": key, "message": "Store this key securely. It won't be shown again."}


# ── Test Endpoints (auth required) ──

@app.post("/test")
@limiter.limit("20/minute")
async def create_test(
    request_obj: TestRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key),
):
    # Validate URL
    valid, error = validate_url(str(request_obj.url))
    if not valid:
        raise HTTPException(status_code=400, detail=error)

    test_id = str(uuid.uuid4())
    started_at = datetime.now().isoformat()

    await db.save_test_result(test_id, "pending", str(request_obj.url), request_obj.objective, started_at)

    background_tasks.add_task(run_test, test_id, request_obj)

    return {
        "test_id": test_id,
        "status": "pending",
        "url": str(request_obj.url),
        "objective": request_obj.objective,
        "started_at": started_at,
    }


async def run_test(test_id: str, request: TestRequest):
    """Execute the QA test asynchronously."""
    from .agent import QAAgent
    from .reporter import ReportGenerator

    await db.update_test_result(test_id, status="running")

    try:
        agent = QAAgent(
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            openai_api_key=os.getenv("OPENAI_API_KEY")
        )

        results = await agent.run_test(
            url=str(request.url),
            objective=request.objective,
            credentials=request.credentials.model_dump() if request.credentials else None,
            custom_steps=request.steps
        )

        reporter = ReportGenerator()
        report_path = reporter.generate(
            test_id=test_id,
            url=str(request.url),
            objective=request.objective,
            results=results
        )

        summary = {
            "passed": results.get("passed", 0),
            "failed": results.get("failed", 0),
            "steps_completed": results.get("steps_completed", []),
            "errors": results.get("errors", []),
        }

        await db.update_test_result(
            test_id,
            status="completed",
            completed_at=datetime.now().isoformat(),
            report_path=report_path,
            summary=summary,
        )

        # Send webhook notification if provided
        if request.webhook_url:
            valid, _ = validate_url(str(request.webhook_url))
            if valid:
                await notify_webhook(str(request.webhook_url), test_id)
            else:
                logger.warning("Webhook URL rejected (SSRF protection): %s", request.webhook_url)

    except Exception as e:
        logger.error("Test %s failed: %s", test_id, e)
        await db.update_test_result(
            test_id,
            status="failed",
            completed_at=datetime.now().isoformat(),
            summary={"error": str(e)},
        )


async def notify_webhook(url: str, test_id: str):
    """Send test completion to webhook URL."""
    import httpx
    try:
        result = await db.get_test_result(test_id)
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(url, json=result)
    except Exception as e:
        logger.warning("Webhook notification failed for %s: %s", test_id, e)


@app.get("/test/{test_id}")
async def get_test(test_id: str, api_key: str = Depends(verify_api_key)):
    result = await db.get_test_result(test_id)
    if not result:
        raise HTTPException(status_code=404, detail="Test not found")
    return result


@app.get("/tests")
async def list_tests(api_key: str = Depends(verify_api_key)):
    return await db.get_all_test_results()


@app.get("/report/{test_id}")
async def get_report(test_id: str, api_key: str = Depends(verify_api_key)):
    result = await db.get_test_result(test_id)
    if not result:
        raise HTTPException(status_code=404, detail="Test not found")
    if not result.get("report_path"):
        raise HTTPException(status_code=400, detail="Report not yet available")
    try:
        with open(result["report_path"], "r") as f:
            return {"report": f.read()}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Report file not found")


# ── Scheduled Tests ──

@app.post("/run-scheduled")
async def run_scheduled_tests(background_tasks: BackgroundTasks):
    scheduled_tests = os.getenv("SCHEDULED_TESTS", "").split(",")
    results = []
    for test_config in scheduled_tests:
        if not test_config.strip():
            continue
        parts = test_config.strip().split("|")
        if len(parts) >= 2:
            url, objective = parts[0], parts[1]
            test_id = str(uuid.uuid4())
            await db.save_test_result(test_id, "pending", url, objective, datetime.now().isoformat())
            request = TestRequest(url=url, objective=objective)
            background_tasks.add_task(run_test, test_id, request)
            results.append({"test_id": test_id, "url": url})
    return {"scheduled": len(results), "tests": results}


# ── Security Scanning ──

@app.post("/security/scan")
@limiter.limit("10/minute")
async def start_security_scan(
    request_obj: SecurityScanRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key),
):
    valid, error = validate_url(str(request_obj.url))
    if not valid:
        raise HTTPException(status_code=400, detail=error)

    scan_id = f"sec_{uuid.uuid4().hex[:12]}"
    frameworks = request_obj.frameworks or ["owasp_top_10", "vapt", "iso_27001", "soc_2"]

    await db.save_security_scan(scan_id, str(request_obj.url), datetime.now().isoformat(), frameworks)

    background_tasks.add_task(run_security_scan, scan_id, str(request_obj.url), request_obj.frameworks)

    return {
        "scan_id": scan_id,
        "status": "pending",
        "url": str(request_obj.url),
        "started_at": datetime.now().isoformat(),
    }


async def run_security_scan(scan_id: str, url: str, frameworks: Optional[List[str]]):
    """Execute security scan asynchronously."""
    await db.update_security_scan(scan_id, status="running")

    try:
        from .browser import BrowserController

        browser = BrowserController()
        await browser.start()

        try:
            await browser.navigate(url)
            content = await browser.get_page_content()

            headers = {}
            cookies = []
            forms = []

            page_data = await browser.page.evaluate("""() => {
                const forms = Array.from(document.forms).map(f => ({
                    action: f.action,
                    method: f.method,
                    inputs: Array.from(f.elements).map(e => ({
                        type: e.type, name: e.name, id: e.id, autocomplete: e.autocomplete
                    }))
                }));
                return { forms };
            }""")
            forms = page_data.get("forms", [])

            cookies_raw = await browser.context.cookies()
            cookies = [
                {"name": c.get("name"), "secure": c.get("secure", False), "httpOnly": c.get("httpOnly", False), "sameSite": c.get("sameSite")}
                for c in cookies_raw
            ]

            scanner = SecurityScanner()
            framework_enums = None
            if frameworks:
                framework_enums = []
                for f in frameworks:
                    try:
                        framework_enums.append(Framework(f.lower()))
                    except ValueError:
                        pass

            result = await scanner.scan(
                url=url, page_content=content, headers=headers,
                cookies=cookies, forms=forms, frameworks=framework_enums
            )

            report = generate_security_report(result)

            await db.update_security_scan(
                scan_id,
                status="completed",
                completed_at=datetime.now().isoformat(),
                overall_score=result.overall_score,
                framework_scores=result.framework_scores,
                summary=result.summary,
                report=report,
                vulnerabilities=[
                    {"id": v.id, "title": v.title, "severity": v.severity.value, "category": v.category, "recommendation": v.recommendation}
                    for v in result.vulnerabilities
                ],
            )

        finally:
            await browser.stop()

    except Exception as e:
        logger.error("Security scan %s failed: %s", scan_id, e)
        await db.update_security_scan(
            scan_id,
            status="failed",
            error=str(e),
            completed_at=datetime.now().isoformat(),
        )


@app.get("/security/scan/{scan_id}")
async def get_security_scan(scan_id: str, api_key: str = Depends(verify_api_key)):
    result = await db.get_security_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@app.get("/security/scans")
async def list_security_scans(api_key: str = Depends(verify_api_key)):
    return await db.get_all_security_scans()


@app.get("/security/report/{scan_id}")
async def get_security_report_endpoint(scan_id: str, api_key: str = Depends(verify_api_key)):
    result = await db.get_security_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    if result.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Scan not yet complete")
    return {"report": result.get("report", "No report available")}


# ── Stats (auth required) ──

@app.get("/stats")
async def get_stats(api_key: str = Depends(verify_api_key)):
    return await db.get_stats()


# ── Serve static files for landing page and dashboard ──

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "landing")
DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard")


@app.get("/landing", response_class=HTMLResponse)
async def serve_landing():
    landing_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(landing_file):
        with open(landing_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>TestGuard AI</h1><p>Landing page not found</p>")


@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    dashboard_file = os.path.join(DASHBOARD_DIR, "index.html")
    if os.path.exists(dashboard_file):
        with open(dashboard_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Dashboard</h1><p>Dashboard not found</p>")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
