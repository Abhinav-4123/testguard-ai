"""
VibeSecurity - Security Scanner
SSL checks, security headers, exposed files, cookie analysis, CORS, server info.
"""
import ssl
import socket
import logging
import asyncio
from datetime import datetime
from typing import Optional, Dict, List
from urllib.parse import urlparse

import aiohttp

import database as db
from config import SCAN_TIMEOUT, SCAN_FILE_TIMEOUT, SSL_CHECK_TIMEOUT

logger = logging.getLogger("vibesecurity.scanner")


# ── SSL/TLS Check ──

async def check_ssl(url: str) -> Optional[Dict]:
    """Check SSL/TLS configuration."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            return {
                "id": "SSL-001", "title": "No HTTPS",
                "description": f"Site is not using HTTPS encryption",
                "severity": "high", "category": "Transport Security",
                "framework": "OWASP A02:2021"
            }

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=SSL_CHECK_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                # Check certificate expiry
                not_after = ssl.cert_time_to_seconds(cert.get("notAfter", ""))
                import time
                if not_after - time.time() < 30 * 86400:
                    return {
                        "id": "SSL-003", "title": "SSL Certificate Expiring Soon",
                        "description": "Certificate expires within 30 days",
                        "severity": "medium", "category": "Transport Security",
                        "framework": "OWASP A02:2021"
                    }

    except ssl.SSLCertVerificationError as e:
        return {
            "id": "SSL-002", "title": "Invalid SSL Certificate",
            "description": str(e)[:200],
            "severity": "high", "category": "Transport Security",
            "framework": "OWASP A02:2021"
        }
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.warning("SSL check failed for %s: %s", url, e)
    return None


# ── Security Headers Check ──

async def check_security_headers(url: str) -> List[Dict]:
    """Check for missing security headers."""
    findings = []
    required_headers = {
        "Strict-Transport-Security": {"id": "HDR-HSTS", "severity": "medium", "description": "HSTS header missing - no forced HTTPS", "framework": "OWASP A05:2021"},
        "X-Content-Type-Options": {"id": "HDR-XCTO", "severity": "low", "description": "X-Content-Type-Options missing - MIME sniffing risk", "framework": "OWASP A05:2021"},
        "X-Frame-Options": {"id": "HDR-XFO", "severity": "medium", "description": "X-Frame-Options missing - clickjacking risk", "framework": "OWASP A05:2021"},
        "Content-Security-Policy": {"id": "HDR-CSP", "severity": "medium", "description": "Content-Security-Policy missing - XSS risk", "framework": "OWASP A05:2021"},
        "Referrer-Policy": {"id": "HDR-REF", "severity": "low", "description": "Referrer-Policy missing - information leakage risk", "framework": "OWASP A05:2021"},
        "Permissions-Policy": {"id": "HDR-PERM", "severity": "low", "description": "Permissions-Policy missing - browser feature control absent", "framework": "OWASP A05:2021"},
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=SCAN_TIMEOUT), ssl=False) as resp:
                headers = resp.headers
                for header, info in required_headers.items():
                    if header.lower() not in {h.lower() for h in headers}:
                        findings.append({
                            "id": info["id"], "title": f"Missing {header}",
                            "description": info["description"],
                            "severity": info["severity"], "category": "Security Headers",
                            "framework": info["framework"]
                        })
    except Exception as e:
        logger.warning("Header check failed for %s: %s", url, e)
        findings.append({
            "id": "HDR-ERR", "title": "Header Check Failed",
            "description": f"Could not fetch headers: {str(e)[:100]}",
            "severity": "info", "category": "Security Headers"
        })
    return findings


# ── Server Information Disclosure ──

async def check_server_info(url: str) -> List[Dict]:
    """Check for server information disclosure."""
    findings = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=SCAN_TIMEOUT), ssl=False) as resp:
                server = resp.headers.get("Server", "")
                if server and any(v in server.lower() for v in ["apache", "nginx", "iis", "express", "gunicorn"]):
                    findings.append({
                        "id": "INFO-001", "title": "Server Version Disclosed",
                        "description": f"Server header reveals: {server[:80]}",
                        "severity": "low", "category": "Information Disclosure",
                        "framework": "OWASP A05:2021"
                    })

                powered_by = resp.headers.get("X-Powered-By", "")
                if powered_by:
                    findings.append({
                        "id": "INFO-002", "title": "Technology Stack Disclosed",
                        "description": f"X-Powered-By header reveals: {powered_by[:80]}",
                        "severity": "low", "category": "Information Disclosure",
                        "framework": "OWASP A05:2021"
                    })
    except Exception as e:
        logger.warning("Server info check failed for %s: %s", url, e)
    return findings


# ── Cookie Security Check ──

async def check_cookies(url: str) -> List[Dict]:
    """Check cookie security attributes."""
    findings = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=SCAN_TIMEOUT), ssl=False) as resp:
                for cookie_header in resp.headers.getall("Set-Cookie", []):
                    cookie_lower = cookie_header.lower()
                    cookie_name = cookie_header.split("=")[0].strip()

                    if "secure" not in cookie_lower:
                        findings.append({
                            "id": "COOKIE-001", "title": f"Cookie Missing Secure Flag: {cookie_name[:30]}",
                            "description": "Cookie transmitted over insecure connections",
                            "severity": "medium", "category": "Cookie Security",
                            "framework": "OWASP A02:2021"
                        })

                    if "httponly" not in cookie_lower:
                        findings.append({
                            "id": "COOKIE-002", "title": f"Cookie Missing HttpOnly Flag: {cookie_name[:30]}",
                            "description": "Cookie accessible via JavaScript - XSS risk",
                            "severity": "medium", "category": "Cookie Security",
                            "framework": "OWASP A07:2021"
                        })

                    if "samesite" not in cookie_lower:
                        findings.append({
                            "id": "COOKIE-003", "title": f"Cookie Missing SameSite Flag: {cookie_name[:30]}",
                            "description": "Cookie sent with cross-site requests - CSRF risk",
                            "severity": "low", "category": "Cookie Security",
                            "framework": "OWASP A01:2021"
                        })
    except Exception as e:
        logger.warning("Cookie check failed for %s: %s", url, e)
    return findings


# ── CORS Check ──

async def check_cors(url: str) -> List[Dict]:
    """Check CORS configuration."""
    findings = []
    try:
        async with aiohttp.ClientSession() as session:
            headers = {"Origin": "https://evil-attacker.com"}
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=SCAN_TIMEOUT), ssl=False, headers=headers) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "*":
                    if acac.lower() == "true":
                        findings.append({
                            "id": "CORS-001", "title": "Wildcard CORS with Credentials",
                            "description": "Access-Control-Allow-Origin: * combined with Allow-Credentials violates CORS spec",
                            "severity": "high", "category": "CORS Configuration",
                            "framework": "OWASP A01:2021"
                        })
                    else:
                        findings.append({
                            "id": "CORS-002", "title": "Wildcard CORS Origin",
                            "description": "Access-Control-Allow-Origin allows all origins",
                            "severity": "medium", "category": "CORS Configuration",
                            "framework": "OWASP A01:2021"
                        })

                elif acao == "https://evil-attacker.com":
                    findings.append({
                        "id": "CORS-003", "title": "CORS Reflects Arbitrary Origins",
                        "description": "Server reflects any Origin header - equivalent to wildcard",
                        "severity": "high", "category": "CORS Configuration",
                        "framework": "OWASP A01:2021"
                    })
    except Exception as e:
        logger.warning("CORS check failed for %s: %s", url, e)
    return findings


# ── Exposed Files & Endpoints ──

async def check_common_misconfigs(url: str) -> List[Dict]:
    """Check for exposed files and common misconfigurations."""
    findings = []
    sensitive_paths = [
        ("/.env", "Environment file exposed", "high"),
        ("/.git/config", "Git repository exposed", "high"),
        ("/.git/HEAD", "Git HEAD file exposed", "high"),
        ("/config.php", "Config file exposed", "medium"),
        ("/phpinfo.php", "PHP info exposed", "medium"),
        ("/.htaccess", "htaccess file exposed", "medium"),
        ("/server-status", "Apache status exposed", "medium"),
        ("/wp-admin/", "WordPress admin panel found", "low"),
        ("/admin/", "Admin panel found", "low"),
        ("/phpmyadmin/", "phpMyAdmin found", "medium"),
        ("/docs", "API documentation exposed", "info"),
        ("/swagger", "Swagger UI exposed", "info"),
        ("/graphql", "GraphQL endpoint found", "info"),
        ("/actuator/health", "Spring Boot actuator exposed", "medium"),
        ("/.well-known/security.txt", "security.txt present", "info"),
        ("/robots.txt", "robots.txt present", "info"),
    ]

    try:
        async with aiohttp.ClientSession() as session:
            for path, issue, severity in sensitive_paths:
                try:
                    check_url = url.rstrip("/") + path
                    async with session.get(
                        check_url,
                        timeout=aiohttp.ClientTimeout(total=SCAN_FILE_TIMEOUT),
                        allow_redirects=False,
                        ssl=False
                    ) as resp:
                        if resp.status == 200:
                            findings.append({
                                "id": f"CFG-{path[1:6].upper().replace('/', '').replace('.', '')}",
                                "title": issue,
                                "description": f"Accessible at {path}",
                                "severity": severity,
                                "category": "Security Misconfiguration",
                                "framework": "OWASP A05:2021"
                            })
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass
    except Exception as e:
        logger.warning("Misconfiguration check failed for %s: %s", url, e)
    return findings


# ── Mixed Content Check ──

async def check_mixed_content(url: str) -> List[Dict]:
    """Check for mixed content on HTTPS pages."""
    findings = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return findings

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=SCAN_TIMEOUT), ssl=False) as resp:
                body = await resp.text()
                if "http://" in body and ("src=" in body or "href=" in body):
                    findings.append({
                        "id": "MIX-001", "title": "Potential Mixed Content",
                        "description": "Page contains HTTP references that may cause mixed content warnings",
                        "severity": "low", "category": "Transport Security",
                        "framework": "OWASP A02:2021"
                    })
    except Exception as e:
        logger.warning("Mixed content check failed for %s: %s", url, e)
    return findings


# ── Main Scan Runner ──

async def run_quick_scan(scan_id: str, target_url: str, user_id: str):
    """Run all security checks and persist results."""
    logger.info("Starting scan %s for %s", scan_id, target_url)
    await db.update_scan(scan_id, status="running")

    vulnerabilities = []

    # Run all checks
    checks = [
        check_ssl(target_url),
        check_security_headers(target_url),
        check_server_info(target_url),
        check_cookies(target_url),
        check_cors(target_url),
        check_common_misconfigs(target_url),
        check_mixed_content(target_url),
    ]

    results = await asyncio.gather(*checks, return_exceptions=True)

    for result in results:
        if isinstance(result, Exception):
            logger.error("Check failed: %s", result)
            continue
        if isinstance(result, dict):
            vulnerabilities.append(result)
        elif isinstance(result, list):
            vulnerabilities.extend(result)

    summary = {
        "total": len(vulnerabilities),
        "critical": sum(1 for v in vulnerabilities if v.get("severity") == "critical"),
        "high": sum(1 for v in vulnerabilities if v.get("severity") == "high"),
        "medium": sum(1 for v in vulnerabilities if v.get("severity") == "medium"),
        "low": sum(1 for v in vulnerabilities if v.get("severity") == "low"),
        "info": sum(1 for v in vulnerabilities if v.get("severity") == "info"),
    }

    await db.update_scan(
        scan_id,
        status="completed",
        vulnerabilities=vulnerabilities,
        summary=summary,
        completed_at=datetime.now().isoformat()
    )

    logger.info("Scan %s completed: %d findings", scan_id, len(vulnerabilities))
