"""
VibeSecurity - Configuration
All settings loaded from environment variables with sensible defaults.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# Server
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))

# Database
DATABASE_PATH = os.getenv("DATABASE_PATH", "data/vibesecurity.db")

# Auth
SESSION_EXPIRY_DAYS = int(os.getenv("SESSION_EXPIRY_DAYS", "7"))
PBKDF2_ITERATIONS = int(os.getenv("PBKDF2_ITERATIONS", "100000"))

# Security
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "https://vibesecurity.in,https://app.vibesecurity.in").split(",")

# Rate Limiting
RATE_LIMIT_LOGIN = os.getenv("RATE_LIMIT_LOGIN", "5/minute")
RATE_LIMIT_SIGNUP = os.getenv("RATE_LIMIT_SIGNUP", "3/minute")
RATE_LIMIT_SCAN = os.getenv("RATE_LIMIT_SCAN", "10/minute")
RATE_LIMIT_API = os.getenv("RATE_LIMIT_API", "30/minute")

# Plan Limits (scans per month)
PLAN_LIMITS = {
    "free": {"scans_per_month": 5, "api_calls_per_month": 100},
    "pro": {"scans_per_month": 100, "api_calls_per_month": 5000},
    "enterprise": {"scans_per_month": -1, "api_calls_per_month": -1},
}

# Scanner
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "10"))
SCAN_FILE_TIMEOUT = int(os.getenv("SCAN_FILE_TIMEOUT", "3"))
SSL_CHECK_TIMEOUT = int(os.getenv("SSL_CHECK_TIMEOUT", "5"))

# Contact
CONTACT_EMAIL = os.getenv("CONTACT_EMAIL", "hello@vibesecurity.in")
ENTERPRISE_EMAIL = os.getenv("ENTERPRISE_EMAIL", "enterprise@vibesecurity.in")
