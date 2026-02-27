"""
VibeSecurity - Authentication System
Handles signup, login, sessions, API keys with SQLite persistence.
"""
import uuid
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, List

import database as db
from config import SESSION_EXPIRY_DAYS, PBKDF2_ITERATIONS, PLAN_LIMITS

logger = logging.getLogger("vibesecurity.auth")


def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    """Hash password with PBKDF2-SHA256. Returns (salt:hash, salt)."""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), PBKDF2_ITERATIONS).hex()
    return f"{salt}:{hashed}", salt


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash."""
    try:
        salt, _ = stored_hash.split(":")
        new_hash, _ = hash_password(password, salt)
        return secrets.compare_digest(new_hash, stored_hash)
    except (ValueError, AttributeError):
        logger.warning("Malformed password hash encountered")
        return False


async def signup(email: str, password: str, name: str = "", company: str = "") -> Dict:
    """Register a new user. Returns dict with success status."""
    existing = await db.get_user_by_email(email)
    if existing:
        return {"success": False, "error": "Email already registered"}

    if len(password) < 8:
        return {"success": False, "error": "Password must be at least 8 characters"}

    user_id = f"user_{uuid.uuid4().hex[:12]}"
    password_hash, _ = hash_password(password)

    created = await db.create_user(user_id, email, password_hash, name, company)
    if not created:
        return {"success": False, "error": "Email already registered"}

    # Generate default API key
    api_key = f"vs_live_{secrets.token_urlsafe(24)}"
    await db.create_api_key(api_key, user_id, "Default Key")

    logger.info("New user registered: %s", email)
    return {"success": True, "user_id": user_id, "api_key": api_key}


async def login(email: str, password: str) -> Dict:
    """Authenticate user. Returns dict with session token on success."""
    user = await db.get_user_by_email(email)
    if not user or not verify_password(password, user["password_hash"]):
        return {"success": False, "error": "Invalid email or password"}

    session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(16)
    expires_at = (datetime.now() + timedelta(days=SESSION_EXPIRY_DAYS)).isoformat()

    await db.create_session(session_token, user["id"], expires_at, csrf_token)

    logger.info("User logged in: %s", email)
    return {
        "success": True,
        "user_id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "session_token": session_token,
        "csrf_token": csrf_token,
        "plan": user["plan"],
    }


async def get_user_from_session(session_token: str) -> Optional[Dict]:
    """Get user from session token. Returns None if invalid/expired."""
    if not session_token:
        return None

    session = await db.get_session(session_token)
    if not session:
        return None

    if datetime.fromisoformat(session["expires_at"]) < datetime.now():
        await db.delete_session(session_token)
        return None

    user = await db.get_user_by_id(session["user_id"])
    if user:
        user["csrf_token"] = session["csrf_token"]
    return user


async def logout(session_token: str):
    """Invalidate a session."""
    await db.delete_session(session_token)


async def generate_api_key(user_id: str, name: str = "API Key") -> Dict:
    """Generate a new API key for a user."""
    user = await db.get_user_by_id(user_id)
    if not user:
        return {"success": False, "error": "User not found"}

    key = f"vs_live_{secrets.token_urlsafe(24)}"
    await db.create_api_key(key, user_id, name)

    logger.info("API key generated for user %s", user_id)
    return {"success": True, "key": key, "name": name}


async def validate_api_key(key: str) -> Optional[Dict]:
    """Validate an API key. Returns user info or None."""
    result = await db.validate_api_key(key)
    if result:
        await db.increment_api_usage(result["user_id"])
    return result


async def check_plan_limit(user_id: str, plan: str) -> tuple[bool, str]:
    """Check if user is within their plan's scan limit."""
    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])
    if limits["scans_per_month"] == -1:
        return True, ""

    usage = await db.get_user_usage(user_id)
    if usage["scans"] >= limits["scans_per_month"]:
        return False, f"Monthly scan limit reached ({limits['scans_per_month']} scans). Upgrade your plan for more."

    return True, ""
