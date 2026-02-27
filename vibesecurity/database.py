"""
VibeSecurity - Database Layer (SQLite via aiosqlite)
Persistent storage for users, sessions, API keys, and scan results.
"""
import json
import logging
import aiosqlite
from pathlib import Path
from typing import Optional, Dict, List

from config import DATABASE_PATH

logger = logging.getLogger("vibesecurity.database")

DB_PATH = Path(DATABASE_PATH)


async def init_db():
    """Initialize database schema."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                name TEXT DEFAULT '',
                company TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                verified INTEGER DEFAULT 0,
                plan TEXT DEFAULT 'free',
                scan_count INTEGER DEFAULT 0,
                api_call_count INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS api_keys (
                key TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id),
                name TEXT DEFAULT 'API Key',
                created_at TEXT NOT NULL,
                last_used TEXT,
                active INTEGER DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id),
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                csrf_token TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                user_id TEXT NOT NULL REFERENCES users(id),
                status TEXT DEFAULT 'queued',
                started_at TEXT NOT NULL,
                completed_at TEXT,
                vulnerabilities TEXT DEFAULT '[]',
                summary TEXT DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id);
        """)
    logger.info("Database initialized at %s", DB_PATH)


def _get_db():
    return aiosqlite.connect(DB_PATH)


# --- User Operations ---

async def create_user(user_id: str, email: str, password_hash: str, name: str = "", company: str = "") -> bool:
    async with _get_db() as db:
        try:
            await db.execute(
                "INSERT INTO users (id, email, password_hash, name, company, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))",
                (user_id, email.lower(), password_hash, name, company)
            )
            await db.commit()
            return True
        except aiosqlite.IntegrityError:
            return False


async def get_user_by_email(email: str) -> Optional[Dict]:
    async with _get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM users WHERE email = ?", (email.lower(),))
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_user_by_id(user_id: str) -> Optional[Dict]:
    async with _get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None


async def increment_scan_usage(user_id: str):
    async with _get_db() as db:
        await db.execute("UPDATE users SET scan_count = scan_count + 1 WHERE id = ?", (user_id,))
        await db.commit()


async def increment_api_usage(user_id: str):
    async with _get_db() as db:
        await db.execute("UPDATE users SET api_call_count = api_call_count + 1 WHERE id = ?", (user_id,))
        await db.commit()


async def get_user_usage(user_id: str) -> Dict:
    async with _get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT scan_count, api_call_count FROM users WHERE id = ?", (user_id,))
        row = await cursor.fetchone()
        if row:
            return {"scans": row["scan_count"], "api_calls": row["api_call_count"]}
        return {"scans": 0, "api_calls": 0}


async def get_stats() -> Dict:
    async with _get_db() as db:
        cursor = await db.execute("SELECT COUNT(*) as c FROM users")
        total_users = (await cursor.fetchone())[0]
        cursor = await db.execute("SELECT COALESCE(SUM(scan_count), 0) as c FROM users")
        total_scans = (await cursor.fetchone())[0]
        cursor = await db.execute("SELECT COALESCE(SUM(api_call_count), 0) as c FROM users")
        total_api_calls = (await cursor.fetchone())[0]
        return {"total_users": total_users, "total_scans": total_scans, "total_api_calls": total_api_calls}


# --- Session Operations ---

async def create_session(token: str, user_id: str, expires_at: str, csrf_token: str):
    async with _get_db() as db:
        await db.execute(
            "INSERT INTO sessions (token, user_id, expires_at, created_at, csrf_token) VALUES (?, ?, ?, datetime('now'), ?)",
            (token, user_id, expires_at, csrf_token)
        )
        await db.commit()


async def get_session(token: str) -> Optional[Dict]:
    async with _get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM sessions WHERE token = ?", (token,))
        row = await cursor.fetchone()
        return dict(row) if row else None


async def delete_session(token: str):
    async with _get_db() as db:
        await db.execute("DELETE FROM sessions WHERE token = ?", (token,))
        await db.commit()


async def cleanup_expired_sessions():
    async with _get_db() as db:
        await db.execute("DELETE FROM sessions WHERE expires_at < datetime('now')")
        await db.commit()


# --- API Key Operations ---

async def create_api_key(key: str, user_id: str, name: str = "API Key"):
    async with _get_db() as db:
        await db.execute(
            "INSERT INTO api_keys (key, user_id, name, created_at) VALUES (?, ?, ?, datetime('now'))",
            (key, user_id, name)
        )
        await db.commit()


async def validate_api_key(key: str) -> Optional[Dict]:
    async with _get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT ak.key, ak.user_id, u.email, u.plan FROM api_keys ak JOIN users u ON ak.user_id = u.id WHERE ak.key = ? AND ak.active = 1",
            (key,)
        )
        row = await cursor.fetchone()
        if row:
            await db.execute("UPDATE api_keys SET last_used = datetime('now') WHERE key = ?", (key,))
            await db.commit()
            return dict(row)
        return None


async def get_user_api_keys(user_id: str) -> List[Dict]:
    async with _get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT key, name, created_at, last_used, active FROM api_keys WHERE user_id = ?",
            (user_id,)
        )
        rows = await cursor.fetchall()
        return [
            {
                "key": f"{row['key'][:12]}...{row['key'][-4:]}",
                "name": row["name"],
                "created_at": row["created_at"],
                "last_used": row["last_used"],
                "active": bool(row["active"]),
            }
            for row in rows
        ]


# --- Scan Operations ---

async def create_scan(scan_id: str, target: str, user_id: str, started_at: str):
    async with _get_db() as db:
        await db.execute(
            "INSERT INTO scans (id, target, user_id, status, started_at) VALUES (?, ?, ?, 'queued', ?)",
            (scan_id, target, user_id, started_at)
        )
        await db.commit()


async def update_scan(scan_id: str, status: str, vulnerabilities: list = None, summary: dict = None, completed_at: str = None):
    async with _get_db() as db:
        fields = ["status = ?"]
        params = [status]
        if vulnerabilities is not None:
            fields.append("vulnerabilities = ?")
            params.append(json.dumps(vulnerabilities))
        if summary is not None:
            fields.append("summary = ?")
            params.append(json.dumps(summary))
        if completed_at:
            fields.append("completed_at = ?")
            params.append(completed_at)
        params.append(scan_id)
        await db.execute(f"UPDATE scans SET {', '.join(fields)} WHERE id = ?", params)
        await db.commit()


async def get_scan(scan_id: str) -> Optional[Dict]:
    async with _get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = await cursor.fetchone()
        if row:
            result = dict(row)
            result["vulnerabilities"] = json.loads(result.get("vulnerabilities") or "[]")
            result["summary"] = json.loads(result.get("summary") or "{}")
            return result
        return None


async def get_user_scans(user_id: str, limit: int = 50) -> List[Dict]:
    async with _get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT id, target, status, started_at, completed_at, summary FROM scans WHERE user_id = ? ORDER BY started_at DESC LIMIT ?",
            (user_id, limit)
        )
        rows = await cursor.fetchall()
        results = []
        for row in rows:
            r = dict(row)
            r["summary"] = json.loads(r.get("summary") or "{}")
            results.append(r)
        return results
