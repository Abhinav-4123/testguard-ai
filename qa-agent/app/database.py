"""
TestGuard AI - Database Layer (SQLite via aiosqlite)
Persistent storage for test results, security scans, API keys, and customers.
"""
import json
import logging
import aiosqlite
from pathlib import Path
from typing import Optional, Dict, List

logger = logging.getLogger("testguard.database")

DB_PATH = Path("data/testguard.db")


async def init_db():
    """Initialize database schema."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS test_results (
                test_id TEXT PRIMARY KEY,
                status TEXT DEFAULT 'pending',
                url TEXT NOT NULL,
                objective TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                report_path TEXT,
                summary TEXT DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS security_scans (
                scan_id TEXT PRIMARY KEY,
                status TEXT DEFAULT 'pending',
                url TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                frameworks TEXT DEFAULT '[]',
                overall_score INTEGER DEFAULT 0,
                framework_scores TEXT DEFAULT '{}',
                vulnerabilities TEXT DEFAULT '[]',
                summary TEXT DEFAULT '{}',
                report TEXT,
                error TEXT
            );
            CREATE TABLE IF NOT EXISTS api_keys (
                key TEXT PRIMARY KEY,
                name TEXT DEFAULT 'API Key',
                created_at TEXT NOT NULL,
                last_used TEXT,
                active INTEGER DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS customers (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                name TEXT NOT NULL,
                company TEXT,
                stripe_customer_id TEXT,
                subscription_id TEXT,
                plan TEXT,
                status TEXT DEFAULT 'created',
                created_at TEXT NOT NULL,
                tests_run INTEGER DEFAULT 0,
                alerts_sent INTEGER DEFAULT 0
            );
        """)
    logger.info("Database initialized at %s", DB_PATH)


def _get_db():
    return aiosqlite.connect(DB_PATH)


# --- Test Results ---

async def save_test_result(test_id: str, status: str, url: str, objective: str, started_at: str):
    async with _get_db() as db:
        await db.execute(
            "INSERT OR REPLACE INTO test_results (test_id, status, url, objective, started_at) VALUES (?, ?, ?, ?, ?)",
            (test_id, status, url, objective, started_at)
        )
        await db.commit()


async def update_test_result(test_id: str, **kwargs):
    async with _get_db() as db:
        fields = []
        params = []
        for key, value in kwargs.items():
            if key == "summary" and isinstance(value, dict):
                value = json.dumps(value)
            fields.append(f"{key} = ?")
            params.append(value)
        params.append(test_id)
        if fields:
            await db.execute(f"UPDATE test_results SET {', '.join(fields)} WHERE test_id = ?", params)
            await db.commit()


async def get_test_result(test_id: str) -> Optional[Dict]:
    async with _get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM test_results WHERE test_id = ?", (test_id,))
        row = await cursor.fetchone()
        if row:
            r = dict(row)
            r["summary"] = json.loads(r.get("summary") or "{}")
            return r
        return None


async def get_all_test_results() -> List[Dict]:
    async with _get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM test_results ORDER BY started_at DESC LIMIT 100")
        rows = await cursor.fetchall()
        results = []
        for row in rows:
            r = dict(row)
            r["summary"] = json.loads(r.get("summary") or "{}")
            results.append(r)
        return results


# --- Security Scans ---

async def save_security_scan(scan_id: str, url: str, started_at: str, frameworks: list):
    async with _get_db() as db:
        await db.execute(
            "INSERT INTO security_scans (scan_id, status, url, started_at, frameworks) VALUES (?, 'pending', ?, ?, ?)",
            (scan_id, url, started_at, json.dumps(frameworks))
        )
        await db.commit()


async def update_security_scan(scan_id: str, **kwargs):
    async with _get_db() as db:
        fields = []
        params = []
        for key, value in kwargs.items():
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            fields.append(f"{key} = ?")
            params.append(value)
        params.append(scan_id)
        if fields:
            await db.execute(f"UPDATE security_scans SET {', '.join(fields)} WHERE scan_id = ?", params)
            await db.commit()


async def get_security_scan(scan_id: str) -> Optional[Dict]:
    async with _get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM security_scans WHERE scan_id = ?", (scan_id,))
        row = await cursor.fetchone()
        if row:
            r = dict(row)
            for field in ["frameworks", "framework_scores", "vulnerabilities", "summary"]:
                r[field] = json.loads(r.get(field) or "[]" if field in ["frameworks", "vulnerabilities"] else r.get(field) or "{}")
            return r
        return None


async def get_all_security_scans() -> List[Dict]:
    async with _get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT scan_id, status, url, started_at, completed_at, overall_score FROM security_scans ORDER BY started_at DESC LIMIT 100")
        return [dict(row) for row in await cursor.fetchall()]


# --- API Keys ---

async def create_api_key(key: str, name: str = "API Key"):
    async with _get_db() as db:
        await db.execute(
            "INSERT INTO api_keys (key, name, created_at) VALUES (?, ?, datetime('now'))",
            (key, name)
        )
        await db.commit()


async def validate_api_key(key: str) -> bool:
    async with _get_db() as db:
        cursor = await db.execute("SELECT key FROM api_keys WHERE key = ? AND active = 1", (key,))
        row = await cursor.fetchone()
        if row:
            await db.execute("UPDATE api_keys SET last_used = datetime('now') WHERE key = ?", (key,))
            await db.commit()
            return True
        return False


# --- Customers ---

async def save_customer(customer_id: str, email: str, name: str, company: str = None, stripe_customer_id: str = None):
    async with _get_db() as db:
        await db.execute(
            "INSERT INTO customers (id, email, name, company, stripe_customer_id, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))",
            (customer_id, email, name, company, stripe_customer_id)
        )
        await db.commit()


async def get_customer(customer_id: str) -> Optional[Dict]:
    async with _get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM customers WHERE id = ?", (customer_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None


async def update_customer(customer_id: str, **kwargs):
    async with _get_db() as db:
        fields = []
        params = []
        for key, value in kwargs.items():
            fields.append(f"{key} = ?")
            params.append(value)
        params.append(customer_id)
        if fields:
            await db.execute(f"UPDATE customers SET {', '.join(fields)} WHERE id = ?", params)
            await db.commit()


async def get_customer_usage(customer_id: str) -> Dict:
    async with _get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT tests_run, alerts_sent FROM customers WHERE id = ?", (customer_id,))
        row = await cursor.fetchone()
        if row:
            return {"tests_run": row["tests_run"], "alerts_sent": row["alerts_sent"]}
        return {"tests_run": 0, "alerts_sent": 0}


# --- Stats ---

async def get_stats() -> Dict:
    async with _get_db() as db:
        cursor = await db.execute("SELECT COUNT(*) FROM test_results")
        total_tests = (await cursor.fetchone())[0]
        cursor = await db.execute("SELECT COUNT(*) FROM test_results WHERE status = 'completed'")
        completed_tests = (await cursor.fetchone())[0]
        cursor = await db.execute("SELECT COUNT(*) FROM test_results WHERE status = 'failed'")
        failed_tests = (await cursor.fetchone())[0]
        cursor = await db.execute("SELECT COUNT(*) FROM test_results WHERE status IN ('pending', 'running')")
        running_tests = (await cursor.fetchone())[0]
        cursor = await db.execute("SELECT COUNT(*) FROM security_scans")
        total_scans = (await cursor.fetchone())[0]
        cursor = await db.execute("SELECT COUNT(*) FROM security_scans WHERE status = 'completed'")
        completed_scans = (await cursor.fetchone())[0]
        cursor = await db.execute("SELECT COALESCE(AVG(overall_score), 0) FROM security_scans WHERE status = 'completed'")
        avg_score = (await cursor.fetchone())[0]

        return {
            "tests": {
                "total": total_tests,
                "passed": completed_tests - failed_tests,
                "failed": failed_tests,
                "running": running_tests,
            },
            "security": {
                "total_scans": total_scans,
                "completed": completed_scans,
                "average_score": round(avg_score),
            },
        }
