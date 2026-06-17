"""SQLite audit log — stores scan results (vulnerabilities and bugs) for dashboard and reporting."""

import json
import logging
from pathlib import Path

import aiosqlite

logger = logging.getLogger(__name__)

DB_PATH = Path("data/aegis.db")

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    scan_task_id TEXT NOT NULL,
    finding_key TEXT NOT NULL,
    finding_rule TEXT NOT NULL,
    finding_file TEXT NOT NULL,
    finding_type TEXT NOT NULL DEFAULT 'VULNERABILITY',
    severity TEXT NOT NULL,
    github_issue_url TEXT,
    devin_session_id TEXT,
    devin_session_url TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    pr_url TEXT,
    tests_passed INTEGER,
    failure_reason TEXT,
    acu_consumed REAL DEFAULT 0.0,
    duration_seconds INTEGER
)
"""


async def init_db() -> None:
    """Create the database and table if they don't exist."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(CREATE_TABLE)
        await db.commit()
    logger.info("Database initialized at %s", DB_PATH)


async def insert_entry(entry: dict[str, object]) -> int:
    """Insert a new audit log entry. Returns the row id."""
    cols = [
        "timestamp", "scan_task_id", "finding_key", "finding_rule",
        "finding_file", "finding_type", "severity", "github_issue_url", "devin_session_id",
        "devin_session_url", "status", "pr_url", "tests_passed",
        "failure_reason", "acu_consumed", "duration_seconds",
    ]
    values = [entry.get(c) for c in cols]
    placeholders = ", ".join(["?"] * len(cols))
    col_names = ", ".join(cols)

    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            f"INSERT INTO audit_log ({col_names}) VALUES ({placeholders})",
            values,
        )
        await db.commit()
        row_id = cursor.lastrowid
    return row_id if row_id is not None else 0


async def update_entry(finding_key: str, scan_task_id: str, updates: dict[str, object]) -> None:
    """Update an existing audit log entry by finding_key + scan_task_id."""
    set_clauses = ", ".join([f"{k} = ?" for k in updates])
    values = list(updates.values()) + [finding_key, scan_task_id]

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            f"UPDATE audit_log SET {set_clauses} WHERE finding_key = ? AND scan_task_id = ?",
            values,
        )
        await db.commit()


async def get_entries(
    severity: str | None = None,
    status: str | None = None,
    scan_task_id: str | None = None,
    finding_type: str | None = None,
) -> list[dict[str, object]]:
    """Query audit log with optional filters."""
    query = "SELECT * FROM audit_log WHERE 1=1"
    params: list[object] = []

    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if status:
        query += " AND status = ?"
        params.append(status)
    if scan_task_id:
        query += " AND scan_task_id = ?"
        params.append(scan_task_id)
    if finding_type:
        query += " AND finding_type = ?"
        params.append(finding_type)

    query += " ORDER BY id DESC"

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(query, params)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_summary() -> dict[str, int]:
    """Compute KPI summary numbers."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT COUNT(*) FROM audit_log")
        row = await cursor.fetchone()
        total = row[0] if row else 0

        cursor = await db.execute("SELECT COUNT(*) FROM audit_log WHERE devin_session_id IS NOT NULL")
        row = await cursor.fetchone()
        sessions = row[0] if row else 0

        cursor = await db.execute("SELECT COUNT(*) FROM audit_log WHERE status = 'fixed'")
        row = await cursor.fetchone()
        resolved = row[0] if row else 0

        cursor = await db.execute("SELECT COUNT(*) FROM audit_log WHERE status IN ('failed', 'timed_out', 'error')")
        row = await cursor.fetchone()
        failed = row[0] if row else 0

    return {
        "findings_detected": total,
        "sessions_triggered": sessions,
        "resolved": resolved,
        "failed": failed,
    }


async def get_scan_runs() -> list[str]:
    """Get distinct scan task IDs for the filter dropdown."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT DISTINCT scan_task_id FROM audit_log ORDER BY id DESC")
        rows = await cursor.fetchall()
        return [row[0] for row in rows]
