"""Dashboard routes — executive summary and audit log."""

from fastapi import APIRouter

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard")
async def dashboard() -> dict[str, str]:
    """Render executive dashboard (Jinja2 template in later stage)."""
    # TODO Stage 7: Jinja2 template rendering
    return {"status": "dashboard placeholder"}


@router.get("/api/results")
async def results() -> dict[str, list[object]]:
    """Return audit log entries as JSON."""
    # TODO Stage 7: query SQLite and return filtered results
    return {"entries": []}


@router.get("/api/summary")
async def summary() -> dict[str, int]:
    """Return executive summary KPI numbers."""
    # TODO Stage 7: compute from audit_log
    return {
        "findings_detected": 0,
        "sessions_triggered": 0,
        "resolved": 0,
        "failed": 0,
    }
