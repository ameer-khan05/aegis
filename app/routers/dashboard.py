"""Dashboard routes — executive summary and audit log."""

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.db import get_entries, get_scan_runs, get_summary

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    severity: str | None = None,
    status: str | None = None,
    scan_run: str | None = None,
    issue_type: str | None = None,
) -> HTMLResponse:
    """Render executive dashboard with KPI cards, filters, and audit table."""
    summary = await get_summary()
    entries = await get_entries(
        severity=severity, status=status, scan_task_id=scan_run, finding_type=issue_type,
    )
    scan_runs = await get_scan_runs()

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        context={
            "summary": summary,
            "entries": entries,
            "scan_runs": scan_runs,
            "filters": {
                "severity": severity,
                "status": status,
                "scan_run": scan_run,
                "issue_type": issue_type,
            },
        },
    )


@router.get("/api/results")
async def results(
    severity: str | None = None,
    status: str | None = None,
    scan_run: str | None = None,
    issue_type: str | None = None,
) -> dict[str, list[dict[str, object]]]:
    """Return audit log entries as JSON."""
    entries = await get_entries(
        severity=severity, status=status, scan_task_id=scan_run, finding_type=issue_type,
    )
    return {"entries": entries}


@router.get("/api/summary")
async def summary() -> dict[str, int]:
    """Return executive summary KPI numbers."""
    return await get_summary()
