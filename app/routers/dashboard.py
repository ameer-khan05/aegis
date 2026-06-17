"""Dashboard routes — executive summary, audit log, and session management."""

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.config import settings
from app.db import get_entries, get_scan_runs, get_summary
from app.services.devin import cancel_session
from app.services.orchestrator import cancel_run_sessions

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
            "max_findings_per_run": settings.MAX_FINDINGS_PER_RUN,
            "max_sessions_per_run": settings.MAX_SESSIONS_PER_RUN,
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
async def summary() -> dict[str, int | float]:
    """Return executive summary KPI numbers."""
    return await get_summary()


@router.post("/api/runs/{scan_task_id}/cancel")
async def cancel_run(scan_task_id: str) -> JSONResponse:
    """Cancel all in-flight Devin sessions for a scan run."""
    results = await cancel_run_sessions(scan_task_id)
    if not results:
        return JSONResponse(
            status_code=404,
            content={"detail": "No in-flight sessions found for this run"},
        )
    return JSONResponse(content={"cancelled": results})


@router.post("/api/sessions/{session_id}/cancel")
async def cancel_single_session(session_id: str) -> JSONResponse:
    """Cancel a single in-flight Devin session."""
    from app.db import update_entry, get_entries

    ok = await cancel_session(session_id)
    if not ok:
        return JSONResponse(
            status_code=502,
            content={"detail": f"Failed to cancel session {session_id}"},
        )

    # Update audit log entry for this session
    entries = await get_entries(status="in_progress")
    for entry in entries:
        if entry.get("devin_session_id") == session_id:
            await update_entry(
                str(entry["finding_key"]), str(entry["scan_task_id"]),
                {"status": "cancelled", "failure_reason": "Manually cancelled"},
            )
            break

    return JSONResponse(content={"session_id": session_id, "status": "cancelled"})
