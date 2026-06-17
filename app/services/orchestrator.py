"""Orchestrator — coordinates the full remediation pipeline."""

import asyncio
import logging
from datetime import datetime, timezone

from app.config import settings
from app.db import init_db, insert_entry, update_entry
from app.models import Finding
from app.services.devin import cancel_session, launch_session, poll_session
from app.services.github import create_issue
from app.services.sonar import fetch_vulnerabilities

logger = logging.getLogger(__name__)

SEVERITY_ORDER: dict[str, int] = {
    "BLOCKER": 0,
    "CRITICAL": 1,
    "MAJOR": 2,
    "MINOR": 3,
    "INFO": 4,
}


def prioritize_findings(findings: list[Finding]) -> list[Finding]:
    """Return findings sorted by severity (most severe first), then most recent first.

    Uses a two-pass stable sort: first by creation_date descending, then by
    severity ascending.  Because Python's sort is stable, equal-severity
    findings keep their date-descending order.
    """
    by_date = sorted(findings, key=lambda f: f.creation_date or "", reverse=True)
    return sorted(by_date, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))


async def run_remediation(scan_task_id: str) -> None:
    """Full remediation loop triggered by a webhook.

    1. Fetch ALL findings from SonarCloud (for reporting)
    2. Record every finding in the audit log
    3. Sort by severity (most severe first) then recency
    4. Launch Devin sessions only for the top MAX_SESSIONS_PER_RUN findings
    5. Mark the rest as 'skipped' so the dashboard shows the cap clearly
    """
    await init_db()

    cap = settings.MAX_SESSIONS_PER_RUN
    logger.info("Starting remediation for scan %s (session cap: %d)", scan_task_id, cap)

    # Step 1: Fetch ALL findings
    findings = await fetch_vulnerabilities()
    if not findings:
        logger.info("No findings to remediate")
        return

    total_detected = len(findings)
    logger.info("Found %d findings total", total_detected)

    # Step 2: Prioritize — severity desc, then most recent first
    ranked = prioritize_findings(findings)

    # Step 3: Split into remediation batch vs skipped
    to_remediate = ranked[:cap]
    to_skip = ranked[cap:]

    logger.info(
        "%d detected, %d will be remediated this run, %d skipped (cap=%d)",
        total_detected, len(to_remediate), len(to_skip), cap,
    )

    # Step 4: Record skipped findings in audit log
    skip_tasks = [_record_skipped(scan_task_id, f) for f in to_skip]
    await asyncio.gather(*skip_tasks, return_exceptions=True)

    # Step 5: Process the top-N findings (issue + session + poll)
    remediate_tasks = [_process_finding(scan_task_id, f) for f in to_remediate]
    await asyncio.gather(*remediate_tasks, return_exceptions=True)

    logger.info(
        "Remediation complete for scan %s — %d detected, %d remediated",
        scan_task_id, total_detected, len(to_remediate),
    )


async def _record_skipped(scan_task_id: str, finding: Finding) -> None:
    """Insert a 'skipped' audit entry for a finding that exceeded the session cap."""
    now = datetime.now(timezone.utc).isoformat()
    entry = {
        "timestamp": now,
        "scan_task_id": scan_task_id,
        "finding_key": finding.key,
        "finding_rule": finding.rule,
        "finding_file": finding.component,
        "finding_type": finding.type,
        "severity": finding.severity,
        "status": "skipped",
        "failure_reason": f"Exceeded MAX_SESSIONS_PER_RUN ({settings.MAX_SESSIONS_PER_RUN})",
    }
    await insert_entry(entry)


async def _process_finding(scan_task_id: str, finding: Finding) -> None:
    """Process a single finding: create issue, launch session, poll, record."""
    now = datetime.now(timezone.utc).isoformat()

    # Insert initial audit entry
    entry = {
        "timestamp": now,
        "scan_task_id": scan_task_id,
        "finding_key": finding.key,
        "finding_rule": finding.rule,
        "finding_file": finding.component,
        "finding_type": finding.type,
        "severity": finding.severity,
        "status": "pending",
    }
    await insert_entry(entry)

    # Create GitHub issue
    issue_url = await create_issue(finding)
    if issue_url:
        await update_entry(finding.key, scan_task_id, {"github_issue_url": issue_url})

    # Launch Devin session
    session_info = await launch_session(finding)
    if not session_info:
        await update_entry(finding.key, scan_task_id, {
            "status": "error",
            "failure_reason": "Failed to launch Devin session",
        })
        return

    session_id = session_info["session_id"]
    session_url = session_info["url"]
    await update_entry(finding.key, scan_task_id, {
        "devin_session_id": session_id,
        "devin_session_url": session_url,
        "status": "in_progress",
    })

    # Poll session to completion
    result = await poll_session(session_id)
    if result is None:
        await update_entry(finding.key, scan_task_id, {
            "status": "timed_out",
            "failure_reason": "Session timed out",
        })
        return

    # Record final result
    status = "fixed" if result.fixed else "failed"
    await update_entry(finding.key, scan_task_id, {
        "status": status,
        "pr_url": result.pr_url,
        "tests_passed": 1 if result.tests_passed else 0,
        "failure_reason": result.failure_reason,
    })

    logger.info(
        "Finding %s: status=%s fixed=%s pr=%s",
        finding.key, status, result.fixed, result.pr_url,
    )


async def cancel_run_sessions(scan_task_id: str) -> dict[str, str]:
    """Cancel all in-flight Devin sessions for a given scan run.

    Returns a mapping of session_id → cancel result ('cancelled' | error message).
    """
    from app.db import get_entries

    entries = await get_entries(status="in_progress", scan_task_id=scan_task_id)
    results: dict[str, str] = {}

    for entry in entries:
        session_id = entry.get("devin_session_id")
        if not session_id or not isinstance(session_id, str):
            continue

        ok = await cancel_session(session_id)
        if ok:
            await update_entry(
                str(entry["finding_key"]), scan_task_id,
                {"status": "cancelled", "failure_reason": "Manually cancelled"},
            )
            results[session_id] = "cancelled"
        else:
            results[session_id] = "cancel_failed"

    return results
