"""Orchestrator — fetches findings and populates the Jira board.

A run does NOT launch Devin sessions. It only:
1. Fetches findings from SonarCloud
2. Creates a Jira ticket (To Do) + GitHub issue per finding
3. Records each finding in the audit log as 'pending'

Devin sessions are launched exclusively by the /webhook/jira endpoint
when a ticket is moved To Do → In Progress.
"""

import asyncio
import logging
from datetime import datetime, timezone

from app.config import settings
from app.db import has_active_entry, has_scan_run, init_db, insert_entry, update_entry
from app.models import Finding
from app.services.devin import cancel_session
from app.services.github import create_issue
from app.services.jira import create_ticket
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
    """Return findings sorted by severity (most severe first), then most recent first."""
    by_date = sorted(findings, key=lambda f: f.creation_date or "", reverse=True)
    return sorted(by_date, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))


async def run_remediation(scan_task_id: str) -> None:
    """Populate the Jira board with tickets for new findings.

    1. Check idempotency — reject duplicate scan runs
    2. Fetch findings from SonarCloud (capped at MAX_FINDINGS_PER_RUN)
    3. Deduplicate — skip findings already tracked
    4. Sort by severity then recency
    5. Create a Jira ticket (To Do) + GitHub issue per finding
    6. Record each in the audit log as 'pending'

    No Devin sessions are launched here. Move a ticket to In Progress
    in Jira to trigger remediation via /webhook/jira.
    """
    await init_db()

    if await has_scan_run(scan_task_id):
        logger.warning(
            "Scan %s already processed — skipping duplicate webhook", scan_task_id,
        )
        return

    findings_cap = settings.MAX_FINDINGS_PER_RUN
    logger.info(
        "Starting ticket creation for scan %s (findings cap: %d)",
        scan_task_id, findings_cap,
    )

    findings = await fetch_vulnerabilities()
    if not findings:
        logger.info("No findings to process")
        return

    total_fetched = len(findings)
    logger.info("Fetched %d findings", total_fetched)

    # Deduplicate — remove findings that already have active entries
    new_findings: list[Finding] = []
    for f in findings:
        if await has_active_entry(f.key):
            logger.info("Skipping duplicate finding %s (already active)", f.key)
        else:
            new_findings.append(f)

    deduped_count = total_fetched - len(new_findings)
    if deduped_count:
        logger.info(
            "Deduplication: %d already active, %d new findings remain",
            deduped_count, len(new_findings),
        )

    if not new_findings:
        logger.info("All findings already have active entries — nothing to do")
        return

    ranked = prioritize_findings(new_findings)

    logger.info(
        "%d fetched, %d deduped, %d new → creating tickets",
        total_fetched, deduped_count, len(ranked),
    )

    # Create a Jira ticket + GitHub issue for every new finding
    tasks = [_record_finding(scan_task_id, f) for f in ranked]
    await asyncio.gather(*tasks, return_exceptions=True)

    logger.info(
        "Scan %s complete — %d tickets created. Move tickets To Do → "
        "In Progress in Jira to trigger remediation.",
        scan_task_id, len(ranked),
    )


async def _record_finding(scan_task_id: str, finding: Finding) -> None:
    """Create a Jira ticket + GitHub issue and record the finding as pending."""
    now = datetime.now(timezone.utc).isoformat()

    entry: dict[str, object] = {
        "timestamp": now,
        "scan_task_id": scan_task_id,
        "finding_key": finding.key,
        "finding_rule": finding.rule,
        "finding_file": finding.component,
        "finding_type": finding.type,
        "severity": finding.severity,
        "status": "pending",
        "problem_summary": finding.message,
    }

    jira = await create_ticket(finding)
    if jira:
        entry["jira_ticket_key"] = jira["key"]
        entry["jira_ticket_url"] = jira["url"]

    await insert_entry(entry)

    issue_url = await create_issue(finding)
    if issue_url:
        await update_entry(finding.key, scan_task_id, {"github_issue_url": issue_url})

    logger.info(
        "Recorded finding %s (%s) — Jira: %s",
        finding.key, finding.severity, entry.get("jira_ticket_key", "n/a"),
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
