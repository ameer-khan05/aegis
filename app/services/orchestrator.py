"""Orchestrator — coordinates the full remediation pipeline."""

import asyncio
import logging
from datetime import datetime, timezone

from app.db import init_db, insert_entry, update_entry
from app.models import Finding
from app.services.devin import launch_session, poll_session
from app.services.github import create_issue
from app.services.sonar import fetch_vulnerabilities

logger = logging.getLogger(__name__)


async def run_remediation(scan_task_id: str) -> None:
    """Full remediation loop triggered by a webhook.

    1. Fetch findings from SonarCloud
    2. For each finding: create GitHub issue, launch Devin session
    3. Poll sessions to terminal state
    4. Record results in audit log
    """
    await init_db()

    logger.info("Starting remediation for scan %s", scan_task_id)

    # Step 1: Fetch findings
    findings = await fetch_vulnerabilities()
    if not findings:
        logger.info("No findings to remediate")
        return

    logger.info("Found %d findings to process", len(findings))

    # Step 2-3: For each finding, create issue + launch session + poll
    tasks = [_process_finding(scan_task_id, f) for f in findings]
    await asyncio.gather(*tasks, return_exceptions=True)

    logger.info("Remediation complete for scan %s", scan_task_id)


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
