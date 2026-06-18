"""Webhook receiver for Jira automation events (ticket transitions)."""

import logging

from fastapi import APIRouter, BackgroundTasks, Request, Response

from app.config import settings
from app.db import get_entries, init_db, update_entry
from app.models import Finding
from app.services.devin import launch_session, poll_session
from app.services.jira import transition_ticket

logger = logging.getLogger(__name__)

router = APIRouter(tags=["jira-webhook"])


async def _count_in_progress() -> int:
    """Count the number of currently in-progress Devin sessions."""
    entries = await get_entries(status="in_progress")
    return len(entries)


async def _process_jira_finding(finding: Finding, ticket_key: str, scan_task_id: str) -> None:
    """Launch a Devin session for a finding triggered by a Jira transition."""
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

    result = await poll_session(session_id)
    if result is None:
        await update_entry(finding.key, scan_task_id, {
            "status": "timed_out",
            "failure_reason": "Session timed out",
        })
        return

    status = "fixed" if result.fixed else "failed"
    await update_entry(finding.key, scan_task_id, {
        "status": status,
        "pr_url": result.pr_url,
        "tests_passed": 1 if result.tests_passed else 0,
        "failure_reason": result.failure_reason,
        "fix_summary": result.fix_summary,
        "acu_consumed": result.acu_consumed,
    })

    # Transition Jira ticket to Done if fix was successful
    if result.fixed and result.pr_url:
        await transition_ticket(ticket_key, "Done")

    logger.info(
        "Jira-triggered finding %s: status=%s fixed=%s pr=%s",
        finding.key, status, result.fixed, result.pr_url,
    )


@router.post("/webhook/jira")
async def jira_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
) -> Response:
    """Receive Jira automation webhook when a ticket transitions To Do → In Progress.

    Authentication: If JIRA_WEBHOOK_SECRET is set, the request must include
    an ``X-Aegis-Secret`` header with the matching value.

    Expected payload shape (configured in Jira Automation):
    {
      "issue": {
        "key": "KAN-123",
        "fields": {
          "summary": "...",
          "status": { "name": "In Progress" }
        }
      },
      "transition": {
        "from_status": "To Do",
        "to_status": "In Progress"
      }
    }
    """
    # Validate shared secret if configured
    if settings.JIRA_WEBHOOK_SECRET:
        provided = request.headers.get("X-Aegis-Secret", "")
        if provided != settings.JIRA_WEBHOOK_SECRET:
            logger.warning("Jira webhook rejected: invalid or missing X-Aegis-Secret header")
            return Response(status_code=401, content="invalid secret")

    payload = await request.json()

    issue = payload.get("issue")
    if not isinstance(issue, dict):
        logger.warning("Jira webhook: missing 'issue' in payload")
        return Response(status_code=400, content="missing issue field")

    ticket_key = issue.get("key", "")
    if not ticket_key:
        logger.warning("Jira webhook: missing issue key")
        return Response(status_code=400, content="missing issue key")

    fields = issue.get("fields", {})
    status_name = fields.get("status", {}).get("name", "")

    transition = payload.get("transition", {})
    to_status = transition.get("to_status", status_name)

    logger.info(
        "Jira webhook received: ticket=%s status=%s to_status=%s",
        ticket_key, status_name, to_status,
    )

    # Only trigger on transition to In Progress
    if to_status.lower() not in ("in progress",):
        logger.info("Skipping: transition to '%s' (not 'In Progress')", to_status)
        return Response(status_code=200, content="skipped: not In Progress transition")

    await init_db()

    # Look up the finding for this ticket in the audit log
    all_entries = await get_entries()
    matching_entry = None
    for entry in all_entries:
        if entry.get("jira_ticket_key") == ticket_key:
            matching_entry = entry
            break

    if matching_entry is None:
        logger.warning("No audit entry found for Jira ticket %s", ticket_key)
        return Response(status_code=404, content="no finding for this ticket")

    finding_key = str(matching_entry["finding_key"])
    current_status = str(matching_entry.get("status", ""))

    # Only launch if the finding is in a launchable state
    if current_status not in ("pending", "skipped"):
        logger.info(
            "Skipping ticket %s: finding %s is already %s",
            ticket_key, finding_key, current_status,
        )
        return Response(status_code=200, content=f"skipped: finding is {current_status}")

    # Respect session cap
    in_progress_count = await _count_in_progress()
    if in_progress_count >= settings.MAX_SESSIONS_PER_RUN:
        logger.warning(
            "Session cap reached (%d/%d) — cannot launch for ticket %s",
            in_progress_count, settings.MAX_SESSIONS_PER_RUN, ticket_key,
        )
        return Response(
            status_code=429,
            content=f"session cap reached ({in_progress_count}/{settings.MAX_SESSIONS_PER_RUN})",
        )

    # Reconstruct the Finding from the audit entry
    finding = Finding(
        key=finding_key,
        rule=str(matching_entry.get("finding_rule", "")),
        severity=str(matching_entry.get("severity", "")),
        component=str(matching_entry.get("finding_file", "")),
        message=str(matching_entry.get("problem_summary", "")),
        type=str(matching_entry.get("finding_type", "VULNERABILITY")),
    )

    scan_task_id = str(matching_entry["scan_task_id"])

    # Mark as in_progress before dispatching to prevent duplicate launches
    await update_entry(finding_key, scan_task_id, {"status": "in_progress"})

    background_tasks.add_task(_process_jira_finding, finding, ticket_key, scan_task_id)
    logger.info("Dispatched Jira-triggered remediation for %s (ticket %s)", finding_key, ticket_key)

    return Response(status_code=200, content="accepted")
