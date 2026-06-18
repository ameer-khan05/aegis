"""Jira Cloud API client — create tickets and manage transitions for findings."""

import base64
import logging

import httpx

from app.config import settings
from app.models import Finding

logger = logging.getLogger(__name__)


def _auth_header() -> str:
    """Build HTTP Basic auth header from email + API token."""
    raw = f"{settings.JIRA_EMAIL}:{settings.JIRA_API_TOKEN}"
    encoded = base64.b64encode(raw.encode()).decode()
    return f"Basic {encoded}"


def _ticket_summary(finding: Finding) -> str:
    """Build a concise ticket summary from the finding."""
    short_file = finding.component.split(":")[-1] if ":" in finding.component else finding.component
    line_part = f":{finding.line}" if finding.line else ""
    return f"[Aegis] {finding.rule}: {finding.message[:100]} ({short_file}{line_part})"


def _ticket_description(finding: Finding) -> dict[str, object]:
    """Build Atlassian Document Format (ADF) description."""
    return {
        "version": 1,
        "type": "doc",
        "content": [
            {
                "type": "table",
                "attrs": {"isNumberColumnEnabled": False, "layout": "default"},
                "content": [
                    _adf_table_row("Type", finding.type),
                    _adf_table_row("Severity", finding.severity),
                    _adf_table_row("Rule", finding.rule),
                    _adf_table_row("File", finding.component),
                    _adf_table_row("Line", str(finding.line or "N/A")),
                    _adf_table_row("Finding Key", finding.key),
                ],
            },
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": finding.message}],
            },
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": "Auto-created by Aegis orchestrator",
                        "marks": [{"type": "em"}],
                    },
                ],
            },
        ],
    }


def _adf_table_row(label: str, value: str) -> dict[str, object]:
    """Build a single ADF table row with a header cell and a data cell."""
    return {
        "type": "tableRow",
        "content": [
            {
                "type": "tableHeader",
                "content": [
                    {"type": "paragraph", "content": [{"type": "text", "text": label}]},
                ],
            },
            {
                "type": "tableCell",
                "content": [
                    {"type": "paragraph", "content": [{"type": "text", "text": value}]},
                ],
            },
        ],
    }


async def create_ticket(finding: Finding) -> dict[str, str] | None:
    """Create a Jira ticket for a finding in To Do status.

    Returns {"key": "KAN-123", "url": "https://..."} or None on failure.
    """
    if not settings.jira_enabled:
        return None

    base = settings.JIRA_BASE_URL.rstrip("/")
    payload = {
        "fields": {
            "project": {"key": settings.JIRA_PROJECT_KEY},
            "summary": _ticket_summary(finding),
            "description": _ticket_description(finding),
            "issuetype": {"name": "Task"},
            "labels": ["aegis", finding.severity.lower(), finding.type.lower()],
        },
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{base}/rest/api/3/issue",
            headers={
                "Authorization": _auth_header(),
                "Content-Type": "application/json",
            },
            json=payload,
        )

        if resp.is_success:
            data = resp.json()
            key = data["key"]
            url = f"{base}/browse/{key}"
            logger.info("Created Jira ticket %s for finding %s", key, finding.key)
            return {"key": key, "url": url}

        logger.error("Failed to create Jira ticket: %s %s", resp.status_code, resp.text)
        return None


async def transition_ticket(ticket_key: str, target_name: str) -> bool:
    """Transition a Jira ticket to the named status (e.g. 'Done', 'In Progress').

    Looks up available transitions and picks the one matching target_name.
    Returns True if successful.
    """
    if not settings.jira_enabled:
        return False

    base = settings.JIRA_BASE_URL.rstrip("/")
    headers = {
        "Authorization": _auth_header(),
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        # Get available transitions
        resp = await client.get(
            f"{base}/rest/api/3/issue/{ticket_key}/transitions",
            headers=headers,
        )
        if not resp.is_success:
            logger.error("Failed to get transitions for %s: %s", ticket_key, resp.status_code)
            return False

        transitions = resp.json().get("transitions", [])
        transition_id = None
        for t in transitions:
            if t["name"].lower() == target_name.lower():
                transition_id = t["id"]
                break

        if transition_id is None:
            available = [t["name"] for t in transitions]
            logger.warning(
                "No '%s' transition found for %s. Available: %s",
                target_name, ticket_key, available,
            )
            return False

        # Execute the transition
        resp = await client.post(
            f"{base}/rest/api/3/issue/{ticket_key}/transitions",
            headers=headers,
            json={"transition": {"id": transition_id}},
        )
        if resp.is_success:
            logger.info("Transitioned %s to '%s'", ticket_key, target_name)
            return True

        logger.error("Failed to transition %s: %s %s", ticket_key, resp.status_code, resp.text)
        return False


async def add_comment(ticket_key: str, body: str) -> bool:
    """Post a plain-text comment to a Jira ticket.

    Returns True if successful. Silently returns False if Jira is disabled
    or the API call fails (non-critical path).
    """
    if not settings.jira_enabled:
        return False

    base = settings.JIRA_BASE_URL.rstrip("/")
    payload = {
        "body": {
            "version": 1,
            "type": "doc",
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": body}],
                },
            ],
        },
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{base}/rest/api/3/issue/{ticket_key}/comment",
            headers={
                "Authorization": _auth_header(),
                "Content-Type": "application/json",
            },
            json=payload,
        )
        if resp.is_success:
            logger.info("Added comment to %s", ticket_key)
            return True

        logger.error("Failed to add comment to %s: %s %s", ticket_key, resp.status_code, resp.text)
        return False


async def get_ticket_finding_key(ticket_key: str) -> str | None:
    """Look up the finding_key stored in a Jira ticket's description.

    Parses the ADF description table for the 'Finding Key' row.
    """
    if not settings.jira_enabled:
        return None

    base = settings.JIRA_BASE_URL.rstrip("/")
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(
            f"{base}/rest/api/3/issue/{ticket_key}",
            headers={"Authorization": _auth_header()},
            params={"fields": "description"},
        )
        if not resp.is_success:
            logger.error("Failed to fetch ticket %s: %s", ticket_key, resp.status_code)
            return None

        desc = resp.json().get("fields", {}).get("description")
        if not isinstance(desc, dict):
            return None

        # Walk ADF to find the Finding Key table row
        for block in desc.get("content", []):
            if block.get("type") != "table":
                continue
            for row in block.get("content", []):
                cells = row.get("content", [])
                if len(cells) < 2:
                    continue
                header_text = _extract_adf_text(cells[0])
                if header_text == "Finding Key":
                    return _extract_adf_text(cells[1])

    return None


def _extract_adf_text(cell: dict[str, object]) -> str:
    """Extract plain text from an ADF table cell."""
    text_parts: list[str] = []
    content = cell.get("content", [])
    if not isinstance(content, list):
        return ""
    for para in content:
        if not isinstance(para, dict):
            continue
        for node in para.get("content", []):
            if isinstance(node, dict) and node.get("type") == "text":
                text_parts.append(str(node.get("text", "")))
    return "".join(text_parts)
