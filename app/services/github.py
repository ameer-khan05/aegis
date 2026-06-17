"""GitHub API client — create issues for findings (vulnerabilities and bugs)."""

import logging

import httpx

from app.config import settings
from app.models import Finding

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"


def _issue_title(finding: Finding) -> str:
    """Deterministic title for dedup."""
    short_file = finding.component.split(":")[-1] if ":" in finding.component else finding.component
    line_part = f":{finding.line}" if finding.line else ""
    return f"[Aegis] {finding.rule}: {finding.message[:80]} in {short_file}{line_part}"


async def create_issue(finding: Finding) -> str | None:
    """Create a GitHub issue for a finding, skipping if one already exists.

    Returns the issue URL, or None if a duplicate was found.
    """
    owner, repo = settings.GITHUB_REPO.split("/")
    title = _issue_title(finding)

    async with httpx.AsyncClient(timeout=30.0) as client:
        headers = {
            "Authorization": f"Bearer {settings.GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
        }

        # Dedup: search for existing open issue with same title prefix
        search_q = f'repo:{settings.GITHUB_REPO} is:issue is:open "[Aegis] {finding.rule}" in:title'
        search_resp = await client.get(
            f"{GITHUB_API}/search/issues",
            params={"q": search_q, "per_page": 5},
            headers=headers,
        )
        if search_resp.is_success:
            items = search_resp.json().get("items", [])
            for item in items:
                if finding.rule in item.get("title", ""):
                    existing_file = finding.component.split(":")[-1] if ":" in finding.component else finding.component
                    if existing_file in item.get("title", ""):
                        logger.info("Issue already exists: %s", item["html_url"])
                        return item["html_url"]

        # Create new issue
        type_label = "security" if finding.type == "VULNERABILITY" else "bug"
        body = (
            f"**Type:** {finding.type}\n"
            f"**Severity:** {finding.severity}\n"
            f"**Rule:** {finding.rule}\n"
            f"**File:** `{finding.component}`\n"
            f"**Line:** {finding.line or 'N/A'}\n\n"
            f"{finding.message}\n\n"
            f"---\n_Auto-created by Aegis orchestrator_"
        )

        resp = await client.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/issues",
            headers=headers,
            json={
                "title": title,
                "body": body,
                "labels": ["aegis", type_label, finding.severity.lower()],
            },
        )

        if resp.is_success:
            url = resp.json()["html_url"]
            logger.info("Created issue: %s", url)
            return url

        logger.error("Failed to create issue: %s %s", resp.status_code, resp.text)
        return None
