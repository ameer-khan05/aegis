"""SonarCloud API client — fetch security vulnerabilities and bugs."""

import logging

import httpx

from app.config import settings
from app.models import Finding

logger = logging.getLogger(__name__)

SONAR_BASE = "https://sonarcloud.io"


async def fetch_vulnerabilities(max_findings: int | None = None) -> list[Finding]:
    """Fetch open findings from SonarCloud, filtered by configured severity and types.

    All configured issue types (VULNERABILITY, BUG, etc.) are requested in a
    single API call so that findings compete equally by severity regardless of
    type.  The orchestrator's ``prioritize_findings`` then sorts them by
    severity → recency before applying the session cap.

    Args:
        max_findings: Hard cap on total findings returned. Defaults to
                      settings.MAX_FINDINGS_PER_RUN.
    """
    cap = max_findings if max_findings is not None else settings.MAX_FINDINGS_PER_RUN
    findings: list[Finding] = []
    issue_types = settings.AEGIS_ISSUE_TYPES  # already comma-separated
    severity_filter = settings.severity_filter

    page = 1
    async with httpx.AsyncClient(timeout=30.0) as client:
        while True:
            resp = await client.get(
                f"{SONAR_BASE}/api/issues/search",
                params={
                    "componentKeys": settings.SONAR_PROJECT_KEY,
                    "types": issue_types,
                    "severities": severity_filter,
                    "statuses": "OPEN,CONFIRMED,REOPENED",
                    "ps": min(100, cap - len(findings)),
                    "p": page,
                },
                headers={"Authorization": f"Bearer {settings.SONAR_TOKEN}"},
            )
            resp.raise_for_status()
            data = resp.json()

            for issue in data.get("issues", []):
                if len(findings) >= cap:
                    break
                findings.append(
                    Finding(
                        key=issue["key"],
                        rule=issue["rule"],
                        severity=issue["severity"],
                        component=issue["component"],
                        line=issue.get("line"),
                        message=issue["message"],
                        type=issue.get("type", "VULNERABILITY"),
                        creation_date=issue.get("creationDate", ""),
                    )
                )

            if len(findings) >= cap:
                break
            total = data.get("paging", {}).get("total", 0)
            if page * 100 >= total:
                break
            page += 1

    type_counts = {}
    for f in findings:
        type_counts[f.type] = type_counts.get(f.type, 0) + 1
    logger.info(
        "Fetched %d findings (cap=%d, severity>=%s, types=%s): %s",
        len(findings), cap, settings.AEGIS_MIN_SEVERITY, issue_types, type_counts,
    )
    return findings
