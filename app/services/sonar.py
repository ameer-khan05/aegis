"""SonarCloud API client — fetch security findings."""

import logging

import httpx

from app.config import settings
from app.models import Finding

logger = logging.getLogger(__name__)

SONAR_BASE = "https://sonarcloud.io"


async def fetch_vulnerabilities() -> list[Finding]:
    """Fetch open vulnerabilities from SonarCloud, filtered by configured severity."""
    findings: list[Finding] = []
    page = 1

    async with httpx.AsyncClient(timeout=30.0) as client:
        while True:
            resp = await client.get(
                f"{SONAR_BASE}/api/issues/search",
                params={
                    "componentKeys": settings.SONAR_PROJECT_KEY,
                    "types": "VULNERABILITY",
                    "severities": settings.AEGIS_MIN_SEVERITY,
                    "statuses": "OPEN,CONFIRMED,REOPENED",
                    "ps": 100,
                    "p": page,
                },
                headers={"Authorization": f"Bearer {settings.SONAR_TOKEN}"},
            )
            resp.raise_for_status()
            data = resp.json()

            for issue in data.get("issues", []):
                findings.append(
                    Finding(
                        key=issue["key"],
                        rule=issue["rule"],
                        severity=issue["severity"],
                        component=issue["component"],
                        line=issue.get("line"),
                        message=issue["message"],
                        type=issue.get("type", "VULNERABILITY"),
                    )
                )

            total = data.get("paging", {}).get("total", 0)
            if page * 100 >= total:
                break
            page += 1

    logger.info(
        "Fetched %d %s vulnerabilities from %s",
        len(findings),
        settings.AEGIS_MIN_SEVERITY,
        settings.SONAR_PROJECT_KEY,
    )
    return findings
