"""SonarCloud API client — fetch security findings."""


async def fetch_vulnerabilities() -> list[dict[str, object]]:
    """Fetch open BLOCKER vulnerabilities from SonarCloud.

    TODO Stage 3: implement paginated fetch from /api/issues/search
    """
    return []
