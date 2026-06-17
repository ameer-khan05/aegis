"""GitHub API client — create issues for findings."""


async def create_issue(finding: dict[str, object]) -> str | None:
    """Create a GitHub issue for a security finding.

    TODO Stage 4: POST to /repos/{owner}/{repo}/issues with dedup check.
    Returns the issue URL or None if already exists.
    """
    return None
