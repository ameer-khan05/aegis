"""Devin API client — launch and poll remediation sessions."""


async def launch_session(finding: dict[str, object]) -> dict[str, object] | None:
    """Launch a Devin session to fix a security finding.

    TODO Stage 5: POST to /v3/organizations/{org_id}/sessions
    Returns session metadata (id, url) or None on failure.
    """
    return None


async def poll_session(session_id: str) -> dict[str, object] | None:
    """Poll a Devin session until terminal state.

    TODO Stage 6: GET /v3/organizations/{org_id}/sessions/{session_id}
    Returns structured output or failure info.
    """
    return None
