"""Devin API client — launch and poll remediation sessions."""

import asyncio
import logging
import time

import httpx

from app.config import settings
from app.models import Finding, SessionResult

logger = logging.getLogger(__name__)

DEVIN_API = "https://api.devin.ai"

STRUCTURED_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "finding_key": {"type": "string"},
        "fixed": {"type": "boolean"},
        "tests_passed": {"type": "boolean"},
        "pr_url": {"type": ["string", "null"]},
        "failure_reason": {"type": ["string", "null"]},
    },
    "required": ["finding_key", "fixed", "tests_passed", "pr_url", "failure_reason"],
    "additionalProperties": False,
}


async def launch_session(finding: Finding) -> dict[str, str] | None:
    """Launch a Devin session to fix a security finding.

    Returns {"session_id": ..., "url": ...} or None on failure.
    """
    prompt = (
        f"Fix the security vulnerability in {finding.component} at line {finding.line}.\n"
        f"Rule: {finding.rule}\n"
        f"Description: {finding.message}\n\n"
        f"Steps:\n"
        f"1. Read the flagged code\n"
        f"2. Apply the fix following the rule guidance\n"
        f"3. Run the test suite (pytest tests/)\n"
        f"4. If tests pass, open a PR targeting the main branch\n"
        f"5. Report structured output with finding_key='{finding.key}'\n\n"
        f"Do NOT auto-merge. Stop after opening the PR."
    )

    payload = {
        "prompt": prompt,
        "repos": [settings.GITHUB_REPO],
        "tags": ["aegis", "security-fix", finding.rule],
        "max_acu_limit": settings.AEGIS_MAX_ACU,
        "title": f"Aegis: Fix {finding.rule} in {finding.component}",
        "create_as_user_id": settings.DEVIN_USER_ID,
        "structured_output_required": True,
        "structured_output_schema": STRUCTURED_OUTPUT_SCHEMA,
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"{DEVIN_API}/v3/organizations/{settings.DEVIN_ORG_ID}/sessions",
            headers={
                "Authorization": f"Bearer {settings.DEVIN_API_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
        )

        if resp.is_success:
            data = resp.json()
            session_id = data.get("session_id", data.get("id", ""))
            url = data.get("url", f"https://app.devin.ai/sessions/{session_id}")
            logger.info("Launched session %s for %s", session_id, finding.key)
            return {"session_id": session_id, "url": url}

        logger.error("Failed to launch session: %s %s", resp.status_code, resp.text)
        return None


async def poll_session(session_id: str) -> SessionResult | None:
    """Poll a Devin session until it reaches a terminal state.

    Terminal states: status in {exit, error} or
    status == suspended with failure-indicating status_detail.

    Returns parsed SessionResult or None on timeout.
    """
    start = time.monotonic()
    terminal_details = {"usage_limit_exceeded", "out_of_credits", "error", "inactivity"}

    async with httpx.AsyncClient(timeout=30.0) as client:
        while (time.monotonic() - start) < settings.AEGIS_SESSION_TIMEOUT:
            resp = await client.get(
                f"{DEVIN_API}/v3/organizations/{settings.DEVIN_ORG_ID}/sessions/{session_id}",
                headers={"Authorization": f"Bearer {settings.DEVIN_API_KEY}"},
            )

            if not resp.is_success:
                logger.warning("Poll failed for %s: %s", session_id, resp.status_code)
                await asyncio.sleep(settings.AEGIS_POLL_INTERVAL)
                continue

            data = resp.json()
            status = data.get("status", "")
            detail = data.get("status_detail", "")

            if status == "exit":
                logger.info("Session %s completed successfully", session_id)
                return _extract_result(data, session_id)

            if status == "error":
                logger.warning("Session %s errored: %s", session_id, detail)
                return _extract_result(data, session_id)

            if status == "suspended" and detail in terminal_details:
                logger.warning("Session %s suspended: %s", session_id, detail)
                return _extract_result(data, session_id)

            logger.debug("Session %s: status=%s detail=%s", session_id, status, detail)
            await asyncio.sleep(settings.AEGIS_POLL_INTERVAL)

    logger.warning("Session %s timed out after %ds", session_id, settings.AEGIS_SESSION_TIMEOUT)
    return None


def _extract_result(data: dict[str, object], session_id: str) -> SessionResult:
    """Parse structured_output from session response, with fallback."""
    structured = data.get("structured_output")
    if isinstance(structured, dict):
        return SessionResult(
            finding_key=str(structured.get("finding_key", "")),
            fixed=bool(structured.get("fixed", False)),
            tests_passed=bool(structured.get("tests_passed", False)),
            pr_url=structured.get("pr_url"),  # type: ignore[arg-type]
            failure_reason=structured.get("failure_reason"),  # type: ignore[arg-type]
        )

    status = str(data.get("status", "error"))
    return SessionResult(
        finding_key="",
        fixed=False,
        tests_passed=False,
        pr_url=None,
        failure_reason=f"Session {session_id} ended with status={status}, no structured output",
    )
