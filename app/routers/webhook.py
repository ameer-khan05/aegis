"""Webhook receiver for SonarCloud scan-complete events."""

import hashlib
import hmac
import logging

from fastapi import APIRouter, BackgroundTasks, Request, Response

from app.config import settings
from app.db import has_scan_run, init_db
from app.services.orchestrator import run_remediation

logger = logging.getLogger(__name__)

router = APIRouter(tags=["webhook"])


def _verify_signature(payload: bytes, signature: str) -> bool:
    """Validate HMAC-SHA256 signature from SonarCloud."""
    expected = hmac.new(
        settings.SONAR_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


@router.post("/webhook/sonar")
async def sonar_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
) -> Response:
    """Receive SonarCloud webhook, validate HMAC, dispatch orchestration."""
    body = await request.body()

    # Validate HMAC-SHA256 signature
    signature = request.headers.get("X-Sonar-Webhook-HMAC-SHA256", "")
    if not signature or not _verify_signature(body, signature):
        logger.warning("Webhook rejected: invalid or missing HMAC signature")
        return Response(status_code=401, content="invalid signature")

    # Parse payload
    payload = await request.json()
    task_id = payload.get("taskId", "unknown")
    status = payload.get("status", "")
    project_key = payload.get("project", {}).get("key", "")
    quality_gate = payload.get("qualityGate", {}).get("status", "")

    logger.info(
        "Webhook received: project=%s task=%s status=%s qg=%s",
        project_key,
        task_id,
        status,
        quality_gate,
    )

    # Idempotency check: reject duplicate task IDs early
    await init_db()
    if await has_scan_run(task_id):
        logger.warning("Webhook rejected: scan %s already processed", task_id)
        return Response(status_code=200, content="skipped: already processed")

    # Dispatch orchestration to background task
    background_tasks.add_task(run_remediation, task_id)
    logger.info(
        "Dispatched remediation for task %s (findings_cap=%d, session_cap=%d)",
        task_id, settings.MAX_FINDINGS_PER_RUN, settings.MAX_SESSIONS_PER_RUN,
    )

    return Response(status_code=200, content="accepted")
