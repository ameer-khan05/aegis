"""Webhook receiver for SonarCloud scan-complete events."""

from fastapi import APIRouter, BackgroundTasks, Request, Response

router = APIRouter(tags=["webhook"])


@router.post("/webhook/sonar")
async def sonar_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
) -> Response:
    """Receive SonarCloud webhook, validate HMAC, dispatch orchestration."""
    # TODO Stage 2: HMAC validation + orchestration dispatch
    return Response(status_code=200, content="accepted")
