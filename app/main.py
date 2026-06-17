"""Aegis — Event-driven security remediation orchestrator."""

import logging

from fastapi import FastAPI

from app.routers import dashboard, webhook

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(name)s: %(message)s")

app = FastAPI(
    title="Aegis",
    description="Event-driven security remediation orchestrator powered by Devin.",
    version="0.1.0",
)

app.include_router(webhook.router)
app.include_router(dashboard.router)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
