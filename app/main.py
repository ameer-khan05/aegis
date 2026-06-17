"""Aegis — Event-driven security remediation orchestrator."""

from fastapi import FastAPI

from app.routers import dashboard, webhook

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
