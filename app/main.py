"""Aegis — Event-driven security remediation orchestrator."""

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI

from app.db import init_db
from app.routers import dashboard, webhook

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    """Initialize the database on startup."""
    await init_db()
    yield


app = FastAPI(
    title="Aegis",
    description="Event-driven security remediation orchestrator powered by Devin.",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(webhook.router)
app.include_router(dashboard.router)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
