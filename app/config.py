"""Aegis configuration via Pydantic Settings — loads from .env file."""

import logging

from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

SEVERITY_LEVELS = ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]


class Settings(BaseSettings):
    # SonarCloud
    SONAR_TOKEN: str
    SONAR_WEBHOOK_SECRET: str
    SONAR_PROJECT_KEY: str = "ameer-khan05_superset-aegis-demo"

    # GitHub
    GITHUB_TOKEN: str
    GITHUB_REPO: str = "ameer-khan05/superset-aegis-demo"

    # Devin API
    DEVIN_API_KEY: str
    DEVIN_ORG_ID: str
    DEVIN_USER_ID: str

    # Jira (optional — leave blank to disable Jira integration)
    JIRA_BASE_URL: str = ""
    JIRA_EMAIL: str = ""
    JIRA_API_TOKEN: str = ""
    JIRA_PROJECT_KEY: str = "KAN"
    JIRA_WEBHOOK_SECRET: str = ""

    # Aegis behaviour
    AEGIS_MIN_SEVERITY: str = "BLOCKER"
    AEGIS_ISSUE_TYPES: str = "VULNERABILITY,BUG"
    AEGIS_MAX_ACU: int = 15
    AEGIS_POLL_INTERVAL: int = 30  # seconds
    AEGIS_SESSION_TIMEOUT: int = 2700  # 45 minutes — sessions typically take 10-15 min
    MAX_FINDINGS_PER_RUN: int = 10  # cap on total findings fetched per run
    MAX_SESSIONS_PER_RUN: int = 5  # cap on Devin sessions launched per webhook run

    @property
    def jira_enabled(self) -> bool:
        """Return True if all Jira settings are configured."""
        return bool(self.JIRA_BASE_URL and self.JIRA_EMAIL and self.JIRA_API_TOKEN)

    @property
    def severity_filter(self) -> str:
        """Expand AEGIS_MIN_SEVERITY into a comma-separated list of all
        severities at or above the configured minimum."""
        threshold = self.AEGIS_MIN_SEVERITY.strip().upper()
        if threshold not in SEVERITY_LEVELS:
            return threshold
        idx = SEVERITY_LEVELS.index(threshold)
        return ",".join(SEVERITY_LEVELS[: idx + 1])

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()

logger.info(
    "Aegis config loaded: MAX_FINDINGS_PER_RUN=%d, MAX_SESSIONS_PER_RUN=%d, "
    "AEGIS_MIN_SEVERITY=%s (filter=%s), AEGIS_ISSUE_TYPES=%s",
    settings.MAX_FINDINGS_PER_RUN,
    settings.MAX_SESSIONS_PER_RUN,
    settings.AEGIS_MIN_SEVERITY,
    settings.severity_filter,
    settings.AEGIS_ISSUE_TYPES,
)
