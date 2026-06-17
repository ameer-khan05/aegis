"""Aegis configuration via Pydantic Settings — loads from .env file."""

from pydantic_settings import BaseSettings


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

    # Aegis behaviour
    AEGIS_MIN_SEVERITY: str = "BLOCKER"
    AEGIS_MAX_ACU: int = 15
    AEGIS_POLL_INTERVAL: int = 30  # seconds
    AEGIS_SESSION_TIMEOUT: int = 1200  # 20 minutes

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
