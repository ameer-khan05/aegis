"""Orchestrator — coordinates the full remediation pipeline."""


async def run_remediation(scan_task_id: str) -> None:
    """Full remediation loop triggered by a webhook.

    Steps:
      1. Fetch findings from SonarCloud
      2. For each finding: create GitHub issue, launch Devin session
      3. Poll sessions to terminal state
      4. Record results in audit log

    TODO Stage 2-6: wire up all services.
    """
    pass
