"""End-to-end test: verify MAX_SESSIONS_PER_RUN caps Devin sessions.

Mocks SonarCloud (returns 12 findings), GitHub (issue creation), and
Devin (session launch + poll) so the full orchestration pipeline runs
locally without real API calls.
"""

import asyncio
import json
import os
import sys
from unittest.mock import patch

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Fake SonarCloud response: 12 findings with mixed severity + dates ──

FAKE_FINDINGS_VULN = [
    {"key": f"vuln-{i}", "rule": f"python:S{1000+i}", "severity": sev,
     "component": f"project:src/file_{i}.py", "line": 10 + i,
     "message": f"Vulnerability #{i}", "type": "VULNERABILITY",
     "creationDate": date}
    for i, (sev, date) in enumerate([
        ("BLOCKER",  "2026-06-15T10:00:00+0000"),
        ("BLOCKER",  "2026-06-14T10:00:00+0000"),
        ("BLOCKER",  "2026-06-13T10:00:00+0000"),
        ("CRITICAL", "2026-06-16T10:00:00+0000"),
        ("CRITICAL", "2026-06-10T10:00:00+0000"),
        ("CRITICAL", "2026-06-09T10:00:00+0000"),
        ("MAJOR",    "2026-06-17T10:00:00+0000"),
    ])
]

FAKE_FINDINGS_BUG = [
    {"key": f"bug-{i}", "rule": f"python:S{2000+i}", "severity": sev,
     "component": f"project:src/bug_{i}.py", "line": 20 + i,
     "message": f"Bug #{i}", "type": "BUG",
     "creationDate": date}
    for i, (sev, date) in enumerate([
        ("BLOCKER",  "2026-06-16T10:00:00+0000"),
        ("BLOCKER",  "2026-06-12T10:00:00+0000"),
        ("CRITICAL", "2026-06-15T10:00:00+0000"),
        ("MAJOR",    "2026-06-11T10:00:00+0000"),
        ("MINOR",    "2026-06-17T10:00:00+0000"),
    ])
]

# Total = 12 findings (7 VULN + 5 BUG)


def make_sonar_response(issue_type: str) -> dict:
    issues = FAKE_FINDINGS_VULN if issue_type == "VULNERABILITY" else FAKE_FINDINGS_BUG
    return {"issues": issues, "paging": {"total": len(issues)}}


# ── Track what the orchestrator does ──

sessions_launched: list[str] = []
issues_created: list[str] = []


class FakeHTTPResponse:
    def __init__(self, data: dict, status_code: int = 200):
        self._data = data
        self.status_code = status_code
        self.is_success = 200 <= status_code < 300
        self.text = json.dumps(data)

    def json(self):
        return self._data

    def raise_for_status(self):
        if not self.is_success:
            raise Exception(f"HTTP {self.status_code}")


class FakeAsyncClient:
    """Mock httpx.AsyncClient that routes requests to fake handlers."""

    def __init__(self, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def get(self, url: str, **kwargs) -> FakeHTTPResponse:
        params = kwargs.get("params", {})

        # SonarCloud issues search
        if "sonarcloud.io/api/issues/search" in url:
            issue_type = params.get("types", "VULNERABILITY")
            return FakeHTTPResponse(make_sonar_response(issue_type))

        # GitHub search (dedup check) — no existing issues
        if "api.github.com/search/issues" in url:
            return FakeHTTPResponse({"items": []})

        # Devin session poll — return immediate success
        if "/sessions/" in url and "api.devin.ai" in url:
            session_id = url.rsplit("/", 1)[-1]
            return FakeHTTPResponse({
                "status": "exit",
                "status_detail": "",
                "structured_output": {
                    "finding_key": session_id,
                    "fixed": True,
                    "tests_passed": True,
                    "pr_url": f"https://github.com/test/repo/pull/{len(sessions_launched)}",
                    "failure_reason": None,
                    "fix_summary": f"Replaced unsafe pattern with safe alternative for {session_id}",
                },
            })

        return FakeHTTPResponse({"error": "unhandled"}, 404)

    async def post(self, url: str, **kwargs) -> FakeHTTPResponse:
        body = kwargs.get("json", {})

        # GitHub issue creation
        if "api.github.com/repos" in url and "/issues" in url:
            title = body.get("title", "")
            issues_created.append(title)
            return FakeHTTPResponse({
                "html_url": f"https://github.com/test/repo/issues/{len(issues_created)}"
            }, 201)

        # Devin session launch
        if "api.devin.ai" in url and "/sessions" in url:
            sid = f"sess-{len(sessions_launched):03d}"
            sessions_launched.append(sid)
            return FakeHTTPResponse({
                "session_id": sid,
                "url": f"https://app.devin.ai/sessions/{sid}",
            })

        return FakeHTTPResponse({"error": "unhandled"}, 404)


async def run_test():
    """Simulate a webhook and verify the session cap."""
    # Clear tracking
    sessions_launched.clear()
    issues_created.clear()

    # Remove any stale DB
    import shutil
    if os.path.exists("data"):
        shutil.rmtree("data")

    # Patch httpx.AsyncClient globally
    with patch("httpx.AsyncClient", FakeAsyncClient):
        from app.services.orchestrator import run_remediation
        from app.db import get_summary, get_entries

        await run_remediation("test-scan-001")

        summary = await get_summary()
        entries = await get_entries()

    return summary, entries


def main():
    print("=" * 60)
    print("  Aegis E2E Test: MAX_SESSIONS_PER_RUN cap verification")
    print("=" * 60)
    print()

    summary, entries = asyncio.run(run_test())

    total_findings = 12  # 7 VULN + 5 BUG
    cap = int(os.environ.get("MAX_SESSIONS_PER_RUN", "5"))

    print(f"Total findings from SonarCloud:  {total_findings}")
    print(f"MAX_SESSIONS_PER_RUN:            {cap}")
    print(f"Sessions actually launched:       {len(sessions_launched)}")
    print(f"Issues created (GitHub):          {len(issues_created)}")
    print()

    print("Dashboard summary (from DB):")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    print()

    # Count statuses
    statuses = {}
    for e in entries:
        s = e.get("status", "unknown")
        statuses[s] = statuses.get(s, 0) + 1
    print(f"Entry statuses: {statuses}")
    print()

    # ── Assertions ──
    errors = []

    if len(sessions_launched) != cap:
        errors.append(f"FAIL: Expected {cap} sessions launched, got {len(sessions_launched)}")

    if summary.get("findings_detected") != total_findings:
        errors.append(f"FAIL: Expected findings_detected={total_findings}, got {summary.get('findings_detected')}")

    if summary.get("sessions_triggered") != cap:
        errors.append(f"FAIL: Expected sessions_triggered={cap}, got {summary.get('sessions_triggered')}")

    expected_skipped = total_findings - cap
    if summary.get("skipped") != expected_skipped:
        errors.append(f"FAIL: Expected skipped={expected_skipped}, got {summary.get('skipped')}")

    if summary.get("resolved") != cap:
        errors.append(f"FAIL: Expected resolved={cap} (all mocked as fixed), got {summary.get('resolved')}")

    # Verify priority ordering: first 5 sessions should be BLOCKERs (there are 5 total)
    blocker_entries = [e for e in entries if e.get("severity") == "BLOCKER" and e.get("status") != "skipped"]
    if len(blocker_entries) < 5:
        errors.append(f"FAIL: Expected all 5 BLOCKERs to be remediated, only {len(blocker_entries)} were")

    skipped_entries = [e for e in entries if e.get("status") == "skipped"]
    if len(skipped_entries) != expected_skipped:
        errors.append(f"FAIL: Expected {expected_skipped} skipped entries, got {len(skipped_entries)}")

    # All skipped should have the cap reason
    for se in skipped_entries:
        reason = se.get("failure_reason", "")
        if "MAX_SESSIONS_PER_RUN" not in str(reason):
            errors.append(f"FAIL: Skipped entry {se.get('finding_key')} missing cap reason: {reason}")
            break

    # Verify problem_summary is populated from finding.message
    entries_with_problem = [e for e in entries if e.get("problem_summary")]
    if len(entries_with_problem) != total_findings:
        errors.append(f"FAIL: Expected {total_findings} entries with problem_summary, got {len(entries_with_problem)}")

    # Verify fix_summary is populated for fixed entries
    fixed_with_fix = [e for e in entries if e.get("status") == "fixed" and e.get("fix_summary")]
    if len(fixed_with_fix) != cap:
        errors.append(f"FAIL: Expected {cap} fixed entries with fix_summary, got {len(fixed_with_fix)}")

    if errors:
        print("RESULTS:")
        for e in errors:
            print(f"  {e}")
        sys.exit(1)
    else:
        print("ALL CHECKS PASSED")
        print()
        print(f"  12 findings detected, {cap} remediated this run, {expected_skipped} skipped (cap={cap})")
        print(f"  All {cap} sessions launched for the highest-severity findings")
        print("  Dashboard summary correctly shows the cap is intentional")
        sys.exit(0)


if __name__ == "__main__":
    main()
