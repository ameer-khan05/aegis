"""End-to-end test: verify session cap, findings cap, dedup, and idempotency.

Mocks SonarCloud (returns 12 findings), GitHub (issue creation), and
Devin (session launch + poll) so the full orchestration pipeline runs
locally without real API calls.
"""

import asyncio
import json
import os
import shutil
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

# Total = 12 findings (7 VULN + 5 BUG), all returned in one combined call.
# MAX_FINDINGS_PER_RUN=10 means only 10 are fetched.
ALL_FINDINGS = FAKE_FINDINGS_VULN + FAKE_FINDINGS_BUG


def make_sonar_response(page_size: int = 100) -> dict:
    """Return a combined response with all issue types mixed together."""
    return {"issues": ALL_FINDINGS[:page_size], "paging": {"total": len(ALL_FINDINGS)}}


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

        # SonarCloud issues search — single combined call for all types
        if "sonarcloud.io/api/issues/search" in url:
            page_size = int(params.get("ps", 100))
            return FakeHTTPResponse(make_sonar_response(page_size))

        # GitHub search (dedup check) — no existing issues
        if "api.github.com/search/issues" in url:
            return FakeHTTPResponse({"items": []})

        # Devin session poll — return immediate success with ACU cost
        if "/sessions/" in url and "api.devin.ai" in url:
            session_id = url.rsplit("/", 1)[-1]
            return FakeHTTPResponse({
                "status": "exit",
                "status_detail": "",
                "acus_consumed": 3.5,
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
    """Simulate a webhook and verify caps + dedup + idempotency."""
    # Clear tracking
    sessions_launched.clear()
    issues_created.clear()

    # Remove any stale DB
    if os.path.exists("data"):
        shutil.rmtree("data")

    # Patch httpx.AsyncClient globally
    with patch("httpx.AsyncClient", FakeAsyncClient):
        from app.services.orchestrator import run_remediation
        from app.db import get_summary, get_entries

        # First run — should process findings normally
        await run_remediation("test-scan-001")

        summary1 = await get_summary()
        entries1 = await get_entries()
        sessions_after_run1 = len(sessions_launched)

        # Second run with SAME task ID — should be rejected (idempotency)
        await run_remediation("test-scan-001")

        summary2 = await get_summary()
        sessions_after_run2 = len(sessions_launched)

        # Third run with NEW task ID — findings should be deduped
        await run_remediation("test-scan-002")

        summary3 = await get_summary()
        sessions_after_run3 = len(sessions_launched)

    return {
        "summary1": summary1, "entries1": entries1,
        "sessions_run1": sessions_after_run1,
        "summary2": summary2, "sessions_run2": sessions_after_run2,
        "summary3": summary3, "sessions_run3": sessions_after_run3,
    }


def main():
    print("=" * 60)
    print("  Aegis E2E Test: Cap, Dedup, and Idempotency Verification")
    print("=" * 60)
    print()

    results = asyncio.run(run_test())

    session_cap = int(os.environ.get("MAX_SESSIONS_PER_RUN", "5"))
    findings_cap = int(os.environ.get("MAX_FINDINGS_PER_RUN", "10"))

    summary1 = results["summary1"]
    entries1 = results["entries1"]

    total_fetched = summary1.get("findings_detected", 0)

    print(f"MAX_FINDINGS_PER_RUN:  {findings_cap}")
    print(f"MAX_SESSIONS_PER_RUN:  {session_cap}")
    print(f"Findings fetched (run 1): {total_fetched}")
    print(f"Sessions launched (run 1): {results['sessions_run1']}")
    print(f"Sessions launched (run 2, same taskId): {results['sessions_run2'] - results['sessions_run1']}")
    print(f"Sessions launched (run 3, new taskId, dedup): {results['sessions_run3'] - results['sessions_run2']}")
    print()

    print("Dashboard summary after run 1:")
    for k, v in summary1.items():
        print(f"  {k}: {v}")
    print()

    # Count statuses
    statuses: dict[str, int] = {}
    for e in entries1:
        s = str(e.get("status", "unknown"))
        statuses[s] = statuses.get(s, 0) + 1
    print(f"Entry statuses (run 1): {statuses}")

    # Count types in fixed entries
    fixed_entries = [e for e in entries1 if e.get("status") == "fixed"]
    fixed_types: dict[str, int] = {}
    for e in fixed_entries:
        t = str(e.get("finding_type", "unknown"))
        fixed_types[t] = fixed_types.get(t, 0) + 1
    print(f"Fixed entry types (run 1): {fixed_types}")
    print()

    # ── Assertions ──
    errors: list[str] = []

    # 1. Findings cap: at most MAX_FINDINGS_PER_RUN findings fetched
    if total_fetched > findings_cap:
        errors.append(
            f"FAIL: Findings cap violated — fetched {total_fetched}, cap is {findings_cap}"
        )

    # 2. Session cap: at most MAX_SESSIONS_PER_RUN sessions launched
    if results["sessions_run1"] != session_cap:
        errors.append(
            f"FAIL: Expected {session_cap} sessions launched, got {results['sessions_run1']}"
        )

    # 3. Skipped entries = fetched - session_cap
    expected_skipped = total_fetched - session_cap
    if summary1.get("skipped") != expected_skipped:
        errors.append(
            f"FAIL: Expected skipped={expected_skipped}, got {summary1.get('skipped')}"
        )

    # 4. All sessions should resolve as fixed
    if summary1.get("resolved") != session_cap:
        errors.append(
            f"FAIL: Expected resolved={session_cap}, got {summary1.get('resolved')}"
        )

    # 5. Priority ordering: all BLOCKERs should be remediated first
    blocker_entries = [
        e for e in entries1
        if e.get("severity") == "BLOCKER" and e.get("status") != "skipped"
    ]
    blocker_count = sum(1 for e in entries1 if e.get("severity") == "BLOCKER")
    if len(blocker_entries) < min(session_cap, blocker_count):
        errors.append(
            f"FAIL: Expected all BLOCKERs to be remediated, only {len(blocker_entries)} were"
        )

    # 6. Mixed types: remediated entries should include BOTH vulnerabilities and bugs
    #    (5 BLOCKERs = 3 VULN + 2 BUG, so the top 5 must include both types)
    fixed_vuln = sum(1 for e in fixed_entries if e.get("finding_type") == "VULNERABILITY")
    fixed_bug = sum(1 for e in fixed_entries if e.get("finding_type") == "BUG")
    if fixed_vuln == 0 or fixed_bug == 0:
        errors.append(
            f"FAIL: Fixed entries should include both types — got "
            f"{fixed_vuln} VULNERABILITY, {fixed_bug} BUG"
        )

    # 7. Skipped entries should have the cap reason
    skipped_entries = [e for e in entries1 if e.get("status") == "skipped"]
    for se in skipped_entries:
        reason = se.get("failure_reason", "")
        if "MAX_SESSIONS_PER_RUN" not in str(reason):
            errors.append(
                f"FAIL: Skipped entry {se.get('finding_key')} missing cap reason: {reason}"
            )
            break

    # 8. problem_summary populated for all entries
    entries_with_problem = [e for e in entries1 if e.get("problem_summary")]
    if len(entries_with_problem) != total_fetched:
        errors.append(
            f"FAIL: Expected {total_fetched} entries with problem_summary, "
            f"got {len(entries_with_problem)}"
        )

    # 9. fix_summary populated for fixed entries
    fixed_with_fix = [
        e for e in entries1
        if e.get("status") == "fixed" and e.get("fix_summary")
    ]
    if len(fixed_with_fix) != session_cap:
        errors.append(
            f"FAIL: Expected {session_cap} fixed entries with fix_summary, "
            f"got {len(fixed_with_fix)}"
        )

    # 10. IDEMPOTENCY: second run with same taskId should launch 0 new sessions
    new_sessions_run2 = results["sessions_run2"] - results["sessions_run1"]
    if new_sessions_run2 != 0:
        errors.append(
            f"FAIL: Idempotency violated — run 2 (same taskId) launched "
            f"{new_sessions_run2} sessions, expected 0"
        )

    # 11. DEDUP: third run with new taskId should only process previously-skipped
    #     findings (fixed entries are deduped, skipped entries get retried)
    new_sessions_run3 = results["sessions_run3"] - results["sessions_run2"]
    if new_sessions_run3 != expected_skipped:
        errors.append(
            f"FAIL: Dedup — run 3 (new taskId) should process {expected_skipped} "
            f"previously-skipped findings, launched {new_sessions_run3} sessions"
        )

    # 12. ACU cost: fixed entries should have acu_consumed > 0, skipped should be 0
    fixed_with_acu = [
        e for e in entries1
        if e.get("status") == "fixed" and (e.get("acu_consumed") or 0) > 0
    ]
    if len(fixed_with_acu) != session_cap:
        errors.append(
            f"FAIL: Expected {session_cap} fixed entries with acu_consumed > 0, "
            f"got {len(fixed_with_acu)}"
        )
    skipped_with_acu = [
        e for e in entries1
        if e.get("status") == "skipped" and (e.get("acu_consumed") or 0) > 0
    ]
    if skipped_with_acu:
        errors.append(
            f"FAIL: Skipped entries should have acu_consumed=0, "
            f"found {len(skipped_with_acu)} with cost"
        )
    total_acu = summary1.get("total_acu", 0)
    expected_acu = session_cap * 3.5  # 3.5 ACU per mock session
    if abs(float(total_acu) - expected_acu) > 0.01:
        errors.append(
            f"FAIL: Expected total_acu={expected_acu}, got {total_acu}"
        )

    if errors:
        print("RESULTS:")
        for e in errors:
            print(f"  {e}")
        sys.exit(1)
    else:
        print("ALL CHECKS PASSED")
        print()
        print(f"  ✓ Findings cap: {total_fetched} fetched (cap={findings_cap})")
        print(f"  ✓ Session cap: {results['sessions_run1']} sessions (cap={session_cap})")
        print(f"  ✓ Skipped: {expected_skipped} findings skipped with cap reason")
        print("  ✓ Priority: BLOCKERs remediated first")
        print(f"  ✓ Mixed types: {fixed_vuln} VULN + {fixed_bug} BUG in top {session_cap}")
        print("  ✓ Idempotency: duplicate taskId rejected (0 new sessions)")
        print(f"  ✓ Dedup: fixed findings skipped, {new_sessions_run3} skipped findings retried")
        print("  ✓ problem_summary + fix_summary populated correctly")
        print(f"  ✓ ACU cost: {len(fixed_with_acu)} fixed entries have cost, total={total_acu} ACU")
        sys.exit(0)


if __name__ == "__main__":
    main()
