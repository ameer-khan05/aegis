# Aegis — Event-Driven Remediation Orchestrator

Aegis automates the remediation of security vulnerabilities **and bugs** found by SonarCloud in the [Apache Superset fork](https://github.com/ameer-khan05/superset-aegis-demo). When a scan completes, Aegis catches the webhook, fetches findings (both `VULNERABILITY` and `BUG` types), creates GitHub issues, and dispatches [Devin AI](https://devin.ai) sessions to fix the code and open PRs — all driven programmatically via the Devin API.

## Architecture

```
┌──────────────┐    webhook     ┌────────────────────────────────────────┐
│  SonarCloud  │ ──────────────▶│  Aegis (FastAPI)                       │
│  Scan        │  HMAC-SHA256   │                                        │
└──────────────┘                │  1. Validate webhook signature         │
                                │  2. GET /api/issues/search (VULN+BUG)  │
                                │  3. POST GitHub Issues (with dedup)    │
                                │  4. POST Devin v3 API (per finding)    │
                                │  5. Poll sessions → structured output  │
                                │  6. Record results → SQLite audit log  │
                                │                                        │
                                │  Dashboard: /dashboard                 │
                                │  ├── KPI cards (found/resolved/failed) │
                                │  ├── Filters (type/severity/status/scan)│
                                │  └── Audit table with PR links         │
                                └────────────────────────────────────────┘
```

## Related Repository

| Repo | Purpose |
|------|---------|
| [ameer-khan05/superset-aegis-demo](https://github.com/ameer-khan05/superset-aegis-demo) | Superset fork — target of remediation (contains issues + Devin-opened PRs) |

## Prerequisites

- Docker & Docker Compose
- ngrok (for webhook exposure during demo)
- API keys (see [Environment Variables](#environment-variables))

## Quick Start

```bash
# 1. Clone
git clone https://github.com/ameer-khan05/aegis.git
cd aegis

# 2. Copy and fill in your secrets
cp .env.example .env
# Edit .env with your actual tokens

# 3. Run
docker-compose up --build

# 4. Expose via ngrok (separate terminal)
ngrok http 8000

# 5. Configure the ngrok URL as a webhook in SonarCloud:
#    SonarCloud → Project → Administration → Webhooks → Create
#    URL: https://xxxx.ngrok-free.app/webhook/sonar
#    Secret: same value as SONAR_WEBHOOK_SECRET in your .env

# 6. Open the dashboard
#    http://localhost:8000/dashboard
```

## Simulate (without live SonarCloud)

For reviewers who want to see the flow without a live SonarCloud scan:

```bash
# Option 1: Python script (computes correct HMAC from your .env)
python simulate.py

# Option 2: Manual curl (replace HMAC with your computed value)
curl -X POST http://localhost:8000/webhook/sonar \
  -H "Content-Type: application/json" \
  -H "X-Sonar-Webhook-HMAC-SHA256: <your_hmac_hex>" \
  -d @tests/fixtures/sample_webhook.json
```

The simulation triggers the full orchestration pipeline. Without valid SonarCloud/Devin/GitHub tokens, API calls will fail gracefully and the dashboard will show the error states.

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Healthcheck |
| `/webhook/sonar` | POST | SonarCloud webhook receiver (HMAC validated) |
| `/dashboard` | GET | Executive summary dashboard (HTML) |
| `/api/results` | GET | Audit log entries (JSON, filterable) |
| `/api/summary` | GET | KPI numbers (JSON) |
| `/docs` | GET | OpenAPI interactive documentation |
| `/api/runs/{id}/cancel` | POST | Cancel all in-flight sessions for a scan run |
| `/api/sessions/{id}/cancel` | POST | Cancel a single in-flight Devin session |

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SONAR_TOKEN` | Yes | — | SonarCloud API token |
| `SONAR_WEBHOOK_SECRET` | Yes | — | HMAC-SHA256 secret for webhook validation |
| `SONAR_PROJECT_KEY` | No | `ameer-khan05_superset-aegis-demo` | SonarCloud project key |
| `GITHUB_TOKEN` | Yes | — | GitHub PAT for issue creation |
| `GITHUB_REPO` | No | `ameer-khan05/superset-aegis-demo` | Target repo for issues |
| `DEVIN_API_KEY` | Yes | — | Devin service user API key |
| `DEVIN_ORG_ID` | Yes | — | Devin organization ID |
| `DEVIN_USER_ID` | Yes | — | Devin user ID (for session attribution) |
| `AEGIS_MIN_SEVERITY` | No | `BLOCKER` | Minimum severity to remediate |
| `AEGIS_ISSUE_TYPES` | No | `VULNERABILITY,BUG` | Comma-separated SonarCloud issue types to fetch |
| `AEGIS_MAX_ACU` | No | `15` | ACU cap per Devin session |
| `AEGIS_POLL_INTERVAL` | No | `30` | Seconds between session polls |
| `AEGIS_SESSION_TIMEOUT` | No | `1200` | Max seconds before timeout |
| `MAX_SESSIONS_PER_RUN` | No | `5` | Max Devin sessions launched per webhook run |

## Dashboard

The dashboard at `/dashboard` provides:

- **KPI Cards** — Findings detected, remediated this run, resolved, failed, skipped (cap)
- **4 Filters** — By Type (Vulnerability/Bug), By Severity (BLOCKER/CRITICAL), By Status (Fixed/Failed/In Progress/Timed Out/Skipped/Cancelled), By Scan Run
- **Cap explainer** — Banner showing session-cap value and intentional skip count
- **Audit Table** — Each finding with links to the GitHub issue, Devin session, and PR
- **Auto-refresh** — Updates every 30 seconds

## How It Works

1. **SonarCloud** completes a scan and fires a webhook to `/webhook/sonar`
2. **Aegis** validates the HMAC-SHA256 signature and checks `status == "SUCCESS"`
3. **Findings Fetcher** calls `GET /api/issues/search` for each configured type (`VULNERABILITY`, `BUG`) filtered to `severities=BLOCKER`
4. **GitHub Issues** are created for each finding (with dedup to avoid duplicates on re-scans)
5. **Session Cap** — findings are sorted by severity (most severe first), then recency (most recent first).  Only the top `MAX_SESSIONS_PER_RUN` (default 5) are dispatched; the rest are recorded as *skipped* so the dashboard shows the full picture
6. **Devin Sessions** are launched via the v3 API with:
   - Repo pinned to the Superset fork
   - Structured output schema (finding_key, fixed, tests_passed, pr_url, failure_reason)
   - ACU cap of 15 per session
   - `create_as_user_id` for session attribution
7. **Poller** checks each session every 30s until terminal state (exit/error/suspended/timeout)
8. **Results** are recorded in SQLite and displayed on the dashboard

## Project Structure

```
aegis/
├── app/
│   ├── main.py             # FastAPI entrypoint + lifespan
│   ├── config.py           # Pydantic Settings (.env)
│   ├── models.py           # Finding, SessionResult, AuditEntry
│   ├── db.py               # SQLite audit log operations
│   ├── routers/
│   │   ├── webhook.py      # POST /webhook/sonar (HMAC validation)
│   │   └── dashboard.py    # Dashboard + JSON APIs
│   ├── services/
│   │   ├── sonar.py        # SonarCloud findings fetcher
│   │   ├── github.py       # GitHub Issues creator
│   │   ├── devin.py        # Devin session launcher + poller
│   │   └── orchestrator.py # End-to-end remediation pipeline
│   └── templates/
│       └── dashboard.html  # Jinja2 executive dashboard
├── tests/
│   └── fixtures/
│       └── sample_webhook.json
├── simulate.py             # Simulation script
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## Development

```bash
# Local dev (without Docker)
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8000
```

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Devin v3 API** | Only version supporting `structured_output_schema`, `repos`, `tags`, ACU cap |
| **1 session per finding** | Simpler tracking; batching is a future optimization |
| **BLOCKER severity only** | Keeps demo to ~5-15 findings, ~75-225 ACU max |
| **Session cap (MAX_SESSIONS_PER_RUN)** | Prevents runaway cost; all findings still recorded for reporting |
| **VULNERABILITY + BUG types** | Demonstrates Devin API handling both security and code quality issues |
| **Configurable severity & types** | `AEGIS_MIN_SEVERITY` + `AEGIS_ISSUE_TYPES` env vars show system scales without burning budget |
| **SQLite** | Zero-config, demo-friendly; swappable for Postgres in production |
| **Jinja2 dashboard** | Lightweight server-rendered; no frontend build step |
| **No auto-merge** | PRs stop at "opened" — human reviews before merge |
| **Hotspots skipped** | SonarCloud hotspots API is internal/unreliable; planned for v2 |

## Stopping In-Flight Sessions

To cancel all running Devin sessions for a specific scan run:

```bash
curl -X POST http://localhost:8000/api/runs/<scan_task_id>/cancel
```

This calls the Devin v3 cancel API for every `in_progress` session in that run and marks them as `cancelled` in the audit log.  Individual sessions can also be cancelled directly via the Devin API:

```bash
curl -X POST https://api.devin.ai/v3/organizations/$DEVIN_ORG_ID/sessions/$SESSION_ID/cancel \
  -H "Authorization: Bearer $DEVIN_API_KEY"
```

## Future Extensions

- **Hotspot remediation** — Once SonarCloud stabilizes the hotspots API
- **Batch sessions** — Group same-file findings into one Devin session
- **Postgres** — For production persistence
- **Auth** — Dashboard authentication for public deployments
- **Slack/email notifications** — Alert on scan completion
