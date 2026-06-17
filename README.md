# Aegis — Event-Driven Security Remediation Orchestrator

Aegis automates the remediation of security vulnerabilities found by SonarCloud in the [Apache Superset fork](https://github.com/ameer-khan05/superset-aegis-demo). When a scan completes, Aegis catches the webhook, fetches findings, creates GitHub issues, and dispatches [Devin AI](https://devin.ai) sessions to fix the code and open PRs — all driven programmatically via the Devin API.

## Architecture

```
┌──────────────┐    webhook     ┌────────────────────────────────────────┐
│  SonarCloud  │ ──────────────▶│  Aegis (FastAPI)                       │
│  Scan        │  HMAC-SHA256   │                                        │
└──────────────┘                │  1. Validate webhook signature         │
                                │  2. GET /api/issues/search (BLOCKER)   │
                                │  3. POST GitHub Issues (with dedup)    │
                                │  4. POST Devin v3 API (per finding)    │
                                │  5. Poll sessions → structured output  │
                                │  6. Record results → SQLite audit log  │
                                │                                        │
                                │  Dashboard: /dashboard                 │
                                │  ├── KPI cards (found/resolved/failed) │
                                │  ├── Filters (severity/status/scan)    │
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
| `AEGIS_MAX_ACU` | No | `15` | ACU cap per Devin session |
| `AEGIS_POLL_INTERVAL` | No | `30` | Seconds between session polls |
| `AEGIS_SESSION_TIMEOUT` | No | `1200` | Max seconds before timeout |

## Dashboard

The dashboard at `/dashboard` provides:

- **KPI Cards** — Findings detected, sessions triggered, resolved, failed
- **3 Filters** — By Severity (BLOCKER/CRITICAL), By Status (Fixed/Failed/In Progress/Timed Out), By Scan Run
- **Audit Table** — Each finding with links to the GitHub issue, Devin session, and PR
- **Auto-refresh** — Updates every 30 seconds

## How It Works

1. **SonarCloud** completes a scan and fires a webhook to `/webhook/sonar`
2. **Aegis** validates the HMAC-SHA256 signature and checks `status == "SUCCESS"`
3. **Findings Fetcher** calls `GET /api/issues/search` filtered to `severities=BLOCKER`
4. **GitHub Issues** are created for each finding (with dedup to avoid duplicates on re-scans)
5. **Devin Sessions** are launched via the v3 API with:
   - Repo pinned to the Superset fork
   - Structured output schema (finding_key, fixed, tests_passed, pr_url, failure_reason)
   - ACU cap of 15 per session
   - `create_as_user_id` for session attribution
6. **Poller** checks each session every 30s until terminal state (exit/error/suspended/timeout)
7. **Results** are recorded in SQLite and displayed on the dashboard

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
| **Configurable severity** | `AEGIS_MIN_SEVERITY` env var shows system scales without burning budget |
| **SQLite** | Zero-config, demo-friendly; swappable for Postgres in production |
| **Jinja2 dashboard** | Lightweight server-rendered; no frontend build step |
| **No auto-merge** | PRs stop at "opened" — human reviews before merge |
| **Hotspots skipped** | SonarCloud hotspots API is internal/unreliable; planned for v2 |

## Future Extensions

- **Hotspot remediation** — Once SonarCloud stabilizes the hotspots API
- **Batch sessions** — Group same-file findings into one Devin session
- **Postgres** — For production persistence
- **Auth** — Dashboard authentication for public deployments
- **Slack/email notifications** — Alert on scan completion
