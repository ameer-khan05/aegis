# Aegis

Event-driven orchestrator that uses the [Devin API](https://docs.devin.ai) as a programmable primitive to autonomously remediate security vulnerabilities and code-quality bugs in a fork of [Apache Superset](https://github.com/ameer-khan05/superset-aegis-demo). SonarCloud detects the findings; Aegis creates a Jira ticket and GitHub issue per finding; moving a Jira ticket from *To Do* to *In Progress* triggers a Devin session that reads the flagged code, applies the fix, runs tests, and opens a pull request; Aegis polls the session and auto-transitions the ticket to *Done* when the PR is open. A live dashboard and SQLite audit log provide full observability. The system was built to clear a security backlog no human team could hand-remediate at scale.

> Built as part of a Devin evaluation.

## Architecture

```
                             ┌───────────────────────────────────────────────────────┐
                             │  SonarCloud                                           │
                             │  Scans on its own cadence; findings persist as backlog│
                             └──────────────────────────┬────────────────────────────┘
                                                        │
                              (backlog already exists)   │ Aegis fetches via API
                                                        │
  PR merged to master                                   ▼
        │              ┌────────────────────────────────────────────────────────────┐
        ▼              │  Aegis Orchestrator (FastAPI)                              │
  ┌──────────┐  POST   │                                                            │
  │  GitHub   │────────▶│  /webhook/sonar                                            │
  │  Action   │ (HMAC)  │    ├─ Validate HMAC signature                              │
  │  (no scan)│         │    ├─ Fetch findings from SonarCloud API                   │
  └──────────┘         │    ├─ Deduplicate against audit log                        │
                        │    ├─ Create Jira ticket (To Do) + GitHub issue per finding│
                        │    └─ Record as 'pending' in SQLite                        │
                        │                                                            │
                        │  /webhook/jira                                             │
  ┌──────────┐  POST   │    ├─ Ticket moved To Do → In Progress                     │
  │  Jira     │────────▶│    ├─ Enforce session cap (MAX_SESSIONS_PER_RUN)           │
  │  Automation│        │    ├─ Launch Devin session (v3 API)                        │
  └──────────┘         │    ├─ Poll until terminal state                            │
                        │    ├─ Transition ticket to Done on success                 │
                        │    └─ Record result + ACU cost in audit log                │
                        │                                                            │
                        │  /dashboard                                                │
                        │    └─ KPI cards, filters, audit table, auto-refresh        │
                        └────────────────────────────────────────────────────────────┘
```

### Key design decisions

| Decision | Why |
|----------|-----|
| **Devin driven as an API primitive** | Not native Automations. The orchestrator controls session lifecycle, prompt, structured output schema, and polling — full programmatic control. |
| **Scan decoupled from trigger** | The GitHub Action that fires on merge does *not* run a SonarCloud scan. It only POSTs the Aegis webhook. A slow full scan never blocks remediation. |
| **Session cap (`MAX_SESSIONS_PER_RUN`)** | Prevents runaway cost and Devin session sprawl. Excess tickets wait in Jira for manual triage. |
| **No auto-merge** | PRs wait for human review. The system intentionally stops at "PR opened." |
| **Structured-output contract** | Each Devin session returns `{finding_key, fixed, tests_passed, pr_url, fix_summary}` — the dashboard is populated from machine-readable results, not scraped logs. |
| **SQLite audit log** | Zero-config, demo-friendly. Swappable for Postgres in production. |

## Tech Stack

Python 3.12 / FastAPI, SQLite (via aiosqlite), httpx (async HTTP), asyncio polling, Jinja2 dashboard, Pydantic v2 settings, Docker Compose.

## Prerequisites

- **Docker** and Docker Compose
- **SonarCloud** project with an API token ([sonarcloud.io](https://sonarcloud.io))
- **Jira Cloud** project (free tier works) with an API token ([id.atlassian.net/manage-profile/security/api-tokens](https://id.atlassian.net/manage-profile/security/api-tokens))
- **Devin** organization with a service user (Admin role) and an API key ([docs.devin.ai](https://docs.devin.ai))
- **GitHub** fine-grained PAT scoped to the fork (Issues: read/write)
- **ngrok** (or any public tunnel) to receive webhooks locally

## Environment Variables

Copy `.env.example` to `.env` and fill in. Secrets are `.gitignore`d.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SONAR_TOKEN` | Yes | — | SonarCloud API token for fetching findings |
| `SONAR_WEBHOOK_SECRET` | Yes | — | Shared HMAC-SHA256 key for webhook signature validation |
| `SONAR_PROJECT_KEY` | No | `ameer-khan05_superset-aegis-demo` | SonarCloud project key |
| `GITHUB_TOKEN` | Yes | — | GitHub PAT for creating issues on the fork |
| `GITHUB_REPO` | No | `ameer-khan05/superset-aegis-demo` | Target repo (`owner/repo`) |
| `DEVIN_API_KEY` | Yes | — | Devin service-user API key |
| `DEVIN_ORG_ID` | Yes | — | Devin organization ID (prefix: `org-`) |
| `DEVIN_USER_ID` | Yes | — | Devin user ID for session attribution (prefix: `user-`) |
| `JIRA_BASE_URL` | No | — | Jira Cloud instance URL (e.g. `https://yoursite.atlassian.net`). Leave blank to disable Jira. |
| `JIRA_EMAIL` | No | — | Atlassian account email for Basic auth |
| `JIRA_API_TOKEN` | No | — | Jira API token |
| `JIRA_PROJECT_KEY` | No | `KAN` | Jira project key for ticket creation |
| `JIRA_WEBHOOK_SECRET` | No | — | Shared secret for `/webhook/jira` authentication (`X-Aegis-Secret` header) |
| `AEGIS_MIN_SEVERITY` | No | `BLOCKER` | Minimum severity threshold — expands upward (e.g. `MAJOR` fetches BLOCKER + CRITICAL + MAJOR) |
| `AEGIS_ISSUE_TYPES` | No | `VULNERABILITY,BUG` | Comma-separated SonarCloud issue types to fetch |
| `MAX_FINDINGS_PER_RUN` | No | `10` | Cap on findings fetched from SonarCloud per run |
| `MAX_SESSIONS_PER_RUN` | No | `5` | Concurrent Devin session cap (enforced on `/webhook/jira`) |
| `AEGIS_MAX_ACU` | No | `15` | ACU budget cap per Devin session |
| `AEGIS_POLL_INTERVAL` | No | `30` | Seconds between session status polls |
| `AEGIS_SESSION_TIMEOUT` | No | `2700` | Max seconds to poll a session before marking timed out (45 min) |

## Setup & Run

```bash
git clone https://github.com/ameer-khan05/aegis.git
cd aegis

cp .env.example .env
# Fill in all required values

docker compose up --build
```

Confirm the dashboard is live at [http://localhost:8000/dashboard](http://localhost:8000/dashboard).

To receive webhooks, expose the server via ngrok:

```bash
ngrok http 8000
# Note the https://*.ngrok-free.app URL
```

## Populating Findings

SonarCloud holds the findings backlog. The trigger workflow intentionally does **not** run a scan — it only fires the Aegis webhook. To populate or refresh the backlog, run a one-time full scan:

1. Go to [Actions → SonarCloud Full Scan](https://github.com/ameer-khan05/superset-aegis-demo/actions/workflows/sonar-full-scan.yml)
2. Click **"Run workflow"** → **"Run workflow"**

This scans the entire codebase (~1.2M lines, takes ~20 min) and uploads findings to SonarCloud. It does **not** trigger Aegis — by design, backlog population is separate from remediation.

## Triggering Remediation

Three paths, depending on your scenario:

### a) Live trigger (merge to master)

Merge a PR to `master` on the fork. The `aegis-trigger.yml` GitHub Action fires automatically:

```
PR merged → aegis-trigger.yml runs → POSTs /webhook/sonar → Aegis fetches findings → creates Jira tickets
```

No scan runs in this path. Aegis reads the existing SonarCloud backlog.

### b) Jira trigger (move ticket To Do → In Progress)

Each finding has a Jira ticket in *To Do*. Move one (or several) to *In Progress* — the Jira Automation rule fires the `/webhook/jira` endpoint, which launches a Devin session for that specific finding.

```
Ticket → In Progress → /webhook/jira → Devin session → fix + PR → ticket → Done
```

The session cap (`MAX_SESSIONS_PER_RUN`) prevents runaway if multiple tickets move at once — excess requests get HTTP 429.

### c) Simulate (no live scan needed)

For reviewers who want to exercise the full pipeline without the external dependencies:

```bash
# Start the server
docker compose up --build

# In another terminal — replay a canned webhook
python simulate.py
# or specify a custom URL:
python simulate.py http://localhost:8000
```

`simulate.py` reads `tests/fixtures/sample_webhook.json`, computes the correct HMAC from your `.env`, and POSTs it. Without valid SonarCloud/Devin/Jira tokens the API calls will fail gracefully — the dashboard will show error states, demonstrating the observability layer.

## Jira Automation Setup

Create an automation rule in your Jira project (Project Settings → Automation → Create rule):

1. **Trigger:** *When: Status changes* — From status `To Do`, To status `In Progress`
2. **Action:** *Send web request*
   - **URL:** `https://<your-ngrok-url>/webhook/jira`
   - **Method:** `POST`
   - **Headers:**
     ```
     Content-Type: application/json
     X-Aegis-Secret: <JIRA_WEBHOOK_SECRET from .env>
     ```
   - **Body:**
     ```json
     {
       "issue": {
         "key": "{{issue.key}}",
         "fields": {
           "summary": "{{issue.summary}}",
           "status": { "name": "{{issue.status.name}}" }
         }
       },
       "transition": {
         "from_status": "To Do",
         "to_status": "In Progress"
       }
     }
     ```

## Observability

### Dashboard (`/dashboard`)

| KPI Card | What it shows |
|----------|---------------|
| Findings Detected | Total findings fetched across all runs |
| Awaiting (Jira To Do) | Findings with tickets created, waiting for triage |
| In Progress | Active Devin sessions currently running |
| Resolved | Sessions that opened a PR successfully |
| Failed | Sessions that errored or couldn't fix the finding |
| Total ACU Cost | Aggregate Devin compute spend across all sessions |

The audit table shows every finding with its severity, rule, file, problem summary, fix summary, Jira ticket link, GitHub issue link, Devin session link, PR link, ACU cost, and status. Filters by type, severity, status, and scan run. Auto-refreshes every 30 seconds.

### How would an engineering leader know it's working?

- **Jira board** reflects the real pipeline state — *To Do* = backlog, *In Progress* = Devin is working, *Done* = PR opened
- **Dashboard KPIs** show throughput (findings → tickets → PRs) and cost (ACU)
- **Audit log** provides a per-finding paper trail from detection to PR
- **GitHub PRs** are the tangible output — each links back to its SonarCloud finding

### API endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/webhook/sonar` | POST | SonarCloud webhook receiver (HMAC validated) |
| `/webhook/jira` | POST | Jira automation receiver (shared-secret validated) |
| `/dashboard` | GET | Executive dashboard (HTML) |
| `/api/results` | GET | Audit log entries (JSON, filterable) |
| `/api/summary` | GET | KPI numbers (JSON) |
| `/api/runs/{id}/cancel` | POST | Cancel all in-flight sessions for a scan run |
| `/api/sessions/{id}/cancel` | POST | Cancel a single Devin session |
| `/docs` | GET | OpenAPI interactive documentation |

## Project Structure

```
aegis/
├── app/
│   ├── main.py                 # FastAPI entrypoint + lifespan
│   ├── config.py               # Pydantic Settings (.env loading, severity expansion)
│   ├── models.py               # Finding, SessionResult dataclasses
│   ├── db.py                   # SQLite audit log (aiosqlite)
│   ├── routers/
│   │   ├── webhook.py          # POST /webhook/sonar — HMAC validation, dispatch
│   │   ├── jira_webhook.py     # POST /webhook/jira — ticket transition → Devin session
│   │   └── dashboard.py        # GET /dashboard, /api/results, /api/summary, cancel
│   ├── services/
│   │   ├── orchestrator.py     # Run pipeline: fetch → dedup → create tickets
│   │   ├── sonar.py            # SonarCloud API client (findings fetch)
│   │   ├── devin.py            # Devin v3 API client (launch, poll, cancel, structured output)
│   │   ├── github.py           # GitHub issue creator (with dedup)
│   │   └── jira.py             # Jira Cloud client (create ticket, transition, lookup)
│   └── templates/
│       └── dashboard.html      # Jinja2 executive dashboard
├── tests/
│   ├── fixtures/
│   │   └── sample_webhook.json # Canned SonarCloud webhook payload
│   └── test_session_cap_e2e.py # End-to-end tests (mocked APIs)
├── simulate.py                 # Replay webhook without live SonarCloud
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

## Development

```bash
# Without Docker
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8000
```

## Related Repository

| Repo | Purpose |
|------|---------|
| [ameer-khan05/superset-aegis-demo](https://github.com/ameer-khan05/superset-aegis-demo) | Apache Superset fork — target of remediation. Contains SonarCloud findings and Devin-opened PRs. |
