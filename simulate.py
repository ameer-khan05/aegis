#!/usr/bin/env python3
"""Simulation mode — replay a canned webhook without live SonarCloud.

Computes the correct HMAC signature using SONAR_WEBHOOK_SECRET from .env
and sends the sample webhook payload to the local Aegis server.

Usage:
    python simulate.py [--url http://localhost:8000]
"""

import hashlib
import hmac
import json
import sys
from pathlib import Path

import httpx

# Load .env manually for the secret
env_path = Path(".env")
env_vars: dict[str, str] = {}
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env_vars[k.strip()] = v.strip()

secret = env_vars.get("SONAR_WEBHOOK_SECRET", "")
if not secret:
    print("ERROR: SONAR_WEBHOOK_SECRET not found in .env")
    sys.exit(1)

# Load sample payload
payload_path = Path("tests/fixtures/sample_webhook.json")
if not payload_path.exists():
    print(f"ERROR: {payload_path} not found")
    sys.exit(1)

payload_bytes = payload_path.read_bytes()
payload_json = json.loads(payload_bytes)

# Compute HMAC
sig = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()

# Send to server
url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
target = f"{url}/webhook/sonar"

print(f"Sending webhook to {target}")
print(f"  Task ID: {payload_json.get('taskId')}")
print(f"  Status: {payload_json.get('status')}")
print(f"  HMAC: {sig[:16]}...")

resp = httpx.post(
    target,
    content=payload_bytes,
    headers={
        "Content-Type": "application/json",
        "X-Sonar-Webhook-HMAC-SHA256": sig,
    },
)

print(f"  Response: {resp.status_code} {resp.text}")
