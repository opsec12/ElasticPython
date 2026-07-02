# Azure Sentinel KQL Threat Hunter

Runs a suite of KQL detection queries against an Azure Log Analytics workspace and maps results to MITRE ATT&CK. Covers the most common identity and access attack patterns visible in Entra ID and Sentinel logs.

## Setup

```bash
pip install azure-identity azure-monitor-query

# Anaconda
conda install -c conda-forge azure-identity azure-monitor-query
```

## Run it

```bash
# Mock mode (no creds needed)
python azure_01_sentinel_hunter.py --mock

# Live hunt — last 24 hours
python azure_01_sentinel_hunter.py --workspace <workspace-id> --hours 24

# Save results to file
python azure_01_sentinel_hunter.py --workspace <workspace-id> --output hunt.jsonl
```

## Options

| Flag | Default | What it does |
|------|---------|--------------|
| `--workspace` | None | Log Analytics workspace ID |
| `--hours` | 24 | Lookback window in hours |
| `--output` | sentinel_hunt.jsonl | Results output file |
| `--mock` | False | Use simulated data, no creds needed |

## Detections

- **SENT-001** (T1078) — Impossible travel: same user signed in from two geographically distant locations within 60 minutes
- **SENT-002** (T1621) — MFA fatigue: ≥5 MFA push denials from the same user in a 10-minute window
- **SENT-003** (T1110.003) — Password spray: ≥10 distinct users targeted from one IP with ≥15 failed attempts in 30 minutes
- **SENT-004** (T1098.003) — Privileged role assignment outside business hours (before 08:00 or after 18:00 UTC)
- **SENT-005** (T1550.001) — Suspicious OAuth consent: user consented to an app requesting `Mail.Read`, `Files.ReadWrite.All`, `offline_access`, or `User.Read.All`
- **SENT-006** (T1078.004) — Anomalous service principal: ≥5 failed sign-ins from the same SP and IP in 10 minutes

## Authentication

Uses `DefaultAzureCredential` — works with any of the following:

```bash
# Interactive login
az login

# Environment variables (service principal)
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
export AZURE_TENANT_ID=...
```

Managed identity is picked up automatically if running inside Azure (VM, ACI, App Service, etc.).

## Output

Console prints each finding sorted by severity. `sentinel_hunt.jsonl` has one result per line with rule ID, severity, actor, MITRE technique, description, and timestamp.

## Notes

KQL queries target `AADSignInLogs` and `AuditLogs` tables. These must be connected as data sources in your Log Analytics workspace — enable them under Sentinel > Data connectors > Azure Active Directory.

Business hours window for SENT-004 is hardcoded to 08:00–18:00 UTC. Adjust the `hour < 8 or hour > 18` condition in the KQL to match your org's timezone.
