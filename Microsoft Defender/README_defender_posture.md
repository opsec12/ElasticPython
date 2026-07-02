# Microsoft Defender for Cloud + Entra ID Posture Scanner

Checks Azure security posture across Defender for Cloud recommendations, active alerts, secure score, RBAC assignments, and Entra ID identity hygiene. Output is a severity-sorted console report and a JSON file.

## Setup

```bash
pip install azure-identity azure-mgmt-security azure-mgmt-authorization azure-mgmt-resource

# Anaconda
conda install -c conda-forge azure-identity azure-mgmt-security azure-mgmt-authorization azure-mgmt-resource
```

## Run it

```bash
# Mock mode (no creds needed)
python azure_02_defender_posture.py --mock

# Live scan
python azure_02_defender_posture.py --subscription <subscription-id>

# Save report
python azure_02_defender_posture.py --subscription <subscription-id> --output report.json
```

## Options

| Flag | Default | What it does |
|------|---------|--------------|
| `--subscription` | (placeholder) | Azure subscription ID |
| `--output` | defender_posture.json | Report output file |
| `--mock` | False | Use simulated data, no creds needed |

## Checks

**Defender for Cloud**
- **DEF-001** — Secure score below 75% (critical <40%, high <60%, medium <75%)
- **DEF-002** — Active unresolved security alerts
- **DEF-003** — Open hardening recommendations (High/Medium/Low)

**RBAC**
- **RBAC-001** (T1098.003) — Owner or Contributor assigned at subscription scope; guest users with any privileged role escalated to critical

**Entra ID**
- **ENTRA-001** (T1550.001) — Stale app registrations with no sign-in activity in 180+ days
- **ENTRA-002** (T1528) — Service principals authenticating with password credentials instead of certificate or managed identity
- **ENTRA-003** (T1078) — Users excluded from Conditional Access policies
- **ENTRA-004** (T1078.004) — Admin accounts with no MFA method registered

## Authentication

Uses `DefaultAzureCredential`:

```bash
# Interactive login
az login

# Environment variables (service principal)
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
export AZURE_TENANT_ID=...
```

## Output

Console groups findings by category (Defender, RBAC, Entra ID) sorted by severity. `defender_posture.json` contains all findings with check ID, severity, resource, description, remediation, and MITRE technique.

## Notes

Entra ID checks (ENTRA-001 through ENTRA-004) require Microsoft Graph API in live mode. Install `msgraph-sdk` and replace `check_entra_id()` with a `GraphServiceClient` implementation. The script runs mock Entra ID checks automatically if Graph SDK is not present.

RBAC checks are scoped to the subscription level. Resource group and resource-level assignments are not evaluated — run the script once per subscription and aggregate reports for full coverage.
