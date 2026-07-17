"""
Microsoft Sentinel / Log Analytics KQL threat hunter.
Runs a suite of KQL detection queries against an Azure Log Analytics workspace
and maps results to MITRE ATT&CK.

Detections:
  - Impossible travel (AADSignInLogs)
  - MFA fatigue / push bombing (repeated MFA denials)
  - Password spray (many failures across many users from one IP)
  - Privileged role assignment outside business hours
  - Suspicious OAuth app consent grants
  - Anomalous service principal sign-ins

Requires:
  pip install azure-identity azure-monitor-query

Auth: DefaultAzureCredential — works with az login, managed identity,
      or AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID env vars.

Run with --mock to test without a real workspace.
"""
import json
import time
import argparse
import math
import random
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from azure.identity import DefaultAzureCredential
    from azure.monitor.query import LogsQueryClient, LogsQueryStatus
    HAS_AZURE = True
except ImportError:
    HAS_AZURE = False


# ── Hunt Result ───────────────────────────────────────────────────────────────

@dataclass
class HuntResult:
    rule_id:     str
    severity:    str
    title:       str
    description: str
    technique:   str
    tactic:      str
    actor:       str
    event_time:  str
    raw:         dict = field(default_factory=dict, repr=False)


# ── KQL Queries ───────────────────────────────────────────────────────────────

KQL_QUERIES = {

    "SENT-001": {
        "title":     "Impossible Travel",
        "technique": "T1078",
        "tactic":    "Initial Access",
        "severity":  "critical",
        "kql": """
AADSignInLogs
| where TimeGenerated > ago(1h)
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend prev_time = prev(TimeGenerated), prev_ip = prev(IPAddress),
         prev_user = prev(UserPrincipalName), prev_loc = prev(Location)
| where UserPrincipalName == prev_user and IPAddress != prev_ip
| extend delta_min = datetime_diff('minute', TimeGenerated, prev_time)
| where delta_min < 60 and prev_loc != Location
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          prev_ip, prev_loc, delta_min
""",
    },

    "SENT-002": {
        "title":     "MFA Fatigue / Push Bombing",
        "technique": "T1621",
        "tactic":    "Credential Access",
        "severity":  "high",
        "kql": """
AADSignInLogs
| where TimeGenerated > ago(1h)
| where ResultType == 500121        // MFA required but denied
| summarize mfa_denials = count(), ips = make_set(IPAddress)
  by UserPrincipalName, bin(TimeGenerated, 10m)
| where mfa_denials >= 5
| project TimeGenerated, UserPrincipalName, mfa_denials, ips
""",
    },

    "SENT-003": {
        "title":     "Password Spray",
        "technique": "T1110.003",
        "tactic":    "Credential Access",
        "severity":  "high",
        "kql": """
AADSignInLogs
| where TimeGenerated > ago(30m)
| where ResultType != 0
| summarize failed_users = dcount(UserPrincipalName),
            total_attempts = count()
  by IPAddress, bin(TimeGenerated, 10m)
| where failed_users >= 10 and total_attempts >= 15
| project TimeGenerated, IPAddress, failed_users, total_attempts
""",
    },

    "SENT-004": {
        "title":     "Privileged Role Assignment Outside Business Hours",
        "technique": "T1098.003",
        "tactic":    "Persistence",
        "severity":  "high",
        "kql": """
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has "Add member to role"
| extend hour = datetime_part('hour', TimeGenerated)
| where hour < 8 or hour > 18
| extend actor = tostring(InitiatedBy.user.userPrincipalName),
         target = tostring(TargetResources[0].userPrincipalName),
         role = tostring(TargetResources[0].modifiedProperties[0].newValue)
| project TimeGenerated, actor, target, role, hour
""",
    },

    "SENT-005": {
        "title":     "Suspicious OAuth App Consent",
        "technique": "T1550.001",
        "tactic":    "Defense Evasion",
        "severity":  "critical",
        "kql": """
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Consent to application"
| extend actor = tostring(InitiatedBy.user.userPrincipalName),
         app   = tostring(TargetResources[0].displayName),
         perms = tostring(TargetResources[0].modifiedProperties)
| where perms has_any ("Mail.Read", "Files.ReadWrite.All",
                       "offline_access", "User.Read.All")
| project TimeGenerated, actor, app, perms
""",
    },

    "SENT-006": {
        "title":     "Anomalous Service Principal Sign-In",
        "technique": "T1078.004",
        "tactic":    "Initial Access",
        "severity":  "high",
        "kql": """
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize failures = count(), locations = make_set(Location)
  by ServicePrincipalName, IPAddress, bin(TimeGenerated, 10m)
| where failures >= 5
| project TimeGenerated, ServicePrincipalName, IPAddress, failures, locations
""",
    },
}


# ── Mock Result Generator ─────────────────────────────────────────────────────

def mock_results(rule_id: str) -> list[dict]:
    now = datetime.now(timezone.utc)
    if rule_id == "SENT-001":
        return [{
            "TimeGenerated": (now - timedelta(minutes=5)).isoformat(),
            "UserPrincipalName": "john.doe@contoso.com",
            "IPAddress": "45.33.32.156",
            "Location": "Moscow, RU",
            "prev_ip": "10.0.1.15",
            "prev_loc": "Washington DC, US",
            "delta_min": 12,
        }]
    if rule_id == "SENT-002":
        return [{
            "TimeGenerated": (now - timedelta(minutes=8)).isoformat(),
            "UserPrincipalName": "admin@contoso.com",
            "mfa_denials": 11,
            "ips": ["91.220.101.5"],
        }]
    if rule_id == "SENT-003":
        return [{
            "TimeGenerated": (now - timedelta(minutes=15)).isoformat(),
            "IPAddress": "198.51.100.33",
            "failed_users": 23,
            "total_attempts": 47,
        }]
    if rule_id == "SENT-004":
        return [{
            "TimeGenerated": (now - timedelta(hours=3)).replace(hour=2).isoformat(),
            "actor": "svc-deploy@contoso.com",
            "target": "newadmin@contoso.com",
            "role": "\"Global Administrator\"",
            "hour": 2,
        }]
    if rule_id == "SENT-005":
        return [{
            "TimeGenerated": (now - timedelta(hours=1)).isoformat(),
            "actor": "intern@contoso.com",
            "app": "Totally Legit App",
            "perms": "Mail.Read offline_access Files.ReadWrite.All",
        }]
    if rule_id == "SENT-006":
        return [{
            "TimeGenerated": (now - timedelta(minutes=20)).isoformat(),
            "ServicePrincipalName": "ci-pipeline-prod",
            "IPAddress": "91.220.101.5",
            "failures": 8,
            "locations": ["RU", "CN"],
        }]
    return []


def result_to_hunt(rule_id: str, meta: dict, row: dict) -> HuntResult:
    actor = (row.get("UserPrincipalName")
             or row.get("ServicePrincipalName")
             or row.get("actor")
             or row.get("IPAddress","unknown"))

    ts = row.get("TimeGenerated", datetime.now(timezone.utc).isoformat())

    desc_map = {
        "SENT-001": (f"Impossible travel: {actor} signed in from "
                     f"{row.get('prev_loc')} then {row.get('Location')} "
                     f"in {row.get('delta_min')} minutes"),
        "SENT-002": (f"MFA fatigue: {actor} received "
                     f"{row.get('mfa_denials')} MFA push denials in 10 min "
                     f"from {row.get('ips')}"),
        "SENT-003": (f"Password spray from {row.get('IPAddress')}: "
                     f"{row.get('failed_users')} users targeted, "
                     f"{row.get('total_attempts')} attempts"),
        "SENT-004": (f"Privileged role assigned at hour {row.get('hour')}:00 UTC — "
                     f"{actor} → {row.get('target')} role={row.get('role')}"),
        "SENT-005": (f"OAuth consent by {actor} to '{row.get('app')}' "
                     f"with sensitive scopes: {row.get('perms','')}[:80]"),
        "SENT-006": (f"Service principal '{actor}' had {row.get('failures')} "
                     f"failed sign-ins from {row.get('IPAddress')} "
                     f"locations={row.get('locations')}"),
    }

    return HuntResult(
        rule_id    = rule_id,
        severity   = meta["severity"],
        title      = meta["title"],
        description= desc_map.get(rule_id, str(row)),
        technique  = meta["technique"],
        tactic     = meta["tactic"],
        actor      = str(actor),
        event_time = ts,
        raw        = row,
    )


# ── Live Query Runner ─────────────────────────────────────────────────────────

def run_kql(client, workspace_id: str, kql: str,
            lookback_hours: int = 24) -> list[dict]:
    try:
        from azure.monitor.query import LogsQueryStatus
        end   = datetime.now(timezone.utc)
        start = end - timedelta(hours=lookback_hours)
        resp  = client.query_workspace(
            workspace_id = workspace_id,
            query        = kql,
            timespan     = (start, end),
        )
        if resp.status == LogsQueryStatus.SUCCESS:
            rows = []
            for table in resp.tables:
                cols = table.columns
                for row in table.rows:
                    rows.append(dict(zip(cols, row)))
            return rows
        return []
    except Exception as e:
        print(f"[warn] KQL query failed: {e}")
        return []

# ── Main ──────────────────────────────────────────────────────────────────────

SEV_COLOR = {"critical": "\033[91m", "high": "\033[93m",
             "medium":   "\033[94m", "low":  "\033[96m"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
RESET     = "\033[0m"


def main():
    parser = argparse.ArgumentParser(description="Azure Sentinel KQL threat hunter")
    parser.add_argument("--workspace",  default=None,
                        help="Log Analytics workspace ID")
    parser.add_argument("--hours",      type=int, default=24,
                        help="Lookback window in hours (default: 24)")
    parser.add_argument("--output",     default="sentinel_hunt.jsonl")
    parser.add_argument("--mock",       action="store_true",
                        help="Use simulated data, no Azure creds needed")
    args = parser.parse_args()

    if not args.mock and not HAS_AZURE:
        print("[!] azure-identity and azure-monitor-query required:")
        print("    pip install azure-identity azure-monitor-query")
        return

    if not args.mock and not args.workspace:
        print("[!] Provide --workspace <Log Analytics workspace ID> or use --mock")
        return

    client = None
    if not args.mock:
        client = LogsQueryClient(DefaultAzureCredential())

    out     = Path(args.output)
    results: list[HuntResult] = []

    print(f"[*] Sentinel Threat Hunter | {len(KQL_QUERIES)} detections | "
          f"lookback={args.hours}h | mock={args.mock}\n")

    for rule_id, meta in KQL_QUERIES.items():
        if args.mock:
            rows = mock_results(rule_id)
        else:
            rows = run_kql(client, args.workspace, meta["kql"], args.hours)

        for row in rows:
            r = result_to_hunt(rule_id, meta, row)
            results.append(r)

    results.sort(key=lambda r: SEV_ORDER.get(r.severity, 9))

    for r in results:
        col = SEV_COLOR.get(r.severity, "")
        print(f"{col}[{r.severity.upper():8}] {r.rule_id:10} | "
              f"{r.technique:10} | {r.title}{RESET}")
        print(f"             {r.description}")
        print(f"             Actor={r.actor}  Time={r.event_time}\n")
        with out.open("a") as f:
            f.write(json.dumps(asdict(r)) + "\n")

    counts = {}
    for r in results:
        counts[r.severity] = counts.get(r.severity, 0) + 1

    print(f"[*] Hunt complete. {len(results)} findings | " +
          " | ".join(f"{k.upper()}: {v}" for k, v in counts.items()))
    print(f"[*] Results → {out}")

if __name__ == "__main__":
    main()
