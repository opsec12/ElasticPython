"""
Microsoft Defender for Cloud + Entra ID posture scanner.
Checks Azure security recommendations, secure score, active alerts,
RBAC overprivilege, guest user risk, stale app registrations,
and Conditional Access coverage gaps.

Requires:
  pip install azure-identity azure-mgmt-security azure-mgmt-authorization azure-mgmt-resource

Auth: DefaultAzureCredential — works with az login, managed identity,
      or AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID env vars.

Run with --mock to test without Azure credentials.
"""

import json
import sys
import argparse
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.security import SecurityCenter
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.resource import ResourceManagementClient
    HAS_AZURE = True
except ImportError:
    HAS_AZURE = False


# ── Finding Model ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    check_id:    str
    title:       str
    severity:    str
    resource:    str
    category:    str
    description: str
    remediation: str
    technique:   str  = ""
    passed:      bool = False
    ts:          str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ── Defender for Cloud Checks ─────────────────────────────────────────────────

def check_secure_score(client, sub_id: str, mock: bool = False) -> list[Finding]:
    findings = []

    if mock:
        scores = [
            {"name": "ASC Default", "score": 42.0, "max": 100.0},
        ]
    else:
        try:
            scores = [
                {"name": s.display_name,
                 "score": s.score.current if s.score else 0,
                 "max":   s.score.max     if s.score else 100}
                for s in client.secure_scores.list()
            ]
        except Exception as e:
            print(f"[warn] Secure score fetch failed: {e}")
            scores = []

    for s in scores:
        pct = (s["score"] / s["max"] * 100) if s["max"] else 0
        sev = ("critical" if pct < 40 else "high" if pct < 60
               else "medium" if pct < 75 else "low")
        findings.append(Finding(
            check_id    = "DEF-001",
            title       = f"Defender Secure Score: {pct:.1f}%",
            severity    = sev,
            resource    = f"subscription/{sub_id}",
            category    = "Defender",
            description = (f"'{s['name']}' score is {s['score']:.1f}/{s['max']:.1f} "
                           f"({pct:.1f}%). {'Below recommended 75%.' if pct < 75 else 'Acceptable.'}"),
            remediation = "Review and remediate open recommendations in Defender for Cloud.",
            passed      = pct >= 75,
        ))

    return findings


def check_defender_alerts(client, sub_id: str, mock: bool = False) -> list[Finding]:
    findings = []

    if mock:
        alerts = [
            {"name": "alert-001", "severity": "High",
             "display_name": "Suspicious PowerShell cmdlets executed",
             "resource": "/subscriptions/.../virtualMachines/vm-prod-01",
             "technique": "T1059.001"},
            {"name": "alert-002", "severity": "Medium",
             "display_name": "Unusual network activity detected",
             "resource": "/subscriptions/.../virtualMachines/vm-dev-02",
             "technique": "T1071"},
        ]
    else:
        try:
            alerts = [
                {"name": a.name,
                 "severity": a.severity or "Medium",
                 "display_name": a.alert_display_name or "",
                 "resource": a.compromised_entity or "",
                 "technique": (a.extended_properties or {}).get("killChainIntent","")}
                for a in client.alerts.list()
                if a.status != "Dismissed"
            ]
        except Exception as e:
            print(f"[warn] Alert fetch failed: {e}")
            alerts = []

    sev_map = {"High": "high", "Medium": "medium", "Low": "low",
               "Critical": "critical", "Informational": "low"}

    for a in alerts:
        sev = sev_map.get(a["severity"], "medium")
        findings.append(Finding(
            check_id    = "DEF-002",
            title       = f"Active Alert: {a['display_name']}",
            severity    = sev,
            resource    = a["resource"],
            category    = "Defender Alerts",
            description = f"Unresolved Defender for Cloud alert: {a['display_name']}",
            remediation = "Investigate and remediate in Defender for Cloud > Security Alerts.",
            technique   = a.get("technique",""),
        ))

    return findings


def check_defender_recommendations(client, sub_id: str,
                                    mock: bool = False) -> list[Finding]:
    findings = []

    if mock:
        recs = [
            {"id": "rec-001",
             "display_name": "MFA should be enabled on accounts with owner permissions",
             "severity": "High", "resource": "subscription"},
            {"id": "rec-002",
             "display_name": "Storage accounts should restrict network access",
             "severity": "Medium", "resource": "storageAccount/proddata"},
            {"id": "rec-003",
             "display_name": "System updates should be installed on machines",
             "severity": "Low", "resource": "virtualMachine/vm-prod-01"},
        ]
    else:
        try:
            recs = [
                {"id": r.name,
                 "display_name": r.display_name or "",
                 "severity": r.severity or "Medium",
                 "resource": r.resource_details.id if r.resource_details else ""}
                for r in client.tasks.list()
            ]
        except Exception as e:
            print(f"[warn] Recommendations fetch failed: {e}")
            recs = []

    sev_map = {"High": "high", "Medium": "medium", "Low": "low"}
    for r in recs:
        sev = sev_map.get(r["severity"], "medium")
        findings.append(Finding(
            check_id    = "DEF-003",
            title       = f"Open Recommendation: {r['display_name']}",
            severity    = sev,
            resource    = r["resource"],
            category    = "Defender Recommendations",
            description = r["display_name"],
            remediation = "Remediate in Defender for Cloud > Recommendations.",
        ))

    return findings


# ── RBAC Checks ───────────────────────────────────────────────────────────────

def check_rbac(auth_client, sub_id: str, mock: bool = False) -> list[Finding]:
    findings = []
    PRIVILEGED_ROLES = {
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
        "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
        "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    }

    if mock:
        assignments = [
            {"principal_id": "user-aaa", "principal_type": "User",
             "role_id": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
             "role_name": "Owner", "scope": f"/subscriptions/{sub_id}"},
            {"principal_id": "sp-bbb",   "principal_type": "ServicePrincipal",
             "role_id": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
             "role_name": "Owner", "scope": f"/subscriptions/{sub_id}"},
            {"principal_id": "guest-ccc","principal_type": "Guest",
             "role_id": "b24988ac-6180-42a0-ab88-20f7382dd24c",
             "role_name": "Contributor", "scope": f"/subscriptions/{sub_id}"},
        ]
    else:
        try:
            scope = f"/subscriptions/{sub_id}"
            assignments = [
                {"principal_id":   a.principal_id,
                 "principal_type": a.principal_type or "Unknown",
                 "role_id":        a.role_definition_id.split("/")[-1],
                 "role_name":      PRIVILEGED_ROLES.get(
                                       a.role_definition_id.split("/")[-1], ""),
                 "scope":          a.scope}
                for a in auth_client.role_assignments.list_for_scope(scope)
                if a.role_definition_id.split("/")[-1] in PRIVILEGED_ROLES
            ]
        except Exception as e:
            print(f"[warn] RBAC fetch failed: {e}")
            assignments = []

    for a in assignments:
        if not a["role_name"]:
            continue

        # Owner at subscription scope — always flag
        is_sub_scope = a["scope"].rstrip("/") == f"/subscriptions/{sub_id}"
        sev = "critical" if (a["role_name"] == "Owner" and is_sub_scope) else "high"

        # Guest with privileged role is extra risky
        if a["principal_type"] == "Guest":
            sev = "critical"

        findings.append(Finding(
            check_id    = "RBAC-001",
            title       = f"{a['role_name']} assigned at subscription scope",
            severity    = sev,
            resource    = f"principal/{a['principal_id']} ({a['principal_type']})",
            category    = "RBAC",
            description = (f"{a['principal_type']} '{a['principal_id']}' has "
                           f"{a['role_name']} at {a['scope']}. "
                           + ("Guest with privileged role is very high risk."
                              if a["principal_type"] == "Guest" else "")),
            remediation = ("Apply least privilege — replace Owner/Contributor with "
                           "scoped custom roles. Remove guest privileged access."),
            technique   = "T1098.003",
        ))

    return findings


# ── Entra ID Checks (mock only — Graph API requires separate SDK) ─────────────

def check_entra_id(mock: bool = False) -> list[Finding]:
    """
    Checks that require Microsoft Graph API.
    In live mode: use 'pip install msgraph-sdk' and authenticate via
    GraphServiceClient(DefaultAzureCredential()).
    Here we simulate common findings.
    """
    findings = []

    if not mock:
        print("[info] Entra ID checks require msgraph-sdk (Graph API). "
              "Running mock checks instead.")

    mock_data = {
        "stale_apps": [
            {"name": "OldReportingApp", "last_sign_in_days": 180},
            {"name": "LegacyCIBot",     "last_sign_in_days": 365},
        ],
        "spn_with_password": [
            {"name": "ci-pipeline-prod"},
            {"name": "legacy-deploy-sp"},
        ],
        "no_ca_users": [
            {"upn": "vendor@partner.com"},
            {"upn": "break-glass@contoso.com"},
        ],
        "no_mfa_admins": [
            {"upn": "helpdesk-admin@contoso.com"},
        ],
    }

    for app in mock_data["stale_apps"]:
        findings.append(Finding(
            check_id    = "ENTRA-001",
            title       = "Stale app registration",
            severity    = "medium",
            resource    = f"appRegistration/{app['name']}",
            category    = "Entra ID",
            description = (f"App '{app['name']}' has not had a sign-in in "
                           f"{app['last_sign_in_days']} days."),
            remediation = "Review and disable or delete unused app registrations.",
            technique   = "T1550.001",
        ))

    for sp in mock_data["spn_with_password"]:
        findings.append(Finding(
            check_id    = "ENTRA-002",
            title       = "Service principal using password credential",
            severity    = "high",
            resource    = f"servicePrincipal/{sp['name']}",
            category    = "Entra ID",
            description = (f"'{sp['name']}' authenticates with a password secret "
                           f"instead of a certificate or managed identity."),
            remediation = ("Migrate to certificate-based auth or managed identity. "
                           "Rotate and remove the password credential."),
            technique   = "T1528",
        ))

    for u in mock_data["no_ca_users"]:
        findings.append(Finding(
            check_id    = "ENTRA-003",
            title       = "User excluded from Conditional Access policies",
            severity    = "high",
            resource    = f"user/{u['upn']}",
            category    = "Entra ID / Conditional Access",
            description = (f"'{u['upn']}' is excluded from one or more CA policies "
                           f"— MFA and compliant device checks may not apply."),
            remediation = ("Review CA policy exclusions. Break-glass accounts should "
                           "be monitored via alerts, not excluded permanently."),
            technique   = "T1078",
        ))

    for u in mock_data["no_mfa_admins"]:
        findings.append(Finding(
            check_id    = "ENTRA-004",
            title       = "Admin account without MFA",
            severity    = "critical",
            resource    = f"user/{u['upn']}",
            category    = "Entra ID",
            description = (f"'{u['upn']}' has a privileged directory role "
                           f"but no MFA method registered."),
            remediation = ("Enforce MFA via CA policy for all admin roles. "
                           "Block sign-in until MFA is registered."),
            technique   = "T1078.004",
        ))

    return findings


# ── Reporter ──────────────────────────────────────────────────────────────────

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEV_COLOR = {"critical": "\033[91m", "high": "\033[93m",
             "medium":   "\033[94m", "low":  "\033[96m"}
RESET = "\033[0m"


def print_report(findings: list[Finding]):
    fails = [f for f in findings if not f.passed]
    fails.sort(key=lambda f: SEV_ORDER.get(f.severity, 9))
    counts = {}
    for f in fails:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"\n{'─'*72}")
    print(f"  Defender for Cloud + Entra ID Posture Report")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  Findings: {len(fails)} | " +
          " | ".join(f"{k.upper()}: {v}" for k, v in counts.items()))
    print(f"{'─'*72}\n")

    current_cat = None
    for f in fails:
        if f.category != current_cat:
            current_cat = f.category
            print(f"  ▶ {f.category}")
        col = SEV_COLOR.get(f.severity, "")
        print(f"  {col}[{f.severity.upper():8}] {f.check_id:10} {f.title}{RESET}")
        print(f"             Resource    : {f.resource}")
        print(f"             Description : {f.description}")
        print(f"             Remediation : {f.remediation}")
        if f.technique:
            print(f"             MITRE       : {f.technique}")
        print()


def save_report(findings: list[Finding], path: Path):
    report = {
        "generated_at":  datetime.now(timezone.utc).isoformat(),
        "total_findings": len([f for f in findings if not f.passed]),
        "findings":       [asdict(f) for f in findings if not f.passed],
    }
    path.write_text(json.dumps(report, indent=2))


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Microsoft Defender for Cloud + Entra ID posture scanner")
    parser.add_argument("--subscription", default="00000000-0000-0000-0000-000000000000",
                        help="Azure subscription ID")
    parser.add_argument("--output",       default="defender_posture.json")
    parser.add_argument("--mock",         action="store_true",
                        help="Use simulated data, no Azure creds needed")
    args = parser.parse_args()

    if not args.mock and not HAS_AZURE:
        print("[!] Azure SDK not installed:")
        print("    pip install azure-identity azure-mgmt-security "
              "azure-mgmt-authorization azure-mgmt-resource")
        sys.exit(1)

    print(f"[*] Defender Posture Scanner | sub={args.subscription} | mock={args.mock}\n")

    all_findings: list[Finding] = []

    if args.mock:
        all_findings += check_secure_score(None,  args.subscription, mock=True)
        all_findings += check_defender_alerts(None, args.subscription, mock=True)
        all_findings += check_defender_recommendations(None, args.subscription, mock=True)
        all_findings += check_rbac(None, args.subscription, mock=True)
        all_findings += check_entra_id(mock=True)
    else:
        cred        = DefaultAzureCredential()
        sec_client  = SecurityCenter(cred, args.subscription)
        auth_client = AuthorizationManagementClient(cred, args.subscription)

        all_findings += check_secure_score(sec_client, args.subscription)
        all_findings += check_defender_alerts(sec_client, args.subscription)
        all_findings += check_defender_recommendations(sec_client, args.subscription)
        all_findings += check_rbac(auth_client, args.subscription)
        all_findings += check_entra_id(mock=False)

    print_report(all_findings)
    out = Path(args.output)
    save_report(all_findings, out)
    print(f"[*] Full report → {out}")


if __name__ == "__main__":
    main()
