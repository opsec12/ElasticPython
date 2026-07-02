"""
IAM policy privilege escalation analyzer.
Parses AWS IAM policy documents, identifies high-risk permissions,
and traces privilege escalation paths — where a lower-privileged identity
can grant itself or another identity admin-level access.

Requires: boto3 (optional — runs in --mock mode without credentials)
  pip install boto3

Reference: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
"""

import json
import sys
import argparse
import itertools
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


# ── Risk Patterns ─────────────────────────────────────────────────────────────

# Actions that let a principal elevate privileges
# Each tuple: (check_id, description, technique, actions_required)
ESCALATION_PATHS = [
    ("ESC-001", "Attach managed policy to self/other",
     "T1098.003",
     ["iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy"]),

    ("ESC-002", "Create/update inline policy on user",
     "T1098.003",
     ["iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy"]),

    ("ESC-003", "Create new IAM user + attach admin policy",
     "T1136.003",
     ["iam:CreateUser", "iam:AttachUserPolicy"]),

    ("ESC-004", "Create access key for another user",
     "T1528",
     ["iam:CreateAccessKey"]),

    ("ESC-005", "Update assume-role trust policy",
     "T1548.005",
     ["iam:UpdateAssumeRolePolicy"]),

    ("ESC-006", "Pass role to Lambda + invoke",
     "T1648",
     ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]),

    ("ESC-007", "Pass role to EC2 instance (attach instance profile)",
     "T1578.002",
     ["iam:PassRole", "ec2:RunInstances"]),

    ("ESC-008", "Create role with admin trust + assume it",
     "T1548.005",
     ["iam:CreateRole", "iam:AttachRolePolicy"]),

    ("ESC-009", "SSM RunCommand on EC2 with privileged role",
     "T1651",
     ["ssm:SendCommand", "iam:PassRole"]),

    ("ESC-010", "CloudFormation stack deploy with admin role",
     "T1610",
     ["cloudformation:CreateStack", "iam:PassRole"]),
]

HIGH_RISK_ACTIONS = {
    "iam:*", "sts:*", "ec2:*", "lambda:*", "s3:*",
    "cloudformation:*", "ssm:*", "secretsmanager:*",
    "kms:*", "logs:DeleteLogGroup",
}

WILDCARD_RESOURCE_SCORE = 40
HIGH_RISK_ACTION_SCORE  = 20
ESCALATION_PATH_SCORE   = 50


# ── Policy Parser ─────────────────────────────────────────────────────────────

def normalize_actions(statement: dict) -> set[str]:
    """Return all Action strings from a policy statement (lowercase)."""
    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    return {a.lower() for a in actions}


def has_wildcard_resource(statement: dict) -> bool:
    resources = statement.get("Resource", [])
    if isinstance(resources, str):
        resources = [resources]
    return "*" in resources or "arn:aws:*:*:*:*" in resources


def is_allow(statement: dict) -> bool:
    return statement.get("Effect", "Deny").lower() == "allow"


def expand_wildcard_actions(action: str, all_actions: set[str]) -> set[str]:
    """Expand e.g. 'iam:*' against known action list."""
    if not action.endswith("*"):
        return {action}
    prefix = action[:-1].lower()
    return {a for a in all_actions if a.startswith(prefix)}


def effective_actions(statements: list[dict]) -> set[str]:
    """Compute net Allow actions after applying Deny statements."""
    allowed = set()
    denied  = set()
    for stmt in statements:
        actions = normalize_actions(stmt)
        if is_allow(stmt):
            allowed |= actions
        else:
            denied  |= actions
    return allowed - denied


# ── Risk Scoring ──────────────────────────────────────────────────────────────

@dataclass
class RiskFinding:
    entity:      str       # user / role / group ARN or name
    entity_type: str       # user | role | group
    check_id:    str
    title:       str
    severity:    str
    description: str
    technique:   str
    score:       int
    policy_name: str = ""


def score_to_severity(score: int) -> str:
    if score >= 50: return "critical"
    if score >= 35: return "high"
    if score >= 20: return "medium"
    return "low"


def analyze_policy_doc(doc: dict, entity: str, entity_type: str,
                        policy_name: str) -> list[RiskFinding]:
    findings = []
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    allow_stmts = [s for s in statements if is_allow(s)]
    actions      = effective_actions(statements)

    # ── Wildcard action + wildcard resource (admin equivalent) ───────────────
    for stmt in allow_stmts:
        acts = normalize_actions(stmt)
        if "*" in acts and has_wildcard_resource(stmt):
            score = WILDCARD_RESOURCE_SCORE + HIGH_RISK_ACTION_SCORE
            findings.append(RiskFinding(
                entity      = entity,
                entity_type = entity_type,
                check_id    = "PERM-001",
                title       = "Full wildcard permission (equivalent to AdministratorAccess)",
                severity    = score_to_severity(score),
                description = (f"Policy '{policy_name}' grants Action:'*' on Resource:'*' — "
                               f"full admin access to all AWS services."),
                technique   = "T1098.003",
                score       = score,
                policy_name = policy_name,
            ))

    # ── High-risk service wildcards (iam:*, s3:*, ec2:*, etc.) ───────────────
    for act in actions:
        for hr in HIGH_RISK_ACTIONS:
            if hr.endswith("*") and act.startswith(hr[:-1]):
                score = HIGH_RISK_ACTION_SCORE
                findings.append(RiskFinding(
                    entity      = entity,
                    entity_type = entity_type,
                    check_id    = "PERM-002",
                    title       = f"High-risk service wildcard: {hr}",
                    severity    = score_to_severity(score),
                    description = (f"Policy '{policy_name}' permits {hr} — "
                                   f"all actions on that service."),
                    technique   = "T1098",
                    score       = score,
                    policy_name = policy_name,
                ))
                break

    # ── Privilege escalation path detection ───────────────────────────────────
    for check_id, desc, technique, required_actions in ESCALATION_PATHS:
        required_lower = {a.lower() for a in required_actions}
        if required_lower.issubset(actions | {f"{a}*" for a in actions}):
            score = ESCALATION_PATH_SCORE
            findings.append(RiskFinding(
                entity      = entity,
                entity_type = entity_type,
                check_id    = check_id,
                title       = f"Privilege escalation path: {desc}",
                severity    = score_to_severity(score),
                description = (f"Entity has: {', '.join(sorted(required_lower))} — "
                               f"can escalate privileges via: {desc}"),
                technique   = technique,
                score       = score,
                policy_name = policy_name,
            ))

    # Deduplicate by check_id
    seen = set()
    deduped = []
    for f in findings:
        key = (f.check_id, f.entity, f.policy_name)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


# ── Mock Data ─────────────────────────────────────────────────────────────────

MOCK_ENTITIES = [
    {
        "name": "svc-deploy",
        "arn":  "arn:aws:iam::123456789:user/svc-deploy",
        "type": "user",
        "policies": [
            ("DeployPolicy", {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow",
                     "Action": ["iam:PassRole", "lambda:CreateFunction",
                                "lambda:InvokeFunction", "s3:*"],
                     "Resource": "*"},
                ]
            }),
        ]
    },
    {
        "name": "developer-role",
        "arn":  "arn:aws:iam::123456789:role/developer-role",
        "type": "role",
        "policies": [
            ("DeveloperPolicy", {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "*", "Resource": "*"},
                ]
            }),
        ]
    },
    {
        "name": "readonly-user",
        "arn":  "arn:aws:iam::123456789:user/readonly-user",
        "type": "user",
        "policies": [
            ("ReadOnlyAccess", {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow",
                     "Action": ["s3:GetObject", "s3:ListBucket",
                                "ec2:DescribeInstances", "cloudwatch:GetMetricData"],
                     "Resource": "*"},
                ]
            }),
        ]
    },
    {
        "name": "ci-pipeline",
        "arn":  "arn:aws:iam::123456789:role/ci-pipeline",
        "type": "role",
        "policies": [
            ("CIPipelinePolicy", {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow",
                     "Action": ["iam:CreateAccessKey", "iam:AttachUserPolicy",
                                "ec2:RunInstances", "iam:PassRole"],
                     "Resource": "*"},
                ]
            }),
        ]
    },
]


# ── AWS Live Scan ─────────────────────────────────────────────────────────────

def fetch_aws_entities(iam_client) -> list[dict]:
    entities = []
    try:
        for user in iam_client.list_users().get("Users", []):
            name = user["UserName"]
            arn  = user["Arn"]
            policies = []
            for p in iam_client.list_user_policies(UserName=name).get("PolicyNames", []):
                doc = iam_client.get_user_policy(UserName=name, PolicyName=p)
                policies.append((p, doc["PolicyDocument"]))
            for p in iam_client.list_attached_user_policies(UserName=name).get("AttachedPolicies", []):
                pv = iam_client.get_policy_version(
                    PolicyArn=p["PolicyArn"],
                    VersionId=iam_client.get_policy(PolicyArn=p["PolicyArn"])["Policy"]["DefaultVersionId"]
                )
                policies.append((p["PolicyName"], pv["PolicyVersion"]["Document"]))
            entities.append({"name": name, "arn": arn, "type": "user", "policies": policies})
    except ClientError as e:
        print(f"[warn] IAM user fetch: {e}")

    try:
        for role in iam_client.list_roles().get("Roles", []):
            name = role["RoleName"]
            arn  = role["Arn"]
            policies = []
            for p in iam_client.list_role_policies(RoleName=name).get("PolicyNames", []):
                doc = iam_client.get_role_policy(RoleName=name, PolicyName=p)
                policies.append((p, doc["PolicyDocument"]))
            for p in iam_client.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
                pv = iam_client.get_policy_version(
                    PolicyArn=p["PolicyArn"],
                    VersionId=iam_client.get_policy(PolicyArn=p["PolicyArn"])["Policy"]["DefaultVersionId"]
                )
                policies.append((p["PolicyName"], pv["PolicyVersion"]["Document"]))
            entities.append({"name": name, "arn": arn, "type": "role", "policies": policies})
    except ClientError as e:
        print(f"[warn] IAM role fetch: {e}")

    return entities


# ── Reporter ──────────────────────────────────────────────────────────────────

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEV_COLOR = {"critical": "\033[91m", "high": "\033[93m",
             "medium": "\033[94m", "low": "\033[96m"}
RESET = "\033[0m"


def print_report(findings: list[RiskFinding]):
    findings.sort(key=lambda f: SEV_ORDER.get(f.severity, 9))
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"\n{'─'*72}")
    print(f"  IAM Privilege Escalation Report — "
          f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  Findings: {len(findings)} | " +
          " | ".join(f"{k.upper()}: {v}" for k,v in counts.items()))
    print(f"{'─'*72}\n")

    current_entity = None
    for f in findings:
        if f.entity != current_entity:
            current_entity = f.entity
            print(f"  [{f.entity_type.upper()}] {f.entity}")
            print(f"  {'─'*60}")
        col = SEV_COLOR.get(f.severity, "")
        print(f"  {col}[{f.severity.upper():8}] {f.check_id:10} {f.title}{RESET}")
        print(f"             {f.description}")
        print(f"             MITRE: {f.technique} | Policy: {f.policy_name}\n")


def save_report(findings: list[RiskFinding], path: Path):
    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "findings": [asdict(f) for f in findings],
    }
    path.write_text(json.dumps(report, indent=2))


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="IAM privilege escalation analyzer")
    parser.add_argument("--output", default="iam_risk_report.json")
    parser.add_argument("--mock",   action="store_true",
                        help="Use built-in sample identities (no AWS creds needed)")
    args = parser.parse_args()

    if not args.mock and not HAS_BOTO3:
        print("[!] boto3 not installed. Use --mock or: pip install boto3")
        sys.exit(1)

    print(f"[*] IAM Privilege Escalation Analyzer | mock={args.mock}")
    print(f"[*] Checking {len(ESCALATION_PATHS)} escalation paths + wildcard rules\n")

    entities = MOCK_ENTITIES if args.mock else fetch_aws_entities(
        boto3.client("iam")
    )

    all_findings: list[RiskFinding] = []
    for entity in entities:
        for policy_name, doc in entity["policies"]:
            findings = analyze_policy_doc(
                doc, entity["arn"], entity["type"], policy_name
            )
            all_findings.extend(findings)

    if not all_findings:
        print("[+] No high-risk findings detected.")
    else:
        print_report(all_findings)

    out = Path(args.output)
    save_report(all_findings, out)
    print(f"[*] Report → {out}")


if __name__ == "__main__":
    main()
