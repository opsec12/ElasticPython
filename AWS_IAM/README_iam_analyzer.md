# IAM Privilege Escalation Analyzer

Parses IAM policy documents attached to users and roles and checks for known privilege escalation paths. Based on Rhino Security Labs research on AWS IAM PrivEsc.

## Setup

```bash
pip install boto3

# Anaconda
conda install -c conda-forge boto3
```

## Run it

```bash
# Mock mode — runs against 4 built-in sample identities (no creds needed)
python iam_analyzer.py --mock

# Live scan
python iam_analyzer.py --output iam_risk.json
```

## Options

| Flag | Default | What it does |
|------|---------|--------------|
| `--output` | iam_risk_report.json | Results output file |
| `--mock` | False | Use built-in sample identities, no AWS creds needed |

## Escalation paths detected

10 known paths are checked against every attached and inline policy:

- `iam:AttachUserPolicy` / `AttachRolePolicy` — attach managed policy to self
- `iam:PutUserPolicy` — create or update inline policy
- `iam:CreateUser` + `iam:AttachUserPolicy` — spin up a new admin user
- `iam:CreateAccessKey` — mint access keys for another user
- `iam:UpdateAssumeRolePolicy` — update trust policy to assume a privileged role
- `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` — exec code as a privileged role via Lambda
- `iam:PassRole` + `ec2:RunInstances` — attach privileged instance profile to EC2
- `iam:CreateRole` + `iam:AttachRolePolicy` — create a new admin role and assume it
- `ssm:SendCommand` + `iam:PassRole` — SSM RunCommand on EC2 with privileged role
- `cloudformation:CreateStack` + `iam:PassRole` — deploy a CFN stack that runs arbitrary code

Also flags wildcard permissions (`iam:*`, `s3:*`, `ec2:*`, etc.) and full admin (`Action: "*" on Resource: "*"`).

## Output

Console prints findings grouped by identity, sorted by severity. `iam_risk_report.json` contains all findings with risk score, MITRE technique, policy name, and remediation context.

```
[CRITICAL] ESC-006    Privilege escalation path: Pass role to Lambda + invoke
           arn:aws:iam::123456789:user/svc-deploy
           MITRE: T1648 | Policy: DeployPolicy

[CRITICAL] PERM-001   Full wildcard permission (equivalent to AdministratorAccess)
           arn:aws:iam::123456789:role/developer-role
           MITRE: T1098.003 | Policy: DeveloperPolicy
```

## Notes

The analyzer needs `iam:ListUsers`, `iam:ListRoles`, `iam:ListAttachedUserPolicies`, `iam:GetPolicyVersion`, and `iam:GetUserPolicy` at minimum. All read-only — no write permissions required.

Inline policies and attached managed policies are both checked. Service control policies (SCPs) are not evaluated — a finding here may be blocked at the org level, so verify against your SCP before remediating.
