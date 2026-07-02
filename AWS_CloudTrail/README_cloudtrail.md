# CloudTrail Threat Hunter

Queries CloudTrail for indicators of compromise across six detection categories. Mock mode injects pre-built attack scenarios to demonstrate each detection.

## Setup

```bash
pip install boto3

# Anaconda
conda install -c conda-forge boto3

# Optional — for real geo lookup (impossible travel detection)
pip install geoip2
```

## Run it

```bash
# Mock mode (no creds needed)
python cloudtrail_hunter.py --mock

# Live — looks back 24 hours
python cloudtrail_hunter.py --region us-east-1 --hours 24

# With real geo lookup
python cloudtrail_hunter.py --mock --geoip-db GeoLite2-City.mmdb
```

## Options

| Flag | Default | What it does |
|------|---------|--------------|
| `--region` | us-east-1 | AWS region to query |
| `--hours` | 24 | How far back to look |
| `--output` | cloudtrail_hunt.jsonl | Results output file |
| `--geoip-db` | None | Path to MaxMind GeoLite2-City.mmdb |
| `--mock` | False | Use simulated data, no AWS creds needed |

## Detections

- **CT-HUNT-001** (T1078.004) — Root account API activity
- **CT-HUNT-002** (T1078) — Console login without MFA
- **CT-HUNT-003** (T1078) — API calls from regions outside an approved list
- **CT-HUNT-004** (T1580) — Recon burst: ≥30 Describe/List/Get calls in 5 minutes from one identity
- **CT-HUNT-005** (T1098) — IAM write operations outside business hours
- **CT-HUNT-006** (T1078) — Impossible travel: same user authenticating from IPs implying travel faster than commercial air (>900 km/h)

## Output

Console prints each finding sorted by severity. `cloudtrail_hunt.jsonl` has one result per line with rule ID, severity, actor, MITRE technique, description, and timestamp.

## Notes

Approved regions are set in `APPROVED_REGIONS` inside the script — update that set to match your org's actual footprint before running live.

Impossible travel uses mock geo data by default. For real lookups, download the free GeoLite2-City database from maxmind.com (requires a free account) and pass the `.mmdb` path via `--geoip-db`.
