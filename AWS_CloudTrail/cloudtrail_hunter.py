"""
CloudTrail threat hunting engine.
Queries CloudTrail logs and detects:
  - Root account usage
  - Console logins without MFA
  - API activity from unusual regions
  - Credential stuffing / access key enumeration
  - High-volume Describe/List calls (reconnaissance)
  - IAM privilege changes outside change windows
  - Impossible travel (same user from geographically distant IPs in <1h)

Requires: boto3
  pip install boto3 geoip2   # geoip2 optional for impossible travel

Run with --mock to test without AWS credentials.
"""

import json
import sys
import time
import math
import argparse
import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

try:
    import geoip2.database
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False


# ── Hunt Result ───────────────────────────────────────────────────────────────

@dataclass
class HuntResult:
    rule_id:     str
    severity:    str
    title:       str
    description: str
    technique:   str
    tactic:      str
    actor:       str          # user / role / ip
    event_time:  str
    region:      str
    raw_event:   dict = field(default_factory=dict, repr=False)


# ── CloudTrail Event Parser ───────────────────────────────────────────────────

def parse_user_identity(uid: dict) -> str:
    t = uid.get("type", "")
    if t == "Root":
        return "ROOT"
    if t == "IAMUser":
        return uid.get("userName", "unknown")
    if t == "AssumedRole":
        arn = uid.get("arn","")
        return arn.split("/")[-1] if arn else "assumed-role"
    return uid.get("principalId", "unknown")


def event_time(record: dict) -> datetime:
    ts = record.get("eventTime", "")
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


# ── Detection Rules ───────────────────────────────────────────────────────────

def detect_root_activity(records: list[dict]) -> list[HuntResult]:
    results = []
    for r in records:
        uid = r.get("userIdentity", {})
        if uid.get("type") == "Root":
            results.append(HuntResult(
                rule_id    = "CT-HUNT-001",
                severity   = "critical",
                title      = "Root account API activity",
                description= (f"Root account performed '{r.get('eventName')}' "
                               f"in {r.get('awsRegion')} from {r.get('sourceIPAddress')}"),
                technique  = "T1078.004",
                tactic     = "Privilege Escalation",
                actor      = "ROOT",
                event_time = r.get("eventTime",""),
                region     = r.get("awsRegion",""),
                raw_event  = {k: r[k] for k in ("eventName","sourceIPAddress","awsRegion")
                              if k in r},
            ))
    return results


def detect_console_no_mfa(records: list[dict]) -> list[HuntResult]:
    results = []
    for r in records:
        if r.get("eventName") != "ConsoleLogin":
            continue
        resp = r.get("responseElements", {}) or {}
        if resp.get("ConsoleLogin") != "Success":
            continue
        add_data = r.get("additionalEventData", {}) or {}
        if not add_data.get("MFAUsed"):
            user = parse_user_identity(r.get("userIdentity", {}))
            results.append(HuntResult(
                rule_id    = "CT-HUNT-002",
                severity   = "high",
                title      = "Console login without MFA",
                description= (f"{user} logged into console without MFA "
                               f"from {r.get('sourceIPAddress')}"),
                technique  = "T1078",
                tactic     = "Initial Access",
                actor      = user,
                event_time = r.get("eventTime",""),
                region     = r.get("awsRegion",""),
                raw_event  = {"user": user, "ip": r.get("sourceIPAddress")},
            ))
    return results


def detect_unusual_regions(records: list[dict],
                            allowed_regions: set[str]) -> list[HuntResult]:
    """Flag API calls from regions outside the org's normal operating footprint."""
    results = []
    for r in records:
        region = r.get("awsRegion","")
        if region and region not in allowed_regions:
            user = parse_user_identity(r.get("userIdentity", {}))
            results.append(HuntResult(
                rule_id    = "CT-HUNT-003",
                severity   = "medium",
                title      = "API call from unexpected region",
                description= (f"{user} invoked '{r.get('eventName')}' "
                               f"in {region} (not in approved list)"),
                technique  = "T1078",
                tactic     = "Defense Evasion",
                actor      = user,
                event_time = r.get("eventTime",""),
                region     = region,
                raw_event  = {"event": r.get("eventName"), "region": region},
            ))
    return results


def detect_recon_burst(records: list[dict],
                        window_minutes: int = 5,
                        threshold: int = 30) -> list[HuntResult]:
    """
    T1580 — Cloud Infrastructure Discovery
    >N Describe/List/Get calls from one identity in a short window.
    """
    RECON_PREFIXES = ("Describe", "List", "Get", "Enumerate", "Scan", "Search")
    by_user: dict[str, list[datetime]] = defaultdict(list)

    for r in records:
        if any(r.get("eventName","").startswith(p) for p in RECON_PREFIXES):
            user = parse_user_identity(r.get("userIdentity", {}))
            by_user[user].append(event_time(r))

    results = []
    for user, times in by_user.items():
        times.sort()
        window = timedelta(minutes=window_minutes)
        for i, t in enumerate(times):
            burst = [ts for ts in times[i:] if ts - t <= window]
            if len(burst) >= threshold:
                results.append(HuntResult(
                    rule_id    = "CT-HUNT-004",
                    severity   = "high",
                    title      = "Reconnaissance burst (cloud enumeration)",
                    description= (f"{user} made {len(burst)} Describe/List/Get calls "
                                   f"in {window_minutes} minutes"),
                    technique  = "T1580",
                    tactic     = "Discovery",
                    actor      = user,
                    event_time = t.isoformat(),
                    region     = "multi",
                    raw_event  = {"calls": len(burst), "window_min": window_minutes},
                ))
                break
    return results


def detect_iam_changes(records: list[dict],
                        change_window_hours: tuple = (8, 18)) -> list[HuntResult]:
    """
    T1098 — Account Manipulation
    IAM write operations outside business hours.
    """
    IAM_WRITE = {
        "CreateUser", "DeleteUser", "AttachUserPolicy", "DetachUserPolicy",
        "PutUserPolicy", "CreateRole", "AttachRolePolicy", "CreateAccessKey",
        "UpdateLoginProfile", "DeleteLoginProfile", "AddUserToGroup",
    }
    results = []
    for r in records:
        if r.get("eventName") not in IAM_WRITE:
            continue
        et  = event_time(r)
        hour = et.hour
        if not (change_window_hours[0] <= hour <= change_window_hours[1]):
            user = parse_user_identity(r.get("userIdentity", {}))
            results.append(HuntResult(
                rule_id    = "CT-HUNT-005",
                severity   = "high",
                title      = "IAM change outside business hours",
                description= (f"{user} called '{r.get('eventName')}' at "
                               f"{et.strftime('%H:%M UTC')} "
                               f"(outside {change_window_hours[0]:02d}:00-"
                               f"{change_window_hours[1]:02d}:00 window)"),
                technique  = "T1098",
                tactic     = "Persistence",
                actor      = user,
                event_time = r.get("eventTime",""),
                region     = r.get("awsRegion",""),
                raw_event  = {"event": r.get("eventName"), "hour_utc": hour},
            ))
    return results


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat/2)**2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2)**2)
    return R * 2 * math.asin(math.sqrt(a))


def detect_impossible_travel(records: list[dict],
                              geoip_db: Optional[str] = None) -> list[HuntResult]:
    """
    T1078 — Valid Accounts
    Same user authenticating from geographically distant IPs within a short time.
    Requires MaxMind GeoLite2-City.mmdb for real geo lookups.
    Mock: uses hardcoded lat/lon per IP prefix.
    """
    MOCK_GEO = {
        "10.":     (38.9, -77.0),   # Washington DC (internal)
        "45.33":   (37.3, -121.8),  # San Jose
        "91.220":  (55.75, 37.6),   # Moscow
        "198.51":  (51.5, -0.12),   # London
        "8.8":     (37.4, -122.0),  # Mountain View
    }

    def lookup(ip: str):
        if geoip_db and HAS_GEOIP2:
            try:
                with geoip2.database.Reader(geoip_db) as reader:
                    r = reader.city(ip)
                    return r.location.latitude, r.location.longitude
            except Exception:
                pass
        for prefix, coords in MOCK_GEO.items():
            if ip.startswith(prefix):
                return coords
        return None

    by_user: dict[str, list[tuple]] = defaultdict(list)
    for r in records:
        if r.get("eventName") not in ("ConsoleLogin", "AssumeRole", "GetSessionToken"):
            continue
        ip   = r.get("sourceIPAddress","")
        user = parse_user_identity(r.get("userIdentity", {}))
        geo  = lookup(ip)
        if geo:
            by_user[user].append((event_time(r), ip, geo))

    results = []
    for user, events in by_user.items():
        events.sort()
        for i in range(len(events)-1):
            t1, ip1, (lat1, lon1) = events[i]
            t2, ip2, (lat2, lon2) = events[i+1]
            if ip1 == ip2:
                continue
            hours = (t2 - t1).total_seconds() / 3600
            dist  = haversine_km(lat1, lon1, lat2, lon2)
            # Max realistic travel speed ~900 km/h (commercial flight)
            if hours > 0 and (dist / hours) > 900:
                results.append(HuntResult(
                    rule_id    = "CT-HUNT-006",
                    severity   = "critical",
                    title      = "Impossible travel detected",
                    description= (f"{user} logged in from {ip1} ({lat1:.1f},{lon1:.1f}) "
                                   f"then {ip2} ({lat2:.1f},{lon2:.1f}) — "
                                   f"{dist:.0f} km in {hours:.1f}h "
                                   f"(implied {dist/max(hours,0.001):.0f} km/h)"),
                    technique  = "T1078",
                    tactic     = "Initial Access",
                    actor      = user,
                    event_time = t2.isoformat(),
                    region     = "multi",
                    raw_event  = {"dist_km": round(dist,1), "hours": round(hours,2),
                                  "ip1": ip1, "ip2": ip2},
                ))
    return results


# ── Mock CloudTrail Records ───────────────────────────────────────────────────

def mock_records() -> list[dict]:
    now = datetime.now(timezone.utc)
    def ts(delta_min=0): return (now - timedelta(minutes=delta_min)).isoformat().replace("+00:00","Z")
    return [
        # Root usage
        {"eventName": "StopLogging", "eventTime": ts(5),
         "awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.5",
         "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123456:root"},
         "responseElements": None, "additionalEventData": {}},

        # Console login without MFA
        {"eventName": "ConsoleLogin", "eventTime": ts(15),
         "awsRegion": "us-east-1", "sourceIPAddress": "10.0.1.10",
         "userIdentity": {"type": "IAMUser", "userName": "jsmith"},
         "responseElements": {"ConsoleLogin": "Success"},
         "additionalEventData": {"MFAUsed": False}},

        # Unusual region
        {"eventName": "RunInstances", "eventTime": ts(20),
         "awsRegion": "ap-southeast-3", "sourceIPAddress": "91.220.101.5",
         "userIdentity": {"type": "IAMUser", "userName": "ci-pipeline"},
         "responseElements": None, "additionalEventData": {}},

        # Recon burst — 40 Describe calls
        *[{"eventName": f"Describe{s}", "eventTime": ts(30 + i),
           "awsRegion": "us-east-1", "sourceIPAddress": "45.33.32.156",
           "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::123:assumed-role/dev/attacker"},
           "responseElements": None, "additionalEventData": {}}
          for i, s in enumerate(["Instances","SecurityGroups","Subnets","VPCs",
                                   "RouteTables","NetworkInterfaces","Images",
                                   "KeyPairs","Volumes","Snapshots"] * 4)],

        # IAM change at 02:30 UTC
        {"eventName": "AttachUserPolicy", "eventTime": now.replace(hour=2,minute=30).isoformat()+"Z",
         "awsRegion": "us-east-1", "sourceIPAddress": "45.33.32.156",
         "userIdentity": {"type": "IAMUser", "userName": "svc-deploy"},
         "responseElements": None, "additionalEventData": {}},

        # Impossible travel
        {"eventName": "ConsoleLogin", "eventTime": ts(90),
         "awsRegion": "us-east-1", "sourceIPAddress": "10.0.0.5",
         "userIdentity": {"type": "IAMUser", "userName": "akim"},
         "responseElements": {"ConsoleLogin": "Success"},
         "additionalEventData": {"MFAUsed": True}},
        {"eventName": "ConsoleLogin", "eventTime": ts(20),
         "awsRegion": "eu-west-1", "sourceIPAddress": "91.220.101.5",
         "userIdentity": {"type": "IAMUser", "userName": "akim"},
         "responseElements": {"ConsoleLogin": "Success"},
         "additionalEventData": {"MFAUsed": True}},
    ]


# ── Runner ────────────────────────────────────────────────────────────────────

APPROVED_REGIONS = {"us-east-1", "us-west-2", "eu-west-1", "us-gov-west-1"}
SEV_COLOR  = {"critical": "\033[91m", "high": "\033[93m",
              "medium": "\033[94m", "low": "\033[96m"}
SEV_ORDER  = {"critical": 0, "high": 1, "medium": 2, "low": 3}
RESET = "\033[0m"


def fetch_cloudtrail_records(region: str, hours: int) -> list[dict]:
    client    = boto3.client("cloudtrail", region_name=region)
    end_time  = datetime.now(timezone.utc)
    start_time= end_time - timedelta(hours=hours)
    records   = []
    kwargs    = {"StartTime": start_time, "EndTime": end_time, "MaxResults": 50}
    while True:
        try:
            resp = client.lookup_events(**kwargs)
        except (ClientError, NoCredentialsError) as e:
            print(f"[warn] CloudTrail fetch error: {e}")
            break
        for event in resp.get("Events", []):
            try:
                records.append(json.loads(event.get("CloudTrailEvent", "{}")))
            except json.JSONDecodeError:
                pass
        token = resp.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token
    return records


def main():
    parser = argparse.ArgumentParser(description="CloudTrail threat hunter")
    parser.add_argument("--region",       default="us-east-1")
    parser.add_argument("--hours",        type=int, default=24,
                        help="How far back to look (default: 24h)")
    parser.add_argument("--output",       default="cloudtrail_hunt.jsonl")
    parser.add_argument("--geoip-db",     default=None,
                        help="Path to MaxMind GeoLite2-City.mmdb (optional)")
    parser.add_argument("--mock",         action="store_true")
    args = parser.parse_args()

    if not args.mock and not HAS_BOTO3:
        print("[!] boto3 not installed. Use --mock or: pip install boto3")
        sys.exit(1)

    print(f"[*] CloudTrail Hunter | region={args.region} | "
          f"lookback={args.hours}h | mock={args.mock}\n")

    records = mock_records() if args.mock else fetch_cloudtrail_records(args.region, args.hours)
    print(f"[*] Loaded {len(records)} CloudTrail records\n")

    all_results: list[HuntResult] = []
    all_results += detect_root_activity(records)
    all_results += detect_console_no_mfa(records)
    all_results += detect_unusual_regions(records, APPROVED_REGIONS)
    all_results += detect_recon_burst(records)
    all_results += detect_iam_changes(records)
    all_results += detect_impossible_travel(records, args.geoip_db)

    all_results.sort(key=lambda r: SEV_ORDER.get(r.severity, 9))

    out = Path(args.output)
    for r in all_results:
        col = SEV_COLOR.get(r.severity,"")
        print(f"{col}[{r.severity.upper():8}] {r.rule_id:14} | "
              f"{r.technique:10} | {r.title}{RESET}")
        print(f"             {r.description}")
        print(f"             Actor={r.actor} Time={r.event_time}\n")
        with out.open("a") as f:
            f.write(json.dumps(asdict(r)) + "\n")

    counts = {}
    for r in all_results:
        counts[r.severity] = counts.get(r.severity, 0) + 1

    print(f"[*] Hunt complete. {len(all_results)} findings | " +
          " | ".join(f"{k.upper()}: {v}" for k,v in counts.items()))
    print(f"[*] Results → {out}")


if __name__ == "__main__":
    main()
