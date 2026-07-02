"""
Threat intelligence aggregator and IOC matcher.
Pulls indicator feeds, stores in SQLite, matches against a log stream.
Maps hits to MITRE ATT&CK techniques.
"""

import sqlite3
import csv
import json
import time
import re
import asyncio
import hashlib
import argparse
import ipaddress
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError
from dataclasses import dataclass, asdict


# ── IOC Types ────────────────────────────────────────────────────────────────

IOC_TYPES = ("ip", "domain", "url", "sha256", "md5")

MITRE_MAP = {
    "ip":     ("C2 Communication",      "T1071"),
    "domain": ("C2 Communication",      "T1071"),
    "url":    ("Phishing / Watering Hole", "T1566"),
    "sha256": ("Malicious File",         "T1204"),
    "md5":    ("Malicious File",         "T1204"),
}


# ── Database ──────────────────────────────────────────────────────────────────

class IOCDatabase:
    def __init__(self, path: str = "threat_intel.db"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS iocs (
                id        INTEGER PRIMARY KEY,
                value     TEXT NOT NULL,
                ioc_type  TEXT NOT NULL,
                feed      TEXT,
                severity  TEXT DEFAULT 'medium',
                added_at  TEXT,
                expires_at TEXT,
                tags      TEXT,
                UNIQUE(value, ioc_type)
            );
            CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(value);
            CREATE TABLE IF NOT EXISTS matches (
                id         INTEGER PRIMARY KEY,
                ioc_value  TEXT,
                ioc_type   TEXT,
                event_src  TEXT,
                event_host TEXT,
                event_user TEXT,
                matched_at TEXT,
                technique  TEXT,
                tactic     TEXT
            );
        """)
        self.conn.commit()

    def upsert(self, value: str, ioc_type: str, feed: str,
               severity: str = "medium", tags: str = "",
               ttl_days: int = 30):
        now     = datetime.now(timezone.utc).isoformat()
        expires = (datetime.now(timezone.utc) + timedelta(days=ttl_days)).isoformat()
        self.conn.execute("""
            INSERT INTO iocs (value, ioc_type, feed, severity, added_at, expires_at, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(value, ioc_type) DO UPDATE SET
                feed=excluded.feed, severity=excluded.severity,
                expires_at=excluded.expires_at, tags=excluded.tags
        """, (value.lower(), ioc_type, feed, severity, now, expires, tags))
        self.conn.commit()

    def lookup(self, value: str, ioc_type: str | None = None) -> list[dict]:
        now = datetime.now(timezone.utc).isoformat()
        if ioc_type:
            cur = self.conn.execute(
                "SELECT * FROM iocs WHERE value=? AND ioc_type=? AND expires_at > ?",
                (value.lower(), ioc_type, now)
            )
        else:
            cur = self.conn.execute(
                "SELECT * FROM iocs WHERE value=? AND expires_at > ?",
                (value.lower(), now)
            )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def record_match(self, ioc: dict, event: dict):
        tactic, technique = MITRE_MAP.get(ioc["ioc_type"], ("Unknown", "T????"))
        self.conn.execute("""
            INSERT INTO matches (ioc_value, ioc_type, event_src, event_host,
                                 event_user, matched_at, technique, tactic)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (ioc["value"], ioc["ioc_type"],
              event.get("source",""), event.get("host",""),
              event.get("user",""), datetime.now(timezone.utc).isoformat(),
              technique, tactic))
        self.conn.commit()

    def stats(self) -> dict:
        cur = self.conn.execute("SELECT COUNT(*) FROM iocs")
        total = cur.fetchone()[0]
        cur = self.conn.execute("SELECT COUNT(*) FROM matches")
        hits  = cur.fetchone()[0]
        cur = self.conn.execute(
            "SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type")
        by_type = dict(cur.fetchall())
        return {"total_iocs": total, "total_matches": hits, "by_type": by_type}

    def close(self):
        self.conn.close()


# ── Feed Parsers ──────────────────────────────────────────────────────────────

def load_feed_from_csv(db: IOCDatabase, path: str, feed_name: str,
                        value_col: str = "indicator",
                        type_col: str  = "type",
                        sev_col: str   = "severity"):
    """Load IOCs from a local CSV file."""
    loaded = 0
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            val      = row.get(value_col, "").strip()
            ioc_type = row.get(type_col, "ip").strip().lower()
            severity = row.get(sev_col, "medium").strip().lower()
            if val and ioc_type in IOC_TYPES:
                db.upsert(val, ioc_type, feed_name, severity)
                loaded += 1
    return loaded


def load_feed_from_list(db: IOCDatabase, indicators: list[tuple],
                         feed_name: str = "manual"):
    """Bulk-load (value, type, severity) tuples."""
    for value, ioc_type, severity in indicators:
        db.upsert(value, ioc_type, feed_name, severity)


def fetch_feed_url(url: str, timeout: int = 10) -> list[str]:
    """Download a newline-delimited IP/domain feed (e.g. abuse.ch). Returns lines."""
    try:
        with urlopen(url, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
        return [l.strip() for l in text.splitlines()
                if l.strip() and not l.startswith("#")]
    except URLError as e:
        print(f"[warn] Feed fetch failed ({url}): {e}")
        return []


# ── IOC Extractor ─────────────────────────────────────────────────────────────

_IP_RE     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}\b")
_SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
_MD5_RE    = re.compile(r"\b[0-9a-fA-F]{32}\b")
_URL_RE    = re.compile(r"https?://[^\s\"'<>]+")


def extract_observables(text: str) -> list[tuple[str, str]]:
    """Pull all observable artifacts from a free-text field."""
    obs = []
    for m in _URL_RE.findall(text):
        obs.append((m, "url"))
    for m in _SHA256_RE.findall(text):
        obs.append((m.lower(), "sha256"))
    for m in _MD5_RE.findall(text):
        obs.append((m.lower(), "md5"))
    for m in _IP_RE.findall(text):
        try:
            if not ipaddress.ip_address(m).is_private:
                obs.append((m, "ip"))
        except ValueError:
            pass
    for m in _DOMAIN_RE.findall(text):
        # skip IPs that regex also matched
        if not _IP_RE.fullmatch(m):
            obs.append((m.lower(), "domain"))
    return obs


# ── Matcher ───────────────────────────────────────────────────────────────────

@dataclass
class MatchResult:
    ioc_value:  str
    ioc_type:   str
    severity:   str
    feed:       str
    tactic:     str
    technique:  str
    event_host: str
    event_user: str
    matched_at: str


def match_event(db: IOCDatabase, event: dict) -> list[MatchResult]:
    """Check a log event dict against the IOC database."""
    text       = json.dumps(event)
    observables= extract_observables(text)
    results    = []
    seen       = set()

    for value, ioc_type in observables:
        if (value, ioc_type) in seen:
            continue
        seen.add((value, ioc_type))
        hits = db.lookup(value, ioc_type)
        for ioc in hits:
            db.record_match(ioc, event)
            tactic, technique = MITRE_MAP.get(ioc_type, ("Unknown", "T????"))
            results.append(MatchResult(
                ioc_value  = value,
                ioc_type   = ioc_type,
                severity   = ioc["severity"],
                feed       = ioc["feed"],
                tactic     = tactic,
                technique  = technique,
                event_host = event.get("host", ""),
                event_user = event.get("user", ""),
                matched_at = datetime.now(timezone.utc).isoformat(),
            ))
    return results


# ── Synthetic Feed + Events ───────────────────────────────────────────────────

SAMPLE_IOCS = [
    ("45.33.32.156",       "ip",     "critical"),
    ("91.220.101.5",       "ip",     "high"),
    ("198.51.100.22",      "ip",     "medium"),
    ("malware.evil.ru",    "domain", "critical"),
    ("phishing-kit.xyz",   "domain", "high"),
    ("update-flash.com",   "domain", "medium"),
    ("https://evil.ru/pay","url",    "high"),
    ("d41d8cd98f00b204e9800998ecf8427e", "md5", "high"),
    ("a" * 64,             "sha256", "critical"),
]

FAKE_EVENTS = [
    {"source": "nginx",  "host": "web01", "user": "anon",
     "raw": "GET http://45.33.32.156/beacon?id=123"},
    {"source": "winlog", "host": "ws22",  "user": "jsmith",
     "raw": "DNS query: malware.evil.ru resolved to 1.2.3.4"},
    {"source": "edr",    "host": "db01",  "user": "root",
     "raw": f"File created hash=d41d8cd98f00b204e9800998ecf8427e"},
    {"source": "proxy",  "host": "ws05",  "user": "bwong",
     "raw": "https://evil.ru/pay?token=abc123"},
    {"source": "syslog", "host": "jump01","user": "akim",
     "raw": "outbound conn to 198.51.100.22:443"},
    {"source": "nginx",  "host": "web01", "user": "anon",
     "raw": "normal GET /index.html 200 OK"},
    {"source": "winlog", "host": "ws11",  "user": "ladmin",
     "raw": "standard login event success"},
]


# ── Main ──────────────────────────────────────────────────────────────────────

async def streaming_match(db: IOCDatabase, duration: float, output_path: Path):
    """Simulate a continuous log stream, matching each event against IOCs."""
    end     = time.time() + duration
    hits    = 0
    checked = 0

    while time.time() < end:
        event = random.choice(FAKE_EVENTS)
        checked += 1
        results = match_event(db, event)

        for r in results:
            hits += 1
            ts  = datetime.now(timezone.utc).strftime("%H:%M:%S")
            sev = r.severity.upper()
            col = "\033[91m" if r.severity == "critical" else "\033[93m"
            print(f"{col}[{ts}] [{sev:8}] {r.technique} | {r.ioc_type:6} {r.ioc_value} "
                  f"| host={r.event_host} user={r.event_user}\033[0m")
            with output_path.open("a") as f:
                f.write(json.dumps(asdict(r)) + "\n")

        await asyncio.sleep(0.1)

    return checked, hits


async def main():
    parser = argparse.ArgumentParser(description="Threat intelligence IOC matcher")
    parser.add_argument("--db",       default="threat_intel.db",
                        help="SQLite database path")
    parser.add_argument("--output",   default="ioc_matches.jsonl",
                        help="Match output file")
    parser.add_argument("--duration", type=float, default=20,
                        help="Stream duration in seconds")
    parser.add_argument("--feed-csv", default=None,
                        help="Optional CSV feed file to import on startup")
    args = parser.parse_args()

    db  = IOCDatabase(args.db)
    out = Path(args.output)

    # Load built-in sample IOCs
    print("[*] Loading sample IOC feed …")
    load_feed_from_list(db, SAMPLE_IOCS, feed_name="sample")

    # Optionally load a CSV feed
    if args.feed_csv and Path(args.feed_csv).exists():
        n = load_feed_from_csv(db, args.feed_csv, feed_name=Path(args.feed_csv).stem)
        print(f"[*] Loaded {n} IOCs from {args.feed_csv}")

    stats = db.stats()
    print(f"[*] IOC database: {stats['total_iocs']} indicators ({stats['by_type']})")
    print(f"[*] Matching log stream for {args.duration}s → {out}\n")

    checked, hits = await streaming_match(db, args.duration, out)

    stats = db.stats()
    print(f"\n[*] Events checked : {checked}")
    print(f"[*] IOC matches    : {hits}")
    print(f"[*] Total matches  : {stats['total_matches']}")
    print(f"[*] Match log      : {out}")

    db.close()


if __name__ == "__main__":
    asyncio.run(main())
