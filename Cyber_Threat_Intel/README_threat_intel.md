# Threat Intelligence IOC Matcher

Downloads, stores, and matches threat intelligence indicators against a live log stream. The database is SQLite so it runs anywhere without a server.

## What it does

- Maintains an IOC database (IP, domain, URL, SHA256, MD5) with TTL-based expiry
- Extracts observables from free-text log fields using regex — IPs, domains, URLs, hashes
- Matches each event's observables against the database
- Tags matches with MITRE technique and writes to a JSONL match log
- Tracks hit counts separately from the IOC table so you can query which indicators fired the most

## Setup

```bash
pip install  # stdlib only — sqlite3 is built-in
```

## Run it

```bash
python threat_intel.py --duration 30 --output ioc_matches.jsonl
```

Import your own feed CSV at startup:

```bash
python threat_intel.py --feed-csv misp_export.csv
```

## Options

| Flag | Default | What it does |
|------|---------|--------------|
| `--db` | threat_intel.db | SQLite database path |
| `--output` | ioc_matches.jsonl | Match output file |
| `--duration` | 20 | Stream duration in seconds |
| `--feed-csv` | None | CSV feed file to import on startup |

## Feed ingestion

The sample feed is hardcoded for demonstration. For production, call `load_feed_from_csv()` with an abuse.ch CSV, a MISP export, or any CSV with `indicator`, `type`, and `severity` columns.

```python
load_feed_from_csv(db, "misp_export.csv", feed_name="misp")
```

`fetch_feed_url()` handles downloading plaintext feeds over HTTP if you want to pull from a remote source directly. Set a cron job or scheduled task to refresh feeds on a schedule — IOCs expire after 30 days by default (configurable via `ttl_days`).

## Output

Console prints each IOC hit in real time:

```
[CRITICAL] T1071  | ip     45.33.32.156 | host=web01 user=anon
[HIGH    ] T1071  | domain malware.evil.ru | host=ws22 user=jsmith
```

`ioc_matches.jsonl` has one JSON object per line with IOC value, type, severity, feed source, MITRE tactic/technique, matched host, matched user, and timestamp.

## Notes

IOC expiry is checked at query time against the `expires_at` field — no background cleanup job needed. Expired indicators stay in the database and can be queried directly if you need historical data.

Observable extraction runs regex over the full JSON-serialized event, so it catches IPs and domains buried in nested fields without you having to specify field paths per log source.
