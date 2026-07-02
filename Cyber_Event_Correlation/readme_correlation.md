# Cyber Security Script

Tools for detection engineering and threat hunting. All run from the command line, output JSONL for SIEM ingestion, and map to MITRE ATT&CK.

---

## log_correlation.py — SIEM Correlation Engine

Ingests structured log events at high throughput and runs sliding-window detection rules to fire alerts. Think Sigma rules but in pure Python with no external dependency on an ELK stack.

**Detection rules included:**

- **BRUTE-001** (T1110) — Credential Access: ≥8 failed auths from the same IP to the same host in 60s
- **LAT-001** (T1021) — Lateral Movement: same user auth-success to ≥3 distinct hosts in 120s
- **PRIVESC-001** (T1548) — Privilege Escalation: successful `sudo`, `runas`, `su`, or `privilege_use`
- **EXFIL-001** (T1048) — Exfiltration: ≥5 outbound upload events to external IPs in 300s

Each rule uses its own sliding deque with automatic expiry. Alerts fire once per threshold breach (counter resets to avoid alert storms). Output goes to a JSONL log with MITRE tactic, technique, affected hosts/users, and timestamp.

**Setup:**
```bash
pip install  # no external dependencies — stdlib only
```

**Run:**
```bash
python log_correlation.py --duration 60 --rate 20 --output alerts.jsonl
```

- `--rate` controls synthetic events per second. In production, swap `_sim_packet()` for your actual log ingestion (Kafka consumer, syslog parser, Splunk forwarder, etc.).
- `--output` is the alert log; pipe it to `jq` or your SIEM.

**Extending it:** Add a new class implementing `evaluate(LogEvent) -> Alert | None` and append it to `CorrelationEngine.rules`. No other changes needed.

---