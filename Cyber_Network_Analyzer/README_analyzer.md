## cyber_03_network_analyzer.py — Passive Network Detection

Analyzes packet metadata (simulated flow records, or live via Scapy) to detect network-layer attack patterns. No deep packet inspection required — works on TCP metadata + limited payload inspection.

**Detection rules:**

- **SCAN-001** (T1046) — Port scan: ≥15 SYN packets from one IP to distinct ports in 30s
- **DNS-EXFIL-001** (T1048.003) — DNS tunneling: subdomain label Shannon entropy > 3.8 bits/char over 20-char labels
- **BEACON-001** (T1071.001) — C2 beaconing: coefficient of variation on connection intervals < 0.15 across ≥8 connections to the same external endpoint
- **CRED-001** (T1552) — Cleartext credentials: `Authorization: Basic` header on port 80

The beacon detector is the interesting one — regular beacons have low timing variance even with jitter. CV < 0.15 catches most commercial C2 frameworks without too many false positives from cron jobs (which typically have CV ≈ 0).

**Setup:**
```bash
pip install  # stdlib only for simulation mode
pip install scapy  # for live capture (requires root/admin)
```

**Run:**
```bash
# Simulation (no privileges needed)
python cyber_03_network_analyzer.py --duration 30 --rate 15

# Output
python cyber_03_network_analyzer.py --output network_detections.jsonl
```

Live capture mode: swap `_sim_packet()` for a Scapy `sniff()` callback feeding a `FlowRecord`. The detection engine is protocol-agnostic.
