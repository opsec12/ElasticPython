"""
Incident timeline visualizer.
Merges auth, process-creation, and network-connection log events
into a unified chronological plot and flags suspicious attack sequences.
"""

import csv
import json
import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    import matplotlib.patches as mpatches
    HAS_MPL = True
except ImportError:
    HAS_MPL = False


# ── Event Model ───────────────────────────────────────────────────────────────

TRACK_ORDER = ["auth", "proc", "net"]

TRACK_LABELS = {
    "auth": "Authentication",
    "proc": "Process Creation",
    "net":  "Network Connection",
}

COLOR_MAP = {
    "auth": "steelblue",
    "proc": "darkorange",
    "net":  "crimson",
}

MARKER_MAP = {
    "auth": "o",
    "proc": "s",
    "net":  "^",
}

# Event subtypes for richer labeling
SUBTYPE_COLOR = {
    "login_success":   "steelblue",
    "login_failure":   "royalblue",
    "sudo":            "purple",
    "cmd_exec":        "darkorange",
    "powershell":      "orangered",
    "proc_inject":     "red",
    "dns_query":       "salmon",
    "outbound_http":   "crimson",
    "outbound_https":  "darkred",
}


# ── Log Parsers ───────────────────────────────────────────────────────────────

TS_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%d/%b/%Y:%H:%M:%S",
    "%b %d %H:%M:%S",
]


def parse_timestamp(ts_str: str) -> datetime | None:
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(ts_str.strip(), fmt)
        except ValueError:
            continue
    return None


def parse_auth_log(path: str) -> list[tuple]:
    """
    Parse /var/log/auth.log style or CSV with columns:
    timestamp, user, src_ip, action, outcome
    """
    events = []
    p = Path(path)
    if not p.exists():
        return events
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = parse_timestamp(row.get("timestamp", ""))
            if not ts:
                continue
            subtype = ("login_failure" if row.get("outcome","").lower() == "failure"
                       else "sudo" if row.get("action","").lower() in ("sudo","su","runas")
                       else "login_success")
            events.append({
                "ts":      ts,
                "track":   "auth",
                "subtype": subtype,
                "label":   f"{row.get('action','')} {row.get('user','')} "
                           f"from {row.get('src_ip','')}",
                "raw":     dict(row),
            })
    return events


def parse_process_log(path: str) -> list[tuple]:
    """
    Parse Sysmon EventID 1 CSV or custom process creation log.
    Expected columns: timestamp, hostname, image, commandline, parent_image
    """
    events = []
    p = Path(path)
    if not p.exists():
        return events
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = parse_timestamp(row.get("timestamp", ""))
            if not ts:
                continue
            image = row.get("image", "").lower()
            cmd   = row.get("commandline", "").lower()
            if "powershell" in image or "powershell" in cmd:
                subtype = "powershell"
            elif any(x in cmd for x in ("inject", "mavinject", "hollowing")):
                subtype = "proc_inject"
            else:
                subtype = "cmd_exec"
            events.append({
                "ts":      ts,
                "track":   "proc",
                "subtype": subtype,
                "label":   f"{Path(image).name} — {cmd[:60]}",
                "raw":     dict(row),
            })
    return events


def parse_network_log(path: str) -> list[tuple]:
    """
    Parse Sysmon EventID 3 or firewall log CSV.
    Expected columns: timestamp, src_ip, dst_ip, dst_port, protocol, direction
    """
    events = []
    p = Path(path)
    if not p.exists():
        return events
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = parse_timestamp(row.get("timestamp", ""))
            if not ts:
                continue
            port = int(row.get("dst_port", 0) or 0)
            if port == 53:
                subtype = "dns_query"
            elif port == 443:
                subtype = "outbound_https"
            else:
                subtype = "outbound_http"
            events.append({
                "ts":      ts,
                "track":   "net",
                "subtype": subtype,
                "label":   (f"{row.get('src_ip','')} → {row.get('dst_ip','')}:"
                            f"{row.get('dst_port','')} ({row.get('protocol','')})"),
                "raw":     dict(row),
            })
    return events


def parse_json_log(path: str) -> list[dict]:
    """
    Generic JSON log: each line is a JSON object with at minimum
    'timestamp', 'track' (auth|proc|net), and 'label' fields.
    """
    events = []
    p = Path(path)
    if not p.exists():
        return events
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = parse_timestamp(obj.get("timestamp", ""))
            if not ts or obj.get("track") not in TRACK_ORDER:
                continue
            obj["ts"] = ts
            events.append(obj)
    return events


# ── Sequence Detector ─────────────────────────────────────────────────────────

ATTACK_SEQUENCES = [
    {
        "name":    "Login → PrivEsc → Beacon",
        "tracks":  ["auth", "proc", "net"],
        "subtypes":["login_success", "sudo", "outbound_http"],
        "window":  60,
        "severity":"critical",
        "technique":"T1078 → T1548 → T1071",
    },
    {
        "name":    "Failed Logins → Success (Brute Force)",
        "tracks":  ["auth", "auth", "auth"],
        "subtypes":["login_failure", "login_failure", "login_success"],
        "window":  120,
        "severity":"high",
        "technique":"T1110",
    },
    {
        "name":    "Process Creation → Outbound Network",
        "tracks":  ["proc", "net"],
        "subtypes":["powershell", "outbound_https"],
        "window":  30,
        "severity":"high",
        "technique":"T1059.001 → T1071.001",
    },
    {
        "name":    "PowerShell → Process Injection → Beacon",
        "tracks":  ["proc", "proc", "net"],
        "subtypes":["powershell", "proc_inject", "outbound_http"],
        "window":  60,
        "severity":"critical",
        "technique":"T1059.001 → T1055 → T1071",
    },
]


def find_sequences(events: list[dict]) -> list[dict]:
    """
    Scan the sorted event list for known attack sequence patterns.
    Returns a list of match dicts with the matching events and sequence metadata.
    """
    matches = []
    n = len(events)

    for seq in ATTACK_SEQUENCES:
        required_tracks  = seq["tracks"]
        required_types   = seq["subtypes"]
        window           = seq["window"]

        for i in range(n):
            e0 = events[i]
            if (e0["track"] != required_tracks[0] or
                    e0.get("subtype") != required_types[0]):
                continue

            chain = [e0]
            remaining_tracks = required_tracks[1:]
            remaining_types  = required_types[1:]
            t0 = e0["ts"]

            for j in range(i + 1, n):
                if not remaining_tracks:
                    break
                ej = events[j]
                if (ej["ts"] - t0).total_seconds() > window:
                    break
                if (ej["track"] == remaining_tracks[0] and
                        ej.get("subtype") == remaining_types[0]):
                    chain.append(ej)
                    remaining_tracks.pop(0)
                    remaining_types.pop(0)

            if not remaining_tracks:
                matches.append({
                    "sequence": seq["name"],
                    "severity": seq["severity"],
                    "technique": seq["technique"],
                    "events": chain,
                    "start": chain[0]["ts"],
                    "end":   chain[-1]["ts"],
                })

    # Deduplicate by start time + sequence name
    seen = set()
    deduped = []
    for m in matches:
        key = (m["sequence"], m["start"])
        if key not in seen:
            seen.add(key)
            deduped.append(m)

    return deduped


# ── Simulator ─────────────────────────────────────────────────────────────────

def generate_mock_events(base_time: datetime | None = None) -> list[dict]:
    """Generate a realistic simulated incident timeline."""
    if base_time is None:
        base_time = datetime(2025, 6, 1, 10, 0, 0)

    def t(delta_s): return base_time + timedelta(seconds=delta_s)

    events = [
        # Recon / brute force
        {"ts": t(0),   "track": "auth", "subtype": "login_failure",
         "label": "SSH login failure — jsmith from 45.33.32.156"},
        {"ts": t(3),   "track": "auth", "subtype": "login_failure",
         "label": "SSH login failure — jsmith from 45.33.32.156"},
        {"ts": t(7),   "track": "auth", "subtype": "login_failure",
         "label": "SSH login failure — jsmith from 45.33.32.156"},
        {"ts": t(12),  "track": "auth", "subtype": "login_success",
         "label": "SSH login SUCCESS — jsmith from 45.33.32.156"},

        # Initial access → discovery
        {"ts": t(18),  "track": "proc", "subtype": "cmd_exec",
         "label": "whoami — /usr/bin/whoami"},
        {"ts": t(20),  "track": "proc", "subtype": "cmd_exec",
         "label": "id — /usr/bin/id"},
        {"ts": t(25),  "track": "net",  "subtype": "dns_query",
         "label": "10.0.1.15 → 8.8.8.8:53 (DNS) evil.c2.ru"},

        # Privilege escalation
        {"ts": t(35),  "track": "auth", "subtype": "sudo",
         "label": "sudo bash — jsmith → root on web01"},
        {"ts": t(38),  "track": "proc", "subtype": "cmd_exec",
         "label": "bash — /bin/bash (root shell)"},

        # Payload delivery
        {"ts": t(45),  "track": "net",  "subtype": "outbound_http",
         "label": "10.0.1.15 → 45.33.32.156:80 (TCP) GET /payload.sh"},
        {"ts": t(48),  "track": "proc", "subtype": "powershell",
         "label": "python3 — exec(urllib.request.urlopen(...).read())"},

        # Lateral movement
        {"ts": t(60),  "track": "net",  "subtype": "outbound_http",
         "label": "10.0.1.15 → 10.0.2.30:22 (SSH) lateral move"},
        {"ts": t(63),  "track": "auth", "subtype": "login_success",
         "label": "SSH login SUCCESS — root from 10.0.1.15 (lateral)"},

        # Process injection
        {"ts": t(75),  "track": "proc", "subtype": "proc_inject",
         "label": "ptrace inject — PID 1234 (sshd)"},

        # C2 beacon
        {"ts": t(90),  "track": "net",  "subtype": "outbound_https",
         "label": "10.0.2.30 → 91.220.101.5:443 (C2 beacon)"},
        {"ts": t(120), "track": "net",  "subtype": "outbound_https",
         "label": "10.0.2.30 → 91.220.101.5:443 (C2 beacon)"},
        {"ts": t(150), "track": "net",  "subtype": "outbound_https",
         "label": "10.0.2.30 → 91.220.101.5:443 (C2 beacon)"},

        # Exfiltration
        {"ts": t(180), "track": "net",  "subtype": "outbound_http",
         "label": "10.0.2.30 → 198.51.100.5:80 POST /upload (exfil 4.2MB)"},
    ]

    return events


# ── Plotter ───────────────────────────────────────────────────────────────────

def plot_timeline(events: list[dict], matches: list[dict],
                  output_path: str | None = None):
    if not HAS_MPL:
        print("[!] matplotlib not installed: pip install matplotlib")
        return

    fig, ax = plt.subplots(figsize=(16, 5))
    fig.patch.set_facecolor("#0d0d0d")
    ax.set_facecolor("#0d0d0d")

    track_y = {t: i for i, t in enumerate(TRACK_ORDER)}

    # Plot each event
    for ev in events:
        y       = track_y.get(ev["track"], 0)
        color   = SUBTYPE_COLOR.get(ev.get("subtype",""), COLOR_MAP.get(ev["track"],"gray"))
        marker  = MARKER_MAP.get(ev["track"], "o")
        ax.scatter(ev["ts"], y, s=140, c=color, marker=marker,
                   zorder=5, edgecolors="white", linewidths=0.5)
        ax.annotate(
            ev.get("label","")[:55],
            (ev["ts"], y),
            xytext=(0, 14), textcoords="offset points",
            fontsize=6.5, color="#cccccc", ha="center", rotation=30,
        )

    # Highlight matched sequences
    SEV_COLORS = {"critical": "#ff4444", "high": "#ffaa00", "medium": "#44aaff"}
    for m in matches:
        col  = SEV_COLORS.get(m["severity"], "yellow")
        t0   = mdates.date2num(m["start"])
        t1   = mdates.date2num(m["end"])
        span = t1 - t0 + 0.0005
        ax.axvspan(m["start"] - timedelta(seconds=2),
                   m["end"]   + timedelta(seconds=2),
                   alpha=0.12, color=col, zorder=1)
        ax.annotate(
            f"⚠ {m['sequence']}\n{m['technique']}",
            xy=(m["start"], len(TRACK_ORDER) - 0.55),
            fontsize=7, color=col, fontweight="bold",
            bbox=dict(boxstyle="round,pad=0.3", fc="#1a1a1a", ec=col, lw=1),
        )

    # Axes formatting
    ax.set_yticks(range(len(TRACK_ORDER)))
    ax.set_yticklabels([TRACK_LABELS[t] for t in TRACK_ORDER],
                       color="white", fontsize=10)
    ax.tick_params(colors="white")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    ax.xaxis.set_major_locator(mdates.AutoDateLocator())
    plt.setp(ax.get_xticklabels(), rotation=25, ha="right",
             color="white", fontsize=8)

    for spine in ax.spines.values():
        spine.set_edgecolor("#333333")

    ax.set_ylim(-0.7, len(TRACK_ORDER) - 0.3)
    ax.grid(True, linestyle="--", alpha=0.2, color="#555555", axis="x")

    # Legend
    legend_handles = [
        mpatches.Patch(color=COLOR_MAP[t], label=TRACK_LABELS[t])
        for t in TRACK_ORDER
    ]
    if matches:
        legend_handles.append(
            mpatches.Patch(color="#ff4444", alpha=0.5, label="Attack Sequence"))
    ax.legend(handles=legend_handles, loc="lower right",
              facecolor="#1a1a1a", edgecolor="#444444",
              labelcolor="white", fontsize=8)

    ax.set_title("Incident Timeline Visualization", color="white",
                 fontsize=13, pad=12)
    ax.set_xlabel("Time (UTC)", color="white", fontsize=9)

    plt.tight_layout()

    if output_path:
        plt.savefig(output_path, dpi=150, bbox_inches="tight",
                    facecolor=fig.get_facecolor())
        print(f"[*] Plot saved → {output_path}")
    else:
        plt.show()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Incident timeline visualizer")
    parser.add_argument("--auth",    default=None, help="Auth log CSV")
    parser.add_argument("--proc",    default=None, help="Process log CSV")
    parser.add_argument("--net",     default=None, help="Network log CSV")
    parser.add_argument("--json",    default=None, help="Generic JSON log (JSONL)")
    parser.add_argument("--output",  default=None,
                        help="Save plot to file (e.g. timeline.png) instead of displaying")
    parser.add_argument("--mock",    action="store_true",
                        help="Use built-in simulated incident data")
    parser.add_argument("--no-plot", action="store_true",
                        help="Print events and detections to console only")
    args = parser.parse_args()

    # Load events
    all_events: list[dict] = []

    if args.mock or not any([args.auth, args.proc, args.net, args.json]):
        print("[*] Using simulated incident data (--mock)")
        all_events = generate_mock_events()
    else:
        if args.auth:
            all_events += parse_auth_log(args.auth)
        if args.proc:
            all_events += parse_process_log(args.proc)
        if args.net:
            all_events += parse_network_log(args.net)
        if args.json:
            all_events += parse_json_log(args.json)

    if not all_events:
        print("[!] No events loaded. Use --mock or provide log file paths.")
        return

    # Sort by timestamp
    all_events.sort(key=lambda e: e["ts"])

    print(f"\n[*] {len(all_events)} events loaded\n")
    print(f"  {'Time':<22} {'Track':<6} {'Subtype':<18} {'Label'}")
    print(f"  {'─'*80}")
    for ev in all_events:
        print(f"  {ev['ts'].strftime('%Y-%m-%d %H:%M:%S'):<22} "
              f"{ev['track']:<6} {ev.get('subtype',''):<18} "
              f"{ev.get('label','')[:50]}")

    # Detect attack sequences
    matches = find_sequences(all_events)

    if matches:
        print(f"\n[!] {len(matches)} suspicious sequence(s) detected:\n")
        for m in matches:
            print(f"  [{m['severity'].upper():8}] {m['sequence']}")
            print(f"             Technique : {m['technique']}")
            print(f"             Window    : {m['start'].strftime('%H:%M:%S')} → "
                  f"{m['end'].strftime('%H:%M:%S')}")
            for ev in m["events"]:
                print(f"             ├─ [{ev['track']}] {ev['ts'].strftime('%H:%M:%S')} "
                      f"{ev.get('label','')[:55]}")
            print()
    else:
        print("\n[+] No known attack sequences detected.")

    if not args.no_plot:
        plot_timeline(all_events, matches, output_path=args.output)


if __name__ == "__main__":
    main()
