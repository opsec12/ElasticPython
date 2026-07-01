# Timeline Events

## Overview

Simple incident timeline visualizer. Takes multiple log sources from a simulated attack — authentication logs, process-creation logs, and network-connection logs — merges them into a unified chronological view, and plots each event type on its own horizontal track.

## Objective

- Parse multiple log files
- Normalize timestamps
- Merge events into a single ordered timeline
- Plot the timeline using Matplotlib
- Identify suspicious sequences (e.g., login → privilege escalation → outbound beacon)

## Setup

```bash
pip install matplotlib
```

## Quick Start

```python
import matplotlib.pyplot as plt
from datetime import datetime

# Example events (replace with parsed log data)
events = [
    ("auth", "2025-06-01 10:00:01"),
    ("proc", "2025-06-01 10:00:05"),
    ("net",  "2025-06-01 10:00:07"),
]

tracks = {"auth": 0, "proc": 1, "net": 2}

# Convert timestamps
xs = [datetime.strptime(t, "%Y-%m-%d %H:%M:%S") for _, t in events]
ys = [tracks[k] for k, _ in events]

# Plot
plt.scatter(xs, ys, s=120, c=["blue", "orange", "red"])
plt.yticks([0, 1, 2], ["auth", "proc", "net"])
plt.title("Incident Timeline Visualization")
plt.xlabel("Time")
plt.grid(True, linestyle="--", alpha=0.5)
plt.show()
```

## Extending It

### Parsing Real Log Files

Replace the hardcoded `events` list with actual log parsers. Each parser should return `(event_type, timestamp_string)` tuples.

```python
import csv
from datetime import datetime

def parse_auth_log(path):
    events = []
    with open(path) as f:
        for line in f:
            # Adjust field positions to match your log format
            parts = line.split()
            ts = f"{parts[0]} {parts[1]}"
            events.append(("auth", ts))
    return events

def parse_sysmon_csv(path):
    events = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(("proc", row["UtcTime"]))
    return events

# Merge and sort
all_events = parse_auth_log("auth.log") + parse_sysmon_csv("sysmon.csv")
all_events.sort(key=lambda e: datetime.strptime(e[1], "%Y-%m-%d %H:%M:%S"))
```

### Highlighting Suspicious Sequences

Once events are merged in order, scan for attack patterns — a login immediately followed by a privilege escalation command followed by an outbound connection within a short window is a classic indicator.

```python
SUSPICIOUS_SEQUENCE = ["auth", "proc", "net"]
WINDOW_SECONDS = 30

from datetime import timedelta

def find_sequences(events, sequence, window_seconds):
    fmt = "%Y-%m-%d %H:%M:%S"
    hits = []
    for i, (etype, ets) in enumerate(events):
        if etype != sequence[0]:
            continue
        t0 = datetime.strptime(ets, fmt)
        chain = [(etype, ets)]
        remaining = list(sequence[1:])
        for j, (etype2, ets2) in enumerate(events[i+1:], i+1):
            if not remaining:
                break
            t1 = datetime.strptime(ets2, fmt)
            if (t1 - t0).total_seconds() > window_seconds:
                break
            if etype2 == remaining[0]:
                chain.append((etype2, ets2))
                remaining.pop(0)
        if not remaining:
            hits.append(chain)
    return hits

matches = find_sequences(all_events, SUSPICIOUS_SEQUENCE, WINDOW_SECONDS)
for m in matches:
    print("Suspicious sequence detected:")
    for etype, ets in m:
        print(f"  [{etype}] {ets}")
```

### Color-Coding by Severity

```python
COLOR_MAP = {
    "auth": "steelblue",
    "proc": "orange",
    "net":  "crimson",
}

colors = [COLOR_MAP.get(k, "gray") for k, _ in events]
plt.scatter(xs, ys, s=120, c=colors, zorder=5)
```

## Notes

Matplotlib's x-axis handles `datetime` objects natively — no need to convert to epoch floats. If timestamps span multiple days, add `plt.gcf().autofmt_xdate()` to rotate the labels so they don't overlap.

Log sources rarely use the same timestamp format. Normalize everything to `datetime` objects early and keep them as `datetime` throughout — only convert back to strings when writing output. Mixing string comparisons and `datetime` arithmetic is where most bugs in timeline tools come from.
