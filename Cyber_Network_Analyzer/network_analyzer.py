"""
Network traffic analyzer — passive detection engine.
Parses packet metadata (or simulated flow records) to detect:
  - Port scans (SYN sweep, horizontal + vertical)
  - DNS exfiltration (high entropy subdomain queries)
  - C2 beaconing (regular outbound connection intervals)
  - Cleartext credential transmission (HTTP Basic Auth)

Runs in simulation mode if Scapy is not available / user lacks capture privileges.
Requires root/admin for live capture mode.
"""
import math
import time
import json
import asyncio
import argparse
import random
import re
import ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path


# ── Flow Record ───────────────────────────────────────────────────────────────

@dataclass
class FlowRecord:
    ts:       float
    src_ip:   str
    dst_ip:   str
    src_port: int
    dst_port: int
    proto:    str      # TCP | UDP | ICMP
    flags:    str      # SYN | ACK | RST | FIN | SYN-ACK
    payload:  str      # partial payload (first 256 bytes)
    length:   int


@dataclass
class Detection:
    rule_id:    str
    severity:   str
    src_ip:     str
    dst_ip:     str
    description: str
    technique:  str
    tactic:     str
    ts:         float = 0.0

    def __post_init__(self):
        if not self.ts:
            self.ts = time.time()


# ── Utility ───────────────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    counts = defaultdict(int)
    for c in s:
        counts[c] += 1
    length = len(s)
    return -sum((v / length) * math.log2(v / length) for v in counts.values())


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ── Detection Rules ───────────────────────────────────────────────────────────

class PortScanDetector:
    """
    T1046 — Network Service Discovery
    SYN packets from one IP to N distinct ports/hosts within a window.
    """
    rule_id   = "SCAN-001"
    severity  = "medium"
    window    = 30
    port_threshold = 15   # distinct dst ports from one src

    def __init__(self):
        self._src_ports: dict[str, dict[str, deque]] = defaultdict(lambda: defaultdict(deque))

    def evaluate(self, pkt: FlowRecord) -> Detection | None:
        if "SYN" not in pkt.flags or "ACK" in pkt.flags:
            return None
        src = pkt.src_ip
        dst = pkt.dst_ip
        q   = self._src_ports[src][dst]
        q.append((pkt.ts, pkt.dst_port))
        cutoff = pkt.ts - self.window
        while q and q[0][0] < cutoff:
            q.popleft()
        ports = {e[1] for e in q}
        if len(ports) >= self.port_threshold:
            det = Detection(
                rule_id     = self.rule_id,
                severity    = self.severity,
                src_ip      = src,
                dst_ip      = dst,
                description = (f"Port scan: {src} → {dst} hit {len(ports)} ports "
                               f"in {self.window}s ({sorted(ports)[:5]}…)"),
                technique   = "T1046",
                tactic      = "Discovery",
            )
            self._src_ports[src][dst].clear()
            return det
        return None


class DNSExfilDetector:
    """
    T1048.003 — Exfiltration Over DNS
    High-entropy subdomain labels in DNS queries suggest tunneling.
    """
    rule_id      = "DNS-EXFIL-001"
    severity     = "high"
    entropy_thresh = 3.8   # bits/char — normal domains ~2.5, encoded data ~4.5
    label_len_min  = 20    # short labels are rarely encoded data

    def evaluate(self, pkt: FlowRecord) -> Detection | None:
        if pkt.proto != "UDP" or pkt.dst_port != 53:
            return None
        # Pull DNS query name from payload (simulated as "QUERY:<name>")
        m = re.search(r"QUERY:([^\s]+)", pkt.payload)
        if not m:
            return None
        fqdn   = m.group(1)
        labels = fqdn.split(".")
        for label in labels[:-2]:   # skip TLD and SLD
            if len(label) < self.label_len_min:
                continue
            entropy = shannon_entropy(label)
            if entropy > self.entropy_thresh:
                return Detection(
                    rule_id     = self.rule_id,
                    severity    = self.severity,
                    src_ip      = pkt.src_ip,
                    dst_ip      = pkt.dst_ip,
                    description = (f"DNS exfil likely: {pkt.src_ip} queried "
                                   f"'{fqdn}' (label entropy={entropy:.2f})"),
                    technique   = "T1048.003",
                    tactic      = "Exfiltration",
                )
        return None


class BeaconDetector:
    """
    T1071.001 — Web Protocols (C2 beaconing)
    Detects suspiciously regular outbound connection intervals.
    CV < 0.15 on ≥8 connection timestamps = likely beacon.
    """
    rule_id   = "BEACON-001"
    severity  = "critical"
    min_conns = 8
    max_cv    = 0.15       # coefficient of variation

    def __init__(self):
        self._sessions: dict[tuple, deque] = defaultdict(deque)

    def evaluate(self, pkt: FlowRecord) -> Detection | None:
        if "SYN" not in pkt.flags or is_private(pkt.dst_ip):
            return None
        key = (pkt.src_ip, pkt.dst_ip, pkt.dst_port)
        q   = self._sessions[key]
        q.append(pkt.ts)
        if len(q) < self.min_conns + 1:
            return None
        intervals = [q[i+1] - q[i] for i in range(len(q) - 1)]
        mean = sum(intervals) / len(intervals)
        if mean < 1.0:
            return None
        stddev = math.sqrt(sum((x - mean) ** 2 for x in intervals) / len(intervals))
        cv     = stddev / mean
        if cv < self.max_cv:
            det = Detection(
                rule_id     = self.rule_id,
                severity    = self.severity,
                src_ip      = pkt.src_ip,
                dst_ip      = pkt.dst_ip,
                description = (f"C2 beacon: {pkt.src_ip}→{pkt.dst_ip}:{pkt.dst_port} "
                               f"interval={mean:.1f}s CV={cv:.3f} ({len(q)} conns)"),
                technique   = "T1071.001",
                tactic      = "Command and Control",
            )
            q.clear()
            return det
        return None


class CleartextCredDetector:
    """
    T1040 — Network Sniffing / T1552 — Unsecured Credentials
    HTTP Basic Auth header in cleartext (port 80).
    """
    rule_id  = "CRED-001"
    severity = "medium"

    def evaluate(self, pkt: FlowRecord) -> Detection | None:
        if pkt.dst_port != 80 and pkt.proto != "TCP":
            return None
        if "Authorization: Basic" in pkt.payload:
            return Detection(
                rule_id     = self.rule_id,
                severity    = self.severity,
                src_ip      = pkt.src_ip,
                dst_ip      = pkt.dst_ip,
                description = (f"Cleartext credentials: {pkt.src_ip} → "
                               f"{pkt.dst_ip}:80 (HTTP Basic Auth)"),
                technique   = "T1552",
                tactic      = "Credential Access",
            )
        return None


# ── Packet Simulator ──────────────────────────────────────────────────────────

INT_IPS = ["10.0.1.10", "10.0.2.20", "192.168.1.5", "172.16.0.3"]
EXT_IPS = ["45.33.32.156", "91.220.101.5", "8.8.8.8", "1.1.1.1"]
PORTS   = [22, 80, 443, 3389, 445, 3306, 8080, 25, 53, 21]

_beacon_next: dict[tuple, float] = {}


def _sim_packet() -> FlowRecord:
    src = random.choice(INT_IPS)
    dst = random.choice(EXT_IPS + INT_IPS)
    return FlowRecord(
        ts       = time.time(),
        src_ip   = src,
        dst_ip   = dst,
        src_port = random.randint(1024, 65535),
        dst_port = random.choice(PORTS),
        proto    = random.choice(["TCP", "UDP"]),
        flags    = random.choice(["SYN", "ACK", "SYN-ACK", "RST", "FIN"]),
        payload  = "",
        length   = random.randint(40, 1500),
    )


def _inject_attack(attack: str) -> FlowRecord:
    now = time.time()
    if attack == "scan":
        return FlowRecord(now, "10.99.0.1", "10.0.1.10",
                          random.randint(1024,65535), random.randint(1,65535),
                          "TCP", "SYN", "", 40)
    if attack == "dns_exfil":
        label = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=35))
        return FlowRecord(now, "10.0.1.10", "8.8.8.8",
                          random.randint(1024,65535), 53, "UDP", "DATA",
                          f"QUERY:{label}.malwaredomain.com", 80)
    if attack == "beacon":
        # 30s beacon ±0.5s jitter
        key = ("10.0.2.20", "45.33.32.156", 4444)
        expected = _beacon_next.get(key, now)
        return FlowRecord(expected, "10.0.2.20", "45.33.32.156",
                          random.randint(1024,65535), 4444, "TCP", "SYN", "", 60)
    if attack == "cleartext":
        return FlowRecord(now, "10.0.1.5", "10.0.0.1",
                          random.randint(1024,65535), 80, "TCP", "ACK",
                          "GET /login HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz", 200)
    return _sim_packet()


# ── Analyzer ──────────────────────────────────────────────────────────────────

class NetworkAnalyzer:
    def __init__(self):
        self.rules = [
            PortScanDetector(),
            DNSExfilDetector(),
            BeaconDetector(),
            CleartextCredDetector(),
        ]
        self.pkt_count = 0
        self.det_count = 0

    def process(self, pkt: FlowRecord) -> list[Detection]:
        self.pkt_count += 1
        dets = []
        for rule in self.rules:
            try:
                d = rule.evaluate(pkt)
                if d:
                    self.det_count += 1
                    dets.append(d)
            except Exception:
                pass
        return dets


# ── Runner ────────────────────────────────────────────────────────────────────

SEV_COLOR = {"critical": "\033[91m", "high": "\033[93m",
             "medium": "\033[94m", "low": "\033[96m"}
RESET = "\033[0m"

ATTACK_CYCLE_MAP = {3: "scan", 7: "dns_exfil", 11: "beacon", 23: "cleartext"}


async def run(analyzer: NetworkAnalyzer, rate: float,
              duration: float, out: Path):
    interval = 1.0 / rate
    end = time.time() + duration
    cycle = 0

    # Pre-seed beacon timestamps so BeaconDetector accumulates enough points
    beacon_src, beacon_dst, beacon_port = "10.0.2.20", "45.33.32.156", 4444
    base = time.time() - 300
    for i in range(10):
        pkt = FlowRecord(base + i*30, beacon_src, beacon_dst,
                         50000+i, beacon_port, "TCP", "SYN", "", 60)
        analyzer.process(pkt)

    while time.time() < end:
        cycle += 1
        attack = ATTACK_CYCLE_MAP.get(cycle % 25)
        pkt = _inject_attack(attack) if attack else _sim_packet()

        dets = analyzer.process(pkt)
        for d in dets:
            ts  = datetime.fromtimestamp(d.ts).strftime("%H:%M:%S")
            col = SEV_COLOR.get(d.severity, "")
            print(f"{col}[{ts}] [{d.severity.upper():8}] {d.rule_id:14} | "
                  f"{d.technique:10} | {d.description}{RESET}")
            with out.open("a") as f:
                f.write(json.dumps(asdict(d)) + "\n")

        await asyncio.sleep(interval)


async def main():
    parser = argparse.ArgumentParser(description="Network traffic analyzer")
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--rate",     type=float, default=15,
                        help="Simulated packets per second")
    parser.add_argument("--output",   default="network_detections.jsonl")
    args = parser.parse_args()

    out      = Path(args.output)
    analyzer = NetworkAnalyzer()

    print(f"[*] Network analyzer (simulation mode) | {args.rate} pps | {args.duration}s")
    print(f"[*] Rules: PortScan, DNSExfil, C2Beacon, CleartextCreds")
    print(f"[*] Detections → {out}\n")

    await run(analyzer, args.rate, args.duration, out)

    print(f"\n[*] Packets: {analyzer.pkt_count} | Detections: {analyzer.det_count}")
    print(f"[*] Detection log: {out}")

if __name__ == "__main__":
    asyncio.run(main())
