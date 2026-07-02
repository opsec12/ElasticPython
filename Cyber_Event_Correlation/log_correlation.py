"""
SIEM-style log correlation engine.
Ingests structured log events, runs sliding-window detection rules,
fires MITRE ATT&CK-tagged alerts to a JSONL log.
"""

import json
import time
import asyncio
import argparse
import random
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path


# ── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class LogEvent:
    timestamp: float
    source: str       # syslog | winlog | nginx | vpn
    host: str
    user: str
    src_ip: str
    action: str
    outcome: str      # success | failure
    raw: str


@dataclass
class Alert:
    rule_id: str
    severity: str     # critical | high | medium | low
    description: str
    hosts: list
    users: list
    src_ips: list
    events_count: int
    fired_at: float = field(default_factory=time.time)
    mitre_tactic: str = ""
    mitre_technique: str = ""


# ── Detection Rules ───────────────────────────────────────────────────────────

class BruteForceRule:
    """
    T1110 — Brute Force
    >N failed auths from the same src_ip to the same host within a time window.
    """
    rule_id   = "BRUTE-001"
    severity  = "high"
    window    = 60
    threshold = 8

    def __init__(self):
        self._buckets: dict[tuple, deque] = defaultdict(deque)

    def evaluate(self, event: LogEvent) -> Alert | None:
        if event.action not in ("auth", "login", "ssh", "smb") or event.outcome != "failure":
            return None
        key = (event.src_ip, event.host)
        q   = self._buckets[key]
        q.append(event.timestamp)
        cutoff = event.timestamp - self.window
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= self.threshold:
            a = Alert(
                rule_id        = self.rule_id,
                severity       = self.severity,
                description    = (f"{len(q)} failed auths from {event.src_ip} "
                                  f"to {event.host} in {self.window}s"),
                hosts          = [event.host],
                users          = [event.user],
                src_ips        = [event.src_ip],
                events_count   = len(q),
                mitre_tactic   = "Credential Access",
                mitre_technique= "T1110",
            )
            self._buckets[key].clear()
            return a
        return None


class LateralMovementRule:
    """
    T1021 — Remote Services
    Same user auth-success to >N distinct hosts within a time window.
    """
    rule_id   = "LAT-001"
    severity  = "high"
    window    = 120
    threshold = 3

    def __init__(self):
        self._user_events: dict[str, deque] = defaultdict(deque)

    def evaluate(self, event: LogEvent) -> Alert | None:
        if event.action not in ("auth", "login", "rdp", "ssh", "smb") or event.outcome != "success":
            return None
        q = self._user_events[event.user]
        q.append((event.timestamp, event.host, event.src_ip))
        cutoff = event.timestamp - self.window
        while q and q[0][0] < cutoff:
            q.popleft()
        hosts = {e[1] for e in q}
        if len(hosts) >= self.threshold:
            a = Alert(
                rule_id        = self.rule_id,
                severity       = self.severity,
                description    = (f"{event.user} authenticated to {len(hosts)} hosts "
                                  f"in {self.window}s: {', '.join(hosts)}"),
                hosts          = list(hosts),
                users          = [event.user],
                src_ips        = list({e[2] for e in q}),
                events_count   = len(q),
                mitre_tactic   = "Lateral Movement",
                mitre_technique= "T1021",
            )
            self._user_events[event.user].clear()
            return a
        return None


class PrivilegeEscalationRule:
    """
    T1548 — Abuse Elevation Control Mechanism
    Detects successful use of privilege-escalation commands.
    """
    rule_id    = "PRIVESC-001"
    severity   = "critical"
    priv_cmds  = {"sudo", "runas", "su", "privilege_use", "secevent_priv"}

    def evaluate(self, event: LogEvent) -> Alert | None:
        if event.action.lower() in self.priv_cmds and event.outcome == "success":
            return Alert(
                rule_id        = self.rule_id,
                severity       = self.severity,
                description    = (f"{event.user} executed '{event.action}' "
                                  f"on {event.host} from {event.src_ip}"),
                hosts          = [event.host],
                users          = [event.user],
                src_ips        = [event.src_ip],
                events_count   = 1,
                mitre_tactic   = "Privilege Escalation",
                mitre_technique= "T1548",
            )
        return None


class DataExfilRule:
    """
    T1048 — Exfiltration Over Alternative Protocol
    Detects high-volume outbound transfers from internal hosts to external IPs.
    Proxy: counts large http_upload events to non-RFC1918 destinations.
    """
    rule_id   = "EXFIL-001"
    severity  = "critical"
    window    = 300   # 5 minutes
    threshold = 5

    def __init__(self):
        self._buckets: dict[tuple, deque] = defaultdict(deque)

    @staticmethod
    def _is_external(ip: str) -> bool:
        private = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                   "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                   "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                   "127.", "169.254.")
        return not any(ip.startswith(p) for p in private)

    def evaluate(self, event: LogEvent) -> Alert | None:
        if event.action not in ("http_upload", "ftp_put", "sftp_put", "dns_txt_query"):
            return None
        if not self._is_external(event.src_ip):
            return None
        key = (event.host, event.src_ip)
        q   = self._buckets[key]
        q.append(event.timestamp)
        cutoff = event.timestamp - self.window
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= self.threshold:
            a = Alert(
                rule_id        = self.rule_id,
                severity       = self.severity,
                description    = (f"Possible exfil: {event.host} → {event.src_ip} "
                                  f"({len(q)} transfers in {self.window}s)"),
                hosts          = [event.host],
                users          = [event.user],
                src_ips        = [event.src_ip],
                events_count   = len(q),
                mitre_tactic   = "Exfiltration",
                mitre_technique= "T1048",
            )
            self._buckets[key].clear()
            return a
        return None


# ── Correlation Engine ────────────────────────────────────────────────────────

class CorrelationEngine:
    def __init__(self, alert_log: Path):
        self.rules = [
            BruteForceRule(),
            LateralMovementRule(),
            PrivilegeEscalationRule(),
            DataExfilRule(),
        ]
        self.alert_log   = alert_log
        self.total_events = 0
        self.total_alerts = 0

    def process(self, event: LogEvent) -> list[Alert]:
        self.total_events += 1
        alerts = []
        for rule in self.rules:
            try:
                alert = rule.evaluate(event)
            except Exception:
                continue
            if alert:
                self.total_alerts += 1
                alerts.append(alert)
                with self.alert_log.open("a") as f:
                    f.write(json.dumps(asdict(alert)) + "\n")
        return alerts


# ── Synthetic Event Stream ────────────────────────────────────────────────────

HOSTS   = ["web01", "db01", "ad01", "vpn01", "jump01", "dc02"]
USERS   = ["jsmith", "akim", "root", "svc_backup", "ladmin", "bwong"]
INT_IPS = ["10.0.1.15", "10.0.2.33", "192.168.1.44", "172.16.5.10"]
EXT_IPS = ["45.33.32.156", "91.220.101.5", "198.51.100.22"]
ACTIONS = ["auth", "login", "ssh", "rdp", "smb", "http_get",
           "http_upload", "sudo", "runas", "dns_txt_query"]

def _random_event() -> LogEvent:
    return LogEvent(
        timestamp = time.time(),
        source    = random.choice(["syslog", "winlog", "nginx", "vpn"]),
        host      = random.choice(HOSTS),
        user      = random.choice(USERS),
        src_ip    = random.choice(INT_IPS + EXT_IPS),
        action    = random.choice(ACTIONS),
        outcome   = random.choices(["success", "failure"], weights=[7, 3])[0],
        raw       = "synthetic",
    )

def _inject_attack(attack: str) -> LogEvent:
    """Inject realistic attack events to trigger rules."""
    if attack == "bruteforce":
        return LogEvent(time.time(), "syslog", "ad01", "unknown",
                        "10.99.99.1", "auth", "failure", "brute force")
    if attack == "lateral":
        return LogEvent(time.time(), "winlog", random.choice(HOSTS), "ladmin",
                        "10.0.1.15", "rdp", "success", "rdp session")
    if attack == "privesc":
        return LogEvent(time.time(), "syslog", "web01", "jsmith",
                        "10.0.1.15", "sudo", "success", "sudo bash")
    if attack == "exfil":
        return LogEvent(time.time(), "nginx", "web01", "svc_backup",
                        "45.33.32.156", "http_upload", "success", "large POST")
    return _random_event()


# ── Runner ────────────────────────────────────────────────────────────────────

SEV_COLORS = {
    "critical": "\033[91m",
    "high":     "\033[93m",
    "medium":   "\033[94m",
    "low":      "\033[96m",
}
RESET = "\033[0m"


async def run(engine: CorrelationEngine, rate: float, duration: float):
    interval = 1.0 / rate
    end      = time.time() + duration
    attack_cycle = 0

    while time.time() < end:
        attack_cycle += 1
        # Inject attack traffic every N events to trigger detections
        if attack_cycle % 5 == 0:
            event = _inject_attack("bruteforce")
        elif attack_cycle % 17 == 0:
            event = _inject_attack("lateral")
        elif attack_cycle % 31 == 0:
            event = _inject_attack("privesc")
        elif attack_cycle % 43 == 0:
            event = _inject_attack("exfil")
        else:
            event = _random_event()

        alerts = engine.process(event)
        for a in alerts:
            ts  = datetime.fromtimestamp(a.fired_at).strftime("%H:%M:%S")
            col = SEV_COLORS.get(a.severity, "")
            print(f"{col}[{ts}] [{a.severity.upper():8}] {a.rule_id:12} | "
                  f"{a.mitre_technique:6} | {a.description}{RESET}")

        await asyncio.sleep(interval)


async def main():
    parser = argparse.ArgumentParser(description="Log correlation engine")
    parser.add_argument("--duration", type=float, default=30,
                        help="Run time in seconds (default: 30)")
    parser.add_argument("--rate",     type=float, default=20,
                        help="Events per second (default: 20)")
    parser.add_argument("--output",   default="alerts.jsonl",
                        help="Alert output file (default: alerts.jsonl)")
    args = parser.parse_args()

    log    = Path(args.output)
    engine = CorrelationEngine(log)

    print(f"[*] Correlation engine | {args.rate} eps | {args.duration}s")
    print(f"[*] Rules: BruteForce, LateralMovement, PrivEsc, DataExfil")
    print(f"[*] Alerts → {log}\n")

    await run(engine, args.rate, args.duration)

    print(f"\n[*] Events: {engine.total_events} | Alerts: {engine.total_alerts}")
    print(f"[*] Alert log: {log}")


if __name__ == "__main__":
    asyncio.run(main())
