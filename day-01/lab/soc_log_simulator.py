#!/usr/bin/env python3
"""
soc_log_simulator.py
--------------------
Simulates real-time log ingestion from four security data sources:
  - Firewall
  - IDS/IPS
  - Endpoint detection agent
  - Authentication server

Output: terminal display + ingested_logs.json for downstream tools.
"""

import random
import time
import datetime
import json
from dataclasses import dataclass, asdict
from typing import List
from enum import Enum


class Severity(Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class LogSource(Enum):
    FIREWALL = "FIREWALL"
    IDS      = "IDS"
    ENDPOINT = "ENDPOINT"
    AUTH     = "AUTH_SERVER"


@dataclass
class SecurityLog:
    timestamp:  str
    source:     str
    severity:   str
    event_type: str
    src_ip:     str
    dst_ip:     str
    detail:     str
    raw:        str


# Data pools — realistic internal and external IP ranges
INTERNAL_IPS   = [f"192.168.1.{i}" for i in range(10, 60)]
EXTERNAL_IPS   = [
    "185.220.101.5", "45.142.212.100", "91.108.4.1",
    "203.0.113.42",  "198.51.100.7",   "185.234.218.48",
    "77.88.8.8",     "104.21.55.60",
]
KNOWN_BAD_IPS  = {"185.220.101.5", "185.234.218.48", "45.142.212.100"}

FIREWALL_EVENTS = [
    ("ALLOW", "TCP",  443, Severity.INFO,     "HTTPS traffic allowed"),
    ("ALLOW", "TCP",  80,  Severity.INFO,     "HTTP traffic allowed"),
    ("DENY",  "TCP",  3389,Severity.HIGH,     "RDP connection blocked from external source"),
    ("DENY",  "TCP",  22,  Severity.HIGH,     "SSH brute-force attempt blocked"),
    ("DENY",  "TCP",  4444,Severity.CRITICAL, "Metasploit default port blocked"),
    ("ALLOW", "UDP",  53,  Severity.INFO,     "DNS query allowed"),
    ("DENY",  "TCP",  445, Severity.CRITICAL, "SMB exploit attempt blocked"),
    ("DENY",  "ICMP", 0,   Severity.MEDIUM,   "Port scan detected and blocked"),
]

IDS_RULES = [
    (1001, Severity.CRITICAL, "RDP brute force — 15 or more failed attempts within 60 seconds"),
    (2044, Severity.HIGH,     "Known command-and-control IP contacted — potential beaconing"),
    (3021, Severity.CRITICAL, "Reverse shell pattern detected — Metasploit signature match"),
    (4019, Severity.MEDIUM,   "Network port scan — SYN flood pattern from single source"),
    (5003, Severity.CRITICAL, "SSH brute-force from known threat actor IP"),
    (6010, Severity.LOW,      "NetBIOS enumeration — possible internal reconnaissance"),
    (7777, Severity.CRITICAL, "EternalBlue SMB exploit pattern detected"),
    (8888, Severity.HIGH,     "PowerShell encoded command execution detected on endpoint"),
]

ENDPOINT_EVENTS = [
    (Severity.INFO,     "USER_LOGIN",    "Successful login"),
    (Severity.LOW,      "USB_INSERT",    "USB storage device inserted"),
    (Severity.HIGH,     "ENCODED_PS",    "PowerShell launched with -EncodedCommand flag"),
    (Severity.CRITICAL, "C2_BEACON",     "Process beaconing to known command-and-control IP"),
    (Severity.CRITICAL, "WEBSHELL_DROP", "Webshell file created on web server"),
    (Severity.HIGH,     "LSASS_DUMP",    "LSASS memory dump attempt detected — credential theft"),
    (Severity.MEDIUM,   "LARGE_EXFIL",  "Large file transfer to external IP"),
    (Severity.INFO,     "PROC_LAUNCH",   "New process launched"),
]

AUTH_EVENTS = [
    (Severity.INFO,     "LOGIN_SUCCESS",     "User authenticated successfully"),
    (Severity.HIGH,     "ACCOUNT_LOCKOUT",   "Account locked — excessive failed attempts"),
    (Severity.CRITICAL, "ADMIN_AFTER_HOURS", "Administrative account login outside business hours"),
    (Severity.HIGH,     "PASSWORD_SPRAY",    "Password spray pattern — multiple accounts targeted"),
    (Severity.MEDIUM,   "MFA_BYPASS",        "MFA bypass attempt detected"),
]


def now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def gen_firewall_log() -> SecurityLog:
    action, proto, port, severity, detail = random.choice(FIREWALL_EVENTS)
    src = random.choice(EXTERNAL_IPS if action == "DENY" else INTERNAL_IPS)
    dst = random.choice(INTERNAL_IPS)
    if src in KNOWN_BAD_IPS:
        severity = Severity.CRITICAL
    raw = f"{now_str()} FIREWALL {action} {proto} {src}:{random.randint(1024,65535)} -> {dst}:{port}"
    return SecurityLog(now_str(), LogSource.FIREWALL.value, severity.value,
                       f"FW_{action}", src, dst, detail, raw)


def gen_ids_log() -> SecurityLog:
    sid, severity, detail = random.choice(IDS_RULES)
    src = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
    dst = random.choice(INTERNAL_IPS)
    if src in KNOWN_BAD_IPS:
        severity = Severity.CRITICAL
    raw = f"{now_str()} IDS ALERT SID:{sid} {src} -> {dst} | {detail}"
    return SecurityLog(now_str(), LogSource.IDS.value, severity.value,
                       f"IDS_{sid}", src, dst, detail, raw)


def gen_endpoint_log() -> SecurityLog:
    severity, etype, detail = random.choice(ENDPOINT_EVENTS)
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(EXTERNAL_IPS)
    host = f"WS-{random.choice(['FINANCE','HR','DEV','MGMT'])}-{random.randint(1,10):02d}"
    raw = f"{now_str()} ENDPOINT={host} EVENT={etype} SRC={src} DETAIL={detail}"
    return SecurityLog(now_str(), LogSource.ENDPOINT.value, severity.value,
                       etype, src, dst, detail, raw)


def gen_auth_log() -> SecurityLog:
    severity, etype, detail = random.choice(AUTH_EVENTS)
    src = random.choice(INTERNAL_IPS + EXTERNAL_IPS)
    dst = "10.0.0.1"
    user = random.choice(["jsmith", "mwilson", "admin", "dchen", "svc_account", "root"])
    raw = f"{now_str()} AUTH USER={user} EVENT={etype} FROM={src} -> {dst} | {detail}"
    return SecurityLog(now_str(), LogSource.AUTH.value, severity.value,
                       etype, src, dst, f"[{user}] {detail}", raw)


GENERATORS = [gen_firewall_log, gen_ids_log, gen_endpoint_log, gen_auth_log]

SEVERITY_COLORS = {
    "INFO":     "\033[37m",
    "LOW":      "\033[34m",
    "MEDIUM":   "\033[33m",
    "HIGH":     "\033[91m",
    "CRITICAL": "\033[41m\033[97m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"
CYAN  = "\033[96m"
GREEN = "\033[92m"


def format_log(log: SecurityLog, count: int) -> str:
    color = SEVERITY_COLORS.get(log.severity, "")
    lines = [
        f"\n{BOLD}{CYAN}[#{count:04d}] {log.timestamp}{RESET}",
        f"  {color}[{log.severity:8s}] [{log.source:12s}] {log.event_type}{RESET}",
        f"  {log.src_ip}  ->  {log.dst_ip}",
        f"  {log.detail}",
        f"\033[2m  RAW: {log.raw}{RESET}",
    ]
    return "\n".join(lines)


def simulate(count: int = 25, delay: float = 0.3):
    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD}{CYAN}  SOC Log Simulator — Real-Time Multi-Source Ingestion{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"  Simulating {count} log events from 4 sources\n")

    stats = {s.value: 0 for s in Severity}
    all_logs: List[SecurityLog] = []

    for i in range(1, count + 1):
        log = random.choice(GENERATORS)()
        all_logs.append(log)
        stats[log.severity] += 1
        print(format_log(log, i))
        time.sleep(delay)

    total = len(all_logs)
    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD}{CYAN}  INGESTION SUMMARY{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        color = SEVERITY_COLORS.get(sev, "")
        bar   = "=" * stats[sev]
        pct   = stats[sev] / total * 100
        print(f"  {color}{sev:8s} | {bar:<20s} {stats[sev]:3d} ({pct:.0f}%){RESET}")
    print(f"\n  Total logs ingested : {total}")
    print(f"  Require action      : {stats['CRITICAL'] + stats['HIGH']} events")
    print(f"{BOLD}{'='*65}{RESET}")

    with open("ingested_logs.json", "w") as f:
        json.dump([asdict(l) for l in all_logs], f, indent=2)
    print(f"\n{GREEN}  Logs saved to ingested_logs.json{RESET}\n")


if __name__ == "__main__":
    simulate(count=25, delay=0.3)
