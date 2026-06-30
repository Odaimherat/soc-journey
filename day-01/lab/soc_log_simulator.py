#!/usr/bin/env python3
"""
SOC Log Simulator
=================
Simulates real-time log ingestion from multiple security sources:
  - Firewall logs
  - IDS/IPS alerts
  - Endpoint detection logs
  - Authentication logs

Day 01 — SOC Analyst Journey | EC-Council CSA Module 01
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
    FIREWALL    = "FIREWALL"
    IDS         = "IDS"
    ENDPOINT    = "ENDPOINT"
    AUTH        = "AUTH_SERVER"
    WEBPROXY    = "WEB_PROXY"

@dataclass
class SecurityLog:
    timestamp: str
    source: str
    severity: str
    event_type: str
    src_ip: str
    dst_ip: str
    detail: str
    raw: str

# ── Realistic data pools ──────────────────────────────────────────────────────

INTERNAL_IPS = [f"192.168.1.{i}" for i in range(10, 60)]
EXTERNAL_IPS = [
    "185.220.101.5", "45.142.212.100", "91.108.4.1",
    "10.10.10.200",  "203.0.113.42",   "198.51.100.7",
    "185.234.218.48","77.88.8.8",      "104.21.55.60",
]
KNOWN_BAD_IPS = {"185.220.101.5", "185.234.218.48", "45.142.212.100"}

FIREWALL_EVENTS = [
    ("ALLOW", "TCP", 443,  Severity.INFO,   "HTTPS traffic allowed"),
    ("ALLOW", "TCP", 80,   Severity.INFO,   "HTTP traffic allowed"),
    ("DENY",  "TCP", 3389, Severity.HIGH,   "RDP connection blocked from external"),
    ("DENY",  "TCP", 22,   Severity.HIGH,   "SSH brute-force attempt blocked"),
    ("DENY",  "TCP", 4444, Severity.CRITICAL,"Metasploit default port blocked"),
    ("ALLOW", "UDP", 53,   Severity.INFO,   "DNS query allowed"),
    ("DENY",  "TCP", 445,  Severity.CRITICAL,"SMB exploit attempt blocked (EternalBlue)"),
    ("DENY",  "ICMP",0,    Severity.MEDIUM, "Port scan detected and blocked"),
]

IDS_RULES = [
    (1001, Severity.CRITICAL, "RDP Brute Force — 15+ failed attempts in 60s"),
    (2044, Severity.HIGH,     "Known C2 IP contacted — potential beaconing"),
    (3021, Severity.CRITICAL, "Metasploit reverse shell pattern detected"),
    (4019, Severity.MEDIUM,   "Network port scan — SYN flood pattern"),
    (5003, Severity.CRITICAL, "SSH brute-force from known threat actor IP"),
    (6010, Severity.LOW,      "NetBIOS enumeration — internal recon possible"),
    (7777, Severity.CRITICAL, "EternalBlue SMB exploit pattern detected"),
    (8888, Severity.HIGH,     "PowerShell encoded command execution detected"),
]

ENDPOINT_EVENTS = [
    (Severity.INFO,     "USER_LOGIN",      "Successful login"),
    (Severity.LOW,      "USB_INSERT",      "USB device inserted"),
    (Severity.HIGH,     "ENCODED_PS",      "PowerShell with -EncodedCommand flag"),
    (Severity.CRITICAL, "C2_BEACON",       "Process beaconing to known C2 IP"),
    (Severity.CRITICAL, "WEBSHELL_DROP",   "Webshell file created on web server"),
    (Severity.HIGH,     "LSASS_DUMP",      "LSASS memory dump attempt (credential theft)"),
    (Severity.MEDIUM,   "LARGE_EXFIL",     "Large file transfer to external IP"),
    (Severity.INFO,     "PROCESS_LAUNCH",  "New process launched"),
]

AUTH_EVENTS = [
    (Severity.INFO,     "LOGIN_SUCCESS",   "User authenticated successfully"),
    (Severity.HIGH,     "ACCOUNT_LOCKOUT", "Account locked — too many failed attempts"),
    (Severity.CRITICAL, "ADMIN_AFTER_HOURS","Admin login at unusual hour"),
    (Severity.HIGH,     "PASS_SPRAY",      "Password spray attack — many accounts targeted"),
    (Severity.MEDIUM,   "MFA_BYPASS_TRY",  "MFA bypass attempt detected"),
]

# ── Generator functions ───────────────────────────────────────────────────────

def random_ip(pool): return random.choice(pool)
def now(): return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def gen_firewall_log() -> SecurityLog:
    action, proto, port, severity, detail = random.choice(FIREWALL_EVENTS)
    src = random_ip(EXTERNAL_IPS if action == "DENY" else INTERNAL_IPS)
    dst = random_ip(INTERNAL_IPS)
    if src in KNOWN_BAD_IPS:
        severity = Severity.CRITICAL
    raw = f"{now()} FW {action} {proto} {src}:{random.randint(1024,65535)} -> {dst}:{port}"
    return SecurityLog(now(), LogSource.FIREWALL.value, severity.value,
                       f"FW_{action}", src, dst, detail, raw)

def gen_ids_log() -> SecurityLog:
    sid, severity, detail = random.choice(IDS_RULES)
    src = random_ip(EXTERNAL_IPS + INTERNAL_IPS)
    dst = random_ip(INTERNAL_IPS)
    if src in KNOWN_BAD_IPS:
        severity = Severity.CRITICAL
    raw = f"{now()} [IDS-ALERT] [SID:{sid}] {src} -> {dst} | {detail}"
    return SecurityLog(now(), LogSource.IDS.value, severity.value,
                       f"IDS_{sid}", src, dst, detail, raw)

def gen_endpoint_log() -> SecurityLog:
    severity, etype, detail = random.choice(ENDPOINT_EVENTS)
    src = random_ip(INTERNAL_IPS)
    dst = random_ip(EXTERNAL_IPS)
    endpoint = f"WS-{random.choice(['FINANCE','HR','DEV','MGMT'])}-{random.randint(1,10):02d}"
    raw = f"{now()} ENDPOINT={endpoint} EVENT={etype} SRC={src} DETAIL={detail}"
    return SecurityLog(now(), LogSource.ENDPOINT.value, severity.value,
                       etype, src, dst, detail, raw)

def gen_auth_log() -> SecurityLog:
    severity, etype, detail = random.choice(AUTH_EVENTS)
    src = random_ip(INTERNAL_IPS + EXTERNAL_IPS)
    dst = "10.0.0.1"  # domain controller
    user = random.choice(["jsmith","mwilson","admin","dchen","svc_account","root"])
    raw = f"{now()} AUTH USER={user} EVENT={etype} FROM={src} -> {dst} | {detail}"
    return SecurityLog(now(), LogSource.AUTH.value, severity.value,
                       etype, src, dst, f"[{user}] {detail}", raw)

GENERATORS = [gen_firewall_log, gen_ids_log, gen_endpoint_log, gen_auth_log]

# ── Color output ─────────────────────────────────────────────────────────────

COLORS = {
    "INFO":     "\033[37m",
    "LOW":      "\033[34m",
    "MEDIUM":   "\033[33m",
    "HIGH":     "\033[91m",
    "CRITICAL": "\033[41m\033[97m",
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "CYAN":     "\033[96m",
    "GREEN":    "\033[92m",
}

def colored(text, *keys):
    return "".join(COLORS.get(k,"") for k in keys) + text + COLORS["RESET"]

def print_log(log: SecurityLog, count: int):
    sev_color = log.severity
    prefix = {
        "INFO":     "ℹ️ ",
        "LOW":      "🔵",
        "MEDIUM":   "🟡",
        "HIGH":     "🔴",
        "CRITICAL": "🚨",
    }.get(log.severity, "  ")

    print(colored(f"\n[#{count:04d}] {log.timestamp}", "BOLD", "CYAN"))
    print(colored(f"  {prefix} [{log.severity:8s}] [{log.source:12s}] {log.event_type}", sev_color))
    print(f"  📍 {log.src_ip}  →  {log.dst_ip}")
    print(f"  📋 {log.detail}")
    print(colored(f"  RAW: {log.raw}", "INFO"))

# ── Main ──────────────────────────────────────────────────────────────────────

def simulate(count=30, delay=0.4):
    print(colored("\n" + "═"*65, "BOLD"))
    print(colored("  🛡️  SOC LOG SIMULATOR — Real-Time Multi-Source Ingestion", "BOLD", "CYAN"))
    print(colored("  EC-Council CSA | Module 01 | Day 01", "GREEN"))
    print(colored("═"*65, "BOLD"))
    print(f"  Simulating {count} log events from 4 sources...\n")

    stats = {s.value: 0 for s in Severity}
    all_logs = []

    for i in range(1, count + 1):
        gen = random.choice(GENERATORS)
        log = gen()
        all_logs.append(log)
        stats[log.severity] += 1
        print_log(log, i)
        time.sleep(delay)

    # Summary
    print(colored("\n" + "═"*65, "BOLD"))
    print(colored("  📊 INGESTION SUMMARY", "BOLD", "CYAN"))
    print(colored("═"*65, "BOLD"))
    total = len(all_logs)
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        bar = "█" * stats[sev]
        print(colored(f"  {sev:8s} | {bar:<20s} {stats[sev]:3d} ({stats[sev]/total*100:.0f}%)", sev))
    print(colored("═"*65, "BOLD"))
    print(f"\n  Total logs ingested: {total}")
    print(f"  Action required:     {stats['CRITICAL'] + stats['HIGH']} events\n")

    # Export JSON
    with open("ingested_logs.json", "w") as f:
        json.dump([asdict(l) for l in all_logs], f, indent=2)
    print(colored("  💾 Logs saved to ingested_logs.json for correlation engine\n", "GREEN"))

if __name__ == "__main__":
    simulate(count=25, delay=0.3)
