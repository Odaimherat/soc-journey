#!/usr/bin/env python3
"""
soc_vs_noc_analyzer.py
----------------------
Classifies operational events as SOC or NOC responsibility and explains
the reasoning. Demonstrates the practical distinction between security
operations and network operations.

The SOC focuses on intelligent adversary activity.
The NOC focuses on naturally occurring system events.
"""

import random
import time
from dataclasses import dataclass
from typing import List

RESET = "\033[0m"; BOLD = "\033[1m"; CYAN = "\033[96m"; GREEN = "\033[92m"
YELLOW = "\033[93m"; RED = "\033[91m"; DIM = "\033[2m"; WHITE = "\033[97m"
MAGENTA = "\033[95m"; BLUE = "\033[94m"

def c(text, *codes): return "".join(codes) + text + RESET


@dataclass
class OperationalEvent:
    description:  str
    owner:        str   # "SOC", "NOC", or "BOTH"
    reasoning:    str
    priority:     str   # "HIGH", "MEDIUM", "LOW"
    escalate_to:  str


EVENTS = [
    OperationalEvent(
        "Border router interface went down — network path to branch office lost",
        "NOC", "Hardware or link failure. No adversary involvement. NOC restores connectivity.",
        "HIGH", "NOC Network Engineer"),
    OperationalEvent(
        "IDS fired 47 alerts for SSH brute-force from IP 185.234.218.48 in 60 seconds",
        "SOC", "Deliberate credential attack from external IP. SOC investigates, blocks, and documents.",
        "HIGH", "SOC L1 -> L2"),
    OperationalEvent(
        "DNS server response time degraded — average latency increased from 8ms to 340ms",
        "NOC", "Performance degradation without adversary indicator. NOC investigates capacity or configuration.",
        "MEDIUM", "NOC Systems Engineer"),
    OperationalEvent(
        "PowerShell process launched with -EncodedCommand flag on a finance workstation at 03:14",
        "SOC", "Encoded PowerShell at unusual hours is a strong indicator of attacker activity. SOC investigates immediately.",
        "HIGH", "SOC L1 -> L2 -> IR"),
    OperationalEvent(
        "Disk utilization on web server reached 92% — automated alert fired",
        "NOC", "Capacity event with no security indicator. NOC clears disk or provisions storage.",
        "LOW", "NOC Systems Engineer"),
    OperationalEvent(
        "User account generated 15 failed login attempts across three servers within 5 minutes",
        "BOTH",
        "NOC sees the authentication infrastructure load. SOC investigates whether this is a brute-force attack or a locked service account.",
        "HIGH", "SOC L1 (primary) + NOC notification"),
    OperationalEvent(
        "SIEM detected outbound connection from internal host to known C2 IP on port 4444",
        "SOC", "Active C2 beacon from a compromised host. SOC isolates the host and begins IR immediately.",
        "HIGH", "SOC L1 -> IR immediately"),
    OperationalEvent(
        "Firewall CPU utilization at 98% — packet drops increasing",
        "NOC", "Hardware resource exhaustion. Could be DDoS (escalate to SOC if traffic pattern is abnormal) but NOC investigates first.",
        "HIGH", "NOC Network Engineer (escalate to SOC if DDoS suspected)"),
    OperationalEvent(
        "A new .php file appeared in the web server document root — not deployed by the dev team",
        "SOC", "Unauthorized file drop on a web server is a webshell indicator. SOC investigates for compromise.",
        "HIGH", "SOC L2 -> IR"),
    OperationalEvent(
        "Backup job failed on database server — backup file not created",
        "NOC", "Operational failure without adversary indicator. NOC investigates and reruns backup.",
        "MEDIUM", "NOC Systems Engineer"),
    OperationalEvent(
        "Domain admin account logged in from a workstation in the accounting department at 22:45",
        "SOC", "Privileged account use outside business hours from an unusual source is a behavioral anomaly. SOC investigates.",
        "HIGH", "SOC L1 -> L2"),
    OperationalEvent(
        "SSL certificate on external web server expires in 7 days — automated warning",
        "NOC", "Scheduled maintenance item. NOC renews certificate before expiry.",
        "LOW", "NOC Systems Engineer"),
    OperationalEvent(
        "Network traffic from internal subnet to competitor IP addresses increased 400% in 2 hours",
        "SOC", "Unusual data volume to specific external destinations is an exfiltration indicator. SOC investigates.",
        "HIGH", "SOC L2 -> IR"),
    OperationalEvent(
        "SNMP trap received — UPS battery at 18% capacity in data center",
        "NOC", "Physical infrastructure alert. NOC coordinates facilities team.",
        "MEDIUM", "NOC Facilities Coordinator"),
    OperationalEvent(
        "Antivirus quarantined a file named 'invoice_q4.exe' on a finance workstation",
        "SOC", "Malware on a finance endpoint is a high-priority security event. SOC validates the quarantine and checks for lateral spread.",
        "HIGH", "SOC L1 -> L2"),
]


def banner():
    print(c("\n" + "="*65, BOLD, CYAN))
    print(c("  SOC vs NOC EVENT CLASSIFIER", BOLD, WHITE))
    print(c("  Demonstrates the practical distinction between security", DIM))
    print(c("  operations and network operations responsibility", DIM))
    print(c("="*65 + "\n", BOLD, CYAN))


def classify_events(events: List[OperationalEvent], delay: float = 1.0):
    soc_count = 0; noc_count = 0; both_count = 0

    for i, event in enumerate(events, 1):
        owner_color = {
            "SOC":  RED,
            "NOC":  BLUE,
            "BOTH": MAGENTA,
        }.get(event.owner, WHITE)

        priority_color = RED if event.priority == "HIGH" else YELLOW if event.priority == "MEDIUM" else GREEN

        print(c(f"\n  EVENT {i:02d}/{len(events)}", BOLD, DIM))
        print(c(f"  {event.description}", WHITE))
        time.sleep(delay * 0.4)
        print(c(f"\n  Owner     : {c(event.owner, owner_color, BOLD)}", ""))
        print(c(f"  Priority  : {c(event.priority, priority_color, BOLD)}", ""))
        print(c(f"  Reasoning : {event.reasoning}", DIM))
        print(c(f"  Escalate  : {event.escalate_to}", CYAN))
        print(c("  " + "-"*60, DIM))
        time.sleep(delay * 0.6)

        if event.owner == "SOC":   soc_count += 1
        elif event.owner == "NOC": noc_count += 1
        else:                      both_count += 1

    return soc_count, noc_count, both_count


def print_summary(soc, noc, both, total):
    print(c("\n\n" + "="*65, BOLD))
    print(c("  CLASSIFICATION SUMMARY", BOLD, CYAN))
    print(c("="*65, BOLD))
    print(c(f"  SOC responsibility  : {soc:>3d} events  ({soc/total*100:.0f}%)", RED))
    print(c(f"  NOC responsibility  : {noc:>3d} events  ({noc/total*100:.0f}%)", BLUE))
    print(c(f"  Shared / Escalate   : {both:>3d} events  ({both/total*100:.0f}%)", MAGENTA))
    print(c("="*65, BOLD))
    print(c("\n  Key Principle:", BOLD, WHITE))
    print(c("  The NOC responds to events that happen to the infrastructure.", DIM))
    print(c("  The SOC responds to events caused by intelligent adversaries.", DIM))
    print(c("  When in doubt, both teams are notified and SOC leads.\n", DIM))


def main():
    banner()
    print(c("  Processing 15 operational events and classifying each...\n", DIM))
    input(c("  Press ENTER to begin classification.", YELLOW))
    soc, noc, both = classify_events(EVENTS, delay=0.8)
    print_summary(soc, noc, both, len(EVENTS))


if __name__ == "__main__":
    main()
