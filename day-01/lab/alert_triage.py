#!/usr/bin/env python3
"""
alert_triage.py
---------------
Simulates the L1 SOC analyst triage workflow.

For each correlated alert the analyst:
  1. Reviews the alert details
  2. Makes a triage decision: FALSE_POSITIVE | ESCALATED_L2 | CLOSED
  3. Adds investigation notes
  4. Generates a structured ticket

Output: terminal session log + triage_tickets.json for the L2 queue.
"""

import json
import os
import datetime
import time
from dataclasses import dataclass, asdict
from typing import List


RESET = "\033[0m"; BOLD = "\033[1m"; CYAN = "\033[96m"; GREEN = "\033[92m"
YELLOW = "\033[93m"; RED = "\033[91m"; MAGENTA = "\033[95m"; DIM = "\033[2m"
CRIT = "\033[41m\033[97m"; BLUE = "\033[94m"; WHITE = "\033[97m"

def c(text, *codes): return "".join(codes) + text + RESET


@dataclass
class TriageTicket:
    ticket_id:        str
    rule_id:          str
    rule_name:        str
    severity:         str
    status:           str
    analyst:          str
    notes:            str
    timestamp:        str
    mitre_tactic:     str
    mitre_technique:  str


def load_alerts() -> List[dict]:
    if os.path.exists("correlated_alerts.json"):
        with open("correlated_alerts.json") as f:
            return json.load(f)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return [
        {"rule_id":"COR-001","rule_name":"Brute Force Attack Chain","severity":"HIGH",
         "confidence":"HIGH","description":"IDS detected brute-force and the firewall blocked the same source.",
         "evidence":["SSH brute-force from known threat actor IP","SSH connection blocked"],
         "src_ips":["185.234.218.48"],"timestamp":ts,
         "mitre_tactic":"Credential Access","mitre_technique":"T1110 - Brute Force"},
        {"rule_id":"COR-002","rule_name":"Known Threat Actor IP Detected","severity":"CRITICAL",
         "confidence":"HIGH","description":"Traffic observed involving known-malicious IPs.",
         "evidence":["Known C2 IP contacted","Process beaconing to known C2 IP"],
         "src_ips":["185.220.101.5"],"timestamp":ts,
         "mitre_tactic":"Command and Control","mitre_technique":"T1071 - Application Layer Protocol"},
        {"rule_id":"COR-005","rule_name":"Active C2 Session — Host Compromised","severity":"CRITICAL",
         "confidence":"HIGH","description":"Host is actively beaconing to C2 infrastructure.",
         "evidence":["Process beaconing to known C2 IP","PowerShell with -EncodedCommand flag"],
         "src_ips":["192.168.1.25"],"timestamp":ts,
         "mitre_tactic":"Command and Control","mitre_technique":"T1105 - Ingress Tool Transfer"},
    ]


def print_banner():
    print(c("\n" + "="*65, BOLD))
    print(c("  SOC L1 ALERT TRIAGE CONSOLE", BOLD, CYAN))
    print(c("="*65, BOLD))
    print(f"  Analyst  : SOC-L1-Analyst-01")
    print(f"  Session  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(c("="*65 + "\n", BOLD))


def print_alert(alert: dict, idx: int, total: int):
    sev       = alert.get("severity", "UNKNOWN")
    sev_color = CRIT if sev == "CRITICAL" else RED if sev == "HIGH" else YELLOW
    print(c(f"\n  ALERT {idx}/{total}  [{alert['rule_id']}]", BOLD, WHITE))
    print(f"  {'-'*60}")
    print(f"  Name         : {c(alert['rule_name'], WHITE, BOLD)}")
    print(f"  Severity     : {c(' '+sev+' ', sev_color)}")
    print(f"  Confidence   : {c(alert.get('confidence','?'), GREEN)}")
    print(f"  MITRE        : {c(alert.get('mitre_tactic','?'), CYAN)}  /  {c(alert.get('mitre_technique','?'), YELLOW)}")
    print(f"  Source IPs   : {', '.join(alert.get('src_ips', []))}")
    print(f"\n  Description  :")
    print(f"    {alert.get('description','')}")
    print(f"\n  Evidence:")
    for ev in alert.get("evidence", []):
        print(f"    - {ev}")


def triage_decision(alert: dict) -> tuple:
    """
    Triage logic applied by an L1 analyst.
    In a live SOC this would be an interactive decision.
    Here we apply deterministic rules that mirror analyst judgment.
    """
    time.sleep(0.9)
    sev  = alert.get("severity", "")
    conf = alert.get("confidence", "")

    if sev == "CRITICAL" and conf == "HIGH":
        return (
            "ESCALATED_L2",
            "Severity is CRITICAL with HIGH confidence correlation across multiple sources. "
            "Immediate escalation to L2 for deep investigation and containment."
        )
    elif sev == "HIGH" and conf == "HIGH":
        return (
            "ESCALATED_L2",
            "HIGH severity confirmed by correlated evidence from multiple log sources. "
            "Escalating to L2 for investigation of scope and impact."
        )
    elif sev == "MEDIUM":
        return (
            "CLOSED",
            "MEDIUM severity event reviewed. No immediate threat indicator confirmed. "
            "Logged and placed under continued monitoring."
        )
    else:
        return (
            "FALSE_POSITIVE",
            "Low confidence, single data source. No corroborating evidence. "
            "Marked as false positive after initial investigation review."
        )


def run():
    print_banner()
    alerts  = load_alerts()
    tickets: List[TriageTicket] = []

    print(c(f"  Alert queue : {len(alerts)} alerts pending triage\n", CYAN))
    time.sleep(0.4)

    for i, alert in enumerate(alerts, 1):
        print_alert(alert, i, len(alerts))
        print(c("\n  Analyst reviewing alert...", YELLOW))
        status, notes = triage_decision(alert)

        status_label = {
            "ESCALATED_L2":   c("  ESCALATED TO L2", RED, BOLD),
            "FALSE_POSITIVE": c("  FALSE POSITIVE — CLOSED", GREEN),
            "CLOSED":         c("  CLOSED — MONITORING", BLUE),
        }[status]
        print(status_label)
        print(c(f"  Notes : {notes}", DIM))

        ticket = TriageTicket(
            ticket_id        = f"TKT-{datetime.datetime.now().strftime('%Y%m%d')}-{i:03d}",
            rule_id          = alert["rule_id"],
            rule_name        = alert["rule_name"],
            severity         = alert["severity"],
            status           = status,
            analyst          = "SOC-L1-Analyst-01",
            notes            = notes,
            timestamp        = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            mitre_tactic     = alert.get("mitre_tactic", ""),
            mitre_technique  = alert.get("mitre_technique", ""),
        )
        tickets.append(ticket)
        time.sleep(0.3)

    escalated = [t for t in tickets if t.status == "ESCALATED_L2"]
    fp        = [t for t in tickets if t.status == "FALSE_POSITIVE"]
    closed    = [t for t in tickets if t.status == "CLOSED"]

    print(c("\n" + "="*65, BOLD))
    print(c("  TRIAGE SESSION SUMMARY", BOLD, CYAN))
    print(c("="*65, BOLD))
    print(f"  Total triaged      : {len(tickets)}")
    print(c(f"  Escalated to L2   : {len(escalated)}", RED, BOLD))
    print(c(f"  False positives   : {len(fp)}", GREEN))
    print(c(f"  Closed/monitoring : {len(closed)}", BLUE))
    print(c("="*65, BOLD))

    if escalated:
        print(c("\n  Tickets escalated to L2:", RED, BOLD))
        for t in escalated:
            notes_preview = t.notes[:75] + "..." if len(t.notes) > 75 else t.notes
            print(f"  [{c(t.ticket_id, MAGENTA)}]  {t.rule_name}  ({t.severity})")
            print(c(f"    {notes_preview}", DIM))

    with open("triage_tickets.json", "w") as f:
        json.dump([asdict(t) for t in tickets], f, indent=2)
    print(c("\n  Tickets saved to triage_tickets.json", GREEN))
    print(c("  Escalated tickets forwarded to the L2 queue.\n", CYAN))


if __name__ == "__main__":
    run()
