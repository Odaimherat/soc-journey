#!/usr/bin/env python3
"""
SOC L1 Alert Triage Tool
========================
Simulates an L1 SOC Analyst working through a queue of correlated alerts.
The analyst:
  1. Reviews each alert
  2. Decides: False Positive | Escalate to L2 | Close
  3. Adds notes
  4. Generates a triage report / ticket

Day 01 — SOC Analyst Journey | EC-Council CSA Module 01
"""

import json
import os
import datetime
import time
from dataclasses import dataclass, asdict
from typing import List

C = {
    "RED":   "\033[91m", "YLW": "\033[93m", "GRN": "\033[92m",
    "CYN":   "\033[96m", "WHT": "\033[97m", "BLD": "\033[1m",
    "MAG":   "\033[95m", "RST": "\033[0m",  "DIM": "\033[2m",
    "CRIT":  "\033[41m\033[97m", "BLU": "\033[94m",
}
def c(text, *keys): return "".join(C.get(k,"") for k in keys) + text + C["RST"]

@dataclass
class TriageTicket:
    ticket_id:   str
    rule_id:     str
    rule_name:   str
    severity:    str
    status:      str   # FALSE_POSITIVE | ESCALATED_L2 | CLOSED
    analyst:     str
    notes:       str
    timestamp:   str
    mitre:       str

def load_alerts():
    if os.path.exists("correlated_alerts.json"):
        with open("correlated_alerts.json") as f:
            return json.load(f)
    # Built-in demo alerts
    return [
        {"rule_id":"COR-001","rule_name":"Brute Force Attack Chain","severity":"HIGH",
         "confidence":"HIGH","description":"IDS detected brute-force AND firewall blocked the same source.",
         "evidence":["SSH brute-force from known threat actor IP","SSH connection blocked"],
         "src_ips":["185.234.218.48"],"timestamp":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
         "mitre_tactic":"Credential Access","mitre_technique":"T1110 - Brute Force"},
        {"rule_id":"COR-002","rule_name":"Known Threat Actor IP Detected","severity":"CRITICAL",
         "confidence":"HIGH","description":"Traffic observed involving known-malicious IPs from threat intelligence feeds.",
         "evidence":["Known C2 IP contacted","Process beaconing to known C2 IP"],
         "src_ips":["185.220.101.5"],"timestamp":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
         "mitre_tactic":"Command and Control","mitre_technique":"T1071 - Application Layer Protocol"},
        {"rule_id":"COR-005","rule_name":"Active C2 Session — Compromised Host","severity":"CRITICAL",
         "confidence":"HIGH","description":"Host is actively beaconing to C2 infrastructure.",
         "evidence":["Process beaconing to known C2 IP","PowerShell with -EncodedCommand flag"],
         "src_ips":["192.168.1.25"],"timestamp":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
         "mitre_tactic":"Command and Control","mitre_technique":"T1105 - Ingress Tool Transfer"},
    ]

def print_banner():
    print(c("\n" + "═"*65, "BLD"))
    print(c("  👁️  SOC L1 ALERT TRIAGE CONSOLE", "BLD", "CYN"))
    print(c("  EC-Council CSA | Module 01 | Day 01", "GRN"))
    print(c("═"*65, "BLD"))
    print(c("  Analyst: SOC-L1-Analyst-01", "DIM"))
    print(c(f"  Session: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "DIM"))
    print(c("═"*65 + "\n", "BLD"))

def print_alert(alert: dict, idx: int, total: int):
    sev = alert.get("severity","UNKNOWN")
    sev_color = "CRIT" if sev == "CRITICAL" else "RED" if sev == "HIGH" else "YLW"
    print(c(f"\n  ┌{'─'*61}┐", "BLD"))
    print(c(f"  │  ALERT {idx}/{total}  [{alert['rule_id']}]  {' '*(52-len(alert['rule_id']))}│", "BLD"))
    print(c(f"  └{'─'*61}┘", "BLD"))
    print(f"\n  {c('NAME:','BLD')}        {c(alert['rule_name'],'WHT','BLD')}")
    print(f"  {c('SEVERITY:','BLD')}    {c(' '+sev+' ', sev_color)}")
    print(f"  {c('CONFIDENCE:','BLD')} {c(alert.get('confidence','?'),'GRN')}")
    print(f"  {c('MITRE:','BLD')}       {c(alert.get('mitre_tactic','?'),'MAG')} — {c(alert.get('mitre_technique','?'),'YLW')}")
    print(f"  {c('SOURCE IPs:','BLD')}  {', '.join(alert.get('src_ips',[]))}")
    print(f"\n  {c('DESCRIPTION:','BLD')}")
    print(f"    {alert.get('description','')}")
    print(f"\n  {c('EVIDENCE:','BLD')}")
    for ev in alert.get("evidence",[]):
        print(f"    🔹 {ev}")

def auto_triage(alert: dict) -> tuple:
    """Auto-triage logic mimicking what an L1 analyst would do."""
    time.sleep(0.8)  # simulate analyst thinking
    sev = alert.get("severity","")
    conf = alert.get("confidence","")
    rule = alert.get("rule_id","")

    if sev == "CRITICAL" and conf == "HIGH":
        return "ESCALATED_L2", "CRITICAL severity + HIGH confidence. Immediate escalation to L2. Potential compromise confirmed by correlation."
    elif sev == "HIGH" and conf == "HIGH":
        return "ESCALATED_L2", "HIGH severity confirmed by multiple log sources. Escalating to L2 for deep investigation."
    elif sev == "MEDIUM":
        return "CLOSED", "Medium severity event reviewed. No immediate threat indicator. Monitoring continued."
    else:
        return "FALSE_POSITIVE", "Low confidence, single source. Marked as false positive after initial investigation."

def run_triage():
    print_banner()
    alerts = load_alerts()
    tickets: List[TriageTicket] = []

    print(c(f"  📥 Alert queue loaded: {len(alerts)} alerts pending triage\n", "CYN"))
    time.sleep(0.5)

    for i, alert in enumerate(alerts, 1):
        print_alert(alert, i, len(alerts))
        print(c("\n  ⏳ Analyst reviewing alert...", "YLW"))
        status, notes = auto_triage(alert)

        status_display = {
            "ESCALATED_L2":  c("  ⬆️  ESCALATED TO L2", "RED", "BLD"),
            "FALSE_POSITIVE": c("  ✅ FALSE POSITIVE — CLOSED", "GRN"),
            "CLOSED":         c("  📁 CLOSED — MONITORING", "BLU"),
        }[status]

        print(status_display)
        print(c(f"  📝 Notes: {notes}", "DIM"))

        ticket = TriageTicket(
            ticket_id=f"TKT-{datetime.datetime.now().strftime('%Y%m%d')}-{i:03d}",
            rule_id=alert["rule_id"], rule_name=alert["rule_name"],
            severity=alert["severity"], status=status,
            analyst="SOC-L1-Analyst-01", notes=notes,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            mitre=f"{alert.get('mitre_tactic','')} | {alert.get('mitre_technique','')}"
        )
        tickets.append(ticket)
        time.sleep(0.3)

    # Final report
    escalated = [t for t in tickets if t.status == "ESCALATED_L2"]
    fp        = [t for t in tickets if t.status == "FALSE_POSITIVE"]
    closed    = [t for t in tickets if t.status == "CLOSED"]

    print(c("\n" + "═"*65, "BLD"))
    print(c("  📊 TRIAGE SESSION SUMMARY", "BLD", "CYN"))
    print(c("═"*65, "BLD"))
    print(f"  Total alerts triaged : {len(tickets)}")
    print(c(f"  Escalated to L2     : {len(escalated)}", "RED", "BLD"))
    print(c(f"  False Positives     : {len(fp)}", "GRN"))
    print(c(f"  Closed/Monitoring   : {len(closed)}", "BLU"))
    print(c("═"*65, "BLD"))

    if escalated:
        print(c("\n  🚨 TICKETS ESCALATED TO L2:", "RED", "BLD"))
        for t in escalated:
            print(f"    [{c(t.ticket_id,'MAG')}] {t.rule_name} ({t.severity})")
            print(c(f"            → {t.notes[:80]}...", "DIM") if len(t.notes)>80 else c(f"            → {t.notes}", "DIM"))

    # Save tickets
    with open("triage_tickets.json", "w") as f:
        json.dump([asdict(t) for t in tickets], f, indent=2)
    print(c("\n  💾 Tickets saved to triage_tickets.json\n", "GRN"))
    print(c("  🔁 Escalated tickets forwarded to L2 queue.\n", "CYN"))

if __name__ == "__main__":
    run_triage()
