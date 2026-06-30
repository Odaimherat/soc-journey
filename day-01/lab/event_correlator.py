#!/usr/bin/env python3
"""
Event Correlator — SIEM-Style Correlation Engine
=================================================
Reads ingested logs and applies correlation rules to detect attack patterns.
Simulates what a real SIEM (Splunk, QRadar, Elastic SIEM) does internally.

Correlation Rules Implemented:
  Rule 001 — Brute Force + Firewall Block combo
  Rule 002 — Known Bad IP contact
  Rule 003 — Lateral Movement (internal scan + exploit)
  Rule 004 — Credential Theft chain (lockout + LSASS dump)
  Rule 005 — C2 Beaconing pattern

Day 01 — SOC Analyst Journey | EC-Council CSA Module 01
"""

import json
import os
import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict

# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class CorrelatedAlert:
    rule_id:     str
    rule_name:   str
    severity:    str
    confidence:  str
    description: str
    evidence:    List[str] = field(default_factory=list)
    src_ips:     List[str] = field(default_factory=list)
    timestamp:   str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ── MITRE ATT&CK mapping ─────────────────────────────────────────────────────

MITRE = {
    "brute_force":       ("Credential Access",    "T1110 - Brute Force"),
    "known_bad_ip":      ("Command and Control",  "T1071 - Application Layer Protocol"),
    "lateral_movement":  ("Lateral Movement",     "T1021 - Remote Services"),
    "credential_theft":  ("Credential Access",    "T1003 - OS Credential Dumping"),
    "c2_beacon":         ("Command and Control",  "T1105 - Ingress Tool Transfer"),
}

# ── Colors ────────────────────────────────────────────────────────────────────

C = {
    "RED":    "\033[91m", "YLW": "\033[93m", "GRN":  "\033[92m",
    "CYN":   "\033[96m",  "WHT": "\033[97m", "BLD":  "\033[1m",
    "MAG":   "\033[95m",  "RST": "\033[0m",  "DIM":  "\033[2m",
    "CRIT":  "\033[41m\033[97m",
}
def c(text, *keys): return "".join(C.get(k,"") for k in keys) + text + C["RST"]

# ── Correlation engine ────────────────────────────────────────────────────────

class SIEMCorrelationEngine:
    def __init__(self):
        self.logs: List[Dict] = []
        self.alerts: List[CorrelatedAlert] = []
        self.known_bad = {"185.220.101.5","185.234.218.48","45.142.212.100","91.108.4.1"}

    def load_logs(self, path="ingested_logs.json"):
        if not os.path.exists(path):
            print(c(f"  ⚠️  No log file at {path}. Run soc_log_simulator.py first!", "YLW"))
            print(c("  📦 Generating synthetic log data for demo...\n", "GRN"))
            self._generate_demo_logs()
            return
        with open(path) as f:
            self.logs = json.load(f)
        print(c(f"  ✅ Loaded {len(self.logs)} logs from {path}", "GRN"))

    def _generate_demo_logs(self):
        """Generate hardcoded demo logs so engine runs standalone."""
        self.logs = [
            {"source":"IDS","severity":"CRITICAL","event_type":"IDS_5003","src_ip":"185.234.218.48","dst_ip":"192.168.1.1","detail":"SSH brute-force from known threat actor IP","raw":"..."},
            {"source":"FIREWALL","severity":"HIGH","event_type":"FW_DENY","src_ip":"185.234.218.48","dst_ip":"192.168.1.1","detail":"SSH connection blocked","raw":"..."},
            {"source":"IDS","severity":"HIGH","event_type":"IDS_2044","src_ip":"185.220.101.5","dst_ip":"192.168.1.10","detail":"Known C2 IP contacted","raw":"..."},
            {"source":"ENDPOINT","severity":"CRITICAL","event_type":"C2_BEACON","src_ip":"192.168.1.25","dst_ip":"185.220.101.5","detail":"Process beaconing to known C2 IP","raw":"..."},
            {"source":"ENDPOINT","severity":"CRITICAL","event_type":"LSASS_DUMP","src_ip":"192.168.1.25","dst_ip":"10.0.0.1","detail":"LSASS memory dump attempt","raw":"..."},
            {"source":"AUTH_SERVER","severity":"HIGH","event_type":"ACCOUNT_LOCKOUT","src_ip":"192.168.1.25","dst_ip":"10.0.0.1","detail":"[admin] Account locked","raw":"..."},
            {"source":"IDS","severity":"CRITICAL","event_type":"IDS_7777","src_ip":"192.168.1.25","dst_ip":"192.168.1.50","detail":"EternalBlue SMB exploit pattern","raw":"..."},
            {"source":"ENDPOINT","severity":"HIGH","event_type":"ENCODED_PS","src_ip":"192.168.1.30","dst_ip":"0.0.0.0","detail":"PowerShell with -EncodedCommand flag","raw":"..."},
        ]
        print(c(f"  📦 Loaded {len(self.logs)} synthetic demo events\n", "GRN"))

    def run_rules(self):
        print(c("\n  🔍 Running correlation rules...\n", "CYN", "BLD"))
        self._rule_brute_force()
        self._rule_known_bad_ip()
        self._rule_lateral_movement()
        self._rule_credential_theft()
        self._rule_c2_beacon()

    def _rule_brute_force(self):
        """Rule 001: IDS brute-force alert + matching firewall block = confirmed attack."""
        ids_bf  = [l for l in self.logs if "brute" in l.get("detail","").lower() or l.get("event_type","") in ("IDS_1001","IDS_5003")]
        fw_deny = [l for l in self.logs if l.get("event_type","") == "FW_DENY" and l.get("severity") in ("HIGH","CRITICAL")]
        if ids_bf and fw_deny:
            ips = list({l["src_ip"] for l in ids_bf})
            t, tech = MITRE["brute_force"]
            self.alerts.append(CorrelatedAlert(
                rule_id="COR-001", rule_name="Brute Force Attack Chain",
                severity="HIGH", confidence="HIGH",
                description="IDS detected brute-force AND firewall blocked the same source. Persistent attacker scanning for valid credentials.",
                evidence=[l["detail"] for l in ids_bf[:2]] + [l["detail"] for l in fw_deny[:1]],
                src_ips=ips, mitre_tactic=t, mitre_technique=tech
            ))

    def _rule_known_bad_ip(self):
        """Rule 002: Any contact with known bad IP is an immediate alert."""
        hits = [l for l in self.logs if l.get("src_ip") in self.known_bad or l.get("dst_ip") in self.known_bad]
        if hits:
            ips = list({l.get("src_ip") for l in hits if l.get("src_ip") in self.known_bad} |
                       {l.get("dst_ip") for l in hits if l.get("dst_ip") in self.known_bad})
            t, tech = MITRE["known_bad_ip"]
            self.alerts.append(CorrelatedAlert(
                rule_id="COR-002", rule_name="Known Threat Actor IP Detected",
                severity="CRITICAL", confidence="HIGH",
                description=f"Traffic observed involving {len(ips)} known-malicious IP(s) from threat intelligence feeds.",
                evidence=[l["detail"] for l in hits[:3]],
                src_ips=ips, mitre_tactic=t, mitre_technique=tech
            ))

    def _rule_lateral_movement(self):
        """Rule 003: Internal port scan followed by exploit attempt = lateral movement."""
        scans   = [l for l in self.logs if "scan" in l.get("detail","").lower()]
        exploits= [l for l in self.logs if "exploit" in l.get("detail","").lower() or "eternal" in l.get("detail","").lower()]
        if scans and exploits:
            t, tech = MITRE["lateral_movement"]
            self.alerts.append(CorrelatedAlert(
                rule_id="COR-003", rule_name="Lateral Movement — Scan then Exploit",
                severity="CRITICAL", confidence="MEDIUM",
                description="Internal recon (port scan) followed by exploit attempt. Classic lateral movement pattern inside the network.",
                evidence=[l["detail"] for l in scans[:1]] + [l["detail"] for l in exploits[:1]],
                src_ips=list({l["src_ip"] for l in scans + exploits}),
                mitre_tactic=t, mitre_technique=tech
            ))

    def _rule_credential_theft(self):
        """Rule 004: Account lockout + LSASS dump = active credential theft campaign."""
        lockouts = [l for l in self.logs if "lockout" in l.get("detail","").lower() or l.get("event_type") == "ACCOUNT_LOCKOUT"]
        lsass    = [l for l in self.logs if "lsass" in l.get("detail","").lower()]
        if lockouts and lsass:
            t, tech = MITRE["credential_theft"]
            self.alerts.append(CorrelatedAlert(
                rule_id="COR-004", rule_name="Credential Theft Campaign",
                severity="CRITICAL", confidence="HIGH",
                description="Account lockouts combined with LSASS dump attempt. Attacker is actively harvesting credentials.",
                evidence=[l["detail"] for l in lockouts[:1]] + [l["detail"] for l in lsass[:1]],
                src_ips=list({l["src_ip"] for l in lockouts + lsass}),
                mitre_tactic=t, mitre_technique=tech
            ))

    def _rule_c2_beacon(self):
        """Rule 005: Endpoint beaconing to external + PowerShell = active C2 session."""
        beacons = [l for l in self.logs if l.get("event_type") == "C2_BEACON" or "beacon" in l.get("detail","").lower()]
        ps_enc  = [l for l in self.logs if l.get("event_type") == "ENCODED_PS" or "encodedcommand" in l.get("detail","").lower()]
        if beacons or ps_enc:
            t, tech = MITRE["c2_beacon"]
            self.alerts.append(CorrelatedAlert(
                rule_id="COR-005", rule_name="Active C2 Session — Compromised Host",
                severity="CRITICAL", confidence="HIGH",
                description="Host is actively beaconing to C2 infrastructure. Attacker has foothold. Immediate isolation required.",
                evidence=[l["detail"] for l in (beacons + ps_enc)[:3]],
                src_ips=list({l["src_ip"] for l in beacons + ps_enc}),
                mitre_tactic=t, mitre_technique=tech
            ))

    def print_report(self):
        print(c("═"*65, "BLD"))
        print(c("  🧠 SIEM CORRELATION REPORT", "BLD", "CYN"))
        print(c("═"*65, "BLD"))
        print(f"  Logs analyzed : {len(self.logs)}")
        print(f"  Alerts fired  : {len(self.alerts)}")
        criticals = sum(1 for a in self.alerts if a.severity == "CRITICAL")
        print(f"  Critical      : {c(str(criticals), 'CRIT')}")
        print(c("═"*65, "BLD"))

        for i, alert in enumerate(self.alerts, 1):
            sev_str = c(f" {alert.severity} ", "CRIT" if alert.severity == "CRITICAL" else "RED" if alert.severity == "HIGH" else "YLW")
            print(f"\n  [{c(alert.rule_id,'MAG','BLD')}] {c(alert.rule_name, 'BLD', 'WHT')} {sev_str}")
            print(f"  {'─'*60}")
            print(f"  📋 {alert.description}")
            print(f"  🎯 MITRE: {c(alert.mitre_tactic,'CYN')} | {c(alert.mitre_technique,'YLW')}")
            print(f"  🌐 Source IPs: {', '.join(alert.src_ips[:4])}")
            print(f"  🔍 Confidence: {c(alert.confidence, 'GRN')}")
            print(f"  📌 Evidence:")
            for ev in alert.evidence[:3]:
                print(f"     • {ev}")

        print(c("\n" + "═"*65, "BLD"))
        print(c("  ✅ Correlation complete. Alerts ready for L1 triage.", "GRN", "BLD"))
        print(c("═"*65 + "\n", "BLD"))

        # Save for triage tool
        with open("correlated_alerts.json", "w") as f:
            json.dump([{
                "rule_id": a.rule_id, "rule_name": a.rule_name,
                "severity": a.severity, "confidence": a.confidence,
                "description": a.description, "evidence": a.evidence,
                "src_ips": a.src_ips, "timestamp": a.timestamp,
                "mitre_tactic": a.mitre_tactic, "mitre_technique": a.mitre_technique
            } for a in self.alerts], f, indent=2)
        print(c("  💾 Alerts saved to correlated_alerts.json\n", "GRN"))


if __name__ == "__main__":
    engine = SIEMCorrelationEngine()
    engine.load_logs()
    engine.run_rules()
    engine.print_report()
