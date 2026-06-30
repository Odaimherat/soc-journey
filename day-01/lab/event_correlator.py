#!/usr/bin/env python3
"""
event_correlator.py
-------------------
SIEM-style correlation engine.
Reads ingested_logs.json and fires correlation rules to surface
attack patterns that individual events would not reveal on their own.

Correlation rules implemented:
  COR-001  Brute force chain — IDS alert + matching firewall block
  COR-002  Known threat actor IP detected in any traffic
  COR-003  Lateral movement — internal scan followed by exploit attempt
  COR-004  Credential theft campaign — account lockout + LSASS dump
  COR-005  Active C2 session — beaconing + encoded PowerShell execution

Output: terminal report + correlated_alerts.json for the triage tool.
"""

import json
import os
import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict


@dataclass
class CorrelatedAlert:
    rule_id:          str
    rule_name:        str
    severity:         str
    confidence:       str
    description:      str
    evidence:         List[str] = field(default_factory=list)
    src_ips:          List[str] = field(default_factory=list)
    timestamp:        str       = ""
    mitre_tactic:     str       = ""
    mitre_technique:  str       = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


MITRE = {
    "brute_force":      ("Credential Access",   "T1110 - Brute Force"),
    "known_bad_ip":     ("Command and Control", "T1071 - Application Layer Protocol"),
    "lateral_movement": ("Lateral Movement",    "T1021 - Remote Services"),
    "cred_theft":       ("Credential Access",   "T1003 - OS Credential Dumping"),
    "c2_beacon":        ("Command and Control", "T1105 - Ingress Tool Transfer"),
}

RESET = "\033[0m"; BOLD = "\033[1m"; CYAN = "\033[96m"; GREEN = "\033[92m"
YELLOW = "\033[93m"; RED = "\033[91m"; MAGENTA = "\033[95m"; DIM = "\033[2m"
CRIT = "\033[41m\033[97m"; WHITE = "\033[97m"

def c(text, *codes): return "".join(codes) + text + RESET


class CorrelationEngine:

    KNOWN_BAD = {"185.220.101.5", "185.234.218.48", "45.142.212.100", "91.108.4.1"}

    def __init__(self):
        self.logs:   List[Dict]           = []
        self.alerts: List[CorrelatedAlert] = []

    def load(self, path: str = "ingested_logs.json"):
        if os.path.exists(path):
            with open(path) as f:
                self.logs = json.load(f)
            print(c(f"  Loaded {len(self.logs)} logs from {path}", GREEN))
        else:
            print(c(f"  {path} not found — loading built-in demo events", YELLOW))
            self._demo_logs()

    def _demo_logs(self):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.logs = [
            {"source":"IDS",         "severity":"CRITICAL","event_type":"IDS_5003","src_ip":"185.234.218.48","dst_ip":"192.168.1.1",  "detail":"SSH brute-force from known threat actor IP","raw":""},
            {"source":"FIREWALL",    "severity":"HIGH",    "event_type":"FW_DENY", "src_ip":"185.234.218.48","dst_ip":"192.168.1.1",  "detail":"SSH connection blocked","raw":""},
            {"source":"IDS",         "severity":"HIGH",    "event_type":"IDS_2044","src_ip":"185.220.101.5", "dst_ip":"192.168.1.10", "detail":"Known command-and-control IP contacted","raw":""},
            {"source":"ENDPOINT",    "severity":"CRITICAL","event_type":"C2_BEACON","src_ip":"192.168.1.25","dst_ip":"185.220.101.5", "detail":"Process beaconing to known C2 IP","raw":""},
            {"source":"ENDPOINT",    "severity":"CRITICAL","event_type":"LSASS_DUMP","src_ip":"192.168.1.25","dst_ip":"10.0.0.1",    "detail":"LSASS memory dump attempt detected","raw":""},
            {"source":"AUTH_SERVER", "severity":"HIGH",    "event_type":"ACCOUNT_LOCKOUT","src_ip":"192.168.1.25","dst_ip":"10.0.0.1","detail":"[admin] Account locked after excessive failures","raw":""},
            {"source":"IDS",         "severity":"CRITICAL","event_type":"IDS_7777","src_ip":"192.168.1.25","dst_ip":"192.168.1.50",  "detail":"EternalBlue SMB exploit pattern detected","raw":""},
            {"source":"ENDPOINT",    "severity":"HIGH",    "event_type":"ENCODED_PS","src_ip":"192.168.1.30","dst_ip":"0.0.0.0",     "detail":"PowerShell launched with -EncodedCommand flag","raw":""},
            {"source":"IDS",         "severity":"MEDIUM",  "event_type":"IDS_4019","src_ip":"192.168.1.25","dst_ip":"192.168.1.50",  "detail":"Network port scan from internal host","raw":""},
        ]
        print(c(f"  Loaded {len(self.logs)} demo events\n", GREEN))

    def run(self):
        print(c("\n  Running correlation rules...\n", CYAN, BOLD))
        self._rule_brute_force()
        self._rule_known_bad_ip()
        self._rule_lateral_movement()
        self._rule_cred_theft()
        self._rule_c2_beacon()

    def _fire(self, rule_id, name, severity, confidence, description, evidence, src_ips, mitre_key):
        tactic, technique = MITRE[mitre_key]
        self.alerts.append(CorrelatedAlert(
            rule_id=rule_id, rule_name=name, severity=severity,
            confidence=confidence, description=description,
            evidence=evidence, src_ips=list(set(src_ips)),
            mitre_tactic=tactic, mitre_technique=technique,
        ))

    def _rule_brute_force(self):
        ids_hits = [l for l in self.logs if "brute" in l.get("detail","").lower()
                    or l.get("event_type","") in ("IDS_1001","IDS_5003")]
        fw_hits  = [l for l in self.logs if l.get("event_type","") == "FW_DENY"
                    and l.get("severity") in ("HIGH","CRITICAL")]
        if ids_hits and fw_hits:
            self._fire("COR-001","Brute Force Attack Chain","HIGH","HIGH",
                "IDS detected brute-force activity and the firewall blocked the same source IP. "
                "This correlation confirms a persistent credential attack rather than a scanning anomaly.",
                [l["detail"] for l in ids_hits[:2]] + [l["detail"] for l in fw_hits[:1]],
                [l["src_ip"] for l in ids_hits], "brute_force")

    def _rule_known_bad_ip(self):
        hits = [l for l in self.logs
                if l.get("src_ip") in self.KNOWN_BAD or l.get("dst_ip") in self.KNOWN_BAD]
        if hits:
            bad_ips = {l["src_ip"] for l in hits if l.get("src_ip") in self.KNOWN_BAD} | \
                      {l["dst_ip"] for l in hits if l.get("dst_ip") in self.KNOWN_BAD}
            self._fire("COR-002","Known Threat Actor IP Detected","CRITICAL","HIGH",
                f"Traffic was observed involving {len(bad_ips)} IP address(es) present on threat intelligence "
                "block lists. Any contact with a known-bad IP is treated as a confirmed indicator of compromise.",
                [l["detail"] for l in hits[:3]], list(bad_ips), "known_bad_ip")

    def _rule_lateral_movement(self):
        scans    = [l for l in self.logs if "scan" in l.get("detail","").lower()]
        exploits = [l for l in self.logs if "exploit" in l.get("detail","").lower()
                    or "eternal" in l.get("detail","").lower()]
        if scans and exploits:
            self._fire("COR-003","Lateral Movement — Scan Followed by Exploit","CRITICAL","MEDIUM",
                "An internal port scan was followed by an exploit attempt originating from the same host. "
                "This pattern is characteristic of an attacker who has already established a foothold "
                "and is now moving laterally through the network.",
                [l["detail"] for l in scans[:1]] + [l["detail"] for l in exploits[:1]],
                [l["src_ip"] for l in scans + exploits], "lateral_movement")

    def _rule_cred_theft(self):
        lockouts = [l for l in self.logs if "lockout" in l.get("detail","").lower()
                    or l.get("event_type") == "ACCOUNT_LOCKOUT"]
        lsass    = [l for l in self.logs if "lsass" in l.get("detail","").lower()]
        if lockouts and lsass:
            self._fire("COR-004","Credential Theft Campaign","CRITICAL","HIGH",
                "Account lockouts were observed in combination with an LSASS memory dump attempt on the same host. "
                "This indicates an active credential harvesting campaign targeting both authentication infrastructure "
                "and local credential stores.",
                [l["detail"] for l in lockouts[:1]] + [l["detail"] for l in lsass[:1]],
                [l["src_ip"] for l in lockouts + lsass], "cred_theft")

    def _rule_c2_beacon(self):
        beacons = [l for l in self.logs if l.get("event_type") == "C2_BEACON"
                   or "beacon" in l.get("detail","").lower()]
        ps_enc  = [l for l in self.logs if l.get("event_type") == "ENCODED_PS"
                   or "encodedcommand" in l.get("detail","").lower()]
        if beacons or ps_enc:
            self._fire("COR-005","Active C2 Session — Host Compromised","CRITICAL","HIGH",
                "An endpoint is actively beaconing to command-and-control infrastructure while also executing "
                "encoded PowerShell commands. The attacker has an active foothold. "
                "Immediate isolation of the affected host is required.",
                [l["detail"] for l in (beacons + ps_enc)[:3]],
                [l["src_ip"] for l in beacons + ps_enc], "c2_beacon")

    def report(self):
        crits = sum(1 for a in self.alerts if a.severity == "CRITICAL")
        print(c("="*65, BOLD))
        print(c("  SIEM CORRELATION REPORT", BOLD, CYAN))
        print(c("="*65, BOLD))
        print(f"  Logs analyzed  : {len(self.logs)}")
        print(f"  Alerts fired   : {len(self.alerts)}")
        print(f"  Critical       : {c(str(crits), CRIT)}")
        print(c("="*65, BOLD))

        for alert in self.alerts:
            sev_color = CRIT if alert.severity == "CRITICAL" else RED
            print(f"\n  [{c(alert.rule_id, MAGENTA, BOLD)}]  {c(alert.rule_name, WHITE, BOLD)}  "
                  f"{c(' '+alert.severity+' ', sev_color)}")
            print(f"  {'-'*60}")
            print(f"  Description  : {alert.description}")
            print(f"  MITRE Tactic : {c(alert.mitre_tactic, CYAN)}")
            print(f"  Technique    : {c(alert.mitre_technique, YELLOW)}")
            print(f"  Source IPs   : {', '.join(alert.src_ips[:4])}")
            print(f"  Confidence   : {c(alert.confidence, GREEN)}")
            print(f"  Evidence:")
            for ev in alert.evidence[:3]:
                print(f"    - {ev}")

        print(c("\n" + "="*65, BOLD))
        print(c("  Correlation complete. Alerts queued for analyst triage.", GREEN, BOLD))
        print(c("="*65, BOLD))

        with open("correlated_alerts.json", "w") as f:
            json.dump([asdict(a) for a in self.alerts], f, indent=2)
        print(c("\n  Alerts saved to correlated_alerts.json\n", GREEN))


if __name__ == "__main__":
    engine = CorrelationEngine()
    engine.load()
    engine.run()
    engine.report()
