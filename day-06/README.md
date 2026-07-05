# Day 06 — IoC Detection Techniques, Live System Analysis, and Hacking Methodology

Deep practical coverage of how SOC analysts detect attacks in progress: network-level IoC detection using packet analysis, live system analysis across 14 monitoring domains, malware IoC identification, insider threat detection, and the full hacking methodology from both attacker and defender perspectives.

---

## What This Covers

- Network scanning IoC detection: TCP half-open, full connect, SYN/FIN, UDP scans — Wireshark filters for each
- ARP poisoning detection: duplicate IP detection, XArp methodology
- MAC flooding detection: Expert Information window analysis, TTL-based identification
- Malware IoCs: 50+ behavioral indicators across endpoint, network, and system layers
- Live system analysis: 14 monitoring techniques — ports, processes, registry, network, DNS, API calls, scheduled tasks, browser activity
- Static/memory analysis: file fingerprinting, string search, PE analysis, malware disassembly
- Insider threat IoCs: 14 categories with detection methodology
- EC-Council 5-phase hacking methodology: Reconnaissance, Scanning, Gaining Access, Maintaining Access, Clearing Tracks
- Lockheed Martin Cyber Kill Chain: all 7 phases with spear-phishing deep-dive scenario

---

## Network Scanning Detection — Wireshark Filters

### TCP Half-Open (SYN) Scan Detection
```
tcp.flags==0x002 or tcp.flags==0x012 or tcp.flags==0x004 or tcp.flags==0x014
```
Detection rule: TCP sessions with fewer than 4 packets total indicate a port scan — the attacker never completes the handshake.

### TCP Full Connect Scan + ICMP Unreachable
```
tcp.flags==0x002 or tcp.flags==0x012 or tcp.flags==0x004 or tcp.flags==0x014 or
(icmp.type==3 and (icmp.code==1 or icmp.code==2 or icmp.code==3 or icmp.code==9 or icmp.code==10 or icmp.code==13))
```

### SYN/FIN DDoS Detection
```
tcp.flags==0x003
```
Packets with both SYN and FIN set simultaneously are malformed — legitimate TCP never does this.

### UDP Scan Detection
```
icmp.type==3 and icmp.code==3
```
ICMP Type 3 Code 3 (Port Unreachable) in large volumes indicates UDP port scanning.

### ARP Poisoning Detection
```
arp.duplicate-address-detected
```
Duplicate IP address warnings in Wireshark Expert Information indicate ARP poisoning in progress.

---

## Live System Analysis — 14 Monitoring Techniques

| Technique | What to Monitor | Key Tool |
|---|---|---|
| Port monitoring | Suspicious ports opened by non-standard processes | netstat -ano, TCPView |
| Process monitoring | Malicious parent-child chains, injected DLLs | Process Monitor, Process Explorer |
| Registry monitoring | Run keys, service entries, IFEO modifications | Process Monitor, RegShot |
| Windows services | New services created by non-admin processes | sc query, Process Monitor |
| Startup programs | Persistence mechanisms added to startup locations | Autoruns (Sysinternals) |
| Event logs | Windows Security events 4624, 4648, 4688, 7045 | Event Viewer, SIEM |
| Installation monitoring | New software installed outside change windows | Windows Installer logs |
| File and folder monitoring | Modified/deleted system binaries, new files in Temp | Process Monitor |
| Device drivers | New kernel drivers loaded | DriverView |
| Network traffic | Beaconing patterns, connections to bad IPs | Wireshark, Zeek |
| DNS monitoring | DGA domains, high-entropy queries, tunneling | Passive DNS, network IDS |
| API calls monitoring | Suspicious API call patterns (VirtualAlloc, WriteProcessMemory) | API Monitor |
| Scheduled task monitoring | New tasks created by non-admin accounts | Task Scheduler, Autoruns |
| Browser activity | Extension installs, unusual download patterns | Browser logs, proxy |

---

## Malware IoC Categories

### Network Indicators
- Abnormal traffic flows and unexpected protocol usage
- Connections to unknown or newly registered domains
- Periodic outbound traffic at regular intervals (beaconing)
- Increase in outbound traffic when user is not active
- Connections to unusual port numbers (4444, 1337, 31337)

### Host/Endpoint Indicators
- Unknown running processes or processes consuming excessive resources
- Suspicious processes at system startup
- LSASS memory read by non-system process
- Running of executables from Temp directories
- Modification, deletion, or relocation of system files
- New registry Run keys created by non-admin accounts

### Behavioral Indicators
- Blue Screen of Death (BSOD) — often triggered by rootkit conflicts
- System slowdown and longer reboot times
- Security software automatically disabled
- Browser configuration changes without user action
- Unusual open ports not associated with known applications
- Account lockouts on multiple accounts simultaneously

---

## Insider Threat IoC Framework

| Category | Indicator | Risk Level |
|---|---|---|
| Data exfiltration | Bulk download of sensitive files | CRITICAL |
| Log tampering | Missing or modified audit logs | CRITICAL |
| Access patterns | Unusual access times or locations | HIGH |
| Authentication | Multiple failed logins followed by success | HIGH |
| Behavioral change | Deviation from established work patterns | MEDIUM |
| Physical access | Attempts to access restricted physical zones | HIGH |
| Data copying | Unauthorized download to USB or personal cloud | CRITICAL |
| Account misuse | Using different user accounts from different systems | HIGH |
| Financial anomaly | Unexplained changes in personal financial status | MEDIUM |

---

## EC-Council Hacking Methodology vs Kill Chain Mapping

| EC-Council Phase | Kill Chain Phase | SOC Detection Focus |
|---|---|---|
| Reconnaissance | Reconnaissance | External threat intel, DNS recon alerts |
| Scanning | Reconnaissance + Weaponization | IDS scan signatures, port scan detection |
| Gaining Access | Delivery + Exploitation | Email gateway, Office macro execution, EDR |
| Maintaining Access | Installation + C2 | Registry monitoring, beacon detection, netflow |
| Clearing Tracks | Actions on Objectives | Event log clearing (Event ID 1102), timestomping |

---

## Lab

Open `lab/live_analysis_console.html` in any browser. No install required.

**Five tabs — all simulated, educational, zero real-world interaction:**

**Process Monitor** — simulated process table showing malicious, suspicious, and clean processes on a compromised Windows host. Includes real-world malware process names, parent-child relationships, network connection counts, and file paths. Terminate, analyze, or quarantine selected processes.

**Network Connections** — simulated netstat output with connection state tracking. Known-bad IPs highlighted in red. Includes C2 beacons, lateral movement attempts, and normal traffic. Block connections or run trace route analysis.

**Registry Monitor** — live registry tree showing persistence keys including Run entries, service entries, and Image File Execution Options (IFEO) modifications. Malicious entries highlighted with full path and threat classification.

**Kill Chain Tracker** — full 7-phase Lockheed Martin kill chain for an active spear-phishing intrusion. Each phase shows: current status (BREACHED/ACTIVE/PENDING), description, IoCs, SOC detection action, MITRE ATT&CK mappings, and step-by-step scenario.

**Insider Threat Analyzer** — user risk profiles with behavioral risk scores and IoC flags. Activity feed showing all suspicious insider events with severity classification. Filter by user to see individual activity timeline.

---

## References

See docs/references.md
