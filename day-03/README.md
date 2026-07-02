# Day 03 — Cyber Threats, IoCs, and Attack Methodology

A practical breakdown of how attackers think and operate — covering threat categories, attack vectors, TTPs, the attacker kill chain, and how a SOC analyst recognizes each attack type from its indicators of compromise.

---

## What This Covers

- What a cyber threat is and the three elements that make one possible
- Nine major attack vectors: cloud, ransomware, phishing, botnets, insider threats, IoT, mobile, web apps, viruses
- Attacker motives and the formula: Attack = Motive + Method + Vulnerability
- TTPs — Tactics, Techniques, and Procedures — and why analysts study them
- Vulnerability categories: TCP/IP, OS, and network device weaknesses
- Network-level attacks in detail: Reconnaissance, Scanning, Sniffing, MITM, Password Attacks
- Indicators of Compromise for each attack type
- The Cyber Kill Chain — all seven stages mapped to what a SOC detects

---

## Core Concepts

### What Makes a Cyber Threat

A cyber threat requires three things to exist simultaneously:

- **Intent** — the attacker has a motive for targeting this organization
- **Capability** — the attacker has TTPs that can actually achieve that goal
- **Opportunity** — a vulnerability exists that allows the attacker in

Remove any one of the three and the threat cannot materialize. This is why vulnerability management is not optional — it removes the opportunity even when intent and capability exist.

**Attack formula**: `Attack = Motive + Method + Vulnerability`

---

### Nine Attack Vectors

| Vector | How It Works | SOC Indicator |
|---|---|---|
| Ransomware | Encrypts files, demands payment | Mass rename events, vssadmin activity, C2 beacon |
| Phishing | Deceptive email triggers macro or credential theft | Office spawning PowerShell, suspicious domain in email header |
| Botnet | Compromised host receives attacker commands | Periodic beaconing, DGA domain queries |
| Insider Threat | Authorized user abuses access | Off-hours logins, bulk data downloads, unusual lateral movement |
| Cloud Threats | Misconfigured cloud resource exploited | Unusual API calls, cross-tenant access attempt |
| IoT Threats | Unpatched IoT device used as entry point | New device on network with immediate outbound connection |
| Mobile Threats | Malicious app exfiltrates data | Unusual data volume from mobile device subnet |
| Web App Threats | SQLi, XSS, RFI against web properties | WAF alert, unusual DB queries, error rate spike |
| Viruses/Worms | Self-replicating code spreads across network | Rapid lateral SMB connections, identical file appearing on multiple hosts |

---

### TTPs — Tactics, Techniques, and Procedures

TTPs describe *how* a specific threat actor operates. They are the most stable part of attacker behavior — tools change, infrastructure changes, but TTPs are hard to change because they reflect how a group *thinks*.

**Tactics** — the high-level strategy: initial access, privilege escalation, lateral movement, exfiltration.

**Techniques** — the specific method used within a tactic: spear-phishing attachment, pass-the-hash, living-off-the-land binary abuse.

**Procedures** — the exact operational steps in sequence that the actor follows for a given technique.

Why this matters for a SOC: detecting a technique is possible from a single log event. Detecting a procedure requires correlating multiple events over time. Detecting a tactic requires understanding the full attack narrative. All three levels require different analysis skills.

---

### Network-Level Attacks

#### Reconnaissance

The attacker maps the target before striking. Techniques:

- **Port scanning** — SYN scan, NULL scan, FIN scan to enumerate open services
- **Ping sweep** — ICMP echo to discover live hosts across a subnet
- **DNS footprinting** — zone transfer requests, reverse lookup enumeration
- **Social engineering** — calling employees to extract network architecture details
- **Passive sniffing** — capturing traffic without sending any packets (invisible to IDS)

SOC detection: sequential connection attempts to closed ports, ICMP sweeps across /24, anomalous DNS AXFR requests.

#### Network Scanning

Systematic probing with tools like Nmap, Nessus, OpenVAS, Masscan. The attacker determines:
- Which hosts are live
- Which services are running (application name and version)
- Which OS each host runs
- Which firewall rules are in place

SOC detection: high-rate SYN packets to multiple ports, service banner grab patterns in logs, IDS SYN-scan signature alerts.

#### Network Sniffing

Passive capture of all packets on a network segment. Three variants:
- **Internal** — attacker already on the network, runs Wireshark or tcpdump
- **External** — intercepts at a firewall or gateway
- **Wireless** — sits near a WiFi access point and captures unencrypted traffic

Sniffing captures cleartext credentials (Telnet, HTTP, FTP), session cookies, router configurations, and email content.

SOC detection: NIC in promiscuous mode, ARP anomalies, unexpected Syslog traffic volume.

#### Man-in-the-Middle (MITM)

The attacker positions themselves between client and server. All traffic passes through the attacker who can read, modify, and inject it. Common methods:
- ARP poisoning (redirects LAN traffic through attacker host)
- SSL stripping (downgrades HTTPS to HTTP)
- DNS spoofing (returns attacker IP for legitimate domain)
- Rogue access point (victim connects to attacker-controlled WiFi)

SOC detection: duplicate ARP replies for the default gateway, SSL certificate anomalies, DNS response from unexpected server.

#### Password Attacks

Attacker attempts to acquire valid credentials. Methods:
- **Brute force** — exhaustively tries all combinations
- **Dictionary attack** — tries common passwords and variations
- **Credential stuffing** — uses leaked username/password pairs from other breaches
- **Password spray** — tries one common password against many accounts (avoids lockout)
- **Pass-the-hash** — uses captured NTLM hash directly without cracking it
- **Keylogging** — captures keystrokes including passwords as typed

SOC detection: account lockouts, failed login spikes, LSASS memory access by non-system process.

---

### Indicators of Compromise (IoCs) by Attack Type

| Attack | Critical IoC | Source |
|---|---|---|
| Reconnaissance | Sequential port connection failures | Firewall |
| Scanning | SYN packets to 1000+ ports from single IP | IDS |
| Sniffing | Promiscuous mode NIC detected | Endpoint |
| MITM | ARP replies from unexpected MAC for gateway IP | Network |
| Password Attack | 15+ failed logins in 60s, then success | Auth Server |
| Ransomware | vssadmin delete shadows / mass file rename | Endpoint |
| Phishing | Office spawning cmd.exe or powershell.exe | EDR |
| Botnet/C2 | Periodic outbound HTTPS at exact interval | Firewall |

---

### The Cyber Kill Chain

```
1. RECONNAISSANCE   — target profiling, OSINT, scanning
2. WEAPONIZATION    — payload creation, exploit packaging
3. DELIVERY         — phishing email, drive-by download, USB
4. EXPLOITATION     — vulnerability triggered, code executed
5. INSTALLATION     — persistence mechanism established
6. C2               — beacon established, attacker has control
7. ACTIONS          — exfiltrate data, encrypt files, disrupt
```

The kill chain matters because an attacker can be stopped at any stage. The earlier the detection, the lower the damage. A SOC that detects at stage 1 (reconnaissance) eliminates the attack entirely. Detection at stage 6 (C2) still allows containment before stage 7 damage occurs.

---

## Lab — Browser-Based SIEM GUI

Open `siem_threat_dashboard.html` in any browser. No install, no server.

**What it does:**
- Live simulated alert feed from four sources (Firewall, IDS, Endpoint, Auth)
- Real-time severity counters and event-per-minute tracking
- Cyber Kill Chain tracker showing current attack stage
- MITRE ATT&CK TTP panel with detected technique counts
- Attack type reference with IoC signatures for all 7 attack categories
- Raw log stream
- Attack vector distribution bar chart
- Alert detail modal with event timeline, triage actions (Escalate / False Positive / Close)
- Incident ticket creation

This is a faithful simulation of what a tier-1 SIEM console looks like in production.

---

## References

See [docs/references.md](docs/references.md)
