# Day 07 — Incidents, Events, and Logging: The Foundation of SIEM

The core module on log management — understanding what logs are, where they come from, how they are formatted, the difference between logs, events, and incidents, Windows and Linux log architecture, and why centralized logging is the backbone of every SOC.

---

## What This Covers

- Kill chain deep dive: spear phishing scenario mapped to all 7 phases with use cases
- Log vs Event vs Incident: the three-tier hierarchy and how they relate
- Why logs matter: 6 key uses from incident detection to compliance
- Log sources: 15+ source types across network, endpoint, and application layers
- Logging requirements: what to log, where to store, how to format
- Local vs centralized logging: architecture differences and when to use each
- Windows Event Logs: 5 log types, event structure (EVENTLOGRECORD), event types
- Critical Windows Event IDs: 4624, 4625, 4648, 4688, 4698, 4720, 4732, 1102, 7045
- Linux logs: /var/log directory structure and what each file contains
- Monitoring and analysis workflows: filtering, correlation, forensic use

---

## The Log-Event-Incident Chain

```
RAW LOG           →    EVENT                →    INCIDENT
────────────────       ──────────────────────    ─────────────────────────────
Timestamped entry      Contextual observation    One or more related events
from a device          with security relevance    confirming a policy violation

Example:               Example:                  Example:
2024-01-15 03:14       Login failure for          47 failures followed by
SSHD: Failed           "root" from external IP    success = confirmed brute force
password for root      at 3am on a weekend        = active incident
```

---

## Critical Windows Event IDs

| Event ID | Name | Severity | SOC Action |
|---|---|---|---|
| 4624 | Successful Logon | INFO | Baseline — alert on anomalous time/location |
| 4625 | Failed Logon | HIGH | Alert: >5 failures from same source in 60s |
| 4648 | Explicit Credentials | HIGH | Alert: suspicious process as caller (lateral movement) |
| 4688 | Process Created | MEDIUM | Alert: Office spawning cmd.exe or PowerShell |
| 4698 | Scheduled Task Created | HIGH | Alert: task from Temp path or by non-admin |
| 4720 | User Account Created | HIGH | Alert: no corresponding change ticket |
| 4732 | Admin Group Changed | CRITICAL | IMMEDIATE alert — any change to Domain Admins |
| 1102 | Audit Log Cleared | CRITICAL | IMMEDIATE P1 — attacker covering tracks |
| 7045 | Service Installed | HIGH | Alert: service binary in Temp or AppData |
| 4776 | Credential Validation | MEDIUM | Alert: spray pattern (many accounts, low frequency) |
| 4663 | Object Access | MEDIUM | Alert: sensitive paths accessed by unexpected user |

---

## Windows Log File Locations

```
C:\Windows\System32\winevt\Logs\
├── Security.evtx      ← Most critical — auth, access, privilege events
├── System.evtx        ← OS components, drivers, services
├── Application.evtx   ← Application-specific events
├── Setup.evtx         ← Installation and configuration events
└── ForwardedEvents.evtx ← Events received from other systems
```

Registry key for log configuration:
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\<Log>
```

---

## Linux Log Structure

```
/var/log/
├── auth.log            ← SSH, sudo, PAM — CRITICAL for SOC
├── syslog              ← General system messages
├── kern.log            ← Kernel messages
├── cron.log            ← Scheduled task execution
├── maillog             ← Mail server events
├── boot.log            ← System startup messages
├── httpd/ or apache2/  ← Web server access and error logs
├── mysql/              ← Database events
└── secure              ← Authentication (RHEL/CentOS variant of auth.log)
```

---

## Logging Requirements Checklist

Before enabling a logging solution:
- What to log: define which event types are required
- Where to store: local disk vs centralized log server
- Log format: timestamp, severity, source, event type, description, user, IP
- Retention policy: how long to keep logs (compliance requirement varies)
- Access control: who can read, write, or delete logs
- Tamper evidence: immutable forwarding to SIEM prevents local log clearing

---

## Lab — SOC-SIEM Log Management Platform

Open `lab/siem_log_platform.html` in any browser. Designed to look and feel like Wazuh, Splunk, or IBM QRadar.

**Dashboard** — real-time event statistics, log ingestion rate by source (Windows/Linux/Firewall/IDS/Web), event type distribution chart, and a live recent security events feed with click-through to full log details.

**Log Viewer** — live log stream with KQL-style filter bar (search by EventID, hostname, severity, IP, message content). Filter by source (Windows Security, Windows System, Linux Auth, Linux Syslog, Firewall, IDS/IPS, Web Server). Click-through event detail panel shows raw log, all parsed fields, SOC response guidance, and category.

**Log Sources** — reference cards for all 10 major log source types with filesystem paths, log format description, and key events to monitor.

**Event ID Reference** — 13 critical Windows and Linux event IDs with full descriptions, MITRE ATT&CK mappings, and specific detection rules. Filter by platform. Click any card to instantly filter the Log Viewer for that event.

**Incident Queue** — 4 pre-built incidents (log cleared, C2 beacon, SSH brute force, domain admin group changed) with full evidence lists, step-by-step timelines, MITRE mappings, and escalate/close workflow.

---

## References

See docs/references.md
