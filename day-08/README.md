# Day 08 — Incident Detection with SIEM (Module 04)

The core module on Security Information and Event Management — what SIEM is, why it exists, its 14 capabilities, architecture with 4 components, the three deployment types, real-world solutions (Splunk, QRadar, ArcSight, AlienVault, Elastic), SIEM use cases and scope, and the 7-stage use case development lifecycle.

---

## What This Covers

- SIEM definition: SIM + SEM unified into a single platform at the heart of SOC
- Why SIEM exists: visibility, incident management, forensics, compliance
- 14 SIEM capabilities: log collection, correlation, alerting, analytics, dashboards, FIM, reporting
- SIEM architecture: 4 components — Data Sources, Collectors, Central Engine, Database
- Three deployment types: In-House, Cloud-Based, Managed — advantages and disadvantages
- Real SIEM solutions: Splunk ES, IBM QRadar, ArcSight ESM, AlienVault USM, Elastic SIEM, LogRhythm
- SIEM scope: Compliance vs Security vs Operations as primary drivers
- SIEM use cases: generic vs specific, correlation logic, event sources, response playbooks
- 7-stage use case development: Scope → Monitoring Req → Event Source → Validation → Logic → Implementation → Response
- Phased deployment: Log Management First, then Use-Case-by-Use-Case (Output-Driven)

---

## SIEM Architecture — Data Flow

```
Data Sources          Collectors/Agents     Central Engine        Database
─────────────         ─────────────────     ──────────────        ────────
FW / IDS / IPS    →   Log Collectors    →   Normalize        →   Hot Storage
Routers/Switches  →   Flow Collectors   →   Correlate        →   Cold Archive
Windows/Linux     →   SNMP Polling      →   Analyze          →   Cloud Bucket
Web/App Servers   →   API Connectors    →   Alert/Dashboard  →   Retention Policy
Cloud Services    →   Syslog Forward    →   Report/Ticket    →   Forensic Index
```

---

## SIEM Capabilities (14 Core)

| Capability | Purpose |
|---|---|
| Log Collection | Agent-based and agentless ingestion from all sources |
| Event Correlation | Link related events across sources into security incidents |
| Real-time Alerting | Threshold-based alerts via email, SMS, dashboard, tickets |
| Security Analytics | Pattern analysis, anomaly detection, behavioral baseline |
| Dashboards | SOC analyst views for operational decision-making |
| Reporting | Compliance reports: PCI-DSS, HIPAA, SOX, FISMA, ISO 27001 |
| Log Forensics | Historical search for incident reconstruction |
| User Activity Monitoring | Track suspicious behavior and insider threats |
| File Integrity Monitoring | Detect unauthorized changes to sensitive files |
| Log Retention | Configurable retention for compliance and forensics |
| Application Log Monitoring | Windows/Linux/Unix server application log analysis |
| Object Access Auditing | Who accessed/modified/deleted sensitive files |
| Threat Intelligence Integration | IP/domain/hash reputation correlation |
| IT Compliance | Built-in compliance frameworks and policy enforcement |

---

## Deployment Types

| Type | Description | Best For |
|---|---|---|
| In-House | Organization owns hardware and software | Large enterprises needing full control |
| Cloud-Based | SIEM-as-a-Service subscription | Organizations without infrastructure budget |
| Managed (MSSP) | Third party operates the SIEM | Organizations without trained SOC staff |

---

## SIEM Use Case Development — 7 Stages

```
1. SCOPE              → Define compliance/security/operations driver
2. MONITORING REQ     → Identify what needs to be monitored and protected
3. EVENT SOURCE       → Map data sources required for the use case
4. EVENT VALIDATION   → Validate that sources produce the required events
5. USE CASE LOGIC     → Define correlation rule / detection condition
6. IMPLEMENTATION     → Configure, test in sandbox, deploy to production
7. USE CASE RESPONSE  → Define incident handling steps for each alert
```

---

## Correlation Rules in This Lab

| Use Case | Severity | MITRE Technique |
|---|---|---|
| Brute Force Authentication Attack | CRITICAL | T1110 |
| C2 Beacon Detection | CRITICAL | T1071.001 |
| Privilege Escalation via Admin Group | CRITICAL | T1078 |
| Security Log Cleared | CRITICAL | T1070.001 |
| Lateral Movement — Credential Reuse | HIGH | T1550.002 |
| Malware Persistence — Startup Mechanisms | HIGH | T1547 |

---

## Lab — SecureSIEM Platform

Open `lab/siem_platform.html` in any browser. Modeled after Splunk Enterprise Security, IBM QRadar, and ArcSight ESM.

**Dashboard** — live event stats (6 cards), log ingestion rate by source, event type distribution, recent critical/high events with click-through, SIEM use case coverage widget.

**Active Alerts** — prioritized alert queue with acknowledge workflow. Click any alert to drill into full log detail.

**Log Viewer** — live log stream with SPL-style search bar. Filter by source (8 options), severity (CRIT/HIGH/MED/INFO), or free-text query. Click any event for the full detail panel: all parsed fields, raw log, and SOC guidance specific to that Event ID.

**Correlation Rules** — 6 real SIEM use cases with full SIEM rule logic (threshold conditions, correlation window, variant rules), required event sources, and step-by-step response playbook.

**SIEM Capabilities** — all 14 capabilities with descriptions, organized as a reference card grid.

**SIEM Architecture** — 4-component architecture visualization with data flow diagram and example technologies for each layer.

**SIEM Solutions** — 6 real-world SIEM platforms with vendor info, deployment type, description, and key features.

**Deployment Types** — In-House vs Cloud vs Managed SIEM comparison with advantages and disadvantages. Phased deployment guidance panel.

---

## References

See docs/references.md
