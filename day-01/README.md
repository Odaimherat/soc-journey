# Day 01 — Security Operations and Management

A practical walkthrough of how Security Operations Centers work — the architecture, the workflow, the roles, and the tooling — with a fully working lab you can run locally.

---

## What This Covers

- Security Management and its four operational pillars
- What a Security Operations Center is and why organizations build them
- The full SOC operational workflow from log collection to incident closure
- Every role inside a SOC and what each one actually does day to day
- The People / Process / Technology framework that makes a SOC function
- The technology stack: SIEM, IDS/IPS, DAM, ticketing, dashboards

---

## Core Concepts

### Security Management

Security Management is a system of interconnected activities that maintains an organization's security posture. Its purpose is to protect the confidentiality, integrity, and availability of organizational assets — information, hardware, and software.

Four activities make up security management:

**Security Infrastructure**
Implements preventive, detective, and corrective controls across the perimeter, network, endpoints, and application layer.

**Security Prevention**
Vulnerability management and penetration testing ensure that known weaknesses are found and remediated before an attacker can exploit them.

**Compliance and Validation**
Governance, risk, and compliance programs — including ISO 27001 readiness and ISMS baselines — ensure the organization meets its obligations.

**Security Operations**
The live operational layer: real-time alerting, threat analysis, correlation, and incident detection and response. This is what the SOC handles.

---

### Security Operations

Security operations is the continuous practice of maintaining a secure IT environment through defined services and processes. Its goals are to prevent, detect, prioritize, and respond to security incidents.

Three aspects run simultaneously:

**Security Monitoring**
Collecting and analyzing logs and data from every device on the network to identify abnormal behavior and escalate it for response.

**Security Incident Management**
Detecting, managing, and resolving security incidents in real time with minimal business impact.

**Situational Awareness**
Using threat intelligence to understand the current threat landscape and make informed, proactive defensive decisions.

---

### The Security Operations Center

A SOC is a centralized unit that continuously monitors, manages, and analyzes security events across an organization's networks, servers, endpoints, databases, applications, and websites.

It provides a single point of view through which all assets are monitored and defended. It collects data from logs, IDS/IPS systems, firewalls, endpoint agents, and network flows — then correlates that data to detect, investigate, and respond to incidents.

Why organizations build a SOC:

- Traditional signature-based tools cannot catch modern attack techniques
- Attackers move slowly across networks, evading single-point detection
- Log management at scale requires centralized infrastructure and dedicated analysts
- Privileged user abuse requires behavioral monitoring, not just perimeter defense
- Compliance requirements demand continuous logging and audit capability

---

### SOC Capabilities

| Capability | Description |
|---|---|
| Situational awareness | Full visibility across all IT infrastructure layers |
| Threat control and prevention | Aggregates data streams, uses external intelligence to stay current |
| Forensics | Structured log analysis to identify root cause and restrict attacker movement |
| Audit and compliance | Collects, stores, and retrieves logs for any audit requirement |
| Prevention | Fine-tuned detection rules and IoC-based blocking |
| Detection | Correlates events across sources and triggers alerts on suspicious activity |
| Response | Immediate, documented handling of confirmed incidents |
| Reporting | Dashboards covering service indicators, technical metrics, and trends |

---

### SOC Operations — Daily Functions

**Log Collection**
Every security device ships logs to a central collector via syslog or agent-based forwarding. Without this, real-time monitoring is not possible.

**Log Retention and Archival**
Logs are stored centrally for forensics, compliance, and behavioral baselining. Historical data establishes what normal looks like — deviations indicate attacks.

**Log Analysis**
Raw logs are cleaned, structured, and analyzed to extract metrics and identify abnormal activity.

**Event Correlation**
Events from multiple sources are correlated automatically based on predefined rules. Correct correlation reduces false positives dramatically.

**Incident Management**
Reported incidents are prioritized by predefined rules and handled systematically to minimize risk and downtime.

**Threat Identification**
Threats and vulnerabilities are determined in real time using threat intelligence feeds and behavioral analytics.

**Threat Reaction**
Reactive: immediate remediation when an attack is in progress.
Proactive: identify and remove weaknesses before an attacker can exploit them.

**Reporting**
Detailed reports covering malicious activity, indicators of compromise, unauthorized access attempts, denial of service events, and suspicious communications.

---

### SOC Workflow

```
[Log Data]  [Threat Data]  [Flow Data]  [Contextual Data]
                      |
                    SIEM
                      |
  COLLECT -> INGEST -> VALIDATE -> REPORT -> RESPOND -> DOCUMENT
                                                  |
                                    (feedback loop back to rules)
```

Each stage:

- **Collect**: Logs forwarded from all network devices to SIEM
- **Ingest**: SIEM normalizes formats, enriches with threat intel, indexes for correlation
- **Validate**: Analysts identify IoCs, triage alerts, confirm incidents
- **Report**: Confirmed incidents become tickets, escalated to response teams
- **Respond**: IR team investigates, contains, and remediates
- **Document**: Incidents recorded for audit and to improve future detection

---

### People — Roles Inside a SOC

```
CISO
  |
SOC Manager
  |-- L1 SOC Analyst         (monitor, triage, escalate)
  |-- L2 SOC Analyst         (investigate, declare, ticket)
  |-- Incident Responder      (remediate, close)
  |-- Threat Hunter / SME     (proactive detection)
```

**L1 SOC Analyst**
Monitors the SIEM alert queue. Performs initial investigation. Escalates real alerts to L2, closes confirmed false positives. Collects and documents event data.

**L2 SOC Analyst**
Prioritizes the escalated queue. Investigates scope and impact. Declares incidents. Forwards tickets to the incident response team.

**Incident Responder**
Deep incident analysis by correlating data across multiple sources. Determines whether critical systems or data are affected. Conducts malware analysis. Prepares risk assessments. Executes countermeasures.

**Threat Hunter / Subject Matter Expert**
Proactively searches for threats that automated systems have not detected. Uses behavioral analytics, threat intelligence, and custom tooling. Does not wait for an alert to start an investigation.

**SOC Manager**
Manages the team, tracks operations, ensures policy and regulatory compliance, evaluates tools, documents incident response plans, and communicates with senior leadership.

**CISO**
Sets the organization-wide security strategy, policies, and procedures. Owns risk management and regulatory compliance at the executive level.

---

### Technology

The SOC technology stack amplifies analyst capability:

- **SIEM** (Splunk, QRadar, Elastic Security): collects, normalizes, correlates, and alerts
- **IDS/IPS**: detects and blocks network-level threats using signatures and behavior
- **Firewall**: enforces network access policy at the perimeter
- **Database Activity Monitoring (DAM)**: tracks and alerts on database access anomalies
- **EDR**: endpoint-level detection and response
- **Ticketing System**: tracks incidents from detection to closure
- **Dashboard**: provides service indicators, technical indicators, and trend data for the team

---

## Lab

```bash
cd lab/
python soc_workflow_demo.py
```

This runs the full pipeline:

1. `soc_log_simulator.py` — generates logs from four sources (firewall, IDS, endpoint, auth)
2. `event_correlator.py` — correlation engine with five rules mapped to MITRE ATT&CK
3. `alert_triage.py` — L1 triage console that processes the alert queue and generates tickets
4. `soc_workflow_demo.py` — orchestrates all of the above end to end

No external dependencies required.

---

## References

See [docs/references.md](docs/references.md)
