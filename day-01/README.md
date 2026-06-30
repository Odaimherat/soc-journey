# 📅 Day 01 — Security Operations & Management: SOC Foundations

> **EC-Council CSA | Module 01 | Pages 17–40**

---

## 🎯 What You Will Learn Today

By the end of this day you will understand:
- What **Security Management** is and its four pillars
- What a **SOC** is, why it exists, and what it does every single day
- The full **SOC workflow**: Collect → Ingest → Validate → Report → Respond → Document
- Every **role** inside a SOC (L1, L2, IR, Threat Hunter, SOC Manager, CISO)
- The **three components** that make a SOC work: People, Process, Technology

---

## 📖 Page-by-Page Breakdown

### Pages 17–18 | Security Management
Security Management is not a single tool or policy — it is a **living system** of interconnected activities designed to maintain an organization's security posture. It protects CIA: **Confidentiality, Integrity, Availability**.

**Four pillars:**
| Pillar | What it does |
|--------|-------------|
| Security Infrastructure | Perimeter, Network, Endpoint, App/Data controls |
| Security Prevention | Vulnerability management + Penetration testing |
| Compliance & Validation | ISO 27001, ISMS baselines, GRC programs |
| Security Operations | Real-time monitoring, alerting, incident response (SOC) |

---

### Pages 19–21 | Security Operations
Security Operations = the **continuous practice** of maintaining a secure IT environment.

Three core tasks:
1. **Security Monitoring** — collect and analyze logs to find abnormal behavior
2. **Security Incident Management** — detect, manage, resolve in real-time
3. **Situational Awareness** — threat intelligence feeding into informed defense decisions

Additional tasks: Vulnerability Management, Security Device Management, Network-flow Monitoring

---

### Pages 22–24 | Security Operations Center (SOC)
The SOC is the **nerve center** of an organization's security. It is a centralized unit that:
- Continuously monitors networks, servers, endpoints, databases, applications, websites
- Provides a **single pane of glass** view across all assets
- Gathers data from: logs, IDS/IPS, firewalls, endpoint devices, network flows
- Facilitates incident detection, investigation, and response

Also called: SDC, SAC, NSOC, SIOC, Threat Defense Center, Cyber Security Center

---

### Pages 24–25 | Why Organizations Need a SOC
Traditional security tools (firewalls, AV, URL filters) are no longer enough. Attackers constantly evolve. The SOC fills the gap by:
- Proactively hunting for threats
- Performing continuous log management (critical for forensics)
- Monitoring privileged user abuse
- Reducing response time to near-zero
- Maintaining full control over log data for compliance

---

### Pages 25–26 | SOC Capabilities
| Capability | Description |
|------------|-------------|
| **Situational Awareness** | Full visibility across all IT infrastructure |
| **Threat Control & Prevention** | Aggregates all data streams, stays updated on external threats |
| **Forensics** | Structured log data → root cause analysis → restrict attacker |
| **Audit & Compliance** | Collects, stores, retrieves logs for audit purposes |
| **Preventing** | Fine-tuning, maintenance tools, IoC-based detection |
| **Detecting** | Collects, correlates, triggers alerts on suspicious activity |
| **Responding** | Handles documented alerts with security teams instantly |
| **Reporting** | Dashboards: service indicators, technical indicators, trend indicators |

---

### Pages 26–31 | SOC Operations (Daily Functions)
| Operation | Purpose |
|-----------|---------|
| Log Collection | Aggregate logs from every security device via syslog or centralized LMS |
| Log Retention & Archival | Store centrally, enable forensics, compliance, and behavior baselining |
| Log Analysis | Extract metrics from raw data; detect abnormal behavior |
| Security Monitoring | Transfer analyzed data to SOC team for situational awareness |
| Event Correlation | Automatically correlate events from multiple sources using predefined rules |
| Incident Management | Prioritize and act on reported incidents per predefined rules |
| Threat Identification | Real-time threat/vulnerability determination via threat intel + behavior analytics |
| Threat Reaction | Reactive (immediate remediation) or Proactive (remove weakness before exploit) |
| Reporting | Detailed reports: malicious activity, IoC, unauthorized access, DoS, suspicious emails |

**Secondary operations:** Malware Analysis, Vulnerability Management, Security Device Management

---

### Pages 31–32 | SOC Workflow

```
[Log Data] [Threat Data] [Flow Data] [Contextual Data]
        ↓
      SIEM
        ↓
   COLLECT → INGEST → VALIDATE → REPORT → RESPOND → DOCUMENT
                                    ↑________________________|
                              (Feedback Loop)
```

---

### Pages 33–40 | People: Roles Inside a SOC

```
CISO
 └── SOC Manager
      ├── L1 SOC Analyst        ← Monitors, triages, escalates
      ├── L2 SOC Analyst        ← Investigates, declares incident
      ├── Incident Responder    ← Remediates and closes
      └── Subject Matter Expert / Threat Hunter  ← Proactive hunting
```

**L1 Analyst**: Monitor SIEM alerts → initial investigation → escalate to L2
**L2 Analyst**: Prioritize alerts → examine sensors → close false positives → basic remediation
**Incident Responder**: Deep correlation → malware analysis → risk assessment → remediation
**Threat Hunter**: Proactive detection → behavior analytics → custom tooling (Endgame, Sqrrl)
**SOC Manager**: Track operations → policy compliance → team management → tool evaluation
**CISO**: Strategy, policies, procedures, risk management, regulatory compliance

---

## 🧪 Lab

```bash
cd lab/
pip install -r requirements.txt

# Run the full SOC pipeline simulation
python soc_workflow_demo.py

# Run just the log simulator
python soc_log_simulator.py

# Run the SIEM-style event correlator
python event_correlator.py

# Run the L1 analyst triage tool
python alert_triage.py
```

---

## 📚 References
See [docs/references.md](docs/references.md)
