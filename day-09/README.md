# Day 09 — SIEM Detection Engine: Use Cases, Sizing, Contextual Data, and Deployment Architectures

Deep coverage of production SIEM operations: how detection rules are written using real regex patterns, how SIEM is sized using EPS calculations, what contextual data enriches log events, the difference between signature and anomaly detection, NetFlow integration, and the 6 deployment architecture options.

---

## What This Covers

- 7-stage use case development lifecycle in depth
- Log data requirements — 12 source types mapped to use cases
- Contextual data — 10 types: user, asset, vulnerability, threat, configuration, data, external, application, business, location
- NetFlow (RFC 3954) — integration with SIEM for traffic anomaly detection
- EPS sizing formula and hardware requirements (mid-range vs high-range)
- Data retention requirements: privacy laws, cost, relevance, compliance
- SIEM deployment architectures — 6 options across self-hosted/cloud × self/MSSP/jointly managed
- Additional deployment recommendations: agents vs agentless, appliance vs software vs virtual
- Signature-based vs anomaly-based detection comparison
- 6 practical detection use cases with real Splunk/regex patterns

---

## Detection Use Cases with Regex Patterns

### SQL Injection Detection

```regex
# SQL meta-characters
/(\%27)|(\')|(\-\-)|(\%23)|(#)/ix

# Error-based SQLi (looks for = followed by quote/semicolon)
/((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i

# UNION-based extraction
/((\%27)|(\'))union/ix

# MSSQL xp_cmdshell Remote Code Execution
/exec(\s|\+)+(s|x)p\w+/ix
```

### XSS Detection

```regex
# Simple XSS with angle brackets
/((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)/ix

# IMG tag onerror handler
/((\%3C)|<)(i|(\%69))(m|(\%6D))(g|(\%47))[^\n]+((\%3E)|>)/i

# JavaScript injection keywords
/(javascript|vbscript|expression|applet|script|embed|iframe|frame)/i
```

### Directory Traversal Detection

```regex
# Core traversal pattern (dot-dot-slash, URL-encoded)
/(\.|(%|%25)2E)(\.|(%|%25)2E)(\/|(%|%25)2F|\\|(%|%25)5C)/i

# Direct sensitive file targets
/\/etc\/passwd|\/etc\/shadow|\/windows\/win\.ini|\/.ssh\/id_rsa/i
```

### Brute Force (Splunk SPL)

```splunk
# Source IPs exceeding login failure threshold
index=web_logs status IN (401, 403)
| stats count BY src_ip | where count > 10

# Success after failures — credential confirmed
index=web_logs | transaction src_ip maxspan=5m
| search status=401 AND status=200
```

### Bad Bot Detection (Splunk SPL)

```splunk
# Known scanner User-Agents
index=web_logs
| regex cs_useragent="(?i)(sqlmap|nikto|nessus|openvas|masscan|nmap|dirbuster)"

# Bots don't load static assets
index=web_logs
| eval is_asset=if(match(cs_uri_stem,"\.(css|js|png|jpg|ico)"),1,0)
| stats sum(is_asset) AS assets, count AS reqs BY src_ip
| where reqs > 50 AND assets = 0
```

---

## Contextual Data Types

| Context Type | Typical Source | SOC Value |
|---|---|---|
| User Context | HR / Active Directory | Detect departing employees, privilege abuse |
| Asset Context | CMDB / Asset Management | Identify criticality of attacked asset |
| Vulnerability Context | Nessus, Qualys, OpenVAS | Prioritize events on known-vulnerable assets |
| Threat Context | MISP, OTX, Recorded Future | Enrich IPs/hashes with threat intel reputation |
| Configuration Context | CIS-CAT, patch management | Detect configuration drift |
| Data Context | DLP tools (Symantec, Purview) | Flag access to classified data |
| External Context | ISAC feeds, CISA advisories | Correlate with current threat landscape |
| Application Context | DAST/SAST tools (ZAP, Checkmarx) | Link web attacks to known app vulnerabilities |
| Business Context | ERP, CRM, business hours rules | Apply time-sensitive and department-scoped rules |
| Location & Physical | Badge access, GPS, subnet mapping | Impossible-travel detection |

---

## EPS Sizing Formula

```
EPS = Total Events Per Day / 86,400 seconds

Example:
  Firewall:        500,000 events/day
  Windows Security: 200,000 events/day
  Linux:           100,000 events/day
  IDS/IPS:          50,000 events/day
  Web Server:      300,000 events/day
  Total:         1,150,000 events/day
  Avg EPS = 1,150,000 / 86,400 = 13.3 EPS
  Peak EPS (3x) = 39.9 EPS
  Daily Storage = 1,150,000 × 300 bytes = 345 MB/day

Hardware Tier: Mid-Range (24 CPU, 64 GB RAM)
```

---

## Deployment Architecture Comparison

| Architecture | Event Sources | Collection | Correlation | Visualization |
|---|---|---|---|---|
| Self-Hosted, Self-Managed | In-house | In-house | In-house | In-house |
| Self-Hosted, MSSP-Managed | In-house | In-house | MSSP | MSSP |
| Self-Hosted, Jointly Managed | In-house | In-house | Joint | Joint |
| Cloud, MSSP-Managed | In-house | Cloud/MSSP | Cloud/MSSP | MSSP |
| Cloud, Jointly Managed | In-house | Joint | Joint | Joint |
| Hybrid, Jointly Managed | In-house | In-house+Cloud | Joint | Joint |

---

## Lab

Open `lab/siem_detection_engine.html` in any browser. No install required.

**9 sections:**

**Dashboard** — live stats, ingestion rate bars, event type distribution (SQLi/XSS/traversal/brute force), recent critical events, detection rule status widget.

**Active Alerts** — prioritized alert queue with acknowledge workflow.

**Log Viewer** — live log stream with SPL-style search, source sidebar, severity filters, full event detail panel with raw log and SOC guidance.

**NetFlow Monitor** — live network flow table showing source/destination IPs, ports, protocols, byte volumes, and anomaly flags. Anomalous flows (C2 ports, high byte volumes to external IPs) highlighted in red. Click any flow for investigation guidance.

**Detection Engine** — 6 production detection rules (SQLi, XSS, Directory Traversal, Brute Force, Parameter Tampering, Bad Bot) with full SIEM correlation logic, actual regex detection patterns, required event sources, and 5-6 step incident response playbooks.

**Sig vs Anomaly** — comparison table of signature-based vs anomaly/UEBA detection with examples and a combined-approach panel.

**Contextual Data** — 10 contextual data types with source systems, descriptions, and example tools.

**EPS Sizing Tool** — interactive calculator: enter events/day per source, calculates average EPS, peak EPS, daily storage requirement, and recommended hardware tier. Hardware requirements table for mid-range vs high-range SIEM.

**Deployment Architectures** — 6 architecture cards with layer-by-layer in-house/MSSP/joint breakdown, pros/cons comparison.

---

## References

See docs/references.md
