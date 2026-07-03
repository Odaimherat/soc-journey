# Day 04 — Password Attacks, Malware, APTs, and Network Protocol Attacks

Deep coverage of attacker techniques: every password cracking method, every major malware family with behavioral timelines and IoCs, the full APT lifecycle with stage-by-stage detection guidance, and five protocol-level network attacks.

---

## What This Covers

- Password attack techniques: Dictionary, Brute Force, Hybrid, Birthday, Rainbow Table, Credential Stuffing, Pass-the-Hash
- Privilege escalation: Vertical vs Horizontal
- Network protocol attacks: DNS Poisoning, ARP Poisoning, DHCP Starvation, DHCP Spoofing, MAC Spoofing, Switch Port Stealing
- Denial of Service: TCP SYN Flood, UDP Flood, ICMP Smurf, DDoS via botnet
- Malware types: Virus, Worm, Trojan, Rootkit, Backdoor, Ransomware, Spyware, Adware, Botnet, Logic Bomb, Polymorphic
- Advanced Persistent Threats: definition, characteristics, 6-phase lifecycle

---

## Lab

Open `lab/apt_malware_workbench.html` in any browser. No install required.

Four interactive tabs:
- **APT Lifecycle** — click each phase for techniques, IoCs, and SOC detection actions
- **Malware Encyclopedia** — behavioral timelines, detectable steps, IoCs, MITRE mappings for 8 malware types
- **Network Attack Simulator** — live network diagram showing ARP, DHCP, DNS, SYN flood, DDoS, APT propagation
- **Password Attack Lab** — real-time strength analyzer and crack-time estimator for all attack techniques

---

## Key Concept Tables

### Password Techniques

| Technique | Defeats | SOC Signal |
|---|---|---|
| Dictionary | Weak/common passwords | Login failures using common wordlist patterns |
| Brute Force | Short passwords | High-rate authentication failures |
| Hybrid | Predictable substitutions | Account lockouts across many accounts |
| Rainbow Table | Unsalted hashes | Hash database compromise + cracking |
| Credential Stuffing | Password reuse | Logins from unusual geos after breach announcement |
| Pass-the-Hash | Extracted NTLM hashes | SMB auth from non-expected source hosts |

### Malware IoC Summary

| Malware | Critical IoC |
|---|---|
| Virus | Hash mismatch on known-good executables |
| Worm | Sequential SMB connections from single host |
| Trojan | Office/browser spawning cmd/PowerShell |
| Rootkit | Process count mismatch between tools |
| Ransomware | vssadmin delete shadows + mass file rename |
| Botnet | Periodic HTTPS at fixed interval to new domain |
| Backdoor | Unexpected listening port on non-system process |

### APT Lifecycle

```
1. Preparation       — OSINT, tool build, team assembly
2. Initial Intrusion — spear-phishing or supply chain compromise
3. C2 Establishment  — encrypted beacon, persistence planted
4. Expansion         — lateral movement, credential theft
5. Persistence       — multiple backdoors, AD-level persistence
6. Exfiltration      — data staged, encrypted, sent out
+ Cleanup            — logs cleared, tools removed
```

---

## References

See docs/references.md
