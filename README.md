# 🛡️ SOC Analyst Journey

> **One module per day. Real labs. Real code. Real understanding.**

[![EC-Council CSA](https://img.shields.io/badge/Cert-EC--Council%20CSA-blue?style=flat-square&logo=shield)](https://www.eccouncil.org/programs/certified-soc-analyst-csa/)
[![Exam](https://img.shields.io/badge/Exam-312--39-red?style=flat-square)](https://www.eccouncil.org/programs/certified-soc-analyst-csa/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Days](https://img.shields.io/badge/Days%20Completed-1-orange?style=flat-square)]()

---

## 📖 What Is This?

A daily, hands-on journey through the **EC-Council Certified SOC Analyst (CSA)** curriculum (Exam 312-39).

Every day I cover ~20 pages of the official material and turn it into:
- 🧠 **Clear explanations** — no fluff, just what matters
- 🧪 **Working labs** — real Python tools you can run
- 📝 **Blog posts** — published on Medium daily

---

## 📅 Daily Progress

| Day | Module | Topic | Lab | Blog |
|-----|--------|-------|-----|------|
| 01 | Module 01 | Security Operations & Management — SOC Foundations | [→ Lab](day-01/lab/) | [→ Medium](#) |

---

## 🗂️ Repository Structure

```
soc-journey/
├── day-01/
│   ├── README.md              # Day summary & concepts
│   ├── lab/
│   │   ├── soc_workflow_demo.py       # Full SOC pipeline simulator
│   │   ├── soc_log_simulator.py       # Multi-source log generator
│   │   ├── event_correlator.py        # SIEM-style correlation engine
│   │   ├── alert_triage.py            # L1 analyst triage tool
│   │   ├── requirements.txt
│   │   └── sample_logs/
│   │       ├── firewall.log
│   │       ├── ids_alert.log
│   │       └── endpoint.log
│   └── docs/
│       └── references.md
└── ...
```

---

## ⚡ Quick Start

```bash
git clone https://github.com/Odaimherat/soc-journey
cd soc-journey/day-01/lab
pip install -r requirements.txt
python soc_workflow_demo.py
```

---

## 🔗 Follow Along

- 📝 **Medium**: [@YourMediumHandle](#)
- 🐙 **GitHub**: [Odaimherat](https://github.com/Odaimherat)

---

*Built with purpose. One day at a time.* 🛡️
