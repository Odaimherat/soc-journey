# SOC Analyst Journey

A daily, hands-on deep dive into Security Operations — building real tools, writing real labs, and documenting every concept clearly.

Each day covers a core topic in security operations with working code you can run, study, and build on.

---

## Structure

```
soc-journey/
├── day-01/
│   ├── README.md
│   ├── lab/
│   │   ├── soc_workflow_demo.py
│   │   ├── soc_log_simulator.py
│   │   ├── event_correlator.py
│   │   ├── alert_triage.py
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

## Topics Covered

| Day | Topic | Lab |
|-----|-------|-----|
| 01  | Security Operations and Management — SOC Foundations | [Day 01](day-01/) |

---

## Quick Start

```bash
git clone https://github.com/Odaimherat/soc-journey
cd soc-journey/day-01/lab
python soc_workflow_demo.py
```

Requirements: Python 3.8 or higher. No external packages needed.

---

## About

Practical security operations content. Every lab runs locally. Every concept is explained in plain language backed by cited sources.
