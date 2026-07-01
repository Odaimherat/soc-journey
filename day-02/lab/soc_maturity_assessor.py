#!/usr/bin/env python3
"""
soc_maturity_assessor.py
------------------------
Interactive SOC maturity assessment tool based on the SOC-CMM framework.

Evaluates five SOC domains across the SOC-CMM 0-5 maturity scale:
  - People and Training
  - Process and Procedure
  - Technology and Tooling
  - Detection and Response
  - Governance and Compliance

Produces a maturity score, domain breakdown, and prioritized improvement roadmap.
"""

import time
from dataclasses import dataclass, field
from typing import List, Dict


RESET = "\033[0m"; BOLD = "\033[1m"; CYAN = "\033[96m"; GREEN = "\033[92m"
YELLOW = "\033[93m"; RED = "\033[91m"; DIM = "\033[2m"; WHITE = "\033[97m"
MAGENTA = "\033[95m"; BLUE = "\033[94m"

def c(text, *codes): return "".join(codes) + text + RESET

MATURITY_LEVELS = {
    0: ("Non-Existent",           RED,     "No processes exist. Aspects are entirely unmanaged."),
    1: ("Initial",                RED,     "Ad hoc, inconsistent. Depends on individual knowledge."),
    2: ("Defined",                YELLOW,  "Processes documented and checked for compliance."),
    3: ("Managed",                YELLOW,  "Actively managed and monitored against metrics."),
    4: ("Quantitatively Managed", CYAN,    "Measured for quality, quantity, and timeliness."),
    5: ("Optimizing",             GREEN,   "Continuous improvement through structured good practices."),
}

@dataclass
class AssessmentQuestion:
    domain:   str
    question: str
    weight:   float = 1.0

@dataclass
class DomainResult:
    domain:    str
    score:     float
    answers:   List[int] = field(default_factory=list)
    gaps:      List[str] = field(default_factory=list)

ASSESSMENT = [
    # People and Training
    AssessmentQuestion("People and Training",
        "Do all SOC analysts have documented roles and clearly defined responsibilities?"),
    AssessmentQuestion("People and Training",
        "Is there a structured onboarding process for new SOC analysts?"),
    AssessmentQuestion("People and Training",
        "Are analysts required to complete ongoing training on new threats and techniques?"),
    AssessmentQuestion("People and Training",
        "Does the SOC have dedicated Threat Hunter or L2+ analyst capacity?"),

    # Process and Procedure
    AssessmentQuestion("Process and Procedure",
        "Are all incident triage, escalation, and closure steps documented in runbooks?"),
    AssessmentQuestion("Process and Procedure",
        "Is there a formal post-incident review process that drives rule improvements?"),
    AssessmentQuestion("Process and Procedure",
        "Are shift handover procedures documented and consistently followed?"),
    AssessmentQuestion("Process and Procedure",
        "Is there a vulnerability management process with defined remediation SLAs?"),

    # Technology and Tooling
    AssessmentQuestion("Technology and Tooling",
        "Does the SOC have a SIEM that collects logs from all critical sources?"),
    AssessmentQuestion("Technology and Tooling",
        "Are correlation rules actively maintained and reviewed for effectiveness?"),
    AssessmentQuestion("Technology and Tooling",
        "Does the SOC use endpoint detection and response (EDR) tooling?"),
    AssessmentQuestion("Technology and Tooling",
        "Is response automation (SOAR or scripted playbooks) in place for common alert types?"),

    # Detection and Response
    AssessmentQuestion("Detection and Response",
        "Can the SOC detect lateral movement across internal network segments?"),
    AssessmentQuestion("Detection and Response",
        "Are MITRE ATT&CK techniques mapped to existing detection coverage?"),
    AssessmentQuestion("Detection and Response",
        "Is mean time to detect (MTTD) tracked and trending downward over time?"),
    AssessmentQuestion("Detection and Response",
        "Does the SOC have documented playbooks for the top ten most likely incident types?"),

    # Governance and Compliance
    AssessmentQuestion("Governance and Compliance",
        "Are SOC KPIs defined, tracked, and reported to senior leadership?"),
    AssessmentQuestion("Governance and Compliance",
        "Does the SOC have a formal review cycle (quarterly or more frequent)?"),
    AssessmentQuestion("Governance and Compliance",
        "Are log retention policies aligned with applicable regulatory requirements?"),
    AssessmentQuestion("Governance and Compliance",
        "Is there executive sponsorship with a defined security budget for SOC operations?"),
]

DOMAIN_GAPS = {
    "People and Training": [
        "Develop role-specific training paths for L1, L2, and IR analysts",
        "Implement quarterly tabletop exercises to test analyst judgment under pressure",
        "Create a knowledge transfer program to reduce dependency on key individuals",
        "Build a threat hunter position and define its scope and tooling",
    ],
    "Process and Procedure": [
        "Document triage, escalation, and closure runbooks for all known alert types",
        "Formalize post-incident review as a mandatory step for all HIGH and CRITICAL incidents",
        "Standardize shift handover with a written checklist and open-incident summary",
        "Define and enforce SLAs for vulnerability remediation by severity",
    ],
    "Technology and Tooling": [
        "Audit log source coverage — identify devices not forwarding to the SIEM",
        "Review and tune correlation rules quarterly to reduce false positive rate",
        "Deploy EDR to all endpoints including servers and workstations",
        "Implement automated playbooks for password reset, IP block, and host isolation",
    ],
    "Detection and Response": [
        "Map current detection rules to MITRE ATT&CK and identify coverage gaps",
        "Build network segmentation monitoring to surface east-west lateral movement",
        "Begin tracking MTTD and MTTR as core operational metrics",
        "Write response playbooks for ransomware, credential theft, and C2 beaconing",
    ],
    "Governance and Compliance": [
        "Define and publish SOC KPIs to leadership on a monthly cadence",
        "Schedule quarterly SOC reviews against a defined capability baseline",
        "Audit log retention policy against NIST, PCI-DSS, and applicable industry regulations",
        "Secure executive sponsorship with a multi-year SOC budget commitment",
    ],
}

def banner():
    print(c("\n" + "="*65, BOLD, CYAN))
    print(c("  SOC MATURITY ASSESSOR — SOC-CMM Framework", BOLD, WHITE))
    print(c("  Evaluating five domains across a 0-5 maturity scale", DIM))
    print(c("="*65 + "\n", BOLD, CYAN))

def ask_score(question: str, q_num: int, total: int) -> int:
    print(c(f"\n  [{q_num}/{total}]", BOLD, MAGENTA), c(question, WHITE))
    print(c("  Rate from 0 (not done) to 5 (fully optimized):", DIM))
    for lvl in range(6):
        name, color, desc = MATURITY_LEVELS[lvl]
        print(c(f"    {lvl}", color, BOLD) + c(f"  {name}: {desc}", DIM))
    while True:
        try:
            val = int(input(c("\n  Your score (0-5): ", YELLOW)))
            if 0 <= val <= 5:
                return val
            print(c("  Enter a number between 0 and 5.", RED))
        except ValueError:
            print(c("  Enter a number.", RED))

def run_assessment() -> List[DomainResult]:
    questions_by_domain: Dict[str, List[AssessmentQuestion]] = {}
    for q in ASSESSMENT:
        questions_by_domain.setdefault(q.domain, []).append(q)

    results = []
    q_num = 0
    total = len(ASSESSMENT)

    for domain, questions in questions_by_domain.items():
        print(c(f"\n\n  DOMAIN: {domain}", BOLD, CYAN))
        print(c("  " + "-"*60, DIM))
        scores = []
        for q in questions:
            q_num += 1
            score = ask_score(q.question, q_num, total)
            scores.append(score)
            time.sleep(0.1)

        domain_score = sum(scores) / len(scores)
        gap_level = max(0, round(domain_score))
        gaps = DOMAIN_GAPS[domain][gap_level:] if gap_level < 4 else []
        results.append(DomainResult(domain=domain, score=domain_score,
                                    answers=scores, gaps=gaps))
        print(c(f"\n  Domain score: {domain_score:.1f}/5.0", GREEN if domain_score >= 3 else YELLOW if domain_score >= 2 else RED))

    return results

def print_report(results: List[DomainResult]):
    overall = sum(r.score for r in results) / len(results)
    level   = min(5, round(overall))
    name, color, desc = MATURITY_LEVELS[level]

    print(c("\n\n" + "="*65, BOLD))
    print(c("  SOC MATURITY ASSESSMENT REPORT", BOLD, CYAN))
    print(c("="*65, BOLD))
    print(f"  Overall Score    : {c(f'{overall:.2f}/5.00', color, BOLD)}")
    print(f"  Maturity Level   : {c(f'Level {level} — {name}', color, BOLD)}")
    print(c(f"  Summary          : {desc}", DIM))
    print(c("="*65, BOLD))

    print(c("\n  DOMAIN BREAKDOWN\n", BOLD, WHITE))
    bar_width = 30
    for r in sorted(results, key=lambda x: x.score):
        filled = int((r.score / 5.0) * bar_width)
        bar    = "=" * filled + "-" * (bar_width - filled)
        lv     = min(5, round(r.score))
        col    = MATURITY_LEVELS[lv][1]
        print(f"  {r.domain:<30s}  [{c(bar, col)}]  {c(f'{r.score:.1f}', col, BOLD)}")

    print(c("\n  PRIORITIZED IMPROVEMENT ROADMAP\n", BOLD, WHITE))
    weakest = sorted(results, key=lambda x: x.score)
    for r in weakest:
        if r.gaps:
            print(c(f"\n  {r.domain} (score: {r.score:.1f})", BOLD, YELLOW))
            for i, gap in enumerate(r.gaps[:3], 1):
                print(c(f"    {i}. {gap}", DIM))

    print(c("\n" + "="*65, BOLD))
    if overall < 2:
        next_step = "Focus immediately on documenting processes and establishing basic tooling."
    elif overall < 3:
        next_step = "Standardize existing practices and begin tracking KPIs."
    elif overall < 4:
        next_step = "Introduce automation and map detection coverage to MITRE ATT&CK."
    else:
        next_step = "Drive continuous improvement through structured review cycles."
    print(c(f"  Next Step: {next_step}", CYAN))
    print(c("="*65 + "\n", BOLD))

    import json, datetime
    report = {
        "timestamp":      datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "overall_score":  round(overall, 2),
        "maturity_level": level,
        "maturity_name":  name,
        "domains": [{"domain": r.domain, "score": round(r.score, 2),
                     "answers": r.answers, "gaps": r.gaps} for r in results],
    }
    with open("maturity_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(c("  Report saved to maturity_report.json\n", GREEN))

if __name__ == "__main__":
    banner()
    print(c("  This tool walks you through 20 questions across five SOC domains.", DIM))
    print(c("  Score each question 0-5 based on your current SOC state.", DIM))
    print(c("  At the end you will receive a maturity score and improvement roadmap.\n", DIM))
    input(c("  Press ENTER to begin the assessment.", YELLOW))
    results = run_assessment()
    print_report(results)
