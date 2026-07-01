#!/usr/bin/env python3
"""
soc_model_comparator.py
-----------------------
Compares the three SOC deployment models — In-House, Outsourced (MSSP), Hybrid —
across eight organizational dimensions and recommends the best fit based on
the organization's specific constraints.
"""

import time
from typing import Dict, List

RESET = "\033[0m"; BOLD = "\033[1m"; CYAN = "\033[96m"; GREEN = "\033[92m"
YELLOW = "\033[93m"; RED = "\033[91m"; DIM = "\033[2m"; WHITE = "\033[97m"
MAGENTA = "\033[95m"; BLUE = "\033[94m"

def c(text, *codes): return "".join(codes) + text + RESET

MODELS = {
    "In-House": {
        "description": "Fully internal SOC. Organization owns infrastructure, tooling, and staffing.",
        "best_for":    "Organizations with high data sensitivity, large security budgets, and long-term security strategy.",
        "time_to_ops": "12-24 months to full capability",
        "cost":        "High upfront. Lower per-incident cost long-term.",
        "dimensions": {
            "Data Sovereignty":       5,
            "Customization":          5,
            "Cost Efficiency":        2,
            "Speed to Deploy":        1,
            "Analyst Expertise":      3,
            "24/7 Coverage":          3,
            "Scalability":            2,
            "Threat Intel Breadth":   2,
        },
        "advantages": [
            "Full control over log data — nothing leaves the organization",
            "Analysts develop deep knowledge of the specific environment",
            "Detection rules can be customized to organizational context",
            "Communication during active incidents is faster internally",
        ],
        "disadvantages": [
            "Takes years to build to full operational maturity",
            "Recruiting skilled analysts is consistently difficult",
            "High upfront capital expenditure required",
            "Return on investment pressure before the team is effective",
        ],
    },
    "Outsourced (MSSP)": {
        "description": "MSSP builds and operates the SOC. Organization pays for the service.",
        "best_for":    "Organizations with limited security budgets, small IT teams, or a need for rapid deployment.",
        "time_to_ops": "4-8 weeks to baseline coverage",
        "cost":        "Low upfront. Higher ongoing per-month cost.",
        "dimensions": {
            "Data Sovereignty":       1,
            "Customization":          2,
            "Cost Efficiency":        4,
            "Speed to Deploy":        5,
            "Analyst Expertise":      4,
            "24/7 Coverage":          5,
            "Scalability":            5,
            "Threat Intel Breadth":   5,
        },
        "advantages": [
            "Operational within weeks rather than years",
            "MSSP analysts bring cross-client threat visibility",
            "No infrastructure investment required",
            "Scales elastically with organizational growth",
        ],
        "disadvantages": [
            "External team lacks deep knowledge of the internal environment",
            "Log data leaves organizational control",
            "Limited ability to customize detection rules",
            "No internal security capability development over time",
        ],
    },
    "Hybrid": {
        "description": "Internal team handles primary operations. MSSP supplements coverage and specialist capability.",
        "best_for":    "Mid-size organizations with partial security staff wanting 24/7 coverage without full internal buildout.",
        "time_to_ops": "6-12 months to full hybrid coverage",
        "cost":        "Medium upfront. Combined internal and vendor ongoing cost.",
        "dimensions": {
            "Data Sovereignty":       3,
            "Customization":          4,
            "Cost Efficiency":        3,
            "Speed to Deploy":        3,
            "Analyst Expertise":      4,
            "24/7 Coverage":          5,
            "Scalability":            4,
            "Threat Intel Breadth":   4,
        },
        "advantages": [
            "Internal knowledge with external maturity and 24/7 coverage",
            "Best approach for organizations that cannot staff overnight",
            "Shared cost reduces upfront burden",
            "Access to MSSP tooling and threat intelligence",
        ],
        "disadvantages": [
            "Coordination between internal and external teams requires discipline",
            "More expensive than pure outsourced over the long term",
            "Data-sharing arrangements with vendor add complexity",
            "Accountability can blur between internal and external teams",
        ],
    },
}

DIMENSIONS = [
    "Data Sovereignty", "Customization", "Cost Efficiency",
    "Speed to Deploy", "Analyst Expertise", "24/7 Coverage",
    "Scalability", "Threat Intel Breadth",
]

WEIGHTS = {
    "Data Sovereignty":     0.20,
    "Customization":        0.10,
    "Cost Efficiency":      0.15,
    "Speed to Deploy":      0.10,
    "Analyst Expertise":    0.15,
    "24/7 Coverage":        0.15,
    "Scalability":          0.05,
    "Threat Intel Breadth": 0.10,
}

def banner():
    print(c("\n" + "="*65, BOLD, CYAN))
    print(c("  SOC MODEL COMPARATOR", BOLD, WHITE))
    print(c("  In-House vs Outsourced (MSSP) vs Hybrid", DIM))
    print(c("="*65 + "\n", BOLD, CYAN))

def print_comparison():
    bar_max = 25
    print(c("  DIMENSION COMPARISON (score out of 5)\n", BOLD, WHITE))
    header = f"  {'Dimension':<28s}  {'In-House':^12s}  {'MSSP':^12s}  {'Hybrid':^12s}"
    print(c(header, BOLD))
    print(c("  " + "-"*62, DIM))

    for dim in DIMENSIONS:
        scores = {m: MODELS[m]["dimensions"][dim] for m in MODELS}
        best   = max(scores.values())
        row    = f"  {dim:<28s}"
        for model in ["In-House", "Outsourced (MSSP)", "Hybrid"]:
            s      = scores[model]
            filled = int((s / 5) * 8)
            bar    = "=" * filled + "-" * (8 - filled)
            col    = GREEN if s == best else YELLOW if s >= 3 else RED
            row   += f"  {c(f'{bar} {s}', col):^20s}"
        print(row)

def get_org_profile() -> Dict[str, int]:
    print(c("\n\n  ORGANIZATIONAL PROFILE\n", BOLD, CYAN))
    print(c("  Answer these questions to get a model recommendation.", DIM))
    print(c("  Score 1 (low priority) to 5 (critical requirement).\n", DIM))

    questions = {
        "Data Sovereignty":     "How critical is it that log data never leaves your infrastructure?",
        "Cost Efficiency":      "How constrained is your security budget?",
        "Speed to Deploy":      "How urgently do you need SOC capability operational?",
        "24/7 Coverage":        "How important is 24/7 coverage without large internal headcount?",
        "Customization":        "How important is it to customize detection rules to your environment?",
    }
    profile = {}
    for dim, question in questions.items():
        print(c(f"  {question}", WHITE))
        while True:
            try:
                val = int(input(c("  Score (1-5): ", YELLOW)))
                if 1 <= val <= 5:
                    profile[dim] = val
                    break
                print(c("  Enter 1-5.", RED))
            except ValueError:
                print(c("  Enter a number.", RED))
        print()
    return profile

def recommend(profile: Dict[str, int]) -> str:
    scores: Dict[str, float] = {}
    for model_name, model_data in MODELS.items():
        score = 0.0
        for dim, user_priority in profile.items():
            model_score = model_data["dimensions"].get(dim, 3)
            weight      = user_priority / 5.0
            score      += model_score * weight
        scores[model_name] = score
    return max(scores, key=lambda m: scores[m]), scores

def print_report(profile, recommendation, scores):
    print(c("\n\n" + "="*65, BOLD))
    print(c("  SOC MODEL RECOMMENDATION", BOLD, CYAN))
    print(c("="*65, BOLD))

    for model_name, score in sorted(scores.items(), key=lambda x: x[1], reverse=True):
        col  = GREEN if model_name == recommendation else YELLOW if score == sorted(scores.values())[-1] else RED
        star = " <-- RECOMMENDED" if model_name == recommendation else ""
        print(f"  {c(model_name, col, BOLD):<30s}  Score: {c(f'{score:.2f}', col)}{c(star, GREEN, BOLD)}")

    print(c("\n" + "="*65, BOLD))
    rec = MODELS[recommendation]
    print(c(f"\n  Recommended Model: {recommendation}", BOLD, GREEN))
    print(c(f"\n  {rec['description']}", DIM))
    print(c(f"\n  Best for     : {rec['best_for']}", WHITE))
    print(c(f"  Time to ops  : {rec['time_to_ops']}", WHITE))
    print(c(f"  Cost profile : {rec['cost']}", WHITE))

    print(c("\n  Advantages:", BOLD))
    for a in rec["advantages"]:
        print(c(f"    + {a}", GREEN))

    print(c("\n  Disadvantages:", BOLD))
    for d in rec["disadvantages"]:
        print(c(f"    - {d}", YELLOW))

    print(c("\n" + "="*65 + "\n", BOLD))

def main():
    banner()
    print_comparison()
    profile = get_org_profile()
    recommendation, scores = recommend(profile)
    print_report(profile, recommendation, scores)

if __name__ == "__main__":
    main()
