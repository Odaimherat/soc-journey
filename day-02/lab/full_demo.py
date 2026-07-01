#!/usr/bin/env python3
"""
full_demo.py
------------
Runs all Day 02 lab tools in sequence with explanatory context between each.

Tools executed:
  1. kpi_dashboard.py         — generates and reports 7-day KPI data
  2. soc_model_comparator.py  — compares deployment models (interactive)
  3. soc_maturity_assessor.py — runs full maturity assessment (interactive)
  4. soc_vs_noc_analyzer.py   — classifies SOC vs NOC events

Run individual tools directly for focused use.
"""

import subprocess
import sys
import time

RESET = "\033[0m"; BOLD = "\033[1m"; CYAN = "\033[96m"; GREEN = "\033[92m"
YELLOW = "\033[93m"; DIM = "\033[2m"; WHITE = "\033[97m"

def c(text, *codes): return "".join(codes) + text + RESET

TOOLS = [
    ("kpi_dashboard.py",        "SOC KPI Dashboard",        "Generates a 7-day operational metrics report and identifies SLA breaches."),
    ("soc_vs_noc_analyzer.py",  "SOC vs NOC Classifier",    "Classifies 15 real-world operational events as SOC or NOC responsibility."),
    ("soc_model_comparator.py", "SOC Model Comparator",     "Compares In-House vs MSSP vs Hybrid and recommends a model for your context."),
    ("soc_maturity_assessor.py","SOC Maturity Assessor",    "Runs a 20-question SOC-CMM maturity assessment and produces a roadmap."),
]

def banner():
    print(c("\n" + "="*65, BOLD, CYAN))
    print(c("  DAY 02 — FULL LAB DEMO", BOLD, WHITE))
    print(c("  SOC Processes, Models, Maturity, KPIs, and SOC vs NOC", DIM))
    print(c("="*65 + "\n", BOLD, CYAN))
    print(c("  This runs all four lab tools in sequence.", DIM))
    print(c("  Two tools are interactive — follow the prompts.\n", DIM))

def run_tool(script, title, description, num, total):
    print(c(f"\n{'─'*65}", BOLD))
    print(c(f"  TOOL {num}/{total}  |  {title}", BOLD, YELLOW))
    print(c(f"  {description}", DIM))
    print(c(f"{'─'*65}\n", BOLD))
    time.sleep(0.5)
    result = subprocess.run([sys.executable, script])
    return result.returncode == 0

def main():
    banner()
    input(c("  Press ENTER to start.", YELLOW))

    for i, (script, title, desc) in enumerate(TOOLS, 1):
        success = run_tool(script, title, desc, i, len(TOOLS))
        if not success:
            print(c(f"\n  Warning: {script} exited with an error. Continuing.\n", YELLOW))
        if i < len(TOOLS):
            print(c(f"\n  Tool {i} complete. Next: {TOOLS[i][1]}", GREEN))
            input(c("  Press ENTER to continue.", YELLOW))

    print(c("\n\n" + "="*65, BOLD, GREEN))
    print(c("  DAY 02 LAB COMPLETE", BOLD, WHITE))
    print(c("="*65, BOLD, GREEN))
    print(c("  Files generated:", CYAN))
    for f in ["kpi_report.json", "maturity_report.json"]:
        print(c(f"    {f}", DIM))
    print(c("\n  Day 03 topic: Cyber Threats, Threat Actors, and the Kill Chain\n", DIM))

if __name__ == "__main__":
    main()
