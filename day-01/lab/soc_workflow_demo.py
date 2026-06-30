#!/usr/bin/env python3
"""
SOC Workflow Demo — Full Pipeline
===================================
Runs the complete SOC workflow end-to-end:

  COLLECT → INGEST → VALIDATE → REPORT → RESPOND → DOCUMENT

This is the master script. Run this for the full experience.

Day 01 — SOC Analyst Journey | EC-Council CSA Module 01
"""

import subprocess
import sys
import time
import os

C = {
    "CYN": "\033[96m", "GRN": "\033[92m", "YLW": "\033[93m",
    "RED": "\033[91m",  "BLD": "\033[1m",  "RST": "\033[0m",
    "MAG": "\033[95m",  "WHT": "\033[97m", "DIM": "\033[2m",
}
def c(text, *keys): return "".join(C.get(k,"") for k in keys) + text + C["RST"]

PIPELINE = [
    ("COLLECT",  "soc_log_simulator.py",  "Ingest logs from Firewall, IDS, Endpoint, Auth"),
    ("INGEST",   None,                    "SIEM normalizes & indexes all raw log data"),
    ("VALIDATE", "event_correlator.py",   "Correlation engine fires rules → alerts generated"),
    ("REPORT",   "alert_triage.py",       "L1 Analyst triages alerts → tickets created"),
    ("RESPOND",  None,                    "L2 + IR team receives escalated tickets"),
    ("DOCUMENT", None,                    "Incidents documented for audit & lessons learned"),
]

def banner():
    print(c("\n" + "╔" + "═"*63 + "╗", "BLD", "CYN"))
    print(c("║" + " "*63 + "║", "BLD", "CYN"))
    print(c("║     🛡️  FULL SOC WORKFLOW PIPELINE DEMONSTRATION        ║", "BLD", "WHT"))
    print(c("║     EC-Council CSA | Module 01 | Day 01                ║", "BLD", "CYN"))
    print(c("║" + " "*63 + "║", "BLD", "CYN"))
    print(c("╚" + "═"*63 + "╝", "BLD", "CYN"))
    print()

def step_header(step_num, stage, description):
    print(c(f"\n{'━'*65}", "BLD"))
    print(c(f"  STEP {step_num}/6  │  {stage}", "BLD", "YLW") + c(f"  ← {description}", "DIM"))
    print(c(f"{'━'*65}", "BLD"))

def run_script(script):
    if not os.path.exists(script):
        print(c(f"  ⚠️  {script} not found in current directory.", "YLW"))
        return False
    result = subprocess.run([sys.executable, script], capture_output=False)
    return result.returncode == 0

def simulate_step(description, duration=1.5):
    steps = ["⣾","⣽","⣻","⢿","⡿","⣟","⣯","⣷"]
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        print(f"\r  {c(steps[i % len(steps)],'CYN')} {description}...", end="", flush=True)
        time.sleep(0.1)
        i += 1
    print(f"\r  {c('✅','GRN')} {description}... {c('Done','GRN','BLD')}")

def main():
    banner()
    print(c("  This demo runs the complete SOC workflow from raw logs", "DIM"))
    print(c("  to documented incident tickets — just like a real SOC.", "DIM"))
    print(c("\n  Press ENTER to start the pipeline...", "YLW"), end="")
    input()

    # Step 1: COLLECT
    step_header(1, "COLLECT", PIPELINE[0][2])
    print(c("\n  Simulating real-time log collection from 4 sources:", "CYN"))
    print(c("    🔥 Firewall  │  🚨 IDS/IPS  │  💻 Endpoint  │  🔑 Auth Server\n", "WHT"))
    time.sleep(0.5)
    run_script("soc_log_simulator.py")

    # Step 2: INGEST (simulate)
    step_header(2, "INGEST", PIPELINE[1][2])
    simulate_step("Normalizing log formats", 1.0)
    simulate_step("Parsing timestamps and fields", 0.8)
    simulate_step("Enriching IPs with threat intel feeds", 1.2)
    simulate_step("Indexing events into SIEM datastore", 1.0)
    simulate_step("Building correlation baseline", 0.8)

    # Step 3: VALIDATE / CORRELATE
    step_header(3, "VALIDATE", PIPELINE[2][2])
    print(c("\n  Running SIEM correlation rules against ingested data...\n", "CYN"))
    time.sleep(0.5)
    run_script("event_correlator.py")

    # Step 4: REPORT / TRIAGE
    step_header(4, "REPORT", PIPELINE[3][2])
    print(c("\n  L1 SOC Analyst reviewing alert queue...\n", "CYN"))
    time.sleep(0.5)
    run_script("alert_triage.py")

    # Step 5: RESPOND (simulate)
    step_header(5, "RESPOND", PIPELINE[4][2])
    simulate_step("L2 Analyst receiving escalated tickets", 0.8)
    simulate_step("Incident Responder assigned to CRITICAL cases", 0.8)
    simulate_step("Containment action: isolating compromised host 192.168.1.25", 1.2)
    simulate_step("Blocking malicious IPs at perimeter firewall", 1.0)
    simulate_step("Initiating malware analysis on collected samples", 0.8)
    simulate_step("Notifying CISO of active incident", 0.5)
    print(c("\n  ⚡ Incident Response actions executed.", "GRN", "BLD"))

    # Step 6: DOCUMENT
    step_header(6, "DOCUMENT", PIPELINE[5][2])
    simulate_step("Writing incident report", 1.0)
    simulate_step("Logging timeline of events", 0.8)
    simulate_step("Updating SOC runbook with new IoCs", 0.8)
    simulate_step("Scheduling post-incident review", 0.5)
    simulate_step("Archiving logs for compliance", 0.8)

    # Final summary
    print(c("\n\n" + "╔" + "═"*63 + "╗", "BLD", "GRN"))
    print(c("║                                                               ║", "BLD", "GRN"))
    print(c("║   ✅  PIPELINE COMPLETE — SOC WORKFLOW EXECUTED              ║", "BLD", "WHT"))
    print(c("║                                                               ║", "BLD", "GRN"))
    print(c("╠" + "═"*63 + "╣", "BLD", "GRN"))
    files = [f for f in ["ingested_logs.json","correlated_alerts.json","triage_tickets.json"] if os.path.exists(f)]
    print(c(f"║   📁 Artifacts generated: {', '.join(files):<36}║", "GRN"))
    print(c("║                                                               ║", "BLD", "GRN"))
    print(c("║   📌 Next: Review triage_tickets.json for L2 escalations     ║", "YLW"))
    print(c("║   📌 Module 02 tomorrow: Logs & Log Management               ║", "YLW"))
    print(c("║                                                               ║", "BLD", "GRN"))
    print(c("╚" + "═"*63 + "╝\n", "BLD", "GRN"))

if __name__ == "__main__":
    main()
