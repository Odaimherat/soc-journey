#!/usr/bin/env python3
"""
soc_workflow_demo.py
--------------------
Orchestrates the full SOC operational pipeline end to end:

  COLLECT -> INGEST -> VALIDATE -> REPORT -> RESPOND -> DOCUMENT

Run this script for the complete demonstration.
Requires soc_log_simulator.py, event_correlator.py, and alert_triage.py
to be in the same directory.
"""

import subprocess
import sys
import time
import os


RESET = "\033[0m"; BOLD = "\033[1m"; CYAN = "\033[96m"; GREEN = "\033[92m"
YELLOW = "\033[93m"; RED = "\033[91m"; DIM = "\033[2m"; WHITE = "\033[97m"

def c(text, *codes): return "".join(codes) + text + RESET


PIPELINE_STAGES = [
    ("COLLECT",   "soc_log_simulator.py",  "Ingest logs from Firewall, IDS, Endpoint, Auth Server"),
    ("INGEST",    None,                    "SIEM normalizes and indexes all raw log data"),
    ("VALIDATE",  "event_correlator.py",   "Correlation engine fires rules and generates alerts"),
    ("REPORT",    "alert_triage.py",       "L1 Analyst triages the alert queue and creates tickets"),
    ("RESPOND",   None,                    "L2 and IR team receives escalated tickets and acts"),
    ("DOCUMENT",  None,                    "Incidents documented for audit and lessons learned"),
]


def banner():
    print(c("\n" + "="*65, BOLD, CYAN))
    print(c("  SOC WORKFLOW PIPELINE — FULL DEMONSTRATION", BOLD, WHITE))
    print(c("  Security Operations and Management", DIM))
    print(c("="*65 + "\n", BOLD, CYAN))


def step_header(num: int, stage: str, description: str):
    print(c(f"\n{'─'*65}", BOLD))
    print(c(f"  STEP {num}/6  |  {stage}", BOLD, YELLOW) + c(f"  {description}", DIM))
    print(c(f"{'─'*65}", BOLD))


def run_script(script: str) -> bool:
    if not os.path.exists(script):
        print(c(f"  Script not found: {script}", YELLOW))
        return False
    result = subprocess.run([sys.executable, script])
    return result.returncode == 0


def simulate_processing(label: str, duration: float = 1.2):
    """Displays an in-progress indicator for simulated processing steps."""
    chars = ["|", "/", "-", "\\"]
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        print(f"\r  {c(chars[i % 4], CYAN)}  {label}...", end="", flush=True)
        time.sleep(0.1)
        i += 1
    print(f"\r  {c('Done', GREEN, BOLD)}  {label}")


def main():
    banner()
    print(c("  This demonstration runs the complete SOC workflow from raw log ingestion", DIM))
    print(c("  through incident triage and response documentation.", DIM))
    print(c("\n  Press ENTER to start the pipeline.", YELLOW), end="")
    input()

    # Step 1 — COLLECT
    step_header(1, "COLLECT", PIPELINE_STAGES[0][2])
    print(c("\n  Collecting logs from four sources: Firewall, IDS, Endpoint, Auth Server\n", CYAN))
    time.sleep(0.5)
    run_script("soc_log_simulator.py")

    # Step 2 — INGEST (simulated)
    step_header(2, "INGEST", PIPELINE_STAGES[1][2])
    simulate_processing("Normalizing log formats across all sources",     1.0)
    simulate_processing("Parsing and validating timestamps",              0.8)
    simulate_processing("Enriching IP addresses with threat intel feeds", 1.2)
    simulate_processing("Indexing events into SIEM data store",           1.0)
    simulate_processing("Building behavioral correlation baseline",       0.8)

    # Step 3 — VALIDATE
    step_header(3, "VALIDATE", PIPELINE_STAGES[2][2])
    print(c("\n  Running correlation rules against ingested event data...\n", CYAN))
    time.sleep(0.5)
    run_script("event_correlator.py")

    # Step 4 — REPORT / TRIAGE
    step_header(4, "REPORT", PIPELINE_STAGES[3][2])
    print(c("\n  L1 SOC Analyst processing alert queue...\n", CYAN))
    time.sleep(0.5)
    run_script("alert_triage.py")

    # Step 5 — RESPOND (simulated)
    step_header(5, "RESPOND", PIPELINE_STAGES[4][2])
    simulate_processing("L2 Analyst receiving escalated tickets",                  0.8)
    simulate_processing("Incident Responder assigned to CRITICAL cases",           0.8)
    simulate_processing("Containment: isolating compromised host 192.168.1.25",    1.2)
    simulate_processing("Blocking malicious IPs at network perimeter",             1.0)
    simulate_processing("Initiating malware analysis on collected samples",        0.8)
    simulate_processing("Notifying CISO of active incident",                       0.5)
    print(c("\n  Incident response actions executed.", GREEN, BOLD))

    # Step 6 — DOCUMENT
    step_header(6, "DOCUMENT", PIPELINE_STAGES[5][2])
    simulate_processing("Writing incident report",                         1.0)
    simulate_processing("Recording full event timeline",                   0.8)
    simulate_processing("Updating detection rules with new indicators",    0.8)
    simulate_processing("Scheduling post-incident review",                 0.5)
    simulate_processing("Archiving logs for compliance retention",         0.8)

    # Final summary
    artifacts = [f for f in ["ingested_logs.json","correlated_alerts.json","triage_tickets.json"]
                 if os.path.exists(f)]

    print(c("\n\n" + "="*65, BOLD, GREEN))
    print(c("  PIPELINE COMPLETE — ALL STAGES EXECUTED", BOLD, WHITE))
    print(c("="*65, BOLD, GREEN))
    print(f"  Artifacts generated  : {', '.join(artifacts) if artifacts else 'none'}")
    print(c("\n  Next steps:", YELLOW))
    print(c("    Review triage_tickets.json for all L2 escalations", DIM))
    print(c("    Use correlated_alerts.json to tune detection rules", DIM))
    print(c("    Use ingested_logs.json for forensic timeline analysis", DIM))
    print(c("\n" + "="*65 + "\n", BOLD, GREEN))


if __name__ == "__main__":
    main()
