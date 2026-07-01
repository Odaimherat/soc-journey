#!/usr/bin/env python3
"""
kpi_dashboard.py
----------------
Simulates a live SOC KPI dashboard.

Tracks and displays eight KPIs defined in the SOC-CMM framework:
  - Response Time
  - Completion Time
  - First-Time Fix Rate
  - Transfer Rate
  - Client Satisfaction
  - System Availability
  - Operations Audit Score
  - Overtime Efficiency

Generates a simulated week of SOC operational data and reports
against defined SLA targets.
"""

import random
import time
import json
import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict

RESET = "\033[0m"; BOLD = "\033[1m"; CYAN = "\033[96m"; GREEN = "\033[92m"
YELLOW = "\033[93m"; RED = "\033[91m"; DIM = "\033[2m"; WHITE = "\033[97m"

def c(text, *codes): return "".join(codes) + text + RESET


@dataclass
class KPITarget:
    name:        str
    unit:        str
    target:      float
    direction:   str   # "lower" or "higher" — which direction is better
    description: str


@dataclass
class DailyKPI:
    date:                str
    response_time_min:   float
    completion_rate_pct: float
    first_fix_rate_pct:  float
    transfer_rate_pct:   float
    satisfaction_score:  float
    availability_pct:    float
    audit_score:         float
    overtime_pct:        float
    incidents_total:     int
    incidents_critical:  int
    false_positive_rate: float


KPI_TARGETS = [
    KPITarget("Response Time",       "minutes", 15.0,  "lower",  "Mean time from alert to first analyst action"),
    KPITarget("Completion Rate",     "%",       95.0,  "higher", "Incidents closed within SLA window"),
    KPITarget("First-Time Fix Rate", "%",       85.0,  "higher", "Incidents resolved without re-assignment"),
    KPITarget("Transfer Rate",       "%",        5.0,  "lower",  "Incidents re-assigned due to incorrect triage"),
    KPITarget("Satisfaction Score",  "/5.0",     4.2,  "higher", "Internal stakeholder satisfaction with SOC response"),
    KPITarget("System Availability", "%",       99.5,  "higher", "Uptime of critical SOC infrastructure"),
    KPITarget("Audit Score",         "%",       90.0,  "higher", "Operations audit result — process adherence"),
    KPITarget("Overtime Efficiency", "%",       10.0,  "lower",  "Unbillable overtime as percentage of total hours"),
]


def generate_week() -> List[DailyKPI]:
    days = []
    base_date = datetime.date.today() - datetime.timedelta(days=7)
    for i in range(7):
        date = (base_date + datetime.timedelta(days=i)).strftime("%Y-%m-%d")
        # Simulate realistic daily variation with slight degradation mid-week
        midweek_factor = 1.0 if i < 2 or i > 5 else 1.15
        days.append(DailyKPI(
            date                = date,
            response_time_min   = round(random.uniform(8, 22) * midweek_factor, 1),
            completion_rate_pct = round(random.uniform(88, 99), 1),
            first_fix_rate_pct  = round(random.uniform(78, 95), 1),
            transfer_rate_pct   = round(random.uniform(2, 12) * midweek_factor, 1),
            satisfaction_score  = round(random.uniform(3.6, 5.0), 2),
            availability_pct    = round(random.uniform(99.1, 100.0), 2),
            audit_score         = round(random.uniform(82, 98), 1),
            overtime_pct        = round(random.uniform(3, 18) * midweek_factor, 1),
            incidents_total     = random.randint(45, 220),
            incidents_critical  = random.randint(1, 12),
            false_positive_rate = round(random.uniform(12, 35), 1),
        ))
    return days


def kpi_status(value: float, target: float, direction: str):
    if direction == "lower":
        if value <= target:             return GREEN, "ON TARGET"
        elif value <= target * 1.25:    return YELLOW, "AT RISK"
        else:                           return RED, "BREACH"
    else:
        if value >= target:             return GREEN, "ON TARGET"
        elif value >= target * 0.90:    return YELLOW, "AT RISK"
        else:                           return RED, "BREACH"


def banner():
    print(c("\n" + "="*70, BOLD, CYAN))
    print(c("  SOC KPI DASHBOARD — 7-Day Operational Report", BOLD, WHITE))
    print(c(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", DIM))
    print(c("="*70 + "\n", BOLD, CYAN))


def print_daily_trend(days: List[DailyKPI]):
    print(c("  DAILY INCIDENT VOLUME\n", BOLD, WHITE))
    max_vol = max(d.incidents_total for d in days)
    for day in days:
        bar_len = int((day.incidents_total / max_vol) * 35)
        bar     = "=" * bar_len
        col     = RED if day.incidents_total > 150 else YELLOW if day.incidents_total > 100 else GREEN
        print(f"  {day.date}  {c(f'{bar:<35s}', col)}  {c(str(day.incidents_total), col, BOLD)} incidents"
              f"  ({c(str(day.incidents_critical), RED)} critical)")
    print()


def print_kpi_summary(days: List[DailyKPI]):
    values = {
        "Response Time":       [d.response_time_min   for d in days],
        "Completion Rate":     [d.completion_rate_pct for d in days],
        "First-Time Fix Rate": [d.first_fix_rate_pct  for d in days],
        "Transfer Rate":       [d.transfer_rate_pct   for d in days],
        "Satisfaction Score":  [d.satisfaction_score  for d in days],
        "System Availability": [d.availability_pct    for d in days],
        "Audit Score":         [d.audit_score         for d in days],
        "Overtime Efficiency": [d.overtime_pct        for d in days],
    }

    print(c("  7-DAY KPI SUMMARY\n", BOLD, WHITE))
    print(c(f"  {'KPI':<26s}  {'7d Avg':>9s}  {'Target':>9s}  {'Unit':<8s}  Status", BOLD))
    print(c("  " + "-"*65, DIM))

    breaches = []
    for kpi in KPI_TARGETS:
        vals  = values[kpi.name]
        avg   = sum(vals) / len(vals)
        col, status = kpi_status(avg, kpi.target, kpi.direction)
        unit  = kpi.unit
        print(f"  {kpi.name:<26s}  {c(f'{avg:>8.2f}', col)}  {kpi.target:>9.1f}  {unit:<8s}  {c(status, col, BOLD)}")
        if status == "BREACH":
            breaches.append((kpi.name, avg, kpi.target, kpi.direction))

    print(c("\n  " + "="*65, BOLD))
    if breaches:
        print(c("\n  SLA BREACHES REQUIRING ACTION:\n", RED, BOLD))
        for name, avg, target, direction in breaches:
            delta = avg - target if direction == "lower" else target - avg
            print(c(f"  {name}: current {avg:.1f} vs target {target:.1f} (delta: {delta:.1f})", RED))
    else:
        print(c("\n  All KPIs within target range.", GREEN, BOLD))

    fp_avg = sum(d.false_positive_rate for d in days) / len(days)
    print(c(f"\n  Additional metric — False Positive Rate: {fp_avg:.1f}%", DIM))
    print(c("  (Industry benchmark: aim below 20%)", DIM))
    print()


def export(days: List[DailyKPI]):
    with open("kpi_report.json", "w") as f:
        json.dump([asdict(d) for d in days], f, indent=2)
    print(c("  Report saved to kpi_report.json\n", GREEN))


def main():
    banner()
    print(c("  Generating 7-day operational data...", DIM))
    time.sleep(0.6)
    days = generate_week()
    print_daily_trend(days)
    print_kpi_summary(days)
    export(days)


if __name__ == "__main__":
    main()
