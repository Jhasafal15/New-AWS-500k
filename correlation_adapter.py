"""
Adapter for feeding analyzed CloudTrail events
into the behavioral correlation engine.
"""

import csv
from pathlib import Path

from correlation.correlation_engine import (
    correlate_events,
    print_correlation_results,
)


def load_analyzed_events(csv_path=None):
    """
    Load analyzed CloudTrail events from CSV.

    Returns:
        list: Event dictionaries suitable for correlation analysis.
    """

    if csv_path is None:
        csv_path = (
            Path(__file__).resolve().parent.parent
            / "data"
            / "analyzed"
            / "iam_anomaly_analysis.csv"
        )

    csv_path = Path(csv_path)

    if not csv_path.exists():
        raise FileNotFoundError(
            f"Analyzed event file not found: {csv_path}"
        )

    events = []
    scenario_counts = {}
    attack_sessions = set()

    with csv_path.open(
        "r",
        encoding="utf-8",
        newline=""
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:

            event_name = row.get("event_name")

            if not event_name:
                continue

            scen = row.get("attack_scenario", "")
            if scen:
                scenario_counts[scen] = scenario_counts.get(scen, 0) + 1
                if scen != "NORMAL_BEHAVIOR" and row.get("session_id"):
                    attack_sessions.add(row.get("session_id"))

            events.append({
                "event_name": event_name,
                "event_source": row.get("event_source", ""),
                "source_ip": row.get("source_ip", ""),
                "final_risk_score": row.get("final_risk_score", ""),
                "final_risk_level": row.get("final_risk_level", ""),
                "anomaly_score": row.get("anomaly_score", ""),
                "rule_risk_score": row.get("rule_risk_score", ""),
                "attack_scenario": scen,
            })

    return events


def run_correlation_analysis(events):
    """
    Send normalized events to the behavioral correlation engine.

    Returns:
        list: Correlation findings.
    """

    return correlate_events(events)


if __name__ == "__main__":
    import sys
    import os
    import json
    from collections import Counter

    input_path = None
    if len(sys.argv) > 1:
        input_path = sys.argv[1]
    elif os.getenv("CORRELATION_INPUT_FILE"):
        input_path = os.getenv("CORRELATION_INPUT_FILE")

    print("=" * 70)
    print("BEHAVIORAL CORRELATION PIPELINE")
    print("=" * 70)
    if input_path:
        print(f"Loading from: {input_path}")

    # Step 1: Load analyzed events
    events = load_analyzed_events(input_path)

    print(f"Events loaded: {len(events)}")

    # Step 2: Run correlation engine
    findings = run_correlation_analysis(events)

    # Step 3: Display correlation findings
    print_correlation_results(findings)

    # Step 4: Save correlation findings JSON for downstream dashboard
    out_dir = Path(os.getenv("OUTPUT_DIR", Path(__file__).resolve().parent.parent / "data" / "analyzed"))
    out_dir.mkdir(parents=True, exist_ok=True)
    scen_counter = Counter(e.get("attack_scenario") for e in events if e.get("attack_scenario"))
    corr_payload = {
        "total_events_correlated": len(events),
        "correlated_patterns_detected": len(findings),
        "patterns": findings,
        "attack_scenario_breakdown": dict(scen_counter),
    }
    corr_json_path = out_dir / "correlation_findings.json"
    corr_json_path.write_text(json.dumps(corr_payload, indent=2), encoding="utf-8")
    print(f"Saved correlation findings to: {corr_json_path}")

    print("=" * 70)
    print("CORRELATION PIPELINE COMPLETED")
    print("=" * 70)