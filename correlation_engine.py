"""
Behavioral correlation engine.

Takes CloudTrail events and searches for combinations of
related activities that are more meaningful together than
individual events.
"""

from collections import Counter
from .correlation_rules import get_correlation_rules


def correlate_events(events):
    """
    Analyze a collection of events against correlation rules.

    Parameters
    ----------
    events : list
        List of CloudTrail event dictionaries.

    Returns
    -------
    list
        Detected correlation findings.
    """

    if not events:
        return []

    event_counts = Counter()

    for event in events:
        if isinstance(event, dict):
            name = event.get("event_name")
            if name:
                event_counts[name] += 1

    findings = []

    for rule in get_correlation_rules():

        matched_events = []
        matched_volume = 0

        for required_event in rule["events"]:
            if required_event in event_counts:
                matched_events.append(required_event)
                matched_volume += event_counts[required_event]

        if len(matched_events) >= 2:

            findings.append({
                "correlation_rule": rule["name"],
                "severity": rule["severity"],
                "score": rule["score"],
                "matched_events": matched_events,
                "matched_event_volume": matched_volume,
                "description": rule["description"]
            })

    return findings


def print_correlation_results(findings):
    """Display correlation results."""

    print()
    print("=" * 70)
    print("BEHAVIORAL CORRELATION ANALYSIS")
    print("=" * 70)

    if not findings:
        print("No correlated behavioral patterns detected.")
        return

    print(f"Correlated patterns detected: {len(findings)}")
    print()

    for finding in findings:

        print(f"Pattern : {finding['correlation_rule']}")
        print(f"Severity: {finding['severity']}")
        print(f"Score   : {finding['score']}")
        print(
            "Events  : "
            + ", ".join(finding["matched_events"])
        )
        print(f"Reason  : {finding['description']}")
        print("-" * 70)


if __name__ == "__main__":

    print("Correlation Engine Test")
    print("-" * 70)

    test_events = [
        {"event_name": "AssumeRole"},
        {"event_name": "ListResources"},
        {"event_name": "ListTables"},
        {"event_name": "DescribeAutoScalingGroups"}
    ]

    results = correlate_events(test_events)

    print_correlation_results(results)