import os
import sys
import json
import pandas as pd
from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

INPUT_FILE = os.getenv("FINDING_INPUT_FILE", "data/analyzed/iam_anomaly_analysis.csv")

OUTPUT_DIR = os.getenv("OUTPUT_DIR", "data/analyzed")

FINDINGS_CSV = os.getenv(
    "FINDINGS_CSV",
    os.path.join(OUTPUT_DIR, "security_findings.csv")
)

FINDINGS_JSON = os.getenv(
    "FINDINGS_JSON",
    os.path.join(OUTPUT_DIR, "security_findings.json")
)


# ============================================================
# FINDING SEVERITY
# ============================================================

SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


# ============================================================
# LOAD ANALYSIS RESULTS
# ============================================================

def load_analysis_results():

    print("\nLoading behavioral analysis results...")

    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(
            f"Analysis file not found: {INPUT_FILE}"
        )

    df = pd.read_csv(INPUT_FILE)

    print(f"Analysis records loaded: {len(df)}")

    return df


# ============================================================
# DETERMINE FINDING TYPE
# ============================================================

def determine_finding_type(row):

    anomaly_score = float(row.get("anomaly_score", 0))
    rule_score = float(row.get("rule_risk_score", 0))
    final_score = float(row.get("final_risk_score", 0))

    if anomaly_score >= 70 and rule_score >= 20:
        return "Combined Behavioral and Rule Risk"

    if anomaly_score >= 70:
        return "Behavioral Anomaly"

    if rule_score >= 20:
        return "Rule-Based Security Finding"

    if final_score >= 40:
        return "Elevated Behavioral Risk"

    return "Low Risk Activity"


# ============================================================
# GENERATE RECOMMENDATION
# ============================================================

def generate_recommendation(row):

    severity = str(
        row.get("final_risk_level", "LOW")
    ).upper()

    anomaly_score = float(
        row.get("anomaly_score", 0)
    )

    rule_score = float(
        row.get("rule_risk_score", 0)
    )

    if severity == "CRITICAL":
        return (
            "Immediately investigate the associated IAM activity "
            "and review permissions, identity usage and source activity."
        )

    if severity == "HIGH":
        return (
            "Investigate the associated IAM activity and verify "
            "whether the observed behavior is authorized."
        )

    if severity == "MEDIUM":
        return (
            "Review the associated IAM activity and monitor "
            "for repeated or correlated suspicious behavior."
        )

    if anomaly_score >= 70:
        return (
            "Review the unusual behavioral pattern and compare "
            "it with the identity's normal activity."
        )

    if rule_score >= 20:
        return (
            "Review the rule-triggered activity and verify "
            "whether the operation was expected."
        )

    return "Continue monitoring the activity."


# ============================================================
# BUILD SECURITY FINDINGS
# ============================================================

def build_findings(df):

    print("\nGenerating security findings...")

    if df.empty:
        return []

    sev_series = df["final_risk_level"].fillna("LOW").astype(str).str.upper()
    score_series = pd.to_numeric(df["final_risk_score"], errors="coerce").fillna(0.0)

    actionable_mask = (sev_series != "LOW") | (score_series >= 40.0)
    actionable_df = df[actionable_mask].copy()
    total_actionable = len(actionable_df)
    print(f"Total actionable behavioral events detected: {total_actionable:,}")

    max_export = int(os.getenv("MAX_BEHAVIORAL_FINDINGS", "2500"))
    if len(actionable_df) > max_export:
        sorted_all = actionable_df.sort_values(
            by=["final_risk_score", "anomaly_score", "rule_risk_score"],
            ascending=[False, False, False]
        )
        crit_df = sorted_all[sorted_all["final_risk_level"].astype(str).str.upper() == "CRITICAL"].head(int(max_export * 0.48))
        high_df = sorted_all[sorted_all["final_risk_level"].astype(str).str.upper() == "HIGH"].head(int(max_export * 0.32))
        med_df = sorted_all[sorted_all["final_risk_level"].astype(str).str.upper() == "MEDIUM"].head(
            max_export - len(crit_df) - len(high_df)
        )
        actionable_df = pd.concat([crit_df, high_df, med_df]).sort_values(
            by=["final_risk_score", "anomaly_score", "rule_risk_score"],
            ascending=[False, False, False]
        )
        print(f"Exporting stratified top {len(actionable_df):,} behavioral findings (Critical/High/Medium) for SOAR & SOC triage...")

    findings = []
    now_iso = datetime.now().isoformat()

    for index, row in actionable_df.iterrows():

        severity = str(
            row.get("final_risk_level", "LOW")
        ).upper()

        final_score = float(
            row.get("final_risk_score", 0)
        )

        finding = {
            "finding_id": f"F-{int(index) + 1:06d}",

            "timestamp": str(row.get("event_time", now_iso)) or now_iso,

            "event_name": str(
                row.get("event_name", "Unknown")
            ),

            "event_source": str(
                row.get("event_source", "Unknown")
            ),

            "source_ip": str(
                row.get("source_ip", "Unknown")
            ),

            "user_name": str(
                row.get("user_name", "security-analyst")
            ),

            "principal_id": str(
                row.get("principal_id", row.get("user_name", "security-analyst"))
            ),

            "attack_scenario": str(
                row.get("attack_scenario", "BEHAVIORAL_ANOMALY")
            ),

            "finding_type": determine_finding_type(row),

            "severity": severity,

            "anomaly_score": round(
                float(row.get("anomaly_score", 0)),
                2
            ),

            "rule_risk_score": round(
                float(row.get("rule_risk_score", 0)),
                2
            ),

            "final_risk_score": round(
                final_score,
                2
            ),

            "risk_reason": str(
                row.get("risk_reasons", "")
            ),

            "recommended_action": generate_recommendation(row)
        }

        findings.append(finding)

    print(
        f"Actionable findings generated: {len(findings)}"
    )

    return findings


# ============================================================
# SAVE FINDINGS
# ============================================================

def save_findings(findings):

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # ----------------------------
    # JSON
    # ----------------------------

    with open(
        FINDINGS_JSON,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            findings,
            file,
            indent=2
        )

    # ----------------------------
    # CSV
    # ----------------------------

    if findings:

        findings_df = pd.DataFrame(findings)

        findings_df.to_csv(
            FINDINGS_CSV,
            index=False
        )

    else:

        pd.DataFrame(
            columns=[
                "finding_id",
                "timestamp",
                "event_name",
                "event_source",
                "source_ip",
                "user_name",
                "principal_id",
                "finding_type",
                "severity",
                "anomaly_score",
                "rule_risk_score",
                "final_risk_score",
                "risk_reason",
                "recommended_action"
            ]
        ).to_csv(
            FINDINGS_CSV,
            index=False
        )

    print("\nFindings saved:")
    print(FINDINGS_CSV)
    print(FINDINGS_JSON)


# ============================================================
# DISPLAY SUMMARY
# ============================================================

def display_summary(findings):

    print("\n" + "=" * 65)
    print("SECURITY FINDING SUMMARY")
    print("=" * 65)

    print(
        f"Total actionable findings: {len(findings)}"
    )

    severity_counts = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0
    }

    for finding in findings:

        severity = finding["severity"]

        if severity in severity_counts:
            severity_counts[severity] += 1

    print("\nSeverity distribution:")

    for severity, count in severity_counts.items():
        print(f"{severity:<10} {count}")

    if findings:

        preview_limit = 15
        print(f"\nTop Findings Preview (showing {min(len(findings), preview_limit)} of {len(findings)}):")

        for finding in findings[:preview_limit]:

            print(
                f"\n[{finding['severity']}] "
                f"{finding['finding_id']}"
            )

            print(
                f"Event       : "
                f"{finding['event_name']}"
            )

            print(
                f"Actor       : "
                f"{finding.get('user_name', 'Unknown')}"
            )

            print(
                f"Finding     : "
                f"{finding['finding_type']}"
            )

            print(
                f"Final Score : "
                f"{finding['final_risk_score']}"
            )

            print(
                f"Reason      : "
                f"{finding['risk_reason']}"
            )

            print(
                f"Action      : "
                f"{finding['recommended_action']}"
            )

    print("\n" + "=" * 65)
    print("FINDING GENERATION COMPLETED")
    print("=" * 65)


# ============================================================
# MAIN
# ============================================================

def main():
    global INPUT_FILE, OUTPUT_DIR, FINDINGS_CSV, FINDINGS_JSON
    import argparse

    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="Security Finding Generator")
        parser.add_argument("--input", default=INPUT_FILE, help="Path to analyzed anomaly CSV")
        parser.add_argument("--output-dir", default=OUTPUT_DIR, help="Output directory")
        args, _ = parser.parse_known_args()
        INPUT_FILE = args.input
        OUTPUT_DIR = args.output_dir
        FINDINGS_CSV = os.path.join(OUTPUT_DIR, "security_findings.csv")
        FINDINGS_JSON = os.path.join(OUTPUT_DIR, "security_findings.json")

    print("=" * 65)
    print("AI CLOUD IAM BEHAVIORAL SECURITY")
    print("SECURITY FINDING GENERATOR")
    print("=" * 65)

    try:

        df = load_analysis_results()

        findings = build_findings(df)

        save_findings(findings)

        display_summary(findings)

    except Exception as error:

        print("\nERROR:")
        print(error)


if __name__ == "__main__":
    main()