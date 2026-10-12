"""
Derivation of Correlated Behavioral Sequences, Unified Security Findings, and Response Recommendations.
Preserves the exact finding synthesis and remediation logic of the active pipeline.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Tuple

import pandas as pd

from .config import (
    CLOUDTRAIL_CSV,
    CSPM_CSV,
    SECURITY_FINDINGS_CSV,
    CORRELATION_SEQUENCES_CSV,
    RESPONSE_RECOMMENDATIONS_CSV,
    SYNTHETIC_DIR,
)


def derive_correlation_sequences(df_ct: pd.DataFrame) -> pd.DataFrame:
    """
    Extracts multi-event correlated attack sequences and outputs sequence-level findings.
    """
    print("Deriving correlated behavioral sequences...")
    seq_records = []

    # Group by non-empty behavior_sequence_id
    grouped = df_ct[df_ct["behavior_sequence_id"].fillna("").ne("")].groupby("behavior_sequence_id")

    for seq_id, group in grouped:
        events = list(group["event_name"])
        rule_name = group["attack_scenario"].iloc[0].replace("_", " ").title()
        sev = group["final_risk_level"].iloc[0]
        score = float(group["final_risk_score"].max())
        user_name = group["user_name"].iloc[0]
        src_ip = group["source_ip"].iloc[0]
        start_t = group["event_time"].iloc[0]
        end_t = group["event_time"].iloc[-1]

        desc = (
            f"Multi-event behavioral correlation pattern '{rule_name}' detected for "
            f"principal '{user_name}' originating from source '{src_ip}' with {len(events)} correlated steps."
        )

        seq_records.append({
            "behavior_sequence_id": seq_id,
            "correlation_rule": rule_name,
            "severity": sev,
            "correlation_score": score,
            "event_count": len(events),
            "matched_events": " -> ".join(events),
            "identity": user_name,
            "source_ip": src_ip,
            "start_time": start_t,
            "end_time": end_t,
            "description": desc,
        })

    df_seq = pd.DataFrame(seq_records)
    SYNTHETIC_DIR.mkdir(parents=True, exist_ok=True)
    df_seq.to_csv(CORRELATION_SEQUENCES_CSV, index=False)
    print(f"Correlation sequences saved to {CORRELATION_SEQUENCES_CSV} ({len(df_seq):,} sequences).")
    return df_seq


def derive_security_findings_and_responses(df_ct: pd.DataFrame, df_cspm: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Synthesizes unified security findings (Behavioral + CSPM) and generates response recommendations.
    """
    print("Synthesizing unified security findings and response recommendations...")
    findings = []
    responses = []

    # 1. Behavioral findings from CloudTrail events with elevated risk (MEDIUM, HIGH, CRITICAL)
    elevated_ct = df_ct[df_ct["final_risk_level"].isin(["MEDIUM", "HIGH", "CRITICAL"])].copy()

    # Sample a representative subset for findings to maintain clean reporting (e.g. up to 25,000 findings)
    if len(elevated_ct) > 25000:
        elevated_ct = elevated_ct.sample(n=25000, random_state=42)

    for idx, (_, row) in enumerate(elevated_ct.iterrows(), start=1):
        f_id = f"F-BEH-{idx:05d}"
        sev = row["final_risk_level"]
        anom_score = float(row["anomaly_score"])
        rule_score = float(row["rule_risk_score"])
        final_score = float(row["final_risk_score"])

        # Determine finding type matching finding_writer.py
        if anom_score >= 70 and rule_score >= 20:
            finding_type = "Combined Behavioral and Rule Risk"
        elif anom_score >= 70:
            finding_type = "Behavioral Anomaly"
        elif rule_score >= 20:
            finding_type = "Rule-Based Security Finding"
        else:
            finding_type = "Elevated Behavioral Risk"

        finding = {
            "finding_id": f_id,
            "timestamp": row["event_time"],
            "event_name": row["event_name"],
            "event_source": row["event_source"],
            "source_ip": row["source_ip"],
            "finding_type": finding_type,
            "severity": sev,
            "anomaly_score": anom_score,
            "rule_risk_score": rule_score,
            "final_risk_score": final_score,
            "risk_reason": row["risk_reasons"],
            "recommended_action": row["recommended_action"],
            "resource_id": row["user_arn"],
            "resource_type": "iam_principal",
            "source_module": "behavioral_analysis",
        }
        findings.append(finding)

        # Generate response recommendation matching response_engine.py
        prio = "IMMEDIATE" if sev == "CRITICAL" else ("HIGH" if sev == "HIGH" or (sev == "MEDIUM" and final_score >= 60) else "MEDIUM")
        resp_type = "IMMEDIATE_CONTAINMENT" if prio == "IMMEDIATE" else ("PRIORITY_INVESTIGATION" if prio == "HIGH" else "INVESTIGATION_AND_MONITORING")

        actions = [
            f"Investigate identity {row['user_name']} and review recent CloudTrail audit logs.",
            f"Verify whether source IP {row['source_ip']} is an authorized corporate endpoint.",
            "Compare API call frequency with baseline activity profiles.",
        ]
        if prio in ["IMMEDIATE", "HIGH"]:
            actions.append("Enforce temporary session revocation or policy restriction pending security verification.")

        responses.append({
            "response_id": f"R-BEH-{idx:05d}",
            "finding_id": f_id,
            "event_name": row["event_name"],
            "finding_type": finding_type,
            "severity": sev,
            "final_risk_score": final_score,
            "risk_level_from_score": sev,
            "response_priority": prio,
            "response_type": resp_type,
            "reason": row["risk_reasons"],
            "recommended_action": row["recommended_action"],
            "response_actions": "; ".join(actions),
        })

    # 2. Integrate CSPM Vulnerability findings
    vuln_records = df_cspm[df_cspm["configuration_status"] == "NON_COMPLIANT"]
    for idx, (_, row) in enumerate(vuln_records.iterrows(), start=1):
        f_id = f"F-CSPM-{idx:05d}"
        sev = row["severity"]
        score = 95.0 if sev == "CRITICAL" else (75.0 if sev == "HIGH" else 50.0)

        finding = {
            "finding_id": f_id,
            "timestamp": "2026-09-30T07:35:37Z",
            "event_name": row["vulnerability_name"],
            "event_source": row["service"],
            "source_ip": "INTERNAL_SCANNER",
            "finding_type": "Vulnerability / CSPM Finding",
            "severity": sev,
            "anomaly_score": 0.0,
            "rule_risk_score": score,
            "final_risk_score": score,
            "risk_reason": f"{row['vulnerability_name']}; Evidence: {row['evidence']}",
            "recommended_action": row["recommended_action"],
            "resource_id": row["resource_id"],
            "resource_type": row["resource_type"],
            "source_module": "vulnerability_analysis",
        }
        findings.append(finding)

        prio = "IMMEDIATE" if sev == "CRITICAL" else ("HIGH" if sev == "HIGH" else "MEDIUM")
        resp_type = "IMMEDIATE_CONTAINMENT" if prio == "IMMEDIATE" else "PRIORITY_INVESTIGATION"

        responses.append({
            "response_id": f"R-CSPM-{idx:05d}",
            "finding_id": f_id,
            "event_name": row["vulnerability_name"],
            "finding_type": "Vulnerability / CSPM Finding",
            "severity": sev,
            "final_risk_score": score,
            "risk_level_from_score": sev,
            "response_priority": prio,
            "response_type": resp_type,
            "reason": f"Misconfiguration detected on {row['resource_id']}: {row['description']}",
            "recommended_action": row["recommended_action"],
            "response_actions": f"Remediate resource {row['resource_id']}; Apply least-privilege or network restriction.",
        })

    df_findings = pd.DataFrame(findings)
    df_responses = pd.DataFrame(responses)

    df_findings.to_csv(SECURITY_FINDINGS_CSV, index=False)
    df_responses.to_csv(RESPONSE_RECOMMENDATIONS_CSV, index=False)

    print(f"Unified security findings saved to {SECURITY_FINDINGS_CSV} ({len(df_findings):,} findings).")
    print(f"Response recommendations saved to {RESPONSE_RECOMMENDATIONS_CSV} ({len(df_responses):,} recommendations).")
    return df_findings, df_responses


def main():
    if not CLOUDTRAIL_CSV.exists() or not CSPM_CSV.exists():
        print("Required CSV files missing. Run generator first.")
        return
    df_ct = pd.read_csv(CLOUDTRAIL_CSV)
    df_cspm = pd.read_csv(CSPM_CSV)
    derive_correlation_sequences(df_ct)
    derive_security_findings_and_responses(df_ct, df_cspm)


if __name__ == "__main__":
    main()
