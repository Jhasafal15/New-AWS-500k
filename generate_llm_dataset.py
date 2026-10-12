"""
Generator for the LLM Supervised Fine-Tuning (SFT) Dataset.
Produces 100,000 diverse, leakage-free instruction-tuning examples across 8 cybersecurity tasks.
Includes converters for ChatML (OpenAI/ShareGPT) and Hugging Face Dataset format.
Optimized with pre-indexed memory structures for instant sampling across 500,000 rows.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Iterator

import numpy as np
import pandas as pd

from .config import (
    RANDOM_SEED,
    DEFAULT_LLM_EXAMPLE_COUNT,
    LLM_TASK_DISTRIBUTION,
    LLM_FINETUNING_JSONL,
    SYNTHETIC_DIR,
)

np.random.seed(RANDOM_SEED)

SYSTEM_SECURITY_PROMPT = (
    "You are an expert Cloud Security Posture Management (CSPM) and Behavioral IAM Risk Analyst. "
    "Your role is to rigorously analyze AWS CloudTrail events, identity baselines, cloud resource configurations, "
    "and correlated behavioral sequences to detect threats, explain risk calculations, and formulate actionable remediations."
)


class LLMDatasetGenerator:
    """
    Synthesizes model-independent instruction-tuning examples from CloudTrail and CSPM data.
    """

    def __init__(self, df_ct: pd.DataFrame, df_cspm: pd.DataFrame, total_examples: int = DEFAULT_LLM_EXAMPLE_COUNT):
        print("Pre-indexing dataset for ultra-fast instruction synthesis...")
        self.df_ct = df_ct
        self.df_cspm = df_cspm
        self.total_examples = total_examples
        self.example_counter = 1

        # Convert to records for O(1) attribute access
        self.ct_records = df_ct.to_dict(orient="records")
        self.n_ct = len(self.ct_records)

        # Pre-compute index arrays
        self.normal_hard_neg_indices = np.where(
            (df_ct["behavior_label"] == "NORMAL") &
            ((df_ct["off_hours"] == 1) | (df_ct["aws_service_activity"] == 1))
        )[0]
        if len(self.normal_hard_neg_indices) == 0:
            self.normal_hard_neg_indices = np.arange(self.n_ct)

        self.anomaly_indices = np.where(
            (df_ct["is_anomaly"] == -1) |
            (df_ct["attack_scenario"].isin(["SERVICE_ACTIVITY", "OFF_HOURS_ANOMALY"]))
        )[0]
        if len(self.anomaly_indices) == 0:
            self.anomaly_indices = np.arange(self.n_ct)

        self.elevated_risk_indices = np.where(df_ct["final_risk_score"] > 30.0)[0]
        if len(self.elevated_risk_indices) == 0:
            self.elevated_risk_indices = np.arange(self.n_ct)

        self.high_crit_indices = np.where(df_ct["final_risk_level"].isin(["HIGH", "CRITICAL"]))[0]
        if len(self.high_crit_indices) == 0:
            self.high_crit_indices = np.arange(self.n_ct)

        # Pre-group correlated sequences
        seq_df = df_ct[df_ct["behavior_sequence_id"].fillna("").ne("")]
        self.seq_groups = [group.to_dict(orient="records") for _, group in seq_df.groupby("behavior_sequence_id")]

        # Pre-group compound chains
        chain_df = df_ct[df_ct["attack_scenario"] == "COMPOUND_ATTACK_CHAIN"]
        self.chain_groups = [group.to_dict(orient="records") for _, group in chain_df.groupby("behavior_sequence_id")]

        self.cspm_records = df_cspm.to_dict(orient="records")
        self.n_cspm = len(self.cspm_records)

    def _task_event_analysis(self) -> Dict[str, Any]:
        """Task 1: Event Analysis (20%) - Triage individual activity."""
        if np.random.rand() < 0.30:
            idx = np.random.choice(self.normal_hard_neg_indices)
        else:
            idx = np.random.randint(0, self.n_ct)
        row = self.ct_records[idx]

        instruction = "Analyze the provided AWS CloudTrail event and determine whether it represents normal, suspicious, or anomalous activity."
        input_data = {
            "event_name": row["event_name"],
            "event_source": row["event_source"],
            "aws_region": row["aws_region"],
            "source_ip": row["source_ip"],
            "user_agent": row["user_agent"],
            "user_type": row["user_type"],
            "user_name": row["user_name"],
            "mfa_used": row["mfa_used"],
            "error_code": row["error_code"] if row["error_code"] else None,
            "event_time": row["event_time"],
            "event_hour": int(row["event_hour"]),
        }
        context = {
            "identity_role": row["user_name"],
            "is_off_hours": bool(row["off_hours"]),
            "aws_service_context": bool(row["aws_service_activity"]),
        }

        label = row["behavior_label"]
        scenario = row["attack_scenario"]
        sev = row["final_risk_level"]

        if label == "NORMAL":
            output = (
                f"Evaluation: NORMAL. The API call '{row['event_name']}' issued by '{row['user_name']}' aligns with "
                f"the principal's behavioral profile. Although the request occurred at hour {row['event_hour']}, "
                f"the presence of established operational patterns and lack of privilege escalation indicators "
                f"confirms this activity is legitimate."
            )
        elif label == "SUSPICIOUS":
            output = (
                f"Evaluation: SUSPICIOUS. The activity exhibits behavioral deviations. The call '{row['event_name']}' "
                f"originated from source IP {row['source_ip']} during off-hours or atypical context, requiring SOC triage."
            )
        else:
            output = (
                f"Evaluation: ANOMALOUS. Critical security deviation detected. Principal '{row['user_name']}' initiated "
                f"'{row['event_name']}' with strong risk indicators: {row['risk_reasons']}. Immediate investigation warranted."
            )

        return {
            "instruction": instruction,
            "input": input_data,
            "context": context,
            "expected_analysis": {
                "behavior": label,
                "scenario": scenario,
                "risk_factors": str(row["risk_reasons"]).split("; "),
            },
            "output": output,
            "label": label,
            "severity": sev,
            "scenario": scenario,
            "event_ids": [row["session_id"]],
        }

    def _task_anomaly_explanation(self) -> Dict[str, Any]:
        """Task 2: Behavioral Anomaly Explanation (15%)."""
        idx = np.random.choice(self.anomaly_indices)
        row = self.ct_records[idx]

        instruction = "Explain why this cloud activity was flagged by behavioral anomaly detection models, or verify if it is an explainable benign deviation."
        input_data = {
            "principal": row["user_name"],
            "event": row["event_name"],
            "source_ip": row["source_ip"],
            "event_rarity": float(row["event_rarity"]),
            "source_rarity": float(row["source_rarity"]),
            "off_hours": bool(row["off_hours"]),
            "failed_request": bool(row["failed_request"]),
        }
        context = {
            "identity_frequency": float(row["identity_frequency"]),
            "user_type": row["user_type"],
        }

        output = (
            f"Anomaly Analysis for {row['user_name']}: "
            f"Event rarity is {row['event_rarity']:.1f}% and source rarity is {row['source_rarity']:.1f}%. "
            f"Key risk triggers identified: {row['risk_reasons']}. "
            f"Ground truth assessment: {row['behavior_label']} under scenario '{row['attack_scenario']}'."
        )

        return {
            "instruction": instruction,
            "input": input_data,
            "context": context,
            "expected_analysis": {
                "is_true_anomaly": (row["behavior_label"] != "NORMAL"),
                "primary_deviations": str(row["risk_reasons"]).split("; "),
            },
            "output": output,
            "label": row["behavior_label"],
            "severity": row["final_risk_level"],
            "scenario": row["attack_scenario"],
            "event_ids": [row["session_id"]],
        }

    def _task_risk_explanation(self) -> Dict[str, Any]:
        """Task 3: Risk Explanation & Fusion (15%)."""
        idx = np.random.choice(self.elevated_risk_indices)
        row = self.ct_records[idx]

        instruction = "Deconstruct the composite risk score for this event, detailing how rule-based security logic (60%) and ML anomaly detection (40%) fuse into the final score."
        input_data = {
            "event_name": row["event_name"],
            "rule_risk_score": float(row["rule_risk_score"]),
            "anomaly_score": float(row["anomaly_score"]),
            "sensitive_operation": bool(row["sensitive_operation"]),
            "privilege_escalation": bool(row["privilege_escalation"]),
            "failed_sensitive_combo": bool(row["failed_sensitive_combo"]),
        }
        context = {
            "rule_weight": 0.60,
            "anomaly_weight": 0.40,
        }

        output = (
            f"Composite Risk Deconstruction: "
            f"1. Rule Risk Contribution (60%): {row['rule_risk_score']} * 0.60 = {row['rule_risk_score'] * 0.60:.2f}. "
            f"2. ML Anomaly Contribution (40%): {row['anomaly_score']} * 0.40 = {row['anomaly_score'] * 0.40:.2f}. "
            f"3. Final Composite Score: {row['final_risk_score']:.2f}, placing this in the '{row['final_risk_level']}' severity category. "
            f"Contributing factors: {row['risk_reasons']}."
        )

        return {
            "instruction": instruction,
            "input": input_data,
            "context": context,
            "expected_analysis": {
                "calculated_final_score": float(row["final_risk_score"]),
                "assigned_risk_level": row["final_risk_level"],
            },
            "output": output,
            "label": row["behavior_label"],
            "severity": row["final_risk_level"],
            "scenario": row["attack_scenario"],
            "event_ids": [row["session_id"]],
        }

    def _task_finding_generation(self) -> Dict[str, Any]:
        """Task 4: Finding Generation (15%)."""
        idx = np.random.choice(self.high_crit_indices)
        row = self.ct_records[idx]

        instruction = "Synthesize an actionable security finding record for the observed security telemetry."
        input_data = {
            "event_name": row["event_name"],
            "event_source": row["event_source"],
            "principal_id": row["principal_id"],
            "source_ip": row["source_ip"],
            "observed_indicators": row["risk_reasons"],
            "composite_score": float(row["final_risk_score"]),
        }
        context = {
            "account_id": row["recipient_account_id"],
            "region": row["aws_region"],
        }

        output = (
            f"Security Finding Generated: "
            f"Title: {row['attack_scenario'].replace('_', ' ').title()} Activity Detected. "
            f"Severity: {row['final_risk_level']}. "
            f"Finding Type: Elevated Behavioral Risk. "
            f"Summary: Principal {row['user_name']} executed '{row['event_name']}' from {row['source_ip']} triggering: {row['risk_reasons']}. "
            f"Recommended Action: {row['recommended_action']}"
        )

        return {
            "instruction": instruction,
            "input": input_data,
            "context": context,
            "expected_analysis": {
                "severity": row["final_risk_level"],
                "finding_type": "Elevated Behavioral Risk",
            },
            "output": output,
            "label": row["behavior_label"],
            "severity": row["final_risk_level"],
            "scenario": row["attack_scenario"],
            "event_ids": [row["session_id"]],
        }

    def _task_correlation_analysis(self) -> Dict[str, Any]:
        """Task 5: Correlation Interpretation (10%)."""
        if self.seq_groups:
            group = self.seq_groups[np.random.randint(0, len(self.seq_groups))]
        else:
            group = [self.ct_records[np.random.randint(0, self.n_ct)] for _ in range(3)]

        events_list = [
            {"event": r["event_name"], "source_ip": r["source_ip"], "time": r["event_time"]}
            for r in group
        ]
        scenario = group[0]["attack_scenario"]
        user_name = group[0]["user_name"]

        instruction = "Correlate the following sequence of cloud events and identify the underlying behavioral attack pattern."
        input_data = {
            "event_sequence": events_list,
            "principal": user_name,
        }
        context = {
            "sequence_id": group[0].get("behavior_sequence_id", "SEQ_001"),
        }

        output = (
            f"Correlated Pattern: {scenario.replace('_', ' ').title()}. "
            f"The sequence demonstrates a structured {scenario.lower()} progression executed by principal '{user_name}'. "
            f"Observing events ({' -> '.join([e['event'] for e in events_list])}) in temporal proximity elevates risk "
            f"beyond isolated events, confirming an organized campaign."
        )

        return {
            "instruction": instruction,
            "input": input_data,
            "context": context,
            "expected_analysis": {
                "pattern": scenario,
                "correlated_event_count": len(events_list),
            },
            "output": output,
            "label": group[0]["behavior_label"],
            "severity": group[0]["final_risk_level"],
            "scenario": scenario,
            "event_ids": [r["session_id"] for r in group],
        }

    def _task_remediation(self) -> Dict[str, Any]:
        """Task 6: Remediation & Response (10%)."""
        idx = np.random.choice(self.high_crit_indices)
        row = self.ct_records[idx]

        instruction = "Formulate a prioritized incident response and remediation plan for this detected security threat."
        input_data = {
            "threat_summary": f"Detected {row['attack_scenario']} with {row['final_risk_level']} severity.",
            "compromised_principal": row["user_arn"],
            "source_ip": row["source_ip"],
            "risk_score": float(row["final_risk_score"]),
        }
        context = {
            "account_id": row["recipient_account_id"],
        }

        output = (
            f"Incident Response Plan (Severity: {row['final_risk_level']}): "
            f"1. Immediate Containment: Revoke active sessions for principal {row['user_name']} and attach an explicit DenyAll inline policy. "
            f"2. Network Isolation: Block source IP {row['source_ip']} at the AWS WAF / Network ACL boundary. "
            f"3. Forensic Investigation: Audit all CloudTrail events associated with principalId {row['principal_id']} over the preceding 72 hours. "
            f"4. Long-Term Hardening: {row['recommended_action']}"
        )

        return {
            "instruction": instruction,
            "input": input_data,
            "context": context,
            "expected_analysis": {
                "priority": "IMMEDIATE" if row["final_risk_level"] == "CRITICAL" else "HIGH",
                "containment_steps": ["Revoke active sessions", "Block source IP", "Audit CloudTrail"],
            },
            "output": output,
            "label": row["behavior_label"],
            "severity": row["final_risk_level"],
            "scenario": row["attack_scenario"],
            "event_ids": [row["session_id"]],
        }

    def _task_cspm_analysis(self) -> Dict[str, Any]:
        """Task 7: CSPM / Posture Analysis (10%)."""
        cspm_row = self.cspm_records[np.random.randint(0, self.n_cspm)]

        instruction = "Assess the security posture risk of this AWS cloud resource and explain the configuration vulnerability."
        input_data = {
            "resource_id": cspm_row["resource_id"],
            "resource_type": cspm_row["resource_type"],
            "service": cspm_row["service"],
            "vulnerability_name": cspm_row["vulnerability_name"],
            "configuration_status": cspm_row["configuration_status"],
            "evidence": cspm_row["evidence"],
        }
        context = {
            "region": cspm_row["region"],
            "policy_scope": cspm_row["policy_scope"],
        }

        output = (
            f"Posture Assessment: {cspm_row['vulnerability_name']} ({cspm_row['severity']} Severity). "
            f"Description: {cspm_row['description']}. "
            f"Blast Radius: Unchecked configuration on {cspm_row['resource_id']} exposes the environment to lateral movement and unauthorized privilege escalation. "
            f"Remediation: {cspm_row['recommended_action']}"
        )

        return {
            "instruction": instruction,
            "input": input_data,
            "context": context,
            "expected_analysis": {
                "vulnerability_id": cspm_row["vulnerability_id"],
                "status": cspm_row["configuration_status"],
            },
            "output": output,
            "label": "ANOMALOUS" if cspm_row["severity"] in ["HIGH", "CRITICAL"] else "NORMAL",
            "severity": cspm_row["severity"],
            "scenario": "CSPM_POSTURE_VULNERABILITY",
            "event_ids": [cspm_row["resource_id"]],
        }

    def _task_incident_summarization(self) -> Dict[str, Any]:
        """Task 8: Incident Summarization (5%)."""
        if self.chain_groups:
            group = self.chain_groups[np.random.randint(0, len(self.chain_groups))]
        else:
            group = [self.ct_records[np.random.randint(0, self.n_ct)] for _ in range(5)]

        user_name = group[0]["user_name"]
        src_ip = group[0]["source_ip"]

        instruction = "Provide an executive SOC incident summary of this correlated multi-stage attack chain."
        input_data = {
            "attack_chain_steps": [r["event_name"] for r in group],
            "principal": user_name,
            "source_ip": src_ip,
            "timespan": f"{group[0]['event_time']} to {group[-1]['event_time']}",
        }
        context = {
            "attack_type": "Compound Multi-Stage Attack Chain",
        }

        output = (
            f"EXECUTIVE INCIDENT SUMMARY: "
            f"A multi-stage attack chain was executed by principal '{user_name}' from unauthorized external IP {src_ip}. "
            f"The adversary initiated reconnaissance, encountered and bypassed access controls through credential creation, "
            f"escalated IAM permissions via role attachment, and successfully enumerated sensitive cloud assets. "
            f"Immediate credential revocation, infrastructure audit, and network boundary enforcement are recommended."
        )

        return {
            "instruction": instruction,
            "input": input_data,
            "context": context,
            "expected_analysis": {
                "incident_type": "Compound Attack Chain",
                "compromise_confirmed": True,
            },
            "output": output,
            "label": "ANOMALOUS",
            "severity": "CRITICAL",
            "scenario": "COMPOUND_ATTACK_CHAIN",
            "event_ids": [r["session_id"] for r in group],
        }

    def generate_and_save(self) -> Path:
        """Generates total_examples according to task distributions and saves to JSONL."""
        print(f"Generating {self.total_examples:,} LLM fine-tuning examples...")
        SYNTHETIC_DIR.mkdir(parents=True, exist_ok=True)

        task_generators = [
            (self._task_event_analysis, int(self.total_examples * LLM_TASK_DISTRIBUTION["event_analysis"])),
            (self._task_anomaly_explanation, int(self.total_examples * LLM_TASK_DISTRIBUTION["anomaly_explanation"])),
            (self._task_risk_explanation, int(self.total_examples * LLM_TASK_DISTRIBUTION["risk_explanation"])),
            (self._task_finding_generation, int(self.total_examples * LLM_TASK_DISTRIBUTION["finding_generation"])),
            (self._task_correlation_analysis, int(self.total_examples * LLM_TASK_DISTRIBUTION["correlation_analysis"])),
            (self._task_remediation, int(self.total_examples * LLM_TASK_DISTRIBUTION["remediation"])),
            (self._task_cspm_analysis, int(self.total_examples * LLM_TASK_DISTRIBUTION["cspm_analysis"])),
            (self._task_incident_summarization, int(self.total_examples * LLM_TASK_DISTRIBUTION["incident_summarization"])),
        ]

        total_written = 0
        with open(LLM_FINETUNING_JSONL, "w", encoding="utf-8", buffering=1024*1024) as f:
            for generator_fn, count in task_generators:
                print(f"  Generating {count:,} examples for {generator_fn.__name__}...")
                for _ in range(count):
                    record = generator_fn()
                    record["example_id"] = f"LLM-{self.example_counter:07d}"
                    self.example_counter += 1
                    f.write(json.dumps(record) + "\n")
                    total_written += 1

        print(f"LLM fine-tuning dataset saved to {LLM_FINETUNING_JSONL} ({total_written:,} examples).")
        return LLM_FINETUNING_JSONL


# ============================================================
# CONVERTER UTILITIES
# ============================================================

def convert_to_chatml(input_jsonl: Path, output_jsonl: Path):
    """Converts instruction dataset to OpenAI / ShareGPT ChatML format."""
    print(f"Converting {input_jsonl} to ChatML format at {output_jsonl}...")
    with open(input_jsonl, "r", encoding="utf-8", buffering=1024*1024) as in_f, open(output_jsonl, "w", encoding="utf-8", buffering=1024*1024) as out_f:
        for line in in_f:
            ex = json.loads(line)
            user_content = f"{ex['instruction']}\n\nTelemetry Input:\n{json.dumps(ex['input'], indent=2)}\n\nContext:\n{json.dumps(ex['context'], indent=2)}"
            chat_record = {
                "messages": [
                    {"role": "system", "content": SYSTEM_SECURITY_PROMPT},
                    {"role": "user", "content": user_content},
                    {"role": "assistant", "content": ex["output"]}
                ]
            }
            out_f.write(json.dumps(chat_record) + "\n")
    print(f"ChatML dataset generated at {output_jsonl}.")


def convert_to_huggingface_format(input_jsonl: Path, output_jsonl: Path):
    """Converts dataset to Hugging Face standard 'prompt' and 'completion' format."""
    print(f"Converting to Hugging Face format at {output_jsonl}...")
    with open(input_jsonl, "r", encoding="utf-8", buffering=1024*1024) as in_f, open(output_jsonl, "w", encoding="utf-8", buffering=1024*1024) as out_f:
        for line in in_f:
            ex = json.loads(line)
            prompt = f"### System:\n{SYSTEM_SECURITY_PROMPT}\n\n### Instruction:\n{ex['instruction']}\n\n### Input:\n{json.dumps(ex['input'])}\n\n### Context:\n{json.dumps(ex['context'])}\n\n### Response:\n"
            completion = ex["output"]
            hf_record = {
                "prompt": prompt,
                "completion": completion,
                "label": ex.get("label", ""),
                "severity": ex.get("severity", ""),
            }
            out_f.write(json.dumps(hf_record) + "\n")
    print(f"Hugging Face dataset generated at {output_jsonl}.")
