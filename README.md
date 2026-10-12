# Synthetic AWS CloudTrail Behavioral Security Dataset & LLM Fine-Tuning Suite

## 1. Project Overview & Architecture
This dataset generator produces a high-fidelity, privacy-safe, reproducible synthetic evaluation suite for **AI-Powered Cloud Security Posture Management (CSPM) with Behavioral and ML-Based IAM Risk Analysis**.

The dataset emulates 4 months of enterprise multi-account AWS activity across normal operations, service automation, hard negatives, reconnaissance sequences, privilege escalations, and compound attack campaigns.

### High-Level Architecture Flow
```
                      ┌────────────────────────────────────────────────────────┐
                      │ Synthetic AWS CloudTrail Event Engine (Vectorized)     │
                      └──────────────────────────┬─────────────────────────────┘
                                                 │
                                                 ▼
                      ┌────────────────────────────────────────────────────────┐
                      │ 17 Behavioral Features Extraction & Risk Engine        │
                      │  • Event/Identity/Source Frequencies & Rarities        │
                      │  • Privilege Escalation & Sensitive Action Combos      │
                      │  • 60% Explainable Rule Score + 40% ML Anomaly Fusion │
                      └──────────────────────────┬─────────────────────────────┘
                                                 │
            ┌────────────────────────────────────┼────────────────────────────────────┐
            ▼                                    ▼                                    ▼
┌─────────────────────────┐          ┌─────────────────────────┐          ┌─────────────────────────┐
│ CloudTrail 500K Dataset │          │ CSPM Posture Inventory  │          │ Correlated Attack Chains│
│ • synthetic_cloudtrail_ │          │ • synthetic_cspm_       │          │ • synthetic_correlation │
│   500k.csv              │          │   inventory.csv         │          │   _sequences.csv        │
│ • synthetic_cloudtrail_ │          │   (5,000 resources)     │          │   (8,916 sequences)     │
│   500k.jsonl            │          └───────────┬─────────────┘          └───────────┬─────────────┘
└───────────┬─────────────┘                      │                                    │
            │                                    └───────────────────┬────────────────┘
            │                                                        │
            ▼                                                        ▼
┌─────────────────────────┐                               ┌─────────────────────────┐
│ Sequence-Safe Splits    │                               │ Unified Security Output │
│ • train_cloudtrail.csv  │                               │ • synthetic_security_   │
│ • val_cloudtrail.csv    │                               │   findings.csv          │
│ • test_cloudtrail.csv   │                               │ • synthetic_response_   │
│ (Zero Leakage Verified) │                               │   recommendations.csv   │
└───────────┬─────────────┘                               └─────────────────────────┘
            │
            ▼
┌────────────────────────────────────────────────────────┐
│ LLM Fine-Tuning Suite (100,000 Examples)               │
│ • synthetic_llm_finetuning.jsonl (Standard Instruction)│
│ • synthetic_llm_chatml.jsonl (OpenAI/ShareGPT)         │
│ • synthetic_llm_huggingface.jsonl (Prompt/Completion)  │
│ • train_llm.jsonl / val_llm.jsonl / test_llm.jsonl     │
└────────────────────────────────────────────────────────┘
```

---

## 2. Generated Deliverables Summary

| File | Description | Records | Size |
|---|---|---|---|
| `synthetic_cloudtrail_500k.csv` | Full behavioral CloudTrail dataset with all 54 fields | 500,000 rows | ~345 MB |
| `synthetic_cloudtrail_500k.jsonl` | Raw AWS CloudTrail-compatible JSON wrapper records | 500,000 lines | ~623 MB |
| `synthetic_cspm_inventory.csv` | Linked resource posture inventory & vulnerability catalog | 5,000 records | ~2.4 MB |
| `synthetic_correlation_sequences.csv` | Correlated multi-step behavioral attack sequences | 8,916 sequences | ~3.2 MB |
| `synthetic_security_findings.csv` | Unified SOC findings (Behavioral + CSPM) | 26,753 findings | ~11.7 MB |
| `synthetic_response_recommendations.csv` | Actionable remediation actions per finding | 26,753 records | ~15.3 MB |
| `synthetic_llm_finetuning.jsonl` | Instruction fine-tuning dataset across 8 SOC tasks | 100,000 examples | ~121 MB |
| `synthetic_llm_chatml.jsonl` | ChatML format (OpenAI / vLLM / Axolotl compatible) | 100,000 examples | ~143 MB |
| `synthetic_llm_huggingface.jsonl` | Hugging Face datasets compatible format | 100,000 examples | ~139 MB |
| `train_cloudtrail.csv` | Sequence-safe training split (70.0%) | 350,029 events | ~241 MB |
| `val_cloudtrail.csv` | Sequence-safe validation split (15.0%) | 74,955 events | ~52 MB |
| `test_cloudtrail.csv` | Sequence-safe test split (15.0%) | 75,016 events | ~52 MB |
| `train_llm.jsonl` | Sequence-safe LLM training split | 70,774 examples | ~85 MB |
| `val_llm.jsonl` | Sequence-safe LLM validation split | 14,678 examples | ~18 MB |
| `test_llm.jsonl` | Sequence-safe LLM test split | 14,548 examples | ~18 MB |
| `dataset_statistics.json` | Complete statistical telemetry & validation report | JSON | ~2.5 KB |

---

## 3. Complete Schema Specification

The dataset contains **54 comprehensive attributes** logically organized into 5 tiers:

### Tier 1: Raw CloudTrail Telemetry
- `event_time`: ISO 8601 UTC timestamp (`2026-06-01T00:00:00Z` to `2026-09-28T23:59:59Z`)
- `event_name`: Exact AWS CloudTrail API event name (e.g. `AssumeRole`, `AttachRolePolicy`, `ListBuckets`)
- `event_source`: Authoritative AWS service endpoint (e.g. `iam.amazonaws.com`, `sts.amazonaws.com`)
- `aws_region`: Valid AWS region identifier (`us-east-1`, `us-east-2`, `us-west-2`, `eu-west-1`, `ap-southeast-1`)
- `source_ip`: Synthetic IP address from discrete corporate, VPN, cloud VPC, or suspicious threat pools
- `user_agent`: Standard AWS SDK / Console / CLI / Boto3 / Python user agent
- `user_type`: AWS principal type (`IAMUser`, `AssumedRole`, `AWSService`)
- `user_name`: Synthetic human or service principal name
- `principal_id`: Unique IAM principal identifier
- `access_key_id`: Synthetic AWS access key identifier (e.g. `AKIA...`, `ASIA...`)
- `user_arn`: Full synthetic Amazon Resource Name
- `mfa_used`: Authentication status (`true`, `false`, `unknown`)
- `error_code`: Populated on failures (e.g. `AccessDenied`, `Client.UnauthorizedOperation`)
- `error_message`: Descriptive error string
- `is_failed`: Boolean flag (True if error occurred)
- `error_present`: Error presence indicator
- `read_only`: Boolean flag indicating state modification
- `recipient_account_id`: Synthetic AWS account ID (`134604497614`)
- `event_hour`: Hour of request (0-23 derived from `event_time`)
- `event_day`: Day of week derived from `event_time`
- `is_night`: Night indicator (`event_hour < 6 or >= 22`)
- `api_category`: Functional classification (`read`, `write`, `delete`, `permission`, `other`)
- `is_privileged_api`: Flag for sensitive IAM/EC2/S3 operations

### Tier 2: Correlation & Session Identifiers
- `session_id`: Unique tracking ID for user session
- `activity_group_id`: Grouping identifier for cohesive activity clusters
- `behavior_sequence_id`: Sequence ID linking multi-step attack campaigns (e.g. `SEQ_REC_000142`)
- `principal_session_id`: Compound key binding principal identity to session

### Tier 3: Ground-Truth Evaluation Labels
- `behavior_label`: High-level security classification (`NORMAL`, `SUSPICIOUS`, `ANOMALOUS`)
- `attack_scenario`: Detailed scenario tag (11 discrete categories)
- `is_anomaly`: Isolation Forest format (`1` = normal, `-1` = anomaly)
- `anomaly_label`: Human-readable label (`NORMAL` vs `ANOMALY`)

### Tier 4: The 17 Behavioral Features (Direct Project Match)
1. `event_frequency`: Absolute occurrence frequency of `event_name` across dataset
2. `event_rarity`: `(1.0 - (event_frequency / max_event_frequency)) * 100`
3. `identity_frequency`: Activity volume for the principal
4. `source_frequency`: Activity volume for originating source
5. `source_rarity`: Relative source abnormality percentage
6. `failed_request`: 1 if error_code is present, else 0
7. `mfa_not_used`: 1 if MFA explicitly active, 0 otherwise (consistent with `analyzer.py`)
8. `mfa_unknown`: 1 if MFA status unavailable, 0 otherwise
9. `write_operation`: 1 if event name starts with write/mutation prefixes
10. `sensitive_operation`: 1 if event belongs to IAM sensitive operations set
11. `privilege_escalation`: 1 if event can alter policy/role boundaries
12. `aws_service_activity`: 1 if originating from internal AWS service principal
13. `event_hour`: Integer hour (0-23)
14. `off_hours`: 1 if `event_hour < 6 or >= 22`
15. `failed_sensitive_combo`: 1 if `failed_request == 1 and sensitive_operation == 1`
16. `privilege_change_combo`: 1 if `privilege_escalation == 1 and write_operation == 1`
17. `existing_rule_score`: Baseline rule score

### Tier 5: Composite Risk Scoring & SOC Explainability
- `rule_risk_score`: Deterministic rule score (0 - 100)
- `anomaly_score`: Calibrated behavioral anomaly score (0 - 100)
- `final_risk_score`: Composite risk fusion `(0.60 * rule) + (0.40 * anomaly) + escalation_bonuses`
- `final_risk_level`: Severity tier (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- `risk_reasons`: Semicolon-delimited explainable factors
- `recommended_action`: Prescriptive SOC remediation directive

---

## 4. Class & Scenario Distributions

```
Total Events: 500,000

Class Breakdown:
  • NORMAL     : 457,039 events (91.41%)
  • SUSPICIOUS :  21,664 events ( 4.33%)
  • ANOMALOUS  :  21,297 events ( 4.26%)

Scenario Breakdown:
  • NORMAL_BEHAVIOR            : 422,002 (84.40%)
  • SERVICE_ACTIVITY (Hard Neg):  20,000 ( 4.00%)
  • OFF_HOURS_ANOMALY          :  12,000 ( 2.40%)
  • RECONNAISSANCE             :  12,000 ( 2.40%)
  • MFA_ANOMALY                :   8,000 ( 1.60%)
  • SERVICE_DISCOVERY          :   7,998 ( 1.60%)
  • SENSITIVE_IAM              :   6,000 ( 1.20%)
  • PRIVILEGE_ESCALATION       :   4,000 ( 0.80%)
  • FAILED_SENSITIVE_OPERATION :   3,000 ( 0.60%)
  • CREDENTIAL_ACTIVITY        :   3,000 ( 0.60%)
  • COMPOUND_ATTACK_CHAIN      :   2,000 ( 0.40%)

Severity Distribution:
  • LOW      : 461,609 (92.32%)
  • MEDIUM   :  30,498 ( 6.10%)
  • HIGH     :   2,690 ( 0.54%)
  • CRITICAL :   5,203 ( 1.04%)
```

---

## 5. Sequence-Safe Splitting & Zero Leakage

To prevent data leakage when training ML and fine-tuning LLMs:
- Events belonging to the same `behavior_sequence_id` or session are assigned atomically to either `train`, `validation`, or `test`.
- Correlated attack chains are never split across train and test sets.
- Automated validation confirmed: **0 shared sequences between splits**.

---

## 6. LLM Fine-Tuning Task Matrix

The 100,000 fine-tuning examples are structured across 8 distinct tasks:

1. **Event Analysis (20% - 20,000 examples)**: Triage raw CloudTrail events using identity baseline and temporal context.
2. **Behavioral Anomaly Explanation (15% - 15,000 examples)**: Explain why an event is flagged or verify hard negatives (e.g. legitimate scheduled backup).
3. **Risk Explanation & Fusion (15% - 15,000 examples)**: Deconstruct 60% rule score + 40% ML anomaly score calculation.
4. **Finding Generation (15% - 15,000 examples)**: Synthesize structured SOC findings with severity and root causes.
5. **Correlation Interpretation (10% - 10,000 examples)**: Connect multi-step event sequences into coherent attack narratives.
6. **Remediation & Response (10% - 10,000 examples)**: Formulate prioritized containment, revocation, and hardening steps.
7. **CSPM Posture Analysis (10% - 10,000 examples)**: Assess cloud resource misconfigurations (wildcard IAM, public S3, unencrypted EBS).
8. **Incident Summarization (5% - 5,000 examples)**: Executive SOC summaries of compound multi-stage compromises.

---

## 7. How to Run & Reproduce

```bash
# Generate the full 500,000-row dataset and 100,000 LLM fine-tuning examples:
python dataset_generator/run_generation.py --rows 500000 --llm-examples 100000 --seed 42

# Generate a fast benchmark sample (e.g. 10,000 rows):
python dataset_generator/run_generation.py --rows 10000 --llm-examples 2000 --seed 42
```

---

## 8. Integration with Existing Project Pipeline

To benchmark the existing pipeline components against the synthetic dataset without altering existing files:

```bash
# Run the existing Analyzer on the synthetic dataset:
python analyzer.py --input data/synthetic/synthetic_cloudtrail_500k.csv

# Feed synthetic events directly into the Behavioral Correlation Adapter:
python -m input_adapters.correlation_adapter --input data/synthetic/synthetic_cloudtrail_500k.csv
```
