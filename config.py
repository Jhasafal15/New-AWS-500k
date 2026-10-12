"""
Configuration settings for the Synthetic AWS CloudTrail Behavioral Security Dataset Generator.
Preserves exact definitions, weights, and schemas of the existing CSPM analyzer.
"""

from pathlib import Path

# ============================================================
# PROJECT & ARTIFACT PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
SYNTHETIC_DIR = DATA_DIR / "synthetic"

# Output dataset file paths
CLOUDTRAIL_CSV = SYNTHETIC_DIR / "synthetic_cloudtrail_500k.csv"
CLOUDTRAIL_JSONL = SYNTHETIC_DIR / "synthetic_cloudtrail_500k.jsonl"
CSPM_CSV = SYNTHETIC_DIR / "synthetic_cspm_inventory.csv"
SECURITY_FINDINGS_CSV = SYNTHETIC_DIR / "synthetic_security_findings.csv"
CORRELATION_SEQUENCES_CSV = SYNTHETIC_DIR / "synthetic_correlation_sequences.csv"
RESPONSE_RECOMMENDATIONS_CSV = SYNTHETIC_DIR / "synthetic_response_recommendations.csv"
LLM_FINETUNING_JSONL = SYNTHETIC_DIR / "synthetic_llm_finetuning.jsonl"
STATISTICS_JSON = SYNTHETIC_DIR / "dataset_statistics.json"

# ============================================================
# RUNTIME PARAMETERS
# ============================================================

RANDOM_SEED = 42
DEFAULT_ROW_COUNT = 500000
DEFAULT_LLM_EXAMPLE_COUNT = 100000

# Synthetic Account ID
SYNTHETIC_ACCOUNT_ID = "134604497614"

# ============================================================
# CLASS & SCENARIO DISTRIBUTIONS (EXACT 500,000 ROWS)
# ============================================================

# Target class distribution: ~90% Normal, ~7% Suspicious, ~3% Anomalous
SCENARIO_TARGET_COUNTS = {
    "NORMAL_BEHAVIOR": 420000,           # Standard day-to-day user/app/admin operations
    "SERVICE_ACTIVITY": 20000,           # Legitimate AWS internal service calls (Hard Negative)
    "OFF_HOURS_ANOMALY": 12000,          # Off-hours activity (mixture of normal scheduled and suspicious)
    "MFA_ANOMALY": 8000,                 # MFA missing/unknown context (mixture of legitimate service & suspicious user)
    "RECONNAISSANCE": 12000,             # Identity and resource discovery sequences
    "SERVICE_DISCOVERY": 8000,           # Broad cloud service discovery patterns
    "SENSITIVE_IAM": 6000,               # Sensitive IAM configurations and role inspection
    "PRIVILEGE_ESCALATION": 4000,        # Privilege escalation attempts and policy attachments
    "CREDENTIAL_ACTIVITY": 3000,         # Access key creation, deletion, login profile manipulation
    "FAILED_SENSITIVE_OPERATION": 3000,  # Repeated AccessDenied on critical APIs
    "COMPOUND_ATTACK_CHAIN": 2000,       # End-to-end multi-stage attack chains
}

# ============================================================
# AWS EVENT TAXONOMY (MATCHING ANALYZER.PY)
# ============================================================

SENSITIVE_EVENTS = {
    "CreateUser",
    "CreateAccessKey",
    "DeleteUser",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreateRole",
    "UpdateAssumeRolePolicy",
    "DeleteRole",
    "UpdateUser",
    "UpdateRole",
    "DeleteAccessKey",
    "DetachUserPolicy",
    "DetachRolePolicy",
    "PassRole",
    "CreatePolicy",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "DeletePolicy",
}

PRIVILEGE_ESCALATION_EVENTS = {
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "UpdateAssumeRolePolicy",
    "PassRole",
}

WRITE_PREFIXES = (
    "Create",
    "Delete",
    "Update",
    "Put",
    "Attach",
    "Detach",
    "Modify",
    "Set",
    "Add",
    "Remove",
)

# Common API event frequency baseline
COMMON_DISCOVERY_EVENTS = [
    "DescribeInstances",
    "DescribeSecurityGroups",
    "DescribeVpcs",
    "DescribeSubnets",
    "ListBuckets",
    "GetBucketLocation",
    "DescribeVolumes",
    "DescribeTags",
    "ListRoles",
    "GetRole",
    "GetUser",
    "ListUsers",
    "ListPolicies",
    "GetPolicy",
]

COMMON_READ_EVENTS = [
    "AssumeRole",
    "GetCallerIdentity",
    "LookupEvents",
    "GetSessionToken",
    "DescribeAutoScalingGroups",
    "GetAccountSummary",
    "GetDatabases",
    "GetTables",
]

RECON_SEQUENCE_EVENTS = [
    "ListResources",
    "ListTables",
    "ListBuckets",
    "DescribeDBSubnetGroups",
]

SERVICE_DISCOVERY_EVENTS = [
    "ListServices",
    "ListResources",
    "DescribeAutoScalingGroups",
]

SENSITIVE_IAM_EVENTS = [
    "ListSecurityConfigurations",
    "AssumeRole",
    "ListRolePolicies",
    "GetAccountAuthorizationDetails",
]

PRIVILEGE_ESCALATION_SEQUENCE_EVENTS = [
    "AssumeRole",
    "CreateRole",
    "AttachRolePolicy",
    "PutRolePolicy",
    "PassRole",
]

AWS_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-2",
    "eu-west-1",
    "ap-southeast-1",
]

# ============================================================
# SCORING & THRESHOLDS (MATCHING ANALYZER.PY)
# ============================================================

RULE_WEIGHT = 0.60
ANOMALY_WEIGHT = 0.40

# Escalation bonuses
CORRELATION_BONUS = 10.0
FAILED_SENSITIVE_BONUS = 5.0

# Thresholds
RISK_LEVEL_THRESHOLDS = {
    "CRITICAL": 85.0,
    "HIGH": 65.0,
    "MEDIUM": 35.0,
    "LOW": 0.0,
}

# ============================================================
# LLM TASK TYPE DISTRIBUTION
# ============================================================

LLM_TASK_DISTRIBUTION = {
    "event_analysis": 0.20,
    "anomaly_explanation": 0.15,
    "risk_explanation": 0.15,
    "finding_generation": 0.15,
    "correlation_analysis": 0.10,
    "remediation": 0.10,
    "cspm_analysis": 0.10,
    "incident_summarization": 0.05,
}

# Train / Validation / Test Ratios (Sequence-preserving)
SPLIT_RATIOS = {
    "train": 0.70,
    "validation": 0.15,
    "test": 0.15,
}
