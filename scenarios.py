"""
Behavioral Scenarios, Identity Profiles, and Behavioral Sequence Definitions.
Designed to generate a realistic mixture of normal, hard negative, suspicious, and compound attack activities.
"""

import random
from typing import Dict, List, Any

# ============================================================
# SYNTHETIC IDENTITIES & BEHAVIORAL BASELINES
# ============================================================

IDENTITIES = {
    # 1. Developers
    "dev-lead-user": {
        "user_type": "IAMUser",
        "principal_id": "AIDAV6VYNULH101DEV01",
        "arn": "arn:aws:iam::134604497614:user/dev-lead-user",
        "access_key_id": "AKIAV6VYNULH101DEV01",
        "source_pool": "corporate",
        "normal_hours": (8, 19),
        "typical_events": ["DescribeInstances", "DescribeSecurityGroups", "ListBuckets", "GetCallerIdentity", "LookupEvents"],
        "mfa_profile": "mostly_true",
    },
    "dev-backend-user": {
        "user_type": "IAMUser",
        "principal_id": "AIDAV6VYNULH102DEV02",
        "arn": "arn:aws:iam::134604497614:user/dev-backend-user",
        "access_key_id": "AKIAV6VYNULH102DEV02",
        "source_pool": "vpn",
        "normal_hours": (9, 20),
        "typical_events": ["DescribeInstances", "DescribeSubnets", "GetDatabases", "GetTables", "DescribeVolumes"],
        "mfa_profile": "mostly_true",
    },
    "dev-frontend-user": {
        "user_type": "IAMUser",
        "principal_id": "AIDAV6VYNULH103DEV03",
        "arn": "arn:aws:iam::134604497614:user/dev-frontend-user",
        "access_key_id": "AKIAV6VYNULH103DEV03",
        "source_pool": "vpn",
        "normal_hours": (9, 18),
        "typical_events": ["ListBuckets", "GetBucketLocation", "DescribeInstances", "GetCallerIdentity"],
        "mfa_profile": "mostly_true",
    },

    # 2. Operations / Infrastructure
    "ops-infra-user": {
        "user_type": "IAMUser",
        "principal_id": "AIDAV6VYNULH201OPS01",
        "arn": "arn:aws:iam::134604497614:user/ops-infra-user",
        "access_key_id": "AKIAV6VYNULH201OPS01",
        "source_pool": "corporate",
        "normal_hours": (7, 21),
        "typical_events": ["DescribeInstances", "DescribeSecurityGroups", "DescribeVpcs", "DescribeSubnets", "DescribeAutoScalingGroups", "DescribeVolumes"],
        "mfa_profile": "strictly_true",
    },
    "ops-platform-admin": {
        "user_type": "AssumedRole",
        "principal_id": "AROAV6VYNULH202ADM02:ops-platform-admin",
        "arn": "arn:aws:sts::134604497614:assumed-role/PlatformAdminRole/ops-platform-admin",
        "access_key_id": "ASIAV6VYNULH202ADM02",
        "source_pool": "corporate",
        "normal_hours": (8, 20),
        "typical_events": ["AssumeRole", "DescribeAutoScalingGroups", "DescribeInstances", "ListRoles", "GetRole"],
        "mfa_profile": "strictly_true",
    },

    # 3. Security Analysts (Legitimate Discovery - Hard Negative)
    "sec-analyst-alice": {
        "user_type": "IAMUser",
        "principal_id": "AIDAV6VYNULH301SEC01",
        "arn": "arn:aws:iam::134604497614:user/sec-analyst-alice",
        "access_key_id": "AKIAV6VYNULH301SEC01",
        "source_pool": "corporate",
        "normal_hours": (9, 18),
        "typical_events": ["ListRoles", "ListPolicies", "ListUsers", "GetAccountSummary", "GetAccountAuthorizationDetails", "ListSecurityConfigurations", "LookupEvents"],
        "mfa_profile": "strictly_true",
    },
    "sec-compliance-auditor": {
        "user_type": "AssumedRole",
        "principal_id": "AROAV6VYNULH302AUD02:auditor-session",
        "arn": "arn:aws:sts::134604497614:assumed-role/SecurityAuditorRole/auditor-session",
        "access_key_id": "ASIAV6VYNULH302AUD02",
        "source_pool": "vpn",
        "normal_hours": (9, 17),
        "typical_events": ["ListRoles", "ListPolicies", "GetRole", "GetPolicy", "ListBuckets", "DescribeSecurityGroups"],
        "mfa_profile": "strictly_true",
    },

    # 4. Administrators
    "breakglass-admin": {
        "user_type": "IAMUser",
        "principal_id": "AIDAV6VYNULH401BRK01",
        "arn": "arn:aws:iam::134604497614:user/breakglass-admin",
        "access_key_id": "AKIAV6VYNULH401BRK01",
        "source_pool": "corporate",
        "normal_hours": (0, 24), # Any time, but infrequent
        "typical_events": ["AssumeRole", "GetCallerIdentity", "AttachRolePolicy", "PutRolePolicy"],
        "mfa_profile": "strictly_true",
    },

    # 5. Automation / CI-CD Roles (Scheduled / Off-Hours - Hard Negatives)
    "ci-cd-deploy-role": {
        "user_type": "AssumedRole",
        "principal_id": "AROAV6VYNULH501CICD1:gitlab-runner",
        "arn": "arn:aws:sts::134604497614:assumed-role/GitLabDeployRole/gitlab-runner",
        "access_key_id": "ASIAV6VYNULH501CICD1",
        "source_pool": "cloud_vpc",
        "normal_hours": (0, 24),
        "typical_events": ["AssumeRole", "DescribeInstances", "DescribeAutoScalingGroups", "DescribeSecurityGroups"],
        "mfa_profile": "unknown",
    },
    "backup-agent-role": {
        "user_type": "AssumedRole",
        "principal_id": "AROAV6VYNULH502BCK02:nightly-backup",
        "arn": "arn:aws:sts::134604497614:assumed-role/AWSBackupDefaultRole/nightly-backup",
        "access_key_id": "ASIAV6VYNULH502BCK02",
        "source_pool": "cloud_vpc",
        "normal_hours": (1, 5), # Scheduled strictly at night!
        "typical_events": ["DescribeVolumes", "DescribeInstances", "DescribeTags"],
        "mfa_profile": "unknown",
    },
    "monitoring-agent-role": {
        "user_type": "AssumedRole",
        "principal_id": "AROAV6VYNULH503MON03:cloudwatch-agent",
        "arn": "arn:aws:sts::134604497614:assumed-role/MonitoringRole/cloudwatch-agent",
        "access_key_id": "ASIAV6VYNULH503MON03",
        "source_pool": "cloud_vpc",
        "normal_hours": (0, 24),
        "typical_events": ["DescribeInstances", "DescribeAutoScalingGroups", "DescribeVolumes"],
        "mfa_profile": "unknown",
    },

    # 6. AWS Service Principals (Hard Negative: AWSService / amazonaws.com)
    "AWSServiceRoleForResourceExplorer": {
        "user_type": "AWSService",
        "principal_id": "AROAR6VYNULHJXOQGXYCR:resource-explorer-2",
        "arn": "arn:aws:sts::134604497614:assumed-role/AWSServiceRoleForResourceExplorer/resource-explorer-2",
        "access_key_id": "ASIAR6VYNULHBPDPAQVG",
        "source_pool": "aws_service",
        "normal_hours": (0, 24),
        "typical_events": ["DescribeAutoScalingGroups", "AssumeRole", "GetDatabases", "ListResources", "ListTables", "DescribeDBSubnetGroups"],
        "mfa_profile": "unknown",
    },

    # 7. Compromised / Attacker Identities (Anomalous & Suspicious)
    "compromised-contractor": {
        "user_type": "IAMUser",
        "principal_id": "AIDAV6VYNULH601BAD01",
        "arn": "arn:aws:iam::134604497614:user/compromised-contractor",
        "access_key_id": "AKIAV6VYNULH601BAD01",
        "source_pool": "external_suspicious",
        "normal_hours": (23, 5), # Prefers off-hours
        "typical_events": ["ListRoles", "ListPolicies", "CreateAccessKey", "AttachUserPolicy", "PutRolePolicy", "ListBuckets"],
        "mfa_profile": "false",
    },
}

# ============================================================
# SOURCE IP POOLS
# ============================================================

IP_POOLS = {
    "corporate": [
        "54.240.196.15",
        "54.240.196.16",
        "12.180.45.22",
        "12.180.45.23",
    ],
    "vpn": [
        "10.100.1.45",
        "10.100.1.78",
        "10.100.2.110",
        "10.100.2.145",
    ],
    "cloud_vpc": [
        "10.0.12.44",
        "10.0.12.89",
        "172.16.5.20",
        "172.16.8.105",
    ],
    "aws_service": [
        "resource-explorer-2.amazonaws.com",
        "autoscaling.amazonaws.com",
        "sts.amazonaws.com",
        "glue.amazonaws.com",
        "ec2.amazonaws.com",
    ],
    "external_suspicious": [
        "185.220.101.5",     # Known Tor exit node range
        "45.154.255.82",     # Bulletproof VPS
        "194.26.29.117",     # Suspicious external scanning IP
        "91.240.118.24",     # Foreign anonymous proxy
        "193.106.191.66",    # Malicious cloud scanner
    ],
}

# User Agent mapping
USER_AGENTS = {
    "console": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "cli": "aws-cli/2.17.45 Python/3.11.9 Windows/10 exe/AMD64 prompt/off",
    "boto3": "Boto3/1.34.144 Python/3.11.9 Linux/5.15.0-105-generic Botocore/1.34.144",
    "terraform": "Terraform/1.8.5 (+https://www.terraform.io) Terraform-AWS-Provider/5.55.0",
    "service": "resource-explorer-2.amazonaws.com",
    "suspicious_script": "python-requests/2.31.0",
}

# Service mapping for event names
EVENT_TO_SERVICE = {
    "AssumeRole": "sts.amazonaws.com",
    "GetCallerIdentity": "sts.amazonaws.com",
    "GetSessionToken": "sts.amazonaws.com",
    "DescribeInstances": "ec2.amazonaws.com",
    "DescribeSecurityGroups": "ec2.amazonaws.com",
    "DescribeVpcs": "ec2.amazonaws.com",
    "DescribeSubnets": "ec2.amazonaws.com",
    "DescribeVolumes": "ec2.amazonaws.com",
    "DescribeTags": "ec2.amazonaws.com",
    "RunInstances": "ec2.amazonaws.com",
    "TerminateInstances": "ec2.amazonaws.com",
    "ModifyInstanceAttribute": "ec2.amazonaws.com",
    "AuthorizeSecurityGroupIngress": "ec2.amazonaws.com",
    "RevokeSecurityGroupIngress": "ec2.amazonaws.com",
    "DescribeAutoScalingGroups": "autoscaling.amazonaws.com",
    "ListBuckets": "s3.amazonaws.com",
    "GetBucketLocation": "s3.amazonaws.com",
    "PutBucketPolicy": "s3.amazonaws.com",
    "DeleteBucketPolicy": "s3.amazonaws.com",
    "ListResources": "resource-explorer-2.amazonaws.com",
    "ListServices": "resource-explorer-2.amazonaws.com",
    "ListTables": "glue.amazonaws.com",
    "GetDatabases": "glue.amazonaws.com",
    "GetTables": "glue.amazonaws.com",
    "DescribeDBSubnetGroups": "rds.amazonaws.com",
    "ListRoles": "iam.amazonaws.com",
    "GetRole": "iam.amazonaws.com",
    "ListUsers": "iam.amazonaws.com",
    "GetUser": "iam.amazonaws.com",
    "ListPolicies": "iam.amazonaws.com",
    "GetPolicy": "iam.amazonaws.com",
    "ListRolePolicies": "iam.amazonaws.com",
    "ListUserPolicies": "iam.amazonaws.com",
    "ListGroups": "iam.amazonaws.com",
    "CreateUser": "iam.amazonaws.com",
    "DeleteUser": "iam.amazonaws.com",
    "CreateRole": "iam.amazonaws.com",
    "DeleteRole": "iam.amazonaws.com",
    "AttachRolePolicy": "iam.amazonaws.com",
    "DetachRolePolicy": "iam.amazonaws.com",
    "AttachUserPolicy": "iam.amazonaws.com",
    "DetachUserPolicy": "iam.amazonaws.com",
    "PutRolePolicy": "iam.amazonaws.com",
    "PutUserPolicy": "iam.amazonaws.com",
    "CreateAccessKey": "iam.amazonaws.com",
    "UpdateAccessKey": "iam.amazonaws.com",
    "DeleteAccessKey": "iam.amazonaws.com",
    "CreatePolicy": "iam.amazonaws.com",
    "CreatePolicyVersion": "iam.amazonaws.com",
    "SetDefaultPolicyVersion": "iam.amazonaws.com",
    "DeletePolicy": "iam.amazonaws.com",
    "PassRole": "iam.amazonaws.com",
    "UpdateAssumeRolePolicy": "iam.amazonaws.com",
    "ListSecurityConfigurations": "emr.amazonaws.com",
    "GetAccountSummary": "iam.amazonaws.com",
    "GetAccountAuthorizationDetails": "iam.amazonaws.com",
    "LookupEvents": "cloudtrail.amazonaws.com",
}

# ============================================================
# BEHAVIORAL SEQUENCE DEFINITIONS
# ============================================================

CORRELATED_SEQUENCE_TEMPLATES = {
    "Reconnaissance Sequence": [
        "ListResources",
        "ListTables",
        "ListBuckets",
        "DescribeDBSubnetGroups",
    ],
    "Sensitive IAM Activity": [
        "ListSecurityConfigurations",
        "AssumeRole",
        "ListRolePolicies",
    ],
    "Service Discovery Pattern": [
        "ListServices",
        "ListResources",
        "DescribeAutoScalingGroups",
    ],
    "Privilege Escalation Sequence": [
        "AssumeRole",
        "CreateRole",
        "AttachRolePolicy",
        "PassRole",
    ],
    "Compound Attack Chain": [
        "ListRoles",
        "ListPolicies",
        "AttachRolePolicy",          # Often failed first!
        "CreateAccessKey",
        "AttachRolePolicy",          # Successful
        "AssumeRole",
        "ListResources",
        "DescribeInstances",
    ],
}
