"""
Generator for Synthetic CSPM Inventory and Cloud Vulnerability Records.
Directly implements the project's vulnerability rules and resource taxonomy.
"""

import json
import uuid
from pathlib import Path
from typing import Dict, List, Any

import numpy as np
import pandas as pd

from .config import (
    RANDOM_SEED,
    SYNTHETIC_ACCOUNT_ID,
    AWS_REGIONS,
    CSPM_CSV,
    SYNTHETIC_DIR,
)
from .scenarios import IDENTITIES

np.random.seed(RANDOM_SEED)

VULNERABILITY_CATALOG = [
    {
        "vulnerability_id": "IAM-V001",
        "name": "Wildcard IAM Permission",
        "category": "IAM",
        "severity": "HIGH",
        "service": "iam",
        "resource_type": "iam_principal",
        "description": "An IAM principal has an Allow statement containing a wildcard action or resource (*:*).",
        "recommendation": "Replace wildcard permissions with the minimum actions and resources required.",
        "evidence_tmpl": {"wildcard_actions": ["*:*"], "effect": "Allow", "policy_name": "FullAdminAccess"}
    },
    {
        "vulnerability_id": "IAM-V002",
        "name": "Administrative IAM Permission",
        "category": "IAM",
        "severity": "HIGH",
        "service": "iam",
        "resource_type": "iam_principal",
        "description": "An IAM principal has broad service-level administrative permissions without boundary restrictions.",
        "recommendation": "Review the permission set and reduce it to least privilege.",
        "evidence_tmpl": {"administrative_actions": ["iam:*", "ec2:*"], "policy_name": "ServiceAdminPolicy"}
    },
    {
        "vulnerability_id": "IAM-V003",
        "name": "IAM User Without MFA",
        "category": "IAM",
        "severity": "MEDIUM",
        "service": "iam",
        "resource_type": "iam_principal",
        "description": "An active IAM user was observed without an enabled virtual or hardware MFA device.",
        "recommendation": "Enable MFA for the IAM user and require MFA for sensitive access.",
        "evidence_tmpl": {"mfa_devices": [], "login_profile_exists": True, "password_last_used": "2026-09-20"}
    },
    {
        "vulnerability_id": "IAM-V004",
        "name": "Potential IAM Privilege Escalation Permission",
        "category": "IAM",
        "severity": "HIGH",
        "service": "iam",
        "resource_type": "iam_principal",
        "description": "The IAM principal has permissions that can modify or pass privileged roles/policies (iam:PassRole, iam:AttachUserPolicy).",
        "recommendation": "Review these permissions and remove them unless explicitly required.",
        "evidence_tmpl": {"escalation_actions": ["iam:PassRole", "iam:AttachUserPolicy"], "risk": "RoleAssumptionAndPolicyAttach"}
    },
    {
        "vulnerability_id": "NET-V001",
        "name": "Public SSH Exposure",
        "category": "NETWORK",
        "severity": "HIGH",
        "service": "ec2",
        "resource_type": "security_group",
        "description": "SSH port 22 is reachable from an unrestricted public source (0.0.0.0/0).",
        "recommendation": "Restrict SSH to trusted CIDRs or use a private administration path such as AWS Systems Manager Session Manager.",
        "evidence_tmpl": {"port": 22, "protocol": "tcp", "cidr_ip": "0.0.0.0/0", "direction": "ingress"}
    },
    {
        "vulnerability_id": "NET-V002",
        "name": "Public RDP Exposure",
        "category": "NETWORK",
        "severity": "HIGH",
        "service": "ec2",
        "resource_type": "security_group",
        "description": "RDP port 3389 is reachable from an unrestricted public source (0.0.0.0/0).",
        "recommendation": "Restrict RDP to trusted CIDRs or use a private administration path.",
        "evidence_tmpl": {"port": 3389, "protocol": "tcp", "cidr_ip": "0.0.0.0/0", "direction": "ingress"}
    },
    {
        "vulnerability_id": "NET-V003",
        "name": "Unrestricted Network Ingress",
        "category": "NETWORK",
        "severity": "HIGH",
        "service": "ec2",
        "resource_type": "security_group",
        "description": "A security-group rule permits all ports and protocols from an unrestricted public source (0.0.0.0/0).",
        "recommendation": "Remove unrestricted ingress and permit only required ports and sources.",
        "evidence_tmpl": {"port_range": "ALL", "protocol": "-1", "cidr_ip": "0.0.0.0/0", "direction": "ingress"}
    },
    {
        "vulnerability_id": "STG-V001",
        "name": "Public S3 Bucket",
        "category": "STORAGE",
        "severity": "HIGH",
        "service": "s3",
        "resource_type": "s3_bucket",
        "description": "The S3 bucket policy or ACL status permits public read/write access.",
        "recommendation": "Remove unintended public access and enable S3 Block Public Access settings.",
        "evidence_tmpl": {"public_read": True, "public_write": False, "block_public_access": False}
    },
    {
        "vulnerability_id": "STG-V002",
        "name": "S3 Bucket Without Default Encryption Evidence",
        "category": "STORAGE",
        "severity": "MEDIUM",
        "service": "s3",
        "resource_type": "s3_bucket",
        "description": "The collector could not find a default encryption configuration on the S3 bucket.",
        "recommendation": "Enable S3 default encryption using SSE-S3 or SSE-KMS.",
        "evidence_tmpl": {"server_side_encryption": "None", "enforce_ssl": False}
    },
    {
        "vulnerability_id": "CMP-V001",
        "name": "Public EC2 Instance",
        "category": "COMPUTE",
        "severity": "MEDIUM",
        "service": "ec2",
        "resource_type": "ec2_instance",
        "description": "The EC2 instance is located in a public subnet and has an assigned public IPv4 address.",
        "recommendation": "Remove unnecessary public exposure or place the instance behind a load balancer and private subnet.",
        "evidence_tmpl": {"public_ip": "54.210.14.99", "subnet_type": "public", "association_id": "eipassoc-0a1b2c3d"}
    },
    {
        "vulnerability_id": "CMP-V002",
        "name": "Unencrypted EBS Volume",
        "category": "COMPUTE",
        "severity": "MEDIUM",
        "service": "ec2",
        "resource_type": "ebs_volume",
        "description": "At least one attached EBS storage volume is reported as unencrypted.",
        "recommendation": "Migrate the workload to encrypted EBS volumes and enforce EBS encryption by default.",
        "evidence_tmpl": {"volume_id": "vol-0123456789abcdef0", "encrypted": False, "kms_key_id": None}
    },
    {
        "vulnerability_id": "CVE-V001",
        "name": "Known Inspector Vulnerability",
        "category": "VULNERABILITY",
        "severity": "HIGH",
        "service": "inspector2",
        "resource_type": "ec2_instance",
        "description": "Amazon Inspector reported a high-severity software package vulnerability (CVE-2024-6387 OpenSSH RegreSSHion).",
        "recommendation": "Patch or upgrade the affected package and verify the Inspector finding is resolved.",
        "evidence_tmpl": {"cve_id": "CVE-2024-6387", "package": "openssh-server", "installed_version": "8.9p1", "fixed_version": "9.8p1"}
    },
]


def generate_cspm_inventory(num_records: int = 5000) -> pd.DataFrame:
    """
    Generates a linked synthetic CSPM posture and inventory dataset.
    Cross-links principals, buckets, and security groups with CloudTrail activity.
    """
    print(f"Generating {num_records:,} synthetic CSPM inventory records...")
    records = []

    # Cross-reference existing identities
    ident_list = list(IDENTITIES.keys())

    for i in range(num_records):
        # 30% are vulnerable findings, 70% are compliant/healthy posture inventory
        is_vuln = (np.random.rand() < 0.35)
        reg = np.random.choice(AWS_REGIONS)

        if is_vuln:
            vuln_meta = np.random.choice(VULNERABILITY_CATALOG)
            vuln_id = vuln_meta["vulnerability_id"]
            name = vuln_meta["name"]
            service = vuln_meta["service"]
            res_type = vuln_meta["resource_type"]
            severity = vuln_meta["severity"]
            desc = vuln_meta["description"]
            rec_action = vuln_meta["recommendation"]
            config_status = "NON_COMPLIANT"

            if service == "iam":
                # Link to an identity
                chosen_user = np.random.choice(ident_list)
                res_id = IDENTITIES[chosen_user]["arn"]
                res_name = chosen_user
                enc_status = "NOT_APPLICABLE"
                public_exp = "INTERNAL_ONLY"
                mfa_en = (IDENTITIES[chosen_user]["mfa_profile"] == "strictly_true")
                scope = "OVERPERMISSIVE" if "Admin" in vuln_meta["name"] or "Wildcard" in vuln_meta["name"] else "RESTRICTED"
                priv_level = "CRITICAL_ADMIN" if "Admin" in vuln_meta["name"] else "POWER_USER"
            elif service == "s3":
                bucket_name = f"corp-assets-{reg}-{i:04d}"
                res_id = f"arn:aws:s3:::{bucket_name}"
                res_name = bucket_name
                enc_status = "UNENCRYPTED" if vuln_id == "STG-V002" else "ENCRYPTED_AES256"
                public_exp = "PUBLIC" if vuln_id == "STG-V001" else "INTERNAL_ONLY"
                mfa_en = False
                scope = "PUBLIC_READ" if vuln_id == "STG-V001" else "STORAGE_DATA"
                priv_level = "STANDARD"
            elif service == "ec2" and res_type == "security_group":
                sg_id = f"sg-{uuid.uuid4().hex[:17]}"
                res_id = f"arn:aws:ec2:{reg}:{SYNTHETIC_ACCOUNT_ID}:security-group/{sg_id}"
                res_name = f"launch-wizard-sg-{i:03d}"
                enc_status = "NOT_APPLICABLE"
                public_exp = "PUBLIC"
                mfa_en = False
                scope = "INGRESS_PERMISSIVE"
                priv_level = "NETWORK_INLINE"
            else: # EC2 Instance or EBS
                inst_id = f"i-{uuid.uuid4().hex[:17]}"
                res_id = f"arn:aws:ec2:{reg}:{SYNTHETIC_ACCOUNT_ID}:instance/{inst_id}"
                res_name = f"web-app-node-{reg}-{i:03d}"
                enc_status = "UNENCRYPTED" if vuln_id == "CMP-V002" else "ENCRYPTED_KMS"
                public_exp = "PUBLIC" if vuln_id == "CMP-V001" else "INTERNAL_ONLY"
                mfa_en = False
                scope = "COMPUTE_HOST"
                priv_level = "STANDARD"

            evidence = dict(vuln_meta["evidence_tmpl"])
        else:
            # Compliant Inventory Record
            service = np.random.choice(["iam", "s3", "ec2"])
            vuln_id = "NONE"
            name = "Compliant Resource Baseline"
            severity = "LOW"
            desc = "Resource configuration adheres to CIS AWS Foundations and internal CSPM baselines."
            rec_action = "Continue automated posture assessment; no remediation required."
            config_status = "COMPLIANT"
            enc_status = "ENCRYPTED_KMS"
            public_exp = "INTERNAL_ONLY"
            mfa_en = True
            scope = "RESTRICTED_LEAST_PRIVILEGE"
            priv_level = "STANDARD"
            evidence = {"cis_benchmark_pass": True, "least_privilege_enforced": True}

            if service == "iam":
                chosen_user = np.random.choice(ident_list)
                res_id = IDENTITIES[chosen_user]["arn"]
                res_name = chosen_user
                res_type = "iam_principal"
            elif service == "s3":
                b_name = f"corp-secure-vault-{reg}-{i:04d}"
                res_id = f"arn:aws:s3:::{b_name}"
                res_name = b_name
                res_type = "s3_bucket"
            else:
                inst_id = f"i-{uuid.uuid4().hex[:17]}"
                res_id = f"arn:aws:ec2:{reg}:{SYNTHETIC_ACCOUNT_ID}:instance/{inst_id}"
                res_name = f"backend-secure-worker-{i:03d}"
                res_type = "ec2_instance"

        records.append({
            "resource_id": res_id,
            "resource_type": res_type,
            "resource_name": res_name,
            "service": service,
            "region": reg if service != "iam" else "global",
            "account_id": SYNTHETIC_ACCOUNT_ID,
            "configuration_status": config_status,
            "encryption_status": enc_status,
            "public_exposure": public_exp,
            "mfa_enabled": mfa_en,
            "policy_scope": scope,
            "privilege_level": priv_level,
            "vulnerability_id": vuln_id,
            "vulnerability_name": name,
            "severity": severity,
            "description": desc,
            "evidence": json.dumps(evidence),
            "recommended_action": rec_action,
        })

    df_cspm = pd.DataFrame(records)
    SYNTHETIC_DIR.mkdir(parents=True, exist_ok=True)
    df_cspm.to_csv(CSPM_CSV, index=False)
    print(f"CSPM inventory dataset saved to {CSPM_CSV} ({len(df_cspm)} records).")
    return df_cspm


def main():
    generate_cspm_inventory(num_records=5000)


if __name__ == "__main__":
    main()
