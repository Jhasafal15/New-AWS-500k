"""
S3 Storage Security Rules (CIS AWS Benchmark Section 2)
"""

import sys
import os
from typing import List, Dict, Any
try:
    from .base_rule import BaseRule, Category, Severity
except ImportError:
    try:
        from src.rules.base_rule import BaseRule, Category, Severity
    except ImportError:
        from base_rule import BaseRule, Category, Severity

class RuleS3Public(BaseRule):
    """CIS AWS 2.1.5: Ensure S3 Buckets are not publicly accessible."""
    def __init__(self):
        super().__init__(
            rule_id="RULE-S3-001",
            rule_name="S3 Bucket Publicly Accessible",
            category=Category.STORAGE,
            severity=Severity.HIGH,
            description="S3 bucket has public read/write permissions or missing Public Access Block."
        )

    def evaluate(self, inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        buckets = inventory.get("s3_buckets", [])

        for bucket in buckets:
            bname = bucket.get("bucket_name")
            is_public = bucket.get("is_public", False)

            if is_public:
                classification = bucket.get("tags", {}).get("DataClassification", "General")
                severity = Severity.CRITICAL if classification == "Confidential" else Severity.HIGH
                desc = (
                    f"CRITICAL: S3 Bucket '{bname}' containing confidential data is publicly accessible to the internet!"
                    if severity == Severity.CRITICAL else
                    f"Bucket '{bname}' has public read/write permissions enabled or lacks S3 Public Access Block."
                )

                findings.append(self.create_finding(
                    resource_type="S3_BUCKET",
                    resource_id=bucket.get("arn", bname),
                    description=desc,
                    severity=severity,
                    raw_config=bucket.get("raw_config", {
                        "is_public": True,
                        "has_public_acl": bucket.get("has_public_acl", False),
                        "public_access_block_enabled": bucket.get("public_access_block_enabled", False)
                    }),
                    custom_suffix=bname
                ))
        return findings


class RuleS3Encryption(BaseRule):
    """CIS AWS 2.1.1: Ensure S3 bucket default encryption is enabled."""
    def __init__(self):
        super().__init__(
            rule_id="RULE-S3-002",
            rule_name="S3 Bucket Missing Default Encryption",
            category=Category.STORAGE,
            severity=Severity.MEDIUM,
            description="Bucket does not enforce AWS KMS/AES-256 server-side encryption."
        )

    def evaluate(self, inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        buckets = inventory.get("s3_buckets", [])

        for bucket in buckets:
            bname = bucket.get("bucket_name")
            encryption_enabled = bucket.get("encryption_enabled", False)

            if not encryption_enabled:
                findings.append(self.create_finding(
                    resource_type="S3_BUCKET",
                    resource_id=bucket.get("arn", bname),
                    description=f"Bucket '{bname}' does not enforce AWS KMS or AES-256 server-side encryption at rest.",
                    severity=Severity.MEDIUM,
                    raw_config=bucket.get("raw_config", {
                        "encryption_enabled": False,
                        "server_side_encryption_algorithm": None
                    }),
                    custom_suffix=bname
                ))
        return findings


class RuleS3Versioning(BaseRule):
    """CIS AWS 2.1.3: Ensure S3 bucket versioning is enabled to protect from accidental deletion."""
    def __init__(self):
        super().__init__(
            rule_id="RULE-S3-003",
            rule_name="S3 Bucket Versioning Disabled",
            category=Category.STORAGE,
            severity=Severity.LOW,
            description="S3 bucket does not have object versioning enabled."
        )

    def evaluate(self, inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        buckets = inventory.get("s3_buckets", [])

        for bucket in buckets:
            bname = bucket.get("bucket_name")
            if not bucket.get("versioning_enabled", False):
                findings.append(self.create_finding(
                    resource_type="S3_BUCKET",
                    resource_id=bucket.get("arn", bname),
                    description=f"Bucket '{bname}' does not have object versioning enabled, increasing ransomware/tamper risk.",
                    severity=Severity.LOW,
                    raw_config=bucket.get("raw_config", {"versioning_enabled": False}),
                    custom_suffix=bname
                ))
        return findings
