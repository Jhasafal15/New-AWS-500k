"""
Module 3: Cloud Security Scanner Engine
Implementation Blueprint following Student 1 guide specifications.
Executes modular rule checks across IAM, S3, EC2, and Network configs.
Outputs findings strictly matching data contract for Student 2 & 3.
"""

import os
import json
import logging
import sys
from typing import List, Dict, Any

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from src.rules.iam_rules import RuleIamMfa, RuleIamAdmin, RuleIamInactiveCredentials
    from src.rules.s3_rules import RuleS3Public, RuleS3Encryption, RuleS3Versioning
    from src.rules.ec2_rules import RuleEc2Ingress, RuleEc2OutdatedAmi, RuleEc2VulnerableSoftware
    from src.rules.cloudtrail_rules import (
        RuleCloudtrailNonMfaSession,
        RuleCloudtrailInspectorDisabled,
        RuleCloudtrailServiceExceptions,
        RuleCloudtrailReconnaissance,
        RulePrivilegeEscalationAttempt,
        RuleFailedSensitiveOperations,
        RuleCredentialTamperingActivity
    )
except ImportError:
    from iam_rules import RuleIamMfa, RuleIamAdmin, RuleIamInactiveCredentials
    from s3_rules import RuleS3Public, RuleS3Encryption, RuleS3Versioning
    from ec2_rules import RuleEc2Ingress, RuleEc2OutdatedAmi, RuleEc2VulnerableSoftware
    from cloudtrail_rules import (
        RuleCloudtrailNonMfaSession,
        RuleCloudtrailInspectorDisabled,
        RuleCloudtrailServiceExceptions,
        RuleCloudtrailReconnaissance,
        RulePrivilegeEscalationAttempt,
        RuleFailedSensitiveOperations,
        RuleCredentialTamperingActivity
    )

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CloudSecurityScanner")

class CloudSecurityScanner:
    def __init__(self, inventory_path: str):
        self.inventory_path = inventory_path
        if not os.path.exists(inventory_path):
            raise FileNotFoundError(f"Normalized cloud inventory file not found: {inventory_path}")
        with open(inventory_path, 'r', encoding='utf-8') as f:
            self.inventory = json.load(f)
        self.findings: List[Dict[str, Any]] = []

    # Modular rule functions explicitly requested in the Day 12-15 Roadmap:
    def rule_iam_mfa(self) -> List[Dict[str, Any]]:
        """Flags active users without MFA."""
        return RuleIamMfa().evaluate(self.inventory)

    def rule_iam_admin(self) -> List[Dict[str, Any]]:
        """Detects wildcard AdministratorAccess policies."""
        return RuleIamAdmin().evaluate(self.inventory)

    def rule_s3_public(self) -> List[Dict[str, Any]]:
        """Flags public read/write ACLs and missing SSE encryption."""
        # Combines public access and missing encryption as outlined in blueprint
        findings = []
        findings.extend(RuleS3Public().evaluate(self.inventory))
        findings.extend(RuleS3Encryption().evaluate(self.inventory))
        return findings

    def rule_ec2_ingress(self) -> List[Dict[str, Any]]:
        """Scans Security Groups for 0.0.0.0/0 on ports 22, 3389, 8080."""
        return RuleEc2Ingress().evaluate(self.inventory)

    # Category Scanners
    def scan_iam(self) -> List[Dict[str, Any]]:
        iam_findings = []
        iam_findings.extend(self.rule_iam_mfa())
        iam_findings.extend(self.rule_iam_admin())
        iam_findings.extend(RuleIamInactiveCredentials().evaluate(self.inventory))
        logger.info(f"IAM Scan completed: {len(iam_findings)} findings identified.")
        return iam_findings

    def scan_s3_buckets(self) -> List[Dict[str, Any]]:
        s3_findings = []
        s3_findings.extend(RuleS3Public().evaluate(self.inventory))
        s3_findings.extend(RuleS3Encryption().evaluate(self.inventory))
        s3_findings.extend(RuleS3Versioning().evaluate(self.inventory))
        logger.info(f"S3 Scan completed: {len(s3_findings)} findings identified.")
        return s3_findings

    def scan_ec2_instances(self) -> List[Dict[str, Any]]:
        ec2_findings = []
        ec2_findings.extend(self.rule_ec2_ingress())
        ec2_findings.extend(RuleEc2OutdatedAmi().evaluate(self.inventory))
        ec2_findings.extend(RuleEc2VulnerableSoftware().evaluate(self.inventory))
        logger.info(f"EC2 & Network Scan completed: {len(ec2_findings)} findings identified.")
        return ec2_findings

    def scan_cloudtrail(self) -> List[Dict[str, Any]]:
        """Audits CloudTrail logs for non-MFA sessions, disabled Inspector, service exceptions, and enterprise attacks."""
        ct_findings = []
        ct_findings.extend(RuleCloudtrailNonMfaSession().evaluate(self.inventory))
        ct_findings.extend(RuleCloudtrailInspectorDisabled().evaluate(self.inventory))
        ct_findings.extend(RuleCloudtrailServiceExceptions().evaluate(self.inventory))
        ct_findings.extend(RuleCloudtrailReconnaissance().evaluate(self.inventory))
        ct_findings.extend(RulePrivilegeEscalationAttempt().evaluate(self.inventory))
        ct_findings.extend(RuleFailedSensitiveOperations().evaluate(self.inventory))
        ct_findings.extend(RuleCredentialTamperingActivity().evaluate(self.inventory))
        logger.info(f"CloudTrail Audit Scan completed: {len(ct_findings)} findings identified.")
        return ct_findings

    def run_all_checks(self) -> List[Dict[str, Any]]:
        """Runs all policy-as-code security scanners and aggregates findings."""
        self.findings = []
        self.findings.extend(self.scan_iam())
        self.findings.extend(self.scan_s3_buckets())
        self.findings.extend(self.scan_ec2_instances())
        self.findings.extend(self.scan_cloudtrail())
        logger.info(f"All security rules executed. Total findings: {len(self.findings)}")
        return self.findings

    def export_findings(self, output_path: str) -> None:
        """Saves findings to JSON file conforming strictly to the Data Contract."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.findings, f, indent=2)
        logger.info(f"Exported {len(self.findings)} findings to {output_path}")

    def generate_summary(self) -> Dict[str, Any]:
        """Provides statistics breakdown by severity and category for Student 2 & 3."""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        category_counts = {}

        for f in self.findings:
            sev = f.get("severity", "LOW")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            cat = f.get("category", "General")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        return {
            "total_findings": len(self.findings),
            "severity_breakdown": severity_counts,
            "category_breakdown": category_counts
        }

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    inv_file = os.path.join(base_dir, "data", "processed", "cloud_inventory.json")
    out_file = os.path.join(base_dir, "data", "processed", "rule_findings.json")

    scanner = CloudSecurityScanner(inv_file)
    scanner.run_all_checks()
    scanner.export_findings(out_file)
    print(json.dumps(scanner.generate_summary(), indent=2))
