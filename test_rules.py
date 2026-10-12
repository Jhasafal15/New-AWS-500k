"""
Unit tests for Module 3: Security Analysis - Rule-Based Engine
Verifies that 100% of injected misconfigurations are flagged and findings conform to Data Contract.
"""

import os
import json
import pytest
from src.rules.scanner import CloudSecurityScanner
from src.rules.iam_rules import RuleIamMfa, RuleIamAdmin
from src.rules.s3_rules import RuleS3Public, RuleS3Encryption
from src.rules.ec2_rules import RuleEc2Ingress, RuleEc2OutdatedAmi
from src.rules.cloudtrail_rules import (
    RuleCloudtrailNonMfaSession,
    RuleCloudtrailServiceExceptions,
    RulePrivilegeEscalationAttempt,
    RuleFailedSensitiveOperations,
    RuleCredentialTamperingActivity
)

@pytest.fixture
def inventory_data():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    inv_file = os.path.join(base_dir, "data", "processed", "cloud_inventory.json")
    with open(inv_file, "r") as f:
        return json.load(f)

@pytest.fixture
def scanner():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    inv_file = os.path.join(base_dir, "data", "processed", "cloud_inventory.json")
    return CloudSecurityScanner(inv_file)

def test_100_percent_iam_mfa_injected_flagged(inventory_data):
    """Verifies that 100% of users without MFA are flagged."""
    unprotected_users = [u for u in inventory_data["iam_users"] if not u["mfa_active"]]
    findings = RuleIamMfa().evaluate(inventory_data)
    
    flagged_ids = {f["resource_id"] for f in findings}
    for user in unprotected_users:
        user_arn = user["arn"]
        assert user_arn in flagged_ids, f"User {user['name']} without MFA was NOT flagged!"
    
    assert len(flagged_ids) == len(unprotected_users), "MFA detection rate is not 100%!"

def test_100_percent_iam_admin_wildcard_flagged(inventory_data):
    """Verifies that 100% of principals with wildcard admin are flagged."""
    admin_entities = [
        e for e in (inventory_data["iam_users"] + inventory_data["iam_roles"])
        if e.get("has_admin_policy") or e.get("has_wildcard_permission")
    ]
    findings = RuleIamAdmin().evaluate(inventory_data)
    
    flagged_ids = {f["resource_id"] for f in findings}
    for entity in admin_entities:
        assert entity["arn"] in flagged_ids, f"Admin entity {entity['name']} was NOT flagged!"

    assert len(flagged_ids) == len(admin_entities), "Admin wildcard detection rate is not 100%!"

def test_100_percent_s3_public_and_unencrypted_flagged(inventory_data):
    """Verifies that 100% of public and unencrypted S3 buckets are flagged."""
    public_buckets = [b for b in inventory_data["s3_buckets"] if b["is_public"]]
    unencrypted_buckets = [b for b in inventory_data["s3_buckets"] if not b["encryption_enabled"]]

    pub_findings = RuleS3Public().evaluate(inventory_data)
    enc_findings = RuleS3Encryption().evaluate(inventory_data)

    flagged_pub_ids = {f["resource_id"] for f in pub_findings}
    flagged_enc_ids = {f["resource_id"] for f in enc_findings}

    for b in public_buckets:
        assert b["arn"] in flagged_pub_ids, f"Public bucket {b['bucket_name']} was NOT flagged!"

    for b in unencrypted_buckets:
        assert b["arn"] in flagged_enc_ids, f"Unencrypted bucket {b['bucket_name']} was NOT flagged!"

    assert len(flagged_pub_ids) == len(public_buckets)
    assert len(flagged_enc_ids) == len(unencrypted_buckets)

def test_100_percent_ec2_ingress_open_ports_flagged(inventory_data):
    """Verifies that 100% of instances with open port 22 or 3389 to 0.0.0.0/0 are flagged."""
    open_ssh_instances = [i for i in inventory_data["ec2_instances"] if 22 in i["internet_exposed_ports"]]
    open_rdp_instances = [i for i in inventory_data["ec2_instances"] if 3389 in i["internet_exposed_ports"]]

    findings = RuleEc2Ingress().evaluate(inventory_data)
    
    ssh_flagged_iids = {f["resource_id"] for f in findings if f["rule_name"] == "Public SSH Port Open to Internet"}
    rdp_flagged_iids = {f["resource_id"] for f in findings if f["rule_name"] == "Public RDP Port Open to Internet"}

    for inst in open_ssh_instances:
        assert inst["instance_id"] in ssh_flagged_iids, f"Instance {inst['name']} with open SSH not flagged!"

    for inst in open_rdp_instances:
        assert inst["instance_id"] in rdp_flagged_iids, f"Instance {inst['name']} with open RDP not flagged!"

    assert len(ssh_flagged_iids) == len(open_ssh_instances)
    assert len(rdp_flagged_iids) == len(open_rdp_instances)

def test_100_percent_outdated_ami_flagged(inventory_data):
    """Verifies that 100% of outdated AMIs are flagged."""
    outdated = [i for i in inventory_data["ec2_instances"] if i.get("is_outdated_ami")]
    findings = RuleEc2OutdatedAmi().evaluate(inventory_data)

    flagged_iids = {f["resource_id"] for f in findings}
    for inst in outdated:
        assert inst["instance_id"] in flagged_iids, f"Outdated AMI on {inst['name']} was not flagged!"
    assert len(flagged_iids) == len(outdated)

def test_data_contract_conformance(scanner):
    """Verifies that 100% of generated findings strictly comply with the JSON Data Contract schema."""
    findings = scanner.run_all_checks()
    assert len(findings) > 0, "Scanner should generate findings"

    required_keys = [
        "finding_id",
        "resource_type",
        "resource_id",
        "category",
        "rule_name",
        "severity",
        "description",
        "raw_config",
        "timestamp"
    ]
    allowed_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    allowed_categories = {"IAM Security", "Network Security", "Storage Security", "Compute Security"}

    for finding in findings:
        for key in required_keys:
            assert key in finding, f"Finding missing mandatory field '{key}': {finding}"
            assert finding[key] is not None, f"Field '{key}' in finding cannot be None!"

        assert finding["severity"] in allowed_severities
        assert finding["category"] in allowed_categories
        assert isinstance(finding["raw_config"], dict)
        assert len(finding["description"]) > 10

def test_enterprise_privilege_escalation_rule(inventory_data):
    """Verifies that IAM privilege escalation attacks from 500k CloudTrail are flagged."""
    findings = RulePrivilegeEscalationAttempt().evaluate(inventory_data)
    assert len(findings) > 0
    for f in findings:
        assert f["rule_name"] == "IAM Privilege Escalation Attempt Detected"
        assert f["severity"] == "CRITICAL"
        assert "risk_score" in f["raw_config"]

def test_enterprise_failed_sensitive_operations_rule(inventory_data):
    """Verifies that unauthorized sensitive policy operations from 500k CloudTrail are flagged."""
    findings = RuleFailedSensitiveOperations().evaluate(inventory_data)
    assert len(findings) > 0
    for f in findings:
        assert f["rule_name"] == "Unauthorized Sensitive Operation & Policy Tampering"
        assert f["severity"] == "HIGH"

def test_enterprise_credential_tampering_rule(inventory_data):
    """Verifies that abnormal access key manipulation from 500k CloudTrail is flagged."""
    findings = RuleCredentialTamperingActivity().evaluate(inventory_data)
    assert len(findings) > 0
    for f in findings:
        assert f["rule_name"] == "Abnormal Access Key Credential Manipulation"
        assert f["severity"] == "HIGH"

def test_enterprise_service_exceptions_rule(inventory_data):
    """Verifies that services with CloudTrail errors are flagged."""
    findings = RuleCloudtrailServiceExceptions().evaluate(inventory_data)
    assert len(findings) >= 1
    for f in findings:
        assert f["severity"] == "MEDIUM"


