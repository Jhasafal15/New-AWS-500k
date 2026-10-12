"""
Unit tests for Module 1: Synthetic Data Generators
"""

import os
import json
import pytest
from src.generators.generate_mock_cloud_data import (
    generate_iam_data,
    generate_s3_data,
    generate_vpcs_and_networks,
    generate_ec2_data,
    generate_cloudtrail_logs
)

def test_iam_generator_count_and_structure():
    iam_data = generate_iam_data(num_users=35, num_roles=15)
    assert len(iam_data) == 50, "Should generate exactly 50 IAM users/roles"
    
    users = [u for u in iam_data if u["type"] == "USER"]
    roles = [r for r in iam_data if r["type"] == "ROLE"]
    assert len(users) == 35
    assert len(roles) == 15

    # Check required fields
    for entity in iam_data:
        assert "resource_id" in entity
        assert "arn" in entity
        assert entity["arn"].startswith("arn:aws:iam::")
        assert "mfa_active" in entity
        assert "attached_policies" in entity
        assert "_injected_misconfiguration" in entity

def test_s3_generator_count_and_structure():
    buckets = generate_s3_data(num_buckets=30)
    assert len(buckets) == 30, "Should generate exactly 30 S3 buckets"

    public_buckets = [b for b in buckets if b["is_public"]]
    unencrypted_buckets = [b for b in buckets if not b["encryption_enabled"]]
    
    assert len(public_buckets) > 0, "Should contain public buckets"
    assert len(unencrypted_buckets) > 0, "Should contain unencrypted buckets"

    for b in buckets:
        assert "bucket_name" in b
        assert b["arn"].startswith("arn:aws:s3:::")
        assert "acl_grants" in b
        assert "public_access_block" in b

def test_ec2_and_vpc_generator():
    vpcs = generate_vpcs_and_networks(num_vpcs=5)
    assert len(vpcs) == 5
    for v in vpcs:
        assert len(v["subnets"]) == 2

    instances = generate_ec2_data(vpcs, num_instances=40)
    assert len(instances) == 40
    
    open_ssh = [i for i in instances if i["_injected_misconfiguration"]["open_ssh"]]
    open_rdp = [i for i in instances if i["_injected_misconfiguration"]["open_rdp"]]
    outdated_amis = [i for i in instances if i["_injected_misconfiguration"]["outdated_ami"]]

    assert len(open_ssh) > 0, "Should inject open SSH instances"
    assert len(open_rdp) > 0, "Should inject open RDP instances"
    assert len(outdated_amis) > 0, "Should inject outdated AMIs"

def test_cloudtrail_generator_count():
    iam_data = generate_iam_data(num_users=10, num_roles=5)
    vpcs = generate_vpcs_and_networks(num_vpcs=2)
    ec2_data = generate_ec2_data(vpcs, num_instances=10)
    s3_data = generate_s3_data(num_buckets=10)

    events = generate_cloudtrail_logs(iam_data, ec2_data, s3_data, count=1000)
    assert len(events) >= 1000, "Should generate at least 1000 CloudTrail events"
    
    for ev in events[:20]:
        assert "eventId" in ev
        assert "eventTime" in ev
        assert "eventName" in ev
        assert "userIdentity" in ev
