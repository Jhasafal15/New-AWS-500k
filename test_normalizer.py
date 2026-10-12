"""
Unit tests for Module 2: Data Loader and Normalizer
"""

import os
import json
import pytest
from src.ingestion.data_loader import DataLoader
from src.ingestion.normalizer import CloudDataNormalizer

@pytest.fixture
def sample_raw_data():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    raw_dir = os.path.join(base_dir, "data", "raw")
    loader = DataLoader(raw_dir)
    return loader.load_all()

def test_data_loader_ingestion(sample_raw_data):
    assert len(sample_raw_data["iam"]) == 50
    assert len(sample_raw_data["s3"]) == 30
    assert len(sample_raw_data["ec2"]) == 40
    assert len(sample_raw_data["vpcs"]) == 5
    assert len(sample_raw_data["cloudtrail"]) >= 50
    assert len(sample_raw_data["software_inventory"]) > 0

def test_normalizer_timestamp_and_identifiers(sample_raw_data):
    normalizer = CloudDataNormalizer(sample_raw_data)
    
    # Test IAM normalization
    iam_res = normalizer.normalize_iam()
    assert "users" in iam_res and "roles" in iam_res
    for user in iam_res["users"]:
        assert user["arn"].startswith("arn:aws:iam::")
        assert "mfa_active" in user
        assert isinstance(user["mfa_active"], bool)
        assert "has_admin_policy" in user
        assert "raw_config" in user

    # Test S3 normalization
    s3_res = normalizer.normalize_s3()
    assert len(s3_res) == 30
    for bucket in s3_res:
        assert bucket["arn"].startswith("arn:aws:s3:::")
        assert isinstance(bucket["is_public"], bool)
        assert isinstance(bucket["encryption_enabled"], bool)

    # Test EC2 normalization
    ec2_res = normalizer.normalize_ec2()
    assert len(ec2_res) == 40
    for inst in ec2_res:
        assert inst["arn"].startswith("arn:aws:ec2:")
        assert isinstance(inst["open_ports"], list)
        assert isinstance(inst["internet_exposed_ports"], list)
        assert "software_inventory" in inst

    # Test CloudTrail normalization
    ct_res = normalizer.normalize_cloudtrail()
    assert len(ct_res) >= 50
    for ev in ct_res:
        assert "event_id" in ev
        assert "event_time" in ev
        assert "event_source" in ev
        assert "event_name" in ev
        assert "mfa_authenticated" in ev

def test_process_and_save(tmp_path, sample_raw_data):
    normalizer = CloudDataNormalizer(sample_raw_data)
    out_file = os.path.join(str(tmp_path), "test_inventory.json")
    result = normalizer.process_and_save(out_file)
    
    assert os.path.exists(out_file)
    with open(out_file, "r") as f:
        loaded = json.load(f)
    
    assert "metadata" in loaded
    assert "iam_users" in loaded
    assert "s3_buckets" in loaded
    assert "ec2_instances" in loaded
    assert loaded["metadata"]["total_resources"] >= 125
    assert loaded["metadata"]["account_id"] == "134604497614"
    assert len(loaded["cloudtrail_events"]) >= 50
