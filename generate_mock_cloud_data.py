"""
Module 1: Simulated Cloud Data Sources Generator
Generates 150+ realistic AWS resources (IAM, EC2, S3, VPC) and 1,000+ CloudTrail logs
with realistic configurations and injected security misconfigurations.
No AWS account or credentials needed.
"""

import json
import os
import random
import csv
from datetime import datetime, timedelta, timezone
from faker import Faker

fake = Faker()
Faker.seed(42)
random.seed(42)

ACCOUNT_ID = "123456789012"
REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]

def generate_iam_data(num_users=35, num_roles=15):
    """Generate 50 realistic IAM users and roles with injected misconfigurations."""
    resources = []
    
    # 1. Admin users with / without MFA
    admin_users = [
        {"name": "admin_dev", "is_admin": True, "mfa_active": False, "role_desc": "Senior Cloud Architect"},
        {"name": "secops_lead", "is_admin": True, "mfa_active": True, "role_desc": "Security Operations Lead"},
        {"name": "infra_deployer", "is_admin": True, "mfa_active": False, "role_desc": "Deployment Automation Account"},
        {"name": "root_backup", "is_admin": True, "mfa_active": False, "role_desc": "Emergency Break-glass Account"},
        {"name": "cloud_governance", "is_admin": True, "mfa_active": True, "role_desc": "Cloud Governance Lead"},
    ]
    
    for item in admin_users:
        created_time = fake.date_time_between(start_date="-2y", end_date="-1y", tzinfo=timezone.utc)
        user = {
            "resource_id": f"AIDA{fake.bothify(text='????????????')}".upper(),
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/{item['name']}",
            "name": item["name"],
            "type": "USER",
            "created_at": created_time.isoformat(),
            "last_login": fake.date_time_between(start_date="-30d", end_date="now", tzinfo=timezone.utc).isoformat(),
            "password_last_used": fake.date_time_between(start_date="-15d", end_date="now", tzinfo=timezone.utc).isoformat(),
            "mfa_active": item["mfa_active"],
            "access_keys": [
                {
                    "access_key_id": f"AKIA{fake.bothify(text='????????????')}".upper(),
                    "status": "Active",
                    "created_at": created_time.isoformat()
                }
            ],
            "attached_policies": ["AdministratorAccess"] if item["is_admin"] else ["ReadOnlyAccess"],
            "inline_policies": [
                {
                    "policy_name": "FullAdminAccessPolicy",
                    "policy_document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*"
                            }
                        ]
                    }
                }
            ] if item["is_admin"] else [],
            "tags": {"Environment": "Production", "Role": item["role_desc"], "Owner": item["name"]},
            "_injected_misconfiguration": {
                "admin_wildcard": item["is_admin"],
                "missing_mfa": not item["mfa_active"]
            }
        }
        resources.append(user)

    # 2. Standard developers, testers, analysts (mix of secure and misconfigured)
    for i in range(num_users - len(admin_users)):
        username = fake.user_name()
        has_wildcard = (i % 5 == 0) # Some have wildcard policies
        has_mfa = (i % 3 != 0)      # Some miss MFA
        inactive = (i % 7 == 0)     # Inactive account (>90 days no login)
        
        created_date = fake.date_time_between(start_date="-3y", end_date="-6m", tzinfo=timezone.utc)
        last_login_date = (created_date + timedelta(days=10)).isoformat() if inactive else fake.date_time_between(start_date="-30d", end_date="now", tzinfo=timezone.utc).isoformat()
        
        policies = []
        if has_wildcard:
            policies.append("AdministratorAccess")
            policies.append("PowerUserAccess")
        else:
            policies.append(random.choice(["AmazonS3ReadOnlyAccess", "AmazonEC2ReadOnlyAccess", "CloudWatchReadOnlyAccess", "AWSLambda_ReadOnlyAccess"]))

        user = {
            "resource_id": f"AIDA{fake.bothify(text='????????????')}".upper(),
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/{username}",
            "name": username,
            "type": "USER",
            "created_at": created_date.isoformat(),
            "last_login": last_login_date,
            "password_last_used": last_login_date,
            "mfa_active": has_mfa,
            "access_keys": [
                {
                    "access_key_id": f"AKIA{fake.bothify(text='????????????')}".upper(),
                    "status": "Active" if not inactive else "Inactive",
                    "created_at": created_date.isoformat()
                }
            ],
            "attached_policies": policies,
            "inline_policies": [
                {
                    "policy_name": "WildcardCustomPolicy",
                    "policy_document": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                    }
                }
            ] if has_wildcard else [],
            "tags": {"Environment": random.choice(["Development", "Staging", "QA"]), "Department": "Engineering"},
            "_injected_misconfiguration": {
                "admin_wildcard": has_wildcard,
                "missing_mfa": not has_mfa,
                "inactive_credentials": inactive
            }
        }
        resources.append(user)

    # 3. IAM Roles (Service roles, cross-account roles, CI/CD roles)
    for i in range(num_roles):
        role_name = f"role_{fake.word()}_{random.choice(['cicd', 'app', 'lambda', 'backup', 'audit'])}"
        has_wildcard = (i % 3 == 0)
        
        role = {
            "resource_id": f"AROA{fake.bothify(text='????????????')}".upper(),
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/{role_name}",
            "name": role_name,
            "type": "ROLE",
            "created_at": fake.date_time_between(start_date="-2y", end_date="-3m", tzinfo=timezone.utc).isoformat(),
            "last_login": None,
            "password_last_used": None,
            "mfa_active": True,  # Roles don't use direct password MFA in the same way, but trust policies can enforce MFA
            "access_keys": [],
            "attached_policies": ["AdministratorAccess"] if has_wildcard else [random.choice(["AWSLambdaBasicExecutionRole", "AmazonSSMManagedInstanceCore", "AmazonEC2ContainerServiceRole"])],
            "inline_policies": [
                {
                    "policy_name": "AssumeRoleBroadAccess",
                    "policy_document": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                    }
                }
            ] if has_wildcard else [],
            "tags": {"Environment": "Production" if i % 2 == 0 else "Staging", "Service": "Backend"},
            "_injected_misconfiguration": {
                "admin_wildcard": has_wildcard,
                "missing_mfa": False,
                "inactive_credentials": False
            }
        }
        resources.append(role)

    return resources


def generate_s3_data(num_buckets=30):
    """Generate 30 realistic S3 buckets with encryption, ACLs, and public exposure."""
    buckets = []
    
    # Specific known test cases
    known_cases = [
        {"name": "company-customer-pii-records-prod", "is_public": True, "encryption_enabled": False, "versioning_enabled": False},
        {"name": "company-public-assets-static-web", "is_public": True, "encryption_enabled": True, "versioning_enabled": True},
        {"name": "company-financial-audit-logs-2026", "is_public": False, "encryption_enabled": True, "versioning_enabled": True},
        {"name": "company-internal-backups-database", "is_public": False, "encryption_enabled": False, "versioning_enabled": False},
        {"name": "company-temp-developer-dropzone", "is_public": True, "encryption_enabled": False, "versioning_enabled": False},
    ]
    
    for item in known_cases:
        region = random.choice(REGIONS)
        bucket = {
            "bucket_name": item["name"],
            "arn": f"arn:aws:s3:::{item['name']}",
            "region": region,
            "creation_date": fake.date_time_between(start_date="-3y", end_date="-2m", tzinfo=timezone.utc).isoformat(),
            "is_public": item["is_public"],
            "acl_grants": [
                {"grantee_type": "Group", "permission": "READ", "uri": "http://acs.amazonaws.com/groups/global/AllUsers"}
            ] if item["is_public"] else [
                {"grantee_type": "CanonicalUser", "permission": "FULL_CONTROL"}
            ],
            "public_access_block": {
                "block_public_acls": not item["is_public"],
                "ignore_public_acls": not item["is_public"],
                "block_public_policy": not item["is_public"],
                "restrict_public_buckets": not item["is_public"]
            },
            "encryption_enabled": item["encryption_enabled"],
            "kms_master_key_id": f"arn:aws:kms:{region}:{ACCOUNT_ID}:key/{fake.uuid4()}" if item["encryption_enabled"] else None,
            "server_side_encryption_algorithm": "aws:kms" if item["encryption_enabled"] else None,
            "versioning_enabled": item["versioning_enabled"],
            "logging_enabled": not item["is_public"],
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "PublicReadGetObject",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": [f"arn:aws:s3:::{item['name']}/*", f"arn:aws:s3:::{item['name']}"]
                    }
                ]
            } if item["is_public"] else None,
            "tags": {"DataClassification": "Confidential" if "pii" in item["name"] or "financial" in item["name"] else "Public", "Environment": "Production"},
            "_injected_misconfiguration": {
                "public_accessible": item["is_public"],
                "missing_encryption": not item["encryption_enabled"],
                "missing_versioning": not item["versioning_enabled"]
            }
        }
        buckets.append(bucket)

    for i in range(num_buckets - len(known_cases)):
        name = f"corp-{fake.word()}-{fake.word()}-{random.randint(100, 999)}"
        is_public = (i % 4 == 0)       # 25% public
        encryption = (i % 3 != 0)      # 33% missing encryption
        versioning = (i % 2 == 0)      # 50% versioning
        region = random.choice(REGIONS)

        bucket = {
            "bucket_name": name,
            "arn": f"arn:aws:s3:::{name}",
            "region": region,
            "creation_date": fake.date_time_between(start_date="-2y", end_date="-1m", tzinfo=timezone.utc).isoformat(),
            "is_public": is_public,
            "acl_grants": [
                {"grantee_type": "Group", "permission": "READ", "uri": "http://acs.amazonaws.com/groups/global/AllUsers"}
            ] if is_public else [
                {"grantee_type": "CanonicalUser", "permission": "FULL_CONTROL"}
            ],
            "public_access_block": {
                "block_public_acls": not is_public,
                "ignore_public_acls": not is_public,
                "block_public_policy": not is_public,
                "restrict_public_buckets": not is_public
            },
            "encryption_enabled": encryption,
            "kms_master_key_id": f"arn:aws:kms:{region}:{ACCOUNT_ID}:key/{fake.uuid4()}" if encryption else None,
            "server_side_encryption_algorithm": "AES256" if encryption else None,
            "versioning_enabled": versioning,
            "logging_enabled": encryption and not is_public,
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "PublicAccessStatement",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{name}/*"
                    }
                ]
            } if is_public else None,
            "tags": {"Environment": random.choice(["Production", "Staging", "Development"]), "Project": fake.bs()},
            "_injected_misconfiguration": {
                "public_accessible": is_public,
                "missing_encryption": not encryption,
                "missing_versioning": not versioning
            }
        }
        buckets.append(bucket)

    return buckets


def generate_vpcs_and_networks(num_vpcs=5):
    """Generate VPC networks, subnets, route tables."""
    vpcs = []
    for i in range(num_vpcs):
        vpc_id = f"vpc-{fake.hexify(text='^^^^^^^^^^^^^^^^')}"
        cidr = f"10.{i}.0.0/16"
        region = random.choice(REGIONS)
        
        subnets = [
            {
                "subnet_id": f"subnet-{fake.hexify(text='^^^^^^^^^^^^^^^^')}",
                "cidr_block": f"10.{i}.1.0/24",
                "availability_zone": f"{region}a",
                "is_public": True,
                "route_table_id": f"rtb-{fake.hexify(text='^^^^^^^^^^^^^^^^')}",
                "has_internet_gateway": True
            },
            {
                "subnet_id": f"subnet-{fake.hexify(text='^^^^^^^^^^^^^^^^')}",
                "cidr_block": f"10.{i}.2.0/24",
                "availability_zone": f"{region}b",
                "is_public": False,
                "route_table_id": f"rtb-{fake.hexify(text='^^^^^^^^^^^^^^^^')}",
                "has_internet_gateway": False
            }
        ]
        
        vpcs.append({
            "vpc_id": vpc_id,
            "arn": f"arn:aws:ec2:{region}:{ACCOUNT_ID}:vpc/{vpc_id}",
            "region": region,
            "cidr_block": cidr,
            "subnets": subnets,
            "tags": {"Name": f"main-vpc-{region}-{i}", "Environment": "Production" if i < 2 else "Dev"}
        })
    return vpcs


def generate_ec2_data(vpcs, num_instances=40):
    """Generate 40 realistic EC2 instances with security groups, open ports (22, 3389, 8080) from 0.0.0.0/0."""
    instances = []
    
    # Specific known vulnerable instances
    known_instances = [
        {"name": "web-bastion-ssh-public", "open_ssh": True, "open_rdp": False, "open_8080": False, "outdated_ami": True, "public": True},
        {"name": "windows-jump-host-rdp", "open_ssh": False, "open_rdp": True, "open_8080": False, "outdated_ami": False, "public": True},
        {"name": "jenkins-ci-controller-open", "open_ssh": True, "open_rdp": False, "open_8080": True, "outdated_ami": True, "public": True},
        {"name": "secure-app-backend", "open_ssh": False, "open_rdp": False, "open_8080": False, "outdated_ami": False, "public": False},
        {"name": "analytics-worker-prod", "open_ssh": False, "open_rdp": False, "open_8080": False, "outdated_ami": False, "public": False}
    ]

    for item in known_instances:
        vpc = random.choice(vpcs)
        subnet = vpc["subnets"][0] if item["public"] else vpc["subnets"][1]
        instance_id = f"i-{fake.hexify(text='^^^^^^^^^^^^^^^^')}"
        sg_id = f"sg-{fake.hexify(text='^^^^^^^^^^^^^^^^')}"
        
        inbound_rules = []
        if item["open_ssh"]:
            inbound_rules.append({"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ip": "0.0.0.0/0", "description": "SSH public access"})
        if item["open_rdp"]:
            inbound_rules.append({"protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr_ip": "0.0.0.0/0", "description": "RDP public access"})
        if item["open_8080"]:
            inbound_rules.append({"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr_ip": "0.0.0.0/0", "description": "Web service public access"})
        
        # Standard safe port
        inbound_rules.append({"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_ip": "0.0.0.0/0", "description": "HTTPS traffic"})
        if not item["public"]:
            # restrict to internal VPC CIDR
            inbound_rules = [
                {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ip": vpc["cidr_block"], "description": "Internal SSH only"},
                {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_ip": vpc["cidr_block"], "description": "Internal HTTPS"}
            ]

        ami_date = fake.date_time_between(start_date="-4y", end_date="-2y", tzinfo=timezone.utc) if item["outdated_ami"] else fake.date_time_between(start_date="-3m", end_date="now", tzinfo=timezone.utc)
        ami_id = f"ami-{fake.hexify(text='^^^^^^^^^^^^^^^^')}"
        
        inst = {
            "instance_id": instance_id,
            "arn": f"arn:aws:ec2:{vpc['region']}:{ACCOUNT_ID}:instance/{instance_id}",
            "name": item["name"],
            "instance_type": "t3.medium" if item["public"] else "m5.large",
            "state": "running",
            "public_ip": fake.ipv4_public() if item["public"] else None,
            "private_ip": fake.ipv4_private(),
            "vpc_id": vpc["vpc_id"],
            "subnet_id": subnet["subnet_id"],
            "region": vpc["region"],
            "ami_id": ami_id,
            "ami_creation_date": ami_date.isoformat(),
            "is_outdated_ami": item["outdated_ami"],
            "security_groups": [
                {
                    "group_id": sg_id,
                    "group_name": f"{item['name']}-sg",
                    "inbound_rules": inbound_rules
                }
            ],
            "iam_instance_profile": f"EC2InstanceProfile-{fake.word()}",
            "tags": {"Name": item["name"], "Environment": "Production", "Owner": "SecOps"},
            "_injected_misconfiguration": {
                "open_ssh": item["open_ssh"],
                "open_rdp": item["open_rdp"],
                "open_8080": item["open_8080"],
                "outdated_ami": item["outdated_ami"],
                "public_exposure": item["public"] and (item["open_ssh"] or item["open_rdp"] or item["open_8080"])
            }
        }
        instances.append(inst)

    for i in range(num_instances - len(known_instances)):
        vpc = random.choice(vpcs)
        is_public = (i % 3 != 0)
        subnet = vpc["subnets"][0] if is_public else vpc["subnets"][1]
        
        open_ssh = (i % 4 == 0)
        open_rdp = (i % 6 == 0)
        open_8080 = (i % 5 == 0)
        outdated_ami = (i % 3 == 0)
        
        instance_id = f"i-{fake.hexify(text='^^^^^^^^^^^^^^^^')}"
        sg_id = f"sg-{fake.hexify(text='^^^^^^^^^^^^^^^^')}"
        
        inbound = []
        if is_public:
            if open_ssh:
                inbound.append({"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ip": "0.0.0.0/0", "description": "SSH internet"})
            if open_rdp:
                inbound.append({"protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr_ip": "0.0.0.0/0", "description": "RDP internet"})
            if open_8080:
                inbound.append({"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr_ip": "0.0.0.0/0", "description": "Port 8080 internet"})
            inbound.append({"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_ip": "0.0.0.0/0", "description": "HTTPS internet"})
        else:
            inbound.append({"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_ip": vpc["cidr_block"], "description": "VPC CIDR only"})

        ami_date = fake.date_time_between(start_date="-4y", end_date="-2y", tzinfo=timezone.utc) if outdated_ami else fake.date_time_between(start_date="-5m", end_date="now", tzinfo=timezone.utc)

        inst = {
            "instance_id": instance_id,
            "arn": f"arn:aws:ec2:{vpc['region']}:{ACCOUNT_ID}:instance/{instance_id}",
            "name": f"ec2-{fake.word()}-{random.randint(10, 99)}",
            "instance_type": random.choice(["t3.micro", "t3.small", "t3.medium", "c5.large"]),
            "state": random.choice(["running", "running", "running", "stopped"]),
            "public_ip": fake.ipv4_public() if is_public else None,
            "private_ip": fake.ipv4_private(),
            "vpc_id": vpc["vpc_id"],
            "subnet_id": subnet["subnet_id"],
            "region": vpc["region"],
            "ami_id": f"ami-{fake.hexify(text='^^^^^^^^^^^^^^^^')}",
            "ami_creation_date": ami_date.isoformat(),
            "is_outdated_ami": outdated_ami,
            "security_groups": [
                {
                    "group_id": sg_id,
                    "group_name": f"sg-{fake.word()}",
                    "inbound_rules": inbound
                }
            ],
            "iam_instance_profile": f"Profile-{fake.word()}",
            "tags": {"Name": f"inst-{i}", "Environment": random.choice(["Production", "Staging", "Dev"])},
            "_injected_misconfiguration": {
                "open_ssh": open_ssh and is_public,
                "open_rdp": open_rdp and is_public,
                "open_8080": open_8080 and is_public,
                "outdated_ami": outdated_ami,
                "public_exposure": is_public and (open_ssh or open_rdp or open_8080)
            }
        }
        instances.append(inst)

    return instances


def generate_cloudtrail_logs(iam_users, ec2_instances, s3_buckets, count=1050):
    """Generate 1,000+ realistic CloudTrail JSON event records reflecting security and admin events."""
    events = []
    
    event_templates = [
        {"source": "signin.amazonaws.com", "name": "ConsoleLogin", "service": "IAM"},
        {"source": "iam.amazonaws.com", "name": "CreateUser", "service": "IAM"},
        {"source": "iam.amazonaws.com", "name": "AttachUserPolicy", "service": "IAM"},
        {"source": "iam.amazonaws.com", "name": "CreateAccessKey", "service": "IAM"},
        {"source": "s3.amazonaws.com", "name": "PutBucketAcl", "service": "S3"},
        {"source": "s3.amazonaws.com", "name": "PutBucketEncryption", "service": "S3"},
        {"source": "s3.amazonaws.com", "name": "GetObject", "service": "S3"},
        {"source": "s3.amazonaws.com", "name": "PutObject", "service": "S3"},
        {"source": "ec2.amazonaws.com", "name": "AuthorizeSecurityGroupIngress", "service": "EC2"},
        {"source": "ec2.amazonaws.com", "name": "RunInstances", "service": "EC2"},
        {"source": "ec2.amazonaws.com", "name": "StopInstances", "service": "EC2"},
        {"source": "sts.amazonaws.com", "name": "AssumeRole", "service": "STS"}
    ]

    base_time = datetime(2026, 9, 1, 8, 0, 0, tzinfo=timezone.utc)
    
    # Specific suspicious event sequences for Student 2 (Anomaly / Behavior analysis)
    # 1. Admin login from suspicious foreign IP without MFA
    events.append({
        "eventVersion": "1.08",
        "eventId": str(fake.uuid4()),
        "eventTime": "2026-09-09T09:58:30Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.24",
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) KaliLinux/2026",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAADMINDEV1234",
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/admin_dev",
            "accountId": ACCOUNT_ID,
            "userName": "admin_dev"
        },
        "responseElements": {"ConsoleLogin": "Success"},
        "additionalEventData": {"MFAUsed": "No", "LoginTo": "https://console.aws.amazon.com"},
        "errorCode": None,
        "errorMessage": None
    })
    
    # 2. AuthorizeSecurityGroupIngress opening port 22 to 0.0.0.0/0
    events.append({
        "eventVersion": "1.08",
        "eventId": str(fake.uuid4()),
        "eventTime": "2026-09-09T10:04:12Z",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "AuthorizeSecurityGroupIngress",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.24",
        "userAgent": "aws-cli/2.15.0 Python/3.11",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAADMINDEV1234",
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/admin_dev",
            "accountId": ACCOUNT_ID,
            "userName": "admin_dev"
        },
        "requestParameters": {
            "groupId": "sg-01a2b3",
            "ipPermissions": {
                "items": [{
                    "ipProtocol": "tcp",
                    "fromPort": 22,
                    "toPort": 22,
                    "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}
                }]
            }
        },
        "responseElements": {"_return": True},
        "errorCode": None,
        "errorMessage": None
    })

    # Generate remaining events up to `count`
    for i in range(count - 2):
        delta_minutes = i * 25 + random.randint(1, 15)
        event_time = (base_time + timedelta(minutes=delta_minutes)).isoformat()
        tmpl = random.choice(event_templates)
        user = random.choice(iam_users)
        region = random.choice(REGIONS)
        
        is_error = (random.random() < 0.06)
        error_code = random.choice(["AccessDenied", "Client.UnauthorizedOperation", "ValidationException"]) if is_error else None
        error_msg = f"User {user['name']} is not authorized to perform {tmpl['name']}" if is_error else None

        req_params = {}
        if tmpl["name"] == "PutBucketAcl":
            bucket = random.choice(s3_buckets)
            req_params = {"bucketName": bucket["bucket_name"], "acl": "public-read" if bucket["is_public"] else "private"}
        elif tmpl["name"] == "AuthorizeSecurityGroupIngress":
            req_params = {"groupId": f"sg-{fake.hexify(text='^^^^^^^^')}", "cidrIp": "0.0.0.0/0" if i % 10 == 0 else "10.0.0.0/16"}
        elif tmpl["name"] == "RunInstances":
            req_params = {"instanceType": "t3.micro", "minCount": 1, "maxCount": 1}

        event = {
            "eventVersion": "1.08",
            "eventId": str(fake.uuid4()),
            "eventTime": event_time,
            "eventSource": tmpl["source"],
            "eventName": tmpl["name"],
            "awsRegion": region,
            "sourceIPAddress": fake.ipv4_public() if random.random() < 0.4 else fake.ipv4_private(),
            "userAgent": random.choice([
                "aws-cli/2.15.22 Python/3.11 Windows/10 botocore/2.4.22",
                "Boto3/1.28.64 Python/3.10.12 Linux/5.15.0",
                "console.amazonaws.com",
                "Terraform/1.6.4 (+https://www.terraform.io)"
            ]),
            "userIdentity": {
                "type": user["type"],
                "principalId": user["resource_id"],
                "arn": user["arn"],
                "accountId": ACCOUNT_ID,
                "userName": user["name"]
            },
            "requestParameters": req_params,
            "responseElements": None if is_error else {"status": "SUCCESS"},
            "errorCode": error_code,
            "errorMessage": error_msg
        }
        events.append(event)

    return events


def generate_software_inventory(ec2_instances, base_dir=None):
    """Generate software inventory metadata linking EC2 instances with software packages and real CISA KEV CVEs."""
    rows = []
    
    # Real-world cloud software catalog cross-referenced with CISA Known Exploited Vulnerabilities Catalog
    software_catalog = [
        {
            "package": "log4j-core",
            "safe_version": "2.17.1",
            "vulnerable_version": "2.14.1",
            "cve": "CVE-2021-44228",
            "severity": "CRITICAL",
            "cisa_vulnerability_name": "Apache Log4j2 Remote Code Execution Vulnerability",
            "cisa_known_exploited": True
        },
        {
            "package": "apache2",
            "safe_version": "2.4.58",
            "vulnerable_version": "2.4.49",
            "cve": "CVE-2021-41773",
            "severity": "CRITICAL",
            "cisa_vulnerability_name": "Apache HTTP Server Path Traversal Vulnerability",
            "cisa_known_exploited": True
        },
        {
            "package": "sudo",
            "safe_version": "1.9.12",
            "vulnerable_version": "1.8.21",
            "cve": "CVE-2021-3156",
            "severity": "HIGH",
            "cisa_vulnerability_name": "Sudo Baron Samedit Heap-Based Buffer Overflow",
            "cisa_known_exploited": True
        },
        {
            "package": "curl",
            "safe_version": "8.4.0",
            "vulnerable_version": "7.68.0",
            "cve": "CVE-2023-38545",
            "severity": "HIGH",
            "cisa_vulnerability_name": "curl SOCKS5 Heap Buffer Overflow Vulnerability",
            "cisa_known_exploited": True
        },
        {
            "package": "openssh-server",
            "safe_version": "9.4p1",
            "vulnerable_version": "7.4p1",
            "cve": "CVE-2018-15473",
            "severity": "HIGH",
            "cisa_vulnerability_name": "OpenSSH User Enumeration Vulnerability",
            "cisa_known_exploited": True
        },
        {
            "package": "nginx",
            "safe_version": "1.24.0",
            "vulnerable_version": "1.14.0",
            "cve": "CVE-2018-16843",
            "severity": "MEDIUM",
            "cisa_vulnerability_name": "Nginx Excess Memory Consumption via HTTP/2",
            "cisa_known_exploited": False
        },
        {
            "package": "openssl",
            "safe_version": "3.0.12",
            "vulnerable_version": "1.1.1k",
            "cve": "CVE-2021-3711",
            "severity": "HIGH",
            "cisa_vulnerability_name": "OpenSSL SM2 Decryption Buffer Overflow",
            "cisa_known_exploited": True
        },
        {
            "package": "docker-ce",
            "safe_version": "24.0.7",
            "vulnerable_version": "19.03.13",
            "cve": "CVE-2020-13401",
            "severity": "MEDIUM",
            "cisa_vulnerability_name": "Docker Engine IPv6 Rogue RA Security Bypass",
            "cisa_known_exploited": False
        },
    ]

    for inst in ec2_instances:
        # Install 3-5 software packages on each instance
        selected_pkgs = random.sample(software_catalog, random.randint(3, 5))
        for item in selected_pkgs:
            # If instance has outdated AMI or is in known vulnerable set, higher chance of vulnerable software
            is_vuln = (inst["is_outdated_ami"] and random.random() < 0.65) or (random.random() < 0.2)
            version = item["vulnerable_version"] if is_vuln else item["safe_version"]
            cve = item["cve"] if is_vuln else "NONE"
            severity = item["severity"] if is_vuln else "NONE"
            cisa_flag = item.get("cisa_known_exploited", False) if is_vuln else False
            cisa_name = item.get("cisa_vulnerability_name", "NONE") if is_vuln else "NONE"

            rows.append({
                "instance_id": inst["instance_id"],
                "instance_name": inst["name"],
                "public_ip": inst["public_ip"] or "None",
                "software_name": item["package"],
                "installed_version": version,
                "is_vulnerable": is_vuln,
                "cve_id": cve,
                "cve_severity": severity,
                "cisa_known_exploited": cisa_flag,
                "cisa_vulnerability_name": cisa_name,
                "scan_timestamp": datetime.now(timezone.utc).isoformat()
            })
    return rows


def generate_all_mock_data(base_output_dir):
    """Main execution to produce raw JSON/CSV datasets."""
    os.makedirs(base_output_dir, exist_ok=True)
    
    print("Generating Module 1 simulated cloud datasets...")
    
    # 1. IAM
    iam_data = generate_iam_data(num_users=35, num_roles=15)
    iam_path = os.path.join(base_output_dir, "iam_users_roles.json")
    with open(iam_path, "w") as f:
        json.dump(iam_data, f, indent=2)
    print(f"Generated {len(iam_data)} IAM users and roles -> {iam_path}")

    # 2. S3
    s3_data = generate_s3_data(num_buckets=30)
    s3_path = os.path.join(base_output_dir, "s3_buckets.json")
    with open(s3_path, "w") as f:
        json.dump(s3_data, f, indent=2)
    print(f"Generated {len(s3_data)} S3 buckets -> {s3_path}")

    # 3. VPC
    vpcs = generate_vpcs_and_networks(num_vpcs=5)
    vpc_path = os.path.join(base_output_dir, "vpc_networks.json")
    with open(vpc_path, "w") as f:
        json.dump(vpcs, f, indent=2)
    print(f"Generated {len(vpcs)} VPCs -> {vpc_path}")

    # 4. EC2
    ec2_data = generate_ec2_data(vpcs, num_instances=40)
    ec2_path = os.path.join(base_output_dir, "ec2_instances.json")
    with open(ec2_path, "w") as f:
        json.dump(ec2_data, f, indent=2)
    print(f"Generated {len(ec2_data)} EC2 instances -> {ec2_path}")

    # 5. CloudTrail
    cloudtrail_data = generate_cloudtrail_logs(iam_data, ec2_data, s3_data, count=1050)
    cloudtrail_path = os.path.join(base_output_dir, "cloudtrail_events.json")
    with open(cloudtrail_path, "w") as f:
        json.dump(cloudtrail_data, f, indent=2)
    print(f"Generated {len(cloudtrail_data)} CloudTrail events -> {cloudtrail_path}")

    # 6. Software Inventory
    software_rows = generate_software_inventory(ec2_data)
    software_path = os.path.join(base_output_dir, "software_inventory.csv")
    with open(software_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "instance_id", "instance_name", "public_ip", "software_name",
            "installed_version", "is_vulnerable", "cve_id", "cve_severity",
            "cisa_known_exploited", "cisa_vulnerability_name", "scan_timestamp"
        ])
        writer.writeheader()
        writer.writerows(software_rows)
    print(f"Generated {len(software_rows)} software inventory rows (cross-referenced with CISA KEV) -> {software_path}")

    summary = {
        "iam_resources": len(iam_data),
        "s3_buckets": len(s3_data),
        "ec2_instances": len(ec2_data),
        "vpcs": len(vpcs),
        "cloudtrail_logs": len(cloudtrail_data),
        "software_inventory_records": len(software_rows),
        "total_cloud_resources": len(iam_data) + len(s3_data) + len(ec2_data) + len(vpcs)
    }
    return summary

if __name__ == "__main__":
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "raw")
    summary = generate_all_mock_data(output_dir)
    print("\nGeneration Summary:")
    print(json.dumps(summary, indent=2))
