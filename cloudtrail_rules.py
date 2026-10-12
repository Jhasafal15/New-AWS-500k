"""
CloudTrail Security Rules (CIS AWS Benchmark & Threat Activity Monitoring)
Evaluates real AWS CloudTrail audit logs for non-MFA sessions, disabled security services,
unauthorized API exceptions, and automated reconnaissance.
"""

from typing import List, Dict, Any
try:
    from .base_rule import BaseRule, Category, Severity
except ImportError:
    try:
        from src.rules.base_rule import BaseRule, Category, Severity
    except ImportError:
        from base_rule import BaseRule, Category, Severity


class RuleCloudtrailNonMfaSession(BaseRule):
    """
    CIS AWS 1.10 / NIST 800-53 IA-2: Ensure multi-factor authentication (MFA)
    is enforced for sensitive role assumptions and API execution sessions.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-CT-001",
            rule_name="Assumed Role Session Without Multi-Factor Authentication",
            category=Category.IAM,
            severity=Severity.HIGH,
            description="STS AssumedRole session was generated without requiring Multi-Factor Authentication (MFA)."
        )

    def evaluate(self, inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        events = inventory.get("cloudtrail_events", [])
        flagged_roles = set()

        for event in events:
            # Check if event is an AssumeRole or assumed-role API execution without MFA
            if event.get("event_name") == "AssumeRole" or (event.get("user_type") == "AssumedRole"):
                if not event.get("mfa_authenticated", False):
                    role_id = event.get("user_arn") or event.get("user_name") or "unknown-role"
                    if role_id not in flagged_roles:
                        flagged_roles.add(role_id)
                        desc = (
                            f"AssumedRole session for principal '{event.get('user_name')}' "
                            f"({role_id}) was established without Multi-Factor Authentication (mfaAuthenticated=false)."
                        )
                        findings.append(self.create_finding(
                            resource_type="AWS::STS::AssumedRole",
                            resource_id=role_id,
                            description=desc,
                            severity=Severity.HIGH,
                            raw_config={
                                "event_name": event.get("event_name"),
                                "event_time": event.get("event_time"),
                                "mfa_authenticated": False,
                                "source_ip": event.get("source_ip_address"),
                                "aws_region": event.get("aws_region")
                            },
                            custom_suffix=str(len(flagged_roles))
                        ))
        return findings


class RuleCloudtrailInspectorDisabled(BaseRule):
    """
    AWS Security Hub / CIS AWS Section 2: Ensure Amazon Inspector vulnerability scanning
    is subscribed and active for continuous vulnerability assessment.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-CT-002",
            rule_name="Amazon Inspector Vulnerability Scanning Inactive or Unsubscribed",
            category=Category.COMPUTE,
            severity=Severity.HIGH,
            description="Amazon Inspector2 is not enabled or subscription is missing in the AWS account."
        )

    def evaluate(self, inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        events = inventory.get("cloudtrail_events", [])
        account_id = inventory.get("metadata", {}).get("account_id", "134604497614")

        # Search for inspector2 subscription exceptions
        inspector_events = [e for e in events if "inspector" in (e.get("event_source") or "").lower()]
        for ev in inspector_events:
            if ev.get("error_code") == "SubscriptionRequiredException":
                desc = (
                    f"AWS account {account_id} attempted to execute {ev.get('event_name')} on "
                    f"Inspector2, but failed with SubscriptionRequiredException. Automated host and "
                    f"container vulnerability scanning is NOT activated."
                )
                findings.append(self.create_finding(
                    resource_type="AWS::Inspector2::Service",
                    resource_id=f"arn:aws:inspector2:{ev.get('aws_region', 'us-east-1')}:{account_id}:service",
                    description=desc,
                    severity=Severity.HIGH,
                    raw_config={
                        "event_source": ev.get("event_source"),
                        "event_name": ev.get("event_name"),
                        "error_code": ev.get("error_code"),
                        "error_message": ev.get("error_message")
                    }
                ))
                break  # Flag once for the account
        return findings


class RuleCloudtrailServiceExceptions(BaseRule):
    """
    CIS AWS 3.1 & 3.4: Monitor repeated authorization, subscription, and general service
    exceptions in CloudTrail audit logs.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-CT-003",
            rule_name="Repeated CloudTrail Service Access & Authorization Exceptions",
            category=Category.COMPUTE,
            severity=Severity.MEDIUM,
            description="Multiple API execution calls failed with service subscription or general runtime errors."
        )

    def evaluate(self, inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        events = inventory.get("cloudtrail_events", [])
        account_id = inventory.get("metadata", {}).get("account_id", "134604497614")

        error_events = [e for e in events if e.get("error_code") and e.get("error_code") != "None"]
        services_with_errors = {}
        for ev in error_events:
            src = ev.get("event_source", "unknown")
            if src not in services_with_errors:
                services_with_errors[src] = []
            services_with_errors[src].append(ev)

        for src, err_list in services_with_errors.items():
            err_codes = list({e.get("error_code") for e in err_list})
            desc = (
                f"Service '{src}' recorded {len(err_list)} failed API invocation(s) in CloudTrail "
                f"with error codes: {', '.join(err_codes)}."
            )
            findings.append(self.create_finding(
                resource_type="AWS::CloudTrail::ServiceAudit",
                resource_id=f"arn:aws:cloudtrail:audit:{src.split('.')[0]}:{account_id}",
                description=desc,
                severity=Severity.MEDIUM,
                raw_config={
                    "service": src,
                    "failure_count": len(err_list),
                    "error_codes": err_codes
                },
                custom_suffix=src.split(".")[0].replace("-", "_")
            ))
        return findings


class RuleCloudtrailReconnaissance(BaseRule):
    """
    MITRE ATT&CK Cloud Matrix T1526 (Cloud Service Discovery):
    Detect high-frequency automated discovery across 10+ cloud services by a single principal.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-CT-004",
            rule_name="Automated Broad Cloud Service Reconnaissance",
            category=Category.IAM,
            severity=Severity.LOW,
            description="Single IAM principal enumerated resources across more than 10 distinct AWS services."
        )

    def evaluate(self, inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        events = inventory.get("cloudtrail_events", [])
        account_id = inventory.get("metadata", {}).get("account_id", "134604497614")

        # Group by principal
        principal_services = {}
        for ev in events:
            p = ev.get("user_name") or "unknown"
            if p not in principal_services:
                principal_services[p] = set()
            src = ev.get("event_source")
            if src:
                principal_services[p].add(src)

        for principal, services in principal_services.items():
            if len(services) >= 10:
                desc = (
                    f"Principal '{principal}' initiated automated discovery and enumeration across "
                    f"{len(services)} distinct AWS services within the audit window."
                )
                findings.append(self.create_finding(
                    resource_type="AWS::IAM::PrincipalActivity",
                    resource_id=f"arn:aws:iam::{account_id}:reconnaissance-monitor/{principal}",
                    description=desc,
                    severity=Severity.LOW,
                    raw_config={
                        "principal": principal,
                        "distinct_services_count": len(services),
                        "services_enumerated": sorted(list(services))
                    },
                    custom_suffix=principal.replace("-", "_")
                ))
        return findings


class RulePrivilegeEscalationAttempt(BaseRule):
    """
    MITRE ATT&CK T1078 / T1098: Detects attempts to escalate privileges by attaching
    administrative policies or modifying IAM role trust relationships.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-ENT-001",
            rule_name="IAM Privilege Escalation Attempt Detected",
            category=Category.IAM,
            severity=Severity.CRITICAL,
            description="Unauthorized attempt to attach administrative policies or elevate IAM principal privileges."
        )

    def evaluate(self, inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        events = inventory.get("cloudtrail_events", [])
        flagged_users = set()

        for ev in events:
            scenario = ev.get("attack_scenario")
            if scenario in ("PRIVILEGE_ESCALATION", "COMPOUND_ATTACK_CHAIN") or ev.get("event_name") in ("AttachRolePolicy", "PutRolePolicy"):
                user = ev.get("user_name", "unknown")
                if user not in flagged_users and ev.get("final_risk_level") in ("CRITICAL", "HIGH"):
                    flagged_users.add(user)
                    desc = (
                        f"Principal '{user}' attempted privilege escalation ({ev.get('event_name')}) "
                        f"on service {ev.get('event_source')} with Risk Score {ev.get('final_risk_score', 'N/A')}."
                    )
                    findings.append(self.create_finding(
                        resource_type="AWS::IAM::PrivilegeEscalation",
                        resource_id=ev.get("user_arn") or f"arn:aws:iam::134604497614:role/{user}",
                        description=desc,
                        severity=Severity.CRITICAL,
                        raw_config={
                            "user": user,
                            "event_name": ev.get("event_name"),
                            "attack_scenario": scenario,
                            "risk_score": ev.get("final_risk_score")
                        },
                        custom_suffix=user.replace("-", "_")
                    ))
        return findings


class RuleFailedSensitiveOperations(BaseRule):
    """
    CIS AWS / NIST 800-53 AC-6: Detects failed unauthorized attempts to delete or modify
    security controls, S3 bucket policies, or encryption keys.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-ENT-002",
            rule_name="Unauthorized Sensitive Operation & Policy Tampering",
            category=Category.STORAGE,
            severity=Severity.HIGH,
            description="Unauthorized attempts to alter storage bucket policies or disable defensive cloud configurations."
        )

    def evaluate(self, inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        events = inventory.get("cloudtrail_events", [])
        flagged_ops = set()

        for ev in events:
            if ev.get("attack_scenario") == "FAILED_SENSITIVE_OPERATION" or ev.get("event_name") in ("DeleteBucketPolicy", "PutBucketAcl"):
                user = ev.get("user_name", "unknown")
                op_key = f"{user}_{ev.get('event_name')}"
                if op_key not in flagged_ops:
                    flagged_ops.add(op_key)
                    desc = (
                        f"Suspicious sensitive operation '{ev.get('event_name')}' attempted by principal '{user}' "
                        f"on {ev.get('event_source')} was flagged with High Risk ({ev.get('final_risk_score', 'N/A')})."
                    )
                    findings.append(self.create_finding(
                        resource_type="AWS::S3::PolicyTampering",
                        resource_id=f"arn:aws:s3:::audit/sensitive-op/{user}/{ev.get('event_name')}",
                        description=desc,
                        severity=Severity.HIGH,
                        raw_config={
                            "user": user,
                            "event_name": ev.get("event_name"),
                            "service": ev.get("event_source"),
                            "risk_score": ev.get("final_risk_score")
                        },
                        custom_suffix=op_key.replace("-", "_")
                    ))
        return findings


class RuleCredentialTamperingActivity(BaseRule):
    """
    MITRE ATT&CK T1098.001: Detects unauthorized credential manipulation including
    abnormal access key creation and deletion by anomalous users.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-ENT-003",
            rule_name="Abnormal Access Key Credential Manipulation",
            category=Category.IAM,
            severity=Severity.HIGH,
            description="Suspicious creation or deletion of long-term IAM access keys detected in audit trail."
        )

    def evaluate(self, inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        events = inventory.get("cloudtrail_events", [])
        flagged_users = set()

        for ev in events:
            if ev.get("attack_scenario") == "CREDENTIAL_ACTIVITY" or ev.get("event_name") in ("CreateAccessKey", "DeleteAccessKey"):
                user = ev.get("user_name", "unknown")
                if user not in flagged_users and ev.get("final_risk_level") in ("CRITICAL", "HIGH"):
                    flagged_users.add(user)
                    desc = (
                        f"Abnormal credential activity: Principal '{user}' executed {ev.get('event_name')} "
                        f"tagged with Risk Score {ev.get('final_risk_score', 'N/A')}."
                    )
                    findings.append(self.create_finding(
                        resource_type="AWS::IAM::AccessKeyActivity",
                        resource_id=f"arn:aws:iam::134604497614:credential-alert/{user}",
                        description=desc,
                        severity=Severity.HIGH,
                        raw_config={
                            "user": user,
                            "event_name": ev.get("event_name"),
                            "risk_score": ev.get("final_risk_score")
                        },
                        custom_suffix=user.replace("-", "_")
                    ))
        return findings

