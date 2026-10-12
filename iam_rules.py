"""
IAM Security Rules (CIS AWS Benchmark Section 1)
"""

import sys
import os
try:
    from .base_rule import BaseRule, Category, Severity
except ImportError:
    try:
        from src.rules.base_rule import BaseRule, Category, Severity
    except ImportError:
        from base_rule import BaseRule, Category, Severity

class RuleIamMfa(BaseRule):
    """CIS AWS 1.5 & 1.10: Ensure MFA is enabled for all IAM users and especially admin accounts."""
    def __init__(self):
        super().__init__(
            rule_id="RULE-IAM-001",
            rule_name="Root or Admin User Missing MFA",
            category=Category.IAM,
            severity=Severity.HIGH,
            description="User has active credentials or Administrator privileges but Multi-Factor Authentication (MFA) is disabled."
        )

    def evaluate(self, inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        users = inventory.get("iam_users", [])

        for user in users:
            mfa_active = user.get("mfa_active", False)
            if not mfa_active:
                has_admin = user.get("has_admin_policy", False) or "AdministratorAccess" in user.get("attached_policies", [])
                severity = Severity.CRITICAL if has_admin else Severity.HIGH
                rule_title = "Root or Admin User Missing MFA" if has_admin else "IAM User Missing MFA"
                desc = (
                    f"User {user.get('name')} has AdministratorAccess policy attached but Multi-Factor Authentication is disabled."
                    if has_admin else
                    f"IAM User {user.get('name')} does not have Multi-Factor Authentication (MFA) enabled for console or API access."
                )

                findings.append(self.create_finding(
                    resource_type="IAM_USER",
                    resource_id=user.get("arn", user.get("resource_id")),
                    description=desc,
                    severity=severity,
                    raw_config={
                        "mfa_active": False,
                        "attached_policies": user.get("attached_policies", []),
                        "has_admin_policy": has_admin
                    },
                    custom_suffix=user.get("name")
                ))
        return findings


class RuleIamAdmin(BaseRule):
    """CIS AWS 1.16: Ensure IAM policies do not allow full '*' administrative privileges."""
    def __init__(self):
        super().__init__(
            rule_id="RULE-IAM-002",
            rule_name="Overly Permissive Wildcard Administrator Access",
            category=Category.IAM,
            severity=Severity.HIGH,
            description="IAM principal has excessive wildcard Administrator privileges (*:*) or direct AdministratorAccess attached."
        )

    def evaluate(self, inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        users = inventory.get("iam_users", [])
        roles = inventory.get("iam_roles", [])

        for entity in users + roles:
            is_user = entity.get("type", "USER") == "USER"
            res_type = "IAM_USER" if is_user else "IAM_ROLE"
            
            has_admin = entity.get("has_admin_policy", False) or "AdministratorAccess" in entity.get("attached_policies", [])
            has_wildcard = entity.get("has_wildcard_permission", False)

            if has_admin or has_wildcard:
                desc = (
                    f"{res_type} {entity.get('name')} is granted full '*' administrative privileges via "
                    f"{'AdministratorAccess policy' if has_admin else 'inline wildcard statement'}."
                )
                findings.append(self.create_finding(
                    resource_type=res_type,
                    resource_id=entity.get("arn", entity.get("resource_id")),
                    description=desc,
                    severity=Severity.HIGH,
                    raw_config={
                        "attached_policies": entity.get("attached_policies", []),
                        "has_wildcard_permission": has_wildcard,
                        "has_admin_policy": has_admin
                    },
                    custom_suffix=entity.get("name")
                ))
        return findings


class RuleIamInactiveCredentials(BaseRule):
    """CIS AWS 1.3: Ensure credentials unused for 90 days or greater are disabled."""
    def __init__(self):
        super().__init__(
            rule_id="RULE-IAM-003",
            rule_name="Unused Credentials Exceeding 90 Days",
            category=Category.IAM,
            severity=Severity.MEDIUM,
            description="IAM credentials have not been used in more than 90 days."
        )

    def evaluate(self, inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        users = inventory.get("iam_users", [])

        for user in users:
            if user.get("is_inactive_90_days", False):
                days = user.get("days_since_active", 90)
                findings.append(self.create_finding(
                    resource_type="IAM_USER",
                    resource_id=user.get("arn", user.get("resource_id")),
                    description=f"User {user.get('name')} has been inactive for {days} days without password or key usage.",
                    severity=Severity.MEDIUM,
                    raw_config={
                        "days_since_active": days,
                        "last_login": user.get("last_login")
                    },
                    custom_suffix=user.get("name")
                ))
        return findings
