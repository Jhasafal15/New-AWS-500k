"""
Correlation rules for behavioral security analysis.

These rules identify combinations of events that become more
meaningful when observed together.
"""


CORRELATION_RULES = [
    {
        "name": "Privilege Escalation Sequence",
        "events": ["AssumeRole", "CreateRole", "AttachRolePolicy"],
        "severity": "HIGH",
        "score": 30,
        "description": "Multiple IAM privilege-related operations observed together."
    },

    {
        "name": "Reconnaissance Sequence",
        "events": [
            "ListResources",
            "ListTables",
            "ListBuckets",
            "DescribeDBSubnetGroups"
        ],
        "severity": "MEDIUM",
        "score": 20,
        "description": "Multiple resource discovery operations indicate reconnaissance behavior."
    },

    {
        "name": "Authentication Anomaly",
        "events": ["ConsoleLogin", "AssumeRole"],
        "severity": "MEDIUM",
        "score": 20,
        "description": "Authentication followed by role assumption."
    },

    {
        "name": "Sensitive IAM Activity",
        "events": [
            "ListSecurityConfigurations",
            "AssumeRole",
            "ListRolePolicies"
        ],
        "severity": "HIGH",
        "score": 25,
        "description": "Sensitive IAM operations occurring together."
    },

    {
        "name": "Service Discovery Pattern",
        "events": [
            "ListServices",
            "ListResources",
            "DescribeAutoScalingGroups"
        ],
        "severity": "MEDIUM",
        "score": 15,
        "description": "Multiple cloud service discovery operations observed."
    }
]


def get_correlation_rules():
    """Return all configured correlation rules."""
    return CORRELATION_RULES