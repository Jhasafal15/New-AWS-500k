"""
Response Rules
AI Cloud IAM Behavioral Security System

Defines response and remediation recommendations based on:
- Severity
- Risk score
- Finding type
- Observed behavior
"""

# =========================================================
# SEVERITY RULES
# =========================================================

RESPONSE_RULES = {

    "CRITICAL": {
        "default_action": "Immediate investigation and containment required.",
        "priority": "IMMEDIATE",
        "response_type": "IMMEDIATE_CONTAINMENT",

        "actions": [
            "Investigate the affected IAM principal",
            "Review recent CloudTrail activity",
            "Review IAM permissions and policies",
            "Temporarily restrict suspicious permissions if confirmed",
            "Verify MFA configuration",
            "Check for related correlated events",
            "Escalate to security administrator"
        ]
    },

    "HIGH": {
        "default_action": "Priority investigation and containment review recommended.",
        "priority": "HIGH",
        "response_type": "PRIORITY_INVESTIGATION",

        "actions": [
            "Review the affected IAM activity",
            "Inspect recent CloudTrail events",
            "Verify whether the activity is expected",
            "Review IAM permissions",
            "Check for related behavioral anomalies",
            "Monitor the principal for repeated activity"
        ]
    },

    "MEDIUM": {
        "default_action": "Review the activity and monitor for recurrence.",
        "priority": "MEDIUM",
        "response_type": "INVESTIGATION_AND_MONITORING",

        "actions": [
            "Review the associated IAM activity",
            "Verify whether the behavior is expected",
            "Check recent CloudTrail activity",
            "Monitor for repeated suspicious behavior",
            "Investigate related correlated events"
        ]
    },

    "LOW": {
        "default_action": "Continue monitoring.",
        "priority": "LOW",
        "response_type": "MONITORING",

        "actions": [
            "Monitor the associated IAM activity",
            "Review if the behavior becomes repetitive",
            "Check for related anomalies if required"
        ]
    }
}


# =========================================================
# BEHAVIOR-SPECIFIC RULES
# =========================================================

BEHAVIOR_RESPONSES = {

    "MFA status unavailable": [
        "Verify MFA configuration for the associated IAM principal",
        "Confirm whether the identity requires MFA"
    ],

    "Off-hours activity": [
        "Verify whether the activity occurred during an approved maintenance window",
        "Review the identity's normal activity schedule"
    ],

    "Rare API event": [
        "Review the API operation and its business purpose",
        "Check whether the operation is normally used by this principal"
    ],

    "Failed AWS API request": [
        "Review the failed API request",
        "Check for repeated authorization failures",
        "Verify IAM permissions associated with the request"
    ],

    "AWS service-to-service activity": [
        "Verify that the service-to-service activity is expected",
        "Review the involved IAM role and trusted services"
    ],

    "High behavioral anomaly score": [
        "Review the principal's recent behavioral history",
        "Compare the activity with the established behavioral baseline"
    ],

    "Isolation Forest anomaly detected": [
        "Review the anomalous event against historical behavior",
        "Check for related anomalous events from the same principal"
    ],

    "reconnaissance": [
        "Review resource discovery activity",
        "Check whether multiple discovery APIs were executed in sequence",
        "Investigate the principal's recent resource access"
    ],

    "privilege": [
        "Review IAM privilege changes",
        "Verify whether elevated permissions were authorized",
        "Check for subsequent sensitive API activity"
    ],

    "assumerole": [
        "Review the assumed role and trust relationship",
        "Verify the source principal that assumed the role",
        "Check subsequent activity performed using the role"
    ]
}


# =========================================================
# FINDING-TYPE RULES
# =========================================================

FINDING_TYPE_RESPONSES = {

    "Behavioral Anomaly": [
        "Compare the event with the established behavioral baseline",
        "Review historical activity for the same principal"
    ],

    "Rule-Based Security Finding": [
        "Review the rule that triggered the finding",
        "Verify whether the observed behavior violates the expected security policy"
    ],

    "Combined Behavioral and Rule Risk": [
        "Review both behavioral anomaly evidence and rule-based indicators",
        "Investigate correlated events surrounding the finding"
    ]
}


# =========================================================
# FUNCTIONS
# =========================================================

def get_severity_rule(severity):
    """
    Return the response rule associated with a severity level.
    """

    severity = str(severity).upper()

    return RESPONSE_RULES.get(
        severity,
        RESPONSE_RULES["LOW"]
    )


def get_behavior_responses(reason):
    """
    Return response recommendations based on keywords
    contained in the finding reason.
    """

    recommendations = []

    reason = str(reason).lower()

    for behavior, actions in BEHAVIOR_RESPONSES.items():

        if behavior.lower() in reason:

            recommendations.extend(actions)

    return recommendations


def get_finding_type_responses(finding_type):
    """
    Return recommendations based on finding type.
    """

    finding_type = str(finding_type)

    return FINDING_TYPE_RESPONSES.get(
        finding_type,
        []
    )


def get_risk_response(risk_score):
    """
    Determine additional response actions from risk score.

    Risk thresholds:
    0-29    : Low
    30-59   : Medium
    60-79   : High
    80-100  : Critical
    """

    try:
        score = float(risk_score)
    except (TypeError, ValueError):
        score = 0

    if score >= 80:

        return {
            "risk_level": "CRITICAL",
            "actions": [
                "Perform immediate security investigation",
                "Review all recent activity associated with the principal"
            ]
        }

    elif score >= 60:

        return {
            "risk_level": "HIGH",
            "actions": [
                "Prioritize investigation of the finding",
                "Review related events within the same activity window"
            ]
        }

    elif score >= 30:

        return {
            "risk_level": "MEDIUM",
            "actions": [
                "Continue investigation and behavioral monitoring"
            ]
        }

    else:

        return {
            "risk_level": "LOW",
            "actions": [
                "Continue normal security monitoring"
            ]
        }