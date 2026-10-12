import json
import os
from datetime import datetime, timezone

import pandas as pd


# ============================================================
# CONFIGURATION / PROJECT PATHS
# ============================================================

# Project structure:
#
# CloudSecurityProject/
# ├── data/
# │   └── processed/
# │       ├── cloudtrail_features.csv
# │       └── behaviour_findings.json
# │
# └── Behaviour Analysis/
#     └── rules/
#         └── rule_engine.py
#
# rule_engine.py is inside:
# CloudSecurityProject\Behaviour Analysis\rules
#
# We therefore go up THREE levels to reach:
# CloudSecurityProject

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

INPUT_FILE = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "cloudtrail_features.csv"
)

OUTPUT_DIR = os.path.join(
    BASE_DIR,
    "data",
    "processed"
)

OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "behaviour_findings.json"
)
# ============================================================
# BEHAVIOUR RULE ENGINE
# ============================================================

class BehaviourRuleEngine:
    """
    Explainable rule-based security behaviour engine.

    Seven behavioural security rules are evaluated:

        R001 - Failed Cloud API Request
        R002 - Activity During Unusual Hours
        R003 - Privileged AWS API Operation
        R004 - Sensitive Operation Without Confirmed MFA
        R005 - Destructive Cloud Operation
        R006 - Root Account Activity
        R007 - IAM Configuration Modification

    Each finding contains:
        - finding ID
        - rule ID and name
        - severity
        - category
        - event details
        - user details
        - reason
        - recommendation
    """

    def __init__(self):
        self.findings = []

        # IMPORTANT:
        # Keep all seven rules in one list.
        self.rules = [
            self.rule_failed_request,       # R001
            self.rule_unusual_hours,        # R002
            self.rule_privileged_api,       # R003
            self.rule_sensitive_without_mfa,# R004
            self.rule_destructive_api,      # R005
            self.rule_root_activity,        # R006
            self.rule_iam_modification,     # R007
        ]

    # ========================================================
    # HELPER FUNCTIONS
    # ========================================================

    @staticmethod
    def clean_value(value, default="unknown"):
        """
        Safely convert NaN, None and empty values into strings.
        """

        if value is None:
            return default

        try:
            if pd.isna(value):
                return default
        except (TypeError, ValueError):
            pass

        value = str(value).strip()

        if not value:
            return default

        return value

    @staticmethod
    def is_true(value):
        """
        Safely interpret boolean-like values from CSV.
        """

        if isinstance(value, bool):
            return value

        if value is None:
            return False

        try:
            if pd.isna(value):
                return False
        except (TypeError, ValueError):
            pass

        return str(value).strip().lower() in {
            "true",
            "1",
            "yes",
            "y",
            "t"
        }

    @staticmethod
    def is_false_or_unknown(value):
        """
        Used for authentication/MFA checks.
        """

        if value is None:
            return True

        try:
            if pd.isna(value):
                return True
        except (TypeError, ValueError):
            pass

        value = str(value).strip().lower()

        return value in {
            "",
            "false",
            "unknown",
            "none",
            "null",
            "nan"
        }

    # ========================================================
    # FINDING CREATION
    # ========================================================

    def create_finding(
        self,
        rule_id,
        rule_name,
        severity,
        category,
        event,
        reason,
        recommendation
    ):
        """
        Create one standardized finding.
        """

        finding = {
            "finding_id": f"BF-{len(self.findings) + 1:04d}",

            "rule_id": rule_id,

            "rule_name": rule_name,

            "severity": severity,

            "category": category,

            "timestamp": self.clean_value(
                event.get("event_time")
            ),

            "event_name": self.clean_value(
                event.get("event_name")
            ),

            "event_source": self.clean_value(
                event.get("event_source")
            ),

            "aws_region": self.clean_value(
                event.get("aws_region")
            ),

            "source_ip": self.clean_value(
                event.get("source_ip")
            ),

            "user_type": self.clean_value(
                event.get("user_type")
            ),

            "user_name": self.clean_value(
                event.get("user_name")
            ),

            "principal_id": self.clean_value(
                event.get("principal_id")
            ),

            "mfa_used": self.clean_value(
                event.get("mfa_used")
            ),

            "is_failed": self.is_true(
                event.get("is_failed")
            ),

            "is_night": self.is_true(
                event.get("is_night")
            ),

            "is_privileged_api": self.is_true(
                event.get("is_privileged_api")
            ),

            "api_category": self.clean_value(
                event.get("api_category")
            ),

            "reason": reason,

            "recommendation": recommendation,

            "generated_at": datetime.now(
                timezone.utc
            ).isoformat()
        }

        self.findings.append(finding)

    # ========================================================
    # R001 - FAILED CLOUD API REQUEST
    # ========================================================

    def rule_failed_request(self, event):
        """
        R001 - Failed Cloud API Request

        Detects CloudTrail API requests that contain an
        error condition.
        """

        if not self.is_true(
            event.get("is_failed")
        ):
            return

        error_code = self.clean_value(
            event.get("error_code")
        )

        error_message = self.clean_value(
            event.get("error_message")
        )

        if error_message == "unknown":
            reason = (
                "A CloudTrail API request failed. "
                f"Error code: {error_code}."
            )
        else:
            reason = (
                "A CloudTrail API request failed. "
                f"Error code: {error_code}. "
                f"Message: {error_message}."
            )

        self.create_finding(
            rule_id="R001",
            rule_name="Failed Cloud API Request",
            severity="MEDIUM",
            category="Authentication / Access",
            event=event,
            reason=reason,
            recommendation=(
                "Review the failed API request and verify "
                "whether the activity was expected."
            )
        )

    # ========================================================
    # R002 - ACTIVITY DURING UNUSUAL HOURS
    # ========================================================

    def rule_unusual_hours(self, event):
        """
        R002 - Activity During Unusual Hours

        Uses the is_night feature generated by the feature
        extractor. The current configured night window is
        22:00 through 05:59 UTC.
        """

        if not self.is_true(
            event.get("is_night")
        ):
            return

        event_name = self.clean_value(
            event.get("event_name")
        )

        event_hour = self.clean_value(
            event.get("event_hour")
        )

        self.create_finding(
            rule_id="R002",
            rule_name="Activity During Unusual Hours",
            severity="LOW",
            category="Behaviour Anomaly",
            event=event,
            reason=(
                f"The event '{event_name}' occurred during "
                f"the configured unusual-hour window. "
                f"Event hour: {event_hour} UTC."
            ),
            recommendation=(
                "Verify whether this activity is expected "
                "for the account, service, or automation."
            )
        )

    # ========================================================
    # R003 - PRIVILEGED AWS API OPERATION
    # ========================================================

    def rule_privileged_api(self, event):
        """
        R003 - Privileged AWS API Operation

        Detects operations already classified by the feature
        extractor as privileged.

        AWS service-to-service activity is not automatically
        treated as suspicious.
        """

        if not self.is_true(
            event.get("is_privileged_api")
        ):
            return

        user_type = self.clean_value(
            event.get("user_type")
        )

        # AWS services may legitimately perform privileged
        # service-to-service operations.
        if user_type.lower() == "awsservice":
            return

        event_name = self.clean_value(
            event.get("event_name")
        )

        self.create_finding(
            rule_id="R003",
            rule_name="Privileged AWS API Operation",
            severity="HIGH",
            category="Privilege / IAM",
            event=event,
            reason=(
                f"A potentially privileged AWS API operation "
                f"was detected: {event_name}."
            ),
            recommendation=(
                "Verify that the operation was authorized and "
                "performed by an appropriate identity."
            )
        )

    # ========================================================
    # R004 - SENSITIVE OPERATION WITHOUT CONFIRMED MFA
    # ========================================================

    def rule_sensitive_without_mfa(self, event):
        """
        R004 - Sensitive Operation Without Confirmed MFA

        A privileged operation with MFA=False or MFA=unknown
        is flagged for authentication review.

        AWS service identities are excluded because their
        CloudTrail MFA field may not represent interactive MFA.
        """

        if not self.is_true(
            event.get("is_privileged_api")
        ):
            return

        user_type = self.clean_value(
            event.get("user_type")
        )

        if user_type.lower() == "awsservice":
            return

        mfa = self.clean_value(
            event.get("mfa_used")
        ).lower()

        if not self.is_false_or_unknown(mfa):
            return

        event_name = self.clean_value(
            event.get("event_name")
        )

        self.create_finding(
            rule_id="R004",
            rule_name="Sensitive Operation Without Confirmed MFA",
            severity="HIGH",
            category="Authentication",
            event=event,
            reason=(
                f"The sensitive operation '{event_name}' "
                f"was observed with MFA status '{mfa}'."
            ),
            recommendation=(
                "Verify the authentication context and consider "
                "enforcing MFA for privileged access."
            )
        )

    # ========================================================
    # R005 - DESTRUCTIVE CLOUD OPERATION
    # ========================================================

    def rule_destructive_api(self, event):
        """
        R005 - Destructive Cloud Operation

        Detects potentially destructive operations using
        the CloudTrail event name.
        """

        original_event_name = self.clean_value(
            event.get("event_name")
        )

        event_name = original_event_name.lower()

        destructive_keywords = [
            "delete",
            "terminate",
            "remove",
            "detach",
            "revoke",
            "destroy"
        ]

        if not any(
            keyword in event_name
            for keyword in destructive_keywords
        ):
            return

        self.create_finding(
            rule_id="R005",
            rule_name="Destructive Cloud Operation",
            severity="HIGH",
            category="Resource Modification",
            event=event,
            reason=(
                f"A potentially destructive cloud operation "
                f"was detected: {original_event_name}."
            ),
            recommendation=(
                "Verify authorization and review the target "
                "resource and surrounding activity."
            )
        )

    # ========================================================
    # R006 - ROOT ACCOUNT ACTIVITY
    # ========================================================

    def rule_root_activity(self, event):
        """
        R006 - Root Account Activity

        Detects CloudTrail activity associated with the
        AWS root identity.
        """

        user_type = self.clean_value(
            event.get("user_type")
        ).lower()

        if user_type != "root":
            return

        self.create_finding(
            rule_id="R006",
            rule_name="Root Account Activity",
            severity="CRITICAL",
            category="Identity Security",
            event=event,
            reason=(
                "CloudTrail recorded activity associated "
                "with the AWS root identity."
            ),
            recommendation=(
                "Verify whether root-account activity was "
                "necessary and authorized. Prefer delegated "
                "IAM identities for routine administration."
            )
        )

    # ========================================================
    # R007 - IAM CONFIGURATION MODIFICATION
    # ========================================================

    def rule_iam_modification(self, event):
        """
        R007 - IAM Configuration Modification

        Detects important IAM configuration changes.
        """

        event_name_original = self.clean_value(
            event.get("event_name")
        )

        event_name = event_name_original.lower()

        event_source = self.clean_value(
            event.get("event_source")
        ).lower()

        iam_operations = {
            "createuser",
            "deleteuser",
            "createrole",
            "deleterole",
            "attachuserpolicy",
            "attachrolepolicy",
            "detachuserpolicy",
            "detachrolepolicy",
            "putuserpolicy",
            "putrolepolicy",
            "deleteuserpolicy",
            "deleterolepolicy",
            "createaccesskey",
            "deleteaccesskey",
            "updateassumerolepolicy",
            "putgrouppolicy",
            "deletegrouppolicy",
            "addusertogroup",
            "removeuserfromgroup"
        }

        is_iam_source = (
            "iam.amazonaws.com" in event_source
        )

        is_iam_operation = (
            event_name in iam_operations
        )

        # Do not flag every IAM read operation.
        # Only important configuration-changing operations
        # are included in this rule.
        if not is_iam_operation:
            return

        # The operation list above is sufficient to identify
        # the sensitive IAM modification.
        self.create_finding(
            rule_id="R007",
            rule_name="IAM Configuration Modification",
            severity="HIGH",
            category="Identity and Access Management",
            event=event,
            reason=(
                f"An IAM configuration change was detected: "
                f"{event_name_original}."
            ),
            recommendation=(
                "Review the identity that performed the change "
                "and verify that the modification matches the "
                "approved access-management policy."
            )
        )

    # ========================================================
    # EVENT ANALYSIS
    # ========================================================

    def analyze_event(self, event):
        """
        Evaluate one event against all seven rules.
        """

        for rule in self.rules:
            try:
                rule(event)
            except Exception as error:
                print(
                    f"Warning: {rule.__name__} failed: {error}"
                )

    # ========================================================
    # DATAFRAME ANALYSIS
    # ========================================================

    def analyze_dataframe(self, dataframe):
        """
        Evaluate every row in the feature CSV.
        """

        self.findings = []

        for _, row in dataframe.iterrows():
            event = row.to_dict()
            self.analyze_event(event)

        return self.findings


# ============================================================
# SAVE FINDINGS
# ============================================================

def save_findings(findings):
    """
    Save findings as behaviour_findings.json.
    """

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    output = {
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "total_findings": len(findings),

        "findings": findings
    }

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            output,
            file,
            indent=4
        )

    return output


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 65)
    print("BEHAVIOUR RULE ENGINE")
    print("=" * 65)

    # --------------------------------------------------------
    # Check input
    # --------------------------------------------------------

    if not os.path.exists(INPUT_FILE):
        print("\nERROR: Feature CSV not found.")
        print(f"Expected: {INPUT_FILE}")
        print("\nRun feature_extractor.py first.")
        return

    print("\nReading features:")
    print(INPUT_FILE)

    # --------------------------------------------------------
    # Load CSV
    # --------------------------------------------------------

    try:
        dataframe = pd.read_csv(INPUT_FILE)
    except Exception as error:
        print(
            f"\nERROR: Could not read CSV: {error}"
        )
        return

    print(
        f"\nEvents loaded: {len(dataframe)}"
    )

    # --------------------------------------------------------
    # Validate useful columns
    # --------------------------------------------------------

    required_columns = [
        "event_name",
        "event_source",
        "user_type",
        "is_failed",
        "mfa_used",
        "is_night",
        "is_privileged_api"
    ]

    missing_columns = [
        column
        for column in required_columns
        if column not in dataframe.columns
    ]

    if missing_columns:
        print("\nWARNING: Some expected feature columns are missing:")
        for column in missing_columns:
            print(f"  - {column}")

        print(
            "\nThe engine will continue, but rules depending "
            "on missing columns may not generate findings."
        )

    # --------------------------------------------------------
    # Run all seven rules
    # --------------------------------------------------------

    engine = BehaviourRuleEngine()

    print("\nRules loaded: 7")

    for index, rule in enumerate(
        engine.rules,
        start=1
    ):
        print(
            f"  {index}. {rule.__name__}"
        )

    print("\nAnalyzing events...")

    findings = engine.analyze_dataframe(
        dataframe
    )

    # --------------------------------------------------------
    # Save findings
    # --------------------------------------------------------

    save_findings(findings)

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print(
        f"\nTotal findings: {len(findings)}"
    )

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for finding in findings:
        severity = finding.get(
            "severity",
            "LOW"
        )

        if severity not in severity_counts:
            severity_counts[severity] = 0

        severity_counts[severity] += 1

    print("\nSeverity summary:")

    for severity in [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW"
    ]:
        print(
            f"  {severity}: "
            f"{severity_counts.get(severity, 0)}"
        )

    # --------------------------------------------------------
    # Rule summary
    # --------------------------------------------------------

    print("\nRule summary:")

    rule_counts = {}

    for finding in findings:
        rule_id = finding.get(
            "rule_id",
            "UNKNOWN"
        )

        rule_counts[rule_id] = (
            rule_counts.get(rule_id, 0) + 1
        )

    rule_names = {
        "R001": "Failed Cloud API Request",
        "R002": "Activity During Unusual Hours",
        "R003": "Privileged AWS API Operation",
        "R004": "Sensitive Operation Without Confirmed MFA",
        "R005": "Destructive Cloud Operation",
        "R006": "Root Account Activity",
        "R007": "IAM Configuration Modification"
    }

    for rule_id in [
        "R001",
        "R002",
        "R003",
        "R004",
        "R005",
        "R006",
        "R007"
    ]:
        print(
            f"  {rule_id} - "
            f"{rule_names[rule_id]}: "
            f"{rule_counts.get(rule_id, 0)}"
        )

    # --------------------------------------------------------
    # Output path
    # --------------------------------------------------------

    print("\nSaved findings to:")
    print(OUTPUT_FILE)

    # --------------------------------------------------------
    # Preview
    # --------------------------------------------------------

    if findings:

        print("\nSample findings:")

        for finding in findings[:10]:

            print(
                "\n----------------------------------------"
            )

            print(
                f"Finding ID     : "
                f"{finding['finding_id']}"
            )

            print(
                f"Rule           : "
                f"{finding['rule_id']} - "
                f"{finding['rule_name']}"
            )

            print(
                f"Severity       : "
                f"{finding['severity']}"
            )

            print(
                f"Category       : "
                f"{finding['category']}"
            )

            print(
                f"Event          : "
                f"{finding['event_name']}"
            )

            print(
                f"User           : "
                f"{finding['user_name']}"
            )

            print(
                f"Source IP      : "
                f"{finding['source_ip']}"
            )

            print(
                f"MFA            : "
                f"{finding['mfa_used']}"
            )

            print(
                f"Reason         : "
                f"{finding['reason']}"
            )

            print(
                f"Recommendation : "
                f"{finding['recommendation']}"
            )

    else:

        print(
            "\nNo rule-based security findings detected."
        )

    print(
        "\n" + "=" * 65
    )

    print(
        "RULE ENGINE COMPLETE"
    )

    print(
        "=" * 65
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
