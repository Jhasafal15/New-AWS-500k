import json
import os
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

INPUT_DIR = os.path.join(
    BASE_DIR,
    "data",
    "raw"
)

OUTPUT_DIR = os.path.join(
    BASE_DIR,
    "data",
    "processed"
)

OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "cloudtrail_features.csv"
)





# ============================================================
# CLOUDTRAIL EVENT EXTRACTION
# ============================================================

def extract_event(event):
    """
    Extract the actual CloudTrail event.

    AWS CloudTrail data can appear in several forms:
        1. Direct CloudTrail event dictionary
        2. CloudTrailEvent stored as JSON string
        3. CloudTrailEvent stored as dictionary
    """

    if not isinstance(event, dict):
        return {}

    # CloudTrail LookupEvents commonly stores the actual
    # event inside CloudTrailEvent.
    cloudtrail_event = event.get("CloudTrailEvent")

    if isinstance(cloudtrail_event, str):

        try:
            parsed_event = json.loads(cloudtrail_event)

            if isinstance(parsed_event, dict):
                return parsed_event

        except json.JSONDecodeError:
            pass

    if isinstance(cloudtrail_event, dict):
        return cloudtrail_event

    # If no wrapper exists, assume event itself is CloudTrail.
    return event


# ============================================================
# MFA EXTRACTION
# ============================================================

def extract_mfa(user_identity):
    """
    Extract MFA authentication status.
    """

    if not isinstance(user_identity, dict):
        return "unknown"

    session_context = user_identity.get(
        "sessionContext",
        {}
    )

    if not isinstance(session_context, dict):
        return "unknown"

    attributes = session_context.get(
        "attributes",
        {}
    )

    if not isinstance(attributes, dict):
        return "unknown"

    mfa_value = attributes.get(
        "mfaAuthenticated"
    )

    if mfa_value is None:
        return "unknown"

    return str(mfa_value).lower()


# ============================================================
# USER NAME EXTRACTION
# ============================================================

def extract_user_name(user_identity):
    """
    Extract the most useful identity name available.
    """

    user_name = user_identity.get(
        "userName"
    )

    if user_name:
        return user_name

    principal_id = user_identity.get(
        "principalId"
    )

    if principal_id:
        return principal_id

    arn = user_identity.get(
        "arn",
        ""
    )

    if arn:
        return arn.split("/")[-1]

    return "unknown"


# ============================================================
# TIME FEATURES
# ============================================================

def extract_time_features(event_time):
    """
    Extract hour and day information from eventTime.
    """

    if not event_time:
        return {
            "event_hour": -1,
            "event_day": "",
            "is_night": False
        }

    try:

        timestamp = pd.to_datetime(
            event_time,
            utc=True
        )

        hour = timestamp.hour

        # Night period used for behavioural analysis.
        is_night = (
            hour >= 22 or
            hour < 6
        )

        return {
            "event_hour": hour,
            "event_day": timestamp.day_name(),
            "is_night": is_night
        }

    except Exception:

        return {
            "event_hour": -1,
            "event_day": "",
            "is_night": False
        }


# ============================================================
# ERROR FEATURES
# ============================================================

def extract_error_features(
    error_code,
    error_message
):
    """
    Convert CloudTrail error information into
    useful behavioural indicators.
    """

    failed = bool(
        error_code or error_message
    )

    return {
        "is_failed": failed,
        "error_present": failed
    }


# ============================================================
# API CLASSIFICATION
# ============================================================

def classify_api(event_name):
    """
    Classify AWS API calls into broad behavioural categories.
    """

    if not event_name:
        return "unknown"

    event_name_lower = event_name.lower()

    read_operations = [
        "get",
        "describe",
        "list",
        "head"
    ]

    write_operations = [
        "create",
        "put",
        "update",
        "modify",
        "attach",
        "associate",
        "start",
        "run",
        "launch"
    ]

    delete_operations = [
        "delete",
        "terminate",
        "remove",
        "detach",
        "disassociate"
    ]

    permission_operations = [
        "policy",
        "permission",
        "role",
        "user",
        "group",
        "access"
    ]

    if any(
        operation in event_name_lower
        for operation in delete_operations
    ):
        return "delete"

    if any(
        operation in event_name_lower
        for operation in permission_operations
    ):
        return "permission"

    if any(
        operation in event_name_lower
        for operation in write_operations
    ):
        return "write"

    if any(
        operation in event_name_lower
        for operation in read_operations
    ):
        return "read"

    return "other"


# ============================================================
# PRIVILEGED API DETECTION
# ============================================================

def detect_privileged_api(event_name):
    """
    Identify potentially sensitive AWS API operations.
    """

    if not event_name:
        return False

    sensitive_operations = [

        # IAM
        "CreateUser",
        "DeleteUser",
        "CreateRole",
        "DeleteRole",
        "AttachUserPolicy",
        "AttachRolePolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "CreateAccessKey",
        "DeleteAccessKey",

        # EC2
        "RunInstances",
        "TerminateInstances",
        "ModifyInstanceAttribute",

        # S3
        "PutBucketPolicy",
        "DeleteBucketPolicy",

        # Security
        "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress"
    ]

    return event_name in sensitive_operations


# ============================================================
# EVENT PROCESSING
# ============================================================

def process_event(raw_event):
    """
    Convert one CloudTrail event into a structured
    behavioural feature record.
    """

    event = extract_event(
        raw_event
    )

    if not event:
        return None

    # --------------------------------------------------------
    # Identity
    # --------------------------------------------------------

    user_identity = event.get(
        "userIdentity",
        {}
    )

    if not isinstance(
        user_identity,
        dict
    ):
        user_identity = {}

    user_type = user_identity.get(
        "type",
        "unknown"
    )

    user_name = extract_user_name(
        user_identity
    )

    principal_id = user_identity.get(
        "principalId",
        ""
    )

    access_key_id = user_identity.get(
        "accessKeyId",
        ""
    )

    arn = user_identity.get(
        "arn",
        ""
    )

    # --------------------------------------------------------
    # Basic event information
    # --------------------------------------------------------

    event_time = event.get(
        "eventTime",
        ""
    )

    event_name = event.get(
        "eventName",
        "unknown"
    )

    event_source = event.get(
        "eventSource",
        "unknown"
    )

    aws_region = event.get(
        "awsRegion",
        "unknown"
    )

    source_ip = event.get(
        "sourceIPAddress",
        "unknown"
    )

    user_agent = event.get(
        "userAgent",
        "unknown"
    )

    recipient_account_id = event.get(
        "recipientAccountId",
        ""
    )

    read_only = event.get(
        "readOnly",
        ""
    )

    # --------------------------------------------------------
    # Errors
    # --------------------------------------------------------

    error_code = event.get(
        "errorCode",
        ""
    )

    error_message = event.get(
        "errorMessage",
        ""
    )

    error_features = extract_error_features(
        error_code,
        error_message
    )

    # --------------------------------------------------------
    # MFA
    # --------------------------------------------------------

    mfa_used = extract_mfa(
        user_identity
    )

    # --------------------------------------------------------
    # Time
    # --------------------------------------------------------

    time_features = extract_time_features(
        event_time
    )

    # --------------------------------------------------------
    # API classification
    # --------------------------------------------------------

    api_category = classify_api(
        event_name
    )

    privileged_api = detect_privileged_api(
        event_name
    )

    # --------------------------------------------------------
    # Behavioural features
    # --------------------------------------------------------

    return {

        # Basic event
        "event_time": event_time,
        "event_name": event_name,
        "event_source": event_source,
        "aws_region": aws_region,

        # Network
        "source_ip": source_ip,
        "user_agent": user_agent,

        # Identity
        "user_type": user_type,
        "user_name": user_name,
        "principal_id": principal_id,
        "access_key_id": access_key_id,
        "user_arn": arn,

        # Authentication
        "mfa_used": mfa_used,

        # Errors
        "error_code": error_code,
        "error_message": error_message,
        "is_failed": error_features["is_failed"],
        "error_present": error_features["error_present"],

        # Request
        "read_only": read_only,

        # AWS
        "recipient_account_id": recipient_account_id,

        # Time behaviour
        "event_hour": time_features["event_hour"],
        "event_day": time_features["event_day"],
        "is_night": time_features["is_night"],

        # API behaviour
        "api_category": api_category,
        "is_privileged_api": privileged_api
    }


# ============================================================
# FIND LATEST JSON
# ============================================================

def find_latest_json():
    """
    Find the newest JSON file in data/raw.
    """

    if not os.path.exists(
        INPUT_DIR
    ):
        return None

    files = [
        os.path.join(
            INPUT_DIR,
            filename
        )
        for filename in os.listdir(
            INPUT_DIR
        )
        if filename.lower().endswith(
            ".json"
        )
    ]

    if not files:
        return None

    return max(
        files,
        key=os.path.getmtime
    )


# ============================================================
# LOAD CLOUDTRAIL EVENTS
# ============================================================

def load_events(data):
    """
    Handle multiple possible CloudTrail JSON structures.
    """

    # --------------------------------------------------------
    # Case 1: AWS LookupEvents response
    # --------------------------------------------------------

    if isinstance(data, dict):

        if isinstance(
            data.get("Events"),
            list
        ):

            return data["Events"]

        # ----------------------------------------------------
        # Case 2: CloudTrail Records format
        # ----------------------------------------------------

        if isinstance(
            data.get("Records"),
            list
        ):

            return data["Records"]

        # ----------------------------------------------------
        # Case 3: Single event
        # ----------------------------------------------------

        return [data]

    # --------------------------------------------------------
    # Case 4: JSON list
    # --------------------------------------------------------

    if isinstance(
        data,
        list
    ):
        return data

    return []


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("CLOUDTRAIL FEATURE EXTRACTION")
    print("=" * 60)

    # --------------------------------------------------------
    # Locate input
    # --------------------------------------------------------

    input_file = find_latest_json()

    if not input_file:

        print(
            "\nERROR: No CloudTrail JSON file found."
        )

        print(
            f"Expected directory: {INPUT_DIR}"
        )

        return

    print(
        f"\nReading: {input_file}"
    )

    # --------------------------------------------------------
    # Load JSON
    # --------------------------------------------------------

    try:

        with open(
            input_file,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

    except Exception as e:

        print(
            f"\nERROR: Could not read JSON: {e}"
        )

        return

    # --------------------------------------------------------
    # Extract events
    # --------------------------------------------------------

    events = load_events(
        data
    )

    print(
        f"Raw events found: {len(events)}"
    )

    # --------------------------------------------------------
    # Process events
    # --------------------------------------------------------

    features = []

    failed_events = 0

    for index, event in enumerate(
        events,
        start=1
    ):

        try:

            extracted = process_event(
                event
            )

            if extracted:

                features.append(
                    extracted
                )

                if extracted["is_failed"]:
                    failed_events += 1

        except Exception as e:

            print(
                f"Warning: Event {index} "
                f"could not be processed: {e}"
            )

    # --------------------------------------------------------
    # Create dataframe
    # --------------------------------------------------------

    df = pd.DataFrame(
        features
    )

    # --------------------------------------------------------
    # Create output directory
    # --------------------------------------------------------

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Save CSV
    # --------------------------------------------------------

    df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print(
        f"\nFeatures extracted: {len(df)}"
    )

    print(
        f"Failed events: {failed_events}"
    )

    print(
        f"Saved to: {OUTPUT_FILE}"
    )

    print(
        "\nFeature columns:"
    )

    for column in df.columns:

        print(
            f"  - {column}"
        )

    # --------------------------------------------------------
    # Preview
    # --------------------------------------------------------

    if not df.empty:

        print(
            "\nSample extracted events:"
        )

        preview_columns = [
            "event_name",
            "event_source",
            "aws_region",
            "source_ip",
            "user_type",
            "user_name",
            "mfa_used",
            "is_failed",
            "event_hour",
            "is_night",
            "api_category",
            "is_privileged_api"
        ]

        available_columns = [
            column
            for column in preview_columns
            if column in df.columns
        ]

        print(
            df[
                available_columns
            ].head(10).to_string(
                index=False
            )
        )

    else:

        print(
            "\nWARNING: No features were extracted."
        )

    print(
        "\n" + "=" * 60
    )
    print(
        "FEATURE EXTRACTION COMPLETE"
    )
    print(
        "=" * 60
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()