import os
import sys
import argparse
import numpy as np
import pandas as pd

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
except ImportError:
    class StandardScaler:
        def fit_transform(self, X):
            X = np.asarray(X, dtype=float)
            mean = np.mean(X, axis=0)
            std = np.std(X, axis=0)
            std[std == 0] = 1.0
            return (X - mean) / std

    class IsolationForest:
        def __init__(self, n_estimators=300, contamination=0.05, random_state=42, n_jobs=None):
            self.contamination = contamination
            self._scores = None

        def fit_predict(self, X):
            X = np.asarray(X, dtype=float)
            z = np.mean(np.abs(X), axis=1)
            self._scores = -z
            thresh = np.quantile(z, 1.0 - self.contamination)
            return np.where(z >= thresh, -1, 1)

        def decision_function(self, X):
            if self._scores is not None and len(self._scores) == len(X):
                return self._scores
            X = np.asarray(X, dtype=float)
            return -np.mean(np.abs(X), axis=1)


# ============================================================
# AI CLOUD IAM RISK ANALYZER - UPGRADED VERSION
# ============================================================

_DEFAULT_NORMALIZED = "data/analyzed/normalized_events.csv"
INPUT_FILE = os.getenv(
    "CLOUDTRAIL_INPUT_FILE",
    _DEFAULT_NORMALIZED if os.path.exists(_DEFAULT_NORMALIZED) else "data/processed/cloudtrail_features.csv",
)
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "data/analyzed")
OUTPUT_FILE = os.getenv(
    "ANOMALY_OUTPUT_FILE",
    os.path.join(OUTPUT_DIR, "iam_anomaly_analysis.csv")
)

N_ESTIMATORS = 300
CONTAMINATION = 0.05
RANDOM_STATE = 42


# ============================================================
# SECURITY EVENT DEFINITIONS
# ============================================================

SENSITIVE_EVENTS = {
    "CreateUser",
    "CreateAccessKey",
    "DeleteUser",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreateRole",
    "UpdateAssumeRolePolicy",
    "DeleteRole",
    "UpdateUser",
    "UpdateRole",
    "DeleteAccessKey",
    "DetachUserPolicy",
    "DetachRolePolicy",
    "PassRole",
    "CreatePolicy",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "DeletePolicy",
}

PRIVILEGE_ESCALATION_EVENTS = {
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "UpdateAssumeRolePolicy",
    "PassRole",
}

WRITE_PREFIXES = (
    "Create",
    "Delete",
    "Update",
    "Put",
    "Attach",
    "Detach",
    "Modify",
    "Set",
    "Add",
    "Remove",
)


# ============================================================
# HELPERS
# ============================================================

def clean(value):
    if pd.isna(value):
        return ""

    value = str(value).strip()

    if value.lower() in {
        "",
        "nan",
        "none",
        "null",
        "unknown",
    }:
        return ""

    return value


def safe_column(df, name, default=""):
    if name in df.columns:
        return df[name]
    return pd.Series(default, index=df.index)


def is_service_event(row):
    user_type = clean(row.get("user_type", "")).lower()
    user_agent = clean(row.get("user_agent", "")).lower()
    source_ip = clean(row.get("source_ip", "")).lower()
    event_source = clean(row.get("event_source", "")).lower()

    if user_type == "awsservice":
        return 1

    if "amazonaws.com" in user_agent:
        return 1

    if "amazonaws.com" in source_ip:
        return 1

    if "amazonaws.com" in event_source:
        return 1

    return 0


def get_mfa_value(row):
    value = clean(row.get("mfa_used", "")).lower()

    if value in {"true", "1", "yes"}:
        return 1

    return 0


def get_mfa_unknown(row):
    value = clean(row.get("mfa_used", "")).lower()

    if value in {
        "",
        "unknown",
        "nan",
        "none",
        "null",
    }:
        return 1

    return 0


def is_failed_request(row):
    error = clean(row.get("error_code", ""))

    if error:
        return 1

    return 0


def is_sensitive_event(row):
    event = clean(row.get("event_name", ""))

    return int(event in SENSITIVE_EVENTS)


def is_privilege_escalation(row):
    event = clean(row.get("event_name", ""))

    return int(event in PRIVILEGE_ESCALATION_EVENTS)


def is_write_operation(row):
    event = clean(row.get("event_name", ""))

    return int(event.startswith(WRITE_PREFIXES))


# ============================================================
# BEHAVIORAL FEATURE ENGINEERING
# ============================================================

def create_behavioral_features(df):
    print("\nCreating advanced behavioral features...")

    features = pd.DataFrame(index=df.index)

    # --------------------------------------------------------
    # 1. EVENT FREQUENCY
    # --------------------------------------------------------

    event_series = (
        safe_column(df, "event_name", "UNKNOWN")
        .fillna("UNKNOWN")
        .astype(str)
    )

    event_counts = event_series.value_counts()

    features["event_frequency"] = (
        event_series.map(event_counts)
        .fillna(1)
        .astype(float)
    )

    # --------------------------------------------------------
    # 2. EVENT RARITY
    # --------------------------------------------------------

    max_event_frequency = max(
        float(features["event_frequency"].max()),
        1.0
    )

    features["event_rarity"] = (
        1.0 -
        (
            features["event_frequency"] /
            max_event_frequency
        )
    ) * 100

    # --------------------------------------------------------
    # 3. IDENTITY FREQUENCY
    # --------------------------------------------------------

    principal = safe_column(df, "principal_id", "")
    user_name = safe_column(df, "user_name", "")

    identity_series = (
        principal.fillna("")
        .astype(str)
        .str.strip()
    )

    fallback_identity = (
        user_name.fillna("UNKNOWN")
        .astype(str)
        .str.strip()
    )

    identity_series = identity_series.where(
        identity_series.ne(""),
        fallback_identity
    )

    identity_series = identity_series.replace(
        {"nan": "UNKNOWN", "": "UNKNOWN"}
    )

    identity_counts = identity_series.value_counts()

    features["identity_frequency"] = (
        identity_series.map(identity_counts)
        .fillna(1)
        .astype(float)
    )

    # --------------------------------------------------------
    # 4. SOURCE FREQUENCY
    # --------------------------------------------------------

    source_series = (
        safe_column(df, "source_ip", "UNKNOWN")
        .fillna("UNKNOWN")
        .astype(str)
        .str.strip()
        .replace({"": "UNKNOWN"})
    )

    source_counts = source_series.value_counts()

    features["source_frequency"] = (
        source_series.map(source_counts)
        .fillna(1)
        .astype(float)
    )

    # --------------------------------------------------------
    # 5. SOURCE RARITY
    # --------------------------------------------------------

    max_source_frequency = max(
        float(features["source_frequency"].max()),
        1.0
    )

    features["source_rarity"] = (
        1.0 -
        (
            features["source_frequency"] /
            max_source_frequency
        )
    ) * 100

    # --------------------------------------------------------
    # 6. FAILED REQUEST (Vectorized)
    # --------------------------------------------------------

    err_series = (
        safe_column(df, "error_code", "")
        .fillna("")
        .astype(str)
        .str.strip()
    )
    err_clean_lower = err_series.str.lower()
    features["failed_request"] = (
        ~err_clean_lower.isin({"", "nan", "none", "null", "unknown"})
    ).astype(int)

    # --------------------------------------------------------
    # 7. MFA (Vectorized)
    # --------------------------------------------------------

    mfa_series = (
        safe_column(df, "mfa_used", "")
        .fillna("")
        .astype(str)
        .str.strip()
        .str.lower()
    )

    features["mfa_not_used"] = (
        mfa_series.isin({"false", "0", "no"})
    ).astype(int)

    features["mfa_unknown"] = (
        mfa_series.isin({"", "unknown", "nan", "none", "null"})
    ).astype(int)

    # --------------------------------------------------------
    # 8. WRITE OPERATION (Vectorized)
    # --------------------------------------------------------

    clean_event_series = (
        safe_column(df, "event_name", "")
        .fillna("")
        .astype(str)
        .str.strip()
    )

    features["write_operation"] = (
        clean_event_series.str.startswith(WRITE_PREFIXES)
    ).astype(int)

    # --------------------------------------------------------
    # 9. SENSITIVE OPERATION (Vectorized)
    # --------------------------------------------------------

    features["sensitive_operation"] = (
        clean_event_series.isin(SENSITIVE_EVENTS)
    ).astype(int)

    # --------------------------------------------------------
    # 10. PRIVILEGE ESCALATION (Vectorized)
    # --------------------------------------------------------

    features["privilege_escalation"] = (
        clean_event_series.isin(PRIVILEGE_ESCALATION_EVENTS)
    ).astype(int)

    # --------------------------------------------------------
    # 11. AWS SERVICE ACTIVITY (Vectorized)
    # --------------------------------------------------------

    ut_s = safe_column(df, "user_type", "").fillna("").astype(str).str.strip().str.lower()
    ua_s = safe_column(df, "user_agent", "").fillna("").astype(str).str.strip().str.lower()
    ip_s = safe_column(df, "source_ip", "").fillna("").astype(str).str.strip().str.lower()
    es_s = safe_column(df, "event_source", "").fillna("").astype(str).str.strip().str.lower()

    features["aws_service_activity"] = (
        (ut_s == "awsservice")
        | ua_s.str.contains("amazonaws.com", regex=False, na=False)
        | ip_s.str.contains("amazonaws.com", regex=False, na=False)
        | es_s.str.contains("amazonaws.com", regex=False, na=False)
    ).astype(int)

    # --------------------------------------------------------
    # 12. EVENT HOUR (Vectorized)
    # --------------------------------------------------------

    if "event_hour" in df.columns and df["event_hour"].notna().all():
        features["event_hour"] = pd.to_numeric(df["event_hour"], errors="coerce").fillna(0).astype(int)
    else:
        try:
            event_time = pd.to_datetime(
                safe_column(df, "event_time", ""),
                format="ISO8601",
                errors="coerce",
                utc=True
            )
        except Exception:
            event_time = pd.to_datetime(
                safe_column(df, "event_time", ""),
                errors="coerce",
                utc=True
            )
        features["event_hour"] = (
            event_time
            .dt.hour
            .fillna(0)
            .astype(int)
        )

    # --------------------------------------------------------
    # 13. OFF-HOURS ACTIVITY
    # --------------------------------------------------------

    features["off_hours"] = (
        (
            features["event_hour"] < 6
        )
        |
        (
            features["event_hour"] >= 22
        )
    ).astype(int)

    # --------------------------------------------------------
    # 14. ERROR + SENSITIVE CORRELATION
    # --------------------------------------------------------

    features["failed_sensitive_combo"] = (
        (
            features["failed_request"] == 1
        )
        &
        (
            features["sensitive_operation"] == 1
        )
    ).astype(int)

    # --------------------------------------------------------
    # 15. PRIVILEGE + ANOMALY PRECURSOR
    # --------------------------------------------------------

    features["privilege_change_combo"] = (
        (
            features["privilege_escalation"] == 1
        )
        &
        (
            features["write_operation"] == 1
        )
    ).astype(int)

    # --------------------------------------------------------
    # 16. EXISTING RULE SCORE IF AVAILABLE
    # --------------------------------------------------------

    if "risk_score" in df.columns:
        features["existing_rule_score"] = (
            pd.to_numeric(
                df["risk_score"],
                errors="coerce"
            ).fillna(0)
        )
    else:
        features["existing_rule_score"] = 0.0

    # --------------------------------------------------------
    # CLEAN
    # --------------------------------------------------------

    features = features.replace(
        [np.inf, -np.inf],
        np.nan
    )

    features = features.fillna(0)

    print(
        f"Advanced behavioral features created: "
        f"{len(features.columns)}"
    )

    print("\nFeature columns:")
    print(list(features.columns))

    return features


# ============================================================
# RULE-BASED RISK ENGINE
# ============================================================

def calculate_rule_score(row):
    score = 0.0

    # Sensitive IAM operation
    if row["sensitive_operation"] == 1:
        score += 35

    # Privilege escalation
    if row["privilege_escalation"] == 1:
        score += 25

    # General write operation
    elif row["write_operation"] == 1:
        score += 10

    # Explicit MFA not used
    if row["mfa_not_used"] == 1:
        score += 15

    # Failed request
    if row["failed_request"] == 1:
        score += 10

    # Rare event
    if row["event_rarity"] >= 75:
        score += 8

    # Rare source
    if row["source_rarity"] >= 75:
        score += 7

    # Off-hours activity
    if row["off_hours"] == 1:
        score += 8

    # Failed sensitive operation
    if row["failed_sensitive_combo"] == 1:
        score += 12

    # Privilege-change correlation
    if row["privilege_change_combo"] == 1:
        score += 8

    # AWS service activity is contextual.
    # Do NOT automatically subtract risk.
    # A service-generated sensitive event can still be important.

    return float(
        np.clip(score, 0, 100)
    )


# ============================================================
# ANOMALY SCORE
# ============================================================

def calculate_anomaly_score(model, X):
    """
    IsolationForest decision_function:
        higher = more normal
        lower  = more abnormal

    Convert abnormality to a 0-100 score.
    """

    decision_scores = model.decision_function(X)

    abnormality = -decision_scores

    min_value = float(
        np.min(abnormality)
    )

    max_value = float(
        np.max(abnormality)
    )

    if max_value == min_value:
        scores = np.zeros(
            len(abnormality)
        )
    else:
        scores = (
            (
                abnormality - min_value
            )
            /
            (
                max_value - min_value
            )
        ) * 100

    return np.clip(
        scores,
        0,
        100
    )


# ============================================================
# FINAL RISK LEVEL
# ============================================================

def get_risk_level(score):
    if score >= 85:
        return "CRITICAL"

    if score >= 65:
        return "HIGH"

    if score >= 35:
        return "MEDIUM"

    return "LOW"


# ============================================================
# RISK REASONS
# ============================================================

def build_reasons(row):
    reasons = []

    if row["sensitive_operation"] == 1:
        reasons.append(
            "Sensitive IAM operation"
        )

    if row["privilege_escalation"] == 1:
        reasons.append(
            "Potential privilege escalation"
        )

    elif row["write_operation"] == 1:
        reasons.append(
            "IAM write operation"
        )

    if row["mfa_not_used"] == 1:
        reasons.append(
            "MFA explicitly not used"
        )

    elif row["mfa_unknown"] == 1:
        reasons.append(
            "MFA status unavailable"
        )

    if row["failed_request"] == 1:
        reasons.append(
            "Failed AWS API request"
        )

    if row["off_hours"] == 1:
        reasons.append(
            "Off-hours activity"
        )

    if row["event_rarity"] >= 75:
        reasons.append(
            "Rare API event"
        )

    if row["source_rarity"] >= 75:
        reasons.append(
            "Rare source"
        )

    if row["failed_sensitive_combo"] == 1:
        reasons.append(
            "Failed sensitive IAM operation"
        )

    if row["privilege_change_combo"] == 1:
        reasons.append(
            "Privilege-change activity"
        )

    if row["is_anomaly"] == -1:
        reasons.append(
            "Isolation Forest anomaly detected"
        )

    if row["anomaly_score"] >= 80:
        reasons.append(
            "High behavioral anomaly score"
        )

    if row["aws_service_activity"] == 1:
        reasons.append(
            "AWS service-to-service activity"
        )

    if not reasons:
        reasons.append(
            "No major risk indicators"
        )

    return "; ".join(
        dict.fromkeys(reasons)
    )


# ============================================================
# RECOMMENDED ACTION
# ============================================================

def get_recommended_action(row):
    level = row["final_risk_level"]

    if level == "CRITICAL":
        return (
            "Immediately investigate identity, review IAM "
            "policies, verify source, and consider temporary "
            "access restriction."
        )

    if level == "HIGH":
        return (
            "Review the IAM event, originating identity, "
            "source and recent privilege changes."
        )

    if level == "MEDIUM":
        return (
            "Review event context and compare with the "
            "identity's normal behavior."
        )

    return (
        "Continue monitoring; no immediate action indicated."
    )


# ============================================================
# MAIN
# ============================================================

def main():
    global INPUT_FILE, OUTPUT_DIR, OUTPUT_FILE

    max_rows = None
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="AI Cloud IAM Behavioral Risk Analyzer")
        parser.add_argument("--input", default=INPUT_FILE, help="Path to input CloudTrail features CSV")
        parser.add_argument("--output", default=OUTPUT_FILE, help="Path to output anomaly analysis CSV")
        parser.add_argument("--max-rows", type=int, default=None, help="Optionally limit rows for fast benchmarking")
        args, _ = parser.parse_known_args()
        INPUT_FILE = args.input
        OUTPUT_FILE = args.output
        OUTPUT_DIR = os.path.dirname(OUTPUT_FILE) or OUTPUT_DIR
        max_rows = args.max_rows

    print("=" * 72)
    print("AI CLOUD IAM BEHAVIORAL RISK ANALYZER")
    print("UPGRADED ML + RULE + CORRELATION ENGINE")
    print("=" * 72)
    print(f"Input file : {INPUT_FILE}")
    print(f"Output file: {OUTPUT_FILE}")

    # --------------------------------------------------------
    # INPUT CHECK
    # --------------------------------------------------------

    if not os.path.exists(INPUT_FILE):

        print(
            f"\nERROR: Input file not found:\n"
            f"{INPUT_FILE}"
        )

        print(
            "\nRun the CloudTrail feature extraction pipeline first."
        )

        return

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    # --------------------------------------------------------
    # LOAD DATA
    # --------------------------------------------------------

    print(
        "\nLoading CloudTrail features..."
    )

    lower_path = str(INPUT_FILE).lower()
    if lower_path.endswith((".json", ".jsonl", ".ndjson", ".gz", ".parquet")) or os.path.isdir(INPUT_FILE):
        try:
            from input_adapters.universal_ingestor import read_input_source
            df = read_input_source(INPUT_FILE, max_rows=max_rows)
        except Exception as e:
            print(f"Warning: Universal ingestor failed: {e}. Falling back to pandas...")
            df = pd.read_csv(INPUT_FILE, nrows=max_rows)
    else:
        try:
            df = pd.read_csv(INPUT_FILE, nrows=max_rows)
            # If CSV is missing basic canonical columns, normalize it
            if not all(col in df.columns for col in ["event_name", "user_name", "source_ip"]):
                from input_adapters.universal_ingestor import normalize_dataframe
                df = normalize_dataframe(df)
        except Exception:
            from input_adapters.universal_ingestor import read_any_file
            df = read_any_file(INPUT_FILE, max_rows=max_rows)

    print(
        f"Events loaded: {len(df)}"
    )

    if len(df) < 20:

        print(
            "\nWARNING: Dataset contains fewer than 20 events."
        )

        print(
            "Isolation Forest results may be unstable "
            "with very small datasets."
        )

    # --------------------------------------------------------
    # FEATURE ENGINEERING
    # --------------------------------------------------------

    features = create_behavioral_features(
        df
    )

    # --------------------------------------------------------
    # ML INPUT
    # --------------------------------------------------------

    X = features.copy()

    X = X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    X = X.fillna(0)

    # Standardization is not required by Isolation Forest,
    # but keeps feature magnitudes comparable for this project.
    scaler = StandardScaler()

    X_scaled = scaler.fit_transform(
        X
    )

    # --------------------------------------------------------
    # ISOLATION FOREST
    # --------------------------------------------------------

    print(
        "\nTraining Isolation Forest..."
    )

    effective_contamination = CONTAMINATION
    if len(df) <= 5:
        effective_contamination = "auto"
    elif len(df) < 20:
        effective_contamination = min(0.2, max(0.05, 1.0 / len(df)))

    model = IsolationForest(
        n_estimators=min(N_ESTIMATORS, 100) if len(df) < 50 else N_ESTIMATORS,
        contamination=effective_contamination,
        random_state=RANDOM_STATE,
        n_jobs=-1
    )

    model.fit(
        X_scaled
    )

    # --------------------------------------------------------
    # ANOMALY PREDICTION
    # --------------------------------------------------------

    predictions = model.predict(
        X_scaled
    )

    df["is_anomaly"] = predictions

    df["anomaly_label"] = np.where(
        predictions == -1,
        "ANOMALY",
        "NORMAL"
    )

    # --------------------------------------------------------
    # ANOMALY SCORE
    # --------------------------------------------------------

    print(
        "\nCalculating behavioral anomaly scores..."
    )

    df["anomaly_score"] = (
        calculate_anomaly_score(
            model,
            X_scaled
        )
    )

    df["anomaly_score"] = (
        df["anomaly_score"]
        .round(2)
    )

    # --------------------------------------------------------
    # COPY FEATURES TO OUTPUT
    # --------------------------------------------------------

    for column in features.columns:
        df[column] = features[column]

    # --------------------------------------------------------
    # RULE SCORE (Vectorized)
    # --------------------------------------------------------

    print(
        "\nCalculating rule-based security score..."
    )

    raw_rule_score = (
        np.where(df["sensitive_operation"] == 1, 35.0, 0.0)
        + np.where(
            df["privilege_escalation"] == 1,
            25.0,
            np.where(df["write_operation"] == 1, 10.0, 0.0)
        )
        + np.where(df["mfa_not_used"] == 1, 15.0, 0.0)
        + np.where(df["failed_request"] == 1, 10.0, 0.0)
        + np.where(df["event_rarity"] >= 75, 8.0, 0.0)
        + np.where(df["source_rarity"] >= 75, 7.0, 0.0)
        + np.where(df["off_hours"] == 1, 8.0, 0.0)
        + np.where(df["failed_sensitive_combo"] == 1, 12.0, 0.0)
        + np.where(df["privilege_change_combo"] == 1, 8.0, 0.0)
    )
    df["rule_risk_score"] = np.clip(raw_rule_score, 0.0, 100.0)

    # --------------------------------------------------------
    # FINAL RISK FUSION
    # --------------------------------------------------------

    print(
        "\nCalculating composite security risk..."
    )

    # Explainable rules = 60%
    # Behavioral ML   = 40%

    df["final_risk_score"] = (
        (
            df["rule_risk_score"] * 0.60
        )
        +
        (
            df["anomaly_score"] * 0.40
        )
    )

    # --------------------------------------------------------
    # CORRELATION / ESCALATION BONUS
    # --------------------------------------------------------

    # Multiple independent indicators together increase
    # confidence that the event deserves investigation.

    correlation_mask = (
        (
            df["is_anomaly"] == -1
        )
        &
        (
            (
                df["sensitive_operation"] == 1
            )
            |
            (
                df["privilege_escalation"] == 1
            )
            |
            (
                df["failed_request"] == 1
            )
        )
    )

    df.loc[
        correlation_mask,
        "final_risk_score"
    ] += 10

    # Failed + sensitive is a stronger signal.
    failed_sensitive_mask = (
        (
            df["failed_request"] == 1
        )
        &
        (
            df["sensitive_operation"] == 1
        )
    )

    df.loc[
        failed_sensitive_mask,
        "final_risk_score"
    ] += 5

    # --------------------------------------------------------
    # CLAMP
    # --------------------------------------------------------

    df["final_risk_score"] = (
        df["final_risk_score"]
        .clip(0, 100)
        .round(2)
    )

    # --------------------------------------------------------
    # RISK LEVEL (Vectorized)
    # --------------------------------------------------------

    scores_arr = df["final_risk_score"].to_numpy()
    df["final_risk_level"] = np.select(
        [scores_arr >= 85, scores_arr >= 65, scores_arr >= 35],
        ["CRITICAL", "HIGH", "MEDIUM"],
        default="LOW"
    )

    # --------------------------------------------------------
    # EXPLANATIONS (Vectorized Bitmask Lookup)
    # --------------------------------------------------------

    print(
        "\nGenerating explainable risk reasons..."
    )

    reason_mask_arr = (
        ((df["sensitive_operation"].to_numpy() == 1).astype(np.int32) * (1 << 0))
        + ((df["privilege_escalation"].to_numpy() == 1).astype(np.int32) * (1 << 1))
        + ((df["write_operation"].to_numpy() == 1).astype(np.int32) * (1 << 2))
        + ((df["mfa_not_used"].to_numpy() == 1).astype(np.int32) * (1 << 3))
        + ((df["mfa_unknown"].to_numpy() == 1).astype(np.int32) * (1 << 4))
        + ((df["failed_request"].to_numpy() == 1).astype(np.int32) * (1 << 5))
        + ((df["off_hours"].to_numpy() == 1).astype(np.int32) * (1 << 6))
        + ((df["event_rarity"].to_numpy() >= 75).astype(np.int32) * (1 << 7))
        + ((df["source_rarity"].to_numpy() >= 75).astype(np.int32) * (1 << 8))
        + ((df["failed_sensitive_combo"].to_numpy() == 1).astype(np.int32) * (1 << 9))
        + ((df["privilege_change_combo"].to_numpy() == 1).astype(np.int32) * (1 << 10))
        + ((df["is_anomaly"].to_numpy() == -1).astype(np.int32) * (1 << 11))
        + ((df["anomaly_score"].to_numpy() >= 80).astype(np.int32) * (1 << 12))
        + ((df["aws_service_activity"].to_numpy() == 1).astype(np.int32) * (1 << 13))
    )
    reason_mask = pd.Series(reason_mask_arr, index=df.index)

    def _mask_to_reason(m: int) -> str:
        r = []
        if m & (1 << 0):
            r.append("Sensitive IAM operation")
        if m & (1 << 1):
            r.append("Potential privilege escalation")
        elif m & (1 << 2):
            r.append("IAM write operation")
        if m & (1 << 3):
            r.append("MFA explicitly not used")
        elif m & (1 << 4):
            r.append("MFA status unavailable")
        if m & (1 << 5):
            r.append("Failed AWS API request")
        if m & (1 << 6):
            r.append("Off-hours activity")
        if m & (1 << 7):
            r.append("Rare API event")
        if m & (1 << 8):
            r.append("Rare source")
        if m & (1 << 9):
            r.append("Failed sensitive IAM operation")
        if m & (1 << 10):
            r.append("Privilege-change activity")
        if m & (1 << 11):
            r.append("Isolation Forest anomaly detected")
        if m & (1 << 12):
            r.append("High behavioral anomaly score")
        if m & (1 << 13):
            r.append("AWS service-to-service activity")
        if not r:
            r.append("No major risk indicators")
        return "; ".join(dict.fromkeys(r))

    unique_masks = reason_mask.unique()
    mask_lookup = {int(m): _mask_to_reason(int(m)) for m in unique_masks}
    df["risk_reasons"] = reason_mask.map(mask_lookup)

    # --------------------------------------------------------
    # RECOMMENDED ACTION (Vectorized)
    # --------------------------------------------------------

    action_map = {
        "CRITICAL": (
            "Immediately investigate identity, review IAM "
            "policies, verify source, and consider temporary "
            "access restriction."
        ),
        "HIGH": (
            "Review the IAM event, originating identity, "
            "source and recent privilege changes."
        ),
        "MEDIUM": (
            "Review event context and compare with the "
            "identity's normal behavior."
        ),
        "LOW": "Continue monitoring; no immediate action indicated."
    }
    df["recommended_action"] = df["final_risk_level"].map(action_map).fillna(action_map["LOW"])

    # --------------------------------------------------------
    # SAVE
    # --------------------------------------------------------

    df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    print("\n" + "=" * 72)
    print("SECURITY ANALYSIS SUMMARY")
    print("=" * 72)

    print(
        f"\nTotal events analyzed: {len(df)}"
    )

    print(
        "\nRisk distribution:"
    )

    distribution = (
        df["final_risk_level"]
        .value_counts()
        .reindex(
            [
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            ],
            fill_value=0
        )
    )

    print(
        distribution
    )

    print(
        f"\nAverage rule risk score: "
        f"{df['rule_risk_score'].mean():.2f}"
    )

    print(
        f"Average anomaly score: "
        f"{df['anomaly_score'].mean():.2f}"
    )

    print(
        f"Average final risk score: "
        f"{df['final_risk_score'].mean():.2f}"
    )

    anomalies = df[
        df["is_anomaly"] == -1
    ]

    high_risk = df[
        df["final_risk_level"].isin(
            [
                "HIGH",
                "CRITICAL"
            ]
        )
    ]

    print(
        f"\nAnomalous events detected: "
        f"{len(anomalies)}"
    )

    print(
        f"High/Critical risk events: "
        f"{len(high_risk)}"
    )

    # --------------------------------------------------------
    # TOP HIGH-RISK EVENTS
    # --------------------------------------------------------

    if not high_risk.empty:

        print(
            "\nTOP HIGH-RISK EVENTS"
        )

        print(
            "-" * 72
        )

        columns = [
            "event_name",
            "final_risk_score",
            "final_risk_level",
            "anomaly_score",
            "rule_risk_score",
            "risk_reasons",
            "recommended_action",
        ]

        available = [
            column
            for column in columns
            if column in high_risk.columns
        ]

        print(
            high_risk[
                available
            ]
            .sort_values(
                "final_risk_score",
                ascending=False
            )
            .head(10)
            .to_string(
                index=False
            )
        )

    else:

        print(
            "\nNo HIGH/CRITICAL events detected."
        )

    # --------------------------------------------------------
    # BEHAVIORAL ANOMALIES
    # --------------------------------------------------------

    if not anomalies.empty:

        print(
            "\n" + "=" * 72
        )

        print(
            "DETECTED BEHAVIORAL ANOMALIES"
        )

        print(
            "=" * 72
        )

        columns = [
            "event_name",
            "event_source",
            "source_ip",
            "anomaly_score",
            "rule_risk_score",
            "final_risk_score",
            "final_risk_level",
            "risk_reasons",
        ]

        available = [
            column
            for column in columns
            if column in anomalies.columns
        ]

        print(
            anomalies[
                available
            ]
            .sort_values(
                "final_risk_score",
                ascending=False
            )
            .head(20)
            .to_string(
                index=False
            )
        )

    # --------------------------------------------------------
    # PROJECT METRICS
    # --------------------------------------------------------

    print(
        "\n" + "=" * 72
    )

    print(
        "ANALYZER METRICS"
    )

    print(
        "=" * 72
    )

    print(
        f"\nML model: Isolation Forest"
    )

    print(
        f"Trees: {N_ESTIMATORS}"
    )

    print(
        f"Contamination: {CONTAMINATION}"
    )

    print(
        f"Behavioral features: "
        f"{len(features.columns)}"
    )

    print(
        "\nRisk fusion:"
    )

    print(
        "Rule engine: 60%"
    )

    print(
        "ML anomaly engine: 40%"
    )

    print(
        "Correlation escalation: enabled"
    )

    print(
        "\nResults saved to:"
    )

    print(
        OUTPUT_FILE
    )

    print(
        "\n" + "=" * 72
    )

    print(
        "ANALYSIS COMPLETED"
    )

    print(
        "=" * 72
    )


if __name__ == "__main__":
    main()
