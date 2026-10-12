"""
Universal CloudTrail & Security Log Ingestor
AI-Powered Cloud Security Posture Management

Accepts ANY input format:
- CSV (standard, Athena, Splunk, uppercase/camelCase columns)
- JSON (AWS S3 {"Records": [...]}, list of dicts, or nested CloudTrailEvent strings)
- JSON Lines (.jsonl, .ndjson)
- GZIP compressed files (.json.gz, .csv.gz)
- Parquet (.parquet)
- Directories of log files

Normalizes all schemas into the canonical schema required by the behavioral,
anomaly detection, and correlation engines.
"""

import os
import sys
import gzip
import json
import glob
from pathlib import Path
from typing import Union, List, Dict, Any, Optional
import pandas as pd
import numpy as np


# ============================================================
# CANONICAL SCHEMA & SENSITIVE APIS
# ============================================================

CANONICAL_COLUMNS = [
    "event_time",
    "event_name",
    "event_source",
    "aws_region",
    "source_ip",
    "user_agent",
    "user_type",
    "user_name",
    "principal_id",
    "access_key_id",
    "user_arn",
    "mfa_used",
    "error_code",
    "error_message",
    "is_failed",
    "read_only",
    "recipient_account_id",
    "event_hour",
    "event_day",
    "is_night",
    "api_category",
    "is_privileged_api",
]

SENSITIVE_IAM_APIS = {
    "CreateUser", "CreateAccessKey", "DeleteUser", "DeleteAccessKey",
    "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
    "CreateRole", "DeleteRole", "UpdateAssumeRolePolicy", "PassRole",
    "CreatePolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion",
    "DeletePolicy", "UpdateUser", "UpdateRole", "UpdateLoginProfile",
    "CreateLoginProfile", "DeleteLoginProfile", "DeactivateMFADevice",
    "EnableMFADevice", "CreateVirtualMFADevice", "ResyncMFADevice",
    "AddUserToGroup", "RemoveUserFromGroup", "AttachGroupPolicy",
    "PutGroupPolicy"
}

# Column name synonym mappings (lowercase normalized -> canonical)
COLUMN_ALIASES = {
    # event_name
    "event_name": "event_name",
    "eventname": "event_name",
    "event": "event_name",
    "action": "event_name",
    "api_name": "event_name",
    "operation": "event_name",
    "method": "event_name",

    # event_time
    "event_time": "event_time",
    "eventtime": "event_time",
    "timestamp": "event_time",
    "time": "event_time",
    "@timestamp": "event_time",
    "datetime": "event_time",
    "date": "event_time",

    # event_source
    "event_source": "event_source",
    "eventsource": "event_source",
    "source": "event_source",
    "service": "event_source",
    "service_name": "event_source",
    "servicename": "event_source",

    # aws_region
    "aws_region": "aws_region",
    "awsregion": "aws_region",
    "region": "aws_region",

    # source_ip
    "source_ip": "source_ip",
    "sourceip": "source_ip",
    "sourceipaddress": "source_ip",
    "client_ip": "source_ip",
    "clientip": "source_ip",
    "ip": "source_ip",
    "ip_address": "source_ip",

    # user_agent
    "user_agent": "user_agent",
    "useragent": "user_agent",
    "caller_agent": "user_agent",

    # user_name
    "user_name": "user_name",
    "username": "user_name",
    "user": "user_name",
    "principal": "user_name",
    "actor": "user_name",
    "identity": "user_name",

    # principal_id
    "principal_id": "principal_id",
    "principalid": "principal_id",
    "principal_arn": "principal_id",

    # access_key_id
    "access_key_id": "access_key_id",
    "accesskeyid": "access_key_id",
    "access_key": "access_key_id",

    # user_arn
    "user_arn": "user_arn",
    "userarn": "user_arn",
    "arn": "user_arn",

    # user_type
    "user_type": "user_type",
    "usertype": "user_type",
    "type": "user_type",

    # mfa_used
    "mfa_used": "mfa_used",
    "mfaused": "mfa_used",
    "mfa": "mfa_used",
    "mfa_authenticated": "mfa_used",
    "mfaauthenticated": "mfa_used",

    # error_code
    "error_code": "error_code",
    "errorcode": "error_code",
    "status": "error_code",
    "response_code": "error_code",

    # error_message
    "error_message": "error_message",
    "errormessage": "error_message",
    "error": "error_message",

    # is_failed
    "is_failed": "is_failed",
    "isfailed": "is_failed",
    "failed": "is_failed",

    # read_only
    "read_only": "read_only",
    "readonly": "read_only",

    # recipient_account_id
    "recipient_account_id": "recipient_account_id",
    "recipientaccountid": "recipient_account_id",
    "account_id": "recipient_account_id",
    "accountid": "recipient_account_id",
}


# ============================================================
# RECORD EXTRACTION & FLATTENING
# ============================================================

def _parse_cloudtrail_event_field(raw_val: Any) -> Dict[str, Any]:
    """Parse nested CloudTrailEvent JSON string if present."""
    if isinstance(raw_val, dict):
        return raw_val
    if isinstance(raw_val, str) and raw_val.strip().startswith("{"):
        try:
            parsed = json.loads(raw_val)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
    return {}


def _extract_user_identity(user_identity: Any) -> Dict[str, Any]:
    """Extract standard fields from a CloudTrail userIdentity object."""
    if isinstance(user_identity, str) and user_identity.strip().startswith("{"):
        try:
            user_identity = json.loads(user_identity)
        except Exception:
            user_identity = {}

    if not isinstance(user_identity, dict):
        return {
            "user_type": "unknown",
            "user_name": "unknown",
            "principal_id": "unknown",
            "user_arn": "unknown",
            "access_key_id": "",
            "mfa_used": "unknown",
        }

    # Extract user name
    user_name = user_identity.get("userName")
    if not user_name:
        session_context = user_identity.get("sessionContext", {})
        if isinstance(session_context, dict):
            session_issuer = session_context.get("sessionIssuer", {})
            if isinstance(session_issuer, dict):
                user_name = session_issuer.get("userName")

    principal_id = user_identity.get("principalId", "")
    arn = user_identity.get("arn", "")

    if not user_name and arn:
        user_name = arn.split("/")[-1]
    if not user_name and principal_id:
        user_name = principal_id.split(":")[-1]

    # Extract MFA status
    mfa_status = "unknown"
    session_context = user_identity.get("sessionContext", {})
    if isinstance(session_context, dict):
        attributes = session_context.get("attributes", {})
        if isinstance(attributes, dict):
            mfa_val = attributes.get("mfaAuthenticated")
            if mfa_val is not None:
                mfa_status = str(mfa_val).lower()

    return {
        "user_type": user_identity.get("type", "unknown"),
        "user_name": user_name or "unknown",
        "principal_id": principal_id or "unknown",
        "user_arn": arn or "unknown",
        "access_key_id": user_identity.get("accessKeyId", ""),
        "mfa_used": mfa_status,
    }


def _flatten_single_cloudtrail_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a raw dictionary (from JSON or CloudTrail) into standard fields."""
    # Check if this record wraps an inner CloudTrailEvent string/dict
    inner = _parse_cloudtrail_event_field(rec.get("CloudTrailEvent"))
    if inner:
        # Merge top-level with inner, preferring inner
        merged = dict(rec)
        merged.update(inner)
        rec = merged

    out: Dict[str, Any] = {}

    # Map column aliases
    for k, v in rec.items():
        clean_key = k.strip().lower()
        if clean_key in COLUMN_ALIASES:
            canon = COLUMN_ALIASES[clean_key]
            if canon not in out or not out[canon]:
                out[canon] = v

    # Deep extract userIdentity if present
    user_ident = rec.get("userIdentity") or rec.get("user_identity")
    if user_ident:
        extracted = _extract_user_identity(user_ident)
        for ek, ev in extracted.items():
            if ek not in out or not out[ek] or out[ek] == "unknown":
                out[ek] = ev

    # Preserve scenario and session metadata if present (e.g., 500k enterprise stream)
    for meta_key in ("attack_scenario", "session_id", "behavior_sequence_id", "behavior_label"):
        if meta_key in rec and rec[meta_key] is not None:
            out[meta_key] = rec[meta_key]

    return out


# ============================================================
# FILE READERS
# ============================================================

def read_json_records(file_path: Union[str, Path], max_rows: Optional[int] = None, flatten_on_fly: bool = False) -> List[Dict[str, Any]]:
    """Read events from JSON, JSON.gz, or JSONL with streaming support for large 500k+ files."""
    file_path = Path(file_path)
    records: List[Dict[str, Any]] = []

    is_gz = file_path.suffix.lower() == ".gz" or str(file_path).lower().endswith(".json.gz")
    ext = file_path.suffix.lower()
    open_fn = gzip.open if is_gz else open

    # Fast streaming path for .jsonl / .ndjson or large files (> 25 MB)
    file_size = file_path.stat().st_size if file_path.exists() else 0
    if ext in (".jsonl", ".ndjson") or file_size > 25 * 1024 * 1024:
        with open_fn(file_path, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_s = line.strip()
                if not line_s:
                    continue
                try:
                    parsed = json.loads(line_s)
                    if isinstance(parsed, dict):
                        if "Records" in parsed and isinstance(parsed["Records"], list):
                            batch = parsed["Records"]
                        elif "Events" in parsed and isinstance(parsed["Events"], list):
                            batch = parsed["Events"]
                        else:
                            batch = [parsed]
                    elif isinstance(parsed, list):
                        batch = parsed
                    else:
                        continue

                    for item in batch:
                        records.append(_flatten_single_cloudtrail_record(item) if flatten_on_fly else item)
                        if max_rows and len(records) >= max_rows:
                            return records
                except Exception:
                    continue
        if records:
            return records

    with open_fn(file_path, "rt", encoding="utf-8", errors="replace") as f:
        content = f.read().strip()

    if not content:
        return []

    # First attempt: Try parsing as standard complete JSON document
    try:
        data = json.loads(content)
        raw_list = []
        if isinstance(data, dict):
            if "Records" in data and isinstance(data["Records"], list):
                raw_list = data["Records"]
            elif "Events" in data and isinstance(data["Events"], list):
                raw_list = data["Events"]
            else:
                raw_list = [data]
        elif isinstance(data, list):
            raw_list = data
        if max_rows and len(raw_list) > max_rows:
            raw_list = raw_list[:max_rows]
        return [_flatten_single_cloudtrail_record(r) for r in raw_list] if flatten_on_fly else raw_list
    except Exception:
        pass

    # Second attempt: Try parsing as JSON Lines (one JSON object per line)
    for line in content.splitlines():
        line_s = line.strip()
        if not line_s:
            continue
        try:
            parsed = json.loads(line_s)
            if isinstance(parsed, dict):
                if "Records" in parsed and isinstance(parsed["Records"], list):
                    batch = parsed["Records"]
                elif "Events" in parsed and isinstance(parsed["Events"], list):
                    batch = parsed["Events"]
                else:
                    batch = [parsed]
            elif isinstance(parsed, list):
                batch = parsed
            else:
                continue
            for item in batch:
                records.append(_flatten_single_cloudtrail_record(item) if flatten_on_fly else item)
                if max_rows and len(records) >= max_rows:
                    return records
        except Exception:
            continue

    return records


def read_any_file(file_path: Union[str, Path], max_rows: Optional[int] = None) -> pd.DataFrame:
    """Read ANY file format (CSV, JSON, JSONL, GZ, Parquet) into a normalized DataFrame."""
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {file_path}")

    ext = file_path.suffix.lower()
    lower_name = str(file_path).lower()

    if ext == ".parquet":
        df = pd.read_parquet(file_path)
        if max_rows and len(df) > max_rows:
            df = df.iloc[:max_rows]
        return normalize_dataframe(df)

    if ext in (".json", ".jsonl", ".ndjson") or lower_name.endswith(".json.gz"):
        flattened = read_json_records(file_path, max_rows=max_rows, flatten_on_fly=True)
        df = pd.DataFrame(flattened)
        del flattened
        return normalize_dataframe(df)

    # Assume CSV / TSV
    for sep in (",", "\t", ";"):
        for enc in ("utf-8", "utf-8-sig", "latin1"):
            try:
                df = pd.read_csv(file_path, sep=sep, nrows=max_rows, encoding=enc, low_memory=False)
                if len(df.columns) > 1:
                    return normalize_dataframe(df)
            except Exception:
                continue

    # Fallback to standard read_csv
    df = pd.read_csv(file_path, nrows=max_rows, errors="replace", low_memory=False)
    return normalize_dataframe(df)


def read_input_source(source_path: Union[str, Path], max_rows: Optional[int] = None) -> pd.DataFrame:
    """Read a single file or an entire directory of logs into a single DataFrame."""
    source_path = Path(source_path)
    if not source_path.exists():
        raise FileNotFoundError(f"Source not found: {source_path}")

    if source_path.is_file():
        return read_any_file(source_path, max_rows=max_rows)

    if source_path.is_dir():
        # Directory: find all supported files
        patterns = ["*.csv", "*.json", "*.jsonl", "*.ndjson", "*.gz", "*.parquet"]
        files: List[Path] = []
        for pat in patterns:
            files.extend(source_path.glob(pat))
            files.extend(source_path.glob(f"**/{pat}"))

        files = sorted(list(set(files)))
        if not files:
            raise ValueError(f"No supported log files found in directory: {source_path}")

        print(f"Found {len(files)} files in directory: {source_path}")
        dfs = []
        rows_read = 0
        for f in files:
            remaining = None if max_rows is None else max_rows - rows_read
            if remaining is not None and remaining <= 0:
                break
            try:
                curr_df = read_any_file(f, max_rows=remaining)
                if not curr_df.empty:
                    dfs.append(curr_df)
                    rows_read += len(curr_df)
            except Exception as e:
                print(f"Warning: skipped {f.name} due to error: {e}")

        if not dfs:
            raise ValueError(f"Failed to read any records from directory: {source_path}")

        combined = pd.concat(dfs, ignore_index=True)
        if max_rows and len(combined) > max_rows:
            combined = combined.iloc[:max_rows]
        return normalize_dataframe(combined)

    raise ValueError(f"Unsupported path: {source_path}")


# ============================================================
# SCHEMA NORMALIZER & ENRICHER
# ============================================================

def classify_api_operation(event_name: str) -> str:
    """Classify API into broad behavioral categories."""
    if not event_name or pd.isna(event_name):
        return "Unknown"

    name = str(event_name).strip()
    if name in SENSITIVE_IAM_APIS:
        return "Sensitive IAM"

    for read_prefix in ("Get", "Describe", "List", "Head", "View", "Lookup"):
        if name.startswith(read_prefix):
            return "Read"

    for write_prefix in ("Create", "Delete", "Update", "Put", "Attach", "Detach", "Modify", "Set", "Add", "Remove", "Terminate"):
        if name.startswith(write_prefix):
            return "Write"

    if "Discovery" in name or "Search" in name or "Find" in name:
        return "Discovery"

    return "Other Operation"


def infer_event_source(event_name: str, existing_source: str = "") -> str:
    """Infer event source domain if missing."""
    if existing_source and str(existing_source).strip() not in ("", "unknown", "nan"):
        return str(existing_source).strip()

    name = str(event_name).strip()
    if "Role" in name or "Policy" in name or "User" in name or "AccessKey" in name or "Group" in name:
        return "iam.amazonaws.com"
    if "Bucket" in name or "Object" in name or "S3" in name:
        return "s3.amazonaws.com"
    if "Instance" in name or "SecurityGroup" in name or "Vpc" in name or "Subnet" in name:
        return "ec2.amazonaws.com"
    if "DB" in name or "Database" in name or "Snapshot" in name:
        return "rds.amazonaws.com"
    if "AssumeRole" in name or "CallerIdentity" in name:
        return "sts.amazonaws.com"
    if "Trail" in name:
        return "cloudtrail.amazonaws.com"
    return "aws.unknown"


def normalize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize any DataFrame into the full canonical schema required by the pipeline."""
    if df.empty:
        return pd.DataFrame(columns=CANONICAL_COLUMNS)

    # Rename existing columns using aliases
    rename_map = {}
    for col in df.columns:
        norm_col = str(col).strip().lower()
        if norm_col in COLUMN_ALIASES:
            canon = COLUMN_ALIASES[norm_col]
            if canon not in df.columns:
                rename_map[col] = canon

    if rename_map:
        df = df.rename(columns=rename_map)

    # 1. event_name
    if "event_name" not in df.columns:
        df["event_name"] = "UnknownApiCall"
    else:
        df["event_name"] = df["event_name"].fillna("UnknownApiCall").astype(str).str.strip()

    # 2. event_time
    if "event_time" not in df.columns:
        now = pd.Timestamp.utcnow()
        df["event_time"] = [
            (now - pd.Timedelta(seconds=5 * i)).strftime("%Y-%m-%dT%H:%M:%SZ")
            for i in range(len(df))
        ]
    else:
        df["event_time"] = df["event_time"].fillna("").astype(str)
        missing_mask = df["event_time"].str.strip() == ""
        if missing_mask.any():
            now = pd.Timestamp.utcnow()
            df.loc[missing_mask, "event_time"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Parse timestamps for hour/day/night (fast ISO8601 path)
    try:
        parsed_time = pd.to_datetime(df["event_time"], format="ISO8601", errors="coerce", utc=True)
    except Exception:
        parsed_time = pd.to_datetime(df["event_time"], errors="coerce", utc=True)
    valid_mask = parsed_time.notna()

    # 3. event_hour
    if "event_hour" not in df.columns or df["event_hour"].isna().all():
        df["event_hour"] = 12
        df.loc[valid_mask, "event_hour"] = parsed_time[valid_mask].dt.hour
    df["event_hour"] = pd.to_numeric(df["event_hour"], errors="coerce").fillna(12).astype(int)

    # 4. event_day
    if "event_day" not in df.columns or df["event_day"].isna().all():
        df["event_day"] = "Wednesday"
        df.loc[valid_mask, "event_day"] = parsed_time[valid_mask].dt.day_name()
    df["event_day"] = df["event_day"].fillna("Wednesday").astype(str)

    # 5. is_night
    if "is_night" not in df.columns:
        df["is_night"] = (df["event_hour"] < 6) | (df["event_hour"] >= 22)
    else:
        df["is_night"] = df["is_night"].astype(str).str.lower().isin(["true", "1", "yes"])

    # 6. event_source (vectorized over unique event names)
    unique_events = df["event_name"].unique()
    source_lookup = {e: infer_event_source(e) for e in unique_events}
    if "event_source" not in df.columns:
        df["event_source"] = df["event_name"].map(source_lookup)
    else:
        df["event_source"] = df["event_source"].fillna("").astype(str)
        empty_source = df["event_source"].str.strip() == ""
        if empty_source.any():
            df.loc[empty_source, "event_source"] = df.loc[empty_source, "event_name"].map(source_lookup)

    # 7. aws_region
    if "aws_region" not in df.columns:
        df["aws_region"] = "us-east-1"
    else:
        df["aws_region"] = df["aws_region"].fillna("us-east-1").astype(str).replace({"": "us-east-1"})

    # 8. source_ip
    if "source_ip" not in df.columns:
        df["source_ip"] = "192.168.1.100"
    else:
        df["source_ip"] = df["source_ip"].fillna("192.168.1.100").astype(str).replace({"": "192.168.1.100"})

    # 9. user_agent
    if "user_agent" not in df.columns:
        df["user_agent"] = "aws-sdk/python (Boto3)"
    else:
        df["user_agent"] = df["user_agent"].fillna("aws-sdk/python").astype(str)

    # 10. user_name
    if "user_name" not in df.columns:
        df["user_name"] = "security-analyst"
    else:
        df["user_name"] = df["user_name"].fillna("security-analyst").astype(str).replace({"": "security-analyst"})

    # 11. user_type
    if "user_type" not in df.columns:
        df["user_type"] = "IAMUser"
    else:
        df["user_type"] = df["user_type"].fillna("IAMUser").astype(str)

    # 12. principal_id
    if "principal_id" not in df.columns:
        df["principal_id"] = df["user_name"]
    else:
        df["principal_id"] = df["principal_id"].fillna(df["user_name"]).astype(str)

    # 13. access_key_id
    if "access_key_id" not in df.columns:
        df["access_key_id"] = ""
    else:
        df["access_key_id"] = df["access_key_id"].fillna("").astype(str)

    # 14. user_arn
    if "user_arn" not in df.columns:
        df["user_arn"] = "arn:aws:iam::123456789012:user/" + df["user_name"].astype(str)
    else:
        df["user_arn"] = df["user_arn"].fillna("").astype(str)

    # 15. mfa_used
    if "mfa_used" not in df.columns:
        df["mfa_used"] = "unknown"
    else:
        df["mfa_used"] = df["mfa_used"].fillna("unknown").astype(str).str.lower()

    # 16. error_code & error_message
    if "error_code" not in df.columns:
        df["error_code"] = ""
    else:
        df["error_code"] = df["error_code"].fillna("").astype(str).replace({"nan": ""})

    if "error_message" not in df.columns:
        df["error_message"] = ""
    else:
        df["error_message"] = df["error_message"].fillna("").astype(str).replace({"nan": ""})

    # 17. is_failed
    if "is_failed" not in df.columns:
        df["is_failed"] = (df["error_code"] != "") | (df["error_message"] != "")
    else:
        df["is_failed"] = df["is_failed"].astype(str).str.lower().isin(["true", "1", "yes"])

    # 18. read_only
    if "read_only" not in df.columns:
        df["read_only"] = df["event_name"].str.startswith(("Get", "Describe", "List", "Head"))
    else:
        df["read_only"] = df["read_only"].astype(str).str.lower().isin(["true", "1", "yes"])

    # 19. recipient_account_id
    if "recipient_account_id" not in df.columns:
        df["recipient_account_id"] = "123456789012"
    else:
        df["recipient_account_id"] = df["recipient_account_id"].fillna("123456789012").astype(str)

    # 20. api_category (vectorized over unique event names)
    cat_lookup = {e: classify_api_operation(e) for e in unique_events}
    if "api_category" not in df.columns:
        df["api_category"] = df["event_name"].map(cat_lookup)
    else:
        df["api_category"] = df["api_category"].fillna("Other").astype(str)

    # 21. is_privileged_api
    if "is_privileged_api" not in df.columns:
        df["is_privileged_api"] = df["event_name"].isin(SENSITIVE_IAM_APIS)
    else:
        df["is_privileged_api"] = df["is_privileged_api"].astype(str).str.lower().isin(["true", "1", "yes"])

    # Keep all canonical columns first, followed by any other original columns
    extra_cols = [c for c in df.columns if c not in CANONICAL_COLUMNS]
    ordered_cols = CANONICAL_COLUMNS + extra_cols
    return df[ordered_cols]


# ============================================================
# CLI TESTER
# ============================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m input_adapters.universal_ingestor <path_to_any_file_or_dir>")
        sys.exit(1)

    path = sys.argv[1]
    print(f"Reading and normalizing: {path}")
    df_result = read_input_source(path, max_rows=20)
    print(f"\nSuccessfully normalized {len(df_result)} records!")
    print(f"Columns: {list(df_result.columns)}")
    print("\nPreview:")
    print(df_result[["event_time", "event_name", "user_name", "source_ip", "api_category", "is_failed"]].head(10))
