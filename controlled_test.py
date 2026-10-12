import pandas as pd
from pathlib import Path
import shutil

# ============================================================
# CONTROLLED BEHAVIOUR ANALYSIS TEST
# ============================================================

BASELINE_FILE = Path("data/processed/cloudtrail_features.baseline.csv")
WORKING_FILE = Path("data/processed/cloudtrail_suspicious_features.csv")
BACKUP_FILE = Path("data/processed/cloudtrail_suspicious_features.backup.csv")

print("=" * 70)
print("CONTROLLED BEHAVIOUR ANALYSIS TEST")
print("=" * 70)

# ------------------------------------------------------------
# 1. Check baseline dataset
# ------------------------------------------------------------

if not BASELINE_FILE.exists():
    print(f"ERROR: Baseline file not found:")
    print(BASELINE_FILE)
    raise SystemExit(1)

if not WORKING_FILE.exists():
    print(f"ERROR: Working dataset not found:")
    print(WORKING_FILE)
    raise SystemExit(1)

# ------------------------------------------------------------
# 2. Backup current suspicious dataset
# ------------------------------------------------------------

shutil.copy2(WORKING_FILE, BACKUP_FILE)

print("\nBackup created:")
print(BACKUP_FILE)

# ------------------------------------------------------------
# 3. Load baseline
# ------------------------------------------------------------

df = pd.read_csv(BASELINE_FILE)

print(f"\nBaseline events loaded: {len(df)}")

if len(df) == 0:
    print("ERROR: Baseline dataset is empty.")
    raise SystemExit(1)

# ------------------------------------------------------------
# 4. Select ONE event
# ------------------------------------------------------------

test_index = df.index[0]

print(f"\nControlled test event index: {test_index}")

if "event_name" in df.columns:
    print(
        "Original event:",
        df.loc[test_index, "event_name"]
    )

# ------------------------------------------------------------
# 5. Helper for safe modification
# ------------------------------------------------------------

def set_value(column, value):
    if column not in df.columns:
        print(f"Column not present, skipping: {column}")
        return

    try:
        df.at[test_index, column] = value
        print(f"Modified {column} -> {value}")
    except Exception as exc:
        print(f"Could not modify {column}: {exc}")

# ------------------------------------------------------------
# 6. Create controlled suspicious behaviour
# ------------------------------------------------------------

print("\nInjecting controlled suspicious behaviour...")

# Authentication anomaly
set_value("mfa_used", False)

# Failed request
set_value("is_failed", True)

# Force non-read-only activity
set_value("read_only", False)

# Make the event represent a sensitive IAM action
set_value("event_name", "PutRolePolicy")

# IAM service
set_value("event_source", "iam.amazonaws.com")

# Permission-related API
set_value("api_category", "permission")

# ------------------------------------------------------------
# 7. Additional suspicious indicators if available
# ------------------------------------------------------------

set_value("error_present", True)

# ------------------------------------------------------------
# 8. Save controlled dataset
# ------------------------------------------------------------

df.to_csv(WORKING_FILE, index=False)

print("\nControlled dataset created:")
print(WORKING_FILE)

# ------------------------------------------------------------
# 9. Display modified event
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("CONTROLLED EVENT")
print("=" * 70)

for column in [
    "event_name",
    "event_source",
    "mfa_used",
    "is_failed",
    "read_only",
    "api_category",
    "error_present"
]:
    if column in df.columns:
        print(f"{column}: {df.loc[test_index, column]}")

print("\n" + "=" * 70)
print("CONTROLLED DATASET READY")
print("=" * 70)

print("\nNow run:")
print("python analyzer.py")

print("\nAfter testing, restore the original dataset with:")
print("Copy-Item data\\processed\\cloudtrail_suspicious_features.backup.csv data\\processed\\cloudtrail_suspicious_features.csv -Force")