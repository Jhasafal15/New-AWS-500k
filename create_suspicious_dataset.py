import pandas as pd
from pathlib import Path

# ============================================================
# CREATE SUSPICIOUS DATASET FOR BEHAVIOUR ANALYSIS TESTING
# ============================================================

INPUT_FILE = Path("data/processed/cloudtrail_features.csv")
OUTPUT_FILE = Path("data/processed/cloudtrail_suspicious_features.csv")


# ============================================================
# HEADER
# ============================================================

print("=" * 70)
print("CREATING SUSPICIOUS CLOUDTRAIL DATASET")
print("=" * 70)


# ============================================================
# CHECK INPUT FILE
# ============================================================

if not INPUT_FILE.exists():
    print(f"\nERROR: Input file not found:")
    print(INPUT_FILE)
    raise SystemExit(1)


# ============================================================
# LOAD ORIGINAL DATA
# ============================================================

try:
    df = pd.read_csv(INPUT_FILE)
except Exception as e:
    print(f"\nERROR loading CSV: {e}")
    raise SystemExit(1)


print(f"\nOriginal events: {len(df)}")
print(f"Columns available: {len(df.columns)}")


# ============================================================
# CREATE COPY
# ============================================================

suspicious = df.copy()


# ============================================================
# SAFE VALUE SETTER
# ============================================================

def set_value(column, index, value):
    """
    Safely modify a dataframe cell.

    The important part:
    Boolean-looking values are written as strings when the
    existing column contains strings.

    This prevents pandas dtype errors such as:

    TypeError:
    Invalid value 'False' for dtype 'str'
    """

    if column not in suspicious.columns:
        print(f"WARNING: Column '{column}' not found. Skipping.")
        return

    current_dtype = suspicious[column].dtype

    try:
        # String/object columns
        if pd.api.types.is_string_dtype(current_dtype) or current_dtype == object:
            suspicious.at[index, column] = str(value)

        # Boolean columns
        elif pd.api.types.is_bool_dtype(current_dtype):
            if isinstance(value, str):
                suspicious.at[index, column] = value.lower() == "true"
            else:
                suspicious.at[index, column] = bool(value)

        # Integer columns
        elif pd.api.types.is_integer_dtype(current_dtype):
            suspicious.at[index, column] = int(value)

        # Float columns
        elif pd.api.types.is_float_dtype(current_dtype):
            suspicious.at[index, column] = float(value)

        # Anything else
        else:
            suspicious.at[index, column] = value

    except Exception:
        # Final fallback: convert column to object/string-safe storage
        suspicious[column] = suspicious[column].astype(object)
        suspicious.at[index, column] = str(value)


# ============================================================
# SHOW AVAILABLE COLUMNS
# ============================================================

print("\nAvailable columns:")
for column in suspicious.columns:
    print(f"  - {column}")


# ============================================================
# CREATE SUSPICIOUS BEHAVIOUR
# ============================================================

print("\nCreating suspicious behaviour...")


if len(suspicious) == 0:
    print("ERROR: Dataset contains no events.")
    raise SystemExit(1)


# ------------------------------------------------------------
# EVENT 1 - HIGH RISK COMBINATION
# ------------------------------------------------------------

i = suspicious.index[0]

print(f"\nModifying event 1: row {i}")

set_value("mfa_used", i, "False")
set_value("is_failed", i, "True")
set_value("is_privileged_api", i, "True")
set_value("write_operation", i, "True")
set_value("sensitive_operation", i, "True")
set_value("privilege_escalation", i, "True")


# ------------------------------------------------------------
# EVENT 2 - FAILED PRIVILEGED REQUEST
# ------------------------------------------------------------

if len(suspicious) > 1:

    i = suspicious.index[1]

    print(f"Modifying event 2: row {i}")

    set_value("mfa_used", i, "False")
    set_value("is_failed", i, "True")
    set_value("is_privileged_api", i, "True")
    set_value("write_operation", i, "True")
    set_value("sensitive_operation", i, "True")


# ------------------------------------------------------------
# EVENT 3 - PRIVILEGE ESCALATION
# ------------------------------------------------------------

if len(suspicious) > 2:

    i = suspicious.index[2]

    print(f"Modifying event 3: row {i}")

    set_value("mfa_used", i, "False")
    set_value("is_failed", i, "True")
    set_value("privilege_escalation", i, "True")
    set_value("is_privileged_api", i, "True")


# ------------------------------------------------------------
# EVENT 4 - SENSITIVE WRITE
# ------------------------------------------------------------

if len(suspicious) > 3:

    i = suspicious.index[3]

    print(f"Modifying event 4: row {i}")

    set_value("mfa_used", i, "False")
    set_value("write_operation", i, "True")
    set_value("sensitive_operation", i, "True")
    set_value("is_privileged_api", i, "True")


# ------------------------------------------------------------
# EVENT 5 - MFA + FAILED REQUEST
# ------------------------------------------------------------

if len(suspicious) > 4:

    i = suspicious.index[4]

    print(f"Modifying event 5: row {i}")

    set_value("mfa_used", i, "False")
    set_value("is_failed", i, "True")
    set_value("is_privileged_api", i, "True")


# ============================================================
# SAVE DATASET
# ============================================================

try:

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    suspicious.to_csv(
        OUTPUT_FILE,
        index=False
    )

except Exception as e:

    print(f"\nERROR saving suspicious dataset: {e}")
    raise SystemExit(1)


# ============================================================
# VERIFY OUTPUT
# ============================================================

print("\n" + "=" * 70)
print("SUSPICIOUS DATASET CREATED SUCCESSFULLY")
print("=" * 70)

print(f"\nOriginal events : {len(df)}")
print(f"Output events   : {len(suspicious)}")
print(f"Output file     : {OUTPUT_FILE}")


# ============================================================
# DISPLAY TEST EVENTS
# ============================================================

print("\nModified test events:")

important_columns = [
    "event_name",
    "event_source",
    "mfa_used",
    "is_failed",
    "is_privileged_api",
    "write_operation",
    "sensitive_operation",
    "privilege_escalation"
]

available_important_columns = [
    column
    for column in important_columns
    if column in suspicious.columns
]


if available_important_columns:

    print(
        suspicious[
            available_important_columns
        ].head(5).to_string(index=False)
    )


# ============================================================
# FINAL
# ============================================================

print("\n" + "=" * 70)
print("TEST DATASET READY")
print("=" * 70)

print("\nNext step:")
print("Run the behaviour analyzer using the suspicious dataset.")
