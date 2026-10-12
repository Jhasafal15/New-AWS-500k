import csv
import json
import os
import subprocess
import sys
from pathlib import Path


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

ANALYZED_DIR = BASE_DIR / "data" / "analyzed"
RAW_DIR = BASE_DIR / "data" / "raw"

ANOMALY_FILE = ANALYZED_DIR / "iam_anomaly_analysis.csv"

VULN_INVENTORY = RAW_DIR / "aws_vulnerability_inventory.json"
VULN_JSON = ANALYZED_DIR / "vulnerability_findings.json"
VULN_CSV = ANALYZED_DIR / "vulnerability_findings.csv"

FINDINGS_JSON = ANALYZED_DIR / "security_findings.json"
FINDINGS_CSV = ANALYZED_DIR / "security_findings.csv"

RESPONSE_JSON = ANALYZED_DIR / "security_response_recommendations.json"
RESPONSE_CSV = ANALYZED_DIR / "security_response_recommendations.csv"


# ============================================================
# DISPLAY FUNCTIONS
# ============================================================

def header():
    print()
    print("=" * 76)
    print("       AI-POWERED CLOUD SECURITY POSTURE MANAGEMENT")
    print("              MASTER SECURITY PIPELINE")
    print("=" * 76)
    print()


def stage(title):
    print()
    print("-" * 76)
    print(title)
    print("-" * 76)


# ============================================================
# COMMAND EXECUTION
# ============================================================

def run_command(command, name):

    print(f"\nRunning: {name}")
    print("Command:", " ".join(str(x) for x in command))

    try:
        result = subprocess.run(
            command,
            cwd=BASE_DIR,
            text=True
        )

    except Exception as error:
        print(f"[ERROR] {name}: {error}")
        return False

    if result.returncode != 0:
        print(f"\n[FAILED] {name}")
        print(f"Exit code: {result.returncode}")
        return False

    print(f"\n[SUCCESS] {name}")
    return True


# ============================================================
# FILE VERIFICATION
# ============================================================

def verify_file(path, description):

    if path.exists():
        print(f"[OK] {description}")
        print(f"     {path}")
        return True

    print(f"[MISSING] {description}")
    print(f"          {path}")
    return False


def count_csv_rows(path):

    if not path.exists():
        return 0

    try:
        with open(
            path,
            "r",
            encoding="utf-8",
            newline=""
        ) as file:

            return max(
                sum(1 for _ in csv.reader(file)) - 1,
                0
            )

    except Exception:
        return 0


def count_json_items(path):

    if not path.exists():
        return 0

    try:

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        if isinstance(data, list):
            return len(data)

        if isinstance(data, dict):

            for key in (
                "findings",
                "security_findings",
                "responses",
                "data",
                "records"
            ):

                if isinstance(data.get(key), list):
                    return len(data[key])

            return 1

        return 0

    except Exception:
        return 0


# ============================================================
# MAIN PIPELINE
# ============================================================

def main():

    header()

    print("Project directory:")
    print(BASE_DIR)

    # ========================================================
    # MODULES 1, 2 & 3 - MULTI-SERVICE CLOUD INGESTION,
    # NORMALIZATION & POLICY-AS-CODE + CISA KEV ENGINE
    # ========================================================

    stage(
        "MODULES 1, 2 & 3 - CLOUD ASSET INGESTION, "
        "NORMALIZATION & POLICY-AS-CODE + CISA KEV ENGINE"
    )

    if (BASE_DIR / "run_pipeline.py").exists():
        run_command(
            [sys.executable, "run_pipeline.py", "--standalone"],
            "Modules 1, 2 & 3: Cloud Inventory + 500K Stream + Policy-as-Code & CISA KEV Scanner"
        )

    # ========================================================
    # STEP 1 - MODULE 4: BEHAVIORAL + ML ANALYSIS (500K STREAM)
    # ========================================================

    stage("STEP 1 - MODULE 4: BEHAVIORAL + ML ANALYSIS (500K STREAM)")

    if not run_command(
        [sys.executable, "analyzer.py"],
        "Behavioral and ML Analysis"
    ):
        print("\nPipeline stopped at Step 1.")
        return

    if not verify_file(
        ANOMALY_FILE,
        "Behavioral anomaly output"
    ):
        print("\nPipeline stopped because behavioral output is missing.")
        return

    anomaly_count = count_csv_rows(ANOMALY_FILE)

    print(
        f"\nEvents in anomaly analysis: "
        f"{anomaly_count}"
    )


    # ========================================================
    # STEP 2 - LIVE VULNERABILITY COLLECTION
    # ========================================================

    stage(
        "STEP 2 - LIVE CLOUD SECURITY / "
        "VULNERABILITY COLLECTION"
    )

    skip_collection = os.getenv(
        "SKIP_LIVE_VULN_COLLECTION",
        ""
    ).lower() in {
        "1",
        "true",
        "yes"
    }

    if not skip_collection:

        if not run_command(
            [
                sys.executable,
                "-m",
                "vulnerability.aws_live_collector"
            ],
            "Live AWS Vulnerability Collection"
        ):
            print("[INFO] Live AWS collection unavailable; using cached aws_vulnerability_inventory.json.")

    else:

        print(
            "[INFO] Live collection skipped by "
            "SKIP_LIVE_VULN_COLLECTION."
        )

    if not verify_file(
        VULN_INVENTORY,
        "AWS vulnerability inventory"
    ):
        print(
            "\nPipeline stopped because "
            "vulnerability inventory is missing."
        )
        return


    # ========================================================
    # STEP 3 - VULNERABILITY / CSPM ANALYSIS
    # ========================================================

    stage(
        "STEP 3 - VULNERABILITY / CSPM ANALYSIS"
    )

    if not run_command(
        [
            sys.executable,
            "-m",
            "vulnerability.vulnerability_engine"
        ],
        "Vulnerability Analysis Engine"
    ):
        print("\nPipeline stopped at Step 3.")
        return

    if not run_command(
        [
            sys.executable,
            "-m",
            "input_adapters.module1_2_3_bridge"
        ],
        "Module 1, 2 & 3 CSPM + CISA KEV Integration Bridge"
    ):
        print("\nPipeline stopped at Step 3B (Module 1-3 Bridge).")
        return

    if not verify_file(
        VULN_JSON,
        "Vulnerability findings JSON"
    ):
        print(
            "\nPipeline stopped because "
            "vulnerability JSON is missing."
        )
        return

    if not verify_file(
        VULN_CSV,
        "Vulnerability findings CSV"
    ):
        print(
            "\nPipeline stopped because "
            "vulnerability CSV is missing."
        )
        return

    vulnerability_count = count_json_items(VULN_JSON)

    print(
        f"\nVulnerability findings: "
        f"{vulnerability_count}"
    )


    # ========================================================
    # STEP 4 - BEHAVIORAL CORRELATION
    # ========================================================

    stage("STEP 4 - BEHAVIORAL CORRELATION")

    if not run_command(
        [
            sys.executable,
            "-m",
            "input_adapters.correlation_adapter"
        ],
        "Behavioral Correlation Adapter + Engine"
    ):
        print("\nPipeline stopped at Step 4.")
        return


    # ========================================================
    # STEP 5 - SECURITY FINDING GENERATION
    # ========================================================

    stage("STEP 5 - SECURITY FINDING GENERATION")

    if not run_command(
        [
            sys.executable,
            "output/finding_writer.py"
        ],
        "Behavioral Security Finding Writer"
    ):
        print("\nPipeline stopped at Step 5.")
        return

    if not verify_file(
        FINDINGS_JSON,
        "Behavioral security findings JSON"
    ):
        print(
            "\nPipeline stopped because "
            "security findings are missing."
        )
        return


    # ========================================================
    # STEP 5B - VULNERABILITY FINDING INTEGRATION
    # ========================================================

    if not run_command(
        [
            sys.executable,
            "-m",
            "vulnerability.merge_findings"
        ],
        "Vulnerability Finding Integration"
    ):
        print(
            "\nPipeline stopped while "
            "integrating vulnerability findings."
        )
        return

    if not verify_file(
        FINDINGS_JSON,
        "Unified security findings JSON"
    ):
        return

    if not verify_file(
        FINDINGS_CSV,
        "Unified security findings CSV"
    ):
        return

    finding_count = count_json_items(FINDINGS_JSON)

    print(
        f"\nUnified security findings: "
        f"{finding_count}"
    )


    # ========================================================
    # STEP 6 - RESPONSE & REMEDIATION
    # ========================================================

    stage("STEP 6 - RESPONSE & REMEDIATION")

    if not run_command(
        [
            sys.executable,
            "-m",
            "response.response_engine"
        ],
        "Response & Remediation Engine"
    ):
        print("\nPipeline stopped at Step 6.")
        return

    if not verify_file(
        RESPONSE_JSON,
        "Response recommendations JSON"
    ):
        return

    if not verify_file(
        RESPONSE_CSV,
        "Response recommendations CSV"
    ):
        return

    response_count = count_json_items(
        RESPONSE_JSON
    )

    # ========================================================
    # STEP 7 - INTERACTIVE SOC DASHBOARD GENERATION
    # ========================================================

    stage("STEP 7 - INTERACTIVE SOC DASHBOARD GENERATION")

    run_command(
        [
            sys.executable,
            "-m",
            "output.dashboard_generator"
        ],
        "Interactive Cyber SOC Dashboard Generator"
    )


    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    stage("FINAL SECURITY PIPELINE SUMMARY")

    print(
        f"\nBehavioral events analyzed     : "
        f"{anomaly_count}"
    )

    print(
        f"Vulnerability findings        : "
        f"{vulnerability_count}"
    )

    print(
        f"Unified security findings     : "
        f"{finding_count}"
    )

    print(
        f"Response recommendations      : "
        f"{response_count}"
    )


    print("\nGenerated outputs:")

    output_files = [
        ANOMALY_FILE,
        VULN_INVENTORY,
        VULN_JSON,
        VULN_CSV,
        FINDINGS_JSON,
        FINDINGS_CSV,
        RESPONSE_JSON,
        RESPONSE_CSV
    ]

    for index, path in enumerate(
        output_files,
        1
    ):
        print(f"  {index}. {path}")


    print()
    print("=" * 76)
    print(
        "       END-TO-END CSPM SECURITY "
        "PIPELINE COMPLETED"
    )
    print("=" * 76)

    print()
    print("Flow:")
    print("CloudTrail")
    print("   |")
    print("   v")
    print("Behavioral + ML Analysis")
    print("   |")
    print("   v")
    print("Live AWS Security Inventory")
    print("   |")
    print("   v")
    print("Vulnerability / CSPM Analysis")
    print("   |")
    print("   v")
    print("Behavioral Correlation")
    print("   |")
    print("   v")
    print("Unified Security Findings")
    print("   |")
    print("   v")
    print("Response & Remediation")
    print()


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()