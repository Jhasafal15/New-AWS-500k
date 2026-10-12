import subprocess
import sys
from pathlib import Path
import time


# ============================================================
# AI CLOUD IAM BEHAVIORAL SECURITY
# CENTRAL ANALYSIS ORCHESTRATOR
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent


def print_header():
    print("=" * 72)
    print("AI CLOUD IAM BEHAVIORAL SECURITY")
    print("CENTRAL ANALYSIS ORCHESTRATOR")
    print("=" * 72)
    print()


def run_stage(stage_name, command):
    """
    Execute one security analysis stage.
    """

    print("=" * 72)
    print(f"[START] {stage_name}")
    print("=" * 72)

    start_time = time.time()

    try:
        result = subprocess.run(
            command,
            cwd=BASE_DIR,
            text=True
        )

        elapsed = time.time() - start_time

        if result.returncode != 0:
            print()
            print(f"[FAILED] {stage_name}")
            print(f"Exit code: {result.returncode}")
            return False

        print()
        print(f"[SUCCESS] {stage_name}")
        print(f"Execution time: {elapsed:.2f} seconds")
        print()

        return True

    except Exception as e:
        print()
        print(f"[ERROR] {stage_name}")
        print(f"Reason: {e}")
        return False


def main():

    print_header()

    print("Project directory:")
    print(BASE_DIR)
    print()

    stages = [

        (
            "1. MODULES 1, 2 & 3: CLOUD ASSET INGESTION, NORMALIZATION & POLICY-AS-CODE + CISA KEV SCANNER",
            [sys.executable, "-m", "input_adapters.module1_2_3_bridge"]
        ),

        (
            "2. MODULE 4: BEHAVIORAL ANALYSIS & ISOLATION FOREST ML ANOMALY DETECTION (500K STREAM)",
            [sys.executable, "analyzer.py"]
        ),

        (
            "3. MODULE 5: MULTI-STAGE BEHAVIORAL CORRELATION ANALYSIS",
            [sys.executable, "-m", "input_adapters.correlation_adapter"]
        ),

        (
            "4. MODULE 6A: BEHAVIORAL SECURITY FINDING GENERATION",
            [sys.executable, "output/finding_writer.py"]
        ),

        (
            "5. MODULE 6B: UNIFIED CSPM + CISA KEV + BEHAVIORAL FINDING INTEGRATION",
            [sys.executable, "-m", "vulnerability.merge_findings"]
        ),

        (
            "6. MODULE 6C: AUTOMATED SOAR RESPONSE & REMEDIATION GENERATION",
            [sys.executable, "-m", "response.response_engine"]
        ),

        (
            "7. MODULE 7: INTERACTIVE CYBER SOC & CSPM DASHBOARD GENERATION",
            [sys.executable, "-m", "output.dashboard_generator"]
        )

    ]

    completed = 0

    for stage_name, command in stages:

        success = run_stage(stage_name, command)

        if not success:
            print()
            print("=" * 72)
            print("PIPELINE STOPPED")
            print("=" * 72)
            print()
            print(f"Failed stage: {stage_name}")
            print()
            return

        completed += 1

    print("=" * 72)
    print("SECURITY PIPELINE COMPLETED")
    print("=" * 72)

    print()
    print(f"Stages completed : {completed}/{len(stages)}")

    print()
    print("Analysis flow:")
    print("CloudTrail Data")
    print("      ↓")
    print("Behavioral Feature Engineering")
    print("      ↓")
    print("Isolation Forest Anomaly Detection")
    print("      ↓")
    print("Behavioral Correlation")
    print("      ↓")
    print("Security Finding Generation")
    print("      ↓")
    print("Response & Remediation")
    print()

    print("Pipeline execution completed successfully.")
    print("=" * 72)


if __name__ == "__main__":
    main()