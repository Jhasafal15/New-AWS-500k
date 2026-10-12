"""
Synthetic Security Pipeline Runner.
Runs the entire end-to-end security pipeline (Behavioral + ML + CSPM + Correlation + Findings + Response)
on the synthetic dataset safely, without overwriting original baseline test files unless requested.
"""

import os
import sys
import argparse
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

def main():
    parser = argparse.ArgumentParser(
        description="Run AI Cloud Security Pipeline on Synthetic Datasets"
    )
    parser.add_argument(
        "--dataset",
        choices=["500k", "test", "val", "train"],
        default="test",
        help="Synthetic dataset split to analyze (default: 'test' [75,000 rows])"
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=10000,
        help="Row limit for execution (default: 10,000 rows for high speed; set 0 for all rows)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/synthetic/analyzed",
        help="Directory to save analysis outputs (default: data/synthetic/analyzed)"
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Write outputs directly into main data/analyzed directory instead of data/synthetic/analyzed"
    )

    args = parser.parse_args()

    # Determine input dataset path
    dataset_files = {
        "500k": BASE_DIR / "data" / "synthetic" / "synthetic_cloudtrail_500k.csv",
        "test": BASE_DIR / "data" / "synthetic" / "test_cloudtrail.csv",
        "val": BASE_DIR / "data" / "synthetic" / "val_cloudtrail.csv",
        "train": BASE_DIR / "data" / "synthetic" / "train_cloudtrail.csv",
    }
    input_file = dataset_files[args.dataset]
    if not input_file.exists():
        print(f"[ERROR] Input dataset not found: {input_file}")
        return

    # Determine output directory
    output_dir = BASE_DIR / "data" / "analyzed" if args.in_place else BASE_DIR / Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    anomaly_file = output_dir / "iam_anomaly_analysis.csv"

    print()
    print("=" * 76)
    print("       AI-POWERED CLOUD SECURITY POSTURE MANAGEMENT")
    print("           SYNTHETIC SECURITY PIPELINE RUNNER")
    print("=" * 76)
    print(f"Dataset      : {args.dataset} ({input_file})")
    print(f"Max Rows     : {'ALL' if args.max_rows == 0 else f'{args.max_rows:,}'}")
    print(f"Output Dir   : {output_dir}")
    print("=" * 76)

    # Set environment variables for child processes
    env = os.environ.copy()
    env["CLOUDTRAIL_INPUT_FILE"] = str(input_file)
    env["OUTPUT_DIR"] = str(output_dir)
    env["ANOMALY_OUTPUT_FILE"] = str(anomaly_file)

    # --------------------------------------------------------
    # STEP 1: BEHAVIORAL + ML ANALYSIS
    # --------------------------------------------------------
    print("\n" + "-" * 76)
    print("STEP 1: BEHAVIORAL + ML ANOMALY ANALYSIS")
    print("-" * 76)
    cmd1 = [
        sys.executable,
        "analyzer.py",
        "--input", str(input_file),
        "--output", str(anomaly_file),
    ]
    if args.max_rows > 0:
        cmd1.extend(["--max-rows", str(args.max_rows)])

    res1 = subprocess.run(cmd1, cwd=BASE_DIR, env=env)
    if res1.returncode != 0:
        print("[FAILED] Step 1 Analyzer failed.")
        return

    # --------------------------------------------------------
    # STEP 2: BEHAVIORAL CORRELATION ANALYSIS
    # --------------------------------------------------------
    print("\n" + "-" * 76)
    print("STEP 2: BEHAVIORAL CORRELATION ANALYSIS")
    print("-" * 76)
    cmd2 = [
        sys.executable,
        "-m",
        "input_adapters.correlation_adapter",
        str(anomaly_file)
    ]
    res2 = subprocess.run(cmd2, cwd=BASE_DIR, env=env)
    if res2.returncode != 0:
        print("[FAILED] Step 2 Correlation Adapter failed.")
        return

    print("\n" + "=" * 76)
    print("SYNTHETIC BEHAVIORAL ANALYSIS PIPELINE COMPLETED SUCCESSFULLY!")
    print("=" * 76)
    print(f"Analyzed Anomaly Output: {anomaly_file}")


if __name__ == "__main__":
    main()
