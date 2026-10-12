"""
Main Pipeline Orchestrator: run_pipeline.py
Single entry-point command for Student 1.
Ingests raw cloud data, normalizes inventory state, executes policy-as-code rule scanners,
and produces unified outputs for Student 2 (Risk Engine) and Student 3 (Streamlit UI/LLM).
"""

import os
import sys
import argparse
import logging
from datetime import datetime, timezone

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.generators.generate_mock_cloud_data import generate_all_mock_data
from src.ingestion.data_loader import DataLoader
from src.ingestion.normalizer import CloudDataNormalizer
from src.rules.scanner import CloudSecurityScanner

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CSPM-Pipeline")

def run_pipeline(generate_data: bool = False, raw_dir: str = None, processed_dir: str = None):
    """Executes the full CSPM Data & Rule Engine pipeline."""
    base_dir = PROJECT_ROOT
    raw_data_dir = raw_dir or os.path.join(base_dir, "data", "raw")
    proc_data_dir = processed_dir or os.path.join(base_dir, "data", "processed")

    os.makedirs(raw_data_dir, exist_ok=True)
    os.makedirs(proc_data_dir, exist_ok=True)

    print("=" * 70)
    print("AI-POWERED CLOUD SECURITY POSTURE MANAGEMENT (CSPM) PLATFORM")
    print("=" * 70)

    # Step 1: Check or Generate Data
    required_raw_files = [
        "iam_users_roles.json",
        "s3_buckets.json",
        "ec2_instances.json",
        "vpc_networks.json",
        "cloudtrail_events.json",
        "software_inventory.csv"
    ]
    missing_files = [f for f in required_raw_files if not os.path.exists(os.path.join(raw_data_dir, f))]

    if generate_data or missing_files:
        print("\n[Step 1/3] Generating realistic cloud asset inventory and activity logs...")
        if missing_files:
            print(f"Missing raw files: {missing_files}. Generating new dataset...")
        summary = generate_all_mock_data(raw_data_dir)
        print(f"-> Generated {summary['total_cloud_resources']} AWS resources and {summary['cloudtrail_logs']} CloudTrail events.")
    else:
        print("\n[Step 1/3] Cloud asset data found. Skipping generation (use --generate to re-create).")

    # Step 2: Data Ingestion & Normalization
    print("\n[Step 2/3] Ingesting and Normalizing Cloud Asset Inventory...")
    loader = DataLoader(raw_data_dir)
    raw_data = loader.load_all()

    normalizer = CloudDataNormalizer(raw_data)
    inventory_file = os.path.join(proc_data_dir, "cloud_inventory.json")
    inventory = normalizer.process_and_save(inventory_file)
    print(f"-> Normalized {inventory['metadata']['total_resources']} cloud resources into unified state.")
    print(f"-> Saved normalized inventory to: {inventory_file}")

    # Step 3: Rule-Based Security Analysis
    print("\n[Step 3/3] Executing Policy-as-Code Security Scanner Engine...")
    scanner = CloudSecurityScanner(inventory_file)
    findings = scanner.run_all_checks()
    findings_file = os.path.join(proc_data_dir, "rule_findings.json")
    scanner.export_findings(findings_file)
    summary_stats = scanner.generate_summary()

    # Step 4: Summary Report
    print("\n" + "=" * 70)
    print("PIPELINE EXECUTION SUMMARY & METRICS")
    print("=" * 70)
    print(f"Timestamp:              {datetime.now(timezone.utc).isoformat()}")
    print(f"Total Cloud Resources:  {inventory['metadata']['total_resources']}")
    print(f"  - IAM Users & Roles:  {inventory['metadata']['counts']['iam_users'] + inventory['metadata']['counts']['iam_roles']}")
    print(f"  - S3 Buckets:         {inventory['metadata']['counts']['s3_buckets']}")
    print(f"  - EC2 Instances:      {inventory['metadata']['counts']['ec2_instances']}")
    print(f"  - VPC Networks:       {inventory['metadata']['counts']['vpcs']}")
    print(f"  - CloudTrail Events:  {inventory['metadata']['counts']['cloudtrail_events']}")
    print("-" * 70)
    print(f"Total Security Findings:{summary_stats['total_findings']}")
    print("Findings by Severity:")
    for sev, count in summary_stats['severity_breakdown'].items():
        print(f"  - {sev:<10}: {count}")
    print("Findings by Category:")
    for cat, count in summary_stats['category_breakdown'].items():
        print(f"  - {cat:<18}: {count}")
    print("-" * 70)
    print("Pipeline Deliverables & Artifacts:")
    print(f"  1. Unified Inventory: {inventory_file}")
    print(f"  2. Security Findings: {findings_file}")
    print("=" * 70)
    print("PIPELINE EXECUTION COMPLETED SUCCESSFULLY!\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-Powered CSPM Data & Rule Engine Pipeline (Modules 1-7 Integrated)")
    parser.add_argument("--generate", action="store_true", help="Force regeneration of synthetic cloud datasets")
    parser.add_argument("--raw-dir", type=str, default=None, help="Directory containing raw JSON/CSV datasets")
    parser.add_argument("--output-dir", type=str, default=None, help="Directory to save processed JSON deliverables")
    parser.add_argument("--standalone", action="store_true", help="Run only Modules 1, 2, & 3 (called by master orchestrator)")
    args = parser.parse_args()

    run_pipeline(generate_data=args.generate, raw_dir=args.raw_dir, processed_dir=args.output_dir)

    if not args.standalone:
        import subprocess
        from pathlib import Path
        base = Path(__file__).resolve().parent
        print("=" * 70)
        print("INTEGRATING MODULES 1, 2 & 3 WITH MODULES 4, 5, 6 & 7 (500K STREAM)")
        print("=" * 70)
        for cmd in [
            [sys.executable, "-m", "vulnerability.vulnerability_engine"],
            [sys.executable, "-c", "from input_adapters.module1_2_3_bridge import integrate_modules_1_2_3; integrate_modules_1_2_3(run_m13_scanner=False)"],
            [sys.executable, "output/finding_writer.py"],
            [sys.executable, "-m", "vulnerability.merge_findings"],
            [sys.executable, "-m", "response.response_engine"],
            [sys.executable, "-m", "output.dashboard_generator"],
        ]:
            subprocess.run(cmd, cwd=base, check=False)

