#!/usr/bin/env python3
"""
========================================================================================
AI-POWERED CLOUD SECURITY POSTURE MANAGEMENT & BEHAVIORAL RISK ANALYZER
UNIVERSAL DATASET ANALYSIS PIPELINE
========================================================================================

Works on ANY input dataset given:
  - Formats: CSV, JSON (Records/LookupEvents), JSON Lines (.jsonl), GZIP (.json.gz), Parquet, or directories
  - Schemas: Automatically maps camelCase, snake_case, AWS CloudTrail, and custom SIEM headers
  - Sizes: Small test sets (50 rows), mid-scale (10k-50k rows), or massive (500k+ rows)
  - End-to-end: Normalization -> 17 Behavioral Features -> Isolation Forest ML ->
               Rule Engine -> 60/40 Risk Fusion -> Correlation Chains ->
               CSPM Posture Checks -> Unified Findings -> Automated Playbooks ->
               Dynamic Interactive HTML Dashboard
"""

import os
import sys
import time
import argparse
import subprocess
from pathlib import Path
from typing import Optional, Union, Dict, List, Any
import pandas as pd
import numpy as np

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from input_adapters.universal_ingestor import read_input_source, normalize_dataframe
from output.dashboard_generator import generate_dashboard_html


def print_banner():
    print()
    print("=" * 80)
    print("      AI-POWERED CLOUD SECURITY POSTURE MANAGEMENT (CSPM)")
    print("         UNIVERSAL BEHAVIORAL & ML RISK ANALYSIS PIPELINE")
    print("=" * 80)
    print()


def run_stage_command(cmd, stage_name, env_vars=None):
    """Run a pipeline sub-command with formatted logging."""
    print(f"\n--- [RUNNING] {stage_name} ---")
    start = time.time()
    
    current_env = os.environ.copy()
    if env_vars:
        current_env.update(env_vars)

    res = subprocess.run(cmd, cwd=BASE_DIR, env=current_env, text=True)
    elapsed = time.time() - start

    if res.returncode != 0:
        print(f"[FAILED] {stage_name} (Exit code: {res.returncode})")
        return False
    
    print(f"[SUCCESS] {stage_name} ({elapsed:.2f}s)")
    return True


def run_pipeline(
    input_source: str,
    cspm_source: Optional[str] = None,
    output_dir: Optional[str] = None,
    max_rows: Optional[int] = None,
    contamination: float = 0.05,
    generate_dashboard: bool = True,
    dashboard_path: Optional[str] = None
):
    """Execute the full end-to-end security analysis pipeline on any input dataset."""
    start_total = time.time()
    print_banner()

    # Output directory
    out_dir = Path(output_dir) if output_dir else BASE_DIR / "data" / "analyzed"
    if not out_dir.is_absolute():
        out_dir = BASE_DIR / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    normalized_cache = out_dir / "normalized_events.csv"

    # Auto-resolve 500,000-event dataset when no explicit input path is given
    if not input_source or input_source == "auto":
        candidates_500k = [
            BASE_DIR / "data" / "raw" / "synthetic_cloudtrail_500k.jsonl",
            BASE_DIR.parent / "synthetic_cloudtrail_500k.jsonl",
            normalized_cache,
            BASE_DIR / "data" / "processed" / "cloudtrail_features.csv",
        ]
        input_path = next((c for c in candidates_500k if c.exists()), candidates_500k[-1])
    else:
        input_path = Path(input_source)
        if not input_path.is_absolute():
            input_path = BASE_DIR / input_path

    if not input_path.exists():
        print(f"ERROR: Input source does not exist: {input_path}")
        return False

    print(f"Input Dataset  : {input_path}")
    print(f"Output Directory: {out_dir}")
    if max_rows:
        print(f"Max Rows Limit  : {max_rows:,}")
    print(f"Contamination   : {contamination}")
    print("-" * 80)

    # =========================================================================
    # STAGE 1 (MODULES 1, 2 & 3): MULTI-SERVICE CLOUD INGESTION, NORMALIZATION & POLICY SCANNER
    # =========================================================================
    print("\n[STAGE 1/6 | MODULES 1, 2 & 3] Running Multi-Service Cloud Asset Ingestion, Normalization & Policy-as-Code Scanner...")
    if (BASE_DIR / "run_pipeline.py").exists():
        cmd_m13 = [sys.executable, str(BASE_DIR / "run_pipeline.py"), "--standalone"]
        run_stage_command(cmd_m13, "Modules 1, 2 & 3: Multi-Service Cloud Inventory + CISA KEV + Policy-as-Code Engine")

    print("\n[STAGE 1B/6 | MODULES 1 & 2] Ingesting and Normalizing 500K CloudTrail Telemetry Stream...")
    t0 = time.time()

    if input_path.resolve() == normalized_cache.resolve() and not max_rows:
        print(f"Using pre-normalized 500,000-event CloudTrail stream at: {normalized_cache} ({time.time()-t0:.2f}s)")
    else:
        try:
            df_normalized = read_input_source(input_path, max_rows=max_rows)
            print(f"Successfully ingested and normalized {len(df_normalized):,} records in {time.time()-t0:.2f}s")
        except Exception as e:
            print(f"ERROR in Ingestion & Normalization: {e}")
            return False

        if df_normalized.empty:
            print("ERROR: Ingested dataset is empty.")
            return False

        # Save normalized intermediate file and immediately release DataFrame RAM before Stage 2 subprocess
        df_normalized.to_csv(normalized_cache, index=False)
        del df_normalized
        import gc
        gc.collect()
        print(f"Cached normalized dataset at: {normalized_cache}")

    # =========================================================================
    # STAGE 2 (MODULE 4): 17 BEHAVIORAL FEATURES & ISOLATION FOREST ML ANOMALY DETECTION
    # =========================================================================
    print("\n[STAGE 2/6 | MODULE 4] Running Behavioral Feature Extraction & Isolation Forest Anomaly Detection...")
    anomaly_output = out_dir / "iam_anomaly_analysis.csv"

    env_stage2 = {
        "CLOUDTRAIL_INPUT_FILE": str(normalized_cache),
        "ANOMALY_OUTPUT_FILE": str(anomaly_output),
        "OUTPUT_DIR": str(out_dir)
    }

    cmd_stage2 = [
        sys.executable,
        str(BASE_DIR / "analyzer.py"),
        "--input", str(normalized_cache),
        "--output", str(anomaly_output)
    ]
    if max_rows:
        cmd_stage2.extend(["--max-rows", str(max_rows)])

    if not run_stage_command(cmd_stage2, "Behavioral Analysis & ML Anomaly Detection", env_vars=env_stage2):
        return False

    # =========================================================================
    # STAGE 3 (MODULE 5): BEHAVIORAL CORRELATION ANALYSIS (ATTACK CHAINS)
    # =========================================================================
    print("\n[STAGE 3/6 | MODULE 5] Running Behavioral Correlation Engine...")
    cmd_stage3 = [
        sys.executable,
        "-m", "input_adapters.correlation_adapter",
        str(anomaly_output)
    ]
    env_stage3 = {
        "CORRELATION_INPUT_FILE": str(anomaly_output),
        "OUTPUT_DIR": str(out_dir)
    }
    if not run_stage_command(cmd_stage3, "Behavioral Correlation Engine", env_vars=env_stage3):
        print("Warning: Correlation engine returned non-zero. Continuing to next stage...")

    # =========================================================================
    # STAGE 4 (MODULES 1, 2 & 3): CSPM POSTURE, CISA KEV & VULNERABILITY EVALUATION
    # =========================================================================
    print("\n[STAGE 4/6 | MODULES 1, 2 & 3] Running CSPM Posture, Policy-as-Code & CISA KEV Analysis...")
    vuln_inventory = None
    if cspm_source:
        vuln_inventory = Path(cspm_source)
        if not vuln_inventory.is_absolute():
            vuln_inventory = BASE_DIR / vuln_inventory
    else:
        # Check standard locations
        candidates = [
            BASE_DIR / "data" / "raw" / "aws_vulnerability_inventory.json",
            BASE_DIR / "data" / "synthetic" / "synthetic_cspm_inventory.csv",
        ]
        for c in candidates:
            if c.exists():
                vuln_inventory = c
                break

    vuln_json = out_dir / "vulnerability_findings.json"
    vuln_csv = out_dir / "vulnerability_findings.csv"

    if vuln_inventory and vuln_inventory.exists():
        print(f"Using CSPM Inventory: {vuln_inventory}")
        env_stage4 = {
            "VULN_INVENTORY_FILE": str(vuln_inventory),
            "OUTPUT_DIR": str(out_dir),
            "VULN_JSON": str(vuln_json),
            "VULN_CSV": str(vuln_csv)
        }
        cmd_stage4 = [sys.executable, "-m", "vulnerability.vulnerability_engine"]
        run_stage_command(cmd_stage4, "Vulnerability Analysis Engine", env_vars=env_stage4)
    else:
        print("No CSPM inventory provided; skipping live posture scan.")

    # Bridge Modules 1, 2 & 3 (125 Cloud Assets + CISA KEV + CIS AWS Policy-as-Code Findings)
    try:
        from input_adapters.module1_2_3_bridge import integrate_modules_1_2_3
        integrate_modules_1_2_3(out_dir, run_m13_scanner=False)
    except Exception as e:
        print(f"Warning: Module 1-3 bridge encountered an issue: {e}")

    # =========================================================================
    # STAGE 5 (MODULE 6): UNIFIED FINDINGS GENERATION & SOAR RESPONSE ENGINE
    # =========================================================================
    print("\n[STAGE 5/6 | MODULE 6] Generating Unified Security Findings & Automated Response Playbooks...")
    findings_json = out_dir / "security_findings.json"
    findings_csv = out_dir / "security_findings.csv"

    env_stage5 = {
        "FINDING_INPUT_FILE": str(anomaly_output),
        "OUTPUT_DIR": str(out_dir),
        "FINDINGS_JSON": str(findings_json),
        "FINDINGS_CSV": str(findings_csv)
    }
    cmd_stage5a = [
        sys.executable,
        str(BASE_DIR / "output" / "finding_writer.py"),
        "--input", str(anomaly_output),
        "--output-dir", str(out_dir)
    ]
    if not run_stage_command(cmd_stage5a, "Finding Writer", env_vars=env_stage5):
        return False

    # Merge CSPM + Module 3 Policy-as-Code + CISA KEV vulnerability findings
    if vuln_json.exists():
        env_stage5b = {
            "VULN_FINDINGS_FILE": str(vuln_json),
            "FINDINGS_JSON": str(findings_json),
            "FINDINGS_CSV": str(findings_csv),
            "OUTPUT_DIR": str(out_dir)
        }
        cmd_stage5b = [sys.executable, "-m", "vulnerability.merge_findings"]
        run_stage_command(cmd_stage5b, "Vulnerability & Policy-as-Code Finding Integration", env_vars=env_stage5b)

    # Response & Remediation Engine
    response_json = out_dir / "security_response_recommendations.json"
    response_csv = out_dir / "security_response_recommendations.csv"

    env_stage5c = {
        "RESPONSE_INPUT_FILE": str(findings_json),
        "OUTPUT_DIR": str(out_dir),
        "RESPONSE_JSON": str(response_json),
        "RESPONSE_CSV": str(response_csv)
    }
    cmd_stage5c = [sys.executable, "-m", "response.response_engine"]
    run_stage_command(cmd_stage5c, "Response & Remediation Engine", env_vars=env_stage5c)

    # =========================================================================
    # STAGE 6 (MODULE 7): DYNAMIC AESTHETIC DASHBOARD COMPILATION
    # =========================================================================
    if generate_dashboard:
        print("\n[STAGE 6/6 | MODULE 7] Compiling Dynamic 7-Module SOC & CSPM Dashboard...")
        dash_file = Path(dashboard_path) if dashboard_path else BASE_DIR / "dashboard.html"
        if not dash_file.is_absolute():
            dash_file = BASE_DIR / dash_file

        generate_dashboard_html(
            anomaly_csv_path=anomaly_output,
            findings_json_path=findings_json,
            response_json_path=response_json if response_json.exists() else None,
            vuln_json_path=vuln_json if vuln_json.exists() else None,
            output_html_path=dash_file,
            dataset_name=input_path.name
        )

    total_time = time.time() - start_total
    print("\n" + "=" * 80)
    print(f"   END-TO-END SECURITY PIPELINE SUCCESSFULLY COMPLETED IN {total_time:.2f}s")
    print("=" * 80)
    print(f"Output Directory  : {out_dir}")
    print(f"Anomaly CSV       : {anomaly_output}")
    print(f"Unified Findings  : {findings_csv}")
    if generate_dashboard:
        print(f"Interactive SOC UI: {dash_file}")
    print("=" * 80 + "\n")
    return {
        "success": True,
        "execution_time_seconds": round(total_time, 2),
        "output_dir": str(out_dir),
        "normalized_file": str(normalized_cache),
        "anomaly_file": str(anomaly_output),
        "findings_json": str(findings_json),
        "findings_csv": str(findings_csv),
        "response_json": str(response_json),
        "response_csv": str(response_csv),
        "vulnerability_json": str(vuln_json) if vuln_json.exists() else None,
        "dashboard_html": str(dash_file) if generate_dashboard else None
    }


def main():
    parser = argparse.ArgumentParser(
        description="AI Cloud Security Posture Management - Universal Analysis Pipeline",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--input", "-i",
        default="auto",
        help="Path to ANY input dataset (defaults to 500,000-event CloudTrail stream)"
    )
    parser.add_argument(
        "--cspm", "-c",
        default=None,
        help="Optional path to CSPM inventory (JSON or CSV)"
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=None,
        help="Custom directory to store analysis outputs (default: data/analyzed)"
    )
    parser.add_argument(
        "--max-rows", "-n",
        type=int,
        default=None,
        help="Optionally limit number of records to process for fast benchmarking"
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="Isolation Forest expected anomaly rate (default: 0.05)"
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Skip automatic HTML dashboard generation"
    )
    parser.add_argument(
        "--dashboard-path",
        default=None,
        help="Custom output path for dashboard.html"
    )

    args = parser.parse_args()

    success = run_pipeline(
        input_source=args.input,
        cspm_source=args.cspm,
        output_dir=args.output_dir,
        max_rows=args.max_rows,
        contamination=args.contamination,
        generate_dashboard=not args.no_dashboard,
        dashboard_path=args.dashboard_path
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
