#!/usr/bin/env python3
"""
Project Packaging Utility for Collaboration
AI-Powered Cloud Security Posture Management

Bundles all code, modules, rules, models, launchers, and lightweight sample data
into a clean, shareable ZIP archive (e.g., < 5MB) suitable for sharing via Email,
Google Drive, Slack, Discord, or GitHub.

Excludes massive multi-hundred-megabyte synthetic data files and __pycache__.
"""

import os
import sys
import zipfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Items to ignore when packaging
EXCLUDE_DIRS = {
    "__pycache__",
    ".pytest_cache",
    ".git",
    ".vscode",
    ".idea",
    "_ARCHIVE"
}

EXCLUDE_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".DS_Store"
}

# Large files to skip in shareable mode (over 50MB)
LARGE_SYNTHETIC_FILES = {
    "synthetic_cloudtrail_500k.csv",
    "synthetic_cloudtrail_500k.jsonl",
    "train_cloudtrail.csv",
    "val_cloudtrail.csv",
    "test_cloudtrail.csv",
    "synthetic_llm_chatml.jsonl",
    "synthetic_llm_finetuning.jsonl",
    "synthetic_llm_huggingface.jsonl",
    "train_llm.jsonl",
    "val_llm.jsonl",
    "test_llm.jsonl",
    "iam_anomaly_analysis_500k.csv"
}


def package_project(zip_filename="CloudSecurity_MasterPipeline.zip", include_large_files=False):
    output_zip_path = BASE_DIR / zip_filename
    print("=" * 70)
    print("PACKAGING CLOUD SECURITY MASTER PIPELINE FOR SHARING")
    print("=" * 70)
    print(f"Target Zip Archive: {output_zip_path}")
    print(f"Include Large Data: {include_large_files}")
    print("-" * 70)

    total_files = 0
    total_bytes = 0

    with zipfile.ZipFile(output_zip_path, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for root, dirs, files in os.walk(BASE_DIR):
            # Prune excluded directories in-place
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

            for file in files:
                file_path = Path(root) / file
                
                # Skip the zip file itself
                if file_path == output_zip_path:
                    continue

                # Skip unwanted extensions
                if file_path.suffix.lower() in EXCLUDE_EXTENSIONS:
                    continue

                # Skip large synthetic files if not requested
                if not include_large_files and file in LARGE_SYNTHETIC_FILES:
                    continue

                rel_path = file_path.relative_to(BASE_DIR)
                
                # Add to zip
                zip_file.write(file_path, arcname=str(rel_path))
                total_files += 1
                total_bytes += file_path.stat().st_size

    zip_size_mb = output_zip_path.stat().st_size / (1024 * 1024)
    print(f"\n[SUCCESS] Packaged {total_files} files ({total_bytes / (1024*1024):.2f} MB uncompressed).")
    print(f"Zip Archive Created: {output_zip_path}")
    print(f"Zip Archive Size   : {zip_size_mb:.2f} MB")
    print("=" * 70)
    print("\nHow to send this to your friend:")
    print("  1. Send 'CloudSecurity_MasterPipeline.zip' via Google Drive, Email, or Slack.")
    print("  2. Your friend can unzip it and immediately run:")
    print("         pip install -r requirements.txt")
    print("         python run_analysis.py --input data/raw/cloudtrail_20260918_140538.json")
    print("  3. Check 'README.md' for full integration patterns.\n")
    return output_zip_path


if __name__ == "__main__":
    include_large = "--include-all-synthetic" in sys.argv
    package_project(include_large_files=include_large)
