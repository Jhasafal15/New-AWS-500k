"""
Master Orchestrator for the Synthetic AWS CloudTrail Behavioral Security Dataset & LLM Suite.
Executes end-to-end generation, sequence correlation, CSPM synthesis, LLM fine-tuning dataset creation,
sequence-safe splitting, and automated validation.
"""

import sys
import time
import argparse
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from dataset_generator.config import (
    RANDOM_SEED,
    DEFAULT_ROW_COUNT,
    DEFAULT_LLM_EXAMPLE_COUNT,
    CLOUDTRAIL_CSV,
    CLOUDTRAIL_JSONL,
    CSPM_CSV,
    LLM_FINETUNING_JSONL,
    SYNTHETIC_DIR,
)
from dataset_generator.generate_cloudtrail_dataset import CloudTrailDatasetGenerator
from dataset_generator.generate_cspm_dataset import generate_cspm_inventory
from dataset_generator.correlate_and_derive import (
    derive_correlation_sequences,
    derive_security_findings_and_responses,
)
from dataset_generator.generate_llm_dataset import (
    LLMDatasetGenerator,
    convert_to_chatml,
    convert_to_huggingface_format,
)
from dataset_generator.splitters import (
    sequence_safe_split_dataframe,
    split_llm_jsonl,
)
from dataset_generator.validators import validate_and_report_dataset


def main():
    parser = argparse.ArgumentParser(
        description="Synthetic AWS CloudTrail Behavioral Security Dataset Generator"
    )
    parser.add_argument(
        "--rows",
        type=int,
        default=DEFAULT_ROW_COUNT,
        help=f"Total CloudTrail events to generate (default: {DEFAULT_ROW_COUNT:,})"
    )
    parser.add_argument(
        "--llm-examples",
        type=int,
        default=DEFAULT_LLM_EXAMPLE_COUNT,
        help=f"Total LLM fine-tuning examples to generate (default: {DEFAULT_LLM_EXAMPLE_COUNT:,})"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=RANDOM_SEED,
        help=f"Deterministic random seed (default: {RANDOM_SEED})"
    )
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="Skip LLM dataset generation"
    )

    args = parser.parse_args()

    start_time = time.time()
    print("=" * 76)
    print("   AI-POWERED CLOUD SECURITY POSTURE MANAGEMENT (CSPM)")
    print("  SYNTHETIC CLOUDTRAIL BEHAVIORAL DATASET & LLM GENERATOR")
    print("=" * 76)
    print(f"Target Event Count  : {args.rows:,}")
    print(f"Target LLM Examples : {args.llm_examples if not args.skip_llm else 0:,}")
    print(f"Random Seed         : {args.seed}")
    print(f"Output Directory    : {SYNTHETIC_DIR}")
    print("=" * 76)

    # --------------------------------------------------------
    # STEP 1: GENERATE CLOUDTRAIL 500K DATASET
    # --------------------------------------------------------
    print("\n>>> STEP 1: Generating 500,000-Row CloudTrail Dataset (CSV + JSONL)...")
    ct_generator = CloudTrailDatasetGenerator(total_rows=args.rows, seed=args.seed)
    df_ct = ct_generator.build_and_save()

    # --------------------------------------------------------
    # STEP 2: GENERATE CSPM VULNERABILITY INVENTORY
    # --------------------------------------------------------
    print("\n>>> STEP 2: Generating Linked CSPM Vulnerability Inventory...")
    df_cspm = generate_cspm_inventory(num_records=5000)

    # --------------------------------------------------------
    # STEP 3: CORRELATE SEQUENCES & DERIVE FINDINGS & RESPONSES
    # --------------------------------------------------------
    print("\n>>> STEP 3: Behavioral Correlation & Security Findings Derivation...")
    df_seq = derive_correlation_sequences(df_ct)
    df_findings, df_responses = derive_security_findings_and_responses(df_ct, df_cspm)

    # --------------------------------------------------------
    # STEP 4: SEQUENCE-SAFE TRAIN / VAL / TEST SPLIT
    # --------------------------------------------------------
    print("\n>>> STEP 4: Executing Sequence-Safe Data Splitting...")
    df_ct = sequence_safe_split_dataframe(df_ct)

    # Update CSV with split_set
    df_ct.to_csv(CLOUDTRAIL_CSV, index=False)

    # --------------------------------------------------------
    # STEP 5: GENERATE LLM FINE-TUNING DATASET
    # --------------------------------------------------------
    if not args.skip_llm:
        print("\n>>> STEP 5: Synthesizing Instruction Fine-Tuning Dataset...")
        llm_gen = LLMDatasetGenerator(df_ct, df_cspm, total_examples=args.llm_examples)
        llm_jsonl_path = llm_gen.generate_and_save()

        print("\n>>> STEP 5B: Splitting LLM Dataset (Sequence-Safe)...")
        split_llm_jsonl(llm_jsonl_path)

        print("\n>>> STEP 5C: Generating Alternative Model Formats (ChatML & Hugging Face)...")
        convert_to_chatml(llm_jsonl_path, SYNTHETIC_DIR / "synthetic_llm_chatml.jsonl")
        convert_to_huggingface_format(llm_jsonl_path, SYNTHETIC_DIR / "synthetic_llm_huggingface.jsonl")

    # --------------------------------------------------------
    # STEP 6: AUTOMATED VALIDATION & STATISTICS EXPORT
    # --------------------------------------------------------
    print("\n>>> STEP 6: Running Automated Validation & Metrics Engine...")
    stats = validate_and_report_dataset(
        df_ct,
        expected_rows=args.rows,
        llm_jsonl_path=LLM_FINETUNING_JSONL if not args.skip_llm else Path("missing")
    )

    elapsed = time.time() - start_time
    print("\n" + "=" * 76)
    print(f"ALL DELIVERABLES GENERATED & VALIDATED IN {elapsed:.2f} SECONDS!")
    print("=" * 76)


if __name__ == "__main__":
    main()
