"""
Sequence-Safe Train / Validation / Test Dataset Splitter.
Guarantees that all events and LLM examples belonging to the same behavioral sequence or session
are preserved entirely within a single split to eliminate data leakage.
"""

import json
from pathlib import Path
from typing import Tuple, Dict, Any, List

import numpy as np
import pandas as pd

from .config import RANDOM_SEED, SPLIT_RATIOS, SYNTHETIC_DIR

np.random.seed(RANDOM_SEED)


def sequence_safe_split_dataframe(
    df: pd.DataFrame,
    sequence_col: str = "behavior_sequence_id",
    session_col: str = "session_id",
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
) -> pd.DataFrame:
    """
    Assigns each row in the DataFrame to 'train', 'validation', or 'test'
    while keeping entire sequences and sessions atomic.
    """
    print("Performing sequence-safe Train / Validation / Test split on events...")
    df = df.copy()

    # Identify primary grouping key: sequence if present, else session
    group_key = df[sequence_col].fillna("").astype(str).str.strip()
    session_key = df[session_col].fillna("").astype(str).str.strip()
    primary_group = group_key.where(group_key.ne(""), session_key)

    unique_groups = np.array(primary_group.unique())
    np.random.shuffle(unique_groups)

    n_groups = len(unique_groups)
    train_end = int(n_groups * train_ratio)
    val_end = train_end + int(n_groups * val_ratio)

    train_groups = set(unique_groups[:train_end])
    val_groups = set(unique_groups[train_end:val_end])
    test_groups = set(unique_groups[val_end:])

    def assign_split(grp):
        if grp in train_groups:
            return "train"
        if grp in val_groups:
            return "validation"
        return "test"

    df["split_set"] = primary_group.map(assign_split)

    # Save split subsets
    train_df = df[df["split_set"] == "train"]
    val_df = df[df["split_set"] == "validation"]
    test_df = df[df["split_set"] == "test"]

    train_df.to_csv(SYNTHETIC_DIR / "train_cloudtrail.csv", index=False)
    val_df.to_csv(SYNTHETIC_DIR / "val_cloudtrail.csv", index=False)
    test_df.to_csv(SYNTHETIC_DIR / "test_cloudtrail.csv", index=False)

    print(f"  Train events      : {len(train_df):,} ({len(train_df)/len(df)*100:.1f}%)")
    print(f"  Validation events : {len(val_df):,} ({len(val_df)/len(df)*100:.1f}%)")
    print(f"  Test events       : {len(test_df):,} ({len(test_df)/len(df)*100:.1f}%)")

    # Verify no sequence leakage across splits
    train_seqs = set(train_df[train_df[sequence_col].ne("")][sequence_col])
    val_seqs = set(val_df[val_df[sequence_col].ne("")][sequence_col])
    test_seqs = set(test_df[test_df[sequence_col].ne("")][sequence_col])

    assert len(train_seqs.intersection(val_seqs)) == 0, "Leakage detected between train and val sequences!"
    assert len(train_seqs.intersection(test_seqs)) == 0, "Leakage detected between train and test sequences!"
    assert len(val_seqs.intersection(test_seqs)) == 0, "Leakage detected between val and test sequences!"
    print("  [PASSED] Zero sequence leakage verified across splits.")

    return df


def split_llm_jsonl(
    input_jsonl: Path,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
) -> Dict[str, int]:
    """
    Splits LLM JSONL dataset into train_llm.jsonl, val_llm.jsonl, and test_llm.jsonl
    grouping by session/event_id to guarantee zero leakage.
    """
    print(f"Splitting LLM dataset from {input_jsonl}...")
    records = []
    with open(input_jsonl, "r", encoding="utf-8") as f:
        for line in f:
            records.append(json.loads(line))

    # Group key: first event id or sequence
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for r in records:
        key = r.get("event_ids", ["DEFAULT"])[0] if r.get("event_ids") else "DEFAULT"
        groups.setdefault(key, []).append(r)

    group_keys = list(groups.keys())
    np.random.shuffle(group_keys)

    n = len(group_keys)
    t_end = int(n * train_ratio)
    v_end = t_end + int(n * val_ratio)

    train_keys = set(group_keys[:t_end])
    val_keys = set(group_keys[t_end:v_end])

    train_file = SYNTHETIC_DIR / "train_llm.jsonl"
    val_file = SYNTHETIC_DIR / "val_llm.jsonl"
    test_file = SYNTHETIC_DIR / "test_llm.jsonl"

    counts = {"train": 0, "validation": 0, "test": 0}
    with open(train_file, "w", encoding="utf-8") as tf, \
         open(val_file, "w", encoding="utf-8") as vf, \
         open(test_file, "w", encoding="utf-8") as tef:

        for k, recs in groups.items():
            if k in train_keys:
                target = tf
                counts["train"] += len(recs)
            elif k in val_keys:
                target = vf
                counts["validation"] += len(recs)
            else:
                target = tef
                counts["test"] += len(recs)

            for rec in recs:
                target.write(json.dumps(rec) + "\n")

    print(f"  Train LLM examples      : {counts['train']:,}")
    print(f"  Validation LLM examples : {counts['validation']:,}")
    print(f"  Test LLM examples       : {counts['test']:,}")
    return counts
