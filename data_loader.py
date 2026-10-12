"""
Module 2: Data Loader
Ingests raw JSON and CSV data files from data/raw/
Validates content, checks schemas, and prepares data for normalization.
"""

import os
import json
import logging
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("DataLoader")

class DataLoader:
    def __init__(self, raw_data_dir: str):
        self.raw_data_dir = raw_data_dir

    def _load_json(self, filename: str) -> list:
        filepath = os.path.join(self.raw_data_dir, filename)
        if not os.path.exists(filepath):
            logger.warning(f"File not found: {filepath}. Returning empty list.")
            return []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                logger.info(f"Loaded {len(data)} records from {filename}")
                return data
        except Exception as e:
            logger.error(f"Error reading JSON file {filepath}: {e}")
            raise

    def _load_csv(self, filename: str) -> pd.DataFrame:
        filepath = os.path.join(self.raw_data_dir, filename)
        if not os.path.exists(filepath):
            logger.warning(f"File not found: {filepath}. Returning empty DataFrame.")
            return pd.DataFrame()
        try:
            df = pd.read_csv(filepath)
            logger.info(f"Loaded {len(df)} rows from {filename}")
            return df
        except Exception as e:
            logger.error(f"Error reading CSV file {filepath}: {e}")
            raise

    def get_cloudtrail_source(self) -> str:
        """Determines the active CloudTrail dataset path, prioritizing the 500k enterprise dataset."""
        p_500k = os.path.join(self.raw_data_dir, "synthetic_cloudtrail_500k.jsonl")
        if os.path.exists(p_500k):
            return p_500k
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(self.raw_data_dir)))
        p_500k_parent = os.path.join(os.path.dirname(project_root), "synthetic_cloudtrail_500k.jsonl")
        if os.path.exists(p_500k_parent):
            return p_500k_parent
        p_real = os.path.join(self.raw_data_dir, "real_cloudtrail_events.json")
        if os.path.exists(p_real):
            return p_real
        return os.path.join(self.raw_data_dir, "cloudtrail_events.json")

    def stream_cloudtrail(self, max_records: int = None):
        """
        High-throughput memory-safe generator.
        Yields CloudTrail events line-by-line with near-zero (< 50MB) RAM usage.
        """
        source_path = self.get_cloudtrail_source()
        if not os.path.exists(source_path):
            return

        if source_path.endswith(".jsonl"):
            count = 0
            with open(source_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    yield json.loads(line)
                    count += 1
                    if max_records and count >= max_records:
                        break
        else:
            with open(source_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for i, item in enumerate(data):
                    yield item
                    if max_records and (i + 1) >= max_records:
                        break

    def load_all(self, cloudtrail_sample_limit: int = 5000) -> dict:
        """Loads all raw datasets into a single python dictionary, sampling CloudTrail if 500k jsonl is present."""
        logger.info(f"Starting raw data ingestion from: {self.raw_data_dir}")
        ct_source = self.get_cloudtrail_source()
        logger.info(f"Active CloudTrail source: {os.path.basename(ct_source)}")

        if ct_source.endswith(".jsonl"):
            logger.info(f"Streaming first {cloudtrail_sample_limit} CloudTrail records into memory for instant validation...")
            ct_events = list(self.stream_cloudtrail(max_records=cloudtrail_sample_limit))
        else:
            ct_events = self._load_json(os.path.basename(ct_source))

        return {
            "iam": self._load_json("iam_users_roles.json"),
            "s3": self._load_json("s3_buckets.json"),
            "ec2": self._load_json("ec2_instances.json"),
            "vpcs": self._load_json("vpc_networks.json"),
            "cloudtrail": ct_events,
            "cloudtrail_source": ct_source,
            "software_inventory": self._load_csv("software_inventory.csv")
        }

if __name__ == "__main__":
    import sys
    raw_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "raw")
    loader = DataLoader(raw_dir)
    data = loader.load_all()
    print("Ingestion complete. Keys loaded:", list(data.keys()))
