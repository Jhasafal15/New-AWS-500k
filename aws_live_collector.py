"""Compatibility launcher for the corrected CSPM AWS collector."""
from .aws_vulnerability_collector import AWSLiveCollector, main

if __name__ == "__main__":
    raise SystemExit(main() or 0)
