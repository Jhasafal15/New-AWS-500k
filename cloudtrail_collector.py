import boto3
import json
import os
from datetime import datetime


def collect_cloudtrail_events(max_results=50):
    cloudtrail = boto3.client("cloudtrail", region_name="us-east-1")

    response = cloudtrail.lookup_events(
        MaxResults=max_results
    )

    events = response.get("Events", [])

    return events


def save_events(events):
    os.makedirs("data/raw", exist_ok=True)

    filename = datetime.now().strftime(
        "data/raw/cloudtrail_%Y%m%d_%H%M%S.json"
    )

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(events, file, indent=4, default=str)

    return filename


if __name__ == "__main__":
    print("Collecting CloudTrail events...")

    events = collect_cloudtrail_events()

    print(f"Events collected: {len(events)}")

    if events:
        filename = save_events(events)
        print(f"Saved to: {filename}")
    else:
        print("No CloudTrail events found.")