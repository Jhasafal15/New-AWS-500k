"""
Merge vulnerability findings into the existing security finding outputs.

This adapter intentionally runs AFTER output/finding_writer.py because the
existing finding writer owns security_findings.json/csv.
"""

import csv
import json
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
VULN_FILE = Path(os.getenv("VULN_FINDINGS_FILE", BASE_DIR / "data" / "analyzed" / "vulnerability_findings.json"))
SECURITY_JSON = Path(os.getenv("FINDINGS_JSON", BASE_DIR / "data" / "analyzed" / "security_findings.json"))
SECURITY_CSV = Path(os.getenv("FINDINGS_CSV", BASE_DIR / "data" / "analyzed" / "security_findings.csv"))


def load_list(path):
    with open(path, "r", encoding="utf-8") as file:
        data = json.load(file)

    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("findings", "security_findings", "data"):
            if isinstance(data.get(key), list):
                return data[key]
    return [data] if isinstance(data, dict) else []


def normalize_vulnerability_finding(finding, index):
    severity = str(finding.get("severity", "MEDIUM")).upper()

    # A deterministic severity-to-score mapping keeps the existing response
    # engine compatible without pretending to have a CVSS score when one was
    # not supplied by the evidence source.
    score_map = {
        "LOW": 25.0,
        "MEDIUM": 50.0,
        "HIGH": 75.0,
        "CRITICAL": 95.0,
    }

    evidence = finding.get("evidence", {})
    evidence_text = json.dumps(evidence, default=str)

    return {
        "finding_id": finding.get("finding_id", f"VULN-{index:04d}"),
        "finding_type": "Vulnerability / CSPM Finding",
        "event_name": finding.get("finding_name", "Vulnerability Finding"),
        "severity": severity,
        "final_risk_score": score_map.get(severity, 50.0),
        "final_risk_level": severity,
        "risk_level": severity,
        "category": finding.get("category", "Vulnerability Management"),
        "resource_id": finding.get("resource_id"),
        "resource_type": finding.get("resource_type"),
        "resource_name": finding.get("resource_name"),
        "user_name": finding.get("resource_name") or finding.get("resource_id") or "aws-resource",
        "service": finding.get("service"),
        "account_id": finding.get("account_id"),
        "region": finding.get("region"),
        "rule_id": finding.get("rule_id"),
        "description": finding.get("description"),
        "reason": (
            f"{finding.get('finding_name', 'Vulnerability finding')}; "
            f"Evidence: {evidence_text}"
        ),
        "risk_reasons": (
            f"{finding.get('finding_name', 'Vulnerability finding')}; "
            f"Evidence: {evidence_text}"
        ),
        "recommendation": finding.get("recommendation"),
        "action": finding.get("recommendation"),
        "evidence": evidence,
        "source_module": finding.get("source_module", "vulnerability_analysis"),
    }


def main():
    if not VULN_FILE.exists():
        raise FileNotFoundError(f"Missing vulnerability findings: {VULN_FILE}")
    if not SECURITY_JSON.exists():
        raise FileNotFoundError(f"Missing security findings: {SECURITY_JSON}")

    behavioral_findings = [
        f for f in load_list(SECURITY_JSON)
        if f.get("finding_type") != "Vulnerability / CSPM Finding"
    ]
    vulnerability_findings = load_list(VULN_FILE)

    normalized = [
        normalize_vulnerability_finding(item, index)
        for index, item in enumerate(vulnerability_findings, 1)
    ]

    combined = behavioral_findings + normalized

    payload = {
        "total_findings": len(combined),
        "behavioral_findings": len(behavioral_findings),
        "vulnerability_findings": len(normalized),
        "findings": combined,
    }

    with open(SECURITY_JSON, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, default=str)

    # Write a union of all keys so behavioral and vulnerability findings can
    # coexist in one CSV without dropping fields.
    fieldnames = []
    for item in combined:
        for key in item:
            if key not in fieldnames:
                fieldnames.append(key)

    with open(SECURITY_CSV, "w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for item in combined:
            row = {}
            for key in fieldnames:
                value = item.get(key, "")
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, default=str)
                row[key] = value
            writer.writerow(row)

    print("=" * 70)
    print("SECURITY FINDING INTEGRATION")
    print("=" * 70)
    print(f"Behavioral findings : {len(behavioral_findings)}")
    print(f"Vulnerability findings: {len(normalized)}")
    print(f"Combined findings   : {len(combined)}")
    print("Updated security_findings.json and security_findings.csv")


if __name__ == "__main__":
    main()
