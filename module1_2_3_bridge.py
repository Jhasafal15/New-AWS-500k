"""
Module 1, 2, & 3 Integration Bridge for CloudSecurity_MasterPipeline.

Self-contained bridge (100% portable across any machine/OS with zero hardcoded user paths)
that executes and connects:
  - Module 1: Multi-Service Cloud Security Data Sources (AWS IAM, S3, EC2, VPC, Software Inventory,
              500k CloudTrail JSONL Stream, and CISA Known Exploited Vulnerabilities Catalog)
  - Module 2: Streaming Data Collection, Normalization & Asset Graph Layer (DataLoader +
              CloudDataNormalizer -> cloud_inventory.json + cloudtrail_500k_analytics.json)
  - Module 3: Policy-as-Code Security Analysis Engine (CloudSecurityScanner -> rule_findings.json)

into Modules 4, 5, 6, and 7 of CloudSecurity_MasterPipeline.
"""

import csv
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Any

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


RECOMMENDATION_MAP = {
    "Root or Admin User Missing MFA": (
        "Enforce hardware or virtual MFA immediately via IAM policy condition "
        "'aws:MultiFactorAuthPresent': 'true' and revoke active sessions."
    ),
    "Overly Permissive Wildcard Administrator Access": (
        "Detach AdministratorAccess / wildcard ('*') inline policies and replace with "
        "least-privilege scoped IAM permissions."
    ),
    "Unused Credentials Exceeding 90 Days": (
        "Deactivate and rotate IAM access keys older than 90 days using "
        "'aws iam update-access-key --status Inactive'."
    ),
    "S3 Bucket Publicly Accessible": (
        "Enable S3 Block Public Access at the bucket and account level and "
        "remove public ACLs/bucket policies."
    ),
    "S3 Bucket Missing Default Encryption": (
        "Enable default Server-Side Encryption with AWS KMS (SSE-KMS) or AES-256 (SSE-S3) "
        "and enforce HTTPS-only transport."
    ),
    "S3 Bucket Versioning Disabled": (
        "Enable S3 Object Versioning and MFA Delete on the bucket to protect against "
        "ransomware and accidental deletion."
    ),
    "Public SSH Port Open to Internet": (
        "Revoke unrestricted 0.0.0.0/0 ingress rules on SSH (port 22); "
        "restrict access to bastion/VPN CIDR blocks or AWS Systems Manager Session Manager."
    ),
    "Public RDP Port Open to Internet": (
        "Revoke unrestricted 0.0.0.0/0 ingress rules on RDP (port 3389); "
        "enforce VPN or AWS Fleet Manager access."
    ),
    "Public Alternative Web/Proxy Port 8080 Open": (
        "Restrict port 8080 ingress to internal ALB/VPC security groups only."
    ),
    "Host Contains Known Vulnerable Software": (
        "Isolate affected EC2 instance immediately, apply vendor security patch for the CISA KEV CVE, "
        "and rotate any instance profile credentials exposed on the host."
    ),
    "EC2 Instance Running Outdated AMI": (
        "Rebuild EC2 instance from a hardened, patched Golden AMI and decommission the legacy image."
    ),
}


def map_rule_id(finding_id: str, rule_name: str, category: str) -> str:
    """Derive a clean canonical rule_id from Module 3 finding metadata."""
    fid = str(finding_id or "")
    if "KEV" in fid or "Vulnerable Software" in rule_name:
        return "KEV-001"
    if "Outdated AMI" in rule_name:
        return "EC2-002"
    if "MFA" in rule_name and "Assumed Role" not in rule_name:
        return "IAM-001"
    if "Wildcard Administrator" in rule_name:
        return "IAM-002"
    if "Unused Credentials" in rule_name or "90 Days" in rule_name:
        return "IAM-003"
    if "Publicly Accessible" in rule_name and "S3" in rule_name:
        return "S3-001"
    if "Missing Default Encryption" in rule_name and "S3" in rule_name:
        return "S3-002"
    if "Versioning Disabled" in rule_name and "S3" in rule_name:
        return "S3-003"
    if "SSH" in rule_name or "RDP" in rule_name or "8080" in rule_name or "Network Security" in category:
        return "EC2-001"
    if any(
        k in rule_name
        for k in (
            "Unauthorized Sensitive Operation",
            "Abnormal Access Key",
            "Privilege Escalation Attempt",
            "CloudTrail Service Access",
            "Assumed Role Session Without Multi-Factor",
        )
    ):
        return "CT-RULE"
    if fid.startswith("RULE-"):
        return fid.split("_")[0].replace("RULE-", "")
    return "CSPM-M3"


def convert_module3_finding(raw_f: Dict[str, Any], index: int) -> Dict[str, Any]:
    """Convert a Module 3 Policy-as-Code finding into MasterPipeline's canonical vulnerability schema."""
    raw_id = str(raw_f.get("finding_id", f"M3-{index:04d}"))
    rule_name = str(raw_f.get("rule_name", "Policy-as-Code Security Violation"))
    category = str(raw_f.get("category", "CSPM Posture"))
    severity = str(raw_f.get("severity", "HIGH")).upper()
    resource_id = str(raw_f.get("resource_id", "unknown-resource"))
    resource_type = str(raw_f.get("resource_type", "cloud_asset")).lower()
    raw_cfg = raw_f.get("raw_config", {})

    resource_name = resource_id.split("/")[-1].split(":")[-1] if resource_id else f"asset-{index}"
    rule_id = map_rule_id(raw_id, rule_name, category)

    if rule_id == "CT-RULE" or "cloudtrail" in resource_type:
        service = "cloudtrail"
    elif "iam" in resource_type or "IAM" in category:
        service = "iam"
    elif "s3" in resource_type or "Storage" in category:
        service = "s3"
    elif "ec2" in resource_type or "Network" in category or "Compute" in category:
        service = "ec2"
    else:
        service = "aws"

    account_id = "134604497614" if "134604497614" in resource_id else "123456789012"
    region = raw_cfg.get("region", "us-east-1") if isinstance(raw_cfg, dict) else "us-east-1"

    recommendation = RECOMMENDATION_MAP.get(
        rule_name,
        "Investigate the affected cloud resource, enforce least-privilege posture, and remediate via IaC."
    )

    return {
        "finding_id": raw_id,
        "rule_id": rule_id,
        "finding_name": rule_name,
        "category": category,
        "severity": severity,
        "resource_id": resource_id,
        "resource_type": resource_type,
        "resource_name": resource_name,
        "service": service,
        "account_id": account_id,
        "region": region,
        "description": raw_f.get("description", rule_name),
        "evidence": raw_cfg if isinstance(raw_cfg, dict) else {"raw": str(raw_cfg)},
        "recommendation": recommendation,
        "source_module": "Module_1_2_3_CSPM_KEV_Engine",
    }


def integrate_modules_1_2_3(output_dir: Path = None, run_m13_scanner: bool = True) -> Dict[str, Any]:
    """
    Execute Modules 1, 2, & 3 inside CloudSecurity_MasterPipeline (using relative paths)
    and merge the resulting 149 Policy-as-Code + CISA KEV findings into vulnerability_findings.json/csv.
    """
    if output_dir is None:
        output_dir = BASE_DIR / "data" / "analyzed"
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    raw_dir = BASE_DIR / "data" / "raw"
    processed_dir = BASE_DIR / "data" / "processed"
    processed_dir.mkdir(parents=True, exist_ok=True)

    # Run Student 1's Module 1, 2, 3 pipeline (DataLoader -> CloudDataNormalizer -> CloudSecurityScanner)
    if run_m13_scanner and (BASE_DIR / "run_pipeline.py").exists():
        try:
            from run_pipeline import run_pipeline as run_m13_pipeline
            run_m13_pipeline(
                generate_data=False,
                raw_dir=str(raw_dir),
                processed_dir=str(processed_dir),
            )
        except Exception as e:
            print(f"[WARN] Module 1-3 direct execution fallback: {e}")

    inv_src = processed_dir / "cloud_inventory.json"
    if not inv_src.exists():
        inv_src = processed_dir / "module1_3_cloud_inventory.json"

    analytics_src = processed_dir / "cloudtrail_500k_analytics.json"
    rules_src = processed_dir / "rule_findings.json"
    if not rules_src.exists():
        rules_src = processed_dir / "module1_3_rule_findings.json"

    summary = {
        "module1_3_found": False,
        "assets_loaded": 0,
        "module3_findings_loaded": 0,
        "kev_findings_count": 0,
        "iam_posture_findings": 0,
        "s3_posture_findings": 0,
        "ec2_network_findings": 0,
        "cloudtrail_policy_findings": 0,
        "combined_vulnerability_findings": 0,
    }

    if not rules_src.exists():
        print(f"[INFO] Module 1-3 findings not found at {rules_src}; skipping Module 1-3 bridge.")
        return summary

    summary["module1_3_found"] = True

    if inv_src.exists():
        dst_inv = processed_dir / "module1_3_cloud_inventory.json"
        if inv_src.resolve() != dst_inv.resolve():
            shutil.copy2(inv_src, dst_inv)
        try:
            inv_data = json.loads(inv_src.read_text(encoding="utf-8"))
            summary["assets_loaded"] = inv_data.get("metadata", {}).get(
                "total_resources",
                len(inv_data.get("iam_users", []))
                + len(inv_data.get("iam_roles", []))
                + len(inv_data.get("s3_buckets", []))
                + len(inv_data.get("ec2_instances", []))
                + len(inv_data.get("vpcs", [])),
            )
        except Exception:
            pass

    if analytics_src.exists():
        shutil.copy2(analytics_src, output_dir / "cloudtrail_500k_analytics.json")

    dst_rules = processed_dir / "module1_3_rule_findings.json"
    if rules_src.resolve() != dst_rules.resolve():
        shutil.copy2(rules_src, dst_rules)

    # Load Module 3 Policy-as-Code + CISA KEV findings
    raw_m3_findings = json.loads(rules_src.read_text(encoding="utf-8"))
    if isinstance(raw_m3_findings, dict):
        raw_m3_findings = raw_m3_findings.get("findings", [])

    converted_m3 = []
    for idx, rf in enumerate(raw_m3_findings, 1):
        cf = convert_module3_finding(rf, idx)
        converted_m3.append(cf)
        rid = cf["rule_id"]
        if rid == "KEV-001":
            summary["kev_findings_count"] += 1
        elif rid == "CT-RULE":
            summary["cloudtrail_policy_findings"] += 1
        elif rid.startswith("IAM-"):
            summary["iam_posture_findings"] += 1
        elif rid.startswith("S3-"):
            summary["s3_posture_findings"] += 1
        elif rid.startswith("EC2-"):
            summary["ec2_network_findings"] += 1

    summary["module3_findings_loaded"] = len(converted_m3)

    # Merge with existing vulnerability_findings.json (from Stage 4 live AWS posture engine)
    vuln_json_path = output_dir / "vulnerability_findings.json"
    vuln_csv_path = output_dir / "vulnerability_findings.csv"

    existing_vulns = []
    scan_ts = "2026-10-11T00:00:00Z"
    if vuln_json_path.exists():
        try:
            vdata = json.loads(vuln_json_path.read_text(encoding="utf-8"))
            if isinstance(vdata, dict):
                existing_vulns = [
                    f for f in vdata.get("findings", [])
                    if f.get("source_module") != "Module_1_2_3_CSPM_KEV_Engine"
                ]
                scan_ts = vdata.get("generated_at") or scan_ts
            elif isinstance(vdata, list):
                existing_vulns = [
                    f for f in vdata
                    if f.get("source_module") != "Module_1_2_3_CSPM_KEV_Engine"
                ]
        except Exception:
            existing_vulns = []

    seen_ids = {f.get("finding_id") for f in existing_vulns if f.get("finding_id")}
    merged_vulns = list(existing_vulns)
    for cf in converted_m3:
        if cf["finding_id"] not in seen_ids:
            merged_vulns.append(cf)
            seen_ids.add(cf["finding_id"])

    summary["combined_vulnerability_findings"] = len(merged_vulns)

    payload = {
        "generated_at": scan_ts,
        "inventory_sources": [
            str(BASE_DIR / "data" / "raw" / "aws_vulnerability_inventory.json"),
            str(inv_src),
        ],
        "module1_3_assets_evaluated": summary["assets_loaded"],
        "live_aws_findings_count": len(existing_vulns),
        "module3_policy_kev_findings_count": len(converted_m3),
        "total_findings": len(merged_vulns),
        "findings": merged_vulns,
    }
    vuln_json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    fields = [
        "finding_id", "rule_id", "finding_name", "category", "severity",
        "resource_id", "resource_type", "resource_name", "service",
        "account_id", "region", "description", "evidence", "recommendation"
    ]
    with vuln_csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for finding in merged_vulns:
            row = dict(finding)
            row["evidence"] = json.dumps(row.get("evidence", {}), default=str)
            writer.writerow(row)

    print("=" * 72)
    print("MODULE 1, 2, & 3 INTEGRATION BRIDGE (CSPM + CISA KEV + 500K STREAM)")
    print("=" * 72)
    print(f"Module 1-2 Normalized Cloud Assets : {summary['assets_loaded']}")
    print(f"Module 3 Policy-as-Code Findings   : {summary['module3_findings_loaded']}")
    print(f"  - IAM Posture Violations         : {summary['iam_posture_findings']}")
    print(f"  - S3 Storage Violations          : {summary['s3_posture_findings']}")
    print(f"  - EC2 / Network & AMI Exposure   : {summary['ec2_network_findings']}")
    print(f"  - CISA KEV Active Exploits       : {summary['kev_findings_count']}")
    print(f"  - CloudTrail Stream Threat Rules : {summary['cloudtrail_policy_findings']}")
    print(f"Friend's Live AWS Posture Findings : {len(existing_vulns)}")
    print(f"Combined CSPM/Vulnerability Total  : {summary['combined_vulnerability_findings']}")
    print("=" * 72)

    return summary


if __name__ == "__main__":
    integrate_modules_1_2_3()
