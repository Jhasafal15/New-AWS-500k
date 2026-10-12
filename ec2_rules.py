"""
EC2 & Network Security Rules (CIS AWS Benchmark Section 4 & 5)
"""

import sys
import os
from typing import List, Dict, Any
try:
    from .base_rule import BaseRule, Category, Severity
except ImportError:
    try:
        from src.rules.base_rule import BaseRule, Category, Severity
    except ImportError:
        from base_rule import BaseRule, Category, Severity

class RuleEc2Ingress(BaseRule):
    """CIS AWS 5.2, 5.3: Ensure no security groups allow ingress from 0.0.0.0/0 to ports 22, 3389, or 8080."""
    def __init__(self):
        super().__init__(
            rule_id="RULE-NET-002",
            rule_name="Public Ingress Port Open to Internet",
            category=Category.NETWORK,
            severity=Severity.CRITICAL,
            description="Security group allows unrestricted ingress from 0.0.0.0/0 on sensitive administrative or application ports."
        )

    def evaluate(self, inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        instances = inventory.get("ec2_instances", [])

        for inst in instances:
            iid = inst.get("instance_id")
            rules = inst.get("security_group_rules", [])
            pub_ip = inst.get("public_ip")
            
            # Check individual open ports
            for rule in rules:
                if not rule.get("is_internet_open", False):
                    continue
                
                fport = rule.get("from_port")
                tport = rule.get("to_port")
                sg_id = rule.get("security_group_id", "sg-unknown")
                
                # Check 22 (SSH)
                if (fport is not None and fport <= 22 <= (tport or fport)):
                    findings.append({
                        "finding_id": f"RULE-NET-001_{iid}_port22",
                        "resource_type": "EC2_INSTANCE",
                        "resource_id": iid,
                        "category": Category.NETWORK.value,
                        "rule_name": "Public SSH Port Open to Internet",
                        "severity": Severity.CRITICAL.value,
                        "description": f"Security group {sg_id} allows inbound TCP port 22 from CIDR 0.0.0.0/0 on instance '{inst.get('name')}'.",
                        "raw_config": {
                            "public_ip": pub_ip,
                            "open_ports": inst.get("open_ports", []),
                            "security_group_id": sg_id,
                            "port": 22
                        },
                        "timestamp": inst.get("ami_creation_date") or "2026-09-26T12:00:00Z"
                    })

                # Check 3389 (RDP)
                if (fport is not None and fport <= 3389 <= (tport or fport)):
                    findings.append({
                        "finding_id": f"RULE-NET-002_{iid}_port3389",
                        "resource_type": "EC2_INSTANCE",
                        "resource_id": iid,
                        "category": Category.NETWORK.value,
                        "rule_name": "Public RDP Port Open to Internet",
                        "severity": Severity.CRITICAL.value,
                        "description": f"Security group {sg_id} allows inbound TCP port 3389 (Windows RDP) from CIDR 0.0.0.0/0 on instance '{inst.get('name')}'.",
                        "raw_config": {
                            "public_ip": pub_ip,
                            "open_ports": inst.get("open_ports", []),
                            "security_group_id": sg_id,
                            "port": 3389
                        },
                        "timestamp": inst.get("ami_creation_date") or "2026-09-26T12:00:00Z"
                    })

                # Check 8080 (Proxy / Alternative HTTP)
                if (fport is not None and fport <= 8080 <= (tport or fport)):
                    findings.append({
                        "finding_id": f"RULE-NET-003_{iid}_port8080",
                        "resource_type": "EC2_INSTANCE",
                        "resource_id": iid,
                        "category": Category.NETWORK.value,
                        "rule_name": "Public Alternative Web/Proxy Port 8080 Open",
                        "severity": Severity.HIGH.value,
                        "description": f"Security group {sg_id} allows inbound TCP port 8080 from CIDR 0.0.0.0/0 on instance '{inst.get('name')}'.",
                        "raw_config": {
                            "public_ip": pub_ip,
                            "open_ports": inst.get("open_ports", []),
                            "security_group_id": sg_id,
                            "port": 8080
                        },
                        "timestamp": inst.get("ami_creation_date") or "2026-09-26T12:00:00Z"
                    })

        # Deduplicate findings by finding_id
        seen = set()
        deduped = []
        for f in findings:
            if f["finding_id"] not in seen:
                seen.add(f["finding_id"])
                deduped.append(f)
        return deduped


class RuleEc2OutdatedAmi(BaseRule):
    """CIS AWS Compute: Ensure instances are running recently patched AMI images."""
    def __init__(self):
        super().__init__(
            rule_id="RULE-COMP-001",
            rule_name="EC2 Instance Running Outdated AMI",
            category=Category.COMPUTE,
            severity=Severity.MEDIUM,
            description="EC2 instance is running an outdated base AMI created more than 365 days ago."
        )

    def evaluate(self, inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        instances = inventory.get("ec2_instances", [])

        for inst in instances:
            if inst.get("is_outdated_ami", False):
                iid = inst.get("instance_id")
                findings.append(self.create_finding(
                    resource_type="EC2_INSTANCE",
                    resource_id=iid,
                    description=f"Instance '{inst.get('name')}' ({iid}) is running outdated AMI {inst.get('ami_id')} created on {inst.get('ami_creation_date')}.",
                    severity=Severity.MEDIUM,
                    raw_config={
                        "ami_id": inst.get("ami_id"),
                        "ami_creation_date": inst.get("ami_creation_date"),
                        "instance_type": inst.get("instance_type")
                    },
                    custom_suffix=iid
                ))
        return findings


class RuleEc2VulnerableSoftware(BaseRule):
    """Compute Security: Flags instances hosting software with known critical/high CVEs."""
    def __init__(self):
        super().__init__(
            rule_id="RULE-COMP-002",
            rule_name="Host Contains Known Vulnerable Software",
            category=Category.COMPUTE,
            severity=Severity.HIGH,
            description="Software packages installed on instance contain unpatched high or critical CVEs."
        )

    def evaluate(self, inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        instances = inventory.get("ec2_instances", [])

        for inst in instances:
            iid = inst.get("instance_id")
            vuln_pkgs = [p for p in inst.get("software_inventory", []) if p.get("is_vulnerable")]
            if vuln_pkgs:
                cisa_pkgs = [p for p in vuln_pkgs if p.get("cisa_known_exploited")]
                crit_pkgs = [p for p in vuln_pkgs if p.get("cve_severity") == "CRITICAL" or p.get("cisa_known_exploited")]
                severity = Severity.CRITICAL if crit_pkgs else Severity.HIGH
                pkg_names = [f"{p['software_name']} ({p['cve_id']})" for p in vuln_pkgs]

                cisa_note = " [ALERT: Actively Exploited in the Wild per CISA KEV Catalog]" if cisa_pkgs else ""
                findings.append(self.create_finding(
                    resource_type="EC2_INSTANCE",
                    resource_id=iid,
                    description=f"Host '{inst.get('name')}' contains {len(vuln_pkgs)} vulnerable packages: {', '.join(pkg_names)}.{cisa_note}",
                    severity=severity,
                    raw_config={
                        "vulnerable_packages": vuln_pkgs,
                        "cisa_exploited_count": len(cisa_pkgs),
                        "public_ip": inst.get("public_ip")
                    },
                    custom_suffix=iid
                ))
        return findings
