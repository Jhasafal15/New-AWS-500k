"""
Base Rule definition for Cloud Misconfiguration Rule Engine.
Defines unified finding schema and compliance categories.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import List, Dict, Any

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class Category(str, Enum):
    IAM = "IAM Security"
    NETWORK = "Network Security"
    STORAGE = "Storage Security"
    COMPUTE = "Compute Security"

class BaseRule(ABC):
    def __init__(self, rule_id: str, rule_name: str, category: Category, severity: Severity, description: str):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.category = category.value
        self.severity = severity.value
        self.default_description = description

    def create_finding(
        self,
        resource_type: str,
        resource_id: str,
        description: str = None,
        severity: Severity = None,
        raw_config: Dict[str, Any] = None,
        custom_suffix: str = ""
    ) -> Dict[str, Any]:
        """Constructs a finding adhering strictly to the student data contract."""
        finding_id = f"{self.rule_id}_{custom_suffix}" if custom_suffix else self.rule_id
        return {
            "finding_id": finding_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "category": self.category,
            "rule_name": self.rule_name,
            "severity": (severity.value if severity else self.severity),
            "description": description or self.default_description,
            "raw_config": raw_config or {},
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        }

    @abstractmethod
    def evaluate(self, inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluates inventory data and returns list of findings."""
        pass
