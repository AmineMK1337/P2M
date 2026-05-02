"""
Shared data schemas for ANDS agents.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

import pandas as pd


@dataclass
class FlowRecord:
    """A single network flow record."""

    features: dict[str, Any]
    source: str = "unknown"
    raw_row: Optional[pd.Series] = None

    def to_dataframe(self) -> pd.DataFrame:
        return pd.DataFrame([self.features])

    @property
    def src_ip(self) -> Optional[str]:
        for key in ("Src IP", " Src IP", "src_ip", "Source IP", "src"):
            if key in self.features and self.features[key] is not None:
                return str(self.features[key])
        return None


@dataclass
class SIEMAlert:
    """A single historical alert retrieved from Kibana/Elasticsearch."""

    src_ip: str
    attack_type: str
    confidence: float
    timestamp: datetime
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ClassificationResult:
    """Output of the fused Detection + Classification Agent."""

    flow: FlowRecord
    is_attack: bool
    attack_type: str
    confidence: float
    model_confidence: float
    siem_confidence: float
    siem_alert_count: int
    decision_source: str
    agent: str = "DetectionClassificationAgent"
    metadata: dict[str, Any] = field(default_factory=dict)
    severity: str = "medium"
    mitigation_actions: list[str] = field(default_factory=list)
    mitigated: bool = False
    mitigation_status: str = "pending"
    
    # Reasoning and acting fields
    reasoning: str = ""
    recommended_actions: list[str] = field(default_factory=list)
    reasoning_details: dict[str, Any] = field(default_factory=dict)

    # Verification layer — populated by VerificationAgent
    verification_score: float = 0.0    # 0.0 = not verified / benign
    verification_verdict: str = ""     # empty = not verified

    @property
    def src_ip(self) -> str:
        """Convenience accessor for mitigation consumers."""
        return self.flow.src_ip or "unknown"

    @property
    def mitigation_attack_type(self) -> str:
        """Canonical attack type key used by mitigation strategy maps."""
        attack = (self.attack_type or "").strip().lower()
        aliases = {
            "intrusion": "DDoS",
            "ddos": "DDoS",
            "portscan": "PortScan",
            "port scan": "PortScan",
            "bruteforce": "BruteForce",
            "brute force": "BruteForce",
            "botnet": "Botnet",
            "web attack": "Web Attack",
            "webattack": "Web Attack",
            "infiltration": "Infiltration",
            "benign": "BENIGN",
        }
        return aliases.get(attack, self.attack_type)
