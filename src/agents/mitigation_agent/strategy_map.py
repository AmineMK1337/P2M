"""
Mitigation strategy map for the ANDS MitigationAgent.

Each key matches ClassificationResult.mitigation_attack_type exactly.
Each value is an ordered list of tool names — most targeted first,
alert_soc always last as a guaranteed audit trail.

For high-confidence DDoS (>=HIGH_CONFIDENCE_THRESHOLD) a more
aggressive override is used: skip rate-limiting, go straight to block.
"""

HIGH_CONFIDENCE_THRESHOLD = 0.85

STRATEGIES: dict[str, list[str]] = {
    "DDoS":        ["rate_limit_ip", "block_ip", "null_route_ip", "alert_soc"],
    "PortScan":    ["block_ip", "alert_soc"],
    "BruteForce":  ["throttle_connections", "block_ip", "alert_soc"],
    "Botnet":      ["block_ip", "quarantine_host", "alert_soc"],
    "Web Attack":  ["block_ip", "alert_soc"],
    "Infiltration":["isolate_host", "block_ip", "alert_soc"],
    "Intrusion":   ["block_ip", "alert_soc"],   # generic fallback for PCA output
    "BENIGN":      [],
}

_HIGH_CONF_OVERRIDES: dict[str, list[str]] = {
    "DDoS": ["block_ip", "null_route_ip", "alert_soc"],
}


def get_strategies(attack_type: str, confidence: float) -> list[str]:
    """
    Return the ordered list of tool names to execute for a given
    attack type and confidence score.
    Falls back to ["alert_soc"] for unknown attack types.
    """
    if attack_type == "BENIGN":
        return []

    if confidence >= HIGH_CONFIDENCE_THRESHOLD and attack_type in _HIGH_CONF_OVERRIDES:
        return _HIGH_CONF_OVERRIDES[attack_type]

    return STRATEGIES.get(attack_type, ["alert_soc"])