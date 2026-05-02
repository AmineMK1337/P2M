"""
Quick connectivity + index verification test for Elasticsearch.
Run: python scripts/test_elasticsearch.py
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.agents.classification_agent.kibana_adapter import KibanaAdapter, KibanaConfig, FLOWS_INDEX, ATTACK_HISTORY_INDEX

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"


def check(label: str, condition: bool, detail: str = "") -> bool:
    tag = PASS if condition else FAIL
    msg = f"{tag} {label}"
    if detail:
        msg += f"  ({detail})"
    print(msg)
    return condition


def main():
    print(f"\n{INFO} Connecting to Elasticsearch at http://localhost:9200 ...\n")

    config = KibanaConfig()
    adapter = KibanaAdapter(config)

    # 1. Basic connectivity
    ok = check("Elasticsearch reachable", adapter.is_available())
    if not ok:
        print(f"\n{FAIL} Cannot connect — is Docker running?  Try: docker compose up -d\n")
        sys.exit(1)

    client = adapter._client

    # 2. Cluster health
    health = client.cluster.health()
    status = health.get("status", "unknown")
    check("Cluster health", status in ("green", "yellow"), f"status={status}")

    # 3. Check all three indices exist
    for index in (config.index, FLOWS_INDEX, ATTACK_HISTORY_INDEX):
        exists = bool(client.indices.exists(index=index))
        check(f"Index '{index}' exists", exists)

    # 4. Verify mappings on network_live_flows
    required_flow_fields = {
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "model_prediction", "predicted_attack_type", "confidence", "is_attack",
    }
    try:
        mapping = client.indices.get_mapping(index=FLOWS_INDEX)
        props = mapping[FLOWS_INDEX]["mappings"].get("properties", {})
        missing = required_flow_fields - props.keys()
        check(
            f"network_live_flows mappings complete",
            len(missing) == 0,
            f"missing: {missing}" if missing else "all fields present",
        )
    except Exception as exc:
        check("network_live_flows mappings", False, str(exc))

    # 5. Verify mappings on confirmed_attack_history
    required_history_fields = {"src_ip", "attack_type", "severity", "confidence", "incident_id"}
    try:
        mapping = client.indices.get_mapping(index=ATTACK_HISTORY_INDEX)
        props = mapping[ATTACK_HISTORY_INDEX]["mappings"].get("properties", {})
        missing = required_history_fields - props.keys()
        check(
            "confirmed_attack_history mappings complete",
            len(missing) == 0,
            f"missing: {missing}" if missing else "all fields present",
        )
    except Exception as exc:
        check("confirmed_attack_history mappings", False, str(exc))

    # 6. Write + read round-trip on confirmed_attack_history
    test_doc = {
        "@timestamp": "2026-05-02T12:00:00Z",
        "src_ip": "10.0.0.99",
        "attack_type": "PortScan",
        "severity": "high",
        "confidence": 0.95,
        "model_confidence": 0.93,
        "siem_confidence": 0.97,
        "decision_source": "model+siem",
        "incident_id": "INC_TEST0001",
    }
    try:
        client.index(index=ATTACK_HISTORY_INDEX, document=test_doc, refresh="wait_for")
        result = adapter.get_ip_history("10.0.0.99")
        check(
            "Round-trip write+read on confirmed_attack_history",
            result["previous_attack_count"] >= 1,
            f"count={result['previous_attack_count']}, types={result['attack_types']}",
        )
    except Exception as exc:
        check("Round-trip write+read", False, str(exc))

    # 7. Write + read round-trip on network_live_flows
    flow_doc = {
        "@timestamp": "2026-05-02T12:00:00Z",
        "src_ip": "10.0.0.99",
        "dst_ip": "192.168.1.1",
        "src_port": 51234,
        "dst_port": 80,
        "protocol": "TCP",
        "packets": 200,
        "bytes": 15000,
        "duration": 0.5,
        "model_prediction": "attack",
        "predicted_attack_type": "PortScan",
        "confidence": 0.95,
        "is_attack": True,
        "decision_source": "model+siem",
        "siem_alert_count": 3,
        "severity": "high",
        "source": "test",
    }
    try:
        client.index(index=FLOWS_INDEX, document=flow_doc, refresh="wait_for")
        resp = client.search(
            index=FLOWS_INDEX,
            body={"query": {"term": {"src_ip": "10.0.0.99"}}, "size": 1},
        )
        hit_count = resp["hits"]["total"]["value"]
        check("Round-trip write+read on network_live_flows", hit_count >= 1, f"hits={hit_count}")
    except Exception as exc:
        check("Round-trip write+read on network_live_flows", False, str(exc))

    print()


if __name__ == "__main__":
    main()
