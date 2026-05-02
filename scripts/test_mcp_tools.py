"""
Direct tool-call test for the MCP server functions.
Seeds Elasticsearch with synthetic attack history, then calls all 4 tools.

Run: python scripts/test_mcp_tools.py
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.agents.classification_agent.kibana_adapter import KibanaAdapter, KibanaConfig, ATTACK_HISTORY_INDEX
from src.agents.classification_agent.mcp_server import (
    check_ip_history,
    check_same_attack_type,
    count_recent_ip_attacks,
    compute_ip_reputation,
    _get_adapter,
)

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"


def check(label: str, condition: bool, detail: str = "") -> bool:
    tag = PASS if condition else FAIL
    print(f"{tag} {label}" + (f"  ({detail})" if detail else ""))
    return condition


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------
TEST_IP = "172.16.99.1"
TEST_TYPE = "PortScan"

SEED_DOCS = [
    # 5 PortScan attacks (3 in last 7 days)
    {"attack_type": "PortScan", "days_ago": 1},
    {"attack_type": "PortScan", "days_ago": 3},
    {"attack_type": "PortScan", "days_ago": 5},
    {"attack_type": "PortScan", "days_ago": 20},
    {"attack_type": "PortScan", "days_ago": 25},
    # 2 SYN Flood attacks (older)
    {"attack_type": "SYN Flood", "days_ago": 40},
    {"attack_type": "SYN Flood", "days_ago": 50},
]


def seed(client) -> None:
    print(f"\n{INFO} Seeding {len(SEED_DOCS)} synthetic attack records for {TEST_IP}...\n")
    for d in SEED_DOCS:
        ts = (datetime.now(timezone.utc) - timedelta(days=d["days_ago"])).isoformat()
        client.index(
            index=ATTACK_HISTORY_INDEX,
            document={
                "@timestamp":       ts,
                "src_ip":           TEST_IP,
                "attack_type":      d["attack_type"],
                "severity":         "high",
                "confidence":       0.92,
                "model_confidence": 0.90,
                "siem_confidence":  0.94,
                "decision_source":  "model+siem",
                "incident_id":      f"INC_SEED_{d['days_ago']:03d}",
            },
            refresh="wait_for",
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    adapter = _get_adapter()
    if not adapter.is_available():
        print(f"{FAIL} Elasticsearch not reachable — is Docker running?")
        sys.exit(1)

    seed(adapter._client)

    print(f"{INFO} Running tool checks...\n")

    # --- Tool 1: check_ip_history ---
    history = check_ip_history(TEST_IP)
    check("check_ip_history: count >= 7",      history["previous_attack_count"] >= 7,
          f"count={history['previous_attack_count']}")
    check("check_ip_history: first_seen set",   history["first_seen"] is not None)
    check("check_ip_history: last_seen set",    history["last_seen"] is not None)
    check("check_ip_history: PortScan in types", "PortScan" in history["attack_types"],
          f"types={history['attack_types']}")
    check("check_ip_history: SYN Flood in types","SYN Flood" in history["attack_types"])
    check("check_ip_history: recent_count >= 3", history["recent_attack_count"] >= 3,
          f"recent={history['recent_attack_count']}")

    print()

    # --- Tool 2: check_same_attack_type ---
    same = check_same_attack_type(TEST_IP, TEST_TYPE, days=30)
    check("check_same_attack_type: count >= 3", same["count"] >= 3,
          f"count={same['count']} (PortScan, 30d)")

    print()

    # --- Tool 3: count_recent_ip_attacks ---
    recent = count_recent_ip_attacks(TEST_IP, days=7)
    check("count_recent_ip_attacks: count >= 3", recent["count"] >= 3,
          f"count={recent['count']} (7d)")

    print()

    # --- Tool 4: compute_ip_reputation ---
    rep = compute_ip_reputation(TEST_IP, TEST_TYPE)
    score = rep["verification_score"]
    verdict = rep["verdict"]
    bd = rep["breakdown"]

    check("compute_ip_reputation: score is float",  isinstance(score, float))
    check("compute_ip_reputation: score in [0,1]",  0.0 <= score <= 1.0, f"score={score}")
    check("compute_ip_reputation: verdict set",     len(verdict) > 0, f"verdict={verdict!r}")
    check("compute_ip_reputation: ip_history_score > 0",      bd["ip_history_score"] > 0)
    check("compute_ip_reputation: same_attack_type_score > 0", bd["same_attack_type_score"] > 0)
    check("compute_ip_reputation: recent_recurrence_score > 0",bd["recent_recurrence_score"] > 0)

    print(f"\n{INFO} Full reputation result:")
    print(f"       IP:           {rep['ip']}")
    print(f"       Attack type:  {rep['attack_type']}")
    print(f"       Score:        {score}")
    print(f"       Verdict:      {verdict}")
    print(f"       Breakdown:    {bd}")
    print()


if __name__ == "__main__":
    main()
