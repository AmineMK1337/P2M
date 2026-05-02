"""
End-to-end test for the VerificationAgent.

Creates a synthetic ClassificationResult (as if the ML model detected an attack),
seeds Elasticsearch with history for the source IP, runs the agent, and asserts
that verification_score / verdict / severity / recommended_actions are correct.

Run: python scripts/test_verification_agent.py
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.shared.schemas import ClassificationResult, FlowRecord
from src.agents.classification_agent.kibana_adapter import KibanaAdapter, KibanaConfig, ATTACK_HISTORY_INDEX
from src.agents.classification_agent.verification_agent import VerificationAgent

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"


def check(label: str, condition: bool, detail: str = "") -> bool:
    tag = PASS if condition else FAIL
    print(f"{tag} {label}" + (f"  ({detail})" if detail else ""))
    return condition


def make_result(src_ip: str, attack_type: str) -> ClassificationResult:
    flow = FlowRecord(features={"Src IP": src_ip, "Dst IP": "10.0.0.1"}, source="test")
    return ClassificationResult(
        flow=flow,
        is_attack=True,
        attack_type=attack_type,
        confidence=0.91,
        model_confidence=0.91,
        siem_confidence=0.0,
        siem_alert_count=0,
        decision_source="model",
        reasoning="Classified as PortScan based on PCA anomaly detection.",
        recommended_actions=["block_immediately", "log_for_investigation"],
        severity="medium",
    )


def seed(client, ip: str, docs: list[dict]) -> None:
    for d in docs:
        ts = (datetime.now(timezone.utc) - timedelta(days=d["days_ago"])).isoformat()
        client.index(
            index=ATTACK_HISTORY_INDEX,
            document={
                "@timestamp":       ts,
                "src_ip":           ip,
                "attack_type":      d["attack_type"],
                "severity":         "high",
                "confidence":       0.92,
                "model_confidence": 0.90,
                "siem_confidence":  0.94,
                "decision_source":  "model+siem",
                "incident_id":      f"INC_VA_{d['days_ago']:03d}",
            },
            refresh="wait_for",
        )


def main():
    config  = KibanaConfig()
    adapter = KibanaAdapter(config)
    agent   = VerificationAgent(adapter)

    if not adapter.is_available():
        print(f"{FAIL} Elasticsearch not reachable")
        sys.exit(1)

    client = adapter._client

    # ------------------------------------------------------------------ #
    # Scenario 1: IP with rich history → Confirmed (score > 0.80)        #
    # ------------------------------------------------------------------ #
    print(f"\n{INFO} Scenario 1 — Known repeat attacker (expect: Confirmed)\n")
    ip1 = "10.11.12.100"
    seed(client, ip1, [
        {"attack_type": "PortScan", "days_ago": 1},
        {"attack_type": "PortScan", "days_ago": 2},
        {"attack_type": "PortScan", "days_ago": 4},
        {"attack_type": "PortScan", "days_ago": 10},
        {"attack_type": "PortScan", "days_ago": 20},
        {"attack_type": "SYN Flood","days_ago": 30},
        {"attack_type": "SYN Flood","days_ago": 45},
    ])

    r1 = agent.verify(make_result(ip1, "PortScan"))
    check("score > 0.80",                  r1.verification_score > 0.80,       f"score={r1.verification_score}")
    check("verdict = Confirmed",           "Confirmed" in r1.verification_verdict)
    check("severity = high",               r1.severity == "high")
    check("block_immediately kept",        "block_immediately" in r1.recommended_actions)
    check("verification_score on result",  r1.verification_score > 0)
    check("metadata.verification present", "verification" in r1.metadata)
    check("reasoning extended",            "Verification" in r1.reasoning)

    # ------------------------------------------------------------------ #
    # Scenario 2: IP with partial history — Suspicious (score 0.50-0.80)#
    # 7 total attacks, 3 same-type (PortScan), only 1 recent            #
    # score = 0.4*0.70 + 0.4*0.60 + 0.2*0.33 = 0.587                  #
    # ------------------------------------------------------------------ #
    print(f"\n{INFO} Scenario 2 — Partial history, some same-type (expect: Suspicious)\n")
    ip2 = "10.11.12.101"
    seed(client, ip2, [
        {"attack_type": "PortScan", "days_ago": 6},    # recent (within 7d)
        {"attack_type": "PortScan", "days_ago": 12},   # same type, not recent
        {"attack_type": "PortScan", "days_ago": 25},   # same type, not recent
        {"attack_type": "SYN Flood","days_ago": 30},
        {"attack_type": "SYN Flood","days_ago": 40},
        {"attack_type": "SYN Flood","days_ago": 50},
        {"attack_type": "SYN Flood","days_ago": 60},
    ])

    r2 = agent.verify(make_result(ip2, "PortScan"))
    check("score in [0.50, 0.80]",        0.50 <= r2.verification_score <= 0.80,
          f"score={r2.verification_score}")
    check("verdict = Suspicious",         "Suspicious" in r2.verification_verdict)
    check("severity = medium",            r2.severity == "medium")
    check("block_immediately downgraded", "block_immediately" not in r2.recommended_actions,
          f"actions={r2.recommended_actions}")
    check("rate_limit in actions",        "rate_limit" in r2.recommended_actions)

    # ------------------------------------------------------------------ #
    # Scenario 3: Brand-new IP → Low Evidence (score < 0.50)             #
    # ------------------------------------------------------------------ #
    print(f"\n{INFO} Scenario 3 — Unknown IP, no history (expect: Low Evidence)\n")
    ip3 = "192.0.2.55"   # no seeded records

    r3 = agent.verify(make_result(ip3, "DoS Hulk"))
    check("score < 0.50",                  r3.verification_score < 0.50,
          f"score={r3.verification_score}")
    check("verdict = Newly Observed",      "Newly Observed" in r3.verification_verdict)
    check("severity = low",                r3.severity == "low")
    check("actions → monitor only",        r3.recommended_actions == ["monitor_closely", "log_for_investigation"],
          f"actions={r3.recommended_actions}")

    # ------------------------------------------------------------------ #
    # Scenario 4: Benign flow — agent is a no-op                         #
    # ------------------------------------------------------------------ #
    print(f"\n{INFO} Scenario 4 — Benign flow (expect: no-op)\n")
    benign = make_result("172.16.0.1", "BENIGN")
    benign.is_attack = False
    original_score = benign.verification_score

    r4 = agent.verify(benign)
    check("verification_score unchanged",  r4.verification_score == original_score)
    check("verdict still empty",           r4.verification_verdict == "")

    print()


if __name__ == "__main__":
    main()
