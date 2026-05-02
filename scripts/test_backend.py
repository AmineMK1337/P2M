"""
Backend API test suite.
Tests all endpoints, validates response shape, and checks that the
VerificationAgent fields appear in /api/dashboard.

Run: python scripts/test_backend.py
Requires the server to be running: uvicorn src.api:app --port 8000
"""

import sys
import json
import time
import urllib.request
import urllib.error
from pathlib import Path

BASE = "http://127.0.0.1:8000"

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"
WARN = "\033[93m[WARN]\033[0m"

failures = 0


def check(label: str, condition: bool, detail: str = "") -> bool:
    global failures
    tag = PASS if condition else FAIL
    if not condition:
        failures += 1
    print(f"  {tag} {label}" + (f"  ({detail})" if detail else ""))
    return condition


def get(path: str, timeout: int = 5) -> tuple[int, dict]:
    url = BASE + path
    try:
        req = urllib.request.urlopen(url, timeout=timeout)
        return req.status, json.loads(req.read())
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception as e:
        return 0, {"error": str(e)}


def wait_for_server(retries: int = 15, delay: float = 1.0) -> bool:
    print(f"\n{INFO} Waiting for server at {BASE} ...")
    for i in range(retries):
        status, _ = get("/api/agents/status")
        if status == 200:
            print(f"  Server ready after {i * delay:.0f}s\n")
            return True
        time.sleep(delay)
    return False


def main():
    if not wait_for_server():
        print(f"{FAIL} Server not reachable. Start it with:\n"
              "  uvicorn src.api:app --port 8000\n")
        sys.exit(1)

    # ------------------------------------------------------------------ #
    # /api/agents/status                                                  #
    # ------------------------------------------------------------------ #
    print(f"{INFO} GET /api/agents/status")
    status, body = get("/api/agents/status")
    check("HTTP 200",                          status == 200, f"got {status}")
    check("classification_agent present",      "classification_agent" in body)
    check("classification_agent = running",    body.get("classification_agent") == "running")
    check("mitigation_agent present",          "mitigation_agent" in body)
    check("siem_agent present",                "siem_agent" in body)
    print()

    # ------------------------------------------------------------------ #
    # /api/system                                                         #
    # ------------------------------------------------------------------ #
    print(f"{INFO} GET /api/system")
    status, body = get("/api/system")
    check("HTTP 200",          status == 200, f"got {status}")
    check("cpu present",       "cpu" in body)
    check("ram present",       "ram" in body)
    check("network present",   "network" in body)
    check("state present",     "state" in body)
    check("capture present",   "capture" in body)
    print()

    # ------------------------------------------------------------------ #
    # /api/logs                                                           #
    # ------------------------------------------------------------------ #
    print(f"{INFO} GET /api/logs")
    status, body = get("/api/logs")
    check("HTTP 200",        status == 200, f"got {status}")
    check("logs key present", "logs" in body)
    check("logs is a list",   isinstance(body.get("logs"), list))
    check("at least 1 log",   len(body.get("logs", [])) >= 1,
          f"count={len(body.get('logs', []))}")
    print()

    # ------------------------------------------------------------------ #
    # /api/dashboard  (wait a moment for the agent loop to process flows) #
    # ------------------------------------------------------------------ #
    print(f"{INFO} GET /api/dashboard  (waiting 5s for agent loop...)")
    time.sleep(5)
    status, body = get("/api/dashboard")
    check("HTTP 200",            status == 200, f"got {status}")

    # Top-level sections
    for section in ("traffic", "features", "detection", "decision", "defense", "mitigation"):
        check(f"section '{section}' present", section in body)

    # detection detail
    det = body.get("detection", {})
    check("detection.prediction present",          "prediction" in det)
    check("detection.confidence present",          "confidence" in det)
    check("detection.attack_type present",         "attack_type" in det)
    check("detection.reasoning present",           "reasoning" in det)
    check("detection.verification_score present",  "verification_score" in det,
          f"got keys: {list(det.keys())}")
    check("detection.verification_verdict present","verification_verdict" in det)

    # If an attack was classified, check the verification fields have values
    if det.get("prediction") == "attack":
        check("verification_score is float",
              isinstance(det.get("verification_score"), (int, float)))
        check("verification_verdict is non-empty string",
              isinstance(det.get("verification_verdict"), str) and len(det.get("verification_verdict", "")) > 0,
              f"verdict={det.get('verification_verdict')!r}")
    else:
        print(f"  {WARN} No attack classified yet — skipping verification value checks")

    # decision detail
    dec = body.get("decision", {})
    check("decision.action present",     "action" in dec)
    check("decision.confidence present", "confidence" in dec)

    # defense detail
    dfn = body.get("defense", {})
    check("defense.blocked_ips present", "blocked_ips" in dfn)
    check("defense.total present",       "total" in dfn)

    # features
    feat = body.get("features", {})
    check("features.flows present",  "flows" in feat)
    check("features.flows > 0",      feat.get("flows", 0) > 0, f"flows={feat.get('flows')}")
    print()

    # ------------------------------------------------------------------ #
    # Summary                                                             #
    # ------------------------------------------------------------------ #
    if failures == 0:
        print(f"{PASS} All checks passed.\n")
    else:
        print(f"{FAIL} {failures} check(s) failed.\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
