#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")/.."

PCAP_PATH="data/test1/simulated_attack.pcap"
CSV_PATH="data/test1/test_output.csv"
LOG_DIR="logs"
BACKEND_LOG="$LOG_DIR/test_full_pipeline_backend.log"
API_BASE="http://127.0.0.1:8000"
SUMMARY_ENDPOINT="$API_BASE/api/pipeline/test-run"

mkdir -p "data/test1" "$LOG_DIR"

echo "[+] Cleaning previous test outputs"
rm -f "$CSV_PATH"
rm -f "$BACKEND_LOG"

if ! python3 - <<'PY'
import sys
import urllib.request

try:
    with urllib.request.urlopen("http://127.0.0.1:8000/api/agents/status", timeout=2) as response:
        sys.exit(0 if response.status == 200 else 1)
except Exception:
    sys.exit(1)
PY
then
  echo "[+] Starting backend API in test mode"
  PYTHONPATH="$PWD" TEST_MODE=1 nohup python3 -m uvicorn src.api:app --host 127.0.0.1 --port 8000 > "$BACKEND_LOG" 2>&1 &

  echo "[+] Waiting for backend API"
  for _ in $(seq 1 30); do
    if python3 - <<'PY'
import sys
import urllib.request

try:
    with urllib.request.urlopen("http://127.0.0.1:8000/api/agents/status", timeout=2) as response:
        sys.exit(0 if response.status == 200 else 1)
except Exception:
    sys.exit(1)
PY
    then
      break
    fi
    sleep 1
  done
fi

echo "[+] Running CICFlowMeter sniffer once"
PYTHONPATH="$PWD/CICflow-meter/src:$PWD" python3 CICflow-meter/src/cicflowmeter/sniffer.py "$PCAP_PATH" "$CSV_PATH"

echo "[+] Running ML inference and publishing results to the backend"
python3 - "$CSV_PATH" "$SUMMARY_ENDPOINT" <<'PY'
import json
import sys
import time
import urllib.request
from pathlib import Path

from src.agents.classification_agent.agent import DetectionClassificationAgent, FlowInputConfig
from src.agents.classification_agent.kibana_adapter import StubKibanaAdapter

csv_path = Path(sys.argv[1])
endpoint = sys.argv[2]

start = time.perf_counter()
agent = DetectionClassificationAgent(
    model_path="deployments/models/pca_intrusion_detector.joblib",
    kibana=StubKibanaAdapter(),
    on_attack=None,
    threshold=0.5,
    kibana_window_minutes=10,
    push_benign_to_kibana=False,
    use_siem_history=False,
)
results = agent.run(FlowInputConfig(mode="csv", csv_path=str(csv_path)))
elapsed = time.perf_counter() - start

total = len(results)
attack_results = [result for result in results if result.is_attack]
benign_count = total - len(attack_results)
last_result = results[-1] if results else None
blocked_ips = []
seen_ips = set()
for result in attack_results:
    ip = result.src_ip
    if ip and ip != "unknown" and ip not in seen_ips:
        seen_ips.add(ip)
        blocked_ips.append(ip)

summary = {
    "status": "completed",
    "source": "test_full_pipeline",
    "total_flows": total,
    "attack_count": len(attack_results),
    "benign_count": benign_count,
    "execution_seconds": round(elapsed, 3),
    "prediction": last_result.attack_type if last_result else "normal",
    "confidence": float(last_result.confidence if last_result else 0.0),
    "model_confidence": float(last_result.model_confidence if last_result else 0.0),
    "siem_confidence": float(last_result.siem_confidence if last_result else 0.0),
    "attack_type": last_result.attack_type if last_result else "BENIGN",
    "reasoning": last_result.reasoning if last_result else "No flows processed.",
    "decision_action": "block" if attack_results else "allow",
    "blocked_ips": blocked_ips,
    "last_blocked_ip": blocked_ips[-1] if blocked_ips else "none",
}

payload = json.dumps(summary).encode("utf-8")
request = urllib.request.Request(
    endpoint,
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(request, timeout=10) as response:
    response.read()

print(f"Total flows processed: {total}")
print(f"Attack flows: {len(attack_results)}")
print(f"Benign flows: {benign_count}")
print(f"Execution time: {elapsed:.2f}s")
print(f"Latest prediction: {summary['prediction']} ({summary['confidence']:.3f})")
print("Backend dashboard updated: /api/dashboard")
PY

echo "[✓] Test pipeline complete"