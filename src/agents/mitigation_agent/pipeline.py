"""
ANDS Pipeline
=============
Wires the ClassificationAgent → MitigationAgent.

Two usage patterns
------------------
1. Callback mode  (real-time)
   MitigationAgent fires automatically via the on_attack= hook on
   ClassificationAgent. Each attack is mitigated the moment it is detected.

2. Batch mode  (offline / replay)
   ClassificationAgent processes all flows first, then MitigationAgent
   handles every flagged ClassificationResult at once.

Run from the repo root:
    python src/pipeline.py           # default: callback mode
    python src/pipeline.py batch     # batch mode
"""

import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)

try:
    from src.agents.classification_agent.agent import (
        DetectionClassificationAgent,
        FlowInputConfig,
    )
    from src.agents.classification_agent.kibana_adapter import (
        KibanaAdapter,
        KibanaConfig,
    )
    from src.agents.mitigation_agent.agent import MitigationAgent, MitigationResult
except ModuleNotFoundError:
    from agents.classification_agent.agent import (
        DetectionClassificationAgent,
        FlowInputConfig,
    )
    from agents.classification_agent.kibana_adapter import (
        KibanaAdapter,
        KibanaConfig,
    )
    from agents.mitigation_agent.agent import MitigationAgent, MitigationResult


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _build_siem_adapter():
    kibana_host = (os.getenv("KIBANA_HOST") or "http://localhost:9200").strip()
    if not kibana_host:
        raise RuntimeError("KIBANA_HOST is required for SIEM history fusion.")

    adapter = KibanaAdapter(
        KibanaConfig(
            host=kibana_host,
            index=os.getenv("KIBANA_INDEX", "ands-alerts"),
            username=os.getenv("KIBANA_USER") or None,
            password=os.getenv("KIBANA_PASS") or None,
            verify_certs=_env_bool("KIBANA_VERIFY_CERTS", False),
            max_alerts=int(os.getenv("SIEM_MAX_ALERTS", "50")),
        )
    )
    if not adapter.is_available():
        raise RuntimeError(
            f"Could not connect to Elasticsearch at {kibana_host}. "
            "Start Elasticsearch/Kibana or update KIBANA_HOST credentials."
        )
    return adapter


# ---------------------------------------------------------------------------
# Pattern 1 — Callback mode (real-time)
# ---------------------------------------------------------------------------

def run_callback_mode():
    """
    MitigationAgent is registered as the on_attack callback on the
    ClassificationAgent. Every confirmed attack is mitigated immediately.
    """
    mitigation_agent = MitigationAgent(model_name="llama3")
    siem_adapter = _build_siem_adapter()
    use_siem_history = _env_bool("USE_SIEM_HISTORY", default=True)

    def on_attack(classification_result):
        result: MitigationResult = mitigation_agent.mitigate(classification_result)
        print(result.summary())

    classification_agent = DetectionClassificationAgent(
        model_path="deployments/models/pca_intrusion_detector.joblib",
        kibana=siem_adapter,
        on_attack=on_attack,            # ← MitigationAgent wired here
        kibana_window_minutes=int(os.getenv("SIEM_WINDOW_MINUTES", "10")),
        push_benign_to_kibana=_env_bool("KIBANA_SAVE_ALL", False),
        use_siem_history=use_siem_history,
    )

    classification_agent.run(
        FlowInputConfig(mode="csv", csv_path="data/flows.csv")
    )


# ---------------------------------------------------------------------------
# Pattern 2 — Batch mode (offline / replay)
# ---------------------------------------------------------------------------

def run_batch_mode():
    """
    ClassificationAgent runs first, then MitigationAgent processes all
    flagged results in one pass.
    """
    siem_adapter = _build_siem_adapter()
    use_siem_history = _env_bool("USE_SIEM_HISTORY", default=True)

    classification_agent = DetectionClassificationAgent(
        model_path="deployments/models/pca_intrusion_detector.joblib",
        kibana=siem_adapter,
        kibana_window_minutes=int(os.getenv("SIEM_WINDOW_MINUTES", "10")),
        push_benign_to_kibana=_env_bool("KIBANA_SAVE_ALL", False),
        use_siem_history=use_siem_history,
    )

    classification_results = classification_agent.run(
        FlowInputConfig(mode="csv", csv_path="data/flows.csv")
    )

    mitigation_agent   = MitigationAgent(model_name="llama3")
    mitigation_results = mitigation_agent.run_batch(classification_results)

    # Both lists are index-aligned
    for c, m in zip(classification_results, mitigation_results):
        if c.is_attack:
            print(m.summary())


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "callback"
    if mode == "batch":
        run_batch_mode()
    else:
        run_callback_mode()