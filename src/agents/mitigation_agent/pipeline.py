"""
ANDS Pipeline — wires ClassificationAgent → MitigationAgent.

Modes
-----
callback  (default)  MitigationAgent fires immediately on each attack.
batch                 Classify all flows first, then mitigate in one pass.

Run from repo root:
    python src/pipeline.py
    python src/pipeline.py batch
"""

import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)

try:
    from src.agents.classification_agent.agent import DetectionClassificationAgent, FlowInputConfig
    from src.agents.classification_agent.kibana_adapter import KibanaAdapter, KibanaConfig
    from src.agents.mitigation_agent.agent import MitigationAgent
except ModuleNotFoundError:
    from agents.classification_agent.agent import DetectionClassificationAgent, FlowInputConfig
    from agents.classification_agent.kibana_adapter import KibanaAdapter, KibanaConfig
    from agents.mitigation_agent.agent import MitigationAgent


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _build_siem_adapter() -> KibanaAdapter:
    host = (os.getenv("KIBANA_HOST") or "http://localhost:9200").strip()
    adapter = KibanaAdapter(
        KibanaConfig(
            host=host,
            index=os.getenv("KIBANA_INDEX", "ands-alerts"),
            username=os.getenv("KIBANA_USER") or None,
            password=os.getenv("KIBANA_PASS") or None,
            verify_certs=_env_bool("KIBANA_VERIFY_CERTS", False),
            max_alerts=int(os.getenv("SIEM_MAX_ALERTS", "50")),
        )
    )
    if not adapter.is_available():
        raise RuntimeError(
            f"Could not connect to Elasticsearch at {host}. "
            "Check KIBANA_HOST / credentials."
        )
    return adapter


def _build_classification_agent(siem_adapter: KibanaAdapter, on_attack=None) -> DetectionClassificationAgent:
    return DetectionClassificationAgent(
        model_path="deployments/models/pca_intrusion_detector.joblib",
        kibana=siem_adapter,
        on_attack=on_attack,
        kibana_window_minutes=int(os.getenv("SIEM_WINDOW_MINUTES", "10")),
        push_benign_to_kibana=_env_bool("KIBANA_SAVE_ALL", False),
        use_siem_history=_env_bool("USE_SIEM_HISTORY", True),
    )


def run_callback_mode() -> None:
    mitigation_agent = MitigationAgent()
    siem_adapter = _build_siem_adapter()

    def on_attack(result):
        print(mitigation_agent.mitigate(result).summary())

    classification_agent = _build_classification_agent(siem_adapter, on_attack=on_attack)
    classification_agent.run(FlowInputConfig(mode="csv", csv_path="data/flows.csv"))


def run_batch_mode() -> None:
    siem_adapter = _build_siem_adapter()
    classification_agent = _build_classification_agent(siem_adapter)
    classifications = classification_agent.run(FlowInputConfig(mode="csv", csv_path="data/flows.csv"))

    mitigation_agent = MitigationAgent()
    results = mitigation_agent.run_batch(classifications)

    for c, m in zip(classifications, results):
        if c.is_attack:
            print(m.summary())


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "callback"
    if mode == "batch":
        run_batch_mode()
    else:
        run_callback_mode()
